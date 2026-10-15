"""Enterprise export allowance survives jobs, connections and worker restarts."""

import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest
from cremore_github_provider.metadata.tests.fake import enterprise_spec, spec

from cremore.coverage.errors import CoverageError
from cremore.coverage.github_exports import ExportControl, next_create_at, public_state
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine

NOW = datetime(2026, 10, 5, tzinfo=UTC)


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        yield InMemoryRepository()
    else:
        engine = make_engine("sqlite:///:memory:")
        create_all(engine)
        try:
            yield SqlRepository(engine)
        finally:
            engine.dispose()


def control(repo, connection=None, *, job=None, now=NOW, context=None):
    @contextmanager
    def transaction():
        yield repo
    return ExportControl(repo, connection or enterprise_spec(), job or uuid.uuid4(),
                         context=context or transaction, now=lambda: now)


def confirmed(stage="queued", **patch):
    return {"stage": stage, "export_id": "e-1", "as_of": NOW.isoformat(), "submitted_at": NOW.isoformat(), **patch}


def test_authentication_failure_before_reservation_preserves_the_provider_error(repo):
    from cremore_github_provider.metadata.adapter import collect_pages
    from cremore_github_provider.metadata.http import SourceError
    from cremore_github_provider.metadata.tests.fake import SECRETS, FakeBroker
    from cremore_github_provider.metadata.tests.test_export_runtime import transport

    class DeniedBroker(FakeBroker):
        def token_for(self, scope, name=""):
            raise SourceError("github_http_403", status=403)

    def no_request(_):
        pytest.fail("An authentication failure must not request an export")

    connection = enterprise_spec(options={"enterprise_only": True})
    pages = list(collect_pages(connection, secrets=SECRETS, checkpoint={}, check=lambda: None,
        transport=transport(no_request), broker=DeniedBroker(), export_control=control(repo, connection)))
    assert pages[-1].status == "PARTIAL"
    assert pages[-1].reasons == ["GITHUB_HTTP_403"]
    assert public_state(repo, connection) == {}


def test_allowance_is_shared_across_connections_and_survives_restarting_the_worker(repo):
    owner = control(repo)
    assert owner.reserve() == {"stage": "reserved"}
    owner.save({"stage": "submitting", "submitted_at": NOW.isoformat()})
    other = control(repo, enterprise_spec(name="another connection"))
    assert other.reserve()["stage"] == "submission_unknown"
    owner.save(confirmed())
    resumed = other.reserve()
    assert resumed["export_id"] == "e-1" and resumed["stage"] == "queued"
    assert next_create_at(repo, enterprise_spec()) == NOW + timedelta(days=1)


def test_a_shared_export_reader_cannot_replace_another_jobs_reservation(repo):
    owner, reader = control(repo), control(repo)
    owner.reserve()
    owner.save(confirmed())
    reader.save(confirmed("complete"))
    assert public_state(repo, enterprise_spec())["stage"] == "queued"
    with pytest.raises(CoverageError, match="RESERVATION_LOST"):
        reader.save(confirmed(export_id="different"))


def test_unknown_submission_waits_for_rolling_cooldown_without_resetting_it(repo):
    owner = control(repo)
    owner.reserve()
    owner.save({"stage": "submission_unknown", "error": "github_unavailable"})
    assert control(repo, now=NOW + timedelta(hours=23)).reserve()["stage"] == "submission_unknown"
    assert control(repo, now=NOW + timedelta(days=1)).reserve() == {"stage": "reserved"}


def test_daily_quota_honors_longer_retry_after_and_public_state_never_contains_export_handle(repo):
    owner = control(repo)
    owner.reserve()
    owner.save({"stage": "quota_wait", "error": "github_rate_limited", "retry_after_seconds": 172800})
    state = public_state(repo, enterprise_spec())
    assert state["next_create_at"] == (NOW + timedelta(days=2)).isoformat()
    assert "job_id" not in state and "export_id" not in state
    assert control(repo).reserve()["stage"] == "quota_wait"


def test_confirmed_permission_rejection_does_not_consume_the_next_days_allowance(repo):
    owner = control(repo)
    owner.reserve()
    owner.save({"stage": "rejected", "error": "github_http_403"})
    assert control(repo).reserve() == {"stage": "reserved"}


def test_each_enterprise_and_origin_has_its_own_allowance_and_organization_reads_are_unaffected(repo):
    owner = control(repo)
    owner.reserve()
    other = enterprise_spec()
    other.scopes[0].id = "another"
    assert control(repo, other).reserve() == {"stage": "reserved"}
    dedicated = enterprise_spec(origin="https://company.ghe.com", edition="dedicated")
    assert control(repo, dedicated).reserve() == {"stage": "reserved"}
    assert next_create_at(repo, spec()) is None


@pytest.mark.parametrize("patch", [{"export_id": "https://signed.example/private"}, {"error": "secret response"},
                                  {"as_of": "yesterday"}, {"stage": "made up"}])
def test_export_coordination_does_not_accept_unvalidated_state_or_urls(repo, patch):
    owner = control(repo)
    owner.reserve()
    with pytest.raises(CoverageError, match="STATE_INVALID"):
        owner.save(confirmed(**patch))


def test_worker_context_fencing_is_checked_on_every_mutation(repo):
    @contextmanager
    def lost():
        raise CoverageError("TEST_LEASE_LOST")
        yield repo
    owner = control(repo, context=lost)
    with pytest.raises(CoverageError, match="TEST_LEASE_LOST"):
        owner.reserve()
    with pytest.raises(CoverageError, match="TEST_LEASE_LOST"):
        owner.save(confirmed())


def test_concurrent_first_reservations_allow_only_one_submission():
    repo = InMemoryRepository()
    owners = [control(repo) for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        states = list(pool.map(lambda owner: owner.reserve(), owners))
    assert sum(state["stage"] == "reserved" for state in states) == 1
    assert sum(state["stage"] == "quota_wait" for state in states) == 7


def test_partial_export_warning_survives_reuse_by_a_second_connection(repo):
    owner = control(repo)
    owner.reserve()
    owner.save(confirmed(warnings=["truncated:true"]))
    assert control(repo).reserve()["warnings"] == ["github_inventory_metadata_incomplete"]


@pytest.mark.parametrize("error", ["github_export_expired", "github_export_content_changed",
                                  "github_export_identity_changed", "github_export_snapshot_changed",
                                  "github_export_failed", "github_export_unavailable_or_not_authorized"])
def test_expired_or_changed_export_is_not_offered_for_reuse_and_keeps_allowance(repo, error):
    owner = control(repo)
    owner.reserve()
    owner.save(confirmed("failed", error=error))
    state = public_state(repo, enterprise_spec(), now=NOW)
    assert state["reuse_available"] is False
    assert state["request_blocked_reason"] == "GITHUB_EXPORT_QUOTA_WAIT"
    assert control(repo).reserve()["stage"] == "quota_wait"
    assert control(repo, now=NOW + timedelta(days=1)).reserve()["stage"] == "reserved"


def test_confirmed_export_with_a_null_as_of_is_saved_and_reused_then_dated(repo):
    # GitHub documents a created export's as_of as "string or null".
    owner = control(repo)
    owner.reserve()
    owner.save(confirmed(as_of=None))
    assert control(repo).reserve() == {"stage": "queued", "export_id": "e-1", "as_of": None,
                                       "submitted_at": NOW.isoformat()}
    # The public enterprise_export keeps its shape: as_of is a string or absent, never null.
    hidden = public_state(repo, enterprise_spec(), now=NOW)
    assert "as_of" not in hidden and hidden["reuse_available"] is True
    owner.save(confirmed())
    assert public_state(repo, enterprise_spec(), now=NOW)["as_of"] == NOW.isoformat()


def test_scheduler_and_display_share_export_wait_without_delaying_separate_audit(repo):
    from cremore.config import Settings
    from cremore.coverage import METADATA_JOB_KIND
    from cremore.coverage.metadata_store import MetadataStore
    from cremore.coverage.scheduling import poll_metadata_schedules
    from cremore.domain.models import ScanJob
    from cremore.operations.collection_schedule import for_job

    settings, store = Settings(), MetadataStore(repo)
    connection = enterprise_spec(schedule_minutes=5, options={"enterprise_only": True})
    first, _ = store.create(connection, "test")
    store.create(connection.model_copy(update={"name": "Second connection, same Enterprise"}), "test")
    audit = enterprise_spec(name="Independent audit", schedule_minutes=5, capabilities=["inventory", "audit"],
        options={"github_inventory": False, "include_audit_events": True, "enterprise_only": True})
    audit_row, _ = store.create(audit, "test")
    owner = control(repo, connection)
    owner.reserve()
    owner.save({"stage": "quota_wait", "retry_after_seconds": 172800})
    result = poll_metadata_schedules(repo, settings, now=NOW)
    assert result == {"enqueued": 1, "skipped": 2}
    jobs = repo.list_jobs(20)
    assert len(jobs) == 1 and jobs[0].payload["coverage_connection_id"] == str(audit_row["id"])
    display = for_job(repo, settings, ScanJob(kind=METADATA_JOB_KIND, payload={
        "coverage_connection_id": str(first["id"]), "coverage_revision": 1}), now=NOW)
    assert display["next_due_at"] == (NOW + timedelta(days=2)).isoformat()
    assert poll_metadata_schedules(repo, settings, now=NOW + timedelta(days=2))["enqueued"] == 2
