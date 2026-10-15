"""The same crash/replay and rollup contracts hold for SQL and memory stores."""

import uuid

import pytest
from sqlalchemy import event

from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import Connection, ConnectionCheckEvent, Credential, Exposure, ScanJob


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def seed(repo):
    credential = repo.upsert_credential(Credential(fingerprint="synthetic-fingerprint", credential_type="TOKEN"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="notion",
        source_connection_id=uuid.uuid4(), resource_name="page", location="page", severity="HIGH",
        metadata={"collector_epoch": 1, "page_id": "parent", "legacy_context": "preserved"}))
    finding = repo.upsert_finding(credential.id, exposure.id, "HIGH")
    return credential, exposure, finding


def test_finding_pages_bound_models_and_advance_by_id(repo):
    seed(repo)
    for index in range(3):
        credential = repo.upsert_credential(Credential(fingerprint=f"page-{index}", credential_type="TOKEN"))
        exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="notion",
            resource_name="page", location=str(index), severity="HIGH"))
        repo.upsert_finding(credential.id, exposure.id, "HIGH")
    expected = sorted((f.id for f in repo.list_findings()), key=str)
    first = repo.list_findings(limit=2)
    second = repo.list_findings(limit=2, after=first[-1].id)
    assert [f.id for f in first + second] == expected
    assert repo.list_findings(limit=2, after=second[-1].id) == []


def test_unknown_placeholder_preserves_observed_severity_and_only_observation_metadata(repo):
    credential, exposure, _ = seed(repo)
    repeated = exposure.model_copy(update={"severity": "UNKNOWN", "metadata": {
        "collector_epoch": 2, "page_id": "parent", "exposure": "private", "catalog_id": "rule-1",
        "arbitrary_untrusted_field": "must not merge"}})
    updated = repo.upsert_exposure(repeated)
    assert updated.id == exposure.id and updated.severity == "HIGH"
    assert updated.metadata["collector_epoch"] == 2 and updated.metadata["catalog_id"] == "rule-1"
    assert updated.metadata["legacy_context"] == "preserved"
    assert "arbitrary_untrusted_field" not in updated.metadata
    assert repo.count_exposures_for_credential(credential.id) == 1
    assert updated.identity_key is not None
    repo.set_exposure_severity(exposure.id, "LOW")
    assert repo.exposures_for_credential(credential.id)[0].severity == "LOW"


def test_fresh_observation_replaces_or_clears_block_and_document_evidence(repo):
    _credential, exposure, _finding = seed(repo)
    current = repo.upsert_exposure(exposure.model_copy(update={"metadata": {
        "page_id": "parent", "revision": "one", "notion_block_id": "a" * 32,
        "document_format": "pdf", "document_extraction_status": "PAGE_LIMIT"}}))
    assert current.metadata["notion_block_id"] == "a" * 32
    current = repo.upsert_exposure(exposure.model_copy(update={"metadata": {
        "page_id": "parent", "revision": "two", "notion_block_id": "b" * 32}}))
    assert current.metadata["notion_block_id"] == "b" * 32
    assert "document_format" not in current.metadata
    current = repo.upsert_exposure(exposure.model_copy(update={"metadata": {
        "page_id": "parent", "revision": ""}}))
    assert "notion_block_id" not in current.metadata
    assert current.metadata["legacy_context"] == "preserved"


def test_rollup_presence_history_ties_and_legacy_reopen(repo):
    credential, exposure, finding = seed(repo)
    other = repo.upsert_exposure(exposure.model_copy(update={"id": None, "location": "other"}))
    assert repo.best_exposure_for_credential(credential.id, preferred_id=other.id) == ("HIGH", other.id)
    repaired = repo.repair_finding_rollup(credential.id)
    assert repaired.primary_exposure_id == exposure.id and repaired.all_locations_removed is False
    count = len(repo.list_finding_events(finding.id))
    repo.repair_finding_rollup(credential.id)
    assert len(repo.list_finding_events(finding.id)) == count
    repo.mark_exposure_removed(exposure.id)
    assert repo.repair_finding_rollup(credential.id).primary_exposure_id == other.id
    repo.mark_exposure_removed(other.id)
    removed = repo.repair_finding_rollup(credential.id)
    assert removed.primary_exposure_id == other.id and removed.severity == "HIGH"
    assert removed.all_locations_removed is True and removed.workflow_status == "OPEN"
    repo.update_finding_status(finding.id, "RESOLVED", resolution="REMOVED_BY_RESCAN")
    repo.upsert_exposure(exposure)
    reopened = repo.repair_finding_rollup(credential.id)
    assert reopened.all_locations_removed is False and reopened.workflow_status == "OPEN"
    repo.update_finding_status(finding.id, "FALSE_POSITIVE", resolution="analyst decision")
    assert repo.repair_finding_rollup(credential.id).workflow_status == "FALSE_POSITIVE"


def test_unknown_active_exposure_prevents_downgrade(repo):
    credential, exposure, _finding = seed(repo)
    repo.mark_exposure_removed(exposure.id)
    uncertain = repo.upsert_exposure(exposure.model_copy(update={"id": None, "location": "unscored", "severity": "UNKNOWN", "status": "OPEN"}))
    known = repo.upsert_exposure(exposure.model_copy(update={"id": None, "location": "low", "severity": "LOW", "status": "OPEN"}))
    repaired = repo.repair_finding_rollup(credential.id)
    assert repaired.severity == "HIGH" and repaired.primary_exposure_id == known.id
    assert repaired.all_locations_removed is False
    repo.set_exposure_severity(uncertain.id, "LOW")
    repaired = repo.repair_finding_rollup(credential.id)
    assert repaired.severity == "LOW" and repaired.primary_exposure_id == known.id


def test_root_lookup_separates_containers_and_notion_identity_survives_titles(repo):
    credential, exposure, _finding = seed(repo)
    connection = exposure.source_connection_id
    for name in ("bucket-a", "bucket-b"):
        repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="s3",
            source_connection_id=connection, resource_name=name, location="config"))
    assert [e.resource_name for e in repo.exposures_for_root(connection, "s3", "bucket-a")] == ["bucket-a"]
    assert repo.exposures_for_root(uuid.uuid4(), "s3", "bucket-a") == []
    page_id = uuid.uuid4()
    for title, stored_id in (("old title", str(page_id).upper()), ("new title", page_id.hex)):
        repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="notion",
            source_connection_id=connection, resource_name=title, location=title, metadata={"page_id": stored_id}))
    rows = repo.exposures_for_root(connection, "notion", "latest title", page_id=str(page_id))
    assert {e.resource_name for e in rows} == {"old title", "new title"}
    assert len({e.container_key for e in rows}) == 1
    assert rows[0].container_key


def test_notion_root_lookup_key_tracks_metadata_merge(repo):
    _credential, exposure, _finding = seed(repo)
    connection = exposure.source_connection_id
    repo.upsert_exposure(exposure.model_copy(update={"metadata": {"collector_epoch": 2}}))
    assert len(repo.exposures_for_root(connection, "notion", "renamed", page_id="parent")) == 1
    repo.set_exposure_severity(exposure.id, "LOW", metadata={"page_id": "new-parent"})
    assert repo.exposures_for_root(connection, "notion", "renamed", page_id="parent") == []
    assert len(repo.exposures_for_root(connection, "notion", "renamed", page_id="new-parent")) == 1


def test_rollup_repairs_severity_when_primary_is_still_open(repo):
    credential, exposure, finding = seed(repo)
    repo.set_exposure_severity(exposure.id, "CRITICAL")
    assert repo.get_finding(finding.id).severity == "HIGH"
    assert repo.repair_finding_rollup(credential.id).severity == "CRITICAL"


def test_rollup_audit_failure_rolls_back_tuple(repo, monkeypatch):
    credential, exposure, finding = seed(repo)
    repo.mark_exposure_removed(exposure.id)
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic audit outage")
    if isinstance(repo, SqlRepository):
        def reject_insert(conn, cursor, statement, parameters, context, executemany):
            if statement.startswith("INSERT INTO finding_events"):
                fail()
        event.listen(repo.engine, "before_cursor_execute", reject_insert)
    else:
        monkeypatch.setattr(repo, "record_finding_event", fail)
    with pytest.raises(RuntimeError, match="audit outage"):
        repo.repair_finding_rollup(credential.id)
    assert repo.get_finding(finding.id).all_locations_removed is None
    assert repo.list_finding_events(finding.id) == []
    if isinstance(repo, SqlRepository):
        event.remove(repo.engine, "before_cursor_execute", reject_insert)


def check_job(repo):
    connection = repo.create_connection(Connection(provider="github", name="synthetic"))
    job = repo.enqueue_job(ScanJob(kind="credential-check", connection_id=connection.id))
    repo.claim_next_job()
    terminal = ConnectionCheckEvent(connection_id=connection.id, job_id=job.id, stage="TERMINAL",
                                    job_status="COMPLETED", outcome="ACTIVE")
    return connection, job, terminal


def test_finish_check_is_one_logical_terminal_transition(repo):
    connection, job, terminal = check_job(repo)
    result = repo.finish_credential_check(job, {"status": "ACTIVE", "credential_evidence": {"status": "ACTIVE"}}, terminal)
    assert result.status == "SUCCEEDED"
    assert repo.get_connection(connection.id).credential_evidence == {"status": "ACTIVE"}
    repo.finish_credential_check(job, {"status": "ERROR"}, terminal.model_copy(update={"outcome": "REJECTED"}))
    assert repo.get_connection(connection.id).status == "ACTIVE"
    assert len(repo.list_check_events(connection.id)) == 1
    assert repo.list_check_events(connection.id)[0].outcome == "ACTIVE"


def test_check_stage_record_is_idempotent(repo):
    connection, _job, terminal = check_job(repo)
    claimed = terminal.model_copy(update={"stage": "CLAIMED_FOR_CHECK", "job_status": "RUNNING"})
    first = repo.record_check_event(claimed)
    assert repo.record_check_event(claimed).id == first.id
    assert len(repo.list_check_events(connection.id)) == 1


@pytest.mark.parametrize("changes", [{"status": "DISABLED"}, {"secret_ref": "sealed:replacement"}])
def test_late_check_cannot_revive_removed_source_or_certify_new_credential(repo, changes):
    connection, job, terminal = check_job(repo)
    repo.update_connection(connection.id, **changes)
    result = repo.finish_credential_check(job, {"status": "ACTIVE", "credential_evidence": {"status": "ACTIVE"}}, terminal)
    current = repo.get_connection(connection.id)
    assert result.status == "SUCCEEDED" and len(repo.list_check_events(connection.id)) == 1
    assert current.status == changes.get("status", "PENDING") and current.credential_evidence is None
    assert repo.update_connection(connection.id, expected_status="ACTIVE", status="PENDING") is None


def test_late_check_preserves_revocation_even_if_status_was_manually_resumed(repo):
    connection, job, terminal = check_job(repo)
    evidence = {"revoked_at": "2026-10-03T00:00:00+00:00", "revoked_by": "admin"}
    repo.update_connection(connection.id, status="ACTIVE", credential_evidence=evidence)
    repo.finish_credential_check(job, {"status": "ACTIVE", "credential_evidence": {"status": "ACTIVE"}}, terminal)
    assert repo.get_connection(connection.id).credential_evidence == evidence
    assert len(repo.list_check_events(connection.id)) == 1


def test_finish_check_ledger_failure_rolls_back_connection_and_job(repo, monkeypatch):
    connection, job, terminal = check_job(repo)
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic ledger outage")
    monkeypatch.setattr(repo, "_record_check_event" if isinstance(repo, SqlRepository) else "record_check_event", fail)
    with pytest.raises(RuntimeError, match="ledger outage"):
        repo.finish_credential_check(job, {"status": "ACTIVE"}, terminal)
    assert repo.get_job(job.id).status == "RUNNING"
    assert repo.get_connection(connection.id).status == "PENDING"
    assert repo.list_check_events(connection.id) == []


def test_finish_check_identity_and_failure_contract(repo):
    connection, job, terminal = check_job(repo)
    with pytest.raises(ValueError):
        repo.finish_credential_check(job, {}, terminal.model_copy(update={"connection_id": uuid.uuid4()}))
    failed = terminal.model_copy(update={"job_status": "FAILED", "outcome": "UNCERTAIN"})
    repo.finish_credential_check(job, {"last_error": "READ_TIMEOUT"}, failed, error="READ_TIMEOUT")
    assert repo.get_job(job.id).status == "FAILED"
    assert repo.list_check_events(connection.id)[0].outcome == "UNCERTAIN"


def test_one_location_found_through_overlapping_connections_counts_once(repo):
    credential = repo.upsert_credential(Credential(fingerprint="overlap", credential_type="TOKEN"))
    account, single = uuid.uuid4(), uuid.uuid4()
    for connection in (account, single):
        repo.upsert_exposure(Exposure(credential_id=credential.id, source_connection_id=connection, source_type="github",
                                      resource_name="jun/app", location=".env.example", line_number=10))
    # rows stay per connection (each tracks its own removal) but it is one place
    assert len(repo.exposures_for_credential(credential.id)) == 2
    assert repo.count_exposures_for_credential(credential.id) == 1
    repo.upsert_exposure(Exposure(credential_id=credential.id, source_connection_id=account, source_type="github",
                                  resource_name="jun/app", location="config.py", line_number=3))
    assert repo.count_exposures_for_credential(credential.id) == 2
