import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from cremore.api.dashboard_test import auth, client
from cremore.db.catalog_store import CatalogStore
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- isolated PostgreSQL fixture
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import ScanJob, ScopeCatalog
from cremore.onboarding.fixtures_test import content_source
from cremore.scanning import scope


def test_sql_catalog_selection_and_all_scan_modes_keep_the_exact_approved_roots():
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    repo = SqlRepository(engine)
    c = client(repo)
    cid = content_source(repo, "github", {"org": "example-org"}, name="Org", secret_ref="vault://github/org").id
    base = f"/api/v1/connections/source/{cid}"
    target = repo.get_connection(cid)
    items = [scope.resource("source", cid, "GITHUB_REPOSITORY", f"example-org/{name}", name,
                            f"https://github.com/example-org/{name}", "github.com") for name in ("app", "archive")]
    CatalogStore(repo).refresh(ScopeCatalog(kind="source", connection_id=cid, snapshot_id="s", completeness="COMPLETE",
                                           auth_revision=scope.auth_revision("source", target), refreshed_at=datetime.now(UTC)), items)
    page = c.post(base + "/resources/search", headers=auth(), json={"exclude": {"q": "archive"}})
    assert page.status_code == 200 and page.json()["known_count"] == 1
    draft = c.post(base + "/selection-drafts", headers=auth(), json={"exclude": {"q": "archive"}}).json()
    assert draft["resource_ids"] == [items[0]["id"]]
    # Names or paths with wildcards pick exact resources; nothing else is kept.
    assert c.post(base + "/selection-drafts", headers=auth(), json={"patterns": ["APP"]}).json()["resource_ids"] == [items[0]["id"]]
    both = c.post(base + "/selection-drafts", headers=auth(), json={"patterns": ["example-org/*"]}).json()
    assert sorted(both["resource_ids"]) == sorted(item["id"] for item in items)
    assert c.post(base + "/selection-drafts", headers=auth(), json={"patterns": ["infra*"]}).json()["resource_ids"] == []
    assert c.post(base + "/selection-drafts", headers=auth(), json={"patterns": [""]}).status_code == 422
    assert c.post(base + "/selection-drafts", headers=auth(), json={"patterns": "app"}).status_code == 422
    saved = c.post(base + "/scan-scope-profiles", headers=auth(), json={
        "name": "app", "change_reason": "approved", "catalog_snapshot_id": "s", "expected_version": 0,
        "selected_roots": [{"resource_id": items[0]["id"], "paths": ["src/"], "priority": 20}],
        "budgets": {"bytes": 1024, "requests": 20, "seconds": 60}})
    assert saved.status_code == 201, saved.text
    profile = saved.json()
    for mode in ("BASELINE", "DELTA", "RECONCILE"):
        preview = c.post(f"/api/v1/scan-scope-profiles/{profile['id']}/preview", headers=auth()).json()
        response = c.post("/api/v1/scan-runs", headers=auth(), json={"plan_id": preview["plan_id"], "profile_version": 1, "mode": mode})
        assert response.status_code == 202, response.text
        job = repo.get_job(uuid.UUID(response.json()["id"]))
        assert job.payload["mode"] == mode
        # The run list names the scope and connection a run belongs to.
        listed = next(item for item in c.get("/api/v1/scan-runs", headers=auth()).json() if item["id"] == str(job.id))
        assert listed["profile_id"] == profile["id"] and listed["connection_kind"] == "source"
        assert len(job.payload["roots"]) == 1 and job.payload["roots"][0]["paths"] == ["src/"]
        assert job.payload["roots"][0]["priority"] == 20
        conflict = c.post("/api/v1/scan-runs", headers=auth(), json={"plan_id": preview["plan_id"], "profile_version": 1,
                                                                 "mode": "DELTA" if mode != "DELTA" else "BASELINE"})
        assert conflict.status_code == 409
        repo.request_job_cancel(job.id)  # withdraw it so the next mode can take the slot
    preview = c.post(f"/api/v1/scan-scope-profiles/{profile['id']}/preview", headers=auth()).json()
    response = c.post("/api/v1/scan-runs", headers=auth(), json={"plan_id": preview["plan_id"], "profile_version": 1, "mode": "INVENTORY"})
    assert response.status_code == 422 and "INVENTORY_REQUIRES_S3_ROOTS" in response.text


def test_inventory_is_explicit_and_only_uses_s3_approved_roots():
    from cremore.domain.models import Connection, ScopeProfile

    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    repo = SqlRepository(engine)
    target = repo.create_connection(Connection(provider="aws", name="S3", config={"bucket": "approved-bucket"}))
    item = scope.resource("source", target.id, "S3_BUCKET", "approved-bucket", "approved-bucket", "approved-bucket", "aws")
    profile = repo.create_scope_profile(ScopeProfile(kind="source", connection_id=target.id, name="approved",
        selected_roots=[{"resource_id": item["id"], "all_current_objects": True, "include_future_descendants": False}],
        auth_revision=scope.auth_revision("source", target), catalog_snapshot_id="s"))
    CatalogStore(repo).refresh(ScopeCatalog(kind="source", connection_id=target.id, snapshot_id="s", completeness="COMPLETE",
        auth_revision=profile.auth_revision), [item])
    c = client(repo)
    preview = c.post(f"/api/v1/scan-scope-profiles/{profile.id}/preview", headers=auth()).json()
    body = {"plan_id": preview["plan_id"], "profile_version": 1, "mode": "INVENTORY"}
    first = c.post("/api/v1/scan-runs", headers=auth(), json=body)
    assert first.status_code == 202, first.text
    repeated = c.post("/api/v1/scan-runs", headers=auth(), json=body)
    assert repeated.status_code == 202 and repeated.json()["id"] == first.json()["id"]
    job = repo.get_job(uuid.UUID(first.json()["id"]))
    assert job.payload["mode"] == "INVENTORY"
    assert [r["resource_id"] for r in job.payload["roots"]] == [item["id"]]

def test_a_second_run_of_the_same_profile_version_returns_the_running_scan_not_a_duplicate():
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    repo = SqlRepository(engine)
    c = client(repo)
    cid = content_source(repo, "github", {"org": "example-org"}, name="Org", secret_ref="vault://github/org").id
    base = f"/api/v1/connections/source/{cid}"
    target = repo.get_connection(cid)
    items = [scope.resource("source", cid, "GITHUB_REPOSITORY", "example-org/app", "app", "https://github.com/example-org/app", "github.com")]
    CatalogStore(repo).refresh(ScopeCatalog(kind="source", connection_id=cid, snapshot_id="s", completeness="COMPLETE",
                                           auth_revision=scope.auth_revision("source", target), refreshed_at=datetime.now(UTC)), items)
    prof = c.post(base + "/scan-scope-profiles", headers=auth(), json={
        "name": "app", "change_reason": "approved", "catalog_snapshot_id": "s", "expected_version": 0,
        "selected_roots": [{"resource_id": items[0]["id"], "paths": ["src/"], "priority": 0}],
        "budgets": {"bytes": 1024, "requests": 20, "seconds": 60}}).json()
    # two separate previews (plans) of the same profile version
    plan_a = c.post(f"/api/v1/scan-scope-profiles/{prof['id']}/preview", headers=auth()).json()
    plan_b = c.post(f"/api/v1/scan-scope-profiles/{prof['id']}/preview", headers=auth()).json()
    assert plan_a["plan_id"] != plan_b["plan_id"]
    first = c.post("/api/v1/scan-runs", headers=auth(), json={"plan_id": plan_a["plan_id"], "profile_version": 1, "mode": "BASELINE"})
    assert first.status_code == 202
    # the second preview's run does not start a duplicate; it returns the already-running scan
    second = c.post("/api/v1/scan-runs", headers=auth(), json={"plan_id": plan_b["plan_id"], "profile_version": 1, "mode": "BASELINE"})
    assert second.status_code == 202 and second.json()["id"] == first.json()["id"]


@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def store(request):
    if request.param == "memory":
        yield InMemoryRepository()
        return
    if request.param == "postgres":
        yield request.getfixturevalue("pg")[1]
        return
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    yield SqlRepository(engine)
    engine.dispose()


def approved_scope(repo):
    """A GitHub scope an Admin saved through the API, and a call that asks for its full read (BASELINE)."""
    c = client(repo)
    cid = content_source(repo, "github", {"org": "example-org"}, name="Org", secret_ref="vault://github/org").id
    items = [scope.resource("source", cid, "GITHUB_REPOSITORY", "example-org/app", "app", "https://github.com/example-org/app", "github.com")]
    CatalogStore(repo).refresh(ScopeCatalog(kind="source", connection_id=cid, snapshot_id="s", completeness="COMPLETE",
                                           auth_revision=scope.auth_revision("source", repo.get_connection(cid)),
                                           refreshed_at=datetime.now(UTC)), items)
    prof = c.post(f"/api/v1/connections/source/{cid}/scan-scope-profiles", headers=auth(), json={
        "name": "app", "change_reason": "approved", "catalog_snapshot_id": "s", "expected_version": 0,
        "selected_roots": [{"resource_id": items[0]["id"], "paths": ["src/"], "priority": 0}],
        "budgets": {"bytes": 1024, "requests": 20, "seconds": 60}}).json()

    def full_read():
        plan = c.post(f"/api/v1/scan-scope-profiles/{prof['id']}/preview", headers=auth()).json()
        response = c.post("/api/v1/scan-runs", headers=auth(), json={"plan_id": plan["plan_id"], "profile_version": 1,
                                                                      "mode": "BASELINE"})
        assert response.status_code == 202, response.text
        return uuid.UUID(response.json()["id"])

    return cid, prof, full_read


def test_a_full_scan_answers_a_repeat_request_behind_more_than_200_change_event_runs(store):
    """Change feeds queue a run per change. With more than 200 of them queued after the scope's full scan, the
    installation's newest 200 jobs no longer include it, and a repeat full read must still be answered by it."""
    from sqlalchemy import update

    from cremore.db.schema import scan_jobs

    repo = store
    cid, prof, full_read = approved_scope(repo)

    def created(job_id, at):  # pinned, so the full scan is the oldest whatever the clock's resolution
        if isinstance(repo, InMemoryRepository):
            repo.jobs[job_id].created_at = at
            return
        with repo.engine.begin() as conn:
            conn.execute(update(scan_jobs).where(scan_jobs.c.id == job_id).values(created_at=at))

    full = full_read()
    start = datetime(2026, 10, 11, 9, 0, tzinfo=UTC)
    created(full, start)
    for n in range(201):
        event = repo.enqueue_job(ScanJob(kind="scope", connection_id=cid, payload={
            "profile_id": prof["id"], "profile_version": 1, "trigger": "EVENT", "mode": "EVENT", "requested_by": "feed"}))
        created(event.id, start + timedelta(seconds=n + 1))
    assert full not in {job.id for job in repo.list_jobs(200)}
    assert full_read() == full
    assert len(repo.list_jobs(1000)) == 202


def test_a_queued_run_whose_trigger_is_json_null_answers_no_full_read(store):
    """SQL reads a JSON-null trigger as BASELINE, as it reads an absent one; the start-run check still refuses such a
    run, as the newest-200 scan it replaced did, so the request gets a run of its own."""
    cid, prof, full_read = approved_scope(store)
    odd = store.enqueue_job(ScanJob(kind="scope", connection_id=cid, payload={
        "profile_id": prof["id"], "profile_version": 1, "mode": "BASELINE", "trigger": None}))
    if not isinstance(store, InMemoryRepository):
        assert [job.id for job in store.active_scope_runs(cid, prof["id"], 1)] == [odd.id]
    assert full_read() != odd.id


def test_a_first_scan_started_after_a_schedule_poll_queued_the_full_scan_is_that_scan():
    """Saving a scope and starting its first scan are two requests; a schedule poll in between queues the scope's full
    scan, which then answers the first scan instead of a second full read beside it, unless the first scan verifies
    what it finds and the scheduled one (like every scheduled run) does not."""
    from cremore.domain.models import ScanJob
    from cremore.scanning import verification_switch

    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    repo = SqlRepository(engine)
    c = client(repo, CREDENTIAL_VERIFICATION_MODE="enabled")  # the API only queues: nothing is verified here
    cid = content_source(repo, "github", {"org": "example-org"}, name="Org", secret_ref="vault://github/org").id
    base = f"/api/v1/connections/source/{cid}"
    target = repo.get_connection(cid)
    items = [scope.resource("source", cid, "GITHUB_REPOSITORY", "example-org/app", "app", "https://github.com/example-org/app", "github.com")]
    CatalogStore(repo).refresh(ScopeCatalog(kind="source", connection_id=cid, snapshot_id="s", completeness="COMPLETE",
                                           auth_revision=scope.auth_revision("source", target), refreshed_at=datetime.now(UTC)), items)
    prof = c.post(base + "/scan-scope-profiles", headers=auth(), json={
        "name": "app", "change_reason": "approved", "catalog_snapshot_id": "s", "expected_version": 0,
        "selected_roots": [{"resource_id": items[0]["id"], "paths": ["src/"], "priority": 0}],
        "budgets": {"bytes": 1024, "requests": 20, "seconds": 60}}).json()
    approval = repo.get_plan(uuid.UUID(c.post(f"/api/v1/scan-scope-profiles/{prof['id']}/preview",
                                              headers=auth()).json()["plan_id"])).auth_revision

    def full_scan(**payload):
        return repo.enqueue_job(ScanJob(kind="scope", connection_id=cid, payload={
            "profile_id": prof["id"], "profile_version": 1, "mode": "RECONCILE", **payload}))

    def first_scan():
        plan_id = c.post(f"/api/v1/scan-scope-profiles/{prof['id']}/preview", headers=auth()).json()["plan_id"]
        response = c.post("/api/v1/scan-runs", headers=auth(), json={"plan_id": plan_id, "profile_version": 1,
                                                                      "mode": "BASELINE"})
        assert response.status_code == 202, response.text
        return uuid.UUID(response.json()["id"])

    scheduled = full_scan(requested_by="schedule", auth_revision=approval, verify=False)
    verifying = first_scan()  # verification is on: the Admin's first scan checks what it finds
    assert verifying != scheduled.id and repo.get_job(verifying).payload.get("verify") is not False
    repo.request_job_cancel(verifying)
    repo.put_setting(verification_switch.KEY, {"enabled": False}, "admin")
    assert first_scan() == scheduled.id
    assert repo.claim_next_job().id == scheduled.id
    assert first_scan() == scheduled.id  # still that scan once a worker has started it
    repo.request_job_cancel(scheduled.id)
    repo.finish_cancelled_job(scheduled.id)
    # Nothing else answers it: another approval's scheduled full scan, an Admin's own full scan, the runs that read
    # only their own paths (a change event's, a finding's rescan, a policy sweep's) and a continuation that starts part
    # way, whatever their mode.
    for other in ({"requested_by": "schedule", "auth_revision": "an-earlier-approval"},
                  {"requested_by": str(uuid.uuid4()), "auth_revision": approval},
                  {"mode": "BASELINE", "trigger": "EVENT", "requested_by": "feed", "auth_revision": approval},
                  {"mode": "BASELINE", "trigger": "RESCAN", "requested_by": str(uuid.uuid4()), "auth_revision": approval},
                  {"mode": "BASELINE", "trigger": "POLICY_SWEEP", "requested_by": "policy", "auth_revision": approval},
                  {"mode": "BASELINE", "trigger": "RESUME", "requested_by": "schedule", "auth_revision": approval}):
        waiting = full_scan(**other)
        started = first_scan()
        assert started != waiting.id and repo.get_job(started).payload["mode"] == "BASELINE"
        repo.request_job_cancel(started)
        repo.request_job_cancel(waiting.id)
