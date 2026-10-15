"""Secret-scanning reports commit only while the source authorization is current."""

import pytest

from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import Connection, ScanJob
from cremore.worker import JobWorker

PREVIOUS = {"collection_status": "COMPLETE", "alerts": [{"number": "1"}], "counts": {"alerts": 1}}
CURRENT = {"collection_status": "COMPLETE", "alerts": [{"number": "2"}], "counts": {"alerts": 1}}


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        yield InMemoryRepository()
        return
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    try:
        yield SqlRepository(engine)
    finally:
        engine.dispose()


def queued(repo):
    conn = repo.create_connection(Connection(
        provider="github", name="Synthetic repository", config={"owner": "example", "repo": "fixture"},
        secret_ref="vault://github/fixture", status="ACTIVE", secret_scanning=PREVIOUS))
    job = repo.enqueue_job(ScanJob(kind="github-secret-scanning", connection_id=conn.id,
        payload={"provider": "github", "owner": "example", "repo": "fixture", "secret_ref": conn.secret_ref}))
    return conn, job


def change_authorization(repo, conn, change):
    updates = {
        "disabled": {"status": "DISABLED"},
        "revoked": {"credential_evidence": {"revoked_at": "2026-10-03T00:00:00+00:00"}},
        "replaced": {"secret_ref": "vault://github/replacement"},
    }
    repo.update_connection(conn.id, **updates[change])


@pytest.mark.parametrize("change", ["disabled", "revoked", "replaced"])
@pytest.mark.parametrize("when", ["before_read", "during_read", "during_failed_read"])
def test_secret_scanning_stale_authorization_preserves_previous_report(repo, change, when):
    conn, job = queued(repo)
    reads = []
    if when == "before_read":
        change_authorization(repo, conn, change)

    def reader(current):
        reads.append(current.id)
        change_authorization(repo, conn, change)
        if when == "during_failed_read":
            raise RuntimeError("synthetic provider detail must not reach report")
        return CURRENT

    assert JobWorker(repo, secret_scanning_reader=reader).process_next()
    saved = repo.get_job(job.id)
    assert saved.status == "FAILED"
    assert saved.error == ("CONNECTION_CREDENTIAL_CHANGED" if change == "replaced" else "CONNECTION_PAUSED")
    assert reads == ([] if when == "before_read" else [job.id])
    assert repo.get_connection(conn.id).secret_scanning == PREVIOUS


@pytest.mark.parametrize("failed", [False, True])
def test_secret_scanning_current_authorization_still_records_safe_report(repo, failed):
    conn, job = queued(repo)

    def reader(current):
        assert current.id == job.id
        if failed:
            raise RuntimeError("synthetic provider detail must not reach report")
        return CURRENT

    assert JobWorker(repo, secret_scanning_reader=reader).process_next()
    assert repo.get_job(job.id).status == "SUCCEEDED"
    saved = repo.get_connection(conn.id).secret_scanning
    if failed:
        assert saved["collection_status"] == "FAILED" and saved["reason_code"] == "RuntimeError"
        assert "synthetic provider detail" not in str(saved)
    else:
        assert saved == CURRENT
