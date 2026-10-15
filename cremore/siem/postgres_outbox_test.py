"""Optional concurrency proofs using the guarded disposable local PostgreSQL DB."""
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from cremore.db import postgres_scan_test
from cremore.db.task_store import TaskStore
from cremore.domain.models import Credential, Exposure
from cremore.siem.outbox import SiemOutbox

pg = postgres_scan_test.pg


def _finding(repo, label):
    credential = repo.upsert_credential(Credential(fingerprint=label,
        credential_type="GITHUB_TOKEN", provider="github"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="github",
        resource_name="synthetic", location="sample", severity="HIGH"))
    return repo.upsert_finding(credential.id, exposure.id, "HIGH")


def test_postgres_concurrent_creation_records_one_event(pg):
    _engine, repo = pg
    barrier = Barrier(8)
    def create(_):
        barrier.wait()
        return _finding(repo, "same-synthetic-finding").id
    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(create, range(8)))
    assert len(set(ids)) == 1
    item, = SiemOutbox(repo).claim("sink")
    assert item["event"]["finding"]["id"] == str(ids[0])


def test_postgres_parallel_claims_and_transaction_rollback(pg):
    _engine, repo = pg
    for number in range(8):
        _finding(repo, "synthetic-" + str(number))
    barrier = Barrier(4)
    def claim(_):
        barrier.wait()
        return SiemOutbox(repo).claim("same", limit=2)
    with ThreadPoolExecutor(max_workers=4) as pool:
        batches = list(pool.map(claim, range(4)))
    ids = [item["event"]["event_id"] for batch in batches for item in batch]
    # A statement snapshot may still select a row another claimant just leased;
    # the guarded upsert rejects it. The next poll must claim every remainder.
    assert len(ids) == len(set(ids))
    ids.extend(item["event"]["event_id"] for item in SiemOutbox(repo).claim("same"))
    assert len(ids) == len(set(ids)) == 8
    assert len(SiemOutbox(repo).claim("independent")) == 8
    tasks = TaskStore(repo)
    tasks.enqueue(uuid.uuid4(), "synthetic", {"mode": "BASELINE"})
    task = tasks.claim()
    with pytest.raises(RuntimeError, match="rollback"), tasks.fenced(task["id"], task["token"]) as bound:
        finding = _finding(bound, "rollback-finding")
        raise RuntimeError("rollback")
    assert repo.get_finding(finding.id) is None
    assert SiemOutbox(repo).claim("same") == []
