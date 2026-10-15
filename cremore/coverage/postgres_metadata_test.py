"""Real PostgreSQL schema-2 publication and Worker WAITING/resume proofs.

Ported from refactor/saas-libraries during the review of the SaaS-structure integration
(2026-09-26); only the fixture and adapter import paths differ. Runs when
CREMORE_TEST_POSTGRES_URL names a disposable localhost cremore_test database.
"""

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from cremore_azure_provider.metadata import adapter

from cremore.coverage import METADATA_JOB_KIND
from cremore.coverage.metadata_models import (
    MetadataBatch,
    MetadataConnectionSpec,
    MetadataFinish,
    MetadataPage,
    metadata_contract,
)
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.store import CoverageError
from cremore.db import task_store
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- shared guarded pytest fixture
from cremore.db.task_store import TaskStore
from cremore.domain.models import ScanJob
from cremore.worker import JobWorker


def inventory():
    """Real normalization of synthetic Azure metadata; no test-module dependency or HTTP."""
    spec = MetadataConnectionSpec.model_validate({"schema_version": 2, "name": "Synthetic",
        "provider": "azure_key_vault", "origin": "https://synthetic.vault.azure.net",
        "edition": "cloud", "scopes": [{"kind": "vault", "id": "synthetic"}],
        "capabilities": ["vault_metadata"], "auth_type": "workload_identity",
        "options": {"mode": "inventory"}})

    class Vault:
        requests = 0
        options = spec.options

        def get(self, path, params=None):
            assert path == "/secrets"
            return {"value": [{"id": spec.origin + "/secrets/synthetic-name",
                "attributes": {"enabled": True, "created": 1726000000, "updated": 1758000000}}]}

    pages = adapter.collect_pages(spec, secrets={}, checkpoint={}, check=lambda: None,
                                  transport=Vault(), now=datetime(2026, 9, 26, tzinfo=UTC))
    records = [record for page in pages for record in page.records]
    assert len(records) > 1
    return spec, records


def test_postgres_metadata_concurrent_batches_are_idempotent_and_conflicts_rejected(pg):
    """Exercise native insert/locking/projection, including an actual conflicting replay."""
    _, repo = pg
    spec, records = inventory()
    store = MetadataStore(repo)
    owner, _ = store.create(spec, "synthetic")
    request_id = str(uuid.uuid4())

    def submit(_):
        run = store.start(owner["id"], 1, request_id, metadata_contract(spec).model_dump())
        store.append(owner["id"], run["id"], MetadataBatch(index=0, items=records), trusted_discovery=True)
        return run["id"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        ids = set(pool.map(submit, range(4)))
    assert len(ids) == 1
    run_id = ids.pop()
    with pytest.raises(CoverageError, match="BATCH_REPLAY_CONFLICT"):
        store.append(owner["id"], run_id, MetadataBatch(index=0, items=records[:1]), trusted_discovery=True)
    result = store.finish(owner["id"], run_id, MetadataFinish(batch_count=1,
        item_count=len(records), status="COMPLETE"))
    assert result["item_count"] == len(records)
    assert len(list(store.iter_records(run_id))) == len(records)
    assert store.inventory(connection_id=owner["id"])["total"] == 1


def test_postgres_metadata_waiting_resumes_existing_run_and_keeps_published_records(pg, monkeypatch):
    """Commit records/checkpoint, queue WAITING, then resume with a new Worker instance."""
    _, repo = pg
    spec, records = inventory()
    store, tasks = MetadataStore(repo), TaskStore(repo)
    now = {"value": datetime.now(UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    seen = []

    def pages(_spec, *, checkpoint, read_records, **kwargs):
        seen.append(checkpoint)
        if not checkpoint:
            yield MetadataPage(records=records[:1], checkpoint={"page": 1})
            yield MetadataPage(checkpoint={"page": 2}, status="WAITING",
                               reasons=["METADATA_RETRY_LATER"], retry_after_seconds=1)
        else:
            assert checkpoint == {"page": 2} and len(list(read_records())) == 1
            yield MetadataPage(records=records[1:], checkpoint={"page": 3}, status="COMPLETE")

    monkeypatch.setattr(adapter, "collect_pages", pages)
    owner, _ = store.create(spec, "synthetic")
    job = repo.enqueue_job(ScanJob(kind=METADATA_JOB_KIND, payload={"provider": spec.provider,
        "coverage_connection_id": str(owner["id"]), "coverage_revision": 1}))
    assert JobWorker(repo).process_next()
    queued = tasks.list_for_run(job.id)[0]
    assert queued["status"] == "QUEUED" and queued["checkpoint"]["next_batch"] == 1
    run_id = store.connection_runs(owner["id"])["items"][0]["id"]
    committed = list(store.iter_records(run_id))
    assert len(committed) == 1
    now["value"] += timedelta(seconds=2)
    assert JobWorker(repo).process_next()
    assert repo.get_job(job.id).status == "SUCCEEDED"
    runs = store.connection_runs(owner["id"])
    assert runs["total"] == 1 and runs["items"][0]["id"] == run_id
    assert runs["items"][0]["status"] == "COMPLETE"
    final = list(store.iter_records(run_id))
    assert len(final) == len(records) and final[:1] == committed
    assert seen == [{}, {"page": 2}]
