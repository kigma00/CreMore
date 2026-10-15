"""A contract or stored spec from before an option existed is the same scope today.

A scope digest covers every option of the model, defaults included, so a release that
only adds an option moves the digest of every stored connection and run. Synthetic,
in memory: each case builds what the earlier code stored and checks the site that
compares it.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.metadata_coverage_test import GITLAB, TOKEN, Signed, create
from cremore.config import Settings
from cremore.coverage.metadata_models import (
    MetadataConnectionSpec,
    MetadataPage,
    metadata_contract,
    same_contract,
    scope_matches,
)
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.models import digest
from cremore.coverage.storage_receipts import StorageReceiptStore
from cremore.coverage.store import CoverageError
from cremore.db.repository import InMemoryRepository

# Options added to MetadataOptions after connections and runs could have been stored.
ADDED = ("actions_run_days", "audit_scope", "enterprise_only", "run_time_limit_minutes")


def legacy_spec(spec):
    value = json.loads(json.dumps(spec))
    for key in ADDED:
        value["options"].pop(key, None)
    return value


def legacy_contract(contract, stored_spec):
    """The contract the earlier code stored: no added options, and its own digest."""
    value = json.loads(json.dumps(contract, default=str))
    for key in ADDED:
        value["spec_snapshot"]["options"].pop(key, None)
    value["scope_digest"] = digest(legacy_spec(stored_spec))
    return value


def test_a_contract_that_predates_an_option_is_the_same_scope():
    spec = MetadataConnectionSpec.model_validate(GITLAB)
    now = metadata_contract(spec).model_dump()
    old = legacy_contract(now, spec.model_dump())
    assert old["scope_digest"] != now["scope_digest"]
    assert same_contract(old, now) and scope_matches(old, spec)
    assert scope_matches(now, legacy_spec(spec.model_dump()))
    other = MetadataConnectionSpec.model_validate({**GITLAB, "scopes": [{"kind": "group", "id": "11"}]})
    assert not same_contract(old, metadata_contract(other).model_dump()) and not scope_matches(old, other)
    assert not same_contract(old, metadata_contract(spec, principal_id="another-principal").model_dump())


def test_a_receipt_accepts_a_run_whose_connection_predates_an_option():
    spec = MetadataConnectionSpec.model_validate(GITLAB)
    owner = {"enabled": True, "revision": 1, "spec": legacy_spec(spec.model_dump())}
    run = {"revision": 1, "status": "COMPLETE", "finished_at": datetime.now(UTC),
           "contract": metadata_contract(spec).model_dump()}
    StorageReceiptStore._usable(owner, run)
    changed = MetadataConnectionSpec.model_validate({**GITLAB, "scopes": [{"kind": "group", "id": "11"}]})
    with pytest.raises(CoverageError, match="RECEIPT_SCOPE_CHANGED"):
        StorageReceiptStore._usable(owner, {**run, "contract": metadata_contract(changed).model_dump()})


@pytest.fixture
def served():
    repo = InMemoryRepository()
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32))
    with TestClient(app) as raw:
        yield repo, Signed(raw)


def finished_run(client, created):
    headers = {"X-Cremore-Collector-Token": created["collector_token"]}
    config = client.get(f"/api/v2/coverage/collector/{created['id']}", headers=headers).json()
    started = client.post(f"/api/v2/coverage/collector/{created['id']}/runs", headers=headers,
                          json={"revision": 1, "request_id": str(uuid.uuid4()), "contract": config["contract"]})
    assert started.status_code == 200, started.text
    run_id = started.json()["id"]
    finished = client.post(f"/api/v2/coverage/collector/{created['id']}/runs/{run_id}/finish", headers=headers,
                           json={"batch_count": 0, "item_count": 0, "status": "PARTIAL"})
    assert finished.status_code == 200, finished.text
    return run_id


def made_before_the_option(repo, run_id):
    store = MetadataStore(repo)
    run = store.memory["runs"][uuid.UUID(run_id)]
    owner = store.memory["connections"][run["connection_id"]]
    run["contract"] = legacy_contract(run["contract"], owner["spec"])


def test_a_comparison_base_that_predates_an_option_still_compares(served):
    repo, client = served
    created = create(client, GITLAB)
    before, after = finished_run(client, created), finished_run(client, created)
    made_before_the_option(repo, before)
    response = client.get(f"/api/v2/coverage/runs/{before}/compare/{after}")
    assert response.status_code == 200, response.text


def test_a_retry_base_that_predates_an_option_is_accepted(served, monkeypatch):
    from cremore_atlassian_provider.metadata import adapter

    repo, client = served
    scope_id = "12345678-1234-4234-8234-123456789012"
    created = create(client, {"name": "Synthetic organization", "provider": "atlassian",
                              "origin": "https://api.atlassian.com",
                              "scopes": [{"kind": "organization", "id": scope_id}],
                              "capabilities": ["inventory"], "auth_type": "bearer",
                              "secret_refs": {"token": "vault://synthetic/admin"}})
    run_id = finished_run(client, created)
    made_before_the_option(repo, run_id)
    monkeypatch.setattr(adapter, "plan_recollection", lambda records, **selection: {"report_type": "metadata_recollection_plan"})
    response = client.post(f"/api/v2/coverage/connections/{created['id']}/collect",
                           json={"retry_from_run": run_id, "scope_id": scope_id, "operations": ["service-accounts"]})
    assert response.status_code == 202, response.text


def test_an_in_flight_run_that_predates_an_option_resumes(monkeypatch):
    from cremore_azure_provider.metadata import adapter

    from cremore.coverage.metadata_job_test import queued
    from cremore.db import task_store
    from cremore.worker import JobWorker

    repo = InMemoryRepository()
    now = {"value": datetime.now(UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])

    def pages(spec, *, checkpoint, **kwargs):
        if not checkpoint:
            yield MetadataPage(checkpoint={"phase": "started"})
            yield MetadataPage(checkpoint={"phase": "resume"}, status="WAITING",
                               reasons=["METADATA_RETRY_LATER"], retry_after_seconds=1)
        else:
            yield MetadataPage(checkpoint={"phase": "done"}, status="COMPLETE")

    monkeypatch.setattr(adapter, "collect_pages", pages)
    store, connection, job = queued(repo)
    worker = JobWorker(repo)
    assert worker.process_next()
    run = store.connection_runs(connection["id"])["items"][0]
    # The run was started by the earlier code; the upgrade lands while it waits.
    made_before_the_option(repo, str(run["id"]))
    now["value"] += timedelta(seconds=2)
    assert worker.process_next()
    assert repo.get_job(job.id).status == "SUCCEEDED", repo.get_job(job.id).error
    assert store.connection_runs(connection["id"])["items"][0]["status"] in ("COMPLETE", "PARTIAL")
