"""The routes of a plan on another provider's credential: plan it from the inventory, queue it, the worker runs it."""

from __future__ import annotations

import uuid

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.remediation import owner_approval
from cremore.remediation.provider_actions_test import (
    KEY,
    Provider,
    body,
    gcp_inventory,
    remediation,
)
from cremore.worker import JobWorker

TOKEN = "provider-actions-" + "q" * 32


@pytest.fixture
def stack(monkeypatch):
    monkeypatch.setattr("cremore_gcp_provider.onboarding._token", lambda connection, secrets: "gcp-synthetic-access")
    repo = InMemoryRepository()
    settings = Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="cd" * 32, ACTION_EXECUTION_ENABLED="true")
    app = create_app(repo=repo, settings=settings)
    google = Provider()
    worker = JobWorker(repo, orchestrator=app.state.orchestrator, settings=settings, http_client_factory=google.client)
    with TestClient(app, headers={"Authorization": "Bearer " + TOKEN}) as client:
        yield repo, client, worker, google


def test_a_plan_is_made_on_the_inventoried_key_queued_and_run_by_the_worker(stack):
    repo, client, worker, google = stack
    repo.put_setting(owner_approval.KEY, {"required": False}, "test")
    entity = gcp_inventory(repo)[KEY]
    path = f"/api/v2/coverage/inventory/{entity}/action-plans"
    blocked = client.get(path).json()
    assert blocked["plans"] == [] and blocked["policy"]["block_reason"] == "REMEDIATION_NOT_SET_UP"
    connection = remediation(repo)
    policy = client.get(path).json()["policy"]
    assert policy["can_plan"] is True and policy["supported_actions"] == ["DISABLE_PROVIDER_CREDENTIAL",
                                                                          "REVOKE_PROVIDER_CREDENTIAL"]
    assert policy["remediation_connection"] == {"id": str(connection["id"]), "name": connection["name"],
                                                "provider": connection["provider"],
                                                "auth_method": connection["auth_method"], "shared_with": []}
    created = client.post(path, json=body())
    assert created.status_code == 201, created.text
    plan = created.json()
    assert plan["target"]["kind"] == "provider_credential" and plan["target"]["reference"]["key_id"] == KEY
    approved = client.post(f"/api/v1/action-plans/{plan['id']}/approve",
                           json={"plan_hash": plan["plan_hash"], "self_approval_confirmed": True})
    assert approved.status_code == 200, approved.text
    queued = client.post(f"/api/v1/action-plans/{plan['id']}/execute", json={"plan_hash": plan["plan_hash"]})
    assert queued.status_code == 202 and queued.json()["status"] == "QUEUED"
    assert google.requests == []  # the API opened nothing
    assert worker.process_next()
    [done] = client.get(path).json()["plans"]
    assert done["status"] == "VERIFIED" and [request[0] for request in google.requests] == ["GET", "POST", "GET"]
    listed = next(item for item in client.get("/api/v1/action-plans").json()["items"] if item["id"] == plan["id"])
    assert listed["target"]["kind"] == "provider_credential" and listed["target"]["provider"] == "gcp"


def test_an_unknown_outcome_is_rechecked_by_the_worker_and_a_bad_request_is_refused(stack):
    repo, client, worker, google = stack
    repo.put_setting(owner_approval.KEY, {"required": False}, "test")
    entity = gcp_inventory(repo)[KEY]
    remediation(repo)
    path = f"/api/v2/coverage/inventory/{entity}/action-plans"
    assert client.post(path, json={**body(), "action_type": "DISABLE_ACCESS_KEY"}).status_code == 422
    assert client.get(f"/api/v2/coverage/inventory/{uuid.uuid4()}/action-plans").status_code == 404
    plan = client.post(path, json=body()).json()
    client.post(f"/api/v1/action-plans/{plan['id']}/approve",
                json={"plan_hash": plan["plan_hash"], "self_approval_confirmed": True})
    google.write_status = 502
    client.post(f"/api/v1/action-plans/{plan['id']}/execute", json={"plan_hash": plan["plan_hash"]})
    assert worker.process_next()
    unknown = client.get(path).json()["plans"][0]
    assert (unknown["status"], unknown["safe_error_code"]) == ("OUTCOME_UNKNOWN", "GCP_HTTP_502")
    stale = client.post(f"/api/v1/action-plans/{plan['id']}/recheck", json={"plan_hash": "0" * 64})
    assert stale.status_code == 409
    google.state = "DISABLED"
    rechecked = client.post(f"/api/v1/action-plans/{plan['id']}/recheck", json={"plan_hash": plan["plan_hash"]})
    assert rechecked.status_code == 202
    assert worker.process_next()
    assert client.get(path).json()["plans"][0]["status"] == "VERIFIED"


def test_an_approved_plans_queued_run_is_no_scan_an_analyst_can_cancel(stack):
    repo, client, _worker, google = stack
    repo.put_setting(owner_approval.KEY, {"required": False}, "test")
    entity = gcp_inventory(repo)[KEY]
    remediation(repo)
    plan = client.post(f"/api/v2/coverage/inventory/{entity}/action-plans", json=body()).json()
    client.post(f"/api/v1/action-plans/{plan['id']}/approve",
                json={"plan_hash": plan["plan_hash"], "self_approval_confirmed": True})
    client.post(f"/api/v1/action-plans/{plan['id']}/execute", json={"plan_hash": plan["plan_hash"]})
    [job] = [job for job in repo.list_jobs() if job.kind == "provider-credential-action"]
    assert client.post(f"/api/v1/source-scan-jobs/{job.id}/cancel").status_code == 404
    assert repo.get_job(job.id).status == "QUEUED" and google.requests == []