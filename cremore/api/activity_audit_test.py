"""Team activity is attributed only after verification, durable, and free of request secrets."""

import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from cremore.api.app import create_app
from cremore.api.conftest import oidc_settings
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- optional isolated PostgreSQL fixture
)
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import FindingEvent
from cremore.operations import audit_integrity


@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def stack(request, issuer, tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'audit.db'}") if request.param == "sqlite" else None
    if engine is not None:
        create_all(engine)
    repo = (request.getfixturevalue("pg")[1] if request.param == "postgres" else
            SqlRepository(engine) if engine is not None else InMemoryRepository())
    settings = oidc_settings()
    app = create_app(repo=repo, settings=settings, oidc_http_client=issuer)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield repo, client, settings
    if engine is not None:
        engine.dispose()


def headers(issuer, **extra):
    return {"Authorization": "Bearer " + issuer.mint(sub="alice", groups=("g-admins",),
            extra={"name": "Alice", "email": "alice@example.test", "sid": "private-session", **extra})}


def events(repo, kind):
    return [event for event in repo.list_events(1000) if event.event_type == kind]


def test_session_and_reads_are_attributed_without_storing_token_or_query(stack, issuer):
    repo, client, settings = stack
    auth = headers(issuer)
    for _ in range(2):
        assert client.get("/api/v1/session?code=private-code", headers=auth).status_code == 200
    assert len(events(repo, "AUTH_SESSION_OBSERVED")) == 1
    completed = events(repo, "API_REQUEST_SUCCEEDED")
    assert len(completed) == 2
    info = json.loads(completed[0].note)
    assert completed[0].actor == "alice"
    assert info["name"] == "Alice" and info["email"] == "alice@example.test"
    assert info["route"] == "/api/v1/session" and info["status"] == 200
    stored = str([event.model_dump() for event in repo.list_events(1000)])
    for secret in (auth["Authorization"].removeprefix("Bearer "), "private-session", "private-code"):
        assert secret not in stored
    audit_integrity.seal(repo, settings)
    assert audit_integrity.walk(repo, settings)["state"] == "INTACT"


def test_session_deduplication_survives_parallel_requests_and_api_restart(stack, issuer):
    repo, client, settings = stack
    auth = headers(issuer)
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _: client.get("/api/v1/session", headers=auth), range(8)))
    assert all(response.status_code == 200 for response in responses)
    with TestClient(create_app(repo=repo, settings=settings, oidc_http_client=issuer)) as other:
        assert other.get("/api/v1/session", headers=auth).status_code == 200
    assert len(events(repo, "AUTH_SESSION_OBSERVED")) == 1
    assert client.get("/api/v1/session", headers=headers(issuer, sid="another-session")).status_code == 200
    assert len(events(repo, "AUTH_SESSION_OBSERVED")) == 2


def test_permissions_validation_and_unknown_identity_are_recorded(stack, issuer):
    repo, client, _ = stack
    viewer = {"Authorization": "Bearer " + issuer.mint(sub="reader", groups=("g-viewers",))}
    assert client.post("/api/v1/scan", headers=viewer, json={"text": "private-body"}).status_code == 403
    denied = events(repo, "API_REQUEST_DENIED")[0]
    assert denied.actor == "reader" and json.loads(denied.note)["status"] == 403
    assert client.post("/api/v1/scan", headers=headers(issuer), json={"unexpected": "private-body"}).status_code == 422
    assert client.get("/api/v1/session", headers={"Authorization": "Bearer forged-private-token"}).status_code == 401
    assert events(repo, "API_REQUEST_DENIED")[0].actor == "UNKNOWN"
    assert client.get("/api/v1/session", headers=headers(issuer, email_verified=False)).status_code == 200
    assert json.loads(events(repo, "API_REQUEST_SUCCEEDED")[0].note)["email"] is None
    stored = str([event.model_dump() for event in repo.list_events(1000)])
    assert "private-body" not in stored and "forged-private-token" not in stored


def test_authenticated_write_is_blocked_when_audit_cannot_be_written(stack, issuer, monkeypatch):
    repo, client, _ = stack
    # A real write route must not reach the scanner when its initial receipt cannot be saved.
    called = []
    monkeypatch.setattr(client.app.state.orchestrator, "scan_resource", lambda *a, **kw: called.append(True))
    def fail(*a, **kw):
        raise RuntimeError("private-database-error")
    monkeypatch.setattr(repo, "record_finding_event", fail)
    assert client.post("/api/v1/scan", headers=headers(issuer), json={"text": "nothing"}).status_code == 503
    assert called == []


def test_http_failure_and_public_audit_fields(stack, issuer, monkeypatch):
    repo, client, _ = stack
    def fail(*a, **kw):
        raise RuntimeError("private-exception")
    monkeypatch.setattr(client.app.state.orchestrator, "scan_resource", fail)
    assert client.post("/api/v1/scan", headers=headers(issuer), json={"text": "private-body"}).status_code == 500
    row = events(repo, "API_REQUEST_FAILED")[0]
    assert json.loads(row.note)["status"] == 500
    rows = client.get("/api/v1/audit", headers=headers(issuer)).json()
    public = next(item for item in rows if item["id"] == str(row.id))
    assert public["actor_name"] == "Alice" and public["actor_email"] == "alice@example.test"
    assert public["activity"]["method"] == "POST"
    assert public["activity"]["route"] == "/api/v1/scan"
    assert "private-exception" not in str(rows) and "private-body" not in str(rows)


def test_uuid_target_and_accepted_work_are_distinct_from_completion(stack, issuer):
    repo, client, _ = stack
    target = str(uuid.uuid4())
    assert client.get(f"/api/v1/scan-jobs/{target}", headers=headers(issuer)).status_code == 404
    info = json.loads(events(repo, "API_REQUEST_FAILED")[0].note)
    assert info["targets"] == {"job_id": target}
    assert info["route"] == "/api/v1/scan-jobs/{job_id}"
    assert client.post("/api/v1/scan", headers=headers(issuer), json={"text": "no credentials"}).status_code == 202
    accepted = events(repo, "API_REQUEST_ACCEPTED")[0]
    assert json.loads(accepted.note)["status"] == 202
    started = next(row for row in events(repo, "API_REQUEST_STARTED") if row.target_id == accepted.target_id)
    assert started.actor == accepted.actor == "alice"


def test_old_domain_rows_use_current_exact_subject_profile_without_rewriting_evidence(stack, issuer):
    repo, client, settings = stack
    old = FindingEvent(actor="alice", target_type="connection", target_id=uuid.uuid4(), event_type="CONNECTION_STOPPED")
    other = FindingEvent(actor="never-signed-in", target_type="connection", target_id=uuid.uuid4(), event_type="CONNECTION_STOPPED")
    old = repo.record_finding_event(old)
    other = repo.record_finding_event(other)
    before = next(row.model_dump() for row in repo.list_events(1000) if row.id == old.id)
    assert client.get("/api/v1/session", headers=headers(issuer)).status_code == 200
    snapshot = events(repo, "API_REQUEST_SUCCEEDED")[0]
    # A changed display profile in the SAME session updates old rows, but never the event's snapshot or actor.
    rows = client.get("/api/v1/audit", headers=headers(issuer, name="Alice Updated", email_verified=False)).json()
    row = next(row for row in rows if row["id"] == str(old.id))
    assert row["actor_id"] == "alice" and row["actor_name"] == "Alice Updated" and row["actor_email"] is None
    assert row["actor_profile_basis"] == "CURRENT_SIGN_IN"
    prior = next(row for row in rows if row["id"] == str(snapshot.id))
    assert prior["actor_name"] == "Alice" and prior["actor_email"] == "alice@example.test"
    assert prior["actor_profile_basis"] == "EVENT_SNAPSHOT"
    assert "actor_name" not in next(row for row in rows if row["id"] == str(other.id))
    assert next(row.model_dump() for row in repo.list_events(1000) if row.id == old.id) == before
    assert len(events(repo, "AUTH_SESSION_OBSERVED")) == 1
    audit_integrity.seal(repo, settings)
    assert audit_integrity.walk(repo, settings)["state"] == "INTACT"


def test_result_write_failure_preserves_start_but_does_not_claim_success(stack, issuer, monkeypatch):
    repo, client, _ = stack
    original = repo.record_finding_event
    def fail_result(event):
        if event.event_type == "API_REQUEST_ACCEPTED":
            raise RuntimeError("private-write-error")
        return original(event)
    monkeypatch.setattr(repo, "record_finding_event", fail_result)
    response = client.post("/api/v1/scan", headers=headers(issuer), json={"text": "nothing"})
    assert response.status_code == 503 and response.json()["error"] == "AUDIT_RECORDING_UNAVAILABLE"
    assert len(events(repo, "API_REQUEST_STARTED")) == 1
    assert not events(repo, "API_REQUEST_ACCEPTED")
