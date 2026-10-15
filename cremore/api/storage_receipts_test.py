"""Storage-record administration uses platform auth, never collector authority."""

import uuid

import pytest
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.auth import LOCAL_ACTOR, Principal
from cremore.config import Settings
from cremore.coverage.coverage_test import (
    ACCOUNT,
    KEY,
    TOKEN,
    USER,
    save,
    spec,
    value,
)
from cremore.coverage.coverage_test import (
    repo as repo,  # noqa: PLC0414 -- shared memory/SQL fixture
)
from cremore.coverage.models import ConnectionSpec, Observation
from cremore.coverage.store import CoverageStore
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414

BASE = "/api/v1/coverage/storage-receipts"
AUTH = {"Authorization": "Bearer " + TOKEN}
IDENTIFIER = "AKIA" + "A" * 16


def seeded(repo):
    store = CoverageStore(repo)
    issuer, token = store.create(ConnectionSpec(name="Synthetic IAM", provider="aws_iam", account_id=ACCOUNT), "setup")
    vault, _ = store.create(spec(), "setup")
    issued = save(store, issuer, [Observation(evidence="ISSUED", credential_type="AWS_ACCESS_KEY",
        identifier=IDENTIFIER, reference=USER, account_id=ACCOUNT)])
    stored = save(store, vault, [value()])
    body = {"id": str(uuid.uuid4()), "source_system": "test-rotation", "source_record_id": "rotation/42",
        "stored_at": "2026-01-01T00:00:00Z",
        "issuer": {"run_id": str(issued["id"]), "batch_index": 0, "item_index": 0},
        "vault": {"run_id": str(stored["id"]), "batch_index": 0, "item_index": 0}}
    return issuer, vault, token, body


def test_storage_record_round_trip_filters_replay_and_revocation(repo):
    issuer, vault, token, body = seeded(repo)
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY=KEY.hex()))
    with TestClient(app) as api:
        baseline = api.get("/api/v1/coverage", headers=AUTH).json()["summary"]
        assert api.get(BASE).status_code == 401
        assert api.post(BASE, headers={"X-Cremore-Collector-Token": token}, json=body).status_code == 401
        choices = api.get(BASE + "/connections", headers=AUTH)
        assert choices.status_code == 200
        assert {item["id"] for item in choices.json()["items"]} == {str(issuer["id"]), str(vault["id"])}
        runs = api.get(f"{BASE}/connections/{issuer['id']}/runs", headers=AUTH).json()
        assert runs["items"][0]["id"] == body["issuer"]["run_id"]
        candidates = api.get(BASE + "/observations", params={"run_id": runs["items"][0]["id"], "role": "issuer"}, headers=AUTH)
        assert candidates.status_code == 200 and candidates.json()["items"][0]["anchor"] == body["issuer"]
        created = api.post(BASE, json=body, headers=AUTH)
        assert created.status_code == 201, created.text
        receipt = created.json()
        assert receipt["submitted_by"] == LOCAL_ACTOR and receipt["applicable"]
        assert receipt["state"] == "STORAGE_RECORDED"
        assert api.post(BASE, json=body, headers=AUTH).json() == receipt
        assert api.post(BASE, json=body | {"source_record_id": "different"}, headers=AUTH).status_code == 409
        query = {"issuer_connection_id": str(issuer["id"]), "issuer_identifier": IDENTIFIER}
        assert api.get(BASE, params=query, headers=AUTH).json()["total"] == 1
        assert api.get(BASE, params=query | {"issuer_identifier": "other"}, headers=AUTH).json()["total"] == 0
        assert api.get(BASE, params={"issuer_entity_id": str(uuid.uuid4())}, headers=AUTH).json()["total"] == 0
        assert api.get(BASE, params={"issuer_identifier": "bad\nquery"}, headers=AUTH).status_code in (409, 422)
        assert "fingerprint" not in created.text and "collector_token" not in created.text
        assert token not in created.text + candidates.text + choices.text
        assert api.get("/api/v1/coverage", headers=AUTH).json()["summary"] == baseline
        revoked = api.post(f"{BASE}/{body['id']}/revoke", headers=AUTH)
        assert revoked.status_code == 200 and revoked.json()["state"] == "REVOKED"
        assert not revoked.json()["applicable"]
        assert api.post(BASE, json=body, headers=AUTH).json() == revoked.json()
        assert api.post(f"{BASE}/{body['id']}/revoke", headers=AUTH).json() == revoked.json()
        assert api.get("/api/v1/coverage", headers=AUTH).json()["summary"] == baseline


@pytest.mark.parametrize("role", ["viewer", "analyst", "remediator", "admin"])
def test_platform_role_enforced_for_each_administrative_route(repo, monkeypatch, role):
    issuer, _, _, body = seeded(repo)
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="oidc", OIDC_ISSUER_URL="https://idp.example.test",
        OIDC_AUDIENCE="cremore", FINGERPRINT_KEY=KEY.hex()))
    monkeypatch.setattr(app.state.oidc_verifier, "verify", lambda _: Principal(subject="synthetic-user", role=role))
    with TestClient(app) as api:
        assert api.get(BASE, headers=AUTH).status_code == 200
        calls = [("GET", BASE + "/connections", None),
            ("GET", f"{BASE}/connections/{issuer['id']}/runs", None),
            ("GET", f"{BASE}/observations?run_id={body['issuer']['run_id']}&role=issuer", None),
            ("POST", BASE, body), ("POST", f"{BASE}/{body['id']}/revoke", None)]
        for method, path, payload in calls:
            response = api.request(method, path, headers=AUTH, **({"json": payload} if payload else {}))
            expected = (201 if path == BASE else 200) if role == "admin" else 403
            assert response.status_code == expected


def test_invalid_observation_or_untrusted_extra_fields_cannot_assert_storage(repo):
    _, _, _, body = seeded(repo)
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY=KEY.hex()))
    with TestClient(app) as api:
        assert api.post(BASE, json=body | {"issuer": body["vault"]}, headers=AUTH).status_code == 409
        for changes in ({"submitted_by": "forged-admin"}, {"stored_at": "2999-01-01T00:00:00Z"}, {"token": "synthetic-secret"}):
            response = api.post(BASE, json=body | changes, headers=AUTH)
            assert response.status_code == 422 and "synthetic-secret" not in response.text
        assert api.get(BASE, headers=AUTH).json()["total"] == 0
        assert api.post(f"{BASE}/{uuid.uuid4()}/revoke", headers=AUTH).status_code == 404


def test_public_certificate_filter_returns_separate_evidence_without_value_match_counts(repo):
    from cremore_azure_provider.public_certificates_test import certificate

    from cremore.coverage.certificate_coverage_test import pair

    pair(repo, certificate.__wrapped__())
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY=KEY.hex()))
    with TestClient(app) as api:
        response = api.get("/api/v1/coverage", params={"state": "PUBLIC_CERTIFICATE_MATCH"}, headers=AUTH)
        assert response.status_code == 200, response.text
        data = response.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["match_basis"] == "PUBLIC_CERTIFICATE_SHA256"
        assert data["summary"]["matched"] == data["summary"]["exposed"] == 0
        assert "PRIVATE_KEY_STORAGE_NOT_PROVEN" in data["items"][0]["reasons"]
