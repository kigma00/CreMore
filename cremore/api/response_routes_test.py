"""Response requests keep role, revision and delivery boundaries at the HTTP edge."""

import datetime as dt
import uuid
from types import SimpleNamespace

from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.app_test import auth, client
from cremore.api.conftest import oidc_settings
from cremore.db.repository import InMemoryRepository
from cremore.domain.models import Credential, Exposure
from cremore.governance import response


def test_report_requires_current_recipient_identity_and_refuses_secrets(issuer, monkeypatch):
    from cremore.governance import response_routing

    repo = InMemoryRepository()
    item = finding(repo)
    settings = oidc_settings()
    app = create_app(repo=repo, settings=settings, oidc_http_client=issuer)
    request_id, person_ref = str(uuid.uuid4()), str(uuid.uuid4())
    now = dt.datetime.now(dt.UTC)
    cycle = {"request_id": request_id, "cycle": 1, "completion_version": 2, "state": "REPORT_REQUIRED",
             "requested_at": (now - dt.timedelta(hours=1)).isoformat(), "requested_by": "analyst", "answer": "APPROVED",
             "assigned_to": "owner@example.test", "recipient": {"person_ref": person_ref},
             "ticket": {"system": "fake", "approval": "a1", "ticket": "t1", "approver": "u1"}}
    repo.put_setting(response.HEAD_PREFIX + str(item.id), {"version": 1, "current": cycle}, "fixture")
    monkeypatch.setattr(response_routing, "resolve", lambda *a, **kw: {"email": "owner@example.test"})
    body = {"expected_version": 1, "request_id": request_id, "report_id": str(uuid.uuid4()), "result": "DONE",
            "path": "RETIRED", "actions": ["REMOVE_PLAINTEXT", "REVOKE"],
            "explanation": "Removed the exposed copy and retired the key with the issuer.",
            "performed_at": (now - dt.timedelta(minutes=1)).isoformat()}
    path = f"/api/v1/findings/{item.id}/response"

    def signed(sub, email, verified=True, groups=("g-viewers",)):
        return {"Authorization": "Bearer " + issuer.mint(sub=sub, groups=groups,
            extra={"email": email, "email_verified": verified})}

    with TestClient(app) as c:
        owner = signed("owner-subject", "owner@example.test")
        other = signed("other-subject", "other@example.test", groups=("g-admins",))
        assert c.post(path + "/report", headers=other, json=body).status_code == 403, "admin cannot impersonate the owner"
        assert c.post(path + "/report", headers=signed("unverified", "owner@example.test", False), json=body).status_code == 403
        assert c.get(path, headers=owner).json()["can_report"] is True
        # A previous trusted sign-in must not stand in for this request's missing verified claim.
        assert c.get(path, headers=signed("owner-subject", "owner@example.test", False)).json()["can_report"] is False
        assert c.post(path + "/review", headers=owner, json={"expected_version": 1}).status_code == 403
        bad = {**body, "explanation": "Removed the key: ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"}
        refused = c.post(path + "/report", headers=owner, json=bad)
        assert refused.status_code == 422 and "ghp_" not in refused.text
        assert c.post(path + "/report", headers=owner, json={**body, "performed_at": True}).status_code == 422
        accepted = c.post(path + "/report", headers=owner, json=body)
        assert accepted.status_code == 200 and accepted.json()["state"] == "WAITING_VERIFICATION"
        assert accepted.json()["current"]["report"]["by"] == "owner-subject"
        monkeypatch.setattr(response_routing, "resolve", lambda *a, **kw: {"email": "new@example.test"})
        assert c.get(path, headers=owner).json()["can_report"] is False
        assert c.post(path + "/report", headers=owner, json=body).status_code == 403


def finding(repo):
    credential = repo.upsert_credential(Credential(fingerprint="synthetic-response", credential_type="TOKEN"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="inline",
        resource_name="synthetic", location="config", severity="HIGH"))
    return repo.upsert_finding(credential.id, exposure.id, "HIGH")


def test_response_routes_enforce_roles_before_any_delivery(issuer, monkeypatch):
    repo = InMemoryRepository()
    item = finding(repo)
    app = create_app(repo=repo, settings=oidc_settings(), oidc_http_client=issuer)
    calls = []
    app.state.ticket_http_client_factory = lambda: SimpleNamespace(close=lambda: calls.append("closed"))
    monkeypatch.setattr(response, "request_ticket", lambda *a, **kw: calls.append("sent") or {
        "state": "WAITING_OWNER", "current": {"requested_by": a[3]}})
    monkeypatch.setattr(response, "release_unknown", lambda *a, **kw: calls.append("released") or {"state": "NEEDS_ACTION"})
    body = {"to": "responder@example.test", "locale": "ko", "expected_version": 0, "request_id": str(uuid.uuid4())}
    release = {"expected_version": 1, "request_id": body["request_id"], "confirmed_no_pending_ticket": True}
    path = f"/api/v1/findings/{item.id}/response"
    with TestClient(app) as c:
        assert c.get(path).status_code == 401
        viewer = {"Authorization": "Bearer " + issuer.mint(groups=("g-viewers",))}
        analyst = {"Authorization": "Bearer " + issuer.mint(groups=("g-analysts",), extra={
            "name": "Synthetic Analyst", "email": "analyst@example.test", "email_verified": True})}
        admin = {"Authorization": "Bearer " + issuer.mint(groups=("g-admins",))}
        assert c.get(path, headers=viewer).json()["state"] == "NEW"
        assert c.post(path + "/ticket", headers=viewer, json=body).status_code == 403
        assert c.post(path + "/release-unknown", headers=analyst, json=release).status_code == 403
        assert calls == []
        sent = c.post(path + "/ticket", headers=analyst, json=body)
        assert sent.status_code == 200
        assert sent.json()["current"]["requested_by_name"] == "Synthetic Analyst"
        assert sent.json()["current"]["requested_by_email"] == "analyst@example.test"
        assert calls == ["sent", "closed"]
        assert c.post(path + "/release-unknown", headers=admin, json=release).status_code == 200
        assert calls[-1] == "released"


def test_response_api_rejects_invalid_inputs_and_closes_client_on_service_failure(monkeypatch):
    c = client()
    item = finding(c.app.state.repo)
    path = f"/api/v1/findings/{item.id}/response"
    calls = []
    c.app.state.ticket_http_client_factory = lambda: SimpleNamespace(close=lambda: calls.append("closed"))

    def conflict(*a, **kw):
        assert kw["request_id"] == request_id
        raise response.ResponseError("RESPONSE_CHANGED", 409)

    monkeypatch.setattr(response, "request_ticket", conflict)
    request_id = str(uuid.uuid4())
    body = {"to": "responder@example.test", "expected_version": 0, "request_id": request_id}
    for invalid in ({**body, "expected_version": True}, {**body, "request_id": "bad"},
                    {**body, "locale": "invalid"}, {**body, "unexpected": "SYNTHETIC_PRIVATE"}):
        result = c.post(path + "/ticket", headers=auth(), json=invalid)
        assert result.status_code == 422 and "SYNTHETIC_PRIVATE" not in result.text
    assert calls == []
    result = c.post(path + "/ticket", headers=auth(), json=body)
    assert result.status_code == 409 and result.json()["detail"] == "RESPONSE_CHANGED"
    assert calls == ["closed"]
    missing = f"/api/v1/findings/{uuid.uuid4()}/response"
    assert c.post(missing + "/ticket", headers=auth(), json=body).status_code == 404
    assert c.get(missing, headers=auth()).status_code == 404
    assert calls == ["closed"]
    release = {"expected_version": 1, "request_id": request_id, "confirmed_no_pending_ticket": "true"}
    assert c.post(path + "/release-unknown", headers=auth(), json=release).status_code == 422
