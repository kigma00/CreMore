"""The owner's approval of a key action plan, through the API. With company sign-in a remediator has CreMore send
the owner a link (audited before it goes, with the address it went to, never the token); only the person it went
to, signed in with a verified email, reads and decides, once, and the plan shows the decision. With the local sign-in
no link goes out and the operator records the owner's approval with its evidence."""

import datetime as dt
import json
import re
import uuid

import pytest
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.app_test import auth, client
from cremore.api.conftest import oidc_settings
from cremore.api.contact_routes_test import GH, bearer
from cremore.db.repository import InMemoryRepository
from cremore.domain.models import ActionPlan, Credential
from cremore.governance.contact_test import MAIL, TOKEN, Relay, Slack

CONSOLE = "https://cremore.example.com"


def add_plan(repo, status="APPROVED"):
    cred = repo.upsert_credential(Credential(fingerprint=uuid.uuid4().hex, credential_type="AWS_ACCESS_KEY", provider="aws"))
    return repo.create_action_plan(ActionPlan(
        credential_id=cred.id, action_type="DISABLE_ACCESS_KEY", status=status, plan_hash="a" * 64,
        requested_by="rita", approved_by="ada", reason_code="EXPOSURE_CONTAINMENT", identifier_hint="AKIA…WXYZ",
        user_name="deploy-bot", account_id="123456789012", expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=2),
        idempotency_key=str(uuid.uuid4())))


def setup(issuer, *, status="APPROVED", relay=None, console=CONSOLE):
    repo = InMemoryRepository()
    plan = add_plan(repo, status)
    client_ = TestClient(create_app(repo=repo, settings=oidc_settings(), oidc_http_client=issuer))
    relay = relay or Relay()
    client_.app.state.contact_transports = {"smtp": relay, "smtp_ssl": relay, "http_client_factory": Slack().client}
    assert client_.put("/api/v1/settings/contact-delivery", headers=bearer(issuer, "ada", "g-admins"), json={
        "mail": MAIL, "slack": {"token": TOKEN, "allowed_channels": ["#security-alerts"]}, "allowed_domains": ["example.com"],
        "console_url": console}).status_code == 200
    return repo, client_, plan, relay


def person(issuer, sub, email, **claims):
    """A signed-in person with no CreMore role (a key's owner), as oauth2-proxy hands the bearer on."""
    return {"Authorization": "Bearer " + issuer.mint(sub=sub, groups=(), extra={"email": email, **claims})}


def events(repo, plan):
    return [(event.event_type, event.actor, event.note) for event in repo.finding_events.values()
            if event.target_id == plan.id and event.event_type.startswith("OWNER_APPROVAL")]


def test_only_the_signed_in_owner_the_link_went_to_decides_once(issuer):
    repo, client, plan, relay = setup(issuer)
    remediator, analyst = bearer(issuer, "rita", "g-remediators"), bearer(issuer, "ann", "g-analysts")
    path = f"/api/v1/action-plans/{plan.id}/owner-approval"
    ask = {"channel": "mail", "to": "kim@example.com", "locale": "ko"}
    assert client.post(path, headers=analyst, json=ask).status_code == 403
    # An owner is a person: a channel's members are not.
    channel = client.post(path, headers=remediator, json={"channel": "slack", "to": "#security-alerts"})
    assert (channel.status_code, channel.json()["detail"]) == (422, "OWNER_APPROVAL_RECIPIENT_NOT_A_PERSON")
    asked = client.post(path, headers=remediator, json=ask)
    assert asked.status_code == 200, asked.text
    shown = asked.json()["owner_approval"]
    assert (shown["state"], shown["channel"], shown["recipient"]) == ("PENDING", "mail", "kim@example.com")
    [message] = relay.sent
    assert message["To"] == "kim@example.com" and message["Subject"] == "[CreMore] AWS 액세스 키 조치 승인 요청"
    token = re.search(re.escape(CONSOLE) + r"/owner-approval#([A-Za-z0-9_-]{43})$", message.get_content(), re.MULTILINE).group(1)
    # Audited before it went out, with the address and never the token.
    [(kind, actor, note)] = events(repo, plan)
    assert (kind, actor) == ("OWNER_APPROVAL_REQUESTED", "rita")
    assert re.fullmatch(r"mail · to=kim@example\.com · text=[0-9a-f]{16} · expires=\S+", note)
    assert token not in json.dumps([repo.installation_settings, [e.note for e in repo.finding_events.values()]], default=str)

    view, decide = "/api/v1/owner-approvals/view", "/api/v1/owner-approvals/decide"
    kim = person(issuer, "kim-sub", "Kim@example.com")
    # The link alone reads and decides nothing.
    for headers in ({}, {"Authorization": "Basic a2ltOng="}):
        refused = client.post(view, headers=headers, json={"token": token})
        assert (refused.status_code, refused.json()["detail"]) == (401, "OWNER_APPROVAL_SIGN_IN_REQUIRED")
    for headers, code in ((person(issuer, "lee-sub", "lee@example.com"), "OWNER_APPROVAL_NOT_RECIPIENT"),
                          (person(issuer, "kim-sub", "kim@example.com", email_verified=False), "OWNER_APPROVAL_EMAIL_UNVERIFIED"),
                          ({"Authorization": "Bearer " + issuer.mint(sub="kim-sub", groups=())}, "OWNER_APPROVAL_EMAIL_UNVERIFIED")):
        for route in (view, decide):
            refused = client.post(route, headers=headers, json={"token": token, "decision": "approve"} if route == decide else {"token": token})
            assert (refused.status_code, refused.json()["detail"]) == (403, code), (route, code)
    viewed = client.post(view, headers=kim, json={"token": token})
    assert viewed.status_code == 200 and viewed.json()["state"] == "PENDING"
    assert viewed.json()["identifier_hint"] == "AKIA…WXYZ" and "plan_hash" not in viewed.json()
    refused = client.post(view, headers=kim, json={"token": "x" * 43})
    assert (refused.status_code, refused.json()["detail"]) == (404, "OWNER_APPROVAL_LINK_INVALID")
    assert client.post(view, headers=kim, json={"token": token, "plan_id": str(plan.id)}).status_code == 422
    # No secret and no hidden text go into the owner's note.
    leaked = client.post(decide, headers=kim, json={"token": token, "decision": "approve", "note": "새 키: " + GH})
    assert (leaked.status_code, leaked.json()["detail"]) == (422, "TEXT_CONTAINS_CREDENTIAL")
    hidden = client.post(decide, headers=kim, json={"token": token, "decision": "approve", "note": "ok" + chr(0x202E)})
    assert (hidden.status_code, hidden.json()["detail"]) == (422, "OWNER_APPROVAL_NOTE_INVALID")
    approved = client.post(decide, headers=kim, json={"token": token, "decision": "approve", "note": "금요일 배포 뒤에 진행해 주세요"})
    assert approved.status_code == 200 and approved.json()["state"] == "APPROVED"
    again = client.post(decide, headers=kim, json={"token": token, "decision": "decline", "note": "새 키: " + GH})
    assert (again.status_code, again.json()["detail"]) == (409, "OWNER_APPROVAL_ALREADY_DECIDED")  # before any note check
    assert events(repo, plan)[1] == ("OWNER_APPROVAL_GRANTED", "kim-sub",
                                     f'plan_hash={"a" * 64} channel=mail to=kim@example.com note="금요일 배포 뒤에 진행해 주세요"')

    # The console shows who was asked and what they said; a granted approval is not asked again, nor recorded.
    listed = client.get("/api/v1/action-plans", headers=analyst).json()["items"][0]["owner_approval"]
    assert (listed["state"], listed["recipient"], listed["note"]) == ("APPROVED", "kim@example.com", "금요일 배포 뒤에 진행해 주세요")
    repeat = client.post(path, headers=remediator, json=ask)
    assert (repeat.status_code, repeat.json()["detail"]) == (409, "OWNER_APPROVAL_ALREADY_GRANTED") and len(relay.sent) == 1
    record = client.post(f"{path}/record", headers=remediator, json={"owner": "kim", "evidence": "mail", "decision": "approve"})
    assert (record.status_code, record.json()["detail"]) == (409, "OWNER_APPROVAL_RECORD_LOCAL_ONLY")


def test_nothing_is_sent_where_it_may_not_go_and_an_unsent_link_takes_no_decision(issuer):
    remediator = bearer(issuer, "rita", "g-remediators")
    ask = {"channel": "mail", "to": "kim@example.com"}
    _repo, client, plan, relay = setup(issuer, console="")
    no_console = client.post(f"/api/v1/action-plans/{plan.id}/owner-approval", headers=remediator, json=ask)
    assert (no_console.status_code, no_console.json()["detail"]) == (409, "OWNER_APPROVAL_CONSOLE_URL_NOT_SET")

    repo, client, plan, relay = setup(issuer)
    path = f"/api/v1/action-plans/{plan.id}/owner-approval"
    outside = client.post(path, headers=remediator, json={**ask, "to": "kim@other.test"})
    assert (outside.status_code, outside.json()["detail"]) == (422, "CONTACT_RECIPIENT_NOT_ALLOWED")
    assert not relay.sent and not events(repo, plan)

    repo, client, plan, relay = setup(issuer, relay=Relay(fail="connect"))
    failed = client.post(f"/api/v1/action-plans/{plan.id}/owner-approval", headers=remediator, json=ask)
    assert failed.status_code == 502
    assert [kind for kind, _actor, _note in events(repo, plan)] == ["OWNER_APPROVAL_REQUESTED", "OWNER_APPROVAL_NOT_SENT"]
    assert events(repo, plan)[1][2] == f"mail · {failed.json()['detail']}"
    listed = client.get("/api/v1/action-plans", headers=remediator).json()["items"][0]["owner_approval"]
    assert listed["state"] == "NOT_SENT"

    class Broken(Relay):
        def send_message(self, message):
            raise RuntimeError("relay library fault")

    repo, client, plan, relay = setup(issuer, relay=Broken())
    with pytest.raises(RuntimeError):  # an unexpected fault still ends the link, with its own code
        client.post(f"/api/v1/action-plans/{plan.id}/owner-approval", headers=remediator, json=ask)
    assert events(repo, plan)[-1][::2] == ("OWNER_APPROVAL_NOT_SENT", "mail · CONTACT_SEND_ERROR")

    repo, client, plan, relay = setup(issuer, status="CANCELLED")
    closed = client.post(f"/api/v1/action-plans/{plan.id}/owner-approval", headers=remediator, json=ask)
    assert (closed.status_code, closed.json()["detail"]) == (409, "OWNER_APPROVAL_PLAN_NOT_OPEN") and not relay.sent


def test_the_local_operator_records_the_owner_approval_instead_of_sending_a_link():
    repo = InMemoryRepository()
    plan = add_plan(repo)
    c = client(repo)
    path = f"/api/v1/action-plans/{plan.id}/owner-approval"
    link = c.post(path, headers=auth(), json={"channel": "mail", "to": "kim@example.com"})
    assert (link.status_code, link.json()["detail"]) == (409, "OWNER_APPROVAL_LINK_NEEDS_SIGN_IN")
    for route, body in (("view", {"token": "x" * 43}), ("decide", {"token": "x" * 43, "decision": "approve"})):
        refused = c.post(f"/api/v1/owner-approvals/{route}", headers=auth(), json=body)
        assert (refused.status_code, refused.json()["detail"]) == (409, "OWNER_APPROVAL_LINK_NEEDS_SIGN_IN")
    leaked = c.post(f"{path}/record", headers=auth(), json={"owner": "kim", "evidence": "키 " + GH, "decision": "approve"})
    assert (leaked.status_code, leaked.json()["detail"]) == (422, "TEXT_CONTAINS_CREDENTIAL")
    blank = c.post(f"{path}/record", headers=auth(), json={"owner": " ", "evidence": "mail", "decision": "approve"})
    assert (blank.status_code, blank.json()["detail"]) == (422, "OWNER_APPROVAL_EVIDENCE_REQUIRED")
    recorded = c.post(f"{path}/record", headers=auth(), json={
        "owner": "김개발 kim@example.com", "evidence": "회신 메일 2026-09-29", "decision": "approve", "note": "금요일 이후"})
    assert recorded.status_code == 200, recorded.text
    shown = recorded.json()["owner_approval"]
    assert (shown["state"], shown["channel"], shown["recipient"], shown["evidence"], shown["note"]) == (
        "APPROVED", "record", "김개발 kim@example.com", "회신 메일 2026-09-29", "금요일 이후")
    [(kind, _actor, note)] = events(repo, plan)
    assert kind == "OWNER_APPROVAL_RECORDED" and 'evidence="회신 메일 2026-09-29"' in note and 'owner="김개발 kim@example.com"' in note
