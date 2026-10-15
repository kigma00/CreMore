"""Exposure responses through the API: an analyst asks by Slack or mail (company sign-in), CreMore sends its own
message with a link, and the person it went to answers on the link page signed in with the company IdP, with no
platform role. The local operator records the request instead. The ticket channel stays the default and works through
a plugin ticket system. Fakes only (contact transports, a fake directory, a fake ticket adapter)."""

import datetime as dt
import json
import re
import uuid

import pytest
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.app_test import GH, auth, client
from cremore.api.conftest import AUDIENCE, oidc_settings
from cremore.api.contact_routes_test import bearer
from cremore.db.repository import InMemoryRepository
from cremore.domain.models import ActionPlan, Credential, Exposure
from cremore.governance import response, response_reports, response_routing
from cremore.governance.contact_test import MAIL, TOKEN, Relay, Slack
from cremore.governance.response_link_test import PERSON, Directory
from cremore.identity import sign_in_groups
from cremore.identity.sign_in_groups_test import GOOGLE, GoogleIssuer, google_settings
from cremore.ticketing.ticketing_test import SETUP, Tickets
from cremore.ticketing.ticketing_test import (
    plugin as plugin,  # noqa: PLC0414 -- the installed fake ticket adapter
)

CONSOLE = "https://cremore.example.com"
PATH = "private/app/.env"
LINK = re.compile(re.escape(CONSOLE) + r"/response#([A-Za-z0-9_-]{43})")
VIEW, ANSWER, OPTIONS = ("/api/v1/response-links/" + action for action in ("view", "answer", "evidence-options"))


@pytest.fixture
def directory(monkeypatch):
    found = Directory()
    monkeypatch.setattr(response_routing, "resolve", found)
    return found


def add_finding(repo, identifier="AKIA" + "A" * 16):
    credential = repo.upsert_credential(Credential(fingerprint=uuid.uuid4().hex, credential_type="AWS_ACCESS_KEY",
                                                   provider="aws", identifier=identifier, identifier_hint="AKIA••••AAAA"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="github",
                                             resource_name="acme/private-repo", location=PATH, severity="HIGH"))
    finding = repo.upsert_finding(credential.id, exposure.id, "HIGH")
    plan = repo.create_action_plan(ActionPlan(credential_id=credential.id, key_id=identifier,
        action_type="PUBLISH_ACCESS_KEY_ROTATION", status="VERIFIED", plan_hash="c" * 64,
        idempotency_key=str(uuid.uuid4())))  # a replacement the report may name
    return finding, plan


def person(issuer, sub, email, **claims):
    """A signed-in person with no CreMore role, as oauth2-proxy hands the bearer on."""
    return {"Authorization": "Bearer " + issuer.mint(sub=sub, groups=(), extra={"email": email, **claims})}


def setup(issuer):
    repo = InMemoryRepository()
    item, plan = add_finding(repo)
    c = TestClient(create_app(repo=repo, settings=oidc_settings(), oidc_http_client=issuer))
    slack, relay = Slack(), Relay()
    c.app.state.contact_transports = {"smtp": relay, "smtp_ssl": relay, "http_client_factory": slack.client}
    assert c.put("/api/v1/settings/contact-delivery", headers=bearer(issuer, "ada", "g-admins"), json={
        "mail": MAIL, "slack": {"token": TOKEN, "allowed_channels": ["#security-alerts"]},
        "allowed_domains": ["example.com"], "console_url": CONSOLE}).status_code == 200
    return repo, c, item, plan, slack


def ask(c, issuer, item, *, version=0, **body):
    return c.post(f"/api/v1/findings/{item.id}/response/ticket", headers=bearer(issuer, "ann", "g-analysts"),
                  json={"expected_version": version, "request_id": str(uuid.uuid4()), "person_ref": PERSON,
                        "channel": "slack", **body})


def report(token, **changes):
    """Done after the request was asked (the server's clock is read after this one)."""
    return {"token": token, "report_id": str(uuid.uuid4()), "result": "DONE", "path": "RETIRED",
            "actions": ["REMOVE_PLAINTEXT", "REVOKE"], "performed_at": dt.datetime.now(dt.UTC).isoformat(),
            "explanation": "Removed the published copy and revoked the old key with the issuer.", **changes}


def test_the_person_asked_answers_on_the_link_page_and_nobody_else_can(issuer, directory):
    repo, c, item, plan, slack = setup(issuer)
    assert ask(c, issuer, item, channel="Slack").status_code == 422  # no such channel
    assert ask(c, issuer, item, channel="record").json()["detail"] == "RESPONSE_RECORD_LOCAL_ONLY"
    asked = ask(c, issuer, item)
    assert asked.status_code == 200, asked.text
    shown = asked.json()
    assert (shown["state"], shown["current"]["channel"], shown["current"]["link_expired"], shown["can_request"]) == (
        "WAITING_OWNER", "slack", False, False)
    token = LINK.search(slack.calls[-1][1]["text"]).group(1)
    assert token not in json.dumps(shown) and "digest" not in json.dumps(shown)
    kim = person(issuer, "kim-sub", "Kim@example.com")
    # The link alone reads nothing; only the person it went to, signed in with a verified address, does.
    for headers, status, code in (({}, 401, "RESPONSE_LINK_SIGN_IN_REQUIRED"),
                                  ({"Authorization": "Basic a2ltOng="}, 401, "RESPONSE_LINK_SIGN_IN_REQUIRED"),
                                  (person(issuer, "kim-sub", "kim@example.com", email_verified=False), 403,
                                   "RESPONSE_LINK_EMAIL_UNVERIFIED"),
                                  ({"Authorization": "Bearer " + issuer.mint(sub="kim-sub", groups=())}, 403,
                                   "RESPONSE_LINK_EMAIL_UNVERIFIED"),
                                  (person(issuer, "lee-sub", "lee@example.com"), 403, "RESPONSE_LINK_NOT_RECIPIENT"),
                                  # A CreMore role is no stand-in for the recipient either.
                                  ({"Authorization": "Bearer " + issuer.mint(sub="ada", groups=("g-admins",), extra={
                                      "email": "ada@example.com"})}, 403, "RESPONSE_LINK_NOT_RECIPIENT")):
        for route, body in ((VIEW, {"token": token}), (ANSWER, report(token)), (OPTIONS, {"token": token})):
            refused = c.post(route, headers=headers, json=body)
            assert (refused.status_code, refused.json()["detail"]) == (status, code), (route, code)
    assert c.post(VIEW, headers={"Authorization": "Bearer " + TOKEN}, json={"token": token}).status_code == 401
    assert c.post(VIEW, headers=kim, json={"token": "x" * 43}).json()["detail"] == "RESPONSE_LINK_INVALID"
    assert c.post(VIEW, headers=kim, json={"token": token, "finding_id": str(item.id)}).status_code == 422
    viewed = c.post(VIEW, headers=kim, json={"token": token})
    assert viewed.status_code == 200 and viewed.json()["can_answer"] is True
    assert viewed.json()["finding"] == {"provider": "aws", "credential_type": "AWS_ACCESS_KEY",
                                        "identifier_hint": "AKIA••••AAAA", "locations": 1}
    text = viewed.text  # never a secret, a location, an address or another person's anything
    assert all(value not in text for value in ("@", PATH, "private-repo", "AKIA" + "A" * 16, "kim"))
    # The replacement search is the link's own finding's, as the console's.
    _other, other_plan = add_finding(repo, identifier="AKIA" + "B" * 16)
    options = c.post(OPTIONS, headers=kim, json={"token": token, "q": ""}).json()
    assert options == c.get(f"/api/v1/findings/{item.id}/response/evidence-options",
                            headers=bearer(issuer, "ann", "g-analysts")).json()
    assert [row["id"] for row in options["plans"]] == [str(plan.id)] and str(other_plan.id) not in json.dumps(options)
    # The directory still has to name the person at that address.
    directory.email = "kim.new@example.com"
    assert c.post(VIEW, headers=kim, json={"token": token}).json()["detail"] == "RESPONSE_LINK_NOT_RECIPIENT"
    directory.email = None
    assert c.post(ANSWER, headers=kim, json=report(token)).json()["detail"] == "RESPONSE_LINK_NOT_RECIPIENT"
    directory.email = "kim@example.com"

    leaked = c.post(ANSWER, headers=kim, json=report(token, explanation="Rotated it, the old one was " + GH))
    assert (leaked.status_code, leaked.json()["detail"]) == (422, "RESPONSE_REPORT_TEXT_INVALID") and GH not in leaked.text
    declined = c.post(ANSWER, headers=kim, json=report(token, result="INCOMPLETE", path="EXCEPTION", actions=[],
                                                        explanation="Our deploy job still reads it; replacing it next week."))
    assert declined.status_code == 200, declined.text
    assert (declined.json()["request"]["state"], declined.json()["request"]["answer"]) == ("NEEDS_ACTION", "DECLINED")
    done = c.post(ANSWER, headers=kim, json=report(token, path="REPLACED", replacement_plan_id=str(plan.id),
                                                   actions=["REMOVE_PLAINTEXT", "ROTATE", "STORE_REPLACEMENT", "CUTOVER"]))
    assert (done.json()["request"]["state"], done.json()["request"]["answer"], done.json()["report"]["version"]) == (
        "WAITING_VERIFICATION", "APPROVED", 2)
    current = c.get(f"/api/v1/findings/{item.id}/response", headers=bearer(issuer, "ann", "g-analysts")).json()["current"]
    assert (current["answered_by"], current["report"]["basis"]) == ("kim-sub", "VERIFIED_IDP_RECIPIENT")
    # A later state takes no answer; the page says so.
    head, value = response._current(repo, str(item.id))
    repo.put_setting(response.HEAD_PREFIX + str(item.id), {**head, "current": {**value, "state": "COMPLETED"}}, "fixture")
    assert c.post(VIEW, headers=kim, json={"token": token}).json()["can_answer"] is False
    for route, body in ((ANSWER, report(token)), (OPTIONS, {"token": token})):
        closed = c.post(route, headers=kim, json=body)
        assert (closed.status_code, closed.json()["detail"]) == (409, "RESPONSE_LINK_CLOSED")


def test_an_ended_link_says_so_and_a_new_request_replaces_it(issuer, directory):
    repo, c, item, _plan, slack = setup(issuer)
    first = ask(c, issuer, item).json()
    token = LINK.search(slack.calls[-1][1]["text"]).group(1)
    kim = person(issuer, "kim-sub", "kim@example.com")
    head, value = response._current(repo, str(item.id))
    ended = {**value, "link": {**value["link"], "expires_at": "2020-01-01T00:00:00+00:00"}}
    repo.put_setting(response.HEAD_PREFIX + str(item.id), {**head, "current": ended}, "fixture")
    for route, body in ((VIEW, {"token": token}), (ANSWER, report(token)), (OPTIONS, {"token": token})):
        expired = c.post(route, headers=kim, json=body)
        assert (expired.status_code, expired.json()["detail"]) == (410, "RESPONSE_LINK_EXPIRED")
    shown = c.get(f"/api/v1/findings/{item.id}/response", headers=bearer(issuer, "ann", "g-analysts")).json()
    assert (shown["current"]["link_expired"], shown["can_request"]) == (True, True)
    # The console's own report is refused for an ended link too: the person is asked again instead.
    with_role = {"Authorization": "Bearer " + issuer.mint(sub="kim-sub", groups=("g-viewers",), extra={
        "email": "kim@example.com"})}
    body = {key: value for key, value in report(token).items() if key != "token"}
    console = c.post(f"/api/v1/findings/{item.id}/response/report", headers=with_role,
                     json={**body, "expected_version": first["version"], "request_id": first["current"]["request_id"]})
    assert (console.status_code, console.json()["detail"]) == (410, "RESPONSE_LINK_EXPIRED")
    again = ask(c, issuer, item, version=first["version"], channel="mail")
    assert again.status_code == 200 and again.json()["current"]["cycle"] == 2
    replaced = c.post(VIEW, headers=kim, json={"token": token})
    assert (replaced.status_code, replaced.json()["detail"]) == (404, "RESPONSE_LINK_INVALID")


def test_the_recipient_with_a_console_role_answers_by_the_console_report_too(issuer, directory):
    _repo, c, item, _plan, _slack = setup(issuer)
    asked = ask(c, issuer, item).json()
    kim = {"Authorization": "Bearer " + issuer.mint(sub="kim-sub", groups=("g-viewers",), extra={
        "email": "kim@example.com", "email_verified": True})}
    status = c.get(f"/api/v1/findings/{item.id}/response", headers=kim).json()
    assert status["can_report"] is True  # no ticket approval is needed for a Slack request
    body = {key: value for key, value in report("x").items() if key != "token"}
    answered = c.post(f"/api/v1/findings/{item.id}/response/report", headers=kim,
                      json={**body, "expected_version": asked["version"], "request_id": asked["current"]["request_id"]})
    assert answered.status_code == 200, answered.text
    assert (answered.json()["state"], answered.json()["current"]["answer"]) == ("WAITING_VERIFICATION", "APPROVED")


def test_a_console_viewer_whose_address_only_folds_to_the_recipients_cannot_answer(issuer, directory):
    repo, c, item, _plan, _slack = setup(issuer)
    asked = ask(c, issuer, item).json()
    before = [(e.event_type, e.note) for e in repo.list_finding_events(item.id)]
    kelvin = {"Authorization": "Bearer " + issuer.mint(sub="kelvin-sub", groups=("g-viewers",), extra={
        "email": "\u212aim@example.com", "email_verified": True})}  # KELVIN SIGN: casefold() makes it "kim@…"
    assert c.get(f"/api/v1/findings/{item.id}/response", headers=kelvin).json()["can_report"] is False
    body = {key: value for key, value in report("x").items() if key != "token"}
    refused = c.post(f"/api/v1/findings/{item.id}/response/report", headers=kelvin,
                     json={**body, "expected_version": asked["version"], "request_id": asked["current"]["request_id"]})
    assert (refused.status_code, refused.json()["detail"]) == (403, "RESPONSE_REPORT_RECIPIENT_REQUIRED")
    after = c.get(f"/api/v1/findings/{item.id}/response", headers=bearer(issuer, "ann", "g-analysts")).json()
    assert (after["state"], after["current"]["answer"], after["version"]) == ("WAITING_OWNER", None, asked["version"])
    assert repo.list_settings(response_reports.PREFIX) == []  # no report stored
    assert [(e.event_type, e.note) for e in repo.list_finding_events(item.id)] == before  # no audit row


def test_a_company_google_account_only_opens_a_link():
    issuer = GoogleIssuer()
    repo = InMemoryRepository()
    repo.put_setting(sign_in_groups.KEY, {"domain": "acme.com"}, "worker")
    c = TestClient(create_app(repo=repo, settings=google_settings(), oidc_http_client=issuer))

    def holder(**extra):
        token = issuer.mint(sub=str(uuid.uuid4()), groups=(), issuer=GOOGLE, audience=AUDIENCE,
                            extra={"email": "kim@acme.com", "email_verified": True, "hd": "acme.com", **extra})
        return {"Authorization": "Bearer " + token}

    consumer = c.post(VIEW, headers=holder(hd=""), json={"token": "x" * 43})  # a personal Google account
    assert (consumer.status_code, consumer.json()["detail"]) == (403, "RESPONSE_LINK_EMAIL_UNVERIFIED")
    workspace = c.post(VIEW, headers=holder(), json={"token": "x" * 43})
    assert (workspace.status_code, workspace.json()["detail"]) == (404, "RESPONSE_LINK_INVALID")


def test_the_local_operator_records_the_request_and_links_need_company_sign_in():
    repo = InMemoryRepository()
    item, _plan = add_finding(repo)
    c = client(repo)
    path = f"/api/v1/findings/{item.id}/response"
    for route, body in ((VIEW, {"token": "x" * 43}), (ANSWER, report("x" * 43)), (OPTIONS, {"token": "x" * 43})):
        refused = c.post(route, headers=auth(), json=body)  # the admin token is no person's sign-in
        assert (refused.status_code, refused.json()["detail"]) == (409, "RESPONSE_LINK_NEEDS_SIGN_IN")
    body = {"expected_version": 0, "request_id": str(uuid.uuid4()), "to": "kim@example.com"}
    slack = c.post(path + "/ticket", headers=auth(), json={**body, "channel": "slack"})
    assert (slack.status_code, slack.json()["detail"]) == (409, "RESPONSE_LINK_NEEDS_SIGN_IN")
    recorded = c.post(path + "/ticket", headers=auth(), json={**body, "channel": "record"})
    assert recorded.status_code == 200 and recorded.json()["state"] == "WAITING_OWNER"
    assert c.get(path, headers=auth()).json()["can_report"] is True
    statement = {key: value for key, value in report("x").items() if key != "token"}
    answered = c.post(path + "/report", headers=auth(), json={
        **statement, "result": "EXCEPTION", "path": "EXCEPTION", "actions": [], "expected_version": 1,
        "request_id": recorded.json()["current"]["request_id"]})
    assert answered.status_code == 200, answered.text
    assert (answered.json()["state"], answered.json()["current"]["answer"],
            answered.json()["current"]["report"]["basis"]) == ("NEEDS_ACTION", "DECLINED", "LOCAL_OPERATOR_STATEMENT")
    assert answered.json()["can_request"] is True


def test_the_ticket_channel_stays_the_default_through_a_plugin_system(issuer, directory):
    _repo, c, item, _plan, _slack = setup(issuer)
    server = Tickets()
    c.app.state.ticket_http_client_factory = server.client
    assert c.put("/api/v1/settings/ticket-system", headers=bearer(issuer, "ada", "g-admins"), json=SETUP).status_code == 200
    asked = c.post(f"/api/v1/findings/{item.id}/response/ticket", headers=bearer(issuer, "ann", "g-analysts"),
                   json={"expected_version": 0, "request_id": str(uuid.uuid4()), "person_ref": PERSON})
    assert asked.status_code == 200, asked.text
    current = asked.json()["current"]
    assert (asked.json()["state"], current["channel"], current["ticket"]["ticket"], current["link_expires_at"]) == (
        "WAITING_OWNER", "ticket", "100", None)
    assert "binding" not in json.dumps(asked.json())
