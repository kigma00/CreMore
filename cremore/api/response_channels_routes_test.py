"""The response channels an Admin approves, and a request's team-channel notice, through the API (a fake Slack
workspace, cremore.governance.response_threads_test)."""

import json
import uuid

from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.conftest import oidc_settings
from cremore.api.contact_routes_test import bearer
from cremore.api.response_link_routes_test import add_finding
from cremore.db.repository import InMemoryRepository
from cremore.governance.contact_test import MAIL, TOKEN, Relay
from cremore.governance.response_link_test import PERSON
from cremore.governance.response_link_test import (
    directory as directory,  # noqa: PLC0414 -- fake directory fixture
)
from cremore.governance.response_threads_test import PUBLIC_CHANNEL, TEAM_CHANNEL, Workspace

PATH = "/api/v1/settings/response-channels"


def setup(issuer):
    repo, ws = InMemoryRepository(), Workspace()
    c = TestClient(create_app(repo=repo, settings=oidc_settings(), oidc_http_client=issuer))
    relay = Relay()
    c.app.state.contact_transports = {"smtp": relay, "smtp_ssl": relay, "http_client_factory": ws.client}
    assert c.put("/api/v1/settings/contact-delivery", headers=bearer(issuer, "ada", "g-admins"), json={
        "mail": MAIL, "slack": {"token": TOKEN, "allowed_channels": []}, "allowed_domains": ["example.com"],
        "console_url": "https://cremore.example.com"}).status_code == 200
    return repo, c, ws


def test_only_an_admin_approves_channels_and_analysts_see_only_names(issuer):
    _repo, c, _ws = setup(issuer)
    admin, analyst = bearer(issuer, "ada", "g-admins"), bearer(issuer, "ann", "g-analysts")
    body = {"expected_version": 0, "channels": [{"channel_id": TEAM_CHANNEL, "allow_public": False},
                                                {"channel_id": PUBLIC_CHANNEL, "allow_public": True}]}
    for method, path in (("GET", PATH), ("PUT", PATH), ("GET", PATH + "/candidates")):
        assert c.request(method, path, headers=analyst, json=body if method == "PUT" else None).status_code == 403
    assert c.get("/api/v1/response-channels", headers=bearer(issuer, "vic", "g-viewers")).status_code == 403
    saved = c.put(PATH, headers=admin, json=body)
    assert saved.status_code == 200 and saved.headers["cache-control"] == "no-store"
    assert saved.json()["version"] == 1 and [row["allow_public"] for row in saved.json()["channels"]] == [False, True]
    assert c.get(PATH, headers=admin).json() == saved.json()
    assert c.get("/api/v1/response-channels", headers=analyst).json() == {"channels": [
        {"channel_id": TEAM_CHANNEL, "name": "team-payments", "is_private": True},
        {"channel_id": PUBLIC_CHANNEL, "name": "general", "is_private": False}]}
    stale = c.put(PATH, headers=admin, json=body)
    assert (stale.status_code, stale.json()["detail"]) == (409, "RESPONSE_CHANNELS_CHANGED")
    public = c.put(PATH, headers=admin, json={"expected_version": 1, "channels": [{"channel_id": PUBLIC_CHANNEL}]})
    assert (public.status_code, public.json()["detail"]) == (422, "RESPONSE_CHANNEL_PUBLIC_NOT_ALLOWED")
    assert c.put(PATH, headers=admin, json={**body, "expected_version": 1, "token": TOKEN}).status_code == 422
    candidates = c.get(PATH + "/candidates", headers=admin)
    assert candidates.status_code == 200 and candidates.json()["truncated"] is False
    assert {row["channel_id"] for row in candidates.json()["channels"]} == {TEAM_CHANNEL, PUBLIC_CHANNEL}
    audit = [row for row in c.get("/api/v1/audit", headers=admin).json() if row["action"] == "RESPONSE_CHANNELS_SAVED"]
    assert len(audit) == 1 and TOKEN not in json.dumps(audit)


def test_a_request_names_an_approved_channel_and_shows_its_thread(issuer, directory):
    repo, c, ws = setup(issuer)
    item, _plan = add_finding(repo)
    admin, analyst = bearer(issuer, "ada", "g-admins"), bearer(issuer, "ann", "g-analysts")
    assert c.put(PATH, headers=admin, json={"expected_version": 0, "channels": [
        {"channel_id": TEAM_CHANNEL, "allow_public": False}]}).status_code == 200
    path = f"/api/v1/findings/{item.id}/response"
    body = {"expected_version": 0, "request_id": str(uuid.uuid4()), "person_ref": PERSON}
    for extra, code in (({"slack_channel": TEAM_CHANNEL}, "RESPONSE_SLACK_CHANNEL_NOT_ALLOWED"),  # the ticket channel
                        ({"channel": "slack", "dm": False}, "RESPONSE_DELIVERY_REQUIRED"),
                        ({"channel": "slack", "slack_channel": PUBLIC_CHANNEL}, "RESPONSE_CHANNEL_NOT_APPROVED")):
        refused = c.post(path + "/ticket", headers=analyst, json={**body, **extra})
        assert (refused.status_code, refused.json()["detail"]) == (422, code), extra
    asked = c.post(path + "/ticket", headers=analyst,
                   json={**body, "channel": "slack", "slack_channel": TEAM_CHANNEL, "dm": False})
    assert asked.status_code == 200, asked.text
    current = asked.json()["current"]
    assert (current["thread"], current["thread_error"]) == ({"channel_id": TEAM_CHANNEL, "name": "team-payments"}, None)
    assert len(ws.notices()) == 1 and not [post for post in ws.posts if post["channel"].startswith("D")]
    rule = c.get(path + "/routing", headers=analyst).json()
    assert rule["slack_channel"] is None  # no rule names one


def test_a_routing_rule_takes_only_an_approved_channel(issuer):
    repo, c, _ws = setup(issuer)
    item, _plan = add_finding(repo)
    refused = c.put(f"/api/v1/findings/{item.id}/response/routing-rule", headers=bearer(issuer, "ada", "g-admins"),
                    json={"expected_version": 0, "person_ref": None, "kind": "location", "key": str(uuid.uuid4()),
                          "channel_id": TEAM_CHANNEL})
    assert (refused.status_code, refused.json()["detail"]) == (422, "RESPONSE_CHANNEL_NOT_APPROVED")
