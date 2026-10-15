"""Slack detection alerts through the API: only an Admin sets them up, sees how delivery stands and sends a test;
the webhook address is sealed and never comes back, a blank one keeps it, the console address is the contact setup's,
and every save and test is audited without its values."""

import json

from fastapi.testclient import TestClient

from cremore.alerts import delivery, setup
from cremore.alerts.delivery_test import WEBHOOK, Hook
from cremore.api import create_app
from cremore.api.conftest import oidc_settings
from cremore.db.repository import InMemoryRepository
from cremore.domain.models import Credential, Exposure
from cremore.governance.contact_test import TOKEN

PATH = "/api/v1/settings/detection-alerts"


def bearer(issuer, sub, group):
    return {"Authorization": "Bearer " + issuer.mint(sub=sub, groups=(group,))}


def start(issuer):
    repo = InMemoryRepository()
    return repo, TestClient(create_app(repo=repo, settings=oidc_settings(), oidc_http_client=issuer))


def audit(client, admin, prefix):
    return [(row["action"], row["note"]) for row in client.get("/api/v1/audit", headers=admin).json()
            if row["action"].startswith(prefix)]


def test_only_an_admin_reaches_the_alert_setup(issuer):
    repo, client = start(issuer)
    for group in ("g-viewers", "g-analysts", "g-remediators"):
        who = bearer(issuer, "someone", group)
        assert client.get(PATH, headers=who).status_code == 403
        assert client.put(PATH, headers=who, json={"min_severity": "HIGH"}).status_code == 403
        assert client.post(PATH + "/test", headers=who).status_code == 403
    assert repo.get_setting(setup.KEY) is None
    shown = client.get(PATH, headers=bearer(issuer, "ada", "g-admins"))
    assert shown.status_code == 200 and shown.headers["cache-control"] == "no-store"
    assert shown.json() == {
        "enabled": False, "transport": "webhook", "webhook_saved": False, "channel": None, "channels": [],
        "bot_ready": False, "min_severity": "INFO", "detail": "standard", "language": "ko",
        "events": ["finding.created", "finding.reappeared", "finding.location_added"], "enabled_at": None,
        "console_url": None, "updated_by": None, "updated_at": None,
        "status": {"pending": 0, "oldest_pending_at": None, "last_seen_at": None, "last_success_at": None,
                   "last_failure_at": None, "last_error_code": None, "consecutive_failures": 0}}


def test_the_webhook_is_checked_sealed_and_a_blank_one_keeps_it(issuer):
    repo, client = start(issuer)
    admin = bearer(issuer, "ada", "g-admins")
    for body, code in (({"webhook_url": "https://hooks.slack.com.evil.example/services/T1/B1/x"}, "ALERTS_WEBHOOK_INVALID"),
                       ({"enabled": True}, "ALERTS_WEBHOOK_REQUIRED"), ({"detail": "everything"}, "ALERTS_DETAIL_INVALID"),
                       ({"webhook": WEBHOOK}, "ALERTS_SETTINGS_INVALID")):
        refused = client.put(PATH, headers=admin, json=body)
        assert (refused.status_code, refused.json()["detail"]) == (422, code), body
    assert repo.get_setting(setup.KEY) is None
    saved = client.put(PATH, headers=admin, json={"webhook_url": WEBHOOK, "enabled": True, "min_severity": "HIGH"})
    assert saved.status_code == 200 and saved.headers["cache-control"] == "no-store"
    view = saved.json()
    assert view["webhook_saved"] is True and view["enabled"] is True and view["enabled_at"] and view["updated_by"] == "ada"
    sealed = repo.get_setting(setup.KEY)["value"]["webhook"]
    assert WEBHOOK not in saved.text + client.get(PATH, headers=admin).text + json.dumps(repo.get_setting(setup.KEY), default=str)
    kept = client.put(PATH, headers=admin, json={"webhook_url": "", "detail": "minimal", "language": "en"})
    assert kept.json()["webhook_saved"] is True and repo.get_setting(setup.KEY)["value"]["webhook"] == sealed
    notes = audit(client, admin, "INSTALLATION_SETTING_CHANGED")
    assert ("INSTALLATION_SETTING_CHANGED", "detection_alerts enabled=on min_severity=HIGH webhook_url=set") in notes
    assert ("INSTALLATION_SETTING_CHANGED", "detection_alerts detail=minimal language=en") in notes
    assert WEBHOOK not in json.dumps(notes)


def test_the_console_address_round_trips_into_the_contact_setup(issuer):
    _repo, client = start(issuer)
    admin = bearer(issuer, "ada", "g-admins")
    contact_body = {"slack": {"token": TOKEN, "allowed_channels": ["#security-alerts", "C0123ABCD9"]},
                    "allowed_domains": ["example.com"]}
    assert client.put("/api/v1/settings/contact-delivery", headers=admin, json=contact_body).status_code == 200
    view = client.put(PATH, headers=admin, json={"console_url": "https://CreMore.Example.com/"}).json()
    assert view["console_url"] == "https://cremore.example.com"
    contact = client.get("/api/v1/settings/contact-delivery", headers=admin).json()
    assert contact["console_url"] == "https://cremore.example.com"
    assert contact["slack"] == {"token_saved": True, "allowed_channels": ["#security-alerts", "C0123ABCD9"]}
    # One address: changed in the contact setup, the alerts read it from there.
    client.put("/api/v1/settings/contact-delivery", headers=admin, json={**contact_body, "console_url": "http://10.0.0.5:3000"})
    assert client.get(PATH, headers=admin).json()["console_url"] == "http://10.0.0.5:3000"
    refused = client.put(PATH, headers=admin, json={"console_url": "https://cremore.example.com/login"})
    assert (refused.status_code, refused.json()["detail"]) == (422, "CONTACT_CONSOLE_URL_INVALID")
    # The bot posts only to a channel listed there.
    refused = client.put(PATH, headers=admin, json={"transport": "bot", "channel": "#general"})
    assert refused.json()["detail"] == "ALERTS_CHANNEL_NOT_ALLOWED"
    view = client.put(PATH, headers=admin, json={"transport": "bot", "channel": "C0123ABCD9", "enabled": True}).json()
    assert (view["transport"], view["channel"], view["bot_ready"], view["channels"]) == (
        "bot", "C0123ABCD9", True, ["#security-alerts", "C0123ABCD9"])
    assert TOKEN not in json.dumps(view)


def test_a_test_message_goes_out_from_the_api_and_is_audited(issuer):
    _repo, client = start(issuer)
    admin = bearer(issuer, "ada", "g-admins")
    hook = Hook((200, "ok", {}), (500, "", {}))
    client.app.state.alerts_http_client_factory = hook.client
    assert client.post(PATH + "/test", headers=admin).json() == {"delivered": False, "error_code": "ALERTS_NOT_CONFIGURED"}
    client.put(PATH, headers=admin, json={"webhook_url": WEBHOOK, "console_url": "https://cremore.example.com"})
    assert client.post(PATH + "/test", headers=admin).json() == {"delivered": True, "error_code": None}
    assert hook.sent[0]["blocks"][0]["text"]["text"] == "CreMore Slack 탐지 알림 시험"
    assert hook.sent[0]["blocks"][2]["elements"][0]["url"] == "https://cremore.example.com/"
    assert client.post(PATH + "/test", headers=admin).json() == {"delivered": False, "error_code": "SINK_UNAVAILABLE"}
    assert audit(client, admin, "DETECTION_ALERTS_TESTED") == [
        ("DETECTION_ALERTS_TESTED", "failed=SINK_UNAVAILABLE"), ("DETECTION_ALERTS_TESTED", "delivered"),
        ("DETECTION_ALERTS_TESTED", "failed=ALERTS_NOT_CONFIGURED")]


def test_the_view_says_how_delivery_stands(issuer):
    repo, client = start(issuer)
    admin = bearer(issuer, "ada", "g-admins")
    client.put(PATH, headers=admin, json={"webhook_url": WEBHOOK, "enabled": True})
    credential = repo.upsert_credential(Credential(fingerprint="synthetic", credential_type="GITHUB_TOKEN", provider="github"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="github", resource_name="acme/app",
                                             location="app.py", severity="HIGH"))
    repo.upsert_finding(credential.id, exposure.id, "HIGH")
    delivery.deliver_pending(repo, oidc_settings(), http_client_factory=Hook((503, "", {})).client)
    status = client.get(PATH, headers=admin).json()["status"]
    # The alert waits for its retry (and audit rows written since wait for the next pass).
    assert status["pending"] >= 1 and (status["last_error_code"], status["consecutive_failures"]) == ("SINK_UNAVAILABLE", 1)
    assert status["oldest_pending_at"] and status["last_seen_at"] and status["last_failure_at"] and status["last_success_at"] is None
