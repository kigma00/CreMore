"""Admin-only SIEM delivery routes: status, test event, held release, event deliveries."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.conftest import oidc_settings
from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.siem.outbox import SiemOutbox

TOKEN = "siem-routes-" + "t" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def local(repo):
    return TestClient(create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN,
                                                              FINGERPRINT_KEY="ab" * 32)))


def test_a_test_event_reaches_the_outbox_and_can_be_followed():
    repo = InMemoryRepository()
    client = local(repo)
    queued = client.post("/api/v1/siem/test-event", headers=AUTH).json()
    assert queued["event_type"] == "siem.test"
    queue = SiemOutbox(repo)
    rows = {item["event"]["event_type"]: item for item in queue.claim("soc", limit=10)}
    # The request itself is an administrator action, sent as audit.action too.
    assert set(rows) == {"siem.test", "audit.action"}
    row = rows["siem.test"]
    assert row["event"]["event_id"] == queued["event_id"] and set(row["event"]["test"]) == {"nonce"}
    audit = rows["audit.action"]["event"]["audit"]
    assert (audit["action"], audit["target_type"], audit["target_id"]) == (
        "SIEM_TEST_EVENT_QUEUED", "siem_event", queued["event_id"])
    assert row["event"]["installation_id"] == client.get("/api/v1/siem/status", headers=AUTH).json()["installation_id"]
    queue.acknowledge("soc", queued["event_id"], row["token"])
    deliveries = client.get(f"/api/v1/siem/events/{queued['event_id']}/deliveries", headers=AUTH).json()
    assert [(d["destination"], d["attempts"], d["delivered_at"] is not None) for d in deliveries["deliveries"]] == [
        ("soc", 1, True)]
    assert client.get("/api/v1/siem/events/not-a-uuid/deliveries", headers=AUTH).status_code == 422
    actions = [row["action"] for row in client.get("/api/v1/audit", headers=AUTH).json()]
    assert "SIEM_TEST_EVENT_QUEUED" in actions


def test_status_shows_whether_the_exporter_is_running_and_what_waits():
    repo = InMemoryRepository()
    client = local(repo)
    body = client.get("/api/v1/siem/status", headers=AUTH).json()
    assert (body["destinations"], body["exporter_active"]) == ([], False)
    client.post("/api/v1/siem/test-event", headers=AUTH)
    SiemOutbox(repo).record_status("soc", "IDLE")
    body = client.get("/api/v1/siem/status", headers=AUTH).json()
    soc, = body["destinations"]
    # The test event and the audit.action for requesting it.
    assert (soc["destination"], soc["pending"], soc["exporter_active"], body["exporter_active"]) == (
        "soc", 2, True, True)
    repo.siem_destination_status["soc"]["last_seen_at"] = datetime.now(UTC) - timedelta(minutes=5)
    assert client.get("/api/v1/siem/status", headers=AUTH).json()["exporter_active"] is False


def test_release_held_is_audited_and_validates_the_destination():
    repo = InMemoryRepository()
    client = local(repo)
    event_id = client.post("/api/v1/siem/test-event", headers=AUTH).json()["event_id"]
    queue = SiemOutbox(repo)
    row = next(item for item in queue.claim("soc", limit=10) if item["event"]["event_id"] == event_id)
    queue.retry("soc", event_id, row["token"], delay_seconds=0, hold=True)
    assert client.post("/api/v1/siem/destinations/soc/release-held", headers=AUTH).json() == {
        "destination": "soc", "released": 1}
    assert client.post("/api/v1/siem/destinations/Bad%20Name/release-held", headers=AUTH).status_code == 422
    audit = client.get("/api/v1/audit", headers=AUTH).json()
    assert any(row["action"] == "SIEM_HELD_RELEASED" and row["note"] == "soc:1" for row in audit)


def test_only_an_admin_operates_siem_delivery(issuer):
    client = TestClient(create_app(repo=InMemoryRepository(), settings=oidc_settings(), oidc_http_client=issuer))
    analyst = {"Authorization": "Bearer " + issuer.mint(sub="ann", groups=("g-analysts",))}
    admin = {"Authorization": "Bearer " + issuer.mint(sub="adam", groups=("g-admins",))}
    event = str(uuid.uuid4())
    for method, path in (("get", "/api/v1/siem/status"), ("post", "/api/v1/siem/test-event"),
                         ("get", f"/api/v1/siem/events/{event}/deliveries"),
                         ("post", "/api/v1/siem/destinations/soc/release-held")):
        assert getattr(client, method)(path, headers=analyst).status_code == 403, path
        assert getattr(client, method)(path, headers=admin).status_code == 200, path


def test_an_analyst_forwards_a_finding_as_it_stands_and_it_is_audited(issuer, monkeypatch):
    import datetime as dt

    from cremore.api.routes import siem as siem_routes
    from cremore.domain.models import Credential, Exposure

    now = dt.datetime.now(dt.UTC)
    monkeypatch.setattr(siem_routes, "_now", lambda: now)  # every request below in the same minute

    repo = InMemoryRepository()
    cred = repo.upsert_credential(Credential(fingerprint="fp", credential_type="GITHUB_TOKEN", provider="github",
                                             identifier_hint="ghp_••••"))
    exposure = repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="github", resource_name="synthetic", location="a"))
    finding = repo.upsert_finding(cred.id, exposure.id, "HIGH")
    client = TestClient(create_app(repo=repo, settings=oidc_settings(), oidc_http_client=issuer))
    viewer = {"Authorization": "Bearer " + issuer.mint(sub="vic", groups=("g-viewers",))}
    analyst = {"Authorization": "Bearer " + issuer.mint(sub="ann", groups=("g-analysts",))}
    path = f"/api/v1/findings/{finding.id}/forward"
    assert client.post(path, headers=viewer).status_code == 403
    # Nothing would take it: say so rather than claim it was sent.
    refused = client.post(path, headers=analyst)
    assert refused.status_code == 409 and "SIEM_NOT_CONFIGURED" in refused.text
    assert client.post(f"/api/v1/findings/{uuid.uuid4()}/forward", headers=analyst).status_code == 404
    # A destination the exporter has not reported on for over a month counts as removed.
    repo.siem_destination_status["gone"] = {"destination": "gone", "last_seen_at": now - dt.timedelta(days=40),
                                            "last_success_at": None, "last_failure_at": None, "last_error_code": None,
                                            "consecutive_failures": 0}
    assert client.post(path, headers=analyst).status_code == 409
    SiemOutbox(repo).record_status("soc", "IDLE")
    # Repeated clicks in a minute are one event, audited once; another person's is their own.
    sent = [client.post(path, headers=analyst).json() for _ in range(3)]
    other = client.post(path, headers={"Authorization": "Bearer " + issuer.mint(sub="bob", groups=("g-analysts",))}).json()
    assert sent[0]["destinations"] == 1 and len({item["event_id"] for item in sent}) == 1 and other["event_id"] != sent[0]["event_id"]
    events = {item["event"]["event_id"]: item["event"] for item in SiemOutbox(repo).claim("soc", limit=20)}
    forwarded = events[sent[0]["event_id"]]
    assert (forwarded["event_type"], forwarded["change"]) == ("finding.forwarded", "FORWARDED")
    assert forwarded["finding"]["id"] == str(finding.id) and forwarded["credential"]["credential_type"] == "GITHUB_TOKEN"
    assert forwarded["finding"]["workflow_status"] == forwarded["finding"]["previous_workflow_status"]
    assert "ann" not in str(forwarded) and "synthetic" not in str(forwarded) and "forwarded_by" not in forwarded  # no name, no location
    audited = [row for row in client.get("/api/v1/audit", headers=analyst).json() if row["action"] == "FINDING_FORWARDED_TO_SIEM"]
    assert sorted(row["note"] for row in audited) == sorted(f"event_id={item['event_id']}" for item in (sent[0], other))


def test_cremore_s_own_alert_channel_is_not_a_destination_a_finding_is_forwarded_to():
    from cremore.domain.models import Credential, Exposure

    repo = InMemoryRepository()
    cred = repo.upsert_credential(Credential(fingerprint="fp", credential_type="GITHUB_TOKEN", provider="github"))
    exposure = repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="github", resource_name="synthetic",
                                             location="a"))
    finding = repo.upsert_finding(cred.id, exposure.id, "HIGH")
    client = local(repo)
    # The Slack alert channel reports every second through the outbox (cremore.alerts.delivery): it takes alerts,
    # not forwarded findings, so alone it is no SIEM to send to.
    SiemOutbox(repo).record_status("cremore.slack-alerts", "SUCCESS")
    refused = client.post(f"/api/v1/findings/{finding.id}/forward", headers=AUTH)
    assert refused.status_code == 409 and "SIEM_NOT_CONFIGURED" in refused.text
    SiemOutbox(repo).record_status("soc", "IDLE")
    assert client.post(f"/api/v1/findings/{finding.id}/forward", headers=AUTH).json()["destinations"] == 1


def test_operations_status_raises_siem_backlog_and_exporter_alerts():
    repo = InMemoryRepository()
    client = local(repo)
    assert client.get("/api/v1/operations/status", headers=AUTH).json()["siem"] == {
        "destinations": 0, "exporter_active": False, "backlogged": []}
    queue = SiemOutbox(repo)
    for _ in range(5):
        queue.record_status("soc", "FAILURE", error_code="HTTP_STATUS_REJECTED")
    body = client.get("/api/v1/operations/status", headers=AUTH).json()
    assert body["siem"] == {"destinations": 1, "exporter_active": True, "backlogged": ["soc"]}
    assert {"code": "SIEM_DELIVERY_BACKLOG", "resource_type": "siem_destination", "resource_id": "soc"} in body["alerts"]
    assert client.get("/api/v1/siem/status", headers=AUTH).json()["destinations"][0]["backlogged"] is True
    repo.siem_destination_status["soc"]["last_seen_at"] = datetime.now(UTC) - timedelta(minutes=10)
    alerts = client.get("/api/v1/operations/status", headers=AUTH).json()["alerts"]
    assert {"code": "SIEM_EXPORTER_INACTIVE", "resource_type": "siem", "resource_id": "exporter"} in alerts
