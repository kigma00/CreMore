"""The Google OAuth client an admin saves in the dashboard: sealed, never shown again, used by the sign-in, and
refused while GCP_OAUTH_* settings pin one. Synthetic client only; nothing reaches Google."""

import json

from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.conftest import GROUPS, oidc_settings
from cremore.api.gcp_oauth_test import BASE, BROWSER, TOKEN, connection, oauth_settings
from cremore.config import Settings
from cremore.db.repository import InMemoryRepository

CLIENT_ID = "saved-synthetic.apps.googleusercontent.com"
# Built at run time: nothing secret-shaped sits in the source.
SECRET = "GOCSPX-" + "s" * 28
CALLBACK = "https://cremore.example.test/gcp/oauth/callback"


def dashboard_stack():
    repo = InMemoryRepository()
    settings = Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32)
    return repo, TestClient(create_app(repo=repo, settings=settings), headers={"Authorization": "Bearer " + TOKEN})


def test_a_client_saved_in_the_dashboard_is_sealed_and_signs_in():
    repo, client = dashboard_stack()
    assert client.get(BASE + "status").json()["configured"] is False
    saved = client.put(BASE + "client", json={"client_id": CLIENT_ID, "client_secret": SECRET, "redirect_uri": CALLBACK})
    assert saved.status_code == 200 and saved.headers["cache-control"] == "no-store"
    assert saved.json() == {"configured": True, "client_id": CLIENT_ID, "redirect_uri": CALLBACK, "source": "DASHBOARD",
                            "locked": False, "scopes": saved.json()["scopes"]}
    assert SECRET not in saved.text and SECRET not in json.dumps(repo.get_setting("gcp_oauth_client")["value"])
    status = client.get(BASE + "status").json()
    assert (status["configured"], status["source"], status["client_id"]) == (True, "DASHBOARD", CLIENT_ID)
    assert SECRET not in json.dumps(status)
    # The sign-in goes to Google with the saved client.
    started = client.post(BASE + "start", json={"browser_key": BROWSER, "connection_id": connection(client)})
    assert started.status_code == 200 and f"client_id={CLIENT_ID}" in started.json()["authorization_url"]
    # A new redirect URI without the secret keeps the saved secret.
    moved = client.put(BASE + "client", json={"client_id": CLIENT_ID, "redirect_uri": "http://localhost:3187/gcp/oauth/callback"})
    assert moved.status_code == 200 and moved.json()["redirect_uri"] == "http://localhost:3187/gcp/oauth/callback"
    events = [event.event_type for event in repo.finding_events.values() if event.target_type == "gcp_oauth"]
    assert events.count("GCP_OAUTH_CLIENT_SAVED") == 2


def test_a_wrong_client_is_refused_and_a_pinned_one_cannot_change():
    _repo, client = dashboard_stack()
    for body in ({"client_id": "not-a-google-client", "client_secret": SECRET, "redirect_uri": CALLBACK},
                 {"client_id": CLIENT_ID, "client_secret": SECRET, "redirect_uri": "https://cremore.example.test/elsewhere"},
                 {"client_id": CLIENT_ID, "redirect_uri": CALLBACK}):  # no secret saved yet
        refused = client.put(BASE + "client", json=body)
        assert refused.status_code in (400, 409, 422) and "GCP_OAUTH_SETUP_REQUIRED" in refused.text
    pinned = TestClient(create_app(repo=InMemoryRepository(), settings=oauth_settings()),
                        headers={"Authorization": "Bearer " + TOKEN})
    status = pinned.get(BASE + "status").json()
    assert (status["source"], status["locked"]) == ("SETTING", True)
    refused = pinned.put(BASE + "client", json={"client_id": CLIENT_ID, "client_secret": SECRET, "redirect_uri": CALLBACK})
    assert refused.status_code == 409 and "GCP_OAUTH_CLIENT_PINNED" in refused.text


def test_another_client_brings_its_own_secret_and_the_form_takes_only_clean_values():
    repo, client = dashboard_stack()
    assert client.put(BASE + "client", json={"client_id": CLIENT_ID, "client_secret": SECRET, "redirect_uri": CALLBACK}).status_code == 200
    # A blank secret keeps the saved one only for the same client.
    other = client.put(BASE + "client", json={"client_id": "other-synthetic.apps.googleusercontent.com", "redirect_uri": CALLBACK})
    assert other.status_code == 409 and "GCP_OAUTH_SETUP_REQUIRED" in other.text
    assert client.get(BASE + "status").json()["client_id"] == CLIENT_ID
    for body in ({"client_id": "a\r\nFORGED\r\n.apps.googleusercontent.com", "client_secret": SECRET, "redirect_uri": CALLBACK},
                 {"client_id": CLIENT_ID, "client_secret": SECRET, "redirect_uri": "https://cremore.example.test/gcp/oauth/\tcallback"},
                 {"client_id": CLIENT_ID, "client_secret": SECRET, "redirect_uri": "https://evil.test\\cremore.example.test/gcp/oauth/callback"},
                 {"client_id": CLIENT_ID, "client_secret": SECRET, "redirect_uri": "https://cremore.example.test:99999/gcp/oauth/callback"},
                 {"client_id": CLIENT_ID, "client_secret": "GOCSPX-with space", "redirect_uri": CALLBACK}):
        refused = client.put(BASE + "client", json=body)
        assert refused.status_code == 409 and "GCP_OAUTH_SETUP_REQUIRED" in refused.text, body
    notes = [event.note for event in repo.finding_events.values() if event.event_type == "GCP_OAUTH_CLIENT_SAVED"]
    assert notes == [f"client_id={CLIENT_ID} redirect_uri={CALLBACK} secret=replaced"]


def test_status_describes_the_saved_client_without_opening_its_secret(monkeypatch):
    _repo, client = dashboard_stack()
    assert client.put(BASE + "client", json={"client_id": CLIENT_ID, "client_secret": SECRET, "redirect_uri": CALLBACK}).status_code == 200
    connection_id = connection(client)

    def unreachable(_self):
        raise RuntimeError("synthetic key store outage")

    monkeypatch.setattr(Settings, "sealing_keys", property(unreachable))
    status = client.get(BASE + "status")
    assert status.status_code == 200 and status.json()["configured"] is True
    # The sign-in needs the secret: an unreachable key store is a retryable refusal, not a 500.
    started = client.post(BASE + "start", json={"browser_key": BROWSER, "connection_id": connection_id})
    assert started.status_code != 500 and "GCP_OAUTH_STORED_AUTH_UNAVAILABLE" in started.text


def test_only_an_admin_saves_the_client(issuer):
    app = create_app(repo=InMemoryRepository(), settings=oidc_settings(), oidc_http_client=issuer)
    client = TestClient(app)
    body = {"client_id": CLIENT_ID, "client_secret": SECRET, "redirect_uri": CALLBACK}
    for role in ("viewer", "analyst", "remediator"):
        headers = {"Authorization": "Bearer " + issuer.mint(sub=role, groups=(GROUPS[role],))}
        assert client.put(BASE + "client", json=body, headers=headers).status_code == 403
        assert client.get(BASE + "status", headers=headers).status_code == 403
    admin = {"Authorization": "Bearer " + issuer.mint(sub="admin", groups=(GROUPS["admin"],))}
    assert client.put(BASE + "client", json=body, headers=admin).status_code == 200
