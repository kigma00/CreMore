"""A Google sign-in for a GCP provider connection -> every use reads with it, in memory and SQL."""

import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from cremore_gcp_provider import oauth
from cremore_gcp_provider.gcp_auth import GcpAuthError
from cremore_gcp_provider.metadata import adapter
from cremore_gcp_provider.metadata.tests.fake import FakeTransport
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.config import Settings
from cremore.coverage.gcp_oauth_store import GcpOAuthStore
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.scheduling import poll_metadata_schedules
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.onboarding.store import ProviderConnectionStore
from cremore.secretstore.resolver import SecretRefError, SecretResolver, inject_secret
from cremore.secretstore.sealed import unseal
from cremore.worker.worker import JobWorker

TOKEN = "synthetic-admin-" + "x" * 32
BROWSER = "a" * 43
FIELDS = {"client_id": "synthetic.apps.googleusercontent.com", "client_secret": "synthetic-client-secret",
          "refresh_token": "synthetic-refresh", "auth_kind": "google_oauth"}
BASE = "/api/v2/gcp/oauth/"
PROJECT = "cremore-demo-project"


# Review 2026-09-26: the OAuth store's row locks (with_for_update) are no-ops on SQLite, so the
# same flows also run on a disposable PostgreSQL when CREMORE_TEST_POSTGRES_URL names one.
@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def stack(request, monkeypatch):
    engine = make_engine("sqlite:///:memory:") if request.param == "sqlite" else None
    if engine is not None:
        create_all(engine)
    if request.param == "postgres":
        repo = request.getfixturevalue("pg")[1]  # the pg fixture owns and drops its engine and schema
    else:
        repo = SqlRepository(engine) if engine is not None else InMemoryRepository()
    settings = oauth_settings()
    app = create_app(repo=repo, settings=settings)
    client = TestClient(app, headers={"Authorization": "Bearer " + TOKEN})
    monkeypatch.setattr(oauth, "exchange", lambda *_: (FIELDS.copy(), {"subject": "123", "email": "test@example.test"}))
    yield repo, settings, client, app
    client.close()
    if engine is not None:
        engine.dispose()


def oauth_settings():
    return Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32,
                    GCP_OAUTH_CLIENT_ID=FIELDS["client_id"], GCP_OAUTH_CLIENT_SECRET=FIELDS["client_secret"],
                    GCP_OAUTH_REDIRECT_URI="http://localhost:3000/gcp/oauth/callback")


def connection(client, purposes=("exposure", "inventory")):
    """Steps 1 and 2 of a GCP connection that signs in with Google (no credential yet)."""
    created = client.post("/api/v1/provider-connections", json={
        "provider": "gcp", "purposes": list(purposes), "auth_method": "google_oauth", "target": {"project": PROJECT}})
    assert created.status_code == 201, created.text
    return created.json()["id"]


def begin(client, connection_id):
    response = client.post(BASE + "start", json={"browser_key": BROWSER, "connection_id": connection_id})
    assert response.status_code == 200, response.text
    body = response.json()
    return {"session_id": body["session_id"], "browser_key": BROWSER, "state": body["state"], "code": "synthetic-code"}


def authorize(client, connection_id):
    form = begin(client, connection_id)
    result = client.post(BASE + "finish", json=form)
    assert result.status_code == 200, result.text
    return {key: form[key] for key in ("session_id", "browser_key")}


def complete(client, session):
    result = client.post(BASE + "complete", json=session)
    assert result.status_code == 200, result.text
    return result.json()


def activate(repo, client, connection_id, purposes=("exposure", "inventory")):
    from cremore.onboarding.fixtures_test import grant_access

    grant_access(repo, connection_id, {purpose: {} for purpose in purposes})
    activated = client.post(f"/api/v1/provider-connections/{connection_id}/activate",
                            json={"purposes": {purpose: {} for purpose in purposes}})
    assert activated.status_code == 200, activated.text
    return {row["kind"]: uuid.UUID(row["id"]) for row in activated.json()["created"]}


def test_the_sign_in_is_the_connections_credential_and_every_use_reads_with_it(stack, monkeypatch):
    from cremore.coverage.gcp_integration_test import responses

    repo, settings, client, app = stack
    cid = connection(client)
    session = authorize(client, cid)
    result = complete(client, session)
    assert complete(client, session) == result == {"provider_connection_id": cid}  # a retry changes nothing
    record = ProviderConnectionStore(repo).get(uuid.UUID(cid))
    sealed = record["secret_refs"]["credential"]
    assert unseal(settings.sealing_keys, sealed) == FIELDS
    assert FIELDS["refresh_token"] not in client.get(f"/api/v1/provider-connections/{cid}").text
    assert [job.kind for job in repo.list_jobs()] == ["provider-check"]  # the sign-in is checked again
    children = activate(repo, client, cid)
    owner = MetadataStore(repo).require_connection(children["metadata"])
    assert owner["spec"]["auth_type"] == "google_oauth"
    assert set(owner["spec"]["secret_refs"].values()) == {sealed}
    calls = []

    def provider_token(fields):
        calls.append(fields.copy())
        return lambda: "synthetic-access"

    monkeypatch.setattr(oauth, "oauth_token", provider_token)
    monkeypatch.setattr(adapter, "adc_token", lambda: pytest.fail("OAuth must never fall back to ADC"))
    monkeypatch.setattr(adapter, "Transport", lambda *_args, **_kw: FakeTransport(responses()))
    for job in repo.list_jobs():
        repo.cancel_job(job.id)
    queued = client.post(f"/api/v2/coverage/connections/{children['metadata']}/collect", json={})
    assert queued.status_code == 202, queued.text
    resolver = SecretResolver(sealing_key=settings.sealing_keys)
    worker = JobWorker(repo, orchestrator=app.state.orchestrator, metadata_secret_resolver=resolver)
    for _ in range(4):
        worker.process_next()
    view = client.get(f"/api/v2/coverage/connections/{children['metadata']}").json()
    assert view["connection_auth"]["state"] == "READY", view
    assert view["connection_auth"]["credential_mode"] == "GOOGLE_OAUTH"
    assert calls[0]["refresh_token"] == FIELDS["refresh_token"]
    source = repo.get_connection(children["content"])
    assert source.secret_ref == sealed
    assert inject_secret("gcp", {"secret_ref": source.secret_ref}, resolver)["token"]() == "synthetic-access"
    public = client.get("/api/v2/coverage/connections").text
    for secret in (FIELDS["refresh_token"], FIELDS["client_secret"], sealed):
        assert secret not in public


def test_only_a_gcp_sign_in_connection_can_start_one(stack):
    _repo, _settings, client, _app = stack
    adc = client.post("/api/v1/provider-connections", json={
        "provider": "gcp", "purposes": ["inventory"], "auth_method": "adc", "target": {"project": PROJECT}}).json()
    for target in (adc["id"], str(uuid.uuid4())):
        refused = client.post(BASE + "start", json={"browser_key": BROWSER, "connection_id": target})
        assert refused.status_code == 409 and refused.json()["error"] == "GCP_SIGN_IN_CONNECTION_REQUIRED"
    assert client.post(BASE + "start", json={"browser_key": BROWSER}).status_code == 422


def test_wrong_binding_state_expiry_and_replay_rejected(stack, monkeypatch):
    repo, _, client, _ = stack
    form = begin(client, connection(client))
    for change in ({"state": "b" * 45}, {"browser_key": "b" * 43}):
        assert client.post(BASE + "finish", json={**form, **change}).status_code == 409
    assert client.post(BASE + "finish", json=form).status_code == 200
    assert client.post(BASE + "finish", json=form).status_code == 409
    session = {key: form[key] for key in ("session_id", "browser_key")}
    store = GcpOAuthStore(repo)
    with store.transaction() as conn:
        row = store._get(conn, "oauth_sessions", uuid.UUID(form["session_id"]))
        row["expires_at"] = datetime.now(UTC) - timedelta(seconds=1)
        store.save(conn, row)
    assert client.post(BASE + "complete", json=session).status_code == 409
    assert not repo.list_jobs()


def test_error_is_sanitized_and_failed_flow_can_only_restart(stack, monkeypatch):
    repo, _, client, _ = stack

    def fail(*_):
        raise GcpAuthError("GCP_OAUTH_REAUTH_REQUIRED")

    monkeypatch.setattr(oauth, "exchange", fail)
    form = begin(client, connection(client))
    response = client.post(BASE + "finish", json=form)
    assert response.status_code == 409 and response.json()["error"] == "GCP_OAUTH_REAUTH_REQUIRED"
    with GcpOAuthStore(repo).transaction() as conn:
        row = GcpOAuthStore(repo)._get(conn, "oauth_sessions", uuid.UUID(form["session_id"]))
    assert row["stage"] == "FAILED" and row["data"] == {}
    assert client.post(BASE + "finish", json=form).status_code == 409


def test_project_errors_are_codes_and_server_configuration_is_private(stack, monkeypatch):
    _, settings, client, _ = stack
    assert client.get(BASE + "status").json()["configured"] is True
    assert FIELDS["client_secret"] not in client.get(BASE + "status").text
    cid = connection(client)
    session = authorize(client, cid)
    monkeypatch.setattr(oauth, "projects", lambda *_args, **_kw: (_ for _ in ()).throw(
        GcpAuthError("GCP_PERMISSION_DENIED_OR_API_DISABLED")))
    assert client.post(BASE + "projects", json=session).status_code == 409
    assert complete(client, session) == {"provider_connection_id": cid}
    settings.gcp_oauth_client_id = ""
    assert client.get(BASE + "status").json()["configured"] is False
    assert client.post(BASE + "start", json={"browser_key": BROWSER, "connection_id": cid}).status_code == 409
    assert client.get(BASE + "status", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_a_new_sign_in_reaches_every_record_and_a_changed_connection_fences_it(stack):
    repo, _settings, client, _ = stack
    cid = connection(client)
    complete(client, authorize(client, cid))
    children = activate(repo, client, cid)
    first = ProviderConnectionStore(repo).get(uuid.UUID(cid))["secret_refs"]["credential"]
    complete(client, authorize(client, cid))
    second = ProviderConnectionStore(repo).get(uuid.UUID(cid))["secret_refs"]["credential"]
    assert second != first
    source = repo.get_connection(children["content"])
    assert source.secret_ref == second and source.status == "PENDING" and source.config == {"project": PROJECT}
    assert set(MetadataStore(repo).require_connection(children["metadata"])["spec"]["secret_refs"].values()) == {second}
    stale = authorize(client, cid)
    client.patch(f"/api/v1/provider-connections/{cid}", json={"name": "Renamed"})
    assert client.post(BASE + "complete", json=stale).json()["error"] == "CONNECTION_REVISION_CONFLICT"


def test_revoked_refresh_token_pauses_schedule_without_empty_inventory(stack, monkeypatch):
    repo, settings, client, app = stack
    cid = connection(client, ("inventory",))
    complete(client, authorize(client, cid))
    children = activate(repo, client, cid, ("inventory",))
    for job in repo.list_jobs():
        repo.cancel_job(job.id)
    client.post(f"/api/v2/coverage/connections/{children['metadata']}/collect", json={})

    def fail(_fields):
        return lambda: (_ for _ in ()).throw(GcpAuthError("GCP_OAUTH_REAUTH_REQUIRED"))

    monkeypatch.setattr(oauth, "oauth_token", fail)
    monkeypatch.setattr(adapter, "adc_token", lambda: pytest.fail("No ADC fallback"))
    worker = JobWorker(repo, orchestrator=app.state.orchestrator,
                       metadata_secret_resolver=SecretResolver(sealing_key=settings.sealing_keys))
    for _ in range(3):
        worker.process_next()
    view = client.get(f"/api/v2/coverage/connections/{children['metadata']}").json()
    assert view["latest_run"]["status"] == "FAILED"
    assert view["connection_auth"]["reason_code"] == "GCP_OAUTH_REAUTH_REQUIRED"
    assert poll_metadata_schedules(repo, settings, now=datetime.now(UTC) + timedelta(hours=1))["enqueued"] == 0


def test_a_completion_that_fails_half_way_changes_nothing(stack, monkeypatch):
    from cremore.onboarding import children as owned

    repo, _, client, _ = stack
    cid = connection(client)
    session = authorize(client, cid)
    monkeypatch.setattr(owned, "repoint", lambda *_args: (_ for _ in ()).throw(RuntimeError("synthetic failure")))
    with pytest.raises(RuntimeError, match="synthetic failure"):
        client.post(BASE + "complete", json=session)
    assert ProviderConnectionStore(repo).get(uuid.UUID(cid))["secret_refs"] == {} and not repo.list_jobs()


def test_missing_gcs_resolver_never_selects_ambient_adc(stack):
    repo, _, client, _ = stack
    cid = connection(client, ("exposure",))
    complete(client, authorize(client, cid))
    source = repo.get_connection(activate(repo, client, cid, ("exposure",))["content"])
    with pytest.raises(SecretRefError, match="GCP_OAUTH_STORED_AUTH_UNAVAILABLE"):
        inject_secret("gcp", {"secret_ref": source.secret_ref}, None)


def test_oauth_session_is_bound_to_the_original_admin(stack):
    from cremore.coverage.store import CoverageError

    repo, _, client, _ = stack
    session = authorize(client, connection(client))
    store = GcpOAuthStore(repo)
    with store.transaction() as conn, pytest.raises(CoverageError, match="GCP_OAUTH_SESSION_EXPIRED_OR_INVALID"):
        store.owned(conn, uuid.UUID(session["session_id"]), "different-admin", BROWSER, {"AUTHORIZED"})


def test_draft_oauth_asks_identity_before_cloud_access_and_rejects_cancelled_drafts(stack, monkeypatch):
    from urllib.parse import parse_qs, urlsplit

    from cremore.onboarding import sessions
    from cremore.onboarding.session_store import SessionStore

    repo, settings, client, _ = stack
    exchanges = []

    def exchange(*_args, cloud_access=True):
        exchanges.append(cloud_access)
        return FIELDS.copy(), {"subject": "123", "email": "test@example.test"}

    monkeypatch.setattr(oauth, "exchange", exchange)
    created = client.post("/api/v1/onboarding-sessions", json={"provider": "gcp", "auth_method": "google_oauth",
        "browser_key": BROWSER}).json()
    assert created["state"] == "AWAITING_OAUTH"
    begun = client.post(BASE + "start", json={"connection_kind": "onboarding", "connection_id": created["id"],
        "browser_key": BROWSER}).json()
    scopes = parse_qs(urlsplit(begun["authorization_url"]).query)["scope"][0].split()
    assert scopes == ["openid", "email"]
    session = {"session_id": begun["session_id"], "browser_key": BROWSER}
    assert client.post(BASE + "finish", json={**session, "code": "synthetic-code", "state": begun["state"]}).status_code == 200
    assert exchanges == [False]
    refused = client.post(BASE + "projects", json=session)
    assert refused.status_code == 409 and refused.json()["error"] == "GCP_PROJECTS_USE_ONBOARDING_WORKER"
    result = complete(client, session)
    assert result == {"onboarding_session_id": created["id"]} and complete(client, session) == result
    assert not ProviderConnectionStore(repo).list()
    row = SessionStore(repo).get(created["id"])
    assert unseal(settings.sealing_keys, row["data"]["secret_refs"]["credential"]) == FIELDS
    # No provider call: supply only the identity evidence for the next consent boundary.
    row = SessionStore(repo).save(row, {**row["data"], "state": "AUTHENTICATED", "authentication": {"status": "GRANTED"}})
    binding = {"browser_key": BROWSER, "expected_revision": row["revision"]}
    view = sessions.discover(repo, row["id"], {**binding, "purposes": ["exposure"]}, row["actor"])
    assert view["state"] == "AWAITING_OAUTH"
    begun = client.post(BASE + "start", json={"connection_kind": "onboarding", "connection_id": created["id"],
        "browser_key": BROWSER}).json()
    scopes = parse_qs(urlsplit(begun["authorization_url"]).query)["scope"][0].split()
    assert "https://www.googleapis.com/auth/cloud-platform" in scopes
    session = {"session_id": begun["session_id"], "browser_key": BROWSER}
    assert client.post(BASE + "finish", json={**session, "code": "synthetic-code", "state": begun["state"]}).status_code == 200
    sessions.cancel(repo, row["id"], binding, row["actor"])
    assert client.post(BASE + "complete", json=session).status_code == 409
    assert not ProviderConnectionStore(repo).list()


def test_postgres_concurrent_completion_of_one_session_sets_the_credential_once(pg, monkeypatch):
    """Several admin tabs completing the same authorized session at once: one credential, one
    check, the same answer for all (the documented retry contract)."""
    repo = pg[1]
    app = create_app(repo=repo, settings=oauth_settings())
    monkeypatch.setattr(oauth, "exchange", lambda *_: (FIELDS.copy(), {"subject": "123", "email": "test@example.test"}))
    tabs = [TestClient(app, headers={"Authorization": "Bearer " + TOKEN}) for _ in range(6)]
    try:
        cid = connection(tabs[0])
        session = authorize(tabs[0], cid)
        with ThreadPoolExecutor(len(tabs)) as pool:
            answers = list(pool.map(lambda tab: tab.post(BASE + "complete", json=session), tabs))
    finally:
        for tab in tabs:
            tab.close()
    assert [answer.status_code for answer in answers] == [200] * len(tabs), [answer.text for answer in answers]
    assert all(answer.json() == answers[0].json() for answer in answers)
    assert [job.kind for job in repo.list_jobs()] == ["provider-check"]
    assert json.dumps(answers[0].json()) == json.dumps({"provider_connection_id": cid})
