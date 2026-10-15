"""A GitHub App made from a manifest, end to end against a synthetic GitHub: the flow is bound to the admin's
browser and GitHub's state, the server alone exchanges the code, the connection is made only once the App is
installed on the organization, and the App's key is never returned or kept outside the sealed credential."""

import base64
import datetime as dt
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import httpx
import pytest

from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- opt-in disposable DB fixture
from cremore.db.repository import InMemoryRepository
from cremore.onboarding import check, github_app, service, sessions
from cremore.onboarding.onboarding_test import PEM, SETTINGS
from cremore.onboarding.session_store import SessionStore
from cremore.onboarding.sessions_test import repo as repo  # noqa: PLC0414 -- memory/SQLite fixture
from cremore.onboarding.store import ProviderConnectionStore
from cremore.secretstore.resolver import SecretResolver

KEY = "k" * 43
RESOLVER = SecretResolver(sealing_key=SETTINGS.sealing_keys)


def github(*, installed=True, owner="acme", status=201):
    def handler(request):
        path = request.url.path.removeprefix("/api/v3")
        if path.startswith("/app-manifests/"):
            return httpx.Response(status, json={"id": 424242, "slug": "cremore-acme", "client_id": "Iv23liABCDEFG",
                                                "name": "CreMore acme", "owner": {"login": owner, "type": "Organization"},
                                                "pem": PEM, "client_secret": "never-kept", "webhook_secret": "never-kept"})
        assert path == "/app/installations"
        rows = [{"id": 99, "account": {"login": "Acme"}, "target_type": "Organization"}] if installed else []
        return httpx.Response(200, json=rows)
    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def begin(repo, **body):
    return github_app.start(repo, SETTINGS, {"browser_key": KEY, "purposes": ["exposure", "inventory"],
                                             "target": {"organization": "acme"}, **body}, "admin")


def refused(call, *args):
    with pytest.raises(github_app.GitHubAppError) as failed:
        call(*args)
    return failed.value.code


def test_the_manifest_flow_makes_the_connection_once_the_app_is_installed():
    repo = InMemoryRepository()
    started = begin(repo)
    assert started["form_url"] == "https://github.com/organizations/acme/settings/apps/new?state=" + started["state"]
    assert started["manifest"]["default_permissions"]["contents"] == "read"
    session = {"session_id": started["session_id"], "browser_key": KEY}
    # Another browser, or a state GitHub did not hand back, gets nowhere.
    assert refused(github_app.convert, repo, SETTINGS, {**session, "browser_key": "x" * 43, "state": started["state"],
                                                        "code": "c0de"}, "admin", github()) == "GITHUB_APP_SESSION_EXPIRED"
    assert refused(github_app.convert, repo, SETTINGS, {**session, "state": "wrong", "code": "c0de"}, "admin",
                   github()) == "GITHUB_APP_STATE_INVALID"
    made = github_app.convert(repo, SETTINGS, {**session, "state": started["state"], "code": "c0de"}, "admin", github())
    assert made == {"install_url": "https://github.com/apps/cremore-acme/installations/new",
                    "app": {"id": "424242", "slug": "cremore-acme", "name": "CreMore acme"}}
    stored = json.dumps(repo.get_setting(github_app.PREFIX + started["session_id"]), default=str)
    assert "PRIVATE KEY" not in stored and base64.b64encode(PEM.strip().encode()).decode()[:40] not in stored
    assert "never-kept" not in stored
    # The code is exchanged once.
    assert refused(github_app.convert, repo, SETTINGS, {**session, "state": started["state"], "code": "c0de"}, "admin",
                   github()) == "GITHUB_APP_SESSION_STAGE"
    # Not installed yet: nothing is made, and it can be asked again.
    assert refused(github_app.complete, repo, SETTINGS, session, "admin", github(installed=False)) == "GITHUB_APP_NOT_INSTALLED"
    done = github_app.complete(repo, SETTINGS, session, "admin", github())
    record = ProviderConnectionStore(repo).get(done["provider_connection_id"])
    assert record["provider"] == "github" and record["auth_method"] == "github_app"
    assert record["purposes"] == ["exposure", "inventory"] and record["target"] == {"organization": "acme"}
    envelope = RESOLVER.resolve(record["secret_refs"]["credential"])
    assert envelope["GITHUB_APP_ID"] == "424242" and envelope["GITHUB_APP_INSTALLATION_ID"] == "99"
    assert base64.b64decode(envelope["GITHUB_APP_PRIVATE_KEY_BASE64"]).decode().strip() == PEM.strip()
    assert service.view(repo, record)["checks"]["job_id"]  # the permission check was asked for
    # Asking again answers with the same connection; the key is gone from the flow.
    assert github_app.complete(repo, SETTINGS, session, "admin", github()) == done
    assert repo.get_setting(github_app.PREFIX + started["session_id"])["value"]["sealed"] is None
    events = {event.event_type for event in repo.finding_events.values()}
    assert {"GITHUB_APP_MANIFEST_STARTED", "GITHUB_APP_MANIFEST_CREATED", "GITHUB_APP_MANIFEST_COMPLETED"} <= events


def test_an_app_made_on_another_account_or_for_another_admin_is_refused():
    repo = InMemoryRepository()
    started = begin(repo)
    session = {"session_id": started["session_id"], "browser_key": KEY}
    assert refused(github_app.convert, repo, SETTINGS, {**session, "state": started["state"], "code": "c0de"}, "other",
                   github()) == "GITHUB_APP_SESSION_EXPIRED"
    assert refused(github_app.convert, repo, SETTINGS, {**session, "state": started["state"], "code": "c0de"}, "admin",
                   github(owner="someone")) == "GITHUB_APP_CREATED_ON_ANOTHER_ACCOUNT"
    assert refused(github_app.complete, repo, SETTINGS, session, "admin", github()) == "GITHUB_APP_SESSION_STAGE"
    # What the wizard would refuse is refused before GitHub is asked.
    assert refused(lambda: begin(repo, purposes=["identity", "remediation"])) == "AUTH_METHOD_NOT_FOR_PURPOSES"
    assert refused(lambda: begin(repo, target={"organization": "bad/org"})) == "FIELD_INVALID:organization"
    assert refused(lambda: begin(repo, browser_key="short")) == "GITHUB_APP_BROWSER_KEY_INVALID"


def test_an_existing_connection_takes_the_new_app_as_its_credential():
    repo = InMemoryRepository()
    record = service.create(repo, SETTINGS, {"provider": "github", "purposes": ["exposure"], "auth_method": "token",
                                             "target": {"organization": "acme"}, "credential": {"token": "ghp_" + "x" * 36}},
                            "admin")
    started = begin(repo, provider_connection_id=record["id"])
    session = {"session_id": started["session_id"], "browser_key": KEY}
    github_app.convert(repo, SETTINGS, {**session, "state": started["state"], "code": "c0de"}, "admin", github())
    done = github_app.complete(repo, SETTINGS, session, "admin", github())
    assert done["provider_connection_id"] == record["id"]
    assert ProviderConnectionStore(repo).get(record["id"])["auth_method"] == "github_app"
    # A Server's people list stays on its token: an App is shown no SAML identities there.
    server = service.create(repo, SETTINGS, {"provider": "github", "edition": "enterprise_server", "purposes": ["identity"],
                                             "auth_method": "token", "target": {"organization": "acme", "host": "https://ghes.example.com"},
                                             "credential": {"token": "ghp_" + "x" * 36}}, "admin")
    assert refused(lambda: begin(repo, provider_connection_id=server["id"])) == "AUTH_METHOD_NOT_FOR_PURPOSES"


def prepared(repo, *, purposes=None, onboarding=True):
    started = begin(repo, **({"onboarding": True, "installation_purposes": purposes or []} if onboarding else {}))
    session = {"session_id": started["session_id"], "browser_key": KEY}
    github_app.convert(repo, SETTINGS, {**session, "state": started["state"], "code": "c0de"}, "admin", github())
    return session


def draft_ids(repo):
    store = SessionStore(repo)
    if store.engine is None:
        return set(repo.provider_onboarding_sessions)
    from sqlalchemy import select

    with store.engine.connect() as conn:
        return set(conn.execute(select(store.table.c.id)).scalars())


@pytest.mark.parametrize("presets", [[], ["exposure", "inventory", "vault"], ["remediation"]])
def test_manifest_completion_authenticates_before_choosing_any_collection(repo, presets):
    session = prepared(repo, purposes=presets)
    assert refused(github_app.complete, repo, SETTINGS, session, "admin", github(installed=False)) == "GITHUB_APP_NOT_INSTALLED"
    assert not draft_ids(repo) and not ProviderConnectionStore(repo).list() and not repo.list_jobs()
    done = github_app.complete(repo, SETTINGS, session, "admin", github())
    assert set(done) == {"onboarding_session_id"}
    row = SessionStore(repo).get(done["onboarding_session_id"])
    assert row["actor"] == "admin" and row["binding_hash"] == github_app._digest(KEY)
    assert row["data"]["purposes"] == [] and row["data"]["plans"] == {}
    assert "organization" not in row["data"]["target"]
    assert not ProviderConnectionStore(repo).list() and not repo.list_connections()
    envelope = RESOLVER.resolve(row["data"]["secret_refs"]["credential"])
    assert envelope["GITHUB_APP_ID"] == "424242" and envelope["GITHUB_APP_INSTALLATION_ID"] == "99"
    view = sessions.read(repo, done["onboarding_session_id"], {"browser_key": KEY}, "admin")
    assert "secret_refs" not in view and "PRIVATE KEY" not in json.dumps(view)
    calls = []

    def handler(request):
        calls.append(request.url.path)
        assert request.url.path == "/app", "No resource discovery or content read before feature selection"
        return httpx.Response(200, json={"id": 424242, "slug": "cremore-acme", "owner": {"login": "acme"},
                                         "permissions": {}})

    worker = SimpleNamespace(repo=repo, settings=SETTINGS, metadata_secret_resolver=RESOLVER,
        http_client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    check.run(worker, repo.get_job(uuid.UUID(view["job_id"])))
    after = sessions.read(repo, view["id"], {"browser_key": KEY}, "admin")
    assert after["state"] == "AUTHENTICATED" and after["authentication"]["status"] == "GRANTED", after
    assert calls == ["/app"] and after["purposes"] == [] and after["plans"] == {}
    assert github_app.complete(repo, SETTINGS, session, "admin", lambda: pytest.fail("Retry called GitHub")) == done
    assert draft_ids(repo) == {row["id"]}
    assert repo.get_setting(github_app.PREFIX + session["session_id"])["value"]["sealed"] is None
    assert refused(github_app.complete, repo, SETTINGS, session, "other", github()) == "GITHUB_APP_SESSION_EXPIRED"
    with pytest.raises(service.OnboardingError, match="ONBOARDING_SESSION_NOT_FOUND"):
        sessions.read(repo, view["id"], {"browser_key": "x" * 43}, "admin")
    # Closing the draft never makes the source manifest transfer its envelope again.
    sessions.cancel(repo, view["id"], {"browser_key": KEY}, "admin")
    assert github_app.complete(repo, SETTINGS, session, "admin", lambda: pytest.fail("Retry called GitHub")) == done
    assert draft_ids(repo) == {row["id"]}


def test_onboarding_manifest_needs_explicit_valid_installation_presets():
    repo = InMemoryRepository()
    for presets in (None, "exposure", [{}], ["billing"], ["remediation", "inventory"]):
        assert refused(lambda selected=presets: begin(repo, onboarding=True, installation_purposes=selected)) == "AUTH_METHOD_NOT_FOR_PURPOSES"
    assert not repo.list_settings(github_app.PREFIX)
    started = begin(repo, onboarding=True, installation_purposes=[])
    assert started["manifest"]["default_permissions"] == {}
    assert begin(repo, onboarding=True, installation_purposes=["identity"])["manifest"]["default_permissions"] == {
        "members": "read"}
    # GHE.com's people are managed users an App is never shown: the App is not asked for Members there.
    assert refused(lambda: begin(repo, onboarding=True, installation_purposes=["identity"], edition="dedicated",
                                 target={"organization": "acme", "host": "https://acme.ghe.com"})) == "AUTH_METHOD_NOT_FOR_PURPOSES"
    session = {"session_id": started["session_id"], "browser_key": KEY}
    record = repo.get_setting(github_app.PREFIX + started["session_id"])
    record["value"]["expires_at"] = (github_app._now() - dt.timedelta(seconds=1)).isoformat()
    repo.put_setting(record["key"], record["value"], "admin")
    assert refused(github_app.convert, repo, SETTINGS, {**session, "state": started["state"], "code": "c0de"},
                   "admin", github()) == "GITHUB_APP_SESSION_EXPIRED"


@pytest.mark.parametrize(("edition", "host"), [("dedicated", "acme.ghe.com"), ("enterprise_server", "github.example.com")])
def test_authentication_draft_preserves_the_enterprise_host_but_not_collection_target(edition, host):
    repo = InMemoryRepository()
    started = begin(repo, onboarding=True, installation_purposes=[], edition=edition,
                    target={"organization": "acme", "host": "https://" + host})
    session = {"session_id": started["session_id"], "browser_key": KEY}
    github_app.convert(repo, SETTINGS, {**session, "state": started["state"], "code": "c0de"}, "admin", github())
    done = github_app.complete(repo, SETTINGS, session, "admin", github())
    view = sessions.read(repo, done["onboarding_session_id"], {"browser_key": KEY}, "admin")
    assert view["edition"] == edition and view["context"] == {"host": host}
    assert view["purposes"] == [] and view["plans"] == {}


def assert_failed_transfer_rolls_back(repo, monkeypatch, *, onboarding=True):
    session = prepared(repo, onboarding=onboarding)
    original = github_app._audit

    def failing_audit(bound, sid, actor, event, note=None):
        if event == "GITHUB_APP_MANIFEST_COMPLETED":
            raise RuntimeError("synthetic final write failure")
        return original(bound, sid, actor, event, note)

    with monkeypatch.context() as patch:
        patch.setattr(github_app, "_audit", failing_audit)
        with pytest.raises(RuntimeError, match="synthetic final write failure"):
            github_app.complete(repo, SETTINGS, session, "admin", github())
    assert not draft_ids(repo) and not ProviderConnectionStore(repo).list() and not repo.list_jobs()
    value = repo.get_setting(github_app.PREFIX + session["session_id"])["value"]
    assert value["stage"] == "CREATED" and value["sealed"]
    assert not any(event.event_type == "ONBOARDING_AUTHENTICATION_REQUESTED" for event in repo.list_events())
    done = github_app.complete(repo, SETTINGS, session, "admin", github())
    assert bool(draft_ids(repo)) is onboarding
    assert bool(ProviderConnectionStore(repo).list()) is not onboarding
    assert github_app.complete(repo, SETTINGS, session, "admin", lambda: pytest.fail("Retry called GitHub")) == done


@pytest.mark.parametrize("onboarding", [True, False])
def test_manifest_transfer_rolls_back_draft_owner_and_job(repo, monkeypatch, onboarding):
    assert_failed_transfer_rolls_back(repo, monkeypatch, onboarding=onboarding)


def assert_concurrent_transfer_is_once(repo, monkeypatch):
    from cremore_github_provider import app_manifest

    session = prepared(repo)
    barrier = Barrier(2)
    installation = app_manifest.installation

    def wait_for_both(*args):
        found = installation(*args)
        barrier.wait(timeout=15)
        return found

    def finish(_):
        try:
            return github_app.complete(repo, SETTINGS, session, "admin", github())
        except github_app.GitHubAppError as exc:
            return exc.code

    with monkeypatch.context() as patch:
        patch.setattr(app_manifest, "installation", wait_for_both)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(finish, range(2)))
    assert sum(isinstance(result, dict) for result in results) == 1
    assert "GITHUB_APP_SESSION_STAGE" in results
    assert len(draft_ids(repo)) == 1 and len(repo.list_jobs()) == 1
    assert not ProviderConnectionStore(repo).list()


def test_concurrent_manifest_completions_create_one_draft(repo, monkeypatch):
    assert_concurrent_transfer_is_once(repo, monkeypatch)


def test_postgres_manifest_transfer_rollback(pg, monkeypatch):
    assert_failed_transfer_rolls_back(pg[1], monkeypatch)


def test_postgres_concurrent_manifest_completions_create_one_draft(pg, monkeypatch):
    assert_concurrent_transfer_is_once(pg[1], monkeypatch)
