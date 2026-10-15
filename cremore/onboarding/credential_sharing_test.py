"""One credential that both collects and acts: shown on both connections and with the plan, never refused (P1c)."""

from __future__ import annotations

import datetime as dt
import json
import uuid
from types import SimpleNamespace

import httpx
import pytest

from cremore.db.repository import InMemoryRepository
from cremore.onboarding import catalog, check, github_enterprise, service
from cremore.onboarding.onboarding_test import (
    PEM,
    SETTINGS,
    github_app,
    github_server,
    run_check,
    worker,
)
from cremore.onboarding.remediation_purpose_test import GITLAB_TOKEN, gitlab
from cremore.onboarding.store import ProviderConnectionStore


def gitlab_server():
    def handler(request):
        if request.url.path == "/api/v4/personal_access_tokens/self":
            return httpx.Response(200, json={"id": 9, "scopes": ["api"], "user_id": 77, "active": True})
        if request.url.path.startswith("/api/v4/groups/10/members/all/"):
            return httpx.Response(200, json={"id": 77, "access_level": 50})
        return httpx.Response(200, json=[])

    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def client(handler):
    return SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)), memo={})


def checked(repo, body, server):
    made = service.create(repo, SETTINGS, body, "admin")
    service.request_check(repo, made["id"], "admin")
    return run_check(repo, made, server)


def shared(repo, view):
    return {row["id"]: row for row in service.list_views(repo)}[view["id"]]["credential"]["shared_with"]


def test_one_token_that_collects_and_acts_is_shown_on_both_and_nothing_is_refused():
    repo = InMemoryRepository()
    acting = checked(repo, gitlab(), gitlab_server())
    collecting = checked(repo, gitlab(purposes=["inventory"]), gitlab_server())
    other = checked(repo, gitlab(purposes=["inventory"], credential={"token": "glpat-" + "SyntheticOtherToken00"}),
                    gitlab_server())
    assert shared(repo, acting) == [{"id": collecting["id"], "name": collecting["name"]}]
    assert shared(repo, collecting) == [{"id": acting["id"], "name": acting["name"]}]
    assert shared(repo, other) == []
    # A mark is a keyed digest, never the token, and never in a view.
    marks = ProviderConnectionStore(repo).get(acting["id"])["checks"]["credential_marks"]
    assert len(marks) == 1 and len(marks[0]) == 32 and GITLAB_TOKEN not in marks[0]
    assert marks[0] not in json.dumps(service.list_views(repo)) and "credential_marks" not in json.dumps(acting)
    # A new credential not checked yet says nothing; checked, it is compared again.
    changed = service.set_credential(repo, SETTINGS, collecting["id"], {"credential": {"token": GITLAB_TOKEN}}, "admin")
    assert shared(repo, acting) == [] and shared(repo, collecting) == []
    run_check(repo, changed, gitlab_server())
    assert shared(repo, acting) == [{"id": collecting["id"], "name": collecting["name"]}]
    # A stopped connection runs nothing, on either side; two acting connections are not a collection.
    service.set_enabled(repo, collecting["id"], False, "admin")
    assert shared(repo, acting) == []
    service.set_enabled(repo, collecting["id"], True, "admin")
    service.set_enabled(repo, acting["id"], False, "admin")
    assert shared(repo, collecting) == []
    second = checked(repo, gitlab(), gitlab_server())
    service.set_enabled(repo, acting["id"], True, "admin")
    names = {"id": collecting["id"], "name": collecting["name"]}
    assert shared(repo, second) == [names] and shared(repo, acting) == [names]  # never each other


def test_a_github_app_is_one_credential_whichever_installation_it_uses():
    repo = InMemoryRepository()
    acting = checked(repo, github_app(purposes=["remediation"]),
                     github_server({"organization_personal_access_tokens": "write", "contents": "read"}))
    elsewhere = github_app(purposes=["exposure"])
    elsewhere["credential"] = {**elsewhere["credential"], "installation_id": "679"}
    scanning = checked(repo, elsewhere, github_server({"contents": "read", "metadata": "read"}, installation=679))
    other_app = github_app(purposes=["exposure"])
    other_app["credential"] = {**other_app["credential"], "app_id": "12346"}
    another = checked(repo, other_app, github_server({"contents": "read", "metadata": "read"}))
    # The App GitHub named for each installation decides (12345 here, whatever the other connection configured).
    assert shared(repo, acting) == [{"id": scanning["id"], "name": scanning["name"]}, {"id": another["id"],
                                                                                        "name": another["name"]}]


def test_a_github_check_mints_one_read_only_token_for_every_purpose():
    repo = InMemoryRepository()
    asked = []
    checked(repo, github_app(purposes=["exposure", "inventory"]),
            github_server({"contents": "read", "metadata": "read", "organization_personal_access_tokens": "write"},
                          asked=asked))
    assert asked == [{"contents": "read", "metadata": "read", "organization_personal_access_tokens": "read"}]


def test_a_github_client_id_is_compared_as_its_apps_number():
    def handler(request):
        assert request.url.path == "/app"
        return httpx.Response(200, json={"id": 12345, "client_id": "Iv1.8a61f9b3a7aba766", "slug": "cremore",
                                         "name": "CreMore", "owner": {"login": "acme", "type": "Organization"},
                                         "permissions": {}})

    module = catalog.module("github")
    secrets = module.credential("github", "github_app",
                                {"app_id": "Iv1.8a61f9b3a7aba766", "installation_id": "678", "private_key": PEM})
    connection = {"provider": "github", "auth_method": "github_app", "target": {"organization": "acme"}}
    assert module.credential_identity(connection, secrets, client(handler)) == ["github_app:https://api.github.com:12345"]
    assert module.credential_identity({**connection, "auth_method": "token"}, {}, None) is None  # a token is itself


def test_google_cloud_adc_is_the_workers_own_identity_and_a_sign_in_its_account():
    import cremore_gcp_provider.remediation as gcp_remediation

    module = catalog.module("gcp")
    adc = {"provider": "gcp", "auth_method": "adc", "target": {"scope": "project", "project": "acme-prod-1"},
           "secret_refs": {}}
    first = check.credential_marks(SETTINGS, adc, {}, module, None)
    assert first and first == check.credential_marks(SETTINGS, {**adc, "target": {"project": "other"}}, {}, module, None)

    def handler(request):
        assert request.url.host == "oauth2.googleapis.com"
        return httpx.Response(200, json={"email": "admin@acme.test", "email_verified": "true"})

    oauth = {**adc, "auth_method": "google_oauth", "secret_refs": {"credential": "sealed"}}
    secrets = {"credential": {}, gcp_remediation._ACCESS: {"token": "gcp-synthetic-access"}}
    assert module.credential_identity(oauth, secrets, client(handler)) == ["google:admin@acme.test"]
    assert module.credential_identity({**adc, "auth_method": "customer_cli"}, {}, None) == []
    # An identity that cannot be read this time is not told (None), and the check itself goes on.
    unreachable = SimpleNamespace(http_client=lambda: (_ for _ in ()).throw(RuntimeError("no client")))
    assert check.credential_marks(SETTINGS, oauth, secrets, module, unreachable) is None


@pytest.mark.parametrize("answer", [42, "a-string", ["\ud800"]])
def test_what_a_provider_says_about_its_identity_never_breaks_the_check(answer):
    module = SimpleNamespace(credential_identity=lambda connection, secrets, context: answer)
    assert check.credential_marks(SETTINGS, {"secret_refs": {}}, {}, module, None) is None


def test_a_check_that_cannot_tell_keeps_the_marks_of_the_same_credential_and_clears_what_it_opened(monkeypatch):
    repo = InMemoryRepository()
    acting = checked(repo, gitlab(), gitlab_server())
    before = ProviderConnectionStore(repo).get(acting["id"])["checks"]["credential_marks"]
    opened = []

    def open_and_keep(worker_, record):
        secrets = {"credential": {"token": GITLAB_TOKEN}, "__access__": {"token": "short-lived"}}
        opened.append(secrets)
        return secrets

    monkeypatch.setattr(check, "open_secrets", open_and_keep)
    monkeypatch.setattr(check, "credential_marks", lambda *args: None)
    service.request_check(repo, acting["id"], "admin")
    run_check(repo, acting, gitlab_server())
    assert ProviderConnectionStore(repo).get(acting["id"])["checks"]["credential_marks"] == before
    assert all(not envelope for secrets in opened for envelope in secrets.values())  # every envelope cleared


def test_integrations_checked_before_marks_are_checked_once_more_by_one_replica():
    repo = InMemoryRepository()
    acting = checked(repo, gitlab(), gitlab_server())
    store = ProviderConnectionStore(repo)
    record = store.get(acting["id"])
    old = {key: value for key, value in record["checks"].items() if key != "credential_marks"}
    store.update(record["id"], record["revision"], "worker", checks=old)  # as an older check left it
    now = dt.datetime(2026, 9, 30, 12, tzinfo=dt.UTC)
    assert check.backfill_marks(repo, now) == 1
    assert check.backfill_marks(repo, now) == 0  # another replica in the same minute
    job = repo.get_job(uuid.UUID(store.get(acting["id"])["checks"]["job_id"]))
    check.run(worker(repo, gitlab_server()), job)
    assert "credential_marks" in store.get(acting["id"])["checks"]
    assert check.backfill_marks(repo, now + dt.timedelta(minutes=1)) == 0  # done once
    requested = next(event for event in repo.list_events(50) if event.event_type == "PROVIDER_CONNECTION_CHECK_REQUESTED")
    assert requested.actor == check.BACKFILL_ACTOR


def test_the_backfill_leaves_providers_that_never_act_alone_and_asks_an_unknown_again_a_day_later(monkeypatch):
    repo = InMemoryRepository()
    store = ProviderConnectionStore(repo)
    # Okta offers no remediation purpose: its credential can never be an acting one, so it is not checked again.
    store.create({"provider": "okta", "edition": "cloud", "name": "Okta", "target": {}, "auth_method": "private_key",
                  "secret_refs": {}, "purposes": ["identity"], "checks": {"results": {"identity": {"status": "PASSED"}}}},
                 "admin")
    now = dt.datetime.now(dt.UTC)
    assert check.backfill_marks(repo, now) == 0
    # A check that could not tell, with nothing earlier to keep, is asked again a day later -- not every minute.
    monkeypatch.setattr(check, "credential_marks", lambda *args: None)
    acting = checked(repo, gitlab(), gitlab_server())
    kept = store.get(acting["id"])["checks"]
    assert (kept["credential_marks"], kept["credential_marks_unknown"]) == ([], True)
    assert check.backfill_marks(repo, now + dt.timedelta(minutes=1)) == 0
    assert check.backfill_marks(repo, now + dt.timedelta(days=1, minutes=1)) == 1


def test_an_unknown_answer_stays_unknown_when_the_write_meets_another_change(monkeypatch):
    from cremore.onboarding.store import ProviderConnectionConflict

    repo = InMemoryRepository()
    made = service.create(repo, SETTINGS, gitlab(), "admin")
    service.request_check(repo, made["id"], "admin")
    original, calls = ProviderConnectionStore.update, []

    def update(self, connection_id, revision, actor, **changes):
        calls.append(actor)
        if actor == "worker" and calls.count("worker") == 1:
            raise ProviderConnectionConflict("PROVIDER_CONNECTION_CHANGED")  # a rename landed first
        return original(self, connection_id, revision, actor, **changes)

    monkeypatch.setattr(ProviderConnectionStore, "update", update)
    monkeypatch.setattr(check, "credential_marks", lambda *args: None)
    run_check(repo, made, gitlab_server())
    kept = ProviderConnectionStore(repo).get(made["id"])["checks"]
    assert calls.count("worker") == 2 and (kept["credential_marks"], kept["credential_marks_unknown"]) == ([], True)


def test_a_refused_github_app_is_asked_once_for_every_purpose():
    repo = InMemoryRepository()
    asked = []

    def handler(request):
        asked.append((request.method, request.url.path))
        return httpx.Response(404)  # the installation is gone

    checked(repo, github_app(purposes=["exposure", "inventory"]),
            lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    assert asked == [("GET", "/app/installations/678")]


def test_the_plan_names_the_collection_that_holds_the_acting_credential(monkeypatch):
    from cremore.remediation import provider_actions
    from cremore.remediation.action_plans import ActionPlanService

    repo = InMemoryRepository()
    acting = checked(repo, gitlab(), gitlab_server())
    collecting = checked(repo, gitlab(purposes=["inventory"]), gitlab_server())
    record = ProviderConnectionStore(repo).get(acting["id"])
    monkeypatch.setattr(provider_actions, "remediation_connection", lambda repo_, target_: record)
    target = {"provider": "gitlab", "actions": ["REVOKE_PROVIDER_CREDENTIAL"], "origin": "https://gitlab.com",
              "reference": {"key": {"id": 1}}}
    answered = ActionPlanService(repo, SETTINGS).target_policy(target)
    assert answered["remediation_connection"] == {"id": acting["id"], "name": acting["name"], "provider": "gitlab",
                                                  "auth_method": "token",
                                                  "shared_with": [{"id": collecting["id"], "name": collecting["name"]}]}


def test_the_enterprise_screen_never_opens_a_remediation_connections_key():
    repo = InMemoryRepository()
    acting = service.create(repo, SETTINGS, github_app(purposes=["remediation"]), "admin")
    with pytest.raises(github_enterprise.GitHubEnterpriseError) as refused:
        github_enterprise._record(repo, acting["id"])
    assert refused.value.code == "GITHUB_APP_CONNECTION_REQUIRED"
