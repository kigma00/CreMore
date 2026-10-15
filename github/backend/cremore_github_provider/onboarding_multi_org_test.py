"""One sealed App owner, explicit organization roots, and organization-bound runtime tokens (fakes only)."""

import base64
import json
from types import SimpleNamespace

import httpx
import pytest

from cremore.db.repository import InMemoryRepository
from cremore.onboarding import github_enterprise, service, sessions, targets
from cremore.onboarding.discovery_test import finish, run
from cremore.onboarding.onboarding_test import PEM
from cremore.onboarding.sessions_test import KEY, SETTINGS, body
from cremore.onboarding.store import ProviderConnectionStore
from cremore.secretstore.resolver import inject_secret
from cremore_github_provider import onboarding, remediation, source
from cremore_github_provider.github_auth import GitHubAppTokenSource, GitHubAuthError

ENVELOPE = {"GITHUB_APP_ID": "12345", "GITHUB_APP_INSTALLATION_ID": "678",
            "GITHUB_APP_PRIVATE_KEY_BASE64": base64.b64encode(PEM.encode()).decode()}


class GitHub:
    def __init__(self, *, owner="Enterprise", denied=None):
        self.owner, self.denied, self.calls = owner, denied, []
        self.orgs = {"acme": 678, "acme-labs": 789}

    def __call__(self, request):
        path = request.url.path
        self.calls.append((request.method, path))
        if path == "/app":
            return httpx.Response(200, json={"id": 12345, "client_id": "Iv23liCREMORE", "slug": "cremore-acme",
                "owner": {"type": self.owner, "slug": "acme-corp"}, "permissions": {}})
        if path == "/app/installations":
            return httpx.Response(200, json=[{"id": i, "target_type": "Organization", "account": {"login": o}}
                for o, i in self.orgs.items()] + [{"id": 99, "target_type": "Enterprise", "account": {"slug": "acme-corp"}},
                {"id": 88, "target_type": "Organization", "account": {"login": "suspended"}, "suspended_at": "2026-01-01"}],
                headers={"link": '<https://untrusted.invalid/>; rel="next"'})
        if path.startswith("/orgs/") and path.endswith("/installation"):
            org = path.split("/")[2]
            if org == self.denied:
                return httpx.Response(403)
            held = {name: "write" for name in set(onboarding.APP_PERMISSIONS["inventory"]) | {"contents", "metadata"}}
            return httpx.Response(200, json={"id": self.orgs[org], "app_id": 12345, "account": {"login": org},
                "target_type": "Organization", "permissions": held})
        if path.startswith("/app/installations/") and path.endswith("/access_tokens"):
            installation = int(path.split("/")[3])
            assert installation in self.orgs.values(), "the saved first installation is never reused for another org"
            return httpx.Response(201, json={"token": "synthetic-installation-" + str(installation),
                "expires_at": "2099-01-01T00:00:00Z", "permissions": json.loads(request.content)["permissions"]})
        if path == "/installation/repositories":
            installation = int(request.headers["authorization"].split("-")[-1])
            org = next(org for org, iid in self.orgs.items() if iid == installation)
            return httpx.Response(200, json={"repositories": [{"owner": {"login": org}}]})
        if path.startswith("/orgs/") and path.endswith("/repos"):
            org = path.split("/")[2]
            assert request.headers["authorization"].endswith(str(self.orgs[org]))
            return httpx.Response(200, json=[{"id": self.orgs[org], "name": "repo", "full_name": org + "/repo",
                "owner": {"login": org}, "default_branch": "main"}])
        raise AssertionError(path)

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self))


def draft(repo, github, purposes):
    view = sessions.create(repo, SETTINGS, {"provider": "github", "edition": "enterprise_cloud",
        "auth_method": "github_app", "browser_key": KEY,
        "credential": {"app_id": "12345", "installation_id": "678", "private_key": PEM}}, "admin")
    view = run(repo, view, github)
    assert view["state"] == "AUTHENTICATED", view
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=purposes), "admin"), github)
    assert view["state"] == "LISTED" and not view["has_more"], view
    assert [r["target"] for r in view["roots"]] == [{"organization": "acme"}, {"organization": "acme-labs"}]
    return view


@pytest.mark.parametrize("owner", ["Enterprise", "Organization"])
def test_multi_org_owner_roundtrip_content_scope_and_enterprise_detection_do_not_expand_collection(owner):
    repo, github = InMemoryRepository(), GitHub(owner=owner)
    view = draft(repo, github, ["inventory", "exposure"])
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[r["id"] for r in view["roots"]],
        plans={"inventory": {}, "exposure": {}}), "admin"), github)
    assert view["state"] == "CHECKED" and view["blockers"] == [], view
    assert {r["provider_resource_id"] for r in view["resources"]} == {"acme/repo", "acme-labs/repo"}
    made = finish(repo, view)
    record = ProviderConnectionStore(repo).get(made["id"])
    assert len(ProviderConnectionStore(repo).list()) == 1
    assert len(record["target"]["roots"]) == 2 and "enterprise" not in record["target"]
    assert record["target"]["auth"]["github_enterprise"] == "acme-corp"
    assert len(made["children"]) == 4, "two chosen org inventories and content sources, no enterprise-wide inventory"
    assert {r["target"]["organization"] for r in targets.records_of(record)} == set(github.orgs)
    controlled = github_enterprise._record(repo, made["id"], active=True)
    assert controlled["target"]["enterprise"] == "acme-corp"
    assert set(github_enterprise._connected(repo, controlled)) == set(github.orgs)
    assert "/orgs/acme-labs/installation" in [path for _, path in github.calls]
    assert ("POST", "/app/installations/789/access_tokens") in github.calls
    assert all(not path.startswith("/enterprises/") for _, path in github.calls)


def test_missing_access_on_second_org_cannot_borrow_first_org_grants():
    repo, github = InMemoryRepository(), GitHub(denied="acme-labs")
    view = draft(repo, github, ["inventory"])
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[r["id"] for r in view["roots"]],
        plans={"inventory": {}}), "admin"), github)
    assert view["state"] == "CHECKED" and view["blockers"]
    with pytest.raises(ValueError, match="REQUIRED_PERMISSIONS_NOT_GRANTED"):
        finish(repo, view)
    assert not ProviderConnectionStore(repo).list()


def test_discovery_pagination_is_local_bounded_and_malformed_or_failed_lists_are_not_empty_success(monkeypatch):
    monkeypatch.setattr(onboarding, "_authentication_headers", lambda *args: {})
    connection = {"auth_method": "github_app", "edition": "cloud", "target": {}, "purposes": ["inventory"]}
    rows = [{"id": i + 1, "target_type": "Organization", "account": {"login": f"org-{i}"}} for i in range(100)]

    def call(response, current=connection):
        requests = []
        def handler(request):
            requests.append(request)
            return response
        context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
        result = onboarding.discover(current, {}, context)
        assert requests[0].url.host == "api.github.com" and requests[0].url.params["per_page"] == "100"
        return result

    roots, complete, cursor = call(httpx.Response(200, json=rows, headers={"link": '<https://bad.invalid/>'}))
    assert len(roots) == 100 and (complete, cursor) == ("PARTIAL", 2)
    with pytest.raises(ValueError, match="GITHUB_ORGANIZATIONS_LIMIT"):
        call(httpx.Response(200, json=rows), {**connection, "discovery_cursor": 100})
    for response in [httpx.Response(403), httpx.Response(200, json={}), httpx.Response(200, json=[{"id": 0}])]:
        with pytest.raises(ValueError, match="GITHUB_ORGANIZATIONS_"):
            call(response)


@pytest.mark.parametrize("change", [{"account": {"login": "other"}}, {"app_id": 2}, {"suspended_at": "now"}, {"id": None}])
def test_bound_installation_refuses_mismatch_before_minting(change):
    calls = []
    def handler(request):
        calls.append(request.method)
        return httpx.Response(200, json={"id": 789, "app_id": 12345, "account": {"login": "acme-labs"},
            "target_type": "Organization", "permissions": {"metadata": "read"}, **change})
    token = GitHubAppTokenSource(lambda: httpx.Client(transport=httpx.MockTransport(handler)), *ENVELOPE.values(),
                                organization="acme-labs", read_only=True)
    with pytest.raises(GitHubAuthError):
        token()
    assert calls == ["GET"]


def test_remediation_and_content_dispatch_bind_every_selected_root_to_its_installation():
    github, secrets = GitHub(), {"credential": dict(ENVELOPE)}
    for org, iid in github.orgs.items():
        connection = {"target_id": targets.target_id({"organization": org}), "target": {"organization": org},
                      "auth_method": "github_app"}
        with github.client() as client:
            assert remediation.whoami(connection, secrets, client) == org
            assert remediation._access(connection, secrets, client).endswith(str(iid))
        child = onboarding.children(connection, "exposure", {})[0]
        payload = {**source.job_payload(child["config"]), "secret_ref": "synthetic"}
        resolved = inject_secret("github-org", payload, SimpleNamespace(resolve=lambda _: dict(ENVELOPE)),
                                 github_client_factory=github.client)
        assert resolved["token"]().endswith(str(iid))
    assert len(secrets[remediation._ACCESS]) == 2, "one root's write token cannot be reused for another"


@pytest.mark.parametrize("code", ["GITHUB_LIST_TRUNCATED", "GITHUB_ENTERPRISE_PERMISSION_REQUIRED", "GITHUB_APP_UNAVAILABLE"])
def test_optional_enterprise_inference_failure_never_rejects_a_verified_app(monkeypatch, code):
    from cremore_github_provider import enterprise_install

    def unavailable(*args):
        raise GitHubAuthError(code)

    monkeypatch.setattr(enterprise_install, "installations", unavailable)
    github = GitHub(owner="Organization")
    connection = {"auth_method": "github_app", "edition": "enterprise_cloud",
                  "target": {"auth": {"github_enterprise": "stale-hint"}}}
    result = onboarding.authenticate(connection, {"credential": ENVELOPE}, SimpleNamespace(http_client=github.client))
    assert result["status"] == "GRANTED"
    assert "enterprise" not in connection["target"] and "github_enterprise" not in connection["target"]["auth"]
    assert github.calls == [("GET", "/app")]


@pytest.mark.parametrize("purposes", [["inventory", "exposure"], ["remediation"]])
def test_selecting_only_the_second_organization_preserves_binding_in_single_target_storage(purposes):
    repo, github = InMemoryRepository(), GitHub()
    view = draft(repo, github, purposes)
    chosen = view["roots"][1]
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[chosen["id"]],
        plans={p: {} for p in purposes}), "admin"), github)
    assert view["state"] == "CHECKED" and not view["blockers"], view
    made = finish(repo, view)
    assert "version" not in made["target"] and made["target"]["organization"] == "acme-labs"
    assert made["target"]["auth"]["github_organization_binding"] is True
    if "inventory" in purposes:
        assert len(made["children"]) == 2
        assert {r["provider_resource_id"] for r in view["resources"]} == {"acme-labs/repo"}
    else:
        with github.client() as client:
            assert remediation.whoami(made, {"credential": ENVELOPE}, client) == "acme-labs"
            assert remediation._access(made, {"credential": ENVELOPE}, client).endswith("789")
    minted = [path for method, path in github.calls if method == "POST"]
    assert minted and set(minted) == {"/app/installations/789/access_tokens"}


def test_editing_a_legacy_single_org_keeps_source_and_scope_history_when_adding_the_same_org_binding():
    repo, github = InMemoryRepository(), GitHub()
    view = draft(repo, github, ["exposure"])
    first = view["roots"][0]["id"]
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[first], plans={"exposure": {}}), "admin"), github)
    made = finish(repo, view)
    store = ProviderConnectionStore(repo)
    record = store.get(made["id"])
    old_source = repo.list_connections()[0]
    old_profile = repo.list_scope_profiles("source", old_source.id)[0]
    # A pre-auth-first v1 App source has the same org and credential, with no redundant org-selection hint.
    old_target = {**record["target"], "auth": {}}
    record = store.update(record["id"], record["revision"], "admin", target=old_target)
    repo.update_connection(old_source.id, config={k: v for k, v in old_source.config.items() if k != "app_organization"})
    view = sessions.edit(repo, SETTINGS, made["id"], {"browser_key": KEY, "expected_revision": record["revision"]}, "admin")
    view = run(repo, view, github)
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=["exposure"]), "admin"), github)
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[r["id"] for r in view["roots"]],
        plans={"exposure": {}}), "admin"), github)
    assert view["state"] == "CHECKED", view
    assert len(view["selected_resources"]) == 1, "the earlier approved selection is restored under the same source key"
    after = finish(repo, view)
    assert len(repo.list_connections()) == 2 and len(after["children"]) == 2
    retained = repo.get_connection(old_source.id)
    assert retained.status == "ACTIVE" and retained.config["app_organization"] == "acme"
    assert repo.list_scope_profiles("source", old_source.id)[0].id == old_profile.id
    assert old_profile.selected_roots[0]["resource_id"] == repo.list_scope_profiles("source", old_source.id)[0].selected_roots[0]["resource_id"]
    # Pause/resume uses the same canonical coordinates and does not lose the selected source.
    service.set_enabled(repo, after["id"], False, "admin")
    assert repo.get_connection(old_source.id).status == "DISABLED"
    service.set_enabled(repo, after["id"], True, "admin", SETTINGS)
    assert repo.get_connection(old_source.id).status == "PENDING"
    assert repo.list_scope_profiles("source", old_source.id)[0].id == old_profile.id


def test_source_identity_ignores_only_the_same_app_organization_hint():
    original = {"org": "acme", "auth_kind": "GITHUB_APP"}
    assert source.onboarding_coordinate({**original, "app_organization": "acme"}) == original
    for config in [{**original, "app_organization": "other"}, {"org": "acme", "app_organization": "acme"},
                   {**original, "app_organization": "acme", "github_host": "other.example.test"}]:
        assert source.onboarding_coordinate(config) != original
