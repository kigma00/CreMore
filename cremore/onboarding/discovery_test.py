"""Provider drafts list metadata without registering targets or running scans."""

import json
import uuid
from types import SimpleNamespace

import httpx
import pytest

from cremore.onboarding import check, service, sessions
from cremore.onboarding.sessions_test import KEY, SETTINGS, body
from cremore.onboarding.sessions_test import (
    repo as repo,  # noqa: PLC0414 -- shared memory/SQL fixture
)
from cremore.onboarding.store import ProviderConnectionStore
from cremore.secretstore.resolver import SecretResolver


def run(repo, view, handler, **extras):
    worker = SimpleNamespace(repo=repo, settings=SETTINGS,
        metadata_secret_resolver=SecretResolver(sealing_key=SETTINGS.sealing_keys),
        http_client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)), **extras)
    check.run(worker, repo.get_job(uuid.UUID(view["job_id"])))
    return sessions.read(repo, view["id"], body(view), "admin")


def start(repo, provider, method, credential=None):
    return sessions.create(repo, SETTINGS, {"browser_key": KEY, "provider": provider,
        "auth_method": method, "credential": credential or {}}, "admin")


def finish(repo, view):
    view = sessions.select(repo, view["id"], body(view, snapshot_id=view["snapshot_id"],
        resource_ids=[r["id"] for r in view.get("resources", [])]), "admin")
    return sessions.complete(repo, SETTINGS, view["id"], body(view, name="Synthetic integration"), "admin")


def test_gitlab_pages_and_multi_target_checks_share_one_owner(repo):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        assert request.method == "GET"
        if request.url.path.endswith("/personal_access_tokens/self"):
            return httpx.Response(200, json={"user_id": 7, "active": True, "scopes": ["read_api"]})
        if request.url.path == "/api/v4/groups":
            return httpx.Response(200, json=[])
        if request.url.path == "/api/v4/projects":
            assert request.url.params["membership"] == "true"  # never every public project of GitLab.com
            page = request.url.params["page"]
            return httpx.Response(200, json=[{"id": int(page), "path_with_namespace": "same display name"}],
                                  headers={"x-next-page": "2" if page == "1" else ""})
        if request.url.path.endswith("/members/all/7"):  # a project's inventory takes its Maintainer
            return httpx.Response(200, json={"access_level": 40})
        assert request.url.path in {"/api/v4/projects/1", "/api/v4/projects/2"}
        return httpx.Response(200, json={"id": int(request.url.path[-1])})

    view = run(repo, start(repo, "gitlab", "token", {"token": "synthetic-gl-token-" + "a" * 20}), handler)
    assert view["state"] == "AUTHENTICATED"
    assert calls == ["/api/v4/personal_access_tokens/self"]
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=["inventory"]), "admin"), handler)
    assert view["completeness"] == "PARTIAL" and view["has_more"]
    first = view["roots"][0]["id"]
    view = run(repo, sessions.discover(repo, view["id"], body(view, more=True), "admin"), handler)
    assert view["completeness"] == "COMPLETE" and first in {r["id"] for r in view["roots"]}
    assert not ProviderConnectionStore(repo).list()
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[r["id"] for r in view["roots"]],
        plans={"inventory": {}}), "admin"), handler)
    assert view["state"] == "CHECKED", view
    result = finish(repo, view)
    assert result["target"]["version"] == 2 and len(result["children"]) == 2
    assert len(ProviderConnectionStore(repo).list()) == 1
    from cremore.coverage.store import CoverageStore

    refs = [CoverageStore(repo).get(uuid.UUID(r["id"]))["spec"]["secret_refs"]["token"] for r in result["children"]]
    assert refs[0] == refs[1]
    stored = service.get(repo, result["id"])
    stored["checks"]["results"]["inventory"]["items"] = [i for i in stored["checks"]["results"]["inventory"]["items"]
        if i.get("target_id") == first]
    from cremore.onboarding.permissions import blockers

    assert blockers(stored, stored["plans"]), "one target's grant cannot approve a different target"
    # Target editing uses the same envelope and owner, and a removal cannot
    # reappear merely because the whole connection is paused and resumed.
    current = service.get(repo, result["id"])
    view = sessions.edit(repo, SETTINGS, current["id"], {"browser_key": KEY, "expected_revision": current["revision"]}, "admin")
    view = run(repo, view, handler)
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=["inventory"]), "admin"), handler)
    view = run(repo, sessions.discover(repo, view["id"], body(view, more=True), "admin"), handler)
    second = next(r["id"] for r in view["roots"] if r["id"] != first)
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[second], plans={"inventory": {}}), "admin"), handler)
    updated = finish(repo, view)
    assert updated["id"] == result["id"] and len(ProviderConnectionStore(repo).list()) == 1
    assert service.get(repo, updated["id"])["secret_refs"] == current["secret_refs"]
    assert len([child for child in updated["children"] if child["state"] == "ENABLED"]) == 1
    service.set_enabled(repo, updated["id"], False, "admin")
    resumed = service.set_enabled(repo, updated["id"], True, "admin")
    assert len([child for child in resumed["children"] if child["state"] == "ENABLED"]) == 1


@pytest.mark.parametrize("denied", [False, True])
def test_aws_runtime_lists_before_registration_and_saves_scope_atomically(repo, denied):
    from cremore.onboarding.onboarding_test import approve_aws

    approve_aws(repo)
    calls = []

    class AwsClient:
        def describe_regions(self, **kwargs):
            calls.append("ec2:DescribeRegions")
            if denied:
                from botocore.exceptions import ClientError

                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "synthetic-private-response"}}, "DescribeRegions")
            return {"Regions": [{"RegionName": "us-east-1"}]}

        def list_buckets(self, **kwargs):
            calls.append("s3:ListBuckets")
            return {"Buckets": [{"Name": "synthetic-test-bucket"}]}

    identity = {"state": "READY", "account_id": "111111111111", "match_key": "iam-role:cremore",
                "kind": "IAM_ROLE", "credential_source": "iam-role"}
    aws = SimpleNamespace(identity=lambda *_: identity, client_factory=lambda *_: AwsClient())
    request = lambda view: run(repo, view, lambda r: pytest.fail("AWS never uses HTTP here"), aws_sessions=aws)
    view = request(start(repo, "aws", "runtime"))
    assert view["state"] == "AUTHENTICATED", view
    assert not calls and not repo.list_aws_accounts()
    view = request(sessions.discover(repo, view["id"], body(view, purposes=["exposure"]), "admin"))
    if denied:
        assert view["state"] == "FAILED" and view["error"] == "AWS_REGIONS_ACCESS_DENIED"
        assert not repo.list_aws_accounts() and "synthetic-private-response" not in json.dumps(view)
        return
    assert view["state"] == "LISTED", view
    assert view["roots"][0]["plan_options"]["regions"] == ["us-east-1"]
    view = request(sessions.inspect(repo, view["id"], body(view, target_ids=[view["roots"][0]["id"]],
        plans={"exposure": {}}), "admin"))
    assert view["state"] == "CHECKED", view
    assert not repo.list_aws_accounts()
    result = finish(repo, view)
    account = repo.list_aws_accounts()[0]
    assert account.validation_status == "VALID"
    profile = repo.list_scope_profiles("aws", account.id)[0]
    from cremore.scanning.scope import auth_revision

    assert profile.auth_revision == auth_revision("aws", account)
    assert len(profile.selected_roots) == 1 and result["status"] == "ACTIVE"
    assert not any(j.kind in {"scope", "scan"} for j in repo.list_jobs(100))


def test_gcp_storage_identity_needs_no_iam_inventory_access(repo, monkeypatch):
    from cremore_gcp_provider import content, gcp_auth

    monkeypatch.setattr(gcp_auth, "adc_token", lambda **_: lambda: "synthetic-adc")
    # The content module may already be imported by another collected test.
    monkeypatch.setattr(content, "adc_token", lambda **_: lambda: "synthetic-adc")
    calls = []

    def handler(request):
        calls.append((request.method, request.url.host, request.url.path))
        assert "iam.googleapis.com" != request.url.host, "Storage-only identities do not need IAM inventory access"
        if request.url.path == "/tokeninfo":
            return httpx.Response(200, json={"expires_in": "3600"})
        if request.url.path == "/v3/projects:search":
            return httpx.Response(200, json={"projects": [{"projectId": "synthetic-project", "state": "ACTIVE"}]})
        if request.url.path.endswith(":testIamPermissions"):
            return httpx.Response(200, json={"permissions": json.loads(request.content)["permissions"]})
        assert request.url.path == "/storage/v1/b"
        return httpx.Response(200, json={"items": [{"id": "synthetic-test-bucket", "name": "synthetic-test-bucket"}]})

    view = run(repo, start(repo, "gcp", "adc"), handler)
    assert view["state"] == "AUTHENTICATED", view
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=["exposure"]), "admin"), handler)
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[view["roots"][0]["id"]],
        plans={"exposure": {}}), "admin"), handler)
    assert view["state"] == "CHECKED", view
    assert len(view["resources"]) == 1
    assert ("GET", "storage.googleapis.com", "/storage/v1/b") in calls
    assert finish(repo, view)["status"] == "ACTIVE"


@pytest.mark.parametrize("provider", ["okta", "keycloak"])
def test_directory_authentication_precedes_optional_reads(repo, provider):
    method = "made_key" if provider == "okta" else "oauth_client"
    context = {"organization": "synthetic.okta.com"} if provider == "okta" else {
        "address": "https://synthetic.example.test", "realm": "staff"}
    credential = {"client_id": "synthetic-client"}
    if provider == "keycloak":
        credential["client_secret"] = "synthetic-secret-never-real"
    view = sessions.create(repo, SETTINGS, {"provider": provider, "auth_method": method, "context": context,
        "credential": credential, "browser_key": KEY}, "admin")
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if request.method == "POST":
            return httpx.Response(200, json={"access_token": "synthetic-access", "token_type": "Bearer", "expires_in": 3600})
        assert request.url.path.endswith("/users"), "unselected apps/events must never be read"
        return httpx.Response(200, json=[])

    if provider == "okta":
        assert view["state"] == "SETUP_REQUIRED" and "job_id" not in view
        assert set(view["generated"]["public_jwk"]) == {"kty", "e", "n", "kid", "alg", "use"}
        original = view["generated"]["kid"]
        view = sessions.authenticate(repo, view["id"], body(view), "admin")
        assert view["generated"]["kid"] == original
    view = run(repo, view, handler)
    assert view["state"] == "AUTHENTICATED", view
    assert len(calls) == 1 and calls[0].endswith("/token")
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=["identity"]), "admin"), handler)
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[view["roots"][0]["id"]],
        plans={"identity": {"apps": False}}), "admin"), handler)
    assert view["state"] == "CHECKED" and view["blockers"] == [], view
    result = finish(repo, view)
    assert result["status"] == "ACTIVE" and len(result["children"]) == 1
    if provider == "keycloak":
        assert result["plans"]["identity"]["admin_events"] is False


def test_github_auth_and_organization_listing_never_use_response_links(repo):
    calls = []

    def handler(request):
        assert request.url.host == "api.github.com" and request.method == "GET"
        calls.append(request.url.path)
        if request.url.path == "/user":
            return httpx.Response(200, json={"id": 7})
        assert request.url.path == "/user/orgs"
        return httpx.Response(200, json=[{"login": "synthetic-org", "type": "Organization"}],
                              headers={"link": '<https://untrusted.invalid/>; rel="next"'})

    view = run(repo, start(repo, "github", "token", {"token": "ghp_" + "x" * 36}), handler)
    assert view["state"] == "AUTHENTICATED" and calls == ["/user"]
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=["exposure"]), "admin"), handler)
    assert view["state"] == "LISTED" and not view["has_more"]
    assert view["roots"][0]["target"]["organization"] == "synthetic-org"


def test_a_server_token_draft_keeps_the_enterprise_so_its_instance_saml_names_the_people(repo):
    """The enterprise is typed before authentication: a PAT draft without it never offers the enterprise SSO choice,
    and a Server's SAML is read nowhere else. The wizard lists organizations next, which takes read:org besides
    read:enterprise: authentication says so before anything is chosen."""
    scopes = "read:enterprise"

    def handler(request):
        assert request.url.host == "ghes.acme.test"
        if request.url.path == "/api/v3/user":
            return httpx.Response(200, json={"id": 7}, headers={"X-OAuth-Scopes": scopes})
        if request.url.path == "/api/v3/user/orgs":  # GitHub: a classic PAT needs user or read:org, else 403
            return httpx.Response(200, json=[{"login": "synthetic-org"}]) if "read:org" in scopes else httpx.Response(403)
        assert request.url.path == "/api/graphql"
        assert json.loads(request.content)["variables"]["enterprise"] == "acme"
        return httpx.Response(200, json={"data": {"enterprise": {"ownerInfo": {"__typename": "EnterpriseOwnerInfo"}}}})

    def authenticated():
        view = sessions.create(repo, SETTINGS, {"browser_key": KEY, "provider": "github", "edition": "enterprise_server",
            "auth_method": "token", "context": {"host": "https://ghes.acme.test", "enterprise": "acme"},
            "credential": {"token": "ghp_" + "x" * 36}}, "admin")
        return run(repo, view, handler)

    view = authenticated()  # the sign-in works; the console warns before anything is chosen
    assert view["state"] == "AUTHENTICATED" and view["authentication"]["detail"] == "GITHUB_TOKEN_READ_ORG_REQUIRED"
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=["identity"]), "admin"), handler)
    assert view["state"] == "FAILED" and view["error"] == "GITHUB_ORGANIZATIONS_HTTP_403"
    scopes = "read:enterprise, read:org"
    view = authenticated()
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=["identity"]), "admin"), handler)
    assert view["state"] == "LISTED" and view["roots"][0]["target"]["enterprise"] == "acme", view.get("error")
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[view["roots"][0]["id"]],
        plans={"identity": {"enterprise_identities": True}}), "admin"), handler)
    assert view["state"] == "CHECKED" and view["blockers"] == [], view
    result = finish(repo, view)
    assert result["status"] == "ACTIVE" and result["plans"]["identity"]["enterprise_identities"] is True


@pytest.mark.parametrize("token, scopes, warning, refused", [
    ("github_pat_" + "x" * 60, None, "AUTH_FIRST_FINE_GRAINED_DISCOVERY_UNSUPPORTED",
     "AUTH_FIRST_FINE_GRAINED_DISCOVERY_UNSUPPORTED"),
    ("ghp_" + "x" * 36, "repo", "GITHUB_TOKEN_READ_ORG_REQUIRED", "GITHUB_ORGANIZATIONS_HTTP_403"),
])
def test_a_github_token_that_cannot_list_organizations_is_warned_at_sign_in_and_may_be_saved_alone(
        repo, token, scopes, warning, refused):
    def handler(request):
        if request.url.path == "/user/orgs":
            return httpx.Response(403)
        assert request.url.path == "/user"
        return httpx.Response(200, json={"id": 7}, headers={} if scopes is None else {"X-OAuth-Scopes": scopes})

    view = run(repo, start(repo, "github", "token", {"token": token}), handler)
    assert view["state"] == "AUTHENTICATED" and view["authentication"]["detail"] == warning
    saved = sessions.complete(repo, SETTINGS, view["id"], body(view, name="GitHub account", authentication_only=True),
                              "admin")
    assert saved["checks"]["authentication_only"] is True  # the sign-in alone needs no organization list
    view = run(repo, start(repo, "github", "token", {"token": token}), handler)
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=["exposure"]), "admin"), handler)
    assert view["state"] == "FAILED" and view["error"] == refused  # never an empty account


def test_github_app_personal_installation_cannot_offer_org_inventory(monkeypatch):
    from cremore_github_provider import onboarding

    monkeypatch.setattr(onboarding, "_authentication_headers", lambda *a: {})
    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=[{"id": 1, "account": {"login": "synthetic", "type": "User"}}]))))
    roots, completeness, cursor = onboarding.discover(
        {"auth_method": "github_app", "edition": "cloud", "target": {}, "purposes": ["inventory"]},
        {"credential": {"GITHUB_APP_INSTALLATION_ID": "1"}}, context)
    assert (roots, completeness, cursor) == ([], "COMPLETE", None)


def test_slack_lists_authenticated_organization_and_only_selected_permissions(repo):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        assert request.url.host == "slack.com", "unselected audit log must not be read"
        if request.url.path == "/api/auth.test":
            return httpx.Response(200, json={"ok": True, "user_id": "U123TEST", "enterprise_id": "E123TEST"})
        if request.url.path == "/api/admin.teams.list":
            return httpx.Response(200, json={"ok": True, "teams": [{"id": "T123TEST"}]})
        assert request.url.path == "/api/admin.apps.approved.list"
        assert request.url.params["enterprise_id"] == "E123TEST"
        return httpx.Response(200, json={"ok": True, "approved_apps": []})

    view = run(repo, start(repo, "slack", "token", {"token": "xoxp-" + "x" * 30}), handler)
    assert view["state"] == "AUTHENTICATED" and calls == ["/api/auth.test"]
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=["inventory"]), "admin"), handler)
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[view["roots"][0]["id"]],
        plans={"inventory": {}}), "admin"), handler)
    assert view["state"] == "CHECKED" and not view["blockers"], view
    assert finish(repo, view)["status"] == "ACTIVE"
    bad = run(repo, start(repo, "slack", "token", {"token": "xoxp-" + "y" * 30}),
              lambda _: httpx.Response(200, json={"team_id": "T123TEST"}))
    assert bad["state"] == "AUTH_FAILED"


@pytest.mark.parametrize("provider", ["vault", "openbao"])
def test_vault_metadata_read_does_not_grant_value_read(repo, provider):
    allow_values = False

    def handler(request):
        if request.url.path.endswith("lookup-self"):
            return httpx.Response(200, json={"data": {"policies": ["synthetic"]}})
        if request.url.path == "/v1/sys/mounts":
            return httpx.Response(200, json={"data": {"secret/": {"type": "kv", "options": {"version": "2"}},
                                                      "database/": {"type": "database"}}})
        assert request.url.path == "/v1/sys/capabilities-self"
        # A LIST is decided on the prefix with its trailing slash; the mount list is asked too (not required).
        assert set(json.loads(request.content)["paths"]) == {"secret/metadata/", "secret/data/*", "sys/mounts"}
        return httpx.Response(200, json={"secret/metadata/": ["list", "read"], "sys/mounts": ["read"],
                                         "secret/data/*": ["read"] if allow_values else ["deny"]})

    view = sessions.create(repo, SETTINGS, {"provider": provider, "auth_method": "token", "browser_key": KEY,
        "context": {"address": "https://vault.example.test"}, "credential": {"token": "synthetic-vault-token"}}, "admin")
    view = run(repo, view, handler)
    assert view["state"] == "AUTHENTICATED", view
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=["vault"]), "admin"), handler)
    assert len(view["roots"]) == 1
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[view["roots"][0]["id"]], plans={"vault": {}}), "admin"), handler)
    assert any(b.get("permission") == "kv_read" for b in view["blockers"])
    with pytest.raises(service.OnboardingError, match="REQUIRED_PERMISSIONS"):
        finish(repo, view)
    allow_values = True
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[view["roots"][0]["id"]], plans={"vault": {}}), "admin"), handler)
    assert not view["blockers"] and "credential_marks" not in view["checks"]
    assert finish(repo, view)["status"] == "ACTIVE"


def test_microsoft_targets_are_bound_to_their_selected_features(repo, monkeypatch):
    from cremore_azure_provider import onboarding

    tenant, subscription = str(uuid.uuid4()), str(uuid.uuid4())
    monkeypatch.setattr(onboarding, "_ambient", lambda *_: "synthetic-azure-token")
    calls = []

    def handler(request):
        calls.append(request.url.path)
        path = request.url.path
        if path == "/subscriptions":
            return httpx.Response(200, json={"value": [{"subscriptionId": subscription, "tenantId": tenant, "state": "Enabled"}]})
        if path.endswith("storageAccounts"):
            return httpx.Response(200, json={"value": [{"id": f"/subscriptions/{subscription}/resourceGroups/test/providers/Microsoft.Storage/storageAccounts/syntheticstore"}]})
        if path.endswith("vaults"):
            return httpx.Response(200, json={"value": [{"id": f"/subscriptions/{subscription}/resourceGroups/test/providers/Microsoft.KeyVault/vaults/synthetic-vault"}]})
        assert path in {"/v1.0/users", "/v1.0/applications", "/v1.0/organization", f"/subscriptions/{subscription}", "/secrets"}
        return httpx.Response(200, json={"value": []})

    view = sessions.create(repo, SETTINGS, {"provider": "azure", "auth_method": "workload_identity", "browser_key": KEY,
        "context": {"tenant": tenant}}, "admin")
    view = run(repo, view, handler)
    assert view["state"] == "AUTHENTICATED" and calls == []
    purposes = ["inventory", "vault", "identity"]
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=purposes), "admin"), handler)
    assert len(view["roots"]) == 3, view
    roots = {r["purposes"][0]: r for r in view["roots"]}
    with pytest.raises(service.OnboardingError, match="EACH_FEATURE_NEEDS_TARGET"):
        sessions.inspect(repo, view["id"], body(view, target_ids=[roots["identity"]["id"]], plans={p: {} for p in purposes}), "admin")
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[r["id"] for r in roots.values()], plans={p: {} for p in purposes}), "admin"), handler)
    assert not view["blockers"], view
    assert calls.count("/v1.0/users") == 1 and calls.count("/secrets") == 1
    result = finish(repo, view)
    assert result["target"]["version"] == 2 and len(result["children"]) == 4


@pytest.mark.parametrize("provider", ["confluence", "bitbucket", "atlassian"])
def test_atlassian_authenticated_lists_never_follow_response_hosts(repo, provider):
    organization = str(uuid.uuid4())
    method = {"confluence": "token", "bitbucket": "api_token", "atlassian": "api_key"}[provider]
    credential = {"token": "synthetic-atlassian-token-value", **({"email": "admin@example.test"} if provider == "bitbucket" else {})}
    context = {"base_url": "https://synthetic.atlassian.net/wiki"} if provider == "confluence" else {}
    purpose = "exposure" if provider != "atlassian" else "inventory"
    calls = []

    def handler(request):
        calls.append(request.url.path)
        assert request.url.host != "untrusted.invalid"
        if request.url.path.endswith("/user/current"):
            return httpx.Response(200, json={"type": "known", "accountId": "synthetic-user"})
        if request.url.path == "/2.0/user":
            return httpx.Response(200, json={"uuid": "{synthetic-user}"})
        if provider == "confluence":
            return httpx.Response(200, json={"results": [{"id": "123", "name": "Space"}], "_links": {"next": "https://untrusted.invalid/?cursor=next"}})
        if provider == "bitbucket":
            return httpx.Response(200, json={"values": [{"slug": "test-workspace", "name": "Workspace"}], "next": "https://untrusted.invalid/?page=2"})
        return httpx.Response(200, json={"data": [{"id": organization, "attributes": {"name": "Test organization"}}]})

    view = sessions.create(repo, SETTINGS, {"provider": provider, "auth_method": method, "browser_key": KEY,
        "credential": credential, "context": context}, "admin")
    view = run(repo, view, handler)
    assert view["state"] == "AUTHENTICATED", view
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=[purpose]), "admin"), handler)
    assert view["state"] == "LISTED" and len(view["roots"]) == 1, view
    assert not ProviderConnectionStore(repo).list()


def test_workspace_authentication_checks_admin_without_enumerating_users(repo):
    from cremore_gcp_provider.workspace.identity_test import SECRETS

    calls = []

    def handler(request):
        calls.append(request.url.path)
        if request.url.path == "/token":
            return httpx.Response(200, json={"access_token": "synthetic-workspace-access", "expires_in": 3600})
        assert request.url.path.endswith("/users/admin@acme.com")
        return httpx.Response(200, json={"isAdmin": True})

    view = sessions.create(repo, SETTINGS, {"provider": "google_workspace", "auth_method": "service_account_delegation",
        "browser_key": KEY, "context": {"domain": "acme.com"}, "credential": SECRETS}, "admin")
    view = run(repo, view, handler)
    assert view["state"] == "AUTHENTICATED", view
    assert len(calls) == 2
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=["identity"]), "admin"), handler)
    assert view["roots"][0]["target"] == {"domain": "acme.com"} and len(calls) == 2
