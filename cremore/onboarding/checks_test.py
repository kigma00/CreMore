"""Each provider's permission check against a synthetic server: statuses and codes only."""

import json
from types import SimpleNamespace

import httpx
import pytest

from cremore.config import Settings
from cremore.onboarding import catalog
from cremore.onboarding.check import clean, summary
from cremore.onboarding.onboarding_test import PEM

TENANT = "11111111-2222-4333-8444-555555555555"


def context(handler, **extra):
    seen = []

    def factory():
        def record(request):
            seen.append(request)
            return handler(request)
        return httpx.Client(transport=httpx.MockTransport(record))

    # Shaped like check.CheckContext: ``memo`` is shared by the purposes of one check.
    return SimpleNamespace(http_client=factory, settings=Settings(FINGERPRINT_KEY="ab" * 32), children=[],
                           seen=seen, memo=extra.pop("memo", {}), **extra)


def run(provider, edition, method, purpose, target, envelope, handler, **extra):
    connection = {"provider": provider, "edition": edition, "auth_method": method, "target": target,
                  "purposes": [purpose], "name": provider}
    ctx = context(handler, **extra)
    items = clean(catalog.module(provider).check(connection, purpose, {"credential": envelope} if envelope else {}, ctx),
                  catalog.permissions_for(provider, purpose, method, target))
    dumped = json.dumps(items)
    assert not any(value in dumped for value in (envelope or {}).values() if len(value) > 8)
    return {item["permission"]: item["status"] for item in items}, items, ctx


def test_gitlab_reads_the_token_scopes_and_the_maintainer_role():
    scopes = ["read_api", "read_repository"]

    def handler(request):
        path = request.url.path
        assert request.headers["PRIVATE-TOKEN"] == "glpat-secret-value-0000"
        if path == "/api/v4/personal_access_tokens/self":
            return httpx.Response(200, json={"scopes": scopes, "user_id": 9})
        if path == "/api/v4/groups/42":
            return httpx.Response(200, json={"id": 42})
        if path == "/api/v4/groups/42/members/all/9":
            return httpx.Response(200, json={"access_level": 30})
        return httpx.Response(404)

    target = {"scope": "group", "id": "42"}
    token = {"token": "glpat-secret-value-0000"}
    exposure, items, _ctx = run("gitlab", "cloud", "token", "exposure", target, token, handler)
    # Without self_rotate (or api) the token is replaced by hand before it expires.
    assert exposure == {"read_repository": "GRANTED", "read_api": "GRANTED", "self_rotate": "MISSING"}
    assert {item["permission"]: item.get("detail") for item in items}["self_rotate"] == "TOKEN_RENEWED_BY_HAND"
    scopes.append("self_rotate")
    # Group CI variables, a group's tokens and its audit events for everyone take the group's Owner.
    vault, items, _ctx = run("gitlab", "cloud", "token", "vault", target, token, handler)
    assert vault == {"read_api": "GRANTED", "owner": "MISSING", "self_rotate": "GRANTED"}
    assert summary(items) == "MISSING"
    inventory, _items, _ctx = run("gitlab", "cloud", "token", "inventory", target, token, handler)
    assert inventory == {"read_api": "GRANTED", "owner": "MISSING", "self_rotate": "GRANTED"}
    # A project's take its Maintainer.
    project = {"scope": "project", "id": "42"}

    def project_handler(request):
        if request.url.path == "/api/v4/projects/42":
            return httpx.Response(200, json={"id": 42})
        if request.url.path == "/api/v4/projects/42/members/all/9":
            return httpx.Response(200, json={"access_level": 40})
        return handler(request)

    vault, _items, _ctx = run("gitlab", "cloud", "token", "vault", project, token, project_handler)
    assert vault == {"read_api": "GRANTED", "maintainer": "GRANTED", "self_rotate": "GRANTED"}


def test_gitlab_instance_inventory_needs_an_administrator():
    def handler(admin):
        def answer(request):
            if request.url.path == "/api/v4/personal_access_tokens/self":
                return httpx.Response(200, json={"scopes": ["read_api"], "user_id": 1})
            if request.url.path == "/api/v4/user":
                return httpx.Response(200, json={"id": 1, "is_admin": admin})
            return httpx.Response(404)
        return answer

    target = {"scope": "instance", "host": "https://gitlab.example.com"}
    status, _items, _ctx = run("gitlab", "self_managed", "token", "inventory", target, {"token": "glpat-x" * 4},
                               handler(True))
    assert status == {"read_api": "GRANTED", "instance_admin": "GRANTED", "self_rotate": "MISSING"}
    status, items, _ctx = run("gitlab", "self_managed", "token", "inventory", target, {"token": "glpat-x" * 4},
                              handler(False))
    assert status["instance_admin"] == "MISSING"
    assert {item.get("detail") for item in items if item["permission"] == "instance_admin"} == {"NOT_AN_ADMINISTRATOR"}


def test_gitlab_refused_token_is_missing_everywhere():
    status, _items, _ctx = run("gitlab", "cloud", "token", "inventory", {"scope": "group", "id": "1"},
                               {"token": "glpat-x" * 4}, lambda request: httpx.Response(401))
    assert status == {"read_api": "MISSING", "owner": "MISSING", "self_rotate": "MISSING"}


def test_confluence_bitbucket_and_the_atlassian_organization_ask_the_read_they_need():
    ok = lambda request: httpx.Response(200, json={})
    denied = lambda request: httpx.Response(403)
    status, _items, ctx = run("confluence", "cloud", "token", "exposure",
                              {"base_url": "https://acme.atlassian.net/wiki", "space": "123"}, {"token": "t" * 24}, ok)
    assert status == {"read_space": "GRANTED", "read_content": "GRANTED"}
    assert [r.url.path for r in ctx.seen] == ["/wiki/api/v2/spaces/123", "/wiki/api/v2/spaces/123/pages"]
    status, _items, ctx = run("bitbucket", "cloud", "api_token", "inventory",
                              {"workspace": "acme", "auth": {"email": "ops@example.com"}},
                              {"token": "t" * 24, "username": "ops@example.com", "password": "t" * 24}, denied)
    assert status == {"list_access_tokens": "MISSING"} and ctx.seen[0].headers["authorization"].startswith("Basic ")
    status, _items, _ctx = run("bitbucket", "data_center", "http_token", "exposure",
                               {"base_url": "https://git.example.com", "project": "PAY"}, {"token": "t" * 24}, ok)
    assert status == {"read_repositories": "GRANTED"}
    status, _items, _ctx = run("atlassian", "cloud", "api_key", "inventory", {"organization": TENANT},
                               {"token": "t" * 24}, ok)
    assert status == {"organization_admin": "GRANTED", "oauth_clients_read": "NOT_REPORTED"}


def test_notion_content_needs_a_shared_page_and_the_inventory_a_workspace():
    shared = lambda request: httpx.Response(200, json={"results": [{"id": "p"}]})
    status, _items, _ctx = run("notion", "cloud", "integration", "exposure", {}, {"token": "secret_" + "a" * 40}, shared)
    assert status == {"read_content": "GRANTED", "pages_shared": "GRANTED"}
    empty = lambda request: httpx.Response(200, json={"results": []})
    status, items, _ctx = run("notion", "cloud", "integration", "exposure", {}, {"token": "secret_" + "a" * 40}, empty)
    assert status["pages_shared"] == "MISSING" and items[1]["detail"] == "NO_PAGE_SHARED_WITH_INTEGRATION"
    status, items, _ctx = run("notion", "cloud", "organization_bot", "inventory", {}, {"token": "ntn_" + "a" * 40}, shared)
    assert status == {"workspace_tokens": "MISSING", "mcp_connections": "MISSING"}
    assert all(item["detail"] == "WORKSPACE_ID_REQUIRED" for item in items)


def test_gcp_asks_the_project_which_permissions_the_identity_holds(monkeypatch):
    from cremore_gcp_provider import gcp_auth

    monkeypatch.setattr(gcp_auth, "adc_token", lambda scopes=None: lambda: "ya29.synthetic")

    def handler(request):
        assert request.url.path == "/v1/projects/acme-prod:testIamPermissions"
        asked = json.loads(request.content)["permissions"]
        return httpx.Response(200, json={"permissions": [p for p in asked if p != "storage.objects.get"]})

    status, _items, _ctx = run("gcp", "cloud", "adc", "exposure", {"scope": "project", "project": "acme-prod"}, None,
                               handler)
    assert status == {"storage.buckets.list": "GRANTED", "storage.objects.list": "GRANTED",
                      "storage.objects.get": "MISSING"}


def test_azure_checks_each_read_with_the_ambient_identity(monkeypatch):
    from cremore_azure_provider.metadata import transport

    monkeypatch.setattr(transport, "default_token", lambda scope, **kw: lambda: "eyJ.synthetic")

    def handler(request):
        host = request.url.host
        if host == "graph.microsoft.com":
            return httpx.Response(200, json={"value": []})
        if host == "management.azure.com":
            return httpx.Response(403)
        if host == "acmedata.blob.core.windows.net":
            return httpx.Response(200, content=b"<EnumerationResults/>")
        return httpx.Response(200, json={"value": []})

    target = {"tenant": TENANT, "subscription": TENANT, "storage_account": "acmedata", "key_vaults": ["acme-vault"]}
    status, _items, _ctx = run("azure", "cloud", "workload_identity", "inventory", target, None, handler)
    assert status == {"applications_read": "GRANTED", "organization_read": "GRANTED", "subscription_read": "MISSING",
                      "subscriptions_list": "NOT_REPORTED", "storage_keys_read": "NOT_REPORTED",
                      "credential_sign_ins": "NOT_REPORTED", "directory_audits": "NOT_REPORTED",
                      "role_management_read": "NOT_REPORTED", "root_role_assignments": "NOT_REPORTED"}
    status, _items, _ctx = run("azure", "cloud", "workload_identity", "exposure", target, None, handler)
    assert status == {"blob_read": "GRANTED"}
    status, _items, _ctx = run("azure", "cloud", "workload_identity", "vault", target, None, handler)
    assert status == {"key_vault_list": "GRANTED", "key_vault_values": "NOT_REPORTED",
                      "key_vault_keys": "NOT_REPORTED", "key_vault_certificates": "NOT_REPORTED",
                      "key_vault_deleted": "NOT_REPORTED", "key_vault_public_certificates": "NOT_REPORTED"}
    status, _items, _ctx = run("entra_id", "cloud", "workload_identity", "identity", {"tenant": TENANT}, None, handler)
    # The tenant check for an opaque token is shown (not required, cremore_azure_provider.onboarding).
    assert status == {"users_read": "GRANTED", "organization_read": "GRANTED"}


def test_a_tenant_without_entra_id_p1_or_p2_is_told_so_for_the_log_options(monkeypatch):
    from cremore_azure_provider.metadata import transport

    monkeypatch.setattr(transport, "default_token", lambda scope, **kw: lambda: "eyJ.synthetic")

    def handler(request):
        if request.url.path.endswith("/auditLogs/signIns"):
            return httpx.Response(403, json={"error": {"code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant"}})
        if request.url.path.endswith("/auditLogs/directoryAudits"):
            return httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied"}})
        return httpx.Response(200, json={"value": []})

    connection = {"provider": "azure", "edition": "cloud", "auth_method": "workload_identity", "target": {"tenant": TENANT},
                  "purposes": ["inventory"], "name": "azure",
                  "plans": {"inventory": {"credential_sign_ins": True, "directory_audits": True}}}
    items = {row["permission"]: row for row in catalog.module("azure").check(connection, "inventory", {}, context(handler))}
    # The license, not a permission, refuses the sign-in logs; the audit log's refusal stays a permission.
    assert items["credential_sign_ins"] == {"permission": "credential_sign_ins", "status": "MISSING",
                                            "detail": "AZURE_ENTRA_PREMIUM_REQUIRED"}
    assert items["directory_audits"] == {"permission": "directory_audits", "status": "MISSING", "detail": "HTTP_403"}


def test_app_permission_options_check_the_entra_roles_read_and_the_root_role_assignments(monkeypatch):
    from cremore_azure_provider.metadata import transport

    monkeypatch.setattr(transport, "default_token", lambda scope, **kw: lambda: "eyJ.synthetic")
    asked = []
    root = f"/providers/Microsoft.Management/managementGroups/{TENANT}/providers/Microsoft.Authorization/roleAssignments"

    def check(plan, arm_status):
        def handler(request):
            asked.append((request.url.host, request.url.path, dict(request.url.params)))
            return httpx.Response(arm_status if request.url.host == "management.azure.com" else 200, json={"value": []})

        connection = {"provider": "azure", "edition": "cloud", "auth_method": "workload_identity", "target": {"tenant": TENANT},
                      "purposes": ["inventory"], "name": "azure", "plans": {"inventory": plan}}
        return {row["permission"]: row for row in catalog.module("azure").check(connection, "inventory", {}, context(handler))}

    items = check({"app_permissions": True}, 403)
    assert items["role_management_read"]["status"] == "GRANTED" and "root_role_assignments" not in items
    assert not any(host == "management.azure.com" for host, _path, _params in asked)
    items = check({"app_azure_roles": True}, 403)
    assert items["root_role_assignments"]["status"] == "MISSING" and "role_management_read" not in items
    assert ("management.azure.com", root, {"api-version": "2022-04-01", "$filter": "atScope()"}) in asked
    # A tenant that never used management groups has no root to read from, and is told so.
    assert check({"app_azure_roles": True}, 404)["root_role_assignments"]["detail"] == "AZURE_ROOT_MANAGEMENT_GROUP_NOT_FOUND"


def test_the_microsoft_connection_signs_in_with_its_certificate_and_asks_devops_too():
    from urllib.parse import parse_qs

    from cremore_azure_provider import app_certificate

    envelope, _shown = app_certificate.make(TENANT, TENANT)
    scopes = []

    def handler(request):
        host, path = request.url.host, request.url.path
        if host == "login.microsoftonline.com":
            form = parse_qs(request.content.decode())
            assert form["client_assertion_type"] == ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]
            scopes.append(form["scope"][0])
            return httpx.Response(200, json={"access_token": "entra-" + str(len(scopes)), "expires_in": 3600})
        assert request.headers["authorization"].startswith("Bearer entra-")
        if host == "graph.microsoft.com":
            # The app reads its own application object only with Application.Read.All.
            return httpx.Response(403 if path.startswith("/v1.0/applications(") else 200, json={"value": []})
        if path.endswith("/_apis/graph/users"):
            return httpx.Response(200, json={"value": [{"descriptor": "aad.MDAwMDAw"}]})
        if "/tokenadmin/" in path or "/_apis/git/" in path:
            return httpx.Response(200, json={"value": []})
        return httpx.Response(200, json={"value": []})

    target = {"tenant": TENANT, "key_vaults": ["acme-vault"], "devops_organization": "acme", "devops_project": "Payments"}
    memo = {}
    status, _items, _ctx = run("azure", "cloud", "certificate", "inventory", target, envelope, handler, memo=memo)
    assert status == {"applications_read": "GRANTED", "organization_read": "GRANTED", "subscriptions_list": "NOT_REPORTED",
                      "storage_keys_read": "NOT_REPORTED", "credential_sign_ins": "NOT_REPORTED", "directory_audits": "NOT_REPORTED",
                      "role_management_read": "NOT_REPORTED", "root_role_assignments": "NOT_REPORTED",
                      "graph_read": "GRANTED", "token_administration": "GRANTED"}
    status, items, _ctx = run("azure", "cloud", "certificate", "exposure", target, envelope, handler, memo=memo)
    assert status == {"code_read": "GRANTED", "applications_read": "MISSING"}
    assert "blob_read" not in {item["permission"] for item in items}
    status, _items, _ctx = run("azure", "cloud", "certificate", "identity", target, envelope, handler, memo=memo)
    assert status == {"users_read": "GRANTED", "organization_read": "GRANTED", "applications_read": "MISSING"}
    # One token per Microsoft resource for the whole check: Graph, then Azure DevOps.
    assert scopes == ["https://graph.microsoft.com/.default", "499b84ac-1321-427f-aa17-267ca6975798/.default"]


def test_a_certificate_the_app_registration_does_not_hold_is_named(monkeypatch):
    from cremore_azure_provider import app_certificate

    envelope, _shown = app_certificate.make(TENANT, TENANT)

    def handler(request):
        return httpx.Response(401, json={"error": "invalid_client", "error_codes": [700027]})

    connection = {"provider": "azure", "edition": "cloud", "auth_method": "certificate", "target": {"tenant": TENANT},
                  "purposes": ["identity"], "name": "azure"}
    with pytest.raises(ValueError) as refused:
        catalog.module("azure").check(connection, "identity", {"credential": envelope}, context(handler))
    assert refused.value.code == "AZURE_CERTIFICATE_NOT_REGISTERED"


def test_azure_devops_asks_graph_then_token_administration():
    def handler(request):
        if request.url.path.endswith("/_apis/graph/users"):
            return httpx.Response(200, json={"value": [{"descriptor": "aad.MDAwMDAw"}]})
        if "/tokenadmin/" in request.url.path:
            return httpx.Response(403)
        return httpx.Response(200, json={"value": []})

    target = {"organization": "acme", "project": "Payments"}
    status, _items, _ctx = run("azure_devops", "cloud", "token", "inventory", target, {"token": "p" * 52}, handler)
    assert status == {"graph_read": "GRANTED", "token_administration": "MISSING"}
    status, _items, ctx = run("azure_devops", "cloud", "token", "exposure", target, {"token": "p" * 52}, handler)
    assert status == {"code_read": "GRANTED"} and ctx.seen[0].headers["authorization"].startswith("Basic ")


def test_a_vault_token_is_asked_its_capabilities_on_each_mount():
    def handler(request):
        assert request.headers["X-Vault-Token"] == "hvs.synthetic-token"
        if request.url.path == "/v1/auth/token/lookup-self":
            return httpx.Response(200, json={"data": {}})
        paths = json.loads(request.content)["paths"]
        return httpx.Response(200, json={paths[0]: ["read", "list"], paths[1]: ["read"]})

    target = {"address": "https://vault.example.com", "namespace": "", "mounts": ["secret", "team"],
              "kv_version": "2", "prefixes": [""]}
    _status, items, _ctx = run("vault", "self_managed", "token", "vault", target, {"token": "hvs.synthetic-token"}, handler)
    by = {(item["permission"], item.get("subject")): item["status"] for item in items}
    assert by[("login", None)] == "GRANTED"
    # A LIST is decided on the prefix with its trailing slash, as Vault lists it.
    assert by[("kv_list", "secret/metadata/")] == "GRANTED" and by[("kv_list", "team/metadata/")] == "MISSING"


def test_a_vault_option_is_checked_on_what_it_reads():
    """Accessors need sudo and list, lease prefixes sudo and list on their prefix, earlier versions read on metadata;
    a root token reads but is named."""
    granted = {"auth/token/accessors": ["sudo", "list"], "auth/token/lookup-accessor": ["update"],
               "sys/leases/lookup/database/creds/app/": ["list"], "sys/leases/lookup": ["update"],
               "secret/metadata/team-a/*": ["read"], "secret/metadata/team-a/": ["list"], "secret/data/team-a/*": ["read"]}

    def handler(token_caps):
        def answer(request):
            if request.url.path == "/v1/auth/token/lookup-self":
                return httpx.Response(200, json={"data": {}})
            return httpx.Response(200, json={path: token_caps(path) for path in json.loads(request.content)["paths"]})
        return answer

    target = {"address": "https://vault.example.com", "namespace": "", "mounts": ["secret"], "kv_version": "2",
              "prefixes": ["team-a"]}
    plan = {"previous_versions": True, "token_accessors": True, "lease_prefixes": ["database/creds/app"]}
    connection = {"provider": "vault", "edition": "self_managed", "auth_method": "token", "target": target,
                  "purposes": ["vault"], "name": "vault", "checks": {"requested_plans": {"vault": plan}}}
    module = catalog.module("vault")
    items = clean(module.check(connection, "vault", {"credential": {"token": "hvs.synthetic-token"}},
                               context(handler(lambda path: granted.get(path, [])))),
                  catalog.permissions_for("vault", "vault", "token", target))
    by = {(item["permission"], item.get("subject")): item["status"] for item in items}
    assert by[("token_accessors", "auth/token/accessors")] == "GRANTED"
    assert by[("leases", "sys/leases/lookup/database/creds/app/")] == "MISSING"  # list without sudo
    assert by[("kv_history", "secret/metadata/team-a/*")] == "GRANTED"
    assert by[("mounts_read", "sys/mounts")] == "MISSING"
    assert {s for (p, s) in by if p in ("token_accessors", "leases", "kv_history")} == set(
        module.permission_subjects(connection, "vault", "token_accessors", plan)
        + module.permission_subjects(connection, "vault", "leases", plan)
        + module.permission_subjects(connection, "vault", "kv_history", plan))
    rooted = clean(module.check(connection, "vault", {"credential": {"token": "hvs.synthetic-token"}},
                                context(handler(lambda path: ["root"]))),
                   catalog.permissions_for("vault", "vault", "token", target))
    assert {item["status"] for item in rooted} == {"GRANTED"} and rooted[0]["detail"] == "ROOT_TOKEN_NOT_RECOMMENDED"


def test_okta_signs_in_with_the_service_app_and_reads_one_page():
    from urllib.parse import parse_qs

    def handler(request, apps_granted=True):
        if request.url.path == "/oauth2/v1/token":
            scope = parse_qs(request.content.decode())["scope"]
            if scope == ["okta.apps.read"] and not apps_granted:
                return httpx.Response(400, json={"error": "invalid_scope"})
            return httpx.Response(200, json={"access_token": "okta.access", "token_type": "Bearer", "expires_in": 3600})
        return httpx.Response(200, json=[])

    envelope = {"client_id": "0oa1synthetic", "private_key": PEM}
    status, _items, ctx = run("okta", "cloud", "private_key_jwt", "identity", {"organization": "acme.okta.com"},
                              envelope, handler)
    assert status == {"users_read": "GRANTED", "apps_read": "GRANTED"}
    # Each permission is asked for with its own token: users with okta.users.read, the app list with okta.apps.read.
    scopes = [parse_qs(r.content.decode())["scope"][0] for r in ctx.seen if r.url.path == "/oauth2/v1/token"]
    paths = [r.url.path for r in ctx.seen if r.url.path != "/oauth2/v1/token"]
    assert scopes == ["okta.users.read", "okta.apps.read"] and paths == ["/api/v1/users", "/api/v1/apps"]
    # One row each answers the check: never a page of apps with their settings and credentials blocks.
    assert [r.url.params["limit"] for r in ctx.seen if r.url.path != "/oauth2/v1/token"] == ["1", "1"]
    status, items, _ctx = run("okta", "cloud", "private_key_jwt", "identity", {"organization": "acme.okta.com"},
                              envelope, lambda request: handler(request, apps_granted=False))
    assert status == {"users_read": "GRANTED", "apps_read": "MISSING"} and items[1]["detail"] == "OKTA_TOKEN_REFUSED"
    refused = lambda request: httpx.Response(401, json={"error": "invalid_client"})
    status, items, _ctx = run("okta", "cloud", "private_key_jwt", "identity", {"organization": "acme.okta.com"},
                              envelope, refused)
    assert status == {"users_read": "MISSING", "apps_read": "MISSING"} and items[0]["detail"] == "OKTA_TOKEN_REFUSED"


def test_keycloak_reads_users_and_admin_events_only_when_asked():
    asked = []

    def handler(request, view_clients=False, realm_has=("account-console", "admin-cli"), clients_status=200):
        if request.url.path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "kc.access", "expires_in": 300, "token_type": "Bearer"})
        if request.url.path.endswith("/admin-events"):
            return httpx.Response(403)
        if request.url.path.endswith("/clients"):
            # Looked up by the realm's public clients' IDs alone: no client a secret could come with is listed.
            client_id = request.url.params["clientId"]
            asked.append(client_id)
            assert client_id in ("account-console", "admin-cli")
            if clients_status != 200:
                return httpx.Response(clients_status)
            seen = [{"id": "00000000-0000-4000-8000-000000000001", "clientId": client_id, "publicClient": True}]
            return httpx.Response(200, json=seen if view_clients and client_id in realm_has else [])  # query-clients: []
        return httpx.Response(200, json=[])

    target = {"address": "https://sso.example.com", "realm": "staff", "api_path": "", "admin_events": True}
    envelope = {"client_id": "cremore", "client_secret": "s" * 32}
    status, items, _ctx = run("keycloak", "self_managed", "oauth_client", "identity", target, envelope, handler)
    assert status == {"view_users": "GRANTED", "view_events": "MISSING", "view_clients": "MISSING"}
    assert items[2]["detail"] == "KEYCLOAK_VIEW_CLIENTS_REQUIRED"
    status, _items, _ctx = run("keycloak", "self_managed", "oauth_client", "identity", target, envelope,
                               lambda request: handler(request, view_clients=True))
    assert status["view_clients"] == "GRANTED"
    # A realm without the account console still answers by its admin CLI client.
    asked.clear()
    status, _items, _ctx = run("keycloak", "self_managed", "oauth_client", "identity", target, envelope,
                               lambda request: handler(request, view_clients=True, realm_has=("admin-cli",)))
    assert status["view_clients"] == "GRANTED" and asked == ["account-console", "admin-cli"]
    # The lookup refused outright is the role missing, said so.
    status, items, _ctx = run("keycloak", "self_managed", "oauth_client", "identity", target, envelope,
                              lambda request: handler(request, clients_status=403))
    assert status["view_clients"] == "MISSING" and items[2]["detail"] == "KEYCLOAK_ACCESS_DENIED"


@pytest.mark.parametrize("provider", ["external_vault"])
def test_a_customer_side_read_is_reported_where_it_happens(provider):
    status, items, _ctx = run(provider, "self_managed", "jsonl", "vault", {"product": "X", "prefixes": ["a"]}, None,
                              lambda request: httpx.Response(500))
    assert status == {"read_items": "NOT_REPORTED"} and items[0]["detail"] == "CUSTOMER_CLI_REPORTS_ON_UPLOAD"


def test_a_github_identity_token_answers_for_the_organization_and_for_the_enterprise():
    """A classic token's scopes say which identities it may read -- the organization's SAML SSO (read:org) or the
    enterprise's (read:enterprise) -- and GitHub says whether its user owns them, since only owners see identities.
    The console counts the one the plan chooses."""
    asked = []

    def handler(scopes, owners=None, status=200):
        def answer(request):
            if request.url.path == "/graphql":
                asked.append(json.loads(request.content)["variables"])
                return httpx.Response(status, json={"data": owners})
            assert request.url.path == "/user"
            return httpx.Response(200, json={"login": "owner"}, headers={} if scopes is None else {"X-OAuth-Scopes": scopes})
        return answer

    def check(handler, target=None):
        result = run("github", "enterprise_cloud", "token", "identity",
                     target or {"organization": "acme", "enterprise": "acme-ent"},
                     {"token": "ghp_" + "c" * 36}, handler)
        queries = {
            ("org",): "query($org: String!) { organization(login: $org) { viewerCanAdminister } }",
            ("enterprise",): "query($enterprise: String!) { enterprise(slug: $enterprise) { ownerInfo { __typename } } }",
            ("org", "enterprise"): "query($org: String!, $enterprise: String!) { "
                                  "organization(login: $org) { viewerCanAdminister } "
                                  "enterprise(slug: $enterprise) { ownerInfo { __typename } } }",
        }
        # Check outside the transport: _owns deliberately catches transport exceptions, including fake assertions.
        for request in result[2].seen:
            if request.url.path == "/graphql":
                body = json.loads(request.content)
                assert " ".join(body["query"].split()) == queries[tuple(body["variables"])]
        return result

    owner = {"organization": {"viewerCanAdminister": True}, "enterprise": {"ownerInfo": {"__typename": "EnterpriseOwnerInfo"}}}
    for scopes, expected in (("read:org, read:enterprise", {"admin_org": "GRANTED", "read_enterprise": "GRANTED"}),
                             ("admin:org, admin:enterprise", {"admin_org": "GRANTED", "read_enterprise": "GRANTED"}),
                             ("read:enterprise", {"admin_org": "MISSING", "read_enterprise": "GRANTED"}),
                             ("repo", {"admin_org": "MISSING", "read_enterprise": "MISSING"})):
        status, _items, _ctx = check(handler(scopes, owner))
        assert status == expected, scopes
    # Each is asked only of a token holding the scope that reads it, so a scope it lacks fails no other answer.
    both = {"org": "acme", "enterprise": "acme-ent"}
    assert asked == [both, both, {"enterprise": "acme-ent"}]
    # Not an owner, or hidden from the token (not a member, or not authorized for SAML SSO): named.
    _status, items, _ctx = check(handler("read:org, read:enterprise", {"organization": {"viewerCanAdminister": False},
                                                                       "enterprise": None}))
    assert {item["permission"]: (item["status"], item.get("detail")) for item in items} == {
        "admin_org": ("MISSING", "NOT_AN_OWNER"), "read_enterprise": ("MISSING", "TARGET_NOT_VISIBLE")}
    # A billing manager sees the enterprise but not its owner information, so cannot read its identities.
    _status, items, _ctx = check(handler("read:org, read:enterprise", {"organization": {"viewerCanAdminister": True},
                                                                       "enterprise": {"ownerInfo": None}}))
    assert {item["permission"]: (item["status"], item.get("detail")) for item in items} == {
        "admin_org": ("GRANTED", None), "read_enterprise": ("MISSING", "NOT_AN_OWNER")}
    # A scope does not establish ownership when GitHub cannot answer. With no
    # enterprise named, enterprise ownership has not been checked either.
    status, _items, _ctx = check(handler("read:org, read:enterprise", {
        "organization": {"viewerCanAdminister": False}, "enterprise": {"ownerInfo": None}}, status=502))
    assert status == {"admin_org": "NOT_REPORTED", "read_enterprise": "NOT_REPORTED"}
    status, _items, _ctx = check(handler("read:org, read:enterprise", {"organization": {"viewerCanAdminister": True}}),
                                 {"organization": "acme"})
    assert status == {"admin_org": "GRANTED", "read_enterprise": "NOT_REPORTED"}
    assert asked[-1] == {"org": "acme"}
    status, items, _ctx = check(handler(None))
    assert status == {"admin_org": "MISSING", "read_enterprise": "MISSING"}  # a fine-grained token reads neither
    assert {item["detail"] for item in items} == {"CLASSIC_TOKEN_REQUIRED"}
    status, items, _ctx = check(lambda request: httpx.Response(401))
    assert {item["detail"] for item in items} == {"GITHUB_TOKEN_REJECTED"} and set(status.values()) == {"MISSING"}


@pytest.mark.parametrize("fault", ["transport", "invalid_json", "oversized", "invalid_data"])
def test_github_owner_check_failure_cannot_grant_ownership(fault, caplog, capsys):
    marker = "synthetic-private-owner-response"
    replies = []

    def handler(request):
        if request.url.path == "/user":
            return httpx.Response(200, json={"login": "owner"}, headers={"X-OAuth-Scopes": "read:org, read:enterprise"})
        if fault == "transport":
            raise httpx.ReadError(marker, request=request)
        if fault == "invalid_json":
            response = httpx.Response(200, content=marker)
        elif fault == "oversized":
            response = httpx.Response(200, json={"data": {
                "organization": {"viewerCanAdminister": False}, "enterprise": {"ownerInfo": None}},
                "private": marker + "x" * (1 << 20)})
            del response.headers["content-length"]  # Bound the streamed body even when its length is not advertised.
        else:
            response = httpx.Response(200, json={"data": [marker]})
        replies.append(response)
        return response

    status, items, ctx = run("github", "enterprise_cloud", "token", "identity",
                             {"organization": "acme", "enterprise": "acme-ent"}, {"token": "ghp_" + "c" * 36}, handler)
    assert [request.url.path for request in ctx.seen] == ["/user", "/graphql"]
    assert status == {"admin_org": "NOT_REPORTED", "read_enterprise": "NOT_REPORTED"}
    assert {item["detail"] for item in items} == {"TARGET_OWNER_NOT_CHECKED"}
    assert all(response.is_closed for response in replies)
    captured = capsys.readouterr()
    assert marker not in json.dumps(items) + caplog.text + captured.out + captured.err


def test_a_github_app_answers_for_the_organization_s_saml_identities_and_never_the_enterprise_s():
    """GitHub shows an organization's SAML identities to an App installation with Members (read); the check asks for
    their count alone. An enterprise's are shown to its owners' classic tokens only: the App answers that as missing."""
    import base64

    envelope = {"GITHUB_APP_ID": "12345", "GITHUB_APP_INSTALLATION_ID": "678",
                "GITHUB_APP_PRIVATE_KEY_BASE64": base64.b64encode(PEM.encode()).decode()}

    def handler(held, answer):
        def respond(request):
            if request.url.path in ("/app/installations/678", "/orgs/acme/installation"):
                return httpx.Response(200, json={"id": 678, "app_id": 12345, "account": {"login": "acme"},
                                                 "target_type": "Organization",
                                                 "permissions": dict.fromkeys(held, "read")})
            if request.url.path == "/app/installations/678/access_tokens":
                minted.append(json.loads(request.content)["permissions"])
                return httpx.Response(201, json={"token": f"ghs_{len(minted):036d}", "expires_at": "2099-01-01T00:00:00Z",
                                                 "permissions": minted[-1]})
            assert request.url.path == "/graphql"
            body = json.loads(request.content)
            asked.append((" ".join(body["query"].split()), body["variables"]))
            bearers.append(request.headers["Authorization"])
            return answer if isinstance(answer, httpx.Response) else httpx.Response(200, json=answer)
        return respond

    def check(answer=None, held=("members",)):
        _status, items, ctx = run("github", "enterprise_cloud", "github_app", "identity",
                                  {"organization": "acme", "enterprise": "acme-ent"}, envelope, handler(held, answer))
        return {item["permission"]: (item["status"], item.get("detail")) for item in items}, ctx

    def provider(found):
        return {"data": {"organization": {"samlIdentityProvider": found}}}

    asked, minted, bearers = [], [], []
    answers, _ctx = check(provider({"externalIdentities": {"totalCount": 3}}), held=("members", "contents"))
    assert answers == {"installation": ("GRANTED", None), "members": ("GRANTED", None),
                       "read_enterprise": ("MISSING", "CLASSIC_TOKEN_REQUIRED")}
    assert asked == [(("query($org: String!) { organization(login: $org) { samlIdentityProvider { "
                       "externalIdentities(first: 1) { totalCount } } } }"), {"org": "acme"})]
    # The check's own read-only token holds what the installation holds; GitHub is asked with the token the people
    # directory reads with, Members (read) alone.
    assert minted == [{"members": "read", "contents": "read"}, {"members": "read"}]
    assert bearers == ["Bearer ghs_" + "2".zfill(36)]
    # No SAML SSO of the organization's own (managed users, or SAML set on the enterprise): an owner's token reads those.
    assert check(provider(None))[0]["members"] == ("MISSING", "GITHUB_IDENTITY_SAML_NOT_ENABLED")
    assert check({"data": {"organization": None}, "errors": [{"type": "FORBIDDEN"}]})[0]["members"] == (
        "MISSING", "ACCESS_DENIED")
    assert check(httpx.Response(502))[0]["members"] == ("NOT_REPORTED", "HTTP_502")
    assert check({"data": []})[0]["members"] == ("NOT_REPORTED", "REQUEST_FAILED")
    # Members not held: missing, and GitHub is not asked.
    answers, ctx = check(held=("metadata",))
    assert answers["members"] == ("MISSING", None) and "/graphql" not in [r.url.path for r in ctx.seen]
