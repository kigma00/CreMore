"""The remediation purpose: its own connection, a check that changes nothing, no collection (P1)."""

from __future__ import annotations

import httpx
import pytest

from cremore.db.repository import InMemoryRepository
from cremore.onboarding import service
from cremore.onboarding.onboarding_test import SETTINGS, run_check
from cremore.onboarding.store import ProviderConnectionStore

GITLAB_TOKEN = "glpat-" + "Synthetic0Onboarding2"  # built from parts: never a real token


def gitlab(**extra):
    return {"provider": "gitlab", "edition": "cloud", "purposes": ["remediation"], "auth_method": "token",
            "target": {"scope": "group", "id": "10"}, "credential": {"token": GITLAB_TOKEN}, **extra}


def test_the_credential_that_acts_is_its_own_connection():
    with pytest.raises(service.OnboardingError) as mixed:
        service.create(InMemoryRepository(), SETTINGS, gitlab(purposes=["inventory", "remediation"]), "admin")
    assert mixed.value.code == "REMEDIATION_NEEDS_ITS_OWN_CONNECTION"
    # An administrator's instance connection may act, as it may read the instance's inventory.
    instance = gitlab(edition="self_managed", target={"scope": "instance", "host": "https://gitlab.example.test"})
    assert service.create(InMemoryRepository(), SETTINGS, instance, "admin")["status"] == "DRAFT"
    with pytest.raises(service.OnboardingError) as scanning:
        service.create(InMemoryRepository(), SETTINGS, {**instance, "purposes": ["exposure"]}, "admin")
    assert scanning.value.code == "GITLAB_INSTANCE_SCOPE_IS_INVENTORY_ONLY"


@pytest.mark.parametrize(("level", "status"), [(50, "PASSED"), (40, "MISSING")])
def test_gitlab_reads_the_role_that_revokes_and_revokes_nothing(level, status):
    repo = InMemoryRepository()
    made = service.create(repo, SETTINGS, gitlab(), "admin")
    service.request_check(repo, made["id"], "admin")
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path))
        if request.url.path == "/api/v4/personal_access_tokens/self":
            return httpx.Response(200, json={"id": 9, "scopes": ["api"], "user_id": 77, "active": True})
        if request.url.path == "/api/v4/groups/10/members/all/77":
            return httpx.Response(200, json={"id": 77, "access_level": level})
        return httpx.Response(404)

    checked = run_check(repo, made, lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    result = checked["checks"]["results"]["remediation"]
    assert result["status"] == status
    rows = {row["permission"]: row for row in result["items"]}
    assert rows["api"]["status"] == "GRANTED" and rows["self_rotate"]["status"] == "GRANTED"
    assert rows["owner"]["status"] == ("GRANTED" if level == 50 else "MISSING")
    assert {method for method, _path in seen} == {"GET"}
    if status == "PASSED":
        # Step 4 creates nothing: an approved plan alone uses the connection.
        active = service.activate(repo, SETTINGS, made["id"], {"purposes": {"remediation": {}}}, "admin")
        assert active["created"] == [] and active["status"] == "ACTIVE"
        assert ProviderConnectionStore(repo).children(made["id"]) == []


def test_gcp_asks_the_project_whether_the_identity_may_disable_and_delete_keys(monkeypatch):
    monkeypatch.setattr("cremore_gcp_provider.onboarding._token", lambda connection, secrets, client_factory=None: "gcp-synthetic-access")
    repo = InMemoryRepository()
    made = service.create(repo, SETTINGS, {"provider": "gcp", "edition": "cloud", "purposes": ["remediation"],
                                           "auth_method": "adc", "target": {"scope": "project",
                                                                            "project": "acme-prod-1"},
                                           "credential": {}}, "admin")
    service.request_check(repo, made["id"], "admin")
    asked = []

    def handler(request):
        asked.append((request.method, request.url.host, request.url.path, request.content))
        if request.url.host == "oauth2.googleapis.com":  # who the sign-in is: never in the URL
            return httpx.Response(200, json={"email": "admin@acme.test", "email_verified": "true"})
        return httpx.Response(200, json={"permissions": ["iam.serviceAccounts.get", "iam.serviceAccountKeys.get",
                                                         "iam.serviceAccountKeys.disable"]})

    checked = run_check(repo, made, lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    items = checked["checks"]["results"]["remediation"]["items"]
    rows = {row["permission"]: row["status"] for row in items}
    assert rows == {"iam.serviceAccounts.get": "GRANTED", "iam.serviceAccountKeys.get": "GRANTED",
                    "iam.serviceAccountKeys.disable": "GRANTED", "iam.serviceAccountKeys.delete": "MISSING"}
    assert [row.get("subject") for row in items if row.get("subject")] == ["google:admin@acme.test"]
    assert [(method, host, path) for method, host, path, _content in asked] == [
        ("POST", "cloudresourcemanager.googleapis.com", "/v1/projects/acme-prod-1:testIamPermissions"),
        ("POST", "oauth2.googleapis.com", "/tokeninfo")]
    assert b"access_token=gcp-synthetic-access" in asked[1][3]
    with pytest.raises(service.OnboardingError, match="REQUIRED_PERMISSIONS_NOT_GRANTED"):
        service.activate(repo, SETTINGS, made["id"], {"purposes": {"remediation": {}}}, "admin")
    assert service.get(repo, made["id"])["plans"] == {}


def test_notion_reads_the_workspace_tokens_and_leaves_the_revoke_scope_to_the_first_run():
    workspace = "00000000-0000-4000-8000-000000000001"
    repo = InMemoryRepository()
    made = service.create(repo, SETTINGS, {"provider": "notion", "edition": "enterprise", "purposes": ["remediation"],
                                           "auth_method": "organization_bot", "target": {"workspace": workspace},
                                           "credential": {"token": "adm_" + "SyntheticOnboardingBot0"}}, "admin")
    service.request_check(repo, made["id"], "admin")
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path))
        return httpx.Response(200, json={"results": [], "has_more": False, "next_cursor": None})

    checked = run_check(repo, made, lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    rows = {row["permission"]: row for row in checked["checks"]["results"]["remediation"]["items"]}
    assert rows["workspace_tokens"]["status"] == "GRANTED"
    # Notion says whether the bot may revoke only by revoking something: nothing is revoked to find out.
    assert (rows["revoke_tokens"]["status"], rows["revoke_tokens"]["detail"]) == ("NOT_REPORTED", "CONFIRMED_WHEN_RUN")
    assert seen == [("GET", f"/admin/v1/spaces/{workspace}/personal_access_tokens")]
    active = service.activate(repo, SETTINGS, made["id"], {"purposes": {"remediation": {}}}, "admin")
    assert active["created"] == [] and active["status"] == "ACTIVE"


@pytest.mark.parametrize(("level", "status"), [("write", "GRANTED"), ("read", "MISSING")])
def test_github_reads_the_apps_write_permission_from_its_installation(level, status):
    from cremore.onboarding.onboarding_test import ORG, github_app, github_server

    repo = InMemoryRepository()
    made = service.create(repo, SETTINGS, github_app(purposes=["remediation"]), "admin")
    service.request_check(repo, made["id"], "admin")
    asked = []
    checked = run_check(repo, made, github_server({"organization_personal_access_tokens": level}, asked=asked))
    rows = {row["permission"]: row for row in checked["checks"]["results"]["remediation"]["items"]}
    # The organization it is installed on is the account a plan binds (cremore.remediation.provider_actions).
    assert rows["installation"] == {"permission": "installation", "status": "GRANTED", "subject": ORG}
    assert rows["organization_personal_access_tokens_write"]["status"] == status
    # The check reads the level from the installation; the only token it mints reads.
    assert asked == [{"organization_personal_access_tokens": "read"}]
    if status == "GRANTED":
        assert service.activate(repo, SETTINGS, made["id"], {"purposes": {"remediation": {}}}, "admin")["created"] == []
    else:
        with pytest.raises(service.OnboardingError, match="REQUIRED_PERMISSIONS_NOT_GRANTED"):
            service.activate(repo, SETTINGS, made["id"], {"purposes": {"remediation": {}}}, "admin")


def test_a_github_app_installed_on_another_account_names_no_account_to_act_as():
    from cremore.onboarding.onboarding_test import github_app, github_server

    repo = InMemoryRepository()
    made = service.create(repo, SETTINGS, github_app(purposes=["remediation"]), "admin")
    service.request_check(repo, made["id"], "admin")
    checked = run_check(repo, made, github_server({"organization_personal_access_tokens": "write"}, account="other-org"))
    rows = {row["permission"]: row for row in checked["checks"]["results"]["remediation"]["items"]}
    # A plan binds the account the check names: a failed installation names none, so none can be planned.
    assert rows["installation"] == {"permission": "installation", "status": "MISSING",
                                    "detail": "INSTALLED_ON_ANOTHER_ACCOUNT"}


def test_azure_devops_lists_one_users_tokens_with_the_scope_that_also_revokes():
    repo = InMemoryRepository()
    made = service.create(repo, SETTINGS, {"provider": "azure_devops", "edition": "cloud", "purposes": ["remediation"],
                                           "auth_method": "token", "target": {"organization": "acme", "project": "web"},
                                           "credential": {"token": "Synthetic" + "DevOpsRemediation0" * 2}}, "admin")
    service.request_check(repo, made["id"], "admin")
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path))
        if request.url.path == "/acme/_apis/graph/users":
            return httpx.Response(200, json={"value": [{"descriptor": "aad.U3ludGhldGlj"}]})
        return httpx.Response(200, json={"value": [], "continuationToken": None})

    checked = run_check(repo, made, lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    rows = {row["permission"]: row["status"] for row in checked["checks"]["results"]["remediation"]["items"]}
    assert rows == {"graph_read": "GRANTED", "token_administration": "GRANTED"}
    assert seen == [("GET", "/acme/_apis/graph/users"),
                    ("GET", "/acme/_apis/tokenadmin/personalaccesstokens/aad.U3ludGhldGlj")]
    assert service.activate(repo, SETTINGS, made["id"], {"purposes": {"remediation": {}}}, "admin")["created"] == []
