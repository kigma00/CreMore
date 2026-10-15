"""Organization-bound PAT identity and permission-aware project discovery."""

import json
from types import SimpleNamespace

import httpx
import pytest

from cremore.onboarding import sessions
from cremore.onboarding.discovery_test import finish, run
from cremore.onboarding.sessions_test import KEY, SETTINGS, body
from cremore.onboarding.sessions_test import repo as repo  # noqa: PLC0414
from cremore_azure_provider import onboarding

USER = "11111111-2222-4333-8444-555555555555"


@pytest.mark.parametrize("field", ["organization", "project"])
@pytest.mark.parametrize("value", [".", "..", " spaced ", "name/elsewhere"])
def test_server_target_names_stay_within_one_path_segment(field, value):
    with pytest.raises(onboarding.OnboardingValueError):
        onboarding.target("azure_devops", "server", {"base_url": "https://devops.example.test/tfs",
            "organization": "Collection", "project": "Project", field: value})


@pytest.mark.parametrize("edition", ["cloud", "server"])
def test_pat_authentication_precedes_project_selection(repo, edition):
    calls = []
    bootstrap = {"organization": "synthetic-team", **({"base_url": "https://devops.example.test/tfs"} if edition == "server" else {})}

    def handler(request):
        calls.append(request.url.path)
        assert request.headers["authorization"].startswith("Basic ")
        if request.url.path.endswith("/_apis/connectionData"):
            return httpx.Response(200, json={"authenticatedUser": {"id": USER}})
        assert request.url.path.endswith("/_apis/projects")
        assert request.url.params["api-version"] == ("5.0" if edition == "server" else "7.1")
        more = request.url.params.get("continuationToken") == "1"
        return httpx.Response(200, json={"value": [{"name": "Second" if more else "First"}]},
                              headers={} if more else {"x-ms-continuationtoken": "1"})

    view = run(repo, sessions.create(repo, SETTINGS, {"browser_key": KEY, "provider": "azure_devops", "edition": edition,
        "auth_method": "server_token" if edition == "server" else "token", "context": bootstrap,
        "credential": {"token": "synthetic-devops-pat-never-real"}}, "admin"), handler)
    assert view["state"] == "AUTHENTICATED" and len(calls) == 1, view
    purposes = ["exposure"] if edition == "server" else ["exposure", "inventory"]
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=purposes), "admin"), handler)
    assert view["state"] == "LISTED" and view["has_more"], view
    view = run(repo, sessions.discover(repo, view["id"], body(view, more=True), "admin"), handler)
    assert view["state"] == "LISTED" and not view["has_more"], view
    project_roots = [r for r in view["roots"] if "project" in r["target"]]
    assert {r["target"]["project"] for r in project_roots} == {"First", "Second"}
    assert all(r["purposes"] == ["exposure"] for r in project_roots)
    if edition == "cloud":
        org_roots = [r for r in view["roots"] if "project" not in r["target"]]
        assert len(org_roots) == 1 and org_roots[0]["purposes"] == ["inventory"]
    assert "synthetic-devops-pat" not in json.dumps(view)


@pytest.mark.parametrize("purpose", ["inventory", "remediation"])
def test_inventory_pat_does_not_require_project_list_permission(purpose):
    connection = {"provider": "azure_devops", "edition": "cloud", "auth_method": "token",
                  "purposes": [purpose], "target": {"organization": "synthetic-team"}}
    context = SimpleNamespace(http_client=lambda: pytest.fail("inventory does not enumerate code projects"))
    roots, complete = onboarding.discover(connection, {"credential": {"token": "synthetic-token"}}, context)
    assert complete == "COMPLETE" and roots[0]["purposes"] == [purpose]
    child = onboarding.children(connection, "inventory", {})[0]
    assert child["spec"]["scopes"] == [{"kind": "organization", "id": "synthetic-team"}]
    with pytest.raises(onboarding.OnboardingValueError, match="AZURE_DEVOPS_PROJECT_REQUIRED"):
        onboarding.children(connection, "exposure", {})


def test_inventory_without_project_activates_with_only_inventory_permissions(repo):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if request.url.path.endswith("/_apis/connectionData"):
            return httpx.Response(200, json={"authenticatedUser": {"id": USER}})
        if request.url.path.endswith("/_apis/graph/users"):
            return httpx.Response(200, json={"value": [{"descriptor": "synthetic-user"}]})
        assert request.url.path.endswith("/_apis/tokenadmin/personalaccesstokens/synthetic-user")
        return httpx.Response(200, json={"value": []})

    view = run(repo, sessions.create(repo, SETTINGS, {"browser_key": KEY, "provider": "azure_devops", "edition": "cloud",
        "auth_method": "token", "context": {"organization": "synthetic-team"},
        "credential": {"token": "synthetic-devops-pat-never-real"}}, "admin"), handler)
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=["inventory"]), "admin"), handler)
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[view["roots"][0]["id"]],
        plans={"inventory": {}}), "admin"), handler)
    assert view["state"] == "CHECKED" and not view["blockers"], view
    result = finish(repo, view)
    assert result["status"] == "ACTIVE" and len(result["children"]) == 1
    assert not any("projects" in path or "repositories" in path for path in calls)


@pytest.mark.parametrize("user", [None, {}, {"id": "00000000-0000-0000-0000-000000000000"},
                                  {"id": USER, "isAnonymous": True}])
def test_anonymous_connection_data_never_authenticates(user):
    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json={"authenticatedUser": user}))))
    result = onboarding.authenticate({"provider": "azure_devops", "edition": "cloud", "target": {"organization": "synthetic-team"}},
                                     {"credential": {"token": "synthetic-token"}}, context)
    assert result["status"] == "MISSING"


@pytest.mark.parametrize("status", [203, 401, 403])
def test_authentication_refusal_is_not_success(status):
    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(status))))
    with pytest.raises(onboarding.OnboardingValueError, match=f"HTTP_{status}"):
        onboarding.authenticate({"provider": "azure_devops", "edition": "cloud", "target": {"organization": "synthetic-team"}},
                                {"credential": {"token": "synthetic-token"}}, context)


@pytest.mark.parametrize("continuation", ["invalid", "0", "-1", "1"])
def test_project_pagination_requires_forward_progress(continuation):
    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json={"value": []}, headers={"x-ms-continuationtoken": continuation}))))
    with pytest.raises(onboarding.OnboardingValueError, match="PAGINATION_INVALID"):
        onboarding.discover({"provider": "azure_devops", "edition": "cloud", "target": {"organization": "synthetic-team"},
                             "purposes": ["exposure"], "discovery_cursor": "1"},
                            {"credential": {"token": "synthetic-token"}}, context)
