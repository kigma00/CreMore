"""Server credentials authenticate before resource lists; no user-token assumptions."""

import json
from types import SimpleNamespace

import httpx
import pytest

from cremore.onboarding import sessions
from cremore.onboarding.discovery_test import finish, run
from cremore.onboarding.sessions_test import KEY, SETTINGS, body
from cremore.onboarding.sessions_test import repo as repo  # noqa: PLC0414
from cremore_atlassian_provider import cloud_api, onboarding


def test_confluence_oauth_authenticates_then_lists_gateway_spaces(repo, monkeypatch):
    for name in ("_TOKENS", "_FAILED", "_CLOUD_IDS"):
        monkeypatch.setattr(cloud_api, name, {})
    calls = []
    site_id = "11111111-2222-4333-8444-555555555555"
    credential = {"client_id": "synthetic-client", "client_secret": "synthetic-secret-never-real"}

    def handler(request):
        calls.append((request.method, request.url.host, request.url.path))
        if request.url.host == "auth.atlassian.com":
            assert request.method == "POST" and request.url.path == "/oauth/token"
            return httpx.Response(200, json={"access_token": "synthetic-access-never-real", "token_type": "Bearer", "expires_in": 3600})
        if request.url.host == "synthetic.example.test":
            assert "authorization" not in request.headers and request.url.path == "/_edge/tenant_info"
            return httpx.Response(200, json={"cloudId": site_id})
        assert request.url.host == "api.atlassian.com", "OAuth tokens never go to the site origin"
        assert request.headers["authorization"] == "Bearer synthetic-access-never-real"
        base = f"/ex/confluence/{site_id}/wiki"
        if request.url.path == base + "/api/v2/spaces/1":
            return httpx.Response(200, json={"id": "1"})
        if request.url.path == base + "/api/v2/spaces/1/pages":
            assert "body-format" not in request.url.params
            return httpx.Response(200, json={"results": [{"id": "10"}]})
        if request.url.path in {base + "/api/v2/pages/10/attachments", base + "/rest/api/content/search"}:
            return httpx.Response(200, json={"results": []})
        assert request.url.path == base + "/api/v2/spaces"
        more = request.url.params.get("cursor") == "next-page"
        return httpx.Response(200, json={"results": [{"id": "2" if more else "1", "name": "Synthetic space"}],
            "_links": {} if more else {"next": "/wiki/api/v2/spaces?cursor=next-page"}})

    view = run(repo, sessions.create(repo, SETTINGS, {"browser_key": KEY, "provider": "confluence",
        "edition": "cloud", "auth_method": "service_account", "context": {"base_url": "https://synthetic.example.test/wiki"},
        "credential": credential}, "admin"), handler)
    assert view["state"] == "AUTHENTICATED", view
    assert calls == [("POST", "auth.atlassian.com", "/oauth/token")]
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=["exposure"]), "admin"), handler)
    assert view["state"] == "LISTED" and view["has_more"], view
    view = run(repo, sessions.discover(repo, view["id"], body(view, more=True), "admin"), handler)
    assert view["state"] == "LISTED" and not view["has_more"] and len(view["roots"]) == 2, view
    assert all(r["target"]["base_url"] == "https://synthetic.example.test/wiki" for r in view["roots"])
    assert "synthetic-secret" not in json.dumps(view) and "synthetic-access" not in json.dumps(view)
    first = next(r["id"] for r in view["roots"] if r["target"]["space"] == "1")
    view = run(repo, sessions.inspect(repo, view["id"], body(view, target_ids=[first], plans={"exposure": {}}), "admin"), handler)
    assert view["state"] == "CHECKED" and len(view["resources"]) == 1 and not view["blockers"], view
    result = finish(repo, view)
    assert result["status"] == "ACTIVE" and len(result["children"]) == 1


@pytest.mark.parametrize("method,edition,context", [
    ("access_token", "cloud", {"workspace": "synthetic-team"}),
    ("http_token", "data_center", {"base_url": "https://bitbucket.example.test"}),
])
def test_bitbucket_nonuser_and_service_tokens_list_only_their_visible_roots(repo, method, edition, context):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        assert request.headers["authorization"] == "Bearer synthetic-bitbucket-token"
        assert request.url.path not in {"/2.0/user", "/rest/api/latest/application-properties"}
        if method == "access_token":
            assert request.url.path == "/2.0/workspaces/synthetic-team/permissions"
            assert request.url.params["pagelen"] == "1"
            return httpx.Response(200, json={"values": []})
        if request.url.path == "/rest/api/latest/profile/recent/repos":
            return httpx.Response(200, json={"values": []})
        assert request.url.path == "/rest/api/latest/projects"
        more = request.url.params["start"] == "1"
        return httpx.Response(200, json={"values": [{"key": "TWO" if more else "ONE", "name": "Synthetic"}],
                                        "isLastPage": more, **({} if more else {"nextPageStart": 1})})

    view = run(repo, sessions.create(repo, SETTINGS, {"browser_key": KEY, "provider": "bitbucket", "edition": edition,
        "auth_method": method, "context": context, "credential": {"token": "synthetic-bitbucket-token"}}, "admin"), handler)
    assert view["state"] == "AUTHENTICATED" and len(calls) == 1, view
    view = run(repo, sessions.discover(repo, view["id"], body(view, purposes=["exposure"]), "admin"), handler)
    assert view["state"] == "LISTED", view
    if edition == "data_center":
        assert view["has_more"]
        view = run(repo, sessions.discover(repo, view["id"], body(view, more=True), "admin"), handler)
        assert not view["has_more"] and {r["target"]["project"] for r in view["roots"]} == {"ONE", "TWO"}
    else:
        assert [r["target"] for r in view["roots"]] == [{"workspace": "synthetic-team"}]
        assert len(calls) == 1, "a workspace token cannot enumerate other workspaces"
    assert "synthetic-bitbucket-token" not in json.dumps(view)


def test_bitbucket_api_token_lists_the_callers_workspaces_without_the_removed_cross_workspace_api():
    """GET /2.0/workspaces left with the cross-workspace APIs on 2026-04-14 (CHANGE-2770); /2.0/user/workspaces lists
    the caller's (CHANGE-3022). A row is the workspace, or a membership naming it."""
    def handler(request):
        assert request.url.path == "/2.0/user/workspaces" and request.headers["authorization"].startswith("Basic ")
        more = request.url.params.get("page") == "2"
        rows = [{"slug": "two", "name": "Two"}] if more else [{"workspace": {"slug": "one", "name": "One"}, "permission": "member"}]
        return httpx.Response(200, json={"values": rows, **({} if more else {"next": "https://api.bitbucket.org/2.0/user/workspaces?page=2"})})

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    connection = {"provider": "bitbucket", "auth_method": "api_token", "edition": "cloud", "target": {}}
    secrets = {"credential": {"token": "synthetic-token", "username": "dev@example.test"}}
    roots, state, following = onboarding.discover(connection, secrets, context)
    assert ([r["target"] for r in roots], state, following) == ([{"workspace": "one"}], "PARTIAL", "2")
    roots, state, following = onboarding.discover({**connection, "discovery_cursor": "2"}, secrets, context)
    assert ([r["target"] for r in roots], state, following) == ([{"workspace": "two"}], "COMPLETE", None)


@pytest.mark.parametrize("method,target", [("access_token", {"workspace": "synthetic-team"}),
                                         ("http_token", {"base_url": "https://bitbucket.example.test"})])
def test_refused_bitbucket_authentication_never_uses_public_fallback(method, target):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(403, json={"message": "private-response"})

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(onboarding.OnboardingValueError, match="HTTP_403"):
        onboarding.authenticate({"provider": "bitbucket", "auth_method": method, "target": target,
                                 "edition": "cloud" if method == "access_token" else "data_center"},
                                {"credential": {"token": "synthetic-token"}}, context)
    assert len(calls) == 1


@pytest.mark.parametrize("body", [{"values": [], "isLastPage": False},
                                  {"values": [], "isLastPage": False, "nextPageStart": 0},
                                  {"values": [], "isLastPage": "true"}])
def test_data_center_pagination_cannot_silently_complete(body):
    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body))))
    with pytest.raises(onboarding.OnboardingValueError, match="PAGINATION_INVALID"):
        onboarding.discover({"provider": "bitbucket", "auth_method": "http_token", "edition": "data_center",
                             "target": {"base_url": "https://bitbucket.example.test"}},
                            {"credential": {"token": "synthetic-token"}}, context)
