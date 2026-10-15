"""Only direct provider grants/restrictions are reported; synthetic hosts never prove effective readers."""

import httpx
import pytest

from cremore_atlassian_provider import bitbucket_source, confluence_source

from .test_bitbucket_context import CLOUD as BITBUCKET
from .test_bitbucket_context import COMMIT
from .test_confluence_context import CLOUD as CONFLUENCE


def test_confluence_lists_direct_user_and_group_restrictions_after_page_scope_validation():
    calls = []
    def handler(request):
        calls.append(request)
        if request.url.path.endswith("/pages/123"):
            return httpx.Response(200, json={"id": "123", "spaceId": "98765", "version": {}})
        assert request.url.path == "/wiki/rest/api/content/123/restriction/byOperation/read"
        return httpx.Response(200, json={"operation": "read", "restrictions": {
            "user": {"results": [{"accountId": "account-1", "displayName": "Person"}]},
            "group": {"results": [{"id": "group-1", "name": "Team"}]}}})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        found = confluence_source.exposure_context(CONFLUENCE, {"repository": "123", "path": "body"}, http_client=client)
    access = found["members"]
    assert access["status"] == "OBSERVED" and not access["truncated"]
    assert [(p["principal_kind"], p["read_access"]) for p in access["people"]] == [("USER", "UNKNOWN"), ("GROUP", "UNKNOWN")]
    assert access["visibility"] == "UNKNOWN" and "SPACE_PERMISSIONS_NOT_EVALUATED" in access["limitations"]
    assert len(calls) == 2


@pytest.mark.parametrize("variant", ["denied", "partial", "malformed", "other_space"])
def test_confluence_permission_error_nested_pagination_and_wrong_space_remain_explicit(variant):
    calls = []
    def handler(request):
        calls.append(request)
        if request.url.path.endswith("/pages/123"):
            return httpx.Response(200, json={"id": "123", "spaceId": "other" if variant == "other_space" else "98765", "version": {}})
        if variant == "denied":
            return httpx.Response(403)
        return httpx.Response(200, json={"operation": "read", "restrictions": {
            "user": {"results": [{"accountId": "u1"}, None] if variant == "malformed" else [{"accountId": "u1"}],
                "_links": {"next": "https://other.invalid/page"} if variant == "partial" else {}},
            "group": {"results": []}}})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        access = confluence_source.exposure_context(CONFLUENCE, {"repository": "123", "path": "body"}, http_client=client)["members"]
    if variant == "other_space":
        assert access["status"] == "UNAVAILABLE" and len(calls) == 1
    elif variant == "denied":
        assert access["status"] == "FORBIDDEN" and "ACCESS_LIST_PERMISSION_REQUIRED" in access["limitations"]
    else:
        assert access["truncated"] and len(access["people"]) == 1
    assert all(request.url.host == "acme.atlassian.net" for request in calls)


@pytest.mark.parametrize("denied_second", [False, True])
def test_bitbucket_pins_paging_preserves_partial_and_distinguishes_groups(denied_second):
    calls = []
    def handler(request):
        calls.append(request)
        path = request.url.path
        if path == "/2.0/repositories/acme/app":
            return httpx.Response(200, json={"is_private": False})
        if path.endswith("/permissions-config/users"):
            if request.url.params["page"] == "2":
                return httpx.Response(403) if denied_second else httpx.Response(200, json={"values": []})
            return httpx.Response(200, json={"values": [{"user": {"uuid": "u1", "display_name": "User"}, "permission": "read"}],
                "next": "https://untrusted.invalid/?page=2"})
        if path.endswith("/permissions-config/groups"):
            return httpx.Response(200, json={"values": [{"group": {"slug": "team", "name": "Team"}, "permission": "admin"}]})
        return httpx.Response(200, json={"values": []})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        access = bitbucket_source.exposure_context(BITBUCKET, {"repository": "acme/app", "path": "a", "commit": COMMIT}, http_client=client)["members"]
    assert access["visibility"] == "PUBLIC" and "PUBLIC_ACCESS_NOT_ENUMERATED" in access["limitations"]
    assert [(p["principal_kind"], p["read_access"]) for p in access["people"]] == [("USER", "UNKNOWN"), ("GROUP", "UNKNOWN")]
    assert access["truncated"] is denied_second and access["status"] == ("FORBIDDEN" if denied_second else "OBSERVED")
    assert all(request.url.host == "api.bitbucket.org" for request in calls) and len(calls) == 5


def test_bitbucket_another_pinned_repository_is_not_read():
    with httpx.Client(transport=httpx.MockTransport(lambda _: pytest.fail("outside the pinned repository"))) as client:
        result = bitbucket_source.exposure_context({**BITBUCKET, "repo": "other"},
            {"repository": "acme/app", "path": "a", "commit": COMMIT}, http_client=client)
    assert result["author"]["status"] == "UNSUPPORTED"
