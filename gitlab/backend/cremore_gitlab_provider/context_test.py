"""Project membership and repository-read evidence remain distinct (fakes only)."""

import httpx
import pytest

from cremore.collectors.base import RequestBudget
from cremore_gitlab_provider import context
from cremore_gitlab_provider.content import SourceHTTP


def members(pages, *, visibility="private", repository_access="enabled"):
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path == "/api/v4/projects/42":
            return httpx.Response(403) if visibility is None else httpx.Response(200, json={
                "visibility": visibility, "repository_access_level": repository_access})
        assert request.url.path == "/api/v4/projects/42/members/all"
        value = pages[int(request.url.params["page"]) - 1]
        return value if isinstance(value, httpx.Response) else httpx.Response(200, json=value)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        http = SourceHTTP({"base_url": "https://gitlab.example.test", "token": "synthetic"}, client,
                          budget=RequestBudget(20))
        result = context._members(http, "42")
    assert all(call.method == "GET" and call.url.host == "gitlab.example.test" for call in calls)
    return result, calls


def row(login, level=30):
    return {"username": login, "name": login, "access_level": level, "state": "active"}


def test_guest_and_planner_membership_is_not_private_repository_read_permission():
    result, _ = members([[row("guest", 10), row("planner", 15), row("security", 25), row("reporter", 20), row("owner", 50)]])
    assert [(person["login"], person["read_access"]) for person in result["people"]] == [
        ("guest", "UNKNOWN"), ("planner", "UNKNOWN"), ("security", "UNKNOWN"),
        ("reporter", "REPORTED"), ("owner", "REPORTED")]
    assert result["evidence_kind"] == "PROVIDER_MEMBERSHIP"
    assert result["limitations"] == ["MEMBERSHIP_IS_NOT_REPOSITORY_READ"]


@pytest.mark.parametrize(("visibility", "limitation"), [
    ("public", "PUBLIC_ACCESS_NOT_ENUMERATED"), ("internal", "INTERNAL_ACCESS_NOT_ENUMERATED"),
    (None, "VISIBILITY_UNAVAILABLE"),
])
def test_nonmember_audience_is_not_presented_as_an_enumerated_member(visibility, limitation):
    result, calls = members([[row("alice")]], visibility=visibility)
    assert result["visibility"] == (visibility.upper() if visibility else "UNKNOWN")
    assert limitation in result["limitations"] and len(result["people"]) == 1 and len(calls) == 2
    if visibility is None:
        assert result["people"][0]["read_access"] == "UNKNOWN"


@pytest.mark.parametrize("repository_access", [None, "disabled"])
def test_project_membership_does_not_override_missing_or_disabled_repository_access(repository_access):
    result, _ = members([[row("alice")]], repository_access=repository_access)
    assert result["people"][0]["read_access"] == "UNKNOWN"
    assert "REPOSITORY_READ_NOT_CONFIRMED" in result["limitations"]


def test_failed_followup_preserves_people_and_the_failure_reason():
    result, _ = members([[row(f"user{i}") for i in range(100)], httpx.Response(403)])
    assert result["status"] == "FORBIDDEN" and result["truncated"] and len(result["people"]) == 100
    assert result["limitations"] == ["PAGED_LIST_NOT_ATOMIC", "MEMBER_PAGE_UNAVAILABLE"]


def test_malformed_rows_and_unknown_levels_do_not_prove_repository_access():
    result, _ = members([[None, row("bool", True), row("custom", 99), row("alice"), row("alice")]])
    assert result["truncated"] and "MALFORMED_MEMBER_ROWS" in result["limitations"]
    assert [(person["login"], person["read_access"]) for person in result["people"]] == [
        ("custom", "UNKNOWN"), ("alice", "REPORTED")]


def test_exact_page_limit_is_partial_even_when_the_api_repeats_the_same_people():
    page = [row(f"user{i}") for i in range(100)]
    result, calls = members([page] * context.MAX_MEMBER_PAGES)
    assert result["truncated"] and result["limitations"] == ["PAGED_LIST_NOT_ATOMIC", "MEMBER_PAGE_LIMIT"]
    assert len(result["people"]) == 100 and len(calls) == context.MAX_MEMBER_PAGES + 1
    assert result["next_page"] == 4


def test_resumed_read_uses_only_current_project_metadata_and_remaining_member_pages():
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path == "/api/v4/projects/42":
            return httpx.Response(200, json={"visibility": "private", "repository_access_level": "enabled"})
        assert request.url.path == "/api/v4/projects/42/members/all"
        page = int(request.url.params["page"])
        return httpx.Response(200, json=[row(f"user{i}") for i in range((page - 1) * 100, min(page * 100, 435))])

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = context.read({"base_url": "https://gitlab.example.test", "token": "synthetic"},
                              {"repository": "42", "path": "app.env"}, http_client=client, member_page=4)
    assert set(result) == {"members"}
    assert len(result["members"]["people"]) == 135 and not result["members"]["truncated"]
    assert not result["members"].get("next_page")
    assert [int(call.url.params["page"]) for call in calls if "page" in call.url.params] == [4, 5]


def test_member_page_cursor_is_bounded_before_any_request():
    calls = []

    class HTTP:
        def get(self, route, params=None):
            calls.append((route, params))
            if route.endswith("/members/all"):
                return [row(f"user{i}") for i in range(100)], {}
            return {"visibility": "private", "repository_access_level": "enabled"}, {}

    result = context._members(HTTP(), "42", start_page=100)
    assert [params["page"] for route, params in calls if route.endswith("/members/all")] == [100]
    assert result["truncated"] and result["next_page"] is None
    for invalid in (0, 101, True, "2"):
        before = len(calls)
        with pytest.raises(ValueError, match="INVALID_MEMBER_PAGE"):
            context._members(HTTP(), "42", start_page=invalid)
        assert len(calls) == before


def test_next_page_header_preserves_short_pages_and_explicit_end():
    result, calls = members([
        httpx.Response(200, json=[row("first")], headers={"x-next-page": "2"}),
        httpx.Response(200, json=[row(f"person{i}") for i in range(100)], headers={"x-next-page": ""}),
    ])
    assert len(calls) == 3 and len(result["people"]) == 101
    assert result["status"] == "OBSERVED" and not result["truncated"]
    assert "PAGED_LIST_NOT_ATOMIC" in result["limitations"]


@pytest.mark.parametrize("next_page", ["1", "3", "https://other.test/page", "100000000000000000000000"])
def test_invalid_page_headers_preserve_rows_without_following_provider_urls_or_skipping_pages(next_page):
    result, calls = members([httpx.Response(200, json=[row("first")], headers={"x-next-page": next_page})])
    assert len(calls) == 2 and len(result["people"]) == 1
    assert result["status"] == "UNAVAILABLE" and result["truncated"]
    assert result["limitations"] == ["MEMBER_PAGINATION_INVALID"]


def test_bot_accounts_are_distinct_from_users():
    result, _ = members([[row("person"), {**row("automation"), "bot": True}]])
    assert [person["principal_kind"] for person in result["people"]] == ["USER", "SERVICE_PRINCIPAL"]
