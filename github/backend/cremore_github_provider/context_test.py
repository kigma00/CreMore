"""Repository access observations keep limits and failed follow-up pages explicit (fakes only)."""

import httpx
import pytest

from cremore_github_provider import context


def members(pages, *, visibility="private"):
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.path == "/repos/acme/app":
            return httpx.Response(403) if visibility is None else httpx.Response(200, json={"visibility": visibility})
        assert request.url.path == "/repos/acme/app/collaborators"
        assert request.url.params["affiliation"] == "all"
        value = pages[int(request.url.params["page"]) - 1]
        return value if isinstance(value, httpx.Response) else httpx.Response(200, json=value)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = context._collaborators(context._Reader({"token": "synthetic"}, client), "acme/app")
    assert all(call.method == "GET" and call.url.host == "api.github.com" for call in calls)
    return result, calls


@pytest.mark.parametrize(("visibility", "limitation"), [
    ("public", "PUBLIC_ACCESS_NOT_ENUMERATED"), ("internal", "INTERNAL_ACCESS_NOT_ENUMERATED"),
    (None, "VISIBILITY_UNAVAILABLE"),
])
def test_visibility_does_not_turn_the_collaborator_list_into_every_possible_reader(visibility, limitation):
    result, calls = members([[{"login": "alice", "type": "User", "role_name": "read"}]], visibility=visibility)
    assert result["visibility"] == (visibility.upper() if visibility else "UNKNOWN")
    assert limitation in result["limitations"]
    assert result["evidence_kind"] == "PROVIDER_COLLABORATORS"
    assert result["people"] == [{"login": "alice", "principal_kind": "USER", "role": "read", "read_access": "REPORTED"}]
    assert len(calls) == 2


def test_second_page_failure_preserves_observed_people_without_claiming_completeness():
    first = [{"login": f"user{i}", "permissions": {"pull": True}} for i in range(100)]
    result, _ = members([first, httpx.Response(403)])
    assert result["status"] == "FORBIDDEN" and result["truncated"]
    assert len(result["people"]) == 100 and result["people"][0]["read_access"] == "REPORTED"
    assert result["limitations"] == ["PAGED_LIST_NOT_ATOMIC", "MEMBER_PAGE_UNAVAILABLE"]


def test_malformed_rows_are_not_silently_treated_as_a_complete_list():
    result, _ = members([[None, {"login": ""}, {"login": "alice", "permissions": {"pull": "false"}}]])
    assert result["status"] == "OBSERVED" and result["truncated"]
    assert result["limitations"] == ["MALFORMED_MEMBER_ROWS"]
    assert result["people"] == [{"login": "alice", "principal_kind": "UNKNOWN", "role": None, "read_access": "UNKNOWN"}]


def test_provider_account_type_distinguishes_users_bots_and_unrecognized_types():
    result, _ = members([[{"login": "person", "type": "User"}, {"login": "automation", "type": "Bot"},
                          {"login": "other", "type": "custom"}, {"login": "malformed", "type": {}}]])
    assert [person["principal_kind"] for person in result["people"]] == ["USER", "SERVICE_PRINCIPAL", "UNKNOWN", "UNKNOWN"]


def test_page_budget_and_duplicate_principals_remain_bounded():
    page = [{"login": f"user{i}", "role_name": "read"} for i in range(100)]
    result, calls = members([page] * context.MAX_MEMBER_PAGES)
    assert result["truncated"] and result["limitations"] == ["PAGED_LIST_NOT_ATOMIC", "MEMBER_PAGE_LIMIT"]
    assert len(result["people"]) == 100 and len(calls) == context.MAX_MEMBER_PAGES + 1
    assert result["next_page"] == 4


def test_last_allowed_member_page_stops_without_an_unbounded_cursor():
    seen = []
    class Reader:
        def get(self, route, params=None):
            if route.endswith("/collaborators"):
                seen.append(params["page"])
                return 200, [{"login": f"user{i}", "role_name": "read"} for i in range(100)]
            return 200, {"visibility": "private"}
    found = context._collaborators(Reader(), "acme/app", start_page=100)
    assert seen == [100] and found["truncated"] and found["next_page"] is None
    for invalid in (0, 101, True, "2"):
        with pytest.raises(ValueError, match="INVALID_MEMBER_PAGE"):
            context._collaborators(Reader(), "acme/app", start_page=invalid)
