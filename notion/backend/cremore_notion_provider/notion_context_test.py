"""Who last edited an exposed Notion page, from a synthetic Notion API (cremore_notion_provider.context)."""

import httpx

from cremore_notion_provider import source

PAGE = "0123456789abcdef0123456789abcdef"
EDITOR = "7d1c5e6a-1111-4222-8333-444455556666"
# Built at run time: a literal would read as a token to secret scanners.
TOKEN = "ntn_" + "s" * 46


def host(seen, *, user_status=200, page_id=PAGE):
    def handler(request):
        seen.append(request)
        assert request.method == "GET" and request.headers["authorization"] == "Bearer " + TOKEN
        assert request.headers["notion-version"]
        if request.url.path == f"/v1/pages/{PAGE}":
            return httpx.Response(200, json={"object": "page", "id": page_id, "last_edited_time": "2026-09-27T01:00:00.000Z",
                                             "last_edited_by": {"object": "user", "id": EDITOR}})
        if request.url.path == f"/v1/users/{EDITOR}":
            if user_status != 200:
                return httpx.Response(user_status, json={"object": "error", "code": "restricted_resource"})
            return httpx.Response(200, json={"object": "user", "id": EDITOR, "type": "person", "name": "Jung Demo",
                                             "person": {"email": "jung@example.com"}})
        return httpx.Response(404, json={"object": "error"})
    return httpx.Client(transport=httpx.MockTransport(handler))


def read(seen, **kwargs):
    return source.exposure_context({"token": TOKEN}, {"page_id": PAGE, "repository": "Onboarding", "path": "https://www.notion.so/x"},
                                   http_client=host(seen, **kwargs))


def test_the_last_editor_of_the_page_with_the_name_and_email_notion_gives():
    seen = []
    found = read(seen)
    assert found == {"codeowners": {"status": "UNSUPPORTED"}, "author": {
        "status": "OBSERVED", "name": "Jung Demo", "login": None, "email": "jung@example.com",
        "at": "2026-09-27T01:00:00.000Z", "commit": None}}
    assert [request.url.path for request in seen] == [f"/v1/pages/{PAGE}", f"/v1/users/{EDITOR}"]


def test_no_user_information_capability_is_forbidden_not_a_bare_id():
    assert read([], user_status=403)["author"] == {"status": "FORBIDDEN"}


def test_a_different_page_or_no_page_id_reads_nothing():
    assert read([], page_id="f" * 32)["author"] == {"status": "UNAVAILABLE"}
    seen = []
    found = source.exposure_context({"token": TOKEN}, {"repository": "Onboarding", "path": "x"}, http_client=host(seen))
    assert found["author"] == {"status": "UNSUPPORTED"} and seen == []
