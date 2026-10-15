"""Who wrote an exposed Confluence page or attachment, from synthetic Cloud and Data Center APIs."""

import httpx

from cremore_atlassian_provider import confluence_source

CLOUD = {"token": "synthetic", "edition": "cloud", "base_url": "https://acme.atlassian.net/wiki", "space": "98765"}
DATA_CENTER = {"token": "synthetic", "edition": "data_center", "base_url": "https://wiki.example.com", "space": "ENG"}


def cloud(seen, *, space="98765", parent="123", user_status=200):
    def handler(request):
        seen.append(request)
        assert request.method == "GET"
        path = request.url.path
        if path == "/wiki/api/v2/pages/123":
            return httpx.Response(200, json={"id": "123", "spaceId": space, "version": {
                "number": 7, "authorId": "5b10a2844c20165700ede21g", "createdAt": "2026-09-26T08:30:00.000Z"}})
        if path == "/wiki/api/v2/attachments/att456":
            return httpx.Response(200, json={"id": "att456", "pageId": parent, "version": {
                "number": 2, "authorId": "712020:aaaa-bbbb", "createdAt": "2026-09-20T00:00:00.000Z"}})
        if path == "/wiki/rest/api/user":
            if user_status != 200:
                return httpx.Response(user_status)
            names = {"5b10a2844c20165700ede21g": ("Han Demo", "han@example.com"), "712020:aaaa-bbbb": ("Yoon Demo", None)}
            name, email = names[request.url.params["accountId"]]
            return httpx.Response(200, json={"accountId": request.url.params["accountId"], "displayName": name,
                                             **({"email": email} if email else {})})
        return httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler))


def data_center(seen):
    def handler(request):
        seen.append(request)
        assert request.method == "GET" and request.url.params["expand"].startswith("version")
        if request.url.path == "/rest/api/content/123":
            return httpx.Response(200, json={"id": "123", "space": {"key": "ENG"}, "version": {
                "number": 3, "when": "2026-09-24T10:00:00.000+09:00", "by": {"type": "known", "username": "yoon", "displayName": "Yoon Demo"}}})
        return httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_the_cloud_page_body_names_its_current_version_author():
    seen = []
    found = confluence_source.exposure_context(CLOUD, {"repository": "123", "path": "body"}, http_client=cloud(seen), members=False)
    assert found == {"codeowners": {"status": "UNSUPPORTED"}, "author": {
        "status": "OBSERVED", "name": "Han Demo", "login": None, "email": "han@example.com", "at": "2026-09-26T08:30:00.000Z",
        "commit": None}}
    assert [request.url.path for request in seen] == ["/wiki/api/v2/pages/123", "/wiki/rest/api/user"]


def test_an_attachment_is_its_own_version_and_must_belong_to_the_page():
    found = confluence_source.exposure_context(CLOUD, {"repository": "123", "path": "attachments/att456"}, http_client=cloud([]))
    assert (found["author"]["name"], found["author"]["email"]) == ("Yoon Demo", None)
    seen = []
    other = confluence_source.exposure_context(CLOUD, {"repository": "123", "path": "attachments/att456"},
                                               http_client=cloud(seen, parent="999"))
    assert other["author"] == {"status": "UNAVAILABLE"} and "/wiki/rest/api/user" not in [r.url.path for r in seen]


def test_a_page_outside_the_space_or_a_refused_user_lookup():
    assert confluence_source.exposure_context(CLOUD, {"repository": "123", "path": "body"},
                                              http_client=cloud([], space="1"))["author"] == {"status": "UNAVAILABLE"}
    assert confluence_source.exposure_context(CLOUD, {"repository": "123", "path": "body"},
                                              http_client=cloud([], user_status=403))["author"] == {"status": "FORBIDDEN"}
    seen = []
    assert confluence_source.exposure_context(CLOUD, {"repository": "123", "path": "../x"},
                                              http_client=cloud(seen))["author"] == {"status": "UNSUPPORTED"}
    assert seen == []


def test_data_center_names_the_author_in_the_version():
    found = confluence_source.exposure_context(DATA_CENTER, {"repository": "123", "path": "body"}, http_client=data_center([]))
    assert found["author"] == {"status": "OBSERVED", "name": "Yoon Demo", "login": "yoon", "email": None,
                               "at": "2026-09-24T10:00:00.000+09:00", "commit": None}
