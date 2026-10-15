"""The last commit that changed an exposed Bitbucket file, from synthetic Cloud and Data Center APIs."""

import httpx

from cremore_atlassian_provider import bitbucket_source

COMMIT = "a" * 40
CLOUD = {"token": "synthetic", "edition": "cloud", "base_url": "https://api.bitbucket.org", "workspace": "acme", "auth_type": "bearer"}
DATA_CENTER = {"token": "synthetic", "edition": "data_center", "base_url": "https://git.example.com", "project": "PLAT",
               "auth_type": "bearer"}


def host(seen, *, status=200):
    def handler(request):
        seen.append(request)
        assert request.method == "GET"
        if status != 200:
            return httpx.Response(status)
        if request.url.path == f"/2.0/repositories/acme/app/commits/{COMMIT}":
            assert (request.url.params["path"], request.url.params["pagelen"]) == ("deploy/app.env", "1")
            return httpx.Response(200, json={"values": [{"hash": "b" * 40, "date": "2026-09-27T01:00:00+00:00", "author": {
                "raw": "Lee Demo <lee@example.com>", "user": {"display_name": "이데모", "nickname": "lee-demo"}}}]})
        if request.url.path == "/rest/api/1.0/projects/PLAT/repos/app/commits":
            assert (request.url.params["path"], request.url.params["until"], request.url.params["limit"]) == ("deploy/app.env", COMMIT, "1")
            return httpx.Response(200, json={"values": [{"id": "c" * 40, "authorTimestamp": 1790000000000, "author": {
                "name": "park", "emailAddress": "park@example.com", "displayName": "Park Demo", "slug": "park"}}]})
        return httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_cloud_reads_the_commit_that_last_changed_the_path():
    found = bitbucket_source.exposure_context(CLOUD, {"repository": "acme/app", "path": "deploy/app.env", "commit": COMMIT},
                                              http_client=host([]), members=False)
    assert found == {"codeowners": {"status": "UNSUPPORTED"}, "author": {
        "status": "OBSERVED", "name": "이데모", "login": "lee-demo", "email": "lee@example.com",
        "at": "2026-09-27T01:00:00+00:00", "commit": "b" * 40}}


def test_data_center_reads_the_commit_until_the_scanned_one():
    found = bitbucket_source.exposure_context(DATA_CENTER, {"repository": "PLAT/app", "path": "deploy/app.env", "commit": COMMIT},
                                              http_client=host([]))
    assert found["author"] == {"status": "OBSERVED", "name": "Park Demo", "login": "park", "email": "park@example.com",
                               "at": "2026-09-21T14:13:20+00:00", "commit": "c" * 40}


def test_another_workspace_or_no_commit_is_not_asked_and_a_refusal_is_forbidden():
    seen = []
    for location in ({"repository": "other/app", "path": "a", "commit": COMMIT}, {"repository": "acme/app", "path": "a", "commit": ""}):
        assert bitbucket_source.exposure_context(CLOUD, location, http_client=host(seen))["author"] == {"status": "UNSUPPORTED"}
    assert seen == []
    refused = bitbucket_source.exposure_context(CLOUD, {"repository": "acme/app", "path": "deploy/app.env", "commit": COMMIT},
                                                http_client=host([], status=403))
    assert refused["author"] == {"status": "FORBIDDEN"}
