"""The last change to an exposed Azure DevOps file, from synthetic Git and TFVC APIs."""

import httpx

from cremore_azure_provider import devops_source

COMMIT = "a" * 40
PAYLOAD = devops_source.job_payload({"organization": "acme", "project": "Platform Team"}) | {"token": "synthetic"}


def host(seen, *, status=200):
    def handler(request):
        seen.append(request)
        assert request.method == "GET" and request.headers["authorization"].startswith("Basic ")
        if status != 200:
            return httpx.Response(status)
        params = request.url.params
        if request.url.path == "/acme/Platform Team/_apis/git/repositories/app/commits":
            assert (params["searchCriteria.itemPath"], params["searchCriteria.itemVersion.version"],
                    params["searchCriteria.itemVersion.versionType"], params["searchCriteria.$top"]) == ("/deploy/app.env", COMMIT, "commit", "1")
            return httpx.Response(200, json={"count": 1, "value": [{"commitId": "b" * 40, "author": {
                "name": "Choi Demo", "email": "choi@example.com", "date": "2026-09-26T19:20:00Z"}}]})
        if request.url.path == "/acme/Platform Team/_apis/tfvc/changesets":
            assert (params["searchCriteria.itemPath"], params["searchCriteria.toId"], params["$top"]) == ("$/Platform Team/src/app.config", "42", "1")
            return httpx.Response(200, json={"count": 1, "value": [{"changesetId": 41, "createdDate": "2026-09-20T00:00:00Z",
                                                                    "author": {"displayName": "Ahn Demo", "uniqueName": "ahn@example.com"}}]})
        return httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_git_reads_the_last_commit_that_changed_the_path_at_the_scanned_commit():
    found = devops_source.exposure_context(PAYLOAD, {"repository": "acme/Platform Team/app", "path": "deploy/app.env", "commit": COMMIT},
                                           http_client=host([]), members=False)
    assert found == {"codeowners": {"status": "UNSUPPORTED"}, "author": {
        "status": "OBSERVED", "name": "Choi Demo", "login": None, "email": "choi@example.com", "at": "2026-09-26T19:20:00Z",
        "commit": "b" * 40}}


def test_tfvc_reads_the_last_changeset_up_to_the_scanned_one():
    found = devops_source.exposure_context(PAYLOAD, {"repository": "acme/Platform Team/$", "path": "src/app.config", "version": "42"},
                                           http_client=host([]))
    assert found["author"] == {"status": "OBSERVED", "name": "Ahn Demo", "login": "ahn@example.com", "email": "ahn@example.com",
                               "at": "2026-09-20T00:00:00Z", "commit": None}


def test_another_organization_or_project_is_not_asked_and_a_refusal_is_forbidden():
    seen = []
    for repository in ("other/Platform Team/app", "acme/Other/app", "acme/Platform Team"):
        assert devops_source.exposure_context(PAYLOAD, {"repository": repository, "path": "a", "commit": COMMIT},
                                              http_client=host(seen))["author"] == {"status": "UNSUPPORTED"}
    assert seen == []
    refused = devops_source.exposure_context(PAYLOAD, {"repository": "acme/Platform Team/app", "path": "deploy/app.env", "commit": COMMIT},
                                             http_client=host([], status=401))
    assert refused["author"] == {"status": "FORBIDDEN"}
