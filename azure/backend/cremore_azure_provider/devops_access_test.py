import httpx
import pytest

from cremore_azure_provider import devops_source

PROJECT = "00000000-0000-4000-8000-000000000001"
REPO = "00000000-0000-4000-8000-000000000002"
PAYLOAD = devops_source.job_payload({"organization": "acme", "project": "Platform"}) | {"token": "synthetic"}


@pytest.mark.parametrize("variant", ["normal", "denied", "wrong_repo", "malformed"])
def test_repository_acl_is_pinned_and_allow_deny_are_not_effective_access(variant):
    calls = []
    def handler(request):
        calls.append(request)
        if request.url.path.endswith("/commits"):
            return httpx.Response(200, json={"value": []})
        if request.url.path.endswith("/repositories/app"):
            return httpx.Response(200, json={"id": REPO, "name": "other" if variant == "wrong_repo" else "app",
                "project": {"id": PROJECT, "name": "Platform", "visibility": "private"}})
        assert request.url.params["token"] == f"repoV2/{PROJECT}/{REPO}"
        assert request.url.params["recurse"] == "false"
        if variant == "denied":
            return httpx.Response(403)
        return httpx.Response(200, json={"value": [{"token": f"repoV2/{PROJECT}/{REPO}", "acesDictionary": {
            "id:allow": {"allow": 2, "deny": 0}, "id:deny": {"allow": 2, "deny": 2},
            **({"broken": {"allow": True, "deny": 0}} if variant == "malformed" else {})}}]})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        access = devops_source.exposure_context(PAYLOAD, {"repository": "acme/Platform/app", "path": "a",
            "commit": "a" * 40}, http_client=client)["members"]
    if variant == "denied":
        assert access["status"] == "FORBIDDEN"
    elif variant == "wrong_repo":
        assert access["status"] == "UNAVAILABLE" and len(calls) == 2
    else:
        assert [p["role"] for p in access["people"]] == ["allow_read", "deny_read"]
        assert all(p["read_access"] == "UNKNOWN" and p["principal_kind"] == "UNKNOWN" for p in access["people"])
        assert access["truncated"] is (variant == "malformed")
