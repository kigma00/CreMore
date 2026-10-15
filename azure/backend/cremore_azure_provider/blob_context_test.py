import httpx
import pytest

from cremore_azure_provider import blob_source


@pytest.mark.parametrize("public,status", [(None, 200), ("blob", 200), ("container", 200), ("invalid", 200), (None, 403)])
def test_container_public_configuration_never_claims_effective_readers(public, status):
    calls = []
    def handler(request):
        calls.append(request)
        assert request.method == "GET" and request.url.host == "acmeprod.blob.core.windows.net"
        assert request.url.path == "/deploy" and request.url.params["restype"] == "container"
        assert request.url.params["comp"] == "acl"
        assert request.headers["authorization"] == "Bearer synthetic"
        return httpx.Response(status, headers={"x-ms-blob-public-access": public} if public else {}, content=b"<SignedIdentifiers/>")
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        access = blob_source.exposure_context({"account": "acmeprod", "token": "synthetic"},
            {"repository": "acmeprod/deploy", "path": "config.env"}, http_client=client)["members"]
    assert len(calls) == 1 and access["visibility"] == "UNKNOWN"
    if status == 403:
        assert access["status"] == "FORBIDDEN" and "people" not in access
    elif public == "invalid":
        assert access["status"] == "UNAVAILABLE"
    else:
        assert access["status"] == "OBSERVED" and len(access["people"]) == int(bool(public))
        assert all(p["principal_kind"] == "PUBLIC" and p["read_access"] == "UNKNOWN" for p in access["people"])
        assert "STORED_ACCESS_POLICIES_NOT_IDENTITIES" in access["limitations"]


def test_stored_access_policy_is_not_a_person_or_sas_and_malformed_rows_are_partial():
    def handler(request):
        return httpx.Response(200, content=b"""<SignedIdentifiers>
          <SignedIdentifier><Id>temporary-read</Id><AccessPolicy><Permission>rl</Permission>
          <Expiry>synthetic-do-not-store</Expiry></AccessPolicy></SignedIdentifier>
          <SignedIdentifier><Id>bad</Id><AccessPolicy><Permission>unknown</Permission></AccessPolicy></SignedIdentifier>
          </SignedIdentifiers>""")
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        access = blob_source.exposure_context({"account": "acmeprod", "token": "synthetic"},
            {"repository": "acmeprod/deploy", "path": "a"}, http_client=client)["members"]
    assert access["truncated"] and len(access["people"]) == 1
    assert access["people"][0]["principal_kind"] == "POLICY" and access["people"][0]["read_access"] == "UNKNOWN"
    assert "synthetic-do-not-store" not in str(access)


@pytest.mark.parametrize("repository", ["otherprod/deploy", "acmeprod/other"])
def test_blob_other_account_or_container_is_rejected_without_request(repository):
    with httpx.Client(transport=httpx.MockTransport(lambda req: pytest.fail("out of scope"))) as client:
        access = blob_source.exposure_context({"account": "acmeprod", "container": "deploy", "token": "synthetic"},
            {"repository": repository, "path": "config.env"}, http_client=client)["members"]
    assert access["status"] == "UNSUPPORTED"
