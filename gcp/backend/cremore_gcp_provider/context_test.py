import httpx
import pytest

from cremore_gcp_provider import source


@pytest.mark.parametrize("variant", ["normal", "uniform", "iam_denied", "acl_denied", "malformed", "wrong_bucket"])
def test_bucket_iam_and_object_acl_are_bounded_grants_not_effective_readers(variant):
    seen = []
    def handler(request):
        seen.append(request)
        assert request.url.host == "storage.googleapis.com"
        assert request.headers["authorization"] == "Bearer synthetic"
        if request.url.path.endswith("/iam"):
            if variant == "iam_denied":
                return httpx.Response(403, text="synthetic-do-not-store")
            return httpx.Response(200, json={"bindings": [{"role": "roles/storage.objectViewer",
                "members": ["group:team@example.test", "allUsers"], "condition": {"expression": "synthetic-do-not-store"}},
                *([{"role": [], "members": []}] if variant == "malformed" else [])]})
        if request.url.path.endswith("/acl"):
            assert request.url.params["generation"] == "1234"
            assert request.url.raw_path.split(b"?")[0].endswith(b"/o/a%2Fb.env/acl")
            return httpx.Response(403) if variant == "acl_denied" else httpx.Response(200, json={"items": [
                {"entity": "user-reader@example.test", "role": "READER"}]})
        return httpx.Response(200, json={"name": "other-bucket" if variant == "wrong_bucket" else "poc-bucket",
            "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": variant == "uniform"}}})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        access = source.exposure_context({"bucket": "poc-bucket", "token": "synthetic"},
            {"repository": "poc-bucket", "path": "a/b.env", "object_version": "1234"}, http_client=client)["members"]
    assert "synthetic-do-not-store" not in str(access)
    assert len(seen) <= 3
    if variant == "wrong_bucket":
        assert access["status"] == "UNAVAILABLE" and len(seen) == 1
        return
    assert all(row["read_access"] == "UNKNOWN" for row in access["people"])
    assert access["truncated"] is (variant in ("iam_denied", "acl_denied", "malformed"))
    if variant == "uniform":
        assert len(seen) == 2 and "OBJECT_ACL_DISABLED_BY_UNIFORM_ACCESS" in access["limitations"]
    if variant in ("iam_denied", "acl_denied"):
        assert access["status"] == "FORBIDDEN" and access["people"]
    else:
        assert access["people"][0]["principal_kind"] == "GROUP"


def test_gcs_foreign_bucket_is_rejected_before_request():
    with httpx.Client(transport=httpx.MockTransport(lambda req: pytest.fail("outside bucket"))) as client:
        access = source.exposure_context({"bucket": "one-bucket", "token": "synthetic"},
            {"repository": "other-bucket", "path": "a"}, http_client=client)["members"]
    assert access["status"] == "UNSUPPORTED"
