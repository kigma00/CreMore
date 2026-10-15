from types import SimpleNamespace

import httpx
import pytest

from cremore.collectors.credential_check import (
    ACTIVE,
    INDETERMINATE,
    REJECTED,
    check_github,
    check_notion,
    check_s3,
    run_credential_check,
)
from cremore.collectors.credential_result import CredentialCheck


class Resp:
    def __init__(self, status, payload=None, headers=None):
        self.status_code, self._payload, self.headers = status, payload or {}, headers or {}

    def json(self):
        return self._payload


class Client:
    def __init__(self, resp):
        self.resp, self.calls = resp, []

    def get(self, url, headers=None):
        self.calls.append((url, headers))
        if isinstance(self.resp, Exception):
            raise self.resp
        return self.resp


def test_github_check_reports_identity_and_scopes_never_the_token():
    client = Client(Resp(200, {"login": "ci-bot"}, {"x-oauth-scopes": "repo, read:org"}))
    result = check_github(client, "ghp_synthetic")
    assert result.status == ACTIVE and result.owner == "ci-bot" and result.scopes == ("repo", "read:org")
    assert client.calls[0][0] == "https://api.github.com/user"
    evidence = result.as_evidence("2026-09-13T00:00:00+00:00")
    assert "ghp_synthetic" not in str(evidence) and evidence["checked_at"]


def test_github_401_is_rejected_and_other_failures_indeterminate():
    assert check_github(Client(Resp(401)), "t").status == REJECTED
    assert check_github(Client(Resp(503)), "t").status == INDETERMINATE
    assert check_github(Client(ConnectionError("down")), "t").error == "ConnectionError"
    assert check_github(Client(Resp(200)), "").error == "NO_CREDENTIAL"


def test_notion_nonobject_response_is_indeterminate():
    result = check_notion(Client(Resp(200, ["invalid"])), "synthetic-token")
    assert result.status == INDETERMINATE and result.error == "MALFORMED_RESPONSE"


def test_github_app_check_uses_installation_endpoint_and_exports_only_safe_refresh_facts():
    class AppSource:
        def __call__(self):
            return "ghs_synthetic"

        def evidence(self):
            return {"credential_mode": "GITHUB_APP", "refresh_supported": True,
                    "expires_at": "2026-09-14T01:00:00+00:00", "token": "must-not-leak"}

        def scopes(self):
            return ("contents:read", "metadata:read")

    client = Client(Resp(200, {"total_count": 1, "repositories": [
        {"owner": {"login": "example-org"}}
    ]}))
    result = check_github(client, AppSource())
    assert result.status == ACTIVE and result.owner == "example-org"
    assert result.scopes == ("contents:read", "metadata:read")
    assert client.calls[0][0].endswith("/installation/repositories?per_page=1")
    evidence = result.as_evidence("2026-09-14T00:00:00+00:00")
    assert evidence["credential_mode"] == "GITHUB_APP"
    assert evidence["refresh_supported"] is True and evidence["expires_at"]
    assert "must-not-leak" not in str(evidence)


def test_notion_check_reads_bot_workspace():
    client = Client(Resp(200, {"name": "Scanner bot", "bot": {"workspace_name": "Example Org"}}))
    result = check_notion(client, "ntn_synthetic")
    assert result.status == ACTIVE and result.owner == "Scanner bot" and result.workspace == "Example Org"
    assert client.calls[0][0].endswith("/v1/users/me")
    assert check_notion(Client(Resp(401)), "t").status == REJECTED


class STS:
    def __init__(self, fail=None):
        self.fail = fail

    def get_caller_identity(self):
        if self.fail:
            raise self.fail
        return {"Arn": "arn:aws:sts::123456789012:assumed-role/scanner/x", "Account": "123456789012"}


class S3:
    def __init__(self, fail=None):
        self.fail = fail

    def head_bucket(self, Bucket):
        if self.fail:
            raise self.fail
        return {}


class AwsErr(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


def test_s3_check_requires_identity_and_bucket_visibility():
    ok = check_s3(STS(), S3(), "example-bucket")
    assert ok.status == ACTIVE and ok.owner.startswith("arn:aws:sts::123456789012") and ok.scopes == ("s3:HeadBucket:example-bucket",)
    assert check_s3(STS(), S3(AwsErr("403")), "example-bucket").status == REJECTED
    assert check_s3(STS(), S3(AwsErr("404")), "example-bucket").status == INDETERMINATE
    assert check_s3(STS(AwsErr("InvalidClientTokenId")), S3(), "b").status == REJECTED
    assert check_s3(STS(RuntimeError("no creds")), S3(), "b").status == INDETERMINATE


def test_run_credential_check_aws_hands_the_payload_to_the_client_factories():
    seen = []

    def s3_factory(payload):
        assert isinstance(payload, dict)  # the payload, not a job object
        seen.append(payload["bucket"])
        return S3()

    result = run_credential_check({"provider": "aws", "bucket": "example-bucket", "region": "us-east-1"},
                                  s3_client_factory=s3_factory, sts_client_factory=lambda: STS())
    assert result.status == ACTIVE and seen == ["example-bucket"]
    no_creds = run_credential_check({"provider": "aws", "bucket": "b"}, s3_client_factory=lambda p: S3(),
                                    sts_client_factory=lambda: STS(RuntimeError("Unable to locate credentials")))
    assert no_creds.status == INDETERMINATE and no_creds.error == "RuntimeError"


def test_run_credential_check_resolves_secret_ref_and_reports_missing_secret():
    class Resolver:
        def resolve(self, ref):
            assert ref == "vault://github/prod"
            return {"token": "ghp_resolved"}

    client = Client(Resp(200, {"login": "octo"}))
    result = run_credential_check({"provider": "github", "owner": "o", "repo": "r", "secret_ref": "vault://github/prod"},
                                  http_client_factory=lambda: client, secret_resolver=Resolver())
    assert result.status == ACTIVE and client.calls[0][1]["Authorization"] == "Bearer ghp_resolved"

    class Broken:
        def resolve(self, ref):
            from cremore_vault_provider.secretstore import SecretStoreError

            raise SecretStoreError("nope")

    missing = run_credential_check({"provider": "notion", "secret_ref": "vault://x"},
                                   http_client_factory=lambda: client, secret_resolver=Broken())
    assert missing.status == REJECTED and missing.error == "SECRET_UNAVAILABLE"


def test_credential_checks_dispatch_through_the_registered_source(monkeypatch):
    from cremore.sources import registry

    expected = CredentialCheck(ACTIVE, owner="registered-source")
    calls = []

    def check(payload, **factories):
        calls.append((payload, factories))
        return expected

    monkeypatch.setitem(registry.PROVIDERS, "synthetic", SimpleNamespace(
        TOKEN_AUTH=False, check_credential=check,
    ))
    payload = {"provider": "synthetic", "scope": "approved"}
    factory = object()
    assert run_credential_check(payload, s3_client_factory=factory) is expected
    assert calls[0][0] is payload
    assert calls[0][1]["s3_client_factory"] is factory


@pytest.mark.parametrize("provider,payload,body", [
    ("gitlab", {"project": "7", "base_url": "https://gitlab.example.test"},
     {"id": 7, "path_with_namespace": "org/project"}),
    ("confluence", {"space": "99", "base_url": "https://synthetic.atlassian.net/wiki", "edition": "cloud"},
     {"results": []}),
    ("bitbucket", {"workspace": "team", "repo": "repo", "edition": "cloud", "base_url": "https://api.bitbucket.org"},
     {"slug": "repo"}),
    ("gcp", {"project": "demo-project"}, {"accounts": []}),
])
@pytest.mark.parametrize("status", [200, 401, 403])
def test_enterprise_credential_checks_preserve_safe_status_and_bounded_request(provider, payload, body, status):
    calls = []

    def answer(request):
        calls.append(request)
        assert request.headers["Authorization"] == "Bearer synthetic-scanner"
        return httpx.Response(status, json=body)

    with httpx.Client(transport=httpx.MockTransport(answer)) as client:
        result = run_credential_check(
            {"provider": provider, "token": "synthetic-scanner", **payload},
            http_client_factory=lambda: client,
        )
    assert len(calls) == 1
    assert result.status == {200: ACTIVE, 401: REJECTED, 403: INDETERMINATE}[status]
    if status != 200:
        expected_error = "SOURCE_HTTP_FAILED"
        if provider == "gcp":
            expected_error = {401: "GCP_AUTHENTICATION_FAILED", 403: "GCP_PERMISSION_DENIED_OR_API_DISABLED"}[status]
        assert result.error == expected_error
    assert "synthetic-scanner" not in str(result.as_evidence("2026-09-24T00:00:00Z"))
