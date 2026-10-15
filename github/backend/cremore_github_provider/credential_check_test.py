"""The connection check of a GitHub App source names the App it confirmed; synthetic, no network."""

from types import SimpleNamespace

from cremore.collectors.credential_result import ACTIVE, INDETERMINATE, REJECTED
from cremore_github_provider.credential_check import check_github
from cremore_github_provider.github_auth import GitHubAuthError


class AppSource:
    def __init__(self, identity):
        self._identity = identity

    def __call__(self):
        return "ghs_synthetic"

    def evidence(self):
        return {"credential_mode": "GITHUB_APP", "refresh_supported": True, "expires_at": "2026-09-14T01:00:00+00:00"}

    def scopes(self):
        return ("metadata:read",)

    def identity(self):
        if isinstance(self._identity, str):
            raise GitHubAuthError(self._identity)
        return self._identity


class Client:
    def __init__(self):
        self.calls = []

    def get(self, url, headers=None):
        self.calls.append(url)
        return SimpleNamespace(status_code=200, headers={},
                               json=lambda: {"repositories": [{"owner": {"login": "example-org"}}]})


def test_check_keeps_the_scan_authorization_revision_and_refuses_a_key_of_another_app():
    import uuid

    from cremore.collectors.credential_result import CredentialCheck
    from cremore.scanning.scope import auth_revision

    app = {"id": 123, "client_id": None, "slug": "cremore", "name": "CreMore", "owner": "platform-team",
           "owner_type": "Organization", "permissions": {}}
    source = AppSource(app)
    result = check_github(Client(), source)
    assert result.status == ACTIVE and result.owner == "example-org" and result.workspace == ""
    # The evidence a check wrote before it asked GET /app: the same credential must keep its
    # revision, or every approved scan scope of the connection would need review again.
    before = CredentialCheck(ACTIVE, owner="example-org", scopes=source.scopes(),
                             detail=source.evidence()).as_evidence("2026-09-14T00:00:00+00:00")
    cid = uuid.uuid4()

    def revision(evidence):
        return auth_revision("source", SimpleNamespace(id=cid, secret_ref="sealed:v1:x", credential_evidence=evidence))

    assert revision(before) == revision(result.as_evidence("2026-09-14T00:05:00+00:00"))
    client = Client()
    mismatch = check_github(client, AppSource("GITHUB_APP_IDENTITY_MISMATCH"))
    assert mismatch.status == REJECTED and mismatch.error == "GITHUB_APP_IDENTITY_MISMATCH" and not client.calls
    assert check_github(Client(), AppSource("GITHUB_APP_UNAVAILABLE")).status == INDETERMINATE


def test_response_identity_and_scopes_are_screened_before_connection_evidence():
    import json

    token = "synthetic-connection-credential"

    class ResponseClient:
        def __init__(self, owner, scopes):
            self.owner, self.scopes = owner, scopes

        def get(self, url, headers=None):
            return SimpleNamespace(status_code=200, headers={"x-oauth-scopes": self.scopes},
                                   json=lambda: {"login": self.owner})

    good = check_github(ResponseClient("example-owner", "read:org, repo"), token)
    assert good.status == ACTIVE and good.scopes == ("read:org", "repo")
    for owner, scopes in ((token, "read:org"), ("owner", token), ("owner", "read:org\nrepo")):
        result = check_github(ResponseClient(owner, scopes), token)
        assert result.status == INDETERMINATE and result.error == "UNSAFE_RESPONSE_METADATA"
        assert token not in json.dumps(result.as_evidence("2026-10-03T00:00:00+00:00"))
