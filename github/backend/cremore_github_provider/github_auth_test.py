from __future__ import annotations

import base64
import datetime as dt
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cremore_github_provider.github_auth import (
    GitHubAppTokenSource,
    GitHubAuthError,
    app_identity,
    app_issuer,
    github_app_fields,
)


class Response:
    def __init__(self, token: str, expires_at: str) -> None:
        self.token, self.expires_at = token, expires_at
        self.status_code, self.headers = 201, {}

    def json(self):
        return {"token": self.token, "expires_at": self.expires_at,
                "permissions": {"contents": "read", "metadata": "read"}}


class Client:
    def __init__(self, responses) -> None:
        self.responses, self.calls = list(responses), []

    def post(self, url, headers=None, json=None, *, follow_redirects=False):
        assert follow_redirects is False
        self.calls.append((url, headers, json))
        return self.responses.pop(0)


def _key() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    return base64.b64encode(pem).decode()


def test_installation_token_is_cached_then_refreshed_before_expiry():
    clock = [dt.datetime(2026, 9, 14, tzinfo=dt.UTC)]
    client = Client([
        Response("ghs_first", "2026-09-14T01:00:00Z"),
        Response("ghs_second", "2026-09-14T02:00:00Z"),
    ])
    source = GitHubAppTokenSource(lambda: client, "123", "456", _key(),
                                  now=lambda: clock[0])
    assert source() == "ghs_first"
    clock[0] += dt.timedelta(minutes=30)
    assert source() == "ghs_first" and len(client.calls) == 1
    clock[0] = dt.datetime(2026, 9, 14, 0, 58, 1, tzinfo=dt.UTC)
    assert source() == "ghs_second" and len(client.calls) == 2
    assert source.evidence()["refresh_supported"] is True
    assert source.scopes() == ("contents:read", "metadata:read")
    assert client.calls[0][0].endswith("/app/installations/456/access_tokens")
    assert client.calls[0][1]["Authorization"].startswith("Bearer ey")
    assertion = client.calls[0][1]["Authorization"].removeprefix("Bearer ")
    claims = jwt.decode(assertion, options={"verify_signature": False})
    assert claims["iss"] == "123" and claims["exp"] - claims["iat"] == 600


def test_concurrent_scan_readers_share_one_installation_token():
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    class SlowClient(Client):
        lock = threading.Lock()

        def post(self, url, headers=None, json=None, *, follow_redirects=False):
            time.sleep(0.05)  # the other readers arrive while this one waits on GitHub
            with self.lock:
                return super().post(url, headers, json, follow_redirects=follow_redirects)

    client = SlowClient([Response("ghs_first", "2026-09-14T01:00:00Z"), Response("ghs_extra", "2026-09-14T01:00:00Z")])
    source = GitHubAppTokenSource(lambda: client, "123", "456", _key(),
                                  now=lambda: dt.datetime(2026, 9, 14, tzinfo=dt.UTC))
    with ThreadPoolExecutor(8) as pool:
        assert list(pool.map(lambda _: source(), range(8))) == ["ghs_first"] * 8
    assert len(client.calls) == 1
    assert source.evidence()["expires_at"] == "2026-09-14T01:00:00+00:00"


def test_installation_token_request_targets_the_configured_host():
    # A GHES base_url must send the actual token issuance to that host's API,
    # not api.github.com.
    client = Client([Response("ghs_ghe", "2026-09-14T01:00:00Z")])
    source = GitHubAppTokenSource(lambda: client, "123", "456", _key(),
                                  base_url="https://ghe.example.com/api/v3",
                                  now=lambda: dt.datetime(2026, 9, 14, tzinfo=dt.UTC))
    assert source() == "ghs_ghe"
    assert client.calls[0][0] == "https://ghe.example.com/api/v3/app/installations/456/access_tokens"


def test_installation_token_request_defaults_to_public_github():
    client = Client([Response("ghs_pub", "2026-09-14T01:00:00Z")])
    source = GitHubAppTokenSource(lambda: client, "123", "456", _key(),
                                  now=lambda: dt.datetime(2026, 9, 14, tzinfo=dt.UTC))
    assert source() == "ghs_pub"
    assert client.calls[0][0] == "https://api.github.com/app/installations/456/access_tokens"


NOW = dt.datetime(2026, 9, 14, tzinfo=dt.UTC)
APP = {"id": 123, "client_id": "Iv1.8a61f9b3a7aba766", "slug": "cremore", "name": "CreMore",
       "owner": {"login": "example-org", "type": "Organization"},
       "permissions": {"organization_administration": "read", "metadata": "read"}}


class GetClient:
    def __init__(self, status, body):
        self.status, self.body, self.calls = status, body, []

    def get(self, url, headers=None, *, follow_redirects=False):
        assert follow_redirects is False
        self.calls.append((url, headers))
        return SimpleNamespace(status_code=self.status, headers={}, content=b"", json=lambda: self.body)


def _issuer(headers):
    return jwt.decode(headers["Authorization"].removeprefix("Bearer "), options={"verify_signature": False})["iss"]


def test_a_client_id_signs_the_app_jwt_including_the_dotted_form():
    key = _key()
    for issuer in ("Iv1.8a61f9b3a7aba766", "Iv23liSynthetic00000"):
        client = Client([Response("ghs_client", "2026-09-14T01:00:00Z")])
        assert GitHubAppTokenSource(lambda client=client: client, issuer, "456", key, now=lambda: NOW)() == "ghs_client"
        assert _issuer(client.calls[0][1]) == issuer
        fields = github_app_fields({"GITHUB_APP_ID": issuer, "GITHUB_APP_INSTALLATION_ID": "456",
                                    "GITHUB_APP_PRIVATE_KEY_BASE64": key})
        assert fields["GITHUB_APP_ID"] == issuer
    for bad in ("Iv", "Iv1.", "Ov23liSynthetic00000", "0", "12a", "Iv1.8a61 f9b3", "Iv1.8a61/../x"):
        with pytest.raises(GitHubAuthError, match="GITHUB_APP_ID_INVALID"):
            app_issuer(bad)


def test_app_identity_is_checked_against_the_configured_app_id_or_client_id():
    key = _key()
    for issuer in ("123", "Iv1.8a61f9b3a7aba766"):
        client = GetClient(200, APP)
        identity = GitHubAppTokenSource(lambda client=client: client, issuer, "456", key, now=lambda: NOW).identity()
        assert identity == {"id": 123, "client_id": "Iv1.8a61f9b3a7aba766", "slug": "cremore", "name": "CreMore",
                            "owner": "example-org", "owner_type": "Organization",
                            "permissions": {"metadata": "read", "organization_administration": "read"}}
        assert client.calls[0][0] == "https://api.github.com/app" and _issuer(client.calls[0][1]) == issuer
    for issuer in ("124", "Iv1.0000000000000000"):
        with pytest.raises(GitHubAuthError, match="GITHUB_APP_IDENTITY_MISMATCH"):
            app_identity(APP, issuer)
    with pytest.raises(GitHubAuthError, match="GITHUB_APP_RESPONSE_MALFORMED"):
        app_identity({**APP, "id": "123"}, "123")
    with pytest.raises(GitHubAuthError, match="GITHUB_APP_REJECTED"):
        GitHubAppTokenSource(lambda: GetClient(401, {}), "123", "456", key, now=lambda: NOW).identity()


class ReadOnlyClient:
    """GitHub for a read-only token: the installation's permissions, then the token it mints with what it grants."""

    def __init__(self, held, granted, status=201):
        self.held, self.granted, self.status, self.calls = held, granted, status, []

    def get(self, url, headers=None, *, follow_redirects=False):
        self.calls.append(("GET", url, None))
        return SimpleNamespace(status_code=200, headers={}, content=b"", json=lambda: {
            "id": 456, "app_id": 123, "account": {"login": "example-org"}, "permissions": self.held})

    def post(self, url, headers=None, json=None, *, follow_redirects=False):
        self.calls.append(("POST", url, json))
        return SimpleNamespace(status_code=self.status, headers={}, content=b"", json=lambda: {
            "token": "ghs_read", "expires_at": "2026-09-14T01:00:00Z",
            **({"permissions": self.granted} if self.granted is not None else {})})


def test_a_read_only_token_asks_for_every_held_permission_at_read_and_is_refused_holding_more():
    key = _key()
    held = {"contents": "write", "metadata": "read", "organization_personal_access_tokens": "write",
            "repository_projects": "admin", "workflows": "write", "profile": "write", "unknown_level": "none"}
    asked = {"contents": "read", "metadata": "read", "organization_personal_access_tokens": "read",
             "repository_projects": "read"}  # workflows and profile have no read level
    client = ReadOnlyClient(held, asked)
    source = GitHubAppTokenSource(lambda: client, "123", "456", key, read_only=True, now=lambda: NOW)
    assert source() == "ghs_read" and "organization_personal_access_tokens:read" in source.scopes()
    assert client.calls[0][:2] == ("GET", "https://api.github.com/app/installations/456")
    assert client.calls[1] == ("POST", "https://api.github.com/app/installations/456/access_tokens", {"permissions": asked})
    # What the installation said is kept for the check: its account, its App and what it holds.
    assert (source.installation["app_id"], source.installation["account"]["login"]) == (123, "example-org")
    # GitHub answering with a token that may write, or naming no permissions: it is not used.
    for granted in ({**asked, "contents": "write"}, None, {}):
        loose = ReadOnlyClient(held, granted)
        with pytest.raises(GitHubAuthError, match="GITHUB_APP_TOKEN_NOT_READ_ONLY"):
            GitHubAppTokenSource(lambda loose=loose: loose, "123", "456", key, read_only=True, now=lambda: NOW)()
    # GitHub refusing one of the held permissions at read says so, not "the App was removed".
    refused = ReadOnlyClient(held, asked, status=422)
    with pytest.raises(GitHubAuthError, match="GITHUB_APP_READ_ONLY_REFUSED"):
        GitHubAppTokenSource(lambda: refused, "123", "456", key, read_only=True, now=lambda: NOW)()
    copilot = ReadOnlyClient({"organization_copilot_seat_management": "write", "metadata": "read"}, {"metadata": "read"})
    GitHubAppTokenSource(lambda: copilot, "123", "456", key, read_only=True, now=lambda: NOW)()
    assert copilot.calls[1][2] == {"permissions": {"metadata": "read"}}  # never read by CreMore: left out
    # Nothing readable: refused before an empty request, which would ask for every permission.
    empty = ReadOnlyClient({"workflows": "write"}, {})
    with pytest.raises(GitHubAuthError, match="GITHUB_APP_REJECTED"):
        GitHubAppTokenSource(lambda: empty, "123", "456", key, read_only=True, now=lambda: NOW)()
    assert [call[0] for call in empty.calls] == ["GET"]
    # Named permissions (a remediation run's) are asked for as they are.
    named = ReadOnlyClient(held, {"organization_personal_access_tokens": "write"})
    GitHubAppTokenSource(lambda: named, "123", "456", key, read_only=True, now=lambda: NOW,
                         permissions={"organization_personal_access_tokens": "write"})()
    assert [call[0] for call in named.calls] == ["POST"]


def test_invalid_app_secret_fails_with_safe_code():
    with pytest.raises(GitHubAuthError) as info:
        GitHubAppTokenSource(lambda: Client([]), "not-an-id", "456", "not-base64")
    assert info.value.code == "GITHUB_APP_ID_INVALID"


def test_provider_rejection_never_includes_response_content():
    response = Response("unused", "2026-09-14T01:00:00Z")
    response.status_code = 401
    source = GitHubAppTokenSource(lambda: Client([response]), "123", "456", _key(),
                                  now=lambda: dt.datetime(2026, 9, 14, tzinfo=dt.UTC))
    with pytest.raises(GitHubAuthError) as info:
        source()
    assert str(info.value) == "GITHUB_APP_REJECTED"
