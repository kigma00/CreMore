"""secret_ref resolution and payload injection tests."""

from __future__ import annotations

import pytest
from cremore_vault_provider.secretstore import SecretStoreError

from cremore.secretstore.resolver import (
    SecretRefError,
    SecretResolver,
    inject_secret,
    parse_ref,
)


def test_parse_ref():
    assert parse_ref("vault://github/acme") == "github/acme"
    with pytest.raises(SecretRefError):
        parse_ref("https://example/x")
    with pytest.raises(SecretRefError):
        parse_ref("vault://")


@pytest.mark.parametrize("ref", [123, "synthetic-private-value", "vault://../outside"])
def test_bad_references_are_typed_errors_without_echoing_the_reference(ref):
    with pytest.raises(SecretRefError) as error:
        parse_ref(ref)
    assert str(ref) not in str(error.value)


@pytest.mark.parametrize("data", [None, [], {"token": ["synthetic"]}, {"token": "x\ny"}])
def test_invalid_resolved_credentials_never_reach_collectors(data):
    with pytest.raises(SecretRefError):
        inject_secret("github", {"secret_ref": "vault://x"}, FakeResolver(data))


class FakeResolver(SecretResolver):
    def __init__(self, data):
        self._data = data

    def resolve(self, ref):  # bypass the KV client
        parse_ref(ref)  # still validate the scheme
        return self._data


def test_inject_token_for_github():
    out = inject_secret("github", {"owner": "o", "repo": "r", "secret_ref": "vault://gh/o"},
                        FakeResolver({"token": "ghp_resolved"}))
    assert out["token"] == "ghp_resolved"
    assert out["owner"] == "o"  # other fields preserved


def test_s3_is_not_injected():
    payload = {"bucket": "b", "secret_ref": "vault://aws/prod"}
    out = inject_secret("s3", payload, FakeResolver({"token": "x"}))
    assert "token" not in out  # S3 uses the scanner's AWS identity


def test_explicit_token_wins_and_no_resolver_is_noop():
    p1 = {"token": "explicit", "secret_ref": "vault://x"}
    assert inject_secret("github", p1, FakeResolver({"token": "other"}))["token"] == "explicit"
    p2 = {"secret_ref": "vault://x"}
    assert inject_secret("github", p2, None) == p2  # no store wired -> unchanged


def test_missing_token_field_raises():
    with pytest.raises(SecretRefError):
        inject_secret("notion", {"secret_ref": "vault://n/ws"}, FakeResolver({"no_token": "x"}))


def test_store_error_is_wrapped():
    class Boom(SecretResolver):
        def __init__(self):
            pass

        def resolve(self, ref):
            raise SecretStoreError("SECRET_NOT_FOUND")

    with pytest.raises(SecretRefError):
        inject_secret("github", {"secret_ref": "vault://x"}, Boom())


def test_github_app_secret_becomes_an_in_memory_token_source():
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    data = {
        "GITHUB_APP_ID": "123",
        "GITHUB_APP_INSTALLATION_ID": "456",
        "GITHUB_APP_PRIVATE_KEY_BASE64": base64.b64encode(pem).decode(),
    }
    out = inject_secret(
        "github",
        {"secret_ref": "vault://github/app"},
        FakeResolver(data),
        github_client_factory=lambda: object(),
    )
    assert callable(out["token"])
    assert "GITHUB_APP_PRIVATE_KEY_BASE64" not in out
    assert out["token"]._read_only is True  # a scan's token reads, whatever else the App may do


def _app_secret_data():
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    return {"GITHUB_APP_ID": "123", "GITHUB_APP_INSTALLATION_ID": "456",
            "GITHUB_APP_PRIVATE_KEY_BASE64": base64.b64encode(pem).decode()}


def test_github_app_token_is_minted_against_the_connection_host():
    # A GHES connection carries base_url = api_base(github_host); the App token
    # source must issue against that host, not api.github.com.
    out = inject_secret(
        "github",
        {"secret_ref": "vault://github/app", "github_host": "ghe.example.com",
         "base_url": "https://ghe.example.com/api/v3"},
        FakeResolver(_app_secret_data()),
        github_client_factory=lambda: object(),
    )
    assert out["token"]._base_url == "https://ghe.example.com/api/v3"


def test_github_app_token_defaults_to_public_without_a_host():
    out = inject_secret(
        "github",
        {"secret_ref": "vault://github/app"},
        FakeResolver(_app_secret_data()),
        github_client_factory=lambda: object(),
    )
    assert out["token"]._base_url == "https://api.github.com"
