"""A GitHub App from a manifest, against a synthetic GitHub: the manifest asks only read permissions, the
code is converted by the server alone, and the installation is found with the App's own JWT."""

import base64
import json

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cremore_github_provider import app_manifest
from cremore_github_provider.github_auth import GitHubAuthError
from cremore_github_provider.onboarding import APP_PERMISSIONS

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                        serialization.NoEncryption()).decode()


def test_the_manifest_asks_read_permissions_for_the_chosen_purposes_only():
    body = app_manifest.manifest("acme", ["exposure", "vault"], APP_PERMISSIONS)
    assert body["name"] == "CreMore acme" and body["public"] is False and body["default_events"] == []
    # Listing environments before their secrets is under Actions: read (GitHub's permissions for GitHub Apps).
    assert body["default_permissions"] == {"metadata": "read", "contents": "read", "organization_secrets": "read",
                                           "secrets": "read", "environments": "read", "actions": "read"}
    assert set(app_manifest.manifest("acme", ["inventory"], APP_PERMISSIONS)["default_permissions"]) == {
        "organization_administration", "organization_personal_access_tokens",
        "organization_personal_access_token_requests", "administration"}
    # The organization's SAML identities: Members (read), asked only when people are read.
    assert app_manifest.manifest("acme", ["identity"], APP_PERMISSIONS)["default_permissions"] == {"members": "read"}
    assert len(app_manifest.manifest("a" * 39, ["exposure"], APP_PERMISSIONS)["name"]) == 34


@pytest.mark.parametrize("purposes, description", [
    ([], "CreMore authenticates this App; no collection permissions are requested."),
    (["exposure"], "CreMore reads repositories (read only)."),
    (["inventory"], "CreMore reads credential inventories (read only)."),
    (["vault"], "CreMore reads secret metadata (read only)."),
    (["identity"], "CreMore reads SAML identities (read only)."),
    (["exposure", "vault"], "CreMore reads repositories, secret metadata (read only)."),
])
def test_manifest_description_names_only_requested_reads(purposes, description):
    assert app_manifest.manifest("acme", purposes, APP_PERMISSIONS)["description"] == description


def test_the_action_app_is_explicit_and_cannot_be_combined_with_a_collection_app():
    body = app_manifest.manifest("acme", ["remediation"], APP_PERMISSIONS)
    assert body["default_permissions"] == {"organization_personal_access_tokens": "write"}
    assert body["name"] == "CreMore Actions acme"
    assert "organization access after approval" in body["description"]
    assert body["default_events"] == [] and body["public"] is False
    assert app_manifest.manifest("acme", [], APP_PERMISSIONS)["default_permissions"] == {}
    for purposes in (["remediation", "exposure"], ["remediation", "identity"], ["unknown"], [{}], None, "remediation"):
        with pytest.raises(GitHubAuthError, match="AUTH_METHOD_NOT_FOR_PURPOSES"):
            app_manifest.manifest("acme", purposes, APP_PERMISSIONS)


def test_where_the_manifest_goes_and_where_the_app_is_installed():
    assert app_manifest.form_url("", "acme") == "https://github.com/organizations/acme/settings/apps/new"
    assert app_manifest.form_url("github.example.com", "acme") == "https://github.example.com/organizations/acme/settings/apps/new"
    assert app_manifest.install_url("", "cremore-acme") == "https://github.com/apps/cremore-acme/installations/new"
    assert app_manifest.install_url("acme.ghe.com", "cremore-acme") == "https://acme.ghe.com/apps/cremore-acme/installations/new"
    assert app_manifest.install_url("github.example.com", "cremore-acme") == "https://github.example.com/github-apps/cremore-acme/installations/new"
    for bad in ("acme/../x", ""):
        with pytest.raises(GitHubAuthError):
            app_manifest.form_url("", bad)


def github(calls, *, status=201, body=None, installations=None):
    def handler(request):
        calls.append(request)
        if request.url.path.startswith("/app-manifests/"):
            assert request.method == "POST" and "authorization" not in request.headers
            return httpx.Response(status, json=body if body is not None else {
                "id": 424242, "slug": "cremore-acme", "client_id": "Iv23liABCDEFG", "name": "CreMore acme",
                "owner": {"login": "acme", "type": "Organization"}, "pem": PEM,
                "client_secret": "never-kept", "webhook_secret": "never-kept"})
        assert request.url.path == "/app/installations"
        claims = jwt.decode(request.headers["authorization"].removeprefix("Bearer "), KEY.public_key(), algorithms=["RS256"])
        assert claims["iss"] == "424242"
        return httpx.Response(200, json=installations if installations is not None else [])
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_the_code_is_converted_by_the_server_and_the_secrets_github_adds_are_not_kept():
    calls = []
    app = app_manifest.convert(github(calls), "", "0123abc")
    assert calls[0].url == "https://api.github.com/app-manifests/0123abc/conversions"
    assert app == {"app_id": "424242", "client_id": "Iv23liABCDEFG", "slug": "cremore-acme", "name": "CreMore acme",
                   "owner": "acme", "private_key_base64": base64.b64encode(PEM.strip().encode()).decode()}
    assert "never-kept" not in json.dumps(app)
    for status, code in ((404, "GITHUB_MANIFEST_CODE_EXPIRED"), (422, "GITHUB_MANIFEST_REFUSED"), (502, "GITHUB_APP_UNAVAILABLE")):
        with pytest.raises(GitHubAuthError) as failed:
            app_manifest.convert(github([], status=status, body={}), "", "0123abc")
        assert failed.value.code == code
    with pytest.raises(GitHubAuthError, match="GITHUB_MANIFEST_CODE_INVALID"):
        app_manifest.convert(github([]), "", "../x")
    with pytest.raises(GitHubAuthError, match="GITHUB_APP_RESPONSE_MALFORMED"):
        app_manifest.convert(github([], body={"id": 1, "slug": "x", "owner": {"login": "acme"}, "pem": "nope"}), "", "c")


def test_the_installation_is_the_one_on_the_organization():
    key = base64.b64encode(PEM.strip().encode()).decode()
    rows = [{"id": 11, "account": {"login": "other"}, "target_type": "Organization"},
            {"id": 12, "account": {"login": "ACME"}, "target_type": "User"},
            {"id": 13, "account": {"login": "Acme"}, "target_type": "Organization"}]
    assert app_manifest.installation(github([], installations=rows), "", "424242", key, "acme") == "13"
    assert app_manifest.installation(github([], installations=rows[:2]), "", "424242", key, "acme") is None
