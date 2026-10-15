"""An installed App that holds no read permission yet (the account card's App) is told what each feature lacks."""

import base64
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cremore_github_provider import onboarding

PEM = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
ENVELOPE = {"GITHUB_APP_ID": "424242", "GITHUB_APP_INSTALLATION_ID": "13",
            "GITHUB_APP_PRIVATE_KEY_BASE64": base64.b64encode(PEM).decode()}


def github(calls, *, account="acme", permissions=None):
    def handler(request):
        calls.append((request.method, request.url.path))
        if request.url.path == "/orgs/acme/installation":
            return httpx.Response(200, json={"id": 13, "app_id": 424242, "target_type": "Organization",
                                             "account": {"login": account, "type": "Organization"},
                                             "permissions": {} if permissions is None else permissions})
        return httpx.Response(403)  # never a token: an empty request would get every permission
    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def check(purpose, plan, http_client):
    connection = {"provider": "github", "edition": "enterprise_cloud", "auth_method": "github_app",
                  "target": {"organization": "acme", "auth": {"github_organization_binding": "acme"}},
                  "secret_refs": {"credential": "sealed:synthetic"}, "purposes": [purpose],
                  "plans": {purpose: plan}}
    return onboarding.check(connection, purpose, {"credential": ENVELOPE}, SimpleNamespace(memo={}, http_client=http_client))


@pytest.mark.parametrize("purpose, plan", [("exposure", {}), ("inventory", {"audit_events": True}), ("identity", {})])
def test_a_bare_app_is_installed_and_lacks_the_features_reads(purpose, plan):
    calls = []
    result = {item["permission"]: item for item in check(purpose, plan, github(calls))}
    assert result["installation"]["status"] == "GRANTED"
    assert all(result[name]["status"] == "MISSING" for name in onboarding.APP_PERMISSIONS[purpose])
    if purpose == "inventory":
        assert result["org_audit_read"]["status"] == "MISSING"
    assert calls == [("GET", "/orgs/acme/installation")]  # no token asked for, no audit or GraphQL probe


def test_a_bare_app_on_another_account_or_a_refused_installation_is_still_not_installed():
    calls = []
    result = check("exposure", {}, github(calls, account="other"))
    assert result == [{"permission": "installation", "status": "ERROR", "detail": "GITHUB_APP_INSTALLATION_MISMATCH"}]

    def gone(request):
        return httpx.Response(404)
    result = check("exposure", {}, lambda: httpx.Client(transport=httpx.MockTransport(gone)))
    assert result == [{"permission": "installation", "status": "MISSING", "detail": "GITHUB_APP_REJECTED"}]
