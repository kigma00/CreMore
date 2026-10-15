"""OIDC verification and role gating tests against the fake issuer fixture."""

from __future__ import annotations

import pytest

pytest.importorskip("jwt")
from fastapi import HTTPException

from cremore.api.auth import (
    LOCAL_ACTOR,
    build_verifier,
    make_auth,
    role_at_least,
)
from cremore.api.conftest import AUDIENCE, ISSUER, oidc_settings


def verifier(issuer):
    return build_verifier(oidc_settings(), issuer)


def test_valid_token_yields_principal_with_highest_role(issuer):
    tok = issuer.mint(sub="alice", groups=("g-viewers", "g-remediators"))
    p = verifier(issuer).verify(tok)
    assert p.subject == "alice"
    assert p.role == "remediator"  # highest of the matching groups wins
    assert "g-viewers" in p.groups


def test_discovery_then_jwks_are_fetched_once_and_cached(issuer):
    v = verifier(issuer)
    before = len(issuer.calls)
    v.verify(issuer.mint())
    v.verify(issuer.mint(sub="bob"))
    fetched = issuer.calls[before:]
    assert fetched.count(ISSUER + "/.well-known/openid-configuration") == 1
    assert fetched.count(ISSUER + "/jwks") == 1


@pytest.mark.parametrize("issuer_url,jwks,configured,allowed", [
    (ISSUER, ISSUER + "/keys", "", True),
    ("http://idp.internal:8080/realm/company", "http://idp.internal:8080/keys", "", True),
    ("https://accounts.google.com", "https://www.googleapis.com/oauth2/v3/certs", "", True),
    (ISSUER, "https://keys.test/oidc", "https://keys.test/oidc", True),
    (ISSUER, "https://keys.test/other", "https://keys.test/oidc", False),
    (ISSUER, "http://127.0.0.1/internal", "", False),
    (ISSUER, "https://unrelated.test/keys", "", False),
    (ISSUER, "http://idp.test/keys", "", False),
    (ISSUER, "https://idp.test:8443/keys", "", False),
    (ISSUER, "file:///keys", "", False),
    (ISSUER, ("https://user:" "password@idp.test/keys"), "", False),
    (ISSUER, ISSUER + "/keys#fragment", "", False),
    (ISSUER, {"url": ISSUER + "/keys"}, "", False),
])
def test_discovered_key_destination_is_approved_before_fetch(issuer_url, jwks, configured, allowed):
    import httpx

    calls = []

    def respond(request):
        calls.append(str(request.url))
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json={"issuer": issuer_url, "jwks_uri": jwks})
        return httpx.Response(200, json={"keys": []})

    with httpx.Client(transport=httpx.MockTransport(respond), follow_redirects=True) as http:
        v = build_verifier(oidc_settings(OIDC_ISSUER_URL=issuer_url, OIDC_JWKS_URL=configured), http)
        if allowed:
            v._refresh_keys()
            assert calls == [issuer_url + "/.well-known/openid-configuration", jwks]
        else:
            with pytest.raises(HTTPException) as exc:
                v._refresh_keys()
            assert exc.value.status_code == 503
            assert len(calls) == 1 and v._jwks_uri is None


def test_oidc_fetch_never_follows_redirects():
    import httpx

    calls = []

    def respond(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://unapproved.test/keys"})

    with (httpx.Client(transport=httpx.MockTransport(respond), follow_redirects=True) as http,
          pytest.raises(HTTPException) as exc):
        build_verifier(oidc_settings(), http)._refresh_keys()
    assert exc.value.status_code == 503 and len(calls) == 1


@pytest.mark.parametrize("kwargs,status", [
    ({"audience": "someone-else"}, 401),
    ({"issuer": "https://evil.test"}, 401),
    ({"expires_in": -60}, 401),
    ({"groups": ("g-nobody",)}, 403),
    ({"groups": ()}, 403),
])
def test_rejections(issuer, kwargs, status):
    tok = issuer.mint(**kwargs)
    with pytest.raises(HTTPException) as exc:
        verifier(issuer).verify(tok)
    assert exc.value.status_code == status


def test_unknown_kid_is_rejected_without_repeated_refresh(issuer):
    v = verifier(issuer)
    v.verify(issuer.mint())  # warm cache
    before = len(issuer.calls)
    with pytest.raises(HTTPException) as exc:
        v.verify(issuer.mint(kid="rotated-away"))
    assert exc.value.status_code == 401
    assert issuer.calls[before:].count(ISSUER + "/jwks") == 0


def test_key_refresh_window_coalesces_callers_and_allows_rotation():
    from concurrent.futures import ThreadPoolExecutor

    from cremore.api.conftest import FakeIssuer

    source = FakeIssuer()
    v = verifier(source)
    now = [1000.0]
    v.clock = lambda: now[0]
    v.verify(source.mint())
    now[0] += 31
    before = len(source.calls)
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(v._key_for, ["missing"] * 8)) == [None] * 8
    assert source.calls[before:].count(ISSUER + "/jwks") == 1
    source.kid = "new-key"
    now[0] += 31
    assert v.verify(source.mint()).subject == "user-1"


def test_failed_key_refresh_is_throttled_and_stale_keys_are_not_accepted():
    from cremore.api.conftest import FakeIssuer

    source = FakeIssuer()
    v = verifier(source)
    now = [1000.0]
    v.clock = lambda: now[0]
    token = source.mint()
    v.verify(token)
    now[0] += v.jwks_ttl + 1
    source.jwks_status = 503
    before = len(source.calls)
    for _ in range(2):
        with pytest.raises(HTTPException) as exc:
            v.verify(token)
        assert exc.value.status_code == 503
    assert source.calls[before:].count(ISSUER + "/jwks") == 1
    source.jwks_status = 200
    now[0] += 31
    assert v.verify(token).subject == "user-1"


def test_garbage_token_is_401(issuer):
    with pytest.raises(HTTPException) as exc:
        verifier(issuer).verify("not.a.jwt")
    assert exc.value.status_code == 401


def test_discovery_issuer_mismatch_is_503(issuer):
    class Lying:
        def get(self, url, **kwargs):
            from cremore.api.conftest import FakeResp

            return FakeResp(200, {"issuer": "https://other.test", "jwks_uri": ISSUER + "/jwks"})

    v = build_verifier(oidc_settings(), Lying())
    with pytest.raises(HTTPException) as exc:
        v.verify(issuer.mint())
    assert exc.value.status_code == 503


def test_role_order():
    assert role_at_least("admin", "viewer")
    assert role_at_least("analyst", "analyst")
    assert not role_at_least("viewer", "analyst")


def test_make_auth_local_mode_is_admin():
    from cremore.config import Settings

    require_auth, require_role, require_principal = make_auth(Settings(AUTH_MODE="local", API_TOKEN="t"), None)
    assert require_principal("Bearer t").role == "admin"
    assert require_auth("Bearer t") == LOCAL_ACTOR
    assert require_role("admin")("Bearer t") == LOCAL_ACTOR
    with pytest.raises(HTTPException) as exc:
        require_auth("Bearer wrong")
    assert exc.value.status_code == 401


def test_make_auth_oidc_role_gate(issuer):
    require_auth, require_role, _principal = make_auth(oidc_settings(), verifier(issuer))
    viewer = "Bearer " + issuer.mint(sub="v", groups=("g-viewers",))
    admin = "Bearer " + issuer.mint(sub="a", groups=("g-admins",))
    assert require_auth(viewer) == "v"
    assert require_role("admin")(admin) == "a"
    with pytest.raises(HTTPException) as exc:
        require_role("analyst")(viewer)
    assert exc.value.status_code == 403
    assert AUDIENCE  # fixture sanity


@pytest.mark.parametrize("method,path,body,allowed,denied,status", [
    # Every collection is created by a provider connection's step 4; connecting is an Admin's.
    ("POST", "/api/v1/provider-connections",
     {"provider": "gitlab", "purposes": ["inventory"], "auth_method": "token",
      "target": {"scope": "group", "id": "10"}, "credential": {"vault_ref": "vault://gitlab/token"}},
     "g-admins", "g-remediators", 201),
    ("POST", "/api/v1/provider-connections/00000000-0000-4000-8000-000000000001/activate",
     {"purposes": {"inventory": {}}}, "g-admins", "g-remediators", 404),
    ("GET", "/api/v1/provider-connections", None, "g-viewers", None, 200),
    ("PUT", "/api/v1/coverage/scope", None, "g-admins", "g-remediators", 200),
    ("PATCH", "/api/v1/coverage/connections/00000000-0000-4000-8000-000000000001",
     {"revision": 1, "enabled": False}, "g-admins", "g-remediators", 404),
    ("POST", "/api/v1/coverage/connections/00000000-0000-4000-8000-000000000001/collect",
     None, "g-admins", "g-remediators", 409),
    ("POST", "/api/v1/aws/accounts/00000000-0000-4000-8000-000000000001/credential-inventory/refresh",
     None, "g-analysts", "g-viewers", 404),
    # Schema 2 keeps the same split: Admin configures a connection, Analyst and
    # above may ask for a collection, and any signed-in role may read.
    ("PATCH", "/api/v2/coverage/connections/00000000-0000-4000-8000-000000000001",
     {"revision": 1, "enabled": False}, "g-admins", "g-remediators", 404),
    ("POST", "/api/v2/coverage/connections/00000000-0000-4000-8000-000000000001/collect",
     None, "g-analysts", "g-viewers", 409),
    ("GET", "/api/v2/coverage/inventory", None, "g-viewers", None, 200),
    ("GET", "/api/v2/coverage/providers", None, "g-viewers", None, 200),
])
def test_coverage_routes_authenticate_each_request(issuer, method, path, body, allowed, denied, status):
    from fastapi.testclient import TestClient

    from cremore.api import create_app
    from cremore.coverage.correlation import scope_revision
    from cremore.db.repository import InMemoryRepository

    if path.endswith("/scope"):
        body = {"revision": scope_revision([]), "confirmed": True}
    with TestClient(create_app(repo=InMemoryRepository(), settings=oidc_settings(),
                               oidc_http_client=issuer)) as client:
        # A successful identity must not be reused for the next caller. Missing
        # resources deliberately exercise authorization before route handling.
        attempts = [(allowed, status), (None, 401), (allowed, status)]
        if denied is not None:
            attempts.insert(1, (denied, 403))
        for group, expected in attempts:
            headers = {"Authorization": "Bearer " + issuer.mint(groups=(group,))} if group else {}
            response = client.request(method, path, json=body, headers=headers)
            assert response.status_code == expected, response.text


def test_a_shared_admin_token_cannot_authenticate_once_oidc_is_on(issuer):
    """The team deployment's guarantee: one shared token is not an identity.

    The public Compose overlay and the Helm chart both keep API_TOKEN set while
    switching AUTH_MODE to oidc. If that token still worked, a team install
    would have an anonymous admin nobody can attribute an action to.
    """
    settings = oidc_settings(API_TOKEN="shared-admin-token-" + "0" * 20)
    require_auth, _role, require_principal = make_auth(settings, verifier(issuer))
    for header in ("Bearer " + settings.api_token, "Bearer ", ""):
        with pytest.raises(HTTPException) as exc:
            require_auth(header)
        assert exc.value.status_code == 401, header
    # A real user is a real subject, which is what the audit log records.
    assert require_principal("Bearer " + issuer.mint(sub="analyst-1", groups=("g-analysts",))).subject == "analyst-1"


def test_a_user_in_no_mapped_group_never_becomes_a_subject(issuer):
    require_auth, require_role, require_principal = make_auth(oidc_settings(), verifier(issuer))
    token = "Bearer " + issuer.mint(sub="outsider", groups=("some-other-team",))
    # Refused at authentication, not merely at the role gate: a token the IdP
    # signed for someone outside every mapped group resolves to no identity at
    # all, so it cannot read anything or appear in the audit log as an actor.
    for call in (require_auth, require_principal, require_role("viewer")):
        with pytest.raises(HTTPException) as exc:
            call(token)
        assert exc.value.status_code == 403


def test_an_oidc_install_needs_no_shared_token_and_local_will_not_start_without_one():
    """What the team overlay relies on when it clears API_TOKEN."""
    from cremore.config import Settings

    shared = {"FINGERPRINT_KEY": "ab" * 32}
    oidc = Settings(AUTH_MODE="oidc", API_TOKEN="", OIDC_ISSUER_URL="https://idp.example.test",
                    OIDC_AUDIENCE="cremore", **shared)
    for component in ("api", "worker"):
        oidc.validate_safety(component)
    # And the reverse: a deployment that drops back to the shared-token mode
    # without restoring a token is refused rather than started wide open.
    with pytest.raises(ValueError, match="API_TOKEN"):
        Settings(AUTH_MODE="local", API_TOKEN="", **shared).validate_safety("api")
