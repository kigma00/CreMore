"""Shared API test fixtures: a fake OIDC issuer with a real RSA JWKS.

No network: discovery and JWKS documents are served by an in-memory client, and
tokens are signed with a throwaway key generated per test session.
"""

from __future__ import annotations

import time

import pytest

ISSUER = "https://idp.test"
AUDIENCE = "cremore-test"
GROUPS = {"viewer": "g-viewers", "analyst": "g-analysts",
          "remediator": "g-remediators", "admin": "g-admins"}


class FakeResp:
    def __init__(self, status: int, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


class FakeIssuer:
    """Serves /.well-known/openid-configuration and the JWKS; mints tokens."""

    def __init__(self):
        jwt = pytest.importorskip("jwt")
        from cryptography.hazmat.primitives.asymmetric import rsa

        self.jwt = jwt
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "test-key-1"
        self.calls: list[str] = []
        self.jwks_status = 200

    # --- the "HTTP client" the verifier is given ----------------------------
    def get(self, url: str, **kwargs):
        assert kwargs.get("follow_redirects", False) is False
        self.calls.append(url)
        if url == ISSUER + "/.well-known/openid-configuration":
            return FakeResp(200, {"issuer": ISSUER, "jwks_uri": ISSUER + "/jwks"})
        if url == ISSUER + "/jwks":
            import json

            from jwt.algorithms import RSAAlgorithm

            public = json.loads(RSAAlgorithm.to_jwk(self.private_key.public_key()))
            public.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
            return FakeResp(self.jwks_status, {"keys": [public]})
        return FakeResp(404, {})

    # --- token minting -------------------------------------------------------
    def mint(self, sub: str = "user-1", groups=("g-viewers",), *, expires_in: int = 300,
             issuer: str = ISSUER, audience: str = AUDIENCE, kid: str | None = None,
             groups_claim: str = "groups", extra: dict | None = None) -> str:
        now = int(time.time())
        claims = {"iss": issuer, "aud": audience, "sub": sub, "iat": now,
                  "exp": now + expires_in, groups_claim: list(groups), **(extra or {})}
        return self.jwt.encode(claims, self.private_key, algorithm="RS256",
                               headers={"kid": kid or self.kid})


@pytest.fixture(scope="session")
def issuer() -> FakeIssuer:
    return FakeIssuer()


def oidc_settings(**overrides):
    """Settings for AUTH_MODE=oidc pointed at the fake issuer."""

    from cremore.config import Settings

    base = {
        "AUTH_MODE": "oidc", "OIDC_ISSUER_URL": ISSUER, "OIDC_AUDIENCE": AUDIENCE,
        "OIDC_VIEWER_GROUP": GROUPS["viewer"], "OIDC_ANALYST_GROUP": GROUPS["analyst"],
        "OIDC_REMEDIATOR_GROUP": GROUPS["remediator"], "OIDC_ADMIN_GROUP": GROUPS["admin"],
        "FINGERPRINT_KEY": "ab" * 32,
    }
    base.update(overrides)
    return Settings(**base)
