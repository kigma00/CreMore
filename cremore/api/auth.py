"""API authentication: local shared token or OIDC bearer tokens.

In ``oidc`` mode the API independently validates every bearer token — issuer,
signature (against the issuer's published JWKS), audience, expiry and subject —
and maps the configured groups claim onto platform roles. It never trusts a
proxy header alone. Discovery and JWKS documents are fetched through an
injectable HTTP client so the verifier is exercised end-to-end with fakes.

Roles are ordered viewer < analyst < remediator < admin; a token with several
matching groups gets the highest. A token with none is rejected (403).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import jwt
from fastapi import Header, HTTPException, Request

from cremore.http_client import bounded_request

ROLE_ORDER = ("viewer", "analyst", "remediator", "admin")
_ALLOWED_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384", "PS256", "PS384", "PS512")
LOCAL_ACTOR = "00000000-0000-0000-0000-000000000001"


@dataclass
class Principal:
    subject: str
    role: str
    groups: tuple[str, ...] = ()
    email: str = ""  # the token's email claim, unless the token says it is not verified
    display_name: str = ""  # display only; authorization and audit keep the immutable subject
    session_mark: str = ""  # digest of verified session evidence, never a bearer or raw session id
    session_basis: str = ""


@dataclass
class OIDCConfig:
    issuer_url: str
    audience: str
    groups_claim: str = "groups"
    # group name -> role
    role_groups: dict[str, str] = field(default_factory=dict)
    jwks_url: str = ""  # Exact administrator-approved destination when hosted elsewhere.


class OIDCVerifier:
    """Validates OIDC ID/access tokens against the issuer's JWKS. ``groups_of`` (an IdP whose tokens carry no groups
    claim, Google) gives a verified token's groups instead of the claim (cremore.identity.sign_in_groups)."""

    def __init__(self, config: OIDCConfig, http_client, *, jwks_ttl: float = 300.0,
                 leeway: float = 30.0, clock=time.time, groups_of=None) -> None:
        self.config = config
        self.groups_of = groups_of
        self.http = http_client
        self.jwks_ttl = jwks_ttl
        self.leeway = leeway
        self.clock = clock
        self._jwks_uri: str | None = None
        self._keys: dict[str, object] = {}
        self._fetched_at: float = 0.0
        self._refresh_lock = threading.Lock()
        self._refresh_not_before = float("-inf")

    # --- key discovery ------------------------------------------------------

    def _discover(self) -> str:
        if self._jwks_uri:
            return self._jwks_uri
        issuer_origin = self._origin(self.config.issuer_url)
        url = self.config.issuer_url.rstrip("/") + "/.well-known/openid-configuration"
        doc = self._get_json(url)
        jwks_uri = doc.get("jwks_uri") if isinstance(doc, dict) else None
        if not jwks_uri:
            raise HTTPException(status_code=503, detail="oidc discovery unavailable")
        # The discovery document must be for the configured issuer.
        if not isinstance(doc.get("issuer"), str) or doc["issuer"].rstrip("/") != self.config.issuer_url.rstrip("/"):
            raise HTTPException(status_code=503, detail="oidc issuer mismatch in discovery")
        destination = self._origin(jwks_uri)
        explicit = self.config.jwks_url
        # Google publishes keys on a separate, fixed origin. Private self-hosted
        # IdPs keep working: their configured origin is the network trust anchor.
        google_keys = (self.config.issuer_url.rstrip("/") == "https://accounts.google.com"
                       and jwks_uri == "https://www.googleapis.com/oauth2/v3/certs")
        if explicit:
            self._origin(explicit)
            allowed = jwks_uri == explicit
        else:
            allowed = destination == issuer_origin or google_keys
        if not allowed:
            raise HTTPException(status_code=503, detail="oidc JWKS destination not approved")
        self._jwks_uri = jwks_uri
        return jwks_uri

    @staticmethod
    def _origin(url):
        try:
            if not isinstance(url, str) or len(url) > 2048 or any(ord(c) <= 32 for c in url) or "\\" in url:
                raise ValueError
            parsed = urlsplit(url)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None or parsed.fragment):
                raise ValueError
            return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            raise HTTPException(status_code=503, detail="oidc endpoint invalid") from None

    def _refresh_keys(self) -> None:
        jwks = self._get_json(self._discover())
        keys = {}
        for entry in (jwks.get("keys", []) if isinstance(jwks, dict) else []):
            kid = entry.get("kid")
            if not kid:
                continue
            try:
                keys[kid] = jwt.PyJWK(entry).key
            except Exception:  # noqa: BLE001, S112 -- Skip unsupported JWKs; no usable key still rejects authentication.
                continue
        self._keys = keys
        self._fetched_at = self.clock()

    def _key_for(self, kid: str):
        # One refresh window per verifier, including misses and failed fetches.
        # Never retain attacker-selected key IDs or accept stale keys on failure.
        with self._refresh_lock:
            now = self.clock()
            stale = (now - self._fetched_at) > self.jwks_ttl
            if kid not in self._keys or stale:
                if now >= self._refresh_not_before:
                    self._refresh_not_before = now + 30.0
                    self._refresh_keys()
                elif stale:
                    raise HTTPException(status_code=503, detail="oidc keys refresh pending")
            return self._keys.get(kid)

    def _get_json(self, url: str):
        try:
            resp = bounded_request(self.http, "GET", url, follow_redirects=False)
        except Exception:  # noqa: BLE001 -- Provider/key parsing failures must fail authentication without exposing response contents.
            raise HTTPException(status_code=503, detail="oidc provider unreachable")
        if getattr(resp, "status_code", 200) != 200:
            raise HTTPException(status_code=503, detail="oidc provider error")
        try:
            return resp.json()
        except Exception:  # noqa: BLE001 -- Provider/key parsing failures must fail authentication without exposing response contents.
            raise HTTPException(status_code=503, detail="oidc provider returned malformed json")

    # --- verification -------------------------------------------------------

    def verify(self, token: str) -> Principal:
        claims = self.claims(token)
        if self.groups_of is not None:
            groups = tuple(self.groups_of(claims))
        else:
            groups = claims.get(self.config.groups_claim) or []
            if isinstance(groups, str):
                groups = [groups]
            groups = tuple(str(g) for g in groups)
        role = _highest_role(groups, self.config.role_groups)
        if role is None:
            raise HTTPException(status_code=403, detail="no platform role for this identity")
        email = claims.get("email")
        email = email.strip() if isinstance(email, str) and email_verified(claims) else ""
        name = claims.get("name")
        name = name.strip()[:200] if isinstance(name, str) else ""
        basis = "sid" if isinstance(claims.get("sid"), str) and claims["sid"] else (
            "auth_time" if type(claims.get("auth_time")) is int else "iat")
        marker = hashlib.sha256(json.dumps([claims["iss"], claims["sub"], basis, claims[basis]],
                                          separators=(",", ":")).encode()).hexdigest()
        return Principal(subject=str(claims["sub"]).strip(), role=role, groups=groups,
                         email=email, display_name=name or email, session_mark=marker, session_basis=basis)

    def claims(self, token: str) -> dict:
        """The token's claims once issuer, signature, audience, expiry and subject hold, whatever its groups
        (a credential's owner opening an approval link has no platform role)."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="malformed token")
        kid = header.get("kid")
        alg = header.get("alg")
        if not kid or alg not in _ALLOWED_ALGS:
            raise HTTPException(status_code=401, detail="unsupported token header")
        key = self._key_for(kid)
        if key is None:
            raise HTTPException(status_code=401, detail="unknown signing key")
        try:
            claims = jwt.decode(
                token, key, algorithms=[alg], audience=self.config.audience,
                issuer=self.config.issuer_url, leeway=self.leeway,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="token expired")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="invalid token")
        if not str(claims.get("sub") or "").strip():
            raise HTTPException(status_code=401, detail="token has no subject")
        return claims


def email_verified(claims: dict) -> bool:
    """Whether a token's ``email`` claim is not marked unverified. An absent ``email_verified`` is trusted (some
    identity providers never send it), so the email claim must be one the company's admins control."""
    return str(claims.get("email_verified", True)).strip().lower() not in ("false", "0")


def _highest_role(groups: tuple[str, ...], role_groups: dict[str, str]) -> str | None:
    best: str | None = None
    for g in groups:
        role = role_groups.get(g)
        if role and (best is None or ROLE_ORDER.index(role) > ROLE_ORDER.index(best)):
            best = role
    return best


def role_at_least(role: str, minimum: str) -> bool:
    return ROLE_ORDER.index(role) >= ROLE_ORDER.index(minimum)


def build_verifier(settings, http_client, groups_of=None) -> OIDCVerifier:
    """``groups_of``: where a token's groups come from when its IdP sends none (group addresses, lower case)."""
    config = OIDCConfig(
        issuer_url=settings.oidc_issuer_url,
        audience=settings.oidc_audience,
        groups_claim=settings.oidc_groups_claim,
        jwks_url=settings.oidc_jwks_url,
        # Unset roles grant nothing; a value shared by two roles resolves to the
        # higher one (later entries win).
        role_groups={
            group.strip().lower() if groups_of is not None else group: role
            for group, role in (
                (settings.oidc_viewer_group, "viewer"),
                (settings.oidc_analyst_group, "analyst"),
                (settings.oidc_remediator_group, "remediator"),
                (settings.oidc_admin_group, "admin"),
            )
            if (group or "").strip()
        },
    )
    return OIDCVerifier(config, http_client, groups_of=groups_of)


def make_auth(settings, verifier: OIDCVerifier | None, on_principal=None, on_request=None):
    """Return (require_auth, require_role, require_principal) FastAPI dependencies.

    ``require_auth`` yields the actor id (subject). ``require_role(minimum)``
    yields the actor id too, after checking the principal's role.
    ``require_principal`` yields the whole :class:`Principal` (for the session
    endpoint). Local mode grants ``admin`` to the single shared-token operator.
    ``on_principal`` sees every verified company sign-in (it keeps the address
    a separation-of-duties check compares, cremore.governance.principals).
    """

    def authenticate(authorization: str, request: Request = None) -> Principal:
        token = authorization.removeprefix("Bearer ").strip()
        if not token:
            raise HTTPException(status_code=401, detail="unauthorized")
        if settings.auth_mode == "local":
            # Constant-time comparison: the shared token is a server credential.
            if not hmac.compare_digest(token.encode(), settings.api_token.encode()):
                raise HTTPException(status_code=401, detail="unauthorized")
            return Principal(subject=LOCAL_ACTOR, role="admin")
        if verifier is None:
            raise HTTPException(status_code=503, detail="oidc verifier not configured")
        principal = verifier.verify(token)
        if on_request is not None and request is not None:
            on_request(request, principal)
        if on_principal is not None and principal.email:
            on_principal(principal)
        return principal

    def require_auth(authorization: str = Header(default=""), request: Request = None) -> str:
        return authenticate(authorization, request).subject

    def require_role(minimum: str):
        if minimum not in ROLE_ORDER:
            raise ValueError(f"unknown role {minimum!r}")

        def dep(authorization: str = Header(default=""), request: Request = None) -> str:
            principal = authenticate(authorization, request)
            if not role_at_least(principal.role, minimum):
                raise HTTPException(status_code=403, detail=f"requires role {minimum}")
            return principal.subject

        return dep

    def require_principal(authorization: str = Header(default=""), request: Request = None) -> Principal:
        return authenticate(authorization, request)

    return require_auth, require_role, require_principal
