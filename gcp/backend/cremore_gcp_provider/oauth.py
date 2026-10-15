"""Google user authorization. Fixed endpoints; credentials never enter errors."""

from __future__ import annotations

import base64
import hashlib
import math
import re
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

import httpx

from cremore.http_client import HTTPResponseTooLarge, bounded_request
from cremore_gcp_provider.gcp_auth import GcpAuthError

SCOPES = ("openid", "email", "https://www.googleapis.com/auth/cloud-platform")
TOKEN_URL = "https://oauth2.googleapis.com/token"
PROJECT = re.compile(r"[a-z][a-z0-9-]{4,61}[a-z0-9]\Z")
REAUTH = frozenset({"GCP_OAUTH_REAUTH_REQUIRED", "GCP_OAUTH_SCOPE_REQUIRED"})


@dataclass(frozen=True)
class OAuthConfig:
    client_id: str
    client_secret: str = field(repr=False)
    redirect_uri: str

    def validate(self):
        uri = urlsplit(self.redirect_uri)
        local = uri.scheme == "http" and uri.hostname in {"localhost", "127.0.0.1", "::1"}
        if (not self.client_id.endswith(".apps.googleusercontent.com") or not self.client_secret
                or len(self.client_id) > 512 or len(self.client_secret) > 8192
                or (uri.scheme != "https" and not local) or not uri.hostname
                or uri.username or uri.password or uri.query or uri.fragment
                or uri.path != "/gcp/oauth/callback"):
            raise GcpAuthError("GCP_OAUTH_SETUP_REQUIRED")
        return self

    def authorization_url(self, state, verifier, *, cloud_access=True):
        self.validate()
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode({
            "client_id": self.client_id, "redirect_uri": self.redirect_uri, "response_type": "code",
            "scope": " ".join(SCOPES if cloud_access else SCOPES[:2]), "access_type": "offline", "prompt": "consent select_account",
            "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
        })


def _retry_after(response):
    """Seconds from a numeric Retry-After header, or None (an HTTP-date form is ignored)."""
    try:
        seconds = float(response.headers.get("retry-after", ""))
    except ValueError:
        return None
    return seconds if math.isfinite(seconds) and seconds > 0 else None


def _json(client, method, url, **kwargs):
    try:
        response = bounded_request(client, method, url, max_response_bytes=1 << 20,
                                   timeout=20.0, follow_redirects=False, **kwargs)
    except HTTPResponseTooLarge:
        raise GcpAuthError("GCP_OAUTH_RESPONSE_INVALID") from None
    except (httpx.HTTPError, OSError):
        # Unreachable or interrupted: transient (TRANSIENT_AUTH_CODES), so a refresh waits and retries.
        raise GcpAuthError("GCP_OAUTH_NETWORK_OR_RESPONSE_FAILED") from None
    if response.status_code == 429 or response.status_code >= 500:
        # Google asked to wait or failed on its side. Checked before the body, which a 5xx page need not
        # carry as JSON, and Retry-After is kept so a waiting worker honors it (review 2026-09-26).
        raise GcpAuthError("GCP_OAUTH_RATE_LIMITED" if response.status_code == 429
                           else "GCP_OAUTH_TEMPORARILY_UNAVAILABLE", retry_after=_retry_after(response))
    try:
        body = response.json()
    except ValueError:
        raise GcpAuthError("GCP_OAUTH_RESPONSE_INVALID") from None
    if not isinstance(body, dict):
        raise GcpAuthError("GCP_OAUTH_RESPONSE_INVALID")
    if response.status_code != 200:
        error = body.get("error") if isinstance(body.get("error"), str) else ""
        if error == "invalid_grant":
            raise GcpAuthError("GCP_OAUTH_REAUTH_REQUIRED")
        if error in {"invalid_client", "unauthorized_client"}:
            raise GcpAuthError("GCP_OAUTH_SETUP_REQUIRED")
        code = {401: "GCP_OAUTH_REAUTH_REQUIRED",
                403: "GCP_PERMISSION_DENIED_OR_API_DISABLED"}.get(response.status_code, "GCP_OAUTH_REQUEST_FAILED")
        raise GcpAuthError(code)
    return body


def _text(body, name, maximum=8192):
    value = body.get(name)
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(c) < 32 for c in value):
        raise GcpAuthError("GCP_OAUTH_RESPONSE_INVALID")
    return value


def exchange(config, code, verifier, client, *, cloud_access=True):
    config.validate()
    body = _json(client, "POST", TOKEN_URL, data={"grant_type": "authorization_code", "code": code,
        "client_id": config.client_id, "client_secret": config.client_secret,
        "redirect_uri": config.redirect_uri, "code_verifier": verifier})
    token = _text(body, "access_token")
    if _text(body, "token_type", 32).lower() != "bearer":
        raise GcpAuthError("GCP_OAUTH_RESPONSE_INVALID")
    scopes = set(_text(body, "scope").split())
    if (cloud_access and SCOPES[2] not in scopes) or not scopes.intersection({"email", "https://www.googleapis.com/auth/userinfo.email"}):
        raise GcpAuthError("GCP_OAUTH_SCOPE_REQUIRED")
    if not body.get("refresh_token"):
        raise GcpAuthError("GCP_OAUTH_OFFLINE_ACCESS_REQUIRED")
    refresh = _text(body, "refresh_token")
    identity = _json(client, "GET", "https://openidconnect.googleapis.com/v1/userinfo",
                     headers={"Authorization": "Bearer " + token})
    subject, email = _text(identity, "sub", 255), _text(identity, "email", 320)
    if identity.get("email_verified") is not True or "@" not in email:
        raise GcpAuthError("GCP_OAUTH_IDENTITY_UNVERIFIED")
    return {"client_id": config.client_id, "client_secret": config.client_secret,
            "refresh_token": refresh, "auth_kind": "google_oauth"}, {"subject": subject, "email": email}


def oauth_token(fields, *, client_factory=None, clock=time.monotonic):
    """Per-job token source. No ambient ADC fallback and no global token cache.

    A scan's concurrent readers refresh one at a time: those that waited take the
    token just received, and a refused answer never replaces the kept one.
    """
    for name in ("client_id", "client_secret", "refresh_token"):
        _text(fields, name)
    token, expiry = "", 0.0
    lock = threading.Lock()

    def read():
        nonlocal token, expiry
        with lock:
            if token and clock() < expiry:
                return token
            factory = client_factory or (lambda: httpx.Client(timeout=20.0, follow_redirects=False))
            with factory() as client:
                body = _json(client, "POST", TOKEN_URL, data={"grant_type": "refresh_token",
                    **{name: fields[name] for name in ("client_id", "client_secret", "refresh_token")}})
            fresh = _text(body, "access_token")
            duration = body.get("expires_in")
            if _text(body, "token_type", 32).lower() != "bearer" or type(duration) is not int or not 0 < duration <= 86400:
                raise GcpAuthError("GCP_OAUTH_RESPONSE_INVALID")
            token, expiry = fresh, clock() + max(0, duration - 60)
            return token

    return read


def projects(fields, client, *, page_token=""):
    token = oauth_token(fields, client_factory=lambda: _Borrowed(client))()
    body = _json(client, "GET", "https://cloudresourcemanager.googleapis.com/v3/projects:search",
                 params={"pageSize": 100, "pageToken": page_token}, headers={"Authorization": "Bearer " + token})
    items = body.get("projects", [])
    if not isinstance(items, list) or len(items) > 100:
        raise GcpAuthError("GCP_OAUTH_RESPONSE_INVALID")
    rows = []
    for item in items:
        if not isinstance(item, dict) or not PROJECT.fullmatch(str(item.get("projectId", ""))):
            raise GcpAuthError("GCP_OAUTH_RESPONSE_INVALID")
        if item.get("state") == "ACTIVE":
            rows.append({"project_id": item["projectId"], "name": str(item.get("displayName", ""))[:200]})
    next_token = body.get("nextPageToken", "")
    if not isinstance(next_token, str) or len(next_token) > 4096:
        raise GcpAuthError("GCP_OAUTH_RESPONSE_INVALID")
    return {"items": rows, "next_page_token": next_token}


class _Borrowed:
    def __init__(self, client):
        self.client = client

    def __enter__(self):
        return self.client

    def __exit__(self, *_):
        pass
