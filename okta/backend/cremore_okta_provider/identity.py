"""Okta Users API read with a service app's private_key_jwt token holding okta.users.read alone.

One listing covers every status: a status filter is the documented way to include
DEPROVISIONED users, which the unfiltered list leaves out. ``statusChanged`` is when
the current status began, so a deactivated or suspended user carries the time it
happened. When the service app requires DPoP, the token request and every API call
carry a proof signed with a key made for this run (RFC 9449); the first answer that
asks for DPoP or a nonce switches to it.

The organization's app list (``options.sources == ["apps"]``, its own collection so a missing grant never makes the
people listing partial) is read with a token holding only ``okta.apps.read``: the Apps API listed once per status
(ACTIVE, INACTIVE), and of each app only its id, label, catalog name and status are kept. That scope also opens
``/api/v1/apps/{id}/credentials/secrets``, which is never called.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import uuid
from urllib.parse import parse_qs, urlsplit

import jwt

from cremore.http_client import HTTPResponseTooLarge, bounded_request
from cremore.identity.idp import App, ReadError, Source, User, apps_only, status_error, utc_text

PROVIDER = "okta"
API_VERSION = "v1"
CONTRACT_VERSION = "okta-users-v1"
SCOPE = "okta.users.read"
APPS_SCOPE = "okta.apps.read"
USER_ID = re.compile(r"[0-9A-Za-z]{10,32}")
APP_ID = USER_ID
APP_KEY = "app_slug"  # the catalog (OIN) name an app integration was added from: slack, amazon_aws
KEY_KINDS = frozenset({"IDP_USER_ID", "LOGIN", "EMAIL"})
STATUSES = ("STAGED", "PROVISIONED", "ACTIVE", "RECOVERY", "PASSWORD_EXPIRED", "LOCKED_OUT", "SUSPENDED",
            "DEPROVISIONED")
# Suspended keeps the account but blocks every app; deactivated removes all app
# assignments. Both are the departure signals the design names.
STATE = {"STAGED": "PENDING", "PROVISIONED": "PENDING", "ACTIVE": "ACTIVE", "RECOVERY": "ACTIVE",
         "PASSWORD_EXPIRED": "ACTIVE", "LOCKED_OUT": "ACTIVE", "SUSPENDED": "DISABLED", "DEPROVISIONED": "DISABLED"}
FILTER = " or ".join(f'status eq "{status}"' for status in STATUSES)
# The Apps API takes one status expression at a time; the app list reads each status it keeps.
APP_STATUS = {"apps": ("ACTIVE", "ACTIVE"), "inactive_apps": ("INACTIVE", "DISABLED")}
SOURCES = (Source("users", "users", completes=True, enabled=lambda spec: not apps_only(spec)),
           Source("apps", "apps", enabled=apps_only), Source("inactive_apps", "apps", enabled=apps_only))
# The client assertion algorithms Okta accepts for private_key_jwt.
_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512")
_HOST =re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")


def validate_spec(spec):
    host = urlsplit(spec.origin).hostname or ""
    if spec.edition != "cloud" or not _HOST.fullmatch(host) or urlsplit(spec.origin).port not in (None, 443):
        raise ValueError("OKTA_ORG_ORIGIN_REQUIRED")
    if spec.tenant != host or not spec.tenant_confirmed:
        raise ValueError("OKTA_TENANT_IS_THE_ORG_HOST")
    if len(spec.scopes) != 1 or spec.scopes[0].kind != "organization" or spec.scopes[0].id != host:
        raise ValueError("OKTA_ONE_ORGANIZATION_SCOPE")
    if spec.auth_type != "private_key_jwt" or set(spec.secret_refs) != {"client_id", "private_key"}:
        raise ValueError("OKTA_SERVICE_APP_PRIVATE_KEY_JWT_REQUIRED")
    if (spec.options.include_audit_events or spec.options.mode != "inventory" or spec.options.page_size > 200
            or spec.options.sources not in ([], ["apps"]) or (apps_only(spec) and spec.options.keep_profiles)):
        raise ValueError("OKTA_COLLECTION_OPTION_NOT_SUPPORTED")


def user(spec, source, row):
    if not isinstance(row, dict) or not isinstance(row.get("id"), str) or row.get("status") not in STATE:
        raise ValueError("OKTA_INVALID_USER")
    profile = row.get("profile") if isinstance(row.get("profile"), dict) else {}
    keys = tuple((kind, profile[name]) for kind, name in (("LOGIN", "login"), ("EMAIL", "email"))
                 if isinstance(profile.get(name), str) and profile[name])
    name = profile.get("displayName") or " ".join(
        part for part in (profile.get("firstName"), profile.get("lastName")) if isinstance(part, str) and part)
    details = tuple((field, value) for field, value in (("display_name", name), ("email", profile.get("email")),
                                                        ("department", profile.get("department")),
                                                        ("title", profile.get("title")))
                    if isinstance(value, str) and value)
    return User(id=row["id"], raw_state=row["status"], state=STATE[row["status"]],
                changed_at=utc_text(row.get("statusChanged")), keys=keys, profile=details)


def event(spec, source, row):  # Okta keeps its status time on the user itself
    return None


def app(spec, source, row):
    """An app integration as its label, catalog name (``slack``, ``amazon_aws``) and status; its credentials and
    settings are never read out of the row."""
    if not isinstance(row, dict) or not isinstance(row.get("id"), str) or row.get("status") != APP_STATUS[source][0]:
        raise ValueError("OKTA_INVALID_APP")
    label = row.get("label") if isinstance(row.get("label"), str) else ""
    if not label:
        return None
    key = row.get("name") if isinstance(row.get("name"), str) else ""
    return App(id=row["id"], raw_state=row["status"], state=APP_STATUS[source][1], name=label, key=key)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def signing_key(value):
    """The service app key: a PEM private key, or a JWK (JSON) that may carry its kid."""
    if not isinstance(value, str) or not value or len(value) > 32768:
        raise ValueError("OKTA_PRIVATE_KEY_INVALID")
    text = value.strip()
    try:
        if text.startswith("{"):
            # PyJWK takes "alg" from the JWK, or infers it from the key type and curve.
            jwk = jwt.PyJWK(json.loads(text))
            if jwk.algorithm_name not in _ALGORITHMS or not hasattr(jwk.key, "sign"):
                raise ValueError
            return jwk.key, jwk.algorithm_name, jwk.key_id
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(text.encode(), password=None)
    except Exception:  # noqa: BLE001 -- key parsing errors can quote the key
        raise ValueError("OKTA_PRIVATE_KEY_INVALID") from None
    if isinstance(key, rsa.RSAPrivateKey):
        return key, "RS256", None
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key, {256: "ES256", 384: "ES384", 521: "ES512"}[key.curve.key_size], None
    raise ValueError("OKTA_PRIVATE_KEY_INVALID")


class _Proof:
    """A DPoP key made for one run; only its public half ever leaves the process."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import rsa

        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = self.key.public_key().public_numbers()
        self.jwk = {"kty": "RSA", "e": _b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
                    "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big"))}
        self.nonce = None

    def __call__(self, method, url, token=None):
        claims = {"htm": method, "htu": url.split("?", 1)[0], "iat": int(time.time()), "jti": str(uuid.uuid4())}
        if self.nonce:
            claims["nonce"] = self.nonce
        if token:
            claims["ath"] = _b64(hashlib.sha256(token.encode()).digest())
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"typ": "dpop+jwt", "jwk": self.jwk})


class Reader:
    def __init__(self, spec, secrets, client, pacer):
        self.spec, self.client, self.pacer = spec, client, pacer
        self.origin = spec.origin
        self.token_url = self.origin + "/oauth2/v1/token"
        self.client_id = secrets.get("client_id", "")
        self.key = secrets.get("private_key", "")
        self.token, self.expires, self.proof = None, 0.0, None
        self.scope = APPS_SCOPE if apps_only(spec) else SCOPE  # each collection's token holds its one scope

    @property
    def requests(self):
        return self.pacer.requests

    def close(self):
        self.token = self.key = None

    def _post_token(self):
        key, algorithm, kid = signing_key(self.key)
        now = int(time.time())
        assertion = jwt.encode({"iss": self.client_id, "sub": self.client_id, "aud": self.token_url, "iat": now,
                                "exp": now + 300, "jti": str(uuid.uuid4())}, key, algorithm=algorithm,
                               headers={"kid": kid} if kid else None)
        form = {"grant_type": "client_credentials", "scope": self.scope,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion}
        headers = {"Accept": "application/json"}
        if self.proof:
            headers["DPoP"] = self.proof("POST", self.token_url)
        self.pacer.before()
        try:
            return bounded_request(self.client, "POST", self.token_url, data=form, headers=headers,
                                   timeout=self.spec.options.timeout_seconds, follow_redirects=False,
                                   max_response_bytes=64 << 10)
        except Exception:  # noqa: BLE001 -- transport errors can carry the assertion
            raise ReadError("OKTA_TOKEN_UNAVAILABLE", retryable=True) from None

    def _authenticate(self):
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", self.client_id or ""):
            raise ReadError("OKTA_CLIENT_ID_INVALID")
        try:
            signing_key(self.key)
        except ValueError:
            raise ReadError("OKTA_PRIVATE_KEY_INVALID") from None
        for _attempt in range(3):
            response = self._post_token()
            if response.status_code == 200:
                break
            error = ""
            try:
                error = response.json().get("error", "")
            except (ValueError, AttributeError):
                pass
            if response.status_code == 400 and error in ("invalid_dpop_proof", "use_dpop_nonce"):
                self.proof = self.proof or _Proof()
                nonce = response.headers.get("dpop-nonce")
                if error == "use_dpop_nonce" and not nonce:
                    raise ReadError("OKTA_DPOP_NONCE_MISSING")
                self.proof.nonce = nonce if isinstance(nonce, str) and len(nonce) <= 512 else self.proof.nonce
                continue
            if response.status_code in (429, 408) or response.status_code >= 500:
                raise status_error("OKTA_TOKEN", response)
            raise ReadError("OKTA_TOKEN_REFUSED")
        else:
            raise ReadError("OKTA_TOKEN_REFUSED")
        try:
            payload = response.json()
            token, kind = payload["access_token"], str(payload.get("token_type", "Bearer"))
            lifetime = int(payload.get("expires_in", 3600))
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ReadError("OKTA_TOKEN_REFUSED") from None
        if not isinstance(token, str) or not token or any(not 33 <= ord(c) <= 126 for c in token):
            raise ReadError("OKTA_TOKEN_REFUSED")
        if (kind.lower() == "dpop") != bool(self.proof):
            raise ReadError("OKTA_TOKEN_TYPE_UNEXPECTED")
        self.token, self.expires = token, time.monotonic() + max(60, lifetime) - 60

    def read(self, scope, source, cursor):
        if (source not in ("users", *APP_STATUS) or scope not in self.spec.scopes
                or (source != "users") != apps_only(self.spec)):
            raise ValueError("OKTA_OPERATION_OUT_OF_SCOPE")
        if self.token is None or time.monotonic() >= self.expires:
            self._authenticate()
        path = "/api/v1/users" if source == "users" else "/api/v1/apps"
        url = self.origin + path
        users = source == "users"
        params = {"filter": FILTER if users else f'status eq "{APP_STATUS[source][0]}"',
                  "limit": self.spec.options.page_size}
        if cursor:
            params["after"] = cursor
        for _attempt in range(2):
            headers = {"Accept": "application/json", "User-Agent": "CreMore-Identity/1.0"}
            if users:
                headers["Content-Type"] = "application/json; okta-response=omitCredentials"
            if self.proof:
                headers["Authorization"] = "DPoP " + self.token
                headers["DPoP"] = self.proof("GET", url, self.token)
            else:
                headers["Authorization"] = "Bearer " + self.token
            self.pacer.before()
            try:
                response = bounded_request(self.client, "GET", url, params=params, headers=headers,
                                           timeout=self.spec.options.timeout_seconds, follow_redirects=False,
                                           max_response_bytes=self.spec.options.max_response_bytes)
            except HTTPResponseTooLarge:
                raise ReadError("OKTA_RESPONSE_LIMIT") from None
            except Exception:  # noqa: BLE001 -- transport errors can carry the bearer
                raise ReadError("OKTA_UNAVAILABLE", retryable=True) from None
            nonce = response.headers.get("dpop-nonce")
            if (response.status_code == 401 and self.proof and nonce and len(nonce) <= 512
                    and "use_dpop_nonce" in response.headers.get("www-authenticate", "")):
                self.proof.nonce = nonce
                continue
            break
        if response.status_code != 200:
            raise status_error("OKTA", response)
        try:
            rows = response.json()
        except (ValueError, RecursionError):
            raise ReadError("OKTA_INVALID_RESPONSE") from None
        if not isinstance(rows, list) or len(rows) > self.spec.options.page_size:
            raise ReadError("OKTA_INVALID_RESPONSE")
        return rows, next_cursor(response.headers.get_list("link") if hasattr(response.headers, "get_list")
                                 else [response.headers.get("link", "")], self.origin, path)


def next_cursor(links, origin, path="/api/v1/users"):
    """The ``after`` of a rel="next" Link on this org's listing path; anything else is refused."""
    for header in links:
        for part in (header or "").split(","):
            match = re.fullmatch(r'\s*<([^>]{1,8192})>\s*;\s*rel="next"\s*', part)
            if not match:
                continue
            target, base = urlsplit(match.group(1)), urlsplit(origin)
            if (target.scheme != "https" or target.hostname != base.hostname or target.port not in (None, 443)
                    or target.path != path or target.username or target.password or target.fragment):
                raise ReadError("OKTA_INVALID_CURSOR")
            after = parse_qs(target.query).get("after", [])
            if len(after) != 1:
                raise ReadError("OKTA_INVALID_CURSOR")
            return after[0]
    return ""


def reader(spec, secrets, client, pacer):
    return Reader(spec, secrets, client, pacer)
