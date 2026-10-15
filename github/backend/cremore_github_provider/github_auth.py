"""Short-lived GitHub App installation-token authentication."""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import re
import threading
from collections.abc import Callable
from contextlib import ExitStack

import jwt

from cremore.http_client import bounded_request

_API = "https://api.github.com"
_PRIVATE_KEY_MAX_BYTES = 64 << 10
_TOKEN_MAX_CHARS = 8192
_REFRESH_SKEW = dt.timedelta(seconds=120)
# Installation-token permissions that have no read level (REST 2022-11-28, "Create an installation access token for
# an app", checked 2026-09-30: workflows, profile), and Copilot seat management, which earlier schemas list as write
# only and CreMore never reads: a read-only token leaves them out.
_WRITE_ONLY = frozenset({"workflows", "profile", "organization_copilot_seat_management"})


def readable(held: dict) -> dict:
    """What a read-only token asks for: every held permission that has a read level, at read."""
    return {name: "read" for name, level in held.items()
            if isinstance(name, str) and level in ("read", "write", "admin") and name not in _WRITE_ONLY}


class GitHubAuthError(RuntimeError):
    """A safe GitHub App authentication error code (never secret material)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _positive_id(value: object, name: str) -> str:
    text = str(value or "").strip()
    if not re.fullmatch(r"[1-9][0-9]{0,19}", text):
        raise GitHubAuthError(f"GITHUB_APP_{name}_INVALID")
    return text


# GitHub accepts either identifier as an App JWT's issuer: the numeric App ID or
# the App's Client ID, "Iv1." plus hex or "Iv23" plus letters and digits (REST
# docs, "Generating a JSON Web Token for a GitHub App"). The dotted form is valid.
_CLIENT_ID = re.compile(r"Iv(?:[0-9A-Za-z]{3,126}|[0-9A-Za-z]{1,8}\.[0-9A-Za-z]{3,100})")


def app_issuer(value: object) -> str:
    """The App JWT issuer: a numeric App ID or a Client ID, nothing else."""
    text = str(value or "").strip()
    if re.fullmatch(r"[1-9][0-9]{0,19}", text) or _CLIENT_ID.fullmatch(text):
        return text
    raise GitHubAuthError("GITHUB_APP_ID_INVALID")


def app_identity(body: object, issuer: object) -> dict:
    """GET /app's answer, checked against the configured issuer.

    It is the App the key signs for: its numeric id (what installations name),
    Client ID, slug, name, owner and the permissions it asks installations for.
    The configured App ID or Client ID must be this App's, or nothing is trusted.
    """
    expected = app_issuer(issuer)
    if not isinstance(body, dict) or type(body.get("id")) is not int or body["id"] < 1:
        raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED")
    if expected not in (str(body["id"]), body.get("client_id")):
        raise GitHubAuthError("GITHUB_APP_IDENTITY_MISMATCH")
    owner, permissions = body.get("owner"), body.get("permissions")
    if not isinstance(owner, dict) or not isinstance(permissions, dict):
        raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED")

    def text(value, limit):
        return value if isinstance(value, str) and 0 < len(value) <= limit and value.isprintable() else None

    return {"id": body["id"], "client_id": text(body.get("client_id"), 128),
            "slug": text(body.get("slug"), 100), "name": text(body.get("name"), 200),
            "owner": text(owner.get("login") or owner.get("slug"), 100), "owner_type": text(owner.get("type"), 32),
            "permissions": {name: level for name, level in sorted(permissions.items())
                            if text(name, 100) and text(level, 32)}}


def _private_key(value: object) -> bytes:
    encoded = str(value or "").strip()
    if not encoded or len(encoded) > (_PRIVATE_KEY_MAX_BYTES * 2):
        raise GitHubAuthError("GITHUB_APP_PRIVATE_KEY_INVALID")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise GitHubAuthError("GITHUB_APP_PRIVATE_KEY_INVALID") from None
    if not decoded or len(decoded) > _PRIVATE_KEY_MAX_BYTES or b"PRIVATE KEY" not in decoded:
        raise GitHubAuthError("GITHUB_APP_PRIVATE_KEY_INVALID")
    return decoded


# What a connection stores for a GitHub App, under the names the worker already
# looks for when it resolves a secret_ref (cremore.secretstore.resolver).
APP_FIELDS = ("GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY_BASE64")


def github_app_fields(value: object) -> dict:
    """The three values of a GitHub App, checked before anything stores them.

    Checked here rather than at first use because the operator is still at the
    form: a PEM pasted with a missing line is worth refusing now, not at the
    next scan. The private key is validated by decoding it, never by logging it.
    """
    if not isinstance(value, dict):
        raise GitHubAuthError("GITHUB_APP_FIELDS_INVALID")
    unknown = set(value) - set(APP_FIELDS)
    if unknown:
        raise GitHubAuthError("GITHUB_APP_FIELDS_INVALID")
    app_id, installation_id, key = (value.get(name) for name in APP_FIELDS)
    fields = {
        "GITHUB_APP_ID": app_issuer(app_id),
        "GITHUB_APP_INSTALLATION_ID": _positive_id(installation_id, "INSTALLATION_ID"),
    }
    _private_key(key)  # decodes and checks it is a PEM; the decoded key is not kept
    fields["GITHUB_APP_PRIVATE_KEY_BASE64"] = str(key).strip()
    return fields


def _utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.UTC)
    return value.astimezone(dt.UTC)


def _expiry(value: object) -> dt.datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED") from None
    if parsed.tzinfo is None:
        raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED")
    return parsed.astimezone(dt.UTC)


def app_assertion(app_id: object, private_key_base64: object, *, now=None) -> str:
    """The App JWT used to discover an installation before a token is issued.

    Installation-token issuance stays in GitHubAppTokenSource. This exists only
    so a caller that must first ask which installation serves an organization
    uses the same key handling and the same claim window as that source.
    """
    moment = _utc(now() if callable(now) else dt.datetime.now(dt.UTC))
    try:
        return jwt.encode(
            {"iat": int(moment.timestamp()) - 60, "exp": int(moment.timestamp()) + 540,
             "iss": app_issuer(app_id)},
            _private_key(private_key_base64),
            algorithm="RS256",
        )
    except GitHubAuthError:
        raise
    except Exception:  # noqa: BLE001 - PyJWT/crypto expose several backend exceptions
        raise GitHubAuthError("GITHUB_APP_PRIVATE_KEY_INVALID") from None


class GitHubAppTokenSource:
    """Issue and cache an installation token, refreshing shortly before expiry."""

    def __init__(
        self,
        client_factory: Callable[[], object],
        app_id: object,
        installation_id: object,
        private_key_base64: object,
        *,
        base_url: str = _API,
        now: Callable[[], dt.datetime] | None = None,
        close_client: bool = True,
        permissions: dict | None = None,
        read_only: bool = False,
        organization: str | None = None,
    ) -> None:
        if not callable(client_factory):
            raise GitHubAuthError("GITHUB_APP_HTTP_CLIENT_UNAVAILABLE")
        self._client_factory = client_factory
        self._close_client = close_client
        # A token for these permissions alone (GitHub refuses one the installation does not hold); None: all of them.
        self._requested = dict(permissions) if permissions else None
        # Scans and collections read: every permission the installation holds, at read, even when the App may write
        # (an App shared with a remediation connection revokes access with the same key).
        self._read_only = read_only and not self._requested
        self._app_id = app_issuer(app_id)
        self._installation_id = _positive_id(installation_id, "INSTALLATION_ID")
        if organization is not None and (not isinstance(organization, str)
                or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", organization)):
            raise GitHubAuthError("GITHUB_ORGANIZATION_INVALID")
        self._organization = organization
        self._private_key = _private_key(private_key_base64)
        self._base_url = base_url.rstrip("/")
        self._now = now or (lambda: dt.datetime.now(dt.UTC))
        # (token, expires_at), replaced as one value: a concurrent read never pairs a token with another's expiry.
        self._issued: tuple[str, dt.datetime] | None = None
        self._lock = threading.Lock()
        self._permissions: tuple[str, ...] = ()
        # What GET /app/installations/{id} said, when a read-only token asked it: the account it is installed on,
        # the numeric App ID and the permissions it holds.
        self.installation: dict | None = None

    def __call__(self) -> str:
        issued = self._issued
        if issued and _utc(self._now()) + _REFRESH_SKEW < issued[1]:
            return issued[0]
        with self._lock:
            # Scan readers that waited here take the token the first of them issued.
            now, issued = _utc(self._now()), self._issued
            if issued and now + _REFRESH_SKEW < issued[1]:
                return issued[0]
            return self._issue(now)

    def pacing_identity(self) -> str:
        """Whom GitHub counts this source's requests against: the App's installation, which every token the
        source mints shares. Requests are paced by it, as a digest, never by one token
        (cremore_github_provider.collectors.github.github_pacer)."""
        return f"app:{self._app_id}:installation:{self._installation_id}"

    def _app_request(self, now: dt.datetime, method: str, path: str, **kwargs):
        try:
            assertion = jwt.encode(
                {"iat": int(now.timestamp()) - 60, "exp": int(now.timestamp()) + 540,
                 "iss": self._app_id},
                self._private_key,
                algorithm="RS256",
            )
        except Exception:  # noqa: BLE001 - PyJWT/crypto expose several backend exceptions
            raise GitHubAuthError("GITHUB_APP_PRIVATE_KEY_INVALID") from None
        try:
            client = self._client_factory()
        except Exception:  # noqa: BLE001 - injected clients may fail with provider-specific types
            raise GitHubAuthError("GITHUB_APP_HTTP_CLIENT_UNAVAILABLE") from None
        try:
            with ExitStack() as cleanup:
                close = getattr(client, "close", None)
                if self._close_client and callable(close):
                    cleanup.callback(close)
                return bounded_request(
                    client, method, self._base_url + path,
                    headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {assertion}",
                             "X-GitHub-Api-Version": "2022-11-28"},
                    max_response_bytes=1 << 20, follow_redirects=False, **kwargs,
                )
        except Exception:  # noqa: BLE001 - transport adapters expose provider-specific types
            raise GitHubAuthError("GITHUB_APP_UNAVAILABLE") from None

    def identity(self) -> dict:
        """The App this key signs for (GET /app with the App JWT), checked against the configured ID."""
        response = self._app_request(_utc(self._now()), "GET", "/app")
        status = getattr(response, "status_code", 0)
        if status in (401, 403, 404):
            raise GitHubAuthError("GITHUB_APP_REJECTED")
        if status != 200:
            raise GitHubAuthError("GITHUB_APP_UNAVAILABLE")
        try:
            body = response.json()
        except ValueError:
            raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED") from None
        return app_identity(body, self._app_id)

    @property
    def holds_no_read(self) -> bool:
        """The installation answered and holds nothing a read-only token could ask for (a bare App)."""
        held = self.installation.get("permissions") if isinstance(self.installation, dict) else None
        return isinstance(held, dict) and not readable(held)

    def installation_info(self, now: dt.datetime | None = None) -> dict:
        """Resolve the selected organization's installation with this App's JWT on every token refresh."""
        path = (f"/orgs/{self._organization}/installation" if self._organization
                else f"/app/installations/{self._installation_id}")
        response = self._app_request(now or _utc(self._now()), "GET", path)
        status = getattr(response, "status_code", 0)
        if status in (401, 403, 404):
            raise GitHubAuthError("GITHUB_APP_REJECTED")
        if status != 200:
            raise GitHubAuthError("GITHUB_APP_UNAVAILABLE")
        try:
            body = response.json()
        except (KeyError, TypeError, ValueError):
            raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED") from None
        if not isinstance(body, dict):
            raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED")
        if self._organization:
            account = body.get("account")
            if (not isinstance(account, dict) or str(account.get("login", "")).lower() != self._organization.lower()
                    or body.get("target_type", account.get("type")) != "Organization"
                    or body.get("suspended_at") is not None):
                raise GitHubAuthError("GITHUB_APP_INSTALLATION_MISMATCH")
            if self._app_id.isdigit() and str(body.get("app_id")) != self._app_id:
                raise GitHubAuthError("GITHUB_APP_IDENTITY_MISMATCH")
            self._installation_id = _positive_id(body.get("id"), "INSTALLATION_ID")
        self.installation = body
        return body

    def _readable(self, now: dt.datetime) -> dict:
        """Every permission the installation holds, asked for at read."""
        held = self.installation_info(now).get("permissions")
        if not isinstance(held, dict):
            raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED")
        wanted = readable(held)
        if not wanted:
            raise GitHubAuthError("GITHUB_APP_REJECTED")  # an empty request would ask for every permission
        return wanted

    def _issue(self, now: dt.datetime) -> str:
        if self._organization and not self._read_only:
            self.installation_info(now)
        requested = self._readable(now) if self._read_only else self._requested
        response = self._app_request(now, "POST", f"/app/installations/{self._installation_id}/access_tokens",
                                     json={"permissions": requested} if requested else {})
        status = getattr(response, "status_code", 0)
        if status == 422 and self._read_only:
            # GitHub would not grant one of the held permissions at read: said as such, not as a removed App.
            raise GitHubAuthError("GITHUB_APP_READ_ONLY_REFUSED")
        if status in (401, 403, 404, 422):
            raise GitHubAuthError("GITHUB_APP_REJECTED")
        if status != 201:
            raise GitHubAuthError("GITHUB_APP_UNAVAILABLE")
        try:
            body = response.json()
            token = body["token"]
            expires_at = _expiry(body["expires_at"])
        except (KeyError, TypeError, ValueError, GitHubAuthError):
            raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED") from None
        if (
            not isinstance(token, str)
            or not token
            or len(token) > _TOKEN_MAX_CHARS
            or any(ch.isspace() or not ch.isprintable() for ch in token)
            or expires_at <= now
        ):
            raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED")
        permissions = body.get("permissions") or {}
        if self._read_only and (not isinstance(permissions, dict) or not permissions
                                or any(level != "read" for level in permissions.values())):
            raise GitHubAuthError("GITHUB_APP_TOKEN_NOT_READ_ONLY")  # never used; it lapses within the hour
        self._permissions = tuple(
            sorted(
                f"{key}:{value}"
                for key, value in permissions.items()
                if isinstance(key, str) and isinstance(value, str)
                and len(key) <= 100 and len(value) <= 32
            )
        ) if isinstance(permissions, dict) else ()
        self._issued = (token, expires_at)
        return token

    def evidence(self) -> dict:
        issued = self._issued
        return {
            "credential_mode": "GITHUB_APP",
            "refresh_supported": True,
            "expires_at": issued[1].isoformat() if issued else None,
        }

    def scopes(self) -> tuple[str, ...]:
        return self._permissions


GitHubToken = str | Callable[[], str]


def resolve_github_token(source: GitHubToken) -> str:
    value = source() if callable(source) else source
    if (
        not isinstance(value, str)
        or len(value) > _TOKEN_MAX_CHARS
        or (value and any(ch.isspace() or not ch.isprintable() for ch in value))
    ):
        raise GitHubAuthError("GITHUB_CREDENTIAL_INVALID")
    return value


def github_token_evidence(source: GitHubToken) -> dict:
    evidence = getattr(source, "evidence", None)
    value = evidence() if callable(evidence) else {}
    return value if isinstance(value, dict) else {}


def github_token_scopes(source: GitHubToken) -> tuple[str, ...]:
    scopes = getattr(source, "scopes", None)
    value = scopes() if callable(scopes) else ()
    return tuple(item for item in value if isinstance(item, str)) if isinstance(value, tuple) else ()
