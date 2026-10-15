"""Host-aware GitHub reads and per-scope installation tokens.

The teammate's Enterprise gateway pinned api.github.com and carried its own
session; this uses the product's host resolution and bounded HTTP client so a
GHES or ghe.com connection reads metadata through the same path its content
scan already uses. A failure keeps a fixed code: no response body, URL or token.
"""

from __future__ import annotations

import time
from email.utils import parsedate_to_datetime

from cremore.http_client import HTTPResponseTooLarge, bounded_request
from cremore_github_provider.github_auth import (
    GitHubAppTokenSource,
    GitHubAuthError,
    app_assertion,
    app_identity,
)
from cremore_github_provider.github_hosts import api_base, normalize_host

from . import API_VERSION, SERVER_API_VERSION
from .endpoints import EndpointError, validate_operation
from .projection import diagnostic_headers, installation_info, slug

KEPT_HEADERS = {"link", "x-github-request-id", "x-accepted-github-permissions",
                "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after"}
RETRYABLE = {"github_rate_limited", "github_unavailable"}


class SourceError(Exception):
    """A sanitized provider failure with an optional retry delay."""

    def __init__(self, code, *, status=0, retry_after=None):
        super().__init__(code)
        self.code, self.status, self.retry_after = code, status, retry_after


class Budget(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def retry_delay(headers, *, max_seconds=3600):
    delay = 60
    value = headers.get("retry-after", "")
    try:
        delay = max(delay, int(value))
    except (ValueError, TypeError):
        try:
            delay = max(delay, int(parsedate_to_datetime(value).timestamp() - time.time()) + 1)
        except (ValueError, TypeError, OverflowError):
            pass
    try:
        delay = max(delay, int(headers.get("x-ratelimit-reset", "0")) - int(time.time()) + 5)
    except (ValueError, TypeError):
        pass
    return min(delay, max_seconds)


class Transport:
    """Documented GETs plus the one token POST, under one shared budget."""

    def __init__(self, client, *, origin, options, max_requests, enterprise="", check=None,
                 sleep=time.sleep):
        self.client = client
        host = normalize_host(origin)
        self.api = api_base(host)
        # GHES 3.20 and earlier answer 400 to 2026-03-10; that version only removes fields we never read.
        self.version = API_VERSION if not host or host.endswith(".ghe.com") else SERVER_API_VERSION
        self.options = options
        self.max_requests = max_requests
        self.enterprise = enterprise
        self.check = check or (lambda: None)
        self.sleep = sleep
        self.requests = 0
        self._next_slot = 0.0

    def _charge(self):
        self.check()
        if self.requests >= self.max_requests:
            raise Budget("REQUEST_BUDGET_EXCEEDED")
        self.requests += 1

    def _pace(self):
        now = time.monotonic()
        interval = 1.0 / self.options.requests_per_second
        earliest = self._next_slot - interval * self.options.burst
        if now < earliest:
            self.wait(earliest - now)
            now = time.monotonic()
        self._next_slot = max(now, self._next_slot) + interval

    def wait(self, seconds):
        remaining = seconds
        while remaining > 0:
            self.check()
            step = min(remaining, 1.0)
            self.sleep(step)
            remaining -= step

    def request(self, method, path, bearer, *, json=None):
        response, headers = self.response(method, path, bearer, json=json)
        try:
            payload = response.json()
        except ValueError:
            raise SourceError("github_invalid_response") from None
        return payload, {key: value for key, value in headers.items()
                         if key in KEPT_HEADERS or key.startswith("x-github-enterprise-")}

    def response(self, method, path, bearer, *, json=None, export=False):
        """Bounded authenticated API response; signed download URLs never become metadata."""
        safe = validate_operation(method, path, enterprise=self.enterprise, allow_export_create=export)
        del safe
        self._charge()
        self._pace()
        try:
            response = bounded_request(
                self.client, method, self.api + path,
                headers={"Authorization": "Bearer " + bearer,
                         "Accept": "application/vnd.github+json",
                         "X-GitHub-Api-Version": self.version,
                         "User-Agent": "CreMore-Coverage/1.0"},
                json=json, timeout=self.options.timeout_seconds, follow_redirects=False,
                max_response_bytes=self.options.max_response_bytes)
        except HTTPResponseTooLarge:
            raise SourceError("github_response_limit") from None
        except Budget:
            raise
        except Exception:  # noqa: BLE001 -- transport errors can embed token-bearing URLs.
            raise SourceError("github_unavailable") from None
        status = response.status_code
        headers = {key.lower(): value for key, value in (response.headers or {}).items()}
        ready = export and method == "GET" and status == 302 and path.startswith(
            f"/enterprises/{self.enterprise}/credentials/exports/")
        if not 200 <= status < 300 and not ready:
            limited = status == 429 or (
                status == 403 and ("retry-after" in headers
                                   or headers.get("x-ratelimit-remaining") == "0"))
            raise SourceError(
                "github_rate_limited" if limited
                else "github_unavailable" if status >= 500
                else "github_http_" + str(status),
                status=status, retry_after=retry_delay(headers, max_seconds=604800 if export else 3600) if limited else None)
        return response, headers


class TokenBroker:
    """One installation token per scope, discovered and verified before use."""

    def __init__(self, transport, *, app_id, private_key, client_factory, enterprise="",
                 installation_id=None, now=None):
        self.transport = transport
        # The configured JWT issuer: a numeric App ID or the App's Client ID.
        self.app_id = str(app_id)
        self._app = None
        self.private_key = private_key
        self.client_factory = client_factory
        self.enterprise = enterprise
        self.installation_id = installation_id
        self.now = now
        self._sources = {}
        self._refused = {}
        self._discovered = []

    def token_for(self, scope, name=""):
        key = (scope, (name or "").lower())
        if key in self._refused:
            raise SourceError(self._refused[key])
        if key not in self._sources:
            self._sources[key] = self._source(scope, name, key)
        try:
            return self._sources[key]()
        except GitHubAuthError as error:
            raise SourceError("installation_token_" + error.code.lower()) from None

    def app_jwt(self):
        """The App JWT for reads about the App itself (its identity and installations)."""
        try:
            return app_assertion(self.app_id, self.private_key, now=self.now)
        except GitHubAuthError as error:
            raise SourceError(error.code.lower()) from None

    def app(self):
        """GET /app once per run: the App the key signs for, checked against the configured ID."""
        if self._app is None:
            raw, _headers = self.transport.request("GET", "/app", self.app_jwt())
            try:
                self._app = app_identity(raw, self.app_id)
            except GitHubAuthError as error:
                raise SourceError(error.code.lower()) from None
        return self._app

    def _app_number(self):
        """Installations name the numeric App ID; a Client ID is resolved through GET /app."""
        return self.app_id if self.app_id.isdecimal() else str(self.app()["id"])

    def _source(self, scope, name, key):
        installation = self.installation_id if scope == "installation" else self._discover(
            scope, name, key)
        # A collection reads: its token holds read access whatever else the App may do. An enterprise installation's
        # token still holds all of its permissions: the token request's documented permissions are organization and
        # repository ones, and whether GitHub takes enterprise ones at read is not confirmed.
        return GitHubAppTokenSource(self.client_factory, self.app_id, installation,
                                    self.private_key, base_url=self.transport.api, close_client=False,
                                    read_only=scope != "enterprise", **({"now": self.now} if self.now else {}))

    def _discover(self, scope, name, key):
        return self.installation_for(scope, name)["id"]

    def installation_for(self, scope, name=""):
        """Verified installation metadata, also used by read-only onboarding checks."""
        key = (scope, (name or "").lower())
        assertion = self.app_jwt()
        path = (f"/enterprises/{slug(self.enterprise)}/installation" if scope == "enterprise"
                else f"/orgs/{slug(name)}/installation")
        try:
            raw, _headers = self.transport.request("GET", path, assertion)
        except SourceError as error:
            if error.code in ("github_http_403", "github_http_404"):
                self._refused[key] = (
                    "enterprise" if scope == "enterprise" else "organization"
                ) + "_installation_" + error.code
                raise SourceError(self._refused[key]) from None
            raise
        info = installation_info(raw)
        expected = "Enterprise" if scope == "enterprise" else "Organization"
        owner = self.enterprise if scope == "enterprise" else name
        if (info["target_type"] != expected
                or info["account_login"].lower() != owner.lower()
                or str(info["app_id"]) != self._app_number()):
            raise SourceError("installation_not_authorized")
        # This App's installation there -- its permissions and any suspension --
        # is evidence for the organization view whether or not a token follows.
        self._discovered.append((scope, owner, info))
        if info["suspended_at"]:
            self._refused[key] = ("enterprise" if scope == "enterprise" else "organization") + "_installation_suspended"
            raise SourceError(self._refused[key])
        return info

    def discovered(self):
        """Installations looked up since the last call, recorded with the page that needed them."""
        found, self._discovered = self._discovered, []
        return found

    def refused(self):
        """Scopes the App is not installed on, so a restart does not retry them."""
        return {key[0] + "|" + key[1]: value for key, value in self._refused.items()}

    def restore(self, refused):
        for key, value in (refused or {}).items():
            parts = key.split("|", 1)
            if len(parts) == 2 and isinstance(value, str):
                self._refused[(parts[0], parts[1])] = value

    def close(self):
        self._sources.clear()


def page_headers(headers):
    return diagnostic_headers(headers)


def endpoint_error(error):
    return str(error) if isinstance(error, EndpointError) else "invalid_page_data"
