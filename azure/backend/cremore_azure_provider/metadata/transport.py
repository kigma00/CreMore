"""Read-only Key Vault data-plane transport: pinned vault, charged budget.

Only the one vault a connection declares is reachable, and only its read
endpoints. A ``nextLink`` is a provider-supplied URL, so its cursor is copied
onto the pinned base rather than followed -- a redirected link would carry the
bearer token somewhere the operator never approved. No response body, URL or
token survives a failure: only a fixed code.
"""

from __future__ import annotations

import re
import time
from urllib.parse import parse_qs, urlsplit

from cremore.http_client import HTTPResponseTooLarge, bounded_request

# Key Vault's data plane is one host per vault. The public suffixes Microsoft
# documents are listed; a host outside this grammar is never requested.
VAULT_HOST = re.compile(
    r"(?P<vault>[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9])"
    r"\.vault\.(?:azure\.net|azure\.cn|usgovcloudapi\.net|microsoftazure\.de)"
)
# Value reads require a separately enabled transport capability.
PATHS = (
    re.compile(r"/secrets"),
    re.compile(r"/secrets/[A-Za-z0-9-]{1,127}/versions"),
    re.compile(r"/deletedsecrets"),
    re.compile(r"/(?:keys|certificates|deletedkeys|deletedcertificates)"),
    re.compile(r"/(?:keys|certificates)/[A-Za-z0-9-]{1,127}/versions"),
)
VALUE_PATH = re.compile(r"/secrets/[A-Za-z0-9-]{1,127}(?:/[A-Za-z0-9]{1,64})?")
CERTIFICATE_PATH = re.compile(r"/certificates/[A-Za-z0-9-]{1,127}(?:/[A-Za-z0-9]{1,64})?")
# Rate limiting or an unavailable provider is not a partial listing: the run
# keeps its cursor and waits instead of recording a smaller result.
DEFERRED = frozenset({"rate_limited", "rate_limit_circuit_open", "provider_unavailable"})
SCOPE = "https://vault.azure.net/.default"
_AUTHORITY_BY_SUFFIX = {
    "azure.net": "login.microsoftonline.com",
    "azure.cn": "login.chinacloudapi.cn",
    "usgovcloudapi.net": "login.microsoftonline.us",
    "microsoftazure.de": "login.microsoftonline.de",
}


class ApiError(Exception):
    """Sanitized HTTP failure: no response body, URL, or token is retained."""

    def __init__(self, code: str, *, retry_after: float | None = None):
        self.code = code
        self.retry_after = retry_after
        super().__init__(code)


class Budget(Exception):
    """A configured request, page or record ceiling was reached."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def vault_name(origin: str) -> str:
    """The vault a connection's origin names, or a refusal."""
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.query
            or parsed.fragment or parsed.path not in ("", "/") or parsed.port not in (None, 443)):
        raise ValueError("AZURE_KEY_VAULT_ORIGIN_REQUIRED")
    host = parsed.hostname or ""
    match = VAULT_HOST.fullmatch(host)
    if match is None:
        raise ValueError("AZURE_KEY_VAULT_ORIGIN_REQUIRED")
    return match.group("vault")


def skip_token(next_link, *, origin=None, path=None) -> str:
    """The cursor out of a nextLink, never the link itself.

    A link that does not name a vault host is refused rather than followed, so
    a provider response can never move the next request somewhere else.
    """
    if next_link is None or next_link == "":
        return ""
    if not isinstance(next_link, str):
        raise ApiError("invalid_response")
    try:
        parsed = urlsplit(next_link)
        port = parsed.port
    except ValueError:
        raise ApiError("invalid_response") from None
    if (parsed.scheme != "https" or not VAULT_HOST.fullmatch(parsed.hostname or "")
            or parsed.username or parsed.password or parsed.fragment or port not in (None, 443)
            or (origin and parsed.hostname != urlsplit(origin).hostname)
            or (path and parsed.path != path)):
        raise ApiError("invalid_response")
    values = parse_qs(parsed.query).get("$skiptoken") or []
    value = values[0] if len(values) == 1 else ""
    if not value or len(value) > 4096 or not re.fullmatch(r"[A-Za-z0-9._~%+/=-]+", value):
        raise ApiError("invalid_response")
    return value


class ReadTransport:
    """Bounded Azure GET transport; concrete services own origins and paths."""

    paths = ()

    def __init__(self, client, token, *, origin, options, max_requests, api_version,
                 check=None, sleep=time.sleep):
        self.client = client
        self.token = token
        self.origin = origin.rstrip("/")
        self.options = options
        self.max_requests = max_requests
        self.api_version = api_version
        self.check = check or (lambda: None)
        self.sleep = sleep
        self.requests = 0
        self.consecutive_rate_limits = 0
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
            self._wait(earliest - now)
            now = time.monotonic()
        self._next_slot = max(now, self._next_slot) + interval

    def _wait(self, seconds):
        # Split so cancellation is observed while a long provider wait elapses.
        remaining = seconds
        while remaining > 0:
            self.check()
            step = min(remaining, 1.0)
            self.sleep(step)
            remaining -= step

    def get(self, path, params=None):
        if not any(pattern.fullmatch(path) for pattern in self.paths):
            raise ValueError("UNAPPROVED_AZURE_KEY_VAULT_PATH")
        return self._request("GET", path, params)

    def _request(self, method, path, params=None):
        query = dict(params or {})
        if self.api_version:
            query["api-version"] = self.api_version
        for attempt in range(self.options.max_retries + 1):
            self._charge()
            self._pace()
            try:
                bearer = self.token()
            except Exception as exc:  # noqa: BLE001 -- credential errors can carry configuration values
                from cremore_azure_provider.app_certificate import CertificateError

                if isinstance(exc, CertificateError):
                    raise ApiError("provider_unavailable" if exc.retryable else exc.code.lower()) from None
                raise ApiError("request_failed") from None
            try:
                response = bounded_request(
                    self.client, method, self.origin + path, params=query,
                    headers={"Authorization": "Bearer " + bearer,
                             "Accept": "application/json"},
                    timeout=self.options.timeout_seconds, follow_redirects=False,
                    max_response_bytes=self.options.max_response_bytes,
                )
            except HTTPResponseTooLarge:
                raise ApiError("oversized_response") from None
            except Budget:
                raise
            except Exception:  # noqa: BLE001 -- transport and auth errors can embed token-bearing URLs.
                raise ApiError("request_failed") from None
            status = response.status_code
            if status == 200:
                self.consecutive_rate_limits = 0
                try:
                    payload = response.json()
                except ValueError:
                    raise ApiError("invalid_json") from None
                if not isinstance(payload, dict):
                    raise ApiError("invalid_response")
                return payload
            if status == 429 or status >= 500:
                delay = _retry_after(response, attempt, self.options.retry_min_seconds)
                if status == 429:
                    self.consecutive_rate_limits += 1
                    if self.consecutive_rate_limits >= self.options.max_consecutive_rate_limits:
                        raise ApiError("rate_limit_circuit_open", retry_after=delay)
                if attempt >= self.options.max_retries:
                    code = "rate_limited" if status == 429 else "provider_unavailable"
                    raise ApiError(code, retry_after=delay if status == 429 else None)
                self._wait(delay)
                continue
            if status == 401:
                raise ApiError("authentication_failed")
            if status == 403:
                # Key Vault answers an RBAC denial and an access-policy denial
                # the same way; which one it was is not distinguishable here.
                raise ApiError("permission_denied")
            if status == 404:
                raise ApiError("http_404")
            raise ApiError(f"http_{status}" if 400 <= status < 600 else "invalid_response")
        raise ApiError("provider_unavailable")


class Transport(ReadTransport):
    """One configured vault; values are opt-in, never part of a default read."""

    def __init__(self, *args, origin, include_values=False, include_public_certificates=False, **kwargs):
        self.vault = vault_name(origin)
        self.paths = (*PATHS, VALUE_PATH) if include_values else PATHS
        if include_public_certificates:
            self.paths = (*self.paths, CERTIFICATE_PATH)
        super().__init__(*args, origin=origin, **kwargs)


def _retry_after(response, attempt, minimum):
    headers = getattr(response, "headers", {}) or {}
    raw = headers.get("retry-after", headers.get("Retry-After", ""))
    try:
        delay = float(raw)
    except (TypeError, ValueError):
        delay = 0.0
    return max(minimum * (2**attempt), min(delay, 3600.0))


def token_for_origin(origin):
    """Resolve ambient credentials for the cloud of an approved vault host."""
    vault_name(origin)
    suffix = urlsplit(origin).hostname.split(".vault.", 1)[1]
    return default_token(f"https://vault.{suffix}/.default", authority=_AUTHORITY_BY_SUFFIX[suffix])


# A person's sign-in on the worker's host (Azure CLI, PowerShell, azd, VS Code, the shared token cache, a browser,
# the Windows account broker) is never the worker's identity, so a collection never runs as whoever last signed in there.
_PERSONAL_SIGN_INS = dict.fromkeys(("exclude_cli_credential", "exclude_powershell_credential",
                                    "exclude_developer_cli_credential", "exclude_shared_token_cache_credential",
                                    "exclude_visual_studio_code_credential", "exclude_interactive_browser_credential",
                                    "exclude_broker_credential"), True)


def ambient_credential(authority=None):
    """The worker's own Azure identity, as Azure's SDK resolves it from the environment's service principal, a
    federated workload identity or a managed identity."""
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError:
        raise ValueError("INSTALL_CREMORE_AZURE_EXTRA") from None
    return DefaultAzureCredential(**_PERSONAL_SIGN_INS, **({"authority": authority} if authority else {}))


def default_token(scope=SCOPE, *, authority=None, tenant_id=None):
    """A token for ``scope`` from the worker's own Azure identity (ambient_credential)."""
    credential = ambient_credential(authority)

    def token():
        return credential.get_token(scope, **({"tenant_id": tenant_id} if tenant_id else {})).token

    return token
