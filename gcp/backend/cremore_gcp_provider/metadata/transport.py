"""Read-only Google API transport: fixed hosts, charged budget, sanitized errors.

The native connector used an AuthorizedSession per process. The product already
mints an ADC token the same way for schema 1 GCP collection, so this reuses that
token source with the shared bounded HTTP client instead of adding a second
stack. No response body, URL or token survives a failure: only a fixed code.
"""

from __future__ import annotations

import re
import time

from cremore_gcp.transport import ApiError, _forbidden_code

from cremore.http_client import HTTPResponseTooLarge, bounded_request
from cremore_gcp_provider.gcp_auth import TRANSIENT_AUTH_CODES, GcpAuthError

# Every host this package may reach. A regional Secret Manager endpoint is
# checked against the region grammar, never taken from a provider response.
_HOSTS = {
    "iam.googleapis.com",
    "apikeys.googleapis.com",
    "secretmanager.googleapis.com",
    "serviceusage.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "policytroubleshooter.googleapis.com",
}
_REGIONAL_HOST = re.compile(r"^secretmanager\.[a-z][a-z0-9-]{1,62}\.rep\.googleapis\.com$")
_URL = re.compile(r"^https://([a-z0-9.-]+)/[A-Za-z0-9/:._~@%-]*$")
# The POSTs that only read: log entries, a project's allow policy, and the troubleshooter's evaluation.
_READ_RPC = (
    ("https://logging.googleapis.com/v2/entries:list", "https://policytroubleshooter.googleapis.com/v3/iam:troubleshoot"),
    re.compile(
        r"^https://cloudresourcemanager\.googleapis\.com/v1/projects/[a-z][a-z0-9-]+:getIamPolicy$"
    ),
)


# A provider that is rate limiting or unavailable is not a partial listing:
# the run keeps its cursor and waits rather than recording a smaller result.
# Throttled or unavailable API reads wait and resume; so does a mid-run token refresh that
# Google's token service asked to retry (it reaches here as ApiError(code.lower())).
DEFERRED = frozenset({"rate_limited", "rate_limit_circuit_open", "provider_unavailable",
                      *(code.lower() for code in TRANSIENT_AUTH_CODES)})


class Budget(Exception):
    """A configured request, page or record ceiling was reached."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def approved(url: str) -> str:
    match = _URL.fullmatch(url.split("?", 1)[0])
    if match is None:
        raise ValueError("UNAPPROVED_GCP_URL")
    host = match.group(1)
    if host not in _HOSTS and not _REGIONAL_HOST.fullmatch(host):
        raise ValueError("UNAPPROVED_GCP_URL")
    return host


class Transport:
    """GET plus the approved read-only POSTs (_READ_RPC), under one shared budget."""

    def __init__(self, client, token, *, options, max_requests, check=None, sleep=time.sleep):
        self.client = client
        self.token = token
        self.options = options
        self.max_requests = max_requests
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
        # A burst is allowed, then requests are spaced by the configured rate.
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

    def _send(self, method, url, *, params=None, body=None):
        approved(url)
        for attempt in range(self.options.max_retries + 1):
            self._charge()
            self._pace()
            try:
                response = bounded_request(
                    self.client,
                    method,
                    url,
                    params=params,
                    json=body,
                    headers={"Authorization": "Bearer " + self.token(), "Accept": "application/json"},
                    timeout=self.options.timeout_seconds,
                    follow_redirects=False,
                    max_response_bytes=self.options.max_response_bytes,
                )
            except HTTPResponseTooLarge:
                raise ApiError("oversized_response") from None
            except Budget:
                raise
            except GcpAuthError as exc:
                raise ApiError(exc.code.lower(), retry_after=exc.retry_after) from None
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
            if status == 403:
                try:
                    code = _forbidden_code(response.json())
                except ValueError:
                    code = "permission_denied_or_api_disabled"
                raise ApiError(code)
            if status == 401:
                raise ApiError("authentication_failed")
            if status == 404:
                raise ApiError("http_404")
            raise ApiError(f"http_{status}" if 400 <= status < 600 else "invalid_response")
        raise ApiError("provider_unavailable")

    def get(self, url, params=None):
        return self._send("GET", url, params=params)

    def post_readonly(self, url, body, params=None):
        fixed, pattern = _READ_RPC
        if url not in fixed and not pattern.fullmatch(url):
            raise ValueError("UNAPPROVED_GCP_URL")
        return self._send("POST", url, params=params, body=body)


def _retry_after(response, attempt, minimum):
    headers = getattr(response, "headers", {}) or {}
    raw = headers.get("retry-after", headers.get("Retry-After", ""))
    try:
        delay = float(raw)
    except (TypeError, ValueError):
        delay = 0.0
    return max(minimum * (2**attempt), min(delay, 3600.0))


def adc_token(scopes=("https://www.googleapis.com/auth/cloud-platform",)):
    from cremore_gcp_provider.gcp_auth import adc_token as source
    return source(scopes)
