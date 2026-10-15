"""Only the documented admin and audit log GETs, with fixed origins and budgets."""

from __future__ import annotations

import math
import re
import time

from cremore.http_client import HTTPResponseTooLarge, bounded_request

from . import API_ORIGIN, AUDIT_ACTIONS, AUDIT_ORIGIN
from .normalization import safe_text

_ERROR = re.compile(r"[a-z_]{1,60}")
_TRANSIENT = ("internal_error", "fatal_error", "service_unavailable", "request_timeout")


class ReadError(Exception):
    def __init__(self, code, *, retryable=False, retry_after=60):
        super().__init__(code)
        self.code, self.retryable, self.retry_after = code, retryable, retry_after


def cursor_text(value, bearer=""):
    value = safe_text(value, bearer=bearer, max_length=2048)
    if "://" in value:
        raise ValueError("SLACK_INVALID_CURSOR")
    return value


def retry_seconds(headers):
    try:
        delay = float(headers.get("retry-after", "60"))
        return max(1, min(3600, math.ceil(delay))) if math.isfinite(delay) else 60
    except (ValueError, TypeError, OverflowError):
        return 60


def refusal(error, *, status=200, headers=None):
    """The ReadError for a Slack ``{"ok": false, "error": ...}`` answer."""
    if error == "ratelimited" or status == 429:
        return ReadError("SLACK_RATE_LIMITED", retryable=True, retry_after=retry_seconds(headers or {}))
    if error in _TRANSIENT or status >= 500 or status == 408:
        return ReadError("SLACK_UNAVAILABLE", retryable=True)
    if isinstance(error, str) and _ERROR.fullmatch(error):
        return ReadError("SLACK_" + error.upper())
    return ReadError("SLACK_HTTP_" + str(status) if status != 200 else "SLACK_REQUEST_REFUSED")


class Transport:
    def __init__(self, client, spec, bearer, check, *, requests=0, sleep=time.sleep):
        self.client, self.spec, self.bearer, self.check = client, spec, bearer, check
        self.requests, self.sleep, self.next_slot = requests, sleep, 0.0

    def approved(self, scope, cursor):
        """One page of ``admin.apps.approved.list`` for the organization or the workspace."""
        params = {"limit": min(self.spec.options.page_size, 1000),
                  "enterprise_id" if scope.kind == "enterprise" else "team_id": scope.id}
        if cursor:
            params["cursor"] = cursor_text(cursor, self.bearer)
        payload = self._get(API_ORIGIN + "/api/admin.apps.approved.list", params)
        return self._page(payload, "approved_apps")

    def audit(self, oldest, latest, cursor):
        """One page of the organization's audit log, app lifecycle actions only, within the window."""
        params = {"action": ",".join(AUDIT_ACTIONS), "oldest": oldest, "latest": latest,
                  "limit": min(self.spec.options.page_size, 1000)}
        if cursor:
            params["cursor"] = cursor_text(cursor, self.bearer)
        payload = self._get(AUDIT_ORIGIN + "/audit/v1/logs", params)
        return self._page(payload, "entries")

    def _page(self, payload, key):
        items = payload.get(key)
        if not isinstance(items, list):
            raise ReadError("SLACK_INVALID_RESPONSE")
        # Audit events sharing a timestamp can exceed the requested (optimistic) limit.
        if len(items) > (9999 if key == "entries" else self.spec.options.page_size):
            raise ReadError("SLACK_PAGE_SIZE_EXCEEDED")
        meta = payload.get("response_metadata")
        following = meta.get("next_cursor") if isinstance(meta, dict) else None
        if following in (None, ""):
            return items, None
        try:
            return items, cursor_text(following, self.bearer)
        except ValueError:
            raise ReadError("SLACK_INVALID_CURSOR") from None

    def _get(self, url, params):
        self.check()
        if self.requests >= self.spec.max_requests:
            raise ReadError("REQUEST_BUDGET_EXCEEDED")
        # Short interruptible pacing; rate-limit waiting is persisted by the worker.
        delay = self.next_slot - time.monotonic()
        while delay > 0:
            step = min(delay, 0.5)
            self.check()
            self.sleep(step)
            delay -= step
        self.next_slot = time.monotonic() + 1 / self.spec.options.requests_per_second
        self.check()
        self.requests += 1
        try:
            response = bounded_request(
                self.client, "GET", url, params=params,
                headers={"Authorization": "Bearer " + self.bearer, "Accept": "application/json",
                         "User-Agent": "CreMore-Coverage/1.0"},
                timeout=self.spec.options.timeout_seconds, follow_redirects=False,
                max_response_bytes=self.spec.options.max_response_bytes,
            )
        except HTTPResponseTooLarge:
            raise ReadError("SLACK_RESPONSE_LIMIT") from None
        except Exception:  # noqa: BLE001 -- HTTP failures can include secret-bearing headers.
            raise ReadError("SLACK_UNAVAILABLE", retryable=True) from None
        self.check()
        try:
            payload = response.json()
        except (ValueError, RecursionError):
            payload = None
        error = payload.get("error") if isinstance(payload, dict) else None
        if response.status_code != 200:
            raise refusal(error, status=response.status_code, headers=response.headers)
        if not isinstance(payload, dict):
            raise ReadError("SLACK_INVALID_RESPONSE")
        # The Web API answers 200 with ok: false; the audit log answers without an ok field.
        if payload.get("ok") is False:
            raise refusal(error, headers=response.headers)
        return payload
