"""Only the documented Enterprise metadata GETs, with fixed origin and budgets."""

from __future__ import annotations

import math
import time

from cremore.http_client import HTTPResponseTooLarge, bounded_request

from . import API_VERSION, ORIGIN, SOURCES
from .normalization import safe_text, uuid_text


class ReadError(Exception):
    def __init__(self, code, *, retryable=False, retry_after=60):
        super().__init__(code)
        self.code, self.retryable, self.retry_after = code, retryable, retry_after


def cursor_text(value, bearer=""):
    value = safe_text(value, bearer=bearer)
    if not value or "://" in value:
        raise ValueError("NOTION_INVALID_CURSOR")
    return value


def retry_seconds(headers):
    try:
        delay = float(headers.get("retry-after", "60"))
        return max(1, min(3600, math.ceil(delay))) if math.isfinite(delay) else 60
    except (ValueError, TypeError, OverflowError):
        return 60


class Transport:
    def __init__(self, client, spec, bearer, check, *, requests=0, sleep=time.sleep):
        self.client, self.spec, self.bearer, self.check = client, spec, bearer, check
        self.requests, self.sleep, self.next_slot = requests, sleep, 0.0

    def read(self, scope, source, cursor):
        if scope not in self.spec.scopes or source not in SOURCES:
            raise ValueError("NOTION_OPERATION_OUT_OF_SCOPE")
        uuid_text(scope.id)
        params = {"page_size": self.spec.options.page_size}
        if source == "personal_access_tokens":
            path = "/admin/v1/spaces/" + scope.id + "/personal_access_tokens"
        else:
            path = "/admin/v1/mcp_client_connections"
            params["workspace_ids"] = scope.id
        if cursor:
            params["cursor"] = cursor_text(cursor, self.bearer)
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
                self.client, "GET", ORIGIN + path, params=params,
                headers={"Authorization": "Bearer " + self.bearer, "Notion-Version": API_VERSION,
                         "Accept": "application/json", "User-Agent": "CreMore-Coverage/1.0"},
                timeout=self.spec.options.timeout_seconds, follow_redirects=False,
                max_response_bytes=self.spec.options.max_response_bytes,
            )
        except HTTPResponseTooLarge:
            raise ReadError("NOTION_RESPONSE_LIMIT") from None
        except Exception:  # noqa: BLE001 -- HTTP failures can include secret-bearing headers.
            raise ReadError("NOTION_UNAVAILABLE", retryable=True) from None
        self.check()
        code = response.status_code
        if code == 429:
            raise ReadError("NOTION_RATE_LIMITED", retryable=True,
                            retry_after=retry_seconds(response.headers))
        if code >= 500 or code == 408:
            raise ReadError("NOTION_UNAVAILABLE", retryable=True)
        if code != 200:
            raise ReadError("NOTION_HTTP_" + str(code))
        try:
            payload = response.json()
        except (ValueError, RecursionError):
            raise ReadError("NOTION_INVALID_RESPONSE") from None
        if (not isinstance(payload, dict) or not isinstance(payload.get("results"), list)
                or not isinstance(payload.get("has_more"), bool)):
            raise ReadError("NOTION_INVALID_RESPONSE")
        if len(payload["results"]) > self.spec.options.page_size:
            raise ReadError("NOTION_PAGE_SIZE_EXCEEDED")
        next_cursor = payload.get("next_cursor")
        if payload["has_more"]:
            try:
                next_cursor = cursor_text(next_cursor, self.bearer)
            except ValueError:
                raise ReadError("NOTION_INVALID_CURSOR") from None
        elif next_cursor is not None:
            # A cursor after an asserted final page is ambiguous, not complete.
            raise ReadError("NOTION_INVALID_CURSOR")
        return payload["results"], next_cursor
