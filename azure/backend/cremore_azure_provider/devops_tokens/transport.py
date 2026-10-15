"""Only the documented Graph user and Token Admin GETs, with a fixed origin and budgets."""

from __future__ import annotations

import base64
import math
import re
import time
from urllib.parse import quote

from cremore.http_client import HTTPResponseTooLarge, bounded_request

from . import GRAPH_API_VERSION, ORIGIN, TOKEN_API_VERSION

DESCRIPTOR = re.compile(r"[a-z]{2,8}\.[A-Za-z0-9_=-]{1,512}")
_CURSOR = re.compile(r"[A-Za-z0-9+/=_.:-]{1,4096}")


class ReadError(Exception):
    def __init__(self, code, *, retryable=False, retry_after=60):
        super().__init__(code)
        self.code, self.retryable, self.retry_after = code, retryable, retry_after


def cursor_text(value):
    if not isinstance(value, str) or not _CURSOR.fullmatch(value) or "://" in value:
        raise ValueError("AZURE_DEVOPS_INVALID_CURSOR")
    return value


def retry_seconds(headers):
    try:
        delay = float(headers.get("retry-after", "60"))
        return max(1, min(3600, math.ceil(delay))) if math.isfinite(delay) else 60
    except (ValueError, TypeError, OverflowError):
        return 60


class Transport:
    def __init__(self, client, spec, secret, check, *, requests=0, sleep=time.sleep):
        self.client, self.spec, self.secret, self.check = client, spec, secret, check
        self.requests, self.sleep, self.next_slot = requests, sleep, 0.0

    def users(self, scope, cursor):
        params = {"api-version": GRAPH_API_VERSION, **({"continuationToken": cursor_text(cursor)} if cursor else {})}
        response, payload = self._get(scope, "/_apis/graph/users", params)
        rows = payload.get("value") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            raise ReadError("AZURE_DEVOPS_INVALID_RESPONSE")
        return rows, self._next(response.headers.get("x-ms-continuationtoken"))

    def personal_access_tokens(self, scope, descriptor, cursor):
        if not isinstance(descriptor, str) or not DESCRIPTOR.fullmatch(descriptor):
            raise ValueError("AZURE_DEVOPS_INVALID_DESCRIPTOR")
        params = {"api-version": TOKEN_API_VERSION, "isPublic": "false", "pageSize": self.spec.options.page_size,
                  **({"continuationToken": cursor_text(cursor)} if cursor else {})}
        _, payload = self._get(scope, "/_apis/tokenadmin/personalaccesstokens/" + quote(descriptor, safe=""), params)
        rows = payload.get("value") if isinstance(payload, dict) else None
        if not isinstance(rows, list) or len(rows) > self.spec.options.page_size:
            raise ReadError("AZURE_DEVOPS_INVALID_RESPONSE")
        return rows, self._next(payload.get("continuationToken"))

    @staticmethod
    def _next(value):
        if value in (None, ""):
            return ""
        try:
            return cursor_text(value)
        except ValueError:
            raise ReadError("AZURE_DEVOPS_INVALID_CURSOR") from None

    def _get(self, scope, path, params):
        if scope not in self.spec.scopes or scope.kind != "organization":
            raise ValueError("AZURE_DEVOPS_OPERATION_OUT_OF_SCOPE")
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
        if callable(self.secret):
            # A Microsoft Entra token for the Microsoft connection's app.
            try:
                authorization = "Bearer " + self.secret()
            except Exception as exc:  # noqa: BLE001 -- credential errors can carry configuration values
                from cremore_azure_provider.app_certificate import CertificateError

                if isinstance(exc, CertificateError):
                    raise ReadError(exc.code, retryable=exc.retryable) from None
                raise ReadError("AZURE_DEVOPS_TOKEN_UNAVAILABLE", retryable=True) from None
        else:
            # A personal access token is the Basic password with an empty user name.
            authorization = "Basic " + base64.b64encode((":" + self.secret).encode()).decode()
        try:
            response = bounded_request(
                self.client, "GET", ORIGIN + "/" + quote(scope.id, safe="") + path, params=params,
                headers={"Authorization": authorization, "Accept": "application/json",
                         "User-Agent": "CreMore-Coverage/1.0"},
                timeout=self.spec.options.timeout_seconds, follow_redirects=False,
                max_response_bytes=self.spec.options.max_response_bytes,
            )
        except HTTPResponseTooLarge:
            raise ReadError("AZURE_DEVOPS_RESPONSE_LIMIT") from None
        except Exception:  # noqa: BLE001 -- HTTP failures can include secret-bearing headers.
            raise ReadError("AZURE_DEVOPS_UNAVAILABLE", retryable=True) from None
        self.check()
        code = response.status_code
        if code == 429:
            raise ReadError("AZURE_DEVOPS_RATE_LIMITED", retryable=True, retry_after=retry_seconds(response.headers))
        if code >= 500 or code == 408:
            raise ReadError("AZURE_DEVOPS_UNAVAILABLE", retryable=True)
        if code != 200:
            # 203 is the sign-in page Azure DevOps returns for a rejected token.
            raise ReadError("AZURE_DEVOPS_HTTP_" + str(code))
        try:
            return response, response.json()
        except (ValueError, RecursionError):
            raise ReadError("AZURE_DEVOPS_INVALID_RESPONSE") from None
