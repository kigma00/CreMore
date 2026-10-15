# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/http.py).
"""Bounded metadata reads. Exception text and error bodies never become results."""

import http.client
import json
import math
import random
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from email.utils import parsedate_to_datetime

from .jsonio import loads
from .read_operations import (
    ACCOUNT_COUNT_OPERATIONS,
    READ_OPERATIONS,
    operation_url,
    valid_identifier,
    validate_next_url,
)
from .snapshot import metadata_snapshot
from .specs import SOURCES
from .steps import CollectionInterrupted

BASE_URL = "https://api.atlassian.com/admin/api-access/v1"
MAX_BYTES = 1024 * 1024
RETRY_STATUSES = {429, 500, 502, 503, 504}


@dataclass(frozen=True)
class Limits:
    max_pages: int = 50
    max_records: int = 5000
    max_requests: int = 100
    max_seconds: float = 120
    timeout: float = 15
    retries: int = 2
    max_retry_wait: float = 30

    def __post_init__(self):
        for name, minimum, maximum in (
            ("max_pages", 1, 1000),
            ("max_records", 1, 100000),
            ("max_requests", 1, 1000),
            ("retries", 0, 5),
        ):
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError("Invalid collection limit: " + name)
        for name, minimum, maximum in (
            ("max_seconds", 1, 600),
            ("timeout", 0.1, 30),
            ("max_retry_wait", 0, 60),
        ):
            value = getattr(self, name)
            if (
                type(value) not in (int, float)
                or not math.isfinite(value)
                or not minimum <= value <= maximum
            ):
                raise ValueError("Invalid collection limit: " + name)


@dataclass
class FetchResult:
    status: object = None
    body: object = field(default=None, repr=False)
    attempts: int = 0
    reason: object = None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def retry_delay(headers, now):
    """Prefer Retry-After; use the documented ISO rate-limit reset as fallback."""
    value = headers.get("Retry-After")
    if value is not None:
        try:
            if str(value).strip().isdigit():
                delay = float(value)
            else:
                date = parsedate_to_datetime(value)
                if date.tzinfo is None:
                    raise ValueError("Timezone required")
                delay = date.timestamp() - now
            if math.isfinite(delay):
                return max(0, delay)
        except (TypeError, ValueError, OverflowError):
            pass
    value = headers.get("X-RateLimit-Reset")
    if isinstance(value, str):
        try:
            date = datetime.fromisoformat(value)
            if date.tzinfo is not None:
                return max(0, date.timestamp() - now)
        except (ValueError, OverflowError):
            pass
    return None


class BearerReadClient:
    def __init__(
        self,
        key,
        limits=None,
        *,
        opener=None,
        clock=time.monotonic,
        wall_clock=time.time,
        sleep=time.sleep,
        jitter=random.random,
        check=None,
        max_response_bytes=MAX_BYTES,
    ):
        if (
            not isinstance(key, str)
            or not key
            or not key.isascii()
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in key)
        ):
            raise ValueError("Invalid authentication configuration")
        self._key = key
        if type(max_response_bytes) is not int or not 1024 <= max_response_bytes <= 20971520:
            raise ValueError("Invalid response byte limit")
        self.max_response_bytes = min(max_response_bytes, MAX_BYTES)
        self.limits = limits or Limits()
        self._opener = opener or urllib.request.build_opener(NoRedirect())
        self._clock, self._wall_clock, self._sleep, self._jitter = clock, wall_clock, sleep, jitter
        self._deadline = clock() + self.limits.max_seconds
        self.requests = 0
        self._check = check

    def check(self):
        if self._check is not None:
            try:
                self._check()
            except CollectionInterrupted:
                raise
            except Exception as error:  # noqa: BLE001 - preserve a worker's exact cancellation cause.
                raise CollectionInterrupted(error) from None

    def _authentication_header(self):
        return "Bearer " + self._key

    def _wait(self, delay):
        if self._check is None:
            self._sleep(delay)
            return
        remaining = delay
        while remaining > 0:
            self.check()
            interval = min(remaining, 1)
            self._sleep(interval)
            remaining -= interval
        self.check()

    def _remaining(self):
        return self._deadline - self._clock()

    def restrict_time(self, seconds):
        """Apply an outer job deadline after connection setup without extending it."""
        if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds < 0:
            raise ValueError("Invalid remaining time")
        self._deadline = min(self._deadline, self._clock() + seconds)

    def snapshot(self, body):
        return metadata_snapshot(body, sensitive_values=(self._key,))

    def _request(
        self, url, *, method="GET", payload=None, response_format="json", authenticate=True
    ):
        if response_format not in ("json", "text"):
            raise ValueError("Unsupported response format")
        if type(authenticate) is not bool:
            raise ValueError("Invalid authentication selection")
        attempts = 0
        for retry in range(self.limits.retries + 1):
            self.check()
            if self.requests >= self.limits.max_requests:
                return FetchResult(attempts=attempts, reason="request_limit")
            remaining = self._remaining()
            if remaining <= 0:
                return FetchResult(attempts=attempts, reason="time_limit")
            request = urllib.request.Request(
                url,
                method=method,
                data=payload,
                headers={
                    **({"Authorization": self._authentication_header()} if authenticate else {}),
                    "Accept": "application/json",
                    **({"Content-Type": "application/json"} if payload is not None else {}),
                },
            )
            self.requests += 1
            attempts += 1  # noqa: SIM113 - early no-request exits preserve actual attempt counts.
            status, headers, reason = None, {}, None
            try:
                try:
                    response = self._opener.open(
                        request, timeout=min(self.limits.timeout, remaining)
                    )
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    status, headers = response.code, response.headers
                    if status == 200:
                        chunks, size = [], 0
                        while True:
                            self.check()
                            if self._remaining() <= 0:
                                return FetchResult(status, attempts=attempts, reason="time_limit")
                            chunk = response.read1(min(65536, self.max_response_bytes + 1 - size))
                            size += len(chunk)
                            if size > self.max_response_bytes:
                                return FetchResult(
                                    status, attempts=attempts, reason="response_too_large"
                                )
                            if not chunk:
                                break
                            chunks.append(chunk)
                        try:
                            raw = b"".join(chunks)
                            body = raw.decode("utf-8") if response_format == "text" else loads(raw)
                        except (ValueError, UnicodeDecodeError, RecursionError):
                            return FetchResult(status, attempts=attempts, reason="invalid_json")
                        return FetchResult(status, body, attempts)
                    reason = "http_" + str(status)
            except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
                reason = "transport_error"
            if status not in RETRY_STATUSES and reason != "transport_error":
                return FetchResult(status, attempts=attempts, reason=reason)
            if retry == self.limits.retries:
                return FetchResult(status, attempts=attempts, reason=reason)
            if self.requests >= self.limits.max_requests:
                return FetchResult(status, attempts=attempts, reason="request_limit")
            delay = retry_delay(headers, self._wall_clock())
            if delay is None:
                delay = 2**retry + self._jitter() * 0.25
            if delay > self.limits.max_retry_wait:
                return FetchResult(status, attempts=attempts, reason="retry_wait_exceeds_limit")
            if delay >= self._remaining():
                return FetchResult(status, attempts=attempts, reason="time_limit")
            self._wait(delay)
        raise AssertionError("Unreachable retry state")


class CloudClient(BearerReadClient):
    def __init__(self, org_id, key, limits=None, *, token_page_size=20, **kwargs):
        if type(token_page_size) is not int or not 1 <= token_page_size <= 1000:
            raise ValueError("Invalid API token page size")
        self.token_page_size = token_page_size
        self.org_id = str(uuid.UUID(org_id))
        super().__init__(key, limits, **kwargs)

    def snapshot(self, body):
        from .read_operations import MANAGEMENT_REASON_CODES

        return metadata_snapshot(
            body, sensitive_values=(self._key,), reason_codes=MANAGEMENT_REASON_CODES
        )

    def fetch(self, source, query):
        spec = SOURCES[source]
        allowed = {"pageSize", "cursor"} if spec["paged"] else set()
        if set(query) - allowed:
            raise ValueError("Unsupported query parameter")
        if "pageSize" in query and (type(query["pageSize"]) is not int or query["pageSize"] != 20):
            raise ValueError("This release uses pageSize=20")
        if "cursor" in query and (
            not isinstance(query["cursor"], str) or len(query["cursor"]) > 8192
        ):
            raise ValueError("Invalid cursor")
        url = BASE_URL + "/orgs/" + self.org_id + "/" + spec["path"]
        if query:
            url += "?" + urllib.parse.urlencode(query)
        return self._request(url)

    def read_metadata(self, operation, *, identifier=None, body=None, cursor=None, next_url=None):
        spec = READ_OPERATIONS[operation]
        url = operation_url(operation, self.org_id, identifier)
        method = spec.get("method", "GET")
        payload = None
        if operation in ACCOUNT_COUNT_OPERATIONS:
            if (
                not isinstance(body, list)
                or not 1 <= len(body) <= 100
                or not all(valid_identifier(v, 100) for v in body)
                or len(body) != len(set(body))
            ):
                raise ValueError("Invalid account count batch")
            payload = json.dumps(body).encode("utf-8")
        elif body is not None:
            raise ValueError("This metadata operation takes no body")
        if next_url is not None:
            if spec.get("pager") != "url" or cursor is not None:
                raise ValueError("Unexpected pagination URL")
            url = validate_next_url(url, next_url)
        else:
            query = dict(spec.get("query", {}))
            if operation == "org-api-tokens":
                query["pageSize"] = self.token_page_size
            if cursor is not None:
                if (
                    spec.get("pager") != "cursor"
                    or not isinstance(cursor, str)
                    or len(cursor) > 8192
                ):
                    raise ValueError("Invalid metadata cursor")
                query["cursor"] = cursor
            if query:
                url += "?" + urllib.parse.urlencode(query)
        return self._request(url, method=method, payload=payload)
