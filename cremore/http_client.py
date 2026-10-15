"""Bound provider responses before buffering or parsing them."""

from __future__ import annotations

import json
import math
import time
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

DEFAULT_MAX_RESPONSE_BYTES = 8 << 20
# A gateway or service that is briefly unavailable; only a read is sent again.
_SERVER_BUSY = frozenset({502, 503, 504})
# A paced GET waits out rate-limit cooldowns of up to this many seconds in all, over at most
# this many attempts; past that the refusal is returned.
PACED_COOLDOWN = 120.0
PACED_ATTEMPTS = 10


class HTTPResponseTooLarge(RuntimeError):
    pass


class _BufferedResponse:
    def __init__(self, status_code: int, headers, body: bytes, encoding: str = "utf-8") -> None:
        self.status_code = status_code
        self.headers = headers
        try:
            self.text = body.decode(encoding or "utf-8", "replace")
        except (LookupError, UnicodeError):  # an unknown charset, or one that refuses "replace" (idna)
            self.text = body.decode("utf-8", "replace")
        self.content = body

    def json(self):
        return json.loads(self.content)


def bounded_request(
    client,
    method: str,
    url: str,
    *,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    retry_429: bool = False,
    before_attempt: Callable[[], None] | None = None,
    pacer=None,
    **kwargs,
):
    """Bound response bytes, optionally retrying explicitly read-only calls.

    At most three attempts and ten seconds of retry delay, attempts included: a
    wait longer than what is left returns the answer instead. A 429 is retried;
    a GET also on 502/503/504 and on GitHub's rate limits (a 403 with
    Retry-After, or X-RateLimit-Remaining 0 with X-RateLimit-Reset). Response
    bodies are never kept. The caller's request budget is charged before every
    attempt, including retries of Notion search.

    A caller that opts in with ``pacer`` (cremore.collectors.base.RequestPacer)
    waits for its slot before every attempt. A rate limit on its GET puts the
    pacer into the cooldown asked for instead of sleeping here, so every reader
    and process of that credential waits it out with the request guard checked;
    the GET is retried while the cooldowns stay within PACED_COOLDOWN seconds in
    all. Slot and cooldown waits do not count against the ten seconds. A pacer
    that must not wait (``waits`` False, a change feed's NoWaitPacer) is never
    slept for: any answer that would be retried ends the request through its
    ``defer``, with the cooldown a rate limit asks of every scan (0 for none),
    or as a busy server (502/503/504) so a caller can tell it from a rate limit.
    """

    if max_response_bytes <= 0:
        raise ValueError("max_response_bytes must be positive")

    started, paced, cooled = time.monotonic(), 0.0, 0.0
    attempts = (PACED_ATTEMPTS if pacer is not None else 3) if retry_429 else 1
    for attempt in range(attempts):
        if pacer is not None:
            began = time.monotonic()
            pacer.acquire()
            paced += time.monotonic() - began
        if before_attempt is not None:
            before_attempt()
        response = _request_once(client, method, url, max_response_bytes, **kwargs)
        if not retry_429 or not _retryable(method, response) or attempt == attempts - 1:
            return response
        delay = _retry_delay(response, attempt)
        limited = pacer is not None and method.upper() == "GET" and _rate_limited(response)
        if not getattr(pacer, "waits", True):
            _close(response)
            pacer.defer(delay if limited and delay <= PACED_COOLDOWN else 0.0, busy=not _rate_limited(response))
            return response
        if limited:
            if cooled + delay > PACED_COOLDOWN:
                return response
            _close(response)
            pacer.defer(delay)
            cooled += delay
            continue
        if delay > 10 - (time.monotonic() - started - paced):
            return response
        _close(response)
        time.sleep(delay)


def _header(headers, name: str):
    """A response header by its lowercase name: httpx headers ignore case, a plain dict may not."""
    value = headers.get(name)
    if value is None and isinstance(headers, dict):
        value = next((v for k, v in headers.items() if isinstance(k, str) and k.lower() == name), None)
    return value


def _exhausted(headers) -> bool:
    remaining = _header(headers, "x-ratelimit-remaining")
    return str(remaining).strip() == "0" and _header(headers, "x-ratelimit-reset") is not None


def _rate_limited(response) -> bool:
    status = getattr(response, "status_code", 200)
    headers = getattr(response, "headers", None) or {}
    return status == 429 or (status == 403 and (_header(headers, "retry-after") is not None or _exhausted(headers)))


def _retryable(method: str, response) -> bool:
    if getattr(response, "status_code", 200) == 429:
        return True
    if method.upper() != "GET":
        return False  # a write the server may already have applied is never sent twice
    return getattr(response, "status_code", 200) in _SERVER_BUSY or _rate_limited(response)


def _retry_delay(response, attempt: int) -> float:
    headers = getattr(response, "headers", {}) or {}
    value = _header(headers, "retry-after")
    if value is None and _exhausted(headers):
        # GitHub: the limit resets at this epoch second.
        value = _header(headers, "x-ratelimit-reset")
        try:
            delay = float(value) - time.time()
        except (TypeError, ValueError):
            delay = float(2 ** attempt)
    else:
        try:
            delay = float(value)
        except (TypeError, ValueError):
            try:
                when = parsedate_to_datetime(value)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=UTC)
                delay = (when - datetime.now(UTC)).total_seconds()
            except (TypeError, ValueError, OverflowError):
                delay = float(2 ** attempt)
    # NaN/Infinity must never reach sleep; an excessive wait returns the answer.
    return max(0.0, delay) if not math.isnan(delay) else float(2 ** attempt)


def _close(response) -> None:
    close = getattr(response, "close", None)
    if callable(close):
        close()


def _request_once(client, method: str, url: str, max_response_bytes: int, **kwargs):

    stream = getattr(client, "stream", None)
    if callable(stream):
        with stream(method, url, **kwargs) as response:
            _check_content_length(response, max_response_bytes)
            body = bytearray()
            for chunk in response.iter_bytes(chunk_size=64 << 10):
                if len(chunk) > max_response_bytes - len(body):
                    raise HTTPResponseTooLarge("provider response exceeds byte limit")
                body.extend(chunk)
            return _BufferedResponse(
                response.status_code,
                response.headers,
                bytes(body),
                getattr(response, "encoding", None) or "utf-8",
            )

    call = getattr(client, method.lower(), None)
    response = call(url, **kwargs) if callable(call) else client.request(method, url, **kwargs)
    try:
        _check_content_length(response, max_response_bytes)
        try:
            content = response.content
        except (AttributeError, RuntimeError):
            content = None
        if isinstance(content, (bytes, bytearray)) and len(content) > max_response_bytes:
            raise HTTPResponseTooLarge("provider response exceeds byte limit")
    except Exception:
        _close(response)
        raise
    return response


def _check_content_length(response, limit: int) -> None:
    try:
        value = (getattr(response, "headers", {}) or {}).get("content-length")
        if value is not None and int(value) > limit:
            raise HTTPResponseTooLarge("provider response exceeds byte limit")
    except (TypeError, ValueError):
        pass
