"""Shared worker pacing with local fallback and owner-thread authorization."""

from __future__ import annotations

import hashlib
import math
import threading
import time
import weakref
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from queue import Empty, Full, Queue

from cremore.collectors.base import CollectorError, check_request_guard, request_pacing

INTERVAL = 0.4  # seconds between a connection's requests: 2.5 a second


class NotionRateLimiter:
    """No-burst 2.5 requests/second cap shared by a connection in this process."""

    def __init__(self, *, clock=time.monotonic, sleep=time.sleep, key=None):
        self.clock, self.sleep = clock, sleep
        self._lock = threading.Lock()
        self._next = 0.0
        self.key = key

    def acquire(self, check=check_request_guard, *, patient=True):
        """Wait for the connection's next slot. Not ``patient``, it still waits for an ordinary slot but fails at
        once with NOTION_RATE_LIMITED while the connection cools down after a 429/529: a wait longer than two slots
        (a slot's own wait reads a little over one as clocks round)."""
        while True:
            check()
            shared = request_pacing()
            if shared is not None and self.key:
                delay = shared.request_delay(self.key, INTERVAL)
                if delay <= 0:
                    return
            else:
                with self._lock:
                    now = self.clock()
                    delay = self._next - now
                    if delay <= 0:
                        self._next = now + INTERVAL
                        return
            if not patient and delay > 2 * INTERVAL:
                raise CollectorError("NOTION_RATE_LIMITED", "cooling down")
            self.sleep(min(delay, 0.1))

    def defer(self, delay):
        shared = request_pacing()
        if shared is not None and self.key:
            shared.request_delay(self.key, INTERVAL, cooldown=delay)
            return
        with self._lock:
            self._next = max(self._next, self.clock() + delay)


class SlotsOnly:
    """A connection's limiter for a change feed, polled from the worker's control loop: it waits for an ordinary
    slot but never waits out a cooldown, failing at once with NOTION_RATE_LIMITED instead, so the feed keeps its
    cursor and the next poll looks again. A 429/529 it meets still cools every caller of the connection down."""

    def __init__(self, limiter):
        self.limiter = limiter

    def acquire(self):
        self.limiter.acquire(patient=False)

    def defer(self, delay):
        self.limiter.defer(delay)


_limiters = weakref.WeakValueDictionary()
_limiters_lock = threading.Lock()


def connection_limiter(token, origin):
    # Neither credentials nor page content is retained in registry keys.
    key = hashlib.sha256((origin + "\0" + token).encode()).hexdigest()
    with _limiters_lock:
        limiter = _limiters.get(key)
        if limiter is None:
            limiter = _limiters[key] = NotionRateLimiter(key=key)
        return limiter


def retry_delay(response, attempt):
    headers = getattr(response, "headers", {}) or {}
    value = headers.get("Retry-After", headers.get("retry-after", ""))
    try:
        delay = float(value)
    except (TypeError, ValueError):
        try:
            stamp = parsedate_to_datetime(value)
            stamp = stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp
            delay = (stamp - datetime.now(UTC)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            delay = float(2 ** attempt)
    return max(0.0, delay) if math.isfinite(delay) else float("inf")


def paced(limiter, send, *, before_attempt=None):
    """``send()`` -- one HTTP attempt, a response or None after a transport failure -- behind
    ``limiter`` (``acquire()``/``defer(seconds)``), retrying 429/529 as Retry-After asks.

    At most three attempts and ten seconds of Retry-After cooldown; the waits for an ordinary
    pacing slot do not count, since a busy connection is no reason to give up. The cooldown
    is the limiter's, so every caller of the connection waits it out and cancellation is
    checked while waiting; a longer Retry-After returns the 429/529 rather than sleeping
    past the bound.
    """
    cooled = 0.0
    for attempt in range(3):
        limiter.acquire()
        if before_attempt is not None:
            before_attempt()
        response = send()
        status = getattr(response, "status_code", None)
        if status not in (429, 529) or attempt == 2:
            return response
        delay = retry_delay(response, attempt)
        if cooled + delay > 10:
            return response
        limiter.defer(delay)
        cooled += delay
    raise AssertionError("bounded retry exhausted")


class RequestDispatcher:
    """Workers ask the owner to check the guard; no DB context runs in workers."""

    def __init__(self):
        self.owner = threading.get_ident()
        # Three authorization tickets and three completion notifications at most.
        self.queue = Queue(maxsize=6)
        self.stopped = threading.Event()

    def call(self, callback):
        if threading.get_ident() == self.owner:
            return callback()
        done = threading.Event()
        result = []
        while not self.stopped.is_set():
            try:
                self.queue.put((callback, done, result), timeout=0.1)
                break
            except Full:
                continue
        else:
            raise CollectorError("NOTION_FETCH_STOPPED")
        while not done.wait(0.1):
            if self.stopped.is_set():
                raise CollectorError("NOTION_FETCH_STOPPED")
        if result:
            raise result[0]

    def completed(self, _future):
        # Wake the owner immediately when the requested page finishes. A full
        # queue already wakes it, so no worker should block on a notification.
        try:
            self.queue.put_nowait(None)
        except Full:
            pass

    def pump(self, timeout=0.05):
        check_request_guard()
        try:
            item = self.queue.get(timeout=timeout)
        except Empty:
            return
        if item is None:
            return
        callback, done, result = item
        try:
            callback()
        except BaseException as exc:
            result.append(exc)
            raise
        finally:
            done.set()
