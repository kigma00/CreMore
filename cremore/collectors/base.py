"""Collector protocol and shared limits."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar, copy_context
from dataclasses import dataclass, field
from threading import Lock
from typing import Protocol

from cremore_aws_provider.aws_identity import (
    error_code as error_label,  # noqa: F401 -- compatibility export used by collectors
)

from cremore.detection import ResourceRef

# A single object exceeding this is skipped: a credential is small, and reading a
# multi-gigabyte artifact into memory is never worth it.
DEFAULT_MAX_OBJECT_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_REQUESTS = 10_000
MAX_CURSOR_BYTES = 8 * 1024
MAX_CURSOR_HISTORY = 10_000
# Raised for a request that must not wait while a provider's rate-limit cooldown holds its pace back.
RATE_LIMITED = "SOURCE_RATE_LIMITED"
# Raised instead when the provider answered 502/503/504 to a request that must not wait for a retry.
UNAVAILABLE = "SOURCE_UNAVAILABLE"
_request_guard = ContextVar("collector_request_guard", default=None)
_request_pacing = ContextVar("collector_request_pacing", default=None)
# Set only in a read-ahead thread's context (cremore.scanning.prefetch): hands a
# callback to the thread that owns the scan's database work and returns its result.
_owner_call = ContextVar("collector_owner_call", default=None)


def run_on_owner(callback):
    """Run ``callback`` on the scan's owner thread; directly when already there.

    Request guards, durable budgets and shared pacing open database transactions,
    which a read-ahead thread never does itself.
    """
    call = _owner_call.get()
    return callback() if call is None else call(callback)


def owner_context(call):
    """A copy of the current context whose guard, budget and pacing work goes through ``call``."""
    context = copy_context()
    context.run(_owner_call.set, call)
    return context


class _OwnerPacing:
    def __init__(self, pacing):
        self.pacing = pacing

    def request_delay(self, *args, **kwargs):
        return run_on_owner(lambda: self.pacing.request_delay(*args, **kwargs))


def request_pacing():
    """Worker-owned shared pacing store; interactive/offline clients use local pacing."""
    pacing = _request_pacing.get()
    # The shared pacing row is a database write: a read-ahead thread asks the owner.
    return pacing if pacing is None or _owner_call.get() is None else _OwnerPacing(pacing)


def check_request_guard() -> None:
    """Recheck cancellation/authorization while waiting, without spending a request."""
    if check := _request_guard.get():
        run_on_owner(check)


@contextmanager
def guard_requests(check, *, pacing=None):
    """Guard every shared budget, including budgets created during root discovery."""
    token = _request_guard.set(check)
    pacing_token = _request_pacing.set(pacing)
    try:
        yield
    finally:
        _request_guard.reset(token)
        _request_pacing.reset(pacing_token)


class RequestPacer:
    """At most one request per ``interval`` seconds for ``key`` (a digest, never a credential).

    Every process of the worker shares the spacing through the scan's pacing store when it
    set one (``request_pacing``); this process alone keeps it otherwise. ``defer(seconds)``
    holds every caller of the key back, as a provider's rate-limit cooldown asks. The request
    guard (cancellation, approval, the time budget) is checked again while waiting.
    """

    def __init__(self, key: str, interval: float, *, clock=time.monotonic, sleep=time.sleep) -> None:
        self.key, self.interval, self.clock, self.sleep = key, interval, clock, sleep
        self._lock = Lock()
        self._next = 0.0

    def acquire(self, *, wait_cooldown: bool = True) -> None:
        """Wait for this caller's slot. With ``wait_cooldown=False`` a cooldown raises
        CollectorError(RATE_LIMITED) instead of being waited out: a slot is never more than one
        interval away, so a longer wait (past one and a half, for clock rounding) is a cooldown."""
        while True:
            check_request_guard()
            shared = request_pacing()
            if shared is not None:
                delay = shared.request_delay(self.key, self.interval)
            else:
                with self._lock:
                    now = self.clock()
                    delay = self._next - now
                    if delay <= 0:
                        self._next = now + self.interval
            if delay <= 0:
                return
            if not wait_cooldown and delay > 1.5 * self.interval:
                raise CollectorError(RATE_LIMITED)
            # A pacing slot is a fraction of a second; a cooldown is waited out a second at a time.
            self.sleep(min(delay, 1.0))

    def defer(self, seconds: float) -> None:
        shared = request_pacing()
        if shared is not None:
            shared.request_delay(self.key, self.interval, cooldown=min(seconds, 3600))
            return
        with self._lock:
            self._next = max(self._next, self.clock() + seconds)


class NoWaitPacer:
    """The pace of a caller that must never wait (a change feed polled on the worker's control loop).

    With a ``RequestPacer`` an ordinary slot is still waited for, but a cooldown already holding its key
    back raises CollectorError(RATE_LIMITED) at once. ``waits`` is False, so bounded_request never sleeps
    for it: a rate limit ends the request through ``defer(seconds)``, which keeps the cooldown asked of
    every scan (``seconds`` > 0, with a ``RequestPacer``) and raises RATE_LIMITED; a busy server ends it
    through ``defer(0, busy=True)``, which raises UNAVAILABLE. Without a pacer (NO_WAIT) there is no slot
    to wait for and no shared cooldown to keep.
    """

    waits = False

    def __init__(self, pacer: RequestPacer | None = None) -> None:
        self.pacer = pacer

    def acquire(self) -> None:
        if self.pacer is not None:
            self.pacer.acquire(wait_cooldown=False)

    def defer(self, seconds: float, *, busy: bool = False) -> None:
        if self.pacer is not None and seconds > 0:
            self.pacer.defer(seconds)
        raise CollectorError(UNAVAILABLE if busy else RATE_LIMITED)


# The change-feed requests of a provider without a shared pace (ContentHTTP.pacer): never a wait.
NO_WAIT = NoWaitPacer()


_pacers: dict[tuple[str, float], RequestPacer] = {}
_pacers_lock = Lock()


def request_pacer(origin: str, credential: str, interval: float) -> RequestPacer:
    """This process's pacer for one provider origin and credential, keyed by their digest."""
    key = hashlib.sha256(f"{origin}\0{credential}".encode()).hexdigest()
    with _pacers_lock:
        pacer = _pacers.get((key, interval))
        if pacer is None:
            if len(_pacers) >= 1024:
                _pacers.clear()  # ponytail: a full registry starts over; a pacer holds one timestamp
            pacer = _pacers[(key, interval)] = RequestPacer(key, interval)
        return pacer


def path_under(path: str, roots: list[str]) -> bool:
    """Match an exact path or slash-delimited descendant without normalizing it."""
    return any(path == root or path.startswith(root.rstrip("/") + "/") for root in roots)


@dataclass
class CollectedObject:
    """One unit of content to scan and where it came from."""

    resource: ResourceRef
    data: bytes | None
    complete: bool = True
    loader: Callable[[], bytes | None] | None = None
    # The collector may already have counted this partially returned object.
    failure_counted: bool = False

    def read(self) -> bytes | None:
        """Load once; None means unreadable while an empty byte string is valid."""
        if self.data is None and self.loader is not None:
            loader, self.loader = self.loader, None
            self.data = loader()
        return self.data


class CollectorError(RuntimeError):
    """The scan scope could not be listed (bucket, repository tree, organisation,
    workspace search).

    Raised instead of silently yielding nothing, so a scan that never saw its
    scope is recorded as FAILED — never as a clean, empty COMPLETED run. ``code``
    is a stable identifier and ``detail`` a short safe label (an HTTP status or
    an exception/AWS error *name*), never a provider message.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def run_stop(exc) -> bool:
    """A spent budget, a cancelled run, or a sweep that yields to a waiting change scan
    (cremore.worker.runtime): it ends the run. It is never one unreadable object, nor a
    reason to read another way."""
    return isinstance(exc, CollectorError) and (
        exc.code.startswith("BUDGET_") or exc.code in ("RUN_CANCELLED", "YIELDED_TO_EVENT"))


class CursorHistory:
    """Bound opaque pagination cursors without retaining their raw history.

    Forks have independent cycle detection and share one aggregate admission
    count, including nested or sequential listings in the same collector.
    """

    def __init__(self):
        self._seen: set[bytes] = set()
        self._admitted = [0]

    def fork(self):
        history = CursorHistory()
        history._admitted = self._admitted
        return history

    def add(self, cursor):
        if not isinstance(cursor, str) or not cursor:
            raise CollectorError("SOURCE_CURSOR_INVALID")
        if len(cursor) > MAX_CURSOR_BYTES:
            raise CollectorError("SOURCE_CURSOR_LIMIT")
        try:
            raw = cursor.encode("utf-8")
        except UnicodeEncodeError:
            raise CollectorError("SOURCE_CURSOR_INVALID") from None
        if len(raw) > MAX_CURSOR_BYTES:
            raise CollectorError("SOURCE_CURSOR_LIMIT")
        digest = hashlib.sha256(raw).digest()
        if digest in self._seen:
            raise CollectorError("SOURCE_PAGINATION_LOOP")
        if self._admitted[0] >= MAX_CURSOR_HISTORY:
            raise CollectorError("SOURCE_CURSOR_LIMIT")
        self._admitted[0] += 1
        self._seen.add(digest)


class RequestBudgetExceeded(CollectorError):
    def __init__(self) -> None:
        super().__init__("BUDGET_REQUESTS")


@dataclass
class RequestBudget:
    """One request counter shared by every provider/root in a scan."""

    limit: int = DEFAULT_MAX_REQUESTS
    used: int = 0
    _lock: Lock = field(default_factory=Lock, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.limit <= 0:
            raise ValueError("request budget must be positive")

    def consume(self) -> None:
        check_request_guard()
        with self._lock:
            if self.used >= self.limit:
                raise RequestBudgetExceeded()
            self.used += 1


class Collector(Protocol):
    """Yields the objects in a scan scope.

    Listing the scope must succeed or raise :class:`CollectorError`. A single
    object that was listed but cannot be read is skipped and counted in
    ``failed_objects`` so the run is reported as partial, never as complete.

    Optional: ``read_concurrency`` (default 1) lets the scan service run that
    many lazy reads at once, which needs ``counts_read_failures`` (a lazy read
    returning None was already counted, with thread-safe counters). A worker
    root run passes the root's saved ``provider_state`` dict in
    ``root["provider_state"]`` and keeps a collector's ``provider_state`` after
    a complete whole-root run.
    """

    failed_objects: int
    authoritative_listing: bool

    def collect(self) -> Iterator[CollectedObject]: ...
