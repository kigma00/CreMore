"""A scoped run: several per-resource collectors under one budget.

Each part is one approved root (a bucket with its prefixes, a repository at a
pinned ref, a set of Notion pages). One root that cannot be listed makes the run
partial; a run in which *no* root could be listed raises, so it is recorded as
failed and never as a clean, empty result. The byte and time budgets stop the
run rather than silently narrowing it: the stop is recorded in ``coverage``.

A lazy object is charged when it is read, never while it is listed: the scan's
detection cache answers for an unchanged object without a download, which spends
no bytes. One that no longer fits what is left stops before it is downloaded.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator

from cremore.collectors.base import (
    CollectedObject,
    Collector,
    CollectorError,
    RequestBudgetExceeded,
)


class ScopedCollector:
    # A collection of heterogeneous approved roots is not a whole connection.
    authoritative_listing = False

    def __init__(self, parts: list[Collector], *, budget_bytes: int | None = None,
                 budget_seconds: float | None = None, clock=time.monotonic) -> None:
        self.parts = list(parts)
        self.budget_bytes = budget_bytes
        self.budget_seconds = budget_seconds
        self.clock = clock
        self.objects = 0
        self.skipped = 0
        self.bytes = 0
        self.roots_failed = 0
        self.stopped: str | None = None
        # Lazy reads run on the scan's read-ahead threads and charge ``bytes`` there.
        self._lock = threading.Lock()

    @property
    def failed_objects(self) -> int:
        return self.roots_failed + sum(int(getattr(p, "failed_objects", 0) or 0) for p in self.parts)

    @property
    def requests(self) -> int:
        return sum(int(getattr(p, "requests", 0) or 0) for p in self.parts)

    @property
    def skipped_archived(self) -> int:
        return sum(int(getattr(p, "skipped_archived", 0) or 0) for p in self.parts)

    @property
    def skipped_unchanged(self) -> int:
        return sum(int(getattr(p, "skipped_unchanged", 0) or 0) for p in self.parts)

    @property
    def skipped_submodules(self) -> int:
        return sum(int(getattr(p, "skipped_submodules", 0) or 0) for p in self.parts)

    @property
    def skipped_objects(self) -> int:
        return self.skipped + sum(int(getattr(p, "skipped_objects", 0) or 0) for p in self.parts)

    def collect(self) -> Iterator[CollectedObject]:
        start = self.clock()
        errors: list[CollectorError] = []
        for part in self.parts:
            if self.stopped:
                break
            try:
                for obj in part.collect():
                    if self.budget_seconds is not None and self.clock() - start > self.budget_seconds:
                        self._stop("BUDGET_SECONDS")
                        break
                    size = len(obj.data) if obj.data is not None else int(obj.resource.size or 0)
                    with self._lock:
                        fits = self.budget_bytes is None or self.bytes + size <= self.budget_bytes
                        if fits:
                            self.objects += 1
                            if obj.data is not None:
                                self.bytes += size
                    if not fits:
                        self._stop("BUDGET_BYTES")
                        break
                    if obj.data is None and obj.loader is not None:
                        obj.loader = self._charged(obj.loader, size)
                    yield obj
            except RequestBudgetExceeded:
                self._stop("BUDGET_REQUESTS")
                break
            except CollectorError as exc:
                self.roots_failed += 1
                errors.append(exc)
        if self.parts and len(errors) == len(self.parts):
            raise errors[0]

    def _stop(self, reason):
        """The first stop is the run's, counted once, whichever thread meets it."""
        with self._lock:
            self._stop_locked(reason)

    def _stop_locked(self, reason):
        if self.stopped is None:
            self.stopped, self.skipped = reason, self.skipped + 1

    def _charged(self, loader, size):
        """A lazy read that reserves its listed size first and keeps what it actually read."""

        def read():
            with self._lock:
                # Reads ahead may have spent the room this object had when it was listed.
                if self.budget_bytes is not None and self.bytes + size > self.budget_bytes:
                    self._stop_locked("BUDGET_BYTES")
                    raise CollectorError("BUDGET_BYTES")
                self.bytes += size
            data = None
            try:
                data = loader()
                return data
            finally:
                with self._lock:
                    self.bytes += (len(data) if data is not None else 0) - size

        return read

    @property
    def coverage(self) -> dict:
        failed = self.failed_objects
        skipped = self.skipped_objects
        return {"attempted": self.objects + failed + skipped, "succeeded": self.objects, "failed": failed,
                "skipped": skipped, "skipped_archived": self.skipped_archived,
                "skipped_submodules": self.skipped_submodules,
                "skipped_unchanged": self.skipped_unchanged,
                "bytes": self.bytes, "requests": self.requests,
                "roots_failed": self.roots_failed, "stopped_reason": self.stopped}
