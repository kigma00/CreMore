"""Read-ahead of lazy collector objects on a small thread pool.

Only downloads leave the scan's owner thread. A reader's request guard, durable
budget charge and shared pacing call are handed to the owner, which runs them
while it waits; extraction, detection and every scan write (results, cache rows,
checkpoints, budget reservations, pacing) stay on the owner in listing order
(cremore.scanning.service).

One exception reaches the database from reader threads: an S3 read through the
worker's account-bound client (cremore_aws_provider.worker_session) re-checks the
account and its approval before each GET and around the body read (read-only
queries), and re-proves the worker identity about every 45 seconds, which writes
one setting. Per-request revocation is a security contract, so those checks stay
on the reader; each uses its own short repository transaction, never the scan's
fenced one, so a task runner holds about ``read_concurrency + 2`` pooled
connections (the readers, the owner and its lease heartbeat).
"""

from __future__ import annotations

import queue
import threading
from concurrent.futures import ThreadPoolExecutor

from cremore.collectors.base import owner_context

WINDOW = 16
MAX_BYTES = 256 << 20


class ReadAheadStopped(BaseException):
    """Unwinds a reader whose scan ended; not an Exception, so no collector swallows it."""


class OwnerCalls:
    """Readers hand callbacks to the owner thread and wait for their outcome."""

    def __init__(self):
        self.owner = threading.get_ident()
        self.queue = queue.SimpleQueue()
        self.stopped = threading.Event()

    def call(self, callback):
        if threading.get_ident() == self.owner:
            return callback()
        done, box = threading.Event(), []
        self.queue.put((callback, done, box))
        while not done.wait(0.1):
            if self.stopped.is_set():
                raise ReadAheadStopped()
        ok, value = box[0]
        if not ok:
            raise value
        return value

    def wake(self, _future=None):
        self.queue.put(None)

    def pump(self, timeout=0.0):
        """Run the callbacks readers wait on. An error goes back to the reader that asked,
        so it surfaces at that object, in listing order; an interrupt also stops the owner."""
        try:
            item = self.queue.get(timeout=timeout) if timeout else self.queue.get_nowait()
        except queue.Empty:
            return
        while True:
            if item is not None:
                callback, done, box = item
                try:
                    box.append((True, callback()))
                except BaseException as exc:
                    box.append((False, exc))
                    if not isinstance(exc, Exception):
                        raise
                finally:
                    done.set()
            try:
                item = self.queue.get_nowait()
            except queue.Empty:
                return


class ReadAhead:
    """Reads submitted and not yet taken. The scan service keeps them within WINDOW and,
    with what its listing itself downloaded, within one MAX_BYTES bound."""

    def __init__(self, concurrency):
        self.calls = OwnerCalls()
        self.pool = ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="scan-read")
        self.reads = {}  # future -> (object, the bytes it may hold before it is read)

    def held(self):
        """A finished read holds what it downloaded; one in flight, what it may download."""
        return sum(len(obj.data) if future.done() and obj.data is not None else estimate
                   for future, (obj, estimate) in self.reads.items())

    def submit(self, obj, size):
        # A fresh context per read: its guard, budget and pacing calls reach the owner.
        future = self.pool.submit(owner_context(self.calls.call).run, obj.read)
        self.reads[future] = (obj, max(0, int(size)))
        future.add_done_callback(self.calls.wake)
        return future

    def result(self, future, idle=None):
        """Wait for one read, serving reader callbacks (and ``idle``) meanwhile."""
        try:
            while not future.done():
                self.calls.pump(0.05)
                if idle is not None:
                    idle()
            return future.result()
        finally:
            self.reads.pop(future, None)

    def close(self):
        self.calls.stopped.set()
        for future in self.reads:
            future.cancel()
        self.pool.shutdown(wait=True, cancel_futures=True)
        self.reads.clear()
