"""Scan service: run a scan over a collector's objects.

Ties any :class:`Collector` to the :class:`Orchestrator`. A single unreadable
object never fails the run — collectors skip and count those — so the summary
reflects what was actually scanned *and* what could not be. A scope that cannot
be listed raises :class:`~cremore.collectors.base.CollectorError` out of ``run``.

Listing runs a little ahead of inspection so cache lookups are batched and, for
collectors that allow it, downloads overlap (cremore.scanning.prefetch).
Extraction, detection and every write stay on the calling thread, in listing order.
"""

from __future__ import annotations

import time
import uuid
from collections import deque
from contextlib import nullcontext, suppress
from dataclasses import dataclass, field

from cremore.collectors.base import Collector, CollectorError, check_request_guard
from cremore.db.scan_store import ScanStore, stable_digest
from cremore.detection import ResourceRef
from cremore.detection.models import DetectorInput, SanitizedDetection
from cremore.scanning import prefetch
from cremore.scanning.extraction import DEFAULT_LIMITS, cache_digest, extract
from cremore.scanning.extraction.contract import RETRYABLE_REASONS
from cremore.scanning.orchestrator import Orchestrator, ScanResourceResult, scan_start
from cremore.scanning.prefetch import ReadAhead
from cremore.sources.registry import CACHED_SOURCES, CONTENT_ADDRESSED_SOURCES

# Extraction outcomes another attempt can change (PARSE_TIMEOUT, PARSER_UNAVAILABLE).
# Every other reason is fixed for the same bytes and extraction policy (the cache
# digest): never worth a re-read.
RETRYABLE_EXTRACTION_REASONS = RETRYABLE_REASONS
# Incomplete extractions without text that are limits or parser outcomes, not format skips.
_LIMIT_REASONS = frozenset({
    "INPUT_LIMIT", "TEXT_LIMIT", "EXPANSION_LIMIT", "MEMBER_SIZE_LIMIT", "MEMBER_LIMIT", "PAGE_LIMIT",
    "DEPTH_LIMIT", "PARSE_TIMEOUT", "PARSER_RESOURCE_LIMIT", "PARSER_FAILURE", "PARSER_UNAVAILABLE",
})
# A parser that crashed is not retried in a loop, but its outcome is never cached
# either: unlike a format's own limits, the next full scan reads the object again.
_PARSER_CRASHES = frozenset({"PARSER_RESOURCE_LIMIT", "PARSER_FAILURE"})
# Objects listed, and looked up in the cache together, ahead of inspection.
LOOKAHEAD = 64
# Trivially clean objects that share one write transaction.
BATCH_OBJECTS = 64
BATCH_SECONDS = 1.0


@dataclass
class ScanSummary:
    objects: int = 0
    detections: int = 0
    findings: int = 0
    # Listed objects that were unreadable or not fully scanned (e.g. the detection
    # cap was reached). Format skips are counted below, not here.
    objects_failed: int = 0
    # Every exposure this run saw; a complete run retires the connection's others.
    exposure_ids: set = field(default_factory=set)
    timings: dict = field(
        default_factory=lambda: {
            "listing_seconds": 0.0,
            "download_seconds": 0.0,
            "extraction_seconds": 0.0,
            "engine_seconds": 0.0,
            "persistence_seconds": 0.0,
        }
    )
    reused: int = 0
    existing_locations_seen: set = field(default_factory=set)
    skipped_unsupported: int = 0  # unknown, encrypted or malformed documents
    skipped_media: int = 0  # raster images
    extraction_reasons: dict[str, int] = field(default_factory=dict)
    # Scanned, but a fixed extraction limit left part of the object uninspected.
    partially_inspected: int = 0


@dataclass(eq=False)
class Outcome:
    """One inspected object, committed in listing order.

    ``complete`` False makes it a retry candidate. ``skip`` is UNREADABLE (nothing
    was read) or a format skip (MEDIA_FORMAT, UNSUPPORTED_FORMAT); either way there
    is no ``result``. ``gap`` names the fixed reason it was not fully inspected,
    ``reused`` means the cache answered and nothing was downloaded for it, and
    ``inspected_at`` (monotonic) is when its inspection ended.
    """

    resource: ResourceRef
    result: ScanResourceResult | None = None
    complete: bool = True
    skip: str | None = None
    gap: str | None = None
    reused: bool = False
    inspected_at: float = field(default_factory=time.monotonic)
    # What the write transaction persists; private to the service. No extracted
    # text is kept: detections are computed before persistence.
    detections: list | None = None
    row: dict | None = None
    counted: bool = False


@dataclass(eq=False)
class _Listed:
    obj: object
    key: tuple | None = None  # (root id, subject, revision) when the cache may answer
    hit: dict | None = None
    future: object = None


def _describe(resource, fmt, reason):
    if fmt != "text" or reason:
        resource.metadata["document_format"] = fmt
        resource.metadata["document_extraction_status"] = reason or "COMPLETE"


class ScanService:
    def __init__(self, orchestrator: Orchestrator, *, extraction_limits=DEFAULT_LIMITS) -> None:
        self.orchestrator = orchestrator
        self.extraction_limits = extraction_limits

    def run(
        self,
        collector: Collector,
        *,
        source_connection_id: uuid.UUID | None = None,
        scan_id: uuid.UUID | None = None,
        verify: bool | None = None,
        verify_config=None,
        reconcile_objects: bool = False,
        before_write=None,
        write_context=None,
        object_committed=None,
        progress=None,
        watched_locations=(),
        object_skipped=None,
        commit_objects=None,
        batchable=None,
        bytes_left=None,
    ) -> ScanSummary:
        """Scan every listed object; per-object writes share the caller's ``write_context``.

        ``commit_objects(repo, outcomes)`` replaces ``object_committed`` and
        ``object_skipped``: inside the write transaction it applies the objects'
        own effects in order and returns how many the caller's budgets admit (the
        rest are committed alone, so the first of them stops as a single commit
        would). With ``batchable(resource)``, trivially clean objects share one
        transaction. ``bytes_left()`` (None: unbounded) keeps reads ahead and pending
        batches within a byte budget, so its last objects are read in order as before.
        """
        progress = progress or check_request_guard
        started_at = scan_start(self.orchestrator.repo, scan_id)
        summary = ScanSummary()
        finding_ids: set = set()
        store = ScanStore(self.orchestrator.repo) if source_connection_id is not None else None
        watched_locations = set(watched_locations)
        engine = self.orchestrator.engine
        engine_digest = getattr(engine, "detection_digest", "")
        digest = cache_digest(engine_digest, limits=self.extraction_limits) if engine_digest else ""
        # Live verification re-reads whatever has detections; a clean row needs no check.
        verifying = bool((verify_config or engine.config.verify).enabled and verify is not False)
        parts = getattr(collector, "parts", None) or [collector]
        # Concurrent reads need collectors that count their own read failures:
        # diffing shared counters around a read only works one read at a time.
        counted = all(getattr(part, "counts_read_failures", False) for part in parts)
        concurrency = min(int(getattr(part, "read_concurrency", 1) or 1) for part in parts) if counted else 1
        budget = getattr(parts[0], "request_budget", None)
        iterator = iter(collector.collect())
        reader = ReadAhead(concurrency) if concurrency > 1 else None
        # Without read-ahead a collector is consumed one object at a time, exactly as before.
        lookahead = LOOKAHEAD if reader is not None else 1
        listed: deque[_Listed] = deque()
        batch: list[Outcome] = []
        incomplete = 0
        previous_root, root_id = None, ""
        listed_all, listing_error = False, None
        batch_started = 0.0

        def list_ahead():
            # Collectors emit adjacent objects from one root. Keep only that root's
            # identity: constant memory, no cross-run or cross-connection reuse.
            nonlocal listed_all, listing_error, previous_root, root_id
            fresh = []
            room = capacity() - held_bytes()
            # Collectors that download while listing (exact keys, retries) stop at the shared
            # bound; one entry is always listed when nothing waits.
            while len(listed) + len(fresh) < lookahead and (room > 0 or not (listed or fresh)):
                progress()
                started = time.monotonic()
                try:
                    obj = next(iterator)
                except StopIteration:
                    listed_all = True
                    break
                except Exception as exc:  # noqa: BLE001 -- re-raised once the objects listed before it are done
                    listed_all, listing_error = True, exc
                    break
                finally:
                    summary.timings["listing_seconds"] += time.monotonic() - started
                resource = obj.resource
                location_key = (resource.source_type, resource.resource or resource.location, resource.location)
                if location_key in watched_locations:
                    summary.existing_locations_seen.add(location_key)
                entry = _Listed(obj)
                revision = resource.revision
                # A source whose revision names an object's content (blob id, generation, ETag,
                # attachment version) is cached: an unchanged object is neither read nor scanned again.
                if store and revision and digest and resource.source_type in CACHED_SOURCES:
                    root = (resource.source_type, resource.metadata.get("page_id") or resource.resource)
                    if root != previous_root:
                        root_id = stable_digest([str(source_connection_id), *root])
                        previous_root = root
                    # A git blob id names content wherever it sits; any other revision is per location.
                    subject = revision if resource.source_type in CONTENT_ADDRESSED_SOURCES else resource.location
                    entry.key = (root_id, subject, revision)
                if getattr(obj, "data", None) is not None:
                    room -= len(obj.data)
                fresh.append(entry)
            keys = [entry.key for entry in fresh if entry.key is not None]
            rows = store.cached_many(source_connection_id, keys, digest) if keys else {}
            for entry in fresh:
                hit = rows.get(entry.key) if entry.key is not None else None
                if hit is not None and not (verifying and (hit["detections"] or hit["skip"])):
                    entry.hit = hit
            listed.extend(fresh)

        def cost(entry):
            # Bytes an object spends: none when the cache answers before any download, or when
            # its read ahead already failed (an unreadable object spends nothing).
            obj = entry.obj
            if getattr(obj, "data", None) is None and (
                    entry.hit is not None or (entry.future is not None and entry.future.done())):
                return 0
            return max(0, int(obj.resource.size or 0))

        def pending_bytes():
            return sum(0 if o.reused else int(o.resource.size or 0) for o in batch)

        def held_bytes():
            # One bound for all bytes read and not yet inspected: what the listing downloaded,
            # and the reads ahead (a finished one its bytes, one in flight its estimate).
            listing = sum(len(e.obj.data) for e in listed
                          if e.future is None and getattr(e.obj, "data", None) is not None)
            return listing + (reader.held() if reader is not None else 0)

        def capacity():
            """What may be held in all: the read-ahead bound, within what the byte budget has left."""
            left = bytes_left() if bytes_left is not None else None
            return prefetch.MAX_BYTES if left is None else min(prefetch.MAX_BYTES, left - pending_bytes())

        def start_reads():
            room = capacity() - held_bytes()
            limit = int(getattr(parts[0], "max_object_bytes", 0) or 0)
            for entry in listed:
                obj = entry.obj
                if (entry.future is not None or entry.hit is not None
                        or getattr(obj, "data", None) is not None or getattr(obj, "loader", None) is None):
                    continue
                known = max(0, int(obj.resource.size or 0))
                # A size the listing did not give is held as large as the object limit allows.
                size = known or limit
                # Near a budget's end the owner reads in order, as a serial scan did: read ahead
                # only what the remaining requests and bytes still cover (an unknown size alone).
                if (len(reader.reads) >= prefetch.WINDOW
                        or (budget is not None and budget.limit - budget.used <= len(reader.reads))
                        or (size > room and (known or held_bytes() > 0))):
                    return
                entry.future = reader.submit(obj, size)
                room -= size

        def row_key(entry):
            resource = entry.obj.resource
            # S3 GET may observe a newer revision than the preceding LIST; the row names what was read.
            if entry.key is None or not resource.revision:
                return None
            subject = resource.revision if resource.source_type in CONTENT_ADDRESSED_SOURCES else resource.location
            return (entry.key[0], subject, resource.revision)

        def count_skip(skip):
            if skip == "MEDIA_FORMAT":
                summary.skipped_media += 1
            else:
                summary.skipped_unsupported += 1

        def note_reason(reason):
            if reason:
                summary.extraction_reasons[reason] = summary.extraction_reasons.get(reason, 0) + 1

        def inspect(entry):
            nonlocal incomplete
            obj, hit = entry.obj, entry.hit
            resource = obj.resource
            if hit is not None:
                summary.reused += 1
                reason = next(iter(hit["reasons"]), "")
                _describe(resource, hit["format"], reason)
                note_reason(reason)
                # Bytes a listing already downloaded (exact keys, retries) are spent all the same.
                reused = getattr(obj, "data", None) is None
                if hit["skip"]:
                    count_skip(hit["skip"])
                    return Outcome(resource, skip=hit["skip"], gap=reason or hit["skip"], reused=reused)
                return Outcome(resource, complete=getattr(obj, "complete", True), gap=reason or None, reused=reused,
                               detections=[SanitizedDetection(**item) for item in hit["detections"]],
                               counted=getattr(obj, "failure_counted", False))
            started = time.monotonic()
            read = getattr(obj, "read", None)
            changed = False
            if entry.future is not None:
                data = reader.result(entry.future, idle=flush_due)
            elif counted or read is None:
                data = read() if read is not None else obj.data
            else:
                skipped_before = int(getattr(collector, "skipped_objects", 0) or 0)
                failed_before = int(getattr(collector, "failed_objects", 0) or 0)
                data = read()
                changed = (int(getattr(collector, "skipped_objects", 0) or 0) != skipped_before
                           or int(getattr(collector, "failed_objects", 0) or 0) != failed_before)
            summary.timings["download_seconds"] += time.monotonic() - started
            if data is None:
                if not (counted or changed or getattr(obj, "failure_counted", False)):
                    incomplete += 1
                return Outcome(resource, complete=False, skip="UNREADABLE")
            started = time.monotonic()
            extracted = extract(data, filename=resource.location, limits=self.extraction_limits, progress=step)
            summary.timings["extraction_seconds"] += time.monotonic() - started
            if extracted.format != "text" or not extracted.complete:
                resource.metadata["document_format"] = extracted.format
                resource.metadata["document_extraction_status"] = extracted.reason or "COMPLETE"
            note_reason(extracted.reason)
            # A reason a cache row keeps is always a gap: incomplete, and fixed for these bytes.
            reasons = {extracted.reason: 1} if extracted.reason and not extracted.complete else {}
            if not extracted.data and not extracted.complete and extracted.reason not in _LIMIT_REASONS:
                # Explicit skips preserve earlier exposures and never establish absence;
                # the same bytes skip the same way, so the skip itself is reused.
                skip = "MEDIA_FORMAT" if extracted.format == "image" else "UNSUPPORTED_FORMAT"
                count_skip(skip)
                key = row_key(entry)
                # A live-verification run writes clean rows only, never a skip.
                row = ({"key": key, "detections": [], "reasons": reasons, "fmt": extracted.format}
                       if key and not verifying else None)
                return Outcome(resource, skip=skip, gap=extracted.reason or skip, row=row)
            started = time.monotonic()
            detections = engine.scan(DetectorInput(extracted.data, resource, verify=verify, verify_config=verify_config))
            summary.timings["engine_seconds"] += time.monotonic() - started
            # Provider context reads stay outside the fenced write. They
            # may invalidate completeness and revision before persistence.
            if refiner := getattr(obj, "refine_detections", None):
                started = time.monotonic()
                detections = refiner(detections)
                summary.timings["download_seconds"] += time.monotonic() - started
            retry = not extracted.complete and extracted.reason in RETRYABLE_EXTRACTION_REASONS
            gap = extracted.reason if not extracted.complete and not retry else None
            complete = getattr(obj, "complete", True) and getattr(detections, "complete", True) and not retry
            key = row_key(entry)
            row = None
            if (complete and key and not (verifying and detections)
                    and extracted.reason not in _PARSER_CRASHES):
                row = {"key": key, "detections": detections, "reasons": reasons, "fmt": extracted.format}
            # Read after refinement: a provider that counted its own partial refinement says so here.
            return Outcome(resource, complete=complete, gap=gap, detections=detections,
                           row=row, counted=getattr(obj, "failure_counted", False))

        def account(outcome):
            nonlocal incomplete
            if outcome.skip is not None:
                return
            result = outcome.result
            summary.objects += 1
            summary.timings["persistence_seconds"] += result.timings["persistence_seconds"]
            if not outcome.complete and not outcome.counted:
                incomplete += 1
            if outcome.gap:
                summary.partially_inspected += 1
            summary.detections += result.detections
            summary.exposure_ids.update(result.exposure_ids)
            finding_ids.update(finding.id for finding in result.findings)

        def commit(outcomes):
            # No provider I/O or detector work is done while holding the lease
            # row. All derived writes and progress share its fenced transaction.
            scanned = [o for o in outcomes if o.skip is None]
            if not (commit_objects or scanned or object_skipped or any(o.row for o in outcomes)):
                return
            if scanned and before_write is not None:
                before_write()
            count = len(outcomes)
            with write_context() if write_context else nullcontext(self.orchestrator.repo) as repo:
                orchestrator = self.orchestrator.using(repo)
                for o in scanned:
                    if o.result is None:
                        o.result = orchestrator.scan_resource(
                            b"", o.resource, source_connection_id=source_connection_id, scan_id=scan_id,
                            verify=verify, verify_config=verify_config, detections=o.detections,
                            scan_started_at=started_at)
                if commit_objects is not None:
                    count = commit_objects(repo, outcomes)
                bound = store if repo is self.orchestrator.repo else None
                for o in outcomes[:count]:
                    if o.row is not None:
                        bound = bound or ScanStore(repo)
                        bound.cache(source_connection_id, *o.row["key"], digest, o.row["detections"],
                                    skip=o.skip, reasons=o.row["reasons"], fmt=o.row["fmt"])
                    if o.skip is None:
                        if reconcile_objects:
                            # A partially inspected object is never evidence that a match is gone.
                            orchestrator.reconcile_resource(
                                source_connection_id, o.resource, o.result.exposure_ids,
                                complete=o.complete and o.gap is None, scan_id=scan_id,
                                scan_started_at=started_at,
                            )
                        if commit_objects is None and object_committed is not None:
                            object_committed(repo, o.resource, o.result, o.complete)
                    elif commit_objects is None and object_skipped is not None:
                        object_skipped(repo, o.resource, o.skip)
            for o in outcomes[:count]:
                account(o)
            for o in outcomes[count:]:
                commit([o])

        def flush_batch():
            nonlocal batch
            pending, batch = batch, []
            if pending:
                commit(pending)

        def flush_due():
            if batch and time.monotonic() - batch_started >= BATCH_SECONDS:
                flush_batch()

        def step():
            # Extraction's progress: a batch that aged while a slow object parses
            # commits now, and readers waiting on the owner are served.
            flush_due()
            if reader is not None:
                reader.calls.pump()
            progress()

        try:
            while True:
                if not listed_all and len(listed) <= lookahead // 2:
                    list_ahead()
                if reader is not None:
                    start_reads()
                if not listed:
                    break
                entry = listed.popleft()
                flush_due()
                left = bytes_left() if bytes_left is not None else None
                if left is not None and pending_bytes() + cost(entry) > left:
                    # What fits commits first; an object the rest of the byte budget cannot
                    # take then stops the run before it is read, and the next run resumes there.
                    flush_batch()
                    if cost(entry) > bytes_left():
                        raise CollectorError("BUDGET_BYTES")
                outcome = inspect(entry)
                # Batching cannot let a stale clean read retire an exposure another run just
                # recorded: one root's tasks never run at once (the per-root lock key), so no
                # event run writes this root between a batched read and its commit.
                if (batchable is not None and commit_objects is not None and outcome.complete
                        and outcome.skip != "UNREADABLE" and not outcome.detections
                        and batchable(outcome.resource)):
                    if not batch:
                        batch_started = time.monotonic()
                    batch.append(outcome)
                    if len(batch) >= BATCH_OBJECTS:
                        flush_batch()
                else:
                    flush_batch()
                    commit([outcome])
                if reader is not None:
                    reader.calls.pump()
            flush_batch()
            if listing_error is not None:
                raise listing_error
        except BaseException:
            # Objects inspected before a stop are committed first, as one-by-one
            # commits had them; a lost lease or cancellation refuses this write too.
            # Whatever that commit meets, the caller sees the stop that ended the run.
            with suppress(Exception):
                flush_batch()
            raise
        finally:
            if reader is not None:
                reader.close()
            if close := getattr(iterator, "close", None):
                close()
        summary.findings = len(finding_ids)
        summary.objects_failed = incomplete + int(getattr(collector, "failed_objects", 0) or 0)
        return summary
