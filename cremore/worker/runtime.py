"""Leased root execution on the existing database queue.

Provider reads happen outside transactions. Only short, lease-fenced result,
audit, cache and checkpoint writes commit. Queue payloads contain references
and approved paths, never resolved tokens or downloaded content.
"""

from __future__ import annotations

import copy
import datetime as dt
import json
import logging
import math
import threading
import time
import uuid
from contextlib import contextmanager

from cremore.collectors.base import (
    CollectorError,
    RequestBudget,
    RequestBudgetExceeded,
    guard_requests,
    path_under,
    run_on_owner,
)
from cremore.db.scan_store import ScanStore, stable_digest
from cremore.scanning import scope
from cremore.scanning.scope import root_identity, split_roots
from cremore.scanning.service import ScanService
from cremore.source_config import RESOURCE_SOURCE
from cremore.sources.registry import BY_RESOURCE_TYPE
from cremore.task_state import safe_task_state

OVERLAP = dt.timedelta(minutes=5)
FAILURE_KEY_LIMIT = 10_000
FAILURE_BYTES_LIMIT = 256_000
LEASE_SECONDS = 120
# Requests reserved per fenced checkpoint write: a crash over-counts at most this many.
RESERVE_REQUESTS = 64
# Cancellation and approval are re-read at most this often between writes.
CHECK_SECONDS = 1.0
PROVIDER_STATE_BYTES = 65_536
# A resumable sweep looks this often for a change scan of its root waiting behind it, and yields to one.
YIELD_SECONDS = 5.0
YIELD_CODE = "YIELDED_TO_EVENT"
# A sweep that gave way ends as a resumed run, which settles removals after the key it resumed from (before it, only
# those a 404 confirms, and a bounded number of HEADs checks) and replaces no gaps. It gives way only on a root whose
# last whole full scan is this recent, so on a root with a steady stream of events (and on its first scan) a sweep still
# runs through at least this often.
YIELD_RECONCILE_SECONDS = 3 * 86400
# A Notion page root's search entry: these text fields, at most this large (cremore_notion_provider.search bounds
# url and title well below it).
PAGE_META_FIELDS = frozenset({"url", "title", "last_edited_time", "observed_at"})
PAGE_META_BYTES = 8192
# A Notion plan's search walk saves the time it walked at least this often between its request reservations: a crash
# loses at most this much of it, and one request's.
WALK_SAVE_SECONDS = 5.0
# The counts a root task's checkpoint keeps across attempts, reported by a run that stops (or skips) before it ends.
STOP_COUNTS = ("objects", "findings", "requests", "bytes", "skipped_unsupported", "skipped_media", "extraction_reasons",
               "partially_inspected", "detection_policy_digest", "engine_name", "engine_version", "policy_held")
# The sources whose DELTA reads only what changed since root["watermark_since"] (S3Collector, NotionCollector). Every
# other DELTA lists the whole root and reads again whatever the revision cache, keyed by the detection policy, does not
# answer (Bitbucket's diff included), or has no cache at all.
WATERMARK_DELTA_TYPES = frozenset({"S3_BUCKET", "NOTION_PAGE", "NOTION_DATA_SOURCE"})
logger = logging.getLogger("cremore.worker")


def failure_state(keys, *, overflow=False):
    """Bound sensitive retry metadata; losing any key requires a full resweep."""
    kept, size = [], 0
    for key in sorted(set(keys)):
        size += len(json.dumps(key).encode()) + 2
        if len(kept) >= FAILURE_KEY_LIMIT or size > FAILURE_BYTES_LIMIT:
            overflow = True
            break
        kept.append(key)
    return {"failed_keys": kept, "retry_overflow": bool(overflow)}


def gap_list(gaps):
    """Bound the [key, reason] pairs kept for gap reports like retry keys; True when cut short."""
    kept, size = [], 0
    for key, reason in sorted(gaps.items()):
        size += len(json.dumps([key, reason]).encode()) + 2
        if len(kept) >= FAILURE_KEY_LIMIT or size > FAILURE_BYTES_LIMIT:
            return kept, True
        kept.append([key, reason])
    return kept, False


def _gaps_seen(state):
    """A root's inspection gaps as a digest: whether another run of the root changed them since a task began."""
    return stable_digest([state.get("inspection_gaps") or [], bool(state.get("inspection_gaps_overflow"))])


def _bounded_state(value):
    """A collector's provider_state as kept: a small JSON object free of content and secret fields."""
    if not isinstance(value, dict):
        return None
    try:
        value = safe_task_state(value)
    except (TypeError, ValueError):
        return None
    return value if len(json.dumps(value)) <= PROVIDER_STATE_BYTES else None


def _resumable(payload):
    root = payload["scope"]
    return (root["resource_type"] == "S3_BUCKET"
            and "exact_keys" not in root
            and payload.get("mode") not in ("EVENT", "INVENTORY")
            and payload["job_payload"].get("trigger") not in ("EVENT", "RESCAN"))


def _inside(root, exposure):
    """Used only on already approved roots; excludes are stronger than includes."""
    rt, location = root["resource_type"], exposure.location
    module = BY_RESOURCE_TYPE.get(rt)
    if module is not None and module.SCOPE_KIND == "object":
        return (
            exposure.source_type == RESOURCE_SOURCE[rt]
            and exposure.resource_name == root["provider_resource_id"]
            and not any(location.startswith(p) for p in root.get("excluded_prefixes") or [])
            and (
                root.get("all_current_objects")
                or any(location.startswith(p) for p in root.get("prefixes") or [])
            )
        )
    if module is not None and module.SCOPE_KIND == "path":
        return (
            exposure.source_type == RESOURCE_SOURCE[rt]
            and exposure.resource_name == root["provider_resource_id"]
            and not path_under(location, root.get("excluded_paths") or [])
            and (not root.get("paths") or path_under(location, root["paths"]))
        )
    page_id = str(root["provider_resource_id"]).replace("-", "").lower()
    return exposure.source_type == "notion" and exposure.metadata.get("page_id") == page_id


class ScanRuntime:
    def __init__(self, worker):
        from cremore.db.task_store import TaskStore

        self.worker, self.repo = worker, worker.repo
        self.tasks = TaskStore(self.repo)

    def validate(self, job, repo=None):
        if getattr(self.worker, "aws_content_sessions", None) is not None:
            self.worker.aws_content_sessions.require_current(job, repo)
        locked = repo is not None
        repo = repo or self.repo
        from cremore.onboarding.store import child_feature_enabled

        kind = job.payload.get("connection_kind", "source") if job.kind == "scope" else "aws" if job.kind == "s3" else "source"
        if job.connection_id and not child_feature_enabled(repo, kind, job.connection_id, "exposure"):
            raise CollectorError("CONNECTION_PAUSED")
        if job.kind != "scope":
            if job.connection_id:
                conn = repo.get_connection(job.connection_id, for_update=locked)
                if conn is not None and (
                    conn.status == "DISABLED" or (conn.credential_evidence or {}).get("revoked_at")
                ):
                    raise CollectorError("CONNECTION_PAUSED")
                if conn is not None and conn.secret_ref != (job.payload or {}).get("secret_ref"):
                    raise CollectorError("CONNECTION_CREDENTIAL_CHANGED")
            return
        p = job.payload
        plan = repo.get_plan(uuid.UUID(p["plan_id"]))
        profile = repo.get_scope_profile(uuid.UUID(p["profile_id"]))
        target = (
            repo.get_aws_account(job.connection_id)
            if p["connection_kind"] == "aws"
            else repo.get_connection(job.connection_id, for_update=locked)
        )
        if plan is None or profile is None or target is None:
            raise CollectorError("SCOPE_PLAN_STALE")
        scope.validate_execution(plan, profile, target)
        if p.get("auth_revision", plan.auth_revision) != plan.auth_revision:
            raise CollectorError("SCOPE_PLAN_STALE")

    def plan(self, job, task):
        """Root membership and seed completion are atomic, so a crash can't lose shards."""
        from cremore.db.task_store import TaskStore

        self.validate(job)
        roots = split_roots(job.payload.get("roots") or [])
        if not roots:
            raise CollectorError("NO_TARGETS_SELECTED")
        budgets = dict(job.payload.get("budgets") or {"requests": 10_000})
        # A Notion run first reads its pages' headers in one search walk, paid from the run's requests and seconds:
        # the root shares come from what it left.
        meta, spent, took = self._page_metadata(job, task, roots, budgets)
        if spent and "requests" in budgets:
            budgets["requests"] = max(0, int(budgets["requests"]) - spent)
        if took and "seconds" in budgets:
            # Never below a second a root, as the walk leaves each root a request (nor above the approved total).
            total = int(budgets["seconds"])
            budgets["seconds"] = max(min(total, len(roots)), total - math.ceil(took))
        with self.tasks.fenced(task["id"], task["token"]) as repo:
            self.validate(job, repo)
            tasks = TaskStore(repo)
            for index, root in enumerate(roots):
                # Fixed shares reserve no more than the approved run total,
                # even when different workers claim roots concurrently.
                share = {
                    k: int(v) // len(roots) + (index < int(v) % len(roots))
                    for k, v in budgets.items()
                }
                base = {k: v for k, v in job.payload.items() if k not in ("roots", "budgets")}
                mode = str(base.get("mode", "BASELINE")).upper()
                if mode == "EVENT" and not root.get(scope.EXACT_FIELDS[root["resource_type"]]):
                    # Legacy RESUME jobs dropped event targets. Never turn a
                    # missing exact target into an empty successful inspection.
                    raise CollectorError("EVENT_EXACT_TARGET_REQUIRED")
                scoped, page = root, str(root["provider_resource_id"]).replace("-", "").lower()
                if page in meta:
                    # Its own page's entry only: the collector skips that page's header read.
                    scoped = {**root, "page_meta": {page: meta[page]}}
                payload = {
                    "mode": mode,
                    "scope": scoped,
                    "job_payload": base,
                    "budgets": share,
                    "connection_lock": str(job.connection_id),
                    "lock_key": stable_digest(
                        [
                            str(job.connection_id),
                            root["resource_type"],
                            root["provider_resource_id"],
                        ]
                    ),
                }
                root_id = root_identity(job.connection_id, root)
                # A change feed that saw history rewritten asks for the root from scratch.
                if base.get("trigger") == "EVENT" and mode != "BASELINE":
                    payload["mode"] = "EVENT"
                    payload["keys"] = (
                        root.get("exact_keys")
                        or root.get("exact_paths")
                        or root.get("exact_page_ids")
                        or []
                    )
                    payload["full_delta"] = mode == "DELTA"
                    payload["scope"] = {
                        k: v
                        for k, v in root.items()
                        if k not in ("exact_keys", "exact_paths", "exact_page_ids")
                    }
                    payload["not_before"] = base.get("not_before")
                    payload["job_payload"] = {
                        k: v
                        for k, v in base.items()
                        if k
                        not in ("plan_id", "policy_digest", "not_before", "requested_by", "mode")
                    }
                    # Per-profile budget/approval identity may not be merged with
                    # another administrator's independently approved scope.
                    root_id = stable_digest([root_id, base.get("event_coalesce_key"), share])
                state = ScanStore(repo).root(root_identity(job.connection_id, root))
                priority = int(root.get("priority", 0))
                if base.get("trigger") == "EVENT":
                    priority += 200
                if (
                    state
                    and state.get("detection_digest")
                    != self.worker.orchestrator.detection_policy_digest
                ):
                    priority = -1000
                tasks.enqueue(job.id, root_id, payload, priority=priority, start_key="")
            result = {"planned_roots": len(roots), **({"requests": spent} if spent else {})}
            tasks.finish(task["id"], task["token"], result)

    def _page_metadata(self, job, task, roots, budgets):
        """``(headers by page id, requests spent, seconds taken)`` from one search walk of a Notion run's approved
        pages before the run is planned (cremore_notion_provider.source.plan_metadata).

        Only a full or incremental run walks, never a change scan, and only while the run's request budget leaves
        every root one request; running out of it ends the walk with what it found. Requests are reserved in the
        plan task's checkpoint before they are sent, and the time walked so far is saved with each reservation and
        before a request once WALK_SAVE_SECONDS passed since the last save: a plan run again after a crash never charges
        the run fewer requests than it spent, nor less time than it walked but that interval and one request's, and
        never charges the first walk twice. A credential or network failure leaves the pages to read their own headers;
        the run's own stop (cancelled, paused, a lost lease) propagates.
        """
        from cremore.db.task_store import LeaseLost, TaskStore

        p = job.payload or {}
        mode = str(p.get("mode", "BASELINE")).upper()
        pages = [root for root in roots if root["resource_type"] in ("NOTION_PAGE", "NOTION_DATA_SOURCE")]
        read = getattr(self.worker, "plan_reader", None)
        hook = getattr(BY_RESOURCE_TYPE.get("NOTION_PAGE"), "plan_metadata", None)
        saved = task.get("checkpoint") or {}
        prior, prior_seconds = int(saved.get("requests", 0)), float(saved.get("seconds", 0))
        limit = int(budgets.get("requests", 0)) - len(roots) - prior
        # The walk leaves every root a second, as it leaves each a request.
        seconds_left = int(budgets["seconds"]) - len(roots) if "seconds" in budgets else None
        if (mode not in ("BASELINE", "RECONCILE", "DELTA") or (p.get("trigger") == "EVENT" and mode != "BASELINE")
                or not pages or read is None or hook is None or limit <= 0
                or (seconds_left is not None and prior_seconds >= seconds_left)):
            return {}, prior, prior_seconds
        runtime, checked, refused, started = self, [None], [], time.monotonic()

        def check():
            if seconds_left is not None and prior_seconds + time.monotonic() - started >= seconds_left:
                raise RequestBudgetExceeded()  # ends the walk with what it found, as its request budget does
            # Cancellation, approval and the lease, at most once a second, as a root's reads re-read them.
            if checked[0] is None or time.monotonic() - checked[0] >= CHECK_SECONDS:
                try:
                    with runtime.tasks.fenced(task["id"], task["token"]) as repo:
                        runtime.validate(job, repo)
                except Exception as exc:
                    refused.append(exc)
                    raise
                checked[0] = time.monotonic()

        class Reserved(RequestBudget):
            reserved, saved_at = 0, started

            def consume(self):
                super().consume()
                now = time.monotonic()
                if self.used > self.reserved or now - self.saved_at >= WALK_SAVE_SECONDS:
                    if self.used > self.reserved:
                        grant = min(RESERVE_REQUESTS, max(1, (self.limit - self.used) // 16))
                        self.reserved = min(self.limit, self.used + grant)
                    with runtime.tasks.fenced(task["id"], task["token"]) as repo:
                        TaskStore(repo).checkpoint(task["id"], task["token"], {
                            "requests": prior + self.reserved, "seconds": prior_seconds + now - started})
                    self.saved_at = now

        budget = Reserved(limit)
        try:
            with guard_requests(check, pacing=ScanStore(self.repo)):
                found = read(job, hook, pages, budget)
        except LeaseLost:
            raise
        except Exception as exc:  # metadata only saves header reads: without it each page reads its own
            if refused:
                raise  # the run's own refusal (paused, a stale approval) stops the plan, as its fenced check would
            code = exc.code if isinstance(exc, CollectorError) else type(exc).__name__
            logger.warning("run %s plans without page metadata: %s", job.id, code)
            found = {}
        # Only what a page root may carry, values as the walk gave them; anything else reads its own header.
        meta = {page: entry for page, entry in (found.items() if isinstance(found, dict) else ())
                if isinstance(page, str) and isinstance(entry, dict) and entry.keys() <= PAGE_META_FIELDS
                and all(isinstance(value, str) for value in entry.values())
                and len(json.dumps(entry)) <= PAGE_META_BYTES}
        return meta, prior + budget.used, prior_seconds + time.monotonic() - started

    @contextmanager
    def keep_lease(self, task):
        stop = threading.Event()

        def renew():
            while not stop.wait(LEASE_SECONDS / 3):
                try:
                    self.tasks.heartbeat(task["id"], task["token"], lease_seconds=LEASE_SECONDS)
                    self.worker.beat(getattr(self.worker.settings, "worker_heartbeat_file", None))
                except Exception:  # noqa: BLE001 -- stop renewal; transaction fence rejects every late write
                    return  # The final fenced write still rejects stale ownership.

        thread = threading.Thread(target=renew, daemon=True)
        thread.start()
        try:
            yield
        finally:
            stop.set()
            thread.join(timeout=1)

    def run_root(self, job, task):
        from cremore.db.task_store import TaskStore

        self.validate(job)
        payload = task["payload"]
        root = copy.deepcopy(payload["scope"])
        state_id = root_identity(job.connection_id, root)
        state = dict(ScanStore(self.repo).root(state_id))
        checkpoint = dict(task.get("checkpoint") or {})
        start = checkpoint.get("scan_start") or dt.datetime.now(dt.UTC).isoformat()
        checkpoint["scan_start"] = start
        evidence = self.worker.orchestrator.detection_evidence
        digest = evidence["detection_policy_digest"]
        requested = payload.get("mode", "BASELINE")
        # A change run of a scope in the upgrade hold (triggers sets policy_hold) on a root last read under an older
        # policy: it reads only what changed, or nothing, and leaves the whole re-read to the scope's next full scan. It
        # never certifies the current policy for the root, so that scan and any policy sweep still read it whole.
        held = (payload["job_payload"].get("policy_hold") is True
                and (requested == "DELTA" or (requested == "EVENT" and bool(payload.get("full_delta"))))
                and bool(state.get("watermark")) and state.get("detection_digest") != digest
                and not state.get("retry_overflow"))
        if state.get("resume_detection_digest") != digest or state.get("retry_overflow"):
            # A cursor proves only the prefix covered under its own policy.
            # Legacy unbound cursors and incomplete failure lists require a sweep.
            state.pop("resume_after", None)
            state.pop("resume_detection_digest", None)
        if checkpoint.get("detection_digest") != digest:
            # A suffix covered by the old detector cannot certify the new
            # policy. Keep consumed budgets, but restart approved traversal.
            checkpoint.pop("last_key", None)
            checkpoint.pop("resume_start", None)
            checkpoint.pop("retried", None)
        checkpoint["detection_digest"] = digest
        checkpoint.update(evidence)
        if held:
            checkpoint["policy_held"] = 1  # reported with the counts, and read by a budget stop (finish_budget_stop)
        else:
            checkpoint.pop("policy_held", None)
        failures_seen = stable_digest(state.get("failed_keys") or [])
        if not checkpoint.get("retried") or checkpoint.get("failures_seen") != failures_seen:
            # Until the task has read its earlier failures again (``retried``) the root's list joins its own; after,
            # the task's list is the truth, joined again only when another run changed the root's list since. Its
            # keys the task already read again then count once too often: a key reported failed too often is safe.
            checkpoint.update(
                failure_state(
                    set(state.get("failed_keys") or []) | set(checkpoint.get("failed_keys") or []),
                    overflow=checkpoint.get("retry_overflow"),
                )
            )
        checkpoint["failures_seen"] = failures_seen
        # A held change run of a root whose DELTA would read it whole (WATERMARK_DELTA_TYPES) reads nothing: change
        # feeds still read what they name, and the full scan the rest. It reports that the root was not read.
        unread = held and root["resource_type"] not in WATERMARK_DELTA_TYPES
        if unread or (requested == "POLICY_SWEEP" and state.get("watermark") and state.get("detection_digest") == digest
                      and not state.get("retry_overflow") and not state.get("failed_keys")):
            # A whole run re-read this root under the current policy after the sweep was queued, and read all of it:
            # poll_policy_sweeps queues no sweep for a root in this state, so reading it again would find nothing that
            # run did not. Earlier attempts' counts, and the root's open gaps, are reported as any run reports them.
            result = {"objects": 0, **{k: checkpoint[k] for k in STOP_COUNTS if k in checkpoint},
                      **({"root_coverage_complete": False} if unread else {"policy_current": 1}),
                      "failure_basis": scope.FAILURE_BASIS}
            if state.get("inspection_gaps") or state.get("inspection_gaps_overflow"):
                result.update(inspection_gaps=len(state.get("inspection_gaps") or []), root_coverage_complete=False)
                if state.get("inspection_gaps_overflow"):
                    result["inspection_gaps_overflow"] = True
            if unread and checkpoint.get("failed_keys"):
                # Earlier failures it did not read again (the root's, and an earlier attempt's joined above): still not
                # read, so the run stays partial for them too.
                result["failed"] = len(checkpoint["failed_keys"])
            if unread and checkpoint.get("retry_overflow"):
                # An earlier attempt's failure list overflowed (kept only in this task's checkpoint): as any run says it.
                result.update(root_coverage_complete=False, stopped_reason="RETRY_STATE_OVERFLOW")
            with self.tasks.fenced(task["id"], task["token"]) as repo:
                self.validate(job, repo)
                TaskStore(repo).finish(task["id"], task["token"], result)
            return
        partial_target = (
            payload["job_payload"].get("trigger") == "RESCAN"
            or "exact_keys" in root
            or "exact_paths" in root
        )
        mode = requested
        # Read last under an older policy: the run reads the root whole, unless it is held.
        stale = state.get("detection_digest") != digest and not held
        if not state.get("watermark") or stale or state.get("retry_overflow"):
            mode = "BASELINE"
        reconcile_age = payload["job_payload"].get("reconcile_if_older_than_seconds")
        reconciled_at = scope.parse_stamp(state.get("last_reconcile"))
        if (
            requested == "DELTA"
            and reconcile_age
            and not held
            and (
                reconciled_at is None
                or (dt.datetime.now(dt.UTC) - reconciled_at).total_seconds() >= reconcile_age
            )
        ):
            mode = "RECONCILE"
        if requested == "EVENT":
            mode = "DELTA" if payload.get("full_delta") else "EVENT"
            if mode == "DELTA" and (state.get("retry_overflow") or stale):
                mode = "BASELINE"
            if mode == "EVENT":
                if not payload.get("keys"):
                    raise CollectorError("EVENT_EXACT_TARGET_REQUIRED")
                field = scope.EXACT_FIELDS[root["resource_type"]]
                root[field] = payload["keys"]
        if requested == "INVENTORY":
            if root["resource_type"] != "S3_BUCKET" or root.get("exact_keys"):
                raise CollectorError("INVENTORY_REQUIRES_S3_ROOT")
            from cremore.scanning import inventory_manifests

            # Read per scan: an Admin who adds a binding does not restart a worker.
            bindings = inventory_manifests.bindings(self.worker.settings, self.repo)
            pointer = bindings.get(f"{job.connection_id}/{root['provider_resource_id']}")
            if not pointer:
                raise CollectorError("INVENTORY_NOT_CONFIGURED")
            root["inventory"] = dict(pointer)
            old = state.get("inventory") or {}
            if (
                old.get("digest") == digest
                and old.get("manifest_bucket") == pointer["manifest_bucket"]
                and old.get("manifest_key") != pointer["manifest_key"]
            ):
                root["inventory"]["prior_manifest_key"] = old.get("manifest_key")
            mode = "INVENTORY"
        stamp = scope.parse_stamp(state.get("watermark"))
        if mode == "DELTA" and stamp is not None:
            root["watermark_since"] = (stamp - OVERLAP).isoformat()
        root["failed_keys"] = list(state.get("failed_keys") or [])
        # What the provider's own collector kept from the last complete whole-root run.
        root["provider_state"] = dict(state.get("provider_state") or {})
        source_type = RESOURCE_SOURCE[root["resource_type"]]
        known = [
            e
            for e in self.repo.exposures_for_root(
                job.connection_id,
                source_type,
                root["provider_resource_id"],
                page_id=root["provider_resource_id"] if source_type == "notion" else None,
            )
            if _inside(root, e)
        ]
        from cremore.governance.response import verification_credentials

        verification = verification_credentials(self.repo)
        root["watched_keys"] = sorted(
            {e.location for e in known if e.status != "REMOVED" or e.credential_id in verification}
            | set(root["failed_keys"])
        )
        # Objects at a known exposure's location commit alone: their reconcile and
        # finding updates keep exactly the transaction they always had.
        exposed = {e.location for e in known}
        # The root's earlier inspection gaps not yet inspected again in this task,
        # and this task's own; both survive a resumed attempt in the checkpoint.
        checkpoint.setdefault("carried_gaps", list(state.get("inspection_gaps") or []))
        checkpoint.setdefault("carried_overflow", bool(state.get("inspection_gaps_overflow")))
        gaps_left = dict(checkpoint["carried_gaps"])
        gaps_run = dict(checkpoint.get("inspection_gaps") or [])
        # This run's own list cut short, apart from the earlier gaps a full run replaces.
        gaps_cut = [bool(checkpoint.get("gaps_overflow"))]
        gaps_dirty = [False]
        # Gaps another run of this root recorded since this task began (a change scan it gave way to) are carried
        # too, so its final save never drops one: a gap reported once too often is safe.
        seen = _gaps_seen(state)
        if checkpoint.setdefault("gaps_seen", seen) != seen:
            gaps_left.update(state.get("inspection_gaps") or [])
            # Into the stored list at once: the first reservation saves this checkpoint, and an attempt stopped before
            # its first commit must not leave the new digest beside the old list.
            checkpoint["carried_gaps"], carried_cut = gap_list(gaps_left)
            checkpoint.update(gaps_seen=seen, carried_overflow=bool(
                checkpoint["carried_overflow"] or state.get("inspection_gaps_overflow") or carried_cut))
            gaps_dirty[0] = True
        resumable = _resumable(payload)
        # A held run neither resumes from the root's cursor nor moves it: its own proves no prefix read under this policy.
        cursor = "" if held else state.get("resume_after") or ""
        if resumable:
            checkpoint.setdefault("resume_start", cursor)
        # Within this run the task checkpoint is the truth; across runs it is the
        # root's saved state, written only when a run stopped with work left.
        carried = checkpoint.get("last_key") or (cursor if resumable else "")
        retried = bool(checkpoint.get("retried")) and bool(carried) and resumable
        if carried and resumable:
            root["start_after"] = carried
            root["failed_keys"] = list(checkpoint.get("failed_keys") or []) if retried else sorted(
                set(root["failed_keys"]) | set(checkpoint.get("failed_keys") or [])
            )
        # The failures this task already met at or before its cursor: not read again, still kept and counted once.
        before = {key for key in root["failed_keys"] if key <= carried} if retried else set()
        remaining = {
            k: max(0, int(v) - int(checkpoint.get(k, 0))) for k, v in payload["budgets"].items()
        }
        p = {
            **payload["job_payload"],
            "roots": [root],
            # Bytes are charged as objects commit (admitted below): a listing-side byte
            # cap would count cache hits that download nothing and stop unchanged rescans.
            "budgets": {k: v for k, v in remaining.items() if k != "bytes"},
            "scan_mode": mode,
            "_lazy": True,
        }
        limits = payload["budgets"]
        if any(int(v) <= 0 for v in remaining.values()):
            exhausted = [k for k, v in remaining.items() if int(v) <= 0]
            if self.worker.share_budget(task, exhausted, "BUDGET_ROOT_SHARE"):
                return
            with self.tasks.fenced(task["id"], task["token"]) as repo:
                self.finish_budget_stop(job, task, repo, "BUDGET_ROOT_SHARE")
            return
        collector = self.worker.collector_factory(job.model_copy(update={"payload": p}))
        parts = getattr(collector, "parts", [collector])
        if retried:
            for part in parts:
                part.retry_before_start = False
        started = time.monotonic()
        seconds_before = float(checkpoint.get("seconds", 0))
        request_limit = int(limits.get("requests", 10_000))
        runtime = self
        checked_at = [None]
        # A change scan of this root waiting behind a resumable sweep runs first: the sweep commits what it has read
        # and goes back to the queue with its checkpoint, at most once per waiting task. It looks only once the
        # attempt has committed an object past where it started, and YIELD_SECONDS after that first commit, so a
        # stream of events never pins the sweep: an attempt still retrying earlier failures, parsing one large
        # document or listing unchanged keys does not give way, and every attempt moves the cursor on. Earlier
        # failures are read again once a task (``retried``), so giving way costs no read of a failed key.
        lock_key = task.get("lock_key") or payload.get("lock_key")
        reconciled_at = scope.parse_stamp(state.get("last_reconcile"))
        may_yield = bool(resumable and lock_key and reconciled_at and dt.datetime.now(dt.UTC) - reconciled_at
                         < dt.timedelta(seconds=YIELD_RECONCILE_SECONDS))
        looked_at, yielding, begun, moved = [started], [None], root.get("start_after") or "", [False]
        # Set once all the attempt listed is committed: it no longer gives way, so its final commit settles the
        # removals its listing proved and the checks after it are never repeated.
        settling = [False]

        def elapsed():
            return time.monotonic() - started + seconds_before

        def progress():
            if limits.get("seconds") and elapsed() >= limits["seconds"]:
                raise CollectorError("BUDGET_SECONDS")
            if yielding[0]:
                raise CollectorError(YIELD_CODE)
            # Cancellation and approval are re-read once a second (and at the start);
            # every write still validates inside its own fenced transaction.
            if checked_at[0] is not None and time.monotonic() - checked_at[0] < CHECK_SECONDS:
                return
            waiting = None
            with self.tasks.fenced(task["id"], task["token"]) as repo:
                self.validate(job, repo)
                if may_yield and not settling[0] and checkpoint.get("last_key", "") > begun:
                    if not moved[0]:
                        moved[0], looked_at[0] = True, time.monotonic()  # the window opens at the first commit
                    elif time.monotonic() - looked_at[0] >= YIELD_SECONDS:
                        looked_at[0] = time.monotonic()
                        waiting = TaskStore(repo).waiting_event(lock_key, skip=checkpoint.get("yielded_to"))
            checked_at[0] = time.monotonic()
            if waiting is not None:
                yielding[0] = waiting
                raise CollectorError(YIELD_CODE)

        class DurableBudget(RequestBudget):
            """Requests are reserved in fenced blocks, never past the limit; the checkpoint
            holds the reserved total, so a crash over-counts and never under-counts."""

            reserved = 0

            def consume(self):
                run_on_owner(self._consume)

            def _consume(self):
                progress()
                if self.used >= self.limit:
                    raise RequestBudgetExceeded()
                if self.used >= self.reserved:
                    # A sixteenth of what is left, so a crash never strands a small budget.
                    grant = min(RESERVE_REQUESTS, max(1, (self.limit - self.used) // 16))
                    with runtime.tasks.fenced(task["id"], task["token"]) as repo:
                        runtime.validate(job, repo)
                        checkpoint["requests"] = self.used + grant
                        checkpoint["seconds"] = elapsed()
                        TaskStore(repo).checkpoint(task["id"], task["token"], checkpoint)
                    self.reserved = self.used + grant
                self.used += 1

        budget = DurableBudget(request_limit, int(checkpoint.get("requests", 0)))
        for part in parts:
            part.request_budget = budget
            # An object larger than all this run may spend fails alone rather than stopping
            # every run at it; one that only outgrows what is left stops the run before it
            # is read (ScanService bytes_left), and the next run resumes at it.
            if limits.get("bytes") and hasattr(part, "max_object_bytes"):
                part.max_object_bytes = min(part.max_object_bytes, remaining["bytes"])

        def charged(outcome):
            # A cache answer downloaded nothing; an unreadable object spends no bytes.
            return 0 if outcome.reused or outcome.skip == "UNREADABLE" else int(outcome.resource.size or 0)

        def bytes_left():
            return max(0, limits["bytes"] - int(checkpoint.get("bytes", 0))) if limits.get("bytes") else None

        def admitted(outcomes):
            """How many objects, in order, the byte and time budgets still take.

            A stop on the first one raises inside its transaction, exactly as a
            single commit did; later ones are committed alone after the others.
            """
            spent = int(checkpoint.get("bytes", 0))
            for count, outcome in enumerate(outcomes):
                if outcome.skip == "UNREADABLE":
                    continue  # nothing was read: no budget is spent or checked
                code = None
                if limits.get("bytes") and spent + charged(outcome) > limits["bytes"]:
                    code = "BUDGET_BYTES"
                elif (limits.get("seconds")
                      and outcome.inspected_at - started + seconds_before > limits["seconds"]):
                    # Timed at its inspection, as a commit right after it would have been:
                    # objects inspected before the deadline are kept, whenever the batch commits.
                    code = "BUDGET_SECONDS"
                if code and count == 0:
                    raise CollectorError(code)
                if code:
                    return count
                spent += charged(outcome)
            return len(outcomes)

        def note_gap(key, outcome):
            # A fixed reason it was not fully inspected; reported until a later read clears it.
            if key in gaps_left or key in gaps_run or outcome.gap:
                gaps_dirty[0] = True
            gaps_left.pop(key, None)
            if not outcome.gap:
                gaps_run.pop(key, None)
            elif key in gaps_run or len(gaps_run) < FAILURE_KEY_LIMIT:
                gaps_run[key] = outcome.gap
            else:
                gaps_cut[0] = True

        def apply(outcome):
            """One object's own effects, identical whether it commits alone or in a batch."""
            resource = outcome.resource
            key = resource.metadata.get("page_id") if resource.source_type == "notion" else resource.location
            record_extraction(resource)
            if outcome.skip == "UNREADABLE":
                failures = set(checkpoint.get("failed_keys") or [])
                if any(key in getattr(part, "confirmed_missing_keys", ()) for part in parts):
                    failures.discard(key)  # a 404: gone, not failed; the final commit settles it as removed
                else:
                    failures.add(key)
                checkpoint.update(failure_state(failures, overflow=checkpoint.get("retry_overflow")))
                if resource.source_type == "s3" and not root.get("exact_keys") and mode != "INVENTORY":
                    # Kept as failed (or gone) in this commit: a resumed attempt need not list it again to read it again.
                    checkpoint["last_key"] = max(checkpoint.get("last_key", ""), resource.location)
                return
            checkpoint["bytes"] = int(checkpoint.get("bytes", 0)) + charged(outcome)
            checkpoint["seconds"] = elapsed()
            if outcome.complete:
                note_gap(key, outcome)
            if outcome.skip:
                # Read, but outside the text scan: not a retry candidate. Budgets,
                # the S3 cursor and the exclusion totals still advance so a resumed
                # task neither re-spends nor re-counts. No reconcile runs for it.
                failures = set(checkpoint.get("failed_keys") or [])
                failures.discard(key)
                for part in parts:
                    for attribute in ("failed_keys", "failed_page_ids"):
                        if hasattr(part, attribute):
                            getattr(part, attribute).discard(key)
                counter = "skipped_unsupported" if outcome.skip == "UNSUPPORTED_FORMAT" else "skipped_media"
                checkpoint[counter] = int(checkpoint.get(counter, 0)) + 1
                if resource.source_type == "s3" and not root.get("exact_keys") and mode != "INVENTORY":
                    checkpoint["last_key"] = max(checkpoint.get("last_key", ""), resource.location)
                checkpoint.update(failure_state(failures, overflow=checkpoint.get("retry_overflow")))
                return
            complete = outcome.complete
            if complete:
                for part in parts:
                    if hasattr(part, "failed_keys"):
                        part.failed_keys.discard(resource.location)
            checkpoint["objects"] = int(checkpoint.get("objects", 0)) + 1
            checkpoint["findings"] = int(checkpoint.get("findings", 0)) + len(outcome.result.findings)
            if outcome.gap:
                checkpoint["partially_inspected"] = int(checkpoint.get("partially_inspected", 0)) + 1
            # No revision/checkpoint can survive without all of this object's writes.
            if resource.source_type == "s3" and not root.get("exact_keys") and mode != "INVENTORY":
                checkpoint["last_key"] = max(checkpoint.get("last_key", ""), resource.location)
                failures = set(checkpoint.get("failed_keys") or []) | set(
                    getattr(parts[0], "failed_keys", set())
                )
                failures.discard(resource.location) if complete else failures.add(resource.location)
                checkpoint.update(
                    failure_state(failures, overflow=checkpoint.get("retry_overflow"))
                )
            elif resource.source_type == "notion":
                checkpoint["objects"] = 1
                failures = set(checkpoint.get("failed_keys") or [])
                page_id = resource.metadata.get("page_id")
                failures.discard(page_id) if complete else failures.add(page_id)
                checkpoint["failed_keys"] = sorted(failures)
            else:
                failures = set(checkpoint.get("failed_keys") or [])
                failures.discard(resource.location) if complete else failures.add(resource.location)
                checkpoint.update(
                    failure_state(failures, overflow=checkpoint.get("retry_overflow"))
                )

        def save_checkpoint(repo):
            if gaps_dirty[0]:
                # Rebuilt only after a commit changed them: the lists can hold thousands of keys.
                checkpoint["inspection_gaps"], run_cut = gap_list(gaps_run)
                checkpoint["carried_gaps"], left_cut = gap_list(gaps_left)
                gaps_cut[0] = gaps_cut[0] or run_cut
                checkpoint["gaps_overflow"] = gaps_cut[0]
                checkpoint["carried_overflow"] = bool(checkpoint.get("carried_overflow") or left_cut)
                gaps_dirty[0] = False
            if resumable:
                # Every failure the attempt knows commits with the cursor, those of keys listed too large to read
                # (never an outcome) too: an attempt resumed after ``retried`` counts them from here.
                checkpoint.update(failure_state(
                    set(checkpoint.get("failed_keys") or []).union(*(getattr(part, "failed_keys", ()) for part in parts)),
                    overflow=checkpoint.get("retry_overflow")))
                if checkpoint.get("last_key", "") > begun:
                    # Past where it started: the earlier failures up to the cursor were read again first
                    # (S3Collector.collect), and their outcome is in this commit.
                    checkpoint["retried"] = True
                # The keys refused as archived, less those this attempt saw fail otherwise (one read that works leaves
                # the failures, and so this list, by the intersection).
                archived = (set(checkpoint.get("archived_keys") or []).difference(
                    *(getattr(part, "unarchived", ()) for part in parts))).union(
                    *(getattr(part, "archived_keys", ()) for part in parts))
                if archived or checkpoint.get("archived_keys"):
                    checkpoint["archived_keys"] = sorted(archived.intersection(checkpoint.get("failed_keys") or []))
            TaskStore(repo).checkpoint(task["id"], task["token"], checkpoint)

        def commit_objects(repo, outcomes):
            """Validate once per fenced transaction, then apply each object in listing order."""
            self.validate(job, repo)
            count = admitted(outcomes)
            for outcome in outcomes[:count]:
                apply(outcome)
            save_checkpoint(repo)
            return count

        def batchable(resource):
            return resource.source_type != "notion" and resource.location not in exposed

        def record_extraction(resource):
            reason = resource.metadata.get("document_extraction_status")
            if reason and reason != "COMPLETE":
                reasons = checkpoint.setdefault("extraction_reasons", {})
                reasons[reason] = int(reasons.get(reason, 0)) + 1

        requested_verify = p.get("verify")
        verify = (
            self.worker.verify
            if requested_verify is None
            else bool(requested_verify) and bool(self.worker.verify)
        )
        try:
            with guard_requests(progress, pacing=ScanStore(self.repo)):
                summary = ScanService(self.worker.orchestrator).run(
                    collector,
                    source_connection_id=job.connection_id,
                    scan_id=job.id,
                    verify=verify,
                    verify_config=self.worker.verify_config(),
                    reconcile_objects=True,
                    write_context=lambda: self.tasks.fenced(task["id"], task["token"]),
                    commit_objects=commit_objects,
                    batchable=batchable,
                    bytes_left=bytes_left,
                )
                settling[0] = True
                for part in parts:
                    # A resumed S3 listing run to its end: its watched keys at or before the cursor, checked once all
                    # it listed is committed, from what the budget left (S3Collector.confirm_before_start).
                    if hasattr(part, "confirm_before_start"):
                        part.confirm_before_start(str(job.id))
        except CollectorError as exc:
            if exc.code == YIELD_CODE and yielding[0]:
                # The objects read so far are committed (the scan service flushes them on any stop) and the saved
                # checkpoint names the last one; the unspent reservation goes back onto it. Deferred, not failed: no
                # attempt is spent, the lease is released and the next claim resumes after that key.
                self.tasks.defer(task["id"], task["token"], YIELD_CODE, delay_seconds=1, checkpoint={
                    "requests": budget.used, "seconds": elapsed(), "yielded_to": yielding[0]})
                logger.info("root task %s yields to change scan %s of its root", task["id"], yielding[0])
                return
            if exc.code.startswith("BUDGET_") and int(checkpoint.get("requests", 0)) != budget.used:
                # No read is in flight any more: give back the unspent reservation so
                # the stop records (and a sibling top-up sees) the requests really made.
                # Onto the checkpoint as committed: a stop flush that failed rolled its
                # objects back, and the cursor must not pass them.
                self.tasks.amend_checkpoint(task["id"], task["token"],
                                            {"requests": budget.used, "seconds": elapsed()})
            raise
        # Failures counted before the cursor that a 404 confirmed missing since are no longer failures (the removals
        # below drop them from the root's list too).
        before.difference_update(*(getattr(part, "confirmed_missing_keys", ()) for part in parts))
        archived_before = len(before.intersection(checkpoint.get("archived_keys") or []))
        coverage = dict(getattr(collector, "coverage", None) or {})
        failures = set(checkpoint.get("failed_keys") or [])
        for part in parts:
            failures.update(getattr(part, "failed_keys", set()))
            failures.update(getattr(part, "failed_page_ids", set()))
        checkpoint.update(
            failure_state(
                failures,
                overflow=checkpoint.get("retry_overflow")
                or any(getattr(part, "retry_overflow", False) for part in parts),
            )
        )
        coverage.update(
            objects=int(checkpoint.get("objects", summary.objects)),
            findings=int(checkpoint.get("findings", summary.findings)),
            failed=summary.objects_failed + len(before) - archived_before,
            timings=summary.timings,
            reused=summary.reused,
            extraction_reasons=dict(checkpoint.get("extraction_reasons") or {}),
            skipped_unsupported=int(checkpoint.get("skipped_unsupported", summary.skipped_unsupported)),
            skipped_media=int(checkpoint.get("skipped_media", summary.skipped_media)),
            partially_inspected=int(checkpoint.get("partially_inspected", summary.partially_inspected)),
            failure_basis=scope.FAILURE_BASIS,
            **evidence,
            requests=budget.used,
            bytes=checkpoint.get("bytes", 0),
            count_basis="COMMITTED_OBJECT_ATTEMPTS",
        )
        if archived_before:
            coverage.update(skipped=int(coverage.get("skipped", 0)) + archived_before,
                            skipped_archived=int(coverage.get("skipped_archived", 0)) + archived_before)
        if checkpoint.get("retry_overflow"):
            coverage.update(root_coverage_complete=False, stopped_reason="RETRY_STATE_OVERFLOW")
        # Format skips and fixed extraction limits are not failures: reading the same
        # bytes again cannot change them, so they never hold back the watermark.
        complete = not (
            coverage["failed"] or coverage.get("skipped") or coverage.get("stopped_reason")
            or coverage.get("root_coverage_complete") is False
        )
        whole = not partial_target and requested not in ("EVENT", "INVENTORY") and not root.get("start_after")
        # A complete full read replaces the root's gaps; any other run only adds its own
        # to those it did not inspect again. Partial collection is never absence evidence.
        full = whole and complete and mode in ("BASELINE", "RECONCILE")
        gaps, gaps_over = gap_list(gaps_run if full else {**gaps_left, **gaps_run})
        gaps_over = gaps_over or gaps_cut[0] or (not full and bool(checkpoint.get("carried_overflow")))
        coverage["inspection_gaps"] = len(gaps)
        if gaps_over:
            coverage["inspection_gaps_overflow"] = True
        if gaps or gaps_over or coverage["skipped_unsupported"] or coverage["skipped_media"] \
                or coverage["partially_inspected"]:
            # Still reported on every run of this root until a read clears them.
            coverage["root_coverage_complete"] = False
        if held:
            # It read what changed under this policy; the rest of the root was last read under an older one.
            coverage.update(policy_held=1, root_coverage_complete=False)
        with self.tasks.fenced(task["id"], task["token"]) as repo:
            self.validate(job, repo)
            for part in parts:
                missing = set(getattr(part, "confirmed_missing_keys", set()))
                if (
                    getattr(part, "listing_complete", False)
                    and not partial_target
                    and requested != "EVENT"
                ):
                    if root["resource_type"] == "S3_BUCKET":
                        missing.update(getattr(part, "missing_keys", set()))
                    elif root["resource_type"] in ("GITHUB_REPOSITORY", "GITLAB_REPOSITORY", "GCS_BUCKET", "CONFLUENCE_PAGE", "BITBUCKET_REPOSITORY"):
                        missing.update(
                            e.location for e in known if e.location not in part.listed_paths
                        )
                if not partial_target and requested != "EVENT":
                    # A resumed S3 listing run to its end settles the approved keys after its cursor (S3Collector).
                    missing.update(getattr(part, "missing_after_start", ()))
                failures.difference_update(missing)
                affected = set()
                observed = set()
                unchanged = set(getattr(part, "unchanged_locations", ())) - missing
                revisions = getattr(part, "unchanged_revisions", {})
                for exposure in known:
                    if exposure.location in missing and exposure.source_type != "notion":
                        repo.mark_exposure_removed(exposure.id)
                        affected.add(exposure.credential_id)
                    elif (exposure.location in unchanged and exposure.metadata.get("revision")
                          and revisions.get(exposure.location) == exposure.metadata["revision"]):
                        # A root watermark alone cannot prove this exposure's
                        # content unchanged: require the observed object revision.
                        repo.mark_exposure_seen(exposure.id)
                        if exposure.status != "REMOVED":
                            observed.add(exposure.credential_id)
                for cid in affected | observed:
                    finding = repo.repair_finding_rollup(cid) if cid in affected else repo.get_finding_for_credential(cid)
                    if finding and (finding.all_locations_removed or cid in observed):
                        self.worker.orchestrator.using(repo).observe_response(finding, scan_id=job.id,
                            scan_started_at=job.started_at or job.created_at, authoritative=complete or cid in observed)
            new_state = dict(state)
            # Events and Inventory are partial current-state signals, never a
            # root baseline. Failure-list overflow keeps the older checkpoint.
            if (
                requested not in ("EVENT", "INVENTORY")
                and not partial_target
                and not checkpoint.get("retry_overflow")
                and (
                    not state.get("retry_overflow")
                    or (complete and not failures and not root.get("start_after"))
                )
                and not coverage.get("stopped_reason")
                and (complete or (state.get("watermark") and len(failures) <= FAILURE_KEY_LIMIT))
            ):
                # The watermark moves, as a held run read (or keeps as failed) all that changed since the last one. The
                # digest does not: until a whole read under this policy, every run but a held one reads the root whole.
                new_state["watermark"] = start
                if not held:
                    new_state["detection_digest"] = digest
                if mode in ("BASELINE", "RECONCILE") and complete and not root.get("start_after"):
                    new_state["last_reconcile"] = start
            new_state.update(inspection_gaps=gaps, inspection_gaps_overflow=gaps_over)
            provider_state = _bounded_state(getattr(parts[0], "provider_state", None)) if len(parts) == 1 else None
            if whole and complete and provider_state is not None:
                new_state["provider_state"] = provider_state
            if mode == "INVENTORY":
                coverage["coverage_basis"] = "INVENTORY_REPORT_ONLY"
                coverage["root_coverage_complete"] = False
                if complete and parts[0].inventory_complete:
                    new_state["inventory"] = {
                        **root["inventory"],
                        "digest": digest,
                        "timestamp": parts[0].manifest_timestamp,
                    }
            cleared_overflow = (
                complete
                and not failures
                and not partial_target
                and requested not in ("EVENT", "INVENTORY")
                and not root.get("start_after")
            )
            new_state.update(
                failure_state(
                    failures,
                    overflow=checkpoint.get("retry_overflow")
                    or (state.get("retry_overflow") and not cleared_overflow),
                )
            )
            # Where the next run picks this root up. Cleared the moment the root
            # is read to the end, so a finished scope never resumes mid-bucket.
            reached = checkpoint.get("last_key") or ""
            budget_stop = str(coverage.get("stopped_reason") or "").startswith("BUDGET_")
            if budget_stop and reached and resumable and not partial_target and not held:
                new_state["resume_after"] = reached
                new_state["resume_detection_digest"] = digest
            elif complete and not held:
                new_state.pop("resume_after", None)
                new_state.pop("resume_detection_digest", None)
            new_state["last_coverage"] = coverage
            ScanStore(repo).save_root(state_id, job.connection_id, new_state)
            # The unspent reservation goes back: a sibling's top-up reads this checkpoint.
            checkpoint["requests"] = budget.used
            save_checkpoint(repo)
            TaskStore(repo).finish(task["id"], task["token"], coverage)

    def finish_budget_stop(self, job, task, repo, code):
        """Keep committed work and its policy when a budget interrupts a root."""
        from cremore.db.task_store import TaskStore

        self.validate(job, repo)
        tasks = TaskStore(repo)
        # The claimed task predates every object commit. Read its fenced checkpoint.
        current = next(t for t in tasks.list_for_run(job.id) if t["id"] == task["id"])
        checkpoint = current.get("checkpoint") or {}
        payload = current["payload"]
        state_id = root_identity(job.connection_id, payload["scope"])
        store = ScanStore(repo)
        state = dict(store.root(state_id))
        saved = dict(state)
        if _resumable(payload) and checkpoint.get("last_key"):
            state.update(failure_state(
                set(state.get("failed_keys") or []) | set(checkpoint.get("failed_keys") or []),
                overflow=state.get("retry_overflow") or checkpoint.get("retry_overflow"),
            ))
            if not checkpoint.get("policy_held"):  # a held run's cursor proves no prefix read under this policy
                state.update(resume_after=checkpoint["last_key"],
                             resume_detection_digest=checkpoint.get("detection_digest"))
        if "carried_gaps" in checkpoint:
            # A stopped run adds the gaps it found to the earlier ones it did not reach, and keeps those another
            # run of this root recorded since it began.
            later = "gaps_seen" in checkpoint and checkpoint["gaps_seen"] != _gaps_seen(saved)
            gaps, over = gap_list({**dict(checkpoint["carried_gaps"]),
                                   **(dict(saved.get("inspection_gaps") or []) if later else {}),
                                   **dict(checkpoint.get("inspection_gaps") or [])})
            state.update(inspection_gaps=gaps, inspection_gaps_overflow=bool(
                over or checkpoint.get("gaps_overflow") or checkpoint.get("carried_overflow")
                or (later and saved.get("inspection_gaps_overflow"))))
        if state != saved:
            store.save_root(state_id, job.connection_id, state)
        coverage = {k: checkpoint[k] for k in STOP_COUNTS if k in checkpoint}
        if state.get("inspection_gaps") or state.get("inspection_gaps_overflow"):
            coverage["inspection_gaps"] = len(state.get("inspection_gaps") or [])
        coverage.update(skipped=1, stopped_reason=code, failure_basis=scope.FAILURE_BASIS)
        tasks.finish(task["id"], task["token"], coverage)
