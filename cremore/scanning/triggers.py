"""Current-state triggers for existing, administrator-approved scopes.

Schedules and change feeds run until an Admin switches them off, a queue once it is
switched on and bound; switches and bindings are read per pass
(cremore/scanning/trigger_settings.py) rather than captured at start-up, so a change
reaches a running worker.

Events never grant scope, provision infrastructure or prove object deletion.
The repository atomically persists each receipt, immutable plan and parent job.
Only a dedicated, explicitly acknowledged queue (SQS, Pub/Sub or Service Bus) is
consumed; its messages are acknowledged after every resulting job has been
accepted durably. Every run is queued even while others scan: runs of different
connections proceed side by side, and a connection's change-event run beside its
sweep (cremore.db.repository.job_lane).
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import NamedTuple
from urllib.parse import unquote_plus

from cremore.db.catalog_store import CatalogStore
from cremore.db.repository import job_lane
from cremore.domain.connections import job_payload_for
from cremore.domain.models import ScanJob
from cremore.scanning import scope, trigger_settings
from cremore.sources.registry import BY_RESOURCE_TYPE

logger = logging.getLogger(__name__)

MAX_EVENT_BYTES = 128 << 10
MAX_EVENT_KEYS = 256
MAX_EVENT_RECORDS = 4096
DEBOUNCE_SECONDS = 5
# The modes of a whole-scope run that answer a slot: a full read (BASELINE, RECONCILE) covers a DELTA too.
_COVERING = {"DELTA": ("DELTA", "RECONCILE", "BASELINE"), "RECONCILE": ("RECONCILE", "BASELINE")}
# How long a scope whose plan was refused (a paused connection, a changed authorization) is not planned again for the
# same open slots. In memory per process, keyed by the scope's row: a refusal never consumes the slot, and an
# approval (a new row) or the next slot plans again at once.
REFUSAL_SECONDS = 300
_refused: dict[tuple, datetime] = {}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_S3_WRITES = {"PutObject", "CopyObject", "CompleteMultipartUpload", "DeleteObject", "DeleteObjects",
              "RestoreObject", "PutObjectTagging", "DeleteObjectTagging", "PutObjectAcl"}


def _receipt(*parts):
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()


def _now(value=None):
    value = value or datetime.now(UTC)
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _profile(repo, profile_id):
    try:
        profile = repo.get_scope_profile(uuid.UUID(str(profile_id)))
    except (ValueError, TypeError, AttributeError):
        profile = None
    if profile is None or profile.state != "READY" or not profile.approved_at or not profile.approved_by:
        raise scope.ScopeError("TRIGGER_PROFILE_NOT_READY", http_status=409)
    return profile


def prepare_trigger_plan(repo, settings, profile_id, trigger, *, now=None):
    """Resolve only approved root IDs against current connection authorization."""
    profile = _profile(repo, profile_id)
    if trigger == "EVENT" and profile.event_mode != "ENABLED":
        raise scope.ScopeError("TRIGGER_EVENTS_DISABLED", http_status=409)
    if trigger == "SCHEDULE" and not (profile.schedule_minutes or full_scan_cadence(
            profile, trigger_settings.full_scan(settings, repo)[0])):
        raise scope.ScopeError("TRIGGER_SCHEDULE_DISABLED", http_status=409)
    target = (repo.get_aws_account(profile.connection_id) if profile.kind == "aws"
              else repo.get_connection(profile.connection_id))
    if target is None:
        raise scope.ScopeError("TRIGGER_CONNECTION_UNAVAILABLE", http_status=409)
    auth = scope.auth_revision(profile.kind, target)
    enabled = target.enabled if profile.kind == "aws" else (
        target.status != "DISABLED" and not (target.credential_evidence or {}).get("revoked_at"))
    from cremore.onboarding.store import child_feature_enabled

    enabled = enabled and child_feature_enabled(repo, profile.kind, target.id, "exposure")
    catalog = CatalogStore(repo).selected(profile.kind, profile.connection_id,
                                        [r["resource_id"] for r in scope.effective_roots(profile)])
    plan = scope.build_plan(profile, catalog, auth=auth, enabled=enabled, now=_now(now),
                            configured_triggers={trigger})
    plan.id = uuid.uuid4()
    plan.trigger = trigger
    plan.verify = False
    scope.validate_execution(plan, profile, target, require_unexpired=True, now=_now(now))
    provider = scope.provider_of(profile.kind, target)
    if profile.kind == "aws":
        base = {"account_id": target.account_id, "region": settings.aws_region,
                "scanner_role_arn": target.scanner_role_arn, "external_id": target.external_id}
    else:
        base = job_payload_for(target)
        if target.secret_ref:
            base["secret_ref"] = target.secret_ref
    return profile, plan, target, base, {"aws": "s3"}.get(provider, provider)


def _event_root(plan, event):
    if not isinstance(event, dict) or set(event) - {"event_id", "resource_id", "keys", "paths", "page_ids"}:
        raise scope.ScopeError("EVENT_INVALID_PAYLOAD")
    root = next((r for r in plan.roots if r["resource_id"] == event.get("resource_id")), None)
    if root is None:
        raise scope.ScopeError("EVENT_OUT_OF_SCOPE", http_status=403)
    exact = scope.EXACT_FIELDS[root["resource_type"]]
    field = exact.removeprefix("exact_")
    if any(key in event for key in {"keys", "paths", "page_ids"} - {field}):
        raise scope.ScopeError("EVENT_INVALID_PAYLOAD")
    values = event.get(field, [])
    if (not isinstance(values, list) or len(values) > MAX_EVENT_RECORDS
            or any(not isinstance(v, str) or not v or _CONTROL.search(v) or len(v.encode()) > 4096 for v in values)):
        raise scope.ScopeError("EVENT_INVALID_PAYLOAD")
    values = list(dict.fromkeys(values))
    for value in values:
        if field == "keys":
            allowed = len(value.encode()) <= 1024 and (
                root.get("all_current_objects") or any(value.startswith(p) for p in root.get("prefixes") or []))
            allowed = allowed and not any(value.startswith(p) for p in root.get("excluded_prefixes") or [])
        elif field == "paths":
            allowed = scope.path_allowed(BY_RESOURCE_TYPE[root["resource_type"]], value, root)
        else:
            approved = [] if root["resource_type"] == "NOTION_DATA_SOURCE" else [root["provider_resource_id"]]
            if root.get("page_mode") != "PAGE_ONLY":
                approved.extend(root.get("descendant_ids") or [])
            allowed = value.replace("-", "") in {page.replace("-", "") for page in approved}
        if not allowed:
            raise scope.ScopeError("EVENT_OUT_OF_SCOPE", http_status=403)
    narrowed = dict(root)
    mode = "EVENT"
    if not values or len(values) > MAX_EVENT_KEYS:
        mode = "DELTA"
    else:
        narrowed[exact] = values
    return narrowed, mode


def change_triggered(resource_type) -> bool:
    """Whether a provider's change signal can start a scan of this kind of root: a change feed, a queue
    notification its source module reads, or S3's own notifications (a Notion page's webhook comes with its feed)."""
    from cremore.scanning import changes

    return (resource_type == "S3_BUCKET" or changes.supports(resource_type)
            or callable(getattr(BY_RESOURCE_TYPE.get(resource_type), "queue_changes", None)))


def event_origin(origin) -> str:
    """Where an event run came from, as its payload's ``requested_by`` records it: ``feed`` (a change feed),
    ``queue`` (the customer's own queue) or ``webhook``. The runtime leaves ``requested_by`` out of the approved
    scope an event task carries, so runs from different origins still merge into one task."""
    return "feed" if origin == "change-feed" else "queue" if origin in trigger_settings.QUEUES else "webhook"


def enqueue_event(repo, settings, profile_id, event, *, origin="webhook", receipt_id=None, now=None, mode=None):
    """Queue one root's work from an event. ``mode="BASELINE"`` rereads the root from scratch
    (a change feed saw history rewritten); otherwise the event's paths decide EVENT or DELTA."""
    event_id = event.get("event_id") if isinstance(event, dict) else None
    if not isinstance(event_id, str) or not event_id or len(event_id) > 256 or _CONTROL.search(event_id):
        raise scope.ScopeError("EVENT_ID_REQUIRED")
    now = _now(now)
    profile, plan, target, base, source = prepare_trigger_plan(repo, settings, profile_id, "EVENT", now=now)
    root, derived = _event_root(plan, event)
    mode = "BASELINE" if mode == "BASELINE" else derived
    plan.roots = [root]
    plan.known_count = 1
    plan.policy_digest = scope.policy_digest(profile, plan.catalog_snapshot_id, plan.auth_revision,
                                             {"event_roots": plan.roots})
    payload = scope.run_payload(plan, profile, base, source)
    payload.update(mode=mode, requested_by=event_origin(origin), event_coalesce_key=_receipt(
        str(profile.id), profile.version, plan.auth_revision, root["resource_id"]),
        not_before=datetime.fromtimestamp((int(now.timestamp()) // DEBOUNCE_SECONDS + 1) * DEBOUNCE_SECONDS, UTC).isoformat())
    # A BASELINE reread reads all of the root under the current policy anyway; it is never held.
    if mode != "BASELINE" and upgrade_hold(repo, settings, now, trigger_settings.schedule_origin(repo, now))(profile):
        payload["policy_hold"] = True
    # Recheck immediately before the transactional enqueue; the worker checks
    # this same version/auth binding again when claiming the resulting work.
    current_profile = _profile(repo, profile_id)
    scope.validate_execution(plan, current_profile, target, require_unexpired=True, now=now)
    receipt = receipt_id or _receipt(origin, str(profile.id), event_id)
    job = ScanJob(kind="scope", connection_id=profile.connection_id, payload=payload)
    return repo.enqueue_triggered_scope(plan, job, receipt)


def _has_resumable_progress(repo, job):
    """Only a committed, advancing S3 cursor supports automatic continuation."""
    from cremore.db.scan_store import ScanStore
    from cremore.db.task_store import TaskStore

    payload = job.payload or {}
    if (payload.get("trigger") in {"EVENT", "RESCAN", "POLICY_SWEEP"}
            or payload.get("mode", "BASELINE") not in {"BASELINE", "DELTA", "RECONCILE"}):
        return False
    roots = scope.split_roots(payload.get("roots") or [])
    if not roots or any(r["resource_type"] != "S3_BUCKET" or "exact_keys" in r for r in roots):
        return False
    expected = {scope.root_identity(job.connection_id, root) for root in roots}
    tasks = [task for task in TaskStore(repo).list_for_run(job.id) if task["kind"] != "PLAN"]
    if {task["root_id"] for task in tasks} != expected:
        return False
    stopped = False
    store = ScanStore(repo)
    for task in tasks:
        result = task.get("result") or {}
        if task["status"] != "SUCCEEDED":
            return False
        if not str(result.get("stopped_reason") or "").startswith("BUDGET_"):
            if (result.get("stopped_reason") or result.get("failed") or result.get("skipped")
                    or result.get("root_coverage_complete") is False):
                return False
            continue
        stopped = True
        checkpoint = task.get("checkpoint") or {}
        reached, start = checkpoint.get("last_key"), checkpoint.get("resume_start")
        digest = checkpoint.get("detection_digest")
        state = store.root(task["root_id"])
        if (not isinstance(reached, str) or not isinstance(start, str) or reached <= start
                or not digest or state.get("resume_after") != reached
                or state.get("resume_detection_digest") != digest
                or checkpoint.get("retry_overflow") or state.get("retry_overflow")):
            return False
    return stopped


def poll_resumable(repo, settings, *, now=None, limit=200):
    """Carry on an approved S3 scope with durable progress after a budget stop.

    Events, exact rescans, Inventory and other providers have no supported
    traversal checkpoint. Their partial result is retained for an operator to
    review and start a fresh scan with a suitable scope/budget. A missing or
    stationary cursor must never create an endless chain of identical runs.

    One continuation per stopped run: the receipt is that run's id, so a replica
    polling at the same time, or the same poll running twice, enqueues it once.
    A continuation that itself stops enqueues the next one, and a run that ends
    without a budget stop ends the chain.
    """

    now = _now(now)
    result = {"enqueued": 0, "skipped": 0}
    seen: set[str] = set()
    for job in repo.list_jobs(limit):
        payload = job.payload or {}
        # A change-event run reads what changed beside a sweep, never the rest of
        # its scope, so it does not supersede the sweep's continuation.
        if job.kind != "scope" or job_lane(job.kind, payload) == "event":
            continue
        profile_id = str(payload.get("profile_id") or "")
        # list_jobs is newest first, so the first sweep seen for a profile is its
        # latest. Claim it whatever it says: a profile whose latest sweep finished
        # cleanly, failed, or is still going has nothing to carry on, and reading
        # past it would continue a run that a later one already superseded.
        if not profile_id or profile_id in seen:
            continue
        seen.add(profile_id)
        if job.status != "SUCCEEDED":
            continue
        coverage = job.coverage or {}
        if not str(coverage.get("stopped_reason") or "").startswith("BUDGET_"):
            continue
        if not _has_resumable_progress(repo, job):
            result["skipped"] += 1
            continue
        try:
            profile, plan, target, base, source = prepare_trigger_plan(
                repo, settings, profile_id, "RESUME", now=now)
            try:
                previous_id = uuid.UUID(str(payload.get("plan_id") or ""))
            except ValueError:
                raise scope.ScopeError("SCOPE_PLAN_STALE", http_status=409) from None
            previous = repo.get_plan(previous_id)
            if previous is None:
                raise scope.ScopeError("SCOPE_PLAN_STALE", http_status=409)
            # New approval or changed credentials are not permission to reuse
            # progress from the superseded run, even if its root IDs still match.
            scope.validate_execution(previous, profile, target, now=now)
            # A continuation continues that run; it does not become a different
            # kind of scan. prepare_trigger_plan turns verification off, which is
            # right for a schedule nobody asked for but wrong here: the first
            # half of this scope was verified because an operator asked for it,
            # and the rest would silently not be. The mode carries over for the
            # same reason -- a half-read BASELINE resumed as a DELTA would skip
            # objects as "unchanged" that it has never read.
            plan.verify = payload.get("verify")
            run = scope.run_payload(plan, profile, base, source)
            run.update(mode=payload.get("mode") or "BASELINE", requested_by="resume")
            if "reconcile_if_older_than_seconds" in payload:
                run["reconcile_if_older_than_seconds"] = payload["reconcile_if_older_than_seconds"]
            _job, created = repo.enqueue_triggered_scope(
                plan, ScanJob(kind="scope", connection_id=profile.connection_id, payload=run),
                _receipt("resume", str(job.id)),
            )
            result["enqueued" if created else "skipped"] += 1
        except scope.ScopeError:
            result["skipped"] += 1
    return result


def full_scan_cadence(profile, default: int) -> int:
    """A scope's full-scan minutes: its own (0 is off), or the installation default when it has none."""
    return default if profile.full_scan_minutes is None else profile.full_scan_minutes


def poll_schedules(repo, settings, *, now=None):
    """One bounded polling pass; database slot receipts make replicas idempotent.

    Full and delta cadences are independent; a scope without a full-scan cadence of
    its own follows the installation default (daily unless an Admin chose otherwise).
    Downtime does not replay historical slots: a current full scan observes the
    selected scope now. A full scan in a delta slot subsumes that delta request, and
    a slot is answered (its receipt names that run) by a whole-scope run of this
    approval that covers it and is still queued or began after the slot did: a
    scheduled one, or the first scan an Admin started when saving the scope. If that
    other run is then cancelled or fails, the slot is open again (see slot_states).
    A full-scan slot is due at its start plus the scope's spread (full_scan_offset), not before.

    A DELTA slot's run of a scope held after the upgrade (upgrade_hold) carries ``policy_hold``. The hold reads the
    digest the sweep pass recorded and its latched change, never this process's: a worker that has not loaded its rules
    yet would read the default rules' digest and hold nothing.
    """
    result = {"enqueued": 0, "skipped": 0, "coalesced": 0}
    now = _now(now)
    if not trigger_settings.schedules_on(settings, repo):
        return result
    cadence = trigger_settings.full_scan(settings, repo)
    origin = trigger_settings.schedule_origin(repo, now)
    held = upgrade_hold(repo, settings, now, origin)
    for key in [key for key, until in _refused.items() if until <= now]:
        _refused.pop(key, None)
    for candidate in repo.list_scheduled_profiles(cadence[0]):
        if candidate.state != "READY" or not candidate.approved_at or not candidate.approved_by:
            result["skipped"] += 1  # prepare_trigger_plan would refuse it; nothing is due until it is approved
            continue
        refusal = None
        try:
            # The listed row tells whether any slot is still open; only an open slot pays for a plan.
            # ponytail: one receipt lookup per slot per poll; batch them in one IN query if scopes reach the thousands.
            slots = slot_states(repo, candidate, now, cadence, origin)
            # The approval time too: a re-approval within one tick of the wall clock leaves updated_at as it was.
            refusal = (str(candidate.id), candidate.version, candidate.auth_revision, str(candidate.updated_at),
                       str(candidate.approved_at), tuple(slot.receipt for slot in slots if not slot.answered))
            if not refusal[-1] or refusal in _refused:
                result["skipped"] += len(slots)
                continue
            try:
                profile, plan, _target, base, source = prepare_trigger_plan(
                    repo, settings, candidate.id, "SCHEDULE", now=now)
            except scope.ScopeError:
                _refused[refusal] = now + timedelta(seconds=REFUSAL_SECONDS)
                result["skipped"] += 1
                continue
            for slot in slot_states(repo, profile, now, cadence, origin):
                if slot.answered:
                    result["skipped"] += 1
                elif repo.coalesce_scheduled_scope(slot.receipt, profile, plan.auth_revision, _COVERING[slot.mode],
                                                   slot.begins, slot.replaces) is not None:
                    result["coalesced"] += 1
                else:
                    run_plan = plan.model_copy(update={"id": uuid.uuid4()})
                    payload = scope.run_payload(run_plan, profile, base, source)
                    # slot_receipt marks the run as this slot's own: however it ends, it consumes the slot.
                    payload.update(mode=slot.mode, requested_by="schedule", schedule_kind=slot.kind,
                                   slot_receipt=slot.receipt)
                    if slot.mode == "DELTA" and held(profile):
                        payload["policy_hold"] = True
                    _job, created = repo.enqueue_triggered_scope(
                        run_plan, ScanJob(kind="scope", connection_id=profile.connection_id, payload=payload),
                        slot.receipt, slot.replaces)
                    result["enqueued" if created else "skipped"] += 1
        except Exception as exc:  # noqa: BLE001 -- one broken scope (a malformed catalog item) never stops the rest
            logger.warning("scheduled scan of scope %s failed: %s", candidate.id, type(exc).__name__)
            if refusal is not None:  # not every 5 s: its open slots wait like a refused plan's, never consumed
                _refused[refusal] = now + timedelta(seconds=REFUSAL_SECONDS)
            result["skipped"] += 1
    return result


class _Slot(NamedTuple):
    kind: str
    mode: str
    receipt: str
    begins: datetime
    ends: datetime
    answered: bool
    replaces: uuid.UUID | None  # the ended run a reopened slot's receipt still names; the new receipt swaps it out


def slot_states(repo, profile, now, cadence, origin=None):
    """Each slot due now, for the worker and the schedule views alike: a receipt, or a full scan subsuming it,
    answers a slot. A receipt naming another run the slot was merged into answers it no longer once that run was
    cancelled or failed; the slot's own scheduled run consumes it however it ended. For a scope approved before the
    schedule ``origin`` (trigger_settings.schedule_origin), a full-scan slot already due at the origin (its start plus
    the scope's spread at or before it) counts as answered: the upgrade's current slot is not run; one due after the
    origin runs at its due time, as for any scope. A full-scan slot ``ends`` when the next one is due."""
    out = []
    for kind, interval, slot, mode in schedule_slots(profile, now, *cadence):
        receipt = slot_receipt(profile, kind, interval, slot, cadence[1])
        begins = datetime.fromtimestamp(slot_start(kind, interval, slot, cadence[1]), UTC)
        spread = full_scan_offset(profile, interval) if kind == "full-scan" else 0
        skipped = (kind == "full-scan" and _before_origin(profile, origin)
                   and begins + timedelta(seconds=spread) <= origin)
        answered, replaces = (True, None) if skipped else repo.slot_receipt_state(receipt, begins)
        out.append(_Slot(kind, mode, receipt, begins, begins + timedelta(seconds=interval + spread),
                         answered or schedule_subsumed(repo, profile, kind, interval, slot, now, *cadence), replaces))
    return out


def _before_origin(profile, origin) -> bool:
    return origin is not None and profile.approved_at is not None and profile.approved_at < origin


def sweep_held(repo, profile, now, cadence, origin) -> bool:
    """Whether a policy sweep of a scope approved before the schedule ``origin`` waits for the full scan of its first
    full-scan slot due after the origin (the first slot_states does not skip), which re-reads the scope under the
    current policy (the runtime then skips what is policy-current). It waits until that slot is due (its start plus the
    scope's spread), has its receipt, and the run the receipt names has ended, in any status: a change run beside a
    full scan still running would re-read a stale root whole. A merged run that failed or was cancelled reopens the
    slot, which then waits for the run the next poll queues. It waits one slot at most. A scope without full scans
    (cadence 0) is never held: nothing else would re-read it. The caller holds nothing while schedules are off, for
    the same reason."""
    full = full_scan_cadence(profile, cadence[0])
    if not full or not _before_origin(profile, origin):
        return False
    interval, offset = full * 60, cadence[1] * 60
    spread = full_scan_offset(profile, interval)
    first = offset + (math.floor((origin.timestamp() - offset - spread) / interval) + 1) * interval
    due = first + spread
    if now.timestamp() >= due + interval:
        return False
    receipt = slot_receipt(profile, "full-scan", interval, (first - offset) // interval, cadence[1])
    return now.timestamp() < due or not repo.slot_run_ended(receipt, datetime.fromtimestamp(first, UTC))


# The longest an upgrade hold can last: sweep_held lets go at the latest one interval after the first slot due after
# the origin is due. That slot is due within one interval of the origin (the one before it was due at or before it),
# so the hold ends by origin + 2 intervals, whatever the spread; no cadence exceeds 1440 minutes (FULL_SCAN_CHOICES,
# scope.validate_profile_input).
MAX_HOLD = timedelta(minutes=2 * 1440)


def upgrade_hold(repo, settings, now, origin, detection_digest=None):
    """The one test of whether a scope is held after the upgrade, as ``profile -> bool``: approved before the schedule
    ``origin``, schedules on with a full-scan cadence, its first post-origin full scan not ended yet (sweep_held),
    and the detection policy the one recorded after the upgrade (trigger_settings.rules_unchanged; ``detection_digest``
    None reads only the recorded digest and its latched change). Its policy sweeps wait, and its DELTA slot and
    change-event runs carry ``policy_hold`` for the runtime. Cheap first: past MAX_HOLD, or for a scope approved after
    the origin, nothing more is read; the settings are read once per call, on the first scope that needs them."""
    if origin is None or now >= origin + MAX_HOLD:
        return lambda profile: False
    memo = {}

    def held(profile):
        if not _before_origin(profile, origin):
            return False
        if "cadence" not in memo:
            saved = trigger_settings.stored(repo)
            memo["cadence"] = (trigger_settings.full_scan(settings, repo, saved)
                               if trigger_settings.schedules_on(settings, repo, saved)
                               and trigger_settings.rules_unchanged(repo, detection_digest) else None)
        return memo["cadence"] is not None and sweep_held(repo, profile, now, memo["cadence"], origin)

    return held


def slot_start(kind, interval, slot, start_minute=trigger_settings.FULL_SCAN_START) -> int:
    """When a slot begins, in seconds since the epoch: a full scan's count from the start minute, the rest from
    midnight UTC."""
    return (start_minute * 60 if kind == "full-scan" else 0) + slot * interval


def slot_receipt(profile, kind, interval, slot, start_minute=trigger_settings.FULL_SCAN_START) -> str:
    """A slot's receipt. A full scan's names when its slot begins and how long it is, never its number, so no receipt
    of the earlier unanchored numbering or of another start minute answers a slot that has not run."""
    if kind == "full-scan":
        return _receipt(kind, str(profile.id), profile.version, slot_start(kind, interval, slot, start_minute), interval)
    return _receipt(kind, str(profile.id), profile.version, slot)


def full_scan_offset(profile, interval) -> int:
    """Seconds after its slot begins that a scope's full scan is due: a stable spread, by the scope's id, over
    min(4 hours, half the interval), so one night's full scans do not all start at the start minute. The same every day
    and on every replica, for the worker and the schedule view alike."""
    spread = max(1, min(240, interval // 120))
    return int(hashlib.sha256(str(profile.id).encode()).hexdigest(), 16) % spread * 60


def full_scan_slot(profile, now, interval, start_minute) -> int:
    """The scope's full-scan slot due at ``now``: the latest whose start plus full_scan_offset has passed."""
    return (int(now.timestamp()) - start_minute * 60 - full_scan_offset(profile, interval)) // interval


def schedule_slots(profile, now, full_default=0, start_minute=trigger_settings.FULL_SCAN_START):
    """Same effective cadences and receipts for the worker and dashboard.

    A full scan (RECONCILE) follows the scope's own cadence or ``full_default``, in slots counted from
    ``start_minute`` (UTC minute of the day): daily from that minute, 12-hourly then and 12 hours later, each due
    the scope's full_scan_offset after its start. An incremental slot, counted from midnight UTC, is always a DELTA.
    """
    full = full_scan_cadence(profile, full_default)
    if full:
        interval = full * 60
        yield "full-scan", interval, full_scan_slot(profile, now, interval, start_minute), "RECONCILE"
    if profile.schedule_minutes:
        interval = profile.schedule_minutes * 60
        yield "schedule", interval, int(now.timestamp()) // interval, "DELTA"


def schedule_subsumed(repo, profile, kind, interval, slot, now, full_default=0,
                      start_minute=trigger_settings.FULL_SCAN_START):
    """Whether a full scan answers this delta slot: one queued in the full-scan slot that began with this delta slot
    (or later), or the next one if it began by the time this delta slot did and is due (its start plus the scope's
    spread) before this delta slot ends. That delta waits for it and merges into it when it is queued, as it did at the
    start minute before the spread; a full scan due after the delta slot ends answers nothing, and the delta runs."""
    full = full_scan_cadence(profile, full_default)
    if kind != "schedule" or not full:
        return False
    full_interval = full * 60
    full_slot = full_scan_slot(profile, now, full_interval, start_minute)
    full_begins = slot_start("full-scan", full_interval, full_slot, start_minute)
    delta_begins = slot_start(kind, interval, slot)
    following = full_begins + full_interval
    if following <= delta_begins and following + full_scan_offset(profile, full_interval) < delta_begins + interval:
        return True
    return (full_begins >= delta_begins and repo.slot_receipt_state(
        slot_receipt(profile, "full-scan", full_interval, full_slot, start_minute),
        datetime.fromtimestamp(full_begins, UTC))[0])


def poll_policy_sweeps(repo, settings, orchestrator, *, cursor=None, limit=100, now=None):
    """Resweep only previously scanned, still-approved roots after a rule change.

    A caller carries next_cursor between bounded polling passes. No new root
    receives its first baseline merely because an operator changed a detector.
    """
    from cremore.db.scan_store import ScanStore

    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        raise ValueError("POLICY_SWEEP_PAGE_LIMIT")
    profiles, next_cursor = repo.list_scope_profiles_page(cursor=cursor, limit=limit)
    now, digest = _now(now), orchestrator.detection_policy_digest
    store = ScanStore(repo)
    result = {"enqueued": 0, "skipped": 0, "next_cursor": next_cursor}
    # After an upgrade, the next full scan re-reads a scope under the current policy; its sweep waits for it, unless
    # an Admin has changed rules since.
    trigger_settings.record_upgrade_digest(repo, digest)
    held = upgrade_hold(repo, settings, now, trigger_settings.schedule_origin(repo, now), digest)
    for candidate in profiles:
        if held(candidate):
            result["skipped"] += 1  # no receipt: queued on a later pass if it is still needed
            continue
        try:
            profile, plan, _target, base, source = prepare_trigger_plan(
                repo, settings, candidate.id, "POLICY_SWEEP", now=now)
            expanded_count = 0
            for approved in plan.roots:
                if approved["resource_type"] in ("NOTION_PAGE", "NOTION_DATA_SOURCE"):
                    expanded_count += 1 + len(approved.get("descendant_ids") or [])
                elif approved["resource_type"] == "S3_BUCKET" and not approved.get("all_current_objects"):
                    expanded_count += len(approved.get("prefixes") or [])
                else:
                    expanded_count += 1
                if expanded_count > 20_000:
                    break
            if expanded_count > 20_000:
                result["skipped"] += 1
                continue
            roots = scope.split_roots(plan.roots)
            identities = [scope.root_identity(profile.connection_id, root) for root in roots]
            # Extremely expanded page selections remain manual until split into
            # smaller approved profiles; never activate a partial unknown scope.
            if len(identities) > 20_000:
                result["skipped"] += 1
                continue
            states = store.roots(identities)
            changed = [root for root, identity in zip(roots, identities)
                       if states.get(identity, {}).get("watermark")
                       and states[identity].get("detection_digest")
                       and states[identity]["detection_digest"] != digest]
            if not changed:
                result["skipped"] += 1
                continue
            plan.roots = changed
            selected = {root["resource_id"] for root in changed}
            plan.known_count = len(selected)
            plan.policy_digest = scope.policy_digest(profile, plan.catalog_snapshot_id, plan.auth_revision,
                                                      {"sweep_roots": changed, "detection_digest": digest})
            payload = scope.run_payload(plan, profile, base, source)
            payload.update(mode="POLICY_SWEEP", requested_by="policy-sweep")
            _job, created = repo.enqueue_triggered_scope(
                plan, ScanJob(kind="scope", connection_id=profile.connection_id, payload=payload),
                _receipt("policy", str(profile.id), profile.version, digest),
            )
            result["enqueued" if created else "skipped"] += 1
        except scope.ScopeError:
            result["skipped"] += 1
    return result


def cleanup_trigger_receipts(repo, *, now=None, limit=10_000):
    """Discard old receipt metadata only; repository preserves active/policy jobs."""
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 10_000:
        raise ValueError("TRIGGER_CLEANUP_LIMIT")
    return repo.prune_trigger_receipts(_now(now) - timedelta(days=15), limit=limit)


def _native_events(body, roots):
    """Normalize S3 mutation notifications and the generic event; read events must not
    self-trigger. None when the body is neither."""
    by_bucket = {r["provider_resource_id"]: r["resource_id"] for r in roots if r["resource_type"] == "S3_BUCKET"}
    changes = {}

    def changed(bucket, key=None):
        if bucket not in by_bucket:
            raise scope.ScopeError("EVENT_OUT_OF_SCOPE", http_status=403)
        values = changes.setdefault(by_bucket[bucket], [])
        if key is None:
            changes[by_bucket[bucket]] = None
        elif values is not None:
            values.append(key)

    if isinstance(body, dict) and "Records" in body:
        records = body["Records"]
        if not isinstance(records, list) or not records or len(records) > MAX_EVENT_RECORDS:
            raise scope.ScopeError("EVENT_INVALID_PAYLOAD")
        for record in records:
            if (record.get("eventSource") != "aws:s3" or not str(record.get("eventName", "")).startswith(
                    ("ObjectCreated:", "ObjectRemoved:", "ObjectRestore:Completed", "ObjectTagging:", "ObjectAcl:"))):
                raise scope.ScopeError("EVENT_UNSUPPORTED_NOTIFICATION")
            changed(record["s3"]["bucket"]["name"], unquote_plus(record["s3"]["object"]["key"], errors="strict"))
    elif isinstance(body, dict) and body.get("source") == "aws.s3":
        detail = body.get("detail") or {}
        if body.get("detail-type") == "AWS API Call via CloudTrail":
            if detail.get("eventSource") != "s3.amazonaws.com" or detail.get("eventName") not in _S3_WRITES:
                raise scope.ScopeError("EVENT_UNSUPPORTED_NOTIFICATION")
            parameters = detail.get("requestParameters") or {}
            changed(parameters.get("bucketName"), parameters.get("key"))
        elif str(body.get("detail-type", "")).startswith("Object "):
            changed(detail["bucket"]["name"], detail.get("object", {}).get("key"))
        else:
            raise scope.ScopeError("EVENT_UNSUPPORTED_NOTIFICATION")
    elif isinstance(body, dict) and "resource_id" in body:
        return [{key: value for key, value in body.items() if key != "event_id"}]
    else:
        return None  # a source module's own notification, or none (_source_notices)
    return [{"resource_id": resource_id, "keys": keys or []} for resource_id, keys in changes.items()]


class SqsQueue:
    """The SQS queue behind the queue interface ``poll_queue`` reads: ``receive()`` returns
    up to ten ``{"id", "body", "attributes", "handle"}``; ``ack`` settles one after its work
    is durable."""

    def __init__(self, client, url):
        self.client, self.url = client, url

    def receive(self):
        response = self.client.receive_message(QueueUrl=self.url, MaxNumberOfMessages=10,
                                               WaitTimeSeconds=0, VisibilityTimeout=60)
        return [{"id": message.get("MessageId", ""), "body": message.get("Body", ""), "attributes": {},
                 "handle": message.get("ReceiptHandle")} for message in response.get("Messages", [])[:10]]

    def ack(self, message):
        self.client.delete_message(QueueUrl=self.url, ReceiptHandle=message["handle"])


def poll_sqs(repo, settings, client_factory, *, now=None):
    """Consume one batch from the explicitly dedicated SQS queue; never discover one.

    ``client_factory`` is called only once a binding exists, so a worker that
    never consumes a queue never builds an SQS client -- which would need a
    Region it may not have.
    """
    return poll_queue(repo, settings, "sqs", lambda url: SqsQueue(client_factory(), url), now=now)


def _source_notices(body, attributes, roots):
    """A source module's own notification (``queue_changes``); None when none recognises it."""
    from cremore.collectors.base import CollectorError
    from cremore.sources.registry import BY_RESOURCE_TYPE

    modules = {}
    for root in roots:
        modules.setdefault(BY_RESOURCE_TYPE[root["resource_type"]], []).append(root)
    for module, group in modules.items():
        read = getattr(module, "queue_changes", None)
        if not callable(read):
            continue
        try:
            answer = read(body, attributes, group)
        except CollectorError as exc:
            raise scope.ScopeError(exc.code, http_status=403 if exc.code == "EVENT_OUT_OF_SCOPE" else 400) from None
        if answer is not None:
            return answer
    return None


def _message_events(repo, profile, roots, body, attributes, feeds_on):
    """The events one queued message carries, each ``{"resource_id", <exact field>?, "mode"?}``."""
    from cremore.scanning import changes
    from cremore.sources.registry import EXACT_FIELDS

    events = _native_events(body, roots) if body is not None else None
    if events is not None:
        if not events:
            raise scope.ScopeError("EVENT_INVALID_PAYLOAD")
        return events
    answers = _source_notices(body, attributes, roots)
    if answers is None:
        raise scope.ScopeError("EVENT_UNSUPPORTED_NOTIFICATION")
    out = []
    for root in roots:
        change = answers.get(root["resource_id"])
        if change is None:
            continue
        # A push moved a repository whose feed already has a cursor: the feed reads it on
        # this same pass and its compare names the files (or sees the force push).
        if feeds_on and changes.wake(repo, profile, root):
            continue
        mode, values = changes.work_for(root, change)
        if mode is None:
            continue
        event = {"resource_id": root["resource_id"]}
        if values:
            event[EXACT_FIELDS[root["resource_type"]].removeprefix("exact_")] = values
        if mode == "BASELINE":
            event["mode"] = mode
        out.append(event)
    return out


def poll_queue(repo, settings, kind, open_queue, *, now=None):
    """Consume one batch from the dedicated queue an Admin bound (``kind`` in
    ``trigger_settings.QUEUES``); never discover one.

    The binding is read per pass, so an Admin who rebinds the queue or switches
    consumption off in the dashboard is obeyed by the next poll, not the next
    deployment. A binding that is not complete reads as off. ``open_queue(address)``
    is called only once a binding exists.

    A message is acknowledged only after every job it asks for is durable; one that
    fails validation or enqueue stays on the queue for its redrive policy.
    """
    binding = trigger_settings.queue_binding(settings, repo, kind)
    if binding is None:
        return {"acknowledged": 0, "failed": 0}
    profile_id, address = binding["profile_id"], binding["queue"]
    now = _now(now)
    queue = open_queue(address)
    profile, plan, _target, _base, _source = prepare_trigger_plan(repo, settings, profile_id, "EVENT", now=now)
    feeds_on = trigger_settings.change_feeds_on(settings, repo)
    result = {"acknowledged": 0, "failed": 0}
    for message in queue.receive()[:10]:
        try:
            raw, message_id = message.get("body"), message.get("id")
            if (not isinstance(message_id, str) or not message_id or len(message_id) > 256
                    or (raw is not None and (not isinstance(raw, str) or len(raw.encode()) > MAX_EVENT_BYTES))):
                raise scope.ScopeError("EVENT_INVALID_PAYLOAD")
            attributes = message.get("attributes") or {}
            if not isinstance(attributes, dict):
                raise scope.ScopeError("EVENT_INVALID_PAYLOAD")
            body = json.loads(raw) if raw else None
            # Events already enqueued keep their receipts, so a redelivery after a failure
            # part way returns them and adds only the rest.
            for event in _message_events(repo, profile, plan.roots, body, attributes, feeds_on):
                event["event_id"] = message_id
                mode = event.pop("mode", None)
                enqueue_event(repo, settings, profile_id, event, origin=kind, now=now, mode=mode,
                              receipt_id=_receipt(kind, address, message_id, event.get("resource_id")))
            queue.ack(message)
            result["acknowledged"] += 1
        except Exception:  # noqa: BLE001 -- any validation, durable enqueue or ACK failure leaves the message unacknowledged
            result["failed"] += 1
    return result
