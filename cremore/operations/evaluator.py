"""Publish connection-health changes as SIEM events, once, from one worker.

Every worker replica calls this from its maintenance tick. A per-minute slot in
installation settings lets exactly one replica evaluate. The last published
state of every connection is kept, so only a change becomes an event
(edge-triggered). Events are queued before the new state is saved: a crash in
between derives the same transitions with the same event ids next time, and the
outbox keeps one copy.
"""

from __future__ import annotations

import datetime as _dt

from cremore.operations import health
from cremore.siem.events import delivery_state, operational_event
from cremore.siem.outbox import SiemOutbox

SLOT_KEY = "operations:health-evaluation"
STATE_KEY = "operations:health-state"
INTERVAL_SECONDS = 60
STATE_FIELDS = ("auth_state", "expiry_stage", "last_status", "freshness")
_FAILED_AUTH = ("REAUTH_REQUIRED", "PERMISSION_LIMITED", "SECRET_UNAVAILABLE")
# The exporter normally drains within seconds; these mean a destination is behind.
BACKLOG_AFTER = _dt.timedelta(minutes=15)
FAILURES_BEFORE_BACKLOG = 5
# The exporter writes a status row every pass (default every 5 s); two minutes of
# silence means it is not running or cannot reach the database.
EXPORTER_SEEN_WITHIN = _dt.timedelta(minutes=2)


def exporter_active(row: dict, now) -> bool:
    seen = health.utc(row["last_seen_at"])
    return seen is not None and now - seen <= EXPORTER_SEEN_WITHIN


def backlogged(row: dict, now) -> bool:
    """A destination holds events, keeps failing, or has let one wait too long."""
    oldest = health.utc(row["oldest_pending_at"])
    return bool(row["held"]) or row["consecutive_failures"] >= FAILURES_BEFORE_BACKLOG or (
        oldest is not None and now - oldest > BACKLOG_AFTER)


def transitions(previous: dict | None, item: dict) -> list[tuple[str, str | None]]:
    """(event_type, recovered_from) for each change a SOC should hear about."""
    if item["auth_state"] == "DISABLED":
        return []  # stopping a connection is an operator decision, audited where it is made
    was = previous or {}
    out = []
    auth, before = item["auth_state"], was.get("auth_state")
    if auth in _FAILED_AUTH and auth != before:
        out.append(("connection.auth_failed", None))
    elif before in _FAILED_AUTH and auth in ("READY", "EXPIRING"):
        out.append(("connection.auth_recovered", None))
    # D3 after D14 is the second warning; D14 after D3 means a later expiry was recorded.
    if item["expiry_stage"] in ("D14", "D3") and item["expiry_stage"] != was.get("expiry_stage"):
        out.append(("connection.auth_expiring", None))
    status, last = item["last_status"], was.get("last_status")
    if status == "FAILED" and last != "FAILED":
        out.append(("collection.failed", None))
    elif last == "FAILED" and status in ("COMPLETE", "PARTIAL"):
        out.append(("collection.recovered", "FAILED"))
    fresh, was_fresh = item["freshness"], was.get("freshness")
    if fresh == "STALE" and was_fresh != "STALE":
        out.append(("collection.stale", None))
    elif was_fresh == "STALE" and fresh == "FRESH":
        out.append(("collection.recovered", "STALE"))
    return out


def publish(repo, settings, *, now=None, actor: str = "worker") -> dict:
    """Evaluate once per slot and queue one event per transition."""
    now = health.utc(now) or _dt.datetime.now(_dt.UTC)
    if not repo.claim_slot(SLOT_KEY, int(now.timestamp()) // INTERVAL_SECONDS, actor):
        return {"evaluated": False, "events": 0}
    stored = (repo.get_setting(STATE_KEY) or {}).get("value") or {}
    items = health.evaluate(repo, settings, now=now)
    states, queued = {}, 0
    for item in items:
        previous = stored.get(item["key"])
        changes = transitions(previous, item)
        sequence = int((previous or {}).get("sequence", 0)) + bool(changes)
        for event_type, recovered_from in changes:
            queued += repo.record_siem_event(operational_event(
                event_type, item, previous=previous, sequence=sequence, now=now, recovered_from=recovered_from))
        states[item["key"]] = {**{field: item[field] for field in STATE_FIELDS}, "sequence": sequence}
    destinations = SiemOutbox(repo).status()
    for row in destinations:
        key, behind = "siem:" + row["destination"], backlogged(row, now)
        previous = stored.get(key) or {}
        was = bool(previous.get("backlogged"))
        change = ("siem.delivery_backlog" if behind and not was
                  else "siem.delivery_recovered" if was and not behind else None)
        sequence = int(previous.get("sequence", 0)) + bool(change)
        if change:
            queued += repo.record_siem_event(delivery_state(change, row, sequence=sequence, now=now))
        states[key] = {"backlogged": behind, "sequence": sequence}
    repo.put_setting(STATE_KEY, states, actor)
    return {"evaluated": True, "events": queued, "connections": len(items), "destinations": len(destinations)}
