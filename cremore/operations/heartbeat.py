"""Liveness that a SOC and an outside monitor can see: worker beats and platform.heartbeat.

Every worker records its own beat each maintenance tick. One replica per interval
queues a platform.heartbeat event, so a SIEM that stops receiving it knows that
CreMore, its database or its exporter stopped -- CreMore never has to report its
own death.
"""

from __future__ import annotations

import datetime as _dt
import socket

from cremore import __version__
from cremore.operations.health import utc
from cremore.siem.events import platform_heartbeat

WORKER_PREFIX = "operations:worker:"
SLOT_KEY = "operations:heartbeat"
# Workers beat once a minute; three missed beats mean the process is gone or stuck.
ALIVE_WITHIN = _dt.timedelta(minutes=3)
RETAIN = _dt.timedelta(hours=24)


def beat(repo, worker_id: str, started_at, *, now=None) -> None:
    now = utc(now) or _dt.datetime.now(_dt.UTC)
    repo.put_setting(WORKER_PREFIX + worker_id, {
        "worker_id": worker_id, "host": socket.gethostname()[:64], "version": __version__,
        "started_at": utc(started_at).isoformat(), "beat_at": now.isoformat()}, "worker")


def workers(repo, *, now=None) -> list[dict]:
    """Workers seen in the retention window, newest beat first."""
    now = utc(now) or _dt.datetime.now(_dt.UTC)
    rows = []
    for record in repo.list_settings(WORKER_PREFIX):
        value = dict(record["value"] or {})
        beat_at = utc(value.get("beat_at"))
        value["alive"] = beat_at is not None and now - beat_at <= ALIVE_WITHIN
        rows.append(value)
    return sorted(rows, key=lambda row: row.get("beat_at") or "", reverse=True)


def queue(repo, *, now=None) -> dict:
    now = utc(now) or _dt.datetime.now(_dt.UTC)
    summary = repo.job_queue_summary()
    oldest = utc(summary["oldest_queued_at"])
    return {"queued": summary["queued"],
            "oldest_queued_seconds": max(0, int((now - oldest).total_seconds())) if oldest else None}


def publish(repo, settings, *, now=None, actor: str = "worker") -> bool:
    """Queue this interval's platform.heartbeat once across every replica."""
    now = utc(now) or _dt.datetime.now(_dt.UTC)
    interval = settings.operations_heartbeat_minutes * 60
    slot = int(now.timestamp()) // interval
    # The interval is part of the key: shortening or lengthening it starts a new counter.
    if not repo.claim_slot(f"{SLOT_KEY}:{interval}", slot, actor):
        return False
    repo.delete_settings_before(WORKER_PREFIX, now - RETAIN)
    waiting = queue(repo, now=now)
    repo.record_siem_event(platform_heartbeat(
        now=now, slot=slot, interval_seconds=interval,
        workers_alive=sum(row["alive"] for row in workers(repo, now=now)),
        queued_jobs=waiting["queued"], oldest_queued_seconds=waiting["oldest_queued_seconds"]))
    return True
