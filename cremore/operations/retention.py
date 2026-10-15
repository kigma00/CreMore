"""Bound the SIEM outbox: drop events every active destination already received.

Heartbeats and test events matter for minutes, so they go a week after delivery.
Findings and connection events stay until SIEM_EVENT_RETENTION_DAYS says
otherwise (default 0: keep), because a new destination id replays what is kept.
"""

from __future__ import annotations

import datetime as _dt

from cremore.operations.health import utc
from cremore.siem.outbox import SiemOutbox

SLOT_KEY = "operations:siem-retention"
INTERVAL_SECONDS = 3600
SHORT_LIVED = ("platform.heartbeat", "siem.test")
SHORT_LIVED_FOR = _dt.timedelta(days=7)
# A destination the exporter has not reported for this long counts as removed.
ACTIVE_WITHIN = _dt.timedelta(days=30)


def prune(repo, settings, *, now=None, actor: str = "worker") -> int | None:
    """One replica per hour; None when another replica had this hour."""
    now = utc(now) or _dt.datetime.now(_dt.UTC)
    if not repo.claim_slot(SLOT_KEY, int(now.timestamp()) // INTERVAL_SECONDS, actor):
        return None
    days = settings.siem_event_retention_days
    return SiemOutbox(repo).prune(before=now - _dt.timedelta(days=days) if days else None,
                                  short_lived_before=now - SHORT_LIVED_FOR, short_lived_types=SHORT_LIVED,
                                  active_since=now - ACTIVE_WITHIN)
