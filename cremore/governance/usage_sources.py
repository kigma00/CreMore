"""Where an AWS key was last used from, read from the usage lookup already saved on its credential row.

Nothing here calls a provider. Like every usage fact (``cremore.api.credential_governance``), the addresses count only
when the lookup ran in the account that owns the key. CloudTrail names an AWS service call by its service host
(``AWS_INTERNAL``); that is not an IP address, and callers say so.
"""

from __future__ import annotations

from cremore_aws_provider.aws_sessions import account_of_arn

from cremore.risk.verification import timestamp

RECENT_SOURCES = 5


def owner_usage_snapshot(cred) -> dict | None:
    """The saved usage lookup, when it is proven to have run in the owner's account; else None."""
    snapshot = cred.usage_snapshot or {}
    owner = account_of_arn(cred.principal_arn)
    return snapshot if snapshot and owner and snapshot.get("collected_account_id") == owner else None


def recent_sources(cred, limit: int | None = RECENT_SOURCES) -> tuple[list[dict], int, bool]:
    """The distinct source addresses the saved lookup saw, newest first (address, kind, last seen, event count), up to
    ``limit``; with how many distinct addresses it saw, and whether that number is a lower bound."""
    snapshot = owner_usage_snapshot(cred) or {}
    summary = snapshot.get("summary") if isinstance(snapshot.get("summary"), dict) else {}
    events = snapshot.get("events") or []
    if isinstance(summary.get("sources"), dict):
        # Every event the lookup read (cremore_aws_provider.investigation.usage_pages.add_page).
        seen = {address: {"address": address, "kind": row.get("kind") or "HOSTNAME", "at": timestamp(row.get("last")),
                          "count": row.get("count") or 0}
                for address, row in summary["sources"].items() if isinstance(row, dict)}
        lower_bound = bool(summary.get("sources_untracked"))
        if lower_bound:
            # The tracked addresses are the first read, not the newest: the kept (newest) events' addresses join them.
            for address, kept in _kept_sources(events).items():
                entry = seen.setdefault(address, kept)
                entry["count"] = max(entry["count"], kept["count"])
                if kept["at"] and (entry["at"] is None or kept["at"] > entry["at"]):
                    entry["at"] = kept["at"]
    else:
        # Saved before every event's address was counted: only the events the snapshot kept.
        seen = _kept_sources(events)
        read = summary.get("events")
        lower_bound = isinstance(read, int) and read > len(events)  # the lookup read more events than it kept
    ordered = sorted(seen.values(), key=lambda entry: (entry["at"] is not None, entry["at"]), reverse=True)
    return [{"address": e["address"], "kind": e["kind"], "last_seen_at": e["at"].isoformat() if e["at"] else None,
             "count": e["count"]} for e in ordered[:limit]], len(seen), lower_bound


def _kept_sources(events) -> dict[str, dict]:
    """The distinct addresses of the events a snapshot kept, each with its latest time and how many events name it."""
    seen: dict[str, dict] = {}
    for event in events:
        address = event.get("source_address") if isinstance(event, dict) else None
        if not address or not isinstance(address, str):
            continue
        at = timestamp(event.get("event_time"))
        entry = seen.setdefault(address, {"address": address, "kind": event.get("source_address_kind") or "HOSTNAME",
                                          "at": None, "count": 0})
        entry["count"] += 1
        if at and (entry["at"] is None or at > entry["at"]):
            entry["at"] = at
    return seen
