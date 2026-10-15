"""Bounded CloudTrail pages and aggregate evidence for durable background reads.

The worker commits each page's aggregate and its cursor together. Event History
is a management-event query, not a complete archive of service/data activity.
"""

import datetime as dt
import hashlib
import json
import re

from cremore_aws_provider.investigation.usage import (
    TECHNIQUE_REVISION,
    TECHNIQUES,
    classify_call,
    empty_usage,
    event_from_lookup,
)

MAX_REQUESTS = 10_000
RECENT_EVENTS = 100
MAX_SOURCES = 256  # distinct addresses counted exactly; events from further ones only add to sources_untracked
_SERVICE = re.compile(r"[a-z0-9.-]{1,128}")
# An IP, a DNS name (at most 253) or "AWS Internal": ASCII only, so a stored key is as many bytes as characters.
_ADDRESS = re.compile(r"[\w .:-]{1,253}", re.ASCII)


def start_snapshot(key, regions, discovery, discovery_error, start, end):
    snapshot = empty_usage(key)
    snapshot.update(collection_status="PARTIAL", region_discovery_status=discovery,
                    window_start=start, window_end=end, collected_at=end,
                    regions_discovered=len(regions), requests_used=0, request_limit=MAX_REQUESTS,
                    summary={"events": 0, "denied": 0, "services": {}, "techniques": {}, "sources": {}, "sources_untracked": 0},
                    coverage=[{"region": region, "status": "PENDING", "event_scope": "MANAGEMENT",
                               "evidence_source": "EVENT_HISTORY", "events_collected": 0,
                               "window_start": start, "window_end": end, "collected_at": end}
                              for region in regions])
    if discovery_error:
        snapshot["region_discovery_error"] = discovery_error
    return snapshot


def read_page(client, key, region, start, end, cursor, seen):
    args = {"LookupAttributes": [{"AttributeKey": "AccessKeyId", "AttributeValue": key}],
            "StartTime": dt.datetime.fromisoformat(start), "EndTime": dt.datetime.fromisoformat(end),
            "MaxResults": 50}
    if cursor:
        args["NextToken"] = cursor
    page = client.lookup_events(**args)
    rows, following = page.get("Events"), page.get("NextToken")
    if not isinstance(rows, list) or len(rows) > 50 or any(not isinstance(row, dict) for row in rows):
        raise ValueError("CLOUDTRAIL_RESPONSE_MALFORMED")
    if following is not None and (not isinstance(following, str) or len(following) > 4096
                                 or hashlib.sha256(following.encode()).hexdigest() in seen):
        raise ValueError("CLOUDTRAIL_PAGINATION_INCOMPLETE")
    return [event_from_lookup(row, region) for row in rows], following


def add_page(snapshot, index, events, following):
    """Count every call; retain only bounded recent detail, independently of coverage."""
    summary = snapshot["summary"]
    sources = summary.get("sources")  # absent from a lookup started before addresses were counted: left to its events
    coverage = snapshot["coverage"][index]
    for event in events:
        summary["events"] += 1
        summary["denied"] += event["outcome"] == "DENIED"
        name = event["event_source"]
        name = name.removesuffix(".amazonaws.com") if _SERVICE.fullmatch(name) else "unknown"
        services = summary["services"]
        if name not in services and len(services) >= 512:
            name = "other"
        row = services.setdefault(name, {"service": name, "calls": 0, "writes": 0, "denied": 0, "last": None})
        row["calls"] += 1
        row["writes"] += event["access_mode"] == "WRITE"
        row["denied"] += event["outcome"] == "DENIED"
        when = event["event_time"][:40]
        if event["outcome"] == "SUCCEEDED" and when > summary.get("last_success", ""):
            summary["last_success"] = when
        if when and (not row["last"] or when > row["last"]):
            row["last"] = when
        if technique := classify_call(event["event_name"]):
            summary["techniques"][technique] = summary["techniques"].get(technique, 0) + 1
        if sources is not None and (address := event.get("source_address")):
            # Not shaped like an address, or past the cap: counted, but not by address (the total is a lower bound).
            if not _ADDRESS.fullmatch(address) or (address not in sources and len(sources) >= MAX_SOURCES):
                summary["sources_untracked"] += 1
            else:
                seen = sources.setdefault(address, {"kind": event.get("source_address_kind") or "HOSTNAME",
                                                    "count": 0, "last": None})
                seen["count"] += 1
                if when and (not seen["last"] or when > seen["last"]):
                    seen["last"] = when
        if event["outcome"] == "UNKNOWN" and not event.get("error_code"):
            coverage["error_code"] = "EVENT_DETAILS_UNAVAILABLE"
        # The snapshot is for investigation, not an event archive. Keep the
        # newest 100 bounded normalized rows; omitted detail never drops counts.
        detail = {key: value[:2048] if isinstance(value, str) else value
                  for key, value in event.items() if key != "resources"}
        detail["resources"] = []
        if len(json.dumps(detail).encode()) <= 8192:
            snapshot["events"].append(detail)
    snapshot["events"].sort(key=lambda row: row.get("event_time", ""), reverse=True)
    del snapshot["events"][RECENT_EVENTS:]
    coverage["events_collected"] += len(events)
    coverage["status"] = "PENDING" if following else "PARTIAL" if coverage.get("error_code") else "COMPLETE"
    snapshot["requests_used"] += 1


def finish_view(snapshot):
    coverage = snapshot["coverage"]
    for status, field in (("COMPLETE", "regions_complete"), ("FAILED", "regions_failed"), ("CAPPED", "regions_capped")):
        snapshot[field] = sum(row["status"] == status for row in coverage)
    snapshot["collection_status"] = (
        "COMPLETE" if coverage and all(row["status"] == "COMPLETE" for row in coverage)
        and snapshot["region_discovery_status"] == "COMPLETE" else
        "FAILED" if not coverage or all(row["status"] == "FAILED" for row in coverage) else "PARTIAL")
    summary = snapshot["summary"]
    snapshot["techniques"] = {"revision": TECHNIQUE_REVISION, "total_events": summary["events"],
                              "classified_events": sum(summary["techniques"].values()),
                              "observed": [{"technique_id": key, "technique_name": TECHNIQUES[key][0], "events": count}
                                           for key, count in sorted(summary["techniques"].items(), key=lambda row: (-row[1], row[0]))]}
    return snapshot
