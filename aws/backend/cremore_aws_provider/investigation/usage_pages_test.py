"""Every event's source address is counted into the summary, not only the newest 100 events the snapshot keeps."""

import datetime as dt
import json

from cremore_aws_provider.investigation import usage_pages as pages
from cremore_aws_provider.investigation.usage import event_from_lookup

BASE = dt.datetime(2026, 9, 1, tzinfo=dt.UTC)
START, END = "2026-07-01T00:00:00+00:00", "2026-10-01T00:00:00+00:00"


def entry(i, address):
    raw = {"eventName": "ListBuckets", "readOnly": True, **({"sourceIPAddress": address} if address else {})}
    return {"EventId": str(i), "EventName": "ListBuckets", "EventSource": "s3.amazonaws.com",
            "EventTime": BASE + dt.timedelta(minutes=i), "CloudTrailEvent": json.dumps(raw)}


def collect(addresses, snapshot=None):
    """CloudTrail answers newest first, 50 events a page; event i happened i minutes after BASE."""
    snapshot = snapshot or pages.start_snapshot("AKIASYNTHETIC", ["us-east-1"], "COMPLETE", "", START, END)
    rows = [entry(i, address) for i, address in reversed(list(enumerate(addresses)))]
    for offset in range(0, len(rows), 50):
        following = str(offset + 50) if offset + 50 < len(rows) else None
        pages.add_page(snapshot, 0, [event_from_lookup(row, "us-east-1") for row in rows[offset:offset + 50]], following)
    return snapshot


def at(i):
    return (BASE + dt.timedelta(minutes=i)).isoformat()


def test_every_event_counts_its_address_while_only_the_newest_100_are_kept():
    recent = ["203.0.113.5", "cloudtrail.amazonaws.com", "2001:db8::1", "198.51.100.1", "198.51.100.2", "192.0.2.9"]
    # 198.51.100.7 is used only in the 30 oldest calls, so none of the 100 kept events carries it.
    addresses = ["198.51.100.7" if i < 30 else recent[i % 6] for i in range(249)] + [None]
    snapshot = collect(addresses)
    summary = snapshot["summary"]
    assert summary["events"] == 250 and summary["services"]["s3"]["calls"] == 250 and summary["last_success"] == at(249)
    assert len(snapshot["events"]) == 100 and snapshot["events"][0]["event_id"] == "249"
    assert "198.51.100.7" not in {event.get("source_address") for event in snapshot["events"]}
    assert summary["sources_untracked"] == 0 and len(summary["sources"]) == 7
    assert summary["sources"]["198.51.100.7"] == {"kind": "IPV4", "count": 30, "last": at(29)}
    # 219 calls from i = 30..248 rotate through six addresses: i % 6 == 0, 1, 2 occur 37 times, 3, 4, 5 occur 36.
    assert summary["sources"]["203.0.113.5"] == {"kind": "IPV4", "count": 37, "last": at(246)}
    assert summary["sources"]["cloudtrail.amazonaws.com"] == {"kind": "AWS_INTERNAL", "count": 37, "last": at(247)}
    assert summary["sources"]["2001:db8::1"] == {"kind": "IPV6", "count": 37, "last": at(248)}
    assert summary["sources"]["192.0.2.9"] == {"kind": "IPV4", "count": 36, "last": at(245)}
    assert sum(row["count"] for row in summary["sources"].values()) == 249  # the call with no address counts nowhere


def test_addresses_beyond_the_cap_are_counted_as_untracked():
    addresses = [f"10.0.{i // 256}.{i % 256}" for i in range(pages.MAX_SOURCES + 43)] + ["10.0.0.0"]
    summary = collect(addresses)["summary"]
    assert len(summary["sources"]) == pages.MAX_SOURCES
    # 10.0.0.0 took a row with the newest call, so its oldest call, read after the cap filled, still counts there.
    assert summary["sources"]["10.0.0.0"]["count"] == 2
    assert summary["sources_untracked"] == 43  # 10.0.0.1..10.0.0.43 came after it filled


def test_only_an_address_shaped_value_becomes_a_key_so_the_stored_tally_stays_small():
    host = "h" * 245 + ".example"  # 253 characters, the longest DNS name
    odd = ["h" * 246 + ".example", "\U0001f600" * 200, "203.0.113.5\n", "<!channel>"]
    summary = collect([host, *odd, "AWS Internal", "::ffff:192.0.2.1"])["summary"]
    assert set(summary["sources"]) == {host, "AWS Internal", "::ffff:192.0.2.1"}
    assert summary["sources"][host]["kind"] == "HOSTNAME" and summary["sources"]["::ffff:192.0.2.1"]["kind"] == "IPV6"
    assert summary["sources_untracked"] == len(odd) and summary["events"] == 7  # counted, just not by address
    # Worst case: every row a 253-character key. Stored as JSON with ASCII escapes, it stays under 100 KB.
    worst = collect([f"{i:03d}" + "h" * 250 for i in range(pages.MAX_SOURCES)] + ["\U0001f600" * 2048] * 10)["summary"]
    assert len(worst["sources"]) == pages.MAX_SOURCES and worst["sources_untracked"] == 10
    assert len(json.dumps(worst["sources"]).encode()) < 100_000


def test_a_lookup_started_before_addresses_were_counted_is_left_to_its_kept_events():
    snapshot = pages.start_snapshot("AKIASYNTHETIC", ["us-east-1"], "COMPLETE", "", START, END)
    for field in ("sources", "sources_untracked"):
        del snapshot["summary"][field]
    summary = collect(["203.0.113.5"] * 60, snapshot)["summary"]
    assert "sources" not in summary and "sources_untracked" not in summary and summary["events"] == 60
