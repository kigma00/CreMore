"""Where a key was used from: the saved lookup's addresses, newest first, and only from the owner's account."""

from cremore.domain.models import Credential
from cremore.governance.usage_sources import recent_sources

ARN = "arn:aws:iam::123456789012:user/ci"


def key(events, account="123456789012", arn=ARN, **snapshot):
    return Credential(fingerprint="f", credential_type="AWS_ACCESS_KEY", provider="aws", principal_arn=arn,
                      usage_snapshot={"collected_account_id": account, "events": events, **snapshot})


def event(address, day, kind="IPV4", hour=5):
    return {"event_time": f"2026-10-{day:02d}T{hour:02d}:00:00+00:00", "source_address": address, "source_address_kind": kind}


def test_only_a_lookup_in_the_owner_account_names_addresses():
    events = [event("203.0.113.5", 1)]
    summary = {"events": 1, "sources": {"203.0.113.5": {"kind": "IPV4", "count": 1, "last": "2026-10-01T05:00:00+00:00"}},
               "sources_untracked": 3}
    for snapshot in ({}, {"summary": summary}):
        assert [s["address"] for s in recent_sources(key(events, **snapshot))[0]] == ["203.0.113.5"]
        assert recent_sources(key(events, account="999999999999", **snapshot)) == ([], 0, False)
        assert recent_sources(key(events, arn=None, **snapshot)) == ([], 0, False)
    assert recent_sources(Credential(fingerprint="f", credential_type="AWS_ACCESS_KEY", principal_arn=ARN)) == ([], 0, False)


def test_addresses_are_distinct_newest_first_counted_and_bounded():
    events = [event("198.51.100.1", 1), event("198.51.100.2", 2), event("198.51.100.1", 3), event("198.51.100.1", 3, hour=2),
              *(event(f"192.0.2.{n}", 4 + n) for n in range(5)),
              {"event_time": "2026-10-30T00:00:00+00:00"}, {"source_address": 7}, "not an event"]
    got, total, lower_bound = recent_sources(key(events))
    assert [s["address"] for s in got] == [f"192.0.2.{n}" for n in (4, 3, 2, 1, 0)]
    assert (total, lower_bound) == (7, False)  # a lookup with no summary kept every event it read
    every, _total, _lower_bound = recent_sources(key(events), None)
    assert len(every) == 7
    repeated = {s["address"]: s for s in every}["198.51.100.1"]
    assert repeated == {"address": "198.51.100.1", "kind": "IPV4", "last_seen_at": "2026-10-03T05:00:00+00:00", "count": 3}


def test_an_aws_service_host_keeps_its_kind_and_an_untimed_address_goes_last():
    events = [{"source_address": "198.51.100.9", "source_address_kind": "IPV4"},
              event("cloudtrail.amazonaws.com", 2, "AWS_INTERNAL")]
    expected = [("cloudtrail.amazonaws.com", "AWS_INTERNAL", False), ("198.51.100.9", "IPV4", True)]
    assert [(s["address"], s["kind"], s["last_seen_at"] is None) for s in recent_sources(key(events))[0]] == expected
    summary = {"sources": {"198.51.100.9": {"kind": "IPV4", "count": 4, "last": None},
                           "cloudtrail.amazonaws.com": {"kind": "AWS_INTERNAL", "count": 1, "last": "2026-10-02T05:00:00+00:00"}}}
    assert [(s["address"], s["kind"], s["last_seen_at"] is None) for s in recent_sources(key([], summary=summary))[0]] == expected


def test_the_summary_of_every_event_read_wins_over_the_kept_events():
    # The kept (newest) events saw one address; the summary counted every event the lookup read.
    kept = [event("203.0.113.5", 9)] * 3
    sources = {"203.0.113.5": {"kind": "IPV4", "count": 40, "last": "2026-10-09T05:00:00+00:00"},
               **{f"192.0.2.{n}": {"kind": "IPV4", "count": n, "last": f"2026-09-{n:02d}T00:00:00+00:00"} for n in range(1, 7)}}
    got, total, lower_bound = recent_sources(key(kept, summary={"events": 61, "sources": sources, "sources_untracked": 0}))
    assert (total, lower_bound) == (7, False)
    assert got == [{"address": "203.0.113.5", "kind": "IPV4", "last_seen_at": "2026-10-09T05:00:00+00:00", "count": 40},
                   *({"address": f"192.0.2.{n}", "kind": "IPV4", "last_seen_at": f"2026-09-{n:02d}T00:00:00+00:00", "count": n}
                     for n in (6, 5, 4, 3))]
    # Events from addresses past the summary's cap: the distinct count is a lower bound.
    assert recent_sources(key(kept, summary={"events": 70, "sources": sources, "sources_untracked": 9}))[1:] == (7, True)


def test_past_the_cap_the_newest_kept_events_join_the_tracked_addresses():
    # The cap filled with the first addresses read; the newest calls came from 203.0.113.9, which it could not track.
    sources = {f"192.0.2.{n}": {"kind": "IPV4", "count": 50, "last": f"2026-09-{n:02d}T00:00:00+00:00"} for n in range(1, 7)}
    kept = [event("203.0.113.9", 21), event("203.0.113.9", 20), event("192.0.2.6", 22), event("192.0.2.6", 22, hour=1)]
    got, total, lower_bound = recent_sources(key(kept, summary={"events": 400, "sources": sources, "sources_untracked": 30}))
    # Each address once: the larger count (the summary's 50 over the kept 2) and the later time (the kept 22nd).
    assert got == [{"address": "192.0.2.6", "kind": "IPV4", "last_seen_at": "2026-10-22T05:00:00+00:00", "count": 50},
                   {"address": "203.0.113.9", "kind": "IPV4", "last_seen_at": "2026-10-21T05:00:00+00:00", "count": 2},
                   *({"address": f"192.0.2.{n}", "kind": "IPV4", "last_seen_at": f"2026-09-{n:02d}T00:00:00+00:00", "count": 50}
                     for n in (5, 4, 3))]
    assert (total, lower_bound) == (7, True)


def test_a_lookup_saved_before_addresses_were_summarised_falls_back_to_the_kept_events():
    kept = [event("203.0.113.5", 9), event("198.51.100.1", 8)]
    # It read 250 events and kept 2: what the kept events name is a lower bound.
    got, total, lower_bound = recent_sources(key(kept, summary={"events": 250, "denied": 0, "services": {}, "techniques": {}}))
    assert [s["address"] for s in got] == ["203.0.113.5", "198.51.100.1"] and (total, lower_bound) == (2, True)
    # It kept every event it read: exact.
    assert recent_sources(key(kept, summary={"events": 2, "services": {}}))[1:] == (2, False)
