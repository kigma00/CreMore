"""Held deliveries, destination status and labels, on memory, SQLite and PostgreSQL."""

import logging
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.siem import outbox
from cremore.siem.config import ExportConfig
from cremore.siem.contract import DeliveryError, SinkProvider, event_family
from cremore.siem.events import siem_test
from cremore.siem.outbox import SiemOutbox
from cremore.siem.runner import Exporter
from cremore.siem.sinks.splunk_hec import SplunkHECSink

T0 = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def store(request, monkeypatch):
    now = {"value": T0}
    monkeypatch.setattr(outbox, "_clock", lambda conn=None: now["value"])
    if request.param == "memory":
        repo = InMemoryRepository()
    elif request.param == "postgres":
        repo = request.getfixturevalue("pg")[1]
    else:
        engine = make_engine("sqlite+pysqlite:///:memory:")
        create_all(engine)
        repo = SqlRepository(engine)
    return repo, SiemOutbox(repo), now


def queue_events(repo, count):
    events = [siem_test(now=T0 + timedelta(seconds=index), nonce=uuid.uuid4()) for index in range(count)]
    for event in events:
        assert repo.record_siem_event(event)
    return events


def test_a_held_delivery_waits_for_an_admin_while_the_rest_flow(store):
    repo, queue, now = store
    first, second = queue_events(repo, 2)
    row, = queue.claim("soc", limit=1)
    assert row["event"]["event_id"] == first["event_id"]
    assert queue.retry("soc", first["event_id"], row["token"], error_code="HTTP_STATUS_REJECTED",
                       delay_seconds=0, hold=True)
    row, = queue.claim("soc", limit=1)
    assert row["event"]["event_id"] == second["event_id"]
    assert queue.acknowledge("soc", second["event_id"], row["token"])
    now["value"] = T0 + timedelta(hours=2)
    assert queue.claim("soc", limit=10) == []
    status, = queue.status()
    assert (status["destination"], status["pending"], status["held"], status["oldest_pending_at"]) == (
        "soc", 0, 1, None)
    held, = queue.deliveries(first["event_id"])
    assert (held["destination"], held["error_code"], held["attempts"]) == ("soc", "HTTP_STATUS_REJECTED", 1)
    assert held["held_at"] == T0.isoformat()
    assert queue.release_held("soc") == 1
    assert queue.release_held("soc") == 0
    row, = queue.claim("soc", limit=10)
    assert (row["event"]["event_id"], row["attempts"]) == (first["event_id"], 1)
    with pytest.raises(ValueError, match="SIEM_INVALID_DESTINATION"):
        queue.release_held("bad destination")


def test_status_counts_what_each_destination_still_owes(store):
    repo, queue, _now = store
    first, second = queue_events(repo, 2)
    queue.record_status("soc", "IDLE")
    row, = queue.claim("soc", limit=1)
    queue.acknowledge("soc", first["event_id"], row["token"])
    by_name = {row["destination"]: row for row in queue.status()}
    assert by_name["soc"]["pending"] == 1
    assert by_name["soc"]["oldest_pending_at"] == datetime.fromisoformat(second["occurred_at"]).isoformat()
    queue.record_status("archive", "IDLE")
    by_name = {row["destination"]: row for row in queue.status()}
    assert by_name["archive"]["pending"] == 2 and by_name["archive"]["last_seen_at"] == T0.isoformat()


def test_destination_status_tracks_consecutive_failures_with_safe_codes(store):
    _repo, queue, now = store
    queue.record_status("soc", "FAILURE", error_code="HTTP_STATUS_REJECTED")
    now["value"] = T0 + timedelta(minutes=1)
    queue.record_status("soc", "FAILURE", error_code="leaked https://example.invalid/token")
    row, = queue.status()
    assert (row["consecutive_failures"], row["last_error_code"]) == (2, "DELIVERY_FAILED")
    assert row["last_failure_at"] == (T0 + timedelta(minutes=1)).isoformat() and row["last_success_at"] is None
    queue.record_status("soc", "SUCCESS")
    row, = queue.status()
    assert (row["consecutive_failures"], row["last_success_at"]) == (0, (T0 + timedelta(minutes=1)).isoformat())
    assert row["last_error_code"] == "DELIVERY_FAILED"  # the last failure stays visible after recovery
    with pytest.raises(ValueError, match="SIEM_INVALID_OUTCOME"):
        queue.record_status("soc", "MAYBE")


class Sink:
    def __init__(self, fail=None):
        self.fail, self.events = fail, []

    def send(self, event):
        if self.fail:
            raise self.fail
        self.events.append(event)

    def close(self):
        pass


def exporter(queue, monkeypatch, sink, **config):
    monkeypatch.setattr("cremore.siem.runner.load_provider", lambda *a, **k: SinkProvider("fake", lambda _: sink))
    return Exporter(queue, ExportConfig.model_validate({"destinations": [{"id": "soc", "provider": "fake"}],
                                                        **config}))


def test_the_exporter_holds_after_max_attempts_and_records_status(store, monkeypatch):
    repo, queue, now = store
    queue_events(repo, 1)
    run = exporter(queue, monkeypatch, Sink(DeliveryError("HTTP_STATUS_REJECTED")), max_attempts=2)
    counts = run.run_once()
    assert (counts.failed, counts.held) == (1, 0)
    now["value"] = T0 + timedelta(hours=2)
    counts = run.run_once()
    assert (counts.failed, counts.held) == (1, 1)
    now["value"] = T0 + timedelta(days=2)
    assert run.run_once().failed == 0  # held: nothing is claimed any more
    row, = queue.status()
    assert (row["held"], row["consecutive_failures"], row["last_error_code"]) == (1, 2, "HTTP_STATUS_REJECTED")


def test_without_a_cap_the_exporter_keeps_retrying(store, monkeypatch):
    repo, queue, now = store
    queue_events(repo, 1)
    run = exporter(queue, monkeypatch, Sink(RuntimeError("body with https://secret.invalid")))
    for hour in range(1, 5):
        now["value"] = T0 + timedelta(hours=hour * 2)
        assert run.run_once().failed == 1
    row, = queue.status()
    assert (row["held"], row["pending"], row["last_error_code"]) == (0, 1, "DELIVERY_FAILED")


def test_retry_after_is_durable_and_never_shortens_backoff(store, monkeypatch):
    repo, queue, now = store
    queue_events(repo, 1)
    sink = Sink(DeliveryError("DELIVERY_RATE_LIMITED", retry_after_seconds=120))
    run = exporter(queue, monkeypatch, sink)
    assert run.run_once().failed == 1
    # Restarting the exporter does not lose the provider's rate-limit deadline.
    run.close()
    sink.fail = None
    run = exporter(queue, monkeypatch, sink)
    now["value"] = T0 + timedelta(seconds=119)
    assert run.run_once().delivered == 0
    now["value"] = T0 + timedelta(seconds=120)
    assert run.run_once().delivered == 1


@pytest.mark.parametrize("value, expected", [(True, None), ("3", None), (-1, 0), (90000, 86400), (0, 0)])
def test_retry_hint_is_bounded(value, expected):
    assert DeliveryError(retry_after_seconds=value).retry_after_seconds == expected


def test_a_status_write_failure_never_stops_delivery(store, monkeypatch, caplog):
    repo, queue, _now = store
    queue_events(repo, 1)
    sink = Sink()
    run = exporter(queue, monkeypatch, sink)

    def broken(*args, **kwargs):
        raise RuntimeError("permission denied for table siem_destination_status")

    monkeypatch.setattr(queue, "record_status", broken)
    with caplog.at_level(logging.WARNING):
        assert run.run_once().delivered == 1
    assert len(sink.events) == 1 and "SIEM_STATUS_WRITE_FAILED" in caplog.text
    assert "permission denied" not in caplog.text


@pytest.mark.parametrize("event_type, family", [
    ("finding.created", "finding"), ("connection.auth_failed", "connection"), ("collection.stale", "collection"),
    ("platform.heartbeat", "platform"), ("siem.test", "siem"), ("unknown.kind", "other"), (None, "other"),
])
def test_event_families(event_type, family):
    assert event_family(event_type) == family


def test_splunk_sourcetype_follows_the_event_family():
    class Response:
        def json(self):
            return {"code": 0}

    sent = []
    sink = object.__new__(SplunkHECSink)
    sink._post = lambda payload, status=None: sent.append(payload) or Response()
    sink.send(siem_test(now=T0, nonce=uuid.uuid4()))
    sink.send({"event_type": "finding.created", "occurred_at": "2026-09-27T12:00:00Z"})
    assert [payload["sourcetype"] for payload in sent] == ["cremore:siem", "cremore:finding"]
