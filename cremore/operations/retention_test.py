"""The SIEM outbox drops only what every active destination received and retention allows."""

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from cremore.config import Settings
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.operations import retention
from cremore.siem import outbox
from cremore.siem.events import operational_event, platform_heartbeat, siem_test
from cremore.siem.outbox import SiemOutbox

SETTINGS = Settings(AUTH_MODE="local", API_TOKEN="retention-" + "t" * 32, FINGERPRINT_KEY="ab" * 32)
NOW = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)


@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    if request.param == "postgres":
        return request.getfixturevalue("pg")[1]
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def connection_event(at):
    item = {"kind": "VAULT", "id": str(uuid.uuid4()), "provider": "vault", "auth_state": "READY", "auth_reason": None,
            "auth_renewal": "EXTERNAL", "expiry_stage": "NONE", "expires_at": None, "freshness": "STALE",
            "last_status": "COMPLETE", "last_success_at": None, "last_failure_code": None}
    return operational_event("collection.stale", item, previous=None, sequence=1, now=at)


def deliver_all(queue, destination):
    for row in queue.claim(destination, limit=1000):
        queue.acknowledge(destination, row["event"]["event_id"], row["token"])


def remaining(repo):
    return sorted(row["event"]["event_type"] for row in SiemOutbox(repo).claim("inspector", limit=1000))


def test_short_lived_events_go_a_week_after_every_active_destination_received_them(repo):
    queue = SiemOutbox(repo)
    for event in (platform_heartbeat(now=NOW - timedelta(days=8), slot=1, interval_seconds=300, workers_alive=1,
                                     queued_jobs=0, oldest_queued_seconds=None),
                  platform_heartbeat(now=NOW - timedelta(days=1), slot=2, interval_seconds=300, workers_alive=1,
                                     queued_jobs=0, oldest_queued_seconds=None),
                  siem_test(now=NOW - timedelta(days=8), nonce=uuid.uuid4()),
                  connection_event(NOW - timedelta(days=100))):
        assert repo.record_siem_event(event)
    queue.record_status("soc", "IDLE")
    assert retention.prune(repo, SETTINGS, now=NOW) == 0  # soc has not received them yet
    deliver_all(queue, "soc")
    assert retention.prune(repo, SETTINGS, now=NOW + timedelta(hours=1)) == 2
    keep_thirty_days = SETTINGS.model_copy(update={"siem_event_retention_days": 30})
    assert retention.prune(repo, keep_thirty_days, now=NOW + timedelta(hours=2)) == 1
    assert remaining(repo) == ["platform.heartbeat"]


def test_a_destination_gone_for_a_month_no_longer_blocks_pruning(repo, monkeypatch):
    queue = SiemOutbox(repo)
    repo.record_siem_event(siem_test(now=NOW - timedelta(days=9), nonce=uuid.uuid4()))
    monkeypatch.setattr(outbox, "_clock", lambda conn=None: NOW - timedelta(days=40))
    queue.record_status("retired", "IDLE")
    monkeypatch.undo()
    assert retention.prune(repo, SETTINGS, now=NOW) == 1


def test_one_replica_prunes_each_hour(repo):
    assert retention.prune(repo, SETTINGS, now=NOW) == 0
    assert retention.prune(repo, SETTINGS, now=NOW + timedelta(minutes=59)) is None
    assert retention.prune(repo, SETTINGS, now=NOW + timedelta(minutes=60)) == 0


def test_the_retention_setting_is_bounded():
    with pytest.raises(ValueError):
        Settings(AUTH_MODE="local", API_TOKEN="retention-" + "t" * 32, FINGERPRINT_KEY="ab" * 32,
                 SIEM_EVENT_RETENTION_DAYS=-1)
