"""Worker beats, the platform heartbeat event and the liveness the operations status shows."""

import os
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from cremore.api import create_app
from cremore.config import Settings
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.schema import installation_settings
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import ScanJob
from cremore.operations import heartbeat
from cremore.siem.outbox import SiemOutbox
from cremore.worker.worker import JobWorker

TOKEN = "heartbeat-test-" + "t" * 32
SETTINGS = Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32, OPERATIONS_HEARTBEAT_MINUTES=5)
NOW = datetime.now(UTC)
# The start of a five-minute heartbeat slot, so offsets below land where they claim.
BASE = NOW.replace(microsecond=0) - timedelta(seconds=int(NOW.timestamp()) % 300)


@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    if request.param == "postgres":
        return request.getfixturevalue("pg")[1]
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def written_at(repo, key, when):
    """Pretend a setting was last written at ``when``; put_setting stamps the real clock."""
    if isinstance(repo, InMemoryRepository):
        repo.installation_settings[key]["updated_at"] = when
    else:
        with repo.engine.begin() as conn:
            conn.execute(update(installation_settings).where(installation_settings.c.key == key).values(
                updated_at=when))


def heartbeats(repo):
    return [row["event"] for row in SiemOutbox(repo).claim("probe", limit=100)
            if row["event"]["event_type"] == "platform.heartbeat"]


def test_a_worker_is_alive_until_it_misses_three_beats(repo):
    heartbeat.beat(repo, "w1", BASE - timedelta(hours=1), now=BASE)
    heartbeat.beat(repo, "w2", BASE - timedelta(hours=1), now=BASE - timedelta(minutes=4))
    rows = heartbeat.workers(repo, now=BASE + timedelta(minutes=1))
    assert [(row["worker_id"], row["alive"]) for row in rows] == [("w1", True), ("w2", False)]
    assert rows[0]["version"] and rows[0]["host"] and rows[0]["started_at"]


def test_one_heartbeat_per_interval_across_replicas(repo):
    assert heartbeat.publish(repo, SETTINGS, now=BASE) is True
    assert heartbeat.publish(repo, SETTINGS, now=BASE + timedelta(minutes=4)) is False
    assert heartbeat.publish(repo, SETTINGS, now=BASE + timedelta(minutes=5)) is True
    beats = heartbeats(repo)
    assert len(beats) == 2 and {beat["platform"]["interval_seconds"] for beat in beats} == {300}
    assert len({beat["event_id"] for beat in beats}) == 2
    # A changed interval gets its own counter, so neither direction can stall it.
    one_minute = SETTINGS.model_copy(update={"operations_heartbeat_minutes": 1})
    assert heartbeat.publish(repo, one_minute, now=BASE + timedelta(minutes=6)) is True
    assert heartbeat.publish(repo, SETTINGS, now=BASE + timedelta(minutes=10)) is True


def test_the_heartbeat_counts_live_workers_and_waiting_jobs_and_prunes_old_beats(repo):
    later = datetime.now(UTC) + timedelta(minutes=10)
    heartbeat.beat(repo, "gone", later - timedelta(days=3), now=later - timedelta(days=2))
    written_at(repo, heartbeat.WORKER_PREFIX + "gone", later - timedelta(days=2))
    heartbeat.beat(repo, "live", later - timedelta(hours=1), now=later)
    repo.enqueue_job(ScanJob(kind="synthetic-queue-probe", payload={}))
    repo.enqueue_job(ScanJob(kind="synthetic-queue-probe", payload={}))
    assert heartbeat.publish(repo, SETTINGS, now=later) is True
    assert [row["worker_id"] for row in heartbeat.workers(repo, now=later)] == ["live"]
    platform = heartbeats(repo)[0]["platform"]
    assert platform["workers_alive"] == 1 and platform["queued_jobs"] == 2
    assert 500 <= platform["oldest_queued_seconds"] <= 700


def test_the_heartbeat_event_names_no_host_or_worker():
    from cremore.siem.events import platform_heartbeat

    event = platform_heartbeat(now=BASE, slot=7, interval_seconds=300, workers_alive=2, queued_jobs=-1,
                               oldest_queued_seconds=None)
    assert set(event) == {"schema_version", "event_id", "event_type", "occurred_at", "product", "platform"}
    assert event["platform"] == {"interval_seconds": 300, "workers_alive": 2, "queued_jobs": None,
                                 "oldest_queued_seconds": None}
    assert event["event_id"] == platform_heartbeat(now=NOW, slot=7, interval_seconds=300, workers_alive=0,
                                                   queued_jobs=0, oldest_queued_seconds=0)["event_id"]


def test_the_worker_beats_and_publishes_from_its_maintenance_tick():
    repo = InMemoryRepository()
    worker = JobWorker(repo, settings=SETTINGS)
    worker.poll_triggers()
    rows = heartbeat.workers(repo)
    assert [(row["worker_id"], row["alive"]) for row in rows] == [(worker.worker_id, True)]
    assert len(heartbeats(repo)) == 1


def test_the_operations_status_shows_worker_liveness():
    repo = InMemoryRepository()
    client = TestClient(create_app(repo=repo, settings=SETTINGS))
    auth = {"Authorization": f"Bearer {TOKEN}"}
    worker = client.get("/api/v1/operations/status", headers=auth).json()["worker"]
    assert (worker["availability"], worker["alive"], worker["observed"]) == ("EXTERNAL_PROBE_REQUIRED", 0, 0)
    assert worker["queue_delay_seconds"] is None and worker["heartbeat_interval_minutes"] == 5
    heartbeat.beat(repo, "w1", datetime.now(UTC) - timedelta(hours=1))
    repo.enqueue_job(ScanJob(kind="synthetic-queue-probe", payload={}))
    body = client.get("/api/v1/operations/status", headers=auth).json()
    worker = body["worker"]
    assert (worker["availability"], worker["alive"], worker["instances"][0]["worker_id"]) == (
        "HEARTBEAT_OBSERVED", 1, "w1")
    assert worker["queue_delay_seconds"] >= 0
    assert "WORKER_HEARTBEAT_MISSING" not in {alert["code"] for alert in body["alerts"]}
    heartbeat.beat(repo, "w1", datetime.now(UTC) - timedelta(hours=1), now=datetime.now(UTC) - timedelta(minutes=10))
    body = client.get("/api/v1/operations/status", headers=auth).json()
    assert body["worker"]["availability"] == "HEARTBEAT_MISSING"
    assert {"code": "WORKER_HEARTBEAT_MISSING", "resource_type": "worker", "resource_id": "all"} in body["alerts"]


def test_the_interval_setting_is_bounded():
    with pytest.raises(ValueError):
        Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32, OPERATIONS_HEARTBEAT_MINUTES=0)
    with pytest.raises(ValueError):
        Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32, OPERATIONS_HEARTBEAT_MINUTES=61)
