"""Edge-triggered connection-health events: once per change, once per slot, allowlisted."""

import json
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text, update

from cremore.config import Settings
from cremore.coverage.models import ConnectionSpec, Contract, Finish
from cremore.coverage.store import CoverageStore
from cremore.db.migrations import SIEM_EVENT_KINDS_VERSION, siem_event_kinds
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import Connection
from cremore.operations import evaluator
from cremore.siem.events import OPERATIONAL_EVENT_TYPES, operational_event
from cremore.siem.outbox import SiemOutbox

SETTINGS = Settings(AUTH_MODE="local", API_TOKEN="evaluator-" + "t" * 32, FINGERPRINT_KEY="ab" * 32)
# Minute-aligned and relative to the real clock: present_connection judges expiry by it.
T0 = datetime.now(UTC).replace(second=0, microsecond=0)


@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    if request.param == "postgres":
        return request.getfixturevalue("pg")[1]
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def item(**changes):
    base = {"key": "content:1", "kind": "CONTENT", "id": str(uuid.uuid4()), "provider": "github",
            "name": "secret-looking name", "auth_state": "READY", "auth_reason": None, "auth_renewal": "MANUAL",
            "expires_at": None, "expires_source": None, "expiry_stage": "NONE", "last_success_at": None,
            "last_failure_at": None, "last_failure_code": None, "last_status": "COMPLETE", "freshness": "FRESH",
            "stale_after_hours": 24}
    return base | changes


def state(**changes):
    return {field: item()[field] for field in evaluator.STATE_FIELDS} | changes


@pytest.mark.parametrize("previous, current, expected", [
    (None, {}, []),
    (None, {"auth_state": "REAUTH_REQUIRED"}, [("connection.auth_failed", None)]),
    (state(), {"auth_state": "PERMISSION_LIMITED"}, [("connection.auth_failed", None)]),
    (state(auth_state="PERMISSION_LIMITED"), {"auth_state": "SECRET_UNAVAILABLE"}, [("connection.auth_failed", None)]),
    (state(auth_state="REAUTH_REQUIRED"), {"auth_state": "REAUTH_REQUIRED"}, []),
    (state(auth_state="REAUTH_REQUIRED"), {}, [("connection.auth_recovered", None)]),
    (state(auth_state="DISABLED"), {"auth_state": "REAUTH_REQUIRED"}, [("connection.auth_failed", None)]),
    (state(auth_state="REAUTH_REQUIRED"), {"auth_state": "DISABLED"}, []),
    (state(), {"auth_state": "UNKNOWN"}, []),
    (state(), {"auth_state": "EXPIRING", "expiry_stage": "D14"}, [("connection.auth_expiring", None)]),
    (state(auth_state="EXPIRING", expiry_stage="D14"), {"auth_state": "EXPIRING", "expiry_stage": "D14"}, []),
    (state(auth_state="EXPIRING", expiry_stage="D14"), {"auth_state": "EXPIRING", "expiry_stage": "D3"},
     [("connection.auth_expiring", None)]),
    (state(), {"last_status": "FAILED"}, [("collection.failed", None)]),
    (state(last_status="FAILED"), {"last_status": "FAILED"}, []),
    (state(last_status="FAILED"), {"last_status": "PARTIAL"}, [("collection.recovered", "FAILED")]),
    (state(), {"freshness": "STALE"}, [("collection.stale", None)]),
    (state(freshness="STALE"), {}, [("collection.recovered", "STALE")]),
    (state(freshness="STALE"), {"freshness": "NOT_SCHEDULED"}, []),
    (None, {"last_status": "FAILED", "freshness": "STALE"}, [("collection.failed", None), ("collection.stale", None)]),
])
def test_only_a_change_is_worth_an_event(previous, current, expected):
    assert evaluator.transitions(previous, item(**current)) == expected


def test_the_event_carries_codes_and_ids_but_no_names():
    current = item(auth_state="REAUTH_REQUIRED", auth_reason="GITHUB_APP_REJECTED",
                   last_failure_code="not a code: provider text", provider="made-up-provider",
                   expires_at="2026-10-01T00:00:00+00:00")
    event = operational_event("connection.auth_failed", current, previous=state(), sequence=3, now=T0)
    assert event["connection"] == {"id": current["id"], "kind": "CONTENT", "provider": "UNKNOWN"}
    assert event["health"]["reason"] == "GITHUB_APP_REJECTED"
    assert event["health"]["previous_auth_state"] == "READY"
    assert event["health"]["last_failure_code"] is None
    assert event["health"]["expires_at"] == "2026-10-01T00:00:00Z"
    assert event["occurred_at"] == T0.isoformat().replace("+00:00", "Z")
    assert "secret-looking name" not in json.dumps(event) and "provider text" not in json.dumps(event)
    again = operational_event("connection.auth_failed", current, previous=state(), sequence=3, now=T0 + timedelta(1))
    assert again["event_id"] == event["event_id"]
    assert operational_event("connection.auth_failed", current, previous=None, sequence=4, now=T0)["event_id"] != event["event_id"]
    with pytest.raises(ValueError, match="SIEM_UNKNOWN_EVENT_TYPE"):
        operational_event("finding.created", current, previous=None, sequence=1, now=T0)
    assert set(OPERATIONAL_EVENT_TYPES) >= {"connection.auth_failed", "collection.stale"}


def events(repo):
    """Queued events in time order; ties sort by type, since event ids are not ordered."""
    claimed = SiemOutbox(repo).claim("probe", limit=1000)
    return sorted((row["event"] for row in claimed),
                  key=lambda e: (e["occurred_at"], e["event_type"], e["health"]["recovered_from"] or ""))


def test_publishing_is_edge_triggered_and_once_per_slot(repo):
    c = repo.create_connection(Connection(provider="github", name="app", status="ACTIVE", config={},
                                          secret_ref="vault://synthetic/token"))
    repo.update_connection(c.id, credential_evidence={"status": "ACTIVE", "checked_at": T0.isoformat()})
    assert evaluator.publish(repo, SETTINGS, now=T0) == {"evaluated": True, "events": 0, "connections": 1,
                                                       "destinations": 0}
    assert evaluator.publish(repo, SETTINGS, now=T0 + timedelta(seconds=30))["evaluated"] is False
    repo.update_connection(c.id, credential_evidence={"status": "REJECTED", "error": "GITHUB_APP_REJECTED",
                                                      "checked_at": T0.isoformat()})
    assert evaluator.publish(repo, SETTINGS, now=T0 + timedelta(minutes=1))["events"] == 1
    assert evaluator.publish(repo, SETTINGS, now=T0 + timedelta(minutes=2))["events"] == 0
    repo.update_connection(c.id, credential_evidence={"status": "ACTIVE", "checked_at": T0.isoformat(),
                                                      "expires_at": (T0 + timedelta(days=10)).isoformat()})
    assert evaluator.publish(repo, SETTINGS, now=T0 + timedelta(minutes=3))["events"] == 2
    queued = events(repo)
    assert [e["event_type"] for e in queued] == [
        "connection.auth_failed", "connection.auth_expiring", "connection.auth_recovered"]
    assert queued[0]["health"]["reason"] == "GITHUB_APP_REJECTED"
    assert queued[1]["health"]["expiry_stage"] == "D14"
    assert all(e["connection"]["id"] == str(c.id) and "app" not in json.dumps(e["connection"]) for e in queued)


def test_a_crash_before_saving_state_does_not_duplicate_events(repo):
    c = repo.create_connection(Connection(provider="github", name="app", status="ACTIVE", config={},
                                          secret_ref="vault://synthetic/token"))
    repo.update_connection(c.id, credential_evidence={"status": "REJECTED", "checked_at": T0.isoformat()})
    original = repo.put_setting

    def crash(key, value, actor):
        raise RuntimeError("simulated crash after events were queued")

    repo.put_setting = crash
    with pytest.raises(RuntimeError):
        evaluator.publish(repo, SETTINGS, now=T0)
    repo.put_setting = original
    assert evaluator.publish(repo, SETTINGS, now=T0 + timedelta(minutes=1))["events"] == 0
    assert [e["event_type"] for e in events(repo)] == ["connection.auth_failed"]


def test_only_one_replica_wins_a_slot(repo):
    slot = int(T0.timestamp()) // evaluator.INTERVAL_SECONDS
    assert repo.claim_slot(evaluator.SLOT_KEY, slot, "worker-a") is True
    assert repo.claim_slot(evaluator.SLOT_KEY, slot, "worker-b") is False
    assert repo.claim_slot(evaluator.SLOT_KEY, slot - 1, "worker-b") is False
    assert repo.claim_slot(evaluator.SLOT_KEY, slot + 1, "worker-b") is True


def test_collection_events_follow_runs_and_freshness(repo):
    store = CoverageStore(repo)
    owner, _ = store.create(ConnectionSpec(name="Vault", provider="aws_secrets_manager", account_id="123456789012",
                                           regions=["us-east-1"]), "admin")

    def finish(status, at, reasons=()):
        """A run that happened at ``at``: the store stamps real time, so move it afterwards."""
        run = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), Contract(engine_digest="d" * 64).model_dump())
        store.finish(owner["id"], run["id"], Finish(batch_count=0, item_count=0, status=status, reasons=list(reasons)))
        if isinstance(repo, InMemoryRepository):
            store.memory["runs"][run["id"]].update(started_at=at, finished_at=at)
        else:
            with repo.engine.begin() as conn:
                conn.execute(update(store.runs).where(store.runs.c.id == run["id"]).values(
                    started_at=at, finished_at=at))

    finish("COMPLETE", T0)
    assert evaluator.publish(repo, SETTINGS, now=T0 + timedelta(minutes=1))["events"] == 0
    assert evaluator.publish(repo, SETTINGS, now=T0 + timedelta(hours=25))["events"] == 1
    finish("FAILED", T0 + timedelta(hours=25, minutes=1), ["NETWORK_UNAVAILABLE"])
    assert evaluator.publish(repo, SETTINGS, now=T0 + timedelta(hours=25, minutes=2))["events"] == 1
    finish("COMPLETE", T0 + timedelta(hours=25, minutes=3))
    assert evaluator.publish(repo, SETTINGS, now=T0 + timedelta(hours=25, minutes=4))["events"] == 2
    queued = events(repo)
    assert [(e["event_type"], e["health"]["recovered_from"]) for e in queued] == [
        ("collection.stale", None), ("collection.failed", None),
        ("collection.recovered", "FAILED"), ("collection.recovered", "STALE")]
    assert queued[1]["health"]["last_failure_code"] == "NETWORK_UNAVAILABLE"
    assert {e["connection"]["kind"] for e in queued} == {"VAULT"}


def test_the_same_operational_event_is_queued_once(repo):
    event = operational_event("collection.stale", item(), previous=None, sequence=1, now=T0)
    assert repo.record_siem_event(event) is True
    assert repo.record_siem_event(event) is False
    assert [e["event_id"] for e in events(repo)] == [event["event_id"]]


def test_an_upgraded_postgres_outbox_accepts_operational_events(pg):
    engine, repo = pg
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE siem_events ALTER COLUMN finding_id SET NOT NULL"))
        conn.execute(text("DELETE FROM schema_migrations WHERE version = :v"), {"v": SIEM_EVENT_KINDS_VERSION})
    with engine.begin() as conn:
        siem_event_kinds(conn)
        siem_event_kinds(conn)
    assert repo.record_siem_event(operational_event("collection.stale", item(), previous=None, sequence=1, now=T0))
    with engine.connect() as conn:
        nullable = conn.execute(text("SELECT is_nullable FROM information_schema.columns "
                                     "WHERE table_name = 'siem_events' AND column_name = 'finding_id' "
                                     "AND table_schema = current_schema()")).scalar_one()
    assert nullable == "YES"


def test_a_destination_that_falls_behind_is_announced_once_and_recovers(repo):
    from cremore.siem.events import siem_test

    queue = SiemOutbox(repo)
    repo.record_siem_event(siem_test(now=T0, nonce=uuid.uuid4()))
    for _ in range(evaluator.FAILURES_BEFORE_BACKLOG):
        queue.record_status("soc", "FAILURE", error_code="HTTP_STATUS_REJECTED")
    assert evaluator.publish(repo, SETTINGS, now=T0 + timedelta(minutes=1))["events"] == 1
    assert evaluator.publish(repo, SETTINGS, now=T0 + timedelta(minutes=2))["events"] == 0
    for row in queue.claim("soc", limit=100):
        queue.acknowledge("soc", row["event"]["event_id"], row["token"])
    queue.record_status("soc", "SUCCESS")
    assert evaluator.publish(repo, SETTINGS, now=T0 + timedelta(minutes=3))["events"] == 1
    announced = [row["event"] for row in queue.claim("archive", limit=100)
                 if row["event"]["event_type"].startswith("siem.delivery")]
    announced.sort(key=lambda e: e["occurred_at"])
    assert [e["event_type"] for e in announced] == ["siem.delivery_backlog", "siem.delivery_recovered"]
    assert announced[0]["delivery"] == {"destination": "soc", "pending": 1, "held": 0, "oldest_pending_seconds": 60,
                                        "consecutive_failures": 5, "last_error_code": "HTTP_STATUS_REJECTED"}


def test_backlog_rules():
    now = T0
    row = {"held": 0, "consecutive_failures": 0, "oldest_pending_at": None}
    assert evaluator.backlogged(row, now) is False
    assert evaluator.backlogged({**row, "held": 1}, now) is True
    assert evaluator.backlogged({**row, "consecutive_failures": 5}, now) is True
    assert evaluator.backlogged({**row, "oldest_pending_at": (now - timedelta(minutes=14)).isoformat()}, now) is False
    assert evaluator.backlogged({**row, "oldest_pending_at": (now - timedelta(minutes=16)).isoformat()}, now) is True
    assert evaluator.exporter_active({"last_seen_at": (now - timedelta(seconds=90)).isoformat()}, now) is True
    assert evaluator.exporter_active({"last_seen_at": (now - timedelta(minutes=3)).isoformat()}, now) is False
    assert evaluator.exporter_active({"last_seen_at": None}, now) is False
