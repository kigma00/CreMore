"""coverage.verdict_changed: baseline, changes, suspension, cap and replay."""

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from cremore.coverage.correlation import scope_revision
from cremore.coverage.hasher import hash_value
from cremore.coverage.models import Batch, ConnectionSpec, Finish
from cremore.coverage.store import CoverageStore
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.detection import ResourceRef
from cremore.detection.engine import Engine, EngineConfig
from cremore.operations import coverage_verdicts
from cremore.scanning.orchestrator import Orchestrator
from cremore.siem.outbox import SiemOutbox

KEY = b"k" * 32
GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
ACCOUNT = "123456789012"
ARN = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:app/db-Ab12Cd"


@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def stack(request):
    if request.param == "memory":
        repo = InMemoryRepository()
    elif request.param == "postgres":
        repo = request.getfixturevalue("pg")[1]
    else:
        engine = make_engine("sqlite+pysqlite:///:memory:")
        create_all(engine)
        repo = SqlRepository(engine)
    engine = Engine(EngineConfig(fingerprint_key=KEY))
    orchestrator = Orchestrator(repo, engine=engine, config=engine.config)
    return repo, orchestrator


SECOND = "ghp_" + "Zy9xW8vU7tS6rQ5pO4nM3lK2jI1hG0fE9dC8"


def vault_run(repo, orchestrator, connection, *, stored, materials=(GH,)):
    store = CoverageStore(repo)
    run = store.start(connection["id"], connection["revision"], str(uuid.uuid4()),
                      {"schema_version": 1, "tool_version": "0.1.0",
                       "scheme": "cremore-credential-fingerprint-v1/hmac-sha256",
                       "engine_digest": orchestrator.engine.detection_digest,
                       "policy_digest": orchestrator.coverage_policy_digest})
    items = [item for index, material in enumerate(materials) for item in hash_value(
        orchestrator.engine, material.encode(), {"reference": ARN.replace("app/db", f"app/db{index}"),
                                                 "account_id": ACCOUNT, "region": "us-east-1", "version": "v1"},
        max_bytes=1024)] if stored else []
    if items:
        store.append(connection["id"], run["id"], Batch(index=0, items=items))
    store.finish(connection["id"], run["id"], Finish(batch_count=int(bool(items)), item_count=len(items), status="COMPLETE"))


def setup(repo, orchestrator):
    orchestrator.scan_resource(GH.encode(), ResourceRef(source_type="inline", resource="synthetic", location="fixture"),
                               verify=False)
    store = CoverageStore(repo)
    connection, _ = store.create(ConnectionSpec(name="SM", provider="aws_secrets_manager", account_id=ACCOUNT,
                                                regions=["us-east-1"]), "admin")
    repo.put_setting("coverage_scope", {"confirmed": True, "revision": scope_revision(store.list_connections())}, "admin")
    return connection


def verdicts(repo):
    return [row["event"] for row in SiemOutbox(repo).claim("probe-" + uuid.uuid4().hex[:8], limit=100)
            if row["event"]["event_type"] == "coverage.verdict_changed"]


def test_baseline_is_silent_then_each_change_is_one_event(stack):
    repo, orchestrator = stack
    connection = setup(repo, orchestrator)
    vault_run(repo, orchestrator, connection, stored=True)
    now = datetime.now(UTC)
    assert coverage_verdicts.publish(repo, None, orchestrator, now=now) == 0  # baseline
    assert coverage_verdicts.publish(repo, None, orchestrator, now=now) == 0  # same slot: another replica won
    vault_run(repo, orchestrator, connection, stored=False)
    assert coverage_verdicts.publish(repo, None, orchestrator, now=now + timedelta(minutes=5)) == 1
    [event] = verdicts(repo)
    verdict = event["verdict"]
    assert (verdict["previous_state"], verdict["state"], verdict["origin"]) == ("MATCHED", "NO_VAULT_MATCH", "EXPOSURE")
    assert verdict["absence_basis"] == "API_LISTING" and event["installation_id"]
    assert GH not in str(event) and ARN not in str(event)
    # Unchanged in the next slot: nothing new.
    assert coverage_verdicts.publish(repo, None, orchestrator, now=now + timedelta(minutes=10)) == 0


def test_an_unconfirmed_scope_suspends_publishing(stack):
    repo, orchestrator = stack
    connection = setup(repo, orchestrator)
    vault_run(repo, orchestrator, connection, stored=True)
    now = datetime.now(UTC)
    coverage_verdicts.publish(repo, None, orchestrator, now=now)
    repo.put_setting("coverage_scope", {"confirmed": False, "revision": "0" * 64}, "admin")
    vault_run(repo, orchestrator, connection, stored=False)
    assert coverage_verdicts.publish(repo, None, orchestrator, now=now + timedelta(minutes=5)) == 0
    assert verdicts(repo) == []


def test_a_capped_pass_continues_and_a_replay_keeps_one_copy(stack, monkeypatch):
    repo, orchestrator = stack
    connection = setup(repo, orchestrator)
    orchestrator.scan_resource(SECOND.encode(), ResourceRef(source_type="inline", resource="second", location="fixture"),
                               verify=False)
    vault_run(repo, orchestrator, connection, stored=True, materials=(GH, SECOND))
    now = datetime.now(UTC)
    coverage_verdicts.publish(repo, None, orchestrator, now=now)
    vault_run(repo, orchestrator, connection, stored=False)
    monkeypatch.setattr(coverage_verdicts, "MAX_EVENTS", 1)
    # A crash after queueing but before saving repeats the same event id.
    saving = coverage_verdicts._Store.save
    monkeypatch.setattr(coverage_verdicts._Store, "save", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        coverage_verdicts.publish(repo, None, orchestrator, now=now + timedelta(minutes=5))
    monkeypatch.setattr(coverage_verdicts._Store, "save", saving)
    assert coverage_verdicts.publish(repo, None, orchestrator, now=now + timedelta(minutes=10)) == 1
    assert coverage_verdicts.publish(repo, None, orchestrator, now=now + timedelta(minutes=15)) == 1
    changed = verdicts(repo)
    assert len(changed) == 2 and len({event["verdict"]["ref"] for event in changed}) == 2
