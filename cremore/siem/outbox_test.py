"""Finding/outbox atomicity and destination lease contracts on real SQLite."""
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import event, insert, select

from cremore.db import repository, sql, task_store
from cremore.db.postgres_scan_test import pg  # noqa: F401 -- isolated database fixture
from cremore.db.repository import InMemoryRepository
from cremore.db.schema import findings, siem_deliveries, siem_events
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.db.task_store import LeaseLost, TaskStore
from cremore.domain.models import Credential, Exposure, Finding
from cremore.siem import outbox
from cremore.siem.events import finding_created
from cremore.siem.outbox import SiemOutbox


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def store(request, monkeypatch):
    now = {"value": datetime(2026, 9, 24, tzinfo=UTC)}
    monkeypatch.setattr(outbox, "_clock", lambda conn=None: now["value"])
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    if request.param == "memory":
        repo = InMemoryRepository()
    elif request.param == "postgres":
        _engine, repo = request.getfixturevalue("pg")
    else:
        engine = make_engine("sqlite+pysqlite:///:memory:")
        create_all(engine)
        repo = SqlRepository(engine)
    yield repo, SiemOutbox(repo), now
    if request.param == "sqlite":
        repo.engine.dispose()


def observation(repo, label="one", *, create_finding=True):
    credential = repo.upsert_credential(Credential(fingerprint="synthetic-" + label,
        credential_type="GITHUB_TOKEN", provider="github", identifier="private identifier",
        identifier_hint="private hint"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="github",
        resource_name="private resource", location="private/path", redacted_line="private context",
        metadata={"arbitrary": "private metadata"}, line_number=7, severity="HIGH"))
    finding = repo.upsert_finding(credential.id, exposure.id, "HIGH") if create_finding else None
    return credential, exposure, finding


def test_alerts_cover_new_locations_and_each_reappearance_without_scan_duplicates(store):
    repo, queue, _now = store
    credential, exposure, _finding = observation(repo)
    for _ in range(3):
        repo.upsert_exposure(exposure.model_copy())
    new_location = repo.upsert_exposure(exposure.model_copy(update={"location": "private/another"}))
    repo.upsert_exposure(new_location.model_copy())
    repo.mark_exposure_removed(exposure.id)
    repo.upsert_exposure(exposure.model_copy())
    repo.upsert_exposure(exposure.model_copy())
    rows = queue.claim("alerts", limit=100)
    alerts = [r["event"] for r in rows if r["event"]["event_type"] in (
        "finding.created", "finding.location_added", "finding.reappeared")]
    assert sorted(e["event_type"] for e in alerts) == ["finding.created", "finding.location_added", "finding.reappeared"]
    assert all(e["finding"]["credential_id"] == str(credential.id) for e in alerts)
    assert next(e for e in alerts if e["event_type"] == "finding.location_added")["exposure"]["id"] == str(new_location.id)
    assert "private" not in json.dumps(alerts)
    assert len(repo.list_findings()) == 1


def test_alert_failure_rolls_back_reappearance_and_location(store, monkeypatch):
    repo, _queue, _now = store
    _credential, exposure, _finding = observation(repo)
    repo.mark_exposure_removed(exposure.id)
    def fail(*args, **kwargs):
        raise RuntimeError("OUTBOX_FIXTURE_ERROR")
    monkeypatch.setattr(sql if isinstance(repo, SqlRepository) else repository, "finding_exposure", fail)
    with pytest.raises(RuntimeError, match="OUTBOX_FIXTURE_ERROR"):
        repo.upsert_exposure(exposure.model_copy())
    assert repo.exposures_for_credential(exposure.credential_id)[0].status == "REMOVED"
    with pytest.raises(RuntimeError, match="OUTBOX_FIXTURE_ERROR"):
        repo.upsert_exposure(exposure.model_copy(update={"location": "private/new"}))
    assert repo.count_exposures_for_credential(exposure.credential_id) == 1


def test_new_findings_produce_one_immutable_initial_snapshot(store):
    repo, queue, _now = store
    credential, exposure, finding = observation(repo)
    repo.upsert_finding(credential.id, exposure.id, "LOW")
    repo.repair_finding_rollup(credential.id)
    repo.update_finding_status(finding.id, "FALSE_POSITIVE", "private analyst note")
    claimed = queue.claim("splunk", limit=10)
    created = [row for row in claimed if row["event"]["event_type"] == "finding.created"]
    assert len(created) == 1  # later changes are their own events, never edits of this one
    payload = created[0]["event"]
    assert payload["finding"] == {"id": str(finding.id), "credential_id": str(credential.id),
                                  "severity": "HIGH", "workflow_status": "OPEN"}
    assert payload["credential"] == {"provider": "github", "credential_type": "GITHUB_TOKEN", "status": "UNKNOWN"}
    assert payload["exposure"]["id"] == str(exposure.id)
    assert payload["exposure"]["line_number"] == 7
    assert uuid.UUID(payload["installation_id"])
    updates = [row["event"] for row in claimed if row["event"]["event_type"] == "finding.updated"]
    assert [(e["change"], e["finding"]["workflow_status"]) for e in updates][-1] == ("WORKFLOW", "FALSE_POSITIVE")
    assert all(e["installation_id"] == payload["installation_id"] for e in updates)
    for item in claimed:
        assert not any(word in json.dumps(item["event"]) for word in ("private", "synthetic-", "fingerprint", "redacted"))
    payload["finding"]["severity"] = "changed by caller"
    independent = [row for row in queue.claim("crowdstrike", limit=10) if row["event"]["event_type"] == "finding.created"]
    assert independent[0]["event"]["finding"]["severity"] == "HIGH"
    assert independent[0]["event"]["event_id"] == payload["event_id"]
    assert queue.claim("splunk") == []


def test_projection_has_fixed_keys_and_does_not_forward_unrecognized_codes():
    credential = Credential(id=uuid.uuid4(), fingerprint="private", provider="PRIVATE_SENTINEL",
                            credential_type="PRIVATE_SENTINEL", credential_status="PRIVATE_SENTINEL")
    exposure = Exposure(id=uuid.uuid4(), credential_id=credential.id, source_type="PRIVATE_SENTINEL",
                        resource_name="private", location="private", line_number=-1)
    finding = Finding(id=uuid.uuid4(), credential_id=credential.id, primary_exposure_id=exposure.id,
                      severity="PRIVATE_SENTINEL", workflow_status="PRIVATE_SENTINEL", created_at=datetime.now(UTC))
    payload = finding_created(finding, credential, exposure)
    assert set(payload) == {"schema_version", "event_id", "event_type", "occurred_at", "product", "finding", "credential", "exposure"}
    assert set(payload["exposure"]) == {"id", "source_type", "source_connection_id", "aws_account_id", "line_number"}
    assert "PRIVATE_SENTINEL" not in json.dumps(payload)
    assert payload["exposure"]["line_number"] is None
    assert payload == finding_created(finding, credential, exposure)
    credential.provider, credential.credential_status = "custom", "Active"
    custom = finding_created(finding, credential, exposure)
    assert custom["credential"] == {"provider": "custom", "credential_type": "CUSTOM", "status": "Active"}


def test_repair_creation_and_legacy_absent_exposure_preserve_contract(store):
    repo, queue, _now = store
    credential, _exposure, _finding = observation(repo, create_finding=False)
    repaired = repo.repair_finding_rollup(credential.id)
    repo.repair_finding_rollup(credential.id)
    first, = queue.claim("repair")
    assert first["event"]["finding"]["id"] == str(repaired.id)
    other = repo.upsert_credential(Credential(fingerprint="legacy", credential_type="TEST"))
    missing = uuid.uuid4()
    finding = repo.upsert_finding(other.id, missing, "LOW")
    second, = queue.claim("repair")
    assert second["event"]["finding"]["id"] == str(finding.id)
    assert second["event"]["exposure"] == {"id": str(missing), "source_type": "UNKNOWN",
        "source_connection_id": None, "aws_account_id": None, "line_number": None}


@pytest.mark.parametrize("repair", [False, True])
def test_projection_failure_rolls_back_finding_creation(store, monkeypatch, repair):
    repo, queue, _now = store
    credential, exposure, _finding = observation(repo, create_finding=False)
    def fail(*args):
        raise RuntimeError("synthetic projection failure")
    monkeypatch.setattr(sql if isinstance(repo, SqlRepository) else repository, "finding_created", fail)
    with pytest.raises(RuntimeError, match="synthetic"):
        if repair:
            repo.repair_finding_rollup(credential.id)
        else:
            repo.upsert_finding(credential.id, exposure.id, "HIGH")
    assert repo.get_finding_for_credential(credential.id) is None
    assert queue.claim("sink") == []


def test_task_transaction_rolls_back_event_and_all_finding_records(store):
    repo, queue, now = store
    tasks = TaskStore(repo)
    tasks.enqueue(uuid.uuid4(), "synthetic", {"mode": "BASELINE"})
    task = tasks.claim(lease_seconds=10)
    with pytest.raises(LeaseLost), tasks.fenced(task["id"], task["token"]) as bound:
        credential, _exposure, finding = observation(bound)
        now["value"] += timedelta(seconds=11)
    assert repo.get_credential(credential.id) is None
    assert repo.get_finding(finding.id) is None
    assert queue.claim("sink") == []


def test_retry_delay_destination_isolation_and_stale_token_fencing(store):
    repo, queue, now = store
    observation(repo)
    first, = queue.claim("one", lease_seconds=10)
    other, = queue.claim("two", lease_seconds=10)
    event_id = first["event"]["event_id"]
    assert queue.acknowledge("two", event_id, first["token"]) is False
    assert queue.retry("one", event_id, first["token"], error_code="private raw error", delay_seconds=5)
    assert queue.claim("one") == []
    assert queue.acknowledge("two", event_id, other["token"])
    now["value"] += timedelta(seconds=5)
    second, = queue.claim("one", lease_seconds=10)
    assert second["attempts"] == 2
    assert second["event"] == first["event"]
    assert queue.acknowledge("one", event_id, first["token"]) is False
    now["value"] += timedelta(seconds=10)
    assert queue.acknowledge("one", event_id, second["token"]) is False
    third, = queue.claim("one")
    assert third["attempts"] == 3 and third["token"] != second["token"]
    assert queue.retry("one", event_id, second["token"]) is False
    assert queue.acknowledge("one", event_id, third["token"])
    assert queue.claim("one") == queue.claim("two") == []
    new_destination, = queue.claim("three")
    assert new_destination["event"] == first["event"]


def test_skip_before_counts_only_older_events_delivered_and_keeps_what_a_destination_holds(store):
    repo, queue, _now = store
    observation(repo, "old")
    leased, = queue.claim("busy", limit=1)
    time.sleep(0.03)  # event times come from the wall clock, which ticks in milliseconds on some hosts
    cut = datetime.now(UTC)
    time.sleep(0.03)
    _credential, _exposure, new = observation(repo, "new")
    queue.skip_before("fresh", cut)
    queue.skip_before("fresh", cut)  # again: nothing changes
    queue.skip_before("busy", cut)
    assert [row["event"]["finding"]["id"] for row in queue.claim("fresh", limit=100)] == [str(new.id)]
    old_id = leased["event"]["event_id"]
    skipped, = [row for row in queue.deliveries(old_id) if row["destination"] == "fresh"]
    assert skipped["attempts"] == 0 and skipped["delivered_at"] and skipped["error_code"] is None
    # A delivery the destination already holds keeps its lease, and its sender can still acknowledge it.
    assert queue.acknowledge("busy", old_id, leased["token"])
    assert len(queue.claim("other", limit=100)) == 2  # other destinations are untouched
    for destination, before, code in (("bad\nname", cut, "SIEM_INVALID_DESTINATION"), ("x", "2026-01-01", "SIEM_INVALID_TIME")):
        with pytest.raises(ValueError, match=code):
            queue.skip_before(destination, before)


def test_bounded_reads_bulk_skips_by_type_and_an_uncounted_put_back(store):
    repo, queue, now = store
    _c, _e, first = observation(repo, "one")
    time.sleep(0.03)
    cut = datetime.now(UTC)
    time.sleep(0.03)
    _c, _e, second = observation(repo, "two")
    repo.update_finding_status(second.id, "ACKNOWLEDGED")  # a finding.updated (WORKFLOW) after the cut
    # From the cut on, everything but finding.created counts as received and finding.created is owed through its row;
    # nothing earlier is read. The newest event time read comes back.
    newest = queue.skip("alerts", since=cut, keep=[("finding.created", None)], queue_kept=True)
    assert newest > cut and queue.skip("alerts", since=newest + timedelta(seconds=1)) is None
    assert queue.oldest_unclaimed("alerts") < cut  # the first finding has no row: a sweep finds it
    row = queue.destination_status("alerts", since=cut)
    assert (row["pending"], row["held"], row["destination"]) == (1, 0, "alerts") and row["oldest_pending_at"]
    claimed, = queue.claim_owed("alerts", limit=100)
    assert claimed["event"]["finding"]["id"] == str(second.id) and claimed["attempts"] == 1
    # Put back without counting the attempt: the next claim is the first attempt again.
    assert queue.defer("alerts", claimed["event"]["event_id"], claimed["token"], delay_seconds=5)
    assert queue.claim_owed("alerts") == []
    now["value"] += timedelta(seconds=5)
    again, = queue.claim_owed("alerts")
    assert again["attempts"] == 1 and again["event"] == claimed["event"]
    assert queue.acknowledge("alerts", again["event"]["event_id"], again["token"]) and queue.claim_owed("alerts") == []
    # Without queue_kept a kept (type, change) pair keeps only that change of that type, and no row.
    queue.skip("rollups", keep=[("finding.updated", "ROLLUP")])
    assert queue.claim("rollups") == []
    assert first.id != second.id


def test_cremore_destinations_are_left_out_of_siem_status_and_retention_still_waits_for_them(store):
    repo, queue, now = store
    observation(repo, "kept")
    queue.record_status("cremore.slack-alerts", "IDLE")
    queue.record_status("splunk", "IDLE")
    assert [row["destination"] for row in queue.status()] == ["splunk"]
    assert [row["destination"] for row in queue.status(include_internal=True)] == ["cremore.slack-alerts", "splunk"]
    since = now["value"] - timedelta(days=1)
    assert queue.seen_since(since) == ["splunk"]
    assert queue.seen_since(since, include_internal=True) == ["cremore.slack-alerts", "splunk"]
    prune = {"before": datetime.now(UTC) + timedelta(days=1), "short_lived_before": since, "short_lived_types": (),
             "active_since": since}
    queue.skip("splunk")
    assert queue.prune(**prune) == 0  # the alert channel reports and has not received it
    queue.skip("cremore.slack-alerts")
    assert queue.prune(**prune) == 1


def test_a_bulk_skip_inserts_in_one_order_so_overlapping_writers_cannot_deadlock():
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    repo = SqlRepository(engine)
    observation(repo)
    statements = []
    event.listen(engine, "before_cursor_execute", lambda conn, cursor, statement, *rest: statements.append(statement))
    SiemOutbox(repo).skip("alerts", keep=[("finding.created", None)], queue_kept=True)
    insert, = [statement for statement in statements if statement.startswith("INSERT INTO siem_deliveries")]
    assert "ORDER BY siem_events.occurred_at, siem_events.event_id" in insert
    engine.dispose()


@pytest.mark.parametrize("kwargs", [{"destination": "https://private.example/token"},
    {"destination": "bad\nname"}, {"destination": "x", "limit": 0}, {"destination": "x", "limit": 1001},
    {"destination": "x", "limit": True}, {"destination": "x", "lease_seconds": 0},
    {"destination": "x", "lease_seconds": 86401}])
@pytest.mark.parametrize("method", ["claim", "claim_owed"])
def test_claim_validation(store, kwargs, method):
    with pytest.raises(ValueError, match="SIEM_INVALID"):
        getattr(store[1], method)(**kwargs)


def test_sql_insert_failure_is_atomic_and_retry_error_is_bounded(tmp_path):
    engine = make_engine("sqlite+pysqlite:///" + str(tmp_path / "atomic.db"))
    create_all(engine)
    repo = SqlRepository(engine)
    credential, exposure, _finding = observation(repo, create_finding=False)
    def fail_insert(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO siem_events"):
            raise RuntimeError("synthetic disk failure")
    event.listen(engine, "before_cursor_execute", fail_insert)
    with pytest.raises(RuntimeError, match="synthetic disk"):
        repo.upsert_finding(credential.id, exposure.id, "HIGH")
    event.remove(engine, "before_cursor_execute", fail_insert)
    assert repo.get_finding_for_credential(credential.id) is None
    repo.upsert_finding(credential.id, exposure.id, "HIGH")
    queue = SiemOutbox(repo)
    claimed, = queue.claim("sink")
    assert queue.retry("sink", claimed["event"]["event_id"], claimed["token"],
                       error_code="private response https://private.example", delay_seconds=0)
    with engine.connect() as conn:
        assert conn.execute(select(siem_deliveries.c.error_code)).scalar_one() == "DELIVERY_FAILED"
    engine.dispose()
    reopened = make_engine("sqlite+pysqlite:///" + str(tmp_path / "atomic.db"))
    try:
        retry, = SiemOutbox(SqlRepository(reopened)).claim("sink")
        assert retry["event"] == claimed["event"] and retry["attempts"] == 2
    finally:
        reopened.dispose()


def test_additive_upgrade_preserves_old_findings_without_backfill(tmp_path):
    engine = make_engine("sqlite+pysqlite:///" + str(tmp_path / "upgrade.db"))
    create_all(engine)
    repo = SqlRepository(engine)
    credential, exposure, _finding = observation(repo, create_finding=False)
    stamp = datetime.now(UTC)
    legacy_id = uuid.uuid4()
    with engine.begin() as conn:
        conn.execute(insert(findings).values(id=legacy_id, credential_id=credential.id,
            primary_exposure_id=exposure.id, severity="HIGH", workflow_status="OPEN", created_at=stamp, updated_at=stamp))
    # Empty additive tables may be absent in an installation predating this feature.
    siem_deliveries.drop(engine)
    siem_events.drop(engine)
    create_all(engine)
    repo.upsert_finding(credential.id, exposure.id, "LOW")
    assert repo.get_finding(legacy_id).severity == "LOW"
    assert SiemOutbox(repo).claim("sink") == []
    observation(repo, "new")
    assert len(SiemOutbox(repo).claim("sink")) == 1
    engine.dispose()


def test_sqlite_parallel_claims_are_bounded_and_unique(tmp_path):
    engine = make_engine("sqlite+pysqlite:///" + str(tmp_path / "concurrent.db"))
    create_all(engine)
    repo = SqlRepository(engine)
    for number in range(8):
        observation(repo, str(number))
    statements = []
    def record(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("SELECT"):
            statements.append(statement)
    event.listen(engine, "before_cursor_execute", record)
    with ThreadPoolExecutor(max_workers=4) as pool:
        batches = list(pool.map(lambda _: SiemOutbox(repo).claim("same", limit=2), range(4)))
    event.remove(engine, "before_cursor_execute", record)
    ids = [item["event"]["event_id"] for batch in batches for item in batch]
    assert len(ids) == len(set(ids)) == 8
    assert all(len(batch) <= 2 for batch in batches)
    assert len(statements) == 4 and all("LIMIT" in statement and "FROM siem_events" in statement for statement in statements)
    engine.dispose()
