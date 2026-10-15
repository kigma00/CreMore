"""Opt-in PostgreSQL proofs. Only a disposable localhost cremore_test DB is allowed.

Set CREMORE_TEST_POSTGRES_URL for PostgreSQL 16+; each test owns and drops one random
schema. No provider credentials, external requests, or user database are used.
"""
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import create_engine, delete, func, insert, select, text, update
from sqlalchemy.engine import make_url

from cremore.db.migrations import migrate_offline
from cremore.db.scan_store import ScanStore
from cremore.db.schema import (
    credentials,
    exposures,
    findings,
    fp_samples,
    migration_archive,
    schema_migrations,
)
from cremore.db.sql import SqlRepository, create_all
from cremore.db.task_store import LeaseLost, TaskStore
from cremore.domain.models import Credential, Exposure, ScanJob, ScopePlan


@pytest.fixture
def pg():
    value = os.environ.get("CREMORE_TEST_POSTGRES_URL")
    if not value:
        pytest.skip("Set CREMORE_TEST_POSTGRES_URL for isolated PostgreSQL integration tests")
    url = make_url(value)
    if url.host not in {"127.0.0.1", "localhost"} or url.database != "cremore_test":
        pytest.fail("Refusing a database other than disposable localhost cremore_test")
    admin = create_engine(url)
    schema = "cremore_test_" + uuid.uuid4().hex
    with admin.begin() as conn:
        version = int(conn.execute(text("SHOW server_version_num")).scalar_one())
        assert version >= 160000
        conn.execute(text(f"CREATE SCHEMA {schema}"))
    engine = create_engine(url, connect_args={"options": f"-c search_path={schema}"}, pool_size=12, max_overflow=12)
    try:
        create_all(engine)
        yield engine, SqlRepository(engine)
    finally:
        engine.dispose()
        # Only the generated schema created above, inside the guarded test DB.
        assert schema.startswith("cremore_test_") and len(schema) == 45 and schema[13:].isalnum()
        with admin.begin() as conn:
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
        admin.dispose()


def test_postgres_concurrent_upserts_are_atomic_and_null_safe(pg):
    engine, repo = pg
    barrier = Barrier(12)
    def write(_):
        barrier.wait()
        credential = repo.upsert_credential(Credential(fingerprint="synthetic-shared", credential_type="TOKEN"))
        exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="github",
            resource_name="synthetic/repo", location="config", severity="HIGH"))
        finding = repo.upsert_finding(credential.id, exposure.id, "HIGH")
        return credential.id, exposure.id, finding.id
    with ThreadPoolExecutor(max_workers=12) as pool:
        identities = list(pool.map(write, range(12)))
    assert len(set(identities)) == 1
    with engine.connect() as conn:
        for table in (credentials, exposures, findings):
            assert conn.execute(select(func.count()).select_from(table)).scalar_one() == 1


def test_postgres_concurrent_approval_revisions_are_distinct(pg):
    _engine, repo = pg
    barrier = Barrier(12)

    def approve(writer):
        barrier.wait(timeout=15)
        return repo.put_revisioned_setting("approval", {"identity": str(writer)}, str(writer))

    with ThreadPoolExecutor(max_workers=12) as pool:
        records = list(pool.map(approve, range(12)))
    assert sorted(record["value"]["revision"] for record in records) == list(range(1, 13))
    latest = max(records, key=lambda record: record["value"]["revision"])
    assert repo.get_setting("approval") == latest
    assert latest["value"]["identity"] == latest["updated_by"]


def test_postgres_skip_locked_and_hierarchical_root_claim_races(pg):
    _engine, repo = pg
    tasks, run = TaskStore(repo), uuid.uuid4()
    for i in range(24):
        tasks.enqueue(run, f"scope-{i}", {"mode": "BASELINE", "lock_key": f"bucket-{i % 4}", "connection_lock": "same"})
    tasks.enqueue(run, "legacy", {"mode": "PLAN", "connection_lock": "same", "exclusive_connection": True}, priority=10)
    tasks.enqueue(run, "independent", {"mode": "BASELINE", "connection_lock": "other"}, priority=5)
    barrier = Barrier(12)
    def claim(_):
        barrier.wait()
        return TaskStore(repo).claim()
    with ThreadPoolExecutor(max_workers=12) as pool:
        claimed = [t for t in pool.map(claim, range(12)) if t]
    # SKIP LOCKED may temporarily hide another root in the first contender's
    # bounded candidate page. A subsequent tick must make that work available.
    followup = tasks.claim()
    if followup:
        claimed.append(followup)
    assert len({t["lock_key"] for t in claimed}) == len(claimed)
    if any(t["exclusive_connection"] for t in claimed):
        assert sum(t["connection_lock"] == "same" for t in claimed) == 1
    assert any(t["root_id"] == "independent" for t in claimed)


def test_postgres_commit_fence_uses_live_database_clock_and_rolls_back_cache(pg):
    engine, repo = pg
    tasks, run = TaskStore(repo), uuid.uuid4()
    tasks.enqueue(run, "bucket", {"mode": "BASELINE"})
    task = tasks.claim(lease_seconds=0.2)
    with pytest.raises(LeaseLost), tasks.fenced(task["id"], task["token"]) as bound:
        bound.upsert_credential(Credential(fingerprint="rolled-back", credential_type="TOKEN"))
        ScanStore(bound).save_root("bucket", uuid.uuid4(), {"watermark": "uncommitted"})
        TaskStore(bound).checkpoint(task["id"], task["token"], {"cursor": "uncommitted"})
        with bound.engine.connect() as conn:
            conn.execute(text("SELECT pg_sleep(0.25)"))
    with engine.connect() as conn:
        assert conn.execute(select(func.count()).select_from(credentials)).scalar_one() == 0
    assert ScanStore(repo).root("bucket") == {}
    assert tasks.list_for_run(run)[0]["checkpoint"] == {}
    reclaimed = tasks.claim()
    assert reclaimed["id"] == task["id"] and reclaimed["token"] != task["token"]
    with pytest.raises(LeaseLost):
        tasks.finish(task["id"], task["token"], {})


def test_postgres_offline_migration_preserves_nullable_identity_references(pg):
    engine, repo = pg
    credential = repo.upsert_credential(Credential(fingerprint="legacy", credential_type="TOKEN"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="s3",
        resource_name="synthetic-bucket", location="config", severity="HIGH"))
    finding = repo.upsert_finding(credential.id, exposure.id, "HIGH")
    duplicate, sample = uuid.uuid4(), uuid.uuid4()
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX exposures_identity_key_unique"))
        conn.execute(delete(schema_migrations).where(schema_migrations.c.version == 2))
        conn.execute(update(exposures).values(identity_key=None, resource_key=None, container_key=None))
        row = dict(conn.execute(select(exposures)).mappings().one())
        row.update(id=duplicate, metadata={"historical_evidence": "synthetic retained"})
        conn.execute(insert(exposures).values(**row))
        conn.execute(update(findings).where(findings.c.id == finding.id).values(primary_exposure_id=duplicate))
        conn.execute(insert(fp_samples).values(id=sample, scope_kind="aws", scope_id=uuid.uuid4(),
            source_type="s3", detector_name="synthetic", credential_type="TOKEN", finding_id=finding.id,
            exposure_id=duplicate, actor="analyst", features=[]))
    assert migrate_offline(engine, offline=True, backup_confirmed=True)["exposures_merged"] == 1
    with engine.connect() as conn:
        survivor = conn.execute(select(exposures)).mappings().one()
        assert survivor["identity_key"] and survivor["resource_key"] and survivor["container_key"]

        assert conn.execute(select(findings.c.primary_exposure_id)).scalar_one() == survivor["id"]
        assert conn.execute(select(fp_samples.c.exposure_id)).scalar_one() == survivor["id"]
        archived = conn.execute(select(migration_archive.c.record).where(migration_archive.c.table_name == "exposures")).scalars().all()
        assert len(archived) == 2 and any(r["metadata"].get("historical_evidence") for r in archived)


def test_postgres_concurrent_plan_consumption_and_trigger_receipt_admit_one_budget(pg):
    _engine, repo = pg
    connection_id = uuid.uuid4()
    plan = repo.create_plan(ScopePlan(kind="source", connection_id=connection_id,
        profile_id=uuid.uuid4(), profile_version=1, executable=True))
    job = ScanJob(kind="scope", connection_id=connection_id)
    barrier = Barrier(8)
    def consume(_):
        barrier.wait()
        return repo.consume_scope_plan(plan.id, 1, job)
    with ThreadPoolExecutor(max_workers=8) as pool:
        admitted = list(pool.map(consume, range(8)))
    assert sum(created for _, created in admitted) == 1
    assert len({j.id for j, _ in admitted}) == 1
    # Receipt admission is independent of already queued work.
    barrier = Barrier(8)
    def trigger(_):
        proposal = plan.model_copy(update={"id": uuid.uuid4(), "job_id": None})
        barrier.wait()
        return repo.enqueue_triggered_scope(proposal, job, "a" * 64)
    with ThreadPoolExecutor(max_workers=8) as pool:
        admitted = list(pool.map(trigger, range(8)))
    assert sum(created for _, created in admitted) == 1
    assert len({j.id for j, _ in admitted}) == 1 and len(repo.list_jobs()) == 2


def test_postgres_two_replicas_reopen_a_slot_whose_merged_run_was_cancelled_once(pg, monkeypatch):
    """The 17:00 slot was merged into an Admin's full read, which was then cancelled. Two replicas polling at once
    queue the slot's own full scan once; a replica still holding the stale receipt swaps nothing out after that."""
    from datetime import timedelta

    from cremore.db.schema import trigger_receipts
    from cremore.scanning import triggers
    from cremore.scanning.triggers_test import NOW, admin_run, full_scan_slot, setup

    monkeypatch.setattr(triggers, "full_scan_offset", lambda profile, interval: 0)  # the 17:00 slot is due at 17:00

    engine, repo = pg
    repo, _conn, profile, _item, settings = setup(repo=repo)
    profile = repo.update_scope_profile(profile.id, schedule_minutes=0)
    start = NOW.replace(hour=17, minute=0, second=0, microsecond=0)
    manual = admin_run(repo, settings, profile, start + timedelta(seconds=30))
    assert triggers.poll_schedules(repo, settings, now=start + timedelta(seconds=30))["coalesced"] == 1
    repo.request_job_cancel(manual.id)
    key = full_scan_slot(repo, settings, profile, start)
    assert repo.slot_receipt_state(key, start) == (False, manual.id)
    replicas, barrier = [repo, SqlRepository(engine)], Barrier(8)

    def poll(n):
        barrier.wait(timeout=15)
        return triggers.poll_schedules(replicas[n % 2], settings, now=start + timedelta(minutes=2))["enqueued"]

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(poll, range(8))) == 1
    [own] = [job for job in repo.list_jobs() if job.id != manual.id]
    assert own.payload["slot_receipt"] == key and repo.slot_receipt_state(key, start) == (True, None)
    # A replica that read the receipt before the swap: its compare-and-swap names the cancelled run and finds the new
    # one, so it neither queues a second run nor points the slot elsewhere.
    _profile, plan, _target, _base, _source = triggers.prepare_trigger_plan(
        repo, settings, profile.id, "SCHEDULE", now=start + timedelta(minutes=2))
    late, created = replicas[1].enqueue_triggered_scope(
        plan, ScanJob(kind="scope", connection_id=profile.connection_id, payload={"requested_by": "schedule"}),
        key, manual.id)
    assert not created and late.id == own.id
    assert replicas[1].coalesce_scheduled_scope(key, profile, plan.auth_revision, ("RECONCILE",), start, manual.id).id == own.id
    with engine.connect() as conn:
        assert conn.execute(select(trigger_receipts.c.job_id).where(trigger_receipts.c.receipt_key == key)).scalar_one() == own.id
    assert len(repo.list_jobs()) == 2


def test_postgres_a_slot_run_has_ended_only_once_the_run_answering_it_is_terminal(pg, monkeypatch):
    """slot_run_ended reads the receipt and its run in one query: no receipt, a run queued, running or cancelling, or a
    merged run that ended cancelled (the slot reopens) has not ended; the slot's own run that failed has."""
    from datetime import timedelta

    from cremore.scanning import triggers
    from cremore.scanning.triggers_test import DAY, admin_run, begun, full_scan_slot, setup

    monkeypatch.setattr(triggers, "full_scan_offset", lambda profile, interval: 0)  # the 17:00 slot is due at 17:00
    _engine, repo = pg
    repo, _conn, profile, _item, settings = setup(repo=repo)
    profile = repo.update_scope_profile(profile.id, schedule_minutes=0, approved_at=DAY - timedelta(days=1))
    start = DAY + timedelta(hours=17)
    key = full_scan_slot(repo, settings, profile, start)
    assert not repo.slot_run_ended(key, start)
    manual = admin_run(repo, settings, profile, start + timedelta(seconds=30))
    assert triggers.poll_schedules(repo, settings, now=start + timedelta(seconds=30))["coalesced"] == 1
    assert not repo.slot_run_ended(key, start)
    begun(repo, manual, start + timedelta(seconds=40))
    assert not repo.slot_run_ended(key, start)
    repo.request_job_cancel(manual.id)
    assert repo.get_job(manual.id).status == "CANCELLING" and not repo.slot_run_ended(key, start)
    repo.finish_cancelled_job(manual.id)
    assert repo.slot_receipt_state(key, start) == (False, manual.id) and not repo.slot_run_ended(key, start)
    assert triggers.poll_schedules(repo, settings, now=start + timedelta(minutes=2))["enqueued"] == 1
    [own] = [job for job in repo.list_jobs() if job.id != manual.id]
    assert not repo.slot_run_ended(key, start)
    repo.fail_job(own.id, "synthetic failure")
    assert repo.slot_receipt_state(key, start) == (True, None) and repo.slot_run_ended(key, start)


def test_postgres_the_migration_records_the_origin_by_the_database_clock_once(pg):
    """create_all (the offline upgrade and a fresh database's startup alike) records the origin with PostgreSQL's
    now(), once: a restart keeps it, a deleted row is not recorded again, and an existing record is kept."""
    from datetime import UTC, datetime

    from cremore.db.migrations import SCHEDULE_ORIGIN_VERSION
    from cremore.db.schema import installation_settings
    from cremore.scanning import trigger_settings

    engine, repo = pg
    with engine.connect() as conn:
        database_now = conn.execute(select(func.now())).scalar_one()
    origin = trigger_settings.schedule_origin(repo, datetime.now(UTC))
    assert origin is not None and origin <= database_now and (database_now - origin).total_seconds() < 600
    assert repo.get_setting(trigger_settings.ORIGIN_KEY)["updated_by"] == "migration"
    create_all(engine)
    assert trigger_settings.schedule_origin(repo, datetime.now(UTC)) == origin
    with engine.begin() as conn:
        conn.execute(delete(installation_settings).where(installation_settings.c.key == trigger_settings.ORIGIN_KEY))
    create_all(engine)
    assert repo.get_setting(trigger_settings.ORIGIN_KEY) is None
    # An earlier build's poll-recorded origin is kept when the migration first runs.
    earlier = datetime(2026, 10, 11, 10, 0, tzinfo=UTC)
    repo.put_setting(trigger_settings.ORIGIN_KEY, {"at": earlier.isoformat()}, "schedule")
    with engine.begin() as conn:
        conn.execute(delete(schema_migrations).where(schema_migrations.c.version == SCHEDULE_ORIGIN_VERSION))
    create_all(engine)
    assert trigger_settings.schedule_origin(repo, datetime.now(UTC)) == earlier


def test_postgres_replicas_recording_the_upgrade_digest_at_once_record_it_once(pg):
    """Every worker's first sweep pass records the digest in force after the upgrade under the record's row lock: the
    origin is kept, one digest is written and no change is latched; a later different digest latches it once."""
    from cremore.scanning import trigger_settings

    engine, repo = pg
    before = repo.get_setting(trigger_settings.ORIGIN_KEY)["value"]

    def record(digest):
        def write(replica):
            barrier.wait(timeout=15)
            trigger_settings.record_upgrade_digest(SqlRepository(engine), digest)
        return write

    barrier = Barrier(8)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(record("after-the-upgrade"), range(8)))
    assert repo.get_setting(trigger_settings.ORIGIN_KEY)["value"] == {**before, "detection_digest": "after-the-upgrade"}
    barrier = Barrier(8)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(record("an-admin-changed-rules"), range(8)))
    assert repo.get_setting(trigger_settings.ORIGIN_KEY)["value"] == {
        **before, "detection_digest": "after-the-upgrade", "rules_changed": True}
    assert not trigger_settings.rules_unchanged(repo, "after-the-upgrade")


def test_postgres_active_scope_runs_filter_the_json_payload_newest_first(pg):
    """The lookup behind the API's start-run check (cremore.api.dashboard _active_scope_run), on PostgreSQL's JSON
    operators: only this connection's and profile version's queued or running whole-scope runs, newest first. An
    absent trigger is BASELINE; a JSON-null one passes too and is refused by the API's own check (catalog_run_test)."""
    from datetime import UTC, datetime, timedelta

    from cremore.db.schema import scan_jobs

    engine, repo = pg
    connection, profile, base = uuid.uuid4(), str(uuid.uuid4()), datetime(2026, 10, 11, 9, 0, tzinfo=UTC)

    def run(minute, *, connection_id=connection, status="QUEUED", **payload):
        job = repo.enqueue_job(ScanJob(kind="scope", connection_id=connection_id,
                                       payload={"profile_id": profile, "profile_version": 3, **payload}))
        with engine.begin() as conn:
            conn.execute(update(scan_jobs).where(scan_jobs.c.id == job.id).values(
                created_at=base + timedelta(minutes=minute), status=status))
        return job.id

    absent, null = run(1), run(2, trigger=None)
    scheduled, running = run(3, trigger="SCHEDULE", mode="RECONCILE"), run(4, trigger="BASELINE", status="RUNNING")
    for minute, other in enumerate(({"trigger": "EVENT"}, {"trigger": "RESUME"}, {"trigger": "RESCAN"},
                                    {"trigger": "POLICY_SWEEP"}, {"profile_version": 4},
                                    {"profile_id": str(uuid.uuid4())}, {"status": "SUCCEEDED"},
                                    {"connection_id": uuid.uuid4()}), start=5):
        run(minute, **other)
    assert [job.id for job in repo.active_scope_runs(connection, profile, 3)] == [running, scheduled, null, absent]


def test_postgres_rescore_bound_repository_rolls_back_and_serializes_cursor(pg, monkeypatch):
    from dataclasses import asdict

    from cremore.risk.model import ExposureFacts, Facts, Verification
    from cremore.scanning.orchestrator import Orchestrator
    from cremore.scanning.rescore import RescoreService

    _engine, repo = pg
    credential = repo.upsert_credential(Credential(fingerprint="rescore-synthetic", credential_type="GITHUB_TOKEN", provider="github"))
    evidence = {"catalog_id": "github-pat", "detector_name": "GitHubPAT", "detection_confidence": "medium",
        "exposure": "internal", "risk_facts": asdict(Facts(provider="github", credential_type="GITHUB_TOKEN",
            verification=Verification(), exposure=ExposureFacts(level="internal")))}
    for i in range(5):
        exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="github",
            resource_name="synthetic/repo", location=f"config-{i}", severity="CRITICAL", metadata=evidence))
    finding = repo.upsert_finding(credential.id, exposure.id, "CRITICAL")
    original = SqlRepository.record_finding_event

    def fail(self, event):
        if event.event_type == "RISK_REEVALUATED":
            raise RuntimeError("synthetic audit failure")
        return original(self, event)

    monkeypatch.setattr(SqlRepository, "record_finding_event", fail)
    with pytest.raises(RuntimeError, match="synthetic audit"):
        RescoreService(Orchestrator(repo)).run_batch(2)
    assert all(e.severity == "CRITICAL" and "rescore" not in e.metadata for e in repo.exposures_for_credential(credential.id))
    assert repo.get_finding(finding.id).all_locations_removed is None
    assert repo.list_finding_events(finding.id) == []
    monkeypatch.setattr(SqlRepository, "record_finding_event", original)
    barrier = Barrier(4)

    def run(_):
        barrier.wait()
        return RescoreService(Orchestrator(repo)).run_batch(2)

    with ThreadPoolExecutor(max_workers=4) as pool:
        batches = list(pool.map(run, range(4)))
    assert sum(b["processed"] for b in batches) == 5
    assert all(e.severity == "LOW" and not e.metadata["rescore"]["needs_rescan"] for e in repo.exposures_for_credential(credential.id))
    assert RescoreService(Orchestrator(repo)).run_batch()["done"]
    assert repo.get_finding(finding.id).severity == "LOW"


def test_postgres_notion_container_lookup_normalizes_identity_not_titles(pg):
    _engine, repo = pg
    credential = repo.upsert_credential(Credential(fingerprint="root-synthetic", credential_type="TOKEN"))
    connection, page_id = uuid.uuid4(), uuid.uuid4()
    for title, stored_id in (("old title", str(page_id).upper()), ("new title", page_id.hex)):
        repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="notion",
            source_connection_id=connection, resource_name=title, location=title, metadata={"page_id": stored_id}))
    assert len(repo.exposures_for_root(connection, "notion", "latest title", page_id=str(page_id))) == 2


def test_postgres_connection_exclusion_is_applied_before_candidate_limit(pg):
    _engine, repo = pg
    tasks, run = TaskStore(repo), uuid.uuid4()
    tasks.enqueue(run, "exclusive", {"mode": "PLAN", "connection_lock": "busy", "exclusive_connection": True}, priority=100)
    assert tasks.claim()["root_id"] == "exclusive"
    for i in range(20):
        tasks.enqueue(run, f"blocked-{i}", {"mode": "BASELINE", "connection_lock": "busy"}, priority=50)
    tasks.enqueue(run, "available", {"mode": "BASELINE", "connection_lock": "other"})
    assert tasks.claim()["root_id"] == "available"


def test_postgres_parent_claim_race_serializes_connections_and_seeds_atomically(pg):
    _engine, repo = pg
    connections = [uuid.uuid4() for _ in range(4)]
    for connection in connections:
        for _ in range(4):
            repo.enqueue_job(ScanJob(kind="scope", connection_id=connection))
    barrier = Barrier(12)

    def claim(_):
        barrier.wait(timeout=15)
        return TaskStore(repo).seed_next_job()

    with ThreadPoolExecutor(max_workers=12) as pool:
        claimed = [job for job in pool.map(claim, range(12)) if job]
    assert len(claimed) == 4 and {job.connection_id for job in claimed} == set(connections)
    assert len([job for job in repo.list_jobs() if job.status == "QUEUED"]) == 12
    for job in claimed:
        [task] = TaskStore(repo).list_for_run(job.id)
        assert task["kind"] == "PLAN" and task["status"] == "QUEUED"
    repo.request_job_cancel(claimed[0].id)
    assert TaskStore(repo).seed_next_job() is None
    repo.finish_cancelled_job(claimed[0].id)
    assert TaskStore(repo).seed_next_job().connection_id == claimed[0].connection_id


def test_postgres_legacy_unscoped_run_blocks_newer_content_without_starving(pg):
    _engine, repo = pg
    tasks = TaskStore(repo)
    active = repo.enqueue_job(ScanJob(kind="scope", connection_id=uuid.uuid4()))
    assert tasks.seed_next_job().id == active.id
    legacy = repo.enqueue_job(ScanJob(kind="inline"))
    later = repo.enqueue_job(ScanJob(kind="scope", connection_id=uuid.uuid4()))
    check = repo.enqueue_job(ScanJob(kind="catalog-refresh"))
    assert tasks.seed_next_job().id == check.id
    assert tasks.seed_next_job() is None
    repo.complete_job(active.id, 0, 0)
    assert tasks.seed_next_job().id == legacy.id
    assert tasks.seed_next_job() is None
    repo.complete_job(legacy.id, 0, 0)
    assert tasks.seed_next_job().id == later.id


def test_postgres_claims_share_the_runners_across_runs_before_age(pg):
    _engine, repo = pg
    tasks, older, newer = TaskStore(repo), uuid.uuid4(), uuid.uuid4()
    for run, prefix, count in ((older, "old", 3), (newer, "new", 2)):
        for i in range(count):
            tasks.enqueue(run, f"{prefix}-{i}", {"mode": "BASELINE", "lock_key": f"{prefix}-{i}"})
    # The grouped running count is joined, and FOR UPDATE OF locks only the candidate scan_tasks rows.
    assert [tasks.claim()["root_id"] for _ in range(3)] == ["old-0", "new-0", "old-1"]
    tasks.enqueue(older, "urgent", {"mode": "BASELINE", "lock_key": "urgent"}, priority=10)
    assert [tasks.claim()["root_id"] for _ in range(3)] == ["urgent", "new-1", "old-2"]


def _postgres_connection_index(conn):
    """The index of migration version 11: one running content job per connection, whatever its lane."""
    from cremore.domain.models import CONTENT_SCAN_KINDS

    kinds = ", ".join(f"'{kind}'" for kind in CONTENT_SCAN_KINDS)
    conn.execute(text("DROP INDEX scan_jobs_one_running_connection"))
    conn.execute(text("CREATE UNIQUE INDEX scan_jobs_one_running_connection ON scan_jobs "
                      "((coalesce(CAST(connection_id AS VARCHAR), 'unscoped'))) "
                      f"WHERE status IN ('RUNNING', 'CANCELLING') AND kind IN ({kinds})"))


def test_postgres_lane_migration_keeps_a_running_sweep_and_admits_one_event_beside_it(pg):
    from sqlalchemy.exc import IntegrityError

    from cremore.db.migrations import SCAN_EVENT_LANE_VERSION
    from cremore.db.schema import scan_jobs

    engine, repo = pg
    target = uuid.uuid4()
    with engine.begin() as conn:
        _postgres_connection_index(conn)
        conn.execute(delete(schema_migrations).where(schema_migrations.c.version == SCAN_EVENT_LANE_VERSION))
    sweep = repo.enqueue_job(ScanJob(kind="scope", connection_id=target, payload={"trigger": "SCHEDULE", "mode": "DELTA"}))
    assert TaskStore(repo).seed_next_job().id == sweep.id
    with engine.begin() as conn:  # a sweep the old binary started, from before lanes
        conn.execute(update(scan_jobs).where(scan_jobs.c.id == sweep.id).values(lane=None))
    assert repo.ensure_scan_slot() and repo.ensure_scan_slot()
    with engine.connect() as conn:
        definition = conn.execute(text("SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() "
                                       "AND indexname='scan_jobs_one_running_connection'")).scalar_one()
        assert "lane" in definition
        assert conn.execute(select(schema_migrations.c.version).where(
            schema_migrations.c.version == SCAN_EVENT_LANE_VERSION)).first()
    events = [repo.enqueue_job(ScanJob(kind="scope", connection_id=target, payload={"trigger": "EVENT", "mode": "EVENT"}))
              for _ in range(2)]
    later_sweep = repo.enqueue_job(ScanJob(kind="scope", connection_id=target, payload={"trigger": "SCHEDULE"}))
    barrier = Barrier(8)

    def claim(_):
        barrier.wait(timeout=15)
        return TaskStore(repo).seed_next_job()

    with ThreadPoolExecutor(max_workers=8) as pool:
        admitted = [job for job in pool.map(claim, range(8)) if job]
    assert [job.id for job in admitted] == [events[0].id]
    for waiting in (events[1], later_sweep):  # each lane of a connection runs one job; the index backs it
        with pytest.raises(IntegrityError), engine.begin() as conn:
            conn.execute(update(scan_jobs).where(scan_jobs.c.id == waiting.id).values(status="RUNNING"))
    repo.enqueue_job(ScanJob(kind="inline"))
    assert TaskStore(repo).seed_next_job() is None  # an unscoped run waits for every lane
    repo.complete_job(events[0].id, 0, 0)
    assert TaskStore(repo).seed_next_job().id == events[1].id


def test_postgres_lane_migration_waits_for_running_rows_the_lane_index_would_refuse(pg):
    from datetime import UTC, datetime

    from cremore.db.migrations import SCAN_EVENT_LANE_VERSION
    from cremore.db.schema import scan_jobs

    engine, repo = pg
    target, ids = uuid.uuid4(), [uuid.uuid4(), uuid.uuid4()]
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX scan_jobs_one_running_connection"))
        conn.execute(delete(schema_migrations).where(schema_migrations.c.version == SCAN_EVENT_LANE_VERSION))
        for job_id in ids:
            conn.execute(insert(scan_jobs).values(id=job_id, kind="scope", status="RUNNING", payload={},
                                                  connection_id=target, objects=0, findings=0,
                                                  created_at=datetime.now(UTC)))
    assert repo.ensure_scan_slot() is False
    with engine.begin() as conn:
        conn.execute(update(scan_jobs).where(scan_jobs.c.id == ids[0]).values(status="SUCCEEDED"))
    assert repo.ensure_scan_slot() is True
    with engine.connect() as conn:
        assert "lane" in conn.execute(text("SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() "
                                           "AND indexname='scan_jobs_one_running_connection'")).scalar_one()


def test_postgres_global_slot_migration_preserves_pending_jobs(pg):
    from cremore.db.migrations import SCAN_CONNECTION_SLOTS_VERSION

    engine, repo = pg
    job = repo.enqueue_job(ScanJob(kind="scope", connection_id=uuid.uuid4()))
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX scan_jobs_one_running_connection"))
        conn.execute(text("CREATE UNIQUE INDEX scan_jobs_one_active_content_scan ON scan_jobs ((kind IS NOT NULL)) "
                          "WHERE status IN ('QUEUED','RUNNING','CANCELLING') AND kind IN ('scope','inline')"))
        conn.execute(delete(schema_migrations).where(schema_migrations.c.version == SCAN_CONNECTION_SLOTS_VERSION))
    assert repo.ensure_scan_slot() and repo.ensure_scan_slot()
    another = repo.enqueue_job(ScanJob(kind="scope", connection_id=uuid.uuid4()))
    assert {TaskStore(repo).seed_next_job().id, TaskStore(repo).seed_next_job().id} == {job.id, another.id}
    with engine.connect() as conn:
        names = set(conn.execute(text("SELECT indexname FROM pg_indexes WHERE schemaname=current_schema()")).scalars())
    assert "scan_jobs_one_running_connection" in names and "scan_jobs_one_active_content_scan" not in names
