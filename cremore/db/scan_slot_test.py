"""Durable scan admission and one executing content run per connection.

Runs against the in-memory repository and real SQLite, the two stores the
worker and API use in tests; PostgreSQL shares the same partial unique index.
"""

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from itertools import count

import pytest

from cremore.db import task_store
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.db.task_store import LeaseLost, TaskStore
from cremore.domain.models import ScanJob, ScopePlan


@pytest.fixture(params=["memory", "sqlite"])
def store(request, monkeypatch, tmp_path):
    now = {"value": datetime(2026, 9, 18, tzinfo=UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    # Real Windows timestamps may tie; tests that specify arrival order use a
    # controlled clock while production uses timestamp/UUID order in both stores.
    sequence = count()
    def stamp():
        return now["value"] + timedelta(microseconds=next(sequence))
    monkeypatch.setattr("cremore.db.repository._now", stamp)
    monkeypatch.setattr("cremore.db.sql._now", stamp)
    if request.param == "memory":
        repo = InMemoryRepository()
    else:
        engine = make_engine("sqlite+pysqlite:///" + (tmp_path / "slot.sqlite3").as_posix())
        create_all(engine)
        repo = SqlRepository(engine)
    return repo, TaskStore(repo), now


def scan(kind="github"):
    return ScanJob(kind=kind, payload={"owner": "o", "repo": "r"})


def test_busy_connections_queue_while_independent_connections_execute(store):
    repo, tasks, _now = store
    one, two = uuid.uuid4(), uuid.uuid4()
    a = repo.enqueue_job(scan().model_copy(update={"connection_id": one}))
    waiting = repo.enqueue_job(scan().model_copy(update={"connection_id": one}))
    b = repo.enqueue_job(scan("notion").model_copy(update={"connection_id": two}))
    assert tasks.seed_next_job().id == a.id
    assert tasks.seed_next_job().id == b.id
    assert tasks.seed_next_job() is None
    assert repo.get_job(waiting.id).status == "QUEUED"
    repo.complete_job(a.id, 0, 0)
    assert tasks.seed_next_job().id == waiting.id


def test_concurrent_claims_do_not_run_same_connection_twice(tmp_path):
    engine = make_engine("sqlite+pysqlite:///" + (tmp_path / "race.sqlite3").as_posix())
    create_all(engine)
    repo = SqlRepository(engine)
    target = uuid.uuid4()
    for _ in range(16):
        repo.enqueue_job(scan().model_copy(update={"connection_id": target}))
    with ThreadPoolExecutor(max_workers=8) as pool:
        claimed = list(pool.map(lambda _: TaskStore(repo).seed_next_job(), range(16)))
    assert len([j for j in claimed if j]) == 1
    assert len(repo.list_jobs()) == 16
    engine.dispose()


def test_index_refuses_two_running_jobs_but_allows_queued_and_other_connections(store):
    from sqlalchemy import update
    from sqlalchemy.exc import IntegrityError

    from cremore.db.schema import scan_jobs

    repo, tasks, _now = store
    target = uuid.uuid4()
    first = repo.enqueue_job(scan().model_copy(update={"connection_id": target}))
    second = repo.enqueue_job(scan().model_copy(update={"connection_id": target}))
    assert tasks.seed_next_job().id == first.id
    if isinstance(repo, SqlRepository):
        with pytest.raises(IntegrityError), repo.engine.begin() as conn:
            conn.execute(update(scan_jobs).where(scan_jobs.c.id == second.id).values(status="RUNNING"))
    assert tasks.seed_next_job() is None


def test_older_unscoped_scan_drains_active_connections_without_starving(store):
    repo, tasks, _now = store
    first = repo.enqueue_job(scan().model_copy(update={"connection_id": uuid.uuid4()}))
    assert tasks.seed_next_job().id == first.id
    legacy = repo.enqueue_job(scan())
    later = repo.enqueue_job(scan().model_copy(update={"connection_id": uuid.uuid4()}))
    metadata = repo.enqueue_job(ScanJob(kind="credential-usage", payload={"account_id": "123456789012"}))
    assert tasks.seed_next_job().id == metadata.id  # non-content work is not blocked
    assert tasks.seed_next_job() is None
    repo.complete_job(first.id, 0, 0)
    assert tasks.seed_next_job().id == legacy.id
    assert tasks.seed_next_job() is None
    repo.complete_job(legacy.id, 0, 0)
    assert tasks.seed_next_job().id == later.id


def test_trigger_receipts_preserve_busy_events_and_are_idempotent(store):
    repo, tasks, _now = store
    connection = uuid.uuid4()
    plan = ScopePlan(kind="source", connection_id=connection, profile_id=uuid.uuid4(), profile_version=1,
                     roots=[], catalog_snapshot_id="s", auth_revision="a", policy_digest="p", executable=True)
    job = ScanJob(kind="scope", connection_id=connection)
    first, created = repo.enqueue_triggered_scope(plan, job, "a" * 64)
    assert created and tasks.seed_next_job().id == first.id
    next_plan = plan.model_copy(update={"id": None})
    second, created = repo.enqueue_triggered_scope(next_plan, job, "b" * 64)
    assert created and second.id != first.id
    again, created = repo.enqueue_triggered_scope(plan.model_copy(update={"id": None}), job, "b" * 64)
    assert not created and again.id == second.id and tasks.seed_next_job() is None
    repo.complete_job(first.id, 0, 0)
    assert tasks.seed_next_job().id == second.id


def seeded_run(repo, tasks):
    job = repo.enqueue_job(scan("scope"))
    assert tasks.seed_next_job().id == job.id
    plan = tasks.claim()
    with tasks.fenced(plan["id"], plan["token"]) as bound:
        nested = TaskStore(bound)
        nested.enqueue(job.id, "root-a", {"mode": "BASELINE"})
        nested.enqueue(job.id, "root-b", {"mode": "BASELINE"})
        nested.finish(plan["id"], plan["token"], {"planned_roots": 2})
    return job


def test_a_task_parked_for_sign_in_keeps_the_slot(store):
    repo, tasks, _now = store
    job = seeded_run(repo, tasks)
    root = tasks.claim()
    tasks.defer(root["id"], root["token"], "AWS_LOGIN_REQUIRED")
    # The task is QUEUED again with no lease, but the job is still RUNNING.
    assert repo.get_job(job.id).status == "RUNNING"
    repo.enqueue_job(scan())
    assert tasks.seed_next_job() is None


def test_stopping_a_running_scan_fences_writes_withdraws_queued_work_and_frees_the_slot(store):
    repo, tasks, _now = store
    job = seeded_run(repo, tasks)
    running = tasks.claim()
    assert repo.request_job_cancel(job.id).status == "CANCELLING"
    # No result, checkpoint or new task of the run can be saved after the request.
    with pytest.raises(LeaseLost, match="RUN_CANCELLED"), tasks.fenced(running["id"], running["token"]):
        pass
    with pytest.raises(LeaseLost, match="RUN_CANCELLED"):
        tasks.checkpoint(running["id"], running["token"], {"objects": 1})
    with pytest.raises(LeaseLost, match="RUN_CANCELLED"):
        tasks.enqueue(job.id, "root-c", {"mode": "BASELINE"})
    # The queued sibling never starts, and the running one ends on release.
    assert tasks.claim() is None
    repo.enqueue_job(scan())
    assert tasks.seed_next_job() is None  # cancellation has not drained yet
    assert tasks.finalize_runs() == 0  # the running task has not stopped yet
    assert tasks.release_cancelled(running["id"], running["token"])
    assert tasks.finalize_runs() == 1
    assert repo.get_job(job.id).status == "CANCELLED"
    assert {t["status"] for t in tasks.list_for_run(job.id) if t["kind"] != "PLAN"} == {"CANCELLED"}
    repo.enqueue_job(scan())  # the slot is free again


def test_a_late_completion_never_overwrites_a_stop(store):
    repo, tasks, _now = store
    job = seeded_run(repo, tasks)
    repo.request_job_cancel(job.id)
    repo.complete_job(job.id, objects=5, findings=1)
    repo.fail_job(job.id, "LATE_FAILURE")
    assert repo.get_job(job.id).status == "CANCELLING"
    for _ in range(2):
        tasks.claim()  # withdraws the queued roots
    assert tasks.finalize_runs() == 1
    repo.complete_job(job.id, objects=5, findings=1)
    assert repo.get_job(job.id).status == "CANCELLED"


def test_a_stop_after_completion_changes_nothing(store):
    repo, tasks, _now = store
    job = repo.enqueue_job(scan())
    tasks.seed_next_job()
    repo.complete_job(job.id, objects=1, findings=0)
    assert repo.request_job_cancel(job.id).status == "SUCCEEDED"


def test_lease_recovery_does_not_rerun_a_task_of_a_stopped_run(store):
    repo, tasks, now = store
    job = seeded_run(repo, tasks)
    running = tasks.claim()
    repo.request_job_cancel(job.id)
    now["value"] += timedelta(seconds=600)  # the worker died; its lease expired
    assert tasks.claim() is None
    assert next(t for t in tasks.list_for_run(job.id) if t["id"] == running["id"])["status"] == "CANCELLED"
    assert tasks.finalize_runs() == 1 and repo.get_job(job.id).status == "CANCELLED"


def test_an_index_built_for_older_content_kinds_is_rebuilt_over_the_registered_ones(tmp_path):
    from sqlalchemy import text

    from cremore.db.migrations import SCAN_SLOT_KINDS_VERSION, _slot_kinds
    from cremore.db.schema import schema_migrations

    engine = make_engine("sqlite+pysqlite:///" + (tmp_path / "kinds.sqlite3").as_posix())
    create_all(engine)
    repo = SqlRepository(engine)
    # An installation whose index predates a newly registered source kind.
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX scan_jobs_one_running_connection"))
        conn.execute(text("CREATE UNIQUE INDEX scan_jobs_one_active_content_scan ON scan_jobs (kind IS NOT NULL) "
                          "WHERE status IN ('QUEUED', 'RUNNING') AND kind IN ('github')"))
        conn.execute(schema_migrations.delete().where(schema_migrations.c.version == SCAN_SLOT_KINDS_VERSION))
    assert repo.ensure_scan_slot() is True
    with engine.begin() as conn:
        sql = conn.execute(text("SELECT sql FROM sqlite_master WHERE name = 'scan_jobs_one_running_connection'")).scalar_one()
        assert "azure_blob" in sql and "'bitbucket'" in sql
        assert conn.execute(schema_migrations.select().where(
            schema_migrations.c.version == SCAN_SLOT_KINDS_VERSION)).mappings().one()["name"] == _slot_kinds()
    assert repo.ensure_scan_slot() is True  # idempotent once the kinds match
    engine.dispose()


def sweep(connection):
    return ScanJob(kind="scope", connection_id=connection, payload={"trigger": "SCHEDULE", "mode": "DELTA"})


def event(connection, mode="EVENT"):
    return ScanJob(kind="scope", connection_id=connection, payload={"trigger": "EVENT", "mode": mode})


def test_a_change_event_runs_beside_a_long_sweep_of_the_same_connection(store):
    repo, tasks, _now = store
    target = uuid.uuid4()
    long_sweep = repo.enqueue_job(sweep(target))
    assert tasks.seed_next_job().id == long_sweep.id
    first = repo.enqueue_job(event(target))
    second = repo.enqueue_job(event(target, mode="DELTA"))  # too many paths: a whole-root delta, still an event
    reread = repo.enqueue_job(event(target, mode="BASELINE"))  # a rewritten history rereads the root: a sweep
    assert tasks.seed_next_job().id == first.id
    assert tasks.seed_next_job() is None  # two events of one connection take turns, as two sweeps do
    repo.complete_job(first.id, 0, 0)
    assert tasks.seed_next_job().id == second.id
    assert tasks.seed_next_job() is None
    repo.complete_job(long_sweep.id, 0, 0)
    assert tasks.seed_next_job().id == reread.id


def test_an_unscoped_run_still_conflicts_with_every_lane(store):
    repo, tasks, _now = store
    target = uuid.uuid4()
    running = repo.enqueue_job(event(target))
    assert tasks.seed_next_job().id == running.id
    legacy = repo.enqueue_job(scan())
    later = repo.enqueue_job(sweep(target))  # a free lane, but behind the older unscoped run
    assert tasks.seed_next_job() is None
    repo.complete_job(running.id, 0, 0)
    assert tasks.seed_next_job().id == legacy.id
    other = repo.enqueue_job(event(uuid.uuid4()))
    assert tasks.seed_next_job() is None  # nothing runs beside an unscoped run
    repo.complete_job(legacy.id, 0, 0)
    assert {tasks.seed_next_job().id, tasks.seed_next_job().id} == {later.id, other.id}


def test_an_event_task_never_scans_a_root_while_the_sweep_scans_it(store):
    repo, tasks, now = store
    target = uuid.uuid4()
    # The runtime's root lock is per connection and root, the same for both lanes (ScanRuntime.plan).
    root = {"lock_key": f"{target}:S3_BUCKET:bucket", "connection_lock": str(target)}

    def planned(job, payload, priority):
        assert tasks.seed_next_job().id == job.id
        planning = tasks.claim(run_id=job.id)
        with tasks.fenced(planning["id"], planning["token"]) as bound:
            TaskStore(bound).enqueue(job.id, f"root-{job.id}", {**payload, **root}, priority=priority)
            TaskStore(bound).finish(planning["id"], planning["token"], {"planned_roots": 1})

    long_sweep = repo.enqueue_job(sweep(target))
    planned(long_sweep, {"mode": "DELTA"}, 0)
    sweeping = tasks.claim()
    assert sweeping["run_id"] == long_sweep.id
    change = repo.enqueue_job(event(target))
    planned(change, {"mode": "EVENT", "keys": ["config/.env"]}, 200)
    now["value"] += timedelta(seconds=30)  # past the event debounce; the sweep's lease still holds
    assert tasks.claim() is None
    tasks.finish(sweeping["id"], sweeping["token"], {})
    assert tasks.claim()["run_id"] == change.id


@pytest.mark.parametrize("kind, payload, lane", [
    ("scope", {"trigger": "EVENT", "mode": "EVENT"}, "event"),
    ("scope", {"trigger": "EVENT", "mode": "DELTA"}, "event"),
    ("scope", {"trigger": "EVENT", "mode": "event"}, "event"),
    ("scope", {"trigger": "EVENT", "mode": "BASELINE"}, "sweep"),
    ("scope", {"trigger": "EVENT"}, "sweep"),  # the runtime plans a missing mode as BASELINE
    ("scope", {"trigger": "SCHEDULE", "mode": "DELTA"}, "sweep"),
    ("scope", {"trigger": "RESCAN", "mode": "EVENT"}, "sweep"),
    ("scope", {}, "sweep"),
    ("scope", None, "sweep"),
    ("github", {"trigger": "EVENT", "mode": "EVENT"}, "sweep"),
])
def test_the_lane_of_each_payload_shape_is_stored_at_every_insert(tmp_path, kind, payload, lane):
    from sqlalchemy import select

    from cremore.db.repository import job_lane
    from cremore.db.schema import scan_jobs

    assert job_lane(kind, payload) == lane
    engine = make_engine("sqlite+pysqlite:///" + (tmp_path / "lane.sqlite3").as_posix())
    create_all(engine)
    repo = SqlRepository(engine)
    connection = uuid.uuid4()
    job = ScanJob(kind=kind, connection_id=connection, payload=payload or {})
    queued = [repo.enqueue_job(job)]
    if kind == "scope":
        plan = ScopePlan(kind="source", connection_id=connection, profile_id=uuid.uuid4(), profile_version=1,
                         roots=[], catalog_snapshot_id="s", auth_revision="a", policy_digest="p", executable=True)
        queued.append(repo.enqueue_triggered_scope(plan, job, "c" * 64)[0])
        approved = repo.create_plan(plan.model_copy(update={"id": None}))
        queued.append(repo.consume_scope_plan(approved.id, 1, job)[0])
    with engine.connect() as conn:
        stored = conn.execute(select(scan_jobs.c.lane).where(scan_jobs.c.id.in_([j.id for j in queued]))).scalars().all()
    assert stored == [lane] * len(queued)
    engine.dispose()


def _old_connection_index(conn):
    """The index of migration version 11: one running content job per connection, whatever its lane."""
    from sqlalchemy import text

    from cremore.domain.models import CONTENT_SCAN_KINDS

    kinds = ", ".join(f"'{kind}'" for kind in CONTENT_SCAN_KINDS)
    conn.execute(text("DROP INDEX scan_jobs_one_running_connection"))
    conn.execute(text("CREATE UNIQUE INDEX scan_jobs_one_running_connection ON scan_jobs "
                      "(coalesce(CAST(connection_id AS VARCHAR), 'unscoped')) "
                      f"WHERE status IN ('RUNNING', 'CANCELLING') AND kind IN ({kinds})"))


@pytest.mark.parametrize("running", [False, True])
def test_the_lane_migration_replaces_the_connection_index(tmp_path, running):
    from sqlalchemy import text, update
    from sqlalchemy.exc import IntegrityError

    from cremore.db.migrations import SCAN_EVENT_LANE_VERSION
    from cremore.db.schema import scan_jobs, schema_migrations

    engine = make_engine("sqlite+pysqlite:///" + (tmp_path / "lanes.sqlite3").as_posix())
    create_all(engine)
    repo, target = SqlRepository(engine), uuid.uuid4()
    tasks = TaskStore(repo)
    with engine.begin() as conn:
        _old_connection_index(conn)
        conn.execute(schema_migrations.delete().where(schema_migrations.c.version == SCAN_EVENT_LANE_VERSION))
    long_sweep = repo.enqueue_job(sweep(target))
    if running:  # a sweep the old binary started, from before lanes: its lane is NULL
        assert tasks.seed_next_job().id == long_sweep.id
        with engine.begin() as conn:
            conn.execute(update(scan_jobs).where(scan_jobs.c.id == long_sweep.id).values(lane=None))
    assert repo.ensure_scan_slot() is True  # the old index admitted it, so the laned one does too
    with engine.connect() as conn:
        sql = conn.execute(text("SELECT sql FROM sqlite_master WHERE name = 'scan_jobs_one_running_connection'")).scalar_one()
        assert "lane" in sql
        assert conn.execute(schema_migrations.select().where(schema_migrations.c.version == SCAN_EVENT_LANE_VERSION)).first()
    assert repo.ensure_scan_slot() is True  # idempotent
    if not running:
        assert tasks.seed_next_job().id == long_sweep.id
    change = repo.enqueue_job(event(target))
    another = repo.enqueue_job(sweep(target))
    assert tasks.seed_next_job().id == change.id
    assert tasks.seed_next_job() is None  # a NULL lane is a sweep, for the claim and for the index
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(update(scan_jobs).where(scan_jobs.c.id == another.id).values(status="RUNNING"))
    engine.dispose()


def test_a_database_without_the_old_index_waits_for_its_running_sweeps_before_the_lane_index(tmp_path):
    from sqlalchemy import insert, text, update

    from cremore.db.migrations import SCAN_EVENT_LANE_VERSION
    from cremore.db.schema import scan_jobs, schema_migrations

    engine = make_engine("sqlite+pysqlite:///" + (tmp_path / "drain.sqlite3").as_posix())
    create_all(engine)
    repo, target = SqlRepository(engine), uuid.uuid4()
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX scan_jobs_one_running_connection"))
        conn.execute(schema_migrations.delete().where(schema_migrations.c.version == SCAN_EVENT_LANE_VERSION))
        ids = [uuid.uuid4(), uuid.uuid4()]
        for job_id in ids:  # two sweeps of one connection at once: no slot index ever held them apart
            conn.execute(insert(scan_jobs).values(id=job_id, kind="scope", status="RUNNING", payload={},
                                                  connection_id=target, objects=0, findings=0,
                                                  created_at=datetime.now(UTC)))
    assert repo.ensure_scan_slot() is False
    with engine.connect() as conn:
        assert not conn.execute(text("SELECT 1 FROM sqlite_master WHERE name = 'scan_jobs_one_running_connection'")).first()
    with engine.begin() as conn:
        conn.execute(update(scan_jobs).where(scan_jobs.c.id == ids[0]).values(status="SUCCEEDED"))
    assert repo.ensure_scan_slot() is True
    with engine.connect() as conn:
        assert "lane" in conn.execute(text(
            "SELECT sql FROM sqlite_master WHERE name = 'scan_jobs_one_running_connection'")).scalar_one()
    engine.dispose()


def test_a_sqlite_file_waits_for_the_other_writers_commit(tmp_path):
    """A worker's control loop and its task runner write one SQLite file; a lease renewal must outwait a write."""
    engine = make_engine("sqlite+pysqlite:///" + (tmp_path / "writers.sqlite3").as_posix())
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA busy_timeout").scalar_one() == 30000
    engine.dispose()


def test_startup_refuses_a_database_without_the_lane_migration():
    from types import SimpleNamespace

    from cremore.db import startup as boot
    from cremore.db.migrations import SCAN_EVENT_LANE_VERSION
    from cremore.db.schema import schema_migrations

    engine = make_engine("sqlite:///:memory:")
    boot.startup(SimpleNamespace(), engine)
    with engine.begin() as conn:
        conn.execute(schema_migrations.delete().where(schema_migrations.c.version == SCAN_EVENT_LANE_VERSION))
    with engine.connect() as conn, pytest.raises(boot.DatabaseSchemaError, match="MIGRATIONS_INCOMPLETE"):
        boot.compatible_schema(conn)
    engine.dispose()


def test_an_upgrade_with_several_active_scans_waits_for_them_before_adding_the_index(tmp_path):
    from sqlalchemy import insert, text, update

    from cremore.db.migrations import SCAN_SLOT_VERSION
    from cremore.db.schema import scan_jobs, schema_migrations

    engine = make_engine("sqlite+pysqlite:///" + (tmp_path / "upgrade.sqlite3").as_posix())
    create_all(engine)
    # An installation from before the limit: no index, two scans running.
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX scan_jobs_one_running_connection"))
        conn.execute(schema_migrations.delete().where(schema_migrations.c.version == SCAN_SLOT_VERSION))
        ids = [uuid.uuid4(), uuid.uuid4()]
        for job_id in ids:
            conn.execute(insert(scan_jobs).values(id=job_id, kind="github", status="RUNNING", payload={},
                                                  objects=0, findings=0, created_at=datetime.now(UTC)))
    create_all(engine)  # startup must not fail
    repo = SqlRepository(engine)
    assert repo.ensure_scan_slot() is False
    repo.enqueue_job(scan())
    assert repo.claim_next_job() is None  # incompatible running scopes still hold admission
    with engine.begin() as conn:
        conn.execute(update(scan_jobs).where(scan_jobs.c.id == ids[0]).values(status="SUCCEEDED"))
    assert repo.ensure_scan_slot() is True
    with engine.begin() as conn:
        assert conn.execute(text("SELECT 1 FROM sqlite_master WHERE name = 'scan_jobs_one_running_connection'")).first()
        assert conn.execute(schema_migrations.select().where(schema_migrations.c.version == SCAN_SLOT_VERSION)).first()
    assert repo.ensure_scan_slot() is True  # idempotent
    engine.dispose()
