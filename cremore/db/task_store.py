"""Leased root work and transaction-fenced observations in the existing DB."""
from __future__ import annotations

import hashlib
import uuid
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime, timedelta

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    String,
    Table,
    UniqueConstraint,
    Uuid,
    and_,
    exists,
    func,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.exc import IntegrityError

from cremore.coverage import JOB_KIND as COVERAGE_JOB_KIND
from cremore.coverage import METADATA_JOB_KIND
from cremore.scanning.scope import FAILURE_BASIS
from cremore.task_state import safe_task_state

EVENT_DEBOUNCE_SECONDS = 2
# Parent job states in which a run's tasks must not start, resume or write.
STOPPED_RUN_STATUSES = ("CANCELLING", "CANCELLED")
EVENT_MAX_DELAY_SECONDS = 10


class LeaseLost(RuntimeError):
    """An expired/superseded execution cannot publish observations."""


def register_task_tables(metadata):
    if "remediation_authorization_nonces" not in metadata.tables:
        Table("remediation_authorization_nonces", metadata,
              Column("nonce", String(36), primary_key=True),
              Column("plan_id", Uuid, nullable=False),
              Column("consumed_at", DateTime(timezone=True), nullable=False))
    if "scan_tasks" in metadata.tables:
        return metadata.tables["scan_tasks"], metadata.tables["scan_task_memberships"]
    tasks = Table("scan_tasks", metadata,
        Column("id", Uuid, primary_key=True), Column("run_id", Uuid, nullable=False),
        Column("root_id", String(128), nullable=False), Column("lock_key", String(256), nullable=False),
        Column("connection_lock", String(128)), Column("exclusive_connection", Boolean, nullable=False, default=False),
        Column("start_key", String(2048), nullable=False), Column("kind", String(32), nullable=False),
        Column("payload", JSON, nullable=False), Column("priority", Integer, nullable=False),
        Column("status", String(32), nullable=False), Column("token", Uuid),
        Column("lease_until", DateTime(timezone=True)), Column("attempts", Integer, nullable=False, default=0),
        Column("checkpoint", JSON, nullable=False, default=dict), Column("result", JSON), Column("error", String(256)),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("available_at", DateTime(timezone=True), nullable=False), Column("finished_at", DateTime(timezone=True)),
        UniqueConstraint("run_id", "root_id", "start_key", name="scan_tasks_enumerator_key"))
    Index("scan_tasks_running_root_unique", tasks.c.lock_key, unique=True,
          postgresql_where=tasks.c.status == "RUNNING", sqlite_where=tasks.c.status == "RUNNING")
    pending = and_(tasks.c.status == "QUEUED", tasks.c.kind == "EVENT")
    Index("scan_tasks_pending_event_root_unique", tasks.c.root_id, unique=True,
          postgresql_where=pending, sqlite_where=pending)
    Index("scan_tasks_claim", tasks.c.status, tasks.c.priority, tasks.c.available_at)
    Index("scan_tasks_connection_claim", tasks.c.connection_lock, tasks.c.status)
    members = Table("scan_task_memberships", metadata,
        Column("run_id", Uuid, primary_key=True), Column("root_id", String(128), primary_key=True),
        Column("start_key", String(2048), primary_key=True), Column("task_id", Uuid, nullable=False, index=True))
    return tasks, members


def _utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _clock(conn=None):
    if conn is None:
        return datetime.now(UTC)
    if conn.dialect.name == "postgresql":
        from sqlalchemy import func
        return conn.execute(select(func.clock_timestamp())).scalar_one()
    value = conn.exec_driver_sql("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')").scalar_one()
    return datetime.fromisoformat(value)


def _charged(task):
    """The requests a task was charged: its result's count, or what its checkpoint reserved when it never finished
    (a Notion plan stopped during its search walk)."""
    return int((task["result"] or {}).get("requests", (task["checkpoint"] or {}).get("requests", 0)))


def _partial_beyond_hold(result):
    """Whether a root's result leaves its run partial (cremore.scanning.scope.job_is_partial) for any reason but the
    upgrade hold (``policy_held``): a failure, skip, stop or gap it counts, or an incomplete root it does not explain."""
    return bool(any(int(result.get(k, 0) or 0) for k in ("failed", "objects_failed", "skipped", "skipped_unsupported",
                                                            "skipped_media", "roots_failed", "partially_inspected",
                                                            "inspection_gaps"))
                or result.get("stopped_reason") or result.get("inspection_gaps_overflow") or result.get("coverage_basis")
                or (result.get("root_coverage_complete") is False and not result.get("policy_held")))


def _scope(payload):
    # These three fields are event hints, never approval/scope inputs; nor is the upgrade hold, merged below.
    scope = {k: v for k, v in payload.items() if k not in {"keys", "full_delta", "not_before"}}
    if isinstance(scope.get("job_payload"), dict):
        scope["job_payload"] = {k: v for k, v in scope["job_payload"].items() if k != "policy_hold"}
    return scope


def _merge_events(old, new):
    if _scope(old) != _scope(new):
        raise ValueError("EVENT_SCOPE_CONFLICT")
    if any(not isinstance(p.get("keys", []), list) or any(not isinstance(k, str) for k in p.get("keys", [])) for p in (old, new)):
        raise ValueError("INVALID_EVENT_KEYS")
    keys = sorted(set(old.get("keys", [])) | set(new.get("keys", [])))
    full = bool(old.get("full_delta") or new.get("full_delta") or len(keys) > 256)
    merged = {**old, "keys": [] if full else keys, "full_delta": full}
    if isinstance(old.get("job_payload"), dict):
        # Held (the runtime reads only what changed, or nothing) only if every merged run was: otherwise it reads.
        held = all((p.get("job_payload") or {}).get("policy_hold") is True for p in (old, new))
        job = {k: v for k, v in old["job_payload"].items() if k != "policy_hold"}
        merged["job_payload"] = {**job, "policy_hold": True} if held else job
    return merged


def _available(payload, now):
    value = payload.get("not_before")
    if value is None:
        return now + timedelta(seconds=EVENT_DEBOUNCE_SECONDS)
    stamp = datetime.fromtimestamp(value, UTC) if isinstance(value, (int, float)) else datetime.fromisoformat(value)
    return min(max(now, _utc(stamp)), now + timedelta(seconds=EVENT_MAX_DELAY_SECONDS))


class _BoundEngine:
    """Private adapter: nested repository/cache begin scopes cannot commit/close."""
    _task_bound = True

    def __init__(self, conn):
        self.connection, self.dialect = conn, conn.dialect

    @contextmanager
    def begin(self):
        yield self.connection

    connect = begin


class TaskStore:
    def __init__(self, repo):
        self.repo, self.engine = repo, getattr(repo, "engine", None)
        if self.engine is not None:
            from cremore.db.schema import metadata
            self.tasks, self.members = register_task_tables(metadata)
        else:
            if not hasattr(repo, "task_state_memory"):
                repo.task_state_memory = {"tasks": {}, "members": {}}
            self.memory = repo.task_state_memory

    @contextmanager
    def _transaction(self):
        if self.engine is None:
            with self.repo._lock:
                yield None
            return
        with self.engine.begin() as conn:
            if conn.dialect.name == "sqlite" and not getattr(self.engine, "_task_bound", False):
                conn.exec_driver_sql("BEGIN IMMEDIATE")
            self.repo._require_scan_schema(conn)
            yield conn

    @staticmethod
    def _insert(conn, table):
        if conn.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as native_insert
        else:
            from sqlalchemy.dialects.sqlite import insert as native_insert
        return native_insert(table)

    def _bound(self, conn):
        if conn is None:
            return self.repo
        from cremore.db.sql import SqlRepository
        repo = SqlRepository(_BoundEngine(conn))
        repo._scan_schema_ready = True
        repo.audit_key = self.repo.audit_key  # rows written in this transaction are the same writer's
        return repo

    def _get(self, conn, task_id, *, lock=False):
        if conn is None:
            return self.memory["tasks"].get(task_id)
        query = select(self.tasks).where(self.tasks.c.id == task_id)
        row = conn.execute(query.with_for_update() if lock else query).mappings().first()
        return dict(row) if row else None

    def _owned(self, conn, task_id, token, *, terminal=False):
        row = self._get(conn, task_id, lock=True)
        statuses = {"RUNNING", "SUCCEEDED", "FAILED"} if terminal else {"RUNNING"}
        if (not row or row["status"] not in statuses or row["token"] != token
                or row["lease_until"] is None or _utc(row["lease_until"]) <= _clock(conn)):
            raise LeaseLost("TASK_LEASE_LOST")
        # The parent row is share-locked, so a stop request and this write are
        # serialized: once CANCELLING commits, no checkpoint or result of the run
        # can be saved, and a write already in flight commits before the stop.
        if self._run_stopped(conn, row["run_id"], lock=True):
            raise LeaseLost("RUN_CANCELLED")
        return row

    def _run_stopped(self, conn, run_id, *, lock=False):
        if conn is None:
            job = getattr(self.repo, "jobs", {}).get(run_id)
            return job is not None and job.status in STOPPED_RUN_STATUSES
        from cremore.db.schema import scan_jobs
        query = select(scan_jobs.c.status).where(scan_jobs.c.id == run_id)
        status = conn.execute(query.with_for_update(read=True) if lock else query).scalar_one_or_none()
        return status in STOPPED_RUN_STATUSES

    def _cancel_stopped_tasks(self, conn, now, execution_role="mixed"):
        """Queued tasks of a stopped run never start; they end CANCELLED."""
        changes = {"status": "CANCELLED", "token": None, "lease_until": None, "finished_at": now}
        if conn is None:
            for task in self.memory["tasks"].values():
                if (task["status"] == "QUEUED" and self._run_stopped(None, task["run_id"])
                        and self._accepts_run(task["run_id"], execution_role)):
                    task.update(changes)
            return
        from cremore.db.schema import scan_jobs
        from cremore.worker.isolation import job_predicate
        stopped = select(scan_jobs.c.id).where(scan_jobs.c.status.in_(STOPPED_RUN_STATUSES),
                                               job_predicate(scan_jobs, execution_role))
        conn.execute(update(self.tasks).where(self.tasks.c.status == "QUEUED", self.tasks.c.run_id.in_(stopped))
                     .values(**changes))

    def release_cancelled(self, task_id, token):
        """End a running task of a stopped run now instead of waiting for its lease."""
        with self._transaction() as conn:
            row = self._get(conn, task_id, lock=True)
            if (row and row["status"] == "RUNNING" and row["token"] == token
                    and self._run_stopped(conn, row["run_id"])):
                self._update(conn, task_id, {"status": "CANCELLED", "token": None, "lease_until": None,
                                             "finished_at": _clock(conn)})
                return True
            return False

    def _update(self, conn, task_id, changes):
        if conn is None:
            self.memory["tasks"][task_id].update(changes)
        else:
            conn.execute(update(self.tasks).where(self.tasks.c.id == task_id).values(**changes))

    def enqueue(self, run_id, root_id, payload, priority=0, start_key=""):
        run_id = uuid.UUID(str(run_id))
        if not isinstance(root_id, str) or not root_id or len(root_id) > 128 or not isinstance(start_key, str) or len(start_key) > 2048:
            raise ValueError("INVALID_TASK_ROOT_OR_START_KEY")
        payload = safe_task_state(payload)
        if not isinstance(payload, dict):
            raise TypeError("TASK_PAYLOAD_MUST_BE_OBJECT")
        kind = str(payload.get("mode", "BASELINE")).upper()
        if kind not in {"PLAN", "BASELINE", "DELTA", "EVENT", "RECONCILE", "POLICY_SWEEP", "INVENTORY"}:
            raise ValueError("INVALID_TASK_MODE")
        lock_key = payload.get("lock_key", root_id)
        if not isinstance(lock_key, str) or not lock_key or len(lock_key) > 256:
            raise ValueError("INVALID_TASK_LOCK_KEY")
        connection_lock = payload.get("connection_lock")
        if connection_lock is not None and (not isinstance(connection_lock, str) or len(connection_lock) > 128):
            raise ValueError("INVALID_CONNECTION_LOCK")
        if kind == "EVENT":
            payload = _merge_events(payload, payload)
        key = (run_id, root_id, start_key)
        with self._transaction() as conn:
            if self._run_stopped(conn, run_id):
                raise LeaseLost("RUN_CANCELLED")
            now = _clock(conn)
            if conn is None:
                current_id = self.memory["members"].get(key)
            else:
                current_id = conn.execute(select(self.members.c.task_id).where(self.members.c.run_id == run_id,
                    self.members.c.root_id == root_id, self.members.c.start_key == start_key)).scalar_one_or_none()
            current = self._get(conn, current_id, lock=True) if current_id else None
            if current is not None:
                if (kind != "EVENT" and current["payload"] != payload) or (kind == "EVENT" and _scope(current["payload"]) != _scope(payload)):
                    raise ValueError("IMMUTABLE_TASK_SCOPE_CHANGED")
                if kind == "EVENT":
                    merged = _merge_events(current["payload"], payload)
                    if merged != current["payload"]:
                        if current["status"] != "QUEUED":
                            raise ValueError("IMMUTABLE_RUNNING_EVENT_HINTS")
                        self._update(conn, current["id"], {"payload": merged})
                        current["payload"] = merged
                return deepcopy(current)
            values = {"id": uuid.uuid4(), "run_id": run_id, "root_id": root_id, "lock_key": lock_key,
                      "connection_lock": connection_lock, "exclusive_connection": bool(payload.get("exclusive_connection")),
                      "start_key": start_key, "kind": kind, "payload": payload, "priority": int(priority),
                      "status": "QUEUED", "token": None, "lease_until": None, "attempts": 0, "checkpoint": {},
                      "result": None, "error": None, "created_at": now, "finished_at": None,
                      "available_at": _available(payload, now) if kind == "EVENT" else now}
            if conn is None:
                if kind == "EVENT":
                    current = next((t for t in self.memory["tasks"].values() if t["root_id"] == root_id
                                    and t["kind"] == "EVENT" and t["status"] == "QUEUED"), None)
                if current is None:
                    self.memory["tasks"][values["id"]] = values
                    current = values
            else:
                for _ in range(4):
                    inserted = conn.execute(self._insert(conn, self.tasks).values(**values)
                        .on_conflict_do_nothing().returning(self.tasks)).mappings().first()
                    if inserted:
                        current = dict(inserted)
                        break
                    if kind == "EVENT":
                        predicate = or_(and_(self.tasks.c.root_id == root_id, self.tasks.c.kind == "EVENT", self.tasks.c.status == "QUEUED"),
                            and_(self.tasks.c.run_id == run_id, self.tasks.c.root_id == root_id, self.tasks.c.start_key == start_key))
                    else:
                        predicate = and_(self.tasks.c.run_id == run_id, self.tasks.c.root_id == root_id, self.tasks.c.start_key == start_key)
                    row = conn.execute(select(self.tasks).where(predicate).with_for_update()).mappings().first()
                    if row:
                        current = dict(row)
                        break
                else:
                    raise RuntimeError("TASK_ENQUEUE_CONTENTION_RETRY")
            if kind == "EVENT" and current["status"] == "QUEUED":
                merged = _merge_events(current["payload"], payload)
                initial = _available(current["payload"], _utc(current["created_at"]))
                cap = max(initial, _utc(current["created_at"]) + timedelta(seconds=EVENT_MAX_DELAY_SECONDS))
                changes = {"payload": merged, "priority": max(int(priority), current["priority"]),
                           "available_at": min(max(_utc(current["available_at"]), _available(payload, now)), cap)}
                self._update(conn, current["id"], changes)
                current.update(changes)
            elif current["payload"] != payload:
                raise ValueError("IMMUTABLE_TASK_SCOPE_CHANGED")
            if conn is None:
                self.memory["members"][key] = current["id"]
            else:
                conn.execute(self._insert(conn, self.members).values(run_id=run_id, root_id=root_id,
                    start_key=start_key, task_id=current["id"]).on_conflict_do_nothing())
            return deepcopy(current)

    def _recover(self, conn, now, max_attempts, execution_role="mixed"):
        if conn is None:
            expired = [deepcopy(t) for t in self.memory["tasks"].values()
                       if t["status"] == "RUNNING" and _utc(t["lease_until"]) <= now
                       and self._accepts_run(t["run_id"], execution_role)]
        else:
            expired = [dict(r) for r in conn.execute(select(self.tasks).where(self.tasks.c.status == "RUNNING",
                self.tasks.c.lease_until <= now, self._run_predicate(execution_role)).limit(100).with_for_update(skip_locked=True)).mappings()]
        for task in expired:
            pending = None
            if task["kind"] == "EVENT":
                if conn is None:
                    pending = next((t for t in self.memory["tasks"].values() if t["root_id"] == task["root_id"]
                                    and t["status"] == "QUEUED" and t["kind"] == "EVENT"), None)
                else:
                    row = conn.execute(select(self.tasks).where(self.tasks.c.root_id == task["root_id"],
                        self.tasks.c.status == "QUEUED", self.tasks.c.kind == "EVENT").with_for_update()).mappings().first()
                    pending = dict(row) if row else None
            if pending and _scope(pending["payload"]) == _scope(task["payload"]):
                if conn is None:
                    for key, task_id in list(self.memory["members"].items()):
                        if task_id == task["id"]:
                            self.memory["members"][key] = pending["id"]
                else:
                    conn.execute(update(self.members).where(self.members.c.task_id == task["id"]).values(task_id=pending["id"]))
                self._update(conn, pending["id"], {"payload": _merge_events(pending["payload"], task["payload"]),
                    "priority": max(pending["priority"], task["priority"])})
                changes = {"status": "SUPERSEDED", "result": {"superseded_by": str(pending["id"])}, "finished_at": now}
            elif pending or task["attempts"] >= max_attempts:
                changes = {"status": "FAILED", "error": "EVENT_SCOPE_CONFLICT" if pending else "LEASE_RETRY_LIMIT", "finished_at": now}
            else:
                changes = {"status": "QUEUED", "available_at": now}
            self._update(conn, task["id"], {**changes, "token": None, "lease_until": None})

    def claim(self, lease_seconds=120, max_attempts=3, *, run_id=None, execution_role="mixed"):
        if lease_seconds <= 0 or max_attempts < 1:
            raise ValueError("INVALID_TASK_LEASE_OR_ATTEMPTS")
        if run_id is not None:
            run_id = uuid.UUID(str(run_id))
        with self._transaction() as conn:
            now = _clock(conn)
            self._recover(conn, now, max_attempts, execution_role)
            # After recovery, so an expired task of a stopped run that recovery
            # just re-queued ends CANCELLED here instead of running again.
            self._cancel_stopped_tasks(conn, now, execution_role)
            # Fair across runs: within a priority, a run with fewer tasks running goes first, so an older run's many
            # roots do not hold every runner while a newer run of another connection waits. Age breaks the tie.
            if conn is None:
                active = [t for t in self.memory["tasks"].values() if t["status"] == "RUNNING"]
                running = {t["lock_key"] for t in active}
                load = Counter(t["run_id"] for t in active)
                members = {v for k, v in self.memory["members"].items() if k[0] == run_id}
                candidates = sorted((t for t in self.memory["tasks"].values() if t["status"] == "QUEUED"
                    and t["lock_key"] not in running and _utc(t["available_at"]) <= now
                    and (run_id is None or t["id"] in members)
                    and self._accepts_run(t["run_id"], execution_role)),
                    key=lambda t: (-t["priority"], load[t["run_id"]], t["created_at"], str(t["id"])))
            else:
                running = self.tasks.alias("running_root")
                # RUNNING rows are few (one per runner), so counting them per run once is cheap and needs no index.
                busy = self.tasks.alias("running_run")
                load = (select(busy.c.run_id, func.count().label("running")).where(busy.c.status == "RUNNING")
                        .group_by(busy.c.run_id).subquery("run_load"))
                query = select(self.tasks).select_from(self.tasks.outerjoin(load, load.c.run_id == self.tasks.c.run_id)).where(
                    self.tasks.c.status == "QUEUED", self.tasks.c.available_at <= now,
                    ~exists(select(running.c.id).where(running.c.lock_key == self.tasks.c.lock_key, running.c.status == "RUNNING")))
                query = query.where(~exists(select(running.c.id).where(
                    running.c.status == "RUNNING", running.c.connection_lock == self.tasks.c.connection_lock,
                    or_(running.c.exclusive_connection.is_(True), self.tasks.c.exclusive_connection.is_(True)))))
                if run_id is not None:
                    query = query.where(self.tasks.c.id.in_(select(self.members.c.task_id).where(self.members.c.run_id == run_id)))
                if execution_role != "mixed":
                    from cremore.db.schema import scan_jobs
                    from cremore.worker.isolation import job_predicate
                    query = query.where(self.tasks.c.run_id.in_(select(scan_jobs.c.id).where(
                        job_predicate(scan_jobs, execution_role))))
                # OF scan_tasks: only candidate rows are locked; the grouped load cannot be, and need not be.
                candidates = [dict(r) for r in conn.execute(query.order_by(self.tasks.c.priority.desc(),
                    func.coalesce(load.c.running, 0), self.tasks.c.created_at, self.tasks.c.id)
                    .limit(16).with_for_update(skip_locked=True, of=self.tasks)).mappings()]
            for task in candidates:
                connection_lock = task["connection_lock"]
                if connection_lock:
                    if conn is None:
                        conflict = any(t["status"] == "RUNNING" and t["connection_lock"] == connection_lock
                            and (task["exclusive_connection"] or t["exclusive_connection"]) for t in self.memory["tasks"].values())
                    else:
                        if conn.dialect.name == "postgresql":
                            key = int.from_bytes(hashlib.sha256(connection_lock.encode()).digest()[:4], "big", signed=True)
                            if not conn.execute(text("SELECT pg_try_advisory_xact_lock(:namespace, :key)"),
                                                {"namespace": 0x43455054, "key": key}).scalar_one():
                                continue
                        query = select(self.tasks.c.id).where(self.tasks.c.status == "RUNNING",
                            self.tasks.c.connection_lock == connection_lock)
                        if not task["exclusive_connection"]:
                            query = query.where(self.tasks.c.exclusive_connection.is_(True))
                        conflict = conn.execute(query.limit(1)).first() is not None
                    if conflict:
                        continue
                if task["attempts"] >= max_attempts:
                    self._update(conn, task["id"], {"status": "FAILED", "error": "LEASE_RETRY_LIMIT", "finished_at": now})
                    continue
                changes = {"status": "RUNNING", "token": uuid.uuid4(), "lease_until": now + timedelta(seconds=lease_seconds),
                           "attempts": task["attempts"] + 1, "error": None}
                if conn is None:
                    self._update(conn, task["id"], changes)
                else:
                    try:
                        with conn.begin_nested():
                            self._update(conn, task["id"], changes)
                    except IntegrityError:
                        continue  # Root claim conflict is contention, not scan failure.
                return deepcopy({**task, **changes})
            return None

    def waiting_event(self, lock_key, *, skip=None):
        """The id of a change-scan task of this root lock that could start now, other than ``skip``, or None: a
        resumable sweep holding the lock yields to it (cremore.worker.runtime)."""
        with self._transaction() as conn:
            now = _clock(conn)
            if conn is None:
                waiting = sorted((t for t in self.memory["tasks"].values() if t["status"] == "QUEUED"
                                  and t["kind"] == "EVENT" and t["lock_key"] == lock_key
                                  and _utc(t["available_at"]) <= now and str(t["id"]) != skip),
                                 key=lambda t: (-t["priority"], t["created_at"], str(t["id"])))
                return str(waiting[0]["id"]) if waiting else None
            query = select(self.tasks.c.id).where(self.tasks.c.status == "QUEUED", self.tasks.c.kind == "EVENT",
                                                  self.tasks.c.lock_key == lock_key, self.tasks.c.available_at <= now)
            if skip is not None:
                query = query.where(self.tasks.c.id != uuid.UUID(str(skip)))
            found = conn.execute(query.order_by(self.tasks.c.priority.desc(), self.tasks.c.created_at,
                                                self.tasks.c.id).limit(1)).scalar_one_or_none()
            return str(found) if found is not None else None

    def heartbeat(self, task_id, token, lease_seconds=120):
        if lease_seconds <= 0:
            raise ValueError("INVALID_TASK_LEASE")
        with self._transaction() as conn:
            self._owned(conn, task_id, token)
            until = _clock(conn) + timedelta(seconds=lease_seconds)
            self._update(conn, task_id, {"lease_until": until})
            return until

    def checkpoint(self, task_id, token, state):
        state = safe_task_state(state)
        with self._transaction() as conn:
            self._owned(conn, task_id, token)
            self._update(conn, task_id, {"checkpoint": state})

    def amend_checkpoint(self, task_id, token, changes):
        """Merge ``changes`` into the saved checkpoint, as the last committed write left it."""
        with self._transaction() as conn:
            task = self._owned(conn, task_id, token)
            self._update(conn, task_id, {"checkpoint": safe_task_state({**(task["checkpoint"] or {}), **changes})})

    def finish(self, task_id, token, result):
        result = safe_task_state(result)
        with self._transaction() as conn:
            self._owned(conn, task_id, token)
            self._update(conn, task_id, {"status": "SUCCEEDED", "result": result, "finished_at": _clock(conn)})

    def defer(self, task_id, token, code, delay_seconds=60, priority=None, checkpoint=None):
        """Return a claimed task to the queue without spending a retry attempt.

        For waits outside the task's control (an expired AWS sign-in, an
        identity awaiting re-approval): checkpoints are kept, so it resumes.
        ``checkpoint`` fields are merged into the saved checkpoint, as the last
        committed write left it, in the same write."""
        if not isinstance(code, str) or not code or len(code) > 256 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for c in code):
            raise ValueError("TASK_ERROR_MUST_BE_SAFE_CODE")
        with self._transaction() as conn:
            task = self._owned(conn, task_id, token)
            self._update(conn, task_id, {
                "status": "QUEUED", "error": code, "token": None, "lease_until": None,
                "available_at": _clock(conn) + timedelta(seconds=max(1, int(delay_seconds))),
                "attempts": max(0, int(task["attempts"]) - 1),
                **({"priority": int(priority)} if priority is not None else {}),
                **({"checkpoint": safe_task_state({**(task["checkpoint"] or {}), **checkpoint})} if checkpoint else {}),
            })

    def top_up_budget(self, task_id, token, keys):
        """Give this root the share other finished roots of its run did not use.

        Roots get fixed shares so concurrent roots never over-reserve; without
        this, one large bucket fails its share while a small sibling finishes
        with most of its share unused. Finished siblings' shares shrink to what
        they used and the difference moves here, so the approved run total never
        grows. Returns ``(granted, pending_priority)``: with nothing granted but
        unfinished siblings (their lowest priority), the caller waits behind them.
        A sibling itself waiting for budget is no reason to wait: two such roots
        would wait on each other forever, so with only those left the caller stops.
        """
        keys = [k for k in keys if k in ("requests", "bytes", "seconds")]
        with self._transaction() as conn:
            me = self._get(conn, task_id)
            if me is None:
                raise LeaseLost("TASK_LEASE_LOST")
            # Lock the whole run in id order (including this task) so two roots
            # topping up at once cannot both take the same spare share.
            if conn is None:
                run = sorted((t for t in self.memory["tasks"].values() if t["run_id"] == me["run_id"]), key=lambda t: str(t["id"]))
            else:
                run = [dict(r) for r in conn.execute(select(self.tasks).where(self.tasks.c.run_id == me["run_id"])
                                                     .order_by(self.tasks.c.id).with_for_update()).mappings()]
            me = self._owned(conn, task_id, token)
            granted = {k: 0 for k in keys}
            pending = None  # lowest priority among unfinished siblings
            for task in run:
                if task["id"] == task_id or task["kind"] == "PLAN":
                    continue
                if task["status"] not in ("SUCCEEDED", "FAILED"):
                    waiting = (task["status"] == "QUEUED" and str(task["error"] or "").startswith("BUDGET_")
                               and (task["checkpoint"] or {}).get("budget_wait"))
                    if not waiting:
                        pending = int(task["priority"]) if pending is None else min(pending, int(task["priority"]))
                    continue
                budgets = dict((task["payload"] or {}).get("budgets") or {})
                changed = False
                for key in keys:
                    if key not in budgets:
                        continue
                    used = int((task["checkpoint"] or {}).get(key, 0))
                    spare = int(budgets[key]) - used
                    if spare > 0:
                        budgets[key], granted[key], changed = used, granted[key] + spare, True
                if changed:
                    self._update(conn, task["id"], {"payload": {**task["payload"], "budgets": budgets}})
            if any(granted.values()):
                budgets = dict((me["payload"] or {}).get("budgets") or {})
                for key, extra in granted.items():
                    budgets[key] = int(budgets.get(key, 0)) + extra
                self._update(conn, task_id, {"payload": {**me["payload"], "budgets": budgets}})
            return sum(granted.values()), pending

    def fail(self, task_id, token, code):
        if not isinstance(code, str) or not code or len(code) > 256 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for c in code):
            raise ValueError("TASK_ERROR_MUST_BE_SAFE_CODE")
        with self._transaction() as conn:
            self._owned(conn, task_id, token)
            self._update(conn, task_id, {"status": "FAILED", "error": code, "finished_at": _clock(conn)})

    def list_for_run(self, run_id):
        run_id = uuid.UUID(str(run_id))
        with self._transaction() as conn:
            if conn is None:
                ids = {v for key, v in self.memory["members"].items() if key[0] == run_id}
                return [deepcopy(self.memory["tasks"][task_id]) for task_id in sorted(ids, key=str)]
            return [dict(r) for r in conn.execute(select(self.tasks).where(self.tasks.c.id.in_(
                select(self.members.c.task_id).where(self.members.c.run_id == run_id))).order_by(self.tasks.c.created_at, self.tasks.c.id)).mappings()]

    def run_states(self, run_id, now=None):
        """Progress and any wait/hold reason for a run, from its tasks.

        ``held`` lists tasks parked by :meth:`defer` for a reason outside their
        control (an expired AWS sign-in, an identity awaiting re-approval): each
        carries the safe code and when it will next be attempted. ``done/total``
        is real progress once roots have been enumerated.
        """
        from datetime import datetime

        now = now or datetime.now(UTC)
        tasks = self.list_for_run(run_id)
        terminal = {"SUCCEEDED", "FAILED", "CANCELLED", "DONE"}
        done = running = queued = 0
        held, failures = [], []
        for t in tasks:
            status = t.get("status")
            root = str(t.get("root_id") or "")
            if status == "FAILED":
                done += 1
                if t.get("error"):
                    failures.append({"root": root, "code": t["error"]})
            elif status in terminal:
                done += 1
            elif status == "RUNNING":
                running += 1
            else:
                queued += 1
                available = t.get("available_at")
                if isinstance(available, str):
                    try:
                        available = datetime.fromisoformat(available)
                    except ValueError:
                        available = None
                if available is not None and available.tzinfo is None:
                    available = available.replace(tzinfo=UTC)  # SQLite returns naive UTC
                if t.get("error") and available is not None and available > now:
                    held.append({"code": t["error"], "next_attempt_at": available.isoformat()})
        codes = [h["code"] for h in held]
        hold_code = max(set(codes), key=codes.count) if codes else None
        next_attempt = min((h["next_attempt_at"] for h in held), default=None)
        return {"total": len(tasks), "done": done, "running": running, "queued": queued,
                "held": held, "hold_code": hold_code, "next_attempt_at": next_attempt, "failures": failures[:50]}

    def _run_predicate(self, execution_role):
        from cremore.db.schema import scan_jobs
        from cremore.worker.isolation import job_predicate
        if execution_role == "mixed":
            from sqlalchemy import true
            return true()
        return self.tasks.c.run_id.in_(select(scan_jobs.c.id).where(job_predicate(scan_jobs, execution_role)))

    def _accepts_run(self, run_id, execution_role):
        from cremore.worker.isolation import accepts
        return accepts(self.repo, self.repo.get_job(run_id), execution_role)

    def consume_authorization(self, nonce, plan_id):
        """A durable, insert-only replay tombstone; never pruned with jobs."""
        nonce, plan_id = str(uuid.UUID(nonce)), uuid.UUID(plan_id)
        with self._transaction() as conn:
            if conn is None:
                used = self.memory.setdefault("authorization_nonces", {})
                if nonce in used:
                    return False
                used[nonce] = {"plan_id": plan_id, "consumed_at": _clock()}
                return True
            from cremore.db.schema import metadata
            table = metadata.tables["remediation_authorization_nonces"]
            return conn.execute(self._insert(conn, table).values(
                nonce=nonce, plan_id=plan_id, consumed_at=_clock(conn)).on_conflict_do_nothing()
                .returning(table.c.nonce)).scalar_one_or_none() is not None

    def seed_next_job(self, *, execution_role="mixed"):
        """Claim parent and durably seed planning together; no unleased planning gap."""
        with self._transaction() as conn:
            bound = self._bound(conn)
            job = bound.claim_next_job(execution_role=execution_role)
            if job is None:
                return None
            from cremore.domain.models import CONTENT_SCAN_KINDS
            try:
                payload = {"mode": "PLAN", "job_id": str(job.id)}
                if job.kind == METADATA_JOB_KIND:
                    cid = str(job.payload["coverage_connection_id"])
                    payload.update(mode="INVENTORY", lock_key="metadata:" + cid,
                                   connection_lock="metadata:" + cid, exclusive_connection=True)
                if job.kind == "credential-usage":
                    key = "credential-usage:" + job.payload["account_id"]
                    payload.update(mode="INVENTORY", lock_key=key, connection_lock=key, exclusive_connection=True)
                if job.connection_id and job.kind in CONTENT_SCAN_KINDS and job.kind != "scope":
                    payload.update(connection_lock=str(job.connection_id), exclusive_connection=True)
                TaskStore(bound).enqueue(job.id, f"plan:{job.id}", payload, priority=100)
            except Exception:
                if conn is None:
                    job.status, job.started_at = "QUEUED", None
                raise
            return job

    def finalize_runs(self, limit=100, *, execution_role="mixed"):
        """Finalize only after planning and every canonical member task are terminal."""
        finalized = 0
        terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
        with self._transaction() as conn:
            bound = self._bound(conn)
            if conn is None:
                populated, unfinished = set(), set()
                for (run_id, _root, _start), task_id in self.memory["members"].items():
                    populated.add(run_id)
                    if self.memory["tasks"][task_id]["status"] not in terminal:
                        unfinished.add(run_id)
                jobs = [j for j in self.repo.jobs.values() if j.status in ("RUNNING", "CANCELLING")
                        and j.id not in unfinished and (j.id in populated or j.status == "CANCELLING")
                        and self._accepts_run(j.id, execution_role)][:limit]
            else:
                from cremore.db.schema import scan_jobs
                from cremore.domain.models import ScanJob
                from cremore.worker.isolation import job_predicate
                members = select(self.tasks.c.id).select_from(self.members.join(
                    self.tasks, self.members.c.task_id == self.tasks.c.id)).where(self.members.c.run_id == scan_jobs.c.id)
                # Apply the batch limit to ready parents, not to earlier parked jobs.
                jobs = [ScanJob.model_validate(dict(r)) for r in conn.execute(select(scan_jobs).where(
                    scan_jobs.c.status.in_(("RUNNING", "CANCELLING")),
                    job_predicate(scan_jobs, execution_role),
                    ~exists(members.where(self.tasks.c.status.not_in(terminal))),
                    or_(exists(members), scan_jobs.c.status == "CANCELLING"))
                    .order_by(scan_jobs.c.created_at, scan_jobs.c.id).limit(limit).with_for_update(skip_locked=True)).mappings()]
            store = TaskStore(bound)
            for job in jobs:
                tasks = store.list_for_run(job.id)
                if any(t["status"] not in terminal for t in tasks):
                    continue
                closed = []  # metadata runs this finalisation closes; their records stay readable
                if job.status == "CANCELLING":
                    if job.kind == METADATA_JOB_KIND:
                        from cremore.coverage.metadata_store import MetadataStore

                        # A stopped collection's open run is closed with it, in this
                        # transaction; what it committed stays readable, never current.
                        for task in tasks:
                            rid = (task.get("checkpoint") or {}).get("metadata_run_id")
                            if rid:
                                MetadataStore(bound).abort(uuid.UUID(job.payload["coverage_connection_id"]),
                                                           uuid.UUID(rid), "METADATA_COLLECTION_STOPPED")
                                closed.append(rid)
                    # Every task has stopped: the slot is released only now.
                    results = [t["result"] or {} for t in tasks if t["kind"] != "PLAN" and t["status"] == "SUCCEEDED"]
                    bound.finish_cancelled_job(job.id, {
                        "objects": sum(int(r.get("objects", 0)) for r in results),
                        "findings": sum(int(r.get("findings", 0)) for r in results),
                        "tasks": len([t for t in tasks if t["kind"] != "PLAN"]),
                        "requests": sum(_charged(t) for t in tasks),
                        "stopped_reason": "CANCELLED", "source": "DURABLE_ROOT_TASKS",
                        **({"coverage_run_ids": sorted(set(closed))} if closed else {})})
                    finalized += 1
                    continue
                if not tasks:
                    continue
                if any(t["status"] != "SUCCEEDED" for t in tasks):
                    reason = "CHILD_TASK_FAILED"
                    if job.kind == METADATA_JOB_KIND:
                        from cremore.coverage.metadata_store import MetadataStore

                        reason = next((t["error"] for t in tasks if t["status"] == "FAILED" and t["error"]),
                                      "METADATA_COLLECTION_FAILED")
                        # A dead worker cannot execute metadata_job's exception
                        # handler. Close only its checkpointed run, in the same
                        # transaction as the terminal parent; abort is idempotent.
                        for task in tasks:
                            rid = (task.get("checkpoint") or {}).get("metadata_run_id")
                            if rid:
                                MetadataStore(bound).abort(uuid.UUID(job.payload["coverage_connection_id"]),
                                                           uuid.UUID(rid), reason)
                                closed.append(rid)
                    if closed:
                        # A failed job keeps no coverage of its own; the closed runs it names are what it read.
                        bound.complete_job(job.id, 0, 0, coverage={"coverage_run_ids": sorted(set(closed)),
                                                                   "source": "DURABLE_ROOT_TASKS"})
                    bound.fail_job(job.id, reason)
                else:
                    # A schema-1 collection runs in its one PLAN task, whose result is the collection's.
                    results = [t["result"] or {} for t in tasks if t["kind"] != "PLAN" or job.kind == COVERAGE_JOB_KIND]
                    coverage = {k: sum(int(r.get(k, 0)) for r in results) for k in
                                ("objects", "findings", "failed", "skipped", "skipped_archived", "skipped_submodules", "skipped_unchanged", "skipped_unsupported", "skipped_media", "roots_failed", "requests", "bytes", "reused",
                                 "partially_inspected", "inspection_gaps")}
                    # A plan's own requests (a Notion run's search walk) are the run's too.
                    coverage["requests"] += sum(_charged(t) for t in tasks if t["kind"] == "PLAN")
                    if any(r.get("inspection_gaps_overflow") for r in results):
                        coverage["inspection_gaps_overflow"] = True  # more gaps than the count says
                    coverage["failed"] = sum(int(r.get("failed", r.get("objects_failed", 0))) for r in results)
                    # One root counted the old way makes the whole sum the old way.
                    if results and all(r.get("failure_basis") == FAILURE_BASIS for r in results):
                        coverage["failure_basis"] = FAILURE_BASIS
                    # A run carries a policy only if every root scanned with the same one.
                    for key in ("detection_policy_digest", "engine_name", "engine_version"):
                        values = {r.get(key) for r in results}
                        if len(values) == 1 and None not in values:
                            coverage[key] = values.pop()
                    timing_keys = {k for r in results for k in r.get("timings", {})}
                    coverage["timings"] = {k: sum(float(r.get("timings", {}).get(k, 0)) for r in results) for k in timing_keys}
                    extraction_keys = {k for r in results for k in r.get("extraction_reasons", {})}
                    coverage["extraction_reasons"] = {
                        k: sum(int(r.get("extraction_reasons", {}).get(k, 0)) for r in results)
                        for k in extraction_keys
                    }
                    reasons = sorted({str(r["stopped_reason"]) for r in results if r.get("stopped_reason")})
                    coverage.update(tasks=len(results), source="DURABLE_ROOT_TASKS", count_basis="COMMITTED_OBJECT_ATTEMPTS",
                                    stopped_reason=",".join(reasons) if reasons else None)
                    if any(r.get("root_coverage_complete") is False for r in results):
                        coverage["root_coverage_complete"] = False
                    held = sum(int(r.get("policy_held", 0)) for r in results)
                    if held:
                        # Roots an upgrade's change run read only in part, or not at all, under the current policy
                        # (cremore.worker.runtime); policy_held_only: nothing else leaves the run partial.
                        coverage["policy_held"] = held
                        if not any(_partial_beyond_hold(r) for r in results):
                            coverage["policy_held_only"] = True
                    bases = sorted({r["coverage_basis"] for r in results if r.get("coverage_basis")})
                    if bases:
                        coverage["coverage_basis"] = bases[0] if len(bases) == 1 else "MIXED"
                    if any("metadata_items" in r for r in results):
                        coverage.update(metadata_items=sum(int(r.get("metadata_items", 0)) for r in results),
                                        coverage_run_ids=sorted({r["coverage_run_id"] for r in results if r.get("coverage_run_id")}),
                                        source_reports=[report for r in results for report in r.get("source_reports", [])],
                                        source_reports_total=sum(r.get("source_reports_total", 0) for r in results),
                                        source_reports_truncated=any(r.get("source_reports_truncated", False) for r in results),
                                        coverage_status=("FAILED" if any(r.get("coverage_status") == "FAILED" for r in results) else
                                                         "COMPLETE" if all(r.get("coverage_status") == "COMPLETE" for r in results) else "PARTIAL"),
                                        count_basis="COMMITTED_METADATA_RECORDS")
                    bound.complete_job(job.id, coverage["objects"], coverage["findings"],
                                       objects_failed=coverage["failed"], coverage=coverage)
                    if coverage.get("coverage_status") == "FAILED":
                        bound.fail_job(job.id, "METADATA_COLLECTION_FAILED")
                finalized += 1
        return finalized

    @contextmanager
    def fenced(self, task_id, token):
        """Provider I/O belongs before this bounded persistence-only context."""
        if self.engine is not None:
            with self._transaction() as conn:
                self._owned(conn, task_id, token)
                yield self._bound(conn)
                self._owned(conn, task_id, token, terminal=True)
            return
        from cremore.db.scan_store import ScanStore
        scan = ScanStore(self.repo)
        with self.repo._lock, scan.memory["lock"]:
            self._owned(None, task_id, token)
            # Development-only memory backend copies scanner state for rollback;
            # production databases keep per-object transaction cost bounded.
            stores = ("credentials", "exposures", "findings", "finding_events", "siem_events", "siem_deliveries",
                      "jobs", "connections", "check_events", "catalogs", "plans", "installation_settings",
                      "_cred_index", "_exp_index", "_finding_index")
            before = {name: deepcopy(getattr(self.repo, name)) for name in stores}
            coverage_before = deepcopy(getattr(self.repo, "coverage_memory", None))
            task_before = deepcopy(self.memory)
            scan_before = deepcopy({k: v for k, v in scan.memory.items() if k != "lock"})
            try:
                yield self.repo
                self._owned(None, task_id, token, terminal=True)
            except BaseException:
                if coverage_before is not None:
                    self.repo.coverage_memory.clear()
                    self.repo.coverage_memory.update(coverage_before)
                elif hasattr(self.repo, "coverage_memory"):
                    # CoverageStore may be created for the first time inside
                    # this transaction. Its new dictionaries must roll back too.
                    self.repo.coverage_memory.clear()
                    self.repo.coverage_memory.update({name: {} for name in ("connections", "runs", "batches", "entities", "records")})
                for name, value in before.items():
                    setattr(self.repo, name, value)
                self.memory.clear()
                self.memory.update(task_before)
                for name, value in scan_before.items():
                    scan.memory[name] = value
                raise
