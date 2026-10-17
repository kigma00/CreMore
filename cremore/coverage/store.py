"""Atomic, revision-bound coverage snapshots using the existing repository DB.

The in-memory path follows TaskStore; production uses short row-locked SQL
transactions. A run is ordered when the server starts it, never when it arrives.
"""

from __future__ import annotations

import copy
import hashlib
import secrets
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Table,
    Text,
    Uuid,
    and_,
    func,
    insert,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError

# Defined in errors.py so providers can raise it without loading SQLAlchemy;
# re-exported here because platform code imports it from this module.
from cremore.coverage.errors import CoverageError
from cremore.coverage.models import Batch, ConnectionSpec, Contract, Finish, digest, in_scope


def register_tables(metadata):
    if "coverage_connections" in metadata.tables:
        return tuple(metadata.tables[name] for name in ("coverage_connections", "coverage_runs", "coverage_batches"))
    connections = Table("coverage_connections", metadata,
        Column("id", Uuid, primary_key=True), Column("spec", JSON, nullable=False),
        Column("revision", Integer, nullable=False), Column("sequence", Integer, nullable=False),
        Column("enabled", Boolean, nullable=False), Column("token_hash", Text, nullable=False),
        Column("created_by", Text, nullable=False), Column("updated_by", Text, nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False))
    runs = Table("coverage_runs", metadata,
        Column("id", Uuid, primary_key=True),
        Column("connection_id", Uuid, ForeignKey("coverage_connections.id"), nullable=False),
        Column("revision", Integer, nullable=False), Column("sequence", Integer, nullable=False),
        Column("request_id", Text, nullable=False), Column("contract", JSON, nullable=False),
        Column("status", Text, nullable=False), Column("reasons", JSON, nullable=False),
        Column("item_count", Integer, nullable=False), Column("started_at", DateTime(timezone=True), nullable=False),
        Column("finished_at", DateTime(timezone=True)),
        # Additive, nullable: how a COMPLETE run knows it saw its whole scope.
        Column("completeness", Text))
    Index("coverage_runs_request", runs.c.connection_id, runs.c.request_id, unique=True)
    Index("coverage_runs_latest", runs.c.connection_id, runs.c.sequence, unique=True)
    batches = Table("coverage_batches", metadata,
        Column("run_id", Uuid, ForeignKey("coverage_runs.id"), primary_key=True),
        Column("index", Integer, primary_key=True), Column("digest", Text, nullable=False),
        Column("items", JSON, nullable=False))
    return connections, runs, batches


# A run must finish within this long of its start: later batches and the finish are refused.
RUN_LIFETIME = timedelta(hours=6)
def utc(value):
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def token_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


class CoverageStore:
    def __init__(self, repo):
        self.repo, self.engine = repo, getattr(repo, "engine", None)
        if self.engine is None:
            with repo._lock:
                if not hasattr(repo, "coverage_memory"):
                    repo.coverage_memory = {"connections": {}, "runs": {}, "batches": {}}
                for name in ("entities", "records"):
                    repo.coverage_memory.setdefault(name, {})
            self.memory = repo.coverage_memory
        else:
            from cremore.db.schema import metadata
            self.connections, self.runs, self.batches = register_tables(metadata)
            from cremore.coverage.metadata_store import register_tables as register_metadata_tables
            self.entities, self.records = register_metadata_tables(metadata)

    @contextmanager
    def transaction(self):
        if self.engine is None:
            with self.repo._lock:
                before = copy.deepcopy(self.memory)
                try:
                    yield None
                except BaseException:
                    self.memory.clear()
                    self.memory.update(before)
                    raise
        else:
            with self.engine.begin() as conn:
                if conn.dialect.name == "sqlite" and not getattr(self.engine, "_task_bound", False):
                    conn.exec_driver_sql("BEGIN IMMEDIATE")
                yield conn

    def _get(self, conn, name, row_id, lock=False):
        if conn is None:
            return copy.deepcopy(self.memory[name].get(row_id))
        table = getattr(self, name)
        query = select(table).where(table.c.id == row_id)
        row = conn.execute(query.with_for_update() if lock else query).mappings().first()
        return dict(row) if row else None

    def _put(self, conn, name, row, new=False):
        if conn is None:
            self.memory[name][row["id"]] = copy.deepcopy(row)
        else:
            table = getattr(self, name)
            statement = insert(table) if new else update(table).where(table.c.id == row["id"])
            conn.execute(statement.values(**row))

    def create(self, spec: ConnectionSpec, actor: str, *, connection_id=None):
        from cremore.coverage.metadata_models import MetadataConnectionSpec
        if not isinstance(spec, (ConnectionSpec, MetadataConnectionSpec)):
            raise CoverageError("INVALID_COVERAGE_SPEC")
        token = secrets.token_urlsafe(32)
        row = {"id": connection_id or uuid.uuid4(), "spec": spec.model_dump(), "revision": 1, "sequence": 0,
               "enabled": True, "token_hash": token_hash(token), "created_by": actor,
               "updated_by": actor, "updated_at": datetime.now(UTC)}
        try:
            with self.transaction() as conn:
                if self._get(conn, "connections", row["id"]):
                    raise CoverageError("CONNECTION_EXISTS")
                self._put(conn, "connections", row, new=True)
        except IntegrityError:
            raise CoverageError("CONNECTION_EXISTS") from None
        return row, token

    def change(self, cid, revision, actor, *, spec=None, enabled=None, rotate=False):
        with self.transaction() as conn:
            row = self._get(conn, "connections", cid, lock=True)
            if not row:
                raise CoverageError("CONNECTION_NOT_FOUND")
            if row["revision"] != revision:
                raise CoverageError("CONNECTION_REVISION_CONFLICT")
            token = secrets.token_urlsafe(32) if rotate else None
            if token:
                row["token_hash"] = token_hash(token)
            if spec is not None:
                if row["spec"].get("schema_version", 1) != spec.model_dump().get("schema_version", 1):
                    raise CoverageError("COVERAGE_SCHEMA_MISMATCH")
                row["spec"] = spec.model_dump()
            if enabled is not None:
                row["enabled"] = enabled
            row.update(revision=revision + 1, updated_by=actor, updated_at=datetime.now(UTC))
            self._put(conn, "connections", row)
        return row, token

    def get(self, cid):
        with self.transaction() as conn:
            return self._get(conn, "connections", cid)

    def list_connections(self):
        with self.transaction() as conn:
            if conn is None:
                return copy.deepcopy(list(self.memory["connections"].values()))
            return [dict(row) for row in conn.execute(select(self.connections).order_by(self.connections.c.updated_at)).mappings()]

    def _connection_runs(self, conn, cid, *, limit=None, request_id=None, observed=False, status=None):
        if conn is None:
            rows = [copy.deepcopy(row) for row in self.memory["runs"].values() if row["connection_id"] == cid]
            rows = [r for r in rows if request_id is None or r["request_id"] == request_id]
            rows = [r for r in rows if status is None or r["status"] == status]
            if observed:
                rows = [r for r in rows if r["status"] in ("COMPLETE", "PARTIAL") and r["item_count"]]
            return sorted(rows, key=lambda row: row["sequence"], reverse=True)[:limit]
        query = select(self.runs).where(self.runs.c.connection_id == cid).order_by(self.runs.c.sequence.desc())
        if request_id is not None:
            query = query.where(self.runs.c.request_id == request_id)
        if status is not None:
            query = query.where(self.runs.c.status == status)
        if observed:
            query = query.where(self.runs.c.status.in_(("COMPLETE", "PARTIAL")), self.runs.c.item_count > 0)
        if limit is not None:
            query = query.limit(limit)
        return [dict(row) for row in conn.execute(query).mappings()]

    def connection_runs(self, cid, *, limit=50):
        """A connection's runs, newest first, without their observation batches or contract."""
        with self.transaction() as conn:
            rows = self._connection_runs(conn, cid, limit=limit)
        return [{key: row.get(key) for key in ("id", "connection_id", "revision", "sequence", "status", "reasons",
                                               "item_count", "completeness", "started_at", "finished_at")} for row in rows]

    def latest_run(self, cid, *, status=None):
        """Read a saved run's status without loading its observation batches."""
        with self.transaction() as conn:
            rows = self._connection_runs(conn, cid, limit=1, status=status)
            return rows[0] if rows else None

    def latest_runs(self):
        """Every connection's newest finished run and newest successful one, without batches."""
        slots = {"finished": ("COMPLETE", "PARTIAL", "FAILED"), "success": ("COMPLETE", "PARTIAL")}
        result = {}
        with self.transaction() as conn:
            for slot, statuses in slots.items():
                if conn is None:
                    newest = {}
                    for run in self.memory["runs"].values():
                        cid = run["connection_id"]
                        if run["status"] in statuses and run["finished_at"] is not None and (
                                cid not in newest or run["sequence"] > newest[cid]["sequence"]):
                            newest[cid] = copy.deepcopy(run)
                else:
                    top = (select(self.runs.c.connection_id, func.max(self.runs.c.sequence).label("sequence"))
                           .where(self.runs.c.status.in_(statuses), self.runs.c.finished_at.isnot(None))
                           .group_by(self.runs.c.connection_id).subquery())
                    newest = {row["connection_id"]: dict(row) for row in conn.execute(select(self.runs).join(
                        top, and_(self.runs.c.connection_id == top.c.connection_id,
                                  self.runs.c.sequence == top.c.sequence))).mappings()}
                for cid, run in newest.items():
                    result.setdefault(cid, {"finished": None, "success": None})[slot] = run
        return result

    @staticmethod
    def authorize(owner, token):
        if not owner or not owner["enabled"] or not secrets.compare_digest(owner["token_hash"], token_hash(token)):
            raise CoverageError("COLLECTOR_UNAUTHORIZED")

    def start(self, cid, revision, request_id, contract, *, token=None):
        request_id = str(uuid.UUID(str(request_id)))
        with self.transaction() as conn:
            owner = self._get(conn, "connections", cid, lock=True)
            if token is not None:
                self._machine(owner, token)
            if not owner or not owner["enabled"]:
                raise CoverageError("CONNECTION_DISABLED_OR_MISSING")
            if owner["revision"] != revision:
                raise CoverageError("CONNECTION_REVISION_CONFLICT")
            version = owner["spec"].get("schema_version", 1)
            if contract.get("schema_version", 1) != version:
                raise CoverageError("COVERAGE_SCHEMA_MISMATCH")
            if version == 2:
                from cremore.coverage.metadata_models import (
                    MetadataConnectionSpec,
                    MetadataContract,
                    metadata_contract,
                )
                spec = MetadataConnectionSpec.model_validate(owner["spec"])
                checked = MetadataContract.model_validate(contract)
                if checked.scope_digest != digest(spec.model_dump()):
                    raise CoverageError("CONNECTION_SCOPE_CONTRACT_MISMATCH")
                if spec.principal_pin and (not checked.principal_verified or checked.principal_id != spec.principal_pin):
                    raise CoverageError("COLLECTOR_PRINCIPAL_MISMATCH")
                expected = metadata_contract(spec, principal_id=checked.principal_id, principal_verified=checked.principal_verified)
                if checked.spec_snapshot is not None and checked.spec_snapshot != expected.spec_snapshot:
                    raise CoverageError("CONNECTION_SCOPE_CONTRACT_MISMATCH")
                contract = expected.model_dump()
            else:
                Contract.model_validate(contract)
            previous = next(iter(self._connection_runs(conn, cid, request_id=request_id)), None)
            if previous:
                if previous["contract"] != contract or previous["revision"] != revision:
                    raise CoverageError("RUN_REPLAY_CONFLICT")
                return previous
            latest = self._connection_runs(conn, cid, limit=1)
            if latest and latest[0]["revision"] == revision and latest[0]["status"] == "RUNNING" and utc(latest[0]["started_at"]) + RUN_LIFETIME > datetime.now(UTC):
                raise CoverageError("COLLECTION_ALREADY_RUNNING")
            owner["sequence"] += 1
            self._put(conn, "connections", owner)
            row = {"id": uuid.uuid4(), "connection_id": cid, "revision": revision,
                   "sequence": owner["sequence"], "request_id": request_id, "contract": contract,
                   "status": "RUNNING", "reasons": [], "item_count": 0,
                   "started_at": datetime.now(UTC), "finished_at": None, "completeness": None}
            self._put(conn, "runs", row, new=True)
            return row

    def _machine(self, owner, token):
        """A collector token's call: the connection's own token, and never for an identity collection, whose
        records a token cannot send and whose run, started or closed by one, would become the latest."""
        self.authorize(owner, token)
        if "identity_status" in ((owner or {}).get("spec") or {}).get("capabilities", ()):
            raise CoverageError("IDENTITY_COLLECTION_IS_WORKER_ONLY")

    def _owned(self, conn, cid, rid, token=None):
        # Lock ordering is always connection then run, including scope changes.
        owner = self._get(conn, "connections", cid, lock=True)
        if token is not None:
            self._machine(owner, token)
        run = self._get(conn, "runs", rid, lock=True)
        if not owner or not run or run["connection_id"] != cid:
            raise CoverageError("RUN_NOT_FOUND")
        if not owner["enabled"] or owner["revision"] != run["revision"]:
            raise CoverageError("RUN_SCOPE_REVOKED")
        return owner, run

    def _batches(self, conn, rid, limit=None):
        if conn is None:
            return sorted((copy.deepcopy(row) for (key, _), row in self.memory["batches"].items()
                           if key == rid), key=lambda row: row["index"])[:limit]
        return [dict(row) for row in conn.execute(select(self.batches).where(self.batches.c.run_id == rid)
                                                  .order_by(self.batches.c.index).limit(limit)).mappings()]

    def append(self, cid, rid, batch: Batch, *, token=None, trusted_discovery=False):
        items = [item.model_dump() for item in batch.items]
        if token is not None and any(token in str(item) for item in items):
            raise CoverageError("UNSAFE_METADATA")
        checksum = digest(items)
        with self.transaction() as conn:
            owner, run = self._owned(conn, cid, rid, token)
            version = run["contract"].get("schema_version", 1)
            if batch.model_dump().get("schema_version", 1) != version:
                raise CoverageError("COVERAGE_SCHEMA_MISMATCH")
            if token is not None and trusted_discovery:
                raise CoverageError("MACHINE_DISCOVERY_NOT_ALLOWED")
            if conn is None:
                previous = self.memory["batches"].get((rid, batch.index))
            else:
                previous = conn.execute(select(self.batches).where(self.batches.c.run_id == rid,
                                        self.batches.c.index == batch.index)).mappings().first()
            if previous:
                if previous["digest"] != checksum:
                    raise CoverageError("BATCH_REPLAY_CONFLICT")
                return
            if run["status"] != "RUNNING" or utc(run["started_at"]) + RUN_LIFETIME < datetime.now(UTC):
                raise CoverageError("RUN_CLOSED_OR_EXPIRED")
            if version == 2:
                from cremore.coverage.metadata_models import (
                    MetadataConnectionSpec,
                    in_metadata_scope,
                )
                from cremore.coverage.providers import validate_record
                spec = MetadataConnectionSpec.model_validate(owner["spec"])
                if any(not in_metadata_scope(spec, item) or not validate_record(spec, item, trusted_discovery=trusted_discovery) for item in batch.items):
                    raise CoverageError("METADATA_OUTSIDE_APPROVED_SCOPE")
            else:
                spec = ConnectionSpec.model_validate(owner["spec"])
                if any(not in_scope(spec, item) for item in batch.items):
                    raise CoverageError("OBSERVATION_OUTSIDE_SCOPE")
            if run["item_count"] + len(items) > spec.max_records:
                raise CoverageError("RUN_ITEM_LIMIT")
            run["item_count"] += len(items)
            self._put(conn, "runs", run)
            row = {"run_id": rid, "index": batch.index, "digest": checksum, "items": items}
            if conn is None:
                self.memory["batches"][(rid, batch.index)] = copy.deepcopy(row)
            else:
                conn.execute(insert(self.batches).values(**row))
            if version == 2:
                from cremore.coverage.metadata_store import project_batch
                project_batch(self, conn, run, batch)

    def finish(self, cid, rid, outcome: Finish, *, token=None):
        with self.transaction() as conn:
            owner, run = self._owned(conn, cid, rid, token)
            version = run["contract"].get("schema_version", 1)
            if outcome.model_dump().get("schema_version", 1) != version:
                raise CoverageError("COVERAGE_SCHEMA_MISMATCH")
            batches = self._batches(conn, rid)
            items = [item for batch in batches for item in batch["items"]]
            if [batch["index"] for batch in batches] != list(range(outcome.batch_count)) or len(items) != outcome.item_count:
                raise CoverageError("INCOMPLETE_SUBMISSION")
            reasons = sorted(set(outcome.reasons))
            if version == 2:
                reports = [item for item in items if item["record_type"] == "operation_report"]
                if not reports:
                    reasons = sorted(set(reasons) | {"SOURCE_COVERAGE_NOT_REPORTED"})
                # A source may emit intermediate page reports. Its terminal
                # report must be explicit; failed/unknown sources never become
                # an empty complete result.
                terminal = {}
                for item in reports:
                    key = (item["provenance"]["operation"], digest(item["scope"]), item["provenance"]["resource_id"])
                    terminal[key] = item
                if any(item["status"] not in ("COMPLETE", "NOT_REQUESTED") for item in terminal.values()):
                    reasons = sorted(set(reasons) | {"SOURCE_COLLECTION_INCOMPLETE"})
                if any(item.get("value_match", {}).get("evidence") == "UNRESOLVED" for item in items if item.get("value_match")):
                    reasons = sorted(set(reasons) | {"UNRESOLVED_ITEMS"})
            else:
                if any(item["evidence"] == "UNRESOLVED" for item in items):
                    reasons = sorted(set(reasons) | {"UNRESOLVED_ITEMS"})
                operation_items = [item for item in items if item["evidence"] == "OPERATION"]
                operations = [item["operation"] for item in operation_items]
                if len({(item["operation"]["name"], item["reference"], item["region"]) for item in operation_items}) != len(operations):
                    raise CoverageError("DUPLICATE_OPERATION_REPORT")
                if any(op["status"] in ("PARTIAL", "FAILED") for op in operations):
                    reasons = sorted(set(reasons) | {"SOURCE_COLLECTION_INCOMPLETE"})
            status = "PARTIAL" if outcome.status == "COMPLETE" and reasons else outcome.status
            # An explicit AWS secret list is complete only for the operator's named references.
            named = version == 1 and bool(owner["spec"].get("references"))
            completeness = (("OPERATOR_DECLARED" if named else "API_LISTING")
                            if status == "COMPLETE" else None)
            if run["status"] != "RUNNING":
                if ((run["status"], run["reasons"], run["item_count"], run.get("completeness"))
                        != (status, reasons, len(items), completeness)):
                    raise CoverageError("RUN_REPLAY_CONFLICT")
                return run
            if utc(run["started_at"]) + RUN_LIFETIME < datetime.now(UTC):
                raise CoverageError("RUN_EXPIRED")
            run.update(status=status, reasons=reasons, item_count=len(items), finished_at=datetime.now(UTC),
                       completeness=completeness)
            self._put(conn, "runs", run)
            if version == 2:
                from cremore.coverage.metadata_store import finish_projection
                finish_projection(self, conn, run)
            return run

    def snapshots(self, cid, limit=2, *, max_items=None):
        with self.transaction() as conn:
            rows = self._connection_runs(conn, cid, limit=limit)
            # Keep the last observed evidence through any number of failed or
            # empty collections. It is history, never proof of current storage.
            if limit > 1:
                for previous in self._connection_runs(conn, cid, limit=1, observed=True):
                    if all(row["id"] != previous["id"] for row in rows):
                        rows.append(previous)
                # Repeated partial runs can otherwise displace the last complete
                # baseline. Keep its facts as history, never as current absence.
                for previous in self._connection_runs(conn, cid, limit=1, status="COMPLETE"):
                    if all(row["id"] != previous["id"] for row in rows):
                        rows.append(previous)
            for row in rows:
                row["items"] = ([] if row["status"] == "RUNNING" else
                                [item for batch in self._batches(conn, row["id"], max_items) for item in batch["items"]][:max_items])
                row["truncated"] = row["status"] != "RUNNING" and len(row["items"]) < row["item_count"]
                if max_items is not None:
                    max_items -= len(row["items"])
            return rows

    def abort(self, cid, rid, reason):
        """Internal worker failure: close the run even after its scope was revoked."""
        with self.transaction() as conn:
            self._get(conn, "connections", cid, lock=True)
            row = self._get(conn, "runs", rid, lock=True)
            if row and row["connection_id"] == cid and row["status"] == "RUNNING":
                row.update(status="FAILED", reasons=[reason], finished_at=datetime.now(UTC))
                self._put(conn, "runs", row)
