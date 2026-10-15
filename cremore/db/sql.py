"""SQLAlchemy-backed repository (sync).

Implements the same :class:`Repository` protocol as the in-memory store.
Scan identities use native PostgreSQL/SQLite conflict handling. Observation
rollups and check finalization own their short transactions; leased scan tasks
can bind those operations to one transaction that rejects stale owners.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from collections.abc import Callable
from types import SimpleNamespace

from sqlalchemy import (
    Engine,
    String,
    and_,
    bindparam,
    case,
    cast,
    create_engine,
    delete,
    exists,
    func,
    insert,
    inspect,
    or_,
    select,
    text,
    tuple_,
    update,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Connection as SAConnection
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool

from cremore.db import audit_chain
from cremore.db.migrations import (
    audit_chain_index,
    audit_targets,
    credential_lookup_index,
    ensure_scan_slot,
    identity_ready,
    metadata_coverage,
    orphan_tickets,
    removed_ticket_system,
    schedule_origin,
    siem_event_kinds,
    siem_owed_index,
    startup_migrations,
)
from cremore.db.repository import job_lane, receipt_reopens
from cremore.db.scan_state import (
    INSTANCE_SOURCES,
    LOCATION_FIELDS,
    SEVERITY_RANK,
    exposure_container_key,
    exposure_identity,
    exposure_resource_key,
    observation_metadata,
    rollup_changes,
)
from cremore.db.schema import (
    action_plans,
    aws_accounts,
    connection_check_events,
    connections,
    credentials,
    custom_rules,
    exposures,
    finding_events,
    findings,
    fp_profiles,
    fp_samples,
    governance_reviews,
    installation_settings,
    management_actions,
    metadata,
    ownership_reviews,
    rotation_jobs,
    scan_jobs,
    scope_catalogs,
    scope_plans,
    scope_profiles,
    selection_drafts,
    siem_events,
    trigger_receipts,
    workflow_tickets,
)
from cremore.domain.models import (
    ACTION_PLAN_UNRESOLVED,
    ACTIVE_JOB_STATUSES,
    CONTENT_SCAN_KINDS,
    ActionPlan,
    AwsAccount,
    Connection,
    ConnectionCheckEvent,
    Credential,
    CustomRule,
    Exposure,
    Finding,
    FindingEvent,
    FPProfile,
    FPSample,
    GovernanceReview,
    JobStatus,
    ManagementAction,
    OwnershipReview,
    RotationJob,
    ScanJob,
    ScopeCatalog,
    ScopePlan,
    ScopeProfile,
    SelectionDraft,
    WorkflowTicket,
)
from cremore.siem.events import (
    audit_action,
    export_audit,
    finding_created,
    finding_exposure,
    finding_updated,
    stamped,
)

INSTALLATION_KEY = "siem.installation"


def _stamp_marker(value) -> str:
    """The change time a finding.updated event_id is derived from."""
    return value.isoformat() if value is not None else ""


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def make_engine(url: str) -> Engine:
    # An in-memory SQLite database is per-connection; share one connection across
    # threads (StaticPool) so the same schema is visible to the API threadpool.
    if url.startswith("sqlite") and ":memory:" in url:
        return create_engine(
            url, future=True, poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
    if url.startswith("sqlite"):
        # A worker's control loop and its task runner are separate writers on one file: a write waits up to
        # 30 s for the other's commit, where pysqlite's 5 s could fail a lease renewal under a long write.
        return create_engine(url, future=True, pool_pre_ping=True, connect_args={"timeout": 30})
    return create_engine(url, future=True, pool_pre_ping=True)


_SCHEMA_LOCK_KEY = 0x6372655f736368  # "cre_sch": one schema writer at a time
# With the schema's hash: one audit sealer at a time per schema, not per database server.
_AUDIT_SEAL_LOCK = 0x617564  # "aud"

# A stop request wins over any later completion or failure of the same job.
_STOPPED = (JobStatus.CANCELLING.value, JobStatus.CANCELLED.value)
_REDACTION_VERSION = 4


def create_all(engine: Engine) -> None:
    """Expand the schema under one PostgreSQL advisory-lock transaction.

    ``cremore/db/schema.py`` is the schema of record. Additive changes (a new
    nullable column) are applied in place. Populated legacy databases remain
    read-accessible, but scan writes require the explicit offline identity
    migration; startup never consolidates exposure evidence automatically.
    """

    if engine.dialect.name != "postgresql":
        metadata.create_all(engine)
        _ensure_columns(engine)
        _migrate_legacy_redactions(engine)
        with engine.begin() as conn:
            startup_migrations(conn)
            ensure_scan_slot(conn)
            credential_lookup_index(conn)
            metadata_coverage(conn)
            siem_event_kinds(conn)
            orphan_tickets(conn)
            audit_chain_index(conn)
            siem_owed_index(conn)
            schedule_origin(conn)
            removed_ticket_system(conn)
        return
    # The API and worker may start together. One transaction-scoped lock and
    # one connection serialize all DDL and release automatically on rollback.
    with engine.begin() as conn:
        conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _SCHEMA_LOCK_KEY})
        metadata.create_all(conn)
        # Runs before the column reconciliation, which refuses to invent a
        # NOT NULL column on an existing table -- correctly, because that is
        # what an explicit migration is for.
        audit_targets(conn)
        siem_event_kinds(conn)
        orphan_tickets(conn)
        _ensure_columns(conn)
        _migrate_legacy_redactions(conn)
        startup_migrations(conn)
        ensure_scan_slot(conn)
        credential_lookup_index(conn)
        metadata_coverage(conn)
        audit_chain_index(conn)
        siem_owed_index(conn)
        schedule_origin(conn)
        removed_ticket_system(conn)


def _ensure_columns(bind: Engine | SAConnection) -> None:
    inspector = inspect(bind)
    for table in metadata.sorted_tables:
        existing = {c["name"] for c in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing:
                continue
            if not column.nullable or column.primary_key:
                raise RuntimeError(
                    f"{table.name}.{column.name} is missing and not nullable; "
                    "it needs an explicit migration"
                )
            ddl = (f"ALTER TABLE {table.name} ADD COLUMN {column.name} "
                   f"{column.type.compile(dialect=bind.dialect)}")
            if isinstance(bind, SAConnection):
                bind.execute(text(ddl))
            else:
                with bind.begin() as conn:
                    conn.execute(text(ddl))


def _migrate_legacy_redactions(bind: Engine | SAConnection) -> None:
    statement = (
        update(exposures)
        .where(exposures.c.redaction_version.is_(None))
        .values(redacted_line=None, redaction_version=_REDACTION_VERSION)
    )
    if isinstance(bind, SAConnection):
        bind.execute(statement)
    else:
        with bind.begin() as conn:
            conn.execute(statement)


class SqlRepository:
    # Set by the API and worker from FINGERPRINT_KEY (cremore/db/audit_chain.py); None writes unauthenticated rows.
    audit_key: bytes | None = None

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self._scan_schema_ready = False

    def _require_scan_schema(self, conn) -> None:
        if not self._scan_schema_ready:
            if not identity_ready(conn):
                raise RuntimeError("OFFLINE_SCAN_MIGRATION_REQUIRED")
            self._scan_schema_ready = True

    @staticmethod
    def _insert(conn, table):
        if conn.dialect.name == "postgresql":
            return pg_insert(table)
        if conn.dialect.name == "sqlite":
            return sqlite_insert(table)
        raise RuntimeError("scan persistence requires PostgreSQL or SQLite")

    @staticmethod
    def _lock_credential(conn, credential_id) -> None:
        if conn.dialect.name == "sqlite":
            conn.execute(update(credentials).where(credentials.c.id == credential_id).values(updated_at=credentials.c.updated_at))
        else:
            conn.execute(select(credentials.c.id).where(credentials.c.id == credential_id).with_for_update()).first()

    # --- credentials --------------------------------------------------------

    def upsert_credential(self, credential: Credential) -> Credential:
        with self.engine.begin() as conn:
            self._require_scan_schema(conn)
            reported = credential.credential_status if credential.credential_status not in (None, "", "UNKNOWN") else None
            before = None
            if reported:
                # Only a verification result can change the status; read it first
                # so the change becomes a finding.updated in this transaction.
                query = select(credentials.c.id, credentials.c.credential_status).where(
                    credentials.c.fingerprint == credential.fingerprint,
                    credentials.c.credential_type == credential.credential_type)
                before = conn.execute(query if conn.dialect.name == "sqlite" else query.with_for_update()).mappings().first()
            now = _now()
            values = _insertable(credential)
            values.update(id=uuid.uuid4(), created_at=now, updated_at=now)
            updates = {field: getattr(credential, field) for field in (
                "provider", "identifier", "identifier_hint", "principal_arn", "principal_name",
                "business_owner", "team", "service_name") if getattr(credential, field)}
            if credential.credential_status and credential.credential_status != "UNKNOWN":
                updates["credential_status"] = credential.credential_status
            updates["updated_at"] = now
            statement = self._insert(conn, credentials).values(**values).on_conflict_do_update(
                index_elements=[credentials.c.fingerprint, credentials.c.credential_type], set_=updates)
            row = conn.execute(statement.returning(credentials)).mappings().one()
            saved = _to(Credential, row)
            if before is not None and before["credential_status"] != saved.credential_status:
                self._record_verification_change(conn, saved, before["credential_status"])
            return saved

    def _record_verification_change(self, conn, credential, previous_status):
        row = conn.execute(select(findings).where(findings.c.credential_id == credential.id)).mappings().first()
        if row is not None:
            finding = _to(Finding, row)
            self._queue_siem(conn, finding_updated(finding, credential, change="VERIFICATION",
                previous_credential_status=previous_status, marker=f"{_stamp_marker(credential.updated_at)}:{previous_status}>{credential.credential_status}"))

    def _installation_id(self, conn) -> str:
        """This installation's random id, created once by whichever writer comes first."""
        cached = getattr(self, "_installation_cache", None)
        if cached:
            return cached
        query = select(installation_settings.c.value).where(installation_settings.c.key == INSTALLATION_KEY)
        value = conn.execute(query).scalar_one_or_none()
        if not value:
            conn.execute(self._insert(conn, installation_settings).values(
                key=INSTALLATION_KEY, value={"id": str(uuid.uuid4())}, updated_by="system",
                updated_at=_now()).on_conflict_do_nothing(index_elements=[installation_settings.c.key]))
            value = conn.execute(query).scalar_one()
        self._installation_cache = value["id"]
        return self._installation_cache

    def installation_id(self) -> str:
        with self.engine.begin() as conn:
            return self._installation_id(conn)

    def _queue_siem(self, conn, event) -> bool:
        # finding_id stays the unique link of a finding's one finding.created
        # event; every later event names the finding inside its payload.
        event = stamped(event, self._installation_id(conn))
        # RETURNING, not rowcount: psycopg reports -1 for ON CONFLICT inserts.
        return conn.execute(self._insert(conn, siem_events).values(
            event_id=uuid.UUID(event["event_id"]), finding_id=None,
            occurred_at=_dt.datetime.fromisoformat(event["occurred_at"]), payload=event,
        ).on_conflict_do_nothing(index_elements=[siem_events.c.event_id]).returning(
            siem_events.c.event_id)).scalar_one_or_none() is not None

    def get_credential(self, credential_id: uuid.UUID) -> Credential | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(credentials).where(credentials.c.id == credential_id)).mappings().first()
            return _to(Credential, dict(row)) if row else None

    def get_credential_by_fingerprint(self, fingerprint: str, credential_type: str) -> Credential | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(credentials).where(credentials.c.fingerprint == fingerprint,
                credentials.c.credential_type == credential_type)).mappings().first()
            return _to(Credential, dict(row)) if row else None

    def find_component_pairs(self, credential_type: str, fingerprint: str, limit: int) -> list[Exposure]:
        field = {"AWS_ACCESS_KEY_ID": "aws_id_component_fingerprint",
                 "AWS_SECRET_ACCESS_KEY": "aws_secret_component_fingerprint"}[credential_type]
        statement = select(exposures).join(credentials, credentials.c.id == exposures.c.credential_id).join(
            findings, findings.c.credential_id == credentials.c.id).where(
                credentials.c.provider == "aws", credentials.c.credential_type == "AWS_ACCESS_KEY",
                findings.c.workflow_status != "FALSE_POSITIVE", exposures.c.status != "FALSE_POSITIVE",
                exposures.c.metadata[field].as_string() == fingerprint,
            ).order_by(exposures.c.last_seen_at.desc(), exposures.c.id.desc()).limit(limit)
        with self.engine.connect() as conn:
            return [_to(Exposure, dict(row)) for row in conn.execute(statement).mappings()]

    def update_credential(self, credential_id: uuid.UUID, **changes) -> Credential | None:
        if "credential_status" not in changes:
            return self._crud_update(credentials, Credential, credential_id, changes)
        with self.engine.begin() as conn:
            query = select(credentials).where(credentials.c.id == credential_id)
            before = conn.execute(query if conn.dialect.name == "sqlite" else query.with_for_update()).mappings().first()
            if before is None:
                return None
            conn.execute(update(credentials).where(credentials.c.id == credential_id).values(**changes, updated_at=_now()))
            saved = _to(Credential, conn.execute(query).mappings().one())
            if before["credential_status"] != saved.credential_status:
                self._record_verification_change(conn, saved, before["credential_status"])
            return saved

    # --- exposures ----------------------------------------------------------

    def upsert_exposure(self, exposure: Exposure) -> Exposure:
        with self.engine.begin() as conn:
            self._require_scan_schema(conn)
            self._lock_credential(conn, exposure.credential_id)
            key = exposure_identity(exposure)
            row = conn.execute(select(exposures).where(exposures.c.identity_key == key)).mappings().first()
            now = _now()
            values = _insertable(exposure)
            values.update(
                id=uuid.uuid4(), identity_key=key, resource_key=exposure_resource_key(exposure),
                container_key=exposure_container_key(exposure),
                first_seen_at=now,
                last_seen_at=now,
                redaction_version=_REDACTION_VERSION,
            )
            updates = {
                "last_seen_at": now,
                "resource_key": exposure_resource_key(exposure),
                "severity": exposures.c.severity if exposure.severity == "UNKNOWN" else exposure.severity,
                "redacted_line": exposure.redacted_line or case(
                    (exposures.c.redaction_version == _REDACTION_VERSION, exposures.c.redacted_line), else_=None),
                "redaction_version": _REDACTION_VERSION,
                "line_number": exposure.line_number if exposure.line_number is not None else exposures.c.line_number,
                "last_scan_id": exposure.last_scan_id or exposures.c.last_scan_id,
                "last_source_scan_id": exposure.last_source_scan_id or exposures.c.last_source_scan_id,
                "metadata": observation_metadata(dict(row["metadata"]) if row else {}, exposure.metadata),
                "status": case((exposures.c.status == "REMOVED", "OPEN"), else_=exposures.c.status),
                "removed_at": case((exposures.c.status == "REMOVED", None), else_=exposures.c.removed_at),
            }
            updates["container_key"] = exposure_container_key({**values, "metadata": updates["metadata"]})
            statement = self._insert(conn, exposures).values(**values).on_conflict_do_update(
                index_elements=[exposures.c.identity_key], set_=updates)
            saved = _to(Exposure, conn.execute(statement.returning(exposures)).mappings().one())
            if row is None or row["status"] == "REMOVED":
                finding_row = conn.execute(select(findings).where(findings.c.credential_id == saved.credential_id)).mappings().first()
                if finding_row is not None:
                    credential_row = conn.execute(select(credentials).where(credentials.c.id == saved.credential_id)).mappings().one()
                    self._queue_siem(conn, finding_exposure(_to(Finding, finding_row), _to(Credential, credential_row), saved,
                        reappeared=row is not None, removed_at=row["removed_at"] if row else None))
            return saved

    def count_exposures_for_credential(self, credential_id: uuid.UUID) -> int:
        with self.engine.connect() as conn:
            instance = case((exposures.c.source_type.in_(INSTANCE_SOURCES),
                func.coalesce(exposures.c.metadata["source_instance"].as_string(), "")), else_="")
            locations = select(*(exposures.c[k] for k in LOCATION_FIELDS), instance).where(
                exposures.c.credential_id == credential_id).distinct().subquery()
            return conn.execute(select(func.count()).select_from(locations)).scalar_one()

    @staticmethod
    def _best_exposure(conn, credential_id, preferred_id=None) -> tuple:
        rank = case(SEVERITY_RANK, value=exposures.c.severity, else_=-1)
        preferred = case((exposures.c.id == preferred_id, 0), else_=1)
        row = conn.execute(select(exposures.c.severity, exposures.c.id).where(
            exposures.c.credential_id == credential_id, exposures.c.status != "REMOVED"
        ).order_by(rank.desc(), preferred, exposures.c.id).limit(1)).first()
        return tuple(row) if row else ("UNKNOWN", None)

    def best_exposure_for_credential(self, credential_id: uuid.UUID,
                                     preferred_id: uuid.UUID | None = None) -> tuple[str, uuid.UUID | None]:
        with self.engine.connect() as conn:
            return self._best_exposure(conn, credential_id, preferred_id)

    def exposures_for_credential(self, credential_id: uuid.UUID) -> list[Exposure]:
        with self.engine.connect() as conn:
            rows = conn.execute(select(exposures).where(exposures.c.credential_id == credential_id)).mappings().all()
            return [_to(Exposure, dict(r)) for r in rows]

    def exposures_for_connection(self, connection_id: uuid.UUID) -> list[Exposure]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(exposures).where(exposures.c.source_connection_id == connection_id)
            ).mappings().all()
            return [_to(Exposure, dict(r)) for r in rows]

    def findings_with_exposures(self, finding_ids, *, exposure_limit=None):
        """(finding, its credential, the credential's exposures) per existing id, in the given order.

        Three queries for any number of findings, instead of get_finding, get_credential and
        exposures_for_credential per finding (second review 2026-09-26: 1,000 SAS findings took
        about 11 s per ARM collection). Exposure order within a credential is unspecified, as in
        exposures_for_credential. An optional limit bounds the aggregate exposure query before
        model allocation; a capped caller must not treat omitted exposures as absent."""
        ids = list(dict.fromkeys(finding_ids))
        if not ids:
            return []
        with self.engine.connect() as conn:
            found = {r["id"]: _to(Finding, dict(r)) for r in conn.execute(
                select(findings).where(findings.c.id.in_(ids))).mappings()}
            owners = {f.credential_id for f in found.values()}
            creds = {r["id"]: _to(Credential, dict(r)) for r in conn.execute(
                select(credentials).where(credentials.c.id.in_(owners))).mappings()} if owners else {}
            grouped = {}
            if owners:
                query = select(exposures).where(exposures.c.credential_id.in_(owners))
                if exposure_limit is not None:
                    query = query.order_by(exposures.c.id).limit(max(0, exposure_limit))
                for r in conn.execute(query).mappings():
                    grouped.setdefault(r["credential_id"], []).append(_to(Exposure, dict(r)))
        return [(found[i], creds.get(found[i].credential_id), grouped.get(found[i].credential_id, []))
                for i in ids if i in found]

    def exposures_for_resource(self, connection_id: uuid.UUID, source_type: str, resource_name: str,
                               location: str, *, page_id: str | None = None, epoch: str | int | None = None) -> list[Exposure]:
        key = exposure_resource_key({"source_connection_id": connection_id, "source_type": source_type,
                                     "resource_name": resource_name, "location": location})
        query = select(exposures).where(exposures.c.resource_key == key, exposures.c.source_connection_id == connection_id,
            exposures.c.source_type == source_type, exposures.c.resource_name == resource_name,
            exposures.c.location == location)
        if page_id is not None:
            query = query.where(exposures.c.metadata["page_id"].as_string() == page_id)
        if epoch is not None:
            query = query.where(cast(exposures.c.metadata["collector_epoch"].as_string(), String) == str(epoch))
        with self.engine.connect() as conn:
            return [_to(Exposure, row) for row in conn.execute(query).mappings()]

    def exposures_for_root(self, connection_id: uuid.UUID, source_type: str, resource_name: str,
                           *, page_id: str | None = None) -> list[Exposure]:
        query = select(exposures).where(exposures.c.source_connection_id == connection_id,
                                        exposures.c.source_type == source_type)
        if source_type == "notion" and not page_id:
            # Compatibility lookup for legacy observations without a page ID.
            query = query.where(exposures.c.resource_name == resource_name)
        else:
            key = exposure_container_key({"source_connection_id": connection_id, "source_type": source_type,
                "resource_name": resource_name, "metadata": {"page_id": page_id}})
            query = query.where(exposures.c.container_key == key)
            if source_type == "notion":
                query = query.where(func.lower(func.replace(exposures.c.metadata["page_id"].as_string(), "-", ""))
                                    == str(page_id).replace("-", "").lower())
            else:
                query = query.where(exposures.c.resource_name == resource_name)
        with self.engine.connect() as conn:
            return [_to(Exposure, row) for row in conn.execute(query).mappings()]

    def mark_exposure_removed(self, exposure_id: uuid.UUID) -> None:
        with self.engine.begin() as conn:
            credential_id = conn.execute(select(exposures.c.credential_id).where(exposures.c.id == exposure_id)).scalar_one_or_none()
            if credential_id is not None:
                self._lock_credential(conn, credential_id)
            conn.execute(
                update(exposures)
                .where(exposures.c.id == exposure_id, exposures.c.status != "REMOVED")
                .values(status="REMOVED", removed_at=_now())
            )

    def mark_exposure_seen(self, exposure_id: uuid.UUID) -> None:
        with self.engine.begin() as conn:
            credential_id = conn.execute(select(exposures.c.credential_id).where(exposures.c.id == exposure_id)).scalar_one_or_none()
            if credential_id is not None:
                self._lock_credential(conn, credential_id)
            conn.execute(update(exposures).where(exposures.c.id == exposure_id, exposures.c.status != "REMOVED")
                         .values(last_seen_at=_now()))

    def set_exposure_severity(self, exposure_id: uuid.UUID, severity: str, *, metadata: dict | None = None) -> None:
        with self.engine.begin() as conn:
            credential_id = conn.execute(select(exposures.c.credential_id).where(exposures.c.id == exposure_id)).scalar_one_or_none()
            if credential_id is not None:
                self._lock_credential(conn, credential_id)
            changes = {"severity": severity}
            if metadata is not None:
                previous = conn.execute(select(exposures).where(exposures.c.id == exposure_id)).mappings().first()
                changes["metadata"] = observation_metadata(previous["metadata"] if previous else {}, metadata)
                if previous:
                    changes["container_key"] = exposure_container_key({**previous, "metadata": changes["metadata"]})
            conn.execute(update(exposures).where(exposures.c.id == exposure_id).values(**changes))

    # --- findings -----------------------------------------------------------

    def _record_siem_finding_created(self, conn, finding):
        credential = conn.execute(select(credentials.c.provider, credentials.c.credential_type,
            credentials.c.credential_status).where(credentials.c.id == finding.credential_id)).mappings().first()
        exposure = conn.execute(select(exposures.c.source_type, exposures.c.source_connection_id,
            exposures.c.aws_account_id, exposures.c.line_number).where(
                exposures.c.id == finding.primary_exposure_id,
                exposures.c.credential_id == finding.credential_id)).mappings().first()
        event = finding_created(finding, SimpleNamespace(**credential) if credential else None,
                                SimpleNamespace(**exposure) if exposure else None)
        event = stamped(event, self._installation_id(conn))
        conn.execute(insert(siem_events).values(event_id=uuid.UUID(event["event_id"]),
            finding_id=finding.id, occurred_at=finding.created_at, payload=event))

    def upsert_finding(self, credential_id: uuid.UUID, primary_exposure_id: uuid.UUID, severity: str) -> Finding:
        with self.engine.begin() as conn:
            self._require_scan_schema(conn)
            self._lock_credential(conn, credential_id)
            now = _now()
            values = {"id": uuid.uuid4(), "credential_id": credential_id, "primary_exposure_id": primary_exposure_id,
                      "severity": severity, "workflow_status": "OPEN", "created_at": now, "updated_at": now}
            statement = self._insert(conn, findings).values(**values).on_conflict_do_update(
                index_elements=[findings.c.credential_id], set_={"severity": severity,
                    "primary_exposure_id": primary_exposure_id, "updated_at": now})
            finding = _to(Finding, conn.execute(statement.returning(findings)).mappings().one())
            if finding.id == values["id"]:
                self._record_siem_finding_created(conn, finding)
            return finding

    def get_finding_for_credential(self, credential_id: uuid.UUID) -> Finding | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(findings).where(findings.c.credential_id == credential_id)).mappings().first()
            return _to(Finding, row) if row else None

    def repair_finding_rollup(self, credential_id: uuid.UUID) -> Finding | None:
        with self.engine.begin() as conn:
            self._require_scan_schema(conn)
            self._lock_credential(conn, credential_id)
            row = conn.execute(select(findings).where(findings.c.credential_id == credential_id).with_for_update()).mappings().first()
            best = self._best_exposure(conn, credential_id, row["primary_exposure_id"] if row else None)
            if row is None:
                if best[1] is None:
                    return None
                now = _now()
                row = conn.execute(insert(findings).values(id=uuid.uuid4(), credential_id=credential_id,
                    primary_exposure_id=best[1], severity=best[0], workflow_status="OPEN",
                    created_at=now, updated_at=now).returning(findings)).mappings().one()
                self._record_siem_finding_created(conn, _to(Finding, row))
            finding = _to(Finding, row)
            unknown = conn.execute(select(exposures.c.id).where(exposures.c.credential_id == credential_id,
                exposures.c.status != "REMOVED", exposures.c.severity.not_in(SEVERITY_RANK)).limit(1)).first() is not None
            changes = rollup_changes(finding, best, active=best[1] is not None, unknown=unknown)
            if not changes:
                return finding
            changes["updated_at"] = _now()
            conn.execute(update(findings).where(findings.c.id == finding.id).values(**changes))
            self._record_event(conn, FindingEvent(finding_id=finding.id,
                actor="scanner", event_type="ROLLUP_UPDATED", from_status=finding.workflow_status,
                to_status=changes.get("workflow_status", finding.workflow_status),
                note="LOCATIONS_REMOVED_KEY_RETIREMENT_UNCONFIRMED" if changes.get("all_locations_removed", finding.all_locations_removed)
                     else "EXPOSURE_ROLLUP_REPAIRED"))
            updated = _to(Finding, {**dict(row), **changes})
            if (updated.workflow_status, updated.severity) != (finding.workflow_status, finding.severity):
                credential = conn.execute(select(credentials).where(credentials.c.id == credential_id)).mappings().first()
                self._queue_siem(conn, finding_updated(updated, _to(Credential, credential) if credential else None,
                    change="ROLLUP", previous_workflow_status=finding.workflow_status,
                    previous_severity=finding.severity, marker=f"{_stamp_marker(updated.updated_at)}:{finding.workflow_status}>{updated.workflow_status}:"
                           f"{finding.severity}>{updated.severity}"))
            return updated

    def list_findings(self, *, limit: int | None = None, after: uuid.UUID | None = None) -> list[Finding]:
        query = select(findings)
        if after is not None:
            query = query.where(findings.c.id > after)
        if limit is not None or after is not None:
            query = query.order_by(findings.c.id)
        if limit is not None:
            query = query.limit(limit)
        with self.engine.connect() as conn:
            rows = conn.execute(query).mappings().all()
            return [_to(Finding, dict(r)) for r in rows]

    def finding_stats(self) -> dict:
        result = {}
        with self.engine.connect() as conn:
            for group, column in (("by_severity", findings.c.severity), ("by_workflow_status", findings.c.workflow_status)):
                result[group] = dict(conn.execute(select(column, func.count()).group_by(column)).all())
            provider = func.coalesce(func.nullif(credentials.c.provider, ""), "unknown")
            result["by_provider"] = dict(conn.execute(select(provider, func.count()).select_from(
                findings.outerjoin(credentials, findings.c.credential_id == credentials.c.id)).group_by(provider)).all())
        return result

    @staticmethod
    def _like(needle: str, columns):
        """Case-insensitive literal substring, or None for "match all"."""
        if not needle:
            return None
        return or_(*[func.lower(cast(column, String)).contains(needle.lower(), autoescape=True) for column in columns])

    def _search(self, joined, columns, searchable, order, needle: str, limit: int, build):
        with self.engine.connect() as conn:
            where = self._like(needle, searchable)
            counted = select(func.count()).select_from(joined)
            listed = select(*columns).select_from(joined).order_by(*order).limit(max(1, int(limit)))
            if where is not None:
                counted, listed = counted.where(where), listed.where(where)
            total = int(conn.execute(counted).scalar() or 0)
            return [build(row) for row in conn.execute(listed).mappings()], total

    def search_connections(self, needle: str, limit: int) -> tuple[list[dict], int]:
        """Filtered, ordered, limited and counted in SQL rather than in memory."""
        from cremore.db.repository import _connection_search_row

        def build(row):
            hit = _connection_search_row(SimpleNamespace(
                id=row["id"], name=row["name"], provider=row["provider"],
                status=row["status"], config=row["config"] or {}))
            hit.pop("_haystack", None)
            return hit

        current = select(connections).where(
            func.coalesce(connections.c.credential_evidence["revoked_at"].as_string(), "") == ""
        ).subquery()
        searchable = [current.c.name, current.c.provider, current.c.status,
                      current.c.config, current.c.id]
        return self._search(current, list(current.c), searchable,
                            [current.c.name, current.c.id], needle, limit, build)

    def search_aws_accounts(self, needle: str, limit: int) -> tuple[list[dict], int]:
        from cremore.db.repository import _aws_account_search_row

        def build(row):
            hit = _aws_account_search_row(SimpleNamespace(
                id=row["id"], name=row["name"], account_id=row["account_id"],
                environment=row["environment"]))
            hit.pop("_haystack", None)
            return hit

        # "aws" is not a column, so a bare "aws" query must still match every
        # account: the literal is folded in rather than filtered out.
        if needle and "aws".startswith(needle.lower()[:3]) and needle.lower() in "aws":
            needle = ""
        searchable = [aws_accounts.c.name, aws_accounts.c.account_id,
                      aws_accounts.c.environment, aws_accounts.c.id]
        return self._search(aws_accounts, list(aws_accounts.c), searchable,
                            [aws_accounts.c.name, aws_accounts.c.id], needle, limit, build)

    def search_assets(self, needle: str, limit: int) -> tuple[list[dict], int, bool]:
        """Catalogued assets across connections, restricted to each connection's
        current snapshot so a stale row can never appear as a live asset."""
        from cremore.db.catalog_store import catalog_indexes, catalog_resources
        from cremore.db.repository import _asset_search_row

        def build(row):
            return _asset_search_row(row["kind"], row["connection_id"], row["resource_id"],
                                     row["name_key"], row["resource_type"],
                                     row["account_id"], row["region"])

        joined = catalog_resources.join(catalog_indexes, and_(
            catalog_resources.c.kind == catalog_indexes.c.kind,
            catalog_resources.c.connection_id == catalog_indexes.c.connection_id,
            catalog_resources.c.observed_snapshot == catalog_indexes.c.snapshot_id))
        searchable = [catalog_resources.c.name_key, catalog_resources.c.resource_id,
                      catalog_resources.c.resource_type, catalog_resources.c.account_id,
                      catalog_resources.c.region]
        columns = [catalog_resources.c.kind, catalog_resources.c.connection_id,
                   catalog_resources.c.resource_id, catalog_resources.c.name_key,
                   catalog_resources.c.resource_type, catalog_resources.c.account_id,
                   catalog_resources.c.region]
        rows, total = self._search(joined, columns, searchable,
                                   [catalog_resources.c.name_key, catalog_resources.c.resource_id],
                                   needle, limit, build)
        with self.engine.connect() as conn:
            incomplete = conn.execute(select(func.count()).select_from(scope_catalogs)
                                      .where(scope_catalogs.c.completeness != "COMPLETE")).scalar()
        return rows, total, bool(incomplete)

    def search_findings(self, needle: str, limit: int) -> tuple[list[dict], int]:
        """Findings joined to their credential, filtered and limited in SQL.

        The searchable text lives on the credential, so this is one join rather
        than a read of every finding followed by a lookup each.
        """
        from cremore.db.repository import _finding_search_row

        def build(row):
            finding = SimpleNamespace(id=row["id"], severity=row["severity"],
                                      workflow_status=row["workflow_status"])
            credential = SimpleNamespace(
                credential_type=row["credential_type"], provider=row["provider"],
                identifier_hint=row["identifier_hint"], principal_name=row["principal_name"],
                principal_arn=row["principal_arn"], service_name=row["service_name"],
                team=row["team"], business_owner=row["business_owner"])
            hit = _finding_search_row(finding, credential)
            hit.pop("_haystack", None)
            return hit

        joined = findings.join(credentials, findings.c.credential_id == credentials.c.id)
        searchable = [credentials.c.credential_type, credentials.c.provider,
                      credentials.c.identifier_hint, credentials.c.principal_name,
                      credentials.c.principal_arn, credentials.c.service_name,
                      credentials.c.team, credentials.c.business_owner,
                      findings.c.severity, findings.c.workflow_status]
        return self._search(joined, [findings.c.id, *searchable], searchable,
                            [credentials.c.credential_type, findings.c.id], needle, limit, build)

    def get_finding(self, finding_id: uuid.UUID) -> Finding | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(findings).where(findings.c.id == finding_id)).mappings().first()
            return _to(Finding, dict(row)) if row else None

    def update_finding_status(self, finding_id: uuid.UUID, workflow_status: str,
                              resolution: str | None = None, *, expected_updated_at=None,
                              expected_status=None, expected_resolution=None) -> Finding | None:
        now = _now()
        values: dict = {"workflow_status": workflow_status, "updated_at": now}
        if workflow_status == "ACKNOWLEDGED":
            values["acknowledged_at"] = now
        elif workflow_status in ("RESOLVED", "FALSE_POSITIVE", "IGNORED"):
            values["resolved_at"] = now
            values["resolution"] = resolution
        elif workflow_status == "OPEN":
            values["resolved_at"] = None
            values["resolution"] = None
        with self.engine.begin() as conn:
            previous = conn.execute(select(findings.c.workflow_status).where(findings.c.id == finding_id)).scalar_one_or_none()
            query = update(findings).where(findings.c.id == finding_id)
            if expected_updated_at is not None:
                query = query.where(findings.c.updated_at == expected_updated_at)
            if expected_status is not None:
                query = query.where(findings.c.workflow_status == expected_status, findings.c.resolution == expected_resolution)
            result = conn.execute(query.values(**values))
            if result.rowcount == 0:
                return None
            row = conn.execute(select(findings).where(findings.c.id == finding_id)).mappings().first()
            saved = _to(Finding, dict(row))
            if previous != saved.workflow_status:
                credential = conn.execute(select(credentials).where(credentials.c.id == saved.credential_id)).mappings().first()
                self._queue_siem(conn, finding_updated(saved, _to(Credential, credential) if credential else None,
                    change="WORKFLOW", previous_workflow_status=previous, marker=f"{_stamp_marker(saved.updated_at)}:{previous}>{saved.workflow_status}"))
            return saved

    def assign_finding(self, finding_id: uuid.UUID, assignee: str | None) -> Finding | None:
        with self.engine.begin() as conn:
            result = conn.execute(update(findings).where(findings.c.id == finding_id).values(
                assigned_to=assignee, updated_at=_now()))
            if result.rowcount == 0:
                return None
            row = conn.execute(select(findings).where(findings.c.id == finding_id)).mappings().first()
            return _to(Finding, dict(row))

    def record_finding_event(self, event: FindingEvent) -> FindingEvent:
        with self.engine.begin() as conn:
            return self._record_event(conn, event)

    def _record_event(self, conn, event: FindingEvent, secret: bytes | None = None) -> FindingEvent:
        values = event.model_dump(exclude={"id", "created_at"})
        values.update(id=uuid.uuid4(), created_at=_now())
        secret = secret or self.audit_key
        values["entry_mac"] = audit_chain.entry(secret, values) if secret else None
        conn.execute(insert(finding_events).values(**values))
        saved = _to(FindingEvent, values)
        if export_audit(saved):
            self._queue_siem(conn, audit_action(saved))
        return saved

    # --- audit chain (cremore/db/audit_chain.py) ------------------------------

    def seal_audit(self, secret: bytes, limit: int = 1000, expected: tuple[int, str] | None = None) -> dict:
        """Seal unsealed audit rows into the chain, oldest first; one sealer per schema at a time.

        The first seal takes in every row written before it, a batch at a time, then starts the chain. A chain
        is never started again once one existed: while an authentic start, anchor or rewind row remains, or while
        this process remembers a head (``expected``), missing positions are ``reset``, not a new beginning. If
        ``expected`` lost its place, AUDIT_CHAIN_REWOUND is recorded and sealed first, in this transaction; with
        no chain left, one such row waits unsealed, and is recorded again whenever none does.
        On PostgreSQL the transaction reads one snapshot: rows committed meanwhile wait for the next seal.
        """
        table = finding_events
        done = {"sealed": 0, "head": None, "reset": False, "rewound": False}
        with self.engine.connect() as bare:
            conn = bare.execution_options(isolation_level="REPEATABLE READ") if bare.dialect.name == "postgresql" else bare
            with conn.begin():
                if conn.dialect.name == "postgresql" and not conn.execute(text(
                        "SELECT pg_try_advisory_xact_lock(hashtext(current_schema()), :key)"), {"key": _AUDIT_SEAL_LOCK}).scalar():
                    return done
                head = conn.execute(select(table.c.chain_seq, table.c.chain_mac)
                                    .where(table.c.chain_seq.is_not(None)).order_by(table.c.chain_seq.desc()).limit(1)).first()
                if head is None:
                    if expected is not None:
                        # This process sealed a chain that is gone: say so in the trail, and start nothing. The row
                        # waits unsealed; if it is removed, the next seal writes it again.
                        if any(audit_chain.authentic(secret, row) for row in conn.execute(select(table).where(
                                table.c.chain_seq.is_(None), table.c.actor == audit_chain.CHAIN_ACTOR,
                                table.c.event_type == audit_chain.REWOUND_EVENT)).mappings()):
                            return {**done, "reset": True}
                        self._record_event(conn, audit_chain.chain_event(
                            audit_chain.REWOUND_EVENT, f"expected_seq={expected[0]} head_seq=0"), secret)
                        return {**done, "reset": True, "rewound": True}
                    if any(audit_chain.authentic(secret, row) for row in conn.execute(select(table).where(
                            table.c.actor == audit_chain.CHAIN_ACTOR, table.c.event_type.in_(audit_chain.CHAIN_EVENTS))).mappings()):
                        return {**done, "reset": True}
                    return {**done, **self._baseline(conn, secret)}
                seq, previous = head.chain_seq, head.chain_mac
                if expected is not None and not audit_chain.same(conn.execute(select(table.c.chain_mac).where(
                        table.c.chain_seq == expected[0])).scalar(), expected[1]):
                    rewound = self._record_event(conn, audit_chain.chain_event(
                        audit_chain.REWOUND_EVENT, f"expected_seq={expected[0]} head_seq={head.chain_seq}"), secret)
                    seq, previous = self._seal_rows(conn, secret, [conn.execute(select(table).where(
                        table.c.id == rewound.id)).mappings().one()], seq, previous)
                    done["rewound"] = True
                rows = list(conn.execute(select(table).where(table.c.chain_seq.is_(None))
                                         .order_by(table.c.created_at, table.c.id).limit(limit)).mappings().all())
                seq, previous = self._seal_rows(conn, secret, rows, seq, previous)
                return {**done, "sealed": len(rows) + done["rewound"], "head": (seq, previous)}

    def _baseline(self, conn, secret: bytes) -> dict:
        """The first seal: every row already written, in batches of 500, then the chain's start after them. The
        start names the rows actually sealed before it (verification reads a start at another place as moved)."""
        table = finding_events
        seq, previous, cursor = 0, "", None
        while True:
            query = select(table).where(table.c.chain_seq.is_(None))
            if cursor is not None:
                query = query.where(tuple_(table.c.created_at, table.c.id) > cursor)
            rows = conn.execute(query.order_by(table.c.created_at, table.c.id).limit(500)).mappings().all()
            if not rows:
                break
            seq, previous = self._seal_rows(conn, secret, rows, seq, previous)
            cursor = (rows[-1]["created_at"], rows[-1]["id"])
        started = self._record_event(conn, audit_chain.chain_event(
            audit_chain.GENESIS_EVENT, f"legacy_rows={seq} key={audit_chain.key_id(secret)}"), secret)
        seq, previous = self._seal_rows(conn, secret, [conn.execute(select(table).where(table.c.id == started.id)).mappings().one()],
                                        seq, previous)
        return {"sealed": seq, "head": (seq, previous)}

    @staticmethod
    def _seal_rows(conn, secret: bytes, rows: list, seq: int, previous: str) -> tuple[int, str]:
        sealed = []
        for row in rows:
            seq += 1
            previous = audit_chain.link(secret, previous, seq, row)
            sealed.append({"row_id": row["id"], "row_seq": seq, "row_mac": previous})
        if sealed:
            conn.execute(update(finding_events).where(finding_events.c.id == bindparam("row_id"), finding_events.c.chain_seq.is_(None))
                         .values(chain_seq=bindparam("row_seq"), chain_mac=bindparam("row_mac")), sealed)
        return seq, previous

    def audit_chain_page(self, after_seq: int = 0, limit: int = 2000) -> list[dict]:
        """Sealed audit rows after ``after_seq``, in chain order."""
        with self.engine.connect() as conn:
            return [dict(row) for row in conn.execute(
                select(finding_events).where(finding_events.c.chain_seq > after_seq)
                .order_by(finding_events.c.chain_seq).limit(limit)).mappings().all()]

    def unsealed_audit(self, limit: int = 10000) -> list[dict]:
        """Audit rows the sealer has not taken in yet, oldest first."""
        with self.engine.connect() as conn:
            return [dict(row) for row in conn.execute(
                select(finding_events).where(finding_events.c.chain_seq.is_(None))
                .order_by(finding_events.c.created_at, finding_events.c.id).limit(limit)).mappings().all()]

    def audit_rows_outside_chain(self, limit: int = 100) -> list[dict]:
        """Rows at a position no chain has (below 1): no walk reaches them, yet listings would show them."""
        with self.engine.connect() as conn:
            return [dict(row) for row in conn.execute(
                select(finding_events).where(finding_events.c.chain_seq < 1).limit(limit)).mappings().all()]

    def audit_chain_rows(self) -> list[dict]:
        """The sealer's own rows (start, anchors, rewinds), sealed or not, in chain order."""
        with self.engine.connect() as conn:
            return [dict(row) for row in conn.execute(select(finding_events).where(
                finding_events.c.actor == audit_chain.CHAIN_ACTOR, finding_events.c.event_type.in_(audit_chain.CHAIN_EVENTS))
                .order_by(finding_events.c.chain_seq)).mappings().all()]

    def audit_macs_at(self, seqs: list[int]) -> dict[int, str | None]:
        """The chain MAC at each position, for the anchors' claims."""
        out: dict[int, str | None] = {}
        wanted = sorted({seq for seq in seqs if isinstance(seq, int)})
        with self.engine.connect() as conn:
            for start in range(0, len(wanted), 500):
                chunk = wanted[start:start + 500]
                out.update({row.chain_seq: row.chain_mac for row in conn.execute(select(
                    finding_events.c.chain_seq, finding_events.c.chain_mac).where(finding_events.c.chain_seq.in_(chunk)))})
        return out

    def list_finding_events(self, finding_id: uuid.UUID) -> list[FindingEvent]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(finding_events)
                .where(finding_events.c.finding_id == finding_id)
                .order_by(finding_events.c.created_at)
            ).mappings().all()
            return [_to(FindingEvent, dict(r)) for r in rows]

    def list_events(self, limit: int = 200) -> list[FindingEvent]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(finding_events).order_by(finding_events.c.created_at.desc()).limit(limit)
            ).mappings().all()
            return [_to(FindingEvent, dict(r)) for r in rows]

    # --- jobs ---------------------------------------------------------------

    def enqueue_job(self, job: ScanJob) -> ScanJob:
        with self.engine.begin() as conn:
            new_id = uuid.uuid4()
            now = _now()
            values = {"id": new_id, "kind": job.kind, "status": JobStatus.QUEUED.value,
                      "payload": job.payload, "connection_id": job.connection_id,
                      "objects": 0, "findings": 0, "created_at": now}
            self._insert_job(conn, values)
            return _to(ScanJob, values)

    @staticmethod
    def _active_content_job(conn) -> ScanJob | None:
        row = conn.execute(select(scan_jobs).where(
            scan_jobs.c.status.in_(ACTIVE_JOB_STATUSES), scan_jobs.c.kind.in_(CONTENT_SCAN_KINDS))
            .order_by(scan_jobs.c.created_at).limit(1)).mappings().first()
        return _to(ScanJob, dict(row)) if row else None

    def active_content_job(self) -> ScanJob | None:
        with self.engine.connect() as conn:
            return self._active_content_job(conn)

    def _insert_job(self, conn, values: dict) -> None:
        """Admission is durable while busy; execution owns the connection slot of the job's lane."""
        conn.execute(insert(scan_jobs).values(**values, lane=job_lane(values["kind"], values.get("payload"))))

    def request_job_cancel(self, job_id: uuid.UUID) -> ScanJob | None:
        """Stop a job: a queued one is withdrawn, a running one enters CANCELLING.

        CANCELLING keeps the scan slot until the worker has stopped every task and
        the run is finalized as CANCELLED; no later result can overwrite it.
        """
        with self.engine.begin() as conn:
            conn.execute(update(scan_jobs).where(scan_jobs.c.id == job_id, scan_jobs.c.status == JobStatus.QUEUED.value)
                         .values(status=JobStatus.CANCELLED.value, finished_at=_now()))
            conn.execute(update(scan_jobs).where(scan_jobs.c.id == job_id, scan_jobs.c.status == JobStatus.RUNNING.value)
                         .values(status=JobStatus.CANCELLING.value))
            row = conn.execute(select(scan_jobs).where(scan_jobs.c.id == job_id)).mappings().first()
            return _to(ScanJob, dict(row)) if row else None

    def finish_cancelled_job(self, job_id: uuid.UUID, coverage: dict | None = None) -> None:
        with self.engine.begin() as conn:
            conn.execute(update(scan_jobs).where(scan_jobs.c.id == job_id, scan_jobs.c.status == JobStatus.CANCELLING.value)
                         .values(status=JobStatus.CANCELLED.value, coverage=coverage, finished_at=_now()))

    def ensure_scan_slot(self) -> bool:
        with self.engine.begin() as conn:
            if conn.dialect.name == "postgresql":
                conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _SCHEMA_LOCK_KEY})
            return ensure_scan_slot(conn)

    def claim_next_job(self, *, execution_role="mixed") -> ScanJob | None:
        from cremore.worker.isolation import job_predicate

        with self.engine.begin() as conn:
            self._require_scan_schema(conn)
            # Only the short admission transaction is global. External I/O and
            # execution are independent across connections and lanes. Null legacy
            # scopes conservatively conflict with every content run; a NULL lane
            # (a row from before lanes) is a sweep, as the unique index reads it.
            if conn.dialect.name == "postgresql":
                conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": 0x6372655f61646d})
            elif not getattr(self.engine, "_task_bound", False):
                conn.exec_driver_sql("BEGIN IMMEDIATE")
            running = scan_jobs.alias("running_content")
            conflict = exists(select(running.c.id).where(
                running.c.kind.in_(CONTENT_SCAN_KINDS), running.c.status.in_(("RUNNING", "CANCELLING")),
                or_(and_(running.c.connection_id == scan_jobs.c.connection_id,
                         func.coalesce(running.c.lane, "sweep") == func.coalesce(scan_jobs.c.lane, "sweep")),
                    running.c.connection_id.is_(None), scan_jobs.c.connection_id.is_(None))))
            older = scan_jobs.alias("older_unscoped_content")
            global_barrier = exists(select(older.c.id).where(
                older.c.kind.in_(CONTENT_SCAN_KINDS), older.c.status == "QUEUED", older.c.connection_id.is_(None),
                or_(older.c.created_at < scan_jobs.c.created_at,
                    and_(older.c.created_at == scan_jobs.c.created_at, older.c.id < scan_jobs.c.id))))
            row = conn.execute(
                select(scan_jobs.c.id)
                .where(scan_jobs.c.status == JobStatus.QUEUED.value, job_predicate(scan_jobs, execution_role),
                       or_(scan_jobs.c.kind.not_in(CONTENT_SCAN_KINDS), and_(~conflict, ~global_barrier)))
                .order_by(scan_jobs.c.created_at, scan_jobs.c.id)
                .limit(1).with_for_update(skip_locked=True)
            ).first()
            if row is None:
                return None
            job_id = row[0]
            now = _now()
            # Atomic claim: only one worker can move QUEUED -> RUNNING.
            result = conn.execute(
                update(scan_jobs)
                .where(scan_jobs.c.id == job_id, scan_jobs.c.status == JobStatus.QUEUED.value)
                .values(status=JobStatus.RUNNING.value, started_at=now)
            )
            if result.rowcount != 1:
                return None
            claimed = conn.execute(select(scan_jobs).where(scan_jobs.c.id == job_id)).mappings().first()
            return _to(ScanJob, dict(claimed))

    def complete_job(self, job_id: uuid.UUID, objects: int, findings: int, objects_failed: int = 0,
                     coverage: dict | None = None) -> None:
        with self.engine.begin() as conn:
            conn.execute(update(scan_jobs).where(scan_jobs.c.id == job_id, scan_jobs.c.status.notin_(_STOPPED)).values(
                status=JobStatus.SUCCEEDED.value, objects=objects, findings=findings,
                objects_failed=objects_failed, coverage=coverage, finished_at=_now()))

    def fail_job(self, job_id: uuid.UUID, error: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(update(scan_jobs).where(scan_jobs.c.id == job_id, scan_jobs.c.status.notin_(_STOPPED)).values(
                status=JobStatus.FAILED.value, error=error[:2000], finished_at=_now()))

    def get_job(self, job_id: uuid.UUID) -> ScanJob | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(scan_jobs).where(scan_jobs.c.id == job_id)).mappings().first()
            return _to(ScanJob, dict(row)) if row else None

    def list_jobs(self, limit: int = 100) -> list[ScanJob]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(scan_jobs).order_by(scan_jobs.c.created_at.desc()).limit(limit)
            ).mappings().all()
            return [_to(ScanJob, dict(r)) for r in rows]

    def job_queue_summary(self) -> dict:
        """How many jobs wait to be claimed and since when the oldest has waited."""
        with self.engine.connect() as conn:
            count, oldest = conn.execute(select(func.count(), func.min(scan_jobs.c.created_at)).where(
                scan_jobs.c.status == JobStatus.QUEUED.value)).one()
        if oldest is not None and oldest.tzinfo is None:
            oldest = oldest.replace(tzinfo=_dt.UTC)  # SQLite drops tz
        return {"queued": int(count), "oldest_queued_at": oldest}

    def latest_connection_jobs(self, kinds: tuple[str, ...], status: str) -> dict[uuid.UUID, ScanJob]:
        """Each connection's most recently finished job of these kinds in this status."""
        chosen = (scan_jobs.c.kind.in_(kinds), scan_jobs.c.status == status,
                  scan_jobs.c.connection_id.isnot(None), scan_jobs.c.finished_at.isnot(None))
        newest = (select(scan_jobs.c.connection_id, func.max(scan_jobs.c.finished_at).label("finished_at"))
                  .where(*chosen).group_by(scan_jobs.c.connection_id).subquery())
        query = select(scan_jobs).join(newest, and_(scan_jobs.c.connection_id == newest.c.connection_id,
                                                    scan_jobs.c.finished_at == newest.c.finished_at)).where(*chosen)
        with self.engine.connect() as conn:
            rows = conn.execute(query).mappings().all()
        return {row["connection_id"]: _to(ScanJob, dict(row)) for row in rows}

    def cancel_job(self, job_id: uuid.UUID) -> ScanJob | None:
        with self.engine.begin() as conn:
            # Only a still-queued job can be withdrawn; the claim is atomic on
            # status, so a job that became RUNNING meanwhile is left alone.
            conn.execute(
                update(scan_jobs)
                .where(scan_jobs.c.id == job_id, scan_jobs.c.status == JobStatus.QUEUED.value)
                .values(status=JobStatus.CANCELLED.value, finished_at=_now())
            )
            row = conn.execute(select(scan_jobs).where(scan_jobs.c.id == job_id)).mappings().first()
            return _to(ScanJob, dict(row)) if row else None

    # --- enterprise entities (generic CRUD over a table) --------------------

    def _crud_create(self, table, cls, model, *, connection=None):
        data = model.model_dump(exclude={"id", "created_at", "updated_at", "resolved_at"})
        now = _now()
        data["id"] = uuid.uuid4()
        if "created_at" in table.c:
            data["created_at"] = now
        if "updated_at" in table.c:
            data["updated_at"] = now
        if connection is not None:
            connection.execute(insert(table).values(**data))
        else:
            with self.engine.begin() as conn:
                conn.execute(insert(table).values(**data))
        return _to(cls, data)

    def _crud_list(self, table, cls, *, limit=None, after=None):
        with self.engine.connect() as conn:
            order = table.c.created_at.desc() if "created_at" in table.c and limit is None and after is None else table.c.id
            query = select(table).order_by(order)
            if after is not None:
                query = query.where(table.c.id > after)
            if limit is not None:
                query = query.limit(limit)
            rows = conn.execute(query).mappings().all()
            return [_to(cls, dict(r)) for r in rows]

    def _crud_get(self, table, cls, entity_id):
        with self.engine.connect() as conn:
            row = conn.execute(select(table).where(table.c.id == entity_id)).mappings().first()
            return _to(cls, dict(row)) if row else None

    def _crud_update(self, table, cls, entity_id, changes: dict, *, expected: dict | None = None, connection=None):
        if "updated_at" in table.c:
            changes = {**changes, "updated_at": _now()}
        if connection is None:
            with self.engine.begin() as conn:
                return self._crud_update(table, cls, entity_id, changes, expected=expected, connection=conn)
        query = update(table).where(table.c.id == entity_id)
        for field, value in (expected or {}).items():
            query = query.where(table.c[field] == value)
        if connection.execute(query.values(**changes)).rowcount == 0:
            return None
        row = connection.execute(select(table).where(table.c.id == entity_id)).mappings().first()
        return _to(cls, dict(row))

    def _crud_delete(self, table, entity_id) -> bool:
        with self.engine.begin() as conn:
            return conn.execute(delete(table).where(table.c.id == entity_id)).rowcount > 0

    # --- operator rules -----------------------------------------------------

    def create_rule(self, rule: CustomRule) -> CustomRule:
        with self.engine.connect() as conn:
            if conn.execute(select(custom_rules.c.id).where(custom_rules.c.name == rule.name)).first():
                raise ValueError(f"rule {rule.name!r} already exists")
        return self._crud_create(custom_rules, CustomRule, rule)

    def list_rules(self) -> list[CustomRule]:
        with self.engine.connect() as conn:
            rows = conn.execute(select(custom_rules).order_by(custom_rules.c.created_at)).mappings().all()
            return [_to(CustomRule, dict(r)) for r in rows]

    def get_rule(self, rule_id: uuid.UUID) -> CustomRule | None:
        return self._crud_get(custom_rules, CustomRule, rule_id)

    def update_rule(self, rule_id: uuid.UUID, **changes) -> CustomRule | None:
        return self._crud_update(custom_rules, CustomRule, rule_id, changes)

    def delete_rule(self, rule_id: uuid.UUID) -> bool:
        return self._crud_delete(custom_rules, rule_id)

    # --- action plans -------------------------------------------------------

    def create_action_plan(self, plan: ActionPlan, audit: FindingEvent | None = None) -> ActionPlan:
        """Reserve the plan's target; ``audit`` is recorded about the new plan in the same transaction."""
        with self.engine.begin() as conn:
            # Serialize reservations on the existing credential row. SQLite
            # needs a write transaction because it has no row-level FOR UPDATE.
            self._lock_credential(conn, plan.credential_id)
            if plan.target and conn.dialect.name == "postgresql":
                # Another provider's credential has no credentials row to lock: lock its key instead.
                conn.execute(text("SELECT pg_advisory_xact_lock(hashtext(current_schema()), hashtext(:key))"),
                             {"key": "action_plan:" + str(plan.credential_id)})
            if conn.execute(select(action_plans.c.id).where(action_plans.c.idempotency_key == plan.idempotency_key)).first():
                raise ValueError("duplicate idempotency key")
            now = plan.requested_at or _now()
            if plan.reserves_target(now):
                active = conn.execute(select(action_plans).where(
                    action_plans.c.credential_id == plan.credential_id,
                    action_plans.c.status.in_(ACTION_PLAN_UNRESOLVED))).mappings()
                if any(_to(ActionPlan, row).reserves_target(now) for row in active):
                    raise ValueError("action plan target locked")
            try:
                created = self._crud_create(action_plans, ActionPlan, plan, connection=conn)
            except IntegrityError:
                raise ValueError("action plan reservation conflict") from None
            if audit is not None:
                self._record_event(conn, audit.model_copy(update={"target_id": created.id}))
            return created

    def list_action_plans(self, credential_id: uuid.UUID | None = None, limit: int = 500) -> list[ActionPlan]:
        """One credential's plans, or the newest ``limit`` plans of every credential when none is given."""
        statement = select(action_plans).order_by(action_plans.c.created_at.desc())
        statement = (statement.where(action_plans.c.credential_id == credential_id) if credential_id is not None
                     else statement.limit(limit))
        with self.engine.connect() as conn:
            return [_to(ActionPlan, dict(r)) for r in conn.execute(statement).mappings().all()]

    def get_action_plan(self, plan_id: uuid.UUID) -> ActionPlan | None:
        return self._crud_get(action_plans, ActionPlan, plan_id)

    def find_action_plan(self, idempotency_key: str) -> ActionPlan | None:
        with self.engine.connect() as conn:
            row = conn.execute(
                select(action_plans).where(action_plans.c.idempotency_key == idempotency_key)
            ).mappings().first()
            return _to(ActionPlan, dict(row)) if row else None

    def update_action_plan(self, plan_id: uuid.UUID, *, expected_status: str | None = None,
                           audit: FindingEvent | None = None, **changes) -> ActionPlan | None:
        """Change the plan if it is still in ``expected_status``; ``audit`` commits with the change."""
        expected = {"status": expected_status} if expected_status is not None else None
        with self.engine.begin() as conn:
            saved = self._crud_update(action_plans, ActionPlan, plan_id, changes, expected=expected, connection=conn)
            if saved is not None and audit is not None:
                self._record_event(conn, audit)
            return saved

    # --- scan scope ------------------------------------------------------------

    def save_catalog(self, catalog: ScopeCatalog) -> ScopeCatalog:
        data = catalog.model_dump(exclude={"id", "created_at", "updated_at"})
        now = _now()
        with self.engine.begin() as conn:
            row = conn.execute(select(scope_catalogs).where(
                scope_catalogs.c.kind == catalog.kind,
                scope_catalogs.c.connection_id == catalog.connection_id)).mappings().first()
            if row is None:
                data.update(id=uuid.uuid4(), created_at=now, updated_at=now)
                conn.execute(insert(scope_catalogs).values(**data))
            else:
                conn.execute(update(scope_catalogs).where(scope_catalogs.c.id == row["id"])
                             .values(**data, updated_at=now))
                data.update(id=row["id"], created_at=row["created_at"], updated_at=now)
        return _to(ScopeCatalog, data)

    def get_catalog(self, kind: str, connection_id: uuid.UUID) -> ScopeCatalog | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(scope_catalogs).where(
                scope_catalogs.c.kind == kind, scope_catalogs.c.connection_id == connection_id)).mappings().first()
            return _to(ScopeCatalog, dict(row)) if row else None

    def create_scope_profile(self, profile: ScopeProfile) -> ScopeProfile:
        return self._crud_create(scope_profiles, ScopeProfile, profile)

    def list_scope_profiles(self, kind: str, connection_id: uuid.UUID) -> list[ScopeProfile]:
        with self.engine.connect() as conn:
            rows = conn.execute(select(scope_profiles).where(
                scope_profiles.c.kind == kind, scope_profiles.c.connection_id == connection_id)
                .order_by(scope_profiles.c.created_at)).mappings().all()
            return [_to(ScopeProfile, dict(r)) for r in rows]

    def get_scope_profile(self, profile_id: uuid.UUID) -> ScopeProfile | None:
        return self._crud_get(scope_profiles, ScopeProfile, profile_id)

    def update_scope_profile(self, profile_id: uuid.UUID, *, expected_version: int | None = None, **changes) -> ScopeProfile | None:
        expected = {"version": expected_version} if expected_version is not None else None
        return self._crud_update(scope_profiles, ScopeProfile, profile_id, changes, expected=expected)

    def create_draft(self, draft: SelectionDraft) -> SelectionDraft:
        return self._crud_create(selection_drafts, SelectionDraft, draft)

    def get_draft(self, draft_id: uuid.UUID) -> SelectionDraft | None:
        return self._crud_get(selection_drafts, SelectionDraft, draft_id)

    def update_draft(self, draft_id: uuid.UUID, **changes) -> SelectionDraft | None:
        return self._crud_update(selection_drafts, SelectionDraft, draft_id, changes)

    def create_plan(self, plan: ScopePlan) -> ScopePlan:
        return self._crud_create(scope_plans, ScopePlan, plan)

    def get_plan(self, plan_id: uuid.UUID) -> ScopePlan | None:
        return self._crud_get(scope_plans, ScopePlan, plan_id)

    def update_plan(self, plan_id: uuid.UUID, **changes) -> ScopePlan | None:
        return self._crud_update(scope_plans, ScopePlan, plan_id, changes)

    def list_scheduled_profiles(self, full_scan_default: int = 0) -> list[ScopeProfile]:
        """Profiles a schedule runs: a cadence of their own, or none for full scans while the installation has one."""
        scheduled = [scope_profiles.c.schedule_minutes > 0, scope_profiles.c.full_scan_minutes > 0]
        if full_scan_default > 0:
            scheduled.append(scope_profiles.c.full_scan_minutes.is_(None))
        with self.engine.connect() as conn:
            return [_to(ScopeProfile, row) for row in conn.execute(select(scope_profiles).where(or_(*scheduled))).mappings()]

    def list_scope_profiles_page(self, cursor: str | None = None, limit: int = 100) -> tuple[list[ScopeProfile], str | None]:
        limit = max(1, min(int(limit), 1000))
        query = select(scope_profiles).order_by(scope_profiles.c.id).limit(limit + 1)
        if cursor:
            query = query.where(scope_profiles.c.id > uuid.UUID(cursor))
        with self.engine.connect() as conn:
            rows = conn.execute(query).mappings().all()
        return [_to(ScopeProfile, r) for r in rows[:limit]], str(rows[limit - 1]["id"]) if len(rows) > limit else None

    def _slot_receipt_row(self, key: str):
        """(job_id, status, slot_receipt, requested_by, created_at) of the run a slot receipt names, or None."""
        payload = scan_jobs.c.payload
        with self.engine.connect() as conn:
            return conn.execute(select(trigger_receipts.c.job_id, scan_jobs.c.status, payload["slot_receipt"].as_string(),
                                       payload["requested_by"].as_string(), scan_jobs.c.created_at)
                                .select_from(trigger_receipts.outerjoin(scan_jobs, scan_jobs.c.id == trigger_receipts.c.job_id))
                                .where(trigger_receipts.c.receipt_key == key)).first()

    def slot_receipt_state(self, key: str, begins: _dt.datetime) -> tuple[bool, uuid.UUID | None]:
        row = self._slot_receipt_row(key)
        if row is None:
            return False, None
        if receipt_reopens(key, begins, *row[1:]):
            return False, row[0]
        return True, None

    def slot_run_ended(self, key: str, begins: _dt.datetime) -> bool:
        row = self._slot_receipt_row(key)
        return row is not None and row[1] not in ACTIVE_JOB_STATUSES and not receipt_reopens(key, begins, *row[1:])

    @staticmethod
    def _swap_receipt(conn, receipt_key: str, replaces: uuid.UUID | None) -> None:
        """Drop a reopened slot's receipt only while it still names ``replaces``, its ended run, in the transaction
        that inserts the new one: a replica that swapped it first left another job_id, so this deletes nothing and the
        insert after it conflicts. Insert-if-absent and delete are what the worker's role may do to receipts."""
        if replaces is not None:
            conn.execute(delete(trigger_receipts).where(trigger_receipts.c.receipt_key == receipt_key,
                                                        trigger_receipts.c.job_id == replaces))

    def prune_trigger_receipts(self, before: _dt.datetime, limit: int = 10000) -> int:
        if before.tzinfo is None:
            raise ValueError("receipt retention requires a timezone")
        with self.engine.begin() as conn:
            query = select(trigger_receipts.c.receipt_key).join(scan_jobs, scan_jobs.c.id == trigger_receipts.c.job_id).where(
                trigger_receipts.c.created_at < before, scan_jobs.c.status.in_(("SUCCEEDED", "FAILED", "CANCELLED")),
                func.coalesce(scan_jobs.c.payload["mode"].as_string(), "") != "POLICY_SWEEP",
                func.coalesce(scan_jobs.c.payload["trigger"].as_string(), "") != "POLICY_SWEEP"
            ).order_by(trigger_receipts.c.created_at, trigger_receipts.c.receipt_key).limit(max(1, min(int(limit), 10000)))
            keys = list(conn.execute(query).scalars())
            if not keys:
                return 0
            return conn.execute(delete(trigger_receipts).where(trigger_receipts.c.receipt_key.in_(keys))).rowcount

    def _scope_job(self, conn, job, plan_id, *, job_id=None):
        now = _now()
        values = {"id": job_id or uuid.uuid4(), "kind": "scope", "status": "QUEUED",
                  "payload": {**job.payload, "plan_id": str(plan_id)}, "connection_id": job.connection_id,
                  "objects": 0, "findings": 0, "objects_failed": 0, "created_at": now}
        self._insert_job(conn, values)
        return _to(ScanJob, values)

    def consume_scope_plan(self, plan_id: uuid.UUID, expected_version: int, job: ScanJob) -> tuple[ScanJob, bool]:
        with self.engine.begin() as conn:
            self._require_scan_schema(conn)
            if conn.dialect.name == "sqlite":
                conn.execute(update(scope_plans).where(scope_plans.c.id == plan_id).values(job_id=scope_plans.c.job_id))
            plan = conn.execute(select(scope_plans).where(scope_plans.c.id == plan_id).with_for_update()).mappings().first()
            if plan is None or plan["profile_version"] != expected_version:
                raise ValueError("SCOPE_PLAN_STALE")
            if job.kind != "scope" or job.connection_id != plan["connection_id"]:
                raise ValueError("SCOPE_PLAN_JOB_MISMATCH")
            if plan["job_id"] is not None:
                existing = conn.execute(select(scan_jobs).where(scan_jobs.c.id == plan["job_id"])).mappings().first()
                if existing is None:
                    raise ValueError("SCOPE_PLAN_JOB_MISSING")
                return _to(ScanJob, existing), False
            expiry = plan["expires_at"]
            if expiry is not None and expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=_dt.UTC)
            if not plan["executable"] or (expiry is not None and expiry <= _now()):
                raise ValueError("SCOPE_PLAN_STALE")
            queued = self._scope_job(conn, job, plan_id)
            conn.execute(update(scope_plans).where(scope_plans.c.id == plan_id).values(job_id=queued.id))
            return queued, True

    def enqueue_triggered_scope(self, plan: ScopePlan, job: ScanJob, receipt_key: str,
                                replaces: uuid.UUID | None = None) -> tuple[ScanJob, bool]:
        if len(receipt_key) != 64 or any(c not in "0123456789abcdef" for c in receipt_key):
            raise ValueError("INVALID_TRIGGER_RECEIPT")
        if job.kind != "scope" or job.connection_id != plan.connection_id:
            raise ValueError("SCOPE_PLAN_JOB_MISMATCH")
        with self.engine.begin() as conn:
            self._require_scan_schema(conn)
            plan_id, job_id = plan.id or uuid.uuid4(), uuid.uuid4()
            self._swap_receipt(conn, receipt_key, replaces)
            statement = self._insert(conn, trigger_receipts).values(receipt_key=receipt_key,
                job_id=job_id, plan_id=plan_id, created_at=_now()).on_conflict_do_nothing()
            inserted = conn.execute(statement.returning(trigger_receipts.c.job_id)).scalar_one_or_none()
            if inserted is None:
                original = conn.execute(select(scan_jobs).join(trigger_receipts, trigger_receipts.c.job_id == scan_jobs.c.id)
                    .where(trigger_receipts.c.receipt_key == receipt_key)).mappings().one()
                return _to(ScanJob, original), False
            values = plan.model_dump(exclude={"id", "created_at", "updated_at", "job_id"})
            values.update(id=plan_id, job_id=job_id, created_at=_now())
            conn.execute(insert(scope_plans).values(**values))
            return self._scope_job(conn, job, plan_id, job_id=job_id), True

    def coalesce_scheduled_scope(self, receipt_key: str, profile: ScopeProfile, auth_revision: str,
                                 modes: tuple[str, ...], since: _dt.datetime,
                                 replaces: uuid.UUID | None = None) -> ScanJob | None:
        """Answer a schedule slot with a whole-scope run of this approval (``profile``'s version, ``auth_revision``) in
        one of ``modes``: a scheduled run or an Admin's, never an event's, a rescan's or a continuation's, that is still
        QUEUED or began at or after ``since``, the slot's start, and did not fail. The slot's receipt names it,
        replacing one that still names ``replaces`` (a reopened slot's ended run)."""
        if len(receipt_key) != 64 or any(c not in "0123456789abcdef" for c in receipt_key):
            raise ValueError("INVALID_TRIGGER_RECEIPT")
        payload = scan_jobs.c.payload
        with self.engine.begin() as conn:
            row = conn.execute(select(scan_jobs).where(
                scan_jobs.c.kind == "scope", scan_jobs.c.connection_id == profile.connection_id,
                or_(scan_jobs.c.status == JobStatus.QUEUED.value,
                    and_(scan_jobs.c.status.in_((JobStatus.RUNNING.value, JobStatus.SUCCEEDED.value)),
                         scan_jobs.c.started_at >= since)),
                payload["profile_id"].as_string() == str(profile.id),
                payload["profile_version"].as_integer() == profile.version,
                payload["auth_revision"].as_string() == auth_revision,
                payload["trigger"].as_string().in_(("BASELINE", "SCHEDULE")),
                func.coalesce(payload["mode"].as_string(), "BASELINE").in_(modes),
            ).order_by(scan_jobs.c.created_at).limit(1)).mappings().first()
            if row is None:
                return None
            self._swap_receipt(conn, receipt_key, replaces)
            conn.execute(self._insert(conn, trigger_receipts).values(receipt_key=receipt_key, job_id=row["id"],
                plan_id=uuid.UUID(row["payload"]["plan_id"]), created_at=_now()).on_conflict_do_nothing())
            return _to(ScanJob, row)

    def active_scope_runs(self, connection_id: uuid.UUID, profile_id: str, profile_version: int) -> list[ScanJob]:
        """This profile version's queued or running whole-scope runs (BASELINE or SCHEDULE; no trigger is BASELINE) on
        one connection, newest first."""
        payload = scan_jobs.c.payload
        with self.engine.connect() as conn:
            rows = conn.execute(select(scan_jobs).where(
                scan_jobs.c.kind == "scope", scan_jobs.c.connection_id == connection_id,
                scan_jobs.c.status.in_((JobStatus.QUEUED.value, JobStatus.RUNNING.value)),
                payload["profile_id"].as_string() == profile_id,
                payload["profile_version"].as_integer() == profile_version,
                func.coalesce(payload["trigger"].as_string(), "BASELINE").in_(("BASELINE", "SCHEDULE")),
            ).order_by(scan_jobs.c.created_at.desc())).mappings().all()
        return [_to(ScanJob, row) for row in rows]

    # --- learned false-positive profiles ---------------------------------------

    @staticmethod
    def _fp_where(table, key: dict):
        return (table.c.scope_kind == key["scope_kind"], table.c.scope_id == key["scope_id"],
                table.c.source_type == key["source_type"], table.c.detector_name == key["detector_name"],
                table.c.credential_type == key["credential_type"])

    def create_fp_sample(self, sample: FPSample) -> FPSample:
        return self._crud_create(fp_samples, FPSample, sample)

    def list_fp_samples(self, **key) -> list[FPSample]:
        with self.engine.connect() as conn:
            rows = conn.execute(select(fp_samples).where(*self._fp_where(fp_samples, key))
                                .order_by(fp_samples.c.created_at)).mappings().all()
            return [_to(FPSample, dict(r)) for r in rows]

    def delete_fp_samples(self, **key) -> int:
        with self.engine.begin() as conn:
            return conn.execute(delete(fp_samples).where(*self._fp_where(fp_samples, key))).rowcount

    def get_fp_profile(self, **key) -> FPProfile | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(fp_profiles).where(*self._fp_where(fp_profiles, key))).mappings().first()
            return _to(FPProfile, dict(row)) if row else None

    def get_fp_profile_by_id(self, profile_id: uuid.UUID) -> FPProfile | None:
        return self._crud_get(fp_profiles, FPProfile, profile_id)

    def save_fp_profile(self, profile: FPProfile) -> FPProfile:
        key = {k: getattr(profile, k) for k in ("scope_kind", "scope_id", "source_type", "detector_name", "credential_type")}
        existing = self.get_fp_profile(**key)
        if existing is None:
            return self._crud_create(fp_profiles, FPProfile, profile)
        return self._crud_update(fp_profiles, FPProfile, existing.id,
                                 profile.model_dump(exclude={"id", "created_at", "updated_at"}))

    def list_fp_profiles(self) -> list[FPProfile]:
        with self.engine.connect() as conn:
            rows = conn.execute(select(fp_profiles).order_by(fp_profiles.c.updated_at.desc())).mappings().all()
            return [_to(FPProfile, dict(r)) for r in rows]

    # --- internal workflow tickets -------------------------------------------

    def create_ticket(self, ticket: WorkflowTicket) -> WorkflowTicket:
        return self._crud_create(workflow_tickets, WorkflowTicket, ticket)

    def list_tickets(self, credential_id: uuid.UUID | None = None, *, limit=None, offset=0) -> list[WorkflowTicket]:
        with self.engine.connect() as conn:
            query = select(workflow_tickets).order_by(workflow_tickets.c.created_at.desc(), workflow_tickets.c.id.desc()).offset(offset)
            if credential_id is not None:
                query = query.where(workflow_tickets.c.credential_id == credential_id)
            if limit is not None:
                query = query.limit(limit)
            return [_to(WorkflowTicket, dict(r)) for r in conn.execute(query).mappings().all()]

    def get_ticket(self, ticket_id: uuid.UUID) -> WorkflowTicket | None:
        return self._crud_get(workflow_tickets, WorkflowTicket, ticket_id)

    def update_ticket(self, ticket_id: uuid.UUID, *, expected_version: int | None = None, **changes) -> WorkflowTicket | None:
        expected = {"version": expected_version} if expected_version is not None else None
        return self._crud_update(workflow_tickets, WorkflowTicket, ticket_id, changes, expected=expected)

    # --- connection check ledger --------------------------------------------

    def _record_check_event(self, conn, event: ConnectionCheckEvent) -> ConnectionCheckEvent:
        values = event.model_dump(exclude={"id"})
        # Serialize stage stamps with the connection's terminal evidence update.
        conn.execute(select(connections.c.id).where(connections.c.id == event.connection_id).with_for_update()).first()
        existing = conn.execute(select(connection_check_events).where(
            connection_check_events.c.job_id == event.job_id,
            connection_check_events.c.stage == event.stage)).mappings().first()
        if existing:
            if existing["connection_id"] != event.connection_id:
                raise ValueError("credential check identity mismatch")
            return _to(ConnectionCheckEvent, existing)
        latest = conn.execute(select(func.max(connection_check_events.c.recorded_at)).where(
            connection_check_events.c.connection_id == event.connection_id)).scalar()
        stamp = event.recorded_at or _now()
        if latest is not None:
            if latest.tzinfo is None:
                latest = latest.replace(tzinfo=_dt.UTC)
            if stamp <= latest:
                stamp = latest + _dt.timedelta(microseconds=1)
        values.update(id=uuid.uuid4(), recorded_at=stamp)
        statement = self._insert(conn, connection_check_events).values(**values).on_conflict_do_nothing(
            index_elements=[connection_check_events.c.job_id, connection_check_events.c.stage])
        conn.execute(statement)
        row = conn.execute(select(connection_check_events).where(
            connection_check_events.c.job_id == event.job_id,
            connection_check_events.c.stage == event.stage)).mappings().one()
        return _to(ConnectionCheckEvent, row)

    def record_check_event(self, event: ConnectionCheckEvent) -> ConnectionCheckEvent:
        with self.engine.begin() as conn:
            self._require_scan_schema(conn)
            return self._record_check_event(conn, event)

    def finish_credential_check(self, job: ScanJob, connection_changes: dict,
                                event: ConnectionCheckEvent, error: str | None = None) -> ScanJob:
        allowed_changes = {"credential_evidence", "last_error", "last_verified_at", "status"}
        if set(connection_changes) - allowed_changes:
            raise ValueError("unsupported credential check connection update")
        with self.engine.begin() as conn:
            self._require_scan_schema(conn)
            if conn.dialect.name == "sqlite":
                conn.execute(update(scan_jobs).where(scan_jobs.c.id == job.id).values(status=scan_jobs.c.status))
            current = conn.execute(select(scan_jobs).where(scan_jobs.c.id == job.id).with_for_update()).mappings().first()
            if (current is None or current["kind"] != "credential-check" or event.stage != "TERMINAL"
                    or event.job_id != current["id"] or event.connection_id != current["connection_id"]):
                raise ValueError("credential check identity mismatch")
            if current["status"] in ("SUCCEEDED", "FAILED", "CANCELLED"):
                return _to(ScanJob, current)
            expected = "QUEUED" if event.job_status == "CANCELLED" else "RUNNING"
            if current["status"] != expected:
                raise ValueError("credential check has incompatible job state")
            if event.job_status not in ("COMPLETED", "FAILED", "CANCELLED"):
                raise ValueError("invalid terminal credential check event")
            existing = conn.execute(select(connection_check_events.c.id).where(
                connection_check_events.c.job_id == job.id,
                connection_check_events.c.stage == "TERMINAL")).first()
            if existing:
                raise ValueError("incomplete legacy credential check requires a new job")
            connection = conn.execute(select(connections.c.status, connections.c.secret_ref,
                                             connections.c.credential_evidence).where(
                connections.c.id == current["connection_id"]).with_for_update()).mappings().first()
            if connection is None:
                raise ValueError("credential check connection missing")
            # Compare under the same row lock as the terminal evidence write.
            if (connection_changes and connection["status"] != "DISABLED"
                    and not (connection["credential_evidence"] or {}).get("revoked_at")
                    and connection["secret_ref"] == (current["payload"] or {}).get("secret_ref")):
                conn.execute(update(connections).where(connections.c.id == current["connection_id"]).values(
                    **connection_changes, updated_at=_now()))
            self._record_check_event(conn, event)
            status = {"COMPLETED": "SUCCEEDED", "FAILED": "FAILED", "CANCELLED": "CANCELLED"}[event.job_status]
            if error is not None and status != "FAILED":
                raise ValueError("credential check error requires FAILED event")
            changes = {"status": status, "finished_at": _now(),
                       "error": (error or "CHECK_FAILED")[:2000] if status == "FAILED" else None,
                       "objects": 1 if status == "SUCCEEDED" else 0, "findings": 0}
            conn.execute(update(scan_jobs).where(scan_jobs.c.id == current["id"]).values(**changes))
            return _to(ScanJob, {**dict(current), **changes})

    def list_check_events(self, connection_id: uuid.UUID) -> list[ConnectionCheckEvent]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(connection_check_events)
                .where(connection_check_events.c.connection_id == connection_id)
                .order_by(connection_check_events.c.recorded_at.desc(), connection_check_events.c.id)
            ).mappings().all()
            return [_to(ConnectionCheckEvent, dict(r)) for r in rows]

    # --- ownership reviews (one per finding) --------------------------------

    def get_ownership_review(self, finding_id: uuid.UUID) -> OwnershipReview | None:
        with self.engine.connect() as conn:
            row = conn.execute(
                select(ownership_reviews).where(ownership_reviews.c.finding_id == finding_id)
            ).mappings().first()
            return _to(OwnershipReview, dict(row)) if row else None

    def save_ownership_review(self, review: OwnershipReview) -> OwnershipReview:
        with self.engine.begin() as conn:
            self._lock_review_findings(conn, [review.finding_id])
            row = conn.execute(
                select(ownership_reviews).where(ownership_reviews.c.finding_id == review.finding_id)
            ).mappings().first()
            return self._write_ownership_review(conn, review, row, _now())

    @staticmethod
    def _lock_review_findings(conn, ids) -> set:
        # Lock the parent even before the first review exists. All writers take
        # the same stable order; SQLite needs a write to acquire its database lock.
        if conn.dialect.name == "sqlite":
            conn.execute(update(findings).where(findings.c.id.in_(ids)).values(updated_at=findings.c.updated_at))
        return set(conn.execute(select(findings.c.id).where(findings.c.id.in_(ids))
                                .order_by(findings.c.id).with_for_update()).scalars())

    @staticmethod
    def _write_ownership_review(conn, review, row, now) -> OwnershipReview:
        values = {field: getattr(review, field) for field in (
            "status", "assigned_team", "due_at", "closed_reason", "revision", "updated_by")}
        values["updated_at"] = now
        if row is not None:
            conn.execute(update(ownership_reviews).where(ownership_reviews.c.id == row["id"]).values(**values))
            return _to(OwnershipReview, {**dict(row), **values})
        values.update(id=uuid.uuid4(), finding_id=review.finding_id, created_at=now)
        conn.execute(insert(ownership_reviews).values(**values))
        return _to(OwnershipReview, values)

    def save_ownership_reviews(self, reviews: list[OwnershipReview], *, audit_actor: str | None) -> list[OwnershipReview] | None:
        """Compare all revisions under parent locks and publish one transaction; ``audit_actor`` audits each change in it."""
        ids = {review.finding_id for review in reviews}
        if len(ids) != len(reviews):
            raise ValueError("duplicate ownership review")
        with self.engine.begin() as conn:
            if self._lock_review_findings(conn, ids) != ids:
                return None
            rows = {row["finding_id"]: row for row in conn.execute(
                select(ownership_reviews).where(ownership_reviews.c.finding_id.in_(ids))).mappings()}
            if any(review.revision != (rows[review.finding_id]["revision"] + 1
                    if review.finding_id in rows else 1) for review in reviews):
                return None
            now = _now()
            saved = [self._write_ownership_review(conn, review, rows.get(review.finding_id), now) for review in reviews]
            if audit_actor is not None:
                for review in saved:
                    before = rows.get(review.finding_id)
                    self._record_event(conn, review.audit_event(before["status"] if before else None, audit_actor))
            return saved

    def create_aws_account(self, account: AwsAccount) -> AwsAccount:
        return self._crud_create(aws_accounts, AwsAccount, account)

    def list_aws_accounts(self) -> list[AwsAccount]:
        return self._crud_list(aws_accounts, AwsAccount)

    def get_aws_account(self, account_id: uuid.UUID, *, for_update: bool = False) -> AwsAccount | None:
        if not for_update:
            return self._crud_get(aws_accounts, AwsAccount, account_id)
        if not getattr(self.engine, "_task_bound", False):
            raise ValueError("account row locks require a bound transaction")
        with self.engine.connect() as conn:
            query = select(aws_accounts).where(aws_accounts.c.id == account_id)
            row = conn.execute(query if conn.dialect.name == "sqlite" else query.with_for_update()).mappings().first()
            return _to(AwsAccount, dict(row)) if row else None

    def update_aws_account(self, account_id: uuid.UUID, **changes) -> AwsAccount | None:
        return self._crud_update(aws_accounts, AwsAccount, account_id, changes)

    def update_aws_account_if_revision(self, account_id: uuid.UUID, revision_field: str, revision: int, **changes) -> AwsAccount | None:
        """Compare-and-set: write only while the purpose's access revision is unchanged."""
        if revision_field not in ("access_revision", "remediation_access_revision"):
            raise ValueError("unknown revision field")
        changes = {**changes, "updated_at": _now()}
        with self.engine.begin() as conn:
            result = conn.execute(update(aws_accounts).where(
                aws_accounts.c.id == account_id,
                func.coalesce(aws_accounts.c[revision_field], 1) == revision).values(**changes))
            if result.rowcount == 0:
                return None
            row = conn.execute(select(aws_accounts).where(aws_accounts.c.id == account_id)).mappings().first()
            return _to(AwsAccount, dict(row))

    def create_review(self, review: GovernanceReview) -> GovernanceReview:
        return self._crud_create(governance_reviews, GovernanceReview, review)

    def list_reviews(self, *, limit=None, after=None) -> list[GovernanceReview]:
        return self._crud_list(governance_reviews, GovernanceReview, limit=limit, after=after)

    def get_review(self, review_id: uuid.UUID) -> GovernanceReview | None:
        return self._crud_get(governance_reviews, GovernanceReview, review_id)

    def update_review(self, review_id: uuid.UUID, **changes) -> GovernanceReview | None:
        return self._crud_update(governance_reviews, GovernanceReview, review_id, changes)

    def create_rotation_job(self, job: RotationJob) -> RotationJob:
        return self._crud_create(rotation_jobs, RotationJob, job)

    def list_rotation_jobs(self, *, limit=None, after=None) -> list[RotationJob]:
        return self._crud_list(rotation_jobs, RotationJob, limit=limit, after=after)

    def get_rotation_job(self, job_id: uuid.UUID) -> RotationJob | None:
        return self._crud_get(rotation_jobs, RotationJob, job_id)

    def update_rotation_job(self, job_id: uuid.UUID, **changes) -> RotationJob | None:
        return self._crud_update(rotation_jobs, RotationJob, job_id, changes)

    def create_management_action(self, action: ManagementAction,
                                 audit: Callable[[ManagementAction], FindingEvent] | None = None) -> ManagementAction:
        """``audit`` makes the audit row about the new request; it is recorded in the same transaction."""
        with self.engine.begin() as conn:
            created = self._crud_create(management_actions, ManagementAction, action, connection=conn)
            if audit is not None:
                self._record_event(conn, audit(created))
            return created

    def list_management_actions(self, *, limit=None, after=None) -> list[ManagementAction]:
        return self._crud_list(management_actions, ManagementAction, limit=limit, after=after)

    def get_management_action(self, action_id: uuid.UUID) -> ManagementAction | None:
        return self._crud_get(management_actions, ManagementAction, action_id)

    # --- installation settings ---------------------------------------------

    def get_setting(self, key: str) -> dict | None:
        with self.engine.connect() as conn:
            row = conn.execute(
                select(installation_settings).where(installation_settings.c.key == key)
            ).mappings().first()
        if not row:
            return None
        record = dict(row)
        if record["updated_at"] is not None and record["updated_at"].tzinfo is None:
            record["updated_at"] = record["updated_at"].replace(tzinfo=_dt.UTC)  # SQLite drops tz
        return record

    def list_settings(self, prefix: str) -> list[dict]:
        with self.engine.connect() as conn:
            rows = conn.execute(select(installation_settings).where(
                installation_settings.c.key.startswith(prefix, autoescape=True)
            ).order_by(installation_settings.c.key)).mappings().all()
        records = [dict(row) for row in rows]
        for record in records:
            if record["updated_at"] is not None and record["updated_at"].tzinfo is None:
                record["updated_at"] = record["updated_at"].replace(tzinfo=_dt.UTC)  # SQLite drops tz
        return records

    def delete_settings_before(self, prefix: str, cutoff: _dt.datetime) -> int:
        """Drop records under a prefix that were last written before the cutoff."""
        with self.engine.begin() as conn:
            deleted = conn.execute(delete(installation_settings).where(
                installation_settings.c.key.startswith(prefix, autoescape=True),
                installation_settings.c.updated_at < cutoff).returning(installation_settings.c.key)).all()
        return len(deleted)

    def claim_slot(self, key: str, slot: int, updated_by: str) -> bool:
        """Advance a named slot; exactly one caller wins each value, across replicas."""
        with self.engine.begin() as conn:
            conn.execute(self._insert(conn, installation_settings).values(
                key=key, value={"slot": -1}, updated_by=updated_by, updated_at=_now(),
            ).on_conflict_do_nothing(index_elements=[installation_settings.c.key]))
            current = conn.execute(select(installation_settings.c.value).where(
                installation_settings.c.key == key).with_for_update()).scalar_one()
            if int((current or {}).get("slot", -1)) >= slot:
                return False
            conn.execute(update(installation_settings).where(installation_settings.c.key == key).values(
                value={"slot": slot}, updated_by=updated_by, updated_at=_now()))
        return True

    def record_siem_event(self, event: dict, audit: FindingEvent | None = None) -> bool:
        """Queue one operational event once; the same event_id is never queued twice. ``audit`` commits with an
        event queued now."""
        with self.engine.begin() as conn:
            queued = self._queue_siem(conn, event)
            if queued and audit is not None:
                self._record_event(conn, audit)
            return queued

    def put_setting(self, key: str, value: dict, updated_by: str) -> dict:
        return self.put_settings({key: value}, updated_by)[key]

    def put_settings(self, values: dict[str, dict], updated_by: str) -> dict[str, dict]:
        """Commit all settings together; concurrent first writes use native upsert."""
        now = _now()
        records = {key: {"key": key, "value": dict(value),
                         "updated_by": updated_by, "updated_at": now}
                   for key, value in values.items()}
        with self.engine.begin() as conn:
            for key in sorted(records):
                record = records[key]
                statement = self._insert(conn, installation_settings).values(**record)
                conn.execute(statement.on_conflict_do_update(
                    index_elements=[installation_settings.c.key],
                    set_={name: record[name] for name in ("value", "updated_by", "updated_at")},
                ))
        return records

    def put_revisioned_setting(self, key: str, value: dict, updated_by: str) -> dict:
        """Lock even the first write; revision, value and actor commit together."""
        value = dict(value)
        with self.engine.begin() as conn:
            # The insert serializes SQLite writers; FOR UPDATE locks PostgreSQL's
            # existing row. An absent row is created inside this same transaction.
            conn.execute(self._insert(conn, installation_settings).values(
                key=key, value={"revision": 0}, updated_by=updated_by, updated_at=_now(),
            ).on_conflict_do_nothing(index_elements=[installation_settings.c.key]))
            current = conn.execute(select(installation_settings.c.value).where(
                installation_settings.c.key == key).with_for_update()).scalar_one()
            # Legacy approvals without an explicit revision already count as 1.
            value["revision"] = int(current.get("revision", 1)) + 1
            record = {"key": key, "value": value, "updated_by": updated_by, "updated_at": _now()}
            conn.execute(update(installation_settings).where(
                installation_settings.c.key == key).values(**record))
        return record

    def update_management_action(self, action_id: uuid.UUID, *, expected_status: str | None = None,
                                 audit: FindingEvent | None = None, **changes) -> ManagementAction | None:
        """Change the request if it is still in ``expected_status``; ``audit`` commits with the change."""
        expected = {"status": expected_status} if expected_status is not None else None
        with self.engine.begin() as conn:
            saved = self._crud_update(management_actions, ManagementAction, action_id, changes, expected=expected, connection=conn)
            if saved is not None and audit is not None:
                self._record_event(conn, audit)
            return saved

    # --- connections --------------------------------------------------------

    def create_connection(self, connection: Connection) -> Connection:
        with self.engine.begin() as conn:
            existing = conn.execute(
                select(connections.c.id).where(
                    connections.c.provider == connection.provider,
                    connections.c.name == connection.name,
                )
            ).first()
            if existing is not None:
                raise ValueError(f"connection {connection.provider}/{connection.name} already exists")
            new_id = uuid.uuid4()
            now = _now()
            values = connection.model_dump(exclude={"id", "created_at", "updated_at"})
            values.update(id=new_id, created_at=now, updated_at=now)
            conn.execute(insert(connections).values(**values))
            return _to(Connection, values)

    def get_connection(self, connection_id: uuid.UUID, *, for_update: bool = False) -> Connection | None:
        # A fenced repository keeps this lock through its result transaction.
        query = select(connections).where(connections.c.id == connection_id)
        if for_update:
            query = query.with_for_update(read=True)
        with self.engine.begin() as conn:
            row = conn.execute(query).mappings().first()
            return _to(Connection, row) if row else None

    def list_connections(self) -> list[Connection]:
        return self._crud_list(connections, Connection)

    def update_connection(self, connection_id: uuid.UUID, *, expected_status: str | None = None, **changes) -> Connection | None:
        expected = {"status": expected_status} if expected_status is not None else None
        return self._crud_update(connections, Connection, connection_id, changes, expected=expected)


def _eq_or_null(column, value):
    return column.is_(None) if value is None else column == value


def _insertable(model) -> dict:
    """Model fields that map to columns, dropping the server-managed id/timestamps."""

    data = model.model_dump(exclude={"id", "created_at", "updated_at", "first_seen_at", "last_seen_at"})
    return data


def _to(cls, mapping: dict):
    value = dict(mapping)
    # SQLite returns timezone-aware columns as naive values. Stored timestamps
    # are UTC; retain the same time contract as memory and PostgreSQL reads.
    for key, item in value.items():
        if isinstance(item, _dt.datetime) and item.tzinfo is None:
            value[key] = item.replace(tzinfo=_dt.UTC)
    if cls is Exposure and value.get("redaction_version") != _REDACTION_VERSION:
        # Preserve stored evidence, but do not display contexts from an older
        # masking algorithm. A new complete observation supplies a safe context.
        value["redacted_line"] = None
    return cls.model_validate(value)
