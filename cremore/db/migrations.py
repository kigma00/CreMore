"""Numbered schema ledger and explicit, offline identity consolidation.

Run only with API/workers stopped and a verified database backup. Startup never
backfills a populated installation. Rollback uses that backup; original merged
rows and changed references are additionally retained in migration_archive.
"""

from __future__ import annotations

import argparse
import json
import os
import uuid
from collections import Counter
from datetime import UTC

from sqlalchemy import Index, delete, func, insert, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from cremore.db.scan_state import (
    SEVERITY_RANK,
    exposure_container_key,
    exposure_identity,
    exposure_resource_key,
    observation_metadata,
)
from cremore.db.schema import (
    AUDIT_CHAIN_INDEX,
    AUDIT_POSITION_CHECK,
    AUDIT_UNSEALED_INDEX,
    ONE_ACTIVE_CONTENT_SCAN,
    SIEM_OWED_INDEX,
    connection_check_events,
    credentials,
    exposures,
    findings,
    fp_samples,
    installation_settings,
    migration_archive,
    scan_jobs,
    schema_migrations,
)
from cremore.domain.models import CONTENT_SCAN_KINDS

IDENTITY_VERSION = 2
IDENTITY_INDEX = Index("exposures_identity_key_unique", exposures.c.identity_key, unique=True)
CHECK_INDEX = Index("connection_check_job_stage_unique", connection_check_events.c.job_id,
                    connection_check_events.c.stage, unique=True)
CREDENTIAL_INDEX = Index("exposures_credential_status", exposures.c.credential_id, exposures.c.status)
CONNECTION_INDEX = Index("exposures_connection", exposures.c.source_connection_id)
RESOURCE_INDEX = Index("exposures_resource_lookup", exposures.c.resource_key)
CONTAINER_INDEX = Index("exposures_container_lookup", exposures.c.container_key)
CREDENTIAL_LOOKUP_INDEX = Index("credentials_provider_type", credentials.c.provider, credentials.c.credential_type)


def _record_version(conn, version: int, name: str) -> None:
    if conn.execute(select(schema_migrations.c.version).where(schema_migrations.c.version == version)).first() is None:
        conn.execute(insert(schema_migrations).values(version=version, name=name))


def startup_migrations(conn) -> None:
    _record_version(conn, 1, "additive_scan_observation_schema")
    if conn.execute(select(schema_migrations.c.version).where(schema_migrations.c.version == IDENTITY_VERSION)).first():
        return
    # A new/empty database needs no data migration. A populated old installation
    # stays readable but cannot start new scan writes until the offline command.
    populated = conn.execute(select(exposures.c.id).limit(1)).first()
    checks = conn.execute(select(connection_check_events.c.id).limit(1)).first()
    jobs = conn.execute(select(scan_jobs.c.id).limit(1)).first()
    if populated is None and checks is None and jobs is None:
        _indexes(conn)
        _record_version(conn, IDENTITY_VERSION, "offline_identity_and_check_lifecycle")


AUDIT_TARGET_VERSION = 4


def audit_targets(conn) -> None:
    """Let the audit trail hold events that are not about a finding."""

    if conn.execute(select(schema_migrations.c.version).where(
            schema_migrations.c.version == AUDIT_TARGET_VERSION)).first():
        return
    if conn.dialect.name == "postgresql":
        conn.exec_driver_sql("ALTER TABLE finding_events ALTER COLUMN finding_id DROP NOT NULL")
        conn.exec_driver_sql("ALTER TABLE finding_events ADD COLUMN IF NOT EXISTS target_type TEXT NOT NULL DEFAULT 'finding'")
        conn.exec_driver_sql("ALTER TABLE finding_events ADD COLUMN IF NOT EXISTS target_id UUID")
        conn.exec_driver_sql("UPDATE finding_events SET target_id = finding_id WHERE target_id IS NULL")
    _record_version(conn, AUDIT_TARGET_VERSION, "audit_trail_targets")


SIEM_EVENT_KINDS_VERSION = 8


def siem_event_kinds(conn) -> None:
    """Let the SIEM outbox hold operational events, which are about no finding."""

    if conn.execute(select(schema_migrations.c.version).where(
            schema_migrations.c.version == SIEM_EVENT_KINDS_VERSION)).first():
        return
    if conn.dialect.name == "postgresql":
        conn.exec_driver_sql("ALTER TABLE siem_events ALTER COLUMN finding_id DROP NOT NULL")
    _record_version(conn, SIEM_EVENT_KINDS_VERSION, "siem_operational_events")


ORPHAN_TICKETS_VERSION = 9


def orphan_tickets(conn) -> None:
    """Let a governance ticket be about a departed owner's credential, which has no finding."""

    if conn.execute(select(schema_migrations.c.version).where(
            schema_migrations.c.version == ORPHAN_TICKETS_VERSION)).first():
        return
    if conn.dialect.name == "postgresql":
        conn.exec_driver_sql("ALTER TABLE workflow_tickets ALTER COLUMN credential_id DROP NOT NULL")
        conn.exec_driver_sql("ALTER TABLE workflow_tickets ALTER COLUMN finding_id DROP NOT NULL")
        conn.exec_driver_sql("ALTER TABLE workflow_tickets ADD COLUMN IF NOT EXISTS orphan_ref UUID")
    _record_version(conn, ORPHAN_TICKETS_VERSION, "departed_owner_tickets")


AUDIT_CHAIN_VERSION = 10


def audit_chain_index(conn) -> None:
    """One audit row per chain position, positions from 1, and the unsealed rows in order. The columns themselves
    are nullable and added at startup; a new database gets the check with its table."""
    if conn.execute(select(schema_migrations.c.version).where(
            schema_migrations.c.version == AUDIT_CHAIN_VERSION)).first():
        return
    AUDIT_CHAIN_INDEX.create(conn, checkfirst=True)
    AUDIT_UNSEALED_INDEX.create(conn, checkfirst=True)
    if conn.dialect.name == "postgresql" and not conn.execute(text(
            "SELECT 1 FROM pg_constraint WHERE conname = :name AND conrelid = 'finding_events'::regclass"),
            {"name": AUDIT_POSITION_CHECK}).first():
        # NOT VALID: no scan of the whole trail under an exclusive lock at startup. Every write from now on is
        # checked; a row already below 1 is what verification reports as SEQUENCE_INVALID.
        conn.exec_driver_sql(f"ALTER TABLE finding_events ADD CONSTRAINT {AUDIT_POSITION_CHECK} "
                             "CHECK (chain_seq IS NULL OR chain_seq >= 1) NOT VALID")
    _record_version(conn, AUDIT_CHAIN_VERSION, "audit_trail_hash_chain")


SIEM_OWED_VERSION = 13


def siem_owed_index(conn) -> None:
    """The undelivered delivery rows per destination, which the Slack alert channel claims each pass
    (cremore/alerts/delivery.py); without it every pass reads all of that destination's rows."""
    if conn.execute(select(schema_migrations.c.version).where(
            schema_migrations.c.version == SIEM_OWED_VERSION)).first():
        return
    SIEM_OWED_INDEX.create(conn, checkfirst=True)
    _record_version(conn, SIEM_OWED_VERSION, "siem_deliveries_owed")


SCHEDULE_ORIGIN_VERSION = 14
SCHEDULE_ORIGIN_KEY = "scan_schedule_origin"


def schedule_origin(conn) -> None:
    """Record when this version's database was migrated, by the database's clock, once (cremore.scanning.trigger_settings
    .schedule_origin): a scope approved before it skips the full-scan slot already due then and holds its policy sweeps
    until the next one has ended. A new database records it before any scope is saved, so none is skipped. A record
    already there (an earlier build recorded it on a poll) is kept, and a row deleted later is not recorded again."""
    if conn.execute(select(schema_migrations.c.version).where(
            schema_migrations.c.version == SCHEDULE_ORIGIN_VERSION)).first():
        return
    now = conn.execute(select(func.now())).scalar_one()
    now = now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)  # SQLite's CURRENT_TIMESTAMP is UTC
    statement = (pg_insert if conn.dialect.name == "postgresql" else sqlite_insert)(installation_settings)
    conn.execute(statement.values(key=SCHEDULE_ORIGIN_KEY, value={"at": now.isoformat()}, updated_by="migration",
                                  updated_at=now).on_conflict_do_nothing(index_elements=[installation_settings.c.key]))
    _record_version(conn, SCHEDULE_ORIGIN_VERSION, "scan_schedule_origin")


BUILTIN_TICKET_SYSTEM_VERSION = 15
TICKET_SYSTEM_KEY = "ticket_system"  # cremore.ticketing.setup.SETTING_KEY
_REMOVED_BUILTIN = "glpi"  # the built-in adapter this version removed


def _removed_builtin(value) -> bool:
    return isinstance(value, dict) and value.get("system") == _REMOVED_BUILTIN


def removed_ticket_system(target) -> None:
    """Delete, once, the saved setup of the built-in ticket system this version removed, with the sign-in secrets
    sealed in it. Data only, and not a runtime requirement (startup does not check it): a plugin system's setup is
    kept, a request asked through the removed one reads as not set up (owner approvals expire on their own) and an
    exposure response asked through it can be asked again (cremore.governance.response, its server binding changed).

    ``target``: the schema transaction's connection (create_all records the ledger with it), or an in-memory
    repository, which has no ledger and keeps nothing across processes: there the deletion alone is the migration,
    and a rerun finds nothing to delete."""
    from cremore.db.repository import InMemoryRepository

    if isinstance(target, InMemoryRepository):
        with target._lock:  # the repository's own lock: the exact key, never a prefix
            record = target.installation_settings.get(TICKET_SYSTEM_KEY)
            if record is not None and _removed_builtin(record.get("value")):
                del target.installation_settings[TICKET_SYSTEM_KEY]
        return
    if target.execute(select(schema_migrations.c.version).where(
            schema_migrations.c.version == BUILTIN_TICKET_SYSTEM_VERSION)).first():
        return
    row = target.execute(select(installation_settings.c.value).where(
        installation_settings.c.key == TICKET_SYSTEM_KEY).with_for_update()).first()
    if row is not None and _removed_builtin(row.value):
        target.execute(delete(installation_settings).where(installation_settings.c.key == TICKET_SYSTEM_KEY))
    _record_version(target, BUILTIN_TICKET_SYSTEM_VERSION, "builtin_ticket_system_removed")


CREDENTIAL_LOOKUP_VERSION = 5
METADATA_COVERAGE_VERSION = 6


def metadata_coverage(conn) -> None:
    """Add only the two metadata projections; preserve every v1 row and writer."""
    from cremore.coverage.metadata_store import register_tables
    from cremore.db.schema import metadata

    for table in register_tables(metadata):
        table.create(conn, checkfirst=True)
    _record_version(conn, METADATA_COVERAGE_VERSION, "coverage_v2_entity_record_projections")


def credential_lookup_index(conn) -> None:
    """Index the provider/type filter the AWS component-pair join starts from.

    ``find_component_pairs`` compares a component fingerprint held inside exposure
    metadata, which no index serves; the join is only cheap because it starts from
    the few AWS pair credentials and reaches exposures by credential_id. Without
    this index that start is a full scan of credentials on every credential
    detail view. The metadata comparison stays a per-candidate recheck; promote
    the two component fingerprints to real columns if that recheck ever dominates.
    """
    if conn.execute(select(schema_migrations.c.version).where(
            schema_migrations.c.version == CREDENTIAL_LOOKUP_VERSION)).first():
        return
    CREDENTIAL_LOOKUP_INDEX.create(conn, checkfirst=True)
    _record_version(conn, CREDENTIAL_LOOKUP_VERSION, "credentials_provider_type_lookup")


SCAN_SLOT_VERSION = 3
# Which content kinds the installed index covers. Its WHERE clause lists them,
# so a newly registered source kind needs the index rebuilt, not just a constant.
SCAN_SLOT_KINDS_VERSION = 7
SCAN_CONNECTION_SLOTS_VERSION = 11
# The slot is per connection and lane (cremore.db.repository.job_lane): a change event's run beside a sweep.
SCAN_EVENT_LANE_VERSION = 12


def _slot_kinds() -> str:
    return "running_content_connection_kinds:" + ",".join(CONTENT_SCAN_KINDS)


def ensure_scan_slot(conn) -> bool:
    """Replace global enqueue exclusion with per-connection execution slots, one per lane.

    Queue rows and audit history are untouched. Old incompatible RUNNING rows
    must drain first. Deploy with old API/workers stopped; mixed binaries still
    disagree about admission. The ledger prevents silent index-semantic drift.
    The lane index only relaxes the per-connection one, so rows the old index
    admitted never stop it; a database that had no index waits for its drain.
    """
    installed = conn.execute(select(schema_migrations.c.version).where(
        schema_migrations.c.version == SCAN_SLOT_VERSION)).first() is not None
    covered = conn.execute(select(schema_migrations.c.name).where(
        schema_migrations.c.version == SCAN_SLOT_KINDS_VERSION)).scalar_one_or_none()
    upgraded = conn.execute(select(schema_migrations.c.version).where(
        schema_migrations.c.version == SCAN_CONNECTION_SLOTS_VERSION)).first() is not None
    laned = conn.execute(select(schema_migrations.c.version).where(
        schema_migrations.c.version == SCAN_EVENT_LANE_VERSION)).first() is not None
    if installed and upgraded and laned and covered == _slot_kinds():
        return True
    running = conn.execute(select(scan_jobs.c.connection_id, scan_jobs.c.lane).where(
        scan_jobs.c.status.in_(("RUNNING", "CANCELLING")), scan_jobs.c.kind.in_(CONTENT_SCAN_KINDS))).all()
    # Grouped here, not in SQL: a NULL lane is a sweep, exactly as the index's coalesce reads it.
    slots = Counter((cid, lane or "sweep") for cid, lane in running)
    if any(count > 1 for count in slots.values()) or (len(running) > 1 and any(cid is None for cid, _ in running)):
        return False
    # Expression indexes are not reflected, so ask the catalog by name.
    catalog = ("SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = :name" if conn.dialect.name == "postgresql"
               else "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = :name")
    exists = conn.execute(text(catalog), {"name": ONE_ACTIVE_CONTENT_SCAN.name}).first() is not None
    if conn.execute(text(catalog), {"name": "scan_jobs_one_active_content_scan"}).first():
        conn.exec_driver_sql("DROP INDEX scan_jobs_one_active_content_scan")
    if exists and installed:
        ONE_ACTIVE_CONTENT_SCAN.drop(conn)
        exists = False
    if not exists:
        ONE_ACTIVE_CONTENT_SCAN.create(conn)
    _record_version(conn, SCAN_SLOT_VERSION, "one_active_content_scan")
    _record_version(conn, SCAN_CONNECTION_SLOTS_VERSION, "durable_queue_connection_execution_slots")
    _record_version(conn, SCAN_EVENT_LANE_VERSION, "connection_execution_slot_per_lane")
    if covered is None:
        _record_version(conn, SCAN_SLOT_KINDS_VERSION, _slot_kinds())
    else:
        conn.execute(update(schema_migrations).where(
            schema_migrations.c.version == SCAN_SLOT_KINDS_VERSION).values(name=_slot_kinds()))
    return True


def identity_ready(conn) -> bool:
    return conn.execute(select(schema_migrations.c.version).where(
        schema_migrations.c.version == IDENTITY_VERSION)).first() is not None


def _indexes(conn) -> None:
    for index in (IDENTITY_INDEX, CHECK_INDEX, CREDENTIAL_INDEX, CONNECTION_INDEX, RESOURCE_INDEX, CONTAINER_INDEX,
                  CREDENTIAL_LOOKUP_INDEX):
        index.create(conn, checkfirst=True)


def _archive(conn, table, row: dict, canonical_id) -> None:
    already = conn.execute(select(migration_archive.c.id).where(
        migration_archive.c.migration_version == IDENTITY_VERSION,
        migration_archive.c.table_name == table.name,
        migration_archive.c.original_id == row["id"])).first()
    if already is None:
        conn.execute(insert(migration_archive).values(
            id=uuid.uuid4(), migration_version=IDENTITY_VERSION, table_name=table.name,
            original_id=row["id"], canonical_id=canonical_id,
            record=json.loads(json.dumps(dict(row), default=str))))


def migrate_offline(engine, *, offline: bool = False, backup_confirmed: bool = False) -> dict:
    if not offline or not backup_confirmed:
        raise ValueError("Stop every API/worker and verify a database backup before offline migration")
    from cremore.db.sql import _SCHEMA_LOCK_KEY, create_all

    create_all(engine)
    totals = {"exposures_backfilled": 0, "exposures_merged": 0, "check_events_merged": 0,
              "jobs_requeued": 0}
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _SCHEMA_LOCK_KEY})
            conn.execute(text("LOCK TABLE exposures, findings, fp_samples, connection_check_events, scan_jobs IN ACCESS EXCLUSIVE MODE"))
        elif conn.dialect.name == "sqlite":
            conn.exec_driver_sql("BEGIN IMMEDIATE")
        if identity_ready(conn):
            return totals
        # The nullable key can be indexed before filling it. Keep the stage
        # index until after check-history duplicates have been archived.
        IDENTITY_INDEX.create(conn, checkfirst=True)
        # Keyset batches bound memory and avoid cursor invalidation while deleting.
        after = None
        while True:
            query = select(exposures).order_by(exposures.c.id).limit(500)
            if after is not None:
                query = query.where(exposures.c.id > after)
            batch = conn.execute(query).mappings().all()
            if not batch:
                break
            for row in batch:
                after = row["id"]
                key = exposure_identity(row)
                canonical = conn.execute(select(exposures).where(
                    exposures.c.identity_key == key, exposures.c.id != row["id"])).mappings().first()
                if canonical is None:
                    conn.execute(update(exposures).where(exposures.c.id == row["id"]).values(
                        identity_key=key, resource_key=exposure_resource_key(row), container_key=exposure_container_key(row)))
                    totals["exposures_backfilled"] += 1
                    continue
                _archive(conn, exposures, canonical, canonical["id"])
                _archive(conn, exposures, row, canonical["id"])
                for table, column in ((findings, findings.c.primary_exposure_id), (fp_samples, fp_samples.c.exposure_id)):
                    for ref in conn.execute(select(table).where(column == row["id"])).mappings():
                        _archive(conn, table, ref, ref["id"])
                    conn.execute(update(table).where(column == row["id"]).values({column.name: canonical["id"]}))
                newest = max((canonical, row), key=lambda r: r["last_seen_at"])
                severity = max((canonical["severity"], row["severity"]), key=lambda s: SEVERITY_RANK.get(s, -1))
                active = canonical["status"] != "REMOVED" or row["status"] != "REMOVED"
                merged_metadata = observation_metadata(canonical["metadata"], newest["metadata"])
                conn.execute(update(exposures).where(exposures.c.id == canonical["id"]).values(
                    resource_key=exposure_resource_key(canonical),
                    container_key=exposure_container_key({**canonical, "metadata": merged_metadata}),
                    first_seen_at=min(canonical["first_seen_at"], row["first_seen_at"]),
                    last_seen_at=max(canonical["last_seen_at"], row["last_seen_at"]), severity=severity,
                    status="OPEN" if active else "REMOVED", removed_at=None if active else newest["removed_at"],
                    metadata=merged_metadata,
                    redacted_line=newest["redacted_line"], redaction_version=newest["redaction_version"]))
                conn.execute(delete(exposures).where(exposures.c.id == row["id"]))
                totals["exposures_merged"] += 1
        # Keep the newest logical stage; every original remains in the archive.
        after = None
        while True:
            query = select(connection_check_events).order_by(connection_check_events.c.id).limit(500)
            if after is not None:
                query = query.where(connection_check_events.c.id > after)
            batch = conn.execute(query).mappings().all()
            if not batch:
                break
            for row in batch:
                after = row["id"]
                group = conn.execute(select(connection_check_events).where(
                    connection_check_events.c.job_id == row["job_id"],
                    connection_check_events.c.stage == row["stage"]).order_by(
                    connection_check_events.c.recorded_at.desc(), connection_check_events.c.id)).mappings().all()
                if len(group) < 2:
                    continue
                for duplicate in group:
                    _archive(conn, connection_check_events, duplicate, group[0]["id"])
                for duplicate in group[1:]:
                    conn.execute(delete(connection_check_events).where(connection_check_events.c.id == duplicate["id"]))
                    totals["check_events_merged"] += 1
        _indexes(conn)
        # Credential checks with a persisted terminal observation are NOT blindly
        # replayed: recovery requires a fresh check job, preserving the old history.
        terminal = select(connection_check_events.c.job_id).where(connection_check_events.c.stage == "TERMINAL")
        conn.execute(update(scan_jobs).where(scan_jobs.c.status == "RUNNING", scan_jobs.c.kind == "credential-check",
                     scan_jobs.c.id.in_(terminal)).values(status="FAILED", error="INTERRUPTED_TERMINAL_CHECK_REQUIRES_NEW_JOB"))
        totals["jobs_requeued"] = conn.execute(update(scan_jobs).where(scan_jobs.c.status == "RUNNING").values(
            status="QUEUED", started_at=None, finished_at=None, error=None, objects=0, findings=0,
            objects_failed=0, coverage=None)).rowcount
        _record_version(conn, IDENTITY_VERSION, "offline_identity_and_check_lifecycle")
    return totals


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="All API and worker processes are stopped")
    parser.add_argument("--backup-confirmed", action="store_true", help="A restorable database backup exists")
    args = parser.parse_args()
    url = os.environ.get("DATABASE_URL")
    if not url:
        parser.error("DATABASE_URL must be set; never put credentials in CLI arguments")
    from cremore.db.sql import make_engine
    engine = make_engine(url)
    try:
        print(json.dumps(migrate_offline(engine, offline=args.offline, backup_confirmed=args.backup_confirmed)))
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
