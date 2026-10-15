"""Offline migration preserves evidence/references and rolls back on failure."""

import uuid
from datetime import UTC

import pytest
from sqlalchemy import delete, func, insert, select, text, update

from cremore.db import migrations
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- guarded PostgreSQL fixture
from cremore.db.schema import (
    connection_check_events,
    exposures,
    finding_events,
    findings,
    fp_samples,
    migration_archive,
    scan_jobs,
    schema_migrations,
)
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import Credential, Exposure, FindingEvent, ScanJob


def legacy_database(tmp_path):
    engine = make_engine(f"sqlite+pysqlite:///{tmp_path / 'legacy.sqlite'}")
    create_all(engine)
    repo = SqlRepository(engine)
    credential = repo.upsert_credential(Credential(fingerprint="synthetic", credential_type="TOKEN"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="s3",
        resource_name="synthetic-bucket", location="config", severity="LOW"))
    finding = repo.upsert_finding(credential.id, exposure.id, "HIGH")
    audit = repo.record_finding_event(FindingEvent(finding_id=finding.id, actor="analyst", event_type="ACKNOWLEDGED"))
    job = repo.enqueue_job(ScanJob(kind="s3"))
    repo.claim_next_job()
    duplicate_id = uuid.uuid4()
    sample_id = uuid.uuid4()
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX exposures_identity_key_unique"))
        conn.execute(text("DROP INDEX connection_check_job_stage_unique"))
        conn.execute(delete(schema_migrations).where(schema_migrations.c.version == 2))
        conn.execute(update(exposures).values(identity_key=None, resource_key=None, container_key=None))
        values = dict(conn.execute(select(exposures)).mappings().one())
        values.update(id=duplicate_id, severity="HIGH", metadata={"historical_evidence": "kept in archive"})
        conn.execute(insert(exposures).values(**values))
        conn.execute(update(findings).where(findings.c.id == finding.id).values(primary_exposure_id=duplicate_id))
        conn.execute(insert(fp_samples).values(id=sample_id, scope_kind="aws", scope_id=uuid.uuid4(),
            source_type="s3", detector_name="synthetic", credential_type="TOKEN", finding_id=finding.id,
            exposure_id=duplicate_id, actor="analyst", features=[]))
    return engine, credential, finding, audit, job, sample_id


def test_offline_migration_archives_evidence_remaps_both_references_and_is_repeatable(tmp_path):
    engine, credential, _finding, audit, job, sample_id = legacy_database(tmp_path)
    with pytest.raises(RuntimeError, match="OFFLINE_SCAN_MIGRATION_REQUIRED"):
        SqlRepository(engine).upsert_credential(credential)
    with pytest.raises(RuntimeError, match="OFFLINE_SCAN_MIGRATION_REQUIRED"):
        SqlRepository(engine).claim_next_job()
    result = migrations.migrate_offline(engine, offline=True, backup_confirmed=True)
    assert result["exposures_merged"] == 1 and result["jobs_requeued"] == 1
    with engine.connect() as conn:
        survivor = conn.execute(select(exposures)).mappings().one()
        assert survivor["severity"] == "HIGH" and survivor["identity_key"]
        assert survivor["resource_key"] and survivor["container_key"]
        assert conn.execute(select(findings.c.primary_exposure_id)).scalar_one() == survivor["id"]
        assert conn.execute(select(fp_samples.c.exposure_id).where(fp_samples.c.id == sample_id)).scalar_one() == survivor["id"]
        assert conn.execute(select(finding_events.c.id)).scalar_one() == audit.id
        archived = conn.execute(select(migration_archive)).mappings().all()
        assert len([a for a in archived if a["table_name"] == "exposures"]) == 2
        assert any(a["record"].get("metadata", {}).get("historical_evidence") for a in archived)
        assert conn.execute(select(scan_jobs.c.status).where(scan_jobs.c.id == job.id)).scalar_one() == "QUEUED"
    assert migrations.migrate_offline(engine, offline=True, backup_confirmed=True)["exposures_merged"] == 0
    assert SqlRepository(engine).upsert_credential(credential).id == credential.id


def test_migration_requires_explicit_offline_and_backup_confirmation(tmp_path):
    engine, *_ = legacy_database(tmp_path)
    for kwargs in ({}, {"offline": True}, {"backup_confirmed": True}):
        with pytest.raises(ValueError, match="backup"):
            migrations.migrate_offline(engine, **kwargs)
    with engine.connect() as conn:
        assert conn.execute(select(func.count()).select_from(exposures)).scalar_one() == 2


def test_migration_failure_restores_duplicate_rows_references_and_version(tmp_path, monkeypatch):
    engine, _, _finding, _, _, _ = legacy_database(tmp_path)
    with engine.connect() as conn:
        original_primary = conn.execute(select(findings.c.primary_exposure_id)).scalar_one()
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic archive failure")
    monkeypatch.setattr(migrations, "_archive", fail)
    with pytest.raises(RuntimeError, match="archive failure"):
        migrations.migrate_offline(engine, offline=True, backup_confirmed=True)
    with engine.connect() as conn:
        assert conn.execute(select(func.count()).select_from(exposures)).scalar_one() == 2
        assert conn.execute(select(findings.c.primary_exposure_id)).scalar_one() == original_primary
        assert not migrations.identity_ready(conn)


def test_check_history_consolidation_preserves_originals_and_does_not_replay_old_terminal(tmp_path):
    engine, *_ = legacy_database(tmp_path)
    job_id, connection_id = uuid.uuid4(), uuid.uuid4()
    from datetime import datetime, timedelta
    now = datetime.now(UTC)
    with engine.begin() as conn:
        conn.execute(insert(scan_jobs).values(id=job_id, kind="credential-check", status="RUNNING", connection_id=connection_id))
        for i, outcome in enumerate(("ACTIVE", "REJECTED")):
            conn.execute(insert(connection_check_events).values(id=uuid.uuid4(), job_id=job_id,
                connection_id=connection_id, stage="TERMINAL", job_status="COMPLETED", outcome=outcome,
                recorded_at=now + timedelta(seconds=i)))
    result = migrations.migrate_offline(engine, offline=True, backup_confirmed=True)
    assert result["check_events_merged"] == 1
    with engine.connect() as conn:
        assert conn.execute(select(connection_check_events.c.outcome)).scalar_one() == "REJECTED"
        assert conn.execute(select(scan_jobs.c.status).where(scan_jobs.c.id == job_id)).scalar_one() == "FAILED"
        assert conn.execute(select(func.count()).select_from(migration_archive).where(
            migration_archive.c.table_name == "connection_check_events")).scalar_one() == 2


def test_legacy_running_job_before_first_finding_still_requires_and_gets_recovery(tmp_path):
    engine = make_engine(f"sqlite+pysqlite:///{tmp_path / 'empty-findings.sqlite'}")
    create_all(engine)
    repo = SqlRepository(engine)
    job = repo.enqueue_job(ScanJob(kind="s3"))
    repo.claim_next_job()
    with engine.begin() as conn:
        conn.execute(delete(schema_migrations).where(schema_migrations.c.version == 2))
    create_all(engine)
    with engine.connect() as conn:
        assert not migrations.identity_ready(conn)
    assert migrations.migrate_offline(engine, offline=True, backup_confirmed=True)["jobs_requeued"] == 1
    assert repo.get_job(job.id).status == "QUEUED"


def test_component_pair_lookup_is_indexed_on_an_upgraded_installation(tmp_path):
    """An existing installation gets the index too, not only a fresh database."""
    engine = make_engine(f"sqlite+pysqlite:///{tmp_path / 'upgrade.sqlite'}")
    create_all(engine)

    def has_index():
        with engine.connect() as conn:
            return conn.execute(text(
                "SELECT 1 FROM sqlite_master WHERE type='index' AND name='credentials_provider_type'")).first() is not None

    assert has_index()
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX credentials_provider_type"))
        conn.execute(delete(schema_migrations).where(
            schema_migrations.c.version == migrations.CREDENTIAL_LOOKUP_VERSION))
    assert not has_index()

    create_all(engine)  # the next startup
    assert has_index()
    create_all(engine)  # idempotent: the ledger entry stops a second attempt
    assert has_index()


def test_alert_claims_read_the_owed_index_on_an_upgraded_installation(tmp_path):
    """An existing installation gets the alert channel's index at the next startup, and the claim reads through it
    instead of every delivery row the destination holds."""
    from sqlalchemy import event

    from cremore.siem.outbox import SiemOutbox

    engine = make_engine(f"sqlite+pysqlite:///{tmp_path / 'owed.sqlite'}")
    create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX siem_deliveries_owed"))
        conn.execute(delete(schema_migrations).where(schema_migrations.c.version == migrations.SIEM_OWED_VERSION))
    create_all(engine)  # the next startup
    outbox = SiemOutbox(SqlRepository(engine))
    statements = []
    event.listen(engine, "before_cursor_execute",
                 lambda _conn, _cursor, statement, parameters, _context, _many: statements.append((statement, parameters)))
    assert outbox.claim_owed("cremore.slack-alerts") == []
    statement, parameters = next(item for item in statements if item[0].lstrip().upper().startswith("SELECT")
                                 and "FROM siem_deliveries" in item[0])
    with engine.connect() as conn:
        plan = " ".join(row[-1] for row in conn.exec_driver_sql("EXPLAIN QUERY PLAN " + statement, parameters))
    assert "USING INDEX siem_deliveries_owed" in plan


def test_the_component_pair_join_starts_from_credentials_not_exposures(tmp_path):
    """Without this index the JSON comparison forces a full scan of credentials."""
    from cremore.db.schema import credentials

    engine = make_engine(f"sqlite+pysqlite:///{tmp_path / 'plan.sqlite'}")
    create_all(engine)
    query = select(exposures).join(credentials, credentials.c.id == exposures.c.credential_id).join(
        findings, findings.c.credential_id == credentials.c.id).where(
            credentials.c.provider == "aws", credentials.c.credential_type == "AWS_ACCESS_KEY",
            exposures.c.metadata["aws_id_component_fingerprint"].as_string() == "a" * 64)
    statement = "EXPLAIN QUERY PLAN " + str(query.compile(engine, compile_kwargs={"literal_binds": True}))

    with engine.connect() as conn:
        plan = " ".join(row[-1] for row in conn.execute(text(statement)))
    assert "SEARCH credentials USING INDEX credentials_provider_type" in plan
    assert "SCAN exposures" not in plan


GLPI_SETUP = {"system": "glpi", "values": {"url": "https://glpi.acme.test/glpi", "client_id": "cremore-client"},
              "sealed": {"version": 1, "ciphertext": "synthetic-sealed-sign-in"}, "secret_names": ["client_secret"]}


def removed_ticket_system_once(engine):
    """Migration 15 deletes the removed built-in system's saved setup (its sealed sign-in in it) once, and nothing
    else: a plugin system's setup and other settings stay."""
    repo = SqlRepository(engine)

    def upgrade():  # an installation from before version 15 starts this version
        with engine.begin() as conn:
            conn.execute(delete(schema_migrations).where(
                schema_migrations.c.version == migrations.BUILTIN_TICKET_SYSTEM_VERSION))
        create_all(engine)

    def ledger():
        with engine.connect() as conn:
            return conn.execute(select(schema_migrations.c.name).where(
                schema_migrations.c.version == migrations.BUILTIN_TICKET_SYSTEM_VERSION)).scalar_one_or_none()

    assert ledger() == "builtin_ticket_system_removed"  # a new database records it with nothing to delete
    repo.put_setting("ticket_system", GLPI_SETUP, "ada")
    repo.put_setting("ticket_system_note", {"system": "glpi"}, "ada")  # another key: not the setup
    create_all(engine)
    assert repo.get_setting("ticket_system")["value"] == GLPI_SETUP  # recorded: a restart runs nothing
    upgrade()
    assert repo.get_setting("ticket_system") is None and ledger() == "builtin_ticket_system_removed"
    assert repo.get_setting("ticket_system_note")["value"] == {"system": "glpi"}
    repo.put_setting("ticket_system", GLPI_SETUP, "ada")
    create_all(engine)  # re-running is a no-op
    with engine.begin() as conn:
        migrations.removed_ticket_system(conn)
    assert repo.get_setting("ticket_system")["value"] == GLPI_SETUP
    plugin = {"system": "servicenow", "values": {"url": "https://tickets.acme.test"}, "sealed": None,
              "secret_names": []}
    repo.put_setting("ticket_system", plugin, "ada")
    upgrade()
    assert repo.get_setting("ticket_system")["value"] == plugin  # a plugin system's setup is kept


def test_the_removed_builtin_ticket_systems_setup_is_deleted_once_on_sqlite(tmp_path):
    engine = make_engine(f"sqlite+pysqlite:///{tmp_path / 'tickets.sqlite'}")
    create_all(engine)
    removed_ticket_system_once(engine)


def test_postgres_the_removed_builtin_ticket_systems_setup_is_deleted_once(pg):
    removed_ticket_system_once(pg[0])


def test_the_removed_builtin_ticket_systems_setup_is_deleted_on_memory():
    """The same cleanup on an in-memory repository (no ledger): the removed system's setup goes, a plugin setup and
    unrelated settings stay, and a rerun changes nothing."""
    from copy import deepcopy

    from cremore.db.repository import InMemoryRepository

    repo = InMemoryRepository()
    repo.put_setting("ticket_system", GLPI_SETUP, "ada")
    repo.put_setting("ticket_system_note", {"system": "glpi"}, "ada")  # another key that starts the same: not the setup
    repo.put_setting("ticket-system:lock", {"slot": 0}, "system:ticketing")
    repo.put_setting("contact_delivery", {"console_url": "https://cremore.example.com"}, "ada")
    migrations.removed_ticket_system(repo)
    assert repo.get_setting("ticket_system") is None
    assert {row["key"] for row in repo.list_settings("")} == {"ticket_system_note", "ticket-system:lock",
                                                            "contact_delivery"}
    kept = deepcopy(repo.installation_settings)
    migrations.removed_ticket_system(repo)  # a rerun
    assert repo.installation_settings == kept
    plugin = {"system": "servicenow", "values": {"url": "https://tickets.acme.test"}, "sealed": None, "secret_names": []}
    repo.put_setting("ticket_system", plugin, "ada")
    kept = deepcopy(repo.installation_settings)
    migrations.removed_ticket_system(repo)
    assert repo.installation_settings == kept and repo.get_setting("ticket_system")["value"] == plugin
