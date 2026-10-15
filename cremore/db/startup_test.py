"""Startup compatibility, fail-closed policy, and secret-safe process errors."""

from types import SimpleNamespace

import pytest
from sqlalchemy import event, text

from cremore.db import startup as boot
from cremore.db.privileges import RUNTIME_ROLES, DatabasePrivilegeError
from cremore.db.privileges_test import (
    pg_roles as pg_roles,  # noqa: PLC0414 -- isolated PostgreSQL roles
)
from cremore.db.sql import make_engine


def test_legacy_bootstrap_remains_idempotent():
    engine = make_engine("sqlite:///:memory:")
    try:
        boot.startup(SimpleNamespace(), engine)
        boot.startup(SimpleNamespace(isolated_deployment=False), engine)
        with engine.connect() as conn:
            boot.compatible_schema(conn)
    finally:
        engine.dispose()


def test_isolated_sqlite_is_rejected_without_ddl():
    engine = make_engine("sqlite:///:memory:")
    seen = []
    event.listen(engine, "before_cursor_execute", lambda _c, _u, sql, *_: seen.append(sql))
    try:
        with pytest.raises(DatabasePrivilegeError, match="POSTGRESQL_REQUIRED"):
            boot.startup(SimpleNamespace(isolated_deployment=True), engine, runtime_role="api")
        assert not seen
    finally:
        engine.dispose()


def test_isolated_mixed_worker_is_rejected():
    engine = make_engine("sqlite:///:memory:")
    try:
        with pytest.raises(DatabasePrivilegeError, match="RUNTIME_ROLE_INVALID"):
            boot.startup(SimpleNamespace(isolated_deployment=True, worker_execution_role="mixed"), engine)
    finally:
        engine.dispose()


@pytest.mark.parametrize("change, expected", [
    ("DROP TABLE finding_annotations", "TABLES_MISSING"),
    ("ALTER TABLE finding_events DROP COLUMN note", "COLUMNS_INCOMPATIBLE"),
    ("DELETE FROM schema_migrations WHERE version=2", "MIGRATIONS_INCOMPLETE"),
    # Not migrated to the schedule origin (version 14): no origin, so no upgrade skip or hold, until it runs.
    ("DELETE FROM schema_migrations WHERE version=14", "MIGRATIONS_INCOMPLETE"),
    ("UPDATE schema_migrations SET name='old' WHERE version=7", "SCAN_INDEX_MIGRATION"),
])
def test_readonly_compatibility_detects_incomplete_schema(change, expected):
    engine = make_engine("sqlite:///:memory:")
    try:
        boot.startup(SimpleNamespace(), engine)
        with engine.begin() as conn:
            conn.execute(text(change))
        seen = []
        event.listen(engine, "before_cursor_execute", lambda _c, _u, sql, *_: seen.append(sql))
        with engine.connect() as conn, pytest.raises(boot.DatabaseSchemaError, match=expected):
            boot.compatible_schema(conn)
        assert all(sql.lstrip().upper().startswith(("SELECT", "PRAGMA")) for sql in seen)
    finally:
        engine.dispose()


def test_postgres_an_isolated_runtime_refuses_a_database_not_migrated_to_the_schedule_origin(pg_roles):
    """A database from before version 14 has no schedule origin. Every isolated runtime refuses it, as for the other
    migrations, until the migration role runs ``initialize``, which records the origin as the schema owner with the
    database's clock; the runtimes then start and only read it."""
    from datetime import UTC, datetime

    from cremore.db.privileges import identifier
    from cremore.db.sql import SqlRepository
    from cremore.scanning import trigger_settings

    schema = identifier(pg_roles.schema)
    try:
        with pg_roles.admin.begin() as conn:
            conn.exec_driver_sql(f"DELETE FROM {schema}.schema_migrations WHERE version=14")
            conn.exec_driver_sql(f"DELETE FROM {schema}.installation_settings WHERE key='scan_schedule_origin'")
        for role in RUNTIME_ROLES:
            with pytest.raises(boot.DatabaseSchemaError, match="DATABASE_MIGRATIONS_INCOMPLETE"):
                boot.startup(SimpleNamespace(isolated_deployment=True), pg_roles.engines[role], runtime_role=role)
    finally:
        boot.initialize(pg_roles.engines["migration"])
    for role in RUNTIME_ROLES:
        boot.startup(SimpleNamespace(isolated_deployment=True), pg_roles.engines[role], runtime_role=role)
    api = SqlRepository(pg_roles.engines["api"])
    assert api.get_setting(trigger_settings.ORIGIN_KEY)["updated_by"] == "migration"
    assert trigger_settings.schedule_origin(api, datetime.now(UTC)) is not None


def test_migration_cli_never_prints_driver_error_or_url(monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", "synthetic-sensitive-url")
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic-password-and-row")
    monkeypatch.setattr(boot, "create_engine", fail)
    assert boot.main([]) == 1
    captured = capsys.readouterr()
    assert captured.out == "DATABASE_SCHEMA_INITIALIZATION_FAILED\n" and captured.err == ""


def test_migration_help_does_not_connect(monkeypatch, capsys):
    def fail(*args, **kwargs):
        pytest.fail("help must never connect to a database")
    monkeypatch.setattr(boot, "create_engine", fail)
    with pytest.raises(SystemExit) as stopped:
        boot.main(["--help"])
    assert stopped.value.code == 0
    assert "migration DATABASE_URL" in capsys.readouterr().out
