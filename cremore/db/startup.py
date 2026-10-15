"""Explicit schema initialization and DDL-free isolated runtime startup.

Run ``python -m cremore.db.startup`` with the migration DATABASE_URL before
starting isolated runtime processes. Existing offline data migrations retain
their separate stopped-process/backup requirements.
"""

from __future__ import annotations

import argparse
import os

from sqlalchemy import (
    CheckConstraint,
    Float,
    UniqueConstraint,
    create_engine,
    inspect,
    select,
    text,
)

from cremore.db.privileges import DatabasePrivilegeError, identifier, verify_runtime


class DatabaseSchemaError(RuntimeError):
    """A schema must be migrated before this runtime may start."""


def _same_type(actual, expected, dialect) -> bool:
    # SQLite reflects the UUID's CHAR storage representation; PostgreSQL may
    # reflect FLOAT as DOUBLE PRECISION. Both retain their declared semantics.
    return (actual.compile(dialect=dialect) == expected.compile(dialect=dialect)
            or isinstance(actual, Float) and isinstance(expected, Float)
            and expected.precision is None and actual.precision in {None, 53})


def compatible_schema(conn, schema: str | None = None) -> None:
    """Read-only verification of the schema of record and the migration ledger."""
    from cremore.db import migrations
    from cremore.db.schema import metadata, schema_migrations

    inspector = inspect(conn)
    existing = set(inspector.get_table_names(schema=schema))
    if not set(metadata.tables) <= existing:
        raise DatabaseSchemaError("DATABASE_TABLES_MISSING_RUN_MIGRATION")
    columns_by_table = inspector.get_multi_columns(schema=schema)
    primary_by_table = inspector.get_multi_pk_constraint(schema=schema)
    uniques_by_table = inspector.get_multi_unique_constraints(schema=schema)
    foreign_by_table = inspector.get_multi_foreign_keys(schema=schema)
    checks_by_table = inspector.get_multi_check_constraints(schema=schema)
    for table in metadata.sorted_tables:
        columns = {column["name"]: column for column in columns_by_table[(schema, table.name)]}
        for expected in table.columns:
            actual = columns.get(expected.name)
            if (actual is None or not _same_type(actual["type"], expected.type, conn.dialect)
                    or actual["nullable"] != expected.nullable):
                raise DatabaseSchemaError(f"DATABASE_COLUMNS_INCOMPATIBLE_RUN_MIGRATION:{table.name}.{expected.name}")
        if primary_by_table[(schema, table.name)]["constrained_columns"] != [col.name for col in table.primary_key]:
            raise DatabaseSchemaError("DATABASE_PRIMARY_KEY_INCOMPATIBLE")
        unique_columns = {tuple(item["column_names"]) for item in uniques_by_table[(schema, table.name)]}
        check_names = {item["name"] for item in checks_by_table[(schema, table.name)]}
        for constraint in table.constraints:
            if isinstance(constraint, UniqueConstraint) and tuple(col.name for col in constraint.columns) not in unique_columns:
                raise DatabaseSchemaError("DATABASE_UNIQUE_CONSTRAINT_MISSING")
            if isinstance(constraint, CheckConstraint) and constraint.name and constraint.name not in check_names:
                raise DatabaseSchemaError("DATABASE_CHECK_CONSTRAINT_MISSING")
        foreign = {(tuple(item["constrained_columns"]), item["referred_schema"] or schema,
                    item["referred_table"], tuple(item["referred_columns"]),
                    item["options"].get("ondelete")) for item in foreign_by_table[(schema, table.name)]}
        for constraint in table.foreign_key_constraints:
            expected = (tuple(col.name for col in constraint.columns), constraint.referred_table.schema or schema,
                        constraint.referred_table.name,
                        tuple(element.column.name for element in constraint.elements), constraint.ondelete)
            if expected not in foreign:
                raise DatabaseSchemaError("DATABASE_FOREIGN_KEY_INCOMPATIBLE")
    versions = dict(conn.execute(select(schema_migrations.c.version, schema_migrations.c.name)).all())
    required = {1, migrations.IDENTITY_VERSION, migrations.SCAN_SLOT_VERSION,
                migrations.AUDIT_TARGET_VERSION, migrations.CREDENTIAL_LOOKUP_VERSION,
                migrations.METADATA_COVERAGE_VERSION, migrations.SCAN_SLOT_KINDS_VERSION,
                migrations.SIEM_EVENT_KINDS_VERSION, migrations.ORPHAN_TICKETS_VERSION,
                migrations.AUDIT_CHAIN_VERSION, migrations.SCAN_CONNECTION_SLOTS_VERSION,
                migrations.SCAN_EVENT_LANE_VERSION, migrations.SIEM_OWED_VERSION,
                migrations.SCHEDULE_ORIGIN_VERSION}
    if conn.dialect.name != "postgresql":
        # The legacy SQLite creator declares nullable targets directly and has
        # never run PostgreSQL's version-4 ALTER migration.
        required.discard(migrations.AUDIT_TARGET_VERSION)
    if not required <= versions.keys():
        raise DatabaseSchemaError("DATABASE_MIGRATIONS_INCOMPLETE")
    if versions[migrations.SCAN_SLOT_KINDS_VERSION] != migrations._slot_kinds():
        raise DatabaseSchemaError("DATABASE_SCAN_INDEX_MIGRATION_REQUIRED")
    if conn.dialect.name == "postgresql":
        indexes = {(row.table_name, row.index_name): (row.indisunique, row.indisvalid, row.indisready)
                   for row in conn.execute(text(
                       "SELECT t.relname AS table_name, i.relname AS index_name, x.indisunique, x.indisvalid, x.indisready "
                       "FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid "
                       "JOIN pg_class t ON t.oid=x.indrelid JOIN pg_namespace n ON n.oid=t.relnamespace "
                       "WHERE n.nspname=:schema"), {"schema": schema})}
        for table in metadata.sorted_tables:
            for index in table.indexes:
                if indexes.get((table.name, index.name)) != (bool(index.unique), True, True):
                    raise DatabaseSchemaError("DATABASE_INDEXES_INCOMPATIBLE_RUN_MIGRATION")


def startup(settings, engine, *, runtime_role: str | None = None) -> None:
    """Legacy bootstrap by default; isolated processes validate and never run DDL."""
    if not getattr(settings, "isolated_deployment", False):
        from cremore.db.sql import create_all

        create_all(engine)
        return
    role = runtime_role or getattr(settings, "worker_execution_role", "mixed")
    with engine.connect() as conn:
        schema = verify_runtime(conn, role)
        compatible_schema(conn, schema)


def initialize(engine) -> None:
    """Only a distinct, unprivileged schema owner can perform additive migrations."""
    from cremore.db.privileges import _postgres, _role, _unprivileged
    from cremore.db.sql import create_all

    with engine.connect() as conn:
        _postgres(conn)
        current, session, schema = conn.execute(text("SELECT current_user, session_user, current_schema()")).one()
        identifier(schema)
        if current != session:
            raise DatabasePrivilegeError("DATABASE_SESSION_IDENTITY_MISMATCH")
        _unprivileged(conn, _role(conn, current))
        owner = conn.execute(text("SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname=:schema"),
                             {"schema": schema}).scalar_one()
        if owner != current:
            raise DatabasePrivilegeError("DATABASE_MIGRATION_OWNER_REQUIRED")
        if conn.execute(text("SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                             "WHERE n.nspname=:schema AND pg_get_userbyid(c.relowner) <> :role "
                             "AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')"),
                        {"schema": schema, "role": current}).first():
            raise DatabasePrivilegeError("DATABASE_TABLE_OWNER_MISMATCH")
    create_all(engine)
    with engine.connect() as conn:
        compatible_schema(conn, schema)


def main(argv=None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    engine = None
    try:
        engine = create_engine(os.environ["DATABASE_URL"], hide_parameters=True)
        initialize(engine)
        print("DATABASE_SCHEMA_READY")
        return 0
    except Exception:  # noqa: BLE001 -- connection/migration errors may include passwords or row values.
        print("DATABASE_SCHEMA_INITIALIZATION_FAILED")
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
