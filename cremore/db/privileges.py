"""Explicit PostgreSQL runtime grants; run provisioning as a database administrator.

No passwords are accepted or printed. Authentication is configured separately.
The schema and database must be dedicated to this installation.
"""

from __future__ import annotations

import argparse
import os
import re
from dataclasses import dataclass

from sqlalchemy import create_engine, text


class DatabasePrivilegeError(RuntimeError):
    """A bounded, non-secret deployment error."""


RUNTIME_ROLES = ("api", "collector", "remediator", "control", "siem")
_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")
_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


def identifier(value: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value) or value.startswith("pg_"):
        raise DatabasePrivilegeError("DATABASE_IDENTIFIER_INVALID")
    return '"' + value + '"'


@dataclass(frozen=True)
class Roles:
    migration: str = "cremore_migration"
    api: str = "cremore_api"
    collector: str = "cremore_collector"
    remediator: str = "cremore_remediator"
    control: str = "cremore_control"
    siem: str = "cremore_siem"

    def validated(self) -> dict[str, str]:
        values = {name: getattr(self, name) for name in ("migration", *RUNTIME_ROLES)}
        for value in values.values():
            identifier(value)
            if value in {"public", "postgres"}:
                raise DatabasePrivilegeError("DATABASE_ROLE_RESERVED")
        if len(set(values.values())) != len(values):
            raise DatabasePrivilegeError("DATABASE_ROLES_MUST_DIFFER")
        return values


DEFAULT_ROLES = Roles()


# Every table has a reviewed role policy. No runtime grant is inherited by a new
# table. gcp_values is a retired raw-value table; migration_archive is offline.
# S=SELECT, I=INSERT, U=UPDATE, D=DELETE. Column grants below are additional.
# The control process sends the Slack alerts (cremore.alerts.delivery): it claims and settles its delivery rows,
# records how a pass went, paces messages and reads what a message names (an S3 exposure's AWS account included).
# Grants are per table and this schema uses no row-level security, so it can also settle or reset any other
# destination's delivery rows and status (a SIEM's), as the SIEM role already can. The API's test message takes
# the same paced slot.
TABLE_ACCESS = {
    # API    collector remediator control SIEM
    "action_plans":                  ("SIU", "S",    "SIU", "S",   ""),
    "aws_accounts":                  ("SIU", "SIU",  "S",   "S",   ""),
    "catalog_indexes":               ("SIU", "SIU",  "",    "",    ""),
    "catalog_resources":             ("SIUD","SIUD", "",    "",    ""),
    "connection_check_events":       ("S",   "SIU",  "SIU", "",    ""),
    "connections":                   ("SIU", "SIU",  "SIU", "S",   ""),
    "coverage_batches":              ("SI",  "SID",  "S",   "",    ""),
    "coverage_connections":          ("SIU", "SIU",  "SU",  "S",   ""),
    "coverage_entities":             ("SIU", "SIUD", "S",   "S",   ""),
    "coverage_records":              ("SI",  "SID",  "S",   "S",   ""),
    "coverage_runs":                 ("SIU", "SIUD", "S",   "S",   ""),
    "coverage_storage_receipts":     ("SIU", "S",    "",    "",    ""),
    "coverage_verdicts":             ("",    "SIUD", "",    "",    ""),
    "credentials":                   ("SU",  "SIU",  "SU",  "S",   ""),
    "custom_rules":                  ("SIUD","S",    "",    "",    ""),
    "exposures":                     ("S",   "SIU",  "S",   "S",   ""),
    "finding_annotations":           ("SIU", "S",    "S",   "S",   ""),
    "finding_contexts":              ("S",   "SIU",  "",    "S",   ""),
    "finding_events":                ("SI",  "SI",   "SI",  "SI",  ""),
    "findings":                      ("SU",  "SIU",  "SU",  "SU",  ""),
    "fp_profiles":                   ("SIU", "SIU",  "",    "",    ""),
    "fp_samples":                    ("SIUD","SIUD", "",    "",    ""),
    "gcp_events":                    ("S",   "SI",   "",    "",    ""),
    "gcp_oauth_sessions":            ("SIUD","",     "",    "",    ""),
    "gcp_objects":                   ("S",   "SIU",  "",    "",    ""),
    "gcp_values":                    ("",    "",     "",    "",    ""),
    "governance_reviews":            ("SIU", "S",    "SU",  "S",   ""),
    "identity_directory_entries":    ("SID", "SID",  "",    "S",   ""),
    "identity_directory_keys":       ("SID", "SID",  "",    "S",   ""),
    "identity_links":                ("S",   "SIUD", "",    "S",   ""),
    "identity_orphans":              ("S",   "SIUD", "S",   "S",   ""),
    "identity_people":               ("S",   "SIUD", "S",   "S",   ""),
    "installation_settings":         ("SIUD","SIUD", "SIU", "SIU", ""),
    "management_actions":            ("SIU", "S",    "SIU", "S",   ""),
    "migration_archive":             ("",    "",     "",    "",    ""),
    "ownership_reviews":             ("SIU", "S",    "S",   "S",   ""),
    "provider_connection_children":  ("SIU", "SIU",  "SU",  "S",   ""),
    "provider_connections":          ("SIUD","SIU",  "SU",  "S",   ""),
    "provider_onboarding_sessions":  ("SIU", "SU",   "SU",  "",    ""),
    "remediation_authorization_nonces": ("", "",     "SI",  "",    ""),
    "rotation_jobs":                 ("SIU", "S",    "SIU", "S",   ""),
    "scan_change_cursors":           ("S",   "SIU",  "",    "",    ""),
    "scan_detection_cache":          ("",    "SIUD", "",    "",    ""),
    "scan_jobs":                     ("SIU", "SIU",  "SIU", "SIU", ""),
    "scan_rescore_state":            ("SIU", "SIU",  "",    "",    ""),
    "scan_request_pacing":           ("SIU", "SIU",  "",    "SIU", ""),
    "scan_root_states":              ("",    "SIU",  "",    "",    ""),
    "scan_task_memberships":         ("S",   "SIU",  "SIU", "",    ""),
    "scan_tasks":                    ("SU",  "SIU",  "SIU", "",    ""),
    "scan_trigger_receipts":         ("SI",  "SID",  "",    "",    ""),
    "schema_migrations":             ("S",   "S",    "S",   "S",   "S"),
    "scope_catalogs":                ("SIU", "SIU",  "",    "",    ""),
    "scope_plans":                   ("SIU", "SIU",  "S",   "S",   ""),
    "scope_profiles":                ("SIU", "S",    "S",   "",    ""),
    "selection_drafts":              ("SIU", "S",    "",    "",    ""),
    "siem_deliveries":                ("SU",  "SD",   "",    "SIU", "SIU"),
    "siem_destination_status":        ("S",   "S",    "",    "SIU", "SIU"),
    "siem_events":                   ("SI",  "SID",  "SI",  "SI",  "S"),
    "workflow_tickets":              ("SIU", "S",    "SIU", "SU",  ""),
}
_CODES = {"S": "SELECT", "I": "INSERT", "U": "UPDATE", "D": "DELETE"}
COLUMN_ACCESS = {
    ("collector", "finding_events", "UPDATE"): {"chain_seq", "chain_mac"},
    # PostgreSQL SELECT FOR UPDATE needs UPDATE on at least one column.
    ("siem", "siem_events", "UPDATE"): {"event_id"},
}


def table_grants(role: str, table: str) -> set[str]:
    if role not in RUNTIME_ROLES:
        raise DatabasePrivilegeError("DATABASE_RUNTIME_ROLE_INVALID")
    return {_CODES[code] for code in TABLE_ACCESS.get(table, ("",) * len(RUNTIME_ROLES))[RUNTIME_ROLES.index(role)]}


def _postgres(conn) -> None:
    if conn.dialect.name != "postgresql":
        raise DatabasePrivilegeError("DATABASE_POSTGRESQL_REQUIRED")
    if int(conn.execute(text("SHOW server_version_num")).scalar_one()) < 160000:
        raise DatabasePrivilegeError("DATABASE_POSTGRESQL_16_REQUIRED")


def _role(conn, name):
    return conn.execute(text("SELECT oid, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, "
                             "rolbypassrls FROM pg_roles WHERE rolname = :name"), {"name": name}).mappings().one_or_none()


def _unprivileged(conn, row) -> None:
    if row is None or any(row[key] for key in ("rolsuper", "rolcreatedb", "rolcreaterole", "rolreplication", "rolbypassrls")):
        raise DatabasePrivilegeError("DATABASE_ROLE_PRIVILEGED")
    if not row["rolcanlogin"]:
        raise DatabasePrivilegeError("DATABASE_LOGIN_ROLE_REQUIRED")
    # NOINHERIT does not prevent SET ROLE. Reject membership altogether.
    if conn.execute(text("SELECT 1 FROM pg_auth_members WHERE member = :oid"), {"oid": row["oid"]}).first():
        raise DatabasePrivilegeError("DATABASE_ROLE_MEMBERSHIP_FORBIDDEN")


def prepare_roles(conn, roles: Roles = DEFAULT_ROLES, schema: str = "cremore") -> None:
    """Create login identities/schema without handling authentication secrets."""
    values, quoted_schema = roles.validated(), identifier(schema)
    _postgres(conn)
    for name in values.values():
        row = _role(conn, name)
        if row is None:
            conn.exec_driver_sql(f"CREATE ROLE {identifier(name)} LOGIN NOSUPERUSER NOCREATEDB "
                                 "NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS")
        else:
            _unprivileged(conn, row)
    owner = conn.execute(text("SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = :schema"),
                         {"schema": schema}).scalar_one_or_none()
    if owner is None:
        conn.exec_driver_sql(f"CREATE SCHEMA {quoted_schema} AUTHORIZATION {identifier(roles.migration)}")
    elif owner != roles.migration:
        raise DatabasePrivilegeError("DATABASE_SCHEMA_OWNER_MISMATCH")
    database = identifier(conn.execute(text("SELECT current_database()")).scalar_one())
    # Dedicated database: PUBLIC's CREATE/TEMP would bypass every role grant.
    conn.exec_driver_sql(f"REVOKE CREATE, TEMPORARY ON DATABASE {database} FROM PUBLIC")
    conn.exec_driver_sql("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    conn.exec_driver_sql(f"REVOKE ALL ON SCHEMA {quoted_schema} FROM PUBLIC")
    for name in values.values():
        quoted = identifier(name)
        conn.exec_driver_sql(f"REVOKE ALL ON DATABASE {database} FROM {quoted}")
        conn.exec_driver_sql(f"GRANT CONNECT ON DATABASE {database} TO {quoted}")
        conn.exec_driver_sql(f"ALTER ROLE {quoted} IN DATABASE {database} SET search_path TO {quoted_schema}, pg_catalog")
        if name != roles.migration:
            conn.exec_driver_sql(f"REVOKE ALL ON SCHEMA {quoted_schema} FROM {quoted}")
            conn.exec_driver_sql(f"GRANT USAGE ON SCHEMA {quoted_schema} TO {quoted}")
    recipients = ", ".join(["PUBLIC", *(identifier(values[name]) for name in RUNTIME_ROLES)])
    for objects in ("TABLES", "SEQUENCES", "FUNCTIONS"):
        conn.exec_driver_sql(f"ALTER DEFAULT PRIVILEGES FOR ROLE {identifier(roles.migration)} "
                             f"REVOKE ALL ON {objects} FROM {recipients}")
        conn.exec_driver_sql(f"ALTER DEFAULT PRIVILEGES FOR ROLE {identifier(roles.migration)} IN SCHEMA {quoted_schema} "
                             f"REVOKE ALL ON {objects} FROM {recipients}")


def grant_runtime(conn, roles: Roles = DEFAULT_ROLES, schema: str = "cremore") -> None:
    """Replace direct grants, including stale column grants; never widen ownership."""
    from cremore.db.schema import metadata

    values, quoted_schema = roles.validated(), identifier(schema)
    _postgres(conn)
    for name in values.values():
        _unprivileged(conn, _role(conn, name))
    rows = conn.execute(text("SELECT c.relname, pg_get_userbyid(c.relowner) AS owner FROM pg_class c "
                             "JOIN pg_namespace n ON n.oid = c.relnamespace "
                             "WHERE n.nspname = :schema AND c.relkind IN ('r', 'p', 'v', 'm', 'f')"),
                        {"schema": schema}).mappings().all()
    if {row["relname"] for row in rows} != set(metadata.tables) or not set(metadata.tables) <= TABLE_ACCESS.keys():
        raise DatabasePrivilegeError("DATABASE_GRANT_SCHEMA_MISMATCH")
    if any(row["owner"] != roles.migration for row in rows):
        raise DatabasePrivilegeError("DATABASE_TABLE_OWNER_MISMATCH")
    recipients = ", ".join(["PUBLIC", *(identifier(values[name]) for name in RUNTIME_ROLES)])
    for objects in ("TABLES", "SEQUENCES", "FUNCTIONS"):
        conn.exec_driver_sql(f"REVOKE ALL ON ALL {objects} IN SCHEMA {quoted_schema} FROM {recipients}")
    for table in metadata.sorted_tables:
        target = f"{quoted_schema}.{identifier(table.name)}"
        columns = ", ".join(identifier(column.name) for column in table.columns)
        conn.exec_driver_sql(f"REVOKE SELECT ({columns}), INSERT ({columns}), UPDATE ({columns}), "
                             f"REFERENCES ({columns}) ON {target} FROM {recipients}")
        for role in RUNTIME_ROLES:
            granted = table_grants(role, table.name)
            if granted:
                conn.exec_driver_sql(f"GRANT {', '.join(sorted(granted))} ON {target} TO {identifier(values[role])}")
            for privilege in ("SELECT", "INSERT", "UPDATE", "REFERENCES"):
                allowed = COLUMN_ACCESS.get((role, table.name, privilege), set())
                if allowed:
                    names = ", ".join(identifier(name) for name in sorted(allowed))
                    conn.exec_driver_sql(f"GRANT {privilege} ({names}) ON {target} TO {identifier(values[role])}")


def verify_runtime(conn, runtime_role: str, schema: str | None = None) -> str:
    """Fail closed on effective privileges, including PUBLIC and column grants."""
    table_grants(runtime_role, "schema_migrations")
    _postgres(conn)
    current, session, active_schema = conn.execute(text("SELECT current_user, session_user, current_schema()")).one()
    schema = active_schema if schema is None else schema
    identifier(schema)
    if current != session or active_schema != schema:
        raise DatabasePrivilegeError("DATABASE_SESSION_IDENTITY_MISMATCH")
    row = _role(conn, current)
    _unprivileged(conn, row)
    params = {"role": current, "oid": row["oid"], "schema": schema}
    if conn.execute(text("SELECT 1 FROM pg_database WHERE datname = current_database() AND "
                         "(datdba = :oid OR has_database_privilege(:role, oid, 'CREATE,TEMP'))"), params).first():
        raise DatabasePrivilegeError("DATABASE_DDL_PRIVILEGE_FORBIDDEN")
    if conn.execute(text("SELECT 1 FROM pg_namespace WHERE nspowner = :oid OR "
                         "(nspname !~ '^pg_' AND nspname <> 'information_schema' "
                         "AND has_schema_privilege(:role, oid, 'CREATE'))"), params).first():
        raise DatabasePrivilegeError("DATABASE_SCHEMA_PRIVILEGE_FORBIDDEN")
    search = conn.execute(text("SELECT current_schemas(false)")).scalar_one()
    if [name for name in search if name != "pg_catalog"] != [schema]:
        raise DatabasePrivilegeError("DATABASE_SEARCH_PATH_INVALID")
    if conn.execute(text("SELECT 1 FROM pg_shdepend WHERE refclassid='pg_authid'::regclass "
                         "AND refobjid=:oid AND deptype='o' AND (dbid=0 OR "
                         "dbid=(SELECT oid FROM pg_database WHERE datname=current_database()))"), params).first():
        raise DatabasePrivilegeError("DATABASE_OBJECT_OWNERSHIP_FORBIDDEN")
    if conn.execute(text("SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
                         "WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' "
                         "AND p.prosecdef AND has_function_privilege(:role, p.oid, 'EXECUTE')"), params).first():
        raise DatabasePrivilegeError("DATABASE_DEFINER_FUNCTION_FORBIDDEN")
    # Catalog queries inspect effective rights without selecting forbidden data.
    # Batch the checks in PostgreSQL instead of one round trip per column/right.
    privileges = (*_PRIVILEGES, "MAINTAIN") if conn.dialect.server_version_info >= (17,) else _PRIVILEGES
    relation_sql = (" FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                    "WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' ")
    if conn.execute(text("SELECT 1" + relation_sql + "AND CASE WHEN c.relkind='S' "
                         "THEN has_sequence_privilege(:role, c.oid, 'USAGE,SELECT,UPDATE') ELSE false END"), params).first():
        raise DatabasePrivilegeError("DATABASE_SEQUENCE_PRIVILEGE_FORBIDDEN")
    rights = conn.execute(text(
        "SELECT n.nspname, c.relname, p.privilege, has_table_privilege(:role, c.oid, p.privilege) AS actual, "
        "has_table_privilege(:role, c.oid, p.privilege || ' WITH GRANT OPTION') AS delegated "
        "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "CROSS JOIN unnest(CAST(:privileges AS text[])) AS p(privilege) "
        "WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' "
        "AND c.relkind IN ('r', 'p', 'v', 'm', 'f')"), {**params, "privileges": list(privileges)}).mappings()
    for right in rights:
        allowed = table_grants(runtime_role, right["relname"]) if right["nspname"] == schema else set()
        if right["actual"] != (right["privilege"] in allowed) or right["delegated"]:
            raise DatabasePrivilegeError("DATABASE_TABLE_PRIVILEGE_MISMATCH")
    columns = conn.execute(text(
        "SELECT n.nspname, c.relname, a.attname, p.privilege, "
        "has_column_privilege(:role, c.oid, a.attnum, p.privilege) AS actual, "
        "has_column_privilege(:role, c.oid, a.attnum, p.privilege || ' WITH GRANT OPTION') AS delegated "
        "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "JOIN pg_attribute a ON a.attrelid=c.oid "
        "CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','REFERENCES']) AS p(privilege) "
        "WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' "
        "AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND a.attnum>0 AND NOT a.attisdropped"), params).mappings()
    for right in columns:
        allowed = table_grants(runtime_role, right["relname"]) if right["nspname"] == schema else set()
        extra = COLUMN_ACCESS.get((runtime_role, right["relname"], right["privilege"]), set()) if right["nspname"] == schema else set()
        expected = right["privilege"] in allowed or right["attname"] in extra
        if right["actual"] != expected or right["delegated"]:
            raise DatabasePrivilegeError("DATABASE_COLUMN_PRIVILEGE_MISMATCH")
    return schema


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "grant"))
    parser.add_argument("--schema", default="cremore")
    for role, name in Roles().validated().items():
        parser.add_argument(f"--{role}-role", default=name)
    args = parser.parse_args(argv)
    engine = None
    try:
        roles = Roles(**{role: getattr(args, role + "_role") for role in ("migration", *RUNTIME_ROLES)})
        roles.validated()
        identifier(args.schema)
        engine = create_engine(os.environ["DATABASE_URL"], hide_parameters=True)
        with engine.begin() as conn:
            if args.phase == "prepare":
                prepare_roles(conn, roles, args.schema)
            else:
                grant_runtime(conn, roles, args.schema)
        print("DATABASE_PRIVILEGES_READY")
        return 0
    except Exception:  # noqa: BLE001 -- driver exceptions may contain credentials.
        print("DATABASE_PRIVILEGES_FAILED")
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
