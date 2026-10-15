"""Offline, all-or-nothing migration of persisted authentication references.

Only authentication columns and declared settings paths are written. Collected
values, findings, fingerprints, audit events and coverage observations are never
read or changed. Unknown authentication references fail the entire transaction;
an operator can supply their SHA-256 -> binding mapping after offline review.
Run with every writer stopped and a verified backup. The flags acknowledge that
operational prerequisite; they do not stop processes or create a backup.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import MetaData, Table, and_, inspect, select, update

from cremore.secretstore.isolation import V3_PREFIX, binding_for_record
from cremore.secretstore.sealed import SealedSecretError, is_sealed, seal_fields, unseal


class MigrationError(ValueError):
    pass


_TABLES = {
    "provider_connections", "provider_onboarding_sessions", "connections", "coverage_connections",
    "scan_jobs", "scan_tasks", "gcp_oauth_sessions", "installation_settings", "scope_profiles", "scope_catalogs",
    "selection_drafts",
}
_CONTROL_SETTINGS = {"gcp_oauth_client": [("sealed",)], "ticket_system": [("sealed",)],
                     "contact_delivery": [("mail", "sealed"), ("slack", "sealed")]}
_CONTROL_PREFIXES = ("github_app_manifest:", "aws_sso_login:")
_REF_NAMES = {"secret_ref", "secret_refs"}


def _digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _replace_refs(value, convert):
    """Only typed authentication slots; never inline content or finding bodies."""
    out = copy.deepcopy(value)
    if not isinstance(out, dict):
        return out
    for key in _REF_NAMES:
        item = out.get(key)
        if isinstance(item, str):
            out[key] = convert(item)
        elif isinstance(item, dict):
            out[key] = {name: convert(ref) for name, ref in item.items()}
    for key in ("spec", "connection", "payload"):
        if isinstance(out.get(key), dict):
            out[key] = _replace_refs(out[key], convert)
    return out


def _sealed_paths(value, prefix=()):
    """Settings contain configuration only; unknown secret locations stop migration."""
    if isinstance(value, str) and is_sealed(value):
        yield prefix, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _sealed_paths(item, (*prefix, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _sealed_paths(item, (*prefix, index))


def _set_path(value, path, replacement):
    place = value
    for key in path[:-1]:
        place = place[key]
    place[path[-1]] = replacement


def migrate(engine, legacy_keys, recipient_keys, control_keys, *, offline=False, backup_confirmed=False,
            bindings=None):
    """Migrate one database atomically. Repeating it leaves ciphertext unchanged.

    ``bindings`` maps SHA-256(reference) to a reviewed authority binding for
    historical references no longer attached to a provider owner. No plaintext
    credential or database URL is returned, logged or written to a manifest.
    """
    if not offline or not backup_confirmed:
        raise MigrationError("SECRET_MIGRATION_OFFLINE_AND_BACKUP_REQUIRED")
    explicit = dict(bindings or {})
    replacements, subjects = {}, {}
    changed = {}
    with engine.begin() as conn:
        names = set(inspect(conn).get_table_names()) & _TABLES
        metadata = MetaData()
        tables = {name: Table(name, metadata, autoload_with=conn) for name in names}
        # PostgreSQL table locks reject concurrent writers for the transaction;
        # offline operation is still required across the other application tables.
        if conn.dialect.name == "postgresql":
            for name in sorted(names):
                conn.exec_driver_sql(f'LOCK TABLE "{name}" IN EXCLUSIVE MODE')
        rows = {name: [dict(row) for row in conn.execute(select(table)).mappings()]
                for name, table in tables.items()}

        def save(name, row, **values):
            values = {key: value for key, value in values.items() if value != row.get(key)}
            if not values:
                return
            table = tables[name]
            conn.execute(update(table).where(and_(*(column == row[column.name] for column in table.primary_key)))
                         .values(**values))
            changed[name] = changed.get(name, 0) + 1

        def register(ref, binding):
            if not isinstance(ref, str) or not ref:
                raise MigrationError("SECRET_MIGRATION_REFERENCE_INVALID")
            prior = subjects.get(ref)
            if prior is not None and prior != binding:
                raise MigrationError("SECRET_MIGRATION_AMBIGUOUS_OWNER")
            subjects[ref] = binding

        for name in ("provider_connections", "provider_onboarding_sessions"):
            for row in rows.get(name, []):
                owner = row if name == "provider_connections" else row["data"]
                for ref in (owner.get("secret_refs") or {}).values():
                    register(ref, binding_for_record(owner))
        for row in rows.get("installation_settings", []):
            if row["key"] == "machine_identity" and row["value"].get("secret"):
                from cremore.identity.machine import machine_binding

                register(row["value"]["secret"], machine_binding(row["value"]))

        def connector(ref):
            if not isinstance(ref, str) or not ref:
                raise MigrationError("SECRET_MIGRATION_REFERENCE_INVALID")
            binding = subjects.get(ref) or explicit.get(_digest(ref))
            if binding is None:
                raise MigrationError("SECRET_MIGRATION_UNOWNED_REFERENCE:" + _digest(ref))
            if ref in replacements:
                return replacements[ref]
            if ref.startswith(V3_PREFIX):
                # Already migrated data stays byte-identical. An offline operator
                # supplies private keys to verify it before removing old roots.
                fields = unseal(recipient_keys, ref, binding=binding)
                if recipient_keys.is_current(ref, binding):
                    fields.clear()
                    return ref
            if ref not in replacements:
                if ref.startswith("vault://"):
                    from cremore.secretstore.resolver import parse_ref

                    parse_ref(ref)
                    fields = {"vault_ref": ref}
                elif not ref.startswith(V3_PREFIX):
                    fields = unseal(legacy_keys, ref)
                try:
                    replacements[ref] = seal_fields(recipient_keys, fields, binding=binding)
                    # Both correct key placement and ciphertext integrity are
                    # verified before the transaction may commit.
                    verified = unseal(recipient_keys, replacements[ref], binding=binding)
                    if verified != fields:
                        raise MigrationError("SECRET_MIGRATION_VERIFY_FAILED")
                    verified.clear()
                finally:
                    fields.clear()
            return replacements[ref]

        def control(ref):
            if not is_sealed(ref):
                raise MigrationError("SECRET_MIGRATION_CONTROL_REFERENCE_INVALID")
            try:
                opened = unseal(control_keys, ref)
                if ref.startswith("sealed:v2:" + str(control_keys.current_id) + ":"):
                    opened.clear()
                    return ref
            except SealedSecretError:
                opened = unseal(legacy_keys, ref)
            try:
                sealed = seal_fields(control_keys, opened)
                verified = unseal(control_keys, sealed)
                if verified != opened:
                    raise MigrationError("SECRET_MIGRATION_VERIFY_FAILED")
                verified.clear()
                return sealed
            finally:
                opened.clear()

        for row in rows.get("provider_connections", []):
            refs = {role: connector(ref) for role, ref in row["secret_refs"].items()}
            checks = copy.deepcopy(row.get("checks") or {})
            from cremore.onboarding.service import check_digest

            # Transport-only re-encryption keeps the checked provider principal
            # and permission proof; stale evidence must remain stale.
            if checks.get("digest") == check_digest(row):
                checks["digest"] = check_digest({**row, "secret_refs": refs})
            save("provider_connections", row, secret_refs=refs, checks=checks)
        for row in rows.get("provider_onboarding_sessions", []):
            save("provider_onboarding_sessions", row, data=_replace_refs(row["data"], connector))

        revisions = {}
        for row in rows.get("connections", []):
            if not row.get("secret_ref"):
                continue
            ref = connector(row["secret_ref"])
            if ref != row["secret_ref"]:
                from cremore.domain.models import Connection
                from cremore.scanning.scope import auth_revision

                source = Connection.model_validate(row)
                revisions[("source", str(row["id"]), auth_revision("source", source))] = auth_revision(
                    "source", source.model_copy(update={"secret_ref": ref}))
            save("connections", row, secret_ref=ref)
        for row in rows.get("coverage_connections", []):
            save("coverage_connections", row, spec=_replace_refs(row["spec"], connector))
        retired_runs = set()
        for name in ("scan_jobs", "scan_tasks"):
            for row in rows.get(name, []):
                payload = _replace_refs(row["payload"], connector)
                retirement = {}
                if ((payload != row["payload"] or row.get("run_id") in retired_runs)
                        and row["status"] in {"QUEUED", "RUNNING", "CANCELLING"}):
                    # Execution snapshots and checkpoints are historical evidence;
                    # do not rewrite their policy/lease digests to bless new work.
                    retirement = {"status": "CANCELLED", "finished_at": datetime.now(UTC),
                                  "error": "CREDENTIAL_SEALING_MIGRATED_REQUEUE"}
                    if name == "scan_jobs":
                        retired_runs.add(row["id"])
                    else:
                        retirement.update(token=None, lease_until=None)
                save(name, row, payload=payload, **retirement)

        for name in ("scope_profiles", "scope_catalogs", "selection_drafts"):
            for row in rows.get(name, []):
                key = (row.get("kind"), str(row.get("connection_id")), row.get("auth_revision"))
                if key in revisions:
                    save(name, row, auth_revision=revisions[key])

        for row in rows.get("gcp_oauth_sessions", []):
            data = copy.deepcopy(row["data"])
            for key in ("pending", "sealed"):
                if data.get(key):
                    data[key] = control(data[key])
            save("gcp_oauth_sessions", row, data=data)
        for row in rows.get("installation_settings", []):
            key, value = row["key"], copy.deepcopy(row["value"])
            allowed = set(_CONTROL_SETTINGS.get(key, ()))
            if key.startswith(_CONTROL_PREFIXES):
                allowed.add(("sealed",))
            for path, ref in _sealed_paths(value):
                if path in allowed:
                    _set_path(value, path, control(ref))
                elif key == "machine_identity" and path == ("secret",):
                    _set_path(value, path, connector(ref))
                else:
                    raise MigrationError("SECRET_MIGRATION_UNCLASSIFIED_SETTING")
            save("installation_settings", row, value=value)
    return {"changed_rows": changed, "connector_references": len(replacements)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--backup-confirmed", action="store_true")
    parser.add_argument("--bindings-file", help="Reviewed SHA-256(reference) to binding JSON map")
    args = parser.parse_args()
    if not args.offline or not args.backup_confirmed:
        parser.error("--offline and --backup-confirmed are required")
    from sqlalchemy import create_engine

    from cremore.config import Settings
    from cremore.secretstore.isolation import RecipientKeys

    engine = None
    try:
        settings = Settings()
        legacy = settings.model_copy(update={"isolated_deployment": False})
        ring = RecipientKeys.from_files(settings.sealing_public_keys_file, settings.sealing_private_keys_file)
        controls = settings.model_copy(update={"isolated_deployment": True}).control_sealing_keys
        bindings = json.loads(Path(args.bindings_file).read_text(encoding="utf-8")) if args.bindings_file else None
        engine = create_engine(settings.database_url)
        result = migrate(engine, legacy.sealing_keys, ring, controls, offline=True, backup_confirmed=True, bindings=bindings)
    except Exception as exc:  # noqa: BLE001 -- driver errors may include raw authentication columns.
        # SQL/driver/provider exceptions can include SQL values and credentials.
        code = str(exc) if isinstance(exc, MigrationError) else "SECRET_MIGRATION_FAILED"
        parser.exit(1, code + "\n")
    finally:
        if engine is not None:
            engine.dispose()
    print(json.dumps({**result, "completed_at": datetime.now(UTC).isoformat()}, sort_keys=True))


if __name__ == "__main__":
    main()
