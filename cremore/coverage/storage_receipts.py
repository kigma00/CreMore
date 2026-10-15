"""Admin assertions of past storage, anchored only to committed observations.

A receipt is neither secret-value equality nor evidence of current storage.
Collection records remain immutable; withdrawing a receipt changes no provider.
"""

from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import JSON, Column, DateTime, ForeignKey, Index, Table, Text, Uuid, func, select
from sqlalchemy.exc import IntegrityError

from cremore.coverage.metadata_models import (
    EntityObservation,
    MetadataConnectionSpec,
    entity_id,
    in_metadata_scope,
    metadata_text,
    scope_matches,
    timestamp,
)
from cremore.coverage.models import (
    MAX_BATCH,
    V1_PURPOSE,
    ConnectionSpec,
    Observation,
    digest,
    in_scope,
)
from cremore.coverage.store import CoverageError, CoverageStore, utc

TABLE = "coverage_storage_receipts"


class ReceiptAnchor(BaseModel):
    model_config = ConfigDict(extra="forbid", revalidate_instances="always")
    run_id: uuid.UUID
    batch_index: int = Field(ge=0, le=100000, strict=True)
    item_index: int = Field(ge=0, lt=MAX_BATCH, strict=True)


class StorageReceiptInput(BaseModel):
    model_config = ConfigDict(extra="forbid", revalidate_instances="always")
    id: uuid.UUID
    issuer: ReceiptAnchor
    vault: ReceiptAnchor
    source_system: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", strict=True)
    source_record_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}$", strict=True)
    stored_at: str = Field(min_length=1, max_length=40, strict=True)

    _labels = field_validator("source_system", "source_record_id")(metadata_text)
    @field_validator("stored_at")
    @classmethod
    def past_storage(cls, value):
        result = timestamp(value)
        if datetime.fromisoformat(result) > datetime.now(UTC):
            raise ValueError("RECEIPT_STORED_AT_IN_FUTURE")
        return result


def register_tables(metadata):
    if TABLE in metadata.tables:
        return metadata.tables[TABLE]
    table = Table(TABLE, metadata,
        Column("id", Uuid, primary_key=True),
        Column("request_digest", Text, nullable=False),
        Column("source_system", Text, nullable=False),
        Column("source_record_id", Text, nullable=False),
        Column("stored_at", DateTime(timezone=True), nullable=False),
        Column("submitted_at", DateTime(timezone=True), nullable=False),
        Column("submitted_by", Text, nullable=False),
        Column("revoked_at", DateTime(timezone=True)), Column("revoked_by", Text),
        Column("issuer_connection_id", Uuid, ForeignKey("coverage_connections.id"), nullable=False),
        Column("vault_connection_id", Uuid, ForeignKey("coverage_connections.id"), nullable=False),
        Column("issuer_run_id", Uuid, ForeignKey("coverage_runs.id"), nullable=False),
        Column("vault_run_id", Uuid, ForeignKey("coverage_runs.id"), nullable=False),
        Column("issuer_entity_id", Uuid), Column("issuer_identifier", Text, nullable=False),
        Column("issuer", JSON, nullable=False), Column("vault", JSON, nullable=False))
    Index(TABLE + "_entity", table.c.issuer_entity_id, table.c.submitted_at)
    Index(TABLE + "_issuer", table.c.issuer_connection_id, table.c.issuer_identifier, table.c.submitted_at)
    return table


def _paging(offset, limit, maximum=100):
    if type(offset) is not int or type(limit) is not int or offset < 0 or not 1 <= limit <= maximum:
        raise CoverageError("RECEIPT_INVALID_PAGE")


class StorageReceiptStore(CoverageStore):
    def __init__(self, repo):
        super().__init__(repo)
        if self.engine is None:
            with repo._lock:
                self.memory.setdefault(TABLE, {})
        else:
            from cremore.db.schema import metadata
            setattr(self, TABLE, register_tables(metadata))

    def _batch(self, conn, anchor):
        if conn is None:
            return self.memory["batches"].get((anchor.run_id, anchor.batch_index))
        return conn.execute(select(self.batches).where(self.batches.c.run_id == anchor.run_id,
                            self.batches.c.index == anchor.batch_index)).mappings().first()

    @staticmethod
    def _usable(owner, run):
        if not owner or not owner["enabled"]:
            raise CoverageError("RECEIPT_CONNECTION_DISABLED_OR_MISSING")
        if run["revision"] != owner["revision"]:
            raise CoverageError("RECEIPT_SCOPE_CHANGED")
        if run["status"] not in {"COMPLETE", "PARTIAL"} or run["finished_at"] is None:
            raise CoverageError("RECEIPT_COMPLETED_RUN_REQUIRED")
        if run["contract"].get("schema_version", 1) != owner["spec"].get("schema_version", 1):
            raise CoverageError("RECEIPT_SCOPE_CHANGED")
        if run["contract"].get("schema_version") == 2 and not scope_matches(run["contract"], owner["spec"]):
            # Read through today's model: a connection stored before an option existed
            # is still the scope its later runs collected.
            raise CoverageError("RECEIPT_SCOPE_CHANGED")

    @staticmethod
    def _locator(owner, run, anchor, raw, role):
        """Revalidate stored records; return an allowlist, never the record itself."""
        version = run["contract"].get("schema_version", 1)
        if version == 2:
            selectable = (raw.get("record_type") == "entity_observation" and
                ((role == "issuer" and raw.get("purpose") == "issuer_inventory"
                  and raw.get("identity", {}).get("kind") in {"credential", "public_key"}) or
                 (role == "vault" and raw.get("purpose") == "vault_metadata"
                  and raw.get("identity", {}).get("kind") in {"vault_item", "vault_version"})))
        else:
            selectable = ((role == "issuer" and raw.get("evidence") == "ISSUED") or
                          (role == "vault" and raw.get("evidence") in {"VALUE", "IDENTIFIER", "UNRESOLVED"}
                           and V1_PURPOSE.get(owner["spec"]["provider"]) == "vault_metadata"))
        if not selectable:
            raise CoverageError("RECEIPT_OBSERVATION_ROLE_MISMATCH")
        try:
            if version == 2:
                from cremore.coverage.providers import validate_record
                spec = MetadataConnectionSpec.model_validate(owner["spec"])
                item = EntityObservation.model_validate(raw)
                valid = in_metadata_scope(spec, item) and validate_record(spec, item, trusted_discovery=True)
                locator = {"entity_id": str(entity_id(item.identity, owner["id"])),
                    "reference": item.identity.object_id, "version": item.value_match.version if item.value_match else "",
                    "origin": item.identity.origin, "tenant": item.identity.tenant,
                    "tenant_confirmed": item.identity.tenant_confirmed, "kind": item.identity.kind}
            else:
                spec = ConnectionSpec.model_validate(owner["spec"])
                item = Observation.model_validate(raw)
                valid = in_scope(spec, item)
                locator = {"reference": item.reference, "version": item.version, "identifier": item.identifier,
                    "account_id": item.account_id, "credential_type": item.credential_type,
                    "namespace": item.namespace, "mount": item.mount}
        except (ValueError, TypeError):
            raise CoverageError("RECEIPT_OBSERVATION_OUTSIDE_SCOPE") from None
        if not valid:
            raise CoverageError("RECEIPT_OBSERVATION_OUTSIDE_SCOPE")
        return {"anchor": anchor.model_dump(mode="json"), "schema_version": version,
            "connection_id": str(owner["id"]), "connection_name": spec.name,
            "connection_revision": owner["revision"], "provider": spec.provider, **locator}

    def _resolve(self, conn, owner, run, anchor, role):
        self._usable(owner, run)
        batch = self._batch(conn, anchor)
        if batch is None or anchor.item_index >= len(batch["items"]):
            raise CoverageError("RECEIPT_OBSERVATION_NOT_FOUND")
        return self._locator(owner, run, anchor, batch["items"][anchor.item_index], role)

    def _owners(self, conn, rows):
        ids = {row[name + "_connection_id"] for row in rows for name in ("issuer", "vault")}
        if conn is None:
            return {cid: self.memory["connections"].get(cid) for cid in ids}
        return {row["id"]: dict(row) for row in conn.execute(
            select(self.connections).where(self.connections.c.id.in_(ids))).mappings()}

    @staticmethod
    def _public(row, owners):
        reasons = ["RECEIPT_REVOKED"] if row["revoked_at"] else []
        for role in ("issuer", "vault"):
            owner = owners.get(row[role + "_connection_id"])
            if not owner or not owner["enabled"]:
                reasons.append(role.upper() + "_CONNECTION_DISABLED_OR_MISSING")
            elif owner["revision"] != row[role]["connection_revision"]:
                reasons.append(role.upper() + "_SCOPE_CHANGED")
        result = {name: deepcopy(row[name]) for name in (
            "source_system", "source_record_id", "submitted_by", "revoked_by", "issuer", "vault")}
        result.update({name: utc(row[name]).isoformat() if row[name] else None
                       for name in ("stored_at", "submitted_at", "revoked_at")})
        return {"id": str(row["id"]), **result, "state": "REVOKED" if row["revoked_at"] else "STORAGE_RECORDED",
                "applicable": not reasons, "reasons": reasons}

    def _replay(self, conn, row, checksum):
        if row["request_digest"] != checksum:
            raise CoverageError("RECEIPT_REPLAY_CONFLICT")
        return self._public(row, self._owners(conn, [row]))

    def create(self, body: StorageReceiptInput, actor):
        body = StorageReceiptInput.model_validate(body)
        checksum = digest(body.model_dump(mode="json"))
        try:
            with self.transaction() as conn:
                previous = self._get(conn, TABLE, body.id)
                if previous:
                    return self._replay(conn, previous, checksum)
                runs = {role: self._get(conn, "runs", getattr(body, role).run_id) for role in ("issuer", "vault")}
                if any(run is None for run in runs.values()):
                    raise CoverageError("RECEIPT_RUN_NOT_FOUND")
                # Same global order for two-connection receipts and scope changes.
                owners = {cid: self._get(conn, "connections", cid, lock=True)
                          for cid in sorted({run["connection_id"] for run in runs.values()}, key=str)}
                previous = self._get(conn, TABLE, body.id, lock=True)
                if previous:
                    return self._replay(conn, previous, checksum)
                locations = {role: self._resolve(conn, owners[run["connection_id"]], run, getattr(body, role), role)
                             for role, run in runs.items()}
                row = {"id": body.id, "request_digest": checksum, "source_system": body.source_system,
                    "source_record_id": body.source_record_id, "stored_at": datetime.fromisoformat(body.stored_at),
                    "submitted_at": datetime.now(UTC), "submitted_by": metadata_text(actor),
                    "revoked_at": None, "revoked_by": None, **locations,
                    "issuer_entity_id": uuid.UUID(locations["issuer"]["entity_id"]) if locations["issuer"].get("entity_id") else None,
                    "issuer_identifier": locations["issuer"].get("identifier", "")}
                for role, run in runs.items():
                    row[role + "_connection_id"], row[role + "_run_id"] = run["connection_id"], run["id"]
                self._put(conn, TABLE, row, new=True)
                return self._public(row, owners)
        except IntegrityError:
            # A UUID collision can cross disjoint connection locks. Re-read only
            # after rollback so PostgreSQL is not left in an aborted transaction.
            with self.transaction() as conn:
                previous = self._get(conn, TABLE, body.id)
                if previous:
                    return self._replay(conn, previous, checksum)
            raise CoverageError("RECEIPT_REPLAY_CONFLICT") from None

    def revoke(self, receipt_id, actor):
        with self.transaction() as conn:
            row = self._get(conn, TABLE, uuid.UUID(str(receipt_id)), lock=True)
            if row is None:
                raise CoverageError("RECEIPT_NOT_FOUND")
            if row["revoked_at"] is None:
                row.update(revoked_at=datetime.now(UTC), revoked_by=metadata_text(actor))
                self._put(conn, TABLE, row)
            return self._public(row, self._owners(conn, [row]))

    def list(self, *, offset=0, limit=50, issuer_entity_id=None, issuer_connection_id=None, issuer_identifier=""):
        _paging(offset, limit)
        filters = {name: uuid.UUID(str(value)) for name, value in (
            ("issuer_entity_id", issuer_entity_id), ("issuer_connection_id", issuer_connection_id)) if value is not None}
        if issuer_identifier:
            try:
                filters["issuer_identifier"] = metadata_text(issuer_identifier)
            except ValueError:
                raise CoverageError("RECEIPT_INVALID_IDENTIFIER") from None
        with self.transaction() as conn:
            if conn is None:
                rows = [row for row in self.memory[TABLE].values() if all(row[k] == v for k, v in filters.items())]
                rows.sort(key=lambda row: (utc(row["submitted_at"]), str(row["id"])), reverse=True)
                total, shown = len(rows), rows[offset:offset + limit]
            else:
                table = getattr(self, TABLE)
                predicates = [table.c[k] == value for k, value in filters.items()]
                total = conn.execute(select(func.count()).select_from(table).where(*predicates)).scalar_one()
                shown = [dict(row) for row in conn.execute(select(table).where(*predicates)
                    .order_by(table.c.submitted_at.desc(), table.c.id.desc()).offset(offset).limit(limit)).mappings()]
            owners = self._owners(conn, shown)
            return {"items": [self._public(row, owners) for row in shown], "total": total, "offset": offset, "limit": limit}

    def candidates(self, run_id, *, role: Literal["issuer", "vault"] = "issuer", offset=0, limit=100):
        """Page eligible records within one bounded run (at most 250,000 items).

        Exact totals require checking that run's records, never provider calls.
        """
        _paging(offset, limit, MAX_BATCH)
        if role not in {"issuer", "vault"}:
            raise CoverageError("RECEIPT_INVALID_ROLE")
        with self.transaction() as conn:
            run = self._get(conn, "runs", uuid.UUID(str(run_id)))
            if run is None:
                raise CoverageError("RECEIPT_RUN_NOT_FOUND")
            owner = self._get(conn, "connections", run["connection_id"])
            self._usable(owner, run)
            shown, total = [], 0
            for batch in self._batches(conn, run["id"]):
                for index, raw in enumerate(batch["items"]):
                    anchor = ReceiptAnchor(run_id=run["id"], batch_index=batch["index"], item_index=index)
                    try:
                        locator = self._locator(owner, run, anchor, raw, role)
                    except CoverageError as error:
                        if str(error) != "RECEIPT_OBSERVATION_ROLE_MISMATCH":
                            raise
                        continue
                    if offset <= total < offset + limit:
                        shown.append(locator)
                    total += 1
            return {"items": shown, "total": total, "offset": offset, "limit": limit}

    def connection_choices(self):
        return {"items": [{"id": str(row["id"]), "name": row["spec"]["name"], "provider": row["spec"]["provider"],
            "enabled": row["enabled"], "revision": row["revision"]} for row in self.list_connections()]}

    def run_page(self, connection_id, *, offset=0, limit=20):
        _paging(offset, limit)
        cid = uuid.UUID(str(connection_id))
        with self.transaction() as conn:
            if self._get(conn, "connections", cid) is None:
                raise CoverageError("RECEIPT_CONNECTION_NOT_FOUND")
            if conn is None:
                rows = self._connection_runs(conn, cid)
                total, shown = len(rows), rows[offset:offset + limit]
            else:
                total = conn.execute(select(func.count()).select_from(self.runs).where(
                    self.runs.c.connection_id == cid)).scalar_one()
                shown = conn.execute(select(self.runs).where(self.runs.c.connection_id == cid)
                    .order_by(self.runs.c.sequence.desc()).offset(offset).limit(limit)).mappings()
            items = [{"id": str(row["id"]), "status": row["status"], "revision": row["revision"],
                      **{key: utc(row[key]).isoformat() if row[key] else None for key in ("started_at", "finished_at")}}
                     for row in shown]
            return {"items": items, "total": total, "offset": offset, "limit": limit}
