"""GCP cumulative observations and lifecycle history; secret values are never stored."""

from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import UTC, datetime

from sqlalchemy import JSON, Column, DateTime, ForeignKey, Index, Table, Text, Uuid, func, select

from cremore.coverage.store import CoverageError, CoverageStore

# The legacy table remains declared only so an explicit offline cleanup can remove old rows.
NAMES = ("gcp_objects", "gcp_events", "gcp_values")


def linked_source_disabled(repo, cid):
    source = repo.get_connection(cid)
    return bool(source and source.provider == "gcp" and source.status == "DISABLED")


def register_tables(metadata):
    if NAMES[0] in metadata.tables:
        return tuple(metadata.tables[name] for name in NAMES)
    tables = []
    for name in NAMES:
        table = Table(name, metadata,
            Column("id", Uuid, primary_key=True),
            Column("connection_id", Uuid, ForeignKey("coverage_connections.id"), nullable=False),
            Column("run_id", Uuid, ForeignKey("coverage_runs.id"), nullable=False),
            Column("source_id", Text, nullable=False),
            Column("observed_at", DateTime(timezone=True), nullable=False),
            Column("body", JSON, nullable=False))
        Index(name + "_connection_time", table.c.connection_id, table.c.observed_at, table.c.id)
        Index(name + "_source", table.c.connection_id, table.c.source_id)
        tables.append(table)
    return tuple(tables)


class GcpStore(CoverageStore):
    def __init__(self, repo):
        super().__init__(repo)
        if self.engine is None:
            with repo._lock:
                for name in NAMES:
                    self.memory.setdefault(name, {})
        else:
            from cremore.db.schema import metadata
            for name, table in zip(NAMES, register_tables(metadata)):
                setattr(self, name, table)

    def require_gcp(self, cid):
        owner = self.get(cid)
        if not owner or owner["spec"].get("schema_version") != 2 or owner["spec"].get("provider") != "gcp":
            raise CoverageError("GCP_CONNECTION_REQUIRED")
        return owner

    def _rows(self, conn, name, cid, *, source_id=None, offset=0, limit=None):
        if conn is None:
            rows = [deepcopy(row) for row in self.memory[name].values()
                    if row["connection_id"] == cid and (source_id is None or row["source_id"] == source_id)]
            rows.sort(key=lambda row: (row["observed_at"], str(row["id"])), reverse=True)
            return rows[offset:None if limit is None else offset + limit]
        table = getattr(self, name)
        query = select(table).where(table.c.connection_id == cid)
        if source_id is not None:
            query = query.where(table.c.source_id == source_id)
        query = query.order_by(table.c.observed_at.desc(), table.c.id.desc()).offset(offset)
        if limit is not None:
            query = query.limit(limit)
        return [dict(row) for row in conn.execute(query).mappings()]

    def count(self, conn, name, cid):
        if conn is None:
            return sum(row["connection_id"] == cid for row in self.memory[name].values())
        table = getattr(self, name)
        return conn.execute(select(func.count()).select_from(table).where(table.c.connection_id == cid)).scalar_one()

    def page(self, cid, kind, *, offset=0, limit=50):
        self.require_gcp(cid)
        if kind not in ("objects", "events"):
            raise CoverageError("GCP_INVALID_PAGE")
        name = "gcp_" + kind
        with self.transaction() as conn:
            total = self.count(conn, name, cid)
            rows = self._rows(conn, name, cid, offset=offset, limit=limit)
        return {"items": [{"id": str(row["id"]), "run_id": str(row["run_id"]),
                            "source_id": row["source_id"],
                            **{key: value for key, value in row["body"].items() if key != "payload_digest"}}
                           for row in rows],
                "total": total, "offset": offset, "limit": limit}

    def _save(self, conn, name, row):
        self._put(conn, name, row, new=self._get(conn, name, row["id"]) is None)

    def _event(self, conn, cid, rid, source_id, event_type, before, after, now):
        eid = uuid.uuid5(rid, "gcp:" + source_id + ":" + event_type)
        if self._get(conn, "gcp_events", eid):
            return 0
        self._put(conn, "gcp_events", {"id": eid, "connection_id": cid, "run_id": rid,
            "source_id": source_id, "observed_at": now,
            "body": {"event_type": event_type, "previous_state": before,
                     "current_state": after, "observed_at": now.isoformat(),
                     "basis": "COLLECTION_OBSERVATION"}}, new=True)
        return 1

    def reconcile(self, cid, rid, records):
        """Keep old observations across partial runs; absence needs a full list."""
        from cremore_gcp_provider.metadata.snapshot import _index, native_snapshots, value_change
        owner = self.require_gcp(cid)
        now = datetime.now(UTC)
        observed = _index(records)
        values_complete = any(item.get("record_type") == "operation_report"
                              and item.get("provenance", {}).get("operation") == "gcp.value_access"
                              and item.get("value_access") == "COMPLETE" for item in records)
        coverage = native_snapshots(records)["inventory"]["coverage"]
        project = owner["spec"]["scopes"][0]["id"]
        with self.transaction() as conn:
            old_rows = self._rows(conn, "gcp_objects", cid)
            old_objects = {row["source_id"]: row for row in old_rows
                           if row["body"].get("project_id") == project}
            events = 0

            def complete(path):
                if path == "service_account_keys" and not complete("service_accounts"):
                    return False
                if path in coverage:
                    return coverage[path]["status"] == "complete"
                if path.startswith("secret_versions:"):
                    parent = path[len("secret_versions:"):]
                    # Only the confirmed absence of the parent implies absent versions.
                    prior = old_objects.get(parent)
                    return bool(parent not in observed and prior and complete(prior["body"]["coverage_path"]))
                return False

            for name, current in observed.items():
                previous = old_objects.get(name)
                old = previous["body"] if previous else None
                before = old["lifecycle_state"] if old else None
                after = current["lifecycle_state"]
                if old is None:
                    events += self._event(conn, cid, rid, name, "discovered", None, after, now)
                elif before != after:
                    events += self._event(conn, cid, rid, name, "state_changed", before, after, now)
                elif old["metadata"] != current["metadata"]:
                    events += self._event(conn, cid, rid, name, "metadata_changed", before, after, now)
                if old or current["payload_digest"]:
                    kind, _reason = value_change(old or {}, current,
                        complete=values_complete and bool(old and old.get("values_complete")))
                    if kind:
                        events += self._event(conn, cid, rid, name, kind, before, after, now)
                body = {**current, "project_id": project, "values_complete": values_complete,
                        "first_seen_at": old["first_seen_at"] if old else now.isoformat(),
                        "last_seen_at": now.isoformat(), "last_checked_at": now.isoformat()}
                if old and not body["payload_digest"]:
                    body["payload_digest"] = old.get("payload_digest")
                    body["values_complete"] = False
                    if not body["fingerprint"]:
                        body["fingerprint"] = old.get("fingerprint")
                        body["values"] = old.get("values", {})
                self._save(conn, "gcp_objects", {"id": uuid.uuid5(cid, "object:" + name),
                    "connection_id": cid, "run_id": rid, "source_id": name, "observed_at": now, "body": body})
            for name, previous in old_objects.items():
                old = previous["body"]
                if (name in observed or old["lifecycle_state"] in ("deleted", "destroyed", "no_longer_listed")
                        or not complete(old["coverage_path"])):
                    continue
                events += self._event(conn, cid, rid, name, "no_longer_listed",
                                      old["lifecycle_state"], "no_longer_listed", now)
                previous.update(run_id=rid, observed_at=now, body={**old,
                    "lifecycle_state": "no_longer_listed", "absent_since": now.isoformat(),
                    "last_checked_at": now.isoformat()})
                self._save(conn, "gcp_objects", previous)
            return {"gcp_objects": self.count(conn, "gcp_objects", cid), "gcp_events_added": events}
