"""Two indexed projections over the existing immutable coverage batches."""

from __future__ import annotations

import copy
import uuid
from bisect import insort
from datetime import UTC, datetime

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
    case,
    delete,
    func,
    or_,
    select,
    update,
)

from cremore.coverage.metadata_models import (
    RECORD_ADAPTER,
    MetadataConnectionSpec,
    ProviderEvent,
    entity_id,
)
from cremore.coverage.models import digest
from cremore.coverage.store import CoverageError, CoverageStore, utc

EVENT_FACET_LIMIT = 100


def _bounded_facets(values):
    """The lexically first bounded distinct labels, without an unbounded set."""
    kept, truncated = [], False
    for value in values:
        if not isinstance(value, str) or not value or value in kept:
            continue
        insort(kept, value)
        if len(kept) > EVENT_FACET_LIMIT:
            kept.pop()
            truncated = True
    return kept, truncated


def _is_usage(record):
    body = record["body"]
    return record["purpose"] == "usage" and (
        record["record_type"] == "provider_event" and body.get("event_type") == "token_activity"
        or record["record_type"] == "relation" and body.get("relation") == "used"
        and body.get("confidence") == "EXACT")


def _snapshot_prefixes():
    from cremore.coverage.providers import _ADAPTERS

    return [(provider, prefix) for provider, registration in _ADAPTERS.items()
            for prefix in registration.descriptor.get("snapshot_identity_prefixes", ())]


def register_tables(metadata):
    if "coverage_entities" in metadata.tables:
        return metadata.tables["coverage_entities"], metadata.tables["coverage_records"]
    entities = Table("coverage_entities", metadata,
        Column("id", Uuid, primary_key=True), Column("canonical_key", Text, nullable=False, unique=True),
        Column("provider", Text, nullable=False), Column("origin", Text, nullable=False),
        Column("tenant", Text, nullable=False), Column("tenant_confirmed", Boolean, nullable=False),
        Column("object_kind", Text, nullable=False), Column("object_id", Text, nullable=False),
        Column("purpose", Text, nullable=False), Column("summary", JSON(none_as_null=True)),
        Column("current_record_id", Uuid), Column("last_success_record_id", Uuid),
        Column("latest_run_id", Uuid), Column("observed_at", DateTime(timezone=True)),
        Column("first_observed_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False))
    Index("coverage_entities_provider_kind", entities.c.provider, entities.c.object_kind, entities.c.observed_at)
    records = Table("coverage_records", metadata,
        Column("id", Uuid, primary_key=True),
        Column("run_id", Uuid, ForeignKey("coverage_runs.id"), nullable=False),
        Column("connection_id", Uuid, ForeignKey("coverage_connections.id"), nullable=False),
        Column("revision", Integer, nullable=False), Column("batch_index", Integer, nullable=False),
        Column("item_index", Integer, nullable=False), Column("record_type", Text, nullable=False),
        Column("entity_id", Uuid, ForeignKey("coverage_entities.id")),
        Column("subject_id", Uuid, ForeignKey("coverage_entities.id")),
        Column("target_id", Uuid, ForeignKey("coverage_entities.id")),
        Column("provider", Text, nullable=False), Column("scope_key", Text, nullable=False),
        Column("purpose", Text, nullable=False), Column("operation", Text, nullable=False),
        Column("observed_at", DateTime(timezone=True), nullable=False), Column("effective_at", DateTime(timezone=True), nullable=False),
        Column("event_key", Text), Column("body", JSON, nullable=False))
    Index("coverage_records_position", records.c.run_id, records.c.batch_index, records.c.item_index, unique=True)
    Index("coverage_records_event", records.c.run_id, records.c.event_key, unique=True)
    Index("coverage_records_entity_time", records.c.entity_id, records.c.effective_at)
    Index("coverage_records_subject", records.c.subject_id, records.c.observed_at)
    Index("coverage_records_target", records.c.target_id, records.c.observed_at)
    Index("coverage_records_connection_scope", records.c.connection_id, records.c.scope_key, records.c.observed_at)
    return entities, records


def _insert_ignore(conn, table, values):
    if conn.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as native_insert
    else:
        from sqlalchemy.dialects.sqlite import insert as native_insert
    return conn.execute(native_insert(table).values(**values).on_conflict_do_nothing()).rowcount


def _identity(store, conn, run, identity, purpose, observed):
    eid = entity_id(identity, run["connection_id"])
    row = {"id": eid, "canonical_key": identity.key(run["connection_id"]),
           "provider": identity.provider, "origin": identity.origin, "tenant": identity.tenant,
           "tenant_confirmed": identity.tenant_confirmed, "object_kind": identity.kind,
           "object_id": identity.object_id, "purpose": purpose, "summary": None,
           "current_record_id": None, "last_success_record_id": None, "latest_run_id": None,
           "observed_at": None, "first_observed_at": observed, "updated_at": datetime.now(UTC)}
    if conn is None:
        store.memory["entities"].setdefault(eid, row)
    else:
        _insert_ignore(conn, store.entities, row)
    return eid


def project_batch(store, conn, run, batch):
    """Called in the same transaction as run count, batch and task checkpoint."""
    spec = run["contract"].get("spec_snapshot") or store._get(conn, "connections", run["connection_id"])["spec"]
    for index, item in enumerate(batch.items):
        body = item.model_dump()
        observed = datetime.fromisoformat(item.provenance.observed_at)
        # When this was true at the provider. An event's own occurrence time
        # is that, so a list of events orders by when they happened rather
        # than by when a run happened to collect them.
        effective = (getattr(item, "effective_at", None) or getattr(item, "occurred_at", None)
                     or item.provenance.provider_generated_at or item.provenance.observed_at)
        ids = {}
        for key in ("identity", "subject", "target"):
            identity = getattr(item, key, None)
            ids[key] = _identity(store, conn, run, identity, item.purpose, observed) if identity else None
        event_key = None
        if isinstance(item, ProviderEvent):
            event_key = digest([spec["provider"], spec["origin"], spec["tenant"], item.event_id,
                                item.event_type, item.occurred_at, str(ids["subject"]), str(ids["target"]),
                                [f.model_dump() for f in item.facts]])
        row = {"id": uuid.uuid5(run["id"], f"{batch.index}:{index}"),
               "run_id": run["id"], "connection_id": run["connection_id"], "revision": run["revision"],
               "batch_index": batch.index, "item_index": index, "record_type": item.record_type,
               "entity_id": ids["identity"], "subject_id": ids["subject"], "target_id": ids["target"],
               "provider": spec["provider"], "scope_key": digest(item.scope.model_dump()), "purpose": item.purpose,
               "operation": item.provenance.operation, "observed_at": observed,
               "effective_at": datetime.fromisoformat(effective), "event_key": event_key, "body": body}
        if conn is None:
            duplicate = event_key and any(r["run_id"] == run["id"] and r["event_key"] == event_key
                                          for r in store.memory["records"].values())
            if not duplicate:
                store.memory["records"][row["id"]] = copy.deepcopy(row)
        else:
            _insert_ignore(conn, store.records, row)


def finish_projection(store, conn, run):
    """Failures never replace last known/successful entity observations."""
    if run["status"] not in ("COMPLETE", "PARTIAL"):
        return
    from cremore.coverage.providers import adapter_for

    owner = store._get(conn, "connections", run["connection_id"])
    spec = MetadataConnectionSpec.model_validate(run["contract"].get("spec_snapshot") or owner["spec"])
    selector = getattr(adapter_for(spec.provider), "current_record_status", None)
    if conn is None:
        rows = [r for r in store.memory["records"].values() if r["run_id"] == run["id"] and r["entity_id"]]
        reports = [r["body"] for r in store.memory["records"].values()
                   if r["run_id"] == run["id"] and r["record_type"] == "operation_report"]
    else:
        reports = conn.execute(select(store.records.c.body).where(store.records.c.run_id == run["id"],
                    store.records.c.record_type == "operation_report").order_by(store.records.c.batch_index, store.records.c.item_index)).scalars().all()
        rows = conn.execute(select(store.records).where(store.records.c.run_id == run["id"],
                                                       store.records.c.entity_id.is_not(None))).mappings()
    prepare = getattr(adapter_for(spec.provider), "prepare_current_records", None)
    if prepare is not None:
        reports = prepare(spec, reports)
    sequences = {}
    def order(record):
        if record["run_id"] not in sequences:
            source = store._get(conn, "runs", record["run_id"])
            sequences[record["run_id"]] = (utc(source["started_at"]), source["sequence"])
        return (utc(record["effective_at"]), utc(record["observed_at"]), sequences[record["run_id"]],
                record["batch_index"], record["item_index"])
    for record in rows:
        source_status = selector(spec, record["body"], reports) if selector else run["status"]
        if source_status not in ("COMPLETE", "PARTIAL"):
            continue
        entity = store._get(conn, "entities", record["entity_id"], lock=True)
        old = store._get(conn, "records", entity["current_record_id"]) if entity["current_record_id"] else None
        if old is None or order(record) > order(old):
            entity.update(summary=record["body"], current_record_id=record["id"], latest_run_id=run["id"],
                          purpose=record["purpose"], observed_at=record["observed_at"], updated_at=datetime.now(UTC))
        if run["status"] == "COMPLETE" and source_status == "COMPLETE":
            success = store._get(conn, "records", entity["last_success_record_id"]) if entity["last_success_record_id"] else None
            if success is None or order(record) > order(success):
                entity["last_success_record_id"] = record["id"]
        store._put(conn, "entities", entity)
        if entity["current_record_id"] == record["id"]:
            from cremore.db.people_directory_store import project_entity

            project_entity(store, conn, entity, run, spec.model_dump())


class MetadataStore(CoverageStore):
    """Indexed inventory and immutable, paged run/source detail."""

    def require_connection(self, cid):
        row = self.get(cid)
        if row is None:
            raise CoverageError("CONNECTION_NOT_FOUND")
        if row["spec"].get("schema_version", 1) != 2:
            raise CoverageError("COVERAGE_SCHEMA_MISMATCH")
        return row

    def connection_runs(self, cid, *, offset=0, limit=50):
        self.require_connection(cid)
        with self.transaction() as conn:
            if conn is None:
                rows = self._connection_runs(conn, cid)
                total, rows = len(rows), rows[offset:offset + limit]
            else:
                total = conn.execute(select(func.count()).select_from(self.runs).where(self.runs.c.connection_id == cid)).scalar_one()
                rows = [dict(row) for row in conn.execute(select(self.runs).where(self.runs.c.connection_id == cid)
                        .order_by(self.runs.c.sequence.desc()).offset(offset).limit(limit)).mappings()]
        return {"items": [{k: row[k] for k in ("id", "connection_id", "revision", "sequence", "status", "reasons", "item_count", "started_at", "finished_at")} for row in rows],
                "total": total, "offset": offset, "limit": limit}

    def recent_run_reports(self, cid, *, limit=101):
        """A bounded history window and the first five reports of each run, without COUNT/N+1 reads."""
        self.require_connection(cid)
        with self.transaction() as conn:
            if conn is None:
                runs = self._connection_runs(conn, cid)[:limit]
                ids = {row["id"] for row in runs}
                records = sorted((row for row in self.memory["records"].values()
                                  if row["run_id"] in ids and row["record_type"] == "operation_report"),
                                 key=lambda row: (str(row["run_id"]), row["batch_index"], row["item_index"]))
            else:
                runs = [dict(row) for row in conn.execute(select(self.runs).where(self.runs.c.connection_id == cid)
                        .order_by(self.runs.c.sequence.desc()).limit(limit)).mappings()]
                ranked = select(self.records.c.run_id, self.records.c.body,
                    func.row_number().over(partition_by=self.records.c.run_id,
                        order_by=(self.records.c.batch_index, self.records.c.item_index)).label("position")
                    ).where(self.records.c.run_id.in_([row["id"] for row in runs]),
                            self.records.c.record_type == "operation_report").subquery()
                records = conn.execute(select(ranked.c.run_id, ranked.c.body).where(ranked.c.position <= 5)
                                       .order_by(ranked.c.run_id, ranked.c.position)).mappings()
            reports = {run["id"]: [] for run in runs}
            for record in records:
                if len(reports[record["run_id"]]) < 5:
                    reports[record["run_id"]].append(copy.deepcopy(record["body"]))
        keys = ("id", "connection_id", "revision", "sequence", "status", "reasons", "item_count", "started_at", "finished_at")
        return [{key: run[key] for key in keys} for run in runs], reports

    def inventory(self, *, offset=0, limit=100, provider="", object_kind="", purpose="", origin="", tenant=None, connection_id=None, q="",
                  details=True, exclude_purposes=()):
        """One page of current entities. With details=False the rows carry no observation_run,
        verification or collections: a caller that ranks many rows attaches them with
        inventory_details() to the ones it shows (the per-row collection lookup dominates a
        large read; second review 2026-09-26). ``exclude_purposes`` leaves those purposes out
        everywhere, counts and facets included (a caller who may not read them)."""
        q = q.casefold()
        snapshots = _snapshot_prefixes()
        with self.transaction() as conn:
            if conn is None:
                rows = [copy.deepcopy(r) for r in self.memory["entities"].values()
                        if r["summary"] is not None and r["purpose"] not in exclude_purposes
                        and not any(r["provider"] == p and r["object_id"].startswith(prefix) for p, prefix in snapshots)]
                total_all = len(rows)
                facets = {key: sorted({r[key] for r in rows})
                          for key in ("provider", "object_kind", "purpose")}
                if connection_id:
                    allowed = {r["entity_id"] for r in self.memory["records"].values() if r["connection_id"] == connection_id}
                    rows = [r for r in rows if r["id"] in allowed]
                rows = [r for r in rows if (not provider or r["provider"] == provider)
                        and (not object_kind or r["object_kind"] == object_kind) and (not purpose or r["purpose"] == purpose)
                        and (not origin or r["origin"] == origin)
                        and (tenant is None or r["tenant"] == tenant)
                        and (not q or q in r["object_id"].casefold() or q in r["provider"].casefold() or q in r["tenant"].casefold())]
                rows.sort(key=lambda r: (utc(r["observed_at"]), str(r["id"])), reverse=True)
                total = len(rows)
                counts = {}
                for row in rows:
                    counts[row["object_kind"]] = counts.get(row["object_kind"], 0) + 1
                shown = rows[offset:offset + limit]
            else:
                table = self.entities
                predicate = [table.c.summary.is_not(None)]
                predicate.extend(~((table.c.provider == p) & table.c.object_id.startswith(prefix, autoescape=True))
                                 for p, prefix in snapshots)
                if exclude_purposes:
                    predicate.append(table.c.purpose.not_in(tuple(exclude_purposes)))
                total_all = conn.execute(select(func.count()).select_from(table).where(*predicate)).scalar_one()
                facet_rows = conn.execute(select(table.c.provider, table.c.object_kind, table.c.purpose)
                                          .where(*predicate).distinct()).mappings().all()
                facets = {key: sorted({r[key] for r in facet_rows})
                          for key in ("provider", "object_kind", "purpose")}
                for column, value in ((table.c.provider, provider), (table.c.object_kind, object_kind),
                                      (table.c.purpose, purpose), (table.c.origin, origin)):
                    if value:
                        predicate.append(column == value)
                if tenant is not None:
                    predicate.append(table.c.tenant == tenant)
                if connection_id:
                    predicate.append(table.c.id.in_(select(self.records.c.entity_id).where(self.records.c.connection_id == connection_id)))
                if q:
                    predicate.append(or_(*(func.lower(c).contains(q, autoescape=True)
                                           for c in (table.c.object_id, table.c.provider, table.c.tenant))))
                total = conn.execute(select(func.count()).select_from(table).where(*predicate)).scalar_one()
                counts = dict(conn.execute(select(table.c.object_kind, func.count()).where(*predicate).group_by(table.c.object_kind)).all())
                shown = [dict(r) for r in conn.execute(select(table).where(*predicate).order_by(
                    table.c.observed_at.desc(), table.c.id.desc()).offset(offset).limit(limit)).mappings()]
            if details:
                self._attach_details(conn, shown)
            return {"schema_version": 2, "items": shown, "total": total, "total_all": total_all,
                    "counts": counts, "facets": facets, "offset": offset, "limit": limit}

    def inventory_details(self, rows):
        """Attach observation_run, verification and collections to rows read with details=False."""
        with self.transaction() as conn:
            self._attach_details(conn, rows)
        return rows

    def snapshot_matches(self, fingerprints, *, limit=1000):
        """Private positive evidence from snapshot rows, never inventory counts.

        The bounded read keeps the newest observation for each comparison contract
        and issuer. Callers must still check that contract against their evidence.
        A later missing/failed collection cannot turn an old match into current proof.
        """
        fingerprints = set(fingerprints)
        if not fingerprints:
            return {"items": [], "truncated": False}
        prefixes = _snapshot_prefixes()
        with self.transaction() as conn:
            if conn is None:
                rows = [copy.deepcopy(row) for row in self.memory["entities"].values()
                        if row["summary"] and row["purpose"] == "issuer_inventory"
                        and row["object_kind"] == "credential"
                        and any(row["provider"] == p and row["object_id"].startswith(s) for p, s in prefixes)
                        and (row["summary"].get("value_match") or {}).get("fingerprint") in fingerprints
                        and self.memory["runs"][row["latest_run_id"]]["status"] in {"COMPLETE", "PARTIAL"}]
                rows.sort(key=lambda row: (utc(row["observed_at"]), str(row["id"])), reverse=True)
                rows = rows[:limit + 1]
            else:
                table = self.entities
                rows = [dict(row) for row in conn.execute(select(table).join(
                    self.runs, self.runs.c.id == table.c.latest_run_id).where(
                        table.c.purpose == "issuer_inventory", table.c.object_kind == "credential",
                        or_(*((table.c.provider == p) & table.c.object_id.startswith(s, autoescape=True)
                              for p, s in prefixes)),
                        table.c.summary[("value_match", "fingerprint")].as_string().in_(fingerprints),
                        self.runs.c.status.in_(("COMPLETE", "PARTIAL")))
                    .order_by(table.c.observed_at.desc(), table.c.id.desc()).limit(limit + 1)).mappings()]
            seen, shown = set(), []
            for row in rows[:limit]:
                match = row["summary"]["value_match"]
                key = (row["provider"], row["origin"], row["tenant"],
                       *(match.get(name) for name in ("fingerprint", "key_id", "scheme", "credential_type",
                                                     "engine_digest", "policy_digest", "material_kind")))
                if key not in seen:
                    seen.add(key)
                    shown.append(row)
            self._attach_details(conn, shown)
            return {"items": shown, "truncated": len(rows) > limit}

    def _attach_details(self, conn, shown):
        if conn is None:
            runs = self.memory["runs"]
        else:
            runs = {r["id"]: r for r in conn.execute(select(self.runs).where(
                self.runs.c.id.in_({row["latest_run_id"] for row in shown}))).mappings()} if shown else {}
        collections = self._collections_for_entities(conn, [row["id"] for row in shown])
        for row in shown:
            run = runs.get(row["latest_run_id"])
            row["observation_run"] = None if run is None else copy.deepcopy({k: run[k] for k in ("id", "status", "connection_id", "revision", "started_at", "finished_at", "reasons")})
            row["verification"] = "NOT_PERFORMED"
            row["collections"] = collections[row["id"]]

    def usage_counts(self, entity_ids):
        """How many use records name each entity, as subject or as target.

        Explicit token activity and exact observed-use relations count. Ownership,
        policy grants, and credential lifecycle events do not establish use.
        A zero means no use record was collected, never that the object was never used.
        """
        ids = list(entity_ids)
        if not ids:
            return {}
        counts = dict.fromkeys(ids, 0)
        with self.transaction() as conn:
            if conn is None:
                for record in self.memory["records"].values():
                    if not _is_usage(record):
                        continue
                    for key in ("entity_id", "subject_id", "target_id"):
                        if record[key] in counts:
                            counts[record[key]] += 1
            else:
                table = self.records
                used = (table.c.purpose == "usage") & or_(
                    (table.c.record_type == "provider_event") & (table.c.body["event_type"].as_string() == "token_activity"),
                    (table.c.record_type == "relation") & (table.c.body["relation"].as_string() == "used")
                    & (table.c.body["confidence"].as_string() == "EXACT"))
                for column in (table.c.entity_id, table.c.subject_id, table.c.target_id):
                    rows = conn.execute(select(column, func.count()).where(
                        used, column.in_(ids)).group_by(column)).all()
                    for eid, count in rows:
                        counts[eid] = counts.get(eid, 0) + count
        return counts

    def latest_usage(self, entity_ids):
        """Last exact observed use per entity, never collection time or ownership.

        Metric timestamps mark the end of an observed interval, not an exact API
        call. Failed/running batches cannot contribute. Missing evidence is unknown.
        Aggregation stays in SQL and returns at most one row per entity and operation.
        """
        ids, result = set(entity_ids), {}
        if not ids:
            return result

        def remember(eid, stamp, operation):
            if eid not in ids or not stamp:
                return
            stamp = utc(datetime.fromisoformat(stamp)).isoformat()
            basis = "METRIC_INTERVAL" if operation in {"cloud_monitoring.api_request_count", "gcp.cloud_monitoring.api_request_count"} else "AUDIT_OBSERVED"
            if eid not in result or stamp > result[eid]["at"]:
                result[eid] = {"at": stamp, "basis": basis}

        with self.transaction() as conn:
            if conn is None:
                for row in self.memory["records"].values():
                    if (not _is_usage(row) or row["body"].get("confidence") != "EXACT"
                            or self.memory["runs"][row["run_id"]]["status"] not in {"COMPLETE", "PARTIAL"}):
                        continue
                    stamp = row["body"].get("occurred_at") if row["record_type"] == "provider_event" else row["body"].get("window_end")
                    for key in ("entity_id", "subject_id", "target_id"):
                        remember(row[key], stamp, row["operation"])
            else:
                table = self.records
                exact = (table.c.body["confidence"].as_string() == "EXACT")
                event = (table.c.record_type == "provider_event") & (table.c.body["event_type"].as_string() == "token_activity")
                relation = (table.c.record_type == "relation") & (table.c.body["relation"].as_string() == "used")
                stamp = case((event, table.c.body["occurred_at"].as_string()), else_=table.c.body["window_end"].as_string())
                for column in (table.c.entity_id, table.c.subject_id, table.c.target_id):
                    rows = conn.execute(select(column, func.max(stamp), table.c.operation).join(
                        self.runs, table.c.run_id == self.runs.c.id).where(
                            column.in_(ids), table.c.purpose == "usage", exact, event | relation,
                            self.runs.c.status.in_(("COMPLETE", "PARTIAL"))
                        ).group_by(column, table.c.operation))
                    for eid, at, operation in rows:
                        remember(eid, at, operation)
        return result

    def explicit_creators(self, entity_ids):
        """Distinct exact creator references; conflicts remain unfilled.

        Relations point from the credential to its creator. Owners, installers
        without an explicit credential relationship, and arbitrary audit actors
        cannot supply this field.
        """
        ids, creators = set(entity_ids), {}
        if not ids:
            return {}
        with self.transaction() as conn:
            if conn is None:
                pairs = {(r["subject_id"], r["target_id"]) for r in self.memory["records"].values()
                         if r["subject_id"] in ids and r["record_type"] == "relation"
                         and r["body"].get("relation") == "created_by" and r["body"].get("confidence") == "EXACT"
                         and self.memory["runs"][r["run_id"]]["status"] in {"COMPLETE", "PARTIAL"}}
                rows = [(subject, self.memory["entities"][target]["object_id"]) for subject, target in pairs]
            else:
                table = self.records
                rows = conn.execute(select(table.c.subject_id, self.entities.c.object_id).join(
                    self.entities, table.c.target_id == self.entities.c.id).join(
                    self.runs, table.c.run_id == self.runs.c.id).where(
                        table.c.subject_id.in_(ids), table.c.record_type == "relation",
                        table.c.body["relation"].as_string() == "created_by",
                        table.c.body["confidence"].as_string() == "EXACT",
                        self.runs.c.status.in_(("COMPLETE", "PARTIAL"))).distinct())
            for subject, creator in rows:
                creators.setdefault(subject, set()).add(creator)
        return {eid: next(iter(names)) if len(names) == 1 else None for eid, names in creators.items()}

    def _collections_for_entities(self, conn, entity_ids):
        """Load collection status once for the requested page, including shared objects."""
        entity_ids = set(entity_ids)
        if not entity_ids:
            return {}
        if conn is None:
            memberships = {(r["entity_id"], r["connection_id"]) for r in self.memory["records"].values()
                           if r["entity_id"] in entity_ids}
            connections = self.memory["connections"]
            connection_ids = {cid for _, cid in memberships}
            latest_runs = {}
            for run in self.memory["runs"].values():
                cid = run["connection_id"]
                if cid in connection_ids and (cid not in latest_runs or run["sequence"] > latest_runs[cid]["sequence"]):
                    latest_runs[cid] = run
        else:
            selected = select(self.records.c.entity_id, self.records.c.connection_id).where(
                self.records.c.entity_id.in_(entity_ids)).distinct().subquery()
            memberships = set(conn.execute(select(selected)).all())
            connection_ids = select(selected.c.connection_id).distinct()
            connections = {r["id"]: r for r in conn.execute(select(self.connections).where(
                self.connections.c.id.in_(connection_ids))).mappings()}
            newest = select(self.runs.c.connection_id, func.max(self.runs.c.sequence).label("sequence")).where(
                self.runs.c.connection_id.in_(connection_ids)).group_by(self.runs.c.connection_id).subquery()
            latest_runs = {r["connection_id"]: r for r in conn.execute(select(self.runs).join(newest,
                (self.runs.c.connection_id == newest.c.connection_id)
                & (self.runs.c.sequence == newest.c.sequence))).mappings()}
        views = {}
        for cid in {cid for _, cid in memberships}:
            connection = connections[cid]
            latest = latest_runs.get(cid)
            reasons = []
            if not connection["enabled"]:
                reasons.append("CONNECTION_DISABLED")
            if latest and latest["revision"] != connection["revision"]:
                reasons.append("CONNECTION_SCOPE_CHANGED")
            if latest and (datetime.now(UTC) - utc(latest["started_at"])).total_seconds() > connection["spec"]["freshness_hours"] * 3600:
                reasons.append("STALE_COLLECTION")
            views[cid] = {"connection_id": cid, "name": connection["spec"]["name"], "enabled": connection["enabled"],
                          "latest_run_id": latest["id"] if latest else None, "status": latest["status"] if latest else "NOT_COLLECTED",
                          "started_at": latest["started_at"] if latest else None, "finished_at": latest["finished_at"] if latest else None,
                          "reasons": sorted(set(reasons + (latest["reasons"] if latest else [])))}
        result = {eid: [] for eid in entity_ids}
        for eid, cid in sorted(memberships, key=lambda pair: str(pair[1])):
            result[eid].append(copy.deepcopy(views[cid]))
        return result

    def record_page(self, *, run_id=None, entity_id=None, connection_id=None, record_type="", object_prefix="", offset=0, limit=100):
        with self.transaction() as conn:
            if conn is None:
                rows = [copy.deepcopy(r) for r in self.memory["records"].values()
                        if (run_id is None or r["run_id"] == run_id)
                        and (entity_id is None or entity_id in (r["entity_id"], r["subject_id"], r["target_id"]))
                        and (connection_id is None or r["connection_id"] == connection_id)
                        and (not record_type or r["record_type"] == record_type)
                        and (not object_prefix or r["entity_id"] is not None
                             and self.memory["entities"][r["entity_id"]]["object_id"].startswith(object_prefix))]
                rows.sort(key=lambda r: (str(r["run_id"]), r["batch_index"], r["item_index"]))
                total, shown = len(rows), rows[offset:offset + limit]
            else:
                table = self.records
                predicate = []
                for column, value in ((table.c.run_id, run_id), (table.c.connection_id, connection_id), (table.c.record_type, record_type)):
                    if value:
                        predicate.append(column == value)
                if entity_id:
                    predicate.append(or_(table.c.entity_id == entity_id, table.c.subject_id == entity_id, table.c.target_id == entity_id))
                if object_prefix:
                    predicate.append(table.c.entity_id.in_(select(self.entities.c.id).where(
                        self.entities.c.object_id.startswith(object_prefix, autoescape=True))))
                total = conn.execute(select(func.count()).select_from(table).where(*predicate)).scalar_one()
                shown = [dict(r) for r in conn.execute(select(table).where(*predicate).order_by(
                    table.c.run_id, table.c.batch_index, table.c.item_index).offset(offset).limit(limit)).mappings()]
            return {"items": shown, "total": total, "offset": offset, "limit": limit,
                    "next_offset": offset + len(shown) if offset + len(shown) < total else None}

    def summaries(self, *, provider, object_kind, enabled_only=False):
        """Every current entity summary of one kind in one read -- for a caller that reads them all, where the
        paged inventory would repeat its counts and facets per page. ``enabled_only``: only entities whose latest
        observation came from a collection still on. Read-only: never change what comes back."""
        with self.transaction() as conn:
            if conn is None:
                runs, connections = self.memory["runs"], self.memory["connections"]
                return [r["summary"] for r in self.memory["entities"].values()
                        if r["summary"] is not None and r["provider"] == provider and r["object_kind"] == object_kind
                        and (not enabled_only or (r["latest_run_id"] in runs and (connections.get(
                            runs[r["latest_run_id"]]["connection_id"]) or {}).get("enabled") is True))]
            table = self.entities
            query = select(table.c.summary).where(
                table.c.summary.is_not(None), table.c.provider == provider, table.c.object_kind == object_kind)
            if enabled_only:
                query = query.join(self.runs, self.runs.c.id == table.c.latest_run_id).join(
                    self.connections, self.connections.c.id == self.runs.c.connection_id).where(
                    self.connections.c.enabled.is_(True))
            return list(conn.execute(query).scalars())

    def latest_finished_observation(self, entity_id, operation):
        """One retained observation for an operation that a later read may miss."""
        with self.transaction() as conn:
            if conn is None:
                rows = [row for row in self.memory["records"].values()
                        if row["entity_id"] == entity_id and row["operation"] == operation
                        and row["record_type"] == "entity_observation"
                        and self.memory["runs"][row["run_id"]]["status"] in {"COMPLETE", "PARTIAL"}
                        and self.memory["runs"][row["run_id"]]["finished_at"] is not None]
                row = max(rows, key=lambda item: (utc(self.memory["runs"][item["run_id"]]["finished_at"]),
                          item["batch_index"], item["item_index"], str(item["id"])), default=None)
            else:
                row = conn.execute(select(self.records).join(self.runs, self.records.c.run_id == self.runs.c.id)
                    .where(self.records.c.entity_id == entity_id, self.records.c.operation == operation,
                           self.records.c.record_type == "entity_observation",
                           self.runs.c.status.in_(["COMPLETE", "PARTIAL"]), self.runs.c.finished_at.is_not(None))
                    .order_by(self.runs.c.finished_at.desc(), self.records.c.batch_index.desc(),
                              self.records.c.item_index.desc(), self.records.c.id.desc()).limit(1)).mappings().first()
            if row is None:
                return None
            run = self._get(conn, "runs", row["run_id"])
            return {"record": copy.deepcopy(dict(row)), "run": {key: run[key] for key in (
                "id", "status", "connection_id", "revision", "started_at", "finished_at", "reasons")}}

    def provider_events(self, *, offset=0, limit=100, provider="", event_type="", connection_id=None, run_id=None,
                        exclude_purposes=()):
        """Events a provider reported, newest first.

        These are not CreMore's own audit records: nobody here performed them,
        and what a provider returns is bounded by its retention and by the scope
        the connection was allowed to read. They are paged and counted on their
        own so that boundary is never blurred with the local action history.
        ``exclude_purposes`` leaves those purposes' events out, facets included.
        ``run_id`` keeps one run's events (a collector that stores its whole look-back window every run).
        Without it, an event several runs stored (the same ``event_key`` on one connection) is listed once,
        from the newest run that stored it.
        """
        with self.transaction() as conn:
            if conn is None:
                rows = [copy.deepcopy(r) for r in self.memory["records"].values()
                        if r["record_type"] == "provider_event" and r["purpose"] not in exclude_purposes]
                providers, providers_cut = _bounded_facets(r["provider"] for r in rows)
                types, types_cut = _bounded_facets(r["body"].get("event_type") for r in rows)
                facets = {"provider": providers, "event_type": types}
                facets_cut = providers_cut or types_cut
                rows = [r for r in rows if (not provider or r["provider"] == provider)
                        and (not connection_id or r["connection_id"] == connection_id)
                        and (not run_id or r["run_id"] == run_id)
                        and (not event_type or r["body"].get("event_type") == event_type)]
                if not run_id:
                    newest = {}
                    for r in rows:
                        key = (r["connection_id"], r["event_key"])
                        if r["event_key"] and (key not in newest or (utc(r["observed_at"]), str(r["id"]))
                                               > (utc(newest[key]["observed_at"]), str(newest[key]["id"]))):
                            newest[key] = r
                    rows = [r for r in rows if not r["event_key"] or newest[(r["connection_id"], r["event_key"])] is r]
                rows.sort(key=lambda r: (utc(r["effective_at"]), utc(r["observed_at"]), str(r["id"])), reverse=True)
                kinds, kinds_cut = _bounded_facets(r["body"].get("event_type") for r in rows)
                total, shown = len(rows), rows[offset:offset + limit]
            else:
                table = self.records
                predicate = [table.c.record_type == "provider_event"]
                if exclude_purposes:
                    predicate.append(table.c.purpose.not_in(tuple(exclude_purposes)))
                facets, facets_cut = {}, False
                for name, column in (("provider", table.c.provider), ("event_type", table.c.body["event_type"].as_string())):
                    values = conn.execute(select(column).where(*predicate, column.is_not(None), column != "").distinct().order_by(column)
                                          .limit(EVENT_FACET_LIMIT + 1)).scalars()
                    facets[name], cut = _bounded_facets(values)
                    facets_cut |= cut
                for column, value in ((table.c.provider, provider), (table.c.connection_id, connection_id),
                                      (table.c.run_id, run_id)):
                    if value:
                        predicate.append(column == value)
                if event_type:
                    predicate.append(table.c.body["event_type"].as_string() == event_type)
                if not run_id:
                    rank = func.row_number().over(partition_by=(table.c.connection_id, table.c.event_key),
                                                  order_by=(table.c.observed_at.desc(), table.c.id.desc())).label("rank")
                    ranked = select(table.c.id, rank).where(table.c.record_type == "provider_event",
                                                             table.c.event_key.is_not(None)).subquery()
                    predicate.append(or_(table.c.event_key.is_(None),
                                         table.c.id.in_(select(ranked.c.id).where(ranked.c.rank == 1))))
                total = conn.execute(select(func.count()).select_from(table).where(*predicate)).scalar_one()
                shown = [dict(r) for r in conn.execute(select(table).where(*predicate).order_by(
                    table.c.effective_at.desc(), table.c.observed_at.desc(), table.c.id.desc()).offset(offset).limit(limit)).mappings()]
                column = table.c.body["event_type"].as_string()
                kinds, kinds_cut = _bounded_facets(conn.execute(select(column).where(*predicate, column.is_not(None), column != "")
                    .distinct().order_by(column).limit(EVENT_FACET_LIMIT + 1)).scalars())
            names = {}
            for row in shown:
                for key in ("subject_id", "target_id"):
                    if row[key] and row[key] not in names:
                        entity = self._get(conn, "entities", row[key])
                        names[row[key]] = None if entity is None else {
                            "entity_id": str(entity["id"]), "object_id": entity["object_id"],
                            "object_kind": entity["object_kind"]}
            items = [{"id": str(row["id"]), "provider": row["provider"],
                      "connection_id": str(row["connection_id"]), "run_id": str(row["run_id"]),
                      "event_type": row["body"].get("event_type", ""),
                      "event_id": row["body"].get("event_id", ""),
                      "occurred_at": row["body"].get("occurred_at"),
                      "observed_at": row["observed_at"],
                      # How the provider tied this event to an object. An event
                      # matched by candidate is not an event about that object.
                      "match_basis": row["body"].get("match_basis", "UNKNOWN"),
                      "confidence": row["body"].get("confidence", "UNKNOWN"),
                      "subject": names.get(row["subject_id"]), "target": names.get(row["target_id"]),
                      "facts": row["body"].get("facts", [])}
                     for row in shown]
        return {"schema_version": 2, "items": items, "total": total, "offset": offset,
                "limit": limit, "event_types": kinds, "facets": facets,
                "facets_truncated": facets_cut, "event_types_truncated": kinds_cut,
                # Naming what this is not is part of the answer.
                "boundary": "PROVIDER_REPORTED_NOT_CREMORE_ACTIONS"}

    def token_activity(self, fingerprints, *, limit=1000):
        """GitHub audit summaries whose private keyed token digest is one of these."""
        fingerprints = sorted(set(fingerprints))
        if not fingerprints:
            return []
        # ponytail: JSON-path filter over GitHub event records; add an indexed
        # digest column if finding lookups become slow on large audit histories.
        with self.transaction() as conn:
            if conn is None:
                rows = [copy.deepcopy(r) for r in self.memory["records"].values()
                        if r["record_type"] == "provider_event" and r["provider"] == "github"
                        and r["body"].get("event_type") == "token_activity"
                        and (r["body"].get("value_match") or {}).get("fingerprint") in fingerprints][:limit]
            else:
                table = self.records
                rows = [dict(r) for r in conn.execute(select(table).where(
                    table.c.record_type == "provider_event", table.c.provider == "github",
                    table.c.body["event_type"].as_string() == "token_activity",
                    table.c.body[("value_match", "fingerprint")].as_string().in_(fingerprints)).limit(limit)).mappings()]
        return rows

    def entity_detail(self, eid, *, offset=0, limit=100):
        with self.transaction() as conn:
            entity = self._get(conn, "entities", eid)
            collections = self._collections_for_entities(conn, [eid])[eid] if entity else []
            current = self._get(conn, "records", entity["current_record_id"]) if entity and entity["current_record_id"] else None
            success = self._get(conn, "records", entity["last_success_record_id"]) if entity and entity["last_success_record_id"] else None
        if entity is None:
            raise CoverageError("ENTITY_NOT_FOUND")
        return {"schema_version": 2, "entity": entity, "collections": collections, "verification": "NOT_PERFORMED",
                "current_record": current, "last_success_record": success,
                "records": self.record_page(entity_id=eid, offset=offset, limit=limit)}

    def latest_success(self, cid):
        with self.transaction() as conn:
            if conn is None:
                row = next((r for r in self._connection_runs(conn, cid) if r["status"] == "COMPLETE"), None)
            else:
                row = conn.execute(select(self.runs).where(self.runs.c.connection_id == cid,
                    self.runs.c.status == "COMPLETE").order_by(self.runs.c.sequence.desc()).limit(1)).mappings().first()
        return None if row is None else {k: row[k] for k in ("id", "connection_id", "revision", "sequence", "status", "reasons", "item_count", "started_at", "finished_at")}

    def run_detail(self, rid, *, offset=0, limit=100, record_type=""):
        with self.transaction() as conn:
            run = self._get(conn, "runs", rid)
        if run is None:
            raise CoverageError("RUN_NOT_FOUND")
        if run["contract"].get("schema_version") != 2:
            raise CoverageError("COVERAGE_SCHEMA_MISMATCH")
        return {"schema_version": 2, "run": run,
                "records": self.record_page(run_id=rid, record_type=record_type, offset=offset, limit=limit)}

    def iter_records(self, rid):
        offset = 0
        while True:
            page = self.record_page(run_id=rid, offset=offset, limit=250)
            for row in page["items"]:
                yield row["body"]
            if page["next_offset"] is None:
                break
            offset = page["next_offset"]

    def previous_success(self, cid, revision, contract, *, before_run=None):
        with self.transaction() as conn:
            rows = self._connection_runs(conn, cid)
        for row in rows:
            if (row["id"] != before_run and row["revision"] == revision and row["status"] == "COMPLETE"
                    and row["contract"] == contract):
                return row
        return None

    def prune_runs(self, cid, *, before, keep=()):
        """Delete a connection's finished runs that ended before ``before`` (never one in
        ``keep``) with their batches and records, then the entities no remaining record
        observes. Used for identity collections, whose history is personal data kept
        only for a bounded time; nothing else calls it. Returns the deleted run count."""
        keep = set(keep)
        with self.transaction() as conn:
            runs = [row for row in self._connection_runs(conn, cid) if row["finished_at"] is not None
                    and utc(row["finished_at"]) < before and row["id"] not in keep and row["status"] != "RUNNING"]
            ids = {row["id"] for row in runs}
            if not ids:
                return 0
            from cremore.db.people_directory_store import prune_profiles

            prune_profiles(self, conn, ids)
            if conn is None:
                touched = {record[key] for record in self.memory["records"].values() if record["run_id"] in ids
                           for key in ("entity_id", "subject_id", "target_id") if record[key]}
                for key in [key for key, record in self.memory["records"].items() if record["run_id"] in ids]:
                    del self.memory["records"][key]
                for key in [key for key in self.memory["batches"] if key[0] in ids]:
                    del self.memory["batches"][key]
                for run_id in ids:
                    self.memory["runs"].pop(run_id, None)
                used = {record[key] for record in self.memory["records"].values()
                        for key in ("entity_id", "subject_id", "target_id") if record[key]}
                for entity_id in touched - used:
                    self.memory["entities"].pop(entity_id, None)
                for entity_id in touched & used:
                    entity = self.memory["entities"].get(entity_id)
                    if entity and entity["current_record_id"] not in self.memory["records"]:
                        entity.update(summary=None, current_record_id=None, latest_run_id=None)
                    if entity and entity["last_success_record_id"] not in self.memory["records"]:
                        entity["last_success_record_id"] = None
                return len(ids)
            records = self.records
            touched = set()
            for key in ("entity_id", "subject_id", "target_id"):
                column = getattr(records.c, key)
                touched |= set(conn.execute(select(column).where(records.c.run_id.in_(ids), column.is_not(None))).scalars())
            conn.execute(delete(records).where(records.c.run_id.in_(ids)))
            conn.execute(delete(self.batches).where(self.batches.c.run_id.in_(ids)))
            conn.execute(delete(self.runs).where(self.runs.c.id.in_(ids)))
            if touched:
                used = set()
                for key in ("entity_id", "subject_id", "target_id"):
                    column = getattr(records.c, key)
                    used |= set(conn.execute(select(column).where(column.in_(touched))).scalars())
                gone = touched - used
                if gone:
                    conn.execute(delete(self.entities).where(self.entities.c.id.in_(gone)))
                remaining = touched & used
                if remaining:
                    live = select(records.c.id)
                    entities = self.entities
                    conn.execute(update(entities).where(entities.c.id.in_(remaining), entities.c.current_record_id.not_in(live))
                                 .values(summary=None, current_record_id=None, latest_run_id=None))
                    conn.execute(update(entities).where(entities.c.id.in_(remaining),
                                                        entities.c.last_success_record_id.not_in(live))
                                 .values(last_success_record_id=None))
            return len(ids)

    def rebuild_projection(self, cid):
        """Explicit bounded replay; never deletes immutable batches or records."""
        with self.transaction() as conn:
            owner = self._get(conn, "connections", cid, lock=True)
            if owner is None or owner["spec"].get("schema_version") != 2:
                raise CoverageError("COVERAGE_SCHEMA_MISMATCH")
            from cremore.coverage.metadata_models import MetadataBatch

            runs = sorted(self._connection_runs(conn, cid), key=lambda r: r["sequence"])
            for run in runs:
                for batch in self._batches(conn, run["id"]):
                    project_batch(self, conn, run, MetadataBatch(index=batch["index"], items=[RECORD_ADAPTER.validate_python(i) for i in batch["items"]]))
                finish_projection(self, conn, run)
        return {"runs": len(runs)}
