"""Root-level catalog storage, with bounded legacy reads until explicit backfill."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import uuid

from sqlalchemy import (
    and_,
    delete,
    exists,
    func,
    insert,
    or_,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from cremore.db.schema import catalog_indexes, catalog_resources, scope_catalogs
from cremore.domain.models import ScopeCatalog
from cremore.scanning import scope


def _where(table, kind, cid):
    return and_(table.c.kind == kind, table.c.connection_id == cid)


def _model(row) -> ScopeCatalog | None:
    if row is None:
        return None
    data = dict(row)
    for key in ("created_at", "updated_at", "refreshed_at"):
        if data.get(key) is not None and data[key].tzinfo is None:
            data[key] = data[key].replace(tzinfo=dt.UTC)
    return ScopeCatalog(**data)


def _cursor_query(query):
    return hashlib.sha256(json.dumps({k: v for k, v in query.items() if k not in ("cursor", "page_size")},
                                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]


class CatalogStore:
    def __init__(self, repo):
        self.repo = repo
        self.engine = getattr(repo, "engine", None)

    def _header(self, conn, kind, cid, *, exclusive=False):
        columns = [column for column in scope_catalogs.c if column.name != "items"]
        row = conn.execute(select(*columns).where(_where(scope_catalogs, kind, cid))
                           .with_for_update(read=not exclusive)).mappings().first()
        return _model(row)

    def header(self, kind: str, cid: uuid.UUID) -> ScopeCatalog | None:
        if self.engine is None:
            catalog = self.repo.get_catalog(kind, cid)
            return catalog.model_copy(update={"items": []}) if catalog else None
        with self.engine.begin() as conn:
            return self._header(conn, kind, cid)

    def _indexed(self, conn, catalog):
        if catalog is None:
            return False
        snapshot = conn.execute(select(catalog_indexes.c.snapshot_id)
                                .where(_where(catalog_indexes, catalog.kind, catalog.connection_id))).scalar()
        if snapshot is not None and snapshot != catalog.snapshot_id:
            raise scope.ScopeError("SCOPE_CATALOG_INDEX_STALE", "refresh the resource catalog", http_status=409)
        return snapshot is not None

    def save_header(self, catalog: ScopeCatalog) -> ScopeCatalog:
        if self.engine is None:
            old = self.repo.get_catalog(catalog.kind, catalog.connection_id)
            return self.repo.save_catalog(old.model_copy(update={"refresh_job_id": catalog.refresh_job_id,
                                           "reason_code": catalog.reason_code}) if old else catalog)
        with self.engine.begin() as conn:
            current = self._header(conn, catalog.kind, catalog.connection_id, exclusive=True)
            if current is None:
                self._write_header(conn, catalog)
            else:
                conn.execute(update(scope_catalogs).where(_where(scope_catalogs, catalog.kind, catalog.connection_id))
                             .values(refresh_job_id=catalog.refresh_job_id, reason_code=catalog.reason_code))
        return self.header(catalog.kind, catalog.connection_id)

    def _write_header(self, conn, catalog):
        values = catalog.model_dump(exclude={"id", "created_at", "updated_at", "items"})
        now = dt.datetime.now(dt.UTC)
        existing = conn.execute(select(scope_catalogs.c.id).where(
            _where(scope_catalogs, catalog.kind, catalog.connection_id)).with_for_update()).scalar()
        if existing is None:
            conn.execute(insert(scope_catalogs).values(**values, id=uuid.uuid4(), items=[], created_at=now, updated_at=now))
        else:
            # Preserve the old JSON snapshot for explicit rollback/backfill;
            # normalized readers never fetch that large field after migration.
            conn.execute(update(scope_catalogs).where(scope_catalogs.c.id == existing)
                         .values(**values, updated_at=now))

    def _upsert(self, conn, table, values, keys):
        if not values:
            return
        values = list({tuple(value[key] for key in keys): value for value in values}.values())
        statement = (pg_insert if conn.dialect.name == "postgresql" else sqlite_insert)(table).values(values)
        conn.execute(statement.on_conflict_do_update(index_elements=keys, set_={
            column.name: statement.excluded[column.name] for column in table.c if column.name not in keys}))

    def refresh(self, catalog: ScopeCatalog, listed, *, replace: bool = True, batch_size: int = 500) -> ScopeCatalog:
        """Publish one complete or explicitly partial root snapshot atomically."""
        if not 1 <= batch_size <= 1000:
            raise ValueError("catalog batch_size must be between 1 and 1000")
        if self.engine is None:
            old = self.repo.get_catalog(catalog.kind, catalog.connection_id)
            items = scope.apply_refresh(old.items if old else [], list(listed), replace=replace)
            return self.repo.save_catalog(catalog.model_copy(update={"items": items}))
        with self.engine.begin() as conn:
            # Serialize the short publication/read boundary for this connection.
            old = self._header(conn, catalog.kind, catalog.connection_id, exclusive=True)
            indexed = self._indexed(conn, old)
            self._write_header(conn, catalog)
            if not replace and not indexed and old:
                legacy = conn.execute(select(scope_catalogs.c["items"]).where(
                    _where(scope_catalogs, catalog.kind, catalog.connection_id))).scalar() or []
                self._write_rows(conn, catalog, legacy, batch_size)
            self._write_rows(conn, catalog, listed, batch_size)
            if replace:
                conn.execute(delete(catalog_resources).where(_where(catalog_resources, catalog.kind, catalog.connection_id),
                    catalog_resources.c.observed_snapshot != catalog.snapshot_id))
            self._upsert(conn, catalog_indexes, [{"kind": catalog.kind, "connection_id": catalog.connection_id,
                         "snapshot_id": catalog.snapshot_id}], ["kind", "connection_id"])
        return self.header(catalog.kind, catalog.connection_id)

    def _write_rows(self, conn, catalog, listed, batch_size):
        batch = []
        for item in listed:
            if not item.get("id") or item.get("resource_type") not in scope.RESOURCE_TYPES:
                raise ValueError("catalog rows must identify provider roots")
            item = dict(item)
            for field in ("last_edited_at", "last_synced_at", "last_scan_at"):
                observed = scope.parse_stamp(item.get(field))
                if observed is not None:
                    item[field] = observed.astimezone(dt.UTC).isoformat()
            stamp = scope.parse_stamp(item.get("last_edited_at") or item.get("last_synced_at"))
            batch.append({"kind": catalog.kind, "connection_id": catalog.connection_id,
                          "resource_id": item["id"], "observed_snapshot": catalog.snapshot_id,
                          "name_key": str(item.get("display_name") or "").lower(),
                          "updated_key": stamp.astimezone(dt.UTC).isoformat() if stamp else "",
                          "resource_type": item["resource_type"], "account_id": item.get("account_id"),
                          "region": item.get("region"), "item": item})
            if len(batch) >= batch_size:
                self._upsert(conn, catalog_resources, batch, ["kind", "connection_id", "resource_id"])
                batch = []
        self._upsert(conn, catalog_resources, batch, ["kind", "connection_id", "resource_id"])

    def backfill(self, kind: str, cid: uuid.UUID, *, batch_size: int = 500) -> int:
        """Explicit maintenance step; never called during API/worker startup."""
        catalog = self.repo.get_catalog(kind, cid)
        if catalog is None:
            return 0
        if self.engine is not None:
            with self.engine.begin() as conn:
                if self._indexed(conn, catalog):
                    return 0
        self.refresh(catalog, catalog.items, batch_size=batch_size)
        return len(catalog.items)

    def selected(self, kind: str, cid: uuid.UUID, ids) -> ScopeCatalog | None:
        ids = list(dict.fromkeys(ids))
        chosen = set(ids)
        if len(ids) > scope.MAX_ROOTS:
            raise ValueError("too many catalog roots")
        if self.engine is None:
            catalog = self.repo.get_catalog(kind, cid)
            return catalog.model_copy(update={"items": [i for i in catalog.items if i["id"] in chosen]}) if catalog else None
        with self.engine.begin() as conn:
            catalog = self._header(conn, kind, cid)
            if self._indexed(conn, catalog):
                items = list(conn.execute(select(catalog_resources.c.item).where(
                    _where(catalog_resources, kind, cid), catalog_resources.c.resource_id.in_(ids))).scalars()) if ids else []
                return catalog.model_copy(update={"items": items})
        legacy = self.repo.get_catalog(kind, cid)
        return legacy.model_copy(update={"items": [i for i in legacy.items if i["id"] in chosen]}) if legacy else None

    def _array_contains(self, conn, field, value):
        if conn.dialect.name == "postgresql":
            return catalog_resources.c.item[field].cast(JSONB).contains([value])
        entries = func.json_each(catalog_resources.c.item, "$." + field).table_valued("key", "value")
        return exists(select(1).select_from(entries).where(entries.c.value == value))

    def _filters(self, conn, query):
        table, clauses = catalog_resources, []
        field = lambda name: table.c.item[name].as_string()
        if query.get("q"):
            q = query["q"].lower()
            clauses.append(or_(table.c.name_key.contains(q, autoescape=True),
                               func.lower(field("provider_resource_id")).contains(q, autoescape=True),
                               table.c.resource_id == q))
        for key in scope._EXACT_FILTERS:
            if not query.get(key):
                continue
            column = table.c[key] if key in ("resource_type", "region", "account_id") else field(key)
            clauses.append(or_(column.is_(None), column.in_(["", "UNKNOWN"])) if query[key] == "UNKNOWN" else column == query[key])
        for query_key, name in (("access_status", "content_readiness"), ("last_sync_status", "last_sync_status"),
                                ("last_scan_status", "last_scan_status")):
            if query.get(query_key):
                clauses.append(func.coalesce(field(name), "UNKNOWN") == query[query_key])
        for key in ("archived", "fork"):
            if query.get(key):
                value = table.c.item[key].as_boolean()
                clauses.append(value.is_(None) if query[key] == "unknown" else value == (query[key] == "true"))
        for key, name in (("topic", "topics"), ("known_root_id", "known_root_ids")):
            if query.get(key):
                clauses.append(field(name).is_(None) if query[key] == "UNKNOWN" else self._array_contains(conn, name, query[key]))
        for key, (name, before) in scope._DATE_FILTERS.items():
            if query.get(key):
                # RFC3339 fields are normalized at write time for SQL comparisons.
                column = field(name)
                bound = scope.parse_stamp(query[key]).astimezone(dt.UTC).isoformat()
                clauses.append(column <= bound if before else column >= bound)
        if query.get("selected"):
            chosen = table.c.resource_id.in_(query.get("selected_ids") or [])
            clauses.append(chosen if query["selected"] == "true" else ~chosen)
        if query.get("exclude"):
            clauses.append(~func.coalesce(and_(*self._filters(conn, query["exclude"])), False))
        return clauses

    def matching(self, kind, cid, query, *, limit=scope.MAX_ROOTS + 1):
        catalog, items, _count, _cursor = self.page(kind, cid, query, limit=limit, selectable_only=True)
        return catalog, items

    def page(self, kind, cid, query, *, limit=None, selectable_only=False):
        size = limit or query.get("page_size", 50)
        if self.engine is not None:
            with self.engine.begin() as conn:
                catalog = self._header(conn, kind, cid)
                if self._indexed(conn, catalog):
                    return self._sql_page(conn, catalog, query, size, selectable_only)
        catalog = self.repo.get_catalog(kind, cid)
        if selectable_only:
            items = [i for i in scope.filter_items(catalog.items if catalog else [], query) if scope.selectable(i)]
            return catalog, items[:size], len(items), None
        page = scope.catalog_page(catalog, kind, cid, "aws", "", {**query, "page_size": size})
        return catalog, page["items"], page["known_count"], page.get("next_cursor")

    def _sql_page(self, conn, catalog, query, size, selectable_only):
        table = catalog_resources
        clauses = [_where(table, catalog.kind, catalog.connection_id), *self._filters(conn, query)]
        if selectable_only:
            clauses.extend((table.c.item["list_visibility"].as_string() == "VISIBLE",
                            table.c.item["content_readiness"].as_string().in_(scope.SELECTABLE_READINESS)))
        total = conn.execute(select(func.count()).select_from(table).where(*clauses)).scalar_one()
        descending = query.get("sort") in ("name_desc", "updated_desc")
        key = table.c.updated_key if query.get("sort") == "updated_desc" else table.c.name_key
        cursor = query.get("cursor")
        if cursor:
            try:
                snapshot, mode, encoded = cursor.split(":", 2)
                last_id, digest = json.loads(base64.urlsafe_b64decode(encoded))
                if snapshot != catalog.snapshot_id or mode != "k" or digest != _cursor_query(query):
                    raise ValueError()
                previous = conn.execute(select(key).where(_where(table, catalog.kind, catalog.connection_id),
                                                          table.c.resource_id == last_id)).scalar_one()
            except Exception as exc:
                raise scope.ScopeError("SCOPE_CURSOR_EXPIRED", "the catalog or query changed", http_status=410) from exc
            if descending:
                clauses.append(or_(key < previous, and_(key == previous, table.c.resource_id < last_id)))
            else:
                clauses.append(or_(key > previous, and_(key == previous, table.c.resource_id > last_id)))
        order = (key.desc(), table.c.resource_id.desc()) if descending else (key, table.c.resource_id)
        rows = conn.execute(select(table.c.item, table.c.resource_id).where(*clauses).order_by(*order).limit(size + 1)).all()
        next_cursor = None
        if len(rows) > size:
            encoded = base64.urlsafe_b64encode(json.dumps([rows[size - 1].resource_id, _cursor_query(query)]).encode()).decode()
            next_cursor = f"{catalog.snapshot_id}:k:{encoded}"
        return catalog, [row.item for row in rows[:size]], total, next_cursor
