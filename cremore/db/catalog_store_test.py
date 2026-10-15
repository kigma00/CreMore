import datetime as dt
import subprocess
import sys
import uuid

import pytest
from sqlalchemy import event, select

from cremore.db.catalog_store import CatalogStore, catalog_resources
from cremore.db.repository import InMemoryRepository
from cremore.db.schema import metadata, scope_catalogs
from cremore.db.sql import SqlRepository, make_engine
from cremore.domain.models import ScopeCatalog
from cremore.scanning import scope


def test_schema_registers_catalog_tables_without_importing_the_store():
    subprocess.run([sys.executable, "-c", """
import sys
from cremore.db import schema
assert 'cremore.db.catalog_store' not in sys.modules
from cremore.db import catalog_store
for name in ('catalog_resources', 'catalog_indexes'):
    assert schema.metadata.tables[name] is getattr(schema, name)
    assert getattr(catalog_store, name) is getattr(schema, name)
"""], check=True)


def sql_store():
    engine = make_engine("sqlite:///:memory:")
    metadata.create_all(engine)
    return CatalogStore(SqlRepository(engine))


def item(cid, name, **extra):
    return scope.resource("aws", cid, "S3_BUCKET", name, name, f"arn:aws:s3:::{name}", "aws", **extra)


def test_normalized_catalog_exceeds_legacy_cap_without_fetching_legacy_json_on_pages():
    store, cid = sql_store(), uuid.uuid4()
    legacy = [item(cid, "legacy")]
    store.repo.save_catalog(ScopeCatalog(kind="aws", connection_id=cid, snapshot_id="old", items=legacy))
    listed = [item(cid, f"bucket-{i:05}", region="us-east-1") for i in range(6001)]
    catalog = ScopeCatalog(kind="aws", connection_id=cid, snapshot_id="new", completeness="COMPLETE")
    store.refresh(catalog, listed)
    with store.engine.connect() as conn:
        assert conn.execute(select(scope_catalogs.c["items"])).scalar_one() == legacy
    statements = []
    def record(_conn, _cursor, statement, _params, _context, _many):
        statements.append(statement)
    event.listen(store.engine, "before_cursor_execute", record)
    query = scope.normalize_query({"page_size": 2})
    header, first, count, cursor = store.page("aws", cid, query)
    assert header.items == [] and count == 6001 and cursor
    _, second, count, _ = store.page("aws", cid, {**query, "cursor": cursor})
    assert [i["display_name"] for i in first + second] == [f"bucket-{i:05}" for i in range(4)]
    selected = store.selected("aws", cid, [listed[-1]["id"]])
    assert len(selected.items) == 1 and selected.items[0]["id"] == listed[-1]["id"]
    assert not any("scope_catalogs.items" in statement for statement in statements)
    assert any("LIMIT" in statement for statement in statements)
    with pytest.raises(scope.ScopeError, match="catalog or query changed"):
        store.page("aws", cid, {**query, "cursor": cursor, "region": "another"})


@pytest.mark.parametrize("query", [
    {"region": "UNKNOWN"}, {"region": "us-east-1"}, {"q": "%"}, {"archived": "false"},
    {"visibility": "PUBLIC"}, {"topic": "infra"}, {"topic": "UNKNOWN"},
    {"known_root_id": "parent"}, {"access_status": "NOT_PROBED"},
    {"synced_after": "2026-09-15T10:00:00+09:00"},
    {"exclude": {"region": "us-east-1"}}, {"exclude": {"topic": "infra"}},
])
def test_sql_filter_semantics_match_existing_scope_filter(query):
    cid = uuid.uuid4()
    stamp = dt.datetime(2026, 9, 15, 2, tzinfo=dt.UTC)
    items = [item(cid, "one", now=stamp, region="us-east-1", topics=["infra"], archived=False),
             item(cid, "two%", now=stamp, visibility="PUBLIC", known_root_ids=["parent"])]
    catalog = ScopeCatalog(kind="aws", connection_id=cid, snapshot_id="s", completeness="COMPLETE")
    normalized = scope.normalize_query(query)
    expected = scope.filter_items(items, normalized)
    store = sql_store()
    store.refresh(catalog, items)
    _, actual, count, _ = store.page("aws", cid, normalized)
    assert [i["id"] for i in actual] == [i["id"] for i in expected]
    assert count == len(expected)


def test_legacy_backfill_is_explicit_idempotent_and_keeps_catalog_completeness():
    store, cid = sql_store(), uuid.uuid4()
    legacy = ScopeCatalog(kind="aws", connection_id=cid, snapshot_id="legacy", completeness="PARTIAL",
                          items=[item(cid, "one")])
    store.repo.save_catalog(legacy)
    assert store.page("aws", cid, scope.normalize_query({}))[2] == 1
    with store.engine.connect() as conn:
        assert conn.execute(select(catalog_resources)).all() == []
    assert store.backfill("aws", cid, batch_size=1) == 1
    assert store.backfill("aws", cid) == 0
    assert store.header("aws", cid).completeness == "PARTIAL"
    assert store.repo.get_catalog("aws", cid).items == legacy.items


@pytest.mark.parametrize("memory", [False, True])
def test_narrow_refresh_keeps_other_roots_and_full_refresh_removes_only_its_catalog(memory):
    store = CatalogStore(InMemoryRepository()) if memory else sql_store()
    cid, other = uuid.uuid4(), uuid.uuid4()
    cat = ScopeCatalog(kind="aws", connection_id=cid, snapshot_id="first", completeness="PARTIAL")
    first, second = item(cid, "one"), item(cid, "two")
    store.refresh(cat, [first, second])
    store.refresh(ScopeCatalog(kind="aws", connection_id=other, snapshot_id="other"), [item(other, "safe")])
    store.refresh(cat.model_copy(update={"snapshot_id": "narrow"}), [{**first, "region": "new"}], replace=False)
    assert store.page("aws", cid, scope.normalize_query({}))[2] == 2
    store.refresh(cat.model_copy(update={"snapshot_id": "full"}), [first])
    assert store.page("aws", cid, scope.normalize_query({}))[2] == 1
    assert store.page("aws", other, scope.normalize_query({}))[2] == 1


def test_duplicate_provider_rows_in_one_batch_do_not_break_atomic_upsert():
    store, cid = sql_store(), uuid.uuid4()
    one = item(cid, "one")
    store.refresh(ScopeCatalog(kind="aws", connection_id=cid, snapshot_id="s"), [one, {**one, "region": "new"}])
    assert store.selected("aws", cid, [one["id"]]).items[0]["region"] == "new"
