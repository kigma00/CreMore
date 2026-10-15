"""Content-cache rows: one row per object and digest, v2 values, legacy rows, batched lookups."""

import inspect
import os
import time
import uuid

import pytest
from sqlalchemy import event, text

from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- disposable PostgreSQL
from cremore.db.repository import InMemoryRepository
from cremore.db.scan_store import ScanStore
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.detection.models import SanitizedDetection


@pytest.fixture(params=["memory", "sql"])
def store(request):
    if request.param == "memory":
        return ScanStore(InMemoryRepository())
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return ScanStore(SqlRepository(engine))


def sqlite_store():
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return engine, ScanStore(SqlRepository(engine))


def detection():
    return SanitizedDetection(detector_name="synthetic", credential_type="synthetic", fingerprint="f" * 64,
                              provider="custom", identifier_hint="", line_number=1, redacted_line="x=****",
                              confidence="low", decoder_type="", material_kind="", extra_safe_data={})


def test_a_clean_s3_revision_is_a_row_and_answers_only_for_that_revision(store):
    cid = uuid.uuid4()
    store.cache(cid, "root", "config/a", "rev-1", "digest", [])
    assert store.cached(cid, "root", "config/a", "rev-1", "digest") == {
        "v": 2, "detections": [], "skip": None, "reasons": {}, "format": "text"}
    assert store.cached(cid, "root", "config/a", "rev-2", "digest") is None
    assert store.cached(cid, "root", "config/a", "rev-1", "other-digest") is None
    assert store.cached(uuid.uuid4(), "root", "config/a", "rev-1", "digest") is None


def test_a_new_revision_replaces_the_row_of_the_same_object(store):
    cid = uuid.uuid4()
    store.cache(cid, "root", "config/a", "rev-1", "digest", [])
    store.cache(cid, "root", "config/a", "rev-2", "digest", [detection()])
    assert store.cached(cid, "root", "config/a", "rev-1", "digest") is None
    assert store.cached(cid, "root", "config/a", "rev-2", "digest")["detections"][0]["fingerprint"] == "f" * 64
    if store.engine is None:
        assert len(store.memory["cache"]) == 1
    else:
        with store.engine.connect() as connection:
            assert connection.execute(text("SELECT count(*) FROM scan_detection_cache")).scalar() == 1


def test_skip_and_gap_rows_keep_only_codes(store):
    cid = uuid.uuid4()
    store.cache(cid, "root", "img.png", "rev", "digest", [], skip="MEDIA_FORMAT", reasons={"MEDIA_FORMAT": 1},
                fmt="image")
    store.cache(cid, "root", "doc.pdf", "rev", "digest", [detection()], reasons={"PDF_GRAPHICS_CONTENT": 1}, fmt="pdf")
    skip = store.cached(cid, "root", "img.png", "rev", "digest")
    gap = store.cached(cid, "root", "doc.pdf", "rev", "digest")
    assert skip["skip"] == "MEDIA_FORMAT" and skip["format"] == "image" and skip["detections"] == []
    assert gap["skip"] is None and gap["reasons"] == {"PDF_GRAPHICS_CONTENT": 1}
    assert gap["detections"][0]["fingerprint"] == "f" * 64
    with pytest.raises(ValueError, match="CACHE_SKIP_INVALID"):
        store.cache(cid, "root", "x", "rev", "digest", [detection()], skip="MEDIA_FORMAT")
    with pytest.raises(ValueError, match="CACHE_SKIP_INVALID"):
        store.cache(cid, "root", "x", "rev", "digest", [], skip="UNREADABLE")


def test_a_legacy_list_value_reads_as_a_complete_text_result():
    store = ScanStore(InMemoryRepository())
    cid = uuid.uuid4()
    store.cache(cid, "root", "a", "rev", "digest", [])
    identity = next(iter(store.memory["cache"]))
    store.memory["cache"][identity]["detections"] = [{"fingerprint": "f" * 64}]
    assert store.cached(cid, "root", "a", "rev", "digest") == {
        "v": 2, "detections": [{"fingerprint": "f" * 64}], "skip": None, "reasons": {}, "format": "text"}


def test_cached_many_answers_by_key_with_at_most_500_ids_per_select():
    engine, store = sqlite_store()
    cid = uuid.uuid4()
    keys = [("root", f"obj/{i:04d}", f"rev-{i}") for i in range(1200)]
    for key in keys[::2]:
        store.cache(cid, *key, "digest", [])
    selects = []

    @event.listens_for(engine, "before_cursor_execute")
    def count(_conn, _cursor, statement, parameters, _context, _many):
        if statement.lstrip().upper().startswith("SELECT") and "scan_detection_cache" in statement:
            selects.append(len(parameters))

    found = store.cached_many(cid, keys, "digest")
    event.remove(engine, "before_cursor_execute", count)
    assert set(found) == set(keys[::2]) and len(selects) == 3 and max(selects) <= 500


def fill(engine, cid, count, start=0):
    """Rows of the same root, as earlier objects of a first baseline would have left."""
    rows = [{"id": f"{i:064d}", "cid": cid.hex, "root": "r" * 64, "subject": f"data/{i:08d}"}
            for i in range(start, start + count)]
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO scan_detection_cache (id, connection_id, root_id, subject, revision, "
                                "digest, detections, updated_at) VALUES (:id, :cid, :root, :subject, 'rev', 'd', "
                                "'{}', CURRENT_TIMESTAMP)"), rows)


def test_a_clean_row_costs_the_same_statements_however_many_rows_its_root_has():
    engine, store = sqlite_store()
    cid = uuid.uuid4()
    statements = []

    @event.listens_for(engine, "before_cursor_execute")
    def count(_conn, _cursor, statement, _parameters, _context, _many):
        statements.append(statement.split()[0].upper())

    per_write, filled = [], 0
    for size in (100, 5_000):
        fill(engine, cid, size - filled, start=filled)
        filled = size
        statements.clear()
        store.cache(cid, "r" * 64, f"new/{size}", "rev", "d", [])
        per_write.append(list(statements))
    event.remove(engine, "before_cursor_execute", count)
    assert per_write[0] == per_write[1] and "DELETE" not in per_write[0]


def test_writing_a_clean_row_does_not_slow_down_as_the_root_grows():
    engine, store = sqlite_store()
    cid = uuid.uuid4()
    seconds, filled = [], 0
    for size in (1_000, 20_000):
        fill(engine, cid, size - filled, start=filled)
        filled = size
        started = time.perf_counter()
        for n in range(200):
            store.cache(cid, "r" * 64, f"new/{size}/{n}", "rev", "d", [])
        seconds.append(time.perf_counter() - started)
    # A DELETE scanning the root's rows per write grew about fivefold from 1,000 to 20,000 rows.
    assert seconds[1] < 2.5 * seconds[0] + 0.05, seconds


def test_prune_keeps_two_million_rows_by_default_and_evicts_past_the_bound(store):
    assert inspect.signature(ScanStore.prune_cache).parameters["max_entries"].default == 2_000_000
    cid = uuid.uuid4()
    for i in range(5):
        store.cache(cid, "root", f"o{i}", "rev", "digest", [])
    assert store.prune_cache() == 0
    assert store.prune_cache(max_entries=3) == 2


@pytest.fixture(params=["sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def sql_store(request):
    if request.param == "postgres":
        engine = request.getfixturevalue("pg")[0]
        return engine, ScanStore(SqlRepository(engine))
    return sqlite_store()


def test_the_row_count_pass_runs_only_when_the_table_can_hold_more_than_the_bound(sql_store):
    engine, store = sql_store
    cid = uuid.uuid4()
    for i in range(5):
        store.cache(cid, "root", f"o{i}", "rev", "digest", [])
    if engine.dialect.name == "postgresql":
        with engine.begin() as connection:
            connection.exec_driver_sql("ANALYZE scan_detection_cache")
    passes = []

    @event.listens_for(engine, "before_cursor_execute")
    def capture(_conn, _cursor, statement, _parameters, _context, _many):
        if "updated_at DESC" in statement:  # the newest-first pass that skips max_entries rows
            passes.append(statement)

    try:
        assert store.prune_cache(max_entries=100) == 0 and passes == []  # five rows cannot pass 100
        assert store.prune_cache(max_entries=3) == 2 and len(passes) == 1
    finally:
        event.remove(engine, "before_cursor_execute", capture)
