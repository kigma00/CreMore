"""Batch settings writes preserve their atomicity and single-setting API."""

import pytest
from sqlalchemy import event

from cremore.db.repository import InMemoryRepository
from cremore.db.settings_store import locked_settings
from cremore.db.sql import SqlRepository, create_all, make_engine


@pytest.fixture(params=["memory", "sql"])
def repo(request):
    if request.param == "memory":
        yield InMemoryRepository()
    else:
        engine = make_engine("sqlite+pysqlite:///:memory:")
        create_all(engine)
        try:
            yield SqlRepository(engine)
        finally:
            engine.dispose()


def test_settings_batch_updates_values_and_actor_together(repo):
    repo.put_setting("first", {"enabled": False}, "old-actor")
    values = {"first": {"enabled": True}, "second": {"enabled": True}}
    records = repo.put_settings(values, "new-actor")
    assert records["first"]["updated_at"] == records["second"]["updated_at"]
    values["first"]["enabled"] = False
    records["second"]["value"]["enabled"] = False
    for key in values:
        record = repo.get_setting(key)
        assert record["value"] == {"enabled": True}
        assert record["updated_by"] == "new-actor"
    assert repo.put_settings({}, "ignored") == {}


def test_invalid_batch_preserves_existing_and_missing_settings(repo):
    before = repo.put_setting("first", {"enabled": False}, "old-actor")
    with pytest.raises(TypeError):
        repo.put_settings({"first": {"enabled": True}, "second": None}, "new-actor")
    assert repo.get_setting("first") == before
    assert repo.get_setting("second") is None


def test_revisioned_settings_replace_payload_and_keep_actor_with_revision(repo):
    repo.put_setting("approval", {"legacy": True}, "previous")
    incoming = {"identity": "first", "revision": 999}
    first = repo.put_revisioned_setting("approval", incoming, "admin-1")
    assert first["value"] == {"identity": "first", "revision": 2}
    assert incoming["revision"] == 999
    first["value"]["identity"] = "mutated"
    second = repo.put_revisioned_setting("approval", {"identity": "second"}, "admin-2")
    assert second["value"] == {"identity": "second", "revision": 3}
    assert repo.get_setting("approval") == second
    assert second["updated_by"] == "admin-2"


@pytest.mark.parametrize("existing", [False, True])
def test_revisioned_setting_failure_rolls_back_placeholder_and_revision(existing):
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    repo = SqlRepository(engine)
    before = repo.put_setting("approval", {"revision": 7}, "previous") if existing else None

    def fail_update(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("UPDATE installation_settings"):
            raise RuntimeError("synthetic settings failure")

    event.listen(engine, "before_cursor_execute", fail_update)
    try:
        with pytest.raises(RuntimeError, match="settings failure"):
            repo.put_revisioned_setting("approval", {"identity": "changed"}, "admin")
        assert repo.get_setting("approval") == before
    finally:
        event.remove(engine, "before_cursor_execute", fail_update)
        engine.dispose()


def test_failed_second_database_write_rolls_back_first():
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    repo = SqlRepository(engine)
    before = repo.put_setting("first", {"enabled": False}, "old-actor")
    writes = 0

    def fail_second(conn, cursor, statement, parameters, context, executemany):
        nonlocal writes
        if statement.startswith("INSERT INTO installation_settings"):
            writes += 1
            if writes == 2:
                raise RuntimeError("synthetic database failure")

    event.listen(engine, "before_cursor_execute", fail_second)
    try:
        with pytest.raises(RuntimeError, match="synthetic database failure"):
            repo.put_settings({"first": {"enabled": True}, "second": {"enabled": True}}, "new-actor")
        assert writes == 2
        assert repo.get_setting("first") == before
        assert repo.get_setting("second") is None
    finally:
        event.remove(engine, "before_cursor_execute", fail_second)
        engine.dispose()


def test_locked_settings_bound_write_cannot_commit_before_outer_transaction():
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    repo = SqlRepository(engine)
    repo.put_setting("parent", {"enabled": True}, "admin")
    try:
        with pytest.raises(RuntimeError, match="synthetic failure"), locked_settings(repo, setting_key="parent") as bound:
            bound.put_setting("child", {"pending": True}, "worker")
            raise RuntimeError("synthetic failure")
        assert repo.get_setting("child") is None
    finally:
        engine.dispose()
