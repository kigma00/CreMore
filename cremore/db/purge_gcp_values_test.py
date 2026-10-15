"""The explicit cleanup touches only retired raw-value rows and fails atomically."""

import pytest
from sqlalchemy import event, text

from cremore.db.purge_gcp_values import purge
from cremore.db.sql import make_engine


def test_purge_is_explicit_idempotent_and_preserves_other_tables():
    engine = make_engine("sqlite:///:memory:")
    try:
        assert purge(engine) == {"rows": 0, "deleted": 0}
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE gcp_values (body TEXT)"))
            conn.execute(text("INSERT INTO gcp_values VALUES ('retired')"))
            conn.execute(text("CREATE TABLE finding_events (id INTEGER)"))
            conn.execute(text("INSERT INTO finding_events VALUES (1)"))
        assert purge(engine) == {"rows": 1, "deleted": 0}
        with pytest.raises(ValueError, match="OFFLINE_GCP_VALUE_PURGE_REQUIRED"):
            purge(engine, apply=True)

        def fail_commit(_conn):
            raise RuntimeError("abort")

        event.listen(engine, "commit", fail_commit)
        with pytest.raises(RuntimeError, match="abort"):
            purge(engine, apply=True, offline=True)
        event.remove(engine, "commit", fail_commit)
        assert purge(engine) == {"rows": 1, "deleted": 0}
        assert purge(engine, apply=True, offline=True) == {"rows": 1, "deleted": 1}
        assert purge(engine, apply=True, offline=True) == {"rows": 0, "deleted": 0}
        with engine.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM finding_events")).scalar_one() == 1
    finally:
        engine.dispose()
