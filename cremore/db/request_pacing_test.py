"""Shared admission across independent workers, without provider calls."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from cremore_notion_provider.collectors.requests import NotionRateLimiter

from cremore.collectors.base import guard_requests
from cremore.db.postgres_scan_test import pg  # noqa: F401 -- shared isolated DB fixture
from cremore.db.repository import InMemoryRepository
from cremore.db.scan_store import ScanStore
from cremore.db.sql import SqlRepository, create_all, make_engine

KEY = "a" * 64


@pytest.fixture(params=["memory", "sql", "postgres"])
def store(request, tmp_path):
    if request.param == "memory":
        repo = InMemoryRepository()
    elif request.param == "postgres":
        _engine, repo = request.getfixturevalue("pg")
    else:
        engine = make_engine("sqlite:///" + (tmp_path / "pacing.db").as_posix())
        create_all(engine)
        repo = SqlRepository(engine)
    return ScanStore(repo)


def test_concurrent_workers_admit_only_one_request(store, monkeypatch):
    monkeypatch.setattr("cremore.db.task_store._clock", lambda conn=None: datetime(2026, 1, 1, tzinfo=UTC))
    def attempt(_):
        return ScanStore(store.repo).request_delay(KEY, 0.4)
    with ThreadPoolExecutor(max_workers=8) as pool:
        delays = list(pool.map(attempt, range(24)))
    assert sum(d == 0 for d in delays) == 1
    assert all(d == 0 or d == pytest.approx(0.4) for d in delays)
    assert store.request_delay("b" * 64, 0.4) == 0


def test_cooldown_shared_and_uses_database_clock(store, monkeypatch):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    monkeypatch.setattr("cremore.db.task_store._clock", lambda conn=None: now)
    first = NotionRateLimiter(key=KEY)
    other = NotionRateLimiter(key=KEY)
    with guard_requests(lambda: None, pacing=store):
        first.acquire()
        first.defer(2)
        assert ScanStore(store.repo).request_delay(KEY, 0.4) == 2
        now += timedelta(seconds=2)
        other.acquire()
        assert store.request_delay(KEY, 0.4) == pytest.approx(0.4)


def test_waiting_request_observes_cancellation(store, monkeypatch):
    monkeypatch.setattr("cremore.db.task_store._clock", lambda conn=None: datetime(2026, 1, 1, tzinfo=UTC))
    store.request_delay(KEY, 0.4, cooldown=10)
    def cancelled():
        raise RuntimeError("CANCELLED_FIXTURE")
    with guard_requests(cancelled, pacing=store), pytest.raises(RuntimeError, match="CANCELLED_FIXTURE"):
        NotionRateLimiter(key=KEY).acquire()


@pytest.mark.parametrize("interval,cooldown", [(0, None), (float("nan"), None), (0.4, float("inf")), (0.4, -1)])
def test_invalid_pacing_rejected(store, interval, cooldown):
    with pytest.raises(ValueError, match="REQUEST_PACING_INVALID"):
        store.request_delay(KEY, interval, cooldown=cooldown)
