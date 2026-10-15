from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from cremore import http_client
from cremore.collectors.base import RequestPacer
from cremore.http_client import HTTPResponseTooLarge, bounded_request


class _StreamResponse:
    status_code = 200
    encoding = "utf-8"

    def __init__(self, chunks, headers=None):
        self.chunks = chunks
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def iter_bytes(self, chunk_size):
        assert chunk_size == 64 << 10
        yield from self.chunks


class _StreamingClient:
    def __init__(self, response):
        self.response = response

    def stream(self, method, url, **kwargs):
        assert (method, url) == ("GET", "https://provider.test/data")
        return self.response


def test_bounded_request_limits_advertised_and_chunked_responses_before_json_parse():
    ok = bounded_request(
        _StreamingClient(_StreamResponse([b'{"ok":', b"true}"])),
        "GET",
        "https://provider.test/data",
        max_response_bytes=11,
    )
    assert ok.json() == {"ok": True}

    for response in (
        _StreamResponse([], {"content-length": "12"}),
        _StreamResponse([b"123456", b"789012"]),
    ):
        with pytest.raises(HTTPResponseTooLarge):
            bounded_request(
                _StreamingClient(response),
                "GET",
                "https://provider.test/data",
                max_response_bytes=11,
            )


@pytest.mark.parametrize("charset", ["idna", "no-such-charset"])
def test_a_charset_that_cannot_be_read_falls_back_to_utf8(charset):
    # idna refuses the "replace" handler with a UnicodeError; an unknown name is a LookupError.
    response = _StreamResponse([b'{"ok":true}'])
    response.encoding = charset
    answer = bounded_request(_StreamingClient(response), "GET", "https://provider.test/data")
    assert (answer.text, answer.json()) == ('{"ok":true}', {"ok": True})


class _Clock:
    """The module's clock: sleeping moves it, and so may an attempt."""

    def __init__(self):
        self.now, self.sleeps = 1000.0, []

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def install(self, monkeypatch):
        monkeypatch.setattr(http_client, "time", SimpleNamespace(
            monotonic=lambda: self.now, time=lambda: self.now, sleep=self.sleep))
        return self


class _Answer:
    def __init__(self, status, headers=None):
        self.status_code, self.headers, self.content = status, headers or {}, b"{}"
        self.closed = False

    def close(self):
        self.closed = True


def _client(method, answers, clock=None, spent=0.0):
    calls = []

    def call(*_args, **_kwargs):
        calls.append(1)
        if clock is not None:
            clock.now += spent
        return answers[len(calls) - 1]

    return SimpleNamespace(**{method: call}), calls


def test_github_rate_limits_and_busy_gateways_are_retried_for_reads(monkeypatch):
    clock = _Clock().install(monkeypatch)
    answers = [_Answer(403, {"Retry-After": "1"}), _Answer(502), _Answer(200)]
    client, calls = _client("get", answers)
    charged = []
    result = bounded_request(client, "GET", "https://api.github.test/repos/o/r", retry_429=True,
                             before_attempt=lambda: charged.append(1))
    assert result.status_code == 200 and len(calls) == len(charged) == 3
    assert clock.sleeps == [1.0, 2.0] and answers[0].closed and answers[1].closed


@pytest.mark.parametrize("status", [502, 503, 504])
def test_each_busy_gateway_status_is_retried_at_most_three_times(monkeypatch, status):
    clock = _Clock().install(monkeypatch)
    client, calls = _client("get", [_Answer(status)] * 3)
    assert bounded_request(client, "GET", "https://provider.test", retry_429=True).status_code == status
    assert len(calls) == 3 and clock.sleeps == [1.0, 2.0]


@pytest.mark.parametrize("method,status", [("POST", 503), ("POST", 502), ("PUT", 504), ("DELETE", 503),
                                           ("POST", 403)])
def test_a_write_is_never_sent_twice_after_a_server_error(monkeypatch, method, status):
    clock = _Clock().install(monkeypatch)
    client, calls = _client(method.lower(), [_Answer(status, {"Retry-After": "0"}), _Answer(200)])
    assert bounded_request(client, method, "https://provider.test", retry_429=True).status_code == status
    assert calls == [1] and clock.sleeps == []


def test_a_plain_permission_refusal_is_not_retried(monkeypatch):
    clock = _Clock().install(monkeypatch)
    client, calls = _client("get", [_Answer(403, {"X-RateLimit-Remaining": "12"}), _Answer(200)])
    assert bounded_request(client, "GET", "https://provider.test", retry_429=True).status_code == 403
    assert calls == [1] and clock.sleeps == []


def test_retries_stay_opt_in(monkeypatch):
    clock = _Clock().install(monkeypatch)
    client, calls = _client("get", [_Answer(503), _Answer(200)])
    assert bounded_request(client, "GET", "https://provider.test").status_code == 503
    assert calls == [1] and clock.sleeps == []


@pytest.mark.parametrize("status", [403, 429])
def test_an_exhausted_github_limit_waits_for_its_reset(monkeypatch, status):
    clock = _Clock().install(monkeypatch)
    limited = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(clock.now) + 3)}
    client, calls = _client("get", [_Answer(status, limited), _Answer(200)])
    assert bounded_request(client, "GET", "https://api.github.test", retry_429=True).status_code == 200
    assert len(calls) == 2 and clock.sleeps == [3.0]


def test_a_reset_beyond_the_bound_returns_the_refusal_without_waiting(monkeypatch):
    clock = _Clock().install(monkeypatch)
    limited = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(clock.now) + 3600)}
    client, calls = _client("get", [_Answer(403, limited), _Answer(200)])
    assert bounded_request(client, "GET", "https://api.github.test", retry_429=True).status_code == 403
    assert calls == [1] and clock.sleeps == []


def test_waits_are_capped_by_the_time_the_attempts_left(monkeypatch):
    clock = _Clock().install(monkeypatch)
    client, calls = _client("get", [_Answer(503, {"Retry-After": "6"}), _Answer(503, {"Retry-After": "6"}),
                                    _Answer(200)])
    assert bounded_request(client, "GET", "https://provider.test", retry_429=True).status_code == 503
    assert len(calls) == 2 and clock.sleeps == [6.0]  # 6 + 6 would pass the ten-second bound
    # Time spent in the attempts themselves counts too.
    clock = _Clock().install(monkeypatch)
    client, calls = _client("get", [_Answer(429, {"Retry-After": "3"}), _Answer(200)], clock, spent=8.0)
    assert bounded_request(client, "GET", "https://provider.test", retry_429=True).status_code == 429
    assert calls == [1] and clock.sleeps == []

class _FakeTime:
    """A clock every waiter shares: sleeping moves it."""

    def __init__(self):
        self.now, self.slept = 0.0, 0.0
        self.lock = threading.Lock()

    def clock(self):
        with self.lock:
            return self.now

    def sleep(self, seconds):
        with self.lock:
            self.now += seconds
            self.slept += seconds


def _pacer(fake, interval=0.1):
    return RequestPacer("a" * 64, interval, clock=fake.clock, sleep=fake.sleep)


def test_a_pacer_spaces_the_requests_of_every_thread():
    pacer = RequestPacer("b" * 64, 0.02)
    started = time.monotonic()
    with ThreadPoolExecutor(8) as pool:
        list(pool.map(lambda _: pacer.acquire(), range(40)))
    # Forty admissions at most one per 20 ms, whichever of the eight threads asked.
    assert time.monotonic() - started >= 39 * 0.02 - 0.01


def test_a_cooldown_holds_back_every_caller_and_process_of_the_key():
    from cremore.collectors.base import guard_requests
    from cremore.db.repository import InMemoryRepository
    from cremore.db.scan_store import ScanStore

    store = ScanStore(InMemoryRepository())  # the worker's pacing store, shared by its processes
    first, second = RequestPacer("c" * 64, 0.05), RequestPacer("c" * 64, 0.05)  # one per process
    with guard_requests(lambda: None, pacing=store):
        first.acquire()
        first.defer(0.3)
        started = time.monotonic()
        second.acquire()
    assert time.monotonic() - started >= 0.25
    # Without a store, the process's own pacer keeps the cooldown for every thread.
    fake = _FakeTime()
    local = _pacer(fake)
    local.defer(5.0)
    with ThreadPoolExecutor(4) as pool:
        list(pool.map(lambda _: local.acquire(), range(4)))
    assert fake.now >= 5.0 + 3 * 0.1 - 1e-9


@pytest.mark.parametrize("limited", [{"Retry-After": "60"},
                                     {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1060"}])
@pytest.mark.parametrize("status", [403, 429])
def test_a_paced_get_waits_out_a_secondary_limit_of_a_minute(monkeypatch, status, limited):
    clock = _Clock().install(monkeypatch)  # the module's own clock and sleep stay unused
    fake = _FakeTime()
    client, calls = _client("get", [_Answer(status, limited), _Answer(200)])
    charged = []
    result = bounded_request(client, "GET", "https://api.github.test/repos/o/r", retry_429=True,
                             before_attempt=lambda: charged.append(1), pacer=_pacer(fake))
    assert result.status_code == 200 and len(calls) == len(charged) == 2
    assert 60.0 <= fake.slept < 60.5 and clock.sleeps == []


def test_cooldowns_past_two_minutes_fail_as_before(monkeypatch):
    _Clock().install(monkeypatch)
    fake = _FakeTime()
    client, calls = _client("get", [_Answer(403, {"Retry-After": "60"}), _Answer(403, {"Retry-After": "61"}),
                                    _Answer(200)])
    assert bounded_request(client, "GET", "https://api.github.test", retry_429=True,
                           pacer=_pacer(fake)).status_code == 403
    assert len(calls) == 2 and 60.0 <= fake.slept < 60.5  # 60 + 61 would pass 120
    fake = _FakeTime()
    client, calls = _client("get", [_Answer(429, {"Retry-After": "121"}), _Answer(200)])
    assert bounded_request(client, "GET", "https://api.github.test", retry_429=True,
                           pacer=_pacer(fake)).status_code == 429
    assert calls == [1] and fake.slept == 0.0


def test_the_request_guard_is_checked_while_a_cooldown_is_waited_out(monkeypatch):
    from cremore.collectors.base import CollectorError, guard_requests

    _Clock().install(monkeypatch)
    fake, checks = _FakeTime(), []

    def guard():
        checks.append(fake.now)
        if fake.now > 30:
            raise CollectorError("RUN_CANCELLED")

    client, calls = _client("get", [_Answer(403, {"Retry-After": "60"}), _Answer(200)])
    with guard_requests(guard), pytest.raises(CollectorError, match="RUN_CANCELLED"):
        bounded_request(client, "GET", "https://api.github.test", retry_429=True, pacer=_pacer(fake))
    assert calls == [1] and 30 < fake.now <= 31 and len(checks) >= 31  # at least once a second


def test_a_paced_write_is_never_retried_after_a_rate_limit(monkeypatch):
    _Clock().install(monkeypatch)
    fake = _FakeTime()
    client, calls = _client("post", [_Answer(403, {"Retry-After": "1"}), _Answer(200)])
    assert bounded_request(client, "POST", "https://api.github.test", retry_429=True,
                           pacer=_pacer(fake)).status_code == 403
    assert calls == [1] and fake.slept == 0.0

def test_a_no_wait_pacer_never_waits_a_cooldown_or_a_busy_server(monkeypatch):
    from cremore.collectors.base import RATE_LIMITED, UNAVAILABLE, CollectorError, NoWaitPacer

    clock = _Clock().install(monkeypatch)
    fake = _FakeTime()
    shared = _pacer(fake)
    client, calls = _client("get", [_Answer(403, {"Retry-After": "60"}), _Answer(200)])
    with pytest.raises(CollectorError, match=RATE_LIMITED):
        bounded_request(client, "GET", "https://api.github.test", retry_429=True, pacer=NoWaitPacer(shared))
    assert calls == [1] and fake.slept == 0.0
    # The cooldown it met holds every other caller back: a scan waits it out, the next feed look skips at once.
    with pytest.raises(CollectorError, match=RATE_LIMITED):
        NoWaitPacer(shared).acquire()
    shared.acquire()
    assert fake.slept >= 60.0
    # A busy server ends the request too, without a cooldown for anyone and without a sleep, under its own code.
    idle = _FakeTime()
    client, calls = _client("get", [_Answer(503), _Answer(200)])
    with pytest.raises(CollectorError, match=UNAVAILABLE):
        bounded_request(client, "GET", "https://api.github.test", retry_429=True, pacer=NoWaitPacer(_pacer(idle)))
    assert calls == [1] and clock.sleeps == [] and idle.slept == 0.0
    _pacer(idle).acquire()
    assert idle.slept == 0.0


@pytest.mark.parametrize("status,headers", [(503, {}), (502, {}), (504, {}), (429, {"Retry-After": "3"}), (429, {})])
def test_the_shared_no_wait_pace_ends_a_feeds_request_at_once_and_scans_still_retry(monkeypatch, status, headers):
    from cremore.collectors.base import NO_WAIT, RATE_LIMITED, UNAVAILABLE, CollectorError
    from cremore.collectors.content import ContentHTTP

    clock = _Clock().install(monkeypatch)

    def http(pacer=None):
        client, calls = _client("get", [_Answer(status, headers), _Answer(200)])
        reader = ContentHTTP({"token": "t"}, client)
        reader.base, reader.pacer = "https://provider.test", pacer
        return reader, calls

    feed, calls = http(NO_WAIT)
    with pytest.raises(CollectorError, match=UNAVAILABLE if status in (502, 503, 504) else RATE_LIMITED):
        feed.get("/changes")
    assert calls == [1] and clock.sleeps == []
    scan, calls = http()  # the same client class, as a scan builds it
    assert scan.get("/file", raw=True) == b"{}" and calls == [1, 1] and len(clock.sleeps) == 1
