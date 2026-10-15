from types import SimpleNamespace

import pytest

from cremore.http_client import bounded_request


class Response:
    def __init__(self, status, retry_after="0"):
        self.status_code = status
        self.headers = {"Retry-After": retry_after}
        self.content = b"{}"
        self.closed = False

    def close(self):
        self.closed = True


def test_rate_limit_retry_is_opt_in_bounded_and_budgeted(monkeypatch):
    sleeps, calls, attempts = [], [], []
    monkeypatch.setattr("cremore.http_client.time.sleep", sleeps.append)
    responses = [Response(429), Response(429), Response(200)]
    def get(*_args, **_kwargs):
        calls.append(1)
        return responses[len(calls) - 1]
    result = bounded_request(SimpleNamespace(get=get), "GET", "https://provider.test",
                             retry_429=True, before_attempt=lambda: attempts.append(1))
    assert result.status_code == 200 and len(calls) == len(attempts) == 3
    assert responses[0].closed and responses[1].closed and len(sleeps) == 2
    post_calls = []
    def post(*_args, **_kwargs):
        post_calls.append(1)
        return Response(429)
    assert bounded_request(SimpleNamespace(post=post), "POST", "https://provider.test").status_code == 429
    assert len(post_calls) == 1


@pytest.mark.parametrize("header", ["60", "inf"])
def test_excessive_retry_after_returns_to_caller_without_sleep(monkeypatch, header):
    sleeps, calls = [], []
    monkeypatch.setattr("cremore.http_client.time.sleep", sleeps.append)
    def get(*_args, **_kwargs):
        calls.append(1)
        return Response(429, header)
    assert bounded_request(SimpleNamespace(get=get), "GET", "https://provider.test", retry_429=True).status_code == 429
    assert calls == [1] and sleeps == []


def test_repeated_rate_limit_stops_after_three_attempts(monkeypatch):
    monkeypatch.setattr("cremore.http_client.time.sleep", lambda _delay: None)
    calls = []
    def get(*_args, **_kwargs):
        calls.append(1)
        return Response(429)
    result = bounded_request(SimpleNamespace(get=get), "GET", "https://provider.test", retry_429=True)
    assert result.status_code == 429 and len(calls) == 3
