"""GitHub REST requests are paced per origin and credential; a secondary limit is waited out, a run stop is not."""

import base64
import datetime
import hashlib
import io
import tarfile
import threading
import time

import httpx
import pytest

from cremore.collectors.base import CollectorError, RequestBudget, RequestPacer
from cremore_github_provider.collectors import github
from cremore_github_provider.collectors.github import GitHubCollector, github_pacer

COMMIT, TREE = "a" * 40, "b" * 40


def _sha(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def test_a_personal_token_is_paced_per_origin_and_token_never_by_the_token_itself():
    same = github_pacer("https://api.github.com/repos/o/r/git/blobs/1", "ghp_synthetic-one")
    assert same is github_pacer("https://api.github.com/repos/x/y", "ghp_synthetic-one")
    assert same.interval == github.REQUEST_INTERVAL == 0.1
    assert same.key == hashlib.sha256(b"https://api.github.com\0token:ghp_synthetic-one").hexdigest()
    others = {github_pacer("https://api.github.com/repos/o/r", "ghp_synthetic-two").key,
              github_pacer("https://ghe.example.test/api/v3/repos/o/r", "ghp_synthetic-one").key}
    assert same.key not in others and len(others) == 2 and "synthetic" not in same.key


def _app(installation, token="ghs_synthetic"):
    from cremore_github_provider.github_auth import GitHubAppTokenSource

    key = base64.b64encode(b"-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----\n").decode()
    source = GitHubAppTokenSource(lambda: None, "123", installation, key)
    source._issued = (token, datetime.datetime(2100, 1, 1, tzinfo=datetime.UTC))  # a token it already minted
    return source


def test_a_github_app_is_paced_per_installation_whatever_token_it_minted():
    url = "https://api.github.com/repos/acme/app"
    one, two = _app("456", "ghs_first-token"), _app("456", "ghs_second-token")  # two root tasks of one org scan
    assert github_pacer(url, one) is github_pacer(url, two)
    assert github_pacer(url, one).key == hashlib.sha256(b"https://api.github.com\0app:123:installation:456").hexdigest()
    assert github_pacer(url, _app("789")).key != github_pacer(url, one).key
    assert github_pacer("https://ghe.example.test/api/v3/repos/acme/app", one).key != github_pacer(url, one).key


def test_every_github_read_names_the_app_installation_not_its_current_token(monkeypatch):
    named = []
    real = github.request_pacer

    def recording(origin, name, interval):
        named.append(name)
        return real(origin, name, interval)

    monkeypatch.setattr(github, "request_pacer", recording)
    for token in ("ghs_first-token", "ghs_second-token"):
        repo = Repository(FILES)
        collector = GitHubCollector(httpx.Client(transport=httpx.MockTransport(repo.handle)), "o", "r", ref="main",
                                    token=_app("456", token), lazy=True)
        list(collector.collect())
    assert set(named) == {"app:123:installation:456"} and len(named) == 6
    # A request that names no credential is paced by its Authorization header's token, as a personal token is.
    named.clear()
    github.fetch_json(httpx.Client(transport=httpx.MockTransport(Repository(FILES).handle)),
                      "https://api.github.com/repos/o/r", {"Authorization": "Bearer ghp_synthetic"})
    assert named == ["token:ghp_synthetic"]


class FakeTime:
    def __init__(self):
        self.now, self.slept, self.lock = 0.0, 0.0, threading.Lock()

    def clock(self):
        with self.lock:
            return self.now

    def sleep(self, seconds):
        with self.lock:
            self.now += seconds
            self.slept += seconds


class Repository:
    """A repository whose second blob read meets GitHub's secondary rate limit once."""

    def __init__(self, files, limited=None, *, archive=False):
        self.files, self.limited, self.archive = files, limited, archive
        self.requests, self.answered = [], set()

    def handle(self, request):
        self.requests.append(request)
        path = request.url.path
        if path == "/repos/o/r":
            return httpx.Response(200, json={"private": True})
        if path == "/repos/o/r/commits/main":
            return httpx.Response(200, json={"sha": COMMIT, "commit": {"tree": {"sha": TREE}}})
        if path == f"/repos/o/r/git/trees/{TREE}":
            return httpx.Response(200, json={"tree": [{"type": "blob", "path": p, "sha": _sha(d), "size": len(d)}
                                                      for p, d in self.files.items()]})
        if path == f"/repos/o/r/tarball/{COMMIT}":
            body = io.BytesIO()
            with tarfile.open(fileobj=body, mode="w:gz") as tar:
                for name, data in self.files.items():
                    info = tarfile.TarInfo("root/" + name)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            return httpx.Response(200, content=body.getvalue())
        sha = path.rsplit("/", 1)[1]
        if self.limited and sha == _sha(self.files["two.txt"]) and sha not in self.answered:
            self.answered.add(sha)
            return httpx.Response(403, headers=self.limited)
        data = next(d for d in self.files.values() if _sha(d) == sha)
        return httpx.Response(200, json={"encoding": "base64", "content": base64.b64encode(data).decode()})

    def collector(self, **kwargs):
        return GitHubCollector(httpx.Client(transport=httpx.MockTransport(self.handle)), "o", "r", ref="main",
                               token="ghs_synthetic", lazy=True, **kwargs)


FILES = {"one.txt": b"first", "two.txt": b"second", "three.txt": b"third"}


@pytest.fixture
def fake(monkeypatch):
    clock = FakeTime()
    pacers = {}

    def pacer(origin, credential, interval):
        return pacers.setdefault((origin, credential), RequestPacer("e" * 64, interval, clock=clock.clock,
                                                                      sleep=clock.sleep))

    monkeypatch.setattr(github, "request_pacer", pacer)
    return clock


@pytest.mark.parametrize("limited", [{"Retry-After": "60"}, "reset"])
def test_a_secondary_limit_of_a_minute_is_waited_out_and_the_run_stays_complete(fake, limited):
    if limited == "reset":  # the exhausted limit resets at an epoch second a minute from now
        limited = {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(time.time()) + 60)}
    repo = Repository(FILES, limited)
    collector = repo.collector()
    read = {obj.resource.location: obj.read() for obj in collector.collect()}
    assert read == FILES and collector.failed_objects == 0
    blob_requests = [r for r in repo.requests if "/git/blobs/" in r.url.path]
    assert len(blob_requests) == len(FILES) + 1 and 59.0 <= fake.slept < 61.0
    # Paced as well: seven requests (three to list, four blob reads with the retry), each slot 0.1 s after the last.
    assert fake.slept >= 59.0 + 0.1 * (len(repo.requests) - 2)


def test_a_limit_longer_than_two_minutes_fails_the_read_as_before(fake):
    collector = Repository(FILES, {"Retry-After": "300"}).collector()
    read = {obj.resource.location: obj.read() for obj in collector.collect()}
    assert read["two.txt"] is None and collector.failed_objects == 1 and fake.slept < 1.0


@pytest.mark.parametrize("code", ["YIELDED_TO_EVENT", "RUN_CANCELLED", "BUDGET_SECONDS"])
def test_a_run_stop_during_a_read_ends_the_run_and_is_not_a_failed_read(fake, code):
    class Stopping(RequestBudget):
        def consume(self):
            super().consume()
            if self.used > 3:  # the listing passed; the first blob read meets the stop
                raise CollectorError(code)

    collector = Repository(FILES).collector(request_budget=Stopping(100))
    objects = list(collector.collect())
    with pytest.raises(CollectorError, match=code):
        objects[0].read()
    assert collector.failed_objects == 0


def test_a_run_stop_during_the_archive_ends_the_run_instead_of_falling_back(fake):
    class Yielding(RequestBudget):
        def consume(self):
            super().consume()
            if self.used > 3:  # the archive request yields to a change scan
                raise CollectorError("YIELDED_TO_EVENT")

    repo = Repository(FILES, archive=True)
    collector = GitHubCollector(httpx.Client(transport=httpx.MockTransport(repo.handle)), "o", "r", ref="main",
                                token="ghs_synthetic", use_archive=True, request_budget=Yielding(100))
    with pytest.raises(CollectorError, match="YIELDED_TO_EVENT"):
        list(collector.collect())
    assert not any("/git/blobs/" in r.url.path for r in repo.requests) and collector.failed_objects == 0
