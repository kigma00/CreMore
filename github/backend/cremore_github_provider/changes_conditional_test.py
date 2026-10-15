"""GitHub's change feed asks for the branch head with the ETag it kept: a 304 ends the look."""

import json
import threading
import time

import httpx
import pytest

from cremore.collectors.base import RequestBudget, RequestPacer
from cremore.scanning.changes import read_changes
from cremore_github_provider.changes import changes_since
from cremore_github_provider.collectors import github

OLD, NEW = "a" * 40, "b" * 40
TAG_OLD, TAG_NEW = 'W/"0a1b2c3d"', 'W/"4e5f6a7b"'
PAYLOAD = {"token": "ghp_" + "t" * 36, "base_url": "https://api.github.com"}


class Repository:
    """A branch whose head (and its ETag) a test moves; every request is recorded."""

    def __init__(self, head, tag, *, etag_header=None):
        self.head, self.tag, self.etag_header = head, tag, etag_header
        self.requests = []

    def handle(self, request):
        self.requests.append(request)
        path = request.url.path
        if path == "/repos/acme/app":
            return httpx.Response(200, json={"default_branch": "main"})
        if path == "/repos/acme/app/commits/main":
            if request.headers.get("if-none-match") == self.tag:
                return httpx.Response(304, headers={"ETag": self.tag})
            body = json.dumps({"sha": self.head, "commit": {"message": "x" * 2000}, "files": []}).encode()
            return httpx.Response(200, content=body, headers={
                "ETag": self.etag_header if self.etag_header is not None else self.tag,
                "Content-Type": "application/json"})
        if path != f"/repos/acme/app/compare/{OLD}...{NEW}":
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(200, json={"status": "ahead", "files": [{"filename": "src/app.env", "status": "modified"}]})

    def read(self, cursor, ref="main"):
        root = {"resource_type": "GITHUB_REPOSITORY", "provider_resource_id": "acme/app", "ref": ref}
        return changes_since(PAYLOAD, root, cursor, request_budget=RequestBudget(20),
                             http_client=lambda: httpx.Client(transport=httpx.MockTransport(self.handle)))


def test_a_first_look_keeps_the_heads_etag_in_the_cursor():
    repo = Repository(NEW, TAG_NEW)
    assert repo.read(None).head == f"{NEW} {TAG_NEW}"
    assert len(repo.requests) == 1 and "if-none-match" not in repo.requests[0].headers


@pytest.mark.parametrize("ref, requests", [("main", 1), ("HEAD", 2)])
def test_an_unmoved_head_answers_304_and_nothing_else_is_asked(ref, requests):
    repo = Repository(NEW, TAG_NEW)
    cursor = f"{NEW} {TAG_NEW}"
    changes = repo.read(cursor, ref)
    # The feed sees the same cursor (cremore.scanning.changes: unchanged) and queues nothing.
    assert changes.head == cursor and changes.paths == [] and not changes.rewritten
    assert len(repo.requests) == requests  # a HEAD root first names its default branch
    conditional = repo.requests[-1]
    assert conditional.headers["if-none-match"] == TAG_NEW
    assert not any("/compare/" in r.url.path for r in repo.requests)


def test_a_moved_head_compares_from_the_cursors_commit_exactly_as_before():
    repo = Repository(NEW, TAG_NEW)
    changes = repo.read(f"{OLD} {TAG_OLD}")
    assert repo.requests[0].headers["if-none-match"] == TAG_OLD
    assert changes.head == f"{NEW} {TAG_NEW}"
    assert changes.paths == ["src/app.env"] and not changes.removals and not changes.rewritten
    assert [r.url.path.rsplit("/", 1)[-1] for r in repo.requests] == ["main", f"{OLD}...{NEW}"]


def test_an_older_plain_sha_cursor_still_works():
    repo = Repository(NEW, TAG_NEW)
    moved = repo.read(OLD)
    assert moved.paths == ["src/app.env"] and moved.head == f"{NEW} {TAG_NEW}"
    assert "if-none-match" not in repo.requests[0].headers
    repo.requests.clear()
    # The same commit under the old format: the cursor takes the ETag, and nothing is read.
    same = repo.read(NEW)
    assert same.head == f"{NEW} {TAG_NEW}" and same.paths == [] and len(repo.requests) == 1


def test_the_same_commit_under_a_new_etag_only_renews_the_cursor():
    repo = Repository(NEW, TAG_NEW)
    changes = repo.read(f"{NEW} {TAG_OLD}")
    assert changes.head == f"{NEW} {TAG_NEW}" and changes.paths == [] and len(repo.requests) == 1


@pytest.mark.parametrize("header", ["", "no-quotes", 'W/"has space"', '"' + "x" * 300 + '"'])
def test_a_header_that_is_not_an_entity_tag_is_never_kept(header):
    repo = Repository(NEW, TAG_NEW, etag_header=header)
    assert repo.read(None).head == NEW


def test_a_damaged_cursor_asks_without_a_condition():
    repo = Repository(NEW, TAG_NEW)
    assert repo.read(f"{NEW} not-a-tag").paths == []
    assert "if-none-match" not in repo.requests[0].headers
    repo.requests.clear()
    # A commit that is not one is gone, as an older feed found it: read from scratch.
    assert repo.read(f"not-a-sha {TAG_NEW}").rewritten
    assert "if-none-match" not in repo.requests[0].headers


def test_an_unchanged_poll_costs_one_rate_limited_answer_before_and_none_after():
    """Measured: the plain cursor reads the full commit (HTTP 200), the composite one a bodiless 304."""
    repo = Repository(NEW, TAG_NEW)
    repo.read(NEW)
    before = [(r.url.path, r.headers.get("if-none-match")) for r in repo.requests]
    repo.requests.clear()
    repo.read(f"{NEW} {TAG_NEW}")
    after = [(r.url.path, r.headers.get("if-none-match")) for r in repo.requests]
    assert before == [("/repos/acme/app/commits/main", None)]
    assert after == [("/repos/acme/app/commits/main", TAG_NEW)]  # answered 304: no body, no rate-limit charge

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


@pytest.fixture
def paced(monkeypatch):
    """The scans' pacers on a fake clock: one per origin and credential, as in a worker process."""
    fake, pacers = FakeTime(), {}

    def pacer(origin, name, interval):
        return pacers.setdefault((origin, name), RequestPacer("f" * 64, interval, clock=fake.clock, sleep=fake.sleep))

    monkeypatch.setattr(github, "request_pacer", pacer)
    return fake


class Throttled:
    """Three repositories behind one token; GitHub answers a secondary limit while ``limited``."""

    def __init__(self):
        self.limited, self.requests = True, []

    def handle(self, request):
        self.requests.append(request.url.path)
        if self.limited:
            return httpx.Response(403, headers={"Retry-After": "60"}, json={"message": "secondary rate limit"})
        if request.url.path.endswith("/commits/main"):
            return httpx.Response(200, json={"sha": NEW}, headers={"ETag": TAG_NEW})
        return httpx.Response(200, json={"status": "ahead", "files": [{"filename": "src/app.env", "status": "modified"}]})

    def poll(self, states):
        roots = [{"resource_type": "GITHUB_REPOSITORY", "provider_resource_id": f"acme/app{i}", "resource_id": f"r{i}",
                  "ref": "main"} for i in range(3)]
        return read_changes(PAYLOAD, roots, states, request_budget=RequestBudget(180),
                            http_client=lambda: httpx.Client(transport=httpx.MockTransport(self.handle)))


def test_a_throttled_feed_pass_answers_at_once_and_the_next_poll_reads_from_the_kept_cursors(paced):
    github_side = Throttled()
    states = {f"r{i}": {"cursor": OLD} for i in range(3)}
    answers = github_side.poll(states)
    # Each root's look fails at once (the feed keeps its cursor); nothing waits on the control loop.
    assert {rid: getattr(answer, "code", None) for rid, answer in answers.items()} == dict.fromkeys(
        states, "SOURCE_RATE_LIMITED")
    assert paced.slept < 2.0 and len(github_side.requests) == 1  # the first answer set the cooldown for all
    paced.now += 61  # the cooldown is over at the next poll
    github_side.limited = False
    answers = github_side.poll(states)
    assert all(answer.paths == ["src/app.env"] and answer.head == f"{NEW} {TAG_NEW}" for answer in answers.values())
    assert sum("/compare/a" in path for path in github_side.requests) == 3  # compared from the kept cursor


def test_a_cooldown_set_by_a_scan_makes_the_feed_skip_rather_than_wait(paced):
    github_side = Throttled()
    github_side.limited = False
    github.github_pacer("https://api.github.com/repos/acme/app0", PAYLOAD["token"]).defer(60)  # a scan met the limit
    answers = github_side.poll({f"r{i}": {"cursor": OLD} for i in range(3)})
    assert {getattr(answer, "code", None) for answer in answers.values()} == {"SOURCE_RATE_LIMITED"}
    assert github_side.requests == [] and paced.slept == 0.0


def test_the_worker_pacing_store_shares_a_scans_cooldown_with_the_feed():
    from cremore.collectors.base import guard_requests
    from cremore.db.repository import InMemoryRepository
    from cremore.db.scan_store import ScanStore

    github_side = Throttled()
    github_side.limited = False
    started = time.monotonic()
    # As the worker's feed reader runs it: no guard, the database's pacing shared with every scan process.
    with guard_requests(None, pacing=ScanStore(InMemoryRepository())):
        github.github_pacer("https://api.github.com/repos/acme/app0", PAYLOAD["token"]).defer(60)
        answers = github_side.poll({f"r{i}": {"cursor": OLD} for i in range(3)})
    assert {getattr(answer, "code", None) for answer in answers.values()} == {"SOURCE_RATE_LIMITED"}
    assert github_side.requests == [] and time.monotonic() - started < 2.0

def test_a_busy_github_fails_the_feeds_look_at_once_instead_of_sleeping(paced, monkeypatch):
    from types import SimpleNamespace

    from cremore import http_client

    sleeps = []
    monkeypatch.setattr(http_client, "time", SimpleNamespace(monotonic=time.monotonic, time=time.time,
                                                             sleep=sleeps.append))
    github_side = Throttled()
    github_side.limited = False
    github_side.handle = lambda request: (github_side.requests.append(request.url.path), httpx.Response(503))[1]
    answers = github_side.poll({f"r{i}": {"cursor": OLD} for i in range(3)})
    assert {answer.code for answer in answers.values()} == {"SOURCE_UNAVAILABLE"}
    # A busy server sets no cooldown for the scans: each root asked once, nobody slept.
    assert len(github_side.requests) == 3 and sleeps == [] and paced.slept < 1.0
