"""Every Notion call waits for the connection's limiter and retries 429/529 as Retry-After asks.

A recording pacing store stands in for the worker's database pacing, so each slot and
cooldown a call asks for is visible without sleeping. Synthetic tokens only.
"""

import hashlib
import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest

from cremore.collectors.base import CollectorError, RequestBudget, guard_requests
from cremore.collectors.credential_result import ACTIVE, INDETERMINATE
from cremore_notion_provider import onboarding, source
from cremore_notion_provider.collectors.requests import paced

# Built at run time: a literal would read as a token to secret scanners.
TOKEN = "ntn_" + "p" * 46
ORIGIN = "https://api.notion.com"
KEY = hashlib.sha256((ORIGIN + "\0" + TOKEN).encode()).hexdigest()
PAGE = "0123456789abcdef0123456789abcdef"
EDITOR = "7d1c5e6a-1111-4222-8333-444455556666"
WORKSPACE = "11111111-2222-4333-8444-555555555555"


class Pacing:
    """A shared pacing store that admits at once and records every slot and cooldown."""

    def __init__(self):
        self.slots, self.cooldowns = [], []

    def request_delay(self, key, interval, *, cooldown=None):
        if cooldown is None:
            self.slots.append((key, interval))
        else:
            self.cooldowns.append((key, cooldown))
        return 0.0


@pytest.fixture
def pacing():
    store = Pacing()
    with guard_requests(lambda: None, pacing=store):
        yield store


def notion(answer, busy=(), retry_after="2"):
    """An httpx client: the first ``len(busy)`` requests get those statuses, then ``answer``."""
    seen, busy = [], list(busy)

    def handler(request):
        seen.append(request)
        assert request.headers["authorization"] == "Bearer " + TOKEN
        if busy:
            return httpx.Response(busy.pop(0), headers={"Retry-After": retry_after}, json={"object": "error"})
        return answer(request)
    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def search_answer(request):
    cursor = json.loads(request.content).get("start_cursor")
    page = {"object": "page", "id": PAGE, "url": "https://www.notion.so/" + PAGE, "properties": {}}
    return httpx.Response(200, json={"results": [page], "has_more": cursor is None,
                                     "next_cursor": None if cursor else "second"})


def user_answer(request):
    if request.url.path == f"/v1/pages/{PAGE}":
        return httpx.Response(200, json={"object": "page", "id": PAGE, "last_edited_time": "2026-10-01T00:00:00.000Z",
                                         "last_edited_by": {"object": "user", "id": EDITOR}})
    return httpx.Response(200, json={"object": "user", "id": EDITOR, "type": "bot", "name": "Scanner",
                                     "bot": {"workspace_name": "Synthetic"}})


def catalog(client):
    return source.list_resources({"token": TOKEN}, "source", str(uuid.uuid4()), http_client=lambda: client,
                                 now=datetime.now(UTC), request_budget=RequestBudget(10))


def credential(client):
    return source.check_credential({"token": TOKEN}, http_client_factory=lambda: client)


def context(client):
    return source.exposure_context({"token": TOKEN}, {"page_id": PAGE}, http_client=client)


def wizard(client):
    return onboarding.check({"target": {}}, "exposure", {"credential": {"token": TOKEN}},
                            SimpleNamespace(http_client=lambda: client))


def test_every_call_waits_for_a_slot_of_the_connection(pacing):
    client, listed = notion(search_answer)
    assert len(catalog(client)[0]) == 2
    client, read = notion(user_answer)
    assert credential(client).status == ACTIVE
    assert context(client)["author"]["status"] == "OBSERVED"
    client, probed = notion(search_answer)
    assert wizard(client)[1]["status"] == "GRANTED"
    # Two catalog pages, the credential check, the editor's page and user reads, the wizard's probe.
    assert (len(listed), len(read), len(probed)) == (2, 3, 1)
    assert pacing.slots == [(KEY, 0.4)] * 6 and not pacing.cooldowns


@pytest.mark.parametrize("status", [429, 529])
@pytest.mark.parametrize("call,answer,ok", [
    (catalog, search_answer, lambda result: len(result[0]) == 2),
    (credential, user_answer, lambda result: result.status == ACTIVE),
    (context, user_answer, lambda result: result["author"]["status"] == "OBSERVED"),
    (wizard, search_answer, lambda result: result[0]["status"] == "GRANTED"),
])
def test_a_busy_answer_is_retried_after_the_cooldown_notion_asks_for(pacing, status, call, answer, ok):
    client, seen = notion(answer, busy=[status])
    assert ok(call(client))
    # The cooldown is shared with every caller of the connection, then the call is sent again.
    assert pacing.cooldowns == [(KEY, 2.0)] and len(pacing.slots) == len(seen)


def test_a_retry_after_beyond_the_bound_is_returned_not_slept(pacing):
    client, seen = notion(search_answer, busy=[429], retry_after="60")
    with pytest.raises(CollectorError, match="NOTION_SEARCH_FAILED: HTTP 429"):
        catalog(client)
    client, more = notion(user_answer, busy=[529], retry_after="60")
    result = credential(client)
    assert (result.status, result.error) == (INDETERMINATE, "HTTP 529")
    assert len(seen) == len(more) == 1 and not pacing.cooldowns


def test_paced_tries_three_times_and_never_retries_a_transport_failure():
    class Limiter:
        def __init__(self):
            self.acquired, self.deferred = 0, []

        def acquire(self):
            self.acquired += 1

        def defer(self, delay):
            self.deferred.append(delay)

    busy = SimpleNamespace(status_code=429, headers={"Retry-After": "0.5"})
    limiter = Limiter()
    assert paced(limiter, lambda: busy) is busy
    assert limiter.acquired == 3 and limiter.deferred == [0.5, 0.5]
    limiter, charged = Limiter(), []
    assert paced(limiter, lambda: None, before_attempt=lambda: charged.append(1)) is None
    assert limiter.acquired == 1 and charged == [1] and not limiter.deferred


def test_only_retry_after_cooldowns_spend_the_ten_second_bound(monkeypatch):
    from cremore_notion_provider.collectors import requests as module

    class SlowLimiter:
        """Each ordinary slot takes a minute on a fake clock; cooldowns are recorded."""

        def __init__(self):
            self.now, self.deferred = 0.0, []

        def acquire(self):
            self.now += 60

        def defer(self, delay):
            self.deferred.append(delay)

    limiter = SlowLimiter()
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: limiter.now))
    busy = SimpleNamespace(status_code=529, headers={"Retry-After": "4"})
    assert paced(limiter, lambda: busy) is busy and limiter.deferred == [4.0, 4.0]
    # Cooldowns beyond the bound end the retries instead of waiting them out.
    limiter, busy.headers = SlowLimiter(), {"Retry-After": "6"}
    assert paced(limiter, lambda: busy) is busy and limiter.deferred == [6.0]


def feed_store(monkeypatch):
    """The worker's database pacing on a clock moved by hand."""
    from cremore.db import task_store
    from cremore.db.repository import InMemoryRepository
    from cremore.db.scan_store import ScanStore

    clock = SimpleNamespace(now=datetime(2026, 10, 1, tzinfo=UTC))
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: clock.now)
    return ScanStore(InMemoryRepository()), clock


def feed(client, store):
    """One change-feed look at an approved page, as the worker's control loop polls it."""
    root = {"resource_id": "root-1", "resource_type": "NOTION_PAGE", "provider_resource_id": PAGE,
            "page_mode": "PAGE_ONLY", "descendant_ids": []}
    states = {"root-1": {"cursor": (datetime.now(UTC) - timedelta(hours=1)).isoformat()}}
    started = time.monotonic()
    with guard_requests(lambda: None, pacing=store):
        answer = source.changes_since_batch({"token": TOKEN}, [root], states, http_client=lambda: client,
                                            request_budget=RequestBudget(10))["root-1"]
    return answer, time.monotonic() - started


def edited_answer(request):
    edited = {"object": "page", "id": PAGE, "url": "https://www.notion.so/" + PAGE,
              "last_edited_time": datetime.now(UTC).isoformat(), "properties": {}}
    return httpx.Response(200, json={"results": [edited], "has_more": False, "next_cursor": None})


def test_a_change_feed_never_waits_out_a_cooldown_and_the_next_poll_reads(monkeypatch):
    store, clock = feed_store(monkeypatch)
    store.request_delay(KEY, 0.4, cooldown=10)  # a scan of this connection met Notion's 429
    client, seen = notion(edited_answer)
    answer, took = feed(client, store)
    # At once, without a request: the root keeps its cursor and the next poll looks again.
    assert isinstance(answer, CollectorError) and answer.code == "NOTION_RATE_LIMITED"
    assert took < 2 and seen == []
    clock.now += timedelta(seconds=11)  # the cooldown is over
    answer, _took = feed(client, store)
    assert answer.paths == [PAGE] and len(seen) == 1


def test_a_429_a_change_feed_meets_cools_every_caller_down_and_ends_the_look():
    from cremore.db.repository import InMemoryRepository
    from cremore.db.scan_store import ScanStore

    store = ScanStore(InMemoryRepository())
    client, seen = notion(edited_answer, busy=[429], retry_after="2")
    answer, took = feed(client, store)
    assert answer.code == "NOTION_RATE_LIMITED" and len(seen) == 1 and took < 2
    # Scans of the connection wait out what Notion asked for.
    assert store.request_delay(KEY, 0.4) > 1


def test_a_limiter_that_must_not_wait_out_a_cooldown_still_waits_for_a_slot():
    from cremore_notion_provider.collectors.requests import NotionRateLimiter

    clock, slept = [100.0], []

    def sleep(seconds):
        slept.append(seconds)
        clock[0] += seconds

    limiter = NotionRateLimiter(clock=lambda: clock[0], sleep=sleep)
    limiter.acquire(check=lambda: None, patient=False)
    limiter.acquire(check=lambda: None, patient=False)  # the next slot, 0.4 s on: waited for
    assert slept and sum(slept) == pytest.approx(0.4)
    limiter.defer(5)
    with pytest.raises(CollectorError, match="NOTION_RATE_LIMITED"):
        limiter.acquire(check=lambda: None, patient=False)
    limiter.acquire(check=lambda: None)  # a scan waits it out
    assert sum(slept) == pytest.approx(5.4)


def test_jobs_outside_a_scan_pace_through_the_worker_s_database(monkeypatch):
    """A catalog refresh and a credential check take the connection's slots from the database the worker's scans
    use, so the worker's processes together keep to Notion's rate (cremore.worker.worker.JobWorker.shared_pacing)."""
    from cremore.db.repository import InMemoryRepository
    from cremore.db.scan_store import ScanStore
    from cremore.domain.models import Connection, ScanJob
    from cremore.worker import JobWorker

    repo = InMemoryRepository()
    conn = repo.create_connection(Connection(provider="notion", name="synthetic", config={}))
    listing, listed = notion(search_answer)
    checking, checked = notion(user_answer)
    worker = JobWorker(repo, catalog_lister=lambda job: source.list_resources(
        {"token": TOKEN}, "source", conn.id, http_client=lambda: listing, now=datetime.now(UTC),
        request_budget=RequestBudget(10)),
        credential_checker=lambda job: source.check_credential({"token": TOKEN}, http_client_factory=lambda: checking))
    slots = []
    request_delay = ScanStore.request_delay

    def recorded(self, key, interval, *, cooldown=None):
        slots.append((key, interval, cooldown))
        return request_delay(self, key, interval, cooldown=cooldown)

    monkeypatch.setattr(ScanStore, "request_delay", recorded)
    for kind, payload in (("catalog-refresh", {"connection_kind": "source", "connection_id": str(conn.id)}),
                          ("credential-check", {})):
        job = repo.enqueue_job(ScanJob(kind=kind, connection_id=conn.id, payload=payload))
        for _ in range(3):
            worker.process_next()
        assert repo.get_job(job.id).status == "SUCCEEDED"
    # Two catalog pages and the identity check, each through the shared row of this token.
    assert (len(listed), len(checked)) == (2, 1)
    assert {key for key, _interval, _cooldown in slots} == {KEY} and len(slots) >= 3
    assert KEY in repo.scan_state_memory["pacing"]


def test_a_remediator_keeps_its_calls_to_its_own_pacing():
    """It has no grant on the pacing table, and its Notion calls (the Admin API) pace themselves."""
    from cremore.collectors.base import request_pacing
    from cremore.config import Settings
    from cremore.db.repository import InMemoryRepository
    from cremore.worker import JobWorker

    def worker(role):
        return JobWorker(InMemoryRepository(), settings=Settings(AUTH_MODE="local", API_TOKEN="0" * 32,
                                                                 FINGERPRINT_KEY="ab" * 32,
                                                                 WORKER_EXECUTION_ROLE=role))

    for role, shared in (("mixed", True), ("collector", True), ("remediator", False)):
        with worker(role).shared_pacing():
            assert (request_pacing() is not None) is shared


def test_organization_bot_probes_share_their_own_token_s_limiter(pacing):
    bot = "ntn_" + "o" * 46
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"results": [], "has_more": False})
    ctx = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    connection = {"provider": "notion", "edition": "enterprise", "auth_method": "organization_bot",
                  "target": {"workspace": WORKSPACE}}
    assert [item["status"] for item in onboarding.check(connection, "inventory", {"credential": {"token": bot}}, ctx)] \
        == ["GRANTED", "GRANTED"]
    assert onboarding.authenticate(connection, {"credential": {"token": bot}}, ctx)["status"] == "GRANTED"
    bot_key = hashlib.sha256((ORIGIN + "\0" + bot).encode()).hexdigest()
    assert len(seen) == 3 and pacing.slots == [(bot_key, 0.4)] * 3
