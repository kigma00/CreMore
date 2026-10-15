"""A Notion run's plan reads its approved pages' headers in one search walk (cremore.worker.runtime.ScanRuntime.plan).

Each page root carries only its own entry, so the page costs one request; the walk is paid from the run's request
budget and never takes what leaves a root without one; a credential, search or budget failure leaves the pages to read
their own headers, while a stop of the run itself still stops the plan; change scans never walk. The worker resolves
the connection's credential for the walk and paces it, and the change feeds, through the database. Fakes only.
"""

import datetime as dt
import hashlib
import json
import logging
import uuid

import pytest

from cremore.collectors.base import RequestBudget
from cremore.db import task_store
from cremore.db.repository import InMemoryRepository
from cremore.db.scan_store import ScanStore
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.db.task_store import TaskStore
from cremore.domain.models import Connection, ScanJob, ScopeCatalog, ScopeProfile
from cremore.scanning import scope
from cremore.secretstore.resolver import SecretRefError
from cremore.worker.factory import build_collector
from cremore.worker.worker import JobWorker

# Built at run time: a literal would read as a token to secret scanners.
TOKEN = "ntn_" + "q" * 46
ORIGIN = "https://api.notion.com"
KEY = hashlib.sha256((ORIGIN + "\0" + TOKEN).encode()).hexdigest()
NOW = dt.datetime.now(dt.UTC)


def pid(n):
    return f"{n:032x}"


def dashed(n):
    value = pid(n)
    return f"{value[:8]}-{value[8:12]}-{value[12:16]}-{value[16:20]}-{value[20:]}"


def page(n, edited=None):
    return {"object": "page", "id": dashed(n), "url": f"https://www.notion.so/Page-{pid(n)}",
            "last_edited_time": edited or (NOW - dt.timedelta(days=30, minutes=n)).isoformat(),
            "properties": {"Name": {"type": "title", "title": [{"plain_text": f"Page {n}"}]}}}


class Response:
    def __init__(self, data, status=200):
        self.data, self.status_code, self.headers = data, status, {}

    def json(self):
        return self.data


class Search:
    """Notion's search over ``pages``, 100 an answer; every request fails with ``status`` when one is given."""

    def __init__(self, pages, status=None):
        self.pages, self.status, self.bodies = pages, status, []

    def post(self, url, headers=None, json=None):
        assert url == ORIGIN + "/v1/search" and headers["Authorization"] == "Bearer " + TOKEN
        self.bodies.append(json)
        if self.status:
            return Response({"object": "error"}, self.status)
        start = int(json.get("start_cursor", 0))
        more = start + 100 < len(self.pages)
        return Response({"results": self.pages[start:start + 100], "has_more": more,
                         "next_cursor": str(start + 100) if more else None})


class Workspace:
    """Notion's page endpoints: each page's Markdown, and the header of a page the plan did not find."""

    def __init__(self):
        self.calls = []

    def get(self, url, headers=None):
        self.calls.append(url)
        page_id = url.split("/v1/pages/")[1].split("/")[0]
        if url.endswith("/markdown"):
            return Response({"object": "page_markdown", "id": page_id, "markdown": "nothing to find here",
                             "truncated": False, "unknown_block_ids": []})
        return Response(page(int(page_id.replace("-", ""), 16)))


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def approve(repo, pages, *, budget=1000):
    """A Notion connection whose approved scope is page ``pages[0]`` with the others as its descendants."""
    conn = repo.create_connection(Connection(provider="notion", name="fixture", config={}))
    item = scope.resource("source", conn.id, "NOTION_PAGE", dashed(pages[0]), "Root",
                          f"https://www.notion.so/{pid(pages[0])}", "notion")
    auth = scope.auth_revision("source", conn)
    catalog = repo.save_catalog(ScopeCatalog(kind="source", connection_id=conn.id, snapshot_id="v1", auth_revision=auth,
                                             items=[item], completeness="COMPLETE"))
    profile = repo.create_scope_profile(ScopeProfile(
        kind="source", connection_id=conn.id, name="approved", state="READY", auth_revision=auth,
        catalog_snapshot_id="v1", budgets={"requests": budget, "bytes": 10_000_000, "seconds": 600},
        selected_roots=[{"resource_id": item["id"], "page_mode": "PAGE_WITH_DESCENDANTS",
                         "descendant_ids": [dashed(n) for n in pages[1:]], "all_current_objects": False,
                         "include_future_descendants": False}]))
    return conn, catalog, profile


def enqueue(repo, approved, mode="BASELINE", trigger=None):
    conn, catalog, profile = approved
    plan = scope.build_plan(profile, catalog, auth=profile.auth_revision, enabled=True)
    plan.trigger = trigger or plan.trigger
    plan = repo.create_plan(plan)
    payload = scope.run_payload(plan, profile, {}, "notion")
    payload["mode"] = mode
    if trigger == "EVENT":
        payload["not_before"] = dt.datetime.now(dt.UTC).isoformat()  # as enqueue_event sets it, without the wait
    return repo.enqueue_job(ScanJob(kind="scope", connection_id=conn.id, payload=payload))


def reader(search, calls=None):
    """The worker's plan reader with the credential already resolved (cremore.cli.worker resolves it)."""
    def read(job, hook, roots, budget):
        if calls is not None:
            calls.append([root["provider_resource_id"] for root in roots])
        return hook({**job.payload, "token": TOKEN}, roots, http_client=search, request_budget=budget)
    return read


def root_tasks(repo, job):
    return [task for task in TaskStore(repo).list_for_run(job.id) if task["kind"] != "PLAN"]


def plan_task(repo, job):
    return next(task for task in TaskStore(repo).list_for_run(job.id) if task["kind"] == "PLAN")


def paced(repo):
    """The pacing rows the database holds (cremore.db.scan_store.ScanStore.request_delay)."""
    if isinstance(repo, InMemoryRepository):
        return set(getattr(repo, "scan_state_memory", {}).get("pacing", {}))
    from sqlalchemy import select

    table = ScanStore(repo).tables["pacing"]
    with repo.engine.connect() as conn:
        return set(conn.execute(select(table.c.id)).scalars())


def test_one_walk_gives_each_page_root_its_own_header_and_is_paid_from_the_run(repo):
    approved = approve(repo, [1, 2, 3, 4], budget=40)
    # Pages 1 to 3 are shared with the integration; search leaves page 4 out.
    search = Search([page(n) for n in (3, 2, 1, 9)])
    job = enqueue(repo, approved)
    assert JobWorker(repo, plan_reader=reader(search)).process_next()
    tasks = root_tasks(repo, job)
    assert len(tasks) == 4 and len(search.bodies) == 1
    metas = {task["payload"]["scope"]["provider_resource_id"]: task["payload"]["scope"].get("page_meta")
             for task in tasks}
    for n in (1, 2, 3):
        [(key, entry)] = metas[dashed(n)].items()
        assert key == pid(n) and set(entry) == {"url", "title", "last_edited_time", "observed_at"}
        assert (entry["url"], entry["title"], entry["last_edited_time"]) == (
            page(n)["url"], f"Page {n}", page(n)["last_edited_time"])
    assert metas[dashed(4)] is None  # it reads its own header
    # The walk's one request comes out of the run's 40: the four roots share the 39 left.
    assert plan_task(repo, job)["result"] == {"planned_roots": 4, "requests": 1}
    assert sorted(task["payload"]["budgets"]["requests"] for task in tasks) == [9, 10, 10, 10]
    # Paced through the database with the connection's scans; the token is kept in no task.
    assert KEY in paced(repo)
    assert TOKEN not in json.dumps([task["payload"] for task in TaskStore(repo).list_for_run(job.id)], default=str)


def test_a_page_the_walk_found_costs_one_request_and_the_job_counts_the_walk():
    repo = InMemoryRepository()
    workspace = Workspace()
    job = enqueue(repo, approve(repo, [1, 2, 3]))
    worker = JobWorker(repo, plan_reader=reader(Search([page(1), page(2)])),
                       collector_factory=lambda job: build_collector(job, http_client_factory=lambda: workspace))
    for _ in range(12):
        worker.process_next()
        if repo.get_job(job.id).status not in ("QUEUED", "RUNNING"):
            break
    done = repo.get_job(job.id)
    assert done.status == "SUCCEEDED"
    # One Markdown read a page; a header read only for the page search did not show.
    assert sorted(url for url in workspace.calls if url.endswith("/markdown")) == sorted(
        f"{ORIGIN}/v1/pages/{dashed(n)}/markdown" for n in (1, 2, 3))
    assert [url for url in workspace.calls if not url.endswith("/markdown")] == [f"{ORIGIN}/v1/pages/{dashed(3)}"]
    # The walk, three Markdown reads and that header.
    assert done.coverage["requests"] == 5


def test_only_a_small_entry_of_the_contract_s_text_fields_reaches_a_page_root():
    repo = InMemoryRepository()
    job = enqueue(repo, approve(repo, [1, 2, 3, 4]))
    entry = {"url": "https://www.notion.so/Page", "title": "Page", "last_edited_time": NOW.isoformat(),
             "observed_at": NOW.isoformat()}
    found = {pid(1): entry, pid(2): {**entry, "title": "x" * 9000}, pid(3): {**entry, "text": "a page body"},
             pid(4): {**entry, "last_edited_time": NOW}}
    assert JobWorker(repo, plan_reader=lambda job, hook, roots, budget: found).process_next()
    metas = {task["payload"]["scope"]["provider_resource_id"]: task["payload"]["scope"].get("page_meta")
             for task in root_tasks(repo, job)}
    # Too large, a field outside the contract, a value that is not text: those pages read their own headers.
    assert metas == {dashed(1): {pid(1): entry}, dashed(2): None, dashed(3): None, dashed(4): None}


@pytest.mark.parametrize("budget,walked", [(5, 1), (4, 0)])
def test_the_walk_takes_only_what_leaves_every_root_a_request_and_keeps_what_it_found(budget, walked, caplog):
    repo = InMemoryRepository()
    # Pages 1 and 2 are in the first answer, 3 and 4 past it: finding those would take a second request.
    search = Search([page(1), page(2)] + [page(n) for n in range(100, 198)] + [page(3), page(4)])
    job = enqueue(repo, approve(repo, [1, 2, 3, 4], budget=budget))
    with caplog.at_level(logging.WARNING, logger="cremore.worker"):
        assert JobWorker(repo, plan_reader=reader(search)).process_next()
    tasks = root_tasks(repo, job)
    found = {task["payload"]["scope"]["provider_resource_id"] for task in tasks if "page_meta" in task["payload"]["scope"]}
    assert len(search.bodies) == walked and found == ({dashed(1), dashed(2)} if walked else set())
    assert sum(task["payload"]["budgets"]["requests"] for task in tasks) == budget - walked
    assert plan_task(repo, job)["result"] == {"planned_roots": 4, **({"requests": 1} if walked else {})}
    assert "without page metadata" not in caplog.text  # the walk ran out of requests: nothing failed


def test_a_credential_or_search_failure_leaves_the_pages_to_read_their_own_headers(caplog):
    repo = InMemoryRepository()

    def unresolvable(job, hook, roots, budget):
        raise SecretRefError("could not resolve secret_ref: SECRET_REF_RESOLUTION_FAILED")

    job = enqueue(repo, approve(repo, [1, 2]))
    with caplog.at_level(logging.WARNING, logger="cremore.worker"):
        assert JobWorker(repo, plan_reader=unresolvable).process_next()
    tasks = root_tasks(repo, job)
    assert len(tasks) == 2 and not any("page_meta" in task["payload"]["scope"] for task in tasks)
    assert plan_task(repo, job)["result"] == {"planned_roots": 2}
    # Only a fixed code is logged, never what the error said.
    assert "SecretRefError" in caplog.text and "could not resolve" not in caplog.text
    # A search Notion fails costs its request and names nothing.
    repo = InMemoryRepository()
    failing = Search([page(1), page(2)], status=500)
    job = enqueue(repo, approve(repo, [1, 2]))
    assert JobWorker(repo, plan_reader=reader(failing)).process_next()
    assert len(failing.bodies) == 1 and plan_task(repo, job)["result"] == {"planned_roots": 2, "requests": 1}
    assert not any("page_meta" in task["payload"]["scope"] for task in root_tasks(repo, job))


@pytest.mark.parametrize("mode,walks", [("DELTA", False), ("EVENT", False), ("BASELINE", True)])
def test_a_change_scan_never_walks(mode, walks):
    """A change feed's run reads the pages it names; one that saw history rewritten reads its roots whole (BASELINE)
    and plans like any full run."""
    repo = InMemoryRepository()
    approved = approve(repo, [1, 2])
    calls = []
    job = enqueue(repo, approved, mode=mode, trigger="EVENT")
    assert JobWorker(repo, plan_reader=reader(Search([page(1), page(2)]), calls)).process_next()
    assert bool(calls) is walks
    assert {task["payload"]["mode"] for task in root_tasks(repo, job)} == ({"BASELINE"} if walks else {"EVENT"})


def test_a_stop_of_the_run_itself_still_stops_the_plan(caplog):
    repo = InMemoryRepository()
    job = enqueue(repo, approve(repo, [1, 2]))

    def stopped(job, hook, roots, budget):
        repo.request_job_cancel(job.id)
        budget.consume()  # its check sees the stop before a request goes out
        raise AssertionError("the walk went on after the stop")

    worker = JobWorker(repo, plan_reader=stopped)
    assert worker.process_next()
    assert root_tasks(repo, job) == [] and repo.get_job(job.id).status == "CANCELLED"
    # A refusal of the run (its connection paused) fails the plan with that refusal, not as missing metadata.
    repo = InMemoryRepository()
    approved = approve(repo, [1, 2])
    job = enqueue(repo, approved)

    def paused(job, hook, roots, budget):
        repo.update_connection(approved[0].id, status="DISABLED")
        budget.consume()
        raise AssertionError("the walk went on after the refusal")

    with caplog.at_level(logging.WARNING, logger="cremore.worker"):
        assert JobWorker(repo, plan_reader=paused).process_next()
    assert plan_task(repo, job)["status"] == "FAILED" and plan_task(repo, job)["error"] == "NEEDS_SCOPE_REVIEW"
    assert root_tasks(repo, job) == [] and "without page metadata" not in caplog.text


class PowerLoss(BaseException):
    """The worker process dies in the middle of the walk."""


def test_a_plan_run_again_after_a_crash_is_charged_what_its_first_walk_reserved(monkeypatch):
    now = {"value": dt.datetime.now(dt.UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    repo = InMemoryRepository()
    job = enqueue(repo, approve(repo, [1, 2], budget=1000))

    def dies(job, hook, roots, budget):
        for _ in range(3):
            budget.consume()
        raise PowerLoss()

    worker = JobWorker(repo, plan_reader=dies)
    with pytest.raises(PowerLoss):
        worker.process_next()
    reserved = plan_task(repo, job)["checkpoint"]["requests"]
    assert 3 <= reserved < 1000  # reserved before the requests went out, a few at a time
    now["value"] += dt.timedelta(seconds=121)  # its lease runs out and the plan is claimed again
    worker.plan_reader = lambda job, hook, roots, budget: {}
    assert worker.process_next()
    assert plan_task(repo, job)["result"] == {"planned_roots": 2, "requests": reserved}
    assert sum(task["payload"]["budgets"]["requests"] for task in root_tasks(repo, job)) == 1000 - reserved


def test_the_walk_s_time_is_paid_from_the_run_s_seconds_and_a_crashed_walk_s_only_once(monkeypatch):
    from types import SimpleNamespace

    from cremore.worker import runtime

    now, clock = {"value": dt.datetime.now(dt.UTC)}, [1000.0]
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    repo = InMemoryRepository()
    job = enqueue(repo, approve(repo, [1, 2]))  # 600 seconds approved for the run

    def dies(job, hook, roots, budget):
        clock[0] += 150  # 150 s into the walk, then the worker dies in it
        budget.consume()
        raise PowerLoss()

    worker = JobWorker(repo, plan_reader=dies)
    with pytest.raises(PowerLoss):
        worker.process_next()
    now["value"] += dt.timedelta(seconds=121)  # its lease runs out and the plan is claimed again

    def walks(job, hook, roots, budget):
        clock[0] += 100
        return {}

    worker.plan_reader = walks
    assert worker.process_next()
    # Both walks' time, the first once, comes off the run's seconds before the roots split them.
    assert [task["payload"]["budgets"]["seconds"] for task in root_tasks(repo, job)] == [175, 175]


def test_a_walk_dying_between_two_reservations_is_charged_its_time_up_to_the_last_periodic_save(monkeypatch):
    """Slow answers within one reservation: the time walked is saved again before a request once WALK_SAVE_SECONDS
    passed since the last save, and no more often, so the plan run again after a crash charges it up to that save."""
    from types import SimpleNamespace

    from cremore.worker import runtime

    now, clock, saved = {"value": dt.datetime.now(dt.UTC)}, [1000.0], []
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    checkpoint = TaskStore.checkpoint
    monkeypatch.setattr(TaskStore, "checkpoint",
                        lambda self, task_id, token, state: saved.append(state) or checkpoint(self, task_id, token, state))
    repo = InMemoryRepository()
    job = enqueue(repo, approve(repo, [1, 2]))  # 600 seconds approved for the run

    def dies(_job, _hook, _roots, budget):
        for _ in range(10):  # answers of 3 s each, all within the walk's first reservation
            budget.consume()
            clock[0] += 3
        raise PowerLoss()  # 30 s into the walk, 6 s after its last save

    worker = JobWorker(repo, plan_reader=dies)
    with pytest.raises(PowerLoss):
        worker.process_next()
    # The reservation before the first request, then the time alone before the 3rd, 5th, 7th and 9th.
    assert [(state["requests"], state["seconds"]) for state in saved] == [(63, 0), (63, 6), (63, 12), (63, 18), (63, 24)]
    assert {k: plan_task(repo, job)["checkpoint"][k] for k in ("requests", "seconds")} == {"requests": 63, "seconds": 24}
    now["value"] += dt.timedelta(seconds=121)  # its lease runs out and the plan is claimed again

    def walks(_job, _hook, _roots, _budget):
        clock[0] += 100
        return {}

    worker.plan_reader = walks
    assert worker.process_next()
    # The 24 s saved and the 100 s of the walk run again come off the run's 600 s before the roots split them.
    assert [task["payload"]["budgets"]["seconds"] for task in root_tasks(repo, job)] == [238, 238]


@pytest.mark.parametrize("pages", [[1, 2], [1, 2, 3]], ids=["two-roots", "three-roots"])
def test_a_walk_outlasting_the_run_s_time_leaves_every_root_a_second_and_the_run_finishes(monkeypatch, pages):
    import time
    from types import SimpleNamespace

    from cremore.worker import runtime

    # Real time plus what the walk spent: the scan service times objects on the real clock.
    late, real = [0.0], time.monotonic
    monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: real() + late[0]))

    class Slow(Search):
        def post(self, url, headers=None, json=None):
            late[0] += 350  # an answer that takes 350 s, waits for Notion included
            return super().post(url, headers=headers, json=json)

    repo, workspace = InMemoryRepository(), Workspace()
    search = Slow([page(n) for n in range(100, 400)])  # none of the approved pages: the walk keeps looking
    job = enqueue(repo, approve(repo, pages))  # 600 seconds approved for the run
    worker = JobWorker(repo, plan_reader=reader(search),
                       collector_factory=lambda job: build_collector(job, http_client_factory=lambda: workspace))
    for _ in range(12):
        worker.process_next()
        if repo.get_job(job.id).status not in ("QUEUED", "RUNNING"):
            break
    # Two answers, 700 s: two roots reach the walk's own cap, three would have left a root less than a second.
    assert len(search.bodies) == 2
    tasks = root_tasks(repo, job)
    assert len(tasks) == len(pages) and all(task["payload"]["budgets"]["seconds"] >= 1 for task in tasks)
    assert repo.get_job(job.id).status == "SUCCEEDED"
    assert not any(task["result"].get("stopped_reason") for task in tasks)



def test_the_worker_resolves_the_credential_for_the_walk_and_paces_change_feeds_through_the_database(monkeypatch):
    pytest.importorskip("boto3")
    import httpx

    from cremore.cli import worker as cli
    from cremore.config import Settings
    from cremore.secretstore.sealed import seal_fields

    settings = Settings(AUTH_MODE="local", API_TOKEN="0" * 32, FINGERPRINT_KEY="ab" * 32)
    repo = InMemoryRepository()
    worker = cli.build_worker(settings, repo)
    sealed = seal_fields(settings.sealing_keys, {"token": TOKEN})
    made = []

    def answer(request):
        assert request.headers["authorization"] == "Bearer " + TOKEN
        return httpx.Response(200, json={"results": [page(1, dt.datetime.now(dt.UTC).isoformat())],
                                         "has_more": False, "next_cursor": None})

    real = httpx.Client

    def client(**_kwargs):
        made.append(real(transport=httpx.MockTransport(answer)))
        return made[-1]

    monkeypatch.setattr(httpx, "Client", client)
    job = ScanJob(kind="scope", connection_id=uuid.uuid4(), payload={"secret_ref": sealed, "source_type": "notion"})
    seen = []

    def read(payload, roots, *, http_client, request_budget):
        seen.append((payload["token"], http_client, roots, request_budget))
        return {"found": "headers"}

    # The plan's walk: the sealed credential is opened here, in the worker, and its client closed after.
    assert worker.plan_reader(job, read, ["root"], "budget") == {"found": "headers"}
    [(token, used, roots, budget)] = seen
    assert (token, roots, budget) == (TOKEN, ["root"], "budget") and used.is_closed
    assert "token" not in job.payload
    # A change feed reads with the same credential and paces with the connection's scans.
    root = {"resource_id": "root-1", "resource_type": "NOTION_PAGE", "provider_resource_id": dashed(1),
            "page_mode": "PAGE_ONLY", "descendant_ids": []}
    states = {"root-1": {"cursor": (dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)).isoformat()}}
    answers = worker.change_reader({"secret_ref": sealed, "connection_id": str(job.connection_id),
                                    "source_type": "notion"}, [root], states, RequestBudget(10))
    assert answers["root-1"].paths == [dashed(1)] and KEY in paced(repo)
