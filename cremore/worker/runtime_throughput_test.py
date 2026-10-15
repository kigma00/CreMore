"""Root runtime throughput: fixed gaps advance the root, unchanged objects are reused,
budgets and validation stop costing a transaction each, clean objects commit in ordered
batches, and a collector's provider state survives only complete whole-root runs."""

import datetime as dt
import hashlib
import io
import json
import threading
import time
from types import SimpleNamespace

import pytest

from cremore.db import task_store as task_store_module
from cremore.db.repository import InMemoryRepository
from cremore.db.scan_store import ScanStore
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.db.task_store import LeaseLost, TaskStore
from cremore.domain.models import Connection, ScanJob, ScopeCatalog, ScopeProfile
from cremore.scanning import scope
from cremore.scanning import service as service_module
from cremore.scanning.extraction import ExtractionResult
from cremore.scanning.scope import root_identity, split_roots
from cremore.scanning.service import ScanService
from cremore.worker import runtime as runtime_module
from cremore.worker.factory import build_collector
from cremore.worker.worker import JobWorker

TOKEN = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
OLD = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 16
PARTIAL = b"%PDF-1.7 synthetic graphics-only page"


class Bucket:
    def __init__(self, objects, latency=0.0):
        self.objects = dict(objects)
        self.modified = {key: OLD for key in self.objects}
        self.latency, self.reads, self.fail = latency, [], set()
        self.slow = {}  # key -> seconds its GET takes
        self.listed = {}  # key -> the size LIST reports, when it differs from GET's

    def etag(self, key):
        return '"' + hashlib.sha256(self.objects[key]).hexdigest()[:16] + '"'

    def list_objects_v2(self, **kw):
        keys = sorted(k for k in self.objects if k.startswith(kw.get("Prefix", "")) and k > kw.get("StartAfter", ""))
        return {"Contents": [{"Key": k, "Size": self.listed.get(k, len(self.objects[k])), "ETag": self.etag(k),
                              "LastModified": self.modified[k]} for k in keys], "IsTruncated": False}

    def get_object(self, Bucket, Key):
        if self.latency or Key in self.slow:
            time.sleep(self.slow.get(Key, self.latency))
        if Key in self.fail:
            raise PermissionError("not disclosed")
        self.reads.append(Key)
        data = self.objects[Key]
        return {"Body": io.BytesIO(data), "ContentLength": len(data), "ETag": self.etag(Key),
                "LastModified": self.modified[Key]}


def environment(objects, backend="memory", *, budgets=None, factory=None):
    if backend == "memory":
        repo = InMemoryRepository()
    else:
        engine = make_engine("sqlite:///:memory:")
        create_all(engine)
        repo = SqlRepository(engine)
    conn = repo.create_connection(Connection(provider="aws", name="fixture", config={"bucket": "fixture"}))
    item = scope.resource("source", conn.id, "S3_BUCKET", "fixture", "fixture", "arn:aws:s3:::fixture", "aws")
    auth = scope.auth_revision("source", conn)
    catalog = repo.save_catalog(ScopeCatalog(kind="source", connection_id=conn.id, snapshot_id="v1",
                                             auth_revision=auth, items=[item], completeness="COMPLETE"))
    profile = repo.create_scope_profile(ScopeProfile(
        kind="source", connection_id=conn.id, name="approved", state="READY", auth_revision=auth,
        catalog_snapshot_id="v1", budgets=budgets or {"requests": 100_000, "bytes": 1 << 30, "seconds": 600},
        selected_roots=[{"resource_id": item["id"], "prefixes": ["data/"], "all_current_objects": False,
                         "include_future_descendants": False}]))
    bucket = Bucket(objects)

    def collector(job):
        built = build_collector(job, s3_client_factory=lambda _: bucket)
        return factory(built, job) if factory else built

    return SimpleNamespace(repo=repo, conn=conn, catalog=catalog, profile=profile, bucket=bucket,
                           worker=JobWorker(repo, collector_factory=collector))


def enqueue(env, mode="BASELINE", *, exact_keys=None, **job_payload):
    plan = scope.build_plan(env.profile, env.catalog, auth=env.profile.auth_revision, enabled=True)
    if exact_keys is not None:
        plan.trigger = "RESCAN"
        plan.roots = [{**r, "exact_keys": exact_keys} for r in plan.roots]
    payload = scope.run_payload(env.repo.create_plan(plan), env.profile, {}, "s3")
    payload.update(mode=mode, **job_payload)
    return env.repo.enqueue_job(ScanJob(kind="scope", connection_id=env.conn.id, payload=payload))


def finish(env, job):
    for _ in range(20):
        env.worker.process_next()
        done = env.repo.get_job(job.id)
        if done.status not in ("QUEUED", "RUNNING"):
            return done
    raise AssertionError("run did not finish")


def run(env, mode="BASELINE", **kwargs):
    return finish(env, enqueue(env, mode, **kwargs))


def root_task(env, job):
    [task] = [t for t in TaskStore(env.repo).list_for_run(job.id) if t["kind"] != "PLAN"]
    return task


def state(env):
    plan = scope.build_plan(env.profile, env.catalog, auth=env.profile.auth_revision, enabled=True)
    return ScanStore(env.repo).root(root_identity(env.conn.id, split_roots(plan.roots)[0]))


def partial_pdfs(monkeypatch):
    """A PDF whose graphics stay unread: a fixed limit of the format, not a failed read."""
    real = service_module.extract

    def extract(data, **kwargs):
        if data.startswith(b"%PDF-"):
            return ExtractionResult(b"visible text only", "pdf", False, "PDF_GRAPHICS_CONTENT")
        return real(data, **kwargs)

    monkeypatch.setattr(service_module, "extract", extract)


@pytest.mark.parametrize("backend", ["memory", "sql"])
def test_skips_and_fixed_gaps_advance_the_root_and_every_later_run_reports_them(monkeypatch, backend):
    partial_pdfs(monkeypatch)
    env = environment({"data/a.txt": b"plain", "data/b.png": PNG, "data/c.pdf": PARTIAL,
                       "data/d.bin": b"\0\1\2\3" * 8}, backend)
    first = run(env)
    result, root = root_task(env, first)["result"], state(env)
    gaps = dict(root["inspection_gaps"])
    assert first.status == "SUCCEEDED" and first.objects_failed == 0 and root["failed_keys"] == []
    # Reading the same bytes again cannot change any of these, so the root advances...
    assert root["watermark"] and root["last_reconcile"]
    assert gaps["data/b.png"] == "MEDIA_FORMAT" and gaps["data/c.pdf"] == "PDF_GRAPHICS_CONTENT"
    # ...and the run says plainly what it could not inspect.
    assert result["partially_inspected"] == 1 and result["skipped_media"] == 1
    assert result["root_coverage_complete"] is False and result["inspection_gaps"] == len(gaps)
    env.bucket.reads.clear()
    delta = run(env, "DELTA", reconcile_if_older_than_seconds=3600)
    later = root_task(env, delta)["result"]
    # Still a DELTA with no forced reconcile: every object is unchanged, nothing is read...
    assert later["skipped_unchanged"] == 4 and env.bucket.reads == []
    assert state(env)["last_reconcile"] == root["last_reconcile"]
    # ...and the root's gaps are reported again on this run.
    assert later["root_coverage_complete"] is False and later["inspection_gaps"] == len(gaps)
    assert scope.job_is_partial(delta)


@pytest.mark.parametrize("backend", ["memory", "sql"])
def test_an_unchanged_reconcile_reads_nothing_and_a_changed_object_is_read_again(monkeypatch, backend):
    partial_pdfs(monkeypatch)
    objects = {f"data/{i:03d}.txt": b"plain text" for i in range(40)}
    objects.update({"data/key.txt": f"k={TOKEN}".encode(), "data/logo.png": PNG, "data/scan.pdf": PARTIAL})
    env = environment(objects, backend)
    run(env)
    assert sorted(env.bucket.reads) == sorted(objects)
    env.bucket.reads.clear()
    again = run(env, "RECONCILE")
    result = root_task(env, again)["result"]
    assert env.bucket.reads == [] and result["reused"] == len(objects) and result["bytes"] == 0
    assert result["skipped_media"] == 1 and result["partially_inspected"] == 1 and again.findings == 1
    [finding] = env.repo.list_findings()
    assert finding.workflow_status == "OPEN" and not finding.all_locations_removed
    env.bucket.objects["data/007.txt"] = b"changed plain text"
    env.bucket.reads.clear()
    run(env, "RECONCILE")
    assert env.bucket.reads == ["data/007.txt"]


def test_requests_and_validation_stop_costing_a_transaction_each(monkeypatch):
    opened = []
    original = TaskStore.fenced

    def fenced(self, task_id, token):
        opened.append(threading.get_ident())
        return original(self, task_id, token)

    monkeypatch.setattr(TaskStore, "fenced", fenced)
    env = environment({f"data/{i:03d}.txt": b"plain" for i in range(200)})
    done = run(env)
    task = root_task(env, done)
    assert task["result"]["requests"] == 201 == task["checkpoint"]["requests"]
    assert task["result"]["objects"] == 200
    # One validation per request and per object plus one commit per object was over 600.
    assert len(opened) < 60, len(opened)
    assert set(opened) == {threading.get_ident()}  # only the owner thread opens one
    opened.clear()
    monkeypatch.setattr(runtime_module, "CHECK_SECONDS", 0.0)
    run(environment({f"data/{i:03d}.txt": b"plain" for i in range(200)}))
    assert len(opened) > 200  # without the once-a-second rule every guard check validates


def test_a_crash_over_counts_reserved_requests_but_never_past_the_limit(monkeypatch):
    class PowerLoss(BaseException):
        pass

    now = {"value": dt.datetime.now(dt.UTC)}
    monkeypatch.setattr(task_store_module, "_clock", lambda conn=None: now["value"])
    env = environment({f"data/{i:03d}.txt": b"plain" for i in range(100)},
                      budgets={"requests": 1000, "bytes": 1 << 30, "seconds": 600})
    get = env.bucket.get_object

    def crash(**kwargs):
        if kwargs["Key"] == "data/050.txt":
            raise PowerLoss()
        return get(**kwargs)

    env.bucket.get_object = crash
    job = enqueue(env)
    assert env.worker.process_next()
    with pytest.raises(PowerLoss):
        env.worker.process_next()
    made = 1 + len(env.bucket.reads) + 1  # the listing, the reads, the crashed GET
    reserved = root_task(env, job)["checkpoint"]["requests"]
    assert made <= reserved <= 1000 and reserved - made < runtime_module.RESERVE_REQUESTS
    env.bucket.get_object = get
    now["value"] += dt.timedelta(seconds=121)
    done = finish(env, job)
    assert done.status == "SUCCEEDED" and root_task(env, done)["result"]["requests"] <= 1000


def test_clean_objects_commit_in_ordered_batches_and_others_commit_alone(monkeypatch):
    monkeypatch.setattr(service_module, "BATCH_SECONDS", 60.0)  # batches end by count here
    objects = {f"data/{i:03d}.txt": b"plain" for i in range(150)}
    objects["data/070.txt"] = f"k={TOKEN}".encode()
    env = environment(objects)
    run(env)
    calls = []
    original = ScanService.run

    def spy(self, collector, **kwargs):
        commit = kwargs["commit_objects"]

        def recorded(repo, outcomes):
            calls.append(([o.resource.location for o in outcomes], threading.get_ident()))
            return commit(repo, outcomes)

        return original(self, collector, **{**kwargs, "commit_objects": recorded})

    monkeypatch.setattr(ScanService, "run", spy)
    env.bucket.objects["data/100.txt"] = f"k={TOKEN[:-1]}Q".encode()
    run(env, "RECONCILE")
    assert [location for locations, _ in calls for location in locations] == sorted(env.bucket.objects)
    assert ["data/070.txt"] in [locations for locations, _ in calls]  # a known exposure's location
    assert ["data/100.txt"] in [locations for locations, _ in calls]  # an object with detections
    assert max(len(locations) for locations, _ in calls) <= 64 and len(calls) <= 8
    assert {ident for _, ident in calls} == {threading.get_ident()}


@pytest.mark.parametrize("backend", ["memory", "sql"])
def test_a_lease_lost_mid_batch_commits_none_of_it_and_the_resume_reads_every_uncommitted_key(
        monkeypatch, backend):
    monkeypatch.setattr(service_module, "BATCH_SECONDS", 60.0)  # batches end by count here
    keys = [f"data/{i:03d}.txt" for i in range(150)]
    env = environment({key: b"plain" for key in keys}, backend)
    now = {"value": dt.datetime.now(dt.UTC)}
    monkeypatch.setattr(task_store_module, "_clock", lambda conn=None: now["value"])
    original = TaskStore.checkpoint
    refused = []

    def checkpoint(self, task_id, token, value):
        if value.get("objects", 0) > 64 and not refused:
            refused.append(value["last_key"])
            raise LeaseLost("TASK_LEASE_LOST")
        return original(self, task_id, token, value)

    monkeypatch.setattr(TaskStore, "checkpoint", checkpoint)
    job = enqueue(env)
    assert env.worker.process_next() and env.worker.process_next()
    kept = root_task(env, job)["checkpoint"]
    assert refused and kept["objects"] == 64 and kept["last_key"] == keys[63]
    env.bucket.reads.clear()
    now["value"] += dt.timedelta(seconds=121)
    done = finish(env, job)
    # The refused batch was read but never committed: the resume reads every key after
    # the last committed one, so none is skipped.
    assert sorted(env.bucket.reads) == keys[64:]
    assert done.status == "SUCCEEDED" and root_task(env, done)["result"]["objects"] == 150


def test_provider_state_is_offered_back_and_kept_only_after_a_complete_whole_root_run():
    offered = []

    def factory(collector, job):
        offered.append(job.payload["roots"][0].get("provider_state"))
        collector.parts[0].provider_state = {"commit": f"c{len(offered)}"}
        return collector

    env = environment({"data/a.txt": b"plain", "data/b.txt": b"plain"}, factory=factory)
    run(env)
    assert offered == [{}] and state(env)["provider_state"] == {"commit": "c1"}
    run(env, "DELTA")
    assert offered[-1] == {"commit": "c1"} and state(env)["provider_state"] == {"commit": "c2"}
    run(env, exact_keys=["data/a.txt"])  # a rescan of chosen keys is not the whole root
    assert state(env)["provider_state"] == {"commit": "c2"}
    env.bucket.fail.add("data/b.txt")
    env.bucket.objects["data/b.txt"] = b"changed"
    assert run(env, "RECONCILE").objects_failed == 1  # an unread object: not a complete run
    assert offered[-1] == {"commit": "c2"} and state(env)["provider_state"] == {"commit": "c2"}


def test_a_provider_state_with_a_secret_shaped_field_is_never_saved():
    def factory(collector, _job):
        collector.parts[0].provider_state = {"commit": "c1", "token": "synthetic-value"}
        return collector

    env = environment({"data/a.txt": b"plain"}, factory=factory)
    assert run(env).status == "SUCCEEDED" and "provider_state" not in state(env)


def test_an_unchanged_rescan_larger_than_the_byte_budget_reads_nothing_and_completes_in_one_run():
    env = environment({f"data/{i:03d}.txt": b"x" * 1000 for i in range(100)},
                      budgets={"requests": 100_000, "bytes": 30_000, "seconds": 600})
    stops = []
    for attempt in range(8):  # the first full read takes several byte-budget runs, each resuming
        done = run(env, "BASELINE" if attempt == 0 else "DELTA")
        stops.append(root_task(env, done)["result"].get("stopped_reason"))
        if not state(env).get("resume_after"):
            break
    assert stops == ["BUDGET_BYTES"] * 3 + [None] and state(env)["watermark"]
    env.bucket.reads.clear()
    again = run(env, "RECONCILE")
    result = root_task(env, again)["result"]
    # Cache hits download nothing, so they spend none of the byte budget.
    assert again.status == "SUCCEEDED" and not result.get("stopped_reason") and not state(env).get("resume_after")
    assert env.bucket.reads == [] and result["reused"] == 100 and result["bytes"] == 0


def test_objects_inspected_before_the_deadline_are_kept_when_a_pending_batch_commits_after_it(monkeypatch):
    monkeypatch.setattr(service_module, "BATCH_SECONDS", 60.0)
    env = environment({f"data/{i:03d}.txt": b"plain" for i in range(40)},
                      budgets={"requests": 100_000, "bytes": 1 << 30, "seconds": 1})
    env.bucket.slow["data/020.txt"] = 1.5  # the deadline passes while this one downloads
    job = enqueue(env)
    assert env.worker.process_next() and env.worker.process_next()
    task = root_task(env, job)
    assert task["result"]["stopped_reason"] == "BUDGET_SECONDS"
    assert task["checkpoint"]["objects"] == 20 and task["checkpoint"]["last_key"] == "data/019.txt"


def test_bytes_a_listing_downloaded_are_spent_even_when_the_cache_answers():
    env = environment({"data/a.txt": b"plain text", "data/b.txt": b"more plain text"})
    run(env)
    rescan = run(env, exact_keys=["data/a.txt"])  # exact keys are read while listing
    result = root_task(env, rescan)["result"]
    assert result["reused"] == 1 and result["bytes"] == len(b"plain text")


def test_gap_lists_are_rebuilt_only_when_a_commit_changes_them(monkeypatch):
    calls = []
    original = runtime_module.gap_list

    def counted(gaps):
        calls.append(len(gaps))
        return original(gaps)

    monkeypatch.setattr(runtime_module, "gap_list", counted)
    run(environment({f"data/{i:03d}.txt": b"plain" for i in range(200)}))
    assert calls == [0]  # the final report only: no commit touched a gap


def test_a_batch_that_ages_while_a_slow_object_parses_commits_before_the_parse_ends(monkeypatch):
    env = environment({**{f"data/{i:03d}.txt": b"plain" for i in range(10)}, "data/zz.pdf": b"%PDF-1.7 slow"})
    real = service_module.extract
    window = {}

    def extract(data, *, filename="", progress=None, **kwargs):
        if filename != "data/zz.pdf":
            return real(data, filename=filename, progress=progress, **kwargs)
        window["start"] = time.monotonic()
        for _ in range(15):
            progress()
            time.sleep(0.1)
        window["end"] = time.monotonic()
        return ExtractionResult(b"visible text", "pdf", True, "")

    monkeypatch.setattr(service_module, "extract", extract)
    calls = []
    original = ScanService.run

    def spy(self, collector, **kwargs):
        commit = kwargs["commit_objects"]

        def recorded(repo, outcomes):
            calls.append(([o.resource.location for o in outcomes], time.monotonic()))
            return commit(repo, outcomes)

        return original(self, collector, **{**kwargs, "commit_objects": recorded})

    monkeypatch.setattr(ScanService, "run", spy)
    run(env)
    [committed_at] = [at for locations, at in calls if "data/000.txt" in locations]
    assert window["start"] < committed_at < window["end"]


def test_a_full_read_drops_an_earlier_cut_short_gap_list_and_other_runs_keep_reporting_it(monkeypatch):
    env = environment({"data/a.txt": b"plain"})
    run(env)
    monkeypatch.setattr(runtime_module, "FAILURE_KEY_LIMIT", 2)
    plan = scope.build_plan(env.profile, env.catalog, auth=env.profile.auth_revision, enabled=True)
    identity = root_identity(env.conn.id, split_roots(plan.roots)[0])
    gone = [[f"data/gone{i}.png", "MEDIA_FORMAT"] for i in range(5)]
    ScanStore(env.repo).save_root(identity, env.conn.id, {**state(env), "inspection_gaps": gone,
                                                          "inspection_gaps_overflow": True})
    delta = root_task(env, run(env, "DELTA"))["result"]
    assert delta["inspection_gaps_overflow"] is True and delta["root_coverage_complete"] is False
    assert state(env)["inspection_gaps_overflow"] is True
    full = root_task(env, run(env, "RECONCILE"))["result"]
    assert "inspection_gaps_overflow" not in full and full["inspection_gaps"] == 0
    assert state(env)["inspection_gaps"] == [] and state(env)["inspection_gaps_overflow"] is False


def test_a_gap_list_past_its_bound_is_cut_and_says_so(monkeypatch):
    monkeypatch.setattr(runtime_module, "FAILURE_KEY_LIMIT", 2)
    env = environment({**{f"data/{i}.png": PNG for i in range(5)}, "data/a.txt": b"plain"})
    result = root_task(env, run(env))["result"]
    assert len(state(env)["inspection_gaps"]) == 2 and state(env)["inspection_gaps_overflow"] is True
    assert result["inspection_gaps_overflow"] is True and result["root_coverage_complete"] is False


def test_a_budget_stop_keeps_the_gaps_it_did_not_reach_and_adds_the_ones_it_found():
    env = environment({"data/a.png": PNG, "data/b.png": PNG, "data/c.txt": b"plain"})
    run(env)
    assert dict(state(env)["inspection_gaps"]) == {"data/a.png": "MEDIA_FORMAT", "data/b.png": "MEDIA_FORMAT"}
    now = dt.datetime.now(dt.UTC)
    env.bucket.objects.update({"data/a.png": b"now plain text", "data/d.png": PNG, "data/e.txt": b"plain"})
    env.bucket.modified.update({"data/a.png": now, "data/d.png": now, "data/e.txt": now})
    # One listing and two reads: the run stops before e.txt, a DELTA that never reached b.png.
    env.profile = env.repo.update_scope_profile(env.profile.id, budgets={"requests": 3, "bytes": 1 << 30,
                                                                         "seconds": 600})
    stopped = run(env, "DELTA")
    assert root_task(env, stopped)["result"]["stopped_reason"] == "BUDGET_REQUESTS"
    assert dict(state(env)["inspection_gaps"]) == {"data/b.png": "MEDIA_FORMAT", "data/d.png": "MEDIA_FORMAT"}
    assert root_task(env, stopped)["result"]["inspection_gaps"] == 2


def test_a_batch_the_byte_budget_only_partly_takes_commits_what_fits_and_stops(monkeypatch):
    monkeypatch.setattr(service_module, "BATCH_SECONDS", 60.0)
    env = environment({f"data/{i:03d}.txt": b"y" * 1000 for i in range(20)},
                      budgets={"requests": 100_000, "bytes": 5_500, "seconds": 600})
    env.bucket.listed = {key: 10 for key in env.bucket.objects}  # grown since LIST
    job = enqueue(env)
    assert env.worker.process_next() and env.worker.process_next()
    task = root_task(env, job)
    assert task["result"]["stopped_reason"] == "BUDGET_BYTES"
    assert task["checkpoint"]["objects"] == 5 and task["checkpoint"]["bytes"] == 5_000
    assert task["checkpoint"]["last_key"] == "data/004.txt" == state(env)["resume_after"]


def test_objects_read_while_listing_never_run_past_the_byte_budget():
    keys = [f"data/{i:03d}.txt" for i in range(40)]
    env = environment({key: b"x" * 1_000_000 for key in keys},
                      budgets={"requests": 100_000, "bytes": 5_500_000, "seconds": 600})
    done = run(env, exact_keys=keys)  # exact keys are downloaded inside the listing
    task = root_task(env, done)
    assert task["result"]["stopped_reason"] == "BUDGET_BYTES"
    assert task["checkpoint"]["objects"] == 5 and task["checkpoint"]["bytes"] == 5_000_000
    assert len(env.bucket.reads) == 6  # one past the budget, as reading one object at a time did


def test_a_read_ahead_that_already_failed_spends_no_budget_and_stops_nothing():
    objects = {f"data/{i:03d}.txt": b"y" * 1000 for i in range(6)}
    env = environment(objects, budgets={"requests": 100_000, "bytes": 5_500, "seconds": 600})
    env.bucket.listed = {f"data/{i:03d}.txt": 900 for i in range(5)}  # grown since LIST
    env.bucket.fail.add("data/005.txt")
    env.bucket.slow["data/000.txt"] = 0.2  # the failing read has finished when its turn comes
    done = run(env)
    result = root_task(env, done)["result"]
    assert result.get("stopped_reason") is None and result["objects"] == 5 and done.objects_failed == 1
    assert state(env)["failed_keys"] == ["data/005.txt"]


def scenario(monkeypatch, batch_objects):
    """A baseline and a changed reconcile; returns what each left behind."""
    monkeypatch.setattr(service_module, "BATCH_OBJECTS", batch_objects)
    monkeypatch.setattr(service_module, "BATCH_SECONDS", 60.0)
    partial_pdfs(monkeypatch)
    objects = {f"data/t{i:03d}.txt": b"plain text" for i in range(70)}
    objects.update({"data/k0.env": f"k={TOKEN}".encode(), "data/k1.env": f"k={TOKEN[:-1]}Q".encode(),
                    "data/u0.txt": b"plain", "data/u1.txt": b"plain"})
    objects.update({f"data/i{i}.png": PNG for i in range(4)})
    objects.update({f"data/p{i}.pdf": PARTIAL for i in range(2)})
    env = environment(objects)
    env.bucket.fail.update({"data/u0.txt", "data/u1.txt"})
    snapshots = [snapshot(env, run(env))]
    env.bucket.objects["data/k0.env"] = b"no credential any more"
    env.bucket.objects["data/t007.txt"] = b"changed plain text"
    env.bucket.fail.discard("data/u0.txt")
    snapshots.append(snapshot(env, run(env, "RECONCILE")))
    return snapshots


def snapshot(env, job):
    task = root_task(env, job)
    root = state(env)
    keys = ("objects", "findings", "bytes", "requests", "skipped_unsupported", "skipped_media",
            "partially_inspected", "extraction_reasons", "last_key", "failed_keys", "inspection_gaps")
    return {
        "checkpoint": {key: task["checkpoint"].get(key) for key in keys},
        "coverage": {key: task["result"].get(key) for key in (*keys[:7], "failed", "inspection_gaps",
                                                              "root_coverage_complete")},
        "root": {**{key: root.get(key) for key in ("failed_keys", "inspection_gaps", "inspection_gaps_overflow",
                                                    "retry_overflow", "resume_after")},
                 "watermark": bool(root.get("watermark"))},
        "exposures": sorted((e.location, e.status, e.line_number)
                            for e in env.repo.exposures_for_connection(env.conn.id)),
        "findings": sorted((f.workflow_status, f.all_locations_removed) for f in env.repo.list_findings()),
        "cache": sorted(json.dumps(value, sort_keys=True) for value in ScanStore(env.repo).memory["cache"].values()),
    }


def test_batched_and_one_by_one_commits_leave_the_same_state(monkeypatch):
    batched = scenario(monkeypatch, 64)
    single = scenario(monkeypatch, 1)
    assert batched == single
    reconciled = batched[1]
    assert ("data/k0.env", "REMOVED", 1) in reconciled["exposures"]  # a clean re-read retired it
    assert reconciled["root"]["failed_keys"] == ["data/u1.txt"]


def test_batched_outcomes_keep_no_extracted_text(monkeypatch):
    import tracemalloc

    peaks = {}
    line = b"status=ok service log line\n"
    objects = {f"data/{i:03d}.log": line * (1024 * 1024 // len(line)) for i in range(16)}
    for size in (64, 1):
        monkeypatch.setattr(service_module, "BATCH_OBJECTS", size)
        monkeypatch.setattr(service_module, "BATCH_SECONDS", 60.0)
        env = environment(objects)
        tracemalloc.start()
        try:
            assert run(env).status == "SUCCEEDED"
            peaks[size] = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
    # Holding each object's text until its batch commits would add about 16 MiB here.
    assert peaks[64] - peaks[1] < 8 << 20, peaks
