"""Approved scopes run end-to-end through the real task and checkpoint path."""

import datetime as dt
import io

import pytest

from cremore.db.repository import InMemoryRepository
from cremore.db.scan_store import ScanStore
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.db.task_store import TaskStore
from cremore.domain.models import Connection, ScanJob, ScopeCatalog, ScopeProfile
from cremore.scanning import scope
from cremore.source_config import RESOURCE_SOURCE
from cremore.worker.factory import build_collector
from cremore.worker.runtime import root_identity, split_roots
from cremore.worker.worker import JobWorker

TOKEN = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"


class Bucket:
    def __init__(self):
        self.objects = {"config/a": TOKEN.encode(), "config/b": b"no credential"}
        self.modified = {k: dt.datetime(2020, 1, 1, tzinfo=dt.UTC) for k in self.objects}
        self.reads = []
        self.fail = set()

    def list_objects_v2(self, **kw):
        return {
            "Contents": [
                {"Key": k, "Size": len(v), "ETag": str(hash(v)), "LastModified": self.modified[k]}
                for k, v in sorted(self.objects.items())
                if k.startswith(kw.get("Prefix", "")) and k > kw.get("StartAfter", "")
            ],
            "IsTruncated": False,
        }

    def get_object(self, Bucket, Key):
        self.reads.append(Key)
        if Key in self.fail:
            raise PermissionError("not disclosed")
        data = self.objects[Key]
        return {
            "Body": io.BytesIO(data),
            "ContentLength": len(data),
            "ETag": str(hash(data)),
            "LastModified": self.modified[Key],
        }


def repository(kind):
    if kind == "memory":
        return InMemoryRepository()
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


@pytest.fixture(params=["memory", "sql"])
def setup(request):
    repo = repository(request.param)
    conn = repo.create_connection(
        Connection(provider="aws", name="fixture", config={"bucket": "fixture"})
    )
    item = scope.resource(
        "source", conn.id, "S3_BUCKET", "fixture", "fixture", "arn:aws:s3:::fixture", "aws"
    )
    auth = scope.auth_revision("source", conn)
    catalog = repo.save_catalog(
        ScopeCatalog(
            kind="source",
            connection_id=conn.id,
            snapshot_id="v1",
            auth_revision=auth,
            items=[item],
            completeness="COMPLETE",
        )
    )
    profile = repo.create_scope_profile(
        ScopeProfile(
            kind="source",
            connection_id=conn.id,
            name="approved",
            selected_roots=[
                {
                    "resource_id": item["id"],
                    "prefixes": ["config/"],
                    "all_current_objects": False,
                    "include_future_descendants": False,
                }
            ],
            state="READY",
            auth_revision=auth,
            catalog_snapshot_id="v1",
            budgets={"requests": 20, "bytes": 10000, "seconds": 30},
        )
    )
    bucket = Bucket()
    worker = JobWorker(
        repo, collector_factory=lambda job: build_collector(job, s3_client_factory=lambda _: bucket)
    )
    return repo, conn, catalog, profile, bucket, worker


def enqueue(setup, mode="BASELINE", exact_keys=None, trigger=None, **job_payload):
    repo, conn, catalog, profile, _, _ = setup
    plan = scope.build_plan(profile, catalog, auth=profile.auth_revision, enabled=True)
    if exact_keys is not None:
        plan.trigger = "RESCAN"
        plan.roots = [{**r, scope.EXACT_FIELDS[r["resource_type"]]: exact_keys} for r in plan.roots]
    plan.trigger = trigger or plan.trigger
    plan = repo.create_plan(plan)
    payload = scope.run_payload(plan, profile, {}, RESOURCE_SOURCE[plan.roots[0]["resource_type"]])
    payload["mode"] = mode
    if trigger == "EVENT":
        payload["not_before"] = dt.datetime.now(dt.UTC).isoformat()  # as enqueue_event sets it, without the wait
    payload.update(job_payload)
    return repo.enqueue_job(ScanJob(kind="scope", connection_id=conn.id, payload=payload)), plan


def finish(setup, job):
    repo, _, _, _, _, worker = setup
    for _ in range(12):
        worker.process_next()
        current = repo.get_job(job.id)
        if current.status not in ("QUEUED", "RUNNING"):
            return current
    raise AssertionError("parent was not finalized")


def test_delta_reads_changed_only_and_location_removal_never_revokes(setup):
    repo, conn, _, _, bucket, _ = setup
    job, plan = enqueue(setup)
    assert finish(setup, job).status == "SUCCEEDED"
    assert sorted(bucket.reads) == ["config/a", "config/b"]
    state = ScanStore(repo).root(root_identity(conn.id, split_roots(plan.roots)[0]))
    assert state["watermark"] and state["detection_digest"]
    bucket.reads.clear()
    bucket.objects["config/a"] = b"removed from current object"
    bucket.modified["config/a"] = dt.datetime.now(dt.UTC)
    delta, _ = enqueue(setup, "DELTA")
    done = finish(setup, delta)
    assert done.status == "SUCCEEDED" and done.objects_failed == 0
    assert bucket.reads == ["config/a"]
    finding = repo.list_findings()[0]
    assert finding.workflow_status == "OPEN" and finding.all_locations_removed is True


def test_an_event_that_asks_for_a_baseline_runs_as_that_baseline(setup):
    """A change feed that saw history rewritten queues an EVENT job whose mode is BASELINE:
    it settles what is gone from the root as a baseline does, which an event never does."""
    repo, _conn, _, _, bucket, _ = setup
    job, _ = enqueue(setup)
    assert finish(setup, job).status == "SUCCEEDED"
    del bucket.objects["config/a"]
    event, _ = enqueue(setup, "DELTA", trigger="EVENT")
    assert finish(setup, event).status == "SUCCEEDED"
    assert repo.list_findings()[0].all_locations_removed is False
    rewritten, _ = enqueue(setup, "BASELINE", trigger="EVENT")
    assert finish(setup, rewritten).status == "SUCCEEDED"
    assert repo.list_findings()[0].all_locations_removed is True


def test_delta_listing_an_unchanged_object_refreshes_its_exposure_sighting(setup):
    repo, conn, _, _, bucket, _ = setup
    job, _ = enqueue(setup)
    assert finish(setup, job).status == "SUCCEEDED"
    [before] = [e.last_seen_at for e in repo.exposures_for_connection(conn.id) if e.location == "config/a"]
    bucket.reads.clear()
    delta, _ = enqueue(setup, "DELTA")
    assert finish(setup, delta).status == "SUCCEEDED"
    assert bucket.reads == []  # unchanged objects are listed, never downloaded again
    [after] = [e for e in repo.exposures_for_connection(conn.id) if e.location == "config/a"]
    assert after.status == "OPEN" and after.last_seen_at > before


@pytest.mark.parametrize("listed_revision", ["changed", "missing"])
def test_delta_listing_does_not_refresh_a_different_or_unknown_revision(setup, monkeypatch, listed_revision):
    repo, conn, _, _, bucket, _ = setup
    job, _ = enqueue(setup)
    assert finish(setup, job).status == "SUCCEEDED"
    [before] = [e.last_seen_at for e in repo.exposures_for_connection(conn.id) if e.location == "config/a"]
    if listed_revision == "changed":
        # Both versions predate the watermark; only the original contains the token.
        bucket.objects["config/a"] = b"replaced long ago without a credential"
    else:
        original = bucket.list_objects_v2

        def without_etag(**kwargs):
            page = original(**kwargs)
            for row in page["Contents"]:
                row.pop("ETag")
            return page

        monkeypatch.setattr(bucket, "list_objects_v2", without_etag)
    bucket.reads.clear()
    delta, _ = enqueue(setup, "DELTA")
    assert finish(setup, delta).status == "SUCCEEDED"
    assert bucket.reads == []
    [after] = [e for e in repo.exposures_for_connection(conn.id) if e.location == "config/a"]
    assert after.last_seen_at == before and after.status == "OPEN"


def test_legacy_resume_event_without_exact_targets_cannot_complete_empty(setup):
    repo, _conn, _, _, bucket, worker = setup
    run, _ = enqueue(setup, "EVENT", trigger="RESUME")
    done = finish(setup, run)
    assert done.status == "FAILED"
    assert any("EVENT_EXACT_TARGET_REQUIRED" in (task.get("error") or "")
               for task in worker.runtime.tasks.list_for_run(run.id))
    assert bucket.reads == [] and repo.list_findings() == []


def test_already_planned_legacy_event_without_keys_is_refused_before_collection(setup):
    from cremore.collectors.base import CollectorError

    _repo, _conn, _, _, bucket, worker = setup
    run, plan = enqueue(setup, "EVENT", trigger="RESUME")
    task = {"payload": {"mode": "EVENT", "scope": plan.roots[0], "job_payload": run.payload,
                        "budgets": run.payload["budgets"], "keys": []}, "checkpoint": {}}
    with pytest.raises(CollectorError, match="EVENT_EXACT_TARGET_REQUIRED"):
        worker.runtime.run_root(run, task)
    assert bucket.reads == []


def test_automatic_s3_continuation_advances_then_ends_the_chain(setup):
    from cremore.scanning.triggers import poll_resumable

    repo, conn, catalog, profile, bucket, worker = setup
    profile = repo.update_scope_profile(profile.id, approved_by="admin", approved_at=dt.datetime.now(dt.UTC),
                                       budgets={"requests": 2, "bytes": 10000, "seconds": 30})
    updated = (repo, conn, catalog, profile, bucket, worker)
    first, _ = enqueue(updated)
    assert finish(updated, first).coverage["stopped_reason"] == "BUDGET_REQUESTS"
    assert bucket.reads == ["config/a"]
    assert poll_resumable(repo, worker.settings)["enqueued"] == 1
    second = next(job for job in repo.list_jobs() if job.id != first.id)
    assert second.payload["trigger"] == "RESUME"
    assert finish(updated, second).status == "SUCCEEDED"
    assert bucket.reads == ["config/a", "config/b"]
    assert poll_resumable(repo, worker.settings) == {"enqueued": 0, "skipped": 0}
    assert len(repo.list_jobs()) == 2


@pytest.mark.parametrize("observation", ["unchanged", "unchanged_partial", "missing"])
def test_delta_listing_updates_cleanup_only_from_a_fresh_complete_observation(setup, monkeypatch, observation):
    from cremore.governance import response
    from cremore.scanning.response_test import answered, request

    repo, _conn, _, _, bucket, _ = setup
    baseline, _ = enqueue(setup)
    assert finish(setup, baseline).status == "SUCCEEDED"
    finding = repo.list_findings()[0]
    answered(repo, finding, request(repo, monkeypatch, finding), dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1))
    bucket.reads.clear()
    if observation in ("missing", "unchanged_partial"):
        if observation == "missing":
            del bucket.objects["config/a"]
        bucket.objects["config/b"] = b"unreadable"
        bucket.modified["config/b"] = dt.datetime.now(dt.UTC)
        bucket.fail.add("config/b")
        partial, _ = enqueue(setup, "DELTA")
        assert finish(setup, partial).status == "SUCCEEDED"
        assert response.summary(repo, finding.id)["state"] == ("WAITING_VERIFICATION" if observation == "missing" else "NEEDS_ACTION")
        bucket.fail.clear()
    delta, _ = enqueue(setup, "DELTA")
    assert finish(setup, delta).status == "SUCCEEDED"
    assert response.summary(repo, finding.id)["state"] == ("REMOVED" if observation == "missing" else "NEEDS_ACTION")
    if observation == "unchanged":
        assert bucket.reads == []
    elif observation == "unchanged_partial":
        assert "config/a" not in bucket.reads


def test_root_identity_and_worker_exports_preserve_persisted_checkpoint_contract():
    import uuid

    connection_id = uuid.UUID("11111111-1111-4111-8111-111111111111")
    root = {"resource_type": "S3_BUCKET", "provider_resource_id": "synthetic-bucket",
            "all_current_objects": False, "prefixes": ["config/", "한글/"], "excluded_prefixes": ["skip/"]}
    assert root_identity is scope.root_identity
    assert split_roots is scope.split_roots
    assert root_identity(connection_id, root) == "737f257d45beb45ac1224536f829fc566d91ee5749fc673c31bc4c4acc791429"
    assert root_identity(connection_id, {**root, "plan_id": "new"}) == root_identity(connection_id, root)
    assert root_identity(connection_id, {**root, "prefixes": ["other/"]}) != root_identity(connection_id, root)


def test_delta_listing_missing_key_is_evidence_and_keeps_one_row_per_read_revision(setup):
    repo, _, _, _, bucket, _ = setup
    job, _ = enqueue(setup)
    assert finish(setup, job).status == "SUCCEEDED"
    del bucket.objects["config/a"]
    delta, _ = enqueue(setup, "DELTA")
    assert finish(setup, delta).status == "SUCCEEDED"
    assert repo.list_findings()[0].all_locations_removed is True
    # config/a's detection row and config/b's clean row: each names the revision GET read.
    store = ScanStore(repo)
    if store.engine is None:
        assert len(store.memory["cache"]) == 2
    else:
        from sqlalchemy import func, select

        with store.engine.connect() as conn:
            assert conn.scalar(select(func.count()).select_from(store.tables["cache"])) == 2


def test_old_failed_key_retried_without_advancing_failed_baseline(setup):
    repo, conn, _, _, bucket, _ = setup
    bucket.fail.add("config/a")
    job, plan = enqueue(setup)
    done = finish(setup, job)
    assert done.status == "SUCCEEDED" and done.objects_failed == 1
    state = ScanStore(repo).root(root_identity(conn.id, split_roots(plan.roots)[0]))
    assert not state.get("watermark") and state["failed_keys"] == ["config/a"]
    bucket.fail.clear()
    bucket.reads.clear()
    retry, _ = enqueue(setup, "DELTA")
    assert finish(setup, retry).status == "SUCCEEDED"
    assert "config/a" in bucket.reads and repo.list_findings()


def test_stale_approval_cannot_read_provider(setup):
    repo, _, _, profile, bucket, _ = setup
    job, _ = enqueue(setup)
    repo.update_scope_profile(profile.id, version=profile.version + 1)
    assert finish(setup, job).status == "FAILED"
    assert bucket.reads == []


def test_exact_rescan_never_establishes_or_advances_root_checkpoint(setup):
    repo, conn, _, _, bucket, _ = setup
    job, plan = enqueue(setup, exact_keys=["config/a"])
    assert finish(setup, job).status == "SUCCEEDED"
    identity = root_identity(conn.id, split_roots(plan.roots)[0])
    assert not ScanStore(repo).root(identity).get("watermark")
    baseline, _ = enqueue(setup)
    assert finish(setup, baseline).status == "SUCCEEDED"
    watermark = ScanStore(repo).root(identity)["watermark"]
    bucket.modified["config/a"] = dt.datetime.now(dt.UTC)
    exact, _ = enqueue(setup, exact_keys=["config/a"])
    assert finish(setup, exact).status == "SUCCEEDED"
    assert ScanStore(repo).root(identity)["watermark"] == watermark


def test_resume_retries_failed_keys_before_cursor_without_claiming_complete_listing():
    from cremore_aws_provider.collectors.s3 import S3Collector

    bucket = Bucket()
    collector = S3Collector(
        bucket,
        "fixture",
        prefixes=["config/"],
        start_after="config/b",
        failed_keys=["config/a", "outside/secret"],
        lazy=True,
    )
    assert [obj.resource.location for obj in collector.collect()] == ["config/a"]
    assert bucket.reads == ["config/a"]
    assert not collector.listing_complete


def test_a_retried_key_too_large_to_read_is_refused_before_its_body_is_read():
    from cremore_aws_provider.collectors.s3 import S3Collector

    class Body(io.BytesIO):
        reads = 0

        def read(self, *args):
            Body.reads += 1
            return super().read(*args)

    bucket = Bucket()
    bucket.objects["config/0-large"] = b"x" * 64  # failed on its listed size in an earlier attempt
    bucket.modified["config/0-large"] = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
    original = bucket.get_object
    bucket.get_object = lambda **kw: {**original(**kw), "Body": Body(bucket.objects[kw["Key"]])}
    collector = S3Collector(bucket, "fixture", prefixes=["config/"], start_after="config/b",
                            failed_keys=["config/0-large"], max_object_bytes=32, lazy=True)
    assert list(collector.collect()) == []
    assert bucket.reads == ["config/0-large"] and Body.reads == 0
    assert collector.failed_objects == 1 and collector.failed_keys == {"config/0-large"}


@pytest.mark.parametrize("prefixes", [["a/", "c/"], ["c/", "a/"]], ids=["sorted", "unsorted"])
def test_a_resumed_listing_run_to_its_end_names_only_approved_keys_after_its_cursor_missing(prefixes):
    from cremore_aws_provider.collectors.s3 import S3Collector

    bucket = Bucket()
    bucket.objects = {key: b"no credential" for key in ("a/kept", "c/n-kept", "c/skip/kept")}
    bucket.modified = dict.fromkeys(bucket.objects, dt.datetime(2020, 1, 1, tzinfo=dt.UTC))
    # Gone: before the cursor in each prefix, after it, under the excluded prefix and outside every approved prefix.
    watched = ["a/gone", "a/zz-gone", "c/a-gone", "c/n-kept", "c/skip/z-gone", "c/z-gone", "d/z-gone"]

    def collector():
        return S3Collector(bucket, "fixture", prefixes=prefixes, excluded_prefixes=["c/skip/"], start_after="c/m",
                           watched_keys=watched, lazy=True)

    cut = collector()
    listing = cut.collect()
    assert next(listing).resource.location == "c/n-kept"
    listing.close()  # a listing cut short names nothing
    assert cut.missing_after_start == set()
    whole = collector()
    assert [obj.resource.location for obj in whole.collect()] == ["c/n-kept"]
    assert whole.missing_after_start == {"c/z-gone"} and not whole.listing_complete


def test_an_event_during_an_active_scan_is_durable_then_runs_after_it(setup, monkeypatch):
    from types import SimpleNamespace

    from cremore.db import repository, sql, task_store
    from cremore.scanning.triggers import enqueue_event

    repo, conn, catalog, profile, bucket, worker = setup
    now = {"value": dt.datetime.now(dt.UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    monkeypatch.setattr(repository, "_now", lambda: now["value"])
    monkeypatch.setattr(sql, "_now", lambda: now["value"])
    repo.update_scope_profile(
        profile.id, event_mode="ENABLED", approved_at=now["value"], approved_by="admin"
    )

    def event(index, key):
        return enqueue_event(repo, SimpleNamespace(), profile.id,
                             {"event_id": str(index), "resource_id": catalog.items[0]["id"], "keys": [key]},
                             now=now["value"])

    first, _ = event(0, "config/a")
    now["value"] += dt.timedelta(milliseconds=1)
    second, created = event(1, "config/b")
    assert created and second.id != first.id
    for _ in range(12):
        now["value"] += dt.timedelta(seconds=6)
        worker.process_next()
        if repo.get_job(first.id).status not in ("QUEUED", "RUNNING"):
            break
    assert repo.get_job(first.id).status == "SUCCEEDED" and bucket.reads == ["config/a"]
    replay, created = event(1, "config/b")
    assert not created and replay.id == second.id
    for _ in range(12):
        now["value"] += dt.timedelta(seconds=6)
        worker.process_next()
        if repo.get_job(second.id).status not in ("QUEUED", "RUNNING"):
            break
    assert repo.get_job(second.id).status == "SUCCEEDED"
    assert sorted(bucket.reads) == ["config/a", "config/b"]
    root = split_roots(scope.build_plan(profile, catalog, auth=profile.auth_revision, enabled=True).roots)[0]
    assert not ScanStore(repo).root(root_identity(conn.id, root)).get("watermark")


def test_failure_overflow_survives_later_success_and_forces_full_recovery(setup, monkeypatch):
    from cremore.worker import runtime

    repo, conn, _, _, bucket, _ = setup
    baseline, plan = enqueue(setup)
    assert finish(setup, baseline).status == "SUCCEEDED"
    identity = root_identity(conn.id, split_roots(plan.roots)[0])
    original = ScanStore(repo).root(identity)["watermark"]
    monkeypatch.setattr(runtime, "FAILURE_KEY_LIMIT", 1)
    bucket.objects = {"config/a": b"unreadable", "config/b": b"unreadable", "config/z": b"clean"}
    bucket.fail.update({"config/a", "config/b"})
    bucket.modified = {k: dt.datetime.now(dt.UTC) for k in bucket.objects}
    delta, _ = enqueue(setup, "DELTA")
    assert finish(setup, delta).status == "SUCCEEDED"
    state = ScanStore(repo).root(identity)
    assert state["retry_overflow"] and state["watermark"] == original
    public = scope.run_public(repo.get_job(delta.id), "source", conn.id)
    assert public["status"] == "PARTIAL" and public["root_coverage_complete"] is False
    assert public.get("coverage_basis") != "INVENTORY_REPORT_ONLY"
    assert public["failed"] == 2 and public["timings"]
    # Even if the next overlap no longer contains b, overflow forces BASELINE.
    bucket.modified = {k: dt.datetime(2020, 1, 1, tzinfo=dt.UTC) for k in bucket.objects}
    bucket.fail.clear()
    bucket.reads.clear()
    recover, _ = enqueue(setup, "DELTA")
    assert finish(setup, recover).status == "SUCCEEDED"
    assert "config/b" in bucket.reads
    assert not ScanStore(repo).root(identity)["retry_overflow"]


def test_crash_cursor_is_invalidated_when_detection_policy_changes(setup, monkeypatch):
    import uuid

    from cremore.db import task_store
    from cremore.domain.models import CustomRule

    class PowerLoss(BaseException):
        pass

    repo, conn, _, _, bucket, worker = setup
    baseline, plan = enqueue(setup)
    assert finish(setup, baseline).status == "SUCCEEDED"
    now = {"value": dt.datetime.now(dt.UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    get = bucket.get_object

    def crash_on_b(**kwargs):
        if kwargs["Key"] == "config/b":
            raise PowerLoss()
        return get(**kwargs)

    monkeypatch.setattr(bucket, "get_object", crash_on_b)
    # An unchanged object is answered from the cache; a changed one must be read.
    bucket.objects["config/b"] = b"changed, still no credential"
    reconcile, _ = enqueue(setup, "RECONCILE")
    assert worker.process_next()
    with pytest.raises(PowerLoss):
        worker.process_next()
    root_task = next(
        t for t in worker.runtime.tasks.list_for_run(reconcile.id) if t["kind"] != "PLAN"
    )
    assert root_task["checkpoint"]["last_key"] == "config/a"
    monkeypatch.setattr(bucket, "get_object", get)
    rule = CustomRule(id=uuid.uuid4(), name="new policy", pattern=TOKEN)
    worker.orchestrator.rule_provider = lambda: [rule]
    now["value"] += dt.timedelta(seconds=121)
    bucket.reads.clear()
    assert finish(setup, reconcile).status == "SUCCEEDED"
    assert "config/a" in bucket.reads
    identity = root_identity(conn.id, split_roots(plan.roots)[0])
    assert (
        ScanStore(repo).root(identity)["detection_digest"]
        == worker.orchestrator.detection_policy_digest
    )


def test_disjoint_splits_keep_only_approved_boundaries():
    roots = split_roots(
        [
            {
                "resource_type": "S3_BUCKET",
                "provider_resource_id": "b",
                "prefixes": ["a/", "a/x/", "b/"],
            },
            {
                "resource_type": "NOTION_PAGE",
                "provider_resource_id": "p",
                "page_mode": "PAGE_ONLY",
                "descendant_ids": ["child"],
            },
        ]
    )
    assert [r.get("prefixes") for r in roots[:2]] == [["a/"], ["b/"]]
    assert roots[2]["exact_page_ids"] == ["p"]


def test_a_root_read_to_the_end_forgets_where_it_resumed(setup, monkeypatch):
    """A resume point that is never cleared is worse than none: every later scan
    of that bucket would start past it and the objects before it would never be
    read again, silently, while the run reported success."""

    from cremore.db import task_store
    from cremore.db.scan_store import ScanStore

    repo, conn, catalog, profile, bucket, worker = setup
    bucket.objects = {f"obj/{i:03d}": b"no credential" for i in range(20)}
    bucket.modified = {k: dt.datetime(2020, 1, 1, tzinfo=dt.UTC) for k in bucket.objects}
    item_id = profile.selected_roots[0]["resource_id"]
    tight = repo.update_scope_profile(profile.id, selected_roots=[
        {"resource_id": item_id, "prefixes": ["obj/"], "all_current_objects": False,
         "include_future_descendants": False}], budgets={"requests": 6, "bytes": 100000, "seconds": 60})
    now = {"value": dt.datetime.now(dt.UTC)}
    real_clock = task_store._clock
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"] if conn is None else real_clock(conn) + (now["value"] - dt.datetime.now(dt.UTC)))

    def one_run(current):
        job, _ = enqueue((repo, conn, catalog, current, bucket, worker))
        for _ in range(40):
            worker.process_next()
            now["value"] += dt.timedelta(seconds=30)
            if repo.get_job(job.id).status not in ("QUEUED", "RUNNING"):
                break
        return repo.get_job(job.id)

    def resume_points():
        return [state.get("resume_after") for state in ScanStore(repo).all_roots()] \
            if hasattr(ScanStore(repo), "all_roots") else None

    one_run(tight)
    # Enough budget to read what is left and reach the end of the listing.
    roomy = repo.update_scope_profile(tight.id, budgets={"requests": 10000, "bytes": 1000000, "seconds": 600})
    for _ in range(6):
        finished = one_run(roomy)
        if not (finished.coverage or {}).get("stopped_reason"):
            break
    assert not (finished.coverage or {}).get("stopped_reason"), finished.coverage

    # The next run must read the bucket from the beginning, not from where a
    # long-finished budget stop happened to leave off. Changed objects are read
    # again rather than answered from the cache.
    bucket.modified = {k: dt.datetime(2021, 1, 1, tzinfo=dt.UTC) for k in bucket.objects}
    bucket.reads = []
    one_run(roomy)
    assert min(bucket.reads) == min(bucket.objects), sorted(bucket.reads)[:3]


def test_the_run_after_a_budget_stop_starts_where_the_last_one_reached(setup, monkeypatch):
    """A scope bigger than one budget is only scannable if the next run carries
    on. The task checkpoint dies with its run, so the key a root reached is kept
    on the root's own state; without it every run re-reads the same first pages
    and the rest of a large bucket is never seen."""

    from cremore.db import task_store

    repo, conn, catalog, profile, bucket, worker = setup
    bucket.objects = {f"obj/{i:03d}": b"no credential" for i in range(30)}
    bucket.modified = {k: dt.datetime(2020, 1, 1, tzinfo=dt.UTC) for k in bucket.objects}
    item_id = profile.selected_roots[0]["resource_id"]
    profile = repo.update_scope_profile(profile.id, selected_roots=[
        {"resource_id": item_id, "prefixes": ["obj/"], "all_current_objects": False,
         "include_future_descendants": False}], budgets={"requests": 8, "bytes": 100000, "seconds": 60})
    now = {"value": dt.datetime.now(dt.UTC)}
    real_clock = task_store._clock
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"] if conn is None else real_clock(conn) + (now["value"] - dt.datetime.now(dt.UTC)))

    def one_run():
        job, _ = enqueue((repo, conn, catalog, profile, bucket, worker))
        for _ in range(40):
            worker.process_next()
            now["value"] += dt.timedelta(seconds=30)
            if repo.get_job(job.id).status not in ("QUEUED", "RUNNING"):
                break
        return repo.get_job(job.id)

    bucket.reads = []
    first = one_run()
    read_first = sorted(bucket.reads)
    assert read_first, "the first run read part of the bucket"
    assert first.status != "FAILED"

    bucket.reads = []
    second = one_run()
    read_second = sorted(bucket.reads)
    assert second.status != "FAILED"
    assert read_second, "the second run read something"
    # It carried on rather than re-reading the same keys from the start.
    assert min(read_second) > max(read_first), (read_first, read_second)


@pytest.mark.parametrize("cursor_policy", [None, "previous-policy"])
def test_cross_run_cursor_requires_evidence_of_the_current_detection_policy(setup, cursor_policy):
    repo, conn, _, _, bucket, worker = setup
    job, plan = enqueue(setup)
    identity = root_identity(conn.id, split_roots(plan.roots)[0])
    store = ScanStore(repo)
    # A completed watermark can describe an older full pass. Only the cursor's
    # own evidence may authorize skipping a prefix in this pass.
    store.save_root(identity, conn.id, {
        "resume_after": "config/a", "resume_detection_digest": cursor_policy,
        "detection_digest": worker.orchestrator.detection_policy_digest,
    })
    assert finish(setup, job).status == "SUCCEEDED"
    assert "config/a" in bucket.reads
    assert "resume_after" not in store.root(identity)
    assert "resume_detection_digest" not in store.root(identity)


def test_budget_stop_retains_failed_prefix_keys_and_committed_counts(setup):
    repo, conn, catalog, profile, bucket, worker = setup
    bucket.objects["config/c"] = b"no credential"
    bucket.modified["config/c"] = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
    bucket.fail.add("config/a")
    profile = repo.update_scope_profile(profile.id, budgets={"requests": 3, "bytes": 10000, "seconds": 30})
    updated = (repo, conn, catalog, profile, bucket, worker)
    job, plan = enqueue(updated)
    first = finish(updated, job)
    state = root_state(updated, plan)
    assert first.coverage["stopped_reason"] == "BUDGET_REQUESTS"
    assert first.objects == 1 and first.coverage["requests"] == 3
    assert state["resume_after"] == "config/b" and state["failed_keys"] == ["config/a"]
    assert state["resume_detection_digest"] == worker.orchestrator.detection_policy_digest
    assert first.coverage["engine_name"] and first.coverage["engine_version"]
    bucket.fail.clear()
    bucket.reads.clear()
    next_job, _ = enqueue(updated)
    finish(updated, next_job)
    assert set(bucket.reads) == {"config/a", "config/c"}
    assert root_state(updated, plan)["failed_keys"] == []


def test_a_scope_that_spends_its_request_budget_stops_and_is_resumable_not_failed(setup, monkeypatch):
    """Running out of provider requests means part of the scope was read, not
    that the scan broke. The run has to end stopped, with the key it reached kept
    so the next run resumes there -- a demo that reports FAILED and zero findings
    because a bucket held more objects than the budget is the worst outcome."""

    from cremore.db import task_store
    from cremore.db.task_store import TaskStore

    repo, conn, catalog, profile, bucket, worker = setup
    bucket.objects = {f"obj/{i:03d}": b"no credential" for i in range(30)}
    bucket.modified = {k: dt.datetime(2020, 1, 1, tzinfo=dt.UTC) for k in bucket.objects}
    item_id = profile.selected_roots[0]["resource_id"]
    # One root, and fewer requests than the objects it has to read.
    profile = repo.update_scope_profile(profile.id, selected_roots=[
        {"resource_id": item_id, "prefixes": ["obj/"], "all_current_objects": False,
         "include_future_descendants": False}], budgets={"requests": 8, "bytes": 100000, "seconds": 60})
    now = {"value": dt.datetime.now(dt.UTC)}
    real_clock = task_store._clock
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"] if conn is None else real_clock(conn) + (now["value"] - dt.datetime.now(dt.UTC)))
    job, _ = enqueue((repo, conn, catalog, profile, bucket, worker))
    for _ in range(40):
        worker.process_next()
        now["value"] += dt.timedelta(seconds=30)
        if repo.get_job(job.id).status not in ("QUEUED", "RUNNING"):
            break

    done = repo.get_job(job.id)
    assert done.status != "FAILED", f"a spent budget is not a failure: {done.error}"
    roots = [t for t in TaskStore(repo).list_for_run(job.id) if t["kind"] != "PLAN"]
    assert roots and all(t["status"] != "FAILED" for t in roots), [(t["status"], t["error"]) for t in roots]
    assert any((t.get("result") or {}).get("stopped_reason") == "BUDGET_REQUESTS" for t in roots), \
        [t.get("result") for t in roots]
    # It read some of the bucket, and not all of it.
    assert 0 < len(bucket.reads) < len(bucket.objects)


def test_a_root_that_outgrows_its_share_uses_what_sibling_roots_left_unused(setup, monkeypatch):
    from cremore.db import task_store
    from cremore.db.task_store import TaskStore

    repo, conn, catalog, profile, bucket, worker = setup
    bucket.objects = {**{f"big/{i}": b"no credential" for i in range(6)}, "small/a": b"no credential"}
    bucket.modified = {k: dt.datetime(2020, 1, 1, tzinfo=dt.UTC) for k in bucket.objects}
    item_id = profile.selected_roots[0]["resource_id"]
    # two roots of one run: shares are fixed halves of 12 requests, but "big/" needs more than 6
    profile = repo.update_scope_profile(profile.id, selected_roots=[
        {"resource_id": item_id, "prefixes": ["big/", "small/"], "all_current_objects": False,
         "include_future_descendants": False}], budgets={"requests": 12, "bytes": 10000, "seconds": 30})
    now = {"value": dt.datetime.now(dt.UTC)}
    real_clock = task_store._clock
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"] if conn is None else real_clock(conn) + (now["value"] - dt.datetime.now(dt.UTC)))
    job, _ = enqueue((repo, conn, catalog, profile, bucket, worker))
    for _ in range(40):
        worker.process_next()
        now["value"] += dt.timedelta(seconds=30)
        if repo.get_job(job.id).status not in ("QUEUED", "RUNNING"):
            break
    done = repo.get_job(job.id)
    tasks = [t for t in TaskStore(repo).list_for_run(job.id) if t["kind"] != "PLAN"]
    assert len(tasks) == 2 and all(t["status"] == "SUCCEEDED" for t in tasks), [(t["status"], t["error"]) for t in tasks]
    assert sorted(bucket.reads) == sorted(bucket.objects)
    # the run total is unchanged: shares were moved, never added
    assert sum(int(t["payload"]["budgets"]["requests"]) for t in tasks) == 12
    assert done.status == "SUCCEEDED"


ZIP = b"PK\x03\x04" + TOKEN.encode()
PNG = b"\x89PNG\r\n\x1a\n" + TOKEN.encode()
OLD = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)


def put(bucket, **objects):
    for name, data in objects.items():
        bucket.objects[f"config/{name}"] = data
        bucket.modified[f"config/{name}"] = OLD


def root_state(setup, plan):
    repo, conn = setup[0], setup[1]
    return ScanStore(repo).root(root_identity(conn.id, split_roots(plan.roots)[0]))


def test_format_skips_are_reported_gaps_that_never_hold_back_the_watermark(setup):
    _repo, conn, _, _, bucket, worker = setup
    put(bucket, c=ZIP, d=PNG)
    job, plan = enqueue(setup)
    done = finish(setup, job)
    state = root_state(setup, plan)
    assert done.objects_failed == 0 and state["failed_keys"] == []
    # Reading the same bytes again cannot change a skip, so the root still advances.
    assert state["watermark"] and state["last_reconcile"]
    assert [key for key, _ in state["inspection_gaps"]] == ["config/c", "config/d"]
    public = scope.run_public(done, "source", conn.id)
    assert public["status"] == "PARTIAL" and public["skipped_unsupported"] == 1 and public["skipped_media"] == 1
    assert public["root_coverage_complete"] is False
    assert public["failure_basis"] == scope.FAILURE_BASIS
    assert done.coverage["detection_policy_digest"] == worker.orchestrator.detection_policy_digest


def test_a_retry_key_that_turns_out_to_be_a_format_skip_leaves_the_retry_list(setup):
    _, _, _, _, bucket, _ = setup
    bucket.fail.add("config/b")
    first, plan = enqueue(setup)
    finish(setup, first)
    assert root_state(setup, plan)["failed_keys"] == ["config/b"] and not root_state(setup, plan).get("watermark")
    bucket.fail.clear()
    put(bucket, b=ZIP)
    second, _ = enqueue(setup)
    finish(setup, second)
    state = root_state(setup, plan)
    assert state["failed_keys"] == [] and state["watermark"]
    assert [key for key, _ in state["inspection_gaps"]] == ["config/b"]


def test_two_format_skips_and_one_failure_stay_partial_and_are_counted_apart(setup):
    _, conn, _, _, bucket, _ = setup
    put(bucket, c=ZIP, d=ZIP, e=b"denied")
    bucket.fail.add("config/e")
    job, plan = enqueue(setup)
    public = scope.run_public(finish(setup, job), "source", conn.id)
    assert public["status"] == "PARTIAL" and public["failed"] == 1 and public["skipped_unsupported"] == 2
    state = root_state(setup, plan)
    assert state["failed_keys"] == ["config/e"] and not state.get("watermark")


@pytest.mark.parametrize("replacement", [ZIP, PNG])
def test_an_exposure_whose_object_became_a_format_skip_is_kept(setup, replacement):
    repo, conn, _, _, bucket, _ = setup
    baseline, plan = enqueue(setup)
    finish(setup, baseline)
    watermark = root_state(setup, plan)["watermark"]
    [exposure] = repo.exposures_for_connection(conn.id)
    bucket.objects["config/a"] = replacement
    bucket.modified["config/a"] = dt.datetime.now(dt.UTC)
    for index, mode in enumerate(("DELTA", "DELTA", "BASELINE")):
        bucket.reads.clear()
        job, _ = enqueue(setup, mode)
        done = finish(setup, job)
        # The skipped object stays a reported gap of the root on every run...
        assert done.status == "SUCCEEDED" and scope.job_is_partial(done)
        assert [key for key, _ in root_state(setup, plan)["inspection_gaps"]] == ["config/a"]
        # ...while the root advances, and the same revision is not read again.
        assert root_state(setup, plan)["watermark"] != watermark
        assert ("config/a" in bucket.reads) == (index == 0), mode
        [kept] = [e for e in repo.exposures_for_connection(conn.id) if e.id == exposure.id]
        assert kept.status != "REMOVED", mode
    assert not repo.list_findings()[0].all_locations_removed


def test_a_resumed_root_keeps_format_skip_bytes_cursor_and_totals(setup, monkeypatch):
    from cremore.db import task_store

    class PowerLoss(BaseException):
        pass

    _, _, _, _, bucket, worker = setup
    bucket.objects, bucket.modified = {}, {}
    put(bucket, a=ZIP, b=TOKEN.encode())
    now = {"value": dt.datetime.now(dt.UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    get = bucket.get_object

    def crash_on_b(**kwargs):
        if kwargs["Key"] == "config/b":
            raise PowerLoss()
        return get(**kwargs)

    monkeypatch.setattr(bucket, "get_object", crash_on_b)
    job, plan = enqueue(setup)
    assert worker.process_next()
    with pytest.raises(PowerLoss):
        worker.process_next()
    root_task = next(t for t in worker.runtime.tasks.list_for_run(job.id) if t["kind"] != "PLAN")
    checkpoint = root_task["checkpoint"]
    assert checkpoint["last_key"] == "config/a" and checkpoint["skipped_unsupported"] == 1
    assert checkpoint["bytes"] == len(ZIP) and not checkpoint.get("failed_keys")
    monkeypatch.setattr(bucket, "get_object", get)
    now["value"] += dt.timedelta(seconds=121)
    bucket.reads.clear()
    done = finish(setup, job)
    assert bucket.reads == ["config/b"]  # the skipped object is neither re-read nor re-counted
    assert done.coverage["skipped_unsupported"] == 1 and done.coverage["bytes"] == len(ZIP) + len(TOKEN)
    state = root_state(setup, plan)
    assert state["watermark"] and [key for key, _ in state["inspection_gaps"]] == ["config/a"]
    assert scope.job_is_partial(done)


def test_a_format_skip_spends_the_byte_budget(setup):
    repo, conn, catalog, profile, bucket, worker = setup
    profile = repo.update_scope_profile(profile.id, budgets={"requests": 20, "bytes": len(ZIP) + 4, "seconds": 30})
    bucket.objects, bucket.modified = {}, {}
    put(bucket, a=ZIP, b=ZIP)
    job, plan = enqueue((repo, conn, catalog, profile, bucket, worker))
    done = finish((repo, conn, catalog, profile, bucket, worker), job)
    # a used the budget, so b no longer fits and is not read as another free skip.
    assert bucket.reads == ["config/a"] and done.coverage["bytes"] == len(ZIP)
    assert not root_state((repo, conn, catalog, profile, bucket, worker), plan).get("watermark")


def test_a_running_scope_scan_stops_on_request_and_a_new_scan_can_start(setup, monkeypatch):
    from cremore.db import task_store

    repo, _conn, _catalog, _profile, bucket, worker = setup
    now = {"value": dt.datetime.now(dt.UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    job, _plan = enqueue(setup)
    assert worker.process_next()  # the plan task enumerates the root
    assert repo.request_job_cancel(job.id).status == "CANCELLING"
    restarted, _ = enqueue(setup)
    assert worker.runtime.tasks.seed_next_job() is None
    worker.process_next()
    assert repo.get_job(job.id).status == "CANCELLED" and bucket.reads == []
    assert finish(setup, restarted).status == "SUCCEEDED"
    assert sorted(bucket.reads) == ["config/a", "config/b"]


def test_a_connection_scan_stopped_mid_run_saves_nothing_after_the_request(setup, monkeypatch):
    from cremore.collectors.base import CollectedObject
    from cremore.detection import ResourceRef

    repo, conn, _catalog, _profile, _bucket, _worker = setup
    job_holder = {}

    class Stops:
        failed_objects = 0
        authoritative_listing = True

        def collect(self):
            yield CollectedObject(ResourceRef(source_type="github", resource="o/r", location="a.py",
                                              metadata={"exposure": "internal"}), TOKEN.encode())
            # An operator stops the scan while the next object is being read.
            repo.request_job_cancel(job_holder["job"].id)
            yield CollectedObject(ResourceRef(source_type="github", resource="o/r", location="b.py",
                                              metadata={"exposure": "internal"}), TOKEN.encode()[:-1] + b"Z")

    worker = JobWorker(repo, collector_factory=lambda job: Stops())
    job_holder["job"] = repo.enqueue_job(ScanJob(kind="github", payload={}, connection_id=conn.id))
    for _ in range(3):
        worker.process_next()
    done = repo.get_job(job_holder["job"].id)
    assert done.status == "CANCELLED"
    # a.py was committed before the request; b.py's write was refused.
    assert {e.location for e in repo.exposures_for_connection(conn.id)} == {"a.py"}
    assert repo.active_content_job() is None


OLDER_POLICY = "0" * 64


def upgraded(setup, changed):
    """The root as an upgrade leaves it: read whole a day ago under an older detection policy, and the ``changed``
    objects written since, an hour ago. Its identity, and when it was read."""
    repo, conn, catalog, profile, bucket, _ = setup
    now = dt.datetime.now(dt.UTC)
    for key, data in changed.items():
        bucket.objects[key], bucket.modified[key] = data, now - dt.timedelta(hours=1)
    identity = root_identity(conn.id, split_roots(scope.build_plan(
        profile, catalog, auth=profile.auth_revision, enabled=True).roots)[0])
    read = (now - dt.timedelta(days=1)).isoformat()
    ScanStore(repo).save_root(identity, conn.id, {"watermark": read, "last_reconcile": read,
                                                  "detection_digest": OLDER_POLICY})
    return identity, read


def root_result(repo, job):
    [task] = [task for task in TaskStore(repo).list_for_run(job.id) if task["kind"] != "PLAN"]
    return task["result"]


@pytest.mark.parametrize("full_mode", ["RECONCILE", "POLICY_SWEEP"])
def test_a_held_delta_reads_what_changed_and_never_certifies_the_new_policy(setup, full_mode):
    repo, conn, _, _, bucket, worker = setup
    identity, read = upgraded(setup, {"config/c": TOKEN.encode()})
    store = ScanStore(repo)
    job, _ = enqueue(setup, "DELTA", trigger="SCHEDULE", policy_hold=True)
    done = finish(setup, job)
    # Only what changed since the watermark is read, under the current policy, and what it holds is found.
    assert done.status == "SUCCEEDED" and bucket.reads == ["config/c"]
    assert [e.location for e in repo.exposures_for_connection(conn.id)] == ["config/c"]
    state = store.root(identity)
    assert state["detection_digest"] == OLDER_POLICY and state["last_reconcile"] == read and state["watermark"] > read
    assert root_result(repo, job)["policy_held"] == 1 and done.coverage["root_coverage_complete"] is False
    public = scope.run_public(done, "source", conn.id)
    assert (public["status"], public["policy_held_roots"], public["policy_held_only"]) == ("PARTIAL", 1, True)
    # The next held DELTA reads only what changed since this one.
    bucket.objects["config/d"], bucket.modified["config/d"] = b"no credential", dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)
    bucket.reads.clear()
    again, _ = enqueue(setup, "DELTA", trigger="SCHEDULE", policy_hold=True)
    assert finish(setup, again).status == "SUCCEEDED" and bucket.reads == ["config/d"]
    # A full scan or a policy sweep still reads the whole root: the cache answers for what the held runs read.
    bucket.reads.clear()
    full, _ = enqueue(setup, full_mode, trigger="SCHEDULE" if full_mode == "RECONCILE" else full_mode)
    assert finish(setup, full).status == "SUCCEEDED" and sorted(bucket.reads) == ["config/a", "config/b"]
    assert sorted(e.location for e in repo.exposures_for_connection(conn.id)) == ["config/a", "config/c"]
    state = store.root(identity)
    assert state["detection_digest"] == worker.orchestrator.detection_policy_digest and state["last_reconcile"] > read


@pytest.mark.parametrize("trigger", ["SCHEDULE", "EVENT"])
def test_without_the_hold_a_change_run_reads_a_root_read_under_an_older_policy_whole(setup, trigger):
    repo, _, _, _, bucket, worker = setup
    identity, _ = upgraded(setup, {"config/c": TOKEN.encode()})
    job, _ = enqueue(setup, "DELTA", trigger=trigger)
    assert finish(setup, job).status == "SUCCEEDED"
    assert sorted(bucket.reads) == ["config/a", "config/b", "config/c"] and "policy_held" not in root_result(repo, job)
    if trigger == "SCHEDULE":
        assert ScanStore(repo).root(identity)["detection_digest"] == worker.orchestrator.detection_policy_digest


def test_a_held_change_feed_asking_for_its_root_reads_only_what_changed(setup):
    repo, _, _, _, bucket, _ = setup
    identity, _ = upgraded(setup, {"config/c": TOKEN.encode()})
    before = ScanStore(repo).root(identity)
    job, _ = enqueue(setup, "DELTA", trigger="EVENT", policy_hold=True)
    assert finish(setup, job).status == "SUCCEEDED" and bucket.reads == ["config/c"]
    state = ScanStore(repo).root(identity)
    assert (state["watermark"], state["detection_digest"]) == (before["watermark"], OLDER_POLICY)
    assert root_result(repo, job)["policy_held"] == 1


def test_a_held_delta_stopped_by_its_budget_leaves_no_cursor_for_the_full_scan(setup):
    repo, conn, catalog, profile, bucket, worker = setup
    # config/a is unchanged since the older policy read it: the held DELTA does not read it.
    identity, read = upgraded(setup, {f"config/{key}": b"no credential" for key in "bcd"})
    tight = (repo, conn, catalog, repo.update_scope_profile(profile.id, budgets={
        "requests": 3, "bytes": 10000, "seconds": 30}), bucket, worker)
    job, _ = enqueue(tight, "DELTA", trigger="SCHEDULE", policy_hold=True)
    stopped = finish(tight, job)
    assert stopped.coverage["stopped_reason"] == "BUDGET_REQUESTS" and sorted(bucket.reads) == ["config/b", "config/c"]
    state = ScanStore(repo).root(identity)
    assert "resume_after" not in state and (state["watermark"], state["detection_digest"]) == (read, OLDER_POLICY)
    assert root_result(repo, job)["policy_held"] == 1
    # The full scan reads the root from its start, config/a too.
    bucket.reads.clear()
    roomy = (repo, conn, catalog, repo.update_scope_profile(profile.id, budgets={
        "requests": 100, "bytes": 10000, "seconds": 30}), bucket, worker)
    full, _ = enqueue(roomy, "RECONCILE", trigger="SCHEDULE")
    assert finish(roomy, full).status == "SUCCEEDED" and sorted(bucket.reads) == ["config/a", "config/d"]
    assert ScanStore(repo).root(identity)["detection_digest"] == worker.orchestrator.detection_policy_digest


def test_a_held_delta_is_not_turned_into_a_reconcile_by_the_age_of_the_last_one(setup):
    repo, _, _, _, bucket, _ = setup
    upgraded(setup, {"config/c": TOKEN.encode()})  # its last whole read was a day ago
    job, _ = enqueue(setup, "DELTA", trigger="SCHEDULE", policy_hold=True, reconcile_if_older_than_seconds=3600)
    assert finish(setup, job).status == "SUCCEEDED" and bucket.reads == ["config/c"]
    assert root_result(repo, job)["policy_held"] == 1


def test_a_held_delta_neither_resumes_from_nor_moves_the_cursor_of_a_stopped_full_scan(setup):
    repo, conn, _, _, bucket, worker = setup
    identity, _ = upgraded(setup, {"config/b": b"changed since"})
    # The first full scan under the current policy stopped after config/b: the cursor names what it read.
    cursor = {"resume_after": "config/b", "resume_detection_digest": worker.orchestrator.detection_policy_digest}
    ScanStore(repo).save_root(identity, conn.id, {**ScanStore(repo).root(identity), **cursor})
    job, _ = enqueue(setup, "DELTA", trigger="SCHEDULE", policy_hold=True)
    assert finish(setup, job).status == "SUCCEEDED" and bucket.reads == ["config/b"]
    state = ScanStore(repo).root(identity)
    assert {k: state.get(k) for k in cursor} == cursor and state["detection_digest"] == OLDER_POLICY


@pytest.fixture(params=["memory", "sql"])
def github(request):
    """One approved GitHub repository path, read through the provider's mock API (github_test.MockGitHub)."""
    from cremore_github_provider.collectors.github_test import MockGitHub

    repo = repository(request.param)
    conn = repo.create_connection(Connection(provider="github", name="fixture", config={"owner": "o", "repo": "r"}))
    item = scope.resource("source", conn.id, "GITHUB_REPOSITORY", "o/r", "o/r", "https://github.com/o/r", "github.com")
    auth = scope.auth_revision("source", conn)
    catalog = repo.save_catalog(ScopeCatalog(kind="source", connection_id=conn.id, snapshot_id="v1",
                                             auth_revision=auth, items=[item], completeness="COMPLETE"))
    profile = repo.create_scope_profile(ScopeProfile(
        kind="source", connection_id=conn.id, name="approved", state="READY", auth_revision=auth,
        catalog_snapshot_id="v1", budgets={"requests": 100, "bytes": 100000, "seconds": 60},
        selected_roots=[{"resource_id": item["id"], "paths": ["src/"], "ref": "refs/heads/main",
                         "all_current_objects": False, "include_future_descendants": False}]))
    fake = MockGitHub({"src/a.txt": b"alpha", "src/b.txt": b"beta", "src/c.txt": b"gamma"})
    worker = JobWorker(repo, collector_factory=lambda job: build_collector(
        job.model_copy(update={"payload": {**job.payload, "token": "synthetic"}}), http_client_factory=lambda: fake.client))
    return repo, conn, catalog, profile, fake, worker


def test_a_held_change_run_of_a_cached_root_downloads_nothing_and_a_change_feed_still_reads_its_paths(github):
    from cremore_github_provider.collectors.github_test import _sha

    repo, conn, catalog, profile, fake, worker = github
    identity = root_identity(conn.id, split_roots(scope.build_plan(
        profile, catalog, auth=profile.auth_revision, enabled=True).roots)[0])
    stale = {"watermark": (dt.datetime.now(dt.UTC) - dt.timedelta(days=1)).isoformat(), "detection_digest": OLDER_POLICY}
    ScanStore(repo).save_root(identity, conn.id, stale)

    def blobs():
        return sorted(r.url.path.rsplit("/", 1)[1] for r in fake.requests if "/git/blobs/" in r.url.path)

    # A DELTA slot, and a change feed asking for the root: under the hold neither lists or downloads anything.
    for trigger in ("SCHEDULE", "EVENT"):
        job, _ = enqueue(github, "DELTA", trigger=trigger, policy_hold=True)
        done = finish(github, job)
        result = root_result(repo, job)
        assert done.status == "SUCCEEDED" and fake.requests == []
        assert (result["objects"], result["policy_held"], result["root_coverage_complete"]) == (0, 1, False)
        assert done.coverage["root_coverage_complete"] is False
    assert ScanStore(repo).root(identity) == stale
    # The paths a change feed names are read, under the current policy.
    event, _ = enqueue(github, "EVENT", exact_keys=["src/b.txt"], trigger="EVENT", policy_hold=True)
    assert finish(github, event).status == "SUCCEEDED" and blobs() == [_sha(b"beta")]
    # Without the hold the same DELTA reads the root whole, as before: only what the change feed read is cached.
    fake.requests.clear()
    delta, _ = enqueue(github, "DELTA", trigger="SCHEDULE")
    assert finish(github, delta).status == "SUCCEEDED" and blobs() == sorted([_sha(b"alpha"), _sha(b"gamma")])
    assert ScanStore(repo).root(identity)["detection_digest"] == worker.orchestrator.detection_policy_digest


def test_a_held_cached_root_with_earlier_failures_reports_them_and_is_not_partial_only_for_the_hold(github):
    """An unread held root does not read its failed keys again: the run says they are still not read."""
    repo, conn, catalog, profile, fake, _worker = github
    identity = root_identity(conn.id, split_roots(scope.build_plan(
        profile, catalog, auth=profile.auth_revision, enabled=True).roots)[0])
    ScanStore(repo).save_root(identity, conn.id, {"watermark": (dt.datetime.now(dt.UTC) - dt.timedelta(days=1)).isoformat(),
                                                  "detection_digest": OLDER_POLICY, "failed_keys": ["src/a.txt"]})
    job, _ = enqueue(github, "DELTA", trigger="SCHEDULE", policy_hold=True)
    done = finish(github, job)
    assert done.status == "SUCCEEDED" and fake.requests == []
    assert (root_result(repo, job)["failed"], done.objects_failed, done.coverage["policy_held"]) == (1, 1, 1)
    assert "policy_held_only" not in done.coverage and scope.job_is_partial(done)
    assert ScanStore(repo).root(identity)["failed_keys"] == ["src/a.txt"]


class PowerLoss(BaseException):
    """The worker process dies where it is."""


def test_a_held_attempt_after_a_crash_reports_the_failures_an_earlier_attempt_committed(github, monkeypatch):
    """Attempt 1 is not held, commits a failed read and dies before the root is finalized; the policy changes, and the
    resumed attempt is held and reads nothing. The failure its checkpoint holds is still reported."""
    import httpx
    from cremore_github_provider.collectors.github_test import _sha

    from cremore.db import task_store
    from cremore.scanning.orchestrator import Orchestrator
    from cremore.worker import runtime

    repo, conn, catalog, profile, fake, worker = github
    identity = root_identity(conn.id, split_roots(scope.build_plan(
        profile, catalog, auth=profile.auth_revision, enabled=True).roots)[0])
    ScanStore(repo).save_root(identity, conn.id, {"watermark": (dt.datetime.now(dt.UTC) - dt.timedelta(days=1)).isoformat(),
                                                  "detection_digest": worker.orchestrator.detection_policy_digest})
    denied = _sha(b"alpha")
    served = fake.handle
    fake.client = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(403) if request.url.path.endswith("/git/blobs/" + denied) else served(request)))

    scans = runtime.ScanService

    class Dies(scans):
        def run(self, *args, **kwargs):
            super().run(*args, **kwargs)  # every object, src/a.txt's failure too, is committed
            raise PowerLoss()

    monkeypatch.setattr(runtime, "ScanService", Dies)
    job, _ = enqueue(github, "DELTA", trigger="SCHEDULE", policy_hold=True)
    assert worker.process_next()  # its plan
    with pytest.raises(PowerLoss):
        worker.process_next()  # the root's current policy: not held, it reads, then dies
    [task] = [t for t in TaskStore(repo).list_for_run(job.id) if t["kind"] != "PLAN"]
    assert task["checkpoint"]["failed_keys"] == ["src/a.txt"] and not ScanStore(repo).root(identity).get("failed_keys")
    monkeypatch.setattr(runtime, "ScanService", scans)
    monkeypatch.setattr(Orchestrator, "detection_policy_digest", property(lambda self: "f" * 64))  # the rules changed
    real_clock = task_store._clock
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: real_clock(conn) + dt.timedelta(seconds=121))
    fake.requests.clear()
    done = finish(github, job)
    result = root_result(repo, job)
    # The resumed attempt is held and reads nothing, yet the failure stays reported: the run is not partial only for the hold.
    assert done.status == "SUCCEEDED" and fake.requests == [] and result["policy_held"] == 1
    assert (result["failed"], done.objects_failed) == (1, 1)
    assert "policy_held_only" not in done.coverage and scope.job_is_partial(done)


def test_a_held_attempt_after_a_crash_reports_an_earlier_attempts_overflowed_failure_list(github, monkeypatch):
    """As above, but attempt 1's failure list overflowed (no key kept): the held attempt still says so, as any run of the
    root would, and the run is not partial only for the hold."""
    import httpx

    from cremore.db import task_store
    from cremore.scanning.orchestrator import Orchestrator
    from cremore.worker import runtime

    repo, conn, catalog, profile, fake, worker = github
    identity = root_identity(conn.id, split_roots(scope.build_plan(
        profile, catalog, auth=profile.auth_revision, enabled=True).roots)[0])
    ScanStore(repo).save_root(identity, conn.id, {"watermark": (dt.datetime.now(dt.UTC) - dt.timedelta(days=1)).isoformat(),
                                                  "detection_digest": worker.orchestrator.detection_policy_digest})
    served = fake.handle
    fake.client = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(403) if "/git/blobs/" in request.url.path else served(request)))
    monkeypatch.setattr(runtime, "FAILURE_KEY_LIMIT", 0)  # the first failed key already overflows the list
    scans = runtime.ScanService

    class Dies(scans):
        def run(self, *args, **kwargs):
            super().run(*args, **kwargs)
            raise PowerLoss()

    monkeypatch.setattr(runtime, "ScanService", Dies)
    job, _ = enqueue(github, "DELTA", trigger="SCHEDULE", policy_hold=True)
    assert worker.process_next()  # its plan
    with pytest.raises(PowerLoss):
        worker.process_next()
    [task] = [t for t in TaskStore(repo).list_for_run(job.id) if t["kind"] != "PLAN"]
    assert task["checkpoint"]["retry_overflow"] is True and task["checkpoint"]["failed_keys"] == []
    assert not ScanStore(repo).root(identity).get("retry_overflow")
    monkeypatch.setattr(runtime, "ScanService", scans)
    monkeypatch.setattr(Orchestrator, "detection_policy_digest", property(lambda self: "f" * 64))  # the rules changed
    real_clock = task_store._clock
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: real_clock(conn) + dt.timedelta(seconds=121))
    fake.requests.clear()
    done = finish(github, job)
    result = root_result(repo, job)
    assert done.status == "SUCCEEDED" and fake.requests == [] and result["policy_held"] == 1
    assert result["stopped_reason"] == "RETRY_STATE_OVERFLOW" and result["root_coverage_complete"] is False
    assert done.coverage["stopped_reason"] == "RETRY_STATE_OVERFLOW"
    assert "policy_held_only" not in done.coverage and scope.job_is_partial(done)
