"""Crash/lease/queue invariants against both real SQLite and the memory repository."""
import io
import time
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from cremore.db import task_store
from cremore.db.repository import InMemoryRepository
from cremore.db.scan_store import ScanStore
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.db.task_store import LeaseLost, TaskStore
from cremore.domain.models import Connection, Credential, ScanJob, ScopeCatalog, ScopeProfile


@pytest.fixture(params=["memory", "sqlite"])
def queue(request, monkeypatch):
    now = {"value": datetime(2026, 9, 15, tzinfo=UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    if request.param == "memory":
        repo = InMemoryRepository()
    else:
        engine = make_engine("sqlite+pysqlite:///:memory:")
        create_all(engine)
        repo = SqlRepository(engine)
    return TaskStore(repo), repo, now


def test_shards_are_idempotent_prioritized_and_serialize_physical_root(queue):
    tasks, _repo, _now = queue
    run = uuid.uuid4()
    a = tasks.enqueue(run, "scope-a", {"mode": "BASELINE", "lock_key": "bucket"}, start_key="a")
    assert tasks.enqueue(run, "scope-a", a["payload"], start_key="a")["id"] == a["id"]
    tasks.enqueue(run, "scope-b", {"mode": "BASELINE", "lock_key": "bucket"}, start_key="b", priority=20)
    tasks.enqueue(run, "other-bucket", {"mode": "BASELINE"}, priority=5)
    high = tasks.claim()
    assert high["root_id"] == "scope-b"
    other = tasks.claim()
    assert other["root_id"] == "other-bucket"
    assert tasks.claim() is None
    tasks.finish(high["id"], high["token"], {})
    assert tasks.claim()["id"] == a["id"]
    with pytest.raises(ValueError, match="IMMUTABLE"):
        tasks.enqueue(run, "scope-a", {"mode": "BASELINE", "lock_key": "broader"}, start_key="a")


def test_claims_share_the_runners_across_runs_before_age_and_after_priority(queue):
    tasks, _repo, now = queue
    older, newer = uuid.uuid4(), uuid.uuid4()
    for run, prefix, count in ((older, "old", 3), (newer, "new", 2)):
        for i in range(count):
            now["value"] += timedelta(seconds=1)  # distinct ages: the older run's roots are all older
            tasks.enqueue(run, f"{prefix}-{i}", {"mode": "BASELINE", "lock_key": f"{prefix}-{i}"})
    # Age alone would give old-0, old-1, old-2 before the newer run of another connection got a runner.
    assert [tasks.claim()["root_id"] for _ in range(3)] == ["old-0", "new-0", "old-1"]
    # Priority still comes first, however many tasks of the run are running.
    now["value"] += timedelta(seconds=1)
    tasks.enqueue(older, "urgent", {"mode": "BASELINE", "lock_key": "urgent"}, priority=10)
    assert [tasks.claim()["root_id"] for _ in range(2)] == ["urgent", "new-1"]
    assert tasks.claim()["root_id"] == "old-2"


def test_expired_claim_reuses_task_checkpoint_but_rejects_old_token(queue):
    tasks, _repo, now = queue
    run = uuid.uuid4()
    tasks.enqueue(run, "bucket", {"mode": "DELTA"})
    first = tasks.claim(lease_seconds=10)
    tasks.checkpoint(first["id"], first["token"], {"cursor": "next"})
    now["value"] += timedelta(seconds=11)
    second = tasks.claim(lease_seconds=10)
    assert second["id"] == first["id"] and second["token"] != first["token"]
    assert second["checkpoint"] == {"cursor": "next"} and second["attempts"] == 2
    for operation in (lambda: tasks.heartbeat(first["id"], first["token"]),
                      lambda: tasks.checkpoint(first["id"], first["token"], {}),
                      lambda: tasks.finish(first["id"], first["token"], {}),
                      lambda: tasks.fail(first["id"], first["token"], "READ_FAILED")):
        with pytest.raises(LeaseLost):
            operation()
    now["value"] += timedelta(seconds=11)
    assert tasks.claim(max_attempts=2) is None
    assert tasks.list_for_run(run)[0]["error"] == "LEASE_RETRY_LIMIT"


def test_fence_rejects_commit_after_expiry_and_rolls_back_repo_cache_checkpoint(queue):
    tasks, repo, now = queue
    run, connection_id = uuid.uuid4(), uuid.uuid4()
    tasks.enqueue(run, "bucket", {"mode": "BASELINE"})
    task = tasks.claim(lease_seconds=10)
    with pytest.raises(LeaseLost), tasks.fenced(task["id"], task["token"]) as bound:
        credential = bound.upsert_credential(Credential(fingerprint="synthetic", credential_type="TOKEN"))
        bound.put_setting("response:test", {"state": "REMOVED"}, "scanner")
        ScanStore(bound).save_root("bucket", connection_id, {"watermark": "must roll back"})
        TaskStore(bound).checkpoint(task["id"], task["token"], {"cursor": "must roll back"})
        now["value"] += timedelta(seconds=11)
    assert repo.get_credential(credential.id) is None
    assert repo.get_setting("response:test") is None
    assert ScanStore(repo).root("bucket") == {}
    assert tasks.list_for_run(run)[0]["checkpoint"] == {}


def test_fenced_finish_and_repo_writes_share_one_commit(queue):
    tasks, repo, _now = queue
    run = uuid.uuid4()
    tasks.enqueue(run, "bucket", {"mode": "BASELINE"})
    task = tasks.claim()
    with tasks.fenced(task["id"], task["token"]) as bound:
        credential = bound.upsert_credential(Credential(fingerprint="synthetic", credential_type="TOKEN"))
        TaskStore(bound).finish(task["id"], task["token"], {"objects": 1})
    assert repo.get_credential(credential.id) is not None
    assert tasks.list_for_run(run)[0]["status"] == "SUCCEEDED"


def event_payload(keys):
    return {"mode": "EVENT", "scope": {"prefixes": ["approved/"]}, "keys": keys,
            "event_coalesce_key": "same-approval", "lock_key": "bucket"}


def test_events_merge_keys_and_run_memberships_but_not_authorization(queue):
    tasks, _repo, now = queue
    first_run, second_run = uuid.uuid4(), uuid.uuid4()
    first = tasks.enqueue(first_run, "approved", event_payload(["approved/a"]))
    second = tasks.enqueue(second_run, "approved", event_payload(["approved/b"]))
    assert second["id"] == first["id"]
    assert second["payload"]["keys"] == ["approved/a", "approved/b"]
    assert tasks.list_for_run(second_run)[0]["id"] == first["id"]
    bad = event_payload(["outside/c"])
    bad["scope"] = {"prefixes": [""]}
    with pytest.raises(ValueError, match="SCOPE"):
        tasks.enqueue(uuid.uuid4(), "approved", bad)
    assert tasks.claim() is None
    now["value"] += timedelta(seconds=3)
    running = tasks.claim()
    third = tasks.enqueue(uuid.uuid4(), "approved", event_payload(["approved/c"]))
    assert third["id"] != running["id"]
    now["value"] += timedelta(seconds=3)
    assert tasks.claim() is None  # Even a new queued event cannot run concurrently.
    tasks.finish(running["id"], running["token"], {})
    assert tasks.claim()["id"] == third["id"]


def test_expired_event_merges_followup_and_preserves_all_parent_memberships(queue):
    tasks, _repo, now = queue
    old_run, new_run = uuid.uuid4(), uuid.uuid4()
    tasks.enqueue(old_run, "approved", event_payload(["approved/a"]))
    now["value"] += timedelta(seconds=3)
    old = tasks.claim(lease_seconds=5)
    new = tasks.enqueue(new_run, "approved", event_payload(["approved/b"]))
    now["value"] += timedelta(seconds=6)
    current = tasks.claim()
    assert current["id"] == new["id"]
    assert current["payload"]["keys"] == ["approved/a", "approved/b"]
    assert tasks.list_for_run(old_run)[0]["id"] == current["id"]
    assert tasks.list_for_run(new_run)[0]["id"] == current["id"]
    with pytest.raises(LeaseLost):
        tasks.finish(old["id"], old["token"], {})


def test_event_overflow_is_full_delta_and_continuous_updates_have_maximum_delay(queue):
    tasks, _repo, now = queue
    start = now["value"]
    first = tasks.enqueue(uuid.uuid4(), "approved", event_payload([f"approved/{i}" for i in range(256)]))
    for i in range(1, 15):
        now["value"] = start + timedelta(seconds=i)
        last = tasks.enqueue(uuid.uuid4(), "approved", event_payload([f"approved/new-{i}"]))
    assert last["id"] == first["id"] and last["payload"]["keys"] == []
    assert last["payload"]["full_delta"] is True
    assert last["available_at"] <= start + timedelta(seconds=task_store.EVENT_MAX_DELAY_SECONDS)
    assert tasks.claim()["id"] == first["id"]


def held_event(keys, held):
    """A change event's root task of a scope in the upgrade hold (``held``: the trigger set policy_hold), or not."""
    return {**event_payload(keys), "job_payload": {"trigger": "EVENT", **({"policy_hold": True} if held else {})}}


@pytest.mark.parametrize("merge", ["queued", "expired"])
@pytest.mark.parametrize("holds", [(True, True), (True, False), (False, True)])
def test_change_events_of_one_root_merge_held_only_if_every_one_was(queue, merge, holds):
    """A held change run reads only what changed, or nothing: a merged task errs toward reading."""
    tasks, _repo, now = queue
    runs = [uuid.uuid4(), uuid.uuid4()]
    tasks.enqueue(runs[0], "approved", held_event(["approved/a"], holds[0]))
    if merge == "expired":  # the first is claimed and its lease runs out while the second waits: claim merges them
        now["value"] += timedelta(seconds=3)
        tasks.claim(lease_seconds=5)
    second = tasks.enqueue(runs[1], "approved", held_event(["approved/b"], holds[1]))
    if merge == "expired":
        now["value"] += timedelta(seconds=6)
        second = tasks.claim()
    assert {tasks.list_for_run(run)[0]["id"] for run in runs} == {second["id"]}
    assert second["payload"]["keys"] == ["approved/a", "approved/b"]
    assert second["payload"]["job_payload"].get("policy_hold", False) is all(holds)



def test_exclusive_legacy_connection_blocks_shared_roots_without_serializing_unrelated_connections(queue):
    tasks, _repo, _now = queue
    run = uuid.uuid4()
    tasks.enqueue(run, "legacy", {"mode": "PLAN", "connection_lock": "c", "exclusive_connection": True}, priority=100)
    tasks.enqueue(run, "a", {"mode": "BASELINE", "connection_lock": "c"})
    tasks.enqueue(run, "b", {"mode": "BASELINE", "connection_lock": "c"})
    tasks.enqueue(run, "other", {"mode": "BASELINE", "connection_lock": "different"})
    legacy = tasks.claim()
    other = tasks.claim()
    assert other["root_id"] == "other"
    assert tasks.claim() is None
    tasks.finish(legacy["id"], legacy["token"], {})
    assert {tasks.claim()["root_id"], tasks.claim()["root_id"]} == {"a", "b"}


def test_seed_planning_and_finalization_are_durable_and_preserve_partial_coverage(queue):
    tasks, repo, _now = queue
    parent = repo.enqueue_job(ScanJob(kind="scope"))
    assert tasks.seed_next_job().id == parent.id
    assert repo.get_job(parent.id).status == "RUNNING"
    seed = tasks.claim()
    assert seed["kind"] == "PLAN"
    with tasks.fenced(seed["id"], seed["token"]) as bound:
        nested = TaskStore(bound)
        nested.enqueue(parent.id, "bucket", {"mode": "BASELINE"})
        nested.finish(seed["id"], seed["token"], {"planned_roots": 1})
    assert tasks.finalize_runs() == 0
    child = tasks.claim()
    tasks.finish(child["id"], child["token"], {"objects": 3, "findings": 1, "failed": 1,
        "skipped": 2, "requests": 8, "bytes": 50, "reused": 1, "timings": {"db": 0.5}, "stopped_reason": "BYTE_LIMIT",
        "root_coverage_complete": False, "coverage_basis": "INVENTORY_REPORT_ONLY"})
    assert tasks.finalize_runs() == 1
    done = repo.get_job(parent.id)
    assert done.status == "SUCCEEDED" and done.objects_failed == 1
    assert done.coverage["stopped_reason"] == "BYTE_LIMIT" and done.coverage["skipped"] == 2
    assert done.coverage["timings"] == {"db": 0.5}
    assert done.coverage["root_coverage_complete"] is False and done.coverage["coverage_basis"] == "INVENTORY_REPORT_ONLY"
    assert tasks.finalize_runs() == 0


def test_blocked_connection_does_not_hide_unrelated_root_beyond_candidate_page(queue):
    tasks, _repo, _now = queue
    run = uuid.uuid4()
    tasks.enqueue(run, "exclusive", {"mode": "PLAN", "connection_lock": "busy", "exclusive_connection": True}, priority=100)
    assert tasks.claim()["root_id"] == "exclusive"
    for i in range(20):
        tasks.enqueue(run, f"blocked-{i}", {"mode": "BASELINE", "connection_lock": "busy"}, priority=50)
    tasks.enqueue(run, "available", {"mode": "BASELINE", "connection_lock": "other"})
    assert tasks.claim()["root_id"] == "available"


def test_finalization_reaches_finished_metadata_after_a_full_batch_of_unfinished_jobs(queue):
    tasks, repo, _now = queue
    waiting = []
    for _ in range(100):
        waiting.append(repo.enqueue_job(ScanJob(kind="catalog-refresh")))
        tasks.seed_next_job()
    parent = repo.enqueue_job(ScanJob(kind=task_store.METADATA_JOB_KIND, payload={
        "coverage_connection_id": str(uuid.uuid4()), "coverage_revision": 1}))
    tasks.seed_next_job()
    child = tasks.claim(run_id=parent.id)
    tasks.finish(child["id"], child["token"], {"metadata_items": 1, "coverage_status": "COMPLETE"})

    assert tasks.finalize_runs() == 1
    done = repo.get_job(parent.id)
    assert done.status == "SUCCEEDED" and done.coverage["metadata_items"] == 1
    assert all(repo.get_job(job.id).status == "RUNNING" for job in waiting)
    assert tasks.finalize_runs() == 0


def test_finalization_limit_counts_ready_parents_and_preserves_empty_run_states(queue):
    tasks, repo, _now = queue
    empty = repo.enqueue_job(ScanJob(kind="catalog-refresh"))
    assert repo.claim_next_job().id == empty.id
    cancelled = repo.enqueue_job(ScanJob(kind="catalog-refresh"))
    assert repo.claim_next_job().id == cancelled.id
    repo.request_job_cancel(cancelled.id)
    failed = repo.enqueue_job(ScanJob(kind="catalog-refresh"))
    tasks.seed_next_job()
    child = tasks.claim(run_id=failed.id)
    tasks.fail(child["id"], child["token"], "SYNTHETIC_FAILURE")

    assert tasks.finalize_runs(limit=1) == 1
    assert sum(repo.get_job(job.id).status in {"CANCELLED", "FAILED"} for job in (cancelled, failed)) == 1
    assert tasks.finalize_runs(limit=1) == 1
    assert repo.get_job(cancelled.id).status == "CANCELLED"
    assert repo.get_job(failed.id).status == "FAILED"
    assert repo.get_job(empty.id).status == "RUNNING"
    assert tasks.finalize_runs() == 0


def test_finalization_uses_canonical_tasks_shared_by_multiple_parents(queue):
    tasks, repo, now = queue
    parents = []
    for _ in range(2):
        parent = repo.enqueue_job(ScanJob(kind="catalog-refresh"))
        assert repo.claim_next_job().id == parent.id
        tasks.enqueue(parent.id, "approved", event_payload(["approved/a"]))
        parents.append(parent)
    assert tasks.list_for_run(parents[0].id)[0]["id"] == tasks.list_for_run(parents[1].id)[0]["id"]
    assert tasks.finalize_runs() == 0
    now["value"] += timedelta(seconds=3)
    child = tasks.claim()
    tasks.finish(child["id"], child["token"], {"objects": 1})
    assert tasks.finalize_runs() == 2
    assert all(repo.get_job(parent.id).coverage["objects"] == 1 for parent in parents)


def test_no_raw_content_or_credentials_in_task_payload(queue):
    tasks, _repo, _now = queue
    for payload in ({"mode": "BASELINE", "text": "raw content"}, {"mode": "BASELINE", "nested": {"access_token": "credential"}}):
        with pytest.raises(ValueError, match="CONTAINS_CONTENT"):
            tasks.enqueue(uuid.uuid4(), "bucket", payload)


def test_defer_requeues_later_without_spending_an_attempt_or_the_checkpoint(queue):
    tasks, _repo, now = queue
    run = uuid.uuid4()
    tasks.enqueue(run, "bucket-a", {"mode": "BASELINE"})
    claimed = tasks.claim()
    tasks.checkpoint(claimed["id"], claimed["token"], {"after": "prefix/k-100"})
    tasks.defer(claimed["id"], claimed["token"], "AWS_LOGIN_REQUIRED", delay_seconds=60)
    [task] = tasks.list_for_run(run)
    assert task["status"] == "QUEUED" and task["error"] == "AWS_LOGIN_REQUIRED" and task["attempts"] == 0
    with pytest.raises(LeaseLost):
        tasks.finish(claimed["id"], claimed["token"], {})
    assert tasks.claim() is None
    now["value"] += timedelta(seconds=61)
    again = tasks.claim()
    assert again["id"] == claimed["id"] and again["attempts"] == 1
    assert again["checkpoint"] == {"after": "prefix/k-100"}
    with pytest.raises(ValueError):
        tasks.defer(again["id"], again["token"], "not a code")


def test_run_states_reports_progress_and_a_hold_reason(queue):
    tasks, _repo, now = queue
    run = uuid.uuid4()
    tasks.enqueue(run, "a", {"mode": "BASELINE", "lock_key": "la"})
    tasks.enqueue(run, "b", {"mode": "BASELINE", "lock_key": "lb"})
    tasks.enqueue(run, "c", {"mode": "BASELINE", "lock_key": "lc"})
    # finish one, park one waiting for AWS login, leave one queued
    first = tasks.claim(); tasks.finish(first["id"], first["token"], {"objects": 5})
    held = tasks.claim(); tasks.defer(held["id"], held["token"], "AWS_LOGIN_REQUIRED", delay_seconds=60)
    state = tasks.run_states(run, now=now["value"])
    assert state["total"] == 3 and state["done"] == 1 and state["queued"] == 2
    assert state["hold_code"] == "AWS_LOGIN_REQUIRED" and len(state["held"]) == 1
    assert state["next_attempt_at"] == (now["value"] + timedelta(seconds=60)).isoformat()
    # once the wait elapses, nothing is held any more
    now["value"] += timedelta(seconds=61)
    assert tasks.run_states(run, now=now["value"])["hold_code"] is None


def test_top_up_moves_only_finished_siblings_unused_share(queue):
    tasks, _repo, _now = queue
    run = uuid.uuid4()
    big = tasks.enqueue(run, "big", {"mode": "BASELINE", "lock_key": "a", "budgets": {"requests": 5}})
    tasks.enqueue(run, "small", {"mode": "BASELINE", "lock_key": "b", "budgets": {"requests": 5}})
    tasks.enqueue(run, "later", {"mode": "BASELINE", "lock_key": "c", "budgets": {"requests": 5}}, priority=-3)
    claimed = {t["root_id"]: t for t in (tasks.claim(), tasks.claim())}
    tasks.checkpoint(claimed["small"]["id"], claimed["small"]["token"], {"requests": 2})
    tasks.finish(claimed["small"]["id"], claimed["small"]["token"], {})
    granted, pending = tasks.top_up_budget(claimed["big"]["id"], claimed["big"]["token"], ["requests"])
    assert (granted, pending) == (3, -3)  # "later" has not run yet: its share stays reserved
    rows = {t["root_id"]: t for t in tasks.list_for_run(run)}
    assert rows["big"]["payload"]["budgets"]["requests"] == 8 and rows["small"]["payload"]["budgets"]["requests"] == 2
    assert sum(t["payload"]["budgets"]["requests"] for t in rows.values()) == 15
    # the same spare is never granted twice
    assert tasks.top_up_budget(claimed["big"]["id"], claimed["big"]["token"], ["requests"])[0] == 0
    assert big["id"] == claimed["big"]["id"]


@pytest.mark.parametrize("second,expected_basis,expected_digest", [
    ({"failure_basis": "EXCLUDES_FORMAT_SKIPS", "detection_policy_digest": "d1"}, "EXCLUDES_FORMAT_SKIPS", "d1"),
    ({"detection_policy_digest": "d1"}, None, "d1"),                              # an old-style root
    ({"failure_basis": "EXCLUDES_FORMAT_SKIPS", "detection_policy_digest": "d2"}, "EXCLUDES_FORMAT_SKIPS", None),
])
def test_a_parent_uses_new_counts_and_one_policy_only_when_every_root_does(queue, second, expected_basis,
                                                                           expected_digest):
    tasks, repo, _now = queue
    parent = repo.enqueue_job(ScanJob(kind="scope"))
    tasks.seed_next_job()
    seed = tasks.claim()
    with tasks.fenced(seed["id"], seed["token"]) as bound:
        nested = TaskStore(bound)
        nested.enqueue(parent.id, "root-a", {"mode": "BASELINE"})
        nested.enqueue(parent.id, "root-b", {"mode": "BASELINE"})
        nested.finish(seed["id"], seed["token"], {"planned_roots": 2})
    first = {"objects": 1, "failed": 1, "skipped_unsupported": 2, "skipped_media": 3,
             "engine_name": "saved-engine", "engine_version": "0.1.0",
             "failure_basis": "EXCLUDES_FORMAT_SKIPS", "detection_policy_digest": "d1"}
    # Matching identities survive aggregation; mixed versions cannot be asserted.
    for result in (first, {"objects": 1, "skipped_unsupported": 1,
                           "engine_name": "saved-engine", "engine_version": "0.2.0", **second}):
        child = tasks.claim()
        tasks.finish(child["id"], child["token"], result)
    assert tasks.finalize_runs() == 1
    coverage = repo.get_job(parent.id).coverage
    assert coverage["failed"] == 1 and coverage["skipped_unsupported"] == 3 and coverage["skipped_media"] == 3
    assert coverage.get("failure_basis") == expected_basis
    assert coverage.get("detection_policy_digest") == expected_digest
    assert coverage["engine_name"] == "saved-engine" and "engine_version" not in coverage


def finished_parent(tasks, repo, plan_result, results):
    """A scope run with one root per result, finished and finalized; its coverage."""
    parent = repo.enqueue_job(ScanJob(kind="scope"))
    tasks.seed_next_job()
    seed = tasks.claim(run_id=parent.id)
    with tasks.fenced(seed["id"], seed["token"]) as bound:
        nested = TaskStore(bound)
        for index in range(len(results)):
            nested.enqueue(parent.id, f"root-{index}", {"mode": "BASELINE", "lock_key": f"{parent.id}-{index}"})
        nested.finish(seed["id"], seed["token"], plan_result)
    for result in results:
        child = tasks.claim(run_id=parent.id)
        tasks.finish(child["id"], child["token"], result)
    assert tasks.finalize_runs() == 1
    return repo.get_job(parent.id).coverage


def test_a_parent_counts_its_roots_partial_inspections_and_gaps_and_its_plan_s_requests(queue):
    tasks, repo, _now = queue
    coverage = finished_parent(tasks, repo, {"planned_roots": 2, "requests": 3}, [
        {"objects": 4, "requests": 5, "partially_inspected": 2, "inspection_gaps": 3},
        {"objects": 1, "requests": 1, "partially_inspected": 1, "inspection_gaps": 10_000,
         "inspection_gaps_overflow": True}])
    assert (coverage["partially_inspected"], coverage["inspection_gaps"]) == (3, 10_003)
    assert coverage["inspection_gaps_overflow"] is True  # a root's list was cut short: more gaps than counted
    # A Notion run's search walk, made by its plan, counts with the roots' requests.
    assert (coverage["requests"], coverage["objects"]) == (9, 5)
    clean = finished_parent(tasks, repo, {"planned_roots": 1}, [{"objects": 2, "requests": 2}])
    assert (clean["partially_inspected"], clean["inspection_gaps"], clean["requests"]) == (0, 0, 2)
    assert "inspection_gaps_overflow" not in clean


HELD_ROOT = {"objects": 1, "policy_held": 1, "root_coverage_complete": False}


@pytest.mark.parametrize("results, held, held_only", [
    ([HELD_ROOT, {"objects": 2}], 1, True),
    ([HELD_ROOT, HELD_ROOT], 2, True),
    ([HELD_ROOT, {"objects": 2, "inspection_gaps": 1, "root_coverage_complete": False}], 1, False),
    ([HELD_ROOT, {"objects": 2, "failed": 1}], 1, False),
    ([HELD_ROOT, {"objects": 2, "skipped": 1, "stopped_reason": "BUDGET_REQUESTS"}], 1, False),
    ([{**HELD_ROOT, "inspection_gaps": 1}, {"objects": 2}], 1, False),  # a held root with a gap of its own
    ([HELD_ROOT, {"objects": 2, "root_coverage_complete": False}], 1, False),  # an incomplete root the hold does not explain
    ([{"objects": 1, "root_coverage_complete": False}, {"objects": 2}], 0, False),  # no hold
])
def test_a_run_counts_the_roots_the_upgrade_hold_left_and_whether_nothing_else_is_partial(queue, results, held,
                                                                                         held_only):
    from cremore.scanning import scope

    tasks, repo, _now = queue
    coverage = finished_parent(tasks, repo, {"planned_roots": len(results)}, results)
    # Never a complete whole-scope read: the held roots were not read whole under the current policy.
    assert coverage["root_coverage_complete"] is False
    assert (coverage.get("policy_held", 0), coverage.get("policy_held_only", False)) == (held, held_only)
    public = scope.run_public(ScanJob(id=uuid.uuid4(), kind="scope", status="SUCCEEDED", coverage=coverage, payload={}),
                              "source", uuid.uuid4())
    assert public["status"] == "PARTIAL" and "result_status" not in public
    assert (public.get("policy_held_roots", 0), public.get("policy_held_only", False)) == (held, held_only)


def test_a_waiting_change_scan_of_a_root_is_found_once_it_can_start(queue):
    tasks, _repo, now = queue
    tasks.enqueue(uuid.uuid4(), "sweep", {"mode": "BASELINE", "lock_key": "bucket"})
    sweep = tasks.claim()
    assert sweep["root_id"] == "sweep" and tasks.waiting_event("bucket") is None
    first = tasks.enqueue(uuid.uuid4(), "approved", event_payload(["approved/a"]))
    elsewhere = tasks.enqueue(uuid.uuid4(), "other-root", {**event_payload(["approved/b"]), "lock_key": "other"})
    assert tasks.waiting_event("bucket") is None  # not before its debounce is over
    now["value"] += timedelta(seconds=3)
    assert tasks.claim() is not None  # the other lock's event starts; this root's waits behind the sweep
    assert tasks.waiting_event("bucket") == str(first["id"]) and tasks.waiting_event("other") is None
    second = tasks.enqueue(uuid.uuid4(), "approved-too", {**event_payload(["approved/c"]),
                                                          "event_coalesce_key": "another-approval"}, priority=5)
    now["value"] += timedelta(seconds=3)
    # The one it already gave way to is passed over; the most urgent of the others is named.
    assert tasks.waiting_event("bucket") == str(second["id"])
    assert tasks.waiting_event("bucket", skip=str(second["id"])) == str(first["id"])
    assert tasks.list_for_run(sweep["run_id"])[0]["status"] == "RUNNING" and elsewhere["id"] != first["id"]


KEYS = [f"obj/{i:03d}" for i in range(300)]


class Archived(Exception):
    """S3's refusal of an archived object."""

    def __init__(self):
        super().__init__("InvalidObjectState")
        self.response = {"Error": {"Code": "InvalidObjectState"}}


class S3Error(Exception):
    """An S3 error code as botocore reports it (a HEAD, which has no body, gives its status code alone)."""

    def __init__(self, status):
        super().__init__(status)
        self.response = {"Error": {"Code": status}}


class Bucket:
    """Small clean objects, ``page`` keys a listing answer. ``on_read(key)``, ``on_list()`` and ``on_head(key)`` run as
    an object is read, a page listed and an object checked; a missing key is NoSuchKey, one in ``denied`` is refused
    after ``slow`` seconds, one in ``archived`` is refused as archived; every read takes ``delay``. A HEAD of a key in
    ``head_denied`` is refused (403), of a missing one 404."""

    def __init__(self, keys=KEYS, *, denied=(), archived=(), slow=0.0, delay=0.0, page=1000):
        self.objects = {key: b"nothing to find here" for key in keys}
        self.modified = dict.fromkeys(keys, datetime(2020, 1, 1, tzinfo=UTC))
        self.denied, self.archived, self.slow, self.delay, self.page = set(denied), set(archived), slow, delay, page
        self.reads, self.on_read, self.on_list, self.heads, self.head_denied = [], None, None, [], set()
        self.on_head = None

    def list_objects_v2(self, **kw):
        if self.on_list is not None:
            self.on_list()
        after = kw.get("ContinuationToken") or kw.get("StartAfter", "")
        keys = [key for key in sorted(self.objects) if key.startswith(kw.get("Prefix", "")) and key > after]
        more = len(keys) > self.page
        keys = keys[:self.page]
        return {"Contents": [{"Key": key, "Size": len(self.objects[key]), "ETag": f'"{key}"',
                              "LastModified": self.modified[key]} for key in keys],
                "IsTruncated": more, **({"NextContinuationToken": keys[-1]} if more else {})}

    def get_object(self, Bucket, Key):  # the S3 API's own parameter names
        self.reads.append(Key)
        time.sleep(self.delay)
        if self.on_read is not None:
            self.on_read(Key)
        if Key not in self.objects:
            raise S3Error("NoSuchKey")
        if Key in self.denied:
            time.sleep(self.slow)
            raise PermissionError("AccessDenied")
        if Key in self.archived:
            raise Archived()
        data = self.objects[Key]
        return {"Body": io.BytesIO(data), "ContentLength": len(data), "ETag": f'"{Key}"',
                "LastModified": self.modified[Key]}

    def head_object(self, Bucket, Key):
        self.heads.append(Key)
        if self.on_head is not None:
            self.on_head(Key)
        if Key in self.head_denied:
            raise S3Error("403")
        if Key not in self.objects:
            raise S3Error("404")
        return {"ContentLength": len(self.objects[Key]), "ETag": f'"{Key}"', "LastModified": self.modified[Key]}


def sweep_env(queue, monkeypatch, bucket, *, look=0.0, budgets=None, reconciled=True, failed=(), state=None,
              prefixes=("obj/",)):
    """A bucket root approved under ``prefixes`` (one root each), a worker scanning it and its runs. The sweep's checks
    run on every request and its look for a waiting change scan starts ``look`` seconds after its first commit
    (YIELD_SECONDS). ``reconciled``: the root had a whole full scan two hours ago (or at this stamp), so its sweeps may
    give way to change scans; ``failed``: the keys that scan could not read; ``state``: more of what it left."""
    from cremore.scanning import scope
    from cremore.worker import runtime
    from cremore.worker.factory import build_collector
    from cremore.worker.worker import JobWorker

    tasks, repo, now = queue
    monkeypatch.setattr(runtime, "CHECK_SECONDS", 0)
    monkeypatch.setattr(runtime, "YIELD_SECONDS", look)
    conn = repo.create_connection(Connection(provider="aws", name="fixture", config={"bucket": "fixture"}))
    item = scope.resource("source", conn.id, "S3_BUCKET", "fixture", "fixture", "arn:aws:s3:::fixture", "aws")
    auth = scope.auth_revision("source", conn)
    catalog = repo.save_catalog(ScopeCatalog(kind="source", connection_id=conn.id, snapshot_id="v1",
                                             auth_revision=auth, items=[item], completeness="COMPLETE"))
    profile = repo.create_scope_profile(ScopeProfile(
        kind="source", connection_id=conn.id, name="approved", state="READY", auth_revision=auth,
        catalog_snapshot_id="v1", budgets=budgets or {"requests": 10_000, "bytes": 10_000_000, "seconds": 600},
        selected_roots=[{"resource_id": item["id"], "prefixes": list(prefixes), "all_current_objects": False,
                         "include_future_descendants": False}]))
    worker = JobWorker(repo, collector_factory=lambda job: build_collector(job, s3_client_factory=lambda _: bucket))
    state_id = scope.root_identity(conn.id, scope.build_plan(profile, catalog, auth=profile.auth_revision,
                                                             enabled=True).roots[0])
    if reconciled:
        ScanStore(repo).save_root(state_id, conn.id, {
            "last_reconcile": reconciled if isinstance(reconciled, str) else (
                datetime.now(UTC) - timedelta(hours=2)).isoformat(),
            "detection_digest": worker.orchestrator.detection_policy_digest, "failed_keys": sorted(failed),
            **(state or {})})

    def enqueue(mode, trigger=None, exact_keys=None, not_before=None, **job_payload):
        plan = scope.build_plan(profile, catalog, auth=profile.auth_revision, enabled=True)
        if exact_keys:
            plan.roots = [{**root, "exact_keys": exact_keys} for root in plan.roots]
        plan.trigger = trigger or plan.trigger
        plan = repo.create_plan(plan)
        payload = {**scope.run_payload(plan, profile, {}, "s3"), "mode": mode, **job_payload}
        if not_before:
            payload["not_before"] = not_before.isoformat()
        return repo.enqueue_job(ScanJob(kind="scope", connection_id=conn.id, payload=payload))

    def root(job):
        [task] = [task for task in tasks.list_for_run(job.id) if task["kind"] != "PLAN"]
        return task

    def finish(job):
        for _ in range(12):
            worker.process_next()
            if repo.get_job(job.id).status not in ("QUEUED", "RUNNING"):
                break
        return repo.get_job(job.id)

    return SimpleNamespace(tasks=tasks, repo=repo, now=now, conn=conn, worker=worker, enqueue=enqueue, root=root,
                           finish=finish, state_id=state_id)


def test_a_sweep_gives_way_to_a_waiting_change_scan_of_its_root_and_resumes_after_its_last_key(queue, monkeypatch):
    bucket = Bucket()
    env = sweep_env(queue, monkeypatch, bucket)
    start = env.now["value"]
    sweep = env.enqueue("BASELINE")
    assert env.worker.process_next()  # the sweep's plan
    # A change scan of one key, which may start ten seconds from now.
    event = env.enqueue("EVENT", "EVENT", ["obj/250"], start + timedelta(seconds=10))
    assert env.worker.process_next()  # its plan: the event lane runs beside the sweep
    event_task = env.root(event)

    def time_passes(key):
        if key == "obj/020":
            env.now["value"] = start + timedelta(seconds=11)  # the change scan is due while the sweep reads

    bucket.on_read = time_passes
    assert env.worker.process_next()  # the sweep, until it gives way
    bucket.on_read = None
    first = list(bucket.reads)
    root = env.root(sweep)
    last = root["checkpoint"]["last_key"]
    # Deferred, not failed: no attempt spent, the lease released, its committed progress and the change scan kept.
    assert (root["status"], root["error"], root["attempts"], root["token"]) == ("QUEUED", "YIELDED_TO_EVENT", 0, None)
    assert root["checkpoint"]["yielded_to"] == str(event_task["id"]) and last in KEYS and last < KEYS[-1]
    # The run is charged the requests it made (one listing, the reads), not what it had reserved.
    assert root["checkpoint"]["requests"] == 1 + len(first) and env.repo.get_job(sweep.id).status == "RUNNING"
    assert env.worker.process_next()  # the change scan runs first
    assert env.repo.get_job(event.id).status == "SUCCEEDED" and bucket.reads[len(first):] == ["obj/250"]
    env.now["value"] = start + timedelta(seconds=13)
    done = env.finish(sweep)
    assert done.status == "SUCCEEDED" and done.objects == 300 and done.objects_failed == 0
    # It resumed after the last key it committed: nothing committed is read twice, and nothing is missed (the key
    # the change scan read was answered from its cache row).
    again = bucket.reads[len(first) + 1:]
    assert again and min(again) > last and "obj/250" not in again
    assert set(first) | set(bucket.reads[len(first):]) == set(KEYS)


def give_way(env, bucket, sweep, due_when, cycles=8):
    """Run the sweep while a new change scan of its root falls due in every attempt (once it reads a key
    ``due_when`` names); the cursor each attempt that gave way left. Ends when the sweep has finished."""
    cursors = []
    for cycle in range(cycles):
        start = env.now["value"]
        event = env.enqueue("EVENT", "EVENT", [f"obj/{280 + cycle:03d}"], start + timedelta(seconds=5))
        assert env.worker.process_next()  # its plan; its root waits for its debounce

        def due(key, start=start):
            if due_when(key):
                env.now["value"] = start + timedelta(seconds=6)

        bucket.on_read = due
        env.worker.process_next()  # the sweep, until it gives way or ends
        bucket.on_read = None
        root = env.root(sweep)
        if root["status"] == "SUCCEEDED":
            env.finish(event)
            break
        assert root["error"] == "YIELDED_TO_EVENT", root
        cursors.append(root["checkpoint"]["last_key"])
        assert env.finish(event).status == "SUCCEEDED"  # the change scan ran first
        env.now["value"] = start + timedelta(seconds=8)  # the sweep's deferral is over
    assert env.repo.get_job(sweep.id).status == "SUCCEEDED", cursors
    return cursors


class PowerLoss(BaseException):
    """The worker process dies where it is."""


def in_order(monkeypatch):
    """One read at a time, and commits only every 64 objects or at a failure, so each attempt's cursor is fixed, not
    timed. An object read ahead of a yield, failed or not, is read again by the next attempt: that is the yield's own
    cost, at most the read-ahead window a yield, and not what these tests count."""
    from cremore_aws_provider.collectors.s3 import S3Collector

    from cremore.scanning import service

    monkeypatch.setattr(S3Collector, "read_concurrency", 1)
    monkeypatch.setattr(service, "BATCH_SECONDS", 3600)


def yield_once(env, bucket, sweep, event_key):
    """One attempt of the sweep, which gives way to a change scan of ``event_key`` falling due as it reads; the change
    scan runs and the sweep's deferral ends. The cursor it gave way at."""
    start = env.now["value"]
    event = env.enqueue("EVENT", "EVENT", [event_key], start + timedelta(seconds=5))
    assert env.worker.process_next()  # its plan
    bucket.on_read = lambda key: env.now.__setitem__("value", start + timedelta(seconds=6))
    assert env.worker.process_next()
    bucket.on_read = None
    root = env.root(sweep)
    assert root["error"] == "YIELDED_TO_EVENT", root
    assert env.finish(event).status == "SUCCEEDED"
    env.now["value"] = start + timedelta(seconds=8)
    return root["checkpoint"]["last_key"]


def test_a_sweep_reads_each_failed_key_once_a_task_however_often_it_gives_way(queue, monkeypatch):
    """Failures of an earlier run (refused, archived, too large to read, readable by now) and of this one: the sweep
    keeps giving way, an attempt resumed after the task read its earlier failures again does not read them again
    (``retried``), and the run still counts each failure once and keeps it for the next run."""
    in_order(monkeypatch)
    earlier = {"denied": "obj/010", "archived": "obj/012", "large": "obj/014", "readable": "obj/016"}
    found = {"denied": "obj/150", "archived": "obj/152", "large": "obj/154"}
    bucket = Bucket(denied=[earlier["denied"], found["denied"]], archived=[earlier["archived"], found["archived"]])
    for key in (earlier["large"], found["large"]):
        bucket.objects[key] = b"x" * 200_000  # past every read's limit: failed on its listed size
    env = sweep_env(queue, monkeypatch, bucket, budgets={"requests": 10_000, "bytes": 100_000, "seconds": 600},
                    failed=earlier.values())
    sweep = env.enqueue("BASELINE")
    assert env.worker.process_next()
    cursors = give_way(env, bucket, sweep, lambda key: True, cycles=20)  # a change scan falls due in every attempt
    assert len(cursors) >= 3 and cursors == sorted(set(cursors)) and cursors[0] < found["denied"] < cursors[-1]
    # Each read once at most; one too large is never fetched, so its body is never read.
    reads = {key: bucket.reads.count(key) for key in [*earlier.values(), *found.values()]}
    assert reads == {"obj/010": 1, "obj/012": 1, "obj/014": 0, "obj/016": 1, "obj/150": 1, "obj/152": 1, "obj/154": 0}
    done = env.repo.get_job(sweep.id)
    assert (done.objects_failed, done.coverage["skipped_archived"], done.coverage["skipped"]) == (4, 2, 2)
    state = ScanStore(env.repo).root(env.state_id)
    assert state["failed_keys"] == sorted(set(reads) - {earlier["readable"]})  # the next run reads them again


def test_a_task_resumed_from_a_cursor_retries_its_failures_once_unless_it_stops_before_recording_that(
        queue, monkeypatch):
    """A task starting at the root's resume cursor first reads the earlier failures at or before it. The first commit
    past the cursor records that (``retried``): an attempt after it does not read them again, while an attempt after a
    crash before it reads them all again."""
    in_order(monkeypatch)
    denied, archived = "obj/010", "obj/012"
    bucket = Bucket(denied=[denied], archived=[archived])
    env = sweep_env(queue, monkeypatch, bucket, failed=[denied, archived])
    store = ScanStore(env.repo)
    store.save_root(env.state_id, env.conn.id, {**store.root(env.state_id), "resume_after": "obj/100",
                                                 "resume_detection_digest": env.worker.orchestrator.detection_policy_digest})
    sweep = env.enqueue("BASELINE")
    assert env.worker.process_next()  # its plan

    def dies(key):
        if key == archived:
            raise PowerLoss()  # in the retry pass, before any commit past the cursor

    bucket.on_read = dies
    with pytest.raises(PowerLoss):
        env.worker.process_next()
    assert "retried" not in env.root(sweep)["checkpoint"]
    env.now["value"] += timedelta(seconds=121)  # its lease runs out and the task is claimed again
    cursor = yield_once(env, bucket, sweep, "obj/280")  # it reads them all again, commits past the cursor, gives way
    assert env.root(sweep)["checkpoint"]["retried"] is True and cursor > "obj/100"
    assert env.finish(sweep).status == "SUCCEEDED"
    # Read by the crashed attempt and the next one, never by the last; nothing else before the cursor is read.
    assert [bucket.reads.count(key) for key in (denied, archived)] == [2, 2]
    assert {key for key in bucket.reads if key <= "obj/100"} == {denied, archived}
    done = env.repo.get_job(sweep.id)
    assert (done.objects_failed, done.coverage["skipped_archived"]) == (1, 1)
    assert store.root(env.state_id)["failed_keys"] == [denied, archived]


def test_a_key_refused_as_archived_then_otherwise_counts_by_its_latest_refusal(queue, monkeypatch):
    """A detection policy change restarts the task's traversal, and a key refused as archived before is refused
    otherwise now. A later attempt, which does not read it again, counts it as failed, not as skipped."""
    from cremore.scanning.orchestrator import Orchestrator

    in_order(monkeypatch)
    key = "obj/005"
    bucket = Bucket(archived=[key])
    env = sweep_env(queue, monkeypatch, bucket)
    sweep = env.enqueue("BASELINE")
    assert env.worker.process_next()
    assert yield_once(env, bucket, sweep, "obj/280") >= key
    assert env.root(sweep)["checkpoint"]["archived_keys"] == [key]
    bucket.archived.discard(key)
    bucket.denied.add(key)
    monkeypatch.setattr(Orchestrator, "detection_policy_digest", property(lambda self: "f" * 64))
    assert yield_once(env, bucket, sweep, "obj/281") >= key  # read again from the start, refused otherwise
    done = env.finish(sweep)
    assert bucket.reads.count(key) == 2  # the last attempt counts it without reading it
    assert (done.status, done.objects_failed, done.coverage["skipped_archived"]) == ("SUCCEEDED", 1, 0)


def test_roots_that_all_wait_for_budget_end_as_budget_stops_rather_than_wait_on_each_other(queue, monkeypatch):
    """Two roots each spend their time share part way through. The second to stop finds its only sibling itself
    waiting for budget, so it stops rather than waits; the first then finds nothing to take and stops too. The run
    ends, each root resumable from where it stopped."""
    from cremore.scanning.scope import root_identity
    from cremore.worker import runtime

    in_order(monkeypatch)
    late, real = [0.0], time.monotonic
    monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: real() + late[0]))
    bucket = Bucket(keys=[f"{prefix}{i:02d}" for prefix in ("a/", "b/") for i in range(10)])

    def slow(key):
        if key.endswith("/02"):
            late[0] += 1000  # a root's 300 s share is spent here

    bucket.on_read = slow
    env = sweep_env(queue, monkeypatch, bucket, reconciled=False, prefixes=("a/", "b/"))
    job = env.enqueue("BASELINE")
    for claims in range(1, 13):
        env.worker.process_next()
        env.now["value"] += timedelta(seconds=11)  # past every deferral
        if env.repo.get_job(job.id).status not in ("QUEUED", "RUNNING"):
            break
    assert env.repo.get_job(job.id).status == "SUCCEEDED" and claims <= 8, claims
    roots = [task for task in env.tasks.list_for_run(job.id) if task["kind"] != "PLAN"]
    assert len(roots) == 2 and all(task["result"]["stopped_reason"].startswith("BUDGET_") for task in roots)
    for task in roots:
        state = ScanStore(env.repo).root(root_identity(env.conn.id, task["payload"]["scope"]))
        assert state["resume_after"].startswith(task["payload"]["scope"]["prefixes"][0])


def test_a_stream_of_change_scans_never_pins_a_sweep_on_one_slow_document(queue, monkeypatch):
    from cremore.scanning import service

    real = service.extract

    def extract(data, *, filename="", limits=service.DEFAULT_LIMITS, progress=None):
        if filename == "obj/120":  # a large document: the parser reports progress while it works
            for _ in range(20):
                time.sleep(0.02)
                progress()
        return real(data, filename=filename, limits=limits, progress=progress)

    monkeypatch.setattr(service, "extract", extract)
    bucket = Bucket(delay=0.005)
    env = sweep_env(queue, monkeypatch, bucket, look=0.1)  # the real 5 s; this parse takes 0.4 s
    sweep = env.enqueue("BASELINE")
    assert env.worker.process_next()
    cursors = give_way(env, bucket, sweep, lambda key: key >= "obj/100")
    # An attempt starting at the document reads it to the end before it may give way.
    assert cursors == sorted(set(cursors)) and env.repo.get_job(sweep.id).objects == 300


def test_a_delta_listing_unchanged_keys_does_not_give_way_before_it_commits_one(queue, monkeypatch):
    bucket = Bucket(page=100)
    env = sweep_env(queue, monkeypatch, bucket, look=0.1)
    assert env.finish(env.enqueue("BASELINE")).status == "SUCCEEDED"
    bucket.modified["obj/290"] = datetime.now(UTC)  # the only change since
    delta = env.enqueue("DELTA")
    assert env.worker.process_next()  # its plan
    start = env.now["value"]
    event = env.enqueue("EVENT", "EVENT", ["obj/150"], start + timedelta(seconds=5))
    assert env.worker.process_next()  # the change scan's plan

    def listing():
        time.sleep(0.05)  # a long run of unchanged keys: nothing to commit while they are listed
        env.now["value"] = start + timedelta(seconds=6)

    bucket.on_list, reads = listing, len(bucket.reads)
    assert env.worker.process_next()  # the DELTA lists every page and reads the one change
    bucket.on_list = None
    root = env.root(delta)
    assert (root["status"], root["error"], root["attempts"]) == ("SUCCEEDED", None, 1)
    assert bucket.reads[reads:] == ["obj/290"] and env.finish(event).status == "SUCCEEDED"


def test_a_gap_a_change_scan_found_while_a_sweep_gave_way_is_kept_when_the_sweep_ends(queue, monkeypatch):
    import dataclasses

    from cremore.scanning import service
    from cremore.scanning.scope import root_identity

    real, reads = service.extract, {"obj/050": 0}

    def extract(data, *, filename="", limits=service.DEFAULT_LIMITS, progress=None):
        result = real(data, filename=filename, limits=limits, progress=progress)
        if filename == "obj/050":
            reads["obj/050"] += 1
            if reads["obj/050"] == 2:  # changed since the sweep read it: now cut at the text limit
                return dataclasses.replace(result, complete=False, reason="TEXT_LIMIT")
        return result

    monkeypatch.setattr(service, "extract", extract)
    bucket = Bucket()
    env = sweep_env(queue, monkeypatch, bucket)
    start = env.now["value"]
    sweep = env.enqueue("BASELINE")
    assert env.worker.process_next()
    event = env.enqueue("EVENT", "EVENT", ["obj/050"], start + timedelta(seconds=10))
    assert env.worker.process_next()

    def due(key):
        if key == "obj/100":
            env.now["value"] = start + timedelta(seconds=11)

    bucket.on_read = due
    assert env.worker.process_next()  # the sweep reads obj/050 whole, then gives way
    bucket.on_read = None
    assert env.root(sweep)["error"] == "YIELDED_TO_EVENT" and reads["obj/050"] == 1
    bucket.objects["obj/050"] = b"changed content, now long"
    assert env.finish(event).status == "SUCCEEDED"  # the change scan finds the gap
    state_id = root_identity(env.conn.id, env.root(sweep)["payload"]["scope"])
    assert ScanStore(env.repo).root(state_id)["inspection_gaps"] == [["obj/050", "TEXT_LIMIT"]]
    env.now["value"] = start + timedelta(seconds=13)
    done = env.finish(sweep)
    # The resumed sweep never read obj/050 again: the gap stays reported, by the root and the run.
    assert done.status == "SUCCEEDED" and done.coverage["inspection_gaps"] == 1
    assert ScanStore(env.repo).root(state_id)["inspection_gaps"] == [["obj/050", "TEXT_LIMIT"]]


def test_a_gap_found_while_a_sweep_gave_way_survives_an_attempt_stopped_before_its_first_commit(queue, monkeypatch):
    import dataclasses

    from cremore.scanning import service
    from cremore.scanning.scope import root_identity
    from cremore.worker import runtime

    real_extract, reads = service.extract, {"obj/050": 0}

    def extract(data, *, filename="", limits=service.DEFAULT_LIMITS, progress=None):
        result = real_extract(data, filename=filename, limits=limits, progress=progress)
        if filename == "obj/050":
            reads["obj/050"] += 1
            if reads["obj/050"] == 2:
                return dataclasses.replace(result, complete=False, reason="TEXT_LIMIT")
        return result

    monkeypatch.setattr(service, "extract", extract)
    late, real = [0.0], time.monotonic
    monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: real() + late[0]))
    bucket = Bucket()
    env = sweep_env(queue, monkeypatch, bucket)
    start = env.now["value"]
    sweep = env.enqueue("BASELINE")
    assert env.worker.process_next()
    event = env.enqueue("EVENT", "EVENT", ["obj/050"], start + timedelta(seconds=10))
    assert env.worker.process_next()

    def due(key):
        if key == "obj/100":
            env.now["value"] = start + timedelta(seconds=11)

    bucket.on_read = due
    assert env.worker.process_next()
    bucket.on_read = None
    assert env.root(sweep)["error"] == "YIELDED_TO_EVENT"
    bucket.objects["obj/050"] = b"changed content, now long"
    assert env.finish(event).status == "SUCCEEDED"
    state_id = root_identity(env.conn.id, env.root(sweep)["payload"]["scope"])
    assert ScanStore(env.repo).root(state_id)["inspection_gaps"] == [["obj/050", "TEXT_LIMIT"]]
    env.now["value"] = start + timedelta(seconds=13)
    # The resumed attempt reserves its first requests, then its seconds budget is up before anything commits.
    bucket.on_list = lambda: late.__setitem__(0, 100_000.0)
    assert env.worker.process_next()
    bucket.on_list = None
    assert ScanStore(env.repo).root(state_id)["inspection_gaps"] == [["obj/050", "TEXT_LIMIT"]]


@pytest.mark.parametrize("reconciled", [False, (datetime.now(UTC) - timedelta(days=4)).isoformat(), "not-a-time"],
                         ids=["never", "four-days-ago", "unreadable"])
def test_a_root_without_a_recent_whole_full_scan_does_not_give_way_and_is_read_through(queue, monkeypatch, reconciled):
    """Its first scan, or a root whose sweeps kept giving way: the sweep runs to the end in one attempt (a whole run
    that settles removals) and the change scan waits for it."""
    bucket = Bucket()
    env = sweep_env(queue, monkeypatch, bucket, reconciled=reconciled)
    start = env.now["value"]
    sweep = env.enqueue("BASELINE")
    assert env.worker.process_next()
    event = env.enqueue("EVENT", "EVENT", ["obj/250"], start + timedelta(seconds=10))
    assert env.worker.process_next()

    def due(key):
        if key == "obj/020":
            env.now["value"] = start + timedelta(seconds=11)

    bucket.on_read = due
    assert env.worker.process_next()
    bucket.on_read = None
    root = env.root(sweep)
    assert (root["status"], root["error"], root["attempts"]) == ("SUCCEEDED", None, 1)
    assert env.repo.get_job(sweep.id).objects == 300
    assert env.finish(event).status == "SUCCEEDED"


TOKEN = ("ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4").encode()


def exposure_status(env, key):
    [status] = [e.status for e in env.repo.exposures_for_connection(env.conn.id) if e.location == key]
    return status


def sweep_gives_way(env, bucket, deleted, on_read=None):
    """A sweep gives way, once it reads obj/020, to a change scan of obj/250, which finds that key's exposure; the
    ``deleted`` objects go once the change scan has run. ``on_read(key)`` runs too as the sweep reads. The sweep, due
    to resume, and the cursor it resumes after."""
    start = env.now["value"]
    sweep = env.enqueue("BASELINE")
    assert env.worker.process_next()
    event = env.enqueue("EVENT", "EVENT", ["obj/250"], start + timedelta(seconds=10))
    assert env.worker.process_next()

    def due(key):
        if on_read is not None:
            on_read(key)
        if key == "obj/020":
            env.now["value"] = start + timedelta(seconds=11)

    bucket.on_read = due
    assert env.worker.process_next()
    bucket.on_read = None
    root = env.root(sweep)
    assert root["error"] == "YIELDED_TO_EVENT"
    assert env.finish(event).status == "SUCCEEDED"
    for key in deleted:
        del bucket.objects[key]
    env.now["value"] = start + timedelta(seconds=13)
    return sweep, root["checkpoint"]["last_key"]


@pytest.mark.parametrize("refused", [False, True], ids=["head-404", "head-denied"])
def test_a_resumed_sweep_settles_removals_after_its_cursor_and_before_it_on_a_head_s_404(queue, monkeypatch, refused):
    """The resumed attempt lists every approved key after its cursor, so an object deleted there is gone. One at or
    before the cursor, which it neither lists nor reads, is gone once a HEAD answers 404; a HEAD refused (AccessDenied,
    403) settles nothing."""
    bucket = Bucket()
    bucket.objects["obj/005"] = bucket.objects["obj/250"] = TOKEN
    if refused:
        bucket.head_denied.add("obj/005")
    env = sweep_env(queue, monkeypatch, bucket)
    sweep, cursor = sweep_gives_way(env, bucket, ["obj/005", "obj/250"])
    assert "obj/005" < cursor < "obj/250"
    assert (exposure_status(env, "obj/005"), exposure_status(env, "obj/250")) == ("OPEN", "OPEN")
    assert bucket.heads == []
    done = env.finish(sweep)
    assert (done.status, done.objects_failed) == ("SUCCEEDED", 0)
    assert (exposure_status(env, "obj/005"), exposure_status(env, "obj/250")) == (
        "OPEN" if refused else "REMOVED", "REMOVED")
    assert bucket.heads == ["obj/005"]  # the watched key after the cursor is settled by the listing


def test_a_resumed_sweep_stopped_again_settles_nothing(queue, monkeypatch):
    """Stopped by its budget before its listing's end, the resumed attempt checks nothing before its cursor and settles
    nothing after it."""
    from cremore.worker import runtime

    late, real = [0.0], time.monotonic
    monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: real() + late[0]))
    bucket = Bucket()
    bucket.objects["obj/005"] = bucket.objects["obj/250"] = TOKEN
    env = sweep_env(queue, monkeypatch, bucket)
    sweep, _cursor = sweep_gives_way(env, bucket, ["obj/005", "obj/250"])
    assert (exposure_status(env, "obj/005"), exposure_status(env, "obj/250")) == ("OPEN", "OPEN")

    def deadline(key):
        if key == "obj/280":  # listed past the deleted key, then the seconds budget is up
            late[0] = 100_000.0

    bucket.on_read = deadline
    env.finish(sweep)
    assert env.root(sweep)["result"]["stopped_reason"] == "BUDGET_SECONDS"
    assert (exposure_status(env, "obj/005"), exposure_status(env, "obj/250")) == ("OPEN", "OPEN")
    assert bucket.heads == []


def test_an_earlier_failure_deleted_before_a_resumed_sweep_s_cursor_is_removed_and_no_longer_failed(
        queue, monkeypatch):
    """An object with an exposure that an earlier run could not read: the sweep reads it again once (refused), gives
    way, and the object is deleted meanwhile. The resumed attempt does not read it again (``retried``); its HEAD's 404
    removes the exposure, drops the key from the root's failures and from the run's failed count."""
    bucket = Bucket()
    bucket.objects["obj/010"] = TOKEN
    env = sweep_env(queue, monkeypatch, bucket)
    assert env.finish(env.enqueue("BASELINE")).status == "SUCCEEDED"  # a whole run finds the exposure
    store = ScanStore(env.repo)
    store.save_root(env.state_id, env.conn.id, {**store.root(env.state_id), "failed_keys": ["obj/010"]})
    bucket.denied.add("obj/010")  # a later run could not read it, and none can now
    bucket.modified = dict.fromkeys(bucket.objects, datetime(2021, 1, 1, tzinfo=UTC))  # all changed: read again
    sweep, cursor = sweep_gives_way(env, bucket, ["obj/010"])
    assert cursor > "obj/010" and exposure_status(env, "obj/010") == "OPEN"
    assert env.root(sweep)["checkpoint"]["retried"] is True and bucket.reads.count("obj/010") == 2
    done = env.finish(sweep)
    assert (done.status, done.objects_failed) == ("SUCCEEDED", 0)
    assert bucket.reads.count("obj/010") == 2 and bucket.heads == ["obj/010"]
    assert exposure_status(env, "obj/010") == "REMOVED" and store.root(env.state_id)["failed_keys"] == []


def test_an_earlier_failure_a_resumed_run_reads_again_and_finds_deleted_is_removed_and_no_longer_failed(
        queue, monkeypatch):
    """The same evidence through the retry pass: a resumed run reads the earlier failures at or before its cursor
    again first, and a GET's 404 is gone, not failed, as a HEAD's is."""
    bucket = Bucket()
    bucket.objects["obj/010"] = TOKEN
    env = sweep_env(queue, monkeypatch, bucket)
    assert env.finish(env.enqueue("BASELINE")).status == "SUCCEEDED"  # a whole run finds the exposure
    store = ScanStore(env.repo)
    store.save_root(env.state_id, env.conn.id, {
        **store.root(env.state_id), "failed_keys": ["obj/010"], "resume_after": "obj/100",
        "resume_detection_digest": env.worker.orchestrator.detection_policy_digest})  # a stopped run could not read it
    del bucket.objects["obj/010"]
    done = env.finish(env.enqueue("BASELINE"))
    assert (done.status, done.objects_failed) == ("SUCCEEDED", 0)
    assert bucket.reads.count("obj/010") == 2 and bucket.heads == []  # read again, so never checked
    assert exposure_status(env, "obj/010") == "REMOVED" and store.root(env.state_id)["failed_keys"] == []


def test_an_object_deleted_between_its_listing_and_its_read_is_never_counted_failed_by_a_later_attempt(
        queue, monkeypatch):
    """A listed object's GET answers 404: the attempt keeps it out of its failures, so the attempt resumed after the
    sweep gives way neither counts it failed nor leaves it in the root's failed keys."""
    in_order(monkeypatch)
    bucket = Bucket()
    env = sweep_env(queue, monkeypatch, bucket)

    def deletes(key):
        if key == "obj/010":
            bucket.objects.pop("obj/015")  # listed already

    sweep, cursor = sweep_gives_way(env, bucket, [], on_read=deletes)
    kept = env.root(sweep)["checkpoint"]["failed_keys"]  # what a later attempt and a budget stop carry on
    assert cursor > "obj/015"
    done = env.finish(sweep)
    assert (done.status, done.objects_failed) == ("SUCCEEDED", 0)
    assert bucket.reads.count("obj/015") == 1 and ScanStore(env.repo).root(env.state_id)["failed_keys"] == []
    assert kept == []


def test_a_resumed_sweep_checks_at_most_its_cap_of_keys_before_its_cursor(queue, monkeypatch):
    """More deleted objects before the cursor than the HEADs one resumed run makes: as many as the cap are checked and
    settled, from a place the run id picks; the others stay as they are, for the next whole run or another resumed run."""
    from cremore_aws_provider.collectors import s3

    monkeypatch.setattr(s3, "MAX_REMOVAL_CHECKS", 2)
    bucket = Bucket()
    gone = ["obj/003", "obj/005", "obj/007"]
    for key in gone:
        bucket.objects[key] = TOKEN
    env = sweep_env(queue, monkeypatch, bucket)
    sweep, cursor = sweep_gives_way(env, bucket, gone)
    assert cursor > gone[-1]
    assert env.finish(sweep).status == "SUCCEEDED"
    assert len(bucket.heads) == 2 and set(bucket.heads) < set(gone)  # which two: the run id picks
    assert [exposure_status(env, key) for key in gone] == ["REMOVED" if key in bucket.heads else "OPEN" for key in gone]


def test_a_resumed_sweep_does_not_give_way_while_it_checks_keys_before_its_cursor(queue, monkeypatch):
    """Once all it listed is committed the attempt no longer looks for a waiting change scan: one falling due during
    its HEADs waits, and the attempt settles what its listing proved and what its HEADs confirmed, checking nothing
    twice."""
    from cremore_aws_provider.collectors import s3

    monkeypatch.setattr(s3, "MAX_REMOVAL_CHECKS", 2)
    bucket = Bucket()
    gone = ["obj/003", "obj/005", "obj/250"]
    for key in gone:
        bucket.objects[key] = TOKEN
    env = sweep_env(queue, monkeypatch, bucket)
    sweep, cursor = sweep_gives_way(env, bucket, gone)
    assert "obj/005" < cursor < "obj/250"
    start = env.now["value"]
    event = env.enqueue("EVENT", "EVENT", ["obj/290"], start + timedelta(seconds=5))
    assert env.worker.process_next()  # its plan; its root waits for its debounce
    bucket.on_head = lambda key: env.now.__setitem__("value", start + timedelta(seconds=6))  # due at the first HEAD
    assert env.finish(sweep).status == "SUCCEEDED"
    assert sorted(bucket.heads) == ["obj/003", "obj/005"]
    assert [exposure_status(env, key) for key in gone] == ["REMOVED"] * 3
    assert env.finish(event).status == "SUCCEEDED"


def test_a_policy_sweep_reads_nothing_of_a_root_a_whole_run_reread_under_the_current_policy(queue, monkeypatch):
    from cremore.scanning.scope import root_identity

    bucket = Bucket()
    env = sweep_env(queue, monkeypatch, bucket, reconciled=False)
    baseline = env.enqueue("BASELINE")
    assert env.finish(baseline).status == "SUCCEEDED"
    state_id = root_identity(env.conn.id, env.root(baseline)["payload"]["scope"])
    store, current = ScanStore(env.repo), env.worker.orchestrator.detection_policy_digest

    def policy_changed():  # an upgrade changed the detection policy: the root was last read under the old one
        store.save_root(state_id, env.conn.id, {**store.root(state_id), "detection_digest": "0" * 64})

    lists = []
    bucket.on_list = lambda: lists.append(1)
    policy_changed()
    reconcile = env.enqueue("RECONCILE", "SCHEDULE")
    assert env.worker.process_next()  # the schedule's run starts first
    sweep = env.enqueue("POLICY_SWEEP", "POLICY_SWEEP")
    assert env.finish(reconcile).status == "SUCCEEDED" and lists  # read whole under the current policy
    assert store.root(state_id)["detection_digest"] == current
    lists.clear()
    reads = len(bucket.reads)
    done = env.finish(sweep)
    assert done.status == "SUCCEEDED" and done.objects == 0 and lists == [] and len(bucket.reads) == reads
    result = env.root(sweep)["result"]
    assert (result["objects"], result["policy_current"], result["detection_policy_digest"]) == (0, 1, current)
    # With no whole run since the policy changed, the sweep reads the root.
    policy_changed()
    again = env.finish(env.enqueue("POLICY_SWEEP", "POLICY_SWEEP"))
    assert again.status == "SUCCEEDED" and lists and again.objects == 300
    assert store.root(state_id)["detection_digest"] == current


def test_a_policy_sweep_reads_a_root_with_unread_objects_and_reports_open_gaps_when_it_reads_nothing(
        queue, monkeypatch):
    bucket = Bucket()
    env = sweep_env(queue, monkeypatch, bucket, reconciled=False)
    assert env.finish(env.enqueue("BASELINE")).status == "SUCCEEDED"  # read whole under the current policy
    store, lists = ScanStore(env.repo), []
    bucket.on_list = lambda: lists.append(1)
    # An object the whole run could not read: the sweep reads the root, that object included.
    store.save_root(env.state_id, env.conn.id, {**store.root(env.state_id), "failed_keys": ["obj/005"]})
    swept = env.finish(env.enqueue("POLICY_SWEEP", "POLICY_SWEEP"))
    assert swept.status == "SUCCEEDED" and lists and "policy_current" not in env.root(swept)["result"]
    assert not store.root(env.state_id)["failed_keys"]
    # Nothing left unread but a gap still open: nothing is read, and the gap is reported as any run of the root does.
    lists.clear()
    store.save_root(env.state_id, env.conn.id, {**store.root(env.state_id),
                                                 "inspection_gaps": [["obj/007", "TEXT_LIMIT"]]})
    skipped = env.finish(env.enqueue("POLICY_SWEEP", "POLICY_SWEEP"))
    result = env.root(skipped)["result"]
    assert lists == [] and result["policy_current"] == 1
    assert (result["inspection_gaps"], result["root_coverage_complete"]) == (1, False)
    assert (skipped.coverage["inspection_gaps"], skipped.coverage["root_coverage_complete"]) == (1, False)


def test_a_policy_sweep_reading_nothing_after_an_earlier_attempt_reports_what_that_attempt_read(queue, monkeypatch):
    in_order(monkeypatch)
    bucket = Bucket()
    env = sweep_env(queue, monkeypatch, bucket, state={  # read whole under an older policy
        "watermark": (datetime.now(UTC) - timedelta(days=1)).isoformat(), "detection_digest": "0" * 64})
    sweep = env.enqueue("POLICY_SWEEP", "POLICY_SWEEP")
    assert env.worker.process_next()  # its plan

    def dies(key):
        if key == "obj/100":
            raise PowerLoss()  # the objects read before it are committed first

    bucket.on_read = dies
    with pytest.raises(PowerLoss):
        env.worker.process_next()
    bucket.on_read = None
    committed = env.root(sweep)["checkpoint"]
    objects, read = committed["objects"], committed["bytes"]
    assert objects > 0 and read > 0
    store = ScanStore(env.repo)  # meanwhile the root is read whole under the current policy
    store.save_root(env.state_id, env.conn.id, {**store.root(env.state_id),
                                                 "detection_digest": env.worker.orchestrator.detection_policy_digest})
    env.now["value"] += timedelta(seconds=121)  # the crashed attempt's lease runs out
    done = env.finish(sweep)
    result = env.root(sweep)["result"]
    assert result["policy_current"] == 1 and (result["objects"], result["bytes"]) == (objects, read)
    assert (done.status, done.objects, done.coverage["bytes"]) == ("SUCCEEDED", objects, read)


def test_a_held_delta_whose_listing_runs_out_of_requests_leaves_no_cursor(queue, monkeypatch):
    """A held DELTA (an upgrade's change run, policy_hold) stopped as it lists: the key it reached names no prefix read
    under the current policy, so the next full scan must not resume after it."""
    in_order(monkeypatch)
    bucket = Bucket(page=10)
    for key in ("obj/005", "obj/105"):  # changed since the older policy read the root
        bucket.modified[key] = datetime.now(UTC) - timedelta(hours=1)
    read = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    env = sweep_env(queue, monkeypatch, bucket, budgets={"requests": 4, "bytes": 10_000_000, "seconds": 600},
                    state={"watermark": read, "detection_digest": "0" * 64})
    job = env.enqueue("DELTA", "SCHEDULE", policy_hold=True)
    assert env.finish(job).status == "SUCCEEDED"
    root = env.root(job)
    # Pages 1 to 3 and obj/005; the 4th page is one request too many.
    assert (root["result"]["stopped_reason"], bucket.reads, root["checkpoint"]["last_key"]) == (
        "BUDGET_REQUESTS", ["obj/005"], "obj/005")
    assert root["result"]["policy_held"] == 1
    state = ScanStore(env.repo).root(env.state_id)
    assert "resume_after" not in state and (state["watermark"], state["detection_digest"]) == (read, "0" * 64)


def test_a_budget_stop_whose_last_commit_failed_resumes_after_the_last_committed_object(queue, monkeypatch):
    from cremore.scanning import service
    from cremore.scanning.scope import root_identity
    from cremore.worker import runtime

    monkeypatch.setattr(service, "BATCH_SECONDS", 100.0)  # a batch commits at 64 objects, or at the stop
    bucket = Bucket()
    env = sweep_env(queue, monkeypatch, bucket, budgets={"requests": 10_000, "bytes": 10_000_000, "seconds": 30})
    late, failing, committed = [0.0], [False], []
    real = time.monotonic
    monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: real() + late[0]))

    def deadline(key):
        if key == "obj/100":  # the run's time is up, and committing what it read since fails
            late[0], failing[0] = 60.0, True

    bucket.on_read = deadline
    cache = ScanStore.cache

    def flaky(self, connection_id, root_id, subject, *args, **kwargs):
        if failing[0]:  # the stop's own flush fails mid-way: its objects roll back
            failing[0] = False
            raise RuntimeError("synthetic transient database failure")
        cache(self, connection_id, root_id, subject, *args, **kwargs)
        committed.append(subject)

    monkeypatch.setattr(ScanStore, "cache", flaky)
    job = env.enqueue("BASELINE")
    assert env.worker.process_next()  # its plan
    assert env.worker.process_next()  # its root, until the seconds budget stops it
    root = env.root(job)
    state = ScanStore(env.repo).root(root_identity(env.conn.id, root["payload"]["scope"]))
    assert root["result"]["stopped_reason"] == "BUDGET_SECONDS" and len(bucket.reads) > 64
    # The cursor and the counts are what was committed, never the objects of the batch that rolled back.
    assert committed == KEYS[:64] and root["checkpoint"]["last_key"] == state["resume_after"] == "obj/063"
    assert root["result"]["objects"] == 64


def test_a_cancelled_run_counts_the_requests_its_plan_reserved(queue):
    tasks, repo, _now = queue
    parent = repo.enqueue_job(ScanJob(kind="scope"))
    tasks.seed_next_job()
    seed = tasks.claim(run_id=parent.id)
    tasks.checkpoint(seed["id"], seed["token"], {"requests": 7})  # a Notion plan's search walk reserved them
    repo.request_job_cancel(parent.id)
    assert tasks.release_cancelled(seed["id"], seed["token"])
    assert tasks.finalize_runs() == 1
    done = repo.get_job(parent.id)
    assert done.status == "CANCELLED" and done.coverage["requests"] == 7
