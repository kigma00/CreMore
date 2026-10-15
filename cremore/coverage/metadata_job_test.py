"""Exercise the shared metadata runner through real stores and task fences."""

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from functools import partial
from types import SimpleNamespace

import pytest
from cremore_azure_provider.metadata import adapter
from cremore_azure_provider.metadata.azure_key_vault_test import Vault, secret, spec

from cremore.coverage import METADATA_JOB_KIND, metadata_auth, metadata_job
from cremore.coverage.metadata_models import MetadataPage
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.store import CoverageError
from cremore.db import task_store
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.db.task_store import TaskStore
from cremore.domain.models import ScanJob
from cremore.worker import JobWorker


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        yield InMemoryRepository()
    else:
        engine = make_engine("sqlite:///:memory:")
        create_all(engine)
        try:
            yield SqlRepository(engine)
        finally:
            engine.dispose()


def queued(repo):
    store = MetadataStore(repo)
    connection, _ = store.create(spec(), "test")
    job = repo.enqueue_job(ScanJob(kind=METADATA_JOB_KIND, payload={
        "provider": "azure_key_vault", "coverage_connection_id": str(connection["id"]),
        "coverage_revision": connection["revision"],
    }))
    return store, connection, job


def test_azure_worker_defaults_to_metadata_without_reading_secret_values(repo, monkeypatch):
    vault = Vault({"/secrets": {"value": [secret()]}})
    monkeypatch.setattr(adapter, "collect_pages", partial(adapter.collect_pages, transport=vault))
    store, connection, job = queued(repo)
    assert JobWorker(repo).process_next()
    done = repo.get_job(job.id)
    assert done.status == "SUCCEEDED", done.error
    assert vault.calls
    assert store.inventory(connection_id=connection["id"])["total"] == 1
    run = store.connection_runs(connection["id"])["items"][0]
    assert run["status"] == "COMPLETE" and run["item_count"] > 0
    result = TaskStore(repo).list_for_run(job.id)[0]["result"]
    assert result["source_reports_total"] > 0


def test_worker_never_advances_native_stream_past_terminal_page(repo, monkeypatch):
    def pages(*args, **kwargs):
        yield MetadataPage(status="COMPLETE")
        pytest.fail("Advancing after the terminal page can perform unwanted provider I/O")

    monkeypatch.setattr(adapter, "collect_pages", pages)
    _store, _connection, job = queued(repo)
    assert JobWorker(repo).process_next()
    assert repo.get_job(job.id).status == "SUCCEEDED"


@pytest.mark.parametrize("prior_page", [False, True])
def test_wait_preserves_checkpoint_and_resumes_without_duplicate_run(repo, monkeypatch, prior_page):
    now = {"value": datetime.now(UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    seen = []

    def pages(spec, *, checkpoint, **kwargs):
        seen.append(checkpoint)
        if not checkpoint:
            if prior_page:
                yield MetadataPage(checkpoint={"phase": "started"})
            yield MetadataPage(checkpoint={"phase": "resume"}, status="WAITING",
                               reasons=["METADATA_RETRY_LATER"], retry_after_seconds=1)
        else:
            yield MetadataPage(checkpoint={"phase": "done"}, status="COMPLETE")

    monkeypatch.setattr(adapter, "collect_pages", pages)
    store, connection, job = queued(repo)
    worker = JobWorker(repo)
    assert worker.process_next()
    task = TaskStore(repo).list_for_run(job.id)[0]
    assert task["status"] == "QUEUED"
    assert task["checkpoint"]["provider"] == {"phase": "resume"}
    assert store.connection_runs(connection["id"])["total"] == int(prior_page)
    now["value"] += timedelta(seconds=2)
    assert worker.process_next()
    assert repo.get_job(job.id).status == "SUCCEEDED"
    assert seen == [{}, {"phase": "resume"}]
    assert store.connection_runs(connection["id"])["total"] == 1


def test_connection_disabled_between_pages_prevents_next_publication(repo, monkeypatch):
    store, connection, job = queued(repo)

    def pages(*args, **kwargs):
        yield MetadataPage(checkpoint={"phase": "first"})
        store.change(connection["id"], 1, "test", enabled=False)
        yield MetadataPage(status="COMPLETE")

    monkeypatch.setattr(adapter, "collect_pages", pages)
    assert JobWorker(repo).process_next()
    assert repo.get_job(job.id).status == "FAILED"
    run = store.connection_runs(connection["id"])["items"][0]
    assert run["status"] == "FAILED"
    assert "CONNECTION_REVISION_CONFLICT" in run["reasons"]


def test_principal_cannot_change_when_resuming_pages(repo, monkeypatch):
    def pages(*args, **kwargs):
        yield MetadataPage(principal_id="first", principal_verified=True)
        yield MetadataPage(principal_id="different", principal_verified=True, status="COMPLETE")

    monkeypatch.setattr(adapter, "collect_pages", pages)
    store, connection, job = queued(repo)
    assert JobWorker(repo).process_next()
    assert repo.get_job(job.id).status == "FAILED"
    run = store.connection_runs(connection["id"])["items"][0]
    assert run["status"] == "FAILED" and "COLLECTOR_PRINCIPAL_MISMATCH" in run["reasons"]


def test_resolved_mapping_is_cleared_when_pre_collection_planning_fails(repo, monkeypatch):
    _store, _connection, job = queued(repo)
    job.payload["retry_from_run"] = str(job.id)
    tasks = TaskStore(repo)
    tasks.enqueue(job.id, "test", {})
    task = tasks.claim()
    values = {"token": "synthetic-credential-for-cleanup-only"}
    monkeypatch.setattr(metadata_auth, "resolve_slots", lambda *args: values)
    with pytest.raises(CoverageError, match="METADATA_RECOLLECTION_UNSUPPORTED"):
        metadata_job.run(SimpleNamespace(repo=repo), job, task,
                         lambda: tasks.fenced(task["id"], task["token"]))
    assert values == {}


def test_provider_io_occurs_outside_publish_transaction(repo, monkeypatch):
    _store, _connection, job = queued(repo)
    tasks = TaskStore(repo)
    tasks.enqueue(job.id, "test", {})
    task = tasks.claim()
    in_transaction = []

    @contextmanager
    def transaction():
        with tasks.fenced(task["id"], task["token"]) as bound:
            in_transaction.append(True)
            try:
                yield bound
            finally:
                in_transaction.pop()

    def pages(*args, **kwargs):
        assert not in_transaction
        yield MetadataPage()
        assert not in_transaction
        yield MetadataPage(status="COMPLETE")

    monkeypatch.setattr(adapter, "collect_pages", pages)
    metadata_job.run(SimpleNamespace(repo=repo), job, task, transaction)
    assert tasks.list_for_run(job.id)[0]["status"] == "SUCCEEDED"


def test_authentication_echo_is_refused_before_any_page_is_saved(repo, monkeypatch):
    marker = "synthetic-authentication-marker"
    values = {"token": marker}
    monkeypatch.setattr(metadata_auth, "resolve_slots", lambda *args: values)
    monkeypatch.setattr(adapter, "collect_pages", lambda *args, **kwargs: iter([
        MetadataPage(checkpoint={"cursor": marker}, status="COMPLETE"),
    ]))
    store, connection, job = queued(repo)
    assert JobWorker(repo).process_next()
    assert repo.get_job(job.id).status == "FAILED"
    assert store.connection_runs(connection["id"])["total"] == 0
    assert values == {}
    task = TaskStore(repo).list_for_run(job.id)[0]
    assert marker not in str(task)


def test_missing_terminal_report_is_failure_not_empty_success(repo, monkeypatch):
    monkeypatch.setattr(adapter, "collect_pages", lambda *args, **kwargs: iter([MetadataPage()]))
    store, connection, job = queued(repo)
    assert JobWorker(repo).process_next()
    assert repo.get_job(job.id).status == "FAILED"
    run = store.connection_runs(connection["id"])["items"][0]
    assert run["status"] == "FAILED" and "METADATA_TERMINAL_REPORT_REQUIRED" in run["reasons"]
    # The failed job names the run it closed, so what it read stays readable from the logs.
    assert repo.get_job(job.id).coverage["coverage_run_ids"] == [str(run["id"])]


def test_missing_authentication_keeps_actionable_error_before_run_exists(repo):
    from cremore_atlassian_provider.tests.test_common_adapter import spec as atlassian_spec

    store = MetadataStore(repo)
    connection, _ = store.create(atlassian_spec(), "test")
    job = repo.enqueue_job(ScanJob(kind=METADATA_JOB_KIND, payload={
        "provider": "atlassian", "coverage_connection_id": str(connection["id"]),
        "coverage_revision": connection["revision"],
    }))
    assert JobWorker(repo).process_next()
    assert repo.get_job(job.id).error == "METADATA_SECRET_UNAVAILABLE"
    assert TaskStore(repo).list_for_run(job.id)[0]["error"] == "METADATA_SECRET_UNAVAILABLE"
    assert store.connection_runs(connection["id"])["total"] == 0


@pytest.mark.parametrize("resumed", [False, True])
def test_authentication_failure_closes_resumed_run_without_exposing_backend_text(repo, monkeypatch, resumed):
    store, connection, job = queued(repo)
    now = {"value": datetime.now(UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    worker = JobWorker(repo)
    if resumed:
        monkeypatch.setattr(adapter, "collect_pages", lambda *args, **kwargs: iter([
            MetadataPage(checkpoint={"page": 1}),
            MetadataPage(status="WAITING", retry_after_seconds=1, reasons=["METADATA_RETRY_LATER"]),
        ]))
        assert worker.process_next()
        now["value"] += timedelta(seconds=2)

    def fail(*args):
        raise RuntimeError("synthetic backend diagnostic: do not publish")

    monkeypatch.setattr(metadata_auth, "resolve_slots", fail)
    assert worker.process_next()
    assert repo.get_job(job.id).error == "METADATA_COLLECTION_FAILED"
    assert TaskStore(repo).list_for_run(job.id)[0]["error"] == "METADATA_COLLECTION_FAILED"
    runs = store.connection_runs(connection["id"])
    assert runs["total"] == int(resumed)
    if resumed:
        assert runs["items"][0]["status"] == "FAILED"
        assert runs["items"][0]["reasons"] == ["METADATA_COLLECTION_FAILED"]


def test_exhausted_worker_recovery_closes_run_and_keeps_committed_records(repo, monkeypatch):
    store, connection, job = queued(repo)
    tasks = TaskStore(repo)
    now = {"value": datetime.now(UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    pages = list(adapter.collect_pages(spec(), secrets={}, checkpoint={}, check=lambda: None,
                                      transport=Vault({"/secrets": {"value": [secret()]}})))
    records = [record for page in pages for record in page.records]

    def interrupted(*args, checkpoint, **kwargs):
        if not checkpoint:
            yield MetadataPage(records=records, checkpoint={"page": 1})
        raise SystemExit("synthetic process interruption")

    monkeypatch.setattr(adapter, "collect_pages", interrupted)
    tasks.seed_next_job()
    for _ in range(3):
        task = tasks.claim(lease_seconds=1)
        assert task is not None
        with pytest.raises(SystemExit):
            metadata_job.run(SimpleNamespace(repo=repo), repo.get_job(job.id), task,
                             partial(tasks.fenced, task["id"], task["token"]))
        assert tasks.finalize_runs() == 0
        now["value"] += timedelta(seconds=2)
    assert tasks.claim(lease_seconds=1) is None
    assert tasks.finalize_runs() == 1
    assert repo.get_job(job.id).status == "FAILED"
    assert repo.get_job(job.id).error == "LEASE_RETRY_LIMIT"
    run = store.connection_runs(connection["id"])["items"][0]
    assert run["status"] == "FAILED" and run["reasons"] == ["LEASE_RETRY_LIMIT"]
    assert run["finished_at"] is not None
    assert len(list(store.iter_records(run["id"]))) == len(records)
    assert tasks.finalize_runs() == 0

    # A fresh job can collect again immediately; the failed run no longer owns the slot.
    monkeypatch.setattr(adapter, "collect_pages", lambda *args, **kwargs: iter([MetadataPage(status="COMPLETE")]))
    retry = repo.enqueue_job(ScanJob(kind=METADATA_JOB_KIND, payload=dict(job.payload)))
    assert JobWorker(repo).process_next()
    assert repo.get_job(retry.id).status == "SUCCEEDED"
    assert store.connection_runs(connection["id"])["total"] == 2


def test_metadata_collection_pause_defers_the_task_and_resume_continues_the_same_run(repo, monkeypatch):
    now = {"value": datetime.now(UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    store, connection, job = queued(repo)
    seen = []

    def pages(spec, *, checkpoint, check, **kwargs):
        seen.append(checkpoint)
        if not checkpoint:
            yield MetadataPage(checkpoint={"page": 1})
            # The operator pauses while the adapter is about to make its next request.
            repo.put_setting(metadata_job.pause_key(connection["id"]), {"job_id": str(job.id)}, "analyst")
            check()
            pytest.fail("a paused collection must not read further")
        yield MetadataPage(checkpoint={"page": 2}, status="COMPLETE")

    monkeypatch.setattr(adapter, "collect_pages", pages)
    worker = JobWorker(repo)
    assert worker.process_next()
    task = TaskStore(repo).list_for_run(job.id)[0]
    assert (task["status"], task["error"]) == ("QUEUED", "METADATA_COLLECTION_PAUSED")
    assert task["checkpoint"]["provider"] == {"page": 1}
    run = store.connection_runs(connection["id"])["items"][0]
    assert run["status"] == "RUNNING" and repo.get_job(job.id).status == "RUNNING"
    # Still paused: the task is claimed again and deferred without calling the adapter.
    now["value"] += timedelta(seconds=metadata_job.PAUSE_RECHECK_SECONDS + 1)
    assert worker.process_next()
    assert len(seen) == 1 and TaskStore(repo).list_for_run(job.id)[0]["status"] == "QUEUED"
    repo.put_setting(metadata_job.pause_key(connection["id"]), {"job_id": None}, "analyst")
    now["value"] += timedelta(seconds=metadata_job.PAUSE_RECHECK_SECONDS + 1)
    assert worker.process_next()
    assert repo.get_job(job.id).status == "SUCCEEDED"
    assert seen == [{}, {"page": 1}]
    runs = store.connection_runs(connection["id"])
    # One run, finished by the resumed attempt (PARTIAL only because these pages carry no source report).
    assert runs["total"] == 1 and runs["items"][0]["status"] in ("COMPLETE", "PARTIAL")
    assert runs["items"][0]["finished_at"] is not None and "METADATA_COLLECTION_PAUSED" not in runs["items"][0]["reasons"]


def test_metadata_collection_pause_for_another_job_is_inert(repo, monkeypatch):
    _store, connection, job = queued(repo)
    repo.put_setting(metadata_job.pause_key(connection["id"]), {"job_id": "an-earlier-job"}, "analyst")
    monkeypatch.setattr(adapter, "collect_pages", lambda *args, **kwargs: iter([MetadataPage(status="COMPLETE")]))
    assert JobWorker(repo).process_next()
    assert repo.get_job(job.id).status == "SUCCEEDED"


def test_metadata_collection_stop_closes_the_run_as_stopped_and_frees_the_connection(repo, monkeypatch):
    store, connection, job = queued(repo)

    def pages(spec, *, checkpoint, check, **kwargs):
        yield MetadataPage(checkpoint={"page": 1})
        repo.request_job_cancel(job.id)
        check()
        pytest.fail("a stopped collection must not read further")

    monkeypatch.setattr(adapter, "collect_pages", pages)
    assert JobWorker(repo).process_next()
    assert repo.get_job(job.id).status == "CANCELLED"
    run = store.connection_runs(connection["id"])["items"][0]
    assert (run["status"], run["reasons"]) == ("FAILED", ["METADATA_COLLECTION_STOPPED"])
    assert run["finished_at"] is not None
    # The stopped job names the run it closed: its report stays readable from the logs.
    assert repo.get_job(job.id).coverage["coverage_run_ids"] == [str(run["id"])]
    monkeypatch.setattr(adapter, "collect_pages", lambda *args, **kwargs: iter([MetadataPage(status="COMPLETE")]))
    again = repo.enqueue_job(ScanJob(kind=METADATA_JOB_KIND, payload=dict(job.payload)))
    assert JobWorker(repo).process_next()
    assert repo.get_job(again.id).status == "SUCCEEDED"
    assert store.connection_runs(connection["id"])["total"] == 2


def test_metadata_collection_stop_while_paused_closes_the_open_run(repo, monkeypatch):
    now = {"value": datetime.now(UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    store, connection, job = queued(repo)

    def pages(spec, *, checkpoint, check, **kwargs):
        yield MetadataPage(checkpoint={"page": 1})
        repo.put_setting(metadata_job.pause_key(connection["id"]), {"job_id": str(job.id)}, "analyst")
        check()

    monkeypatch.setattr(adapter, "collect_pages", pages)
    worker = JobWorker(repo)
    assert worker.process_next()
    assert repo.request_job_cancel(job.id).status == "CANCELLING"
    worker.process_next()
    assert repo.get_job(job.id).status == "CANCELLED"
    run = store.connection_runs(connection["id"])["items"][0]
    assert (run["status"], run["reasons"]) == ("FAILED", ["METADATA_COLLECTION_STOPPED"])


def _age_pause(repo, connection_id, age):
    key, when = metadata_job.pause_key(connection_id), datetime.now(UTC) - age
    if getattr(repo, "engine", None) is None:
        repo.installation_settings[key]["updated_at"] = when
    else:
        from sqlalchemy import update

        from cremore.db.schema import installation_settings

        with repo.engine.begin() as conn:
            conn.execute(update(installation_settings).where(installation_settings.c.key == key).values(updated_at=when))


def test_metadata_collection_pause_without_a_run_ends_the_job_after_the_pause_limit(repo, monkeypatch):
    now = {"value": datetime.now(UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    store, connection, job = queued(repo)
    # Paused before its first page: there is no run to close, only the job slot to give back.
    repo.put_setting(metadata_job.pause_key(connection["id"]), {"job_id": str(job.id)}, "analyst")
    monkeypatch.setattr(adapter, "collect_pages", lambda *args, **kwargs: pytest.fail("a paused collection must not start"))
    worker = JobWorker(repo)
    assert worker.process_next()
    assert TaskStore(repo).list_for_run(job.id)[0]["status"] == "QUEUED"
    _age_pause(repo, connection["id"], metadata_job.RUN_LIFETIME - timedelta(minutes=15))
    now["value"] += timedelta(seconds=metadata_job.PAUSE_RECHECK_SECONDS + 1)
    assert worker.process_next()
    assert TaskStore(repo).list_for_run(job.id)[0]["status"] == "QUEUED"  # not yet: 15 minutes are left
    _age_pause(repo, connection["id"], metadata_job.RUN_LIFETIME - timedelta(minutes=5))
    now["value"] += timedelta(seconds=metadata_job.PAUSE_RECHECK_SECONDS + 1)
    assert worker.process_next()
    worker.process_next()
    done = repo.get_job(job.id)
    assert (done.status, done.error) == ("FAILED", "METADATA_COLLECTION_PAUSE_EXPIRED")
    assert store.connection_runs(connection["id"])["total"] == 0
    # The connection can collect again at once.
    monkeypatch.setattr(adapter, "collect_pages", lambda *args, **kwargs: iter([MetadataPage(status="COMPLETE")]))
    again = repo.enqueue_job(ScanJob(kind=METADATA_JOB_KIND, payload=dict(job.payload)))
    assert JobWorker(repo).process_next()
    assert repo.get_job(again.id).status == "SUCCEEDED"


def test_the_pause_is_read_inside_the_checks_own_transaction(monkeypatch):
    # One transaction per check, not a second one for the pause setting.
    from cremore.db.task_store import _BoundEngine

    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    try:
        repo = SqlRepository(engine)
        _store, connection, job = queued(repo)
        reads, original = [], SqlRepository.get_setting

        def spy(self, key):
            if key == metadata_job.pause_key(connection["id"]):
                reads.append(isinstance(self.engine, _BoundEngine))
            return original(self, key)

        def pages(spec, *, checkpoint, check, **kwargs):
            check()
            check()
            yield MetadataPage(status="COMPLETE")

        monkeypatch.setattr(SqlRepository, "get_setting", spy)
        monkeypatch.setattr(adapter, "collect_pages", pages)
        assert JobWorker(repo).process_next()
        assert repo.get_job(job.id).status == "SUCCEEDED"
        assert len(reads) >= 3 and all(reads)
    finally:
        engine.dispose()


def _age_run(repo, rid, age):
    store = MetadataStore(repo)
    started = datetime.now(UTC) - age
    if getattr(repo, "engine", None) is None:
        store.memory["runs"][rid]["started_at"] = started
    else:
        from sqlalchemy import update

        with repo.engine.begin() as conn:
            conn.execute(update(store.runs).where(store.runs.c.id == rid).values(started_at=started))


def test_metadata_collection_pause_expires_before_the_run_does(repo, monkeypatch):
    now = {"value": datetime.now(UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: now["value"])
    records = [record for page in adapter.collect_pages(spec(), secrets={}, checkpoint={}, check=lambda: None,
               transport=Vault({"/secrets": {"value": [secret()]}})) for record in page.records]
    store, connection, job = queued(repo)

    def pages(spec, *, checkpoint, check, **kwargs):
        yield MetadataPage(records=records, checkpoint={"page": 1})
        repo.put_setting(metadata_job.pause_key(connection["id"]), {"job_id": str(job.id)}, "analyst")
        check()
        pytest.fail("a paused collection must not read further")

    monkeypatch.setattr(adapter, "collect_pages", pages)
    worker = JobWorker(repo)
    assert worker.process_next()
    run = store.connection_runs(connection["id"])["items"][0]
    assert run["status"] == "RUNNING"
    # Still paused near the end of the run's lifetime: the next look closes it with what it committed.
    _age_run(repo, run["id"], metadata_job.RUN_LIFETIME - timedelta(minutes=5))
    now["value"] += timedelta(seconds=metadata_job.PAUSE_RECHECK_SECONDS + 1)
    assert worker.process_next()
    run = store.connection_runs(connection["id"])["items"][0]
    assert run["status"] == "PARTIAL" and "METADATA_COLLECTION_PAUSE_EXPIRED" in run["reasons"]
    assert run["item_count"] == len(records) and run["finished_at"] is not None
    assert repo.get_job(job.id).status == "SUCCEEDED"
