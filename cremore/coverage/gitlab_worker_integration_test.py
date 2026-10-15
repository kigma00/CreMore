"""GitLab CI-variable metadata through the worker, stores and coverage report."""

import hashlib
import json
from functools import partial
from types import SimpleNamespace

import pytest
from cremore_gitlab_provider.metadata import adapter
from cremore_gitlab_provider.metadata.http import CollectionError
from cremore_gitlab_provider.metadata.tests.test_extensions import (
    VALUE,
    Fixture,
    spec,
    variable,
)

from cremore.coverage import METADATA_JOB_KIND
from cremore.coverage.correlation import report, scope_revision
from cremore.coverage.metadata_job_test import (
    repo as repo,  # noqa: PLC0414 -- shared pytest fixture
)
from cremore.coverage.metadata_store import MetadataStore
from cremore.coverage.models import Contract
from cremore.coverage.store import CoverageStore
from cremore.db.task_store import TaskStore
from cremore.detection import ResourceRef
from cremore.detection.engine import EngineConfig
from cremore.domain.models import ScanJob
from cremore.scanning.orchestrator import Orchestrator
from cremore.worker import JobWorker

KEY = b"gitlab-worker-synthetic-hmac-key-32bytes"
SCOPE = [{"kind": "group", "id": "10"}]


def queued(repo, connection_spec):
    store = MetadataStore(repo)
    connection, _ = store.create(connection_spec, "synthetic-admin")
    job = repo.enqueue_job(ScanJob(kind=METADATA_JOB_KIND, payload={
        "provider": "gitlab", "coverage_connection_id": str(connection["id"]),
        "coverage_revision": connection["revision"],
    }))
    return store, connection, job


def prepared(repo):
    orchestrator = Orchestrator(repo, config=EngineConfig(fingerprint_key=KEY))
    scanned = orchestrator.scan_resource(VALUE.encode(), ResourceRef(
        source_type="github", location="synthetic-gitlab-ci-integration"), verify=False)
    assert scanned.credentials == 1
    worker = JobWorker(repo, orchestrator=orchestrator, metadata_secret_resolver=SimpleNamespace(
        resolve=lambda ref: {"token": "SYNTHETIC_ADMIN"}))
    return worker


def coverage(repo, worker):
    contract = Contract(engine_digest=worker.orchestrator.engine.detection_digest,
                        policy_digest=worker.orchestrator.coverage_policy_digest).model_dump()
    return report(repo, contract, fingerprint_key_id=hashlib.sha256(KEY).hexdigest())


def confirm_scope(repo):
    repo.put_setting("coverage_scope", {
        "confirmed": True, "revision": scope_revision(CoverageStore(repo).list_connections()),
    }, "synthetic-admin")


def test_opt_in_worker_persists_gitlab_fingerprint_and_matches_exposure(repo, monkeypatch):
    connection_spec = spec(["ci_variables"], values=True, scopes=SCOPE)
    client = Fixture(connection_spec, {"/groups/10/variables": [variable()]})
    monkeypatch.setattr(adapter, "collect_pages", partial(adapter.collect_pages, client=client))
    store, connection, job = queued(repo, connection_spec)
    worker = prepared(repo)
    confirm_scope(repo)
    assert worker.process_next()
    done = repo.get_job(job.id)
    assert done.status == "SUCCEEDED", done.error
    run = store.connection_runs(connection["id"])["items"][0]
    assert run["status"] == "COMPLETE", run["reasons"]
    rows = list(store.iter_records(run["id"]))
    matches = [row["value_match"] for row in rows if row.get("value_match")]
    assert len(matches) == 1 and matches[0]["evidence"] == "VALUE"
    view = coverage(repo, worker)
    assert view["summary"]["matched"] == 1 and view["summary"]["no_vault_match"] == 0
    assert not view["scope_reasons"], view["scope_reasons"]
    assert view["items"][0]["state"] == "MATCHED"
    assert any(path == "/groups/10/variables" for path, _ in client.calls)
    serialized = json.dumps([rows, TaskStore(repo).list_for_run(job.id), view], default=str)
    assert VALUE not in serialized and "SYNTHETIC_ADMIN" not in serialized
    assert matches[0]["fingerprint"] not in json.dumps(view, default=str)


def test_metadata_only_worker_never_creates_value_match_or_absence_claim(repo, monkeypatch):
    connection_spec = spec(["ci_variables"], scopes=SCOPE)
    client = Fixture(connection_spec, {"/groups/10/variables": [variable()]})
    monkeypatch.setattr(adapter, "collect_pages", partial(adapter.collect_pages, client=client))
    store, connection, job = queued(repo, connection_spec)
    worker = prepared(repo)
    confirm_scope(repo)
    assert worker.process_next() and repo.get_job(job.id).status == "SUCCEEDED"
    run = store.connection_runs(connection["id"])["items"][0]
    rows = list(store.iter_records(run["id"]))
    assert run["status"] == "COMPLETE" and not any(row.get("value_match") for row in rows)
    assert VALUE not in json.dumps(rows, default=str)
    view = coverage(repo, worker)
    assert view["summary"]["unknown"] == 1 and view["summary"]["no_vault_match"] == 0
    assert "NO_VAULT_CONNECTED" in view["scope_reasons"]


@pytest.mark.parametrize("response,reason", [
    (CollectionError("PERMISSION_DENIED", "synthetic", 403), "VARIABLE_DISCOVERY_INCOMPLETE"),
    ([variable(value=None)], "VALUE_UNAVAILABLE"),
])
def test_unreadable_or_missing_values_are_partial_and_never_prove_absence(repo, monkeypatch, response, reason):
    connection_spec = spec(["ci_variables"], values=True, scopes=SCOPE)
    client = Fixture(connection_spec, {"/groups/10/variables": response})
    monkeypatch.setattr(adapter, "collect_pages", partial(adapter.collect_pages, client=client))
    store, connection, _job = queued(repo, connection_spec)
    worker = prepared(repo)
    confirm_scope(repo)
    assert worker.process_next()
    run = store.connection_runs(connection["id"])["items"][0]
    assert run["status"] == "PARTIAL" and reason in run["reasons"]
    view = coverage(repo, worker)
    assert view["summary"]["unknown"] == 1 and view["summary"]["no_vault_match"] == 0
    assert "VAULT_VALUE_SCOPE_NOT_COMPLETE" in view["scope_reasons"]


def test_worker_rejects_cross_scope_value_before_persistence(repo, monkeypatch):
    connection_spec = spec(["ci_variables"], values=True, scopes=SCOPE)
    client = Fixture(connection_spec, {"/groups/10/variables": [variable()]})
    collect = adapter.collect_pages

    def forged(*args, **kwargs):
        for page in collect(*args, client=client, **kwargs):
            for row in page.records:
                if getattr(row, "value_match", None):
                    row.value_match.reference = row.value_match.reference.replace("groups/10/", "groups/999/")
            yield page

    monkeypatch.setattr(adapter, "collect_pages", forged)
    store, connection, job = queued(repo, connection_spec)
    worker = prepared(repo)
    confirm_scope(repo)
    assert worker.process_next()
    assert repo.get_job(job.id).status == "FAILED"
    run = store.connection_runs(connection["id"])["items"][0]
    assert run["status"] == "FAILED"
    assert not any(row.get("value_match") for row in store.iter_records(run["id"]))
    view = coverage(repo, worker)
    assert view["summary"]["unknown"] == 1 and view["summary"]["no_vault_match"] == 0


def test_missing_group_or_project_scope_fails_before_collection(repo, monkeypatch):
    connection_spec = spec(["ci_variables"], values=True, scopes=[{"kind": "user", "id": "self"}],
                           options={"include_self_pat": True})
    # Storage can retain generic typed connection snapshots; the worker must
    # enforce the provider contract before resolving secrets or calling APIs.
    monkeypatch.setattr(adapter, "collect_pages", lambda *args, **kwargs: pytest.fail("Unapproved collection"))
    store, connection, job = queued(repo, connection_spec)
    worker = prepared(repo)
    confirm_scope(repo)
    assert worker.process_next()
    assert repo.get_job(job.id).status == "FAILED"
    assert repo.get_job(job.id).error == "INVALID_METADATA_PROVIDER_SCOPE"
    assert store.connection_runs(connection["id"])["total"] == 0
    view = coverage(repo, worker)
    assert view["summary"]["unknown"] == 1 and view["summary"]["no_vault_match"] == 0
