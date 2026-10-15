"""No network: API -> durable queue -> paginated aggregate -> saved UI evidence."""

import copy
import datetime as dt
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.dashboard_test import _aws_key_credential
from cremore.config import Settings
from cremore.coverage import credential_usage as usage
from cremore.coverage.coverage_test import approved_aws
from cremore.coverage.coverage_test import repo as repo  # noqa: PLC0414
from cremore.db import task_store
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414
from cremore.db.task_store import TaskStore
from cremore.worker import JobWorker

TOKEN = "synthetic-usage-admin-" + "z" * 32


class Trail:
    def __init__(self, count=10051):
        self.count, self.calls = count, []
        self.interrupt = None

    def describe_regions(self, **kwargs):
        return {"Regions": [{"RegionName": "us-east-1"}]}

    def lookup_events(self, **kwargs):
        self.calls.append(kwargs)
        if self.interrupt:
            self.interrupt()
        offset = int(kwargs.get("NextToken") or 0)
        end = min(offset + 50, self.count)
        return {"Events": [{"EventId": str(i), "EventName": "ListBuckets", "EventSource": "s3.amazonaws.com",
                            "EventTime": dt.datetime(2026, 10, 1, tzinfo=dt.UTC) + dt.timedelta(seconds=i),
                            "CloudTrailEvent": json.dumps({"eventName": "ListBuckets", "readOnly": True,
                                                           "requestParameters": {"secret": "NEVER_SAVE_RAW"}})}
                           for i in range(offset, end)], **({"NextToken": str(end)} if end < self.count else {})}


@pytest.fixture
def setup(repo, monkeypatch):
    account = approved_aws(repo)
    settings = Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32)
    repo.put_setting("aws_usage_lookup", {"enabled": True}, "admin")
    cred = _aws_key_credential(repo)
    trail = Trail()
    session = SimpleNamespace(account_id=account.account_id, pin="1:1", client=lambda *args: trail,
                              evidence=lambda: {"collected_account_id": account.account_id, "collected_via": "ROLE"})
    sessions = SimpleNamespace(open=lambda *args: session,
                              refusal=lambda *args: (None, repo.get_aws_account(account.id), {"revision": 1}))
    worker = JobWorker(repo, settings=settings, aws_sessions=sessions)
    worker.poll_triggers = lambda: None
    monkeypatch.setattr(usage.time, "sleep", lambda *_: None)
    clock = [dt.datetime.now(dt.UTC)]
    monkeypatch.setattr(task_store, "_clock", lambda *args: clock[0])
    app = create_app(repo=repo, settings=settings, aws_sessions=sessions, usage_service_factory=lambda _: None)
    client = TestClient(app)
    client.headers.update({"Authorization": "Bearer " + TOKEN})
    return SimpleNamespace(repo=repo, settings=settings, cred=cred, account=account, session=session,
                           worker=worker, trail=trail, clock=clock, client=client,
                           path=f"/api/v1/credentials/{cred.id}/usage")


def start(s):
    response = s.client.post(s.path + "/refresh?background=true")
    assert response.status_code == 202, response.json()
    job = usage.job_for(s.repo, s.repo.get_credential(s.cred.id))
    return job


def tick(s):
    s.clock[0] += dt.timedelta(seconds=2)
    return s.worker.process_next()


def test_background_inventory_owner_is_local_and_keeps_provenance(setup, monkeypatch):
    from cremore.api.credential_governance import credential_governance
    from cremore.coverage.models import Batch, ConnectionSpec, Contract, Finish, Observation
    from cremore.coverage.store import CoverageStore

    s = setup
    arn = s.cred.principal_arn
    s.repo.update_credential(s.cred.id, principal_arn=None, principal_arn_source=None)
    store = CoverageStore(s.repo)
    row, _ = store.create(ConnectionSpec(name="Synthetic IAM", provider="aws_iam", account_id=s.account.account_id), "admin")
    run = store.start(row["id"], row["revision"], str(s.cred.id), Contract(engine_digest="a" * 64).model_dump())
    store.append(row["id"], run["id"], Batch(index=0, items=[Observation(
        reference=arn, principal_arn=arn, account_id=s.account.account_id, evidence="ISSUED",
        credential_type="AWS_ACCESS_KEY", identifier=s.cred.identifier, state="Active")]))
    store.finish(row["id"], run["id"], Finish(batch_count=1, item_count=1, status="COMPLETE"))
    opened = []
    monkeypatch.setattr(s.worker.aws_sessions, "open", lambda account, purpose: opened.append(account) or s.session)
    start(s)
    assert opened == [s.account.account_id]
    assert not s.trail.calls
    before = s.repo.get_credential(s.cred.id)
    evidence = before.usage_snapshot["owner_lookup"]
    assert before.principal_arn_source == "IAM_INVENTORY"
    assert evidence["run_id"] == str(run["id"])
    monkeypatch.setattr(usage, "_metadata", lambda *args: ({}, {}))
    tick(s)
    after = s.repo.get_credential(s.cred.id)
    assert after.usage_snapshot["owner_lookup"] == evidence
    owner = next(fact for fact in credential_governance(after, [], None)["metadata"] if fact["key"] == "provider_owner")
    assert owner["source"] == "IAM_INVENTORY" and owner["observed_at"] == evidence["observed_at"]


def test_background_over_ten_thousand_resumes_and_keeps_small_exact_summary(setup):
    s = setup
    job = start(s)
    assert start(s).id == job.id  # no duplicate concurrent refresh
    assert not s.trail.calls  # the HTTP request does no CloudTrail I/O
    assert s.client.post(s.path + "/refresh").status_code == 409
    assert tick(s)
    assert s.repo.get_job(job.id).status == "RUNNING"
    before = s.client.get(s.path).json()
    assert before["summary"]["events"] == 1000 and before["refresh_job"]["status"] == "RUNNING"
    assert "cursor" not in json.dumps(before) and "NextToken" not in json.dumps(before)
    # A fresh worker, not an in-process closure, continues from the committed cursor.
    resumed = JobWorker(s.repo, settings=s.settings, aws_sessions=s.worker.aws_sessions)
    resumed.poll_triggers = lambda: None
    s.worker = resumed
    for _ in range(15):
        tick(s)
        if s.repo.get_job(job.id).status == "SUCCEEDED":
            break
    assert s.repo.get_job(job.id).status == "SUCCEEDED"
    view = s.client.get(s.path).json()
    assert view["collection_status"] == "COMPLETE" and view["summary"]["events"] == 10051
    assert view["summary"]["services"]["s3"]["calls"] == 10051
    assert view["techniques"]["total_events"] == 10051 and view["techniques"]["classified_events"] == 10051
    assert len(view["events"]) == 100 and view["events"][0]["event_id"] == "10050"
    assert view["events"][0]["technique_id"] == "T1619"
    assert len({(c["StartTime"], c["EndTime"]) for c in s.trail.calls}) == 1
    assert len(s.trail.calls) == 202 and len(json.dumps(view)) < 100_000
    assert "NEVER_SAVE_RAW" not in json.dumps(s.repo.get_credential(s.cred.id).usage_snapshot)


@pytest.mark.parametrize("reason", ["cancel", "switch", "access"])
def test_collection_checks_cancellation_switch_and_approval_before_next_page(setup, reason, monkeypatch):
    s = setup
    monkeypatch.setattr(usage, "PAGES_PER_TURN", 1)
    job = start(s)
    tick(s)
    saved = copy.deepcopy(s.repo.get_credential(s.cred.id).usage_snapshot)
    if reason == "cancel":
        response = s.client.post(f"/api/v1/source-scan-jobs/{job.id}/cancel")
        assert response.status_code == 200
    elif reason == "switch":
        s.repo.put_setting("aws_usage_lookup", {"enabled": False}, "admin")
    else:
        # Use the actual approval key so a changed approval cannot pass the commit fence.
        from cremore_aws_provider import aws_access
        s.repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER], {"revision": 2}, "admin")
        s.worker.aws_sessions.refusal = lambda *_: ("AWS_ACCESS_REVISION_CHANGED", None, None)
    tick(s)
    assert len(s.trail.calls) == 1
    assert s.repo.get_credential(s.cred.id).usage_snapshot == saved
    assert s.repo.get_job(job.id).status in ("CANCELLED", "FAILED")


def test_request_budget_stops_without_claiming_completion(setup, monkeypatch):
    s = setup
    monkeypatch.setattr(usage.pages, "MAX_REQUESTS", 2)
    job = start(s)
    tick(s)
    view = s.client.get(s.path).json()
    assert view["collection_status"] == "PARTIAL" and view["summary"]["events"] == 100
    assert view["coverage"][0]["error_code"] == "REQUEST_LIMIT_REACHED"
    assert s.repo.get_job(job.id).status == "SUCCEEDED" and len(s.trail.calls) == 2


def test_cancel_during_provider_read_discards_page_and_cursor(setup):
    s = setup
    job = start(s)
    s.trail.interrupt = lambda: s.repo.request_job_cancel(job.id)
    tick(s)
    assert s.repo.get_job(job.id).status == "CANCELLED"
    saved = s.repo.get_credential(s.cred.id).usage_snapshot
    assert saved["summary"]["events"] == 0
    task = TaskStore(s.repo).list_for_run(job.id)[0]
    assert task["checkpoint"]["cursor"] is None


def test_expired_lease_cannot_publish_a_page(setup, monkeypatch):
    s = setup
    job = start(s)
    s.trail.interrupt = lambda: s.clock.__setitem__(0, s.clock[0] + dt.timedelta(seconds=300))
    tick(s)
    assert s.repo.get_credential(s.cred.id).usage_snapshot["summary"]["events"] == 0
    assert TaskStore(s.repo).list_for_run(job.id)[0]["checkpoint"]["cursor"] is None


def test_page_and_cursor_roll_back_together_then_recover_without_duplicate_counts(setup, monkeypatch):
    s = setup
    s.trail.count = 151
    job = start(s)
    checkpoint = TaskStore.checkpoint
    crashed = []

    class Crash(BaseException):
        pass

    def crash_after_page(self, task_id, token, state):
        if state.get("cursor") and not crashed:
            crashed.append(True)
            raise Crash()
        return checkpoint(self, task_id, token, state)

    monkeypatch.setattr(TaskStore, "checkpoint", crash_after_page)
    with pytest.raises(Crash):
        tick(s)
    assert s.repo.get_credential(s.cred.id).usage_snapshot["summary"]["events"] == 0
    assert TaskStore(s.repo).list_for_run(job.id)[0]["checkpoint"]["cursor"] is None
    s.clock[0] += dt.timedelta(seconds=121)
    tick(s)
    assert s.repo.get_job(job.id).status == "SUCCEEDED"
    assert s.repo.get_credential(s.cred.id).usage_snapshot["summary"]["events"] == 151
    assert [c.get("NextToken") for c in s.trail.calls] == [None, None, "50", "100", "150"]


def test_aggregate_cannot_be_promoted_when_the_account_is_unverified(setup):
    s = setup
    s.trail.count = 1
    start(s)
    tick(s)
    snapshot = s.repo.get_credential(s.cred.id).usage_snapshot
    s.repo.update_credential(s.cred.id, usage_snapshot={**snapshot, "collected_account_id": "999999999999"})
    assert s.client.get(s.path).json()["collection_status"] == "ACCOUNT_UNVERIFIED"


def test_login_expiry_keeps_checkpoint_and_resumes_without_recounting(setup, monkeypatch):
    from cremore_aws_provider.aws_identity import AwsLoginRequired

    s = setup
    s.trail.count = 101
    monkeypatch.setattr(usage, "PAGES_PER_TURN", 1)
    job = start(s)
    tick(s)
    saved = copy.deepcopy(s.repo.get_credential(s.cred.id).usage_snapshot)

    def expired():
        raise AwsLoginRequired()

    s.trail.interrupt = expired
    tick(s)
    assert s.repo.get_credential(s.cred.id).usage_snapshot == saved
    assert usage.public_job(s.repo, s.repo.get_credential(s.cred.id))["error_code"] == "AWS_LOGIN_REQUIRED"
    s.trail.interrupt = None
    s.clock[0] += dt.timedelta(seconds=61)
    tick(s)
    tick(s)
    assert s.repo.get_job(job.id).status == "SUCCEEDED"
    assert s.client.get(s.path).json()["summary"]["events"] == 101
    assert [c.get("NextToken") for c in s.trail.calls] == [None, "50", "50", "100"]


@pytest.mark.parametrize("cursor", ["50", 42])
def test_invalid_or_cyclic_cursor_preserves_partial_evidence(setup, monkeypatch, cursor):
    s = setup
    monkeypatch.setattr(usage, "PAGES_PER_TURN", 1)
    start(s)
    tick(s)
    s.trail.lookup_events = lambda **_: {"Events": [], "NextToken": cursor}
    tick(s)
    view = s.client.get(s.path).json()
    assert view["collection_status"] == "FAILED" and view["summary"]["events"] == 50
    assert view["coverage"][0]["status"] == "FAILED"


def test_time_budget_is_incomplete(setup, monkeypatch):
    s = setup
    monkeypatch.setattr(usage, "MAX_ELAPSED", dt.timedelta(seconds=-1))
    start(s)
    tick(s)
    assert not s.trail.calls
    assert s.client.get(s.path).json()["coverage"][0]["error_code"] == "TIME_LIMIT_REACHED"


def test_old_synchronous_refresh_cannot_overwrite_new_background_result(setup):
    s = setup
    def collect(*args):
        job = usage.enqueue(s.repo, s.settings, s.cred, s.session, s.cred.principal_arn)
        s.repo.complete_job(job.id, 0, 0)
        return usage.empty_usage(s.cred.identifier)
    client = TestClient(create_app(repo=s.repo, settings=s.settings, aws_sessions=s.worker.aws_sessions,
                                  usage_service_factory=lambda _: SimpleNamespace(
                                      collect=collect, last_used=usage.CredentialUsageService(lambda _: None).last_used)))
    response = client.post(s.path + "/refresh", headers={"Authorization": "Bearer " + TOKEN})
    assert response.status_code == 409
    assert usage.job_for(s.repo, s.repo.get_credential(s.cred.id)) is not None


def test_postgres_concurrent_refreshes_deduplicate_and_tasks_serialize_by_account(pg):
    _, repo = pg
    account = approved_aws(repo)
    settings = Settings(FINGERPRINT_KEY="ab" * 32)
    cred = _aws_key_credential(repo)
    session = SimpleNamespace(account_id=account.account_id, pin="1:1")
    with ThreadPoolExecutor(max_workers=6) as pool:
        jobs = list(pool.map(lambda _: usage.enqueue(repo, settings, cred, session, cred.principal_arn), range(6)))
    assert len({job.id for job in jobs}) == 1
    other = repo.upsert_credential(cred.model_copy(update={"id": None, "fingerprint": "another-key", "usage_snapshot": None}))
    usage.enqueue(repo, settings, other, session, other.principal_arn)
    tasks = TaskStore(repo)
    tasks.seed_next_job()
    tasks.seed_next_job()
    assert tasks.claim() is not None
    assert tasks.claim() is None  # same account's second key cannot race LookupEvents


@pytest.mark.parametrize("outcome,status,error", [
    ("success", "AVAILABLE", ""), ("no_information", "NO_INFORMATION", ""),
    ("AccessDenied", "DENIED", "AccessDenied"), ("ThrottlingException", "FAILED", "ThrottlingException"),
    ("NoSuchEntity", "FAILED", "NoSuchEntity"), ("malformed", "FAILED", "ValueError"),
    ("ExpiredToken", "LOGIN", ""),
    ("not_requested", "NOT_REQUESTED", ""),
])
def test_background_last_used_status_survives_pages_and_prior_success(setup, monkeypatch, outcome, status, error):
    from cremore.api.credential_governance import credential_governance
    from cremore.api.finding_evidence import credential_metadata

    s = setup
    s.trail.count = 0
    observed = dt.datetime(2026, 10, 2, tzinfo=dt.UTC)
    native = observed - dt.timedelta(days=1)
    selected = ["success"]

    class ProviderError(Exception):
        def __init__(self, code):
            self.response = {"Error": {"Code": code, "Message": "RAW_MESSAGE_MUST_NOT_BE_SAVED"}}

    def last_used(**_):
        if selected[0] == "success":
            return {"AccessKeyLastUsed": {"LastUsedDate": native, "ServiceName": "s3", "Region": "us-east-1"}}
        if selected[0] == "no_information":
            return {"AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}}
        if selected[0] == "malformed":
            return {"AccessKeyLastUsed": {"LastUsedDate": "RAW_MESSAGE_MUST_NOT_BE_SAVED"}}
        raise ProviderError(selected[0])

    monkeypatch.setattr(s.trail, "get_access_key_last_used", last_used, raising=False)
    service = usage.CredentialUsageService
    monkeypatch.setattr(usage, "CredentialUsageService", lambda factory, ec2, iam, **kwargs: service(
        factory, ec2, None if selected[0] == "not_requested" else iam, **kwargs, now=lambda: observed))
    first = start(s)
    tick(s)
    assert s.repo.get_job(first.id).status == "SUCCEEDED"
    assert s.repo.get_credential(s.cred.id).last_used_at == native
    selected[0] = outcome
    start(s)
    previous = copy.deepcopy(s.repo.get_credential(s.cred.id).usage_snapshot)
    tick(s)
    stored = s.repo.get_credential(s.cred.id)
    assert stored.last_used_at == native and stored.last_used_service == "s3" and stored.last_used_region == "us-east-1"
    if status == "LOGIN":
        assert stored.usage_snapshot == previous
        assert usage.public_job(s.repo, stored)["error_code"] == "AWS_LOGIN_REQUIRED"
        return
    expected = {"status": status, "observed_at": observed.isoformat()}
    if error:
        expected["error_code"] = error
    if status == "AVAILABLE":
        expected.update(at=native.isoformat(), service="s3", region="us-east-1")
    assert stored.usage_snapshot["last_used"] == expected
    assert s.client.get(s.path).json()["last_used"] == expected
    assert "RAW_MESSAGE_MUST_NOT_BE_SAVED" not in json.dumps(stored.usage_snapshot)
    meta = credential_metadata(stored, [])
    fact = next(f for f in credential_governance(stored, [])["metadata"] if f["key"] == "last_used_at")
    if status == "AVAILABLE":
        assert meta["last_used_at"]["observed_at"] == fact["observed_at"] == observed.isoformat()
    else:
        expected_availability = "NOT_OBSERVED" if status == "NO_INFORMATION" else "NOT_COLLECTED"
        assert meta["field_status"]["last_used_at"] == fact["availability"] == expected_availability
        assert fact["value"] is None and "last_used_at" not in meta
