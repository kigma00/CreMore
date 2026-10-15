"""Issued AWS keys outlive a running, failed or partial IAM collection, and a long collection renews
its scanner session. Synthetic fakes only."""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from cremore.coverage import JOB_KIND
from cremore.coverage.correlation import report
from cremore.coverage.coverage_test import ACCOUNT, KEY, USER, approved_aws, contract, save
from cremore.coverage.coverage_test import repo as repo  # noqa: PLC0414 -- pytest fixture re-export
from cremore.coverage.models import ConnectionSpec, Observation
from cremore.coverage.store import CoverageStore
from cremore.detection.engine import EngineConfig
from cremore.domain.models import ScanJob
from cremore.scanning.orchestrator import Orchestrator
from cremore.worker.worker import JobWorker

KEPT, OTHER = "AKIA0123456789ABCDEF", "AKIAZZZZZZZZZZZZZZZZ"
OTHER_USER = f"arn:aws:iam::{ACCOUNT}:user/denied"


def issued(identifier, user=USER):
    return Observation(reference=user, account_id=ACCOUNT, evidence="ISSUED", credential_type="AWS_ACCESS_KEY",
                       identifier=identifier)


def listed(repo):
    view = report(repo, contract())
    return view["summary"]["issued"], {(row["identifier"], row["issued"]["current_evidence"])
                                        for row in view["items"] if row["origin"] == "ISSUANCE"}


def test_issued_keys_stay_through_a_running_failed_or_partial_collection_as_history(repo):
    approved_aws(repo)
    store = CoverageStore(repo)
    owner, _ = store.create(ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT), "admin")
    save(store, owner, [issued(KEPT), issued(OTHER, OTHER_USER)])
    assert listed(repo) == (2, {(KEPT, True), (OTHER, True)})
    # A run in progress lists nothing yet: the last finished run stands, no longer as current.
    running = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), contract())
    assert listed(repo) == (2, {(KEPT, False), (OTHER, False)})
    store.abort(owner["id"], running["id"], "INVENTORY_INTERRUPTED")
    assert listed(repo) == (2, {(KEPT, False), (OTHER, False)})
    # One user's keys could not be listed: that key stays as history from the last complete run.
    denied = Observation(reference=OTHER_USER, account_id=ACCOUNT, evidence="UNRESOLVED", reason="IAM_KEY_LIST_FAILED")
    save(store, owner, [issued(KEPT), denied], status="PARTIAL", reasons=["IAM_KEY_LIST_FAILED"])
    assert listed(repo) == (2, {(KEPT, True), (OTHER, False)})
    # A complete run is the new baseline: a key it no longer lists is gone.
    save(store, owner, [issued(KEPT)])
    assert listed(repo) == (1, {(KEPT, True)})


def test_a_long_iam_collection_opens_its_scanner_session_again_before_it_expires(repo):
    account = approved_aws(repo)
    now = datetime(2026, 10, 13, tzinfo=UTC)
    clock, opened, calls = [now], [], []

    class IAM:
        def __init__(self, session):
            self.session = session

        def __getattr__(self, operation):
            def call(**kwargs):
                calls.append((operation, self.session))
                clock[0] += timedelta(minutes=11)  # each read takes eleven of the session's fifteen minutes
                if operation == "list_users":
                    return {"Users": [{"Arn": USER, "UserName": "robot"}]}
                if operation == "list_access_keys":
                    return {"AccessKeyMetadata": [{"AccessKeyId": KEPT, "Status": "Active"}]}
                return {}
            return call

    def open_session(*_args):
        opened.append(clock[0])
        number = len(opened)
        return SimpleNamespace(pin="1:1", credentials={"Expiration": clock[0] + timedelta(minutes=15)},
                               client=lambda service, *_a, **_k: IAM(number))

    sessions = SimpleNamespace(open=open_session, refusal=lambda *_: (None, account, {"revision": 1}),
                               now=lambda: clock[0])
    store = CoverageStore(repo)
    owner, _ = store.create(ConnectionSpec(name="IAM", provider="aws_iam", account_id=ACCOUNT), "admin")
    job = repo.enqueue_job(ScanJob(kind=JOB_KIND, payload={"provider": "aws", "account_id": ACCOUNT,
        "coverage_connection_id": str(owner["id"]), "coverage_revision": 1, "access_pin": "1:1"}))
    worker = JobWorker(repo, orchestrator=Orchestrator(repo, config=EngineConfig(fingerprint_key=KEY)), aws_sessions=sessions)
    assert worker.process_next()
    assert repo.get_job(job.id).status == "SUCCEEDED", repo.get_job(job.id).error
    # The second read came within five minutes of the first session's expiry: a new session, a new client.
    assert [session for _operation, session in calls][:2] == [1, 2] and len(opened) >= 2
    assert any(item["identifier"] == KEPT for item in store.snapshots(owner["id"])[0]["items"])
