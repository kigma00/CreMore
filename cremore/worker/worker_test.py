"""Worker tests over the in-memory repository."""

from __future__ import annotations

import logging
import uuid

from cremore.db.repository import InMemoryRepository
from cremore.domain.models import ScanJob
from cremore.worker import JobWorker

GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"


def test_worker_runs_inline_job():
    repo = InMemoryRepository()
    job = repo.enqueue_job(ScanJob(kind="inline", payload={
        "text": f"token = {GH}", "source_type": "github",
        "resource_name": "org/repo", "location": "app.py", "exposure": "public",
    }))
    worker = JobWorker(repo)

    assert worker.process_next() is True
    done = repo.get_job(job.id)
    assert done.status == "SUCCEEDED"
    assert done.objects == 1
    assert done.findings == 1
    assert len(repo.list_findings()) == 1

    # Queue now empty.
    assert worker.process_next() is False


def test_a_task_runner_claims_without_polling_the_triggers():
    """A supervised runner leaves triggers to the control loop, which keeps polling while it scans."""
    repo = InMemoryRepository()
    job = repo.enqueue_job(ScanJob(kind="inline", payload={"text": f"token = {GH}", "exposure": "internal"}))
    worker = JobWorker(repo)
    polled = []
    worker.poll_triggers = lambda: polled.append(True)

    assert worker.process_next(poll=False) is True
    assert repo.get_job(job.id).status == "SUCCEEDED" and polled == []
    assert worker.process_next() is False and polled == [True]  # the single loop still polls


def test_a_sweep_and_a_change_event_over_one_root_plan_the_same_root_lock():
    """The event lane lets the two runs be RUNNING together; the planned root lock keeps them off one root."""
    from cremore.db.repository import job_lane
    from cremore.db.task_store import TaskStore
    from cremore.domain.models import Connection, ScopeCatalog, ScopeProfile
    from cremore.scanning import scope

    repo = InMemoryRepository()
    conn = repo.create_connection(Connection(provider="aws", name="fixture", config={"bucket": "fixture"}))
    item = scope.resource("source", conn.id, "S3_BUCKET", "fixture", "fixture", "arn:aws:s3:::fixture", "aws")
    auth = scope.auth_revision("source", conn)
    catalog = repo.save_catalog(ScopeCatalog(kind="source", connection_id=conn.id, snapshot_id="v1",
                                             auth_revision=auth, items=[item], completeness="COMPLETE"))
    profile = repo.create_scope_profile(ScopeProfile(
        kind="source", connection_id=conn.id, name="approved", state="READY", auth_revision=auth,
        catalog_snapshot_id="v1", budgets={"requests": 20, "bytes": 10000, "seconds": 30},
        selected_roots=[{"resource_id": item["id"], "prefixes": ["config/"], "all_current_objects": False,
                         "include_future_descendants": False}]))

    def queue(trigger, mode, exact_keys=None):
        plan = scope.build_plan(profile, catalog, auth=profile.auth_revision, enabled=True)
        plan.trigger = trigger
        if exact_keys:
            plan.roots = [{**root, "exact_keys": exact_keys} for root in plan.roots]
        plan = repo.create_plan(plan)
        payload = {**scope.run_payload(plan, profile, {}, "s3"), "mode": mode}
        return repo.enqueue_job(ScanJob(kind="scope", connection_id=conn.id, payload=payload))

    worker, tasks = JobWorker(repo), TaskStore(repo)
    sweep = queue("SCHEDULE", "DELTA")
    change = queue("EVENT", "EVENT", exact_keys=["config/.env"])
    assert (job_lane(sweep.kind, sweep.payload), job_lane(change.kind, change.payload)) == ("sweep", "event")
    # Both are admitted, whichever comes first: the jobs can share one clock tick, so their order is not fixed.
    assert {tasks.seed_next_job().id, tasks.seed_next_job().id} == {sweep.id, change.id}
    assert {repo.get_job(sweep.id).status, repo.get_job(change.id).status} == {"RUNNING"}
    roots = {}
    for job in (sweep, change):
        worker.runtime.plan(repo.get_job(job.id), tasks.claim(run_id=job.id))
        [roots[job.id]] = [task for task in tasks.list_for_run(job.id) if task["kind"] != "PLAN"]
    assert roots[sweep.id]["kind"] == "DELTA" and roots[change.id]["kind"] == "EVENT"
    assert roots[sweep.id]["lock_key"] == roots[change.id]["lock_key"]
    assert roots[sweep.id]["connection_lock"] == roots[change.id]["connection_lock"] == str(conn.id)


def test_a_task_runner_probes_its_aws_identity_without_reporting_it():
    from cremore_aws_provider import aws_identity

    repo = InMemoryRepository()
    worker = JobWorker(repo, aws_identity_probe=lambda: dict(SSO))
    worker.reports_identity = False  # run_task_loop sets this: the control loop's report stands for the worker
    assert worker.aws_identity(refresh=True)["match_key"] == SSO["match_key"]
    assert repo.get_setting(aws_identity.WORKER_IDENTITY_KEY) is None
    worker.reports_identity = True
    worker.aws_identity(refresh=True)
    assert repo.get_setting(aws_identity.WORKER_IDENTITY_KEY)["value"]["match_key"] == SSO["match_key"]


def test_worker_marks_bad_job_failed_and_continues():
    repo = InMemoryRepository()
    bad = repo.enqueue_job(ScanJob(kind="s3", payload={"bucket": "b"}))  # no client factory
    worker = JobWorker(repo)

    assert worker.process_next() is True
    assert repo.get_job(bad.id).status == "FAILED"
    assert repo.get_job(bad.id).error

    # The failed scan released the slot, so the next one can be queued and run.
    good = repo.enqueue_job(ScanJob(kind="inline", payload={"text": f"k={GH}", "exposure": "internal"}))

    assert worker.process_next() is True  # good one still runs
    assert repo.get_job(good.id).status == "SUCCEEDED"


def test_content_access_is_rechecked_at_commit_and_released_on_failure():
    from cremore.collectors.base import CollectorError

    class Access:
        def __init__(self):
            self.checked, self.released = [], []

        def require_current(self, job, bound_repo=None):
            self.checked.append(bound_repo is not None)
            if bound_repo is not None:
                raise CollectorError("AWS_ACCESS_REVISION_CHANGED")

        def release(self, job):
            self.released.append(job.id)

    repo = InMemoryRepository()
    job = repo.enqueue_job(ScanJob(kind="inline", payload={"text": f"token = {GH}"}))
    access = Access()
    JobWorker(repo, aws_content_sessions=access).process_next()
    assert False in access.checked and True in access.checked
    assert access.released == [job.id]
    assert repo.get_job(job.id).status == "FAILED"
    assert repo.list_findings() == []


def test_legacy_request_guard_covers_factory_discovery_and_empty_listing():
    from cremore.collectors.base import RequestBudget

    repo = InMemoryRepository()
    job = repo.enqueue_job(ScanJob(kind="s3", payload={"bucket": "synthetic"}))
    attempts = []

    def factory(_job):
        budget = RequestBudget()
        budget.consume()
        attempts.append("discovery")

        class Listing:
            def collect(self):
                repo.request_job_cancel(job.id)
                budget.consume()
                attempts.append("must not read after cancellation")
                yield from ()

        return Listing()

    JobWorker(repo, collector_factory=factory).process_next()
    assert attempts == ["discovery"]
    assert repo.get_job(job.id).status == "CANCELLED"
    RequestBudget().consume()  # The per-run guard cannot leak into subsequent work.


def test_worker_records_unlistable_scope_as_failed_with_code():
    """No credentials / access denied must never produce a clean, empty SUCCEEDED job."""

    class NoCredsS3:
        def list_objects_v2(self, **kwargs):
            raise RuntimeError("Unable to locate credentials")

    repo = InMemoryRepository()
    job = repo.enqueue_job(ScanJob(kind="s3", payload={"bucket": "example-bucket"}))
    from cremore.worker.factory import build_collector

    worker = JobWorker(repo, collector_factory=lambda j: build_collector(j, s3_client_factory=lambda _j: NoCredsS3()))
    assert worker.process_next() is True
    done = repo.get_job(job.id)
    assert done.status == "FAILED" and done.error == "S3_LIST_FAILED: RuntimeError"


def test_worker_records_partial_runs():
    class PartlyReadableS3:
        def list_objects_v2(self, **kwargs):
            return {"Contents": [{"Key": "a", "Size": 3}, {"Key": "b", "Size": 3}], "IsTruncated": False}

        def get_object(self, Bucket, Key):
            if Key == "b":
                raise PermissionError("denied")
            import io

            return {"Body": io.BytesIO(b"abc")}

    repo = InMemoryRepository()
    job = repo.enqueue_job(ScanJob(kind="s3", payload={"bucket": "example-bucket"}))
    from cremore.worker.factory import build_collector

    JobWorker(repo, collector_factory=lambda j: build_collector(j, s3_client_factory=lambda _j: PartlyReadableS3())).process_next()
    done = repo.get_job(job.id)
    assert done.status == "SUCCEEDED" and done.objects == 1 and done.objects_failed == 1


def test_worker_credential_check_updates_the_connection_not_the_secret():
    from cremore.collectors.credential_check import CredentialCheck
    from cremore.domain.models import Connection

    repo = InMemoryRepository()
    conn = repo.create_connection(Connection(provider="github", name="app", config={"owner": "o", "repo": "r"},
                                             secret_ref="vault://github/app"))
    seen = []

    def checker(job):
        seen.append(job.payload)
        return CredentialCheck("ACTIVE", owner="ci-bot", scopes=("repo",))

    job = repo.enqueue_job(ScanJob(kind="credential-check", connection_id=conn.id,
                                   payload={"provider": "github", "owner": "o", "repo": "r", "secret_ref": "vault://github/app"}))
    assert JobWorker(repo, credential_checker=checker).process_next() is True
    assert repo.get_job(job.id).status == "SUCCEEDED"
    updated = repo.get_connection(conn.id)
    assert updated.status == "ACTIVE" and updated.last_verified_at is not None and updated.last_error is None
    assert updated.credential_evidence["owner"] == "ci-bot" and updated.credential_evidence["scopes"] == ["repo"]
    assert "token" not in updated.credential_evidence and seen[0]["secret_ref"] == "vault://github/app"

    # A rejected credential marks the connection ERROR with the safe reason.
    repo.enqueue_job(ScanJob(kind="credential-check", connection_id=conn.id,
                             payload={"provider": "github", "secret_ref": conn.secret_ref}))
    JobWorker(repo, credential_checker=lambda j: CredentialCheck("REJECTED", error="HTTP 401")).process_next()
    rejected = repo.get_connection(conn.id)
    assert rejected.status == "ERROR" and rejected.last_error == "HTTP 401"
    # Without a checker wired, the job fails rather than pretending.
    bad = repo.enqueue_job(ScanJob(kind="credential-check", connection_id=conn.id, payload={"provider": "github"}))
    JobWorker(repo).process_next()
    assert repo.get_job(bad.id).status == "FAILED"


def test_complete_connection_scan_retires_exposures_partial_does_not():
    from cremore.collectors.base import CollectedObject
    from cremore.detection import ResourceRef
    from cremore.domain.models import Connection

    repo = InMemoryRepository()
    conn = repo.create_connection(Connection(provider="github", name="app", config={"owner": "o", "repo": "r"}))
    contents = {"a.py": f"t={GH}"}

    class Fake:
        failed_objects = 0
        authoritative_listing = True

        def collect(self):
            for path, text in contents.items():
                yield CollectedObject(ResourceRef(source_type="github", resource="o/r", location=path,
                                                  metadata={"exposure": "public"}), text.encode())

    worker = JobWorker(repo, collector_factory=lambda job: Fake())
    repo.enqueue_job(ScanJob(kind="github", payload={}, connection_id=conn.id))
    worker.process_next()
    finding = repo.list_findings()[0]
    assert finding.workflow_status == "OPEN"

    # A partial run (one unreadable object) proves nothing absent: nothing retired.
    contents.clear()
    Fake.failed_objects = 1
    repo.enqueue_job(ScanJob(kind="github", payload={}, connection_id=conn.id))
    worker.process_next()
    assert repo.get_finding(finding.id).workflow_status == "OPEN"

    # A complete empty run retires the location, not the credential's risk.
    Fake.failed_objects = 0
    repo.enqueue_job(ScanJob(kind="github", payload={}, connection_id=conn.id))
    worker.process_next()
    assert repo.get_finding(finding.id).workflow_status == "OPEN"
    assert repo.get_finding(finding.id).all_locations_removed is True


def test_jobs_claimed_once():
    repo = InMemoryRepository()
    repo.enqueue_job(ScanJob(kind="inline", payload={"text": "nothing"}))
    a = repo.claim_next_job()
    b = repo.claim_next_job()
    assert a is not None and b is None  # only one claim of the single job


def test_heartbeat_touches_file_and_tolerates_bad_path(tmp_path):
    import os
    import time

    hb = tmp_path / "cremore-worker.heartbeat"
    JobWorker.beat(str(hb))
    assert hb.exists()
    first = os.path.getmtime(hb)
    time.sleep(0.05)
    JobWorker.beat(str(hb))
    assert os.path.getmtime(hb) >= first  # refreshed, never recreated with older mtime
    # An unwritable path must not raise: the probe fails, the loop keeps running.
    JobWorker.beat(str(tmp_path / "missing-dir" / "hb"))
    JobWorker.beat(None)


def test_factory_builds_collectors_by_kind():
    from cremore_aws_provider.collectors.s3 import S3Collector
    from cremore_github_provider.collectors.github import GitHubCollector
    from cremore_notion_provider.collectors.notion import NotionCollector

    from cremore.worker.factory import build_collector

    http = build_collector(
        ScanJob(kind="notion", payload={"token": "ntn_x", "max_pages": 5}),
        http_client_factory=lambda: object(),
        max_object_bytes=123,
    )
    assert isinstance(http, NotionCollector) and http.max_pages == 5 and http.max_object_bytes == 123

    gh = build_collector(
        ScanJob(kind="github", payload={"owner": "o", "repo": "r"}),
        http_client_factory=lambda: object(),
        max_object_bytes=123,
    )
    assert isinstance(gh, GitHubCollector) and gh.max_object_bytes == 123

    from cremore_github_provider.collectors.github import GitHubOrgCollector

    org = build_collector(
        ScanJob(kind="github-org", payload={"org": "acme", "max_repos": 10}),
        http_client_factory=lambda: object(),
        max_object_bytes=123,
    )
    assert isinstance(org, GitHubOrgCollector) and org.org == "acme" and org.max_object_bytes == 123

    s3 = build_collector(
        ScanJob(kind="s3", payload={"bucket": "b"}),
        s3_client_factory=lambda job: object(),
        max_object_bytes=123,
    )
    assert isinstance(s3, S3Collector) and s3.max_object_bytes == 123

    scoped = build_collector(
        ScanJob(kind="scope", payload={
            "budgets": {"requests": 7},
            "roots": [
                {"resource_type": "S3_BUCKET", "provider_resource_id": "b", "all_current_objects": True},
                {"resource_type": "GITHUB_REPOSITORY", "provider_resource_id": "o/r"},
            ],
        }),
        s3_client_factory=lambda job: object(),
        http_client_factory=lambda: object(),
        max_object_bytes=123,
    )
    assert scoped.parts[0].max_object_bytes == scoped.parts[1].max_object_bytes == 123
    assert scoped.parts[0].request_budget is scoped.parts[1].request_budget
    assert scoped.parts[0].request_budget.limit == 7


def test_worker_reads_the_dashboard_verification_switch_for_each_job():
    from cremore.scanning import verification_switch

    repo = InMemoryRepository()
    assert JobWorker(repo).verify is None  # no installation ceiling: engine default
    assert JobWorker(repo, verify=False).verify is False  # installation lock wins
    worker = JobWorker(repo, verify=True)
    assert worker.verify is True  # on by default
    repo.put_setting(verification_switch.KEY, {"enabled": False}, "admin")
    assert worker.verify is False
    repo.put_setting(verification_switch.KEY, {"enabled": True}, "admin")
    assert worker.verify is True


# --- the worker's own AWS identity ------------------------------------------

SSO = {"state": "READY", "kind": "IDENTITY_CENTER", "account_id": "111111111111",
       "match_key": "identity-center:aws:111111111111:SecurityAudit", "permission_set": "SecurityAudit"}


class _LoginExpired(Exception):
    """Shaped like botocore's UnauthorizedSSOTokenError."""


_LoginExpired.__name__ = "UnauthorizedSSOTokenError"


def _aws_worker(repo, identity, **kwargs):
    state = {"value": identity}
    worker = JobWorker(repo, aws_identity_probe=lambda: state["value"], **kwargs)
    return worker, state


def _task(repo, job):
    from cremore.db.task_store import TaskStore

    [task] = TaskStore(repo).list_for_run(job.id)
    return task


def _role_job(repo):
    return repo.enqueue_job(ScanJob(kind="s3", payload={
        "bucket": "example-bucket", "scanner_role_arn": "arn:aws:iam::123456789012:role/CredentialExposureScannerRole",
        "external_id": "external-id-0123456789"}))


def test_worker_defers_aws_work_while_signed_out_without_spending_retries():
    from cremore_aws_provider import aws_identity

    repo = InMemoryRepository()
    repo.put_setting(aws_identity.APPROVED_IDENTITY_KEY, {"match_key": SSO["match_key"]}, "admin")
    job = _role_job(repo)
    worker, _state = _aws_worker(repo, {"state": "LOGIN_REQUIRED", "error_code": "UnauthorizedSSOTokenError"},
                                collector_factory=lambda _j: (_ for _ in ()).throw(AssertionError("must not scan")))

    assert worker.process_next() is True
    task = _task(repo, job)
    assert task["status"] == "QUEUED" and task["error"] == "AWS_LOGIN_REQUIRED" and task["attempts"] == 0
    report = repo.get_setting(aws_identity.WORKER_IDENTITY_KEY)["value"]
    assert report["state"] == "LOGIN_REQUIRED" and report["checked_at"]
    assert repo.get_job(job.id).status != "FAILED"


def test_worker_holds_aws_work_when_the_identity_differs_from_the_approval():
    from cremore_aws_provider import aws_identity

    repo = InMemoryRepository()
    repo.put_setting(aws_identity.APPROVED_IDENTITY_KEY, {"match_key": "identity-center:aws:111111111111:Other"}, "admin")
    job = _role_job(repo)
    worker, _ = _aws_worker(repo, SSO)
    assert worker.aws_hold(job) == "AWS_SCANNER_IDENTITY_CHANGED"
    # non-AWS work is never held
    assert worker.aws_hold(ScanJob(kind="github", payload={"owner": "o", "repo": "r"})) is None
    repo.put_setting(aws_identity.APPROVED_IDENTITY_KEY, {"match_key": SSO["match_key"]}, "admin")
    assert worker.aws_hold(job) is None


def test_roles_anywhere_refresh_failure_is_reported_and_held_until_recovery(monkeypatch):
    from datetime import UTC, datetime, timedelta

    from botocore.exceptions import CredentialRetrievalError
    from cremore_aws_provider import aws_identity, roles_anywhere

    monkeypatch.setenv(roles_anywhere.CONFIG_ENV, "/synthetic/operator.json")
    monkeypatch.setattr(roles_anywhere, "load", lambda _: ([], datetime.now(UTC) + timedelta(days=90)))
    repo = InMemoryRepository()
    repo.put_setting(aws_identity.APPROVED_IDENTITY_KEY, {"match_key": SSO["match_key"]}, "admin")
    job = _role_job(repo)

    def refused():
        raise CredentialRetrievalError(provider="custom-process", error_msg="synthetic-sensitive-output")

    worker = JobWorker(repo, aws_identity_probe=refused,
                       collector_factory=lambda _j: (_ for _ in ()).throw(AssertionError("must not scan")))
    assert worker.process_next() is True
    task = _task(repo, job)
    assert task["status"] == "QUEUED" and task["error"] == "AWS_ROLES_ANYWHERE_RENEWAL_FAILED" and task["attempts"] == 0
    report = repo.get_setting(aws_identity.WORKER_IDENTITY_KEY)["value"]
    assert report["renewal_health"]["state"] == "ERROR"
    assert "synthetic-sensitive-output" not in str(report)
    worker.aws_identity_probe = lambda: dict(SSO)
    worker.aws_identity(refresh=True)
    assert worker.aws_hold(job) is None


def test_worker_defers_when_the_sign_in_expires_mid_scan():
    from cremore_aws_provider import aws_identity

    class ExpiringS3:
        def list_objects_v2(self, **kwargs):
            raise _LoginExpired("token expired")

    repo = InMemoryRepository()
    job = _role_job(repo)
    from cremore.worker.factory import build_collector

    worker, _ = _aws_worker(repo, SSO, collector_factory=lambda j: build_collector(j, s3_client_factory=lambda _j: ExpiringS3()))
    assert worker.process_next() is True
    task = _task(repo, job)
    assert task["status"] == "QUEUED" and task["error"] == "AWS_LOGIN_REQUIRED" and task["attempts"] == 0
    assert repo.get_setting(aws_identity.WORKER_IDENTITY_KEY)["value"]["state"] == "LOGIN_REQUIRED"
    assert repo.get_job(job.id).status != "FAILED"


def _role_account(repo, **fields):
    from cremore.domain.models import AwsAccount

    return repo.create_aws_account(AwsAccount(account_id="123456789012", name="prod",
                                              scanner_role_arn="arn:aws:iam::123456789012:role/CredentialExposureScannerRole",
                                              external_id="external-id-0123456789", **fields))


def _approve(repo, match_key=SSO["match_key"]):
    from cremore_aws_provider import aws_access

    revision = aws_access.next_revision(repo, aws_access.SCANNER)
    repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER], {"match_key": match_key, "revision": revision}, "admin")
    return revision


def _valid(checked):
    from cremore_aws_provider.investigation.role_validation import RoleValidation

    return lambda a: checked.append(a.account_id) or RoleValidation("VALID", "ok", "arn:aws:sts::123456789012:assumed-role/x/y",
                                                                    code="SCANNER_ROLE_ASSUMED")


def test_worker_runs_aws_role_checks_under_the_queued_revisions():
    from cremore_aws_provider import aws_access

    repo = InMemoryRepository()
    revision = _approve(repo)
    acct = _role_account(repo)
    checked = []
    worker, _ = _aws_worker(repo, SSO, aws_role_checker=_valid(checked))
    job_id = aws_access.queue_validation(repo, acct, aws_access.SCANNER, revision)
    assert worker.process_next() is True
    stored = repo.get_aws_account(acct.id)
    assert checked == ["123456789012"] and stored.validation_detail == "SCANNER_ROLE_ASSUMED" and stored.validated_at
    assert aws_access.effective_validation(stored, aws_access.SCANNER, aws_access.approval(repo, aws_access.SCANNER))["status"] == "VALID"
    assert repo.get_job(uuid.UUID(job_id)).status == "SUCCEEDED"

    # a check queued before the role changed is discarded without calling AWS
    stale = aws_access.queue_validation(repo, acct, aws_access.SCANNER, revision)
    repo.update_aws_account(acct.id, **aws_access.access_changes(acct, {"scanner_role_arn": "arn:aws:iam::123456789012:role/New"}))
    assert stale != job_id and worker.process_next() is True
    assert checked == ["123456789012"] and repo.get_job(uuid.UUID(stale)).status == "SUCCEEDED"
    assert repo.get_aws_account(acct.id).validation_key == f"1:{revision}"


def test_a_check_started_before_a_new_approval_never_revalidates_the_account():
    from cremore_aws_provider import aws_access
    from cremore_aws_provider.investigation.role_validation import RoleValidation

    repo = InMemoryRepository()
    first = _approve(repo)
    acct = _role_account(repo)

    def slow_checker(account):
        _approve(repo)  # identity B approved while identity A's check is running
        return RoleValidation("VALID", "ok", "arn", code="SCANNER_ROLE_ASSUMED")

    worker, _ = _aws_worker(repo, SSO, aws_role_checker=slow_checker)
    aws_access.queue_validation(repo, acct, aws_access.SCANNER, first)
    assert worker.process_next() is True
    stored = repo.get_aws_account(acct.id)
    assert stored.validation_key is None
    assert aws_access.effective_validation(stored, aws_access.SCANNER, aws_access.approval(repo, aws_access.SCANNER))["status"] == "PENDING"


def test_worker_waits_for_sign_in_instead_of_recording_it_against_the_account():
    from cremore_aws_provider import aws_access
    from cremore_aws_provider.investigation.role_validation import RoleValidation

    repo = InMemoryRepository()
    revision = _approve(repo)
    acct = _role_account(repo)
    worker, _ = _aws_worker(repo, SSO, aws_role_checker=lambda a: RoleValidation("INVALID", "x", code="AWS_LOGIN_REQUIRED"))
    job = uuid.UUID(aws_access.queue_validation(repo, acct, aws_access.SCANNER, revision))
    assert worker.process_next() is True
    from cremore.db.task_store import TaskStore

    [task] = TaskStore(repo).list_for_run(job)
    assert task["status"] == "QUEUED" and task["error"] == "AWS_LOGIN_REQUIRED" and task["attempts"] == 0
    assert repo.get_aws_account(acct.id).validation_key is None


def test_worker_queues_revalidation_for_stale_results_once():

    repo = InMemoryRepository()
    revision = _approve(repo)
    acct = _role_account(repo)
    worker, _ = _aws_worker(repo, SSO, aws_role_checker=_valid([]))
    assert worker.queue_stale_validations() == 1
    assert worker.queue_stale_validations() == 1  # reuses the pending job
    assert len([j for j in repo.list_jobs(50) if j.kind == "aws-role-check"]) == 1
    worker.process_next()
    assert worker.queue_stale_validations() == 0
    _approve(repo)
    assert worker.queue_stale_validations() == 1 and repo.get_aws_account(acct.id).validation_key == f"1:{revision}"


def test_a_connection_scan_with_only_format_skips_retires_deleted_files_and_keeps_skipped_ones():
    from cremore.collectors.base import CollectedObject
    from cremore.detection import ResourceRef
    from cremore.domain.models import Connection
    from cremore.scanning.scope import FAILURE_BASIS

    repo = InMemoryRepository()
    conn = repo.create_connection(Connection(provider="github", name="app", config={"owner": "o", "repo": "r"}))
    contents = {"deleted.py": f"t={GH}".encode(), "report": f"k={GH[:-1]}Z".encode()}

    class Fake:
        failed_objects = 0
        authoritative_listing = True

        def collect(self):
            for path, data in contents.items():
                yield CollectedObject(ResourceRef(source_type="github", resource="o/r", location=path,
                                                  metadata={"exposure": "public"}), data)

    worker = JobWorker(repo, collector_factory=lambda job: Fake())
    repo.enqueue_job(ScanJob(kind="github", payload={}, connection_id=conn.id))
    worker.process_next()
    before = {e.location: e for e in repo.exposures_for_connection(conn.id)}
    assert set(before) == {"deleted.py", "report"}

    # deleted.py is gone and report is now a PDF: a format skip is not a failure,
    # so the complete run retires the deleted file but keeps the skipped location.
    del contents["deleted.py"]
    contents["report"] = b"%PDF-1.7\n" + contents["report"]
    job = repo.enqueue_job(ScanJob(kind="github", payload={}, connection_id=conn.id))
    worker.process_next()
    after = {e.location: e.status for e in repo.exposures_for_connection(conn.id)}
    assert after == {"deleted.py": "REMOVED", "report": before["report"].status}
    done = repo.get_job(job.id)
    assert done.objects_failed == 0 and done.coverage["skipped_unsupported"] == 1
    assert done.coverage["failure_basis"] == FAILURE_BASIS and done.coverage["authoritative_listing"] is True
    assert done.coverage["detection_policy_digest"] == worker.orchestrator.detection_policy_digest
    from cremore.scanning.scope import job_is_partial

    assert job_is_partial(done)

    # Without an authoritative listing nothing absent is proven, even by an empty run.
    Fake.authoritative_listing = False
    contents.clear()
    repo.enqueue_job(ScanJob(kind="github", payload={}, connection_id=conn.id))
    worker.process_next()
    assert {e.location: e.status for e in repo.exposures_for_connection(conn.id)}["report"] != "REMOVED"


def test_legacy_scan_checks_current_authorization_before_each_object_write():
    from cremore.collectors.base import CollectedObject
    from cremore.detection import ResourceRef
    from cremore.domain.models import Connection

    repo = InMemoryRepository()
    conn = repo.create_connection(Connection(provider="github", name="scope", config={"owner": "o", "repo": "r"}))

    class DuringRead:
        def collect(self):
            repo.update_connection(conn.id, status="DISABLED", credential_evidence={"revoked_at": "2026-10-03"})
            yield CollectedObject(ResourceRef(source_type="github", resource="o/r", location="readme.txt"), b"example")

    job = repo.enqueue_job(ScanJob(kind="github", connection_id=conn.id))
    worker = JobWorker(repo, collector_factory=lambda _: DuringRead())
    worker.process_next()
    done = repo.get_job(job.id)
    assert done.status == "FAILED" and done.error.startswith("CONNECTION_PAUSED")
    assert done.objects == 0 and not repo.exposures_for_connection(conn.id)


# --- Identity Center assignment sweep ----------------------------------------


def _sso_settings(**overrides):
    """Configuration only ALLOWS the sweep; the Admin's switch lives in the repo."""
    from types import SimpleNamespace

    base = {"sso_discovery_allowed": True, "aws_sso_discovery_permission_set": "",
            "aws_sso_discovery_interval_minutes": 60, "aws_sso_discovery_exclude_set": frozenset(),
            "aws_org_discovery_enabled": False}
    base.update(overrides)
    return SimpleNamespace(**base)


def _switch_sso_on(repo, permission_set="CreMoreScanner", enabled=True):
    from cremore_aws_provider import aws_sso_settings

    repo.put_setting(aws_sso_settings.PERMISSION_SET_KEY, {"permission_set": permission_set}, "admin")
    repo.put_setting(aws_sso_settings.DISCOVERY_KEY, {"enabled": enabled}, "admin")


class _SweepSso:
    """Minimal paginated sso stand-in: one assigned account with the set."""

    def get_paginator(self, operation):
        return self

    def paginate(self, **kwargs):
        if "accountId" in kwargs:
            return iter([{"roleList": [{"roleName": "CreMoreScanner"}]}])
        return iter([{"accountList": [{"accountId": "1" * 12, "accountName": "alpha"}]}])


def test_the_assignment_sweep_registers_accounts_without_any_deployment(monkeypatch):
    # A fresh CI runner can have less uptime than the discovery interval.
    monkeypatch.setattr("cremore.worker.worker.time.monotonic", lambda: 10.0)
    from cremore_aws_provider import aws_access

    from cremore.db.repository import InMemoryRepository

    repo = InMemoryRepository()
    _switch_sso_on(repo)
    worker, _state = _aws_worker(repo, {"state": "READY"}, settings=_sso_settings(),
                                 sso_session_factory=lambda: (_SweepSso(), "tok"))
    worker._maybe_discover_sso_accounts()
    [account] = repo.list_aws_accounts()
    assert account.account_id == "1" * 12 and account.access == aws_access.SSO_PERMISSION_SET
    assert account.sso_role_name == "CreMoreScanner" and account.source == "SSO"

    # The interval gate holds the next sweep off; nothing is registered twice.
    worker._maybe_discover_sso_accounts()
    assert len(repo.list_aws_accounts()) == 1


def test_an_expired_sign_in_pauses_the_sweep_instead_of_failing_it(caplog):
    from cremore_aws_provider.aws_identity import AwsLoginRequired

    from cremore.db.repository import InMemoryRepository

    repo = InMemoryRepository()
    _switch_sso_on(repo)

    def expired():
        raise AwsLoginRequired()

    worker, _state = _aws_worker(repo, {"state": "READY"}, settings=_sso_settings(),
                                 sso_session_factory=expired)
    with caplog.at_level(logging.WARNING, logger="cremore.worker"):
        worker._maybe_discover_sso_accounts()
    # Waiting for the operator to sign in again is not a failure to warn about.
    assert repo.list_aws_accounts() == [] and caplog.records == []


def test_the_sweep_needs_all_three_gates():
    """Configuration allows it, an Admin switched it on, and a permission set is
    chosen. All three are re-read every poll, so the dashboard can stop it."""
    from cremore.db.repository import InMemoryRepository

    def never():
        raise AssertionError("the sweep must not run")

    # Nothing chosen and nothing switched on.
    bare = InMemoryRepository()
    _aws_worker(bare, {"state": "READY"}, settings=_sso_settings(),
                sso_session_factory=never)[0]._maybe_discover_sso_accounts()

    # Switched on, but no permission set to sweep with.
    no_set = InMemoryRepository()
    _switch_sso_on(no_set, permission_set="")
    _aws_worker(no_set, {"state": "READY"}, settings=_sso_settings(),
                sso_session_factory=never)[0]._maybe_discover_sso_accounts()

    # Chosen, but the Admin has not switched the sweep on.
    off = InMemoryRepository()
    _switch_sso_on(off, enabled=False)
    _aws_worker(off, {"state": "READY"}, settings=_sso_settings(),
                sso_session_factory=never)[0]._maybe_discover_sso_accounts()

    # Both set, but configuration hard-locks it off.
    locked = InMemoryRepository()
    _switch_sso_on(locked)
    _aws_worker(locked, {"state": "READY"}, settings=_sso_settings(sso_discovery_allowed=False),
                sso_session_factory=never)[0]._maybe_discover_sso_accounts()

    # No factory wired at all is the other half of the same guard.
    none = InMemoryRepository()
    _switch_sso_on(none)
    _aws_worker(none, {"state": "READY"}, settings=_sso_settings())[0]._maybe_discover_sso_accounts()

    for repo in (bare, no_set, off, locked, none):
        assert repo.list_aws_accounts() == []
