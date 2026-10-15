import datetime as dt
import io
import uuid

import pytest

from cremore.coverage.job import require_current_access
from cremore.domain.models import ScanJob
from cremore_aws_provider import aws_access
from cremore_aws_provider.aws_identity import AwsLoginRequired
from cremore_aws_provider.aws_readonly import ReadOnlyViolation
from cremore_aws_provider.aws_sessions_test import NOW, SCANNER_ROLE, setup, sso_setup
from cremore_aws_provider.worker_session import (
    FRESH_IDENTITY_SECONDS,
    RECENT_PROOF_SECONDS,
    ContentSessions,
)


class S3:
    def __init__(self, world, credentials):
        self.world, self.credentials = world, credentials

    def _read(self, operation, kwargs, result):
        self.world["reads"].append((operation, kwargs, self.credentials))
        if callback := self.world.get("during_read"):
            callback()
        return result

    def list_buckets(self, **kwargs):
        return self._read("list_buckets", kwargs, {"Buckets": [{"Name": "member-bucket"}]})

    def head_bucket(self, **kwargs):
        return self._read("head_bucket", kwargs, {})

    def list_objects_v2(self, **kwargs):
        first = "ContinuationToken" not in kwargs
        page = {"Contents": [{"Key": "one" if first else "two"}], "IsTruncated": first}
        if first:
            page["NextContinuationToken"] = "next"
        return self._read("list_objects_v2", kwargs, page)

    def get_object(self, **kwargs):
        return self._read("get_object", kwargs, {"Body": self.world.setdefault("body", io.BytesIO(b"test"))})

    def get_paginator(self, operation):
        from botocore.paginate import Paginator
        from botocore.session import get_session

        sdk = get_session()
        name = "ListObjectsV2"
        return Paginator(getattr(self, operation), sdk.get_paginator_model("s3").get_paginator(name),
                         sdk.get_service_model("s3").operation_model(name))


def content_setup(monkeypatch, *, mode="ROLE", **fields):
    if mode == "SSO_PERMISSION_SET":
        sessions, repo, world, clock = sso_setup(monkeypatch, **fields)
        account = repo.list_aws_accounts()[0]
    else:
        if mode == "RUNTIME_IDENTITY":
            fields.update(access=mode, account_id="111111111111", scanner_role_arn=None, external_id=None)
        sessions, repo, world, account = setup(**fields)
        clock = {"now": NOW}
        sessions.now = lambda: clock["now"]
    world["reads"] = []
    base = sessions.client_factory

    def factory(purpose, service, region, credentials):
        if service == "s3":
            if mode != "RUNTIME_IDENTITY":
                assert credentials is not None, "no ambient S3 fallback"
            return S3(world, credentials)
        return base(purpose, service, region, credentials)

    sessions.client_factory = factory
    world["mono"] = mono = {"t": 0.0}
    manager = ContentSessions(sessions, require_current_access, clock=lambda: mono["t"])
    job = ScanJob(id=uuid.uuid4(), kind="catalog-refresh", connection_id=account.id, payload={
        "provider": "aws", "connection_kind": "aws", "connection_id": str(account.id),
        "account_id": account.account_id, "scanner_role_arn": "untrusted-payload-role", "external_id": "untrusted",
    })
    return manager, sessions, repo, world, account, job, clock


@pytest.mark.parametrize("mode", ["ROLE", "SSO_PERMISSION_SET", "RUNTIME_IDENTITY"])
def test_content_uses_only_the_registered_account_and_keeps_the_readonly_boundary(monkeypatch, mode):
    manager, _sessions, repo, world, account, job, _clock = content_setup(monkeypatch, mode=mode)
    client = manager.client(job, "s3", "us-east-1")
    with pytest.raises(ReadOnlyViolation):
        client.delete_object(Bucket="b", Key="x")
    with pytest.raises(ReadOnlyViolation):
        client.get_paginator("delete_object")
    assert world["reads"] == [] and world["assumed"] == []
    assert client.list_buckets()["Buckets"] == [{"Name": "member-bucket"}]
    client.head_bucket(Bucket="b")
    assert world["reads"][-1][1]["ExpectedBucketOwner"] == account.account_id
    if mode == "ROLE":
        assert world["assumed"][0]["RoleArn"] == SCANNER_ROLE
        assert world["assumed"][0]["ExternalId"] == account.external_id
    elif mode == "SSO_PERMISSION_SET":
        assert world["vended"][0]["accountId"] == account.account_id
        assert world["assumed"] == []
    else:
        assert world["reads"][0][2] is None and world["assumed"] == []
    probes = len(world["probes"])
    manager.require_current(job, repo)
    assert len(world["probes"]) == probes, "a durable write never calls AWS"


@pytest.mark.parametrize("account_id,code", [(None, "ACCOUNT_OWNER_UNKNOWN"), ("999999999999", "ACCOUNT_NOT_CONNECTED")])
def test_missing_or_unregistered_account_never_uses_ambient_credentials(monkeypatch, account_id, code):
    manager, _sessions, _repo, world, _account, _job, _clock = content_setup(monkeypatch)
    job = ScanJob(kind="s3", payload={"account_id": account_id, "bucket": "b"})
    with pytest.raises(aws_access.AccessBlocked, match=code):
        manager.client(job, "s3", "us-east-1")
    assert world["reads"] == world["assumed"] == world["probes"] == []


@pytest.mark.parametrize("change,code", [
    ({"enabled": False}, "ACCOUNT_DISABLED"),
    ({"org_present": False}, "ORG_ACCOUNT_REMOVED"),
    ({"in_deployment_scope": False}, "OUT_OF_DEPLOYMENT_SCOPE"),
    ({"validation_status": "FAILED", "validation_detail": "ACCOUNT_NOT_VALIDATED"}, "ACCOUNT_NOT_VALIDATED"),
    ({"access_revision": 2}, "REVALIDATION_REQUIRED"),
])
def test_each_request_refuses_withdrawn_account_access_and_latches_the_failure(monkeypatch, change, code):
    manager, _sessions, repo, world, account, job, _clock = content_setup(
        monkeypatch, source="ORGANIZATION", org_present=True, org_state="ACTIVE", in_deployment_scope=True)
    client = manager.client(job, "s3", "us-east-1")
    client.list_buckets()
    repo.update_aws_account(account.id, **change)
    with pytest.raises(aws_access.AccessBlocked, match=code):
        client.head_bucket(Bucket="b")
    assert len(world["reads"]) == 1
    # Even a restored setting cannot make a swallowed refusal become COMPLETE.
    repo.update_aws_account(account.id, **{key: getattr(account, key) for key in change})
    with pytest.raises(aws_access.AccessBlocked, match=code):
        manager.require_current(job, repo)


def test_new_approved_revision_does_not_reauthorize_an_old_task(monkeypatch):
    manager, _sessions, repo, world, account, job, _clock = content_setup(monkeypatch)
    client = manager.client(job, "s3", "us-east-1")
    client.list_buckets()
    approved = aws_access.approval(repo, aws_access.SCANNER)
    repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER], {**approved, "revision": 2}, "admin")
    aws_access.record_validation(repo, account, aws_access.SCANNER, access_revision=account.access_revision,
                                 approval_revision=2, current_approval_revision=2, status="VALID", detail="OK")
    with pytest.raises(aws_access.AccessBlocked, match="AWS_ACCESS_REVISION_CHANGED"):
        client.head_bucket(Bucket="b")
    assert len(world["reads"]) == len(world["assumed"]) == 1


def _fresh(world):
    return len([probe for probe in world["probes"] if probe[1]])


@pytest.mark.parametrize("mode", ["ROLE", "SSO_PERMISSION_SET", "RUNTIME_IDENTITY"])
def test_every_request_refuses_a_disabled_account_in_every_access_mode(monkeypatch, mode):
    manager, _sessions, repo, world, account, job, _clock = content_setup(monkeypatch, mode=mode)
    client = manager.client(job, "s3", "us-east-1")
    client.head_bucket(Bucket="b")
    repo.update_aws_account(account.id, enabled=False)
    with pytest.raises(aws_access.AccessBlocked, match="ACCOUNT_DISABLED"):
        client.head_bucket(Bucket="b")
    assert len(world["reads"]) == 1


def test_revend_reproves_the_identity_inside_the_window(monkeypatch):
    manager, sessions, _repo, world, _account, job, clock = content_setup(monkeypatch)
    previous = dict(world["identity"])

    def identity(purpose, fresh):
        world["probes"].append((purpose, fresh))
        return world["identity"] if fresh else previous

    sessions.identity = identity
    client = manager.client(job, "s3", "us-east-1")
    client.list_buckets()
    proofs = _fresh(world)
    world["identity"] = {"state": "READY", "match_key": "a-different-identity"}
    # The role credentials expire; the last proof is older than a moment but the window has not passed.
    clock["now"] += dt.timedelta(minutes=56)
    world["mono"]["t"] += RECENT_PROOF_SECONDS + 1
    with pytest.raises(aws_access.AccessBlocked, match="AWS_IDENTITY_CHANGED"):
        client.list_buckets()
    assert len(world["assumed"]) == 2 and len(world["reads"]) == 1
    assert _fresh(world) == proofs + 1


def test_change_during_revend_is_refused_before_the_request(monkeypatch):
    manager, sessions, repo, world, account, job, clock = content_setup(monkeypatch)
    client = manager.client(job, "s3", "us-east-1")
    client.list_buckets()
    original = sessions._assume

    def assume(acct, purpose, role):
        result = original(acct, purpose, role)
        repo.update_aws_account(account.id, enabled=False)
        return result

    sessions._assume = assume
    clock["now"] += dt.timedelta(minutes=56)
    with pytest.raises(aws_access.AccessBlocked, match="ACCOUNT_DISABLED"):
        client.list_buckets()
    assert len(world["assumed"]) == 2 and len(world["reads"]) == 1


def test_failed_fresh_proof_does_not_use_up_the_window(monkeypatch):
    manager, sessions, _repo, world, _account, job, _clock = content_setup(monkeypatch)
    client = manager.client(job, "s3", "us-east-1")
    client.list_buckets()
    world["mono"]["t"] += FRESH_IDENTITY_SECONDS
    real = sessions.identity
    failures = {"left": 1}

    def flaky(purpose, fresh):
        if fresh and failures["left"]:
            failures["left"] -= 1
            raise TimeoutError("synthetic transient failure")
        return real(purpose, fresh)

    sessions.identity = flaky
    with pytest.raises(TimeoutError):
        client.list_buckets()
    proofs = _fresh(world)
    client.list_buckets()  # still inside the window of the failed attempt, yet proved again
    assert _fresh(world) == proofs + 1


def test_changed_identity_is_probed_fresh_within_the_window_and_then_refused(monkeypatch):
    manager, sessions, _repo, world, _account, job, _clock = content_setup(monkeypatch)
    previous = dict(world["identity"])
    sessions.identity = lambda purpose, fresh: world["identity"] if fresh else previous
    client = manager.client(job, "s3", "us-east-1")
    client.list_buckets()
    world["identity"] = {"state": "READY", "match_key": "a-different-identity"}
    # Inside the interval the role credentials vended under the approved identity are still used.
    world["mono"]["t"] += FRESH_IDENTITY_SECONDS - 1
    client.head_bucket(Bucket="b")
    world["mono"]["t"] += 1
    with pytest.raises(aws_access.AccessBlocked, match="AWS_IDENTITY_CHANGED"):
        client.head_bucket(Bucket="b")
    assert len(world["reads"]) == 2
    # The refusal latches: a restored identity does not reopen this job's reads.
    world["identity"] = previous
    world["mono"]["t"] += FRESH_IDENTITY_SECONDS
    with pytest.raises(aws_access.AccessBlocked, match="AWS_IDENTITY_CHANGED"):
        client.list_buckets()


def test_identity_is_reproved_once_per_window_not_per_request(monkeypatch):
    manager, _sessions, _repo, world, _account, job, _clock = content_setup(monkeypatch)
    client = manager.client(job, "s3", "us-east-1")
    for _ in range(50):
        client.get_object(Bucket="b", Key="k")["Body"].read()
        world["body"] = io.BytesIO(b"test")
    fresh = [probe for probe in world["probes"] if probe[1]]
    assert len(fresh) == 1 and len(world["reads"]) == 50
    world["mono"]["t"] += FRESH_IDENTITY_SECONDS
    client.head_bucket(Bucket="b")
    assert len([probe for probe in world["probes"] if probe[1]]) == 2


def test_reused_credentials_cost_no_second_refusal_check_per_request(monkeypatch):
    manager, sessions, _repo, _world, _account, job, _clock = content_setup(monkeypatch)
    client = manager.client(job, "s3", "us-east-1")
    client.head_bucket(Bucket="b")
    calls = []
    original = sessions.refusal

    def counted(*args, **kwargs):
        calls.append(kwargs.get("fresh", False))
        return original(*args, **kwargs)

    sessions.refusal = counted
    client.head_bucket(Bucket="b")
    # Before the call, inside opening the session, and after the call; neither a fresh identity probe
    # nor the re-check after opening runs when the credentials were reused (it used to be four).
    assert len(calls) == 3 and not any(calls)


def test_concurrent_readers_share_one_identity_probe(monkeypatch):
    import threading

    manager, _sessions, _repo, world, _account, job, _clock = content_setup(monkeypatch)
    client = manager.client(job, "s3", "us-east-1")
    probes_before = len([probe for probe in world["probes"] if probe[1]])
    world["mono"]["t"] += FRESH_IDENTITY_SECONDS
    errors = []

    def read():
        try:
            for _ in range(10):
                client.head_bucket(Bucket="b")
        except Exception as exc:  # noqa: BLE001 -- surfaced by the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=read) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors and len(world["reads"]) == 80
    assert len([probe for probe in world["probes"] if probe[1]]) == probes_before + 1


@pytest.mark.parametrize("mode", ["ROLE", "SSO_PERMISSION_SET"])
def test_long_scan_refreshes_the_same_account_and_refuses_failed_refresh(monkeypatch, mode):
    manager, _sessions, _repo, world, _account, job, clock = content_setup(monkeypatch, mode=mode)
    client = manager.client(job, "s3", "us-east-1")
    client.list_buckets()
    first = world["reads"][-1][2]
    clock["now"] += dt.timedelta(minutes=56)
    client.list_buckets()
    assert world["reads"][-1][2] is not first
    assert len(world["assumed"] if mode == "ROLE" else world["vended"]) == 2
    world["deny"] = True
    world["error"] = PermissionError("synthetic denied")
    with pytest.raises(aws_access.AccessBlocked, match="ASSUME_ROLE_DENIED|SSO_ROLE_NOT_ASSIGNED"):
        client.list_buckets()
    assert len(world["reads"]) == 2


def test_paginator_rebinds_each_page_and_cannot_escape_current_authorization(monkeypatch):
    manager, _sessions, repo, world, account, job, clock = content_setup(monkeypatch)
    client = manager.client(job, "s3", "us-east-1")
    pages = iter(client.get_paginator("list_objects_v2").paginate(Bucket="b"))
    assert next(pages)["Contents"] == [{"Key": "one"}]
    clock["now"] += dt.timedelta(minutes=56)
    assert next(pages)["Contents"] == [{"Key": "two"}]
    assert world["reads"][0][2] is not world["reads"][1][2]
    assert world["reads"][1][1] == {"Bucket": "b", "ContinuationToken": "next", "ExpectedBucketOwner": account.account_id}
    pages = iter(client.get_paginator("list_objects_v2").paginate(Bucket="b"))
    next(pages)
    repo.update_aws_account(account.id, enabled=False)
    before = len(world["reads"])
    with pytest.raises(aws_access.AccessBlocked, match="ACCOUNT_DISABLED"):
        next(pages)
    assert len(world["reads"]) == before


def test_response_and_stream_reads_are_discarded_when_authorization_changes(monkeypatch):
    manager, _sessions, repo, world, account, job, _clock = content_setup(monkeypatch)
    client = manager.client(job, "s3", "us-east-1")
    body = client.get_object(Bucket="b", Key="k")["Body"]
    repo.update_aws_account(account.id, enabled=False)
    with pytest.raises(aws_access.AccessBlocked, match="ACCOUNT_DISABLED"):
        body.read()
    assert world["body"].tell() == 0
    body.close()
    manager.release(job)
    repo.update_aws_account(account.id, enabled=True)
    world["body"] = io.BytesIO(b"test")
    world["during_read"] = lambda: repo.update_aws_account(account.id, enabled=False)
    client = manager.client(job, "s3", "us-east-1")
    with pytest.raises(aws_access.AccessBlocked, match="ACCOUNT_DISABLED"):
        client.get_object(Bucket="b", Key="k")
    assert world["body"].closed


def test_wrong_account_or_bucket_owner_and_uninitialized_commit_are_refused(monkeypatch):
    manager, _sessions, repo, world, _account, job, _clock = content_setup(monkeypatch)
    with pytest.raises(aws_access.AccessBlocked, match="AWS_SESSION_UNAVAILABLE"):
        manager.require_current(job, repo)
    with pytest.raises(aws_access.AccessBlocked, match="ACCOUNT_MISMATCH"):
        manager.client(job.model_copy(update={"payload": {**job.payload, "account_id": "999999999999"}}), "s3", "us-east-1")
    client = manager.client(job, "s3", "us-east-1")
    with pytest.raises(aws_access.AccessBlocked, match="ACCOUNT_MISMATCH"):
        client.head_bucket(Bucket="b", ExpectedBucketOwner="999999999999")
    assert world["reads"] == world["assumed"] == []


def test_credential_expiry_remains_a_login_hold_and_nonaws_jobs_are_untouched(monkeypatch):
    manager, _sessions, repo, world, _account, job, _clock = content_setup(monkeypatch)
    manager.require_current(ScanJob(kind="github", payload={}), repo)
    client = manager.client(job, "s3", "us-east-1")
    world["identity"] = {"state": "LOGIN_REQUIRED"}
    with pytest.raises(AwsLoginRequired):
        client.list_buckets()
    assert world["reads"] == []
