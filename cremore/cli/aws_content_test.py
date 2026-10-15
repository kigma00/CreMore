"""Exercise the real worker factories with fake, account-bound AWS clients."""

from types import SimpleNamespace

import pytest
from cremore_aws_provider import aws_access, aws_sessions
from cremore_aws_provider.worker_session_test import content_setup

from cremore.cli.cli_test import _settings
from cremore.cli.worker import build_worker
from cremore.db.catalog_store import CatalogStore
from cremore.domain.models import Connection, ScanJob


def wired(monkeypatch, *, mode="SSO_PERMISSION_SET"):
    _manager, sessions, repo, world, account, job, clock = content_setup(monkeypatch, mode=mode)
    base = sessions.client_factory

    def clients(purpose, service, region, credentials):
        if service == "sts" and credentials is not None:
            world.setdefault("identity_reads", []).append(credentials)
            return SimpleNamespace(get_caller_identity=lambda: {
                "Account": account.account_id, "Arn": f"arn:aws:sts::{account.account_id}:assumed-role/Scanner/session",
            })
        return base(purpose, service, region, credentials)

    monkeypatch.setattr(aws_sessions, "boto3_client_factory", lambda settings: clients)
    worker = build_worker(_settings(), repo)
    worker.aws_identity_probe = lambda: world["identity"]
    worker.aws_sessions.now = lambda: clock["now"]
    worker.poll_triggers = lambda: None
    return worker, repo, world, account, job


@pytest.mark.parametrize("mode", ["ROLE", "SSO_PERMISSION_SET", "RUNTIME_IDENTITY"])
def test_catalog_factory_uses_the_connected_account_not_payload_roles_or_ambient_identity(monkeypatch, mode):
    worker, _repo, world, account, job = wired(monkeypatch, mode=mode)
    listed, status = worker.catalog_lister(job)
    assert status == "COMPLETE"
    assert [(r["provider_resource_id"], r["account_id"]) for r in listed] == [("member-bucket", account.account_id)]
    assert world["reads"][0][0] == "list_buckets"
    if mode != "RUNTIME_IDENTITY":
        assert world["reads"][0][2] is not None
    if mode == "SSO_PERMISSION_SET":
        assert world["vended"][0]["accountId"] == account.account_id
        assert world["assumed"] == []


@pytest.mark.parametrize("scoped", [False, True])
def test_content_factory_reads_with_sso_member_credentials_and_account_provenance(monkeypatch, scoped):
    worker, _repo, world, account, job = wired(monkeypatch)
    p = {**job.payload, "bucket": "member-bucket", "_lazy": True}
    if scoped:
        p["roots"] = [{"resource_type": "S3_BUCKET", "provider_resource_id": "member-bucket",
                       "account_id": account.account_id, "all_current_objects": True}]
    scan = job.model_copy(update={"kind": "scope" if scoped else "s3", "payload": p})
    objects = iter(worker.collector_factory(scan).collect())
    obj = next(objects)
    assert obj.resource.account_id == account.account_id
    assert obj.read() == b"test"
    assert world["vended"][0]["accountId"] == account.account_id
    assert all(creds is not None for _op, _kwargs, creds in world["reads"])
    assert all(kwargs.get("ExpectedBucketOwner") == account.account_id for op, kwargs, _creds in world["reads"]
               if op in ("list_objects_v2", "get_object"))


def test_credential_check_reports_member_identity_and_bucket_uses_the_same_session(monkeypatch):
    worker, repo, world, account, _job = wired(monkeypatch)
    connection = repo.create_connection(Connection(provider="aws", name="member", scope="member-bucket",
        config={"account_id": account.account_id, "bucket": "member-bucket"}))
    job = ScanJob(kind="credential-check", connection_id=connection.id, payload={
        "provider": "aws", "account_id": account.account_id, "bucket": "member-bucket"})
    result = worker.credential_checker(job)
    assert result.status == "ACTIVE"
    assert f"::{account.account_id}:" in result.owner
    assert world["identity_reads"] == [world["reads"][0][2]]
    assert world["reads"][0][1]["ExpectedBucketOwner"] == account.account_id


def test_catalog_does_not_publish_when_account_is_withdrawn_after_last_response(monkeypatch):
    worker, repo, _world, account, job = wired(monkeypatch)
    original = worker.catalog_lister

    def listing(job):
        result = original(job)
        repo.update_aws_account(account.id, enabled=False)
        return result

    worker.catalog_lister = listing
    with pytest.raises(aws_access.AccessBlocked, match="AWS_ACCESS_REVISION_CHANGED"):
        worker._run_catalog_refresh(job)
    assert CatalogStore(repo).header("aws", account.id) is None


def test_credential_result_does_not_publish_when_account_is_withdrawn_after_check(monkeypatch):
    worker, repo, _world, account, _job = wired(monkeypatch)
    connection = repo.create_connection(Connection(provider="aws", name="member", scope="member-bucket",
        config={"account_id": account.account_id, "bucket": "member-bucket"}))
    job = repo.enqueue_job(ScanJob(kind="credential-check", connection_id=connection.id, payload={
        "provider": "aws", "account_id": account.account_id, "bucket": "member-bucket"}))
    original = worker.credential_checker

    def check(job):
        result = original(job)
        repo.update_aws_account(account.id, enabled=False)
        return result

    worker.credential_checker = check
    with pytest.raises(aws_access.AccessBlocked, match="AWS_ACCESS_REVISION_CHANGED"):
        worker._run_credential_check(job)
    assert not repo.get_connection(connection.id).credential_evidence


def test_task_cleanup_releases_content_pin_after_completion(monkeypatch):
    worker, repo, _world, _account, job = wired(monkeypatch)
    queued = repo.enqueue_job(job.model_copy(update={"id": None}))
    assert worker.process_next()
    assert repo.get_job(queued.id).status == "SUCCEEDED"
    assert worker.aws_content_sessions._jobs == {}
