"""Production composition uses approved partition, never job/root hints or bucket region."""

import pytest
from cremore_aws_provider import aws_access, aws_sessions
from cremore_aws_provider.aws_sessions_test import setup
from cremore_aws_provider.collectors.inventory_test import CURRENT, MockS3, _row

from cremore.cli.worker_test import _settings
from cremore.domain.models import ScanJob


class S3(MockS3):
    def list_buckets(self, **kwargs):
        self.calls.append(("list_buckets",))
        return {"Buckets": [{"Name": "source", "BucketRegion": "us-east-1"}]}

    def list_objects_v2(self, **kwargs):
        self.calls.append(("list_objects", kwargs))
        assert kwargs["ExpectedBucketOwner"] == "111111111111"
        return {"Contents": [{"Key": "example.env", "Size": 9}]}

    def get_object(self, *, ExpectedBucketOwner, **kwargs):
        assert ExpectedBucketOwner == "111111111111"
        return super().get_object(**kwargs)


def _worker(monkeypatch, partition):
    from cremore.cli.worker import build_worker

    sessions, repo, world, account = setup(access=aws_access.RUNTIME_IDENTITY, account_id="111111111111",
                                          scanner_role_arn=None, external_id=None)
    approved = dict(repo.get_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER])["value"])
    if partition is None:
        approved.pop("partition", None)  # an approval without one
    else:
        approved["partition"] = partition
    repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER], approved, "admin")
    client = S3({"example.env": b"synthetic"})
    client.add_report(CURRENT, [_row("example.env")], destinationBucket=f"arn:{partition}:s3:::inventory")

    def factory(purpose, service, region, credentials):
        assert purpose == aws_access.SCANNER and service == "s3" and credentials is None
        return client

    sessions.client_factory = factory
    monkeypatch.setattr(aws_sessions, "AccountSessions", lambda *args, **kwargs: sessions)
    monkeypatch.setattr(aws_sessions, "boto3_client_factory", lambda settings: factory)
    return build_worker(_settings(), repo), repo, world, account, client


def _job(account, path):
    payload = {"provider": "aws", "connection_kind": "aws", "connection_id": str(account.id),
               "account_id": account.account_id, "bucket": "source", "region": "us-east-1",
               "partition": "aws-cn-spoofed", "_lazy": True}
    kind = "catalog-refresh" if path == "catalog" else "s3"
    if path in ("scope", "inventory"):
        kind = "scope"
        root = {"resource_type": "S3_BUCKET", "provider_resource_id": "source", "all_current_objects": True,
                "account_id": account.account_id, "region": "us-east-1", "partition": "aws-us-gov-spoofed"}
        if path == "inventory":
            root["inventory"] = {"manifest_bucket": "inventory", "manifest_key": CURRENT}
        payload["roots"] = [root]
    return ScanJob(kind=kind, connection_id=account.id, payload=payload)


@pytest.mark.parametrize("partition", ["aws", "aws-us-gov", "aws-cn", "aws-eusc"])
@pytest.mark.parametrize("path", ["s3", "scope", "inventory", "catalog"])
def test_production_s3_threads_approved_partition_and_ignores_payload_and_region(monkeypatch, partition, path):
    worker, _repo, _world, account, _client = _worker(monkeypatch, partition)
    job = _job(account, path)
    original = job.model_dump(mode="json")
    if path == "catalog":
        [row], completeness = worker.catalog_lister(job)
        assert row["canonical_reference"] == f"arn:{partition}:s3:::source"
        assert completeness == "COMPLETE"
    else:
        [obj] = list(worker.collector_factory(job).collect())
        assert obj.resource.resource_arn == f"arn:{partition}:s3:::source/example.env"
    assert job.model_dump(mode="json") == original


@pytest.mark.parametrize("partition", [None, "", "untrusted"])
@pytest.mark.parametrize("path", ["s3", "scope", "inventory", "catalog"])
def test_production_s3_missing_or_invalid_approved_partition_fails_before_reads(monkeypatch, partition, path):
    worker, _repo, _world, account, client = _worker(monkeypatch, partition)
    job = _job(account, path)
    with pytest.raises(aws_access.AccessBlocked, match="^AWS_PARTITION_UNAVAILABLE$"):
        if path == "catalog":
            worker.catalog_lister(job)
        else:
            worker.collector_factory(job)
    assert client.calls == []


@pytest.mark.parametrize("path", ["s3", "scope", "inventory", "catalog"])
def test_production_s3_partition_lookup_preserves_account_refusal(monkeypatch, path):
    worker, repo, _world, account, client = _worker(monkeypatch, "aws-us-gov")
    repo.update_aws_account(account.id, enabled=False)
    job = _job(account, path)
    with pytest.raises(aws_access.AccessBlocked, match="^ACCOUNT_DISABLED$"):
        if path == "catalog":
            worker.catalog_lister(job)
        else:
            worker.collector_factory(job)
    assert client.calls == []
