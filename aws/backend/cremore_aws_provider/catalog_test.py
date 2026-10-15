"""Every bucket catalog projection uses explicit trusted partition metadata."""

from datetime import UTC, datetime

import pytest

from cremore.collectors.base import CollectorError, RequestBudget
from cremore_aws_provider.source import list_resources


class S3:
    def __init__(self):
        self.calls = []

    def list_buckets(self, **kwargs):
        self.calls.append("list")
        return {"Buckets": [{"Name": "source", "BucketRegion": "us-east-1"}]}

    def head_bucket(self, **kwargs):
        self.calls.append("head")
        return {}


@pytest.mark.parametrize("partition", ["aws", "aws-us-gov", "aws-cn", "aws-eusc"])
@pytest.mark.parametrize("kind,reference", [("aws", None), ("aws", "source"), ("source", None),
                                           ("source", "source"), ("source", "outside")])
def test_catalog_bucket_arns_use_trusted_partition_for_every_projection(partition, kind, reference):
    client = S3()
    payload = {"account_id": "123456789012", "bucket": "source", "partition": "untrusted",
               "region": "us-east-1", "reference": reference}
    rows, _ = list_resources(payload, kind, "connection", s3_client=lambda: client,
                            s3_partition=partition, now=datetime.now(UTC), request_budget=RequestBudget())
    [row] = rows
    assert row["canonical_reference"] == f"arn:{partition}:s3:::{reference or 'source'}"
    if reference == "outside":
        assert row["reason_code"] == "OUT_OF_CONNECTION_SCOPE"
        assert client.calls == []


@pytest.mark.parametrize("partition", [None, "", "untrusted", "aws:other"])
def test_catalog_rejects_invalid_explicit_partition_before_provider_requests(partition):
    client = S3()
    with pytest.raises(CollectorError) as error:
        list_resources({}, "aws", "connection", s3_client=lambda: client, s3_partition=partition,
                       now=datetime.now(UTC), request_budget=RequestBudget())
    assert error.value.code == "AWS_PARTITION_UNAVAILABLE"
    assert client.calls == []
