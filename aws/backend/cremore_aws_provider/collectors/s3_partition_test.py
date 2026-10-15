"""Synthetic S3 objects retain the caller's trusted partition in both read paths."""

import pytest

from cremore_aws_provider.collectors.inventory_test import CURRENT, MockS3, _row
from cremore_aws_provider.collectors.s3 import S3Collector


@pytest.mark.parametrize("partition", ["aws", "aws-us-gov", "aws-cn", "aws-eusc"])
@pytest.mark.parametrize("inventory", [False, True])
def test_object_arn_uses_explicit_partition_including_inventory_children(partition, inventory):
    client = MockS3({"example.env": b"synthetic"})
    if inventory:
        client.add_report(CURRENT, [_row("example.env")], destinationBucket=f"arn:{partition}:s3:::inventory")
        collector = client.collector(partition=partition, region="us-east-1")
    else:
        collector = S3Collector(client, "source", keys=["example.env"], partition=partition, region="us-east-1")
    [obj] = list(collector.collect())
    assert obj.resource.resource_arn == f"arn:{partition}:s3:::source/example.env"
    assert obj.data == b"synthetic"


@pytest.mark.parametrize("partition", [None, "", "untrusted", "aws:other"])
@pytest.mark.parametrize("inventory", [False, True])
def test_collectors_reject_invalid_explicit_partition_before_reading(partition, inventory):
    client = MockS3()
    with pytest.raises(ValueError, match="^AWS_PARTITION_UNAVAILABLE$"):
        if inventory:
            client.collector(partition=partition)
        else:
            S3Collector(client, "source", partition=partition)
    assert client.calls == []
