"""Onboarding catalogs use the proven scanner approval before accounts are registered."""

import uuid
from types import SimpleNamespace

import pytest

from cremore.collectors.base import RequestBudget
from cremore.db.repository import InMemoryRepository
from cremore_aws_provider import aws_access, onboarding_discovery
from cremore_aws_provider.catalog_test import S3
from cremore_aws_provider.onboarding import OnboardingValueError


def _context(partition):
    repo, client = InMemoryRepository(), S3()
    identity = {"state": "READY", "account_id": "111111111111", "match_key": "synthetic-workload",
                "kind": "IAM_ROLE", "credential_source": "iam-role"}
    approved = {**identity, "revision": 1}
    if partition is not None:
        approved["partition"] = partition
    repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER], approved, "admin")
    context = SimpleNamespace(repo=repo, settings=None, before_request=None,
                              aws_sessions=SimpleNamespace(identity=lambda *_: identity,
                                                           client_factory=lambda *_: client))
    record = {"auth_method": "runtime", "purposes": ["exposure"],
              "target": {"accounts": [identity["account_id"]], "partition": "untrusted", "region": "us-east-1"}}
    return context, record, client


@pytest.mark.parametrize("partition", ["aws", "aws-us-gov", "aws-cn", "aws-eusc"])
def test_onboarding_catalog_threads_trusted_approval_partition(partition):
    context, record, client = _context(partition)
    [row], complete, _ = onboarding_discovery.list_onboarding_scope(record, uuid.uuid4(), context, RequestBudget())
    assert row["canonical_reference"] == f"arn:{partition}:s3:::source"
    assert complete == "COMPLETE" and client.calls == ["list"]
    assert context.repo.list_aws_accounts() == []


@pytest.mark.parametrize("partition", [None, "", "untrusted"])
def test_onboarding_catalog_requires_supported_approved_partition(partition):
    context, record, client = _context(partition)
    with pytest.raises(OnboardingValueError, match="^AWS_PARTITION_UNAVAILABLE$"):
        onboarding_discovery.list_onboarding_scope(record, uuid.uuid4(), context, RequestBudget())
    assert client.calls == []


def test_onboarding_catalog_rejects_approval_changed_while_opening_session():
    context, record, client = _context("aws-us-gov")
    approved = context.repo.get_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER])["value"]
    identity = context.aws_sessions.identity

    def changed(*args):
        context.repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER], {**approved, "revision": 2}, "admin")
        return identity(*args)

    context.aws_sessions.identity = changed
    with pytest.raises(OnboardingValueError, match="^AWS_SCANNER_IDENTITY_CHANGED$"):
        onboarding_discovery.list_onboarding_scope(record, uuid.uuid4(), context, RequestBudget())
    assert client.calls == []
