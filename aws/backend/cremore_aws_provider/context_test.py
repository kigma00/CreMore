import json
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from cremore_aws_provider import context, source
from cremore_aws_provider.aws_readonly import readonly_client

ACCOUNT = "123456789012"


class Sessions:
    def __init__(self, *, variant="normal", partition="aws"):
        self.calls, self.variant, self.partition = [], variant, partition
        self.changed = False
        self.account = SimpleNamespace(access_revision=1)

    def open(self, account, purpose):
        assert account == ACCOUNT and purpose == "scanner"
        return SimpleNamespace(account_id=ACCOUNT, pin="1:1", client=lambda service, region: readonly_client(self, service))

    def refusal(self, account, purpose):
        return ("AWS_IDENTITY_CHANGED" if self.changed else None, self.account, {"revision": 1, "partition": self.partition})

    def __getattr__(self, operation):
        def call(**kwargs):
            self.calls.append((operation, kwargs))
            assert kwargs["Bucket"] == "poc-bucket" and kwargs["ExpectedBucketOwner"] == ACCOUNT
            if self.variant == "denied" and operation == "get_object_acl":
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "synthetic-do-not-store"}}, operation)
            if self.variant == "changed" and operation == "get_bucket_acl":
                self.changed = True
            if operation == "get_bucket_policy":
                return {"Policy": json.dumps({"Statement": [
                    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:{self.partition}:s3:::poc-bucket/*",
                     "Condition": {"StringEquals": {"x": "synthetic-do-not-store"}}},
                    {"Effect": "Deny", "Principal": {"AWS": "arn:aws:iam::123456789012:role/restricted"},
                     "Action": "s3:*", "Resource": f"arn:{self.partition}:s3:::poc-bucket/a[1].env"},
                    {"Effect": "Allow", "Principal": "wrong-object", "Action": "s3:GetObject", "Resource": f"arn:{self.partition}:s3:::poc-bucket/other"}
                ]})}
            if operation == "get_bucket_acl":
                return {"Grants": [{"Permission": "READ", "Grantee": {"Type": "CanonicalUser", "ID": "owner-canonical"}}]}
            if operation == "get_object_acl":
                assert kwargs["VersionId"] == "version-1" and kwargs["Key"] == "a[1].env"
                return {"Grants": [{"Permission": "READ", "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]}
            assert operation == "get_public_access_block"
            return {"PublicAccessBlockConfiguration": {"IgnorePublicAcls": True}}
        return call


@pytest.mark.parametrize("variant,partition", [("normal", "aws"), ("normal", "aws-us-gov"), ("denied", "aws"), ("changed", "aws")])
def test_s3_approved_scanner_pins_account_scope_and_policy_metadata(variant, partition):
    sessions, checks = Sessions(variant=variant, partition=partition), []
    access = source.exposure_context({"account_id": ACCOUNT, "bucket": "poc-bucket"},
        {"repository": "poc-bucket", "path": "a[1].env", "object_version": "version-1"}, http_client=None,
        aws_sessions=sessions, check_scope=lambda: checks.append(True))["members"]
    assert "synthetic-do-not-store" not in str(access)
    if variant == "changed":
        assert access["status"] == "BLOCKED" and "people" not in access and len(sessions.calls) == 2
        return
    assert len(sessions.calls) == 4 and len(checks) >= 5
    assert access["status"] == ("FORBIDDEN" if variant == "denied" else "OBSERVED")
    assert access["truncated"] is (variant == "denied")
    assert all(row["read_access"] == "UNKNOWN" for row in access["people"])
    assert "wrong-object" not in str(access)
    assert any(row["effect"] == "DENY" for row in access["people"])
    assert "BUCKET_ACL_IS_NOT_OBJECT_READ" in access["limitations"]
    assert "PUBLIC_ACCESS_BLOCK_ENABLED" in access["limitations"]


def test_s3_requires_approved_account_and_never_uses_ambient_credentials():
    sessions = Sessions()
    for payload in ({"bucket": "poc-bucket"}, {"bucket": "other", "account_id": ACCOUNT}):
        access = context.read(payload, {"repository": "poc-bucket", "path": "a"},
            aws_sessions=sessions, check_scope=lambda: None)["members"]
        assert access["status"] == "BLOCKED"
    assert sessions.calls == []


def test_s3_scope_revocation_discards_results_before_the_next_call():
    sessions = Sessions()
    def check():
        if sessions.calls:
            raise ValueError("scope changed")
    access = context.read({"account_id": ACCOUNT, "bucket": "poc-bucket"},
        {"repository": "poc-bucket", "path": "a"}, aws_sessions=sessions, check_scope=check)["members"]
    assert access["status"] == "BLOCKED" and "people" not in access
    assert len(sessions.calls) == 1
