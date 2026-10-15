import json
import re
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from cremore_aws_provider.aws_readonly import READ_OPERATIONS, ReadOnlyViolation, readonly_client
from cremore_aws_provider.investigation.identity_policies import (
    READ_ACTIONS,
    collect_identity_policies,
    summarize,
)

DENY_ALL = {"Version": "2012-10-17", "Statement": [{"Sid": "DenyEverything", "Effect": "Deny", "Action": "*", "Resource": "*"}]}
ADMIN = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
QUARANTINE_ARN = "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV3"
# The real policy denies a named list of actions; it never denies "*".
QUARANTINE = {"Statement": [{"Sid": "Quarantine", "Effect": "Deny",
                             "Action": ["lambda:CreateFunction", "iam:CreateUser", "ec2:RunInstances"], "Resource": "*"}]}
S3_READ = {"Statement": {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
                         "Resource": ["arn:aws:s3:::app", "arn:aws:s3:::app/*"],
                         "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}}}


def denied(op):
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized for arn:aws:iam::1:user/x"}}, op)


class FakeIAM:
    def __init__(self, *, user_inline=None, user_managed=(), groups=None, role_inline=None, boundary=None, deny=()):
        self.user_inline, self.user_managed = user_inline or {}, list(user_managed)
        self.groups, self.role_inline, self.boundary, self.deny = groups or {}, role_inline or {}, boundary, set(deny)
        self.managed = {"arn:aws:iam::aws:policy/AdministratorAccess": ADMIN, "arn:aws:iam::123456789012:policy/S3Read": S3_READ,
                        "arn:aws:iam::123456789012:policy/Boundary": S3_READ}
        self.calls = []

    def _call(self, op):
        self.calls.append(op)
        if op in self.deny:
            raise denied(op)

    def get_user(self, UserName):
        self._call("get_user")
        return {"User": {"UserName": UserName, **({"PermissionsBoundary": {"PermissionsBoundaryArn": self.boundary}} if self.boundary else {})}}

    def get_role(self, RoleName):
        self._call("get_role")
        return {"Role": {"RoleName": RoleName}}

    def list_user_policies(self, UserName, Marker=None):
        self._call("list_user_policies")
        names = sorted(self.user_inline)
        # two pages, to prove pagination is followed
        return {"PolicyNames": names[:1], "IsTruncated": True, "Marker": "m"} if not Marker and len(names) > 1 else \
            {"PolicyNames": names[1:] if Marker else names, "IsTruncated": False}

    def get_user_policy(self, UserName, PolicyName):
        self._call("get_user_policy")
        return {"PolicyDocument": self.user_inline[PolicyName]}

    def list_attached_user_policies(self, UserName):
        self._call("list_attached_user_policies")
        return {"AttachedPolicies": [{"PolicyArn": a, "PolicyName": a.rsplit("/", 1)[-1]} for a in self.user_managed]}

    def list_groups_for_user(self, UserName):
        self._call("list_groups_for_user")
        return {"Groups": [{"GroupName": g} for g in self.groups]}

    def list_group_policies(self, GroupName):
        self._call("list_group_policies")
        return {"PolicyNames": []}

    def get_group_policy(self, GroupName, PolicyName):
        raise AssertionError("no inline group policies listed")

    def list_attached_group_policies(self, GroupName):
        self._call("list_attached_group_policies")
        return {"AttachedPolicies": [{"PolicyArn": a, "PolicyName": a.rsplit("/", 1)[-1]} for a in self.groups[GroupName]]}

    def list_role_policies(self, RoleName):
        self._call("list_role_policies")
        return {"PolicyNames": sorted(self.role_inline)}

    def get_role_policy(self, RoleName, PolicyName):
        self._call("get_role_policy")
        return {"PolicyDocument": self.role_inline[PolicyName]}

    def list_attached_role_policies(self, RoleName):
        self._call("list_attached_role_policies")
        return {"AttachedPolicies": []}

    def get_policy(self, PolicyArn):
        self._call("get_policy")
        return {"Policy": {"DefaultVersionId": "v2"}}

    def get_policy_version(self, PolicyArn, VersionId):
        self._call("get_policy_version")
        assert VersionId == "v2"
        return {"PolicyVersion": {"Document": self.managed[PolicyArn]}}


USER = "arn:aws:iam::123456789012:user/team/scanner-test-user"


@pytest.mark.parametrize("document", [[], {"Statement": [{"Effect": "Unexpected", "Action": "*", "Resource": "*"}]}])
def test_malformed_policy_documents_never_become_all_actions_allowed(document):
    got = collect_identity_policies(FakeIAM(user_inline={"malformed": document}), USER)
    assert got["collection_status"] == "PARTIAL" and got["errors"]
    assert got["summary"]["allow_all_policies"] == []


def test_cyclic_iam_pagination_is_bounded_and_reports_partial_evidence():
    class Repeating(FakeIAM):
        def list_user_policies(self, **kwargs):
            self.calls.append("list_user_policies")
            return {"PolicyNames": [], "IsTruncated": True, "Marker": "same"}

    iam = Repeating()
    got = collect_identity_policies(iam, USER)
    assert got["collection_status"] == "PARTIAL"
    assert iam.calls.count("list_user_policies") == 2
    assert any(error["error_code"] == "IAM_PAGINATION_INCOMPLETE" for error in got["errors"])


def test_deny_everything_inline_policy_is_read_as_written():
    iam = FakeIAM(user_inline={"DenyEverything": DENY_ALL, "Other": json.dumps(S3_READ)})
    got = collect_identity_policies(readonly_client(iam, "iam"), USER)
    assert got["collection_status"] == "COMPLETE" and got["principal_type"] == "IAM_USER" and got["errors"] == []
    assert [p["name"] for p in got["policies"]] == ["DenyEverything", "Other"]
    assert got["policies"][0]["statements"] == [{"sid": "DenyEverything", "effect": "Deny", "condition_keys": [], "actions": ["*"],
                                                 "not_actions": [], "resources": ["*"], "not_resources": [], "truncated": False}]
    assert got["summary"]["deny_all_policies"] == ["DenyEverything"] and got["summary"]["allow_all_policies"] == []
    # condition operators and keys only: the value (an IP range) is never stored
    assert got["policies"][1]["statements"][0]["condition_keys"] == ["IpAddress:aws:SourceIp"] and "203.0.113" not in json.dumps(got)


def test_managed_group_and_boundary_policies_for_a_user():
    iam = FakeIAM(user_managed=["arn:aws:iam::aws:policy/AdministratorAccess"], groups={"devs": ["arn:aws:iam::123456789012:policy/S3Read"]},
                  boundary="arn:aws:iam::123456789012:policy/Boundary")
    got = collect_identity_policies(iam, USER)
    assert [(p["source"], p["name"]) for p in got["policies"]] == [
        ("MANAGED_USER", "AdministratorAccess"), ("MANAGED_GROUP", "S3Read"), ("PERMISSIONS_BOUNDARY", "Boundary")]
    assert got["policies"][0]["aws_managed"] and got["policies"][1]["group"] == "devs"
    summary = got["summary"]
    # administrator access, but the boundary does not allow everything
    assert summary["allow_all_policies"] == ["AdministratorAccess"] and summary["boundary_limits_allow_all"]
    assert summary["allowed_actions"] == ["*", "s3:GetObject", "s3:ListBucket"]


def test_assumed_role_session_reads_the_role_and_access_denied_is_partial():
    iam = FakeIAM(role_inline={"ci": ADMIN}, deny={"list_attached_role_policies"})
    got = collect_identity_policies(iam, "arn:aws:sts::123456789012:assumed-role/Deployer/ci@example.com")
    assert got["principal_type"] == "IAM_ROLE" and got["collection_status"] == "PARTIAL"
    assert got["errors"] == [{"step": "ListAttachedRolePolicies", "error_code": "AccessDenied"}]
    assert "not authorized" not in json.dumps(got) and got["summary"]["allow_all_policies"] == ["ci"]
    everything = FakeIAM(deny={"get_user", "list_user_policies", "list_attached_user_policies", "list_groups_for_user"})
    assert collect_identity_policies(everything, USER)["collection_status"] == "FAILED"
    # an operation outside the scanner's read-only boundary is recorded, not raised
    class Refusing(FakeIAM):
        def __getattribute__(self, name):
            if name == "list_attached_user_policies":
                raise ReadOnlyViolation("scanner operation denied")
            return super().__getattribute__(name)

    refused = collect_identity_policies(Refusing(), USER)
    assert refused["collection_status"] == "PARTIAL"
    assert {"step": "ListAttachedUserPolicies", "error_code": "ReadOnlyViolation"} in refused["errors"]
    assert collect_identity_policies(FakeIAM(), "arn:aws:iam::123456789012:root")["collection_status"] == "NOT_APPLICABLE"
    assert collect_identity_policies(FakeIAM(), "arn:aws:sts::123456789012:federated-user/bob")["collection_status"] == "UNSUPPORTED"


def test_every_read_is_allowed_for_the_scanner_and_granted_by_the_templates():
    from cremore_aws_provider.aws_identity import SCANNER_ACTIONS

    snake = lambda action: re.sub(r"(?<!^)(?=[A-Z])", "_", action.split(":", 1)[1]).lower()
    assert {snake(a) for a in READ_ACTIONS} <= READ_OPERATIONS["iam"]
    assert set(READ_ACTIONS) <= set(SCANNER_ACTIONS)  # Identity Center uses this policy directly.
    root = Path(__file__).resolve().parents[4] / "deploy" / "cloudformation"
    for template in ("member-account-role.yaml", "single-account.yaml"):
        text = (root / template).read_text(encoding="utf-8")
        assert all(re.search(rf"\b{re.escape(a)}\b", text) for a in READ_ACTIONS), template


def test_summary_ignores_conditional_or_scoped_wildcards():
    scoped = {"source": "INLINE_USER", "name": "p", "statements": [
        {"sid": "", "effect": "Deny", "actions": ["*"], "resources": ["*"], "not_actions": [], "not_resources": [],
         "condition_keys": ["Bool:aws:MultiFactorAuthPresent"]},
        {"sid": "", "effect": "Allow", "actions": ["*"], "resources": ["arn:aws:s3:::app/*"], "not_actions": [], "not_resources": [],
         "condition_keys": []}]}
    summary = summarize([scoped])
    assert summary["deny_all_policies"] == [] and summary["allow_all_policies"] == [] and summary["conditional_statements"] == 1


def test_aws_quarantine_policy_is_named_and_cannot_be_forged_by_name():
    """A genuine AWS-managed policy is an attachment fact, not exposure evidence."""

    iam = FakeIAM(user_managed=[QUARANTINE_ARN])
    iam.managed[QUARANTINE_ARN] = QUARANTINE
    reading = collect_identity_policies(iam, USER)
    summary = reading["summary"]
    assert summary["quarantine_policies"] == ["AWSCompromisedKeyQuarantineV3"]
    assert any("do not establish the attaching actor" in item for item in reading["limitations"])
    # It denies named actions rather than "*", so without this the whole fact
    # reads as an ordinary deny statement count.
    assert summary["deny_all_policies"] == [] and summary["allow_all_policies"] == [] and summary["deny_statements"] == 1
    # A customer-managed policy can carry the same name: the AWS-owned ARN is what counts.
    forged = {"source": "MANAGED_USER", "name": "AWSCompromisedKeyQuarantineV3", "statements": [],
              "arn": "arn:aws:iam::123456789012:policy/AWSCompromisedKeyQuarantineV3"}
    assert summarize([forged])["quarantine_policies"] == []
    # Other partitions attach the same AWS-owned policy.
    china = {**forged, "arn": "arn:aws-cn:iam::aws:policy/AWSCompromisedKeyQuarantineV2"}
    assert summarize([china])["quarantine_policies"] == [china["name"]]
