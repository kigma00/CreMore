"""Potential-access tests with a fake IAM client, wired into the risk model."""

from __future__ import annotations

import json

import pytest

from cremore import risk
from cremore_aws_provider.investigation import (
    PotentialAccessService,
    provider_from_service,
    to_risk_signal,
)

ARN = "arn:aws:iam::123456789012:user/app-service"


class FakeIAM:
    def __init__(self, decisions: dict[str, str], pages: int = 1):
        self.decisions = decisions
        self.pages = pages
        self.calls = 0

    def simulate_principal_policy(self, PolicySourceArn, ActionNames, ResourceArns, Marker=None):
        self.calls += 1
        size = (len(ActionNames) + self.pages - 1) // self.pages
        results = [{"EvalActionName": a, "EvalDecision": self.decisions.get(a, "implicitDeny")}
                   for a in ActionNames[(self.calls - 1) * size:self.calls * size]]
        truncated = self.calls < self.pages
        return {"EvaluationResults": results, "IsTruncated": truncated,
                "Marker": str(self.calls) if truncated else None}


def _priv(sig):
    r = risk.assess(risk.Facts(
        provider="aws", credential_type="AWS_ACCESS_KEY",
        verification=risk.Verification(status="valid", aws_privilege=sig),
        exposure=risk.ExposureFacts(level="internal"),
    ))
    return next(e for e in r.evidence if e.dimension == "privilege_scope")


class BoomIAM:
    def simulate_principal_policy(self, **kwargs):
        raise RuntimeError("throttled")


SESSION_ARN = "arn:aws:sts::123456789012:assumed-role/App/session-abc"
ROLE_ARN = "arn:aws:iam::123456789012:role/team/App"  # the real role carries a path


class SessionIAM(FakeIAM):
    """A scanner IAM client that resolves an assumed-role name and records the source simulated."""

    def __init__(self, decisions, role_arn=ROLE_ARN, get_role_fails=False):
        super().__init__(decisions)
        self._role_arn, self._get_role_fails = role_arn, get_role_fails
        self.get_role_names, self.simulated_source = [], None

    def get_role(self, RoleName):
        self.get_role_names.append(RoleName)
        if self._get_role_fails:
            raise RuntimeError("AccessDenied")
        return {"Role": {"Arn": self._role_arn}}

    def simulate_principal_policy(self, PolicySourceArn, ActionNames, ResourceArns, Marker=None):
        self.simulated_source = PolicySourceArn
        return super().simulate_principal_policy(PolicySourceArn, ActionNames, ResourceArns, Marker)


def test_none_allowed_scores_low_privilege():
    pa = PotentialAccessService(FakeIAM({})).collect(ARN)  # all implicit deny
    assert pa.collection_status == "COMPLETE"
    assert pa.allowed == []
    priv = _priv(to_risk_signal(pa))
    assert priv.points == 5 and priv.reason_code == "aws_iam_no_high_impact_actions_allowed"


def test_escalation_allowed_scores_max_privilege():
    pa = PotentialAccessService(FakeIAM({"iam:CreateAccessKey": "allowed"})).collect(ARN)
    allowed = pa.allowed
    assert len(allowed) == 1 and allowed[0].risk == "PRIVILEGE_ESCALATION"
    priv = _priv(to_risk_signal(pa))
    assert priv.points == 20 and priv.reason_code == "aws_iam_privilege_escalation_allowed"


def test_read_only_allowed_scores_read_band():
    pa = PotentialAccessService(FakeIAM({"s3:GetObject": "allowed"})).collect(ARN)
    priv = _priv(to_risk_signal(pa))
    assert priv.points == 10 and priv.reason_code == "aws_iam_read_only_actions_allowed"


def test_unsupported_principal_leaves_privilege_unknown():
    pa = PotentialAccessService(FakeIAM({})).collect("not-an-arn")
    assert pa.collection_status == "UNSUPPORTED"
    sig = to_risk_signal(pa)
    assert sig.evaluated is False
    assert _priv(sig).reason_code == "privilege_scope_unknown"


def test_sts_session_is_evaluated_against_the_role_it_assumed():
    iam = SessionIAM({"s3:GetObject": "allowed"})
    pa = PotentialAccessService(iam).collect(SESSION_ARN)
    # Resolved by role name from the session ARN (then read again with the role's policies for named resources).
    assert set(iam.get_role_names) == {"App"}
    assert iam.simulated_source == ROLE_ARN         # simulated the role's real ARN, with its path
    assert pa.collection_status == "COMPLETE"
    assert pa.principal_arn == SESSION_ARN and pa.evaluated_role_arn == ROLE_ARN
    assert any("session policies" in limit for limit in pa.limitations)  # the session-vs-role caveat is recorded
    assert to_risk_signal(pa).evaluated is True     # the session now scores a privilege, like a long-lived key


def test_sts_session_falls_back_to_the_pathless_role_arn_without_get_role():
    iam = SessionIAM({}, get_role_fails=True)
    pa = PotentialAccessService(iam).collect(SESSION_ARN)
    assert iam.simulated_source == "arn:aws:iam::123456789012:role/App"
    assert pa.collection_status == "COMPLETE"
    assert pa.evaluated_role_arn == "arn:aws:iam::123456789012:role/App"


def test_view_surfaces_the_evaluated_role_for_a_session():
    from cremore_aws_provider.investigation.usage import potential_access_view

    pa = PotentialAccessService(SessionIAM({})).collect(SESSION_ARN)
    view = potential_access_view(pa)
    assert view["principal_arn"] == SESSION_ARN and view["evaluated_role_arn"] == ROLE_ARN
    assert view["evidence_level"] == "POTENTIAL"
    # a plain IAM principal has no separate evaluated role in the view
    assert "evaluated_role_arn" not in potential_access_view(PotentialAccessService(FakeIAM({})).collect(ARN))


def test_pagination_is_followed():
    iam = FakeIAM({"iam:PassRole": "allowed"}, pages=3)
    pa = PotentialAccessService(iam).collect(ARN)
    assert iam.calls == 3
    assert pa.collection_status == "COMPLETE"


def test_failure_is_reported_not_raised():
    pa = PotentialAccessService(BoomIAM()).collect(ARN)
    assert pa.collection_status == "FAILED"
    assert to_risk_signal(pa).evaluated is False


@pytest.mark.parametrize("change", ["missing", "duplicate", "unknown", "missing_marker"])
def test_incomplete_or_malformed_evaluations_never_establish_low_privilege(change):
    class PartialIAM(FakeIAM):
        def simulate_principal_policy(self, **kwargs):
            page = super().simulate_principal_policy(**kwargs)
            if change == "missing":
                page["EvaluationResults"].pop()
            elif change == "duplicate":
                page["EvaluationResults"].append(page["EvaluationResults"][0])
            elif change == "unknown":
                page["EvaluationResults"][0]["EvalDecision"] = "unknown"
            else:
                page["IsTruncated"] = True
                page.pop("Marker", None)
            return page

    result = PotentialAccessService(PartialIAM({})).collect(ARN)
    assert result.collection_status in ("PARTIAL", "FAILED")
    assert not to_risk_signal(result).evaluated


def test_provider_memoises_one_simulation_per_principal():
    iam = FakeIAM({"iam:CreateAccessKey": "allowed"})
    provider = provider_from_service(PotentialAccessService(iam))

    first = provider(ARN)
    second = provider(ARN)
    assert first is second  # cached, not re-simulated
    assert iam.calls == 1  # one IAM call serves repeated exposures of the principal
    assert first.evaluated and "PRIVILEGE_ESCALATION" in first.allowed_risks


def test_provider_yields_unevaluated_signal_on_failure():
    provider = provider_from_service(PotentialAccessService(BoomIAM()))
    assert provider(ARN).evaluated is False  # failure never raises into the scan


def test_session_provider_evaluates_each_principal_in_its_own_account():
    from cremore_aws_provider.aws_access import AccessBlocked
    from cremore_aws_provider.investigation.potential_access import provider_from_sessions

    class Sessions:
        def __init__(self):
            self.opened, self.blocked = [], {"999999999999"}

        def open(self, account_id, purpose):
            self.opened.append((account_id, purpose))
            if account_id in self.blocked or account_id is None:
                raise AccessBlocked("ACCOUNT_NOT_CONNECTED")
            return type("S", (), {"account_id": account_id, "client": lambda self, service, region: FakeIAM({})})()

    sessions = Sessions()
    provider = provider_from_sessions(sessions, "us-east-1")
    signal = provider("arn:aws:iam::123456789012:user/ci")
    assert signal.evaluated and signal.account_id == "123456789012"  # provenance travels with the score
    assert provider("arn:aws:iam::999999999999:user/other").evaluated is False
    # the account gate runs on every call, even when the evaluation is memoised
    provider("arn:aws:iam::123456789012:user/ci")
    sessions.blocked.add("123456789012")
    assert provider("arn:aws:iam::123456789012:user/ci").evaluated is False
    assert sessions.opened == [("123456789012", "scanner"), ("999999999999", "scanner"),
                               ("123456789012", "scanner"), ("123456789012", "scanner")]


class EvidenceIAM(FakeIAM):
    def __init__(self, detail, decision="implicitDeny"):
        super().__init__({"kms:Decrypt": decision})
        self.detail = detail

    def simulate_principal_policy(self, **kwargs):
        assert kwargs["ResourceArns"] == ["*"]
        assert "ContextEntries" not in kwargs
        page = super().simulate_principal_policy(**kwargs)
        for row in page["EvaluationResults"]:
            if row["EvalActionName"] == "kms:Decrypt":
                row.update(self.detail)
        return page


@pytest.mark.parametrize("decision", ["implicitDeny", "allowed", "explicitDeny"])
def test_missing_condition_context_survives_public_and_saved_evidence_without_scoring(decision):
    from cremore_aws_provider.investigation.permission_evidence import saved_risk_signal
    from cremore_aws_provider.investigation.usage import potential_access_view

    result = PotentialAccessService(EvidenceIAM({"MissingContextValues": ["aws:SourceIp", "aws:SourceIp"]}, decision)).collect(ARN)
    assert result.collection_status == "COMPLETE"  # Request completion is not assessment completeness.
    assert not to_risk_signal(result).evaluated
    view = potential_access_view(result)
    assert view["assessment_status"] == "MISSING_CONTEXT"
    assert view["effective_access"] == "NOT_EVALUATED"
    assert view["resource_arns"] == ["*"] and view["request_context"] == "NOT_SUPPLIED"
    row = next(row for row in view["actions"] if row["action"] == "kms:Decrypt")
    assert row["missing_context_values"] == ["aws:SourceIp"]
    assert not saved_risk_signal(view, "123456789012").evaluated


@pytest.mark.parametrize("organization,boundary", [(True, True), (False, True), (True, False)])
def test_returned_policy_layers_are_distinct_from_absent_details(organization, boundary):
    from cremore_aws_provider.investigation.usage import potential_access_view

    result = PotentialAccessService(EvidenceIAM({
        "OrganizationsDecisionDetail": {"AllowedByOrganizations": organization},
        "PermissionsBoundaryDecisionDetail": {"AllowedByPermissionsBoundary": boundary},
    }, "allowed" if organization and boundary else "explicitDeny")).collect(ARN)
    assert result.collection_status == "COMPLETE"
    view = potential_access_view(result)
    kms = next(row for row in view["actions"] if row["action"] == "kms:Decrypt")
    assert kms["organizations_allowed"] is organization
    assert kms["permissions_boundary_allowed"] is boundary
    assert "organizations_allowed" not in next(row for row in view["actions"] if row["action"] == "s3:GetObject")
    assert view["effective_access"] == "NOT_EVALUATED"


@pytest.mark.parametrize("detail", [
    {"MissingContextValues": "aws:SourceIp"}, {"MissingContextValues": ["private value\n"]},
    {"MissingContextValues": ["aws:key"] * 201},
    {"OrganizationsDecisionDetail": {"AllowedByOrganizations": "false"}},
    {"PermissionsBoundaryDecisionDetail": {}},
])
def test_malformed_evidence_is_partial_not_an_empty_context_or_an_allow(detail):
    result = PotentialAccessService(EvidenceIAM(detail)).collect(ARN)
    assert result.collection_status == "PARTIAL"
    assert not to_risk_signal(result).evaluated


def test_contradictory_allowed_and_boundary_denial_cannot_score_or_become_allowed():
    result = PotentialAccessService(EvidenceIAM({
        "PermissionsBoundaryDecisionDetail": {"AllowedByPermissionsBoundary": False}}, "allowed")).collect(ARN)
    assert not result.allowed and not to_risk_signal(result).evaluated


PAYROLL, OBJECTS = "arn:aws:s3:::payroll", "arn:aws:s3:::payroll/*"
SECRET = "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf"


class PolicyIAM(FakeIAM):
    """A principal with one inline policy of ``statements``; a request on ``*`` allows nothing, ``grants`` maps
    (action, resource) to the simulator's decision on a named resource, and ``details`` to more of its result."""

    def __init__(self, statements, grants, details=None):
        super().__init__({})
        self.statements, self.grants, self.details, self.requests = statements, grants, details or {}, []

    def __getattr__(self, name):  # get_user / get_role, and the policy listings of either
        if name in ("get_user", "get_role"):
            return lambda **kw: {"User" if name == "get_user" else "Role": {}}
        if name.startswith("list_attached_"):
            return lambda **kw: {"AttachedPolicies": [], "IsTruncated": False}
        if name.startswith("list_") and name.endswith("_policies"):
            return lambda **kw: {"PolicyNames": ["inline"], "IsTruncated": False}
        if name in ("get_user_policy", "get_role_policy"):
            return lambda **kw: {"PolicyDocument": {"Version": "2012-10-17", "Statement": self.statements}}
        if name == "list_groups_for_user":
            return lambda **kw: {"Groups": [], "IsTruncated": False}
        raise AttributeError(name)

    def simulate_principal_policy(self, PolicySourceArn, ActionNames, ResourceArns, Marker=None, **extra):
        resource = ResourceArns[0]
        self.requests.append((resource, extra.get("ResourcePolicy")))
        return {"EvaluationResults": [{"EvalActionName": action, "EvalDecision": "implicitDeny" if resource == "*"
                                       else self.grants.get((action, resource), "implicitDeny"),
                                       **self.details.get((action, resource), {})} for action in ActionNames],
                "IsTruncated": False}


class Policies:
    """S3, Secrets Manager and KMS clients that hold resource policies; ``None`` has none, an exception code refuses."""

    def __init__(self, bucket="{}", secret="{}", keys=None):
        self.bucket, self.secret, self.keys, self.asked = bucket, secret, keys or {}, []

    def get_key_policy(self, KeyId, PolicyName):
        self.asked.append(("key", KeyId, PolicyName))
        return {"Policy": self.keys[KeyId]}

    def get_bucket_policy(self, Bucket, ExpectedBucketOwner):
        from botocore.exceptions import ClientError

        self.asked.append(("bucket", Bucket, ExpectedBucketOwner))
        if self.bucket in ("NoSuchBucketPolicy", "AccessDenied"):
            raise ClientError({"Error": {"Code": self.bucket, "Message": "synthetic"}}, "GetBucketPolicy")
        return {"Policy": self.bucket}

    def get_resource_policy(self, SecretId):
        self.asked.append(("secret", SecretId))
        return {"ResourcePolicy": self.secret} if self.secret else {}


def test_a_grant_on_named_resources_is_found_where_a_request_on_star_finds_none():
    from cremore_aws_provider.investigation.permission_evidence import saved_risk_signal
    from cremore_aws_provider.investigation.usage import potential_access_view

    statements = [{"Effect": "Allow", "Action": ["s3:Get*", "s3:ListBucket"], "Resource": [PAYROLL, OBJECTS]},
                  {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": SECRET},
                  {"Effect": "Allow", "NotAction": "iam:*", "Resource": "arn:aws:s3:::other/*"}]
    iam = PolicyIAM(statements, {("s3:GetObject", OBJECTS): "allowed", ("s3:ListBucket", PAYROLL): "allowed",
                                 ("secretsmanager:GetSecretValue", SECRET): "explicitDeny"})
    resources = Policies(bucket='{"Statement": []}', secret='{"Statement": [{"Effect": "Deny"}]}')
    result = PotentialAccessService(iam, s3=resources, secrets=lambda region: resources).collect(ARN)
    actions = {a.action: a for a in result.actions}
    assert (actions["s3:GetObject"].decision, actions["s3:GetObject"].resource_scope) == ("ALLOWED", "NAMED")
    assert actions["s3:GetObject"].resources == (OBJECTS,) and actions["s3:ListBucket"].resources == (PAYROLL,)
    # The secret's own policy denies it: the action stays without an allow, and the deny is kept per resource.
    assert actions["secretsmanager:GetSecretValue"].decision == "IMPLICIT_DENY"
    named = {n.resource: n for n in result.named_resources}
    assert named[SECRET].explicit_deny == ("secretsmanager:GetSecretValue",)
    assert {n.resource_policy for n in named.values()} == {"EVALUATED"} and result.named_resources_complete
    # A NotAction statement names no particular resource; each policy was read for the user's own account.
    assert set(named) == {PAYROLL, OBJECTS, SECRET}
    assert ("bucket", "payroll", "123456789012") in resources.asked and ("secret", SECRET) in resources.asked
    assert ("arn:aws:s3:::payroll/*", '{"Statement": []}') in iam.requests
    assert to_risk_signal(result).allowed_risks == frozenset({"READ"})
    view = potential_access_view(result)
    assert view["assessment_version"] == 3 and view["resource_arns"][0] == "*" and SECRET in view["resource_arns"]
    assert next(row for row in view["actions"] if row["action"] == "s3:GetObject")["resources"] == [OBJECTS]
    assert saved_risk_signal(view, "123456789012").allowed_risks == frozenset({"READ"})
    broken = {**view, "actions": [{**row, "resources": ["not-an-arn"]} if row["action"] == "s3:GetObject" else row
                                  for row in view["actions"]]}
    assert not saved_risk_signal(broken, "123456789012").evaluated  # malformed evidence never scores


@pytest.mark.parametrize("bucket,state", [("NoSuchBucketPolicy", "NONE"), ("AccessDenied", "NOT_READ"),
                                          # Text past Latin-1 the simulator refuses; it is simulated without.
                                          ('{"Id": "보안", "Statement": []}', "NOT_READ")])
def test_a_resource_policy_that_is_absent_or_unreadable_says_so(bucket, state):
    iam = PolicyIAM([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": OBJECTS},
                     {"Effect": "Allow", "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::logs-*/*"}],
                    {("s3:GetObject", OBJECTS): "allowed"})
    resources = Policies(bucket=bucket)
    result = PotentialAccessService(iam, s3=resources).collect(ARN)
    named = {n.resource: n.resource_policy for n in result.named_resources}
    # A pattern names many buckets: no single policy is read for it.
    assert named == {OBJECTS: state, "arn:aws:s3:::logs-*/*": "NOT_READ"}
    assert all(policy is None for _resource, policy in iam.requests)


def test_a_role_is_simulated_on_named_resources_without_their_policies():
    role = "arn:aws:iam::123456789012:role/app"
    iam = PolicyIAM([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": OBJECTS}], {("s3:GetObject", OBJECTS): "allowed"})
    resources = Policies()
    result = PotentialAccessService(iam, s3=resources).collect(role)
    assert next(a for a in result.actions if a.action == "s3:GetObject").resources == (OBJECTS,)
    # The simulator takes a resource policy only for an IAM user caller.
    assert [n.resource_policy for n in result.named_resources] == ["NOT_SUPPORTED"] and not resources.asked


KEY = "arn:aws:kms:eu-west-1:123456789012:key/{}"


def _key_policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


# The default key policy: IAM policies of the account may grant the key's use.
DEFAULT_KEY_POLICY = _key_policy({"Sid": "Enable IAM User Permissions", "Effect": "Allow",
                                  "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:*", "Resource": "*"})


def test_a_kms_key_policy_decides_what_an_identity_policy_alone_allows():
    from cremore_aws_provider.investigation.usage import potential_access_view

    enabled, closed, granted, conditional = (KEY.format(name) for name in ("1-enabled", "2-closed", "3-granted", "4-when"))
    alias = "arn:aws:kms:eu-west-1:123456789012:alias/app"
    admins = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:role/KeyAdmins"}, "Action": "kms:*",
              "Resource": "*"}
    when = {"Effect": "Allow", "Principal": {"AWS": "123456789012"}, "Action": "kms:Decrypt", "Resource": "*",
            "Condition": {"StringEquals": {"kms:CallerAccount": "123456789012"}}}
    keys = [enabled, closed, granted, conditional, alias]
    # The simulator joins each key policy to the identity policy, so it allows on every key; on one of them a
    # statement of the key policy itself names the user.
    iam = PolicyIAM([{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": keys}],
                    {("kms:Decrypt", key): "allowed" for key in keys},
                    {("kms:Decrypt", granted): {"ResourceSpecificResults": [{
                        "EvalResourceName": granted, "EvalResourceDecision": "allowed",
                        "MatchedStatements": [{"SourcePolicyId": "ResourcePolicy", "SourcePolicyType": "resource"}]}]}})
    resources = Policies(keys={enabled: DEFAULT_KEY_POLICY, closed: _key_policy(admins), granted: _key_policy(admins),
                               conditional: _key_policy(when)})
    result = PotentialAccessService(iam, kms=lambda region: resources).collect(ARN)
    decrypt = next(a for a in result.actions if a.action == "kms:Decrypt")
    assert (decrypt.decision, decrypt.resources) == ("ALLOWED", (enabled, granted))
    named = {n.resource: n for n in result.named_resources}
    assert (named[closed].allowed, named[closed].key_policy_blocks) == ((), ("kms:Decrypt",))
    # Only under a condition: neither allowed nor blocked, and the condition's key says why.
    assert (named[conditional].allowed, named[conditional].key_policy_blocks, named[conditional].conditional,
            named[conditional].missing_context_values) == ((), (), ("kms:Decrypt",), ("kms:CallerAccount",))
    # An alias ARN in a policy grants no key use, so it is not simulated.
    assert alias not in named and all(resource != alias for resource, _policy in iam.requests)
    assert {n.resource_policy for n in named.values()} == {"EVALUATED"}
    assert ("key", closed, "default") in resources.asked and (closed, _key_policy(admins)) in iam.requests
    rows = {row["resource"]: row for row in potential_access_view(result)["named_resources"]}
    assert rows[closed]["key_policy_blocks"] == ["kms:Decrypt"] and "key_policy_blocks" not in rows[enabled]


def test_a_key_whose_policy_leaves_iam_out_keeps_the_action_without_an_allow():
    key = KEY.format("closed")
    iam = PolicyIAM([{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key}], {("kms:Decrypt", key): "allowed"})
    result = PotentialAccessService(iam, kms=lambda region: Policies(keys={key: _key_policy()})).collect(ARN)
    assert next(a for a in result.actions if a.action == "kms:Decrypt").decision == "IMPLICIT_DENY"
    assert "SECRET_ACCESS" not in to_risk_signal(result).allowed_risks
    assert result.named_resources[0].key_policy_blocks == ("kms:Decrypt",)


@pytest.mark.parametrize("statement,verdict", [
    ({"Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:*"}, "ENABLED"),
    ({"Principal": {"AWS": ["arn:aws:iam::999999999999:root", "123456789012"]}, "Action": ["kms:Decrypt"]}, "ENABLED"),
    ({"Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "NotAction": "kms:ScheduleKeyDeletion"}, "ENABLED"),
    # The key policy's own grant to the user, or to everyone, needs nothing of IAM.
    ({"Principal": {"AWS": ARN}, "Action": ["kms:Decrypt", "kms:Encrypt"]}, "ENABLED"),
    ({"Principal": "*", "Action": "kms:*"}, "ENABLED"),
    ({"Principal": {"AWS": "*"}, "Action": "kms:Decrypt"}, "ENABLED"),
    ({"Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "NotAction": "kms:Decrypt"}, "REFUSED"),
    # An AWS managed key lets IAM policies grant only reading its metadata.
    ({"Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": ["kms:Describe*", "kms:Get*", "kms:List*"]},
     "REFUSED"),
    ({"Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "kms:*"}, "REFUSED"),
    ({"Principal": {"AWS": "arn:aws-us-gov:iam::123456789012:root"}, "Action": "kms:*"}, "REFUSED"),
    ({"Principal": {"AWS": "arn:aws:iam::123456789012:user/someone-else"}, "Action": "kms:*"}, "REFUSED"),
    ({"Principal": {"Service": "logs.amazonaws.com"}, "Action": "kms:*"}, "REFUSED"),
    ({"Effect": "Deny", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:*"}, "REFUSED"),
    ({"Principal": {"AWS": "arn:aws:iam::123456789012:root"}}, "REFUSED"),  # no Action: KMS refuses such a policy
    # A statement for this key alone, for other keys only, or for everything but some.
    ({"Principal": {"AWS": ARN}, "Action": "kms:Decrypt", "Resource": KEY.format("this")}, "ENABLED"),
    ({"Principal": {"AWS": ARN}, "Action": "kms:Decrypt", "Resource": KEY.format("other")}, "REFUSED"),
    ({"Principal": {"AWS": ARN}, "Action": "kms:Decrypt", "NotResource": "*"}, "REFUSED"),
])
def test_whether_a_key_policy_admits_decrypt_beside_the_identity_policy(statement, verdict):
    from cremore_aws_provider.investigation.potential_access import _key_policy_admits

    policy = _key_policy({"Effect": "Allow", **({} if "NotResource" in statement else {"Resource": "*"}), **statement})
    assert _key_policy_admits(policy, KEY.format("this"), ARN, "kms:Decrypt") == (verdict, ())
    assert _key_policy_admits("not json", KEY.format("this"), ARN, "kms:Decrypt") == ("UNKNOWN", ())


def test_an_aws_managed_keys_grant_through_a_service_depends_on_the_request():
    """An AWS managed key lets everyone in the account use it only through its service (kms:ViaService): that is not
    an allow without the request, and the condition says why."""
    from cremore_aws_provider.investigation.potential_access import _key_policy_admits

    managed = _key_policy({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": ["kms:Decrypt"], "Resource": "*",
                           "Condition": {"StringEquals": {"kms:CallerAccount": "123456789012",
                                                          "kms:ViaService": "secretsmanager.eu-west-1.amazonaws.com"}}},
                          {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                           "Action": ["kms:Describe*", "kms:Get*", "kms:List*", "kms:RevokeGrant"], "Resource": "*"})
    assert _key_policy_admits(managed, KEY.format("this"), ARN, "kms:Decrypt") == (
        "UNKNOWN", ("kms:CallerAccount", "kms:ViaService"))


@pytest.mark.parametrize("statement,counted", [
    ({"SourcePolicyType": "Resource Policy", "SourcePolicyId": "ResourcePolicy"}, True),
    ({"SourcePolicyType": "Resource Policy", "SourcePolicyId": "something-else"}, True),
    ({"SourcePolicyType": "resource"}, True), ({"SourcePolicyId": "ResourcePolicy"}, True),
    # A managed policy's id is its own name: one named ResourcePolicy is still the user's identity policy.
    ({"SourcePolicyType": "IAM Policy", "SourcePolicyId": "ResourcePolicy"}, False),
])
def test_the_simulators_names_for_the_resource_policy_all_count(statement, counted):
    """The API reference lists ``resource``; its examples, like the service, say ``Resource Policy``."""
    key = KEY.format("granted")
    detail = {"ResourceSpecificResults": [{"EvalResourceName": key, "EvalResourceDecision": "allowed",
                                           "MatchedStatements": [statement]}]}
    iam = PolicyIAM([{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": key}], {("kms:Decrypt", key): "allowed"},
                    {("kms:Decrypt", key): detail})
    other = {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:role/Admin"}, "Action": "kms:*", "Resource": "*"}
    result = PotentialAccessService(iam, kms=lambda region: Policies(keys={key: _key_policy(other)})).collect(ARN)
    assert next(a for a in result.actions if a.action == "kms:Decrypt").resources == ((key,) if counted else ())


def test_missing_context_a_named_resource_reports_is_kept_and_withholds_the_allow():
    # With a resource ARN the simulator puts missing context under ResourceSpecificResults.
    detail = {"ResourceSpecificResults": [{"EvalResourceName": OBJECTS, "EvalResourceDecision": "allowed",
                                           "MissingContextValues": ["aws:SourceIp"]}]}
    iam = PolicyIAM([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": OBJECTS}],
                    {("s3:GetObject", OBJECTS): "allowed"}, {("s3:GetObject", OBJECTS): detail})
    result = PotentialAccessService(iam).collect(ARN)
    assert next(a for a in result.actions if a.action == "s3:GetObject").decision == "IMPLICIT_DENY"
    assert result.named_resources[0].missing_context_values == ("aws:SourceIp",)
    assert result.named_resources[0].conditional == ("s3:GetObject",)
    broken = PolicyIAM([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": OBJECTS}],
                       {("s3:GetObject", OBJECTS): "allowed"}, {("s3:GetObject", OBJECTS): {"ResourceSpecificResults": "x"}})
    malformed = PotentialAccessService(broken).collect(ARN)
    assert malformed.error_code and not malformed.named_resources and not malformed.named_resources_complete


def test_more_named_resources_than_the_limit_are_marked_incomplete():
    buckets = [f"arn:aws:s3:::bucket-{index:02}/*" for index in range(30)]
    iam = PolicyIAM([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": buckets}], {})
    result = PotentialAccessService(iam).collect(ARN)
    assert len(result.named_resources) == 25 and result.named_resources_complete is False


def test_legacy_saved_simulation_requires_recollection_and_current_round_trip_preserves_score():
    from cremore_aws_provider.investigation.permission_evidence import saved_risk_signal
    from cremore_aws_provider.investigation.usage import potential_access_view

    result = PotentialAccessService(FakeIAM({"s3:GetObject": "allowed"})).collect(ARN)
    view = potential_access_view(result)
    assert saved_risk_signal(view, "123456789012").allowed_risks == frozenset({"READ"})
    view.pop("assessment_version")
    assert not saved_risk_signal(view, "123456789012").evaluated
    assert view["collection_status"] == "COMPLETE"  # Do not rewrite historical evidence.
