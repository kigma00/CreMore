import fnmatch
import json
import re
from pathlib import Path

import pytest

from cremore_aws_provider.aws_readonly import READ_OPERATIONS, ReadOnlyViolation, readonly_client


class SDK:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def call(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return {"ok": True}
        return call


@pytest.mark.parametrize("service,operation", [
    ("s3", "put_bucket_notification_configuration"), ("s3", "restore_object"),
    ("iam", "update_access_key"), ("cloudtrail", "put_event_selectors"),
    ("secretsmanager", "get_secret_value"), ("s3", "_make_api_call"),
    ("s3", "generate_presigned_url"), ("s3", "get_waiter"),
])
def test_scanner_rejects_disallowed_calls_before_the_sdk(service, operation):
    sdk = SDK()
    guarded = readonly_client(sdk, service)
    with pytest.raises(ReadOnlyViolation):
        getattr(guarded, operation)()
    with pytest.raises(ReadOnlyViolation):
        guarded.get_paginator(operation)
    assert sdk.calls == []


def test_exact_read_operations_and_paginators_still_work():
    for service, operations in READ_OPERATIONS.items():
        sdk = SDK()
        guarded = readonly_client(sdk, service)
        for operation in operations:
            assert getattr(guarded, operation)() == {"ok": True}
        assert len(sdk.calls) == len(operations)
        assert readonly_client(guarded, service) is guarded
    s3 = readonly_client(SDK(), "s3")
    assert s3.get_paginator("list_objects_v2") == {"ok": True}
    with pytest.raises(ValueError):
        readonly_client(s3, "iam")


def test_onboarding_probes_work_without_allowing_ssm_values_or_writes():
    from cremore_aws_provider.onboarding import PROBES

    for probes in PROBES.values():
        for _key, service, operation, arguments, *_labels in probes:
            sdk = SDK()
            assert getattr(readonly_client(sdk, service), operation)(**arguments) == {"ok": True}
            assert sdk.calls == [(operation, (), arguments)]
    sdk = SDK()
    ssm = readonly_client(sdk, "ssm")
    for operation in ("get_parameter", "get_parameters", "get_parameters_by_path", "put_parameter", "delete_parameter"):
        with pytest.raises(ReadOnlyViolation):
            getattr(ssm, operation)()
    assert sdk.calls == []


def _role_blocks(template):
    """Read this template's resource mapping; policy documents are native JSON.

    Only the existing two-space resource/four-space Type shape is supported;
    a template layout change fails the guard instead of guessing YAML semantics.
    """
    resources = template.split("\nResources:\n", 1)[1].split("\nOutputs:", 1)[0]
    starts = list(re.finditer(r"(?m)^  ([A-Za-z0-9]+):\s*$", resources))
    return {match.group(1): resources[match.end():starts[i + 1].start() if i + 1 < len(starts) else len(resources)]
            for i, match in enumerate(starts)}


@pytest.mark.parametrize("name,scanner", [
    ("member-account-role.yaml", "ScannerRole"),
    ("single-account.yaml", "ScannerRole"),
    ("security-account.yaml", "ScannerExecutionRole"),
])
def test_unconditional_scanner_deny_covers_mutations_without_disabling_required_reads(name, scanner):
    template = (Path(__file__).resolve().parents[3] / "deploy" / "cloudformation" / name).read_text(encoding="utf-8")
    roles = _role_blocks(template)
    role = roles[scanner]
    assert re.search(r"(?m)^    Type: AWS::IAM::Role$", role)
    assert not re.search(r"(?m)^    Condition:", role)
    # Require the deny to be an unconditional member of Scanner.Properties.Policies.
    marker = "      Policies:\n        - PolicyName: ScannerMutationDeny\n          PolicyDocument: "
    document, _ = json.JSONDecoder().raw_decode(role.split(marker, 1)[1])
    [statement] = document["Statement"]
    assert statement["Effect"] == "Deny" and statement["Resource"] == "*"
    assert "Condition" not in statement and "NotAction" not in statement and "NotResource" not in statement
    assert all(isinstance(action, str) and ":" in action for action in statement["Action"])
    denied = lambda action: any(fnmatch.fnmatchcase(action.lower(), pattern.lower()) for pattern in statement["Action"])
    for action in ("s3:PutBucketNotification", "s3:PutInventoryConfiguration", "s3:PutObject",
                   "s3:DeleteObject", "s3:RestoreObject", "iam:UpdateAccessKey", "iam:AttachRolePolicy",
                   "cloudtrail:PutEventSelectors", "cloudtrail:StopLogging", "secretsmanager:PutSecretValue",
                   "secretsmanager:GetSecretValue", "events:PutRule", "sqs:PurgeQueue", "kms:DisableKey"):
        assert denied(action), action
    for action in ("s3:GetObject", "s3:ListBucket", "iam:GenerateCredentialReport",
                   "iam:SimulatePrincipalPolicy", "sts:AssumeRole", "cloudtrail:StartQuery",
                   "cloudtrail:GetQueryResults", "kms:Decrypt", "kms:GetKeyPolicy", "secretsmanager:DescribeSecret"):
        assert not denied(action), action
    # The scanner reads a key's policy (potential access) wherever it reads bucket policies.
    if scanner == "ScannerRole":
        assert "kms:GetKeyPolicy" in role and '!Sub "arn:${AWS::Partition}:kms:*:${AWS::AccountId}:key/*"' in role
    for resource_name, other in roles.items():
        if resource_name != scanner:
            assert "PolicyName: ScannerMutationDeny" not in other


def _member_template() -> str:
    path = Path(__file__).resolve().parents[3] / "deploy" / "cloudformation" / "member-account-role.yaml"
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("name", ["member-account-role.yaml", "single-account.yaml"])
def test_the_value_reader_reads_only_listed_values_and_only_as_the_scanner(name):
    import yaml

    text = (Path(__file__).resolve().parents[3] / "deploy" / "cloudformation" / name).read_text(encoding="utf-8")
    # BaseLoader keeps an intrinsic's argument and drops its tag (!Ref X -> "X", !If -> [condition, then, else]).
    template = yaml.load(text, Loader=yaml.BaseLoader)
    params, conditions, resources = template["Parameters"], template["Conditions"], template["Resources"]
    assert "value-reader" in template["Description"]
    assert params["EnableVaultValueRead"]["Default"] == "false"
    assert params["VaultValueReaderRoleName"]["Default"] == "CredentialVaultValueReaderRole"
    # The server's secret ARN rule (cremore/coverage/models.py): a known partition and the six-character suffix.
    secret = params["VaultSecretArns"]["AllowedPattern"]
    assert re.fullmatch(secret, "arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:prod/db-AbCdEf")
    for bad in ("arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db",
                "arn:aws-iso:secretsmanager:us-iso-east-1:123456789012:secret:prod/db-AbCdEf"):
        assert not re.fullmatch(secret, bad), bad
    for key, good, bad in (
            ("VaultSecretArns", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf",
             "arn:aws:secretsmanager:us-east-1:123456789012:secret:*"),
            ("VaultParameterPathArns", "arn:aws:ssm:*:123456789012:parameter/prod/*", "arn:aws:ssm:*:123456789012:parameter/*"),
            ("VaultKmsKeyArns", "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab", "arn:aws:kms:us-east-1:123456789012:key/*")):
        assert params[key]["Type"] == "CommaDelimitedList" and params[key]["Default"] == ""
        pattern = params[key]["AllowedPattern"]
        assert re.fullmatch(pattern, "") and re.fullmatch(pattern, good) and not re.fullmatch(pattern, bad), key
    assert re.fullmatch(params["VaultParameterPathArns"]["AllowedPattern"], "arn:aws:ssm:us-east-1:123456789012:parameter/prod")
    # The server's path rule (onboarding._SSM_PATH) takes exactly the paths the stack can name.
    from cremore_aws_provider.onboarding import _SSM_PATH
    for path in ("prod", "prod/app", "a.b_c-d/e", "prod@x", "a:b", "p~q", "x+y", "k=v", "a//b", ""):
        stack = bool(re.fullmatch(params["VaultParameterPathArns"]["AllowedPattern"],
                                  f"arn:aws:ssm:us-east-1:123456789012:parameter/{path}"))
        assert bool(_SSM_PATH.fullmatch(path)) == stack, path
    reader = resources["VaultValueReaderRole"]
    assert reader["Condition"] == "VaultValueReadEnabled" and conditions["VaultValueReadEnabled"] == ["EnableVaultValueRead", "true"]
    props = reader["Properties"]
    assert props["RoleName"] == "VaultValueReaderRoleName" and props["MaxSessionDuration"] == "3600"
    # Only this stack's scanner role, and only with the account's ExternalId.
    assert props["AssumeRolePolicyDocument"]["Statement"] == [{
        "Effect": "Allow", "Principal": {"AWS": "ScannerRole.Arn"}, "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"sts:ExternalId": "ExternalId"}}}]
    deny, listed_only, secrets, paths, keys = props["Policies"]
    [statement] = deny["PolicyDocument"]["Statement"]
    assert deny["PolicyName"] != "ScannerMutationDeny" and statement["Effect"] == "Deny" and statement["Resource"] == "*"
    assert "Condition" not in statement and "NotAction" not in statement
    [scanner_deny] = resources["ScannerRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    # The scanner's list without GetSecretValue, the value reads CreMore never makes, and Parameter Store changes.
    assert set(statement["Action"]) == (set(scanner_deny["Action"]) - {"secretsmanager:GetSecretValue"} | {
        "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParameterHistory", "ssm:PutParameter", "ssm:DeleteParameter*",
        "ssm:LabelParameterVersion", "ssm:UnlabelParameterVersion", "ssm:AddTagsToResource", "ssm:RemoveTagsFromResource",
        "ssm:PutResourcePolicy", "ssm:DeleteResourcePolicy"})
    denied = lambda action: any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in statement["Action"])
    assert denied("secretsmanager:BatchGetSecretValue") and denied("secretsmanager:PutSecretValue")
    assert denied("ssm:DeleteParameters") and denied("ssm:PutParameter")
    assert not any(denied(a) for a in ("secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret",
                                       "secretsmanager:ListSecretVersionIds", "ssm:GetParametersByPath", "kms:Decrypt"))
    # A secret's resource policy (Principal "*" with aws:PrincipalOrgID) cannot widen the list: every other secret is
    # denied, and with no list every secret is. No such deny for KMS: AWS managed keys are never listed.
    reads = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "secretsmanager:ListSecretVersionIds"]
    assert listed_only["PolicyName"] == "VaultValueReaderListedSecretsOnly"
    [[condition, listed, none]] = listed_only["PolicyDocument"]["Statement"]
    assert condition == "HasVaultSecretArns"
    assert listed == {"Effect": "Deny", "Action": reads, "NotResource": "VaultSecretArns"}
    assert none == {"Effect": "Deny", "Action": reads, "Resource": "*"}
    assert "kms" not in json.dumps(listed_only)
    # Each list is its own policy, left out while the list is empty.
    for policy, condition, actions, resource in (
            (secrets, "HasVaultSecretArns",
             ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "secretsmanager:ListSecretVersionIds"],
             "VaultSecretArns"),
            (paths, "HasVaultParameterPathArns", "ssm:GetParametersByPath", "VaultParameterPathArns"),
            (keys, "HasVaultKmsKeyArns", "kms:Decrypt", "VaultKmsKeyArns")):
        assert policy[0] == condition and policy[2] == "AWS::NoValue"
        assert "VaultValueReadEnabled" in str(conditions[condition]) and resource in str(conditions[condition])
        [allowed] = policy[1]["PolicyDocument"]["Statement"]
        assert allowed["Effect"] == "Allow" and allowed["Action"] == actions and allowed["Resource"] == resource
    [decrypt] = keys[1]["PolicyDocument"]["Statement"]
    assert decrypt["Condition"] == {"StringLike": {"kms:ViaService": [
        "secretsmanager.*.amazonaws.com", "ssm.*.amazonaws.com", "secretsmanager.*.amazonaws.com.cn", "ssm.*.amazonaws.com.cn"]}}
    # The scanner may assume this role and nothing else it gains with the option.
    [assume] = [p for p in resources["ScannerRole"]["Properties"]["Policies"]
                if isinstance(p, list) and p[0] == "VaultValueReadEnabled"]
    assert assume[1]["PolicyDocument"]["Statement"] == [{"Effect": "Allow", "Action": "sts:AssumeRole",
        "Resource": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/${VaultValueReaderRoleName}"}]
    assert template["Outputs"]["VaultValueReaderRoleArn"]["Condition"] == "VaultValueReadEnabled"
    if name == "single-account.yaml":  # its scanner role has no ExternalId; the reader's trust needs one
        assert params["ExternalId"]["Default"] == "" and re.fullmatch(params["ExternalId"]["AllowedPattern"], "e" * 16)
        rule = template["Rules"]["VaultValueReadRequiresExternalId"]
        assert rule["RuleCondition"] == ["EnableVaultValueRead", "true"] and "ExternalId" in str(rule["Assertions"])


def test_execution_role_can_resolve_its_own_arn_without_reading_other_roles():
    import yaml

    path = Path(__file__).resolve().parents[3] / "deploy" / "cloudformation" / "security-account.yaml"
    template = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    policies = template["Resources"]["ScannerExecutionRole"]["Properties"]["Policies"]
    [lookup] = [policy for policy in policies if isinstance(policy, dict) and policy.get("PolicyName") == "ReadOwnRole"]
    assert lookup["PolicyDocument"]["Statement"] == [{"Effect": "Allow", "Action": "iam:GetRole",
        "Resource": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/${ScannerExecutionRoleName}"}]


@pytest.mark.parametrize("name,parameter,role,optional", [
    ("single-account.yaml", "ScannerWorkloadPrincipalArn", "ScannerRole", False),
    ("single-account.yaml", "RemediationWorkloadPrincipalArn", "RemediationRole", True),
    ("security-account.yaml", "PlatformPrincipalArn", "ScannerExecutionRole", False),
    ("security-account.yaml", "PlatformPrincipalArn", "RemediationExecutionRole", False),
])
def test_direct_role_trust_accepts_only_an_exact_iam_principal(name, parameter, role, optional):
    template = (Path(__file__).resolve().parents[3] / "deploy" / "cloudformation" / name).read_text(encoding="utf-8")
    block = re.split(r"\n  (?=\S)", template.split(f"\n  {parameter}:\n", 1)[1], maxsplit=1)[0]
    pattern = re.search(r"(?m)^    AllowedPattern: '([^']+)'$", block)
    assert pattern, "a trust principal must be constrained before CloudFormation creates the role"
    assert f"Principal: {{ AWS: !Ref {parameter} }}" in _role_blocks(template)[role]
    for arn in ("arn:aws:iam::123456789012:role/workload/Scanner", "arn:aws:iam::123456789012:user/auditor",
                "arn:aws-us-gov:iam::123456789012:role/workload", "arn:aws-cn:iam::123456789012:role/workload"):
        assert re.fullmatch(pattern[1], arn), arn
    for invalid in ("123456789012", "arn:aws:iam::123456789012:root", "*",
                    "arn:aws:iam::123456789012:role/*", "arn:aws:iam::*:role/scanner",
                    "arn:aws:sts::123456789012:assumed-role/scanner/session", "arn:aws:iam::123456789012:role/"):
        assert not re.fullmatch(pattern[1], invalid), invalid
    assert bool(re.fullmatch(pattern[1], "")) is optional


def test_single_account_is_the_default_and_still_asserts_the_account_match():
    template = _member_template()
    # Default mode is SingleAccount.
    assert re.search(r"(?m)^  DeploymentMode:\s*$", template)
    assert re.search(r"(?m)^    Default: SingleAccount$", template)
    # The account-match rule is kept, only gated to SingleAccount.
    rule = template.split("TargetAccountMustMatch:", 1)[1].split("OrganizationModeRequiresOrgId:", 1)[0]
    assert "RuleCondition: !Equals [!Ref DeploymentMode, 'SingleAccount']" in rule
    assert "!Ref TargetAccountId" in rule and "!Ref AWS::AccountId" in rule


def test_organization_mode_skips_the_account_match_but_requires_the_org_id():
    template = _member_template()
    # TargetAccountId may be empty (Organization mode leaves it unused)...
    assert "AllowedPattern: '^$|^[0-9]{12}$'" in template
    # ...but Organization mode must still carry the aws:PrincipalOrgID guard.
    rule = template.split("OrganizationModeRequiresOrgId:", 1)[1]
    assert "RuleCondition: !Equals [!Ref DeploymentMode, 'Organization']" in rule
    assert "!Not [!Equals [!Ref OrganizationId, '']]" in rule
