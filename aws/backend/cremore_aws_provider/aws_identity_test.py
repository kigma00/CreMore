"""Runtime AWS identity: stable principals, trust derivation, login-expiry detection."""

from __future__ import annotations

import pytest

from cremore_aws_provider import aws_identity as ident


@pytest.mark.parametrize("method,profiles,expected", [
    ("iam-role", {}, "iam-role"), ("container-role", {}, "container-role"),
    ("assume-role-with-web-identity", {}, "assume-role-with-web-identity"),
    ("sso", {}, None), ("env", {}, None), ("shared-credentials-file", {}, None),
    ("custom-process", {}, None),
    ("assume-role", {"default": {"role_arn": "synthetic-role", "credential_source": "Ec2InstanceMetadata"}}, "iam-role"),
    ("assume-role", {"default": {"source_profile": "source"}, "source": {"sso_session": "human"}}, None),
    ("assume-role", {"default": {"source_profile": "source"}, "source": {"aws_access_key_id": "synthetic"}}, None),
    ("assume-role", {"default": {"source_profile": "default"}}, None),
    ("assume-role", {"default": {"mfa_serial": "human", "credential_source": "Ec2InstanceMetadata"}}, None),
])
def test_server_workload_provenance_reads_only_refresh_method(method, profiles, expected):
    from types import SimpleNamespace

    session = SimpleNamespace(get_credentials=lambda: SimpleNamespace(method=method), profile_name="default",
                              _session=SimpleNamespace(full_config={"profiles": profiles}))
    assert ident.server_workload_source(session) == expected

ACCOUNT = "111122223333"
SUFFIX = "1234567890abcdef"


@pytest.mark.parametrize("response,expected", [
    ({"Error": {"Code": "404"}}, "404"),
    ({"Error": {"Code": "raw untrusted error detail"}}, "RuntimeError"),
    ({"Error": []}, "RuntimeError"),
])
def test_collector_and_aws_errors_share_safe_codes(response, expected):
    from cremore.collectors.base import error_label
    error = RuntimeError("untrusted message")
    error.response = response
    assert error_label(error) == ident.error_code(error) == expected


class Sts:
    def __init__(self, arn=None, exc=None):
        self.arn, self.exc = arn, exc

    def get_caller_identity(self):
        if self.exc:
            raise self.exc
        return {"Arn": self.arn, "Account": ACCOUNT}


class Iam:
    def __init__(self, arn=None):
        self.arn = arn

    def get_role(self, RoleName):
        if self.arn is None:
            raise PermissionError("AccessDenied")
        return {"Role": {"Arn": self.arn}}


class ClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class UnauthorizedSSOTokenError(Exception):
    pass


def sso_session(permission_set="CreMoreScanner"):
    return f"arn:aws:sts::{ACCOUNT}:assumed-role/AWSReservedSSO_{permission_set}_{SUFFIX}/alice@example.com"


def test_identity_center_trust_pins_path_region_and_permission_set_but_not_the_suffix():
    looked_up = f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/eu-west-2/AWSReservedSSO_CreMoreScanner_{SUFFIX}"
    out = ident.describe(Sts(sso_session()), Iam(looked_up))
    assert out["kind"] == "IDENTITY_CENTER" and out["sso_region"] == "eu-west-2" and out["principal_arn"] == looked_up
    pattern = out["trust"]["principal_pattern"]
    assert pattern == f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/eu-west-2/AWSReservedSSO_CreMoreScanner_" + "?" * 16
    assert out["match_key"] == f"identity-center:aws:{ACCOUNT}:CreMoreScanner"
    assert "alice" not in pattern and SUFFIX not in pattern and ident.approvable(out) is None


def test_identity_center_region_from_profile_and_us_east_1_has_no_region_segment():
    out = ident.describe(Sts(sso_session()), Iam(None), sso_region="us-east-1")
    assert "/sso.amazonaws.com/AWSReservedSSO_CreMoreScanner_" in out["trust"]["principal_pattern"]
    unknown = ident.describe(Sts(sso_session()), None)
    assert unknown["requires"] == "IDENTITY_CENTER_REGION" and ident.approvable(unknown) == "IDENTITY_CENTER_REGION_REQUIRED"
    assert unknown["trust"] is None


def test_iam_role_path_is_looked_up_or_given_exactly_never_widened():
    session = f"arn:aws:sts::{ACCOUNT}:assumed-role/SecurityScanner/i-0abc"
    exact = f"arn:aws:iam::{ACCOUNT}:role/platform/security/SecurityScanner"
    assert ident.describe(Sts(session), Iam(exact))["trust"] == {"type": "IamRole", "principal_arn": exact}
    missing = ident.describe(Sts(session), Iam(None))
    assert missing["requires"] == "ROLE_ARN" and missing["principal_arn"] is None
    given = ident.describe(Sts(session), None, role_arn=exact)
    assert given["principal_arn"] == exact and given["match_key"] == f"role:aws:{ACCOUNT}:SecurityScanner"
    for wrong in ("arn:aws:iam::999988887777:role/SecurityScanner", f"arn:aws:iam::{ACCOUNT}:role/OtherRole",
                  f"arn:aws:iam::{ACCOUNT}:role/*/SecurityScanner"):
        assert ident.describe(Sts(session), None, role_arn=wrong)["requires"] == "ROLE_ARN", wrong


def test_users_are_stable_root_is_refused_and_sessions_are_never_principals():
    user = f"arn:aws:iam::{ACCOUNT}:user/ops/alice"
    out = ident.describe(Sts(user), None)
    assert out["kind"] == "IAM_USER" and out["principal_arn"] == user and ident.approvable(out) is None
    root = ident.describe(Sts(f"arn:aws:iam::{ACCOUNT}:root"), None)
    assert root["kind"] == "ROOT" and ident.approvable(root) == "ROOT_CREDENTIALS_REFUSED"
    fed = ident.describe(Sts(f"arn:aws:sts::{ACCOUNT}:federated-user/bob"), None)
    assert ident.approvable(fed) == "UNSUPPORTED_IDENTITY"
    sso = ident.describe(Sts(sso_session()), None, sso_region="eu-west-2")
    assert ":sts::" not in sso["principal_arn"] and "assumed-role" not in sso["match_key"]


def test_longer_permission_set_names_cannot_match_the_pattern():
    import fnmatch

    pattern = ident.describe(Sts(sso_session()), None, sso_region="ap-northeast-2")["trust"]["principal_pattern"]
    base = f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/ap-northeast-2/AWSReservedSSO_"
    assert fnmatch.fnmatchcase(f"{base}CreMoreScanner_abcdef0123456789", pattern)
    assert not fnmatch.fnmatchcase(f"{base}CreMoreScanner_Admin_abcdef0123456789", pattern)


@pytest.mark.parametrize(("exc", "state"), [
    (UnauthorizedSSOTokenError("expired"), "LOGIN_REQUIRED"),
    (ClientError("ExpiredToken"), "LOGIN_REQUIRED"),
    (type("NoCredentialsError", (Exception,), {})(), "NO_CREDENTIALS"),
    (ClientError("Throttling"), "ERROR"),
])
def test_credential_failures_are_states_not_exceptions(exc, state):
    assert ident.describe(Sts(exc=exc))["state"] == state


def test_login_required_is_found_through_wrapped_collector_errors():
    from cremore.collectors.base import CollectorError

    try:
        try:
            raise UnauthorizedSSOTokenError("token expired")
        except UnauthorizedSSOTokenError as inner:
            raise CollectorError("S3_LIST_FAILED", "UnauthorizedSSOTokenError") from inner
    except CollectorError as wrapped:
        assert ident.is_login_required(wrapped)
        assert ident.collection_error_code(wrapped) == "AWS_LOGIN_REQUIRED"
    assert not ident.is_login_required(ClientError("AccessDenied"))
    assert ident.collection_error_code(ClientError("AccessDenied")) == "AccessDenied"
    assert not ident.is_login_required("AccessDenied")
    for code in ("ExpiredToken", "ExpiredTokenException", "UnauthorizedSSOTokenError", "AWS_LOGIN_REQUIRED", "AwsLoginRequired"):
        assert ident.is_login_required(code)


def test_stack_parameters_and_cli_command_are_shell_safe():
    trust = ident.describe(Sts(sso_session()), None, sso_region="eu-west-2")["trust"]
    params = ident.stack_parameters(trust, target_account="444455556666", external_id="ext-_abc123",
                                    role_name="CredentialExposureScannerRole")
    assert params["TrustedPrincipalType"] == "IdentityCenter" and params["IdentityCenterAccountId"] == ACCOUNT
    cmd = ident.cli_command(params, region="eu-west-2", template_file="member-account-role.yaml",
                            stack_name="cremore-scanner")
    assert "'TrustedPrincipalPattern=arn:aws:iam::" in cmd and "????????????????'" in cmd and "\n" not in cmd
    policy = ident.hub_policy("aws", "CredentialExposureScannerRole")["Statement"][0]
    assert policy["Action"] == "sts:AssumeRole" and policy["Resource"] == "arn:aws:iam::*:role/CredentialExposureScannerRole"


def test_the_hub_policy_names_the_registered_accounts_or_their_organization():
    open_ = ident.hub_policy("aws-eusc", "R")["Statement"][0]
    assert "Condition" not in open_ and open_["Resource"] == "arn:aws-eusc:iam::*:role/R"
    listed = ident.hub_policy("aws", "R", accounts=["222222222222", "111111111111", "111111111111"])["Statement"][0]
    assert listed["Condition"] == {"StringEquals": {"aws:ResourceAccount": ["111111111111", "222222222222"]}}
    # An organization covers the accounts a sync registers later.
    org = ident.hub_policy("aws", "R", accounts=["111111111111"], organizations=["o-abc123"])["Statement"][0]
    assert org["Condition"] == {"StringEquals": {"aws:ResourceOrgID": ["o-abc123"]}}


def test_the_european_sovereign_cloud_partition_and_region_are_accepted_everywhere_aws_is_checked():
    import re

    from cremore.api import finding_evidence, source_contract
    from cremore.api.aws_support import console_host
    from cremore.remediation import action_plans
    from cremore_aws_provider import (
        aws_inventory_settings,
        aws_org_settings,
        onboarding,
        secret_inventory,
        usage_inventory,
    )

    region, arn = "eusc-de-east-1", "arn:aws-eusc:secretsmanager:eusc-de-east-1:123456789012:secret:app/db-Ab12Cd"
    for pattern in (ident._REGION, aws_inventory_settings._REGION, aws_org_settings.REGION, finding_evidence._REGION):
        assert pattern.fullmatch(region), pattern.pattern
    assert onboarding._REGION.fullmatch(region) and usage_inventory._REGION_DIRECTORY.fullmatch(region)
    assert ident._SSO_PATH.match(f"role/aws-reserved/sso.amazonaws.com/{region}/AWSReservedSSO_Read_0123456789abcdef")
    assert secret_inventory._ARN.fullmatch(arn) and action_plans._SECRET_ARN.fullmatch(arn)
    assert arn.startswith(source_contract.SECRET_ARN_PREFIX)
    assert usage_inventory._ARN.fullmatch("arn:aws-eusc:iam::123456789012:user/robot")
    assert console_host("aws-eusc", region) == "eusc-de-east-1.console.amazonaws-eusc.eu"
    assert re.fullmatch(ident._REGION, "us-east-1") and not ident._REGION.fullmatch("abcde-east-1")


def test_the_hub_scope_is_the_organization_only_when_every_registered_account_is_in_it():
    from cremore.api.aws_support import hub_scope
    from cremore.db.repository import InMemoryRepository
    from cremore.domain.models import AwsAccount
    from cremore_aws_provider.aws_org_context import SUMMARY_KEY, put_account_context

    repo = InMemoryRepository()
    assert hub_scope(repo) == {"accounts": []}
    for account in ("111111111111", "222222222222"):
        repo.create_aws_account(AwsAccount(account_id=account, name=account))
    repo.create_aws_account(AwsAccount(account_id="333333333333", name="self", access="RUNTIME_IDENTITY"))
    assert hub_scope(repo) == {"accounts": ["111111111111", "222222222222"]}  # nothing assumed in its own account
    repo.put_setting(SUMMARY_KEY, {"status": "COMPLETE", "organization_id": "o-abc123"}, "test")
    inside = {"status": "COMPLETE", "organization_id": "o-abc123", "path": [{"id": "r-ab12", "name": "Root"}]}
    put_account_context(repo, "111111111111", "organization", inside)
    # A sync records the organization on every account; an account without a path is outside it.
    put_account_context(repo, "222222222222", "organization", {**inside, "path": []})
    assert hub_scope(repo) == {"accounts": ["111111111111", "222222222222"]}
    put_account_context(repo, "222222222222", "organization", inside)
    assert hub_scope(repo) == {"organizations": ["o-abc123"]}
    repo.put_setting(SUMMARY_KEY, {"status": "PARTIAL", "organization_id": "o-abc123"}, "test")
    assert hub_scope(repo) == {"accounts": ["111111111111", "222222222222"]}


def test_remediation_trust_parameters_never_touch_the_scanner_trust():
    scanner = {"type": "IdentityCenter", "account_id": "111111111111", "principal_pattern": "p"}
    remediation = {"type": "IamRole", "principal_arn": "arn:aws:iam::111111111111:role/ops/Remediate"}
    params = ident.stack_parameters(scanner, target_account="123456789012", external_id="e" * 16, role_name="S",
                                    remediation_trust=remediation, remediation_role_name="R")
    assert params["TrustedPrincipalType"] == "IdentityCenter" and params["TrustedPrincipalPattern"] == "p"
    assert params["EnableRemediation"] == "true" and params["MemberRemediationRoleName"] == "R"
    assert params["RemediationTrustedPrincipalType"] == "IamRole" and params["RemediationTrustedPrincipalArn"].endswith("/ops/Remediate")
    assert "EnableRemediation" not in ident.stack_parameters(scanner, target_account="1" * 12, external_id="e" * 16, role_name="S")


def test_a_missing_profile_is_diagnosed_rather_than_crashing_the_diagnostic(monkeypatch, tmp_path):
    """boto3.Session() raises ProfileNotFound when AWS_PROFILE names a profile
    that is not there -- which is one of the states this must be able to report."""
    from cremore_aws_provider.aws_identity import local_credential_sources

    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "missing-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "missing-credentials"))
    monkeypatch.setenv("AWS_PROFILE", "ghost")
    found = local_credential_sources("ghost")
    assert found["reason"] == "AWS_CONFIG_NOT_MOUNTED"
    assert found["config_present"] is False and found["profiles"] == []

    # With a configuration present, the same missing profile is a different fix.
    config = tmp_path / "config"
    config.write_text("[profile real]\nregion = us-east-1\n", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    named = local_credential_sources("ghost")
    assert named["reason"] == "PROFILE_NOT_IN_CONFIG" and named["profiles"] == ["real"]
    # And a profile that exists, with no cached sign-in, is a third.
    assert local_credential_sources("real")["reason"] == "NO_CACHED_SIGN_IN"


def test_the_diagnostic_never_reads_credential_contents(tmp_path, monkeypatch):
    from cremore_aws_provider.aws_identity import local_credential_sources

    creds = tmp_path / "credentials"
    creds.write_text("[real]\naws_secret_access_key = super-secret-value\n", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds))
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    found = local_credential_sources()
    assert found["credentials_present"] is True
    assert "super-secret-value" not in str(found)


def test_a_mounted_but_unreadable_aws_directory_is_its_own_diagnosis(tmp_path, monkeypatch):
    """The common Linux first run: ~/.aws is mode 700 and the containers default
    to uid 65532, so every file in it is unreadable. That needs CREMORE_UID, not
    AWS_CONFIG_DIR, and the two look identical if only file existence is checked.
    """
    from cremore_aws_provider.aws_identity import local_credential_sources

    home = tmp_path / ".aws"
    home.mkdir()
    (home / "config").write_text("[profile real]\nregion = us-east-1\n", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(home / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(home / "credentials"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    assert local_credential_sources()["home_readable"] is True

    real = __import__("pathlib").Path.iterdir

    def denied(self):
        if self == home:
            raise PermissionError(13, "Permission denied")
        return real(self)

    monkeypatch.setattr("pathlib.Path.iterdir", denied)
    found = local_credential_sources()
    assert found["home_readable"] is False
    # Never AWS_CONFIG_NOT_MOUNTED: the directory is there, just not readable.
    assert found["reason"] == "AWS_CONFIG_UNREADABLE"


def test_the_permission_set_policy_matches_what_the_member_role_may_do():
    """SSO_PERMISSION_SET assumes nothing, so the permission set *is* the access.
    It must therefore carry the same read-only work the member role template
    grants -- minus the one mutating action, which only remediation may hold."""
    import re
    from pathlib import Path

    from cremore_aws_provider.aws_identity import SCANNER_ACTIONS, hub_policy, permission_set_policy

    template = Path(__file__).resolve().parents[3] / "deploy/cloudformation/member-account-role.yaml"
    granted = set(re.findall(r"^\s*- ([a-z0-9]+:[A-Za-z]+)\s*$", template.read_text(encoding="utf-8"), re.MULTILINE))
    actions = set(SCANNER_ACTIONS)

    # Nothing CreMore asks a permission set for is outside what the reviewed
    # member role template already grants.
    assert actions - granted == set(), sorted(actions - granted)
    # The mutating action belongs to the remediation role alone.
    assert "iam:UpdateAccessKey" in granted and "iam:UpdateAccessKey" not in actions
    assert not [a for a in actions if re.search(r":(Put|Update|Delete|Create|Write)", a)]

    policy = permission_set_policy()
    assert policy["Statement"][0]["Action"] == list(SCANNER_ACTIONS)
    # The hub policy is the wrong answer here: assuming a role buys this mode nothing.
    assert "sts:AssumeRole" not in actions
    assert hub_policy("aws", "R")["Statement"][0]["Action"] == "sts:AssumeRole"
