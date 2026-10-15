from cremore_aws_provider.investigation.role_validation import validate_scanner_role

ROLE = "arn:aws:iam::123456789012:role/CredentialExposureScannerRole"


class FakeSTS:
    def __init__(self, *, account="123456789012", fail=None, identity_only=False):
        self.account, self.fail, self.identity_only = account, fail, identity_only
        self.calls: list[dict] = []

    def assume_role(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            raise self.fail
        arn = f"arn:aws:sts::{self.account}:assumed-role/CredentialExposureScannerRole/x"
        out = {"Credentials": {"AccessKeyId": "ASIA000000" "0000000000"}}
        if not self.identity_only:
            out["AssumedRoleUser"] = {"Arn": arn}
        return out

    def get_caller_identity(self):
        return {"Account": self.account}


def test_valid_when_assumed_identity_is_in_the_registered_account():
    sts = FakeSTS()
    result = validate_scanner_role(ROLE, "ext-id-0123456789abcdef", "123456789012", sts)
    assert result.status == "VALID" and result.assumed_arn.startswith("arn:aws:sts::123456789012:")
    # The ExternalId is passed through: it is the confused-deputy guard.
    assert sts.calls[0]["ExternalId"] == "ext-id-0123456789abcdef"


def test_invalid_when_role_lives_in_another_account():
    result = validate_scanner_role(ROLE, "ext", "123456789012", FakeSTS(account="999999999999"))
    assert result.status == "INVALID" and "999999999999" in result.detail


def test_assume_failure_is_reported_not_raised():
    result = validate_scanner_role(ROLE, "ext", "123456789012", FakeSTS(fail=PermissionError("denied")))
    assert result.status == "INVALID" and "PermissionError" in result.detail


def test_never_uses_the_calling_identity_when_assumed_user_is_missing():
    # get_caller_identity() on this client would name the hub, which may even equal the target account
    result = validate_scanner_role(
        ROLE, "ext-id-0123456789abcdef", "123456789012", FakeSTS(identity_only=True)
    )
    assert result.status == "INVALID" and result.code == "CALLER_IDENTITY_FAILED"


def test_runtime_identity_accounts_are_confirmed_by_caller_identity_only():
    from cremore.domain.models import AwsAccount
    from cremore_aws_provider.investigation.role_validation import validate_account_access

    sts = FakeSTS(account="111111111111")
    own = AwsAccount(account_id="111111111111", name="self", access="RUNTIME_IDENTITY")
    result = validate_account_access(own, sts)
    assert (result.status, result.code) == ("VALID", "RUNTIME_ACCOUNT_CONFIRMED") and sts.calls == []
    other = AwsAccount(account_id="123456789012", name="x", access="RUNTIME_IDENTITY")
    assert validate_account_access(other, sts).code == "ACCOUNT_MISMATCH"


def test_missing_role_arn_is_invalid():
    assert validate_scanner_role("", "ext", "123456789012", FakeSTS()).status == "INVALID"


def test_missing_external_id_is_invalid_without_calling_sts():
    sts = FakeSTS()
    result = validate_scanner_role(ROLE, "", "123456789012", sts)
    assert result.status == "INVALID" and "ExternalId" in result.detail and sts.calls == []


def test_remediation_purpose_uses_the_remediation_role_and_its_own_code():
    from cremore.domain.models import AwsAccount
    from cremore_aws_provider.investigation.role_validation import validate_account_access

    sts = FakeSTS()
    account = AwsAccount(account_id="123456789012", name="prod", scanner_role_arn=ROLE, external_id="ext-id-0123456789abcdef",
                         remediation_role_arn=ROLE.replace("Scanner", "Remediation"))
    result = validate_account_access(account, sts, purpose="remediation")
    assert result.code == "REMEDIATION_ROLE_ASSUMED" and sts.calls[0]["RoleArn"].endswith("CredentialExposureRemediationRole")
    assert validate_account_access(account, FakeSTS()).code == "SCANNER_ROLE_ASSUMED"


# --- SSO_PERMISSION_SET validation -------------------------------------------

SUFFIX = "0123456789abcdef"


class FakeSsoVendor:
    def __init__(self, *, error=None):
        self.error, self.calls = error, []

    def get_role_credentials(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return {"roleCredentials": {"accessKeyId": "ASIA" + "0" * 16, "secretAccessKey": "s",
                                    "sessionToken": "t", "expiration": 4102444800000}}


class FakeVendedSTS:
    def __init__(self, arn, account=None, fail=None):
        self.arn, self.account, self.fail = arn, account, fail

    def get_caller_identity(self):
        if self.fail is not None:
            raise self.fail
        out = {"Arn": self.arn}
        if self.account is not None:
            out["Account"] = self.account
        return out


class SSOTokenLoadError(Exception):
    """Recognised by cremore_aws_provider.aws_identity as "sign in again", not "access denied"."""


def _sso_account(account_id="123456789012", permission_set="CreMoreScanner"):
    from cremore.domain.models import AwsAccount

    return AwsAccount(account_id=account_id, name="prod", access="SSO_PERMISSION_SET",
                      sso_role_name=permission_set, source="SSO")


def _vended_arn(account="123456789012", permission_set="CreMoreScanner", suffix=SUFFIX, user="security-officer"):
    return f"arn:aws:sts::{account}:assumed-role/AWSReservedSSO_{permission_set}_{suffix}/{user}"


def test_sso_access_is_valid_only_when_the_account_and_the_permission_set_both_match():
    from cremore_aws_provider.investigation.role_validation import validate_sso_access

    sso = FakeSsoVendor()
    result = validate_sso_access(_sso_account(), sso, "tok",
                                 lambda creds: FakeVendedSTS(_vended_arn(), account="123456789012"))
    assert result.status == "VALID" and result.code == "SSO_ROLE_ASSUMED"
    assert sso.calls == [{"accessToken": "tok", "accountId": "123456789012", "roleName": "CreMoreScanner"}]


def test_credentials_vended_for_another_account_are_refused():
    from cremore_aws_provider.investigation.role_validation import validate_sso_access

    result = validate_sso_access(_sso_account(), FakeSsoVendor(), "tok",
                                 lambda creds: FakeVendedSTS(_vended_arn(account="999999999999"),
                                                             account="999999999999"))
    assert result.status == "INVALID" and result.code == "ACCOUNT_MISMATCH"


def test_a_different_permission_set_under_the_same_record_is_caught():
    """An assignment can be swapped; the recorded name alone would not notice."""
    from cremore_aws_provider.investigation.role_validation import validate_sso_access

    for arn in (_vended_arn(permission_set="AdministratorAccess"),
                "arn:aws:sts::123456789012:assumed-role/SomeOtherRole/x",
                _vended_arn(suffix="not-sixteen-hex"),
                ""):
        result = validate_sso_access(_sso_account(), FakeSsoVendor(), "tok",
                                     lambda creds, a=arn: FakeVendedSTS(a, account="123456789012"))
        assert result.status == "INVALID", arn
        assert result.code in ("PERMISSION_SET_MISMATCH", "ACCOUNT_MISMATCH"), arn


def test_a_permission_set_name_containing_underscores_still_matches():
    from cremore_aws_provider.investigation.role_validation import validate_sso_access

    account = _sso_account(permission_set="CreMore_Scanner_v2")
    arn = _vended_arn(permission_set="CreMore_Scanner_v2")
    result = validate_sso_access(account, FakeSsoVendor(), "tok",
                                 lambda creds: FakeVendedSTS(arn, account="123456789012"))
    assert result.status == "VALID" and result.code == "SSO_ROLE_ASSUMED"


def test_a_withdrawn_assignment_and_an_expired_sign_in_report_differently():
    from cremore_aws_provider.investigation.role_validation import validate_sso_access

    gone = validate_sso_access(_sso_account(), FakeSsoVendor(error=RuntimeError("ForbiddenException")), "tok",
                               lambda creds: FakeVendedSTS(_vended_arn()))
    assert gone.status == "INVALID" and gone.code == "SSO_ROLE_NOT_ASSIGNED"

    expired = validate_sso_access(_sso_account(), FakeSsoVendor(error=SSOTokenLoadError("cache gone")), "tok",
                                  lambda creds: FakeVendedSTS(_vended_arn()))
    # The worker turns this into a hold instead of recording it against the account.
    assert expired.status == "INVALID" and expired.code == "AWS_LOGIN_REQUIRED"


def test_an_account_with_no_recorded_permission_set_never_calls_aws():
    from cremore_aws_provider.investigation.role_validation import validate_sso_access

    sso = FakeSsoVendor()
    result = validate_sso_access(_sso_account(permission_set=None), sso, "tok",
                                 lambda creds: FakeVendedSTS(_vended_arn()))
    assert result.status == "INVALID" and result.code == "NO_PERMISSION_SET_RECORDED"
    assert sso.calls == []


def test_the_account_falls_back_to_the_arn_when_get_caller_identity_omits_it():
    from cremore_aws_provider.investigation.role_validation import validate_sso_access

    result = validate_sso_access(_sso_account(), FakeSsoVendor(), "tok",
                                 lambda creds: FakeVendedSTS(_vended_arn()))
    assert result.status == "VALID" and result.code == "SSO_ROLE_ASSUMED"


def test_access_mode_routing_keeps_sso_out_of_key_actions_and_out_of_probeless_processes():
    from cremore_aws_provider.investigation.role_validation import (
        RoleValidation,
        validate_account_access,
    )

    account = _sso_account()
    sentinel = RoleValidation("VALID", "probed", code="SSO_ROLE_ASSUMED")
    assert validate_account_access(account, FakeSTS(), sso_probe=lambda a: sentinel) is sentinel
    # Key actions must not run through an operator's permission set.
    denied = validate_account_access(account, FakeSTS(), purpose="remediation", sso_probe=lambda a: sentinel)
    assert denied.status == "INVALID" and denied.code == "ACCESS_NOT_CONFIGURED"
    # A process with no Identity Center client says so, rather than blaming the account.
    missing = validate_account_access(account, FakeSTS())
    assert missing.status == "INVALID" and missing.code == "WORKER_AWS_NOT_CONFIGURED"
