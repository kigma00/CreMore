"""Owner resolution for an access key id observed without its secret.

Synthetic IAM answers only: nothing here authenticates as a discovered key, and
the key id handed to the fakes is the non-secret half of an AWS credential.
"""

import pytest
from botocore.exceptions import ClientError

from cremore_aws_provider.aws_access import AccessBlocked
from cremore_aws_provider.aws_identity import AwsLoginRequired
from cremore_aws_provider.investigation.usage import resolve_key_owner

ID = "AKIA" + "Z5X9K2MBV7QP3LN6"


def _error(code):
    return ClientError({"Error": {"Code": code, "Message": "provider text must not leak"}}, "GetAccessKeyLastUsed")


class Account:
    """One connected account's IAM/STS, answering only about the keys it holds."""

    def __init__(self, *, keys=(), user_arn="", caller="arn:aws:iam::1:role/scanner", fail=None):
        self.keys, self.user_arn, self.caller, self.fail = dict(keys), user_arn, caller, fail

    def get_access_key_last_used(self, AccessKeyId):
        if self.fail:
            raise _error(self.fail)
        if AccessKeyId not in self.keys:
            raise _error("NoSuchEntity")
        return {"UserName": self.keys[AccessKeyId]} if self.keys[AccessKeyId] else {
            "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"}}

    def get_user(self, UserName):
        if not self.user_arn:
            raise _error("AccessDenied")
        return {"User": {"Arn": self.user_arn}}

    def get_caller_identity(self):
        return {"Arn": self.caller}

    def client(self, service, region=None):
        return self


def _sessions(mapping):
    def open_session(account_id):
        value = mapping[account_id]
        if isinstance(value, Exception):
            raise value
        return value
    return open_session


def test_the_owning_account_is_found_and_others_are_recorded_as_misses():
    accounts = {
        "111111111111": Account(),
        "222222222222": Account(keys={ID: "ci-deployer"}, user_arn="arn:aws:iam::222222222222:user/ops/ci-deployer"),
        "333333333333": Account(keys={ID: "never-reached"}),
    }
    owner, attempts = resolve_key_owner(_sessions(accounts), list(accounts), ID)

    assert owner.account_id == "222222222222" and owner.user_name == "ci-deployer"
    # The path comes from get_user; a synthesized ARN would drop it.
    assert owner.principal_arn == "arn:aws:iam::222222222222:user/ops/ci-deployer"
    # The search stops at the owner and never reports on accounts it did not read.
    assert [row["status"] for row in attempts] == ["NOT_IN_ACCOUNT", "OWNER"]


def test_an_account_that_could_not_be_opened_is_unchecked_not_a_miss():
    owner, attempts = resolve_key_owner(
        _sessions({"111111111111": AccessBlocked("ACCOUNT_NOT_CONNECTED"), "222222222222": Account()}),
        ["111111111111", "222222222222"], ID)

    assert owner is None
    assert attempts[0] == {"account_id": "111111111111", "status": "NOT_CHECKED",
                           "error_code": "ACCOUNT_NOT_CONNECTED"}
    assert attempts[1]["status"] == "NOT_IN_ACCOUNT"


@pytest.mark.parametrize("code,status", [("AccessDenied", "NOT_CHECKED"), ("NoSuchEntity", "NOT_IN_ACCOUNT")])
def test_a_denied_read_is_not_evidence_that_the_key_is_absent(code, status):
    owner, attempts = resolve_key_owner(_sessions({"1": Account(fail=code)}), ["1"], ID)

    assert owner is None and attempts[0]["status"] == status
    assert "provider text" not in str(attempts)


def test_a_root_key_is_owned_even_though_iam_returns_no_user_name():
    account = Account(keys={ID: ""}, caller="arn:aws-us-gov:iam::444444444444:role/scanner")
    owner, _ = resolve_key_owner(_sessions({"444444444444": account}), ["444444444444"], ID)

    # The partition is read from CreMore's own identity, never assumed commercial.
    assert owner.principal_arn == "arn:aws-us-gov:iam::444444444444:root" and owner.user_name == ""


def test_an_empty_provider_answer_does_not_establish_root_ownership():
    class Malformed(Account):
        def get_access_key_last_used(self, **kwargs):
            return {}

    owner, attempts = resolve_key_owner(_sessions({"444444444444": Malformed()}), ["444444444444"], ID)
    assert owner is None and attempts[0]["status"] == "NOT_CHECKED"


def test_an_unreadable_partition_leaves_the_root_owner_unresolved():
    class NoCaller(Account):
        def get_caller_identity(self):
            raise _error("AccessDenied")

    owner, attempts = resolve_key_owner(_sessions({"1": NoCaller(keys={ID: ""})}), ["1"], ID)
    assert owner is None and attempts[0]["error_code"] == "OWNER_PARTITION_NOT_READ"


def test_an_owner_whose_arn_cannot_be_read_still_names_its_account_and_user():
    account = Account(keys={ID: "ci-deployer"})  # get_user denied
    owner, _ = resolve_key_owner(_sessions({"555555555555": account}), ["555555555555"], ID)

    assert owner.account_id == "555555555555" and owner.user_name == "ci-deployer"
    assert owner.principal_arn == ""


def test_a_lost_scanner_session_stops_the_search_instead_of_reporting_absence():
    calls = []

    class Expired(Account):
        def get_access_key_last_used(self, AccessKeyId):
            calls.append(AccessKeyId)
            raise _error("ExpiredToken")

    with pytest.raises(AwsLoginRequired):
        resolve_key_owner(_sessions({"1": Expired(), "2": Account()}), ["1", "2"], ID)
    assert calls == [ID]  # the second account is never reported on
