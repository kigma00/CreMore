import datetime as dt

import pytest

from cremore_aws_provider import aws_sso
from cremore_aws_provider.aws_identity import AwsLoginRequired

NOW = dt.datetime(2026, 9, 18, 8, 0, tzinfo=dt.UTC)
CLOCK = lambda: NOW


class ExpiredToken(Exception):
    """Named so cremore_aws_provider.aws_identity._LOGIN_ERRORS recognises it by class name."""


class FakeSso:
    """Stands in for boto3 sso, whose shapes differ from STS on purpose.

    ``accounts`` are ListAccounts pages' entries, ``roles`` maps an account id to
    its role names (or an Exception to raise), and ``credentials`` maps
    ``(account, role)`` to the raw camelCase payload or an Exception.
    """

    def __init__(self, accounts=(), roles=None, credentials=None):
        self.accounts = list(accounts)
        self.roles = roles or {}
        self.credentials = credentials or {}
        self.calls = []

    def get_paginator(self, operation):
        return _Paginator(self, operation)

    def get_role_credentials(self, **kwargs):
        self.calls.append(("get_role_credentials", kwargs))
        value = self.credentials.get((kwargs["accountId"], kwargs["roleName"]))
        if isinstance(value, Exception):
            raise value
        if value is None:  # nothing registered for this pair: Identity Center refuses it
            raise RuntimeError("ForbiddenException")
        return {"roleCredentials": value}


class _Paginator:
    def __init__(self, client, operation):
        self.client, self.operation = client, operation

    def paginate(self, **kwargs):
        self.client.calls.append((self.operation, kwargs))
        if self.operation == "list_accounts":
            # Two pages, so a caller that reads only the first is caught.
            half = (len(self.client.accounts) + 1) // 2
            return iter([{"accountList": self.client.accounts[:half]},
                         {"accountList": self.client.accounts[half:]}])
        if self.operation == "list_account_roles":
            value = self.client.roles.get(kwargs["accountId"], [])
            if isinstance(value, Exception):
                raise value
            return iter([{"roleList": [{"roleName": name} for name in value]}])
        raise AssertionError(self.operation)


def _entry(account_id, name):
    return {"accountId": account_id, "accountName": name, "emailAddress": f"{name}@example.test"}


def _creds(expiration):
    return {"accessKeyId": "ASIA" + "0" * 16, "secretAccessKey": "s", "sessionToken": "t",
            "expiration": expiration}


# --- credentials: the shape that differs most from STS -----------------------


def test_expiration_is_read_as_epoch_milliseconds_not_seconds():
    """sso:GetRoleCredentials reports a long; sts:AssumeRole returns a datetime.

    Reading it as seconds would put every credential in 1970 and re-vend on
    every call; passing it through unconverted would raise in the session cache.
    """
    expires = NOW + dt.timedelta(hours=1)
    sso = FakeSso(credentials={("111111111111", "Scan"): _creds(int(expires.timestamp() * 1000))})
    creds = aws_sso.role_credentials(sso, "tok", "111111111111", "Scan", now=CLOCK)
    assert creds["Expiration"] == expires
    # Normalised to the STS key names the session cache and boto3 factory expect.
    assert set(creds) == {"AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}
    assert creds["AccessKeyId"] == "ASIA" + "0" * 16


def test_an_expiry_in_the_wrong_unit_or_the_past_falls_back_instead_of_pinning_a_dead_credential():
    expires = NOW + dt.timedelta(hours=1)
    for value in (int(expires.timestamp()),  # seconds, not milliseconds: reads as 1970
                  int((NOW - dt.timedelta(hours=2)).timestamp() * 1000),  # genuinely past
                  0, -1, None, "soon", True, 10 ** 22):  # absent or unusable
        creds = aws_sso.role_credentials(
            FakeSso(credentials={("111111111111", "Scan"): _creds(value)}), "tok", "111111111111", "Scan", now=CLOCK)
        assert creds["Expiration"] == NOW + dt.timedelta(minutes=15), value
        # Never in the past: that would re-vend on every single call.
        assert creds["Expiration"] > NOW


def test_a_datetime_expiry_is_accepted_and_always_made_aware():
    naive = (NOW + dt.timedelta(hours=1)).replace(tzinfo=None)
    creds = aws_sso.role_credentials(
        FakeSso(credentials={("1" * 12, "Scan"): _creds(naive)}), "tok", "1" * 12, "Scan", now=CLOCK)
    # A naive value would raise when compared against an aware "now" in the cache.
    assert creds["Expiration"] == NOW + dt.timedelta(hours=1)
    assert creds["Expiration"].tzinfo is not None


def test_incomplete_credentials_are_refused_rather_than_used():
    partial = {"accessKeyId": "ASIA", "secretAccessKey": "", "sessionToken": "t", "expiration": 1}
    sso = FakeSso(credentials={("1" * 12, "Scan"): partial})
    with pytest.raises(aws_sso.SsoRoleUnavailable):
        aws_sso.role_credentials(sso, "tok", "1" * 12, "Scan", now=CLOCK)


def test_an_expired_sign_in_is_told_apart_from_a_removed_assignment():
    """One waits for the operator; the other is a fact about the account."""
    login = FakeSso(credentials={("1" * 12, "Scan"): ExpiredToken("UnauthorizedSSOTokenError")})
    with pytest.raises(AwsLoginRequired):
        aws_sso.role_credentials(login, "tok", "1" * 12, "Scan", now=CLOCK)
    gone = FakeSso(credentials={("1" * 12, "Scan"): RuntimeError("ForbiddenException")})
    with pytest.raises(aws_sso.SsoRoleUnavailable):
        aws_sso.role_credentials(gone, "tok", "1" * 12, "Scan", now=CLOCK)


# --- the assignment listing --------------------------------------------------


def test_every_page_is_read_and_each_account_carries_its_sorted_permission_sets():
    sso = FakeSso(accounts=[_entry("1" * 12, "alpha"), _entry("2" * 12, "beta"), _entry("3" * 12, "gamma")],
                  roles={"1" * 12: ["Scan", "AdministratorAccess"], "2" * 12: ["Scan"], "3" * 12: []})
    listed = aws_sso.list_assigned(sso, "tok")
    assert [a["account_id"] for a in listed] == ["1" * 12, "2" * 12, "3" * 12]
    assert listed[0]["roles"] == ["AdministratorAccess", "Scan"]
    assert listed[0]["name"] == "alpha" and listed[0]["email"] == "alpha@example.test"
    assert listed[2]["roles"] == []


def test_a_malformed_account_id_is_dropped_and_a_blank_name_falls_back_to_the_id():
    sso = FakeSso(accounts=[{"accountId": "nope", "accountName": "x"},
                            {"accountId": "4" * 12, "accountName": "   "}],
                  roles={"4" * 12: ["Scan"]})
    listed = aws_sso.list_assigned(sso, "tok")
    assert [a["account_id"] for a in listed] == ["4" * 12]
    assert listed[0]["name"] == "4" * 12 and listed[0]["email"] is None


def test_one_unreadable_role_list_never_shortens_the_account_list():
    """An empty role list must not be mistaken for a removed assignment, so the
    account is still returned; cremore/aws_sso_discovery.py relies on this."""
    sso = FakeSso(accounts=[_entry("1" * 12, "alpha"), _entry("2" * 12, "beta")],
                  roles={"1" * 12: RuntimeError("AccessDeniedException"), "2" * 12: ["Scan"]})
    listed = aws_sso.list_assigned(sso, "tok")
    assert [a["account_id"] for a in listed] == ["1" * 12, "2" * 12]
    assert listed[0]["roles"] == [] and listed[1]["roles"] == ["Scan"]


def test_an_expired_sign_in_during_listing_is_raised_not_swallowed():
    sso = FakeSso(accounts=[_entry("1" * 12, "alpha")],
                  roles={"1" * 12: ExpiredToken("UnauthorizedSSOTokenError")})
    with pytest.raises(AwsLoginRequired):
        aws_sso.list_assigned(sso, "tok")


def test_a_role_name_that_is_not_a_permission_set_name_is_dropped():
    sso = FakeSso(accounts=[_entry("1" * 12, "alpha")],
                  roles={"1" * 12: ["Scan", "way/too/slashed", "x" * 40, ""]})
    assert aws_sso.list_assigned(sso, "tok")[0]["roles"] == ["Scan"]


# --- the Identity Center Region ----------------------------------------------


def test_the_approved_region_wins_over_local_config(monkeypatch):
    """A local config edit must not move CreMore to another directory's Region."""
    monkeypatch.setattr("cremore_aws_provider.aws_identity.local_sso_region", lambda: "us-east-1")
    assert aws_sso.region_for({"sso_region": "ap-northeast-2"}) == "ap-northeast-2"
    assert aws_sso.region_for({}) == "us-east-1"
    assert aws_sso.region_for(None) == "us-east-1"


def test_no_region_anywhere_is_its_own_refusal(monkeypatch):
    monkeypatch.setattr("cremore_aws_provider.aws_identity.local_sso_region", lambda: None)
    with pytest.raises(aws_sso.SsoRegionUnknown):
        aws_sso.region_for(None)
    with pytest.raises(aws_sso.SsoRegionUnknown):
        aws_sso.client("")


def test_permission_set_names_match_what_aws_allows():
    assert aws_sso.PERMISSION_SET.fullmatch("CreMoreScanner")
    assert aws_sso.PERMISSION_SET.fullmatch("a+=,.@_-A9")
    assert not aws_sso.PERMISSION_SET.fullmatch("")
    assert not aws_sso.PERMISSION_SET.fullmatch("x" * 33)  # AWS caps a permission set at 32
    assert not aws_sso.PERMISSION_SET.fullmatch("has space")
    assert not aws_sso.PERMISSION_SET.fullmatch("has/slash")


# --- a token cache that cannot be rewritten ----------------------------------


def test_an_unwritable_token_cache_is_told_apart_from_an_expired_sign_in(monkeypatch):
    """botocore rewrites the cache on every hourly renewal and stores the rotated
    refresh token there, so a read-only mount fails with EROFS. That is neither
    an expired sign-in nor a withdrawn assignment, and reporting it as either
    sends the operator to the AWS console instead of to their mount."""
    import errno as _errno

    import botocore.tokens

    for number in (_errno.EROFS, _errno.EACCES, _errno.EPERM):
        def resolver(_session, code=number):
            raise OSError(code, "Read-only file system")

        monkeypatch.setattr(botocore.tokens, "create_token_resolver", resolver)
        with pytest.raises(aws_sso.SsoCacheNotWritable):
            aws_sso.access_token()

    # An unrelated OSError is not silently relabelled as a cache problem.
    def other(_session):
        raise OSError(_errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(botocore.tokens, "create_token_resolver", other)
    with pytest.raises(OSError) as raised:
        aws_sso.access_token()
    assert not isinstance(raised.value, aws_sso.SsoCacheNotWritable)


def test_an_expired_client_registration_still_reports_as_needing_a_sign_in(monkeypatch):
    """The ~90-day cliff: botocore checks registrationExpiresAt locally, makes no
    AWS call, and returns no token. Only a human can fix that."""
    import botocore.tokens

    class NoToken:
        def load_token(self, **_kwargs):
            return None

    monkeypatch.setattr(botocore.tokens, "create_token_resolver", lambda _s: NoToken())
    with pytest.raises(AwsLoginRequired):
        aws_sso.access_token()
