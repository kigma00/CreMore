import datetime as dt

import pytest

from cremore.db.repository import InMemoryRepository
from cremore.domain.models import AwsAccount
from cremore_aws_provider import aws_access
from cremore_aws_provider.aws_readonly import ReadOnlyViolation
from cremore_aws_provider.aws_sessions import AccountSessions, account_of_arn

NOW = dt.datetime(2026, 9, 15, tzinfo=dt.UTC)
KEY = "identity-center:aws:111111111111:SecurityAudit"
SCANNER_ROLE = "arn:aws:iam::123456789012:role/CredentialExposureScannerRole"
REMEDIATION_ROLE = "arn:aws:iam::123456789012:role/CredentialExposureRemediationRole"


class FakeSTS:
    def __init__(self, world):
        self.world = world

    def assume_role(self, **kwargs):
        self.world["assumed"].append(kwargs)
        if self.world.get("deny"):
            raise PermissionError("AccessDenied")
        account = self.world.get("role_account", "123456789012")
        return {"AssumedRoleUser": {"Arn": f"arn:aws:sts::{account}:assumed-role/r/cremore"},
                "Credentials": {"AccessKeyId": "ASIA" + "0" * 16, "SecretAccessKey": "s", "SessionToken": "t",
                                "Expiration": NOW + dt.timedelta(hours=1)}}


class FakeIAM:
    def __init__(self, world, creds):
        self.world, self.creds = world, creds

    def list_access_keys(self, **kwargs):
        self.world["calls"].append(("list_access_keys", self.creds))
        return {"AccessKeyMetadata": []}

    def update_access_key(self, **kwargs):
        self.world["calls"].append(("update_access_key", self.creds))


def setup(identity=None, **account_fields):
    repo = InMemoryRepository()
    world = {"assumed": [], "calls": [], "identity": identity or {"state": "READY", "match_key": KEY, "account_id": "111111111111"},
             "probes": []}
    fields = {"account_id": "123456789012", "name": "prod", "scanner_role_arn": SCANNER_ROLE,
              "remediation_role_arn": REMEDIATION_ROLE, "external_id": "external-id-0123456789"}
    fields.update(account_fields)
    account = repo.create_aws_account(AwsAccount(**fields))
    for purpose in aws_access.PURPOSES:
        # A saved approval carries the identity's partition (aws_identity.describe, aws_access.save_approval).
        repo.put_setting(aws_access.APPROVAL_KEYS[purpose], {"match_key": KEY, "partition": "aws", "revision": 1}, "admin")
        aws_access.record_validation(repo, account, purpose, access_revision=account.access_revision, approval_revision=1,
                                     current_approval_revision=1, status="VALID", detail="OK")

    def factory(purpose, service, region, creds):
        return FakeSTS(world) if service == "sts" else FakeIAM(world, creds)

    def identity(purpose, fresh):
        world["probes"].append((purpose, fresh))
        return world["identity"]

    sessions = AccountSessions(repo, None, client_factory=factory, identity=identity, now=lambda: NOW)
    return sessions, repo, world, repo.get_aws_account(account.id)


def blocked(sessions, account_id, purpose):
    with pytest.raises(aws_access.AccessBlocked) as exc:
        sessions.open(account_id, purpose)
    return exc.value.code


def test_role_session_is_in_the_account_and_scanner_clients_are_read_only():
    sessions, _repo, world, _acct = setup()
    session = sessions.open("123456789012", aws_access.SCANNER)
    assert session.evidence() == {"collected_account_id": "123456789012", "collected_via": "ROLE"}
    assert world["assumed"][0]["RoleArn"] == SCANNER_ROLE and world["assumed"][0]["ExternalId"] == "external-id-0123456789"
    iam = session.client("iam")
    iam.list_access_keys(UserName="u")
    with pytest.raises(ReadOnlyViolation):
        iam.update_access_key(UserName="u", AccessKeyId="AKIA", Status="Inactive")
    assert world["calls"] == [("list_access_keys", session.credentials)]


def test_unknown_or_unconnected_owner_is_refused_before_any_aws_call():
    sessions, _repo, world, _acct = setup()
    assert blocked(sessions, None, aws_access.SCANNER) == "ACCOUNT_OWNER_UNKNOWN"
    assert blocked(sessions, "999999999999", aws_access.SCANNER) == "ACCOUNT_NOT_CONNECTED"
    assert world["assumed"] == [] and world["probes"] == []


def test_a_role_in_another_account_is_never_used():
    sessions, _repo, world, _acct = setup()
    world["role_account"] = "999999999999"
    assert blocked(sessions, "123456789012", aws_access.REMEDIATION) == "ACCOUNT_MISMATCH"


def test_scanner_credentials_are_cached_but_every_check_runs_again():
    sessions, repo, world, acct = setup()
    first = sessions.open("123456789012", aws_access.SCANNER)
    assert sessions.open("123456789012", aws_access.SCANNER).credentials is first.credentials
    assert len(world["assumed"]) == 1 and len(world["probes"]) == 2

    repo.update_aws_account(acct.id, enabled=False)
    assert blocked(sessions, "123456789012", aws_access.SCANNER) == "ACCOUNT_DISABLED"
    repo.update_aws_account(acct.id, enabled=True)
    world["identity"] = {"state": "READY", "match_key": "identity-center:aws:111111111111:Other"}
    assert blocked(sessions, "123456789012", aws_access.SCANNER) == "AWS_IDENTITY_CHANGED"
    world["identity"] = {"state": "LOGIN_REQUIRED"}
    assert blocked(sessions, "123456789012", aws_access.SCANNER) == "AWS_LOGIN_REQUIRED"
    # a new ExternalId bumps the revision: the cached credentials no longer match and validation is stale
    world["identity"] = {"state": "READY", "match_key": KEY}
    repo.update_aws_account(acct.id, **aws_access.access_changes(acct, {"external_id": "external-id-rotated-000"}))
    assert blocked(sessions, "123456789012", aws_access.SCANNER) == "REVALIDATION_REQUIRED"


def test_remediation_sessions_are_never_cached_and_probe_identity_fresh():
    sessions, _repo, world, _acct = setup()
    sessions.open("123456789012", aws_access.REMEDIATION)
    sessions.open("123456789012", aws_access.REMEDIATION)
    assert len(world["assumed"]) == 2 and world["probes"] == [("remediation", True), ("remediation", True)]
    assert world["assumed"][0]["RoleArn"] == REMEDIATION_ROLE


def test_a_scanner_result_does_not_open_a_remediation_session():
    sessions, repo, _world, _acct = setup()
    repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.REMEDIATION], {"match_key": KEY, "revision": 2}, "admin")
    assert blocked(sessions, "123456789012", aws_access.REMEDIATION) == "REVALIDATION_REQUIRED"
    assert sessions.open("123456789012", aws_access.SCANNER).account_id == "123456789012"


def test_runtime_identity_account_uses_the_identity_only_in_its_own_account():
    sessions, _repo, world, _acct = setup(account_id="111111111111", access="RUNTIME_IDENTITY",
                                          scanner_role_arn=None, remediation_role_arn=None, external_id=None)
    session = sessions.open("111111111111", aws_access.SCANNER)
    assert session.via == "RUNTIME_IDENTITY" and session.credentials is None and world["assumed"] == []
    world["identity"] = {"state": "READY", "match_key": KEY, "account_id": "222222222222"}
    assert blocked(sessions, "111111111111", aws_access.SCANNER) == "ACCOUNT_MISMATCH"


def test_disabled_or_unvalidated_runtime_account_cannot_be_bypassed():
    sessions, repo, _world, acct = setup(account_id="111111111111", access="RUNTIME_IDENTITY",
                                         scanner_role_arn=None, remediation_role_arn=None, external_id=None, enabled=False)
    assert blocked(sessions, "111111111111", aws_access.SCANNER) == "ACCOUNT_DISABLED"
    repo.update_aws_account(acct.id, enabled=True, validation_key=None)
    assert blocked(sessions, "111111111111", aws_access.SCANNER) == "ACCOUNT_NOT_VALIDATED"


READER = "arn:aws:iam::123456789012:role/CredentialVaultValueReaderRole"
LEAK = "synthetic-provider-text-never-shown"


def chained(sessions, world):
    """The scanner assume, then the chained one; each call's credentials are told apart."""
    world.update(chain=[], reader_account="123456789012", reader_deny=False)

    class STS:
        def __init__(self, creds):
            self.creds = creds

        def assume_role(self, **kwargs):
            world["assumed"].append(kwargs)
            world["chain"].append(self.creds)
            reader = kwargs["RoleArn"].endswith(":role/CredentialVaultValueReaderRole")
            if reader and world["reader_deny"]:
                raise PermissionError("AccessDenied " + LEAK)
            account = world["reader_account"] if reader else "123456789012"
            return {"AssumedRoleUser": {"Arn": f"arn:aws:sts::{account}:assumed-role/r/cremore"},
                    "Credentials": {"AccessKeyId": f"ASIA{len(world['assumed']):016d}", "SecretAccessKey": LEAK,
                                    "SessionToken": LEAK, "Expiration": NOW + dt.timedelta(hours=1)}}

    sessions.client_factory = lambda purpose, service, region, creds: STS(creds) if service == "sts" else FakeIAM(world, creds)


def test_value_reader_chains_from_the_scanner_session_with_the_accounts_external_id():
    from cremore_aws_provider.aws_readonly import READ_OPERATIONS
    from cremore_aws_provider.aws_sessions import VALUE_READER_ROLE

    sessions, _repo, world, _acct = setup()
    chained(sessions, world)
    reader = sessions.value_reader("123456789012", "CredentialVaultValueReaderRole", "connection-1")
    scanner_call, reader_call = world["assumed"]
    assert scanner_call["RoleArn"] == SCANNER_ROLE and world["chain"][0] is None  # the server's own identity
    assert reader_call == {"RoleArn": READER, "RoleSessionName": "cremore-vault-connection-1", "DurationSeconds": 900,
                           "ExternalId": "external-id-0123456789"}
    # The chained call ran with the scanner session's credentials, never the server's.
    assert world["chain"][1]["AccessKeyId"] == f"ASIA{1:016d}"
    assert reader.via == VALUE_READER_ROLE and reader.purpose == aws_access.SCANNER
    assert reader.credentials["AccessKeyId"] == f"ASIA{2:016d}"
    assert reader.pin == sessions.open("123456789012", aws_access.SCANNER).pin
    # Value-read clients only, whatever a caller asks for.
    assert reader.client("secretsmanager", "us-east-1", operations=READ_OPERATIONS)._allowed >= {"get_secret_value"}
    with pytest.raises(ReadOnlyViolation):
        reader.client("secretsmanager", "us-east-1").put_secret_value(SecretId="x")
    with pytest.raises(ValueError):
        reader.client("iam")
    # Never cached: the scanner credentials are, the reader's are asked again.
    sessions.value_reader("123456789012", "CredentialVaultValueReaderRole", "connection-1")
    assert [call["RoleArn"] for call in world["assumed"]] == [SCANNER_ROLE, READER, READER]


def test_value_reader_runs_every_scanner_check_first():
    sessions, repo, world, acct = setup()
    chained(sessions, world)
    repo.update_aws_account(acct.id, enabled=False)
    with pytest.raises(aws_access.AccessBlocked) as exc:
        sessions.value_reader("123456789012", "CredentialVaultValueReaderRole", "c")
    assert exc.value.code == "ACCOUNT_DISABLED" and world["assumed"] == []
    repo.update_aws_account(acct.id, enabled=True)
    world["identity"] = {"state": "READY", "match_key": "identity-center:aws:111111111111:Other"}
    with pytest.raises(aws_access.AccessBlocked) as exc:
        sessions.value_reader("123456789012", "CredentialVaultValueReaderRole", "c")
    assert exc.value.code == "AWS_IDENTITY_CHANGED" and world["assumed"] == []
    with pytest.raises(aws_access.AccessBlocked) as exc:
        sessions.value_reader("999999999999", "CredentialVaultValueReaderRole", "c")
    assert exc.value.code == "ACCOUNT_NOT_CONNECTED"


def test_only_member_role_access_reaches_a_value_reader(monkeypatch):
    sessions, _repo, world, _acct = setup(account_id="111111111111", access="RUNTIME_IDENTITY",
                                          scanner_role_arn=None, remediation_role_arn=None, external_id=None)
    with pytest.raises(aws_access.AccessBlocked) as exc:
        sessions.value_reader("111111111111", "CredentialVaultValueReaderRole", "c")
    assert exc.value.code == "VALUE_READER_NEEDS_ROLE_ACCESS" and world["assumed"] == []
    sessions, _repo, world, _clock = sso_setup(monkeypatch)
    with pytest.raises(aws_access.AccessBlocked) as exc:
        sessions.value_reader("123456789012", "CredentialVaultValueReaderRole", "c")
    # Refused before Identity Center vends a credential, so nothing is cached for it either.
    assert exc.value.code == "VALUE_READER_NEEDS_ROLE_ACCESS" and world["assumed"] == [] and world["vended"] == []
    assert sessions._cache == {}


def test_only_a_scanner_member_role_session_chains_and_a_reader_session_makes_value_clients_whatever_its_purpose():
    from cremore_aws_provider.aws_sessions import (
        VALUE_READER_ROLE,
        AccountSession,
        chain_value_reader,
    )

    sessions, _repo, world, _acct = setup()
    chained(sessions, world)
    remediation = AccountSession("123456789012", aws_access.REMEDIATION, aws_access.ROLE, {"AccessKeyId": "x"},
                                 sessions.client_factory)
    with pytest.raises(aws_access.AccessBlocked) as exc:
        chain_value_reader(remediation, READER, "external-id-0123456789", "c", region=None, now=lambda: NOW)
    assert exc.value.code == "VALUE_READER_NEEDS_ROLE_ACCESS" and world["assumed"] == []
    odd = AccountSession("123456789012", aws_access.REMEDIATION, VALUE_READER_ROLE, {"AccessKeyId": "x"}, sessions.client_factory)
    with pytest.raises(ReadOnlyViolation):
        odd.client("secretsmanager", "us-east-1").put_secret_value(SecretId="x")
    with pytest.raises(ValueError):
        odd.client("iam")


def test_a_value_reader_in_another_partition_is_named_in_that_partition():
    gov = "arn:aws-us-gov:iam::123456789012:role/CredentialExposureScannerRole"
    sessions, _repo, world, _acct = setup(scanner_role_arn=gov)
    chained(sessions, world)
    sessions.value_reader("123456789012", "CredentialVaultValueReaderRole", "c")
    assert [call["RoleArn"] for call in world["assumed"]] == [
        gov, "arn:aws-us-gov:iam::123456789012:role/CredentialVaultValueReaderRole"]


@pytest.mark.parametrize("case,code", [("denied", "VALUE_READER_ASSUME_DENIED"), ("account", "ACCOUNT_MISMATCH"),
                                       ("name", "VALUE_READER_ROLE_INVALID")])
def test_a_refused_value_reader_is_a_safe_code_and_no_credential_is_logged(caplog, case, code):
    import logging

    caplog.set_level(logging.DEBUG)
    sessions, _repo, world, _acct = setup()
    chained(sessions, world)
    world["reader_deny"] = case == "denied"
    world["reader_account"] = "999999999999" if case == "account" else "123456789012"
    with pytest.raises(aws_access.AccessBlocked) as exc:
        sessions.value_reader("123456789012", "Reader/../Other" if case == "name" else "CredentialVaultValueReaderRole", "c")
    assert exc.value.code == code and str(exc.value) == code
    assert [call["RoleArn"] for call in world["assumed"]] == [SCANNER_ROLE] + ([] if case == "name" else [READER])
    assert LEAK not in caplog.text and "ASIA" not in caplog.text


def test_account_of_arn():
    assert account_of_arn("arn:aws:iam::123456789012:user/a") == "123456789012"
    assert account_of_arn("arn:aws:secretsmanager:ap-northeast-2:123456789012:secret:x") == "123456789012"
    assert account_of_arn("arn:aws:s3:::bucket") is None and account_of_arn(None) is None


def test_aws_clients_are_built_only_in_reviewed_places():
    """Supplementary guard; the behaviour tests above are the real contract."""
    import re
    from pathlib import Path

    allowed = {
        "aws/backend/cremore_aws_provider/aws_sessions.py": 3,  # the account-session factory (base identity per purpose, assumed roles)
        "cremore/api/aws_support.py": 4,  # identity probe (GetCallerIdentity / GetRole), per purpose profile, the org probe, the on-demand org sweep
        "aws/backend/cremore_aws_provider/aws_identity.py": 2,  # local profile metadata and SDK workload refresh provenance
        "aws/backend/cremore_aws_provider/aws_sso.py": 3,  # cached-token resolver, the Identity Center client, the vended session
        # The dashboard sign-in's SSO OIDC client (RegisterClient, StartDeviceAuthorization, CreateToken): it takes no
        # AWS credentials and reaches no account; it only seeds the SSO cache aws_sso.py reads.
        "aws/backend/cremore_aws_provider/aws_sso_login.py": 1,
        "cremore/cli/worker.py": 5,  # readonly scanner clients, same-session identity/provenance probe, two SQS clients, vended STS
        "cremore/cli/coverage.py": 1,  # customer-side approved vault scope; STS account check, passive hashing only
        "aws/backend/cremore_aws_provider/remediation/aws_clients.py": 1,  # STS authenticating as a candidate key, not an identity
        # This installation's own sealing master, not a customer account: it is the
        # workload identity's KMS Decrypt, so it is deliberately not routed through
        # AccountSessions, which exists to prove WHICH connected account was reached.
        "aws/backend/cremore_aws_provider/kms.py": 1,
    }
    import tomllib

    root = Path(__file__).resolve().parents[3]
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    package_paths = config["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    found = {}
    for package in package_paths:
        for path in (root / package).rglob("*.py"):
            if path.name.endswith("_test.py") or path.name.startswith("test_") or path.name == "conftest.py":
                continue
            count = len(re.findall(r"boto3\.(?:client|Session)\(", path.read_text(encoding="utf-8")))
            if count:
                found[path.relative_to(root).as_posix()] = count
    assert found == allowed


@pytest.mark.parametrize("mode", ["RUNTIME_IDENTITY", "ROLE"])
def test_on_prem_web_identity_refreshes_without_metadata_or_personal_login(monkeypatch, tmp_path, mode):
    """Real SDK refresh logic with fake STS; the host has no EC2 metadata or AWS key."""
    import boto3
    import botocore.credentials
    import botocore.session

    from cremore_aws_provider.aws_identity import server_workload_source

    for key in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    token_file = tmp_path / "projected-jwt"
    token_file.write_text("synthetic-jwt-first", encoding="utf-8")
    for key, value in {"AWS_EC2_METADATA_DISABLED": "true", "AWS_ROLE_ARN": SCANNER_ROLE,
        "AWS_WEB_IDENTITY_TOKEN_FILE": str(token_file), "AWS_ROLE_SESSION_NAME": "cremore-server",
        "AWS_CONFIG_FILE": str(tmp_path / "no-config"), "AWS_SHARED_CREDENTIALS_FILE": str(tmp_path / "no-keys")}.items():
        monkeypatch.setenv(key, value)
    clock, tokens, assumed, reads = [dt.datetime.now(dt.UTC)], [], [], []
    monkeypatch.setattr(botocore.credentials, "_local_now", lambda: clock[0])

    def credentials(key, minutes):
        return {"AccessKeyId": key, "SecretAccessKey": "synthetic-secret", "SessionToken": "synthetic-session",
                "Expiration": clock[0] + dt.timedelta(minutes=minutes)}

    class WebSTS:
        def assume_role_with_web_identity(self, **kwargs):
            tokens.append(kwargs["WebIdentityToken"])
            return {"Credentials": credentials("web-" + str(len(tokens)), 30)}

    sdk = botocore.session.get_session()

    def create_client(service, **kwargs):
        assert service == "sts", "the SDK must not call a real endpoint"
        return WebSTS()

    monkeypatch.setattr(sdk, "create_client", create_client)
    session = boto3.Session(botocore_session=sdk)
    assert server_workload_source(session) == "assume-role-with-web-identity"
    base = session.get_credentials()
    # The SDK binds its default clock when the class is defined; inject the
    # same synthetic clock into its credential cache as the STS fetcher above.
    monkeypatch.setattr(base, "_time_fetcher", lambda: clock[0])
    aid = "123456789012"
    sessions, _repo, world, _account = setup(account_id=aid, access=mode)
    world["identity"].update(account_id=aid, kind="IAM_ROLE", credential_source="assume-role-with-web-identity")

    def factory(purpose, service, region, creds):
        class Client:
            def assume_role(self, **kwargs):
                assumed.append(base.get_frozen_credentials().access_key)
                return {"AssumedRoleUser": {"Arn": f"arn:aws:sts::{aid}:assumed-role/scanner/run"},
                        "Credentials": credentials("member-" + str(len(assumed)), 15)}

            def list_access_keys(self, **kwargs):
                reads.append(creds["AccessKeyId"] if creds else base.get_frozen_credentials().access_key)
                return {"AccessKeyMetadata": []}
        return Client()

    sessions.client_factory, sessions.now = factory, lambda: clock[0]
    sessions.open(aid, aws_access.SCANNER).client("iam").list_access_keys(UserName="synthetic")
    token_file.write_text("synthetic-jwt-rotated", encoding="utf-8")
    clock[0] += dt.timedelta(minutes=31)
    sessions.open(aid, aws_access.SCANNER).client("iam").list_access_keys(UserName="synthetic")
    assert tokens == ["synthetic-jwt-first", "synthetic-jwt-rotated"]
    assert reads == (["web-1", "web-2"] if mode == "RUNTIME_IDENTITY" else ["member-1", "member-2"])
    assert assumed == ([] if mode == "RUNTIME_IDENTITY" else ["web-1", "web-2"])


# --- SSO_PERMISSION_SET: Identity Center vends the account's credentials ------

START_URL = "https://d-1234567890.awsapps.com/start"
OTHER_URL = "https://d-1111111111.awsapps.com/start"


class FakeSsoClient:
    def __init__(self, world):
        self.world = world

    def get_role_credentials(self, **kwargs):
        self.world["vended"].append(kwargs)
        if self.world.get("error") is not None:
            raise self.world["error"]
        expires = self.world.get("expires", NOW + dt.timedelta(hours=1))
        return {"roleCredentials": {"accessKeyId": "ASIA" + "0" * 16, "secretAccessKey": "s",
                                    "sessionToken": "t", "expiration": int(expires.timestamp() * 1000)}}


def sso_setup(monkeypatch, *, approved_start_url=START_URL, current_start_url=START_URL, **account_fields):
    """An account reached through an Identity Center assignment, nothing deployed."""
    monkeypatch.setattr("cremore_aws_provider.aws_sso.access_token", lambda profile="": "tok")
    repo = InMemoryRepository()
    clock = {"now": NOW}
    world = {"vended": [], "probes": [], "clients": [], "assumed": [], "calls": [], "error": None,
             "identity": {"state": "READY", "match_key": KEY, "account_id": "111111111111",
                          "sso_region": "ap-northeast-2", "sso_start_url": current_start_url}}
    fields = {"account_id": "123456789012", "name": "prod", "access": aws_access.SSO_PERMISSION_SET,
              "sso_role_name": "CreMoreScanner", "source": "SSO", "org_present": True}
    fields.update(account_fields)
    account = repo.create_aws_account(AwsAccount(**fields))
    approval = {"match_key": KEY, "partition": "aws", "revision": 1, "sso_region": "ap-northeast-2"}
    if approved_start_url:
        approval["sso_start_url"] = approved_start_url
    for purpose in aws_access.PURPOSES:
        repo.put_setting(aws_access.APPROVAL_KEYS[purpose], dict(approval), "admin")
        aws_access.record_validation(repo, account, purpose, access_revision=account.access_revision,
                                     approval_revision=1, current_approval_revision=1, status="VALID", detail="OK")

    def factory(purpose, service, region, creds):
        world["clients"].append((purpose, service, region))
        if service == "sso":
            return FakeSsoClient(world)
        return FakeSTS(world) if service == "sts" else FakeIAM(world, creds)

    def identity(purpose, fresh):
        world["probes"].append((purpose, fresh))
        return world["identity"]

    sessions = AccountSessions(repo, None, client_factory=factory, identity=identity, now=lambda: clock["now"])
    return sessions, repo, world, clock


def test_sso_session_vends_the_permission_set_and_records_how_it_was_collected(monkeypatch):
    sessions, _repo, world, _clock = sso_setup(monkeypatch)
    session = sessions.open("123456789012", aws_access.SCANNER)
    assert session.evidence() == {"collected_account_id": "123456789012", "collected_via": "SSO_PERMISSION_SET"}
    assert world["vended"] == [{"accessToken": "tok", "accountId": "123456789012", "roleName": "CreMoreScanner"}]
    # The Identity Center client is built in the directory's Region, not the scan Region.
    assert ("scanner", "sso", "ap-northeast-2") in world["clients"]
    # Nothing was assumed: no member role exists in this account.
    assert world["assumed"] == []
    # Scanner clients stay read-only whatever minted the credentials.
    iam = session.client("iam")
    iam.list_access_keys(UserName="u")
    with pytest.raises(ReadOnlyViolation):
        iam.update_access_key(UserName="u", AccessKeyId="AKIA", Status="Inactive")


def test_sso_credentials_are_cached_until_they_are_nearly_expired(monkeypatch):
    sessions, _repo, world, clock = sso_setup(monkeypatch)
    world["expires"] = NOW + dt.timedelta(hours=1)
    sessions.open("123456789012", aws_access.SCANNER)
    sessions.open("123456789012", aws_access.SCANNER)
    assert len(world["vended"]) == 1
    # Inside the 5-minute margin the credential is re-minted rather than risked.
    clock["now"] = NOW + dt.timedelta(minutes=56)
    sessions.open("123456789012", aws_access.SCANNER)
    assert len(world["vended"]) == 2


def test_an_unpinned_or_changed_identity_center_instance_blocks_the_account(monkeypatch):
    """The same profile name can be repointed at another directory, which would
    vend a different estate under the same approval. match_key cannot see that."""
    sessions, _repo, world, _clock = sso_setup(monkeypatch, current_start_url=OTHER_URL)
    assert blocked(sessions, "123456789012", aws_access.SCANNER) == "AWS_SSO_SESSION_CHANGED"
    assert world["vended"] == []

    sessions, _repo, world, _clock = sso_setup(monkeypatch, approved_start_url=None)
    assert blocked(sessions, "123456789012", aws_access.SCANNER) == "AWS_SSO_SESSION_UNKNOWN"
    assert world["vended"] == []


def test_an_sso_account_without_a_permission_set_is_refused_before_any_call(monkeypatch):
    sessions, _repo, world, _clock = sso_setup(monkeypatch, sso_role_name=None)
    assert blocked(sessions, "123456789012", aws_access.SCANNER) == "ACCESS_NOT_CONFIGURED"
    assert world["vended"] == []


def test_key_actions_never_run_through_an_operators_permission_set(monkeypatch):
    sessions, _repo, world, _clock = sso_setup(monkeypatch)
    assert blocked(sessions, "123456789012", aws_access.REMEDIATION) == "ACCESS_NOT_CONFIGURED"
    assert world["vended"] == []


def test_a_withdrawn_assignment_and_an_expired_sign_in_are_different_answers(monkeypatch):
    from cremore_aws_provider.aws_identity import AwsLoginRequired

    sessions, _repo, world, _clock = sso_setup(monkeypatch)
    world["error"] = RuntimeError("ForbiddenException")
    assert blocked(sessions, "123456789012", aws_access.SCANNER) == "SSO_ROLE_NOT_ASSIGNED"

    sessions, _repo, world, _clock = sso_setup(monkeypatch)

    class SSOTokenLoadError(Exception):
        pass

    world["error"] = SSOTokenLoadError("cache gone")
    # Not a fact about the account: AWS work waits for the operator to sign in.
    with pytest.raises(AwsLoginRequired):
        sessions.open("123456789012", aws_access.SCANNER)


def test_an_sso_account_is_still_subject_to_every_ordinary_block(monkeypatch):
    sessions, repo, world, _clock = sso_setup(monkeypatch)
    account = repo.list_aws_accounts()[0]
    repo.update_aws_account(account.id, org_present=False)
    assert blocked(sessions, "123456789012", aws_access.SCANNER) == "SSO_ASSIGNMENT_REMOVED"
    repo.update_aws_account(account.id, org_present=True, enabled=False)
    assert blocked(sessions, "123456789012", aws_access.SCANNER) == "ACCOUNT_DISABLED"
    assert world["vended"] == []


def test_an_unwritable_token_cache_blocks_the_session_with_its_own_code(monkeypatch):
    """Reported as SSO_ROLE_NOT_ASSIGNED it would send an operator to the AWS
    console to check an assignment that is perfectly fine."""
    from cremore_aws_provider import aws_sso

    sessions, _repo, world, _clock = sso_setup(monkeypatch)

    def unwritable(profile=""):
        raise aws_sso.SsoCacheNotWritable("[Errno 30] Read-only file system")

    monkeypatch.setattr("cremore_aws_provider.aws_sso.access_token", unwritable)
    assert blocked(sessions, "123456789012", aws_access.SCANNER) == "SSO_CACHE_NOT_WRITABLE"
    assert world["vended"] == []
