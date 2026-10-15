"""Rotation tests with fake IAM / Secrets Manager / STS. No AWS, no sleeping."""

from __future__ import annotations

import json

import pytest

from cremore_aws_provider.remediation.rotation import (
    RotationError,
    RotationOutcome,
    RotationPlan,
    RotationService,
    STSIdentity,
    STSValidator,
)

USER = "app-service-user"
ACCOUNT = "123456789012"
OLD_KEY = "AKIAOLDKEY" "0000000ABC"
NEW_KEY = "AKIANEWKEY" "0000000XYZ"
IDENTITY = STSIdentity(account=ACCOUNT, arn=f"arn:aws:iam::{ACCOUNT}:user/{USER}", user_id="AIDANEW")


class FakeIAM:
    def __init__(self, existing: int = 1):
        self.keys = [{"AccessKeyId": OLD_KEY, "Status": "Active"} for _ in range(existing)]

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": list(self.keys)}

    def create_access_key(self, UserName):
        self.keys.append({"AccessKeyId": NEW_KEY, "Status": "Active"})
        return {"AccessKey": {"AccessKeyId": NEW_KEY, "SecretAccessKey": "n" * 40, "Status": "Active"}}


class FakeSecrets:
    def __init__(self):
        self.versions = {"v0": json.dumps({"AWS_ACCESS_KEY_ID": OLD_KEY, "AWS_SECRET_ACCESS_KEY": "o" * 40})}
        self.current = "v0"
        self.pending: str | None = None
        self._n = 0

    def get_secret_value(self, SecretId, VersionStage="AWSCURRENT"):
        vid = self.current if VersionStage == "AWSCURRENT" else self.pending
        if vid is None:
            raise RuntimeError("ResourceNotFound")
        return {"VersionId": vid, "SecretString": self.versions[vid]}

    def put_secret_value(self, SecretId, SecretString, VersionStages):
        self._n += 1
        vid = f"v{self._n}"
        self.versions[vid] = SecretString
        if "AWSPENDING" in VersionStages:
            self.pending = vid
        return {"VersionId": vid}

    def update_secret_version_stage(self, SecretId, VersionStage, MoveToVersionId, RemoveFromVersionId=""):
        self.current = MoveToVersionId
        self.pending = None


class FakeSTS(STSValidator):
    def __init__(self, identity=IDENTITY, fail_times=0, code="InvalidClientTokenId"):
        self.identity, self.fail_times, self.code, self.calls = identity, fail_times, code, 0

    def validate(self, access_key_id, secret_access_key):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RotationError(self.code)
        return self.identity


def _plan(**kw) -> RotationPlan:
    base = {"user_name": USER, "account_id": ACCOUNT, "secret_arn": "arn:aws:secretsmanager:...:secret",
                "expected_current_version": "v0", "old_key_id": OLD_KEY,
                "requested_by": "user-1", "approved_by": "user-2"}
    base.update(kw)
    return RotationPlan(**base)


def _allow(plan, phase):
    return None


def _service(iam=None, secrets=None, sts=None, guard=_allow) -> RotationService:
    return RotationService(iam or FakeIAM(), secrets or FakeSecrets(), sts or FakeSTS(),
                           guard=guard, validation_backoff=0)


def test_prepare_then_publish_happy_path():
    iam, secrets, sts = FakeIAM(), FakeSecrets(), FakeSTS()
    svc = RotationService(iam, secrets, sts, guard=_allow, validation_backoff=0)
    plan = _plan()

    assert svc.prepare(plan) == RotationOutcome.PREPARED
    assert plan.new_key_id == NEW_KEY
    assert plan.stages == ["CREATED", "STAGED", "VALIDATED", "READBACK"]
    # Old key still Active; secret current unchanged until publish.
    assert json.loads(secrets.get_secret_value("arn", "AWSCURRENT")["SecretString"])["AWS_ACCESS_KEY_ID"] == OLD_KEY

    assert svc.publish(plan) == RotationOutcome.PUBLISHED
    current = json.loads(secrets.get_secret_value("arn", "AWSCURRENT")["SecretString"])
    assert current["AWS_ACCESS_KEY_ID"] == NEW_KEY


def test_two_party_required():
    with pytest.raises(RotationError) as e:
        _service().prepare(_plan(approved_by="user-1"))  # same as requester
    assert e.value.code == "ROTATION_TWO_PARTY_REQUIRED"


def test_no_key_slot_when_two_keys_exist():
    with pytest.raises(RotationError) as e:
        _service(iam=FakeIAM(existing=2)).prepare(_plan())
    assert e.value.code == "ROTATION_NO_KEY_SLOT"


def test_secret_drift_rejected():
    with pytest.raises(RotationError) as e:
        _service().prepare(_plan(expected_current_version="stale"))
    assert e.value.code == "ROTATION_SECRET_DRIFT"


def test_validate_retries_only_propagation_errors():
    sts = FakeSTS(fail_times=2, code="InvalidClientTokenId")  # propagates, then succeeds
    assert _service(sts=sts).prepare(_plan()) == RotationOutcome.PREPARED
    assert sts.calls == 3


def test_validate_terminal_error_not_retried():
    sts = FakeSTS(fail_times=1, code="ServiceFailure")  # ambiguous -> terminal
    with pytest.raises(RotationError) as e:
        _service(sts=sts).prepare(_plan())
    assert e.value.code == "ROTATION_SUCCESSOR_VALIDATION_FAILED"
    assert sts.calls == 1  # no unsafe retry


def test_publish_requires_prepared():
    with pytest.raises(RotationError) as e:
        _service().publish(_plan())  # nothing prepared
    assert e.value.code == "ROTATION_NOTHING_PREPARED"


class _Session:
    def __init__(self, via="RUNTIME_IDENTITY", account_id=ACCOUNT, pin="1:1"):
        self.via, self.account_id, self.pin = via, account_id, pin


class _RecordingIAM(FakeIAM):
    def __init__(self):
        super().__init__()
        self.calls = []

    def list_access_keys(self, UserName):
        self.calls.append("list_access_keys")
        return super().list_access_keys(UserName)

    def create_access_key(self, UserName):
        self.calls.append("create_access_key")
        return super().create_access_key(UserName)


SECRET = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:app/key-AbCdEf"


def test_member_account_rotation_is_refused_before_any_aws_call():
    from cremore_aws_provider.remediation.rotation import session_guard

    for session, secret in ((_Session(via="ROLE"), SECRET),
                            (_Session(account_id="210987654321"), SECRET),
                            (_Session(), SECRET.replace(ACCOUNT, "210987654321"))):
        iam, secrets = _RecordingIAM(), FakeSecrets()
        with pytest.raises(RotationError) as exc:
            _service(iam, secrets, guard=session_guard(session)).prepare(_plan(secret_arn=secret))
        assert exc.value.code == "ROTATION_ACCOUNT_NOT_SUPPORTED"
        assert iam.calls == [] and secrets.pending is None and secrets._n == 0


def test_publish_requires_the_authorization_prepare_ran_under():
    from cremore_aws_provider.remediation.rotation import session_guard

    secrets = FakeSecrets()
    plan = _plan(secret_arn=SECRET)
    _service(secrets=secrets, guard=session_guard(_Session(pin="1:1"))).prepare(plan)
    assert plan.access_pin == "1:1" and secrets.pending

    # a new remediation approval (or account change) between the phases stops publish before the promotion
    with pytest.raises(RotationError) as exc:
        _service(secrets=secrets, guard=session_guard(_Session(pin="1:2"))).publish(plan)
    assert exc.value.code == "ROTATION_ACCESS_CHANGED" and secrets.current == "v0"
    # a plan prepared before pins existed is never published
    legacy = _plan(secret_arn=SECRET, new_key_id=NEW_KEY, pending_version=secrets.pending)
    with pytest.raises(RotationError):
        _service(secrets=secrets, guard=session_guard(_Session(pin="1:1"))).publish(legacy)
    assert _service(secrets=secrets, guard=session_guard(_Session(pin="1:1"))).publish(plan) == RotationOutcome.PUBLISHED


def test_publish_rechecks_current_version_and_old_key_before_promoting():
    for drift in ("version", "key"):
        secrets, plan = FakeSecrets(), _plan()
        svc = _service(secrets=secrets)
        svc.prepare(plan)
        if drift == "version":
            secrets.versions["other"] = secrets.versions["v0"]
            secrets.current = "other"
        else:
            secrets.versions["v0"] = json.dumps({"AWS_ACCESS_KEY_ID": "different-key"})
        before = secrets.current
        with pytest.raises(RotationError):
            svc.publish(plan)
        assert secrets.current == before and "PUBLISHED" not in plan.stages


@pytest.mark.parametrize("field", ["VersionId", "SecretString"])
def test_prepare_does_not_claim_readback_of_another_pending_value(field):
    class WrongPending(FakeSecrets):
        def get_secret_value(self, SecretId, VersionStage="AWSCURRENT"):
            value = super().get_secret_value(SecretId, VersionStage)
            if VersionStage == "AWSPENDING":
                value[field] = "different-value"
            return value

    plan = _plan()
    with pytest.raises(RotationError, match="ROTATION_PENDING_READBACK_MISMATCH"):
        _service(secrets=WrongPending()).prepare(plan)
    assert "READBACK" not in plan.stages


def test_successor_iam_identity_accepts_a_user_path_and_rejects_a_foreign_arn():
    valid = STSIdentity(account=ACCOUNT, arn=f"arn:aws:iam::{ACCOUNT}:user/services/{USER}", user_id="AIDANEW")
    assert _service(sts=FakeSTS(valid)).prepare(_plan()) == RotationOutcome.PREPARED
    for arn in (f"arn:aws:iam::210987654321:user/{USER}", f"arn:aws:sts::{ACCOUNT}:assumed-role/{USER}"):
        with pytest.raises(RotationError, match="ROTATION_SUCCESSOR_IDENTITY_MISMATCH"):
            _service(sts=FakeSTS(STSIdentity(account=ACCOUNT, arn=arn, user_id="AIDANEW"))).prepare(_plan())


def test_a_successor_sts_keeps_rejecting_is_named_for_the_successor_not_the_sign_in():
    from cremore_aws_provider.aws_identity import collection_error_code

    sts = FakeSTS(fail_times=99, code="InvalidClientTokenId")
    plan = _plan()
    with pytest.raises(RotationError) as e:
        _service(sts=sts).prepare(plan)
    assert e.value.code == "ROTATION_SUCCESSOR_VALIDATION_FAILED" and sts.calls == 8
    assert collection_error_code(e.value) == "ROTATION_SUCCESSOR_VALIDATION_FAILED"
    assert plan.stages == ["CREATED", "STAGED"]


@pytest.mark.parametrize("code", ["ExpiredToken", "RequestExpired"])
def test_a_terminal_login_listed_sts_code_is_not_carried_as_the_sign_in(code):
    from cremore_aws_provider.aws_identity import collection_error_code

    sts = FakeSTS(fail_times=1, code=code)
    with pytest.raises(RotationError) as e:
        _service(sts=sts).prepare(_plan())
    assert sts.calls == 1 and e.value.__context__ is None
    assert collection_error_code(e.value) == "ROTATION_SUCCESSOR_VALIDATION_FAILED"


def test_the_staged_successor_keeps_the_secrets_other_fields():
    secrets = FakeSecrets()
    secrets.versions["v0"] = json.dumps({"AWS_ACCESS_KEY_ID": OLD_KEY, "AWS_SECRET_ACCESS_KEY": "o" * 40,
                                         "region": "eu-west-1", "endpoint": "https://example.invalid"})
    _service(secrets=secrets).prepare(_plan())
    assert json.loads(secrets.versions[secrets.pending]) == {
        "AWS_ACCESS_KEY_ID": NEW_KEY, "AWS_SECRET_ACCESS_KEY": "n" * 40,
        "region": "eu-west-1", "endpoint": "https://example.invalid"}


def test_a_promotion_whose_readback_fails_is_started_never_confirmed():
    class WrongCurrent(FakeSecrets):
        def update_secret_version_stage(self, **kwargs):
            super().update_secret_version_stage(**kwargs)
            self.current = "v0"  # AWS answered, but AWSCURRENT is not the successor

    secrets, plan = WrongCurrent(), _plan()
    svc = _service(secrets=secrets)
    svc.prepare(plan)
    with pytest.raises(RotationError, match="ROTATION_PUBLISH_READBACK_MISMATCH"):
        svc.publish(plan)
    assert plan.stages[-1] == "PROMOTED" and "PUBLISHED" not in plan.stages
    assert len(plan.stage_times) == len(plan.stages)


def _client_error(status, retries):
    from botocore.exceptions import ClientError

    return ClientError({"Error": {"Code": "AccessDenied", "Message": "synthetic"},
                        "ResponseMetadata": {"HTTPStatusCode": status, "RetryAttempts": retries}}, "CreateAccessKey")


@pytest.mark.parametrize("error,written", [
    (_client_error(403, 0), False),  # refused outright: no key exists
    (_client_error(409, 2), True),   # a lost earlier attempt may have created the key
    (_client_error(500, 0), True),
    (TimeoutError("synthetic"), True),
])
def test_only_a_single_refused_create_counts_as_no_write(error, written):
    class Failing(FakeIAM):
        def create_access_key(self, UserName):
            raise error

    plan = _plan()
    with pytest.raises(type(error)):
        _service(iam=Failing()).prepare(plan)
    assert plan.write_started is written and plan.stages == []
