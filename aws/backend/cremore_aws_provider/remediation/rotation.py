"""Approved AWS IAM access-key rotation (Lambda-free).

Two phases, each separately approved:

* PREPARE  — create a successor key, stage it into the secret's AWSPENDING
             version, prove the successor authenticates (STS GetCallerIdentity),
             and read it back. The old key stays Active.
* PUBLISH  — promote AWSPENDING to AWSCURRENT so consumers pick up the successor.
             Disabling the old key is a separate, later approved step.

Safety invariants enforced here:

* two-party control: the approver must differ from the requester, except in a
  single-operator (shared-token) install where the one operator re-confirmed it;
* the secret must still be at the version the plan bound (no drift);
* a fresh IAM key is eventually consistent, so successor validation retries only
  the known propagation errors and treats anything else as terminal — an
  ambiguous provider error never triggers an unsafe retry.

Clients (IAM, Secrets Manager) and the STS validator are injected, so the whole
flow is exercised with fakes and no AWS access. Written from the AWS API
reference, not from any Lambda rotation template.
"""

from __future__ import annotations

import datetime as _dt
import enum
import json
import time
from dataclasses import dataclass, field

# STS error codes a just-created key returns only while it is still propagating.
# Retrying these is safe; anything else is terminal so an uncertain outcome is
# preserved rather than retried.
_PROPAGATION_CODES = {"InvalidClientTokenId", "AuthFailure", "SignatureDoesNotMatch"}
_MAX_KEYS = 2  # IAM allows at most two access keys per user.


class RotationOutcome(str, enum.Enum):
    PREPARED = "PREPARED"
    PUBLISHED = "PUBLISHED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"
    BLOCKED = "BLOCKED"


class RotationError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class RotationPlan:
    user_name: str
    account_id: str
    secret_arn: str
    expected_current_version: str
    old_key_id: str
    requested_by: str
    approved_by: str = ""
    single_operator: bool = False
    new_key_id: str = ""
    pending_version: str = ""
    stages: list[str] = field(default_factory=list)
    stage_times: list[str] = field(default_factory=list)  # when each stage was reached, in step with ``stages``
    # Access authorization PREPARE ran under; PUBLISH must run under the same one.
    access_pin: str = ""
    write_started: bool = False


@dataclass
class STSIdentity:
    account: str
    arn: str
    user_id: str


class STSValidator:
    """Validates a candidate key by calling STS GetCallerIdentity as it."""

    def validate(self, access_key_id: str, secret_access_key: str) -> STSIdentity:
        """Return the identity, or raise RotationError('<STS code>')."""
        raise NotImplementedError


def session_guard(session):
    """Rotation runs only in the explicit RUNTIME_IDENTITY account, for a secret in that account.

    Member-account rotation is not supported: its remediation role cannot
    create keys or write secrets, so it is refused before the first AWS call.
    PREPARE records the session's authorization pin; PUBLISH requires the same
    pin, so a successor prepared under an earlier identity approval or account
    configuration is never published under a newer one.
    """

    from cremore_aws_provider.aws_sessions import account_of_arn

    def guard(plan: RotationPlan, phase: str) -> None:
        if (session.via != "RUNTIME_IDENTITY" or session.account_id != plan.account_id
                or account_of_arn(plan.secret_arn) != plan.account_id):
            raise RotationError("ROTATION_ACCOUNT_NOT_SUPPORTED")
        if phase == "PREPARE":
            plan.access_pin = session.pin
        elif not plan.access_pin or plan.access_pin != session.pin:
            raise RotationError("ROTATION_ACCESS_CHANGED")

    return guard


class RotationService:
    def __init__(
        self,
        iam,
        secrets,
        sts_validator: STSValidator,
        *,
        guard,
        max_validation_attempts: int = 8,
        validation_backoff: float = 2.0,
    ) -> None:
        self.iam = iam
        self.secrets = secrets
        self.sts = sts_validator
        # guard(plan, phase) runs before a phase's first AWS call and raises RotationError to stop it.
        self.guard = guard
        self.max_validation_attempts = max_validation_attempts
        self.validation_backoff = validation_backoff

    # --- PREPARE ------------------------------------------------------------

    def prepare(self, plan: RotationPlan) -> RotationOutcome:
        self._require_two_party(plan)
        self.guard(plan, "PREPARE")

        current = self._require_current(plan)

        listed = self.iam.list_access_keys(UserName=plan.user_name)
        if not isinstance(listed, dict) or listed.get("IsTruncated", False) is not False \
                or not isinstance(listed.get("AccessKeyMetadata"), list):
            raise RotationError("ROTATION_KEY_LIST_INCOMPLETE")
        keys = listed["AccessKeyMetadata"]
        if len(keys) >= _MAX_KEYS:
            raise RotationError("ROTATION_NO_KEY_SLOT")

        plan.write_started = True
        try:
            created = self.iam.create_access_key(UserName=plan.user_name)["AccessKey"]
        except Exception as exc:
            if _rejected(exc):  # IAM answered 4xx: the request was refused and no key exists
                plan.write_started = False
            raise
        new_id, new_secret = created["AccessKeyId"], created["SecretAccessKey"]
        plan.new_key_id = new_id
        _mark(plan, "CREATED")

        # Stage the successor into AWSPENDING before proving it, so a crash after
        # creation still leaves the key recoverable from the secret. The secret's
        # other fields (a region, an endpoint) carry over to the new version.
        staged = self.secrets.put_secret_value(
            SecretId=plan.secret_arn,
            SecretString=json.dumps({**current, "AWS_ACCESS_KEY_ID": new_id, "AWS_SECRET_ACCESS_KEY": new_secret}),
            VersionStages=["AWSPENDING"],
        )
        plan.pending_version = staged.get("VersionId", "")
        if not isinstance(plan.pending_version, str) or not plan.pending_version:
            raise RotationError("ROTATION_PENDING_VERSION_UNKNOWN")
        _mark(plan, "STAGED")

        self._validate_new(plan, new_id, new_secret)
        _mark(plan, "VALIDATED")

        # Read back the pending version to confirm it is retrievable.
        self.readback(plan.secret_arn, "AWSPENDING", plan.pending_version, new_id, secret=new_secret)
        _mark(plan, "READBACK")
        return RotationOutcome.PREPARED

    def _validate_new(self, plan: RotationPlan, key_id: str, secret: str) -> None:
        for attempt in range(self.max_validation_attempts):
            if attempt:
                time.sleep(self.validation_backoff)
            try:
                identity = self.sts.validate(key_id, secret)
            except RotationError as exc:
                if exc.code in _PROPAGATION_CODES:
                    continue  # eventual consistency: retry
                break  # terminal: raised below, outside the handler, so no STS code rides along as __context__
            arn = identity.arn.split(":", 5)
            if (identity.account != plan.account_id or len(arn) != 6 or arn[0] != "arn"
                    or arn[2] != "iam" or arn[3] or arn[4] != plan.account_id or not arn[5].startswith("user/")
                    or arn[5].rsplit("/", 1)[-1] != plan.user_name.rsplit("/", 1)[-1]):
                raise RotationError("ROTATION_SUCCESSOR_IDENTITY_MISMATCH")
            return
        # A terminal STS error, or one STS keeps returning after every retry. Its raw code (InvalidClientTokenId,
        # ExpiredToken) would read as CreMore's own sign-in failing, so the failure is named for the successor.
        raise RotationError("ROTATION_SUCCESSOR_VALIDATION_FAILED")

    # --- PUBLISH ------------------------------------------------------------

    def publish(self, plan: RotationPlan) -> RotationOutcome:
        self._require_two_party(plan)
        self.guard(plan, "PUBLISH")
        if not plan.pending_version:
            raise RotationError("ROTATION_NOTHING_PREPARED")

        self._require_current(plan)
        self.readback(plan.secret_arn, "AWSPENDING", plan.pending_version, plan.new_key_id)
        # Promote AWSPENDING -> AWSCURRENT (and demote the old current).
        plan.write_started = True
        self.secrets.update_secret_version_stage(
            SecretId=plan.secret_arn,
            VersionStage="AWSCURRENT",
            MoveToVersionId=plan.pending_version,
            RemoveFromVersionId=plan.expected_current_version,
        )
        _mark(plan, "PROMOTED")

        self.readback(plan.secret_arn, "AWSCURRENT", plan.pending_version, plan.new_key_id)
        _mark(plan, "PUBLISHED")
        return RotationOutcome.PUBLISHED

    # --- helpers ------------------------------------------------------------

    def _require_current(self, plan: RotationPlan) -> dict:
        current = self.secrets.get_secret_value(SecretId=plan.secret_arn, VersionStage="AWSCURRENT")
        if not isinstance(current, dict) or current.get("VersionId") != plan.expected_current_version:
            raise RotationError("ROTATION_SECRET_DRIFT")
        data = _parse_secret(current.get("SecretString", ""))
        if data.get("AWS_ACCESS_KEY_ID") != plan.old_key_id:
            raise RotationError("ROTATION_OLD_KEY_BINDING_MISMATCH")
        return data

    def readback(self, secret_arn: str, stage: str, version_id: str, key_id: str, *, secret: str | None = None) -> None:
        """Read-only proof of the exact version and successor, shared with reconciliation."""
        value = self.secrets.get_secret_value(SecretId=secret_arn, VersionStage=stage)
        data = _parse_secret(value.get("SecretString", "")) if isinstance(value, dict) else {}
        if not data or value.get("VersionId") != version_id or not key_id or data.get("AWS_ACCESS_KEY_ID") != key_id \
                or (secret is not None and data.get("AWS_SECRET_ACCESS_KEY") != secret):
            code = "ROTATION_PENDING_READBACK_MISMATCH" if stage == "AWSPENDING" else "ROTATION_PUBLISH_READBACK_MISMATCH"
            raise RotationError(code)

    @staticmethod
    def _require_two_party(plan: RotationPlan) -> None:
        if not plan.approved_by or (plan.approved_by == plan.requested_by and not plan.single_operator):
            raise RotationError("ROTATION_TWO_PARTY_REQUIRED")


def _parse_secret(value: str) -> dict:
    try:
        data = json.loads(value)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _mark(plan: RotationPlan, stage: str) -> None:
    plan.stages.append(stage)
    plan.stage_times.append(_dt.datetime.now(_dt.UTC).isoformat())


def _rejected(exc: BaseException) -> bool:
    """AWS refused the one request it got (4xx, no SDK retry): nothing was done.

    A retried request is never taken as refused: an earlier attempt whose answer was lost may have succeeded.
    """
    response = getattr(exc, "response", None)
    meta = response.get("ResponseMetadata") if isinstance(response, dict) else None
    if not isinstance(meta, dict) or meta.get("RetryAttempts") != 0:
        return False
    status = meta.get("HTTPStatusCode")
    return isinstance(status, int) and 400 <= status < 500
