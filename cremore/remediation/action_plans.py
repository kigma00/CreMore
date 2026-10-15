"""Approval-bound IAM key action plans (disable, delete, rotation phases).

A plan binds one exact target (account, IAM user, access key id) and its
operational review into a content hash. A *different* administrator approves
that hash; a remediator then requests execution of the same hash before the
plan expires. Execution follows write-then-read-back: the provider write is
recorded as started, the resulting state is read back, and only a read-back
that proves the intended state is ``VERIFIED``. Anything else is
``OUTCOME_UNKNOWN`` and may only be *rechecked* (read-only) — never retried.

Readiness is an operator attestation (change window, consumer confirmations,
impact and recovery review) that the server re-evaluates at read and execute
time. It gates execution; it never proves that a workload survived.

Provider adapters:

* :class:`KeyActionAdapter` — ``iam:UpdateAccessKey`` (disable),
  ``iam:DeleteAccessKey`` (delete, inactive keys only), ``iam:ListAccessKeys``
  (read-back).
* the existing :class:`~cremore_aws_provider.remediation.rotation.RotationService` for the
  PREPARE / PUBLISH phases.
* another provider's credential (``ActionPlan.target``, cremore.remediation.provider_actions): the
  API queues execution and recheck (``QUEUED``) and the worker, which alone opens the remediation
  connection's secrets, runs every check again before it writes (``run_queued``, ``recheck_queued``).
"""

from __future__ import annotations

import datetime as _dt
import functools
import hashlib
import hmac
import json
import logging
import re
import uuid

from cremore_aws_provider.aws_identity import collection_error_code

from cremore.domain.models import ACTION_PLAN_UNRESOLVED, ActionPlan, Credential, FindingEvent
from cremore.remediation import owner_approval

ACTIONS = ("DISABLE_ACCESS_KEY", "DELETE_ACCESS_KEY", "PREPARE_ACCESS_KEY_ROTATION", "PUBLISH_ACCESS_KEY_ROTATION")
ROTATION_ACTIONS = ("PREPARE_ACCESS_KEY_ROTATION", "PUBLISH_ACCESS_KEY_ROTATION")
# Cannot be undone: a planned change with its acknowledgement, and the installation's deletion switch.
IRREVERSIBLE = ("DELETE_ACCESS_KEY", "REVOKE_PROVIDER_CREDENTIAL")
# A queued provider plan found in one of these has nothing left for the worker to do.
_SETTLED = ("CANCELLED", "FAILED", "VERIFIED", "OUTCOME_UNKNOWN", "EXPIRED")
# OWNER_DEPARTED: a key the departed-owner check found (cremore.identity.leavers).
REASONS = ("EXPOSURE_CONTAINMENT", "SECURITY_INCIDENT", "OWNER_REQUEST", "OWNER_DEPARTED")
UNRESOLVED = ACTION_PLAN_UNRESOLVED
POLICY_REVISION = "INDEPENDENT_APPROVAL_OPERATIONAL_V2"
SEMANTICS_REVISION = "cremore-credential-semantics-v1"
ROTATION_WORKFLOW = "APPROVED_ROTATION_V1"
ACTION_WORKFLOW = "APPROVED_ACTION_V1"
ADAPTER_VERSIONS = {"DISABLE_ACCESS_KEY": "AWS_DISABLE_V1", "DELETE_ACCESS_KEY": "AWS_DELETE_V1",
                    "PREPARE_ACCESS_KEY_ROTATION": "AWS_ROTATION_V1", "PUBLISH_ACCESS_KEY_ROTATION": "AWS_ROTATION_V1"}
_ENVIRONMENTS = ("PRODUCTION", "STAGING", "DEVELOPMENT", "DISASTER_RECOVERY")
_IMPACTS = ("UNKNOWN", "LIMITED", "SIGNIFICANT", "CRITICAL")
_TRANSITIONS = ("UNKNOWN", "PENDING", "FAILED", "SUCCEEDED")
_AUTH_BASES = ("UNKNOWN", "OLD_FALLBACK", "NEW_CREDENTIAL")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_VERSION = re.compile(r"^[A-Za-z0-9-]{32,64}$")
_SECRET_ARN = re.compile(r"^arn:(aws|aws-us-gov|aws-cn|aws-eusc):secretsmanager:[a-z]{2,4}(?:-[a-z]+)+-[0-9]+:[0-9]{12}:secret:.+$")
# RotationService journal stage -> the dashboard's stage vocabulary.
_STAGE_MAP = {"CREATED": "CREATED", "STAGED": "PENDING_WRITE_STARTED", "VALIDATED": "VALIDATED",
              "READBACK": "PENDING_CONFIRMED", "PROMOTED": "PROMOTE_STARTED", "PUBLISHED": "PROMOTE_CONFIRMED"}
_KEY_STATUS_ABSENT = "ABSENT"


logger = logging.getLogger(__name__)
_REFUSAL_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,80}")

# The audit trail's record of each plan change; a refused attempt is ACTION_PLAN_REFUSED.
_PLAN_EVENTS = {"APPROVED": "ACTION_PLAN_APPROVED", "CANCELLED": "ACTION_PLAN_CANCELLED",
                "QUEUED": "ACTION_PLAN_QUEUED", "EXECUTING": "ACTION_PLAN_EXECUTION_STARTED", "VERIFIED": "ACTION_PLAN_VERIFIED",
                "FAILED": "ACTION_PLAN_FAILED", "OUTCOME_UNKNOWN": "ACTION_PLAN_OUTCOME_UNKNOWN"}


class ActionPlanError(ValueError):
    def __init__(self, code: str, message: str = "", *, http_status: int = 422) -> None:
        super().__init__(message or code)
        self.code = code
        self.http_status = http_status


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def _parse_time(value, what: str) -> _dt.datetime:
    if not isinstance(value, str) or not value:
        raise ActionPlanError("CHANGE_REVIEW_INVALID", f"{what} must be an ISO-8601 timestamp")
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))  # noqa: FURB162 -- Preserve rejection of misplaced Z markers in the established timestamp contract.
    except ValueError:
        raise ActionPlanError("CHANGE_REVIEW_INVALID", f"{what} must be an ISO-8601 timestamp")
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.UTC)


def _iso(value) -> str | None:
    return value.isoformat() if isinstance(value, _dt.datetime) else (value or None)


# --- review validation --------------------------------------------------------


def validate_review(action_type: str, review) -> dict | None:
    """Normalise the operator's review; raise ActionPlanError on a malformed one."""

    if review is None:
        return None
    if not isinstance(review, dict):
        raise ActionPlanError("CHANGE_REVIEW_INVALID", "operational_review must be an object")
    rotation = action_type in ROTATION_ACTIONS
    mode = review.get("mode")
    if mode not in ("PLANNED", "EMERGENCY"):
        raise ActionPlanError("CHANGE_REVIEW_INVALID", "mode must be PLANNED or EMERGENCY")

    def ident(key: str, required: bool = True) -> str:
        value = review.get(key, "")
        if value in (None, "") and not required:
            return ""
        if not isinstance(value, str) or not _UUID.fullmatch(value):
            raise ActionPlanError("CHANGE_REVIEW_INVALID", f"{key} must be a UUID reference")
        return value

    def flag(key: str, source=review) -> bool:
        value = source.get(key, False)
        if not isinstance(value, bool):
            raise ActionPlanError("CHANGE_REVIEW_INVALID", f"{key} must be a boolean")
        return value

    out = {
        "mode": mode,
        "scope_evidence_id": ident("scope_evidence_id"),
        "recovery_evidence_id": ident("recovery_evidence_id"),
        "scope_complete": flag("scope_complete"),
        "unknown_consumers": flag("unknown_consumers"),
        "business_impact": review.get("business_impact", "UNKNOWN"),
        "impact_accepted": flag("impact_accepted"),
        "stop_criteria_reviewed": flag("stop_criteria_reviewed"),
        "replacement_reviewed": flag("replacement_reviewed"),
        "window_start": _parse_time(review.get("window_start"), "window_start").isoformat(),
        "window_end": _parse_time(review.get("window_end"), "window_end").isoformat(),
    }
    if out["business_impact"] not in _IMPACTS:
        raise ActionPlanError("CHANGE_REVIEW_INVALID", "business_impact is not a known level")
    if _parse_time(out["window_end"], "window_end") <= _parse_time(out["window_start"], "window_start"):
        raise ActionPlanError("CHANGE_REVIEW_INVALID", "window_end must be after window_start")
    if mode == "EMERGENCY":
        out["incident_id"] = ident("incident_id", required=False)
    if action_type in IRREVERSIBLE:
        out["deletion_acknowledged"] = flag("deletion_acknowledged")
    consumers = review.get("consumers", [])
    if not isinstance(consumers, list) or len(consumers) > 100:
        raise ActionPlanError("CHANGE_REVIEW_INVALID", "consumers must be a list of at most 100 entries")
    seen: set[tuple[str, str]] = set()
    cleaned = []
    for item in consumers:
        if not isinstance(item, dict):
            raise ActionPlanError("CHANGE_REVIEW_INVALID", "each consumer must be an object")
        consumer = {
            "consumer_id": item.get("consumer_id", ""), "owner_id": item.get("owner_id", ""),
            "evidence_id": item.get("evidence_id", "") or "", "environment": item.get("environment", ""),
            "transition": item.get("transition", "UNKNOWN"), "authentication_basis": item.get("authentication_basis", "UNKNOWN"),
            "workload_succeeded": flag("workload_succeeded", item),
            "scheduled_cycle_checked": flag("scheduled_cycle_checked", item),
            "confirmed_at": item.get("confirmed_at", ""), "valid_until": item.get("valid_until", ""),
        }
        for key in ("consumer_id", "owner_id"):
            if not isinstance(consumer[key], str) or not _UUID.fullmatch(consumer[key]):
                raise ActionPlanError("CHANGE_REVIEW_INVALID", f"consumer {key} must be a UUID reference")
        if consumer["evidence_id"] and not _UUID.fullmatch(str(consumer["evidence_id"])):
            raise ActionPlanError("CHANGE_REVIEW_INVALID", "consumer evidence_id must be a UUID reference")
        if consumer["environment"] not in _ENVIRONMENTS or consumer["transition"] not in _TRANSITIONS \
                or consumer["authentication_basis"] not in _AUTH_BASES:
            raise ActionPlanError("CHANGE_REVIEW_INVALID", "consumer environment/transition/authentication is invalid")
        if not rotation:
            confirmed = _parse_time(consumer["confirmed_at"], "confirmed_at")
            valid = _parse_time(consumer["valid_until"], "valid_until")
            if valid <= confirmed:
                raise ActionPlanError("CHANGE_REVIEW_INVALID", "valid_until must be after confirmed_at")
            consumer["confirmed_at"], consumer["valid_until"] = confirmed.isoformat(), valid.isoformat()
        key = (consumer["consumer_id"], consumer["environment"])
        if key in seen:
            raise ActionPlanError("CHANGE_REVIEW_INVALID", "duplicate consumer/environment")
        seen.add(key)
        cleaned.append(consumer)
    out["consumers"] = cleaned
    return out


def validate_rotation_binding(action_type: str, binding, allowlist: list[str]) -> dict | None:
    if action_type not in ROTATION_ACTIONS:
        if binding not in (None, {}):
            raise ActionPlanError("ROTATION_BINDING_INVALID", "rotation binding only applies to rotation phases")
        return None
    if not isinstance(binding, dict):
        raise ActionPlanError("ROTATION_BINDING_INVALID", "rotation binding is required for rotation phases")
    secret_arn = binding.get("secret_arn", "")
    version = binding.get("expected_current_version", "")
    if not isinstance(secret_arn, str) or not _SECRET_ARN.fullmatch(secret_arn):
        raise ActionPlanError("ROTATION_BINDING_INVALID", "secret_arn must be an exact Secrets Manager ARN")
    if secret_arn not in allowlist:
        raise ActionPlanError("ROTATION_SECRET_NOT_ALLOWLISTED", "secret_arn is not on the installation allowlist")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise ActionPlanError("ROTATION_BINDING_INVALID", "expected_current_version must be a 32-64 character version id")
    out = {"secret_arn": secret_arn, "expected_current_version": version}
    prep = binding.get("preparation_plan_id")
    if action_type == "PUBLISH_ACCESS_KEY_ROTATION":
        if not isinstance(prep, str) or not _UUID.fullmatch(prep):
            raise ActionPlanError("ROTATION_BINDING_INVALID", "publish requires a verified preparation_plan_id")
        out["preparation_plan_id"] = prep
    elif prep:
        raise ActionPlanError("ROTATION_BINDING_INVALID", "prepare must not reference a preparation plan")
    return out


# --- readiness ------------------------------------------------------------------


def evaluate_readiness(action_type: str, review: dict | None, now: _dt.datetime | None = None) -> dict:
    """Re-evaluate the operator attestation. Reasons use the dashboard's codes."""

    now = now or _now()
    rotation = action_type in ROTATION_ACTIONS
    deleting = action_type in IRREVERSIBLE
    reasons: list[str] = []
    confirmed = declared = 0
    mode = "NONE"
    if review is None:
        reasons.append("CHANGE_REVIEW_REQUIRED")
    else:
        mode = review["mode"]
        emergency = mode == "EMERGENCY"
        start, end = _parse_time(review["window_start"], "window_start"), _parse_time(review["window_end"], "window_end")
        if not (start <= now < end):
            reasons.append("CHANGE_WINDOW_NOT_CURRENT")
        if review["business_impact"] == "UNKNOWN" or not review["impact_accepted"] or not review["stop_criteria_reviewed"]:
            reasons.append("IMPACT_AND_RECOVERY_REVIEW_REQUIRED")
        if not review["scope_complete"] or review["unknown_consumers"]:
            reasons.append("CONSUMER_SCOPE_INCOMPLETE")
        if not review["replacement_reviewed"]:
            reasons.append("REPLACEMENT_REVIEW_REQUIRED")
        consumers = review.get("consumers", [])
        declared = len(consumers)
        if emergency:
            if not review.get("incident_id"):
                reasons.append("EMERGENCY_INCIDENT_REQUIRED")
            if rotation or deleting:
                reasons.append("ROTATION_PLANNED_REVIEW_REQUIRED" if rotation else "DELETE_PLANNED_ACKNOWLEDGEMENT_REQUIRED")
        else:
            if not consumers:
                reasons.append("EMPTY_CONSUMER_SCOPE")
            if not rotation:
                current = [c for c in consumers
                           if c.get("evidence_id") and _parse_time(c["confirmed_at"], "confirmed_at") <= now
                           < _parse_time(c["valid_until"], "valid_until")]
                if len(current) != len(consumers):
                    reasons.append("CONSUMER_EVIDENCE_NOT_CURRENT")
                confirmed = sum(1 for c in current if c["transition"] == "SUCCEEDED" and c["workload_succeeded"]
                                and c["authentication_basis"] == "NEW_CREDENTIAL")
                if consumers and confirmed != len(consumers):
                    reasons.append("CONSUMER_TRANSITION_NOT_CONFIRMED")
            if deleting and not review.get("deletion_acknowledged"):
                reasons.append("DELETE_PLANNED_ACKNOWLEDGEMENT_REQUIRED")
    reasons = list(dict.fromkeys(reasons))
    status = "INCOMPLETE" if reasons else ("EMERGENCY_REVIEW_REQUIRED" if mode == "EMERGENCY" else "READY_FOR_APPROVAL")
    return {
        "status": status, "mode": mode, "evidence_basis": "OPERATOR_ATTESTATION", "reasons": reasons,
        "confirmed_consumers": confirmed, "declared_consumers": declared,
        "execution_gate_passed": not reasons, "requires_independent_approval": True,
        "incident_closed": False, "automatic_restore_exposed_key": False,
    }


def compute_plan_hash(fields: dict) -> str:
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --- provider adapters ------------------------------------------------------------


class KeyActionAdapter:
    """IAM access-key operations with read-back. Implementations raise on failure."""

    def key_status(self, user_name: str, key_id: str) -> str:
        """'Active' | 'Inactive' | 'ABSENT'."""
        raise NotImplementedError

    def has_newer_key(self, user_name: str, key_id: str, since: _dt.datetime) -> bool:
        """Whether another key was created at or after execution began; incomplete reads raise."""
        raise NotImplementedError

    def disable_key(self, user_name: str, key_id: str) -> None:
        raise NotImplementedError

    def delete_key(self, user_name: str, key_id: str) -> None:
        raise NotImplementedError


def build_key_action_adapter_factory(region: str):
    """Compatibility entry point for the AWS provider's adapter factory."""
    from cremore_aws_provider.remediation.key_actions import (
        build_key_action_adapter_factory as build,
    )

    return build(region)


def __getattr__(name: str):
    if name == "Boto3KeyActionAdapter":
        from cremore_aws_provider.remediation.key_actions import Boto3KeyActionAdapter

        return Boto3KeyActionAdapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _error_label(exc: BaseException) -> str:
    return collection_error_code(exc)


def _state_code(value) -> str:
    return {"Active": "STATE_ACTIVE", "Inactive": "STATE_INACTIVE", "ABSENT": "STATE_ABSENT"}.get(
        value if isinstance(value, str) else "", "STATE_UNKNOWN")


def _preflight(action: str, state: str, disable_first: bool) -> str | None:
    """Why another provider's credential in ``state`` is not written to (None: write)."""
    if state == "ABSENT":
        return "CREDENTIAL_ABSENT"
    if state == "REVOKED":
        return "CREDENTIAL_ALREADY_REVOKED"
    if state == "EXPIRED":
        return "CREDENTIAL_EXPIRED"  # unusable already
    if action == "DISABLE_PROVIDER_CREDENTIAL" and state == "DISABLED":
        return "CREDENTIAL_ALREADY_DISABLED"
    if action == "REVOKE_PROVIDER_CREDENTIAL" and state == "ACTIVE" and disable_first:
        return "CREDENTIAL_NOT_DISABLED"  # like an AWS key, deleted only once disabled
    return None


# --- service ------------------------------------------------------------------------


def _refusals(action: str):
    """Record a refused attempt at ``action`` in the audit trail, then let the refusal reach the caller."""

    def wrap(method):
        @functools.wraps(method)
        def run(self, plan, actor, *args, **kwargs):
            try:
                return method(self, plan, actor, *args, **kwargs)
            except ActionPlanError as exc:
                # An execution an emergency declaration opened is refused as that emergency.
                self.refused(plan, actor, "EMERGENCY" if kwargs.get("emergency") else action, exc.code)
                raise
        return run
    return wrap


class ActionPlanService:
    def __init__(self, repo, settings, *, now=None, write_context=None, signed_approval=None, authorization_mode="execute") -> None:
        self.repo = repo
        self.settings = settings
        self.now = now or _now
        self.write_context = write_context
        self.signed_approval = signed_approval
        self.authorization_mode = authorization_mode

    def _refusal(self, event: FindingEvent) -> None:
        # A refusal answers the caller whether or not its audit row could be written.
        try:
            if self.write_context is not None:
                with self.write_context() as bound:
                    bound.record_finding_event(event)
            else:
                self.repo.record_finding_event(event)
        except Exception as exc:  # noqa: BLE001 -- the refusal stands; only its audit row is lost, and that is logged
            logger.warning("could not audit a refused action plan request: %s", type(exc).__name__)

    def refused(self, plan: ActionPlan, actor: str, action: str, code) -> None:
        """Audit a refused attempt at ``action`` on this plan, also when a route refused it after the gate."""
        code = code if isinstance(code, str) and _REFUSAL_CODE.fullmatch(code) else "REFUSED"
        self._refusal(FindingEvent(target_type="action_plan", target_id=plan.id, actor=actor or "", event_type="ACTION_PLAN_REFUSED",
                                   from_status=plan.status, to_status=plan.status, note=f"{action} {code} plan_hash={plan.plan_hash}"))

    def _save(self, plan: ActionPlan, actor: str, *, repo=None, **changes) -> ActionPlan:
        """Change the plan if nobody else did; a new status (or a recheck) is audited in the same transaction
        (``repo``: one already in a transaction with more writes)."""
        if self.write_context is not None and repo is None:
            with self.write_context() as bound:
                return self._save(plan, actor, repo=bound, **changes)
        if changes.get("status") == "EXECUTING" and getattr(self.settings, "isolated_deployment", False):
            from cremore.remediation import authorization
            claims = authorization.verify(self.settings, plan, self.signed_approval, self.authorization_mode, now=self.now(), repo=self.repo)
            authorization.consume(repo or self.repo, claims)
        status = changes.get("status", plan.status)
        event = (_PLAN_EVENTS.get(status) if status != plan.status
                 else "ACTION_PLAN_RECHECKED" if changes.get("recheck_only") else None)
        note = " ".join(part for part in (f"plan_hash={plan.plan_hash}", changes.get("safe_error_code"),
                                          "RECHECK" if changes.get("recheck_only") else None) if part)
        audit = FindingEvent(target_type="action_plan", target_id=plan.id, actor=actor or "", event_type=event,
                             from_status=plan.status, to_status=status, note=note) if event else None
        saved = (repo or self.repo).update_action_plan(plan.id, expected_status=plan.status, audit=audit, **changes)
        if saved is None:
            raise ActionPlanError("PLAN_STATE_CONFLICT", "another request changed this plan", http_status=409)
        return saved.model_copy(deep=True)

    # --- eligibility / policy -------------------------------------------------

    @staticmethod
    def _iam_user(principal_arn: str) -> tuple[str, str]:
        parts = (principal_arn or "").split(":")
        if len(parts) != 6 or parts[2] != "iam" or not parts[5].startswith("user/"):
            return "", ""
        account = parts[4]
        name = parts[5][len("user/"):].split("/")[-1]
        return (name, account) if account.isdigit() and len(account) == 12 and name else ("", "")

    #: Disabling or rotating a key is addressed by its key id, never by its
    #: secret, so an identifier observed alone is actionable once the owner
    #: account's IAM has named it. A secret alone carries no key id and stays out.
    ELIGIBLE_TYPES = frozenset({"AWS_ACCESS_KEY", "AWS_ACCESS_KEY_ID"})

    def eligible(self, credential) -> bool:
        user, _ = self._iam_user(credential.principal_arn or "")
        identifier = credential.identifier or ""
        # An STS session credential carries no IAM access key to disable or
        # rotate; IAM would answer NoSuchEntity for its id.
        return (credential.credential_type in self.ELIGIBLE_TYPES and bool(user)
                and bool(identifier) and not identifier.startswith("ASIA"))

    def unresolved(self, credential_id) -> bool:
        now = self.now()
        return (bool(self.legacy_rotation_jobs(credential_id))
                or any(plan.reserves_target(now) for plan in self.repo.list_action_plans(credential_id)))

    def legacy_rotation_jobs(self, credential_id, account_id="", key_id="") -> list:
        """Unsettled legacy writes cannot be retried or silently released by the new workflow.

        REQUESTED can mean a crash after a write; FAILED did not distinguish a
        preflight refusal from an unknown outcome. Keep the original audit state.
        """
        return [job for job in self.repo.list_rotation_jobs() if job.status != "PUBLISHED"
                and (job.credential_id == credential_id or account_id and key_id
                     and job.account_id == account_id and job.old_key_id == key_id)]

    def _require_no_legacy_rotation(self, credential_id, account_id="", key_id="") -> None:
        jobs = self.legacy_rotation_jobs(credential_id, account_id, key_id)
        if jobs:
            raise ActionPlanError("LEGACY_ROTATION_RECONCILIATION_REQUIRED",
                "administrator review of legacy job outcomes is required; no automatic retry or release: "
                + ", ".join(str(job.id) for job in jobs[:20]), http_status=409)

    @property
    def single_operator(self) -> bool:
        """Shared-token installs have one identity; it may approve its own plan
        after explicitly re-confirming it. Any OIDC install keeps two parties."""
        return self.settings.auth_mode == "local"

    def _approval_valid(self, plan: ActionPlan) -> bool:
        return bool(plan.approved_by) and (plan.approved_by != plan.requested_by or self.single_operator)

    def _ticket_owner_among(self, plan: ActionPlan, subjects, *, pending: bool = False) -> bool:
        """Whether the account that answered in the ticket system as the owner (with ``pending`` also the one still
        being asked) is one of ``subjects`` by any address it carries, or cannot be told apart from one (a
        signed-in person whose address CreMore never saw). One operator: never."""
        from cremore.governance import principals

        marks = owner_approval.ticket_owner_marks(self.repo, plan, pending=pending)
        if not marks or self.single_operator:
            return False
        known = principals.marks(self.repo, [subject for subject in subjects if subject])
        return any(value is None or any(hmac.compare_digest(value, mark) for mark in marks) for value in known.values())

    def installation_policy(self) -> dict:
        """What this installation allows for every plan, whatever the credential."""
        s = self.settings
        return {
            "execution_enabled": bool(s.action_execution_enabled),
            "independent_approval_required": not self.single_operator,
            "single_operator": self.single_operator,
            "auth_mode": s.auth_mode,
            "independent_authorization_required": bool(getattr(s, "isolated_deployment", False)),
            "supported_action": "DISABLE_ACCESS_KEY",
            "supported_actions": list(ACTIONS),
            "rotation_execution_enabled": bool(s.rotation_execution_enabled),
            "rotation_secret_arns": list(s.rotation_secret_arn_list),
            "rotation_workflow": ROTATION_WORKFLOW,
            "deletion_execution_enabled": bool(s.action_execution_enabled and s.action_deletion_enabled),
            "owner_approval_required": owner_approval.required(self.repo),
            "owner_ticket_system": self._ticket_system(),
        }

    def _ticket_system(self) -> str | None:
        """The name of the ticket system an owner's approval can be asked in, or None."""
        from cremore.ticketing import registry, setup

        name = setup.configured(self.repo)
        try:
            return registry.load(name).label if name else None
        except ValueError:
            return None

    def policy(self, credential) -> dict:
        eligible = self.eligible(credential)
        _user, account = self._iam_user(credential.principal_arn or "")
        legacy = self.legacy_rotation_jobs(credential.id, account, credential.identifier or "")
        locked = bool(legacy) or self.unresolved(credential.id)
        can = eligible and not locked
        policy = {**self.installation_policy(), "can_plan": can, "can_delete": can}
        if not can:
            reason = ("LEGACY_ROTATION_RECONCILIATION_REQUIRED" if legacy else
                      "ACTION_PLAN_TARGET_LOCKED" if (eligible and locked) else "CREDENTIAL_NOT_ELIGIBLE")
            policy["block_reason"] = reason
            policy["deletion_block_reason"] = reason
        if legacy:
            policy["legacy_rotation_job_ids"] = [str(job.id) for job in legacy[:20]]
        return policy

    # --- lifecycle --------------------------------------------------------------

    def create(self, credential, account_record_id: str, actor: str, body: dict) -> ActionPlan:
        """Plan an action on the credential's key; a refused request is audited against the credential."""
        try:
            return self._create(credential, account_record_id, actor, body)
        except ActionPlanError as exc:
            self._refusal(FindingEvent(
                target_type="credential" if isinstance(credential, Credential) else "orphan", target_id=credential.id,
                actor=actor or "", event_type="ACTION_PLAN_REFUSED", note=f"REQUEST {exc.code}"))
            raise

    def _create(self, credential, account_record_id: str, actor: str, body: dict) -> ActionPlan:
        if not isinstance(body, dict):
            raise ActionPlanError("REQUEST_INVALID", "request must be an object")
        key = body.get("idempotency_key")
        if not isinstance(key, str) or not _UUID.fullmatch(key):
            raise ActionPlanError("REQUEST_INVALID", "idempotency_key must be a UUID")
        existing = self.repo.find_action_plan(key)
        action_type = body.get("action_type", "DISABLE_ACCESS_KEY")
        if action_type not in ACTIONS:
            raise ActionPlanError("REQUEST_INVALID", f"action_type must be one of {', '.join(ACTIONS)}")
        reason = body.get("reason_code")
        if reason not in REASONS:
            raise ActionPlanError("REQUEST_INVALID", f"reason_code must be one of {', '.join(REASONS)}")
        if not self.eligible(credential):
            raise ActionPlanError("CREDENTIAL_NOT_ELIGIBLE", "only a discovered AWS access key bound to an IAM user can be planned")
        review = validate_review(action_type, body.get("operational_review"))
        rotation = validate_rotation_binding(action_type, body.get("rotation"), self.settings.rotation_secret_arn_list)
        request = {"credential_id": credential.id, "requested_by": actor, "action_type": action_type,
                   "reason_code": reason, "operational_review": review, "rotation": rotation}
        if existing is not None:
            if any(getattr(existing, field) != value for field, value in request.items()):
                raise ActionPlanError("IDEMPOTENCY_KEY_REUSED", "idempotency_key belongs to another request", http_status=409)
            return existing
        _user, account = self._iam_user(credential.principal_arn or "")
        self._require_no_legacy_rotation(credential.id, account, credential.identifier or "")
        if self.unresolved(credential.id):
            raise ActionPlanError("ACTION_PLAN_TARGET_LOCKED", "an unresolved plan already reserves this key", http_status=409)
        if action_type == "PUBLISH_ACCESS_KEY_ROTATION":
            self._verified_preparation(credential.id, rotation)
        user_name, account_id = self._iam_user(credential.principal_arn or "")
        now = self.now()
        requested_at = now
        expires_at = now + _dt.timedelta(hours=max(1, int(self.settings.action_plan_ttl_hours)))
        fields = {
            "credential_id": str(credential.id), "account_id": account_id, "user_name": user_name,
            "principal_arn": credential.principal_arn, "key_id": credential.identifier,
            "action_type": action_type, "reason_code": reason, "operational_review": review,
            "rotation": rotation, "requested_by": actor, "requested_at": requested_at.isoformat(),
            "expires_at": expires_at.isoformat(), "policy_revision": POLICY_REVISION,
        }
        rotation_phase = action_type in ROTATION_ACTIONS
        plan = ActionPlan(
            credential_id=credential.id, aws_account_id=account_record_id, account_id=account_id,
            user_name=user_name, principal_arn=credential.principal_arn or "",
            identifier_hint=credential.identifier_hint or "", key_id=credential.identifier or "",
            action_type=action_type, status="PENDING_APPROVAL", requested_by=actor, requested_at=requested_at,
            expires_at=expires_at, plan_hash=compute_plan_hash(fields), reason_code=reason, idempotency_key=key,
            operational_review=review, readiness=evaluate_readiness(action_type, review, now), rotation=rotation,
            workflow_version=ROTATION_WORKFLOW if rotation_phase else ACTION_WORKFLOW,
            adapter_version=ADAPTER_VERSIONS[action_type], policy_revision=POLICY_REVISION,
            semantics_revision=SEMANTICS_REVISION,
        )
        requested = FindingEvent(target_type="action_plan", actor=actor, event_type="ACTION_PLAN_REQUESTED",
                                 to_status="PENDING_APPROVAL", note=f"{action_type} {reason} plan_hash={plan.plan_hash}")
        try:
            return self.repo.create_action_plan(plan, audit=requested)
        except ValueError:
            existing = self.repo.find_action_plan(key)
            if existing is not None:
                if all(getattr(existing, field) == value for field, value in request.items()):
                    return existing
                raise ActionPlanError("IDEMPOTENCY_KEY_REUSED", "idempotency_key belongs to another request", http_status=409) from None
            raise ActionPlanError("ACTION_PLAN_TARGET_LOCKED", "another request reserved this target", http_status=409) from None

    def _verified_preparation(self, credential_id, rotation: dict) -> ActionPlan:
        prep = self.repo.get_action_plan(uuid.UUID(rotation["preparation_plan_id"]))
        if (prep is None or prep.credential_id != credential_id or prep.action_type != "PREPARE_ACCESS_KEY_ROTATION"
                or prep.status != "VERIFIED" or not prep.rotation
                or prep.rotation.get("secret_arn") != rotation["secret_arn"]
                or prep.rotation.get("expected_current_version") != rotation["expected_current_version"]
                or not prep.new_key_id or not prep.pending_version):
            raise ActionPlanError("PREPARATION_PLAN_NOT_VERIFIED",
                                  "publish needs a VERIFIED preparation plan for the same secret and version")
        return prep

    def _current(self, plan: ActionPlan) -> str:
        now = self.now()
        if plan.status in ("PENDING_APPROVAL", "APPROVED") and plan.expires_at and plan.expires_at <= now:
            return "EXPIRED"
        return plan.status

    def _bind(self, plan: ActionPlan, plan_hash) -> None:
        if not isinstance(plan_hash, str) or plan_hash.lower() != plan.plan_hash:
            raise ActionPlanError("PLAN_HASH_MISMATCH", "the request is not bound to this plan's content", http_status=409)

    @_refusals("APPROVE")
    def approve(self, plan: ActionPlan, actor: str, plan_hash, self_approval_confirmed: bool = False) -> ActionPlan:
        plan = plan.model_copy(deep=True)
        self._bind(plan, plan_hash)
        if self._current(plan) != "PENDING_APPROVAL":
            raise ActionPlanError("PLAN_NOT_PENDING", f"plan is {self._current(plan)}", http_status=409)
        if not actor:
            raise ActionPlanError("INDEPENDENT_APPROVAL_REQUIRED", "a different administrator must approve", http_status=409)
        if actor == plan.requested_by:
            if not self.single_operator:
                raise ActionPlanError("INDEPENDENT_APPROVAL_REQUIRED", "a different administrator must approve", http_status=409)
            if self_approval_confirmed is not True:
                raise ActionPlanError("SELF_APPROVAL_CONFIRMATION_REQUIRED",
                                      "re-confirm the reviewed target and plan hash to approve your own plan", http_status=409)
        if owner_approval.owner_decider(self.repo, plan) == actor or self._ticket_owner_among(plan, [actor], pending=True):
            # Whoever decided as the key's owner does not also approve for the security team.
            raise ActionPlanError("INDEPENDENT_APPROVAL_REQUIRED", "the key's owner cannot also approve the plan",
                                  http_status=409)
        readiness = evaluate_readiness(plan.action_type, plan.operational_review, self.now())
        if not readiness["execution_gate_passed"]:
            raise ActionPlanError("READINESS_GATE_FAILED", "; ".join(readiness["reasons"]), http_status=409)
        return self._save(plan, actor, status="APPROVED", approved_by=actor, approved_at=self.now(),
                                            readiness=readiness)

    @_refusals("CANCEL")
    def cancel(self, plan: ActionPlan, actor: str) -> ActionPlan:
        plan = plan.model_copy(deep=True)
        current = self._current(plan)
        if current not in ("PENDING_APPROVAL", "APPROVED", "QUEUED") or plan.provider_write_started_at:
            raise ActionPlanError("PLAN_NOT_CANCELLABLE", f"plan is {current}", http_status=409)
        return self._save(plan, actor, status="CANCELLED")

    def _execution_gate(self, plan: ActionPlan, actor: str, plan_hash, emergency: bool = False,
                        status: str = "APPROVED", signed_approval=None) -> dict:
        """``status``: APPROVED when asked to run, QUEUED when the worker runs a provider plan it was handed."""
        self._bind(plan, plan_hash)
        from cremore.remediation import authorization
        authorization.verify(self.settings, plan, signed_approval or self.signed_approval,
                             "emergency" if emergency else self.authorization_mode, now=self.now(), repo=self.repo)
        if self._current(plan) != status:
            raise ActionPlanError("PLAN_NOT_APPROVED" if status == "APPROVED" else "PLAN_NOT_QUEUED",
                                  f"plan is {self._current(plan)}", http_status=409)
        if not self._approval_valid(plan) or not actor:
            raise ActionPlanError("INDEPENDENT_APPROVAL_REQUIRED", "approval must come from a different identity", http_status=409)
        self._require_no_legacy_rotation(plan.credential_id, plan.account_id, plan.key_id)
        s = self.settings
        if not s.action_execution_enabled:
            raise ActionPlanError("EXECUTION_DISABLED", "ACTION_EXECUTION_ENABLED is false", http_status=409)
        if plan.action_type in IRREVERSIBLE and not s.action_deletion_enabled:
            raise ActionPlanError("DELETION_DISABLED", "ACTION_DELETION_ENABLED is false", http_status=409)
        if plan.action_type in ROTATION_ACTIONS and not s.rotation_execution_enabled:
            raise ActionPlanError("ROTATION_DISABLED", "ACTION_ROTATION_ENABLED is false", http_status=409)
        if plan.action_type in ROTATION_ACTIONS:
            validate_rotation_binding(plan.action_type, plan.rotation, s.rotation_secret_arn_list)
        if not emergency and owner_approval.needed(self.repo, plan):
            raise ActionPlanError("OWNER_APPROVAL_REQUIRED", "the key's owner has not approved this plan", http_status=409)
        decider = owner_approval.owner_decider(self.repo, plan)
        if ((decider is not None and decider in (plan.approved_by, plan.requested_by))
                or self._ticket_owner_among(plan, [plan.approved_by, plan.requested_by])):
            # Checked again here: an owner's decision can land after the approval that read no decision yet.
            raise ActionPlanError("INDEPENDENT_APPROVAL_REQUIRED", "the key's owner also acted for the security team",
                                  http_status=409)
        readiness = evaluate_readiness(plan.action_type, plan.operational_review, self.now())
        if not readiness["execution_gate_passed"]:
            raise ActionPlanError("READINESS_GATE_FAILED", "; ".join(readiness["reasons"]), http_status=409)
        return readiness

    @_refusals("EXECUTE")
    def gate(self, plan: ActionPlan, actor: str, plan_hash) -> dict:
        """Every approval and policy check execution makes, before any provider session is built."""
        return self._execution_gate(plan, actor, plan_hash)

    @_refusals("EMERGENCY")
    def emergency(self, plan: ActionPlan, actor: str, plan_hash, reason: str, *, signed_approval=None) -> None:
        """An Admin's containment of a publicly exposed key while its owner's approval is still missing: every other
        check of execution holds, and the declaration is audited before any provider session is built."""
        if plan.action_type != owner_approval.EMERGENCY_ACTION:
            raise ActionPlanError("EMERGENCY_ACTION_NOT_ALLOWED", "only disabling a key is an emergency", http_status=409)
        if not owner_approval.needed(self.repo, plan):
            raise ActionPlanError("EMERGENCY_NOT_NEEDED", "execute the plan as usual", http_status=409)
        if not owner_approval.publicly_exposed(self.repo, plan.credential_id):
            raise ActionPlanError("EMERGENCY_NOT_PUBLIC", "the key has no current public exposure", http_status=409)
        self._execution_gate(plan, actor, plan_hash, emergency=True, signed_approval=signed_approval)
        owner_approval.declare_emergency(self.repo, plan, actor, reason, self.now())

    @_refusals("RECHECK")
    def bound(self, plan: ActionPlan, actor: str, plan_hash) -> None:
        """The request names this plan's content; checked before a recheck builds a provider session."""
        self._bind(plan, plan_hash)

    @_refusals("EXECUTE")
    def execute(self, plan: ActionPlan, actor: str, plan_hash, *, adapter: KeyActionAdapter | None = None,
                rotation_service=None, emergency: bool = False, queued: bool = False) -> ActionPlan:
        plan = plan.model_copy(deep=True)
        if getattr(self.settings, "isolated_deployment", False):
            from cremore.worker.isolation import execution_role
            if execution_role(self.settings) != "remediator" or self.write_context is None or not queued:
                raise ActionPlanError("ACTION_REQUIRES_ISOLATED_WORKER", "queue this action", http_status=409)
        if plan.target:
            raise ActionPlanError("PROVIDER_PLAN_RUNS_IN_WORKER", "queue it: only the worker opens its credential",
                                  http_status=409)
        # An emergency holds only for a disable its caller declared (and audited) for this plan.
        emergency = (emergency and plan.action_type == owner_approval.EMERGENCY_ACTION
                     and (owner_approval.emergency(self.repo, plan.id) or {}).get("by") == actor)
        readiness = self._execution_gate(plan, actor, plan_hash, emergency, status="QUEUED" if queued else "APPROVED")
        if plan.action_type in ROTATION_ACTIONS:
            return self._execute_rotation(plan, actor, readiness, rotation_service)
        if adapter is None:
            raise ActionPlanError("ADAPTER_NOT_CONFIGURED", "no IAM adapter is configured on this API", http_status=503)
        now = self.now()
        # Preflight (read-only): the key must exist, and a deletion target must
        # already be inactive. Failures here never start a provider write.
        try:
            status = adapter.key_status(plan.user_name, plan.key_id)
        except Exception as exc:  # noqa: BLE001 -- Provider failures retain failed/unknown outcome; never retry uncertain writes or expose secrets.
            return self._save(plan, actor, status="FAILED", safe_error_code=_error_label(exc),
                                                readiness=readiness, executed_at=now)
        if status == _KEY_STATUS_ABSENT:
            return self._save(plan, actor, status="FAILED", safe_error_code="KEY_ABSENT", readiness=readiness,
                                                executed_at=now)
        if status not in ("Active", "Inactive"):
            return self._save(plan, actor, status="FAILED", safe_error_code="KEY_STATE_UNKNOWN", readiness=readiness,
                              executed_at=now)
        if plan.action_type == "DELETE_ACCESS_KEY" and status != "Inactive":
            return self._save(plan, actor, status="FAILED", safe_error_code="KEY_NOT_INACTIVE",
                                                readiness=readiness, executed_at=now)
        readiness = self._execution_gate(plan, actor, plan_hash, emergency, status="QUEUED" if queued else "APPROVED")
        plan = self._save(plan, actor, status="EXECUTING", provider_write_started_at=now,
                                            executed_at=now, readiness=readiness)
        try:
            if plan.action_type == "DISABLE_ACCESS_KEY":
                adapter.disable_key(plan.user_name, plan.key_id)
                wanted = "Inactive"
            else:
                adapter.delete_key(plan.user_name, plan.key_id)
                wanted = _KEY_STATUS_ABSENT
            observed = adapter.key_status(plan.user_name, plan.key_id)
        except Exception as exc:  # noqa: BLE001 -- Provider failures retain failed/unknown outcome; never retry uncertain writes or expose secrets.
            # The write may or may not have happened: unknown, never retried.
            return self._save(plan, actor, status="OUTCOME_UNKNOWN", safe_error_code=_error_label(exc))
        if observed == wanted:
            return self._save(plan, actor, status="VERIFIED", verified_at=self.now(), safe_error_code=None)
        return self._save(plan, actor, status="OUTCOME_UNKNOWN", safe_error_code=_state_code(observed))

    def _execute_rotation(self, plan: ActionPlan, actor: str, readiness: dict, rotation_service) -> ActionPlan:
        from cremore_aws_provider.remediation.rotation import RotationPlan

        if rotation_service is None:
            raise ActionPlanError("ROTATION_SERVICE_NOT_CONFIGURED", "no rotation service is configured on this API",
                                  http_status=503)
        binding = plan.rotation or {}
        prep = None
        if plan.action_type == "PUBLISH_ACCESS_KEY_ROTATION":
            prep = self._verified_preparation(plan.credential_id, binding)
        rp = RotationPlan(
            user_name=plan.user_name, account_id=plan.account_id, secret_arn=binding.get("secret_arn", ""),
            expected_current_version=binding.get("expected_current_version", ""), old_key_id=plan.key_id,
            requested_by=plan.requested_by, approved_by=plan.approved_by or actor, single_operator=self.single_operator,
            new_key_id=(prep.new_key_id if prep else ""), pending_version=(prep.pending_version if prep else ""),
            access_pin=((prep.access_pin or "") if prep else ""),
        )
        now = self.now()
        plan = self._save(plan, actor, status="EXECUTING", provider_write_started_at=now,
                                            executed_at=now, readiness=readiness)
        progress = list(plan.rotation_progress or [])

        def journal() -> list[dict]:
            stamp = self.now().isoformat()
            times = rp.stage_times
            return progress + [{"stage": _STAGE_MAP.get(s, s), "recorded_at": times[i] if i < len(times) else stamp}
                               for i, s in enumerate(rp.stages)]

        try:
            if plan.action_type == "PREPARE_ACCESS_KEY_ROTATION":
                rotation_service.prepare(rp)
                return self._save(plan, actor, status="VERIFIED", verified_at=self.now(), safe_error_code=None,
                    result_kind="SUCCESSOR_PREPARED_OLD_KEY_ACTIVE", next_step="INDEPENDENTLY_APPROVE_PUBLISH",
                    rotation_progress=journal(), new_key_id=rp.new_key_id, pending_version=rp.pending_version,
                    access_pin=rp.access_pin or None)
            rotation_service.publish(rp)
            return self._save(plan, actor, status="VERIFIED", verified_at=self.now(), safe_error_code=None,
                result_kind="SUCCESSOR_PUBLISHED_OLD_KEY_ACTIVE", next_step="VERIFY_CONSUMER_TRANSITION_BEFORE_DISABLE",
                rotation_progress=journal(), new_key_id=rp.new_key_id, pending_version=rp.pending_version)
        except Exception as exc:  # noqa: BLE001 -- Provider failures retain failed/unknown outcome; never retry uncertain writes or expose secrets.
            # Validation and readback can fail after a key was created or a version promoted: such a target stays
            # reserved for reconciliation. A failure before the first write (a read, a refused create) changed nothing.
            uncertain = rp.write_started or bool(rp.stages)
            return self._save(plan, actor, status="OUTCOME_UNKNOWN" if uncertain else "FAILED", safe_error_code=_error_label(exc),
                result_kind="PROVIDER_OUTCOME_UNKNOWN_OLD_KEY_NOT_DISABLED" if uncertain else "ROTATION_NOT_COMPLETED",
                next_step="READ_ONLY_RECHECK_NO_WRITE_RETRY" if uncertain else "REVIEW_ACTION_STATE",
                rotation_progress=journal(), new_key_id=rp.new_key_id or None,
                pending_version=rp.pending_version or None, access_pin=rp.access_pin or None)

    @_refusals("RECHECK")
    def recheck(self, plan: ActionPlan, actor: str, plan_hash, *, adapter: KeyActionAdapter | None = None,
                rotation_service=None) -> ActionPlan:
        """Read-only reconciliation of an OUTCOME_UNKNOWN plan. Never writes."""
        plan = plan.model_copy(deep=True)
        self._bind(plan, plan_hash)
        if plan.target:
            raise ActionPlanError("PROVIDER_PLAN_RUNS_IN_WORKER", "queue it: only the worker opens its credential",
                                  http_status=409)
        if plan.status != "OUTCOME_UNKNOWN":
            raise ActionPlanError("PLAN_NOT_UNKNOWN", f"plan is {plan.status}", http_status=409)
        if not self._approval_valid(plan) or not actor:
            raise ActionPlanError("INDEPENDENT_APPROVAL_REQUIRED", "recheck requires the approved plan", http_status=409)
        if plan.action_type in ROTATION_ACTIONS:
            if (plan.action_type == "PREPARE_ACCESS_KEY_ROTATION" and not plan.new_key_id
                    and not plan.pending_version and not plan.rotation_progress):
                starts = [stamp.replace(tzinfo=_dt.UTC) if stamp.tzinfo is None else stamp
                          for stamp in (plan.executed_at, plan.provider_write_started_at) if stamp is not None]
                if not starts:
                    return self._save(plan, actor, recheck_only=True, safe_error_code="ROTATION_EXECUTION_TIME_UNKNOWN")
                try:
                    if adapter is None:
                        if rotation_service is None:
                            raise ActionPlanError("ADAPTER_NOT_CONFIGURED")
                        from cremore_aws_provider.remediation.key_actions import (
                            Boto3KeyActionAdapter,
                        )

                        adapter = Boto3KeyActionAdapter(rotation_service.iam)
                    # AWS's clock is not ours: a key made up to five minutes before the recorded start may be this
                    # plan's own successor, so it keeps the plan unknown rather than closing it.
                    if adapter.has_newer_key(plan.user_name, plan.key_id, min(starts) - _dt.timedelta(minutes=5)):
                        return self._save(plan, actor, recheck_only=True, safe_error_code="ROTATION_UNRECORDED_KEY_EXISTS")
                except Exception as exc:  # noqa: BLE001 -- A failed read cannot release an uncertain target.
                    return self._save(plan, actor, recheck_only=True, safe_error_code=_error_label(exc))
                return self._save(plan, actor, status="FAILED", recheck_only=True, safe_error_code=None,
                                  result_kind="ROTATION_NOT_COMPLETED", next_step="REVIEW_ACTION_STATE")
            if rotation_service is None or not plan.pending_version or not plan.new_key_id:
                return self._save(plan, actor, recheck_only=True)
            stage = "AWSPENDING" if plan.action_type == "PREPARE_ACCESS_KEY_ROTATION" else "AWSCURRENT"
            if stage == "AWSPENDING" and not any(entry.get("stage") == "VALIDATED" for entry in plan.rotation_progress):
                return self._save(plan, actor, recheck_only=True, safe_error_code="ROTATION_SUCCESSOR_VALIDATION_NOT_RECORDED")
            try:
                rotation_service.readback((plan.rotation or {}).get("secret_arn", ""), stage,
                                          plan.pending_version, plan.new_key_id)
            except Exception as exc:  # noqa: BLE001 -- Provider failures retain failed/unknown outcome; never retry uncertain writes or expose secrets.
                return self._save(plan, actor, recheck_only=True, safe_error_code=_error_label(exc))
            kind = "SUCCESSOR_PREPARED_OLD_KEY_ACTIVE" if stage == "AWSPENDING" else "SUCCESSOR_PUBLISHED_OLD_KEY_ACTIVE"
            step = "INDEPENDENTLY_APPROVE_PUBLISH" if stage == "AWSPENDING" else "VERIFY_CONSUMER_TRANSITION_BEFORE_DISABLE"
            return self._save(plan, actor, status="VERIFIED", verified_at=self.now(), recheck_only=True,
                              safe_error_code=None, result_kind=kind, next_step=step)
        if adapter is None:
            raise ActionPlanError("ADAPTER_NOT_CONFIGURED", "no IAM adapter is configured on this API", http_status=503)
        try:
            observed = adapter.key_status(plan.user_name, plan.key_id)
        except Exception as exc:  # noqa: BLE001 -- Provider failures retain failed/unknown outcome; never retry uncertain writes or expose secrets.
            return self._save(plan, actor, recheck_only=True, safe_error_code=_error_label(exc))
        wanted = "Inactive" if plan.action_type == "DISABLE_ACCESS_KEY" else _KEY_STATUS_ABSENT
        if observed == wanted:
            return self._save(plan, actor, status="VERIFIED", verified_at=self.now(), recheck_only=True,
                                                safe_error_code=None)
        return self._save(plan, actor, recheck_only=True, safe_error_code=_state_code(observed))

    # --- another provider's credential (cremore.remediation.provider_actions) ----------------------------------

    def target_policy(self, target: dict) -> dict:
        """What may be planned on this inventoried credential now, and the remediation connection that would act."""
        from cremore.remediation import provider_actions

        reason, connection = None, None
        try:
            connection = provider_actions.remediation_connection(self.repo, target)
        except provider_actions.ProviderActionError as exc:
            reason = exc.code
        if self.unresolved(provider_actions.target_key(target)):
            reason = "ACTION_PLAN_TARGET_LOCKED"
        acting = None
        if connection:
            from cremore.onboarding.service import shared_credentials
            from cremore.onboarding.store import ProviderConnectionStore

            # A scan or collection that holds the same credential: shown with the plan, as it is on the connection.
            shared = shared_credentials(ProviderConnectionStore(self.repo).list()).get(connection["id"], [])
            acting = {"id": str(connection["id"]), "name": connection["name"], "provider": connection["provider"],
                      "auth_method": connection["auth_method"], "shared_with": shared}
        policy = {**self.installation_policy(), "supported_actions": list(target["actions"]), "can_plan": reason is None,
                  "remediation_connection": acting, **({"revokes": target["revokes"]} if "revokes" in target else {})}
        if reason:
            policy["block_reason"] = reason
        return policy

    def create_for_target(self, entity_id, actor: str, body: dict) -> ActionPlan:
        """Plan an action on an inventoried credential of another provider; a refused request is audited."""
        try:
            return self._create_for_target(entity_id, actor, body)
        except ActionPlanError as exc:
            try:
                target_id = uuid.UUID(str(entity_id))
            except ValueError:
                target_id = None
            self._refusal(FindingEvent(target_type="coverage_entity", target_id=target_id, actor=actor or "",
                                       event_type="ACTION_PLAN_REFUSED", note=f"REQUEST {exc.code}"))
            raise

    def _create_for_target(self, entity_id, actor: str, body: dict) -> ActionPlan:
        from cremore.remediation import provider_actions

        if not isinstance(body, dict):
            raise ActionPlanError("REQUEST_INVALID", "request must be an object")
        key = body.get("idempotency_key")
        if not isinstance(key, str) or not _UUID.fullmatch(key):
            raise ActionPlanError("REQUEST_INVALID", "idempotency_key must be a UUID")
        action_type = body.get("action_type")
        if action_type not in provider_actions.ACTIONS:
            raise ActionPlanError("REQUEST_INVALID", f"action_type must be one of {', '.join(provider_actions.ACTIONS)}")
        reason = body.get("reason_code")
        if reason not in REASONS:
            raise ActionPlanError("REQUEST_INVALID", f"reason_code must be one of {', '.join(REASONS)}")
        if body.get("rotation") not in (None, {}):
            raise ActionPlanError("REQUEST_INVALID", "rotation only applies to AWS rotation phases")
        try:
            target = provider_actions.target_of(self.repo, entity_id)
            if action_type not in target["actions"]:
                raise provider_actions.ProviderActionError("ACTION_NOT_SUPPORTED_FOR_CREDENTIAL")
            connection = provider_actions.remediation_connection(self.repo, target)
        except provider_actions.ProviderActionError as exc:
            raise ActionPlanError(exc.code, "this credential cannot be planned now",
                                  http_status=404 if exc.code == "CREDENTIAL_NOT_FOUND" else 409) from None
        review = validate_review(action_type, body.get("operational_review"))
        lock = provider_actions.target_key(target)
        # What acts is bound too: the connection, its sign-in method and the account its check named.
        bound = {**{name: target[name] for name in ("provider", "entity_id", "object_id", "origin", "tenant",
                                                     "reference", "hint", "revokes") if name in target},
                 "connection_id": str(connection["id"]), "connection_name": connection["name"],
                 "auth_method": connection["auth_method"],
                 "subject": provider_actions.checked_subject(connection, target["reference"])}
        request = {"credential_id": lock, "requested_by": actor, "action_type": action_type, "reason_code": reason,
                   "operational_review": review, "target": bound}
        existing = self.repo.find_action_plan(key)
        if existing is not None:
            if any(getattr(existing, field) != value for field, value in request.items()):
                raise ActionPlanError("IDEMPOTENCY_KEY_REUSED", "idempotency_key belongs to another request", http_status=409)
            return existing
        if self.unresolved(lock):
            raise ActionPlanError("ACTION_PLAN_TARGET_LOCKED", "an unresolved plan already reserves this credential",
                                  http_status=409)
        now = self.now()
        expires_at = now + _dt.timedelta(hours=max(1, int(self.settings.action_plan_ttl_hours)))
        fields = {"credential_id": str(lock), "target": bound, "action_type": action_type, "reason_code": reason,
                  "operational_review": review, "requested_by": actor, "requested_at": now.isoformat(),
                  "expires_at": expires_at.isoformat(), "policy_revision": POLICY_REVISION}
        plan = ActionPlan(
            credential_id=lock, target=bound, identifier_hint=target["hint"], action_type=action_type,
            status="PENDING_APPROVAL", requested_by=actor, requested_at=now, expires_at=expires_at,
            plan_hash=compute_plan_hash(fields), reason_code=reason, idempotency_key=key, operational_review=review,
            readiness=evaluate_readiness(action_type, review, now), workflow_version=ACTION_WORKFLOW,
            adapter_version=provider_actions.module(target["provider"]).ADAPTER_VERSION,
            policy_revision=POLICY_REVISION, semantics_revision=SEMANTICS_REVISION,
        )
        requested = FindingEvent(target_type="action_plan", actor=actor, event_type="ACTION_PLAN_REQUESTED",
                                 to_status="PENDING_APPROVAL", note=f"{action_type} {reason} plan_hash={plan.plan_hash}")
        try:
            return self.repo.create_action_plan(plan, audit=requested)
        except ValueError:
            existing = self.repo.find_action_plan(key)
            if existing is not None:
                if all(getattr(existing, field) == value for field, value in request.items()):
                    return existing
                raise ActionPlanError("IDEMPOTENCY_KEY_REUSED", "idempotency_key belongs to another request", http_status=409) from None
            raise ActionPlanError("ACTION_PLAN_TARGET_LOCKED", "another request reserved this target", http_status=409) from None

    def _enqueue(self, plan: ActionPlan, actor: str, mode: str, *, signed_approval=None, **changes) -> ActionPlan:
        """The worker's job and the plan's change (with its audit row) in one transaction."""
        from cremore.domain.models import ScanJob
        from cremore.onboarding.store import atomic
        from cremore.remediation.provider_actions import JOB_KIND

        job = ScanJob(kind=JOB_KIND, payload={"plan_id": str(plan.id), "plan_hash": plan.plan_hash, "actor": actor,
                                              "mode": mode, **({"signed_approval": signed_approval} if signed_approval else {})})
        with atomic(self.repo) as bound:
            if changes:
                plan = self._save(plan, actor, repo=bound, **changes)
            else:  # a recheck asked for: in the audit trail from the request, not only once it ran
                bound.record_finding_event(FindingEvent(
                    target_type="action_plan", target_id=plan.id, actor=actor or "",
                    event_type="ACTION_PLAN_RECHECK_REQUESTED", from_status=plan.status, to_status=plan.status,
                    note=f"plan_hash={plan.plan_hash}"))
            bound.enqueue_job(job)
        return plan

    def interrupted(self, plan_id, actor: str) -> None:
        """A worker run that broke off without a result: a plan still waiting to run fails (nothing was written);
        one whose write started is unknown, to be rechecked. Best effort, for the job fails anyway."""
        try:
            plan = self.repo.get_action_plan(plan_id)
            if plan is not None and plan.status == "QUEUED":
                self._save(plan, actor, status="FAILED", safe_error_code="WORKER_ERROR", executed_at=self.now())
            elif plan is not None and plan.status == "EXECUTING":
                self._save(plan, actor, status="OUTCOME_UNKNOWN", safe_error_code="EXECUTION_INTERRUPTED")
        except Exception as exc:  # noqa: BLE001 -- the job's own failure is what gets reported
            logger.warning("could not settle an interrupted provider plan: %s", type(exc).__name__)

    @_refusals("EXECUTE")
    def queue_execution(self, plan: ActionPlan, actor: str, plan_hash, *, signed_approval=None, emergency=False) -> ActionPlan:
        """Hand an approved provider plan to the worker, which alone opens the remediation connection's secrets and
        runs every check again (``run_queued``)."""
        plan = plan.model_copy(deep=True)
        if not plan.target and not getattr(self.settings, "isolated_deployment", False):
            raise ActionPlanError("PLAN_NOT_QUEUEABLE", "an AWS key plan runs at once", http_status=409)
        emergency = bool(emergency and plan.action_type == owner_approval.EMERGENCY_ACTION
                         and (owner_approval.emergency(self.repo, plan.id) or {}).get("by") == actor)
        readiness = self._execution_gate(plan, actor, plan_hash, emergency=emergency, signed_approval=signed_approval)
        return self._enqueue(plan, actor, "emergency" if emergency else "execute", signed_approval=signed_approval,
                             status="QUEUED", readiness=readiness)

    @_refusals("RECHECK")
    def queue_recheck(self, plan: ActionPlan, actor: str, plan_hash, *, signed_approval=None) -> ActionPlan:
        """Hand a read-only recheck of an OUTCOME_UNKNOWN provider plan to the worker, one at a time."""
        from cremore.remediation.provider_actions import JOB_KIND

        plan = plan.model_copy(deep=True)
        self._bind(plan, plan_hash)
        if not plan.target and not getattr(self.settings, "isolated_deployment", False):
            raise ActionPlanError("PLAN_NOT_QUEUEABLE", "an AWS key plan is rechecked at once", http_status=409)
        from cremore.remediation import authorization
        authorization.verify(self.settings, plan, signed_approval, "recheck", now=self.now(), repo=self.repo)
        if plan.status != "OUTCOME_UNKNOWN":
            raise ActionPlanError("PLAN_NOT_UNKNOWN", f"plan is {plan.status}", http_status=409)
        if not self._approval_valid(plan) or not actor:
            raise ActionPlanError("INDEPENDENT_APPROVAL_REQUIRED", "recheck requires the approved plan", http_status=409)
        if any(job.kind == JOB_KIND and job.status in ("QUEUED", "RUNNING")
               and (job.payload or {}).get("plan_id") == str(plan.id) for job in self.repo.list_jobs(500)):
            raise ActionPlanError("RECHECK_ALREADY_QUEUED", "the worker has this plan's recheck already",
                                  http_status=409)
        return self._enqueue(plan, actor, "recheck", signed_approval=signed_approval)

    def _queued_gate(self, plan: ActionPlan, actor: str, plan_hash) -> dict:
        readiness = self._execution_gate(plan, actor, plan_hash, status="QUEUED")
        if plan.expires_at and plan.expires_at <= self.now():
            raise ActionPlanError("PLAN_EXPIRED", "the plan expired while it waited", http_status=409)
        return readiness

    @_refusals("EXECUTE")
    def run_queued(self, plan: ActionPlan, actor: str, plan_hash, opener) -> ActionPlan:
        """The worker's side of a queued execution: every check again, the credential's state, the write, the
        read-back. ``opener()`` opens the remediation connection (provider_actions.Session) once the gate passed."""
        from cremore.remediation.provider_actions import WANTED, code_of

        plan = plan.model_copy(deep=True)
        self._bind(plan, plan_hash)
        if plan.status == "EXECUTING":
            # A worker stopped between the write and its read-back: whether the write happened is unknown.
            return self._save(plan, actor, status="OUTCOME_UNKNOWN", safe_error_code="EXECUTION_INTERRUPTED")
        if plan.status in _SETTLED:
            return plan  # cancelled while it waited, or it ran already: nothing to do, and nobody was refused
        if not plan.target or plan.status != "QUEUED":
            raise ActionPlanError("PLAN_NOT_QUEUED", f"plan is {plan.status}", http_status=409)
        now = self.now()
        try:
            readiness = self._queued_gate(plan, actor, plan_hash)
        except ActionPlanError as exc:
            # Nothing was written: the plan ends here, and a new one is planned if it is still wanted.
            return self._save(plan, actor, status="FAILED", safe_error_code=exc.code, executed_at=now)
        session = None
        try:
            try:
                session = opener()
                state = session.state()
            except Exception as exc:  # noqa: BLE001 -- read-only preflight: nothing written, the code alone is kept
                return self._save(plan, actor, status="FAILED", safe_error_code=code_of(exc), readiness=readiness,
                                  executed_at=now)
            refusal = _preflight(plan.action_type, state, session.disable_first)
            if refusal is None and plan.target.get("subject"):
                # The credential acts as the account the plan was approved with, asked of the provider now.
                try:
                    if session.whoami() != plan.target["subject"]:
                        refusal = "REMEDIATION_CONNECTION_CHANGED"
                except Exception as exc:  # noqa: BLE001 -- a read: nothing written, the code alone is kept
                    refusal = code_of(exc)
            if refusal is None:
                try:
                    readiness = self._queued_gate(plan, actor, plan_hash)  # anything that landed during the read
                except ActionPlanError as exc:
                    refusal = exc.code
            if refusal is not None:
                return self._save(plan, actor, status="FAILED", safe_error_code=refusal, readiness=readiness,
                                  executed_at=now)
            plan = self._save(plan, actor, status="EXECUTING", provider_write_started_at=now, executed_at=now,
                              readiness=readiness)
            try:
                session.apply(plan.action_type)
            except Exception as exc:  # noqa: BLE001 -- a clear refusal changed nothing; anything else may have
                return self._save(plan, actor, status="FAILED" if getattr(exc, "refused", False) is True
                                  else "OUTCOME_UNKNOWN", safe_error_code=code_of(exc))
            try:
                observed = session.state()
            except Exception as exc:  # noqa: BLE001 -- the write may have happened: unknown, never retried
                return self._save(plan, actor, status="OUTCOME_UNKNOWN", safe_error_code=code_of(exc))
            if observed in WANTED[plan.action_type]:
                return self._save(plan, actor, status="VERIFIED", verified_at=self.now(), safe_error_code=None)
            return self._save(plan, actor, status="OUTCOME_UNKNOWN", safe_error_code="STATE_" + observed)
        finally:
            if session is not None:
                session.close()

    @_refusals("RECHECK")
    def recheck_queued(self, plan: ActionPlan, actor: str, plan_hash, opener) -> ActionPlan:
        """The worker's read-only recheck of an OUTCOME_UNKNOWN provider plan. Never writes."""
        from cremore.remediation.provider_actions import WANTED, code_of

        plan = plan.model_copy(deep=True)
        self._bind(plan, plan_hash)
        if plan.target and plan.status in _SETTLED and plan.status != "OUTCOME_UNKNOWN":
            return plan  # settled by an earlier recheck meanwhile
        if not plan.target or plan.status != "OUTCOME_UNKNOWN":
            raise ActionPlanError("PLAN_NOT_UNKNOWN", f"plan is {plan.status}", http_status=409)
        if not self._approval_valid(plan) or not actor:
            raise ActionPlanError("INDEPENDENT_APPROVAL_REQUIRED", "recheck requires the approved plan", http_status=409)
        session = None
        try:
            try:
                session = opener()
                observed = session.state()
            except Exception as exc:  # noqa: BLE001 -- read-only: the plan stays unknown with the code
                return self._save(plan, actor, recheck_only=True, safe_error_code=code_of(exc))
            if observed in WANTED[plan.action_type]:
                return self._save(plan, actor, status="VERIFIED", verified_at=self.now(), recheck_only=True,
                                  safe_error_code=None)
            return self._save(plan, actor, recheck_only=True, safe_error_code="STATE_" + observed)
        finally:
            if session is not None:
                session.close()

    # --- public shape -----------------------------------------------------------

    def public(self, plan: ActionPlan) -> dict:
        readiness = evaluate_readiness(plan.action_type, plan.operational_review, self.now())
        out = {
            "id": str(plan.id), "credential_id": str(plan.credential_id), "aws_account_id": plan.aws_account_id,
            "account_id": plan.account_id, "user_name": plan.user_name, "principal_arn": plan.principal_arn,
            "identifier_hint": plan.identifier_hint, "action_type": plan.action_type, "status": self._current(plan),
            "requested_by": plan.requested_by, "requested_at": _iso(plan.requested_at) or "",
            "approved_by": plan.approved_by, "approved_at": _iso(plan.approved_at),
            "self_approved": bool(plan.approved_by) and plan.approved_by == plan.requested_by,
            "expires_at": _iso(plan.expires_at) or "", "plan_hash": plan.plan_hash, "reason_code": plan.reason_code,
            "semantics_revision": plan.semantics_revision, "adapter_version": plan.adapter_version,
            "policy_revision": plan.policy_revision, "workflow_version": plan.workflow_version,
            "executed_at": _iso(plan.executed_at), "provider_write_started_at": _iso(plan.provider_write_started_at),
            "verified_at": _iso(plan.verified_at), "safe_error_code": plan.safe_error_code,
            "recheck_only": plan.recheck_only, "operational_review": plan.operational_review, "readiness": readiness,
            "result_kind": plan.result_kind, "next_step": plan.next_step,
            "owner_approval": owner_approval.current(self.repo, plan.id, self.now()),
            "owner_emergency": owner_approval.emergency_view(self.repo, plan),
        }
        # An Admin may contain a publicly exposed key at once while its owner has not approved yet.
        if (plan.action_type == owner_approval.EMERGENCY_ACTION and out["status"] == "APPROVED"
                and owner_approval.needed(self.repo, plan)):
            out["emergency_eligible"] = owner_approval.publicly_exposed(self.repo, plan.credential_id)
        if plan.action_type in ROTATION_ACTIONS:
            out["rotation"] = plan.rotation
            out["rotation_progress"] = list(plan.rotation_progress or [])
        if plan.target:
            # Identifiers only (cremore.remediation.provider_actions): which credential, where, acted on through which
            # remediation connection.
            out["target"] = {"kind": "provider_credential", **plan.target}
        return {k: v for k, v in out.items() if v is not None}
