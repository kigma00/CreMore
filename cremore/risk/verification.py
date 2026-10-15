"""Dated, saved verification shared by badges and risk; never a provider call."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

from cremore.risk import model as risk

RISK_STATUS = {
    "verified": risk.VALID, "restricted": risk.RESTRICTED, "rejected": risk.INVALID,
    "expired": risk.EXPIRED, "indeterminate": risk.UNKNOWN,
    "not_attempted": risk.NOT_ATTEMPTED, "disabled": risk.NOT_ATTEMPTED,
    "unsupported": risk.NOT_ATTEMPTED,
}


def timestamp(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@dataclass(frozen=True)
class Observation:
    state: str = "not_attempted"
    checked_at: datetime | None = None
    reason: str = ""
    metadata: dict = field(default_factory=dict)
    last_confirmed: dict = field(default_factory=dict)

    @property
    def risk_status(self):
        if self.state in {"indeterminate", "unsupported"} and self.reason != "ACTIVE_VERIFICATION_TIME_ORDER_UNKNOWN":
            prior = self.last_confirmed.get("verification_state")
            if prior in {"verified", "restricted"}:
                return risk.HISTORICAL_VALID if prior == "verified" else risk.HISTORICAL_RESTRICTED
        return RISK_STATUS.get(self.state, risk.UNKNOWN)

    def apply(self, facts, *, credential=None):
        """Keep permission evidence with the check that produced it."""
        meta = self.last_confirmed if self.risk_status in {risk.HISTORICAL_VALID, risk.HISTORICAL_RESTRICTED} else self.metadata
        verification = facts.verification
        try:
            saved = risk.facts_from_snapshot(meta["risk_facts"])
            if saved.provider == facts.provider and saved.credential_type == facts.credential_type:
                verification = saved.verification
        except (KeyError, TypeError, ValueError, AttributeError):
            pass  # Old observations may have only individual, safe provider facts.
        if scopes := meta.get("verification_scopes"):
            verification = replace(verification, scopes=tuple(s.strip() for s in str(scopes).split(",") if s.strip()))
        if credential is not None and facts.provider == credential.provider == "aws":
            from cremore_aws_provider.investigation.permission_evidence import (
                permission_snapshot,
                saved_risk_signal,
            )

            snapshot = credential.usage_snapshot or {}
            potential = permission_snapshot(snapshot, credential.principal_arn).get("potential_access") or {}
            evaluated = timestamp(potential.get("evaluated_at"))
            # Usage lookup is independent of authentication. A newer failed/partial
            # simulation cannot keep presenting an older successful one as current.
            if evaluated and (self.checked_at is None or evaluated >= self.checked_at):
                verification = replace(verification, aws_privilege=saved_risk_signal(
                    potential, snapshot["collected_account_id"]))
        return replace(facts, verification=replace(verification, status=self.risk_status))


def latest_verification(exposures, credential=None, *, now=None) -> Observation:
    now = timestamp(now) or datetime.now(UTC)
    candidates = []
    confirmed = []
    for exposure in exposures:
        meta = exposure.metadata or {}
        snapshot = meta.get("risk_facts") or {}
        stored = snapshot.get("verification", {}) if isinstance(snapshot, dict) else {}
        status = stored.get("status") if isinstance(stored, dict) else None
        state = meta.get("verification_state") or {
            risk.VALID: "verified", risk.RESTRICTED: "restricted", risk.INVALID: "rejected",
            risk.UNKNOWN: "indeterminate", risk.EXPIRED: "expired",
        }.get(status, "not_attempted")
        if state in ("not_attempted", "disabled"):
            continue
        at = timestamp(meta.get("verification_checked_at"))
        order_at = at or timestamp(exposure.last_seen_at)
        observation = Observation(state, at, metadata=meta)
        # Older native checks sent only two components for ASIA credentials, so
        # their rejection is not revocation evidence. A COMPLETE bound triple is a
        # real GetCallerIdentity probe (id + secret + session token), so its
        # rejection stands; only the unbound two-component case is demoted.
        native_sts = (str(getattr(credential, "identifier", "") or getattr(credential, "identifier_hint", "")).startswith("ASIA")
                      and (meta.get("catalog_id") == "aws-access-key-pair-v1"
                           or meta.get("detector_name") == "CreMoreNativeAWSAccessKey"))
        if (native_sts and meta.get("aws_session_material") != "COMPLETE" and state == "rejected"
                and meta.get("verification_error") in {"InvalidClientTokenId", "AuthFailure"}):
            observation = replace(observation, state="indeterminate", reason="AWS_STS_SESSION_TOKEN_NOT_BOUND")
        if ("verification_checked_at" in meta and at is None) or (at is not None and at > now):
            observation = replace(observation, state="indeterminate", checked_at=None,
                                  reason="ACTIVE_VERIFICATION_TIME_ORDER_UNKNOWN")
        elif at is None:
            observation = replace(observation, reason="ACTIVE_VERIFICATION_CHECK_TIME_NOT_RECORDED")
        prior = meta.get("verification_last_confirmed")
        if isinstance(prior, dict) and not (native_sts and prior.get("verification_state") == "rejected"
                                           and prior.get("verification_error") in {"InvalidClientTokenId", "AuthFailure"}):
            confirmed.append((timestamp(prior.get("verification_checked_at")) or order_at, prior))
        if observation.state in {"verified", "restricted", "rejected"}:
            confirmed.append((order_at, meta))
        candidates.append((order_at, observation))
    if not candidates:
        return Observation()
    if any(at is None for at, _ in candidates):
        return Observation("indeterminate", reason="ACTIVE_VERIFICATION_TIME_ORDER_UNKNOWN")
    latest_at = max(at for at, _ in candidates)
    latest = [value for at, value in candidates if at == latest_at]
    if len({(value.state, value.reason) for value in latest}) != 1:
        return Observation("indeterminate", latest_at, "ACTIVE_VERIFICATION_SAME_TIME_CONFLICT")
    observation = latest[0]
    if confirmed:
        observation = replace(observation, last_confirmed=max(confirmed, key=lambda item: item[0] or datetime.min.replace(tzinfo=UTC))[1])
    if observation.state in {"indeterminate", "unsupported"}:
        expiry = timestamp(observation.last_confirmed.get("verification_expires_at"))
        if expiry is not None and expiry <= now:
            return replace(observation, state="expired", reason="RECORDED_PROVIDER_EXPIRATION_ELAPSED")
    if observation.state in ("verified", "restricted"):
        expirations = [timestamp(value.metadata.get("verification_expires_at")) for value in latest]
        expiry = min((at for at in expirations if at is not None), default=None)
        if expiry is not None and expiry <= now:
            return replace(observation, state="expired", reason="RECORDED_PROVIDER_EXPIRATION_ELAPSED")
        if str(getattr(credential, "credential_status", "")).upper() in {"INACTIVE", "REVOKED", "EXPIRED"}:
            return replace(observation, state="indeterminate",
                           reason="ACTIVE_VERIFICATION_TERMINAL_RECORD_CONFLICT")
    return observation
