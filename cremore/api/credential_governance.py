"""The dashboard's per-credential governance projection, from saved evidence only.

The console reads verification, ownership and usage from ``governance.metadata``
facts (through ``cremore/api/credential_records.py``). Without this projection every
credential showed "verification evidence unavailable", even when the provider
had confirmed it active during the scan.

Nothing here calls a provider. Each fact names its source and the time it was
observed; a verification outcome is the result at check time, never proof of
current usability.
"""

from __future__ import annotations

import datetime as _dt
import hashlib

from cremore_aws_provider.aws_sessions import account_of_arn

from cremore.governance.usage_sources import owner_usage_snapshot
from cremore.risk.verification import latest_verification, timestamp

_AT_CHECK_TIME = "ACTIVE_VERIFICATION_OUTCOME_AT_CHECK_TIME_NOT_CURRENT_USABILITY"
_SAFE_DETAIL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-")
_PARTIAL_AWS = {"AWS_ACCESS_KEY_ID": "AWS_IDENTIFIER_ONLY", "AWS_SECRET_ACCESS_KEY": "AWS_SECRET_ONLY",
                "AWS_SESSION_TOKEN": "AWS_SESSION_TOKEN_ONLY"}
_LINKED_PAIR = "LINKED_PAIR_ACTIVE_VERIFICATION"
_IAM_OWNER_LOOKUP = "IAM_OWNER_LOOKUP"


def _iso(value) -> str | None:
    if not isinstance(value, _dt.datetime):
        return None
    return (value if value.tzinfo else value.replace(tzinfo=_dt.UTC)).isoformat()


def _fact(key, value, *, source="", availability="AVAILABLE", observed_at=None, reason="", detail="") -> dict:
    return {"key": key, "value": value, "source": source, "source_detail": detail, "confidence": None,
            "confidence_basis": "NOT_SCORED", "observed_at": observed_at, "availability": availability, "reason": reason}


def _safe(code) -> str:
    code = str(code or "")[:64]
    return code if code and set(code) <= _SAFE_DETAIL else ""


def _linked_pair_verification(component) -> dict | None:
    """A complete pair holding this exact component authenticated at check time.

    ``component_evidence`` links a partial observation to complete pairs by keyed
    component equality, so a linked pair contains these exact bytes. Only a
    success carries over: authenticating proves both the pairing and the key. A
    rejection cannot separate a dead component from an adjacency-based pairing
    that was never a real key, so a rejected link stays NOT_VERIFIABLE here.
    """
    positives = [link for link in (component or {}).get("links") or []
                 if link.get("verification_state") in ("verified", "restricted")]
    if not positives:
        return None
    dated = [(at, link) for link in positives if (at := timestamp(link.get("verification_checked_at")))]
    at, link = max(dated, key=lambda row: row[0]) if dated else (None, positives[0])
    return _fact("verification", "VERIFIED_ACTIVE", source=_LINKED_PAIR, observed_at=_iso(at),
                 reason=_AT_CHECK_TIME if at else "ACTIVE_VERIFICATION_CHECK_TIME_NOT_RECORDED",
                 detail="RESTRICTED" if link.get("verification_state") == "restricted" else "")


def verification_fact(exposures, credential=None, *, observation=None, component=None) -> dict:
    """The latest recorded verification outcome across this credential's locations."""
    if reason := _PARTIAL_AWS.get(getattr(credential, "credential_type", "")):
        # An ID or a secret alone cannot be verified, but a complete pair built
        # from this same component may already carry a provider answer.
        return _linked_pair_verification(component) or _fact(
            "verification", "NOT_SUPPORTED", source="DISCOVERY_SOURCE", availability="NOT_VERIFIABLE",
            reason=reason)
    observation = observation or latest_verification(exposures, credential)
    state = observation.state
    if state in ("not_attempted", "disabled"):
        return _fact("verification", "NOT_REQUESTED", availability="UNKNOWN", reason="NOT_REQUESTED")
    observed = _iso(observation.checked_at)
    detail = _safe(observation.metadata.get("verification_error"))
    if state in ("verified", "restricted"):
        return _fact("verification", "VERIFIED_ACTIVE", source="ACTIVE_VERIFICATION", observed_at=observed,
                     reason=observation.reason or _AT_CHECK_TIME, detail="RESTRICTED" if state == "restricted" else "")
    if state == "rejected":
        return _fact("verification", "VERIFIED_INACTIVE", source="ACTIVE_VERIFICATION", observed_at=observed,
                     reason=observation.reason or _AT_CHECK_TIME, detail=detail)
    if state == "expired":
        return _fact("verification", "VERIFIED_EXPIRED", source="ACTIVE_VERIFICATION", observed_at=observed,
                     reason=observation.reason, detail=detail)
    if state == "unsupported":
        return _fact("verification", "NOT_SUPPORTED", source="ACTIVE_VERIFICATION", availability="NOT_SUPPORTED",
                     observed_at=observed, reason=detail or "NOT_SUPPORTED")
    return _fact("verification", "INCONCLUSIVE", source="ACTIVE_VERIFICATION", availability="UNKNOWN",
                 observed_at=observed, reason=observation.reason or "ACTIVE_VERIFICATION_INCONCLUSIVE", detail=detail)


def _owner_facts(cred, verification: dict, observation) -> list[dict]:
    arn = cred.principal_arn
    if not arn:
        ran_here = verification.get("source") == "ACTIVE_VERIFICATION"
        reason = "NOT_RETURNED" if ran_here and verification["value"].startswith("VERIFIED_") else "NOT_COLLECTED"
        return [_fact("provider_owner", None, availability="UNKNOWN", reason=reason)]
    # An owner read from the owning account's IAM is not a provider verification
    # of this credential, and saying so would overstate what was proven.
    if getattr(cred, "principal_arn_source", "") in {_IAM_OWNER_LOOKUP, "IAM_INVENTORY"}:
        source, reason = cred.principal_arn_source, "OWNER_ACCOUNT_IAM_RECORD_NOT_CREDENTIAL_VERIFICATION"
        snapshot = cred.usage_snapshot or {}
        observed = ((snapshot.get("owner_lookup") or {}).get("observed_at") if source == "IAM_INVENTORY"
                    else snapshot.get("collected_at"))
    else:
        source, reason = "ACTIVE_VERIFICATION", _AT_CHECK_TIME
        owner_evidence = next((meta for meta in (observation.metadata, observation.last_confirmed)
                               if meta.get("verification_arn") == arn), {})
        observed = _iso(timestamp(owner_evidence.get("verification_checked_at")))
    kind = "IAM_USER" if ":user/" in arn else "IAM_ROLE_SESSION" if ":assumed-role/" in arn else "ROOT" if arn.endswith(":root") else ""
    facts = [_fact("provider_owner", arn, source=source, observed_at=observed, reason=reason)]
    if kind:
        facts.append(_fact("provider_owner_kind", kind, source=source, observed_at=observed))
    if account := account_of_arn(arn):
        facts.append(_fact("provider_account_id", account, source=source, observed_at=observed))
    return facts


def _usage_facts(cred) -> list[dict]:
    snapshot = owner_usage_snapshot(cred)
    if snapshot is None:
        # A lookup not proven to have run in the owner's account is not usage evidence.
        return [_fact("last_used_at", None, availability="NOT_COLLECTED", reason="NOT_COLLECTED")]
    last = snapshot.get("last_used") or {}
    observed = last.get("observed_at")
    available = last.get("status") == "AVAILABLE" and last.get("at") and observed
    no_information = last.get("status") == "NO_INFORMATION" and observed
    reason = last.get("status") if last.get("status") in {
        "NO_INFORMATION", "DENIED", "FAILED", "NOT_REQUESTED",
    } else "NOT_COLLECTED"
    facts = [_fact("last_used_at", last["at"] if available else None, source="PROVIDER_NATIVE", observed_at=observed,
                   availability="AVAILABLE" if available else "NOT_OBSERVED" if no_information else "NOT_COLLECTED",
                   reason="" if available else reason, detail="IAM_GET_ACCESS_KEY_LAST_USED")]
    if available:
        for key in ("service", "region"):
            if last.get(key):
                facts.append(_fact("last_used_" + key, last[key], source="PROVIDER_NATIVE", observed_at=observed))
    return facts


def _capability(support: str, reason: str) -> dict:
    return {"documented_support": support, "reason": reason}


def _type_capability(cred) -> dict:
    aws_key = (cred.provider or "") == "aws" and cred.credential_type == "AWS_ACCESS_KEY"
    if aws_key:
        caps = {
            "verification": _capability("SUPPORTED", "STS_GET_CALLER_IDENTITY"),
            "expiration": _capability("NOT_SUPPORTED", "NO_PROVIDER_MANAGED_EXPIRATION"),
            "last_used": _capability("CONDITIONAL", "OWNER_ACCOUNT_CONNECTION_REQUIRED"),
            "provider_owner": _capability("SUPPORTED", "STS_GET_CALLER_IDENTITY"),
            "last_actor": _capability("CONDITIONAL", "OWNER_ACCOUNT_CONNECTION_REQUIRED"),
            "disable": _capability("CONDITIONAL", "APPROVED_ACTION_PLAN_AND_REMEDIATION_ROLE_REQUIRED"),
            "revoke": _capability("CONDITIONAL", "APPROVED_ACTION_PLAN_AND_REMEDIATION_ROLE_REQUIRED"),
            "rotation": _capability("CONDITIONAL", "RUNTIME_IDENTITY_ACCOUNT_ONLY"),
            "refresh": _capability("NOT_APPLICABLE", "LONG_LIVED_KEY"),
        }
        if (cred.identifier or cred.identifier_hint or "").startswith("ASIA"):
            caps.update(
                verification=_capability("CONDITIONAL", "AWS_STS_COMPLETE_SESSION_AND_VERIFICATION_ENABLED_REQUIRED"),
                expiration=_capability("CONDITIONAL", "PROVIDER_EXPIRATION_EVIDENCE_REQUIRED"),
                last_used=_capability("CONDITIONAL", "BOUNDED_CLOUDTRAIL_HISTORY"),
                provider_owner=_capability("CONDITIONAL", "SAVED_SESSION_EVIDENCE_REQUIRED"),
                refresh=_capability("NOT_SUPPORTED", "NEW_STS_SESSION_REQUIRED"),
            )
            for name in ("disable", "revoke", "rotation"):
                caps[name] = _capability("NOT_APPLICABLE", "AWS_STS_TEMPORARY_CREDENTIAL")
    else:
        caps = {name: _capability("UNKNOWN", "NOT_DOCUMENTED_HERE") for name in (
            "verification", "expiration", "last_used", "provider_owner", "last_actor", "disable", "revoke",
            "rotation", "refresh")}
        if reason := _PARTIAL_AWS.get(cred.credential_type):
            for name in ("verification", "disable", "revoke", "rotation", "refresh"):
                caps[name] = _capability("NOT_SUPPORTED", reason)
            # A key id is addressable without its secret: the owner account's
            # IAM names it, and disabling or rotating a key takes the id. Only
            # verification still needs the missing half. A secret alone carries
            # no key id, so nothing about it is addressable; nor is a temporary
            # session credential, which is no IAM user's access key.
            if cred.credential_type == "AWS_ACCESS_KEY_ID" and not (
                    cred.identifier or cred.identifier_hint or "").startswith("ASIA"):
                caps.update(last_used=_capability("CONDITIONAL", "OWNER_ACCOUNT_CONNECTION_REQUIRED"),
                            provider_owner=_capability("CONDITIONAL", "OWNER_ACCOUNT_CONNECTION_REQUIRED"))
                for name in ("disable", "revoke", "rotation"):
                    caps[name] = _capability("CONDITIONAL", "APPROVED_ACTION_PLAN_AND_REMEDIATION_ROLE_REQUIRED")
    return {"credential_type": cred.credential_type, "provider": cred.provider or "", "execution_authorized": False,
            "connection_required": aws_key, **{f"supports_{name}": value for name, value in caps.items()}}


def _management(cred, settings) -> dict:
    allowed = getattr(settings, "secret_manager_reference_list", None) if settings is not None else None
    if not allowed:
        return {"status": "NO_MANAGER_CONNECTED", "match_status": "UNKNOWN", "reason": "NO_MANAGER_CONNECTED_TO_THIS_INSTALLATION"}
    if cred.management_reference:
        return {"status": "MANAGED_MATCHED", "match_status": "POSSIBLE_MATCH", "match_basis": "ADMIN_CONFIGURED",
                "reason": "ADMIN_DECLARATION_NOT_EXACT_CREDENTIAL_MATCH"}
    return {"status": "UNKNOWN", "match_status": "UNKNOWN", "reason": "NO_ADMIN_DECLARATION"}


def credential_governance(cred, exposures, settings=None, *, observation=None, component=None) -> dict:
    observation = observation or latest_verification(exposures, cred)
    verification = verification_fact(exposures, cred, observation=observation, component=component)
    business = ([_fact("business_owner", cred.business_owner, source="ADMIN_CONFIGURED")] if cred.business_owner
                else [_fact("business_owner", None, availability="UNKNOWN", reason="BUSINESS_OWNER_NOT_ASSIGNED")])
    metadata = [verification, *_owner_facts(cred, verification, observation), *business, *_usage_facts(cred)]
    if reason := _PARTIAL_AWS.get(cred.credential_type):
        metadata.insert(1, _fact("material_completeness", reason, source="DISCOVERY_SOURCE",
                                 observed_at=_iso(max((at for e in exposures if (at := timestamp(e.last_seen_at))), default=None)),
                                 reason=reason))
    elif cred.provider == "aws" and cred.credential_type == "AWS_ACCESS_KEY" and (cred.identifier or "").startswith("ASIA"):
        current = [e for e in exposures if e.status not in ("REMOVED", "FALSE_POSITIVE")]
        states = {value if (value := e.metadata.get("aws_session_material")) in ("COMPLETE", "UNBOUND", "AMBIGUOUS")
                  else "UNKNOWN" for e in current}
        material = ("AMBIGUOUS" if "AMBIGUOUS" in states else "COMPLETE" if states == {"COMPLETE"}
                    else "UNBOUND" if states == {"UNBOUND"} else "MIXED" if "COMPLETE" in states else "UNKNOWN")
        reason = "AWS_STS_MATERIAL_" + material
        metadata.insert(1, _fact("material_completeness", reason, source="DISCOVERY_SOURCE", reason=reason,
                                 availability="UNKNOWN" if material == "UNKNOWN" else "AVAILABLE",
                                 observed_at=_iso(max((at for e in current if (at := timestamp(e.last_seen_at))), default=None))))
    previous = observation.last_confirmed
    if previous:
        metadata.append(_fact("last_confirmed_verification",
            "VERIFIED_INACTIVE" if previous.get("verification_state") == "rejected" else "VERIFIED_ACTIVE",
            source="ACTIVE_VERIFICATION", observed_at=_iso(timestamp(previous.get("verification_checked_at"))),
            reason=_AT_CHECK_TIME))
    if expiry_at := timestamp(observation.metadata.get("verification_expires_at") or previous.get("verification_expires_at")):
        metadata.append(_fact("expires_at", expiry_at.isoformat(), source="ACTIVE_VERIFICATION",
                              observed_at=_iso(observation.checked_at)))
    aws_key = (cred.provider or "") == "aws" and cred.credential_type == "AWS_ACCESS_KEY"
    revision = hashlib.sha256(repr((str(cred.id), str(cred.updated_at), verification["value"],
                                    verification["observed_at"])).encode()).hexdigest()[:16]
    return {
        "revision": revision,
        "credential_id": str(cred.id),
        "credential_type": cred.credential_type,
        "classification_status": "DETECTED",
        "classification_basis": "DETECTOR_RULE",
        "provider": cred.provider or "",
        "metadata": metadata,
        "management": _management(cred, settings),
        "type_capability": _type_capability(cred),
        "panel_hints": ["PROVIDER_IDENTITY", "USAGE", *(["AWS_ACTIVITY"] if aws_key else [])],
        "discovery_coverage": "SUPPLIED_EXPOSURES_ONLY",
        "limitations": [_AT_CHECK_TIME, "OBSERVATION_IS_NOT_COMPLETE_PROVIDER_COVERAGE"],
    }
