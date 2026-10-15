"""Finding and ownership-review response projections shared across API endpoints."""

from __future__ import annotations

from cremore.api.credential_governance import credential_governance
from cremore.api.http_support import (
    isoformat,
)
from cremore.domain.models import OWNERSHIP_REVIEW_STATUSES

REVIEW_STATUSES = OWNERSHIP_REVIEW_STATUSES


REVIEW_REASONS = ("RESPONSIBLE_TEAM_CONFIRMED", "CREDENTIAL_RETIRED", "NOT_ACTIONABLE")


def present_finding(finding, cred, exposures, owner_review=None, settings=None, *, verification=None,
                       component=None) -> dict:
    """Map a Python finding onto the richer shape the dashboard's list expects.

    Every nested governance/metadata object is optional in the web contract, so
    they are omitted; the flat fields are filled from the credential and its
    most-recent exposure. The ownership review is attached when one exists.
    """

    from cremore.api.finding_evidence import _risk, merged_locations, removal_pending
    from cremore.db.scan_state import SEVERITY_RANK
    from cremore.risk.verification import latest_verification

    # Overlapping connections that found the same place count as one location.
    locations = merged_locations(exposures)
    current = [(e, rows) for e, rows in locations if getattr(e, "status", "OPEN") != "REMOVED"]
    exps = [e for e, _ in current]
    primary = next((e for e, rows in current if any(r.id == finding.primary_exposure_id for r in rows)),
                   exps[0] if exps else None)
    # Expiry and later checks apply to the credential at every saved location.
    # The list and detail use the same projection even before background rescore.
    verification = verification or latest_verification(exposures, cred)
    levels = {e.id: _risk(e, cred, occurrences=len(current), verification=verification)["effective_severity"]
              for e in exps}
    if exps:
        primary = min(exps, key=lambda e: (-SEVERITY_RANK.get(levels[e.id], -1), e.id != primary.id, str(e.id)))
    provider = (cred.provider if cred else None) or ""
    first = min((r.first_seen_at for _, rows in current for r in rows if r.first_seen_at), default=None)
    last = max((e.last_seen_at for e in exps if e.last_seen_at), default=None)
    return {
        "id": str(finding.id),
        "severity": levels[primary.id] if primary else finding.severity,
        "primary_exposure_id": str(primary.id if primary else finding.primary_exposure_id),
        "workflow_status": finding.workflow_status,
        "all_locations_removed": finding.all_locations_removed,
        "assigned_to": getattr(finding, "assigned_to", None),
        "credential_id": str(finding.credential_id),
        "credential_type": cred.credential_type if cred else "UNKNOWN",
        "provider": provider or None,
        "providers": [provider] if provider else [],
        "identifier_hint": (cred.identifier_hint if cred else None) or None,
        "credential_status": (cred.credential_status if cred else "UNKNOWN"),
        "principal_name": (cred.principal_name if cred else None),
        # The identity the provider returned when the key was verified (e.g. its IAM user ARN).
        "principal": (cred.principal_name or cred.principal_arn) if cred else None,
        "business_owner": (cred.business_owner if cred else None),
        "team": (cred.team if cred else None),
        "last_used_at": isoformat(getattr(cred, "last_used_at", None)) if cred else None,
        "scope_id": str(primary.source_connection_id) if primary and primary.source_connection_id else "",
        "scope_name": primary.resource_name if primary else "",
        "scope_type": primary.source_type if primary else "",
        "source_connection_id": str(primary.source_connection_id) if primary and primary.source_connection_id else None,
        "source_type": primary.source_type if primary else "",
        "resource_name": primary.resource_name if primary else "",
        "location": primary.location if primary else "",
        "exposure_count": len(exps),
        "removal_pending_location_count": sum(removal_pending(e, rows) for e, rows in locations),
        "first_seen_at": isoformat(first) or isoformat(getattr(finding, "created_at", None)) or "",
        "last_seen_at": isoformat(last) or isoformat(getattr(finding, "updated_at", None)) or "",
        **({"owner_review": present_owner_review(owner_review)} if owner_review is not None else {}),
        **({"governance": credential_governance(cred, exposures, settings, observation=verification,
                                                component=component)} if cred else {}),
    }


def present_owner_review(r) -> dict:
    return {
        "status": r.status,
        "assigned_team": r.assigned_team or None,
        "due_at": isoformat(r.due_at),
        "closed_reason": r.closed_reason or "",
        "revision": r.revision,
        "updated_at": isoformat(r.updated_at),
    }


def default_owner_review() -> dict:
    return {"status": "OPEN", "revision": 0}


def detail_credential(cred) -> dict:
    """The dashboard's FindingDetail.credential: the stored credential fields
    plus the contract's names (``type``, ``status``, ``principal``…)."""

    hint = cred.identifier_hint or ""
    klass = (
        "TEMPORARY_STS"
        if hint.startswith("ASIA")
        else "LONG_LIVED"
        if hint.startswith("AKIA")
        else "UNKNOWN"
    )
    out = cred.model_dump(mode="json", exclude={"identifier", "fingerprint"})
    out.update(
        {
            "id": str(cred.id),
            "type": cred.credential_type,
            "credential_class": klass,
            "provider": cred.provider or "",
            "observed_providers": [cred.provider] if cred.provider else [],
            "identifier_hint": hint or None,
            "secret_stored": False,
            "status": cred.credential_status,
            "principal": cred.principal_name or cred.principal_arn or None,
            "capabilities": {"disable": False, "delete": False},
        }
    )
    return out


def finding_summary(finding, cred) -> dict:
    return {
        "id": str(finding.id),
        "severity": finding.severity,
        "workflow_status": finding.workflow_status,
        "all_locations_removed": finding.all_locations_removed,
        "assigned_to": finding.assigned_to,
        "credential_id": str(finding.credential_id),
        "provider": cred.provider if cred else None,
        "credential_type": cred.credential_type if cred else None,
        "identifier_hint": cred.identifier_hint if cred else None,
        "credential_status": cred.credential_status if cred else None,
    }
