"""Versioned, allowlisted snapshots for outbound security monitoring.

Creation records the initial observation, before later review or verification.
Only known catalog codes and internal UUIDs cross this boundary; source text,
credential material, location labels and arbitrary metadata never do.
"""
from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from functools import lru_cache
from typing import get_args

from cremore.domain.models import (
    ACTION_PLAN_STATUSES,
    CONTENT_SCAN_KINDS,
    OWNERSHIP_REVIEW_STATUSES,
    CredentialStatus,
    Severity,
    WorkflowStatus,
)

# Operational events say "go look at the current state"; they carry no names,
# paths, provider text or secrets, only internal UUIDs and known codes.
OPERATIONAL_EVENT_TYPES = (
    "connection.auth_expiring", "connection.auth_failed", "connection.auth_recovered",
    "collection.failed", "collection.stale", "collection.recovered",
)
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,95}")
_HEALTH_ENUMS = {
    "kind": ("CONTENT", "METADATA", "VAULT", "AWS_ACCOUNT", "AWS_INVENTORY"),
    "auth_state": ("READY", "EXPIRING", "REAUTH_REQUIRED", "PERMISSION_LIMITED",
                   "SECRET_UNAVAILABLE", "DISABLED", "UNKNOWN"),
    "auth_renewal": ("AUTO", "MANUAL", "HUMAN_SESSION", "EXTERNAL", "UNKNOWN"),
    "expiry_stage": ("NONE", "D14", "D3", "EXPIRED"),
    "freshness": ("FRESH", "STALE", "NEVER_COLLECTED", "NOT_SCHEDULED"),
    "last_status": ("COMPLETE", "PARTIAL", "FAILED", "NOT_COLLECTED"),
}


@lru_cache(maxsize=1)
def _providers():
    from cremore.coverage.metadata_models import MetadataConnectionSpec
    from cremore.coverage.models import ConnectionSpec
    from cremore.sources.registry import BY_SOURCE
    names = set(BY_SOURCE) | {"aws"}
    for model in (ConnectionSpec, MetadataConnectionSpec):
        names.update(get_args(model.model_fields["provider"].annotation))
    return frozenset(names)


@lru_cache(maxsize=1)
def _catalog_codes():
    # Reuse the catalog's metadata without running detection or verification.
    from cremore.detection.catalog import builtin_definitions
    return frozenset((item.catalog.provider, item.catalog.credential_type) for item in builtin_definitions())


def _uuid(value, *, optional=False):
    if value is None and optional:
        return None
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("SIEM_INVALID_ID") from None


def _enum(value, enum):
    return value if value in {item.value for item in enum} else "UNKNOWN"


def _code(value):
    return value if isinstance(value, str) and _CODE.fullmatch(value) else None


def _stamp(value) -> str | None:
    if value is None:
        return None
    value = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return value.isoformat().replace("+00:00", "Z")


def operational_event(event_type: str, item: dict, *, previous: dict | None, sequence: int, now,
                      recovered_from: str | None = None) -> dict:
    """Project one connection-health transition from the health view's allowlisted fields."""
    if event_type not in OPERATIONAL_EVENT_TYPES:
        raise ValueError("SIEM_UNKNOWN_EVENT_TYPE")

    def enum(field, value):
        return value if value in _HEALTH_ENUMS[field] else "UNKNOWN"

    def when(value):
        try:
            return _stamp(datetime.fromisoformat(value)) if isinstance(value, str) else None
        except ValueError:
            return None

    connection_id = _uuid(item["id"])
    marker = f"{event_type}:{item['kind']}:{connection_id}:{sequence}:{recovered_from or ''}"
    return {
        "schema_version": 1,
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, "cremore:" + marker)),
        "event_type": event_type,
        "occurred_at": _stamp(now),
        "product": "CreMore",
        "connection": {
            "id": connection_id,
            "kind": enum("kind", item["kind"]),
            "provider": item["provider"] if item["provider"] in _providers() else "UNKNOWN",
        },
        "health": {
            "auth_state": enum("auth_state", item["auth_state"]),
            "previous_auth_state": enum("auth_state", previous["auth_state"]) if previous else None,
            "reason": _code(item["auth_reason"]),
            "auth_renewal": enum("auth_renewal", item["auth_renewal"]),
            "expiry_stage": enum("expiry_stage", item["expiry_stage"]),
            "expires_at": when(item["expires_at"]),
            "freshness": enum("freshness", item["freshness"]),
            "last_status": enum("last_status", item["last_status"]),
            "last_success_at": when(item["last_success_at"]),
            "last_failure_code": _code(item["last_failure_code"]),
            "recovered_from": recovered_from if recovered_from in ("FAILED", "STALE", None) else None,
        },
    }


DELIVERY_EVENT_TYPES = ("siem.delivery_backlog", "siem.delivery_recovered")
_DESTINATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")


def delivery_state(event_type: str, row: dict, *, sequence: int, now) -> dict:
    """A destination fell behind or caught up; every other destination hears about it."""
    if event_type not in DELIVERY_EVENT_TYPES:
        raise ValueError("SIEM_UNKNOWN_EVENT_TYPE")
    destination = row["destination"] if _DESTINATION.fullmatch(str(row["destination"])) else "UNKNOWN"
    oldest = row.get("oldest_pending_at")
    waited = int((now - datetime.fromisoformat(oldest)).total_seconds()) if oldest else None
    return {
        "schema_version": 1,
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cremore:{event_type}:{destination}:{sequence}")),
        "event_type": event_type,
        "occurred_at": _stamp(now),
        "product": "CreMore",
        "delivery": {
            "destination": destination,
            "pending": _count(row.get("pending")),
            "held": _count(row.get("held")),
            "oldest_pending_seconds": _count(max(waited, 0)) if waited is not None else None,
            "consecutive_failures": _count(row.get("consecutive_failures")),
            "last_error_code": _code(row.get("last_error_code")),
        },
    }


def siem_test(*, now, nonce) -> dict:
    """An Admin-requested event that proves each destination receives CreMore's events."""
    nonce = _uuid(nonce)
    return {
        "schema_version": 1,
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, "cremore:siem.test:" + nonce)),
        "event_type": "siem.test",
        "occurred_at": _stamp(now),
        "product": "CreMore",
        "test": {"nonce": nonce},
    }


def _count(value, maximum=2**31 - 1):
    return value if type(value) is int and 0 <= value <= maximum else None


def platform_heartbeat(*, now, slot: int, interval_seconds: int, workers_alive: int, queued_jobs: int,
                       oldest_queued_seconds: int | None) -> dict:
    """One liveness beat per interval; a SIEM alerts on its absence, not on its content."""
    return {
        "schema_version": 1,
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cremore:platform.heartbeat:{interval_seconds}:{slot}")),
        "event_type": "platform.heartbeat",
        "occurred_at": _stamp(now),
        "product": "CreMore",
        "platform": {
            "interval_seconds": _count(interval_seconds, 86400),
            "workers_alive": _count(workers_alive),
            "queued_jobs": _count(queued_jobs),
            "oldest_queued_seconds": _count(oldest_queued_seconds),
        },
    }


AUDIT_CHAIN_STATES = ("INTACT", "BROKEN", "UNAUTHENTICATED", "ANCHOR_MISMATCH", "UNKNOWN")
AUDIT_CHAIN_PROBLEMS = ("SEQUENCE_GAP", "SEQUENCE_INVALID", "MAC_MISMATCH", "GENESIS_MISSING", "GENESIS_INVALID",
                        "GENESIS_MOVED", "CHAIN_RESET", "KEY_MISMATCH", "ANCHOR_CLAIM_MISMATCH", "ANCHOR_SEQUENCE_GAP",
                        "CHAIN_REWOUND", "UNAUTHENTICATED")
_MAC = re.compile(r"[0-9a-f]{64}")


def _chain_mac(value):
    return value if isinstance(value, str) and _MAC.fullmatch(value) else None


def audit_chain_anchor(*, now, slot: int, report: dict, number: int | None = None) -> dict:
    """The audit trail's chain head, its start and the result of verifying it, once an hour.

    A SIEM alerts on a state other than INTACT, a start (genesis) that changes, an anchor number that is not
    one more than the last, and a head sequence that goes down: each means the trail was rewritten.
    """
    head = report.get("head") or {}
    genesis = report.get("genesis") or {}
    first = next((item for item in report.get("problems") or [] if not item.get("acknowledged")), {})
    unauthenticated = report.get("unauthenticated") or {}
    return {
        "schema_version": 1,
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cremore:audit.chain_anchor:{slot}")),
        "event_type": "audit.chain_anchor",
        "occurred_at": _stamp(now),
        "product": "CreMore",
        "audit": {
            "chain_state": report.get("state") if report.get("state") in AUDIT_CHAIN_STATES else "UNKNOWN",
            "chain_seq": _count(head.get("seq")),
            "chain_mac": _chain_mac(head.get("mac")),
            "genesis_seq": _count(genesis.get("seq")),
            "genesis_mac": _chain_mac(genesis.get("mac")),
            "anchor_no": _count(number),
            "open_problems": _count(report.get("open_problems")),
            "problem_seq": _count(first.get("seq")),
            "problem_reason": first.get("kind") if first.get("kind") in AUDIT_CHAIN_PROBLEMS else None,
            "unauthenticated": _count((unauthenticated.get("sealed_count") or 0) + (unauthenticated.get("pending_count") or 0)),
            "pending": _count(report.get("pending")),
        },
    }


def stamped(event: dict, installation_id) -> dict:
    """The same event with the installation it came from.

    A random per-installation UUID lets one SIEM hold several installations;
    the writer adds it when it records the event, so the exporter needs no
    access to installation settings.
    """
    return {**event, "installation_id": _uuid(installation_id)}


def _finding_codes(credential):
    provider = getattr(credential, "provider", None)
    credential_type = getattr(credential, "credential_type", None)
    if provider == "custom":
        return provider, "CUSTOM"
    if (provider, credential_type) not in _catalog_codes():
        return "UNKNOWN", "UNKNOWN"
    return provider, credential_type


FINDING_CHANGES = ("WORKFLOW", "VERIFICATION", "ROLLUP")


def finding_updated(finding, credential, *, change: str, previous_workflow_status=None, previous_severity=None,
                    previous_credential_status=None, marker) -> dict:
    """A finding's state changed: triage, a verification result, or a scan's rollup.

    ``marker`` names the change (the time it was written), so a replayed write
    yields the same ``event_id`` and a new change a new one.
    """
    if change not in FINDING_CHANGES:
        raise ValueError("SIEM_UNKNOWN_FINDING_CHANGE")
    finding_id = _uuid(finding.id)
    stamp = finding.updated_at if change != "VERIFICATION" else getattr(credential, "updated_at", None)
    if stamp is None:
        raise ValueError("SIEM_MISSING_EVENT_TIME")
    provider, credential_type = _finding_codes(credential)

    def status(value):
        return _enum(value, CredentialStatus) if value is not None else None

    return {
        "schema_version": 1,
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cremore:finding.updated:{finding_id}:{change}:{marker}")),
        "event_type": "finding.updated",
        "occurred_at": _stamp(stamp),
        "product": "CreMore",
        "change": change,
        "finding": {
            "id": finding_id,
            "credential_id": _uuid(finding.credential_id),
            "severity": _enum(finding.severity, Severity),
            "previous_severity": _enum(previous_severity, Severity) if previous_severity is not None else None,
            "workflow_status": _enum(finding.workflow_status, WorkflowStatus),
            "previous_workflow_status": (_enum(previous_workflow_status, WorkflowStatus)
                                         if previous_workflow_status is not None else None),
        },
        "credential": {
            "provider": provider,
            "credential_type": credential_type,
            "status": status(getattr(credential, "credential_status", None)) or "UNKNOWN",
            "previous_status": status(previous_credential_status),
        },
    }


def finding_forwarded(finding, credential, *, now, request_id) -> dict:
    """An analyst sent a finding as it stands to the SIEM and webhook destinations (the console's "send webhook
    event"). No notes or names: who sent it is on the audit.action event that goes with it. ``request_id`` names
    the request (the API makes one per person, finding and minute, so a repeated click is the same event)."""
    finding_id = _uuid(finding.id)
    provider, credential_type = _finding_codes(credential)
    status = _enum(finding.workflow_status, WorkflowStatus)
    credential_status = getattr(credential, "credential_status", None)
    return {
        "schema_version": 1,
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cremore:finding.forwarded:{finding_id}:{_uuid(request_id)}")),
        "event_type": "finding.forwarded",
        "occurred_at": _stamp(now),
        "product": "CreMore",
        "change": "FORWARDED",
        "finding": {
            "id": finding_id,
            "credential_id": _uuid(finding.credential_id),
            "severity": _enum(finding.severity, Severity),
            # Nothing changed: a SIEM that maps closures reads none here.
            "workflow_status": status, "previous_workflow_status": status,
        },
        "credential": {
            "provider": provider,
            "credential_type": credential_type,
            "status": _enum(credential_status, CredentialStatus) if credential_status is not None else "UNKNOWN",
        },
    }


# The audit trail records people's actions; the scanner's own bookkeeping and
# the schedulers that act for nobody are not administrator activity.
_SYSTEM_ACTOR = re.compile(r"(?:scanner|worker|api|aws-inventory|[a-z0-9-]+-schedule|system:[a-z0-9_:-]+)\Z")
_TARGET = re.compile(r"[a-z][a-z0-9_]{0,63}")


def is_system_actor(actor) -> bool:
    return not isinstance(actor, str) or bool(_SYSTEM_ACTOR.fullmatch(actor))


_RESPONSE_ACTIONS = frozenset({
    "RESPONSE_REQUESTED", "RESPONSE_TICKET_OPENED", "RESPONSE_LATE_TICKET_OPENED", "RESPONSE_SEND_UNKNOWN",
    "RESPONSE_TICKET_CHECKED", "RESPONSE_ANSWER_REFUSED", "RESPONSE_CLEANUP_DECLARED", "RESPONSE_DECLINED",
    "RESPONSE_SEND_RELEASED", "RESPONSE_REMOVAL_VERIFIED", "RESPONSE_REAPPEARED", "RESPONSE_STILL_EXPOSED",
    "RESPONSE_REVIEW_STARTED", "RESPONSE_REPORT_RECORDED", "RESPONSE_EVIDENCE_UPDATED", "RESPONSE_COMPLETED",
    # A request sent as a Slack DM or mail with a CreMore link: it went out, or it did not (its link ended).
    "RESPONSE_LINK_SENT", "RESPONSE_NOT_SENT",
    # An Admin's approved Slack channels for response notices (ids and which allow public posts; never the token).
    "RESPONSE_CHANNELS_SAVED",
})
_RESPONSE_STATES = frozenset({"NEW", "ASSIGNED", "SENDING", "SEND_UNKNOWN", "NOT_SENT", "WAITING_OWNER",
                              "WAITING_VERIFICATION", "NEEDS_ACTION", "REMOVED", "REVIEWING", "REPORT_REQUIRED", "COMPLETED"})


def export_audit(event) -> bool:
    """Include scan-verified response transitions, without exporting all scanner bookkeeping."""
    return not is_system_actor(event.actor) or event.event_type in _RESPONSE_ACTIONS


def audit_action(event) -> dict:
    """One administrator action from the audit trail, without notes or who by name.

    The actor becomes a stable reference derived from the subject, so a SIEM
    can group one person's actions while the name, e-mail or IdP subject stays
    in CreMore's own audit log.
    """
    audit_id = _uuid(event.id)
    stamp = event.created_at
    if stamp is None:
        raise ValueError("SIEM_MISSING_EVENT_TIME")

    def workflow(value):
        if not value:
            return None
        # A key action plan's statuses and an ownership review's are fixed codes too; anything else stays UNKNOWN.
        if event.target_type == "action_plan" and value in ACTION_PLAN_STATUSES:
            return value
        if event.event_type == "OWNERSHIP_REVIEW_UPDATED" and value in OWNERSHIP_REVIEW_STATUSES:
            return value
        if event.event_type in _RESPONSE_ACTIONS:
            return value if value in _RESPONSE_STATES else "UNKNOWN"
        return _enum(value, WorkflowStatus)

    return {
        "schema_version": 1,
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, "cremore:audit.action:" + audit_id)),
        "event_type": "audit.action",
        "occurred_at": _stamp(stamp),
        "product": "CreMore",
        "audit": {
            "id": audit_id,
            "action": _code(event.event_type) or "UNKNOWN",
            "target_type": event.target_type if isinstance(event.target_type, str) and _TARGET.fullmatch(event.target_type) else "unknown",
            "target_id": _uuid(event.target_id, optional=True) if event.target_id is not None else None,
            "finding_id": _uuid(event.finding_id, optional=True),
            "actor_ref": str(uuid.uuid5(uuid.NAMESPACE_URL, "cremore:actor:" + str(event.actor))),
            "from_status": workflow(event.from_status),
            "to_status": workflow(event.to_status),
        },
    }


COVERAGE_STATES = ("MATCHED", "NO_VAULT_MATCH", "UNKNOWN", "IDENTIFIER_ONLY", "IDENTIFIER_NOT_OBSERVED",
                   "PUBLIC_CERTIFICATE_MATCH", "PUBLIC_CERTIFICATE_NOT_OBSERVED")
_BASES = ("API_LISTING", "READER_REPORTED", "OPERATOR_DECLARED")
_MATCH_BASES = ("VALUE_FINGERPRINT", "SESSION_FINGERPRINT", "KEY_PAIR_FINGERPRINT", "IDENTIFIER", "PROVIDER_DIGEST",
                "PUBLIC_CERTIFICATE", "NONE")


def coverage_verdict_changed(*, key: str, sequence: int, row: dict, previous_state: str | None, now,
                             absence_basis) -> dict:
    """An exposed or issued credential's vault verdict changed.

    The row is identified by internal UUIDs only; an issued key without one is
    named by a reference derived from its comparison key, never the key ID.
    """
    state = row.get("state") if row.get("state") in COVERAGE_STATES else "UNKNOWN"
    reference = str(uuid.uuid5(uuid.NAMESPACE_URL, "cremore:coverage:" + key))
    return {
        "schema_version": 1,
        # The key's own change counter: a replay after a crash repeats this id.
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cremore:coverage.verdict_changed:{reference}:{int(sequence)}")),
        "event_type": "coverage.verdict_changed",
        "occurred_at": _stamp(now),
        "product": "CreMore",
        "verdict": {
            "ref": reference,
            "origin": row.get("origin") if row.get("origin") in ("EXPOSURE", "ISSUANCE") else "UNKNOWN",
            "credential_id": _uuid(row.get("credential_id"), optional=True),
            "finding_id": _uuid(row.get("finding_id"), optional=True),
            "entity_id": _uuid(row.get("entity_id"), optional=True),
            "credential_type": _code(row.get("credential_type")) or "UNKNOWN",
            "state": state,
            "previous_state": previous_state if previous_state in COVERAGE_STATES else None,
            "match_basis": row.get("match_basis") if row.get("match_basis") in _MATCH_BASES else None,
            "absence_basis": absence_basis if absence_basis in _BASES and state in (
                "NO_VAULT_MATCH", "IDENTIFIER_NOT_OBSERVED") else None,
        },
    }


ORPHAN_VERDICTS = ("USED_AFTER_DEPARTURE", "ACTIVE", "REVOKED_OR_EXPIRED", "UNKNOWN")
_LINK_BASES = ("SCIM_EXTERNAL_ID", "SAML_NAME_ID", "EXTERNAL_UID", "IDP_OBJECT_ID", "VERIFIED_EMAIL", "OPERATOR_CONFIRMED")
_DEPARTURE_BASES = ("PROVIDER_REPORTED", "ADMIN_EVENT", "FIRST_OBSERVED_DISABLED", "FIRST_OBSERVED_MISSING")
_VAULT_STATES = COVERAGE_STATES


def identity_credential_orphaned(*, orphan_ref, sequence: int, verdict: str, previous_verdict, credential_ref,
                                 person_ref, provider: str, credential_type, departed_at, departure_basis,
                                 link_basis, last_used_at, exposed, vault_state, now) -> dict:
    """A departed person's credential got a verdict, or a new one.

    People, accounts and credentials are named by internal references only: no
    email, login, IdP user id or key id crosses this boundary.
    """
    verdict = verdict if verdict in ORPHAN_VERDICTS else "UNKNOWN"
    reference = _uuid(orphan_ref)
    return {
        "schema_version": 1,
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"cremore:identity.credential_orphaned:{reference}:{int(sequence)}")),
        "event_type": "identity.credential_orphaned",
        "occurred_at": _stamp(now),
        "product": "CreMore",
        "orphan": {
            "ref": reference,
            "verdict": verdict,
            "previous_verdict": previous_verdict if previous_verdict in ORPHAN_VERDICTS else None,
            "credential_ref": _uuid(credential_ref, optional=True),
            "person_ref": _uuid(person_ref),
            "provider": _code(str(provider or "").upper()) or "UNKNOWN",
            "credential_type": _code(credential_type) or "UNKNOWN",
            "departed_at": _stamp(departed_at),
            "departure_basis": departure_basis if departure_basis in _DEPARTURE_BASES else None,
            "link_basis": link_basis if link_basis in _LINK_BASES else None,
            "last_used_at": _stamp(last_used_at),
            "exposed": exposed if isinstance(exposed, bool) else None,
            "vault_state": vault_state if vault_state in _VAULT_STATES else None,
        },
    }


def finding_created(finding, credential, exposure) -> dict:
    """Project one newly persisted finding; tolerate legacy missing relations."""
    finding_id = _uuid(finding.id)
    stamp = finding.created_at
    if stamp is None:
        raise ValueError("SIEM_MISSING_EVENT_TIME")
    stamp = stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp.astimezone(UTC)
    provider, credential_type = _finding_codes(credential)
    source_type = getattr(exposure, "source_type", None)
    line = getattr(exposure, "line_number", None)
    return {
        "schema_version": 1,
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, "cremore:finding.created:" + finding_id)),
        "event_type": "finding.created",
        "occurred_at": stamp.isoformat().replace("+00:00", "Z"),
        "product": "CreMore",
        "finding": {
            "id": finding_id,
            "credential_id": _uuid(finding.credential_id),
            "severity": _enum(finding.severity, Severity),
            "workflow_status": _enum(finding.workflow_status, WorkflowStatus),
        },
        "credential": {
            "provider": provider,
            "credential_type": credential_type,
            "status": _enum(getattr(credential, "credential_status", None), CredentialStatus),
        },
        "exposure": {
            "id": _uuid(finding.primary_exposure_id),
            "source_type": source_type if source_type in CONTENT_SCAN_KINDS else "UNKNOWN",
            "source_connection_id": _uuid(getattr(exposure, "source_connection_id", None), optional=True),
            "aws_account_id": _uuid(getattr(exposure, "aws_account_id", None), optional=True),
            "line_number": line if type(line) is int and 0 <= line <= 2**31 - 1 else None,
        },
    }


def finding_exposure(finding, credential, exposure, *, reappeared=False, removed_at=None) -> dict:
    """An existing credential gained a location or returned after confirmed removal.

    Only normalized enums and internal IDs are projected, never page names,
    paths, matched values, source responses or surrounding text.
    """
    event = finding_created(finding, credential, exposure)
    kind = "finding.reappeared" if reappeared else "finding.location_added"
    marker = f"{kind}:{_uuid(exposure.id)}:{_stamp(removed_at) if reappeared else ''}"
    event.update(event_type=kind, event_id=str(uuid.uuid5(uuid.NAMESPACE_URL, "cremore:" + marker)),
                 occurred_at=_stamp(exposure.last_seen_at))
    event["exposure"]["id"] = _uuid(exposure.id)
    # A location just inserted holds the UNKNOWN placeholder until it is scored: the finding's severity stands then.
    if _enum(exposure.severity, Severity) != "UNKNOWN":
        event["finding"]["severity"] = _enum(exposure.severity, Severity)
    return event
