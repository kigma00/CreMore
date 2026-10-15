"""Internal response tickets and playbooks.

A ticket records who is responsible for a finding, what the reviewer has
attested to (a fixed checklist), and when the review is due. It is operator
declaration only: nothing here revokes a token, cleans a source or proves a
workload adopted a new credential — the dashboard says so on every record.

Templates are fixed checklists. A ``CUSTOM`` ticket freezes its playbook at
creation: the operator picks up to 12 steps, optional applicability conditions
that must all match the saved finding and the declared priority/impact at that
moment, and an approval rule. ``INDEPENDENT_ADMIN`` requires an Admin other
than the creator and last editor to approve the exact reviewed content
(``review_digest``) before the ticket can be resolved; any later edit
invalidates that approval.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
import uuid

from cremore.domain.models import WorkflowTicket
from cremore.domain.text import unsafe_text

STATUSES = ("OPEN", "IN_PROGRESS", "WAITING_OWNER", "WAITING_APPROVAL", "NEEDS_ATTENTION", "RESOLVED")
PRIORITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
IMPACTS = ("UNKNOWN", "NONE", "LIMITED", "SIGNIFICANT")
STEP_STATUSES = ("TODO", "REVIEWED", "NOT_APPLICABLE")
STEPS = (
    "CONFIRM_OWNER_AND_TARGET", "REVIEW_CONTAINMENT", "REVIEW_PROVIDER_ACTION", "REVIEW_SOURCE_AND_HISTORY_CLEANUP",
    "INVESTIGATE_IMPACT", "REVIEW_REVALIDATION", "REVIEW_SHARING_SCOPE", "ASSIGN_RESPONSIBILITY",
    "REVIEW_SERVICE_AUTH_MIGRATION", "REVIEW_CONSUMER_ADOPTION", "REVIEW_SUPPORTED_RESTRICTIONS", "SET_FOLLOW_UP",
    "REVIEW_APPROVAL",
)
PLAYBOOK_STEPS: dict[str, tuple[str, ...]] = {
    "PUBLIC_EXPOSURE": ("CONFIRM_OWNER_AND_TARGET", "REVIEW_CONTAINMENT", "REVIEW_PROVIDER_ACTION",
                        "REVIEW_SOURCE_AND_HISTORY_CLEANUP", "INVESTIGATE_IMPACT", "REVIEW_REVALIDATION"),
    "EXCESSIVE_SHARING": ("CONFIRM_OWNER_AND_TARGET", "REVIEW_SHARING_SCOPE", "ASSIGN_RESPONSIBILITY",
                          "REVIEW_SUPPORTED_RESTRICTIONS", "SET_FOLLOW_UP"),
    "PERSONAL_PAT_SERVICE_USE": ("CONFIRM_OWNER_AND_TARGET", "REVIEW_SERVICE_AUTH_MIGRATION",
                                 "REVIEW_CONSUMER_ADOPTION", "SET_FOLLOW_UP"),
    "DEFERRED_REPLACEMENT": ("CONFIRM_OWNER_AND_TARGET", "REVIEW_CONTAINMENT", "REVIEW_SUPPORTED_RESTRICTIONS",
                             "SET_FOLLOW_UP", "REVIEW_APPROVAL"),
    # Opened by the departed-owner check for a credential whose owner left
    # (cremore.identity.leavers): confirm the link, stop or hand over the credential.
    "DEPARTED_OWNER": ("CONFIRM_OWNER_AND_TARGET", "REVIEW_PROVIDER_ACTION", "REVIEW_SERVICE_AUTH_MIGRATION",
                       "REVIEW_CONSUMER_ADOPTION", "SET_FOLLOW_UP"),
    "CUSTOM": (),
}
CONDITION_VALUES = {
    "PROVIDER": None,  # any provider slug (_PROVIDER); it must still match the saved finding
    "FINDING_SEVERITY": ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
    "DECLARED_PRIORITY": ("CRITICAL", "HIGH", "MEDIUM", "LOW"),
    "DECLARED_SERVICE_IMPACT": ("UNKNOWN", "NONE", "LIMITED", "SIGNIFICANT"),
}
APPROVAL_RULES = ("NONE", "INDEPENDENT_ADMIN")
EVIDENCE_KINDS = ("FINDING", "EXPOSURE", "ACTION_PLAN", "ORPHAN")
STORAGE_METHODS = ("UNKNOWN", "SECRET_MANAGER_REFERENCE", "PLATFORM_SECRET", "WORKLOAD_IDENTITY", "LOCAL_CONFIG",
                   "ENVIRONMENT", "OTHER_REVIEWED")
_PROVIDER = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_NIL = "00000000-0000-0000-0000-000000000000"
# Free text must never carry a secret: the same shape checks the dashboard applies.
_UNSAFE_TEXT = re.compile(
    r"[\x00-\x1f\x7f]|://|(?:gh[pousr]_|github_pat_|ntn_|secret_)[A-Za-z0-9]|(?:AKIA|ASIA)[A-Z0-9]{16}|-----BEGIN|Bearer\s|[A-Za-z0-9+/=_-]{32,}",
    re.IGNORECASE)


class TicketError(ValueError):
    def __init__(self, code: str, message: str = "", *, http_status: int = 422) -> None:
        super().__init__(message or code)
        self.code = code
        self.http_status = http_status


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def _iso(value) -> str | None:
    return value.isoformat() if isinstance(value, _dt.datetime) else None


def _ref(value, what: str) -> uuid.UUID:
    if not isinstance(value, str) or not _UUID.fullmatch(value.lower()) or value.lower() == _NIL:
        raise TicketError("WORKFLOW_ACTOR_INVALID", f"{what} must be a UUID reference")
    return uuid.UUID(value)


def _text(value, what: str, limit: int, *, required: bool) -> str:
    if value is None or value == "":
        if required:
            raise TicketError("WORKFLOW_FIELDS_INVALID", f"{what} is required")
        return ""
    if (not isinstance(value, str) or len(value) > limit or value.strip() != value or _UNSAFE_TEXT.search(value)
            or unsafe_text(value)):  # also what hides or reorders text, and a lone surrogate no response can carry
        raise TicketError("WORKFLOW_FIELDS_INVALID",
                          f"{what} must be plain text up to {limit} characters (no tokens, URLs or control characters)")
    return value


def _stamp(value, what: str) -> _dt.datetime:
    if not isinstance(value, str) or not value:
        raise TicketError("WORKFLOW_DATE_INVALID", f"{what} must be an ISO-8601 timestamp")
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))  # noqa: FURB162 -- Preserve rejection of misplaced Z markers in the established timestamp contract.
    except ValueError:
        raise TicketError("WORKFLOW_DATE_INVALID", f"{what} must be an ISO-8601 timestamp")
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.UTC)


def actor_ref(actor: str) -> uuid.UUID:
    """A stable UUID reference for an actor id (tickets store references only)."""

    try:
        return uuid.UUID(str(actor))
    except (ValueError, AttributeError, TypeError):
        return uuid.uuid5(uuid.NAMESPACE_URL, f"cremore:actor:{actor}")


def review_digest(ticket: WorkflowTicket) -> str:
    """Digest of the reviewed content an independent approval binds to.

    The workflow status is deliberately not part of it: an approval covers the
    owner, checklist, dates and evidence, and resolving the ticket is the step
    that consumes the approval, not a change to what was approved.
    """

    content = {
        "template_id": ticket.template_id, "priority": ticket.priority, "service_impact": ticket.service_impact,
        "responsible_team": ticket.responsible_team, "owner_id": str(ticket.owner_id) if ticket.owner_id else "",
        "review_due_at": _iso(ticket.review_due_at), "evidence": ticket.evidence, "security_review": ticket.security_review,
        "steps": [{"code": s.get("code"), "status": s.get("status")} for s in ticket.steps],
        "playbook": ticket.playbook,
    }
    return hashlib.sha256(json.dumps(content, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _security_review(value) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise TicketError("WORKFLOW_REVIEW_INVALID", "security_review must be an object")
    out = {}
    for key, limit in (("service_name", 128), ("issuer_context", 256), ("allowed_scope", 512),
                       ("rotation_plan", 512), ("offboarding_plan", 512), ("incident_plan", 512)):
        out[key] = _text(value.get(key), f"security_review.{key}", limit, required=True)
    method = value.get("storage_method", "UNKNOWN")
    if method not in STORAGE_METHODS:
        raise TicketError("WORKFLOW_REVIEW_INVALID", "security_review.storage_method is not a known method")
    out["storage_method"] = method
    return out


def _evidence(value, default: list[dict]) -> list[dict]:
    if value is None:
        return [dict(item) for item in default]
    if not isinstance(value, list) or len(value) > 32:
        raise TicketError("WORKFLOW_EVIDENCE_INVALID", "evidence must hold at most 32 references")
    seen: set[str] = set()
    out = []
    for item in value:
        if not isinstance(item, dict) or item.get("kind") not in EVIDENCE_KINDS:
            raise TicketError("WORKFLOW_EVIDENCE_INVALID", "evidence kind must be FINDING, EXPOSURE, ACTION_PLAN or ORPHAN")
        ref = _ref(item.get("id"), "evidence id")
        key = f"{item['kind']}:{ref}"
        if key in seen:
            raise TicketError("WORKFLOW_EVIDENCE_INVALID", "duplicate evidence reference")
        seen.add(key)
        out.append({"kind": item["kind"], "id": str(ref)})
    return out


class TicketService:
    def __init__(self, repo, *, now=None) -> None:
        self.repo = repo
        self.now = now or _now

    # --- catalog -------------------------------------------------------------

    @staticmethod
    def templates() -> list[dict]:
        return [{"id": tid, "steps": list(steps)} for tid, steps in PLAYBOOK_STEPS.items()]

    # --- create ---------------------------------------------------------------

    def create(self, finding, credential, actor: str, body: dict) -> WorkflowTicket:
        if not isinstance(body, dict):
            raise TicketError("WORKFLOW_FIELDS_INVALID", "request must be an object")
        # A ticket records the operator's review, never a provider action: every finding can have one.
        provider = (credential.provider or "").lower()
        provider = provider if _PROVIDER.fullmatch(provider) else "unknown"
        template = body.get("template_id", "PUBLIC_EXPOSURE")
        if not isinstance(template, str) or template not in PLAYBOOK_STEPS or template == "DEPARTED_OWNER":
            raise TicketError("WORKFLOW_FIELDS_INVALID", "template_id is not a known playbook")
        fields = self._common_fields(body, [{"kind": "FINDING", "id": str(finding.id)}])
        if template == "CUSTOM":
            steps = body.get("custom_steps")
            if not isinstance(steps, list) or not 1 <= len(steps) <= 12 \
                    or any(not isinstance(s, str) or s not in STEPS for s in steps) or len(set(steps)) != len(steps):
                raise TicketError("WORKFLOW_STEP_INVALID", "custom_steps must be 1-12 distinct known review steps")
            customization = body.get("customization")
            playbook = self._playbook({} if customization is None else customization, list(steps), finding, provider, fields)
        else:
            steps = list(PLAYBOOK_STEPS[template])
            playbook = None
        who = actor_ref(actor)
        now = self.now()
        ticket = WorkflowTicket(
            credential_id=credential.id, finding_id=finding.id, provider=provider,
            credential_type=credential.credential_type, template_id=template, status="OPEN", version=1,
            steps=[{"code": s, "status": "TODO"} for s in steps], playbook=playbook, created_by=who, updated_by=who,
            created_at=now, updated_at=now, **fields,
        )
        if ticket.owner_id:
            ticket.assigned_by, ticket.assigned_at = who, now
        ticket.review_digest = review_digest(ticket)
        return self.repo.create_ticket(ticket)

    def create_for_orphan(self, orphan: dict, *, now=None, existing=None) -> WorkflowTicket:
        """The departed-owner check's ticket for one credential (or account) that needs action.

        One ticket per orphan: ``existing`` maps orphan refs to tickets already open, so
        a pass that stopped before saving the ticket id does not open a second one.
        """
        ref = uuid.UUID(str(orphan["orphan_ref"]))
        found = (existing or {}).get(ref)
        if found is not None:
            return found
        now = now or self.now()
        credential = (orphan.get("body") or {}).get("credential") or {}
        used = orphan["verdict"] == "USED_AFTER_DEPARTURE"
        system = actor_ref("system:identity-leavers")
        ticket = WorkflowTicket(
            orphan_ref=ref, provider=str(orphan.get("provider") or "")[:64],
            credential_type=str(credential.get("type") or "")[:96], template_id="DEPARTED_OWNER", status="OPEN",
            version=1, priority="CRITICAL" if used else "HIGH", service_impact="UNKNOWN",
            review_due_at=now + _dt.timedelta(days=1 if used else 7),
            evidence=[{"kind": "ORPHAN", "id": str(ref)}],
            steps=[{"code": step, "status": "TODO"} for step in PLAYBOOK_STEPS["DEPARTED_OWNER"]],
            created_by=system, updated_by=system, created_at=now, updated_at=now)
        ticket.review_digest = review_digest(ticket)
        return self.repo.create_ticket(ticket)

    def _common_fields(self, body: dict, default_evidence: list[dict]) -> dict:
        priority = body.get("priority", "HIGH")
        impact = body.get("service_impact", "UNKNOWN")
        if priority not in PRIORITIES or impact not in IMPACTS:
            raise TicketError("WORKFLOW_FIELDS_INVALID", "priority or service_impact is not a known level")
        owner = body.get("owner_id")
        return {
            "priority": priority, "service_impact": impact,
            "responsible_team": _text(body.get("responsible_team"), "responsible_team", 128, required=False),
            "owner_id": _ref(owner, "owner_id") if owner else None,
            "review_due_at": _stamp(body.get("review_due_at"), "review_due_at"),
            "evidence": _evidence(body.get("evidence"), default_evidence),
            "security_review": _security_review(body.get("security_review")),
        }

    def _playbook(self, customization: dict, steps: list[str], finding, provider: str, fields: dict) -> dict:
        if not isinstance(customization, dict):
            raise TicketError("WORKFLOW_PLAYBOOK_INVALID", "customization must be an object")
        rule = customization.get("approval_rule", "INDEPENDENT_ADMIN")
        if rule not in APPROVAL_RULES:
            raise TicketError("WORKFLOW_PLAYBOOK_INVALID", "approval_rule must be NONE or INDEPENDENT_ADMIN")
        raw = customization.get("conditions")
        raw = [] if raw is None else raw
        if not isinstance(raw, list) or len(raw) > 4:
            raise TicketError("WORKFLOW_PLAYBOOK_INVALID", "at most four applicability conditions")
        facts = {"PROVIDER": provider, "FINDING_SEVERITY": finding.severity,
                 "DECLARED_PRIORITY": fields["priority"], "DECLARED_SERVICE_IMPACT": fields["service_impact"]}
        conditions, seen = [], set()
        for item in raw:
            if not isinstance(item, dict):
                raise TicketError("WORKFLOW_PLAYBOOK_INVALID", "applicability condition must be an object")
            field, equals = item.get("field"), item.get("equals")
            values = CONDITION_VALUES.get(field, ()) if isinstance(field, str) else ()
            if values is None:  # a provider slug
                allowed = isinstance(equals, str) and bool(_PROVIDER.fullmatch(equals))
            else:
                allowed = equals in values
            if not allowed or field in seen:
                raise TicketError("WORKFLOW_PLAYBOOK_INVALID", "unknown or duplicate applicability condition")
            seen.add(field)
            if facts[field] != equals:
                raise TicketError("WORKFLOW_PLAYBOOK_NOT_APPLICABLE",
                                  f"condition {field} = {equals} does not match the saved finding ({facts[field]})")
            conditions.append({"field": field, "equals": equals})
        return {"schema_version": 1, "config": {"conditions": conditions, "approval_rule": rule}, "steps": steps,
                "finding_severity": finding.severity, "provider": provider, "declared_priority": fields["priority"],
                "declared_service_impact": fields["service_impact"], "evaluated_at": self.now().isoformat()}

    # --- update ---------------------------------------------------------------

    def update(self, ticket: WorkflowTicket, actor: str, body: dict) -> WorkflowTicket:
        ticket = ticket.model_copy(deep=True)
        if not isinstance(body, dict):
            raise TicketError("WORKFLOW_FIELDS_INVALID", "request must be an object")
        if type(body.get("expected_version")) is not int or body["expected_version"] != ticket.version:
            raise TicketError("WORKFLOW_VERSION_CONFLICT", "the ticket changed since it was read", http_status=409)
        status = body.get("status", ticket.status)
        if status not in STATUSES:
            raise TicketError("WORKFLOW_FIELDS_INVALID", "status is not a known review status")
        fields = self._common_fields({**body, "review_due_at": body.get("review_due_at") or _iso(ticket.review_due_at)},
                                     ticket.evidence)
        steps_in = body.get("steps", [{"code": s["code"], "status": s["status"]} for s in ticket.steps])
        if not isinstance(steps_in, list) or any(not isinstance(s, dict) for s in steps_in) \
                or [s.get("code") for s in steps_in] != [s["code"] for s in ticket.steps]:
            raise TicketError("WORKFLOW_STEP_INVALID", "steps must be the ticket's checklist in order")
        who = actor_ref(actor)
        now = self.now()
        steps = []
        for old, new in zip(ticket.steps, steps_in):
            st = new.get("status")
            if st not in STEP_STATUSES:
                raise TicketError("WORKFLOW_STEP_INVALID", "step status must be TODO, REVIEWED or NOT_APPLICABLE")
            entry = {"code": old["code"], "status": st}
            if st != "TODO":
                if old.get("status") == st and old.get("reviewed_by"):
                    entry.update(reviewed_by=old["reviewed_by"], reviewed_at=old.get("reviewed_at"))
                else:
                    entry.update(reviewed_by=str(who), reviewed_at=now.isoformat())
            steps.append(entry)
        changes = {**fields, "status": status, "steps": steps, "updated_by": who, "updated_at": now,
                   "version": ticket.version + 1}
        if fields["owner_id"] and fields["owner_id"] != ticket.owner_id:
            changes.update(assigned_by=who, assigned_at=now)
        if status == "RESOLVED":
            rule = ((ticket.playbook or {}).get("config") or {}).get("approval_rule")
            if any(s["status"] == "TODO" for s in steps):
                raise TicketError("WORKFLOW_RESOLUTION_BLOCKED", "every checklist step must be reviewed first", http_status=409)
            if not fields["responsible_team"] or not fields["owner_id"]:
                raise TicketError("WORKFLOW_RESOLUTION_BLOCKED", "a responsible team and owner are required to resolve")
            if rule == "INDEPENDENT_ADMIN":
                # The approval must bind the exact content being resolved.
                approval = ticket.internal_approval
                if not approval or approval.get("content_digest") != review_digest(ticket.model_copy(update=changes)):
                    raise TicketError("WORKFLOW_APPROVAL_REQUIRED",
                                      "an independent Admin must approve this exact reviewed content first", http_status=409)
            changes.update(resolution_basis="MANUAL_WORKFLOW_REVIEW_COMPLETED", resolved_by=who, resolved_at=now)
        else:
            changes.update(resolution_basis="NOT_RESOLVED", resolved_by=None, resolved_at=None)
        digest = review_digest(ticket.model_copy(update=changes))
        changes["review_digest"] = digest
        # Any content change invalidates a previous approval.
        if ticket.internal_approval and ticket.internal_approval.get("content_digest") != digest:
            changes["internal_approval"] = None
        return self._save(ticket, **changes)

    def _save(self, ticket: WorkflowTicket, **changes) -> WorkflowTicket:
        saved = self.repo.update_ticket(ticket.id, expected_version=ticket.version, **changes)
        if saved is None:
            raise TicketError("WORKFLOW_VERSION_CONFLICT", "the ticket changed since it was read", http_status=409)
        return saved

    # --- approval -------------------------------------------------------------

    def approve(self, ticket: WorkflowTicket, actor: str, body: dict) -> WorkflowTicket:
        ticket = ticket.model_copy(deep=True)
        rule = ((ticket.playbook or {}).get("config") or {}).get("approval_rule")
        if rule != "INDEPENDENT_ADMIN":
            raise TicketError("WORKFLOW_APPROVAL_NOT_APPLICABLE", "this playbook has no internal approval rule")
        if not isinstance(body, dict) or body.get("confirm") is not True:
            raise TicketError("WORKFLOW_FIELDS_INVALID", "confirm must be true")
        if type(body.get("expected_version")) is not int or body["expected_version"] != ticket.version:
            raise TicketError("WORKFLOW_VERSION_CONFLICT", "the ticket changed since it was read", http_status=409)
        if body.get("content_digest") != ticket.review_digest:
            raise TicketError("WORKFLOW_DIGEST_MISMATCH", "content_digest does not match the reviewed content", http_status=409)
        who = actor_ref(actor)
        if who in (ticket.created_by, ticket.updated_by):
            raise TicketError("WORKFLOW_INDEPENDENCE_REQUIRED",
                              "the approver must differ from the creator and the last editor", http_status=409)
        if ticket.status == "RESOLVED":
            raise TicketError("WORKFLOW_ALREADY_RESOLVED", "a resolved ticket cannot be approved", http_status=409)
        if any(s["status"] == "TODO" for s in ticket.steps) or not ticket.owner_id or not ticket.responsible_team \
                or not ticket.evidence:
            raise TicketError("WORKFLOW_APPROVAL_BLOCKED",
                              "every step must be reviewed and an owner, team and evidence recorded", http_status=409)
        now = self.now()
        approval = {"approved_by": str(who), "approved_at": now.isoformat(), "source_version": ticket.version,
                    "content_digest": ticket.review_digest}
        # The approval is a new revision of the record; the digest of the reviewed
        # content is unchanged because the approval itself is not reviewed content.
        return self._save(ticket, internal_approval=approval, version=ticket.version + 1, updated_at=now)

    # --- public shape ---------------------------------------------------------

    @staticmethod
    def public(t: WorkflowTicket) -> dict:
        out = {
            "id": str(t.id), "credential_id": str(t.credential_id) if t.credential_id else None,
            "finding_id": str(t.finding_id) if t.finding_id else None,
            "orphan_ref": str(t.orphan_ref) if t.orphan_ref else None,
            "provider": t.provider, "credential_type": t.credential_type, "template_id": t.template_id,
            "status": t.status, "version": t.version, "priority": t.priority, "service_impact": t.service_impact,
            "responsible_team": t.responsible_team, "review_due_at": _iso(t.review_due_at), "evidence": t.evidence,
            "steps": t.steps, "created_by": str(t.created_by), "created_at": _iso(t.created_at),
            "updated_by": str(t.updated_by), "updated_at": _iso(t.updated_at), "resolution_basis": t.resolution_basis,
        }
        for key in ("owner_id", "assigned_by", "resolved_by"):
            value = getattr(t, key)
            if value:
                out[key] = str(value)
        for key in ("assigned_at", "resolved_at"):
            value = _iso(getattr(t, key))
            if value:
                out[key] = value
        for key in ("security_review", "playbook", "internal_approval", "review_digest"):
            value = getattr(t, key)
            if value:
                out[key] = value
        return out


def envelope(data) -> dict:
    return {"mode": "REAL", "scope": "THIS_CUSTOMER_INSTALLATION", "provider_changed": False,
            "manager_required": False, "provider_execution": "NOT_EXECUTED_BY_WORKFLOW",
            "evidence_basis": "OPERATOR_DECLARATION", "data": data}
