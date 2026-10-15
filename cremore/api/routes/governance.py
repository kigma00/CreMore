"""Credential actions: plans, approvals, rotation and the tickets that record them.

Registered by the dashboard composition root. Shared behavior is imported
from independent API libraries; dependencies arrive through DashboardContext.
"""

from __future__ import annotations

import hmac
import json
import uuid
from typing import Literal

from cremore_aws_provider import aws_access
from fastapi import Depends, Header, HTTPException, Query, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from cremore.api.auth import email_verified
from cremore.api.governance_presenters import available_actions as _available_actions
from cremore.api.governance_presenters import present_action as _action_public
from cremore.api.governance_presenters import present_review as _review_public
from cremore.api.governance_presenters import present_rotation as _rotation_public
from cremore.api.http_support import http_error as _http
from cremore.api.http_support import page_rows, unsafe_text
from cremore.api.http_support import parse_uuid as _uuid
from cremore.api.http_support import utc_now as _now
from cremore.api.route_context import DashboardContext
from cremore.api.routes.credentials import _credentials_in
from cremore.domain.models import FindingEvent
from cremore.governance import contact as delivery
from cremore.governance.tickets import TicketError, TicketService
from cremore.governance.tickets import envelope as _workflow_envelope
from cremore.remediation import owner_approval
from cremore.remediation.action_plans import ActionPlanError


class OwnerApprovalBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel: Literal[delivery.CHANNELS]
    to: str = Field(min_length=1, max_length=254)
    locale: Literal[owner_approval.LOCALES] = "ko"


class OwnerLinkBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(max_length=64)


class OwnerDecisionBody(OwnerLinkBody):
    decision: Literal["approve", "decline"]
    note: str = Field(default="", max_length=owner_approval.NOTE_MAX)


class EmergencyBody(BaseModel):
    signed_approval: dict | None = None
    model_config = ConfigDict(extra="forbid")
    plan_hash: str = Field(max_length=64)
    reason: str = Field(max_length=owner_approval.REASON_MAX)


class OwnerNoticeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel: Literal["mail", "slack", "record"]
    to: str = Field(min_length=1, max_length=254)
    locale: Literal[owner_approval.LOCALES] = "ko"
    evidence: str = Field(default="", max_length=owner_approval.EVIDENCE_MAX)


class OwnerTicketBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    to: str = Field(min_length=1, max_length=254)
    locale: Literal[owner_approval.LOCALES] = "ko"


class OwnerRecordBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner: str = Field(min_length=1, max_length=200)
    evidence: str = Field(min_length=1, max_length=owner_approval.EVIDENCE_MAX)
    decision: Literal["approve", "decline"]
    note: str = Field(default="", max_length=owner_approval.NOTE_MAX)


OWNER_LINK_CODES = ("OWNER_APPROVAL_LINK_NEEDS_SIGN_IN", "OWNER_APPROVAL_SIGN_IN_REQUIRED",
                    "OWNER_APPROVAL_EMAIL_UNVERIFIED")


def link_holder(app, repo, settings, authorization: str, codes: tuple[str, str, str]) -> dict:
    """The signed-in person opening a link CreMore sent (an owner approval, an exposure response): company sign-in
    only, a verified email of the company's, no platform role needed (the local admin token is no sign-in).
    ``codes``: the refusals as (not a company sign-in install 409, no bearer 401, email not verified/company 403)."""
    needs_sign_in, sign_in_required, email_unverified = codes
    if settings.auth_mode != "oidc":
        raise _http(409, needs_sign_in)
    verifier = getattr(app.state, "oidc_verifier", None)
    token = authorization.removeprefix("Bearer ").strip() if authorization.startswith("Bearer ") else ""
    if verifier is None or not token:
        raise _http(401, sign_in_required)
    claims = verifier.claims(token)
    email = claims.get("email")
    if not isinstance(email, str) or "@" not in email or not email_verified(claims):
        raise _http(403, email_unverified)
    from cremore.identity import sign_in_groups

    # With Google sign-in anyone holds a Google account: only one of the company's Workspace opens a link.
    if not sign_in_groups.company_account(repo, settings, claims):
        raise _http(403, email_unverified)
    return {"subject": str(claims["sub"]).strip(), "email": email.strip()}


def register(ctx: DashboardContext) -> None:
    _account_session, _plan_error, action_plans, app = ctx._account_session, ctx._plan_error, ctx.action_plans, ctx.app
    key_action_adapter_factory, repo, require_auth, require_role = ctx.key_action_adapter_factory, ctx.repo, ctx.require_auth, ctx.require_role
    rotation_service_factory, settings, ticket_service = ctx.rotation_service_factory, ctx.settings, ctx.ticket_service

    def _secret_region(arn: str) -> str:
        parts = (arn or "").split(":")
        return parts[3] if len(parts) > 3 and parts[3] else settings.aws_region

    def _plan_or_404(plan_id: str):
        plan = repo.get_action_plan(_uuid(plan_id, "plan_id"))
        if plan is None:
            raise _http(404, "action plan not found")
        return plan

    @app.get("/api/v1/action-plans")
    def all_action_plans(status: str = "", _actor: str = Depends(require_auth)) -> dict:
        """The newest key action plans of every credential and departed owner's key, for the approvals queue."""
        items = []
        for plan in repo.list_action_plans():
            public = action_plans.public(plan)
            if status and public["status"] != status:
                continue
            if "target" not in public:  # another provider's credential names itself (provider_credential)
                cred = repo.get_credential(plan.credential_id)
                # A departed owner's key is planned by its orphan reference, not a discovered credential.
                public["target"] = ({"kind": "credential", "credential_type": cred.credential_type,
                                     "provider": cred.provider} if cred is not None else {"kind": "departed_owner"})
            items.append(public)
        return {"items": items, "policy": action_plans.installation_policy()}

    @app.get("/api/v2/coverage/inventory/{entity_id}/action-plans")
    def inventory_action_plans(entity_id: str, _actor: str = Depends(require_auth)) -> dict:
        """Plans on a credential another provider's inventory lists, and what may be planned on it now."""
        from cremore.remediation import provider_actions

        try:
            target = provider_actions.target_of(repo, _uuid(entity_id, "entity_id"))
        except provider_actions.ProviderActionError as exc:
            if exc.code == "CREDENTIAL_NOT_FOUND":
                raise _http(404, "credential not found") from None
            return {"plans": [], "policy": {**action_plans.installation_policy(), "supported_actions": [],
                                            "can_plan": False, "block_reason": exc.code}}
        plans = repo.list_action_plans(provider_actions.target_key(target))
        return {"plans": [action_plans.public(plan) for plan in plans], "policy": action_plans.target_policy(target)}

    @app.post("/api/v2/coverage/inventory/{entity_id}/action-plans", status_code=201)
    def create_inventory_action_plan(entity_id: str, body: dict,
                                     actor: str = Depends(require_role("remediator"))) -> dict:
        """Plan disabling or revoking that credential, through the provider connection set up to act on it."""
        try:
            return action_plans.public(action_plans.create_for_target(_uuid(entity_id, "entity_id"), actor, body))
        except ActionPlanError as exc:
            raise _plan_error(exc)

    @app.get("/api/v1/action-plans/{plan_id}/authorization-request")
    def authorization_request(plan_id: str, mode: Literal["execute", "emergency", "recheck"] = "execute",
                              _actor: str = Depends(require_role("remediator"))) -> dict:
        """Exact non-secret target and operation for review by the external signer."""
        from cremore.remediation.authorization import request_for
        return request_for(_plan_or_404(plan_id), mode, repo=repo)

    @app.post("/api/v1/action-plans/{plan_id}/approve")
    def approve_action_plan(plan_id: str, body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        plan = _plan_or_404(plan_id)
        try:
            body = body or {}
            return action_plans.public(action_plans.approve(plan, actor, body.get("plan_hash"),
                                                            body.get("self_approval_confirmed") is True))
        except ActionPlanError as exc:
            raise _plan_error(exc)

    @app.post("/api/v1/action-plans/{plan_id}/execute")
    def execute_action_plan(plan_id: str, body: dict, response: Response,
                            actor: str = Depends(require_role("remediator"))) -> dict:
        """Execute an approved plan with write-then-read-back. Only a read-back
        that proves the intended state is VERIFIED; anything else is
        OUTCOME_UNKNOWN and may only be rechecked, never retried.

        A plan on another provider's credential is queued (202): only the worker opens the credential that acts."""

        plan = _plan_or_404(plan_id)
        if plan.target or getattr(settings, "isolated_deployment", False):
            try:
                queued = action_plans.queue_execution(plan, actor, (body or {}).get("plan_hash"),
                                                       signed_approval=(body or {}).get("signed_approval"))
            except ActionPlanError as exc:
                raise _plan_error(exc)
            response.status_code = 202
            return action_plans.public(queued)
        try:
            # Every approval and policy gate first: no AWS session for a request that cannot run.
            action_plans.gate(plan, actor, (body or {}).get("plan_hash"))
        except ActionPlanError as exc:
            raise _plan_error(exc)
        return _run(plan, actor, (body or {}).get("plan_hash"), "EXECUTE")

    def _run(plan, actor: str, plan_hash, step: str, emergency: bool = False) -> dict:
        """Build the plan's provider clients (a refusal there is audited as ``step``) and execute it."""
        try:
            adapter, rotation = _action_clients(plan)
        except HTTPException as exc:  # e.g. no AWS session for the plan's account: refused after the gate
            action_plans.refused(plan, actor, step, str(exc.detail).split(":", 1)[0])
            raise
        try:
            return action_plans.public(action_plans.execute(plan, actor, plan_hash, adapter=adapter,
                                                            rotation_service=rotation, emergency=emergency))
        except ActionPlanError as exc:
            raise _plan_error(exc)

    @app.post("/api/v1/action-plans/{plan_id}/emergency-execute")
    def emergency_execute_action_plan(plan_id: str, body: EmergencyBody, response: Response,
                                      actor: str = Depends(require_role("admin"))) -> dict:
        """Contain a publicly exposed key at once while its owner has not approved yet: an Admin's decision with
        a reason, audited before the provider is touched; the owner is told afterwards (owner-notice)."""
        plan = _plan_or_404(plan_id)
        try:
            reason = _clean(body.reason, "EMERGENCY_REASON_INVALID", newlines=True)
            if len(reason) < owner_approval.REASON_MIN:
                raise _http(422, "EMERGENCY_REASON_REQUIRED")
        except HTTPException as exc:
            action_plans.refused(plan, actor, "EMERGENCY", str(exc.detail))  # a refused emergency is audited too
            raise
        try:
            action_plans.emergency(plan, actor, body.plan_hash, reason, signed_approval=body.signed_approval)
        except ActionPlanError as exc:
            raise _plan_error(exc)
        if getattr(settings, "isolated_deployment", False):
            try:
                queued = action_plans.queue_execution(plan, actor, body.plan_hash,
                                                       signed_approval=body.signed_approval, emergency=True)
            except ActionPlanError as exc:
                raise _plan_error(exc)
            response.status_code = 202
            return action_plans.public(queued)
        return _run(plan, actor, body.plan_hash, "EMERGENCY", emergency=True)

    @app.post("/api/v1/action-plans/{plan_id}/owner-notice")
    def notify_owner_after(plan_id: str, body: OwnerNoticeBody, actor: str = Depends(require_role("remediator"))) -> dict:
        """Tell the key's owner what an emergency containment did: CreMore sends its own text (no link), or the
        operator records how the owner was told. The notice is claimed (and audited) before a message goes out; a
        message that did not go out releases it."""
        plan = _plan_or_404(plan_id)
        record = owner_approval.emergency(repo, plan.id)
        if not record or not record.get("notice_pending") or not owner_approval.emergency_applied(repo, plan):
            raise _http(409, "OWNER_NOTICE_NOT_PENDING")
        now = _now()
        if body.channel == "record":
            owner = _clean(body.to, "OWNER_APPROVAL_OWNER_INVALID")
            evidence = _clean(body.evidence, "OWNER_APPROVAL_EVIDENCE_INVALID")
            if not owner or not evidence:
                raise _http(422, "OWNER_APPROVAL_EVIDENCE_REQUIRED")
            note = f"record · owner={json.dumps(owner, ensure_ascii=False)} · evidence={json.dumps(evidence, ensure_ascii=False)}"
            try:
                owner_approval.noticed(repo, plan, actor, channel="record", recipient=owner, evidence=evidence, note=note,
                                       now=now)
            except owner_approval.OwnerApprovalError as exc:
                raise _http(exc.http_status, exc.code) from None
            return action_plans.public(repo.get_action_plan(plan.id))
        ready = delivery.channels(repo)
        if not ready[body.channel]:
            raise _http(409, "CONTACT_CHANNEL_NOT_SET_UP")
        declined = (owner_approval.current(repo, plan.id, now) or {}).get("state") == "DECLINED"
        try:
            to = delivery.recipients(body.channel, [body.to], ready["allowed_domains"], ready["allowed_channels"])
            if "@" not in to[0]:
                raise _http(422, "OWNER_APPROVAL_RECIPIENT_NOT_A_PERSON")
            subject, text = owner_approval.notice_message(plan, record, body.locale, declined=declined)
            # The same outbound checks as any message: one-line subject, plain text, no secret value.
            subject, text = delivery.message(body.channel, subject, text,
                                             lambda value: bool(_credentials_in(app.state.orchestrator, value)))
            delivery.reserve(repo, actor, 1, now)
            marks = delivery.fingerprints(settings, to, subject, text)
            owner_approval.noticed(repo, plan, actor, channel=body.channel, recipient=to[0], evidence=None,
                                   note=f"{body.channel} · to={to[0]} · text={marks[1]}", now=now)
        except (delivery.ContactError, owner_approval.OwnerApprovalError) as exc:
            raise _http(exc.http_status, exc.code) from None
        try:
            sent = delivery.send(repo, settings, body.channel, to, subject, text,
                                 **(getattr(app.state, "contact_transports", None) or {}))
        except delivery.ContactError as exc:
            owner_approval.notice_not_sent(repo, plan, actor, f"{body.channel} · {exc.code}")
            raise _http(exc.http_status, exc.code) from None
        except Exception:
            owner_approval.notice_not_sent(repo, plan, actor, f"{body.channel} · CONTACT_SEND_ERROR")
            raise
        if not sent["delivered"]:
            code = sent["failed"][0]["code"] if sent["failed"] else "CONTACT_NOT_DELIVERED"
            owner_approval.notice_not_sent(repo, plan, actor, f"{body.channel} · {code}")
            raise _http(502, code)
        return action_plans.public(repo.get_action_plan(plan.id))
    def _action_clients(plan):
        """Clients for the account pinned on the plan, from a freshly verified remediation session."""
        from cremore.remediation.action_plans import ROTATION_ACTIONS

        rotating = plan.action_type in ROTATION_ACTIONS
        factory = rotation_service_factory if rotating else key_action_adapter_factory
        if factory is None:
            return None, None
        session = _account_session(plan.account_id, aws_access.REMEDIATION)
        if rotating:
            return None, factory(session, _secret_region((plan.rotation or {}).get("secret_arn", "")))
        return factory(session), None

    @app.post("/api/v1/action-plans/{plan_id}/recheck")
    def recheck_action_plan(plan_id: str, body: dict, response: Response,
                            actor: str = Depends(require_role("remediator"))) -> dict:
        plan = _plan_or_404(plan_id)
        if plan.target or getattr(settings, "isolated_deployment", False):
            try:
                queued = action_plans.queue_recheck(plan, actor, (body or {}).get("plan_hash"),
                                                     signed_approval=(body or {}).get("signed_approval"))
            except ActionPlanError as exc:
                raise _plan_error(exc)
            response.status_code = 202
            return action_plans.public(queued)
        try:
            action_plans.bound(plan, actor, (body or {}).get("plan_hash"))
        except ActionPlanError as exc:
            raise _plan_error(exc)
        # A read-back only proves a state (e.g. key ABSENT) inside the plan's own account.
        try:
            adapter, rotation = _action_clients(plan) if plan.status == "OUTCOME_UNKNOWN" else (None, None)
        except HTTPException as exc:
            action_plans.refused(plan, actor, "RECHECK", str(exc.detail).split(":", 1)[0])
            raise
        try:
            return action_plans.public(action_plans.recheck(plan, actor, (body or {}).get("plan_hash"),
                                                            adapter=adapter, rotation_service=rotation))
        except ActionPlanError as exc:
            raise _plan_error(exc)

    @app.post("/api/v1/action-plans/{plan_id}/cancel")
    def cancel_action_plan(plan_id: str, actor: str = Depends(require_role("remediator"))) -> dict:
        plan = _plan_or_404(plan_id)
        try:
            return action_plans.public(action_plans.cancel(plan, actor))
        except ActionPlanError as exc:
            raise _plan_error(exc)

    def _clean(value: str, code: str, *, newlines: bool = False) -> str:
        """Free text an owner or the operator adds: no hidden characters and nothing the detector reads as a secret."""
        text = value.strip()
        if text and unsafe_text(text.replace("\t", " "), newlines=newlines):
            raise _http(422, code)
        if text and _credentials_in(app.state.orchestrator, text):
            raise _http(422, "TEXT_CONTAINS_CREDENTIAL")
        return text

    @app.post("/api/v1/action-plans/{plan_id}/owner-approval")
    def request_owner_approval(plan_id: str, body: OwnerApprovalBody,
                               actor: str = Depends(require_role("remediator"))) -> dict:
        """Send the credential's owner a link to approve or decline the plan's operational impact after signing in.
        The request is audited before the message goes out; a message that did not go out ends its link."""
        plan = _plan_or_404(plan_id)
        if settings.auth_mode != "oidc":
            raise _http(409, "OWNER_APPROVAL_LINK_NEEDS_SIGN_IN")  # the local operator records the approval instead
        now = _now()
        ready = delivery.channels(repo)
        if not ready[body.channel]:
            raise _http(409, "CONTACT_CHANNEL_NOT_SET_UP")
        if not ready["console_url"]:
            raise _http(409, "OWNER_APPROVAL_CONSOLE_URL_NOT_SET")
        try:
            to = delivery.recipients(body.channel, [body.to], ready["allowed_domains"], ready["allowed_channels"])
            if "@" not in to[0]:
                raise _http(422, "OWNER_APPROVAL_RECIPIENT_NOT_A_PERSON")  # a channel's members are not the owner
            token, expires = owner_approval.new_link(repo, plan, now)
            subject, text = owner_approval.message(plan, ready["console_url"] + owner_approval.LINK_PATH + token,
                                                   expires, body.locale)
            delivery.reserve(repo, actor, 1, now)
            marks = delivery.fingerprints(settings, to, subject, text)
            owner_approval.start(repo, plan, actor, token=token, expires=expires, channel=body.channel,
                                 recipient=to[0], now=now, note=f"{body.channel} · to={to[0]} · text={marks[1]}"
                                                                 f" · expires={expires.isoformat()}")
        except (delivery.ContactError, owner_approval.OwnerApprovalError) as exc:
            raise _http(exc.http_status, exc.code) from None
        try:
            sent = delivery.send(repo, settings, body.channel, to, subject, text,
                                 **(getattr(app.state, "contact_transports", None) or {}))
        except delivery.ContactError as exc:
            owner_approval.withdraw(repo, plan, token, actor, f"{body.channel} · {exc.code}")
            raise _http(exc.http_status, exc.code) from None
        except Exception:
            owner_approval.withdraw(repo, plan, token, actor, f"{body.channel} · CONTACT_SEND_ERROR")
            raise
        if not sent["delivered"]:
            code = sent["failed"][0]["code"] if sent["failed"] else "CONTACT_NOT_DELIVERED"
            owner_approval.withdraw(repo, plan, token, actor, f"{body.channel} · {code}")
            raise _http(502, code)
        return action_plans.public(repo.get_action_plan(plan.id))

    @app.post("/api/v1/action-plans/{plan_id}/owner-approval/record")
    def record_owner_approval(plan_id: str, body: OwnerRecordBody,
                              actor: str = Depends(require_role("remediator"))) -> dict:
        """The local operator records the approval the owner gave outside CreMore, with its reference. With company
        sign-in the owner decides through the link themselves, so a record could stand in for them: refused."""
        plan = _plan_or_404(plan_id)
        if settings.auth_mode != "local":
            raise _http(409, "OWNER_APPROVAL_RECORD_LOCAL_ONLY")
        owner = _clean(body.owner, "OWNER_APPROVAL_OWNER_INVALID")
        evidence = _clean(body.evidence, "OWNER_APPROVAL_EVIDENCE_INVALID")
        note = _clean(body.note, "OWNER_APPROVAL_NOTE_INVALID", newlines=True)
        if not owner or not evidence:
            raise _http(422, "OWNER_APPROVAL_EVIDENCE_REQUIRED")
        try:
            owner_approval.record(repo, plan, actor, owner=owner, evidence=evidence, decision=body.decision,
                                  note=note, now=_now())
        except owner_approval.OwnerApprovalError as exc:
            raise _http(exc.http_status, exc.code) from None
        return action_plans.public(repo.get_action_plan(plan.id))

    # --- the owner's approval asked in the company's ticket system (cremore/ticketing) -------------------------

    @app.get("/api/v1/ticket-system")
    def ticket_system(_actor: str = Depends(require_role("analyst"))) -> dict:
        """The ticket system an owner's approval can be asked in, or none."""
        from cremore.ticketing import registry, setup

        name = setup.configured(repo)
        try:
            label = registry.load(name).label if name else None
        except ValueError:
            name = label = None  # an adapter that no longer loads asks nobody
        return {"system": name, "label": label}

    def _ticket_client():
        factory = getattr(app.state, "ticket_http_client_factory", None)
        if factory is not None:
            return factory()
        import httpx

        return httpx.Client(timeout=15.0, follow_redirects=False)

    @app.post("/api/v1/action-plans/{plan_id}/owner-approval/ticket")
    def request_owner_approval_ticket(plan_id: str, body: OwnerTicketBody,
                                      actor: str = Depends(require_role("remediator"))) -> dict:
        """Ask the credential's owner for the plan's approval in the company's ticket system: a ticket asks their
        own account there, and the worker records the answer (cremore.ticketing.sweep). Audited before the ticket
        opens; a ticket that did not open ends the request."""
        from cremore.governance import principals
        from cremore.ticketing import setup
        from cremore.ticketing.contract import ApprovalRequest, TicketError, safe_code

        plan = _plan_or_404(plan_id)
        system_name = setup.configured(repo)
        if not system_name:
            raise _http(409, "TICKET_SYSTEM_NOT_SET_UP")
        try:
            owner = delivery.address(body.to)
        except delivery.ContactError:
            raise _http(422, "OWNER_APPROVAL_RECIPIENT_INVALID") from None
        def refused(status: int, code: str):
            """Refused before anything was asked, and audited: attempts to be one's own owner stay in view."""
            owner_approval.ticket_refused(repo, plan, actor, code, owner)
            return _http(status, code)

        separate = settings.auth_mode == "oidc"
        known = principals.marks(repo, [who for who in (actor, plan.requested_by, plan.approved_by) if who])
        if separate and any(value is None for value in known.values()):
            # The owner is told apart from the people on the security side of this plan by address, since the
            # ticket system knows people by address: someone whose sign-in never carried one cannot be.
            raise refused(409, "OWNER_APPROVAL_ACTOR_EMAIL_UNKNOWN")
        if separate and any(hmac.compare_digest(value, principals.mark(settings, owner)) for value in known.values()):
            raise refused(403, "OWNER_APPROVAL_SAME_PERSON")  # before the ticket system is even asked
        now = _now()
        request = str(uuid.uuid4())
        try:
            expires = owner_approval.window(repo, plan, now)
            delivery.reserve(repo, actor, 1, now)  # a lookup and a ticket that mails the owner: the hourly budget
        except (owner_approval.OwnerApprovalError, delivery.ContactError) as exc:
            raise _http(exc.http_status, exc.code) from None
        title, lines = owner_approval.ticket_message(plan, expires, body.locale)
        client = _ticket_client()
        started = False
        try:
            # The system, its name and the server it asks on come from one reading of the setup.
            system, system_name, binding = setup.open_system(repo, settings, client)
            try:
                # The account the system will ask, with every address it carries: none of them may be a
                # security-side person's (an alias, a second address, the service account CreMore signs in as).
                approver = system.find_approver(owner)
                marks = {principals.mark(settings, address) for address in (owner, *approver.addresses)}
                if separate and any(any(hmac.compare_digest(value, mark) for mark in marks) for value in known.values()):
                    raise refused(403, "OWNER_APPROVAL_SAME_PERSON")
                owner_approval.start_ticket(repo, plan, actor, system=system_name, binding=binding,
                                            recipient=owner, recipient_marks=marks, request=request, expires=expires,
                                            now=now, note=f"{system_name} · to={owner} · expires={expires.isoformat()}")
                started = True
                opened = system.open_approval(ApprovalRequest(title=title, lines=lines), approver)
            finally:
                system.close()
        except TicketError as exc:
            code = safe_code(exc)
            if started:
                left = f" · ticket={exc.ticket}" if exc.ticket and owner_approval.reference_ok(exc.ticket) else ""
                owner_approval.ticket_not_opened(repo, plan, request, actor, f"{system_name} · {code}{left}")
            else:
                owner_approval.ticket_refused(repo, plan, actor, code, owner)  # the owner's account not found, …
            raise _http(503 if exc.retryable else 409, code) from None
        except (owner_approval.OwnerApprovalError, delivery.ContactError) as exc:
            raise _http(exc.http_status, exc.code) from None
        except HTTPException:
            raise
        except Exception:
            if started:
                owner_approval.ticket_not_opened(repo, plan, request, actor, f"{system_name} · TICKET_SYSTEM_ERROR")
            raise
        finally:
            client.close()
        try:
            owner_approval.ticket_opened(repo, plan, request, system_name, opened, actor)
        except owner_approval.OwnerApprovalError as exc:
            owner_approval.ticket_not_opened(repo, plan, request, actor, f"{system_name} · {exc.code}")
            raise _http(exc.http_status, exc.code) from None
        return action_plans.public(repo.get_action_plan(plan.id))

    def _linked_plan(plan_id: str):
        return repo.get_action_plan(uuid.UUID(plan_id))

    def _link_holder(authorization: str) -> dict:
        """The signed-in person opening an owner link."""
        return link_holder(app, repo, settings, authorization, OWNER_LINK_CODES)

    # The owner's link page (cremore.remediation.owner_approval): the token and the person's own sign-in.
    @app.post("/api/v1/owner-approvals/view")
    def view_owner_approval(body: OwnerLinkBody, authorization: str = Header(default="")) -> dict:
        holder = _link_holder(authorization)
        try:
            return owner_approval.view(repo, body.token, _now(), _linked_plan, holder)
        except owner_approval.OwnerApprovalError as exc:
            raise _http(exc.http_status, exc.code) from None

    @app.post("/api/v1/owner-approvals/decide")
    def decide_owner_approval(body: OwnerDecisionBody, authorization: str = Header(default="")) -> dict:
        holder = _link_holder(authorization)
        now = _now()
        try:
            # The link, its holder and its state first: the note is checked only for a decision that can be made.
            state = owner_approval.view(repo, body.token, now, _linked_plan, holder)["state"]
        except owner_approval.OwnerApprovalError as exc:
            raise _http(exc.http_status, exc.code) from None
        if state != "PENDING":
            raise _http(409, "OWNER_APPROVAL_PLAN_CHANGED" if state == "WITHDRAWN" else "OWNER_APPROVAL_ALREADY_DECIDED")
        note = _clean(body.note, "OWNER_APPROVAL_NOTE_INVALID", newlines=True)
        try:
            return owner_approval.decide(repo, body.token, body.decision, note, now, _linked_plan, holder)
        except owner_approval.OwnerApprovalError as exc:
            raise _http(exc.http_status, exc.code) from None

    @app.get("/api/v1/governance/reviews")
    def governance_reviews(response: Response, _actor: str = Depends(require_auth),
                           limit: int = Query(default=200, ge=1, le=500), cursor: uuid.UUID | None = None) -> list[dict]:
        return [_review_public(r) for r in page_rows(repo.list_reviews(limit=limit + 1, after=cursor), response, limit)]

    @app.post("/api/v1/governance/reviews", status_code=201)
    def open_review(body: dict, actor: str = Depends(require_role("analyst"))) -> dict:
        from cremore.domain.models import GovernanceReview

        fid = _uuid(body.get("finding_id"), "finding_id")
        if repo.get_finding(fid) is None:
            raise _http(422, "valid finding_id is required")
        review = repo.create_review(GovernanceReview(
            finding_id=fid,
            kind=body.get("kind", "OWNERSHIP"),
            question=body.get("question", ""),
            assignee=body.get("assignee"),
            created_by=actor,
        ))
        return _review_public(review)

    @app.post("/api/v1/governance/reviews/{review_id}/resolve")
    def resolve_review(review_id: str, body: dict, _actor: str = Depends(require_role("analyst"))) -> dict:
        updated = repo.update_review(_uuid(review_id, "review_id"), status="RESOLVED",
                                     response=body.get("response"),
                                     resolved_at=_now())
        if updated is None:
            raise _http(404, "review not found")
        return _review_public(updated)

    @app.get("/api/v1/rotation-automation/profiles")
    def rotation_profiles(_actor: str = Depends(require_auth)) -> list[dict]:
        # The rotation service supports approved two-party AWS key
        # rotation (PREPARE/PUBLISH); execution stays off unless enabled.
        return [{
            "id": "aws-access-key",
            "provider": "aws",
            "credential_type": "AWS_ACCESS_KEY",
            "display_name": "AWS access key (PREPARE/PUBLISH)",
            "two_party": True,
            "execution_enabled": False,
            "workflow": "APPROVED_ROTATION_V1",
            "migration_code": "LEGACY_ROTATION_REQUIRES_ACTION_PLAN",
            "action_plan_path": "/api/v1/credentials/{credential_id}/action-plans",
        }]

    @app.get("/api/v1/rotation-automation/jobs")
    def rotation_jobs(response: Response, _actor: str = Depends(require_auth),
                      limit: int = Query(default=200, ge=1, le=500), cursor: uuid.UUID | None = None) -> list[dict]:
        return [{**_rotation_public(j), "read_only": True, "migration_required": True,
                 "migration_code": "LEGACY_ROTATION_REQUIRES_ACTION_PLAN",
                 "action_plan_path": f"/api/v1/credentials/{j.credential_id}/action-plans",
                 "reconciliation_required": j.status != "PUBLISHED"}
                for j in page_rows(repo.list_rotation_jobs(limit=limit + 1, after=cursor), response, limit)]

    @app.post("/api/v1/rotation-automation/preview")
    def rotation_preview(body: dict, _actor: str = Depends(require_auth)) -> dict:
        cred_id = body.get("credential_id")
        cred = repo.get_credential(_uuid(cred_id, "credential_id")) if cred_id else None
        if cred is None:
            raise _http(422, "valid credential_id is required")
        return {
            "credential_id": str(cred.id),
            "credential_type": cred.credential_type,
            "supported": cred.credential_type == "AWS_ACCESS_KEY",
            "phases": ["PREPARE", "PUBLISH"],
            "two_party": True,
            "execution_enabled": False,
            "migration_code": "LEGACY_ROTATION_REQUIRES_ACTION_PLAN",
            "action_plan_path": f"/api/v1/credentials/{cred.id}/action-plans",
            "note": "Create PREPARE and PUBLISH action plans with operational review, exact target, "
                    "plan hash and administrator approval. Legacy rotation jobs are read-only.",
        }

    def _rotation_migration(actor, job_id=None):
        # Old requests carry neither the approved hash nor the operational review.
        # Never infer those attestations or resume an ambiguous historical write.
        job = repo.get_rotation_job(_uuid(job_id, "job_id")) if job_id else None
        if job_id and job is None:
            raise _http(404, "rotation job not found")
        code = "LEGACY_ROTATION_REQUIRES_ACTION_PLAN"
        migration = {"code": code, "read_only": True,
                     "action_plan_path": f"/api/v1/credentials/{job.credential_id if job else '{credential_id}'}/action-plans",
                     "reconciliation_required": bool(job and job.status != "PUBLISHED")}
        if job:
            migration["legacy_job_id"] = str(job.id)
            repo.record_finding_event(FindingEvent(target_type="rotation_job", target_id=job.id,
                actor=actor, event_type="ROTATION_LEGACY_WRITE_REFUSED", from_status=job.status,
                to_status=job.status, note=code))
        return JSONResponse(status_code=409, content={"detail": code, "error": code, "migration": migration})

    @app.post("/api/v1/rotation-automation/apply")
    def rotation_apply(body: dict, actor: str = Depends(require_role("analyst"))):
        return _rotation_migration(actor)

    @app.post("/api/v1/rotation-automation/jobs/{job_id}/approve")
    def rotation_approve(job_id: str, actor: str = Depends(require_role("remediator"))):
        return _rotation_migration(actor, job_id)

    @app.post("/api/v1/rotation-automation/jobs/{job_id}/publish")
    def rotation_publish(job_id: str, actor: str = Depends(require_role("remediator"))):
        return _rotation_migration(actor, job_id)

    @app.get("/api/v1/rotation-capabilities")
    def rotation_capabilities(_actor: str = Depends(require_auth)) -> list[dict]:
        return [{"credential_type": "AWS_ACCESS_KEY", "rotatable": True, "two_party": True}]

    @app.get("/api/v1/management-actions")
    def management_actions(response: Response, _actor: str = Depends(require_auth),
                           limit: int = Query(default=200, ge=1, le=500), cursor: uuid.UUID | None = None) -> list[dict]:
        return [_action_public(a) for a in page_rows(repo.list_management_actions(limit=limit + 1, after=cursor), response, limit)]

    @app.post("/api/v1/management-actions", status_code=201)
    def request_action(body: dict, actor: str = Depends(require_role("analyst"))) -> dict:
        from cremore.api.routes.credentials import _credentials_in
        from cremore.domain.models import ManagementAction

        fid = _uuid(body.get("finding_id"), "finding_id")
        finding = repo.get_finding(fid)
        if finding is None:
            raise _http(422, "valid finding_id is required")
        action_type = body.get("action_type", "ACKNOWLEDGE_OWNER")
        if action_type not in _available_actions(repo.get_credential(finding.credential_id)):
            raise _http(422, "MANAGEMENT_ACTION_INVALID: this action is not offered for the finding's credential")
        note = body.get("note")
        if note is not None and (not isinstance(note, str) or len(note) > 500 or unsafe_text(note, newlines=True)):
            raise _http(422, "MANAGEMENT_NOTE_INVALID: the note is plain text up to 500 characters")
        if note and _credentials_in(app.state.orchestrator, note):
            raise _http(422, "TEXT_CONTAINS_CREDENTIAL: the note looks like it holds a secret value")
        # The note stays on the request; the audit row, written with it, names the request and its kind.
        action = repo.create_management_action(
            ManagementAction(finding_id=fid, action_type=action_type, requested_by=actor, note=note or None),
            audit=lambda made: FindingEvent(finding_id=fid, actor=actor, event_type="MANAGEMENT_ACTION_REQUESTED",
                                            note=f"action={made.id} type={action_type}"))
        return _action_public(action)

    @app.post("/api/v1/management-actions/{action_id}/confirm")
    def confirm_action(action_id: str, body: dict | None = None, actor: str = Depends(require_role("remediator"))) -> dict:
        aid = _uuid(action_id, "action_id")
        before = repo.get_management_action(aid)
        if before is None:
            raise _http(404, "action not found")
        own = bool(before.requested_by) and before.requested_by == actor

        def audit(event_type, note):
            return FindingEvent(finding_id=before.finding_id, actor=actor, event_type=event_type,
                                note=f"action={before.id} type={before.action_type} {note}".strip())

        def refuse(code, message):
            # A refused confirmation is audited too, like a refused action plan step.
            repo.record_finding_event(audit("MANAGEMENT_ACTION_REFUSED", f"code={code}"))
            raise _http(409, f"{code}: {message}")

        # Two operators; a shared-token installation has one, who re-confirms their own request instead.
        if own and not action_plans.single_operator:
            refuse("SECOND_OPERATOR_REQUIRED", "a management action must be confirmed by a second operator")
        if own and not (isinstance(body, dict) and body.get("self_approval_confirmed") is True):
            refuse("SELF_APPROVAL_CONFIRMATION_REQUIRED", "re-confirm your own request on this single-operator installation")
        if before.status != "PENDING":
            refuse("MANAGEMENT_ACTION_NOT_PENDING", f"the action is {before.status}")
        # Only a request still pending changes, once, with its audit row in the same transaction.
        updated = repo.update_management_action(aid, expected_status="PENDING", status="CONFIRMED", confirmed_by=actor,
                                                audit=audit("MANAGEMENT_ACTION_CONFIRMED", "self_approval=confirmed" if own else ""))
        if updated is None:
            refuse("MANAGEMENT_ACTION_NOT_PENDING", "confirmed or closed meanwhile")
        return _action_public(updated)

    @app.get("/api/v1/management-actions/targets")
    def management_targets(response: Response, _actor: str = Depends(require_auth),
                           limit: int = Query(default=200, ge=1, le=500), cursor: uuid.UUID | None = None) -> list[dict]:
        # Open findings are the actionable targets.
        out = []
        for finding in page_rows(repo.list_findings(limit=limit + 1, after=cursor), response, limit):
            if finding.workflow_status == "RESOLVED":
                continue
            cred = repo.get_credential(finding.credential_id)
            out.append({
                "finding_id": str(finding.id),
                "credential_id": str(finding.credential_id),
                "credential_type": cred.credential_type if cred else "UNKNOWN",
                "severity": finding.severity,
                "available_actions": _available_actions(cred),
            })
        return out

    def _ticket_error(exc: TicketError) -> HTTPException:
        return _http(exc.http_status, f"{exc.code}: {exc}")

    def _ticket_or_404(ticket_id: str):
        ticket = repo.get_ticket(_uuid(ticket_id, "ticket_id"))
        if ticket is None:
            raise _http(404, "ticket not found")
        return ticket

    def _audit(event_type: str, actor: str, finding_id, note: str) -> None:

        repo.record_finding_event(FindingEvent(finding_id=finding_id, actor=actor, event_type=event_type, note=note))

    @app.get("/api/v1/tickets")
    def tickets(offset: int = 0, credential_id: str | None = None, _actor: str = Depends(require_auth)) -> dict:
        if offset < 0 or offset > 100_000:
            raise _http(422, "offset must be between 0 and 100000")
        rows = repo.list_tickets(_uuid(credential_id, "credential_id") if credential_id else None, limit=51, offset=offset)
        page = rows[:50]
        return _workflow_envelope({"items": [TicketService.public(t) for t in page],
                                   "next_offset": offset + 50 if len(rows) > 50 else None})

    @app.get("/api/v1/governance/playbooks")
    def playbooks(_actor: str = Depends(require_auth)) -> dict:
        return _workflow_envelope({"templates": TicketService.templates()})

    @app.post("/api/v1/tickets", status_code=201)
    def create_ticket(body: dict, actor: str = Depends(require_role("analyst"))) -> dict:
        finding = repo.get_finding(_uuid(body.get("finding_id"), "finding_id"))
        if finding is None:
            raise _http(404, "finding not found")
        cred = repo.get_credential(finding.credential_id)
        if cred is None:
            raise _http(404, "credential not found")
        try:
            ticket = ticket_service.create(finding, cred, actor, body)
        except TicketError as exc:
            raise _ticket_error(exc)
        _audit("TICKET_CREATED", actor, finding.id, f"ticket {ticket.id} ({ticket.template_id})")
        return _workflow_envelope(TicketService.public(ticket))

    @app.put("/api/v1/tickets/{ticket_id}")
    def update_ticket(ticket_id: str, body: dict, actor: str = Depends(require_role("analyst"))) -> dict:
        ticket = _ticket_or_404(ticket_id)
        try:
            updated = ticket_service.update(ticket, actor, body)
        except TicketError as exc:
            raise _ticket_error(exc)
        _audit("TICKET_UPDATED", actor, ticket.finding_id, f"ticket {ticket.id} v{updated.version} {updated.status}")
        return _workflow_envelope(TicketService.public(updated))

    @app.post("/api/v1/tickets/{ticket_id}/approve")
    def approve_ticket(ticket_id: str, body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        ticket = _ticket_or_404(ticket_id)
        try:
            updated = ticket_service.approve(ticket, actor, body)
        except TicketError as exc:
            raise _ticket_error(exc)
        _audit("TICKET_APPROVED", actor, ticket.finding_id, f"ticket {ticket.id} digest {ticket.review_digest}")
        return _workflow_envelope(TicketService.public(updated))
