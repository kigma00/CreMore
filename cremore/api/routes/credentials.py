"""The credential list and what analysts add to a finding.

``GET /api/v1/credential-records`` is readable by any signed-in user, like the finding
list (cremore.api.credential_records). Tags, the review stage, comments, remediation
steps and owner contacts are analyst writes (cremore.db.annotation_store), each guarded
by the annotations' revision and recorded in the finding's history. Free text is
refused when the detection engine finds a credential in it, so no secret enters the
history; ``/api/v1/text-check`` runs the same check on a draft without keeping it.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from typing import Literal

from fastapi import Depends, Query
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from cremore.api import credential_records
from cremore.api.auth import Principal
from cremore.api.http_support import http_error, unsafe_text
from cremore.api.http_support import logger as _log
from cremore.db.annotation_store import (
    STAGES,
    STEP_IDS,
    STEP_STATES,
    AnnotationConflict,
    AnnotationStore,
)
from cremore.domain.models import FindingEvent
from cremore.governance import contact as delivery
from cremore.governance import response as response_process
from cremore.governance import response_routing

MAX_TEXT = 2000
MAX_TAG = 40
MAX_TAGS = 20
CHANNELS = ("mail", "slack")
TEMPLATES = ("info", "revoke", "purpose", "scope")


class _Revised(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: StrictInt = Field(ge=0)


class TagsBody(_Revised):
    tags: list[str] = Field(max_length=MAX_TAGS)


class StageBody(_Revised):
    stage: Literal[STAGES]


class StepBody(_Revised):
    status: Literal[STEP_STATES]
    comment: str | None = Field(default=None, max_length=MAX_TEXT)


class ContactBody(_Revised):
    channel: Literal[CHANNELS]
    template: Literal[TEMPLATES]
    recipients: StrictInt = Field(ge=1, le=500)
    due_at: _dt.date


class SendBody(_Revised):
    channel: Literal[CHANNELS]
    template: Literal[TEMPLATES]
    due_at: _dt.date
    to: list[str] = Field(min_length=1, max_length=delivery.MAX_RECIPIENTS)
    subject: str = Field(default="", max_length=delivery.SUBJECT_MAX)
    body: str = Field(min_length=1, max_length=delivery.BODY_MAX)


class TextBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=MAX_TEXT)


class ResponseTicketBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: StrictInt = Field(ge=0)
    request_id: uuid.UUID
    to: str | None = Field(default=None, min_length=1, max_length=254)
    person_ref: uuid.UUID | None = None
    team: str | None = Field(default=None, max_length=100)
    locale: Literal["ko", "en"] = "ko"
    # How the responder is asked; ``ticket`` (the plugin ticket system) when not said, as before channels.
    channel: Literal[response_process.CHANNELS] = "ticket"
    # With slack/mail: an Admin-approved team channel also gets a notice (its thread carries progress); dm=False makes
    # that notice the only delivery.
    slack_channel: str | None = Field(default=None, min_length=1, max_length=20)
    dm: StrictBool = True


class ResponseReviewBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: StrictInt = Field(ge=0)


class ResponseReportFields(BaseModel):
    """A responder's report: its business rules (DONE needs its actions) are response_reports.normalize's."""
    model_config = ConfigDict(extra="forbid")
    report_id: uuid.UUID
    result: Literal["DONE", "INCOMPLETE", "EXCEPTION"]
    path: Literal["RETIRED", "REPLACED", "EXCEPTION"]
    actions: list[Literal["REMOVE_PLAINTEXT", "REVOKE", "ROTATE", "STORE_REPLACEMENT", "CUTOVER", "DISABLE"]] = Field(min_length=0, max_length=6)
    explanation: str = Field(min_length=20, max_length=2000)
    performed_at: str = Field(max_length=40)
    replacement_plan_id: uuid.UUID | None = None
    replacement_entity_id: uuid.UUID | None = None


class ResponseReportBody(ResponseReportFields):
    expected_version: StrictInt = Field(ge=0)
    request_id: uuid.UUID


class ResponseAssignmentBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: StrictInt = Field(ge=0)
    person_ref: uuid.UUID | None
    team: str | None = Field(default=None, max_length=100)


class ResponseRuleBody(ResponseAssignmentBody):
    kind: Literal["location", "account"]
    key: uuid.UUID
    channel_id: str | None = Field(default=None, min_length=1, max_length=20)


class ResponseReleaseBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: StrictInt = Field(ge=0)
    request_id: uuid.UUID
    confirmed_no_pending_ticket: StrictBool


def _credentials_in(orchestrator, text: str) -> list[str]:
    """Credential types the engine finds in ``text``; the text is scanned in memory only."""
    from cremore.governance.response_reports import credential_types

    return credential_types(orchestrator, text)


def _hides_text(text: str) -> bool:
    """What a comment may not hold: lines and tabs stay, nothing that hides, breaks or reorders text."""
    return unsafe_text(text.replace("\t", " "), newlines=True)


def register(ctx) -> None:
    from cremore.api.routes import response_links

    response_links.register(ctx)  # the responder's link page: no platform role, the person's own sign-in
    app, repo, settings = ctx.app, ctx.repo, ctx.settings
    analyst = ctx.require_role("analyst")
    store = AnnotationStore(repo)

    def orchestrator():
        return app.state.orchestrator

    def finding_or_404(finding_id):
        finding = repo.get_finding(finding_id)
        if finding is None:
            raise http_error(404, "FINDING_NOT_FOUND")
        return finding

    def clean(text: str) -> str:
        text = (text or "").strip()
        if _hides_text(text):
            raise http_error(422, "TEXT_CONTROL_CHARACTERS")
        if _credentials_in(orchestrator(), text):
            raise http_error(422, "TEXT_CONTAINS_CREDENTIAL")
        return text

    def change(finding_id, revision, actor, event_type, note, **changes):
        try:
            saved = store.change(finding_id, revision, actor, **changes)
        except AnnotationConflict:
            raise http_error(409, "ANNOTATIONS_CHANGED") from None
        repo.record_finding_event(FindingEvent(finding_id=finding_id, actor=actor, event_type=event_type, note=note))
        return public(saved)

    def public(row) -> dict:
        return {"finding_id": str(row["finding_id"]), "tags": list(row["tags"]), "stage": row["stage"],
                "steps": row["steps"], "contact": row["contact"], "revision": row["revision"],
                "updated_by": row["updated_by"],
                "updated_at": row["updated_at"].isoformat() if hasattr(row["updated_at"], "isoformat") else row["updated_at"]}

    def response_public(value) -> dict:
        from cremore.api.activity_audit import profiles

        cycles = [value.get("current"), *(value.get("history") or [])]
        known = profiles(repo, {cycle.get("requested_by") for cycle in cycles if cycle})
        def shown(cycle):
            if not cycle:
                return cycle
            profile = known.get(cycle.get("requested_by")) or {}
            return {**cycle, "requested_by_name": profile.get("name"),
                    "requested_by_email": profile.get("email")}
        return {**value, "current": shown(value.get("current")),
                "history": [shown(cycle) for cycle in value.get("history", [])]}

    @app.get("/api/v1/credential-records")
    def credential_list(_actor: str = Depends(ctx.require_auth)) -> dict:
        return credential_records.build(repo, settings, orchestrator())

    @app.get("/api/v1/findings/{finding_id}/response")
    def response_status(finding_id: uuid.UUID, history_offset: int = Query(default=0, ge=0),
                        principal: Principal = Depends(ctx.require_principal)) -> dict:
        finding_or_404(finding_id)
        from cremore.governance import response_reports

        value = response_process.public(repo, finding_id, history_offset=history_offset)
        value["can_report"] = response_reports.authorized(repo, settings, value.get("current") or {}, principal.subject,
                                                        verified_email=principal.email)
        return response_public(value)

    @app.post("/api/v1/findings/{finding_id}/response/review")
    def response_review(finding_id: uuid.UUID, body: ResponseReviewBody, actor: str = Depends(analyst)) -> dict:
        try:
            return response_public(response_process.start_review(repo, finding_id, actor, expected_version=body.expected_version))
        except response_process.ResponseError as exc:
            raise http_error(exc.http_status, exc.code) from None

    @app.post("/api/v1/findings/{finding_id}/response/report")
    def response_report(finding_id: uuid.UUID, body: ResponseReportBody, principal: Principal = Depends(ctx.require_principal)) -> dict:
        try:
            return response_public(response_process.submit_report(repo, settings, finding_id, principal.subject,
                expected_version=body.expected_version, request_id=body.request_id, report_id=body.report_id,
                data=body.model_dump(mode="json", exclude={"expected_version", "request_id", "report_id"}),
                verified_email=principal.email,
                contains_credentials=lambda text: bool(_credentials_in(orchestrator(), text))))
        except response_process.ResponseError as exc:
            raise http_error(exc.http_status, exc.code) from None

    @app.get("/api/v1/findings/{finding_id}/response/reports")
    def response_reports(finding_id: uuid.UUID, request_id: uuid.UUID, offset: int = Query(default=0, ge=0),
                         _actor: str = Depends(ctx.require_auth)) -> dict:
        try:
            return response_process.report_history(repo, finding_id, request_id, offset=offset)
        except response_process.ResponseError as exc:
            raise http_error(exc.http_status, exc.code) from None

    @app.get("/api/v1/findings/{finding_id}/response/evidence-options")
    def response_evidence_options(finding_id: uuid.UUID, q: str = Query(default="", max_length=200),
                                  _actor: str = Depends(ctx.require_auth)) -> dict:
        from cremore.coverage import response_evidence

        return response_evidence.options(repo, finding_or_404(finding_id), now=_dt.datetime.now(_dt.UTC), q=q)

    @app.post("/api/v1/findings/{finding_id}/response/ticket")
    def request_response(finding_id: uuid.UUID, body: ResponseTicketBody,
                         actor: str = Depends(analyst)) -> dict:
        """Ask the responder to remove exposure (a Slack DM or mail with a CreMore link, a plugin ticket, or a local
        record); their completion still requires a later scan."""
        finding_or_404(finding_id)
        team = clean(body.team or "") or None
        asked = {"to": body.to, "person_ref": body.person_ref, "team": team, "locale": body.locale,
                 "expected_version": body.expected_version, "request_id": str(body.request_id), "channel": body.channel,
                 "slack_channel": body.slack_channel, "dm": body.dm}
        if body.channel != "ticket":
            try:
                return response_public(response_process.request_ticket(repo, settings, finding_id, actor,
                    transports=getattr(app.state, "contact_transports", None) or {}, **asked))
            except response_process.ResponseError as exc:
                raise http_error(exc.http_status, exc.code) from None
        factory = getattr(app.state, "ticket_http_client_factory", None)
        if factory is None:
            import httpx

            factory = lambda: httpx.Client(timeout=15.0, follow_redirects=False)
        client = factory()
        try:
            return response_public(response_process.request_ticket(repo, settings, finding_id, actor,
                                                                   http_client=client, **asked))
        except response_process.ResponseError as exc:
            raise http_error(exc.http_status, exc.code) from None
        finally:
            client.close()

    @app.get("/api/v1/findings/{finding_id}/response/routing")
    def response_routing_status(finding_id: uuid.UUID, _actor: str = Depends(analyst)) -> dict:
        finding_or_404(finding_id)
        try:
            return response_routing.public(repo, settings, finding_id, orchestrator=orchestrator())
        except response_process.ResponseError as exc:
            raise http_error(exc.http_status, exc.code) from None

    @app.put("/api/v1/findings/{finding_id}/response/assignment")
    def response_assignment(finding_id: uuid.UUID, body: ResponseAssignmentBody,
                            actor: str = Depends(analyst)) -> dict:
        finding_or_404(finding_id)
        try:
            return response_routing.assign(repo, settings, finding_id, actor, person_ref=body.person_ref,
                team=clean(body.team or "") or None, expected_version=body.expected_version)
        except response_process.ResponseError as exc:
            raise http_error(exc.http_status, exc.code) from None

    @app.put("/api/v1/findings/{finding_id}/response/routing-rule")
    def response_rule(finding_id: uuid.UUID, body: ResponseRuleBody,
                      actor: str = Depends(ctx.require_role("admin"))) -> dict:
        finding_or_404(finding_id)
        try:
            return response_routing.save_rule(repo, settings, finding_id, actor, kind=body.kind, key=str(body.key),
                person_ref=body.person_ref, team=clean(body.team or "") or None,
                expected_version=body.expected_version, orchestrator=orchestrator(), channel_id=body.channel_id)
        except response_process.ResponseError as exc:
            raise http_error(exc.http_status, exc.code) from None

    @app.post("/api/v1/findings/{finding_id}/response/release-unknown")
    def release_response(finding_id: uuid.UUID, body: ResponseReleaseBody,
                         actor: str = Depends(ctx.require_role("admin"))) -> dict:
        """Audit an administrator's check that no external ticket remains pending after an uncertain send."""
        finding_or_404(finding_id)
        try:
            return response_public(response_process.release_unknown(repo, finding_id, actor,
                expected_version=body.expected_version, request_id=str(body.request_id),
                confirmed_no_pending_ticket=body.confirmed_no_pending_ticket))
        except response_process.ResponseError as exc:
            raise http_error(exc.http_status, exc.code) from None

    @app.post("/api/v1/text-check")
    def text_check(body: TextBody, _actor: str = Depends(analyst)) -> dict:
        found = _credentials_in(orchestrator(), body.text)
        return {"contains_credential": bool(found), "credential_types": found, "unsafe": _hides_text(body.text)}

    @app.get("/api/v1/findings/{finding_id}/annotations")
    def annotations(finding_id: uuid.UUID, _actor: str = Depends(ctx.require_auth)) -> dict:
        finding_or_404(finding_id)
        return public(store.get(finding_id))

    @app.put("/api/v1/findings/{finding_id}/tags")
    def set_tags(finding_id: uuid.UUID, body: TagsBody, actor: str = Depends(analyst)) -> dict:
        finding_or_404(finding_id)
        tags = []
        for raw in body.tags:
            tag = raw.strip().lstrip("#").strip()
            if not tag or len(tag) > MAX_TAG or unsafe_text(tag):
                raise http_error(422, "TAG_INVALID")
            if tag not in tags:
                tags.append(tag)
        clean("\n".join(tags))
        before = store.get(finding_id)["tags"]
        added, removed = [t for t in tags if t not in before], [t for t in before if t not in tags]
        note = " ".join(["+#" + t for t in added] + ["-#" + t for t in removed])[:MAX_TEXT] or "unchanged"
        return change(finding_id, body.revision, actor, "TAGS_CHANGED", note, tags=tags)

    @app.put("/api/v1/findings/{finding_id}/stage")
    def set_stage(finding_id: uuid.UUID, body: StageBody, actor: str = Depends(analyst)) -> dict:
        """Reviewing or remediating: the two halves of an acknowledged finding."""
        if finding_or_404(finding_id).workflow_status != "ACKNOWLEDGED":
            raise http_error(409, "FINDING_NOT_ACKNOWLEDGED")
        return change(finding_id, body.revision, actor, "STAGE_CHANGED", body.stage, stage=body.stage)

    @app.put("/api/v1/findings/{finding_id}/remediation/{step}")
    def set_step(finding_id: uuid.UUID, step: str, body: StepBody, actor: str = Depends(analyst)) -> dict:
        finding_or_404(finding_id)
        if step not in STEP_IDS:
            raise http_error(404, "REMEDIATION_STEP_NOT_FOUND")
        current = store.get(finding_id)
        previous = (current["steps"] or {}).get(step) or {}
        comment = previous.get("comment", "") if body.comment is None else clean(body.comment)
        steps = {**(current["steps"] or {}), step: {
            "status": body.status, "comment": comment, "updated_by": actor,
            "updated_at": _dt.datetime.now(_dt.UTC).isoformat()}}
        note = f"{step}: {body.status}" + (" · comment" if comment != previous.get("comment", "") else "")
        return change(finding_id, body.revision, actor, "REMEDIATION_STEP", note, steps=steps)

    @app.post("/api/v1/findings/{finding_id}/comments", status_code=201)
    def comment(finding_id: uuid.UUID, body: TextBody, actor: str = Depends(analyst)) -> dict:
        finding_or_404(finding_id)
        text = clean(body.text)
        if not text:
            raise http_error(422, "TEXT_EMPTY")
        event = repo.record_finding_event(FindingEvent(finding_id=finding_id, actor=actor, event_type="COMMENT",
                                                       note=text))
        return event.model_dump(mode="json") if event is not None else {"finding_id": str(finding_id), "note": text}

    @app.post("/api/v1/findings/{finding_id}/contacts", status_code=201)
    def contact(finding_id: uuid.UUID, body: ContactBody, actor: str = Depends(analyst)) -> dict:
        """Record that an owner was asked, and by when; CreMore does not send the message."""
        finding_or_404(finding_id)
        today = _dt.datetime.now(_dt.UTC).date()
        if not today <= body.due_at <= today + _dt.timedelta(days=365):
            raise http_error(422, "DUE_DATE_OUT_OF_RANGE")
        record = {"channel": body.channel, "template": body.template, "recipients": body.recipients,
                  "due_at": body.due_at.isoformat(), "at": _dt.datetime.now(_dt.UTC).isoformat(), "by": actor}
        note = f"{body.channel} · {body.template} · {body.recipients} · {body.due_at.isoformat()}"
        return change(finding_id, body.revision, actor, "OWNER_CONTACTED", note, contact=record)

    @app.get("/api/v1/contact-delivery")
    def contact_delivery(_actor: str = Depends(analyst)) -> dict:
        """The channels CreMore sends on itself and the domains it sends to, for the contact window."""
        return delivery.channels(repo)

    @app.post("/api/v1/findings/{finding_id}/contacts/send")
    def send_contact(finding_id: uuid.UUID, body: SendBody, actor: str = Depends(analyst)) -> dict:
        """Send the message on a channel CreMore sends itself, then record the contact as /contacts does. The
        history names the channel, template and how many received it, never the text or the addresses."""
        finding_or_404(finding_id)
        now = _dt.datetime.now(_dt.UTC)
        if not now.date() <= body.due_at <= now.date() + _dt.timedelta(days=365):
            raise http_error(422, "DUE_DATE_OUT_OF_RANGE")
        if store.get(finding_id)["revision"] != body.revision:
            raise http_error(409, "ANNOTATIONS_CHANGED")  # checked before anything goes out

        def failed(code: str) -> None:
            repo.record_finding_event(FindingEvent(finding_id=finding_id, actor=actor, event_type="OWNER_CONTACT_FAILED",
                                                   note=f"{body.channel} · {body.template} · {code}"))

        ready = delivery.channels(repo)
        if not ready[body.channel]:
            raise http_error(409, "CONTACT_CHANNEL_NOT_SET_UP")
        try:
            to = delivery.recipients(body.channel, body.to, ready["allowed_domains"], ready["allowed_channels"])
            subject, text = delivery.message(body.channel, body.subject, body.body,
                                            lambda value: bool(_credentials_in(orchestrator(), value)))
            delivery.reserve(repo, actor, len(to), now)
            sent = delivery.send(repo, settings, body.channel, to, subject, text,
                                **(getattr(app.state, "contact_transports", None) or {}))
        except delivery.ContactError as exc:
            if exc.http_status in (429, 502):  # it did not go out: refused on the way, or the hour's limit
                failed(exc.code)
            raise http_error(exc.http_status, exc.code) from None
        if not sent["delivered"]:
            code = sent["failed"][0]["code"] if sent["failed"] else "CONTACT_NOT_DELIVERED"
            failed(code)
            raise http_error(502, code)
        # The message is out: its audit row comes first; digests let an investigator match a message they hold.
        marks = delivery.fingerprints(settings, sent["delivered"], subject, text)
        repo.record_finding_event(FindingEvent(
            finding_id=finding_id, actor=actor, event_type="OWNER_CONTACT_SENT",
            note=f"{body.channel} · {body.template} · {len(sent['delivered'])} · {body.due_at.isoformat()}"
                 f" · to={marks[0]} · text={marks[1]}"))
        record = {"channel": body.channel, "template": body.template, "recipients": len(sent["delivered"]),
                  "due_at": body.due_at.isoformat(), "at": now.isoformat(), "by": actor, "sent": True}
        saved = None
        for _attempt in range(3):
            # Recorded on the annotations as they are now, whatever was read before; a failure here loses no audit.
            try:
                saved = store.change(finding_id, store.get(finding_id)["revision"], actor, contact=record)
                break
            except AnnotationConflict:
                continue
            except Exception as exc:  # noqa: BLE001 -- the send and its audit row stand
                _log.warning("contact sent but not recorded on the annotations: %s", type(exc).__name__)
                break
        return {"delivered": sent["delivered"], "failed": sent["failed"], "annotations": public(saved) if saved else None}
