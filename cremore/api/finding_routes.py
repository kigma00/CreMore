"""Finding reads and analyst triage, registered at their original API positions.

Credential investigation/review routes remain in routes/findings.py. This owner
needs no dashboard composition context or provider clients.
"""

from __future__ import annotations

import json
import uuid

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field, StrictInt

from cremore.api.finding_presenters import detail_credential
from cremore.api.http_support import unsafe_text
from cremore.config import Settings
from cremore.db.annotation_store import AnnotationStore
from cremore.db.repository import Repository
from cremore.db.scan_state import SEVERITY_RANK
from cremore.domain.models import FindingEvent
from cremore.scanning.learned_fp import LearnedFPService


class ResolveRequest(BaseModel):
    resolution: str = Field(default="", max_length=500)


class AssignRequest(BaseModel):
    assignee: str | None = Field(default=None, max_length=200)  # operator subject id, or null to unassign
    person_ref: uuid.UUID | None = None
    team: str | None = Field(default=None, max_length=100)
    expected_version: StrictInt | None = Field(default=None, ge=0)


class ReasonRequest(BaseModel):
    reason_code: str = Field(default="", max_length=500)



class BulkTriageRequest(BaseModel):
    """Several findings judged together; each is still recorded on its own."""

    finding_ids: list[uuid.UUID] = []
    reason_code: str = Field(default="", max_length=500)


def register_reads(app: FastAPI, repo: Repository, settings: Settings, require_auth) -> None:
    @app.get("/api/v1/findings")
    def list_findings(
        response: Response,
        _actor: str = Depends(require_auth),
        severity: str | None = None,
        workflow_status: str | None = None,
        provider: str | None = None,
        limit: int = Query(default=200, ge=1, le=500),
        cursor: uuid.UUID | None = None,
    ) -> list[dict]:
        from cremore.api.finding_presenters import present_finding as _dashboard_finding

        page = repo.list_findings(limit=limit + 1, after=cursor)
        if len(page) > limit:
            response.headers["X-Next-Cursor"] = str(page[limit - 1].id)
        response.headers["X-Page-Limit"] = str(limit)
        # Bound dependent rows before model materialization as well. A partial
        # exposure set cannot be presented as a complete finding summary.
        rows = repo.findings_with_exposures([f.id for f in page[:limit]], exposure_limit=10_001)
        if sum(len(exposures) for _, _, exposures in rows) > 10_000:
            raise HTTPException(status_code=413, detail="FINDING_PAGE_TOO_LARGE: request fewer findings")
        out = []
        response_bytes = 2
        for finding, cred, exposures in rows:
            summary = _dashboard_finding(
                finding, cred, exposures, owner_review=repo.get_ownership_review(finding.id), settings=settings
            )
            if severity and summary["severity"] != severity.upper():
                continue
            if workflow_status and summary["workflow_status"] != workflow_status.upper():
                continue
            if provider and summary["provider"] != provider:
                continue
            response_bytes += len(json.dumps(jsonable_encoder(summary), ensure_ascii=False).encode("utf-8")) + 1
            if response_bytes > 8 * 1024 * 1024:
                raise HTTPException(status_code=413, detail="FINDING_PAGE_TOO_LARGE: request fewer findings")
            out.append(summary)
        # Effective severity and filters retain their projection semantics within
        # this stable ID page; callers follow X-Next-Cursor even for an empty page.
        out.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], -1), reverse=True)
        return out

    @app.get("/api/v1/stats")
    def stats(_actor: str = Depends(require_auth)) -> dict:
        grouped = repo.finding_stats()
        total = sum(grouped["by_severity"].values())
        # Open = everything not resolved; the dashboard's headline number.
        open_count = total - grouped["by_workflow_status"].get("RESOLVED", 0)
        return {
            "total": total,
            "open": open_count,
            **grouped,
        }

    @app.get("/api/v1/findings/{finding_id}")
    def get_finding(finding_id: uuid.UUID, _actor: str = Depends(require_auth)) -> dict:
        finding = repo.get_finding(finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="finding not found")
        from cremore.api.finding_evidence import (
            credential_metadata,
            detection_details,
            exposure_path,
            merged_locations,
            removal_pending,
            source_location,
        )
        from cremore.api.finding_presenters import present_finding as _dashboard_finding
        from cremore.api.governance_presenters import present_action as _action_public
        from cremore.api.governance_presenters import present_review as _review_public

        cred = repo.get_credential(finding.credential_id)
        exposures = repo.exposures_for_credential(finding.credential_id)
        from cremore.risk.verification import latest_verification

        verification = latest_verification(exposures, cred)
        from cremore.api.credential_components import component_evidence

        # Built before the projection: a partial AWS observation takes its
        # verification from a complete pair that holds the same component.
        component = component_evidence(repo, cred, exposures)
        detail = _dashboard_finding(
            finding, cred, exposures, owner_review=repo.get_ownership_review(finding_id), settings=settings,
            verification=verification, component=component,
        )
        # The account investigations run in: the verified key owner's connected
        # account (cremore_aws_provider.aws_sessions routing), else the account the key was found through.
        from cremore_aws_provider.aws_sessions import account_of_arn

        owner = account_of_arn(cred.principal_arn) if cred else None
        account = next((a for a in repo.list_aws_accounts() if owner and a.account_id == owner), None) or (
            repo.get_aws_account(cred.aws_account_id) if cred and cred.aws_account_id else None
        )
        locations = merged_locations(exposures)
        metadata = credential_metadata(cred, exposures, verification=verification) if cred else {}
        primary_id = detail["primary_exposure_id"]
        detail.update(
            {
                "primary_exposure_id": str(primary_id),
                "component_evidence": component,
                # Credential identity in the dashboard's FindingDetail shape, never
                # the raw secret or identifier.
                "credential": {**detail_credential(cred), "governance": detail["governance"],
                               "credential_metadata": metadata} if cred else None,
                # The six stages, each from the evidence gathered above; a stage
                # nobody collected reports that rather than reading as safe.
                "exposure_path": exposure_path(cred, exposures, finding=finding,
                                               verification=verification, metadata=metadata),
                "source_scope": {
                    "id": detail.get("scope_id", ""),
                    "name": detail.get("scope_name", ""),
                    "type": detail.get("scope_type", ""),
                },
                "aws_account": {
                    "id": str(account.id),
                    "name": account.name,
                    "environment": account.environment,
                }
                if account
                else None,
                "exposures": [
                    {
                        **e.model_dump(mode="json"),
                        "metadata": {key: value for key, value in e.metadata.items()
                                     if key != "issuer_comparison" and not key.endswith("fingerprint")},
                        "provider": cred.provider if cred else "",
                        "scope_id": str(e.source_connection_id or e.aws_account_id or ""),
                        "scope_name": e.resource_name,
                        # every connection that found this same location
                        "source_connection_ids": sorted({str(r.source_connection_id or r.aws_account_id or "") for r in rows} - {""}),
                        "removal_pending": removal_pending(e, rows),
                        "detection_details": detection_details(e, cred, occurrences=len(locations), verification=verification),
                        "source_location": source_location(e),
                    }
                    for e, rows in locations
                ],
                "events": [e.model_dump(mode="json") for e in repo.list_finding_events(finding_id)],
                "reviews": [
                    _review_public(r) for r in repo.list_reviews() if r.finding_id == finding_id
                ],
                "management_actions": [
                    _action_public(a)
                    for a in repo.list_management_actions()
                    if a.finding_id == finding_id
                ],
            }
        )
        return detail


def register_triage(app: FastAPI, repo: Repository, learned_fp: LearnedFPService,
                    require_auth, require_role) -> None:
    def _validate_note(value):
        from cremore.api.routes.credentials import _credentials_in
        from cremore.detection.safe_text import safe_fact_text

        if value and (unsafe_text(value, newlines=True) or safe_fact_text(value.replace("\n", " ")) is None
                      or _credentials_in(app.state.orchestrator, value)):
            raise HTTPException(status_code=422, detail="TRIAGE_NOTE_INVALID: use a short note without credentials")

    def _transition(finding_id, to_status, actor, *, event_type, resolution=None, note=None):
        _validate_note(resolution)
        _validate_note(note)
        before = repo.get_finding(finding_id)
        if before is None:
            raise HTTPException(status_code=404, detail="finding not found")
        # Capture the prior status as a value: the in-memory store returns a live
        # reference that update_finding_status mutates in place.
        from_status = before.workflow_status
        finding = repo.update_finding_status(finding_id, to_status, resolution=resolution)
        # A transition ends the review stage an acknowledged finding was in.
        AnnotationStore(repo).clear_stage(finding_id, actor)
        repo.record_finding_event(
            FindingEvent(
                finding_id=finding_id,
                actor=actor,
                event_type=event_type,
                from_status=from_status,
                to_status=to_status,
                note=note or resolution,
            )
        )
        return finding

    @app.post("/api/v1/findings/{finding_id}/acknowledge")
    def acknowledge_finding(
        finding_id: uuid.UUID, actor: str = Depends(require_role("analyst"))
    ) -> dict:
        finding = _transition(finding_id, "ACKNOWLEDGED", actor, event_type="ACKNOWLEDGED")
        return {"id": str(finding.id), "workflow_status": finding.workflow_status}

    @app.post("/api/v1/findings/{finding_id}/resolve")
    def resolve_finding(
        finding_id: uuid.UUID, body: ResolveRequest, actor: str = Depends(require_role("analyst"))
    ) -> dict:
        finding = _transition(
            finding_id, "RESOLVED", actor, event_type="RESOLVED", resolution=body.resolution
        )
        return {
            "id": str(finding.id),
            "workflow_status": finding.workflow_status,
            "resolution": finding.resolution,
        }

    @app.post("/api/v1/findings/{finding_id}/reopen")
    def reopen_finding(
        finding_id: uuid.UUID, body: ResolveRequest, actor: str = Depends(require_role("analyst"))
    ) -> dict:
        _validate_note(body.resolution)
        before = repo.get_finding(finding_id)
        # Reopening a finding a learned profile auto-triaged contradicts the
        # profile: it is deactivated and re-learned from scratch.
        contradicted = learned_fp.record_contradiction(before) if before is not None else None
        finding = _transition(
            finding_id, "OPEN", actor, event_type="REOPENED", note=body.resolution
        )
        out = {"id": str(finding.id), "workflow_status": finding.workflow_status}
        if contradicted is not None:
            out["learned_fp_profile_deactivated"] = str(contradicted.id)
        return out

    @app.post("/api/v1/findings/{finding_id}/false-positive")
    def false_positive_finding(
        finding_id: uuid.UUID, body: ReasonRequest, actor: str = Depends(require_role("analyst"))
    ) -> dict:
        """Analyst judgement: the match is not a credential. Audited; reopenable."""

        finding = _transition(
            finding_id,
            "FALSE_POSITIVE",
            actor,
            event_type="FALSE_POSITIVE",
            note=body.reason_code or "FALSE_POSITIVE_CONFIRMED",
        )
        samples = learned_fp.record_false_positive(finding, actor)
        return {
            "id": str(finding.id),
            "workflow_status": finding.workflow_status,
            "learned_fp_samples": samples,
        }

    @app.post("/api/v1/findings/false-positive")
    def false_positive_findings(
        body: BulkTriageRequest, actor: str = Depends(require_role("analyst"))
    ) -> dict:
        """Confirm several findings as false positives in one analyst action.

        Each finding still transitions one at a time and is audited individually,
        exactly as the single-finding route does: this saves the clicking, not the
        judgement or its record. Ids that do not exist are reported rather than
        failing the batch, so one stale id cannot block the rest.
        """

        ids = list(dict.fromkeys(body.finding_ids))
        if not ids or len(ids) > 200:
            raise HTTPException(status_code=422, detail="finding_ids must hold 1-200 unique ids")
        confirmed, missing, samples = [], [], 0
        for finding_id in ids:
            try:
                finding = _transition(
                    finding_id, "FALSE_POSITIVE", actor, event_type="FALSE_POSITIVE",
                    note=body.reason_code or "FALSE_POSITIVE_CONFIRMED")
            except HTTPException as failure:
                if failure.status_code != 404:
                    raise
                missing.append(str(finding_id))
                continue
            samples += learned_fp.record_false_positive(finding, actor)
            confirmed.append(str(finding.id))
        return {"confirmed": confirmed, "missing": missing,
                "confirmed_count": len(confirmed), "learned_fp_samples": samples}

    @app.post("/api/v1/findings/{finding_id}/ignore")
    def ignore_finding(
        finding_id: uuid.UUID, body: ReasonRequest, actor: str = Depends(require_role("analyst"))
    ) -> dict:
        """Accepted / out of scope by decision. Audited; reopenable."""

        finding = _transition(
            finding_id, "IGNORED", actor, event_type="IGNORED", note=body.reason_code or "TRIAGED"
        )
        return {"id": str(finding.id), "workflow_status": finding.workflow_status}

    @app.post("/api/v1/findings/{finding_id}/assign")
    def assign_finding(
        finding_id: uuid.UUID, body: AssignRequest, actor: str = Depends(require_role("analyst"))
    ) -> dict:
        before = repo.get_finding(finding_id)
        if before is None:
            raise HTTPException(status_code=404, detail="finding not found")
        if "person_ref" in body.model_fields_set:
            from cremore.governance import response, response_routing

            if body.assignee is not None:
                raise HTTPException(status_code=422, detail="RESPONSE_RECIPIENT_MISMATCH")
            team = (body.team or "").strip() or None
            _validate_note(team)
            try:
                result = response_routing.assign(repo, app.state.settings, finding_id, actor,
                    person_ref=body.person_ref, team=team, expected_version=body.expected_version)
            except response.ResponseError as exc:
                raise HTTPException(status_code=exc.http_status, detail=exc.code) from None
            return {"id": str(finding_id), "assigned_to": repo.get_finding(finding_id).assigned_to, **result}
        if getattr(app.state.settings, "auth_mode", "local") == "oidc":
            raise HTTPException(status_code=422, detail="RESPONSE_PERSON_REQUIRED")

        # The name goes into the audit trail, which is never rewritten: one line of plain text, nothing secret-shaped.
        _validate_note(body.assignee)
        if body.assignee is not None and unsafe_text(body.assignee):
            raise HTTPException(status_code=422, detail="ASSIGNEE_INVALID: one line of plain text up to 200 characters, no secret values")
        finding = repo.assign_finding(finding_id, body.assignee)
        repo.record_finding_event(
            FindingEvent(
                finding_id=finding_id,
                actor=actor,
                event_type="ASSIGNED",
                note=f"assigned to {body.assignee}" if body.assignee else "unassigned",
            )
        )
        return {"id": str(finding.id), "assigned_to": finding.assigned_to}

    @app.get("/api/v1/findings/{finding_id}/events")
    def list_events(finding_id: uuid.UUID, _actor: str = Depends(require_auth)) -> list[dict]:
        if repo.get_finding(finding_id) is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return [e.model_dump(mode="json") for e in repo.list_finding_events(finding_id)]
