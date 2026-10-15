"""Findings and the credentials behind them, including ownership review.

Registered by the dashboard composition root. Shared behavior is imported
from independent API libraries; dependencies arrive through DashboardContext.
"""

from __future__ import annotations

import datetime as _dt
import uuid

from cremore_aws_provider import aws_access, aws_identity
from cremore_aws_provider.aws_sessions import account_of_arn
from cremore_aws_provider.investigation import investigation_switches
from fastapi import Depends, Query, Response
from fastapi.responses import JSONResponse

from cremore.api.auth import Principal
from cremore.api.aws_support import access_key_metadata as _access_key_metadata
from cremore.api.finding_presenters import REVIEW_REASONS as _REVIEW_REASONS
from cremore.api.finding_presenters import REVIEW_STATUSES as _REVIEW_STATUSES
from cremore.api.finding_presenters import default_owner_review as _default_owner_review
from cremore.api.finding_presenters import present_finding as _dashboard_finding
from cremore.api.finding_presenters import present_owner_review as _owner_review_public
from cremore.api.http_support import http_error as _http
from cremore.api.http_support import isoformat as _iso
from cremore.api.http_support import page_rows, unsafe_text
from cremore.api.http_support import parse_uuid as _uuid
from cremore.api.http_support import utc_now as _now
from cremore.api.route_context import DashboardContext
from cremore.api.search_service import search_payload
from cremore.domain.models import OwnershipReview, ScopePlan
from cremore.governance import ownership
from cremore.remediation.action_plans import ActionPlanError
from cremore.scanning import scope as _scope


def register(ctx: DashboardContext) -> None:
    _account_session, _plan_error, _profile_or_404, _profiles_with_state = ctx._account_session, ctx._plan_error, ctx._profile_or_404, ctx._profiles_with_state
    _scope_error, _scope_plan_or_404, _scope_target, _secret_metadata = ctx._scope_error, ctx._scope_plan_or_404, ctx._scope_target, ctx._secret_metadata
    _start_run, action_plans, app = ctx._start_run, ctx.action_plans, ctx.app
    catalog_store, potential_access_factory, repo, require_auth = ctx.catalog_store, ctx.potential_access_factory, ctx.repo, ctx.require_auth
    require_principal, require_role, secret_metadata_factory = ctx.require_principal, ctx.require_role, ctx.secret_metadata_factory
    settings, usage_service_factory = ctx.settings, ctx.usage_service_factory

    def _management_public(cred) -> dict:
        allowed = settings.secret_manager_reference_list
        reference = cred.management_reference or None
        if not allowed:
            status, match, reason = "NO_MANAGER_CONNECTED", "UNKNOWN", "NO_MANAGER_CONNECTED_TO_THIS_INSTALLATION"
        elif reference:
            status, match, reason = "MANAGED_MATCHED", "POSSIBLE_MATCH", "ADMIN_DECLARATION_NOT_EXACT_CREDENTIAL_MATCH"
        else:
            status, match, reason = "UNKNOWN", "UNKNOWN", "NO_ADMIN_DECLARATION"
        return {
            "credential_id": str(cred.id), "mode": "REAL", "provider_changed": False, "secret_value_returned": False,
            "revision": int(cred.management_revision or 0), "status": status, "match_status": match, "reason": reason,
            "updated_at": _iso(cred.management_updated_at),
            **({"reference": reference} if reference else {}),
            "can_read_metadata": bool(reference and secret_metadata_factory is not None
                                      and investigation_switches.effective(
                                          settings, repo, investigation_switches.SECRETS_INVENTORY)),
        }

    @app.get("/api/v1/credentials/{credential_id}/management")
    def credential_management(credential_id: str, _actor: str = Depends(require_auth)) -> dict:
        return _management_public(_credential_or_404(credential_id))

    @app.put("/api/v1/credentials/{credential_id}/management")
    def set_credential_management(credential_id: str, body: dict, _actor: str = Depends(require_role("admin"))) -> dict:
        """Declare which allowlisted Secrets Manager ARN may hold this credential.
        Platform metadata only: nothing is created, rotated or revoked."""

        cred = _credential_or_404(credential_id)
        reference = str((body or {}).get("reference") or "").strip()
        if reference not in settings.secret_manager_reference_list:
            raise _http(422, "reference must be one of the installation's allowlisted Secrets Manager ARNs")
        if (body or {}).get("revision") != int(cred.management_revision or 0):
            raise _http(409, "MANAGEMENT_REVISION_CONFLICT: management mapping changed since it was read")
        updated = repo.update_credential(cred.id, management_reference=reference,
                                         management_revision=int(cred.management_revision or 0) + 1,
                                         management_updated_at=_now())
        return _management_public(updated)

    @app.delete("/api/v1/credentials/{credential_id}/management")
    def clear_credential_management(credential_id: str, body: dict | None = None,
                                    _actor: str = Depends(require_role("admin"))) -> dict:
        cred = _credential_or_404(credential_id)
        if (body or {}).get("revision") != int(cred.management_revision or 0):
            raise _http(409, "MANAGEMENT_REVISION_CONFLICT: management mapping changed since it was read")
        updated = repo.update_credential(cred.id, management_reference=None,
                                         management_revision=int(cred.management_revision or 0) + 1,
                                         management_updated_at=_now())
        return _management_public(updated)

    @app.get("/api/v1/credentials/{credential_id}/management/metadata")
    def credential_management_metadata(credential_id: str, _actor: str = Depends(require_role("admin"))) -> dict:
        cred = _credential_or_404(credential_id)
        if not cred.management_reference:
            raise _http(422, "no secret-manager reference is declared for this credential")
        if getattr(settings, "isolated_deployment", False):
            from cremore.api.aws_support import queue_aws_read
            return queue_aws_read(repo, settings, "secret-metadata", _actor, {"kind": "credential", "id": str(cred.id)})
        return {"credential_id": str(cred.id), "reference_revision": int(cred.management_revision or 0),
                "match_status": "POSSIBLE_MATCH", "match_basis": "ADMIN_CONFIGURED",
                **_secret_metadata(cred.management_reference)}

    @app.get("/api/v1/search")
    def unified_search(q: str = "", limit: int = 10,
                       principal: Principal = Depends(require_principal)) -> dict:
        """One search across the objects a reader can already list."""

        if limit < 1 or limit > 50:
            raise _http(422, "limit must be between 1 and 50")
        return search_payload(repo, getattr(principal, "role", "") or "viewer", q, limit)

    @app.get("/api/v1/credentials")
    def credentials(response: Response, _actor: str = Depends(require_auth),
                    limit: int = Query(default=200, ge=1, le=500), cursor: uuid.UUID | None = None) -> list[dict]:
        out = []
        for finding in page_rows(repo.list_findings(limit=limit + 1, after=cursor), response, limit):
            cred = repo.get_credential(finding.credential_id)
            if cred is None:
                continue
            out.append({
                "id": str(cred.id),
                "credential_type": cred.credential_type,
                "provider": cred.provider,
                "identifier_hint": cred.identifier_hint,
                "credential_status": cred.credential_status,
                "principal_name": cred.principal_name,
                "business_owner": cred.business_owner,
                "team": cred.team,
            })
        return out

    @app.get("/api/v1/exposure-surface")
    def exposure_surface(response: Response, _actor: str = Depends(require_auth),
                         limit: int = Query(default=200, ge=1, le=500), cursor: uuid.UUID | None = None) -> dict:
        """Open findings grouped by the identity their credential belongs to."""

        from cremore.api.exposure_surface import surface

        rows = []
        page = page_rows(repo.list_findings(limit=limit + 1, after=cursor), response, limit)
        joined = repo.findings_with_exposures([f.id for f in page], exposure_limit=10_001)
        if sum(len(exposures) for _, _, exposures in joined) > 10_000:
            raise _http(413, "FINDING_PAGE_TOO_LARGE: request fewer findings")
        for finding, cred, exposures in joined:
            row = _dashboard_finding(finding, cred, exposures,
                                     owner_review=repo.get_ownership_review(finding.id), settings=settings)
            # Every place this credential was found, not only the primary one.
            rows.append({**row, "source_types": sorted({e.source_type for e in exposures if e.source_type})})
        return surface(rows)

    def _credential_or_404(credential_id: str):
        cred = repo.get_credential(_uuid(credential_id, "credential_id"))
        if cred is None:
            raise _http(404, "credential not found")
        return cred

    @app.get("/api/v1/credentials/{credential_id}/usage")
    def credential_usage(credential_id: str, _actor: str = Depends(require_auth)) -> dict:
        # Calls are labelled with the technique they belong to at read time, so a
        # snapshot saved before the mapping existed is labelled the same way.
        from cremore_aws_provider.investigation.usage import classify_events, empty_usage

        from cremore.coverage.credential_usage import public_job

        cred = _credential_or_404(credential_id)
        snapshot = dict(cred.usage_snapshot or empty_usage(cred.identifier or ""))
        if refresh_job := public_job(repo, cred):
            snapshot["refresh_job"] = refresh_job
        if snapshot["collection_status"] == "NOT_COLLECTED":
            return classify_events(snapshot)
        owner = account_of_arn(cred.principal_arn)
        if not owner or snapshot.get("collected_account_id") != owner:
            # Recorded before collections named their account (or for another
            # owner): shown, but never as complete evidence until re-collected.
            return classify_events({**snapshot, "collection_status": "ACCOUNT_UNVERIFIED",
                                    "recorded_collection_status": snapshot.get("collection_status"),
                                    "account_verified": False})
        return classify_events({**snapshot, "account_verified": True})

    @app.post("/api/v1/credentials/{credential_id}/usage/refresh")
    def refresh_credential_usage(credential_id: str, background: bool = False,
                                 _actor: str = Depends(require_role("analyst"))):
        """Look up the key's observed use now (read-only AWS calls) and store the snapshot."""

        from cremore_aws_provider.investigation.usage import (
            potential_access_view,
            require_usage_session,
        )

        cred = _credential_or_404(credential_id)
        if cred.provider != "aws" or not cred.identifier or not cred.identifier.startswith(("AKIA", "ASIA")):
            raise _http(422, "observed-use lookup applies to discovered AWS access keys")
        if usage_service_factory is None or not investigation_switches.effective(
                settings, repo, investigation_switches.USAGE_LOOKUP):
            raise _http(501, "USAGE_LOOKUP_OFF: observed-use lookup is switched off for this installation "
                             "(needs cloudtrail:LookupEvents, ec2:DescribeRegions, iam:GetAccessKeyLastUsed)")
        # CloudTrail history and IAM last-used live in the key owner's account.
        # An identifier alone must not trigger an IAM sweep of every connected
        # account. Reuse exact current inventory evidence, or keep it unknown.
        owner_arn, owner_user, owner_evidence = cred.principal_arn or "", "", None
        if not owner_arn or cred.principal_arn_source == "IAM_INVENTORY":
            from cremore_aws_provider.inventory_view import key_owner

            resolved = key_owner(repo, cred.identifier, settings=settings)
            if resolved is None or (owner_arn and resolved[0].principal_arn != owner_arn):
                raise _http(409, "ACCOUNT_OWNER_UNKNOWN: current IAM inventory does not establish a unique owner. "
                                 "Refresh the owning account's IAM inventory, or verify the complete key pair first.")
            owner, owner_evidence = resolved
            owner_arn, owner_user = owner.principal_arn, owner.user_name
            account_id = owner.account_id
        else:
            account_id = account_of_arn(owner_arn)
        session = _account_session(account_id, aws_access.SCANNER)
        from cremore.coverage.credential_usage import enqueue, job_for
        from cremore.db.settings_store import locked_settings
        from cremore.domain.models import ACTIVE_JOB_STATUSES

        if background or getattr(settings, "isolated_deployment", False):
            queued = enqueue(repo, settings, cred, session, owner_arn, owner_user, owner_evidence=owner_evidence)
            return JSONResponse({"job_id": str(queued.id), "status": queued.status}, status_code=202)
        active = job_for(repo, cred)
        previous_job_id = (cred.usage_snapshot or {}).get("refresh_job_id")
        if active and active.status in ACTIVE_JOB_STATUSES:
            raise _http(409, "USAGE_COLLECTION_RUNNING: a background collection is already running")
        try:
            usage = usage_service_factory(session)
            snapshot = {**usage.collect(cred.identifier, owner_arn), **session.evidence()}
            require_usage_session(snapshot)
            if owner_evidence:
                snapshot["owner_lookup"] = owner_evidence
            if owner_arn:
                from cremore_aws_provider.investigation.identity_policies import (
                    collect_identity_policies,
                )

                # Read with the owner-account scanner session, never the found key.
                snapshot["identity_policies"] = collect_identity_policies(session.client("iam"), owner_arn)
            # Observed use being on is not permission to simulate what the principal could reach.
            if (potential_access_factory is not None and owner_arn
                    and investigation_switches.effective(settings, repo, investigation_switches.POTENTIAL_ACCESS)):
                # The policies just read name the resources the simulation checks beyond ``*``.
                snapshot["potential_access"] = potential_access_view(potential_access_factory(session).collect(
                    owner_arn, identity_policies=snapshot["identity_policies"]))
            snapshot["access_key"] = _access_key_metadata(session, cred, owner_user)
            require_usage_session(snapshot)
            last = usage.last_used(cred.identifier)
            snapshot["last_used"] = last.snapshot()
        except Exception as exc:
            if aws_identity.is_login_required(exc):
                raise _http(409, "AWS_LOGIN_REQUIRED: CreMore's AWS session is unavailable; sign in again. "
                                 "Previously saved evidence and collection times were not changed.") from None
            raise
        changes: dict = {"usage_snapshot": snapshot}
        if owner_arn and not cred.principal_arn:
            # Learned from saved IAM inventory, not by verifying the key.
            # principal_arn_source keeps that provenance with the value so the
            # governance projection never reports it as a provider verification.
            changes.update(principal_arn=owner_arn, principal_arn_source="IAM_INVENTORY",
                           **({"principal_name": owner_user} if owner_user else {}))
        # IAM's own status for this exact key. Only the two documented values are
        # taken; "NOT_FOUND" is a listing outcome, not a provider lifecycle state.
        if key_status := {"Active": "Active", "Inactive": "Inactive"}.get(
                str(snapshot["access_key"].get("status") or "")):
            changes["credential_status"] = key_status
        if snapshot["access_key"].get("created_at"):
            changes["credential_created_at"] = _dt.datetime.fromisoformat(snapshot["access_key"]["created_at"])
        if last.status == "AVAILABLE" and last.at is not None:
            changes.update(last_used_at=last.at, last_used_service=last.service or None,
                           last_used_region=last.region or None)
        with locked_settings(repo, account_id=account_id) as bound:
            current = bound.get_credential(cred.id)
            active = job_for(bound, current)
            if ((active and active.status in ACTIVE_JOB_STATUSES)
                    or (current.usage_snapshot or {}).get("refresh_job_id") != previous_job_id):
                raise _http(409, "USAGE_COLLECTION_RUNNING: a background collection is already running")
            bound.update_credential(cred.id, **changes)
        return snapshot

    @app.get("/api/v1/credentials/{credential_id}/action-plans")
    def list_action_plans(credential_id: str, _actor: str = Depends(require_auth)) -> dict:
        cred = _credential_or_404(credential_id)
        return {"plans": [action_plans.public(p) for p in repo.list_action_plans(cred.id)],
                "policy": action_plans.policy(cred)}

    @app.post("/api/v1/credentials/{credential_id}/action-plans", status_code=201)
    def create_action_plan(credential_id: str, body: dict, actor: str = Depends(require_role("remediator"))) -> dict:
        """Bind an IAM key action (disable / delete / rotation phase) to a plan
        hash. Nothing touches AWS: a different Admin must approve (a single
        shared-token operator re-confirms instead), then execution is requested
        against the same hash."""

        cred = _credential_or_404(credential_id)
        account = next((a for a in repo.list_aws_accounts()
                        if a.account_id == action_plans._iam_user(cred.principal_arn or "")[1]), None)
        try:
            plan = action_plans.create(cred, str(account.id) if account else "", actor, body)
        except ActionPlanError as exc:
            raise _plan_error(exc)
        return action_plans.public(plan)

    @app.get("/api/v1/findings/{finding_id}/ownership-review")
    def ownership_review(finding_id: str, _actor: str = Depends(require_auth)) -> dict:
        fid = _uuid(finding_id, "finding_id")
        if repo.get_finding(fid) is None:
            raise _http(404, "finding not found")
        review = repo.get_ownership_review(fid)
        return {
            "finding_id": str(fid),
            "review": _owner_review_public(review) if review else _default_owner_review(),
            # The owners the exposed file's CODEOWNERS names, as the finding-context job read them.
            "context": ownership.review_context(ownership.ContextStore(repo).get(fid)),
        }

    @app.get("/api/v1/findings/{finding_id}/context")
    def finding_context(finding_id: str, _actor: str = Depends(require_role("analyst"))) -> dict:
        """Each exposed file's owners/author and provider-reported collaborators or members, with limits."""
        fid = _uuid(finding_id, "finding_id")
        if repo.get_finding(fid) is None:
            raise _http(404, "finding not found")
        return ownership.public(ownership.ContextStore(repo).get(fid), ownership._active(repo, fid))

    @app.post("/api/v1/findings/{finding_id}/context", status_code=202)
    def collect_finding_context(finding_id: str, _actor: str = Depends(require_role("analyst"))) -> dict:
        """Read it again now, with each source connection's own credential (one job per finding)."""
        fid = _uuid(finding_id, "finding_id")
        if repo.get_finding(fid) is None:
            raise _http(404, "finding not found")
        job = ownership.enqueue(repo, fid)
        return ownership.public(ownership.ContextStore(repo).get(fid), job)

    @app.post("/api/v1/ownership-reviews/bulk")
    def ownership_reviews_bulk(body: dict, actor: str = Depends(require_role("analyst"))) -> dict:
        """Apply one review state to up to 100 findings. Every item carries the
        revision it was read at; a stale revision rejects the whole request."""

        items = body.get("items")
        if not isinstance(items, list) or not items or len(items) > 100:
            raise _http(422, "items must hold 1..100 {finding_id, revision} entries")
        status = body.get("status")
        if status not in _REVIEW_STATUSES:
            raise _http(422, f"status must be one of {', '.join(_REVIEW_STATUSES)}")
        raw_team = body.get("assigned_team")
        if raw_team is not None and not isinstance(raw_team, str):
            raise _http(422, "ASSIGNED_TEAM_INVALID: assigned_team is text")
        team = (raw_team or "").strip()
        from cremore.api.routes.credentials import _credentials_in

        # The team goes into the audit trail, which is never rewritten: one line, nothing that reorders or hides
        # text, nothing secret-shaped.
        if unsafe_text(team):
            raise _http(422, "TEXT_CONTROL_CHARACTERS: assigned_team must be one line of plain text")
        if len(team.encode("utf-8")) > 128:
            raise _http(422, "ASSIGNED_TEAM_TOO_LONG: assigned_team must be at most 128 bytes")
        if _credentials_in(app.state.orchestrator, team):
            raise _http(422, "TEXT_CONTAINS_CREDENTIAL: assigned_team looks like it holds a secret value")
        if status != "OPEN" and not team:
            raise _http(422, "assigned_team is required unless the review is OPEN")
        due_raw = body.get("due_at")
        due_at = None
        if due_raw:
            try:
                due_at = _dt.datetime.fromisoformat(str(due_raw).replace("Z", "+00:00"))  # noqa: FURB162 -- Preserve rejection of misplaced Z markers in the established timestamp contract.
            except ValueError:
                raise _http(422, "due_at must be an ISO-8601 timestamp")
        if status == "WAITING_OWNER" and due_at is None:
            raise _http(422, "due_at is required while waiting for the owner")
        reason = str(body.get("closed_reason") or "")
        if status == "CLOSED" and reason not in _REVIEW_REASONS:
            raise _http(422, f"closed_reason must be one of {', '.join(_REVIEW_REASONS)}")
        if status != "CLOSED":
            reason = ""

        planned = []
        seen: set = set()
        for item in items:
            if not isinstance(item, dict):
                raise _http(422, "each item must hold a finding_id and revision")
            fid = _uuid(item.get("finding_id"), "finding_id")
            revision = item.get("revision")
            if fid in seen or type(revision) is not int or revision < 0:
                raise _http(422, "each item needs a unique finding_id and a non-negative revision")
            seen.add(fid)
            if repo.get_finding(fid) is None:
                raise _http(422, f"finding {fid} not found")
            planned.append(OwnershipReview(
                finding_id=fid, status=status, assigned_team=team, due_at=due_at,
                closed_reason=reason, revision=revision + 1, updated_by=actor))
        saved = repo.save_ownership_reviews(planned, audit_actor=actor)
        if saved is None:
            raise _http(409, "REVIEW_REVISION_CONFLICT: a review changed since it was read")
        out = [{"finding_id": str(review.finding_id), "review": _owner_review_public(review)} for review in saved]
        return {"updated": len(out), "items": out}

    def _rescan_context(finding_id: str, exposure_id):
        finding = repo.get_finding(_uuid(finding_id, "finding_id"))
        if finding is None:
            raise _http(404, "finding not found")
        eid = _uuid(exposure_id, "exposure_id")
        exposure = next((e for e in repo.exposures_for_credential(finding.credential_id) if e.id == eid), None)
        if exposure is None:
            raise _http(404, "exposure not found on this finding")
        if exposure.source_connection_id is None:
            raise _http(422, "RESCAN_UNAVAILABLE: this exposure was not found through a registered connection")
        return finding, exposure

    @app.get("/api/v1/findings/{finding_id}/rescan-profiles")
    def rescan_profiles(finding_id: str, exposure_id: str, _actor: str = Depends(require_role("analyst"))) -> dict:
        """Approved, ready scope profiles of the connection an exposure was found through."""

        finding, exposure = _rescan_context(finding_id, exposure_id)
        cid = str(exposure.source_connection_id)
        _t, _p, enabled, auth, cuuid = _scope_target("source", cid)
        rows = [(p, s) for p, s in _profiles_with_state("source", cuuid, auth, enabled) if s == "READY"]
        return {"finding_id": str(finding.id), "exposure_id": str(exposure.id), "kind": "source", "connection_id": cid,
                "profiles": [_scope.profile_public(p, s) for p, s in rows[:100]]}

    @app.post("/api/v1/findings/{finding_id}/rescan-preview")
    def rescan_preview(finding_id: str, body: dict, _actor: str = Depends(require_role("analyst"))) -> dict:
        """A fixed plan for exactly the exposure's current location inside one approved profile."""

        finding, exposure = _rescan_context(finding_id, (body or {}).get("exposure_id"))
        profile = _profile_or_404((body or {}).get("profile_id"))
        if profile.kind != "source" or profile.connection_id != exposure.source_connection_id:
            raise _http(422, "RESCAN_OUT_OF_SCOPE: the profile belongs to a different connection")
        _t, _p, enabled, auth, cid = _scope_target("source", str(profile.connection_id))
        if _scope.profile_state(profile, auth=auth, enabled=enabled) != "READY":
            raise _http(409, "NEEDS_SCOPE_REVIEW: the profile is not ready; review it first")
        from cremore.source_config import RESOURCE_SOURCE
        resource_type = next((kind for kind, source in RESOURCE_SOURCE.items() if source == exposure.source_type), None)
        if resource_type is None:
            raise _http(422, "RESCAN_UNSUPPORTED_SOURCE: this location cannot be rescanned exactly")
        references = [exposure.resource_name]
        if exposure.source_type == "notion":
            page_id = _scope._notion_id(exposure.location)
            references = [page_id]
            if len(page_id) == 32 and all(c in "0123456789abcdef" for c in page_id.lower()):
                references.append(str(uuid.UUID(page_id)))
        ids = [_scope.resource_id("source", cid, resource_type, ref) for ref in references]
        catalog = catalog_store.selected("source", cid, ids)
        try:
            root, target = _scope.rescan_target(finding, exposure, profile, catalog)
        except _scope.ScopeError as exc:
            raise _scope_error(exc)
        verify = bool((body or {}).get("verify"))
        plan = repo.create_plan(ScopePlan(
            kind="source", connection_id=cid, profile_id=profile.id, profile_version=profile.version,
            catalog_snapshot_id=profile.catalog_snapshot_id, auth_revision=profile.auth_revision,
            policy_digest=_scope.policy_digest(profile, catalog.snapshot_id if catalog else "", auth,
                                               {"rescan": target, "verify": verify}),
            resources=[next(i for i in catalog.items if i["id"] == target["resource_id"])], roots=[root],
            known_count=1, unresolved_count=0, warnings=[], executable=True, trigger="RESCAN",
            rescan_target=target, verify=verify, expires_at=_now() + _scope.PLAN_TTL))
        return {"kind": "source", "connection_id": str(cid), "plan_id": str(plan.id), "profile_id": str(profile.id),
                "profile_version": profile.version, "policy_digest": plan.policy_digest,
                "expires_at": _iso(plan.expires_at), "executable": True, "known_count": 1, "rescan_target": target}

    @app.post("/api/v1/findings/{finding_id}/rescan", status_code=202)
    def rescan_finding(finding_id: str, body: dict, actor: str = Depends(require_role("analyst"))) -> dict:
        """Run the confirmed exact-location plan (trigger RESCAN)."""

        if (body or {}).get("confirm") is not True:
            raise _http(422, "confirm must be true")
        plan = _scope_plan_or_404((body or {}).get("plan_id"))
        if plan.trigger != "RESCAN" or (plan.rescan_target or {}).get("finding_id") != str(_uuid(finding_id, "finding_id")):
            raise _http(422, "RESCAN_PLAN_MISMATCH: the plan was not prepared for this finding")
        return _start_run(plan, (body or {}).get("profile_version"), actor)
