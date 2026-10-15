"""Connected AWS accounts: onboarding, discovery and the read-only investigations.

Registered by the dashboard composition root. Shared behavior is imported
from independent API libraries; dependencies arrive through DashboardContext.
"""

from __future__ import annotations

import datetime as _dt
import re
import secrets
import uuid

from cremore_aws_provider import (
    aws_access,
    aws_identity,
    aws_org_settings,
    aws_sso,
    aws_sso_settings,
)
from fastapi import Depends, HTTPException, Response

from cremore.api.aws_support import DISCOVERY_LIMIT as _DISCOVERY_LIMIT
from cremore.api.aws_support import (
    REMEDIATION_ROLE_NAME,
    SCANNER_ROLE_NAME,
    STACK_NAME,
    TEMPLATE_FILE,
)
from cremore.api.aws_support import hub_scope as _hub_scope
from cremore.api.aws_support import member_template_path as _member_template_path
from cremore.api.aws_support import partition as _partition
from cremore.api.aws_support import permission_set_options as _permission_set_options
from cremore.api.aws_support import present_approved_identity as _approved_public
from cremore.api.aws_support import present_aws_account as _aws_account_public
from cremore.api.aws_support import present_identity as _identity_public
from cremore.api.aws_support import quick_create_url as _quick_create_url
from cremore.api.aws_support import role_name as _role_name
from cremore.api.aws_support import sign_in_diagnosis as _sign_in_diagnosis
from cremore.api.http_support import actor_label as _actor_label
from cremore.api.http_support import http_error as _http
from cremore.api.http_support import isoformat as _iso
from cremore.api.http_support import logger as _log
from cremore.api.http_support import parse_uuid as _uuid
from cremore.api.route_context import DashboardContext

_ORGANIZATION_ID = re.compile(r"o-[a-z0-9]{10,32}")
# deploy/cloudformation/member-account-role.yaml's ExternalId, narrower than what the sweep itself accepts.
_TEMPLATE_EXTERNAL_ID = re.compile(r"[A-Za-z0-9+=,.@:/_-]{16,128}")
_STACKSET_PARAMETERS = "cremore-stackset-parameters.json"


def register(ctx: DashboardContext) -> None:
    _api_identity, _approvals, _aws_hold, _validate_account = ctx._api_identity, ctx._approvals, ctx._aws_hold, ctx._validate_account
    _worker_identity, app, aws_discovery_probe, aws_discovery_sweep = ctx._worker_identity, ctx.app, ctx.aws_discovery_probe, ctx.aws_discovery_sweep
    repo, require_auth, require_role, settings = ctx.repo, ctx.require_auth, ctx.require_role, ctx.settings

    def _approved_identity(purpose: str = aws_access.SCANNER) -> dict | None:
        approved = aws_access.approval(repo, purpose, settings)
        record = repo.get_setting(aws_access.APPROVAL_KEYS[purpose])
        if approved is not None and record:
            approved.update(approved_by=_actor_label(record["updated_by"]), approved_at=_iso(record["updated_at"]),
                            source="DASHBOARD")
        return approved

    def _account_public(a, approvals=None) -> dict:
        from cremore_aws_provider.aws_org_context import account_context
        from cremore_aws_provider.inventory_view import inventory_summary
        return {**_aws_account_public(a, _approvals() if approvals is None else approvals),
                "discovery_context": account_context(repo, a.account_id),
                "inventory_summary": inventory_summary(repo, a, settings=settings)}

    @app.post("/api/v1/aws/accounts/discover")
    def discover_now(source: str = "sso", actor: str = Depends(require_role("admin"))) -> dict:
        """Run one discovery sweep now, instead of waiting for the worker's poll.

        The same read-only sweep the worker runs, so a switch turned on in the
        dashboard has a visible result immediately rather than within the hour.
        Registers accounts and queues their checks; nothing in AWS is mutated.
        """
        source = (source or "").strip().lower()
        if source not in ("sso", "org"):
            raise _http(422, "source must be sso or org")
        if not getattr(settings, "sso_discovery_allowed" if source == "sso" else "org_discovery_allowed"):
            raise _http(409, "AWS_DISCOVERY_DISABLED")
        approved = _approved_identity()
        if approved is None:
            raise _http(409, "IDENTITY_NOT_APPROVED: approve the AWS identity CreMore runs as first")
        if getattr(settings, "isolated_deployment", False):
            from cremore.api.aws_support import queue_aws_read
            return queue_aws_read(repo, settings, "discover", actor, {"source": source})
        pending = aws_access.pending_validations(repo)

        def queue(account):
            aws_access.queue_validation(repo, account, aws_access.SCANNER, approved["revision"], pending)

        if source == "org" and not aws_org_settings.config(settings, repo)["external_id"]:
            raise _http(409, "EXTERNAL_ID_NOT_SET: set the StackSet's shared ExternalId first")
        try:
            result = aws_discovery_sweep(source, approved, queue) or {}
        except HTTPException:
            raise
        except aws_sso.SsoCacheNotWritable as exc:
            raise _http(409, "SSO_CACHE_NOT_WRITABLE: the Identity Center token cache must be writable so the "
                             "sign-in can be renewed") from exc
        except aws_identity.AwsLoginRequired:
            raise _http(409, "AWS_LOGIN_REQUIRED: sign in again on the computer running CreMore") from None
        except Exception as exc:  # Report discovery failures as safe codes.
            raise _http(409, f"{aws_identity.error_code(exc)}: the discovery sweep could not be completed") from exc
        from cremore.onboarding.adoption import adopt

        # What the sweep registered joins its connection now, not at the worker's next poll.
        adopted = adopt(repo, settings, actor)
        return {"source": source, **{k: result.get(k) for k in ("registered", "changed", "skipped", "error")},
                "adopted": len(adopted)}

    @app.get("/api/v1/aws/requests/{request_id}")
    def aws_request_result(request_id: str, principal=Depends(ctx.require_principal)):
        from fastapi.responses import JSONResponse

        from cremore.collectors.base import CollectorError
        from cremore.coverage import aws_requests
        ident = _uuid(request_id, "request_id")
        job = repo.get_job(ident)
        if (job is None or job.kind != aws_requests.JOB_KIND or job.payload.get("actor") != principal.subject):
            raise _http(404, "AWS_REQUEST_NOT_FOUND")
        if job.payload.get("operation") != "secrets-inventory" and principal.role != "admin":
            raise _http(403, "ADMIN_REQUIRED")
        try:
            status, result = aws_requests.result(repo, ident, principal.subject)
        except CollectorError:
            raise _http(404, "AWS_REQUEST_NOT_FOUND") from None
        if status == "SUCCEEDED":
            return result
        if status in ("FAILED", "CANCELLED"):
            raise _http(409, result["error_code"])
        return JSONResponse({"status": status, "request_id": str(ident),
                             "poll_url": f"/api/v1/aws/requests/{ident}"}, status_code=202)

    @app.get("/api/v1/aws/accounts")
    def aws_accounts(_actor: str = Depends(require_auth)) -> list[dict]:
        approvals = _approvals()
        return [_account_public(a, approvals) for a in repo.list_aws_accounts()]

    @app.get("/api/v1/aws/scanner-identity")
    def aws_scanner_identity(_actor: str = Depends(require_auth)) -> dict:
        """What the API and worker processes each run as, and what an Admin approved."""

        api = _api_identity()
        worker, stale = _worker_identity()
        approved = _approved_identity()
        partition = (approved or {}).get("partition") or api.get("partition") or "aws"
        both_ready = bool(worker) and not stale and api.get("state") == worker.get("state") == "READY"
        return {
            "identity_source": "collector" if getattr(settings, "isolated_deployment", False) else "api",
            "api": _identity_public(api),
            "worker": _identity_public(worker) if worker else None,
            # Why there is no sign-in, when there is none. describe() can only
            # report that fact; the three causes need different fixes and the
            # dashboard has to be able to say which one this is.
            "sign_in": _sign_in_diagnosis(settings, api),
            "worker_stale": stale,
            "same_identity": both_ready and api.get("match_key") == worker.get("match_key"),
            "approvable": aws_identity.approvable(api),
            "approved": _approved_public(approved),
            "hold": _aws_hold(),
            # Whether an Admin may sign in to IAM Identity Center from the console: on a single operator's install
            # only. A team install reaches AWS as the server (machine identity, an instance or pod role).
            "sign_in_here": settings.auth_mode == "local" and not getattr(settings, "isolated_deployment", False),
            "scanner_role_name": SCANNER_ROLE_NAME,
            "policy": aws_identity.hub_policy(partition, SCANNER_ROLE_NAME, **_hub_scope(repo)),
            # SSO_PERMISSION_SET accounts assume nothing, so the hub policy above
            # would leave a permission set unable to read a single object. What
            # that mode needs is the read-only work itself.
            "permission_set_policy": aws_identity.permission_set_policy(),
        }

    # IAM Identity Center sign-in from the dashboard (cremore_aws_provider.aws_sso_login): the device authorization
    # an admin approves in the AWS access portal. Its secret part (client secret, device code) stays sealed here,
    # bound to the admin who started it, until the token is saved in the SSO cache or the attempt ends.
    # Only on a single operator's install (AUTH_MODE=local; owner review and approval 2026-10-02): whoever approves
    # the code becomes the identity CreMore runs as, which on a team install would be one person's session.
    _SSO_LOGIN, _SSO_LOGIN_TTL = "aws_sso_login:", _dt.timedelta(minutes=15)
    _SSO_LOGIN_CLAIM = _dt.timedelta(seconds=30)  # a poll that died holding the attempt lets the next one in

    def _sso_login_allowed() -> None:
        if getattr(settings, "isolated_deployment", False):
            raise _http(409, "AWS_LOGIN_REQUIRES_WORKER")
        if settings.auth_mode != "local":
            raise _http(409, "AWS_SSO_LOGIN_SOLO_ONLY: a team install reaches AWS as the server (machine identity or "
                             "an instance or pod role), not through a person's sign-in from the console")

    def _sso_login_move(session_id: str, actor: str, expected: str, value: dict) -> bool:
        """Move the attempt on only from the state it was read in: a second poll finds it moved."""
        from cremore.db.settings_store import locked_settings

        key = _SSO_LOGIN + session_id
        with locked_settings(repo, setting_key=key) as bound:
            current = (bound.get_setting(key) or {}).get("value") or {}
            if current.get("actor") != actor or current.get("state") != expected:
                return False
            bound.put_setting(key, value, actor)
        return True

    def _sso_login_audit(session_id: str, actor: str, event: str, note: str | None = None) -> None:
        from cremore.domain.models import FindingEvent

        repo.record_finding_event(FindingEvent(target_type="aws_sso_login", target_id=uuid.UUID(session_id), actor=actor,
                                               event_type=event, note=note))

    @app.post("/api/v1/aws/sso-login/start")
    def start_aws_sso_login(response: Response, actor: str = Depends(require_role("admin"))) -> dict:
        """The code and link an admin approves in the AWS access portal, for the profile CreMore runs as."""
        from cremore_aws_provider import aws_sso_login

        from cremore.secretstore.sealed import seal_fields

        response.headers["Cache-Control"] = "no-store"
        # Abandoned attempts go first, also those a single operator's install left before it became a team install.
        repo.delete_settings_before(_SSO_LOGIN, _dt.datetime.now(_dt.UTC) - _SSO_LOGIN_TTL)
        _sso_login_allowed()
        # Only in place of a missing or expired sign-in: a working one is never replaced from here, since whoever
        # approves the code becomes the identity CreMore -- and the host's own CLI -- runs as.
        state = _api_identity(fresh=True).get("state")
        if state not in ("NO_CREDENTIALS", "LOGIN_REQUIRED") and _aws_hold() != "AWS_LOGIN_REQUIRED":
            raise _http(409, "AWS_SIGN_IN_PRESENT: CreMore already has a working AWS sign-in")
        try:
            shown, kept = aws_sso_login.begin(oidc_factory=getattr(app.state, "aws_sso_oidc_factory", None))
        except aws_sso_login.LoginError as exc:
            raise _http(409 if exc.code == "AWS_SSO_SESSION_REQUIRED" else 502, exc.code) from None
        session_id = str(uuid.uuid4())
        sealed = seal_fields(settings.sealing_keys, {key: str(value) for key, value in kept.items()})
        kept.clear()
        repo.put_setting(_SSO_LOGIN + session_id, {"actor": actor, "state": aws_sso_login.PENDING, "sealed": sealed}, actor)
        _sso_login_audit(session_id, actor, "AWS_SSO_LOGIN_STARTED", shown["start_url"])
        return {"session_id": session_id, **shown}

    @app.post("/api/v1/aws/sso-login/poll")
    def poll_aws_sso_login(body: dict, response: Response, actor: str = Depends(require_role("admin"))) -> dict:
        """Whether the admin approved yet (``PENDING``, ``DONE``, ``EXPIRED``, ``DENIED``, ``FAILED``)."""
        from cremore_aws_provider import aws_sso_login

        from cremore.secretstore.sealed import SealedSecretError, unseal

        response.headers["Cache-Control"] = "no-store"
        now = _dt.datetime.now(_dt.UTC)
        repo.delete_settings_before(_SSO_LOGIN, now - _SSO_LOGIN_TTL)  # abandoned attempts go with any poll
        _sso_login_allowed()
        session_id = (body or {}).get("session_id")
        try:
            session_id = str(uuid.UUID(str(session_id)))
        except ValueError:
            raise _http(404, "AWS_SSO_LOGIN_NOT_FOUND") from None
        record = repo.get_setting(_SSO_LOGIN + session_id)
        value = (record or {}).get("value") or {}
        if value.get("actor") != actor:
            raise _http(404, "AWS_SSO_LOGIN_NOT_FOUND")
        claimed = value.get("state") == "POLLING"
        if claimed and now - _dt.datetime.fromisoformat(value.get("claimed_at") or now.isoformat()) < _SSO_LOGIN_CLAIM:
            return {"state": aws_sso_login.PENDING, "code": None}  # another poll is asking AWS right now
        if not claimed and value.get("state") != aws_sso_login.PENDING:
            return {"state": value.get("state"), "code": value.get("code")}
        # One poll at a time asks AWS: two would redeem the device code twice and the loser would record a failure.
        pending = {key: item for key, item in value.items() if key != "claimed_at"} | {"state": aws_sso_login.PENDING}
        if not _sso_login_move(session_id, actor, value["state"], {**pending, "state": "POLLING", "claimed_at": now.isoformat()}):
            return {"state": aws_sso_login.PENDING, "code": None}
        code = None
        try:
            kept = unseal(settings.sealing_keys, value["sealed"])
            kept["registration_expires_at"] = int(kept["registration_expires_at"])
        except (SealedSecretError, KeyError, ValueError):
            _sso_login_move(session_id, actor, "POLLING", {"actor": actor, "state": aws_sso_login.FAILED, "code": "AWS_SSO_LOGIN_EXPIRED"})
            raise _http(409, "AWS_SSO_LOGIN_EXPIRED") from None
        try:
            state = aws_sso_login.complete(kept, oidc_factory=getattr(app.state, "aws_sso_oidc_factory", None))
        except aws_sso_login.LoginError as exc:
            state, code = aws_sso_login.FAILED, exc.code
        except Exception:  # noqa: BLE001 -- an unexpected failure ends the attempt instead of leaving it claimed
            state, code = aws_sso_login.FAILED, "AWS_SSO_LOGIN_UNAVAILABLE"
        finally:
            kept.clear()
        if state == aws_sso_login.PENDING:
            _sso_login_move(session_id, actor, "POLLING", pending)
            return {"state": state, "code": code}
        # Ended: the sealed part goes, only the outcome stays.
        _sso_login_move(session_id, actor, "POLLING", {"actor": actor, "state": state, "code": code})
        note = code
        if state == aws_sso_login.DONE:
            # Who approved the code is now who CreMore runs as: read it again and keep it in the audit.
            note = _api_identity(fresh=True).get("caller_arn") or None
        _sso_login_audit(session_id, actor, "AWS_SSO_LOGIN_" + state, note)
        return {"state": state, "code": code}

    @app.put("/api/v1/aws/scanner-identity")
    def approve_aws_scanner_identity(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        """Approve the identity both processes run as; member roles are deployed to trust it."""

        body = body or {}
        if body.get("confirm") is not True:
            raise _http(422, "confirm must be true")
        role_arn = body.get("role_arn") if isinstance(body.get("role_arn"), str) else None
        sso_region = body.get("sso_region") if isinstance(body.get("sso_region"), str) else None
        api = _api_identity(role_arn, sso_region, fresh=True)
        if reason := aws_identity.approvable(api):
            raise _http(409, f"{reason}: the API process cannot use this AWS identity as the scanner identity")
        worker, stale = _worker_identity()
        if not worker or stale:
            raise _http(409, "WORKER_IDENTITY_UNKNOWN: start the worker; it reports its AWS identity every minute")
        if worker.get("state") != "READY":
            raise _http(409, f"WORKER_{worker.get('state') or 'UNKNOWN'}: the worker process cannot sign in to AWS")
        if worker.get("match_key") != api.get("match_key"):
            raise _http(409, "WORKER_IDENTITY_MISMATCH: the API and worker run as different AWS identities")
        value = aws_access.save_approval(repo, aws_access.SCANNER, api, actor)
        _log.info("AWS scanner identity approved by %s: %s", actor, value["principal_arn"])
        # Earlier results no longer count (their key names the old revision);
        # re-prove every account that can still be checked.
        pending = aws_access.pending_validations(repo)
        for acct in repo.list_aws_accounts():
            if aws_access.validation_refusal(acct, aws_access.SCANNER, value) is None:
                aws_access.queue_validation(repo, acct, aws_access.SCANNER, value["revision"], pending)
        return aws_scanner_identity(actor)

    @app.get("/api/v1/aws/remediation-identity")
    def aws_remediation_identity(_actor: str = Depends(require_auth)) -> dict:
        """The identity the API uses for approved key actions (AWS_REMEDIATION_PROFILE, or the default login)."""

        api = _api_identity(purpose=aws_access.REMEDIATION)
        approved = _approved_identity(aws_access.REMEDIATION)
        scanner = _approved_identity()
        partition = (approved or {}).get("partition") or api.get("partition") or "aws"
        return {
            "identity_source": "remediator" if getattr(settings, "isolated_deployment", False) else "api",
            "api": _identity_public(api),
            "profile": settings.aws_remediation_profile or None,
            "approvable": aws_identity.approvable(api),
            "approved": _approved_public(approved),
            # Recommended, not enforced: scanning and key actions under different identities.
            "same_as_scanner": bool(approved and scanner and approved.get("match_key")
                                    and approved.get("match_key") == scanner.get("match_key")),
            "remediation_role_name": REMEDIATION_ROLE_NAME,
            "policy": aws_identity.hub_policy(partition, REMEDIATION_ROLE_NAME, **_hub_scope(repo)),
        }

    @app.put("/api/v1/aws/remediation-identity")
    def approve_aws_remediation_identity(body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        body = body or {}
        if body.get("confirm") is not True:
            raise _http(422, "confirm must be true")
        role_arn = body.get("role_arn") if isinstance(body.get("role_arn"), str) else None
        sso_region = body.get("sso_region") if isinstance(body.get("sso_region"), str) else None
        api = _api_identity(role_arn, sso_region, fresh=True, purpose=aws_access.REMEDIATION)
        if reason := aws_identity.approvable(api):
            raise _http(409, f"{reason}: the API process cannot use this AWS identity for key actions")
        value = aws_access.save_approval(repo, aws_access.REMEDIATION, api, actor)
        _log.info("AWS remediation identity approved by %s: %s", actor, value["principal_arn"])
        return aws_remediation_identity(actor)

    @app.get("/api/v1/aws/accounts/onboarding")
    def aws_onboarding(_actor: str = Depends(require_auth)) -> dict:
        approved = _approved_identity()
        configured = approved is not None
        return {
            "configured": configured,
            "region": settings.aws_region,
            "scanner_role_name": SCANNER_ROLE_NAME,
            "quick_create": bool(settings.aws_onboarding_template_url),
            # Which routes exist at all, from local state only. Whether one works
            # right now is a live probe (/aws/accounts/discoverable) an
            # administrator asks for, never something a dashboard refresh calls.
            "sources": {
                "sso": {
                    "supported": bool(configured and approved.get("kind") == "IDENTITY_CENTER"
                                      and approved.get("sso_start_url")),
                    "permission_set": aws_sso_settings.permission_set(settings, repo)["name"],
                    "auto_discovery": aws_sso_settings.discovery_effective(settings, repo),
                },
                "org": {
                    "supported": configured,
                    "auto_discovery": aws_org_settings.effective(settings, repo),
                    "external_id_configured": bool(aws_org_settings.config(settings, repo)["external_id"]),
                    "ou_ids": aws_org_settings.config(settings, repo)["ou_ids"],
                },
                "manual": {"supported": configured},
            },
            "configuration": None if configured else "IDENTITY_NOT_APPROVED",
        }

    @app.get("/api/v1/aws/accounts/discoverable")
    def aws_discoverable(source: str = "sso", _actor: str = Depends(require_role("admin"))) -> dict:
        """Accounts a discovery source could register right now.

        Read-only and on demand: it lists an estate, so it runs when an
        administrator opens the connect dialog, not on a dashboard refresh.
        """
        source = (source or "").strip().lower()
        if source not in ("sso", "org"):
            raise _http(422, "source must be sso or org")
        if not getattr(settings, "sso_discovery_allowed" if source == "sso" else "org_discovery_allowed"):
            raise _http(409, "AWS_DISCOVERY_DISABLED")
        approved = _approved_identity()
        if getattr(settings, "isolated_deployment", False):
            from cremore.api.aws_support import queue_aws_read
            return queue_aws_read(repo, settings, "discoverable", _actor, {"source": source})
        try:
            probed = aws_discovery_probe(source, approved) or {}
        except Exception as exc:  # noqa: BLE001 -- reported as a safe code, never provider text
            probed = {"available": False, "reason": aws_identity.error_code(exc), "accounts": []}
        listed = probed.get("accounts") or []
        known = {a.account_id: a for a in repo.list_aws_accounts()}
        chosen = aws_sso_settings.permission_set(settings, repo)
        wanted = chosen["name"] or ""
        accounts = []
        for entry in listed[:_DISCOVERY_LIMIT]:
            account_id = str(entry.get("account_id") or entry.get("id") or "")
            roles = [str(r) for r in (entry.get("roles") or [])]
            record = known.get(account_id)
            if record is not None:
                selectable = False
            elif source == "sso":
                # Assigned to the account is not enough: it must carry the one
                # permission set CreMore is configured to use.
                selectable = bool(wanted) and wanted in roles
            else:
                selectable = entry.get("state") == "ACTIVE"
            accounts.append({
                "account_id": account_id,
                "name": str(entry.get("name") or account_id),
                "roles": roles,
                "state": entry.get("state"),
                "registered": record is not None,
                "registered_access": record.access if record is not None else None,
                "selectable": selectable,
            })
        return {
            "source": source,
            "available": bool(probed.get("available")),
            "reason": probed.get("reason"),
            "permission_set": wanted or None,
            "permission_set_locked": chosen["locked"],
            "permission_set_source": chosen["source"],
            # Every permission set Identity Center reports, so an Admin can pick
            # one here instead of editing the deployment's environment.
            "available_permission_sets": _permission_set_options(listed) if source == "sso" else [],
            "start_url": probed.get("start_url"),
            "region": probed.get("region"),
            "external_id_configured": probed.get("external_id_configured"),
            "total": len(listed),
            "truncated": len(listed) > _DISCOVERY_LIMIT,
            "accounts": accounts,
        }

    def _deployment(acct) -> dict:
        approved = _approved_identity()
        if approved is None:
            raise _http(409, "AWS_SCANNER_IDENTITY_NOT_APPROVED: approve the AWS identity CreMore runs as first")
        if acct.access == aws_access.SSO_PERMISSION_SET:
            # Nothing is deployed for this access mode, so there is no command to
            # show. Promotion is what creates one, and it changes the record.
            raise _http(409, "IDENTITY_CENTER_ACCESS: this account is reached through its Identity Center "
                             "assignment; promote it to member-role access to deploy a stack")
        remediation = _approved_identity(aws_access.REMEDIATION) if acct.remediation_role_arn else None
        # The command creates the roles this account record points at, so names registered
        # through the API (not the defaults) still match what validation assumes.
        params = aws_identity.stack_parameters(approved["trust"], target_account=acct.account_id,
                                               external_id=acct.external_id or "",
                                               role_name=_role_name(acct.scanner_role_arn, SCANNER_ROLE_NAME),
                                               remediation_trust=(remediation or {}).get("trust"),
                                               remediation_role_name=_role_name(acct.remediation_role_arn, REMEDIATION_ROLE_NAME))
        region = settings.aws_region
        return {
            "cloudformation_url": _quick_create_url(settings, approved, params) if settings.aws_onboarding_template_url else None,
            "deployment": {
                "stack_name": STACK_NAME,
                "region": region,
                "template_file": TEMPLATE_FILE,
                "template_path": "/api/v1/aws/onboarding/template",
                "parameters": params,
                "cli_command": aws_identity.cli_command(params, region=region, template_file=TEMPLATE_FILE,
                                                        stack_name=STACK_NAME),
            },
        }

    @app.get("/api/v1/aws/onboarding/template")
    def aws_onboarding_template(_actor: str = Depends(require_auth)):
        from fastapi.responses import Response

        path = _member_template_path()
        if path is None:
            raise _http(404, "member-account-role.yaml is not packaged with this API")
        return Response(path.read_text(encoding="utf-8"), media_type="application/x-yaml",
                        headers={"Content-Disposition": f'attachment; filename="{TEMPLATE_FILE}"',
                                 "Cache-Control": "no-store"})

    @app.get("/api/v1/aws/onboarding/organization")
    def aws_organization_onboarding(organization_id: str = "", _actor: str = Depends(require_role("admin"))) -> dict:
        """The service-managed StackSet that puts the scanner role in every account of the organization's OUs.

        The role trusts the approved CreMore identity, as one account's stack does, scoped by aws:PrincipalOrgID
        and the StackSet's shared ExternalId the Organizations sweep assumes with. The parameters go in a file:
        an ExternalId may hold a comma, which the CLI's shorthand would split. An account the sweep excludes is
        left out of the deployment too (AccountFilterType=DIFFERENCE); AWS's automatic deployment does not follow
        that filter for an account added to or moved between the target OUs later."""
        approved = _approved_identity()
        if approved is None:
            raise _http(409, "AWS_SCANNER_IDENTITY_NOT_APPROVED: approve the AWS identity CreMore runs as first")
        if not _ORGANIZATION_ID.fullmatch(organization_id or ""):
            raise _http(422, "AWS_ORGANIZATION_ID_INVALID: the organization ID is o- and 10 to 32 lower-case "
                             "letters or digits")
        region = settings.aws_region
        if not aws_org_settings.REGION.fullmatch(region or ""):
            raise _http(409, "AWS_REGION_INVALID: AWS_REGION is not an AWS Region name")
        org = aws_org_settings.config(settings, repo)
        external_id = org["external_id"] or ""
        if not external_id:
            raise _http(409, "EXTERNAL_ID_NOT_SET: set the StackSet's shared ExternalId first")
        if not _TEMPLATE_EXTERNAL_ID.fullmatch(external_id):
            raise _http(409, "EXTERNAL_ID_TEMPLATE_LENGTH: the member role template takes an ExternalId of 16 to 128 "
                             "characters")
        params = {"DeploymentMode": "Organization", "OrganizationId": organization_id,
                  **aws_identity.stack_parameters(approved["trust"], target_account="", external_id=external_id,
                                                  role_name=SCANNER_ROLE_NAME)}
        targets, excludes = list(org["ou_ids"]), list(org["excludes"])
        deployment = f"OrganizationalUnitIds={','.join(targets) or 'r-xxxx'}"
        if excludes:
            deployment += f",Accounts={','.join(excludes)},AccountFilterType=DIFFERENCE"
        return {
            "region": region, "stack_set_name": STACK_NAME, "template_file": TEMPLATE_FILE,
            "template_path": "/api/v1/aws/onboarding/template", "parameters_file": _STACKSET_PARAMETERS,
            "parameters": [{"ParameterKey": key, "ParameterValue": value} for key, value in params.items()],
            "targets": targets, "excludes": excludes,
            "commands": [
                (f"aws cloudformation create-stack-set --region {region} --stack-set-name {STACK_NAME} "
                 f"--template-body file://{TEMPLATE_FILE} --permission-model SERVICE_MANAGED "
                 "--auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false --capabilities CAPABILITY_NAMED_IAM "
                 f"--parameters file://{_STACKSET_PARAMETERS}"),
                (f"aws cloudformation create-stack-instances --region {region} --stack-set-name {STACK_NAME} "
                 f"--deployment-targets {deployment} --regions {region}"),
            ],
        }

    @app.get("/api/v1/aws/accounts/{account_id}/onboarding")
    def aws_account_onboarding(account_id: str, _actor: str = Depends(require_role("admin"))) -> dict:
        acct = repo.get_aws_account(_uuid(account_id, "account_id"))
        if acct is None:
            raise _http(404, "account not found")
        return {**_account_public(acct), **_deployment(acct)}

    @app.post("/api/v1/aws/accounts/validate")
    def validate_all_aws_accounts(_actor: str = Depends(require_role("admin"))) -> dict:
        approved = aws_access.approval(repo, aws_access.SCANNER, settings)
        return {"accounts": [_validate_account(str(a.id)) for a in repo.list_aws_accounts()
                             if a.enabled and aws_access.validation_refusal(a, aws_access.SCANNER, approved) is None]}

    @app.post("/api/v1/aws/accounts/{account_id}/validate")
    def validate_aws_account(account_id: str, purpose: str = aws_access.SCANNER,
                             _actor: str = Depends(require_role("admin"))) -> dict:
        """Prove the purpose's role can be assumed *and* that the assumed
        identity is in the registered account (read-only STS calls)."""

        if purpose not in aws_access.PURPOSES:
            raise _http(422, "purpose must be scanner or remediation")
        return _validate_account(account_id, purpose)

    @app.post("/api/v1/aws/accounts/{account_id}/onboarding/validate")
    def validate_aws_onboarding(account_id: str, _actor: str = Depends(require_role("admin"))) -> dict:
        return _validate_account(account_id)

    @app.patch("/api/v1/aws/accounts/{account_id}")
    def update_aws_account(account_id: str, body: dict, _actor: str = Depends(require_role("admin"))) -> dict:
        acct = repo.get_aws_account(_uuid(account_id, "account_id"))
        if acct is None:
            raise _http(404, "account not found")
        if "validation_status" in (body or {}):
            raise _http(422, "validation_status is set only by role validation")
        changes = {k: v for k, v in (body or {}).items()
                   if k in ("name", "environment", "enabled", "scanner_role_arn", "remediation_role_arn")}
        updated = repo.update_aws_account(acct.id, **aws_access.access_changes(acct, changes))
        if updated is None:
            raise _http(404, "account not found")
        return _account_public(updated)

    @app.post("/api/v1/aws/accounts/{account_id}/promote")
    def promote_aws_account(account_id: str, _actor: str = Depends(require_role("admin"))) -> dict:
        """Move an Identity Center account onto its own member scanner role.

        The record, its findings and its history stay; only how CreMore reaches
        the account changes. ``access_changes`` bumps the scanner revision, so the
        stored VALID stops counting until the deployed role has been proved --
        scanning is blocked in between rather than silently continuing.
        """
        acct = repo.get_aws_account(_uuid(account_id, "account_id"))
        if acct is None:
            raise _http(404, "account not found")
        if acct.access != aws_access.SSO_PERMISSION_SET:
            raise _http(409, "NOT_AN_IDENTITY_CENTER_ACCOUNT: only Identity Center access is promoted this way")
        approved = _approved_identity()
        if approved is None:
            raise _http(409, "IDENTITY_NOT_APPROVED: approve the AWS identity CreMore runs as first")
        partition = approved.get("partition") or _partition(settings.scanner_principal_arn)
        changes = {
            "access": aws_access.ROLE,
            "sso_role_name": None,
            "scanner_role_arn": acct.scanner_role_arn
            or f"arn:{partition}:iam::{acct.account_id}:role/{SCANNER_ROLE_NAME}",
            "external_id": acct.external_id or secrets.token_urlsafe(24),
            # The assignment sweep must stop owning this record: once the member
            # role is the path in, an assignment taken away is no longer a reason
            # to block the account (cremore/aws_sso_discovery.py).
            "source": "MANUAL",
        }
        updated = repo.update_aws_account(acct.id, **aws_access.access_changes(acct, changes))
        if updated is None:
            raise _http(404, "account not found")
        _log.info("AWS account %s promoted to member-role access", acct.account_id)
        return {**_account_public(updated), **_deployment(updated)}
