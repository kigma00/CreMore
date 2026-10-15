"""Compose dashboard dependencies and register the HTTP routes.

Reusable projections, contracts and services live in their named API modules.
The explicit imports below preserve the pre-extraction Python import surface;
new consumers should import the owning module directly.
"""

from __future__ import annotations

from cremore_aws_provider import aws_access, aws_identity
from cremore_aws_provider.aws_sessions import account_of_arn
from cremore_aws_provider.investigation import investigation_switches
from fastapi import Depends, FastAPI, HTTPException

from cremore.api import aws_support as _aws_support
from cremore.api import detection_catalog as _detection_catalog
from cremore.api import finding_presenters as _finding_presenters
from cremore.api import governance_presenters as _governance_presenters
from cremore.api import http_support as _http_support
from cremore.api import rule_payloads as _rule_payloads
from cremore.api import search_service as _search_service
from cremore.api import source_contract as _source_contract
from cremore.api import source_presenters as _source_presenters
from cremore.api.auth import LOCAL_ACTOR, Principal
from cremore.domain.connections import (
    job_payload_for,
)
from cremore.domain.models import (
    ConnectionStatus,
    ScanJob,
    ScopeProfile,
)
from cremore.operations.health import aws_identity_hold

# Backward-compatible aliases. Production consumers import the owning library.
_ACTOR_NAMESPACE = _http_support.ACTOR_NAMESPACE
_WEB_ROLE = _http_support.WEB_ROLE
_actor_label = _http_support.actor_label
_http = _http_support.http_error
_iso = _http_support.isoformat
_log = _http_support.logger
_log_safe = _http_support.log_safe
_now = _http_support.utc_now
_uuid = _http_support.parse_uuid
actor_uuid = _http_support.actor_uuid

CREDENTIAL_CHECK = _source_contract.CREDENTIAL_CHECK
SECRET_SCANNING = _source_contract.SECRET_SCANNING
_BUCKET_RE = _source_contract.BUCKET_RE
_GITHUB_NAME_RE = _source_contract.GITHUB_NAME_RE
_REVOCATION_GUIDANCE = _source_contract.REVOCATION_GUIDANCE
_SECRET_ARN_PREFIX = _source_contract.SECRET_ARN_PREFIX
_SOURCE_CAPABILITIES = _source_contract.SOURCE_CAPABILITIES
_SOURCE_TO_PROVIDER = _source_contract.SOURCE_TO_PROVIDER
_SOURCE_TYPES = _source_contract.SOURCE_TYPES
_config_from_scope = _source_contract.config_from_scope
_job_source_type = _source_contract.job_source_type
_provider_to_source = _source_contract.provider_to_source
_scope_ref = _source_contract.scope_ref

_JOB_STATUS_TO_WEB = _source_presenters.JOB_STATUS_TO_WEB
_dashboard_connection = _source_presenters.present_connection
_dashboard_job = _source_presenters.present_job

_REVIEW_REASONS = _finding_presenters.REVIEW_REASONS
_REVIEW_STATUSES = _finding_presenters.REVIEW_STATUSES
_dashboard_finding = _finding_presenters.present_finding
_default_owner_review = _finding_presenters.default_owner_review
_owner_review_public = _finding_presenters.present_owner_review

_credential_type_catalog = _detection_catalog.credential_type_catalog
_credential_types = _detection_catalog.credential_types
_detector_catalog = _detection_catalog.detector_catalog
_reviewed_semantics = _detection_catalog.reviewed_semantics

_MAX_SAMPLE = _rule_payloads.MAX_SAMPLE
_RULE_FIELDS = _rule_payloads.RULE_FIELDS
_rule_from_body = _rule_payloads.rule_from_body
_rule_public = _rule_payloads.present_rule

_DECLARATION_FIELDS = _governance_presenters.DECLARATION_FIELDS
_ENVIRONMENT_FIELDS = _governance_presenters.ENVIRONMENT_FIELDS
_PURPOSES = _governance_presenters.PURPOSES
_action_public = _governance_presenters.present_action
_available_actions = _governance_presenters.available_actions
_capability = _governance_presenters.capability
_clean_declaration = _governance_presenters.clean_declaration
_governance_common = _governance_presenters.governance_common
_governance_item_aws = _governance_presenters.governance_item_aws
_governance_item_source = _governance_presenters.governance_item_source
_review_public = _governance_presenters.present_review
_rotation_public = _governance_presenters.present_rotation

REMEDIATION_ROLE_NAME = _aws_support.REMEDIATION_ROLE_NAME
SCANNER_ROLE_NAME = _aws_support.SCANNER_ROLE_NAME
STACK_NAME = _aws_support.STACK_NAME
TEMPLATE_FILE = _aws_support.TEMPLATE_FILE
_DISCOVERY_LIMIT = _aws_support.DISCOVERY_LIMIT
_access_key_metadata = _aws_support.access_key_metadata
_approved_public = _aws_support.present_approved_identity
_aws_account_public = _aws_support.present_aws_account
_console_host = _aws_support.console_host
_default_discovery_probe = _aws_support.default_discovery_probe
_default_discovery_sweep = _aws_support.default_discovery_sweep
_default_identity_probe = _aws_support.default_identity_probe
_iam_user_from_arn = _aws_support.iam_user_from_arn
_identity_public = _aws_support.present_identity
_member_template_path = _aws_support.member_template_path
_onboarding_configured = _aws_support.onboarding_configured
_partition = _aws_support.partition
_permission_set_options = _aws_support.permission_set_options
_probe_org = _aws_support.probe_org
_probe_sso = _aws_support.probe_sso
_quick_create_url = _aws_support.quick_create_url
_role_name = _aws_support.role_name
_sign_in_diagnosis = _aws_support.sign_in_diagnosis
open_account_session = _aws_support.open_account_session
secrets_inventory_session = _aws_support.secrets_inventory_session

SEARCH_ROLES = _search_service.SEARCH_ROLES
_managed_object_search = _search_service.managed_object_search
search_payload = _search_service.search_payload


def register_dashboard_routes(app: FastAPI, repo, settings, require_auth,
                              secrets_inventory_factory=None, require_role=None,
                              rotation_service_factory=None, require_principal=None,
                              aws_role_validator=None, usage_service_factory=None, aws_identity_probe=None,
                              potential_access_factory=None, key_action_adapter_factory=None,
                              secret_metadata_factory=None, aws_sessions=None, aws_remediation_validator=None,
                              learned_fp=None, task_states=None, aws_discovery_probe=None, aws_discovery_sweep=None) -> None:
    """Attach the dashboard contract to an existing FastAPI app.

    ``require_role(minimum)`` gates mutations by platform role; when the caller
    supplies none (older tests), every authenticated actor is treated as admin.
    ``require_principal`` yields the whole principal for the session endpoint.
    ``rotation_service_factory()`` returns a RotationService bound to live AWS
    clients; when None, rotation can be requested and reviewed but never executed.
    ``aws_role_validator(account)`` checks a member scanner role in this process
    (tests and embedded use); by default the check is queued for the worker,
    which is the process that assumes the role when scanning.
    ``aws_identity_probe(role_arn=None, sso_region=None)`` describes the AWS
    identity this API process runs as (``cremore_aws_provider.aws_identity.describe``).
    ``aws_discovery_probe(source, approved)`` lists the accounts a discovery
    source could register right now; it is read-only and called only when an
    administrator opens the connect dialog, never on a dashboard refresh.
    ``aws_discovery_sweep(source, approved, queue_validation)`` runs one
    registration sweep of that source on demand, so a switch turned on in the
    dashboard does not have to wait for the worker's next poll.
    Every AWS investigation and action runs in the account it concerns, through
    ``aws_sessions`` (``cremore_aws_provider.aws_sessions.AccountSessions``). The factories build
    their service from that session: ``usage_service_factory(session)``,
    ``potential_access_factory(session)``, ``secret_metadata_factory(session, region)``,
    ``secrets_inventory_factory(session)``, ``key_action_adapter_factory(session)``.
    """

    from cremore.remediation.action_plans import ActionPlanError, ActionPlanService

    action_plans = ActionPlanService(repo, settings)

    if require_role is None:
        def require_role(_minimum: str):
            return require_auth

    if require_principal is None:
        def require_principal(_actor: str = Depends(require_auth)) -> Principal:
            return Principal(subject=_actor, role="admin")

    isolated = getattr(settings, "isolated_deployment", False)
    if isolated:
        from cremore.coverage.aws_requests import DeclaredSessions
        aws_sessions = DeclaredSessions(repo, settings)
    if aws_identity_probe is None:
        aws_identity_probe = _default_identity_probe(settings)
    if aws_discovery_probe is None:
        aws_discovery_probe = _default_discovery_probe(settings)
    if aws_discovery_sweep is None:
        aws_discovery_sweep = _default_discovery_sweep(settings, repo)
    identity_cache: dict = {}

    def current_detection_digest() -> str | None:
        """The policy a scan started now would record; None when this app has no engine."""
        orchestrator = getattr(app.state, "orchestrator", None)
        if orchestrator is None:
            return None
        orchestrator.refresh_rules()
        return orchestrator.detection_policy_digest

    def _api_identity(role_arn=None, sso_region=None, *, fresh=False, purpose=aws_access.SCANNER) -> dict:
        now = _now()
        if isolated:
            key = "aws_identity:remediator" if purpose == aws_access.REMEDIATION else aws_identity.WORKER_IDENTITY_KEY
            record = repo.get_setting(key)
            updated = (record or {}).get("updated_at")
            if not updated or (now - updated).total_seconds() > 300:
                return {"state": "ERROR", "error_code": "WORKER_IDENTITY_UNKNOWN"}
            value = dict(record["value"])
            if role_arn and role_arn != value.get("principal_arn"):
                return {"state": "ERROR", "error_code": "WORKER_IDENTITY_MISMATCH"}
            if sso_region and sso_region != value.get("sso_region"):
                return {"state": "ERROR", "error_code": "WORKER_IDENTITY_MISMATCH"}
            return value
        cached = identity_cache.get(purpose)
        if not fresh and not role_arn and not sso_region and cached and (now - cached[0]).total_seconds() < 15:
            return cached[1]
        try:
            kwargs = {"role_arn": role_arn, "sso_region": sso_region}
            if purpose != aws_access.SCANNER:
                kwargs["purpose"] = purpose
            value = aws_identity_probe(**kwargs)
        except Exception as exc:  # noqa: BLE001 -- a missing SDK or config is a reported state
            value = {"state": "ERROR", "error_code": aws_identity.error_code(exc)}
        if not role_arn and not sso_region:
            identity_cache[purpose] = (now, value)
        return value

    def _worker_identity() -> tuple[dict | None, bool]:
        record = repo.get_setting(aws_identity.WORKER_IDENTITY_KEY)
        if not record:
            return None, True
        stale = record["updated_at"] is None or (_now() - record["updated_at"]).total_seconds() > 300
        return record["value"], stale


    def _approvals() -> dict:
        return {purpose: aws_access.approval(repo, purpose, settings) for purpose in aws_access.PURPOSES}


    def _account_session(account_id: str | None, purpose: str):
        return open_account_session(aws_sessions, account_id, purpose)


    def _aws_hold() -> str | None:
        return aws_identity_hold(repo)

    @app.get("/api/v1/session")
    def session(principal: Principal = Depends(require_principal)) -> dict:
        from cremore.governance.tickets import actor_ref

        local = settings.auth_mode == "local"
        return {"id": principal.subject,
                "name": ("local operator" if local and principal.subject == LOCAL_ACTOR
                         else principal.display_name or principal.subject),
                "email": principal.email or None,
                "role": _WEB_ROLE.get(principal.role, "Viewer"),
                # How tickets name this person (created_by, owner_id): the subject when it is a UUID, else one made from it.
                "ref": str(actor_ref(principal.subject)),
                "auth_mode": settings.auth_mode}


    # --- the three optional read-only AWS investigations ----------------------

    _INVESTIGATION_LABELS = {key: name for name, key in investigation_switches.NAMES.items()}


    def _secret_metadata(arn: str) -> dict:
        from cremore_aws_provider.investigation.secret_metadata import SecretMetadataError

        if secret_metadata_factory is None or not investigation_switches.effective(
                settings, repo, investigation_switches.SECRETS_INVENTORY):
            raise _http(501, "SECRETS_INVENTORY_OFF: secret metadata reads are switched off for this installation "
                             "(needs secretsmanager:DescribeSecret and ListSecretVersionIds on the exact ARN)")
        session = _account_session(account_of_arn(arn), aws_access.SCANNER)
        try:
            metadata = secret_metadata_factory(session, arn.split(":")[3]).describe(arn)
        except SecretMetadataError as exc:
            raise _http(502, f"SECRET_METADATA_UNAVAILABLE: {exc.code}")
        return {"secret_value_returned": False, "last_access_semantics": "SECRET_STORAGE_ACCESS_NOT_CREDENTIAL_USE",
                "observed_at": _now().isoformat(), "metadata": metadata, **session.evidence()}

    def _resolve(kind: str, connection_id: str):
        if kind == "source":
            conn = repo.get_connection(_uuid(connection_id, "connection_id"))
            if conn is None:
                raise _http(404, "connection not found")
            return conn
        if kind == "aws":
            acct = repo.get_aws_account(_uuid(connection_id, "connection_id"))
            if acct is None:
                raise _http(404, "account not found")
            return acct
        raise _http(422, "kind must be 'aws' or 'source'")


    def _validate_account(account_id: str, purpose: str = aws_access.SCANNER) -> dict:
        acct = repo.get_aws_account(_uuid(account_id, "account_id"))
        if acct is None:
            raise _http(404, "account not found")
        approved = aws_access.approval(repo, purpose, settings)
        if refusal := aws_access.validation_refusal(acct, purpose, approved):
            raise _http(409, f"{refusal}: this account cannot be validated for {purpose} access")
        revision = approved["revision"]
        if purpose == aws_access.REMEDIATION and not isolated:
            # Key actions run in this API process, so this process proves the remediation access.
            if aws_remediation_validator is None:
                raise _http(503, "AWS_ACCESS_NOT_CONFIGURED: this API cannot validate remediation access")
            current = _api_identity(fresh=True, purpose=aws_access.REMEDIATION)
            if current.get("state") in ("LOGIN_REQUIRED", "NO_CREDENTIALS"):
                raise _http(409, "AWS_LOGIN_REQUIRED: sign in to AWS again on the computer running CreMore")
            if current.get("state") != "READY" or current.get("match_key") != approved.get("match_key"):
                raise _http(409, "AWS_IDENTITY_CHANGED: the remediation identity differs from the approved one")
            validator = aws_remediation_validator
        else:
            validator = None if isolated else aws_role_validator
        if validator is not None:
            result = validator(acct)
            stored = aws_access.record_validation(
                repo, acct, purpose, access_revision=aws_access.access_revision(acct, purpose), approval_revision=revision,
                current_approval_revision=(aws_access.approval(repo, purpose, settings) or {}).get("revision"),
                status=result.status, detail=getattr(result, "code", "") or "ASSUME_ROLE_DENIED")
            current = aws_access.effective_validation(repo.get_aws_account(acct.id), purpose, approved)
            return {"id": str(acct.id), "account_id": acct.account_id, "purpose": purpose, "status": current["status"],
                    "detail": current["detail"], "assumed_arn": result.assumed_arn,
                    "check": "COMPLETED" if stored else "SUPERSEDED"}
        # The worker assumes roles when scanning, so it is the process that must prove it.
        job_id = aws_access.queue_validation(repo, acct, purpose, revision)
        current = aws_access.effective_validation(acct, purpose, approved)
        return {"id": str(acct.id), "account_id": acct.account_id, "purpose": purpose, "status": current["status"],
                "detail": current["detail"], "validated_at": _iso(current["validated_at"]),
                "check": "QUEUED", "check_job_id": job_id}


    def _plan_error(exc: ActionPlanError) -> HTTPException:
        return _http(exc.http_status, f"{exc.code}: {exc}")


    # --- scan scope: catalog, profiles, drafts, plans, runs, exact rescan ---

    from cremore.db.catalog_store import CatalogStore
    from cremore.scanning import scope as _scope

    catalog_store = CatalogStore(repo)

    def _scope_error(exc: _scope.ScopeError) -> HTTPException:
        return _http(exc.http_status, f"{exc.code}: {exc}")

    def _scope_target(kind: str, connection_id: str):
        """(target, provider, enabled, auth_revision, connection uuid)."""

        target = _resolve(kind, connection_id)
        if kind == "source":
            evidence = target.credential_evidence or {}
            enabled = target.status != ConnectionStatus.DISABLED.value and not evidence.get("revoked_at")
        else:
            enabled = bool(target.enabled)
        from cremore.onboarding.store import child_feature_enabled

        enabled = enabled and child_feature_enabled(repo, kind, target.id, "exposure")
        return target, _scope.provider_of(kind, target), enabled, _scope.auth_revision(kind, target), target.id


    def _base_payload(kind: str, target, provider: str) -> dict:
        if kind == "aws":
            return {"account_id": target.account_id, "region": settings.aws_region,
                    "scanner_role_arn": target.scanner_role_arn, "external_id": target.external_id}
        payload = job_payload_for(target)
        if target.secret_ref:
            payload["secret_ref"] = target.secret_ref
        return payload


    def _profiles_with_state(kind: str, cid, auth: str, enabled: bool):
        rows = repo.list_scope_profiles(kind, cid)
        return [(p, _scope.profile_state(p, auth=auth, enabled=enabled)) for p in rows]


    def _save_profile(kind: str, connection_id: str, body: dict, actor: str, existing=None) -> dict:
        from cremore.onboarding import permissions
        from cremore.onboarding.service import OnboardingError

        _t, _p, enabled, auth, cid = _scope_target(kind, connection_id)
        try:
            fields = _scope.validate_profile_input(body)
        except _scope.ScopeError as exc:
            raise _scope_error(exc)
        expected = fields.pop("expected_version")
        if existing is None and expected != 0:
            raise _http(409, "SCOPE_VERSION_CONFLICT: a new profile must be saved with expected_version 0")
        if existing is not None and expected != existing.version:
            raise _http(409, "SCOPE_VERSION_CONFLICT: the saved profile changed since it was read")
        try:
            permissions.require_scope(repo, kind, cid, fields, existing)
        except OnboardingError as exc:
            raise _http(exc.status, exc.code) from None
        catalog = catalog_store.header(kind, cid)
        if fields["selected_roots"] and (catalog is None or not catalog.snapshot_id) and not permissions.scope_reduction(existing, fields):
            raise _http(409, "SCOPE_CATALOG_NOT_COLLECTED: refresh the resource catalog before selecting targets")
        if (fields["selected_roots"] and not permissions.scope_reduction(existing, fields)
                and (catalog is None or fields["catalog_snapshot_id"] != catalog.snapshot_id)):
            raise _http(409, "SCOPE_CATALOG_CHANGED: the catalog was refreshed; review the selection against it")
        now = _now()
        if existing is None:
            profile = repo.create_scope_profile(ScopeProfile(
                kind=kind, connection_id=cid, version=1, auth_revision=auth, approved_by=actor, approved_at=now, **fields))
        else:
            profile = repo.update_scope_profile(existing.id, expected_version=expected, version=expected + 1, auth_revision=auth,
                                                approved_by=actor, approved_at=now, **fields)
            if profile is None:
                raise _http(409, "SCOPE_VERSION_CONFLICT: the saved profile changed since it was read")
        state = _scope.profile_state(profile, auth=auth, enabled=enabled)
        repo.update_scope_profile(profile.id, expected_version=profile.version, state=state)
        _audit_scope(actor, f"scope profile {profile.id} v{profile.version} saved: {fields['change_reason']}")
        return _scope.profile_public(profile, state)

    def _audit_scope(actor: str, note: str) -> None:
        # Operator text (a change reason) is logged escaped so a newline in it
        # cannot forge a separate log record.
        _log.info("scope: %s by %s", _log_safe(note), _log_safe(actor))


    def _profile_or_404(profile_id: str):
        profile = repo.get_scope_profile(_uuid(profile_id, "profile_id"))
        if profile is None:
            raise _http(404, "scope profile not found")
        return profile


    def _active_scope_run(connection_id, profile_id: str, profile_version: int, mode: str, auth_revision=None,
                          verify=None):
        """A queued/running whole-scope job for this exact profile version and mode, if any. A full read asked for
        (the first scan saved with the scope) is also answered by the scope's scheduled full scan of the same
        approval: a schedule poll between saving the scope and starting its scan must not mean two. A change event's
        or a finding's rescan reads only its own paths and answers nothing, and no run answers a request that would
        verify what it finds when the run itself does not (scheduled runs never verify)."""
        from cremore.scanning import verification_switch

        # As the worker decides it (cremore.worker.worker JobWorker.verify): the installation ceiling and the switch.
        on = verification_switch.effective(settings, repo)

        def verifies(requested) -> bool:
            return on if requested is None else bool(requested) and on

        wanted = verifies(verify)
        # The repository returns only this profile version's queued or running whole-scope runs on the connection,
        # newest first, however many change-event runs are queued beside them.
        for job in repo.active_scope_runs(connection_id, profile_id, profile_version):
            p = job.payload or {}
            # Only a whole-scope run answers: not a change event's, a rescan's, a policy sweep's or a continuation
            # that starts part way (RESUME), the same runs coalesce_scheduled_scope accepts.
            if p.get("trigger", "BASELINE") not in ("BASELINE", "SCHEDULE") or (wanted and not verifies(p.get("verify"))):
                continue
            if p.get("mode", "BASELINE") == mode:
                return job
            if (mode == "BASELINE" and p.get("mode") == "RECONCILE" and p.get("requested_by") == "schedule"
                    and auth_revision is not None and p.get("auth_revision") == auth_revision):
                return job
        return None

    def _start_run(plan, requested_version, actor: str, mode: str = "BASELINE") -> dict:
        if mode not in ("BASELINE", "DELTA", "RECONCILE", "INVENTORY"):
            raise _http(422, "mode must be BASELINE, DELTA, RECONCILE or INVENTORY")
        if mode == "INVENTORY" and any(r.get("resource_type") != "S3_BUCKET" for r in plan.roots):
            raise _http(422, "INVENTORY_REQUIRES_S3_ROOTS")
        if plan.job_id is not None:
            # The same immutable request again: hand back the run it created.
            job = repo.get_job(plan.job_id)
            if job is not None:
                if (job.payload or {}).get("mode", "BASELINE") != mode:
                    raise _http(409, "SCOPE_RUN_MODE_CONFLICT: this plan was already used with another mode")
                return _scope.run_public(job, plan.kind, plan.connection_id)
        profile = repo.get_scope_profile(plan.profile_id)
        if profile is None:
            raise _http(404, "scope profile not found")
        if requested_version != plan.profile_version or profile.version != plan.profile_version:
            raise _http(409, "SCOPE_PLAN_STALE: the profile changed since this plan was prepared")
        target, provider, _enabled, _auth, cid = _scope_target(plan.kind, str(plan.connection_id))
        # Guard against a duplicate concurrent scan: if this profile version is
        # already queued or running in the same mode, return that run instead of
        # starting a second scan of the same scope (e.g. a re-previewed plan).
        # A finding's rescan reads its exact locations and verifies: no other run answers it.
        active = None if plan.trigger == "RESCAN" else _active_scope_run(
            cid, str(plan.profile_id), plan.profile_version, mode, plan.auth_revision, plan.verify)
        if active is not None:
            return _scope.run_public(active, plan.kind, cid)
        try:
            from cremore.onboarding.store import child_feature_enabled

            if not child_feature_enabled(repo, plan.kind, target.id, "exposure"):
                raise _scope.ScopeError("CONNECTION_PAUSED", http_status=409)
            _scope.validate_execution(plan, profile, target, require_unexpired=True)
        except _scope.ScopeError as exc:
            raise _scope_error(exc)
        payload = _scope.run_payload(plan, profile, _base_payload(plan.kind, target, provider), _provider_to_source(provider))
        payload["mode"] = mode
        payload["requested_by"] = str(actor_uuid(actor))
        try:
            job, created = repo.consume_scope_plan(plan.id, requested_version,
                ScanJob(kind="scope", payload=payload, connection_id=cid))
        except ValueError as exc:
            raise _http(409, str(exc))
        if (job.payload or {}).get("mode", "BASELINE") != mode:
            raise _http(409, "SCOPE_RUN_MODE_CONFLICT: this plan was already used with another mode")
        if created:
            _audit_scope(actor, f"{plan.trigger.lower()} run {job.id} started from plan {plan.id}")
        return _scope.run_public(job, plan.kind, cid)

    def _scope_plan_or_404(plan_id):
        plan = repo.get_plan(_uuid(plan_id, "plan_id"))
        if plan is None:
            raise _http(404, "scope plan not found")
        return plan


    # Internal ticket workflow. Every response
    # is wrapped in an envelope stating that no provider action is executed by
    # it: tickets are operator declarations against a fixed checklist.
    from cremore.governance.tickets import TicketService

    ticket_service = TicketService(repo)

    # Each area registers its own routes. The context carries what they
    # share; nothing here reaches back into an area.
    from cremore.api import routes

    routes.register_areas(routes.DashboardContext(
        _INVESTIGATION_LABELS=_INVESTIGATION_LABELS, _account_session=_account_session, _api_identity=_api_identity,
        _approvals=_approvals, _aws_hold=_aws_hold, _base_payload=_base_payload,
        _plan_error=_plan_error, _profile_or_404=_profile_or_404, _profiles_with_state=_profiles_with_state, _resolve=_resolve,
        _save_profile=_save_profile, _scope_error=_scope_error, _scope_plan_or_404=_scope_plan_or_404, _scope_target=_scope_target,
        _secret_metadata=_secret_metadata, _start_run=_start_run, _validate_account=_validate_account, _worker_identity=_worker_identity,
        action_plans=action_plans, app=app, aws_discovery_probe=aws_discovery_probe, aws_discovery_sweep=aws_discovery_sweep,
        aws_sessions=aws_sessions,
        catalog_store=catalog_store, current_detection_digest=current_detection_digest, key_action_adapter_factory=key_action_adapter_factory,
        learned_fp=learned_fp, potential_access_factory=potential_access_factory, repo=repo, require_auth=require_auth,
        require_principal=require_principal, require_role=require_role, rotation_service_factory=rotation_service_factory, secret_metadata_factory=secret_metadata_factory,
        secrets_inventory_factory=secrets_inventory_factory, settings=settings, task_states=task_states,
        ticket_service=ticket_service, usage_service_factory=usage_service_factory,
    ))
