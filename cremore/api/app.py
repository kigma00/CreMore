"""FastAPI application.

Reproduces the finding-facing part of the API contract the web dashboard calls.
The repository is injected so the same routes serve the in-memory store in tests
and the SQL store in production. Auth is a bearer token in local mode; OIDC is
wired where the deployment provides it.
"""

from __future__ import annotations

import logging
import uuid

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from cremore.api import finding_routes
from cremore.api.aws_support import secret_record_public as _secret_record_public
from cremore.api.finding_presenters import (
    detail_credential as _detail_credential,  # noqa: F401 -- compatibility
)
from cremore.api.finding_presenters import finding_summary as _finding_summary
from cremore.api.finding_routes import (  # noqa: F401 -- existing request model imports
    AssignRequest,
    BulkTriageRequest,
    ReasonRequest,
    ResolveRequest,
)
from cremore.api.http_support import BoundedRequestBody as _BoundedRequestBody
from cremore.api.http_support import register_http_handlers
from cremore.api.source_presenters import connection_public as _connection_public
from cremore.api.source_presenters import scan_job_public
from cremore.config import Settings, get_settings
from cremore.db.repository import InMemoryRepository, Repository
from cremore.db.scan_state import SEVERITY_RANK as _SEVERITY_RANK  # noqa: F401 -- compatibility
from cremore.detection import ResourceRef
from cremore.domain.connections import (
    ConnectionError as ConnectionValidationError,
)
from cremore.domain.connections import (
    job_kind_for,
    job_payload_for,
    validate_connection,
)
from cremore.domain.models import ConnectionStatus, ScanJob
from cremore.scanning import Orchestrator


class ScanRequest(BaseModel):
    text: str
    source_type: str = "inline"
    resource_name: str = "inline"
    location: str = "inline"
    exposure: str = "unknown"


class ConnectionUpdateRequest(BaseModel):
    status: str | None = None  # ACTIVE | DISABLED
    config: dict | None = None
    # Refused: the credential is the provider connection's (PUT /api/v1/provider-connections/{id}/credential).
    secret_ref: str | None = None
    token: str | None = None


def create_app(
    repo: Repository | None = None,
    settings: Settings | None = None,
    secrets_inventory_factory=None,
    oidc_http_client=None,
    rotation_service_factory=None,
    aws_role_validator=None,
    aws_identity_probe=None,
    aws_remediation_validator=None,
    usage_service_factory=None,
    potential_access_factory=None,
    key_action_adapter_factory=None,
    secret_metadata_factory=None,
    aws_sessions=None,
    task_states=None,
    aws_discovery_probe=None,
    aws_discovery_sweep=None,
) -> FastAPI:
    from cremore.api.auth import build_verifier, make_auth
    from cremore.detection.engine import EngineConfig
    from cremore.detection.verify import VerifierConfig

    settings = settings or get_settings()
    settings.validate_safety("api")
    repo = repo if repo is not None else InMemoryRepository()
    from cremore.operations import audit_integrity

    audit_integrity.attach(repo, settings)  # audit rows this API writes carry its entry MAC
    # Keyed fingerprints and the verification switch come from configuration so
    # the API's inline scan behaves exactly like the worker's.
    from cremore.scanning.learned_fp import LearnedFPService

    learned_fp = LearnedFPService(repo, settings)
    orchestrator = Orchestrator(
        repo,
        config=EngineConfig(
            fingerprint_key=settings.fingerprint_key_bytes,
            verify=VerifierConfig(enabled=settings.verification_enabled,
                                  known_github_hosts=settings.known_github_hosts),
        ),
        rule_provider=repo.list_rules,
        learned_fp=learned_fp,
    )

    app = FastAPI(title="CreMore", version="0.1.0")
    app.add_middleware(_BoundedRequestBody, max_input_bytes=settings.max_input_bytes)
    app.state.repo = repo
    app.state.settings = settings
    app.state.orchestrator = orchestrator

    verifier = None
    from cremore.identity import sign_in_groups

    # Google sign-in carries no groups: the worker reads the role groups' members from Google Workspace.
    try:
        sign_in_groups.publish_wanted(repo, settings)
    except Exception as exc:  # noqa: BLE001 -- the API serves without it; the worker keeps the groups it was asked for
        logging.getLogger(__name__).warning("could not publish the sign-in role groups: %s", type(exc).__name__)
    if settings.auth_mode == "oidc":
        if oidc_http_client is None:
            import httpx

            oidc_http_client = httpx.Client(timeout=10.0, follow_redirects=False)
        verifier = build_verifier(settings, oidc_http_client,
                                  groups_of=sign_in_groups.Lookup(repo, settings) if sign_in_groups.google(settings) else None)
    app.state.oidc_verifier = verifier
    # require_auth -> actor id; require_role(min) -> actor id after a role check;
    # require_principal -> the Principal (subject + role) for the session endpoint.
    from cremore.governance import principals

    activity = None
    if settings.auth_mode == "oidc":
        from cremore.api.activity_audit import ActivityAudit, ActivityMiddleware

        activity = ActivityAudit(repo)
        app.add_middleware(ActivityMiddleware, audit=activity)
    require_auth, require_role, require_principal = make_auth(
        settings, verifier, on_principal=lambda who: principals.remember(repo, settings, who.subject, who.email),
        on_request=activity.begin if activity else None)

    register_http_handlers(app)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok", "version": app.version}

    finding_routes.register_reads(app, repo, settings, require_auth)

    @app.post("/api/v1/scan", status_code=202)
    def scan(body: ScanRequest, _actor: str = Depends(require_role("analyst"))) -> dict:
        orchestrator.refresh_rules()
        data = body.text.encode("utf-8")
        if len(data) > settings.max_input_bytes:
            raise HTTPException(status_code=413, detail="scan input exceeds MAX_INPUT_BYTES")
        resource = ResourceRef(
            source_type=body.source_type,
            resource=body.resource_name,
            location=body.location,
            metadata={"exposure": body.exposure},
        )
        # The engine's ceiling comes from settings; the dashboard switch decides per scan.
        from cremore.scanning import verification_switch

        verify = None if verification_switch.switch(repo)["enabled"] else False
        from cremore.scanning import scan_switches
        vconfig = scan_switches.verify_config_for(orchestrator.config.verify, settings, repo)
        result = orchestrator.scan_resource(data, resource, verify=verify, verify_config=vconfig)
        return {
            "detections": result.detections,
            "findings": [
                _finding_summary(f, repo.get_credential(f.credential_id)) for f in result.findings
            ],
        }

    @app.get("/api/v1/scan-jobs")
    def list_scan_jobs(_actor: str = Depends(require_auth), limit: int = 100) -> list[dict]:
        limit = max(1, min(limit, 500))
        return [scan_job_public(job) for job in repo.list_jobs(limit)]

    @app.get("/api/v1/scan-jobs/{job_id}")
    def get_scan_job(job_id: uuid.UUID, _actor: str = Depends(require_auth)) -> dict:
        job = repo.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        return scan_job_public(job)

    # --- connections --------------------------------------------------------
    # (GET /api/v1/connections — the list with declarations and capability
    # projection — lives in cremore.api.dashboard.) Sources are created by a
    # provider connection's step 4 (cremore/onboarding), never on their own.

    @app.get("/api/v1/connections/{connection_id}")
    def get_connection(connection_id: uuid.UUID, _actor: str = Depends(require_auth)) -> dict:
        conn = repo.get_connection(connection_id)
        if conn is None:
            raise HTTPException(status_code=404, detail="connection not found")
        return _connection_public(conn)

    @app.patch("/api/v1/connections/{connection_id}")
    def update_connection(
        connection_id: uuid.UUID,
        body: ConnectionUpdateRequest,
        _actor: str = Depends(require_role("admin")),
    ) -> dict:
        conn = repo.get_connection(connection_id)
        if conn is None:
            raise HTTPException(status_code=404, detail="connection not found")
        if body.secret_ref is not None or body.token is not None:
            raise HTTPException(status_code=409, detail=(
                "CREDENTIAL_BELONGS_TO_PROVIDER_CONNECTION: change it on the provider connection"))
        changes: dict = {}
        if body.status is not None:
            if body.status not in (ConnectionStatus.ACTIVE.value, ConnectionStatus.DISABLED.value):
                raise HTTPException(status_code=422, detail="status must be ACTIVE or DISABLED")
            changes["status"] = body.status
        if body.config is not None:
            candidate = conn.model_copy(update={"config": body.config})
            try:
                validate_connection(candidate)
            except ConnectionValidationError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
            changes["config"] = body.config
        updated = repo.update_connection(connection_id, **changes)
        return _connection_public(updated)

    @app.post("/api/v1/connections/{connection_id}/scan", status_code=202)
    def scan_connection(
        connection_id: uuid.UUID, _actor: str = Depends(require_role("analyst"))
    ) -> dict:
        conn = repo.get_connection(connection_id)
        if conn is None:
            raise HTTPException(status_code=404, detail="connection not found")
        if conn.status == ConnectionStatus.DISABLED.value:
            raise HTTPException(status_code=409, detail="connection is disabled")
        payload = job_payload_for(conn)
        if conn.secret_ref:
            payload["secret_ref"] = conn.secret_ref
        job = repo.enqueue_job(
            ScanJob(kind=job_kind_for(conn), payload=payload, connection_id=conn.id)
        )
        return {"id": str(job.id), "status": job.status}

    finding_routes.register_triage(app, repo, learned_fp, require_auth, require_role)

    # --- AWS Secrets Manager inventory (read-only; no secret values) --------

    # The dashboard contract the Next.js web/ calls through CREMORE_API_URL.
    from cremore.api.coverage import register_coverage_routes
    register_coverage_routes(app, repo, orchestrator, require_auth, require_role, aws_sessions, settings, require_principal)
    from cremore.api.metadata_coverage import register_metadata_routes
    register_metadata_routes(app, repo, require_auth, require_role, require_principal, settings)
    from cremore.api.gcp_coverage import register_gcp_routes
    register_gcp_routes(app, repo, require_auth)
    from cremore.api.gcp_oauth import register_gcp_oauth_routes
    register_gcp_oauth_routes(app, repo, settings, require_role)
    from cremore.api.dashboard import register_dashboard_routes

    register_dashboard_routes(
        app,
        repo,
        settings,
        require_auth,
        secrets_inventory_factory=secrets_inventory_factory,
        require_role=require_role,
        rotation_service_factory=rotation_service_factory,
        require_principal=require_principal,
        aws_role_validator=aws_role_validator,
        aws_identity_probe=aws_identity_probe,
        aws_discovery_probe=aws_discovery_probe,
        aws_discovery_sweep=aws_discovery_sweep,
        aws_remediation_validator=aws_remediation_validator,
        usage_service_factory=usage_service_factory,
        task_states=task_states,
        potential_access_factory=potential_access_factory,
        key_action_adapter_factory=key_action_adapter_factory,
        secret_metadata_factory=secret_metadata_factory,
        aws_sessions=aws_sessions,
        learned_fp=learned_fp,
    )

    @app.get("/api/v1/aws/secrets-inventory")
    def secrets_inventory(account_id: str | None = None, _actor: str = Depends(require_auth)) -> dict:
        # Wiring the factory only means the installation allows this; whether it
        # runs is an Admin's switch, and it has to hold on every path that can
        # reach AWS, not only the one the dashboard happens to call.
        from cremore_aws_provider.investigation import investigation_switches

        if secrets_inventory_factory is None or not investigation_switches.effective(
                settings, repo, investigation_switches.SECRETS_INVENTORY):
            raise HTTPException(status_code=501, detail="SECRETS_INVENTORY_OFF: "
                                "secret inventory is switched off for this installation")
        from cremore.api.aws_support import secrets_inventory_session

        if getattr(settings, "isolated_deployment", False):
            from cremore.api.aws_support import queue_aws_read
            return queue_aws_read(repo, settings, "secrets-inventory", _actor,
                                  {"account_id": account_id, "compact": False})
        session = secrets_inventory_session(repo, settings, aws_sessions, account_id)
        inv = secrets_inventory_factory(session)
        return {
            "account_id": session.account_id,
            "collected_via": session.via,
            "region": inv.region,
            "collection_status": inv.collection_status,
            "error_code": inv.error_code,
            "total": len(inv.secrets),
            "without_rotation": len(inv.without_rotation),
            "secrets": [_secret_record_public(s) for s in inv.secrets],
        }

    # Registered last: any dashboard path this API does not implement answers
    # 501 with a reason instead of a bare 404, so a panel shows *why*.
    @app.api_route(
        "/api/v1/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        include_in_schema=False,
    )
    def not_supported(path: str, _actor: str = Depends(require_auth)):
        raise HTTPException(
            status_code=501,
            detail=f"not supported by this API: /api/v1/{path} "
            "(see docs/ARCHITECTURE.md, dashboard support matrix)",
        )

    return app
