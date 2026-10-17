"""FastAPI 앱 생성과 라우터 등록.

1. 설정으로 앱과 인증 의존성을 구성한다.
2. 기존 순서대로 컨트롤러를 등록한다.
3. 상태 확인 경로를 제공한다.
"""

from __future__ import annotations

from fastapi import FastAPI

from cremore.api import finding_routes
from cremore.api.http_support import BoundedRequestBody as _BoundedRequestBody
from cremore.api.http_support import register_http_handlers
from cremore.config import Settings, get_settings
from cremore.controller.aws_inventory_controller import AwsInventoryController
from cremore.controller.connection_controller import (
    ConnectionController,
)
from cremore.controller.scan_controller import (
    ScanController,
)
from cremore.controller.unsupported_controller import UnsupportedController
from cremore.db.repository import InMemoryRepository, Repository
from cremore.service.aws_inventory_service import AwsInventoryService
from cremore.service.bootstrap_service import BootstrapService
from cremore.service.connection_service import ConnectionService
from cremore.service.inline_scan_service import InlineScanService


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
    settings = settings or get_settings()
    settings.validate_safety("api")
    repo = repo if repo is not None else InMemoryRepository()
    BootstrapService.attach_audit(repo, settings)
    learned_fp, orchestrator = BootstrapService.scan_components(repo, settings)

    app = FastAPI(title="CreMore", version="0.1.0")
    app.add_middleware(_BoundedRequestBody, max_input_bytes=settings.max_input_bytes)
    app.state.repo = repo
    app.state.settings = settings
    app.state.orchestrator = orchestrator

    verifier = None
    from cremore.identity import sign_in_groups

    BootstrapService.publish_sign_in_groups(repo, settings)
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

    ScanController.register(
        app, InlineScanService(repo, settings, orchestrator), require_auth, require_role
    )

    # --- connections --------------------------------------------------------
    # (GET /api/v1/connections — the list with declarations and capability
    # projection — lives in cremore.api.dashboard.) Sources are created by a
    # provider connection's step 4 (cremore/onboarding), never on their own.

    ConnectionController.register(app, ConnectionService(repo), require_auth, require_role)

    finding_routes.register_triage(app, repo, learned_fp, require_auth, require_role)

    # --- AWS Secrets Manager inventory (read-only; no secret values) --------

    # The dashboard contract the Next.js web/ calls through CREMORE_API_URL.
    from cremore.api.coverage import register_coverage_routes
    register_coverage_routes(app, repo, orchestrator, require_auth, require_role, aws_sessions, settings, require_principal)
    from cremore.api.metadata_coverage import register_metadata_routes
    register_metadata_routes(app, repo, require_auth, require_role, require_principal, settings)
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

    from cremore_aws_provider.investigation import investigation_switches

    from cremore.api.aws_support import secrets_inventory_session

    AwsInventoryController.register(
        app,
        AwsInventoryService(
            repo, settings, aws_sessions, secrets_inventory_factory,
            lambda settings, repo: investigation_switches.effective(
                settings, repo, investigation_switches.SECRETS_INVENTORY
            ),
            secrets_inventory_session,
        ),
        require_auth,
    )

    # Registered last: any dashboard path this API does not implement answers
    # 501 with a reason instead of a bare 404, so a panel shows *why*.
    UnsupportedController.register(app, require_auth)

    return app
