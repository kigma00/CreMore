"""Secret managers and the vault-coverage comparison.

Registered by the dashboard composition root. Shared behavior is imported
from independent API libraries; dependencies arrive through DashboardContext.
"""

from __future__ import annotations

from cremore_aws_provider.investigation import investigation_switches
from fastapi import Depends

from cremore.api.aws_support import secrets_inventory_session
from cremore.api.route_context import DashboardContext


def register(ctx: DashboardContext) -> None:
    app, aws_sessions, repo, require_auth = ctx.app, ctx.aws_sessions, ctx.repo, ctx.require_auth
    secrets_inventory_factory, settings = ctx.secrets_inventory_factory, ctx.settings

    @app.get("/api/v1/secret-managers")
    def secret_managers(_actor: str = Depends(require_auth)) -> dict:
        """The installation's secret-manager configuration: explicit, metadata-only references."""

        allowed = settings.secret_manager_reference_list
        return {"mode": "REAL", "scope": "THIS_INSTALLATION_CONFIGURATION",
                "items": [{"provider": "AWS_SECRETS_MANAGER", "mode": "METADATA_ONLY",
                           "coverage": "EXPLICIT_REFERENCES_ONLY", "allowed_references": allowed}] if allowed else []}

    @app.get("/api/v1/secret-managers/aws/inventory")
    def secret_managers_aws_inventory(account_id: str | None = None, _actor: str = Depends(require_auth)) -> dict:
        if secrets_inventory_factory is None or not investigation_switches.effective(
                settings, repo, investigation_switches.SECRETS_INVENTORY):
            return {"region": "", "collection_status": "NOT_CONFIGURED", "total": 0,
                    "without_rotation": 0, "secrets": []}
        if getattr(settings, "isolated_deployment", False):
            from cremore.api.aws_support import queue_aws_read
            return queue_aws_read(repo, settings, "secrets-inventory", _actor,
                                  {"account_id": account_id, "compact": True})
        session = secrets_inventory_session(repo, settings, aws_sessions, account_id)
        inv = secrets_inventory_factory(session)
        return {
            **session.evidence(),
            "region": inv.region,
            "collection_status": inv.collection_status,
            "total": len(inv.secrets),
            "without_rotation": len(inv.without_rotation),
            "secrets": [{"arn": s.arn, "name": s.name, "rotation_enabled": s.rotation_enabled,
                         "stale": s.stale} for s in inv.secrets],
        }
