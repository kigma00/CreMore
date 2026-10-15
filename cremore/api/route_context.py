"""Explicit dependencies shared by dashboard route registrars.

This module imports no routes or application factory. A registrar can be
imported independently, and a missing or misspelled dependency fails while
constructing the context. Provider service factories remain injection ports;
their concrete implementations are selected by the application composition root.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cremore_aws_provider.aws_sessions import AccountSessions
    from fastapi import FastAPI

    from cremore.config import Settings
    from cremore.db.catalog_store import CatalogStore
    from cremore.db.repository import Repository
    from cremore.governance.tickets import TicketService
    from cremore.remediation.action_plans import ActionPlanService
    from cremore.scanning.learned_fp import LearnedFPService

Callback = Callable[..., Any]


@dataclass(frozen=True, slots=True, kw_only=True)
class DashboardContext:
    """Application-scoped services and callbacks, fixed at route registration.

    Freezing the wiring does not freeze repositories, caches or services: their
    lifecycle and state remain owned by the application that supplies them.
    """

    app: FastAPI
    repo: Repository
    settings: Settings
    require_auth: Callback
    require_principal: Callback
    require_role: Callable[[str], Callback]
    action_plans: ActionPlanService
    ticket_service: TicketService
    catalog_store: CatalogStore
    learned_fp: LearnedFPService | None
    aws_sessions: AccountSessions | None

    current_detection_digest: Callable[[], str | None]
    task_states: Callback | None
    aws_discovery_probe: Callback
    aws_discovery_sweep: Callback
    key_action_adapter_factory: Callback | None
    potential_access_factory: Callback | None
    rotation_service_factory: Callback | None
    secret_metadata_factory: Callback | None
    secrets_inventory_factory: Callback | None
    usage_service_factory: Callback | None

    _INVESTIGATION_LABELS: Mapping[str, str]
    _account_session: Callback
    _api_identity: Callback
    _approvals: Callback
    _aws_hold: Callable[[], str | None]
    _base_payload: Callback
    _plan_error: Callback
    _profile_or_404: Callback
    _profiles_with_state: Callback
    _resolve: Callback
    _save_profile: Callback
    _scope_error: Callback
    _scope_plan_or_404: Callback
    _scope_target: Callback
    _secret_metadata: Callback
    _start_run: Callback
    _validate_account: Callback
    _worker_identity: Callback
