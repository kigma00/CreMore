"""Provider-owned collection contract for Slack's admin and audit log APIs."""

from . import API_ORIGIN

DESCRIPTOR = {
    "provider": "slack",
    "label": "Slack Enterprise",
    "purpose": ["issuer_inventory"],
    "editions": ["cloud"],
    "origins": [API_ORIGIN],
    "origin_hint": API_ORIGIN,
    "auth_types": ["bearer"],
    "auth_secret_roles": {"bearer": ["token"]},
    "scope_kinds": ["enterprise", "workspace"],
    "capabilities": ["inventory", "audit"],
    "modes": ["inventory"],
    "options": ["include_audit_events", "audit_lookback_days"],
    "defaults": {"options": {"requests_per_second": 0.3}},
    "native_export": True,
    "compare": True,
    "recollect": False,
    "limitations": [
        "ENTERPRISE_ORGANIZATION_ADMIN_USER_TOKEN_REQUIRED",
        "ADMIN_APPS_READ_SCOPE_REQUIRED",
        "AUDITLOGS_READ_SCOPE_AND_OWNER_INSTALL_REQUIRED_FOR_THE_AUDIT_LOG",
        "APPROVED_APPS_ARE_NOT_INSTALLATIONS",
        "TOKEN_VALUES_AND_WEBHOOK_URLS_NOT_RETURNED",
        "USER_TOKENS_ARE_LISTED_PER_APP_NOT_PER_USER",
        "NO_TOKEN_USE_IS_REPORTED",
        "AUDIT_LOG_READ_ONLY_WITHIN_THE_LOOKBACK_WINDOW",
    ],
}
