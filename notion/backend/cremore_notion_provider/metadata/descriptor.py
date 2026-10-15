"""Provider-owned onboarding contract for the Enterprise Admin API."""

from . import ORIGIN

DESCRIPTOR = {
    "provider": "notion",
    "label": "Notion Enterprise",
    "purpose": ["issuer_inventory"],
    "editions": ["cloud"],
    "origins": [ORIGIN],
    "origin_hint": ORIGIN,
    "auth_types": ["bearer"],
    "auth_secret_roles": {"bearer": ["token"]},
    "scope_kinds": ["workspace"],
    "capabilities": ["inventory"],
    "modes": ["inventory"],
    "options": ["sources"],
    "source_options": [
        {"value": "personal_access_tokens", "label": "Personal access tokens", "label_ko": "개인 액세스 토큰"},
        {"value": "mcp_client_connections", "label": "MCP client connections", "label_ko": "MCP 클라이언트 연결"},
    ],
    "defaults": {"options": {"sources": ["personal_access_tokens"]}},
    "native_export": True,
    "compare": True,
    "recollect": False,
    "limitations": [
        "ENTERPRISE_PLAN_AND_ORGANIZATION_BOT_REQUIRED",
        "PAT_READ_SCOPE_REQUIRED",
        "MCP_CONNECTION_READ_SCOPE_REQUIRED_WHEN_REQUESTED",
        "TOKEN_VALUES_AND_SHARED_VALUE_DIGESTS_NOT_RETURNED",
        "INTERNAL_INTEGRATION_AND_ORGANIZATION_BOT_TOKENS_NOT_LISTED",
        "MCP_CONNECTIONS_ARE_NOT_INDIVIDUAL_ACCESS_OR_REFRESH_TOKENS",
        "LAST_USED_AT_UPDATES_AT_MOST_ONCE_PER_HOUR",
        "PROVIDER_STATUS_IS_NOT_CREDENTIAL_VERIFICATION",
    ],
}
