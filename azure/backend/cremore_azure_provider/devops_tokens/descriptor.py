"""Declarative Azure DevOps token inventory onboarding; importing this performs no collection."""

from . import ORIGIN

DESCRIPTOR = {
    "provider": "azure_devops",
    "label": "Azure DevOps Services",
    "purpose": ["issuer_inventory"],
    "editions": ["cloud"],
    "origins": [ORIGIN],
    "origin_hint": ORIGIN,
    "auth_types": ["token", "private_key_jwt", "workload_identity"],
    "auth_secret_roles": {"token": ["token"], "private_key_jwt": ["client_id", "private_key", "tenant_id"],
                          "workload_identity": []},
    "scope_kinds": ["organization"],
    "capabilities": ["inventory"],
    "modes": ["inventory"],
    "options": ["sources"],
    "source_options": [
        {"value": "personal_access_tokens", "label": "Personal access tokens", "label_ko": "개인 액세스 토큰"},
    ],
    "defaults": {"options": {"sources": ["personal_access_tokens"]}},
    "native_export": True,
    "compare": False,
    "recollect": False,
    "limitations": [
        "ORGANIZATION_ADMIN_WITH_TOKEN_ADMINISTRATION_AND_GRAPH_READ_REQUIRED",
        "TOKENS_ARE_LISTED_PER_USER_FROM_THE_ORGANIZATION_GRAPH",
        "TOKEN_VALUES_AND_HASHES_ARE_NOT_RETURNED",
        "LISTING_ABSENCE_IS_NOT_REVOCATION",
        "PROVIDER_STATUS_IS_NOT_CREDENTIAL_VERIFICATION",
    ],
}
