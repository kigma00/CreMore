"""Provider-owned onboarding metadata; importing it performs no collection."""

DESCRIPTOR = {
    "provider": "gcp",
    "label": "Google Cloud",
    "purpose": ["issuer_inventory", "vault_metadata", "usage"],
    "editions": ["cloud"],
    "origins": ["https://googleapis.com"],
    "origin_hint": "https://googleapis.com",
    # Integration: google_oauth comes from gcp-dashboard-oauth; the organization and
    # folder scopes come from refactoring's discovery mode, which also accepts OAuth.
    "auth_types": ["adc", "workload_identity", "google_oauth"],
    "auth_secret_roles": {"adc": [], "workload_identity": [],
                          "google_oauth": ["client_id", "client_secret", "refresh_token"]},
    "scope_kinds": ["project", "organization", "folder"],
    "capabilities": ["inventory", "vault_metadata", "relations", "public_keys",
                     "vault_value", "issuer_value"],
    "modes": ["inventory", "discovery"],
    "options": ["locations", "include_deleted", "include_values", "audit_lookback_days", "sources",
                "max_targets"],
    "defaults": {
        "capabilities": ["inventory", "vault_metadata", "public_keys", "issuer_value", "vault_value"],
        "options": {"include_deleted": True, "include_values": True},
        "schedule_minutes": 5,
    },
    "native_export": True, "compare": True, "recollect": False,
    "limitations": [
        "SERVICE_ACCOUNT_PRIVATE_KEYS_EXIST_ONLY_IN_THE_CREATE_RESPONSE",
        "API_KEY_LISTING_RETURNS_NO_KEY_STRING",
        "DELETED_API_KEYS_COVER_THE_LAST_30_DAYS_ONLY",
        "VERSION_LISTING_AND_VALUE_ACCESS_NEED_DIFFERENT_PERMISSIONS",
        "IAM_ALLOW_BINDINGS_ARE_NOT_EFFECTIVE_PERMISSION_EVALUATION",
        "AN_EMPTY_AUDIT_WINDOW_IS_UNKNOWN_NOT_UNUSED",
        "DISCOVERY_REQUIRES_ONE_ORGANIZATION_OR_FOLDER_AND_INVENTORY_CAPABILITY_ONLY",
        "DISCOVERED_PROJECTS_REQUIRE_SEPARATE_EXPLICIT_INVENTORY_AND_VALUE_ACCESS_APPROVAL",
        "RESOURCE_MANAGER_LISTS_DIRECT_CHILDREN_RECURSIVE_LISTING_NEEDS_ACCESS_AT_EACH_PARENT",
        "OAUTH_ACCESS_AND_REFRESH_TOKEN_SESSIONS_HAVE_NO_GLOBAL_GCP_INVENTORY_API",
    ],
}
