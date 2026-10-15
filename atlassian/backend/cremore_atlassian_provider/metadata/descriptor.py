"""Provider-owned onboarding metadata; importing it performs no collection."""

ATLASSIAN = {
    "provider": "atlassian",
    "label": "Atlassian organization",
    "purpose": ["issuer_inventory"],
    "editions": ["cloud", "enterprise_cloud"],
    "origins": ["https://api.atlassian.com"],
    "origin_hint": "https://api.atlassian.com",
    "auth_types": ["bearer"],
    "auth_secret_roles": {"bearer": ["token"]},
    "scope_kinds": ["organization"],
    "capabilities": ["inventory", "relations", "policy", "public_keys"],
    "modes": ["inventory", "discovery", "accounts"],
    "options": ["sources", "include_account_reads", "max_targets"],
    "native_export": True, "compare": True, "recollect": True,
    "limitations": [
        "SERVICE_ACCOUNT_LISTING_IS_A_PREVIEW_API",
        "API_ACCESS_AND_USER_MANAGEMENT_PERMISSIONS_ARE_NOT_THE_SAME",
        "INVENTORY_COMPLETE_IS_NEVER_CLAIMED",
    ],
}


BITBUCKET = {
    "provider": "bitbucket",
    "label": "Bitbucket",
    "purpose": ["issuer_inventory"],
    "editions": ["cloud", "enterprise_cloud", "data_center"],
    "origins": [],
    "origin_hint": "https://api.bitbucket.org",
    "auth_types": ["bearer", "basic"],
    "auth_secret_roles": {"bearer": ["token"], "basic": ["username", "password"]},
    "scope_kinds": ["workspace", "user", "project", "repository"],
    "capabilities": ["inventory", "relations", "policy", "public_keys"],
    "modes": ["bitbucket", "runners", "branch_restrictions", "inventory"],
    "options": ["max_targets", "api_path"],
    "native_export": True, "compare": True, "recollect": True,
    "edition_features": {
        "data_center": {"native_export": True, "compare": True, "recollect": True},
    },
    "limitations": [
        "A_PUBLIC_KEY_OR_KNOWN_HOST_IS_NOT_AN_EXPOSED_SECRET",
        "A_RUNNER_REPORTING_OFFLINE_IS_NOT_A_REVOKED_CREDENTIAL",
        "BRANCH_RESTRICTION_TOKEN_REFERENCES_ARE_NOT_A_TOKEN_LISTING",
        "CLOUD_FULL_ACCESS_TOKEN_LISTING_CONTRACT_IS_UNVERIFIED",
        "DATA_CENTER_10_4_LISTS_SELECTED_USER_PROJECT_REPOSITORY_HTTP_TOKEN_METADATA",
        "DATA_CENTER_REQUIRES_BEARER_INVENTORY_MODE_AND_APPROVED_SCOPES",
        "DATA_CENTER_LISTING_DOES_NOT_PROVE_EXPIRY_PERMISSIONS_OR_CURRENT_VALIDITY",
    ],
}
