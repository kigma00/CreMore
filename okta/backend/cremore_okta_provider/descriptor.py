"""Okta onboarding contract; importing it performs no collection."""

DESCRIPTOR = {
    "provider": "okta",
    "label": "Okta",
    "purpose": ["identity_status"],
    # "idp": lists people and their status; the departed-owner check reads them.
    "identity_role": "idp",
    "editions": ["cloud"],
    "origins": [],
    "origin_hint": "https://example.okta.com",
    "tenant": "origin_host",
    "auth_types": ["private_key_jwt"],
    "auth_secret_roles": {"private_key_jwt": ["client_id", "private_key"]},
    "scope_kinds": ["organization"],
    "capabilities": ["identity_status"],
    "modes": ["inventory"],
    "options": ["page_size", "sources"],
    "defaults": {"options": {"page_size": 200}},
    "required_permissions": ["okta.users.read", "okta.apps.read (app list option only)"],
    "native_export": False,
    "compare": False,
    "recollect": False,
    "limitations": [
        "SERVICE_APP_WITH_PRIVATE_KEY_JWT_AND_ONE_READ_SCOPE_PER_COLLECTION",
        "EMAILS_AND_LOGINS_ARE_KEPT_ONLY_AS_KEYED_DIGESTS",
        "SUSPENDED_AND_DEACTIVATED_COUNT_AS_DEPARTED",
        "A_DELETED_USER_IS_DATED_BY_THE_FIRST_COMPLETE_LISTING_WITHOUT_IT",
    ],
}
