"""Google Workspace onboarding contract; importing it performs no collection."""

DESCRIPTOR = {
    "provider": "google_workspace",
    "label": "Google Workspace",
    "purpose": ["identity_status"],
    # "idp": lists people and their status; the departed-owner check reads them.
    "identity_role": "idp",
    "editions": ["cloud"],
    "origins": ["https://admin.googleapis.com"],
    "origin_hint": "https://admin.googleapis.com",
    "tenant": "domain",
    "auth_types": ["private_key_jwt"],
    # private_key: the service account's JSON key; username: the Workspace administrator it acts as.
    "auth_secret_roles": {"private_key_jwt": ["private_key", "username"]},
    "scope_kinds": ["organization"],
    "capabilities": ["identity_status"],
    "modes": ["inventory"],
    "options": ["page_size"],
    "defaults": {"options": {"page_size": 500}},
    "required_permissions": ["https://www.googleapis.com/auth/admin.directory.user.readonly (domain-wide delegation)"],
    "native_export": False,
    "compare": False,
    "recollect": False,
    "limitations": [
        "SERVICE_ACCOUNT_WITH_DOMAIN_WIDE_DELEGATION_OF_ADMIN_DIRECTORY_USER_READONLY",
        "EMAILS_ARE_KEPT_ONLY_AS_KEYED_DIGESTS",
        "SUSPENDED_ARCHIVED_AND_DELETED_COUNT_AS_DEPARTED",
        "A_SUSPENSION_IS_DATED_BY_THE_FIRST_COLLECTION_THAT_SAW_IT",
    ],
}
