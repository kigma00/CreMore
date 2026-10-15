"""GitHub SAML/SCIM identity onboarding contract; importing it performs no collection."""

DESCRIPTOR = {
    "provider": "github_identity",
    "label": "GitHub SAML/SCIM identities",
    "purpose": ["identity_status"],
    # "directory": names which person each GitHub login is; it lists no people's status.
    "identity_role": "directory",
    "identity_accounts_of": "github",
    "editions": ["enterprise_cloud", "cloud", "enterprise_server", "dedicated"],
    "origins": ["https://github.com"],
    "origin_hint": "https://ghes.example.com",
    "tenant": "none",
    "auth_types": ["bearer", "github_app"],
    "auth_secret_roles": {"bearer": ["token"], "github_app": ["app_id", "installation_id", "private_key"]},
    "scope_kinds": ["organization", "enterprise"],
    "capabilities": ["identity_status"],
    "modes": ["inventory"],
    "options": ["page_size"],
    "defaults": {"options": {"page_size": 100}},
    "required_permissions": ["classic PAT of an organization owner: read:org (or admin:org), authorized for SAML SSO",
                             "or a GitHub App installed on the organization: Members (read), for the organization's SAML",
                             ("classic PAT of an enterprise owner: read:enterprise (or admin:enterprise), for the "
                              "enterprise's managed users or SAML")],
    "native_export": False,
    "compare": False,
    "recollect": False,
    "limitations": [
        "ORGANIZATION_SAML_SSO_OR_ENTERPRISE_SSO_REQUIRED",
        "AN_ENTERPRISE_IS_READ_ALONE",
        "AN_ENTERPRISE_IS_READ_WITH_ITS_OWNER_TOKEN_NEVER_AN_APP",
        "UNCLAIMED_IDENTITIES_NAME_NO_LOGIN",
        "A_MANAGED_LOGIN_IS_NEVER_DERIVED_FROM_THE_IDP_USER_NAME",
        "NAME_IDS_AND_EMAILS_ARE_KEPT_ONLY_AS_KEYED_DIGESTS",
    ],
}
