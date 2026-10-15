# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/specs.py).
"""Fixed paths and selected metadata; no caller-supplied target URLs."""

TOKEN_FIELDS = (
    "id",
    "label",
    "status",
    "createdAt",
    "expiresAt",
    "lastActiveAt",
    "user.id",
    "user.orgId",
    "user.name",
    "user.email",
    "scopes",
)
KEY_FIELDS = (
    "id",
    "label",
    "createdAt",
    "expiresAt",
    "lastActiveAt",
    "systemAccountId",
    "resource",
    "orgId",
    "keyType",
    "scopes",
    "createdBy.id",
    "createdBy.name",
    "createdBy.email",
)
TOKEN_USER_FIELDS = ("id", "name", "email", "appType", "orgId", "userStatus")
SERVICE_OAUTH_FIELDS = (
    "clientId",
    "clientName",
    "createdAt",
    "expiresAt",
    "scopes",
    "clientRevokerId",
    "clientRevocationTime",
    "disabled",
    "tokenEndpointAuthMethod",
) + tuple(
    parent + "." + field
    for parent in ("serviceAccount", "createdBy")
    for field in TOKEN_USER_FIELDS
)

# Preserve native CLI defaults. The documented org OAuth cursor shape is supported;
# historical array responses remain explicitly unverified, never complete.
DEFAULT_SOURCES = ("admin-api-keys", "org-api-tokens", "service-account-api-tokens")
SOURCES = {
    "admin-api-keys": {
        "path": "api-keys",
        "kind": "admin_api_key",
        "paged": True,
        "fields": KEY_FIELDS,
        "parents": {"createdBy": True},
        "id_field": "id",
        "org_field": "orgId",
        "required": (
            "id",
            "label",
            "keyType",
            "createdAt",
            "expiresAt",
            "lastActiveAt",
            "createdBy.id",
            "createdBy.name",
            "createdBy.email",
        ),
    },
    "org-api-tokens": {
        "path": "api-tokens",
        "kind": "api_token",
        "paged": True,
        "fields": TOKEN_FIELDS,
        "parents": {"user": True},
        "id_field": "id",
        "org_field": "user.orgId",
        "required": ("id", "label", "status", "createdAt", "user.id", "user.name", "user.email"),
    },
    "service-account-api-tokens": {
        "path": "service-accounts/api-tokens",
        "kind": "api_token",
        "paged": False,
        "fields": TOKEN_FIELDS,
        "parents": {"user": True},
        "id_field": "id",
        "org_field": "user.orgId",
        "required": ("id", "label", "status", "createdAt", "user.id", "user.name", "user.email"),
    },
    "service-account-oauth-clients": {
        "path": "service-accounts/oauth-clients",
        "kind": "service_account_oauth_client",
        "paged": False,
        "fields": SERVICE_OAUTH_FIELDS,
        "parents": {"serviceAccount": True, "createdBy": False},
        "id_field": "clientId",
        "org_field": "serviceAccount.orgId",
        "required": (
            "clientId",
            "clientName",
            "scopes",
            "serviceAccount.id",
            "serviceAccount.name",
        ),
        # Undocumented fields observed in the lab; no provider-status inference.
        "booleans": ("disabled",),
        "null_only": ("tokenEndpointAuthMethod",),
    },
    "org-oauth-clients": {
        "path": "oauth-clients",
        "kind": "org_oauth_client",
        "paged": True,
        "fields": ("clientId", "name", "createdAt", "updatedAt", "status"),
        "parents": {},
        "id_field": "clientId",
        "org_field": None,
        "required": ("clientId", "name", "status"),
        "epoch_ms": ("createdAt", "updatedAt"),
        "allow_array_variant": True,
    },
}
