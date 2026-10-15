# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/read_operations.py).
"""Fixed public metadata reads; the two POST routes only return counts."""

import re
from urllib.parse import quote, urljoin, urlsplit

from .identities import CLOUD_IDS
from .specs import SOURCES

ORIGIN = "https://api.atlassian.com"
ACCESS = "/admin/api-access/v1/orgs/{org_id}/"
READ_OPERATIONS = {
    name: {
        "path": ACCESS + spec["path"],
        "method": "GET",
        "shape": "array_or_data"
        if name == "org-oauth-clients"
        else "data"
        if spec["paged"]
        else "array",
        "pager": "cursor" if spec["paged"] else None,
        "query": {"pageSize": 20} if spec["paged"] else {},
    }
    for name, spec in SOURCES.items()
}
READ_OPERATIONS.update(
    {
        "admin-api-key-count": {"path": ACCESS + "api-keys/count", "shape": "integer"},
        "org-api-token-count": {"path": ACCESS + "api-tokens/count", "shape": "integer"},
        "org-oauth-client-count": {
            "path": ACCESS + "oauth-clients/count",
            "method": "POST",
            # ECOHELP-167001: request is an account-ID array, not an empty POST.
            "shape": "account_counts",
        },
        "service-accounts": {"path": ACCESS + "service-accounts", "shape": "items", "pager": "url"},
        "service-account-token-counts": {
            "path": ACCESS + "service-accounts/count",
            "method": "POST",
            "shape": "account_counts",
        },
        "service-account-api-tokens-by-account": {
            "path": ACCESS + "service-accounts/{identifier}/api-tokens",
            "shape": "array",
        },
        "service-account-oauth-clients-by-account": {
            "path": ACCESS + "service-accounts/{identifier}/oauth-clients",
            "shape": "array",
        },
        "oauth-client-detail": {"path": ACCESS + "oauth-clients/{identifier}", "shape": "object"},
        "managed-accounts": {
            "path": "/admin/v1/orgs/{org_id}/users",
            "shape": "data",
            "pager": "url",
        },
        "user-management-permissions": {"path": "/users/{identifier}/manage", "shape": "object"},
        "user-profile": {"path": "/users/{identifier}/manage/profile", "shape": "object"},
        "user-api-tokens": {"path": "/users/{identifier}/manage/api-tokens", "shape": "array"},
    }
)
for _operation, _fields in CLOUD_IDS.items():
    READ_OPERATIONS[_operation]["identity_fields"] = _fields
STATIC_OPERATIONS = tuple(SOURCES) + (
    "admin-api-key-count",
    "org-api-token-count",
    "service-accounts",
    "managed-accounts",
)
ACCOUNT_DETAIL_OPERATIONS = ("user-management-permissions", "user-profile", "user-api-tokens")
ACCOUNT_COUNT_OPERATIONS = ("service-account-token-counts", "org-oauth-client-count")
# User Management OpenAPI: Manageability.RestrictionReason.key, not key material.
MANAGEMENT_REASON_CODES = frozenset(
    (
        "administrative",
        "administrative.notMyself",
        "authPolicy.saml",
        "blocked.exportControl",
        "externalDirectory.scim",
        "externalDirectory.google",
        "myselfOnly",
        "managedAccount",
    )
)


def valid_identifier(value, max_length=128):
    return (
        isinstance(value, str)
        and 1 <= len(value) <= max_length
        and re.fullmatch(r"[A-Za-z0-9:|_-]+", value) is not None
    )


def operation_url(operation, org_id, identifier=None):
    spec = READ_OPERATIONS[operation]
    if "{identifier}" in spec["path"]:
        if not valid_identifier(identifier):
            raise ValueError("Invalid metadata identifier")
    elif identifier is not None:
        raise ValueError("Unexpected metadata identifier")
    return ORIGIN + spec["path"].format(org_id=org_id, identifier=quote(identifier or "", safe=""))


class PaginationScopeError(ValueError):
    """The provider's next link leaves the configured metadata resource."""


def validate_next_url(current_base, next_url):
    """Follow only pagination on exactly the same HTTPS origin and resource path."""
    if not isinstance(next_url, str) or not next_url or len(next_url) > 8192:
        raise ValueError("Invalid pagination URL")
    if any(c.isspace() or ord(c) < 32 for c in next_url) or "\\" in next_url:
        raise ValueError("Invalid pagination URL")
    resolved = urljoin(current_base, next_url)
    base, target = urlsplit(current_base), urlsplit(resolved)
    if (
        target.scheme != "https"
        or target.netloc != base.netloc
        or target.path != base.path
        or target.fragment
        or target.username
        or target.password
    ):
        raise PaginationScopeError("Pagination target outside this metadata resource")
    return resolved
