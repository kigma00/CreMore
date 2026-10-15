"""Inspect one Cloud admin response without printing credential metadata values.

This is a single-page diagnostic, not a complete inventory collector.
Only documented, fixed GET endpoints can be selected. No retries or redirects.
"""

import argparse
import json
import os
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path

if not __package__:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from cremore_atlassian_provider.metadata.connections import (
    load_cloud as load_connection,
)
from cremore_atlassian_provider.metadata.connections import (
    profile_argument,
)

BASE_URL = "https://api.atlassian.com/admin/api-access/v1"
MAX_BYTES = 1024 * 1024
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
ENDPOINTS = {
    "admin-api-keys": {
        "path": "api-keys?pageSize=20",
        "container": "data",
        "fields": (
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
        ),
    },
    "user-api-tokens": {
        "path": "api-tokens?pageSize=20",
        "container": "data",
        "fields": TOKEN_FIELDS,
    },
    "service-accounts": {
        "path": "service-accounts",
        "container": "items",
        "fields": (
            "id",
            "atlassianId",
            "displayName",
            "email",
            "status",
            "container",
            "updatedAt",
            "createdById",
            "description",
        ),
    },
    "service-account-api-tokens": {
        "path": "service-accounts/api-tokens",
        "container": None,
        "fields": TOKEN_FIELDS,
    },
    "service-account-oauth-clients": {
        "path": "service-accounts/oauth-clients",
        "container": None,
        "fields": (
            "clientId",
            "clientName",
            "serviceAccount.id",
            "scopes",
            "expiresAt",
            "createdAt",
            "createdBy.id",
            "clientRevokerId",
            "clientRevocationTime",
        ),
    },
    "org-oauth-clients": {
        "path": "oauth-clients?pageSize=20",
        "container": "data",
        "fields": ("clientId", "name", "createdAt", "updatedAt", "status"),
    },
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def field_type(record, field):
    value = record
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return "missing"
        value = value[part]
    return "null" if value is None else type(value).__name__


def summarize(endpoint, status, body):
    """Only emit fixed field names, JSON types, counts and booleans."""
    spec = ENDPOINTS[endpoint]
    result = {
        "endpoint": endpoint,
        "http_status": status,
        "body_type": type(body).__name__,
        "inventory_complete": False,
    }
    if status != 200:
        result["outcome"] = "http_error"
        return result
    container = spec["container"]
    records = (
        body if container is None else (body.get(container) if isinstance(body, dict) else None)
    )
    outcome = "documented_shape"
    if endpoint == "org-oauth-clients" and isinstance(body, list):
        records = body
        outcome = "observed_array_variant"
    if not isinstance(records, list):
        result["outcome"] = "unexpected_shape"
        return result
    result["outcome"] = outcome
    result["record_count"] = len(records)
    result["non_object_records"] = sum(not isinstance(r, dict) for r in records)
    if result["non_object_records"]:
        result["outcome"] = "unexpected_record_shape"
    if records:
        result["field_types"] = {
            f: sorted({field_type(r, f) for r in records if isinstance(r, dict)})
            for f in spec["fields"]
        }
    links = body.get("links") if isinstance(body, dict) else None
    result["next_field_type"] = field_type({"links": links}, "links.next")
    result["next_present"] = bool(links.get("next")) if isinstance(links, dict) else False
    # This tool intentionally never follows a cursor or declares total coverage.
    return result


def probe(endpoint, org_id, key, opener=None):
    org_id = str(uuid.UUID(org_id))
    url = BASE_URL + "/orgs/" + org_id + "/" + ENDPOINTS[endpoint]["path"]
    request = urllib.request.Request(
        url, method="GET", headers={"Authorization": "Bearer " + key, "Accept": "application/json"}
    )
    opener = opener or urllib.request.build_opener(NoRedirect())
    result = {
        "endpoint": endpoint,
        "observed_at": datetime.now(UTC).isoformat(),
        "requests": 1,
        "method": "GET",
        "inventory_complete": False,
    }
    try:
        try:
            response = opener.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result["http_status"] = response.code
            result["rate_limit_headers_present"] = [
                name
                for name in (
                    "X-RateLimit-Limit",
                    "X-RateLimit-Remaining",
                    "X-RateLimit-Reset",
                    "Retry-After",
                )
                if name in response.headers
            ]
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                result["outcome"] = "response_too_large"
            else:
                try:
                    body = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    result["outcome"] = "invalid_json"
                else:
                    result.update(summarize(endpoint, response.code, body))
    except (urllib.error.URLError, TimeoutError, OSError):
        result["outcome"] = "transport_error"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", choices=ENDPOINTS, default="admin-api-keys")
    parser.add_argument(
        "--profile",
        type=profile_argument,
        help="Explicit local connection name; never falls back to another profile.",
    )
    args = parser.parse_args()
    directory = Path.cwd() / ".local"
    try:
        org_id, key = load_connection(directory, args.profile)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        parser.exit(2, "Cannot load the selected private local connection. No request made.\n")
    result = probe(args.endpoint, org_id, key)
    result["connection_profile"] = args.profile
    filename = (
        "probe-"
        + datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        + "-"
        + uuid.uuid4().hex[:8]
        + ".json"
    )
    serialized = json.dumps(result, indent=2) + "\n"
    try:
        fd = os.open(directory / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(serialized)
    except OSError:
        parser.exit(2, "Request finished, but the sanitized report could not be saved.\n")
    print(serialized, end="")
    return 0 if result.get("outcome") == "documented_shape" else 1


if __name__ == "__main__":
    raise SystemExit(main())
