"""Per-operation response fields pinned to four official OpenAPI documents.

The packaged field paths are derived data, not API responses. Explicit native
compatibility additions below preserve the teammate's documented observations.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files

from .bitbucket import OPERATIONS
from .read_operations import READ_OPERATIONS
from .specs import SOURCES, TOKEN_USER_FIELDS

OMITTED_TAIL = "_cremore_omitted_tail"
REPORT_FIELDS = frozenset(
    [
        "operation",
        "method",
        "coverage",
        "reason",
        "requests",
        "received_records",
        "saved_records",
        "last_http_status",
        "page_count",
        "redactions",
        "record_quality",
        "target_id",
        "requested_account_ids",
        "query",
        "coverage_basis",
        "accepted_records",
        "invalid_records",
        "duplicate_observations",
    ]
)
PAGE_FIELDS = frozenset(
    ["observed_at", "http_status", "redactions", "received_records", "saved_records"]
)
CONTEXT_FIELDS = frozenset(
    [
        "source",
        "attempt",
        "operation",
        "page_number",
        "target_id",
        "requested_account_ids",
        "container_name",
        "stage",
        "row_index",
        "mode",
        "config_hash",
    ]
)
SUMMARY_FIELDS = frozenset(
    [
        "schema_version",
        "report_type",
        "provider",
        "environment",
        "queried_org_id",
        "workspace",
        "started_at",
        "finished_at",
        "connection_profile",
        "inventory_complete",
        "run_status",
        "requested_sources",
        "limits",
        "target_discovery",
        "targets_omitted_by_limit",
        "count_ids_exceeding_contract_limit",
        "not_requested_no_observed_targets",
        "not_requested_by_configuration",
        "collections",
        "count_comparisons",
        "collection_mode",
        "targets",
        "key_details_omitted_by_limit",
        "runner_details_omitted_by_limit",
        "invalid_identifiers",
        "not_requested_operations",
        "not_requested_by_mode",
        "public_listing_contract_unverified",
        "identity_link_candidates",
        "counts",
        "warning_counts",
        "source_reasons",
    ]
)
INTERNAL_CHILDREN = {
    "redactions": {"secret_fields_omitted", "sensitive_values_omitted", "truncated_nodes"},
    "record_quality": {
        "assessed_records",
        "identified_records",
        "unique_identities",
        "duplicate_records",
        "invalid_records",
        "unidentified_records",
        "identity_not_configured_records",
    },
    "query": {"pageSize"},
    "limits": {
        "max_pages",
        "max_records",
        "max_requests",
        "max_seconds",
        "timeout",
        "retries",
        "max_retry_wait",
        "max_targets",
        "max_targets_per_kind",
        "org_api_tokens_page_size",
        "page_size",
    },
    "target_discovery": {
        "service_account_ids",
        "user_ids",
        "oauth_client_ids",
        "invalid_identifiers",
    },
    "targets": {"users", "projects", "repositories"},
    "targets_omitted_by_limit": {
        "users",
        "projects",
        "repositories",
        "service_account_ids",
        "user_ids",
        "oauth_client_ids",
    },
    "counts": {"observations", "identities", "unambiguous_credentials", "conflicted_identities"},
    "count_comparisons": {
        "listing",
        "count_operation",
        "listed_unique_ids",
        "reported_count",
        "equal_at_observation",
        "proves_completeness",
        "comparison_scope",
        "requested_account_count",
    },
    "identity_link_candidates": {"provider_id", "kinds", "state", "basis"},
    "warning_counts": {"name", "count"},
}


def valid_internal(value):
    def visit(node, name):
        if isinstance(node, dict):
            if "_cremore_omitted" in node:
                return True
            if name not in INTERNAL_CHILDREN or set(node) - INTERNAL_CHILDREN[name]:
                return False
            return all(visit(child, key) for key, child in node.items())
        if isinstance(node, list):
            return all(visit(child, name) for child in node)
        return node is None or type(node) in {str, bool, int, float}

    return all(visit(child, name) for name, child in value.items())


@lru_cache(maxsize=1)
def official_contracts():
    return json.loads(
        files(__package__).joinpath("response-fields.json").read_text(encoding="utf-8")
    )["operations"]


def _add(paths, prefix, dotted_name, types=()):
    parts = dotted_name.split(".")
    for index, part in enumerate(parts):
        prefix += "/" + part
        paths.setdefault(prefix, []).extend(types if index == len(parts) - 1 else ["object"])


@lru_cache(maxsize=50)
def response_paths(provider, operation):
    paths = {key: list(value) for key, value in official_contracts()[provider][operation].items()}
    if provider == "atlassian":
        if operation == "oauth-client-detail":
            paths["/createdAt"] = ["integer", "string"]
        if operation == "org-oauth-client-count":
            # Support-confirmed contract; the pinned public schema says total.
            # Keep the old total field readable in historical stored records.
            paths.update(
                {
                    key: list(value)
                    for key, value in official_contracts()[provider][
                        "service-account-token-counts"
                    ].items()
                }
            )
            return paths
        mapped = {
            "service-account-api-tokens-by-account": "service-account-api-tokens",
            "service-account-oauth-clients-by-account": "service-account-oauth-clients",
            "user-api-tokens": "org-api-tokens",
            "oauth-client-detail": "service-account-oauth-clients",
        }.get(operation, operation)
        if mapped in SOURCES:
            source = SOURCES[mapped]
            prefix = (
                ""
                if operation == "oauth-client-detail"
                else "/data/*"
                if source["paged"] and operation not in {"user-api-tokens"}
                else "/*"
            )
            for field in source["fields"]:
                _add(paths, prefix, field)
                if field == "scopes":
                    paths[prefix + "/scopes/*"] = ["string"]
            if mapped in {"admin-api-keys", "org-api-tokens", "service-account-api-tokens"}:
                # Live token/key responses reuse the same user metadata as
                # OAuth. Preserve the issuer and account context in discovery.
                parents = ("createdBy",) if mapped == "admin-api-keys" else ("createdBy", "user")
                for parent in parents:
                    for field in TOKEN_USER_FIELDS:
                        _add(paths, prefix, parent + "." + field, ["string"])
            if mapped == "org-oauth-clients":
                # Support-confirmed array shape; pagination remains unverified.
                for field in SOURCES["service-account-oauth-clients"]["fields"]:
                    _add(paths, "/data/*", field)
                    if field == "scopes":
                        paths["/data/*/scopes/*"] = ["string"]
                # Legacy data/links records use epoch milliseconds; the live
                # service-account-shaped array uses ISO timestamps.
                paths["/data/*/createdAt"] = ["integer", "string"]
        return paths
    if operation == "workspace-oidc-configuration":
        paths = {"": ["object"]}
        for field in (
            "issuer",
            "jwks_uri",
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
        ):
            paths["/" + field] = ["string"]
        for field in (
            "scopes_supported",
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
            "claims_supported",
        ):
            paths["/" + field], paths["/" + field + "/*"] = ["array"], ["string"]
    elif operation == "workspace-oidc-keys":
        paths = {"": ["object"], "/keys": ["array"], "/keys/*": ["object"]}
        for field in ("kid", "kty", "use", "alg", "n", "e", "x", "y", "crv", "x5t", "x5t#S256"):
            paths["/keys/*/" + field] = ["string"]
        for field in ("x5c", "key_ops"):
            paths["/keys/*/" + field], paths["/keys/*/" + field + "/*"] = ["array"], ["string"]
    elif operation == "workspace-gpg-key":
        paths = {
            "": [],
            "/values": ["array"],
            "/values/*": ["object"],
            "/next": ["string"],
            "/pagelen": ["integer"],
            "/size": ["integer"],
        }
        for field in ("key", "fingerprint", "created_on", "parent_fingerprint", "type"):
            paths["/values/*/" + field] = ["string"]
    elif operation in {"project-deploy-keys", "repository-deploy-keys",
                       "project-deploy-key-detail", "repository-deploy-key-detail"}:
        # The published Deploy Key responses use a numeric id. The pinned
        # schema omits it, but identity projection needs this documented field.
        prefix = "" if operation.endswith("-detail") else "/values/*"
        paths[prefix + "/id"] = ["integer"]
    if operation in {"repositories", "repository-detail"}:
        # The repository slug names each repository route (fan-out reads it); the pinned schema omits it.
        paths[("" if operation == "repository-detail" else "/values/*") + "/slug"] = ["string"]
    if "branch-restriction" in operation:
        prefix = "" if operation.endswith("-detail") else "/values/*"
        paths[prefix + "/access_tokens"] = ["array"]
        paths[prefix + "/access_tokens/*"] = ["object"]
        for field in ("id", "name", "uuid", "type"):
            paths[prefix + "/access_tokens/*/" + field] = []
    return paths


def response_prefix(provider, operation, value, *, row=False, container=None):
    spec = (READ_OPERATIONS if provider == "atlassian" else OPERATIONS)[operation]
    if row:
        prefix = (
            "/" + container + "/*" if container and container not in {"array", "scalar"} else "/*"
        )
        # The organization OAuth array is a specifically retained native variant
        # of the schema's data envelope, not a general alternate shape.
        if operation == "org-oauth-clients" and provider == "atlassian":
            return "/data/*"
        return prefix
    if spec["shape"] == "array_or_data" and isinstance(value, list):
        return "/data"
    return ""


def filter_response(provider, operation, value, *, row=False, container=None):
    paths = response_paths(provider, operation)
    prefix = response_prefix(provider, operation, value, row=row, container=container)

    def visit(node, path):
        if isinstance(node, dict) and "_cremore_omitted" in node:
            return node
        kinds = paths.get(path)
        if kinds is None:
            return {"_cremore_omitted": "unapproved_response_field"}
        kind = (
            "null"
            if node is None
            else {
                dict: "object",
                list: "array",
                str: "string",
                bool: "boolean",
                int: "integer",
                float: "number",
            }.get(type(node))
        )
        if (
            kind != "null"
            and kinds
            and kind not in kinds
            and not (kind == "integer" and "number" in kinds)
        ):
            return {"_cremore_omitted": "invalid_response_type"}
        if isinstance(node, dict):
            result = {}
            for name, child in node.items():
                child_path = path + "/" + name
                if child_path in paths:
                    result[name] = visit(child, child_path)
                else:
                    result[OMITTED_TAIL] = {"_cremore_omitted": "unapproved_response_field"}
            return result
        if isinstance(node, list):
            return [visit(child, path + "/*") for child in node]
        return node

    return visit(value, prefix)


def valid_normalized(value, operation):
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "source",
            "record_contract",
            "observed_at",
            "fields",
            "parent_states",
            "warnings",
            "derived",
        }
        or value["source"] != operation
    ):
        return False
    candidates = [SOURCES[operation]]
    if operation == "org-oauth-clients":
        candidates.append(SOURCES["service-account-oauth-clients"])
    source = next((item for item in candidates if item["kind"] == value["record_contract"]), None)
    if (
        source is None
        or not isinstance(value["fields"], dict)
        or set(value["fields"]) != set(source["fields"])
    ):
        return False
    for name, field in value["fields"].items():
        if (
            not isinstance(field, dict)
            or set(field) - {"state", "value", "normalized_utc"}
            or field.get("state") not in {"present", "null", "missing", "invalid_type"}
        ):
            return False
        if field["state"] != "present" and "value" in field:
            return False
        if field["state"] == "present":
            item = field.get("value")
            if name == "scopes":
                if not isinstance(item, list) or not all(isinstance(entry, str) for entry in item):
                    return False
            elif name in source.get("epoch_ms", ()):
                if type(item) is not int:
                    return False
            elif name in source.get("booleans", ()):
                if type(item) is not bool:
                    return False
            elif name in source.get("null_only", ()) or not isinstance(item, str):
                return False
    return (
        set(value["parent_states"]) <= set(source["parents"])
        and set(value["derived"]) <= {"expired_at_observation"}
        and isinstance(value["warnings"], list)
        and all(isinstance(item, str) for item in value["warnings"])
    )
