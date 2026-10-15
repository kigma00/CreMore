"""Pure metadata projection from the eight organization collectors.

Every field list, scope check and shape refusal is the teammate's. Only the
transport, pagination and CLI wrappers were dropped: this module never makes a
request. Missing and explicitly null fields stay distinct, and a repository
permission flag is never promoted into a token scope.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re

SLUG = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
REPO_NAME = re.compile(r"[A-Za-z0-9_.-]{1,100}")

# -- SSO credential authorizations (classic PAT, OAuth, App user token, SSH) --
SSO_FIELDS = (
    "login", "credential_id", "credential_type", "authorized_credential_id",
    "authorized_credential_title", "authorized_credential_note", "scopes",
    "credential_authorized_at", "credential_accessed_at",
    "authorized_credential_expires_at", "token_last_eight",
)
SSH_FIELDS = (
    "login", "credential_id", "credential_type", "authorized_credential_id",
    "authorized_credential_title", "fingerprint", "credential_authorized_at",
    "credential_accessed_at", "authorized_credential_expires_at",
)
SSO_TYPES = {
    "personal access token": ("classic_pat", "classic_pats", SSO_FIELDS),
    "OAuth app token": ("oauth_app_token", "oauth_app_tokens", SSO_FIELDS),
    "GitHub app token": ("github_app_user_token", "github_app_user_tokens", SSO_FIELDS),
    "SSH key": ("user_ssh_key", "user_ssh_keys", SSH_FIELDS),
}

# -- fine-grained PAT and its grants --------------------------------------
PAT_FIELDS = (
    "id", "token_id", "token_name", "repository_selection", "repositories_url",
    "permissions", "access_granted_at", "token_expired", "token_expires_at",
    "token_last_used_at",
)
REQUEST_FIELDS = tuple(k for k in PAT_FIELDS if k != "access_granted_at") + ("created_at", "reason")
OWNER_FIELDS = ("login", "id", "node_id", "type", "html_url", "avatar_url", "site_admin")
FULL_REPO_FIELDS = (
    "id", "node_id", "name", "full_name", "private", "visibility", "html_url",
    "archived", "disabled", "default_branch", "created_at", "updated_at", "pushed_at",
)

# -- App installations -----------------------------------------------------
ACCOUNT_FIELDS = ("login", "id", "node_id", "type", "html_url", "avatar_url", "site_admin")
INSTALLATION_FIELDS = (
    "id", "app_id", "app_slug", "target_id", "target_type", "repository_selection",
    "created_at", "updated_at", "suspended_at", "html_url", "access_tokens_url",
    "repositories_url", "single_file_name", "has_multiple_single_files", "single_file_paths",
)
ENTERPRISE_INSTALLATION_FIELDS = ("id", "client_id", "app_slug", "repository_selection",
                                  "permissions", "events", "created_at", "updated_at")

# -- deploy keys -----------------------------------------------------------
KEY_FIELDS = ("id", "title", "url", "verified", "created_at", "read_only", "added_by",
              "last_used", "enabled")
SHORT_REPO_FIELDS = ("id", "name", "full_name", "private", "visibility", "html_url",
                     "archived", "disabled")

# -- Actions policy and run context ---------------------------------------
ACTOR_FIELDS = ("id", "login", "type", "html_url")
RUN_FIELDS = (
    "id", "name", "path", "workflow_id", "run_number", "run_attempt", "event",
    "status", "conclusion", "head_branch", "head_sha", "created_at", "updated_at",
    "run_started_at", "html_url",
)
JOB_FIELDS = (
    "id", "run_id", "run_attempt", "name", "workflow_name", "status", "conclusion",
    "head_branch", "head_sha", "started_at", "completed_at", "html_url",
    "labels", "runner_id", "runner_name", "runner_group_id", "runner_group_name",
)
WORKFLOW_POLICY = {"default_workflow_permissions": str, "can_approve_pull_request_reviews": bool}
ACTIONS_POLICY = {"enabled": bool, "allowed_actions": str, "sha_pinning_required": bool}
FORK_POLICY = {
    "run_workflows_from_fork_pull_requests": bool,
    "send_write_tokens_to_workflows": bool,
    "send_secrets_and_variables": bool,
    "require_approval_for_fork_pr_workflows": bool,
}
DIAGNOSTIC_HEADERS = (
    "x-github-request-id", "x-accepted-github-permissions",
    "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after",
)


def slug(value):
    if not isinstance(value, str) or not SLUG.fullmatch(value):
        raise ValueError("invalid_organization_slug")
    return value


def positive_id(value):
    return type(value) is int and value > 0


def require_id(value):
    if not positive_id(value):
        raise ValueError("invalid_record_id")
    return value


def pick(row, fields):
    return {key: row[key] for key in fields if key in row}


def diagnostic_headers(headers):
    lowered = {key.lower(): value for key, value in (headers or {}).items()}
    return {key: lowered[key] for key in DIAGNOSTIC_HEADERS if key in lowered}


def project_pat(row, fields):
    """Select metadata fields; preserve missing fields separately from null."""
    result = pick(row, fields)
    if "owner" in row:
        owner = row["owner"]
        if owner is not None and not isinstance(owner, dict):
            raise ValueError("unexpected_owner_shape")
        result["owner"] = None if owner is None else pick(owner, OWNER_FIELDS)
    return result


def repository_metadata(row, org, *, fields=FULL_REPO_FIELDS, shallow=False):
    if not isinstance(row, dict):
        raise ValueError("unexpected_repository_shape")  # noqa: TRY004 - a provider response shape, not a caller argument type
    name = row.get("name")
    if not isinstance(name, str) or name in (".", "..") or not REPO_NAME.fullmatch(name):
        raise ValueError("invalid_repository_name")
    if not positive_id(row.get("id")):
        raise ValueError("invalid_repository_id")
    if (not isinstance(row.get("full_name"), str)
            or row["full_name"].casefold() != f"{org}/{name}".casefold()):
        raise ValueError("repository_scope_mismatch")
    if not shallow:
        owner = row.get("owner")
        if (not isinstance(owner, dict) or not isinstance(owner.get("login"), str)
                or owner["login"].casefold() != org.casefold()):
            raise ValueError("repository_scope_mismatch")
    return pick(row, fields)


def account_metadata(account):
    if account is None:
        return None
    if not isinstance(account, dict):
        raise ValueError("unexpected_account_shape")  # noqa: TRY004 - a provider response shape, not a caller argument type
    return pick(account, ACCOUNT_FIELDS)


def project_installation(row, kind, org):
    """Select metadata, including explicit nulls, after checking organization scope."""
    owner_key = "account" if kind == "installations" else "owner"
    owner = row.get(owner_key)
    if (not isinstance(owner, dict) or not isinstance(owner.get("login"), str)
            or owner["login"].casefold() != org.casefold()):
        raise ValueError("installation_scope_mismatch" if kind == "installations"
                         else "repository_scope_mismatch")
    result = pick(row, INSTALLATION_FIELDS if kind == "installations" else FULL_REPO_FIELDS)
    result[owner_key] = account_metadata(owner)
    if kind != "installations":
        return result
    if "permissions" in row:
        permissions = row["permissions"]
        if permissions is not None and (not isinstance(permissions, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            and value in {"read", "write", "admin", "none"}
            for key, value in permissions.items()
        )):
            raise ValueError("unexpected_permissions_shape")
        result["permissions"] = permissions
    if "events" in row:
        events = row["events"]
        if events is not None and (not isinstance(events, list)
                                   or not all(isinstance(event, str) for event in events)):
            raise ValueError("unexpected_events_shape")
        result["events"] = events
    if "suspended_by" in row:
        result["suspended_by"] = account_metadata(row["suspended_by"])
    # Raw response fields such as token, temp_clone_token and repository.permissions
    # are deliberately excluded. Repository permission flags are not token scopes.
    return result


def public_key_metadata(key):
    """Hash the decoded SSH wire-format public key, not the printable key text."""
    if key is None:
        return {"key_metadata_error": "public_key_unavailable"}
    try:
        if not isinstance(key, str):
            raise ValueError  # noqa: TRY004 - a provider response shape, not a caller argument type
        parts = key.split()
        if len(parts) < 2:
            raise ValueError
        algorithm = parts[0]
        blob = base64.b64decode(parts[1], validate=True)
        length = int.from_bytes(blob[:4], "big")
        if (not 1 <= length <= 256 or len(blob) < 4 + length + 4
                or blob[4:4 + length].decode("ascii") != algorithm):
            raise ValueError
        digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
        return {"key_algorithm": algorithm, "fingerprint": "SHA256:" + digest,
                "key_metadata_error": None}
    except (ValueError, binascii.Error, UnicodeError):
        # Retain the other key metadata, but explicitly report derivation failure.
        return {"key_metadata_error": "invalid_ssh_public_key_format"}


def deploy_key_metadata(row, repository):
    if not positive_id(row.get("id")):
        raise ValueError("invalid_deploy_key_id")
    for name in ("verified", "read_only", "enabled"):
        if name in row and row[name] is not None and type(row[name]) is not bool:
            raise ValueError("unexpected_key_flag_type")
    result = pick(row, KEY_FIELDS)
    result["credential_type"] = "Deploy key"
    result["repository"] = dict(repository)
    result.update(public_key_metadata(row.get("key")))
    return result


def policy_metadata(row, schema):
    if not isinstance(row, dict) or not any(key in row for key in schema):
        raise ValueError("unexpected_policy_response")
    for key, expected in schema.items():
        if key in row and row[key] is not None and type(row[key]) is not expected:
            raise ValueError("unexpected_policy_field_type")
    # Missing and explicit null remain distinct. No defaults are invented.
    return pick(row, schema)


def run_metadata(row, repository):
    if not positive_id(row.get("id")) or not positive_id(row.get("run_attempt")):
        raise ValueError("invalid_run_id_or_attempt")
    linked = row.get("repository")
    if (not isinstance(linked, dict) or linked.get("id") != repository["id"]
            or not positive_id(linked.get("id"))
            or not isinstance(linked.get("full_name"), str)
            or linked["full_name"].casefold() != repository["full_name"].casefold()):
        raise ValueError("run_repository_scope_mismatch")
    result = pick(row, RUN_FIELDS)
    for name in ("actor", "triggering_actor"):
        if name in row:
            if row[name] is not None and not isinstance(row[name], dict):
                raise ValueError("unexpected_actor_shape")
            result[name] = None if row[name] is None else pick(row[name], ACTOR_FIELDS)
    if "head_repository" in row:
        head = row["head_repository"]
        if head is not None and not isinstance(head, dict):
            raise ValueError("unexpected_head_repository_shape")
        result["head_repository"] = None if head is None else pick(
            head, ("id", "full_name", "fork", "private", "visibility"))
    return result


def job_metadata(row, run):
    if not positive_id(row.get("id")):
        raise ValueError("invalid_job_id")
    if (type(row.get("run_id")) is not int or row["run_id"] != run["id"]
            or ("run_attempt" in row and (type(row["run_attempt"]) is not int
                                          or row["run_attempt"] != run["run_attempt"]))):
        raise ValueError("job_run_scope_mismatch")
    if "labels" in row and row["labels"] is not None and (
        not isinstance(row["labels"], list) or not all(isinstance(v, str) for v in row["labels"])
    ):
        raise ValueError("unexpected_runner_labels")
    return pick(row, JOB_FIELDS)


def installation_info(item):
    """The Enterprise engine's installation check, before a token is requested."""
    if not isinstance(item, dict) or not positive_id(item.get("id")):
        raise ValueError("invalid_installation_response")
    account = item.get("account")
    if not isinstance(account, dict):
        raise ValueError("invalid_installation_response")  # noqa: TRY004 - a provider response shape, not a caller argument type
    login = account.get("login") or account.get("slug")
    slug(login)
    target = item.get("target_type") or account.get("type") or (
        "Enterprise" if account.get("slug") else "Unknown")
    if not isinstance(item.get("permissions"), dict):
        raise ValueError("invalid_installation_permissions")  # noqa: TRY004 - a provider response shape, not a caller argument type
    selection = item.get("repository_selection")
    return {"id": item["id"], "target_type": target, "account_login": login,
            "account_id": account.get("id") if positive_id(account.get("id")) else None,
            "app_id": item.get("app_id"), "suspended_at": item.get("suspended_at"),
            "repository_selection": selection if selection in ("all", "selected") else None,
            "permissions": {name: level for name, level in sorted(item["permissions"].items())
                            if isinstance(name, str) and isinstance(level, str)
                            and 0 < len(name) <= 100 and 0 < len(level) <= 32}}


# -- Enterprise inventory and audit allowlists ----------------------------
# Copied from the Enterprise program's evidence projection. A field outside
# these sets never reaches storage, and a secret-shaped key never does at all.
INVENTORY_FIELDS = frozenset({
    "inventory_id", "credential_id", "fingerprint", "item_type", "credential_type",
    "display_name", "owner", "owner_id", "owner_type", "application", "application_id", "credential_state", "basis",
    "authorization_state", "effective_access_state", "state_reason", "created_at",
    "updated_at", "last_used_at", "expires_at", "next_expires_at",
    "credential_instance_count", "enterprise_authorized", "authorization_count",
    "authorized_organizations", "age_days", "never_expires", "past_expiration_policy",
    "past_expiration_policy_basis", "expiry_unknown", "expiry_status", "scopes",
    "permissions", "repository_selection", "repositories", "source_endpoint",
    "source_scope", "org", "repository", "installation_id", "app_id", "client_id",
    "app_slug", "account", "suspended_at", "read_only", "key_algorithm", "added_by",
    "enabled", "access_granted_at", "authorization_id", "credential_accessed_at",
    "credential_authorized_at", "token_expired", "policy", "title", "name",
    "html_url", "target_id", "target_type", "single_file_name", "has_multiple_single_files",
    "single_file_paths", "events", "checks", "public_key_last_used", "account_type",
})
AUDIT_FIELDS = frozenset({
    "source_endpoint", "source_scope", "@timestamp", "_document_id", "action", "actor",
    "actor_id", "actor_is_bot", "actor_is_agent", "actor_location", "actor_ip", "business",
    "business_id", "org", "org_id", "repo", "repo_id", "repository", "repository_id", "user",
    "user_id", "user_agent", "created_at", "operation_type", "request_id",
    "programmatic_access_type", "token_id", "token_scopes", "user_programmatic_access_id",
    "user_programmatic_access_name", "user_programmatic_access_request_id", "repositories",
    "repository_selection", "fingerprint", "managed_token_id", "managed_token_scopes",
    "managed_oauth_access_id", "managed_oauth_scopes", "application_id", "application_name",
    "application_type", "application_client_id", "oauth_application_id", "oauth_application",
    "oauth_credential_type", "owner", "owner_id", "owner_type", "title", "name", "read_only",
    "public_repo", "explanation", "integration", "integration_id", "permissions",
    "old_permissions", "scopes", "old_scopes", "token_expiration", "old_token_expiration",
    "exempt_administrators", "reason", "state", "previous_state", "new_state", "access",
    "old_access", "visibility",
})
SECRET_KEYS = re.compile(
    r"(?i)(?:^authorization$|(?:^|_)(?:secret|password|private_key|access_token"
    r"|refresh_token|hashed_token|pem)(?:$|_))"
)
CREDENTIAL_ACTION = re.compile(
    r"^(?:personal_access_token|org_credential_authorization|public_key|oauth_access|"
    r"oauth_authorization|oauth_application|integration_installation|integration|"
    r"github_app|fine_grained_personal_access_token|credential|business_credential_authorization|"
    r"auto_approve_personal_access_token_requests)\.|"
    r"^business\.(?:enable|disable)_app_delegated_credential_authorizations$")


def allowlisted(row, fields):
    """Keep approved names only, and never a key whose name reads as a secret."""
    return {key: value for key, value in row.items()
            if key in fields and not SECRET_KEYS.search(key)}
