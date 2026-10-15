"""Project-scoped Google Cloud credential and vault-reference inventory.

The native collector's endpoints, allowlists and coverage vocabulary are kept
exactly. What changed is the shape: every list is a generator that hands one
page back before the next request, so the worker can commit that page with a
restart cursor and stop between pages. Value reads live in values.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import quote

from cremore_gcp.resources import (
    API_KEY_NAME_RE,
    API_KEY_UID_RE,
    KEY_NAME_RE,
    PROJECT_RE,
    REGION_RE,
    REGIONAL_SECRET_NAME_RE,
    RESOURCE_ID_RE,
    SA_EMAIL_RE,
    SECRET_NAME_RE,
    VERSION_NAME_RE,
    resolved_error,  # noqa: F401 -- Existing adapter imports remain supported.
    safe_string,
    secret_api_base,  # noqa: F401 -- Existing provider imports remain supported.
    status_value,
)

from .transport import DEFERRED, ApiError

SERVICES = ("iam.googleapis.com", "apikeys.googleapis.com", "secretmanager.googleapis.com")
_DISABLE_REASONS = {
    "SERVICE_ACCOUNT_KEY_DISABLE_REASON_USER_INITIATED",
    "SERVICE_ACCOUNT_KEY_DISABLE_REASON_EXPOSED",
    "SERVICE_ACCOUNT_KEY_DISABLE_REASON_COMPROMISE_DETECTED",
}
_CLIENT_RESTRICTIONS = (
    "browserKeyRestrictions",
    "serverKeyRestrictions",
    "androidKeyRestrictions",
    "iosKeyRestrictions",
)


@dataclass
class Page:
    """One provider page: rows to publish and the cursor that resumes after it."""

    rows: list[dict[str, Any]] = field(default_factory=list)
    cursor: dict[str, Any] | None = None
    status: str = "complete"
    error: str | None = None
    pages: int = 0
    received: int = 0


def response_pages(request, field_name, *, max_pages, cursor=None):
    """The same Google page-token contract serves inventory and read-only RPCs."""
    state = dict(cursor or {})
    token = state.get("page_token", state.get("token", ""))
    seen = set(state.get("seen", []))
    number = int(state.get("page", 0))
    while True:
        if number >= max_pages:
            yield Page(status="partial", error="page_limit_reached", pages=number)
            return
        number += 1
        try:
            response = request(token)
        except ApiError as exc:
            if exc.code in DEFERRED:
                raise
            yield Page(status="partial", error=exc.code, pages=number - 1)
            return
        values = response.get(field_name, [])
        if not isinstance(values, list) or not all(isinstance(row, dict) for row in values):
            yield Page(status="partial", error="invalid_response", pages=number)
            return
        next_token = response.get("nextPageToken", "")
        if not isinstance(next_token, str):
            yield Page(rows=values, status="partial", error="invalid_page_token", pages=number,
                       received=len(values))
            return
        if not next_token:
            yield Page(rows=values, status="complete", pages=number, received=len(values))
            return
        if next_token in seen:
            yield Page(rows=values, status="partial", error="page_token_cycle", pages=number,
                       received=len(values))
            return
        seen.add(next_token)
        token = next_token
        yield Page(rows=values, cursor={"page_token": token, "seen": sorted(seen), "page": number},
                   status="running", pages=number, received=len(values))


def time_value(value: Any) -> str | None:
    """Provider timestamps are copied only if RFC 3339 parses them."""
    from datetime import datetime

    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return None
    return value


def validate_options(project_id: str, max_pages: int) -> None:
    if not PROJECT_RE.fullmatch(project_id):
        raise ValueError("A valid GCP project ID is required")
    if not 1 <= max_pages <= 100000:
        raise ValueError("max_pages is out of range")


class Collector:
    """Paged reads over one project. Every method yields before its next request."""

    def __init__(self, project_id, transport, *, max_pages=100, page_size=100):
        validate_options(project_id, max_pages)
        self.project_id = project_id
        self.transport = transport
        self.max_pages = max_pages
        self.page_size = page_size
        self.project_aliases = {project_id}
        self._project_resolved = False

    def project_resource(self, name):
        """Bind numeric canonical names through the approved project's own metadata."""
        parts = name.split("/") if isinstance(name, str) else []
        if len(parts) < 3 or parts[0] != "projects":
            return False
        parent = parts[1]
        if parent in self.project_aliases:
            return True
        if not re.fullmatch(r"[1-9][0-9]{0,19}", parent):
            return False
        if not self._project_resolved:
            try:
                row = self.transport.get(f"https://cloudresourcemanager.googleapis.com/v3/projects/{self.project_id}")
            except ApiError as exc:
                if exc.code in DEFERRED:
                    raise
                row = {}
            self._project_resolved = True
            canonical = row.get("name") if isinstance(row, dict) else None
            if (isinstance(row, dict) and row.get("projectId") == self.project_id and isinstance(canonical, str)
                    and re.fullmatch(r"projects/[1-9][0-9]{0,19}", canonical)):
                self.project_aliases.add(canonical.split("/")[1])
        return parent in self.project_aliases

    def service_state(self, service: str) -> dict[str, str | None]:
        url = (
            f"https://serviceusage.googleapis.com/v1/projects/{self.project_id}/services/{service}"
        )
        try:
            response = self.transport.get(url)
        except ApiError as exc:
            if exc.code in DEFERRED:
                raise
            return {"state": "unknown", "error_code": exc.code}
        state = response.get("state")
        if state == "ENABLED":
            return {"state": "enabled", "error_code": None}
        if state == "DISABLED":
            return {"state": "disabled", "error_code": None}
        return {"state": "unknown", "error_code": "invalid_service_state"}

    def pages(self, url, field_name, *, cursor=None, page_size=None, extra_params=None):
        """Yield one response page at a time with the cursor that follows it."""
        def request(token):
            params = {"pageSize": page_size or self.page_size, **(extra_params or {})}
            if token:
                params["pageToken"] = token
            return self.transport.get(url, params)

        yield from response_pages(request, field_name, max_pages=self.max_pages, cursor=cursor)

    # -- projections -------------------------------------------------------

    def service_accounts(self, rows):
        project, items, invalid = self.project_id, [], 0
        for account in rows:
            email = safe_string(account.get("email"), SA_EMAIL_RE)
            if email is None:
                invalid += 1
                continue
            items.append({
                "object_type": "principal", "credential_type": None,
                "source": "gcp_iam_service_accounts", "project_id": project,
                "source_id": f"projects/{project}/serviceAccounts/{email}",
                "service_account_email": email,
                "disabled": status_value(account.get("disabled")),
                "display_name": account.get("displayName")
                if isinstance(account.get("displayName"), str) else None,
                "unique_id": safe_string(account.get("uniqueId"), RESOURCE_ID_RE),
            })
        return items, invalid

    def service_account_keys(self, email, *, account_id=None):
        """One account's keys: a single unpaged read in the native contract."""
        project = self.project_id
        encoded = quote(email, safe="@._-")
        response = self.transport.get(
            f"https://iam.googleapis.com/v1/projects/{project}/serviceAccounts/{encoded}/keys", None
        )
        keys = response.get("keys", [])
        if not isinstance(keys, list) or not all(isinstance(key, dict) for key in keys):
            raise ApiError("invalid_response")
        items, errors = [], {}
        for key in keys:
            key_type = key.get("keyType")
            if key_type not in ("USER_MANAGED", "SYSTEM_MANAGED"):
                errors["unexpected_key_type"] = errors.get("unexpected_key_type", 0) + 1
                continue
            name = safe_string(key.get("name"), KEY_NAME_RE)
            aliases = {email}
            if isinstance(account_id, str) and account_id.isascii() and account_id.isdigit():
                aliases.add(account_id)
            if name is None or not self.project_resource(name) or name.split("/")[3] not in aliases:
                errors["invalid_key_identifier"] = errors.get("invalid_key_identifier", 0) + 1
                continue
            # Resource aliases are accepted only from this run's account listing;
            # stable stored identity and follow-up requests use the approved email.
            name = f"projects/{project}/serviceAccounts/{email}/keys/{name.rsplit('/', 1)[-1]}"
            items.append({
                "object_type": "credential",
                "credential_type": "service_account_user_managed_key"
                if key_type == "USER_MANAGED" else "service_account_system_managed_key",
                "source": "gcp_iam_service_account_keys", "project_id": project,
                "source_id": name, "service_account_email": email,
                "key_id": name.rsplit("/", 1)[-1],
                "key_algorithm": key.get("keyAlgorithm")
                if isinstance(key.get("keyAlgorithm"), str) else None,
                "valid_after_time": time_value(key.get("validAfterTime")),
                "valid_before_time": time_value(key.get("validBeforeTime")),
                "disabled": status_value(key.get("disabled")),
                "disable_reason": key.get("disableReason")
                if key.get("disableReason") in _DISABLE_REASONS else None,
                "key_origin": key.get("keyOrigin")
                if key.get("keyOrigin") in ("USER_PROVIDED", "GOOGLE_PROVIDED") else None,
            })
        return items, errors

    def api_keys(self, rows):
        project, items, invalid = self.project_id, [], 0
        for key in rows:
            name = safe_string(key.get("name"), API_KEY_NAME_RE)
            if name is None or not self.project_resource(name):
                invalid += 1
                continue
            restrictions = key.get("restrictions")
            if isinstance(restrictions, dict):
                client_types = [k for k in _CLIENT_RESTRICTIONS if k in restrictions]
                client_type = (
                    client_types[0] if len(client_types) == 1
                    else "none" if not client_types else "ambiguous"
                )
                api_targets = restrictions.get("apiTargets", [])
                api_target_count = len(api_targets) if isinstance(api_targets, list) else None
                services = sorted({
                    target["service"] for target in api_targets
                    if isinstance(target, dict) and isinstance(target.get("service"), str)
                }) if isinstance(api_targets, list) else []
            else:
                client_type, api_target_count, services = "unknown", None, []
            items.append({
                "object_type": "credential", "credential_type": "api_key",
                "source": "gcp_api_keys", "project_id": project, "source_id": name,
                "key_id": name.rsplit("/", 1)[-1],
                "api_key_uid": safe_string(key.get("uid"), API_KEY_UID_RE),
                "display_name": key.get("displayName")
                if isinstance(key.get("displayName"), str) else None,
                "created_at": time_value(key.get("createTime")),
                "updated_at": time_value(key.get("updateTime")),
                "deleted_at": time_value(key.get("deleteTime")),
                "client_restriction_type": client_type,
                "api_target_count": api_target_count,
                "api_target_services": services,
                "service_account_email": safe_string(key.get("serviceAccountEmail"), SA_EMAIL_RE),
            })
        return items, invalid

    def secrets(self, rows, region=None):
        project, items, invalid = self.project_id, [], 0
        pattern = REGIONAL_SECRET_NAME_RE if region else SECRET_NAME_RE
        for secret in rows:
            name = safe_string(secret.get("name"), pattern)
            if (name is None or not self.project_resource(name)
                    or (region and name.split("/")[3] != region)):
                invalid += 1
                continue
            rotation = secret.get("rotation") if isinstance(secret.get("rotation"), dict) else {}
            items.append({
                "object_type": "vault_item", "credential_type": None,
                "source": "gcp_secret_manager", "project_id": project, "source_id": name,
                **({"location": region} if region else {}),
                "created_at": time_value(secret.get("createTime")),
                "expires_at": time_value(secret.get("expireTime")),
                "next_rotation_time": time_value(rotation.get("nextRotationTime")),
                "rotation_period": rotation.get("rotationPeriod")
                if isinstance(rotation.get("rotationPeriod"), str) else None,
                # Labels and annotations carry customer-chosen keys and free
                # text. The shared store keeps only approved field names, so
                # they are counted and recorded as an omission instead.
                "label_count": len(secret["labels"]) if isinstance(secret.get("labels"), dict) else None,
                "annotation_count": len(secret["annotations"])
                if isinstance(secret.get("annotations"), dict) else None,
            })
        return items, invalid

    def regions(self, rows):
        """Only supported non-global locations, from the provider's own list."""
        names, invalid = set(), 0
        for location in rows:
            name = location.get("name")
            match = (
                re.fullmatch(r"projects/[a-zA-Z0-9-]+/locations/([a-z0-9-]+)", name)
                if isinstance(name, str) else None
            )
            if match is None or not REGION_RE.fullmatch(match.group(1)):
                invalid += 1
                continue
            if match.group(1) != "global":
                names.add(match.group(1))
        return sorted(names), invalid

    def versions(self, rows, secret_name):
        items, invalid = [], 0
        for version in rows:
            name = safe_string(version.get("name"), VERSION_NAME_RE)
            state = version.get("state")
            if (name is None or not self.project_resource(name) or not name.startswith(secret_name + "/versions/")
                    or state not in ("ENABLED", "DISABLED", "DESTROYED")):
                invalid += 1
                continue
            items.append({
                "object_type": "vault_version", "credential_type": "secret_version",
                "source": "gcp_secret_manager", "project_id": self.project_id,
                "source_id": name, "parent_secret": secret_name, "state": state,
                "created_at": time_value(version.get("createTime")),
                "destroyed_at": time_value(version.get("destroyTime")),
            })
        return items, invalid


def lifecycle(item: dict, now: str | None = None) -> str:
    """Native lifecycle vocabulary; a listing gap is never a deletion.

    With ``now``, a service account key past its provider-reported
    validBeforeTime ("usable before this timestamp") is expired.
    """
    kind = item.get("credential_type")
    if kind == "api_key" and item.get("deleted_at"):
        return "deleted"
    if kind == "secret_version":
        return {"ENABLED": "active", "DISABLED": "disabled", "DESTROYED": "destroyed"}.get(
            item.get("state"), "unknown"
        )
    if item.get("disabled") is True:
        return "disabled"
    expiry = item.get("valid_before_time") if item.get("source") == "gcp_iam_service_account_keys" else None
    expires = datetime.fromisoformat(expiry) if now and expiry else None
    if expires is not None and expires.tzinfo is not None and expires <= datetime.fromisoformat(now):
        return "expired"
    return "active"
