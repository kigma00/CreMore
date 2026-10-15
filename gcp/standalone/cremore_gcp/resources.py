"""Google resource identifiers and pure metadata normalization rules."""

from __future__ import annotations

import re
from typing import Any

from .transport import ApiError

PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,61}[a-z0-9]$")
SA_EMAIL_RE = re.compile(
    r"^[a-z0-9][a-z0-9-]{0,62}@(?:[a-z0-9-]{1,63}\.iam\.gserviceaccount\.com"
    r"|developer\.gserviceaccount\.com|appspot\.gserviceaccount\.com)$"
)
RESOURCE_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")
# IAM service-account key IDs are the 40-character hexadecimal key fingerprint,
# not the arbitrary identifiers used by Secret Manager and other resources.
SERVICE_ACCOUNT_KEY_ID_RE = re.compile(r"^[0-9a-f]{40}$")
API_KEY_NAME_RE = re.compile(r"^projects/[0-9]+/locations/global/keys/[a-zA-Z0-9-]+$")
API_KEY_UID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
SECRET_NAME_RE = re.compile(r"^projects/[a-zA-Z0-9-]+/secrets/[a-zA-Z0-9_-]+$")
REGION_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
REGIONAL_SECRET_NAME_RE = re.compile(
    r"^projects/[a-zA-Z0-9-]+/locations/[a-z0-9-]+/secrets/[a-zA-Z0-9_-]+$"
)
KEY_NAME_RE = re.compile(r"^projects/[^/]+/serviceAccounts/[^/]+/keys/[a-zA-Z0-9_-]+$")
VERSION_NAME_RE = re.compile(
    r"^projects/[a-zA-Z0-9-]+/(?:locations/[a-z0-9-]+/)?secrets/[a-zA-Z0-9_-]+/versions/[1-9][0-9]*$"
)


def safe_string(value: Any, pattern: re.Pattern[str]) -> str | None:
    return value if isinstance(value, str) and pattern.fullmatch(value) else None


def status_value(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def resolved_error(code: str | None, service_state: str) -> str | None:
    if code == "permission_denied_or_api_disabled":
        if service_state == "enabled":
            return "permission_denied"
        if service_state == "disabled":
            return "api_disabled"
    return code


def secret_api_base(name: str) -> str:
    """A regional endpoint is derived from the approved name grammar only."""
    match = re.fullmatch(
        r"projects/[^/]+/locations/([a-z0-9-]+)/secrets/[^/]+(?:/versions/[1-9][0-9]*)?", name
    )
    if match:
        region = match.group(1)
        if not REGION_RE.fullmatch(region):
            raise ApiError("invalid_location_identifier")
        return f"https://secretmanager.{region}.rep.googleapis.com/v1"
    return "https://secretmanager.googleapis.com/v1"
