"""GCP identifier matching shared with the platform-independent connector."""

from cremore_gcp.linkage import (
    GOOGLE_API_KEY_RE,
    LOOKUP_KEY_URL,
    match_api_key,
    match_service_account_key,
    service_account_key_identifier,
    service_account_key_identifiers,
)
from cremore_gcp.resources import (
    API_KEY_NAME_RE,
    RESOURCE_ID_RE,
    SA_EMAIL_RE,
)
from cremore_gcp.transport import ApiError

__all__ = [
    "API_KEY_NAME_RE",
    "GOOGLE_API_KEY_RE",
    "LOOKUP_KEY_URL",
    "RESOURCE_ID_RE",
    "SA_EMAIL_RE",
    "ApiError",
    "match_api_key",
    "match_service_account_key",
    "service_account_key_identifier",
    "service_account_key_identifiers",
]
