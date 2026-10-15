"""Compatibility exports for the shared GCP key-material readers."""

from cremore_gcp.resources import API_KEY_NAME_RE, KEY_NAME_RE, VERSION_NAME_RE, secret_api_base
from cremore_gcp.transport import ApiError
from cremore_gcp.values import (
    MAX_PUBLIC_KEY_BYTES,
    MAX_SECRET_BYTES,
    crc32c,
    read_api_key_string,
    read_secret_version,
    read_service_account_public_key,
)
from cremore_gcp.values import (
    decode_base64 as _decode,
)

__all__ = [
    "API_KEY_NAME_RE",
    "KEY_NAME_RE",
    "MAX_PUBLIC_KEY_BYTES",
    "MAX_SECRET_BYTES",
    "VERSION_NAME_RE",
    "ApiError",
    "_decode",
    "crc32c",
    "read_api_key_string",
    "read_secret_version",
    "read_service_account_public_key",
    "secret_api_base",
]
