"""Bounded Google key-material reads shared by CLI and platform adapters.

Readers return values in memory. Callers own explicit storage and native output
formatting; no platform runtime or persistence dependency is loaded here.
"""

from __future__ import annotations

import base64
import re
from binascii import Error as Base64Error
from typing import Any

from .resources import API_KEY_NAME_RE, KEY_NAME_RE, VERSION_NAME_RE, secret_api_base
from .transport import ApiError

MAX_SECRET_BYTES = 65536
MAX_PUBLIC_KEY_BYTES = 16384


def crc32c(data: bytes) -> int:
    """Castagnoli CRC used by Secret Manager's dataCrc32c field."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def decode_base64(encoded: Any, *, max_bytes: int = MAX_SECRET_BYTES) -> bytes:
    if not isinstance(encoded, str):
        raise ApiError("invalid_payload")
    if len(encoded) > 4 * ((max_bytes + 2) // 3):
        raise ApiError("oversized_payload")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (Base64Error, ValueError):
        raise ApiError("invalid_payload") from None
    if len(data) > max_bytes:
        raise ApiError("oversized_payload")
    return data


def decode_secret_payload(payload: Any) -> bytes:
    if not isinstance(payload, dict):
        raise ApiError("invalid_payload")
    data = decode_base64(payload.get("data"))
    checksum = payload.get("dataCrc32c")
    if checksum is not None:
        if (isinstance(checksum, bool) or not isinstance(checksum, (int, str))
                or not re.fullmatch(r"[0-9]{1,10}", str(checksum))
                or not 0 <= int(checksum) <= 0xFFFFFFFF):
            raise ApiError("invalid_checksum")
        if int(checksum) != crc32c(data):
            raise ApiError("checksum_mismatch")
    return data


def read_api_key_string(transport, name: str) -> str:
    if not API_KEY_NAME_RE.fullmatch(name):
        raise ApiError("invalid_key_identifier")
    response = transport.get(f"https://apikeys.googleapis.com/v2/{name}/keyString")
    value = response.get("keyString")
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ApiError("invalid_key_string")
    return value


def read_service_account_public_key(transport, name: str) -> str:
    """The X.509 public certificate. Listing never returns the private key."""
    if not KEY_NAME_RE.fullmatch(name):
        raise ApiError("invalid_key_identifier")
    response = transport.get(
        f"https://iam.googleapis.com/v1/{name}", {"publicKeyType": "TYPE_X509_PEM_FILE"}
    )
    if response.get("name") != name:
        raise ApiError("invalid_key_identifier")
    data = decode_base64(response.get("publicKeyData"), max_bytes=MAX_PUBLIC_KEY_BYTES)
    try:
        public_key = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ApiError("invalid_public_key") from None
    if not (public_key.strip().startswith("-----BEGIN CERTIFICATE-----")
            and public_key.strip().endswith("-----END CERTIFICATE-----")):
        raise ApiError("invalid_public_key")
    return public_key


def read_secret_version(transport, name: str) -> bytes:
    """Access one immutable version; the provider checksum must agree."""
    if not VERSION_NAME_RE.fullmatch(name):
        raise ApiError("invalid_version_name")
    response = transport.get(f"{secret_api_base(name)}/{name}:access")
    if response.get("name") != name:
        raise ApiError("invalid_version_name")
    return decode_secret_payload(response.get("payload"))
