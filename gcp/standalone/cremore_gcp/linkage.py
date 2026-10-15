"""Conservative GCP service-account key identifier matching.

The caller may hold a secret-bearing scan result in memory, but this function
only reads its client email and private key ID. It never returns the candidate
or any credential value. Matching IDs do not prove that a key is usable.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from .resources import API_KEY_NAME_RE, SA_EMAIL_RE, SERVICE_ACCOUNT_KEY_ID_RE
from .transport import ApiError, JsonTransport

GOOGLE_API_KEY_RE = re.compile(r"^AIza[A-Za-z0-9_-]{35}$")
LOOKUP_KEY_URL = "https://apikeys.googleapis.com/v2/keys:lookupKey"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_KEY_JSON_BYTES = 1024 * 1024
MAX_KEY_JSON_NODES = 1024
MAX_KEY_JSON_DEPTH = 32


def service_account_key_identifier(candidate: Mapping[str, Any]) -> str | None:
    """Return the passive inventory identity from JSON metadata alone.

    The private key and project_id fields are deliberately never read. The
    caller must bind this identifier to its approved project/connection; this
    does not establish possession, cryptographic consistency or validity.
    """
    if not isinstance(candidate, Mapping):
        return None
    email = candidate.get("client_email")
    key_id = candidate.get("private_key_id")
    if (candidate.get("type") != "service_account" or not isinstance(email, str)
            or not SA_EMAIL_RE.fullmatch(email) or not isinstance(key_id, str)
            or not SERVICE_ACCOUNT_KEY_ID_RE.fullmatch(key_id)):
        return None
    return f"serviceAccountKey:{email}:{key_id}"


def is_service_account_key_identifier(value: str) -> bool:
    parts = value.split(":") if isinstance(value, str) else []
    # The same checks service_account_key_identifier applies, made on the parts directly. Building a
    # key-JSON-shaped dict (type, client_email, private_key_id) here made container secret scanners
    # (Trivy's gcp-service-account rule) report a GCP key inside the shipped package.
    return (len(parts) == 3 and parts[0] == "serviceAccountKey"
            and bool(SA_EMAIL_RE.fullmatch(parts[1])) and bool(SERVICE_ACCOUNT_KEY_ID_RE.fullmatch(parts[2])))


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_FIELD")
        result[key] = value
    return result


def _invalid_json_constant(_value):
    raise ValueError("INVALID_JSON_CONSTANT")


def _pem_bytes(value: bytes) -> bytes | None:
    if not isinstance(value, bytes) or not 1 <= len(value) <= 16384:
        return None
    normalized = value.replace(b"\\r\\n", b"\n").replace(b"\\n", b"\n").replace(b"\r\n", b"\n")
    normalized = normalized.rstrip(b"\r\n")
    if (not normalized.startswith(b"-----BEGIN PRIVATE KEY-----\n")
            or not normalized.endswith(b"\n-----END PRIVATE KEY-----")):
        return None
    return normalized


def service_account_key_identifiers(data: bytes, private_key: bytes) -> tuple[str, ...]:
    """Link a detected PEM only to metadata in its own bounded JSON object.

    Escaped JSON and actual PEM newlines compare equally. Every distinct ID
    sharing the PEM is returned so the caller can keep ambiguity explicit.
    Malformed/duplicate-key/oversized JSON produces no link. There is no nearby
    text inference, cryptographic verification, credential use or I/O.
    """
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_KEY_JSON_BYTES:
        return ()
    detected = _pem_bytes(private_key)
    if detected is None:
        return ()
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_json_object,
                              parse_constant=_invalid_json_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return ()
    if not isinstance(document, (dict, list)):
        return ()
    pending, nodes, identifiers = [(document, 0)], 0, set()
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > MAX_KEY_JSON_NODES or depth > MAX_KEY_JSON_DEPTH:
            return ()
        if isinstance(value, dict):
            candidate_id = service_account_key_identifier(value)
            candidate_key = value.get("private_key") if candidate_id is not None else None
            if isinstance(candidate_key, str):
                try:
                    candidate_pem = _pem_bytes(candidate_key.encode("utf-8"))
                except UnicodeEncodeError:
                    candidate_pem = None
                if candidate_pem is not None and candidate_pem == detected:
                    identifiers.add(candidate_id)
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
    return tuple(sorted(identifiers))


def match_service_account_key(
    inventory: Mapping[str, Any], candidate: Mapping[str, Any]
) -> dict[str, str | None]:
    """Match a service-account JSON candidate to a listed user-managed key.

    A non-match is conclusive only for a complete project key inventory. The
    source project is taken from inventory, never inferred from the candidate.
    """
    identifier = service_account_key_identifier(candidate)
    if identifier is None:
        return {"status": "invalid_candidate", "source_id": None, "basis": None, "validity": "unverified"}
    _, email, key_id = identifier.split(":")

    matches = [
        item for item in inventory.get("items", [])
        if isinstance(item, dict)
        and item.get("object_type") == "credential"
        and item.get("credential_type") == "service_account_user_managed_key"
        and item.get("project_id") == inventory.get("project_id")
        and item.get("service_account_email") == email
        and item.get("key_id") == key_id
    ]
    if len(matches) == 1:
        return {
            "status": "identifier_match", "source_id": matches[0]["source_id"],
            "basis": "client_email+private_key_id", "validity": "unverified",
        }
    if len(matches) > 1:
        return {"status": "ambiguous_inventory", "source_id": None, "basis": None, "validity": "unverified"}

    key_coverage = inventory.get("coverage", {}).get("service_account_keys", {})
    status = "not_found_in_complete_scope" if key_coverage.get("status") == "complete" else "unknown_in_partial_scope"
    return {"status": status, "source_id": None, "basis": None, "validity": "unverified"}


def match_api_key(
    inventory: Mapping[str, Any], candidate: str, transport: JsonTransport
) -> dict[str, str | None]:
    """Look up a discovered Google API key and match its exact resource name.

    The candidate is sent only to Google's fixed lookup endpoint and is never
    returned. This is an explicit operator action, never scheduled collection.
    A resource-name match identifies the key, not its usability.
    """
    result: dict[str, str | None] = {
        "status": "invalid_candidate", "source_id": None,
        "basis": None, "validity": "unverified", "error_code": None,
    }
    if not isinstance(candidate, str) or not GOOGLE_API_KEY_RE.fullmatch(candidate):
        return result
    if inventory.get("provider") != "gcp" or not isinstance(inventory.get("items"), list):
        return {**result, "status": "invalid_inventory"}

    try:
        response = transport.get(LOOKUP_KEY_URL, {"keyString": candidate})
    except ApiError as exc:
        if exc.code == "http_404":
            return {**result, "status": "lookup_not_found"}
        return {**result, "status": "lookup_unavailable", "error_code": exc.code}

    name = response.get("name")
    parent = response.get("parent")
    if not name:
        return {**result, "status": "lookup_has_no_resource"}
    if (
        not isinstance(name, str) or not API_KEY_NAME_RE.fullmatch(name)
        or not isinstance(parent, str) or parent != name.rsplit("/keys/", 1)[0]
    ):
        return {**result, "status": "invalid_lookup_response"}

    matches = [
        item for item in inventory["items"]
        if isinstance(item, dict)
        and item.get("object_type") == "credential"
        and item.get("credential_type") == "api_key"
        and item.get("project_id") == inventory.get("project_id")
        and item.get("source_id") == name
    ]
    if len(matches) == 1:
        return {
            "status": "resource_match", "source_id": name,
            "basis": "google_keys_lookupKey_exact_name", "validity": "unverified",
            "error_code": None,
        }
    if len(matches) > 1:
        return {**result, "status": "ambiguous_inventory"}
    return {
        "status": "lookup_found_not_in_inventory", "source_id": name,
        "basis": "google_keys_lookupKey_exact_name", "validity": "unverified",
        "error_code": None,
    }


def scan_text(data: bytes, inventory: dict, transport) -> dict:
    """Resolve each distinct Google API key candidate without saving its value."""
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError("Source file exceeds 8 MiB")
    candidates: dict[str, list[int]] = {}
    # Use the same candidate shape as the CreMore Google API key detector.
    for match in re.finditer(rb"(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])", data):
        value = match.group().decode("ascii")
        if GOOGLE_API_KEY_RE.fullmatch(value):
            candidates.setdefault(value, []).append(data.count(b"\n", 0, match.start()) + 1)
    matches = []
    for candidate, lines in candidates.items():
        result = match_api_key(inventory, candidate, transport)
        matches.append({"line_numbers": lines[:100], "occurrences": len(lines), **result})
    return {
        "schema_version": "0.1", "provider": "gcp",
        "project_id": inventory.get("project_id"),
        "inventory_collected_at": inventory.get("collected_at"),
        "collected_at": datetime.now(UTC).isoformat(),
        "matches": matches,
    }
