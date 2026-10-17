"""Passive customer-side projection. Secret bytes never become API observations."""

import json
import re

from cremore.coverage.models import Observation
from cremore.detection import DetectorInput, ResourceRef
from cremore.detection.fingerprint import fingerprint

_AWS_ID = re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_AWS_SECRET = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")


def hash_value(engine, value: bytes, location: dict, *, max_bytes: int) -> list[Observation]:
    def unresolved(reason):
        return [Observation(**location, evidence="UNRESOLVED", reason=reason)]

    if not engine.config.fingerprint_key or len(engine.config.fingerprint_key) < 32:
        raise ValueError("FINGERPRINT_KEY_REQUIRED")
    if len(value) > max_bytes:
        return unresolved("VALUE_TOO_LARGE")
    if not value:
        return unresolved("EMPTY_VALUE")
    try:
        value.decode("utf-8")
    except UnicodeDecodeError:
        return unresolved("UNSUPPORTED_BINARY")
    ids = {m.decode("ascii") for m in _AWS_ID.findall(value)}
    # The exposure engine pairs nearby AWS fields. Multiple candidate keys in
    # one vault object cannot prove which pair was intentionally stored.
    if len(ids) > 1:
        return unresolved("AMBIGUOUS_AWS_PAIRS")
    if ids and len(_AWS_SECRET.findall(value.decode("utf-8"))) > 1:
        return unresolved("AMBIGUOUS_AWS_PAIRS")
    try:
        parsed = json.loads(value)
    except (ValueError, RecursionError):
        parsed = None
    if parsed is not None and ids:
        def count_secrets(node):
            if isinstance(node, dict):
                return sum(int("secret" in key.lower() and isinstance(item, str)) + count_secrets(item)
                           for key, item in node.items())
            if isinstance(node, list):
                return sum(count_secrets(item) for item in node)
            return 0
        if count_secrets(parsed) > 1:
            return unresolved("AMBIGUOUS_AWS_PAIRS")
        def has_pair(node):
            if isinstance(node, dict):
                strings = [item for item in node.values() if isinstance(item, str)]
                local = any(_AWS_ID.search(item.encode()) for item in strings) and any(_AWS_SECRET.search(item) for item in strings)
                return local or any(has_pair(item) for item in node.values())
            if isinstance(node, list):
                return any(has_pair(item) for item in node)
            return isinstance(node, str) and bool(_AWS_ID.search(node.encode()) and _AWS_SECRET.search(node))
        if _AWS_SECRET.search(value.decode("utf-8")) and not has_pair(parsed):
            return unresolved("UNPAIRED_AWS_MATERIAL")
    detections = engine.scan(DetectorInput(data=value, resource=ResourceRef(source_type="vault"), verify=False))
    result = []
    for detected in detections:
        if detected.credential_type == "AWS_ACCESS_KEY_ID":
            # Handled as IDENTIFIER below, never as secret-value equality.
            continue
        # Identifiers are deliberately restricted to AWS key IDs. A detector's
        # arbitrary identifier can itself contain private customer material.
        identifier = detected.identifier if _AWS_ID.fullmatch(detected.identifier.encode()) else ""
        session_fingerprint = None
        if (identifier.startswith("ASIA") and detected.credential_type == "AWS_ACCESS_KEY"
                and detected.extra_safe_data.get("aws_session_material") == "COMPLETE"):
            session_fingerprint = detected.extra_safe_data.get("aws_session_fingerprint")
        result.append(Observation(**location, evidence="VALUE", credential_type=detected.credential_type,
                                  fingerprint=detected.fingerprint, identifier=identifier,
                                  provider_digest=(detected.extra_safe_data.get("issuer_comparison") or {}).get("github_token_digest"),
                                  session_fingerprint=session_fingerprint))
    paired_ids = {item.identifier for item in result if item.credential_type == "AWS_ACCESS_KEY"}
    result.extend(Observation(**location, evidence="IDENTIFIER", credential_type="AWS_ACCESS_KEY", identifier=key)
                  for key in sorted(ids - paired_ids))
    if not detections.complete:
        result.extend(unresolved("DETECTION_LIMIT"))
    if ids - paired_ids or any(d.credential_type == "AWS_SECRET_ACCESS_KEY" for d in detections):
        result.extend(unresolved("UNPAIRED_AWS_MATERIAL"))
    if not result:
        result.extend(unresolved("UNRECOGNIZED_MATERIAL"))
    if not ids and not any(d.credential_type.startswith("AWS_") for d in detections):
        # Unlabelled vault strings can equal a known exposed/issued secret
        # (for example a bare Azure Storage key). They do not become a new
        # credential type, prove an issuer, or clear unresolved coverage.
        known = {item.fingerprint for item in result if item.fingerprint}
        pending, visited = [parsed if parsed is not None else value.decode("utf-8")], 0
        while pending:
            node = pending.pop()
            visited += 1
            if visited > 1024:
                result.extend(unresolved("VALUE_SCALAR_LIMIT"))
                break
            if isinstance(node, dict):
                pending.extend(node.values())
            elif isinstance(node, list):
                pending.extend(node)
            elif isinstance(node, str) and 20 <= len(node) <= 16384 and not _AWS_SECRET.fullmatch(node):
                try:
                    candidate = fingerprint(node.encode("utf-8"), key=engine.config.fingerprint_key)
                except UnicodeEncodeError:
                    result.extend(unresolved("UNSUPPORTED_TEXT"))
                    continue
                if candidate not in known:
                    result.append(Observation(**location, evidence="VALUE", credential_type="OPAQUE_VALUE", fingerprint=candidate))
                    known.add(candidate)
    return result
