"""Bounded, immutable owner statements. Statements never authorize provider writes."""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import uuid

from cremore.detection.safe_text import safe_fact_text
from cremore.domain.text import unsafe_text

ACTIONS = frozenset({"REMOVE_PLAINTEXT", "REVOKE", "ROTATE", "STORE_REPLACEMENT", "CUTOVER", "DISABLE"})
PATHS = frozenset({"RETIRED", "REPLACED", "EXCEPTION"})
RESULTS = frozenset({"DONE", "INCOMPLETE", "EXCEPTION"})
PREFIX = "response:report:"
MAX_VERSIONS = 100


def credential_types(orchestrator, text):
    """Inspect free text in memory with the installation's rules; never verify externally."""
    from cremore.detection import DetectorInput, ResourceRef

    if not text:
        return []
    orchestrator.refresh_rules()
    found = orchestrator.engine.scan(DetectorInput(data=text.encode("utf-8"),
        resource=ResourceRef(source_type="inline"), verify=False))
    return sorted({d.credential_type for d in found})


def same_address(email, assigned_to) -> bool:
    """A verified sign-in address names the request's address: both ASCII, compared lowercase in constant time, as
    contact addresses are. Unicode case folding would let a Kelvin sign stand in for a K. The one rule of the link
    page, the console report and the directory check."""
    return (isinstance(email, str) and isinstance(assigned_to, str) and bool(email) and email.isascii()
            and assigned_to.isascii() and hmac.compare_digest(email.lower().encode(), assigned_to.lower().encode()))


def directory_current(repo, settings, value, *, now):
    """The request's IdP person still resolves (complete, current, active, same IdP) at the address it was asked at."""
    from cremore.governance import response_routing
    from cremore.governance.response import ResponseError

    ref = (value.get("recipient") or {}).get("person_ref")
    if not ref:
        return False
    try:
        person = response_routing.resolve(repo, settings, ref, now=now)
    except ResponseError:  # no longer current/complete/same IdP: fail closed
        return False
    return same_address(person.get("email"), value.get("assigned_to"))


def _reached(value):
    """The request reached its recipient: the ticket opened, the link's message went out, or (record) it was asked."""
    if (value.get("channel") or "ticket") == "ticket":
        return bool((value.get("ticket") or {}).get("approval"))
    return value.get("state") not in (None, "SENDING", "NOT_SENT")


def authorized(repo, settings, value, actor, *, verified_email=None):
    """The verified sign-in address must still name the request's current recipient (``same_address``)."""
    if not _reached(value) or not actor:
        return False
    if getattr(settings, "auth_mode", "local") == "local":
        return True  # the single operator records a statement (a ticket request's own approval stays mandatory)
    return (same_address(verified_email, value.get("assigned_to"))
            and directory_current(repo, settings, value, now=dt.datetime.now(dt.UTC)))


def normalize(data, *, now, requested_at, contains_credentials):
    from cremore.governance.response import ResponseError, _when

    keys = {"result", "path", "actions", "explanation", "performed_at", "replacement_plan_id", "replacement_entity_id"}
    if not isinstance(data, dict) or set(data) - keys:
        raise ResponseError("RESPONSE_REPORT_INVALID", 422)
    result, path, actions = data.get("result"), data.get("path"), data.get("actions")
    if (not isinstance(result, str) or not isinstance(path, str) or result not in RESULTS or path not in PATHS
            or not isinstance(actions, list) or (result == "DONE" and not actions)
            or len(actions) > len(ACTIONS) or any(not isinstance(a, str) or a not in ACTIONS for a in actions)
            or len(set(actions)) != len(actions)):
        raise ResponseError("RESPONSE_REPORT_INVALID", 422)
    text = data.get("explanation")
    if (not isinstance(text, str) or not 20 <= len(text.strip()) <= 2000
            or unsafe_text(text, newlines=True) or "<" in text or ">" in text
            or safe_fact_text(text.replace("\n", " ")) is None or contains_credentials(text)):
        raise ResponseError("RESPONSE_REPORT_TEXT_INVALID", 422)
    at = _when(data.get("performed_at"))
    if at is None or at > now or at < requested_at:
        raise ResponseError("RESPONSE_REPORT_TIME_INVALID", 422)
    out = {"result": result, "path": path, "actions": sorted(actions), "explanation": text.strip(),
           "performed_at": at.isoformat()}
    for key in ("replacement_plan_id", "replacement_entity_id"):
        value = data.get(key)
        if value:
            try:
                out[key] = str(uuid.UUID(str(value)))
            except (ValueError, TypeError):
                raise ResponseError("RESPONSE_REPORT_REFERENCE_INVALID", 422) from None
    if result == "DONE":
        needed = {"REMOVE_PLAINTEXT", "REVOKE"} if path == "RETIRED" else {
            "REMOVE_PLAINTEXT", "ROTATE", "STORE_REPLACEMENT", "CUTOVER"}
        if path == "EXCEPTION" or not needed.issubset(actions):
            raise ResponseError("RESPONSE_REPORT_ACTIONS_REQUIRED", 422)
        if path == "REPLACED" and not any(out.get(k) for k in ("replacement_plan_id", "replacement_entity_id")):
            raise ResponseError("RESPONSE_REPLACEMENT_REQUIRED", 422)
    if path != "REPLACED" and any(out.get(k) for k in ("replacement_plan_id", "replacement_entity_id")):
        raise ResponseError("RESPONSE_REPORT_REFERENCE_INVALID", 422)
    return out


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def ticket_authorized(repo, settings, value, *, now):
    """External actor is checked against the exact ticket; still require the current IdP recipient."""
    if settings is None:
        return False
    if settings.auth_mode == "local":
        return True
    return directory_current(repo, settings, value, now=now)


def store(repo, finding_id, value, normalized, actor, *, report_id, now, basis):
    """Called under the response lock; caller appends the same-transaction audit event."""
    from cremore.governance.response import ResponseError, _row, _stamp

    key = PREFIX + finding_id + ":" + value["request_id"] + ":" + report_id
    previous = _row(repo, key)
    if previous:
        if previous["content_hash"] != digest(normalized) or previous["by"] != actor:
            raise ResponseError("RESPONSE_REPORT_ID_REUSED")
        return previous
    if value.get("report_count", 0) >= MAX_VERSIONS:
        raise ResponseError("RESPONSE_REPORT_LIMIT", 422)
    report = {**normalized, "id": report_id, "content_hash": digest(normalized), "by": actor,
              "received_at": _stamp(now), "version": value.get("report_count", 0) + 1, "basis": basis}
    report["hash"] = digest(report)
    repo.put_setting(key, report, actor)
    return report
