"""Opt-in Graph beta service-principal sign-ins attributed to exact listed keys.

The v1.0 sign-in contract does not expose servicePrincipalCredentialKeyId.
No key ID, unsuccessful sign-in, or absent inventory means no credential use.
Raw sign-ins, IPs, device data and authentication detail are never persisted.
"""

from copy import deepcopy
from datetime import UTC, datetime, timedelta

from cremore.coverage.facts import unpack_facts
from cremore.coverage.metadata_models import EntityIdentity, ProviderEvent
from cremore_azure_provider.metadata.transport import DEFERRED, ApiError

from .normalization import _time, guid, provenance, report
from .transport import cursor_from_link

SOURCE = "credential_sign_ins"
PATH = "/beta/auditLogs/signIns"
FIELDS = "id,createdDateTime,appId,servicePrincipalId,servicePrincipalCredentialKeyId,status,signInEventTypes"


def credential_index(records):
    index = {}
    for record in records:
        identity = record.get("identity") or {}
        if (record.get("record_type") != "entity_observation" or identity.get("kind") not in {"credential", "public_key"}
                or record.get("provenance", {}).get("operation") not in {"azure.entra.applications", "azure.entra.service_principals"}):
            continue
        facts = unpack_facts(record.get("facts") or [])
        app, key = guid(facts.get("application_id")), guid(facts.get("key_id"))
        if app and key:
            index.setdefault((app, key), {})[identity["object_id"]] = identity
    return index


def events(spec, rows, index, start, end):
    records, reasons = [], set()
    for row in rows:
        if not isinstance(row, dict):
            reasons.add("INVALID_SIGN_IN_RECORD")
            continue
        stamp, event_id = _time(row.get("createdDateTime")), guid(row.get("id"))
        status = row.get("status")
        if not stamp or not event_id or not start <= stamp < end:
            reasons.add("INVALID_SIGN_IN_EVIDENCE")
            continue
        if not isinstance(status, dict) or type(status.get("errorCode")) is not int:
            reasons.add("SIGN_IN_RESULT_UNKNOWN")
            continue
        if status["errorCode"] != 0:
            continue
        if row.get("signInEventTypes") != ["servicePrincipal"]:
            reasons.add("SIGN_IN_TYPE_NOT_SUPPORTED")
            continue
        app, key, principal = (guid(row.get(name)) for name in (
            "appId", "servicePrincipalCredentialKeyId", "servicePrincipalId"))
        matches = index.get((app, key), {}) if app and key and principal else {}
        matched = [identity for identity in matches.values() if not identity["object_id"].startswith("service_principal:")
                   or identity["object_id"].split(":")[1] == principal]
        if len(matched) > 1:
            reasons.add("SIGN_IN_CREDENTIAL_AMBIGUOUS")
            continue
        for identity in matched:
            records.append(ProviderEvent(scope=spec.scopes[0], purpose="usage",
                provenance=provenance(SOURCE, spec.origin + PATH), event_id=event_id,
                event_type="token_activity", occurred_at=stamp,
                subject=EntityIdentity.model_validate(identity), match_basis="PROVIDER_EXPLICIT", confidence="EXACT"))
        if not matched:
            reasons.add("SIGN_IN_CREDENTIAL_NOT_ATTRIBUTED")
    return records, reasons


def collect_sign_ins(spec, state, transport, previous, spent, check, *, directory=False):
    # Same page/budget/fencing contract as the surrounding inventory collector.
    from .adapter import _degrade, _page

    if directory:
        from . import directory_audit

        source, path, fields = directory_audit.SOURCE, directory_audit.PATH, directory_audit.FIELDS
        index, parse_rows = directory_audit.credential_index(previous), directory_audit.events
    else:
        source, path, fields = SOURCE, PATH, FIELDS
        index, parse_rows = credential_index(previous), events
    cursor = state["cursor"]
    if not cursor:
        end = datetime.now(UTC)
        cursor = {"window_start": (end - timedelta(days=spec.options.audit_lookback_days or 1)).isoformat(),
                  "window_end": end.isoformat()}
        state["cursor"] = cursor
    start, end = _time(cursor.get("window_start")), _time(cursor.get("window_end"))
    if (not start or not end or start >= end or datetime.fromisoformat(end) - datetime.fromisoformat(start)
            > timedelta(days=30)):
        raise ValueError("AZURE_ENTRA_AUDIT_WINDOW_INVALID")
    while True:
        check()
        committed, cursor = deepcopy(state), deepcopy(state["cursor"])
        reasons = set(cursor.get("reasons", []))
        date = "activityDateTime" if directory else "createdDateTime"
        params = {"$select": fields, "$top": min(spec.options.page_size, 100),
                  "$filter": ("category eq 'ApplicationManagement' and " if directory else "signInEventTypes/any(t: t eq 'servicePrincipal') and ")
                  + date + " ge " + start + " and " + date + " lt " + end}
        if cursor.get("skiptoken"):
            params["$skiptoken"] = cursor["skiptoken"]
        pages, received, saved = (cursor.get(name, 0) for name in ("pages", "received", "saved"))
        records, next_token = [], ""
        try:
            payload = transport.get(path, params)
            rows = payload.get("value")
            if not isinstance(rows, list):
                raise ApiError("invalid_response")
            pages += 1
            received += len(rows)
            next_token = cursor_from_link(payload.get("@odata.nextLink"), spec.origin, path)
            if next_token and next_token in cursor.get("seen", []):
                raise ApiError("pagination_cycle")
            records, invalid = parse_rows(spec, rows, index, start, end)
            reasons.update(invalid)
            saved += len(records)
        except ApiError as exc:
            if exc.code in DEFERRED:
                raise
            reasons.add(exc.code.upper())
            next_token = ""
        state["requests"] = spent + transport.requests
        if next_token and pages >= spec.max_pages:
            reasons.add("PAGE_LIMIT_REACHED")
            next_token = ""
        if next_token:
            state["cursor"] = {"window_start": start, "window_end": end, "skiptoken": next_token,
                               "seen": [*cursor.get("seen", []), next_token], "pages": pages,
                               "received": received, "saved": saved, "reasons": sorted(reasons)}
        else:
            result = report(spec, source, status="PARTIAL" if reasons else "COMPLETE",
                            reasons=reasons, pages=pages, received=received, saved=saved)
            records.append(result.model_copy(update={"purpose": "usage", "native_schema_version": "v1.0" if directory else "beta",
                                                       "window_start": start, "window_end": end}))
            if reasons:
                _degrade(state, reasons)
            state["phase"] += 1
            state["cursor"] = {}
        yield _page(spec, state, records, committed)
        if not next_token:
            return
