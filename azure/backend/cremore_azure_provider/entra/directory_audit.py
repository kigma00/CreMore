"""Exact credential additions in directory audits, without retaining change payloads."""

import json
import re

from cremore.coverage.metadata_models import EntityIdentity, MetadataRelation

from .normalization import _time, guid, provenance

SOURCE = "directory_audits"
PATH = "/v1.0/auditLogs/directoryAudits"
FIELDS = "id,activityDateTime,result,initiatedBy,targetResources,category"
_KEY_ID = re.compile(r"\bKeyIdentifier=([0-9a-fA-F-]{36})(?:,|\])")


def credential_index(records):
    index = {}
    for record in records:
        identity = record.get("identity") or {}
        if record.get("record_type") != "entity_observation" or identity.get("kind") not in {"credential", "public_key"}:
            continue
        parts = identity.get("object_id", "").split(":")
        if len(parts) == 4 and parts[0] in {"application", "service_principal"} and guid(parts[1]) and guid(parts[3]):
            index.setdefault((parts[0], parts[1], parts[3]), {})[identity["object_id"]] = identity
    return index


def _keys(value):
    if not isinstance(value, str) or len(value) > 262144:
        return None
    try:
        rows = json.loads(value)
    except (ValueError, TypeError):
        return None
    if not isinstance(rows, list) or len(rows) > 1000:
        return None
    keys = set()
    for row in rows:
        if not isinstance(row, str):
            return None
        matched = _KEY_ID.findall(row)
        if len(matched) != 1 or not guid(matched[0]):
            return None
        keys.add(guid(matched[0]))
    return keys


def events(spec, rows, index, start, end):
    records, reasons = [], set()
    for row in rows:
        if not isinstance(row, dict) or row.get("result") != "success":
            continue
        stamp, event_id = _time(row.get("activityDateTime")), row.get("id")
        if (not stamp or not start <= stamp < end or not isinstance(event_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", event_id)):
            reasons.add("INVALID_DIRECTORY_AUDIT_EVIDENCE")
            continue
        initiated = row.get("initiatedBy") or {}
        if not isinstance(initiated, dict):
            continue
        user, app = initiated.get("user") or {}, initiated.get("app") or {}
        actor_id = guid(user.get("id")) if isinstance(user, dict) else None
        app_id = guid(app.get("servicePrincipalId")) if isinstance(app, dict) else None
        if bool(actor_id) == bool(app_id):
            reasons.add("DIRECTORY_AUDIT_ACTOR_UNATTRIBUTED")
            continue
        actor = EntityIdentity(provider=spec.provider, origin=spec.origin, tenant=spec.tenant, tenant_confirmed=True,
                               kind="principal", object_id=("user:" + actor_id if actor_id else "service_principal:" + app_id))
        targets = row.get("targetResources")
        if not isinstance(targets, list):
            reasons.add("INVALID_DIRECTORY_AUDIT_TARGETS")
            continue
        for target in targets:
            if not isinstance(target, dict):
                continue
            family = {"Application": "application", "ServicePrincipal": "service_principal"}.get(target.get("type"))
            parent = guid(target.get("id"))
            if not family or not parent:
                continue
            properties = target.get("modifiedProperties")
            if not isinstance(properties, list):
                continue
            for prop in properties:
                if not isinstance(prop, dict) or prop.get("displayName") != "KeyDescription":
                    continue
                old, new = _keys(prop.get("oldValue")), _keys(prop.get("newValue"))
                if old is None or new is None:
                    reasons.add("DIRECTORY_AUDIT_KEY_CHANGE_UNATTRIBUTED")
                    continue
                for key in sorted(new - old):
                    identities = index.get((family, parent, key), {})
                    if len(identities) != 1:
                        reasons.add("DIRECTORY_AUDIT_CREDENTIAL_NOT_LISTED")
                        continue
                    identity = next(iter(identities.values()))
                    records.append(MetadataRelation(scope=spec.scopes[0], purpose="usage",
                        subject=EntityIdentity.model_validate(identity), target=actor, relation="created_by",
                        match_basis="AUDIT_REFERENCE", confidence="EXACT", window_start=stamp, window_end=stamp,
                        provenance=provenance(SOURCE, spec.origin + PATH + "/" + event_id)))
    return records, reasons
