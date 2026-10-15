"""Typed GitHub observations, events and reports for the shared projections.

Each native record keeps its own object kind so the dashboard can count issued
credentials apart from public keys, installations, policies and requests. A
provider's own state is recorded as reported; nothing here verifies a token.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

# Integration: moved from cremore.coverage.providers.facts, whose package import ran the adapter
# registry (every provider) and the coverage store; this module loads neither.
from cremore.coverage.facts import FactWriter, unpack_facts
from cremore.coverage.metadata_models import (
    EntityIdentity,
    EntityObservation,
    MetadataOmission,
    MetadataPermission,
    MetadataProvenance,
    MetadataRelation,
    OperationReport,
    ProviderEvent,
    RecordQuality,
)

from . import CONTRACT_VERSION, NATIVE_SCHEMA, SOURCE_COMMIT
from .projection import AUDIT_FIELDS, CREDENTIAL_ACTION, INVENTORY_FIELDS, allowlisted

# Native collector result key -> (object kind, purpose, id prefix).
RESULT_KINDS = {
    "classic_pats": ("credential", "sso"),
    "oauth_app_tokens": ("credential", "sso"),
    "github_app_user_tokens": ("credential", "sso"),
    "user_ssh_keys": ("public_key", "sso"),
    "fine_grained_pats": ("credential", "fgpat"),
    "deploy_keys": ("public_key", "deployKey"),
    "installations": ("installation", "installation"),
}
# A context kind absent from this map produces no entity: the page's report
# already carries the same record, and two entities for one policy would count
# twice. "actions_policy" is exactly that case.
CONTEXT_KINDS = {
    "pat_request": ("request", "patRequest"),
    "pat_request_repositories": ("request", "patRequest"),
    "collector_accessible_repository": ("resource", "repository"),
    "enterprise_org_repository": ("resource", "repository"),
    "installation_repository": ("context", "installationRepository"),
    "enterprise_org_installation": ("installation", "installation"),
    "unclassified_sso_authorization": ("unknown", "sso"),
    "enterprise_organizations": ("context", "organizations"),
    "actions_environment": ("resource", "environment"),
}
_STATES = {
    "active": ("ACTIVE", "PROVIDER_REPORTED"),
    "expired": ("EXPIRED", "PROVIDER_REPORTED"),
    "revoked": ("REVOKED", "PROVIDER_REPORTED"),
    "deleted": ("DELETED", "PROVIDER_REPORTED"),
}


def now() -> str:
    return datetime.now(UTC).isoformat()


def identity(spec, kind, value) -> EntityIdentity:
    return EntityIdentity(provider="github", origin=spec.origin, tenant=spec.tenant,
                          tenant_confirmed=spec.tenant_confirmed, kind=kind, object_id=value)


def provenance(operation, resource_id="", *, generated_at=None) -> MetadataProvenance:
    return MetadataProvenance(operation=operation[:128], observed_at=now(),
                              resource_id=resource_id[:2048],
                              provider_generated_at=generated_at, source_commit=SOURCE_COMMIT,
                              contract_version=CONTRACT_VERSION)


def _facts(values):
    writer = FactWriter()
    return writer.facts({key: value for key, value in values.items() if value is not None}), \
        writer.omissions


def _permissions(row):
    """A grant is typed; a repository permission flag is not a token scope."""
    result = []
    permissions = row.get("permissions")
    if isinstance(permissions, dict):
        for name, level in sorted(permissions.items()):
            if isinstance(name, str) and isinstance(level, str):
                result.append(MetadataPermission(kind="permission", name=name[:256],
                                                 effect="ALLOW", actions=[level[:256]]))
    elif isinstance(permissions, dict | list):
        result.append(MetadataPermission(kind="permission", name="unreadable", effect="UNKNOWN"))
    scopes = row.get("scopes")
    if isinstance(scopes, list):
        for scope in scopes[:250 - len(result)]:
            if isinstance(scope, str):
                result.append(MetadataPermission(kind="scope", name=scope[:256], effect="ALLOW"))
    selection = row.get("repository_selection")
    if isinstance(selection, str):
        result.append(MetadataPermission(kind="repository_grant", name=selection[:256],
                                         resource_kind="repository", effect="UNKNOWN"))
    return result[:250]


def _state(row, kind):
    if kind == "request":
        return "PENDING", "PROVIDER_REPORTED", "requested"
    if kind == "installation":
        return (("DISABLED", "PROVIDER_REPORTED", "suspended") if row.get("suspended_at")
                else ("ACTIVE", "PROVIDER_REPORTED", "listed"))
    if isinstance(row.get("credential_state"), str):
        return _STATES.get(row["credential_state"], ("UNKNOWN", "UNKNOWN")) + (
            row["credential_state"],)
    if row.get("token_expired") is True:
        return "EXPIRED", "PROVIDER_REPORTED", "token_expired"
    if row.get("enabled") is False:
        return "DISABLED", "PROVIDER_REPORTED", "disabled"
    if row.get("token_expired") is False or row.get("credential_authorized_at"):
        return "ACTIVE", "PROVIDER_REPORTED", "listed"
    return "UNKNOWN", "UNKNOWN", "UNKNOWN"


def object_id_for(prefix, org, row):
    if prefix == "sso":
        return f"sso:{org}:{row.get('credential_id') or row.get('authorized_credential_id')}"
    if prefix == "fgpat":
        return f"fgpat:{org}:{row['id']}"
    if prefix == "patRequest":
        return f"patRequest:{org}:{row['id']}"
    if prefix == "deployKey":
        return f"deployKey:{row['repository']['full_name']}:{row['id']}"
    if prefix == "installation":
        return "installation:" + str(row.get("installation_id") or row["id"])
    if prefix == "repository":
        return "repository:" + str(row.get("full_name") or f"{org}/{row.get('name')}")
    if prefix == "installationRepository":
        return (f"installationRepository:{row['installation_id']}:"
                f"{row['repository']['full_name']}")
    if prefix == "organizations":
        return "organizations:" + org
    return f"{prefix}:{org}"


def observation(spec, scope, *, kind, object_id, operation, resource_id, row, purpose="issuer_inventory",
                generated_at=None) -> EntityObservation:
    normalized, basis, provider_state = _state(row, kind)
    # A GitHub App permission name is open-ended, so the grant is kept as a
    # typed permission rather than as an arbitrary fact key.
    facts, omissions = _facts({key: value for key, value in row.items()
                               if key != "permissions"})
    return EntityObservation(
        scope=scope, purpose=purpose, identity=identity(spec, kind, object_id),
        provenance=provenance(operation, resource_id, generated_at=generated_at),
        facts=facts, omissions=omissions, permissions=_permissions(row),
        provider_state=provider_state, normalized_state=normalized, state_basis=basis,
    )


def report(spec, scope, operation, *, status, reasons=(), pages=0, received=0, saved=0,
           resource_id="", purpose="issuer_inventory", facts=None, shape="array",
           report_type="github_source_report", mode="", quality=None) -> OperationReport:
    values, omissions = _facts(facts or {})
    return OperationReport(
        scope=scope, purpose=purpose, provenance=provenance(operation, resource_id),
        status=status, reasons=sorted(set(reasons)), pages=pages, received_records=received,
        saved_records=saved, proves_completeness=False, shape=shape,
        record_quality=quality or RecordQuality(records=received, identified=saved),
        native_schema_version=NATIVE_SCHEMA, report_type=report_type, collection_mode=mode,
        facts=values, omissions=omissions,
    )


def relation(spec, scope, subject, target, *, relation_kind, match_basis, confidence,
             operation, resource_id="", facts=None, purpose="issuer_inventory") -> MetadataRelation:
    values, omissions = _facts(facts or {})
    return MetadataRelation(
        scope=scope, purpose=purpose, subject=subject, target=target, relation=relation_kind,
        match_basis=match_basis, confidence=confidence,
        provenance=provenance(operation, resource_id), facts=values, omissions=omissions,
    )


def audit_event(spec, scope, row, *, operation, org="", value_context=None) -> ProviderEvent | None:
    """One audit entry, kept only when its action concerns a credential.

    With the provider-hash opt-in, an SSO authorization entry's managed token
    hash is keyed for this installation in memory and kept only as the event's
    private value match, so the event can be joined to the inventory credential
    it names; the vendor hash itself is dropped.
    """
    action = row.get("action")
    if not isinstance(action, str) or not CREDENTIAL_ACTION.match(action):
        return None
    document, occurred = _document(row), _occurred(row)
    if document is None or occurred is None:
        return None
    occurred = occurred.isoformat()
    values = allowlisted(row, AUDIT_FIELDS)
    facts, omissions = _facts(values)
    actor = values.get("actor")
    subject = (identity(spec, "principal", "principal:" + actor)
               if isinstance(actor, str) and actor else None)
    target = _audit_target(spec, values, org)
    event = ProviderEvent(
        scope=scope, purpose="usage", provenance=provenance(operation, document),
        event_id=document[:512], event_type=action[:128], occurred_at=occurred,
        subject=subject, target=target,
        match_basis="PROVIDER_ID" if target is not None else "UNKNOWN",
        confidence="EXACT" if target is not None else "UNKNOWN",
        facts=facts, omissions=omissions,
    )
    if (value_context is not None and action.startswith("org_credential_authorization.")
            and row.get("managed_hashed_token") is not None):
        from .digest_evidence import keyed, match

        try:
            event.value_match = match(keyed(row["managed_hashed_token"], value_context), event.event_id,
                                      value_context, observed_at=event.provenance.observed_at)
        except ValueError:
            event.omissions.append(MetadataOmission(path="managed_hashed_token", reason="INVALID_PROVIDER_DIGEST"))
    return event


def _document(row):
    document = row.get("_document_id") or row.get("request_id")
    return document if isinstance(document, str) and document else None


def _occurred(row):
    occurred = row.get("created_at") or row.get("@timestamp")
    if isinstance(occurred, (int, float)) and not isinstance(occurred, bool):
        occurred = datetime.fromtimestamp(occurred / 1000, UTC).isoformat()
    if not isinstance(occurred, str):
        return None
    try:
        return datetime.fromisoformat(occurred).astimezone(UTC)
    except ValueError:
        return None


# Summary fact -> the audit field whose distinct values it keeps.
_ACTIVITY_VALUES = {"action": "action", "repo": "repo", "actor": "actor",
                    "programmatic_access_type": "programmatic_access_type"}


def token_activity(spec, scope, rows, context, *, operation) -> list[ProviderEvent]:
    """Entries GitHub recorded as made with a token: one summary per token and page.

    The vendor ``hashed_token`` is keyed for this installation in memory and
    dropped; only a discovered token keyed the same way can match the summary.
    Entry IDs are kept so overlapping collection windows count an entry once.
    """
    from .digest_evidence import keyed, match

    groups = {}
    for row in rows:
        document, occurred = _document(row), _occurred(row)
        if row.get("hashed_token") is None or document is None or occurred is None:
            continue
        try:
            fingerprint = keyed(row["hashed_token"], context)
        except ValueError as exc:
            # Activity is positive evidence only; an unreadable hash links nothing.
            if str(exc) != "GITHUB_INVALID_PROVIDER_DIGEST":
                raise
            continue
        group = groups.setdefault(fingerprint, {"documents": [], "first": occurred, "last": occurred,
                                                **{name: set() for name in _ACTIVITY_VALUES}})
        group["documents"].append(document)
        group["first"], group["last"] = min(group["first"], occurred), max(group["last"], occurred)
        for name, field in _ACTIVITY_VALUES.items():
            if isinstance(row.get(field), str) and row[field]:
                group[name].add(row[field])
    events = []
    for fingerprint, group in groups.items():
        event_id = ("token_activity:" + group["documents"][0])[:512]
        facts, omissions = _facts({"events": len(group["documents"]), "first_seen_at": group["first"].isoformat(),
                                   "last_seen_at": group["last"].isoformat(), "_document_id": group["documents"],
                                   **{name: sorted(group[name])[:32] for name in _ACTIVITY_VALUES}})
        event = ProviderEvent(scope=scope, purpose="usage", provenance=provenance(operation, event_id),
                              event_id=event_id, event_type="token_activity",
                              occurred_at=group["last"].isoformat(), facts=facts, omissions=omissions)
        event.value_match = match(fingerprint, event_id, context, observed_at=event.provenance.observed_at)
        events.append(event)
    return events


def _audit_target(spec, values, org):
    # user_programmatic_access_id is a fine-grained PAT's token id, but fgpat: entities are keyed by
    # grant id; that join is made by exact id at export time (audit_links), never as a stored target.
    for key, prefix in (("token_id", "token"), ("managed_token_id", "token"),
                        ("managed_oauth_access_id", "oauth")):
        value = values.get(key)
        if isinstance(value, (int, str)) and not isinstance(value, bool) and str(value):
            scope_name = values.get("org") if isinstance(values.get("org"), str) else org
            return identity(spec, "credential", f"{prefix}:{scope_name or ''}:{value}")
    return None


# GitHub documents credential_id as unique only together with credential_type,
# and only for these types; an SSH key is identified by its fingerprint.
INVENTORY_ID_TYPES = frozenset({"classic_pat", "fine_grained_pat", "oauth_app_user_token",
                                "github_app_user_token"})


def fingerprint_key(value):
    """One form of an SSH public-key fingerprint for identity and matching."""
    if not isinstance(value, str):
        return None
    if re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}=?", value):
        return value.rstrip("=")
    found = re.fullmatch(r"(?:MD5:)?((?:[0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2})", value)
    return found.group(1).lower() if found else None


def inventory_object_id(values):
    """A credential keeps its identity across runs.

    The inventory_id "can differ for the same credential between responses"
    (token inventory API, 2026-03-10), so it only names rows GitHub gives no
    per-row identifier for: App installations, federated JTIs, principals.
    """
    kind, credential = values.get("credential_type"), values.get("credential_id")
    if (kind in INVENTORY_ID_TYPES and not isinstance(credential, bool) and isinstance(credential, int | str)
            and re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", str(credential))):
        return f"inventory:{kind}:id:{credential}"
    fingerprint = fingerprint_key(values.get("fingerprint"))
    if kind == "ssh_key" and fingerprint:
        return "inventory:ssh_key:fingerprint:" + fingerprint
    if str(values["inventory_id"]).startswith("export:"):
        return f"inventory:export:{kind}:" + values["inventory_id"].removeprefix("export:")
    return "inventory:" + str(values["inventory_id"])


def inventory_observation(spec, scope, row, *, operation, generated_at=None, value_context=None) -> EntityObservation:
    """One Enterprise credential inventory row, in the API's own vocabulary."""
    values = allowlisted(row, INVENTORY_FIELDS)
    kind = ("principal" if values.get("item_type") == "token_issuer_principal"
            else "public_key" if values.get("credential_type") in ("ssh_key", "SSH key",
                                                                   "deploy_key", "Deploy key")
            else "credential")
    object_id = inventory_object_id(values)
    normalized, basis = _STATES.get(values.get("credential_state"), ("UNKNOWN", "UNKNOWN"))
    facts, omissions = _facts(values)
    result = EntityObservation(
        scope=scope, purpose="issuer_inventory", identity=identity(spec, kind, object_id),
        provenance=provenance(operation, str(values.get("inventory_id", ""))[:2048],
                              generated_at=generated_at),
        facts=facts, omissions=omissions, permissions=_permissions(values),
        provider_state=str(values.get("credential_state", "UNKNOWN"))[:64],
        normalized_state=normalized, state_basis=basis,
    )
    if spec.options.include_provider_hashes:
        from .digest_evidence import value_match

        try:
            result.value_match = value_match(row, object_id, value_context,
                                             observed_at=result.provenance.observed_at)
        except ValueError as exc:
            if str(exc) != "GITHUB_INVALID_PROVIDER_DIGEST":
                raise
            result.omissions.append(MetadataOmission(path="hashed_token", reason="INVALID_PROVIDER_DIGEST"))
    return result


def record_values(item) -> dict:
    facts = item.facts if hasattr(item, "facts") else item["facts"]
    return unpack_facts([f.model_dump() if hasattr(f, "model_dump") else f for f in facts])
