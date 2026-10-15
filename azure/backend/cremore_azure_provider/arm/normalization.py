"""ARM responses projected into explicit metadata and keyed evidence."""

import base64
import re
from datetime import UTC, datetime

# Integration: moved from cremore.coverage.providers.facts, whose package import ran the adapter
# registry (every provider) and the coverage store; this module loads neither.
from cremore.coverage.facts import FactWriter
from cremore.coverage.hasher import hash_value
from cremore.coverage.metadata_models import (
    EntityIdentity,
    EntityObservation,
    MetadataProvenance,
    MetadataValueContract,
    MetadataValueMatch,
    OperationReport,
)
from cremore_azure_provider.entra.normalization import _time, guid
from cremore_azure_provider.sas import signed_fingerprints

from . import CONTRACT_VERSION
from .transport import STORAGE_ID, VAULT_ID


def provenance(operation, resource=""):
    return MetadataProvenance(operation="azure.arm." + operation,
                              observed_at=datetime.now(UTC).isoformat(), resource_id=resource,
                              contract_version=CONTRACT_VERSION)


def observation(spec, scope, operation, identifier, values, *, kind="resource", resource=None, value_match=None):
    writer = FactWriter()
    return EntityObservation(scope=scope, purpose="issuer_inventory",
        provenance=provenance(operation, resource or identifier),
        identity=EntityIdentity(provider=spec.provider, origin=spec.origin, tenant=spec.tenant,
                                tenant_confirmed=True, kind=kind, object_id=identifier),
        facts=writer.facts({key: value for key, value in values.items() if value is not None}),
        omissions=writer.omissions, value_match=value_match)


def subscription_record(spec, scope, row):
    if not isinstance(row, dict):
        return None
    identifier = guid(row.get("subscriptionId"))
    if not identifier or guid(row.get("tenantId")) != spec.tenant:
        return None
    if str(row.get("id", "")).casefold() != "/subscriptions/" + identifier:
        return None
    if scope.kind == "subscription" and scope.id != identifier:
        return None
    return observation(spec, scope, "subscriptions", row["id"], {
        "id": identifier, "name": row.get("displayName"), "state": row.get("state"),
        "resource_type": "subscription", "account_id": identifier})


def resource_record(spec, scope, phase, row):
    if not isinstance(row, dict):
        return None
    identifier = row.get("id")
    pattern = VAULT_ID if phase == "vaults" else STORAGE_ID
    match = pattern.fullmatch(identifier) if isinstance(identifier, str) else None
    if not match or match[1].casefold() != scope.id:
        return None
    expected_type = "microsoft.keyvault/vaults" if phase == "vaults" else "microsoft.storage/storageaccounts"
    if str(row.get("type", "")).casefold() != expected_type:
        return None
    name = identifier.rsplit("/", 1)[1]
    if not isinstance(row.get("name"), str) or row["name"].casefold() != name.casefold():
        return None
    properties = row.get("properties") if isinstance(row.get("properties"), dict) else {}
    # A storage account states its creation in properties; a vault only in ARM's systemData.
    system = row.get("systemData") if isinstance(row.get("systemData"), dict) else {}
    created = system.get("createdAt") if phase == "vaults" else properties.get("creationTime")
    values = {"resource_id": identifier, "resource_type": row["type"], "name": row["name"],
              "location": row.get("location"), "kind": row.get("kind"),
              "created_at": _time(created), "state": properties.get("provisioningState")}
    if phase == "vaults":
        uri = properties.get("vaultUri")
        if guid(properties.get("tenantId")) != spec.tenant or not isinstance(uri, str):
            return None
        expected = "https://" + name.lower() + ".vault.azure.net"
        if uri.rstrip("/").lower() != expected:
            return None
        values["vault_uri"] = expected
    elif isinstance(properties.get("allowSharedKeyAccess"), bool):
        values["permissions"] = {"name": "shared_key_access", "allowed": properties["allowSharedKeyAccess"]}
    return observation(spec, scope, phase, identifier, values)


def storage_key_records(spec, scope, account, payload, context):
    rows = payload.get("keys")
    if not isinstance(rows, list) or not rows:
        return [], {"INVALID_KEY_LIST"}
    records, reasons, seen = [], set(), set()
    if context.get("sas_candidate_status", {}).get("complete") is False:
        reasons.add("SAS_CANDIDATE_LIMIT_REACHED")
    for row in rows:
        name = row.get("keyName") if isinstance(row, dict) else None
        if name not in {"key1", "key2"} or name in seen:
            reasons.add("UNSUPPORTED_OR_DUPLICATE_KEY_NAME")
            continue
        seen.add(name)
        reference = account + "/keys/" + name
        value = row.get("value")
        reason, hashed = None, None
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9+/]{86}==", value):
            reason = "INVALID_STORAGE_KEY_VALUE"
        else:
            try:
                if len(base64.b64decode(value, validate=True)) != 64:
                    raise ValueError
            except ValueError:
                reason = "INVALID_STORAGE_KEY_VALUE"
            if reason is None:
                candidates = hash_value(context["engine"], ("AccountKey=" + value).encode(),
                                        {"reference": reference}, max_bytes=1024)
                matches = [item for item in candidates if item.evidence == "VALUE"
                           and item.credential_type == "AZURE_STORAGE_KEY"]
                if len(matches) == 1 and not any(item.evidence == "UNRESOLVED" for item in candidates):
                    hashed = matches[0]
                else:
                    reason = "STORAGE_KEY_NOT_RECOGNIZED"
        # Which discovered SAS this key signed, recomputed offline from their signed fields.
        signed = signed_fingerprints(value, account.rsplit("/", 1)[1].lower(), context.get("sas_candidates") or [],
                                     context["engine"].config.fingerprint_key) if hashed else []
        match = MetadataValueMatch(reference=reference, version_state="CURRENT", key_id=context["key_id"],
            engine_digest=context["engine_digest"], policy_digest=context["policy_digest"],
            read_at=datetime.now(UTC).isoformat(), evidence="VALUE" if hashed else "UNRESOLVED",
            credential_type="AZURE_STORAGE_KEY", fingerprint=hashed.fingerprint if hashed else None,
            reason=reason, signed_fingerprints=signed)
        if reason:
            reasons.add(reason)
        records.append(observation(spec, scope, "storage_keys", reference, {
            "name": name, "credential_type": "AZURE_STORAGE_KEY", "resource_id": account,
            "created_at": _time(row.get("creationTime")), "permissions": row.get("permissions"),
            "material_kind": "STATIC_ACCOUNT_KEY", "key_id": name,
        }, kind="credential", resource=spec.origin + account + "/listKeys", value_match=match))
    if seen != {"key1", "key2"}:
        reasons.add("EXPECTED_KEY_SLOTS_NOT_RETURNED")
    return records, reasons


def report(spec, scope, phase, *, reasons=(), status=None, pages=0, received=0, saved=0, context=None):
    result = OperationReport(scope=scope, purpose="issuer_inventory", provenance=provenance(phase),
        status=status or ("PARTIAL" if reasons else "COMPLETE"), reasons=sorted(set(reasons)),
        pages=pages, received_records=received, saved_records=saved, proves_completeness=False,
        shape="array", report_type="azure_resource_manager_source_report", collection_mode=spec.options.mode)
    if context is not None:
        result.value_access = "PARTIAL" if reasons else "COMPLETE"
        result.value_contract = MetadataValueContract(**{key: context[key] for key in (
            "key_id", "engine_digest", "policy_digest")})
    return result
