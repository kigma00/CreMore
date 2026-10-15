"""Explicit Graph field projection; password values and hints are excluded."""

import base64
import re
from datetime import UTC, datetime

# Integration: moved from cremore.coverage.providers.facts, whose package import ran the adapter
# registry (every provider) and the coverage store; this module loads neither.
from cremore.coverage.facts import FactWriter
from cremore.coverage.metadata_models import (
    EntityIdentity,
    EntityObservation,
    MetadataOmission,
    MetadataProvenance,
    OperationReport,
)

from . import CONTRACT_VERSION
from .transport import GUID


def guid(value):
    return value.lower() if isinstance(value, str) and re.fullmatch(GUID, value) else None


def provenance(operation, resource=""):
    return MetadataProvenance(operation="azure.entra." + operation,
                              observed_at=datetime.now(UTC).isoformat(),
                              resource_id=resource, contract_version=CONTRACT_VERSION)


def _observation(spec, operation, object_id, kind, resource, values, *, omissions=(), state="UNKNOWN"):
    writer = FactWriter()
    return EntityObservation(
        scope=spec.scopes[0], purpose="issuer_inventory",
        provenance=provenance(operation, resource),
        identity=EntityIdentity(provider=spec.provider, origin=spec.origin, tenant=spec.tenant,
                                tenant_confirmed=True, kind=kind, object_id=object_id),
        facts=writer.facts({key: value for key, value in values.items() if value is not None}),
        omissions=[*writer.omissions, *omissions], normalized_state=state,
        provider_state=state, state_basis="PROVIDER_REPORTED" if state != "UNKNOWN" else "UNKNOWN")


def _time(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.astimezone(UTC).isoformat() if parsed.tzinfo is not None else None
    except ValueError:
        return None


def entity_records(spec, phase, row):
    """Return observations and missing/invalid-data reasons, never raw rows."""
    if not isinstance(row, dict) or not guid(row.get("id")) or not guid(row.get("appId")):
        return [], {"INVALID_IDENTIFIERS"}
    parent = guid(row["id"])
    application = guid(row["appId"])
    family = "application" if phase == "applications" else "service_principal"
    endpoint = "applications" if phase == "applications" else "servicePrincipals"
    resource = spec.origin + "/v1.0/" + endpoint + "/" + parent
    principal = _observation(spec, phase, family + ":" + parent, "principal", resource, {
        "id": parent, "application_id": application, "display_name": row.get("displayName"),
        "principal_kind": family, "type": row.get("servicePrincipalType"),
        "enabled": row.get("accountEnabled"), "created_at": _time(row.get("createdDateTime")),
    }, state="DISABLED" if row.get("accountEnabled") is False else "UNKNOWN")
    records, reasons = [principal], set()
    for field in ("passwordCredentials", "keyCredentials"):
        entries = row.get(field)
        if not isinstance(entries, list):
            reasons.add("CREDENTIAL_COLLECTION_NOT_RETURNED")
            continue
        seen = set()
        for entry in entries:
            key_id = guid(entry.get("keyId")) if isinstance(entry, dict) else None
            if not key_id or key_id in seen:
                reasons.add("INVALID_CREDENTIAL_IDENTIFIERS")
                continue
            seen.add(key_id)
            credential_type, kind = "AZURE_CLIENT_SECRET", "credential"
            if field == "keyCredentials":
                credential_type, kind = (("AZURE_CERTIFICATE", "public_key")
                                         if entry.get("type") == "AsymmetricX509Cert"
                                         else ("AZURE_APPLICATION_KEY", "credential"))
            expires, starts = _time(entry.get("endDateTime")), _time(entry.get("startDateTime"))
            if any(entry.get(field) is not None and parsed is None for field, parsed in (
                ("endDateTime", expires), ("startDateTime", starts))):
                reasons.add("INVALID_CREDENTIAL_TIMESTAMPS")
            state = "DISABLED" if row.get("accountEnabled") is False else "UNKNOWN"
            if expires and datetime.fromisoformat(expires) <= datetime.now(UTC):
                state = "EXPIRED"
            omissions = [MetadataOmission(path="/" + field + "/" + name, reason="SECRET_FIELD_OMITTED")
                         for name in ("secretText", "hint") if name in entry]
            # startDateTime is when the credential becomes valid (a certificate's NotBefore, or a start the
            # caller chose), not when it was added, so it is not filed as a creation time.
            values = {"credential_id": key_id, "key_id": key_id, "credential_type": credential_type,
                      "application_id": application, "parent_id": parent, "principal_kind": family,
                      "display_name": entry.get("displayName"), "not_before": starts,
                      "expires_at": expires, "key_type": entry.get("type"), "use": entry.get("usage")}
            if field == "keyCredentials" and isinstance(entry.get("customKeyIdentifier"), str):
                try:
                    if len(entry["customKeyIdentifier"]) > 256:
                        raise ValueError
                    identifier = base64.b64decode(entry["customKeyIdentifier"], validate=True)
                    if not 1 <= len(identifier) <= 128:
                        raise ValueError
                    values.update(fingerprint=identifier.hex(), algorithm="PROVIDER_CUSTOM_KEY_IDENTIFIER")
                except ValueError:
                    reasons.add("INVALID_PUBLIC_KEY_IDENTIFIER")
            records.append(_observation(spec, phase, f"{family}:{parent}:{field}:{key_id}", kind,
                                         resource, values, omissions=omissions, state=state))
    return records, reasons


def federated_record(spec, application_id, row):
    if not isinstance(row, dict) or not guid(row.get("id")):
        return None
    if (any(not isinstance(row.get(name), str) or not 1 <= len(row[name]) <= limit
            for name, limit in (("name", 120), ("issuer", 600), ("subject", 600)))
            or not isinstance(row.get("audiences"), list) or len(row["audiences"]) != 1
            or not isinstance(row["audiences"][0], str) or not 1 <= len(row["audiences"][0]) <= 600):
        return None
    identifier = guid(row["id"])
    resource = spec.origin + "/v1.0/applications/" + application_id + "/federatedIdentityCredentials"
    return _observation(spec, "federated_identity_credentials",
                        f"application:{application_id}:federated_identity:{identifier}", "trust", resource, {
        "id": identifier, "parent_id": application_id, "name": row.get("name"),
        "issuer": row.get("issuer"), "subject": row.get("subject"), "audience": row.get("audiences"),
        "material_kind": "WORKLOAD_IDENTITY_TRUST", "state_basis": "PROVIDER_REPORTED",
    })


def report(spec, phase, *, status="COMPLETE", reasons=(), pages=0, received=0, saved=0, resource="", facts=None):
    writer = FactWriter()
    return OperationReport(scope=spec.scopes[0], purpose="issuer_inventory",
                           provenance=provenance(phase, resource), status=status,
                           reasons=sorted(set(reasons)), pages=pages,
                           received_records=received, saved_records=saved,
                           proves_completeness=False, shape="array",
                           native_schema_version="v1.0", report_type="azure_entra_source_report",
                           collection_mode="inventory",
                           facts=writer.facts({key: value for key, value in (facts or {}).items() if value is not None}))
