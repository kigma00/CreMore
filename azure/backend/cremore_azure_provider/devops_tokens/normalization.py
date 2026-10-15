"""Explicit projections of documented Token Admin fields; token values are never kept."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from uuid import UUID

# Integration: moved from cremore.coverage.providers.facts, whose package import ran the adapter
# registry (every provider) and the coverage store; this module loads neither.
from cremore.coverage.facts import FactWriter, unpack_facts
from cremore.coverage.metadata_models import (
    EntityIdentity,
    EntityObservation,
    MetadataFact,
    MetadataProvenance,
    OperationReport,
    RecordQuality,
    metadata_text,
)

from . import CONTRACT_VERSION, TOKEN_API_VERSION

SESSION_FIELDS = {"authorizationId", "displayName", "scope", "validFrom", "validTo", "isValid", "isPublic",
                  "userId", "clientId", "accessId", "hostAuthorizationId", "targetAccounts", "token",
                  "alternateToken", "publicData", "source", "claims"}
_SCOPE = re.compile(r"[A-Za-z0-9_.]{1,128}")
_FRACTION = re.compile(r"(\.\d{6})\d+")
LIMITATIONS = ["TOKEN_VALUES_NOT_RETURNED", "USERS_OUTSIDE_THE_ORGANIZATION_GRAPH_NOT_LISTED"]
SOURCE = "personal_access_tokens"


def uuid_text(value):
    try:
        parsed = str(UUID(str(value)))
    except ValueError:
        raise ValueError("AZURE_DEVOPS_INVALID_IDENTIFIER") from None
    if not isinstance(value, str) or parsed != value.lower():
        raise ValueError("AZURE_DEVOPS_INVALID_IDENTIFIER")
    return parsed


def utc_text(value):
    """Token Admin returns ISO times, sometimes without an offset (UTC) or with 7 fraction digits."""
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("AZURE_DEVOPS_INVALID_TIME")
    parsed = datetime.fromisoformat(_FRACTION.sub(r"\1", value.replace("Z", "+00:00")))
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).astimezone(UTC).isoformat()


def operation():
    return "azure_devops." + SOURCE


def resource(scope):
    return "organization:" + scope.id + "/" + SOURCE


def provenance(scope, observed_at):
    return MetadataProvenance(operation=operation(), observed_at=observed_at, resource_id=resource(scope),
                              contract_version=CONTRACT_VERSION)


def fields_from(row, owner, writer):
    """The kept fields of one listed token; unknown and value fields become omissions."""
    if not isinstance(row, dict) or not isinstance(row.get("isValid"), bool) or row.get("isPublic") is True:
        raise ValueError("AZURE_DEVOPS_INVALID_RECORD")
    for key in row.keys() - SESSION_FIELDS:
        writer.omit("field/" + hashlib.sha256(str(key).encode()).hexdigest(), "UNAPPROVED_METADATA_FIELD")
    for key in ("token", "alternateToken"):
        if row.get(key) not in (None, ""):
            writer.omit(key, "TOKEN_VALUE_NOT_COLLECTED")
    fields = {"authorization_id": uuid_text(row.get("authorizationId")),
              "status": "valid" if row["isValid"] else "invalid"}
    for name, key in (("created_at", "validFrom"), ("expires_at", "validTo")):
        if row.get(key) is not None:
            try:
                fields[name] = utc_text(row[key])
            except ValueError:
                writer.omit(name, "INVALID_METADATA_TIME")
    if isinstance(row.get("displayName"), str) and row["displayName"]:
        try:
            fields["display_name"] = metadata_text(row["displayName"])
        except ValueError:
            writer.omit("display_name", "INVALID_METADATA_VALUE")
    if isinstance(row.get("scope"), str):
        scopes = row["scope"].split()
        if all(_SCOPE.fullmatch(value) for value in scopes) and len(scopes) <= 100:
            fields["scopes"] = scopes
        else:
            writer.omit("scopes", "INVALID_METADATA_VALUE")
    for name, key in (("user_id", "userId"), ("client_id", "clientId")):
        if row.get(key) and row[key] != "00000000-0000-0000-0000-000000000000":
            try:
                fields[name] = uuid_text(row[key])
            except ValueError:
                writer.omit(name, "INVALID_METADATA_VALUE")
    kept = {key: value for key, value in (owner or {}).items()
            if key in ("name", "email", "origin", "origin_id") and value}
    if (owner or {}).get("descriptor"):
        # The subject descriptor the owner's tokens are listed under: an approved revoke reads the token back there.
        kept["subject"] = owner["descriptor"]
    if kept:
        fields["owner"] = kept
    return fields


def project(spec, scope, fields, *, observed_at, writer=None):
    writer = writer or FactWriter()
    state, normalized = fields["status"], "INACTIVE"
    if state == "valid":
        expired = fields.get("expires_at") and datetime.fromisoformat(fields["expires_at"]) < datetime.fromisoformat(observed_at)
        normalized = "EXPIRED" if expired else "ACTIVE"
    return EntityObservation(
        scope=scope, purpose="issuer_inventory",
        identity=EntityIdentity(provider="azure_devops", origin=spec.origin, tenant=spec.tenant,
                                tenant_confirmed=spec.tenant_confirmed, kind="credential",
                                object_id="pat:" + scope.id + ":" + fields["authorization_id"]),
        provenance=provenance(scope, observed_at), facts=writer.facts(fields), omissions=writer.omissions,
        provider_state=state, normalized_state=normalized, state_basis="PROVIDER_REPORTED")


def observation(spec, scope, row, owner, *, observed_at):
    writer = FactWriter()
    return project(spec, scope, fields_from(row, owner, writer), observed_at=observed_at, writer=writer)


def report(scope, *, observed_at, status, reasons=(), pages=0, received=0, saved=0, invalid=0,
           duplicates=0, complete=False):
    return OperationReport(
        scope=scope, provenance=provenance(scope, observed_at), status=status,
        reasons=sorted({*LIMITATIONS, *reasons}), pages=pages, received_records=received,
        saved_records=saved, proves_completeness=complete, shape="array",
        native_schema_version=TOKEN_API_VERSION, report_type="azure_devops_token_admin_report",
        collection_mode="inventory",
        record_quality=RecordQuality(records=received, identified=saved, invalid_records=invalid, duplicates=duplicates),
        facts=[MetadataFact(name="coverage_basis", value="ORGANIZATION_GRAPH_USERS_ONLY")],
    )


def record_values(record):
    return unpack_facts(record.get("facts", []))
