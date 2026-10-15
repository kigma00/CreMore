"""Explicit projections of documented Admin API fields, with bounded omissions."""

from __future__ import annotations

import hashlib
import math
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit
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
from cremore.coverage.models import digest

from . import API_VERSION, CONTRACT_VERSION

_SECRET = re.compile(r"(?:adm_|secret_|ntn_)", re.IGNORECASE)
PAT_FIELDS = {
    "id", "creator", "created_at", "status", "name", "expires_at", "last_used_at",
    "revoked_at", "revoked_by",
}
MCP_FIELDS = {
    "client", "created_at", "is_enterprise_managed", "user", "workspaces", "idp_issuer",
    "last_active_at",
}
LIMITATIONS = ["TOKEN_VALUES_NOT_RETURNED", "NOT_ALL_NOTION_CREDENTIAL_TYPES"]


def uuid_text(value):
    if not isinstance(value, str) or len(value) != 36:
        raise ValueError("NOTION_INVALID_IDENTIFIER")
    try:
        parsed = str(UUID(value))
    except ValueError:
        raise ValueError("NOTION_INVALID_IDENTIFIER") from None
    if parsed != value:
        raise ValueError("NOTION_INVALID_IDENTIFIER")
    return parsed


def safe_text(value, *, bearer="", max_length=2048):
    if (not isinstance(value, str) or len(value) > max_length or _SECRET.search(value)
            or bearer and bearer in value):
        raise ValueError("NOTION_UNSAFE_METADATA")
    return metadata_text(value)


def epoch_milliseconds(value):
    """The Admin API uses milliseconds, never seconds or numeric strings."""
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or not 0 <= value <= 253402300799999):
        raise ValueError("NOTION_INVALID_TIME")
    return datetime.fromtimestamp(value / 1000, UTC).isoformat(timespec="milliseconds")


def operation(source):
    return "notion." + source


def resource(scope, source):
    # The MCP API is organization-wide; this identifier binds its mandatory
    # workspace filter as well as the endpoint to the saved provenance.
    return "workspace:" + scope.id + "/" + source


def provenance(scope, source, observed_at):
    return MetadataProvenance(operation=operation(source), observed_at=observed_at,
                              resource_id=resource(scope, source), contract_version=CONTRACT_VERSION)


def _unknown(writer, row, allowed, path=""):
    for key in row.keys() - allowed:
        # Provider-controlled field names can themselves contain secrets.
        hashed_path = "field/" + hashlib.sha256((path + str(key)).encode()).hexdigest()
        writer.omit(hashed_path, "UNAPPROVED_METADATA_FIELD")


def _person(value, writer, path, bearer, *, revoker=False):
    if not isinstance(value, dict):
        raise TypeError("NOTION_INVALID_PRINCIPAL")
    allowed = {"id", "name", "email"} | ({"type"} if revoker else set())
    _unknown(writer, value, allowed | {"profile_photo_url"}, path)
    if "profile_photo_url" in value:
        writer.omit(path + "/profile_photo_url", "PROFILE_IMAGE_NOT_COLLECTED")
    result = {"id": uuid_text(value.get("id"))}
    if revoker:
        if value.get("type") not in ("bot", "organization_bot", "user"):
            raise ValueError("NOTION_INVALID_PRINCIPAL")
        result["type"] = value["type"]
    for field in ("name", "email"):
        if field in value:
            try:
                result[field] = safe_text(value[field], bearer=bearer)
            except ValueError:
                writer.omit(path + "/" + field, "INVALID_METADATA_VALUE")
    return result


def observation(spec, scope, source, row, *, observed_at, bearer=""):
    if not isinstance(row, dict):
        raise TypeError("NOTION_INVALID_RECORD")
    writer = FactWriter()
    _unknown(writer, row, PAT_FIELDS if source == "personal_access_tokens" else MCP_FIELDS)
    fields = {"created_at": epoch_milliseconds(row.get("created_at"))}
    if source == "personal_access_tokens":
        fields["id"] = uuid_text(row.get("id"))
        fields["creator"] = _person(row.get("creator"), writer, "creator", bearer)
        state = row.get("status")
        if state not in ("active", "expired", "revoked"):
            raise ValueError("NOTION_INVALID_STATUS")
        fields["status"] = state
        if "name" in row:
            try:
                fields["name"] = safe_text(row["name"], bearer=bearer)
            except ValueError:
                writer.omit("name", "INVALID_METADATA_VALUE")
        if "revoked_by" in row:
            fields["revoked_by"] = _person(row["revoked_by"], writer, "revoked_by", bearer, revoker=True)
        time_fields = ("expires_at", "last_used_at", "revoked_at")
        kind, object_id = "credential", "pat:" + scope.id + ":" + fields["id"]
    else:
        client = row.get("client")
        if not isinstance(client, dict) or not isinstance(row.get("is_enterprise_managed"), bool):
            raise ValueError("NOTION_INVALID_MCP_CONNECTION")
        _unknown(writer, client, {"key", "name", "type"}, "client/")
        fields["client"] = {key: safe_text(client.get(key), bearer=bearer)
                            for key in ("key", "name", "type")}
        if not fields["client"]["key"]:
            raise ValueError("NOTION_INVALID_MCP_CONNECTION")
        user = row.get("user")
        if not isinstance(user, dict):
            raise TypeError("NOTION_INVALID_PRINCIPAL")
        _unknown(writer, user, {"id"}, "user/")
        fields["user"] = {"id": uuid_text(user.get("id"))}
        workspaces = row.get("workspaces")
        if (not isinstance(workspaces, list) or not workspaces
                or any(not isinstance(item, dict) or uuid_text(item.get("id")) != scope.id
                       for item in workspaces)):
            raise ValueError("NOTION_WORKSPACE_MISMATCH")
        fields["workspaces"] = [{"id": scope.id}]
        for workspace in workspaces:
            _unknown(writer, workspace, {"id"}, "workspaces/")
        fields["is_enterprise_managed"] = row["is_enterprise_managed"]
        if "idp_issuer" in row:
            if not fields["is_enterprise_managed"]:
                raise ValueError("NOTION_INVALID_MCP_CONNECTION")
            fields["idp_issuer"] = safe_text(row["idp_issuer"], bearer=bearer)
            issuer = urlsplit(fields["idp_issuer"])
            if (issuer.scheme != "https" or not issuer.hostname or issuer.username or issuer.password
                    or issuer.query or issuer.fragment):
                raise ValueError("NOTION_INVALID_IDP_ISSUER")
        identity = [scope.id, fields["user"]["id"], fields["client"]["key"],
                    fields["is_enterprise_managed"], fields.get("idp_issuer")]
        kind, object_id = "installation", "mcp:" + scope.id + ":" + digest(identity)
        state, time_fields = "UNKNOWN", ("last_active_at",)
    for field in time_fields:
        if field in row:
            try:
                fields[field] = epoch_milliseconds(row[field])
            except ValueError:
                writer.omit(field, "INVALID_METADATA_TIME")
    facts = writer.facts(fields)
    return EntityObservation(
        scope=scope, purpose="issuer_inventory",
        identity=EntityIdentity(provider="notion", origin=spec.origin, tenant=spec.tenant,
                                tenant_confirmed=spec.tenant_confirmed, kind=kind, object_id=object_id),
        provenance=provenance(scope, source, observed_at), facts=facts, omissions=writer.omissions,
        provider_state=state, normalized_state=state.upper(),
        state_basis="UNKNOWN" if source == "mcp_client_connections" else "PROVIDER_REPORTED",
    )


def report(scope, source, *, observed_at, status, reasons=(), pages=0, received=0,
           saved=0, invalid=0, duplicates=0, complete=False):
    return OperationReport(
        scope=scope, provenance=provenance(scope, source, observed_at), status=status,
        reasons=sorted({*LIMITATIONS, *reasons}), pages=pages, received_records=received,
        saved_records=saved, proves_completeness=complete, shape="array",
        native_schema_version=API_VERSION, report_type="notion_admin_source_report",
        collection_mode="inventory",
        record_quality=RecordQuality(records=received, identified=saved, invalid_records=invalid,
                                     duplicates=duplicates),
        facts=[MetadataFact(name="coverage_basis", value="DECLARED_WORKSPACE_AND_SOURCE_ONLY")],
    )


def record_values(record):
    return unpack_facts(record.get("facts", []))
