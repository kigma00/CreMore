"""Typed, reversible GCP observations for the shared coverage projections.

Every record keeps enough of the native row to rebuild the connector's own
inventory and relationship JSON, and nothing the shared field contract has not
approved. A value only appears as a fingerprint produced by the product's own
detection engine, never as the value itself.
"""

from __future__ import annotations

from datetime import UTC, datetime

# Integration: moved from cremore.coverage.providers.facts, whose package import ran the adapter
# registry (every provider) and the coverage store; this module loads neither.
from cremore.coverage.facts import FactWriter, unpack_facts
from cremore.coverage.metadata_models import (
    EntityIdentity,
    EntityObservation,
    MetadataOmission,
    MetadataProvenance,
    MetadataRelation,
    MetadataValueMatch,
    OperationReport,
    RecordQuality,
)

from . import CONTRACT_VERSION, NATIVE_INVENTORY_SCHEMA, SOURCE_COMMIT
from .effective_access import permissions as effective_permissions

# Native item source -> shared object kind and purpose.
KINDS = {
    "gcp_iam_service_accounts": ("principal", "issuer_inventory"),
    "gcp_iam_service_account_keys": ("credential", "issuer_inventory"),
    "gcp_api_keys": ("credential", "issuer_inventory"),
    "gcp_secret_manager": ("vault_item", "vault_metadata"),
}
_STATES = {
    "active": ("ACTIVE", "PROVIDER_REPORTED"),
    "disabled": ("DISABLED", "PROVIDER_REPORTED"),
    "expired": ("EXPIRED", "PROVIDER_REPORTED"),
    "deleted": ("DELETED", "PROVIDER_REPORTED"),
    "destroyed": ("DELETED", "PROVIDER_REPORTED"),
    "unknown": ("UNKNOWN", "UNKNOWN"),
}


def now() -> str:
    return datetime.now(UTC).isoformat()


def object_id(item: dict) -> str:
    """A stable identity inside the project namespace, not a bare provider ID."""
    source = item["source"]
    if item.get("object_type") == "vault_version":
        parent = item["parent_secret"]
        return f"secretVersion:{_location(parent)}:" + item["source_id"].split("/secrets/", 1)[1]
    if source == "gcp_iam_service_accounts":
        return "serviceAccount:" + item["service_account_email"]
    if source == "gcp_iam_service_account_keys":
        return f"serviceAccountKey:{item['service_account_email']}:{item['key_id']}"
    if source == "gcp_api_keys":
        return "apiKey:" + item["key_id"]
    location = item.get("location", "global")
    return f"secret:{location}:" + item["source_id"].rsplit("/", 1)[-1]


def identity(spec, kind, value) -> EntityIdentity:
    return EntityIdentity(provider="gcp", origin=spec.origin, tenant=spec.tenant,
                          tenant_confirmed=spec.tenant_confirmed, kind=kind, object_id=value)


def provenance(operation, resource_id="", *, generated_at=None) -> MetadataProvenance:
    return MetadataProvenance(operation=operation, observed_at=now(), resource_id=resource_id,
                              provider_generated_at=generated_at, source_commit=SOURCE_COMMIT,
                              contract_version=CONTRACT_VERSION)


def _entity_facts(item):
    """Native keys mapped onto approved names; the rest becomes an omission."""
    source = item["source"]
    values = {"project_id": item["project_id"], "resource_name": item["source_id"]}
    omitted = []
    if source == "gcp_iam_service_accounts":
        values.update(service_account_email=item["service_account_email"],
                      disabled=item.get("disabled"), display_name=item.get("display_name"),
                      id=item.get("unique_id"))
    elif source == "gcp_iam_service_account_keys":
        values.update(key_id=item["key_id"], service_account_email=item["service_account_email"],
                      key_type=item["credential_type"], key_origin=item.get("key_origin"),
                      key_algorithm=item.get("key_algorithm"),
                      valid_after_time=item.get("valid_after_time"),
                      valid_before_time=item.get("valid_before_time"),
                      disabled=item.get("disabled"), disabled_reason=item.get("disable_reason"))
        if item.get("public_key"):
            values["public_key"] = item["public_key"]
    elif source == "gcp_api_keys":
        values.update(key_id=item["key_id"], uid=item.get("api_key_uid"),
                      display_name=item.get("display_name"), created_at=item.get("created_at"),
                      updated_at=item.get("updated_at"), deleted_at=item.get("deleted_at"),
                      service_account_email=item.get("service_account_email"),
                      restrictions={"type": item.get("client_restriction_type"),
                                    "count": item.get("api_target_count"),
                                    "service": item.get("api_target_services") or None})
    elif item.get("object_type") == "vault_version":
        values.update(version_id=item["source_id"].rsplit("/", 1)[-1],
                      secret_id=item["parent_secret"].rsplit("/", 1)[-1],
                      location=_location(item["parent_secret"]), state=item.get("state"),
                      created_at=item.get("created_at"), destroyed_at=item.get("destroyed_at"))
    else:
        values.update(secret_id=item["source_id"].rsplit("/", 1)[-1],
                      location=item.get("location", "global"),
                      created_at=item.get("created_at"), expires_at=item.get("expires_at"),
                      next_rotation_time=item.get("next_rotation_time"),
                      rotation_period=item.get("rotation_period"),
                      count=item.get("label_count"))
        if item.get("label_count") or item.get("annotation_count"):
            omitted.append(MetadataOmission(path="/labels", reason="UNAPPROVED_METADATA_FIELD"))
    writer = FactWriter()
    facts = writer.facts({key: value for key, value in values.items() if value is not None})
    return facts, writer.omissions + omitted


def _location(secret_name):
    parts = secret_name.split("/")
    return parts[3] if len(parts) > 4 and parts[2] == "locations" else "global"


def observation(spec, scope, item, *, value_match=None, payload_digest=None) -> EntityObservation:
    kind, purpose = (
        ("vault_version", "vault_metadata") if item.get("object_type") == "vault_version"
        else KINDS[item["source"]]
    )
    from .collector import lifecycle

    operation = item["source"] + (".versions" if item.get("object_type") == "vault_version" else "")
    observed = provenance(operation, item["source_id"])
    # The expiry is judged at the observation's own time, so the record states what it saw.
    state = lifecycle(item, observed.observed_at)
    normalized, basis = _STATES.get(state, ("UNKNOWN", "UNKNOWN"))
    facts, omissions = _entity_facts(item)
    # A user-managed key's account access, as Policy Troubleshooter evaluated it (effective_access).
    access = effective_permissions(item["project_id"], item["effective_access"]) if item.get("effective_access") else []
    return EntityObservation(
        scope=scope, purpose=purpose, identity=identity(spec, kind, object_id(item)),
        provenance=observed,
        facts=facts, omissions=omissions, provider_state=state, normalized_state=normalized,
        state_basis=basis, value_match=value_match, payload_digest=payload_digest, permissions=access,
    )


def value_match(context, reference, *, version="", version_state="UNKNOWN",
                observation_row=None, reason=None) -> MetadataValueMatch:
    """One v1 hashed observation projected into the schema 2 value contract."""
    shared = {"reference": reference, "version": version, "version_state": version_state,
              "key_id": context["key_id"], "engine_digest": context["engine_digest"],
              "policy_digest": context["policy_digest"], "read_at": now()}
    if observation_row is None:
        return MetadataValueMatch(evidence="UNRESOLVED", reason=reason or "VALUE_UNAVAILABLE",
                                  **shared)
    return MetadataValueMatch(
        evidence=observation_row.evidence, credential_type=observation_row.credential_type,
        fingerprint=observation_row.fingerprint, identifier=observation_row.identifier,
        provider_digest=getattr(observation_row, "provider_digest", None),
        session_fingerprint=getattr(observation_row, "session_fingerprint", None),
        issuer_identifier=getattr(observation_row, "issuer_identifier", ""),
        reason=observation_row.reason, **shared,
    )


def relation(spec, scope, edge, *, purpose="usage") -> MetadataRelation:
    subject_kind, subject_id = _edge_identity(edge["source_id"])
    target_kind, target_id = _edge_identity(edge["target_id"])
    observed = edge["evidence_class"] == "observed_access"
    listing = edge["evidence_class"] == "provider_listing"
    creation = edge["evidence_class"] == "credential_creation"
    writer = FactWriter()
    # source_id and target_id keep the provider's own resource names so the
    # native edge, including its identifier, is rebuilt from the record alone.
    values = {key: edge.get(key) for key in (
        "source_id", "target_id", "relation", "evidence_class", "evidence_source", "evidence_id",
        "coverage_path", "log_name", "insert_id", "method_name", "request_count",
        "caller_identity", "service", "role", "policy_resource", "condition_present",
        "effective_access", "secret_id", "version_id", "resource_name",
        "inherited_policies", "deny_policies", "principal_access_boundaries",
        "membership_resolution", "condition_evaluation",
    )}
    return MetadataRelation(
        scope=scope, purpose=purpose,
        subject=identity(spec, subject_kind, subject_id),
        target=identity(spec, target_kind, target_id),
        # A listing is the provider's own statement of ownership, an audit or
        # metric entry is observed use, and an allow policy is only a candidate.
        relation="created_by" if creation else "owns" if listing else "used" if observed else "can_access",
        match_basis="AUDIT_REFERENCE" if edge["evidence_source"].startswith("cloud_logging")
        else "POLICY" if edge["evidence_source"].startswith("iam_allow_policy") else "PROVIDER_ID",
        confidence="CANDIDATE" if not (observed or listing or creation) else "EXACT",
        window_start=edge["first_observed_at"], window_end=edge["last_observed_at"],
        provenance=provenance(edge["evidence_source"], edge["evidence_id"]),
        facts=writer.facts({key: value for key, value in values.items() if value is not None}),
        omissions=writer.omissions,
    )


def _edge_identity(value: str) -> tuple[str, str]:
    """Native edge endpoints name either an inventory object or a bare resource."""
    if value.startswith(("gcp_principal:", "iam_member:")):
        return "principal", value
    if value.startswith("gcp_api:"):
        return "resource", value
    if "/secrets/" in value and "/versions/" in value:
        return "vault_version", f"secretVersion:{_location(value)}:" + value.split("/secrets/", 1)[1]
    if "/secrets/" in value:
        return "vault_item", f"secret:{_location(value)}:" + value.rsplit("/", 1)[-1]
    if "/serviceAccounts/" in value and "/keys/" in value:
        email, key = value.split("/serviceAccounts/", 1)[1].split("/keys/")
        return "credential", f"serviceAccountKey:{email}:{key}"
    if "/serviceAccounts/" in value:
        return "principal", "serviceAccount:" + value.rsplit("/", 1)[-1]
    if "/locations/global/keys/" in value:
        return "credential", "apiKey:" + value.rsplit("/", 1)[-1]
    return "resource", value


def report(spec, scope, operation, *, purpose="issuer_inventory", status="COMPLETE", reasons=(),
           pages=0, received=0, saved=0, facts=None, resource_id="", quality=None,
           value_access="NOT_REQUESTED", value_contract=None, window=(None, None),
           shape="unknown") -> OperationReport:
    writer = FactWriter()
    values = {key: value for key, value in (facts or {}).items() if value is not None}
    return OperationReport(
        scope=scope, purpose=purpose, provenance=provenance(operation, resource_id),
        status=status, reasons=sorted(set(reasons)), pages=pages, received_records=received,
        saved_records=saved, proves_completeness=False, shape=shape,
        record_quality=quality or RecordQuality(records=received, identified=saved),
        native_schema_version=NATIVE_INVENTORY_SCHEMA, report_type="gcp_source_report",
        collection_mode=spec.options.mode, window_start=window[0], window_end=window[1],
        value_access=value_access, value_contract=value_contract,
        facts=writer.facts(values), omissions=writer.omissions,
    )


def record_values(item) -> dict:
    """Read a stored record's facts back as the plain mapping they came from."""
    facts = item.facts if hasattr(item, "facts") else item["facts"]
    return unpack_facts([f.model_dump() if hasattr(f, "model_dump") else f for f in facts])
