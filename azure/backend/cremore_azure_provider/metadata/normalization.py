"""Key Vault responses as typed observations, with the rotation claim removed.

Two mappings the native adapter made are refused here.

``updated_on`` is the last time *any* property of the secret changed: a tag
edit, an enable, a new expiry. Recording it as a rotation would tell an
operator a credential was replaced when nothing about the value changed. It is
recorded under its own name, ``updated_at``, and nowhere else.

``rotation_enabled`` came from a tag. A tag is what an operator wrote on the
object, not what the provider does. The Key Vault data plane publishes no
rotation policy for a *secret* at all, so the honest record is that rotation is
not established -- with the tags left out entirely, since an unapproved tag key
would otherwise become metadata the field allowlist never approved.
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
    OperationReport,
    RecordQuality,
)

from . import API_VERSION, CONTRACT_VERSION, SOURCE_COMMIT

# What a Key Vault listing can never establish, stated on every report so an
# absent answer is never read as a negative one.
ROTATION_UNKNOWN = "SECRET_ROTATION_POLICY_NOT_PUBLISHED_BY_THE_DATA_PLANE"
UPDATED_IS_NOT_ROTATION = "UPDATED_ON_IS_A_PROPERTY_CHANGE_NOT_A_ROTATION"
TAGS_OMITTED = "TAGS_ARE_AN_OPERATOR_DECLARATION_NOT_PROVIDER_STATE"


def now() -> str:
    return datetime.now(UTC).isoformat()


def epoch(value) -> str | None:
    """Key Vault attributes carry Unix seconds; anything else is not a time."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not -62135596800 <= value <= 253402300799:
        return None
    return datetime.fromtimestamp(value, UTC).isoformat()


def identity(spec, kind, value) -> EntityIdentity:
    return EntityIdentity(provider="azure_key_vault", origin=spec.origin, tenant=spec.tenant,
                          tenant_confirmed=spec.tenant_confirmed, kind=kind, object_id=value)


def provenance(operation, resource_id="") -> MetadataProvenance:
    return MetadataProvenance(operation=operation, observed_at=now(),
                              resource_id=resource_id[:2048], source_commit=SOURCE_COMMIT,
                              contract_version=CONTRACT_VERSION)


def secret_name(identifier) -> str:
    """The secret name out of a Key Vault identifier, or "" if it is not one."""
    if not isinstance(identifier, str) or "/secrets/" not in identifier:
        return ""
    tail = identifier.split("/secrets/", 1)[1].split("/")
    return tail[0] if tail and tail[0] else ""


def version_id(identifier) -> str:
    if not isinstance(identifier, str) or "/secrets/" not in identifier:
        return ""
    parts = identifier.split("/secrets/", 1)[1].split("/")
    return parts[1] if len(parts) > 1 else ""


def object_id(vault: str, item: dict) -> str:
    """A stable identity inside the vault namespace, not a bare provider URL."""
    name = secret_name(item.get("id"))
    version = version_id(item.get("id"))
    if version:
        return f"secretVersion:{vault}:{name}/versions/{version}"
    return f"secret:{vault}:{name}"


def _state(attributes: dict) -> tuple[str, str, str]:
    """(provider state, normalized state, basis) from the attributes block.

    ``enabled: false`` is the provider's own word. An expiry in the past is
    read as expired because the provider publishes the expiry, not because
    anything here checked whether the secret still works.
    """
    if attributes.get("enabled") is False:
        return "disabled", "DISABLED", "PROVIDER_REPORTED"
    expiry = epoch(attributes.get("exp"))
    if expiry and datetime.fromisoformat(expiry) <= datetime.now(UTC):
        return "expired", "EXPIRED", "PROVIDER_REPORTED"
    if attributes.get("enabled") is True:
        return "enabled", "ACTIVE", "PROVIDER_REPORTED"
    return "unknown", "UNKNOWN", "UNKNOWN"


def observation(spec, scope, vault: str, item: dict, *, operation: str,
                deleted: bool = False) -> EntityObservation:
    attributes = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
    version = version_id(item.get("id"))
    kind = "vault_version" if version else "vault_item"
    provider_state, normalized, basis = _state(attributes)
    if deleted:
        provider_state, normalized, basis = "deleted", "DELETED", "PROVIDER_REPORTED"
    values = {
        "resource_name": item.get("id"),
        "secret_id": secret_name(item.get("id")),
        "location": vault,
        "enabled": attributes.get("enabled"),
        "created_at": epoch(attributes.get("created")),
        # The last property change, under the name that says so. It is never
        # a rotation: a tag edit moves this value and the secret is untouched.
        "updated_at": epoch(attributes.get("updated")),
        "expires_at": epoch(attributes.get("exp")),
        "not_before": epoch(attributes.get("nbf")),
        "recovery_level": attributes.get("recoveryLevel"),
        "recoverable_days": attributes.get("recoverableDays"),
        "content_type": item.get("contentType"),
        "managed": item.get("managed"),
    }
    if version:
        values["version_id"] = version
    if deleted:
        values["deleted_at"] = epoch(item.get("deletedDate"))
    writer = FactWriter()
    facts = writer.facts({key: value for key, value in values.items() if value is not None})
    omissions = list(writer.omissions)
    if isinstance(item.get("tags"), dict) and item["tags"]:
        # The native adapter read rotation settings out of these. They are the
        # operator's own writing, so they are left out and the reason is kept.
        omissions.append(MetadataOmission(path="/tags", reason=TAGS_OMITTED))
    return EntityObservation(
        scope=scope, purpose="vault_metadata", identity=identity(spec, kind, object_id(vault, item)),
        provenance=provenance(operation, str(item.get("id") or "")),
        facts=facts, omissions=omissions, provider_state=provider_state,
        normalized_state=normalized, state_basis=basis,
    )


def report(spec, scope, operation, *, status="COMPLETE", reasons=(), pages=0, received=0,
           saved=0, facts=None, resource_id="", shape="array") -> OperationReport:
    writer = FactWriter()
    values = {key: value for key, value in (facts or {}).items() if value is not None}
    return OperationReport(
        scope=scope, purpose="vault_metadata", provenance=provenance(operation, resource_id),
        status=status, reasons=sorted(set(reasons)), pages=pages, received_records=received,
        saved_records=saved, proves_completeness=False, shape=shape,
        record_quality=RecordQuality(records=received, identified=saved),
        native_schema_version=API_VERSION, report_type="azure_key_vault_source_report",
        collection_mode=spec.options.mode,
        facts=writer.facts(values), omissions=writer.omissions,
    )


def record_values(item) -> dict:
    """Read a stored record's facts back as the plain mapping they came from."""
    facts = item.facts if hasattr(item, "facts") else item["facts"]
    return unpack_facts([f.model_dump() if hasattr(f, "model_dump") else f for f in facts])
