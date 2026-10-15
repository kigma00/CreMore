"""Key/certificate metadata listings; no private key or certificate secret reads."""

import re

# Integration: moved from cremore.coverage.providers.facts, whose package import ran the adapter
# registry (every provider) and the coverage store; this module loads neither.
from cremore.coverage.facts import FactWriter
from cremore.coverage.metadata_models import EntityObservation, MetadataOmission

from .normalization import TAGS_OMITTED, _state, epoch, identity, provenance, report
from .transport import ApiError

SOURCES = ("keys", "key_versions", "deleted_keys", "certificates", "certificate_versions", "deleted_certificates")
_KIND = {"keys": "key", "certificates": "certificate"}


def resource_identity(spec, resource):
    if not isinstance(resource, str):
        return None
    match = re.fullmatch(re.escape(spec.origin) + r"/(keys|certificates)/([A-Za-z0-9-]{1,127})(?:/([A-Za-z0-9]{1,64}))?", resource)
    if not match:
        return None
    family, name, version = match.groups()
    prefix = _KIND[family] + ("Version" if version else "")
    identifier = f"{prefix}:{spec.scopes[0].id}:{name}" + ("/versions/" + version if version else "")
    return family, name, version or "", identifier


def observation(spec, scope, row, phase):
    resource = row.get("kid") if "key" in phase else row.get("id")
    parsed = resource_identity(spec, resource)
    if not parsed:
        return None
    family, name, version, object_id = parsed
    if family != ("keys" if "key" in phase else "certificates"):
        return None
    if "versions" not in phase and version:
        return None
    attributes = row.get("attributes") if isinstance(row.get("attributes"), dict) else {}
    provider_state, normalized, basis = _state(attributes)
    if phase.startswith("deleted_"):
        provider_state, normalized, basis = "deleted", "DELETED", "PROVIDER_REPORTED"
    values = {"resource_name": resource, "resource_type": _KIND[family], "name": name,
              "version_id": version or None, "enabled": attributes.get("enabled"),
              "created_at": epoch(attributes.get("created")), "updated_at": epoch(attributes.get("updated")),
              "expires_at": epoch(attributes.get("exp")), "not_before": epoch(attributes.get("nbf")),
              "recoverable_days": attributes.get("recoverableDays"), "recovery_level": attributes.get("recoveryLevel"),
              "managed": row.get("managed"), "deleted_at": epoch(row.get("deletedDate"))}
    if (family == "certificates" and isinstance(row.get("x5t"), str)
            and re.fullmatch(r"[A-Za-z0-9_-]{27}=?", row["x5t"])):
        values["x5t"] = row["x5t"]
    writer = FactWriter()
    facts = writer.facts({key: value for key, value in values.items() if value is not None})
    omissions = list(writer.omissions)
    if family == "certificates" and "x5t" in row and "x5t" not in values:
        omissions.append(MetadataOmission(path="/x5t", reason="INVALID_METADATA_VALUE"))
    for field in ("cer", "key", "value", "secret", "privateKey"):
        if field in row:
            omissions.append(MetadataOmission(path="/" + field, reason="MATERIAL_NOT_COLLECTED"))
    if row.get("tags"):
        omissions.append(MetadataOmission(path="/tags", reason=TAGS_OMITTED))
    return EntityObservation(scope=scope, purpose="vault_metadata",
        provenance=provenance("azure.key_vault." + phase, resource),
        identity=identity(spec, "vault_version" if version else "vault_item", object_id),
        facts=facts, omissions=omissions, provider_state=provider_state,
        normalized_state=normalized, state_basis=basis)


def collect_resources(context, cursor, *, phase):
    from .adapter import _complete_operation, _page

    spec, run = context["spec"], context["run"]
    family = "keys" if "key" in phase else "certificates"
    versions = "versions" in phase
    # As for secret versions: a version listing is only as complete as the parent listing that named it.
    parent = ([] if not versions or _complete_operation(context["records"], run.scope.model_dump(),
                                                         "azure.key_vault." + family)
              else ["PARENT_LISTING_INCOMPLETE"])
    if versions:
        names = sorted({parsed[1] for item in context["records"]
                        if item.get("record_type") == "entity_observation"
                        and item.get("provenance", {}).get("operation") == "azure.key_vault." + family
                        and (parsed := resource_identity(spec, item["provenance"].get("resource_id")))
                        and parsed[0] == family and not parsed[2]})
        paths = [f"/{family}/{name}/versions" for name in names]
    else:
        paths = ["/" + ("deleted" + family if phase.startswith("deleted_") else family)]
    index = int(cursor.get("index", 0))
    pages, received, saved = (int(cursor.get(name, 0)) for name in ("pages", "received", "saved"))
    if index > len(paths):
        raise ValueError("AZURE_KEY_VAULT_CHECKPOINT_MISMATCH")
    token = cursor.get("skiptoken", "")
    seen = set(cursor.get("seen", []))
    if not paths:
        yield [report(spec, run.scope, "azure.key_vault." + phase, status="PARTIAL" if parent else "COMPLETE",
                      reasons=["NO_LISTED_RESOURCES_FOR_VERSIONS", *parent], shape="empty")], {}
    while index < len(paths):
        rows, next_token = _page(context["transport"], paths[index], {"skiptoken": token}, origin=spec.origin)
        pages += 1
        received += len(rows)
        records = []
        for row in rows:
            record = observation(spec, run.scope, row, phase) if isinstance(row, dict) else None
            if record and versions:
                parsed = resource_identity(spec, record.provenance.resource_id)
                if not parsed[2] or parsed[1] != names[index]:
                    record = None
            if record:
                records.append(record)
        saved += len(records)
        if next_token and next_token in seen:
            raise ApiError("invalid_response")
        more = bool(next_token) or index + 1 < len(paths)
        if not more or pages >= spec.max_pages:
            reasons = ((["PAGE_LIMIT_REACHED"] if more else []) + (["INVALID_IDENTIFIERS"] if received != saved else [])
                       + parent)
            yield [*records, report(spec, run.scope, "azure.key_vault." + phase,
                status="PARTIAL" if reasons else "COMPLETE", reasons=reasons,
                pages=pages, received=received, saved=saved)], {}
            return
        if next_token:
            seen.add(next_token)
        else:
            index += 1
            seen = set()
        token = next_token
        yield records, {"index": index, "skiptoken": token, "seen": sorted(seen),
                        "pages": pages, "received": received, "saved": saved}
