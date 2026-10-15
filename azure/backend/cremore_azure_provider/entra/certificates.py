"""Opt-in singleton Graph reads for public certificate fingerprints."""

from copy import deepcopy

# Integration: moved from cremore.coverage.providers.facts, whose package import ran the adapter
# registry (every provider) and the coverage store; this module loads neither.
from cremore.coverage.facts import unpack_facts
from cremore.coverage.metadata_models import EntityObservation, MetadataFact
from cremore_azure_provider.metadata.transport import DEFERRED, ApiError
from cremore_azure_provider.public_certificates import EVIDENCE_CLASS, certificate_sha256

from .normalization import guid, provenance, report


def _targets(spec, records):
    from .adapter import validate_record

    targets = {}
    for body in records:
        # The latest observation of each certificate wins, so one app_access added carries its permissions on.
        if (body.get("record_type") != "entity_observation"
                or body.get("identity", {}).get("kind") != "public_key"
                or body.get("provenance", {}).get("operation") not in {
                    "azure.entra.applications", "azure.entra.service_principals", "azure.entra.app_access"}):
            continue
        item = EntityObservation.model_validate(body)
        if not validate_record(spec, item):
            raise ValueError("AZURE_ENTRA_RECORD_REPLAY_REJECTED")
        family, parent, _, key_id = item.identity.object_id.split(":")
        values = unpack_facts(body["facts"])
        application = guid(values.get("application_id"))
        if not application or values.get("credential_type") != "AZURE_CERTIFICATE":
            continue
        key = (family, parent, application)
        targets.setdefault(key, {})[key_id] = item
    return sorted(targets.items())


def collect_certificates(spec, state, transport, previous, spent, check):
    from .adapter import _degrade, _page

    targets = _targets(spec, previous)
    cursor = state["cursor"]
    index = cursor.get("index", 0)
    saved = cursor.get("saved", 0)
    reasons = set(cursor.get("reasons", []))
    if len(targets) > spec.options.max_targets:
        targets = targets[:spec.options.max_targets]
        reasons.add("TARGET_LIMIT_REACHED")
    if index > len(targets):
        raise ValueError("AZURE_ENTRA_CHECKPOINT_MISMATCH")
    if state["status"] != "COMPLETE":
        reasons.add("CERTIFICATE_DISCOVERY_INCOMPLETE")
    while index < len(targets):
        check()
        committed = deepcopy(state)
        (family, parent, application), known = targets[index]
        path = "/v1.0/" + ("applications" if family == "application" else "servicePrincipals") + "/" + parent
        records = []
        try:
            payload = transport.get(path, {"$select": "id,appId,keyCredentials"})
            if (guid(payload.get("id")) != parent or guid(payload.get("appId")) != application
                    or payload.get("@odata.nextLink") or not isinstance(payload.get("keyCredentials"), list)):
                raise ApiError("invalid_certificate_parent")
            identifiers = [guid(entry.get("keyId")) if isinstance(entry, dict) else None
                           for entry in payload["keyCredentials"]]
            if None in identifiers or len(set(identifiers)) != len(identifiers):
                raise ApiError("invalid_certificate_identifiers")
            seen = set()
            for entry in payload["keyCredentials"]:
                key_id = guid(entry.get("keyId")) if isinstance(entry, dict) else None
                seen.add(key_id)
                if entry.get("type") != "AsymmetricX509Cert":
                    if key_id in known:
                        reasons.add("CERTIFICATE_INVENTORY_CHANGED")
                    continue
                if key_id not in known:
                    reasons.add("CERTIFICATE_INVENTORY_CHANGED")
                    continue
                try:
                    fingerprint = certificate_sha256(entry.get("key"))
                except ValueError:
                    reasons.add("INVALID_PUBLIC_CERTIFICATE")
                    continue
                item = known[key_id].model_copy(deep=True)
                item.provenance = provenance("public_certificates", spec.origin + path)
                item.facts.extend([MetadataFact(name="sha256_fingerprint", value=fingerprint),
                                   MetadataFact(name="evidence_class", value=EVIDENCE_CLASS)])
                records.append(item)
            if set(known) - seen:
                reasons.add("CERTIFICATE_INVENTORY_CHANGED")
        except ApiError as exc:
            if exc.code in DEFERRED:
                raise
            reasons.add(exc.code.upper())
        index += 1
        saved += len(records)
        state["requests"] = spent + transport.requests
        finished = index == len(targets) or index >= spec.max_pages
        if index >= spec.max_pages and index < len(targets):
            reasons.add("PAGE_LIMIT_REACHED")
        if finished:
            records.append(report(spec, "public_certificates", status="PARTIAL" if reasons else "COMPLETE",
                                  reasons=reasons, pages=index, received=index, saved=saved))
            if reasons:
                _degrade(state, reasons)
            state["phase"] += 1
            state["cursor"] = {}
        else:
            state["cursor"] = {"index": index, "saved": saved, "reasons": sorted(reasons)}
        yield _page(spec, state, records, committed)
        if finished:
            return
    if not targets:
        committed = deepcopy(state)
        state["phase"] += 1
        state["cursor"] = {}
        if reasons:
            _degrade(state, reasons)
        yield _page(spec, state, [report(spec, "public_certificates", status="PARTIAL" if reasons else "COMPLETE",
                                        reasons=reasons)], committed)
