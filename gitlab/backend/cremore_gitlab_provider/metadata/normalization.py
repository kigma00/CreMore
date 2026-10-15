"""Typed, reversible GitLab observations for the shared coverage projections."""

from __future__ import annotations

from pydantic import ValidationError

# Integration: moved from cremore.coverage.providers.facts, whose package import ran the adapter
# registry (every provider) and the coverage store; this module loads neither.
from cremore.coverage.facts import FactWriter
from cremore.coverage.facts import unpack_facts as _unpack_facts
from cremore.coverage.metadata_models import (
    EntityIdentity,
    EntityObservation,
    MetadataFact,
    MetadataPermission,
    MetadataProvenance,
    MetadataRelation,
    OperationReport,
    ProviderEvent,
)

from .audit import utc_time
from .model import now, stable_id

SOURCE_COMMIT = "744c48c877737ee9bee0cba0de571f1de4da9ead"
NATIVE_PREFIX = "gitlab.native."
CREATION_EVIDENCE_PATH = "/audit/creation_evidence"


def unpack_facts(facts):
    """Restore the one GitLab field stored at an approved JSON-pointer path."""
    payload = _unpack_facts(facts)
    if CREATION_EVIDENCE_PATH in payload:
        audit = payload.setdefault("audit", {})
        if not isinstance(audit, dict) or "creation_evidence" in audit:
            raise ValueError("GITLAB_CONFLICTING_AUDIT_FACTS")
        audit["creation_evidence"] = payload.pop(CREATION_EVIDENCE_PATH)
    return payload


def _inventory_facts(writer, payload):
    """Keep range endpoints within the common six-level fact limit."""
    audit = payload.get("audit")
    if not isinstance(audit, dict) or "creation_evidence" not in audit:
        return writer.facts(payload)
    remaining = {**payload, "audit": {k: v for k, v in audit.items() if k != "creation_evidence"}}
    facts = writer.facts(remaining)
    # A JSON pointer preserves the native path without spending an extra node
    # level on audit. Use the same writer budget and all existing value filters.
    evidence = writer.fact("creation_evidence", audit["creation_evidence"], "audit/creation_evidence")
    if evidence is not None:
        facts.append(MetadataFact.model_validate({**evidence.model_dump(), "name": CREATION_EVIDENCE_PATH}))
    return facts


def identity(spec, native, *, asset=False):
    if asset:
        kind = "principal" if native["kind"] == "user" else "resource"
        object_id = f"{native['kind']}:{native['id']}"
    else:
        kind = "public_key" if native["namespace"] == "error_tracking_client_key" else "credential"
        object_id = native["namespace"] + ":" + stable_id(native)
    return EntityIdentity(
        provider="gitlab",
        origin=spec.origin,
        tenant=spec.tenant,
        tenant_confirmed=spec.tenant_confirmed,
        kind=kind,
        object_id=object_id,
    )


def _state(metadata):
    if metadata.get("revoked") is True or metadata.get("status") == "revoked":
        return "revoked", "REVOKED", "PROVIDER_REPORTED"
    if metadata.get("expired") is True:
        return "expired", "EXPIRED", "PROVIDER_REPORTED"
    if metadata.get("active") is True or metadata.get("status") == "active":
        return "active", "ACTIVE", "PROVIDER_REPORTED"
    if metadata.get("active") is False:
        return "inactive", "INACTIVE", "PROVIDER_REPORTED"
    if "active" not in metadata and metadata.get("revoked") is False and metadata.get("expired") is False:
        return "active", "ACTIVE", "PROVIDER_REPORTED"
    return "UNKNOWN", "UNKNOWN", "UNKNOWN"


def _permissions(metadata, writer):
    permissions = []
    scopes = metadata.get("scopes", [])
    if isinstance(scopes, list):
        for name in scopes:
            try:
                permissions.append(MetadataPermission(kind="scope", name=name, effect="ALLOW"))
            except (ValidationError, ValueError):
                writer.omit("metadata/scopes", "INVALID_METADATA_VALUE")
    granular = metadata.get("granular_scopes", [])
    if isinstance(granular, list):
        for grant in granular:
            if not isinstance(grant, dict) or not isinstance(grant.get("permissions"), list):
                continue
            scope = (
                "project"
                if grant.get("project_id") is not None
                else "group"
                if grant.get("group_id") is not None
                else ""
            )
            resource = str(grant.get(scope + "_id", "")) if scope else ""
            for name in grant["permissions"]:
                try:
                    permissions.append(
                        MetadataPermission(
                            kind="permission",
                            name=name,
                            effect="ALLOW",
                            resource_kind=scope,
                            resource_id=resource,
                        )
                    )
                except (ValidationError, ValueError):
                    writer.omit("metadata/granular_scopes", "INVALID_METADATA_VALUE")
    if len(permissions) > 250:
        writer.omit("metadata/scopes", "PERMISSION_LIMIT")
    return permissions[:250]


def record(spec, scope, kind, payload):
    """Native payload shape is retained in approved facts, not an opaque blob."""
    writer = FactWriter()
    facts = _inventory_facts(writer, payload) if kind == "inventory" else writer.facts(payload)
    clean = unpack_facts([fact.model_dump() for fact in facts])
    timestamp = (
        payload.get("observed_at")
        or payload.get("last_seen")
        or payload.get("observation", {}).get("observed_at")
        or now()
    )
    source = (
        payload.get("observation", {}).get("source_id")
        or payload.get("id")
        or payload.get("audit_event_id")
        or payload.get("inventory_id")
        or ""
    )
    provenance = MetadataProvenance(
        operation=NATIVE_PREFIX + kind,
        resource_id=str(source),
        observed_at=timestamp,
        source_commit=SOURCE_COMMIT,
        contract_version="gitlab-native-1.2/metadata-v2",
    )
    common = {
        "scope": scope,
        "provenance": provenance,
        "facts": facts,
        "omissions": writer.omissions,
    }
    if kind == "capability":
        return OperationReport(
            **common,
            status="UNSUPPORTED",
            reasons=["GITLAB_CLOUD_MANAGED_API_ONLY"],
            report_type="gitlab_capability",
            native_schema_version="1.4",
        )
    if kind in {"observation", "inventory"}:
        metadata = (
            clean.get("observation", {}).get("metadata", {})
            if kind == "observation"
            else clean.get("metadata", {})
        )
        state, normalized, basis = _state(metadata)
        permissions = _permissions(metadata, writer)
        return EntityObservation(
            **{**common, "omissions": writer.omissions},
            identity=identity(spec, payload["identity"]),
            permissions=permissions,
            provider_state=state,
            normalized_state=normalized,
            state_basis=basis,
        )
    if kind == "asset":
        return EntityObservation(**common, identity=identity(spec, payload, asset=True))
    if kind == "audit":
        interpreted = payload["interpretation"]
        occurred = interpreted.get("created_at")
        if occurred is None:
            try:
                occurred = utc_time(payload.get("metadata", {}).get("created_at")).isoformat()
            except (TypeError, ValueError):
                pass
        if occurred is not None:
            types = payload.get("metadata", {}).get("event_type") or payload.get(
                "metadata", {}
            ).get("event_name")
            event_type = (
                types
                if isinstance(types, str) and 0 < len(types) <= 128
                else interpreted.get("action", "unknown")
            )
            target = identity(spec, payload["identity"]) if payload.get("identity") else None
            actor_id = interpreted.get("actor_id")
            subject = (
                identity(spec, {"kind": "user", "id": actor_id}, asset=True)
                if actor_id is not None
                else None
            )
            return ProviderEvent(
                **common,
                event_id=payload["audit_event_id"],
                event_type=event_type,
                occurred_at=occurred,
                subject=subject,
                target=target,
                match_basis="AUDIT_REFERENCE" if target else "UNKNOWN",
                confidence="EXACT" if target else "UNKNOWN",
            )
        writer.omit("interpretation/created_at", "EVENT_TIME_UNKNOWN")
        return OperationReport(
            **{**common, "omissions": writer.omissions},
            status="PARTIAL",
            reasons=["EVENT_TIME_UNKNOWN"],
            report_type="gitlab_audit_unresolved",
        )
    if kind == "source":
        status = {"complete": "COMPLETE", "failed": "FAILED", "pending": "PARTIAL"}[
            payload["status"]
        ]
        error = payload.get("error") or {}
        params = payload["spec"]["params"]
        return OperationReport(
            **common,
            status=status,
            reasons=[error["code"]] if error else [],
            pages=payload["pages"],
            received_records=payload["records_seen"],
            saved_records=payload.get("audit_event_counts", {}).get(
                "retained", payload["records_seen"]
            ),
            proves_completeness=payload["status"] == "complete"
            and payload["spec"]["handler"]
            in {
                "token_list",
                "resource_list",
                "graphql_triggers",
                "audit_events",
                "subgroups",
                "projects",
                "agents",
                "service_accounts",
            },
            report_type=payload["spec"]["handler"],
            native_schema_version="1.4",
            window_start=params.get("created_after"),
            window_end=params.get("created_before"),
        )
    if kind == "relation":
        credential = identity(spec, payload["identity"])
        person = identity(spec, {"kind": "user", "id": payload["user_id"]}, asset=True)
        owns = payload["relationship"] == "owns"
        return MetadataRelation(
            **common,
            subject=person if owns else credential,
            target=credential if owns else person,
            relation=payload["relationship"],
            match_basis="AUDIT_REFERENCE"
            if payload["state"] == "observed_in_audit"
            else "PROVIDER_EXPLICIT",
            confidence="EXACT",
        )
    return OperationReport(
        **common, status="COMPLETE", report_type="gitlab_" + kind, native_schema_version="1.4"
    )


def relation_payloads(inventory):
    """Only explicit owners and unambiguous creators become graph relationships."""
    for role, relationship in (("owner", "owns"), ("issuer", "created_by")):
        person = inventory["summary"][role]
        if person.get("id") is not None and person["status"] in {"observed", "observed_in_audit"}:
            yield {
                "inventory_id": inventory["inventory_id"],
                "identity": inventory["identity"],
                "observed_scopes": inventory["observed_scopes"],
                "user_id": person["id"],
                "relationship": relationship,
                "evidence": person["evidence"],
                "state": person["status"],
            }


def replay(store, records):
    for item in records:
        operation = item.get("provenance", {}).get("operation", "")
        if item.get("identity", {}).get("origin"):
            store.set_setting("base_url", item["identity"]["origin"])
        if operation.startswith(NATIVE_PREFIX):
            kind = operation[len(NATIVE_PREFIX) :]
            if kind in {"observation", "asset", "audit", "filtered_audit", "source"}:
                payload = unpack_facts(item.get("facts", []))
                store.replay(kind, payload)
                if kind == "source" and payload["spec"]["handler"] in {
                    "audit_plan",
                    "audit_events",
                }:
                    store.set_setting(
                        "config",
                        {**(store.get_setting("config") or {}), "include_audit_events": True},
                    )
        elif operation == "gitlab.run":
            payload = unpack_facts(item.get("facts", []))
            store.set_setting("run_status", item["status"])
            store.set_setting("started_at", payload.get("started_at"))
            store.set_setting("code_provenance", payload.get("code_provenance"))
            store.set_setting("execution_history", payload.get("execution_history", []))
            store.set_setting("coverage_notes", payload.get("warnings", []))
