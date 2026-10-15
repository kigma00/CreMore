"""CI variable metadata and opt-in ephemeral value fingerprints.

The GitLab list API itself returns values, including for a metadata request.
Discard them before normalization; masking/hidden flags are never interpreted
as proof that the API omitted a value or that the value is safe to disclose.
"""

from __future__ import annotations

import hashlib
import re

# Integration: moved from cremore.coverage.providers.facts, whose package import ran the adapter
# registry (every provider) and the coverage store; this module loads neither.
from cremore.coverage.facts import FactWriter, unpack_facts
from cremore.coverage.hasher import hash_value
from cremore.coverage.metadata_models import (
    EntityObservation,
    MetadataValueContract,
    MetadataValueMatch,
    OperationReport,
)

from .extensions import PREFIX, _common, _identity
from .http import CollectionError
from .model import now, stable_id


def validate_context(context):
    if not isinstance(context, dict) or not context.get("engine"):
        raise ValueError("GITLAB_VARIABLE_VALUE_CONTEXT_REQUIRED")
    contract = MetadataValueContract(**{key: context.get(key) for key in (
        "key_id", "engine_digest", "policy_digest")})
    key = context["engine"].config.fingerprint_key
    if not key or len(key) < 32 or hashlib.sha256(key).hexdigest() != contract.key_id:
        raise ValueError("GITLAB_FINGERPRINT_KEY_REQUIRED")
    if context["engine"].detection_digest != contract.engine_digest:
        raise ValueError("GITLAB_ENGINE_CONTRACT_MISMATCH")
    return contract


def reference(scope, row):
    key, environment = row.get("key"), row.get("environment_scope")
    if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_]{1,255}", key):
        raise CollectionError("INVALID_VARIABLE_KEY", "CI 변수의 키가 올바르지 않습니다.")
    if not isinstance(environment, str) or not 1 <= len(environment) <= 255:
        raise CollectionError("INVALID_VARIABLE_ENVIRONMENT", "CI 변수의 환경 범위가 없습니다.")
    digest = stable_id({"key": key, "environment_scope": environment})
    return f"{scope.kind}s/{scope.id}/variables/{digest}"


def observation(spec, scope, row):
    resource = reference(scope, row)
    metadata = {key: row[key] for key in (
        "environment_scope", "variable_type", "protected", "masked", "hidden",
    ) if key in row}
    metadata["name"] = row["key"]
    if "raw" in row:
        metadata["variable_raw"] = row["raw"]
    writer = FactWriter()
    facts = writer.facts(metadata)
    return EntityObservation(
        **_common(spec, scope, "ci_variables", resource, purpose="vault_metadata"),
        identity=_identity(spec, "vault_item", resource), facts=facts, omissions=writer.omissions,
    )


def _match(context, resource, row=None, reason=None):
    arguments = {"reference": resource, "version_state": "CURRENT", "read_at": now(),
                 "key_id": context["key_id"], "engine_digest": context["engine_digest"],
                 "policy_digest": context["policy_digest"]}
    if row is None:
        return MetadataValueMatch(evidence="UNRESOLVED", reason=reason or "VALUE_UNAVAILABLE", **arguments)
    return MetadataValueMatch(
        evidence=row.evidence, credential_type=row.credential_type,
        fingerprint=row.fingerprint, identifier=row.identifier, reason=row.reason,
        provider_digest=getattr(row, "provider_digest", None),
        session_fingerprint=getattr(row, "session_fingerprint", None),
        issuer_identifier=getattr(row, "issuer_identifier", ""), **arguments,
    )


def collect(spec, scope, store, task, body, context):
    seen, reasons = set(), set(task.get("source_reasons", []))
    for item in body:
        # Pop from a local copy before any record/store helper sees this row.
        row = dict(item)
        value = row.pop("value", None)
        entity = observation(spec, scope, row)
        resource = entity.identity.object_id
        if resource in seen:
            raise CollectionError("DUPLICATE_VARIABLE_SCOPE", "변수의 키와 환경 범위가 중복되었습니다.")
        seen.add(resource)
        store.pending.append(("extension", entity.model_dump()))
        if spec.options.include_values:
            matches = []
            if not isinstance(value, str):
                matches = [_match(context, resource, reason="VALUE_UNAVAILABLE")]
            else:
                try:
                    content = value.encode("utf-8")
                    hashed = hash_value(context["engine"], content, {"reference": resource},
                                        max_bytes=1_048_576)
                    del content
                    matches = [_match(context, resource, result) for result in hashed[:25]]
                    if len(hashed) > 25:
                        matches.append(_match(context, resource, reason="VALUE_MATCH_LIMIT_REACHED"))
                except UnicodeError:
                    matches = [_match(context, resource, reason="INVALID_VALUE_ENCODING")]
            for match in matches:
                result = entity.model_copy(deep=True)
                result.provenance.operation = PREFIX + "ci_variable_values"
                result.value_match = match
                store.pending.append(("extension", result.model_dump()))
                if match.evidence == "UNRESOLVED":
                    reasons.add(match.reason)
        del value
    if reasons:
        store._put("tasks", task["id"], {**store.state["tasks"][task["id"]],
                                         "source_reasons": sorted(reasons)})
    return len(body)


def reports(spec, store, context):
    for task in store.state["tasks"].values():
        if task["spec"]["handler"] != "ci_variables":
            continue
        scope = next(scope for scope in spec.scopes if scope.model_dump() == task["spec"]["context"]["scope"])
        reasons = set(task.get("source_reasons", []))
        if task["status"] != "complete":
            reasons.add("VARIABLE_DISCOVERY_INCOMPLETE")
        result = OperationReport(
            **_common(spec, scope, "ci_variable_values" if spec.options.include_values else "ci_variables",
                      task["spec"]["path"], purpose="vault_metadata"),
            status="PARTIAL" if reasons else "COMPLETE", reasons=sorted(reasons),
            pages=task["pages"], received_records=task["records_seen"],
            saved_records=task["records_seen"], proves_completeness=not reasons,
        )
        if spec.options.include_values:
            result.value_access = "PARTIAL" if reasons else "COMPLETE"
            result.value_contract = validate_context(context)
        yield result


def validate_record(spec, item):
    if ("ci_variables" not in spec.options.sources or item.purpose != "vault_metadata"
            or item.scope.kind not in {"group", "project"}):
        return False
    prefix = f"{item.scope.kind}s/{item.scope.id}/variables/"
    if item.record_type == "operation_report":
        return item.provenance.resource_id == "/" + prefix.rstrip("/") and (
            item.provenance.operation == PREFIX + "ci_variable_values"
            if spec.options.include_values else item.value_access == "NOT_REQUESTED")
    if item.record_type != "entity_observation" or item.identity.kind != "vault_item":
        return False
    resource = item.identity.object_id
    if not re.fullmatch(re.escape(prefix) + "[0-9a-f]{64}", resource):
        return False
    facts = unpack_facts([fact.model_dump() for fact in item.facts])
    try:
        expected = reference(item.scope, {"key": facts.get("name"), "environment_scope": facts.get("environment_scope")})
    except CollectionError:
        return False
    if resource != expected or item.provenance.resource_id != resource:
        return False
    if item.value_match is None:
        return item.provenance.operation == PREFIX + "ci_variables"
    return (item.provenance.operation == PREFIX + "ci_variable_values"
            and item.value_match.reference == resource and item.value_match.version == ""
            and item.value_match.version_state == "CURRENT")
