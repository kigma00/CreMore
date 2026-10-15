"""Opt-in Key Vault value comparison; secret bytes stay inside this function."""

from __future__ import annotations

import hashlib
import re

from cremore.coverage.hasher import hash_value
from cremore.coverage.metadata_models import (
    EntityObservation,
    MetadataValueContract,
    MetadataValueMatch,
)

from .normalization import now, observation, provenance, report, secret_name, version_id
from .transport import DEFERRED, ApiError

MAX_SECRET_BYTES = 1_048_576


def validate_context(context):
    if not isinstance(context, dict) or not context.get("engine"):
        raise ValueError("AZURE_KEY_VAULT_VALUE_CONTEXT_REQUIRED")
    contract = MetadataValueContract(**{key: context.get(key) for key in (
        "key_id", "engine_digest", "policy_digest")})
    key = context["engine"].config.fingerprint_key
    if not key or len(key) < 32 or hashlib.sha256(key).hexdigest() != contract.key_id:
        raise ValueError("AZURE_KEY_VAULT_FINGERPRINT_KEY_REQUIRED")
    if contract.engine_digest != context["engine"].detection_digest:
        raise ValueError("AZURE_KEY_VAULT_ENGINE_CONTRACT_MISMATCH")


def _targets(context):
    spec = context["spec"]
    output = {}
    for item in context["records"]:
        if item.get("record_type") != "entity_observation":
            continue
        operation = item.get("provenance", {}).get("operation")
        resource = item.get("provenance", {}).get("resource_id", "")
        if operation not in {"azure.key_vault.secrets", "azure.key_vault.versions"}:
            continue
        if not re.fullmatch(re.escape(spec.origin) + r"/secrets/[A-Za-z0-9-]{1,127}(?:/[A-Za-z0-9]{1,64})?", resource):
            continue
        # The current endpoint is read even when versions are selected. A
        # version listing alone cannot tell which enabled value is current.
        output[resource] = (resource, operation == "azure.key_vault.secrets", item)
    return [output[key] for key in sorted(output)]


def _unread(holder, resource, listed, reason):
    """The listed record, unchanged, carrying why its value was not compared.

    A failed read learns nothing new about the secret, so the listing's state
    and dates stay its summary rather than an attribute-less UNKNOWN."""
    record = EntityObservation.model_validate({
        **listed, "provenance": provenance("azure.key_vault.value_access", resource).model_dump()})
    record.value_match = _match(holder, resource, version_id(resource), False, reason=reason)
    return record


def _match(holder, reference, version, current, row=None, reason=None):
    shared = {"reference": reference, "version": version,
              "version_state": "CURRENT" if current else "UNKNOWN",
              "key_id": holder["key_id"], "engine_digest": holder["engine_digest"],
              "policy_digest": holder["policy_digest"], "read_at": now()}
    if row is None:
        return MetadataValueMatch(evidence="UNRESOLVED", reason=reason or "VALUE_UNAVAILABLE", **shared)
    return MetadataValueMatch(evidence=row.evidence, credential_type=row.credential_type,
                              fingerprint=row.fingerprint, identifier=row.identifier,
                              provider_digest=getattr(row, "provider_digest", None),
                              session_fingerprint=getattr(row, "session_fingerprint", None),
                              issuer_identifier=getattr(row, "issuer_identifier", ""),
                              reason=row.reason, **shared)


def collect_values(context, cursor):
    spec, run, holder = context["spec"], context["run"], context["value_context"]
    targets = _targets(context)
    index = int(cursor.get("index", 0))
    read = int(cursor.get("read", 0))
    errors = set(cursor.get("errors", []))
    if index < 0 or index > len(targets) or read < 0 or read > index:
        raise ValueError("AZURE_KEY_VAULT_CHECKPOINT_MISMATCH")
    while index < len(targets):
        resource, current, listed = targets[index]
        item = {"id": resource}
        reference = resource
        records = []
        try:
            if listed.get("provider_state") == "disabled":
                # Key Vault refuses a GET on a disabled secret with 403; that is the
                # listed state, not a missing permission, so it is not requested.
                raise ApiError("secret_disabled")
            payload = context["transport"].get(resource[len(spec.origin):])
            returned = payload.get("id")
            expected = re.escape(spec.origin + "/secrets/" + secret_name(resource))
            if (not isinstance(returned, str)
                    or not re.fullmatch(expected + r"/[A-Za-z0-9]{1,64}", returned)
                    or (not current and returned != resource)):
                raise ApiError("invalid_identifier")
            value = payload.pop("value", None)
            if not isinstance(value, str):
                raise ApiError("invalid_value_response")
            item = payload
            reference = returned
            try:
                data = value.encode("utf-8")
            except UnicodeError:
                raise ApiError("invalid_value_encoding") from None
            del value
            rows = hash_value(holder["engine"], data, {"reference": reference},
                              max_bytes=MAX_SECRET_BYTES)
            del data
            read += 1
            if len(rows) > 25:
                errors.add("VALUE_MATCH_LIMIT_REACHED")
            for row in rows[:25]:
                record = observation(spec, run.scope, run.vault, item,
                                     operation="azure.key_vault.value_access")
                record.value_match = _match(holder, reference, version_id(reference), current, row)
                records.append(record)
                if row.evidence == "UNRESOLVED":
                    errors.add(row.reason)
        except ApiError as exc:
            if exc.code in DEFERRED:
                raise
            errors.add(exc.code.upper())
            records.append(_unread(holder, resource, listed, exc.code.upper()))
        index += 1
        if index == len(targets):
            records.append(_report(context, len(targets), read, errors))
        yield records, ({"index": index, "read": read, "errors": sorted(errors)}
                        if index < len(targets) else {})
    if not targets:
        yield [_report(context, 0, 0, errors)], {}


def _report(context, total, read, errors):
    spec, run, holder = context["spec"], context["run"], context["value_context"]
    # A failed/partial listing cannot become complete merely because its
    # smaller set of readable values succeeded.
    incomplete = bool(errors or read != total or run.status != "COMPLETE")
    reasons = sorted(errors | ({"METADATA_DISCOVERY_INCOMPLETE"} if run.status != "COMPLETE" else set()))
    result = report(spec, run.scope, "azure.key_vault.value_access",
                    status="PARTIAL" if incomplete else "COMPLETE", reasons=reasons,
                    received=total, saved=read,
                    facts={"selection": "current_and_listed_versions" if "versions" in spec.options.sources
                           else "current_versions", "objects_seen": total})
    result.value_access = "PARTIAL" if incomplete else "COMPLETE"
    result.value_contract = MetadataValueContract(**{name: holder[name] for name in (
        "key_id", "engine_digest", "policy_digest")})
    return result
