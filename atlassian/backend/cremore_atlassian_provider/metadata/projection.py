"""Typed common-storage projection of the teammate's metadata observations.

Only named metadata fields cross this boundary. Unknown names and rejected
values become explicit omissions; they never become a serialized payload.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from urllib.parse import quote

from pydantic import ValidationError

from cremore.coverage.metadata_models import (
    FACT_NAMES,
    EntityIdentity,
    EntityObservation,
    FieldCatalogEntry,
    MetadataFact,
    MetadataOmission,
    MetadataProvenance,
    OperationReport,
    RecordQuality,
)

from .bitbucket import OPERATIONS
from .discovery import collection_records
from .identities import BITBUCKET_IDS, CLOUD_IDS, record_identity
from .metadata import normalize, utc_now
from .read_operations import READ_OPERATIONS
from .specs import SOURCES
from .url_safety import unsafe_url

SOURCE_COMMIT = "49abdc11a998f61917e151ab276e84c7a21815ea"
CONTRACT_VERSION = "atlassian-common-v1"
STATUS = {
    "complete": "COMPLETE",
    "partial": "PARTIAL",
    "failed": "FAILED",
    "unverified": "UNKNOWN",
    "not_requested": "NOT_REQUESTED",
}


def source_key(operation, target=None, account_ids=None):
    value = [operation, target, account_ids]
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _fact(name, value, omissions, *, depth=1, budget=None):
    if isinstance(value, tuple):
        value = list(value)
    budget = [1800] if budget is None else budget
    if depth > 6 or budget[0] <= 0:
        omissions.append(MetadataOmission(path="/metadata", reason="METADATA_FACT_LIMIT"))
        return MetadataFact(name=name, state="INVALID", reason="METADATA_FACT_LIMIT")
    budget[0] -= 1
    if isinstance(value, dict) and "_cremore_omitted" in value:
        reason = (
            "SENSITIVE_VALUE_OMITTED"
            if value["_cremore_omitted"] == "sensitive_value"
            else "METADATA_OMITTED"
        )
        omissions.append(MetadataOmission(path="/metadata", reason=reason))
        return MetadataFact(name=name, state="INVALID", reason=reason)
    if value is None:
        return MetadataFact(name=name, state="NULL")
    if unsafe_url(value):
        omissions.append(MetadataOmission(path="/metadata", reason="URL_CREDENTIALS_OMITTED"))
        return MetadataFact(name=name, state="INVALID", reason="URL_CREDENTIALS_OMITTED")
    if isinstance(value, (dict, list)):
        children = []
        items = value.items() if isinstance(value, dict) else (("entry", child) for child in value)
        for key, child in items:
            if key not in FACT_NAMES:
                omissions.append(
                    MetadataOmission(path="/metadata/*", reason="UNAPPROVED_METADATA_FIELD")
                )
                continue
            if len(children) >= 500 or budget[0] <= 0:
                omissions.append(MetadataOmission(path="/metadata", reason="METADATA_FACT_LIMIT"))
                break
            children.append(_fact(key, child, omissions, depth=depth + 1, budget=budget))
        return MetadataFact(
            name=name, container="object" if isinstance(value, dict) else "array", children=children
        )
    try:
        return MetadataFact(name=name, value=value)
    except ValidationError:
        omissions.append(MetadataOmission(path="/metadata", reason="UNSAFE_OR_INVALID_METADATA"))
        return MetadataFact(name=name, state="INVALID", reason="UNSAFE_OR_INVALID_METADATA")


def facts(values):
    omissions, budget = [], [1800]
    result = [_fact(name, value, omissions, budget=budget) for name, value in values.items()]
    # Omission counts can be high on a response with an unknown schema. The
    # reason is preserved once, without copying attacker-controlled field names.
    unique = {(item.path, item.reason): item for item in omissions}
    return result, list(unique.values())


def decode_fact(fact):
    if hasattr(fact, "model_dump"):
        fact = fact.model_dump()
    state = fact.get("state", "PRESENT")
    if state in ("MISSING", "INVALID"):
        return {
            "_cremore_omitted": "sensitive_value"
            if fact.get("reason") == "SENSITIVE_VALUE_OMITTED"
            else "typed_projection"
        }
    if state == "NULL":
        return None
    if fact.get("container") == "array":
        return [decode_fact(child) for child in fact.get("children", [])]
    if fact.get("container") == "object" or fact.get("children"):
        return {child["name"]: decode_fact(child) for child in fact.get("children", [])}
    return fact.get("value")


def record_facts(record):
    if hasattr(record, "model_dump"):
        record = record.model_dump()
    return {fact["name"]: decode_fact(fact) for fact in record.get("facts", [])}


def encode_observation(value):
    value = deepcopy(value)
    value["fields"] = [{"name": name, "metadata": field} for name, field in value["fields"].items()]
    return value


def decode_observation(value):
    value = deepcopy(value)
    value["fields"] = {entry["name"]: entry["metadata"] for entry in value["fields"]}
    return value


def _family(operation, row):
    mapped = {
        "service-account-api-tokens-by-account": "service-account-api-tokens",
        "service-account-oauth-clients-by-account": "service-account-oauth-clients",
        "user-api-tokens": "org-api-tokens",
    }.get(operation, operation)
    if mapped in SOURCES:
        item = normalize(mapped, row, utc_now(), allow_service_oauth_variant=True)
        return "credential", item["record_contract"] if item else SOURCES[mapped]["kind"]
    if "oauth-client" in operation:
        return "credential", "oauth_client"
    if "branch-restriction" in operation or operation == "user-management-permissions":
        return "policy", operation.removesuffix("-detail").removesuffix("s")
    if "runner" in operation:
        return "runner", operation.removesuffix("-detail").removesuffix("s")
    if any(
        part in operation
        for part in ("ssh-key", "gpg-key", "deploy-key", "known-host", "oidc-keys")
    ):
        return "public_key", operation.removesuffix("-detail").removesuffix("s")
    if "oidc-configuration" in operation:
        return "trust", "oidc_configuration"
    if operation in (
        "service-accounts",
        "managed-accounts",
        "current-user",
        "user-profile",
        "workspace-members",
    ):
        return "principal", "account"
    family = {"repositories": "repository", "projects": "project"}.get(
        operation, operation.removesuffix("-detail")
    )
    return "resource", family


def identity_for(spec, scope, operation, row, target=None, *, normalized=False):
    if normalized:
        field = SOURCES[operation]["id_field"]
        identity = record_identity({"id": row["fields"][field].get("value")}, ("id",))
        kind, family = "credential", row["record_contract"]
    else:
        if not isinstance(row, dict):
            return None
        fields = (BITBUCKET_IDS if spec.provider == "bitbucket" else CLOUD_IDS).get(
            operation, ("uuid", "account_id", "id", "clientId")
        )
        identity = record_identity(row, fields)
        kind, family = _family(operation, row)
    if identity is None:
        return None
    value = identity["value"]
    parent = target[0] if isinstance(target, (tuple, list)) else target
    contextual = (
        "deploy-key" in operation
        or "known-host" in operation
        or "branch-restriction" in operation
        or "runner" in operation
    )
    pieces = [
        scope.kind,
        scope.id,
        family,
        str(parent or "") if contextual else "",
        type(value).__name__,
        str(value),
    ]
    object_id = "/".join(quote(piece, safe="") for piece in pieces)
    try:
        return EntityIdentity(
            provider=spec.provider,
            origin=spec.origin,
            tenant=spec.tenant,
            tenant_confirmed=spec.tenant_confirmed,
            kind=kind,
            object_id=object_id,
        )
    except ValidationError:
        return None


def _catalog(value):
    entries = []
    mapping = {
        "str": "string",
        "int": "integer",
        "float": "number",
        "bool": "boolean",
        "dict": "object",
        "list": "array",
        "null": "null",
    }
    for path, types in value.items():
        if any(
            part not in FACT_NAMES and part != "[]" and not part.isdecimal()
            for part in path.strip("/").split("/")
            if part
        ):
            continue
        try:
            entry = FieldCatalogEntry(
                path=path or "/",
                types=list(dict.fromkeys(mapping.get(t, "invalid") for t in types)),
            )
        except ValidationError:
            continue
        entries.append(entry)
        if len(entries) == 512:
            break
    return entries


def _base(spec, scope, operation, context, values, *, observed_at=None):
    values = {"context": context, **values}
    projected, omissions = facts(values)
    return {
        "scope": scope,
        "provenance": MetadataProvenance(
            operation=operation,
            observed_at=observed_at or utc_now(),
            resource_id=context.get("source", ""),
            source_commit=SOURCE_COMMIT,
            contract_version=CONTRACT_VERSION,
        ),
        "facts": projected,
        "omissions": omissions,
    }


def report_record(
    spec, scope, operation, context, values, *, native=None, observed_at=None, catalog=None
):
    native = native or {}
    base = _base(spec, scope, operation, context, values, observed_at=observed_at)
    quality = native.get("record_quality", {})
    quality = {name: value for name, value in quality.items() if name in RecordQuality.model_fields}
    reason = native.get("reason")
    reasons = [reason.upper()] if reason else []
    header = values.get("metadata", {}) if context["stage"] == "run_summary" else {}
    return OperationReport(
        **base,
        status=STATUS.get(native.get("coverage"), "PARTIAL"),
        reasons=reasons,
        pages=native.get("page_count", 0),
        received_records=native.get("received_records", 0),
        saved_records=native.get("saved_records", native.get("accepted_records", 0)),
        record_quality=RecordQuality(**quality),
        field_catalog=_catalog(catalog or {}),
        native_schema_version="3" if spec.options.mode == "inventory" else "1",
        report_type=header.get("report_type", "inventory") if header else context["stage"],
        collection_mode=spec.options.mode,
        window_start=header.get("started_at"),
        window_end=header.get("finished_at"),
    )


def _row_record(spec, scope, operation, context, row, *, observed_at, normalized=False):
    value = encode_observation(row) if normalized else row
    base = _base(spec, scope, operation, context, {"metadata": value}, observed_at=observed_at)
    identity = identity_for(
        spec, scope, operation, row, context.get("target_id"), normalized=normalized
    )
    if identity is None:
        return OperationReport(
            **base,
            status="UNKNOWN",
            reasons=["NO_STABLE_ENTITY_ID"],
            report_type=context["stage"],
            collection_mode=spec.options.mode,
        )
    status = (
        row.get("fields", {}).get("status", {}).get("value") if normalized else row.get("status")
    )
    status = status if isinstance(status, str) and len(status) <= 64 else "UNKNOWN"
    try:
        return EntityObservation(
            **base,
            identity=identity,
            provider_state=status,
            normalized_state=status.upper()
            if status.upper()
            in {"ACTIVE", "INACTIVE", "EXPIRED", "REVOKED", "DELETED", "DISABLED", "PENDING"}
            else "UNKNOWN",
            state_basis="PROVIDER_REPORTED" if status != "UNKNOWN" else "UNKNOWN",
        )
    except ValidationError:
        return EntityObservation(**base, identity=identity)


def project_step(spec, scope, event, attempt):
    report, operation = event.report, event.operation
    context = {
        "source": source_key(
            operation, report.get("target_id"), report.get("requested_account_ids")
        ),
        "attempt": attempt,
        "operation": operation,
        "page_number": report.get("page_count", 0),
        **{name: report[name] for name in ("target_id", "requested_account_ids") if name in report},
    }
    if event.completed:
        return [
            report_record(
                spec,
                scope,
                operation,
                {**context, "stage": "operation_complete"},
                {"metadata": report},
                native=report,
            )
        ]
    if spec.options.mode == "inventory":
        rows = [
            _row_record(
                spec,
                scope,
                operation,
                {**context, "stage": "normalized", "row_index": index},
                row,
                observed_at=row["observed_at"],
                normalized=True,
            )
            for index, row in enumerate(event.observations)
        ]
        rows.append(
            report_record(
                spec,
                scope,
                operation,
                {**context, "stage": "page_header"},
                {"metadata": report},
                native=report,
            )
        )
        return rows
    page = event.page
    from .field_contract import filter_response

    page = {**page, "metadata": filter_response(spec.provider, operation, page["metadata"])}
    specs = OPERATIONS if spec.provider == "bitbucket" else READ_OPERATIONS
    rows, container = collection_records(specs[operation], page["metadata"])
    context["container_name"] = (container or "array") if rows is not None else "scalar"
    header = {
        name: value for name, value in page.items() if name not in ("metadata", "field_types")
    }
    body = deepcopy(page["metadata"])
    if rows is not None:
        if container:
            body.pop(container, None)
        else:
            body = None
    body_name = (
        "public_key"
        if isinstance(body, str) and body.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        else "fields"
    )
    output = [
        report_record(
            spec,
            scope,
            operation,
            {**context, "stage": "page_header"},
            {"metadata": header, body_name: body},
            native=report,
            observed_at=page["observed_at"],
            catalog=page.get("field_types"),
        )
    ]
    if rows is not None:
        output.extend(
            _row_record(
                spec,
                scope,
                operation,
                {**context, "stage": "row", "row_index": index},
                row,
                observed_at=page["observed_at"],
            )
            for index, row in enumerate(rows)
        )
    elif (
        isinstance(body, dict)
        and identity_for(spec, scope, operation, body, context.get("target_id")) is not None
    ):
        # Keep a typed dashboard observation for a detail response. The page
        # header remains the sole source used to reconstruct its native report.
        output.append(
            _row_record(
                spec,
                scope,
                operation,
                {**context, "stage": "detail"},
                body,
                observed_at=page["observed_at"],
            )
        )
    return output
