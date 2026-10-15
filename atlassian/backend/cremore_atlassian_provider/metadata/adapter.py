"""Common coverage worker adapter; no native connection files or local job store."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from copy import deepcopy
from dataclasses import replace

from cremore.coverage.metadata_models import MetadataConnectionSpec, MetadataPage

from . import bitbucket_dc, bitbucket_dc_replay, replay
from .bitbucket import (
    BRANCH_OPERATIONS,
    CORE_OPERATIONS,
    OPERATIONS,
    RUNNER_OPERATIONS,
    BitbucketClient,
)
from .collector import iter_source
from .connections import valid_workspace
from .discovery import iter_operation
from .http import CloudClient, Limits
from .jobs import iter_job, validate_job
from .metadata import utc_now
from .projection import (
    CONTRACT_VERSION,
    SOURCE_COMMIT,
    project_step,
    record_facts,
    report_record,
    source_key,
)
from .read_operations import ACCOUNT_DETAIL_OPERATIONS, READ_OPERATIONS
from .recollect import validate_task
from .replay import operations_from_records
from .specs import DEFAULT_SOURCES, SOURCES
from .steps import CollectionInterrupted
from .url_safety import contains_unsafe_url

__all__ = [
    "collect_pages",
    "compare_records",
    "current_record_status",
    "native_snapshots",
    "plan_recollection",
    "validate_record",
    "validate_spec",
]

MODE_MAP = {
    "inventory": "cloud-inventory",
    "discovery": "cloud-discovery",
    "accounts": "cloud-accounts",
    "bitbucket": "bitbucket-core",
    "runners": "bitbucket-runners",
    "branch_restrictions": "bitbucket-branches",
}


def _compare_runs(before, after, *, spec, scope_id=None):
    """Retain native chronology and optional scope selection for both products."""
    if getattr(spec, "edition", "cloud") == "data_center":
        return bitbucket_dc_replay.compare_records(before, after, spec=spec, scope_id=scope_id)
    return compare_records(before, after, scope_id=scope_id)


def _native_records(records):
    records = list(records)
    dc = any((r.model_dump() if hasattr(r, "model_dump") else r)
             .get("provenance", {}).get("contract_version") == bitbucket_dc.CONTRACT for r in records)
    return records, bitbucket_dc_replay if dc else replay


def native_snapshots(records):
    records, native = _native_records(records)
    return native.native_snapshots(records)


def compare_records(before_records, after_records, *, scope_id=None):
    before_records, before = _native_records(before_records)
    after_records, after = _native_records(after_records)
    if before is not after:
        raise ValueError("ATLASSIAN_COMPARE_EDITION_MISMATCH")
    return before.compare_records(before_records, after_records, scope_id=scope_id)


def plan_recollection(records, *, scope_id=None, operations=None, include_unverified=False):
    records, native = _native_records(records)
    return native.plan_recollection(records, scope_id=scope_id,
                                   operations=operations, include_unverified=include_unverified)


def allowed_operations(spec):
    if spec.edition == "data_center":
        return {bitbucket_dc.OPERATIONS[scope.kind] for scope in spec.scopes}
    mode = spec.options.mode
    if mode == "inventory":
        return set(spec.options.sources or DEFAULT_SOURCES)
    if mode == "accounts":
        return {"managed-accounts", *ACCOUNT_DETAIL_OPERATIONS}
    if mode == "discovery":
        return set(READ_OPERATIONS) - (
            set()
            if spec.options.include_account_reads
            else {"managed-accounts", *ACCOUNT_DETAIL_OPERATIONS}
        )
    if mode == "runners":
        return {"repositories", *RUNNER_OPERATIONS}
    if mode == "branch_restrictions":
        return {"repositories", *BRANCH_OPERATIONS}
    return set(CORE_OPERATIONS)


def validate_spec(spec):
    if spec.edition == "data_center":
        return bitbucket_dc.validate_spec(spec)
    if spec.options.api_path:
        raise ValueError("ATLASSIAN_CLOUD_CONTEXT_PATH_NOT_SUPPORTED")
    cloud = spec.provider == "atlassian"
    if spec.provider not in {"atlassian", "bitbucket"} or spec.edition not in {
        "cloud",
        "enterprise_cloud",
    }:
        raise ValueError("ATLASSIAN_EDITION_NOT_SUPPORTED")
    if spec.origin != ("https://api.atlassian.com" if cloud else "https://api.bitbucket.org"):
        raise ValueError("ATLASSIAN_ORIGIN_NOT_SUPPORTED")
    allowed_modes = (
        {"inventory", "discovery", "accounts"}
        if cloud
        else {"bitbucket", "runners", "branch_restrictions"}
    )
    if spec.options.mode not in allowed_modes or "inventory" not in spec.capabilities:
        raise ValueError("ATLASSIAN_INVALID_METADATA_MODE")
    if (
        set(spec.capabilities) - {"inventory", "relations", "policy", "public_keys"}
        or spec.options.include_values
        or spec.options.include_actions
    ):
        raise ValueError("ATLASSIAN_CAPABILITY_NOT_SUPPORTED")
    if spec.auth_type not in ({"bearer"} if cloud else {"bearer", "basic"}):
        raise ValueError("ATLASSIAN_AUTHENTICATION_NOT_SUPPORTED")
    required = {"username", "password"} if spec.auth_type == "basic" else {"token"}
    if set(spec.secret_refs) != required:
        raise ValueError("ATLASSIAN_SECRET_ROLES_REQUIRED")
    if spec.options.sources and (
        spec.options.mode != "inventory" or set(spec.options.sources) - set(SOURCES)
    ):
        raise ValueError("ATLASSIAN_INVALID_SOURCES")
    for scope in spec.scopes:
        if scope.kind != ("organization" if cloud else "workspace"):
            raise ValueError("ATLASSIAN_INVALID_ROOT_SCOPE")
        if cloud:
            try:
                valid = str(uuid.UUID(scope.id)) == scope.id
            except ValueError:
                valid = False
        else:
            valid = valid_workspace(scope.id)
        if not valid:
            raise ValueError("ATLASSIAN_INVALID_ROOT_SCOPE")


def validate_record(spec, record):
    if spec.edition == "data_center":
        return bitbucket_dc.validate_record(spec, record)
    # This adapter emits observations and reports only. An outer row context
    # does not authorize arbitrary relation or event endpoints.
    if record.record_type not in {"entity_observation", "operation_report"}:
        return False
    try:
        validate_spec(spec)
        if (
            record.scope not in spec.scopes
            or record.provenance.contract_version != CONTRACT_VERSION
            or record.provenance.source_commit != SOURCE_COMMIT
        ):
            return False
        values = record_facts(record)
        if contains_unsafe_url(values):
            return False
        context = values.get("context", {})
        stage = context.get("stage")
        from .field_contract import (
            CONTEXT_FIELDS,
            PAGE_FIELDS,
            REPORT_FIELDS,
            SUMMARY_FIELDS,
            filter_response,
            valid_internal,
            valid_normalized,
        )

        if not isinstance(context, dict) or set(context) - CONTEXT_FIELDS:
            return False
        if set(values) - {"context", "metadata", "fields", "public_key"}:
            return False
        if stage == "run_summary":
            header = values.get("metadata")
            if (
                not isinstance(header, dict)
                or set(header) - SUMMARY_FIELDS
                or not valid_internal(header)
            ):
                return False
            if (
                header.get("provider") != "atlassian"
                or header.get("inventory_complete") is not False
                or header.get("queried_org_id", header.get("workspace")) != record.scope.id
            ):
                return False
            return (
                record.provenance.operation == "atlassian-summary"
                and record.record_type == "operation_report"
                and context.get("mode") == spec.options.mode
            )
        operation = context.get("operation")
        if operation not in allowed_operations(spec) or operation != record.provenance.operation:
            return False
        if stage not in {"row", "normalized", "detail", "page_header", "operation_complete"}:
            return False
        if (
            type(context.get("attempt")) is not int
            or context["attempt"] < 1
            or type(context.get("page_number")) is not int
            or context["page_number"] < 0
        ):
            return False
        if (
            context.get("source")
            != source_key(operation, context.get("target_id"), context.get("requested_account_ids"))
            or record.provenance.resource_id != context["source"]
        ):
            return False
        specs = READ_OPERATIONS if spec.provider == "atlassian" else OPERATIONS
        validate_task(operation, context, specs, record.scope.id)
        metadata = values.get("metadata")
        if stage in {"operation_complete", "page_header"}:
            allowed = (
                REPORT_FIELDS
                if stage == "operation_complete" or spec.options.mode == "inventory"
                else PAGE_FIELDS
            )
            if (
                not isinstance(metadata, dict)
                or set(metadata) - allowed
                or not valid_internal(metadata)
            ):
                return False
        if stage == "page_header" and spec.options.mode != "inventory":
            value = values.get("fields", values.get("public_key"))
            if filter_response(spec.provider, operation, value) != value:
                return False
        if stage in {"row", "detail"} and (
            filter_response(
                spec.provider,
                operation,
                metadata,
                row=stage == "row",
                container=context.get("container_name"),
            )
            != metadata
        ):
            return False
        from .projection import decode_observation, identity_for

        row = values.get("metadata")
        if stage == "normalized":
            row = decode_observation(row)
            if not valid_normalized(row, operation):
                return False
        if record.record_type == "entity_observation":
            identity = identity_for(
                spec,
                record.scope,
                operation,
                row,
                context.get("target_id"),
                normalized=stage == "normalized",
            )
            if identity != record.identity:
                return False
        return True
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def configuration_hash(spec):
    # Revisions/sealed references can rotate independently; scope and read
    # behavior remain the comparison contract. Authentication role is included.
    value = spec.model_dump(exclude={"name", "secret_refs", "freshness_hours"})
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def current_record_status(spec, body, reports):
    """Status for this source's one terminal attempt; abandoned rows stay history."""
    if spec.edition == "data_center":
        return bitbucket_dc.current_record_status(spec, body, reports)
    if body.get("record_type") != "entity_observation":
        return None
    context = record_facts(body).get("context", {})
    latest = None
    for value in reports:
        report = value.model_dump() if hasattr(value, "model_dump") else value
        if report.get("scope") != body.get("scope"):
            continue
        facts = record_facts(report)
        report_context = facts.get("context", {})
        if report_context.get("stage") != "operation_complete" or report_context.get(
            "source"
        ) != context.get("source"):
            continue
        if latest is None or report_context["attempt"] > latest[0]:
            latest = (report_context["attempt"], facts.get("metadata", {}).get("coverage"))
    if latest is None or context.get("attempt") != latest[0]:
        return None
    return "COMPLETE" if latest[1] == "complete" and not body.get("omissions") else "PARTIAL"


def _job(spec, scope):
    mode = spec.options.mode
    limits = Limits(
        max_pages=min(spec.max_pages, 1000),
        max_records=min(spec.max_records, 100000),
        max_requests=min(spec.max_requests, 1000),
        timeout=min(spec.options.timeout_seconds, 30),
        retries=min(spec.options.max_retries, 5),
    )
    from dataclasses import asdict

    job = {
        "name": "coverage",
        "profile": "coverage",
        "mode": MODE_MAP[mode],
        "expected_scope": scope.id,
        "limits": asdict(limits),
        "max_targets": spec.options.max_targets,
        "page_size": 20
        if mode in {"inventory", "accounts"}
        else min(spec.options.page_size, 1000 if mode == "discovery" else 100),
    }
    if mode == "inventory" and spec.options.sources:
        job["sources"] = list(spec.options.sources)
    if mode == "discovery":
        job["include_account_reads"] = spec.options.include_account_reads
    return validate_job(job), limits


def _client(spec, scope, secrets, limits, check):
    if spec.provider == "atlassian":
        return CloudClient(
            scope.id,
            secrets["token"],
            limits,
            token_page_size=min(spec.options.page_size, 1000),
            check=check,
        )
    return BitbucketClient(
        scope.id,
        secrets["password" if spec.auth_type == "basic" else "token"],
        limits,
        page_size=min(spec.options.page_size, 100),
        auth_type=spec.auth_type,
        email=secrets.get("username") if spec.auth_type == "basic" else None,
        check=check,
    )


def _recollect_iterator(client, plan, *, now):
    reports = []
    specs = READ_OPERATIONS if plan["job"]["mode"].startswith("cloud-") else OPERATIONS
    for task in plan["tasks"]:
        validate_task(task["operation"], task, specs, plan["job"]["expected_scope"])
        if plan["job"]["mode"] == "cloud-inventory":
            report, _ = yield from iter_source(client, task["operation"], now=now)
            reports.append({**report, "operation": task["operation"]})
            continue
        reports.append(
            (
                yield from iter_operation(
                    client,
                    task["operation"],
                    identifier=task["target_id"],
                    body=task["requested_account_ids"],
                    specs=specs,
                    now=now,
                )
            )
        )
    return reports


def _record_batches(records):
    batch, size = [], 0
    for record in records:
        length = len(record.model_dump_json().encode())
        if batch and (len(batch) >= 100 or size + length > 1_700_000):
            yield batch
            batch, size = [], 0
        if length > 1_900_000:
            raise ValueError("ATLASSIAN_TYPED_RECORD_LIMIT")
        batch.append(record)
        size += length
    if batch:
        yield batch


def collect_pages(
    spec: MetadataConnectionSpec,
    *,
    secrets,
    checkpoint,
    check,
    read_records=None,
    client_factory=None,
    now=utc_now,
    recollection_plan=None,
):
    """Read each page outside DB transactions, publish, then continue the generator.

    The caller commits records/checkpoint atomically. A restart uses only complete
    typed operation attempts; interrupted reads start at page one in a new attempt.
    """
    validate_spec(spec)
    if spec.edition == "data_center":
        yield from bitbucket_dc.collect_pages(
            spec, secrets=secrets, checkpoint=checkpoint, check=check, read_records=read_records,
            client_factory=client_factory, now=now, recollection_plan=recollection_plan)
        return
    if spec.principal_pin:
        raise ValueError("ATLASSIAN_PRINCIPAL_PIN_UNVERIFIABLE")
    required = {"username", "password"} if spec.auth_type == "basic" else {"token"}
    if not required <= set(secrets):
        raise ValueError("ATLASSIAN_SECRET_ROLES_REQUIRED")
    config_hash = configuration_hash(spec)
    execution_scopes = spec.scopes
    recollection_hash = None
    if recollection_plan is not None:
        if recollection_plan.get("report_type") != "metadata_recollection_plan":
            raise ValueError("ATLASSIAN_INVALID_RECOLLECTION_PLAN")
        execution_scopes = [
            scope for scope in spec.scopes if scope.id == recollection_plan["job"]["expected_scope"]
        ]
        if len(execution_scopes) != 1:
            raise ValueError("ATLASSIAN_RECOLLECTION_SCOPE_MISMATCH")
        recollection_hash = hashlib.sha256(
            json.dumps(recollection_plan, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    if checkpoint and (
        checkpoint.get("provider") != spec.provider
        or checkpoint.get("config_hash") != config_hash
        or checkpoint.get("version") != 1
        or checkpoint.get("recollection_hash") != recollection_hash
    ):
        raise ValueError("ATLASSIAN_CHECKPOINT_MISMATCH")
    attempt = checkpoint.get("attempt", 0) + 1
    if type(attempt) is not int or not 1 <= attempt <= 10000:
        raise ValueError("ATLASSIAN_INVALID_ATTEMPT")
    committed = list(read_records()) if read_records else []
    if checkpoint and not read_records:
        raise ValueError("ATLASSIAN_COMMITTED_RECORD_READER_REQUIRED")
    started = checkpoint.get("started_at", now())
    start_scope = checkpoint.get("scope_index", 0)
    state = {
        "version": 1,
        "provider": spec.provider,
        "config_hash": config_hash,
        "attempt": attempt,
        "started_at": started,
        "scope_index": start_scope,
        "requests": checkpoint.get("requests", 0),
        "recollection_hash": recollection_hash,
    }
    overall = checkpoint.get("status", "COMPLETE")
    seen_success = checkpoint.get("seen_success", False)
    projection_omissions = checkpoint.get("projection_omissions", False)
    # Page checkpoints inside a scope carry the earlier scopes' outcome, so a second resume keeps it.
    state.update(status=overall, seen_success=seen_success)
    factory = client_factory or _client
    deadline = time.monotonic() + 120
    try:
        for scope_index in range(start_scope, len(execution_scopes)):
            check()
            scope = execution_scopes[scope_index]
            job, limits = _job(spec, scope)
            client = factory(spec, scope, secrets, limits, check)
            client.restrict_time(max(0, deadline - time.monotonic()))
            # Global requests include attempts already durably observed.
            requests_before = state["requests"]
            client.requests = requests_before
            completed = operations_from_records(committed, scope, complete_only=True)
            source_omissions = {}

            def cached(
                operation, *, identifier=None, body=None, completed=completed, client=client
            ):
                value = completed.get(source_key(operation, identifier, body))
                if value is None:
                    return None
                report, observations = deepcopy(value)
                if hasattr(client, "runner_identities"):
                    for page in (
                        report.get("pages", []) if isinstance(report.get("pages"), list) else []
                    ):
                        client.runner_identities.observe(operation, page["metadata"])
                return (report, observations) if spec.options.mode == "inventory" else report

            client.completed_report = cached
            iterator = iter_job(job, client, now=now)
            if recollection_plan is not None:
                if (
                    recollection_plan["job"]["expected_scope"] != scope.id
                    or recollection_plan["job"]["mode"] != job["mode"]
                ):
                    raise ValueError("ATLASSIAN_RECOLLECTION_SCOPE_MISMATCH")
                if recollection_plan.get("report_type") != "metadata_recollection_plan" or any(
                    task.get("operation") not in allowed_operations(spec)
                    for task in recollection_plan["tasks"]
                ):
                    raise ValueError("ATLASSIAN_RECOLLECTION_OPERATION_MISMATCH")
                iterator = _recollect_iterator(client, recollection_plan, now=now)
            while True:
                check()
                try:
                    event = next(iterator)
                except StopIteration as end:
                    result = end.value
                    break
                source = source_key(
                    event.operation,
                    event.report.get("target_id"),
                    event.report.get("requested_account_ids"),
                )
                if event.completed and source_omissions.get(source):
                    event = replace(
                        event,
                        report={
                            **event.report,
                            "coverage": "unverified",
                            "reason": "typed_projection_omissions",
                        },
                    )
                records = project_step(spec, scope, event, attempt)
                omitted = any(record.omissions for record in records)
                source_omissions[source] = source_omissions.get(source, False) or omitted
                projection_omissions |= omitted
                state.update(
                    scope_index=scope_index,
                    requests=client.requests,
                    projection_omissions=projection_omissions,
                )
                for batch in _record_batches(records):
                    check()
                    yield MetadataPage(records=batch, checkpoint=deepcopy(state))
            if recollection_plan is not None:
                # Selected recollection stays a selected-read view. It cannot
                # establish completion of the previous full inventory.
                result = {
                    "schema_version": 3 if spec.options.mode == "inventory" else 1,
                    "report_type": (
                        "inventory"
                        if spec.options.mode == "inventory"
                        else "managed_account_metadata_discovery"
                        if spec.options.mode == "accounts"
                        else "metadata_discovery"
                    )
                    if spec.provider == "atlassian"
                    else "bitbucket_metadata_discovery",
                    "collection_mode": {
                        "bitbucket": "core",
                        "runners": "runners",
                        "branch_restrictions": "branch_restrictions",
                    }.get(spec.options.mode),
                    "provider": "atlassian",
                    "environment": "cloud" if spec.provider == "atlassian" else "bitbucket_cloud",
                    "queried_org_id": scope.id,
                    "workspace": scope.id,
                    "connection_profile": "coverage",
                    "started_at": started,
                    "finished_at": now(),
                    "inventory_complete": False,
                    "run_status": "unverified",
                    "collections": result,
                    "source_reasons": [
                        "SELECTED_READS_ONLY",
                        "NEW_OBSERVATION_WINDOW",
                        "SOURCE_SNAPSHOT_UNCHANGED",
                        "NO_NEW_TARGET_FANOUT",
                    ],
                }
            result["started_at"] = started
            summary = {
                name: value
                for name, value in result.items()
                if name not in {"collections", "inventory", "warning_counts"}
            }
            # Dynamic warning names are normalized into explicit name/count pairs.
            if "warning_counts" in result:
                summary["warning_counts"] = [
                    {"name": key, "count": value} for key, value in result["warning_counts"].items()
                ]
            record = report_record(
                spec,
                scope,
                "atlassian-summary",
                {
                    "stage": "run_summary",
                    "mode": spec.options.mode,
                    "attempt": attempt,
                    "config_hash": config_hash,
                },
                {"metadata": summary},
                native={"coverage": result["run_status"]},
                observed_at=result["finished_at"],
            )
            projection_omissions |= bool(record.omissions)
            seen_success |= result["run_status"] != "failed"
            if result["run_status"] != "complete":
                overall = "PARTIAL" if seen_success or overall == "PARTIAL" else "FAILED"
            elif overall == "FAILED":
                overall = "PARTIAL"
            state.update(
                scope_index=scope_index + 1,
                requests=client.requests,
                status=overall,
                seen_success=seen_success,
                projection_omissions=projection_omissions,
            )
            check()
            yield MetadataPage(records=[record], checkpoint=deepcopy(state))
        if projection_omissions:
            overall = "PARTIAL"
        check()
        yield MetadataPage(
            checkpoint=deepcopy(state),
            status=overall,
            reasons=["METADATA_PROJECTION_OMISSIONS"] if projection_omissions else [],
        )
    except CollectionInterrupted as interrupted:
        raise interrupted.cause from None
