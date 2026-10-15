"""Checkpointed Notion PAT and MCP inventories inside explicit workspace scopes."""

from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from datetime import UTC, datetime

from cremore.coverage.metadata_models import (
    RECORD_ADAPTER,
    MetadataConnectionSpec,
    MetadataPage,
    checkpoint_json,
    in_metadata_scope,
)
from cremore.coverage.models import digest

from . import API_VERSION, CONTRACT_VERSION, ORIGIN, SOURCES
from .normalization import observation, operation, record_values, report, resource, uuid_text
from .transport import ReadError, Transport, cursor_text

_COUNTS = ("task", "requests", "pages", "records", "retries", "op_pages", "received", "saved",
           "invalid", "duplicates")
_HASH = re.compile(r"[0-9a-f]{64}")
_REASONS = {"NOTION_INVALID_RECORD", "NOTION_METADATA_OMITTED", "NOTION_DUPLICATE_RECORD",
            "NOTION_CURSOR_CYCLE", "NOTION_CURSOR_HISTORY_LIMIT", "PAGE_BUDGET_EXCEEDED",
            "RECORD_BUDGET_EXCEEDED", "REQUEST_BUDGET_EXCEEDED", "NOTION_RETRY_LIMIT",
            "NOTION_RESPONSE_LIMIT", "NOTION_UNAVAILABLE", "NOTION_RATE_LIMITED",
            "NOTION_INVALID_RESPONSE", "NOTION_PAGE_SIZE_EXCEEDED", "NOTION_INVALID_CURSOR",
            "NOTION_WORKSPACE_UNVERIFIED"}


def _reason(value):
    return isinstance(value, str) and (value in _REASONS or bool(re.fullmatch(r"NOTION_HTTP_[1-5][0-9]{2}", value)))


def validate_spec(spec):
    if spec.provider != "notion" or spec.edition != "cloud" or spec.origin != ORIGIN:
        raise ValueError("NOTION_ENTERPRISE_CLOUD_REQUIRED")
    if spec.auth_type != "bearer" or set(spec.secret_refs) != {"token"}:
        raise ValueError("NOTION_ORGANIZATION_BOT_REFERENCE_REQUIRED")
    if set(spec.capabilities) != {"inventory"}:
        raise ValueError("NOTION_INVENTORY_CAPABILITY_REQUIRED")
    if spec.principal_pin is not None:
        raise ValueError("NOTION_ADMIN_PRINCIPAL_PIN_UNVERIFIABLE")
    for scope in spec.scopes:
        if scope.kind != "workspace":
            raise ValueError("NOTION_WORKSPACE_SCOPE_REQUIRED")
        uuid_text(scope.id)
    if (spec.options.mode != "inventory" or spec.options.page_size > 100
            or spec.options.include_values
            or spec.options.include_audit_events or spec.options.include_actions
            or spec.options.locations or spec.options.include_deleted
            or spec.options.audit_created_after or spec.options.audit_lookback_days
            or set(spec.options.sources) - set(SOURCES)):
        raise ValueError("NOTION_COLLECTION_OPTION_NOT_SUPPORTED")


def _enabled(spec, source):
    return source in (spec.options.sources or [SOURCES[0]])


def validate_record(spec, item):
    try:
        validate_spec(spec)
        if not in_metadata_scope(spec, item) or item.purpose != "issuer_inventory":
            return False
        source = item.provenance.operation.removeprefix("notion.")
        if (source not in SOURCES or item.provenance.operation != operation(source)
                or item.provenance.contract_version != CONTRACT_VERSION
                or item.provenance.source_commit is not None
                or item.provenance.resource_id != resource(item.scope, source)):
            return False
        if item.record_type == "operation_report":
            values = record_values(item.model_dump())
            return (values == {"coverage_basis": "DECLARED_WORKSPACE_AND_SOURCE_ONLY"}
                    and item.native_schema_version == API_VERSION
                    and item.report_type == "notion_admin_source_report" and item.collection_mode == "inventory"
                    and item.received_records <= item.pages * spec.options.page_size
                    and item.saved_records <= item.received_records
                    and item.record_quality.records == item.received_records
                    and item.record_quality.identified == item.saved_records
                    and item.value_access == "NOT_REQUESTED" and item.value_contract is None
                    and (_enabled(spec, source) or item.status == "NOT_REQUESTED")
                    and (not item.proves_completeness or item.status == "COMPLETE"
                         and item.received_records == item.saved_records
                         and not item.record_quality.invalid_records and not item.record_quality.duplicates))
        if (item.record_type != "entity_observation" or not _enabled(spec, source)
                or item.value_match is not None or item.permissions or item.effective_at is not None):
            return False
        # Reconstruct the allowlisted provider shape, then project it again.
        # This rejects extra/nested facts and forged object IDs or states.
        values = record_values(item.model_dump())
        if any(fact.state != "PRESENT" for fact in item.facts):
            return False
        for field in ("created_at", "expires_at", "last_used_at", "revoked_at", "last_active_at"):
            if field in values:
                value = datetime.fromisoformat(values[field])
                if value.tzinfo is None:
                    return False
                values[field] = value.timestamp() * 1000
        rebuilt = observation(spec, item.scope, source, values, observed_at=item.provenance.observed_at)
        return (rebuilt.identity == item.identity and rebuilt.facts == item.facts
                and rebuilt.provider_state == item.provider_state
                and rebuilt.normalized_state == item.normalized_state and rebuilt.state_basis == item.state_basis)
    except (ValueError, TypeError, AttributeError, OverflowError):
        return False


validate_machine_record = validate_record


def _initial(spec):
    return {"provider": "notion", "version": 1, "config_hash": digest(spec.model_dump()),
            **dict.fromkeys(_COUNTS, 0), "cursor": "", "seen": [], "reasons": [], "op_reasons": []}


def _state(spec, checkpoint, bearer):
    if not isinstance(checkpoint, dict):
        raise TypeError("NOTION_CHECKPOINT_MISMATCH")
    state = deepcopy(checkpoint) if checkpoint else _initial(spec)
    base = _initial(spec)
    if (set(state) != set(base) or state["provider"] != "notion"
            or type(state["version"]) is not int or state["version"] != 1
            or state["config_hash"] != base["config_hash"]
            or any(type(state[key]) is not int or state[key] < 0 for key in _COUNTS)
            or state["task"] > len(spec.scopes) * len(SOURCES)
            or state["requests"] > spec.max_requests or state["pages"] > spec.max_pages
            or state["records"] > spec.max_records or state["retries"] > spec.options.max_retries
            or state["op_pages"] > state["pages"] or state["saved"] > state["received"]
            or state["received"] > state["op_pages"] * spec.options.page_size
            or state["records"] < state["saved"]
            or not isinstance(state["seen"], list) or len(state["seen"]) > 20000
            or any(not isinstance(value, str) or not _HASH.fullmatch(value) for value in state["seen"])
            or len(set(state["seen"])) != len(state["seen"])
            or any(not isinstance(state[key], list) or len(state[key]) > 100
                   or any(not _reason(value) for value in state[key]) for key in ("reasons", "op_reasons"))):
        raise ValueError("NOTION_CHECKPOINT_MISMATCH")
    if state["cursor"]:
        cursor_text(state["cursor"], bearer)
        if hashlib.sha256(state["cursor"].encode()).hexdigest() not in state["seen"]:
            raise ValueError("NOTION_CHECKPOINT_MISMATCH")
    elif state["cursor"] != "":
        raise ValueError("NOTION_CHECKPOINT_MISMATCH")
    if not state["cursor"] and state["seen"]:
        raise ValueError("NOTION_CHECKPOINT_MISMATCH")
    if state["task"] == len(spec.scopes) * len(SOURCES) and any(
            state[key] for key in ("cursor", "op_pages", "received", "saved", "invalid", "duplicates")):
        raise ValueError("NOTION_CHECKPOINT_MISMATCH")
    return checkpoint_json(state)


def _advance(state):
    state["task"] += 1
    for key in ("retries", "op_pages", "received", "saved", "invalid", "duplicates"):
        state[key] = 0
    state["cursor"], state["seen"], state["op_reasons"] = "", [], []


def _degrade(state, code):
    state["reasons"] = sorted({*state["reasons"], code})
    state["op_reasons"] = sorted({*state["op_reasons"], code})


def _report(state, scope, source, stamp, status):
    return report(scope, source, observed_at=stamp, status=status, reasons=state["op_reasons"],
                  pages=state["op_pages"], received=state["received"], saved=state["saved"],
                  invalid=state["invalid"], duplicates=state["duplicates"],
                  complete=status == "COMPLETE" and not state["op_reasons"])


def _replay(spec, read_records, state):
    seen = {}
    verified = set()
    reports = set()
    tasks = [(scope.id, operation(source)) for scope in spec.scopes for source in SOURCES]
    count = 0
    for raw in read_records() if read_records is not None else ():
        count += 1
        item = RECORD_ADAPTER.validate_python(raw)
        if not validate_record(spec, item):
            raise ValueError("NOTION_REPLAY_RECORD_REJECTED")
        if item.record_type == "entity_observation":
            seen[(item.scope.id, item.provenance.operation, item.identity.object_id)] = True
        elif item.record_type == "operation_report":
            reports.add((item.scope.id, item.provenance.operation))
            if item.provenance.operation == operation(SOURCES[0]) and item.pages:
                verified.add(item.scope.id)
    if count != state["records"]:
        raise ValueError("NOTION_REPLAY_COUNT_MISMATCH")
    if reports != set(tasks[:state["task"]]):
        raise ValueError("NOTION_REPLAY_PROGRESS_MISMATCH")
    if state["task"] < len(tasks):
        current = tasks[state["task"]]
        if state["saved"] != sum(key[:2] == current for key in seen):
            raise ValueError("NOTION_REPLAY_PROGRESS_MISMATCH")
    return seen, verified


def collect_pages(spec, *, secrets, checkpoint, check, read_records=None, client=None, now=None,
                  sleep=None):
    if not isinstance(spec, MetadataConnectionSpec):
        spec = MetadataConnectionSpec.model_validate(spec)
    validate_spec(spec)
    if (set(secrets) != {"token"} or not isinstance(secrets["token"], str)
            or not secrets["token"] or len(secrets["token"]) > 32768
            or any(char.isspace() for char in secrets["token"])):
        raise ValueError("NOTION_ORGANIZATION_BOT_REQUIRED")
    bearer = secrets["token"]
    state = _state(spec, checkpoint, bearer)
    if checkpoint and read_records is None:
        raise ValueError("NOTION_RECORD_REPLAY_REQUIRED")
    seen, verified = _replay(spec, read_records, state)
    tasks = [(scope, source) for scope in spec.scopes for source in SOURCES]
    own_client = client is None
    if own_client:
        import httpx

        client = httpx.Client(timeout=spec.options.timeout_seconds, follow_redirects=False)
    transport = Transport(client, spec, bearer, check, requests=state["requests"],
                          **({"sleep": sleep} if sleep else {}))
    try:
        while state["task"] < len(tasks):
            check()
            previous = deepcopy(state)
            scope, source = tasks[state["task"]]
            stamp = (now or datetime.now(UTC)).isoformat()
            if not _enabled(spec, source):
                records = [report(scope, source, observed_at=stamp, status="NOT_REQUESTED")]
                finished = True
            else:
                if state["pages"] >= spec.max_pages:
                    _degrade(state, "PAGE_BUDGET_EXCEEDED")
                    break
                try:
                    rows, next_cursor = transport.read(scope, source, state["cursor"])
                except ReadError as exc:
                    state["requests"] = transport.requests
                    if exc.retryable and state["retries"] < min(
                            spec.options.max_retries, spec.options.max_consecutive_rate_limits):
                        state["retries"] += 1
                        yield MetadataPage(checkpoint=deepcopy(state), status="WAITING",
                                           reasons=[exc.code], retry_after_seconds=exc.retry_after)
                        return
                    _degrade(state, exc.code)
                    if exc.retryable:
                        _degrade(state, "NOTION_RETRY_LIMIT")
                    records = [_report(state, scope, source, stamp,
                                       "PARTIAL" if state["op_pages"] else "FAILED")]
                    finished = True
                else:
                    state["requests"] = transport.requests
                    state["pages"] += 1
                    state["op_pages"] += 1
                    state["received"] += len(rows)
                    state["retries"] = 0
                    records = []
                    for row in rows:
                        try:
                            item = observation(spec, scope, source, row, observed_at=stamp, bearer=bearer)
                        except (ValueError, TypeError, AttributeError, OverflowError):
                            state["invalid"] += 1
                            _degrade(state, "NOTION_INVALID_RECORD")
                            continue
                        key = (scope.id, operation(source), item.identity.object_id)
                        if key in seen:
                            state["duplicates"] += 1
                            _degrade(state, "NOTION_DUPLICATE_RECORD")
                            continue
                        if any(omission.reason != "PROFILE_IMAGE_NOT_COLLECTED" for omission in item.omissions):
                            _degrade(state, "NOTION_METADATA_OMITTED")
                        records.append(item)
                        seen[key] = True
                    state["saved"] += len(records)
                    finished = not next_cursor
                    if next_cursor:
                        marker = hashlib.sha256(next_cursor.encode()).hexdigest()
                        if marker in state["seen"]:
                            _degrade(state, "NOTION_CURSOR_CYCLE")
                            finished = True
                        elif len(state["seen"]) >= 20000:
                            _degrade(state, "NOTION_CURSOR_HISTORY_LIMIT")
                            finished = True
                        else:
                            state["cursor"] = next_cursor
                            state["seen"].append(marker)
                    if finished:
                        if source == SOURCES[1] and not state["saved"] and scope.id not in verified:
                            # MCP lists an unknown or foreign workspace as []: no PAT page or row shows it exists.
                            _degrade(state, "NOTION_WORKSPACE_UNVERIFIED")
                        records.append(_report(state, scope, source, stamp,
                                               "PARTIAL" if state["op_reasons"] else "COMPLETE"))
            if state["records"] + len(records) > spec.max_records:
                # The response was read but no record was committed: keep the
                # previous cursor while retaining the consumed request budget.
                requests, pages = state["requests"], state["pages"]
                state = previous
                state["requests"], state["pages"] = requests, pages
                _degrade(state, "RECORD_BUDGET_EXCEEDED")
                break
            for item in records:
                if not validate_record(spec, item):
                    raise ValueError("NOTION_RECORD_REJECTED")
            state["records"] += len(records)
            if finished:
                if source == SOURCES[0] and state["op_pages"]:
                    verified.add(scope.id)  # the PAT list answers 404 for a workspace outside the organization
                _advance(state)
            # A cursor advances in the same yielded page as its records. The
            # worker persists both in one transaction under its current lease.
            check()
            yield MetadataPage(records=records, checkpoint=deepcopy(state))
        status = "COMPLETE" if not state["reasons"] else "PARTIAL" if state["pages"] else "FAILED"
        yield MetadataPage(checkpoint=deepcopy(state), status=status, reasons=state["reasons"])
    finally:
        transport.bearer = ""
        if own_client:
            client.close()


def native_snapshots(records):
    groups = {}
    for item in records or []:
        scope = item.get("scope", {}).get("id", "")
        source = item.get("provenance", {}).get("operation", "").removeprefix("notion.")
        if source not in SOURCES:
            continue
        target = groups.setdefault((scope, source), {"workspace_id": scope, "source": source,
            "api_version": API_VERSION, "records": [], "reports": [], "credential_match": "UNAVAILABLE",
            "match_reason": "NO_STABLE_SHARED_CREDENTIAL_IDENTIFIER"})
        if item.get("record_type") == "entity_observation":
            target["records"].append(record_values(item))
        elif item.get("record_type") == "operation_report":
            target["reports"].append(item)
    return list(groups.values())


def _compare_runs(before, after, *, spec, scope_id=None):
    def selected(rows):
        return [item for item in rows if scope_id is None or item.get("scope", {}).get("id") == scope_id]

    before, after = selected(before), selected(after)
    old = {item["identity"]["object_id"]: item for item in before if item.get("record_type") == "entity_observation"}
    new = {item["identity"]["object_id"]: item for item in after if item.get("record_type") == "entity_observation"}
    reports = {}
    for item in after:
        if item.get("record_type") == "operation_report":
            key = (item["scope"]["id"], item["provenance"]["operation"])
            reports.setdefault(key, []).append(item)
    complete = {key for key, rows in reports.items()
                if all(row.get("status") == "COMPLETE" and row.get("proves_completeness") is True for row in rows)}
    missing, unknown = [], []
    for key in sorted(old.keys() - new.keys()):
        item = old[key]
        if (item["scope"]["id"], item["provenance"]["operation"]) in complete:
            missing.append(key)
        else:
            unknown.append({"object_id": key, "reason": "SOURCE_NOT_COMPLETELY_LISTED"})
    changed = []
    for key in sorted(old.keys() & new.keys()):
        left, right = record_values(old[key]), record_values(new[key])
        fields = sorted(field for field in left.keys() | right.keys() if left.get(field) != right.get(field))
        if fields:
            changed.append({"object_id": key, "fields": fields})
    return {"added": sorted(new.keys() - old.keys()), "no_longer_listed": missing, "changed": changed,
            "absence_not_evaluated": unknown,
            "notes": ["LISTING_ABSENCE_IS_NOT_REVOCATION", "PROVIDER_STATUS_IS_NOT_CREDENTIAL_VERIFICATION"]}
