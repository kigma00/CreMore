"""Checkpointed Slack app inventory of one organization or workspace.

Tasks run in ``SOURCES`` order. With the audit option the organization's audit log is read first,
within a window fixed when the run starts, and folded into a per-app summary the checkpoint keeps;
the approved apps then take its installs, and the apps it shows installed outside the approved list
follow. Each page's records and the checkpoint that follows them are saved together by the worker.
"""

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

from . import API_ORIGIN, AUDIT_ACTIONS, CONTRACT_VERSION, SOURCES
from .normalization import (
    APP_ID,
    BASIS,
    KINDS,
    MAX_PLACES,
    PLACE,
    ROW_FACTS,
    SCOPE_NAME,
    approved_app,
    audit_app,
    audit_event,
    merge,
    operation,
    record_values,
    report,
    resource,
    rows,
    scope_id,
)
from .transport import ReadError, Transport, cursor_text

_COUNTS = ("task", "requests", "pages", "records", "retries", "op_pages", "received", "saved", "invalid",
           "duplicates", "offset")
_HASH = re.compile(r"[0-9a-f]{64}")
_ROW = re.compile(r"(bot|user|hook):([ET][A-Z0-9]{2,30}):(A[A-Z0-9]{2,30})")
_REASONS = {"PAGE_BUDGET_EXCEEDED", "RECORD_BUDGET_EXCEEDED", "REQUEST_BUDGET_EXCEEDED"}
_SUMMARY = {"n": str, "b": str, "u": str, "iu": str, "in": str, "s": str, "la": str, "w": str,
            "na": int, "ba": int, "ua": int, "i": int, "sa": int, "l": int}
_PLACES = re.compile(f"(?:{PLACE.pattern})=-?[1-9][0-9]{{0,11}}(?:;(?:{PLACE.pattern})=-?[1-9][0-9]{{0,11}})*")
_SCOPES = re.compile(f"(?:{SCOPE_NAME.pattern}(?:,{SCOPE_NAME.pattern})*)?")
_STATES = {"INSTALLED": "ACTIVE", "UNINSTALLED": "REVOKED", "APPROVED": "UNKNOWN"}
MAX_AUDIT_APPS = 5000
INSTALLED_BATCH = 1000
DEFAULT_LOOKBACK_DAYS = 90


def _reason(value):
    return isinstance(value, str) and (value in _REASONS or bool(re.fullmatch(r"SLACK_[A-Z0-9_]{1,80}", value)))


def validate_spec(spec):
    if spec.provider != "slack" or spec.edition != "cloud" or spec.origin != API_ORIGIN:
        raise ValueError("SLACK_CLOUD_REQUIRED")
    if spec.auth_type != "bearer" or set(spec.secret_refs) != {"token"}:
        raise ValueError("SLACK_ADMIN_TOKEN_REFERENCE_REQUIRED")
    options = spec.options
    audit = options.include_audit_events
    if set(spec.capabilities) != ({"inventory", "audit"} if audit else {"inventory"}) or len(spec.capabilities) > 2:
        raise ValueError("SLACK_CAPABILITIES_INVALID")
    if spec.principal_pin is not None:
        raise ValueError("SLACK_ADMIN_PRINCIPAL_PIN_UNVERIFIABLE")
    if len(spec.scopes) != 1:
        raise ValueError("SLACK_ONE_SCOPE_REQUIRED")
    scope_id(spec.scopes[0])
    if (options.mode != "inventory" or options.page_size > 1000 or options.sources
            or options.include_actions or options.locations or options.include_deleted
            or options.audit_created_after or (options.audit_lookback_days is not None and not audit)
            or (options.audit_lookback_days or 0) > 365 or options.requests_per_second > 1):
        raise ValueError("SLACK_COLLECTION_OPTION_NOT_SUPPORTED")


def _enabled(spec, source):
    return source == "approved_apps" or spec.options.include_audit_events


def validate_record(spec, item):
    try:
        validate_spec(spec)
        scope = spec.scopes[0]
        if not in_metadata_scope(spec, item) or item.purpose != "issuer_inventory" or item.scope != scope:
            return False
        source = item.provenance.operation.removeprefix("slack.")
        if (source not in SOURCES or item.provenance.operation != operation(source)
                or item.provenance.contract_version != CONTRACT_VERSION
                or item.provenance.source_commit is not None
                or item.provenance.resource_id != resource(scope, source)):
            return False
        if item.record_type == "operation_report":
            return (record_values(item.model_dump()) == {"coverage_basis": BASIS[source]}
                    and item.report_type == "slack_admin_source_report" and item.collection_mode == "inventory"
                    and item.native_schema_version == "web-api"
                    and item.saved_records <= item.received_records
                    and item.record_quality.records == item.received_records
                    and item.record_quality.identified == item.saved_records
                    and item.value_access == "NOT_REQUESTED" and item.value_contract is None
                    and (_enabled(spec, source) or item.status == "NOT_REQUESTED")
                    and all(_reason(code) or code == "TOKEN_VALUES_AND_WEBHOOK_URLS_NOT_RETURNED"
                            for code in item.reasons)
                    # Only the approved list proves it is whole; the audit log is a window.
                    and (not item.proves_completeness
                         or source == "approved_apps" and item.status == "COMPLETE"
                         and not item.record_quality.invalid_records and not item.record_quality.duplicates))
        if (item.record_type != "entity_observation" or source == "audit_events" or not _enabled(spec, source)
                or item.value_match is not None or item.permissions or item.effective_at is not None):
            return False
        match = _ROW.fullmatch(item.identity.object_id)
        if (not match or match.group(2) != scope.id or item.identity.provider != "slack"
                or item.identity.kind != "credential" or item.identity.origin != spec.origin):
            return False
        values = record_values(item.model_dump())
        if (set(values) - ROW_FACTS or values.get("app_id") != match.group(3)
                or values.get("token_type") != KINDS[match.group(1)]
                or any(fact.state != "PRESENT" for fact in item.facts)):
            return False
        if _STATES.get(item.provider_state) != item.normalized_state:
            return False
        if (item.state_basis == "UNKNOWN") != (item.provider_state == "APPROVED"):
            return False
        return source != "installed_apps" or item.provider_state == "INSTALLED"
    except (ValueError, TypeError, AttributeError, OverflowError):
        return False


def _initial(spec):
    return {"provider": "slack", "version": 1, "config_hash": digest(spec.model_dump()),
            **dict.fromkeys(_COUNTS, 0), "cursor": "", "seen": [], "reasons": [], "op_reasons": [],
            "window": [], "audit": {}}


def _summary_ok(app_id, summary):
    if not isinstance(app_id, str) or not APP_ID.fullmatch(app_id) or not isinstance(summary, dict):
        return False
    for key, value in summary.items():
        kind = _SUMMARY.get(key)
        if kind is None or type(value) is not kind or (kind is int and not 0 <= value <= 253402300799):
            return False
    where = summary.get("w", "")
    return (summary.get("s") in (None, "installed", "removed") and summary.get("la") in (None, *AUDIT_ACTIONS)
            and all(_SCOPES.fullmatch(summary.get(key, "")) for key in ("b", "u"))
            and (not where or _PLACES.fullmatch(where) is not None and where.count(";") < MAX_PLACES)
            and ("s" in summary) == bool(where))


def _state(spec, checkpoint, bearer):
    if not isinstance(checkpoint, dict):
        raise TypeError("SLACK_CHECKPOINT_MISMATCH")
    state = deepcopy(checkpoint) if checkpoint else _initial(spec)
    base = _initial(spec)
    window = state.get("window")
    if (set(state) != set(base) or state["provider"] != "slack"
            or type(state["version"]) is not int or state["version"] != 1
            or state["config_hash"] != base["config_hash"]
            or any(type(state[key]) is not int or state[key] < 0 for key in _COUNTS)
            or state["task"] > len(SOURCES)
            or state["requests"] > spec.max_requests or state["pages"] > spec.max_pages
            or state["records"] > spec.max_records or state["retries"] > spec.options.max_retries
            or state["op_pages"] > state["pages"] or state["saved"] > state["received"]
            or not isinstance(window, list) or window and (
                len(window) != 2 or any(type(value) is not int or value < 0 for value in window)
                or window[0] >= window[1])
            or not isinstance(state["audit"], dict) or len(state["audit"]) > MAX_AUDIT_APPS
            or not all(_summary_ok(app_id, summary) for app_id, summary in state["audit"].items())
            or not isinstance(state["seen"], list) or len(state["seen"]) > 20000
            or any(not isinstance(value, str) or not _HASH.fullmatch(value) for value in state["seen"])
            or len(set(state["seen"])) != len(state["seen"])
            or any(not isinstance(state[key], list) or len(state[key]) > 100
                   or any(not _reason(value) for value in state[key]) for key in ("reasons", "op_reasons"))):
        raise ValueError("SLACK_CHECKPOINT_MISMATCH")
    if state["cursor"]:
        cursor_text(state["cursor"], bearer)
        if hashlib.sha256(state["cursor"].encode()).hexdigest() not in state["seen"]:
            raise ValueError("SLACK_CHECKPOINT_MISMATCH")
    elif state["cursor"] != "" or state["seen"]:
        raise ValueError("SLACK_CHECKPOINT_MISMATCH")
    return checkpoint_json(state)


def _advance(state):
    state["task"] += 1
    for key in ("retries", "op_pages", "received", "saved", "invalid", "duplicates", "offset"):
        state[key] = 0
    state["cursor"], state["seen"], state["op_reasons"] = "", [], []


def _degrade(state, code):
    state["reasons"] = sorted({*state["reasons"], code})
    state["op_reasons"] = sorted({*state["op_reasons"], code})


def _report(state, scope, source, stamp, status, *, complete=False):
    return report(scope, source, observed_at=stamp, status=status, reasons=state["op_reasons"],
                  pages=state["op_pages"], received=state["received"], saved=state["saved"],
                  invalid=state["invalid"], duplicates=state["duplicates"],
                  complete=complete and status == "COMPLETE" and not state["op_reasons"],
                  window=state["window"] if source == "audit_events" and state["window"] else None)


def _replay(spec, read_records, state):
    """The object ids saved before this resumption; the count and finished tasks must match the checkpoint."""
    seen, reports, count = set(), set(), 0
    for raw in read_records() if read_records is not None else ():
        count += 1
        item = RECORD_ADAPTER.validate_python(raw)
        if not validate_record(spec, item):
            raise ValueError("SLACK_REPLAY_RECORD_REJECTED")
        if item.record_type == "entity_observation":
            seen.add(item.identity.object_id)
        else:
            reports.add(item.provenance.operation)
    if count != state["records"]:
        raise ValueError("SLACK_REPLAY_COUNT_MISMATCH")
    if reports != {operation(source) for source in SOURCES[:state["task"]]}:
        raise ValueError("SLACK_REPLAY_PROGRESS_MISMATCH")
    return seen


def _audit_page(scope, state, entries, bearer):
    for entry in entries:
        try:
            found = audit_event(entry, scope, bearer=bearer)
        except (ValueError, TypeError, AttributeError, OverflowError):
            state["invalid"] += 1
            _degrade(state, "SLACK_INVALID_RECORD")
            continue
        if found is None:
            continue
        app_id, event = found
        if app_id not in state["audit"] and len(state["audit"]) >= MAX_AUDIT_APPS:
            _degrade(state, "SLACK_AUDIT_APP_LIMIT")
            continue
        merge(state["audit"].setdefault(app_id, {}), event)
        state["saved"] += 1
    return []


def _apps_page(spec, scope, state, seen, items, stamp, bearer):
    records = []
    for item in items:
        try:
            app, omitted = approved_app(item, bearer=bearer)
            made = rows(spec, scope, "approved_apps", app, state["audit"].get(app["id"]), observed_at=stamp,
                        omitted=omitted)
        except (ValueError, TypeError, AttributeError, OverflowError):
            state["invalid"] += 1
            _degrade(state, "SLACK_INVALID_RECORD")
            continue
        if any(row.identity.object_id in seen for row in made):
            state["duplicates"] += 1
            _degrade(state, "SLACK_DUPLICATE_RECORD")
            continue
        # A field Slack added is only noted; a value that could not be read makes the listing partial.
        if any(reason != "UNAPPROVED_METADATA_FIELD" for _path, reason in omitted):
            _degrade(state, "SLACK_METADATA_OMITTED")
        seen.update(row.identity.object_id for row in made)
        records.extend(made)
        state["saved"] += 1
    return records


def _installed_page(spec, scope, state, seen, stamp):
    """The next batch of apps the audit log shows installed that the approved list did not name."""
    apps = sorted(state["audit"])
    records = []
    for app_id in apps[state["offset"]:state["offset"] + INSTALLED_BATCH]:
        summary = state["audit"][app_id]
        state["received"] += 1
        if summary.get("s") != "installed" or any(f"{kind}:{scope.id}:{app_id}" in seen for kind in KINDS):
            continue
        made = rows(spec, scope, "installed_apps", audit_app(app_id, summary), summary, observed_at=stamp)
        seen.update(row.identity.object_id for row in made)
        records.extend(made)
        state["saved"] += 1
    state["offset"] += INSTALLED_BATCH
    finished = state["offset"] >= len(apps)
    if finished:
        # What the audit log or the approved list missed may hide an install: any gap of this run counts.
        records.append(report(scope, "installed_apps", observed_at=stamp,
                              status="PARTIAL" if state["reasons"] else "COMPLETE", reasons=state["reasons"],
                              received=state["received"], saved=state["saved"]))
    return records, finished


def collect_pages(spec, *, secrets, checkpoint, check, read_records=None, client=None, now=None, sleep=None):
    if not isinstance(spec, MetadataConnectionSpec):
        spec = MetadataConnectionSpec.model_validate(spec)
    validate_spec(spec)
    bearer = secrets.get("token") if isinstance(secrets, dict) and set(secrets) == {"token"} else None
    if not isinstance(bearer, str) or not bearer or len(bearer) > 4096 or any(char.isspace() for char in bearer):
        raise ValueError("SLACK_ADMIN_TOKEN_REQUIRED")
    state = _state(spec, checkpoint, bearer)
    if checkpoint and read_records is None:
        raise ValueError("SLACK_RECORD_REPLAY_REQUIRED")
    seen = _replay(spec, read_records, state)
    scope = spec.scopes[0]
    own_client = client is None
    if own_client:
        import httpx

        client = httpx.Client(timeout=spec.options.timeout_seconds, follow_redirects=False)
    transport = Transport(client, spec, bearer, check, requests=state["requests"],
                          **({"sleep": sleep} if sleep else {}))
    try:
        while state["task"] < len(SOURCES):
            check()
            previous = deepcopy(state)
            source = SOURCES[state["task"]]
            moment = now or datetime.now(UTC)
            stamp = moment.isoformat()
            if not _enabled(spec, source):
                records, finished = [report(scope, source, observed_at=stamp, status="NOT_REQUESTED")], True
            elif source == "installed_apps":
                records, finished = _installed_page(spec, scope, state, seen, stamp)
            else:
                if state["pages"] >= spec.max_pages:
                    _degrade(state, "PAGE_BUDGET_EXCEEDED")
                    break
                if source == "audit_events" and not state["window"]:
                    days = spec.options.audit_lookback_days or DEFAULT_LOOKBACK_DAYS
                    latest = int(moment.timestamp())
                    state["window"] = [latest - days * 86400, latest]
                try:
                    if source == "audit_events":
                        items, following = transport.audit(*state["window"], state["cursor"])
                    else:
                        items, following = transport.approved(scope, state["cursor"])
                except ReadError as exc:
                    state["requests"] = transport.requests
                    if exc.retryable and state["retries"] < min(spec.options.max_retries,
                                                                spec.options.max_consecutive_rate_limits):
                        state["retries"] += 1
                        yield MetadataPage(checkpoint=deepcopy(state), status="WAITING", reasons=[exc.code],
                                           retry_after_seconds=exc.retry_after)
                        return
                    _degrade(state, exc.code)
                    if exc.retryable:
                        _degrade(state, "SLACK_RETRY_LIMIT")
                    records = [_report(state, scope, source, stamp, "PARTIAL" if state["op_pages"] else "FAILED")]
                    finished = True
                else:
                    state["requests"] = transport.requests
                    state["pages"] += 1
                    state["op_pages"] += 1
                    state["received"] += len(items)
                    state["retries"] = 0
                    records = (_audit_page(scope, state, items, bearer) if source == "audit_events"
                               else _apps_page(spec, scope, state, seen, items, stamp, bearer))
                    finished = not following
                    if following:
                        marker = hashlib.sha256(following.encode()).hexdigest()
                        if marker in state["seen"]:
                            _degrade(state, "SLACK_CURSOR_CYCLE")
                            finished = True
                        elif len(state["seen"]) >= 20000:
                            _degrade(state, "SLACK_CURSOR_HISTORY_LIMIT")
                            finished = True
                        else:
                            state["cursor"] = following
                            state["seen"].append(marker)
                    if finished:
                        records.append(_report(state, scope, source, stamp,
                                               "PARTIAL" if state["op_reasons"] else "COMPLETE",
                                               complete=source == "approved_apps"))
            if state["records"] + len(records) > spec.max_records:
                # The response was read but no record was committed: keep the previous cursor
                # while retaining the consumed request budget.
                requests, pages = state["requests"], state["pages"]
                state = previous
                state["requests"], state["pages"] = requests, pages
                _degrade(state, "RECORD_BUDGET_EXCEEDED")
                break
            for item in records:
                if not validate_record(spec, item):
                    raise ValueError("SLACK_RECORD_REJECTED")
            state["records"] += len(records)
            if finished:
                _advance(state)
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
        scope = item.get("scope", {})
        source = item.get("provenance", {}).get("operation", "").removeprefix("slack.")
        if source not in SOURCES:
            continue
        target = groups.setdefault((scope.get("kind"), scope.get("id"), source), {
            "scope": {"kind": scope.get("kind"), "id": scope.get("id")}, "source": source, "records": [],
            "reports": [], "credential_match": "UNAVAILABLE", "match_reason": "NO_TOKEN_VALUE_OR_DIGEST_RETURNED"})
        if item.get("record_type") == "entity_observation":
            target["records"].append({"object_id": item.get("identity", {}).get("object_id"), **record_values(item)})
        elif item.get("record_type") == "operation_report":
            target["reports"].append(item)
    return list(groups.values())


def _compare_runs(before, after, *, spec, scope_id=None):
    def selected(items):
        return [item for item in items if scope_id is None or item.get("scope", {}).get("id") == scope_id]

    before, after = selected(before), selected(after)
    old = {item["identity"]["object_id"]: item for item in before if item.get("record_type") == "entity_observation"}
    new = {item["identity"]["object_id"]: item for item in after if item.get("record_type") == "entity_observation"}
    reports = {}
    for item in after:
        if item.get("record_type") == "operation_report":
            reports.setdefault(item["provenance"]["operation"], []).append(item)
    # Only a whole approved list proves an approved app is gone; the audit log is a window.
    whole = all(row.get("status") == "COMPLETE" and row.get("proves_completeness") is True
                for row in reports.get(operation("approved_apps"), [])) and operation("approved_apps") in reports
    missing, unknown = [], []
    for key in sorted(old.keys() - new.keys()):
        if whole and old[key]["provenance"]["operation"] == operation("approved_apps"):
            missing.append(key)
        else:
            unknown.append({"object_id": key, "reason": "SOURCE_NOT_COMPLETELY_LISTED"})
    changed = []
    for key in sorted(old.keys() & new.keys()):
        left, right = record_values(old[key]), record_values(new[key])
        fields = sorted(field for field in left.keys() | right.keys() if left.get(field) != right.get(field))
        if old[key].get("provider_state") != new[key].get("provider_state"):
            fields = sorted({*fields, "state"})
        if fields:
            changed.append({"object_id": key, "fields": fields})
    return {"added": sorted(new.keys() - old.keys()), "no_longer_listed": missing, "changed": changed,
            "absence_not_evaluated": unknown,
            "notes": ["LISTING_ABSENCE_IS_NOT_REVOCATION", "PROVIDER_STATUS_IS_NOT_CREDENTIAL_VERIFICATION"]}
