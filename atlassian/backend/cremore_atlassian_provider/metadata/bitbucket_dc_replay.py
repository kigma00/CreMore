"""Offline DC views and recovery plans from validated canonical observations."""

from __future__ import annotations

from urllib.parse import urlsplit

# errors.py keeps this provider module free of the platform's DB layer.
from cremore.coverage.errors import CoverageError
from cremore.coverage.metadata_models import RECORD_ADAPTER, MetadataConnectionSpec, MetadataScope

from . import bitbucket_dc as dc
from .compare import add_row, compare_sources, new_source, timestamp
from .jsonio import bounded_json, canonical

PLAN_TYPE = "bitbucket_dc_recollection_plan"
STATUS = {"COMPLETE": "complete", "PARTIAL": "partial", "FAILED": "failed",
          "UNKNOWN": "unverified", "UNSUPPORTED": "unverified", "NOT_REQUESTED": "not_requested"}


def require(condition):
    if not condition:
        raise CoverageError("BITBUCKET_DC_INVALID_REPLAY")


def _record_spec(record):
    """Recover only the endpoint boundary, never an executable credential."""
    url = urlsplit(record.provenance.resource_id)
    suffix = "/rest/access-tokens/latest" + dc.scope_path(record.scope)
    require(not url.query and not url.fragment and url.path.endswith(suffix))
    identity = getattr(record, "identity", None)
    return MetadataConnectionSpec(
        name="DC replay", provider="bitbucket", edition="data_center",
        origin=f"{url.scheme}://{url.netloc}", scopes=[record.scope], capabilities=["inventory"],
        tenant=identity.tenant if identity else "", tenant_confirmed=identity.tenant_confirmed if identity else False,
        secret_refs={"token": "vault://replay/unused"}, options={"api_path": url.path[:-len(suffix)]})


def native_snapshots(records, *, spec=None):
    """One bounded typed snapshot per observed scope; no Cloud schema invention."""
    # Persisted run contracts intentionally strip all secret references. Replay
    # validates the original scope/options with an inert placeholder, not auth.
    if spec is not None:
        spec = spec.model_copy(update={"secret_refs": {"token": "vault://replay/unused"}})
    groups, installations, tenants = {}, set(), set()
    for index, value in enumerate(records):
        require(index < 101000)
        record = RECORD_ADAPTER.validate_python(value.model_dump() if hasattr(value, "model_dump") else value)
        inferred = _record_spec(record)
        require(dc.validate_record(spec or inferred, record))
        installations.add((inferred.origin, dc.api_path(inferred)))
        if record.record_type == "entity_observation":
            tenants.add((record.identity.tenant, record.identity.tenant_confirmed))
        key = (record.scope.kind, record.scope.id)
        group = groups.setdefault(key, {
            "schema_version": 1, "report_type": "bitbucket_dc_http_token_snapshot",
            "provider": "bitbucket", "environment": "data_center", "contract_version": dc.CONTRACT,
            "origin": inferred.origin, "context_path": dc.api_path(inferred),
            "scope": record.scope.model_dump(), "operation": record.provenance.operation,
            "resource_id": record.provenance.resource_id, "inventory_complete": False, "records": [],
        })
        require(group["resource_id"] == record.provenance.resource_id)
        group["records"].append(record.model_dump())
    require(len(installations) <= 1 and len(tenants) <= 1 and len(groups) <= 1000)
    result = []
    for key in sorted(groups):
        group = groups[key]
        reports = [item for item in group["records"] if item["record_type"] == "operation_report"]
        require(len(reports) <= 1)
        times = [item["provenance"]["observed_at"] for item in group["records"]]
        group.update(started_at=min(times, key=timestamp), finished_at=max(times, key=timestamp),
                     coverage=STATUS[reports[0]["status"]] if reports else "unverified")
        if reports:
            require(timestamp(reports[0]["provenance"]["observed_at"]) == timestamp(group["finished_at"]))
        result.append(group)
    bounded_json(result)
    return result


def _select(snapshots, scope_id):
    if scope_id is None:
        return snapshots
    # The shared API selects an ID, not a kind. Refuse ambiguous user/project IDs.
    result = [item for item in snapshots if item["scope"]["id"] == scope_id]
    require(len(result) == 1)
    return result


def _source(snapshot):
    context = {key: snapshot[key] for key in ("scope", "resource_id")}
    source = new_source(snapshot["operation"], context, snapshot["coverage"], "/records")
    reports = []
    for index, record in enumerate(snapshot["records"]):
        if record["record_type"] == "operation_report":
            reports.append(record)
            source["ref"] = f"/records/{index}"
            continue
        facts = {}
        for fact in record["facts"]:
            if fact["state"] in {"PRESENT", "NULL"}:
                facts[fact["name"]] = {"state": fact["state"], "value": fact["value"]}
            else:
                facts[fact["name"]] = {"_cremore_omitted": fact["state"]}
                source["issues"].add("incomplete_metadata")
        add_row(source, record["identity"], facts, f"/records/{index}")
    if not reports:
        source["issues"].add("missing_operation_report")
    else:
        report = reports[0]
        saved = sum(len(rows) for rows in source["rows"].values())
        if report["saved_records"] != saved or report["received_records"] < saved:
            source["issues"].add("saved_record_count_mismatch")
        if report["status"] == "COMPLETE" and not report["pages"]:
            source["issues"].add("missing_pages")
        if report["status"] in {"FAILED", "NOT_REQUESTED", "UNSUPPORTED"} and saved:
            source["issues"].add("unexpected_observations")
        if set(report["reasons"]) - {dc.LIMITATION, "NOT_SELECTED_FOR_RECOLLECTION"}:
            source["issues"].add("collection_limitations")
    return source


def compare_records(before_records, after_records, *, spec=None, scope_id=None):
    before = _select(native_snapshots(before_records, spec=spec), scope_id)
    after = _select(native_snapshots(after_records, spec=spec), scope_id)
    require(bool(before) and bool(after))
    require((before[0]["origin"], before[0]["context_path"]) == (after[0]["origin"], after[0]["context_path"]))
    before_tenants = {canonical(row["identity"] | {"object_id": ""}) for item in before for row in item["records"]
                      if row["record_type"] == "entity_observation"}
    after_tenants = {canonical(row["identity"] | {"object_id": ""}) for item in after for row in item["records"]
                     if row["record_type"] == "entity_observation"}
    require(not before_tenants or not after_tenants or before_tenants == after_tenants)
    windows = [{"started_at": min((item["started_at"] for item in values), key=timestamp),
                "finished_at": max((item["finished_at"] for item in values), key=timestamp)}
               for values in (before, after)]
    require(timestamp(windows[0]["finished_at"]) <= timestamp(windows[1]["started_at"]))
    sources = [{canonical([item["operation"], item["scope"]]): _source(item) for item in values}
               for values in (before, after)]
    compared, counts = compare_sources(*sources)
    return {
        "schema_version": 1, "report_type": "bitbucket_dc_metadata_comparison",
        "provider": "bitbucket", "environment": "data_center", "contract_version": dc.CONTRACT,
        "before_window": windows[0], "after_window": windows[1], "inventory_complete": False,
        "comparison_status": "limited" if counts["limited_sources"] or not counts["sources"] else "complete",
        "counts": dict(counts), "sources": compared,
        "limitations": ["absence_does_not_prove_revocation", "selected_scopes_only",
                        "authentication_visibility_not_verified", "collection_windows_are_not_atomic"],
    }


def plan_recollection(records, *, scope_id=None, operations=None, include_unverified=False):
    snapshots = _select(native_snapshots(records), scope_id)
    require(bool(snapshots) and type(include_unverified) is bool)
    if operations is not None:
        require(type(operations) is list and bool(operations) and all(type(op) is str for op in operations))
        require(len(operations) == len(set(operations)) and set(operations) <= set(dc.OPERATIONS.values()))
    tasks = []
    for snapshot in snapshots:
        source = _source(snapshot)
        eligible = source["coverage"] in {"failed", "partial"} or (
            include_unverified and source["coverage"] != "not_requested"
            and (source["coverage"] == "unverified" or bool(source["issues"])))
        if eligible and (operations is None or snapshot["operation"] in operations):
            tasks.append({key: snapshot[key] for key in ("scope", "operation", "resource_id")}
                         | {"previous_coverage": source["coverage"]})
    if not tasks:
        raise CoverageError("BITBUCKET_DC_NO_RECOLLECTION_TARGETS")
    return {
        "schema_version": 1, "report_type": PLAN_TYPE, "contract_version": dc.CONTRACT,
        "origin": snapshots[0]["origin"], "context_path": snapshots[0]["context_path"],
        "tasks": tasks, "selected_count": len(tasks), "include_unverified": include_unverified,
        "page_policy": "restart_at_first_page", "fanout_policy": "selected_targets_only",
    }


def selected_scopes(spec, plan):
    """Bind an internal plan to the current approved spec before any HTTP call."""
    require(type(plan) is dict and set(plan) == {
        "schema_version", "report_type", "contract_version", "origin", "context_path", "tasks",
        "selected_count", "include_unverified", "page_policy", "fanout_policy"})
    require(type(plan["schema_version"]) is int and plan["schema_version"] == 1
            and plan["report_type"] == PLAN_TYPE and plan["contract_version"] == dc.CONTRACT
            and plan["origin"] == spec.origin and plan["context_path"] == dc.api_path(spec)
            and plan["page_policy"] == "restart_at_first_page" and plan["fanout_policy"] == "selected_targets_only"
            and type(plan["include_unverified"]) is bool and type(plan["selected_count"]) is int
            and type(plan["tasks"]) is list and 1 <= len(plan["tasks"]) <= len(spec.scopes)
            and plan["selected_count"] == len(plan["tasks"]))
    selected = set()
    for task in plan["tasks"]:
        require(type(task) is dict and set(task) == {"scope", "operation", "resource_id", "previous_coverage"})
        scope = MetadataScope.model_validate(task["scope"])
        key = (scope.kind, scope.id)
        require(scope in spec.scopes and key not in selected and task["operation"] == dc.OPERATIONS[scope.kind]
                and task["resource_id"] == dc.endpoint(spec, scope)
                and (task["previous_coverage"] in {"failed", "partial"}
                     or plan["include_unverified"] and task["previous_coverage"] in {"complete", "unverified"}))
        selected.add(key)
    return selected
