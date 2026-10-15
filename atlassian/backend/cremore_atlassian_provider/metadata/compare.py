# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/compare.py).
"""Compare saved metadata observations offline; absence never proves revocation."""

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from .bitbucket import CORE_OPERATIONS, OPERATIONS
from .discovery import collection_records, valid_scalar_shape
from .identities import BITBUCKET_IDS, CLOUD_IDS, record_identity
from .jsonio import (
    MAX_BYTES,
    MAX_DEPTH,
    MAX_NODES,
    canonical,
    load_json,
)
from .jsonio import (
    bounded_json as validate_json,
)
from .read_operations import READ_OPERATIONS
from .specs import SOURCES
from .storage import save_private

MISSING = object()
COVERAGES = {"complete", "partial", "failed", "unverified", "not_requested"}
EVENTS = (
    "first_observed",
    "metadata_changed",
    "not_observed",
    "observation_unknown",
    "metadata_unknown",
)


class ComparisonError(ValueError):
    """Invalid, incompatible or unbounded input; never include input values."""


def require(condition):
    if not condition:
        raise ComparisonError("Invalid or incompatible metadata snapshots")


def bounded_json(value):
    validate_json(value, max_nodes=MAX_NODES, max_depth=MAX_DEPTH)


def load_snapshot(path):
    return load_json(path, max_bytes=MAX_BYTES, max_nodes=MAX_NODES, max_depth=MAX_DEPTH)


def timestamp(value):
    require(type(value) is str)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ComparisonError("Invalid snapshot time") from None
    require(parsed.tzinfo is not None and parsed.utcoffset() is not None)
    return parsed


def scope(snapshot):
    require(type(snapshot) is dict and snapshot.get("provider") == "atlassian")
    kind, version = snapshot.get("report_type", "inventory"), snapshot.get("schema_version")
    require(type(version) is int)
    environment = snapshot.get("environment")
    if kind == "bitbucket_metadata_discovery":
        require(version == 1 and environment == "bitbucket_cloud")
        mode = snapshot.get("collection_mode")
        if mode is None:
            # Early core snapshots predate the mode field. Do not infer runner mode.
            reports = snapshot.get("collections")
            require(type(reports) is list and all(type(r) is dict for r in reports))
            operations = [r.get("operation") for r in reports]
            require(
                all(type(op) is str and op in CORE_OPERATIONS for op in operations)
                and "current-user" in operations
                and "workspace" in operations
            )
            mode = "core"
        require(mode in ("core", "runners", "branch_restrictions"))
        target = snapshot.get("workspace")
    else:
        require(
            environment == "cloud"
            and (
                (kind == "inventory" and version == 3)
                or (
                    kind in ("metadata_discovery", "managed_account_metadata_discovery")
                    and version == 1
                )
            )
        )
        mode, target = None, snapshot.get("queried_org_id")
    require(type(target) is str and bool(target))
    profile = snapshot.get("connection_profile")
    require(profile is None or type(profile) is str)
    require(timestamp(snapshot.get("started_at")) <= timestamp(snapshot.get("finished_at")))
    return {
        "provider": "atlassian",
        "environment": environment,
        "report_type": kind,
        "schema_version": version,
        "scope_id": target,
        "collection_mode": mode,
        "connection_profile": profile,
    }


def pointer_part(value):
    return value.replace("~", "~0").replace("/", "~1")


def new_source(operation, context, coverage, ref):
    require(coverage in COVERAGES)
    return {
        "operation": operation,
        "context": context,
        "coverage": coverage,
        "ref": ref,
        "rows": {},
        "issues": set(),
        "unidentified_records": 0,
    }


def add_row(source, key, value, ref):
    if key is None:
        source["unidentified_records"] += 1
        source["issues"].add("unidentifiable_records")
        return
    encoded = canonical(key)
    source["rows"].setdefault(encoded, []).append({"identity": key, "value": value, "ref": ref})
    if len(source["rows"][encoded]) > 1:
        source["issues"].add("duplicate_identities")


def incomplete_metadata(value):
    if type(value) is dict:
        if "_cremore_omitted" in value and value["_cremore_omitted"] != "sensitive_value":
            return True
        return any(incomplete_metadata(child) for child in value.values())
    return type(value) is list and any(incomplete_metadata(child) for child in value)


def discovery_sources(snapshot):
    bitbucket = snapshot["environment"] == "bitbucket_cloud"
    specs, ids = (OPERATIONS, BITBUCKET_IDS) if bitbucket else (READ_OPERATIONS, CLOUD_IDS)
    reports, sources = snapshot.get("collections"), {}
    require(type(reports) is list)
    for index, report in enumerate(reports):
        require(type(report) is dict)
        operation = report.get("operation")
        require(type(operation) is str and operation in specs)
        context = {
            key: report[key] for key in ("target_id", "requested_account_ids") if key in report
        }
        if "requested_account_ids" in context:
            values = context["requested_account_ids"]
            require(type(values) is list and all(type(v) is str for v in values))
            context["requested_account_ids"] = sorted(values)
        if "target_id" in context:
            target = context["target_id"]
            require(
                type(target) is str
                or (type(target) is list and all(type(v) is str for v in target))
            )
        key = canonical([operation, context])
        require(key not in sources)
        ref = "/collections/" + str(index)
        source = new_source(operation, context, report.get("coverage"), ref)
        sources[key] = source
        pages = report.get("pages")
        require(type(pages) is list)
        total_rows = 0
        if not pages and source["coverage"] == "complete":
            source["issues"].add("missing_pages")
        for page_index, page in enumerate(pages):
            require(type(page) is dict and "metadata" in page)
            body = page["metadata"]
            page_ref = ref + "/pages/" + str(page_index) + "/metadata"
            if page.get("http_status") != 200:
                source["issues"].add("unexpected_page_status")
                continue
            if incomplete_metadata(body) or page.get("redactions", {}).get("truncated_nodes", 0):
                source["issues"].add("incomplete_metadata")
            rows, container = collection_records(specs[operation], body)
            if rows is not None:
                total_rows += len(rows)
                if operation not in ids:
                    # Future list types need an explicit source-local identity.
                    source["issues"].add("unsupported_record_identity")
                for row_index, row in enumerate(rows):
                    row_ref = (
                        page_ref + ("/" + container if container else "") + "/" + str(row_index)
                    )
                    add_row(source, record_identity(row, ids.get(operation, ())), row, row_ref)
            elif valid_scalar_shape(specs[operation]["shape"], body):
                add_row(source, {"source_document": True}, body, page_ref)
            else:
                source["issues"].add("unexpected_metadata_shape")
        if "saved_records" in report and (
            type(report["saved_records"]) is not int or report["saved_records"] != total_rows
        ):
            source["issues"].add("saved_record_count_mismatch")
        if report.get("redactions", {}).get("truncated_nodes", 0):
            source["issues"].add("incomplete_metadata")
    return sources


def inventory_sources(snapshot):
    reports, inventory, sources = snapshot.get("collections"), snapshot.get("inventory"), {}
    require(type(reports) is dict and type(inventory) is list)
    for operation, report in reports.items():
        require(operation in SOURCES and type(report) is dict)
        source = new_source(operation, {}, report.get("coverage"), "/collections/" + operation)
        if report.get("invalid_records", 0) or report.get("duplicate_observations", 0):
            source["issues"].add("invalid_or_duplicate_records")
        sources[canonical([operation, {}])] = source
    for index, entry in enumerate(inventory):
        require(type(entry) is dict and type(entry.get("observations")) is list)
        for obs_index, observation in enumerate(entry["observations"]):
            require(type(observation) is dict and observation.get("source") in reports)
            operation = observation["source"]
            source = sources[canonical([operation, {}])]
            fields = observation.get("fields")
            require(type(fields) is dict and all(type(v) is dict for v in fields.values()))
            identifier = fields.get(SOURCES[operation]["id_field"], {})
            key = (
                record_identity({"id": identifier.get("value")}, ("id",))
                if identifier.get("state") == "present"
                else None
            )
            # Normalized timestamps and observation-time derived expiry are local artifacts.
            value = {
                "fields": {
                    name: {k: v for k, v in field.items() if k != "normalized_utc"}
                    for name, field in fields.items()
                },
                "record_contract": observation.get("record_contract"),
                "parent_states": observation.get("parent_states"),
            }
            add_row(
                source, key, value, "/inventory/" + str(index) + "/observations/" + str(obs_index)
            )
    for source in sources.values():
        report = reports[source["operation"]]
        saved = sum(len(rows) for rows in source["rows"].values()) + source["unidentified_records"]
        if "accepted_records" in report and (
            type(report["accepted_records"]) is not int or report["accepted_records"] != saved
        ):
            source["issues"].add("saved_record_count_mismatch")
        if report.get("pages") == 0 and source["coverage"] == "complete":
            source["issues"].add("missing_pages")
    return sources


def diff_paths(before, after, path=""):
    """Return changed/unknown JSON pointers; never return field values."""
    if any(type(value) is dict and "_cremore_omitted" in value for value in (before, after)):
        return [], [path]
    if before is MISSING or after is MISSING:
        if incomplete_metadata(before if after is MISSING else after):
            return [], [path]
        return [path], []
    if type(before) is not type(after):
        return [path], []
    if type(before) is dict:
        if any(key.startswith("_cremore_omitted_tail") for key in set(before) | set(after)):
            return [], [path]
        changes, unknown = [], []
        for key in sorted(set(before) | set(after)):
            changed, omitted = diff_paths(
                before.get(key, MISSING), after.get(key, MISSING), path + "/" + pointer_part(key)
            )
            changes.extend(changed)
            unknown.extend(omitted)
        return changes, unknown
    if type(before) is list:
        if incomplete_metadata(before) or incomplete_metadata(after):
            return [], [path]
        # Arrays stay ordered. No common schema or unordered-field contract is imposed.
        changes, unknown = [], []
        for index in range(max(len(before), len(after))):
            changed, omitted = diff_paths(
                before[index] if index < len(before) else MISSING,
                after[index] if index < len(after) else MISSING,
                path + "/" + str(index),
            )
            changes.extend(changed)
            unknown.extend(omitted)
        return changes, unknown
    return ([path], []) if before != after else ([], [])


def source_summary(source):
    if source is None:
        return {"coverage": "not_observed", "issues": ["source_not_observed"]}
    return {
        "coverage": source["coverage"],
        "issues": sorted(source["issues"]),
        "source_ref": source["ref"],
        "unidentified_records": source["unidentified_records"],
    }


def comparable_absence(source):
    return source is not None and source["coverage"] == "complete" and not source["issues"]


def input_limits(snapshot):
    """Only fixed reason codes; do not expose target identifiers in a summary."""
    reasons = []
    if snapshot.get("run_status", "complete") != "complete":
        reasons.append("collection_run_incomplete")
    for key in (
        "targets_omitted_by_limit",
        "key_details_omitted_by_limit",
        "runner_details_omitted_by_limit",
        "invalid_identifiers",
        "count_ids_exceeding_contract_limit",
    ):
        value = snapshot.get(key, 0)
        present = any(value.values()) if type(value) is dict else bool(value)
        if present:
            reasons.append(key)
    if snapshot.get("target_discovery", {}).get("invalid_identifiers", 0):
        reasons.append("invalid_discovered_identifiers")
    return reasons


def compare_snapshots(before, after):
    for snapshot in (before, after):
        bounded_json(snapshot)
    before_scope, after_scope = scope(before), scope(after)
    require(before_scope == after_scope)
    require(timestamp(before["finished_at"]) <= timestamp(after["started_at"]))
    extract = inventory_sources if before_scope["report_type"] == "inventory" else discovery_sources
    old_sources, new_sources = extract(before), extract(after)
    limits = {"before": input_limits(before), "after": input_limits(after)}
    sources, counts = compare_sources(old_sources, new_sources)
    return {
        "schema_version": 1,
        "report_type": "metadata_snapshot_comparison",
        "scope": before_scope,
        "before_window": {k: before[k] for k in ("started_at", "finished_at")},
        "after_window": {k: after[k] for k in ("started_at", "finished_at")},
        "comparison_status": "limited"
        if counts["limited_sources"] or not counts["sources"] or any(limits.values())
        else "complete",
        "input_limits": limits,
        "inventory_complete": False,
        "counts": dict(counts),
        "sources": sources,
        "limitations": [
            "absence_does_not_prove_revocation",
            "authentication_visibility_not_verified",
            "observations_are_not_unique_credentials",
            "nested_arrays_are_ordered",
            "collection_windows_are_not_atomic",
        ],
    }


def compare_sources(old_sources, new_sources):
    """Compare validated source-local observations, preserving unknown absence."""
    sources, counts = [], Counter({event: 0 for event in EVENTS})
    counts.update({"unchanged_observations": 0, "sources": 0, "limited_sources": 0})
    for source_key in sorted(set(old_sources) | set(new_sources)):
        old, new = old_sources.get(source_key), new_sources.get(source_key)
        basis = new or old
        # Unrequested legacy slots are not observations.
        if all(s is None or s["coverage"] == "not_requested" for s in (old, new)):
            continue
        limited = not (comparable_absence(old) and comparable_absence(new))
        item = {
            "operation": basis["operation"],
            "context": basis["context"],
            "before": source_summary(old),
            "after": source_summary(new),
            "events": [],
            "unchanged_observations": 0,
        }
        old_rows, new_rows = (old["rows"] if old else {}), (new["rows"] if new else {})
        for record_key in sorted(set(old_rows) | set(new_rows)):
            left, right = old_rows.get(record_key, []), new_rows.get(record_key, [])
            event = {
                "identity": (right or left)[0]["identity"],
                "before_refs": [r["ref"] for r in left],
                "after_refs": [r["ref"] for r in right],
            }
            if len(left) > 1 or len(right) > 1:
                event.update(change_type="observation_unknown", reason="duplicate_identity")
            elif not left:
                event.update(
                    change_type="first_observed", baseline_complete=comparable_absence(old)
                )
            elif not right:
                event.update(
                    change_type="not_observed"
                    if comparable_absence(new)
                    else "observation_unknown",
                    reason="absent_from_complete_source"
                    if comparable_absence(new)
                    else "current_source_incomplete",
                )
            else:
                changed, unknown = diff_paths(left[0]["value"], right[0]["value"])
                if not changed and not unknown:
                    item["unchanged_observations"] += 1
                    counts["unchanged_observations"] += 1
                    continue
                event.update(
                    change_type="metadata_changed" if changed else "metadata_unknown",
                    changed_paths=changed,
                    unknown_paths=unknown,
                )
                if unknown:
                    limited = True
            item["events"].append(event)
            counts[event["change_type"]] += 1
        item["comparison_limited"] = limited
        counts["limited_sources"] += int(limited)
        counts["sources"] += 1
        sources.append(item)
    return sources, counts


def main(argv=None, *, directory=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True, help="Earlier saved collector JSON.")
    parser.add_argument(
        "--after",
        required=True,
        help="Later saved collector JSON of the same scope, mode and profile.",
    )
    parser.add_argument(
        "--output-dir", type=Path, help="Existing private directory (mode 700); defaults to .local."
    )
    args = parser.parse_args(argv)
    output_dir = args.output_dir or directory or Path.cwd() / ".local"
    try:
        before, before_hash = load_snapshot(args.before)
        after, after_hash = load_snapshot(args.after)
        result = compare_snapshots(before, after)
        result["input_sha256"] = {"before": before_hash, "after": after_hash}
        filename = save_private(output_dir, result, prefix="comparison")
    except KeyboardInterrupt:
        parser.exit(130, "Comparison interrupted.\n")
    except Exception:  # noqa: BLE001 - CLI/QA boundary must suppress credential-bearing errors.
        parser.exit(
            2,
            "Comparison failed: check input format, scope, time order and private output directory. Details suppressed.\n",
        )
    # No IDs, paths supplied by the user, field names or provider values on stdout.
    print(
        json.dumps(
            {
                "comparison_status": result["comparison_status"],
                "counts": result["counts"],
                "output_file": filename,
            },
            indent=2,
        )
    )
    return 1 if result["comparison_status"] == "limited" else 0


if __name__ == "__main__":
    raise SystemExit(main())
