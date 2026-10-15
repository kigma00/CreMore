"""Reconstruct coherent native views from committed typed observation records."""

from __future__ import annotations

from copy import deepcopy

from .compare import compare_snapshots
from .metadata import group_inventory, oauth_link_candidates
from .projection import decode_observation, record_facts, source_key
from .recollect import build_plan
from .snapshot import field_catalog
from .specs import SOURCES


def operations_from_records(records, scope, *, complete_only=False):
    """One terminal operation attempt per source; never combine retry pages."""
    groups = {}
    for value in records:
        record = value.model_dump() if hasattr(value, "model_dump") else value
        if record.get("scope") != scope.model_dump():
            continue
        decoded = record_facts(record)
        context = decoded.get("context", {})
        if context.get("stage") not in {
            "row",
            "normalized",
            "detail",
            "page_header",
            "operation_complete",
        }:
            continue
        key = (context.get("source"), context.get("attempt"))
        groups.setdefault(key, []).append((record, decoded, context))
    latest = {}
    for (source, attempt), pieces in groups.items():
        terminals = [piece for piece in pieces if piece[2]["stage"] == "operation_complete"]
        if len(terminals) != 1:
            continue
        report = deepcopy(terminals[0][1].get("metadata", {}))
        operation = terminals[0][2]["operation"]
        if source != source_key(
            operation, report.get("target_id"), report.get("requested_account_ids")
        ):
            raise ValueError("ATLASSIAN_INVALID_SOURCE_ID")
        if complete_only and (
            report.get("coverage") != "complete"
            or any(piece[0].get("omissions") for piece in pieces)
        ):
            continue
        if source in latest and latest[source][0] >= attempt:
            continue
        page_count = report.pop("page_count", 0)
        inventory = (
            any(piece[2]["stage"] == "normalized" for piece in pieces)
            or terminals[0][0].get("collection_mode") == "inventory"
        )
        observations = []
        headers = sorted(
            (piece for piece in pieces if piece[2]["stage"] == "page_header"),
            key=lambda piece: piece[2]["page_number"],
        )
        if [piece[2]["page_number"] for piece in headers] != list(range(1, page_count + 1)):
            continue
        if inventory:
            report["pages"] = page_count
            for _, decoded, context in sorted(
                pieces,
                key=lambda piece: (piece[2].get("page_number", 0), piece[2].get("row_index", -1)),
            ):
                if context["stage"] == "normalized":
                    observations.append(decode_observation(decoded["metadata"]))
        else:
            report["pages"] = []
            report["operation"] = operation
            for record, decoded, context in headers:
                page = deepcopy(decoded["metadata"])
                body = deepcopy(decoded.get("fields", decoded.get("public_key")))
                container = context["container_name"]
                rows = [
                    piece
                    for piece in pieces
                    if piece[2]["stage"] == "row"
                    and piece[2]["page_number"] == context["page_number"]
                ]
                rows.sort(key=lambda piece: piece[2]["row_index"])
                if [piece[2]["row_index"] for piece in rows] != list(range(len(rows))):
                    raise ValueError("ATLASSIAN_INCOMPLETE_PAGE")
                values = []
                for row_record, row_decoded, _ in rows:
                    row = deepcopy(row_decoded["metadata"])
                    if row_record.get("omissions") and isinstance(row, dict):
                        row["_cremore_omitted"] = "typed_projection"
                    values.append(row)
                if container == "array":
                    body = values
                elif container != "scalar":
                    if not isinstance(body, dict):
                        raise ValueError("ATLASSIAN_INCOMPLETE_PAGE")
                    body[container] = values
                if record.get("omissions"):
                    page.setdefault("redactions", {})["truncated_nodes"] = max(
                        1, page.get("redactions", {}).get("truncated_nodes", 0)
                    )
                page["metadata"] = body
                page["field_types"] = field_catalog(body)
                report["pages"].append(page)
        # Omitted metadata is unknown even if the transport finished.
        if (
            any(piece[0].get("omissions") for piece in pieces)
            and report.get("coverage") == "complete"
        ):
            report["coverage"], report["reason"] = "unverified", "typed_projection_omissions"
        latest[source] = (attempt, report, observations)
    return {source: (report, observations) for source, (_, report, observations) in latest.items()}


def native_snapshots(records):
    """Return one finished view per approved root scope, suitable for compare/plan."""
    records = list(records)
    summaries = {}
    from cremore.coverage.metadata_models import MetadataScope

    for value in records:
        record = value.model_dump() if hasattr(value, "model_dump") else value
        decoded = record_facts(record)
        context = decoded.get("context", {})
        if context.get("stage") == "run_summary":
            key = (record["scope"]["kind"], record["scope"]["id"])
            previous = summaries.get(key)
            if previous is None or context["attempt"] > previous[1]["attempt"]:
                summaries[key] = (decoded["metadata"], context)
    result = []
    for (kind, identifier), (header, context) in summaries.items():
        scope = MetadataScope(kind=kind, id=identifier)
        operations = operations_from_records(records, scope)
        snapshot = deepcopy(header)
        if context["mode"] == "inventory":
            snapshot["collections"] = {name: {"coverage": "not_requested"} for name in SOURCES}
            observations = []
            for source, (report, items) in operations.items():
                operation = next((name for name in SOURCES if source_key(name) == source), None)
                if operation is not None:
                    snapshot["collections"][operation] = report
                observations.extend(items)
            snapshot["inventory"] = group_inventory(observations)
            snapshot["identity_link_candidates"] = oauth_link_candidates(snapshot["inventory"])
        else:
            snapshot["collections"] = [report for report, _ in operations.values()]
        if "warning_counts" in snapshot and isinstance(snapshot["warning_counts"], list):
            snapshot["warning_counts"] = {
                item["name"]: item["count"] for item in snapshot["warning_counts"]
            }
        snapshot["_common_config_hash"] = context["config_hash"]
        result.append(snapshot)
    return result


def _select(records, scope_id):
    snapshots = native_snapshots(records)
    if scope_id is not None:
        snapshots = [
            value
            for value in snapshots
            if value.get("queried_org_id", value.get("workspace")) == scope_id
        ]
    if len(snapshots) != 1:
        raise ValueError("ATLASSIAN_FINISHED_SCOPE_REQUIRED")
    return snapshots[0]


def compare_records(before_records, after_records, *, scope_id=None):
    before, after = _select(before_records, scope_id), _select(after_records, scope_id)
    if before["_common_config_hash"] != after["_common_config_hash"]:
        raise ValueError("ATLASSIAN_COMPARE_CONFIGURATION_MISMATCH")
    return compare_snapshots(before, after)


def plan_recollection(records, *, scope_id=None, operations=None, include_unverified=False):
    return build_plan(
        _select(records, scope_id), operations=operations, include_unverified=include_unverified
    )
