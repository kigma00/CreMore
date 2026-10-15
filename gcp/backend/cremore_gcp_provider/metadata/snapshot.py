"""Rebuild the native connector's own JSON from the shared committed records.

The inventory, relationship and change views the operator knew from the native
CLI are reproduced here from typed records, so a run can still be read in the
shape the connector produced. Nothing is re-requested from the provider and no
value is ever reconstructed: only what the records already hold.
"""

from __future__ import annotations

import json

from . import NATIVE_INVENTORY_SCHEMA, NATIVE_RELATIONS_SCHEMA
from .normalization import record_values

_SOURCE_BY_OPERATION = {
    "gcp.service_accounts": "service_accounts",
    "gcp.service_account_keys": "service_account_keys",
    "gcp.api_keys": "api_keys",
    "gcp.secret_manager": "secret_manager",
    "gcp.secret_manager_locations": "secret_manager_locations",
    "gcp.secret_versions": "secret_versions",
    "gcp.value_access": "value_reads",
}
_STATUS = {"COMPLETE": "complete", "PARTIAL": "partial", "FAILED": "error",
           "UNSUPPORTED": "not_collected", "NOT_REQUESTED": "not_collected",
           "UNKNOWN": "not_collected"}
_ACCESS_RELATIONS = {
    "secret_access_observed", "secret_version_access_observed",
    "service_account_key_secret_access_observed",
    "service_account_key_version_access_observed",
}


def _coverage_name(item):
    operation = item["provenance"]["operation"]
    if operation == "gcp.secret_versions" and item["provenance"]["resource_id"]:
        # Each secret keeps its own version coverage, as the native watcher did.
        return "secret_versions:" + item["provenance"]["resource_id"]
    if operation.startswith("gcp.secret_manager_regional."):
        return "secret_manager_regional:" + operation.rsplit(".", 1)[-1]
    if operation.startswith(("gcp.cloud_", "gcp.iam_allow_policy")):
        return record_values(item).get("coverage_path")
    return _SOURCE_BY_OPERATION.get(operation)


def _item(values, kind):
    """One inventory row in the native vocabulary, rebuilt from its facts."""
    name = values.get("resource_name")
    if kind == "principal":
        return {"object_type": "principal", "credential_type": None,
                "source": "gcp_iam_service_accounts", "project_id": values.get("project_id"),
                "source_id": name, "service_account_email": values.get("service_account_email"),
                "disabled": values.get("disabled")}
    if kind == "credential" and (values.get("uid") is not None
                                 or (isinstance(name, str) and "/locations/global/keys/" in name)):
        restrictions = values.get("restrictions") or {}
        return {"object_type": "credential", "credential_type": "api_key",
                "source": "gcp_api_keys", "project_id": values.get("project_id"),
                "source_id": name, "key_id": values.get("key_id"),
                "api_key_uid": values.get("uid"), "created_at": values.get("created_at"),
                "updated_at": values.get("updated_at"), "deleted_at": values.get("deleted_at"),
                "client_restriction_type": restrictions.get("type"),
                "api_target_count": restrictions.get("count"),
                "service_account_email": values.get("service_account_email")}
    if kind == "credential":
        return {"object_type": "credential", "credential_type": values.get("key_type"),
                "source": "gcp_iam_service_account_keys", "project_id": values.get("project_id"),
                "source_id": name, "service_account_email": values.get("service_account_email"),
                "key_id": values.get("key_id"),
                "valid_after_time": values.get("valid_after_time"),
                "valid_before_time": values.get("valid_before_time"),
                "disabled": values.get("disabled"),
                "disable_reason": values.get("disabled_reason"),
                "key_origin": values.get("key_origin")}
    if kind == "vault_version":
        return {"object_type": "vault_version", "credential_type": "secret_version",
                "source": "gcp_secret_manager", "project_id": values.get("project_id"),
                "source_id": name, "state": values.get("state"),
                "created_at": values.get("created_at"),
                "destroyed_at": values.get("destroyed_at")}
    row = {"object_type": "vault_item", "credential_type": None, "source": "gcp_secret_manager",
           "project_id": values.get("project_id"), "source_id": name,
           "created_at": values.get("created_at"), "expires_at": values.get("expires_at"),
           "next_rotation_time": values.get("next_rotation_time")}
    if values.get("location") and values["location"] != "global":
        row["location"] = values["location"]
    return row


def _split(records):
    entities, relations, reports = [], [], []
    for item in records:
        kind = item.get("record_type")
        if kind == "entity_observation":
            entities.append(item)
        elif kind == "relation":
            relations.append(item)
        elif kind == "operation_report":
            reports.append(item)
    return entities, relations, reports


def native_snapshots(records):
    """The connector's inventory plus its relationship snapshot, side by side."""
    from .discovery import native_discovery

    records = list(records)
    entities, relations, reports = _split(records)
    coverage, api_states, project, collected = {}, {}, None, None
    for item in reports:
        values = record_values(item)
        if item.get("scope", {}).get("kind") == "project":
            project = project or item["scope"]["id"]
        collected = collected or item["provenance"]["observed_at"]
        if values.get("api_states"):
            api_states = {row["service"]: {"state": row["state"],
                                          "error_code": row["error_code"]}
                          for row in values["api_states"]}
        name = _coverage_name(item)
        if name is None:
            continue
        entry = {"status": _STATUS.get(item["status"], "not_collected"),
                 "pages_read": values.get("pages_read", item.get("pages", 0)),
                 "objects_seen": values.get("objects_seen", item.get("received_records", 0)),
                 "error_code": values.get("error_code")}
        for extra in ("accounts_checked", "accounts_seen", "locations_seen", "locations_checked",
                      "keys_checked", "points_seen", "series_seen", "invalid_identifiers",
                      "selection"):
            if values.get(extra) is not None:
                entry[extra] = values[extra]
        if values.get("error_counts"):
            entry["error_counts"] = {row["code"]: row["count"] for row in values["error_counts"]}
        coverage[name] = entry

    seen, items = set(), []
    for item in entities:
        if item["identity"]["kind"] == "resource":
            continue
        values = record_values(item)
        name = values.get("resource_name")
        if not isinstance(name, str) or name in seen:
            continue
        seen.add(name)
        project = project or values.get("project_id")
        items.append(_item(values, item["identity"]["kind"]))
    items.sort(key=lambda row: (row["object_type"], row["source_id"] or ""))
    inventory = {"schema_version": NATIVE_INVENTORY_SCHEMA, "provider": "gcp",
                 "project_id": project, "collected_at": collected, "scope": "one_project",
                 "items": items, "api_states": api_states, "coverage": coverage}
    result = {"inventory": inventory, "relations": _relations(relations, coverage, project, collected)}
    discovery = native_discovery(records)
    if discovery["resources"] or discovery["operations"]:
        result["discovery"] = discovery
    return result


def _relations(relations, coverage, project, collected):
    from .relations import edge_id

    edges, window = [], None
    for item in relations:
        values = record_values(item)
        if values.get("relation") is None or values.get("source_id") is None:
            continue
        path = values.get("coverage_path")
        edge = {
            "source_id": values["source_id"], "target_id": values.get("target_id"),
            "relation": values["relation"], "evidence_class": values.get("evidence_class"),
            "evidence_source": values.get("evidence_source"),
            "evidence_id": values.get("evidence_id"),
            "first_observed_at": item.get("window_start"),
            "last_observed_at": item.get("window_end"),
            "coverage_path": path,
            # Restored from that path's own report, which is what the native
            # collector stamped on every edge once its coverage was final.
            "collection_status": (coverage.get(path) or {}).get("status", "unknown"),
        }
        for extra in ("request_count", "caller_identity", "role", "policy_resource",
                      "condition_present", "effective_access", "secret_id", "version_id",
                      "inherited_policies", "deny_policies", "principal_access_boundaries",
                      "membership_resolution", "condition_evaluation",
                      "log_name", "insert_id", "method_name", "service"):
            if values.get(extra) is not None:
                edge[extra] = values[extra]
        edge["id"] = edge_id(edge)
        edges.append(edge)
        if item.get("window_start") and item.get("window_end"):
            window = {"start": item["window_start"], "end": item["window_end"]}
    edges.sort(key=lambda edge: (edge["target_id"] or "", edge["source_id"], edge["relation"],
                                 edge["id"]))
    secrets = {}
    for edge in edges:
        observed = edge["relation"] in _ACCESS_RELATIONS
        if not observed and edge["evidence_class"] != "policy_possible":
            continue
        key = edge.get("secret_id") or edge["target_id"]
        current = secrets.setdefault(key, {
            "status": "unknown", "relation_ids": [],
            "missing_logs_mean": "unknown_not_unused",
            "secret_access_log_coverage": (coverage.get("secret_access_logs") or {}).get(
                "status", "unknown"),
            "secret_iam_policy_coverage": (coverage.get("secret_iam_policies") or {}).get(
                "status", "unknown"),
        })
        current["relation_ids"].append(edge["id"])
        if observed:
            current["status"] = "observed_access"
        elif current["status"] != "observed_access":
            current["status"] = "policy_possible"
    return {"schema_version": NATIVE_RELATIONS_SCHEMA, "provider": "gcp", "project_id": project,
            "collected_at": collected, "window": window, "scope": "one_project_global_secrets",
            "coverage": coverage, "relations": edges, "secret_index": secrets}


def compare_records(records, previous, *, spec=None):
    """The watcher's change vocabulary, computed between two committed runs.

    Absence is only meaningful where the later run listed the whole path: a
    source that failed or was never requested leaves the object untouched.
    """
    after = _index(records)
    before = _index(previous)
    coverage = native_snapshots(records)["inventory"]["coverage"]
    events, value_unknown = [], []
    values_complete = all(any(
        item.get("record_type") == "operation_report"
        and item.get("provenance", {}).get("operation") == "gcp.value_access"
        and item.get("value_access") == "COMPLETE" for item in rows
    ) for rows in (records, previous))
    for name in sorted(after):
        current, old = after[name], before.get(name)
        if old is None:
            events.append(_event(name, "discovered", None, current["lifecycle_state"]))
            continue
        if old["lifecycle_state"] != current["lifecycle_state"]:
            events.append(_event(name, "state_changed", old["lifecycle_state"],
                                 current["lifecycle_state"]))
        elif old["metadata"] != current["metadata"]:
            events.append(_event(name, "metadata_changed", old["lifecycle_state"],
                                 current["lifecycle_state"]))
        kind, reason = value_change(old, current, complete=values_complete)
        if kind:
            events.append(_event(name, kind, old["lifecycle_state"], current["lifecycle_state"]))
        if reason:
            value_unknown.append({"source_id": name, "reason": reason})
    unlisted = []
    for name in sorted(before):
        if name in after:
            continue
        path = before[name]["coverage_path"]
        paths = [path, "service_accounts"] if path == "service_account_keys" else [path]
        if any((coverage.get(p) or {}).get("status") != "complete" for p in paths):
            unlisted.append({"source_id": name, "reason": "source_not_completely_listed"})
            continue
        if before[name]["lifecycle_state"] in ("deleted", "destroyed", "no_longer_listed"):
            continue
        events.append(_event(name, "no_longer_listed", before[name]["lifecycle_state"],
                             "no_longer_listed"))
    return {"schema_version": NATIVE_RELATIONS_SCHEMA, "provider": "gcp",
            "project_id": native_snapshots(records)["inventory"]["project_id"],
            "events": events, "objects_before": len(before), "objects_after": len(after),
            "absence_not_evaluated": unlisted, "value_not_evaluated": value_unknown}


def _event(name, kind, before, after):
    return {"source_id": name, "event_type": kind, "previous_state": before,
            "current_state": after}


def value_change(old, current, *, complete):
    """Compare whole-payload HMACs; older observations retain their detected-value contract."""
    prior_payload, latest_payload = old.get("payload_digest"), current.get("payload_digest")
    if prior_payload or latest_payload:
        if not prior_payload:
            return "value_collected", None
        reason = ("value_unavailable" if not latest_payload else
                  "value_contract_changed" if any(prior_payload[name] != latest_payload[name]
                                                   for name in ("scheme", "key_id")) else
                  "value_collection_incomplete" if not complete else None)
        if reason:
            return None, reason
        return ("value_changed", None) if prior_payload["fingerprint"] != latest_payload["fingerprint"] else (None, None)
    prior, latest = old.get("values", {}), current["values"]
    if old.get("fingerprint") and not prior:
        return None, "value_contract_not_recorded"
    if latest and not prior:
        return "value_collected", None
    if prior:
        reason = ("value_unavailable" if not latest else
                  "value_contract_changed" if prior.keys() != latest.keys() else
                  "value_collection_incomplete" if not complete else None)
        if reason:
            return None, reason
        if prior != latest:
            return "value_changed", None
    return None, None


def _index(records):
    from .collector import lifecycle

    index = {}
    for item in records:
        if item.get("record_type") != "entity_observation" or item["identity"]["kind"] == "resource":
            continue
        values = record_values(item)
        name = values.get("resource_name")
        if not isinstance(name, str):
            continue
        row = _item(values, item["identity"]["kind"])
        entry = index.setdefault(name, {"metadata": row, "fingerprint": None, "values": {}, "payload_digest": None,
                                        "coverage_path": _path(row),
                                        "lifecycle_state": lifecycle(row)})
        if item.get("payload_digest"):
            entry["payload_digest"] = item["payload_digest"]
        match = item.get("value_match")
        if match and match.get("evidence") == "VALUE":
            contract = json.dumps([match.get(key) for key in (
                "scheme", "key_id", "engine_digest", "policy_digest", "material_kind")], separators=(",", ":"))
            entry["fingerprint"] = match["fingerprint"]  # legacy stored/public projection
            entry["values"].setdefault(contract, set()).add(
                (match.get("credential_type"), match["fingerprint"]))
    for entry in index.values():
        entry["values"] = {contract: [list(value) for value in sorted(values)]
                           for contract, values in sorted(entry["values"].items())}
    return index


def _path(row):
    source, kind = row["source"], row["object_type"]
    if kind == "vault_version":
        return "secret_versions:" + row["source_id"].split("/versions/")[0]
    if source == "gcp_iam_service_accounts":
        return "service_accounts"
    if source == "gcp_iam_service_account_keys":
        return "service_account_keys"
    if source == "gcp_api_keys":
        return "api_keys"
    return ("secret_manager_regional:" + row["location"]) if row.get("location") else "secret_manager"
