"""Build GitLab 1.4 inventory from committed worker observations."""
from copy import deepcopy

from .audit import enrich_from_audit, token_audit_scopes
from .audit_coverage import CreationCoverageIndex, query_status
from .metadata_policy import METADATA_POLICY
from .model import metadata_view, observed_scopes

SCHEMA_VERSION = "1.4"

def inventory_rows(self):
    events_by_record = {}
    for event in self.audit_events():
        events_by_record.setdefault(event["inventory_id"], []).append(event)
    config = self.get_setting("config") or {}
    audit_enabled = config.get("include_audit_events") or config.get(
        "include_deploy_token_audit"
    )
    tasks_by_scope = {}
    for task in self.coverage():
        if task["handler"] in {"audit_plan", "audit_events"}:
            scope = task["context"]["scope"]
            tasks_by_scope.setdefault((scope["kind"], scope["id"]), []).append(task)
    creation_coverage = CreationCoverageIndex(
        tasks_by_scope, config, self.get_setting("coverage_notes") or [])
    for record_id in sorted(self.state["records"]):
        value = self.state["records"][record_id]
        observations = [
            deepcopy(value["observations"][key]) for key in sorted(value["observations"])
        ]
        metadata, summary = metadata_view(observations)
        evidence = events_by_record.get(record_id, []) if audit_enabled else []
        if audit_enabled:
            enrich_from_audit(summary, evidence)
        scopes = token_audit_scopes(value["identity"]["scope"], observations)
        tasks = (
            [task for scope in sorted(scopes) for task in tasks_by_scope.get(scope, [])]
            if audit_enabled else []
        )
        queried = {
            (task["context"]["scope"]["kind"], task["context"]["scope"]["id"])
            for task in tasks
        }
        audit = {
            "query_status": query_status(tasks) if audit_enabled else "disabled",
            "source_ids": [task["source_id"] for task in tasks],
            "query_scope": "group_project_only",
            "unqueried_scopes": [
                {
                    "kind": kind,
                    "id": identifier,
                    "reason": "user_audit_api_not_collected"
                    if kind == "user"
                    else "scope_not_scheduled",
                }
                for kind, identifier in sorted(scopes - queried)
            ],
            "matching_events": len(evidence),
            "matching_creation_events": sum(
                event["interpretation"].get("action") == "created" for event in evidence
            ),
            "event_refs": [
                {key: event[key] for key in ("audit_event_id", "event_id", "scope")}
                for event in evidence
            ],
            "event_details_file": "audit_events.json",
            "creation_evidence": creation_coverage.describe(metadata, scopes, evidence),
        }
        for relation in ("owner", "issuer"):
            person = summary[relation]
            profile = (
                self.asset_metadata("user", person["id"]) if person["id"] is not None else None
            )
            person["profile_status"] = (
                "not_applicable"
                if person["id"] is None
                else "observed"
                if profile is not None
                else "not_observed"
            )
            if profile is not None:
                person["profile"] = profile
        identity = value["identity"]
        yield {
            "token_id": identity["native_id"],
            "schema_version": SCHEMA_VERSION,
            "inventory_id": record_id,
            "identity": deepcopy(identity),
            "credential_types": list(value["families"]),
            "scope": deepcopy(identity["scope"]),
            "observed_scopes": observed_scopes(observations),
            "first_seen_at_this_run": value["first_seen"],
            "last_seen_at_this_run": value["last_seen"],
            "summary": summary,
            "metadata": metadata,
            "observations": observations,
            "audit": audit,
            "metadata_merge_policy": "handler_priority_deep_merge_v1",
            "metadata_policy": METADATA_POLICY,
        }
