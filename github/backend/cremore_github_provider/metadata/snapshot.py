"""Rebuild both programs' own JSON views from the records a run committed.

The organization view groups each source's records the way the per-collector
scripts printed them; the Enterprise view is the scan summary its checkpoint
carried. Nothing is re-requested, and a task that failed keeps its reason rather
than appearing as a source with no records.
"""

from __future__ import annotations

import re

from . import API_VERSION, NATIVE_SCHEMA
from .normalization import record_values
from .permissions import organization_health, planned_kinds

_SOURCE_BY_KIND = {
    "org_sso": "organization_saml_sso_authorizations",
    "org_fgpat": "organization_fine_grained_pat",
    "org_fgpat_repositories": "organization_fine_grained_pat_repositories",
    "org_pat_requests": "organization_pat_requests",
    "org_installations": "organization_github_app_installations",
    "org_repositories": "collector_accessible_repositories",
    "org_workflow_policy": "github_actions_token_policy_context",
    "repo_deploy_keys": "repository_deploy_keys",
    "repo_workflow_policy": "github_actions_token_policy_context",
    "repo_actions_policy": "github_actions_token_policy_context",
    "repo_fork_policy": "github_actions_token_policy_context",
    "repo_actions_runs": "github_actions_token_policy_and_run_context",
    "run_jobs": "github_actions_token_policy_and_run_context",
    "org_actions_secrets": "github_actions_organization_secret_metadata",
    "repo_actions_secrets": "github_actions_repository_secret_metadata",
    "environment_actions_secrets": "github_actions_environment_secret_metadata",
    "repo_environments": "github_actions_repository_environments",
    "org_secret_repositories": "github_actions_secret_selected_repositories",
    "enterprise_org_installations": "enterprise_organization_installations",
    "enterprise_org_repositories": "enterprise_organization_repositories",
    "enterprise_installation_repositories": "enterprise_organization_installation_repositories",
}
_STATUS = {"COMPLETE": True, "FAILED": False, "PARTIAL": False, "NOT_REQUESTED": False,
           "UNSUPPORTED": False, "UNKNOWN": False}
# Reads about the Enterprise or the App as a whole, never about one organization.
_ENTERPRISE_KINDS = ("inventory", "organizations", "audit", "git_audit", "app")

def _split(records):
    entities, events, reports = [], [], []
    for item in records:
        kind = item.get("record_type")
        if kind == "entity_observation":
            entities.append(item)
        elif kind == "provider_event" and item.get("event_type") != "token_activity":
            # GitHub's own audit vocabulary; CreMore's keyed summaries are not entries.
            events.append(item)
        elif kind == "operation_report":
            reports.append(item)
    return entities, events, reports


def _combined_status(reports):
    # NOT_REQUESTED is an org audit the completed Enterprise audit covered; like the platform
    # (store.py), it never makes a source incomplete.
    statuses = {report["status"] for report in reports}
    if statuses == {"NOT_REQUESTED"}:
        return "NOT_REQUESTED"
    statuses.discard("NOT_REQUESTED")
    return ("NOT_COLLECTED" if not statuses else "COMPLETE" if statuses == {"COMPLETE"}
            else "PARTIAL" if "COMPLETE" in statuses or "PARTIAL" in statuses
            else "FAILED" if "FAILED" in statuses else "UNKNOWN")


def _source_summary(rows):
    if len(rows) == 1:
        return rows[0]
    status = _combined_status(rows)
    endpoints = {row["endpoint"] for row in rows}
    # A source can span repositories. Keep each endpoint in tasks; naming one
    # here would attribute the aggregate counts and failures to that one repo.
    return {**rows[0], "endpoint": next(iter(endpoints)) if len(endpoints) == 1 else None,
            "status": status, "complete": status == "COMPLETE",
            "pages_succeeded": sum(row["pages_succeeded"] for row in rows),
            "records_collected": sum(row["records_collected"] for row in rows),
            "error": ", ".join(sorted({row["error"] for row in rows if row["error"]})) or None,
            "warnings": sorted({warning for row in rows for warning in row["warnings"]})}


def native_snapshots(records):
    records = list(records)
    entities, events, reports = _split(records)
    organizations, tasks, warnings = {}, [], []
    source_tasks = {}
    inventory, authorizations, generated_at, window = [], [], None, None
    enterprise, app = "", None
    # Discovery is evidence even when the App cannot read any organization
    # endpoint yet, or the worker has not reached those tasks. Keep every page.
    for item in entities:
        if item["provenance"]["operation"] == "github.organizations":
            for name in record_values(item).get("organization", []):
                organizations.setdefault(name, {"org": name, "sources": {}, "records": {}})
    for item in reports:
        values = record_values(item)
        kind = values.get("kind") or item["provenance"]["operation"].removeprefix("github.")
        scope = values.get("scope") or ""
        row = {"kind": kind, "scope": scope, "endpoint": values.get("path"),
               "status": item["status"], "complete": _STATUS.get(item["status"], False),
               "pages_succeeded": item["pages"], "records_collected": item["saved_records"],
               "error": (item["reasons"] or [None])[0],
               "warnings": values.get("warnings") or []}
        tasks.append(row)
        warnings.extend(row["warnings"])
        generated_at = values.get("generated_at") or generated_at
        if values.get("window_start"):
            window = window or {"start": values["window_start"]}
        if kind in _ENTERPRISE_KINDS and not enterprise:
            enterprise = scope
        if scope and kind not in _ENTERPRISE_KINDS + CHECK_OPERATIONS:
            organizations.setdefault(scope, {"org": scope, "sources": {}, "records": {}})
            source_tasks.setdefault((scope, kind), []).append(row)

    for (scope, kind), rows in source_tasks.items():
        organizations[scope]["sources"][kind] = {
            "source": _SOURCE_BY_KIND.get(kind, kind), **_source_summary(rows)}

    for item in entities:
        values = record_values(item)
        operation = item["provenance"]["operation"].removeprefix("github.")
        if operation == "inventory":
            if item["identity"]["kind"] == "context":
                authorizations.append(values)
            else:
                inventory.append(values)
            continue
        if operation == "app":
            app = app_identity(item)
            continue
        if operation in _ENTERPRISE_KINDS:
            continue
        scope = _owner(values, item)
        if not scope:
            continue
        group = organizations.setdefault(scope, {"org": scope, "sources": {}, "records": {}})
        bucket = group["records"].setdefault(_group_for(item["identity"]["kind"], operation), [])
        bucket.append(values)

    audit = [record_values(item) | {"action": item["event_type"], "_document_id": item["event_id"],
                                    "created_at": item["occurred_at"]} for item in events]
    authorizations.extend(record_values(item) for item in records if item.get("record_type") == "relation"
                          and item.get("provenance", {}).get("operation") == "github.inventory")
    from .audit_links import audit_links
    return {
        "organizations": {name: value for name, value in sorted(organizations.items())},
        "enterprise": {
            "schema_version": NATIVE_SCHEMA, "api_version": API_VERSION,
            "enterprise": enterprise, "app": app, "window": window, "generated_at": generated_at,
            "inventory_count": len(inventory), "inventory": inventory,
            "authorizations": authorizations,
            "unidentified_rows": sum(row.get("basis") == "EXPORT_ROW_ONLY" for row in inventory),
            "audit_count": len(audit), "audit_events": audit,
            # Which credential each event names, by exact identifiers only, and
            # every event none could place (with the reason).
            "audit_links": audit_links(records),
            "inventory_complete": any(t["kind"] == "inventory" and t["complete"] for t in tasks),
            "warnings": sorted(set(warnings)), "tasks": tasks,
        },
    }


# Reads of an installation check run (plan_recollection), which collects no credentials.
CHECK_OPERATIONS = ("installation_check", "app_installations")
# Where this App's own installation on an organization was observed.
INSTALLATION_OPERATIONS = ("installation", *CHECK_OPERATIONS)
# Why an organization's installation lookup gave no installation to compare.
_REFUSAL = re.compile(r"(?:ORGANIZATION|ENTERPRISE)_INSTALLATION_[A-Z0-9_]{1,80}|INSTALLATION_NOT_AUTHORIZED")


def installation_state(record):
    """The facts an organization's health is judged on, from one installation record."""
    values = record_values(record)
    return {"installed": True, "suspended": bool(values.get("suspended_at")),
            "installation_id": values.get("id"), "repository_selection": values.get("repository_selection"),
            "permissions": {grant["name"]: (grant.get("actions") or [None])[0]
                            for grant in record.get("permissions") or [] if grant.get("kind") == "permission"},
            "checked_at": record["provenance"]["observed_at"],
            "basis": record["provenance"]["operation"].removeprefix("github.")}


def installation_check_run(reports):
    """Whether a run is an installation check: every report of one says so."""
    return any(report.get("collection_mode") == "installation_check" for report in reports)


def _overlay(checks, organizations, installations, failures):
    """Apply installation checks newer than the collection, oldest first; the newest word wins.

    A failed lookup supersedes an older observation in this view (it is unknown
    now, never not installed). Only a complete installation list shows that an
    organization the collection knew has no installation of this App.
    """
    app = None
    for records in checks:
        seen, planned, complete, checked_at = set(), set(), False, None
        for item in records:
            operation = item["provenance"]["operation"].removeprefix("github.")
            values = record_values(item)
            if item["record_type"] == "entity_observation" and operation == "app":
                app = app_identity(item)
            elif item["record_type"] == "entity_observation" and operation in CHECK_OPERATIONS:
                org = values.get("org")
                if isinstance(org, str) and org:
                    installations[org.casefold()] = installation_state(item)
                    failures.pop(org.casefold(), None)
                    seen.add(org.casefold())
            elif item["record_type"] == "operation_report" and operation == "installation_check":
                name = (values.get("scope") or "").casefold()
                if name and item["status"] != "COMPLETE":
                    installations.pop(name, None)
                    refused = [reason for reason in item.get("reasons") or [] if _REFUSAL.fullmatch(reason)]
                    failures[name] = (refused or item.get("reasons") or ["INSTALLATION_CHECK_FAILED"])[0]
            elif item["record_type"] == "operation_report" and operation == "app_installations":
                complete, checked_at = item["status"] == "COMPLETE", item["provenance"]["observed_at"]
                planned = {name.casefold() for name in values.get("organization") or [] if isinstance(name, str)}
        if complete:
            # Only an organization the listing was checking can be absent from it.
            for name in organizations:
                if name.casefold() in planned and name.casefold() not in seen:
                    installations[name.casefold()] = {"installed": False, "checked_at": checked_at,
                                                      "basis": "app_installations"}
                    failures.pop(name.casefold(), None)
    return app


def app_identity(record):
    """The App a run confirmed (GET /app), with the permissions it asks installations for."""
    return {**record_values(record), "permissions": {
        grant["name"]: (grant.get("actions") or [None])[0]
        for grant in record.get("permissions") or [] if grant.get("kind") == "permission"}}


def organization_roster(records, *, spec=None, checks=()):
    """Stream a small, metadata-only roster, including discovered unread orgs.

    Keep the worst status across repository tasks of the same source; the
    final successful repository must not hide an earlier permission failure.
    Each organization's health compares this App's installation permissions
    with the reads it ran (or, unread, would start with); ``checks`` are the
    records of installation check runs newer than this collection, one list per
    run, oldest first. No credential facts or secret references are returned.
    """
    organizations, discovery = {}, []
    installations, failures, app, check_run = {}, {}, None, False

    def group(name):
        return organizations.setdefault(name, {})

    def summary(reports):
        return {"status": _combined_status(reports),
                "reasons": sorted({reason for report in reports
                                   for reason in report.get("reasons", [])}),
                "pages": sum(report.get("pages", 0) for report in reports)}

    for item in records:
        operation = item["provenance"]["operation"].removeprefix("github.")
        if item["record_type"] == "entity_observation" and operation == "organizations":
            for name in record_values(item).get("organization", []):
                group(name)
        elif item["record_type"] == "entity_observation" and operation in INSTALLATION_OPERATIONS:
            org = record_values(item).get("org")
            if isinstance(org, str) and org:
                installations[org.casefold()] = installation_state(item)
        elif item["record_type"] == "entity_observation" and operation == "app":
            app = app_identity(item)
        elif item["record_type"] == "operation_report":
            check_run = check_run or item.get("collection_mode") == "installation_check"
            if operation == "organizations":
                discovery.append(item)
            elif operation not in _ENTERPRISE_KINDS + CHECK_OPERATIONS:
                name = record_values(item).get("scope")
                if name:
                    group(name).setdefault(operation, []).append(
                        {key: item[key] for key in ("status", "reasons", "pages")})
                    refused = [reason for reason in item.get("reasons") or [] if _REFUSAL.fullmatch(reason)]
                    if refused:
                        failures.setdefault(name.casefold(), refused[0])
    app = _overlay(checks, organizations, installations, failures) or app
    planned = planned_kinds(spec) if spec is not None else set()
    return {"discovery": summary(discovery), "app": app, "installation_check": check_run, "items": [
        {"org": name, **summary([report for rows in sources.values() for report in rows]),
         "sources": [{"kind": kind, **summary(rows)} for kind, rows in sorted(sources.items())],
         "health": organization_health(installations.get(name.casefold()), set(sources) or planned,
                                       failure=failures.get(name.casefold()))}
        for name, sources in sorted(organizations.items())]}


def _owner(values, item):
    for key in ("org", "scope", "source_scope"):
        value = values.get(key)
        if isinstance(value, str) and value:
            return value
    full = values.get("full_name")
    if isinstance(full, str) and "/" in full:
        return full.split("/", 1)[0]
    identity = item.get("identity", {}).get("object_id", "")
    # An object id is prefix:scope:..., but installationRepository names its
    # installation first, so the organization is the repository's owner.
    for part in identity.split(":")[1:]:
        if "/" in part:
            return part.split("/", 1)[0]
        if part and not part.isdecimal():
            return part
    return ""


def _group_for(kind, operation):
    if kind == "vault_item":
        return "actions_secrets"
    if operation in ("org_fgpat", "org_fgpat_repositories"):
        return "fine_grained_pats"
    if operation == "org_pat_requests":
        return "pat_requests"
    if operation == "repo_deploy_keys":
        return "deploy_keys"
    if operation in ("org_installations", "enterprise_org_installations") + INSTALLATION_OPERATIONS:
        return "installations"
    if operation == "org_sso":
        return "sso_authorizations"
    if kind == "policy":
        return "policies"
    if kind == "resource":
        return "repositories"
    return "context"
