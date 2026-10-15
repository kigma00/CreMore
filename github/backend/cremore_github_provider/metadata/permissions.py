"""The App permission each organization read needs, and an organization's installation health.

Permission names are GitHub's own (REST "Permissions required for GitHub Apps",
API 2026-03-10); develop_github's org_health compared the same names per
collector. Holding them is not a collection check: SAML SSO, the plan, the
repository selection, pagination and rate limits can still stop a read. The
health view is derived from observed installation records and never calls GitHub.
"""

from __future__ import annotations

from .descriptor import SOURCE_PERMISSIONS

LEVELS = {"read": 1, "write": 2, "admin": 3}


def missing(required, granted):
    """Permission names the installation lacks at the required level."""
    return sorted(name for name, level in required.items()
                  if not isinstance(granted, dict) or LEVELS.get(granted.get(name), 0) < LEVELS[level])


# The reads a page of each read can lead to, whatever it holds (pages.handle_page, actions.handle_page).
FOLLOW_UPS = {"org_fgpat": ("org_fgpat_repositories",), "org_pat_requests": ("org_pat_request_repositories",),
              "org_actions_secrets": ("org_secret_repositories",), "repo_actions_runs": ("run_jobs",),
              "repo_environments": ("environment_actions_secrets",)}


def planned_kinds(spec):
    """Every organization read a connection would make, follow-ups included, before any has run.

    An organization audit that only stands in for the Enterprise audit log is not counted.
    """
    from .pages import repository_read_kinds, seed_org_tasks

    options = {"sources": tuple(spec.options.sources), "include_actions": spec.options.include_actions}
    kinds = {item["kind"] for item in seed_org_tasks("", "planned", **options, server=spec.edition == "enterprise_server")}
    if "org_repositories" in kinds:
        kinds.update(repository_read_kinds(options))
    kinds.update(follow for kind in list(kinds) for follow in FOLLOW_UPS.get(kind, ()))
    if spec.options.include_audit_events and (spec.options.mode == "organization"
                                              or spec.options.audit_scope == "organization"):
        kinds.add("org_audit")
    return kinds & set(SOURCE_PERMISSIONS)


def organization_health(installation, kinds, *, failure=None):
    """Suspension first, then permission names per read; a lookup that failed is unknown, never uninstalled."""
    status, reason = "unknown", failure or "installation_not_checked"
    permissions = (installation or {}).get("permissions")
    if installation is not None:
        if installation.get("installed") is False:
            status, reason = "not_installed", "absent_from_complete_app_installation_list"
        elif installation.get("suspended"):
            status, reason = "suspended", "installation_suspended"
        elif not isinstance(permissions, dict):
            reason = "installation_permissions_unavailable"
        else:
            status, reason = "permissions_present", "permission_names_only_not_collection_validation"
    rows = []
    for kind in sorted(set(kinds) & set(SOURCE_PERMISSIONS)):
        lacking = missing(SOURCE_PERMISSIONS[kind], permissions) if status == "permissions_present" else []
        rows.append({"kind": kind, "required": dict(SOURCE_PERMISSIONS[kind]), "missing": lacking,
                     "status": ("missing_permissions" if lacking else "permissions_present")
                     if status == "permissions_present" else status})
    if status == "permissions_present" and any(row["missing"] for row in rows):
        status, reason = "limited", "required_installation_permissions_missing"
    installation = installation or {}
    return {"status": status, "reason": reason, "checked_at": installation.get("checked_at"),
            "basis": installation.get("basis"), "api_access_verified": False,
            "repository_selection": installation.get("repository_selection") or "unknown", "sources": rows}
