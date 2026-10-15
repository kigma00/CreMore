"""Explicit process authority and queue ownership for isolated installations.

These checks prevent configuration mistakes. The OS key mounts, database grants
and cloud policy are the boundary against arbitrary code in a process.
"""
from __future__ import annotations

ROLES = ("mixed", "collector", "remediator", "control")
ACTION_JOB = "provider-credential-action"


def execution_role(settings):
    role = getattr(settings, "worker_execution_role", "mixed")
    if role not in ROLES:
        raise ValueError("WORKER_EXECUTION_ROLE_INVALID")
    if getattr(settings, "isolated_deployment", False) and role == "mixed":
        raise ValueError("ISOLATED_WORKER_ROLE_REQUIRED")
    return role


def job_role(repo, job):
    if job.kind == ACTION_JOB:
        return "remediator"
    if job.kind == "aws-role-check" and (job.payload or {}).get("purpose") == "remediation":
        return "remediator"
    if job.kind == "provider-check":
        from cremore.onboarding.session_store import SessionStore
        from cremore.onboarding.store import ProviderConnectionStore

        try:
            session_id = (job.payload or {}).get("onboarding_session_id")
            session = SessionStore(repo).get(session_id) if session_id else None
            data = (session or {}).get("data") or {}
            if data.get("credential_purpose") == "remediator" or "remediation" in data.get("purposes", []):
                return "remediator"
            record = ProviderConnectionStore(repo).get((job.payload or {}).get("provider_connection_id"))
        except (ValueError, TypeError):
            record = None
        if record and "remediation" in record["purposes"]:
            return "remediator"
    return "collector"


def accepts(repo, job, role):
    return role == "mixed" or (role != "control" and job is not None and job_role(repo, job) == role)


def job_predicate(jobs, role):
    """Filter before SQL claim LIMIT, including checks created before the split."""
    from sqlalchemy import String, and_, cast, exists, false, func, or_, select, true

    from cremore.db.schema import metadata
    from cremore.onboarding.session_store import register_table
    from cremore.onboarding.store import register_tables

    if role == "mixed":
        return true()
    if role == "control":
        return false()
    if role not in ROLES:
        raise ValueError("WORKER_EXECUTION_ROLE_INVALID")
    owners, _ = register_tables(metadata)
    # UUID storage is native on PostgreSQL and compact text on SQLite.
    same = func.replace(cast(owners.c.id, String), "-", "") == func.replace(
        jobs.c.payload["provider_connection_id"].as_string(), "-", "")
    sessions = register_table(metadata)
    session_same = func.replace(cast(sessions.c.id, String), "-", "") == func.replace(
        jobs.c.payload["onboarding_session_id"].as_string(), "-", "")
    remediation_session = exists(select(sessions.c.id).where(session_same, or_(
        sessions.c.data["credential_purpose"].as_string() == "remediator",
        sessions.c.data["purposes"][0].as_string() == "remediation")))
    remediation_check = exists(select(owners.c.id).where(same, owners.c.purposes[0].as_string() == "remediation"))
    remediate = or_(jobs.c.kind == ACTION_JOB,
                   and_(jobs.c.kind == "aws-role-check", jobs.c.payload["purpose"].as_string() == "remediation"),
                   and_(jobs.c.kind == "provider-check", or_(remediation_check, remediation_session)))
    # JSON missing purpose produces NULL: coalesce keeps ordinary jobs visible.
    return func.coalesce(remediate, False) if role == "remediator" else ~func.coalesce(remediate, False)
