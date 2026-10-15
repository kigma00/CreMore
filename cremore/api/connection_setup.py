"""Setup evidence for one connection, derived from what is already stored.

The seven steps are read out of a declaration, a credential check, a catalog
snapshot, an approved scope and a saved checkpoint. None of them is a record of
what an operator clicked: opening the screen records nothing, and a step is
COMPLETE only when the evidence behind it exists.

Two distinctions the screen depends on live here:

* A connection that collects management metadata has no content catalog, no
  target selection and no approved scan scope. Those steps are NOT_APPLICABLE
  rather than PENDING, so a management-only connection is never shown as a
  half-finished content connection.
* The saved checkpoint is an operator's note about their own progress. It is
  bound to the evidence that existed when it was written, so evidence that
  changed afterwards shows the checkpoint as stale instead of silently
  standing for the new state.
"""

from __future__ import annotations

import hashlib
import json

STEPS = ("PURPOSE", "ENVIRONMENT", "AUTHENTICATION", "CATALOG", "SELECTION",
         "SCOPE_SAVED", "EXECUTION_CHOICE")
# The steps that only exist for a connection that scans content.
CONTENT_STEPS = ("CATALOG", "SELECTION", "SCOPE_SAVED")
CHOICES = ("DRAFT", "SAVE_ONLY", "RUN_NOW", "SCHEDULED", "EVENTS", "MANAGEMENT_ONLY")
# A management-only connection has no scope to point a choice at.
MANAGEMENT_CHOICES = ("DRAFT", "MANAGEMENT_ONLY")
PROFILE_LIMIT = 50
# The run statuses the dashboard's setup summary accepts. A job that is
# stopping is still running, so it is reported as running until it is not.
RUN_STATUS = {"QUEUED": "QUEUED", "RUNNING": "RUNNING", "SUCCEEDED": "COMPLETED",
              "FAILED": "FAILED", "CANCELLING": "RUNNING", "CANCELLED": "CANCELLED"}
FAILED_RUN = ("FAILED", "CANCELLED")


def checkpoint_key(kind: str, connection_id) -> str:
    return f"connection_setup:{kind}:{connection_id}"


def _step(code: str, status: str, observed_at=None, evidence_id=None) -> dict:
    row = {"code": code, "status": status}
    if observed_at:
        row["observed_at"] = observed_at
    if evidence_id:
        row["evidence_id"] = evidence_id
    return row


def _digest(payload) -> str:
    encoded = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _path_exclusions(roots) -> int:
    total = 0
    for root in roots or []:
        if isinstance(root, dict):
            total += len(root.get("excluded_prefixes") or []) + len(root.get("excluded_paths") or [])
    return total


def profile_row(profile, state: str, auth: str, iso) -> dict:
    """One saved scope profile as the setup summary counts it."""
    row = {
        "id": str(profile.id), "version": int(profile.version), "state": state,
        # A count, not the list: the summary says how many targets were chosen,
        # and the targets themselves are read on the scope screen.
        "selected_roots": len(profile.selected_roots or []),
        "excluded_resources": len(profile.excluded_ids or []),
        "excluded_paths": _path_exclusions(profile.selected_roots),
        "schedule_minutes": int(profile.schedule_minutes or 0),
        "full_scan_minutes": profile.full_scan_minutes,
        "event_mode": profile.event_mode if profile.event_mode in ("ENABLED", "DISABLED") else "DISABLED",
        "authorization_current": profile.auth_revision == auth,
    }
    approved = iso(profile.approved_at)
    # An absent timestamp is absent. A null would read as a recorded time of
    # nothing, and the dashboard refuses the whole page rather than show it.
    if approved:
        row["approved_at"] = approved
    return row


def runs_of(jobs, iso) -> tuple[dict | None, dict | None]:
    """(most recent run, most recent failed or cancelled run) as summary rows."""
    return (run_row(next(iter(jobs), None), iso),
            run_row(next((job for job in jobs if job.status in FAILED_RUN), None), iso))


def run_row(job, iso) -> dict | None:
    if job is None:
        return None
    payload = job.payload or {}
    row = {"id": str(job.id), "profile_id": str(payload.get("profile_id", "")),
           "profile_version": int(payload.get("profile_version", 0) or 0),
           "status": RUN_STATUS.get(job.status, "UNKNOWN"),
           "created_at": iso(job.created_at) or ""}
    finished = iso(job.finished_at)
    if finished:
        row["completed_at"] = finished
    return row


def catalog_block(catalog, known_count: int, auth: str, job_status: str, iso) -> dict:
    """What the resource catalog holds, and whether it still matches the authorization."""
    if catalog is None or not catalog.snapshot_id:
        # Never collected is not an empty catalog, and neither is a count of 0.
        return {"snapshot_id": "", "status": "NOT_COLLECTED", "known_count": 0,
                "authorization_current": False, "job_status": job_status}
    status = catalog.completeness if catalog.completeness in ("COMPLETE", "PARTIAL") else "UNKNOWN"
    block = {"snapshot_id": catalog.snapshot_id, "status": status,
             "known_count": max(0, int(known_count or 0)),
             "authorization_current": catalog.auth_revision == auth, "job_status": job_status}
    updated = iso(getattr(catalog, "updated_at", None))
    if updated:
        block["updated_at"] = updated
    return block


def steps(*, declaration, authenticated_at, management_only, catalog, profiles, checkpoint, iso):
    """The seven steps, each COMPLETE only where its evidence exists."""
    declared = declaration or {}
    declared_at = declared.get("declared_at")
    environment = declared.get("environment") or {}
    approved = [(profile, state) for profile, state in profiles if profile.approved_at]
    with_targets = [(profile, state) for profile, state in profiles if profile.selected_roots]
    ready = [(profile, state) for profile, state in approved if state == "READY"]

    def content(code, done, observed=None, evidence=None):
        if management_only:
            return _step(code, "NOT_APPLICABLE")
        return _step(code, "COMPLETE" if done else "PENDING", observed, evidence)

    return [
        # A declaration with an unknown product says nothing about purpose.
        _step("PURPOSE", "COMPLETE" if declared.get("product_type") not in (None, "", "UNKNOWN")
              else "PENDING", declared_at),
        _step("ENVIRONMENT", "COMPLETE" if any(environment.get(field) for field in
              ("deployment_type", "account_kind", "plan", "topology", "partition", "sso",
               "user_management", "api_base_url")) or environment.get("regions")
              else "PENDING", declared_at),
        # A recorded check, not a stored credential: holding a secret proves
        # nothing about whether the provider still accepts it.
        _step("AUTHENTICATION", "COMPLETE" if authenticated_at else "PENDING", authenticated_at),
        content("CATALOG", bool(catalog and catalog.snapshot_id),
                iso(getattr(catalog, "updated_at", None)) if catalog else None,
                catalog.snapshot_id if catalog and catalog.snapshot_id else None),
        content("SELECTION", bool(with_targets),
                iso(with_targets[0][0].updated_at) if with_targets else None,
                str(with_targets[0][0].id) if with_targets else None),
        content("SCOPE_SAVED", bool(ready),
                iso(ready[0][0].approved_at) if ready else None,
                str(ready[0][0].id) if ready else None),
        _step("EXECUTION_CHOICE", "COMPLETE" if checkpoint else "PENDING",
              (checkpoint or {}).get("saved_at")),
    ]


def evidence(*, kind, connection_id, enabled, declaration, authenticated_at, management_only,
             catalog, known_count, catalog_job_status, auth, profiles, checkpoint, iso,
             recent_run=None, recent_failure=None, probe="AVAILABLE", investigation="NOT_AVAILABLE"):
    """The whole setup block the dashboard reads for one connection."""
    rows = steps(declaration=declaration, authenticated_at=authenticated_at,
                 management_only=management_only, catalog=catalog, profiles=profiles,
                 checkpoint=checkpoint, iso=iso)
    pending = [row["code"] for row in rows if row["status"] == "PENDING"]
    shown = sorted(profiles, key=lambda pair: (pair[0].updated_at or pair[0].created_at or 0,
                                               str(pair[0].id)), reverse=True)[:PROFILE_LIMIT]
    profile_rows = [profile_row(profile, state, auth, iso) for profile, state in shown]
    block = {
        # Whether a durable server-side investigation can be started for this
        # connection. There is none on this API: content is scanned through the
        # queued scan job, so the screen must not offer a control for one.
        "investigation": investigation,
        # Whether a read-only identity call exists at all. A provider that has
        # none is not "unchecked"; there is nothing to check it with, and the
        # screen must not offer a control that cannot run.
        "probe": probe,
        "stage": pending[0] if pending else "REVIEWED",
        # A disabled connection is not "in progress": nothing further can run.
        "status": "DISCONNECTED" if not enabled else "IN_PROGRESS" if pending else "REVIEWED",
        "management_only": bool(management_only),
        "steps": rows,
        "catalog": catalog_block(catalog, known_count, auth, catalog_job_status, iso),
        "profiles": profile_rows,
        "profile_count": len(profiles),
        # Totals across saved profiles, which is a count of selections and not
        # a count of distinct resources in the organisation.
        "selected_roots": sum(len(profile.selected_roots or []) for profile, _ in profiles),
        "excluded_resources": sum(len(profile.excluded_ids or []) for profile, _ in profiles),
        "excluded_paths": sum(_path_exclusions(profile.selected_roots) for profile, _ in profiles),
    }
    if recent_run:
        block["recent_run"] = recent_run
    if recent_failure:
        block["recent_failure"] = recent_failure
    # The checkpoint is bound to the evidence that existed when it was written.
    # EXECUTION_CHOICE is left out because that step *is* the checkpoint:
    # including it would make every save invalidate itself.
    digest = _digest({"kind": kind, "connection_id": str(connection_id),
                      "steps": [row for row in block["steps"] if row["code"] != "EXECUTION_CHOICE"],
                      "catalog": block["catalog"], "profiles": profile_rows,
                      "management_only": block["management_only"]})
    saved = checkpoint or {}
    block.update({
        "evidence_digest": digest,
        "version": int(saved.get("version") or 0),
        "choice": saved.get("choice") if saved.get("choice") in CHOICES else "DRAFT",
        "checkpoint_current": bool(saved) and saved.get("evidence_digest") == digest,
    })
    for field in ("profile_id", "saved_at", "saved_by", "saved_stage"):
        if saved.get(field):
            block[field] = saved[field]
    return block


def validate_checkpoint(body, current: dict, profile_ids: set[str]) -> dict:
    """The operator's note, checked against the evidence it claims to describe.

    Raises :class:`ValueError` with a stable code. A stale expected version or
    a digest from evidence that has since changed is a conflict, not an
    overwrite: the operator is recording what they saw, and they did not see
    this.
    """
    body = body if isinstance(body, dict) else {}
    choice = body.get("choice")
    allowed = MANAGEMENT_CHOICES if current["management_only"] else CHOICES
    if choice not in allowed:
        raise ValueError("SETUP_CHOICE_NOT_SUPPORTED")
    if body.get("expected_version") != current["version"]:
        raise ValueError("SETUP_VERSION_CONFLICT")
    if body.get("evidence_digest") != current["evidence_digest"]:
        raise ValueError("SETUP_EVIDENCE_CHANGED")
    profile_id = body.get("profile_id") or ""
    if choice in ("DRAFT", "MANAGEMENT_ONLY"):
        profile_id = ""
    elif profile_id not in profile_ids:
        # A choice that names a scope must name one this connection saved.
        raise ValueError("SETUP_PROFILE_NOT_FOUND")
    return {"version": current["version"] + 1, "choice": choice, "profile_id": profile_id,
            "evidence_digest": current["evidence_digest"], "saved_stage": current["stage"]}
