"""Connection and collection/scan job response projections. No route registration."""

from __future__ import annotations

import datetime as _dt

from cremore.api.http_support import (
    isoformat,
    utc_now,
)
from cremore.api.source_contract import (
    CREDENTIAL_CHECK,
    SECRET_SCANNING,
    job_source_type,
    provider_to_source,
    scope_ref,
)
from cremore.coverage import JOB_KIND, METADATA_JOB_KIND
from cremore.domain.models import CONTENT_SCAN_KINDS
from cremore.scanning.extraction.contract import public_reasons
from cremore.scanning.scope import FAILURE_BASIS, job_error_code, job_is_partial, rule_basis
from cremore.secretstore.sealed import is_sealed

JOB_STATUS_TO_WEB = {"QUEUED": "QUEUED", "RUNNING": "RUNNING", "SUCCEEDED": "COMPLETED",
                      "FAILED": "FAILED", "CANCELLING": "CANCELLING", "CANCELLED": "CANCELLED"}


def present_connection(c) -> dict:
    evidence = c.credential_evidence or {}
    check_status = evidence.get("status", "UNKNOWN")
    refresh_supported = evidence.get("refresh_supported") is True
    recorded_expires_at = (
        evidence.get("expires_at") if isinstance(evidence.get("expires_at"), str) else None
    )
    expiry_state = "UNKNOWN"
    expires = None
    if recorded_expires_at:
        try:
            expires = _dt.datetime.fromisoformat(recorded_expires_at)
            expires = expires.astimezone(_dt.UTC) if expires.tzinfo else None
        except ValueError:
            expires = None
    expires_at = expires.isoformat() if expires else None
    if evidence.get("revoked_at"):
        expiry_state = "REVOKED"
    elif expires and refresh_supported and check_status == "ACTIVE":
        expiry_state = "VALID"
    elif expires and expires <= utc_now():
        expiry_state = "EXPIRED"
    elif expires and expires <= utc_now() + _dt.timedelta(hours=24):
        expiry_state = "EXPIRING_SOON"
    elif expires:
        expiry_state = "VALID"
    if c.status == "DISABLED":
        auth_state = "DISABLED"
    elif check_status == "ACTIVE":
        auth_state = "READY"
    elif check_status == "REJECTED":
        auth_state = "SECRET_UNAVAILABLE" if evidence.get("error") == "SECRET_UNAVAILABLE" else "REAUTH_REQUIRED"
    else:
        auth_state = "AUTH_FRESHNESS_UNKNOWN"
    if not refresh_supported and expiry_state == "EXPIRED" and auth_state == "READY":
        auth_state = "AUTH_EXPIRED"
    elif not refresh_supported and expiry_state == "EXPIRING_SOON" and auth_state == "READY":
        auth_state = "AUTH_LIFETIME_TOO_SHORT"
    return {
        "id": str(c.id),
        "profile_ref": scope_ref(c),
        "display_name": c.name,
        "source_type": provider_to_source(c.provider),
        "enabled": c.status != "DISABLED",
        "created_at": isoformat(c.created_at) or "",
        "updated_at": isoformat(c.updated_at) or "",
        # A sealed token is stored encrypted by CreMore; a vault:// pointer is
        # operator-managed secret supply; S3 uses the scanner's own identity.
        "credential_source": "GITHUB_APP" if (c.config or {}).get("auth_kind") == "GITHUB_APP"
        else "CREMORE_ENCRYPTED" if is_sealed(c.secret_ref)
        else "OPERATOR_MOUNTED_ENV" if c.secret_ref or c.provider in ("gcp", "azure_blob") else "NONE",
        "credential_ref": "",
        "credential": {
            "status": "REVOKED" if evidence.get("revoked_at") else
            check_status if check_status in ("ACTIVE", "REJECTED", "INDETERMINATE") else "UNKNOWN",
            "owner": evidence.get("owner") or None,
            "workspace": evidence.get("workspace") or None,
            "scopes": list(evidence.get("scopes") or []),
            "checked_at": evidence.get("checked_at"),
            "expires_at": expires_at,
            "check_error": evidence.get("error") or None,
            "revoked_at": evidence.get("revoked_at"),
            "revocation_reason": evidence.get("revocation_reason"),
            "checkable": not evidence.get("revoked_at"),
        },
        "expiry_state": expiry_state,
        # Counts only. The alerts themselves are read one connection at a time.
        "secret_scanning": {key: value for key, value in (c.secret_scanning or {}).items() if key != "alerts"} or None,
        "connection_auth": {
            "state": auth_state,
            "reason_code": (
                "AUTH_EXPIRED" if auth_state == "AUTH_EXPIRED" else
                "AUTH_LIFETIME_TOO_SHORT" if auth_state == "AUTH_LIFETIME_TOO_SHORT" else
                evidence.get("error") or None
            ),
            "checked_at": evidence.get("checked_at"),
            "expires_at": expires_at,
            "refresh_supported": refresh_supported,
            "source_freshness": "UNKNOWN",
            "check_scope": "CONNECTION_AUTHENTICATION",
        },
    }


def present_job(job, conn, current_digest: str | None = None) -> dict:
    """A scan job in the dashboard's SourceScanJob shape.

    The stored error is the exception type and message; only the type name is
    served, so a provider error text can never carry request details outward.
    """

    coverage = job.coverage or {}
    failed = int(coverage.get("failed", job.objects_failed or 0) or 0)
    new_basis = coverage.get("failure_basis") == FAILURE_BASIS
    partial = job_is_partial(job)
    status = JOB_STATUS_TO_WEB.get(job.status, job.status)
    if job.status == "SUCCEEDED" and partial:
        status = "PARTIAL"
    error_code = job_error_code(job)
    if job.error:
        message = "The scope could not be listed; the run is not a clean result."\
            if error_code and error_code.endswith(("_LIST_FAILED", "_UNAVAILABLE", "_SEARCH_FAILED"))\
            else "The job failed; the worker log has the details."
    elif failed and (new_basis or not coverage.get("skipped_unsupported")):
        # `failed` holds unreadable objects and objects not fully scanned (for
        # example, the detection cap was reached); format skips are not in it.
        error_code, message = "OBJECTS_INCOMPLETE", f"{failed} listed object(s) failed or were not fully scanned."
    elif failed:
        # Recorded before format skips were counted apart: the two cannot be
        # separated after the fact, so neither is claimed.
        error_code, message = "OBJECTS_NOT_SCANNED", (
            f"{failed} listed object(s) failed, were not fully scanned or were in unsupported formats "
            "(counted together before format skips were separated).")
    elif partial and coverage.get("policy_held_only"):
        # Nothing failed: an upgrade changed the detection rules, and the scope's next full scan reads it whole.
        error_code = "POLICY_HELD"
        message = ("After the upgrade this run read only what changed, or nothing, under the new detection rules; "
                   "the scope's next full scan reads all of it.")
    elif partial:
        error_code = str(coverage.get("stopped_reason") or "SCOPE_INCOMPLETE")
        message = "The run stopped before its full approved scope was covered."
    else:
        message = None
    # Neither reads content: both are provider reads about the connection itself.
    is_check = job.kind in (CREDENTIAL_CHECK, SECRET_SCANNING)
    payload = job.payload or {}
    if job.kind in ("scope", "catalog-refresh"):
        source_type = payload.get("source_type") or (provider_to_source(conn.provider) if conn else "s3")
    elif is_check and conn:
        source_type = provider_to_source(conn.provider)
    else:
        source_type = job_source_type(job.kind)
    content_scan = job.kind in CONTENT_SCAN_KINDS
    extra = {}
    if content_scan and job.status in ("SUCCEEDED", "FAILED", "CANCELLED"):
        # A connection-wide scan (not a scope run) carries whether its listing
        # covered the whole connection, for the connection card's rule status.
        extra["connection_wide"] = job.kind != "scope"
        extra["authoritative_listing"] = bool(coverage.get("authoritative_listing"))
        extra["objects_failed"] = failed
        if current_digest is not None:
            extra["rule_basis"] = rule_basis(coverage, current_digest)
        if new_basis:
            extra["format_skips"] = {"unsupported": int(coverage.get("skipped_unsupported") or 0),
                                     "media": int(coverage.get("skipped_media") or 0)}
    return {
        **extra,
        "id": str(job.id),
        "source_connection_id": str(job.connection_id) if job.connection_id else "",
        "display_name": conn.name if conn else job.kind,
        "profile_ref": scope_ref(conn) if conn else job.kind,
        "source_type": source_type,
        "status": status,
        "attempt": 1,
        "started_at": isoformat(job.started_at),
        "completed_at": isoformat(job.finished_at),
        "findings_total": job.findings,
        "result_status": (
            "SCANNED" if job.status == "SUCCEEDED" and content_scan and not partial else None
        ),
        "safe_error_code": error_code,
        "safe_error_message": message,
        "created_at": isoformat(job.created_at) or "",
        "job_kind": "SECRET_SCANNING" if job.kind == SECRET_SCANNING
        else "CREDENTIAL_CHECK" if is_check else "INVENTORY" if job.kind == "catalog-refresh" else "SCAN",
    }


def connection_public(conn) -> dict:
    """A connection as served by the API: scope and status, never the secret.

    Credential references and sealed tokens are replaced by markers; internal
    Vault paths and ciphertext do not leave the installation's storage boundary.
    """

    from cremore.secretstore.sealed import public_ref

    return {
        "id": str(conn.id),
        "provider": conn.provider,
        "name": conn.name,
        "status": conn.status,
        "config": conn.config,
        "secret_ref": public_ref(conn.secret_ref),
        "last_error": conn.last_error,
        "last_verified_at": conn.last_verified_at.isoformat() if conn.last_verified_at else None,
    }


def present_scan_run(job, current_digest=None, *, task_states=None) -> dict:
    cov = job.coverage or {}
    start, end = job.started_at, job.finished_at
    elapsed = ((end or utc_now()) - start).total_seconds() if start is not None else None
    timings = cov.get("timings") or {}
    # Actual scan time: the summed engine/listing/persistence/download work,
    # which excludes any time the run sat parked waiting (e.g. AWS re-login).
    active = sum(v for v in timings.values() if isinstance(v, (int, float))) if timings else None
    payload = job.payload or {}
    detail = {
        "id": str(job.id),
        # A run that stopped on a budget, skipped rows or failed a root read
        # part of its scope. run_public already says PARTIAL for that; this
        # projection reported the raw SUCCEEDED, so the scan history called a
        # bounded stop a completed scan.
        # Any metadata collection (schema 2, or schema 1: AWS inventory and Vault/secret-store reads) is
        # partial when its stored runs were: finalize_runs records both under the same count basis.
        "status": "PARTIAL" if job.status == "SUCCEEDED" and (job_is_partial(job)
            or (job.kind in (METADATA_JOB_KIND, JOB_KIND) and cov.get("coverage_status") == "PARTIAL")) else job.status,
        "kind": job.kind,
        "mode": payload.get("mode", "BASELINE"),
        "trigger_type": "MANUAL" if payload.get("trigger", "BASELINE") == "BASELINE"
        else payload.get("trigger") if payload.get("trigger") in {"RESCAN", "SCHEDULE", "EVENT", "POLICY_SWEEP", "RESUME"}
        else "UNKNOWN",
        "connection_id": str(job.connection_id) if job.connection_id else None,
        "resources_succeeded": job.objects,
        "resources_failed": job.objects_failed or 0,
        "findings_total": job.findings,
        "duration_seconds": round(active, 1) if active is not None else (round(elapsed, 1) if elapsed is not None else None),
        "elapsed_seconds": round(elapsed, 1) if elapsed is not None else None,
        "bytes": cov.get("bytes"),
        "requests": cov.get("requests"),
        "reused": cov.get("reused"),
        "skipped": cov.get("skipped"),
        "skipped_unchanged": cov.get("skipped_unchanged"),
        "skipped_unsupported": cov.get("skipped_unsupported"),
        "skipped_media": cov.get("skipped_media"),
        "extraction_reasons": public_reasons(cov.get("extraction_reasons")),
        "failure_basis": cov.get("failure_basis"),
        "skipped_archived": cov.get("skipped_archived"),
        "skipped_submodules": cov.get("skipped_submodules"),
        "roots_failed": cov.get("roots_failed"),
        "stopped_reason": cov.get("stopped_reason"),
        "engine_seconds": (cov.get("timings") or {}).get("engine_seconds"),
        "error": job_error_code(job),
        "created_at": isoformat(job.created_at) or "",
        "started_at": isoformat(job.started_at),
        "completed_at": isoformat(job.finished_at),
    }
    # Which connection, scope, provider connection or finding a run belongs to (ids only, for the logs screen).
    for key in ("connection_kind", "profile_id", "provider_connection_id", "coverage_connection_id", "finding_id"):
        if payload.get(key):
            detail[key] = str(payload[key])
    # The schema 2 metadata runs a collection stored, for its operation report and export (ids only). A schema 1
    # collection (AWS inventory, vault KV) records its run too, but the v2 run routes do not read it.
    if job.kind == METADATA_JOB_KIND and cov.get("coverage_run_ids"):
        detail["coverage_run_ids"] = [str(rid) for rid in cov["coverage_run_ids"]]
    if (job.kind in (METADATA_JOB_KIND, JOB_KIND) and cov.get("count_basis") == "COMMITTED_METADATA_RECORDS"
            and type(cov.get("metadata_items")) is int and cov["metadata_items"] >= 0):
        detail.update(metadata_items=cov["metadata_items"], count_basis="COMMITTED_METADATA_RECORDS")
    if cov.get("policy_held"):
        # Roots an upgrade's change run did not read whole under the new rules (as run_public serves them).
        detail["policy_held_roots"] = int(cov["policy_held"])
        if cov.get("policy_held_only"):
            detail["policy_held_only"] = True  # nothing else leaves the run partial
    # Each run is compared by the policy it recorded itself, so a later full
    # rescan never changes how an older run is labelled.
    if (current_digest is not None and job.status in ("SUCCEEDED", "FAILED", "CANCELLED")
            and job.kind in CONTENT_SCAN_KINDS):
        detail["rule_basis"] = rule_basis(cov, current_digest)
    # Active runs get live progress + any wait/hold reason; failed/partial runs
    # get the specific per-root failure codes so an operator can see what broke.
    active_run = job.status in ("QUEUED", "RUNNING", "CANCELLING")
    wants_failures = job.error or (job.objects_failed or 0) or (cov.get("roots_failed") or 0) or job.status == "FAILED"
    if task_states is not None and (active_run or wants_failures):
        try:
            state = task_states(job.id)
        except Exception:  # noqa: BLE001 -- progress is best-effort, never fails the list
            state = None
        if state:
            if active_run:
                detail["progress"] = {"done": state["done"], "total": state["total"],
                                      "running": state["running"], "queued": state["queued"]}
                if state.get("hold_code"):
                    detail["hold"] = {"code": state["hold_code"], "next_attempt_at": state["next_attempt_at"],
                                      "waiting_tasks": len(state["held"])}
            if state.get("failures"):
                detail["failures"] = [{"root": f["root"][:12], "code": f["code"]} for f in state["failures"]]
    return detail


def scan_job_public(job) -> dict:
    """Compatibility job response: no payload and no provider exception text."""
    return {**job.model_dump(mode="json", exclude={"payload"}), "error": job_error_code(job)}
