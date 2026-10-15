"""GCP onboarding and reads over the shared worker's persisted collection."""

from __future__ import annotations

import uuid

from fastapi import Depends, Query

from cremore.coverage.gcp_store import GcpStore


def authentication(store, owner, latest, job=None):
    """Report only the current revision's observed Google API access."""
    result = {"state": "NOT_CHECKED", "checked_at": None, "reason_code": None,
              "credential_mode": "GOOGLE_OAUTH" if owner["spec"].get("auth_type") == "google_oauth" else "ADC",
              "refresh_supported": True}
    if not latest or latest["revision"] != owner["revision"]:
        if job and job.payload.get("coverage_revision") == owner["revision"] and job.error:
            result.update(state="INDETERMINATE", reason_code=job.error)
        return result
    result["checked_at"] = latest["finished_at"] or latest["started_at"]
    errors = latest["reasons"]
    auth_error = next((reason for reason in errors if reason.startswith(("GCP_ADC_", "GCP_AUTH_", "GCP_OAUTH_"))
                       or reason == "AUTHENTICATION_FAILED"), None)
    if auth_error:
        result.update(state="FAILED", reason_code=auth_error)
        return result
    if latest["status"] == "RUNNING":
        result["state"] = "CHECKING"
        return result
    observed = {"gcp.service_accounts", "gcp.api_keys", "gcp.secret_manager"}
    for record in store.iter_records(latest["id"]):
        if (record["record_type"] == "operation_report" and record["provenance"]["operation"] in observed
                and record["status"] in ("COMPLETE", "PARTIAL") and record["pages"] > 0):
            result["state"] = "READY"
            return result
    result.update(state="INDETERMINATE", reason_code=next(iter(errors), "GCP_ACCESS_NOT_ESTABLISHED"))
    return result


def register_gcp_routes(app, repo, require_auth):
    @app.get("/api/v2/coverage/connections/{connection_id}/gcp")
    def state(connection_id: uuid.UUID, kind: str = Query(default="events", pattern="^(objects|events)$"),
              offset: int = Query(default=0, ge=0), limit: int = Query(default=50, ge=1, le=500),
              _actor=Depends(require_auth)):
        store = GcpStore(repo)
        owner = store.require_gcp(connection_id)
        with store.transaction() as conn:
            counts = {name: store.count(conn, "gcp_" + name, connection_id) for name in ("objects", "events")}
        return {"connection_id": str(connection_id), "project_id": owner["spec"]["scopes"][0]["id"],
                "counts": counts, "kind": kind, "page": store.page(connection_id, kind, offset=offset, limit=limit),
                "basis": "COLLECTION_OBSERVATION"}
