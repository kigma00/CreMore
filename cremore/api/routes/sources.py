"""Source connections: registering one, what it last read, and what it could not.

Registered by the dashboard composition root. Shared behavior is imported
from independent API libraries; dependencies arrive through DashboardContext.
"""

from __future__ import annotations

import fnmatch

from cremore_aws_provider import aws_access, aws_identity
from cremore_aws_provider.investigation import investigation_switches
from fastapi import Depends, Request

from cremore import detection
from cremore.api import connection_setup
from cremore.api.governance_presenters import clean_declaration as _clean_declaration
from cremore.api.governance_presenters import governance_item_aws as _governance_item_aws
from cremore.api.governance_presenters import governance_item_source as _governance_item_source
from cremore.api.http_support import actor_uuid
from cremore.api.http_support import http_error as _http
from cremore.api.http_support import isoformat as _iso
from cremore.api.http_support import parse_uuid as _uuid
from cremore.api.http_support import utc_now as _now
from cremore.api.route_context import DashboardContext
from cremore.api.source_contract import CREDENTIAL_CHECK, SECRET_SCANNING
from cremore.api.source_contract import REVOCATION_GUIDANCE as _REVOCATION_GUIDANCE
from cremore.api.source_contract import SECRET_ARN_PREFIX as _SECRET_ARN_PREFIX
from cremore.api.source_contract import SOURCE_CAPABILITIES as _SOURCE_CAPABILITIES
from cremore.api.source_contract import SOURCE_TO_PROVIDER as _SOURCE_TO_PROVIDER
from cremore.api.source_contract import provider_to_source as _provider_to_source
from cremore.api.source_contract import scope_ref as _scope_ref
from cremore.api.source_presenters import present_connection as _dashboard_connection
from cremore.api.source_presenters import present_job as _dashboard_job
from cremore.domain.connections import (
    job_kind_for,
    job_payload_for,
    queue_credential_check,
)
from cremore.domain.models import (
    CONTENT_SCAN_KINDS,
    ConnectionCheckEvent,
    ConnectionStatus,
    FindingEvent,
    ScanJob,
    ScopeCatalog,
    SelectionDraft,
)
from cremore.scanning import scope as _scope
from cremore.scanning import verification_switch
from cremore.sources.registry import PROVIDER_FAMILIES


def register(ctx: DashboardContext) -> None:
    _approvals, _base_payload, _profiles_with_state, _resolve = ctx._approvals, ctx._base_payload, ctx._profiles_with_state, ctx._resolve
    _save_profile, _scope_error, _scope_target, _secret_metadata = ctx._save_profile, ctx._scope_error, ctx._scope_target, ctx._secret_metadata
    _validate_account, app, catalog_store, current_detection_digest = ctx._validate_account, ctx.app, ctx.catalog_store, ctx.current_detection_digest
    repo, require_auth, require_role, settings = ctx.repo, ctx.require_auth, ctx.require_role, ctx.settings

    def _secrets_inventory_on() -> bool:
        return investigation_switches.effective(settings, repo, investigation_switches.SECRETS_INVENTORY)

    @app.get("/api/v1/source-types")
    def source_types(_actor: str = Depends(require_auth)) -> dict:
        """The source catalog the dashboard's registration form is built from."""

        return {
            "engine": detection.NAME,
            "engine_version": detection.VERSION,
            "profile_secret_mode": "SECRET_REFERENCE",
            # The form's "approved secret ARN" picker is a Secrets-Manager-only
            # mode; this platform attaches vault:// references by API instead.
            "secret_reference_enabled": False,
            "allowed_secret_refs": [],
            "dashboard_queue": True,
            "source_runtime": "native",
            "network_verification": verification_switch.effective(settings, repo),
            "capabilities": [dict(c) for c in _SOURCE_CAPABILITIES],
        }

    @app.get("/api/v1/source-connections")
    def source_connections(_actor: str = Depends(require_auth)) -> list[dict]:
        return [_dashboard_connection(c) for c in repo.list_connections()]

    @app.post("/api/v1/source-connections/{connection_id}/scans", status_code=202)
    def queue_source_scan(connection_id: str, _actor: str = Depends(require_role("analyst"))) -> dict:
        conn = repo.get_connection(_uuid(connection_id, "connection_id"))
        if conn is None:
            raise _http(404, "connection not found")
        if conn.status == ConnectionStatus.DISABLED.value:
            raise _http(409, "CONNECTION_DISABLED: connection is disabled")
        payload = job_payload_for(conn)
        if conn.secret_ref:
            payload["secret_ref"] = conn.secret_ref
        job = repo.enqueue_job(ScanJob(kind=job_kind_for(conn), payload=payload, connection_id=conn.id))
        return _dashboard_job(job, conn)

    @app.get("/api/v1/source-scan-jobs")
    def source_scan_jobs(_actor: str = Depends(require_auth)) -> list[dict]:
        cache: dict = {}

        def lookup(cid):
            if cid is None:
                return None
            if cid not in cache:
                cache[cid] = repo.get_connection(cid)
            return cache[cid]

        digest = current_detection_digest()
        return [_dashboard_job(job, lookup(job.connection_id), digest) for job in repo.list_jobs(200)
                if job.kind != aws_identity.ROLE_CHECK_JOB]

    @app.post("/api/v1/source-connections/{connection_id}/credential/check", status_code=202)
    def check_connection_credential(connection_id: str, actor: str = Depends(require_role("analyst"))) -> dict:
        """Queue a read-only identity check of the connection's own credential
        (GitHub /user, Notion /users/me, STS GetCallerIdentity + HeadBucket)."""

        conn = repo.get_connection(_uuid(connection_id, "connection_id"))
        if conn is None:
            raise _http(404, "connection not found")
        if conn.status == ConnectionStatus.DISABLED.value:
            raise _http(409, "CONNECTION_DISABLED: connection is disabled")
        return _dashboard_job(queue_credential_check(repo, conn, actor_uuid(actor)), conn)

    @app.get("/api/v1/source-connections/{connection_id}/secret-scanning")
    def read_secret_scanning(connection_id: str, _actor: str = Depends(require_auth)) -> dict:
        """The provider's own secret-scanning alerts, as last read."""

        conn = repo.get_connection(_uuid(connection_id, "connection_id"))
        if conn is None:
            raise _http(404, "connection not found")
        if conn.provider != "github":
            raise _http(422, "secret-scanning alerts are a GitHub read")
        from cremore_github_provider.collectors.github_secret_scanning import NOT_ESTABLISHED

        return conn.secret_scanning or {
            "collection_status": "NOT_COLLECTED", "reason_code": "", "alerts": [], "truncated": False,
            "counts": {"alerts": 0}, "limitations": list(NOT_ESTABLISHED),
        }

    @app.post("/api/v1/source-connections/{connection_id}/secret-scanning", status_code=202)
    def queue_secret_scanning(connection_id: str, actor: str = Depends(require_role("analyst"))) -> dict:
        """Queue a read of GitHub's own secret-scanning alerts for this connection.

        Read-only, and only for a connection this installation already owns. The
        response carries the raw secret, so the reader drops it before storage.
        """

        conn = repo.get_connection(_uuid(connection_id, "connection_id"))
        if conn is None:
            raise _http(404, "connection not found")
        if conn.provider != "github":
            raise _http(422, "secret-scanning alerts are a GitHub read")
        if conn.status == ConnectionStatus.DISABLED.value:
            raise _http(409, "CONNECTION_DISABLED: connection is disabled")
        payload = {"provider": conn.provider, **job_payload_for(conn), "requested_by": str(actor_uuid(actor))}
        if conn.secret_ref:
            payload["secret_ref"] = conn.secret_ref
        return _dashboard_job(repo.enqueue_job(
            ScanJob(kind=SECRET_SCANNING, payload=payload, connection_id=conn.id)), conn)

    @app.post("/api/v1/source-connections/{connection_id}/credential/revoke")
    def revoke_connection_credential(connection_id: str, body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        """Stop this platform using the connection: disable it and withdraw its
        queued work. The provider-side token is NOT revoked; the response says
        where to do that."""

        conn = repo.get_connection(_uuid(connection_id, "connection_id"))
        if conn is None:
            raise _http(404, "connection not found")
        reason = str((body or {}).get("reason") or "").strip()[:512]
        now = _now()
        cancelled = 0
        for job in repo.list_jobs(500):
            if job.connection_id == conn.id and job.status == "QUEUED":
                repo.cancel_job(job.id)
                cancelled += 1
                if job.kind == CREDENTIAL_CHECK:
                    repo.record_check_event(ConnectionCheckEvent(
                        connection_id=conn.id, job_id=job.id, source_type=_provider_to_source(conn.provider),
                        stage="TERMINAL", job_status="CANCELLED", outcome="NOT_DISPATCHED", reason_code="JOB_CANCELLED",
                        requested_by=actor_uuid(str((job.payload or {}).get("requested_by") or actor)),
                        requested_at=job.created_at))
        evidence = dict(conn.credential_evidence or {})
        evidence.update({"revoked_at": now.isoformat(), "revocation_reason": reason or None, "revoked_by": actor})
        from_status = conn.status
        repo.update_connection(conn.id, status=ConnectionStatus.DISABLED.value, credential_evidence=evidence,
                               last_error="CONNECTION_REVOKED")
        repo.record_finding_event(FindingEvent(
            target_type="connection", target_id=conn.id, actor=actor,
            event_type="CONNECTION_STOPPED", from_status=from_status,
            to_status=ConnectionStatus.DISABLED.value, note=reason or None))
        guidance, url = _REVOCATION_GUIDANCE.get(conn.provider, ("Revoke the credential at its provider.", None))
        return {"connection_id": str(conn.id), "revoked_at": now.isoformat(), "jobs_cancelled": cancelled,
                "guidance": guidance, "self_service_url": url}

    @app.get("/api/v1/source-connections/{connection_id}/verification-history")
    def connection_verification_history(connection_id: str, limit: int = 20, cursor: str | None = None,
                                        _actor: str = Depends(require_auth)) -> dict:
        """Append-only credential-check ledger: job requested / claimed / ended."""

        conn = repo.get_connection(_uuid(connection_id, "connection_id"))
        if conn is None:
            raise _http(404, "connection not found")
        limit = max(1, min(limit, 20))
        events = repo.list_check_events(conn.id)
        if cursor:
            cursor_id = _uuid(cursor, "cursor")
            index = next((i for i, e in enumerate(events) if e.id == cursor_id), None)
            if index is None:
                raise _http(410, "HISTORY_CURSOR_EXPIRED: history cursor expired")
            events = events[index + 1:]
        page, rest = events[:limit], events[limit:]
        items = [{
            "id": str(e.id), "job_id": str(e.job_id), "source_type": e.source_type, "stage": e.stage,
            "job_status": e.job_status, "outcome": e.outcome, "reason_code": e.reason_code, "provenance": e.provenance,
            "requested_by": str(e.requested_by or actor_uuid("unknown")), "requested_at": _iso(e.requested_at) or _iso(e.recorded_at),
            "recorded_at": _iso(e.recorded_at),
        } for e in page]
        out = {"connection_id": str(conn.id), "scope": "CONNECTION_AUTHENTICATION", "coverage": "RECORDED_EVENTS_ONLY",
               "network_dispatch": "NOT_CAPTURED", "items": items}
        if rest and items:
            out["next_cursor"] = items[-1]["id"]
        return out

    @app.get("/api/v1/source-connections/{connection_id}/blast-radius")
    def connection_blast_radius(connection_id: str, _actor: str = Depends(require_auth)) -> dict:
        """What this connection's credential has reached: distinct resources,
        locations and findings recorded through it — observed, never inferred."""

        conn = repo.get_connection(_uuid(connection_id, "connection_id"))
        if conn is None:
            raise _http(404, "connection not found")
        exposures = [e for e in repo.exposures_for_connection(conn.id) if e.status != "REMOVED"]
        by_resource: dict[str, dict] = {}
        for e in exposures:
            row = by_resource.setdefault(e.resource_name, {"resource": e.resource_name, "locations": 0, "last_seen_at": ""})
            row["locations"] += 1
            row["last_seen_at"] = max(row["last_seen_at"], _iso(e.last_seen_at) or "")
        credential_ids = {e.credential_id for e in exposures}
        findings = [f for f in repo.list_findings() if f.credential_id in credential_ids]
        severity_counts: dict[str, int] = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        jobs = [j for j in repo.list_jobs(500) if j.connection_id == conn.id
                and j.kind in CONTENT_SCAN_KINDS]
        finished = sorted(j.finished_at for j in jobs if j.finished_at)
        shown = _dashboard_connection(conn)
        guidance, url = _REVOCATION_GUIDANCE.get(conn.provider, ("", None))
        return {
            "connection_id": str(conn.id), "display_name": conn.name, "source_type": shown["source_type"],
            "credential": shown["credential"], "expiry_state": shown["expiry_state"],
            "declared_scopes": [_scope_ref(conn)],
            "resources_reached": len(by_resource), "resources": sorted(by_resource.values(), key=lambda r: r["resource"]),
            "findings_found": len(findings), "severity_counts": severity_counts,
            "first_scan_at": finished[0].isoformat() if finished else None,
            "last_scan_at": finished[-1].isoformat() if finished else None,
            "scan_count": len(jobs), "revocation_guidance": guidance, "revocation_url": url,
            "provider_revocable": conn.provider in ("github", "notion"),
        }

    @app.get("/api/v1/source-connections/{connection_id}/secret-metadata")
    def connection_secret_metadata(connection_id: str, _actor: str = Depends(require_role("admin"))) -> dict:
        conn = repo.get_connection(_uuid(connection_id, "connection_id"))
        if conn is None:
            raise _http(404, "connection not found")
        if not (conn.secret_ref or "").startswith(_SECRET_ARN_PREFIX):
            raise _http(422, "this connection's secret reference is not a Secrets Manager ARN")
        if getattr(settings, "isolated_deployment", False):
            from cremore.api.aws_support import queue_aws_read
            return queue_aws_read(repo, settings, "secret-metadata", _actor, {"kind": "connection", "id": str(conn.id)})
        return {"connection_id": str(conn.id), **_secret_metadata(conn.secret_ref)}

    @app.post("/api/v1/source-scan-jobs/{job_id}/cancel")
    def cancel_source_scan(job_id: str, actor: str = Depends(require_role("analyst"))) -> dict:
        from cremore.remediation.provider_actions import JOB_KIND as PROVIDER_ACTION

        before = repo.get_job(_uuid(job_id, "job_id"))
        # An approved plan's run is not a scan: it is withdrawn by cancelling the plan (remediator), which is audited.
        if before is None or before.kind == PROVIDER_ACTION:
            raise _http(404, "job not found")
        from_status = before.status
        # A content scan can be stopped while running (CANCELLING until every task
        # has stopped); a check can only be withdrawn while it is still queued.
        job = (repo.request_job_cancel(before.id) if before.kind in (*CONTENT_SCAN_KINDS, "credential-usage")
               else repo.cancel_job(before.id))
        if job is None:
            raise _http(404, "job not found")
        if job.status not in ("CANCELLED", "CANCELLING"):
            raise _http(409, f"JOB_NOT_STOPPABLE: job is {job.status}; it can no longer be stopped")
        conn = repo.get_connection(job.connection_id) if job.connection_id else None
        if job.kind == CREDENTIAL_CHECK and conn is not None and from_status == "QUEUED":
            repo.record_check_event(ConnectionCheckEvent(
                connection_id=conn.id, job_id=job.id, source_type=_provider_to_source(conn.provider),
                stage="TERMINAL", job_status="CANCELLED", outcome="NOT_DISPATCHED", reason_code="JOB_CANCELLED",
                requested_by=actor_uuid(str((job.payload or {}).get("requested_by") or actor)), requested_at=job.created_at))
        return _dashboard_job(job, conn)

    @app.get("/api/v1/connections")
    def connections_page(q: str = "", provider: str = "", offset: int = 0, limit: int = 50,
                         _actor: str = Depends(require_auth)) -> dict:
        """Connections (AWS accounts and source connections) as a searched page.

        Counting and paging happen here rather than in the browser: an
        installation with more connections than one page used to be silently cut
        off at 200. ``total`` is computed over the same filter as the page, so a
        reader can tell "no connection matches" from "this page is empty", and
        ``provider_counts`` is a real total per provider rather than a sum of
        whatever pages happen to be loaded.
        """

        if offset < 0 or limit < 1 or limit > 200:
            raise _http(422, "offset must be >= 0 and limit between 1 and 200")
        needle = q.strip().lower()[:200]
        wanted = provider.strip().lower()
        allowed_providers = set(_SOURCE_TO_PROVIDER.values()) | set(PROVIDER_FAMILIES.values())
        if wanted and wanted not in allowed_providers:
            raise _http(422, f"provider must be one of {sorted(allowed_providers)}")
        selected_providers = {name for name, family in PROVIDER_FAMILIES.items() if family == wanted} | {wanted}

        approvals = _approvals()
        rows: list[tuple[str, str, str, dict]] = []
        for conn in repo.list_connections():
            # Retain the record and audit trail, but omit stopped connections
            # before counting, searching and paging the operational list.
            if (conn.credential_evidence or {}).get("revoked_at"):
                continue
            scope = _scope_ref(conn)
            text = " ".join(str(v) for v in (conn.name, conn.provider, scope, conn.id,
                                              PROVIDER_FAMILIES.get(conn.provider, ""))).lower()
            rows.append(((conn.provider or "").lower(), (conn.name or "").lower(), str(conn.id),
                         {"text": text, "item": lambda c=conn: _governance_item_source(c)}))
        # One switch read for the whole page, not one per account row.
        secrets_on = _secrets_inventory_on()
        for acct in repo.list_aws_accounts():
            text = " ".join(str(v) for v in (acct.name, acct.account_id, acct.environment, acct.id)).lower()
            rows.append(("aws", (acct.name or "").lower(), str(acct.id),
                         {"text": text, "item": lambda a=acct: _governance_item_aws(a, settings, approvals, secrets_on)}))
        # A stable order is what makes offset paging meaningful across requests.
        rows.sort(key=lambda row: (row[0], row[1], row[2]))

        matched = [row for row in rows if not needle or needle in row[3]["text"]]
        counts: dict[str, int] = {}
        for row in matched:
            counts[row[0]] = counts.get(row[0], 0) + 1
        scoped = [row for row in matched if not wanted or row[0] in selected_providers]
        page = scoped[offset:offset + limit]
        return {
            "connections": [row[3]["item"]() for row in page],
            "limit": limit,
            "offset": offset,
            "returned": len(page),
            "total": len(scoped),
            "has_more": offset + len(page) < len(scoped),
            # Kept for older clients; the same fact as has_more.
            "truncated": offset + len(page) < len(scoped),
            # Totals per provider under the search, before the provider facet, so
            # the facet can show counts without hiding what it would filter out.
            "provider_counts": counts,
            "filtered": bool(needle or wanted),
        }

    def _governance_item(kind: str, target) -> dict:
        return (_governance_item_source(target) if kind == "source"
                else _governance_item_aws(target, settings, _approvals(), _secrets_inventory_on()))

    def _authenticated_at(kind: str, target) -> str | None:
        """When the provider last accepted this connection's credential.

        A stored secret is not authentication and a refused check is not
        authentication either; only a check the provider accepted counts.
        """
        if kind == "source":
            evidence = target.credential_evidence or {}
            return evidence.get("checked_at") if evidence.get("status") == "ACTIVE" else None
        validation = aws_access.effective_validation(target, aws_access.SCANNER,
                                                     _approvals().get(aws_access.SCANNER))
        return _iso(validation["validated_at"]) if validation["status"] == "VALID" else None

    def _catalog_job_status(catalog) -> str:
        if catalog is None or catalog.refresh_job_id is None:
            return "NOT_REQUESTED"
        job = repo.get_job(catalog.refresh_job_id)
        if job is None:
            return "NOT_REQUESTED"
        return {"QUEUED": "QUEUED", "RUNNING": "RUNNING", "SUCCEEDED": "COMPLETED",
                "FAILED": "FAILED", "CANCELLING": "RUNNING",
                "CANCELLED": "CANCELLED"}.get(job.status, "NOT_REQUESTED")

    def _setup_evidence(kind: str, target) -> dict:
        """The connection's setup progress, read out of stored evidence only."""
        _t, _provider, enabled, auth, cid = _scope_target(kind, str(target.id))
        catalog = catalog_store.header(kind, cid)
        known = 0
        if catalog is not None and catalog.snapshot_id:
            _c, _items, known, _cursor = catalog_store.page(kind, cid, _scope.normalize_query({}))
        declaration = (target.config or {}).get("declaration") if kind == "source" else target.declaration
        return connection_setup.evidence(
            kind=kind, connection_id=cid, enabled=enabled, declaration=declaration,
            authenticated_at=_authenticated_at(kind, target),
            # Every v1 connection here is a content connection; a metadata-only
            # connection has no content catalog and is not one of these kinds.
            management_only=False,
            catalog=catalog, known_count=known, catalog_job_status=_catalog_job_status(catalog),
            auth=auth, profiles=_profiles_with_state(kind, cid, auth, enabled),
            checkpoint=(repo.get_setting(connection_setup.checkpoint_key(kind, cid)) or {}).get("value"),
            iso=_iso, **dict(zip(("recent_run", "recent_failure"),
                                 connection_setup.runs_of(_scope_runs(kind, cid), _iso), strict=True)))

    @app.get("/api/v1/connections/{kind}/{connection_id}/capabilities")
    def connection_capabilities(kind: str, connection_id: str, _actor: str = Depends(require_auth)) -> dict:
        target = _resolve(kind, connection_id)
        return {**_governance_item(kind, target), "onboarding": _setup_evidence(kind, target)}

    @app.post("/api/v1/connections/{kind}/{connection_id}/onboarding")
    def save_connection_setup(kind: str, connection_id: str, body: dict,
                              actor: str = Depends(require_role("admin"))) -> dict:
        """Record the administrator's own note about setup progress.

        This runs nothing. It cannot authenticate, approve a scope, submit a
        scan or enable a schedule; it stores what the administrator saw, bound
        to the evidence that existed when they saw it.
        """

        target = _resolve(kind, connection_id)
        current = _setup_evidence(kind, target)
        try:
            saved = connection_setup.validate_checkpoint(
                body, current, {row["id"] for row in current["profiles"]})
        except ValueError as exc:
            raise _http(409 if str(exc) != "SETUP_CHOICE_NOT_SUPPORTED" else 422, str(exc)) from None
        saved["saved_by"] = actor
        saved["saved_at"] = _now().isoformat()
        repo.put_setting(connection_setup.checkpoint_key(kind, target.id), saved, actor)
        return {**_governance_item(kind, target), "onboarding": _setup_evidence(kind, target)}

    @app.post("/api/v1/connections/{kind}/{connection_id}/probe")
    def probe_connection(kind: str, connection_id: str, actor: str = Depends(require_role("admin"))) -> dict:
        """Ask the provider who this connection is, and record only that.

        One read-only identity call per provider. It never reads content and
        never changes the connection's scope.
        """

        target = _resolve(kind, connection_id)
        if kind == "aws":
            _validate_account(str(target.id))
        else:
            check_connection_credential(str(target.id), actor)
        target = _resolve(kind, connection_id)
        return {**_governance_item(kind, target), "onboarding": _setup_evidence(kind, target)}

    @app.post("/api/v1/connections/{kind}/{connection_id}/profile")
    def declare_connection(kind: str, connection_id: str, body: dict,
                           _actor: str = Depends(require_role("admin"))) -> dict:
        """Record the administrator's non-secret declaration (product, auth,
        environment, purposes). A declaration is never observed evidence."""

        target = _resolve(kind, connection_id)
        declaration = _clean_declaration(body)
        if kind == "source":
            updated = repo.update_connection(target.id, config={**target.config, "declaration": declaration})
        else:
            updated = repo.update_aws_account(target.id, declaration=declaration)
        return {**_governance_item(kind, updated), "onboarding": _setup_evidence(kind, updated)}

    @app.get("/api/v1/connections/{kind}/{connection_id}/inspection")
    def connection_inspection(kind: str, connection_id: str, _actor: str = Depends(require_auth)):
        _resolve(kind, connection_id)
        # No persistent metadata investigation exists on this API: content is
        # scanned directly through the queued scan job. `null` = not started.

    def _refresh_reason(catalog) -> str | None:
        if catalog is None or catalog.refresh_job_id is None:
            return None
        job = repo.get_job(catalog.refresh_job_id)
        if job is None:
            return None
        if job.status == "QUEUED":
            return "REFRESH_QUEUED"
        if job.status == "RUNNING":
            return "REFRESH_RUNNING"
        if job.status == "FAILED":
            return (job.error or "REFRESH_FAILED").split(":", 1)[0].strip()
        return None

    def _catalog_view(kind: str, connection_id: str, query: dict) -> dict:
        _target, provider, _enabled, auth, cid = _scope_target(kind, connection_id)
        try:
            normalized = _scope.normalize_query(query)
            catalog, items, count, cursor = catalog_store.page(kind, cid, normalized)
            header = catalog.model_copy(update={"items": []}) if catalog else None
            page = _scope.catalog_page(header, kind, cid, provider, auth, {**normalized, "cursor": None},
                                       reason_code=_refresh_reason(catalog), metadata_search_enabled=provider == "notion")
            page.update(items=items, known_count=count, has_more=cursor is not None)
            if cursor:
                page["next_cursor"] = cursor
            return page
        except _scope.ScopeError as exc:
            raise _scope_error(exc)

    def _enqueue_refresh(kind: str, connection_id: str, extra: dict | None = None):
        """Queue a metadata-only listing; a pending plain refresh is not duplicated."""

        target, provider, enabled, auth, cid = _scope_target(kind, connection_id)
        if not enabled:
            raise _http(409, "CONNECTION_PAUSED: the connection is disabled or its credential was revoked")
        catalog = catalog_store.header(kind, cid)
        if not extra and _refresh_reason(catalog) in ("REFRESH_QUEUED", "REFRESH_RUNNING"):
            return catalog
        payload = {**_base_payload(kind, target, provider), "connection_kind": kind, "connection_id": str(cid),
                   "provider": provider, "source_type": _provider_to_source(provider), "auth_revision": auth,
                   **(extra or {})}
        job = repo.enqueue_job(ScanJob(kind="catalog-refresh", payload=payload, connection_id=cid))
        base = catalog or ScopeCatalog(kind=kind, connection_id=cid, auth_revision=auth)
        return catalog_store.save_header(base.model_copy(update={"refresh_job_id": job.id, "reason_code": None}))

    @app.get("/api/v1/connections/{kind}/{connection_id}/resources")
    def scope_resources(kind: str, connection_id: str, request: Request,
                        _actor: str = Depends(require_role("analyst"))) -> dict:
        """One page of the connection's resource catalog (metadata only; listing never approves content)."""

        return _catalog_view(kind, connection_id, dict(request.query_params))

    @app.post("/api/v1/connections/{kind}/{connection_id}/resources/search")
    def scope_resources_search(kind: str, connection_id: str, body: dict,
                               _actor: str = Depends(require_role("analyst"))) -> dict:
        """Catalog page filtered by selection state (selected_ids travel in the body)."""

        return _catalog_view(kind, connection_id, body)

    @app.post("/api/v1/connections/{kind}/{connection_id}/resources/refresh")
    def scope_resources_refresh(kind: str, connection_id: str, _actor: str = Depends(require_role("analyst"))) -> dict:
        """Queue a metadata refresh (catalog-refresh job); no content is scanned."""

        _enqueue_refresh(kind, connection_id)
        return _catalog_view(kind, connection_id, {})

    @app.post("/api/v1/connections/{kind}/{connection_id}/resources/resolve-reference")
    def scope_resolve_reference(kind: str, connection_id: str, body: dict,
                                _actor: str = Depends(require_role("analyst"))) -> dict:
        """Confirm one already-approved provider reference through this connection (metadata only)."""

        reference = (body or {}).get("reference")
        if not isinstance(reference, str) or not reference.strip() or len(reference) > 2048:
            raise _http(422, "reference is required")
        _enqueue_refresh(kind, connection_id, {"reference": reference.strip()})
        return _catalog_view(kind, connection_id, {})

    @app.post("/api/v1/connections/{kind}/{connection_id}/resources/notion-search", status_code=202)
    def scope_notion_search(kind: str, connection_id: str, body: dict,
                            _actor: str = Depends(require_role("admin"))) -> dict:
        """Explicit Notion title search within the integration's boundary (metadata only)."""

        _target, provider, _e, _a, _c = _scope_target(kind, connection_id)
        if provider != "notion":
            raise _http(422, "metadata search is only available for Notion connections")
        query = (body or {}).get("query")
        if not isinstance(query, str) or not query.strip() or len(query) > 256:
            raise _http(422, "query is required")
        catalog = _enqueue_refresh(kind, connection_id, {"query": query.strip()})
        return {"job_id": str(catalog.refresh_job_id), "status": "QUEUED", "mode": "METADATA_ONLY"}

    def _scope_runs(kind: str, cid) -> list:
        wanted = str(cid)
        return [job for job in repo.list_jobs(500) if job.kind == "scope"
                and (job.payload or {}).get("connection_kind") == kind and (job.payload or {}).get("connection_id") == wanted][:200]

    @app.get("/api/v1/connections/{kind}/{connection_id}/scan-scope-profiles")
    def scope_profiles(kind: str, connection_id: str, _actor: str = Depends(require_role("analyst"))) -> dict:
        """Saved scope profiles and scoped runs of a connection, with its scope state."""

        _t, _p, enabled, auth, cid = _scope_target(kind, connection_id)
        rows = _profiles_with_state(kind, cid, auth, enabled)
        return {"kind": kind, "connection_id": str(cid),
                "profiles": [_scope.profile_public(p, s) for p, s in rows[:200]],
                "runs": [_scope.run_public(j, kind, cid) for j in _scope_runs(kind, cid)],
                "state": _scope.connection_state([s for _, s in rows], enabled=enabled)}

    @app.post("/api/v1/connections/{kind}/{connection_id}/scan-scope-profiles", status_code=201)
    def create_scope_profile(kind: str, connection_id: str, body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        """Save a new approved scope profile (exact resource ids and per-resource options)."""

        return _save_profile(kind, connection_id, body, actor)

    @app.post("/api/v1/connections/{kind}/{connection_id}/selection-drafts", status_code=201)
    def create_selection_draft(kind: str, connection_id: str, body: dict, _actor: str = Depends(require_role("analyst"))) -> dict:
        """Freeze every catalog match of a query into exact resource ids (never a growing selection).

        ``patterns`` (optional): names or paths with ``*`` and ``?`` (``platform/*``); a resource is kept
        when its name or reference matches one of them."""

        _t, _p, _e, auth, cid = _scope_target(kind, connection_id)
        catalog = catalog_store.header(kind, cid)
        if catalog is None or not catalog.snapshot_id:
            raise _http(409, "SCOPE_CATALOG_NOT_COLLECTED: refresh the resource catalog first")
        patterns = (body or {}).get("patterns") or []
        if (not isinstance(patterns, list) or len(patterns) > 64
                or any(not isinstance(p, str) or not p.strip() or len(p) > 256 for p in patterns)):
            raise _http(422, "patterns must be up to 64 names or paths")
        patterns = [p.strip().lower() for p in patterns]
        try:
            query = _scope.normalize_query({k: v for k, v in (body or {}).items() if k != "patterns"})
        except _scope.ScopeError as exc:
            raise _scope_error(exc)
        query.pop("cursor", None)
        catalog, matches = catalog_store.matching(kind, cid, query)
        if patterns:
            limited = len(matches) > _scope.MAX_ROOTS
            matches = [item for item in matches if any(
                fnmatch.fnmatchcase(str(item.get(key) or "").lower(), pattern)
                for key in ("display_name", "canonical_reference", "provider_resource_id") for pattern in patterns)]
            query["patterns"] = patterns
        else:
            limited = False
        draft = repo.create_draft(SelectionDraft(
            kind=kind, connection_id=cid, catalog_snapshot_id=catalog.snapshot_id, auth_revision=catalog.auth_revision or auth,
            query=query, resource_ids=[i["id"] for i in matches[:_scope.MAX_ROOTS]], status="READY",
            unknown_remainder=limited or len(matches) > _scope.MAX_ROOTS or catalog.completeness != "COMPLETE",
            expires_at=_now() + _scope.DRAFT_TTL))
        return _scope.draft_public(draft, matches[:_scope.MAX_ROOTS])
