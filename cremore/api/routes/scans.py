"""Scan scope, the runs it produces, and what each run actually covered.

Registered by the dashboard composition root. Shared behavior is imported
from independent API libraries; dependencies arrive through DashboardContext.
"""

from __future__ import annotations

from fastapi import Depends

from cremore.api.http_support import http_error as _http
from cremore.api.http_support import parse_uuid as _uuid
from cremore.api.http_support import utc_now as _now
from cremore.api.route_context import DashboardContext
from cremore.api.source_presenters import present_scan_run
from cremore.scanning import scope as _scope
from cremore.scanning import trigger_settings


def register(ctx: DashboardContext) -> None:
    from cremore.api.routes import notion_hooks

    notion_hooks.register(ctx)
    _profile_or_404, _save_profile, _scope_plan_or_404, _scope_target = ctx._profile_or_404, ctx._save_profile, ctx._scope_plan_or_404, ctx._scope_target
    _start_run, app, catalog_store, current_detection_digest = ctx._start_run, ctx.app, ctx.catalog_store, ctx.current_detection_digest
    repo, require_auth, require_role, settings = ctx.repo, ctx.require_auth, ctx.require_role, ctx.settings

    @app.get("/api/v1/scan-activity")
    def scan_activity(_actor: str = Depends(require_auth)) -> dict:
        """Compatibility summary of the oldest pending content run, not a start lock.

        The run list exposes concurrent work; new work can always be queued.
        """
        return {"active": _scope.active_scan_public(repo.active_content_job())}

    @app.get("/api/v1/scans")
    def scans(_actor: str = Depends(require_auth)) -> list[dict]:
        # Account-wide AWS scans are not a job kind here; S3 runs as a source scan.
        return []

    @app.get("/api/v1/scan-runs")
    def scan_runs(_actor: str = Depends(require_auth)) -> list[dict]:
        # Surface the queued/finished scan jobs as scan runs, with coverage detail.
        digest = current_detection_digest()
        return [present_scan_run(job, digest, task_states=ctx.task_states) for job in repo.list_jobs(200)]

    @app.get("/api/v1/scan-runs/{job_id}")
    def scan_run(job_id: str, _actor: str = Depends(require_auth)) -> dict:
        from cremore.coverage.github_exports import job_state
        from cremore.operations.collection_schedule import for_job

        job = repo.get_job(_uuid(job_id, "job_id"))
        if job is None:
            raise _http(404, "SCAN_RUN_NOT_FOUND")
        return {**present_scan_run(job, current_detection_digest(), task_states=ctx.task_states),
                "schedule": for_job(repo, settings, job), "enterprise_export": job_state(repo, job)}

    @app.patch("/api/v1/scan-scope-profiles/{profile_id}")
    def update_scope_profile(profile_id: str, body: dict, actor: str = Depends(require_role("admin"))) -> dict:
        """Save a new version of a scope profile (expected_version guards the edit)."""

        existing = _profile_or_404(profile_id)
        return _save_profile(existing.kind, str(existing.connection_id), body, actor, existing=existing)

    @app.post("/api/v1/scan-scope-profiles/{profile_id}/preview")
    def preview_scope_profile(profile_id: str, _actor: str = Depends(require_role("analyst"))) -> dict:
        """Resolve the saved profile against the current catalog into a fixed, expiring plan."""

        profile = _profile_or_404(profile_id)
        _t, _p, enabled, auth, cid = _scope_target(profile.kind, str(profile.connection_id))
        catalog = catalog_store.selected(profile.kind, cid, [r["resource_id"] for r in _scope.effective_roots(profile)])
        configured = set()
        if trigger_settings.schedules_on(settings, repo):
            configured.add("SCHEDULE")
        if str(profile.id) in trigger_settings.event_profiles(settings, repo) or (
                trigger_settings.change_feeds_on(settings, repo)
                and _scope.provider_of(profile.kind, _t) in trigger_settings.CHANGE_FEED_PROVIDERS):
            configured.add("EVENT")
        plan = repo.create_plan(_scope.build_plan(profile, catalog, auth=auth, enabled=enabled,
                                                 configured_triggers=configured))
        state = _scope.profile_state(profile, auth=auth, enabled=enabled)
        return _scope.plan_public(plan, _scope.profile_public(profile, state))

    def _draft_view(draft) -> dict:
        if (draft.status == "READY" and draft.expires_at
                and _scope.parse_stamp(draft.expires_at.isoformat()) <= _now()):
            draft = repo.update_draft(draft.id, status="EXPIRED")
        resources: list = []
        if draft.status == "READY":
            catalog = catalog_store.selected(draft.kind, draft.connection_id, draft.resource_ids)
            items = {i["id"]: i for i in (catalog.items if catalog else [])}
            if catalog is None or catalog.snapshot_id != draft.catalog_snapshot_id or any(i not in items for i in draft.resource_ids):
                draft = repo.update_draft(draft.id, status="EXPIRED")
            else:
                resources = [items[i] for i in draft.resource_ids]
        return _scope.draft_public(draft, resources)

    def _draft_or_404(draft_id: str):
        draft = repo.get_draft(_uuid(draft_id, "draft_id"))
        if draft is None:
            raise _http(404, "selection draft not found")
        return draft

    @app.get("/api/v1/selection-drafts/{draft_id}")
    def get_selection_draft(draft_id: str, _actor: str = Depends(require_role("analyst"))) -> dict:
        return _draft_view(_draft_or_404(draft_id))

    @app.post("/api/v1/selection-drafts/{draft_id}/cancel")
    def cancel_selection_draft(draft_id: str, _actor: str = Depends(require_role("analyst"))) -> dict:
        draft = _draft_or_404(draft_id)
        if draft.status in ("QUEUED", "PREPARING", "READY"):
            draft = repo.update_draft(draft.id, status="CANCELLED")
        return _scope.draft_public(draft, [])

    @app.post("/api/v1/scan-runs", status_code=202)
    def create_scan_run(body: dict, actor: str = Depends(require_role("analyst"))) -> dict:
        """Start one run of an executable, unexpired plan (idempotent per plan)."""

        plan = _scope_plan_or_404((body or {}).get("plan_id"))
        if plan.trigger != "BASELINE":
            raise _http(422, "this plan is a finding rescan; start it through the finding")
        return _start_run(plan, (body or {}).get("profile_version"), actor, (body or {}).get("mode", "BASELINE"))

    def _run_or_404(run_id: str):
        job = repo.get_job(_uuid(run_id, "run_id"))
        if job is None or job.kind != "scope":
            raise _http(404, "scan run not found")
        return job

    @app.get("/api/v1/scan-runs/{run_id}/coverage")
    def scan_run_coverage(run_id: str, _actor: str = Depends(require_auth)) -> dict:
        """The run's observed coverage counters (objects, bytes, requests, budget stops)."""

        job = _run_or_404(run_id)
        p = job.payload or {}
        return _scope.run_public(job, p.get("connection_kind", "source"), p.get("connection_id") or job.connection_id)

    @app.post("/api/v1/scan-runs/{run_id}/cancel")
    def cancel_scan_run(run_id: str, _actor: str = Depends(require_role("analyst"))) -> dict:
        job = _run_or_404(run_id)
        job = repo.request_job_cancel(job.id) or job
        p = job.payload or {}
        return _scope.run_public(job, p.get("connection_kind", "source"), p.get("connection_id") or job.connection_id)
