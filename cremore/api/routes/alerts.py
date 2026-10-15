"""Slack alerts for new detections (cremore/alerts): an Admin's setup, how delivery stands, and a test message.

Registered by the dashboard composition root. The webhook address is sealed on arrival and never returned; saves are
audited with the change (cremore/installation_settings.py) and each test by its outcome code.
"""

from __future__ import annotations

import uuid

from fastapi import Depends, Response

from cremore.api.http_support import actor_label as _actor_label
from cremore.api.http_support import http_error as _http
from cremore.api.http_support import isoformat as _iso
from cremore.api.route_context import DashboardContext

_TARGET = uuid.uuid5(uuid.NAMESPACE_URL, "cremore:detection_alerts")


def register(ctx: DashboardContext) -> None:
    app, repo, require_role, settings = ctx.app, ctx.repo, ctx.require_role, ctx.settings

    def _view() -> dict:
        from cremore.alerts import delivery, setup

        row = repo.get_setting(setup.KEY) or {}
        return {**setup.public(repo), "updated_by": _actor_label(row.get("updated_by")),
                "updated_at": _iso(row.get("updated_at")), "status": delivery.status(repo)}

    @app.get("/api/v1/settings/detection-alerts")
    def get_detection_alerts(response: Response, _actor: str = Depends(require_role("admin"))) -> dict:
        response.headers["Cache-Control"] = "no-store"
        return _view()

    @app.put("/api/v1/settings/detection-alerts")
    def put_detection_alerts(body: dict, response: Response, actor: str = Depends(require_role("admin"))) -> dict:
        """Change the fields sent; a blank webhook keeps the saved one, console_url is the contact setup's."""
        from cremore.alerts import setup

        response.headers["Cache-Control"] = "no-store"
        try:
            setup.save(repo, settings, body, actor)
        except setup.AlertSetupError as exc:
            raise _http(exc.http_status, exc.code) from None
        return _view()

    @app.post("/api/v1/settings/detection-alerts/test")
    def test_detection_alerts(actor: str = Depends(require_role("admin"))) -> dict:
        """One test message with the saved setup, sent from this API process: {delivered, error_code}."""
        from cremore.alerts import delivery
        from cremore.domain.models import FindingEvent

        sent = delivery.send_test(repo, settings, http_client_factory=getattr(app.state, "alerts_http_client_factory", None))
        repo.record_finding_event(FindingEvent(target_type="detection_alerts", target_id=_TARGET, actor=actor,
                                               event_type="DETECTION_ALERTS_TESTED",
                                               note="delivered" if sent["delivered"] else f"failed={sent['error_code']}"))
        return sent
