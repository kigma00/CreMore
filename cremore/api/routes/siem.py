"""SIEM delivery operations: destination status, test events, held deliveries, and a finding sent on request.

The API never sees a destination's endpoint or token; those live only in the
exporter's configuration. It reads what the exporter recorded per destination id.
"""

from __future__ import annotations

import uuid

from fastapi import Depends

from cremore.api.http_support import http_error, parse_uuid
from cremore.api.http_support import utc_now as _now
from cremore.api.route_context import DashboardContext
from cremore.domain.models import FindingEvent
from cremore.operations.evaluator import backlogged, exporter_active
from cremore.operations.retention import ACTIVE_WITHIN
from cremore.siem.events import finding_forwarded, siem_test
from cremore.siem.outbox import SiemOutbox


def register(ctx: DashboardContext) -> None:
    app, repo, require_role = ctx.app, ctx.repo, ctx.require_role

    @app.get("/api/v1/siem/status")
    def siem_status(_actor: str = Depends(require_role("admin"))) -> dict:
        now = _now()
        destinations = SiemOutbox(repo).status()
        for row in destinations:
            row["exporter_active"] = exporter_active(row, now)
            row["backlogged"] = backlogged(row, now)
        # The installation id every event carries, for filtering one install in a shared SIEM.
        return {"generated_at": now.isoformat(), "installation_id": repo.installation_id(),
                "destinations": destinations,
                "exporter_active": any(row["exporter_active"] for row in destinations)}

    @app.post("/api/v1/siem/test-event")
    def siem_test_event(actor: str = Depends(require_role("admin"))) -> dict:
        """Queue a siem.test event for every destination; follow it with the deliveries route."""
        event = siem_test(now=_now(), nonce=uuid.uuid4())
        repo.record_siem_event(event)
        repo.record_finding_event(FindingEvent(target_type="siem_event", target_id=uuid.UUID(event["event_id"]),
                                               actor=actor, event_type="SIEM_TEST_EVENT_QUEUED"))
        return {"event_id": event["event_id"], "event_type": event["event_type"]}

    @app.post("/api/v1/findings/{finding_id}/forward", status_code=202)
    def forward_finding(finding_id: str, actor: str = Depends(require_role("analyst"))) -> dict:
        """Send a finding as it stands to the SIEM and webhook destinations (``finding.forwarded``), audited in the
        same transaction. One event per person, finding and minute: a repeated click is that event again."""
        finding = repo.get_finding(parse_uuid(finding_id, "finding_id"))
        if finding is None:
            raise http_error(404, "FINDING_NOT_FOUND")
        now = _now()
        destinations = SiemOutbox(repo).seen_since(now - ACTIVE_WITHIN)
        if not destinations:
            raise http_error(409, "SIEM_NOT_CONFIGURED: no SIEM or webhook destination takes events from this installation")
        minute = now.replace(second=0, microsecond=0).isoformat()
        event = finding_forwarded(finding, repo.get_credential(finding.credential_id), now=now,
                                  request_id=uuid.uuid5(uuid.NAMESPACE_URL, f"cremore:forward:{actor}:{finding.id}:{minute}"))
        repo.record_siem_event(event, audit=FindingEvent(finding_id=finding.id, actor=actor, event_type="FORWARDED_TO_SIEM",
                                                         note=f"event_id={event['event_id']}"))
        return {"event_id": event["event_id"], "event_type": event["event_type"], "destinations": len(destinations)}

    @app.get("/api/v1/siem/events/{event_id}/deliveries")
    def siem_event_deliveries(event_id: str, _actor: str = Depends(require_role("admin"))) -> dict:
        return {"event_id": str(parse_uuid(event_id, "event_id")),
                "deliveries": SiemOutbox(repo).deliveries(event_id)}

    @app.post("/api/v1/siem/destinations/{destination}/release-held")
    def siem_release_held(destination: str, actor: str = Depends(require_role("admin"))) -> dict:
        """Give a destination's held deliveries a fresh round of attempts."""
        try:
            released = SiemOutbox(repo).release_held(destination)
        except ValueError:
            raise http_error(422, "SIEM_INVALID_DESTINATION: destination ids are lowercase letters, digits, - and _") from None
        repo.record_finding_event(FindingEvent(target_type="siem_destination", actor=actor,
                                               event_type="SIEM_HELD_RELEASED", note=f"{destination}:{released}"))
        return {"destination": destination, "released": released}
