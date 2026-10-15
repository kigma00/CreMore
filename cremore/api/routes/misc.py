"""The small reads every screen needs: the session, the audit log, the catalogs.

Registered by the dashboard composition root. Shared behavior is imported
from independent API libraries; dependencies arrive through DashboardContext.
"""

from __future__ import annotations

import datetime as _dt
import re
import threading
import time
import uuid

from fastapi import Depends
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from cremore import detection
from cremore.api.activity_audit import profiles as activity_profiles
from cremore.api.activity_audit import public as activity_public
from cremore.api.detection_catalog import credential_type_catalog as _credential_type_catalog
from cremore.api.detection_catalog import credential_types as _credential_types
from cremore.api.detection_catalog import detector_catalog as _detector_catalog
from cremore.api.http_support import http_error
from cremore.api.http_support import isoformat as _iso
from cremore.api.http_support import utc_now as _now
from cremore.api.route_context import DashboardContext
from cremore.api.source_contract import SOURCE_TYPES as _SOURCE_TYPES
from cremore.api.source_presenters import present_connection as _dashboard_connection
from cremore.domain.models import FindingEvent
from cremore.governance import response_threads
from cremore.operations import audit_integrity, health, heartbeat
from cremore.operations.evaluator import backlogged, exporter_active
from cremore.risk import POLICY_VERSION
from cremore.scanning import verification_switch
from cremore.scanning.scope import job_is_partial
from cremore.siem.outbox import SiemOutbox


class DetectorSwitch(BaseModel):
    """Turn one built-in detector on or off for this installation."""

    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool


class AuditAcknowledgement(BaseModel):
    """Problems of the audit chain an admin has examined, by the ``ack`` key the check gave each one."""

    model_config = ConfigDict(extra="forbid")
    items: list[str] = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=500)

    @field_validator("items")
    @classmethod
    def known(cls, value):
        if any(not audit_integrity.ITEM.match(item) for item in value) or len(set(value)) != len(value):
            raise ValueError("AUDIT_ACK_INVALID: items are distinct problem keys (KIND@seq:N#evidence) from the last check")
        return value

    @field_validator("reason")
    @classmethod
    def said(cls, value):
        if not value.strip() or not value.isprintable():
            raise ValueError("AUDIT_ACK_REASON_REQUIRED")
        return value.strip()


class ExpiryDeclaration(BaseModel):
    """An operator-entered expiry for a credential whose provider does not report one."""

    model_config = ConfigDict(extra="forbid")
    expires_at: _dt.datetime | None

    @field_validator("expires_at")
    @classmethod
    def bounded(cls, value):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("EXPIRY_TIMEZONE_REQUIRED")
        value = value.astimezone(_dt.UTC)
        if not _dt.datetime(2000, 1, 1, tzinfo=_dt.UTC) <= value <= _now() + _dt.timedelta(days=3660):
            raise ValueError("EXPIRY_OUT_OF_RANGE")
        return value


def register(ctx: DashboardContext) -> None:
    _aws_hold, app, repo, require_auth = ctx._aws_hold, ctx.app, ctx.repo, ctx.require_auth
    require_role, settings = ctx.require_role, ctx.settings

    @app.get("/api/v1/detection-engine")
    def detection_engine(_actor: str = Depends(require_auth)) -> dict:
        from cremore.detection import switches

        changed = switches.changes(repo)
        detectors = _detector_catalog(frozenset(i for i, row in changed.items() if not row["enabled"]))
        for detector in detectors:
            if detector["id"] in changed:
                detector["switched_by"] = changed[detector["id"]]["updated_by"]
                detector["switched_at"] = _iso(changed[detector["id"]]["updated_at"])
        return {
            "name": detection.NAME,
            "display_name": "CreMore native engine",
            "version": detection.VERSION,
            "mode": "INDEPENDENT",
            "coverage_status": "BACKEND_MANAGED",
            "detector_scope": "CATALOG_ONLY",
            "collection_sources": _SOURCE_TYPES,
            "network_verification": verification_switch.effective(settings, repo),
            "risk_policy": POLICY_VERSION,
            "scan_policy": {"max_object_size_mb": settings.max_object_size_mb, "archives_enabled": False},
            "detectors": detectors,
        }

    @app.put("/api/v1/detection-engine/detectors/{detector_id}")
    def switch_detector(detector_id: str, body: DetectorSwitch, actor: str = Depends(require_role("admin"))) -> dict:
        """Leave a built-in detector out of scans from the next rule refresh, or bring it back. A change is stored
        with the audit row naming it, as every installation setting is; an unchanged switch stores nothing."""
        from cremore.api.routes.settings import locked_installation_settings, setting_changed
        from cremore.detection import switches

        try:
            switches.require_known(detector_id)
        except ValueError as exc:
            raise http_error(404, str(exc)) from None
        key = switches.PREFIX + detector_id
        with locked_installation_settings(repo) as bound:
            record = bound.get_setting(key)
            changed = switches.is_on(record) != body.enabled
            if changed:
                record = bound.put_setting(key, {"enabled": body.enabled}, actor)
                setting_changed(bound, actor, key, {"enabled": body.enabled})
        orchestrator = getattr(app.state, "orchestrator", None)
        if changed and orchestrator is not None:
            orchestrator.refresh_rules()  # this process's inline scans follow at once; workers within a minute
        return {"id": detector_id, "enabled": body.enabled, "switched_by": (record or {}).get("updated_by"),
                "switched_at": _iso((record or {}).get("updated_at"))}

    @app.get("/api/v1/credential-types")
    def credential_types(_actor: str = Depends(require_auth)) -> list[dict]:
        return _credential_types()

    @app.get("/api/v1/credential-type-catalog")
    def credential_type_catalog(_actor: str = Depends(require_auth)) -> dict:
        return _credential_type_catalog()

    @app.get("/api/v1/operations/status")
    def operations_status(_actor: str = Depends(require_role("admin"))) -> dict:
        """Safe operational roll-up; provider errors and job payloads stay private."""

        connections = [_dashboard_connection(c) for c in repo.list_connections()]
        observed_jobs = repo.list_jobs(501)
        jobs, jobs_truncated = observed_jobs[:500], len(observed_jobs) > 500
        auth_states = (
            "READY", "REAUTH_REQUIRED", "SECRET_UNAVAILABLE", "AUTH_EXPIRED",
            "AUTH_LIFETIME_TOO_SHORT", "AUTH_FRESHNESS_UNKNOWN", "DISABLED",
        )
        auth_counts = {state: 0 for state in auth_states}
        alerts = []
        for connection in connections:
            state = connection["connection_auth"]["state"]
            auth_counts[state] = auth_counts.get(state, 0) + 1
            needs_auth = (
                connection.get("credential_source") != "NONE"
                or connection.get("source_type") == "s3"
            )
            if state not in ("READY", "DISABLED") and needs_auth:
                alerts.append({
                    "code": f"CONNECTION_{state}",
                    "resource_type": "connection",
                    "resource_id": connection["id"],
                })
        health_items = health.evaluate(repo, settings)
        # Before the per-job alerts, which alone can fill the cap of 100.
        alerts.extend(health.feed_alerts(repo, settings, health_items))
        job_counts = {state: 0 for state in ("QUEUED", "RUNNING", "FAILED", "PARTIAL")}
        for job in jobs:
            if job.status in job_counts:
                job_counts[job.status] += 1
            # A run partial only for the upgrade hold waits, as planned, for the scope's next full scan.
            if job_is_partial(job) and not (job.coverage or {}).get("policy_held_only"):
                job_counts["PARTIAL"] += 1
                alerts.append({"code": "JOB_PARTIAL", "resource_type": "job",
                               "resource_id": str(job.id)})
            if job.status == "FAILED":
                alerts.append({"code": "JOB_FAILED", "resource_type": "job",
                               "resource_id": str(job.id)})
        if job_counts["QUEUED"] and not job_counts["RUNNING"]:
            activity = "QUEUE_WAITING"
        elif job_counts["RUNNING"]:
            activity = "PROCESSING"
        else:
            activity = "IDLE_OR_UNOBSERVED"
        alerts.extend(health.alerts(health_items, settings))
        beats, waiting = heartbeat.workers(repo), heartbeat.queue(repo)
        alive = sum(row["alive"] for row in beats)
        if beats and not alive:
            alerts.append({"code": "WORKER_HEARTBEAT_MISSING", "resource_type": "worker", "resource_id": "all"})
        now, siem_rows = _now(), SiemOutbox(repo).status()
        behind = [row["destination"] for row in siem_rows if backlogged(row, now)]
        siem_active = any(exporter_active(row, now) for row in siem_rows)
        alerts.extend({"code": "SIEM_DELIVERY_BACKLOG", "resource_type": "siem_destination", "resource_id": name}
                      for name in behind)
        if siem_rows and not siem_active:
            alerts.append({"code": "SIEM_EXPORTER_INACTIVE", "resource_type": "siem", "resource_id": "exporter"})
        alerts.extend(response_threads.alerts(repo, now=now))
        # The installation's own alerts (how it reaches AWS, its workers, its SIEM exporter, the response threads' job)
        # lead and are never cut by the cap on per-connection and per-job alerts, which a busy install reaches first.
        whole = ("aws_identity", "worker", "siem", "response_threads")
        installation = [alert for alert in alerts if alert["resource_type"] in whole]
        alerts = [alert for alert in alerts if alert["resource_type"] not in whole]
        return {
            "generated_at": _now().isoformat(),
            "authentication": {"counts": auth_counts, "total": len(connections)},
            "connection_health": health.summarize(health_items),
            "siem": {"destinations": len(siem_rows), "exporter_active": siem_active, "backlogged": behind},
            "worker": {
                "activity": activity,
                "queued_jobs": job_counts["QUEUED"],
                "running_jobs": job_counts["RUNNING"],
                # Database beats from each worker; a supervisor still restarts a stuck process.
                "availability": ("HEARTBEAT_OBSERVED" if alive else "HEARTBEAT_MISSING" if beats
                                 else "EXTERNAL_PROBE_REQUIRED"),
                "health_source": "WORKER_HEARTBEAT_OR_PROCESS_SUPERVISOR",
                "alive": alive,
                "observed": len(beats),
                "last_beat_at": beats[0].get("beat_at") if beats else None,
                "queue_delay_seconds": waiting["oldest_queued_seconds"],
                "instances": [{key: row.get(key) for key in ("worker_id", "host", "version", "started_at",
                                                             "beat_at", "alive")} for row in beats[:20]],
                "heartbeat_interval_minutes": settings.operations_heartbeat_minutes,
            },
            "jobs": {"counts": job_counts, "observed": len(jobs), "truncated": jobs_truncated},
            "alerts": ([{"code": hold, "resource_type": "aws_identity", "resource_id": "worker"}]
                       if (hold := _aws_hold()) else []) + installation + alerts[:100],
            "alerts_truncated": len(alerts) > 100,
        }

    @app.get("/api/v1/operations/connections")
    def connection_health(_actor: str = Depends(require_auth)) -> dict:
        """Every connection kind in one health vocabulary; codes only, never secrets."""

        items = health.evaluate(repo, settings)
        return {"generated_at": _now().isoformat(), "summary": health.summarize(items), "items": items}

    @app.put("/api/v1/operations/connections/{key}/expiry")
    def declare_connection_expiry(key: str, body: ExpiryDeclaration,
                                  actor: str = Depends(require_role("admin"))) -> dict:
        """Record when a credential expires when its provider does not say; null clears it."""

        item = next((i for i in health.evaluate(repo, settings) if i["key"] == key), None)
        if item is None:
            raise http_error(404, "CONNECTION_NOT_FOUND: no connection has this health key")
        value = body.expires_at.isoformat() if body.expires_at else None
        repo.put_setting(health.EXPIRY_PREFIX + key, {"expires_at": value}, actor)
        repo.record_finding_event(FindingEvent(
            target_type="connection_health", target_id=uuid.UUID(item["id"]), actor=actor,
            event_type="CONNECTION_EXPIRY_DECLARED" if value else "CONNECTION_EXPIRY_CLEARED", note=value))
        return next(i for i in health.evaluate(repo, settings) if i["key"] == key)

    @app.get("/api/v1/audit")
    def audit(_actor: str = Depends(require_auth), limit: int = 200) -> list[dict]:
        limit = max(1, min(limit, 1000))
        events = repo.list_events(limit)
        profiles = activity_profiles(repo, {e.actor for e in events})
        connections = repo.list_connections()
        connection_names = {c.id: c.name for c in connections}
        finding_names = {}
        for finding_id in {e.target_id or e.finding_id for e in events
                           if (e.target_type or "finding") == "finding" and (e.target_id or e.finding_id)}:
            finding = repo.get_finding(finding_id)
            credential = repo.get_credential(finding.credential_id) if finding else None
            if credential:
                # Use only the same masked hint exposed in the findings list.
                finding_names[finding_id] = " · ".join(value for value in (
                    credential.credential_type, credential.identifier_hint) if value)
        rows = [{
            "id": str(e.id),
            "actor_id": e.actor,
            # A finding's events keep the prefix readers already know; anything
            # else names its own action, because "FINDING_CONNECTION_STOPPED"
            # would describe the wrong thing.
            "action": f"FINDING_{e.event_type}" if (e.target_type or "finding") == "finding" else e.event_type,
            "target_type": e.target_type or "finding",
            "target_id": str(e.target_id or e.finding_id or ""),
            "target_name": connection_names.get(e.target_id) if e.target_type == "connection" else
                finding_names.get(e.target_id or e.finding_id) if (e.target_type or "finding") == "finding" else None,
            "from_status": e.from_status,
            "to_status": e.to_status,
            "note": e.note,
            "created_at": _iso(e.created_at) or "",
            **activity_public(e, profiles.get(e.actor)),
        } for e in events]
        recorded_stops = {e.target_id for e in events
                          if e.target_type == "connection" and e.event_type == "CONNECTION_STOPPED"}
        # Older installations saved revocation evidence without an audit event.
        # Expose that evidence explicitly; do not fabricate an actor or a new event.
        for connection in connections:
            evidence = connection.credential_evidence or {}
            if not evidence.get("revoked_at") or connection.id in recorded_stops:
                continue
            rows.append({
                "id": f"connection-stop-record:{connection.id}",
                "actor_id": evidence.get("revoked_by") or "UNKNOWN",
                "action": "CONNECTION_STOPPED", "target_type": "connection",
                "target_id": str(connection.id), "target_name": connection.name,
                "from_status": None, "to_status": "DISABLED",
                "note": evidence.get("revocation_reason"),
                "created_at": str(evidence["revoked_at"]),
                "recovered_from_connection": True,
            })

        def event_time(row):
            try:
                value = _dt.datetime.fromisoformat(row["created_at"])
                return (value if value.tzinfo else value.replace(tzinfo=_dt.UTC)).timestamp()
            except (ValueError, TypeError):
                return float("-inf")

        rows.sort(key=event_time, reverse=True)
        return rows[:limit]

    checks = {"lock": threading.Lock(), "walk": None, "at": 0.0}

    def walked(fresh: bool = False) -> dict:
        """The last walk while it is under a minute old; else one walk, never two at once (429 while one runs)."""
        if not fresh and checks["walk"] is not None and time.monotonic() - checks["at"] < 60:
            return checks["walk"]
        if not checks["lock"].acquire(blocking=False):
            raise http_error(429, "AUDIT_CHECK_RUNNING: an integrity check is running; try again shortly")
        try:
            checks["walk"], checks["at"] = audit_integrity.walk(repo, settings), time.monotonic()
            return checks["walk"]
        finally:
            checks["lock"].release()

    @app.get("/api/v1/audit/integrity")
    def audit_integrity_check(_actor: str = Depends(require_role("analyst")),
                              anchor_seq: int | None = None, anchor_mac: str | None = None) -> dict:
        """Verify the audit trail's hash chain, optionally against a head kept outside CreMore."""
        if (anchor_seq is None) != (anchor_mac is None):
            raise http_error(422, "ANCHOR_INVALID: give both anchor_seq and anchor_mac")
        anchor = None
        if anchor_seq is not None:
            if anchor_seq < 1 or not re.fullmatch(r"[0-9a-f]{64}", anchor_mac or ""):
                raise http_error(422, "ANCHOR_INVALID: anchor_seq is a chain position, anchor_mac 64 lowercase hex digits")
            anchor = (anchor_seq, anchor_mac)
        # An anchor is one lookup on top of the last walk, so asking about many anchors walks once.
        return audit_integrity.with_anchor(repo, walked(), anchor)

    @app.post("/api/v1/audit/integrity/acknowledge")
    def acknowledge_audit_problems(body: AuditAcknowledgement, actor: str = Depends(require_role("admin"))) -> dict:
        """Accept problems open now, each as it is now; the acknowledgement is a chained audit row itself."""
        from cremore.api.routes.credentials import (
            _credentials_in,
        )

        if _credentials_in(app.state.orchestrator, body.reason):
            raise http_error(422, "TEXT_CONTAINS_CREDENTIAL: the reason looks like it holds a secret value")
        if not checks["lock"].acquire(blocking=False):
            raise http_error(429, "AUDIT_CHECK_RUNNING: an integrity check is running; try again shortly")
        try:
            audit_integrity.acknowledge(repo, settings, actor, body.items, body.reason)
        except ValueError as exc:
            raise http_error(422, f"{exc}: acknowledge only problems open now, as the last check named them") from None
        finally:
            checks["lock"].release()
        checks["walk"] = None
        return {"acknowledged": len(body.items)}
