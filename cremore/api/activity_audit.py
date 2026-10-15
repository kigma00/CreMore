"""OIDC request receipts in the existing MAC-protected, append-only audit trail.

The signed session is first observed at the API, not at the IdP's password/MFA screen.
Only declared routes, UUID targets, verified identity and HTTP status are retained.
Bodies, query strings, headers, bearer tokens and exception text never enter a receipt.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid

from fastapi import HTTPException
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from cremore.db.settings_store import locked_settings
from cremore.domain.models import FindingEvent

logger = logging.getLogger(__name__)
LOCK = "activity-audit:lock"
SYSTEM = "system:principals"


def _text(value, limit):
    return "".join(char for char in (value or "") if char.isprintable())[:limit] or None


def _profile_key(subject):
    return "activity-audit:sessions:" + hashlib.sha256(subject.encode()).hexdigest()


def profiles(repo, subjects):
    """Current verified display profiles; never infer a person from a name or email."""
    return {subject: ((repo.get_setting(_profile_key(subject)) or {}).get("value") or {}).get("profile", {})
            for subject in subjects if subject and subject != "UNKNOWN"}


def public(event, profile=None):
    """Expose the versioned receipt without changing historical event/chain fields."""
    display = {"actor_name": (profile or {}).get("name"), "actor_email": (profile or {}).get("email"),
               "actor_profile_basis": "CURRENT_SIGN_IN"} if profile else {}
    if event.target_type not in {"api_request", "sign_in"}:
        return display
    try:
        data = json.loads(event.note or "")
    except (TypeError, ValueError):
        return display
    if not isinstance(data, dict) or data.get("schema") != 1:
        return display
    return {"actor_name": data.get("name"), "actor_email": data.get("email"),
            "actor_profile_basis": "EVENT_SNAPSHOT",
            "activity": {key: data.get(key) for key in ("method", "route", "targets", "status", "role", "session_basis")}}


class ActivityAudit:
    def __init__(self, repo):
        self.repo = repo
        # Parent exists before locked_settings locks it, including on concurrent API startups.
        repo.put_setting(LOCK, {"version": 1}, SYSTEM)

    def _event(self, scope, kind, status=None, *, sign_in=False):
        state = scope.setdefault("state", {})
        who = state.get("audit_principal")
        targets = {}
        for name, value in scope.get("path_params", {}).items():
            try:
                targets[name] = str(uuid.UUID(str(value)))
            except (ValueError, TypeError, AttributeError):
                pass  # Free-form route parameters can contain secrets, so keep the template only.
        note = {"schema": 1, "name": _text(who.display_name, 200) if who else None,
                "email": _text(who.email, 320) if who else None, "role": who.role if who else None,
                "method": scope["method"] if scope["method"] in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} else "OTHER",
                "route": getattr(scope.get("route"), "path", "UNMATCHED"),
                "targets": targets, "status": status}
        if sign_in:
            note["session_basis"] = who.session_basis
        request_id = state.setdefault("audit_request_id", uuid.uuid4())
        return FindingEvent(target_type="sign_in" if sign_in else "api_request", target_id=request_id,
                            actor=who.subject if who else "UNKNOWN", event_type=kind,
                            note=json.dumps(note, ensure_ascii=False, separators=(",", ":")))

    def begin(self, request, principal):
        state = request.scope.setdefault("state", {})
        if state.get("audit_started"):
            return
        state["audit_principal"] = principal
        try:
            # The receipt must be durable before the route (or its role gate) can run.
            self.repo.record_finding_event(self._event(request.scope, "API_REQUEST_STARTED"))
            state["audit_started"] = True
            self._session(request.scope, principal)
        except Exception as exc:  # noqa: BLE001 -- fail closed without leaking database/identity material
            logger.error("activity audit unavailable: %s", type(exc).__name__)
            raise HTTPException(503, "AUDIT_RECORDING_UNAVAILABLE") from None

    def _session(self, scope, principal):
        key = _profile_key(principal.subject)
        profile = {"name": _text(principal.display_name, 200), "email": _text(principal.email, 320)}
        previous = (self.repo.get_setting(key) or {}).get("value") or {}
        if previous.get("profile") == profile and (not principal.session_mark or principal.session_mark in previous.get("markers", [])):
            return
        # ponytail: one short installation lock; shard by actor if simultaneous sign-ins become a bottleneck.
        with locked_settings(self.repo, setting_key=LOCK) as bound:
            previous = (bound.get_setting(key) or {}).get("value") or {}
            markers = previous.get("markers", [])
            if principal.session_mark and principal.session_mark not in markers:
                bound.record_finding_event(self._event(scope, "AUTH_SESSION_OBSERVED", sign_in=True))
                markers = [*markers[-31:], principal.session_mark]
            if previous != {"markers": markers, "profile": profile}:
                bound.put_setting(key, {"markers": markers, "profile": profile}, SYSTEM)

    def finish(self, scope, status):
        kind = ("API_REQUEST_ACCEPTED" if status == 202 else "API_REQUEST_SUCCEEDED" if status < 400
                else "API_REQUEST_DENIED" if status in {401, 403} else "API_REQUEST_FAILED")
        self.repo.record_finding_event(self._event(scope, kind, status))


class ActivityMiddleware:
    """Record HTTP results without buffering bodies or changing the existing request size limit."""

    def __init__(self, app, audit):
        self.app, self.audit = app, audit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith("/api/"):
            await self.app(scope, receive, send)
            return
        recorded = False
        unavailable = False

        async def audited_send(message):
            nonlocal recorded, unavailable
            if message["type"] == "http.response.start":
                try:
                    await run_in_threadpool(self.audit.finish, scope, message["status"])
                    recorded = True
                except Exception as exc:  # noqa: BLE001 -- a successful response cannot hide a missing receipt
                    logger.error("activity audit unavailable: %s", type(exc).__name__)
                    unavailable = True
                    await JSONResponse({"detail": "AUDIT_RECORDING_UNAVAILABLE", "error": "AUDIT_RECORDING_UNAVAILABLE"},
                                       status_code=503)(scope, receive, send)
            if not unavailable:
                await send(message)

        try:
            await self.app(scope, receive, audited_send)
        except Exception:
            if not recorded and not unavailable:
                try:
                    await run_in_threadpool(self.audit.finish, scope, 500)
                except Exception as exc:  # noqa: BLE001 -- preserve the original failure, never log exception text
                    logger.error("activity audit unavailable: %s", type(exc).__name__)
            raise
