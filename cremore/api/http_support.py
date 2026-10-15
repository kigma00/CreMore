"""Shared HTTP validation, timestamps and actor references. No route registration."""

from __future__ import annotations

import datetime as _dt
import logging
import re
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from cremore.api.auth import LOCAL_ACTOR
from cremore.domain import text as _plain_text
from cremore.domain.models import ScanBusy

logger = logging.getLogger("cremore.api.dashboard")


ACTOR_NAMESPACE = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")


def actor_uuid(actor: str) -> uuid.UUID:
    """A stable UUID reference for an actor id (the ledger only stores references)."""

    try:
        return uuid.UUID(str(actor))
    except (ValueError, AttributeError, TypeError):
        return uuid.uuid5(ACTOR_NAMESPACE, f"cremore:actor:{actor}")


WEB_ROLE = {"viewer": "Viewer", "analyst": "Analyst", "remediator": "Remediator", "admin": "Admin"}


def log_safe(value: object) -> str:
    """A log-safe rendering of untrusted text: line breaks and other control
    characters are escaped so one value can never read as several records."""

    text = str(value).replace("\r", "\\r").replace("\n", "\\n")
    return "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in text)


def http_error(status: int, detail: str) -> HTTPException:
    return HTTPException(status_code=status, detail=detail)


def page_rows(rows, response, limit):
    """A bounded repository page with an extra row to prove continuation."""
    response.headers["X-Page-Limit"] = str(limit)
    if len(rows) > limit:
        response.headers["X-Next-Cursor"] = str(rows[limit - 1].id)
    return rows[:limit]


# The routes' text rule; it lives with the domain so services without FastAPI (tickets) apply the same one.
unsafe_text = _plain_text.unsafe_text


def parse_uuid(value, what: str) -> uuid.UUID:
    """Parse a client-supplied id; a malformed one is a 422, never a 500."""

    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        raise http_error(422, f"{what} must be a UUID")


def utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


def isoformat(value) -> str | None:
    return value.isoformat() if value is not None and hasattr(value, "isoformat") else None


def actor_label(actor: str | None) -> str | None:
    return "local operator" if actor == LOCAL_ACTOR else actor


def validation_details(request, exc: RequestValidationError) -> list[dict]:
    """Only declared field names and validation codes may leave a failed request.

    Pydantic inputs, contexts and messages can contain submitted credentials.
    Dictionary keys in an error location are also input, not schema field names.
    """
    declared = {"body", "path", "query", "header", "cookie"}
    dependant = getattr(request.scope.get("route"), "dependant", None)
    for group in ("body_params", "path_params", "query_params", "header_params", "cookie_params"):
        for field in getattr(dependant, group, ()):
            declared.update((field.name, field.alias))
            annotation = field.field_info.annotation
            for name, model_field in getattr(annotation, "model_fields", {}).items():
                declared.update((name, model_field.alias or name))
    details = []
    for error in exc.errors():
        location = [part if type(part) is int or part in declared else "<field>"
                    for part in error.get("loc", ())]
        code = error.get("type", "invalid_value")
        if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", code):
            code = "invalid_value"
        details.append({"loc": location, "type": code, "msg": "Invalid value"})
    return details


class BoundedRequestBody:
    """Bound mutating request bodies before FastAPI allocates/parses them."""

    _JSON_OVERHEAD = 64 << 10

    def __init__(self, app, max_input_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_input_bytes + self._JSON_OVERHEAD

    async def __call__(self, scope, receive, send):
        if (
            scope.get("type") != "http"
            or scope.get("method") not in {"POST", "PUT", "PATCH", "DELETE"}
        ):
            await self.app(scope, receive, send)
            return

        async def reject() -> None:
            response = JSONResponse(
                {
                    "detail": "request body is too large",
                    "error": "request body is too large",
                },
                status_code=413,
            )
            await response(scope, receive, send)

        for name, value in scope.get("headers", ()):
            if name.lower() != b"content-length":
                continue
            try:
                too_large = int(value) > self.max_body_bytes
            except (TypeError, ValueError):
                too_large = False
            if too_large:
                await reject()
                return

        body = bytearray()
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(chunk) > self.max_body_bytes - len(body):
                await reject()
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay, send)


def register_http_handlers(app: FastAPI) -> None:
    # Every error carries both `detail` (FastAPI convention) and `error` (what
    # the dashboard shows), so a 4xx/5xx reads as its reason, never "Request failed".
    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_request, exc: StarletteHTTPException):
        detail = exc.detail if isinstance(exc.detail, str) else "request failed"
        return JSONResponse(
            {"detail": exc.detail, "error": detail},
            status_code=exc.status_code,
            headers=getattr(exc, "headers", None),
        )

    # Every scan start path (manual, rescan, plan run) reports a taken slot the
    # same way, naming the scan that holds it so the dashboard can show it.
    @app.exception_handler(ScanBusy)
    async def _scan_busy(_request, exc: ScanBusy):
        from cremore.scanning.scope import active_scan_public

        return JSONResponse(
            # `error` is the code the dashboard localizes; the scan that holds the slot is named.
            {"detail": "ALREADY_SCANNING", "error": "ALREADY_SCANNING",
             "active_scan": active_scan_public(exc.active)},
            status_code=409,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request, exc: RequestValidationError):
        if _request.url.path.startswith(("/api/v1/coverage", "/api/v2/coverage")):
            return JSONResponse({"detail": "INVALID_COVERAGE_REQUEST", "error": "INVALID_COVERAGE_REQUEST"}, status_code=422)
        return JSONResponse(
            {
                "detail": validation_details(_request, exc),
                "error": "request body or parameters are invalid",
            },
            status_code=422,
        )
