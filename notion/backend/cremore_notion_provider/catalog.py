"""notion metadata-only resource listing."""
from __future__ import annotations

from cremore.collectors.base import (
    CollectorError,
    RequestBudget,
    RequestBudgetExceeded,
    error_label,
)
from cremore.http_client import bounded_request
from cremore.scanning.catalog_projection import MAX_LISTED
from cremore.scanning.scope import resource
from cremore_notion_provider.collectors.requests import connection_limiter, paced

# Not the collector's 2026-03-11: from 2025-09-03 search lists data sources instead of
# databases and a database row's parent becomes its data source, so approved
# NOTION_DATA_SOURCE ids and every row's parent_id would change under existing scopes.
# https://developers.notion.com/docs/upgrade-guide-2025-09-03
_NOTION_VERSION = "2022-06-28"


def _notion_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Notion-Version": _NOTION_VERSION, "Content-Type": "application/json"}


def _notion_ok(resp):
    status = getattr(resp, "status_code", 200)
    if status != 200:
        return None, f"HTTP {status}"
    try:
        data = resp.json()
    except Exception as exc:  # noqa: BLE001 -- Provider failures retain incomplete visibility and safe labels, never confirmed absence.
        return None, error_label(exc)
    return (data if isinstance(data, dict) else None), "OK"


def _title(obj: dict) -> str:
    if obj.get("object") == "page":
        for prop in (obj.get("properties") or {}).values():
            if isinstance(prop, dict) and prop.get("type") == "title":
                return "".join(t.get("plain_text", "") for t in prop.get("title") or [])
        return ""
    return "".join(t.get("plain_text", "") for t in obj.get("title") or [])


def _notion_resource(kind, cid, obj: dict, now) -> dict | None:
    kind_of = obj.get("object")
    oid = obj.get("id")
    if not oid or kind_of not in ("page", "database", "data_source"):
        return None
    parent = obj.get("parent") or {}
    ptype = parent.get("type", "")
    parent_id = parent.get(ptype) if ptype in ("page_id", "database_id", "data_source_id") else None
    return resource(kind, cid, "NOTION_PAGE" if kind_of == "page" else "NOTION_DATA_SOURCE", oid, _title(obj) or oid,
                    obj.get("url") or f"https://www.notion.so/{oid.replace('-', '')}", "notion.so", now=now,
                    parent_id=parent_id, known_root_ids=[parent_id] if parent_id else [],
                    last_edited_at=obj.get("last_edited_time") or None, visibility="INTERNAL",
                    archived=obj.get("archived") if isinstance(obj.get("archived"), bool) else None)


def _notion(payload, kind, cid, client, now, budget: RequestBudget) -> tuple[list[dict], str]:
    base = str(payload.get("base_url") or "https://api.notion.com").rstrip("/")
    token = payload.get("token") or ""
    reference = payload.get("reference")
    limiter = connection_limiter(token, base)

    def fetch(method, path, **kwargs):
        def send():
            return bounded_request(client, method, base + path, headers=_notion_headers(token), **kwargs)

        try:
            return _notion_ok(paced(limiter, send, before_attempt=budget.consume))
        except RequestBudgetExceeded:
            raise
        except Exception as exc:  # noqa: BLE001 -- Provider failures retain incomplete visibility and safe labels, never confirmed absence.
            return None, error_label(exc)

    if reference:
        from cremore.scanning.scope import _notion_id

        raw = _notion_id(reference)
        page_id = f"{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:]}" if len(raw) == 32 else reference
        for path in (f"/v1/pages/{page_id}", f"/v1/databases/{page_id}"):
            data, label = fetch("GET", path)
            item = _notion_resource(kind, cid, data, now) if data else None
            if item:
                return [item], "PARTIAL"
            if label not in ("HTTP 403", "HTTP 404"):
                raise CollectorError("NOTION_REFERENCE_FAILED", label if data is None else "MALFORMED_RESPONSE")
        denied = resource(kind, cid, "NOTION_PAGE", page_id, page_id, f"https://www.notion.so/{raw}", "notion.so",
                          now=now, list_visibility="DENIED", reason_code="INSUFFICIENT_PERMISSION")
        return [denied], "PARTIAL"
    out, cursor, seen_cursors = [], None, set()
    while len(out) < MAX_LISTED:
        body: dict = {"page_size": 100}
        if payload.get("query"):
            body["query"] = str(payload["query"])[:256]
        if cursor:
            body["start_cursor"] = cursor
        data, label = fetch("POST", "/v1/search", json=body)
        if data is None:
            raise CollectorError("NOTION_SEARCH_FAILED", label)
        for obj in data.get("results", []):
            item = _notion_resource(kind, cid, obj, now)
            if item:
                out.append(item)
        if not data.get("has_more"):
            return out, "PARTIAL" if payload.get("query") else "COMPLETE"
        if not data.get("next_cursor"):
            return out, "PARTIAL"
        cursor = data["next_cursor"]
        if cursor in seen_cursors:
            return out, "PARTIAL"
        seen_cursors.add(cursor)
    return out[:MAX_LISTED], "PARTIAL"
