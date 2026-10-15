"""What Notion says about an exposed page (cremore.governance.ownership): who last edited it.

Reads, with the content connection's own integration token, the page (GET /v1/pages/{id}) for
``last_edited_by`` and ``last_edited_time``, then that user (GET /v1/users/{id}) for a name and, for a
person, an email. The user read needs the integration's user information capability; without it the
author is FORBIDDEN, never a bare id. Notion has no CODEOWNERS and its API does not say who can open a
page, so neither is read. Nothing is written.

Docs: https://developers.notion.com/reference/page, https://developers.notion.com/reference/get-user
"""

from __future__ import annotations

import re

from cremore.collectors.base import RequestBudget
from cremore_notion_provider.collectors.notion import NotionCollector

_PAGE = re.compile(r"[0-9a-f]{32}")
_USER = re.compile(r"[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}")


def _status(label):
    return ("NOT_FOUND_OR_NOT_VISIBLE" if label == "HTTP 404" else "FORBIDDEN" if label in ("HTTP 401", "HTTP 403")
            else "UNAVAILABLE")


def _author(notion, page):
    body, label = notion._get(f"/v1/pages/{page}")
    if body is None or body.get("object") != "page" or str(body.get("id", "")).replace("-", "").lower() != page:
        return {"status": _status(label) if body is None else "UNAVAILABLE"}
    editor = (body.get("last_edited_by") or {}).get("id") if isinstance(body.get("last_edited_by"), dict) else None
    if not isinstance(editor, str) or not _USER.fullmatch(editor):
        return {"status": "UNAVAILABLE"}
    user, label = notion._get(f"/v1/users/{editor}")
    if user is None or user.get("object") != "user":
        return {"status": _status(label) if user is None else "UNAVAILABLE"}
    person = user.get("person") if user.get("type") == "person" and isinstance(user.get("person"), dict) else {}
    return {"status": "OBSERVED", "name": user.get("name"), "login": None, "email": person.get("email"),
            "at": body.get("last_edited_time"), "commit": None}


def read(payload, location, *, http_client, members=True) -> dict:
    """``{codeowners, author}`` for one exposed page ({page_id, ...}); ``members`` is not read here."""
    page = str(location.get("page_id") or "")
    out = {"codeowners": {"status": "UNSUPPORTED"}}
    if not _PAGE.fullmatch(page) or not payload.get("token"):
        return {**out, "author": {"status": "UNSUPPORTED"}}
    notion = NotionCollector(http_client, token=payload["token"], request_budget=RequestBudget(4))
    return {**out, "author": _author(notion, page)}
