"""Revoking a Notion Enterprise personal access token by the ID the Admin API lists (cremore.remediation.provider_actions).

Notion has no disable: ``DELETE /admin/v1/spaces/{space}/personal_access_tokens/{id}`` revokes the token for good
(a repeat leaves it revoked). The token is read back where Notion lists it, ``status`` active, expired or revoked,
among its creator's tokens (``creator_ids``); a token missing from that whole list is ABSENT.

The acting token is the remediation connection's organization bot token, with the scopes
``personal-access-token:read`` and ``personal-access-token:write-high-impact`` (Notion does not let one imply the
other); nothing here keeps or reports a token, a token name or a response body.
"""

from __future__ import annotations

import uuid
from urllib.parse import quote

import httpx

from cremore.coverage.facts import unpack_facts
from cremore.http_client import bounded_request
from cremore_notion_provider.metadata import API_VERSION, ORIGIN
from cremore_notion_provider.metadata.normalization import uuid_text
from cremore_notion_provider.metadata.transport import cursor_text


class ProviderActionError(ValueError):
    """A fixed code (``refused``: Notion answered without revoking anything), as the platform reads it."""

    def __init__(self, code: str, *, refused: bool = False):
        super().__init__(code)
        self.code, self.refused = code, refused


ADAPTER_VERSION = "NOTION_PAT_REVOKE_V1"
_STATES = {"active": "ACTIVE", "expired": "EXPIRED", "revoked": "REVOKED"}
_REFUSED = (400, 401, 403, 404)
PAGE_SIZE = 100
# ponytail: one creator's tokens, read whole; a member with more than this is refused rather than paged forever.
MAX_PAGES = 50


def _uuid(value):
    try:
        return uuid_text(value)
    except ValueError:
        return None


def _same(value, wanted) -> bool:
    """Whether Notion's ID names ``wanted`` (a canonical UUID), however Notion spells it."""
    try:
        return str(uuid.UUID(str(value))) == wanted
    except ValueError:
        return False


def reference(entity, record):
    """{workspace, pat_id, creator_id, key, hint} of a personal access token a workspace's inventory lists."""
    parts = str(entity.get("object_id") or "").split(":")
    body = (record or {}).get("body") or {}
    values = unpack_facts(body.get("facts") or [])
    creator = values.get("creator") if isinstance(values.get("creator"), dict) else {}
    scope = body.get("scope") if isinstance(body.get("scope"), dict) else {}
    if len(parts) != 3 or parts[0] != "pat" or str(entity.get("origin") or "") != ORIGIN:
        return None
    workspace, pat_id, creator_id = _uuid(parts[1]), _uuid(parts[2]), _uuid(creator.get("id"))
    if (not workspace or not pat_id or not creator_id or values.get("id") != pat_id
            or scope.get("kind") != "workspace" or scope.get("id") != workspace):
        return None
    return {"workspace": workspace, "pat_id": pat_id, "creator_id": creator_id,
            "key": {"workspace": workspace, "pat_id": pat_id},
            "hint": f"personal_access_token {pat_id} (creator {creator_id})"}


def actions(reference):
    return ("REVOKE_PROVIDER_CREDENTIAL",)


def covers(connection, reference) -> bool:
    """A remediation connection acts in the one workspace it names."""
    return (connection.get("target") or {}).get("workspace") == reference.get("workspace")


def _path(reference) -> str:
    return f"/admin/v1/spaces/{quote(reference['workspace'], safe='')}/personal_access_tokens"


def _call(secrets, client, method, path, params=None):
    token = (secrets.get("credential") or {}).get("token", "")
    try:
        return bounded_request(client, method, ORIGIN + path, params=params,
                               headers={"Authorization": "Bearer " + token, "Notion-Version": API_VERSION,
                                        "Accept": "application/json"},
                               max_response_bytes=1 << 20, follow_redirects=False, timeout=30)
    except (httpx.ConnectError, httpx.ConnectTimeout):
        raise ProviderActionError("NOTION_UNAVAILABLE", refused=True) from None  # never reached Notion
    except Exception:  # noqa: BLE001 -- transport errors can carry the token header; only a code leaves
        raise ProviderActionError("NOTION_UNAVAILABLE") from None


def state(connection, secrets, reference, client) -> str:
    cursor, seen = None, set()
    for _page in range(MAX_PAGES):
        params = {"creator_ids": reference["creator_id"], "page_size": str(PAGE_SIZE)}
        if cursor:
            params["cursor"] = cursor
        response = _call(secrets, client, "GET", _path(reference), params)
        if response.status_code in (401, 403):
            raise ProviderActionError("NOTION_PERMISSION_DENIED")
        if response.status_code == 404:
            raise ProviderActionError("NOTION_WORKSPACE_NOT_VISIBLE")  # the workspace, never the token
        if response.status_code != 200:
            raise ProviderActionError("NOTION_UNAVAILABLE" if response.status_code >= 500 or response.status_code == 429
                                      else "NOTION_TOKEN_UNREADABLE")
        try:
            body = response.json()
        except ValueError:
            raise ProviderActionError("NOTION_TOKEN_UNREADABLE") from None
        rows = body.get("results") if isinstance(body, dict) else None
        if not isinstance(rows, list) or not isinstance(body.get("has_more"), bool):
            raise ProviderActionError("NOTION_TOKEN_UNREADABLE")
        for row in rows:
            if isinstance(row, dict) and _same(row.get("id"), reference["pat_id"]):
                creator = row.get("creator") if isinstance(row.get("creator"), dict) else {}
                if not _same(creator.get("id"), reference["creator_id"]) or row.get("status") not in _STATES:
                    raise ProviderActionError("NOTION_TOKEN_UNREADABLE")
                return _STATES[row["status"]]
        if not body["has_more"]:
            if body.get("next_cursor") is not None:
                raise ProviderActionError("NOTION_TOKEN_UNREADABLE")  # a cursor after the last page: not whole
            return "ABSENT"  # the creator's whole list, without it
        try:
            cursor = cursor_text(body.get("next_cursor"), (secrets.get("credential") or {}).get("token", ""))
        except ValueError:
            raise ProviderActionError("NOTION_TOKEN_UNREADABLE") from None
        if cursor in seen:
            raise ProviderActionError("NOTION_TOKEN_UNREADABLE")
        seen.add(cursor)
    raise ProviderActionError("NOTION_LIST_TOO_LONG")


def apply(connection, secrets, reference, action, client) -> None:
    if action != "REVOKE_PROVIDER_CREDENTIAL":
        raise ProviderActionError("ACTION_NOT_SUPPORTED_FOR_CREDENTIAL", refused=True)
    response = _call(secrets, client, "DELETE", f"{_path(reference)}/{quote(reference['pat_id'], safe='')}")
    if response.status_code == 200:
        return
    if response.status_code in _REFUSED:
        # Notion answered without revoking (bad request, no permission or scope, no such token in the workspace).
        raise ProviderActionError("NOTION_PERMISSION_DENIED" if response.status_code in (401, 403)
                                  else f"NOTION_HTTP_{response.status_code}", refused=True)
    raise ProviderActionError(f"NOTION_HTTP_{response.status_code}" if 100 <= response.status_code < 600
                              else "NOTION_UNAVAILABLE")
