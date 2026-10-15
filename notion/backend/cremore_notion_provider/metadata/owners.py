"""Who owns a listed Notion personal access token (departed-owner check).

A PAT is its creator's: Notion names the creator with its user id and, when the
organization bot may read emails, the creator's email, which Notion verified at sign
in. An MCP client connection belongs to its user, named by id only, so it links only
through an administrator's confirmation.
"""

from __future__ import annotations

from cremore.coverage.facts import unpack_facts

# Every PAT of every workspace member is listed by the Enterprise Admin API.
LISTS_EVERY_USER_CREDENTIAL = True


def credential_owner(row):
    values = unpack_facts((row.get("summary") or {}).get("facts") or [])
    object_id = row.get("object_id", "")
    if object_id.startswith("pat:"):
        creator = values.get("creator") if isinstance(values.get("creator"), dict) else {}
        if not isinstance(creator.get("id"), str):
            return None
        email = creator.get("email")
        status = values.get("status")
        return {"account": creator["id"], "label": creator.get("name") or creator["id"],
                "keys": [("VERIFIED_EMAIL", email)] if isinstance(email, str) and email else [],
                "credential_type": "NOTION_PERSONAL_ACCESS_TOKEN", "name": values.get("name") or "",
                "state": {"active": "ACTIVE", "expired": "REVOKED_OR_EXPIRED",
                          "revoked": "REVOKED_OR_EXPIRED"}.get(status, "UNKNOWN"),
                "last_used_at": values.get("last_used_at"), "expires_at": values.get("expires_at")}
    if object_id.startswith("mcp:"):
        user = values.get("user") if isinstance(values.get("user"), dict) else {}
        if not isinstance(user.get("id"), str):
            return None
        client = values.get("client") if isinstance(values.get("client"), dict) else {}
        return {"account": user["id"], "label": user["id"], "keys": [],
                "credential_type": "NOTION_MCP_CONNECTION", "name": client.get("name") or "",
                "state": "UNKNOWN", "last_used_at": values.get("last_active_at"), "expires_at": None}
    return None
