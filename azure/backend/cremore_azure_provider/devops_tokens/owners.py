"""Who owns a listed Azure DevOps PAT (departed-owner check).

The PAT Lifecycle admin API lists every user's tokens. A Microsoft Entra user's
originId is its Entra object id, the same id an Entra ID collection keeps for that
person; the mail address the organization graph reports is the directory's.
"""

from __future__ import annotations

from cremore.coverage.facts import unpack_facts

LISTS_EVERY_USER_CREDENTIAL = True


def credential_owner(row):
    values = unpack_facts((row.get("summary") or {}).get("facts") or [])
    owner = values.get("owner") if isinstance(values.get("owner"), dict) else {}
    account = values.get("user_id") or owner.get("origin_id")
    if not isinstance(account, str) or not account:
        return None
    keys = []
    if owner.get("origin") == "aad" and isinstance(owner.get("origin_id"), str):
        keys.append(("IDP_OBJECT_ID", owner["origin_id"]))
    if isinstance(owner.get("email"), str) and owner["email"]:
        keys.append(("VERIFIED_EMAIL" if owner.get("origin") in ("aad", "msa") else "UNVERIFIED_EMAIL", owner["email"]))
    normalized = (row.get("summary") or {}).get("normalized_state", "UNKNOWN")
    return {"account": account, "label": owner.get("name") or owner.get("email") or account, "keys": keys,
            "credential_type": "AZURE_DEVOPS_PAT", "name": values.get("display_name") or "",
            "state": "ACTIVE" if normalized == "ACTIVE" else "REVOKED_OR_EXPIRED"
            if normalized in ("EXPIRED", "INACTIVE", "REVOKED") else "UNKNOWN",
            "last_used_at": None, "expires_at": values.get("expires_at")}
