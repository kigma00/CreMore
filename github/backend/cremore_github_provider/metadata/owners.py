"""Who owns a listed GitHub credential (departed-owner check).

GitHub names a token's owner by login: a fine-grained PAT's grant, an SSO credential
authorization and an Enterprise credential inventory row all do. Which person a login
is comes from the organization's SAML/SCIM identities or a managed-user enterprise's
(github_identity), keyed by the same account reference; the login alone is only a
candidate. GitHub lists only the tokens an organization authorized or granted, never
every token a member holds.
"""

from __future__ import annotations

from cremore.coverage.facts import unpack_facts

LISTS_EVERY_USER_CREDENTIAL = False
_ENDED_STATES = {"REVOKED", "EXPIRED", "DELETED", "DISABLED", "INACTIVE"}
# Inventory credential_type -> the code the provider catalog declares (onboarding.py); others are GITHUB_<TYPE>.
_INVENTORY_TYPES = {"oauth_app_user_token": "GITHUB_OAUTH_TOKEN", "github_app_user_token": "GITHUB_APP_USER_TOKEN",
                    "ssh_key": "GITHUB_SSH_KEY", "SSH key": "GITHUB_SSH_KEY"}


def _state(row, expired=None):
    normalized = (row.get("summary") or {}).get("normalized_state", "UNKNOWN")
    if expired is True or normalized in _ENDED_STATES:
        return "REVOKED_OR_EXPIRED"
    return "ACTIVE" if normalized == "ACTIVE" else "UNKNOWN"


def credential_owner(row):
    values = unpack_facts((row.get("summary") or {}).get("facts") or [])
    object_id = row.get("object_id", "")
    if object_id.startswith("fgpat:"):
        owner = values.get("owner") if isinstance(values.get("owner"), dict) else {}
        login = owner.get("login")
        if owner.get("type") not in (None, "User"):
            return None
        found = {"credential_type": "GITHUB_FINE_GRAINED_PAT", "name": values.get("token_name") or "",
                 "state": _state(row, values.get("token_expired")),
                 "last_used_at": values.get("token_last_used_at"), "expires_at": values.get("token_expires_at")}
    elif object_id.startswith("sso:"):
        login = values.get("login")
        found = {"credential_type": "GITHUB_SSO_AUTHORIZED_CREDENTIAL",
                 "name": values.get("authorized_credential_title") or values.get("credential_type") or "",
                 "state": _state(row), "last_used_at": values.get("credential_accessed_at"),
                 "expires_at": values.get("authorized_credential_expires_at")}
    elif object_id.startswith("inventory:") and (
            row.get("object_kind") == "credential"
            or row.get("object_kind") == "public_key" and values.get("credential_type") in ("ssh_key", "SSH key")):
        login = values.get("owner")
        if values.get("owner_type") is not None and str(values["owner_type"]).casefold() != "user":
            return None
        kind = str(values.get("credential_type") or "CREDENTIAL")
        found = {"credential_type": _INVENTORY_TYPES.get(kind, "GITHUB_" + kind.upper()),
                 "name": values.get("display_name") or "", "state": _state(row),
                 "last_used_at": values.get("last_used_at"), "expires_at": values.get("expires_at")}
    else:
        return None
    if not isinstance(login, str) or not login:
        return None
    return {"account": login.lower(), "label": login, "keys": [("PROVIDER_LOGIN", login)], **found}
