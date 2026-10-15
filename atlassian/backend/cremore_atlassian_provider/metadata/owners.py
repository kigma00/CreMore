"""Who owns a listed Atlassian credential (departed-owner check).

Organization API tokens are a managed account's own tokens: the account id and its
email, which belongs to a domain the organization verified. An admin API key is the
organization's, but the administrator who created it is named, so a key left by a
departed administrator is found too. Service account tokens belong to no person.
"""

from __future__ import annotations

from cremore.coverage.facts import unpack_facts

# The organization's managed accounts are listed with all their API tokens.
LISTS_EVERY_USER_CREDENTIAL = True
_ACTIVE = {"ALLOWED", "ACTIVE", "ENABLED"}
# BLOCKED is an organization policy an admin can lift again: the token is neither revoked nor expired.
_ENDED = {"REVOKED", "EXPIRED", "DISABLED", "DELETED"}


def _fields(metadata):
    """Both stored shapes: a normalized field list, or a provider row kept as-is."""
    if isinstance(metadata.get("fields"), list):
        values = {}
        for field in metadata["fields"]:
            if isinstance(field, dict) and (field.get("metadata") or {}).get("state") == "present":
                values[field.get("name")] = field["metadata"].get("value")
        return values
    flat = {}
    for key, value in metadata.items():
        if isinstance(value, dict):
            flat.update({key + "." + child: item for child, item in value.items()})
        else:
            flat[key] = value
    return flat


def credential_owner(row):
    values = unpack_facts((row.get("summary") or {}).get("facts") or [])
    metadata = values.get("metadata") if isinstance(values.get("metadata"), dict) else {}
    source = metadata.get("source") or (values.get("context") or {}).get("operation")
    fields = _fields(metadata)
    if source in ("org-api-tokens", "user-api-tokens"):
        prefix, kind = "user", "ATLASSIAN_API_TOKEN"
    elif source == "admin-api-keys":
        prefix, kind = "createdBy", "ATLASSIAN_ADMIN_API_KEY"
    else:
        return None
    account = fields.get(prefix + ".id")
    if not isinstance(account, str) or not account:
        return None
    email = fields.get(prefix + ".email")
    status = str(fields.get("status") or "").upper()
    return {"account": account, "label": fields.get(prefix + ".name") or account,
            "keys": [("VERIFIED_EMAIL", email)] if isinstance(email, str) and email else [],
            "credential_type": kind, "name": fields.get("label") or "",
            "relation": "owns" if prefix == "user" else "created_by",
            "state": "ACTIVE" if status in _ACTIVE else "REVOKED_OR_EXPIRED" if status in _ENDED else "UNKNOWN",
            "last_used_at": fields.get("lastActiveAt"), "expires_at": fields.get("expiresAt")}
