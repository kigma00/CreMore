"""Who owns a listed GitLab token (departed-owner check).

A personal access token is its user's (``user_id``). An administrator's read of that
user names the external sign-in identities GitLab linked (``identities[].extern_uid``:
SAML and group SAML -- SCIM-provisioned users' too --, LDAP, OpenID Connect and the
like) and the primary email, which GitLab confirms; the username is only a candidate. A login at another service
(GitHub, Bitbucket and the other providers in _ACCOUNT_ELSEWHERE) names an account
there, not a person of the company's IdP, and is no key. Tokens of a bot or service
account user belong to no person.
"""

from __future__ import annotations

from datetime import UTC, datetime

from cremore.coverage.facts import unpack_facts

LISTS_EVERY_USER_CREDENTIAL = False
_PERSONAL = {"personal_access_token"}
# GitLab OmniAuth providers whose uid is an account at another SaaS or social network (docs.gitlab.com/integration/
# omniauth, with the ones GitLab has since removed -- dingtalk, facebook, twitter, ultraauth -- whose identities an
# upgraded instance still keeps). SAML and OpenID Connect providers may carry any name an administrator gives them,
# so the company's sign-ins are everything else. A Google account id is unique to that account (a Workspace user's
# is the Workspace user id), so google_oauth2 stays.
_ACCOUNT_ELSEWHERE = frozenset({"alicloud", "atlassian_oauth2", "bitbucket", "dingtalk", "facebook", "github", "gitlab",
                                "salesforce", "twitter", "ultraauth"})


def _expires_at(value):
    """GitLab date-only access tokens expire at midnight UTC on that date."""
    if isinstance(value, str) and len(value) == 10:
        try:
            return datetime.fromisoformat(value).replace(tzinfo=UTC).isoformat()
        except ValueError:
            return None
    return value


def credential_owner(row):
    values = unpack_facts((row.get("summary") or {}).get("facts") or [])
    identity = values.get("identity") if isinstance(values.get("identity"), dict) else {}
    family = values.get("family") or next(iter(values.get("credential_types") or []), None)
    # A service account's PAT shares the namespace but belongs to no person.
    if identity.get("namespace") not in _PERSONAL or "service_account" in str(family):
        return None
    summary = values.get("summary") if isinstance(values.get("summary"), dict) else {}
    owner = summary.get("owner") if isinstance(summary.get("owner"), dict) else {}
    metadata = values.get("metadata") if isinstance(values.get("metadata"), dict) else {}
    if not metadata and isinstance(values.get("observation"), dict):
        metadata = values["observation"].get("metadata") or {}
    user_id = owner.get("id") if owner.get("id") is not None else metadata.get("user_id")
    if not isinstance(user_id, int) or isinstance(user_id, bool):
        return None
    profile = owner.get("profile") if isinstance(owner.get("profile"), dict) else {}
    if profile.get("bot") is True:
        return None
    keys = []
    if isinstance(profile.get("email"), str) and profile["email"]:
        keys.append(("VERIFIED_EMAIL", profile["email"]))
    for entry in profile.get("identities") or []:
        if (isinstance(entry, dict) and isinstance(entry.get("extern_uid"), str) and entry["extern_uid"]
                and str(entry.get("provider") or "").casefold() not in _ACCOUNT_ELSEWHERE):
            keys.append(("EXTERNAL_UID", entry["extern_uid"]))
    if isinstance(profile.get("username"), str) and profile["username"]:
        keys.append(("PROVIDER_LOGIN", profile["username"]))
    revoked, active = metadata.get("revoked"), metadata.get("active")
    state = "REVOKED_OR_EXPIRED" if revoked is True or active is False else "ACTIVE" if active is True else "UNKNOWN"
    return {"account": "user:" + str(user_id), "label": profile.get("username") or "user " + str(user_id),
            "keys": keys, "credential_type": "GITLAB_PERSONAL_ACCESS_TOKEN", "name": metadata.get("name") or "",
            "state": state, "last_used_at": metadata.get("last_used_at"),
            "expires_at": _expires_at(metadata.get("expires_at"))}
