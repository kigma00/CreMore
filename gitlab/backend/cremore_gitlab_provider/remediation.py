"""Revoking a GitLab token by the ID GitLab's own list gives (cremore.remediation.provider_actions).

GitLab has no disable: a token is revoked, which cannot be undone. The token is read back where GitLab lists it
(``revoked``/``active``; a revoked group or project token is kept 30 days, a deploy token is deleted), so the
remediation connection acts only through documented endpoints:

* group and project access tokens: ``DELETE /{groups|projects}/:id/access_tokens/:token_id`` (the group's Owner,
  the project's Maintainer or an administrator);
* deploy tokens: ``DELETE /{groups|projects}/:id/deploy_tokens/:token_id`` (the same roles);
* personal access tokens, service accounts' included: ``DELETE /personal_access_tokens/:id``, an administrator of a
  Self-Managed or Dedicated instance only (another user's token).

The acting token is the remediation connection's own (scope ``api``); nothing here keeps or reports a token or a
response body. GitLab also answers 404 for a group or project the token cannot see, so a group or project token's
404 means "gone" only while its group or project is visible.
"""

from __future__ import annotations

from urllib.parse import quote

import httpx

from cremore.coverage.facts import unpack_facts
from cremore.http_client import bounded_request


class ProviderActionError(ValueError):
    """A fixed code (``refused``: GitLab answered without revoking anything), as the platform reads it."""

    def __init__(self, code: str, *, refused: bool = False):
        super().__init__(code)
        self.code, self.refused = code, refused


ADAPTER_VERSION = "GITLAB_TOKEN_REVOKE_V1"
# A token always belongs to a user: a plan binds it, so the check must have named it (cremore.remediation).
SUBJECT_METHODS = ("token",)
CLOUD = "https://gitlab.com"
PERSONAL = ("personal_access_token", "group_service_account_pat", "project_service_account_pat")
RESOURCE = ("group_access_token", "project_access_token")
DEPLOY = ("group_deploy_token", "project_deploy_token")
_REFUSED = (400, 401, 403, 404)


def _positive(value) -> bool:
    return type(value) is int and value > 0


def reference(entity, record):
    """{family, token_id, instance, scope?, listed_in, key, hint} of a token GitLab can revoke through a documented
    endpoint; None for any other. ``key`` is GitLab's own identity of the token (metadata.model.identity): the
    personal token ID space is one, whatever user or service account it belongs to."""
    body = (record or {}).get("body") or {}
    values = unpack_facts(body.get("facts") or [])
    identity = values.get("identity") if isinstance(values.get("identity"), dict) else {}
    types = {kind for kind in values.get("credential_types") or [] if isinstance(kind, str)}
    family = values.get("family") if isinstance(values.get("family"), str) else None
    families = {family} if family else types
    if len(families) != 1:
        return None
    family = next(iter(families))
    token_id, instance = identity.get("native_id"), identity.get("instance")
    listed = body.get("scope") if isinstance(body.get("scope"), dict) else {}
    if (family not in PERSONAL + RESOURCE + DEPLOY or not _positive(token_id) or not isinstance(instance, str)
            or instance.rstrip("/") != str(entity.get("origin") or "").rstrip("/")
            or not instance.startswith("https://")):
        return None
    out = {"family": family, "token_id": token_id, "instance": instance.rstrip("/"),
           "listed_in": {"kind": str(listed.get("kind") or ""), "id": str(listed.get("id") or "")}}
    if family in PERSONAL:
        metadata = values.get("metadata") if isinstance(values.get("metadata"), dict) else {}
        out["key"] = {"namespace": "personal_access_token", "token_id": token_id}
        if _positive(metadata.get("user_id")):
            out["user_id"] = metadata["user_id"]  # whose token it is, shown to whoever approves; not its identity
        out["hint"] = f"{family} #{token_id}" + (f" (user {out['user_id']})" if "user_id" in out else "")
        return out
    scope = identity.get("scope") if isinstance(identity.get("scope"), dict) else {}
    kind = "group" if family.startswith("group_") else "project"
    if scope.get("kind") != kind or not _positive(scope.get("id")):
        return None
    out["scope"] = {"kind": kind, "id": scope["id"]}
    out["key"] = {"namespace": "resource_access_token" if family in RESOURCE else "deploy_token",
                  "token_id": token_id, "scope": out["scope"]}
    out["hint"] = f"{family} #{token_id} ({kind} {scope['id']})"
    return out


def actions(reference):
    return ("REVOKE_PROVIDER_CREDENTIAL",)


def _origin(connection) -> str:
    return ((connection.get("target") or {}).get("host") or CLOUD).rstrip("/")


def covers(connection, reference) -> bool:
    """An administrator's instance connection reaches every token of its instance; a group's or project's reaches
    the group or project tokens its own scope names, or a collection of that scope listed."""
    target = connection.get("target") or {}
    if reference.get("instance") != _origin(connection):
        return False
    if target.get("scope") == "instance":
        return True
    if reference.get("family") in PERSONAL:
        return False  # another user's token: an administrator's
    mine = {"kind": target.get("scope"), "id": str(target.get("id") or "")}
    own = {"kind": reference["scope"]["kind"], "id": str(reference["scope"]["id"])}
    return own == mine or (target.get("scope") == "group" and reference.get("listed_in") == mine)


def _path(reference) -> str:
    token = quote(str(reference["token_id"]), safe="")
    if reference["family"] in PERSONAL:
        return f"/personal_access_tokens/{token}"
    scope = reference["scope"]
    kind = "access_tokens" if reference["family"] in RESOURCE else "deploy_tokens"
    return f"/{scope['kind']}s/{quote(str(scope['id']), safe='')}/{kind}/{token}"


def _call(connection, secrets, client, method, path):
    token = (secrets.get("credential") or {}).get("token", "")
    try:
        return bounded_request(client, method, _origin(connection) + "/api/v4" + path,
                               headers={"PRIVATE-TOKEN": token, "Accept": "application/json"},
                               max_response_bytes=64 << 10, follow_redirects=False, timeout=30)
    except (httpx.ConnectError, httpx.ConnectTimeout):
        raise ProviderActionError("GITLAB_UNAVAILABLE", refused=True) from None  # never reached GitLab
    except Exception:  # noqa: BLE001 -- transport errors can carry the token header; only a code leaves
        raise ProviderActionError("GITLAB_UNAVAILABLE") from None


def _parent_visible(connection, secrets, client, reference) -> bool:
    """Whether the token's group or project is visible to the acting token, so that a 404 for the token is its own.
    GitLab not answering is neither."""
    scope = reference["scope"]
    response = _call(connection, secrets, client, "GET", f"/{scope['kind']}s/{quote(str(scope['id']), safe='')}")
    if response.status_code >= 500 or response.status_code == 429:
        raise ProviderActionError("GITLAB_UNAVAILABLE")
    return response.status_code == 200


def whoami(connection, secrets, client) -> str:
    """The user the acting token belongs to, as the remediation check reports it (``user:<id>``)."""
    response = _call(connection, secrets, client, "GET", "/personal_access_tokens/self")
    if response.status_code != 200:
        raise ProviderActionError("GITLAB_UNAVAILABLE" if response.status_code >= 500 or response.status_code == 429
                                  else "GITLAB_TOKEN_UNREADABLE")
    try:
        user = response.json().get("user_id")
    except (ValueError, AttributeError):
        raise ProviderActionError("GITLAB_TOKEN_UNREADABLE") from None
    return f"user:{user}" if type(user) is int else ""


def state(connection, secrets, reference, client) -> str:
    response = _call(connection, secrets, client, "GET", _path(reference))
    if response.status_code == 404:
        # An administrator sees every personal token; a group's or project's 404 counts only while it is visible.
        if reference["family"] not in PERSONAL and not _parent_visible(connection, secrets, client, reference):
            raise ProviderActionError("GITLAB_TARGET_NOT_VISIBLE")
        return "ABSENT"
    if response.status_code in (401, 403):
        raise ProviderActionError("GITLAB_PERMISSION_DENIED")
    if response.status_code != 200:
        raise ProviderActionError("GITLAB_UNAVAILABLE" if response.status_code >= 500 or response.status_code == 429
                                  else "GITLAB_TOKEN_UNREADABLE")
    try:
        body = response.json()
    except ValueError:
        raise ProviderActionError("GITLAB_TOKEN_UNREADABLE") from None
    if not isinstance(body, dict) or body.get("id") != reference["token_id"]:
        raise ProviderActionError("GITLAB_TOKEN_UNREADABLE")
    if body.get("revoked") is True:
        return "REVOKED"
    if body.get("expired") is True or body.get("active") is False:
        return "EXPIRED"  # unusable already; nothing to revoke
    if body.get("revoked") is False and (body.get("active") is True or reference["family"] in DEPLOY):
        return "ACTIVE"
    raise ProviderActionError("GITLAB_TOKEN_UNREADABLE")


def apply(connection, secrets, reference, action, client) -> None:
    if action != "REVOKE_PROVIDER_CREDENTIAL":
        raise ProviderActionError("ACTION_NOT_SUPPORTED_FOR_CREDENTIAL", refused=True)
    response = _call(connection, secrets, client, "DELETE", _path(reference))
    if response.status_code in (200, 204):
        return
    if response.status_code in _REFUSED:
        # GitLab answered the request without revoking (bad request, no permission, no such token).
        raise ProviderActionError("GITLAB_PERMISSION_DENIED" if response.status_code in (401, 403)
                                  else f"GITLAB_HTTP_{response.status_code}", refused=True)
    raise ProviderActionError(f"GITLAB_HTTP_{response.status_code}" if 100 <= response.status_code < 600
                              else "GITLAB_UNAVAILABLE")
