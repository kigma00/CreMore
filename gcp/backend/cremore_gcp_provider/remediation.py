"""Disabling and deleting a Google Cloud service-account key by its key ID (cremore.remediation.provider_actions).

Google recommends disabling a key first (``keys:disable``, reversible) and deleting it later (``keys.delete``,
irreversible); only a user-managed key can be either. Neither revokes short-lived tokens already minted with the key.
The key's state is read back with ``keys.get`` (``disabled``); a key Google no longer has is ABSENT.

The identity that acts is the remediation connection's: the worker's Application Default Credentials or an
administrator's Google sign-in (cremore_gcp_provider.onboarding), holding ``iam.serviceAccounts.get``,
``iam.serviceAccountKeys.get``, ``.disable`` and ``.delete`` on the connection's project in a custom role
(roles/iam.serviceAccountKeyAdmin would also let it create keys, so act as any service account). Its access token is
asked for once per run and kept only in that run's secrets, dropped with them.
"""

from __future__ import annotations

import re
from urllib.parse import quote

import httpx

from cremore.coverage.facts import unpack_facts
from cremore.http_client import bounded_request


class ProviderActionError(ValueError):
    """A fixed code (``refused``: Google answered without changing anything), as the platform reads it."""

    def __init__(self, code: str, *, refused: bool = False):
        super().__init__(code)
        self.code, self.refused = code, refused


ADAPTER_VERSION = "GCP_SERVICE_ACCOUNT_KEY_V1"
DISABLE_BEFORE_REVOKE = True
# An administrator's Google sign-in names its account (the email scope): a plan binds it (cremore.remediation).
SUBJECT_METHODS = ("google_oauth",)
_API = "https://iam.googleapis.com/v1"
_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
# A service account's email; the key ID as the inventory accepts it (cremore_gcp_provider.metadata.adapter).
_EMAIL = re.compile(r"[a-z0-9][a-z0-9._-]{0,99}@[a-z0-9][a-z0-9.-]{0,219}")
_KEY = re.compile(r"[A-Za-z0-9_-]{1,128}")
_USER_MANAGED = "service_account_user_managed_key"
_REFUSED = (400, 401, 403, 404)
_CODE = re.compile(r"[A-Z0-9_]{1,64}")
_ACCESS = "__access__"  # this run's access token, in the run's secrets


def reference(entity, record):
    """{project, email, key_id, key, hint} of a user-managed key its project's inventory lists."""
    parts = str(entity.get("object_id") or "").split(":")
    if len(parts) != 3 or parts[0] != "serviceAccountKey":
        return None
    _, email, key_id = parts
    body = (record or {}).get("body") or {}
    facts = unpack_facts(body.get("facts") or [])
    scope = body.get("scope") or {}
    project = facts.get("project_id")
    if (facts.get("key_type") != _USER_MANAGED or not isinstance(project, str) or not _PROJECT.fullmatch(project)
            or scope.get("kind") != "project" or scope.get("id") != project
            or not _EMAIL.fullmatch(email) or not _KEY.fullmatch(key_id)
            or facts.get("service_account_email") != email or facts.get("key_id") != key_id):
        return None
    # A key ID belongs to one service account, and the account's email names it everywhere.
    return {"project": project, "email": email, "key_id": key_id, "key": {"email": email, "key_id": key_id},
            "hint": f"{key_id[:12]} · {email[:100]} · {project}"}


def actions(reference):
    return ("DISABLE_PROVIDER_CREDENTIAL", "REVOKE_PROVIDER_CREDENTIAL")


def covers(connection, reference) -> bool:
    """A remediation connection acts on the one project it names."""
    target = connection.get("target") or {}
    return target.get("scope", "project") == "project" and target.get("project") == reference.get("project")


def _name(reference) -> str:
    return f"projects/{reference['project']}/serviceAccounts/{reference['email']}/keys/{reference['key_id']}"


def _account_url(reference) -> str:
    return f"{_API}/projects/{quote(reference['project'], safe='')}/serviceAccounts/{quote(reference['email'], safe='@')}"


def _url(reference) -> str:
    return f"{_account_url(reference)}/keys/{quote(reference['key_id'], safe='')}"


def _access(connection, secrets) -> str:
    """The run's access token, asked for once; a sign-in that failed sent nothing to IAM."""
    from cremore_gcp_provider.onboarding import _token

    held = secrets.setdefault(_ACCESS, {})
    if "token" not in held:
        try:
            held["token"] = _token(connection, secrets)
        except Exception as exc:  # noqa: BLE001 -- a sign-in error can carry what it was given; only a code leaves
            code = getattr(exc, "code", None)
            raise ProviderActionError(code if isinstance(code, str) and _CODE.fullmatch(code) else "GCP_SIGN_IN_FAILED",
                                      refused=True) from None
    return held["token"]


def _call(connection, secrets, client, method, url, **kwargs):
    token = _access(connection, secrets)
    try:
        return bounded_request(client, method, url, headers={"Authorization": "Bearer " + token},
                               max_response_bytes=64 << 10, follow_redirects=False, timeout=30, **kwargs)
    except (httpx.ConnectError, httpx.ConnectTimeout):
        raise ProviderActionError("GCP_UNAVAILABLE", refused=True) from None  # never reached Google
    except Exception:  # noqa: BLE001 -- transport errors can carry the request; only a code leaves
        raise ProviderActionError("GCP_UNAVAILABLE") from None


def _in_project(connection, secrets, client, reference) -> bool:
    """Whether the service account is the plan's project's own (False: Google no longer has it)."""
    response = _call(connection, secrets, client, "GET", _account_url(reference))
    if response.status_code == 404:
        return False
    if response.status_code in (401, 403):
        raise ProviderActionError("GCP_PERMISSION_DENIED")
    if response.status_code != 200:
        raise ProviderActionError("GCP_UNAVAILABLE" if response.status_code >= 500 or response.status_code == 429
                                  else "GCP_KEY_UNREADABLE")
    try:
        body = response.json()
    except ValueError:
        raise ProviderActionError("GCP_KEY_UNREADABLE") from None
    if not isinstance(body, dict) or body.get("projectId") != reference["project"] or body.get("email") != reference["email"]:
        raise ProviderActionError("GCP_ACCOUNT_NOT_IN_PROJECT")
    return True


def whoami(connection, secrets, client) -> str:
    """The Google account the connection acts as, when Google says (``google:<email>``); "" when it does not."""
    token = _access(connection, secrets)
    try:
        # The token goes in the body, never in a URL a proxy could log.
        response = bounded_request(client, "POST", "https://oauth2.googleapis.com/tokeninfo", data={"access_token": token},
                                   max_response_bytes=64 << 10, follow_redirects=False, timeout=30)
    except Exception:  # noqa: BLE001 -- transport errors can carry the request; only a code leaves
        raise ProviderActionError("GCP_UNAVAILABLE") from None
    if response.status_code != 200:
        raise ProviderActionError("GCP_UNAVAILABLE" if response.status_code >= 500 or response.status_code == 429
                                  else "GCP_SIGN_IN_FAILED")
    try:
        body = response.json()
    except ValueError:
        raise ProviderActionError("GCP_SIGN_IN_FAILED") from None
    email = body.get("email") if isinstance(body, dict) else None
    verified = isinstance(body, dict) and body.get("email_verified") in (True, "true")
    return f"google:{email}" if isinstance(email, str) and _EMAIL.fullmatch(email) and verified else ""


def state(connection, secrets, reference, client) -> str:
    if not _in_project(connection, secrets, client, reference):
        return "ABSENT"  # a key of an account Google no longer has
    response = _call(connection, secrets, client, "GET", _url(reference))
    if response.status_code == 404:
        return "ABSENT"
    if response.status_code in (401, 403):
        raise ProviderActionError("GCP_PERMISSION_DENIED")
    if response.status_code != 200:
        raise ProviderActionError("GCP_UNAVAILABLE" if response.status_code >= 500 or response.status_code == 429
                                  else "GCP_KEY_UNREADABLE")
    try:
        body = response.json()
    except ValueError:
        raise ProviderActionError("GCP_KEY_UNREADABLE") from None
    # Exactly the key the plan names, in the project it names (the listing gives this same form).
    if not isinstance(body, dict) or body.get("name") != _name(reference):
        raise ProviderActionError("GCP_KEY_UNREADABLE")
    if body.get("keyType") != "USER_MANAGED":
        raise ProviderActionError("GCP_KEY_NOT_USER_MANAGED")
    disabled = body.get("disabled", False)
    if not isinstance(disabled, bool):
        raise ProviderActionError("GCP_KEY_UNREADABLE")
    return "DISABLED" if disabled else "ACTIVE"


def apply(connection, secrets, reference, action, client) -> None:
    if action == "DISABLE_PROVIDER_CREDENTIAL":
        response = _call(connection, secrets, client, "POST", _url(reference) + ":disable", json={})
    elif action == "REVOKE_PROVIDER_CREDENTIAL":
        response = _call(connection, secrets, client, "DELETE", _url(reference))
    else:
        raise ProviderActionError("ACTION_NOT_SUPPORTED_FOR_CREDENTIAL", refused=True)
    if response.status_code == 200:
        return
    if response.status_code in _REFUSED:
        # Google answered the request without carrying it out (bad request, no permission, no such key).
        raise ProviderActionError("GCP_PERMISSION_DENIED" if response.status_code in (401, 403)
                                  else f"GCP_HTTP_{response.status_code}", refused=True)
    raise ProviderActionError(f"GCP_HTTP_{response.status_code}" if 100 <= response.status_code < 600
                              else "GCP_UNAVAILABLE")
