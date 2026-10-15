"""Revoking a fine-grained personal access token's access to an organization (cremore.remediation.provider_actions).

``POST /orgs/{org}/personal-access-tokens/{pat_id}`` with ``{"action": "revoke"}`` ends the access the organization
granted the token (the grant CreMore lists as ``fgpat:{org}:{pat_id}``). The token itself keeps working wherever
else it may, and its owner can ask the organization for access again, which an organization owner approves anew;
the grant revoked cannot be restored. Only a GitHub App can call it, with the organization permission "Personal access
tokens: write". The grant is read back in the organization's list filtered by the token's ID (one grant per token and
organization, GitHub lists it while it lasts): a grant missing from that filtered list is ABSENT, and a list GitHub
did not filter proves nothing. A grant whose token has expired is still revoked: its access may come back with the
token.

The acting App installation is the remediation connection's own; its installation token is asked for once per run,
for this permission alone, and kept only in that run's secrets. Nothing here keeps or reports a token or a response
body.
"""

from __future__ import annotations

import datetime as _dt
import re
from urllib.parse import quote

import httpx

from cremore.coverage.facts import unpack_facts
from cremore.http_client import bounded_request
from cremore_github_provider.github_auth import GitHubAppTokenSource, GitHubAuthError
from cremore_github_provider.github_hosts import api_base, web_base


class ProviderActionError(ValueError):
    """A fixed code (``refused``: GitHub answered without revoking anything), as the platform reads it."""

    def __init__(self, code: str, *, refused: bool = False):
        super().__init__(code)
        self.code, self.refused = code, refused


ADAPTER_VERSION = "GITHUB_FINE_GRAINED_PAT_ACCESS_V1"
# A revoke ends the organization's grant, not the token (cremore.remediation.provider_actions shows it so).
REVOKES = "ORGANIZATION_ACCESS"
# The App installation's check names the organization it is installed on: a plan binds it.
SUBJECT_METHODS = ("github_app",)
_ORG = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
_CODE = re.compile(r"[A-Z0-9_]{1,64}")
_REFUSED = (400, 401, 403, 404, 422)
_ACCESS = "__access__"  # this run's installation token, in the run's secrets
# The one permission a run's installation token is asked for (GitHub narrows the token to it).
PERMISSIONS = {"organization_personal_access_tokens": "write"}
PER_PAGE = 100


def _positive(value) -> bool:
    return type(value) is int and value > 0


def reference(entity, record):
    """{host, organization, pat_id, token_id, owner?, key, hint} of a fine-grained PAT grant an organization's
    inventory lists; None for any other credential."""
    parts = str(entity.get("object_id") or "").split(":")
    body = (record or {}).get("body") or {}
    values = unpack_facts(body.get("facts") or [])
    scope = body.get("scope") if isinstance(body.get("scope"), dict) else {}
    if len(parts) != 3 or parts[0] != "fgpat":
        return None
    _, organization, pat = parts
    host, pat_id, token_id = str(entity.get("origin") or ""), values.get("id"), values.get("token_id")
    if (not _ORG.fullmatch(organization) or not host.startswith("https://") or not _positive(pat_id)
            or str(pat_id) != pat or not _positive(token_id) or scope.get("kind") != "organization"
            or str(scope.get("id") or "").lower() != organization.lower()):
        return None
    owner = values.get("owner") if isinstance(values.get("owner"), dict) else {}
    login = owner.get("login") if isinstance(owner.get("login"), str) and _LOGIN.fullmatch(owner["login"]) else None
    out = {"host": host, "organization": organization, "pat_id": pat_id, "token_id": token_id,
           # The grant, one per token and organization.
           "key": {"host": host, "organization": organization.lower(), "pat_id": pat_id},
           "hint": f"fine-grained PAT {token_id} · {organization}" + (f" ({login})" if login else "")}
    if login:
        out["owner"] = login
    return out


def actions(reference):
    return ("REVOKE_PROVIDER_CREDENTIAL",)


def covers(connection, reference) -> bool:
    """A remediation connection acts in the one organization it is installed on."""
    target = connection.get("target") or {}
    try:
        host = web_base(target.get("host"))
    except ValueError:
        return False
    return (host == reference.get("host")
            and str(target.get("organization") or "").lower() == str(reference.get("organization") or "").lower())


def _source(connection, secrets, client) -> GitHubAppTokenSource:
    envelope = secrets.get("credential") or {}
    return GitHubAppTokenSource(lambda: client, envelope.get("GITHUB_APP_ID"),
                                envelope.get("GITHUB_APP_INSTALLATION_ID"),
                                envelope.get("GITHUB_APP_PRIVATE_KEY_BASE64"),
                                base_url=api_base((connection.get("target") or {}).get("host")), close_client=False,
                                permissions=PERMISSIONS,
                                organization=connection["target"]["organization"] if (connection.get("target_id")
                                    or connection["target"].get("auth", {}).get("github_organization_binding")) else None)


def _signed_in(exc) -> ProviderActionError:
    code = getattr(exc, "code", None)
    # Nothing reached the organization: the App's sign-in itself failed.
    return ProviderActionError(code if isinstance(code, str) and _CODE.fullmatch(code) else "GITHUB_APP_REJECTED",
                               refused=True)


def _access(connection, secrets, client) -> str:
    """The run's installation token, asked for once."""
    held = secrets.setdefault(_ACCESS, {})
    key = ((api_base((connection.get("target") or {}).get("host")), connection["target"].get("organization", "").lower())
           if connection.get("target_id") else "token")
    if key not in held:
        try:
            held[key] = _source(connection, secrets, client)()
        except (GitHubAuthError, ValueError) as exc:
            raise _signed_in(exc) from None
    return held[key]


def _call(connection, secrets, client, method, path, **kwargs):
    token = _access(connection, secrets, client)
    try:
        return bounded_request(client, method, api_base((connection.get("target") or {}).get("host")) + path,
                               headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                                        "Authorization": "Bearer " + token},
                               max_response_bytes=1 << 20, follow_redirects=False, timeout=30, **kwargs)
    except (httpx.ConnectError, httpx.ConnectTimeout):
        raise ProviderActionError("GITHUB_UNAVAILABLE", refused=True) from None  # never reached GitHub
    except Exception:  # noqa: BLE001 -- transport errors can carry the token header; only a code leaves
        raise ProviderActionError("GITHUB_UNAVAILABLE") from None


def _grants(reference) -> str:
    return f"/orgs/{quote(reference['organization'], safe='')}/personal-access-tokens"


def whoami(connection, secrets, client) -> str:
    """The organization the App installation is on, as its check names it (the connection's own spelling)."""
    envelope = secrets.get("credential") or {}
    try:
        source = _source(connection, secrets, client)
        if connection.get("target_id") or connection["target"].get("auth", {}).get("github_organization_binding"):
            source.installation_info()
            return connection["target"]["organization"]
        response = source._app_request(_dt.datetime.now(_dt.UTC), "GET",
                                       f"/app/installations/{quote(str(envelope.get('GITHUB_APP_INSTALLATION_ID')), safe='')}")
    except (GitHubAuthError, ValueError) as exc:
        raise _signed_in(exc) from None
    if response.status_code != 200:
        raise ProviderActionError("GITHUB_UNAVAILABLE" if response.status_code >= 500 or response.status_code == 429
                                  else "GITHUB_APP_REJECTED")
    try:
        account = (response.json() or {}).get("account") or {}
    except (ValueError, AttributeError):
        raise ProviderActionError("GITHUB_APP_REJECTED") from None
    login = account.get("login") if isinstance(account, dict) else None
    organization = str((connection.get("target") or {}).get("organization") or "")
    if not isinstance(login, str) or not login:
        return ""
    return organization if login.lower() == organization.lower() else login[:256]


def state(connection, secrets, reference, client) -> str:
    response = _call(connection, secrets, client, "GET", _grants(reference),
                     params={"token_id[]": str(reference["token_id"]), "per_page": str(PER_PAGE)})
    if response.status_code in (401, 403):
        raise ProviderActionError("GITHUB_PERMISSION_DENIED")
    if response.status_code == 404:
        raise ProviderActionError("GITHUB_ORGANIZATION_NOT_VISIBLE")  # the organization, never the grant
    if response.status_code != 200:
        raise ProviderActionError("GITHUB_UNAVAILABLE" if response.status_code >= 500 or response.status_code == 429
                                  else "GITHUB_GRANT_UNREADABLE")
    try:
        rows = response.json()
    except ValueError:
        raise ProviderActionError("GITHUB_GRANT_UNREADABLE") from None
    # Only this token's grants, all on one page: anything else is a list GitHub did not filter, which says nothing
    # about this grant's absence.
    if (not isinstance(rows, list) or len(rows) >= PER_PAGE
            or any(not isinstance(row, dict) or row.get("token_id") != reference["token_id"]
                   or not _positive(row.get("id")) for row in rows)):
        raise ProviderActionError("GITHUB_GRANT_UNREADABLE")
    # Listed is active, the token's own expiry aside: its access may come back with the token.
    return "ACTIVE" if any(row.get("id") == reference["pat_id"] for row in rows) else "ABSENT"


def apply(connection, secrets, reference, action, client) -> None:
    if action != "REVOKE_PROVIDER_CREDENTIAL":
        raise ProviderActionError("ACTION_NOT_SUPPORTED_FOR_CREDENTIAL", refused=True)
    response = _call(connection, secrets, client, "POST", f"{_grants(reference)}/{reference['pat_id']}",
                     json={"action": "revoke"})
    if response.status_code == 204:
        return
    if response.status_code in _REFUSED:
        # GitHub answered without revoking (bad request, no permission, no such grant, validation failed).
        raise ProviderActionError("GITHUB_PERMISSION_DENIED" if response.status_code in (401, 403)
                                  else f"GITHUB_HTTP_{response.status_code}", refused=True)
    raise ProviderActionError(f"GITHUB_HTTP_{response.status_code}" if 100 <= response.status_code < 600
                              else "GITHUB_UNAVAILABLE")
