"""Revoking an Azure DevOps personal access token by its authorization ID (cremore.remediation.provider_actions).

``POST https://vssps.dev.azure.com/{organization}/_apis/tokenadmin/revocations?isPublic=false`` with
``[{"authorizationId": ...}]`` revokes a listed token for good (204). Only a Project Collection Administrator's token
with the ``vso.tokenadministration`` scope may call it, the same scope that lists the tokens. A revocation can take
up to an hour to show, so a read-back that still finds the token valid leaves the outcome to a recheck. The token is
read back among its owner's tokens (``personalaccesstokens/{subjectDescriptor}``, the descriptor the inventory listed
it under); a token missing from that whole list is ABSENT.

The acting token is the remediation connection's own; nothing here keeps or reports a token or a response body.
"""

from __future__ import annotations

import base64
import datetime as _dt
from urllib.parse import quote

import httpx

from cremore.coverage.facts import unpack_facts
from cremore.http_client import bounded_request
from cremore_azure_provider.devops_tokens import ORIGIN, TOKEN_API_VERSION
from cremore_azure_provider.devops_tokens.adapter import ORGANIZATION
from cremore_azure_provider.devops_tokens.normalization import utc_text, uuid_text
from cremore_azure_provider.devops_tokens.transport import DESCRIPTOR, cursor_text


class ProviderActionError(ValueError):
    """A fixed code (``refused``: Azure DevOps answered without revoking anything), as the platform reads it."""

    def __init__(self, code: str, *, refused: bool = False):
        super().__init__(code)
        self.code, self.refused = code, refused


ADAPTER_VERSION = "AZURE_DEVOPS_PAT_REVOKE_V1"
# 203 is the sign-in page Azure DevOps answers a rejected token with.
_DENIED = (203, 401, 403)
_REFUSED = (400, 404) + _DENIED
PAGE_SIZE = 100
# ponytail: one owner's tokens, read whole; an owner with more than this is refused rather than paged forever.
MAX_PAGES = 50


def reference(entity, record):
    """{organization, authorization_id, owner_descriptor, key, hint} of a personal access token an organization's
    inventory lists under its owner's descriptor; None for any other."""
    parts = str(entity.get("object_id") or "").split(":")
    body = (record or {}).get("body") or {}
    values = unpack_facts(body.get("facts") or [])
    scope = body.get("scope") if isinstance(body.get("scope"), dict) else {}
    owner = values.get("owner") if isinstance(values.get("owner"), dict) else {}
    if len(parts) != 3 or parts[0] != "pat" or str(entity.get("origin") or "") != ORIGIN:
        return None
    _, organization, authorization = parts
    try:
        authorization_id = uuid_text(authorization)
    except ValueError:
        return None
    descriptor = owner.get("subject")  # the owner's subject descriptor, as the inventory listed the token
    if (not ORGANIZATION.fullmatch(organization) or values.get("authorization_id") != authorization_id
            or not isinstance(descriptor, str) or not DESCRIPTOR.fullmatch(descriptor)
            or scope.get("kind") != "organization" or scope.get("id") != organization):
        return None
    return {"organization": organization, "authorization_id": authorization_id, "owner_descriptor": descriptor,
            "key": {"organization": organization.lower(), "authorization_id": authorization_id},
            "hint": f"PAT {authorization_id} · {organization}"}


def actions(reference):
    return ("REVOKE_PROVIDER_CREDENTIAL",)


def covers(connection, reference) -> bool:
    """A remediation connection acts in the one Azure DevOps Services organization it names."""
    target = connection.get("target") or {}
    return (connection.get("edition") == "cloud" and not target.get("base_url")
            and str(target.get("organization") or "").lower() == str(reference.get("organization") or "").lower())


def _call(secrets, client, method, url, **kwargs):
    token = (secrets.get("credential") or {}).get("token", "")
    try:
        return bounded_request(client, method, url,
                               headers={"Authorization": "Basic " + base64.b64encode((":" + token).encode()).decode(),
                                        "Accept": "application/json"},
                               max_response_bytes=1 << 20, follow_redirects=False, timeout=30, **kwargs)
    except (httpx.ConnectError, httpx.ConnectTimeout):
        raise ProviderActionError("AZURE_DEVOPS_UNAVAILABLE", refused=True) from None  # never reached Azure DevOps
    except Exception:  # noqa: BLE001 -- transport errors can carry the token header; only a code leaves
        raise ProviderActionError("AZURE_DEVOPS_UNAVAILABLE") from None


def _base(reference) -> str:
    return f"{ORIGIN}/{quote(reference['organization'], safe='')}/_apis/tokenadmin"


def _expired(value) -> bool:
    try:
        return _dt.datetime.fromisoformat(utc_text(value)) < _dt.datetime.now(_dt.UTC)
    except ValueError:
        return False  # no readable expiry: its validity alone says


def state(connection, secrets, reference, client) -> str:
    url = f"{_base(reference)}/personalaccesstokens/{quote(reference['owner_descriptor'], safe='')}"
    cursor, seen = "", set()
    for _page in range(MAX_PAGES):
        params = {"api-version": TOKEN_API_VERSION, "isPublic": "false", "pageSize": str(PAGE_SIZE),
                  **({"continuationToken": cursor} if cursor else {})}
        response = _call(secrets, client, "GET", url, params=params)
        if response.status_code in _DENIED:
            raise ProviderActionError("AZURE_DEVOPS_PERMISSION_DENIED")
        if response.status_code == 404:
            raise ProviderActionError("AZURE_DEVOPS_OWNER_NOT_VISIBLE")  # the owner, never the token
        if response.status_code != 200:
            raise ProviderActionError("AZURE_DEVOPS_UNAVAILABLE" if response.status_code >= 500
                                      or response.status_code == 429 else "AZURE_DEVOPS_TOKEN_UNREADABLE")
        try:
            body = response.json()
        except ValueError:
            raise ProviderActionError("AZURE_DEVOPS_TOKEN_UNREADABLE") from None
        rows = body.get("value") if isinstance(body, dict) else None
        if not isinstance(rows, list) or len(rows) > PAGE_SIZE:
            raise ProviderActionError("AZURE_DEVOPS_TOKEN_UNREADABLE")
        for row in rows:
            if isinstance(row, dict) and str(row.get("authorizationId") or "").lower() == reference["authorization_id"]:
                if not isinstance(row.get("isValid"), bool):
                    raise ProviderActionError("AZURE_DEVOPS_TOKEN_UNREADABLE")
                if not row["isValid"]:
                    return "REVOKED"  # listed, and no longer valid
                return "EXPIRED" if _expired(row.get("validTo")) else "ACTIVE"
        following = body.get("continuationToken")
        if following in (None, ""):
            return "ABSENT"  # the owner's whole list, without it
        try:
            cursor = cursor_text(following)
        except ValueError:
            raise ProviderActionError("AZURE_DEVOPS_TOKEN_UNREADABLE") from None
        if cursor in seen:
            raise ProviderActionError("AZURE_DEVOPS_TOKEN_UNREADABLE")
        seen.add(cursor)
    raise ProviderActionError("AZURE_DEVOPS_LIST_TOO_LONG")


def apply(connection, secrets, reference, action, client) -> None:
    if action != "REVOKE_PROVIDER_CREDENTIAL":
        raise ProviderActionError("ACTION_NOT_SUPPORTED_FOR_CREDENTIAL", refused=True)
    response = _call(secrets, client, "POST", f"{_base(reference)}/revocations",
                     params={"api-version": TOKEN_API_VERSION, "isPublic": "false"},
                     json=[{"authorizationId": reference["authorization_id"]}])
    if response.status_code in (200, 204):
        return
    if response.status_code in _REFUSED:
        # Azure DevOps answered without revoking (bad request, a rejected token, no permission).
        raise ProviderActionError("AZURE_DEVOPS_PERMISSION_DENIED" if response.status_code in _DENIED
                                  else f"AZURE_DEVOPS_HTTP_{response.status_code}", refused=True)
    raise ProviderActionError(f"AZURE_DEVOPS_HTTP_{response.status_code}" if 100 <= response.status_code < 600
                              else "AZURE_DEVOPS_UNAVAILABLE")
