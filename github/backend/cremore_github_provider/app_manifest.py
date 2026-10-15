"""A GitHub App registered from a manifest for one organization.

The admin posts the manifest CreMore writes to GitHub's "new app" page of the organization and presses
Create; GitHub sends the browser back with a one-hour code, which the server alone converts
(``POST /app-manifests/{code}/conversions``): the App's ID and private key go from GitHub to CreMore without
passing through the browser or the clipboard. The admin then installs the App on the organization, and the
server finds that installation with the App's own JWT (``GET /app/installations``) rather than trusting an
installation ID in a redirect. The client and webhook secrets GitHub also returns are never kept.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import quote

from cremore.http_client import bounded_request
from cremore_github_provider.github_auth import GitHubAuthError, app_assertion
from cremore_github_provider.github_hosts import api_base, normalize_host, web_base

_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
_CODE = re.compile(r"[A-Za-z0-9_-]{1,512}")
_SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?")
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
# Collection Apps read only. A separate action App has one explicitly selected write grant.
MAX_PAGES = 10


def manifest(organization, purposes, permissions) -> dict:
    """What CreMore asks GitHub to create: a private App for the explicitly chosen installation permissions and
    no webhook events. The browser adds its own origin (``url``, ``redirect_url``, ``setup_url``,
    ``hook_attributes``), since only it knows the address the admin reaches CreMore at."""
    if (not isinstance(purposes, list) or any(not isinstance(purpose, str) for purpose in purposes)
            or set(purposes) - {"exposure", "inventory", "vault", "identity", "remediation"}
            or ("remediation" in purposes and set(purposes) != {"remediation"})):
        raise GitHubAuthError("AUTH_METHOD_NOT_FOR_PURPOSES")
    acting = "remediation" in purposes
    wanted = {"organization_personal_access_tokens": "write"} if acting else {}
    reads = []
    for purpose, label in (("exposure", "repositories"), ("inventory", "credential inventories"),
                           ("vault", "secret metadata"), ("identity", "SAML identities")):
        if purpose in purposes:
            wanted.update(dict.fromkeys(permissions[purpose], "read"))
            reads.append(label)
    return {"name": f"CreMore {'Actions ' if acting else ''}{organization}"[:34], "public": False, "default_permissions": wanted,
            "default_events": [], "request_oauth_on_install": False, "setup_on_update": False,
            "description": ("CreMore Actions revokes fine-grained personal access tokens' organization access after approval."
                            if acting else f"CreMore reads {', '.join(reads)} (read only)." if reads
                            else "CreMore authenticates this App; no collection permissions are requested.")}


def form_url(host, organization) -> str:
    """GitHub's "register a new App" page of the organization, where the browser posts the manifest."""
    if not _LOGIN.fullmatch(str(organization or "")):
        raise GitHubAuthError("GITHUB_ORGANIZATION_INVALID")
    return f"{web_base(host)}/organizations/{quote(organization, safe='')}/settings/apps/new"


def install_url(host, slug) -> str:
    """Where the admin installs the App (GitHub Enterprise Server names its Apps github-apps)."""
    if not _SLUG.fullmatch(str(slug or "")):
        raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED")
    normalized = normalize_host(host)
    path = "github-apps" if normalized and not normalized.endswith(".ghe.com") else "apps"
    return f"{web_base(host)}/{path}/{slug}/installations/new"


def convert(client, host, code) -> dict:
    """The App GitHub made from the manifest: ``{app_id, client_id, slug, name, owner, private_key_base64}``."""
    if not isinstance(code, str) or not _CODE.fullmatch(code):
        raise GitHubAuthError("GITHUB_MANIFEST_CODE_INVALID")
    try:
        response = bounded_request(client, "POST", f"{api_base(host)}/app-manifests/{code}/conversions",
                                   headers=_HEADERS, max_response_bytes=1 << 20, follow_redirects=False)
    except Exception:  # noqa: BLE001 -- transport errors can quote the code
        raise GitHubAuthError("GITHUB_APP_UNAVAILABLE") from None
    status = response.status_code
    if status == 404:
        raise GitHubAuthError("GITHUB_MANIFEST_CODE_EXPIRED")  # used, or older than an hour
    if status != 201:
        raise GitHubAuthError("GITHUB_APP_UNAVAILABLE" if status >= 500 or status == 429 else "GITHUB_MANIFEST_REFUSED")
    try:
        body = response.json()
        app_id, pem, slug = body["id"], body["pem"], body.get("slug")
        owner = (body.get("owner") or {}).get("login") or (body.get("owner") or {}).get("slug")
    except (ValueError, KeyError, TypeError, AttributeError):
        raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED") from None
    if (type(app_id) is not int or app_id < 1 or not isinstance(pem, str) or "PRIVATE KEY" not in pem
            or not _SLUG.fullmatch(str(slug or "")) or not isinstance(owner, str) or not _LOGIN.fullmatch(owner)):
        raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED")
    key = base64.b64encode(pem.strip().encode("ascii", "ignore")).decode("ascii")
    app_assertion(app_id, key)  # the key signs, or it is refused now rather than at first use
    client_id = body.get("client_id")
    name = body.get("name")
    return {"app_id": str(app_id), "client_id": client_id if isinstance(client_id, str) and len(client_id) <= 128 else None,
            "slug": slug, "name": name if isinstance(name, str) and name.isprintable() and len(name) <= 200 else slug,
            "owner": owner, "private_key_base64": key}


def installation(client, host, app_id, private_key_base64, organization) -> str | None:
    """The App's installation on ``organization``, found with the App's JWT; None until it is installed."""
    wanted = str(organization or "").lower()
    assertion = app_assertion(app_id, private_key_base64)
    for page in range(1, MAX_PAGES + 1):
        try:
            response = bounded_request(client, "GET", f"{api_base(host)}/app/installations",
                                       params={"per_page": 100, "page": page},
                                       headers={**_HEADERS, "Authorization": "Bearer " + assertion},
                                       max_response_bytes=1 << 20, follow_redirects=False)
        except Exception:  # noqa: BLE001 -- transport errors can carry the assertion
            raise GitHubAuthError("GITHUB_APP_UNAVAILABLE") from None
        if response.status_code in (401, 403):
            raise GitHubAuthError("GITHUB_APP_REJECTED")
        if response.status_code != 200:
            raise GitHubAuthError("GITHUB_APP_UNAVAILABLE")
        try:
            rows = response.json()
        except ValueError:
            raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED") from None
        if not isinstance(rows, list):
            raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED")
        for row in rows:
            account = row.get("account") if isinstance(row, dict) else None
            login = account.get("login") if isinstance(account, dict) else None
            if (isinstance(login, str) and login.lower() == wanted and type(row.get("id")) is int and row["id"] > 0
                    and row.get("target_type") == "Organization"):
                return str(row["id"])
        if len(rows) < 100:
            return None
    return None
