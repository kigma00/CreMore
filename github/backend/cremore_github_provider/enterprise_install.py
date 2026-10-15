"""CreMore's GitHub App installed on the organizations of an enterprise (recommendation O-C2).

An App installed on an enterprise account may install Apps on the enterprise's organizations when it holds the
enterprise permission "Enterprise organization installations" (read and write): ``POST
/enterprises/{enterprise}/apps/organizations/{org}/installations`` (public preview on GitHub Enterprise Cloud;
documented for GitHub Enterprise Server 3.19). CreMore's App installs itself:

1. its owner transfers it to the enterprise (it becomes internal, installable in every organization there);
2. an enterprise owner adds that permission and installs it on the enterprise account;
3. the enterprise installation lists the organizations it may install on, and installs the same App on the
   chosen ones with access to all their repositories.

GitHub's manifest flow makes no enterprise App and grants no enterprise permission, so steps 1 and 2 are done in
GitHub. Each call here uses the App's JWT or a short-lived token of its enterprise installation, held in memory
only and revoked once used. A listing longer than ten pages stops with ``GITHUB_LIST_TRUNCATED`` rather than
reading as complete.
"""

from __future__ import annotations

import re
import time
from urllib.parse import quote

import httpx

from cremore.http_client import bounded_request
from cremore_github_provider.github_auth import (
    GitHubAppTokenSource,
    GitHubAuthError,
    app_assertion,
    app_identity,
)
from cremore_github_provider.github_hosts import api_base

_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?")
MAX_PAGES = 10  # 1,000 organizations or installations
_TIMEOUT = httpx.Timeout(10.0, connect=5.0)  # one call; the worker's tick budget bounds the rest


def _name(value, pattern, code) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise GitHubAuthError(code)
    return value


def _call(client, method, url, bearer, **kwargs):
    try:
        return bounded_request(client, method, url, headers={**_HEADERS, "Authorization": "Bearer " + bearer},
                               max_response_bytes=1 << 20, follow_redirects=False, timeout=_TIMEOUT, **kwargs)
    except Exception:  # noqa: BLE001 -- transport errors can carry the bearer
        raise GitHubAuthError("GITHUB_APP_UNAVAILABLE") from None


def _refused(response) -> GitHubAuthError:
    status = response.status_code
    if status in (401, 403):
        # Not installed on the enterprise, or without "Enterprise organization installations: read and write".
        return GitHubAuthError("GITHUB_ENTERPRISE_PERMISSION_REQUIRED")
    if status == 404:
        return GitHubAuthError("GITHUB_ENTERPRISE_NOT_FOUND")  # no such enterprise here, or a server without the API
    if status == 422:
        return GitHubAuthError("GITHUB_ENTERPRISE_INSTALL_REFUSED")  # e.g. the App is not the enterprise's
    return GitHubAuthError("GITHUB_APP_UNAVAILABLE")


def _pages(client, url, bearer, pick, deadline=None):
    for page in range(1, MAX_PAGES + 1):
        if deadline is not None and page > 1 and time.monotonic() > deadline:
            raise GitHubAuthError("GITHUB_TOO_SLOW")  # the rest waits for a later tick
        response = _call(client, "GET", url, bearer, params={"per_page": 100, "page": page})
        if response.status_code != 200:
            raise _refused(response)
        try:
            rows = pick(response.json())
        except (ValueError, TypeError, KeyError, AttributeError):
            raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED") from None
        if not isinstance(rows, list):
            raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED")
        yield from rows
        if len(rows) < 100:
            return
    # A cut list would read as "not installed there" and install or report the wrong thing: stop instead.
    raise GitHubAuthError("GITHUB_LIST_TRUNCATED")


def app(client, host, app_id, private_key_base64) -> dict:
    """The App the key signs for (``GET /app``): its Client ID, slug and owner."""
    response = _call(client, "GET", f"{api_base(host)}/app", app_assertion(app_id, private_key_base64))
    if response.status_code != 200:
        raise GitHubAuthError("GITHUB_APP_REJECTED" if response.status_code in (401, 403, 404) else "GITHUB_APP_UNAVAILABLE")
    try:
        found = app_identity(response.json(), app_id)
    except ValueError:
        raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED") from None
    if not found["client_id"] or not _SLUG.fullmatch(found["slug"] or ""):
        raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED")
    return found


def installations(client, host, app_id, private_key_base64, deadline=None) -> dict:
    """Where the App is installed (``GET /app/installations``): ``{"enterprises": {slug: id}, "organizations":
    {login (lower case): id}}``."""
    out = {"enterprises": {}, "organizations": {}}
    assertion = app_assertion(app_id, private_key_base64)
    for row in _pages(client, f"{api_base(host)}/app/installations", assertion, lambda body: body, deadline):
        account = row.get("account") if isinstance(row, dict) else None
        if not isinstance(account, dict) or type(row.get("id")) is not int or row["id"] < 1:
            continue
        slug, login = account.get("slug"), account.get("login")
        if row.get("target_type") == "Enterprise" and isinstance(slug, str) and _LOGIN.fullmatch(slug):
            out["enterprises"][slug.lower()] = str(row["id"])
        elif row.get("target_type") == "Organization" and isinstance(login, str) and _LOGIN.fullmatch(login):
            out["organizations"][login.lower()] = str(row["id"])
    return out


def enterprise_token(client_factory, host, app_id, installation_id, private_key_base64) -> str:
    """A token of the App's enterprise installation, for the calls below; ``revoke`` it when done."""

    def short():
        client = client_factory()
        client.timeout = _TIMEOUT  # the same per-call limit as every other call here
        return client

    return GitHubAppTokenSource(short, app_id, installation_id, private_key_base64, base_url=api_base(host))()


def revoke(client, host, token) -> None:
    """End an installation token before its hour is up (``DELETE /installation/token``); best effort."""
    try:
        _call(client, "DELETE", f"{api_base(host)}/installation/token", token)
    except GitHubAuthError:
        pass  # it expires within the hour anyway


def installable_organizations(client, host, token, enterprise, deadline=None) -> list[str]:
    """The enterprise's organizations an App can be installed on."""
    enterprise = _name(enterprise, _LOGIN, "GITHUB_ENTERPRISE_INVALID")
    url = f"{api_base(host)}/enterprises/{quote(enterprise, safe='')}/apps/installable_organizations"
    logins = []
    for row in _pages(client, url, token, lambda body: body, deadline):
        login = row.get("login") if isinstance(row, dict) else None
        if isinstance(login, str) and _LOGIN.fullmatch(login):
            logins.append(login)
    return logins


def install(client, host, token, enterprise, organization, client_id) -> str:
    """Install the App (``client_id``) on one organization with access to all its repositories; its installation ID.
    GitHub answers 200 for an App already there (a suspended one is unsuspended) and 201 for a new one."""
    enterprise = _name(enterprise, _LOGIN, "GITHUB_ENTERPRISE_INVALID")
    organization = _name(organization, _LOGIN, "GITHUB_ORGANIZATION_INVALID")
    url = (f"{api_base(host)}/enterprises/{quote(enterprise, safe='')}/apps/organizations/"
           f"{quote(organization, safe='')}/installations")
    response = _call(client, "POST", url, token, json={"client_id": client_id, "repository_selection": "all"})
    if response.status_code not in (200, 201):
        raise _refused(response)
    try:
        installation_id = response.json()["id"]
    except (ValueError, TypeError, KeyError):
        raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED") from None
    if type(installation_id) is not int or installation_id < 1:
        raise GitHubAuthError("GITHUB_APP_RESPONSE_MALFORMED")
    return str(installation_id)
