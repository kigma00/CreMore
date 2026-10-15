"""What Confluence says about an exposed page or attachment (cremore.governance.ownership): who wrote its
current version.

Reads, with the content connection's own credential and inside its space: on Cloud the page (v2 GET
/pages/{id}) and, for an attachment, the attachment (v2 GET /attachments/{id}) for the version's authorId
and createdAt, then that account (v1 GET /rest/api/user?accountId=) for the display name and, when the
user's profile shows it, the email; on Data Center the content's version (GET /rest/api/content/{id}
?expand=version) names the author. Direct page read restrictions are also read; ancestor/space
permissions and group membership are not evaluated. Confluence has no CODEOWNERS.
Nothing is written.

Docs: https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-page/,
https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-attachment/,
https://developer.atlassian.com/cloud/confluence/rest/v1/api-group-users/
"""

from __future__ import annotations

import re
from urllib.parse import quote

from cremore.collectors.base import CollectorError, RequestBudget
from cremore_atlassian_provider.confluence_content import SourceHTTP

_PAGE = re.compile(r"[0-9]{1,20}")
_ATTACHMENT = re.compile(r"attachments/((?:att)?[0-9]{1,20})")
_ACCOUNT = re.compile(r"[A-Za-z0-9:_-]{1,128}")


def _status(exc):
    return ("NOT_FOUND_OR_NOT_VISIBLE" if exc.detail == "404" else "FORBIDDEN" if exc.detail in ("401", "403")
            else "UNAVAILABLE")


def _content(http, cloud, page, attachment, space):
    """The page's (or its attachment's) version, once the page is in the connection's space."""
    route = "/pages/" + quote(page, safe="") if cloud else "/content/" + quote(page, safe="")
    body, _ = http.get(route, params=None if cloud else {"expand": "version,space"})
    if not isinstance(body, dict):
        raise CollectorError("SOURCE_RESPONSE_MALFORMED")
    in_space = str(body.get("spaceId", "")) if cloud else (body.get("space") or {}).get("key", "")
    if str(body.get("id")) != page or in_space != space:
        raise CollectorError("CONFLUENCE_PAGE_OUTSIDE_SCOPE")
    if attachment is None:
        return body.get("version") or {}
    route = "/attachments/" + quote(attachment, safe="") if cloud else "/content/" + quote(attachment, safe="")
    found, _ = http.get(route, params=None if cloud else {"expand": "version,container"})
    if not isinstance(found, dict):
        raise CollectorError("SOURCE_RESPONSE_MALFORMED")
    parent = str(found.get("pageId", "")) if cloud else str((found.get("container") or {}).get("id", ""))
    if parent != page:
        raise CollectorError("CONFLUENCE_PAGE_OUTSIDE_SCOPE")
    return found.get("version") or {}


def _author(http, payload, version):
    cloud = payload["edition"] == "cloud"
    if not isinstance(version, dict):
        return {"status": "UNAVAILABLE"}
    if not cloud:
        by = version.get("by") if isinstance(version.get("by"), dict) else {}
        if not by.get("displayName") and not by.get("username"):
            return {"status": "UNAVAILABLE"}
        return {"status": "OBSERVED", "name": by.get("displayName"), "login": by.get("username"), "email": None,
                "at": version.get("when"), "commit": None}
    account = version.get("authorId")
    if not isinstance(account, str) or not _ACCOUNT.fullmatch(account):
        return {"status": "UNAVAILABLE"}
    # The user lookup is the v1 API beside the v2 one, on the same site.
    api, http.base = http.base, http.site() + "/rest/api"
    try:
        user, _ = http.get("/user", params={"accountId": account})
    except CollectorError as exc:
        return {"status": _status(exc)}
    finally:
        http.base = api
    if not isinstance(user, dict):
        return {"status": "UNAVAILABLE"}
    return {"status": "OBSERVED", "name": user.get("displayName") or user.get("publicName"), "login": None,
            "email": user.get("email") or None, "at": version.get("createdAt"), "commit": None}


def _restrictions(http, page):
    """The page's direct read restriction subjects; space/ancestor permission is not implied."""
    result = {"basis": "CONFLUENCE_PAGE_RESTRICTIONS", "evidence_kind": "PROVIDER_RESTRICTIONS",
              "visibility": "UNKNOWN", "limitations": ["ANCESTOR_PERMISSIONS_NOT_EVALUATED", "GROUP_MEMBERS_NOT_EXPANDED",
              "RESTRICTION_IS_NOT_READ_PERMISSION", "SPACE_PERMISSIONS_NOT_EVALUATED"]}
    api, http.base = http.base, http.site() + "/rest/api"
    try:
        body, _ = http.get(f"/content/{page}/restriction/byOperation/read",
                           params={"expand": "restrictions.user,restrictions.group", "start": 0, "limit": 100})
    except CollectorError as exc:
        return {**result, "status": _status(exc), "limitations": [*result["limitations"],
                "ACCESS_LIST_PERMISSION_REQUIRED" if exc.detail in ("401", "403") else "ACCESS_LIST_UNAVAILABLE"]}
    finally:
        http.base = api
    if not isinstance(body, dict) or body.get("operation") != "read" or not isinstance(body.get("restrictions"), dict):
        return {**result, "status": "UNAVAILABLE"}
    people, partial = [], False
    for kind in ("user", "group"):
        block = body["restrictions"].get(kind)
        rows = block.get("results") if isinstance(block, dict) else None
        if not isinstance(rows, list):
            partial = True
            continue
        # Nested restriction arrays have independent pagination. Never treat the first expansion as the full ACL.
        links = block.get("_links") if isinstance(block.get("_links"), dict) else {}
        partial |= len(rows) >= 100 or bool(links.get("next"))
        for row in rows[:100]:
            ident = (row.get("accountId") or row.get("userKey") or row.get("username")) if kind == "user" and isinstance(row, dict) else (
                row.get("id") or row.get("name") if isinstance(row, dict) else None)
            if not isinstance(ident, str) or not 0 < len(ident) <= 256 or not ident.isprintable():
                partial = True
                continue
            people.append({"login": ident, "principal_id": ident, "principal_kind": kind.upper(),
                "name": row.get("displayName") or row.get("name"), "role": "read_restriction",
                "permission": "read", "effect": "RESTRICT", "read_access": "UNKNOWN"})
    if partial:
        result["limitations"].append("RESTRICTION_LIST_PARTIAL")
    return {**result, "status": "OBSERVED", "people": people, "truncated": partial}


def read(payload, location, *, http_client, members=True) -> dict:
    """``{codeowners, author}`` for one exposed page body or attachment ({repository: page id, path})."""
    page, path = str(location.get("repository") or ""), str(location.get("path") or "")
    match = _ATTACHMENT.fullmatch(path)
    out = {"codeowners": {"status": "UNSUPPORTED"}}
    if not _PAGE.fullmatch(page) or not (path == "body" or match) or not payload.get("space"):
        return {**out, "author": {"status": "UNSUPPORTED"}}
    # A service account's token may first need the site's cloud ID and a token grant: two more requests.
    limit = (6 if getattr(payload.get("token"), "gateway", False) else 4) + int(members)
    http = SourceHTTP({**payload, "max_requests": limit}, http_client, budget=RequestBudget(limit))
    try:
        version = _content(http, payload["edition"] == "cloud", page, match.group(1) if match else None, payload["space"])
    except CollectorError as exc:
        status = "UNAVAILABLE" if exc.code == "CONFLUENCE_PAGE_OUTSIDE_SCOPE" else _status(exc)
        return {**out, "author": {"status": status}, **({"members": {"status": status}} if members else {})}
    return {**out, "author": _author(http, payload, version), **({"members": _restrictions(http, page)} if members else {})}
