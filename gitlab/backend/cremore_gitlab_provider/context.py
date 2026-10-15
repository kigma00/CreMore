"""What GitLab says about an exposed file (cremore.governance.ownership): its CODEOWNERS file, the last
commit that changed it and who can read its project.

Reads with the source connection's own credential, at the commit the scan read: the CODEOWNERS file
(the first of the root, docs/ and .gitlab/, as GitLab looks), one commits page for the path and at most
MAX_MEMBER_PAGES pages of the project's members, inherited ones included, with the role each holds.
Nothing is written.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from cremore.collectors.base import CollectorError, RequestBudget
from cremore_gitlab_provider.content import SourceHTTP

CODEOWNERS = ("CODEOWNERS", "docs/CODEOWNERS", ".gitlab/CODEOWNERS")
MAX_MEMBER_PAGES = 3
MAX_MEMBER_PAGE = 100
MAX_CODEOWNERS_BYTES = 3 * 1024 * 1024
_PROJECT = re.compile(r"[0-9]{1,20}|[A-Za-z0-9_.-]{1,255}(?:/[A-Za-z0-9_.-]{1,255}){1,20}")
_SHA = re.compile(r"[0-9a-f]{40,64}")
# GitLab's access levels (Members API). Minimal access (5) and no access (0) cannot open the project, so they are not listed.
ROLES = {10: "guest", 15: "planner", 20: "reporter", 25: "security_manager", 30: "developer", 40: "maintainer", 50: "owner"}


def _status(exc):
    if exc.code == "SOURCE_RESPONSE_TOO_LARGE":
        return "TRUNCATED"
    return ("NOT_FOUND_OR_NOT_VISIBLE" if exc.detail == "404" else "FORBIDDEN" if exc.detail in ("401", "403")
            else "UNAVAILABLE")


def _codeowners(http, project, ref):
    for path in CODEOWNERS:
        try:
            text = http.get(f"/projects/{project}/repository/files/{quote(path, safe='')}/raw",
                            params={"ref": ref or "HEAD"}, raw=True, max_bytes=MAX_CODEOWNERS_BYTES)
        except CollectorError as exc:
            if exc.detail == "404":
                continue
            return {"status": _status(exc), **({"path": path} if exc.code == "SOURCE_RESPONSE_TOO_LARGE" else {})}
        return {"status": "OBSERVED", "path": path, "text": text.decode("utf-8", "replace")}
    return {"status": "NO_CODEOWNERS"}


def _last_commit(http, project, path, ref):
    try:
        rows, _headers = http.get(f"/projects/{project}/repository/commits",
                                  params={"path": path, "per_page": 1, **({"ref_name": ref} if ref else {})})
    except CollectorError as exc:
        return {"status": _status(exc)}
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        return {"status": "NOT_FOUND_OR_NOT_VISIBLE"}
    row = rows[0]
    return {"status": "OBSERVED", "name": row.get("author_name"), "email": row.get("author_email"), "login": None,
            "at": row.get("authored_date"), "commit": row.get("id") if isinstance(row.get("id"), str) else None}


def _audience(http, project):
    try:
        body, _ = http.get(f"/projects/{project}")
    except CollectorError:
        body = None
    visibility = body.get("visibility") if isinstance(body, dict) else None
    if visibility not in ("public", "internal", "private"):
        return {"visibility": "UNKNOWN", "limitations": ["VISIBILITY_UNAVAILABLE"]}, False
    limitations = [{"public": "PUBLIC_ACCESS_NOT_ENUMERATED", "internal": "INTERNAL_ACCESS_NOT_ENUMERATED"}[visibility]] if visibility != "private" else []
    repository_read = body.get("repository_access_level") in ("enabled", "private")
    if not repository_read:
        limitations.append("REPOSITORY_READ_NOT_CONFIRMED")
    return {"visibility": visibility.upper(), "limitations": limitations}, repository_read


def _members(http, project, *, start_page=1):
    if type(start_page) is not int or not 1 <= start_page <= MAX_MEMBER_PAGE:
        raise ValueError("INVALID_MEMBER_PAGE")
    audience, repository_read = _audience(http, project)
    result = {"basis": "GITLAB_PROJECT_MEMBERS", "evidence_kind": "PROVIDER_MEMBERSHIP", **audience}
    people, seen, malformed = [], set(), False
    for page in range(start_page, min(start_page + MAX_MEMBER_PAGES, MAX_MEMBER_PAGE + 1)):
        if page > 1 and "PAGED_LIST_NOT_ATOMIC" not in result["limitations"]:
            result["limitations"].append("PAGED_LIST_NOT_ATOMIC")
        try:
            rows, headers = http.get(f"/projects/{project}/members/all", params={"per_page": 100, "page": page})
        except CollectorError as exc:
            result["limitations"].append("MEMBER_PAGE_UNAVAILABLE")
            return {**result, "status": _status(exc), "truncated": True, **({"people": people} if people else {})}
        if not isinstance(rows, list):
            result["limitations"].append("MEMBER_PAGE_UNAVAILABLE")
            return {**result, "status": "UNAVAILABLE", "truncated": True, **({"people": people} if people else {})}
        malformed = malformed or len(rows) > 100
        for row in rows[:100]:
            if (not isinstance(row, dict) or not isinstance(row.get("username"), str)
                    or not 0 < len(row["username"]) <= 128 or type(row.get("access_level")) is not int):
                malformed = True
                continue
            if row.get("state", "active") != "active" or row["access_level"] < 10:
                continue
            login, level = row["username"], row["access_level"]
            if login.casefold() in seen:
                continue
            seen.add(login.casefold())
            confirmed = repository_read and level in (20, 30, 40, 50)
            people.append({"login": login, "name": row.get("name") if isinstance(row.get("name"), str) else None,
                           "principal_kind": "SERVICE_PRINCIPAL" if row.get("bot") is True else "USER",
                           "role": ROLES.get(level), "read_access": "REPORTED" if confirmed else "UNKNOWN"})
            if not confirmed and "MEMBERSHIP_IS_NOT_REPOSITORY_READ" not in result["limitations"]:
                result["limitations"].append("MEMBERSHIP_IS_NOT_REPOSITORY_READ")
        if malformed and "MALFORMED_MEMBER_ROWS" not in result["limitations"]:
            result["limitations"].append("MALFORMED_MEMBER_ROWS")
        next_page = headers.get("x-next-page")
        if next_page and next_page != str(page + 1):
            result["limitations"].append("MEMBER_PAGINATION_INVALID")
            return {**result, "status": "UNAVAILABLE", "people": people, "truncated": True}
        if next_page == "" or next_page is None and len(rows) < 100:
            return {**result, "status": "OBSERVED", "people": people, "truncated": malformed}
    result["limitations"].append("MEMBER_PAGE_LIMIT")
    return {**result, "status": "OBSERVED", "people": people, "truncated": True,
            "next_page": page + 1 if page < MAX_MEMBER_PAGE else None}


def read(payload, location, *, http_client, members=True, member_page=1) -> dict:
    """``{codeowners, author[, members]}`` for one exposed ``location`` ({repository: project id or path, path, commit})."""
    project, path = str(location.get("repository") or ""), location.get("path") or ""
    if not _PROJECT.fullmatch(project) or not path:
        return {"codeowners": {"status": "UNSUPPORTED"}, "author": {"status": "UNSUPPORTED"}}
    project = quote(project, safe="")
    ref = location.get("commit") if _SHA.fullmatch(str(location.get("commit") or "")) else ""
    http = SourceHTTP({**payload, "max_requests": 20}, http_client, budget=RequestBudget(20), max_bytes=MAX_CODEOWNERS_BYTES)
    out = {} if member_page > 1 else {
        "codeowners": _codeowners(http, project, ref), "author": _last_commit(http, project, path, ref)}
    if members:
        out["members"] = _members(http, project, start_page=member_page)
    return out
