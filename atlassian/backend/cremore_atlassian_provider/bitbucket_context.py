"""What Bitbucket says about an exposed file (cremore.governance.ownership): the last commit that changed it.

Reads, with the content connection's own credential and only in its workspace (Cloud) or project (Data
Center), one commit at the commit the scan read: on Cloud GET /2.0/repositories/{workspace}/{repo}/commits/
{commit}?path=&pagelen=1 (author raw "Name <email>" and the linked account's display name), on Data Center
GET /rest/api/1.0/projects/{project}/repos/{repo}/commits?path=&until=&limit=1 (author name, email and
display name). CODEOWNERS is not a Bitbucket Cloud feature, and the repository permission lists need
repository admin and name only explicitly granted users, so neither is read. Nothing is written.

Docs: https://developer.atlassian.com/cloud/bitbucket/rest/api-group-commits/,
https://developer.atlassian.com/server/bitbucket/rest/ (Repository: get commits)
"""

from __future__ import annotations

import datetime as dt
import re
from urllib.parse import parse_qs, quote, urlsplit

from cremore.collectors.base import CollectorError, RequestBudget
from cremore_atlassian_provider.bitbucket_content import SourceHTTP

_REPOSITORY = re.compile(r"([A-Za-z0-9_~-]{1,128})/([A-Za-z0-9_.-]{1,128})")
_SHA = re.compile(r"[0-9a-f]{40,64}")
_RAW = re.compile(r"\s*(.*?)\s*<([^<>\s]+@[^<>\s]+)>\s*")
MAX_PERMISSION_PAGES = 3


def _status(exc):
    return ("NOT_FOUND_OR_NOT_VISIBLE" if exc.detail == "404" else "FORBIDDEN" if exc.detail in ("401", "403")
            else "UNAVAILABLE")


def _cloud(row):
    author = row.get("author") if isinstance(row.get("author"), dict) else {}
    user = author.get("user") if isinstance(author.get("user"), dict) else {}
    raw = _RAW.fullmatch(author.get("raw") or "") if isinstance(author.get("raw"), str) else None
    return {"name": user.get("display_name") or (raw.group(1) if raw else None) or author.get("raw"),
            "login": user.get("nickname"), "email": raw.group(2) if raw else None, "at": row.get("date"),
            "commit": row.get("hash")}


def _data_center(row):
    author = row.get("author") if isinstance(row.get("author"), dict) else {}
    stamp = row.get("authorTimestamp")
    at = (dt.datetime.fromtimestamp(stamp / 1000, dt.UTC).isoformat()
          if isinstance(stamp, int) and not isinstance(stamp, bool) and stamp > 0 else None)
    return {"name": author.get("displayName") or author.get("name"), "login": author.get("slug") or author.get("name"),
            "email": author.get("emailAddress"), "at": at, "commit": row.get("id")}


def _permissions(http, cloud, owner, repo):
    result = {"basis": "BITBUCKET_REPOSITORY_PERMISSIONS", "evidence_kind": "PROVIDER_GRANTS",
        "visibility": "UNKNOWN", "limitations": ["INHERITED_PERMISSIONS_NOT_EVALUATED", "GROUP_MEMBERS_NOT_EXPANDED",
        "GRANT_IS_NOT_EFFECTIVE_PERMISSION"]}
    base = f"/repositories/{owner}/{repo}" if cloud else f"/projects/{owner}/repos/{repo}"
    try:
        metadata, _ = http.get(base)
        public = metadata.get("is_private") is False if cloud and isinstance(metadata, dict) else (
            metadata.get("public") is True if isinstance(metadata, dict) else False)
        if isinstance(metadata, dict) and type(metadata.get("is_private" if cloud else "public")) is bool:
            result["visibility"] = "PUBLIC" if public else "PRIVATE"
        if public:
            result["limitations"].append("PUBLIC_ACCESS_NOT_ENUMERATED")
    except CollectorError:
        result["limitations"].append("VISIBILITY_UNAVAILABLE")
    people, partial, failure, completed = [], False, None, 0
    for kind in ("user", "group"):
        route = base + (f"/permissions-config/{kind}s" if cloud else f"/permissions/{kind}s")
        cursor, seen = 1 if cloud else 0, set()
        for _ in range(MAX_PERMISSION_PAGES):
            try:
                body, _headers = http.get(route, params={"page": cursor, "pagelen": 50} if cloud else {"start": cursor, "limit": 50})
            except CollectorError as exc:
                failure, partial = _status(exc), True
                result["limitations"].append("ACCESS_LIST_PERMISSION_REQUIRED" if exc.detail in ("401", "403") else "ACCESS_LIST_UNAVAILABLE")
                break
            rows = body.get("values") if isinstance(body, dict) else None
            if not isinstance(rows, list):
                failure, partial = "UNAVAILABLE", True
                break
            partial |= len(rows) > 50
            for row in rows[:50]:
                subject = row.get(kind) if isinstance(row, dict) else None
                if isinstance(subject, str) and kind == "group":
                    subject = {"name": subject}
                ident = (subject.get("uuid") or subject.get("account_id") or subject.get("slug") or subject.get("name")) if isinstance(subject, dict) else None
                role = row.get("permission") if isinstance(row, dict) else None
                if not isinstance(ident, str) or not 0 < len(ident) <= 256 or role not in ("read", "write", "admin", "REPO_READ", "REPO_WRITE", "REPO_ADMIN"):
                    partial = True
                    continue
                people.append({"login": ident, "principal_id": ident, "principal_kind": kind.upper(),
                    "name": subject.get("display_name") or subject.get("displayName") or subject.get("name"),
                    "role": role.lower(), "permission": role, "effect": "ALLOW", "read_access": "UNKNOWN"})
            more = bool(body.get("next")) if cloud else body.get("isLastPage") is not True
            if not more:
                completed += 1
                break
            next_cursor = (parse_qs(urlsplit(body["next"]).query).get("page") or [""])[0] if cloud and isinstance(body.get("next"), str) else body.get("nextPageStart")
            if cloud and isinstance(next_cursor, str) and next_cursor.isdecimal():
                next_cursor = int(next_cursor)
            if not rows or type(next_cursor) is not int or next_cursor <= cursor or next_cursor in seen:
                failure, partial = "UNAVAILABLE", True
                result["limitations"].append("ACCESS_PAGINATION_INVALID")
                break
            seen.add(cursor)
            cursor = next_cursor
        else:
            partial = True
            result["limitations"].append("MEMBER_PAGE_LIMIT")
    return {**result, "status": failure or "OBSERVED", "people": people, "truncated": partial or completed != 2,
            "limitations": list(dict.fromkeys(result["limitations"]))}


def read(payload, location, *, http_client, members=True) -> dict:
    """``{codeowners, author}`` for one exposed file ({repository: owner/repo, path, commit})."""
    cloud = payload.get("edition", "cloud") == "cloud"
    match = _REPOSITORY.fullmatch(str(location.get("repository") or ""))
    path, commit = str(location.get("path") or ""), str(location.get("commit") or "")
    out = {"codeowners": {"status": "UNSUPPORTED"}}
    # Only the connection's own workspace or project, at a commit the scan read.
    if (not match or match.group(1) != payload.get("workspace" if cloud else "project")
            or (payload.get("repo") and payload["repo"] != match.group(2)) or not path
            or not _SHA.fullmatch(commit)):
        return {**out, "author": {"status": "UNSUPPORTED"}}
    owner, repo = (quote(part, safe="") for part in match.groups())
    limit = 8 if members else 2
    http = SourceHTTP({**payload, "max_requests": limit}, http_client, budget=RequestBudget(limit))
    access = {"members": _permissions(http, cloud, owner, repo)} if members else {}
    try:
        if cloud:
            body, _ = http.get(f"/repositories/{owner}/{repo}/commits/{commit}", params={"path": path, "pagelen": 1})
        else:
            body, _ = http.get(f"/projects/{owner}/repos/{repo}/commits", params={"path": path, "until": commit, "limit": 1})
    except CollectorError as exc:
        return {**out, **access, "author": {"status": _status(exc)}}
    rows = body.get("values") if isinstance(body, dict) else None
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        return {**out, **access, "author": {"status": "NOT_FOUND_OR_NOT_VISIBLE"}}
    return {**out, **access, "author": {"status": "OBSERVED", **(_cloud(rows[0]) if cloud else _data_center(rows[0]))}}
