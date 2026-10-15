"""What GitHub says about an exposed file (cremore.governance.ownership): its CODEOWNERS file, the last
commit that changed it and who can read its repository.

Reads with the source connection's own credential, at the commit the scan read: the CODEOWNERS file
(the first of .github/, the root and docs/, as GitHub looks), one commits page for the path and at most
MAX_MEMBER_PAGES pages of repository collaborators (outside collaborators, members through teams and
the organization's base permission, and owners) with the role each holds. Nothing is written.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from cremore.http_client import HTTPResponseTooLarge, bounded_request

CODEOWNERS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
MAX_MEMBER_PAGES = 3
MAX_MEMBER_PAGE = 100
MAX_CODEOWNERS_BYTES = 3 * 1024 * 1024
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_SHA = re.compile(r"[0-9a-f]{40,64}")
_ROLES = ("admin", "maintain", "write", "triage", "read")


class _Reader:
    def __init__(self, payload, client):
        self.client, self.base = client, str(payload.get("base_url") or "https://api.github.com").rstrip("/")
        self.token, self.requests = payload.get("token", ""), 0

    def get(self, route, params=None, *, raw=False):
        """``(status, body)``: the JSON (or bytes) of a 200, else None with the HTTP status."""
        token = self.token() if callable(self.token) else self.token
        if not token:
            return 0, None
        self.requests += 1
        headers = {"Authorization": "Bearer " + token, "X-GitHub-Api-Version": "2022-11-28",
                   "Accept": "application/vnd.github.raw" if raw else "application/vnd.github+json"}
        try:
            response = bounded_request(self.client, "GET", self.base + route, params=params, headers=headers,
                                       follow_redirects=False,
                                       max_response_bytes=MAX_CODEOWNERS_BYTES if raw else 4 << 20)
        except HTTPResponseTooLarge:
            return 413, None
        except Exception:  # noqa: BLE001 -- a transport failure is a status, never its text
            return 0, None
        if response.status_code != 200:
            return response.status_code, None
        if raw:
            return 200, response.content
        try:
            return 200, response.json()
        except ValueError:
            return 0, None


def _status(code):
    return "NOT_FOUND_OR_NOT_VISIBLE" if code == 404 else "FORBIDDEN" if code in (401, 403) else "UNAVAILABLE"


def _codeowners(reader, repository, ref):
    for path in CODEOWNERS:
        code, body = reader.get(f"/repos/{repository}/contents/{quote(path)}", {"ref": ref} if ref else None, raw=True)
        if code == 404:
            continue
        if code == 413:
            return {"status": "TRUNCATED", "path": path}
        if code != 200:
            return {"status": _status(code)}
        return {"status": "OBSERVED", "path": path, "text": body.decode("utf-8", "replace")}
    return {"status": "NO_CODEOWNERS"}


def _last_commit(reader, repository, path, ref):
    code, rows = reader.get(f"/repos/{repository}/commits", {"path": path, "per_page": 1, **({"sha": ref} if ref else {})})
    if code != 200:
        return {"status": _status(code)}
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        return {"status": "NOT_FOUND_OR_NOT_VISIBLE"}
    row = rows[0]
    commit = row.get("commit") if isinstance(row.get("commit"), dict) else {}
    author = commit.get("author") if isinstance(commit.get("author"), dict) else {}
    account = row.get("author") if isinstance(row.get("author"), dict) else {}
    return {"status": "OBSERVED", "name": author.get("name"), "email": author.get("email"), "login": account.get("login"),
            "at": author.get("date"), "commit": row.get("sha") if isinstance(row.get("sha"), str) else None}


def _role(row):
    if row.get("role_name") in _ROLES:
        return row["role_name"]
    permissions = row.get("permissions") if isinstance(row.get("permissions"), dict) else {}
    return next((name for name in ("admin", "maintain", "push", "triage", "pull") if permissions.get(name) is True), None)


def _audience(reader, repository):
    code, body = reader.get(f"/repos/{repository}")
    visibility = body.get("visibility") if code == 200 and isinstance(body, dict) else None
    if visibility not in ("public", "internal", "private"):
        return {"visibility": "UNKNOWN", "limitations": ["VISIBILITY_UNAVAILABLE"]}
    limitation = {"public": "PUBLIC_ACCESS_NOT_ENUMERATED", "internal": "INTERNAL_ACCESS_NOT_ENUMERATED"}.get(visibility)
    return {"visibility": visibility.upper(), "limitations": [limitation] if limitation else []}


def _collaborators(reader, repository, *, start_page=1):
    if isinstance(start_page, bool) or not isinstance(start_page, int) or not 1 <= start_page <= MAX_MEMBER_PAGE:
        raise ValueError("INVALID_MEMBER_PAGE")
    result = {"basis": "GITHUB_REPOSITORY_COLLABORATORS", "evidence_kind": "PROVIDER_COLLABORATORS",
              **_audience(reader, repository)}
    people, seen, malformed = [], set(), False
    for page in range(start_page, min(start_page + MAX_MEMBER_PAGES, MAX_MEMBER_PAGE + 1)):
        if page > 1 and "PAGED_LIST_NOT_ATOMIC" not in result["limitations"]:
            result["limitations"].append("PAGED_LIST_NOT_ATOMIC")
        code, rows = reader.get(f"/repos/{repository}/collaborators", {"affiliation": "all", "per_page": 100, "page": page})
        if code != 200 or not isinstance(rows, list):
            result["limitations"].append("MEMBER_PAGE_UNAVAILABLE")
            return {**result, "status": _status(code) if code != 200 else "UNAVAILABLE", "truncated": True,
                    **({"people": people} if people else {})}
        malformed = malformed or len(rows) > 100
        for row in rows[:100]:
            if (not isinstance(row, dict) or not isinstance(row.get("login"), str)
                    or not 0 < len(row["login"]) <= 128):
                malformed = True
                continue
            login, role = row["login"], _role(row)
            if login.casefold() in seen:
                continue
            seen.add(login.casefold())
            people.append({"login": login, "role": role,
                           "principal_kind": {"User": "USER", "Bot": "SERVICE_PRINCIPAL"}.get(row.get("type"), "UNKNOWN")
                           if isinstance(row.get("type"), str) else "UNKNOWN",
                           "read_access": "REPORTED" if role else "UNKNOWN"})
        if malformed and "MALFORMED_MEMBER_ROWS" not in result["limitations"]:
            result["limitations"].append("MALFORMED_MEMBER_ROWS")
        if len(rows) < 100:
            return {**result, "status": "OBSERVED", "people": people, "truncated": malformed}
    result["limitations"].append("MEMBER_PAGE_LIMIT")
    return {**result, "status": "OBSERVED", "people": people, "truncated": True,
            "next_page": page + 1 if page < MAX_MEMBER_PAGE else None}


def read(payload, location, *, http_client, members=True, member_page=1) -> dict:
    """``{codeowners, author[, members]}`` for one exposed ``location`` ({repository, path, commit})."""
    repository, path = location.get("repository") or "", location.get("path") or ""
    if not _REPOSITORY.fullmatch(repository) or not path:
        return {"codeowners": {"status": "UNSUPPORTED"}, "author": {"status": "UNSUPPORTED"}}
    ref = location.get("commit") if _SHA.fullmatch(str(location.get("commit") or "")) else ""
    reader = _Reader(payload, http_client)
    out = {} if member_page > 1 else {
        "codeowners": _codeowners(reader, repository, ref), "author": _last_commit(reader, repository, path, ref)}
    if members:
        out["members"] = _collaborators(reader, repository, start_page=member_page)
    return out
