"""What Azure DevOps says about an exposed file (cremore.governance.ownership): the last change to it.

Reads, with the content connection's own token and only in its organization and project, one entry at
the version the scan read: for Git the last commit that changed the path (GET .../_apis/git/repositories/
{repo}/commits?searchCriteria.itemPath=&searchCriteria.itemVersion.version=<commit>&searchCriteria.$top=1:
author name, email and date), for TFVC the last changeset at or before the scanned one (GET .../_apis/tfvc/
changesets?searchCriteria.itemPath=&searchCriteria.toId=&$top=1: author display and unique name). Azure
DevOps has no CODEOWNERS file. The Git repository's direct Read ACEs are listed separately; inherited
rights, groups, branch ACLs and effective permissions are not evaluated. Nothing is written.

Docs: https://learn.microsoft.com/rest/api/azure/devops/git/commits/get-commits,
https://learn.microsoft.com/rest/api/azure/devops/tfvc/changesets/get-changesets (scope vso.code)
"""

from __future__ import annotations

import re
from urllib.parse import quote

from cremore.collectors.base import CollectorError, RequestBudget
from cremore_azure_provider.devops_content import TFVC_ROOT, SourceHTTP, valid_name

_SHA = re.compile(r"[0-9a-f]{40}")
_CHANGESET = re.compile(r"[0-9]{1,12}")
_GUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_GIT_SECURITY_NAMESPACE = "52d39943-cb85-4d7f-8fa8-c6baac873819"


def _status(exc):
    return ("NOT_FOUND_OR_NOT_VISIBLE" if exc.detail == "404" else "FORBIDDEN" if exc.detail in ("401", "403")
            else "UNAVAILABLE")


def _git(http, project, repository, path, commit):
    body, _ = http.get(http.repositories(project) + "/" + quote(repository, safe="") + "/commits", params={
        **http.api, "searchCriteria.itemPath": "/" + path, "searchCriteria.itemVersion.version": commit,
        "searchCriteria.itemVersion.versionType": "commit", "searchCriteria.$top": 1})
    rows = body.get("value") if isinstance(body, dict) else None
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        return {"status": "NOT_FOUND_OR_NOT_VISIBLE"}
    author = rows[0].get("author") if isinstance(rows[0].get("author"), dict) else {}
    return {"status": "OBSERVED", "name": author.get("name"), "login": None, "email": author.get("email"),
            "at": author.get("date"), "commit": rows[0].get("commitId")}


def _tfvc(http, project, path, changeset):
    body, _ = http.get(http.tfvc(project) + "/changesets", params={
        **http.api, "searchCriteria.itemPath": "$/" + project + "/" + path, "searchCriteria.toId": changeset, "$top": 1})
    rows = body.get("value") if isinstance(body, dict) else None
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        return {"status": "NOT_FOUND_OR_NOT_VISIBLE"}
    author = rows[0].get("author") if isinstance(rows[0].get("author"), dict) else {}
    unique = author.get("uniqueName") if isinstance(author.get("uniqueName"), str) else ""
    return {"status": "OBSERVED", "name": author.get("displayName"), "login": unique or None,
            "email": unique if "@" in unique else None, "at": rows[0].get("createdDate"), "commit": None}


def _access(http, project, repository):
    result = {"basis": "AZURE_DEVOPS_REPOSITORY_ACL", "evidence_kind": "PROVIDER_GRANTS", "visibility": "UNKNOWN",
        "limitations": ["INHERITED_PERMISSIONS_NOT_EVALUATED", "GROUP_MEMBERS_NOT_EXPANDED",
        "GRANT_IS_NOT_EFFECTIVE_PERMISSION", "BRANCH_PERMISSIONS_NOT_EVALUATED"]}
    if repository == TFVC_ROOT:
        return {**result, "status": "UNSUPPORTED", "limitations": ["TFVC_PATH_ACL_NOT_SUPPORTED"]}
    try:
        metadata, _ = http.get(http.repositories(project) + "/" + quote(repository, safe=""), params=http.api)
        parent = metadata.get("project") if isinstance(metadata, dict) else None
        if (not isinstance(parent, dict) or not _GUID.fullmatch(str(parent.get("id") or ""))
                or not _GUID.fullmatch(str(metadata.get("id") or "")) or parent.get("name") != project
                or metadata.get("name") != repository):
            return {**result, "status": "UNAVAILABLE"}
        if parent.get("visibility") in ("public", "private"):
            result["visibility"] = parent["visibility"].upper()
        if result["visibility"] == "PUBLIC":
            result["limitations"].append("PUBLIC_ACCESS_NOT_ENUMERATED")
        token = f"repoV2/{parent['id']}/{metadata['id']}"
        body, _ = http.get(f"/_apis/accesscontrollists/{_GIT_SECURITY_NAMESPACE}", params={**http.api,
            "token": token, "includeExtendedInfo": "false", "recurse": "false"})
    except CollectorError as exc:
        return {**result, "status": _status(exc), "limitations": [*result["limitations"],
            "ACCESS_LIST_PERMISSION_REQUIRED" if exc.detail in ("401", "403") else "ACCESS_LIST_UNAVAILABLE"]}
    rows = body.get("value") if isinstance(body, dict) else None
    if not isinstance(rows, list):
        return {**result, "status": "UNAVAILABLE"}
    people, partial = [], len(rows) > 1
    for row in rows[:1]:
        if not isinstance(row, dict) or row.get("token") != token or not isinstance(row.get("acesDictionary"), dict):
            partial = True
            continue
        aces = row["acesDictionary"]
        partial |= len(aces) > 300
        for descriptor, ace in list(aces.items())[:300]:
            if (not isinstance(descriptor, str) or not 0 < len(descriptor) <= 256 or not isinstance(ace, dict)
                    or type(ace.get("allow")) is not int or type(ace.get("deny")) is not int
                    or ace["allow"] < 0 or ace["deny"] < 0):
                partial = True
                continue
            if not (ace["allow"] | ace["deny"]) & 2:
                continue
            people.append({"login": descriptor, "principal_id": descriptor, "principal_kind": "UNKNOWN",
                "name": None, "role": "deny_read" if ace["deny"] & 2 else "allow_read",
                "permission": "Git.Read", "effect": "DENY" if ace["deny"] & 2 else "ALLOW", "read_access": "UNKNOWN"})
    if partial:
        result["limitations"].append("ACCESS_LIST_PARTIAL")
    return {**result, "status": "OBSERVED", "people": people, "truncated": partial}


def read(payload, location, *, http_client, members=True) -> dict:
    """``{codeowners, author}`` for one exposed file ({repository: organization/project/repo, path, commit|version})."""
    parts = str(location.get("repository") or "").split("/")
    path = str(location.get("path") or "")
    out = {"codeowners": {"status": "UNSUPPORTED"}}
    # Only the connection's own organization and project.
    if (len(parts) != 3 or parts[0] != payload.get("organization") or parts[1] != payload.get("project") or not path
            or not (parts[2] == TFVC_ROOT or valid_name(parts[2]))):
        return {**out, "author": {"status": "UNSUPPORTED"}}
    tfvc = parts[2] == TFVC_ROOT
    commit, version = str(location.get("commit") or ""), str(location.get("version") or "")
    if not (_CHANGESET.fullmatch(version) if tfvc else _SHA.fullmatch(commit)):
        return {**out, "author": {"status": "UNSUPPORTED"}}
    limit = 4 if members else 2
    http = SourceHTTP({**payload, "max_requests": limit}, http_client, budget=RequestBudget(limit))
    try:
        author = _tfvc(http, parts[1], path, version) if tfvc else _git(http, parts[1], parts[2], path, commit)
    except CollectorError as exc:
        author = {"status": _status(exc)}
    return {**out, "author": author, **({"members": _access(http, parts[1], parts[2])} if members else {})}
