"""What changed in an Azure DevOps Git repository since a commit, or in a TFVC project since a changeset (change feed).

Git: the branch head comes from the exact ref. The commit diff (``diffs/commits`` between
the two commit ids) names the merge base (``commonCommit``) and how far the old head is
behind: an old head that is not the merge base, or one the new head no longer contains,
is rewritten history; a missing old commit is too. Folder entries only say a folder
changed and are skipped; a diff that says it left changes out, or a very long one, is
read as "unknown" and the scan lists the tree, skipping blobs the cache knows by id.

TFVC: the cursor is the newest changeset id under ``$/{project}``. The changesets after
it (newest first, at most MAX_CHANGESETS) and each one's changes name the files under the
project root; a rename's source path comes with it, and a delete or rename is a removal,
as in Git. More changesets or changes than the bounds, a folder renamed, deleted or
branched (its files are not listed one by one), or a path whose case would decide the
approved scope differently, reads the whole root (the cache skips items it knows by
changeset).
[Diffs - Get](https://learn.microsoft.com/en-us/rest/api/azure/devops/git/diffs/get?view=azure-devops-rest-7.1),
[Changesets - Get Changesets](https://learn.microsoft.com/en-us/rest/api/azure/devops/tfvc/changesets/get-changesets?view=azure-devops-rest-7.1),
[Changesets - Get Changeset Changes](https://learn.microsoft.com/en-us/rest/api/azure/devops/tfvc/changesets/get-changeset-changes?view=azure-devops-rest-7.1)
"""

from __future__ import annotations

import re
from urllib.parse import quote, urlsplit

from cremore.collectors.base import NO_WAIT, CollectorError, path_under
from cremore.collectors.changes import Changes, pushed, reread
from cremore.sources.validation import path

from .devops_content import TFVC_ROOT, SourceHTTP, branch_ref

_SHA = re.compile(r"[a-f0-9]{40}")
PAGE = 100
CHANGE_LIMIT = 2000
# With CHANGE_LIMIT, a TFVC look costs at most 1 + 30 + 20 requests, inside the feed's 60 per root.
MAX_CHANGESETS = 30
# Folder changes that leave its files as they are; any other folder change hides which files moved.
_FOLDER_SAFE = frozenset({"add", "encoding", "lock", "property", "none"})


def changes_since(payload, root, cursor, *, http_client, request_budget):
    organization, project, repository = root["provider_resource_id"].split("/", 2)
    http = SourceHTTP({**payload, "organization": organization}, http_client(), budget=request_budget)
    http.pacer = NO_WAIT  # polled on the worker's control loop: a rate limit or a busy server ends the look at once
    if repository == TFVC_ROOT:
        return _tfvc(http, project, root, cursor)
    route = http.repositories(project) + "/" + quote(repository, safe="")
    api = http.api
    selected_ref, default = root.get("ref"), None
    if selected_ref in (None, "", "HEAD"):
        metadata, _ = http.get(route, params=api)
        default = metadata.get("defaultBranch")
    selected_ref = branch_ref(selected_ref, default)
    refs, _ = http.get(route + "/refs", params={**api, "filter": selected_ref.removeprefix("refs/")})
    head = next((row.get("objectId") for row in (refs.get("value") or [])
                 if isinstance(row, dict) and row.get("name") == selected_ref), None)
    if not isinstance(head, str) or not _SHA.fullmatch(head):
        raise CollectorError("AZURE_DEVOPS_COMMIT_MALFORMED")
    if not cursor or cursor == head:
        return Changes(head=head)
    paths, removals, skip = [], False, 0
    while True:
        try:
            diff, _ = http.get(route + "/diffs/commits", params={
                **api, "baseVersion": cursor, "baseVersionType": "commit", "targetVersion": head,
                "targetVersionType": "commit", "$top": PAGE, "$skip": skip})
        except CollectorError as exc:
            if exc.code == "SOURCE_HTTP_FAILED" and exc.detail in ("400", "404"):
                return Changes(head=head, paths=None, rewritten=True, reason="AZURE_DEVOPS_BASE_COMMIT_MISSING")
            raise
        if not isinstance(diff, dict) or not isinstance(diff.get("changes"), list):
            raise CollectorError("AZURE_DEVOPS_DIFF_MALFORMED")
        if skip == 0 and (diff.get("commonCommit") != cursor or int(diff.get("behindCount") or 0) > 0):
            return Changes(head=head, paths=None, rewritten=True, reason="AZURE_DEVOPS_HISTORY_REWRITTEN")
        for change in diff["changes"]:
            item = change.get("item") if isinstance(change, dict) else None
            if not isinstance(item, dict):
                raise CollectorError("AZURE_DEVOPS_DIFF_MALFORMED")
            if item.get("isFolder") or item.get("gitObjectType") == "tree":
                continue
            paths.append(path(str(item.get("path", ""))))
            kind = str(change.get("changeType") or "")
            if "delete" in kind or "rename" in kind:
                removals = True
                if isinstance(change.get("originalPath"), str):
                    paths.append(path(change["originalPath"]))
        if len(paths) >= CHANGE_LIMIT:
            return Changes(head=head, paths=None, reason="AZURE_DEVOPS_DIFF_LIMIT")
        if len(diff["changes"]) < PAGE:
            if diff.get("allChangesIncluded") is False:
                return Changes(head=head, paths=None, reason="AZURE_DEVOPS_DIFF_INCOMPLETE")
            return Changes(head=head, paths=paths, removals=removals)
        skip += PAGE


def _changesets(http, project, params):
    """Changeset ids under the project's TFVC root, newest first."""
    body, _ = http.get(http.tfvc(project) + "/changesets", params={
        **http.api, "searchCriteria.itemPath": "$/" + project, "$orderby": "id desc", **params})
    rows = body.get("value") if isinstance(body, dict) else None
    ids = [row.get("changesetId") if isinstance(row, dict) else None for row in rows or []]
    if not isinstance(rows, list) or any(type(ident) is not int or ident <= 0 for ident in ids):
        raise CollectorError("AZURE_DEVOPS_CHANGESETS_MALFORMED")
    return ids


def _tfvc(http, project, root, cursor):
    if not cursor:
        latest = _changesets(http, project, {"$top": 1})
        if not latest:
            raise CollectorError("AZURE_DEVOPS_CHANGESET_UNAVAILABLE")
        return Changes(head=str(latest[0]))
    if not cursor.isdigit() or not 0 < int(cursor) < 1 << 31:
        latest = _changesets(http, project, {"$top": 1})
        if not latest:
            raise CollectorError("AZURE_DEVOPS_CHANGESET_UNAVAILABLE")
        return Changes(head=str(latest[0]), paths=None, reason="AZURE_DEVOPS_TFVC_CURSOR_INVALID")
    since = int(cursor)
    # fromId may include the cursor's own changeset; reaching it (or fewer rows) means none was left out.
    rows = _changesets(http, project, {"searchCriteria.fromId": since, "$top": MAX_CHANGESETS + 1})
    newer = [ident for ident in rows if ident > since]
    if not newer:
        return Changes(head=cursor)
    head = str(max(newer))
    if len(rows) > MAX_CHANGESETS and min(rows) > since:
        return Changes(head=head, paths=None, reason="AZURE_DEVOPS_TFVC_CHANGESET_LIMIT")
    top = "$/" + project
    paths, removals, counted = [], False, 0
    for ident in sorted(newer):
        skip = 0
        while True:
            body, _ = http.get(f"/_apis/tfvc/changesets/{ident}/changes", params={**http.api, "$top": PAGE, "$skip": skip})
            changes = body.get("value") if isinstance(body, dict) else None
            if not isinstance(changes, list):
                raise CollectorError("AZURE_DEVOPS_CHANGES_MALFORMED")
            counted += len(changes)
            for change in changes:
                item = change.get("item") if isinstance(change, dict) else None
                if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                    raise CollectorError("AZURE_DEVOPS_CHANGES_MALFORMED")
                kinds = {kind.strip() for kind in str(change.get("changeType") or "").lower().split(",") if kind.strip()}
                sources = [source.get("serverItem") for source in change.get("mergeSources") or []
                           if isinstance(source, dict) and source.get("isRename") and isinstance(source.get("serverItem"), str)]
                for name in [item["path"], *sources]:
                    inside = name.lower().startswith(top.lower() + "/")
                    if not inside and name.lower() != top.lower():
                        continue  # another project's path in the same changeset
                    if item.get("isFolder") or not inside:
                        if kinds <= _FOLDER_SAFE:
                            continue
                        return Changes(head=head, paths=None, reason="AZURE_DEVOPS_TFVC_FOLDER_CHANGE")
                    try:
                        paths.append(path(name[len(top) + 1:]))
                    except ValueError:
                        raise CollectorError("AZURE_DEVOPS_CHANGES_MALFORMED") from None
                if kinds & {"delete", "rename", "sourcerename"}:
                    removals = True
            if counted >= CHANGE_LIMIT or len(paths) >= CHANGE_LIMIT:
                return Changes(head=head, paths=None, reason="AZURE_DEVOPS_TFVC_CHANGE_LIMIT")
            if len(changes) < PAGE:
                break
            skip += PAGE
    paths = list(dict.fromkeys(paths))
    if not _case_safe(root, paths):
        return Changes(head=head, paths=None, reason="AZURE_DEVOPS_TFVC_PATH_CASE")
    return Changes(head=head, paths=paths, removals=removals)


def _case_safe(root, paths):
    """Whether the feed's exact path rules decide every path as TFVC's case-insensitive scan does."""
    rules = [rule for key in ("paths", "excluded_paths") for rule in root.get(key) or []]
    return all(path_under(value, [rule]) == path_under(value.lower(), [rule.lower()]) for value in paths for rule in rules)


def _organization(url):
    parts = urlsplit(url or "")
    host = (parts.hostname or "").lower()
    if host == "dev.azure.com":
        return (parts.path.split("/") + ["", ""])[1] or None
    return host.removesuffix(".visualstudio.com") if host.endswith(".visualstudio.com") else None


def queue_changes(body, attributes, roots):
    """A ``git.push`` service hook delivered to the customer's Service Bus queue
    (cremore.scanning.triggers); it says which repository and branch moved.
    [Service hook events](https://learn.microsoft.com/en-us/azure/devops/service-hooks/events?view=azure-devops#git.push)
    """
    if not (isinstance(body, dict) and body.get("publisherId") == "tfs" and isinstance(body.get("resource"), dict)):
        return None
    if body.get("eventType") != "git.push":
        raise CollectorError("EVENT_UNSUPPORTED_NOTIFICATION")
    repository = body["resource"].get("repository") or {}
    project, name = (repository.get("project") or {}).get("name"), repository.get("name")
    organization = _organization(repository.get("remoteUrl") or repository.get("url"))
    if not isinstance(project, str) or not isinstance(name, str):
        raise CollectorError("EVENT_INVALID_PAYLOAD")

    def same(root):
        org, root_project, root_name = root["provider_resource_id"].split("/", 2)
        return (root["resource_type"] == "AZURE_DEVOPS_REPOSITORY" and root_project.lower() == project.lower()
                and root_name.lower() == name.lower() and (organization is None or org.lower() == organization.lower()))

    root = next((r for r in roots if same(r)), None)
    if root is None:
        raise CollectorError("EVENT_OUT_OF_SCOPE")
    moved = [update for update in body["resource"].get("refUpdates") or [] if isinstance(update, dict)
             and set(update.get("newObjectId") or "0") != {"0"}
             and pushed(root, update.get("name"), repository.get("defaultBranch"))]
    if not moved:
        return {}
    return reread(root, moved[-1].get("newObjectId"), reason="AZURE_DEVOPS_PUSH")
