"""What changed in a GitLab project since a commit (change feed, cremore.scanning.changes).

The ref's head is one request. When it moved, the merge base of the old and new heads
says whether history was only extended (the base is the old head) or rewritten; a
missing old commit is rewritten too. The compare API names the changed files; a
compare that timed out, or one at GitLab's diff limit, is read as "unknown" and the
scan lists the tree, skipping blobs the detection cache already knows by id.
[Repositories API](https://docs.gitlab.com/api/repositories/#compare-branches-tags-or-commits),
[merge base](https://docs.gitlab.com/api/repositories/#merge-base)
"""

from __future__ import annotations

import re
from urllib.parse import quote

from cremore.collectors.base import NO_WAIT, CollectorError
from cremore.collectors.changes import Changes, pushed, reread
from cremore_gitlab_provider.content import SourceHTTP

_SHA = re.compile(r"[0-9a-f]{40,64}")
DIFF_LIMIT = 1000


def _missing(exc):
    # With two refs, GitLab's merge_base uses 400 for unknown refs; ContentHTTP keeps only the status.
    return exc.code == "SOURCE_HTTP_FAILED" and exc.detail in ("400", "404")


def changes_since(payload, root, cursor, *, http_client, request_budget):
    http = SourceHTTP(payload, http_client(), budget=request_budget)
    http.pacer = NO_WAIT  # polled on the worker's control loop: a rate limit or a busy server ends the look at once
    route = "/projects/" + quote(root["provider_resource_id"], safe="")
    commit, _ = http.get(route + "/repository/commits/" + quote(root.get("ref") or "HEAD", safe=""))
    head = commit.get("id") if isinstance(commit, dict) else None
    if not isinstance(head, str) or not _SHA.fullmatch(head):
        raise CollectorError("GITLAB_COMMIT_MALFORMED")
    if not cursor or cursor == head:
        return Changes(head=head)
    try:
        base, _ = http.get(route + "/repository/merge_base", params=[("refs[]", cursor), ("refs[]", head)])
    except CollectorError as exc:
        if _missing(exc):
            return Changes(head=head, paths=None, rewritten=True, reason="GITLAB_BASE_COMMIT_MISSING")
        raise
    if not isinstance(base, dict) or base.get("id") != cursor:
        return Changes(head=head, paths=None, rewritten=True, reason="GITLAB_HISTORY_REWRITTEN")
    compare, _ = http.get(route + "/repository/compare", params={"from": cursor, "to": head, "straight": "true"})
    if not isinstance(compare, dict) or not isinstance(compare.get("diffs"), list):
        raise CollectorError("GITLAB_COMPARE_MALFORMED")
    if compare.get("compare_timeout") is True:
        return Changes(head=head, paths=None, reason="GITLAB_COMPARE_TIMEOUT")
    if len(compare["diffs"]) >= DIFF_LIMIT:
        return Changes(head=head, paths=None, reason="GITLAB_COMPARE_DIFF_LIMIT")
    paths, removals = [], False
    for diff in compare["diffs"]:
        if not isinstance(diff, dict) or not isinstance(diff.get("new_path"), str):
            raise CollectorError("GITLAB_COMPARE_MALFORMED")
        paths.append(diff["new_path"])
        if diff.get("deleted_file") is True or diff.get("renamed_file") is True:
            removals = True
            if isinstance(diff.get("old_path"), str):
                paths.append(diff["old_path"])
    return Changes(head=head, paths=paths, removals=removals)


def queue_changes(body, attributes, roots):
    """A push webhook a customer relays to their queue (cremore.scanning.triggers).

    GitLab lists at most 20 commits in a push and does not mark a force push, so the push
    only says which project and branch moved; the change feed's merge base finds a rewrite.
    [Push events](https://docs.gitlab.com/user/project/integrations/webhook_events/#push-events)
    """
    if not (isinstance(body, dict) and isinstance(body.get("object_kind"), str) and isinstance(body.get("project"), dict)):
        return None
    project = str(body.get("project_id") or body["project"].get("id") or "")
    root = next((r for r in roots if r["provider_resource_id"] == project), None)
    if root is None:
        raise CollectorError("EVENT_OUT_OF_SCOPE")
    if body["object_kind"] == "tag_push":
        return {}
    if body["object_kind"] != "push":
        raise CollectorError("EVENT_UNSUPPORTED_NOTIFICATION")
    after = body.get("after")
    if not isinstance(after, str) or set(after) == {"0"} or not pushed(root, body.get("ref"), body["project"].get("default_branch")):
        return {}  # a deleted branch or another branch
    return reread(root, after, reason="GITLAB_PUSH")
