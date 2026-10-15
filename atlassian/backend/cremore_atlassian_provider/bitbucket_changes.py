"""What changed in a Bitbucket repository since a commit (change feed, design 4.3).

Bitbucket file listings carry no blob hash, so the change set comes from a diff of
the two commits and the scan reads exactly those files.

* Cloud: ``diffstat/{new}..{old}?topic=false`` (the new commit first, unlike git diff)
  pages through status/old/new path entries. HTTP 555 means the diff took too long.
  ``merge-base/{new}..{old}`` tells whether the old head is still an ancestor.
* Data Center: ``changes?since={old}&until={new}`` pages with ``isLastPage``; the
  server cuts the list at ``page.max.changes`` (default 1,000) without saying so.

The whole repository is read again when the old commit cannot be found (rewritten
history, read from scratch), when Cloud answers 555, when Data Center returns as many
entries as the configured limit or its pages do not reach the last one, when a diff
runs past MAX_DIFF_PAGES pages or names an entry without a path, or when a directory
entry appears (the files inside are unknown). An UNKNOWN change is read as a changed
file. A content scan reads the same diff (``diff``) to keep the cached results of the
files it does not name (bitbucket_content).
[Cloud 2.0 OpenAPI](https://dac-static.atlassian.com/cloud/bitbucket/swagger.v3.json),
[Data Center 10.4 OpenAPI](https://dac-static.atlassian.com/server/bitbucket/10.4.swagger.v3.json)
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, quote, urlsplit

from cremore.collectors.base import NO_WAIT, CollectorError
from cremore.collectors.changes import Changes, pushed, reread
from cremore.sources.validation import path

from .bitbucket_content import SourceHTTP

_SHA = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})")
DEFAULT_DC_LIMIT = 1000
PAGE = 500
MAX_DIFF_PAGES = 20


def _head(http, route, cloud, ref):
    if ref in ("", "HEAD"):
        metadata, _ = http.get(route if cloud else route + "/branches/default")
        ref = (metadata.get("mainbranch") or {}).get("name") if cloud else metadata.get("latestCommit")
        if not ref:
            raise CollectorError("BITBUCKET_DEFAULT_REF_UNAVAILABLE")
    commit, _ = http.get(route + ("/commit/" if cloud else "/commits/") + quote(ref.removeprefix("refs/heads/"), safe=""))
    head = commit.get("hash" if cloud else "id", "") if isinstance(commit, dict) else ""
    if not _SHA.fullmatch(head):
        raise CollectorError("BITBUCKET_COMMIT_MALFORMED")
    return head


def _missing(exc, *codes):
    return exc.code == "SOURCE_HTTP_FAILED" and exc.detail in codes


def changes_since(payload, root, cursor, *, http_client, request_budget):
    cloud = payload["edition"] == "cloud"
    owner, repo = root["provider_resource_id"].split("/", 1)
    http = SourceHTTP(payload, http_client(), budget=request_budget)
    http.pacer = NO_WAIT  # polled on the worker's control loop: a rate limit or a busy server ends the look at once
    route = ("/repositories/" if cloud else "/projects/") + quote(owner, safe="") + ("/" if cloud else "/repos/") \
        + quote(repo, safe="")
    head = _head(http, route, cloud, root.get("ref") or "HEAD")
    if not cursor or cursor == head:
        return Changes(head=head)
    return diff(http, route, cursor, head, payload)


def diff(http, route, cursor, head, payload):
    """The files changed between commit ``cursor`` and ``head``, or ``paths=None`` when that is not known."""
    return _cloud(http, route, cursor, head) if payload["edition"] == "cloud" else _data_center(
        http, route, cursor, head, payload)


def _cloud(http, route, cursor, head):
    try:
        base, _ = http.get(route + "/merge-base/" + head + ".." + cursor)
    except CollectorError as exc:
        if _missing(exc, "404"):
            return Changes(head=head, paths=None, rewritten=True, reason="BITBUCKET_BASE_COMMIT_MISSING")
        raise
    if not isinstance(base, dict) or base.get("hash") != cursor:
        return Changes(head=head, paths=None, rewritten=True, reason="BITBUCKET_HISTORY_REWRITTEN")
    paths, removals, page, seen = [], False, "1", set()
    while True:
        if len(seen) >= MAX_DIFF_PAGES:
            return Changes(head=head, paths=None, reason="BITBUCKET_DIFF_LIMIT")
        try:
            body, _ = http.get(route + "/diffstat/" + head + ".." + cursor,
                               params={"topic": "false", "pagelen": PAGE, "page": page})
        except CollectorError as exc:
            if _missing(exc, "555"):
                return Changes(head=head, paths=None, reason="BITBUCKET_DIFF_TIMEOUT")
            if _missing(exc, "404"):
                return Changes(head=head, paths=None, rewritten=True, reason="BITBUCKET_BASE_COMMIT_MISSING")
            raise
        if not isinstance(body, dict) or not isinstance(body.get("values"), list):
            raise CollectorError("BITBUCKET_DIFFSTAT_MALFORMED")
        for entry in body["values"]:
            if not isinstance(entry, dict):
                raise CollectorError("BITBUCKET_DIFFSTAT_MALFORMED")
            named = [entry[side]["path"] for side in ("new", "old")
                     if isinstance(entry.get(side), dict) and isinstance(entry[side].get("path"), str)]
            if not named:
                return Changes(head=head, paths=None, reason="BITBUCKET_DIFFSTAT_INCOMPLETE")
            if not _addressable(named):
                return Changes(head=head, paths=None, reason="BITBUCKET_PATH_UNSUPPORTED")
            paths.extend(path(name) for name in named)
            if entry.get("status") in ("removed", "renamed"):
                removals = True
        following = body.get("next")
        if not following:
            return Changes(head=head, paths=list(dict.fromkeys(paths)), removals=removals)
        page = (parse_qs(urlsplit(following).query).get("page") or [None])[0]
        if page is None or page in seen:
            raise CollectorError("SOURCE_PAGINATION_LOOP")
        seen.add(page)


def _data_center(http, route, cursor, head, payload):
    limit = int(payload.get("max_changes") or DEFAULT_DC_LIMIT)
    paths, removals, start, received = [], False, 0, 0
    for _page in range(MAX_DIFF_PAGES):
        try:
            body, _ = http.get(route + "/changes", params={"since": cursor, "until": head, "start": start,
                                                           "limit": min(PAGE, limit)})
        except CollectorError as exc:
            if _missing(exc, "404", "400"):
                return Changes(head=head, paths=None, rewritten=True, reason="BITBUCKET_BASE_COMMIT_MISSING")
            raise
        if not isinstance(body, dict) or not isinstance(body.get("values"), list):
            raise CollectorError("BITBUCKET_CHANGES_MALFORMED")
        for change in body["values"]:
            received += 1
            if not isinstance(change, dict):
                raise CollectorError("BITBUCKET_CHANGES_MALFORMED")
            if change.get("nodeType") == "DIRECTORY":
                return Changes(head=head, paths=None, reason="BITBUCKET_DIRECTORY_CHANGE")
            if change.get("nodeType") not in (None, "FILE"):
                continue  # a submodule pointer has no file content here
            named = [value["toString"] for value in (change.get("path"), change.get("srcPath"))
                     if isinstance(value, dict) and isinstance(value.get("toString"), str) and value["toString"]]
            if not named:
                return Changes(head=head, paths=None, reason="BITBUCKET_CHANGES_INCOMPLETE")
            if not _addressable(named):
                return Changes(head=head, paths=None, reason="BITBUCKET_PATH_UNSUPPORTED")
            paths.extend(path(text) for text in named)
            if change.get("type") in ("DELETE", "MOVE"):
                removals = True
        if received >= limit:
            return Changes(head=head, paths=None, reason="BITBUCKET_CHANGE_LIMIT_REACHED")
        if body.get("isLastPage") is True:
            return Changes(head=head, paths=list(dict.fromkeys(paths)), removals=removals)
        following = body.get("nextPageStart")
        if type(following) is not int or following <= start:
            return Changes(head=head, paths=None, reason="BITBUCKET_CHANGES_INCOMPLETE")
        start = following
    return Changes(head=head, paths=None, reason="BITBUCKET_DIFF_LIMIT")


def _addressable(names):
    """False for a git file name the scan cannot address (a backslash, a control character, over 1024
    characters): the root is read again, where the collector counts that file as not read."""
    try:
        for name in names:
            path(name)
    except ValueError:
        return False
    return True


def queue_changes(body, attributes, roots):
    """A push webhook a customer relays to their queue (cremore.scanning.triggers): Cloud
    ``repo:push`` (which marks a forced push) or Data Center ``repo:refs_changed``.
    [Cloud](https://support.atlassian.com/bitbucket-cloud/docs/event-payloads/#Push),
    [Data Center](https://confluence.atlassian.com/bitbucketserver/event-payload-938025882.html)
    """
    if not isinstance(body, dict) or not isinstance(body.get("repository"), dict):
        return None
    repository = body["repository"]
    if isinstance(body.get("push"), dict):
        name, updates = repository.get("full_name"), []  # (change, ref, new head)
        for change in body["push"].get("changes") or []:
            new = change.get("new") if isinstance(change, dict) else None  # None: the branch was deleted
            if isinstance(new, dict) and new.get("type") in ("branch", "named_branch") and isinstance(new.get("name"), str):
                updates.append((change, "refs/heads/" + new["name"], (new.get("target") or {}).get("hash")))
    elif body.get("eventKey") == "repo:refs_changed":
        name = f"{(repository.get('project') or {}).get('key')}/{repository.get('slug')}"
        updates = [(change, (change.get("ref") or {}).get("id") or change.get("refId"), change.get("toHash"))
                   for change in body.get("changes") or [] if isinstance(change, dict) and change.get("type") != "DELETE"]
    else:
        return None
    root = next((r for r in roots if isinstance(name, str) and r["provider_resource_id"].lower() == name.lower()), None)
    if root is None:
        raise CollectorError("EVENT_OUT_OF_SCOPE")
    moved = [(change, head) for change, ref, head in updates if pushed(root, ref)]
    if not moved:
        return {}
    return reread(root, moved[-1][1], rewritten=any(change.get("forced") for change, _head in moved),
                  reason="BITBUCKET_PUSH")
