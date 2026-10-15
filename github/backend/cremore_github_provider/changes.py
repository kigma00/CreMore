"""What changed in a GitHub repository since a commit (change feed, cremore.scanning.changes).

The branch head is one conditional request: the cursor is ``"<sha> <ETag>"`` (a plain
``"<sha>"`` from an older feed still works, without the condition), and a 304 answer
means the head did not move, which GitHub does not count against the rate limit and
which ends the look. When it moved, the compare API names the files that changed and
whether the old commit is still an ancestor: ``ahead`` is a fast-forward, ``diverged``
or ``behind`` is rewritten history, and a 404 means the old commit is gone (a force push
that was cleaned up). GitHub lists at most 300 files in a compare, so a list that long
is read as "unknown": the scan lists the tree and the detection cache skips every blob
whose SHA it has already scanned.

The feed is polled on the worker's control loop, so it never waits out a rate-limit
cooldown: it keeps the scans' pace (one slot at most), but while a cooldown holds the
credential back, or when its own request meets a rate limit (which still starts the
cooldown for every scan), the root's look fails with SOURCE_RATE_LIMITED at once, and a
busy server (502/503/504) fails it with SOURCE_UNAVAILABLE; the cursor stays and the
next poll asks again.
[Conditional requests](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#use-conditional-requests-if-appropriate),
[Compare two commits](https://docs.github.com/en/rest/commits/commits#compare-two-commits)
"""

from __future__ import annotations

import re
from urllib.parse import quote

from cremore.collectors.base import (
    RATE_LIMITED,
    UNAVAILABLE,
    CollectorError,
    NoWaitPacer,
    error_label,
    run_stop,
)
from cremore.collectors.changes import Changes, pushed, reread
from cremore.http_client import bounded_request
from cremore_github_provider.collectors.github import fetch_json, github_pacer
from cremore_github_provider.github_auth import resolve_github_token

_SHA = re.compile(r"[0-9a-f]{40}")
# An entity tag as GitHub sends it (weak or strong, quoted); anything else is not kept.
_ETAG = re.compile(r'(?:W/)?"[\x21\x23-\x7e]{1,200}"')
COMPARE_FILE_LIMIT = 300


def _headers(payload):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = resolve_github_token(payload.get("token", ""))
    if token:
        headers["Authorization"] = "Bearer " + token
    return headers


def _status(label):
    return int(label.split()[1]) if label.startswith("HTTP ") and label.split()[1].isdigit() else None


def _head(client, url, headers, etag, consume, pacer):
    """The head commit and its ETag; None when ``etag`` still names it (HTTP 304)."""
    try:
        response = bounded_request(client, "GET", url, headers={**headers, "If-None-Match": etag} if etag else headers,
                                   retry_429=True, before_attempt=consume, pacer=pacer)
    except Exception as exc:  # injected provider clients have different error types
        if run_stop(exc) or getattr(exc, "code", None) in (RATE_LIMITED, UNAVAILABLE):
            raise
        raise CollectorError("GITHUB_HEAD_UNAVAILABLE", error_label(exc)) from None
    status = getattr(response, "status_code", 200)
    if status == 304 and etag:
        return None, etag
    try:
        commit = response.json() if status == 200 else None
    except ValueError:
        commit = None
    head = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(head, str) or not _SHA.fullmatch(head):
        raise CollectorError("GITHUB_HEAD_UNAVAILABLE", f"HTTP {status}" if status != 200 else "INVALID_COMMIT")
    tag = (getattr(response, "headers", None) or {}).get("etag")
    return head, tag if isinstance(tag, str) and _ETAG.fullmatch(tag) else ""


def changes_since(payload, root, cursor, *, http_client, request_budget):
    owner, _, repo = root["provider_resource_id"].partition("/")
    base = (payload.get("base_url") or "https://api.github.com").rstrip("/") + "/repos/" + quote(owner, safe="") + "/" \
        + quote(repo, safe="")
    client, headers = http_client(), _headers(payload)
    # The scans' own pace for this credential, without waiting out a cooldown on the control loop.
    pacer = NoWaitPacer(github_pacer(base, payload.get("token", "")))

    def get(route):
        body, label = fetch_json(client, base + route, headers, before_attempt=request_budget.consume, pacer=pacer)
        return body, label

    # "<sha> <ETag>"; an older feed's cursor is the sha alone and asks without a condition.
    since, _, etag = (cursor or "").partition(" ")
    if not _SHA.fullmatch(since) or not _ETAG.fullmatch(etag):
        etag = ""
    branch = (root.get("ref") or "HEAD").removeprefix("refs/heads/")
    if branch == "HEAD":
        info, label = get("")
        if not isinstance(info, dict) or not isinstance(info.get("default_branch"), str):
            raise CollectorError("GITHUB_REPOSITORY_UNAVAILABLE", label)
        branch = info["default_branch"]
    head, tag = _head(client, base + "/commits/" + quote(branch, safe=""), headers, etag, request_budget.consume, pacer)
    if head is None:
        return Changes(head=cursor)  # 304: the head has not moved; nothing else is asked
    current = head + " " + tag if tag else head
    if not cursor or since == head:
        return Changes(head=current)
    compare, label = get("/compare/" + quote(since, safe="") + "..." + head)
    if compare is None:
        if _status(label) == 404:
            return Changes(head=current, paths=None, rewritten=True, reason="GITHUB_BASE_COMMIT_MISSING")
        raise CollectorError("GITHUB_COMPARE_UNAVAILABLE", label)
    if not isinstance(compare, dict) or compare.get("status") not in ("ahead", "identical", "diverged", "behind"):
        raise CollectorError("GITHUB_COMPARE_MALFORMED")
    if compare["status"] in ("diverged", "behind"):
        return Changes(head=current, paths=None, rewritten=True, reason="GITHUB_HISTORY_REWRITTEN")
    files = compare.get("files") or []
    if not isinstance(files, list):
        raise CollectorError("GITHUB_COMPARE_MALFORMED")
    if len(files) >= COMPARE_FILE_LIMIT:
        return Changes(head=current, paths=None, reason="GITHUB_COMPARE_FILE_LIMIT")
    paths, removals = [], False
    for item in files:
        name = item.get("filename") if isinstance(item, dict) else None
        if not isinstance(name, str) or not name:
            raise CollectorError("GITHUB_COMPARE_MALFORMED")
        paths.append(name)
        if item.get("status") in ("removed", "renamed"):
            removals = True
            if isinstance(item.get("previous_filename"), str) and item["previous_filename"]:
                paths.append(item["previous_filename"])
    return Changes(head=current, paths=paths, removals=removals)


def queue_changes(body, attributes, roots):
    """A push webhook a customer relays to their queue (cremore.scanning.triggers).

    A push lists at most 2,048 commits, so its file lists are not trusted: the push only
    says which repository and branch moved and whether it was forced.
    [push](https://docs.github.com/en/webhooks/webhook-events-and-payloads#push)
    """
    if not (isinstance(body, dict) and isinstance(body.get("repository"), dict) and "pusher" in body
            and isinstance(body.get("ref"), str) and "after" in body):
        return None
    name = body["repository"].get("full_name")
    root = next((r for r in roots if isinstance(name, str) and r["provider_resource_id"].lower() == name.lower()), None)
    if root is None:
        raise CollectorError("EVENT_OUT_OF_SCOPE")
    if body.get("deleted") or not pushed(root, body["ref"], body["repository"].get("default_branch")):
        return {}
    return reread(root, body.get("after"), rewritten=body.get("forced"), reason="GITHUB_PUSH")
