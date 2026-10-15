"""bitbucket content API operations; shared lifecycle stays in the platform.

Bitbucket lists no blob ids, so a file's revision is a commit whose content it has:
the head a run reads, or -- on a DELTA run after a complete one -- the revision the
file already had, when the diff from the commit that run read to the head
(bitbucket_changes.diff) positively leaves the file out. The detection cache then
answers for it without a download. The run keeps ``provider_state`` = ``{"commit": the
head it read, "base": the commit of the last full read, "revisions": {commit: [paths]}}``
for the files whose revision is not ``base``. BASELINE and RECONCILE runs read every
file at the head and start a new base, so a diff that dropped a file without saying so
(Data Center's page.max.changes) is healed by the next full scan. A missing or damaged
state, a diff that is cut short, over its page bound or unreadable, rewritten history,
or a state too large to keep also reads every file at the head. The listing is complete
either way, so exposure retirement still sees every file.
"""
from __future__ import annotations

import base64
import json
import re
from collections import deque
from urllib.parse import parse_qs, quote, urlsplit

from cremore.collectors.base import CollectorError, run_stop
from cremore.collectors.content import ContentCollector, ContentHTTP, build_roots

# The pure helper, not the cremore.source_config compatibility module: that one
# imports the content registry and with it every provider's source module.
from cremore.sources.validation import path

_COMMIT = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})")
# A state larger than this reads every file instead (the worker keeps at most 64 KiB).
STATE_BYTES = 48 << 10


class SourceHTTP(ContentHTTP):
    def __init__(self, payload, client, **kwargs):
        super().__init__(payload, client, **kwargs)
        self.base = payload["base_url"] + ("/2.0" if payload["edition"] == "cloud" else "/rest/api/1.0")

    def authorization(self, token):
        if self.payload.get("auth_type") == "api_token":
            return "Basic " + base64.b64encode((self.payload["username"] + ":" + token).encode()).decode()
        return super().authorization(token)

    def bitbucket_pages(self, route, params=None):
        cloud = self.payload["edition"] == "cloud"
        cursor, seen = "1" if cloud else 0, set()
        while True:
            paging = {"page": cursor, "pagelen": 100} if cloud else {"start": cursor, "limit": 100}
            body, _ = self.get(route, params={**(params or {}), **paging})
            if not isinstance(body, dict) or not isinstance(body.get("values"), list):
                raise CollectorError("SOURCE_LIST_MALFORMED")
            yield from body["values"]
            if cloud:
                if not body.get("next"):
                    return
                # Only copy the cursor onto our pinned route, never the URL or credentials.
                cursor = (parse_qs(urlsplit(body["next"]).query).get("page") or [None])[0]
            else:
                if body.get("isLastPage") is True:
                    return
                cursor = body.get("nextPageStart")
                if type(cursor) is not int or cursor < 0:
                    raise CollectorError("SOURCE_PAGINATION_INCOMPLETE")
            if cursor is None or str(cursor) in seen:
                raise CollectorError("SOURCE_PAGINATION_LOOP")
            seen.add(str(cursor))


def roots(payload, client, budget=None):
    """Discovery does not approve content reads."""
    http = SourceHTTP(payload, client, budget=budget)
    cloud = payload["edition"] == "cloud"
    owner = payload["workspace" if cloud else "project"]
    route = "/repositories/" + quote(owner, safe="") if cloud else "/projects/" + quote(owner, safe="") + "/repos"
    if payload.get("repo"):
        row, _ = http.get(route + "/" + quote(payload["repo"], safe=""))
        rows = [row]
    else:
        rows = http.bitbucket_pages(route)
    for row in rows:
        slug = row.get("slug", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", slug) or slug in (".", ".."):
            raise CollectorError("BITBUCKET_REPOSITORY_MALFORMED")
        yield "BITBUCKET_REPOSITORY", owner + "/" + slug, owner + "/" + slug


class Collector(ContentCollector):
    PROVIDER = "bitbucket"
    ROOT_FIELD = "repo"
    HTTP = SourceHTTP

    def resource_metadata(self):
        return {"source_instance": self.p["base_url"], "bitbucket_edition": self.p["edition"]}

    @classmethod
    def root_payload(cls, payload, identifier):
        return {**payload, cls.ROOT_FIELD: identifier.split("/", 1)[1]}

    def objects(self):
        cloud = self.p["edition"] == "cloud"
        owner, repo = self.p["workspace" if cloud else "project"], self.p["repo"]
        resource = owner + "/" + repo
        route = "/repositories/" + quote(owner, safe="") + "/" + quote(repo, safe="") if cloud else "/projects/" + quote(owner, safe="") + "/repos/" + quote(repo, safe="")
        ref = self.p.get("ref", "HEAD")
        if ref == "HEAD":
            metadata, _ = self.http.get(route if cloud else route + "/branches/default")
            ref = (metadata.get("mainbranch") or {}).get("name") if cloud else metadata.get("latestCommit")
            if not ref:
                raise CollectorError("BITBUCKET_DEFAULT_REF_UNAVAILABLE")
        commit, _ = self.http.get(route + ("/commit/" if cloud else "/commits/") + quote(ref, safe=""))
        revision = commit.get("hash" if cloud else "id", "")
        if not _COMMIT.fullmatch(revision):
            raise CollectorError("BITBUCKET_COMMIT_MALFORMED")
        carried = self._carried(route, revision)
        base, kept = carried if carried is not None else (revision, {})
        files = []  # every file at the head, selected or not: the state names only files that still exist

        def kept_revision(key):
            # A Data Center path the diff would name differently is read at the head.
            return kept.get(key, base) if carried is not None and key == key.strip("/") else revision

        if cloud:
            pending, seen = deque([""]), {""}
            while pending:
                directory = pending.popleft()
                for item in self.http.bitbucket_pages(route + "/src/" + revision + "/" + quote(directory, safe="/")):
                    if self._unreadable(item["path"]):
                        continue
                    key = path(item["path"])
                    if key in seen or not key or directory and not key.startswith(directory + "/"):
                        raise CollectorError("BITBUCKET_TREE_MALFORMED")
                    if len(seen) > self.max_objects:
                        raise CollectorError("SOURCE_OBJECT_LIMIT")
                    seen.add(key)
                    if item.get("type") == "commit_directory":
                        pending.append(key)
                    elif item.get("type") == "commit_file":
                        files.append(key)
                        if self.selected(key):
                            yield self.object(resource, key, revision, lambda key=key: self.http.get(route + "/src/" + revision + "/" + quote(key, safe="/"), raw=True), revision=kept_revision(key))
        else:
            for key in self.http.bitbucket_pages(route + "/files", {"at": revision}):
                if self._unreadable(key):
                    continue
                files.append(key)
                if self.selected(key):
                    yield self.object(resource, key, revision, lambda key=key: self.http.get(route + "/raw/" + quote(key, safe="/"), params={"at": revision}, raw=True), revision=kept_revision(key))
        present = set(files)
        revisions = {}
        for key, commit in kept.items():
            if commit != base and key in present:
                revisions.setdefault(commit, []).append(key)
        # Saved by the worker only after a complete run of the whole root.
        self.provider_state = {"commit": revision, "base": base,
                               **({"revisions": {c: sorted(keys) for c, keys in revisions.items()}} if revisions else {})}

    def _unreadable(self, key):
        """A git file name the scan cannot address (a backslash, a control character, over 1024 characters):
        counted as an object not read, so the repository's other files are still scanned."""
        try:
            path(key)
        except ValueError:
            if not isinstance(key, str):
                raise CollectorError("BITBUCKET_TREE_MALFORMED") from None
            self.failed_objects += 1
            return True
        return False

    def _carried(self, route, head):
        """``(base, {path: revision})`` when files the diff leaves out keep their revision; None: read all at the head."""
        state = self.p.get("provider_state") or {}
        since, base, saved = state.get("commit"), state.get("base"), state.get("revisions") or {}
        # Only a DELTA trusts the chain of diffs; a full scan (BASELINE, RECONCILE) reads every file again.
        if (self.p.get("scan_mode") != "DELTA" or not isinstance(since, str)
                or not _COMMIT.fullmatch(since) or not isinstance(base, str) or not _COMMIT.fullmatch(base)
                or not isinstance(saved, dict)):
            return None
        kept = {}
        for commit, keys in saved.items():
            if not (isinstance(commit, str) and _COMMIT.fullmatch(commit) and isinstance(keys, list)
                    and all(isinstance(key, str) for key in keys)):
                return None
            kept.update(dict.fromkeys(keys, commit))
        if since != head:
            from cremore_atlassian_provider.bitbucket_changes import diff

            try:
                changes = diff(self.http, route, since, head, self.p)
            except Exception as exc:  # a diff that cannot be read reads every file instead
                if run_stop(exc):
                    raise
                return None
            if changes.rewritten or changes.paths is None:
                return None
            kept.update(dict.fromkeys(changes.paths, head))
        grouped = {}
        for key, commit in kept.items():
            grouped.setdefault(commit, []).append(key)
        if len(json.dumps({"commit": head, "base": base, "revisions": grouped})) > STATE_BYTES:
            return None
        return base, kept

    bitbucket = objects


def build(payload, client, **kwargs):
    return build_roots(Collector, roots, payload, client, **kwargs)
