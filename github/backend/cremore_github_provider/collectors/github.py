"""GitHub repository collector.

Reads a repository's blobs through the GitHub REST API (git trees + blobs) and
yields them for scanning. The HTTP client is injected so the collector is
testable without network. Repository visibility (public/private) is read once
and recorded as the exposure level.

Docs: https://docs.github.com/en/rest/git/trees and .../git/blobs
"""

from __future__ import annotations

import base64
import binascii
import re
import threading
from collections import deque
from collections.abc import Callable, Iterator
from urllib.parse import quote, urlsplit

from cremore.collectors.base import (
    DEFAULT_MAX_OBJECT_BYTES,
    RATE_LIMITED,
    UNAVAILABLE,
    CollectedObject,
    CollectorError,
    RequestBudget,
    error_label,
    request_pacer,
    run_stop,
)
from cremore.collectors.base import (
    path_under as _under,  # compatibility alias for existing imports
)
from cremore.detection import ResourceRef
from cremore.http_client import DEFAULT_MAX_RESPONSE_BYTES, bounded_request
from cremore_github_provider.github_auth import GitHubToken, resolve_github_token

_API = "https://api.github.com"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MAX_TREE_ENTRIES = 200_000
_MAX_TREE_DEPTH = 128
# GitHub's secondary rate limits allow about 900 points a minute per REST endpoint (a GET is one)
# and 100 concurrent requests: ten requests a second per origin and credential keep a scan's
# eight readers below both, and the worker's pacing store holds every process to it.
REQUEST_INTERVAL = 0.1


def github_pacer(url: str, credential: GitHubToken):
    """The shared pacer of a GitHub origin and credential, keyed only by their digest: a GitHub App's
    installation (every token minted for it counts against the same limits), else the token itself."""
    parts = urlsplit(url)
    identity = getattr(credential, "pacing_identity", None)
    name = identity() if callable(identity) else "token:" + resolve_github_token(credential)
    return request_pacer(f"{parts.scheme}://{parts.netloc}", name, REQUEST_INTERVAL)


def _bearer(headers: dict) -> str:
    value = next((str(value) for name, value in headers.items() if str(name).lower() == "authorization"), "")
    return value.removeprefix("Bearer ")


def fetch_json(
    client,
    url: str,
    headers: dict,
    *,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    before_attempt: Callable[[], None] | None = None,
    credential: GitHubToken | None = None,
    pacer=None,
) -> tuple[object | None, str]:
    """(json, safe label). json is None on transport error, non-200 or bad JSON;
    the label names the failure (HTTP status or exception class) for reporting.
    A run stop (a spent budget, a cancelled or yielding run) raises: it ends the
    run, not one read. Requests are paced by ``credential`` (a token or an App
    token source; the Authorization header's token without it) and a secondary
    rate limit is waited out by every reader (bounded_request). ``pacer``
    replaces that pace: a change feed's NoWaitPacer raises RATE_LIMITED (or
    UNAVAILABLE for a busy server) instead of waiting out a cooldown or a retry."""

    try:
        resp = bounded_request(
            client, "GET", url, headers=headers, max_response_bytes=max_response_bytes,
            retry_429=True, before_attempt=before_attempt,
            pacer=pacer or github_pacer(url, _bearer(headers) if credential is None else credential),
        )
    except Exception as exc:  # injected provider clients have different error types
        if run_stop(exc) or getattr(exc, "code", None) in (RATE_LIMITED, UNAVAILABLE):
            raise
        return None, error_label(exc)
    status = getattr(resp, "status_code", 200)
    if status != 200:
        return None, f"HTTP {status}"
    try:
        return resp.json(), "OK"
    except Exception as exc:  # noqa: BLE001 -- report malformed provider JSON as incomplete coverage
        return None, error_label(exc)


_fetch_json = fetch_json  # compatibility for callers of the original helper


class GitHubCollector:
    # Lazy blob reads overlap on the scan's read-ahead threads (cremore.scanning.prefetch);
    # every counter a read touches changes under ``_lock``, and a read shares no other state.
    read_concurrency = 8
    counts_read_failures = True

    def __init__(
        self,
        client,
        owner: str,
        repo: str,
        *,
        ref: str = "HEAD",
        token: GitHubToken = "",
        max_object_bytes: int = DEFAULT_MAX_OBJECT_BYTES,
        base_url: str = _API,
        paths: list[str] | None = None,
        excluded_paths: list[str] | None = None,
        exact_paths: list[str] | None = None,
        request_budget: RequestBudget | None = None,
        use_archive: bool = False,
        lazy: bool = False,
    ) -> None:
        if max_object_bytes <= 0:
            raise ValueError("max_object_bytes must be positive")
        self.client = client
        self.owner = owner
        self.repo = repo
        # The trees API takes a branch name or SHA, not a full ref name.
        self.ref = ref.removeprefix("refs/heads/")
        self.token = token
        self.max_object_bytes = max_object_bytes
        self.request_budget = request_budget or RequestBudget()
        self.base_url = base_url.rstrip("/")
        from cremore_github_provider.github_hosts import host_from_api_base
        self.github_host = host_from_api_base(self.base_url)
        # Approved scope inside the tree: included path roots (a file or a
        # directory), excluded path roots (exclusions win), or exact paths only
        # (a rescan; a missing exact path counts as unreadable).
        self.paths = list(paths or [])
        self.excluded_paths = list(excluded_paths or [])
        self.exact_paths = set(exact_paths) if exact_paths is not None else None
        self.failed_objects = 0
        self.requests = 0
        self.use_archive = use_archive
        self.lazy = lazy
        self.commit_sha = ""
        self.skipped_submodules = 0
        self.authoritative_listing = False
        self.listing_complete = False
        self.listed_paths: set[str] = set()
        self.confirmed_missing_keys: set[str] = set()
        self._lock = threading.Lock()

    def _request(self) -> None:
        self.request_budget.consume()
        with self._lock:
            self.requests += 1

    def _failed(self, count: int = 1) -> None:
        with self._lock:
            self.failed_objects += count

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = resolve_github_token(self.token)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _get_json(self, path: str) -> tuple[dict | None, str]:
        limit = DEFAULT_MAX_RESPONSE_BYTES
        if "/git/blobs/" in path:
            _, wrapped = _base64_limits(self.max_object_bytes)
            limit = max(limit, wrapped + (64 << 10))
        data, label = fetch_json(
            self.client,
            self.base_url + path,
            self._headers(),
            max_response_bytes=limit,
            before_attempt=self._request,
            credential=self.token,
        )
        return (data if isinstance(data, dict) else None), label

    def _selected(self, path: str) -> bool:
        if self.excluded_paths and _under(path, self.excluded_paths):
            return False
        if self.paths and not _under(path, self.paths):
            return False
        return self.exact_paths is None or path in self.exact_paths

    def _tree_selected(self, path: str) -> bool:
        if self.excluded_paths and _under(path, self.excluded_paths):
            return False
        if self.exact_paths == set():
            return False
        roots = self.exact_paths if self.exact_paths is not None else self.paths
        return not roots or any(_under(path, [root]) or _under(root, [path]) for root in roots)

    def _entries(self) -> list[dict]:
        """Resolve the ref once; every listing and download uses that snapshot."""

        self.authoritative_listing = False
        self.listing_complete = False
        commit, label = self._get_json(
            f"/repos/{self.owner}/{self.repo}/commits/{quote(self.ref, safe='')}"
        )
        tree_sha = ((commit or {}).get("commit") or {}).get("tree", {}).get("sha", "")
        self.commit_sha = (commit or {}).get("sha", "")
        if not _SHA.fullmatch(str(self.commit_sha)) or not _SHA.fullmatch(str(tree_sha)):
            raise CollectorError("GITHUB_TREE_UNAVAILABLE", label if commit is None else "INVALID_COMMIT")
        path = f"/repos/{self.owner}/{self.repo}/git/trees/{tree_sha}"
        tree, label = self._get_json(path + "?recursive=1")
        if tree is None or not isinstance(tree.get("tree"), list):
            raise CollectorError("GITHUB_TREE_UNAVAILABLE", label)
        if not tree.get("truncated"):
            if len(tree["tree"]) > _MAX_TREE_ENTRIES:
                self._failed()
            else:
                self.authoritative_listing = not self.paths and not self.excluded_paths and self.exact_paths is None
                self.listing_complete = True
            return tree["tree"][:_MAX_TREE_ENTRIES]

        # A recursive response can repeatedly omit the same files. Enumerate
        # non-recursive subtrees instead, bounded by the shared request budget.
        entries: dict[str, dict] = {}
        pending = deque([(str(tree_sha), "", 0)])
        complete = True
        while pending:
            sha, prefix, depth = pending.popleft()
            if depth > _MAX_TREE_DEPTH:
                self._failed()
                complete = False
                continue
            subtree, _ = self._get_json(
                f"/repos/{self.owner}/{self.repo}/git/trees/{quote(sha, safe='')}"
            )
            if subtree is None or not isinstance(subtree.get("tree"), list):
                self._failed()
                complete = False
                continue
            if subtree.get("truncated"):
                self._failed()
                complete = False
            for entry in subtree["tree"]:
                relative = entry.get("path", "")
                if not isinstance(relative, str) or not relative or "/" in relative:
                    self._failed()
                    complete = False
                    continue
                full_path = prefix + relative
                if len(entries) + len(pending) >= _MAX_TREE_ENTRIES:
                    self._failed()
                    return list(entries.values())
                if entry.get("type") == "tree":
                    if self._tree_selected(full_path):
                        pending.append((str(entry.get("sha", "")), full_path + "/", depth + 1))
                else:
                    entries[full_path] = {**entry, "path": full_path}
        self.authoritative_listing = complete and not self.paths and not self.excluded_paths and self.exact_paths is None
        self.listing_complete = complete
        return list(entries.values())

    def _exposure(self) -> str:
        info, _ = self._get_json(f"/repos/{self.owner}/{self.repo}")
        if not info:
            return "unknown"
        return "public" if info.get("private") is False else "internal"

    def collect(self) -> Iterator[CollectedObject]:
        exposure = self._exposure()
        slug = f"{self.owner}/{self.repo}"
        entries = self._entries()
        found: set[str] = set()
        selected: dict[str, dict] = {}
        for entry in entries:
            path = entry.get("path", "")
            sha = entry.get("sha", "")
            if not path or not sha or not self._selected(path):
                continue
            if entry.get("type") == "commit":
                found.add(path)
                self.skipped_submodules += 1
                self._failed()
                continue
            if entry.get("type") != "blob":
                continue
            found.add(path)
            size = int(entry.get("size", 0) or 0)
            if size < 0 or size > self.max_object_bytes:
                self._failed()
                continue
            selected[path] = entry

        self.listed_paths = found
        if self.listing_complete and self.exact_paths is not None:
            self.confirmed_missing_keys = {p for p in self.exact_paths - found if self._selected(p)}

        remaining = dict(selected)
        full_repo = not self.paths and not self.excluded_paths and self.exact_paths is None
        if self.use_archive and full_repo and callable(getattr(self.client, "stream", None)):
            from cremore_github_provider.collectors.github_archive import (
                TRUSTED_HOSTS,
                ArchiveUnavailable,
                archive_blobs,
            )

            # An Enterprise Server's archive is used while its redirect stays on the server's own
            # API or web host; a redirect anywhere else falls back to the blob API below.
            hosts = TRUSTED_HOSTS if self.base_url == _API else frozenset(
                host for host in (urlsplit(self.base_url).hostname, self.github_host) if host)
            url, headers = f"{self.base_url}/repos/{self.owner}/{self.repo}/tarball/{self.commit_sha}", self._headers()
            pacer = github_pacer(url, self.token)

            def request():
                pacer.acquire()
                self._request()

            try:
                for path, data in archive_blobs(
                    self.client, url, headers, selected, self.max_object_bytes, request, hosts=hosts,
                ):
                    entry = remaining.pop(path, None)
                    if entry is not None and self._selected(path):
                        yield self._object(slug, path, entry["sha"], exposure, data)
            except ArchiveUnavailable:
                # Archive limits, unavailable archives, export-ignore and
                # export-subst all fall back to the same pinned blob API.
                pass
        for path, entry in remaining.items():
            if not self._selected(path):
                continue
            sha = entry["sha"]
            if int(entry.get("size", 0) or 0) == 0:
                data = b""
            elif self.lazy:
                # The path was selected above; a read that returns None has counted itself.
                yield self._object(slug, path, sha, exposure, None, size=int(entry["size"]),
                                   loader=lambda sha=sha: self._blob(sha))
                continue
            else:
                data = self._blob(sha)
            if data is None:
                continue
            yield self._object(slug, path, sha, exposure, data)
        if self.exact_paths is not None:
            # An exact location that is no longer in the tree could not be read.
            self._failed(sum(1 for path in self.exact_paths - found if self._selected(path)))

    def _object(self, slug: str, path: str, sha: str, exposure: str, data: bytes | None,
                *, size: int = 0, loader: Callable[[], bytes | None] | None = None) -> CollectedObject:
        return CollectedObject(
            ResourceRef(source_type="github", resource=slug, location=path,
                        size=len(data) if data is not None else size, revision=sha,
                        metadata={"exposure": exposure, "commit_sha": self.commit_sha, "blob_sha": sha,
                                  **({"github_host": self.github_host} if self.github_host else {})}),
            data, loader=loader,
        )

    def _blob(self, sha: str) -> bytes | None:
        blob, _ = self._get_json(f"/repos/{self.owner}/{self.repo}/git/blobs/{quote(sha, safe='')}")
        if not blob or blob.get("encoding") != "base64":
            self._failed()
            return None
        content = blob.get("content") or ""
        if not isinstance(content, str):
            self._failed()
            return None
        max_encoded, max_wrapped = _base64_limits(self.max_object_bytes)
        # GitHub wraps base64 at 60 columns. Reject anything larger before
        # allocating decoded bytes; the final decoded-length check remains.
        if len(content) > max_wrapped:
            self._failed()
            return None
        content = content.replace("\n", "")
        if len(content) > max_encoded:
            self._failed()
            return None
        try:
            data = base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError):
            self._failed()
            return None
        if len(data) > self.max_object_bytes:
            self._failed()
            return None
        return data


def _base64_limits(decoded_bytes: int) -> tuple[int, int]:
    encoded = 4 * ((decoded_bytes + 2) // 3)
    return encoded, encoded + 2 * ((encoded + 59) // 60)


def account_repos_path(get: Callable[[str], tuple[object | None, str]], base_url: str, owner: str) -> tuple[str, bool]:
    """Repository list of a personal account: an owner ``/orgs`` does not know (HTTP 404).

    The token's own account lists its private repositories too (``/user/repos``);
    any other account lists only its public ones, which is not its full inventory.
    Returns a path with a ``{page}`` placeholder and whether the listing is complete.

    Docs: https://docs.github.com/en/rest/repos/repos#list-repositories-for-the-authenticated-user
    """

    me, _ = get(f"{base_url}/user")
    if isinstance(me, dict) and str(me.get("login") or "").lower() == owner.lower():
        return "/user/repos?type=owner&per_page=100&page={page}", True
    return f"/users/{owner}/repos?type=owner&per_page=100&page={{page}}", False


class GitHubOrgCollector:
    """Scan every repository in an organisation or personal account through one connection.

    Lists the owner's repositories (paginated) and delegates each to a
    :class:`GitHubCollector`, so a single GitHub connection covers the whole org
    rather than one repo at a time. One unreadable repo never fails the inventory.

    Docs: https://docs.github.com/en/rest/repos/repos#list-organization-repositories
    """

    # Its lazy reads are its repositories' blob reads (GitHubCollector).
    read_concurrency = GitHubCollector.read_concurrency
    counts_read_failures = True

    def __init__(
        self,
        client,
        org: str,
        *,
        token: GitHubToken = "",
        max_repos: int = 1000,
        max_object_bytes: int = DEFAULT_MAX_OBJECT_BYTES,
        base_url: str = _API,
        request_budget: RequestBudget | None = None,
        use_archive: bool = False,
        lazy: bool = False,
    ) -> None:
        if max_repos <= 0:
            raise ValueError("max_repos must be positive")
        if max_object_bytes <= 0:
            raise ValueError("max_object_bytes must be positive")
        self.client = client
        self.org = org
        self.token = token
        self.max_repos = max_repos
        self.max_object_bytes = max_object_bytes
        self.base_url = base_url.rstrip("/")
        self.request_budget = request_budget or RequestBudget()
        self.use_archive = use_archive
        self.lazy = lazy
        self._listed = False
        self._public_only = False  # another user's account: private repositories are not listable
        # Repositories that could not be listed (empty, no access) plus
        # unreadable blobs inside the ones that were.
        self._failed_objects = 0
        self._requests = 0
        self._subcollectors: list[GitHubCollector] = []

    @property
    def failed_objects(self) -> int:
        return self._failed_objects + sum(sub.failed_objects for sub in self._subcollectors)

    @property
    def requests(self) -> int:
        return self._requests + sum(sub.requests for sub in self._subcollectors)

    @property
    def authoritative_listing(self) -> bool:
        return self._listed and not self._public_only and self._failed_objects == 0 and all(
            sub.authoritative_listing for sub in self._subcollectors
        )

    def _request(self) -> None:
        self.request_budget.consume()
        self._requests += 1

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = resolve_github_token(self.token)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _repos(self) -> Iterator[str]:
        page = 1
        seen = 0
        path = f"/orgs/{self.org}/repos?per_page=100&page={{page}}"

        def get(url):
            return fetch_json(self.client, url, self._headers(), before_attempt=self._request, credential=self.token)

        while True:
            repos, label = get(self.base_url + path.format(page=page))
            if label == "HTTP 404" and path.startswith("/orgs/"):
                path, complete = account_repos_path(get, self.base_url, self.org)
                self._public_only = not complete
                continue
            if not isinstance(repos, list):
                # The organisation's repository list is the scope; if any page
                # cannot be read the inventory is incomplete, not empty.
                raise CollectorError("GITHUB_ORG_LIST_FAILED", label)
            if not repos:
                return
            for repo in repos:
                name = repo.get("name")
                if name:
                    yield name
                    seen += 1
                    if seen >= self.max_repos:
                        # Reaching a configured cap cannot prove full coverage.
                        self._failed_objects += 1
                        return
            if len(repos) < 100:
                return
            page += 1

    def collect(self) -> Iterator[CollectedObject]:
        for repo in self._repos():
            sub = GitHubCollector(
                self.client, self.org, repo,
                token=self.token, max_object_bytes=self.max_object_bytes,
                base_url=self.base_url, request_budget=self.request_budget,
                use_archive=self.use_archive,
                lazy=self.lazy,
            )
            self._subcollectors.append(sub)
            try:
                yield from sub.collect()
            except CollectorError as exc:
                if run_stop(exc):
                    raise
                # One repository that cannot be listed (empty, archived without
                # access) makes the inventory partial, not failed.
                self._failed_objects += 1
        self._listed = True
