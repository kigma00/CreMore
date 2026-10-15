"""Pinned GitHub collection and archive safety, entirely through mock HTTP."""

import hashlib
import io
import tarfile

import httpx
import pytest

from cremore.collectors.base import DEFAULT_MAX_OBJECT_BYTES, RequestBudget, RequestBudgetExceeded
from cremore_github_provider.collectors import github_archive
from cremore_github_provider.collectors.github import GitHubCollector

COMMIT = "a" * 40
TREE = "b" * 40
SUBTREE = "c" * 40


def _sha(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def _entries(files):
    return [{"type": "blob", "path": path, "sha": _sha(data), "size": len(data)}
            for path, data in files.items()]


def _tar(files, symlinks=()):
    body = io.BytesIO()
    with tarfile.open(fileobj=body, mode="w:gz") as archive:
        for path, data in files.items():
            info = tarfile.TarInfo("generated-root/" + path)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        for path in symlinks:
            info = tarfile.TarInfo("generated-root/" + path)
            info.type = tarfile.SYMTYPE
            info.linkname = "../../outside"
            archive.addfile(info)
    return body.getvalue()


class MockGitHub:
    def __init__(self, files, *, archive=None, redirect="https://codeload.github.com/o/r/archive",
                 recursive=None, subtrees=None):
        self.files = files
        self.archive, self.redirect = archive, redirect
        self.recursive = recursive
        self.subtrees = subtrees or {}
        self.requests = []
        self.client = httpx.Client(transport=httpx.MockTransport(self.handle))

    def handle(self, request):
        self.requests.append(request)
        path = request.url.path
        if request.url.host == "codeload.github.com":
            return httpx.Response(200, content=self.archive)
        if path == "/repos/o/r":
            return httpx.Response(200, json={"private": True})
        if path == "/repos/o/r/commits/main":
            return httpx.Response(200, json={"sha": COMMIT, "commit": {"tree": {"sha": TREE}}})
        if path == f"/repos/o/r/git/trees/{TREE}" and request.url.query:
            return httpx.Response(200, json=self.recursive or {"tree": _entries(self.files)})
        if "/git/trees/" in path:
            sha = path.rsplit("/", 1)[1]
            return httpx.Response(200, json=self.subtrees[sha])
        if "/git/blobs/" in path:
            import base64

            sha = path.rsplit("/", 1)[1]
            data = next(data for data in self.files.values() if _sha(data) == sha)
            return httpx.Response(200, json={"encoding": "base64", "content": base64.b64encode(data).decode()})
        if path == f"/repos/o/r/tarball/{COMMIT}":
            if self.archive is None:
                return httpx.Response(404)
            return httpx.Response(302, headers={"location": self.redirect})
        raise AssertionError(f"unexpected mock request: {request.url}")

    def collector(self, **kwargs):
        return GitHubCollector(self.client, "o", "r", ref="refs/heads/main", token="integration-token", **kwargs)


def test_commit_is_pinned_and_blob_revision_is_exposed():
    fake = MockGitHub({"one.txt": b"one", "empty": b""})
    objects = list(fake.collector().collect())
    assert {o.resource.location: o.data for o in objects} == fake.files
    assert all(o.resource.revision == _sha(o.data) for o in objects)
    assert all(o.resource.metadata["commit_sha"] == COMMIT for o in objects)
    assert len([r for r in fake.requests if "/commits/" in r.url.path]) == 1
    assert all(TREE in r.url.path for r in fake.requests if "/git/trees/" in r.url.path)


def test_truncated_tree_is_completed_without_following_submodules():
    files = {"root.txt": b"root", "src/app.py": b"app"}
    tree = [*_entries({"root.txt": b"root"}), {"type": "tree", "path": "src", "sha": SUBTREE},
            {"type": "commit", "path": "vendor", "sha": "d" * 40}]
    fake = MockGitHub(files, recursive={"truncated": True, "tree": []}, subtrees={
        TREE: {"tree": tree}, SUBTREE: {"tree": _entries({"app.py": b"app"})},
    })
    collector = fake.collector()
    assert {o.resource.location: o.data for o in collector.collect()} == files
    assert collector.failed_objects == 1 and collector.skipped_submodules == 1
    assert not any("d" * 40 in r.url.path for r in fake.requests)


def test_exact_scope_never_reads_excluded_files_or_uses_archive():
    files = {"allowed": b"allowed", "excluded": b"excluded", "other": b"other"}
    fake = MockGitHub(files, archive=_tar(files))
    collector = fake.collector(use_archive=True, exact_paths=["allowed", "excluded"], excluded_paths=["excluded"])
    assert [o.resource.location for o in collector.collect()] == ["allowed"]
    assert not any("/tarball/" in r.url.path for r in fake.requests)
    reads = [r.url.path.rsplit("/", 1)[1] for r in fake.requests if "/git/blobs/" in r.url.path]
    assert reads == [_sha(b"allowed")]
    assert not collector.authoritative_listing


def test_lazy_blobs_expose_identity_without_downloading_and_load_only_once():
    fake = MockGitHub({"file": b"content", "empty": b""})
    collector = fake.collector(lazy=True)
    objects = list(collector.collect())
    assert collector.authoritative_listing
    assert not any("/git/blobs/" in r.url.path for r in fake.requests)
    content = next(o for o in objects if o.resource.location == "file")
    assert content.data is None and content.resource.size == 7
    assert content.resource.revision == _sha(b"content")
    assert content.read() == content.read() == b"content"
    assert len([r for r in fake.requests if "/git/blobs/" in r.url.path]) == 1
    assert next(o for o in objects if o.resource.location == "empty").read() == b""


def test_unreadable_lazy_blob_is_not_an_empty_success():
    class DeniedBlob(MockGitHub):
        def handle(self, request):
            if "/git/blobs/" in request.url.path:
                self.requests.append(request)
                return httpx.Response(403)
            return super().handle(request)

    fake = DeniedBlob({"file": b"content"})
    collector = fake.collector(lazy=True)
    obj = next(collector.collect())
    assert obj.read() is None and obj.read() is None
    assert collector.failed_objects == 1
    assert len([r for r in fake.requests if "/git/blobs/" in r.url.path]) == 1


def test_rate_limit_retries_consume_the_shared_request_budget(monkeypatch):
    from cremore import http_client

    class RateLimited(MockGitHub):
        limited = False

        def handle(self, request):
            if "/commits/" in request.url.path and not self.limited:
                self.limited = True
                self.requests.append(request)
                return httpx.Response(429, headers={"Retry-After": "0"})
            return super().handle(request)

    monkeypatch.setattr(http_client.time, "sleep", lambda seconds: None)
    fake = RateLimited({"file": b"content"})
    with pytest.raises(RequestBudgetExceeded):
        list(fake.collector(request_budget=RequestBudget(3)).collect())
    assert len(fake.requests) == 3 and fake.limited


def test_truncated_fallback_respects_the_shared_request_budget():
    fake = MockGitHub({}, recursive={"truncated": True, "tree": []})
    with pytest.raises(RequestBudgetExceeded):
        list(fake.collector(request_budget=RequestBudget(3)).collect())
    assert len(fake.requests) == 3


@pytest.mark.parametrize("size", [0, 4096, 1024 * 1024])
def test_archive_member_read_requests_verified_size_without_lowering_configured_limit(monkeypatch, size):
    data = (bytes(range(256)) * ((size + 255) // 256))[:size]
    fake = MockGitHub({"file": data}, archive=_tar({"file": data}))
    requested_sizes = []
    original_read = tarfile.ExFileObject.read

    def checked_read(stream, requested_size=-1):
        requested_sizes.append(requested_size)
        # Reject the oversized request before allocating it in the regression.
        assert requested_size == size
        return original_read(stream, requested_size)

    monkeypatch.setattr(tarfile.ExFileObject, "read", checked_read)
    collector = fake.collector(use_archive=True)
    objects = list(collector.collect())
    assert requested_sizes == [size]
    assert collector.max_object_bytes == DEFAULT_MAX_OBJECT_BYTES == 50 * 1024 * 1024
    assert {obj.resource.location: obj.data for obj in objects} == fake.files
    assert collector.failed_objects == 0
    assert not any("/git/blobs/" in request.url.path for request in fake.requests)


def test_archive_short_member_read_uses_verified_blob_fallback(monkeypatch):
    data = b"complete file"
    fake = MockGitHub({"file": data}, archive=_tar({"file": data}))
    original_read = tarfile.ExFileObject.read

    def short_read(stream, size=-1):
        return original_read(stream, size)[:-1]

    monkeypatch.setattr(tarfile.ExFileObject, "read", short_read)
    collector = fake.collector(use_archive=True)
    assert [obj.data for obj in collector.collect()] == [data]
    assert collector.failed_objects == 0
    blob_requests = [request for request in fake.requests if "/git/blobs/" in request.url.path]
    assert len(blob_requests) == 1 and blob_requests[0].url.path.endswith(_sha(data))


def test_archive_keeps_configured_object_size_limit():
    files = {"permitted": b"a" * 16, "too-large": b"b" * 17}
    fake = MockGitHub(files, archive=_tar(files))
    collector = fake.collector(use_archive=True, max_object_bytes=16)
    assert {obj.resource.location: obj.data for obj in collector.collect()} == {"permitted": files["permitted"]}
    assert collector.failed_objects == 1
    assert not any("/git/blobs/" in request.url.path for request in fake.requests)


def test_archive_verifies_content_and_falls_back_for_missing_substituted_and_symlink_members():
    files = {"same": b"same", "ignored": b"not archived", "substituted": b"original", "link": b"target"}
    fake = MockGitHub(files, archive=_tar({"same": b"same", "substituted": b"modified"}, symlinks=["link"]))
    collector = fake.collector(use_archive=True)
    assert {o.resource.location: o.data for o in collector.collect()} == files
    blob_reads = {r.url.path.rsplit("/", 1)[1] for r in fake.requests if "/git/blobs/" in r.url.path}
    assert blob_reads == {_sha(files[p]) for p in ("ignored", "substituted", "link")}
    assert collector.failed_objects == 0
    archive_requests = [r for r in fake.requests if "/tarball/" in r.url.path or r.url.host == "codeload.github.com"]
    assert archive_requests[0].headers["authorization"] == "Bearer integration-token"
    assert "authorization" not in archive_requests[1].headers
    assert archive_requests[0].url.path.endswith(COMMIT)


def test_archive_redirect_strips_client_default_credentials_and_cookie_jar():
    fake = MockGitHub({"file": b"content"}, archive=_tar({"file": b"content"}))
    fake.client.headers["Authorization"] = "Bearer client-default"
    fake.client.auth = httpx.BasicAuth("default", "credential")
    fake.client.cookies.set("session", "client-cookie", domain=".github.com")
    assert [o.data for o in fake.collector(use_archive=True).collect()] == [b"content"]
    redirected = next(r for r in fake.requests if r.url.host == "codeload.github.com")
    assert "authorization" not in redirected.headers
    assert "cookie" not in redirected.headers


@pytest.mark.parametrize("target", ["https://untrusted.invalid/archive", "http://codeload.github.com/archive",
                                   "https://user@codeload.github.com/archive", "https://codeload.github.com:444/archive"])
def test_untrusted_archive_redirect_is_not_requested_and_falls_back(target):
    fake = MockGitHub({"file": b"content"}, archive=_tar({"file": b"content"}), redirect=target)
    assert [o.data for o in fake.collector(use_archive=True).collect()] == [b"content"]
    assert all(r.url.host == "api.github.com" for r in fake.requests)


@pytest.mark.parametrize("limit,value", [("MAX_COMPRESSED_BYTES", 16), ("MAX_EXPANDED_BYTES", 128),
                                        ("MAX_MEMBERS", 0), ("MAX_SECONDS", -1)])
def test_archive_limit_preserves_coverage_using_blob_fallback(monkeypatch, limit, value):
    fake = MockGitHub({"file": b"content"}, archive=_tar({"file": b"content"}))
    monkeypatch.setattr(github_archive, limit, value)
    collector = fake.collector(use_archive=True)
    assert [o.data for o in collector.collect()] == [b"content"]
    assert collector.failed_objects == 0
    assert any("/git/blobs/" in r.url.path for r in fake.requests)


def test_archive_request_budget_exhaustion_is_not_hidden_by_fallback():
    fake = MockGitHub({"file": b"content"}, archive=_tar({"file": b"content"}))
    with pytest.raises(RequestBudgetExceeded):
        list(fake.collector(use_archive=True, request_budget=RequestBudget(4)).collect())
    assert len(fake.requests) == 4


def test_archive_does_not_accept_traversal_names_as_tree_paths():
    fake = MockGitHub({"file": b"content"}, archive=_tar({"../file": b"content", "file": b"content"}))
    assert [o.data for o in fake.collector(use_archive=True).collect()] == [b"content"]
    assert not any("/git/blobs/" in r.url.path for r in fake.requests)
