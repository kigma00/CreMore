"""Collector and scan-service tests (no network; fake AWS/GitHub clients)."""

from __future__ import annotations

import base64
import io
import json

from cremore_aws_provider.collectors.s3 import S3Collector
from cremore_github_provider.collectors.github import GitHubCollector, GitHubOrgCollector
from cremore_notion_provider.collectors.notion import NotionCollector

from cremore.db.repository import InMemoryRepository
from cremore.scanning import Orchestrator
from cremore.scanning.service import ScanService

GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"


# --- S3 --------------------------------------------------------------------

class FakeS3:
    def __init__(self, objects: dict[str, bytes], pab: dict | None = None):
        self.objects = objects
        self.pab = pab

    def get_public_access_block(self, Bucket):
        if self.pab is None:
            raise RuntimeError("no config")
        return {"PublicAccessBlockConfiguration": self.pab}

    def list_objects_v2(self, Bucket, Prefix="", ContinuationToken=None):
        contents = [{"Key": k, "Size": len(v)} for k, v in self.objects.items() if k.startswith(Prefix)]
        return {"Contents": contents, "IsTruncated": False}

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self.objects[Key])}


def test_s3_collector_yields_objects():
    s3 = FakeS3({"a.txt": b"nothing here", "creds.env": f"TOKEN={GH}".encode()})
    got = {o.resource.location: o.data for o in S3Collector(s3, "bucket").collect()}
    assert set(got) == {"a.txt", "creds.env"}
    assert GH.encode() in got["creds.env"]


def test_s3_exposure_from_public_access_block():
    blocked = {"BlockPublicAcls": True, "IgnorePublicAcls": True,
               "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    s3 = FakeS3({"k": b"x"}, pab=blocked)
    obj = next(S3Collector(s3, "bucket").collect())
    assert obj.resource.metadata["exposure"] == "internal"


def test_s3_scan_end_to_end():
    s3 = FakeS3({"creds.env": f"AWS_TOKEN={GH}".encode()})
    repo = InMemoryRepository()
    summary = ScanService(Orchestrator(repo)).run(S3Collector(s3, "bucket", account_id="acct"))
    assert summary.objects == 1
    assert summary.findings == 1
    assert repo.list_findings()[0].severity  # scored


# --- GitHub ----------------------------------------------------------------

class FakeResp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


class FakeGH:
    def __init__(self, private: bool, blobs: dict[str, bytes]):
        self.private = private
        self.blobs = blobs

    def get(self, url, headers=None):
        if url.endswith("/repos/o/r"):
            return FakeResp(200, {"private": self.private})
        if "/commits/" in url:
            return FakeResp(200, {"sha": "a" * 40, "commit": {"tree": {"sha": "b" * 40}}})
        if "/git/trees/" in url:
            tree = [{"type": "blob", "path": f"f{i}.txt", "sha": sha, "size": len(data)}
                    for i, (sha, data) in enumerate(self.blobs.items())]
            return FakeResp(200, {"tree": tree})
        if "/git/blobs/" in url:
            sha = url.rsplit("/", 1)[1]
            return FakeResp(200, {"encoding": "base64",
                                  "content": base64.b64encode(self.blobs[sha]).decode()})
        return FakeResp(404, {})


def test_github_collector_reads_blobs():
    gh = FakeGH(private=False, blobs={"sha1": b"clean", "sha2": f"key: {GH}".encode()})
    objs = list(GitHubCollector(gh, "o", "r").collect())
    assert len(objs) == 2
    assert all(o.resource.metadata["exposure"] == "public" for o in objs)
    assert any(GH.encode() in o.data for o in objs)


class FakeOrgGH:
    """Fake GitHub for an org: /orgs/{org}/repos plus per-repo tree/blobs."""

    def __init__(self, repos: dict[str, dict[str, bytes]]):
        self.repos = repos  # repo name -> {sha: blob}

    def get(self, url, headers=None):
        if "/orgs/" in url and "/repos" in url:
            # One page of repos (page=1); empty on later pages.
            page = 1
            if "&page=" in url:
                page = int(url.split("&page=")[1].split("&")[0])
            if page > 1:
                return FakeResp(200, [])
            return FakeResp(200, [{"name": name} for name in self.repos])
        # Per-repo endpoints: /repos/{org}/{repo}...
        for name, blobs in self.repos.items():
            if f"/{name}" in url:
                if url.endswith(f"/{name}"):
                    return FakeResp(200, {"private": True})
                if "/commits/" in url:
                    return FakeResp(200, {"sha": "a" * 40, "commit": {"tree": {"sha": "b" * 40}}})
                if "/git/trees/" in url:
                    tree = [{"type": "blob", "path": f"f{i}.txt", "sha": sha, "size": len(data)}
                            for i, (sha, data) in enumerate(blobs.items())]
                    return FakeResp(200, {"tree": tree})
                if "/git/blobs/" in url:
                    sha = url.rsplit("/", 1)[1]
                    return FakeResp(200, {"encoding": "base64",
                                          "content": base64.b64encode(blobs[sha]).decode()})
        return FakeResp(404, {})


def test_github_org_collector_scans_every_repo():
    gh = FakeOrgGH({
        "api": {"s1": f"k={GH}".encode()},
        "web": {"s2": b"nothing", "s3": f"tok={GH}".encode()},
    })
    objs = list(GitHubOrgCollector(gh, "acme").collect())
    repos = {o.resource.resource for o in objs}
    assert repos == {"acme/api", "acme/web"}
    assert sum(1 for o in objs if GH.encode() in o.data) == 2


def test_github_personal_account_collector_scans_the_accounts_repositories():
    class Personal(FakeOrgGH):
        def __init__(self, repos, login):
            super().__init__(repos)
            self.login, self.urls = login, []

        def get(self, url, headers=None):
            self.urls.append(url)
            if "/orgs/" in url:
                return FakeResp(404, {})
            if url.endswith("/user"):
                return FakeResp(200, {"login": self.login})
            if "/user/repos?" in url or "/users/jun/repos?" in url:
                return FakeResp(200, [] if "page=2" in url else [{"name": name} for name in self.repos])
            return super().get(url, headers)

    own = Personal({"app": {"s1": f"k={GH}".encode()}}, login="Jun")
    collector = GitHubOrgCollector(own, "jun")
    assert {o.resource.resource for o in collector.collect()} == {"jun/app"}
    assert any("/user/repos?type=owner" in u for u in own.urls) and collector.authoritative_listing
    # another person's account lists only public repositories: never an authoritative inventory
    other = Personal({"app": {"s1": b"x"}}, login="someone-else")
    collector = GitHubOrgCollector(other, "jun")
    list(collector.collect())
    assert any("/users/jun/repos?type=owner" in u for u in other.urls) and not collector.authoritative_listing


def test_github_scan_end_to_end_public_is_higher():
    gh = FakeGH(private=False, blobs={"sha2": f"key: {GH}".encode()})
    repo = InMemoryRepository()
    summary = ScanService(Orchestrator(repo)).run(GitHubCollector(gh, "o", "r"))
    assert summary.findings == 1
    # public repo -> exposure public -> MEDIUM (unverified github token).
    assert repo.list_findings()[0].severity == "MEDIUM"


# --- Notion ----------------------------------------------------------------

def _rt(text: str) -> list[dict]:
    return [{"plain_text": text}]


class FakeNotion:
    """A fake Notion API: one search page of pages, each with block children."""

    def __init__(self, pages: list[dict], children: dict[str, list[dict]]):
        self.pages = [{"last_edited_time": "2026-10-01T00:00:00.000Z", **page} for page in pages]
        self.children = children

    def post(self, url, headers=None, json=None):
        if url.endswith("/v1/search"):
            return FakeResp(200, {"results": self.pages, "has_more": False, "next_cursor": None})
        return FakeResp(404, {})

    def get(self, url, headers=None):
        if "/v1/pages/" in url:
            page_id = url.split("/v1/pages/")[1]
            page = next((page for page in self.pages if page["id"] == page_id), None)
            return FakeResp(200, page) if page else FakeResp(404, {})
        if "/v1/blocks/" in url:
            block_id = url.split("/v1/blocks/")[1].split("/children")[0]
            blocks = self.children.get(block_id, [])
            return FakeResp(200, {"results": blocks, "has_more": False, "next_cursor": None})
        return FakeResp(404, {})


def test_notion_collector_assembles_page_text():
    pages = [{
        "object": "page", "id": "page1", "url": "https://notion.so/page1",
        "properties": {"Name": {"type": "title", "title": _rt("Runbook")}},
    }]
    children = {"page1": [
        {"type": "paragraph", "id": "b1", "has_children": False,
         "paragraph": {"rich_text": _rt(f"deploy key {GH}")}},
        {"type": "heading_1", "id": "b2", "has_children": False,
         "heading_1": {"rich_text": _rt("Secrets")}},
    ]}
    objs = list(NotionCollector(FakeNotion(pages, children), token="ntn_x").collect())
    assert len(objs) == 1
    assert objs[0].resource.source_type == "notion"
    assert objs[0].resource.resource == "Runbook"
    assert objs[0].resource.metadata["exposure"] == "internal"
    assert GH.encode() in objs[0].data


def test_notion_walks_nested_children():
    pages = [{"object": "page", "id": "p", "url": "u", "properties": {}}]
    children = {
        "p": [{"type": "toggle", "id": "t", "has_children": True,
               "toggle": {"rich_text": _rt("open me")}}],
        "t": [{"type": "paragraph", "id": "c", "has_children": False,
               "paragraph": {"rich_text": _rt(f"nested {GH}")}}],
    }
    obj = next(NotionCollector(FakeNotion(pages, children), token="ntn_x").collect())
    assert GH.encode() in obj.data


# --- failure semantics: never a clean empty run ------------------------------

import pytest

from cremore.collectors.base import (
    CollectorError,
    RequestBudget,
    RequestBudgetExceeded,
)


class FailingS3(FakeS3):
    def __init__(self, objects, *, list_error=None, unreadable=()):
        super().__init__(objects)
        self.list_error, self.unreadable = list_error, set(unreadable)

    def list_objects_v2(self, **kwargs):
        if self.list_error:
            raise self.list_error
        return super().list_objects_v2(**kwargs)

    def get_object(self, Bucket, Key):
        if Key in self.unreadable:
            raise PermissionError("AccessDenied")
        return super().get_object(Bucket, Key)


class BotoLikeError(Exception):
    """Shaped like botocore's ClientError: the AWS error code lives in .response."""

    def __init__(self, code):
        super().__init__(f"An error occurred ({code}) ...")
        self.response = {"Error": {"Code": code, "Message": "sensitive provider text"}}


def test_s3_listing_failure_is_a_collector_error_not_an_empty_run():
    with pytest.raises(CollectorError) as info:
        list(S3Collector(FailingS3({}, list_error=BotoLikeError("AccessDenied")), "bucket").collect())
    assert info.value.code == "S3_LIST_FAILED" and info.value.detail == "AccessDenied"
    assert "sensitive" not in str(info.value)  # only the error *code* is reported
    with pytest.raises(CollectorError) as info:
        list(S3Collector(FailingS3({}, list_error=RuntimeError("no creds")), "bucket").collect())
    assert str(info.value) == "S3_LIST_FAILED: RuntimeError"


def test_s3_unreadable_objects_are_counted_and_the_run_is_partial():
    s3 = FailingS3({"ok.env": f"T={GH}".encode(), "denied.env": b"x"}, unreadable={"denied.env"})
    collector = S3Collector(s3, "bucket")
    summary = ScanService(Orchestrator(InMemoryRepository())).run(collector)
    assert summary.objects == 1 and summary.findings == 1
    assert summary.objects_failed == 1 and collector.failed_objects == 1


class FailingGH(FakeGH):
    def __init__(self, *, tree_status=200, bad_blobs=(), **kw):
        super().__init__(**kw)
        self.tree_status, self.bad_blobs = tree_status, set(bad_blobs)

    def get(self, url, headers=None):
        if "/git/trees/" in url and self.tree_status != 200:
            return FakeResp(self.tree_status, {"message": "Not Found"})
        if "/git/blobs/" in url and url.rsplit("/", 1)[1] in self.bad_blobs:
            return FakeResp(403, {})
        return super().get(url, headers)


def test_github_tree_failure_raises_and_blob_failures_count():
    with pytest.raises(CollectorError) as info:
        list(GitHubCollector(FailingGH(private=True, blobs={}, tree_status=404), "o", "r").collect())
    assert info.value.code == "GITHUB_TREE_UNAVAILABLE" and info.value.detail == "HTTP 404"
    gh = FailingGH(private=False, blobs={"a": b"one", "b": b"two"}, bad_blobs={"b"})
    collector = GitHubCollector(gh, "o", "r")
    assert len(list(collector.collect())) == 1 and collector.failed_objects == 1


def test_github_org_listing_failure_raises_but_one_bad_repo_is_partial():
    class DeniedOrg(FakeOrgGH):
        def get(self, url, headers=None):
            if "/orgs/" in url:
                return FakeResp(403, {})
            return super().get(url, headers)

    with pytest.raises(CollectorError) as info:
        list(GitHubOrgCollector(DeniedOrg({}), "acme").collect())
    assert info.value.code == "GITHUB_ORG_LIST_FAILED"

    class EmptyRepoOrg(FakeOrgGH):
        def get(self, url, headers=None):
            if "/empty/git/trees/" in url:
                return FakeResp(409, {"message": "Git Repository is empty."})
            return super().get(url, headers)

    gh = EmptyRepoOrg({"api": {"s1": f"k={GH}".encode()}, "empty": {}})
    collector = GitHubOrgCollector(gh, "acme")
    objs = list(collector.collect())
    assert {o.resource.resource for o in objs} == {"acme/api"} and collector.failed_objects == 1


def test_notion_search_failure_raises_and_unreadable_pages_count():
    class DeniedNotion(FakeNotion):
        def post(self, url, headers=None, json=None):
            return FakeResp(401, {"code": "unauthorized"})

    with pytest.raises(CollectorError) as info:
        list(NotionCollector(DeniedNotion([], {}), token="ntn_x").collect())
    assert info.value.code == "NOTION_SEARCH_FAILED" and info.value.detail == "HTTP 401"

    class BlockedNotion(FakeNotion):
        def get(self, url, headers=None):
            if "/v1/blocks/locked/" in url:
                return FakeResp(403, {})
            return super().get(url, headers)

    pages = [{"object": "page", "id": "locked", "url": "u1", "properties": {}},
             {"object": "page", "id": "open", "url": "u2", "properties": {}}]
    children = {"open": [{"type": "paragraph", "id": "b", "has_children": False,
                          "paragraph": {"rich_text": _rt(f"t {GH}")}}]}
    collector = NotionCollector(BlockedNotion(pages, children), token="ntn_x")
    assert len(list(collector.collect())) == 1 and collector.failed_objects == 1


def test_notion_scan_end_to_end():
    pages = [{"object": "page", "id": "p", "url": "u", "properties": {}}]
    children = {"p": [{"type": "paragraph", "id": "b", "has_children": False,
                       "paragraph": {"rich_text": _rt(f"token {GH}")}}]}
    repo = InMemoryRepository()
    summary = ScanService(Orchestrator(repo)).run(
        NotionCollector(FakeNotion(pages, children), token="ntn_x"))
    assert summary.objects == 1 and summary.findings == 1
    # workspace-internal exposure -> LOW for an unverified github token.
    assert repo.list_findings()[0].severity == "LOW"


# --- approved scope inside a resource (prefixes, paths, exact locations) ------

from cremore.collectors.scoped import ScopedCollector


@pytest.mark.parametrize("path,roots,expected", [
    ("src", ["src"], True),
    ("src/file", ["src/"], True),
    ("src-other/file", ["src"], False),
    ("src", ["src/"], False),
    ("src/file", [], False),
    ("src/file", [""], False),
    ("/file", [""], True),
    ("", [""], True),
    ("src/../file", ["src"], True),
])
def test_path_scope_predicate_preserves_literal_boundaries(path, roots, expected):
    from cremore_github_provider.collectors.github import _under

    from cremore.collectors.base import path_under

    assert _under is path_under
    assert path_under(path, roots) is expected


def test_s3_scope_prefixes_exclusions_and_exact_keys():
    s3 = FakeS3({"a/1.txt": b"one", "a/skip/2.txt": b"two", "b/3.txt": b"three", "c/4.txt": b"four"})
    got = [o.resource.location for o in S3Collector(s3, "bucket", prefixes=["a/", "b/"], excluded_prefixes=["a/skip/"]).collect()]
    assert got == ["a/1.txt", "b/3.txt"]
    exact = S3Collector(s3, "bucket", keys=["c/4.txt", "missing.txt"])
    assert [o.resource.location for o in exact.collect()] == ["c/4.txt"]
    assert exact.failed_objects == 1 and exact.requests == 3  # exposure check + reads; never a listing


def test_github_scope_paths_exclusions_and_exact_paths():
    class TreeGH(FakeGH):
        def get(self, url, headers=None):
            if "/git/trees/" in url:
                assert f"/git/trees/{'b' * 40}?" in url  # immutable tree resolved from main once
                tree = [{"type": "blob", "path": p, "sha": s, "size": len(self.blobs[s])} for p, s in
                        (("src/app.py", "s1"), ("src/vendor/x.py", "s2"), ("README.md", "s3"))]
                return FakeResp(200, {"tree": tree})
            return super().get(url, headers)

    gh = TreeGH(private=True, blobs={"s1": b"app", "s2": b"vendor", "s3": b"readme"})
    got = [o.resource.location for o in GitHubCollector(gh, "o", "r", ref="refs/heads/main", paths=["src"],
                                                        excluded_paths=["src/vendor"]).collect()]
    assert got == ["src/app.py"]
    exact = GitHubCollector(gh, "o", "r", ref="refs/heads/main", exact_paths=["README.md", "gone.py"])
    assert [o.resource.location for o in exact.collect()] == ["README.md"] and exact.failed_objects == 1


def test_notion_exact_page_ids_skip_search():
    class PageNotion(FakeNotion):
        def post(self, url, headers=None, json=None):
            raise AssertionError("search must not run for exact page ids")

        def get(self, url, headers=None):
            if url.endswith("/v1/pages/p1"):
                return FakeResp(200, self.pages[0])
            if "/v1/pages/" in url:
                return FakeResp(404, {})
            return super().get(url, headers)

    pages = [{"object": "page", "id": "p1", "url": "u", "properties": {}}]
    children = {"p1": [{"type": "paragraph", "id": "b", "has_children": False, "paragraph": {"rich_text": _rt(f"k {GH}")}}]}
    col = NotionCollector(PageNotion(pages, children), token="ntn_x", page_ids=["p1", "p-missing"])
    objs = list(col.collect())
    assert len(objs) == 1 and GH.encode() in objs[0].data and col.failed_objects == 1


def test_scoped_collector_budgets_and_root_failures_are_reported_not_hidden():
    ok = S3Collector(FakeS3({"a": b"12345", "b": b"12345", "c": b"12345"}), "ok")
    bad = S3Collector(FailingS3({}, list_error=RuntimeError("AccessDenied")), "bad")
    col = ScopedCollector([bad, ok], budget_bytes=10)
    got = [o.resource.location for o in col.collect()]
    assert got == ["a", "b"] and col.stopped == "BUDGET_BYTES"
    cov = col.coverage
    assert cov["succeeded"] == 2 and cov["skipped"] == 1 and cov["roots_failed"] == 1 and cov["failed"] == 1 and cov["bytes"] == 10
    assert cov["attempted"] == 4 and cov["stopped_reason"] == "BUDGET_BYTES"
    # every root unlistable -> the run failed, never an empty success
    with pytest.raises(CollectorError):
        list(ScopedCollector([S3Collector(FailingS3({}, list_error=RuntimeError("x")), "bad")]).collect())
    # time budget
    ticks = iter([0, 0, 100])
    slow = ScopedCollector([S3Collector(FakeS3({"a": b"1", "b": b"2"}), "s")], budget_seconds=5, clock=lambda: next(ticks))
    assert [o.resource.location for o in slow.collect()] == ["a"] and slow.stopped == "BUDGET_SECONDS"


def test_request_budget_is_shared_and_scope_reports_the_stop():
    budget = RequestBudget(3)
    org = GitHubOrgCollector(
        FakeOrgGH({"api": {"s1": b"one"}}), "acme", request_budget=budget
    )
    with pytest.raises(RequestBudgetExceeded):
        list(org.collect())
    assert budget.used == 3 and org.requests == 3

    scoped_budget = RequestBudget(1)
    scoped = ScopedCollector(
        [S3Collector(FakeS3({"a": b"one"}), "bucket", request_budget=scoped_budget)]
    )
    assert list(scoped.collect()) == []
    assert scoped.stopped == "BUDGET_REQUESTS" and scoped.coverage["skipped"] == 1
    assert scoped.coverage["requests"] == 1


def test_oversized_s3_objects_are_partial_and_streams_are_closed():
    class TrackingBody(io.BytesIO):
        was_closed = False

        def close(self):
            self.was_closed = True
            super().close()

    class LyingS3(FakeS3):
        def __init__(self):
            super().__init__({"large": b"12345"})
            self.body = TrackingBody(self.objects["large"])

        def list_objects_v2(self, **kwargs):
            return {"Contents": [{"Key": "large", "Size": 1}], "IsTruncated": False}

        def get_object(self, **kwargs):
            return {"Body": self.body}

    fake = LyingS3()
    collector = S3Collector(fake, "bucket", max_object_bytes=3)
    assert list(collector.collect()) == []
    assert collector.failed_objects == 1 and fake.body.was_closed


def test_github_truncated_tree_and_oversized_blob_are_partial():
    class PartialGH(FakeGH):
        def __init__(self):
            super().__init__(private=True, blobs={"small": b"ok", "large": b"12345"})
            self.urls = []

        def get(self, url, headers=None):
            self.urls.append(url)
            if "/git/trees/" in url:
                return FakeResp(200, {"truncated": True, "tree": [
                    {"type": "blob", "path": "small", "sha": "small", "size": 2},
                    {"type": "blob", "path": "large", "sha": "large", "size": 5},
                ]})
            return super().get(url, headers)

    fake = PartialGH()
    collector = GitHubCollector(fake, "o", "r", max_object_bytes=3)
    assert [obj.data for obj in collector.collect()] == [b"ok"]
    assert collector.failed_objects == 2
    assert not any(url.endswith("/git/blobs/large") for url in fake.urls)


def test_github_rejects_large_encoded_blob_before_decode():
    class LyingGH(FakeGH):
        def get(self, url, headers=None):
            if "/git/trees/" in url:
                return FakeResp(200, {"tree": [
                    {"type": "blob", "path": "large", "sha": "large", "size": 1}
                ]})
            return super().get(url, headers)

    collector = GitHubCollector(
        LyingGH(private=True, blobs={"large": b"12345"}), "o", "r", max_object_bytes=3
    )
    assert list(collector.collect()) == [] and collector.failed_objects == 1


def test_notion_page_and_text_caps_make_coverage_partial():
    pages = [
        {"object": "page", "id": "empty", "url": "u1", "properties": {}},
        {"object": "page", "id": "second", "url": "u2", "properties": {}},
    ]
    children = {
        "empty": [],
        "second": [{"type": "paragraph", "id": "b", "has_children": False,
                    "paragraph": {"rich_text": _rt("secret")}}],
    }
    page_cap = NotionCollector(FakeNotion(pages, children), "ntn_x", max_pages=1)
    empty_objects = list(page_cap.collect())
    assert len(empty_objects) == 1 and empty_objects[0].data == b""
    assert empty_objects[0].complete and page_cap.failed_objects == 1

    text_cap = NotionCollector(FakeNotion(pages[1:], children), "ntn_x", max_object_bytes=4)
    objects = list(text_cap.collect())
    assert len(objects) == 1 and len(objects[0].data) <= 4 and text_cap.failed_objects == 1


def test_notion_depth_cap_is_reported_as_partial():
    pages = [{"object": "page", "id": "p", "url": "u", "properties": {}}]
    children = {
        "p": [{"type": "toggle", "id": "a", "has_children": True,
               "toggle": {"rich_text": _rt("a")}}],
        "a": [{"type": "toggle", "id": "b", "has_children": True,
               "toggle": {"rich_text": _rt("b")}}],
        "b": [{"type": "toggle", "id": "c", "has_children": True,
               "toggle": {"rich_text": _rt("c")}}],
    }
    collector = NotionCollector(FakeNotion(pages, children), "ntn_x")
    assert len(list(collector.collect())) == 1 and collector.failed_objects == 1

from cremore.collectors.content import ContentCollector


class SimpleResponse:
    def __init__(self, status, body):
        self.status_code, self.headers = status, {}
        self.content = body if isinstance(body, bytes) else json.dumps(body).encode()

    def json(self):
        return json.loads(self.content)


class SyntheticContent(ContentCollector):
    """A minimal content collector: each loader returns, raises or yields nothing."""

    PROVIDER = "synthetic"

    class HTTP:
        def __init__(self, payload, client, *, budget=None, max_bytes=0):
            self.budget = budget or RequestBudget(100)

    def __init__(self, loads, *, lazy=True):
        super().__init__({"_lazy": lazy}, None)
        self.loads = loads

    def objects(self):
        for key, load in self.loads.items():
            yield self.object("root", key, "v1", load, revision="rev-" + key)


def test_content_reads_record_their_size_and_count_each_failure_once():
    def denied():
        raise CollectorError("SOURCE_HTTP_FAILED", "403")

    collector = SyntheticContent({"a": lambda: b"12345", "b": denied, "c": lambda: None})
    objects = list(collector.collect())
    assert all(obj.resource.size == 0 for obj in objects)  # nothing read yet
    assert [obj.read() for obj in objects] == [b"12345", None, None]
    assert objects[0].resource.size == 5 and collector.failed_objects == 2
    assert collector.read_concurrency == 8 and collector.counts_read_failures is True
    eager = SyntheticContent({"a": lambda: b"123", "c": lambda: None}, lazy=False)
    a, c = list(eager.collect())
    assert a.resource.size == 3 and c.data is None and c.failure_counted and eager.failed_objects == 1


def test_a_content_object_over_the_shrunken_limit_is_one_failed_object():
    from cremore_gcp_provider.content import Collector as GcsCollector

    class Gcs:
        def get(self, url, params=None, **_kwargs):
            if url.endswith("/b/bucket/o"):
                rows = [{"name": name, "generation": "1", "size": "0"} for name in ("big", "small")]
                return SimpleResponse(200, {"items": rows})
            return SimpleResponse(200, b"x" * 64 if url.endswith("/big") else b"ok")

    collector = GcsCollector({"bucket": "bucket", "token": "t", "_lazy": True}, Gcs())
    assert collector.max_object_bytes == collector.http.max_bytes
    collector.max_object_bytes = 32  # what the worker leaves after the byte budget is spent
    assert collector.http.max_bytes == 32
    big, small = list(collector.collect())
    assert big.read() is None and small.read() == b"ok" and collector.failed_objects == 1


@pytest.mark.parametrize("code", ["BUDGET_REQUESTS", "BUDGET_SECONDS", "BUDGET_BYTES", "RUN_CANCELLED"])
def test_a_budget_or_cancellation_stop_during_a_content_read_ends_the_root(code):
    def stopped():
        raise CollectorError(code)

    collector = SyntheticContent({"a": stopped})
    [obj] = list(collector.collect())
    with pytest.raises(CollectorError, match=code):
        obj.read()
    assert collector.failed_objects == 0


def test_github_collector_stamps_the_enterprise_host_on_findings():
    gh = FakeGH(private=True, blobs={"sha9": f"key: {GH}".encode()})
    objs = list(GitHubCollector(gh, "o", "r", base_url="https://ghe.example.com/api/v3").collect())
    assert objs and all(o.resource.metadata.get("github_host") == "ghe.example.com" for o in objs)
    # github.com leaves no host stamp (the default)
    pub = list(GitHubCollector(FakeGH(private=True, blobs={"s": f"k={GH}".encode()}), "o", "r").collect())
    assert pub and all("github_host" not in o.resource.metadata for o in pub)
