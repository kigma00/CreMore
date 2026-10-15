"""GitLab change feed against a synthetic project (merge base and compare APIs)."""

from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from cremore.collectors.base import CollectorError, RequestBudget
from cremore_gitlab_provider.changes import DIFF_LIMIT, changes_since

OLD, NEW = "a" * 40, "b" * 40
ROOT = {"resource_type": "GITLAB_REPOSITORY", "provider_resource_id": "42", "ref": "main"}
PAYLOAD = {"token": "glpat-synthetic", "base_url": "https://gitlab.example.com"}


def serve(*, base=OLD, compare=None, base_status=200):
    def handler(request):
        path = request.url.path
        if path == "/api/v4/projects/42/repository/commits/main":
            return httpx.Response(200, json={"id": NEW})
        if path == "/api/v4/projects/42/repository/merge_base":
            assert parse_qs(urlsplit(str(request.url)).query)["refs[]"] == [OLD, NEW]
            return httpx.Response(base_status, json={"id": base} if base_status == 200 else {})
        assert path == "/api/v4/projects/42/repository/compare"
        assert request.url.params["straight"] == "true"
        return httpx.Response(200, json=compare)

    return handler


def read(handler, cursor=OLD):
    return changes_since(PAYLOAD, ROOT, cursor, http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)),
                         request_budget=RequestBudget(20))


def test_a_fast_forward_names_the_changed_files():
    changes = read(serve(compare={"diffs": [
        {"old_path": "a.env", "new_path": "a.env"},
        {"old_path": "old.txt", "new_path": "new.txt", "renamed_file": True}], "compare_timeout": False}))
    assert changes.paths == ["a.env", "new.txt", "old.txt"] and changes.removals


@pytest.mark.parametrize("status", [400, 404])
def test_a_merge_base_other_than_the_old_head_or_a_missing_commit_is_rewritten(status):
    assert read(serve(base="c" * 40)).rewritten
    missing = read(serve(base_status=status))
    assert missing.rewritten and missing.reason == "GITLAB_BASE_COMMIT_MISSING"
    assert missing.head == NEW and missing.paths is None


@pytest.mark.parametrize("endpoint", ["commits/main", "compare"])
def test_a_400_outside_merge_base_is_not_treated_as_rewritten(endpoint):
    success = serve()

    def handler(request):
        if request.url.path.endswith("/repository/" + endpoint):
            return httpx.Response(400, json={"message": "Bad Request"})
        return success(request)

    with pytest.raises(CollectorError) as failed:
        read(handler)
    assert failed.value.code == "SOURCE_HTTP_FAILED" and failed.value.detail == "400"


@pytest.mark.parametrize("status", [401, 403, 422])
def test_other_merge_base_errors_are_not_treated_as_rewritten(status):
    with pytest.raises(CollectorError) as failed:
        read(serve(base_status=status))
    assert failed.value.code == "SOURCE_HTTP_FAILED" and failed.value.detail == str(status)


def test_a_timed_out_or_overlong_compare_is_read_as_unknown():
    assert read(serve(compare={"diffs": [], "compare_timeout": True})).paths is None
    long = [{"old_path": f"f{n}", "new_path": f"f{n}"} for n in range(DIFF_LIMIT)]
    assert read(serve(compare={"diffs": long})).reason == "GITLAB_COMPARE_DIFF_LIMIT"


def test_an_unmoved_head_asks_nothing_more():
    assert read(serve(), cursor=NEW).paths == []


def push(kind="push", **fields):
    return {"object_kind": kind, "ref": "refs/heads/main", "before": OLD, "after": NEW, "project_id": 42,
            "project": {"id": 42, "default_branch": "main"}, "total_commits_count": 1, **fields}


def test_a_push_rereads_the_project_and_tags_deletions_and_other_branches_ask_for_nothing():
    from cremore_gitlab_provider.changes import queue_changes

    root = {**ROOT, "resource_id": "r1"}
    assert queue_changes(push(), {}, [root])["r1"].paths is None
    assert queue_changes(push("tag_push", ref="refs/tags/v1"), {}, [root]) == {}
    assert queue_changes(push(after="0" * 40), {}, [root]) == {}
    assert queue_changes(push(ref="refs/heads/feature"), {}, [root]) == {}
    with pytest.raises(CollectorError, match="EVENT_UNSUPPORTED_NOTIFICATION"):
        queue_changes(push("merge_request"), {}, [root])
    with pytest.raises(CollectorError, match="EVENT_OUT_OF_SCOPE"):
        queue_changes(push(project_id=7, project={"id": 7}), {}, [root])
    assert queue_changes({"ref": "main"}, {}, [root]) is None

@pytest.mark.parametrize("status", [503, 429])
def test_a_busy_or_throttled_gitlab_ends_the_feeds_look_at_once_and_a_scan_still_retries(monkeypatch, status):
    import time
    from types import SimpleNamespace

    from cremore import http_client
    from cremore_gitlab_provider.content import SourceHTTP

    sleeps, seen = [], []
    monkeypatch.setattr(http_client, "time", SimpleNamespace(monotonic=time.monotonic, time=time.time, sleep=sleeps.append))

    def busy(request):
        seen.append(request.url.path)
        return httpx.Response(status, headers={"Retry-After": "2"})

    with pytest.raises(CollectorError, match="SOURCE_UNAVAILABLE" if status == 503 else "SOURCE_RATE_LIMITED"):
        read(busy)  # polled on the worker's control loop: no sleep, the cursor stays
    assert len(seen) == 1 and sleeps == []
    answers = [httpx.Response(status, headers={"Retry-After": "2"}), httpx.Response(200, json={"id": NEW})]
    scan = SourceHTTP(PAYLOAD, httpx.Client(transport=httpx.MockTransport(lambda _request: answers.pop(0))))
    assert scan.get("/projects/42/repository/commits/main")[0] == {"id": NEW} and sleeps == [2.0]
