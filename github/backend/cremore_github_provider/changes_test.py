"""GitHub change feed against a synthetic repository (compare API)."""

import httpx
import pytest

from cremore.collectors.base import CollectorError, RequestBudget
from cremore_github_provider.changes import COMPARE_FILE_LIMIT, changes_since

OLD, NEW = "a" * 40, "b" * 40
ROOT = {"resource_type": "GITHUB_REPOSITORY", "provider_resource_id": "acme/app", "ref": "HEAD"}
PAYLOAD = {"token": "ghp_" + "t" * 36, "base_url": "https://api.github.com"}


def serve(compare=None, *, status=200):
    seen = []

    def handler(request):
        seen.append(request.url.path)
        assert request.headers["authorization"] == "Bearer " + PAYLOAD["token"]
        if request.url.path == "/repos/acme/app":
            return httpx.Response(200, json={"default_branch": "main"})
        if request.url.path == "/repos/acme/app/commits/main":
            return httpx.Response(200, json={"sha": NEW})
        assert request.url.path == f"/repos/acme/app/compare/{OLD}...{NEW}"
        return httpx.Response(status, json=compare or {})

    return handler, seen


def read(handler, cursor=OLD):
    return changes_since(PAYLOAD, ROOT, cursor, http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)),
                         request_budget=RequestBudget(20))


def test_a_first_look_and_an_unmoved_head_read_no_compare():
    handler, seen = serve()
    assert read(handler, cursor=None).head == NEW
    assert read(handler, cursor=NEW).paths == []
    assert not [path for path in seen if "/compare/" in path]


def test_a_fast_forward_names_the_changed_files_and_removals():
    handler, _seen = serve({"status": "ahead", "files": [
        {"filename": "src/app.env", "status": "modified"},
        {"filename": "new/name.txt", "status": "renamed", "previous_filename": "old/name.txt"},
        {"filename": "gone.txt", "status": "removed"}]})
    changes = read(handler)
    assert changes.paths == ["src/app.env", "new/name.txt", "old/name.txt", "gone.txt"]
    assert changes.removals and not changes.rewritten


def test_diverged_history_or_a_missing_old_commit_is_rewritten():
    handler, _seen = serve({"status": "diverged", "files": []})
    assert read(handler).rewritten
    handler, _seen = serve(status=404)
    missing = read(handler)
    assert missing.rewritten and missing.reason == "GITHUB_BASE_COMMIT_MISSING"


def test_a_compare_at_the_file_limit_is_read_as_unknown():
    handler, _seen = serve({"status": "ahead", "files": [{"filename": f"f{n}", "status": "added"}
                                                          for n in range(COMPARE_FILE_LIMIT)]})
    changes = read(handler)
    assert changes.paths is None and changes.reason == "GITHUB_COMPARE_FILE_LIMIT"


def push(**fields):
    return {"ref": "refs/heads/main", "before": OLD, "after": NEW, "forced": False, "pusher": {"name": "dev"},
            "repository": {"full_name": "Acme/App", "default_branch": "main"}, **fields}


QUEUE_ROOT = {**ROOT, "resource_id": "r1"}


def test_a_push_on_the_read_branch_rereads_the_repository_and_a_forced_one_from_scratch():
    from cremore_github_provider.changes import queue_changes

    answer = queue_changes(push(), {}, [QUEUE_ROOT])["r1"]
    assert (answer.head, answer.paths, answer.rewritten) == (NEW, None, False)
    assert queue_changes(push(forced=True), {}, [QUEUE_ROOT])["r1"].rewritten
    assert queue_changes(push(ref="refs/heads/feature"), {}, [QUEUE_ROOT]) == {}
    assert queue_changes(push(deleted=True), {}, [QUEUE_ROOT]) == {}
    assert queue_changes({"action": "opened", "repository": {}}, {}, [QUEUE_ROOT]) is None


def test_a_push_for_a_repository_outside_the_roots_is_refused():
    from cremore_github_provider.changes import queue_changes

    with pytest.raises(CollectorError, match="EVENT_OUT_OF_SCOPE"):
        queue_changes(push(repository={"full_name": "acme/other"}), {}, [QUEUE_ROOT])
