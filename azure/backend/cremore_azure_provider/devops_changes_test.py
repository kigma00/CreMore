"""Azure DevOps change feed against a synthetic repository (diffs/commits)."""

import httpx
import pytest

from cremore.collectors.base import RequestBudget
from cremore_azure_provider.devops_changes import PAGE, changes_since

OLD, NEW = "a" * 40, "b" * 40
ROOT = {"resource_type": "AZURE_DEVOPS_REPOSITORY", "provider_resource_id": "acme/Payments/api", "ref": ""}
PAYLOAD = {"token": "synthetic-pat", "organization": "acme", "project": "Payments"}


def change(path, kind="edit", folder=False, original=None):
    item = {"path": path, "gitObjectType": "tree" if folder else "blob"}
    if folder:
        item["isFolder"] = True
    out = {"item": item, "changeType": kind}
    if original:
        out["originalPath"] = original
    return out


def serve(pages, *, status=200, common=OLD, behind=0, all_included=True):
    def handler(request):
        path = request.url.path
        if path == "/acme/Payments/_apis/git/repositories/api":
            return httpx.Response(200, json={"defaultBranch": "refs/heads/main"})
        if path == "/acme/Payments/_apis/git/repositories/api/refs":
            return httpx.Response(200, json={"value": [{"name": "refs/heads/main", "objectId": NEW}]})
        assert path == "/acme/Payments/_apis/git/repositories/api/diffs/commits"
        assert request.url.params["baseVersion"] == OLD and request.url.params["targetVersion"] == NEW
        if status != 200:
            return httpx.Response(status)
        index = int(request.url.params["$skip"]) // PAGE
        return httpx.Response(200, json={"changes": pages[index], "commonCommit": common, "behindCount": behind,
                                         "allChangesIncluded": all_included})

    return handler


def read(handler, cursor=OLD):
    return changes_since(PAYLOAD, ROOT, cursor, http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)),
                         request_budget=RequestBudget(20))


def test_changed_blobs_are_named_and_folders_skipped_across_pages():
    first = [change(f"/src/f{n}.cs") for n in range(PAGE - 1)] + [change("/src", folder=True)]
    second = [change("/new.env", "rename", original="/old.env")]
    changes = read(serve([first, second]))
    assert changes.paths[:2] == ["src/f0.cs", "src/f1.cs"] and changes.paths[-2:] == ["new.env", "old.env"]
    assert changes.removals and len(changes.paths) == PAGE - 1 + 2


def test_a_moved_merge_base_a_behind_count_or_a_missing_commit_is_rewritten():
    assert read(serve([[]], common="c" * 40)).rewritten
    assert read(serve([[]], behind=2)).rewritten
    assert read(serve([[]], status=404)).reason == "AZURE_DEVOPS_BASE_COMMIT_MISSING"


def test_a_diff_that_left_changes_out_is_read_as_unknown():
    assert read(serve([[change("/a.txt")]], all_included=False)).reason == "AZURE_DEVOPS_DIFF_INCOMPLETE"


@pytest.mark.parametrize("selected", ["main", "refs/heads/main", "HEAD", ""])
def test_changes_resolve_the_same_exact_branch_as_content_reads(selected):
    calls = []
    handler = serve([[]])

    def tracked(request):
        calls.append(request)
        if request.url.path.endswith("/refs"):
            assert request.url.params["filter"] == "heads/main"
        return handler(request)

    result = changes_since(PAYLOAD, {**ROOT, "ref": selected}, OLD,
        http_client=lambda: httpx.Client(transport=httpx.MockTransport(tracked)), request_budget=RequestBudget(10))
    assert result.head == NEW
    assert any(r.url.path.endswith("/api") for r in calls) is (selected in ("", "HEAD"))


def service_hook(event="git.push", org_url="https://dev.azure.com/acme/_git/api", **resource):
    body = {"publisherId": "tfs", "eventType": event, "resource": {
        "refUpdates": [{"name": "refs/heads/main", "oldObjectId": OLD, "newObjectId": NEW}],
        "repository": {"name": "API", "project": {"name": "payments"}, "remoteUrl": org_url,
                       "defaultBranch": "refs/heads/main"}, **resource}}
    return body


def test_a_git_push_hook_rereads_the_repository_it_names():
    from cremore_azure_provider.devops_changes import queue_changes

    root = {**ROOT, "resource_id": "r1"}
    assert queue_changes(service_hook(), {}, [root])["r1"].head == NEW
    assert queue_changes(service_hook(org_url="https://acme.visualstudio.com/Payments/_git/api"), {}, [root])
    assert queue_changes(service_hook(refUpdates=[{"name": "refs/heads/dev", "newObjectId": NEW}]), {}, [root]) == {}
    assert queue_changes(service_hook(refUpdates=[{"name": "refs/heads/main", "newObjectId": "0" * 40}]), {}, [root]) == {}


def test_another_organization_or_event_is_refused():
    import pytest

    from cremore.collectors.base import CollectorError
    from cremore_azure_provider.devops_changes import queue_changes

    root = {**ROOT, "resource_id": "r1"}
    with pytest.raises(CollectorError, match="EVENT_OUT_OF_SCOPE"):
        queue_changes(service_hook(org_url="https://dev.azure.com/contoso/_git/api"), {}, [root])
    with pytest.raises(CollectorError, match="EVENT_UNSUPPORTED_NOTIFICATION"):
        queue_changes(service_hook("workitem.updated"), {}, [root])
    assert queue_changes({"eventType": "git.push"}, {}, [root]) is None

@pytest.mark.parametrize("root", [ROOT, {**ROOT, "provider_resource_id": "acme/Payments/$", "resource_type": "AZURE_DEVOPS_TFVC"}],
                         ids=["git", "tfvc"])
@pytest.mark.parametrize("status", [503, 429])
def test_a_busy_or_throttled_server_ends_the_feeds_look_at_once_and_a_scan_still_retries(monkeypatch, status, root):
    import time
    from types import SimpleNamespace

    from cremore import http_client
    from cremore.collectors.base import CollectorError
    from cremore_azure_provider.devops_content import SourceHTTP

    sleeps, seen = [], []
    monkeypatch.setattr(http_client, "time", SimpleNamespace(monotonic=time.monotonic, time=time.time, sleep=sleeps.append))

    def busy(request):
        seen.append(request.url.path)
        return httpx.Response(status, headers={"Retry-After": "2"})

    with pytest.raises(CollectorError, match="SOURCE_UNAVAILABLE" if status == 503 else "SOURCE_RATE_LIMITED"):
        changes_since(PAYLOAD, root, "42" if root["provider_resource_id"].endswith("$") else OLD,
                      http_client=lambda: httpx.Client(transport=httpx.MockTransport(busy)), request_budget=RequestBudget(20))
    assert len(seen) == 1 and sleeps == []  # polled on the worker's control loop: no sleep, the cursor stays
    answers = [httpx.Response(status, headers={"Retry-After": "2"}), httpx.Response(200, json={"value": []})]
    scan = SourceHTTP(PAYLOAD, httpx.Client(transport=httpx.MockTransport(lambda _request: answers.pop(0))))
    assert scan.get("/Payments/_apis/git/repositories", params=scan.api)[0] == {"value": []} and sleeps == [2.0]
