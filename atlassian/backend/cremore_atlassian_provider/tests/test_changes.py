"""Bitbucket and Confluence change feeds against synthetic servers (design 4.3 re-read rules)."""

import datetime as dt

import httpx
import pytest

from cremore.collectors.base import CollectorError, RequestBudget
from cremore_atlassian_provider.bitbucket_changes import changes_since
from cremore_atlassian_provider.confluence_changes import changes_since_batch

OLD, NEW = "a" * 40, "b" * 40
CLOUD = {"token": "synthetic", "edition": "cloud", "base_url": "https://api.bitbucket.org", "workspace": "acme"}
DC = {"token": "synthetic", "edition": "data_center", "base_url": "https://git.acme.test", "project": "PAY"}


def client(handler):
    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def cloud(diffstat_pages, *, base=OLD, statuses=None):
    statuses = statuses or {}

    def handler(request):
        path = request.url.path
        if path == "/2.0/repositories/acme/app/commit/main":
            return httpx.Response(200, json={"hash": NEW})
        if path == f"/2.0/repositories/acme/app/merge-base/{NEW}..{OLD}":
            return httpx.Response(statuses.get("base", 200), json={"hash": base})
        assert path == f"/2.0/repositories/acme/app/diffstat/{NEW}..{OLD}"
        assert request.url.params["topic"] == "false"
        if statuses.get("diffstat"):
            return httpx.Response(statuses["diffstat"])
        page = int(request.url.params["page"])
        body = {"values": diffstat_pages[page - 1]}
        if page < len(diffstat_pages):
            body["next"] = f"https://api.bitbucket.org/2.0/repositories/acme/app/diffstat/x?page={page + 1}"
        return httpx.Response(200, json=body)

    return handler


def read_cloud(handler):
    return changes_since(CLOUD, {"provider_resource_id": "acme/app", "ref": "main"}, OLD,
                         http_client=client(handler), request_budget=RequestBudget(20))


def test_cloud_diffstat_pages_name_the_changed_files():
    changes = read_cloud(cloud([[{"status": "modified", "old": {"path": "a.env"}, "new": {"path": "a.env"}}],
                                [{"status": "renamed", "old": {"path": "old.txt"}, "new": {"path": "new.txt"}}]]))
    assert changes.paths == ["a.env", "new.txt", "old.txt"] and changes.removals


def test_cloud_555_reads_the_whole_repository_and_a_moved_merge_base_rewrites():
    assert read_cloud(cloud([], statuses={"diffstat": 555})).reason == "BITBUCKET_DIFF_TIMEOUT"
    assert read_cloud(cloud([], base="c" * 40)).rewritten
    assert read_cloud(cloud([], statuses={"base": 404})).reason == "BITBUCKET_BASE_COMMIT_MISSING"


def data_center(pages, *, status=200, limit_hint=None):
    def handler(request):
        path = request.url.path
        if path == "/rest/api/1.0/projects/PAY/repos/app/commits/main":
            return httpx.Response(200, json={"id": NEW})
        assert path == "/rest/api/1.0/projects/PAY/repos/app/changes"
        assert request.url.params["since"] == OLD and request.url.params["until"] == NEW
        if status != 200:
            return httpx.Response(status)
        start = int(request.url.params["start"])
        index = next(i for i, (begin, _values, _last) in enumerate(pages) if begin == start)
        begin, values, last = pages[index]
        body = {"values": values, "isLastPage": last}
        if not last:
            body["nextPageStart"] = begin + len(values)
        return httpx.Response(200, json=body)

    return handler


def read_dc(handler, **payload):
    return changes_since({**DC, **payload}, {"provider_resource_id": "PAY/app", "ref": "main"}, OLD,
                         http_client=client(handler), request_budget=RequestBudget(20))


def entry(path, kind="MODIFY", node="FILE", src=None):
    value = {"type": kind, "nodeType": node, "path": {"toString": path}}
    if src:
        value["srcPath"] = {"toString": src}
    return value


def test_data_center_changes_through_the_last_page_and_unknown_is_read():
    changes = read_dc(data_center([(0, [entry("a.env"), entry("b.txt", "UNKNOWN")], False),
                                   (2, [entry("new.txt", "MOVE", src="old.txt")], True)]))
    assert changes.paths == ["a.env", "b.txt", "new.txt", "old.txt"] and changes.removals


def test_a_git_name_the_scan_cannot_address_rereads_the_root_instead_of_failing_the_feed():
    # Git allows a backslash in a file name; the scan's path rule does not.
    odd = "dir\\name.env"
    cloud_changes = read_cloud(cloud([[{"status": "modified", "old": {"path": odd}, "new": {"path": odd}}]]))
    dc_changes = read_dc(data_center([(0, [entry("a.env"), entry(odd)], True)]))
    for changes in (cloud_changes, dc_changes):
        assert (changes.paths, changes.reason) == (None, "BITBUCKET_PATH_UNSUPPORTED")


@pytest.mark.parametrize("pages, payload, reason", [
    ([(0, [entry("dir", node="DIRECTORY")], True)], {}, "BITBUCKET_DIRECTORY_CHANGE"),
    ([(0, [entry(f"f{n}") for n in range(3)], False)], {"max_changes": 3}, "BITBUCKET_CHANGE_LIMIT_REACHED"),
    ([(0, [entry("a")], False), (0, [entry("a")], False)], {}, None),
])
def test_data_center_rereads_at_the_limit_on_a_directory_or_an_unfinished_list(pages, payload, reason):
    if reason is None:
        # A page that points back to its own start never reaches the last page.
        def handler(request):
            if request.url.path.endswith("/commits/main"):
                return httpx.Response(200, json={"id": NEW})
            return httpx.Response(200, json={"values": [entry("a")], "isLastPage": False, "nextPageStart": 0})
        assert read_dc(handler).reason == "BITBUCKET_CHANGES_INCOMPLETE"
        return
    assert read_dc(data_center(pages), **payload).reason == reason


def test_data_center_missing_old_commit_is_rewritten():
    assert read_dc(data_center([], status=404)).rewritten


CONFLUENCE = {"token": "synthetic", "edition": "cloud", "base_url": "https://acme.atlassian.net/wiki", "space": "98765"}


def test_confluence_one_search_names_the_pages_whose_version_moved():
    seen = []

    def handler(request):
        seen.append(request)
        if request.url.path == "/wiki/api/v2/spaces/98765":
            return httpx.Response(200, json={"id": "98765", "key": "ENG"})
        assert request.url.path == "/wiki/rest/api/content/search"
        # CQL's space field matches the key; a Cloud source stores the numeric space ID.
        assert 'space = "ENG"' in request.url.params["cql"] and "now(" in request.url.params["cql"]
        return httpx.Response(200, json={"results": [{"id": "11", "version": {"number": 4}},
                                                     {"id": "22", "version": {"number": 7}}], "_links": {}})

    roots = [{"resource_id": rid, "provider_resource_id": pid} for rid, pid in
             (("r11", "11"), ("r22", "22"), ("r33", "33"), ("new", "44"))]
    checked = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=10)
    states = {"r11": {"cursor": "v3", "checked_at": checked}, "r22": {"cursor": "v7", "checked_at": checked},
              "r33": {"cursor": "v1", "checked_at": checked}}
    answers = changes_since_batch(CONFLUENCE, roots, states, http_client=client(handler), request_budget=RequestBudget(5))
    assert len(seen) == 2  # the space's key, then one search
    assert (answers["r11"].head, answers["r11"].paths) == ("v4", None)
    assert answers["r22"].paths == [] and answers["r33"].head == "v1"
    assert answers["new"].head == "seen"  # a first look reads nothing
    # Data Center stores the key itself: one search, no space lookup.
    seen.clear()
    dc = {**CONFLUENCE, "edition": "data_center", "base_url": "https://wiki.acme.test", "space": "ENG"}

    def dc_handler(request):
        seen.append(request)
        assert request.url.path == "/rest/api/content/search" and 'space = "ENG"' in request.url.params["cql"]
        return httpx.Response(200, json={"results": [{"id": "11", "version": {"number": 4}}], "_links": {}})

    answers = changes_since_batch(dc, roots, states, http_client=client(dc_handler), request_budget=RequestBudget(5))
    assert len(seen) == 1 and answers["r11"].head == "v4"


def test_confluence_cloud_space_without_a_key_fails_the_look():
    def handler(request):
        return httpx.Response(200, json={"id": "98765"})

    states = {"r1": {"cursor": "v1", "checked_at": dt.datetime.now(dt.UTC) - dt.timedelta(minutes=10)}}
    with pytest.raises(CollectorError, match="CONFLUENCE_SPACE_MALFORMED"):
        changes_since_batch(CONFLUENCE, [{"resource_id": "r1", "provider_resource_id": "1"}], states,
                            http_client=client(handler), request_budget=RequestBudget(5))


def test_confluence_unchecked_for_a_week_reads_every_page_again():
    roots = [{"resource_id": "r1", "provider_resource_id": "1"}]
    states = {"r1": {"cursor": "v1", "checked_at": dt.datetime.now(dt.UTC) - dt.timedelta(days=8)}}
    answer = changes_since_batch(CONFLUENCE, roots, states, http_client=None, request_budget=None)["r1"]
    assert answer.paths is None and answer.reason == "CONFLUENCE_WINDOW_TOO_OLD"


CLOUD_ROOT = {"resource_id": "r1", "resource_type": "BITBUCKET_REPOSITORY", "provider_resource_id": "acme/app", "ref": ""}
DC_ROOT = {**CLOUD_ROOT, "provider_resource_id": "PAY/app", "ref": "refs/heads/main"}


def cloud_push(*changes):
    return {"push": {"changes": list(changes)}, "repository": {"full_name": "acme/app"}}


def branch(name, *, forced=False):
    return {"new": {"type": "branch", "name": name, "target": {"hash": NEW}}, "old": {"type": "branch", "name": name},
            "forced": forced, "truncated": False}


def test_cloud_push_rereads_the_repository_and_a_forced_one_from_scratch():
    from cremore_atlassian_provider.bitbucket_changes import queue_changes

    assert queue_changes(cloud_push(branch("main")), {}, [CLOUD_ROOT])["r1"].head == NEW
    assert queue_changes(cloud_push(branch("main", forced=True)), {}, [CLOUD_ROOT])["r1"].rewritten
    # A deleted branch or a tag names no new content.
    assert queue_changes(cloud_push({"new": None, "old": {"type": "branch", "name": "x"}}), {}, [CLOUD_ROOT]) == {}
    assert queue_changes(cloud_push({"new": {"type": "tag", "name": "v1"}}), {}, [CLOUD_ROOT]) == {}


def test_data_center_refs_changed_matches_the_read_branch_only():
    from cremore_atlassian_provider.bitbucket_changes import queue_changes

    def refs_changed(ref, kind="UPDATE"):
        return {"eventKey": "repo:refs_changed", "repository": {"slug": "app", "project": {"key": "PAY"}},
                "changes": [{"ref": {"id": ref}, "refId": ref, "fromHash": OLD, "toHash": NEW, "type": kind}]}

    assert queue_changes(refs_changed("refs/heads/main"), {}, [DC_ROOT])["r1"].head == NEW
    assert queue_changes(refs_changed("refs/heads/feature"), {}, [DC_ROOT]) == {}
    assert queue_changes(refs_changed("refs/heads/main", "DELETE"), {}, [DC_ROOT]) == {}
    with pytest.raises(CollectorError, match="EVENT_OUT_OF_SCOPE"):
        queue_changes(cloud_push(branch("main")) | {"repository": {"full_name": "acme/other"}}, {}, [CLOUD_ROOT])
    assert queue_changes({"eventKey": "pr:opened", "repository": {}}, {}, [DC_ROOT]) is None

@pytest.fixture
def sleeps(monkeypatch):
    """bounded_request's sleeps, recorded instead of slept."""
    import time
    from types import SimpleNamespace

    from cremore import http_client

    slept = []
    monkeypatch.setattr(http_client, "time", SimpleNamespace(monotonic=time.monotonic, time=time.time, sleep=slept.append))
    return slept


@pytest.mark.parametrize("status", [503, 429])
def test_a_busy_or_throttled_server_ends_each_feed_look_at_once(sleeps, status):
    seen = []

    def busy(request):
        seen.append(request.url.path)
        return httpx.Response(status, headers={"Retry-After": "2"})

    # The feeds are polled on the worker's control loop: the look fails at once and its cursor stays.
    for payload, owner in ((CLOUD, "acme/app"), (DC, "PAY/app")):
        with pytest.raises(CollectorError, match="SOURCE_UNAVAILABLE" if status == 503 else "SOURCE_RATE_LIMITED"):
            changes_since(payload, {"provider_resource_id": owner, "ref": "main"}, OLD, http_client=client(busy),
                          request_budget=RequestBudget(20))
    states = {"r1": {"cursor": "v1", "checked_at": dt.datetime.now(dt.UTC) - dt.timedelta(minutes=10)}}
    with pytest.raises(CollectorError, match="SOURCE_UNAVAILABLE" if status == 503 else "SOURCE_RATE_LIMITED"):
        changes_since_batch(CONFLUENCE, [{"resource_id": "r1", "provider_resource_id": "1"}], states,
                            http_client=client(busy), request_budget=RequestBudget(5))
    assert len(seen) == 3 and sleeps == []


def test_a_scan_through_the_same_clients_still_retries_a_busy_server(sleeps):
    from cremore_atlassian_provider import bitbucket_content, confluence_content

    for module, payload in ((bitbucket_content, CLOUD), (confluence_content, CONFLUENCE)):
        answers = [httpx.Response(503), httpx.Response(200, json={"ok": True})]
        http = module.SourceHTTP(payload, client(lambda _request, answers=answers: answers.pop(0))())
        assert http.get("/anything")[0] == {"ok": True} and answers == []
    assert sleeps == [1.0, 1.0]
