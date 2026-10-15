"""Bitbucket rescans read only what changed since the commit the last complete run read."""

import uuid
from collections import Counter

import httpx
import pytest

from cremore.collectors.base import CollectorError, RequestBudget, RequestBudgetExceeded
from cremore.db.repository import InMemoryRepository
from cremore.scanning.orchestrator import Orchestrator
from cremore.scanning.service import ScanService
from cremore_atlassian_provider import bitbucket_changes, bitbucket_content
from cremore_atlassian_provider.bitbucket_content import Collector

C1, C2, C3, OTHER = "1" * 40, "2" * 40, "3" * 40, "9" * 40
TREES = {
    C1: {"a.txt": b"alpha one", "b.txt": b"bravo one", "dir/c.txt": b"charlie one", "dir/d.txt": b"delta one"},
    C2: {"a.txt": b"alpha one", "b.txt": b"bravo two", "dir/c.txt": b"charlie one", "dir/d.txt": b"delta one"},
    C3: {"a.txt": b"alpha three", "b.txt": b"bravo two", "dir/c.txt": b"charlie one", "dir/d.txt": b"delta one",
         "dir/e.txt": b"echo three"},
}


def changed(old, new, trees=TREES):
    """The two-tree diff a server reports: every path whose content differs or that exists on one side only."""
    before, after = trees[old], trees[new]
    return sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))


class Cloud:
    """Bitbucket Cloud 2.0 with a branch whose head a test moves; requests are counted by kind."""

    ROUTE = "/2.0/repositories/team/repo"

    def __init__(self, head=C1, *, merge_base=None, diff_status=200, diff_page=500, trees=TREES):
        self.head, self.merge_base, self.diff_status, self.diff_page = head, merge_base, diff_status, diff_page
        self.trees = trees
        self.requests, self.downloads = Counter(), []

    def handle(self, request):
        path, params = request.url.path, request.url.params
        assert request.headers["authorization"] == "Bearer t"
        if path == self.ROUTE:
            self.requests["head"] += 1
            return httpx.Response(200, json={"mainbranch": {"name": "main"}})
        if path == self.ROUTE + "/commit/main":
            self.requests["head"] += 1
            return httpx.Response(200, json={"hash": self.head})
        if path.startswith(self.ROUTE + "/merge-base/"):
            self.requests["diff"] += 1
            new, old = path.rsplit("/", 1)[1].split("..")
            if old not in self.trees:
                return httpx.Response(404)
            return httpx.Response(200, json={"hash": self.merge_base or old})
        if path.startswith(self.ROUTE + "/diffstat/"):
            self.requests["diff"] += 1
            if self.diff_status != 200:
                return httpx.Response(self.diff_status)
            new, old = path.rsplit("/", 1)[1].split("..")
            assert params["topic"] == "false"
            entries = [{"status": "modified", "old": {"path": p} if p in self.trees[old] else None,
                        "new": {"path": p} if p in self.trees[new] else None} for p in changed(old, new, self.trees)]
            page = int(params["page"])
            body = {"values": entries[(page - 1) * self.diff_page:page * self.diff_page]}
            if page * self.diff_page < len(entries):
                body["next"] = f"https://api.bitbucket.org{path}?page={page + 1}"
            return httpx.Response(200, json=body)
        prefix = f"{self.ROUTE}/src/{self.head}/"
        assert path.startswith(prefix), path
        rest = path.removeprefix(prefix)
        tree = self.trees[self.head]
        directories = {p.rsplit("/", 1)[0] for p in tree if "/" in p}
        if rest == "" or rest in directories:
            self.requests["listing"] += 1
            inside = [p for p in tree if (p.rsplit("/", 1)[0] if "/" in p else "") == rest]
            values = [{"type": "commit_directory", "path": d} for d in sorted(directories) if rest == ""]
            values += [{"type": "commit_file", "path": p} for p in sorted(inside)]
            return httpx.Response(200, json={"values": values})
        self.requests["download"] += 1
        self.downloads.append(rest)
        return httpx.Response(200, content=tree[rest])

    def collector(self, state=None, mode="DELTA", budget=None):
        payload = {"edition": "cloud", "base_url": "https://api.bitbucket.org", "workspace": "team", "repo": "repo",
                   "token": "t", "_lazy": True, "scan_mode": mode}
        if state is not None:
            payload["provider_state"] = state
        return Collector(payload, httpx.Client(transport=httpx.MockTransport(self.handle)), request_budget=budget)


def revisions(collector):
    """Each listed file's revision; lazy objects, so nothing is downloaded."""
    return {obj.resource.location: obj.resource.revision for obj in collector.collect()}


def test_a_full_read_names_every_file_by_the_head_and_starts_the_base():
    server = Cloud(C1)
    collector = server.collector(mode="BASELINE")
    assert revisions(collector) == dict.fromkeys(TREES[C1], C1)
    assert collector.provider_state == {"commit": C1, "base": C1}
    assert server.requests["diff"] == 0 and server.downloads == []


@pytest.mark.parametrize("server_type", ["cloud", "data_center"])
def test_a_git_name_the_scan_cannot_address_is_counted_unread_and_the_rest_is_scanned(server_type):
    # Git allows a backslash in a file name; the scan's path rule does not.
    trees = {C1: {**TREES[C1], "odd\\name.txt": b"unread"}}
    server = Cloud(C1, trees=trees) if server_type == "cloud" else DataCenter(C1, trees=trees)
    collector = server.collector(mode="BASELINE") if server_type == "cloud" else server.collector({}, "BASELINE")
    assert revisions(collector) == dict.fromkeys(TREES[C1], C1)
    assert collector.failed_objects == 1 and collector.listing_complete


def test_files_the_diff_leaves_out_keep_their_revision_across_runs():
    server = Cloud(C2)
    second = server.collector({"commit": C1, "base": C1})
    assert revisions(second) == {"a.txt": C1, "b.txt": C2, "dir/c.txt": C1, "dir/d.txt": C1}
    assert second.provider_state == {"commit": C2, "base": C1, "revisions": {C2: ["b.txt"]}}
    assert second.listed_paths == set(TREES[C2])  # the listing stays complete

    server.head = C3
    third = server.collector(second.provider_state)
    # b.txt keeps C2, the commit it was read at, though the diff now starts at C2.
    assert revisions(third) == {"a.txt": C3, "b.txt": C2, "dir/c.txt": C1, "dir/d.txt": C1, "dir/e.txt": C3}
    assert third.provider_state == {"commit": C3, "base": C1, "revisions": {C2: ["b.txt"], C3: ["a.txt", "dir/e.txt"]}}

    server.requests.clear()
    unmoved = server.collector(third.provider_state)
    assert revisions(unmoved) == {"a.txt": C3, "b.txt": C2, "dir/c.txt": C1, "dir/d.txt": C1, "dir/e.txt": C3}
    assert server.requests["diff"] == 0  # the head did not move: no diff is asked
    assert unmoved.provider_state == third.provider_state


@pytest.mark.parametrize("mode", ["RECONCILE", "BASELINE"])
def test_a_full_scan_never_reuses_carried_revisions_and_starts_a_new_base(mode):
    server = Cloud(C3)
    full = server.collector({"commit": C3, "base": C1, "revisions": {C2: ["b.txt"], C3: ["a.txt", "dir/e.txt"]}}, mode)
    assert revisions(full) == dict.fromkeys(TREES[C3], C3)
    assert full.provider_state == {"commit": C3, "base": C3} and server.requests["diff"] == 0


def test_a_file_that_no_longer_exists_leaves_the_state():
    collector = Cloud(C3).collector({"commit": C3, "base": C1,
                                     "revisions": {C2: ["b.txt"], C3: ["a.txt", "dir/e.txt", "gone.txt"]}})
    revisions(collector)
    assert collector.provider_state == {"commit": C3, "base": C1,
                                        "revisions": {C2: ["b.txt"], C3: ["a.txt", "dir/e.txt"]}}


def scan(repo, connection, server, state, mode="DELTA"):
    server.requests.clear()
    server.downloads.clear()
    collector = server.collector(state, mode)
    summary = ScanService(Orchestrator(repo)).run(collector, source_connection_id=connection)
    assert summary.objects_failed == 0 and summary.objects == len(server.trees[server.head])
    return collector.provider_state, sum(server.requests.values()), sorted(server.downloads)


def test_a_rescan_downloads_only_the_changed_files_measured_against_a_full_reread():
    repo, connection = InMemoryRepository(), uuid.uuid4()
    server = Cloud(C1)
    state, _requests, downloads = scan(repo, connection, server, None, "BASELINE")
    assert downloads == sorted(TREES[C1])

    server.head = C2
    # Before: without the kept commit every file is named by the new head, so every file is read again.
    _before_state, before_requests, before_downloads = scan(repo, connection, server, None)
    assert before_downloads == sorted(TREES[C2])

    # After: the same rescan from the state of the C1 run reads the one changed file.
    repo, connection = InMemoryRepository(), uuid.uuid4()
    server.head = C1
    state, _requests, _downloads = scan(repo, connection, server, None, "BASELINE")
    server.head = C2
    state, after_requests, after_downloads = scan(repo, connection, server, state)
    assert after_downloads == ["b.txt"]
    # Head (2) and listing (2) requests are the same; the diff (2) replaces three of the four downloads.
    assert (before_requests, after_requests) == (2 + 2 + 4, 2 + 2 + 2 + 1)

    server.head = C3
    state, third_requests, third_downloads = scan(repo, connection, server, state)
    assert third_downloads == ["a.txt", "dir/e.txt"] and third_requests == 2 + 2 + 2 + 2
    _state, unchanged_requests, unchanged = scan(repo, connection, server, state)
    assert unchanged == [] and unchanged_requests == 2 + 2  # no diff, no download


def test_request_counts_for_a_large_repository_with_one_changed_file():
    """Measured on 400 files in 8 directories: the rescan's requests before and after carry-forward."""
    big = {C1: {f"dir{i % 8}/file{i:03d}.txt": f"content {i}".encode() for i in range(400)}}
    big[C2] = {**big[C1], "dir3/file011.txt": b"content 11, edited"}
    counts = {}
    for label, keep in (("before", False), ("after", True)):
        repo, connection = InMemoryRepository(), uuid.uuid4()
        server = Cloud(C1, trees=big)
        state, _requests, _downloads = scan(repo, connection, server, None, "BASELINE")
        server.head = C2
        _state, counts[label], downloads = scan(repo, connection, server, state if keep else None)
        assert len(downloads) == (1 if keep else 400)
    # head 2 + listing 9 + 400 downloads, against head 2 + listing 9 + diff 2 + 1 download.
    assert counts == {"before": 411, "after": 14}


@pytest.mark.parametrize("state, mode, server_options, reason", [
    (None, "DELTA", {}, "no state kept"),
    ({}, "DELTA", {}, "empty state"),
    ({"commit": C1, "base": C1}, "BASELINE", {}, "a full read"),
    ({"commit": C1, "base": C1}, "RECONCILE", {}, "a full scan trusts no diff"),
    ({"commit": C1, "base": C1}, "EVENT", {}, "an event reads named files"),
    ({"commit": "not-a-commit", "base": C1}, "DELTA", {}, "damaged commit"),
    ({"commit": C1, "base": C1, "revisions": ["b.txt"]}, "DELTA", {}, "damaged revisions"),
    ({"commit": C1, "base": C1, "revisions": {"zz": ["b.txt"]}}, "DELTA", {}, "damaged revision commit"),
    ({"commit": C1, "base": C1, "revisions": {C1: [7]}}, "DELTA", {}, "damaged path"),
    ({"commit": OTHER, "base": C1}, "DELTA", {}, "the saved commit no longer exists"),
    ({"commit": C1, "base": C1}, "DELTA", {"merge_base": OTHER}, "history was rewritten (force push)"),
    ({"commit": C1, "base": C1}, "DELTA", {"diff_status": 555}, "the diff timed out"),
    ({"commit": C1, "base": C1}, "DELTA", {"diff_status": 500}, "the diff failed"),
    ({"commit": C1, "base": C1}, "DELTA", {"diff_status": 403}, "the diff was refused"),
])
def test_anything_uncertain_reads_every_file_at_the_head(state, mode, server_options, reason):
    server = Cloud(C2, **server_options)
    collector = server.collector(state, mode)
    assert revisions(collector) == dict.fromkeys(TREES[C2], C2), reason
    assert collector.provider_state == {"commit": C2, "base": C2}


def test_a_diff_past_its_page_bound_reads_every_file(monkeypatch):
    monkeypatch.setattr(bitbucket_changes, "MAX_DIFF_PAGES", 2)
    server = Cloud(C3, diff_page=1)  # three changed paths, one per page
    collector = server.collector({"commit": C1, "base": C1})
    assert revisions(collector) == dict.fromkeys(TREES[C3], C3)
    assert server.requests["diff"] == 1 + 2  # merge base, then two pages and no more


def test_a_state_too_large_to_keep_reads_every_file(monkeypatch):
    monkeypatch.setattr(bitbucket_content, "STATE_BYTES", 64)
    collector = Cloud(C2).collector({"commit": C1, "base": C1})
    assert revisions(collector) == dict.fromkeys(TREES[C2], C2)
    assert collector.provider_state == {"commit": C2, "base": C2}


def test_a_spent_request_budget_stops_the_run_instead_of_reading_everything():
    server = Cloud(C2)
    collector = server.collector({"commit": C1, "base": C1}, budget=RequestBudget(3))
    with pytest.raises(RequestBudgetExceeded):
        revisions(collector)
    assert not hasattr(collector, "provider_state")


def test_a_yielding_run_stops_at_the_diff_instead_of_reading_everything():
    class Yielding(RequestBudget):
        def consume(self):
            super().consume()
            if self.used > 2:  # the head is resolved; the run yields to a change scan at the diff
                raise CollectorError("YIELDED_TO_EVENT")

    server = Cloud(C2)
    collector = server.collector({"commit": C1, "base": C1}, budget=Yielding(100))
    with pytest.raises(CollectorError, match="YIELDED_TO_EVENT"):
        revisions(collector)
    assert server.requests["listing"] == 0 and not hasattr(collector, "provider_state")

class DataCenter:
    ROUTE = "/rest/api/1.0/projects/PAY/repos/app"

    def __init__(self, head, *, status=200, trees=TREES, cut=None):
        # ``cut``: the server's page.max.changes, below the connection's max_changes and not announced.
        self.head, self.status, self.trees, self.cut = head, status, trees, cut
        self.requests, self.downloads = Counter(), []

    def handle(self, request):
        path, params = request.url.path, request.url.params
        if path == self.ROUTE + "/branches/default":
            return httpx.Response(200, json={"latestCommit": self.head})
        if path == self.ROUTE + "/commits/" + self.head:
            return httpx.Response(200, json={"id": self.head})
        if path == self.ROUTE + "/changes":
            self.requests["diff"] += 1
            if self.status != 200:
                return httpx.Response(self.status)
            old, new, trees = params["since"], params["until"], self.trees
            values = [{"type": "MODIFY" if p in trees[old] and p in trees[new] else "ADD" if p in trees[new] else "DELETE",
                       "nodeType": "FILE", "path": {"toString": p}} for p in changed(old, new, trees)]
            return httpx.Response(200, json={"values": values[:self.cut], "isLastPage": True})
        if path == self.ROUTE + "/files":
            assert params["at"] == self.head
            return httpx.Response(200, json={"values": sorted(self.trees[self.head]), "isLastPage": True})
        if path.startswith(self.ROUTE + "/raw/"):
            key = path.removeprefix(self.ROUTE + "/raw/")
            self.downloads.append(key)
            return httpx.Response(200, content=self.trees[params["at"]][key])
        raise AssertionError(path)

    def collector(self, state, mode="DELTA", **options):
        payload = {"edition": "data_center", "base_url": "https://git.acme.test", "project": "PAY", "repo": "app",
                   "token": "t", "_lazy": True, "scan_mode": mode, "provider_state": state, **options}
        return Collector(payload, httpx.Client(transport=httpx.MockTransport(self.handle)))


def test_a_change_list_cut_without_notice_is_healed_by_the_next_full_scan():
    # Built at run time: a credential-shaped literal never sits in the source.
    secret = ("aws_access_key_id = " + "AKIA" + "IOSFODNN7EXAMPLQ\naws_secret_access_key = "
              + "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEZ\n").encode()
    trees = {C1: {"a.txt": b"one", "b.txt": b"two", "c.txt": b"three"},
             C2: {"a.txt": b"one!", "b.txt": b"two!", "c.txt": secret}}
    repo, connection = InMemoryRepository(), uuid.uuid4()
    server = DataCenter(C1, trees=trees, cut=2)

    def scan(state, mode):
        server.downloads.clear()
        collector = server.collector(state, mode)
        summary = ScanService(Orchestrator(repo)).run(collector, source_connection_id=connection)
        return collector.provider_state, summary.detections, sorted(server.downloads)

    state, found, downloads = scan({}, "BASELINE")
    assert (found, downloads) == (0, ["a.txt", "b.txt", "c.txt"])
    server.head = C2
    state, found, downloads = scan(state, "DELTA")
    # The cut list leaves c.txt out and a DELTA trusts it, as it trusts the change feed...
    assert (found, downloads) == (0, ["a.txt", "b.txt"])
    # ...until the next full scan, which reads every file at the head and starts a new base.
    state, found, downloads = scan(state, "RECONCILE")
    assert (found, downloads, state) == (1, ["c.txt"], {"commit": C2, "base": C2})


def test_data_center_keeps_revisions_from_its_changes_list():
    collector = DataCenter(C3).collector({"commit": C2, "base": C1, "revisions": {C2: ["b.txt"]}})
    assert revisions(collector) == {"a.txt": C3, "b.txt": C2, "dir/c.txt": C1, "dir/d.txt": C1, "dir/e.txt": C3}
    assert collector.provider_state == {"commit": C3, "base": C1, "revisions": {C2: ["b.txt"], C3: ["a.txt", "dir/e.txt"]}}


@pytest.mark.parametrize("options, status", [({"max_changes": 2}, 200), ({}, 404), ({}, 400), ({}, 500)])
def test_data_center_reads_everything_at_its_change_limit_or_when_the_list_fails(options, status):
    server = DataCenter(C3, status=status)
    collector = server.collector({"commit": C1, "base": C1}, **options)
    assert revisions(collector) == dict.fromkeys(TREES[C3], C3)
    assert collector.provider_state == {"commit": C3, "base": C3}


def test_the_worker_runtime_keeps_the_state_and_reads_only_what_changed():
    """End to end: a scope job's root state carries ``provider_state`` between runs of the real runtime."""
    from cremore.db.scan_store import ScanStore
    from cremore.domain.models import Connection, ScanJob, ScopeCatalog, ScopeProfile
    from cremore.scanning import scope
    from cremore.worker.factory import build_collector
    from cremore.worker.worker import JobWorker

    repo, server = InMemoryRepository(), Cloud(C1)
    config = {"workspace": "team", "edition": "cloud", "base_url": "https://api.bitbucket.org"}
    conn = repo.create_connection(Connection(provider="bitbucket", name="fixture", config=config))
    item = scope.resource("source", conn.id, "BITBUCKET_REPOSITORY", "team/repo", "team/repo", "team/repo", "bitbucket")
    auth = scope.auth_revision("source", conn)
    catalog = repo.save_catalog(ScopeCatalog(kind="source", connection_id=conn.id, snapshot_id="v1",
                                             auth_revision=auth, items=[item], completeness="COMPLETE"))
    profile = repo.create_scope_profile(ScopeProfile(
        kind="source", connection_id=conn.id, name="approved", state="READY", auth_revision=auth,
        catalog_snapshot_id="v1", budgets={"requests": 100_000, "bytes": 1 << 30, "seconds": 600},
        selected_roots=[{"resource_id": item["id"], "all_current_objects": True, "include_future_descendants": False}]))

    def collector(job):
        return build_collector(job.model_copy(update={"payload": {**job.payload, "token": "t"}}),
                               http_client_factory=lambda: httpx.Client(transport=httpx.MockTransport(server.handle)))

    worker = JobWorker(repo, collector_factory=collector)

    def run(mode):
        plan = scope.build_plan(profile, catalog, auth=profile.auth_revision, enabled=True)
        payload = scope.run_payload(repo.create_plan(plan), profile, config, "bitbucket")
        payload.update(mode=mode)
        job = repo.enqueue_job(ScanJob(kind="scope", connection_id=conn.id, payload=payload))
        server.downloads.clear()
        for _ in range(20):
            worker.process_next()
            if repo.get_job(job.id).status not in ("QUEUED", "RUNNING"):
                break
        assert repo.get_job(job.id).status == "SUCCEEDED"
        identity = scope.root_identity(conn.id, plan.roots[0])
        return sorted(server.downloads), ScanStore(repo).roots([identity])[identity]["provider_state"]

    assert run("BASELINE") == (sorted(TREES[C1]), {"commit": C1, "base": C1})
    server.head = C2
    assert run("DELTA") == (["b.txt"], {"commit": C2, "base": C1, "revisions": {C2: ["b.txt"]}})
    server.head = C3
    assert run("DELTA") == (["a.txt", "dir/e.txt"],
                            {"commit": C3, "base": C1, "revisions": {C2: ["b.txt"], C3: ["a.txt", "dir/e.txt"]}})
    # A full scan names every file by the head: the files whose result was kept under C1 or C2 are read again.
    assert run("RECONCILE") == (["b.txt", "dir/c.txt", "dir/d.txt"], {"commit": C3, "base": C3})
    assert run("DELTA") == ([], {"commit": C3, "base": C3})
