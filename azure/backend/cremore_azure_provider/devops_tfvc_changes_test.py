"""TFVC change feed by changeset, and TFVC items named by the changeset they last changed in."""

import base64
import hashlib
import uuid

import httpx
import pytest

from cremore.collectors.base import CollectorError, RequestBudget
from cremore.db.repository import InMemoryRepository
from cremore.scanning import changes as feeds
from cremore.scanning.orchestrator import Orchestrator
from cremore.scanning.service import ScanService
from cremore_azure_provider import devops_changes, devops_content, devops_source

PAYLOAD = {"token": "synthetic-pat", "organization": "acme", "project": "Payments"}
ROOT = {"resource_type": "AZURE_DEVOPS_TFVC", "provider_resource_id": "acme/Payments/$", "resource_id": "r1"}


def change(path, kind="edit", *, folder=False, renamed_from=None):
    item = {"path": path, "version": 1}
    if folder:
        item["isFolder"] = True
    out = {"item": item, "changeType": kind}
    if renamed_from:
        out["mergeSources"] = [{"serverItem": renamed_from, "isRename": True}]
    return out


class Project:
    """A TFVC project whose changesets (id -> changes) a test writes; requests are recorded."""

    def __init__(self, changesets, *, inclusive=True):
        self.changesets, self.inclusive = changesets, inclusive
        self.requests = []

    def handle(self, request):
        self.requests.append(request)
        path, params = request.url.raw_path.decode().split("?", 1)[0], request.url.params
        assert request.url.host == "dev.azure.com" and params["api-version"] == "7.1"
        if path == "/acme/Payments/_apis/tfvc/changesets":
            assert params["searchCriteria.itemPath"] == "$/Payments" and params["$orderby"] == "id desc"
            since = int(params.get("searchCriteria.fromId", 0))
            ids = sorted((i for i in self.changesets if i > since or self.inclusive and i == since), reverse=True)
            return httpx.Response(200, json={"value": [{"changesetId": i} for i in ids[:int(params["$top"])]]})
        prefix = "/acme/_apis/tfvc/changesets/"
        assert path.startswith(prefix) and path.endswith("/changes"), path
        found = self.changesets[int(path.removeprefix(prefix).split("/")[0])]
        skip, top = int(params["$skip"]), int(params["$top"])
        return httpx.Response(200, json={"value": found[skip:skip + top]})

    def read(self, cursor, root=ROOT, budget=20):
        return devops_source.changes_since(PAYLOAD, root, cursor, request_budget=RequestBudget(budget),
                                           http_client=lambda: httpx.Client(transport=httpx.MockTransport(self.handle)))


HISTORY = {
    42: [change("$/Payments/src/app.config", "add")],
    43: [change("$/Payments/src/app.config")],
    44: [change("$/Payments/docs", "add", folder=True), change("$/Payments/docs/new.md", "add"),
         change("$/Other/elsewhere.txt")],
    45: [change("$/Payments/src/app.config", "edit, encoding")],
}


def test_a_first_look_records_the_newest_changeset():
    project = Project(HISTORY)
    assert project.read(None).head == "45" and len(project.requests) == 1


def test_no_newer_changeset_is_unchanged_for_one_request():
    project = Project(HISTORY)
    answer = project.read("45")
    assert (answer.head, answer.paths, answer.rewritten) == ("45", [], False) and len(project.requests) == 1


def test_files_changed_under_the_root_are_named_and_another_projects_are_not():
    project = Project(HISTORY)
    answer = project.read("42")
    assert answer.head == "45" and answer.paths == ["src/app.config", "docs/new.md"] and not answer.removals
    # One listing of changesets, then one page of changes for each of 43, 44 and 45.
    assert len(project.requests) == 4


def test_a_rename_names_both_paths_and_a_delete_or_rename_is_a_removal():
    project = Project({**HISTORY, 46: [change("$/Payments/new.cfg", "rename, edit", renamed_from="$/Payments/old.cfg")],
                       47: [change("$/Payments/gone.txt", "delete")]})
    answer = project.read("45")
    assert answer.paths == ["new.cfg", "old.cfg", "gone.txt"] and answer.removals and answer.head == "47"
    # A removal reads the whole root, as for Git (only GitHub confirms a missing path).
    assert feeds.work_for(ROOT, answer) == ("DELTA", None)
    plain = Project(HISTORY).read("42")
    assert feeds.work_for(ROOT, plain) == ("EVENT", ["src/app.config", "docs/new.md"])


@pytest.mark.parametrize("kind", ["rename", "delete", "branch", "undelete", "merge, branch", "rollback"])
def test_a_folder_change_that_hides_its_files_reads_the_whole_root(kind):
    answer = Project({**HISTORY, 46: [change("$/Payments/src", kind, folder=True)]}).read("45")
    assert answer.paths is None and answer.reason == "AZURE_DEVOPS_TFVC_FOLDER_CHANGE" and answer.head == "46"


def test_a_change_to_the_project_root_itself_reads_the_whole_root():
    answer = Project({**HISTORY, 46: [change("$/payments", "rename", folder=True)]}).read("45")
    assert answer.paths is None and answer.reason == "AZURE_DEVOPS_TFVC_FOLDER_CHANGE"


def test_more_changesets_than_the_bound_read_the_whole_root(monkeypatch):
    monkeypatch.setattr(devops_changes, "MAX_CHANGESETS", 2)
    answer = Project(HISTORY, inclusive=False).read("42")
    assert answer.paths is None and answer.reason == "AZURE_DEVOPS_TFVC_CHANGESET_LIMIT" and answer.head == "45"
    # The cursor's own changeset in the answer shows that nothing older was left out.
    assert Project({42: [], 44: HISTORY[44], 45: HISTORY[45]}).read("42").paths == ["docs/new.md", "src/app.config"]


def test_changes_are_paged_and_bounded():
    many = [change(f"$/Payments/data/f{n:03d}.txt") for n in range(150)]
    project = Project({42: [], 43: many})
    answer = project.read("42")
    assert answer.paths == [f"data/f{n:03d}.txt" for n in range(150)]
    assert [r.url.params.get("$skip") for r in project.requests[1:]] == ["0", "100"]
    huge = Project({42: [], 43: [change(f"$/Payments/f{n}") for n in range(devops_changes.CHANGE_LIMIT)]})
    assert huge.read("42", budget=40).reason == "AZURE_DEVOPS_TFVC_CHANGE_LIMIT"


def test_a_damaged_cursor_reads_the_whole_root():
    answer = Project(HISTORY).read("not-a-changeset")
    assert answer.paths is None and answer.reason == "AZURE_DEVOPS_TFVC_CURSOR_INVALID" and answer.head == "45"


def test_a_path_whose_case_would_change_the_scope_decision_reads_the_whole_root():
    project = Project({42: [], 43: [change("$/Payments/SRC/app.config")]})
    answer = project.read("42", root={**ROOT, "paths": ["src"]})
    assert answer.paths is None and answer.reason == "AZURE_DEVOPS_TFVC_PATH_CASE"
    same = project.read("42", root={**ROOT, "paths": ["SRC"]})
    assert same.paths == ["SRC/app.config"]


def test_a_malformed_answer_fails_this_root_only():
    def broken(request):
        return httpx.Response(200, json={"value": [{"changesetId": "45"}]})

    out = feeds.read_changes(PAYLOAD, [ROOT], {"r1": {"cursor": "42"}}, request_budget=RequestBudget(5),
                             http_client=lambda: httpx.Client(transport=httpx.MockTransport(broken)))
    assert isinstance(out["r1"], CollectorError) and out["r1"].code == "AZURE_DEVOPS_CHANGESETS_MALFORMED"


def test_the_platform_feed_reaches_tfvc_roots():
    assert feeds.supports("AZURE_DEVOPS_TFVC")
    project = Project(HISTORY)
    out = feeds.read_changes(PAYLOAD, [ROOT], {"r1": {"cursor": "43"}}, request_budget=RequestBudget(10),
                             http_client=lambda: httpx.Client(transport=httpx.MockTransport(project.handle)))
    assert out["r1"].head == "45" and out["r1"].paths == ["docs/new.md", "src/app.config"]


class Tree:
    """The TFVC item listing at the latest changeset and item reads, counted."""

    def __init__(self, latest, items, *, hashes=False):
        self.latest, self.items = latest, items  # path -> (last changeset, content)
        self.hashes = hashes  # the listing's MD5 (hashValue): each file's own when True, this one for all when a str
        self.reads = []

    def handle(self, request):
        params = request.url.params
        if request.url.raw_path.decode().split("?", 1)[0].endswith("/changesets"):
            return httpx.Response(200, json={"value": [{"changesetId": self.latest}]})
        if params.get("scopePath"):
            assert params["versionDescriptor.version"] == str(self.latest)
            return httpx.Response(200, json={"value": [{"path": "$/Payments", "isFolder": True}] + [
                {"path": "$/Payments/" + key, "size": len(data), "version": last,
                 **({"hashValue": self.hashes if isinstance(self.hashes, str) else _md5(data)} if self.hashes else {})}
                for key, (last, data) in self.items.items()]})
        key = params["path"].removeprefix("$/Payments/")
        self.reads.append(key)
        return httpx.Response(200, content=self.items[key][1])

    def collector(self):
        payload = devops_content.Collector.root_payload(devops_source.job_payload(
            {"organization": "acme", "project": "Payments", "version_control": "tfvc"}) | {"token": "synthetic-pat"},
            "acme/Payments/$")
        return devops_content.Collector({**payload, "_lazy": True}, httpx.Client(transport=httpx.MockTransport(self.handle)))


def _md5(data):
    return base64.b64encode(hashlib.md5(data, usedforsecurity=False).digest()).decode()


def _name(key, changeset):
    return f"{changeset}:path:{hashlib.sha256(key.encode()).hexdigest()}"


def test_items_are_named_by_the_changeset_they_last_changed_in_and_their_path():
    tree = Tree(45, {"src/app.config": (43, b"a=1"), "src/other.config": (43, b"b=2"), "docs/new.md": (44, b"doc"),
                     "odd/future.txt": (99, b"x"), "odd/none.txt": (None, b"y")})
    named = {obj.resource.location: obj.resource.revision for obj in tree.collector().collect()}
    assert named == {"src/app.config": _name("src/app.config", 43), "src/other.config": _name("src/other.config", 43),
                     "docs/new.md": _name("docs/new.md", 44), "odd/future.txt": "", "odd/none.txt": ""}
    # Two files of one changeset never share a cached result; an item without a usable changeset is read at once.
    assert named["src/app.config"] != named["src/other.config"]
    assert sorted(tree.reads) == ["odd/future.txt", "odd/none.txt"]


def test_two_files_whose_listed_md5s_collide_are_never_answered_by_one_read():
    # Anyone who can check in can make a file whose MD5 equals a clean file's: the listing's hashValue
    # must not name the content, or the second file would take the first's cached result unread.
    tree = Tree(45, {"src/app.config": (43, b"a=1"), "src/other.config": (43, b"secret")}, hashes=_md5(b"a=1"))
    named = {obj.resource.location: obj.resource.revision for obj in tree.collector().collect()}
    assert named == {"src/app.config": _name("src/app.config", 43), "src/other.config": _name("src/other.config", 43)}
    repo, connection = InMemoryRepository(), uuid.uuid4()
    result = ScanService(Orchestrator(repo)).run(tree.collector(), source_connection_id=connection)
    assert result.objects == 2 and result.reused == 0 and sorted(tree.reads) == ["src/app.config", "src/other.config"]


def test_paths_that_differ_only_after_case_folding_never_share_a_name():
    # U+212A KELVIN SIGN lower-cases to "k": folded, these two items of one changeset would share a cache entry.
    tree = Tree(45, {"\u212a.txt": (43, b"first"), "k.txt": (43, b"second")})
    named = {obj.resource.location: obj.resource.revision for obj in tree.collector().collect()}
    assert named["\u212a.txt"] != named["k.txt"] and named["k.txt"] == _name("k.txt", 43)


def test_an_unchanged_item_is_answered_by_the_cache_on_the_next_scan():
    repo, connection = InMemoryRepository(), uuid.uuid4()
    tree = Tree(45, {"src/app.config": (43, b"a=1"), "docs/new.md": (44, b"doc")})
    first = ScanService(Orchestrator(repo)).run(tree.collector(), source_connection_id=connection)
    assert first.objects == 2 and sorted(tree.reads) == ["docs/new.md", "src/app.config"]
    tree.reads.clear()
    tree.latest, tree.items["docs/new.md"] = 46, (46, b"doc, edited")
    second = ScanService(Orchestrator(repo)).run(tree.collector(), source_connection_id=connection)
    assert second.objects == 2 and second.reused == 1 and tree.reads == ["docs/new.md"]
