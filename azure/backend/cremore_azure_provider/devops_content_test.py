"""Azure DevOps Services Git listing and reads through synthetic JSON responses only."""

import base64
import weakref

import httpx
import pytest

from cremore.collectors.base import CollectorError
from cremore_azure_provider import devops_content, devops_source

TOKEN = "synthetic-devops-pat"
COMMIT = "a" * 40
REPO = "/acme/Platform%20Team/_apis/git/repositories/api"


def http(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def payload(**config):
    return devops_source.job_payload({"organization": "acme", "project": "Platform Team", **config}) | {"token": TOKEN}


def repository(handle_blob=None, *, refs=None, items=None, disabled=False):
    calls = []

    def handle(request):
        calls.append(request)
        assert request.headers["authorization"] == "Basic " + base64.b64encode((":" + TOKEN).encode()).decode()
        assert request.url.host == "dev.azure.com" and request.url.params["api-version"] == "7.1"
        path = request.url.raw_path.decode().split("?", 1)[0]
        if path == REPO:
            return httpx.Response(200, json={"name": "api", "defaultBranch": "refs/heads/main", "isDisabled": disabled})
        if path == REPO + "/refs":
            assert request.url.params["filter"] == "heads/main"
            return httpx.Response(200, json={"value": refs if refs is not None else [
                {"name": "refs/heads/main-old", "objectId": "b" * 40}, {"name": "refs/heads/main", "objectId": COMMIT}]})
        if path == REPO + "/items":
            assert request.url.params["versionDescriptor.version"] == COMMIT
            assert request.url.params["recursionLevel"] == "Full"
            return httpx.Response(200, json={"value": items if items is not None else [
                {"path": "/", "gitObjectType": "tree", "objectId": "c" * 40},
                {"path": "/src", "gitObjectType": "tree", "objectId": "d" * 40},
                {"path": "/src/app.env", "gitObjectType": "blob", "objectId": "1" * 40},
                {"path": "/docs/readme.md", "gitObjectType": "blob", "objectId": "2" * 40}]})
        if path.startswith(REPO + "/blobs/"):
            assert request.url.params["$format"] == "octetstream"
            return (handle_blob or (lambda request: httpx.Response(200, content=b"SYNTHETIC=value")))(request)
        raise AssertionError(path)

    return handle, calls


def test_the_default_branch_is_pinned_exactly_and_blobs_are_read_by_their_ids():
    handle, calls = repository()
    collector = devops_content.build(payload(repository="api", paths=["src"]), http(handle))
    objects = list(collector.collect())
    assert [(item.resource.resource, item.resource.location, item.resource.version_id) for item in objects] == [
        ("acme/Platform Team/api", "src/app.env", COMMIT)]
    assert objects[0].data == b"SYNTHETIC=value" and collector.listing_complete
    assert [request.url.raw_path.decode().split("?")[0].rsplit("/", 1)[-1] for request in calls][-1] == "1" * 40


@pytest.mark.parametrize("selected", ["main", "refs/heads/main", "HEAD", ""])
def test_scope_branch_selection_cannot_be_rebound_to_a_prefixed_or_head_named_branch(selected):
    handle, calls = repository(refs=[
        {"name": "refs/heads/refs/heads/main", "objectId": "b" * 40},
        {"name": "refs/heads/HEAD", "objectId": "c" * 40},
        {"name": "refs/heads/main", "objectId": COMMIT},
    ])
    root = {"resource_type": "AZURE_DEVOPS_REPOSITORY", "provider_resource_id": "acme/Platform Team/api",
            "ref": selected, "paths": ["src"]}
    collector = devops_source.build_root(None, payload(), root, http_client_factory=lambda: http(handle))
    [item] = list(collector.collect())
    assert item.resource.version_id == COMMIT
    assert [r.url.params["filter"] for r in calls if r.url.path.endswith("/refs")] == ["heads/main"]


def test_an_explicit_full_ref_does_not_accept_a_different_branch_when_the_selected_one_is_absent():
    handle, calls = repository(refs=[{"name": "refs/heads/refs/heads/main", "objectId": "b" * 40}])
    collector = devops_content.build({**payload(repository="api"), "ref": "refs/heads/main"}, http(handle))
    with pytest.raises(CollectorError, match="AZURE_DEVOPS_COMMIT_MALFORMED"):
        list(collector.collect())
    assert not collector.listing_complete
    assert not any("/items" in r.url.path or "/blobs/" in r.url.path for r in calls)


@pytest.mark.parametrize("selected", ["refs/tags/main", "refs/pull/1/merge", "refs/heads/"])
def test_unsupported_or_empty_ref_namespaces_never_become_branch_names(selected):
    handle, calls = repository()
    collector = devops_content.build({**payload(repository="api"), "ref": selected}, http(handle))
    with pytest.raises(CollectorError, match="AZURE_DEVOPS_COMMIT_MALFORMED"):
        list(collector.collect())
    assert not any(r.url.path.endswith("/refs") for r in calls)


# Past the 8 MiB JSON cap of a listing response.
TOO_LARGE = b" " * ((8 << 20) + 1)


def test_a_listing_past_the_response_cap_is_read_folder_by_folder():
    # Second review 2026-09-26: one Full listing of a large repository failed the whole scan.
    files = {"/root.env": "1", "/src/main.env": "2", "/src/app/app.env": "3", "/src/app/deep/x.env": "4", "/docs/readme.md": "5"}
    folders = ["/", "/src", "/src/app", "/src/app/deep", "/docs"]
    handle_repository, _ = repository()
    listings = []

    def handle(request):
        path, params = request.url.raw_path.decode().split("?", 1)[0], request.url.params
        if path != REPO + "/items":
            return handle_repository(request)
        assert params["versionDescriptor.version"] == COMMIT and params["versionDescriptor.versionType"] == "commit"
        scope, level = params["scopePath"], params["recursionLevel"]
        listings.append((scope, level))
        if level == "Full" and scope in ("/", "/src"):
            return httpx.Response(200, content=TOO_LARGE)
        below = lambda item: item != scope and item.startswith(scope.rstrip("/") + "/") and (
            level == "Full" or "/" not in item[len(scope.rstrip("/")) + 1:])
        return httpx.Response(200, json={"value": [{"path": scope, "gitObjectType": "tree"}]
            + [{"path": item, "gitObjectType": "tree"} for item in folders if below(item)]
            + [{"path": item, "gitObjectType": "blob", "objectId": blob * 40} for item, blob in files.items() if below(item)]})

    collector = devops_content.build(payload(repository="api", excluded_paths=["docs"]), http(handle))
    assert sorted(item.resource.location for item in collector.collect()) == [
        "root.env", "src/app/app.env", "src/app/deep/x.env", "src/main.env"]
    assert collector.listing_complete and listings == [
        ("/", "Full"), ("/", "OneLevel"), ("/src", "Full"), ("/src", "OneLevel"), ("/src/app", "Full"), ("/docs", "Full")]


def test_split_listing_releases_the_parent_rows_before_reading_a_child():
    class Rows(list):
        pass

    retained = []
    collector = devops_content.Collector(payload(repository="api"), http(lambda _: None))

    def get(_route, *, params):
        scope = params["scopePath"]
        if scope != "/":
            assert retained[0]() is None
            return {"value": []}, {}
        if params["recursionLevel"] == "Full":
            raise CollectorError("SOURCE_RESPONSE_TOO_LARGE")
        rows = Rows([{"path": "/src", "gitObjectType": "tree"}])
        retained.append(weakref.ref(rows))
        return {"value": rows}, {}

    collector.http.get = get
    assert list(collector.items("route", {}, "/", lambda row: row.get("gitObjectType") == "tree")) == []


def test_directory_entries_consume_the_shared_listing_budget():
    handle, _ = repository(items=[{"path": "/one", "gitObjectType": "tree"},
                                  {"path": "/two", "gitObjectType": "tree"}])
    collector = devops_content.build(payload(repository="api", max_objects=1), http(handle))
    with pytest.raises(CollectorError, match="SOURCE_OBJECT_LIMIT"):
        list(collector.collect())
    assert not collector.listing_complete


@pytest.mark.parametrize("selection,expected", [
    ({"paths": ["src"]}, ["SRC/app.config"]),
    ({"excluded_paths": ["src"]}, []),
    ({"exact_paths": ["src/app.config"]}, ["SRC/app.config"]),
    ({"_connection_scope": {"excluded_paths": ["src"]}}, []),
])
def test_tfvc_scope_comparisons_follow_the_server_case_semantics(selection, expected):
    handle, _ = tfvc(items=[{"path": "$/Platform Team/SRC/app.config", "size": 16}])
    config = devops_content.Collector.root_payload(payload(version_control="tfvc"), "acme/Platform Team/$")
    collector = devops_content.Collector({**config, **selection}, http(handle))
    assert [item.resource.location for item in collector.collect()] == expected


def test_git_path_selection_remains_case_sensitive():
    handle, _ = repository()
    collector = devops_content.build(payload(repository="api", paths=["SRC"]), http(handle))
    assert list(collector.collect()) == []


@pytest.mark.parametrize("child, error", [("$/PLATFORM TEAM/src", None), ("$/Other", "AZURE_DEVOPS_TREE_MALFORMED")])
def test_a_split_tfvc_listing_folds_case_and_stays_under_the_project(child, error):
    handle_tfvc, _ = tfvc()
    scopes = []

    def handle(request):
        params = request.url.params
        scopes.append(params.get("scopePath"))
        if params.get("recursionLevel") == "Full" and params["scopePath"] == "$/Platform Team":
            return httpx.Response(200, content=TOO_LARGE)
        if params.get("recursionLevel") == "OneLevel":
            return httpx.Response(200, json={"value": [
                {"path": "$/platform team", "isFolder": True}, {"path": child, "isFolder": True}]})
        if params.get("recursionLevel") == "Full":
            assert params["scopePath"] == child
            return httpx.Response(200, json={"value": [
                {"path": child, "isFolder": True}, {"path": child + "/app.config", "size": 16}]})
        return handle_tfvc(request)

    collector = devops_content.build(devops_content.Collector.root_payload(
        payload(version_control="tfvc"), "acme/Platform Team/$"), http(handle))
    if error:
        with pytest.raises(CollectorError, match=error):
            list(collector.collect())
        assert child not in scopes  # nothing outside the project root is listed
    else:
        assert [item.resource.location for item in collector.collect()] == ["src/app.config"]


@pytest.mark.parametrize("change,code", [
    ({"refs": [{"name": "refs/heads/main-old", "objectId": "b" * 40}]}, "AZURE_DEVOPS_COMMIT_MALFORMED"),
    ({"items": [{"path": "/a", "gitObjectType": "blob", "objectId": "1" * 40},
                {"path": "/a", "gitObjectType": "blob", "objectId": "2" * 40}]}, "AZURE_DEVOPS_TREE_MALFORMED"),
    ({"disabled": True}, "AZURE_DEVOPS_REPOSITORY_DISABLED"),
])
def test_an_unpinned_malformed_or_disabled_repository_fails_instead_of_looking_empty(change, code):
    handle, _ = repository(**change)
    with pytest.raises(CollectorError) as caught:
        list(devops_content.build(payload(repository="api"), http(handle)).collect())
    assert caught.value.code == code


def test_project_catalog_skips_disabled_repositories_and_rejects_unsafe_names():
    def handle(request):
        return httpx.Response(200, json={"value": [{"name": "api"}, {"name": "old", "isDisabled": True}, {"name": "web"}]})

    assert [row[1] for row in devops_content.roots(payload(), http(handle))] == [
        "acme/Platform Team/api", "acme/Platform Team/web"]
    assert devops_content.Collector.root_payload(payload(), "acme/Platform Team/web")["repository"] == "web"
    with pytest.raises(CollectorError, match="AZURE_DEVOPS_REPOSITORY_MALFORMED"):
        list(devops_content.roots(payload(), http(lambda request: httpx.Response(200, json={"value": [{"name": "a/b"}]}))))


@pytest.mark.parametrize("config", [
    {"organization": "-acme", "project": "p"}, {"organization": "acme", "project": "a/b"},
    {"organization": "acme", "project": "p", "repository": "x?y"}, {"organization": "acme", "project": " p"},
    {"organization": "acme", "project": "p", "ref": "refs/heads/main"}, {"organization": "acme"},
])
def test_names_stay_single_url_segments(config):
    with pytest.raises(ValueError):
        devops_source.validate_config(config)


def test_a_server_collection_uses_its_own_address_api_version_and_a_chosen_branch():
    seen = []

    def handle(request):
        seen.append(request)
        assert request.url.host == "tfs.example.test" and request.url.params["api-version"] == "5.0"
        path = request.url.raw_path.decode().split("?", 1)[0]
        base = "/tfs/DefaultCollection/Platform%20Team/_apis/git/repositories/api"
        if path == base:
            return httpx.Response(200, json={"name": "api", "defaultBranch": "refs/heads/main"})
        if path == base + "/refs":
            assert request.url.params["filter"] == "heads/release/1.0"
            return httpx.Response(200, json={"value": [{"name": "refs/heads/release/1.0", "objectId": COMMIT}]})
        if path == base + "/items":
            return httpx.Response(200, json={"value": [{"path": "/app.env", "gitObjectType": "blob", "objectId": "1" * 40}]})
        return httpx.Response(200, content=b"SYNTHETIC=value")

    config = payload(organization="DefaultCollection", base_url="https://tfs.example.test/tfs", repository="api",
                     ref="release/1.0")
    [item] = list(devops_content.build(config, http(handle)).collect())
    assert item.resource.metadata["source_instance"] == "https://tfs.example.test/tfs"
    assert item.resource.version_id == COMMIT and len(seen) == 4
    from cremore.db.scan_state import exposure_location

    location = {"source_type": "azure_devops", "resource_name": item.resource.resource, "location": "app.env",
                "object_version": COMMIT, "metadata": item.resource.metadata}
    assert exposure_location(location)[-1] == "https://tfs.example.test/tfs"


@pytest.mark.parametrize("config", [
    {"organization": "acme", "project": "p", "base_url": "https://dev.azure.com/acme"},
    {"organization": "acme", "project": "p", "base_url": "https://acme.visualstudio.com"},
    {"organization": "Default/Collection", "project": "p", "base_url": "https://tfs.example.test/tfs"},
    {"organization": "acme", "project": "p", "base_url": "http://tfs.example.test"},
])
def test_services_keep_their_fixed_address_and_servers_need_https(config):
    with pytest.raises(ValueError):
        devops_source.validate_config(config)


def tfvc(handle_item=None, items=None):
    calls = []

    def handle(request):
        calls.append(request)
        path = request.url.raw_path.decode().split("?", 1)[0]
        assert path.startswith("/acme/Platform%20Team/_apis/tfvc/")
        params = request.url.params
        if path.endswith("/changesets"):
            assert params["$top"] == "1" and params["searchCriteria.itemPath"] == "$/Platform Team"
            return httpx.Response(200, json={"value": [{"changesetId": 42}]})
        if params.get("recursionLevel") == "None":
            return httpx.Response(200, json={"path": "$/Platform Team", "isFolder": True})
        if params.get("scopePath"):
            assert params["versionDescriptor.version"] == "42" and params["versionDescriptor.versionType"] == "changeset"
            return httpx.Response(200, json={"value": items if items is not None else [
                {"path": "$/Platform Team", "isFolder": True},
                {"path": "$/Platform Team/src", "isFolder": True},
                {"path": "$/Platform Team/src/app.config", "size": 16, "version": 40},
                {"path": "$/platform team/src/old.config", "size": 8, "deletionId": 7},
                {"path": "$/Platform Team/big.bin", "size": 1 << 30}]})
        assert params["versionDescriptor.version"] == "42" and request.headers["accept"] == "application/octet-stream"
        return (handle_item or (lambda request: httpx.Response(200, content=b"SYNTHETIC=value")))(request)

    return handle, calls


def test_tfvc_is_read_at_the_latest_changeset_and_names_its_project_root():
    handle, calls = tfvc()
    config = payload(version_control="tfvc")
    assert [row[1] for row in devops_content.roots(config, http(handle))] == ["acme/Platform Team/$"]
    collector = devops_content.build(devops_content.Collector.root_payload(config, "acme/Platform Team/$"), http(handle))
    objects = list(collector.collect())
    assert [(item.resource.resource, item.resource.location, item.resource.version_id) for item in objects] == [
        ("acme/Platform Team/$", "src/app.config", "42")]
    assert objects[0].data == b"SYNTHETIC=value" and collector.failed_objects == 1  # the oversized file is not read
    assert calls[-1].url.params["path"] == "$/Platform Team/src/app.config"


def test_tfvc_items_outside_the_project_root_fail_the_listing():
    handle, _ = tfvc(items=[{"path": "$/Other/secret.txt", "size": 4}])
    with pytest.raises(CollectorError, match="AZURE_DEVOPS_TREE_MALFORMED"):
        root = devops_content.Collector.root_payload(payload(version_control="tfvc"), "acme/Platform Team/$")
        list(devops_content.build(root, http(handle)).collect())


@pytest.mark.parametrize("config", [
    {"organization": "acme", "project": "p", "version_control": "tfvc", "repository": "api"},
    {"organization": "acme", "project": "p", "version_control": "tfvc", "ref": "main"},
    {"organization": "acme", "project": "p", "version_control": "svn"},
])
def test_tfvc_scope_is_the_project_root_only(config):
    with pytest.raises(ValueError):
        devops_source.validate_config(config)


def test_scope_round_trip_and_credential_check_codes():
    assert devops_source.config_from_scope("acme/Platform Team/api") == {
        "organization": "acme", "project": "Platform Team", "repository": "api"}
    assert devops_source.config_from_scope("acme/Platform Team/$") == {
        "organization": "acme", "project": "Platform Team", "version_control": "tfvc"}
    assert devops_source.scope_ref({"organization": "acme", "project": "Platform Team"}) == "acme/Platform Team"
    ok = devops_source.check_credential(payload(), http_client_factory=lambda: http(
        lambda request: httpx.Response(200, json={"value": [{"name": "api"}]})))
    assert ok.status == "ACTIVE"
    for status, expected in ((401, ("REJECTED", "AZURE_DEVOPS_AUTHENTICATION_FAILED")),
                             (203, ("REJECTED", "AZURE_DEVOPS_AUTHENTICATION_FAILED")),
                             (403, ("INDETERMINATE", "AZURE_DEVOPS_PERMISSION_DENIED"))):
        result = devops_source.check_credential(payload(), http_client_factory=lambda status=status: http(
            lambda request: httpx.Response(status, text="<html>sign in</html>")))
        assert (result.status, result.error) == expected
