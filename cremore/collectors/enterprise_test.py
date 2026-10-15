"""Synthetic provider contracts exercised through catalogs, plans and workers."""

import uuid

import httpx
import pytest

from cremore.collectors.base import CollectorError, RequestBudget
from cremore.collectors.enterprise import EnterpriseCollector, SourceHTTP, roots
from cremore.db.repository import InMemoryRepository
from cremore.detection.engine import EngineConfig
from cremore.domain.connections import job_kind_for, job_payload_for, validate_connection
from cremore.domain.models import Connection, ScanJob, ScopeCatalog, ScopeProfile
from cremore.scanning import scope
from cremore.scanning.orchestrator import Orchestrator
from cremore.source_config import config
from cremore.worker import JobWorker
from cremore.worker.factory import build_collector

GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"
CONFIGS = {"bitbucket": {"workspace": "team", "repo": "repo", "edition": "cloud"},
           "gitlab": {"project": "7", "base_url": "https://gitlab.example.test"},
           "gcp": {"bucket": "synthetic-bucket"},
           "confluence": {"space": "99", "base_url": "https://synthetic.atlassian.net/wiki", "edition": "cloud"}}


def test_replaced_request_budget_guards_http_before_any_listing_request():
    class Cancelled(RequestBudget):
        def consume(self):
            raise CollectorError("RUN_CANCELLED")

    def never(request):
        raise AssertionError("cancelled listing must not reach HTTP")

    with httpx.Client(transport=httpx.MockTransport(never)) as client:
        collector = EnterpriseCollector("gitlab", {**CONFIGS["gitlab"], "token": "synthetic"}, client)
        collector.request_budget = Cancelled()
        assert collector.http.budget is collector.request_budget
        with pytest.raises(CollectorError, match="RUN_CANCELLED"):
            list(collector.collect())


def handle(request):
    assert request.headers["Authorization"] == "Bearer synthetic-scanner"
    path = request.url.path
    if path.endswith("/repositories/team/repo"):
        return httpx.Response(200, json={"slug": "repo", "mainbranch": {"name": "main"}})
    if "/commit/" in path:
        return httpx.Response(200, json={"hash": "a" * 40})
    if path.startswith("/2.0/repositories/") and "/src/" in path:
        if path.endswith("/config.txt"):
            assert "a" * 40 in path
            return httpx.Response(200, content=GH.encode())
        return httpx.Response(200, json={"values": [{"type": "commit_file", "path": "src/config.txt"}]})
    if path.endswith("/projects/7"):
        return httpx.Response(200, json={"id": 7, "path_with_namespace": "org/project"})
    if "/commits/" in path:
        return httpx.Response(200, json={"id": "a" * 40})
    if path.endswith("/repository/tree"):
        assert request.url.params["ref"] == "a" * 40
        return httpx.Response(200, json=[{"type": "blob", "path": "src/config.txt", "id": "b" * 40}])
    if path.endswith("/raw"):
        return httpx.Response(200, content=GH.encode())
    if path.endswith("/b/synthetic-bucket"):
        return httpx.Response(200, json={"name": "synthetic-bucket"})
    if path.endswith("/o"):
        return httpx.Response(200, json={"items": [{"name": "src/config.txt", "generation": "7", "size": "100"}]})
    if "/o/" in path:
        assert request.url.params["generation"] == "7" and request.url.params["ifGenerationMatch"] == "7"
        return httpx.Response(200, content=GH.encode())
    if path.endswith("/spaces/99/pages"):
        return httpx.Response(200, json={"results": [{"id": "123"}]})
    if path.endswith("/pages/123"):
        return httpx.Response(200, json={"id": "123", "spaceId": "99", "version": {"number": 2}, "body": {"storage": {"value": GH}}})
    if path.endswith("/attachments"):
        return httpx.Response(200, json={"results": []})
    raise AssertionError("Unexpected synthetic provider request")


@pytest.mark.parametrize("provider", list(CONFIGS))
def test_content_provider_runs_end_to_end_without_verifying_detected_credentials(provider):
    repo = InMemoryRepository()
    connection = Connection(provider=provider, name="Synthetic", status="ACTIVE", config=CONFIGS[provider])
    validate_connection(connection)
    connection = repo.create_connection(connection)
    payload = job_payload_for(connection) | {"token": "synthetic-scanner"}
    job = repo.enqueue_job(ScanJob(kind=job_kind_for(connection), connection_id=connection.id, payload=payload))
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        worker = JobWorker(repo, orchestrator=Orchestrator(repo, config=EngineConfig(fingerprint_key=b"k" * 32)), verify=False,
                           collector_factory=lambda job: build_collector(job, http_client_factory=lambda: client))
        assert worker.process_next()
    assert repo.get_job(job.id).status == "SUCCEEDED"
    assert repo.get_job(job.id).objects == 1
    assert len(repo.list_findings()) == 1
    assert repo.exposures_for_connection(connection.id)[0].source_type == provider


@pytest.mark.parametrize("provider", list(CONFIGS))
def test_catalog_and_approved_scope_connect_to_scoped_collector(provider):
    from cremore.scanning.catalog import list_resources
    cid = uuid.uuid4()
    connection = Connection(id=cid, provider=provider, name="Synthetic", status="ACTIVE", config=config(provider, CONFIGS[provider]))
    payload = job_payload_for(connection) | {"token": "synthetic-scanner", "connection_kind": "source", "connection_id": str(cid)}
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        items, status = list_resources(payload, http_client=lambda: client)
        assert status == "COMPLETE" and len(items) == 1
        item = items[0]
        root = {"resource_id": item["id"], "all_current_objects": True, "include_future_descendants": False, "paths": [], "prefixes": []}
        profile = ScopeProfile(id=uuid.uuid4(), kind="source", connection_id=cid, name="Approved", selected_roots=[root],
                               auth_revision=scope.auth_revision("source", connection), catalog_snapshot_id="snapshot")
        catalog = ScopeCatalog(kind="source", connection_id=cid, snapshot_id="snapshot", items=items)
        plan = scope.build_plan(profile, catalog, auth=profile.auth_revision, enabled=True)
        scope.validate_execution(plan, profile, connection, require_unexpired=True)
        job = ScanJob(kind="scope", payload=payload | {"roots": plan.roots})
        objects = list(build_collector(job, http_client_factory=lambda: client).collect())
        assert len(objects) == 1 and objects[0].data == GH.encode()


def test_gitlab_pins_revision_honors_paths_and_marks_raw_failure_partial():
    calls = []
    def failure(request):
        calls.append(request)
        if request.url.path.endswith("/raw"):
            return httpx.Response(403)
        return handle(request)
    payload = config("gitlab", CONFIGS["gitlab"]) | {"token": "synthetic-scanner", "paths": ["src"]}
    with httpx.Client(transport=httpx.MockTransport(failure)) as client:
        collector = EnterpriseCollector("gitlab", payload, client)
        objects = list(collector.collect())
        assert objects[0].data is None and collector.failed_objects == 1 and collector.listing_complete
        assert "src/config.txt" in collector.listed_paths
        calls.clear()
        empty = EnterpriseCollector("gitlab", payload | {"excluded_paths": ["src"]}, client)
        assert list(empty.collect()) == []
        assert not any(r.url.path.endswith("/raw") for r in calls)


def test_gcs_oversized_objects_stay_in_listing_and_requests_are_bounded():
    payload = config("gcp", CONFIGS["gcp"]) | {"token": "synthetic-scanner", "prefixes": ["src/"]}
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        collector = EnterpriseCollector("gcp", payload, client, max_object_bytes=60)
        assert list(collector.collect()) == []
        assert collector.failed_objects == 1 and "src/config.txt" in collector.listed_paths
        collector = EnterpriseCollector("gcp", payload, client, request_budget=RequestBudget(1))
        with pytest.raises(CollectorError, match="BUDGET_REQUESTS"):
            list(collector.collect())


@pytest.mark.parametrize("route,params", [
    ("/spaces/99/pages", {"status": "current"}),
    ("/pages/123/attachments", None),
])
def test_confluence_cloud_listing_omits_initial_cursor_and_uses_next_cursor(route, params):
    calls = []

    def provider(request):
        calls.append(request)
        assert request.url.path == "/wiki/api/v2" + route
        assert request.headers["Authorization"] == "Bearer synthetic-scanner"
        assert request.url.params["limit"] == "100"
        for key, value in (params or {}).items():
            assert request.url.params[key] == value
        if "cursor" in request.url.params:
            if not request.url.params["cursor"]:
                # Cloud rejects an empty cursor instead of treating it as page one.
                return httpx.Response(400, json={"errors": [
                    {"code": "INVALID_REQUEST_PARAMETER"},
                ]})
            assert request.url.params["cursor"] == "next+page=="
            return httpx.Response(200, json={"results": [{"id": "456"}]})
        return httpx.Response(200, json={
            "results": [{"id": "123"}],
            "_links": {"next": "/wiki/api/v2" + route + "?cursor=next%2Bpage%3D%3D&limit=100"},
        })

    payload = config("confluence", CONFIGS["confluence"]) | {"token": "synthetic-scanner"}
    with httpx.Client(transport=httpx.MockTransport(provider)) as client:
        http = SourceHTTP("confluence", payload, client, budget=RequestBudget(2))
        assert list(http.confluence_pages(route, params)) == [{"id": "123"}, {"id": "456"}]
    assert len(calls) == 2
    assert "cursor" not in calls[0].url.params


def test_confluence_data_center_context_and_external_download_rejection():
    requests = []
    def dc(request):
        requests.append(request)
        if request.url.path.endswith("/content/123"):
            return httpx.Response(200, json={"id": "123", "space": {"key": "OPS"}, "version": {"number": 1}, "body": {"storage": {"value": GH}}})
        if request.url.path.endswith("/child/attachment"):
            return httpx.Response(200, json={"results": [{"id": "att1", "_links": {"download": "/confluence/download/attachments/123/file"}}, {"id": "att2", "_links": {"download": "https://other.example.test/private"}}]})
        if request.url.path == "/confluence/download/attachments/123/file":
            return httpx.Response(200, content=b"synthetic document")
        raise AssertionError("Unexpected request")
    payload = config("confluence", {"space": "OPS", "edition": "data_center", "base_url": "https://docs.example.test/confluence"}) | {"page_id": "123", "token": "synthetic-scanner"}
    with httpx.Client(transport=httpx.MockTransport(dc)) as client:
        collector = EnterpriseCollector("confluence", payload, client)
        assert len(list(collector.collect())) == 2
        assert collector.failed_objects == 1 and "attachments/att2" in collector.listed_paths
    assert all(r.url.host == "docs.example.test" for r in requests)


@pytest.mark.parametrize("changes", [{"base_url": "http://gitlab.example.test"}, {"base_url": "https://user:pass@gitlab.example.test"}, {"project": "../project"}, {"token": GH}])
def test_config_rejects_unsafe_endpoints_and_secret_fields(changes):
    with pytest.raises(ValueError):
        config("gitlab", CONFIGS["gitlab"] | changes)


def test_scope_changes_cannot_widen_new_provider_execution():
    cid = uuid.uuid4()
    target = Connection(id=cid, provider="gitlab", name="test", config=CONFIGS["gitlab"], status="ACTIVE")
    item = scope.resource("source", cid, "GITLAB_REPOSITORY", "7", "7", "7", "gitlab")
    root = {"resource_id": item["id"], "all_current_objects": False, "include_future_descendants": False, "paths": ["src"]}
    profile = ScopeProfile(id=uuid.uuid4(), kind="source", connection_id=cid, name="approved", selected_roots=[root], auth_revision=scope.auth_revision("source", target), catalog_snapshot_id="s")
    plan = scope.build_plan(profile, ScopeCatalog(kind="source", connection_id=cid, snapshot_id="s", items=[item]), auth=profile.auth_revision, enabled=True)
    plan.roots[0]["paths"] = []
    with pytest.raises(scope.ScopeError):
        scope.validate_execution(plan, profile, target)


@pytest.mark.parametrize("provider", list(CONFIGS))
def test_onboarding_catalog_approved_worker_rescan_and_event_scope(provider):
    from datetime import UTC, datetime

    from fastapi.testclient import TestClient

    from cremore.api import create_app
    from cremore.config import Settings
    from cremore.scanning.catalog import list_resources
    from cremore.scanning.triggers import _event_root
    repo = InMemoryRepository()
    token = "synthetic-admin-" + "a" * 32
    api = TestClient(create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=token, FINGERPRINT_KEY=(b"k" * 32).hex())))
    from cremore.onboarding.fixtures_test import content_source

    connection = content_source(repo, provider, CONFIGS[provider], name="Synthetic", status="ACTIVE")
    auth = scope.auth_revision("source", connection)
    payload = job_payload_for(connection) | {"token": "synthetic-scanner", "connection_kind": "source", "connection_id": str(connection.id)}
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        items, _ = list_resources(payload, http_client=lambda: client)
        from cremore.db.repository import _asset_search_row
        assert _asset_search_row("source", connection.id, items[0]["id"], "Synthetic", items[0]["resource_type"], None, None)["provider"] == provider
        catalog = repo.save_catalog(ScopeCatalog(kind="source", connection_id=connection.id, snapshot_id="snapshot", auth_revision=auth, items=items, completeness="COMPLETE"))
        root = {"resource_id": items[0]["id"], "all_current_objects": False, "prefixes": ["src/"], "paths": ["body"] if provider == "confluence" else ["src"], "include_future_descendants": False}
        profile = repo.create_scope_profile(ScopeProfile(kind="source", connection_id=connection.id, name="Approved", state="READY",
            selected_roots=[root], auth_revision=auth, catalog_snapshot_id="snapshot", approved_by="admin", approved_at=datetime.now(UTC),
            budgets={"requests": 100, "bytes": 10000, "seconds": 60}))
        plan = repo.create_plan(scope.build_plan(profile, catalog, auth=auth, enabled=True))
        payload.pop("token")  # Runtime resolver supplies secrets after task persistence.
        job = repo.enqueue_job(ScanJob(kind="scope", connection_id=connection.id, payload=scope.run_payload(plan, profile, payload, provider)))
        worker = JobWorker(repo, orchestrator=Orchestrator(repo, config=EngineConfig(fingerprint_key=b"k" * 32)), verify=False,
            collector_factory=lambda job: build_collector(job.model_copy(update={"payload": job.payload | {"token": "synthetic-scanner"}}), http_client_factory=lambda: client))
        for _ in range(6):
            worker.process_next()
            if repo.get_job(job.id).status == "SUCCEEDED":
                break
        assert repo.get_job(job.id).status == "SUCCEEDED"
        exposure = repo.exposures_for_connection(connection.id)[0]
        finding = repo.list_findings()[0]
        exact, _ = scope.rescan_target(finding, exposure, profile, catalog)
        field = "exact_keys" if provider == "gcp" else "exact_paths"
        assert exact[field] == [exposure.location]
        preview = api.post(f"/api/v1/findings/{finding.id}/rescan-preview", headers={"Authorization": "Bearer " + token},
            json={"profile_id": str(profile.id), "exposure_id": str(exposure.id)})
        assert preview.status_code == 200, preview.text
        assert preview.json()["rescan_target"]["source_type"] == provider
        event_field = "keys" if provider == "gcp" else "paths"
        with pytest.raises(scope.ScopeError, match="EVENT_OUT_OF_SCOPE"):
            _event_root(plan, {"resource_id": items[0]["id"], event_field: ["outside/file"]})


@pytest.mark.parametrize("provider,resource_type,identifier,download_suffix", [
    ("gitlab", "GITLAB_REPOSITORY", "7", "/raw"),
    ("bitbucket", "BITBUCKET_REPOSITORY", "team/repo", "/config.txt"),
])
def test_an_unchanged_revision_is_not_downloaded_again(provider, resource_type, identifier, download_suffix):
    """The tree lists each file's blob id; a blob the scan already read is reused, not fetched (design 4.3)."""
    from datetime import UTC, datetime

    repo = InMemoryRepository()
    connection = repo.create_connection(Connection(provider=provider, name=provider, config=CONFIGS[provider], status="ACTIVE"))
    auth = scope.auth_revision("source", connection)
    item = scope.resource("source", connection.id, resource_type, identifier, identifier, identifier, provider)
    catalog = repo.save_catalog(ScopeCatalog(kind="source", connection_id=connection.id, snapshot_id="s", auth_revision=auth,
                                             items=[item], completeness="COMPLETE"))
    profile = repo.create_scope_profile(ScopeProfile(
        kind="source", connection_id=connection.id, name="Approved", state="READY", auth_revision=auth,
        selected_roots=[{"resource_id": item["id"], "all_current_objects": False, "paths": ["src"],
                         "include_future_descendants": False}],
        catalog_snapshot_id="s", approved_by="admin", approved_at=datetime.now(UTC),
        budgets={"requests": 100, "bytes": 10000, "seconds": 60}))
    downloads = []

    def counting(request):
        if request.url.path.endswith(download_suffix):
            downloads.append(request.url.path)
        return handle(request)

    with httpx.Client(transport=httpx.MockTransport(counting)) as client:
        worker = JobWorker(repo, orchestrator=Orchestrator(repo, config=EngineConfig(fingerprint_key=b"k" * 32)), verify=False,
            collector_factory=lambda job: build_collector(job.model_copy(update={"payload": job.payload | {"token": "synthetic-scanner"}}),
                                                          http_client_factory=lambda: client))
        for mode in ("BASELINE", "DELTA"):
            plan = repo.create_plan(scope.build_plan(profile, catalog, auth=auth, enabled=True))
            payload = scope.run_payload(plan, profile, job_payload_for(connection), provider) | {"mode": mode}
            job = repo.enqueue_job(ScanJob(kind="scope", connection_id=connection.id, payload=payload))
            for _ in range(6):
                worker.process_next()
                if repo.get_job(job.id).status == "SUCCEEDED":
                    break
            assert repo.get_job(job.id).status == "SUCCEEDED"
            assert len(downloads) == 1, mode  # read once, then reused by its blob id
    assert len(repo.list_findings()) == 1


def test_gcs_prefix_and_exact_keys_preserve_literal_slashes():
    payload = config("gcp", CONFIGS["gcp"] | {"prefixes": ["src/"], "excluded_prefixes": ["src/private/"]})
    assert payload["prefixes"] == ["src/"]
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        collector = EnterpriseCollector("gcp", payload | {"token": "synthetic"}, client)
        assert collector.selected("src/file") and not collector.selected("src-private/file")
        assert not collector.selected("src/private/file") and not collector.selected("/src/file")


def test_unreadable_objects_cannot_evade_collection_limits():
    def large(request):
        return httpx.Response(200, json={"items": [{"name": f"large/{i}", "generation": "1", "size": "9999999"} for i in range(3)]})
    with httpx.Client(transport=httpx.MockTransport(large)) as client:
        collector = EnterpriseCollector("gcp", CONFIGS["gcp"] | {"token": "synthetic", "max_objects": 2}, client, max_object_bytes=100)
        with pytest.raises(CollectorError, match="SOURCE_OBJECT_LIMIT"):
            list(collector.collect())
        assert not collector.authoritative_listing and len(collector.listed_paths) == 2


@pytest.mark.parametrize("provider", list(CONFIGS))
def test_plan_cannot_override_connection_path_limits(provider):
    field = "prefixes" if provider == "gcp" else "paths"
    payload = config(provider, CONFIGS[provider] | {field: ["allowed/"]}) | {"token": "synthetic-scanner"}
    rt = {"gitlab": "GITLAB_REPOSITORY", "gcp": "GCS_BUCKET", "confluence": "CONFLUENCE_PAGE", "bitbucket": "BITBUCKET_REPOSITORY"}[provider]
    ident = {"gitlab": "7", "gcp": "synthetic-bucket", "confluence": "123", "bitbucket": "team/repo"}[provider]
    requests = []
    def mocked(request):
        requests.append(request)
        return handle(request)
    with httpx.Client(transport=httpx.MockTransport(mocked)) as client:
        job = ScanJob(kind="scope", payload=payload | {"roots": [{"resource_type": rt, "provider_resource_id": ident, field: [], "all_current_objects": True}]})
        assert list(build_collector(job, http_client_factory=lambda: client).collect()) == []
    assert not any(r.url.path.endswith(("/raw", "/config.txt")) or r.url.params.get("alt") == "media" for r in requests)
    if provider == "confluence":
        assert all("body-format" not in r.url.params for r in requests)


def test_bitbucket_data_center_paging_context_pinning_and_path_filter():
    calls = []
    def mocked(request):
        calls.append(request)
        assert request.url.host == "code.example.test" and request.headers["Authorization"] == "Bearer synthetic-scanner"
        p = request.url.path
        if p.endswith("/branches/default"):
            return httpx.Response(200, json={"latestCommit": "a" * 40})
        if "/commits/" in p:
            return httpx.Response(200, json={"id": "a" * 40})
        if p.endswith("/files"):
            assert request.url.params["at"] == "a" * 40
            return httpx.Response(200, json={"values": ["src/config.txt"] if request.url.params["start"] == "0" else ["private/config.txt"],
                "isLastPage": request.url.params["start"] != "0", "nextPageStart": 7})
        if p.endswith("/raw/src/config.txt"):
            assert request.url.params["at"] == "a" * 40
            return httpx.Response(200, content=GH.encode())
        raise AssertionError("Unexpected request")
    payload = config("bitbucket", {"project": "OPS", "repo": "repo", "edition": "data_center", "base_url": "https://code.example.test/bitbucket", "paths": ["src"]}) | {"token": "synthetic-scanner"}
    with httpx.Client(transport=httpx.MockTransport(mocked)) as client:
        collector = EnterpriseCollector("bitbucket", payload, client)
        objects = list(collector.collect())
    assert len(objects) == 1 and collector.listing_complete
    assert objects[0].resource.resource == "OPS/repo"
    assert all(r.url.path.startswith("/bitbucket/rest/api/1.0/") for r in calls)


def test_bitbucket_cloud_api_token_and_untrusted_pagination_url():
    import base64
    calls = []
    def mocked(request):
        calls.append(request)
        assert request.url.host == "api.bitbucket.org"
        assert request.headers["Authorization"] == "Basic " + base64.b64encode(b"operator@example.test:synthetic-scanner").decode()
        body = {"values": [{"slug": "one"}], "next": "https://untrusted.example.test/steal?page=2"} if request.url.params["page"] == "1" else {"values": [{"slug": "two"}]}
        return httpx.Response(200, json=body)
    payload = config("bitbucket", {"workspace": "team", "auth_type": "api_token", "username": "operator@example.test"}) | {"token": "synthetic-scanner"}
    with httpx.Client(transport=httpx.MockTransport(mocked)) as client:
        assert [row[1] for row in roots("bitbucket", payload, client)] == ["team/one", "team/two"]
    assert len(calls) == 2


@pytest.mark.parametrize("failure", [None, "loop", "limit", "read"])
def test_bitbucket_nested_tree_limits_and_failures_never_imply_complete_content(failure):
    calls = []
    sha = "a" * 40
    def mocked(request):
        calls.append(request)
        tail = request.url.path.split("/src/" + sha + "/")[-1]
        if "/src/" not in request.url.path:
            return handle(request)
        if tail == "":
            return httpx.Response(200, json={"values": [{"type": "commit_directory", "path": "src"}]})
        if tail == "src":
            page = request.url.params["page"]
            return httpx.Response(200, json={"values": [{"type": "commit_file", "path": "src/config.txt"}] if page == "1" else [],
                **({"next": "https://api.bitbucket.org/ignored?page=2"} if failure == "loop" else {})})
        assert tail == "src/config.txt"
        return httpx.Response(403 if failure == "read" else 200, content=GH.encode())
    payload = config("bitbucket", CONFIGS["bitbucket"] | {"paths": ["src"], "max_objects": 1 if failure == "limit" else 10}) | {"token": "synthetic-scanner"}
    with httpx.Client(transport=httpx.MockTransport(mocked)) as client:
        collector = EnterpriseCollector("bitbucket", payload, client)
        if failure in ("loop", "limit"):
            with pytest.raises(CollectorError, match="SOURCE_PAGINATION_LOOP" if failure == "loop" else "SOURCE_OBJECT_LIMIT"):
                list(collector.collect())
            assert not collector.listing_complete and not collector.authoritative_listing
        else:
            objects = list(collector.collect())
            assert len(objects) == 1 and collector.listing_complete
            assert objects[0].resource.version_id == sha
            assert collector.failed_objects == (1 if failure == "read" else 0)
            assert objects[0].complete == (failure != "read")
    assert len(calls) <= 7


def test_self_managed_gitlab_tokens_are_not_verified_against_gitlab_com():
    from cremore.detection import DetectorInput, ResourceRef
    from cremore.detection.engine import Engine
    from cremore.detection.verify import VerifierConfig
    calls = []
    def mocked(request):
        calls.append(request.url.host)
        return httpx.Response(200, json={"id": 1})
    with httpx.Client(transport=httpx.MockTransport(mocked)) as client:
        engine = Engine(EngineConfig(fingerprint_key=b"k" * 32, http_client=client, verify=VerifierConfig(enabled=True)))
        token = ("glpat-" + "Ab3De5Fg7Hj9Kl1Mn2Pq").encode()
        result = engine.scan(DetectorInput(data=token, resource=ResourceRef(source_type="gitlab",
            metadata={"source_instance": "https://gitlab.example.test"})))
        assert result[0].extra_safe_data["verification_error"] == "GITLAB_ISSUER_HOST_UNCONFIRMED"
        assert calls == []
        engine.scan(DetectorInput(data=token, resource=ResourceRef(source_type="gitlab",
            metadata={"source_instance": "https://gitlab.com"})))
        assert calls == ["gitlab.com"]


@pytest.mark.parametrize("cross_host", [False, True])
def test_gitlab_token_found_elsewhere_is_not_sent_to_gitlab_com_when_a_self_managed_host_is_known(cross_host):
    from cremore.detection import DetectorInput, ResourceRef
    from cremore.detection.engine import Engine
    from cremore.detection.verify import VerifierConfig
    calls = []
    def mocked(request):
        calls.append(request.url.host)
        return httpx.Response(401)
    token = ("glpat-" + "Ab3De5Fg7Hj9Kl1Mn2Pq").encode()
    with httpx.Client(transport=httpx.MockTransport(mocked)) as client:
        engine = Engine(EngineConfig(fingerprint_key=b"k" * 32, http_client=client, verify=VerifierConfig(
            enabled=True, cross_host=cross_host, known_gitlab_hosts=("gitlab.example.test",))))
        [found] = engine.scan(DetectorInput(data=token, resource=ResourceRef(source_type="notion")))
    extra = found.extra_safe_data
    if cross_host:  # sent only with the admin's cross-host consent, and a rejection is not conclusive
        assert calls == ["gitlab.com"] and extra["verification_state"] == "indeterminate"
        assert extra["verification_error"] == "REJECTED_ON_GITLAB_COM_SELF_MANAGED_UNCHECKED"
    else:
        assert calls == [] and extra["verification_error"] == "GITLAB_ISSUER_HOST_UNCONFIRMED"


def test_registered_self_managed_gitlab_hosts_reach_the_verifier():
    from types import SimpleNamespace

    from cremore.detection.verify import VerifierConfig
    from cremore.scanning.scan_switches import verify_config_for
    repo = InMemoryRepository()
    settings = SimpleNamespace(capability_probe_allowed=False, cross_host_verification_allowed=False,
                               known_github_hosts=())
    assert verify_config_for(VerifierConfig(enabled=True), settings, repo).known_gitlab_hosts == ()
    for base in ("https://gitlab.com", "https://gitlab.example.test"):
        repo.create_connection(Connection(provider="gitlab", name=base, config={"base_url": base}))
    assert verify_config_for(VerifierConfig(enabled=True), settings, repo).known_gitlab_hosts == ("gitlab.example.test",)


def test_gitlab_com_verification_names_the_token_itself():
    from cremore.detection import DetectorInput, ResourceRef
    from cremore.detection.engine import Engine
    from cremore.detection.verify import VerifierConfig
    paths = []
    def mocked(request):
        paths.append(request.url.path)
        return httpx.Response(200, json={"id": 42, "user_id": 7, "name": "ci", "scopes": ["read_repository"],
                                         "expires_at": "2027-01-01", "active": True, "revoked": False})
    token = ("glpat-" + "Ab3De5Fg7Hj9Kl1Mn2Pq").encode()
    with httpx.Client(transport=httpx.MockTransport(mocked)) as client:
        engine = Engine(EngineConfig(fingerprint_key=b"k" * 32, http_client=client, verify=VerifierConfig(enabled=True)))
        [found] = engine.scan(DetectorInput(data=token, resource=ResourceRef(source_type="gitlab",
            metadata={"source_instance": "https://gitlab.com"})))
    assert paths == ["/api/v4/personal_access_tokens/self"]
    extra = found.extra_safe_data
    assert extra["verification_state"] == "verified" and extra["verification_token_id"] == "42"
    assert extra["verification_owner_id"] == "7" and extra["verification_scopes"] == "read_repository"


@pytest.mark.parametrize("cross_host", [False, True])
def test_a_self_managed_gitlab_token_is_checked_only_on_its_registered_instance(cross_host):
    from cremore.detection import DetectorInput, ResourceRef
    from cremore.detection.engine import Engine
    from cremore.detection.verify import VerifierConfig
    token = ("glpat-" + "Ab3De5Fg7Hj9Kl1Mn2Pq").encode()
    calls = []
    def mocked(request):
        calls.append((request.url.host, request.url.path))
        assert request.headers["PRIVATE-TOKEN"] == token.decode()
        if request.url.path.startswith("/rejects/"):
            return httpx.Response(401)
        return httpx.Response(200, json={"id": 42, "user_id": 7, "name": "ci", "scopes": ["api"], "expires_at": None})
    def scan(instance, known=("gitlab.example.test",)):
        with httpx.Client(transport=httpx.MockTransport(mocked)) as client:
            engine = Engine(EngineConfig(fingerprint_key=b"k" * 32, http_client=client, verify=VerifierConfig(
                enabled=True, cross_host=cross_host, known_gitlab_hosts=known)))
            [found] = engine.scan(DetectorInput(data=token, resource=ResourceRef(source_type="gitlab",
                metadata={"source_instance": instance})))
        return found.extra_safe_data
    # The registered instance it was found in, under its own base path; never GitLab.com, even with cross-host.
    extra = scan("https://gitlab.example.test/gitlab")
    assert calls == [("gitlab.example.test", "/gitlab/api/v4/personal_access_tokens/self")]
    assert extra["verification_state"] == "verified" and extra["verification_token_id"] == "42"
    assert extra["verification_host"] == "gitlab.example.test"
    # One instance saying no is not proof the token is inactive elsewhere.
    extra = scan("https://gitlab.example.test/rejects")
    assert extra["verification_state"] == "indeterminate" and extra["verification_host"] == "gitlab.example.test"
    assert extra["verification_error"] == "REJECTED_ON_SELF_MANAGED_GITLAB_OTHER_HOSTS_UNCHECKED"
    calls.clear()
    # An unregistered host, or a source URL that fails the registration rule, is never contacted.
    for instance, known in (("https://gitlab.example.test", ("gitlab.other.test",)),
                            ("http://gitlab.example.test", ("gitlab.example.test",)),
                            ("https://user@gitlab.example.test", ("gitlab.example.test",))):
        assert scan(instance, known)["verification_error"] == "GITLAB_ISSUER_HOST_UNCONFIRMED"
    assert calls == []
