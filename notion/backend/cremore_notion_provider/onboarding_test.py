"""Notion wizard choices reach the existing bounded PAT/MCP collector; fakes only."""

import json
import uuid
from types import SimpleNamespace

import httpx
import pytest

from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore.coverage.store import CoverageStore
from cremore.db.repository import InMemoryRepository
from cremore.onboarding import service
from cremore.onboarding.onboarding_test import SETTINGS, activated, run_check
from cremore_notion_provider import onboarding
from cremore_notion_provider.metadata.adapter import collect_pages, validate_spec

WORKSPACE = "11111111-2222-4333-8444-555555555555"
TOKEN = "ntn_synthetic_notion_onboarding_token"
CONNECTION = {"provider": "notion", "edition": "enterprise", "auth_method": "organization_bot",
              "target": {"workspace": WORKSPACE}, "purposes": ["inventory"]}


@pytest.mark.parametrize(("plan", "sources"), [
    ({}, ["personal_access_tokens"]),  # Saved plans predate these options.
    ({"personal_access_tokens": False, "mcp_connections": True}, ["mcp_client_connections"]),
    ({"personal_access_tokens": True, "mcp_connections": True}, ["personal_access_tokens", "mcp_client_connections"]),
])
def test_selected_inventory_sources_reach_only_their_workspace_endpoints(plan, sources):
    [child] = onboarding.children(CONNECTION, "inventory", plan)
    spec = MetadataConnectionSpec.model_validate({**child["spec"], "secret_refs": {"token": "vault://notion/test"}})
    validate_spec(spec)
    assert spec.options.sources == sources
    asked = []

    def handler(request):
        asked.append(request.url)
        return httpx.Response(200, json={"results": [], "has_more": False, "next_cursor": None})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        pages = list(collect_pages(spec, secrets={"token": TOKEN}, checkpoint={}, check=lambda: None,
                                   client=client, sleep=lambda _: None))
    assert len(asked) == len(sources) and pages
    assert [url.path for url in asked] == [
        f"/admin/v1/spaces/{WORKSPACE}/personal_access_tokens" if source == "personal_access_tokens"
        else "/admin/v1/mcp_client_connections" for source in sources]
    for url in asked:
        if url.path.endswith("mcp_client_connections"):
            assert url.params["workspace_ids"] == WORKSPACE


@pytest.mark.parametrize(("pat", "mcp"), [(200, 403), (403, 200)])
def test_admin_read_permissions_are_independent_and_bounded(pat, mcp):
    asked = []

    def handler(request):
        asked.append(request.url)
        assert request.method == "GET" and request.url.params["page_size"] == "1"
        return httpx.Response(mcp if request.url.path.endswith("mcp_client_connections") else pat)

    ctx = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    items = onboarding.check(CONNECTION, "inventory", {"credential": {"token": TOKEN}}, ctx)
    assert {item["permission"]: item["status"] for item in items} == {
        "workspace_tokens": "GRANTED" if pat == 200 else "MISSING",
        "mcp_connections": "GRANTED" if mcp == 200 else "MISSING"}
    assert asked[1].params["workspace_ids"] == WORKSPACE
    assert TOKEN not in json.dumps(items)


def test_plan_changes_reuse_owned_collection_and_empty_selection_is_atomic():
    repo = InMemoryRepository()
    factory = lambda: httpx.Client(transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json={"results": [], "has_more": False, "next_cursor": None})))
    record, active = activated(repo, {**CONNECTION, "credential": {"token": TOKEN}}, {"inventory": {}}, factory)
    [child] = active["created"]
    store, cid = CoverageStore(repo), uuid.UUID(child["id"])
    before = store.get(cid)
    assert before["spec"]["options"]["sources"] == ["personal_access_tokens"]
    for plan, sources in [({"mcp_connections": True}, ["personal_access_tokens", "mcp_client_connections"]),
                          ({"personal_access_tokens": False, "mcp_connections": True}, ["mcp_client_connections"]),
                          ({}, ["personal_access_tokens"])]:
        service.request_check(repo, record["id"], "admin", {"plans": {"inventory": plan}})
        run_check(repo, record, factory)
        view = service.update_plan(repo, SETTINGS, record["id"], "inventory", {"plan": plan}, "admin")
        assert view["changed"][0]["id"] == str(cid)
        assert len(store.list_connections()) == 1
        assert store.get(cid)["spec"]["options"]["sources"] == sources
        assert store.get(cid)["spec"]["secret_refs"] == before["spec"]["secret_refs"]
    saved = store.get(cid)
    with pytest.raises(service.OnboardingError, match="NOTION_INVENTORY_SOURCES_REQUIRED"):
        service.update_plan(repo, SETTINGS, record["id"], "inventory",
                            {"plan": {"personal_access_tokens": False, "mcp_connections": False}}, "admin")
    assert store.get(cid) == saved


@pytest.mark.parametrize("pat,mcp,expected,calls", [(200, 403, "GRANTED", 1), (403, 200, "GRANTED", 2),
    (403, 403, "MISSING", 2), (401, 200, "MISSING", 1), (500, 403, "MISSING", 2)])
def test_enterprise_auth_accepts_either_inventory_scope_without_directory_scope(pat, mcp, expected, calls):
    seen = []

    def handler(request):
        seen.append(request.url)
        assert request.url.params["page_size"] == "1"
        assert "/users" not in request.url.path
        return httpx.Response(mcp if request.url.path.endswith("mcp_client_connections") else pat,
                              json={"results": [], "has_more": False})

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    result = onboarding.authenticate(CONNECTION, {"credential": {"token": TOKEN}}, context)
    assert result["status"] == expected and len(seen) == calls
    assert TOKEN not in json.dumps(result)


def test_enterprise_auth_does_not_accept_malformed_success_or_missing_workspace():
    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json={"object": "user"})) ))
    assert onboarding.authenticate(CONNECTION, {"credential": {"token": TOKEN}}, context)["status"] == "ERROR"
    assert onboarding.authenticate({**CONNECTION, "target": {}}, {}, context)["detail"] == "NOTION_WORKSPACE_ID_REQUIRED"


def test_standard_plan_rejects_enterprise_auth_and_inventory_on_server():
    for method, purposes in [("organization_bot", []), ("integration", ["inventory"])]:
        with pytest.raises(service.OnboardingError):
            service._method("notion", purposes, method, "standard", new_setup=True)
    assert service._method("notion", ["exposure"], "integration", "standard", new_setup=True)
    with pytest.raises(service.OnboardingError, match="EDITION_RETIRED_FOR_NEW_CONNECTIONS"):
        service._method("notion", ["exposure"], "integration", "cloud", new_setup=True)
    assert service._method("notion", ["exposure"], "integration", "cloud")


@pytest.fixture
def unpaced(monkeypatch):
    from cremore_notion_provider.collectors import requests

    monkeypatch.setattr(requests, "connection_limiter",
                        lambda *_: SimpleNamespace(acquire=lambda: None, defer=lambda _: None))


def test_missing_workspace_cannot_authenticate_or_grant_mcp(unpaced):
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(200 if request.url.path.endswith("mcp_client_connections") else 404,
                              json={"results": [], "has_more": False})

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    result = onboarding.authenticate(CONNECTION, {"credential": {"token": TOKEN}}, context)
    assert result["status"] == "MISSING"
    assert result["detail"] == "NOTION_WORKSPACE_NOT_VISIBLE"
    assert seen == [f"/admin/v1/spaces/{WORKSPACE}/personal_access_tokens"]
    seen.clear()
    items = onboarding.check(CONNECTION, "inventory", {"credential": {"token": TOKEN}}, context)
    assert {item["permission"]: item["status"] for item in items} == {
        "workspace_tokens": "MISSING", "mcp_connections": "MISSING"}
    assert all(item["detail"] == "NOTION_WORKSPACE_NOT_VISIBLE" for item in items)
    assert seen == [f"/admin/v1/spaces/{WORKSPACE}/personal_access_tokens"]


def test_unverified_workspace_mcp_only_empty_listing_is_not_a_complete_inventory(unpaced):
    # A mistyped or foreign workspace: the bot lacks the PAT scope (403) and MCP answers any unknown ID with [].
    def handler(request):
        return httpx.Response(200 if request.url.path.endswith("mcp_client_connections") else 403,
                              json={"results": [], "has_more": False, "next_cursor": None})

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    assert onboarding.authenticate(CONNECTION, {"credential": {"token": TOKEN}}, context)["status"] == "GRANTED"
    items = onboarding.check(CONNECTION, "inventory", {"credential": {"token": TOKEN}}, context)
    assert {item["permission"]: item["status"] for item in items} == {
        "workspace_tokens": "MISSING", "mcp_connections": "GRANTED"}
    [child] = onboarding.children(CONNECTION, "inventory", {"personal_access_tokens": False, "mcp_connections": True})
    spec = MetadataConnectionSpec.model_validate({**child["spec"], "secret_refs": {"token": "vault://notion/test"}})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        pages = list(collect_pages(spec, secrets={"token": TOKEN}, checkpoint={}, check=lambda: None,
                                   client=client, sleep=lambda _: None))
    mcp = [row for page in pages for row in page.records
           if row.record_type == "operation_report" and row.provenance.operation == "notion.mcp_client_connections"]
    assert [(row.status, row.proves_completeness) for row in mcp] == [("PARTIAL", False)]
    assert pages[-1].status == "PARTIAL" and "NOTION_WORKSPACE_UNVERIFIED" in pages[-1].reasons


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503, None])
def test_failed_search_does_not_claim_no_pages_shared(status, unpaced):
    def handler(request):
        if status is None:
            raise httpx.ConnectError("synthetic transport failure", request=request)
        return httpx.Response(status, headers={"Retry-After": "0"})

    context = SimpleNamespace(http_client=lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    read, shared = onboarding.check(CONNECTION, "exposure", {"credential": {"token": TOKEN}}, context)
    assert shared["status"] == "NOT_REPORTED"
    assert shared["detail"] == read["detail"]
    assert shared["detail"] != "NO_PAGE_SHARED_WITH_INTEGRATION"
