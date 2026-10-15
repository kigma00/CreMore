"""Reference confirmation keeps provider outages distinct from access denials."""

from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest

from cremore.collectors.base import CollectorError, RequestBudget
from cremore.scanning.catalog import list_resources
from cremore_notion_provider import catalog

PAGE = "11111111-2222-4333-8444-555555555555"
NOW = datetime(2026, 10, 1, tzinfo=UTC)
PAYLOAD = {"provider": "notion", "connection_kind": "source", "connection_id": "synthetic",
           "token": "synthetic", "reference": PAGE}


@pytest.fixture(autouse=True)
def unpaced(monkeypatch):
    monkeypatch.setattr(catalog, "connection_limiter",
                        lambda *_: SimpleNamespace(acquire=lambda: None, defer=lambda _: None))


def resolve(handler):
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        return list_resources(PAYLOAD, http_client=lambda: client, now=NOW, request_budget=RequestBudget(10))


@pytest.mark.parametrize("status", [401, 429, 500, 503, 529, None])
@pytest.mark.parametrize("after_page_denial", [False, True])
def test_reference_failure_never_returns_denied(status, after_page_denial):
    def handler(request):
        if after_page_denial and "/pages/" in request.url.path:
            return httpx.Response(404)
        if status is None:
            raise httpx.ConnectError("synthetic transport failure", request=request)
        return httpx.Response(status, headers={"Retry-After": "0"})

    with pytest.raises(CollectorError) as error:
        resolve(handler)
    assert error.value.code == "NOTION_REFERENCE_FAILED"
    assert error.value.detail == (f"HTTP {status}" if status is not None else "ConnectError")


@pytest.mark.parametrize("page_status,database_status", [(403, 403), (403, 404), (404, 403), (404, 404)])
def test_reference_denied_only_after_both_endpoints_refuse(page_status, database_status):
    items, completeness = resolve(lambda request: httpx.Response(
        page_status if "/pages/" in request.url.path else database_status))
    assert completeness == "PARTIAL"
    assert items[0]["list_visibility"] == "DENIED"
    assert items[0]["reason_code"] == "INSUFFICIENT_PERMISSION"


def test_reference_database_after_page_not_found_is_still_visible():
    items, completeness = resolve(lambda request: httpx.Response(404) if "/pages/" in request.url.path
                                 else httpx.Response(200, json={"object": "database", "id": PAGE}))
    assert completeness == "PARTIAL"
    assert items[0]["resource_type"] == "NOTION_DATA_SOURCE"
    assert items[0]["list_visibility"] == "VISIBLE"


def test_reference_malformed_success_is_not_permission_denial():
    with pytest.raises(CollectorError, match="NOTION_REFERENCE_FAILED"):
        resolve(lambda _: httpx.Response(200, json={"unexpected": "response"}))
