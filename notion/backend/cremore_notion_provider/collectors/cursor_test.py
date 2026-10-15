import httpx
import pytest

from cremore.collectors import base
from cremore.collectors.base import CollectorError
from cremore_notion_provider.collectors.notion import NotionCollector


@pytest.mark.parametrize("cursor", ["x" * 17, {"bad": True}, None])
def test_notion_search_rejects_bad_cursor_without_another_request(monkeypatch, cursor):
    monkeypatch.setattr(base, "MAX_CURSOR_BYTES", 16)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"results": [], "has_more": True, "next_cursor": cursor})

    collector = NotionCollector(httpx.Client(transport=httpx.MockTransport(handler)), "synthetic")
    with pytest.raises(CollectorError) as caught:
        list(collector.collect())
    assert str(caught.value) == "NOTION_SEARCH_INCOMPLETE: invalid cursor"
    assert len(calls) == 1


def test_notion_search_cursor_count_is_bounded_even_with_empty_pages(monkeypatch):
    monkeypatch.setattr(base, "MAX_CURSOR_HISTORY", 2)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"results": [], "has_more": True, "next_cursor": str(len(calls))})

    collector = NotionCollector(httpx.Client(transport=httpx.MockTransport(handler)), "synthetic")
    with pytest.raises(CollectorError, match="NOTION_SEARCH_INCOMPLETE"):
        list(collector.collect())
    assert len(calls) == 3


def test_notion_block_cursor_limit_retains_partial_status_and_escapes_opaque_cursors(monkeypatch):
    monkeypatch.setattr(base, "MAX_CURSOR_BYTES", 16)
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 2:
            assert request.url.params["start_cursor"] == "next&x=1"
            assert "x" not in request.url.params
        return httpx.Response(200, json={"results": [], "has_more": True,
                                        "next_cursor": "next&x=1" if len(calls) == 1 else "x" * 17})

    collector = NotionCollector(httpx.Client(transport=httpx.MockTransport(handler)), "synthetic")
    assert collector._page_data("page") == (b"", False)
    assert len(calls) == 2


def test_notion_nested_block_histories_share_the_aggregate_cursor_budget(monkeypatch):
    monkeypatch.setattr(base, "MAX_CURSOR_HISTORY", 1)
    calls = []

    def handler(request):
        calls.append(request)
        parent = "/blocks/page/" in request.url.path
        if parent:
            return httpx.Response(200, json={"results": [{"id": "child", "has_children": True}],
                "has_more": True, "next_cursor": "parent-next"})
        return httpx.Response(200, json={"results": [], "has_more": "start_cursor" not in request.url.params,
                                        "next_cursor": "child-next"})

    collector = NotionCollector(httpx.Client(transport=httpx.MockTransport(handler)), "synthetic")
    assert collector._page_data("page") == (b"", False)
    assert len(calls) == 3  # no parent continuation after the child used the shared admission
