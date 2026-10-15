import pytest

from cremore.collectors.base import CollectorError
from cremore.collectors.scan_safety_test import Notion, Response, paragraph
from cremore_notion_provider.collectors.notion import NotionCollector


def test_notion_watermark_skips_old_bodies_but_retries_failed_pages():
    client = Notion({"old": [paragraph("unchanged")], "retry": [paragraph("retry content")]})
    collector = NotionCollector(client, "synthetic", page_ids=["old", "retry"],
                                watermark_since="2026-09-15T01:00:00Z", failed_page_ids=["retry"])
    [obj] = list(collector.collect())
    assert obj.resource.metadata["page_id"] == "retry" and obj.complete
    assert collector.skipped_unchanged == 1 and collector.failed_page_ids == set()
    assert not any("/blocks/old/" in url for url in client.calls)
    assert sum(url.endswith("/pages/retry") for url in client.calls) == 1
    assert sum(url.endswith("/pages/retry/markdown") for url in client.calls) == 1


def test_notion_delta_records_only_watched_pages_it_found_unchanged():
    client = Notion({"old": [], "quiet": []})
    collector = NotionCollector(client, "synthetic", page_ids=["old", "quiet"],
                                watermark_since="2026-09-15T01:00:00Z",
                                watched_keys=["https://notion.so/old", "https://notion.so/elsewhere"])
    assert list(collector.collect()) == []
    assert collector.unchanged_locations == {"https://notion.so/old"}


def test_notion_page_changed_during_read_keeps_the_revision_seen_before_it_and_is_read_again():
    class Moving(Notion):
        def __init__(self):
            super().__init__({"moving": [paragraph("observed fragment")]})
            self.headers = 0

        def get(self, url, **kwargs):
            response = super().get(url, **kwargs)
            if "/pages/" in url:
                self.headers += 1
                if self.headers > 1:
                    response.data["last_edited_time"] = "2026-09-15T02:00:00Z"
            return response
    client = Moving()
    collector = NotionCollector(client, "synthetic", page_ids=["moving"])
    [obj] = list(collector.collect())
    # No header read after the body: the revision is the one seen before reading it.
    assert obj.data == b"observed fragment" and obj.complete and obj.resource.revision == "2026-09-15T00:00:00Z"
    assert collector.failed_page_ids == set() and sum("/blocks/" not in url for url in client.calls) == 2
    # The edit (at or after the run's start) is read by the next delta run.
    again = NotionCollector(client, "synthetic", page_ids=["moving"], watermark_since="2026-09-15T00:55:00Z")
    assert len(list(again.collect())) == 1 and again.skipped_unchanged == 0


def test_known_failure_omitted_by_search_is_retried_and_search_uses_edit_order():
    class Search(Notion):
        def post(self, url, **kwargs):
            assert kwargs["json"]["sort"] == {"direction": "descending", "timestamp": "last_edited_time"}
            return Response({"results": [], "has_more": False})
    client = Search({"retry": []})
    collector = NotionCollector(client, "synthetic", failed_page_ids=["retry"], watermark_since="2026-09-15T01:00:00Z")
    [obj] = list(collector.collect())
    assert obj.data == b"" and obj.complete and collector.failed_page_ids == set()
    assert not collector.authoritative_listing


def test_missing_known_page_remains_failed_not_removed():
    class Missing(Notion):
        def get(self, url, **kwargs):
            return Response({}, 404)
    collector = NotionCollector(Missing({}), "synthetic", page_ids=["missing"], failed_page_ids=["missing"])
    assert list(collector.collect()) == []
    assert collector.failed_page_ids == {"missing"} and collector.failed_objects == 1


def test_repeating_search_and_block_cursors_cannot_loop_or_claim_complete():
    class SearchLoop(Notion):
        def __init__(self):
            super().__init__({})
            self.searches = 0

        def post(self, *_args, **_kwargs):
            self.searches += 1
            return Response({"results": [], "has_more": True, "next_cursor": "repeat"})
    client = SearchLoop()
    with pytest.raises(CollectorError, match="NOTION_SEARCH_INCOMPLETE"):
        list(NotionCollector(client, "synthetic").collect())
    assert client.searches == 2

    class BlocksLoop(Notion):
        def get(self, url, **kwargs):
            if "/blocks/" in url:
                return Response({"results": [], "has_more": True, "next_cursor": "repeat"})
            return super().get(url, **kwargs)
    collector = NotionCollector(BlocksLoop({}), "synthetic", page_ids=["parent"])
    [obj] = list(collector.collect())
    assert obj.data == b"" and not obj.complete and collector.failed_objects == 1
