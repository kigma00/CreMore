import threading
import time
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta

import pytest

from cremore.collectors.base import (
    CollectorError,
    RequestBudget,
    RequestBudgetExceeded,
    guard_requests,
)
from cremore.detection.models import SanitizedDetection
from cremore_notion_provider.collectors.notion import LOOKBACK, NotionCollector
from cremore_notion_provider.collectors.requests import (
    NotionRateLimiter,
    connection_limiter,
    retry_delay,
)

PAGE = "a" * 32
BLOCK = "b" * 32
REVISION = "2026-10-01T00:00:00Z"


class Unpaced:
    def acquire(self):
        pass

    def defer(self, delay):
        pass


class Response:
    def __init__(self, data, status=200, headers=None):
        self.data, self.status_code = data, status
        self.headers = headers or {}

    def json(self):
        return self.data


class Client:
    def __init__(self, *, markdown="observed text", truncated=False, unknown=None, blocks=None):
        self.markdown, self.truncated, self.unknown = markdown, truncated, unknown or []
        self.blocks = blocks if blocks is not None else [paragraph(markdown)]
        self.calls = []
        self.revision = REVISION  # the page header's last_edited_time

    def get(self, url, **kwargs):
        self.calls.append(url)
        assert kwargs["headers"]["Notion-Version"] == "2026-03-11"
        if "/blocks/" in url:
            return Response({"results": self.blocks, "has_more": False})
        page = url.split("/pages/")[1].split("/")[0]
        if url.endswith("/markdown"):
            return Response({"object": "page_markdown", "id": page, "markdown": self.markdown,
                             "truncated": self.truncated, "unknown_block_ids": self.unknown})
        return Response({"object": "page", "id": page, "url": f"https://notion.so/{page}",
                         "last_edited_time": self.revision})


def paragraph(text, identifier=BLOCK):
    return {"id": identifier, "type": "paragraph", "paragraph": {"rich_text": [{"plain_text": text}]}}


def collector(client=None, **kwargs):
    return NotionCollector(client or Client(), "synthetic", page_ids=[PAGE], rate_limiter=Unpaced(), **kwargs)


def detection(line=1):
    return SanitizedDetection("synthetic", "TEST", "synthetic-fingerprint", line_number=line)


def test_markdown_only_until_a_detection_then_exact_block_refinement():
    client = Client()
    source = collector(client)
    [obj] = list(source.collect())
    assert obj.data == b"observed text" and obj.complete
    # The page's header, then its Markdown: no second header read after the body.
    assert len(client.calls) == 2 and not any("/blocks/" in url for url in client.calls)
    assert obj.refine_detections([]) == []
    # A fresh object is refined once, after the engine has actually detected it.
    [obj] = list(collector(client).collect())
    result = [detection()]
    assert obj.refine_detections(result) is result
    assert result[0].extra_safe_data == {"notion_block_id": BLOCK}
    assert obj.resource.location == f"https://notion.so/{PAGE}"
    count = len(client.calls)
    assert obj.refine_detections(result) is result and len(client.calls) == count


@pytest.mark.parametrize("blocks", [[paragraph("observed text", "c" * 32), paragraph("observed text")],
                                    [paragraph("similar masked hint")]])
def test_ambiguous_or_nonexact_block_evidence_is_not_attributed(blocks):
    [obj] = list(collector(Client(blocks=blocks)).collect())
    [found] = obj.refine_detections([detection()])
    assert found.extra_safe_data == {}


def test_incomplete_markdown_preserves_observed_text_and_permission_gap():
    source = collector(Client(markdown="markdown evidence", unknown=[BLOCK], blocks=[paragraph("block evidence")]))
    [obj] = list(source.collect())
    assert b"markdown evidence" in obj.data and b"block evidence" in obj.data
    assert not obj.complete and obj.resource.revision == ""
    assert source.failed_objects == 1 and source.failed_page_ids == {PAGE}


def test_truncated_markdown_can_fall_back_to_complete_approved_blocks():
    source = collector(Client(markdown="fragment", truncated=True, blocks=[paragraph("full text")]))
    [obj] = list(source.collect())
    assert obj.complete and b"fragment" in obj.data and b"full text" in obj.data


@pytest.mark.parametrize("kind,field", [("bookmark", "caption"), ("embed", "caption"), ("template", "rich_text")])
def test_unknown_markdown_tags_read_block_text(kind, field):
    text = f'<unknown url="https://notion.so/outside" alt="{kind}"/>'
    client = Client(markdown=text, blocks=[
        {"id": BLOCK, "type": kind, kind: {field: [{"plain_text": "block evidence"}]}}])
    [obj] = list(collector(client).collect())
    assert obj.complete and b"block evidence" in obj.data and text.encode() in obj.data
    assert obj.resource.metadata["content_format"] == "markdown+blocks"
    assert len(client.calls) == 3 and "/blocks/" in client.calls[-1]
    assert not any("outside" in url for url in client.calls)


def test_unknown_markdown_tags_with_unsupported_blocks_remain_uncheckpointed():
    source = collector(Client(markdown='<unknown alt="unsupported"/>', blocks=[{"type": "unsupported"}]))
    [obj] = list(source.collect())
    assert not obj.complete and obj.resource.revision == ""
    assert source.failed_objects == 1 and source.failed_page_ids == {PAGE}


def test_unknown_markdown_fallback_respects_request_budget():
    client = Client(markdown='<unknown alt="bookmark"/>')
    source = collector(client, request_budget=RequestBudget(2))
    with pytest.raises(RequestBudgetExceeded):
        list(source.collect())
    assert source.requests == len(client.calls) == 2


def test_markdown_limit_is_utf8_safe_partial_and_never_checkpointed():
    source = collector(Client(markdown="가나다라"), max_object_bytes=7)
    [obj] = list(source.collect())
    assert obj.data.decode() == "가나" and not obj.complete and source.failed_page_ids == {PAGE}


def test_markdown_failure_falls_back_without_following_child_page_or_unknown_ids():
    class Missing(Client):
        def get(self, url, **kwargs):
            if url.endswith("/markdown"):
                self.calls.append(url)
                return Response({}, 404)
            return super().get(url, **kwargs)
    client = Missing(blocks=[paragraph("visible"), {"type": "child_page", "id": "outside", "has_children": True}])
    [obj] = list(collector(client).collect())
    assert obj.data == b"visible" and obj.complete
    assert not any("outside" in url for url in client.calls)


def test_refinement_failure_keeps_detection_and_marks_retry():
    class Denied(Client):
        def get(self, url, **kwargs):
            if "/blocks/" in url:
                return Response({}, 403)
            return super().get(url, **kwargs)
    source = collector(Denied())
    [obj] = list(source.collect())
    result = [detection()]
    assert obj.refine_detections(result) is result and result[0].extra_safe_data == {}
    assert not obj.complete and obj.resource.revision == "" and source.failed_page_ids == {PAGE}


def test_three_fetch_workers_overlap_and_yield_in_order_with_owner_thread_guards():
    context = ContextVar("synthetic_context", default="missing")
    context.set("present")
    owner = threading.get_ident()
    guards = []

    class Concurrent(Client):
        def __init__(self):
            super().__init__()
            self.lock, self.active, self.peak, self.threads = threading.Lock(), 0, 0, set()

        def get(self, url, **kwargs):
            assert context.get() == "present"
            with self.lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
                self.threads.add(threading.get_ident())
            time.sleep(0.02)
            try:
                return super().get(url, **kwargs)
            finally:
                with self.lock:
                    self.active -= 1
    client = Concurrent()
    ids = [f"{n:032x}" for n in range(7)]
    source = NotionCollector(client, "synthetic", page_ids=ids, rate_limiter=Unpaced())
    with guard_requests(lambda: guards.append(threading.get_ident())):
        objects = list(source.collect())
    assert [obj.resource.metadata["page_id"] for obj in objects] == ids
    assert client.peak == 3 and len(client.threads) == 3 and owner not in client.threads
    assert guards and set(guards) == {owner}


def test_cancellation_during_fetch_is_propagated_and_executor_stops():
    calls = []
    def guard():
        calls.append(1)
        if len(calls) > 3:
            raise CollectorError("SYNTHETIC_CANCELLED")
    with guard_requests(guard), pytest.raises(CollectorError, match="SYNTHETIC_CANCELLED"):
        list(collector().collect())
    assert not any(thread.name.startswith("notion-fetch") for thread in threading.enumerate())


def test_closing_after_first_page_does_not_leave_prefetch_workers_blocked():
    source = NotionCollector(Client(), "synthetic", page_ids=[f"{n:032x}" for n in range(10)],
                             rate_limiter=Unpaced())
    iterator = source.collect()
    assert next(iterator).complete
    started = time.monotonic()
    iterator.close()
    assert time.monotonic() - started < 1
    assert not any(thread.name.startswith("notion-fetch") for thread in threading.enumerate())


def test_decoded_view_line_does_not_create_block_attribution():
    [obj] = list(collector().collect())
    found = detection()
    found.decoder_type = "base64"
    assert obj.refine_detections([found])[0].extra_safe_data == {}


def test_table_cells_captions_and_equations_are_in_block_fallback():
    client = Client(blocks=[
        {"type": "table_row", "table_row": {"cells": [[{"plain_text": "cell"}]]}},
        {"type": "image", "image": {"caption": [{"plain_text": "caption"}]}},
        {"type": "equation", "equation": {"expression": "equation"}},
    ])
    assert collector(client)._page_data(PAGE) == (b"cell\ncaption\nequation", True)


def test_unreadable_child_and_unsupported_blocks_stay_partial():
    source = collector(Client(blocks=[{"type": "unsupported"}, {"type": "toggle", "has_children": True}]))
    assert source._page_data(PAGE) == (b"", False)


@pytest.mark.parametrize("status", [429, 529])
def test_transient_retries_are_bounded_and_charge_every_attempt(status):
    class Busy(Client):
        def get(self, url, **kwargs):
            self.calls.append(url)
            return Response({}, status, {"Retry-After": "0"})
    client = Busy()
    source = collector(client, request_budget=RequestBudget(2))
    with pytest.raises(RequestBudgetExceeded):
        list(source.collect())
    assert source.requests == len(client.calls) == 2


def test_large_retry_after_is_not_ignored_or_slept_unboundedly():
    class Busy(Client):
        def get(self, url, **kwargs):
            self.calls.append(url)
            return Response({}, 429, {"Retry-After": "1000"})
    client = Busy()
    source = collector(client)
    assert list(source.collect()) == [] and len(client.calls) == 1
    assert source.failed_page_ids == {PAGE}


def test_connection_rate_limit_is_shared_and_has_no_burst():
    assert connection_limiter("one", "https://api.notion.com") is connection_limiter("one", "https://api.notion.com")
    clock = [0.0]
    times = []
    limiter = NotionRateLimiter(clock=lambda: clock[0], sleep=lambda delay: clock.__setitem__(0, clock[0] + delay))
    for _ in range(9):
        limiter.acquire(check=lambda: None)
        times.append(clock[0])
    assert times == pytest.approx([index * 0.4 for index in range(9)])
    limiter.defer(2)
    limiter.acquire(check=lambda: None)
    assert clock[0] == pytest.approx(times[-1] + 2)
    assert retry_delay(Response({}, headers={"Retry-After": "nan"}), 0) == float("inf")


def test_retry_after_delays_the_shared_limiter_and_checks_cancellation():
    clock = [0.0]
    limiter = NotionRateLimiter(clock=lambda: clock[0], sleep=lambda delay: clock.__setitem__(0, clock[0] + delay))

    class OnceBusy(Client):
        def get(self, url, **kwargs):
            if not self.calls:
                self.calls.append(url)
                return Response({}, 529, {"Retry-After": "1.2"})
            return super().get(url, **kwargs)

    source = NotionCollector(OnceBusy(), "synthetic", rate_limiter=limiter)
    assert source._get(f"/v1/pages/{PAGE}")[0]["id"] == PAGE
    assert source.requests == 2 and clock[0] == pytest.approx(1.2)
    limiter.defer(5)
    def cancel():
        raise CollectorError("CANCEL_DURING_WAIT")
    with guard_requests(cancel), pytest.raises(CollectorError, match="CANCEL_DURING_WAIT"):
        limiter.acquire()


def test_modified_page_skips_only_old_successes_and_retries_failures():
    source = collector(watermark_since="2026-10-02T00:00:00Z")
    assert list(source.collect()) == [] and source.requests == 1
    source = collector(watermark_since="2026-10-02T00:00:00Z", failed_page_ids=[PAGE])
    assert len(list(source.collect())) == 1 and source.requests == 2


def meta(edited=REVISION, *, observed=None, title="Runbook"):
    observed = observed or datetime.now(UTC).isoformat()
    return {PAGE: {"url": f"https://notion.so/Runbook-{PAGE}", "title": title, "last_edited_time": edited,
                   "observed_at": observed}}


def test_search_metadata_reads_a_page_with_its_markdown_alone():
    client = Client()
    [obj] = list(collector(client, page_meta=meta()).collect())
    assert client.calls == [f"https://api.notion.com/v1/pages/{PAGE}/markdown"]
    assert obj.complete and obj.data == b"observed text"
    assert (obj.resource.resource, obj.resource.location, obj.resource.revision) == (
        "Runbook", f"https://notion.so/Runbook-{PAGE}", REVISION)
    # A key spelled with dashes names the same page.
    dashed = f"{PAGE[:8]}-{PAGE[8:12]}-{PAGE[12:16]}-{PAGE[16:20]}-{PAGE[20:]}"
    client = Client()
    list(collector(client, page_meta={dashed: meta()[PAGE]}).collect())
    assert len(client.calls) == 1


@pytest.mark.parametrize("entry", [{"url": "", "title": "x", "last_edited_time": REVISION},
                                   {"url": "u", "title": None, "last_edited_time": REVISION},
                                   {"url": "u", "title": "x", "last_edited_time": "not a time"}, "not a dict"])
def test_an_entry_that_is_not_a_page_header_is_ignored(entry):
    client = Client()
    [obj] = list(collector(client, page_meta={PAGE: entry}).collect())
    assert len(client.calls) == 2 and obj.resource.location == f"https://notion.so/{PAGE}"


def test_a_delta_run_skips_a_page_fresh_metadata_shows_unchanged_without_a_request():
    client = Client()
    source = collector(client, page_meta=meta(), watermark_since="2026-10-02T00:00:00Z",
                       watched_keys=[f"https://notion.so/Runbook-{PAGE}"])
    assert list(source.collect()) == [] and client.calls == [] and source.requests == 0
    assert source.skipped_unchanged == 1 and source.unchanged_locations == {f"https://notion.so/Runbook-{PAGE}"}
    # A page that failed before is read whatever its edit time says: its Markdown alone.
    source = collector(client, page_meta=meta(), watermark_since="2026-10-02T00:00:00Z", failed_page_ids=[PAGE])
    assert len(list(source.collect())) == 1 and source.requests == 1 and source.failed_page_ids == set()


@pytest.mark.parametrize("observed", ["2026-10-01T00:00:00+00:00", None,
                                      (datetime.now(UTC) + timedelta(hours=6)).isoformat()])
def test_stale_unstamped_or_future_metadata_leaves_a_delta_decision_to_the_header(observed):
    entry = meta()[PAGE]
    if observed:
        entry["observed_at"] = observed
    else:
        del entry["observed_at"]
    client = Client()
    source = collector(client, page_meta={PAGE: entry}, watermark_since="2026-10-02T00:00:00Z")
    assert list(source.collect()) == [] and client.calls == [f"https://api.notion.com/v1/pages/{PAGE}"]
    # Outside a delta run the same metadata still saves the header read.
    client = Client()
    assert len(list(collector(client, page_meta={PAGE: entry}).collect())) == 1 and len(client.calls) == 1


@pytest.mark.parametrize("edited,read", [("2026-10-09T11:45:00Z", True), ("2026-10-09T11:43:00Z", False)])
def test_a_delta_decision_looks_back_lag_rounding_and_skew_before_the_watermark(edited, read):
    # The last run started at 12:00:30; watermark_since is that less the runtime's overlap.
    # A skip there on metadata walked at 11:55:31 can miss an edit at 11:45:45 the index had
    # not shown yet, which Notion reports as 11:45:00: this run must still read it.
    since = datetime(2026, 10, 9, 11, 55, 30, tzinfo=UTC)
    assert since - LOOKBACK == datetime(2026, 10, 9, 11, 43, 30, tzinfo=UTC)
    for page_meta in (meta(edited), None):
        client = Client()
        client.revision = edited
        source = collector(client, page_meta=page_meta, watermark_since=since)
        assert len(list(source.collect())) == int(read) and source.skipped_unchanged == int(not read)


def test_a_detected_page_from_metadata_is_refined_against_its_blocks_and_header():
    client = Client()
    [obj] = list(collector(client, page_meta=meta()).collect())
    result = [detection()]
    assert obj.refine_detections(result) is result and result[0].extra_safe_data == {"notion_block_id": BLOCK}
    assert [url.rsplit("/v1/", 1)[1] for url in client.calls] == [
        f"pages/{PAGE}/markdown", f"blocks/{PAGE}/children?page_size=100", f"pages/{PAGE}"]
    assert obj.complete and obj.resource.revision == REVISION
    # The fresh header names the page as it is now: renamed since the walk, it has moved.
    assert obj.resource.location == f"https://notion.so/{PAGE}" and obj.resource.resource == "Runbook"
    # The header moved since the search walk: the hit stays, the page is read again next run.
    client = Client()
    [obj] = list(collector(client, page_meta=meta("2026-09-30T00:00:00Z")).collect())
    [found] = obj.refine_detections([detection()])
    assert found.extra_safe_data == {} and not obj.complete and obj.resource.revision == ""
    assert obj.resource.location == f"https://notion.so/{PAGE}"


def test_a_page_edited_while_its_body_was_read_is_read_again_by_the_next_delta_run():
    # The page's task starts (its watermark), the body is read, and an edit lands meanwhile.
    start = datetime(2026, 10, 1, 0, 0, 30, tzinfo=UTC)
    client = Client()
    client.revision = "2026-10-01T00:00:00Z"
    [obj] = list(collector(client).collect())
    assert obj.complete and obj.resource.revision == "2026-10-01T00:00:00Z" and len(client.calls) == 2
    client.revision = "2026-10-01T00:01:00Z"  # minute-granular edit time of the concurrent edit
    source = collector(client, watermark_since=start - timedelta(minutes=5))
    assert len(list(source.collect())) == 1 and source.skipped_unchanged == 0
