"""Offline Notion transport + real detector benchmark; no content is written.

Run with an installation of this checkout:
  python -m scripts.benchmark_notion_markdown --pages 500 --latency-ms 5
  python -m scripts.benchmark_notion_markdown --pages 5 --paced
  python scripts/benchmark_notion_markdown.py --pages 500 --changed 5 --assert

Without --paced, wall time excludes provider pacing. The separately reported
pacing floor is arithmetic, not a measured live-provider completion time.

--changed K counts requests instead, one collector per page as the runtime splits a
Notion root: (a) a full scan with the plan's search metadata (its walk plus one request
per page; the walk finds every approved page here, all of them the shared pages), (b) the
same scan without metadata, (c) a change scan (the feed's search walk plus the EVENT reads
of the K changed pages), and, printed only, (d) the approved pages spread evenly over a
workspace ten times larger. Paced seconds are requests / 2.5. --assert exits nonzero when
(a) costs more than 1.05 requests per page or (c) 10 paced seconds.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta

from cremore_notion_provider.collectors.notion import NotionCollector, _timestamp
from cremore_notion_provider.collectors.requests import NotionRateLimiter
from cremore_notion_provider.source import changes_since_batch, plan_metadata

from cremore.collectors.base import RequestBudget, guard_requests
from cremore.detection import Engine
from cremore.detection.custom import rule_definition
from cremore.detection.engine import EngineConfig
from cremore.detection.models import DetectorInput
from cremore.domain.models import CustomRule

REVISION = "2026-10-01T00:00:00Z"
REQUESTS_PER_SECOND = 2.5


class Response:
    status_code = 200

    def __init__(self, data):
        self.data = data

    def json(self):
        return self.data


class Unpaced:
    def acquire(self):
        pass

    def defer(self, delay):
        pass


class SyntheticClient:
    """Four nested block groups/page; every tenth page has a synthetic match."""

    def __init__(self, pages, latency):
        self.pages, self.latency = pages, latency
        self.lock = threading.Lock()
        self.requests, self.active, self.peak = 0, 0, 0

    def _begin(self):
        with self.lock:
            self.requests += 1
            self.active += 1
            self.peak = max(self.peak, self.active)
        time.sleep(self.latency)

    def _end(self):
        with self.lock:
            self.active -= 1

    @staticmethod
    def page(index):
        identifier = f"{index:032x}"
        return {"object": "page", "id": identifier, "last_edited_time": REVISION,
                "url": f"https://notion.so/{identifier}"}

    @staticmethod
    def text(index):
        return f"SYNTHETIC_NOTION_{index:08d}" if index % 10 == 0 else "ordinary synthetic text"

    def post(self, _url, *, json, **_kwargs):
        self._begin()
        try:
            start = int(json.get("start_cursor", 0))
            end = min(start + 100, self.pages)
            return Response({"results": [self.page(index) for index in range(start, end)],
                             "has_more": end < self.pages, "next_cursor": str(end)})
        finally:
            self._end()

    def get(self, url, **_kwargs):
        self._begin()
        try:
            if "/pages/" in url:
                identifier = url.split("/pages/")[1].split("/")[0]
                index = int(identifier, 16)
                if url.endswith("/markdown"):
                    return Response({"object": "page_markdown", "id": identifier,
                                     "markdown": "\n".join([self.text(index)] * 4),
                                     "truncated": False, "unknown_block_ids": []})
                return Response(self.page(index))
            identifier = url.split("/blocks/")[1].split("/")[0]
            if "." not in identifier:
                return Response({"results": [{"type": "toggle", "id": f"{identifier}.{n}",
                                              "has_children": True} for n in range(4)], "has_more": False})
            page, group = identifier.split(".")
            block_id = f"{int(page, 16) * 4 + int(group) + 10000:032x}"
            return Response({"results": [{"id": block_id, "type": "paragraph",
                                         "paragraph": {"rich_text": [{"plain_text": self.text(int(page, 16))}]}}],
                             "has_more": False})
        finally:
            self._end()


class LegacyBlocksCollector(NotionCollector):
    """The previous sequential page/block request strategy, with the same cap."""

    def _markdown_data(self, page_id):
        data, complete = self._page_data(page_id)
        return data, complete, "blocks"

    def collect(self):
        # Single-page delegates reproduce sequential read + header recheck;
        # the listing remains one Search pagination walk for the whole run.
        from cremore.collectors.base import CollectedObject
        from cremore.detection import ResourceRef

        for page in self._iter_pages():
            page, data, complete, _mode = self._read_page(page)
            assert complete and data is not None
            header = self._header(page["id"])
            assert header and _timestamp(header["last_edited_time"]) == _timestamp(page["last_edited_time"])
            yield CollectedObject(ResourceRef(source_type="notion", resource=page["id"],
                                              location=page["url"]), data)


def measure(kind, pages, latency, paced):
    client = SyntheticClient(pages, latency)
    limiter = NotionRateLimiter() if paced else Unpaced()
    cls = LegacyBlocksCollector if kind == "sequential_blocks" else NotionCollector
    source = cls(client, "synthetic-benchmark", max_pages=pages, rate_limiter=limiter)
    rule = CustomRule(id=uuid.UUID(int=1), name="Synthetic benchmark", pattern=r"SYNTHETIC_NOTION_[0-9]{8}")
    engine = Engine(EngineConfig(), definitions=[rule_definition(rule)])
    started = time.perf_counter()
    count = detections = 0
    for obj in source.collect():
        found = engine.scan(DetectorInput(obj.data, obj.resource, verify=False))
        if found and kind != "sequential_blocks":
            obj.refine_detections(found)
        assert obj.complete
        count += 1
        detections += len(found)
    wall = time.perf_counter() - started
    assert count == pages and detections == (pages + 9) // 10
    return {"strategy": kind, "pages": count, "detections": detections, "requests": client.requests,
            "peak_http_in_flight": client.peak, "measured_wall_seconds": round(wall, 4),
            "pacing_enabled": paced, "computed_2_5rps_floor_seconds": round(max(0, client.requests - 1) * 0.4, 1)}


class CountingWorkspace:
    """Search (newest edits first), page headers and Markdown; every request is counted."""

    def __init__(self, pages, changed, cursor):
        old, new = (cursor - timedelta(days=1)).isoformat(), (cursor + timedelta(minutes=1)).isoformat()
        self.pages = [{"object": "page", "id": f"{index:032x}", "url": f"https://notion.so/Page-{index:032x}",
                       "last_edited_time": new if index < changed else old,
                       "properties": {"title": {"type": "title", "title": [{"plain_text": f"Page {index}"}]}}}
                      for index in range(pages)]
        self.by_id = {page["id"]: page for page in self.pages}
        self.requests = 0

    def post(self, _url, *, json, **_kwargs):
        self.requests += 1
        start = int(json.get("start_cursor", 0))
        end = min(start + 100, len(self.pages))
        return Response({"results": self.pages[start:end], "has_more": end < len(self.pages),
                         "next_cursor": str(end)})

    def get(self, url, **_kwargs):
        self.requests += 1
        identifier = url.split("/pages/")[1].split("/")[0]
        if url.endswith("/markdown"):
            return Response({"object": "page_markdown", "id": identifier, "markdown": "ordinary synthetic text",
                             "truncated": False, "unknown_block_ids": []})
        return Response(self.by_id[identifier])


class Admit:
    """The worker's shared pacing store, admitting at once: pacing is computed, not slept."""

    def request_delay(self, key, interval, *, cooldown=None):
        return 0.0


def read_pages(client, page_ids, page_meta=None):
    # One collector per page, as the runtime's split roots read a Notion scope.
    for page_id in page_ids:
        entry = (page_meta or {}).get(page_id)
        objects = list(NotionCollector(client, "synthetic-benchmark", page_ids=[page_id],
                                       page_meta={page_id: entry} if entry else None).collect())
        assert len(objects) == 1 and objects[0].complete


def request_counts(pages, changed):
    cursor = datetime.now(UTC) - timedelta(hours=1)
    ids = [f"{index:032x}" for index in range(pages)]
    root = {"resource_id": "benchmark", "resource_type": "NOTION_PAGE", "provider_resource_id": ids[0],
            "page_mode": "PAGE_WITH_DESCENDANTS", "descendant_ids": ids[1:]}
    payload = {"token": "synthetic-benchmark"}
    with guard_requests(lambda: None, pacing=Admit()):
        full = CountingWorkspace(pages, changed, cursor)
        meta = plan_metadata(payload, [root], http_client=lambda: full, request_budget=RequestBudget(100_000))
        assert sorted(meta) == ids
        read_pages(full, ids, meta)
        bare = CountingWorkspace(pages, changed, cursor)
        read_pages(bare, ids)
        change = CountingWorkspace(pages, changed, cursor)
        answer = changes_since_batch(payload, [root], {"benchmark": {"cursor": cursor.isoformat()}},
                                     http_client=lambda: change, request_budget=RequestBudget(60))["benchmark"]
        assert answer.paths == ids[:changed]
        read_pages(change, answer.paths)  # an EVENT run's pages carry no plan metadata
        # The approved pages spread evenly over a workspace ten times larger: the walk's cap
        # leaves the less recently edited half to their own headers.
        wide = CountingWorkspace(pages * 10, 0, cursor)
        approved = [page["id"] for page in wide.pages[::10]]
        spread = {**root, "provider_resource_id": approved[0], "descendant_ids": approved[1:]}
        read_pages(wide, approved, plan_metadata(payload, [spread], http_client=lambda: wide,
                                                 request_budget=RequestBudget(100_000)))
    return {"pages": pages, "changed": changed, "full_with_metadata_requests": full.requests,
            "full_without_metadata_requests": bare.requests, "change_scan_requests": change.requests,
            "wide_workspace_pages": pages * 10, "wide_workspace_requests": wide.requests}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pages", type=int, default=500)
    parser.add_argument("--latency-ms", type=float, default=5)
    parser.add_argument("--paced", action="store_true")
    parser.add_argument("--changed", type=int, help="count requests of full and change scans instead")
    parser.add_argument("--assert", dest="check", action="store_true",
                        help="with --changed: exit 1 unless the request targets hold")
    args = parser.parse_args(argv)
    if not 1 <= args.pages <= 1000 or not 0 <= args.latency_ms <= 1000:
        parser.error("pages must be 1..1000 and latency-ms 0..1000")
    if args.changed is None:
        for strategy in ("sequential_blocks", "markdown_three_workers"):
            print(json.dumps(measure(strategy, args.pages, args.latency_ms / 1000, args.paced), sort_keys=True))
        return 0
    if not 0 <= args.changed <= args.pages:
        parser.error("changed must be 0..pages")
    counts = request_counts(args.pages, args.changed)
    per_page = counts["full_with_metadata_requests"] / args.pages
    full_seconds = counts["full_with_metadata_requests"] / REQUESTS_PER_SECOND
    change_seconds = counts["change_scan_requests"] / REQUESTS_PER_SECOND
    ok = per_page <= 1.05 and change_seconds < 10
    print(json.dumps(counts, sort_keys=True))
    print(f"NOTION BENCH {'OK' if ok else 'FAIL'} full_requests_per_page={per_page:.2f} "
          f"full_paced_seconds={full_seconds:.1f} change_requests={counts['change_scan_requests']} "
          f"change_paced_seconds={change_seconds:.1f}")
    return 1 if args.check and not ok else 0


if __name__ == "__main__":
    sys.exit(main())
