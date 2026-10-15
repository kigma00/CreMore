"""Notion workspace collector.

Reads approved pages as Markdown with three bounded fetch workers. Block walks
are reserved for incomplete Markdown and detected-page location refinement.
The injected HTTP client must support concurrent reads (the product uses httpx).

A page costs one request (its Markdown) when the run's plan found its header in
search (``page_meta``: cremore_notion_provider.search.plan_metadata, attached to each
page root by the worker runtime when it plans the run), two (header and Markdown)
otherwise, and none when a delta run finds it unchanged by fresh metadata. Every
request goes through the connection's limiter.

Notion content shared with an integration is workspace-internal, so the exposure
level is recorded as ``internal`` (not public).

Docs:
  https://developers.notion.com/reference/retrieve-page-markdown
  https://developers.notion.com/reference/post-search
  https://developers.notion.com/reference/get-block-children
  https://developers.notion.com/reference/rich-text
"""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from cremore.collectors.base import (
    DEFAULT_MAX_OBJECT_BYTES,
    CollectedObject,
    CollectorError,
    CursorHistory,
    RequestBudget,
    RequestBudgetExceeded,
    error_label,
)
from cremore.detection import ResourceRef
from cremore.http_client import bounded_request
from cremore_notion_provider.collectors.requests import (
    RequestDispatcher,
    connection_limiter,
    paced,
)

_API = "https://api.notion.com"
_VERSION = "2026-03-11"
# Blocks can nest arbitrarily; bound the walk so one deeply-nested page can never
# cost unbounded requests. Two levels covers the common page/toggle/column shapes.
_MAX_BLOCK_DEPTH = 2
NOTION_COLLECTOR_EPOCH = "notion-page-only-v1"
_FETCH_WORKERS = 3
# How far Notion's search index may trail a page's own edit time.
SEARCH_LAG = timedelta(minutes=10)
# Notion reports edit times rounded down to the minute.
EDIT_ROUNDING = timedelta(seconds=60)
# How far a worker's clock may stand from Notion's.
CLOCK_SKEW = timedelta(seconds=60)
# A delta run skips a page only when its reported edit time is older than watermark_since
# (the last run's start less the runtime's overlap) less this look-back (_read_page).
LOOKBACK = SEARCH_LAG + EDIT_ROUNDING + CLOCK_SKEW
# Search metadata older than this never decides that a page is unchanged (_fresh). The
# arithmetic in _fresh needs it no longer than the runtime's overlap
# (cremore/scanning/changes_test.py keeps the two consistent).
META_FRESH = timedelta(minutes=5)
# An observed_at this far ahead of our clock comes from a broken clock, not a fresh walk.
_AHEAD = timedelta(seconds=30)


class NotionCollector:
    # Search omission is not deletion evidence (index lag and sharing changes).
    authoritative_listing = False

    def __init__(
        self,
        client,
        token: str,
        *,
        max_object_bytes: int = DEFAULT_MAX_OBJECT_BYTES,
        max_pages: int = 1000,
        base_url: str = _API,
        notion_version: str = _VERSION,
        page_ids: list[str] | None = None,
        request_budget: RequestBudget | None = None,
        watermark_since: datetime | str | None = None,
        failed_page_ids: list[str] | None = None,
        watched_keys: list[str] | None = None,
        rate_limiter=None,
        page_meta: dict | None = None,
    ) -> None:
        if max_object_bytes <= 0:
            raise ValueError("max_object_bytes must be positive")
        if max_pages <= 0:
            raise ValueError("max_pages must be positive")
        self.client = client
        self.token = token
        self.max_object_bytes = max_object_bytes
        self.max_pages = max_pages
        self.base_url = base_url.rstrip("/")
        self.notion_version = notion_version
        self.request_budget = request_budget or RequestBudget()
        self._cursors = CursorHistory()
        self._cursor_lock = threading.Lock()
        self._dispatcher = None
        self.rate_limiter = rate_limiter or connection_limiter(token, self.base_url)
        # Approved scope: exactly these page ids (no search); a page that cannot
        # be fetched counts as unreadable, never as absent.
        self.page_ids = None if page_ids is None else list(page_ids)
        self.watermark_since = _timestamp(watermark_since)
        if watermark_since is not None and self.watermark_since is None:
            raise ValueError("watermark_since must be an ISO timestamp")
        self.retry_page_ids = frozenset(page.replace("-", "").lower() for page in (failed_page_ids or []))
        self.failed_page_ids: set[str] = set(self.retry_page_ids)
        # Search headers of the approved pages (plan_metadata), by dash-free lower-case id.
        # An entry that is not one is ignored: that page reads its own header instead.
        self.page_meta = {str(key).replace("-", "").lower(): meta
                          for key, meta in (page_meta.items() if isinstance(page_meta, dict) else ())
                          if _usable_meta(meta)}
        self.skipped_unchanged = 0
        # Watched page locations a delta run found unchanged: their recorded
        # exposures are still there, although the page is not read again.
        self._watched = frozenset(watched_keys or [])
        self.unchanged_locations: set[str] = set()
        # Pages that were found but whose blocks could not be read.
        self.failed_objects = 0
        self.requests = 0

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Notion-Version": self.notion_version,
            "Content-Type": "application/json",
        }

    # The limiter protocol requests.paced() drives: pacing, budget and cooldowns are
    # authorized on the owner thread, where the run's guard and budget live.
    def acquire(self) -> None:
        def authorize():
            self.rate_limiter.acquire()
            self.request_budget.consume()
            self.requests += 1
        if self._dispatcher is None:
            authorize()
        else:
            self._dispatcher.call(authorize)

    def defer(self, delay) -> None:
        # A retry cools down all three workers and sibling roots, not just this call.
        if self._dispatcher is None:
            self.rate_limiter.defer(delay)
        else:
            self._dispatcher.call(lambda: self.rate_limiter.defer(delay))

    def _fetch(self, method, path, **kwargs):
        failed = []

        def send():
            try:
                return bounded_request(
                    self.client, method, self.base_url + path, headers=self._headers(), **kwargs,
                )
            except RequestBudgetExceeded:
                raise
            except Exception as exc:  # noqa: BLE001 -- only safe provider error labels cross this boundary
                failed.append(error_label(exc))
                return None

        # Guard/lease exceptions raised while authorizing propagate, never become provider errors.
        resp = paced(self, send)
        return (None, failed[-1]) if failed else self._json_ok(resp)

    def _post(self, path: str, body: dict) -> tuple[dict | None, str]:
        return self._fetch("POST", path, json=body)

    def _get(self, path: str) -> tuple[dict | None, str]:
        return self._fetch("GET", path)

    @staticmethod
    def _json_ok(resp) -> tuple[dict | None, str]:
        status = getattr(resp, "status_code", 200)
        if status != 200:
            return None, f"HTTP {status}"
        try:
            data = resp.json()
        except Exception as exc:  # noqa: BLE001 -- Provider failure is a partial collection, with only the safe error label exposed.
            return None, error_label(exc)
        return (data if isinstance(data, dict) else None), "OK"

    def collect(self) -> Iterator[CollectedObject]:
        dispatcher = self._dispatcher = RequestDispatcher()
        executor = ThreadPoolExecutor(max_workers=_FETCH_WORKERS, thread_name_prefix="notion-fetch")
        pending = deque()
        pages = iter(self._iter_pages())
        exhausted = False
        attempted = 0
        try:
            while pending or not exhausted:
                while len(pending) < _FETCH_WORKERS and not exhausted:
                    try:
                        page = next(pages)
                    except StopIteration:
                        exhausted = True
                        break
                    if attempted >= self.max_pages:
                        self.failed_objects += 1
                        exhausted = True
                        break
                    attempted += 1
                    # Each job gets a fresh context; only the owner runs its request guard.
                    future = executor.submit(copy_context().run, self._read_page, page)
                    future.add_done_callback(dispatcher.completed)
                    pending.append(future)
                if not pending:
                    break
                future = pending[0]
                while not future.done():
                    dispatcher.pump()
                pending.popleft()
                page, data, complete, mode = future.result()
                page_id = str(page.get("id", ""))
                identity = page_id.replace("-", "").lower()
                if mode == "unchanged":
                    self.skipped_unchanged += 1
                    if page.get("url", page_id) in self._watched:
                        self.unchanged_locations.add(page.get("url", page_id))
                    continue
                if data is None or not complete:
                    self.failed_objects += 1
                    if identity:
                        self.failed_page_ids.add(identity)
                else:
                    self.failed_page_ids.discard(identity)
                if data is None:
                    continue
                obj = NotionPage(
                    ResourceRef(
                        source_type="notion", resource=_page_title(page) or page_id,
                        location=page.get("url", page_id), size=len(data),
                        revision=str(page.get("last_edited_time") or "") if complete else "",
                        metadata={"exposure": "internal", "page_id": identity,
                                  "collector_epoch": NOTION_COLLECTOR_EPOCH, "content_format": mode},
                    ), data, complete=complete, failure_counted=not complete,
                )
                obj.refiner = lambda detections, obj=obj: self._refine(obj, detections)
                yield obj
        finally:
            dispatcher.stopped.set()
            for future in pending:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
            self._dispatcher = None

    def _read_page(self, page):
        requested = page.get("_requested_page_id")
        if requested:
            page = self._header(requested)
            if page is None:
                return {"id": requested}, None, False, "unreadable"
        page_id = page.get("id")
        if page.get("object") != "page" or not isinstance(page_id, str) or not page_id:
            return {}, None, False, "unreadable"
        identity = page_id.replace("-", "").lower()
        modified = _timestamp(page.get("last_edited_time"))
        # LOOKBACK widens every source of the edit time alike: the previous run may have
        # skipped this page on search metadata (_fresh) while its watermark claimed the
        # run's start; looking back the same margin catches what that skip missed,
        # whichever way this run learns the time.
        if (self.watermark_since is not None and modified is not None
                and modified < self.watermark_since - LOOKBACK and identity not in self.retry_page_ids):
            return page, None, True, "unchanged"
        data, complete, mode = self._markdown_data(page_id)
        # No second header read after the body. The run's watermark is its start, and the
        # next delta run reads every page edited at or after that watermark less its overlap,
        # so an edit made while this body was read is read again then. Notion's edit times
        # are minute-granular, so the re-check never caught an edit within the same minute;
        # it only cost one more request per page.
        # An unknown revision cannot be checkpointed as a complete read.
        if modified is None:
            complete = False
        return page, data, complete, mode

    def _header(self, page_id):
        """The page's own header, or None when it cannot be read as this page."""
        current, _ = self._get(f"/v1/pages/{quote(page_id, safe='')}")
        if (current is None or current.get("object") != "page"
                or str(current.get("id", "")).replace("-", "").lower() != page_id.replace("-", "").lower()):
            return None
        return current

    def _markdown_data(self, page_id):
        result, _ = self._get(f"/v1/pages/{quote(page_id, safe='')}/markdown")
        valid = (isinstance(result, dict) and result.get("object") == "page_markdown"
                 and str(result.get("id", result.get("page_id", ""))).replace("-", "").lower()
                 == page_id.replace("-", "").lower()
                 and isinstance(result.get("markdown"), str)
                 and isinstance(result.get("truncated"), bool)
                 and isinstance(result.get("unknown_block_ids"), list))
        if valid:
            text = result["markdown"]
            encoded = text[:self.max_object_bytes].encode("utf-8")
            data = encoded[:self.max_object_bytes].decode("utf-8", "ignore").encode("utf-8")
            within_cap = len(text) <= self.max_object_bytes and len(encoded) <= self.max_object_bytes
            if not result["truncated"] and not result["unknown_block_ids"] and "<unknown" not in text:
                return data, within_cap, "markdown"
        # Unknown blocks may be permission gaps. A fallback cannot certify those
        # gaps away, even when its visible blocks finish successfully.
        fallback, complete = self._page_data(page_id)
        if valid:
            if fallback is None:
                return data, False, "markdown"
            # Keep both observed representations: a partial block walk must not
            # discard a detection already present in the Markdown fragment.
            joined = data + (b"\n" if data and fallback else b"") + fallback
            within_cap = within_cap and len(joined) <= self.max_object_bytes
            joined = joined[:self.max_object_bytes].decode("utf-8", "ignore").encode("utf-8")
            return joined, complete and within_cap and not result["unknown_block_ids"], "markdown+blocks"
        return fallback, complete, "blocks"

    def _refine(self, obj, detections):
        if not detections or obj.resource.metadata.get("content_format") != "markdown":
            return detections
        blocks = []
        _, complete = self._page_data(obj.resource.metadata["page_id"], blocks=blocks)
        # The header read after the blocks: another revision than the body's means an edit
        # landed in between. Its url and title name the page as it is now, so a page renamed
        # since the plan's search walk is recorded where it now lives.
        header = self._header(obj.resource.metadata["page_id"])
        modified = _timestamp(obj.resource.revision)
        stable = (header is not None and modified is not None
                  and _timestamp(header.get("last_edited_time")) == modified)
        if header is not None and isinstance(header.get("url"), str) and header["url"]:
            obj.resource.location = header["url"]
            obj.resource.resource = _page_title(header) or obj.resource.resource
        if not complete or not stable:
            obj.complete = False
            obj.resource.revision = ""
            if not obj.failure_counted:
                obj.failure_counted = True
                self.failed_objects += 1
            self.failed_page_ids.add(obj.resource.metadata["page_id"])
        # Line content stays in memory. Masked hints are never matching evidence.
        # Attribute only one exact, unique block and only at the same revision.
        if complete and stable:
            lines = (obj.data or b"").decode("utf-8").splitlines()
            for detection in detections:
                number = detection.line_number
                # Decoded-view line numbers do not necessarily name Markdown lines.
                if detection.decoder_type or number is None or not 1 <= number <= len(lines):
                    continue
                line = lines[number - 1].strip()
                matches = {block_id for block_id, text in blocks if line and line in text}
                if len(matches) == 1:
                    block_id = matches.pop()
                    detection.extra_safe_data["notion_block_id"] = block_id
        return detections

    def search(self) -> Iterator[dict]:
        """Search answers for the pages shared with the connection, most recently edited first.

        Each answer's ``results`` is a list of objects. A failed, malformed or looping walk
        raises rather than end early, so no caller mistakes it for the whole list.
        """
        cursor: str | None = None
        seen_cursors = self._cursors.fork()
        while True:
            body: dict = {"filter": {"property": "object", "value": "page"}, "page_size": 100,
                          "sort": {"direction": "descending", "timestamp": "last_edited_time"}}
            if cursor:
                body["start_cursor"] = cursor
            result, label = self._post("/v1/search", body)
            if result is None:
                # The search *is* the scope: an unauthorised or failed search
                # means the workspace was never listed.
                raise CollectorError("NOTION_SEARCH_FAILED", label)
            items = result.get("results")
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                raise CollectorError("NOTION_SEARCH_INCOMPLETE", "invalid results")
            yield result
            if not result.get("has_more"):
                return
            cursor = result.get("next_cursor")
            try:
                with self._cursor_lock:
                    seen_cursors.add(cursor)
            except CollectorError:
                raise CollectorError("NOTION_SEARCH_INCOMPLETE", "invalid cursor") from None

    def _iter_pages(self) -> Iterator[dict]:
        if self.page_ids is not None:
            for index, page_id in enumerate(self.page_ids):
                if index >= self.max_pages:
                    self.failed_objects += len(self.page_ids) - index
                    self.failed_page_ids.update(page.replace("-", "").lower() for page in self.page_ids[index:])
                    return
                meta = self.page_meta.get(page_id.replace("-", "").lower())
                # Stale metadata may still name the page; only a delta decision needs it fresh.
                if meta is not None and (self.watermark_since is None or _fresh(meta)):
                    yield {"object": "page", "id": page_id, "url": meta["url"], "title": meta["title"],
                           "last_edited_time": meta["last_edited_time"]}
                else:
                    yield {"_requested_page_id": page_id}
            return
        pending_retries = set(self.retry_page_ids)
        for result in self.search():
            for item in result["results"]:
                pending_retries.discard(str(item.get("id", "")).replace("-", "").lower())
                yield item
        # A failed page can be absent from Notion's eventually indexed search.
        # Retry the already-known ID; omission or 404 never proves removal.
        for page_id in sorted(pending_retries):
            page = self._header(page_id)
            if page is None:
                self.failed_objects += 1
            else:
                yield page

    def _page_data(self, block_id: str, *, blocks=None) -> tuple[bytes | None, bool]:
        """Return bounded page bytes and whether every advertised block was read."""

        out = bytearray()

        def append(text: str, *, separate: bool) -> bool:
            if not text:
                return True
            prefix = b"\n" if separate and out else b""
            remaining = self.max_object_bytes - len(out)
            if remaining <= len(prefix):
                return False
            if prefix:
                out.extend(prefix)
                remaining -= len(prefix)
            # Slice characters first so encoding one provider-controlled run
            # cannot allocate more than a small multiple of the remaining cap.
            encoded = text[:remaining].encode("utf-8")
            if len(encoded) <= remaining and len(text) <= remaining:
                out.extend(encoded)
                return True
            out.extend(encoded[:remaining].decode("utf-8", "ignore").encode("utf-8"))
            return False

        def walk(parent_id: str, depth: int) -> tuple[bool, bool]:
            readable = False
            complete = True
            cursor: str | None = None
            seen_cursors = self._cursors.fork()
            while True:
                path = f"/v1/blocks/{quote(parent_id, safe='')}/children?page_size=100"
                if cursor:
                    path += "&start_cursor=" + quote(cursor, safe="")
                result, _ = self._get(path)
                if result is None:
                    return readable, False
                readable = True
                results = result.get("results")
                if not isinstance(results, list):
                    return readable, False
                for block in results:
                    if not isinstance(block, dict):
                        complete = False
                        continue
                    if block.get("type") == "unsupported":
                        complete = False
                    # The selected page owns its nested blocks, never the body
                    # of a child page/database (those require separate approval).
                    if block.get("type") in ("child_page", "child_database"):
                        continue
                    if blocks is not None:
                        block_text = "".join(_block_text_runs(block))
                        identifier = str(block.get("id", "")).replace("-", "").lower()
                        if identifier and len(identifier) == 32 and all(c in "0123456789abcdef" for c in identifier):
                            blocks.append((identifier, block_text[:self.max_object_bytes]))
                    first_run = True
                    for block_text in _block_text_runs(block):
                        if not append(block_text, separate=first_run):
                            return True, False
                        first_run = False
                    if block.get("has_children"):
                        if depth >= _MAX_BLOCK_DEPTH or not isinstance(block.get("id"), str) or not block["id"]:
                            complete = False
                        else:
                            _, child_complete = walk(block["id"], depth + 1)
                            complete = complete and child_complete
                if not result.get("has_more"):
                    return readable, complete
                cursor = result.get("next_cursor")
                try:
                    with self._cursor_lock:
                        seen_cursors.add(cursor)
                except CollectorError:
                    return readable, False

        readable, complete = walk(block_id, 0)
        return (bytes(out) if readable else None), complete


class NotionPage(CollectedObject):
    """Provider-local, transient post-detection location refinement hook."""

    refiner = None

    def refine_detections(self, detections):
        if self.refiner is None:
            return detections
        callback, self.refiner = self.refiner, None
        return callback(detections)


def _block_text_runs(block: dict) -> Iterator[str]:
    """Yield plain-text runs without assembling an unbounded block string.

    Rich text, table cells, captions and equation expressions stay inside the
    owning page. Child pages/databases are filtered by the caller.
    """

    block_type = block.get("type", "")
    payload = block.get(block_type, {}) if block_type else {}
    if not isinstance(payload, dict):
        return
    groups = [payload.get("rich_text"), payload.get("caption")]
    if block_type == "table_row" and isinstance(payload.get("cells"), list):
        groups.extend(payload["cells"])
    for runs in groups:
        if not isinstance(runs, list):
            continue
        for run in runs:
            text = run.get("plain_text", "") if isinstance(run, dict) else ""
            if isinstance(text, str) and text:
                yield text
    expression = payload.get("expression") if block_type == "equation" else None
    if isinstance(expression, str):
        yield expression


def _page_title(page: dict) -> str:
    """Best-effort page title from its properties (the title-typed property)."""

    if isinstance(page.get("title"), str):  # a header built from search metadata
        return page["title"]
    props = page.get("properties", {})
    if not isinstance(props, dict):
        return ""
    for prop in props.values():
        if isinstance(prop, dict) and prop.get("type") == "title":
            runs = prop.get("title", [])
            if isinstance(runs, list):
                return "".join(r.get("plain_text", "") for r in runs if isinstance(r, dict))
    return ""


def _timestamp(value) -> datetime | None:
    try:
        stamp = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
        return stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp.astimezone(UTC)
    except (TypeError, ValueError, OverflowError):
        return None


def _usable_meta(meta) -> bool:
    return (isinstance(meta, dict) and isinstance(meta.get("url"), str) and bool(meta["url"])
            and isinstance(meta.get("title"), str) and _timestamp(meta.get("last_edited_time")) is not None)


def _fresh(meta) -> bool:
    """Whether search metadata may decide that a page is unchanged.

    The run's watermark W for the page is the start of its task, which can come long after
    the plan's search walk. A skip on metadata observed at most META_FRESH before W misses
    only edits the index did not show yet: made after the walk less SEARCH_LAG on Notion's
    clock (at most CLOCK_SKEW from ours) and reported up to EDIT_ROUNDING earlier, so
    reported after W - META_FRESH - SEARCH_LAG - CLOCK_SKEW - EDIT_ROUNDING. The next delta
    run skips only pages reported before W - overlap - LOOKBACK (_read_page), which keeps
    every such edit while META_FRESH + SEARCH_LAG + CLOCK_SKEW + EDIT_ROUNDING <= overlap +
    LOOKBACK, that is META_FRESH <= the runtime's 5-minute overlap. Older metadata, metadata
    without ``observed_at`` or with one from a clock far ahead leaves the decision to the
    page's own header.
    """
    observed = _timestamp(meta.get("observed_at"))
    return observed is not None and -_AHEAD <= datetime.now(UTC) - observed <= META_FRESH
