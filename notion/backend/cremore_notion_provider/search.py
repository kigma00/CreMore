"""What Notion's search says about approved pages: their headers for a run's plan, and
which of them changed since the last look (change feed, cremore.scanning.changes).

Both walk ``POST /v1/search`` for pages, most recently edited first, through the
collector's paced and budgeted requests in its Notion-Version (2025-09-03 turned database
results and parents into data sources; a page's id, url, title and edit time, all this
reads, kept their shape). Search trails edits a little and leaves pages out for many
reasons (sharing, index delay, trash), so a page the walk does not find reads its own
header, and a removal is never reported.
[Search](https://developers.notion.com/reference/post-search)
"""

from __future__ import annotations

import datetime as _dt
import math
import re

from cremore.collectors.base import CollectorError, RequestBudget, RequestBudgetExceeded
from cremore.collectors.changes import Changes
from cremore_notion_provider.collectors.notion import NotionCollector, _page_title, _timestamp
from cremore_notion_provider.collectors.requests import SlotsOnly
from cremore_notion_provider.source import approved_pages

# The window reaches this far behind the cursor (the previous poll's start). An edit that
# poll's walk did not show was made after the cursor less SEARCH_LAG on Notion's clock
# (CLOCK_SKEW from ours) and is reported up to EDIT_ROUNDING earlier: 12 minutes in all
# (collectors/notion.py), with room to spare.
OVERLAP = _dt.timedelta(minutes=15)
# A root unread for longer is read whole: its window could cost more than a poll's budget,
# and a cursor that never moves would keep failing the same window. Longer than the
# longest feed interval an Admin can set (a day), so a daily feed still walks.
MAX_WINDOW = _dt.timedelta(days=2)
_PAGE_ID = re.compile(r"[0-9a-f]{32}")
_MAX_TEXT = 2048


class _WalkCap(RequestBudgetExceeded):
    """The walk's own request cap: reaching it ends the walk early, it is no failure."""


class _CappedBudget:
    """The run's budget, charged per request, under this walk's own cap."""

    def __init__(self, budget, cap):
        self.budget, self.left = budget, cap

    def consume(self):
        if self.left <= 0:
            raise _WalkCap()
        self.budget.consume()
        self.left -= 1


def _identity(page_id) -> str:
    return str(page_id).replace("-", "").lower()


def _notion(payload, http_client, budget, *, feed=False):
    # A factory, as for every change feed, or a client.
    client = http_client() if callable(http_client) else http_client
    notion = NotionCollector(client, payload.get("token") or "", request_budget=budget)
    if feed:  # polled from the control loop: never wait out a cooldown (collectors.requests.SlotsOnly)
        notion.rate_limiter = SlotsOnly(notion.rate_limiter)
    return notion


def _header(item):
    """``(identity, {"url", "title", "last_edited_time"})`` of a full page result, else None."""
    identity = _identity(item.get("id", ""))
    url, edited = item.get("url"), item.get("last_edited_time")
    try:
        title = _page_title(item)
    except TypeError:  # a title run that is not text
        return None
    if (item.get("object") != "page" or not _PAGE_ID.fullmatch(identity) or not isinstance(url, str)
            or not url or len(url) > _MAX_TEXT or len(title) > _MAX_TEXT
            or not isinstance(edited, str) or _timestamp(edited) is None):
        return None  # a partial or odd result: that page reads its own header
    return identity, {"url": url, "title": title, "last_edited_time": edited}


def plan_metadata(payload, roots, *, http_client, request_budget) -> dict:
    """``{page id (32 lower-case hex): {"url", "title", "last_edited_time", "observed_at"}}``
    for the approved pages one search walk finds; ``{}`` after Notion fails or answers in
    a shape this does not know.

    The walk stops once every approved page is found and sends at most
    min(ceil(A/100)*3 + 10, A) requests for A approved pages: a workspace far larger than
    the approved scope costs a bounded prefix of its most recently edited pages, and the
    walk never costs more header reads than it can save. ``observed_at`` is the walk's start:
    the collector does not let older metadata decide that a page is unchanged. The request
    budget running out ends the walk like its cap and keeps what it found; the run's other
    stops (cancellation, a lost lease) are no Notion failure and propagate.
    """
    wanted = {_identity(page) for root in roots for page in approved_pages(root)}
    if not wanted:
        return {}
    observed = _dt.datetime.now(_dt.UTC).isoformat()
    cap = min(math.ceil(len(wanted) / 100) * 3 + 10, len(wanted))
    notion = _notion(payload, http_client, _CappedBudget(request_budget or RequestBudget(), cap))
    found = {}
    try:
        for result in notion.search():
            for item in result["results"]:
                header = _header(item)
                if header is not None and header[0] in wanted:
                    found[header[0]] = {**header[1], "observed_at": observed}
            if len(found) == len(wanted):
                break
    except RequestBudgetExceeded:
        pass  # its own cap or the run's budget: the rest read their own headers
    except CollectorError as exc:
        if not exc.code.startswith("NOTION_"):
            raise
        return {}  # a failed or malformed search: every page reads its own header instead
    return found


def changes_since_batch(payload, roots, states, *, http_client, request_budget):
    """``{resource_id: Changes}``: each root's approved pages edited since its last look.

    The cursor is the start of the previous poll. One walk, newest edits first, reads until
    results are older than the oldest cursor less OVERLAP; each root takes the approved pages
    edited inside its own window. A root never looked at only records this poll's start (the
    scan that set its state covers the present). A walk that stops early still answers every
    root whose whole window it read. The others are read whole (DELTA) when the budget or
    Notion's own listing ran out, so their cursors move on rather than face an ever longer
    window, and get the error when the search failed, so the next poll reads it again. The
    walk never waits out the connection's cooldown after a 429 (it runs on the worker's
    control loop): it fails at once with NOTION_RATE_LIMITED and the cursors stay.
    """
    now = _dt.datetime.now(_dt.UTC)
    head = now.isoformat()
    out, known = {}, []
    for root in roots:
        cursor = (states.get(root["resource_id"]) or {}).get("cursor")
        since = _timestamp(cursor) if cursor else None
        if not cursor:
            out[root["resource_id"]] = Changes(head=head)
        elif since is None or now - since > MAX_WINDOW:
            reason = "NOTION_WINDOW_TOO_OLD" if since else "NOTION_CURSOR_INVALID"
            out[root["resource_id"]] = Changes(head=head, paths=None, reason=reason)
        else:
            pages = {_identity(page): page for page in approved_pages(root)}
            known.append((root, since - OVERLAP, pages))
    if not known:
        return out
    floor = min(bound for _root, bound, _pages in known)
    edited, oldest, reached, limited, failure = [], None, False, False, None
    try:
        for result in _notion(payload, http_client, request_budget, feed=True).search():
            for item in result["results"]:
                when = _timestamp(item.get("last_edited_time"))
                if when is not None and when < floor:
                    reached = True  # sorted newest first: the rest are older still
                    break
                # A result without a time sorts among its neighbours: read it.
                edited.append((_identity(item.get("id", "")), when))
                if when is not None and (oldest is None or when < oldest):
                    oldest = when
            status = result.get("request_status")
            limited = limited or (isinstance(status, dict) and status.get("type") == "incomplete")
            if reached:
                break
    except CollectorError as exc:
        failure = exc
    whole = reached or (failure is None and not limited)
    for root, bound, pages in known:
        # A window starting after the oldest edit read was read whole; one starting at that
        # very time was not (more pages may share that minute on the unread answers).
        if not whole and (oldest is None or bound <= oldest):
            if isinstance(failure, RequestBudgetExceeded):
                out[root["resource_id"]] = Changes(head=head, paths=None, reason="NOTION_FEED_BUDGET")
            elif failure is not None:
                out[root["resource_id"]] = failure
            else:  # Notion stopped the listing short of the window
                out[root["resource_id"]] = Changes(head=head, paths=None, reason="NOTION_SEARCH_INCOMPLETE")
            continue
        paths = [pages[identity] for identity, when in edited
                 if identity in pages and (when is None or when >= bound)]
        out[root["resource_id"]] = Changes(head=head, paths=list(dict.fromkeys(paths)), reason="search")
    return out
