"""A plan's page headers and the change feed from Notion's search (cremore_notion_provider.search); fakes only."""

from datetime import UTC, datetime, timedelta

import pytest

from cremore.collectors.base import (
    CollectorError,
    RequestBudget,
    guard_requests,
)
from cremore.collectors.changes import Changes
from cremore_notion_provider import source

NOW = datetime.now(UTC)


def pid(n):
    return f"{n:032x}"


def dashed(n):
    value = pid(n)
    return f"{value[:8]}-{value[8:12]}-{value[12:16]}-{value[16:20]}-{value[20:]}"


def page(n, edited=None, **extra):
    edited = edited or (NOW - timedelta(days=30, minutes=n)).isoformat()
    return {"object": "page", "id": dashed(n), "url": f"https://www.notion.so/Page-{pid(n)}",
            "last_edited_time": edited,
            "properties": {"Name": {"type": "title", "title": [{"plain_text": f"Page {n}"}]}}, **extra}


class Response:
    def __init__(self, data, status=200):
        self.data, self.status_code, self.headers = data, status, {}

    def json(self):
        return self.data


class Search:
    """Notion's search over ``pages`` (newest edits first), 100 per answer; counts requests."""

    def __init__(self, pages, *, fail_at=None, status=None, endless=False):
        self.pages, self.fail_at, self.status, self.endless = pages, fail_at, status, endless
        self.bodies = []

    def post(self, url, headers=None, json=None):
        assert url == "https://api.notion.com/v1/search" and headers["Notion-Version"] == "2026-03-11"
        assert json["filter"] == {"property": "object", "value": "page"} and json["page_size"] == 100
        assert json["sort"] == {"direction": "descending", "timestamp": "last_edited_time"}
        self.bodies.append(json)
        if self.fail_at == len(self.bodies):
            return Response({"object": "error"}, 500)
        start = int(json.get("start_cursor", 0))
        rows = self.pages[start:start + 100]
        more = self.endless or start + 100 < len(self.pages)
        body = {"results": rows, "has_more": more, "next_cursor": str(start + 100) if more else None}
        if self.status:
            body["request_status"] = self.status
        return Response(body)


class Admit:
    def request_delay(self, key, interval, *, cooldown=None):
        return 0.0


@pytest.fixture(autouse=True)
def unpaced():
    # The shared pacing store a worker provides, admitting every request at once.
    with guard_requests(lambda: None, pacing=Admit()):
        yield


def page_root(n, descendants=(), mode="PAGE_WITH_DESCENDANTS", rid=None):
    return {"resource_id": rid or f"root-{n}", "resource_type": "NOTION_PAGE", "provider_resource_id": dashed(n),
            "page_mode": mode, "descendant_ids": [dashed(d) for d in descendants]}


def rows_root(rows, rid="rows"):
    return {"resource_id": rid, "resource_type": "NOTION_DATA_SOURCE", "provider_resource_id": "d" * 32,
            "page_mode": "DATA_SOURCE_SELECTED_PAGES", "descendant_ids": [dashed(r) for r in rows]}


def plan(roots, search, budget=None):
    return source.plan_metadata({"token": "synthetic"}, roots, http_client=lambda: search,
                                request_budget=budget or RequestBudget(1000))


def feed(roots, states, search, budget=None):
    return source.changes_since_batch({"token": "synthetic"}, roots, states, http_client=lambda: search,
                                      request_budget=budget or RequestBudget(60))


# --- plan_metadata ------------------------------------------------------------------------------


def test_the_walk_stops_once_every_approved_page_is_found_and_names_only_them():
    search = Search([page(n) for n in range(250)])
    found = plan([page_root(5, descendants=[70])], search)
    assert len(search.bodies) == 1 and set(found) == {pid(5), pid(70)}
    assert found[pid(5)] == {"url": f"https://www.notion.so/Page-{pid(5)}", "title": "Page 5",
                             "last_edited_time": page(5)["last_edited_time"], "observed_at": found[pid(5)]["observed_at"]}
    assert datetime.now(UTC) - datetime.fromisoformat(found[pid(5)]["observed_at"]) < timedelta(minutes=1)
    # The last approved page sits in the third answer: the walk reads that far, no further.
    search = Search([page(n) for n in range(450)])
    assert set(plan([page_root(5, descendants=[6, 230])], search)) == {pid(5), pid(6), pid(230)}
    assert len(search.bodies) == 3


def test_the_walk_is_bounded_and_keeps_what_it_found():
    search = Search([page(n) for n in range(5000)])
    # 51 approved pages, 50 of them never shared: at most ceil(51/100)*3 + 10 requests.
    found = plan([page_root(3, descendants=range(10_000, 10_050))], search)
    assert set(found) == {pid(3)} and len(search.bodies) == 13
    # Two approved pages never cost more than two requests, the header reads they can save.
    search = Search([page(n) for n in range(1000)])
    assert set(plan([page_root(150, descendants=[950])], search)) == {pid(150)} and len(search.bodies) == 2


def test_only_approved_pages_of_each_root_kind_are_named():
    search = Search([page(n) for n in range(20)])
    roots = [rows_root([7, 8]), page_root(1, descendants=[9], mode="PAGE_ONLY"),
             {**page_root(2, descendants=[11]), "exact_page_ids": [dashed(12)]}]
    # Rows of the data source, the page-only page (not its descendant) and the exact page alone.
    assert set(plan(roots, search)) == {pid(7), pid(8), pid(1), pid(12)}


def test_a_partial_result_is_left_to_its_own_header():
    search = Search([{"object": "page", "id": dashed(1)}, page(2, url=None), page(3)])
    assert set(plan([page_root(1, descendants=[2, 3])], search)) == {pid(3)}


@pytest.mark.parametrize("search", [
    Search([page(n) for n in range(300)], fail_at=2),
    Search([page(1), "not an object"]),
    Search([page(1, properties={"Name": {"type": "title", "title": [{"plain_text": 7}]}})], fail_at=2),
])
def test_a_failed_or_malformed_search_returns_no_metadata(search):
    assert plan([page_root(1, descendants=[250, 251])], search) == {}


class LeaseLost(RuntimeError):
    pass


@pytest.mark.parametrize("stop", [CollectorError("RUN_CANCELLED"), CollectorError("BUDGET_SECONDS"),
                                  LeaseLost("TASK_LEASE_LOST")])
def test_the_run_s_own_stops_propagate(stop):
    def guard():
        raise stop
    with guard_requests(guard, pacing=Admit()), pytest.raises(type(stop)) as caught:
        plan([page_root(1)], Search([page(1)]))
    assert caught.value is stop


def test_the_run_s_request_budget_running_out_ends_the_walk_and_keeps_what_it_found():
    # Page 5 is in the first answer, pages 250 and 251 in the third; the budget pays for one request.
    search = Search([page(n) for n in range(300)])
    assert set(plan([page_root(5, descendants=[250, 251])], search, RequestBudget(1))) == {pid(5)}
    assert len(search.bodies) == 1


def test_no_approved_page_sends_no_request():
    search = Search([page(1)])
    assert plan([rows_root([])], search) == {} and search.bodies == []


# --- changes_since_batch ------------------------------------------------------------------------


def at(minutes):
    """An edit time relative to the cursor CURSOR."""
    return (CURSOR + timedelta(minutes=minutes)).isoformat()


CURSOR = NOW - timedelta(hours=1)


def test_a_first_look_records_this_poll_without_a_request():
    search = Search([page(1, at(1))])
    [answer] = feed([page_root(1)], {}, search).values()
    assert answer.paths == [] and not answer.rewritten and search.bodies == []
    assert NOW <= datetime.fromisoformat(answer.head) <= datetime.now(UTC)


def test_a_known_root_gets_its_approved_pages_edited_inside_its_window():
    pages = [page(1, at(1)), page(2, at(-10)), page(3, at(-14)), page(4, at(-20))] + [page(n) for n in range(5, 300)]
    search = Search(pages)
    root = page_root(1, descendants=[2, 4])
    answer = feed([root], {root["resource_id"]: {"cursor": CURSOR.isoformat()}}, search)[root["resource_id"]]
    # Page 3 is not approved; page 4 is older than the cursor less the 15-minute overlap.
    assert answer.paths == [dashed(1), dashed(2)] and answer.reason == "search"
    assert not answer.removals and not answer.rewritten and datetime.fromisoformat(answer.head) >= NOW
    # The first result older than the window ends the walk, although more answers exist.
    assert len(search.bodies) == 1


def test_one_walk_answers_every_root_inside_its_own_window():
    search = Search([page(1, at(1)), page(2, at(-30)), page(3, at(-70))] + [page(n) for n in range(4, 9)])
    new, old = page_root(1, descendants=[2], rid="new"), page_root(9, descendants=[2, 3], rid="old")
    states = {"new": {"cursor": CURSOR.isoformat()}, "old": {"cursor": (CURSOR - timedelta(hours=1)).isoformat()}}
    answers = feed([new, old], states, search)
    assert answers["new"].paths == [dashed(1)] and answers["old"].paths == [dashed(2), dashed(3)]
    assert len(search.bodies) == 1


def test_a_data_source_root_names_only_its_approved_rows():
    # The data source itself and a row nobody approved changed too.
    search = Search([{**page(99, at(3)), "id": "d" * 32}, page(8, at(2)), page(7, at(1))])
    root = rows_root([7])
    assert feed([root], {"rows": {"cursor": CURSOR.isoformat()}}, search)["rows"].paths == [dashed(7)]


def test_a_result_without_an_edit_time_inside_the_walk_is_read():
    search = Search([page(1, at(1)), {"object": "page", "id": dashed(2)}, page(3, at(-60))])
    root = page_root(1, descendants=[2, 3])
    assert feed([root], {root["resource_id"]: {"cursor": CURSOR.isoformat()}}, search)[root["resource_id"]].paths \
        == [dashed(1), dashed(2)]


def test_a_failed_search_answers_the_error_and_first_looks_still_record():
    known, fresh = page_root(1, rid="known"), page_root(2, rid="fresh")
    answers = feed([known, fresh], {"known": {"cursor": CURSOR.isoformat()}}, Search([page(1, at(1))], fail_at=1))
    assert isinstance(answers["known"], CollectorError) and answers["known"].code == "NOTION_SEARCH_FAILED"
    assert isinstance(answers["fresh"], Changes) and answers["fresh"].paths == []


@pytest.mark.parametrize("spent", ["requests", "time"])
def test_a_walk_out_of_budget_answers_the_windows_it_read_and_reads_the_rest_whole(spent):
    """A feed pass whose time is up (cremore.scanning.changes.PassBudget) ends the walk in hand as spent requests do,
    so one long walk never holds the worker's control loop past the pass."""
    from cremore.scanning.changes import PassBudget

    def budget(search):
        return RequestBudget(1) if spent == "requests" else PassBudget(60, stop=lambda: len(search.bodies) >= 1)

    # 100 edits in the last half hour, then older ones: one answer covers the newer window.
    recent = [page(n, at(1 - n * 30 / 100)) for n in range(1, 101)]
    search = Search(recent + [page(n, at(-60 - n)) for n in range(101, 250)])
    new, old = page_root(1, descendants=[80], rid="new"), page_root(2, descendants=[150], rid="old")
    states = {"new": {"cursor": CURSOR.isoformat()}, "old": {"cursor": (CURSOR - timedelta(hours=3)).isoformat()}}
    answers = feed([new, old], states, search, budget(search))
    # The newer window begins after the oldest edit walked (29 minutes before its cursor), so it
    # was read whole; page 80, walked at 23 minutes before, lies outside it.
    assert answers["new"].paths == [dashed(1)] and answers["new"].reason == "search"
    # The older one runs past it: the whole root is read and its cursor moves on.
    assert answers["old"].paths is None and answers["old"].reason == "NOTION_FEED_BUDGET"
    assert len(search.bodies) == 1
    # A window starting at the oldest edit walked was not read whole: that minute may go on.
    search = Search([page(n, at(-10)) for n in range(1, 150)], endless=True)
    edge = {"edge": {"cursor": (CURSOR + timedelta(minutes=5)).isoformat()}}
    assert feed([page_root(1, rid="edge")], edge, search, budget(search))["edge"].reason == "NOTION_FEED_BUDGET"


@pytest.mark.parametrize("cursor,reason", [((NOW - timedelta(days=3)).isoformat(), "NOTION_WINDOW_TOO_OLD"),
                                           ("not a time", "NOTION_CURSOR_INVALID")])
def test_an_old_or_unreadable_cursor_reads_the_whole_root(cursor, reason):
    search = Search([page(1, at(1))])
    answer = feed([page_root(1)], {"root-1": {"cursor": cursor}}, search)["root-1"]
    assert answer.paths is None and answer.reason == reason and search.bodies == []
    # A daily feed, the longest interval an Admin can set, still walks its window.
    daily = (NOW - timedelta(days=1, minutes=5)).isoformat()
    assert feed([page_root(1)], {"root-1": {"cursor": daily}}, search)["root-1"].paths == [dashed(1)]


def test_a_listing_notion_cut_short_reads_the_whole_root():
    search = Search([page(1, at(1))], status={"type": "incomplete", "incomplete_reason": "query_result_limit_reached"})
    answer = feed([page_root(1)], {"root-1": {"cursor": CURSOR.isoformat()}}, search)["root-1"]
    assert answer.paths is None and answer.reason == "NOTION_SEARCH_INCOMPLETE"
    # A walk that reached its window needs nothing it was not given.
    search = Search([page(1, at(1)), page(2, at(-60))], status={"type": "incomplete"})
    assert feed([page_root(1)], {"root-1": {"cursor": CURSOR.isoformat()}}, search)["root-1"].paths == [dashed(1)]
