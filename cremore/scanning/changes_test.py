"""Change feeds turn a moved head into the least work that covers it (design 4.3, section 7 criteria)."""

import os
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from cremore.collectors.base import CollectorError, guard_requests
from cremore.collectors.changes import Changes
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- disposable PostgreSQL
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.scanning import changes, scope, triggers
from cremore.scanning.triggers_test import NOW, setup, switch_triggers


class Feed:
    """A provider answering from a script: one Changes (or error) per poll."""

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def __call__(self, payload, roots, states, budget):
        self.calls.append({root["resource_id"]: dict(states[root["resource_id"]]) for root in roots})
        answer = self.answers.pop(0)
        return {root["resource_id"]: answer for root in roots}


def github():
    repo, _connection, profile, item, settings = setup("github")
    switch_triggers(repo, change_feeds_enabled=True)
    return repo, profile, item, settings


def poll(repo, settings, feed, at):
    return changes.poll_change_feeds(repo, settings, feed, now=at)


def jobs(repo):
    return sorted(repo.jobs.values(), key=lambda job: job.created_at)


def test_change_feeds_read_by_default_and_an_admin_s_off_or_the_installation_lock_stops_them():
    repo, _connection, _profile, _item, settings = setup("github")
    feed = Feed(Changes(head="a" * 40))
    assert poll(repo, settings, feed, NOW)["checked"] == 1
    switch_triggers(repo, change_feeds_enabled=False)
    assert poll(repo, settings, feed, NOW + timedelta(minutes=10)) == {"checked": 0, "enqueued": 0}
    switch_triggers(repo, change_feeds_enabled=True)
    locked = settings.model_copy(update={"scan_change_feeds_mode": "disabled"})
    assert poll(repo, locked, feed, NOW + timedelta(minutes=10)) == {"checked": 0, "enqueued": 0}
    assert len(feed.calls) == 1


def test_one_broken_scope_never_stops_the_others_feeds(monkeypatch):
    """A scope whose plan fails unexpectedly (a malformed catalog item) is logged and skipped; the scopes after it are
    still read."""
    repo, _connection, _profile, _item, settings = setup("github")
    setup("github", repo=repo, name="other")
    real, seen = triggers.prepare_trigger_plan, []

    def plan(repo, settings, profile_id, *args, **kw):
        seen.append(str(profile_id))
        if seen[0] == str(profile_id):  # whichever scope is listed first
            raise KeyError("resource_type")
        return real(repo, settings, profile_id, *args, **kw)

    monkeypatch.setattr(triggers, "prepare_trigger_plan", plan)
    feed = Feed(Changes(head="a" * 40))
    assert poll(repo, settings, feed, NOW)["checked"] == 1 and len(set(seen)) == 2


def test_a_first_look_records_the_head_and_a_moved_head_scans_only_changed_approved_files():
    repo, _profile, item, settings = github()
    feed = Feed(Changes(head="a" * 40),
                Changes(head="b" * 40, paths=["approved/app.env", "outside/readme.md", "approved/private/key.pem"]))
    first = poll(repo, settings, feed, NOW)
    assert (first["checked"], first["enqueued"]) == (1, 0) and repo.jobs == {}
    # Within the five-minute interval the root is not asked again.
    assert poll(repo, settings, feed, NOW + timedelta(minutes=2))["checked"] == 0
    second = poll(repo, settings, feed, NOW + timedelta(minutes=6))
    assert second["enqueued"] == 1
    assert feed.calls[1][item["id"]]["cursor"] == "a" * 40
    [job] = jobs(repo)
    assert job.payload["mode"] == "EVENT"
    assert job.payload["roots"][0]["exact_paths"] == ["approved/app.env"]


def test_a_rewritten_history_reads_the_root_again_from_scratch():
    repo, _profile, _item, settings = github()
    feed = Feed(Changes(head="a" * 40), Changes(head="c" * 40, paths=None, rewritten=True,
                                                reason="GITHUB_HISTORY_REWRITTEN"))
    poll(repo, settings, feed, NOW)
    poll(repo, settings, feed, NOW + timedelta(minutes=6))
    [job] = jobs(repo)
    assert job.payload["mode"] == "BASELINE"
    [saved] = repo.change_cursors.values()
    assert saved["state"]["reason"] == "GITHUB_HISTORY_REWRITTEN" and saved["state"]["last_mode"] == "BASELINE"


@pytest.mark.parametrize("answer", [
    Changes(head="d" * 40, paths=None, reason="GITHUB_COMPARE_FILE_LIMIT"),
    Changes(head="d" * 40, paths=[f"approved/f{n}" for n in range(triggers.MAX_EVENT_KEYS + 1)]),
])
def test_an_unknown_or_too_long_change_list_reads_the_whole_root(answer):
    repo, _profile, _item, settings = github()
    feed = Feed(Changes(head="a" * 40), answer)
    poll(repo, settings, feed, NOW)
    poll(repo, settings, feed, NOW + timedelta(minutes=6))
    [job] = jobs(repo)
    assert job.payload["mode"] == "DELTA" and "exact_paths" not in job.payload["roots"][0]


def test_removals_are_exact_only_where_the_collector_confirms_a_missing_file():
    root = {"resource_type": "GITLAB_REPOSITORY", "paths": [], "excluded_paths": []}
    assert changes.work_for(root, Changes(head="x", paths=["a"], removals=True)) == ("DELTA", None)
    github_root = {**root, "resource_type": "GITHUB_REPOSITORY"}
    assert changes.work_for(github_root, Changes(head="x", paths=["a"], removals=True)) == ("EVENT", ["a"])


def test_a_change_outside_the_approved_paths_moves_the_cursor_without_a_scan():
    repo, _profile, _item, settings = github()
    feed = Feed(Changes(head="a" * 40), Changes(head="e" * 40, paths=["docs/readme.md"]))
    poll(repo, settings, feed, NOW)
    result = poll(repo, settings, feed, NOW + timedelta(minutes=6))
    assert result["enqueued"] == 0 and repo.jobs == {}
    [saved] = repo.change_cursors.values()
    assert saved["state"]["cursor"] == "e" * 40


def test_a_provider_or_queueing_failure_keeps_the_cursor_for_the_next_poll(monkeypatch):
    repo, _profile, _item, settings = github()
    feed = Feed(Changes(head="a" * 40), CollectorError("SOURCE_HTTP_FAILED", "502"), Changes(head="f" * 40, paths=["approved/x"]),
                Changes(head="f" * 40, paths=["approved/x"]))
    poll(repo, settings, feed, NOW)
    failed = poll(repo, settings, feed, NOW + timedelta(minutes=6))
    assert failed["failed"] == 1
    [saved] = repo.change_cursors.values()
    assert saved["state"] == {"cursor": "a" * 40, "changed_at": None, "error": "SOURCE_HTTP_FAILED",
                              "failing_since": (NOW + timedelta(minutes=6)).isoformat()}

    def unavailable(*args, **kwargs):
        raise RuntimeError("database unavailable")

    # A run is queued whatever else is scanning; only a failed queueing leaves the change to be read again. The
    # failure is that root's own: the pass goes on, and the root's next look comes after its interval.
    monkeypatch.setattr(triggers, "enqueue_event", unavailable)
    assert poll(repo, settings, feed, NOW + timedelta(minutes=12))["failed"] == 1
    [saved] = repo.change_cursors.values()
    assert saved["state"]["cursor"] == "a" * 40  # not moved: the change is still to be read
    assert saved["state"]["error"] == "CHANGE_FEED_FAILED"
    assert saved["state"]["failing_since"] == (NOW + timedelta(minutes=6)).isoformat()  # the streak's first failure
    monkeypatch.undo()
    assert poll(repo, settings, feed, NOW + timedelta(minutes=13))["checked"] == 0  # not read again inside its interval
    assert poll(repo, settings, feed, NOW + timedelta(minutes=18))["enqueued"] == 1
    [job] = jobs(repo)
    assert job.payload["requested_by"] == "feed"  # the alert says a change feed started it


def test_a_refused_queueing_keeps_the_cursor_and_waits_the_root_s_interval(monkeypatch):
    repo, _profile, _item, settings = github()
    feed = Feed(Changes(head="a" * 40), Changes(head="f" * 40, paths=["approved/x"]),
                Changes(head="f" * 40, paths=["approved/x"]))
    poll(repo, settings, feed, NOW)

    def refused(*args, **kwargs):
        raise scope.ScopeError("EVENT_KEY_REFUSED")

    monkeypatch.setattr(triggers, "enqueue_event", refused)
    assert poll(repo, settings, feed, NOW + timedelta(minutes=6))["failed"] == 1
    [saved] = repo.change_cursors.values()
    assert saved["state"]["cursor"] == "a" * 40 and saved["state"]["error"] == "EVENT_KEY_REFUSED"
    assert poll(repo, settings, feed, NOW + timedelta(minutes=7))["checked"] == 0  # not asked again on every pass
    monkeypatch.undo()
    assert poll(repo, settings, feed, NOW + timedelta(minutes=12))["enqueued"] == 1


def test_a_failing_feed_keeps_when_its_failures_began_until_a_look_succeeds(monkeypatch):
    """The operations status warns of a feed failing for an hour (cremore/operations/health.feed_alerts): the first
    failure of a streak is kept through the failures after it, a successful look ends the streak, and a refused
    queueing is a failure of the feed too."""
    repo, _profile, _item, settings = github()
    feed = Feed(Changes(head="a" * 40), CollectorError("SOURCE_RATE_LIMITED"), CollectorError("SOURCE_UNAVAILABLE"),
                Changes(head="a" * 40), Changes(head="b" * 40, paths=["approved/x"]))

    def state():
        [saved] = repo.change_cursors.values()
        return saved["state"]

    poll(repo, settings, feed, NOW)
    assert "failing_since" not in state()
    first = NOW + timedelta(minutes=6)
    assert poll(repo, settings, feed, first)["failed"] == 1
    assert (state()["error"], state()["failing_since"]) == ("SOURCE_RATE_LIMITED", first.isoformat())
    assert poll(repo, settings, feed, NOW + timedelta(minutes=12))["failed"] == 1
    assert (state()["error"], state()["failing_since"]) == ("SOURCE_UNAVAILABLE", first.isoformat())
    assert poll(repo, settings, feed, NOW + timedelta(minutes=18))["unchanged"] == 1
    assert state() == {"cursor": "a" * 40, "changed_at": None}

    def refused(*args, **kwargs):
        raise scope.ScopeError("EVENT_KEY_REFUSED")

    monkeypatch.setattr(triggers, "enqueue_event", refused)
    refusal = NOW + timedelta(minutes=24)
    assert poll(repo, settings, feed, refusal)["failed"] == 1
    assert state() == {"cursor": "a" * 40, "changed_at": None, "error": "EVENT_KEY_REFUSED",
                       "failing_since": refusal.isoformat()}


def test_a_root_not_read_for_longer_than_its_window_starts_a_new_failure_streak():
    """Feeds off or a paused scope is no failing feed: a failure after a gap longer than the root's interval and
    LOOK_SLACK dates its streak anew, while one inside that window keeps it."""
    repo, _profile, _item, settings = github()
    feed = Feed(Changes(head="a" * 40), *[CollectorError("SOURCE_RATE_LIMITED")] * 3)

    def since():
        [saved] = repo.change_cursors.values()
        return saved["state"]["failing_since"]

    poll(repo, settings, feed, NOW)
    first = NOW + timedelta(minutes=6)
    poll(repo, settings, feed, first)
    window = timedelta(minutes=changes.DEFAULT_MINUTES) + changes.LOOK_SLACK  # GitHub's five minutes
    kept = first + window
    assert poll(repo, settings, feed, kept)["failed"] == 1 and since() == first.isoformat()
    switch_triggers(repo, change_feeds_enabled=False)
    assert poll(repo, settings, feed, kept + timedelta(minutes=30))["checked"] == 0
    switch_triggers(repo, change_feeds_enabled=True)
    resumed = kept + window + timedelta(minutes=1)
    assert poll(repo, settings, feed, resumed)["failed"] == 1 and since() == resumed.isoformat()


@pytest.mark.parametrize("name", ["approved/line\nbreak.env", "approved/" + "d" * 4100])
def test_a_changed_name_the_event_check_refuses_reads_the_root_s_changes_and_moves_the_cursor(name):
    """Anyone who can push can commit such a name; every later look from the old cursor would meet it again."""
    repo, _profile, _item, settings = github()
    feed = Feed(Changes(head="a" * 40), Changes(head="b" * 40, paths=[name, "approved/app.env"]))
    poll(repo, settings, feed, NOW)
    assert poll(repo, settings, feed, NOW + timedelta(minutes=6))["enqueued"] == 1
    [job] = jobs(repo)
    assert job.payload["mode"] == "DELTA" and "exact_paths" not in job.payload["roots"][0]
    [saved] = repo.change_cursors.values()
    assert saved["state"]["cursor"] == "b" * 40 and "error" not in saved["state"]
    assert (saved["state"]["last_mode"], saved["state"]["reason"]) == ("DELTA", "EVENT_INVALID_PAYLOAD")


def test_active_scans_do_not_pause_change_feeds_and_detected_work_is_durable():
    from cremore.domain.models import ScanJob

    repo, _profile, _item, settings = github()
    feed = Feed(Changes(head="a" * 40), Changes(head="b" * 40, paths=["approved/x"]))
    active = repo.enqueue_job(ScanJob(kind="github", payload={"owner": "o", "repo": "r"}))
    assert repo.claim_next_job().id == active.id
    assert poll(repo, settings, feed, NOW)["checked"] == 1
    assert poll(repo, settings, feed, NOW + timedelta(minutes=6))["enqueued"] == 1
    assert len(feed.calls) == 2 and len(repo.jobs) == 2
    assert repo.claim_next_job() is None
    active.status = "SUCCEEDED"
    assert repo.claim_next_job().id != active.id


def test_per_provider_minutes_come_from_the_admin_setting():
    repo, _profile, _item, settings = github()
    switch_triggers(repo, change_feed_minutes={"github": 30})
    feed = Feed(Changes(head="a" * 40), Changes(head="a" * 40))
    poll(repo, settings, feed, NOW)
    assert poll(repo, settings, feed, NOW + timedelta(minutes=10))["checked"] == 0
    assert poll(repo, settings, feed, NOW + timedelta(minutes=31))["checked"] == 1


def test_a_missed_change_is_caught_by_the_installation_s_full_scan_not_by_the_feed():
    """The feed only reads changes; an event-driven scope without a schedule of its own is still scanned in full,
    by the schedule's daily default (cremore/scanning/triggers.py poll_schedules)."""
    repo, profile, _item, settings = github()
    repo.update_scope_profile(profile.id, schedule_minutes=0)
    feed = Feed(Changes(head="a" * 40), Changes(head="a" * 40))
    assert poll(repo, settings, feed, NOW) == {"checked": 1, "enqueued": 0, "unchanged": 0, "failed": 0, "deferred": 0}
    assert poll(repo, settings, feed, NOW + timedelta(minutes=6))["unchanged"] == 1 and not repo.jobs
    assert triggers.poll_schedules(repo, settings, now=NOW)["enqueued"] == 1
    [job] = jobs(repo)
    assert (job.payload["mode"], job.payload["requested_by"]) == ("RECONCILE", "schedule")


class NotionSearch:
    """Notion's search as the change feed walks it: the approved page at its edit times."""

    def __init__(self, page_id):
        self.page_id, self.edited, self.searches, self.endless = page_id, [], 0, False

    def post(self, url, headers=None, json=None):
        assert url == "https://api.notion.com/v1/search"
        assert json["sort"] == {"direction": "descending", "timestamp": "last_edited_time"}
        self.searches += 1
        if self.endless:  # recent edits beyond what one poll's budget can walk
            now = datetime.now(UTC).isoformat()
            rows = [{"object": "page", "id": f"{n:032x}", "last_edited_time": now} for n in range(100)]
            body = {"results": rows, "has_more": True, "next_cursor": str(self.searches)}
        else:
            body = {"results": [{"object": "page", "id": self.page_id, "last_edited_time": when}
                                for when in self.edited], "has_more": False, "next_cursor": None}
        return SimpleNamespace(status_code=200, headers={}, json=lambda: body)


class Admit:
    """A shared pacing store that admits every request at once."""

    def request_delay(self, key, interval, *, cooldown=None):
        return 0.0


def rewind(repo, minutes):
    """The saved cursor is a poll's own start; polls run minutes apart, never within one clock tick."""
    # The head is the wall clock, which ticks in milliseconds on some hosts: two polls within one tick would name
    # the same change and the second would be handed the first's run.
    time.sleep(0.03)
    [saved] = repo.change_cursors.values()
    saved["state"]["cursor"] = (datetime.fromisoformat(saved["state"]["cursor"]) - timedelta(minutes=minutes)).isoformat()
    return saved["state"]["cursor"]


def test_a_notion_search_feed_queues_an_event_run_for_the_changed_approved_page():
    repo, _connection, profile, item, settings = setup("notion")
    # A page root carries no paths; the shared setup fills them for the code hosts.
    repo.update_scope_profile(profile.id, selected_roots=[
        {**profile.selected_roots[0], "paths": [], "excluded_paths": []}])
    switch_triggers(repo, change_feeds_enabled=True)
    search = NotionSearch(item["provider_resource_id"])

    def reader(payload, roots, states, budget):
        # The worker's reader: the source module's own feed, discovered through the registry.
        return changes.read_changes(payload, roots, states, http_client=lambda: search, request_budget=budget)

    first = poll(repo, settings, reader, NOW)
    assert (first["checked"], first["enqueued"], search.searches) == (1, 0, 0) and repo.jobs == {}
    rewind(repo, 6)
    search.edited.append(datetime.now(UTC).isoformat())
    second = poll(repo, settings, reader, NOW + timedelta(minutes=6))
    assert (second["enqueued"], search.searches) == (1, 1), second
    [job] = jobs(repo)
    assert job.payload["mode"] == "EVENT" and job.payload["trigger"] == "EVENT"
    assert job.payload["roots"][0]["exact_page_ids"] == [item["provider_resource_id"]]
    [saved] = repo.change_cursors.values()
    changed = {key: saved["state"][key] for key in ("changed_at", "last_mode", "reason")}
    assert changed == {"changed_at": (NOW + timedelta(minutes=6)).isoformat(), "last_mode": "EVENT", "reason": "search"}
    # Nothing new: the time-stamped head moves on, the record of the last change stays.
    search.edited = [(datetime.now(UTC) - timedelta(days=1)).isoformat()]
    cursor = rewind(repo, 6)
    assert poll(repo, settings, reader, NOW + timedelta(minutes=12))["unchanged"] == 1 and len(jobs(repo)) == 1
    [saved] = repo.change_cursors.values()
    assert saved["state"]["cursor"] != cursor and {key: saved["state"][key] for key in changed} == changed
    # A window the poll's budget cannot walk reads the root whole and the cursor moves on.
    search.endless = True
    cursor = rewind(repo, 6)
    with guard_requests(lambda: None, pacing=Admit()):
        assert poll(repo, settings, reader, NOW + timedelta(minutes=18))["enqueued"] == 1
    [saved] = repo.change_cursors.values()
    assert saved["state"]["cursor"] != cursor and saved["state"]["reason"] == "NOTION_FEED_BUDGET"
    whole = jobs(repo)[-1]
    assert whole.payload["mode"] == "DELTA" and "exact_page_ids" not in whole.payload["roots"][0]


def test_notion_look_backs_cover_the_worker_runtime_s_overlap():
    """The Notion margins (cremore_notion_provider.collectors.notion._fresh) build on the runtime's
    delta overlap; changing it must fail here, not miss edits silently."""
    from cremore_notion_provider import search
    from cremore_notion_provider.collectors import notion

    from cremore.worker.runtime import OVERLAP

    late = notion.SEARCH_LAG + notion.CLOCK_SKEW + notion.EDIT_ROUNDING
    # A skip on metadata META_FRESH old misses only edits reported after W - META_FRESH - late;
    # the next delta run skips only those reported before W - OVERLAP - LOOKBACK.
    assert notion.META_FRESH + late <= OVERLAP + notion.LOOKBACK
    # The feed's window reaches past every edit the previous poll's walk could not show yet.
    assert late <= search.OVERLAP


def test_read_changes_keeps_one_roots_failure_its_own(monkeypatch):
    from cremore.sources.registry import BY_RESOURCE_TYPE

    module = BY_RESOURCE_TYPE["GITHUB_REPOSITORY"]

    def fake(payload, root, cursor, *, http_client, request_budget):
        if root["resource_id"] == "bad":
            raise CollectorError("SOURCE_HTTP_FAILED", "500")
        return Changes(head="ok")

    monkeypatch.setattr(module, "changes_since", fake)
    roots = [{"resource_id": "good", "resource_type": "GITHUB_REPOSITORY"},
             {"resource_id": "bad", "resource_type": "GITHUB_REPOSITORY"},
             {"resource_id": "bucket", "resource_type": "S3_BUCKET"}]
    answers = changes.read_changes({}, roots, {}, http_client=None, request_budget=None)
    assert answers["good"] == Changes(head="ok") and isinstance(answers["bad"], CollectorError)
    assert "bucket" not in answers
    # Once the pass is out of time no further root starts; the one in progress has finished.
    started = []
    budget = changes.PassBudget(changes.REQUESTS_PER_ROOT, stop=lambda: "good" in started)
    monkeypatch.setattr(module, "changes_since", lambda payload, root, cursor, **_kw: (
        started.append(root["resource_id"]) or Changes(head="ok")))
    assert list(changes.read_changes({}, roots, {}, http_client=None, request_budget=budget)) == ["good"]
    assert started == ["good"]


@pytest.mark.parametrize("provider, planned", [("aws", 0), ("gcp", 0), ("github", 1)])
def test_only_scopes_whose_source_has_a_feed_are_planned_on_a_pass(monkeypatch, provider, planned):
    """Object stores report changes through a queue: their event-enabled scopes cost no plan on every pass."""
    repo, _connection, _profile, _item, settings = setup(provider)
    calls = []
    real = triggers.prepare_trigger_plan
    monkeypatch.setattr(triggers, "prepare_trigger_plan", lambda *args, **kw: calls.append(1) or real(*args, **kw))
    feed = Feed(Changes(head="a" * 40))
    assert poll(repo, settings, feed, NOW)["checked"] == planned
    assert len(calls) == len(feed.calls) == planned


def test_a_pass_starts_no_root_once_its_time_is_spent_and_the_next_pass_takes_the_roots_left_first(monkeypatch):
    """A provider that throttles every request cannot hold the worker's control loop: after PASS_SECONDS no
    further connection or root starts, the roots not reached keep their cursors, and they lead the next pass."""
    from cremore.sources.registry import BY_RESOURCE_TYPE

    repo, connection, _profile, item, settings = setup("github")
    by_connection = {connection.id: item["id"]}
    for number in range(4):
        _repo, connection, _profile, item, _settings = setup("github", repo=repo, name=f"test-{number}")
        by_connection[connection.id] = item["id"]
    clock, seconds, read = [0.0], [0], []

    def changes_since(payload, root, cursor, *, http_client, request_budget):
        read.append(root["resource_id"])
        clock[0] += seconds[0]
        return Changes(head="b" * 40, paths=["approved/x"]) if cursor else Changes(head="a" * 40)

    monkeypatch.setattr(BY_RESOURCE_TYPE["GITHUB_REPOSITORY"], "changes_since", changes_since)

    def run(at):
        read.clear()
        return changes.poll_change_feeds(repo, settings, lambda payload, roots, states, budget: changes.read_changes(
            payload, roots, states, http_client=None, request_budget=budget), now=at, clock=lambda: clock[0])

    assert run(NOW)["checked"] == 5
    before = dict(repo.change_cursors)
    seconds[0] = 8  # each root now takes eight seconds: three fit in the pass's twenty
    first = run(NOW + timedelta(minutes=6))
    assert (first["checked"], first["enqueued"], first["deferred"]) == (3, 3, 2) and len(read) == 3
    left = [key for key, row in before.items() if repo.change_cursors[key] == row]
    assert len(left) == 2 and all(before[key]["state"]["cursor"] == "a" * 40 for key in left)
    second = run(NOW + timedelta(minutes=12))
    assert set(read[:2]) == {by_connection[before[key]["connection_id"]] for key in left}
    assert (second["checked"], second["enqueued"], second["deferred"]) == (3, 2, 2)


def test_a_pass_whose_planning_is_slow_still_reads_and_one_failing_root_never_stops_the_others(monkeypatch):
    """The pass budget counts reading only, and a root whose answer fails to apply records its error and its look
    instead of ending the pass, so it goes behind the others next time."""
    from cremore.sources.registry import BY_RESOURCE_TYPE

    repo, connection, _profile, item, settings = setup("github")
    for number in range(2):
        setup("github", repo=repo, name=f"test-{number}")
    clock, read = [0.0], []
    real_plan = triggers.prepare_trigger_plan

    def slow_plan(*args, **kwargs):
        clock[0] += 30  # planning alone outlasts PASS_SECONDS
        return real_plan(*args, **kwargs)

    monkeypatch.setattr(triggers, "prepare_trigger_plan", slow_plan)

    def changes_since(payload, root, cursor, *, http_client, request_budget):
        read.append(root["resource_id"])
        return Changes(head="b" * 40, paths=["approved/x"]) if cursor else Changes(head="a" * 40)

    monkeypatch.setattr(BY_RESOURCE_TYPE["GITHUB_REPOSITORY"], "changes_since", changes_since)

    def run(at):
        return changes.poll_change_feeds(repo, settings, lambda payload, roots, states, budget: changes.read_changes(
            payload, roots, states, http_client=None, request_budget=budget), now=at, clock=lambda: clock[0])

    assert run(NOW)["checked"] == 3 and len(read) == 3
    monkeypatch.setattr(triggers, "prepare_trigger_plan", real_plan)  # queueing a change plans too
    real_apply = changes._apply

    def failing_apply(repo_, settings_, profile, root, root_id, *rest):
        if root["resource_id"] == item["id"]:
            raise RuntimeError("synthetic failure")
        return real_apply(repo_, settings_, profile, root, root_id, *rest)

    monkeypatch.setattr(changes, "_apply", failing_apply)
    later = NOW + timedelta(minutes=6)
    result = run(later)
    assert (result["checked"], result["failed"], result["enqueued"]) == (3, 1, 2)
    failed = [row for row in repo.change_cursors.values() if row["connection_id"] == connection.id]
    assert failed and failed[0]["state"]["error"] == "CHANGE_FEED_FAILED" and failed[0]["state"]["cursor"] == "a" * 40
    assert failed[0]["checked_at"] == later


@pytest.fixture(params=["sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def sql_repo(request):
    if request.param == "postgres":
        return request.getfixturevalue("pg")[1]
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def test_cursors_are_kept_moved_and_woken_in_the_database(sql_repo):
    repo, _connection, profile, _item, settings = setup("github", repo=sql_repo)
    switch_triggers(repo, change_feeds_enabled=True)
    feed = Feed(Changes(head="a" * 40), Changes(head="b" * 40, paths=["approved/app.env"]))
    assert poll(repo, settings, feed, NOW)["checked"] == 1
    _profile, plan, _target, _base, _source = triggers.prepare_trigger_plan(repo, settings, profile.id, "EVENT", now=NOW)
    root_id = scope.root_identity(profile.connection_id, plan.roots[0])
    store = changes.CursorStore(repo)
    assert store.get(root_id)["state"]["cursor"] == "a" * 40
    # Within the interval only a wake makes the root due again.
    assert poll(repo, settings, feed, NOW + timedelta(minutes=1))["checked"] == 0
    assert changes.wake(repo, profile, plan.roots[0])
    assert poll(repo, settings, feed, NOW + timedelta(minutes=1))["enqueued"] == 1
    saved = store.get(root_id)
    assert saved["state"]["cursor"] == "b" * 40 and saved["profile_id"] == profile.id
