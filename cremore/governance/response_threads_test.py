"""Team channel notices for exposure-response requests and their thread progress, against a fake Slack workspace
(the contact fakes' transport pattern): Admin-approved channels read with conversations.info on save and before every
post, the request's notice and DM, and the minute job's fixed-text replies. Memory, SQLite and (when configured)
PostgreSQL stores."""
import datetime as dt
import hashlib
import json
import re
import uuid
from urllib.parse import parse_qs

import httpx
import pytest

from cremore.governance import contact, response_channels, response_threads
from cremore.governance import response as service
from cremore.governance.contact_test import TOKEN, Relay
from cremore.governance.response_link_test import (
    LOCAL,
    NOW,
    PATH,
    PERSON,
    TEAM,
    answer,
    contact_setup,
    finding,
    statement,
)
from cremore.governance.response_link_test import (
    directory as directory,  # noqa: PLC0414 -- fake directory fixture
)
from cremore.governance.response_link_test import (
    pg as pg,  # noqa: PLC0414 -- guarded PostgreSQL fixture
)
from cremore.governance.response_link_test import (
    repo as repo,  # noqa: PLC0414 -- memory/SQLite/PostgreSQL stores
)
from cremore.siem.events_changes_test import events as siem_events
from cremore.ticketing import setup

TEAM_CHANNEL, PUBLIC_CHANNEL = "C0TEAM0001", "C0PUBLIC01"
LINK = re.compile(r"https://cremore\.example\.com/response#([A-Za-z0-9_-]{43})")


class Workspace:
    """The Slack Web API methods CreMore calls, each a POST with the bot's bearer. ``fail[method]``: the answers to
    give next, one per call (``("status", 429)``, ``("error", "missing_scope")`` or ``("raise", None)``)."""

    def __init__(self):
        self.users = {"kim@example.com": "U01KIM"}
        self.channels = {TEAM_CHANNEL: self.channel(TEAM_CHANNEL, "team-payments", private=True),
                         PUBLIC_CHANNEL: self.channel(PUBLIC_CHANNEL, "general", private=False)}
        self.calls, self.posts, self.fail, self.refuse, self.on_post, self.on_call = [], [], {}, {}, None, None

    @staticmethod
    def channel(channel_id, name, *, private):
        return {"id": channel_id, "name": name, "is_private": private, "is_archived": False, "is_ext_shared": False,
                "is_pending_ext_shared": False, "is_member": True}

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self))

    def __call__(self, request):
        assert request.headers["authorization"] == "Bearer " + TOKEN and request.url.host == "slack.com"
        assert request.method == "POST" and not request.url.query
        method = request.url.path.rsplit("/", 1)[1]
        form = request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded")
        body = {k: v[0] for k, v in parse_qs(request.content.decode()).items()} if form else json.loads(request.content)
        self.calls.append((method, body))
        if self.on_call is not None:
            self.on_call(method, body)
        if self.fail.get(method):
            kind, value = self.fail[method].pop(0)
            if kind == "status":
                return httpx.Response(value, headers={"retry-after": "30"})
            if kind == "raise":
                raise httpx.ConnectError("synthetic network failure")
            return httpx.Response(200, json={"ok": False, "error": value})
        if method == "conversations.info":
            found = self.channels.get(body["channel"])
            return httpx.Response(200, json={"ok": True, "channel": found} if found else
                                  {"ok": False, "error": "channel_not_found"})
        if method == "conversations.list":
            rows = list(self.channels.values())
            start, limit = int(body.get("cursor") or 0), int(body["limit"])
            page = rows[start:start + limit]
            cursor = str(start + limit) if start + limit < len(rows) else ""
            return httpx.Response(200, json={"ok": True, "channels": page, "response_metadata": {"next_cursor": cursor}})
        if method == "users.lookupByEmail":
            user = self.users.get(body["email"])
            return httpx.Response(200, json={"ok": True, "user": {"id": user}} if user else
                                  {"ok": False, "error": "users_not_found"})
        if method == "conversations.open":
            return httpx.Response(200, json={"ok": True, "channel": {"id": "D" + body["users"]}})
        assert method == "chat.postMessage"
        if body["channel"] in self.refuse:
            return httpx.Response(200, json={"ok": False, "error": self.refuse[body["channel"]]})
        if self.on_post is not None:
            self.on_post(body)
        self.posts.append(body)
        return httpx.Response(200, json={"ok": True, "ts": f"1700000000.{len(self.posts):06d}"})

    def notices(self, channel=TEAM_CHANNEL):
        return [post for post in self.posts if post["channel"] == channel and "thread_ts" not in post]

    def replies(self, ts=None):
        return [post["text"] for post in self.posts if "thread_ts" in post and (ts is None or post["thread_ts"] == ts)]


@pytest.fixture
def ws():
    return Workspace()


def transports(ws, relay=None):
    relay = relay or Relay()
    return {"smtp": relay, "smtp_ssl": relay, "http_client_factory": ws.client}


def approve(repo, ws, *channels, allow_public=(), version=0):
    return response_channels.save(repo, TEAM, {"expected_version": version, "channels": [
        {"channel_id": channel, "allow_public": channel in allow_public} for channel in channels]}, "admin",
        http_client_factory=ws.client, now=NOW)


def ask(repo, ws, item, *, channel="slack", slack_channel=TEAM_CHANNEL, dm=True, version=0, now=NOW, locale="en",
        settings=TEAM, **kwargs):
    return service.request_ticket(repo, settings, item.id, "analyst", channel=channel, expected_version=version,
                                  request_id=uuid.uuid4(), now=now, transports=transports(ws), locale=locale,
                                  slack_channel=slack_channel, dm=dm,
                                  **({"person_ref": PERSON} if settings is TEAM else {}) | kwargs)


def ready(repo, ws):
    item = finding(repo)
    contact_setup(repo)
    approve(repo, ws, TEAM_CHANNEL)
    return item


def run(repo, ws, minute, **kwargs):
    return response_threads.sweep(repo, TEAM, now=NOW + dt.timedelta(minutes=minute), http_client_factory=ws.client,
                                  **kwargs)


def pointer(repo, token):
    return repo.get_setting(service.LINK_PREFIX + hashlib.sha256(token.encode()).hexdigest())


def events(repo, item):
    return [(e.event_type, e.note) for e in repo.list_finding_events(item.id) if e.event_type.startswith("RESPONSE_")]


# --- the Admin's approved channels -----------------------------------------------------------------------------------

def test_approved_channels_are_read_from_slack_on_every_save_and_audited(repo, ws):
    contact_setup(repo)
    saved = approve(repo, ws, TEAM_CHANNEL, PUBLIC_CHANNEL, allow_public=(PUBLIC_CHANNEL,))
    assert saved == {"version": 1, "channels": [
        {"channel_id": TEAM_CHANNEL, "name": "team-payments", "is_private": True, "allow_public": False,
         "checked_at": NOW.isoformat()},
        {"channel_id": PUBLIC_CHANNEL, "name": "general", "is_private": False, "allow_public": True,
         "checked_at": NOW.isoformat()}]}
    assert response_channels.public(repo) == saved  # reloaded as saved
    assert response_channels.listed(repo) == {"channels": [
        {"channel_id": TEAM_CHANNEL, "name": "team-payments", "is_private": True},
        {"channel_id": PUBLIC_CHANNEL, "name": "general", "is_private": False}]}
    [audit] = [e for e in repo.list_events(50) if e.event_type == "RESPONSE_CHANNELS_SAVED"]
    assert (audit.actor, audit.target_type, audit.note) == (
        "admin", "response_channels", f"version=1 channels={TEAM_CHANNEL},{PUBLIC_CHANNEL} allow_public={PUBLIC_CHANNEL}")
    assert TOKEN not in json.dumps([repo.list_settings(response_channels.KEY), audit.note], default=str)
    with pytest.raises(service.ResponseError) as stale:
        approve(repo, ws, TEAM_CHANNEL, version=0)  # another Admin saved meanwhile
    assert (stale.value.code, stale.value.http_status) == ("RESPONSE_CHANNELS_CHANGED", 409)
    ws.channels["C0ARCHIV01"] = {**ws.channel("C0ARCHIV01", "old", private=True), "is_archived": True}
    ws.channels["C0EXTERN01"] = {**ws.channel("C0EXTERN01", "partner", private=True), "is_ext_shared": True}
    ws.channels["C0PENDNG01"] = {**ws.channel("C0PENDNG01", "invited", private=True), "is_pending_ext_shared": True}
    for channel, code in (("C0UNKNOW01", "RESPONSE_CHANNEL_NOT_FOUND"), ("C0ARCHIV01", "RESPONSE_CHANNEL_ARCHIVED"),
                          ("C0EXTERN01", "RESPONSE_CHANNEL_EXTERNAL"), ("C0PENDNG01", "RESPONSE_CHANNEL_EXTERNAL"),
                          (PUBLIC_CHANNEL, "RESPONSE_CHANNEL_PUBLIC_NOT_ALLOWED")):
        with pytest.raises(service.ResponseError) as refused:
            approve(repo, ws, TEAM_CHANNEL, channel, version=1)
        assert (refused.value.code, refused.value.http_status) == (code, 422), channel
    with pytest.raises(service.ResponseError) as external:  # shared with another company: whatever the Admin allows
        approve(repo, ws, "C0EXTERN01", allow_public=("C0EXTERN01",), version=1)
    assert external.value.code == "RESPONSE_CHANNEL_EXTERNAL"
    ws.fail["conversations.info"] = [("error", "missing_scope")]
    with pytest.raises(service.ResponseError) as scope:
        approve(repo, ws, TEAM_CHANNEL, version=1)
    assert scope.value.code == "SLACK_SCOPE_MISSING"
    with pytest.raises(service.ResponseError, match="RESPONSE_CHANNELS_INVALID"):
        approve(repo, ws, "#team-payments", version=1)  # an id, never a name
    assert response_channels.public(repo) == saved  # nothing refused was stored
    assert [e.event_type for e in repo.list_events(50)].count("RESPONSE_CHANNELS_SAVED") == 1
    assert approve(repo, ws, version=1) == {"version": 2, "channels": []}  # an empty list saves without Slack


def test_the_candidate_listing_is_bounded_across_pages(repo, ws, monkeypatch):
    contact_setup(repo)
    for index in range(7):
        channel_id = f"C0LIST{index:04d}"
        ws.channels[channel_id] = ws.channel(channel_id, f"team-{index}", private=bool(index % 2))
    ws.channels["C0NOTMEM01"] = {**ws.channel("C0NOTMEM01", "elsewhere", private=False), "is_member": False}
    ws.channels["C0EXTERN01"] = {**ws.channel("C0EXTERN01", "partner", private=True), "is_ext_shared": True}
    monkeypatch.setattr(response_channels, "CANDIDATE_LIMIT", 3)
    whole = response_channels.candidates(repo, TEAM, http_client_factory=ws.client)
    assert whole["truncated"] is False and len(whole["channels"]) == 10  # every page read; the non-member left out
    assert {"channel_id": "C0EXTERN01", "name": "partner", "is_private": True, "is_ext_shared": True} in whole["channels"]
    monkeypatch.setattr(response_channels, "CANDIDATE_PAGES", 2)
    ws.calls.clear()
    capped = response_channels.candidates(repo, TEAM, http_client_factory=ws.client)
    assert capped["truncated"] is True and len(capped["channels"]) == 6
    assert [method for method, _body in ws.calls] == ["conversations.list"] * 2
    assert all(body["types"] == "public_channel,private_channel" and body["exclude_archived"] == "true"
               for _method, body in ws.calls)
    ticks = iter([0, 11])  # the time budget ends the read too: the second page is past it
    monkeypatch.setattr(response_channels, "CANDIDATE_PAGES", 10)
    timed = response_channels.candidates(repo, TEAM, http_client_factory=ws.client, clock=lambda: next(ticks))
    assert timed["truncated"] is True and len(timed["channels"]) == 3


# --- the request's notice ---------------------------------------------------------------------------------------------

def test_a_request_with_a_team_channel_mentions_the_person_and_keeps_its_thread(repo, ws, directory):
    item = ready(repo, ws)
    asked = ask(repo, ws, item)
    current = asked["current"]
    assert (asked["state"], current["thread"], current["thread_error"]) == (
        "WAITING_OWNER", {"channel_id": TEAM_CHANNEL, "name": "team-payments"}, None)
    [dm] = [post for post in ws.posts if post["channel"] == "DU01KIM"]
    [notice] = ws.notices()
    assert notice["text"].startswith("<@U01KIM>: the security team asks you")
    token = LINK.search(notice["text"]).group(1)
    assert LINK.search(dm["text"]).group(1) == token and pointer(repo, token) is not None
    assert all(value not in notice["text"] for value in ("kim@example.com", PATH, "private-repo", "<!channel>"))
    assert "github / GITHUB_PAT" in notice["text"] and "Progress is posted in this thread." in notice["text"]
    stored = service._current(repo, str(item.id))[1]["thread"]
    assert stored == {"channel_id": TEAM_CHANNEL, "name": "team-payments", "ts": "1700000000.000002"}
    assert stored["ts"] not in json.dumps(asked)  # the thread's ts stays server-side
    assert events(repo, item)[-1] == ("RESPONSE_LINK_SENT",
                                      f"request={current['request_id']} cycle=1 via=slack dm channel={TEAM_CHANNEL}")
    # Before the post, the channel was read again (conversations.info) after the approval's own read.
    assert [method for method, body in ws.calls if body.get("channel") == TEAM_CHANNEL][-2:] == [
        "conversations.info", "chat.postMessage"]


def test_a_channel_only_request_carries_the_link_and_falls_back_to_the_name(repo, ws, directory):
    item = ready(repo, ws)
    ws.users.clear()  # Slack does not know the person's address: their name, no mention
    asked = ask(repo, ws, item, dm=False, locale="ko")
    assert asked["state"] == "WAITING_OWNER" and asked["current"]["thread"]["channel_id"] == TEAM_CHANNEL
    assert not any(method == "conversations.open" for method, _body in ws.calls)  # no DM
    [notice] = ws.notices()
    assert notice["text"].startswith("Kim님, 보안팀이") and "<@" not in notice["text"]
    assert "플레이북" not in notice["text"]  # a channel shows the link; the playbook is the DM's and the link page's
    assert pointer(repo, LINK.search(notice["text"]).group(1)) is not None
    assert events(repo, item)[-1][1].endswith(f"via=slack channel={TEAM_CHANNEL}")


def test_a_fallback_name_that_looks_like_slack_markup_is_shown_as_text(repo, ws, directory):
    item = ready(repo, ws)
    ws.users.clear()  # no Slack account for the address: the directory's name stands in
    directory.name = "Kim <!channel> <#C0OTHER01>"
    ask(repo, ws, item, dm=False)
    [notice] = ws.notices()
    assert notice["text"].startswith("Kim &lt;!channel&gt; &lt;#C0OTHER01&gt;: the security team asks you")
    assert "<!" not in notice["text"] and "<#" not in notice["text"]


@pytest.mark.parametrize("name", ["kim@example.com", "<@U0ADMIN1>"])
def test_a_fallback_name_with_an_address_sign_is_never_shown(repo, ws, directory, name):
    """The directory fills a missing display name with the email; Slack does not know the address either."""
    item = ready(repo, ws)
    ws.users.clear()
    directory.name = name
    ask(repo, ws, item, dm=False)
    [notice] = ws.notices()
    assert notice["text"].startswith("The person asked: the security team asks you")
    assert "kim@example.com" not in notice["text"] and "U0ADMIN1" not in notice["text"]


def withdraw(repo, ws):
    response_channels.save(repo, TEAM, {"expected_version": response_channels.public(repo)["version"], "channels": []},
                           "admin", http_client_factory=ws.client, now=NOW)


CHANGES = [({"is_ext_shared": True}, "RESPONSE_CHANNEL_EXTERNAL"),
           ({"is_private": False}, "RESPONSE_CHANNEL_PUBLIC_NOT_ALLOWED"),
           ({"is_archived": True}, "RESPONSE_CHANNEL_ARCHIVED"),
           (None, "RESPONSE_CHANNEL_NOT_APPROVED")]  # None: the Admin withdraws the channel


def flip(repo, ws, change):
    if change is None:
        withdraw(repo, ws)
    else:
        ws.channels[TEAM_CHANNEL].update(change)


@pytest.mark.parametrize(("change", "code"), CHANGES)
def test_a_channel_that_changes_while_the_dm_goes_out_gets_no_notice(repo, ws, directory, change, code):
    item = ready(repo, ws)
    flipped = []

    def during_dm(method, body):  # the DM is slow; the channel changes meanwhile
        if method == "chat.postMessage" and body["channel"].startswith("D") and not flipped:
            flipped.append(flip(repo, ws, change))

    ws.on_call = during_dm
    asked = ask(repo, ws, item)
    assert flipped and ws.notices() == [] and len(ws.posts) == 1  # the DM went out, the notice did not
    assert (asked["state"], asked["current"]["thread"], asked["current"]["thread_error"]) == ("WAITING_OWNER", None, code)
    # The notice the only delivery: the change during the address lookup ends the request.
    other, flipped[:] = finding(repo), []
    if change is None:
        approve(repo, ws, TEAM_CHANNEL, version=response_channels.public(repo)["version"])
    else:
        ws.channels[TEAM_CHANNEL] = ws.channel(TEAM_CHANNEL, "team-payments", private=True)
    ws.on_call = lambda method, body: (flipped.append(flip(repo, ws, change))
                                       if method == "users.lookupByEmail" and not flipped else None)
    alone = ask(repo, ws, other, dm=False)
    assert (alone["state"], alone["current"]["error_code"], alone["current"]["thread_error"]) == ("NOT_SENT", code, code)
    assert ws.notices() == []


def test_a_failed_notice_keeps_a_delivered_dm_and_ends_a_channel_only_request(repo, ws, directory):
    item = ready(repo, ws)
    ws.refuse[TEAM_CHANNEL] = "not_in_channel"
    with_dm = ask(repo, ws, item)
    assert (with_dm["state"], with_dm["current"]["thread"], with_dm["current"]["thread_error"]) == (
        "WAITING_OWNER", None, "SLACK_NOT_IN_CHANNEL")
    assert events(repo, item)[-1][1].endswith("via=slack dm")
    other = finding(repo)
    alone = ask(repo, ws, other, dm=False)
    assert (alone["state"], alone["current"]["error_code"], alone["current"]["thread_error"]) == (
        "NOT_SENT", "SLACK_NOT_IN_CHANNEL", "SLACK_NOT_IN_CHANNEL")
    [refused] = [body for method, body in ws.calls if method == "chat.postMessage" and body["channel"] == TEAM_CHANNEL][-1:]
    assert pointer(repo, LINK.search(refused["text"]).group(1)) is None  # the link is dead


@pytest.mark.parametrize(("change", "code"), [
    ({"is_private": False}, "RESPONSE_CHANNEL_PUBLIC_NOT_ALLOWED"),
    ({"is_ext_shared": True}, "RESPONSE_CHANNEL_EXTERNAL"),
    ({"is_pending_ext_shared": True}, "RESPONSE_CHANNEL_EXTERNAL"),
    ({"is_archived": True}, "RESPONSE_CHANNEL_ARCHIVED"),
])
def test_a_channel_that_changed_since_its_approval_gets_no_request(repo, ws, directory, change, code):
    item = ready(repo, ws)
    ws.channels[TEAM_CHANNEL].update(change)
    with pytest.raises(service.ResponseError) as refused:
        ask(repo, ws, item)
    assert (refused.value.code, refused.value.http_status) == (code, 409)
    assert ws.posts == [] and repo.list_settings(service.HEAD_PREFIX) == []


def test_a_channel_notice_needs_a_link_request_an_approved_channel_and_a_target(repo, ws, directory):
    item = ready(repo, ws)

    def refused(**kwargs):
        with pytest.raises(service.ResponseError) as error:
            ask(repo, ws, item, **kwargs)
        return error.value.code, error.value.http_status

    assert refused(channel="record", settings=LOCAL, to="kim@example.com") == ("RESPONSE_SLACK_CHANNEL_NOT_ALLOWED", 422)
    assert refused(channel="ticket") == ("RESPONSE_SLACK_CHANNEL_NOT_ALLOWED", 422)
    assert refused(slack_channel=None, dm=False) == ("RESPONSE_DELIVERY_REQUIRED", 422)
    assert refused(slack_channel=PUBLIC_CHANNEL) == ("RESPONSE_CHANNEL_NOT_APPROVED", 422)
    assert ws.posts == [] and repo.list_settings(service.HEAD_PREFIX) == []


# --- the thread's progress --------------------------------------------------------------------------------------------

def test_each_state_change_gets_one_fixed_reply_in_the_thread(repo, ws, directory):
    item = ready(repo, ws)
    first = ask(repo, ws, item)
    thread = service._current(repo, str(item.id))[1]["thread"]["ts"]
    token = LINK.search(ws.notices()[0]["text"]).group(1)
    assert setup.configured(repo) is None  # no ticket system: the replies need none
    assert run(repo, ws, 1) == 0 and ws.replies() == []  # asked and sent: nothing to say yet
    answer(repo, token, statement(result="EXCEPTION", path="EXCEPTION", actions=[],
                                  explanation="An external vendor holds this key; the contract ends next quarter."))
    answer(repo, token, now=NOW + dt.timedelta(minutes=3))
    started = NOW + dt.timedelta(minutes=4)
    assert service.observe_scan(repo, item.id, removed=True, observed_at=started, scan_started_at=started)
    for exposure in repo.exposures_for_credential(item.credential_id):
        repo.mark_exposure_removed(exposure.id)
    repo.repair_finding_rollup(item.credential_id)
    version = service.summary(repo, item.id)["version"]
    checks = {key: {"state": "PASS"} for key in ("report", "removal", "retirement", "replacement", "vault", "cutover")}
    assert service.reconcile(repo, item.id, checks, expected_version=version, now=started)
    assert run(repo, ws, 5) == 4
    assert ws.replies(thread) == [response_threads.TEXTS["en"][kind] for kind in
                                  ("exception", "done", "verified", "completed")]
    later = NOW + dt.timedelta(minutes=6)
    assert service.observe_scan(repo, item.id, removed=False, observed_at=later, scan_started_at=later)
    later = NOW + dt.timedelta(minutes=7)
    assert service.observe_scan(repo, item.id, removed=False, observed_at=later, scan_started_at=later)
    assert run(repo, ws, 8) == 2
    assert ws.replies(thread)[4:] == [response_threads.TEXTS["en"]["reappeared"],
                                      response_threads.TEXTS["en"]["still_exposed"]]
    second = ask(repo, ws, item, version=service.summary(repo, item.id)["version"], now=NOW + dt.timedelta(minutes=9))
    assert run(repo, ws, 10) == 1
    assert ws.replies(thread)[6:] == [response_threads.TEXTS["en"]["rerequested"]]
    assert run(repo, ws, 11) == 0  # each said once
    # The new request's own thread: its link ends unanswered, and that shows once.
    new_thread = service._current(repo, str(item.id))[1]["thread"]["ts"]
    assert new_thread != thread and second["current"]["previous_request_id"] == first["current"]["request_id"]
    assert run(repo, ws, 9 + 7 * 24 * 60) == 1 and run(repo, ws, 9 + 7 * 24 * 60 + 1) == 0
    assert ws.replies(new_thread) == [response_threads.TEXTS["en"]["expired"]]
    text = json.dumps(ws.replies())
    assert all(value not in text for value in ("vendor", "kim@", PATH, "Removed the published copy"))
    assert service.public(repo, item.id, now=NOW)["current"]["thread_error"] is None


def test_threads_replaced_twice_before_any_reply_still_get_every_reply(repo, ws, directory):
    """A→B→C while Slack does not answer: A's and B's replies are owed until posted, then their threads retire."""
    item = ready(repo, ws)

    def thread_of(request_id):
        return service._row(repo, service._key(str(item.id), request_id))["thread"]["ts"]

    first = ask(repo, ws, item)
    answer(repo, LINK.search(ws.notices()[-1]["text"]).group(1),
           statement(result="INCOMPLETE", path="EXCEPTION", actions=[],
                     explanation="The deploy job still reads it; replacing it next week."))
    ws.fail["chat.postMessage"] = [("status", 503)]
    assert run(repo, ws, 1) == 0 and ws.replies() == []  # Slack down: nothing moves
    version = service.summary(repo, item.id)["version"]
    second = ask(repo, ws, item, version=version, now=NOW + dt.timedelta(minutes=2))
    answer(repo, LINK.search(ws.notices()[-1]["text"]).group(1),
           statement(result="EXCEPTION", path="EXCEPTION", actions=[],
                     explanation="An external vendor holds this key until the contract ends.",
                     performed_at=(NOW + dt.timedelta(minutes=2, seconds=30)).isoformat()),
           now=NOW + dt.timedelta(minutes=3))
    version = service.summary(repo, item.id)["version"]
    third = ask(repo, ws, item, version=version, now=NOW + dt.timedelta(minutes=4), slack_channel=None)  # no thread
    assert third["current"]["thread"] is None
    assert run(repo, ws, 5) == 4
    texts = response_threads.TEXTS["en"]
    assert ws.replies(thread_of(first["current"]["request_id"])) == [texts["not_done"], texts["rerequested"]]
    assert ws.replies(thread_of(second["current"]["request_id"])) == [texts["exception"], texts["rerequested"]]
    assert run(repo, ws, 6) == 0  # both retired: marked here, never deleted by this job
    assert all(row["value"] == {"retired": True} for row in repo.list_settings(response_threads.THREAD_PREFIX))
    service.sweep(repo, TEAM, None, now=NOW + dt.timedelta(minutes=6))  # the mixed/collector worker drops them
    assert repo.list_settings(response_threads.THREAD_PREFIX) == []
    assert run(repo, ws, 7) == 0 and len(ws.replies()) == 4


def test_two_replicas_in_one_minute_post_once(repo, ws, directory):
    item = ready(repo, ws)
    ask(repo, ws, item)
    answer(repo, LINK.search(ws.notices()[0]["text"]).group(1))
    other = []
    ws.on_post = lambda body: other.append(run(repo, ws, 1)) if "thread_ts" in body and not other else None
    assert run(repo, ws, 1) == 1
    assert other == [0] and len(ws.replies()) == 1  # the second replica found the minute taken


def test_a_reply_is_posted_at_least_once_across_a_crash(repo, ws, directory, monkeypatch):
    item = ready(repo, ws)
    ask(repo, ws, item)
    answer(repo, LINK.search(ws.notices()[0]["text"]).group(1))
    # The network fails before Slack takes the reply: nothing moves, the next minute posts it.
    ws.fail["chat.postMessage"] = [("raise", None)]
    assert run(repo, ws, 1) == 0 and ws.replies() == []
    assert repo.get_setting(response_threads.STATE_KEY)["value"]["error"] == "SLACK_UNAVAILABLE"
    assert run(repo, ws, 2) == 1 and len(ws.replies()) == 1
    # Slack took the next reply, then the process died before its cursor moved: the reply goes again.
    started = NOW + dt.timedelta(minutes=3)
    assert service.observe_scan(repo, item.id, removed=True, observed_at=started, scan_started_at=started)
    original = response_threads._commit

    def crash(*args):
        raise RuntimeError("process died")

    monkeypatch.setattr(response_threads, "_commit", crash)
    with pytest.raises(RuntimeError):
        run(repo, ws, 3)
    monkeypatch.setattr(response_threads, "_commit", original)
    assert run(repo, ws, 4) == 1
    verified = response_threads.TEXTS["en"]["verified"]
    assert ws.replies()[1:] == [verified, verified]


@pytest.mark.parametrize(("change", "code"), [
    ({"is_private": False}, "RESPONSE_CHANNEL_PUBLIC_NOT_ALLOWED"),
    ({"is_ext_shared": True}, "RESPONSE_CHANNEL_EXTERNAL"),
    ({"is_archived": True}, "RESPONSE_CHANNEL_ARCHIVED"),
])
def test_a_channel_that_changed_gets_no_reply_and_says_why(repo, ws, directory, change, code):
    item = ready(repo, ws)
    ask(repo, ws, item)
    answer(repo, LINK.search(ws.notices()[0]["text"]).group(1))
    before = service.public(repo, item.id, now=NOW)
    ws.channels[TEAM_CHANNEL].update(change)
    assert run(repo, ws, 1) == 0 and ws.replies() == []
    after = service.public(repo, item.id, now=NOW)
    assert after["current"]["thread_error"] == code
    assert (after["state"], after["version"]) == (before["state"], before["version"])  # the response did not move
    assert sum(1 for method, body in ws.calls if method == "conversations.info"
               and body["channel"] == TEAM_CHANNEL) == 4  # approval, the request's two checks, and before this reply
    ws.channels[TEAM_CHANNEL].update(ws.channel(TEAM_CHANNEL, "team-payments", private=True))
    assert run(repo, ws, 2) == 0  # the refused reply is not owed any more


@pytest.mark.parametrize(("failure", "code"), [(("status", 429), "SLACK_RATE_LIMITED"),
                                               (("status", 503), "SLACK_UNAVAILABLE")])
def test_a_slack_that_does_not_answer_stops_the_run_and_the_next_minute_posts(repo, ws, directory, failure, code):
    items = [ready(repo, ws), finding(repo)]
    for item in items:
        ask(repo, ws, item)
        answer(repo, LINK.search(ws.notices()[-1]["text"]).group(1))
    ws.fail["chat.postMessage"] = [failure]
    ws.calls.clear()
    assert run(repo, ws, 1) == 0
    assert sum(1 for method, _body in ws.calls if method == "chat.postMessage") == 1  # the run stopped there
    state = repo.get_setting(response_threads.STATE_KEY)["value"]
    assert {key: state[key] for key in ("at", "posted", "error", "owed")} == {
        "at": (NOW + dt.timedelta(minutes=1)).isoformat(), "posted": 0, "error": code, "owed": 2}
    assert all(service.public(repo, item.id, now=NOW)["current"]["thread_error"] is None for item in items)
    assert run(repo, ws, 1) == 0  # the same minute is taken
    assert run(repo, ws, 2) == 2 and len(ws.replies()) == 2


def test_channel_saves_reach_siem_without_anything_private(repo, ws):
    contact_setup(repo)
    approve(repo, ws, TEAM_CHANNEL, PUBLIC_CHANNEL, allow_public=(PUBLIC_CHANNEL,))
    [row] = [row for row in siem_events(repo, "audit.action") if row["audit"]["action"] == "RESPONSE_CHANNELS_SAVED"]
    assert row["audit"]["target_type"] == "response_channels"
    assert not any(value in json.dumps(row) for value in (TEAM_CHANNEL, "team-payments", "general", "admin", TOKEN))


def test_missing_channel_scopes_refuse_only_the_channel_features(repo, ws, directory):
    item = ready(repo, ws)
    ws.fail["conversations.info"] = [("error", "missing_scope")]
    with pytest.raises(service.ResponseError, match="SLACK_SCOPE_MISSING"):
        ask(repo, ws, item)
    assert ask(repo, ws, item, slack_channel=None)["state"] == "WAITING_OWNER"  # the DM needs no channel scope
    assert set(contact.SLACK_SCOPES) >= {"channels:read", "groups:read"}


def answered_and_verified(repo, ws, item, *, minute=3):
    """Two replies owed in one thread: the answer (done) and the scan that confirms the removal."""
    ask(repo, ws, item)
    answer(repo, LINK.search(ws.notices()[-1]["text"]).group(1))
    started = NOW + dt.timedelta(minutes=minute)
    assert service.observe_scan(repo, item.id, removed=True, observed_at=started, scan_started_at=started)


@pytest.mark.parametrize(("change", "code"), CHANGES)
def test_a_channel_that_changes_between_two_replies_of_one_run_gets_only_the_first(repo, ws, directory, change, code):
    item = ready(repo, ws)
    answered_and_verified(repo, ws, item)
    ws.on_post = lambda body: flip(repo, ws, change) if "thread_ts" in body and not ws.replies() else None
    checks = sum(1 for method, _body in ws.calls if method == "conversations.info")
    assert run(repo, ws, 4) == 1
    assert ws.replies() == [response_threads.TEXTS["en"]["done"]]
    assert service.public(repo, item.id, now=NOW)["current"]["thread_error"] == code
    if change is not None:  # each reply read the channel itself; no decision was carried over
        assert sum(1 for method, _body in ws.calls if method == "conversations.info") == checks + 2


def refuse_delete(self, prefix, cutoff):
    raise PermissionError("permission denied for table installation_settings")  # the control role has SIU only


def test_the_job_never_deletes_so_replies_flow_where_deleting_is_refused(repo, ws, directory, monkeypatch):
    item = ready(repo, ws)
    first = ask(repo, ws, item)
    answer(repo, LINK.search(ws.notices()[-1]["text"]).group(1),
           statement(result="INCOMPLETE", path="EXCEPTION", actions=[],
                     explanation="The deploy job still reads it; replacing it next week."))
    second = ask(repo, ws, item, version=service.summary(repo, item.id)["version"], now=NOW + dt.timedelta(minutes=3))
    texts = response_threads.TEXTS["en"]
    retired = response_threads.THREAD_PREFIX + str(item.id) + ":" + first["current"]["request_id"]
    kept = response_threads.THREAD_PREFIX + str(item.id) + ":" + second["current"]["request_id"]
    with monkeypatch.context() as control:  # every run as the control process: no DELETE on installation_settings
        control.setattr(type(repo), "delete_settings_before", refuse_delete)
        assert run(repo, ws, 4) == 2 and ws.replies() == [texts["not_done"], texts["rerequested"]]
        assert run(repo, ws, 5) == 0 and repo.get_setting(retired)["value"] == {"retired": True}
        late = 3 + int(service.LINK_LIFETIME.total_seconds()) // 60
        assert run(repo, ws, late) == 1 and ws.replies()[2:] == [texts["expired"]]  # later minutes still post
        assert repo.get_setting(response_threads.STATE_KEY)["value"]["error"] is None
    service.sweep(repo, TEAM, None, now=NOW + dt.timedelta(minutes=late))  # the mixed/collector worker may delete
    assert repo.get_setting(retired) is None and repo.get_setting(kept) is not None


def test_newer_scans_that_change_nothing_get_no_reply_and_do_not_grow_the_cursor(repo, ws, directory):
    item = ready(repo, ws)
    asked = ask(repo, ws, item)
    answer(repo, LINK.search(ws.notices()[-1]["text"]).group(1))
    started = NOW + dt.timedelta(minutes=4)
    assert service.observe_scan(repo, item.id, removed=True, observed_at=started, scan_started_at=started)
    for exposure in repo.exposures_for_credential(item.credential_id):
        repo.mark_exposure_removed(exposure.id)
    repo.repair_finding_rollup(item.credential_id)
    checks = {key: {"state": "PASS"} for key in ("report", "removal", "retirement", "replacement", "vault", "cutover")}
    assert service.reconcile(repo, item.id, checks, expected_version=service.summary(repo, item.id)["version"],
                             now=started)
    texts = response_threads.TEXTS["en"]
    assert run(repo, ws, 5) == 3 and ws.replies() == [texts["done"], texts["verified"], texts["completed"]]
    key = response_threads.THREAD_PREFIX + str(item.id) + ":" + asked["current"]["request_id"]
    cursor = repo.get_setting(key)["value"]
    for day in (1, 2, 3):  # daily scans after completion: removal confirmed again, nothing changed
        at = started + dt.timedelta(days=day)
        assert service.observe_scan(repo, item.id, removed=True, observed_at=at, scan_started_at=at)
        assert run(repo, ws, day * 24 * 60 + 5) == 0
    assert repo.get_setting(key)["value"] == cursor and len(ws.replies()) == 3
    for day in (4, 5, 6):  # exposed again, then the same evidence on every later scan
        at = started + dt.timedelta(days=day)
        assert service.observe_scan(repo, item.id, removed=False, observed_at=at, scan_started_at=at)
    assert [kind for kind, _note in events(repo, item)[-3:]] == [
        "RESPONSE_REAPPEARED", "RESPONSE_STILL_EXPOSED", "RESPONSE_STILL_EXPOSED"]
    assert run(repo, ws, 6 * 24 * 60 + 5) == 2 and ws.replies()[3:] == [texts["reappeared"], texts["still_exposed"]]
    assert len(repo.get_setting(key)["value"]["posted"]) == len(cursor["posted"]) + 2
    assert run(repo, ws, 6 * 24 * 60 + 6) == 0


@pytest.mark.parametrize("error", ["restricted_action_thread_locked", "restricted_action_read_only_channel",
                                   "restricted_action_non_threadable_channel"])
def test_a_locked_thread_does_not_hold_back_the_others(repo, ws, directory, error):
    items = [ready(repo, ws), finding(repo)]
    for item in items:
        ask(repo, ws, item)
        answer(repo, LINK.search(ws.notices()[-1]["text"]).group(1))
    ws.fail["chat.postMessage"] = [("error", error)]  # the first thread the run reaches is locked
    assert run(repo, ws, 1) == 1 and len(ws.replies()) == 1
    errors = sorted(str(service.public(repo, item.id, now=NOW)["current"]["thread_error"]) for item in items)
    assert errors == sorted(["None", "SLACK_" + error.upper()])
    assert run(repo, ws, 2) == 0  # the refused reply is not owed again


def test_a_missing_scope_stops_the_run_and_every_reply_goes_once_it_is_back(repo, ws, directory):
    item = ready(repo, ws)
    answered_and_verified(repo, ws, item)
    ws.fail["conversations.info"] = [("error", "missing_scope")] * 2  # an Admin removed channels:read for a while
    for minute in (4, 5):
        assert run(repo, ws, minute) == 0
        assert repo.get_setting(response_threads.STATE_KEY)["value"]["error"] == "SLACK_SCOPE_MISSING"
    assert service.public(repo, item.id, now=NOW)["current"]["thread_error"] is None  # nothing was dropped
    assert run(repo, ws, 6) == 2
    assert ws.replies() == [response_threads.TEXTS["en"][kind] for kind in ("done", "verified")]


# --- the operations alert ------------------------------------------------------------------------------------------
# Audit rows and settings rows take the store's clock, so these runs and reads are timed from it, not from NOW.

def test_replies_owed_for_over_an_hour_raise_an_operations_alert_naming_why(repo, ws, directory):
    item = ready(repo, ws)
    start = dt.datetime.now(dt.UTC)
    ask(repo, ws, item, now=start)
    answer(repo, LINK.search(ws.notices()[-1]["text"]).group(1),
           statement(performed_at=(start + dt.timedelta(minutes=1)).isoformat()), now=start + dt.timedelta(minutes=1))
    ws.fail["chat.postMessage"] = [("status", 503)] * 2
    assert response_threads.sweep(repo, TEAM, now=start + dt.timedelta(minutes=2), http_client_factory=ws.client) == 0
    state = repo.get_setting(response_threads.STATE_KEY)["value"]
    assert state["owed"] == 1 and state["error"] == "SLACK_UNAVAILABLE"
    since = dt.datetime.fromisoformat(state["owed_since"])  # the answer's audit row
    hour = response_threads.ALERT_AFTER
    assert response_threads.alerts(repo, now=since + hour) == []
    late = since + hour + dt.timedelta(minutes=1)
    assert response_threads.sweep(repo, TEAM, now=late, http_client_factory=ws.client) == 0  # Slack still failing
    assert response_threads.alerts(repo, now=late) == [{
        "code": "RESPONSE_THREADS_FAILING", "resource_type": "response_threads", "resource_id": "progress",
        "last_run_at": late.isoformat(), "owed_replies": 1, "failing_since": since.isoformat(),
        "error_codes": ["SLACK_UNAVAILABLE"]}]
    after = late + dt.timedelta(minutes=1)
    assert response_threads.sweep(repo, TEAM, now=after, http_client_factory=ws.client) == 1
    assert response_threads.alerts(repo, now=after) == []


def test_open_threads_without_a_run_for_over_an_hour_raise_an_operations_alert(repo, ws, directory):
    assert response_threads.alerts(repo) == []  # no thread: no run is owed
    item = ready(repo, ws)
    ask(repo, ws, item, now=dt.datetime.now(dt.UTC))
    [row] = repo.list_settings(response_threads.THREAD_PREFIX)
    opened, hour = service._utc(row["updated_at"]), response_threads.ALERT_AFTER
    assert response_threads.alerts(repo, now=opened + hour) == []
    late = opened + hour + dt.timedelta(minutes=1)
    stopped = {"code": "RESPONSE_THREADS_STOPPED", "resource_type": "response_threads", "resource_id": "progress",
               "last_run_at": None, "open_threads": 1, "failing_since": opened.isoformat()}
    assert response_threads.alerts(repo, now=late) == [stopped]
    # A run with nothing owed still counts: the job is there.
    assert response_threads.sweep(repo, TEAM, now=late, http_client_factory=ws.client) == 0 and not ws.replies()
    assert repo.get_setting(response_threads.STATE_KEY)["value"]["owed"] == 0
    assert response_threads.alerts(repo, now=late + hour) == []
    later = late + hour + dt.timedelta(minutes=1)
    assert response_threads.alerts(repo, now=later) == [
        {**stopped, "last_run_at": late.isoformat(), "failing_since": late.isoformat()}]
