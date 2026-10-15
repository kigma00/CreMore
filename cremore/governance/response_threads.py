"""Progress replies in the thread of an exposure-response request's team-channel notice (cremore.governance.response).

Once a minute, where Slack alerts go out (the mixed worker, a split deployment's control process), one replica
(``claim_slot``) reads the response audit rows of each request that has a thread and posts one fixed-text reply per
state change: answered (done, not done, exception), removal verified, still exposed, reappeared, completed, asked again
(in the replaced request's thread) and, once it shows, the link's end. Never the explanation, an address or a path.
A newer scan that only repeats what the thread was told (the same evidence again, or removal confirmed again after
completion) is owed nothing; that follows from the audit rows alone, so the cursor keeps only the replies owed.

Right before each post the channel's approval is read again and the channel with ``conversations.info``: an archived
channel, one now shared with another company, a public one the Admin did not allow, or one no longer approved gets
nothing, and the refusal is kept on the request as ``thread_error`` (the response's state never changes here).
Slack has no check-and-post, so a change in the moment between the two calls can still be missed.

Every thread is registered with its cursor (``response:thread:<finding>:<request>``, the audit rows it has answered)
when the request that made it is saved, so a thread is served however many later requests replaced its own before a
run could post. A replaced request's thread is marked retired once all it is owed was replied; this job never deletes
(the control database role has no DELETE on installation_settings), the response sweep (cremore.governance.response,
run by the mixed and collector workers) drops retired rows.
Delivery is at least once: the cursor is written after the post or a definite refusal. A 429, a 5xx, a timeout, a
missing scope or any other failure every post would meet stops the run; the next minute tries again. The thread posts
are not audit rows. While any thread is open every minute's run keeps, in ``response:threads:state``, its time, its
error and the replies still owed with the oldest one's time; ``alerts`` reads only that and the open threads to tell
the operations status (GET /api/v1/operations/status) when replies have waited over an hour or no run came.
"""

from __future__ import annotations

import datetime as dt
import re
import time
import uuid
from typing import NamedTuple

from cremore.governance import contact, response, response_channels
from cremore.governance.response_reports import PREFIX as REPORT_PREFIX

SWEEP_KEY = "response:threads:sweep"
STATE_KEY = "response:threads:state"
THREAD_PREFIX = response.THREAD_PREFIX
ACTOR = "system:response-threads"
BUDGET_SECONDS = 20  # the loop's share; what is left waits for the next minute
ALERT_AFTER = dt.timedelta(hours=1)  # replies owed, or open threads without a run, this long: an operations alert
MAX_POSTS = 20  # replies per run, across every thread
_REQUEST = re.compile(r"\brequest=([0-9a-f-]{36})\b")
_REPORT = re.compile(r"\breport=([0-9a-f-]{36})\b")
_KINDS = {"RESPONSE_CLEANUP_DECLARED": "done", "RESPONSE_DECLINED": "not_done", "RESPONSE_REMOVAL_VERIFIED": "verified",
          "RESPONSE_STILL_EXPOSED": "still_exposed", "RESPONSE_REAPPEARED": "reappeared",
          "RESPONSE_COMPLETED": "completed"}
_EVIDENCE = frozenset({"verified", "still_exposed", "reappeared"})
# A refusal of one channel or message: kept as thread_error, and the cursor moves on. Any other failure stops the run;
# a missing scope too, so what is owed goes out once the Admin adds it back.
_DEFINITE = frozenset({
    "RESPONSE_CHANNEL_NOT_FOUND", "RESPONSE_CHANNEL_ARCHIVED", "RESPONSE_CHANNEL_EXTERNAL",
    "RESPONSE_CHANNEL_PUBLIC_NOT_ALLOWED", "RESPONSE_CHANNEL_NOT_APPROVED",
    "SLACK_CHANNEL_NOT_FOUND", "SLACK_NOT_IN_CHANNEL", "SLACK_IS_ARCHIVED", "SLACK_MSG_TOO_LONG", "SLACK_NO_TEXT",
    "SLACK_INVALID_ARGUMENTS", "SLACK_CANNOT_REPLY_TO_MESSAGE", "SLACK_THREAD_NOT_FOUND",
})


def _definite(code: str) -> bool:
    # Slack's restricted_action family (read-only channel, locked thread, a channel without threads, ...) is about
    # this channel or thread only.
    return code in _DEFINITE or code.startswith("SLACK_RESTRICTED_ACTION")


TEXTS = {
    "ko": {"done": "응답: 정리를 마쳤다고 보고했습니다. CreMore가 이후 검사로 확인합니다.",
           "not_done": "응답: 아직 정리를 마치지 못했다고 보고했습니다.",
           "exception": "응답: 예외로 보고했습니다.",
           "verified": "검사 결과: 노출된 곳에서 제거가 확인되었습니다.",
           "still_exposed": "검사 결과: 아직 노출되어 있습니다.",
           "reappeared": "검사 결과: 다시 노출되었습니다.",
           "completed": "대응 완료: 제거와 후속 조치가 모두 확인되었습니다.",
           "rerequested": "새 대응 요청을 보냈습니다. 이 요청은 끝났습니다.",
           "expired": "응답 링크가 만료되었습니다. 보안팀이 다시 요청할 수 있습니다."},
    "en": {"done": "Answered: cleanup reported done. CreMore verifies it with a later scan.",
           "not_done": "Answered: cleanup reported not finished.",
           "exception": "Answered: reported as an exception.",
           "verified": "Scan: removal confirmed where it was exposed.",
           "still_exposed": "Scan: still exposed.",
           "reappeared": "Scan: exposed again.",
           "completed": "Completed: removal and the follow-up checks are confirmed.",
           "rerequested": "A new request was sent; this one has ended.",
           "expired": "The answer link expired. The security team can ask again."},
}


class Item(NamedTuple):
    finding_id: str
    cycle: dict
    key: str  # the audit row's id, or "expired"
    kind: str
    at: dt.datetime  # since when it is owed: the audit row's time, or the link's end


def _thread_key(finding_id: str, request_id: str) -> str:
    return THREAD_PREFIX + finding_id + ":" + request_id


def _declined(repo, finding_id, request_id, note) -> str:
    """An answer that is not done: an exception when the report it records says so."""
    found = _REPORT.search(note or "")
    report = response._row(repo, REPORT_PREFIX + finding_id + ":" + request_id + ":" + found.group(1)) if found else {}
    return "exception" if report.get("result") == "EXCEPTION" else "not_done"


def _items(repo, now) -> tuple[list[Item], list[tuple[str, str]], int]:
    """(what is owed, the threads that are done, how many threads are open): for each registered thread, every state
    change of its request the thread has not answered yet, in the order they were recorded, then the request asked
    after it and, for the current request, its link's end. A replaced request changes no more, so its thread is done
    once nothing is owed."""
    registered = {}
    for row in repo.list_settings(THREAD_PREFIX):
        value = row.get("value") or {}
        if value.get("retired"):
            continue
        finding_id, _, request_id = row["key"][len(THREAD_PREFIX):].partition(":")
        registered.setdefault(finding_id, {})[request_id] = set(value.get("posted") or [])
    items, done = [], []
    for finding_id, threads in registered.items():
        _head, current = response._current(repo, finding_id)
        cycles = {row["value"]["request_id"]: row["value"]
                  for row in repo.list_settings(response.CYCLE_PREFIX + finding_id + ":")}
        after = {cycle["previous_request_id"]: cycle["request_id"] for cycle in cycles.values()
                 if cycle.get("previous_request_id")}
        events = [event for event in repo.list_finding_events(uuid.UUID(finding_id))
                  if event.event_type in _KINDS or event.event_type == "RESPONSE_REQUESTED"]
        for request_id, posted in threads.items():
            cycle = cycles.get(request_id) or {}
            if not cycle.get("thread"):
                done.append((finding_id, request_id))  # nothing to reply in
                continue
            owed, last = [], None
            for event in events:
                found = _REQUEST.search(event.note or "")
                request = found.group(1) if found else None
                kind = None
                if request == request_id and event.event_type in _KINDS:
                    kind = _KINDS[event.event_type]
                    if kind == "not_done":
                        kind = _declined(repo, finding_id, request, event.note)
                    if kind in _EVIDENCE and (kind == last or (
                            kind == "verified" and event.from_status == event.to_status == "COMPLETED")):
                        continue  # a newer scan repeating what the thread was told: no state change
                    last = kind
                elif event.event_type == "RESPONSE_REQUESTED" and request is not None and request == after.get(request_id):
                    kind = "rerequested"
                if kind and str(event.id) not in posted:
                    owed.append(Item(finding_id, cycle, str(event.id), kind, response._utc(event.created_at)))
            replaced = request_id in after
            if (not replaced and current.get("request_id") == request_id
                    and cycle.get("state") in ("WAITING_OWNER", "REPORT_REQUIRED")
                    and response._link_expired(cycle, now) and "expired" not in posted):
                owed.append(Item(finding_id, cycle, "expired", "expired",
                                 response._when((cycle.get("link") or {}).get("expires_at")) or now))
            if owed:
                items.extend(owed)
            elif replaced:
                done.append((finding_id, request_id))
    return items, done, sum(len(threads) for threads in registered.values())


def _check(repo, call, channel_id) -> str | None:
    """None when a reply may go to the channel now: its approval read again, then Slack's description of it. The
    refusal code otherwise. A failure that is not about this channel (429, 5xx, the token, a missing scope) is raised:
    it stops the run."""
    entry = response_channels.approved(repo).get(channel_id)
    if entry is None:
        return "RESPONSE_CHANNEL_NOT_APPROVED"
    try:
        response_channels.check(call, channel_id, entry.get("allow_public") is True, status=409)
    except response.ResponseError as exc:
        if _definite(exc.code):
            return exc.code
        raise contact.ContactError(exc.code, exc.http_status) from None
    except contact.ContactError as exc:
        if _definite(exc.code):
            return exc.code
        raise
    return None


def _thread_error(repo, finding_id, request_id, code) -> None:
    """Keep the thread's last refusal on its request (None once a reply goes out again), written only on a change.
    Neither the state nor the version changes, and no audit row is written: thread posts are not response events."""
    if response._row(repo, response._key(finding_id, request_id)).get("thread_error") == code:
        return
    with response._locked(repo) as bound:
        value = response._row(bound, response._key(finding_id, request_id))
        if not value or value.get("thread_error") == code:
            return
        value = {**value, "thread_error": code}
        bound.put_setting(response._key(finding_id, request_id), value, ACTOR)
        head, current = response._current(bound, finding_id)
        if current.get("request_id") == request_id:
            bound.put_setting(response.HEAD_PREFIX + finding_id, {**head, "current": value}, ACTOR)


def _commit(repo, item: Item, code) -> None:
    """The thread's cursor moves past this state change: after its reply went out or was refused for good."""
    key = _thread_key(item.finding_id, item.cycle["request_id"])
    posted = list(response._row(repo, key).get("posted") or [])
    repo.put_setting(key, {"posted": [*posted, item.key]}, ACTOR)
    _thread_error(repo, item.finding_id, item.cycle["request_id"], code)


def sweep(repo, settings, *, now=None, clock=time.monotonic, http_client_factory=None) -> int:
    """One minute's replies (at most MAX_POSTS tried, each with its own channel check, within BUDGET_SECONDS): how
    many went out. While any thread is open the minute is claimed and its state kept even when nothing is owed."""
    now = now or dt.datetime.now(dt.UTC)
    items, done, threads = _items(repo, now)
    if not threads or not repo.claim_slot(SWEEP_KEY, int(now.timestamp()) // 60, ACTOR):
        return 0
    for finding_id, request_id in done:  # nothing left to say: retired here, dropped by the response sweep
        repo.put_setting(_thread_key(finding_id, request_id), {"retired": True}, ACTOR)
    deadline = clock() + BUDGET_SECONDS
    posted, settled, error = 0, 0, None
    try:
        if items:
            with contact.slack_session(repo, settings, http_client_factory=http_client_factory) as call:
                for tried, item in enumerate(items):
                    if tried >= MAX_POSTS or clock() > deadline:
                        break
                    thread = item.cycle["thread"]
                    code = _check(repo, call, thread["channel_id"])  # never a decision carried over from another post
                    if code is None:
                        words = TEXTS[item.cycle.get("locale") if item.cycle.get("locale") in TEXTS else "ko"]
                        try:
                            call("chat.postMessage", json={"channel": thread["channel_id"], "thread_ts": thread["ts"],
                                                           "text": words[item.kind], "link_names": False,
                                                           "unfurl_links": False, "unfurl_media": False})
                            posted += 1
                        except contact.ContactError as exc:
                            if not _definite(exc.code):
                                raise
                            code = exc.code
                    _commit(repo, item, code)
                    settled += 1
    except contact.ContactError as exc:
        error = exc.code  # not answering, or nothing would go: the rest waits for the next minute
    left = items[settled:]  # each item is settled in order, or the run stops at it
    repo.put_setting(STATE_KEY, {"at": now.isoformat(), "posted": posted, "error": error, "owed": len(left),
                                 "owed_since": min(item.at for item in left).isoformat() if left else None}, ACTOR)
    return posted


def alerts(repo, *, now=None) -> list[dict]:
    """The operations alert for this job, from its last state and the open threads only (no Slack, no audit read).
    ``RESPONSE_THREADS_STOPPED``: threads are open and no run came for over ALERT_AFTER (no mixed worker or control
    process runs the job, or the job fails before it can say why). ``RESPONSE_THREADS_FAILING``: runs come, but a reply
    has been owed for over ALERT_AFTER (Slack not answering, the bot's token or a scope gone, contact delivery off)."""
    now = now or dt.datetime.now(dt.UTC)
    state = (repo.get_setting(STATE_KEY) or {}).get("value") or {}
    ran = response._when(state.get("at"))
    base = {"resource_type": "response_threads", "resource_id": "progress",
            "last_run_at": ran.isoformat() if ran else None}
    if ran is None or now - ran > ALERT_AFTER:
        opened = [response._utc(row["updated_at"]) for row in repo.list_settings(THREAD_PREFIX)
                  if not (row.get("value") or {}).get("retired") and row.get("updated_at")]
        if not opened:
            return []  # nothing open: no run is owed
        # A thread opened after the last run waited only since it opened (an open thread's row is written only then
        # and by runs).
        since = max(ran, min(opened)) if ran else min(opened)
        if now - since <= ALERT_AFTER:
            return []
        return [{"code": "RESPONSE_THREADS_STOPPED", **base, "open_threads": len(opened),
                 "failing_since": since.isoformat()}]
    since = response._when(state.get("owed_since"))
    if not state.get("owed") or since is None or now - since <= ALERT_AFTER:
        return []
    return [{"code": "RESPONSE_THREADS_FAILING", **base, "owed_replies": state["owed"],
             "failing_since": since.isoformat(), "error_codes": [state["error"]] if state.get("error") else []}]
