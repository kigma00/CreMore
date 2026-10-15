"""Slack alerts for new detections, delivered from the SIEM outbox (destination ``cremore.slack-alerts``).

Every new finding, new location and reappearance is written to the outbox in the transaction that records it, so
nothing is missed here: an event is acknowledged only after Slack accepted its message (at least once: an answer lost
on the way can repeat a message), and a failed message is retried with backoff and never held. An event no alert needs
is acknowledged without a message: other types in bulk, and one by one a type or severity filtered out or a false
positive, but never on a state that is not settled yet (a location not scored yet, a false-positive closure a learned
profile may still reopen): that alert waits a few seconds. Turning alerts on skips the kept history and what happened
while they were off, never an alert still owed. Messages are built from the database at send time and paced to one per
1.1 s across worker replicas, and a 429 cools every replica down for as long as Slack asked. A message Slack refuses for
its content is split, shortened, then retried alone while the rest goes on; any other failure stops the pass. A pass
reads only new events (each given a delivery row in one statement: from the cursor, LAG back, every FULL_READ_SECONDS;
between, from just before the newest event the last read saw) and the rows still owed through their index, so neither
a long kept history, a burst nor a long outage is read every second; once an hour the whole history is checked for an
event written later than LAG. A pass stops trying before its lease could run out. The webhook address, the bot token
and Slack's answers are never logged or stored: only fixed codes are.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import logging
import math
import time
import uuid

import httpx

from cremore.alerts import messages, setup
from cremore.db.scan_state import LOCATION_FIELDS, SEVERITY_RANK, exposure_location
from cremore.db.scan_store import ScanStore
from cremore.domain.models import Exposure
from cremore.governance import contact
from cremore.governance.usage_sources import recent_sources
from cremore.http_client import HTTPResponseTooLarge, bounded_request
from cremore.siem.contract import DeliveryError
from cremore.siem.outbox import SiemOutbox, safe_code

logger = logging.getLogger("cremore.alerts")
# httpx logs every request's URL at INFO and a webhook URL is a secret: quiet it wherever alerts are sent from, as
# every CreMore process entry point already does.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

DESTINATION = "cremore.slack-alerts"
# One message per PACING_SECONDS for the whole installation, shared by every worker replica through the database.
PACING_KEY = hashlib.sha256(b"cremore:slack-alerts").hexdigest()
PACING_SECONDS = 1.1
MAX_WAIT_SECONDS = 2.5  # the longest a pass waits for the slot; a longer cooldown (Slack's 429) ends the pass instead
BATCH = 100
SINGLE_UP_TO, DIGEST_SIZE = 3, 15
LEASE_SECONDS = 300  # outlasts a pass: it sends a few paced messages, each bounded by TIMEOUT
TIMEOUT = 10.0
# A pass tries nothing after this long, so the answer to its last message (two tries, each waiting for the slot and
# Slack) comes while its lease still holds: an acknowledgement never misses its lease and resends.
PASS_SECONDS = LEASE_SECONDS - (TIMEOUT + MAX_WAIT_SECONDS + 30)
MAX_RESPONSE_BYTES = 4096
STATE_KEY = "detection_alerts:history"  # the turn-on handled, the cursor, the last reads and the last sweep
LAG = _dt.timedelta(minutes=5)  # how late a write may commit (or its host's clock run) and still be read in order
# Turn-on and turn-off boundaries move this far toward sending. An event's time is the writing process's clock (not
# the database's, on PostgreSQL too), which may run up to LAG ahead: an extra alert is better than a missed one.
SKEW = LAG
FULL_READ_SECONDS = 30  # how often a pass reads every event from the cursor again; between, only the new ones
OVERLAP = _dt.timedelta(seconds=5)  # a quick read starts this long before the newest event the last read saw
SWEEP_SECONDS = 3600  # how often the whole kept history is checked for a write later than LAG
PLACES_READ = 1000  # the most open locations of a credential an alert reads to count them; past it, "1,000+"
SETTLE_SECONDS = 60  # how long an alert waits for its location's score; past it, it goes out unscored
FP_SETTLE_SECONDS = 10  # how long a false-positive closure must stand: a learned profile reopens within moments
DEFER_SECONDS = 2
RATE_LIMITED = ("DELIVERY_RATE_LIMITED", "SLACK_RATE_LIMITED", "SLACK_RATELIMITED")
# Refusals of one message (its blocks, text or size; a webhook's 400, 413 or 422 is DELIVERY_REJECTED): it is split,
# shortened, then retried alone while the rest goes on. Any other failure (a 5xx, Slack's internal_error, the token,
# the channel, the network, a code not known here) is one every message would meet: the pass stops and the rest waits.
ONE_MESSAGE = frozenset({
    "DELIVERY_REJECTED", "SLACK_INVALID_BLOCKS", "SLACK_INVALID_BLOCKS_FORMAT", "SLACK_MSG_TOO_LONG",
    "SLACK_MSG_BLOCKS_TOO_LONG", "SLACK_NO_TEXT", "SLACK_TOO_MANY_ATTACHMENTS", "SLACK_INVALID_ARGUMENTS",
})
_ACTOR = "system:alerts"
_TRIGGERS = ("RESCAN", "SCHEDULE", "EVENT", "POLICY_SWEEP", "RESUME")
_CLOSED = ("REMOVED", "FALSE_POSITIVE")  # a location in either state is not counted as open
_sleep = time.sleep


class _Cooling(DeliveryError):
    """The shared slot is cooling down after a 429: nothing was sent."""


def deliver_pending(repo, settings, *, http_client_factory=None, now=None, stop=None) -> dict:
    """One pass, about every second; nothing is claimed while alerts are off. Gives every event since the cursor a
    row in one statement (acknowledged unsent unless an alert may need it), claims up to BATCH rows still owed, decides
    each from the database, sends the alerts (a message each up to three, digests of at most fifteen beyond) and records
    how the pass went. ``stop`` (true once the process is shutting down) claims nothing and ends a pass after the
    message in hand, putting the rest back at once instead of leaving it claimed until its lease runs out."""
    value = setup.config(repo)
    result = {"enabled": value["enabled"], "claimed": 0, "skipped": 0, "deferred": 0, "messages": 0, "delivered": 0,
              "retried": 0, "error_code": None}
    if not value["enabled"] or (stop is not None and stop()):
        return result
    now = now or _dt.datetime.now(_dt.UTC)
    outbox, store = SiemOutbox(repo), ScanStore(repo)
    state = _settle_history(repo, outbox, value, now)
    read_moved = _read(outbox, state, value, now)
    started = outbox.clock()
    claimed = outbox.claim_owed(DESTINATION, limit=BATCH, lease_seconds=LEASE_SECONDS)
    result["claimed"] = len(claimed)
    rows, read, console = _findings(repo, claimed), _reader(repo), contact.channels(repo)["console_url"]
    due = []
    for row in claimed:
        try:
            verdict, item = _decide(rows, read, value, row["event"], console, now)
        except Exception as exc:  # noqa: BLE001 -- one event that cannot be read waits alone; the rest goes on
            logger.warning("SLACK_ALERT_UNREADABLE kind=%s", type(exc).__name__)
            result["retried"] += outbox.retry(DESTINATION, row["event"]["event_id"], row["token"],
                                              error_code="DELIVERY_FAILED", delay_seconds=_backoff(row, None))
            continue
        if verdict == "ack":
            result["skipped"] += outbox.acknowledge(DESTINATION, row["event"]["event_id"], row["token"])
        elif verdict == "defer":
            result["deferred"] += outbox.defer(DESTINATION, row["event"]["event_id"], row["token"],
                                               delay_seconds=DEFER_SECONDS)
        else:
            due.append((row, item))
    # A severity rise this pass already announces through one of its locations' own alerts, at least as severe as the
    # finding is now, needs no second message.
    announced = {}
    for _row, item in due:
        if item["kind"] != "finding.severity_raised":
            announced[item["finding_id"]] = max(announced.get(item["finding_id"], -1), _rank(item["severity"]))
    for pair in [pair for pair in due if pair[1]["kind"] == "finding.severity_raised"
                 and announced.get(pair[1]["finding_id"], -1) >= _rank(pair[1]["severity"])]:
        due.remove(pair)
        result["skipped"] += outbox.acknowledge(DESTINATION, pair[0]["event"]["event_id"], pair[0]["token"])
    groups = ([due[start:start + DIGEST_SIZE] for start in range(0, len(due), DIGEST_SIZE)]
              if len(due) > SINGLE_UP_TO else [[pair] for pair in due])
    outcome = _send_all(repo, settings, value, outbox, store, groups, result, http_client_factory, started, stop)
    outbox.record_status(DESTINATION, outcome, error_code=result["error_code"])
    _advance(repo, state, now, read_moved)
    return result


def send_test(repo, settings, *, http_client_factory=None) -> dict:
    """One test message with the saved setup, sent now from the calling process (the API), through the same shared
    slot and cooldown as the alerts: {delivered, error_code}. A refusal of its content is tried once more without the
    button, as an alert's short form is: a console address Slack refuses in a button (localhost, an IP) fails no alert."""
    value, store = setup.config(repo), ScanStore(repo)
    console = contact.channels(repo)["console_url"]
    for buttons in (True, False):
        if _wait_turn(store):
            return {"delivered": False, "error_code": "DELIVERY_RATE_LIMITED"}
        payload = messages.trial_message(console, language=value["language"], buttons=buttons)
        try:
            _send(repo, settings, value, payload, http_client_factory)
        except DeliveryError as exc:
            if exc.code in RATE_LIMITED:
                _cool(store, exc.retry_after_seconds)
            if buttons and console and exc.code in ONE_MESSAGE:
                continue
            return {"delivered": False, "error_code": safe_code(exc.code)}
        return {"delivered": True, "error_code": None}


def status(repo) -> dict:
    """How delivery stands: what waits, when the worker last looked, the last success and failure. Counted from the
    rows still owed and, while alerts are on, the events since the cursor, so a long kept history is not read; nothing
    is read while alerts were never on."""
    value = setup.config(repo)
    state = (repo.get_setting(STATE_KEY) or {}).get("value") or {}
    first = _time(value.get("first_enabled_at")) or _time(value.get("enabled_at"))
    cursor = _time(state.get("cursor")) or (first - SKEW if first else None)
    keys = ("pending", "oldest_pending_at", "last_seen_at", "last_success_at", "last_failure_at", "last_error_code",
            "consecutive_failures")
    if cursor is None:
        return dict.fromkeys(keys) | {"pending": 0, "consecutive_failures": 0}
    now = _dt.datetime.now(_dt.UTC)
    row = SiemOutbox(repo).destination_status(DESTINATION, since=min(cursor, now - LAG) if value["enabled"] else now)
    return {key: row[key] for key in keys}


def _settle_history(repo, outbox, value, now) -> dict:
    """Where this pass starts, kept in STATE_KEY. Once per turning on, mark delivered (unsent) the history before
    alerts were first on and what happened while they were last off, each boundary moved SKEW toward sending (an
    alert owed from a time they were on is never skipped). Once an hour, and at once when the last sweep looks to be in
    the future (a clock that ran ahead), move the cursor back to an event with no row: one written later than LAG
    allowed."""
    state = dict((repo.get_setting(STATE_KEY) or {}).get("value") or {})
    stamp, changed = value.get("enabled_at") or "", False
    if state.get("enabled_at") != stamp:
        on = _time(stamp) or now
        first, off = _time(value.get("first_enabled_at")) or on, _time(value.get("disabled_at"))
        if "enabled_at" not in state:  # never settled: the history before alerts were first on (no sweep due now)
            outbox.skip_before(DESTINATION, first - SKEW)
            state["cursor"], state["swept_at"] = (first - SKEW).isoformat(), now.isoformat()
        if off is not None and off > first and off + SKEW < on - SKEW:
            outbox.skip_before(DESTINATION, on - SKEW, since=off + SKEW)
        state["enabled_at"], changed = stamp, True
        state.pop("full_at", None)
    if _time(state.get("cursor")) is None:  # never set, or not a time: read from the first turn-on again
        state["cursor"], changed = ((_time(value.get("first_enabled_at")) or now) - SKEW).isoformat(), True
        state.pop("full_at", None)
    swept = _time(state.get("swept_at"))
    if swept is None or not 0 <= (now - swept).total_seconds() < SWEEP_SECONDS:
        missing = outbox.oldest_unclaimed(DESTINATION)
        if missing is not None and missing < _time(state["cursor"]):
            state["cursor"] = missing.isoformat()
            state.pop("full_at", None)
        state["swept_at"], changed = now.isoformat(), True
    if changed:
        repo.put_setting(STATE_KEY, state, _ACTOR)
    return state


def _read(outbox, state, value, now) -> bool:
    """Give the events since the last read a delivery row: owed when an alert may need it, else delivered unsent. A full
    read starts at the cursor (LAG back): every FULL_READ_SECONDS, and when a turn-on or the sweep moved the cursor. A
    quick read in between starts OVERLAP before the newest event the last read saw, so a burst is read once, not every
    second for LAG. An event that commits more than OVERLAP late is the next full read's, more than LAG late the hourly
    sweep's. True when what the next pass starts from changed."""
    start, full_at, newest = min(_time(state["cursor"]), now - LAG), _time(state.get("full_at")), _time(state.get("newest"))
    # A full read stamped up to LAG ahead came from a replica whose clock runs ahead: still recent, or replicas a little
    # apart would each see the other's stamp as stale or future and read in full on every pass.
    full = full_at is None or newest is None or not (
        -LAG.total_seconds() <= (now - full_at).total_seconds() < FULL_READ_SECONDS)
    seen = outbox.skip(DESTINATION, since=start if full else max(start, min(newest, now) - OVERLAP), keep=_kept(value),
                       queue_kept=True)
    if full:
        state["full_at"] = now.isoformat()
    seen = min(seen, now) if seen is not None else None  # a writer's clock running ahead never moves the reads ahead
    moved = seen is not None and (newest is None or abs((seen - newest).total_seconds()) >= OVERLAP.total_seconds())
    if moved:
        state["newest"] = seen.isoformat()
    return full or moved


def _advance(repo, state, now, changed) -> None:
    """Move the cursor up to LAG ago (every earlier event this pass could see has a row now; one committed later is the
    sweep's), or back there from a time a clock that ran ahead set. Written when it moved a minute or more, or the read
    changed where the next pass starts."""
    cursor, target = _time(state["cursor"]), now - LAG
    if (target - cursor).total_seconds() >= 60 or cursor > now:
        state["cursor"], changed = target.isoformat(), True
    if changed:
        repo.put_setting(STATE_KEY, state, _ACTOR)


def _kept(value) -> tuple:
    """The events a pass claims one by one: the alert types chosen, and severity rises while a minimum filters some
    alerts out. Every other event is acknowledged in bulk."""
    return (*((kind, None) for kind in value["events"]),
            *((("finding.updated", "ROLLUP"),) if value["min_severity"] != "INFO" else ()))


def _send_all(repo, settings, value, outbox, store, groups, result, http_client_factory, started, stop=None) -> str:
    """Send each group in turn and return how the pass went. A refusal of one message splits a digest, then tries the
    short form (its console link as text only; once that goes out, the rest of the pass goes without buttons), then
    retries that alert alone while the rest goes on. Any other failure stops the pass and all that is left waits. Past
    PASS_SECONDS since the claim, or once the process is stopping, what is left goes back untried for the next pass."""
    queue, outcome, buttons = list(groups), "IDLE", True
    while queue:
        if (outbox.clock() - started).total_seconds() > PASS_SECONDS or (stop is not None and stop()):
            for row, _item in (pair for group in queue for pair in group):
                result["deferred"] += outbox.defer(DESTINATION, row["event"]["event_id"], row["token"], delay_seconds=0)
            break
        group = queue.pop(0)
        try:
            _attempt(repo, settings, value, store, group, value["detail"], http_client_factory, buttons=buttons)
        except DeliveryError as exc:
            if exc.code not in ONE_MESSAGE:
                _stop(outbox, store, [group, *queue], exc, result)
                return "FAILURE"
            if len(group) > 1:
                queue[:0] = [[pair] for pair in group]
                continue
            try:  # no button: a console address Slack refuses for one (localhost, an IP) cannot fail this form too
                _attempt(repo, settings, value, store, group, "minimal", http_client_factory, buttons=False)
                refused, buttons = None, False
            except DeliveryError as again:
                if again.code not in ONE_MESSAGE:
                    _stop(outbox, store, [group, *queue], again, result)
                    return "FAILURE"
                refused = again
            if refused is not None:
                row, code = group[0][0], safe_code(refused.code)
                result["retried"] += outbox.retry(DESTINATION, row["event"]["event_id"], row["token"], error_code=code,
                                                  delay_seconds=_backoff(row, refused.retry_after_seconds))
                logger.warning("SLACK_ALERT_REFUSED code=%s", code)
                result["error_code"], outcome = code, "FAILURE"
                continue
        result["messages"] += 1
        outcome = "SUCCESS" if outcome == "IDLE" else outcome
        for row, _item in group:
            result["delivered"] += outbox.acknowledge(DESTINATION, row["event"]["event_id"], row["token"])
    return outcome


def _attempt(repo, settings, value, store, group, detail, http_client_factory, *, buttons=True) -> None:
    """Render and send one message in the installation's next slot; DeliveryError when it does not go out."""
    try:
        payload = messages.render([item for _row, item in group], detail=detail, language=value["language"],
                                  buttons=buttons)
    except Exception as exc:  # noqa: BLE001 -- a message that cannot be built is refused like one Slack refuses
        logger.warning("SLACK_ALERT_RENDER_FAILED kind=%s", type(exc).__name__)
        raise DeliveryError("DELIVERY_REJECTED") from None
    wait = _wait_turn(store)
    if wait:
        raise _Cooling("DELIVERY_RATE_LIMITED", retry_after_seconds=math.ceil(wait))
    try:
        _send(repo, settings, value, payload, http_client_factory)
    except DeliveryError:
        raise
    except Exception as exc:  # noqa: BLE001 -- only a fixed code leaves; the message is retried like a refused one
        logger.warning("SLACK_ALERT_SEND_FAILED kind=%s", type(exc).__name__)
        raise DeliveryError("DELIVERY_FAILED") from None


def _stop(outbox, store, left, exc, result) -> None:
    """A refusal every message would meet: the group tried waits with backoff or Slack's Retry-After, the groups not
    tried wait for the Retry-After or DEFER_SECONDS without counting an attempt (each takes its turn as the one tried,
    so backoff grows for all while the destination fails), and a 429 cools every replica's sending down."""
    code, hint = safe_code(exc.code), exc.retry_after_seconds
    tried = [] if isinstance(exc, _Cooling) else left[0]
    if code in RATE_LIMITED and not isinstance(exc, _Cooling):
        _cool(store, hint)
    for row, _item in tried:
        result["retried"] += outbox.retry(DESTINATION, row["event"]["event_id"], row["token"], error_code=code,
                                          delay_seconds=_backoff(row, hint))
    for row, _item in (pair for group in left[1 if tried else 0:] for pair in group):
        result["deferred"] += outbox.defer(DESTINATION, row["event"]["event_id"], row["token"],
                                           delay_seconds=hint or DEFER_SECONDS)
    logger.warning("SLACK_ALERT_FAILED code=%s events=%d", code, sum(len(group) for group in left))
    result["error_code"] = code


def _cool(store, hint) -> None:
    store.request_delay(PACING_KEY, PACING_SECONDS, cooldown=min(hint if hint is not None else 10, 3600))


def _backoff(row, hint) -> int:
    delay = min(3600, 5 * 2 ** min(row["attempts"], 10))
    return max(delay, hint) if hint is not None else delay


def _wait_turn(store) -> float:
    """Take the installation's next message slot, waiting while another message (any replica's) holds it. Returns
    the wait left instead when it is longer than MAX_WAIT_SECONDS (a 429 cooldown), 0 once the slot is taken."""
    while (delay := store.request_delay(PACING_KEY, PACING_SECONDS)) > 0:
        if delay > MAX_WAIT_SECONDS:
            return delay
        _sleep(min(delay, PACING_SECONDS))
    return 0.0


def _send(repo, settings, value, payload, http_client_factory) -> None:
    """Hand one message to Slack, or raise DeliveryError with a fixed code (and Slack's Retry-After)."""
    if value["transport"] == "bot":
        if not value["channel"]:
            raise DeliveryError("ALERTS_NOT_CONFIGURED")
        try:
            contact.post_slack(repo, settings, value["channel"], payload, http_client_factory=http_client_factory)
        except contact.ContactError as exc:
            raise DeliveryError(exc.code, retry_after_seconds=exc.retry_after) from None
        return
    try:
        url = setup.opened_webhook(settings, value)
    except setup.AlertSetupError as exc:
        raise DeliveryError(exc.code) from None
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    try:
        with (http_client_factory() if http_client_factory else httpx.Client(follow_redirects=False)) as client:
            response = bounded_request(client, "POST", url, content=body, timeout=TIMEOUT, follow_redirects=False,
                                       headers={"Content-Type": "application/json; charset=utf-8"},
                                       max_response_bytes=MAX_RESPONSE_BYTES)
    except HTTPResponseTooLarge:
        raise DeliveryError("RESPONSE_TOO_LARGE") from None
    except Exception as exc:  # noqa: BLE001 -- transport errors can carry the webhook address
        raise DeliveryError("DELIVERY_TIMEOUT" if isinstance(exc, httpx.TimeoutException | TimeoutError)
                            else "HTTP_DELIVERY_FAILED") from None
    status_code = response.status_code
    if status_code == 429:
        headers = getattr(response, "headers", None) or {}
        raise DeliveryError("DELIVERY_RATE_LIMITED", retry_after_seconds=contact.retry_after(headers.get("retry-after")))
    if status_code in (401, 403):
        raise DeliveryError("AUTH_FAILED")
    if status_code in (400, 413, 422):  # this message's content (invalid_blocks, too long): not the destination
        raise DeliveryError("DELIVERY_REJECTED")
    if status_code >= 500:
        raise DeliveryError("SINK_UNAVAILABLE")
    if status_code != 200:  # 404 no_service, 410 channel_is_archived: the webhook itself
        raise DeliveryError("HTTP_STATUS_REJECTED")
    if bytes(getattr(response, "content", b"") or b"").strip() != b"ok":
        raise DeliveryError("INVALID_RESPONSE")


def _findings(repo, claimed) -> dict:
    """Each claimed event's finding and credential, and the exposures its alert names (the event's own location and the
    finding's primary one), read by id for the whole pass: never every location a credential has."""
    ids, named = [], set()
    for row in claimed:
        try:
            ids.append(uuid.UUID(str(row["event"]["finding"]["id"])))
            named.add(uuid.UUID(str((row["event"].get("exposure") or {})["id"])))
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
    if not ids:
        return {}
    found = repo.findings_with_exposures(ids, exposure_limit=0)
    exposures = _exposures(repo, named | {finding.primary_exposure_id for finding, _credential, _none in found})
    return {finding.id: (finding, credential, exposures) for finding, credential, _none in found}


def _exposures(repo, ids) -> dict:
    """Exposures by id, in one read."""
    if getattr(repo, "engine", None) is None:
        with repo._lock:
            return {key: repo.exposures[key] for key in ids if key in repo.exposures}
    from sqlalchemy import select

    from cremore.db.schema import exposures
    with repo.engine.connect() as conn:
        return {row["id"]: Exposure.model_validate(dict(row))
                for row in conn.execute(select(exposures).where(exposures.c.id.in_(list(ids)))).mappings()}


def _open_places(repo, credential_id) -> tuple[set, bool, bool, dict]:
    """A credential's open locations (not removed, not a false positive) from at most PLACES_READ of its rows: the
    places, whether one is not scored yet, whether it has more rows than were read, and the (first seen, id) of the
    rows at each place (rows stay per connection or account; rows sharing a place are one location)."""
    if getattr(repo, "engine", None) is None:
        with repo._lock:
            rows = [(row.id, row.first_seen_at, exposure_location(row), row.severity) for row in repo.exposures.values()
                    if row.credential_id == credential_id and row.status not in _CLOSED][:PLACES_READ + 1]
    else:
        from sqlalchemy import select

        from cremore.db.schema import exposures
        with repo.engine.connect() as conn:
            rows = [(row["id"], row["first_seen_at"], exposure_location(row), row["severity"]) for row in conn.execute(
                select(*(exposures.c[name] for name in ("id", "first_seen_at", *LOCATION_FIELDS, "metadata", "severity")))
                .where(exposures.c.credential_id == credential_id, exposures.c.status.not_in(_CLOSED)).limit(
                PLACES_READ + 1)).mappings()]
    holders = {}
    for ident, seen, place, _severity in rows[:PLACES_READ]:
        holders.setdefault(place, []).append((seen, str(ident)))
    return (set(holders), any(row[3] == "UNKNOWN" for row in rows), len(rows) > PLACES_READ, holders)


def _reader(repo):
    """Reads for one pass, each asked once (a burst names the same scan, connection and credential): a repository
    method's name, or a function of (repo, key)."""
    seen = {}

    def read(method, key):
        if key is None:
            return None
        if (method, key) not in seen:
            seen[(method, key)] = method(repo, key) if callable(method) else getattr(repo, method)(key)
        return seen[(method, key)]

    return read


def _decide(rows, read, value, event, console, now) -> tuple[str, dict | None]:
    """('send', what the alert says) or ('ack' | 'defer', None), from the database now. A state that is not settled
    yet never decides a skip: a location not scored yet, or a false-positive closure younger than a learned profile
    takes to reopen, waits a few seconds."""
    kind, minimum = event.get("event_type"), value["min_severity"]
    raised = kind == "finding.updated" and event.get("change") == "ROLLUP" and minimum != "INFO"
    if not raised and (kind not in setup.EVENTS or kind not in value["events"]):
        return "ack", None
    try:
        found = rows.get(uuid.UUID(str(event["finding"]["id"])))
    except (KeyError, TypeError, ValueError, AttributeError):
        return "ack", None
    if found is None:
        return "ack", None
    finding, credential, exposures = found
    age = _age(event, now)
    if finding.workflow_status == "FALSE_POSITIVE":  # measured from the closure, or the event when its time is unknown
        stood = (now - finding.resolved_at).total_seconds() if finding.resolved_at else age
        return ("defer", None) if stood < FP_SETTLE_SECONDS else ("ack", None)
    previous = (event.get("finding") or {}).get("previous_severity") if raised else None
    if raised:
        # A finding that rose from below the minimum to meet it: its own alerts were filtered out until now. While one
        # of its locations is not scored yet, that location's own alert may be what announces the rise: wait.
        if previous == "UNKNOWN" or not _rank(previous) < SEVERITY_RANK[minimum] <= _rank(finding.severity):
            return "ack", None
        if age < SETTLE_SECONDS and read(_open_places, finding.credential_id)[1]:
            return "defer", None
        exposure, severity = exposures.get(finding.primary_exposure_id), finding.severity
    else:
        exposure = exposures.get(_uuid((event.get("exposure") or {}).get("id")))
        if exposure is not None and exposure.status == "FALSE_POSITIVE":
            return "ack", None
        severity = exposure.severity if kind != "finding.created" and exposure is not None else finding.severity
        if severity == "UNKNOWN":
            if age < SETTLE_SECONDS:
                return "defer", None
            severity = finding.severity  # never scored in time: it goes out unfiltered, with the finding's severity
        elif not _due(severity, minimum):
            return "ack", None
    codes, here = event.get("credential") or {}, {exposure_location(exposure)} if exposure else set()
    places, _unscored, more, holders = read(_open_places, finding.credential_id)
    # A place is one location whichever connection or account reads it: only its first open row announces it.
    held = holders.get(exposure_location(exposure), []) if exposure is not None else []
    if kind == "finding.location_added" and held and min(held)[1] != str(exposure.id):
        return "ack", None
    job = read("get_job", exposure.last_source_scan_id or exposure.last_scan_id) if exposure else None
    trigger = (job.payload or {}).get("trigger", "BASELINE") if job else None
    sources, sources_total, sources_more = (recent_sources(credential, messages.SOURCES_SHOWN) if credential
                                            else ([], 0, False))
    return "send", {
        "kind": "finding.severity_raised" if raised else kind, "severity": severity, "previous_severity": previous,
        "event_id": str(event.get("event_id")), "finding_id": str(finding.id), "credential_id": str(finding.credential_id),
        "provider": credential.provider if credential else codes.get("provider"),
        "credential_type": credential.credential_type if credential else codes.get("credential_type"),
        "status": credential.credential_status if credential else None,
        "source_type": exposure.source_type if exposure else (event.get("exposure") or {}).get("source_type"),
        "connection": getattr(read("get_connection", exposure.source_connection_id)
                              or read("get_aws_account", exposure.aws_account_id), "name", None) if exposure else None,
        "resource": exposure.resource_name if exposure else None,
        "location": exposure.location if exposure else None,
        "line": exposure.line_number if exposure else None,
        "first_seen": exposure.first_seen_at if exposure else finding.created_at,
        "trigger": "MANUAL" if trigger == "BASELINE" else trigger if trigger in _TRIGGERS else None,
        # A change event's run records where it came from (feed, queue or webhook) as its requested_by.
        "origin": (job.payload or {}).get("requested_by") if job and trigger == "EVENT" else None,
        "others": len(places - here), "others_more": more,
        "sources": sources, "sources_total": sources_total, "sources_more": sources_more,
        "link": f"{console}/?view=exposed&id=credential%3A{finding.credential_id}" if console else None,
    }


def _due(severity, minimum) -> bool:
    """INFO lets every alert through; otherwise the severity meets the minimum (NONE never does)."""
    return minimum == "INFO" or _rank(severity) >= SEVERITY_RANK[minimum]


def _rank(severity) -> int:
    return SEVERITY_RANK.get(severity, -1)


def _uuid(value) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None


def _age(event, now) -> float:
    """Seconds since the event was written; an unreadable time decides now."""
    try:
        return (now - _dt.datetime.fromisoformat(event["occurred_at"])).total_seconds()
    except (KeyError, TypeError, ValueError):
        return float("inf")


def _time(value) -> _dt.datetime | None:
    try:
        stamp = _dt.datetime.fromisoformat(value) if isinstance(value, str) and value else None
    except ValueError:
        return None
    return stamp.replace(tzinfo=_dt.UTC) if stamp is not None and stamp.tzinfo is None else stamp
