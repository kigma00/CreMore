"""Slack detection alerts from the SIEM outbox, against a fake Incoming Webhook and a fake Slack Web API: nothing is
claimed while alerts are off, turning them on skips the history and the time off but never an owed alert, every alert
event is acknowledged exactly once and only after Slack accepted its message, a refusal every message would meet stops
the pass (a 429 cools every replica down) while a refusal of one message holds back nothing else, what needs no alert
is acknowledged without a message but never on unsettled state, and neither the webhook address nor the token reaches
a log or the outbox."""

import datetime as dt
import json
import logging
import os
import time
import uuid
from collections import Counter
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import update

from cremore.alerts import delivery, setup
from cremore.config import Settings
from cremore.db import task_store
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.scan_store import ScanStore
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import Connection, Credential, Exposure, ScanJob
from cremore.governance import contact
from cremore.governance.contact_test import TOKEN, Slack
from cremore.scanning.learned_fp import RESOLUTION_PREFIX
from cremore.siem import outbox
from cremore.siem.outbox import SiemOutbox

SETTINGS = Settings(FINGERPRINT_KEY="ab" * 32)
# Built at run time: nothing secret-shaped sits in the source.
WEBHOOK = "https://hooks.slack.com/services/T0ABC1234/B0ABC5678/" + "k" * 24


@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def repo(request):
    if request.param == "memory":
        yield InMemoryRepository()
        return
    if request.param == "postgres":
        yield request.getfixturevalue("pg")[1]
        return
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    yield SqlRepository(engine)
    engine.dispose()


@pytest.fixture
def clock(monkeypatch):
    """The outbox's and the pacing's clock, moved by hand; a paced wait moves it instead of sleeping."""
    state = SimpleNamespace(now=dt.datetime.now(dt.UTC), slept=[])

    def tick(seconds):
        state.now += dt.timedelta(seconds=seconds)

    def sleep(seconds):
        state.slept.append(round(seconds, 3))
        tick(seconds + 1e-6)  # past the slot, never short of it by a float rounding

    monkeypatch.setattr(outbox, "_clock", lambda conn=None: state.now)
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: state.now)
    monkeypatch.setattr(delivery, "_sleep", sleep)
    state.tick = tick
    return state


@pytest.fixture
def acks(monkeypatch):
    """Every one-by-one acknowledgement that took, by event id (bulk acknowledgements of non-alerts are not here)."""
    taken = []
    original = SiemOutbox.acknowledge

    def acknowledge(self, destination, event_id, token):
        done = original(self, destination, event_id, token)
        if done and destination == delivery.DESTINATION:
            taken.append(event_id)
        return done

    monkeypatch.setattr(SiemOutbox, "acknowledge", acknowledge)
    return taken


class Hook:
    """A fake Slack Incoming Webhook: records each message and answers in turn (then 200 "ok")."""

    def __init__(self, *answers):
        self.answers, self.sent = list(answers), []

    def __call__(self, request):
        assert (request.method, request.url.host, request.url.path) == ("POST", "hooks.slack.com",
                                                                       "/services/T0ABC1234/B0ABC5678/" + "k" * 24)
        self.sent.append(json.loads(request.content))
        answer = self.answers.pop(0) if self.answers else (200, "ok", {})
        if isinstance(answer, Exception):
            raise answer
        status, body, headers = answer
        return httpx.Response(status, text=body, headers=headers)

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self))


class Picky(Hook):
    """Slack refusing (HTTP 400 invalid_blocks) every message that names one of ``refused``."""

    def __init__(self, *refused):
        super().__init__()
        self.refused = refused

    def __call__(self, request):
        body = json.loads(request.content)
        self.sent.append(body)
        bad = any(word in json.dumps(body) for word in self.refused)
        return httpx.Response(400 if bad else 200, text="invalid_blocks" if bad else "ok")


class Slow(Picky):
    """Picky, answering each request ``latency`` seconds later on the outbox's clock."""

    def __init__(self, clock, latency, *refused):
        super().__init__(*refused)
        self.clock, self.latency = clock, latency

    def __call__(self, request):
        self.clock.tick(self.latency)
        return super().__call__(request)


def backdate(repo, finding, when):
    """Stamp a finding's finding.created event earlier, as a slow commit or a writer's clock running behind would."""
    if isinstance(repo, InMemoryRepository):
        event, = [item for item in repo.siem_events.values()
                  if item["event_type"] == "finding.created" and item["finding"]["id"] == str(finding.id)]
        event["occurred_at"] = when.isoformat()
        return
    from cremore.db.schema import siem_events

    with repo.engine.begin() as conn:
        conn.execute(update(siem_events).where(siem_events.c.finding_id == finding.id).values(occurred_at=when))


def found(repo, label, severity="HIGH", **exposure):
    credential = repo.upsert_credential(Credential(
        fingerprint="synthetic-fingerprint-" + label, credential_type="GITHUB_TOKEN", provider="github",
        identifier="private-identifier-" + label, identifier_hint="ghp_masked-hint-" + label))
    row = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="github", resource_name="acme/" + label,
                                        location=f"src/{label}.py", line_number=3, severity=severity,
                                        redacted_line="private redacted line", **exposure))
    return credential, row, repo.upsert_finding(credential.id, row.id, severity)


def enable(repo, **body):
    setup.save(repo, SETTINGS, {"webhook_url": WEBHOOK, "enabled": True, **body}, "ada")


def deliver(repo, client=None, *, now=None):
    """A pass; by default two minutes on, when every event has settled (scored, closures standing)."""
    return delivery.deliver_pending(repo, SETTINGS, http_client_factory=client,
                                    now=now or dt.datetime.now(dt.UTC) + dt.timedelta(minutes=2))


def young():
    return dt.datetime.now(dt.UTC)


def apart():
    time.sleep(0.03)  # event times come from the wall clock, which ticks in milliseconds on some hosts


def headers(payload) -> str:
    return payload["blocks"][0]["text"]["text"]


def sent_text(hook) -> str:
    return json.dumps(hook.sent, ensure_ascii=False)


def mark_exposure_false_positive(repo, exposure_id):
    if isinstance(repo, InMemoryRepository):
        repo.exposures[exposure_id].status = "FALSE_POSITIVE"
        return
    from cremore.db.schema import exposures

    with repo.engine.begin() as conn:
        conn.execute(update(exposures).where(exposures.c.id == exposure_id).values(status="FALSE_POSITIVE"))


def test_nothing_is_claimed_while_alerts_are_off(repo, clock):
    _credential, _row, finding = found(repo, "off")
    setup.save(repo, SETTINGS, {"webhook_url": WEBHOOK}, "ada")  # saved, not turned on
    hook = Hook()
    assert deliver(repo, hook.client) == {"enabled": False, "claimed": 0, "skipped": 0, "deferred": 0, "messages": 0,
                                          "delivered": 0, "retried": 0, "error_code": None}
    assert hook.sent == [] and not SiemOutbox(repo).status(include_internal=True)
    assert delivery.status(repo)["pending"] == 0  # never on: nothing read
    # Another destination still finds every event untouched.
    assert any(row["event"]["finding"]["id"] == str(finding.id) for row in SiemOutbox(repo).claim("other", limit=100)
               if row["event"]["event_type"] == "finding.created")


def test_turning_alerts_on_skips_the_history_and_the_time_off_but_never_an_owed_alert(repo, clock, acks, monkeypatch):
    monkeypatch.setattr(delivery, "SKEW", dt.timedelta(0))  # exact boundaries here; the margin has its own test
    _old, _row, old = found(repo, "before")
    apart()
    enable(repo, console_url="https://cremore.example.com")
    found(repo, "owed")
    failing = Hook((503, "", {}))
    assert deliver(repo, failing.client)["error_code"] == "SINK_UNAVAILABLE"  # the owed alert waits for its retry
    events = {row["event"]["finding"]["id"]: row["event"]["event_id"] for row in SiemOutbox(repo).claim("probe", limit=100)
              if row["event"]["event_type"] == "finding.created"}
    skipped, = [item for item in SiemOutbox(repo).deliveries(events[str(old.id)]) if item["destination"] == delivery.DESTINATION]
    assert skipped["attempts"] == 0 and skipped["delivered_at"] and events[str(old.id)] not in acks
    # Off: nothing is claimed. What happens while off is skipped when they are on again; the owed alert is not.
    setup.save(repo, SETTINGS, {"enabled": False}, "ada")
    found(repo, "while-off")
    assert deliver(repo, failing.client)["claimed"] == 0
    apart()
    enable(repo)
    found(repo, "again")
    clock.tick(10)
    hook = Hook()
    deliver(repo, hook.client)
    sent = sent_text(hook)
    assert "acme/owed" in sent and "acme/again" in sent and "acme/while-off" not in sent and "acme/before" not in sent
    assert delivery.status(repo)["pending"] == 0 and len(acks) == len(set(acks)) == 2


def test_detections_made_while_on_are_sent_after_a_toggle_even_if_no_pass_ran(repo, clock, monkeypatch):
    monkeypatch.setattr(delivery, "SKEW", dt.timedelta(0))
    enable(repo)
    apart()
    hook = Hook()
    deliver(repo, hook.client)  # history settled, nothing due
    for number in range(3):
        found(repo, f"while-on-{number}")  # the control loop stalls before its next pass
    apart()
    setup.save(repo, SETTINGS, {"enabled": False}, "ada")
    apart()
    enable(repo)
    deliver(repo, hook.client)
    assert sum(f"acme/while-on-{number}" in sent_text(hook) for number in range(3)) == 3


def test_the_skip_boundary_leans_toward_an_extra_alert(repo, clock):
    found(repo, "a-moment-before")  # within the clock margin of turning on
    enable(repo)
    hook = Hook()
    deliver(repo, hook.client)
    assert "acme/a-moment-before" in sent_text(hook)


def test_an_alert_is_acknowledged_only_after_slack_accepts_it(repo, clock, acks):
    enable(repo)
    found(repo, "one")
    hook = Hook((503, "", {}))
    result = deliver(repo, hook.client)
    assert (result["messages"], result["retried"], result["error_code"]) == (0, 1, "SINK_UNAVAILABLE")
    assert result["skipped"] == 0 and acks == []  # the audit row of turning alerts on went in bulk
    status = delivery.status(repo)
    assert (status["last_error_code"], status["consecutive_failures"], status["last_success_at"]) == ("SINK_UNAVAILABLE", 1, None)
    clock.tick(9)  # the first retry waits 5 * 2^1 seconds
    assert deliver(repo, hook.client)["claimed"] == 0 and len(hook.sent) == 1
    clock.tick(1)
    assert deliver(repo, hook.client)["delivered"] == 1 and len(hook.sent) == 2
    assert hook.sent[0] == hook.sent[1]  # the same alert, built again from the database
    status = delivery.status(repo)
    assert status["consecutive_failures"] == 0 and status["last_success_at"] and status["pending"] == 0
    assert deliver(repo, hook.client)["claimed"] == 0 and len(acks) == len(set(acks)) == 1


@pytest.mark.parametrize(("answer", "code", "wait"), [
    ((429, "", {"Retry-After": "120"}), "DELIVERY_RATE_LIMITED", 120),
    ((429, "", {}), "DELIVERY_RATE_LIMITED", 10),
    ((401, "invalid_token", {}), "AUTH_FAILED", 10),
    ((403, "action_prohibited", {}), "AUTH_FAILED", 10),
    ((404, "no_service", {}), "HTTP_STATUS_REJECTED", 10),
    ((503, "", {}), "SINK_UNAVAILABLE", 10),
    ((200, "invalid_payload", {}), "INVALID_RESPONSE", 10),
    ((200, "ok" * 3000, {}), "RESPONSE_TOO_LARGE", 10),
    (httpx.ConnectError("cannot reach " + WEBHOOK), "HTTP_DELIVERY_FAILED", 10),
    (httpx.ReadTimeout("timed out reading " + WEBHOOK), "DELIVERY_TIMEOUT", 10),
])
def test_refusals_every_message_would_meet_keep_the_alert_for_a_retry_and_never_hold_it(repo, clock, caplog, answer,
                                                                                         code, wait):
    caplog.set_level(logging.DEBUG)
    enable(repo)
    found(repo, "one")
    hook = Hook(answer)
    assert deliver(repo, hook.client)["error_code"] == code
    clock.tick(wait - 1)
    deliver(repo, hook.client)
    assert len(hook.sent) == 1  # Retry-After is honoured, and backoff when Slack gave none
    clock.tick(1)
    deliver(repo, hook.client)
    assert len(hook.sent) == 2 and delivery.status(repo)["pending"] == 0
    row = SiemOutbox(repo).destination_status(delivery.DESTINATION)
    assert row["held"] == 0 and row["last_error_code"] == code
    # Neither the address nor anything Slack said is kept or logged.
    stored = json.dumps([SiemOutbox(repo).status(include_internal=True), repo.get_setting(setup.KEY)], default=str)
    for secret in (WEBHOOK, "k" * 24, "invalid_token", "no_service", "invalid_payload", "action_prohibited"):
        assert secret not in stored and secret not in caplog.text


@pytest.mark.parametrize("answer", [lambda: httpx.Response(503, text="<html>Service Unavailable</html>"),
                                    lambda: httpx.Response(200, json={"ok": False, "error": "internal_error"})])
def test_a_slack_server_error_through_the_bot_stops_the_pass_at_one_request(repo, clock, answer):
    contact.save(repo, SETTINGS, {"slack": {"token": TOKEN, "allowed_channels": ["#security-alerts"]},
                                  "allowed_domains": ["example.com"]}, "ada")
    setup.save(repo, SETTINGS, {"transport": "bot", "channel": "#security-alerts", "enabled": True}, "ada")
    for number in range(20):
        found(repo, f"down-{number:02}")
    calls = []

    def client():
        return httpx.Client(transport=httpx.MockTransport(lambda request: calls.append(request) or answer()))

    result = deliver(repo, client)
    assert len(calls) == 1 and result["error_code"] in ("SLACK_UNAVAILABLE", "SLACK_INTERNAL_ERROR")
    assert (result["delivered"], result["retried"] + result["deferred"]) == (0, 20)
    clock.tick(delivery.DEFER_SECONDS)
    deliver(repo, client)
    assert len(calls) == 2  # one request a pass: no message is split or shortened for a failure of Slack's own


def test_a_rate_limit_holds_back_every_replica_for_as_long_as_slack_asked(repo, clock):
    enable(repo)
    found(repo, "first")
    hook = Hook((429, "", {"Retry-After": "120"}))
    deliver(repo, hook.client)
    found(repo, "second")
    clock.tick(2)
    second = deliver(repo, hook.client)  # another alert, a pass later: nothing goes to Slack while it cools down
    assert len(hook.sent) == 1 and (second["deferred"], second["error_code"]) == (1, "DELIVERY_RATE_LIMITED")
    assert delivery.send_test(repo, SETTINGS, http_client_factory=hook.client) == {
        "delivered": False, "error_code": "DELIVERY_RATE_LIMITED"}
    assert len(hook.sent) == 1
    clock.tick(118)
    deliver(repo, hook.client)
    assert "acme/first" in sent_text(hook) and "acme/second" in sent_text(hook) and len(hook.sent) == 3


def test_a_message_slack_refuses_holds_back_no_other_alert(repo, clock, acks):
    enable(repo)
    poison, _row, _finding = found(repo, "poison")
    apart()
    found(repo, "innocent")
    hook = Picky(str(poison.id))  # refused in every form: its credential is in the link and the IDs
    result = deliver(repo, hook.client)
    assert "acme/innocent" in json.dumps([body for body in hook.sent if str(poison.id) not in json.dumps(body)])
    assert (result["delivered"], result["retried"], result["error_code"]) == (1, 1, "DELIVERY_REJECTED")
    # Tried in full, then in the short form; then only that alert waits for its backoff.
    assert [str(poison.id) in json.dumps(body) for body in hook.sent].count(True) == 2
    clock.tick(10)
    assert deliver(repo, hook.client)["retried"] == 1 and delivery.status(repo)["pending"] == 1


def test_a_digest_slack_refuses_is_split_and_a_short_form_goes_out(repo, clock):
    enable(repo, detail="standard")
    for label in ("one", "two", "three", "poison-name"):
        found(repo, label)
    hook = Picky("acme/poison-name")  # refused only while the name is in it: the short form leaves names out
    result = deliver(repo, hook.client)
    assert result["delivered"] == 4 and result["retried"] == 0
    assert headers(hook.sent[0]) == "CreMore 새 탐지 4건"  # the digest, refused, then each alert alone
    assert len(hook.sent) == 1 + 4 + 1 and delivery.status(repo)["pending"] == 0
    assert "acme/poison-name" not in json.dumps(hook.sent[-1])


def test_what_needs_no_alert_is_acknowledged_without_a_message(repo, clock, acks):
    enable(repo, min_severity="HIGH", events=["finding.created", "finding.reappeared"])
    found(repo, "low", "LOW")  # below the minimum
    _credential, row, _kept = found(repo, "high", "HIGH")
    repo.upsert_exposure(row.model_copy(update={"id": None, "location": "src/elsewhere.py"}))  # a location: not chosen
    _c, _r, judged = found(repo, "judged", "CRITICAL")
    repo.update_finding_status(judged.id, "FALSE_POSITIVE")  # judged before the alert went out
    _c, one_place, _f = found(repo, "one-place-judged", "CRITICAL")
    mark_exposure_false_positive(repo, one_place.id)
    hook = Hook()
    result = deliver(repo, hook.client)
    assert result["messages"] == 1 and "acme/high" in sent_text(hook)
    assert result["skipped"] == result["claimed"] - 1 == 3 and delivery.status(repo)["pending"] == 0
    assert len(acks) == len(set(acks)) == result["claimed"]


def test_unsettled_state_waits_instead_of_deciding_a_skip(repo, clock):
    enable(repo, min_severity="HIGH")
    _credential, low, _finding = found(repo, "low", "LOW")
    hook = Hook()
    deliver(repo, hook.client)
    # A new location is written before it is scored: the alert waits for the score, then goes out on it.
    scored = repo.upsert_exposure(low.model_copy(update={"id": None, "location": "deploy/prod.env", "severity": "UNKNOWN"}))
    waiting = deliver(repo, hook.client, now=young())
    assert (waiting["deferred"], waiting["skipped"], waiting["messages"]) == (1, 0, 0)
    repo.set_exposure_severity(scored.id, "CRITICAL")
    clock.tick(3)
    deliver(repo, hook.client, now=young())
    assert [headers(body) for body in hook.sent] == ["[심각] 새 위치에서 발견"]
    # Never scored in time: past the wait it goes out unfiltered, with the finding's severity.
    repo.upsert_exposure(low.model_copy(update={"id": None, "location": "deploy/never-scored.env", "severity": "UNKNOWN"}))
    deliver(repo, hook.client, now=young())
    clock.tick(3)
    deliver(repo, hook.client, now=young() + dt.timedelta(seconds=delivery.SETTLE_SECONDS + 1))
    assert headers(hook.sent[-1]) == "[낮음] 새 위치에서 발견" and "deploy/never-scored.env" in json.dumps(hook.sent[-1])
    # A learned profile closed the finding a moment ago and may reopen it: a new location waits for that.
    enable(repo, min_severity="INFO")
    _c, first, reopened = found(repo, "auto-closed", "MEDIUM")
    deliver(repo, hook.client)
    repo.update_finding_status(reopened.id, "FALSE_POSITIVE", f"{RESOLUTION_PREFIX}profile similarity=0.99")
    repo.upsert_exposure(first.model_copy(update={"id": None, "location": "public/app.js", "severity": "HIGH"}))
    assert deliver(repo, hook.client, now=young())["deferred"] == 1
    repo.update_finding_status(reopened.id, "OPEN")  # what reopen_auto does
    clock.tick(3)
    deliver(repo, hook.client, now=young())
    assert "public/app.js" in json.dumps(hook.sent[-1])


def test_a_finding_that_rises_to_the_minimum_is_announced_once(repo, clock):
    enable(repo, min_severity="HIGH")
    credential, low, _finding = found(repo, "rising", "LOW")
    hook = Hook()
    deliver(repo, hook.client)
    assert hook.sent == []  # LOW: filtered out
    repo.set_exposure_severity(low.id, "CRITICAL")  # verified active, rescored
    repo.repair_finding_rollup(credential.id)
    deliver(repo, hook.client)
    assert [headers(body) for body in hook.sent] == ["[심각] 심각도 상승"]
    assert "심각도: 낮음 → 심각" in hook.sent[0]["blocks"][1]["text"]["text"]
    # A rise caused by a new location announced in the same pass is that location's alert only.
    other, place, _f = found(repo, "second", "LOW")
    deliver(repo, hook.client)
    repo.upsert_exposure(place.model_copy(update={"id": None, "location": "deploy/key.env", "severity": "CRITICAL"}))
    repo.repair_finding_rollup(other.id)
    deliver(repo, hook.client)
    assert [headers(body) for body in hook.sent[1:]] == ["[심각] 새 위치에서 발견"]


def test_a_rise_beyond_what_its_location_alert_says_is_announced_too(repo, clock):
    enable(repo, min_severity="LOW", language="en")
    credential, first, _finding = found(repo, "quiet", "INFO")
    hook = Hook()
    deliver(repo, hook.client)
    assert hook.sent == []  # INFO: filtered out
    repo.upsert_exposure(first.model_copy(update={"id": None, "location": "src/other.py", "severity": "LOW"}))
    repo.set_exposure_severity(first.id, "HIGH")  # the first place verified active, rescored, in the same pass
    repo.repair_finding_rollup(credential.id)
    deliver(repo, hook.client)
    assert sorted(headers(body) for body in hook.sent) == ["[High] Severity raised", "[Low] Found at a new location"]


def test_up_to_three_alerts_go_one_by_one_and_more_as_digests_of_fifteen(repo, clock, acks, monkeypatch):
    asked = []
    original = ScanStore.request_delay
    monkeypatch.setattr(ScanStore, "request_delay", lambda self, key, interval, **kw: asked.append((key, interval))
                        or original(self, key, interval, **kw))
    enable(repo)
    for number in range(3):
        found(repo, f"single-{number}")
    hook = Hook()
    assert deliver(repo, hook.client)["messages"] == 3
    assert [headers(payload) for payload in hook.sent] == ["[높음] 새 자격증명 노출"] * 3
    assert clock.slept == [1.1, 1.1]  # one message per 1.1 s, through the shared slot
    assert {key for key, _interval in asked} == {delivery.PACING_KEY} and {interval for _key, interval in asked} == {1.1}
    assert len(delivery.PACING_KEY) == 64 and set(delivery.PACING_KEY) <= set("0123456789abcdef")
    for number in range(20):
        found(repo, f"burst-{number:02}")
    hook = Hook()
    result = deliver(repo, hook.client)
    assert result["messages"] == 2 and result["delivered"] == 20
    assert [headers(payload) for payload in hook.sent] == ["CreMore 새 탐지 15건", "CreMore 새 탐지 5건"]
    assert [len(payload["blocks"]) - 1 for payload in hook.sent] == [15, 5]
    counts = Counter(acks)
    assert set(counts.values()) == {1} and len(counts) == 3 + 20  # every alert once; non-alerts went in bulk
    assert delivery.status(repo)["pending"] == 0


def test_a_failure_mid_pass_keeps_what_went_out_and_the_rest_waits(repo, clock, acks):
    enable(repo)
    for number in range(3):
        found(repo, f"part-{number}")
    hook = Hook((200, "ok", {}), (503, "", {}))
    result = deliver(repo, hook.client)
    assert (result["messages"], result["delivered"], result["retried"], result["deferred"]) == (1, 1, 1, 1)
    assert len(hook.sent) == 2 and delivery.status(repo)["last_error_code"] == "SINK_UNAVAILABLE"
    clock.tick(delivery.DEFER_SECONDS)  # the alert not tried waits that long; the one tried, its backoff
    assert deliver(repo, hook.client)["delivered"] == 1
    clock.tick(10 - delivery.DEFER_SECONDS)
    assert deliver(repo, hook.client)["delivered"] == 1
    alerts = [payload["blocks"][1]["text"]["text"] for payload in hook.sent]
    assert sorted({line for text in alerts for line in text.split("\n") if line.startswith("리소스")}) == [
        "리소스: acme/part-0", "리소스: acme/part-1", "리소스: acme/part-2"]
    assert len(acks) == len(set(acks)) == 3 and delivery.status(repo)["pending"] == 0


def test_the_bot_posts_to_the_listed_channel_and_honours_slack_rate_limits(repo, clock, acks):
    contact.save(repo, SETTINGS, {"slack": {"token": TOKEN, "allowed_channels": ["#security-alerts"]},
                                  "allowed_domains": ["example.com"]}, "ada")
    setup.save(repo, SETTINGS, {"transport": "bot", "channel": "#security-alerts", "enabled": True,
                                "language": "en"}, "ada")
    found(repo, "bot")
    limited = Slack(limit_after=0)
    assert deliver(repo, limited.client)["error_code"] == "SLACK_RATE_LIMITED"
    slack = Slack()
    clock.tick(29)  # Slack asked for 30 seconds, more than the backoff's 10
    assert deliver(repo, slack.client)["claimed"] == 0 and slack.calls == []
    clock.tick(1)
    assert deliver(repo, slack.client)["delivered"] == 1
    [(method, body)] = slack.calls
    assert method == "chat.postMessage" and body["channel"] == "#security-alerts"
    assert body["blocks"][0]["text"]["text"] == "[High] New credential exposure"
    assert (body["link_names"], body["unfurl_links"], body["unfurl_media"], body["mrkdwn"]) == (False, False, False, False)
    # A channel the contact setup no longer lists is not posted to; the alert waits for the setup to be fixed.
    contact.save(repo, SETTINGS, {"slack": {"allowed_channels": ["C0123ABCD9"]}, "allowed_domains": ["example.com"]}, "ada")
    found(repo, "unlisted")
    assert deliver(repo, slack.client)["error_code"] == "CONTACT_RECIPIENT_NOT_ALLOWED" and len(slack.calls) == 1
    assert TOKEN not in json.dumps([SiemOutbox(repo).status(include_internal=True), repo.get_setting(setup.KEY)], default=str)


def test_an_alert_is_read_from_the_database_when_sent_and_carries_no_secret_material(repo, clock):
    contact.save(repo, SETTINGS, {"console_url": "https://cremore.example.com", "allowed_domains": []}, "ada")
    enable(repo)
    connection = repo.create_connection(Connection(provider="github", name="Payments GitHub"))
    job = repo.enqueue_job(ScanJob(kind="scope", connection_id=connection.id, payload={"trigger": "SCHEDULE"}))
    credential, row, _finding = found(repo, "payments", source_connection_id=connection.id, last_source_scan_id=job.id)
    repo.upsert_exposure(row.model_copy(update={"id": None, "location": "src/other.py"}))
    repo.update_credential(credential.id, credential_status="Active")  # verified after it was found
    hook = Hook()
    deliver(repo, hook.client)
    first = hook.sent[0]
    lines = first["blocks"][1]["text"]["text"].split("\n")
    assert lines == ["유형: GitHub token · 발급: github", "검증: 활성 확인", "발견 위치: GitHub · Payments GitHub",
                     "리소스: acme/payments", "위치: src/payments.py (3행)", lines[5], "검사 시작: 예약",
                     "다른 열린 위치: 1곳", f"콘솔: https://cremore.example.com/?view=exposed&amp;id=credential%3A{credential.id}"]
    assert lines[5].startswith("처음 발견: ") and lines[5].endswith(" KST")
    assert first["blocks"][2]["elements"][0]["url"] == f"https://cremore.example.com/?view=exposed&id=credential%3A{credential.id}"
    text = sent_text(hook)
    for secret in ("synthetic-fingerprint", "private-identifier", "masked-hint", "private redacted line"):
        assert secret not in text, secret


@pytest.mark.parametrize("origin,shown", [("queue", "검사 시작: 변경 알림(큐)"), ("feed", "검사 시작: 변경 알림(피드)"),
                                          ("api", "검사 시작: 변경 알림")])
def test_an_alert_names_where_the_change_event_that_found_it_came_from(repo, clock, origin, shown):
    enable(repo)
    connection = repo.create_connection(Connection(provider="github", name="Payments GitHub"))
    job = repo.enqueue_job(ScanJob(kind="scope", connection_id=connection.id,
                                   payload={"trigger": "EVENT", "requested_by": origin}))
    found(repo, "payments", source_connection_id=connection.id, last_source_scan_id=job.id)
    hook = Hook()
    deliver(repo, hook.client)
    assert shown in hook.sent[0]["blocks"][1]["text"]["text"].split("\n")


def test_an_alert_names_where_an_aws_key_was_recently_used_from_only_when_the_lookup_ran_in_its_owner_account(repo, clock):
    arn = "arn:aws:iam::123456789012:user/ci"
    events = [{"event_time": f"2026-10-0{day}T05:03:00+00:00", "source_address": address, "source_address_kind": kind}
              for day, address, kind in ((1, "203.0.113.5", "IPV4"), (2, "198.51.100.7", "IPV4"),
                                          (3, "cloudtrail.amazonaws.com", "AWS_INTERNAL"), (4, "2001:db8::1", "IPV6"))]
    credential, _row, _finding = found(repo, "aws")
    repo.update_credential(credential.id, provider="aws", credential_type="AWS_ACCESS_KEY", principal_arn=arn,
                           usage_snapshot={"collected_account_id": "123456789012", "events": events})
    enable(repo)
    hook = Hook()
    deliver(repo, hook.client)
    lines = hook.sent[0]["blocks"][1]["text"]["text"].split("\n")
    assert ("최근 사용 출처: 2001:db8::1 (2026-10-04 14:03 KST), AWS 서비스 cloudtrail.amazonaws.com (2026-10-03 14:03 KST), "
            "198.51.100.7 (2026-10-02 14:03 KST) +1") in lines
    # Another account's lookup is not evidence about this key.
    other, _row, _finding = found(repo, "other")
    repo.update_credential(other.id, provider="aws", credential_type="AWS_ACCESS_KEY", principal_arn=arn,
                           usage_snapshot={"collected_account_id": "999999999999", "events": events})
    hook.sent.clear()
    deliver(repo, hook.client)
    assert hook.sent and "최근 사용 출처" not in sent_text(hook)
    # Minimal never names addresses, even from a lookup in the owner's account.
    again, _row, _finding = found(repo, "again")
    repo.update_credential(again.id, provider="aws", credential_type="AWS_ACCESS_KEY", principal_arn=arn,
                           usage_snapshot={"collected_account_id": "123456789012", "events": events})
    setup.save(repo, SETTINGS, {"detail": "minimal"}, "ada")
    hook.sent.clear()
    deliver(repo, hook.client)
    assert hook.sent and "최근 사용 출처" not in sent_text(hook) and "203.0.113.5" not in sent_text(hook)


@pytest.mark.parametrize("language,shown", [
    ("ko", "최근 사용 출처: 192.0.2.6 (2026-09-06 09:00 KST), 192.0.2.5 (2026-09-05 09:00 KST), 192.0.2.4 (2026-09-04 09:00 KST) +3 이상"),
    ("en", "Recently used from: 192.0.2.6 (2026-09-06 00:00 UTC), 192.0.2.5 (2026-09-05 00:00 UTC), 192.0.2.4 (2026-09-04 00:00 UTC) +3+")])
def test_an_alert_counts_every_address_the_lookup_read_not_only_the_kept_events(repo, clock, language, shown):
    # The kept (newest) events name one address; the summary counted six across every event, and more past its cap.
    kept = [{"event_time": "2026-09-01T00:00:00+00:00", "source_address": "192.0.2.1", "source_address_kind": "IPV4"}]
    sources = {f"192.0.2.{n}": {"kind": "IPV4", "count": n, "last": f"2026-09-{n:02d}T00:00:00+00:00"} for n in range(1, 7)}
    credential, _row, _finding = found(repo, "aws")
    repo.update_credential(credential.id, provider="aws", credential_type="AWS_ACCESS_KEY",
                           principal_arn="arn:aws:iam::123456789012:user/ci",
                           usage_snapshot={"collected_account_id": "123456789012", "events": kept,
                                           "summary": {"events": 300, "sources": sources, "sources_untracked": 9}})
    enable(repo, language=language)
    hook = Hook()
    deliver(repo, hook.client)
    assert shown in hook.sent[0]["blocks"][1]["text"]["text"].split("\n")


def test_a_name_shaped_like_a_credential_is_not_shown(repo, clock):
    token = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"  # synthetic, built at run time
    enable(repo)
    connection = repo.create_connection(Connection(provider="github", name="team " + token))
    credential = repo.upsert_credential(Credential(fingerprint="synthetic-named", credential_type="GITHUB_TOKEN",
                                                   provider="github"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="website", resource_name="acme/" + token,
                                             location=f"https://docs.example.com/{token}/page?x=1", line_number=2,
                                             severity="HIGH", source_connection_id=connection.id))
    repo.upsert_finding(credential.id, exposure.id, "HIGH")
    hook = Hook()
    deliver(repo, hook.client)
    text = sent_text(hook)
    assert token not in text and text.count("(표시하지 않음 · 콘솔에서 확인)") == 3


def test_the_test_message_goes_out_with_the_saved_setup_through_the_shared_slot(repo, clock):
    assert delivery.send_test(repo, SETTINGS, http_client_factory=Hook().client) == {
        "delivered": False, "error_code": "ALERTS_NOT_CONFIGURED"}
    setup.save(repo, SETTINGS, {"webhook_url": WEBHOOK, "language": "en"}, "ada")  # a test needs no switch on
    hook = Hook()
    assert delivery.send_test(repo, SETTINGS, http_client_factory=hook.client) == {"delivered": True, "error_code": None}
    assert headers(hook.sent[0]) == "CreMore Slack detection alert test"
    assert delivery.send_test(repo, SETTINGS, http_client_factory=Hook((429, "", {"Retry-After": "5"})).client) == {
        "delivered": False, "error_code": "DELIVERY_RATE_LIMITED"}
    assert clock.slept == [1.1, 1.1]  # each test waited for the slot the one before took
    clock.tick(5)  # Slack's five seconds
    # Nothing of a test enters the outbox.
    assert not SiemOutbox(repo).status(include_internal=True)
    contact.save(repo, SETTINGS, {"slack": {"token": TOKEN, "allowed_channels": ["#security-alerts"]},
                                  "allowed_domains": ["example.com"]}, "ada")
    setup.save(repo, SETTINGS, {"transport": "bot"}, "ada")
    assert delivery.send_test(repo, SETTINGS, http_client_factory=Slack().client)["error_code"] == "ALERTS_NOT_CONFIGURED"
    setup.save(repo, SETTINGS, {"channel": "#security-alerts"}, "ada")
    slack = Slack()
    clock.tick(2)
    assert delivery.send_test(repo, SETTINGS, http_client_factory=slack.client) == {"delivered": True, "error_code": None}
    assert slack.calls[0][1]["channel"] == "#security-alerts"


def test_pacing_waits_for_a_slot_another_replica_holds_and_never_sleeps_through_a_cooldown(repo, clock):
    store = ScanStore(repo)
    assert store.request_delay(delivery.PACING_KEY, delivery.PACING_SECONDS) == 0  # another replica just sent
    assert delivery._wait_turn(store) == 0 and clock.slept == [1.1]
    delivery._cool(store, 30)
    assert 29 < delivery._wait_turn(store) <= 30 and clock.slept == [1.1]


def test_an_idle_pass_acknowledges_non_alerts_in_bulk(repo, clock, acks):
    enable(repo)
    hook = Hook()
    deliver(repo, hook.client)
    for number in range(5):
        repo.record_siem_event({"schema_version": 1, "event_id": f"00000000-0000-4000-8000-00000000000{number}",
                                "event_type": "siem.test", "occurred_at": dt.datetime.now(dt.UTC).isoformat(),
                                "product": "CreMore", "test": {"nonce": f"00000000-0000-4000-8000-00000000001{number}"}})
    result = deliver(repo, hook.client)
    assert result["claimed"] == 0 and acks == [] and delivery.status(repo)["pending"] == 0  # all five in one statement
    state = repo.get_setting(delivery.STATE_KEY)["value"]
    assert state["cursor"] and state["swept_at"]
    # CreMore's own destination is no SIEM: SIEM status, the backlog evaluator and the forward count leave it out.
    assert [row["destination"] for row in SiemOutbox(repo).status(include_internal=True)] == [delivery.DESTINATION]
    assert SiemOutbox(repo).status() == [] and SiemOutbox(repo).seen_since(clock.now - dt.timedelta(days=1)) == []


def test_an_owed_alert_does_not_hold_the_cursor_back(repo, clock, acks, monkeypatch):
    enable(repo)
    found(repo, "owed")
    hook = Hook((503, "", {}), (503, "", {}))
    begun = dt.datetime.now(dt.UTC)
    deliver(repo, hook.client, now=begun)
    seen = []
    original = SiemOutbox.skip
    monkeypatch.setattr(SiemOutbox, "skip", lambda self, *args, **kw: seen.append(kw.get("since")) or original(self, *args, **kw))
    later = begun + dt.timedelta(hours=2)
    clock.tick(10)
    assert deliver(repo, hook.client, now=later)["retried"] == 1  # Slack still failing two hours on
    clock.tick(20)
    assert deliver(repo, hook.client, now=later + dt.timedelta(seconds=1))["delivered"] == 1
    # The last pass read the events from its cursor (LAG before the pass before it), not from the owed alert's time:
    # the owed alert came through its delivery row.
    assert seen[-1] == later - delivery.LAG and len(acks) == 1


def test_an_event_stamped_before_the_cursor_is_found_by_the_hourly_sweep(repo, clock):
    enable(repo)
    begun = dt.datetime.now(dt.UTC)
    hook = Hook()
    deliver(repo, hook.client, now=begun)
    deliver(repo, hook.client, now=begun + dt.timedelta(minutes=10))
    found(repo, "late")  # stamped before the cursor, as a slow commit or a writer's clock running behind would be
    deliver(repo, hook.client, now=begun + dt.timedelta(minutes=11))
    assert hook.sent == []  # no pass reads the whole history every second
    deliver(repo, hook.client, now=begun + dt.timedelta(minutes=61))
    assert "acme/late" in sent_text(hook)


def test_a_clock_that_ran_ahead_and_was_corrected_holds_no_alert_back(repo, clock):
    enable(repo)
    hook = Hook()
    deliver(repo, hook.client, now=young())
    deliver(repo, hook.client, now=young() + dt.timedelta(hours=3))  # the host's clock ran three hours ahead
    found(repo, "after-correction")
    deliver(repo, hook.client, now=young())
    assert "acme/after-correction" in sent_text(hook)
    state = repo.get_setting(delivery.STATE_KEY)["value"]
    assert max(delivery._time(state["cursor"]), delivery._time(state["swept_at"])) <= dt.datetime.now(dt.UTC)


def test_a_console_address_slack_refuses_in_a_button_still_lets_the_short_form_out(repo, clock):
    contact.save(repo, SETTINGS, {"console_url": "http://localhost:3000", "allowed_domains": []}, "ada")
    enable(repo, detail="minimal")
    found(repo, "local-console")
    hook = Picky('"url"')  # Slack refusing the button's address
    result = deliver(repo, hook.client)
    assert (result["delivered"], result["retried"], len(hook.sent)) == (1, 0, 2)
    assert '"url"' not in json.dumps(hook.sent[-1]) and "http://localhost:3000/?view=exposed" in json.dumps(hook.sent[-1])
    # Once the short form went out, the rest of the pass goes without buttons: a digest is not refused, then split.
    for number in range(20):
        found(repo, f"burst-{number:02}")
    hook = Picky('"url"')
    result = deliver(repo, hook.client)
    assert (result["delivered"], len(hook.sent)) == (20, 1 + 15 + 1 + 1)  # refused digest, its 15 split, short, digest
    assert '"url"' not in json.dumps(hook.sent[-1]) and headers(hook.sent[-1]) == "CreMore 새 탐지 5건"


def test_a_test_message_goes_out_without_the_button_slack_refuses_as_alerts_do(repo, clock):
    contact.save(repo, SETTINGS, {"console_url": "http://localhost:3000", "allowed_domains": []}, "ada")
    setup.save(repo, SETTINGS, {"webhook_url": WEBHOOK, "language": "en"}, "ada")
    hook = Picky('"url"')  # Slack refusing the button's address
    assert delivery.send_test(repo, SETTINGS, http_client_factory=hook.client) == {"delivered": True, "error_code": None}
    assert len(hook.sent) == 2 and '"url"' not in json.dumps(hook.sent[-1])
    assert "http://localhost:3000" in json.dumps(hook.sent[-1])
    clock.tick(2)
    hook = Picky("CreMore")  # refused in every form: one retry, then its code
    assert delivery.send_test(repo, SETTINGS, http_client_factory=hook.client) == {
        "delivered": False, "error_code": "DELIVERY_REJECTED"}
    assert len(hook.sent) == 2


def test_a_pass_tries_nothing_past_its_deadline_so_no_answer_outlives_its_lease(repo, clock, acks, monkeypatch):
    monkeypatch.setattr(delivery, "PASS_SECONDS", 10)
    enable(repo, detail="standard")
    for number in range(8):
        found(repo, f"slow-{number}")
    hook = Slow(clock, 1.5, "acme/slow-")  # every full message refused: two tries an alert, 1.5 s each
    started = clock.now
    first = deliver(repo, hook.client)
    assert first["deferred"] and first["delivered"] and (clock.now - started).total_seconds() <= 10 + 2 * 1.5
    for _ in range(5):  # what was put back goes out in the next passes
        if not deliver(repo, hook.client)["claimed"]:
            break
    accepted = [body for body in hook.sent if "acme/slow-" not in json.dumps(body)]
    assert len(accepted) == len(acks) == len(set(acks)) == 8  # every alert accepted once, each acknowledged in time


def test_a_stopping_process_sends_nothing_new_and_puts_what_it_claimed_back_at_once(repo, clock, acks):
    """A shutdown during a pass: the message in flight goes out and is acknowledged, the rest is not left claimed until
    its lease runs out but goes back for the next process now, and a pass that starts stopping claims nothing."""
    enable(repo, detail="standard")
    for number in range(3):
        found(repo, f"stop-{number}")
        apart()
    hook = Hook()
    later = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=2)
    assert delivery.deliver_pending(repo, SETTINGS, http_client_factory=hook.client, now=later,
                                    stop=lambda: True)["claimed"] == 0 and not hook.sent
    first = delivery.deliver_pending(repo, SETTINGS, http_client_factory=hook.client, now=later,
                                     stop=lambda: len(hook.sent) >= 1)
    assert (first["messages"], first["delivered"], first["deferred"]) == (1, 1, 2) and len(acks) == 1
    second = deliver(repo, hook.client)  # at once: nothing waits for the first pass's lease
    assert (second["claimed"], second["delivered"]) == (2, 2) and len(hook.sent) == len(acks) == len(set(acks)) == 3


def test_an_unreadable_cursor_reads_again_from_the_first_turn_on(repo, clock):
    enable(repo)
    hook = Hook()
    deliver(repo, hook.client)
    for broken in (None, "not a time", 7):
        repo.put_setting(delivery.STATE_KEY, {**repo.get_setting(delivery.STATE_KEY)["value"], "cursor": broken}, "x")
        found(repo, f"after-{broken}")
        deliver(repo, hook.client)
    assert all(f"acme/after-{broken}" in sent_text(hook) for broken in (None, "not a time", 7))
    assert delivery.status(repo)["pending"] == 0


def test_a_quick_read_takes_only_new_events_and_a_late_commit_waits_for_the_next_full_read(repo, clock, monkeypatch):
    enable(repo)
    found(repo, "first")
    hook = Hook()
    begun = dt.datetime.now(dt.UTC)
    deliver(repo, hook.client, now=begun)  # a full read: it remembers the newest event it saw
    seen = []
    original = SiemOutbox.skip
    monkeypatch.setattr(SiemOutbox, "skip", lambda self, *args, **kw: seen.append(kw.get("since")) or original(self, *args, **kw))
    _credential, _row, late = found(repo, "late")
    backdate(repo, late, begun - dt.timedelta(minutes=1))  # committed now, stamped a minute ago
    found(repo, "on-time")
    deliver(repo, hook.client, now=begun + dt.timedelta(seconds=1))
    assert seen[-1] > begun - delivery.OVERLAP - dt.timedelta(seconds=1)  # from just before the newest event seen
    assert "acme/on-time" in sent_text(hook) and "acme/late" not in sent_text(hook)
    deliver(repo, hook.client, now=begun + dt.timedelta(seconds=delivery.FULL_READ_SECONDS + 1))
    assert seen[-1] <= begun - delivery.LAG and "acme/late" in sent_text(hook)  # the next full read finds it


def test_replicas_whose_clocks_differ_keep_reading_quickly_between_full_reads(repo, clock, monkeypatch):
    # A replica whose clock runs 45 s ahead stamped the last full read: to this one it lies in the future, which is
    # still recent, not a reason to read everything again on every pass.
    enable(repo)
    found(repo, "first")
    hook = Hook()
    begun = dt.datetime.now(dt.UTC)
    deliver(repo, hook.client, now=begun + dt.timedelta(seconds=45))  # the replica ahead
    seen = []
    original = SiemOutbox.skip
    monkeypatch.setattr(SiemOutbox, "skip", lambda self, *args, **kw: seen.append(kw.get("since")) or original(self, *args, **kw))
    deliver(repo, hook.client, now=begun + dt.timedelta(seconds=1))  # this replica, a second later by its own clock
    assert seen[-1] > begun - delivery.OVERLAP - dt.timedelta(seconds=1)  # a quick read, not one from the cursor


def test_an_alert_counts_open_locations_from_a_bounded_read_and_names_its_own(repo, clock, monkeypatch):
    monkeypatch.setattr(delivery, "PLACES_READ", 2)
    enable(repo, language="en")
    _credential, first, _finding = found(repo, "many")
    hook = Hook()
    deliver(repo, hook.client)
    for number in range(3):
        repo.upsert_exposure(first.model_copy(update={"id": None, "location": f"src/copy-{number}.py"}))
    deliver(repo, hook.client)
    lines = [line for body in hook.sent[1:] for line in body["blocks"][1]["text"]["text"].split("\n")]
    assert sorted(line for line in lines if line.startswith("Location")) == [
        f"Location: src/copy-{number}.py (line 3)" for number in range(3)]
    counts = [line for line in lines if line.startswith("Other open locations")]
    assert len(counts) == 3 and all(line.endswith("+") for line in counts)  # more open rows than were read


def test_a_place_another_open_row_holds_is_no_new_location(repo, clock):
    enable(repo, language="en")
    _credential, first, _finding = found(repo, "shared")
    hook = Hook()
    deliver(repo, hook.client)
    assert len(hook.sent) == 1
    # The same file read again through another connection: a row of its own, at a place one open row holds.
    repo.upsert_exposure(first.model_copy(update={"id": None, "source_connection_id": uuid.uuid4()}))
    deliver(repo, hook.client)
    assert len(hook.sent) == 1
    # Two connections finding a new place in one pass: one alert for it.
    for _ in range(2):
        repo.upsert_exposure(first.model_copy(update={"id": None, "source_connection_id": uuid.uuid4(),
                                                      "location": "src/new.py"}))
    deliver(repo, hook.client)
    assert len(hook.sent) == 2 and "src/new.py" in json.dumps(hook.sent[1])


def test_a_writer_clock_ahead_of_the_turn_off_by_less_than_lag_loses_no_alert(repo, clock):
    real = dt.datetime.now(dt.UTC)
    setup.save(repo, SETTINGS, {"webhook_url": WEBHOOK, "enabled": True}, "ada", now=real - dt.timedelta(hours=1))
    hook = Hook()
    deliver(repo, hook.client, now=real - dt.timedelta(minutes=10))
    setup.save(repo, SETTINGS, {"enabled": False}, "ada", now=real - dt.timedelta(minutes=4))
    found(repo, "clock-ahead")  # written now: four minutes after the turn-off, by the API's clock
    setup.save(repo, SETTINGS, {"enabled": True}, "ada", now=real + dt.timedelta(minutes=30))
    deliver(repo, hook.client, now=real + dt.timedelta(minutes=31))
    assert "acme/clock-ahead" in sent_text(hook)
