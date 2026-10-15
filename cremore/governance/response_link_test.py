"""Exposure responses asked by Slack or mail with a CreMore link, or recorded by the local operator: the link's token
lives only in the message (its digest names the request), a message that did not go out ends its link, only the
current directory recipient reads and answers it, and their report is the answer, recorded atomically. Fakes only:
the contact fakes of cremore.governance.contact_test and a fake directory; memory, SQLite and (when configured)
PostgreSQL stores."""
import datetime as dt
import hashlib
import json
import os
import re
import uuid

import pytest

from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- guarded PostgreSQL fixture
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import Credential, Exposure
from cremore.governance import contact, response_routing
from cremore.governance import response as service
from cremore.governance import response_reports as reports
from cremore.governance.contact_test import MAIL, TOKEN, Relay, Slack
from cremore.onboarding.onboarding_test import SETTINGS
from cremore.siem.events_changes_test import events as siem_events
from cremore.ticketing import setup

NOW = dt.datetime(2026, 9, 30, 3, 0, tzinfo=dt.UTC)
CONSOLE = "https://cremore.example.com"
TEAM = SETTINGS.model_copy(update={"auth_mode": "oidc", "oidc_issuer_url": "https://idp.example.com"})
LOCAL = SETTINGS
PERSON = str(uuid.uuid4())
KIM = {"subject": "kim-sub", "email": "Kim@Example.com"}
PATH = "private/app/.env"  # where it was exposed: never in a message or on the link page
LINK = re.compile(re.escape(CONSOLE) + r"/response#([A-Za-z0-9_-]{43})")


@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    if request.param == "postgres":
        return request.getfixturevalue("pg")[1]
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


class Directory:
    """The people directory (cremore.identity.people) as response_routing.resolve reads it: one person, whose
    address can change and who can leave."""

    def __init__(self):
        self.email = "kim@example.com"
        self.name = "Kim"

    def __call__(self, repo, settings, ref, *, now=None):
        if str(ref) != PERSON or self.email is None:
            raise service.ResponseError("PERSON_INACTIVE")
        return {"id": PERSON, "person_ref": PERSON, "name": self.name, "email": self.email, "department": "Platform",
                "title": None, "state": "ACTIVE", "selectable": True, "reason": None, "observed_at": NOW.isoformat()}


@pytest.fixture
def directory(monkeypatch):
    found = Directory()
    monkeypatch.setattr(response_routing, "resolve", found)
    return found


def finding(repo, *, identifier="ghp_••••"):
    credential = repo.upsert_credential(Credential(fingerprint=uuid.uuid4().hex, credential_type="GITHUB_PAT",
                                                   provider="github", identifier_hint=identifier))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="github",
                                             resource_name="acme/private-repo", location=PATH, severity="HIGH"))
    return repo.upsert_finding(credential.id, exposure.id, "HIGH")


def contact_setup(repo, **overrides):
    body = {"mail": MAIL, "slack": {"token": TOKEN, "allowed_channels": ["#security-alerts"]},
            "allowed_domains": ["example.com"], "console_url": CONSOLE, **overrides}
    contact.save(repo, SETTINGS, body, "admin")


def transports(slack=None, relay=None):
    relay = relay or Relay()
    return {"smtp": relay, "smtp_ssl": relay, "http_client_factory": (slack or Slack()).client}


def ask(repo, item, *, channel="slack", settings=TEAM, version=0, sent=None, now=NOW, **kwargs):
    return service.request_ticket(repo, settings, item.id, "analyst", channel=channel, expected_version=version,
                                  request_id=uuid.uuid4(), now=now, transports=sent or transports(),
                                  **({"person_ref": PERSON} if settings is TEAM else {}) | kwargs)


def slack_text(slack):
    return [body["text"] for method, body in slack.calls if method == "chat.postMessage"][-1]


def token_of(text):
    return LINK.search(text).group(1)


def pointer(repo, token):
    return repo.get_setting(service.LINK_PREFIX + hashlib.sha256(token.encode()).hexdigest())


def audit(repo, item):
    return [(e.event_type, e.actor, e.from_status, e.to_status, e.note) for e in repo.list_finding_events(item.id)
            if e.event_type.startswith("RESPONSE_")]


def statement(**changes):
    return {"result": "DONE", "path": "RETIRED", "actions": ["REMOVE_PLAINTEXT", "REVOKE"],
            "explanation": "Removed the published copy and revoked the old token with the issuer.",
            "performed_at": (NOW + dt.timedelta(minutes=1)).isoformat(), **changes}


def answer(repo, token, data=None, *, holder=KIM, report_id=None, now=NOW + dt.timedelta(minutes=2)):
    return service.link_answer(repo, TEAM, token, holder, report_id=report_id or uuid.uuid4(), data=data or statement(),
                               contains_credentials=lambda text: "synthetic-secret" in text, now=now)


def test_a_slack_request_sends_a_link_only_its_digest_names(repo, directory):
    item = finding(repo)
    contact_setup(repo)
    slack = Slack()
    asked = ask(repo, item, sent=transports(slack))
    current = asked["current"]
    assert (asked["state"], current["channel"], current["ticket"], asked["can_request"]) == (
        "WAITING_OWNER", "slack", None, False)
    assert (current["link_expires_at"], current["link_expired"]) == ((NOW + service.LINK_LIFETIME).isoformat(), False)
    assert current["assigned_to"] == "kim@example.com" and current["recipient"]["person_ref"] == PERSON
    text = slack_text(slack)
    token = token_of(text)
    # The issuing service and type, the masked identifier, what to do, until when, and the link; never the location.
    assert "github / GITHUB_PAT" in text and "ghp_••••" in text and "2026-10-07 03:00 UTC" in text
    assert "평문을 지우고" in text and PATH not in text and "private-repo" not in text
    # The playbook follows: GitHub's revocation steps, the git clean-up for where it still is, and the vault steps.
    guide = text[text.index("조치 방법(플레이북)"):]
    assert "■ GitHub에서 토큰 삭제 후 재발급" in guide and "■ 노출 원본과 이력 정리" in guide and "■ 새 값을 Vault로 옮기기" in guide
    assert "git filter-repo --replace-text" in guide and "\nhttps://github.com/settings/tokens" in guide
    assert "<b>" not in guide and "{name}" not in guide and token not in guide
    assert pointer(repo, token)["value"] == {"finding_id": str(item.id), "request_id": current["request_id"]}
    rows = audit(repo, item)
    assert [row[:4] for row in rows] == [("RESPONSE_REQUESTED", "analyst", "NEW", "SENDING"),
                                         ("RESPONSE_LINK_SENT", "analyst", "SENDING", "WAITING_OWNER")]
    expected = contact.fingerprints(TEAM, ["kim@example.com"], "[CreMore] 노출 자격증명 정리 요청", text)[1]
    assert f"slack to=kim@example.com text={expected} expires={(NOW + service.LINK_LIFETIME).isoformat()}" in rows[0][4]
    # The token is in the message alone: no setting, cycle, projection or audit note holds it.
    stored = json.dumps([repo.list_settings(""), [row[4] for row in rows], service.public(repo, item.id, now=NOW)],
                        default=str)
    assert token not in stored and "digest" not in json.dumps(service.public(repo, item.id, now=NOW))
    # The SIEM sees the transitions and states, never the address, the token or the text.
    exported = [row for row in siem_events(repo, "audit.action") if row["audit"]["action"].startswith("RESPONSE_")]
    assert [(row["audit"]["action"], row["audit"]["to_status"]) for row in exported] == [
        ("RESPONSE_REQUESTED", "SENDING"), ("RESPONSE_LINK_SENT", "WAITING_OWNER")]
    assert not any(value in json.dumps(exported) for value in ("kim@", token, expected, "github"))


def test_a_mail_request_carries_the_same_link_in_english(repo, directory):
    item = finding(repo)
    contact_setup(repo)
    relay = Relay()
    asked = ask(repo, item, channel="mail", sent=transports(relay=relay), locale="en")
    assert (asked["state"], asked["current"]["channel"]) == ("WAITING_OWNER", "mail")
    [message] = relay.sent
    assert message["To"] == "kim@example.com" and message["Subject"] == "[CreMore] Exposed credential cleanup request"
    body = message.get_content()
    assert "Issuing service / type: github / GITHUB_PAT" in body and "Answer by (the link expires): 2026-10-07" in body
    assert pointer(repo, token_of(body)) is not None and PATH not in body
    assert "How to fix it (playbook)" in body and "■ Delete and reissue the token in GitHub" in body


class Broken(Relay):
    def send_message(self, message):
        raise RuntimeError("relay library fault")


@pytest.mark.parametrize(("channel", "sent", "code"), [
    ("slack", lambda: transports(Slack(users={"lee@example.com": "U02"})), "SLACK_USERS_NOT_FOUND"),  # this person
    ("slack", lambda: transports(Slack(error="invalid_auth")), "SLACK_INVALID_AUTH"),  # ContactError: nothing went
    ("mail", lambda: transports(relay=Relay(fail="connect")), "SMTP_UNAVAILABLE"),
    ("mail", lambda: transports(relay=Broken()), "CONTACT_SEND_ERROR"),  # an unexpected exception
])
def test_a_message_that_did_not_go_out_ends_its_link_and_can_be_asked_again(repo, directory, monkeypatch, channel,
                                                                             sent, code):
    item = finding(repo)
    contact_setup(repo)
    tokens = []
    original = service._link_message
    monkeypatch.setattr(service, "_link_message", lambda *a: tokens.append(token_of(a[1])) or original(*a))
    failed = ask(repo, item, channel=channel, sent=sent())
    assert (failed["state"], failed["current"]["error_code"], failed["can_request"]) == ("NOT_SENT", code, True)
    [token] = tokens
    assert pointer(repo, token) is None  # the link is dead: its pointer is gone
    assert [row[:4] for row in audit(repo, item)][-1] == ("RESPONSE_NOT_SENT", "analyst", "SENDING", "NOT_SENT")
    assert audit(repo, item)[-1][4].endswith(f"via={channel} code={code}")
    with pytest.raises(service.ResponseError) as dead:
        service.link_view(repo, TEAM, token, KIM, now=NOW)
    assert (dead.value.code, dead.value.http_status) == ("RESPONSE_LINK_INVALID", 404)
    # SEND_UNKNOWN and its admin release are the ticket channel's: nothing is left to release here.
    with pytest.raises(service.ResponseError, match="RESPONSE_NOT_UNKNOWN"):
        service.release_unknown(repo, item.id, "admin", expected_version=failed["version"],
                                request_id=failed["current"]["request_id"], confirmed_no_pending_ticket=True)
    again = ask(repo, item, channel="slack", version=failed["version"])
    assert (again["state"], again["current"]["cycle"]) == ("WAITING_OWNER", 2)
    assert again["current"]["previous_request_id"] == failed["current"]["request_id"]


def test_the_response_sweep_ends_a_send_past_its_deadline_without_any_ticket_system(repo, directory, monkeypatch):
    item = finding(repo)
    contact_setup(repo)
    tokens = []
    original = service._link_message
    monkeypatch.setattr(service, "_link_message", lambda *a: tokens.append(token_of(a[1])) or original(*a))
    monkeypatch.setattr(service, "_finish_link", lambda *a, **kw: None)  # the process died after saving, before sending
    assert ask(repo, item)["state"] == "SENDING"
    monkeypatch.undo()
    monkeypatch.setattr(response_routing, "resolve", directory)
    assert setup.configured(repo) is None  # no ticket system: the ticket sweep never runs
    assert service.sweep(repo, TEAM, None, now=NOW + dt.timedelta(minutes=4)) == 0
    assert service.public(repo, item.id, now=NOW)["state"] == "SENDING"
    late = NOW + dt.timedelta(seconds=service.SEND_SECONDS)

    def refuse_delete(self, prefix, cutoff):
        raise PermissionError("permission denied for table installation_settings")

    # The ticket sweep lists ticket requests in the control process, which may not delete: a link send waits there.
    with monkeypatch.context() as control:
        control.setattr(type(repo), "delete_settings_before", refuse_delete)
        assert service.pending(repo, now=late) == []
    assert service.public(repo, item.id, now=NOW)["state"] == "SENDING" and pointer(repo, tokens[0]) is not None
    service.sweep(repo, TEAM, None, now=late)
    ended = service.public(repo, item.id, now=NOW)
    assert (ended["state"], ended["current"]["error_code"], ended["can_request"]) == (
        "NOT_SENT", "RESPONSE_SEND_TIMED_OUT", True)
    assert audit(repo, item)[-1][:4] == ("RESPONSE_NOT_SENT", service.ACTOR, "SENDING", "NOT_SENT")
    assert pointer(repo, tokens[0]) is None


def test_link_requests_are_refused_where_nobody_could_answer_them(repo, directory):
    item = finding(repo)

    def refused(code, status=409, **kwargs):
        with pytest.raises(service.ResponseError) as error:
            ask(repo, item, **kwargs)
        assert (error.value.code, error.value.http_status) == (code, status)

    contact_setup(repo)
    refused("RESPONSE_LINK_NEEDS_SIGN_IN", settings=LOCAL, to="kim@example.com")  # nobody signs in to a local install
    refused("RESPONSE_RECORD_LOCAL_ONLY", channel="record")  # with company sign-in the person answers themselves
    refused("RESPONSE_RECIPIENT_NOT_A_PERSON", 422, to="#security-alerts")  # a channel's members are not the responder
    refused("RESPONSE_PERSON_REQUIRED", 422, person_ref=None, to="kim@example.com")
    directory.email = "kim@other.test"
    refused("CONTACT_RECIPIENT_NOT_ALLOWED", 422)  # only to the domains the admin allowed
    directory.email = "kim@example.com"
    contact_setup(repo, console_url=None)
    refused("RESPONSE_CONSOLE_URL_NOT_SET")
    contact_setup(repo, mail=None)
    refused("CONTACT_CHANNEL_NOT_SET_UP", channel="mail")
    assert repo.list_settings(service.HEAD_PREFIX) == [] and repo.list_settings(service.LINK_PREFIX) == []


def test_only_the_current_directory_recipient_reads_the_link_until_it_ends(repo, directory):
    item = finding(repo)
    contact_setup(repo)
    slack = Slack()
    ask(repo, item, sent=transports(slack))
    token = token_of(slack_text(slack))

    def code(holder=KIM, now=NOW, token=token):
        with pytest.raises(service.ResponseError) as error:
            service.link_view(repo, TEAM, token, holder, now=now)
        return error.value.code, error.value.http_status

    view = service.link_view(repo, TEAM, token, KIM, now=NOW)
    playbook = view.pop("playbook")
    assert view == {"finding": {"provider": "github", "credential_type": "GITHUB_PAT", "identifier_hint": "ghp_••••",
                                "locations": 1},
                    "request": {"cycle": 1, "state": "WAITING_OWNER", "requested_at": NOW.isoformat(),
                                "link_expires_at": (NOW + service.LINK_LIFETIME).isoformat(), "answer": None,
                                "answered_at": None},
                    "report": None, "can_answer": True}
    # How to fix it in both languages: revoke at GitHub, clean up the git place it is still at, store the new value.
    assert [[s["title"] for s in playbook[lang]] for lang in ("ko", "en")] == [
        ["GitHub에서 토큰 삭제 후 재발급", "노출 원본과 이력 정리", "새 값을 Vault로 옮기기"],
        ["Delete and reissue the token in GitHub", "Clean up the source and its history", "Move the new value into Vault"]]
    assert playbook["en"][0]["link"] == ["GitHub token settings", "https://github.com/settings/tokens"]
    assert PATH not in json.dumps(playbook) and "private-repo" not in json.dumps(playbook)
    assert "@" not in json.dumps(view) and PATH not in json.dumps(view)
    assert code({"subject": "lee-sub", "email": "lee@example.com"}) == ("RESPONSE_LINK_NOT_RECIPIENT", 403)
    assert code({"subject": "kim-sub", "email": "\u212aim@example.com"}) == ("RESPONSE_LINK_NOT_RECIPIENT", 403)  # Kelvin
    assert code(token="x" * 43) == code(token="not a token") == ("RESPONSE_LINK_INVALID", 404)
    assert code(now=NOW + service.LINK_LIFETIME) == ("RESPONSE_LINK_EXPIRED", 410)
    directory.email = "kim.new@example.com"  # the directory now names another address for the person
    assert code() == ("RESPONSE_LINK_NOT_RECIPIENT", 403)
    directory.email = None  # the person left
    assert code() == ("RESPONSE_LINK_NOT_RECIPIENT", 403)
    assert audit(repo, item)[-1][0] == "RESPONSE_LINK_SENT"  # reading changed nothing


def test_the_report_is_the_answer_recorded_with_it_and_a_later_one_replaces_it(repo, directory):
    item = finding(repo)
    contact_setup(repo)
    slack = Slack()
    ask(repo, item, sent=transports(slack))
    token = token_of(slack_text(slack))
    report_id = uuid.uuid4()
    declined = answer(repo, token, statement(result="INCOMPLETE", path="EXCEPTION", actions=[],
                                              explanation="The deploy pipeline still reads it; rotating next week."),
                      report_id=report_id)
    assert (declined["request"]["state"], declined["request"]["answer"], declined["can_answer"]) == (
        "NEEDS_ACTION", "DECLINED", True)
    assert declined["report"]["result"] == "INCOMPLETE" and declined["report"]["version"] == 1
    current = service.summary(repo, item.id, now=NOW)["current"]
    assert (current["answered_by"], current["received_at"]) == ("kim-sub", (NOW + dt.timedelta(minutes=2)).isoformat())
    assert current["report"]["basis"] == "VERIFIED_IDP_RECIPIENT" and current["report"]["by"] == "kim-sub"
    before = len(audit(repo, item))
    assert answer(repo, token, statement(result="INCOMPLETE", path="EXCEPTION", actions=[],
                                         explanation="The deploy pipeline still reads it; rotating next week."),
                  report_id=report_id) == declined  # the same report again: nothing new
    assert len(audit(repo, item)) == before
    with pytest.raises(service.ResponseError, match="RESPONSE_REPORT_ID_REUSED"):
        answer(repo, token, report_id=report_id)
    done = answer(repo, token, now=NOW + dt.timedelta(minutes=3))
    assert (done["request"]["state"], done["request"]["answer"], done["report"]["version"]) == (
        "WAITING_VERIFICATION", "APPROVED", 2)
    assert [row[:4] for row in audit(repo, item)][2:] == [
        ("RESPONSE_REPORT_RECORDED", "kim-sub", "WAITING_OWNER", "WAITING_OWNER"),
        ("RESPONSE_DECLINED", "kim-sub", "WAITING_OWNER", "NEEDS_ACTION"),
        ("RESPONSE_REPORT_RECORDED", "kim-sub", "NEEDS_ACTION", "NEEDS_ACTION"),
        ("RESPONSE_CLEANUP_DECLARED", "kim-sub", "NEEDS_ACTION", "WAITING_VERIFICATION")]
    assert all("rotating next week" not in row[4] for row in audit(repo, item))
    # Only a complete scan started after the answer verifies removal.
    started = NOW + dt.timedelta(minutes=4)
    assert service.observe_scan(repo, item.id, removed=True, observed_at=started, scan_started_at=started)
    for change, code in (({"explanation": "Removed it: synthetic-secret"}, "RESPONSE_REPORT_TEXT_INVALID"),
                         ({"actions": ["REMOVE_PLAINTEXT"]}, "RESPONSE_REPORT_ACTIONS_REQUIRED")):
        with pytest.raises(service.ResponseError, match=code):
            answer(repo, token, statement(**change))
    assert len(reports_of(repo, item)) == 2


def reports_of(repo, item):
    return repo.list_settings(reports.PREFIX + str(item.id) + ":")


def test_an_answer_and_its_report_commit_together(directory, monkeypatch):
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    repo = SqlRepository(engine)
    item = finding(repo)
    contact_setup(repo)
    slack = Slack()
    ask(repo, item, sent=transports(slack))
    token = token_of(slack_text(slack))
    before = service.public(repo, item.id, now=NOW)
    original = SqlRepository.record_finding_event

    def broken(self, event):
        if event.event_type == "RESPONSE_CLEANUP_DECLARED":
            raise RuntimeError("synthetic audit failure")
        return original(self, event)

    monkeypatch.setattr(SqlRepository, "record_finding_event", broken)
    with pytest.raises(RuntimeError, match="synthetic audit failure"):
        answer(repo, token)
    assert service.public(repo, item.id, now=NOW) == before and reports_of(repo, item) == []


def test_a_closed_or_replaced_request_takes_no_answer(repo, directory):
    item = finding(repo)
    contact_setup(repo)
    slack = Slack()
    first = ask(repo, item, sent=transports(slack))
    token = token_of(slack_text(slack))
    head, cycle = service._current(repo, str(item.id))
    for change in ({"state": "COMPLETED"}, {"state": "NEEDS_ACTION", "recurred_at": NOW.isoformat()}):
        repo.put_setting(service.HEAD_PREFIX + str(item.id), {**head, "current": {**cycle, **change}}, "fixture")
        assert service.link_view(repo, TEAM, token, KIM, now=NOW)["can_answer"] is False
        for call in (lambda: answer(repo, token), lambda: service.link_finding(repo, TEAM, token, KIM, now=NOW)):
            with pytest.raises(service.ResponseError) as closed:
                call()
            assert (closed.value.code, closed.value.http_status) == ("RESPONSE_LINK_CLOSED", 409)
    repo.put_setting(service.HEAD_PREFIX + str(item.id), head, "fixture")
    # Unanswered past its end: the request can be asked again, and the new one ends the old link.
    later = NOW + service.LINK_LIFETIME
    shown = service.public(repo, item.id, now=later)
    assert (shown["current"]["link_expired"], shown["can_request"]) == (True, True)
    with pytest.raises(service.ResponseError, match="RESPONSE_ALREADY_PENDING"):
        ask(repo, item, version=first["version"])  # not before then
    again = ask(repo, item, version=first["version"], now=later, sent=transports(slack))
    assert again["current"]["cycle"] == 2 and pointer(repo, token) is None
    with pytest.raises(service.ResponseError) as replaced:
        service.link_view(repo, TEAM, token, KIM, now=later)
    assert replaced.value.code == "RESPONSE_LINK_INVALID"
    assert service.link_view(repo, TEAM, token_of(slack_text(slack)), KIM, now=later)["request"]["cycle"] == 2


def test_the_local_operator_records_the_request_and_then_its_answer(repo):
    item = finding(repo)
    asked = ask(repo, item, channel="record", settings=LOCAL, to="Kim@Example.com")
    assert (asked["state"], asked["current"]["channel"], asked["current"]["link_expires_at"]) == (
        "WAITING_OWNER", "record", None)
    assert audit(repo, item)[0][4].endswith(f"record to=kim@example.com requested_at={NOW.isoformat()}")
    assert repo.list_settings(service.LINK_PREFIX) == []  # nothing was sent: no link
    answered = service.submit_report(repo, LOCAL, item.id, "local-operator", expected_version=asked["version"],
                                     request_id=asked["current"]["request_id"], report_id=uuid.uuid4(),
                                     data=statement(), contains_credentials=lambda _text: False,
                                     now=NOW + dt.timedelta(minutes=2))
    current = answered["current"]
    assert (answered["state"], current["answer"], current["answered_by"]) == (
        "WAITING_VERIFICATION", "APPROVED", "local-operator")
    assert current["report"]["basis"] == "LOCAL_OPERATOR_STATEMENT"
    assert [row[0] for row in audit(repo, item)] == [
        "RESPONSE_REQUESTED", "RESPONSE_REPORT_RECORDED", "RESPONSE_CLEANUP_DECLARED"]


def cycle(repo, item, *, version=3, **fields):
    value = {"request_id": str(uuid.uuid4()), "cycle": 1, "state": "WAITING_OWNER", "completion_version": 2,
             "requested_at": NOW.isoformat(), "requested_by": "analyst", "assigned_to": "kim@example.com", **fields}
    repo.put_setting(service.HEAD_PREFIX + str(item.id), {"version": version, "cycle": 1, "current": value}, "fixture")
    repo.put_setting(service._key(str(item.id), value["request_id"]), value, "fixture")


def test_a_new_request_starts_only_when_the_current_one_can_no_longer_be_answered(repo, directory):
    item = finding(repo)
    contact_setup(repo)
    expires = {"expires_at": (NOW + dt.timedelta(hours=1)).isoformat(), "digest": ""}
    glpi_binding = setup._binding({"system": "glpi", "values": {"url": "https://glpi.acme.test/glpi"}})
    ticket = {"system": "glpi", "binding": glpi_binding, "ticket": "100", "approval": "500", "approver": "42"}
    cases = [
        ({"state": "NOT_SENT", "channel": "slack", "link": expires}, NOW, True),
        ({"channel": "slack", "link": expires}, NOW, False),
        ({"channel": "slack", "link": expires}, NOW + dt.timedelta(hours=1), True),  # its link ended unanswered
        ({"state": "REPORT_REQUIRED", "channel": "mail", "link": expires}, NOW + dt.timedelta(hours=2), True),
        ({"state": "WAITING_VERIFICATION", "channel": "slack", "link": expires}, NOW + dt.timedelta(hours=2), False),
        ({"state": "SENDING", "channel": "slack", "link": expires}, NOW + dt.timedelta(hours=2), False),
        ({"state": "COMPLETED", "channel": "mail", "link": expires}, NOW + dt.timedelta(hours=2), False),
        ({"channel": "record"}, NOW + dt.timedelta(days=30), False),  # the operator records its answer
        # A request asked in a ticket system no longer set up (an old GLPI request after migration 15).
        ({"ticket": ticket}, NOW, True),
        ({"state": "REPORT_REQUIRED", "ticket": ticket}, NOW, True),
        ({"state": "SEND_UNKNOWN", "ticket": ticket}, NOW, False),  # an admin releases an uncertain ticket first
        ({"state": "WAITING_VERIFICATION", "ticket": ticket}, NOW, False),
    ]
    for fields, now, startable in cases:
        cycle(repo, item, **fields)
        assert service.public(repo, item.id, now=now)["can_request"] is startable, (fields, now)
        if not startable:
            with pytest.raises(service.ResponseError, match="RESPONSE_ALREADY_PENDING"):
                ask(repo, item, version=3, now=now)
    # The same old ticket request is not replaceable while the system it was asked in is still the one set up.
    repo.put_setting(setup.SETTING_KEY, {"system": "glpi", "values": {"url": "https://glpi.acme.test/glpi"}}, "fixture")
    cycle(repo, item, ticket=ticket)
    assert service.public(repo, item.id, now=NOW)["can_request"] is False
    repo.put_setting(setup.SETTING_KEY, {}, "migration")
    assert service.public(repo, item.id, now=NOW)["can_request"] is True
    assert ask(repo, item, version=3)["current"]["cycle"] == 2
