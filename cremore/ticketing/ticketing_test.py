"""The owner's approval asked in a plugin ticket system, against one small synthetic adapter installed as a plugin
(``cremore.ticket_systems`` entry point, allowed by TICKET_SYSTEM_PLUGINS): the setup keeps its secrets sealed, the
ticket asks the owner's own account, the worker records the answer once and only from that account, and the security
side cannot answer as the owner. No ticket system is built in."""

import datetime as dt
import json
import uuid

import pytest

from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import ActionPlan
from cremore.onboarding.onboarding_test import SETTINGS
from cremore.remediation import owner_approval as oa
from cremore.ticketing import registry, setup
from cremore.ticketing import sweep as ticket_sweep
from cremore.ticketing.contract import (
    Answer,
    ApprovalRequest,
    Approver,
    Field,
    Opened,
    TicketError,
    TicketSystemProvider,
)

TARGET = uuid.uuid5(uuid.NAMESPACE_URL, "cremore:ticket_system")
TOKEN = "fake-token-" + "t" * 16  # built at run time: nothing secret-shaped sits in the source
SETUP = {"system": "fake", "values": {"url": "https://tickets.acme.test/", "queue": "3"},
         "secrets": {"token": TOKEN}}
NOW = dt.datetime(2026, 9, 30, 3, 0, tzinfo=dt.UTC)


class Tickets:
    """A ticket system's state: its accounts by address, the tickets CreMore opened, and how each was answered.
    ``fail``: a step (``find``, ``open``, ``approval``, ``answer:<ticket>``, ``check``) that raises its error."""

    def __init__(self, *, users=None, fail=None):
        self.users = {"kim@example.com": ("42", ("kim@example.com",))} if users is None else users
        self.fail, self.tickets, self.answers, self.seen = dict(fail or {}), {}, {}, []

    def client(self):
        return _Client(self)

    def answer(self, state, by, report=None):
        """The newest approval asked is answered, with the system's own free comment (never kept by CreMore)."""
        self.answers[list(self.answers)[-1]] = Answer(state=state, by=str(by), at="2026-09-30T04:05:06+00:00",
                                                      comment="raw external comment", report=report)


class _Client:
    """What CreMore hands the adapter as its HTTP client: here, the way to the synthetic system."""

    def __init__(self, server):
        self.server = server

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        pass


class _System:
    def __init__(self, server, values, secrets):
        assert secrets == {"token": TOKEN}  # opened from the sealed setup for this call only
        self.server, self.url = server, values["url"]

    def _step(self, name):
        self.server.seen.append(name)
        if name in self.server.fail:
            raise self.server.fail[name]

    def check(self):
        self._step("check")

    def find_approver(self, address):
        self._step("find")
        found = self.server.users.get(address.lower())
        if not found:
            raise TicketError("FAKE_USER_NOT_FOUND")
        return Approver(*found)

    def open_approval(self, request, approver):
        self._step("open")
        number = str(100 + len(self.server.tickets))
        self.server.tickets[number] = request
        if "approval" in self.server.fail:  # the ticket opened, the approval in it did not
            error = self.server.fail["approval"]
            raise TicketError(error.code, retryable=error.retryable, ticket=number)
        approval = str(500 + len(self.server.answers))
        self.server.answers[(number, approval)] = Answer(state="WAITING")
        return Opened(number, approval, approver.id, url=f"{self.url}/ticket/{number}")

    def answer(self, opened):
        self._step("answer:" + opened.ticket)
        return self.server.answers[(opened.ticket, opened.approval)]

    def close(self):
        pass


def _validate(values):
    url = values.get("url")
    if not isinstance(url, str) or not url.startswith("https://") or "@" in url:
        raise ValueError("FAKE_URL_INVALID")
    return {"url": url.rstrip("/"), "queue": int(values["queue"]) if values.get("queue") else None}


PROVIDER = TicketSystemProvider(
    id="fake", label="Fake tickets", validate=_validate,
    fields=(Field("url", "Address", "주소", "url"), Field("queue", "Queue", "큐", "number", required=False),
            Field("token", "API token", "API 토큰", "secret")),
    build=lambda values, secrets, client: _System(client.server, values, secrets))


class _Entry:
    name = "fake"

    def load(self):
        return PROVIDER


def install(monkeypatch):
    """The fake adapter as an installed package's entry point the installation allows."""
    monkeypatch.setattr(registry, "entry_points", lambda group: [_Entry()] if group == registry.ENTRY_POINT_GROUP else [])
    monkeypatch.setenv(registry.PLUGINS_ENV, "fake")


@pytest.fixture(autouse=True)
def plugin(monkeypatch):
    install(monkeypatch)


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def plan(**changes):
    fields = {"status": "APPROVED", "plan_hash": "a" * 64, "expires_at": NOW + dt.timedelta(days=7),
              "requested_by": "sub-rita", "approved_by": "sub-ada", "idempotency_key": str(uuid.uuid4()), **changes}
    return ActionPlan(id=uuid.uuid4(), credential_id=uuid.uuid4(), action_type="DISABLE_ACCESS_KEY",
                      identifier_hint="AKIA…<b>WXYZ</b>", user_name="deploy-bot", account_id="123456789012",
                      reason_code="EXPOSURE_CONTAINMENT", **fields)


def audited(repo):
    if isinstance(repo, InMemoryRepository):
        rows = [(e.event_type, e.actor, e.note) for e in repo.finding_events.values()]
    else:
        from sqlalchemy import select

        from cremore.db.schema import finding_events
        with repo.engine.connect() as conn:
            rows = [(row.event_type, row.actor, row.note) for row in conn.execute(select(finding_events))]
    return [row for row in rows if row[0].startswith("OWNER_APPROVAL")]


def ask(repo, target, server, *, to="kim@example.com", request=None, marks=("m",)):
    """What the request route does: find the account, record and audit, open the ticket, keep its references."""
    request = request or str(uuid.uuid4())
    expires = oa.window(repo, target, NOW)
    title, lines = oa.ticket_message(target, expires, "ko")
    system, name, binding = setup.open_system(repo, SETTINGS, server.client())
    approver = system.find_approver(to)
    oa.start_ticket(repo, target, "sub-rita", system=name, binding=binding, recipient=to,
                    recipient_marks=marks, request=request, expires=expires, now=NOW, note=f"{name} · to={to}")
    opened = system.open_approval(ApprovalRequest(title=title, lines=lines), approver)
    oa.ticket_opened(repo, target, request, name, opened, "sub-rita")
    return request, opened


def test_no_ticket_system_is_built_in_and_a_plugin_is_offered_only_when_allowed(monkeypatch):
    monkeypatch.delenv(registry.PLUGINS_ENV)
    assert registry.available() == []
    with pytest.raises(ValueError, match="TICKET_SYSTEM_UNAVAILABLE"):
        registry.load("glpi")  # the removed built-in one (its setup is deleted by migration 15)
    monkeypatch.setenv(registry.PLUGINS_ENV, "fake")
    assert registry.available() == ["fake"] and registry.load("fake") is PROVIDER


def test_the_setup_seals_its_secrets_and_keeps_them_only_for_the_same_server(repo):
    view, note = setup.save(repo, SETTINGS, SETUP, "ada", TARGET)
    stored = json.dumps(repo.get_setting(setup.SETTING_KEY), default=str)
    assert TOKEN not in stored + json.dumps(view) + note
    assert view["current"] == {"system": "fake", "secrets_saved": ["token"],
                               "values": {"url": "https://tickets.acme.test", "queue": 3}}
    assert [item["name"] for item in view["systems"][0]["fields"]] == ["url", "queue", "token"]
    assert note == "system=fake url=https://tickets.acme.test queue=3 secrets=token replaced"
    # A blank secret keeps the saved one for the same address and sign-in values, not for another server.
    kept, note = setup.save(repo, SETTINGS, {**SETUP, "values": {**SETUP["values"], "queue": "7"}, "secrets": {}},
                            "ada", TARGET)
    assert kept["current"]["values"]["queue"] == 7 and note.endswith("secrets=kept")
    with pytest.raises(setup.SetupError) as refused:
        setup.save(repo, SETTINGS, {**SETUP, "values": {"url": "https://tickets.other.test"}, "secrets": {}}, "ada", TARGET)
    assert refused.value.code == "TICKET_SYSTEM_SECRET_REQUIRED"
    with pytest.raises(setup.SetupError) as refused:
        setup.save(repo, SETTINGS, {**SETUP, "values": {"url": "ftp://tickets.acme.test"}}, "ada", TARGET)
    assert refused.value.code == "FAKE_URL_INVALID"  # the adapter's own validation code
    # The system and the server a request is bound to come from one reading of the setup.
    ready = setup.open_system(repo, SETTINGS, Tickets().client())
    assert (ready.name, ready.binding) == ("fake", setup.binding(repo))
    for system in ("servicenow", "glpi"):
        with pytest.raises(setup.SetupError) as refused:
            setup.save(repo, SETTINGS, {"system": system, "values": {}}, "ada", TARGET)
        assert refused.value.code == "TICKET_SYSTEM_UNAVAILABLE"
    off, note = setup.save(repo, SETTINGS, {"system": None}, "ada", TARGET)
    assert off["current"] is None and setup.configured(repo) is None and note == "system=off (was fake)"


def test_a_ticket_asks_the_owners_own_account_and_its_answer_is_read_back(repo):
    setup.save(repo, SETTINGS, SETUP, "ada", TARGET)
    server = Tickets()
    target = plan()
    _request, opened = ask(repo, target, server)
    assert opened == Opened(ticket="100", approval="500", approver="42", url="https://tickets.acme.test/ticket/100")
    [ticket] = server.tickets.values()
    assert ticket.title == "[CreMore] AWS 액세스 키 조치 승인 요청 · AKIA…<b>WXYZ</b>"  # plain text: the adapter escapes
    shown = oa.current(repo, target.id, NOW)
    assert shown["state"] == "PENDING" and shown["channel"] == "fake" and shown["ticket"] == {
        "system": "fake", "ticket": "100", "approval": "500", "check_code": None, "answered_by": None,
        "answered_at": None, "url": "https://tickets.acme.test/ticket/100"}
    assert [row[:2] for row in audited(repo)] == [("OWNER_APPROVAL_REQUESTED", "sub-rita"),
                                                  ("OWNER_APPROVAL_TICKET_OPENED", "sub-rita")]
    assert audited(repo)[1][2] == f"plan_hash={'a' * 64} fake ticket=100 approval=500 approver=42"


def test_the_worker_records_the_owners_answer_once_and_only_from_the_account_asked(repo):
    setup.save(repo, SETTINGS, SETUP, "ada", TARGET)
    server = Tickets()
    target = repo.create_action_plan(plan())
    ask(repo, target, server)

    def run(minute):
        return ticket_sweep.sweep(repo, SETTINGS, server.client, now=NOW + dt.timedelta(minutes=minute))

    assert run(0) == 0 and oa.current(repo, target.id, NOW)["state"] == "PENDING"  # still waiting
    server.answer("APPROVED", 42)
    assert run(0) == 0  # one worker per minute
    assert run(1) == 1
    shown = oa.current(repo, target.id, NOW)
    assert (shown["state"], shown["decided_by"], shown["evidence"]) == ("APPROVED", "fake:user:42",
                                                                         "fake ticket #100 approval #500")
    assert oa.granted(repo, target) and not oa.needed(repo, target)
    assert audited(repo)[-1] == ("OWNER_APPROVAL_GRANTED", "fake:user:42",
                                 (f"plan_hash={'a' * 64} channel=fake to=kim@example.com fake ticket=100 approval=500 "
                                  "answered_at=2026-09-30T04:05:06+00:00"))
    reads = len(server.seen)
    assert run(2) == 0 and len(audited(repo)) == 3 and len(server.seen) == reads  # recorded once, then not read

    # Someone else answered (a substitute, a group member): not the owner's decision; the owner is asked again.
    other = repo.create_action_plan(plan())
    ask(repo, other, server)
    server.answer("APPROVED", 77)
    assert run(3) == 1
    assert oa.current(repo, other.id, NOW)["state"] == "ANSWERED_BY_OTHER" and not oa.granted(repo, other)
    assert audited(repo)[-1][:2] == ("OWNER_APPROVAL_TICKET_REFUSED", oa.ACTOR)
    assert audited(repo)[-1][2].endswith("answer=APPROVED by=77 asked=42")
    assert oa.current(repo, target.id, NOW)["state"] == "APPROVED"  # the first plan's answer stands


def test_an_answer_is_not_taken_for_a_changed_plan_an_ended_request_or_a_failed_read(repo):
    setup.save(repo, SETTINGS, SETUP, "ada", TARGET)
    server = Tickets()
    target = repo.create_action_plan(plan())
    request, _opened = ask(repo, target, server)
    server.fail["answer:100"] = TicketError("FAKE_UNAVAILABLE", retryable=True)
    ticket_sweep.sweep(repo, SETTINGS, server.client, now=NOW)
    assert oa.current(repo, target.id, NOW)["ticket"]["check_code"] == "FAKE_UNAVAILABLE"  # shown, read again later
    del server.fail["answer:100"]
    ticket_sweep.sweep(repo, SETTINGS, server.client, now=NOW + dt.timedelta(minutes=1))
    assert oa.current(repo, target.id, NOW)["ticket"]["check_code"] is None  # the read worked again
    changed = target.model_copy(update={"plan_hash": "b" * 64})
    assert oa.ticket_answered(repo, str(target.id), request, Answer(state="APPROVED", by="42"), NOW,
                              lambda _id: changed) is None
    assert oa.current(repo, target.id, NOW)["state"] == "PENDING"  # the plan changed: nothing to decide
    late = NOW + oa.LINK_LIFETIME + dt.timedelta(minutes=1)
    server.answer("APPROVED", 42)  # too late
    assert oa.pending_tickets(repo, late) == []  # an ended request is not read any more
    assert ticket_sweep.sweep(repo, SETTINGS, server.client, now=late) == 0
    assert oa.current(repo, target.id, late)["state"] == "EXPIRED" and not oa.granted(repo, target)


def test_a_request_asked_on_another_server_or_a_system_no_longer_set_up_is_not_read(repo):
    setup.save(repo, SETTINGS, SETUP, "ada", TARGET)
    server = Tickets()
    target = repo.create_action_plan(plan())
    ask(repo, target, server)
    server.answer("APPROVED", 42)
    # An admin points CreMore at another server, whose ticket 100 and approval 500 are other things.
    setup.save(repo, SETTINGS, {**SETUP, "values": {**SETUP["values"], "url": "https://tickets.other.test"}}, "ada", TARGET)
    assert ticket_sweep.sweep(repo, SETTINGS, server.client, now=NOW) == 0
    shown = oa.current(repo, target.id, NOW)
    assert (shown["state"], shown["ticket"]["check_code"]) == ("PENDING", "TICKET_SYSTEM_CHANGED")
    # A system no longer set up (a removed adapter's setup deleted): nothing is read; the request waits out its time.
    repo.put_setting(setup.SETTING_KEY, {}, "migration")
    assert ticket_sweep.sweep(repo, SETTINGS, server.client, now=NOW + dt.timedelta(minutes=1)) == 0
    assert oa.current(repo, target.id, NOW)["ticket"]["check_code"] == "TICKET_SYSTEM_NOT_SET_UP"
    assert oa.current(repo, target.id, NOW + oa.LINK_LIFETIME)["state"] == "EXPIRED"


def test_the_minute_stops_when_the_system_does_not_answer_and_one_fault_never_stops_the_rest(repo):
    setup.save(repo, SETTINGS, SETUP, "ada", TARGET)
    server = Tickets()
    first, second = repo.create_action_plan(plan()), repo.create_action_plan(plan())
    ask(repo, first, server)
    ask(repo, second, server)
    down = TicketError("FAKE_UNAVAILABLE", retryable=True)
    server.fail.update({"answer:100": down, "answer:101": down})
    reads = len(server.seen)
    ticket_sweep.sweep(repo, SETTINGS, server.client, now=NOW)
    assert len(server.seen) == reads + 1  # the first read found the system down: no second wait this minute
    server.fail.clear()
    # A time budget: once spent, the rest waits for the next minute.
    ticks = iter([0, 100])
    reads = len(server.seen)
    ticket_sweep.sweep(repo, SETTINGS, server.client, now=NOW + dt.timedelta(minutes=1), clock=lambda: next(ticks))
    assert len(server.seen) == reads
    # One request's fault (not the system's) is logged and the others are still read.
    server.answer("APPROVED", 42)  # the second plan's owner approves

    def flaky(repo_, plan_id, *args, **kwargs):
        if plan_id == str(first.id):
            raise RuntimeError("store fault")
        return original(repo_, plan_id, *args, **kwargs)

    original, oa.ticket_answered = oa.ticket_answered, flaky
    try:
        assert ticket_sweep.sweep(repo, SETTINGS, server.client, now=NOW + dt.timedelta(minutes=2)) == 1
    finally:
        oa.ticket_answered = original


def test_with_company_sign_in_an_answer_the_security_side_could_have_given_is_not_the_owners(repo):
    from cremore.governance import principals

    setup.save(repo, SETTINGS, SETUP, "ada", TARGET)
    server = Tickets()
    for subject in ("sub-rita", "sub-ada"):
        principals.remember(repo, SETTINGS, subject, subject.removeprefix("sub-") + "@example.com")
    ada = principals.mark(SETTINGS, "ada@example.com")  # ada approved the plan
    target = repo.create_action_plan(plan())
    ask(repo, target, server, marks=(principals.mark(SETTINGS, "kim@example.com"), ada))  # kim's account carries ada's
    server.answer("DECLINED", 42)
    oidc = SETTINGS.model_copy(update={"auth_mode": "oidc"})
    assert ticket_sweep.sweep(repo, oidc, server.client, now=NOW) == 1
    assert oa.current(repo, target.id, NOW)["state"] == "NOT_INDEPENDENT"  # not a decision: the owner is asked again
    assert audited(repo)[-1][2].endswith("answer=DECLINED reason=SECURITY_SIDE_OR_UNKNOWN_ADDRESS")
