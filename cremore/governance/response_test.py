"""Completion declarations, durable ticket sends and fresh scan evidence, using fakes only (a plugin ticket system,
cremore.ticketing.ticketing_test)."""
import datetime as dt
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from cremore.db.postgres_scan_test import (
    pg,  # noqa: F401 -- reuse the guarded disposable PostgreSQL fixture
)
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.governance import response as service
from cremore.governance.tickets_test import seed
from cremore.onboarding.onboarding_test import SETTINGS
from cremore.ticketing import setup, sweep
from cremore.ticketing.contract import Answer, Approver, Opened, TicketError
from cremore.ticketing.ticketing_test import NOW, SETUP, TARGET, Tickets, plan
from cremore.ticketing.ticketing_test import ask as ask_owner
from cremore.ticketing.ticketing_test import (
    plugin as plugin,  # noqa: PLC0414 -- the installed fake adapter
)


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    yield_repo = SqlRepository(engine)
    return yield_repo


def prepare(repo):
    _, _, finding, _ = seed(repo=repo)
    setup.save(repo, SETTINGS, SETUP, "admin", TARGET)
    return finding, Tickets()


def ask(repo, finding, server, *, request_id=None, version=0, now=NOW, legacy=True):
    with server.client() as client:
        result = service.request_ticket(repo, SETTINGS, finding.id, "analyst", to="Kim@Example.com",
                                      expected_version=version, request_id=request_id or uuid.uuid4(),
                                      now=now, http_client=client)
    if legacy:
        # Existing removal-only cycles retain their historical contract after upgrade.
        head, cycle = service._current(repo, str(finding.id))
        cycle = {k: v for k, v in cycle.items() if k != "completion_version"}
        repo.put_setting(service.HEAD_PREFIX + str(finding.id), {**head, "current": cycle}, "fixture")
        repo.put_setting(service._key(str(finding.id), cycle["request_id"]), cycle, "fixture")
        result = service.public(repo, finding.id)
    return result


def answer(repo, finding, asked, state="APPROVED", *, now=NOW + dt.timedelta(minutes=1), by="42"):
    return service.answered(repo, finding.id, asked["current"]["request_id"],
                            Answer(state, by=by, at="2026-09-30T03:00:10Z", comment="raw external secret omitted"),
                            system="fake", binding=setup.binding(repo), received_at=now)


def scan(repo, finding, *, removed, start=NOW + dt.timedelta(minutes=2), authoritative=True):
    return service.observe_scan(repo, finding.id, removed=removed, observed_at=start + dt.timedelta(seconds=10),
                                scan_started_at=start, authoritative=authoritative, scan_id="scan-1")


def events(repo, finding):
    return [event for event in repo.list_finding_events(finding.id) if event.event_type.startswith("RESPONSE_")]


def test_completion_is_only_a_declaration_until_a_fresh_complete_scan(repo):
    finding, server = prepare(repo)
    assert service.public(repo, finding.id)["state"] == "NEW"
    asked = ask(repo, finding, server)
    assert asked["state"] == "WAITING_OWNER" and asked["version"] == 2
    assert "실행 승인이 아닙니다" in str(next(iter(server.tickets.values())))
    assert "github / GITHUB_PAT" in str(next(iter(server.tickets.values())))
    assert "Masked identifier: ghp_••••" in str(next(iter(server.tickets.values())))
    # The ticket carries the playbook: GitHub's revocation guide with its link.
    assert "조치 방법(플레이북)" in str(next(iter(server.tickets.values())))
    assert "https://github.com/settings/tokens" in str(next(iter(server.tickets.values())))
    assert repo.get_finding(finding.id).assigned_to is None
    assert not scan(repo, finding, removed=True)  # answer not received
    assert answer(repo, finding, asked)
    assert not answer(repo, finding, asked)
    waiting = service.public(repo, finding.id)
    assert waiting["state"] == "WAITING_VERIFICATION"
    assert waiting["current"]["answered_at"] == "2026-09-30T03:00:10+00:00"
    assert waiting["current"]["received_at"] == "2026-09-30T03:01:00+00:00"
    assert not scan(repo, finding, removed=True, start=NOW)  # in-flight scan predates receipt
    assert not scan(repo, finding, removed=True, start=NOW + dt.timedelta(minutes=1))  # equality is not fresh
    assert not scan(repo, finding, removed=True, authoritative=False)
    assert not service.observe_scan(repo, finding.id, removed=True, observed_at=NOW + dt.timedelta(hours=1))
    assert scan(repo, finding, removed=True)
    assert not scan(repo, finding, removed=True)
    assert service.public(repo, finding.id)["state"] == "REMOVED"
    assert repo.get_finding(finding.id).workflow_status == "OPEN"  # removal is not key retirement
    assert not scan(repo, finding, removed=False, start=NOW)  # late result from an old scan
    assert scan(repo, finding, removed=False, start=NOW + dt.timedelta(minutes=3))
    assert service.public(repo, finding.id)["state"] == "NEEDS_ACTION"
    history = events(repo, finding)
    assert [event.event_type for event in history] == [
        "RESPONSE_REQUESTED", "RESPONSE_TICKET_OPENED", "RESPONSE_CLEANUP_DECLARED",
        "RESPONSE_REMOVAL_VERIFIED", "RESPONSE_REAPPEARED"]
    assert "to=kim@example.com" in history[0].note
    assert "ticket=100 approval=500 approver=42" in history[1].note
    assert "received_at=2026-09-30T03:01:00+00:00" in history[2].note
    assert "scan_started_at=" in history[3].note
    stored = json.dumps(repo.list_settings(service.CYCLE_PREFIX), default=str)
    assert "raw external secret omitted" not in stored
    assert "binding" not in json.dumps(service.public(repo, finding.id))


def test_still_exposed_and_declined_start_new_linked_cycles_without_overwriting_history(repo):
    finding, server = prepare(repo)
    first = ask(repo, finding, server)
    assert answer(repo, finding, first)
    assert scan(repo, finding, removed=False)
    current = service.public(repo, finding.id)
    second = ask(repo, finding, server, version=current["version"])
    assert second["current"]["cycle"] == 2
    assert second["current"]["previous_request_id"] == first["current"]["request_id"]
    assert "ticket: 100" in str(server.tickets["101"])
    assert answer(repo, finding, second, "DECLINED")
    result = service.public(repo, finding.id)
    assert result["state"] == "NEEDS_ACTION" and result["history_total"] == 2
    assert result["history"][1]["request_id"] == first["current"]["request_id"]
    assert result["history"][1]["received_at"] is not None


def test_request_id_is_idempotent_and_stale_version_cannot_send(repo):
    finding, server = prepare(repo)
    request_id = uuid.uuid4()
    asked = ask(repo, finding, server, request_id=request_id)
    server.seen.clear()
    assert ask(repo, finding, server, request_id=request_id) == asked
    assert server.seen == []
    with pytest.raises(service.ResponseError, match="RESPONSE_CHANGED"):
        ask(repo, finding, server)
    assert server.seen == []
    with pytest.raises(service.ResponseError, match="RESPONSE_ALREADY_PENDING"):
        ask(repo, finding, server, version=asked["version"])
    assert len(server.tickets) == 1 and server.seen == []


def test_fresh_cleanup_after_more_action_is_needed_does_not_require_another_ticket(repo):
    finding, server = prepare(repo)
    asked = ask(repo, finding, server)
    assert answer(repo, finding, asked)
    assert scan(repo, finding, removed=False)
    assert service.public(repo, finding.id)["state"] == "NEEDS_ACTION"
    assert not scan(repo, finding, removed=False, start=NOW + dt.timedelta(minutes=3))
    assert not scan(repo, finding, removed=True)  # same older scan cannot undo its positive observation
    assert scan(repo, finding, removed=True, start=NOW + dt.timedelta(minutes=3))
    assert not scan(repo, finding, removed=True, start=NOW + dt.timedelta(minutes=4))
    assert service.public(repo, finding.id)["state"] == "REMOVED"
    assert len(server.tickets) == 1


def test_same_scan_new_location_positive_dominates_earlier_absence(repo):
    finding, server = prepare(repo)
    asked = ask(repo, finding, server)
    assert answer(repo, finding, asked)
    assert scan(repo, finding, removed=True)
    assert scan(repo, finding, removed=False)  # same scan start/id, discovered at a later location
    assert service.public(repo, finding.id)["state"] == "NEEDS_ACTION"
    assert not scan(repo, finding, removed=True)  # later old-location cleanup cannot erase that positive


def test_wrong_account_and_changed_server_do_not_declare_completion(repo):
    finding, server = prepare(repo)
    asked = ask(repo, finding, server)
    assert not answer(repo, finding, asked, by="43")
    assert service.public(repo, finding.id)["current"]["error_code"] == "RESPONSE_ANSWERED_BY_OTHER"
    assert not service.answered(repo, finding.id, asked["current"]["request_id"], Answer("APPROVED", by="42"),
                               system="fake", binding="other", received_at=NOW + dt.timedelta(minutes=1))
    assert service.public(repo, finding.id)["state"] == "WAITING_OWNER"
    assert answer(repo, finding, asked)


def test_unknown_send_cannot_retry_until_explicit_operator_assertion(repo):
    finding, server = prepare(repo)
    # Ticket exists, but creation of its approval failed: outcome needs a human.
    server.fail["approval"] = TicketError("FAKE_UNAVAILABLE", retryable=True)
    unknown = ask(repo, finding, server)
    assert unknown["state"] == "SEND_UNKNOWN" and unknown["current"]["ticket"]["ticket"] == "100"
    with pytest.raises(service.ResponseError, match="RESPONSE_ALREADY_PENDING"):
        ask(repo, finding, server, version=unknown["version"])
    with pytest.raises(service.ResponseError, match="RESPONSE_CONFIRMATION_REQUIRED"):
        service.release_unknown(repo, finding.id, "admin", expected_version=unknown["version"],
                                request_id=unknown["current"]["request_id"], confirmed_no_pending_ticket=False)
    released = service.release_unknown(repo, finding.id, "admin", expected_version=unknown["version"],
                                       request_id=unknown["current"]["request_id"], confirmed_no_pending_ticket=True)
    assert released["state"] == "NEEDS_ACTION"
    assert released["current"]["release_basis"] == "OPERATOR_CONFIRMED_NO_PENDING_TICKET"
    del server.fail["approval"]
    next_request = ask(repo, finding, server, version=released["version"])
    assert next_request["state"] == "WAITING_OWNER" and len(server.tickets) == 2
    assert next_request["history"][1]["error_code"] == "FAKE_UNAVAILABLE"


def test_sending_crash_expires_without_resend_and_late_result_cannot_overwrite_next_cycle(repo, monkeypatch):
    finding, server = prepare(repo)
    original = service._finish_send
    monkeypatch.setattr(service, "_finish_send", lambda *args, **kwargs: None)  # simulated crash after remote write
    sending = ask(repo, finding, server)
    assert sending["state"] == "SENDING"
    monkeypatch.setattr(service, "_finish_send", original)
    assert service.pending(repo, now=NOW + dt.timedelta(minutes=4)) == []
    assert service.public(repo, finding.id)["state"] == "SENDING"
    assert service.pending(repo, now=NOW + dt.timedelta(minutes=6)) == []
    unknown = service.public(repo, finding.id)
    assert unknown["state"] == "SEND_UNKNOWN" and len(server.tickets) == 1
    released = service.release_unknown(repo, finding.id, "admin", expected_version=unknown["version"],
                                       request_id=unknown["current"]["request_id"], confirmed_no_pending_ticket=True)
    next_request = ask(repo, finding, server, version=released["version"])
    original(repo, str(finding.id), sending["current"]["request_id"], "analyst",
             refs={"ticket": "100", "approval": "500", "url": None})
    final = service.public(repo, finding.id)
    assert final["current"]["request_id"] == next_request["current"]["request_id"]
    assert final["history"][1]["ticket"]["ticket"] == "100"
    assert events(repo, finding)[-1].event_type == "RESPONSE_LATE_TICKET_OPENED"


def test_sweep_reads_cleanup_responses_without_action_plans(repo):
    finding, server = prepare(repo)
    ask(repo, finding, server)
    server.answer("APPROVED", 42)
    assert sweep.sweep(repo, SETTINGS, server.client, now=NOW + dt.timedelta(minutes=1)) == 1
    assert service.public(repo, finding.id)["state"] == "WAITING_VERIFICATION"
    assert sweep.sweep(repo, SETTINGS, server.client, now=NOW + dt.timedelta(minutes=2)) == 0


def test_summaries_are_one_batch_without_history_or_per_finding_reads(repo, monkeypatch):
    finding, server = prepare(repo)
    ask(repo, finding, server)
    monkeypatch.setattr(repo, "get_finding", lambda *_: pytest.fail("per-finding read"))
    monkeypatch.setattr(repo, "get_setting", lambda *_: pytest.fail("per-setting read"))
    result = service.summaries(repo, [finding])
    assert result[str(finding.id)]["state"] == "WAITING_OWNER"
    assert "history" not in result[str(finding.id)]


def test_verification_watch_keeps_removed_paths_until_response_verification(repo):
    finding, server = prepare(repo)
    asked = ask(repo, finding, server)
    assert service.verification_credentials(repo) == set()
    assert answer(repo, finding, asked)
    assert service.verification_credentials(repo) == {finding.credential_id}
    assert scan(repo, finding, removed=False)
    assert service.verification_credentials(repo) == {finding.credential_id}
    assert scan(repo, finding, removed=True, start=NOW + dt.timedelta(minutes=3))
    assert service.verification_credentials(repo) == set()


def _race_requests(repo, monkeypatch):
    finding, _server = prepare(repo)
    barrier, opened = Barrier(2), []

    class Adapter:
        def find_approver(self, _address):
            barrier.wait(timeout=5)
            return Approver("42", ("kim@example.com",))

        def open_approval(self, request, approver):
            opened.append(request)
            return Opened("100", "500", approver.id)

        def close(self):
            pass

    monkeypatch.setattr(setup, "open_system", lambda repo, settings, client:
                        setup.Ready(Adapter(), "fake", setup.binding(repo)))

    def run():
        try:
            return service.request_ticket(repo, SETTINGS, finding.id, "analyst", to="kim@example.com",
                expected_version=0, request_id=uuid.uuid4(), now=NOW, http_client=None)["state"]
        except service.ResponseError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: run(), range(2)))
    assert sorted(results) == ["RESPONSE_CHANGED", "WAITING_OWNER"]
    assert len(opened) == 1 and len(events(repo, finding)) == 2


def test_concurrent_callers_send_exactly_one_ticket(monkeypatch):
    _race_requests(InMemoryRepository(), monkeypatch)


def test_postgres_concurrent_requests_and_scan_transitions_are_once(pg, monkeypatch):  # noqa: F811 -- pytest fixture
    _engine, repo = pg
    _race_requests(repo, monkeypatch)
    finding = repo.list_findings()[0]
    asked = service.public(repo, finding.id)
    assert answer(repo, finding, asked)
    barrier = Barrier(2)

    def observe():
        barrier.wait(timeout=5)
        return scan(repo, finding, removed=True)

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: observe(), range(2))) == [False, True]
    assert sum(event.event_type == "RESPONSE_REMOVAL_VERIFIED" for event in events(repo, finding)) == 1


def test_sweep_stops_all_ticket_reads_after_a_retryable_owner_approval_error(repo):
    finding, server = prepare(repo)
    ask_owner(repo, plan(), server)
    ask(repo, finding, server)
    server.seen.clear()
    server.fail["answer:100"] = TicketError("FAKE_UNAVAILABLE", retryable=True)
    assert sweep.sweep(repo, SETTINGS, server.client, now=NOW + dt.timedelta(minutes=1)) == 0
    assert "answer:101" not in server.seen
    assert service.public(repo, finding.id)["state"] == "WAITING_OWNER"


def test_sweep_resumes_fairly_after_owner_reads_consume_the_budget(repo):
    finding, server = prepare(repo)
    ask_owner(repo, plan(), server)
    ask(repo, finding, server)
    server.answer("APPROVED", 42)  # only the response request, not the earlier key-action approval
    ticks = iter([0, 0, 21])
    assert sweep.sweep(repo, SETTINGS, server.client, now=NOW + dt.timedelta(minutes=1),
                       clock=lambda: next(ticks)) == 0
    assert service.public(repo, finding.id)["state"] == "WAITING_OWNER"
    # The next minute starts after that owner request, so cleanup cannot starve.
    ticks = iter([0, 0, 21])
    assert sweep.sweep(repo, SETTINGS, server.client, now=NOW + dt.timedelta(minutes=2),
                       clock=lambda: next(ticks)) == 1
    assert service.public(repo, finding.id)["state"] == "WAITING_VERIFICATION"


def test_sql_transition_and_audit_rollback_together(monkeypatch):
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    repo = SqlRepository(engine)
    finding, server = prepare(repo)
    asked = ask(repo, finding, server)
    original = SqlRepository.record_finding_event

    def broken(self, event):
        if event.event_type == "RESPONSE_CLEANUP_DECLARED":
            raise RuntimeError("synthetic audit failure")
        return original(self, event)

    monkeypatch.setattr(SqlRepository, "record_finding_event", broken)
    with pytest.raises(RuntimeError, match="synthetic audit failure"):
        answer(repo, finding, asked)
    assert service.public(repo, finding.id) == asked


def test_ticket_url_never_preserves_embedded_sign_in_values():
    assert service._url("https://tickets.example.test/ticket/1") == "https://tickets.example.test/ticket/1"
    assert service._url("https://:synthetic-password@tickets.example.test/ticket/1") is None
    assert service._url("https://name@tickets.example.test/ticket/1") is None
    assert service._url("https://name:synthetic-password@tickets.example.test/ticket/1") is None
