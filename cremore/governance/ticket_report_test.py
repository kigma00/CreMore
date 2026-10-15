"""Ticket-native reports: transport -> recipient binding -> immutable statement -> verification, fakes only (a plugin
ticket system whose answer carries the structured report, cremore.ticketing.ticketing_test)."""
import datetime as dt
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest

from cremore.governance import response as service
from cremore.governance import response_reports
from cremore.governance.response_completion_test import prepare, statement
from cremore.governance.response_test import NOW, SETTINGS, ask, events
from cremore.governance.response_test import pg as pg  # noqa: PLC0414
from cremore.governance.response_test import plugin as plugin  # noqa: PLC0414
from cremore.governance.response_test import repo as repo  # noqa: PLC0414
from cremore.ticketing import sweep
from cremore.ticketing.contract import Answer


def reply(repo, finding, asked, data, *, by="42", settings=SETTINGS, state="APPROVED"):
    return service.answered(repo, finding.id, asked["current"]["request_id"],
        Answer(state, by=by, at=(NOW + dt.timedelta(minutes=2)).isoformat(), report=data),
        system="fake", binding=service._current(repo, str(finding.id))[1]["ticket"]["binding"],
        received_at=NOW + dt.timedelta(minutes=3), settings=settings, contains_credentials=lambda t: "synthetic-secret" in t)


def test_native_report_is_one_reply_with_immutable_audit_and_no_automatic_completion(repo):
    finding, server = prepare(repo)
    asked = ask(repo, finding, server, legacy=False)
    assert reply(repo, finding, asked, statement())
    current = service.summary(repo, finding.id)["current"]
    assert current["state"] == "WAITING_VERIFICATION"
    assert current["report"]["basis"] == "TICKET_RECIPIENT_STATEMENT"
    assert current["report"]["by"] == "fake:user:42"
    assert current["report"]["explanation"] == statement()["explanation"]
    assert len(service.report_history(repo, finding.id, asked["current"]["request_id"])["items"]) == 1
    assert any(e.event_type == "RESPONSE_REPORT_RECORDED" for e in events(repo, finding))
    assert all(statement()["explanation"] not in e.note for e in events(repo, finding))
    before = len(events(repo, finding))
    assert not reply(repo, finding, asked, statement())
    assert len(events(repo, finding)) == before


@pytest.mark.parametrize("change", [{"explanation": "Okay"}, {"explanation": "Must not keep the synthetic-secret in the report"},
    {"actions": []}, {"performed_at": "not-a-time"}, {"path": "REPLACED"}, {"replacement_entity_id": "bad"}, {"result": []}, {"path": {}}])
def test_invalid_report_is_not_saved_and_corrected_ticket_reply_is_retried(repo, change):
    finding, server = prepare(repo)
    asked = ask(repo, finding, server, legacy=False)
    assert reply(repo, finding, asked, statement(**change))
    current = service.summary(repo, finding.id)["current"]
    assert current["state"] == "REPORT_REQUIRED" and not current["report"]
    assert len(service.pending(repo)) == 1
    assert not repo.list_settings(response_reports.PREFIX)
    before = len(events(repo, finding))
    assert not reply(repo, finding, asked, statement(**change))
    assert len(events(repo, finding)) == before
    assert reply(repo, finding, asked, statement())
    assert service.summary(repo, finding.id)["state"] == "WAITING_VERIFICATION"


def test_wrong_actor_and_stale_idp_recipient_cannot_submit_ticket_reports(repo, monkeypatch):
    finding, server = prepare(repo)
    asked = ask(repo, finding, server, legacy=False)
    assert not reply(repo, finding, asked, statement(), by="99")
    assert not repo.list_settings(response_reports.PREFIX)
    oidc = SETTINGS.model_copy(update={"auth_mode": "oidc"})
    assert reply(repo, finding, asked, statement(), settings=oidc)
    assert service.summary(repo, finding.id)["current"]["error_code"] == "RESPONSE_REPORT_RECIPIENT_REQUIRED"
    assert not repo.list_settings(response_reports.PREFIX)


def test_adapter_and_worker_ingest_report_and_keep_legacy_execution_approvals_separate(repo):
    finding, server = prepare(repo)
    ask(repo, finding, server, legacy=False)
    server.answer("APPROVED", 42, report=statement())  # the adapter's structured report with the approval
    orchestrator = SimpleNamespace(refresh_rules=lambda: None, engine=SimpleNamespace(scan=lambda request: []))
    assert sweep.sweep(repo, SETTINGS, server.client, now=NOW + dt.timedelta(minutes=3), orchestrator=orchestrator) == 1
    current = service.summary(repo, finding.id)["current"]
    assert current["report"]["actions"] == ["REMOVE_PLAINTEXT", "REVOKE"]
    assert current["state"] == "WAITING_VERIFICATION"
    assert "raw external" not in json.dumps(repo.list_settings(response_reports.PREFIX), default=str)


def test_incomplete_report_remains_needs_action(repo):
    finding, server = prepare(repo)
    asked = ask(repo, finding, server, legacy=False)
    assert reply(repo, finding, asked, statement(result="INCOMPLETE", actions=[]), state="DECLINED")
    assert service.summary(repo, finding.id)["state"] == "NEEDS_ACTION"


def test_worker_refuses_recipient_whose_ticket_account_email_changed(repo):
    finding, server = prepare(repo)
    ask(repo, finding, server, legacy=False)
    server.answer("APPROVED", 42, report=statement())
    server.users = {}  # the ticket directory no longer has the address asked
    assert sweep.sweep(repo, SETTINGS, server.client, now=NOW + dt.timedelta(minutes=3)) == 0
    assert not repo.list_settings(response_reports.PREFIX)
    assert service.summary(repo, finding.id)["current"]["error_code"] == "FAKE_USER_NOT_FOUND"


def test_postgres_concurrent_ticket_replies_record_one_report(pg):
    _engine, repo = pg
    finding, server = prepare(repo)
    asked = ask(repo, finding, server, legacy=False)
    barrier = Barrier(2)

    def receive():
        barrier.wait(timeout=10)
        return reply(repo, finding, asked, statement())

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(receive) for _ in range(2)]
        assert sorted(f.result(timeout=20) for f in futures) == [False, True]
    assert service.report_history(repo, finding.id, asked["current"]["request_id"])["total"] == 1
    assert len([e for e in events(repo, finding) if e.event_type == "RESPONSE_REPORT_RECORDED"]) == 1
