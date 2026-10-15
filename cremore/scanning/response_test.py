"""Fresh, complete scans drive cleanup verification inside the scan transaction."""

import datetime as dt
import uuid
from dataclasses import replace
from unittest.mock import patch

import pytest

from cremore.collectors.base import CollectedObject
from cremore.collectors.bytes_source import BytesCollector
from cremore.config import Settings
from cremore.db import task_store
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- pytest fixture re-export
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.db.task_store import LeaseLost, TaskStore
from cremore.detection import ResourceRef
from cremore.domain.models import ScanJob
from cremore.governance import contact, response
from cremore.scanning import Orchestrator
from cremore.scanning.service import ScanService
from cremore.ticketing.contract import Answer, Approver, Opened

TOKEN = ("ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4").encode()
NOW = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=10)
RESOURCE = ResourceRef(source_type="github", resource="synthetic/repo", location="config.env")


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def repo(request):
    if request.param == "memory":
        yield InMemoryRepository()
    elif request.param == "sqlite":
        engine = make_engine("sqlite:///:memory:")
        create_all(engine)
        try:
            yield SqlRepository(engine)
        finally:
            engine.dispose()
    else:
        yield request.getfixturevalue("pg")[1]


class Tickets:
    def find_approver(self, address):
        return Approver("synthetic-owner", (address,))

    def open_approval(self, message, approver):
        return Opened("synthetic-ticket", "synthetic-approval", approver.id)

    def close(self):
        pass


def request(repo, monkeypatch, finding):
    repo.assign_finding(finding.id, "responder@example.test")
    repo.put_setting(contact.SETTING_KEY, {"allowed_domains": ["example.test"]}, "test")
    monkeypatch.setattr(response.setup, "open_system", lambda *args: (Tickets(), "synthetic", "binding"))
    monkeypatch.setattr(response.setup, "binding", lambda repo: "binding")
    request_id = str(uuid.uuid4())
    response.request_ticket(repo, Settings(), finding.id, "analyst", to="responder@example.test", now=NOW,
                            expected_version=0, request_id=request_id, http_client=object())
    # Persisted v1 removal-only cycles remain supported across the completion upgrade.
    head, cycle = response._current(repo, str(finding.id))
    cycle = {k: v for k, v in cycle.items() if k != "completion_version"}
    repo.put_setting(response.HEAD_PREFIX + str(finding.id), {**head, "current": cycle}, "fixture")
    repo.put_setting(response._key(str(finding.id), request_id), cycle, "fixture")
    return request_id


def answered(repo, finding, request_id, received=NOW + dt.timedelta(minutes=1)):
    assert response.answered(repo, finding.id, request_id,
        Answer("APPROVED", "synthetic-owner", received.isoformat()),
        system="synthetic", binding="binding", received_at=received)


def scan(orch, connection, data, *, resource=RESOURCE, complete=True,
         started=NOW + dt.timedelta(minutes=2), **kwargs):
    with patch("cremore.db.repository._now", return_value=started), patch("cremore.db.sql._now", return_value=started):
        job = orch.repo.enqueue_job(ScanJob(kind="inline"))
        assert orch.repo.claim_next_job().id == job.id
    try:
        result = ScanService(orch).run(BytesCollector([CollectedObject(resource, data, complete=complete)]),
            source_connection_id=connection, scan_id=job.id, verify=False, reconcile_objects=True, **kwargs)
    except BaseException:
        orch.repo.fail_job(job.id, "SYNTHETIC_SCAN_INTERRUPTED")
        raise
    orch.repo.complete_job(job.id, result.objects, result.findings, result.objects_failed)
    return result


@pytest.mark.parametrize("complete", [True, False])
def test_only_fresh_complete_absence_verifies_and_reappearance_keeps_the_assignee(repo, monkeypatch, complete):
    orch, connection = Orchestrator(repo), uuid.uuid4()
    scan(orch, connection, TOKEN, started=NOW - dt.timedelta(minutes=1))
    finding = repo.list_findings()[0]
    request_id = request(repo, monkeypatch, finding)
    answered(repo, finding, request_id)
    scan(orch, connection, b"clean but incomplete", complete=False)
    assert response.summary(repo, finding.id)["state"] == "WAITING_VERIFICATION"
    assert not repo.get_finding(finding.id).all_locations_removed
    # A scan begun before the answer cannot confirm it even if it finishes later.
    scan(orch, connection, b"clean", started=NOW)
    assert repo.get_finding(finding.id).all_locations_removed
    assert response.summary(repo, finding.id)["state"] == "WAITING_VERIFICATION"
    scan(orch, connection, b"still clean")
    assert response.summary(repo, finding.id)["state"] == "REMOVED"
    count = len(repo.list_finding_events(finding.id))
    scan(orch, connection, b"still clean")
    assert len(repo.list_finding_events(finding.id)) == count
    # The same credential in a new place opens the existing response cycle.
    scan(orch, connection, TOKEN, resource=replace(RESOURCE, location="another.env"),
         started=NOW + dt.timedelta(minutes=3), complete=complete)
    assert response.summary(repo, finding.id)["state"] == "NEEDS_ACTION"
    assert len(repo.list_findings()) == 1
    assert repo.get_finding(finding.id).assigned_to == "responder@example.test"
    events = [event.event_type for event in repo.list_finding_events(finding.id)]
    assert events.count("RESPONSE_REMOVAL_VERIFIED") == 1 and events.count("RESPONSE_REAPPEARED") == 1


def test_a_clean_resource_does_not_turn_an_unread_other_location_into_fresh_positive_evidence(repo, monkeypatch):
    orch, connection = Orchestrator(repo), uuid.uuid4()
    scan(orch, connection, TOKEN)
    other = replace(RESOURCE, location="other.env")
    scan(orch, connection, TOKEN, resource=other)
    finding = repo.list_findings()[0]
    answered(repo, finding, request(repo, monkeypatch, finding))
    scan(orch, connection, b"clean")
    assert not repo.get_finding(finding.id).all_locations_removed
    assert response.summary(repo, finding.id)["state"] == "WAITING_VERIFICATION"
    scan(orch, connection, TOKEN, resource=other, complete=False)
    assert response.summary(repo, finding.id)["state"] == "NEEDS_ACTION"
    count = len(repo.list_finding_events(finding.id))
    scan(orch, connection, TOKEN, resource=other)
    assert len(repo.list_finding_events(finding.id)) == count


def test_credential_moved_to_a_new_path_in_the_same_scan_is_not_reported_removed(repo, monkeypatch):
    orch, connection = Orchestrator(repo), uuid.uuid4()
    scan(orch, connection, TOKEN)
    finding = repo.list_findings()[0]
    answered(repo, finding, request(repo, monkeypatch, finding))
    moved = replace(RESOURCE, location="moved.env")
    ScanService(orch).run(BytesCollector([CollectedObject(RESOURCE, b"clean"), CollectedObject(moved, TOKEN)]),
        source_connection_id=connection, verify=False, reconcile_objects=True)
    assert not repo.get_finding(finding.id).all_locations_removed
    assert response.summary(repo, finding.id)["state"] == "NEEDS_ACTION"


def test_legacy_connection_reconciliation_does_not_observe_preserved_unsupported_content(repo, monkeypatch):
    orch, connection = Orchestrator(repo), uuid.uuid4()
    scan(orch, connection, TOKEN)
    finding = repo.list_findings()[0]
    answered(repo, finding, request(repo, monkeypatch, finding))
    preserved = {(RESOURCE.source_type, RESOURCE.resource, RESOURCE.location)}
    orch.reconcile_connection(connection, [], seen_locations=preserved, scan_started_at=NOW + dt.timedelta(minutes=2))
    assert response.summary(repo, finding.id)["state"] == "WAITING_VERIFICATION"
    assert not repo.get_finding(finding.id).all_locations_removed
    orch.reconcile_connection(connection, [], seen_locations=set(), scan_started_at=NOW + dt.timedelta(minutes=2))
    assert response.summary(repo, finding.id)["state"] == "REMOVED"


def test_service_records_start_before_collector_reads_and_before_a_mid_scan_owner_reply(repo, monkeypatch):
    orch, connection = Orchestrator(repo), uuid.uuid4()
    scan(orch, connection, TOKEN)
    finding = repo.list_findings()[0]
    request_id = request(repo, monkeypatch, finding)
    clock = {"start": NOW}
    monkeypatch.setattr("cremore.scanning.service.scan_start", lambda *args: clock["start"])

    class ReplyDuringRead:
        def collect(self):
            answered(repo, finding, request_id, NOW + dt.timedelta(minutes=1))
            clock["start"] = NOW + dt.timedelta(minutes=2)
            yield CollectedObject(RESOURCE, b"clean")

    ScanService(orch).run(ReplyDuringRead(), source_connection_id=connection, verify=False, reconcile_objects=True)
    assert repo.get_finding(finding.id).all_locations_removed
    assert response.summary(repo, finding.id)["state"] == "WAITING_VERIFICATION"
    ScanService(orch).run(BytesCollector([CollectedObject(RESOURCE, b"still clean")]),
        source_connection_id=connection, verify=False, reconcile_objects=True)
    assert response.summary(repo, finding.id)["state"] == "REMOVED"


def test_lost_lease_rolls_back_response_head_cycle_and_audit_with_the_exposure(repo, monkeypatch):
    orch, connection = Orchestrator(repo), uuid.uuid4()
    scan(orch, connection, TOKEN)
    finding = repo.list_findings()[0]
    answered(repo, finding, request(repo, monkeypatch, finding))
    before, events = response.public(repo, finding.id), repo.list_finding_events(finding.id)
    clock = {"now": dt.datetime.now(dt.UTC)}
    monkeypatch.setattr(task_store, "_clock", lambda conn=None: clock["now"])
    tasks = TaskStore(repo)
    tasks.enqueue(uuid.uuid4(), "synthetic-root", {"mode": "BASELINE"})
    task = tasks.claim(lease_seconds=10)

    def expire(*args):
        clock["now"] += dt.timedelta(seconds=11)

    with pytest.raises(LeaseLost):
        scan(orch, connection, b"clean", write_context=lambda: tasks.fenced(task["id"], task["token"]),
             object_committed=expire)
    assert response.public(repo, finding.id) == before
    assert repo.list_finding_events(finding.id) == events
    assert not repo.get_finding(finding.id).all_locations_removed
    assert all(e.status != "REMOVED" for e in repo.exposures_for_credential(finding.credential_id))
