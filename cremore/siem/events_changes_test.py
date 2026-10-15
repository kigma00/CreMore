"""finding.updated, audit.action and installation_id, recorded with the change itself."""

import json
import os
import uuid

import pytest

from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import Credential, Exposure, FindingEvent
from cremore.siem.events import audit_action, finding_updated, is_system_actor
from cremore.siem.outbox import SiemOutbox


@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    if request.param == "postgres":
        return request.getfixturevalue("pg")[1]
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def events(repo, kind=None):
    rows = [row["event"] for row in SiemOutbox(repo).claim("probe-" + uuid.uuid4().hex[:8], limit=100)]
    return [row for row in rows if kind is None or row["event_type"] == kind]


def observed(repo):
    credential = repo.upsert_credential(Credential(fingerprint="synthetic-" + uuid.uuid4().hex, credential_type="GITHUB_TOKEN",
                                                   provider="github", identifier="private-identifier"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="github",
                                             resource_name="private-resource", location="private/path",
                                             line_number=3, severity="HIGH"))
    return credential, repo.upsert_finding(credential.id, exposure.id, "HIGH")


def test_triage_changes_become_finding_updated_once_each(repo):
    _credential, finding = observed(repo)
    repo.update_finding_status(finding.id, "ACKNOWLEDGED")
    repo.update_finding_status(finding.id, "ACKNOWLEDGED")  # no change, no event
    repo.update_finding_status(finding.id, "RESOLVED", "private resolution note")
    updates = events(repo, "finding.updated")
    assert [(e["change"], e["finding"]["previous_workflow_status"], e["finding"]["workflow_status"]) for e in updates] == [
        ("WORKFLOW", "OPEN", "ACKNOWLEDGED"), ("WORKFLOW", "ACKNOWLEDGED", "RESOLVED")]
    assert len({e["event_id"] for e in updates}) == 2
    text = json.dumps(updates)
    assert "private" not in text and "synthetic-" not in text
    assert all(e["finding"]["id"] == str(finding.id) for e in updates)


def test_a_new_location_not_scored_yet_carries_the_findings_severity(repo):
    credential, _finding = observed(repo)  # a HIGH finding
    for location, severity in (("private/elsewhere", "UNKNOWN"), ("private/scored", "LOW")):
        repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="github", resource_name="private-resource",
                                      location=location, line_number=4, severity=severity))
    added = [event["finding"]["severity"] for event in events(repo, "finding.location_added")]
    assert sorted(added) == ["HIGH", "LOW"]  # the placeholder never reaches a SIEM; a scored location keeps its own


def test_a_verification_result_is_its_own_change(repo):
    credential, _finding = observed(repo)
    repo.upsert_credential(Credential(fingerprint=credential.fingerprint, credential_type="GITHUB_TOKEN",
                                      provider="github", credential_status="Active"))
    repo.upsert_credential(Credential(fingerprint=credential.fingerprint, credential_type="GITHUB_TOKEN",
                                      provider="github", credential_status="Active"))  # same result
    repo.update_credential(credential.id, credential_status="Revoked")
    repo.update_credential(credential.id, management_reference=None)  # not a verification
    changes = [(e["change"], e["credential"]["previous_status"], e["credential"]["status"])
               for e in events(repo, "finding.updated")]
    assert changes == [("VERIFICATION", "UNKNOWN", "Active"), ("VERIFICATION", "Active", "Revoked")]


def test_administrator_actions_become_audit_action_without_names_or_notes(repo):
    target = uuid.uuid4()
    person = "alice@corp.example"
    repo.record_finding_event(FindingEvent(target_type="coverage_connection", target_id=target, actor=person,
                                           event_type="COVERAGE_VAULT_TOKEN_SET", note="private note from alice"))
    repo.record_finding_event(FindingEvent(target_type="coverage_connection", target_id=target, actor="metadata-schedule",
                                           event_type="METADATA_COLLECTION_QUEUED"))
    [event] = events(repo, "audit.action")
    audit = event["audit"]
    assert (audit["action"], audit["target_type"], audit["target_id"]) == ("COVERAGE_VAULT_TOKEN_SET",
                                                                          "coverage_connection", str(target))
    assert audit["actor_ref"] == str(uuid.uuid5(uuid.NAMESPACE_URL, "cremore:actor:" + person))
    text = json.dumps(event)
    assert "alice" not in text and "private" not in text


def test_every_event_carries_one_stable_installation_id(repo):
    _credential, finding = observed(repo)
    repo.update_finding_status(finding.id, "FALSE_POSITIVE")
    repo.record_siem_event({"schema_version": 1, "event_id": str(uuid.uuid4()), "event_type": "siem.test",
                            "occurred_at": "2026-09-28T00:00:00Z", "product": "CreMore", "test": {"nonce": str(uuid.uuid4())}})
    ids = {event["installation_id"] for event in events(repo)}
    assert len(ids) == 1 and uuid.UUID(ids.pop()) == uuid.UUID(repo.installation_id())


def test_installation_id_survives_a_new_repository_on_the_same_database(tmp_path):
    engine = make_engine(f"sqlite+pysqlite:///{tmp_path / 'cremore.db'}")
    create_all(engine)
    first = SqlRepository(engine).installation_id()
    assert SqlRepository(engine).installation_id() == first


def test_concurrent_first_writers_agree_on_the_installation_id(pg):
    from concurrent.futures import ThreadPoolExecutor

    engine = pg[1].engine
    with ThreadPoolExecutor(8) as pool:
        ids = set(pool.map(lambda _: SqlRepository(engine).installation_id(), range(8)))
    assert len(ids) == 1


def test_builders_refuse_what_they_cannot_name():
    assert is_system_actor("scanner") and is_system_actor("aws-inventory-schedule") and is_system_actor(None)
    assert not is_system_actor("00000000-0000-0000-0000-000000000001")
    event = FindingEvent(id=uuid.uuid4(), target_type="Weird Type!", actor="bob", event_type="not a code",
                         created_at=__import__("datetime").datetime.now(__import__("datetime").UTC))
    built = audit_action(event)
    assert (built["audit"]["action"], built["audit"]["target_type"]) == ("UNKNOWN", "unknown")
    with pytest.raises(ValueError, match="SIEM_UNKNOWN_FINDING_CHANGE"):
        finding_updated(None, None, change="OTHER", marker="x")


def test_an_ownership_review_change_carries_the_review_states():
    import datetime as dt

    event = FindingEvent(id=uuid.uuid4(), finding_id=uuid.uuid4(), actor="alice", event_type="OWNERSHIP_REVIEW_UPDATED",
                         from_status="WAITING_OWNER", to_status="CLOSED", note='team="payments" due=-',
                         created_at=dt.datetime.now(dt.UTC))
    audit = audit_action(event)["audit"]
    # A review's own codes, not the finding's workflow (where CLOSED is unknown and OPEN means something else).
    assert (audit["action"], audit["from_status"], audit["to_status"]) == ("OWNERSHIP_REVIEW_UPDATED", "WAITING_OWNER", "CLOSED")
    assert "payments" not in json.dumps(audit)


def test_response_transitions_reach_siem_including_scan_confirmation(repo):
    _credential, finding = observed(repo)
    transitions = [
        ("alice@corp.example", "RESPONSE_REQUESTED", "NEW", "SENDING"),
        ("alice@corp.example", "RESPONSE_TICKET_OPENED", "SENDING", "WAITING_OWNER"),
        ("glpi:user:42", "RESPONSE_CLEANUP_DECLARED", "WAITING_OWNER", "WAITING_VERIFICATION"),
        ("scanner", "RESPONSE_REMOVAL_VERIFIED", "WAITING_VERIFICATION", "REMOVED"),
        ("scanner", "RESPONSE_REAPPEARED", "REMOVED", "NEEDS_ACTION"),
        ("system:response", "RESPONSE_SEND_UNKNOWN", "SENDING", "SEND_UNKNOWN"),
        # A Slack/mail request with a CreMore link: sent, or not sent (its link ended), by a person or the reaper.
        ("alice@corp.example", "RESPONSE_LINK_SENT", "SENDING", "WAITING_OWNER"),
        ("system:response", "RESPONSE_NOT_SENT", "SENDING", "NOT_SENT"),
        ("kim-subject", "RESPONSE_DECLINED", "WAITING_OWNER", "NEEDS_ACTION"),
        ("analyst", "RESPONSE_REVIEW_STARTED", "NEW", "REVIEWING"),
        ("responder", "RESPONSE_REPORT_RECORDED", "REPORT_REQUIRED", "WAITING_VERIFICATION"),
        ("system:response", "RESPONSE_EVIDENCE_UPDATED", "WAITING_VERIFICATION", "WAITING_VERIFICATION"),
        ("system:response", "RESPONSE_COMPLETED", "WAITING_VERIFICATION", "COMPLETED"),
    ]
    recorded = [repo.record_finding_event(FindingEvent(finding_id=finding.id, actor=actor,
        event_type=action, from_status=before, to_status=after, note="private ticket address and contents"))
        for actor, action, before, after in transitions]
    repo.record_finding_event(FindingEvent(finding_id=finding.id, actor="scanner", event_type="RESPONSE_UNKNOWN"))
    exported = events(repo, "audit.action")
    assert sorted((row["audit"]["action"], row["audit"]["from_status"], row["audit"]["to_status"])
                  for row in exported) == sorted((action, before, after) for _, action, before, after in transitions)
    assert {row["audit"]["id"] for row in exported} == {str(row.id) for row in recorded}
    assert all(row["occurred_at"] and row["audit"]["finding_id"] == str(finding.id) for row in exported)
    assert not any(value in json.dumps(exported) for value in ("private", "alice@", "glpi:user:42", "synthetic-"))
    altered = recorded[-1].model_copy(update={"to_status": "private-response"})
    assert audit_action(altered)["audit"]["to_status"] == "UNKNOWN"
