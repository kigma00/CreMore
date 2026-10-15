"""SqlRepository tests over an in-memory SQLite database.

Proves the SQL store is interface-compatible with the in-memory one and that the
end-to-end orchestration works against a real database engine.
"""

from __future__ import annotations

import time
import uuid

import pytest

pytest.importorskip("sqlalchemy")

from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.detection import ResourceRef
from cremore.domain.models import Connection, Credential, Exposure
from cremore.scanning import Orchestrator

GH = "ghp_" + "aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY2zC4"


@pytest.fixture()
def repo() -> SqlRepository:
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def test_a_management_action_is_confirmed_once_with_its_audit_row(repo):
    from cremore.domain.models import FindingEvent, ManagementAction

    cred = repo.upsert_credential(Credential(fingerprint="fp", credential_type="GITHUB_TOKEN", provider="github"))
    exposure = repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="github", resource_name="r", location="a"))
    finding = repo.upsert_finding(cred.id, exposure.id, "HIGH")
    made = repo.create_management_action(
        ManagementAction(finding_id=finding.id, action_type="ACKNOWLEDGE_OWNER", requested_by="ann"),
        audit=lambda action: FindingEvent(finding_id=finding.id, actor="ann", event_type="MANAGEMENT_ACTION_REQUESTED",
                                          note=f"action={action.id} type=ACKNOWLEDGE_OWNER"))

    def confirm(who):
        return repo.update_management_action(made.id, expected_status="PENDING", status="CONFIRMED", confirmed_by=who,
                                             audit=FindingEvent(finding_id=finding.id, actor=who, event_type="MANAGEMENT_ACTION_CONFIRMED"))

    # Two confirmations that both read the request as pending: only the first changes it, and only it is audited.
    assert confirm("rita").confirmed_by == "rita" and confirm("rob") is None
    events = [(e.event_type, e.actor, e.note) for e in repo.list_finding_events(finding.id) if e.event_type.startswith("MANAGEMENT")]
    assert events == [("MANAGEMENT_ACTION_REQUESTED", "ann", f"action={made.id} type=ACKNOWLEDGE_OWNER"),
                      ("MANAGEMENT_ACTION_CONFIRMED", "rita", None)]
    assert repo.get_management_action(made.id).confirmed_by == "rita"


def test_connection_search_hides_revoked_before_counting_and_limiting(repo):
    stopped = repo.create_connection(Connection(provider="github", name="a-stopped", status="DISABLED",
        credential_evidence={"revoked_at": "2026-09-20T00:00:00Z"}))
    repo.create_connection(Connection(provider="github", name="b-paused", status="DISABLED",
        credential_evidence={"revoked_at": None}))
    repo.create_connection(Connection(provider="github", name="c-active"))
    items, total = repo.search_connections("", 1)
    assert total == 2 and [item["label"] for item in items] == ["b-paused"]
    assert repo.search_connections("a-stopped", 10) == ([], 0)
    assert repo.get_connection(stopped.id) is not None


def test_finding_search_counts_before_limiting_and_preserves_hit_contract(repo):
    for kind, team, severity in (("TOKEN_B", "shared", "HIGH"),
                                  ("TOKEN_A", "shared", "CRITICAL"),
                                  ("TOKEN_C", "other", "LOW")):
        credential = repo.upsert_credential(Credential(
            fingerprint=kind, credential_type=kind, provider="github", team=team))
        repo.upsert_finding(credential.id, uuid.uuid4(), severity)
    hits, total = repo.search_findings("shared", 1)
    assert total == 2 and [hit["label"] for hit in hits] == ["TOKEN_A"]
    assert hits[0] == {"kind": "finding", "id": hits[0]["id"], "label": "TOKEN_A",
                       "provider": "github", "context": "", "detail": "CRITICAL · OPEN"}
    assert repo.search_findings("critical", 10) == (hits, 1)
    assert repo.search_findings("not-present", 10) == ([], 0)
    all_hits, total = repo.search_findings("", 10)
    assert total == 3 and [hit["label"] for hit in all_hits] == ["TOKEN_A", "TOKEN_B", "TOKEN_C"]


@pytest.mark.parametrize("needle,expected,total", [
    ("alpha_team", ["alpha_team"], 1),
    ("%", ["alpha%team"], 1),
    ("_", ["alpha_team"], 1),
    ("/", ["path//team"], 2),
    ("//", ["path//team"], 1),
    ("\\", ["path\\team"], 1),
    ("alpha", ["alpha%team"], 4),
])
def test_search_matches_literal_substrings_before_counting_and_limiting(repo, needle, expected, total):
    from cremore.db.repository import InMemoryRepository

    for store in (repo, InMemoryRepository()):
        for name in ("alpha_team", "alphaxteam", "alpha%team", "alphaxxxteam", "path/team", "path//team", "path\\team"):
            store.create_connection(Connection(provider="github", name=name))
        hits, count = store.search_connections(needle, 1)
        assert count == total
        assert [hit["label"] for hit in hits] == expected


def test_credential_upsert_dedupes(repo):
    a = repo.upsert_credential(Credential(fingerprint="fp1", credential_type="GITHUB_TOKEN", provider="github"))
    assert a.id is not None
    # Same identity, new info -> update, same row.
    b = repo.upsert_credential(Credential(fingerprint="fp1", credential_type="GITHUB_TOKEN",
                                          credential_status="Active"))
    assert b.id == a.id
    assert repo.get_credential(a.id).credential_status == "Active"
    # A different type is a different credential.
    c = repo.upsert_credential(Credential(fingerprint="fp1", credential_type="NPM_TOKEN"))
    assert c.id != a.id


@pytest.mark.parametrize("memory", [False, True])
@pytest.mark.parametrize("operation", ["auto_triage", "reopen"])
def test_learned_fp_compare_and_set_preserves_a_concurrent_manual_decision(repo, memory, operation):
    from types import SimpleNamespace

    from cremore.db.repository import InMemoryRepository
    from cremore.scanning.learned_fp import RESOLUTION_PREFIX, LearnedFPService

    store = InMemoryRepository() if memory else repo
    credential = store.upsert_credential(Credential(fingerprint="cas-test", credential_type="TEST"))
    exposure = store.upsert_exposure(Exposure(credential_id=credential.id, source_type="inline",
                                              resource_name="synthetic", location="sample"))
    finding = store.upsert_finding(credential.id, exposure.id, "LOW")
    if operation == "reopen":
        finding = store.update_finding_status(finding.id, "FALSE_POSITIVE", RESOLUTION_PREFIX + "synthetic-profile")
    stale = finding.model_copy(deep=True)
    manual_status = "FALSE_POSITIVE" if operation == "reopen" else "IGNORED"
    store.update_finding_status(finding.id, manual_status, "manual review")
    service = LearnedFPService(store)
    if operation == "reopen":
        result = service.reopen_auto(stale)
    else:
        result = service.auto_triage(stale, exposure, SimpleNamespace(id=uuid.uuid4()), 1.0)
    assert result.workflow_status == manual_status and result.resolution == "manual review"
    assert store.list_finding_events(finding.id) == []


def test_exposure_and_finding_roundtrip(repo):
    cred = repo.upsert_credential(Credential(fingerprint="fp2", credential_type="GITHUB_TOKEN"))
    exp = repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="github",
                                        resource_name="org/repo", location="app.py",
                                        source_connection_id=uuid.uuid4(), severity="LOW"))
    assert exp.id is not None
    # Re-upsert same location -> same exposure, updated severity.
    exp2 = repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="github",
                                         resource_name="org/repo", location="app.py",
                                         source_connection_id=exp.source_connection_id, severity="HIGH"))
    assert exp2.id == exp.id
    assert len(repo.exposures_for_credential(cred.id)) == 1

    repo.set_exposure_severity(exp.id, "CRITICAL")
    assert repo.exposures_for_credential(cred.id)[0].severity == "CRITICAL"

    finding = repo.upsert_finding(cred.id, exp.id, "CRITICAL")
    assert finding.id is not None
    assert repo.get_finding(finding.id).severity == "CRITICAL"
    assert len(repo.list_findings()) == 1


def test_connection_roundtrip_on_sql(repo):
    conn = repo.create_connection(Connection(provider="github", name="acme",
                                             config={"owner": "acme", "repo": "app"},
                                             secret_ref="vault://x"))
    assert conn.id is not None and conn.status == "PENDING"
    assert repo.get_connection(conn.id).name == "acme"
    assert len(repo.list_connections()) == 1

    updated = repo.update_connection(conn.id, status="ACTIVE")
    assert updated.status == "ACTIVE"

    with pytest.raises(ValueError):  # unique(provider, name)
        repo.create_connection(Connection(provider="github", name="acme", config={"owner": "a", "repo": "b"}))


def test_orchestrator_end_to_end_on_sql(repo):
    orch = Orchestrator(repo)
    orch.scan_resource(
        f"token = {GH}".encode(),
        ResourceRef(source_type="github", resource="org/repo", location="a.py",
                    metadata={"exposure": "public"}),
    )
    findings = repo.list_findings()
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    cred = repo.get_credential(findings[0].credential_id)
    assert cred.credential_type == "GITHUB_TOKEN"
    # Re-scan dedupes.
    orch.scan_resource(f"token = {GH}".encode(),
                       ResourceRef(source_type="github", resource="org/repo", location="a.py",
                                   metadata={"exposure": "public"}))
    assert len(repo.list_findings()) == 1


def test_job_cancel_and_audit_events_on_sql(repo):
    from cremore.domain.models import FindingEvent, ScanJob

    queued = repo.enqueue_job(ScanJob(kind="inline", payload={"text": "x"}))
    time.sleep(0.03)  # job times come from the wall clock, which ticks in milliseconds on some hosts
    # Only one content scan can be active, so the second queued job is a check.
    running = repo.enqueue_job(ScanJob(kind="credential-check", payload={"provider": "github"}))
    assert repo.claim_next_job().id == queued.id  # oldest first -> `queued` is now RUNNING
    # a RUNNING job is left alone; the still-queued one is withdrawn
    assert repo.cancel_job(queued.id).status == "RUNNING"
    assert repo.cancel_job(running.id).status == "CANCELLED"
    assert repo.claim_next_job() is None  # a cancelled job is never claimed
    assert repo.cancel_job(uuid.uuid4()) is None
    repo.complete_job(queued.id, objects=3, findings=0, objects_failed=1)
    assert repo.get_job(queued.id).objects_failed == 1 and repo.get_job(queued.id).status == "SUCCEEDED"

    cred = repo.upsert_credential(Credential(fingerprint="fp-a", credential_type="GITHUB_TOKEN"))
    exp = repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="github",
                                        resource_name="o/r", location="a", severity="LOW"))
    finding = repo.upsert_finding(cred.id, exp.id, "LOW")
    repo.record_finding_event(FindingEvent(finding_id=finding.id, actor="a", event_type="ACKNOWLEDGED"))
    time.sleep(0.03)  # distinct created_at on coarse clocks
    repo.record_finding_event(FindingEvent(finding_id=finding.id, actor="b", event_type="ASSIGNED"))
    assert [e.event_type for e in repo.list_events()] == ["ASSIGNED", "ACKNOWLEDGED"]  # newest first
    assert len(repo.list_events(limit=1)) == 1


def test_create_all_adds_missing_nullable_columns():
    from sqlalchemy import inspect, text

    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    # Simulate a database created by an earlier version (no external_id column).
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE aws_accounts DROP COLUMN external_id"))
    assert "external_id" not in {c["name"] for c in inspect(engine).get_columns("aws_accounts")}
    create_all(engine)  # idempotent upgrade
    assert "external_id" in {c["name"] for c in inspect(engine).get_columns("aws_accounts")}
    from cremore.domain.models import AwsAccount

    acct = SqlRepository(engine).create_aws_account(AwsAccount(account_id="123456789012", name="p", external_id="ext"))
    assert acct.external_id == "ext"


def test_postgres_schema_creation_uses_one_transaction_scoped_lock(monkeypatch):
    from cremore.db import sql

    calls = []

    class Conn:
        dialect = type("Dialect", (), {"name": "postgresql"})()

        def execute(self, statement, params=None):
            calls.append((str(statement), params))

    conn = Conn()

    class Transaction:
        def __enter__(self):
            calls.append("begin")
            return conn

        def __exit__(self, *_):
            calls.append("end")

    class Engine:
        dialect = conn.dialect

        def begin(self):
            return Transaction()

    monkeypatch.setattr(sql.metadata, "create_all", lambda bind: calls.append(("create_all", bind)))
    monkeypatch.setattr(sql, "audit_targets", lambda bind: calls.append(("audit", bind)))
    monkeypatch.setattr(sql, "siem_event_kinds", lambda bind: calls.append(("siem_events", bind)))
    monkeypatch.setattr(sql, "orphan_tickets", lambda bind: calls.append(("orphan_tickets", bind)))
    monkeypatch.setattr(sql, "_ensure_columns", lambda bind: calls.append(("ensure", bind)))
    monkeypatch.setattr(
        sql, "_migrate_legacy_redactions", lambda bind: calls.append(("migrate", bind))
    )
    monkeypatch.setattr(sql, "startup_migrations", lambda bind: calls.append(("ledger", bind)))
    monkeypatch.setattr(sql, "ensure_scan_slot", lambda bind: calls.append(("slot", bind)))
    monkeypatch.setattr(sql, "credential_lookup_index", lambda bind: calls.append(("lookup", bind)))
    monkeypatch.setattr(sql, "metadata_coverage", lambda bind: calls.append(("metadata", bind)))
    monkeypatch.setattr(sql, "audit_chain_index", lambda bind: calls.append(("audit_chain", bind)))
    monkeypatch.setattr(sql, "siem_owed_index", lambda bind: calls.append(("siem_owed", bind)))
    monkeypatch.setattr(sql, "schedule_origin", lambda bind: calls.append(("schedule_origin", bind)))
    monkeypatch.setattr(sql, "removed_ticket_system", lambda bind: calls.append(("ticket_system", bind)))
    sql.create_all(Engine())

    assert calls[0] == "begin" and "pg_advisory_xact_lock" in calls[1][0]
    assert calls[2:] == [
        ("create_all", conn),
        # Before the column reconciliation, which will not invent a NOT NULL column.
        ("audit", conn),
        # The SIEM outbox accepts operational events before any writer runs.
        ("siem_events", conn),
        # Tickets about a departed owner's credential carry no finding.
        ("orphan_tickets", conn),
        ("ensure", conn),
        ("migrate", conn),
        ("ledger", conn),
        ("slot", conn),
        ("lookup", conn),
        # The schema 2 projections join the same transaction-scoped lock.
        ("metadata", conn),
        # So does the audit trail's unique chain position, after the columns exist.
        ("audit_chain", conn),
        # The alert channel's undelivered rows.
        ("siem_owed", conn),
        # The upgrade's moment, by the database's clock, under the same lock: one row however many processes start.
        ("schedule_origin", conn),
        # The removed built-in ticket system's setup, once (data only).
        ("ticket_system", conn),
        "end",
    ]


def test_column_upgrade_can_share_the_schema_transaction_connection():
    from sqlalchemy import inspect, text

    from cremore.db import sql

    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE aws_accounts DROP COLUMN external_id"))
        sql._ensure_columns(conn)
    assert "external_id" in {c["name"] for c in inspect(engine).get_columns("aws_accounts")}


def test_create_all_scrubs_legacy_redacted_lines_and_versions_new_rows():
    from sqlalchemy import select, text

    from cremore.db.schema import exposures

    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    repo = SqlRepository(engine)
    cred = repo.upsert_credential(Credential(fingerprint="legacy", credential_type="TOKEN"))
    exp = repo.upsert_exposure(
        Exposure(
            credential_id=cred.id,
            source_type="github",
            resource_name="o/r",
            location="config.py",
            redacted_line="token = ••••",
        )
    )
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE exposures DROP COLUMN redaction_version"))
        conn.execute(
            text("UPDATE exposures SET redacted_line = 'raw secret from an older release'")
        )

    create_all(engine)
    with engine.connect() as conn:
        row = conn.execute(select(exposures)).mappings().one()
    assert row["redacted_line"] is None and row["redaction_version"] == 4

    # A decoded-only rescan has no safe line context and must not revive an
    # unversioned value that appeared after startup.
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE exposures SET redacted_line = 'legacy', redaction_version = NULL"
            )
        )
    repo.upsert_exposure(
        Exposure(
            credential_id=cred.id,
            source_type="github",
            resource_name="o/r",
            location="config.py",
        )
    )
    with engine.connect() as conn:
        row = conn.execute(select(exposures).where(exposures.c.id == exp.id)).mappings().one()
    assert row["redacted_line"] is None and row["redaction_version"] == 4


def test_older_masking_context_is_hidden_without_rewriting_stored_evidence(repo):
    from sqlalchemy import select, update

    from cremore.db.rescore_store import RescoreStore
    from cremore.db.schema import exposures

    credential = repo.upsert_credential(Credential(fingerprint="older-mask", credential_type="TOKEN"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="s3",
        resource_name="synthetic", location="config", redacted_line="safe context"))
    with repo.engine.begin() as conn:
        conn.execute(update(exposures).where(exposures.c.id == exposure.id)
                     .values(redaction_version=3, redacted_line="previously stored context"))
    assert repo.exposures_for_credential(credential.id)[0].redacted_line is None
    with repo.engine.connect() as conn:
        assert RescoreStore(repo).page(conn, credential.id, None, 10)[0].redacted_line is None
        saved = conn.execute(select(exposures).where(exposures.c.id == exposure.id)).mappings().one()
        assert saved["redacted_line"] == "previously stored context" and saved["redaction_version"] == 3


def test_rules_reviews_and_exposure_retirement_on_sql(repo):
    from cremore.domain.models import CustomRule, OwnershipReview

    rule = repo.create_rule(CustomRule(name="Marker", pattern=r"(?P<secret>X_[A-Z]{4})", keywords=["x_"],
                                       fixture_tests=[{"id": "NEUTRAL_TEXT", "expected": False}]))
    assert rule.id is not None and rule.revision == 1 and rule.fixture_tests == [{"id": "NEUTRAL_TEXT", "expected": False}]
    assert repo.update_rule(rule.id, enabled=False, revision=2).enabled is False
    assert [r.name for r in repo.list_rules()] == ["Marker"]
    with pytest.raises(ValueError):
        repo.create_rule(CustomRule(name="Marker", pattern="y"))
    assert repo.delete_rule(rule.id) is True and repo.delete_rule(rule.id) is False

    cred = repo.upsert_credential(Credential(fingerprint="fp-r", credential_type="GITHUB_TOKEN"))
    conn_id = uuid.uuid4()
    exp = repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="github", resource_name="o/r",
                                        location="a", severity="LOW", source_connection_id=conn_id))
    finding = repo.upsert_finding(cred.id, exp.id, "LOW")
    assert repo.get_ownership_review(finding.id) is None
    saved = repo.save_ownership_review(OwnershipReview(finding_id=finding.id, status="IN_PROGRESS",
                                                       assigned_team="payments", revision=1, updated_by="a"))
    assert saved.revision == 1 and saved.id is not None
    again = repo.save_ownership_review(OwnershipReview(finding_id=finding.id, status="CLOSED", assigned_team="payments",
                                                       closed_reason="CREDENTIAL_RETIRED", revision=2, updated_by="b"))
    assert again.id == saved.id and again.status == "CLOSED" and repo.get_ownership_review(finding.id).revision == 2

    assert [e.id for e in repo.exposures_for_connection(conn_id)] == [exp.id]
    repo.mark_exposure_removed(exp.id)
    retired = repo.exposures_for_connection(conn_id)[0]
    assert retired.status == "REMOVED" and retired.removed_at is not None
    # a rescan that sees it again reopens the exposure
    assert repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="github", resource_name="o/r",
                                         location="a", severity="LOW", source_connection_id=conn_id)).status == "OPEN"


def test_action_plans_and_usage_snapshot_on_sql(repo):
    from cremore.domain.models import ActionPlan

    cred = repo.upsert_credential(Credential(fingerprint="fp-ap", credential_type="AWS_ACCESS_KEY", identifier="AKIA0"))
    plan = repo.create_action_plan(ActionPlan(credential_id=cred.id, action_type="DISABLE_ACCESS_KEY", requested_by="a",
                                              idempotency_key="k-1", plan_hash="h" * 64,
                                              operational_review={"mode": "PLANNED", "consumers": []},
                                              readiness={"reasons": []}, rotation_progress=[]))
    assert plan.id is not None and plan.status == "PENDING_APPROVAL" and plan.recheck_only is False
    assert repo.find_action_plan("k-1").id == plan.id and repo.find_action_plan("nope") is None
    with pytest.raises(ValueError):
        repo.create_action_plan(ActionPlan(credential_id=cred.id, action_type="DISABLE_ACCESS_KEY", idempotency_key="k-1"))
    updated = repo.update_action_plan(plan.id, status="OUTCOME_UNKNOWN", recheck_only=True, safe_error_code="STATE_ACTIVE",
                                      rotation_progress=[{"stage": "CREATED", "recorded_at": "2026-09-14T00:00:00+00:00"}])
    assert updated.recheck_only is True and updated.rotation_progress[0]["stage"] == "CREATED"
    assert [p.id for p in repo.list_action_plans(cred.id)] == [plan.id]
    # The approvals queue: every credential's plans, newest first, at most ``limit`` of them.
    other = repo.upsert_credential(Credential(fingerprint="fp-ap-2", credential_type="AWS_ACCESS_KEY", identifier="AKIA1"))
    newer = repo.create_action_plan(ActionPlan(credential_id=other.id, action_type="DISABLE_ACCESS_KEY", requested_by="b",
                                               idempotency_key="k-2", plan_hash="i" * 64, operational_review=None,
                                               readiness={"reasons": []}, rotation_progress=[]))
    assert [p.id for p in repo.list_action_plans()] == [newer.id, plan.id]
    assert [p.id for p in repo.list_action_plans(limit=1)] == [newer.id]
    snap = {"collection_status": "COMPLETE", "events": []}
    assert repo.update_credential(cred.id, usage_snapshot=snap, last_used_service="s3").usage_snapshot == snap
    assert repo.get_credential(cred.id).last_used_service == "s3"
    mapped = repo.update_credential(cred.id, management_reference="arn:aws:secretsmanager:us-east-1:123456789012:secret:a-AbCdEf",
                                    management_revision=1)
    assert mapped.management_revision == 1 and mapped.management_reference.endswith("a-AbCdEf")

    from cremore.domain.models import ConnectionCheckEvent

    conn_id, job_id = uuid.uuid4(), uuid.uuid4()
    repo.record_check_event(ConnectionCheckEvent(connection_id=conn_id, job_id=job_id, source_type="github",
                                                 stage="REQUESTED", job_status="QUEUED", requested_by=uuid.uuid4()))
    repo.record_check_event(ConnectionCheckEvent(connection_id=conn_id, job_id=job_id, source_type="github",
                                                 stage="TERMINAL", job_status="COMPLETED", outcome="ACTIVE",
                                                 reason_code="CHECK_RESULT",
                                                 recorded_at=dt_now() + __import__("datetime").timedelta(seconds=1)))
    events = repo.list_check_events(conn_id)
    assert [e.stage for e in events] == ["TERMINAL", "REQUESTED"] and events[0].id is not None
    assert repo.list_check_events(uuid.uuid4()) == []


def dt_now():
    import datetime as _d

    return _d.datetime.now(_d.UTC)


def test_enterprise_entities_roundtrip_on_sql(repo):
    from cremore.domain.models import AwsAccount, GovernanceReview, ManagementAction, RotationJob

    # AWS account: the enabled bool survives the Integer column round-trip.
    acct = repo.create_aws_account(AwsAccount(account_id="123456789012", name="prod"))
    assert acct.id is not None and acct.enabled is True and acct.validation_status == "PENDING"
    updated = repo.update_aws_account(acct.id, enabled=False, validation_status="VALID")
    assert updated.enabled is False and updated.validation_status == "VALID"
    assert repo.get_aws_account(acct.id).name == "prod"
    assert len(repo.list_aws_accounts()) == 1

    fid = uuid.uuid4()
    review = repo.create_review(GovernanceReview(finding_id=fid, question="who owns this?"))
    assert review.status == "OPEN" and review.resolved_at is None
    assert repo.update_review(review.id, status="RESOLVED", response="team a").status == "RESOLVED"

    job = repo.create_rotation_job(RotationJob(credential_id=fid, requested_by="alice"))
    assert job.status == "REQUESTED" and job.phase == "PREPARE"
    assert repo.update_rotation_job(job.id, status="PREPARED").status == "PREPARED"

    action = repo.create_management_action(
        ManagementAction(finding_id=fid, action_type="ROTATE", requested_by="alice"))
    confirmed = repo.update_management_action(action.id, status="CONFIRMED", confirmed_by="bob")
    assert confirmed.status == "CONFIRMED" and confirmed.confirmed_by == "bob"
    assert repo.get_management_action(uuid.uuid4()) is None  # unknown id -> None, not error


def test_workflow_ticket_roundtrip(repo):
    from cremore.domain.models import WorkflowTicket

    cred = repo.upsert_credential(Credential(fingerprint="fp-t", credential_type="GITHUB_PAT", provider="github"))
    finding = repo.upsert_finding(cred.id, uuid.uuid4(), "HIGH")
    t = repo.create_ticket(WorkflowTicket(credential_id=cred.id, finding_id=finding.id, provider="github",
                                          credential_type="GITHUB_PAT", steps=[{"code": "SET_FOLLOW_UP", "status": "TODO"}],
                                          evidence=[{"kind": "FINDING", "id": str(finding.id)}], created_by=uuid.uuid4(),
                                          updated_by=uuid.uuid4()))
    assert t.id and t.created_at and repo.get_ticket(t.id).steps[0]["code"] == "SET_FOLLOW_UP"
    updated = repo.update_ticket(t.id, status="RESOLVED", version=2, internal_approval={"approved_by": "x"})
    assert updated.status == "RESOLVED" and updated.version == 2 and updated.internal_approval["approved_by"] == "x"
    assert [x.id for x in repo.list_tickets(cred.id)] == [t.id] and repo.list_tickets(uuid.uuid4()) == []


def test_scan_scope_tables_roundtrip(repo):
    from cremore.domain.models import ScanJob, ScopeCatalog, ScopePlan, ScopeProfile, SelectionDraft

    cid = uuid.uuid4()
    saved = repo.save_catalog(ScopeCatalog(kind="source", connection_id=cid, snapshot_id="s1", auth_revision="a1",
                                           items=[{"id": "r1", "display_name": "x"}], completeness="COMPLETE"))
    assert saved.id and repo.get_catalog("source", cid).items[0]["id"] == "r1" and repo.get_catalog("aws", cid) is None
    again = repo.save_catalog(ScopeCatalog(kind="source", connection_id=cid, snapshot_id="s2", items=[], completeness="PARTIAL"))
    assert again.id == saved.id and repo.get_catalog("source", cid).snapshot_id == "s2"  # one row per connection

    profile = repo.create_scope_profile(ScopeProfile(kind="source", connection_id=cid, name="p", selected_roots=[{"resource_id": "r1"}],
                                                     budgets={"bytes": 1, "requests": 1, "seconds": 1}, catalog_snapshot_id="s2"))
    assert repo.list_scope_profiles("source", cid)[0].id == profile.id and repo.list_scope_profiles("aws", cid) == []
    assert repo.update_scope_profile(profile.id, version=2, state="READY").version == 2

    draft = repo.create_draft(SelectionDraft(kind="source", connection_id=cid, catalog_snapshot_id="s2", resource_ids=["r1"],
                                             unknown_remainder=True))
    assert repo.get_draft(draft.id).unknown_remainder is True and repo.update_draft(draft.id, status="CANCELLED").status == "CANCELLED"

    plan = repo.create_plan(ScopePlan(kind="source", connection_id=cid, profile_id=profile.id, profile_version=2,
                                      resources=[{"id": "r1"}], roots=[{"resource_id": "r1"}], known_count=1, executable=True,
                                      rescan_target={"path": "a"}, verify=False))
    fetched = repo.get_plan(plan.id)
    assert fetched.executable is True and fetched.verify is False and fetched.rescan_target == {"path": "a"} and fetched.job_id is None
    job = repo.enqueue_job(ScanJob(kind="scope", payload={"plan_id": str(plan.id)}))
    assert repo.update_plan(plan.id, job_id=job.id).job_id == job.id
    repo.claim_next_job()
    repo.complete_job(job.id, 2, 0, objects_failed=1, coverage={"skipped": 3})
    assert repo.get_job(job.id).coverage == {"skipped": 3}


def test_learned_fp_tables_roundtrip(repo):
    from cremore.domain.models import FPProfile, FPSample

    key = {"scope_kind": "source", "scope_id": uuid.uuid4(), "source_type": "github", "detector_name": "d", "credential_type": "T"}
    for actor in ("alice", "bob"):
        repo.create_fp_sample(FPSample(**key, finding_id=uuid.uuid4(), exposure_id=uuid.uuid4(), actor=actor, features=["ext:py"]))
    assert [s.actor for s in repo.list_fp_samples(**key)] == ["alice", "bob"]
    saved = repo.save_fp_profile(FPProfile(**key, sample_count=2, distinct_actors=2, active=True, threshold=0.7, centroid={"ext:py": 1.0}))
    assert saved.id and repo.get_fp_profile(**key).active is True and repo.get_fp_profile_by_id(saved.id).threshold == 0.7
    again = repo.save_fp_profile(FPProfile(**key, sample_count=0, active=False))
    assert again.id == saved.id and repo.list_fp_profiles()[0].active is False  # one row per key
    assert repo.delete_fp_samples(**key) == 2 and repo.list_fp_samples(**key) == []


def test_installation_settings_upsert_and_record_the_writer(repo):
    assert repo.get_setting("credential_verification") is None
    first = repo.put_setting("credential_verification", {"enabled": False}, "admin-1")
    stored = repo.get_setting("credential_verification")
    assert stored["value"] == {"enabled": False} and stored["updated_by"] == "admin-1" and stored["updated_at"]
    repo.put_setting("credential_verification", {"enabled": True}, "admin-2")
    again = repo.get_setting("credential_verification")
    assert again["value"] == {"enabled": True} and again["updated_by"] == "admin-2"
    assert again["updated_at"] >= first["updated_at"]


def test_a_rescan_never_regresses_an_owner_learned_from_iam():
    """The provenance must survive the passive rescan that follows it."""
    from cremore.domain.models import Credential

    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    repo = SqlRepository(engine)
    detected = Credential(fingerprint="fp", credential_type="AWS_ACCESS_KEY_ID", provider="aws",
                          identifier="AKIA" + "Z5X9K2MBV7QP3LN6")
    cred = repo.upsert_credential(detected)
    assert cred.principal_arn_source is None

    repo.update_credential(cred.id, principal_arn="arn:aws:iam::222222222222:user/ops/ci-deployer",
                           principal_arn_source="IAM_OWNER_LOOKUP", credential_status="Active")
    # The next scan sees the same bytes and knows nothing about the owner.
    repo.upsert_credential(detected.model_copy(update={"id": None}))

    saved = repo.get_credential(cred.id)
    assert saved.principal_arn_source == "IAM_OWNER_LOOKUP"
    assert saved.principal_arn == "arn:aws:iam::222222222222:user/ops/ci-deployer"
    assert saved.credential_status == "Active"
