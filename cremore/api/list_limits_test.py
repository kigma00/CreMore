"""Bound public pages in SQL before materialization; preserve internal full reads."""

import uuid

import pytest
from sqlalchemy import event

from cremore.api.dashboard_test import auth, client
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import (
    Credential,
    Exposure,
    GovernanceReview,
    ManagementAction,
    RotationJob,
    WorkflowTicket,
)


@pytest.mark.parametrize("sql", [False, True])
def test_public_sibling_lists_page_and_stats_aggregate(sql, monkeypatch):
    if sql:
        engine = make_engine("sqlite:///:memory:")
        create_all(engine)
        repo = SqlRepository(engine)
    else:
        repo = InMemoryRepository()
    groups = {name: [] for name in ("findings", "reviews", "actions", "rotations", "tickets")}
    for index in range(3):
        cred = repo.upsert_credential(Credential(fingerprint=str(index), credential_type="GENERIC_SECRET", provider="github"))
        exposure = repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="github", resource_name="r", location=f"{index}.txt"))
        finding = repo.upsert_finding(cred.id, exposure.id, "LOW")
        groups["findings"].append(finding.id)
        groups["reviews"].append(repo.create_review(GovernanceReview(finding_id=finding.id)).id)
        groups["actions"].append(repo.create_management_action(ManagementAction(finding_id=finding.id, action_type="ACKNOWLEDGE_OWNER")).id)
        groups["rotations"].append(repo.create_rotation_job(RotationJob(credential_id=cred.id)).id)
        groups["tickets"].append(repo.create_ticket(WorkflowTicket(credential_id=cred.id, finding_id=finding.id)).id)
    c = client(repo)
    queries = []
    if sql:
        event.listen(engine, "before_cursor_execute", lambda conn, cursor, statement, params, context, many: queries.append(statement))
    for route, collection in (("credentials", "findings"), ("exposure-surface", "findings"),
                              ("management-actions/targets", "findings"), ("governance/reviews", "reviews"),
                              ("rotation-automation/jobs", "rotations"), ("management-actions", "actions")):
        first = c.get("/api/v1/" + route, headers=auth(), params={"limit": 1})
        assert first.status_code == 200, first.text
        assert first.headers["X-Page-Limit"] == "1"
        cursor = first.headers["X-Next-Cursor"]
        assert uuid.UUID(cursor) == min(groups[collection])
        if isinstance(first.json(), list):
            assert len(first.json()) == 1
        last = c.get("/api/v1/" + route, headers=auth(), params={"limit": 2, "cursor": cursor})
        assert last.status_code == 200 and "X-Next-Cursor" not in last.headers
        assert c.get("/api/v1/" + route, headers=auth(), params={"limit": 501}).status_code == 422
    # Internal safety checks still see every legacy pending record.
    assert len(repo.list_rotation_jobs()) == 3
    assert len(repo.list_tickets(limit=1, offset=2)) == 1
    assert len(repo.list_tickets()) == 3
    def no_full_read(*args, **kwargs):
        pytest.fail("stats or tickets materialized an unbounded list")
    monkeypatch.setattr(repo, "list_findings", no_full_read)
    stats = c.get("/api/v1/stats", headers=auth())
    assert stats.json() == {"total": 3, "open": 3, "by_severity": {"LOW": 3},
                            "by_workflow_status": {"OPEN": 3}, "by_provider": {"github": 3}}
    tickets = repo.list_tickets
    def bounded_tickets(*args, **kwargs):
        assert kwargs == {"limit": 51, "offset": 1}
        return tickets(*args, **kwargs)
    monkeypatch.setattr(repo, "list_tickets", bounded_tickets)
    assert len(c.get("/api/v1/tickets?offset=1", headers=auth()).json()["data"]["items"]) == 2
    if sql:
        assert any("GROUP BY" in q and "count(" in q.lower() for q in queries)
        for table in ("governance_reviews", "rotation_jobs", "management_actions", "workflow_tickets"):
            assert any(f"FROM {table}" in q and "LIMIT" in q for q in queries)
