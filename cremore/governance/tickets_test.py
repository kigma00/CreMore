"""Internal ticket rules: fixed checklists, frozen CUSTOM playbooks, independent approval."""

import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import Credential, Exposure
from cremore.governance.tickets import STEPS, TicketError, TicketService, review_digest

A, B = "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"
DUE = "2026-10-01T09:00:00Z"


def seed(provider="github", severity="HIGH", repo=None):
    repo = repo if repo is not None else InMemoryRepository()
    cred = repo.upsert_credential(Credential(fingerprint="fp", credential_type="GITHUB_PAT", provider=provider,
                                             identifier_hint="ghp_••••"))
    exposure = repo.upsert_exposure(Exposure(credential_id=cred.id, source_type="github",
                                           resource_name="synthetic", location="synthetic"))
    finding = repo.upsert_finding(cred.id, exposure.id, severity)
    return repo, cred, finding, TicketService(repo)


def test_templates_are_fixed_checklists_and_custom_is_empty():
    templates = {t["id"]: t["steps"] for t in TicketService.templates()}
    assert len(templates) == 6 and templates["CUSTOM"] == []
    assert templates["DEPARTED_OWNER"][0] == "CONFIRM_OWNER_AND_TARGET"
    assert templates["PUBLIC_EXPOSURE"][0] == "CONFIRM_OWNER_AND_TARGET"
    assert all(s in STEPS for steps in templates.values() for s in steps)


def test_create_defaults_evidence_to_the_finding_and_rejects_secret_like_text():
    _repo, cred, finding, svc = seed()
    t = svc.create(finding, cred, A, {"review_due_at": DUE, "responsible_team": "payments"})
    assert t.template_id == "PUBLIC_EXPOSURE" and t.status == "OPEN" and t.version == 1
    assert [s["status"] for s in t.steps] == ["TODO"] * 6
    assert t.evidence == [{"kind": "FINDING", "id": str(finding.id)}]
    assert str(t.created_by) == A and len(t.review_digest) == 64
    with pytest.raises(TicketError) as exc:
        svc.create(finding, cred, A, {"review_due_at": DUE, "responsible_team": "ghp_" + "x" * 30})
    assert exc.value.code == "WORKFLOW_FIELDS_INVALID"
    with pytest.raises(TicketError) as exc:
        svc.create(finding, cred, A, {"review_due_at": "soon"})
    assert exc.value.code == "WORKFLOW_DATE_INVALID"


def test_ticket_text_takes_nothing_that_hides_or_reorders_it():
    _repo, cred, finding, svc = seed()
    review = {"service_name": "billing", "issuer_context": "org", "allowed_scope": "read", "rotation_plan": "quarterly",
              "offboarding_plan": "revoke", "incident_plan": "page"}
    for team in ("pay" + chr(0x202E) + "ments", "pay" + chr(0x200B) + "ments", chr(0x3164)):
        with pytest.raises(TicketError) as exc:
            svc.create(finding, cred, A, {"review_due_at": DUE, "responsible_team": team})
        assert exc.value.code == "WORKFLOW_FIELDS_INVALID", ascii(team)
    # A lone surrogate would be stored and then break every read of the ticket list.
    with pytest.raises(TicketError) as exc:
        svc.create(finding, cred, A, {"review_due_at": DUE, "security_review": {**review, "service_name": chr(0xD800)}})
    assert exc.value.code == "WORKFLOW_FIELDS_INVALID"
    made = svc.create(finding, cred, A, {"review_due_at": DUE, "responsible_team": "결제팀", "security_review": review})
    assert made.responsible_team == "결제팀" and made.security_review["service_name"] == "billing"


def test_every_provider_gets_tickets():
    _repo, cred, finding, svc = seed(provider="slack")
    assert svc.create(finding, cred, A, {"review_due_at": DUE}).provider == "slack"
    body = {"review_due_at": DUE, "template_id": "CUSTOM", "custom_steps": ["CONFIRM_OWNER_AND_TARGET"],
            "customization": {"conditions": [{"field": "PROVIDER", "equals": "slack"}], "approval_rule": "NONE"}}
    assert svc.create(finding, cred, A, body).playbook["provider"] == "slack"
    for wrong in ("Slack Inc", ["slack"], ""):
        with pytest.raises(TicketError) as exc:
            svc.create(finding, cred, A, {**body, "customization": {"conditions": [{"field": "PROVIDER", "equals": wrong}]}})
        assert exc.value.code == "WORKFLOW_PLAYBOOK_INVALID"
    # A credential whose provider is not a plain name still gets a ticket, under "unknown".
    _repo, cred, finding, svc = seed(provider="")
    assert svc.create(finding, cred, A, {"review_due_at": DUE}).provider == "unknown"


def test_update_guards_version_and_records_who_reviewed_each_step():
    _repo, cred, finding, svc = seed()
    t = svc.create(finding, cred, A, {"review_due_at": DUE})
    with pytest.raises(TicketError) as exc:
        svc.update(t, B, {"expected_version": 7})
    assert exc.value.http_status == 409
    steps = [{"code": s["code"], "status": "REVIEWED"} for s in t.steps]
    t2 = svc.update(t, B, {"expected_version": 1, "status": "IN_PROGRESS", "steps": steps, "owner_id": B,
                           "responsible_team": "payments"})
    assert t2.version == 2 and t2.steps[0]["reviewed_by"] == B and t2.steps[0]["reviewed_at"]
    assert str(t2.assigned_by) == B and t2.assigned_at
    first_review = t2.steps[0]["reviewed_at"]
    # keeping a step reviewed keeps the original attestation
    t3 = svc.update(t2, A, {"expected_version": 2, "steps": steps})
    assert t3.steps[0]["reviewed_by"] == B and t3.steps[0]["reviewed_at"] == first_review
    # the checklist cannot be reordered or swapped
    with pytest.raises(TicketError) as exc:
        svc.update(t3, A, {"expected_version": 3, "steps": list(reversed(steps))})
    assert exc.value.code == "WORKFLOW_STEP_INVALID"


def test_resolution_needs_every_step_reviewed_and_an_owner():
    _repo, cred, finding, svc = seed()
    t = svc.create(finding, cred, A, {"review_due_at": DUE})
    with pytest.raises(TicketError) as exc:
        svc.update(t, A, {"expected_version": 1, "status": "RESOLVED"})
    assert exc.value.code == "WORKFLOW_RESOLUTION_BLOCKED"
    steps = [{"code": s["code"], "status": "NOT_APPLICABLE"} for s in t.steps]
    done = svc.update(t, A, {"expected_version": 1, "status": "RESOLVED", "steps": steps, "owner_id": A,
                             "responsible_team": "payments"})
    assert done.status == "RESOLVED" and done.resolution_basis == "MANUAL_WORKFLOW_REVIEW_COMPLETED"
    assert str(done.resolved_by) == A and done.resolved_at


def test_custom_playbook_freezes_conditions_and_requires_independent_admin():
    _repo, cred, finding, svc = seed(severity="CRITICAL")
    body = {"review_due_at": DUE, "template_id": "CUSTOM", "custom_steps": ["CONFIRM_OWNER_AND_TARGET", "SET_FOLLOW_UP"],
            "priority": "CRITICAL",
            "customization": {"conditions": [{"field": "FINDING_SEVERITY", "equals": "CRITICAL"},
                                             {"field": "DECLARED_PRIORITY", "equals": "CRITICAL"}],
                              "approval_rule": "INDEPENDENT_ADMIN"}}
    t = svc.create(finding, cred, A, body)
    assert t.playbook["steps"] == ["CONFIRM_OWNER_AND_TARGET", "SET_FOLLOW_UP"] and t.playbook["schema_version"] == 1
    assert t.playbook["finding_severity"] == "CRITICAL" and t.playbook["config"]["approval_rule"] == "INDEPENDENT_ADMIN"
    # a condition that does not match the saved finding is refused, never silently dropped
    bad = {**body, "customization": {"conditions": [{"field": "PROVIDER", "equals": "aws"}]}}
    with pytest.raises(TicketError) as exc:
        svc.create(finding, cred, A, bad)
    assert exc.value.code == "WORKFLOW_PLAYBOOK_NOT_APPLICABLE"
    with pytest.raises(TicketError):
        svc.create(finding, cred, A, {**body, "custom_steps": ["NOT_A_STEP"]})

    steps = [{"code": s["code"], "status": "REVIEWED"} for s in t.steps]
    ready = svc.update(t, A, {"expected_version": 1, "steps": steps, "owner_id": A, "responsible_team": "sec"})
    digest_v2 = str(ready.review_digest)  # the in-memory repo mutates in place; keep the value
    # resolving without approval is blocked
    with pytest.raises(TicketError) as exc:
        svc.update(ready, A, {"expected_version": 2, "status": "RESOLVED", "steps": steps, "owner_id": A,
                              "responsible_team": "sec"})
    assert exc.value.code == "WORKFLOW_APPROVAL_REQUIRED"
    # the creator / last editor cannot approve; a digest mismatch is refused
    approve = {"confirm": True, "expected_version": 2, "content_digest": ready.review_digest}
    with pytest.raises(TicketError) as exc:
        svc.approve(ready, A, approve)
    assert exc.value.code == "WORKFLOW_INDEPENDENCE_REQUIRED"
    with pytest.raises(TicketError) as exc:
        svc.approve(ready, B, {**approve, "content_digest": "0" * 64})
    assert exc.value.code == "WORKFLOW_DIGEST_MISMATCH"
    approved = svc.approve(ready, B, approve)
    assert approved.internal_approval["approved_by"] == B and approved.internal_approval["source_version"] == 2
    assert approved.version == 3 and approved.review_digest == digest_v2
    # editing reviewed content invalidates the approval
    edited = svc.update(approved, A, {"expected_version": 3, "steps": steps, "owner_id": A, "responsible_team": "sec2"})
    assert edited.internal_approval is None and edited.review_digest != digest_v2
    # status-only changes do not
    digest_v4 = str(edited.review_digest)
    approved2 = svc.approve(edited, B, {"confirm": True, "expected_version": 4, "content_digest": digest_v4})
    moved = svc.update(approved2, A, {"expected_version": 5, "status": "WAITING_APPROVAL", "steps": steps, "owner_id": A,
                                      "responsible_team": "sec2"})
    assert moved.internal_approval and moved.review_digest == digest_v4
    done = svc.update(moved, A, {"expected_version": 6, "status": "RESOLVED", "steps": steps, "owner_id": A,
                                 "responsible_team": "sec2"})
    assert done.status == "RESOLVED" and done.internal_approval["content_digest"] == done.review_digest
    with pytest.raises(TicketError) as exc:
        svc.approve(done, B, {"confirm": True, "expected_version": 7, "content_digest": done.review_digest})
    assert exc.value.code == "WORKFLOW_ALREADY_RESOLVED"


def test_public_shape_matches_the_dashboard_contract():
    _repo, cred, finding, svc = seed()
    t = svc.create(finding, cred, "oidc|alice", {"review_due_at": DUE, "owner_id": B,
                                                 "security_review": {"service_name": "CI", "issuer_context": "org app",
                                                                     "storage_method": "PLATFORM_SECRET",
                                                                     "allowed_scope": "read repo", "rotation_plan": "quarterly",
                                                                     "offboarding_plan": "admin event", "incident_plan": "revoke"}})
    out = TicketService.public(t)
    assert uuid.UUID(out["created_by"]) and out["created_by"] != "00000000-0000-0000-0000-000000000000"
    assert out["owner_id"] == B and out["assigned_by"] == out["created_by"] and out["assigned_at"]
    assert out["security_review"]["storage_method"] == "PLATFORM_SECRET"
    assert "resolved_by" not in out and "playbook" not in out and "internal_approval" not in out
    assert out["review_digest"] == review_digest(t)


@pytest.mark.parametrize("body", [
    {"template_id": []},
    {"template_id": "CUSTOM", "custom_steps": [["CONFIRM_OWNER_AND_TARGET"]]},
    {"template_id": "CUSTOM", "custom_steps": ["CONFIRM_OWNER_AND_TARGET"], "customization": False},
    {"template_id": "CUSTOM", "custom_steps": ["CONFIRM_OWNER_AND_TARGET"],
     "customization": {"conditions": ["PROVIDER"]}},
    {"template_id": "CUSTOM", "custom_steps": ["CONFIRM_OWNER_AND_TARGET"],
     "customization": {"conditions": [{"field": [], "equals": "aws"}]}},
    {"owner_id": A + "\n"},
])
def test_malformed_ticket_fields_fail_with_typed_errors(body):
    repo, cred, finding, svc = seed()
    with pytest.raises(TicketError):
        svc.create(finding, cred, A, {"review_due_at": DUE, **body})
    assert repo.list_tickets() == []


@pytest.mark.parametrize("body", [{"expected_version": True}, {"expected_version": 1, "steps": [None]}])
def test_malformed_update_does_not_change_ticket(body):
    repo, cred, finding, svc = seed()
    ticket = svc.create(finding, cred, A, {"review_due_at": DUE})
    before = ticket.model_copy(deep=True)
    with pytest.raises(TicketError):
        svc.update(ticket, A, body)
    assert repo.get_ticket(ticket.id) == before


@pytest.fixture(params=["memory", "sql"])
def ticket_repo(request, tmp_path):
    if request.param == "memory":
        yield InMemoryRepository()
    else:
        engine = make_engine(f"sqlite+pysqlite:///{(tmp_path / 'tickets.db').as_posix()}")
        create_all(engine)
        try:
            yield SqlRepository(engine)
        finally:
            engine.dispose()


@pytest.mark.parametrize("operation", ["edit", "approve"])
def test_ticket_revision_is_claimed_atomically(ticket_repo, monkeypatch, operation):
    repo, cred, finding, svc = seed(repo=ticket_repo)
    ticket = svc.create(finding, cred, A, {"review_due_at": DUE, "template_id": "CUSTOM",
                                         "custom_steps": ["CONFIRM_OWNER_AND_TARGET"]})
    ticket = svc.update(ticket, A, {"expected_version": 1, "owner_id": A, "responsible_team": "sec",
                                    "steps": [{"code": "CONFIRM_OWNER_AND_TARGET", "status": "REVIEWED"}]})
    prior = ticket.model_copy(deep=True)
    saved_update = repo.update_ticket
    ready = Barrier(2)

    def competing_update(*args, **kwargs):
        ready.wait(timeout=10)
        return saved_update(*args, **kwargs)

    monkeypatch.setattr(repo, "update_ticket", competing_update)

    def edit_or_approve(actor):
        try:
            if operation == "approve":
                return svc.approve(prior, actor, {"confirm": True, "expected_version": prior.version,
                                                 "content_digest": prior.review_digest})
            return svc.update(prior, actor, {"expected_version": prior.version, "responsible_team": "sec"})
        except TicketError as exc:
            assert exc.code == "WORKFLOW_VERSION_CONFLICT" and exc.http_status == 409
            return None

    with ThreadPoolExecutor(max_workers=2) as workers:
        tasks = [workers.submit(edit_or_approve, actor) for actor in (B, "independent-reviewer")]
        results = [task.result(timeout=20) for task in tasks]
    assert sum(result is not None for result in results) == 1
    assert repo.get_ticket(ticket.id).version == prior.version + 1
