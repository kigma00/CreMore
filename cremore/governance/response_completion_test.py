"""The v2 response path, fake provider evidence only, against memory and SQL stores."""
import copy
import datetime as dt
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from cremore.coverage import response_evidence
from cremore.domain.models import ActionPlan, Credential, Exposure
from cremore.governance import response as service
from cremore.governance import response_reports
from cremore.governance.response_test import (
    NOW,
    SETTINGS,
    answer,
    ask,
    events,
    scan,
)
from cremore.governance.response_test import pg as pg  # noqa: PLC0414 -- guarded PostgreSQL fixture
from cremore.governance.response_test import (
    plugin as plugin,  # noqa: PLC0414 -- the installed fake adapter
)
from cremore.governance.response_test import repo as repo  # noqa: PLC0414 -- fixture re-export
from cremore.ticketing import setup
from cremore.ticketing.ticketing_test import SETUP, TARGET, Tickets


def prepare(repo, kind="AWS_ACCESS_KEY"):
    credential = repo.upsert_credential(Credential(fingerprint="fake-response-value", provider="aws",
        credential_type=kind, identifier="AKIA" + "A" * 16, identifier_hint="AKIA••••AAAA"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="inline",
        resource_name="synthetic", location="synthetic"))
    finding = repo.upsert_finding(credential.id, exposure.id, "HIGH")
    setup.save(repo, SETTINGS, SETUP, "admin", TARGET)
    return finding, Tickets()


def statement(**kw):
    return {"result": "DONE", "path": "RETIRED", "actions": ["REMOVE_PLAINTEXT", "REVOKE"],
            "explanation": "Removed the published copy and retired the old credential after checking consumers.",
            "performed_at": (NOW + dt.timedelta(minutes=1)).isoformat(), **kw}


def report(repo, finding, *, data=None, report_id=None, version=None):
    current = service.summary(repo, finding.id)
    return service.submit_report(repo, SETTINGS, finding.id, "owner", expected_version=current["version"] if version is None else version,
        request_id=current["current"]["request_id"], report_id=report_id or uuid.uuid4(), data=data or statement(),
        contains_credentials=lambda text: "synthetic-secret" in text, now=NOW + dt.timedelta(minutes=2))


def action(repo, finding, kind="DELETE_ACCESS_KEY", **kw):
    credential = repo.get_credential(finding.credential_id)
    return repo.create_action_plan(ActionPlan(credential_id=finding.credential_id, key_id=credential.identifier,
        action_type=kind, status="VERIFIED", verified_at=NOW + dt.timedelta(minutes=1),
        approved_by="independent-approver", plan_hash="c" * 64, idempotency_key=str(uuid.uuid4()), **kw))


def evaluate(repo, finding, compared=None):
    current = service.summary(repo, finding.id)
    checks = response_evidence.evaluate(repo, repo.get_finding(finding.id), current["current"],
        compared or {"connections": [], "items": []}, now=NOW + dt.timedelta(minutes=6))
    service.reconcile(repo, finding.id, checks, expected_version=current["version"], now=NOW + dt.timedelta(minutes=6))
    return service.summary(repo, finding.id)


def remove(repo, finding):
    # The scanner owns this bit; a response declaration never changes it.
    for exposure in repo.exposures_for_credential(finding.credential_id):
        repo.mark_exposure_removed(exposure.id)
    repo.repair_finding_rollup(finding.credential_id)


def test_report_and_acknowledgement_do_not_mean_retirement_or_completion(repo):
    finding, server = prepare(repo)
    asked = ask(repo, finding, server, legacy=False)
    assert asked["current"]["completion_version"] == 2
    assert answer(repo, finding, asked)
    assert service.summary(repo, finding.id)["state"] == "REPORT_REQUIRED"
    assert not answer(repo, finding, asked)
    assert report(repo, finding)["state"] == "WAITING_VERIFICATION"
    assert not scan(repo, finding, removed=True)  # equal to report receipt is not after it
    assert scan(repo, finding, removed=True, start=NOW + dt.timedelta(minutes=3))
    remove(repo, finding)
    assert evaluate(repo, finding)["state"] == "WAITING_VERIFICATION"
    action(repo, finding, "DISABLE_ACCESS_KEY")
    assert evaluate(repo, finding)["state"] == "WAITING_VERIFICATION", "reversible blocking is not retirement"
    action(repo, finding)
    completed = evaluate(repo, finding)
    assert completed["state"] == "COMPLETED"
    assert completed["current"]["verification"]["vault"]["state"] == "NA"
    before = len(events(repo, finding))
    evaluate(repo, finding)
    assert len(events(repo, finding)) == before, "unchanged maintenance must not flood audit"
    assert scan(repo, finding, removed=True, start=NOW + dt.timedelta(minutes=6))
    assert service.summary(repo, finding.id)["state"] == "COMPLETED", "a clean rescan keeps completion stable"
    assert scan(repo, finding, removed=False, start=NOW + dt.timedelta(minutes=7))
    assert service.summary(repo, finding.id)["state"] == "NEEDS_ACTION"
    assert scan(repo, finding, removed=True, start=NOW + dt.timedelta(minutes=8))
    assert evaluate(repo, finding)["state"] == "NEEDS_ACTION", "old acknowledgement cannot settle recurrence"
    assert len(server.tickets) == 1, "rescans never send tickets"
    assert service.summary(repo, finding.id)["current"]["completed_at"]


@pytest.mark.parametrize("change", [
    {"explanation": "Okay"}, {"explanation": "x" * 2001}, {"explanation": "Explained synthetic-secret that must not be saved"},
    {"explanation": "<b>This is not an accepted plain text statement</b>"},
    {"explanation": "Do not store the hidden control \u202e in this message"},
    {"performed_at": "tomorrow"}, {"performed_at": (NOW - dt.timedelta(days=1)).isoformat()},
    {"actions": ["REMOVE_PLAINTEXT"]}, {"replacement_plan_id": "bad"},
    {"path": "REPLACED", "actions": ["REMOVE_PLAINTEXT", "ROTATE", "STORE_REPLACEMENT", "CUTOVER"]},
])
def test_incomplete_or_unsafe_report_never_persists(repo, change):
    finding, server = prepare(repo)
    ask(repo, finding, server, legacy=False)
    before = json.dumps(repo.list_settings(service.HEAD_PREFIX), default=str)
    with pytest.raises(service.ResponseError):
        report(repo, finding, data=statement(**change))
    assert repo.list_settings(response_reports.PREFIX) == []
    assert json.dumps(repo.list_settings(service.HEAD_PREFIX), default=str) == before


def test_reports_are_immutable_idempotent_and_versioned_with_safe_audit(repo):
    finding, server = prepare(repo)
    asked = ask(repo, finding, server, legacy=False)
    report_id = uuid.uuid4()
    first = report(repo, finding, report_id=report_id)
    assert first["state"] == "WAITING_OWNER", "report cannot substitute for ticket approval"
    assert report(repo, finding, report_id=report_id, version=asked["version"]) == first
    with pytest.raises(service.ResponseError, match="RESPONSE_REPORT_ID_REUSED"):
        report(repo, finding, report_id=report_id, data=statement(explanation="Changed explanation with different factual details."))
    second = report(repo, finding, data=statement(explanation="The copy in the runbook was also removed after verifying the owner."))
    history = service.report_history(repo, finding.id, asked["current"]["request_id"])
    assert history["total"] == 2 and history["items"][1] == first["current"]["report"]
    assert second["current"]["report"]["version"] == 2
    assert all("explanation" not in e.note for e in events(repo, finding))
    assert any(first["current"]["report"]["hash"] in e.note for e in events(repo, finding))


def test_replacement_requires_bound_publish_complete_current_value_and_old_retirement(repo):
    finding, server = prepare(repo)
    asked = ask(repo, finding, server, legacy=False)
    secret = "arn:aws:secretsmanager:us-east-1:123456789012:secret:synthetic-test"
    p = action(repo, finding, "PUBLISH_ACCESS_KEY_ROTATION", rotation={"secret_arn": secret},
               new_key_id="AKIA" + "B" * 16, pending_version="version-2")
    answer(repo, finding, asked)
    report(repo, finding, data=statement(path="REPLACED", actions=["REMOVE_PLAINTEXT", "ROTATE", "STORE_REPLACEMENT", "CUTOVER"], replacement_plan_id=str(p.id)))
    scan(repo, finding, removed=True, start=NOW + dt.timedelta(minutes=3))
    remove(repo, finding)
    location = {"connection_id": "vault-1", "run_id": "run-1", "provider": "aws_secrets_manager", "reference": secret,
        "version": "version-2", "identifier": p.new_key_id, "credential_type": "AWS_ACCESS_KEY", "evidence": "VALUE",
        "current_evidence": True, "observed_at": (NOW + dt.timedelta(minutes=4)).isoformat()}
    compared = {"connections": [{"id": "vault-1", "enabled": True, "reasons": [], "latest": {"status": "COMPLETE", "id": "run-1"}}],
                "items": [{"locations": [location]}]}
    assert evaluate(repo, finding, compared)["state"] == "WAITING_VERIFICATION", "publish keeps the old key active"
    action(repo, finding)
    for change in ({"evidence": "IDENTIFIER"}, {"version": "old"}, {"current_evidence": False}, {"identifier": "AKIA" + "C" * 16}):
        bad = copy.deepcopy(compared)
        bad["items"][0]["locations"][0].update(change)
        assert evaluate(repo, finding, bad)["state"] == "WAITING_VERIFICATION"
    partial = copy.deepcopy(compared)
    partial["connections"][0]["latest"]["status"] = "PARTIAL"
    assert evaluate(repo, finding, partial)["state"] == "WAITING_VERIFICATION"
    assert evaluate(repo, finding, compared)["state"] == "COMPLETED"
    assert evaluate(repo, finding, partial)["state"] == "WAITING_VERIFICATION", "freshness and scope invalidation update completion"
    assert scan(repo, finding, removed=False, start=NOW + dt.timedelta(minutes=7))
    assert scan(repo, finding, removed=True, start=NOW + dt.timedelta(minutes=8))
    assert evaluate(repo, finding, compared)["state"] == "NEEDS_ACTION", "recurrence also invalidates approval while vault proof is stale"


def test_key_id_only_exposure_cannot_trigger_normal_secret_completion(repo):
    finding, server = prepare(repo, "AWS_ACCESS_KEY_ID")
    asked = ask(repo, finding, server, legacy=False)
    answer(repo, finding, asked)
    report(repo, finding)
    action(repo, finding)
    scan(repo, finding, removed=True, start=NOW + dt.timedelta(minutes=3))
    remove(repo, finding)
    assert evaluate(repo, finding)["state"] == "WAITING_VERIFICATION"


def test_review_is_explicit_and_stale_proof_cannot_overwrite_new_report(repo):
    finding, server = prepare(repo)
    assert service.public(repo, finding.id)["state"] == "NEW"
    started = service.start_review(repo, finding.id, "analyst", expected_version=0, now=NOW)
    assert started["state"] == "REVIEWING" and started["version"] == 1
    asked = ask(repo, finding, server, version=1, legacy=False)
    answer(repo, finding, asked)
    before = service.summary(repo, finding.id)
    report(repo, finding)
    assert not service.reconcile(repo, finding.id, {}, expected_version=before["version"], now=NOW)


def test_worker_uses_actual_saved_vault_runs_and_invalidates_a_partial_refresh(repo):
    from cremore.coverage.models import Batch, ConnectionSpec, Contract, Finish, Observation
    from cremore.coverage.store import CoverageStore
    from cremore.scanning.orchestrator import Orchestrator

    finding, server = prepare(repo)
    asked = ask(repo, finding, server, legacy=False)
    secret = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app-Ab12Cd"
    p = action(repo, finding, "PUBLISH_ACCESS_KEY_ROTATION", rotation={"secret_arn": secret},
               new_key_id="AKIA" + "B" * 16, pending_version="version-2")
    answer(repo, finding, asked)
    report(repo, finding, data=statement(path="REPLACED", actions=["REMOVE_PLAINTEXT", "ROTATE", "STORE_REPLACEMENT", "CUTOVER"], replacement_plan_id=str(p.id)))
    action(repo, finding)
    scan(repo, finding, removed=True, start=NOW + dt.timedelta(minutes=3))
    remove(repo, finding)
    orchestrator = Orchestrator(repo)
    orchestrator.refresh_rules()
    contract = Contract(engine_digest=orchestrator.engine.detection_digest,
                        policy_digest=orchestrator.coverage_policy_digest).model_dump()
    store = CoverageStore(repo)
    owner, _ = store.create(ConnectionSpec(name="Synthetic vault", provider="aws_secrets_manager",
        account_id="123456789012", regions=["us-east-1"]), "fixture")
    observation = Observation(reference=secret, account_id="123456789012", region="us-east-1", version="version-2",
        evidence="VALUE", credential_type="AWS_ACCESS_KEY", identifier=p.new_key_id, fingerprint="a" * 64)

    def collect(status):
        run = store.start(owner["id"], owner["revision"], str(uuid.uuid4()), contract)
        store.append(owner["id"], run["id"], Batch(index=0, items=[observation]))
        store.finish(owner["id"], run["id"], Finish(batch_count=1, item_count=1, status=status,
                     reasons=["CALL_LIMIT"] if status == "PARTIAL" else []))
        return run

    run = collect("COMPLETE")
    now = dt.datetime.now(dt.UTC)
    assert service.sweep(repo, SETTINGS, orchestrator, now=now) == 1
    completed = service.summary(repo, finding.id)
    assert completed["state"] == "COMPLETED"
    assert completed["current"]["verification"]["vault"]["run_id"] == str(run["id"])
    assert service.sweep(repo, SETTINGS, orchestrator, now=now) == 0
    collect("PARTIAL")
    assert service.sweep(repo, SETTINGS, orchestrator, now=now + dt.timedelta(minutes=1)) == 1
    assert service.summary(repo, finding.id)["state"] == "WAITING_VERIFICATION"


def test_postgres_worker_uses_saved_vault_runs(pg):
    test_worker_uses_actual_saved_vault_runs_and_invalidates_a_partial_refresh(pg[1])


def test_postgres_concurrent_reports_preserve_one_version_and_audit(pg):
    repo = pg[1]
    finding, server = prepare(repo)
    asked = ask(repo, finding, server, legacy=False)
    barrier = Barrier(2)

    def submit(_):
        barrier.wait(timeout=5)
        try:
            report(repo, finding, version=asked["version"])
            return "RECORDED"
        except service.ResponseError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(submit, range(2))) == ["RECORDED", "RESPONSE_CHANGED"]
    assert service.report_history(repo, finding.id, asked["current"]["request_id"])["total"] == 1
    assert sum(e.event_type == "RESPONSE_REPORT_RECORDED" for e in events(repo, finding)) == 1


def test_replacement_rejects_partial_issuer_evidence_and_different_origin(repo, monkeypatch):
    finding, server = prepare(repo)
    asked = ask(repo, finding, server, legacy=False)
    answer(repo, finding, asked)
    replacement = str(uuid.uuid4())
    report(repo, finding, data=statement(path="REPLACED", actions=["REMOVE_PLAINTEXT", "ROTATE", "STORE_REPLACEMENT", "CUTOVER"], replacement_entity_id=replacement))
    monkeypatch.setattr(response_evidence, "linked", lambda *a, **kw: [{"entity_id": str(uuid.uuid4()), "evidence": "VALUE",
        "provider": "gitlab", "origin": "https://gitlab.example.test", "tenant": "one", "current_evidence": False}])
    monkeypatch.setattr(response_evidence, "plans_for", lambda *a: [])
    run = {"id": str(uuid.uuid4()), "status": "PARTIAL"}
    monkeypatch.setattr(response_evidence.MetadataStore, "run_detail", lambda *a, **kw: {"run": run})
    issued = {"provider": "gitlab", "origin": "https://gitlab.example.test", "tenant": "one", "current_evidence": True,
              "state": "ACTIVE", "run_id": run["id"]}
    compared = {"connections": [], "items": [{"entity_id": replacement, "issued": issued, "exposed": False, "state": "UNKNOWN"}]}

    def check():
        return evaluate(repo, finding, compared)["current"]["verification"]["replacement"]["state"]

    assert check() == "WAIT"
    run["status"] = "COMPLETE"
    assert check() == "PASS"
    for key, value in (("origin", "https://elsewhere.example.test"), ("tenant", "two"), ("provider", "github"), ("run_id", str(uuid.uuid4()))):
        previous, issued[key] = issued[key], value
        assert check() == "WAIT"
        issued[key] = previous
