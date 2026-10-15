"""Authority routing, independent signatures and lease-fenced one-use actions."""
from __future__ import annotations

import copy
import datetime as dt
import json
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.db.task_store import TaskStore
from cremore.domain.models import ScanJob
from cremore.onboarding.store import ProviderConnectionStore
from cremore.remediation import authorization, owner_approval
from cremore.remediation.action_plans import ActionPlanError, ActionPlanService
from cremore.remediation.action_plans_test import FakeAdapter, credential
from cremore.remediation.provider_actions_test import review
from cremore.worker import JobWorker
from cremore.worker.isolation import execution_role


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        yield InMemoryRepository()
    else:
        engine = make_engine("sqlite+pysqlite:///:memory:")
        create_all(engine)
        yield SqlRepository(engine)
        engine.dispose()


@pytest.fixture(scope="module")
def admission_policy(tmp_path_factory):
    from cremore.secretstore.provision import provision

    root = tmp_path_factory.mktemp("admission") / "keys"
    provision({"version": 1, "connections": [{"provider": "github", "auth_method": "github_app",
        "target": {}, "purposes": ["remediation"]}]}, root)
    return str(root / "recipients.json")


@pytest.fixture
def signing(tmp_path, admission_policy):
    private = Ed25519PrivateKey.generate()
    public_path = tmp_path / "approval-public.pem"
    public_path.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM,
                                                            serialization.PublicFormat.SubjectPublicKeyInfo))
    settings = Settings(AUTH_MODE="local", API_TOKEN="a" * 32, FINGERPRINT_KEY="ab" * 32,
                        ACTION_EXECUTION_ENABLED=True).model_copy(update={
                            "isolated_deployment": True, "worker_execution_role": "remediator",
                            "sealing_public_keys_file": admission_policy,
                            "remediation_approval_public_key_file": str(public_path)})
    return private, settings


def approved(repo, settings):
    repo.put_setting(owner_approval.KEY, {"required": False}, "test")
    service = ActionPlanService(repo, settings)
    plan = service.create(credential(repo), "", "alice", {
        "action_type": "DISABLE_ACCESS_KEY", "reason_code": "EXPOSURE_CONTAINMENT",
        "idempotency_key": str(uuid.uuid4()), "operational_review": review()})
    return service, service.approve(plan, "bob", plan.plan_hash)


def signed(private, plan, repo=None, mode="execute"):
    return authorization.sign(authorization.request_for(plan, mode, repo=repo), private,
                              (dt.datetime.now(dt.UTC) + dt.timedelta(minutes=10)).isoformat())


def quiet_worker(repo, settings, adapter=None):
    worker = JobWorker(repo, settings=settings, action_clients=lambda plan: (adapter, None))
    worker.poll_triggers = lambda: None
    return worker


def test_isolated_mixed_role_is_rejected(signing):
    _, settings = signing
    with pytest.raises(ValueError, match="ISOLATED_WORKER_ROLE_REQUIRED"):
        execution_role(settings.model_copy(update={"worker_execution_role": "mixed"}))


def test_sql_and_memory_claims_filter_actual_connection_purpose_before_limit(repo):
    store = ProviderConnectionStore(repo)
    owners = [store.create({"provider": "gitlab", "edition": "cloud", "name": role,
                           "target": {}, "auth_method": "token", "secret_refs": {},
                           "purposes": [role]}, "admin") for role in ("exposure", "remediation")]
    tasks = TaskStore(repo)
    collector_jobs = [repo.enqueue_job(ScanJob(kind="catalog-refresh", payload={})) for _ in range(20)]
    action = repo.enqueue_job(ScanJob(kind="provider-credential-action", payload={}))
    checks = [repo.enqueue_job(ScanJob(kind="provider-check", payload={"provider_connection_id": str(o["id"])}))
              for o in owners]
    role_check = repo.enqueue_job(ScanJob(kind="aws-role-check", payload={"purpose": "remediation"}))
    assert tasks.seed_next_job(execution_role="control") is None
    expected_ids = {action.id, checks[1].id, role_check.id}
    seen = set()
    for _ in range(3):
        seeded = tasks.seed_next_job(execution_role="remediator")
        assert seeded.id in expected_ids
        claimed = tasks.claim(execution_role="remediator")
        assert claimed["run_id"] == seeded.id
        seen.add(seeded.id)
        tasks.finish(claimed["id"], claimed["token"], {})
    assert seen == expected_ids
    assert tasks.seed_next_job(execution_role="remediator") is None
    assert tasks.claim(execution_role="collector") is None
    expected_ids = {job.id for job in [*collector_jobs, checks[0]]}
    seen = set()
    for _ in expected_ids:
        seeded = tasks.seed_next_job(execution_role="collector")
        assert seeded.id in expected_ids
        claimed = tasks.claim(execution_role="collector")
        assert claimed["run_id"] == seeded.id
        seen.add(seeded.id)
        tasks.finish(claimed["id"], claimed["token"], {})
    assert seen == expected_ids


def test_missing_or_forged_approval_cannot_queue_even_with_database_approval(repo, signing):
    private, settings = signing
    service, plan = approved(repo, settings)
    forged = signed(private, plan)
    forged["claims"]["action"] = "DELETE_ACCESS_KEY"
    for proof in (None, forged):
        with pytest.raises(ActionPlanError, match="independent signed authorization"):
            service.queue_execution(plan, "carol", plan.plan_hash, signed_approval=proof)
    assert repo.list_jobs() == []


@pytest.mark.parametrize("field,value", [("key_id", "different-key"), ("account_id", "999999999999"),
                                          ("user_name", "another-user"), ("action_type", "DELETE_ACCESS_KEY"),
                                          ("target", {"provider": "gitlab"})])
def test_signature_binds_actual_plan_fields_not_only_stored_hash(repo, signing, field, value):
    private, settings = signing
    _, plan = approved(repo, settings)
    proof = signed(private, plan)
    altered = plan.model_copy(update={field: value})
    with pytest.raises(ActionPlanError):
        authorization.verify(settings, altered, proof)


def test_signature_binds_mode_expiry_and_verifier_key(repo, signing, tmp_path):
    private, settings = signing
    _, plan = approved(repo, settings)
    proof = signed(private, plan)
    with pytest.raises(ActionPlanError):
        authorization.verify(settings, plan, proof, "emergency")
    with pytest.raises(ActionPlanError):
        authorization.verify(settings, plan, proof, now=dt.datetime.now(dt.UTC) + dt.timedelta(hours=1))
    wrong = tmp_path / "wrong.pem"
    wrong.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM,
                                                                           serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises(ActionPlanError):
        authorization.verify(settings.model_copy(update={"remediation_approval_public_key_file": str(wrong)}), plan, proof)


def test_only_remediator_executes_aws_action_and_nonce_survives_plan_state_rewrite(repo, signing):
    private, settings = signing
    service, plan = approved(repo, settings)
    proof = signed(private, plan)
    service.queue_execution(plan, "carol", plan.plan_hash, signed_approval=proof)
    adapter = FakeAdapter()
    collector = quiet_worker(repo, settings.model_copy(update={"worker_execution_role": "collector"}), adapter)
    assert not collector.process_next()
    worker = quiet_worker(repo, settings, adapter)
    assert worker.process_next()
    assert repo.get_action_plan(plan.id).status == "VERIFIED"
    assert len(adapter.writes) == 1
    # The DB-approved bit is not enough even if rewritten after an execution.
    reset = repo.update_action_plan(plan.id, status="APPROVED")
    service.queue_execution(reset, "carol", reset.plan_hash, signed_approval=proof)
    assert worker.process_next()
    assert len(adapter.writes) == 1
    assert repo.get_action_plan(plan.id).safe_error_code == "SIGNED_AUTHORIZATION_ALREADY_USED"


def test_worker_reverifies_plan_before_opening_any_cloud_client(repo, signing):
    private, settings = signing
    service, plan = approved(repo, settings)
    service.queue_execution(plan, "carol", plan.plan_hash, signed_approval=signed(private, plan))
    repo.update_action_plan(plan.id, key_id="substituted")
    worker = quiet_worker(repo, settings)
    worker.action_clients = lambda p: pytest.fail("opened cloud credentials for an altered plan")
    assert worker.process_next()
    assert repo.get_action_plan(plan.id).safe_error_code == "SIGNED_AUTHORIZATION_INVALID"


def test_cancel_during_preflight_never_writes_and_nonce_is_not_consumed(repo, signing):
    private, settings = signing
    service, plan = approved(repo, settings)
    proof = signed(private, plan)
    service.queue_execution(plan, "carol", plan.plan_hash, signed_approval=proof)
    job = repo.list_jobs()[0]

    class Cancelling(FakeAdapter):
        def key_status(self, *args):
            repo.request_job_cancel(job.id)
            return "Active"

    adapter = Cancelling()
    assert quiet_worker(repo, settings, adapter).process_next()
    assert adapter.writes == []
    assert TaskStore(repo).consume_authorization(proof["claims"]["nonce"], str(plan.id))


def test_nonce_reservation_rolls_back_with_execution_transaction(repo):
    from cremore.onboarding.store import atomic
    nonce, plan_id = str(uuid.uuid4()), str(uuid.uuid4())
    with pytest.raises(RuntimeError), atomic(repo) as bound:
        assert TaskStore(bound).consume_authorization(nonce, plan_id)
        raise RuntimeError("synthetic persistence failure")
    assert TaskStore(repo).consume_authorization(nonce, plan_id)
    assert not TaskStore(repo).consume_authorization(nonce, plan_id)


def test_api_queues_aws_actions_without_opening_injected_action_clients(repo, signing):
    from fastapi.testclient import TestClient

    from cremore.api import create_app
    private, settings = signing
    _, plan = approved(repo, settings)
    calls = []
    app = create_app(repo=repo, settings=settings, key_action_adapter_factory=lambda *a: calls.append(a))
    with TestClient(app, headers={"Authorization": "Bearer " + settings.api_token}) as client:
        exported = client.get(f"/api/v1/action-plans/{plan.id}/authorization-request")
        assert exported.status_code == 200
        proof = authorization.sign(exported.json(), private,
                                   (dt.datetime.now(dt.UTC) + dt.timedelta(minutes=10)).isoformat())
        response = client.post(f"/api/v1/action-plans/{plan.id}/execute",
                               json={"plan_hash": plan.plan_hash, "signed_approval": proof})
    assert response.status_code == 202, response.text
    assert response.json()["status"] == "QUEUED" and calls == []


def test_offline_signing_command_and_no_overwrite(repo, signing, tmp_path):
    private, settings = signing
    _, plan = approved(repo, settings)
    request = tmp_path / "request.json"
    request.write_text(json.dumps(authorization.request_for(plan)), encoding="utf-8")
    key = tmp_path / "external-private.pem"
    key.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    output = tmp_path / "approval.json"
    args = ["--request", str(request), "--private-key", str(key), "--output", str(output),
            "--expires-at", (dt.datetime.now(dt.UTC) + dt.timedelta(minutes=10)).isoformat()]
    authorization.main(args)
    proof = json.loads(output.read_text())
    assert authorization.verify(settings, plan, proof)["plan_id"] == str(plan.id)
    before = copy.deepcopy(output.read_bytes())
    with pytest.raises(FileExistsError):
        authorization.main(args)
    assert output.read_bytes() == before


def test_verifier_requires_readable_ed25519_public_key(signing, tmp_path):
    private, settings = signing
    assert authorization.verifier(settings).public_bytes_raw() == private.public_key().public_bytes_raw()
    path = tmp_path / "invalid.pem"
    for content in (None, b"malformed", private.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption())):
        if content is not None:
            path.write_bytes(content)
        with pytest.raises(ValueError, match="REMEDIATION_APPROVAL_VERIFIER_INVALID"):
            authorization.verifier(settings.model_copy(update={"remediation_approval_public_key_file": str(path)}))


@pytest.mark.parametrize("outcome", ["success", "failure", "changed", "cancelled"])
def test_machine_identity_check_is_collector_only_and_fenced(repo, signing, monkeypatch, outcome):
    from cremore.identity import machine

    _, settings = signing
    repo.put_setting(machine.KEY, {"revision": 1}, "admin")
    job = repo.enqueue_job(ScanJob(kind="machine-identity-check", payload={"revision": 1, "actor": "admin"}))
    calls = []

    def check(_keeper):
        calls.append(True)
        if outcome == "failure":
            raise RuntimeError("synthetic token must never be persisted")
        if outcome == "changed":
            repo.put_setting(machine.KEY, {"revision": 2}, "admin")
        if outcome == "cancelled":
            repo.request_job_cancel(job.id)
        return {"aws": {"state": "READY", "claims": {"sub": "synthetic-subject"}}}

    monkeypatch.setattr(machine.Keeper, "test", check)
    assert not quiet_worker(repo, settings).process_next()
    assert calls == []
    assert quiet_worker(repo, settings.model_copy(update={"worker_execution_role": "collector"})).process_next()
    row = repo.get_setting(machine.TEST_KEY)
    if outcome in ("changed", "cancelled"):
        assert row is None
    else:
        value = row["value"]
        assert value["revision"] == 1 and value["tested_by"] == "admin" and value["job_id"] == str(job.id)
        assert value["state"] == ("COMPLETED" if outcome == "success" else "FAILED")
        if outcome == "failure":
            assert value["tokens"] == {} and value["safe_error_code"] == "MACHINE_IDENTITY_CHECK_FAILED"
            assert "synthetic token" not in json.dumps(value)
