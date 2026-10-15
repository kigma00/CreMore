"""Approval-bound IAM key action plans: gates, hash binding, write-then-read-back."""

from __future__ import annotations

import datetime as dt
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import Credential
from cremore.remediation import owner_approval
from cremore.remediation.action_plans import (
    ActionPlanError,
    ActionPlanService,
    Boto3KeyActionAdapter,
    KeyActionAdapter,
    evaluate_readiness,
    validate_review,
)

NOW = dt.datetime(2026, 9, 14, 9, 0, tzinfo=dt.UTC)
SECRET_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:app/key-AbCdEf"
U = lambda n: f"00000000-0000-4000-8000-{n:012d}"


def review(**overrides) -> dict:
    base = {
        "mode": "PLANNED", "scope_evidence_id": U(1), "recovery_evidence_id": U(2),
        "scope_complete": True, "unknown_consumers": False, "business_impact": "LIMITED",
        "impact_accepted": True, "stop_criteria_reviewed": True, "replacement_reviewed": True,
        "window_start": (NOW - dt.timedelta(hours=1)).isoformat(), "window_end": (NOW + dt.timedelta(hours=4)).isoformat(),
        "consumers": [{"consumer_id": U(3), "owner_id": U(4), "evidence_id": U(5), "environment": "PRODUCTION",
                       "transition": "SUCCEEDED", "authentication_basis": "NEW_CREDENTIAL", "workload_succeeded": True,
                       "scheduled_cycle_checked": True, "confirmed_at": (NOW - dt.timedelta(hours=2)).isoformat(),
                       "valid_until": (NOW + dt.timedelta(hours=6)).isoformat()}],
    }
    base.update(overrides)
    return base


def settings(**kw) -> Settings:
    # Distinct identities (alice/bob/carol) model a multi-user OIDC install.
    return Settings(**{"AUTH_MODE": "oidc", "API_TOKEN": "t", **kw})


def credential(repo) -> Credential:
    return repo.upsert_credential(Credential(
        fingerprint="fp", credential_type="AWS_ACCESS_KEY", provider="aws", identifier="AKIAZ5X9K2" "MBV7QP3LN6",
        identifier_hint="AKIA••••••••••••3LN6", principal_arn="arn:aws:iam::123456789012:user/ci-deployer"))


class FakeAdapter(KeyActionAdapter):
    def __init__(self, status="Active", *, fail_write=None, fail_read=None):
        self.status, self.fail_write, self.fail_read, self.writes = status, fail_write, fail_read, []

    def key_status(self, user_name, key_id):
        if self.fail_read:
            raise self.fail_read
        return self.status

    def disable_key(self, user_name, key_id):
        self.writes.append(("disable", user_name, key_id))
        if self.fail_write:
            raise self.fail_write
        self.status = "Inactive"

    def delete_key(self, user_name, key_id):
        self.writes.append(("delete", user_name, key_id))
        if self.fail_write:
            raise self.fail_write
        self.status = "ABSENT"


def service(repo, *, owner_gate=False, **kw) -> ActionPlanService:
    # These tests are about the plan's own gates; the owner's approval (on by default) has its own tests.
    if not owner_gate:
        repo.put_setting(owner_approval.KEY, {"required": False}, "test")
    return ActionPlanService(repo, settings(**kw), now=lambda: NOW)


def body(**overrides) -> dict:
    base = {"action_type": "DISABLE_ACCESS_KEY", "reason_code": "EXPOSURE_CONTAINMENT",
            "idempotency_key": str(uuid.uuid4()), "operational_review": review()}
    base.update(overrides)
    return base


@pytest.fixture(params=["memory", "sql"])
def action_repo(request, tmp_path):
    if request.param == "memory":
        yield InMemoryRepository()
    else:
        engine = make_engine(f"sqlite+pysqlite:///{(tmp_path / 'actions.db').as_posix()}")
        create_all(engine)
        try:
            yield SqlRepository(engine)
        finally:
            engine.dispose()


@pytest.mark.parametrize("operation", ["create", "execute"])
def test_competing_action_requests_reserve_and_execute_once(action_repo, monkeypatch, operation):
    repo = action_repo
    cred = credential(repo)
    svc = service(repo, ACTION_EXECUTION_ENABLED="true")
    ready = Barrier(2)
    adapter = FakeAdapter()
    if operation == "create":
        original = repo.create_action_plan

        def synchronized(*args, **kwargs):
            ready.wait(timeout=10)
            return original(*args, **kwargs)

        monkeypatch.setattr(repo, "create_action_plan", synchronized)
        perform = lambda: svc.create(cred, "", "alice", body())
    else:
        plan = svc.create(cred, "", "alice", body())
        snapshot = svc.approve(plan, "bob", plan.plan_hash).model_copy(deep=True)
        original = repo.update_action_plan

        def synchronized(*args, **kwargs):
            if kwargs.get("status") == "EXECUTING":
                ready.wait(timeout=10)
            return original(*args, **kwargs)

        monkeypatch.setattr(repo, "update_action_plan", synchronized)
        perform = lambda: svc.execute(snapshot, "carol", snapshot.plan_hash, adapter=adapter)

    def request_once():
        try:
            return perform()
        except ActionPlanError as exc:
            assert exc.http_status == 409
            return None

    with ThreadPoolExecutor(max_workers=2) as workers:
        tasks = [workers.submit(request_once) for _ in range(2)]
        results = [task.result(timeout=20) for task in tasks]
    assert sum(result is not None for result in results) == 1
    assert len(repo.list_action_plans(cred.id)) == 1
    assert len(adapter.writes) == (1 if operation == "execute" else 0)


def test_incomplete_key_listing_cannot_prove_absence():
    class IncompleteIAM:
        def list_access_keys(self, **kwargs):
            return {"AccessKeyMetadata": [], "IsTruncated": True}

    with pytest.raises(ValueError, match="PAGINATION_INCOMPLETE"):
        Boto3KeyActionAdapter(IncompleteIAM()).key_status("synthetic", "synthetic-key")


def test_replaying_an_idempotency_key_requires_the_same_normalized_request(action_repo):
    svc = service(action_repo)
    cred = credential(action_repo)
    request = body()
    original = svc.create(cred, "", "alice", request)
    assert svc.create(cred, "", "alice", request).id == original.id
    with pytest.raises(ActionPlanError, match="another request"):
        svc.create(cred, "", "alice", {**request, "reason_code": "OWNER_REQUEST"})


def test_review_uses_instants_and_rejects_truthy_nonboolean_attestations():
    valid = review(window_start="2026-09-14T10:00:00+09:00", window_end="2026-09-14T02:00:00+00:00")
    assert validate_review("DISABLE_ACCESS_KEY", valid)
    for flag in ("workload_succeeded", "scheduled_cycle_checked"):
        with pytest.raises(ActionPlanError):
            validate_review("DISABLE_ACCESS_KEY", review(consumers=[{**review()["consumers"][0], flag: "false"}]))


def test_a_rotation_failure_after_key_creation_keeps_the_target_reserved():
    from cremore_aws_provider.remediation.rotation import RotationError

    class PartlyWritten(FakeRotation):
        def prepare(self, plan):
            plan.stages.append("CREATED")
            plan.new_key_id = "synthetic-successor"
            raise RotationError("ROTATION_SUCCESSOR_VALIDATION_FAILED")

    repo = InMemoryRepository()
    cred = credential(repo)
    svc = service(repo, ACTION_EXECUTION_ENABLED="true", ACTION_ROTATION_ENABLED="true", ROTATION_SECRET_ARNS=SECRET_ARN)
    plan = svc.create(cred, "", "alice", body(action_type="PREPARE_ACCESS_KEY_ROTATION",
        rotation={"secret_arn": SECRET_ARN, "expected_current_version": "A" * 32}))
    approved = svc.approve(plan, "bob", plan.plan_hash)
    result = svc.execute(approved, "carol", approved.plan_hash, rotation_service=PartlyWritten())
    assert result.status == "OUTCOME_UNKNOWN" and svc.unresolved(cred.id)
    assert result.new_key_id == "synthetic-successor"


@pytest.mark.parametrize("written,status", [(False, "FAILED"), (True, "OUTCOME_UNKNOWN")])
def test_a_provider_error_is_unknown_only_once_a_rotation_write_may_have_happened(written, status):
    class ReadFails(FakeRotation):
        def prepare(self, plan):
            plan.write_started = written  # e.g. GetSecretValue throttled before any write, or CreateAccessKey timed out
            raise TimeoutError("synthetic")

    repo = InMemoryRepository()
    cred = credential(repo)
    svc = service(repo, ACTION_EXECUTION_ENABLED="true", ACTION_ROTATION_ENABLED="true", ROTATION_SECRET_ARNS=SECRET_ARN)
    plan = svc.create(cred, "", "alice", body(action_type="PREPARE_ACCESS_KEY_ROTATION",
        rotation={"secret_arn": SECRET_ARN, "expected_current_version": "A" * 32}))
    approved = svc.approve(plan, "bob", plan.plan_hash)
    result = svc.execute(approved, "carol", approved.plan_hash, rotation_service=ReadFails())
    assert result.status == status and result.safe_error_code == "TimeoutError"
    # Nothing written: the key is free for the next plan (an emergency disable included).
    assert bool(svc.unresolved(cred.id)) is written


def test_the_rotation_timeline_keeps_each_stages_own_time():
    class Timed(FakeRotation):
        def prepare(self, plan):
            super().prepare(plan)
            plan.stage_times = ["2026-09-14T00:00:01+00:00", "2026-09-14T00:00:02+00:00"]

    repo = InMemoryRepository()
    cred = credential(repo)
    svc = service(repo, ACTION_EXECUTION_ENABLED="true", ACTION_ROTATION_ENABLED="true", ROTATION_SECRET_ARNS=SECRET_ARN)
    plan = svc.create(cred, "", "alice", body(action_type="PREPARE_ACCESS_KEY_ROTATION",
        rotation={"secret_arn": SECRET_ARN, "expected_current_version": "A" * 32}))
    approved = svc.approve(plan, "bob", plan.plan_hash)
    times = [e["recorded_at"] for e in svc.execute(approved, "carol", approved.plan_hash, rotation_service=Timed()).rotation_progress]
    assert times[:2] == ["2026-09-14T00:00:01+00:00", "2026-09-14T00:00:02+00:00"]
    assert times[2] == times[3] == svc.now().isoformat()  # stages without their own time fall back to the save time


@pytest.mark.parametrize("status", ["REQUESTED", "PREPARED", "FAILED"])
def test_legacy_rotation_uncertainty_reserves_the_key_without_changing_history(action_repo, status):
    from cremore.domain.models import RotationJob

    cred = credential(action_repo)
    svc = service(action_repo, ACTION_EXECUTION_ENABLED="true")
    plan = svc.create(cred, "", "alice", body())
    plan = svc.approve(plan, "bob", plan.plan_hash)
    job = action_repo.create_rotation_job(RotationJob(credential_id=cred.id, status=status,
        account_id="123456789012", old_key_id=cred.identifier, requested_by="old-operator"))
    before = job.model_dump()
    policy = svc.policy(cred)
    assert not policy["can_plan"] and policy["legacy_rotation_job_ids"] == [str(job.id)]
    assert policy["block_reason"] == "LEGACY_ROTATION_RECONCILIATION_REQUIRED"
    with pytest.raises(ActionPlanError, match="administrator review"):
        svc.create(cred, "", "alice", body())
    adapter = FakeAdapter()
    with pytest.raises(ActionPlanError, match="administrator review"):
        svc.execute(plan, "carol", plan.plan_hash, adapter=adapter)
    assert not adapter.writes and action_repo.get_rotation_job(job.id).model_dump() == before


def test_rotation_execution_rechecks_the_current_secret_allowlist():
    repo = InMemoryRepository()
    cred = credential(repo)
    svc = service(repo, ACTION_EXECUTION_ENABLED="true", ACTION_ROTATION_ENABLED="true", ROTATION_SECRET_ARNS=SECRET_ARN)
    plan = svc.create(cred, "", "alice", body(action_type="PREPARE_ACCESS_KEY_ROTATION",
        rotation={"secret_arn": SECRET_ARN, "expected_current_version": "A" * 32}))
    plan = svc.approve(plan, "bob", plan.plan_hash)
    svc.settings = settings(ACTION_EXECUTION_ENABLED="true", ACTION_ROTATION_ENABLED="true")
    rotation = FakeRotation()
    with pytest.raises(ActionPlanError) as error:
        svc.execute(plan, "carol", plan.plan_hash, rotation_service=rotation)
    assert error.value.code == "ROTATION_SECRET_NOT_ALLOWLISTED" and not rotation.calls


def test_rotation_recheck_does_not_equate_a_pending_stage_with_successor_validation():
    repo = InMemoryRepository()
    cred = credential(repo)
    svc = service(repo, ACTION_EXECUTION_ENABLED="true", ACTION_ROTATION_ENABLED="true", ROTATION_SECRET_ARNS=SECRET_ARN)
    plan = svc.create(cred, "", "alice", body(action_type="PREPARE_ACCESS_KEY_ROTATION",
        rotation={"secret_arn": SECRET_ARN, "expected_current_version": "A" * 32}))
    plan = svc.approve(plan, "bob", plan.plan_hash)
    plan = repo.update_action_plan(plan.id, status="OUTCOME_UNKNOWN", pending_version="v-pending",
                                   new_key_id="synthetic-successor", rotation_progress=[{"stage": "CREATED"}])
    result = svc.recheck(plan, "carol", plan.plan_hash, rotation_service=FakeRotation())
    assert result.status == "OUTCOME_UNKNOWN" and result.recheck_only


@pytest.mark.parametrize("case,expected,code", [
    ("original", "FAILED", None),
    ("older", "FAILED", None),
    # Made a minute before the recorded start by AWS's clock: may be this plan's own successor.
    ("within_skew", "OUTCOME_UNKNOWN", "ROTATION_UNRECORDED_KEY_EXISTS"),
    ("same_time", "OUTCOME_UNKNOWN", "ROTATION_UNRECORDED_KEY_EXISTS"),
    ("newer_page", "OUTCOME_UNKNOWN", "ROTATION_UNRECORDED_KEY_EXISTS"),
    ("denied", "OUTCOME_UNKNOWN", "AccessDenied"),
    ("incomplete", "OUTCOME_UNKNOWN", "IAM_PAGINATION_INCOMPLETE"),
    ("missing_date", "OUTCOME_UNKNOWN", "KEY_LIST_INCOMPLETE"),
    ("invalid_date", "OUTCOME_UNKNOWN", "KEY_LIST_INCOMPLETE"),
])
def test_stuck_rotation_recheck_reads_keys_before_releasing_target(action_repo, case, expected, code):
    from types import SimpleNamespace

    from botocore.exceptions import ClientError

    repo = action_repo
    cred = credential(repo)
    svc = service(repo, ACTION_EXECUTION_ENABLED="true", ACTION_ROTATION_ENABLED="true", ROTATION_SECRET_ARNS=SECRET_ARN)
    plan = svc.create(cred, "", "alice", body(action_type="PREPARE_ACCESS_KEY_ROTATION",
        rotation={"secret_arn": SECRET_ARN, "expected_current_version": "A" * 32}))
    plan = svc.approve(plan, "bob", plan.plan_hash)
    plan = repo.update_action_plan(plan.id, status="OUTCOME_UNKNOWN", executed_at=NOW,
                                  provider_write_started_at=NOW + dt.timedelta(seconds=1))
    with pytest.raises(ActionPlanError) as locked:
        svc.create(cred, "", "alice", body())
    assert locked.value.code == "ACTION_PLAN_TARGET_LOCKED"
    before = trail(repo)
    calls = []

    class IAM:
        def list_access_keys(self, **kwargs):
            calls.append(kwargs)
            assert kwargs["UserName"] == "ci-deployer"
            if case == "denied":
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "sensitive response"}}, "ListAccessKeys")
            keys = [{"AccessKeyId": cred.identifier, "CreateDate": NOW - dt.timedelta(days=10)}]
            if case == "incomplete":
                return {"AccessKeyMetadata": keys, "IsTruncated": True}
            if case == "newer_page" and "Marker" not in kwargs:
                return {"AccessKeyMetadata": keys, "IsTruncated": True, "Marker": "next"}
            if case != "original":
                other = {"AccessKeyId": "synthetic-unrecorded-key"}
                if case == "older":
                    other["CreateDate"] = NOW - dt.timedelta(days=1)
                elif case == "within_skew":
                    other["CreateDate"] = NOW - dt.timedelta(minutes=1)
                elif case in ("same_time", "newer_page"):
                    other["CreateDate"] = NOW + dt.timedelta(seconds=case == "newer_page")
                elif case == "invalid_date":
                    other["CreateDate"] = "not-a-date"
                keys.append(other)
            return {"AccessKeyMetadata": keys}

    result = svc.recheck(plan, "carol", plan.plan_hash, rotation_service=SimpleNamespace(iam=IAM()))
    assert result.status == expected and result.recheck_only
    assert result.safe_error_code == code
    assert calls and len(calls) == (2 if case == "newer_page" else 1)
    assert result.new_key_id is None and result.pending_version is None and result.rotation_progress == []
    after = trail(repo)
    assert all(entry in after for entry in before) and len(after) == len(before) + 1
    event = next(entry for entry in after if entry not in before)
    assert event[0] == ("ACTION_PLAN_FAILED" if expected == "FAILED" else "ACTION_PLAN_RECHECKED")
    assert event[3:5] == ("OUTCOME_UNKNOWN", expected) and event[5].endswith("RECHECK")
    assert "sensitive response" not in repr(after)
    if expected == "FAILED":
        assert result.result_kind == "ROTATION_NOT_COMPLETED" and not svc.unresolved(cred.id)
        assert svc.create(cred, "", "alice", body()).action_type == "DISABLE_ACCESS_KEY"
    else:
        assert svc.unresolved(cred.id)


@pytest.mark.parametrize("changes,code", [
    ({}, "ROTATION_EXECUTION_TIME_UNKNOWN"),
    ({"executed_at": NOW, "rotation_progress": [{"stage": "CREATED"}]}, None),
    ({"executed_at": NOW, "new_key_id": "synthetic-successor"}, None),
    ({"executed_at": NOW, "pending_version": "synthetic-pending"}, None),
])
def test_stuck_rotation_recheck_does_not_clear_missing_time_or_write_evidence(changes, code):
    from types import SimpleNamespace

    repo = InMemoryRepository()
    cred = credential(repo)
    svc = service(repo, ACTION_EXECUTION_ENABLED="true", ACTION_ROTATION_ENABLED="true", ROTATION_SECRET_ARNS=SECRET_ARN)
    plan = svc.create(cred, "", "alice", body(action_type="PREPARE_ACCESS_KEY_ROTATION",
        rotation={"secret_arn": SECRET_ARN, "expected_current_version": "A" * 32}))
    plan = svc.approve(plan, "bob", plan.plan_hash)
    plan = repo.update_action_plan(plan.id, status="OUTCOME_UNKNOWN", **changes)
    result = svc.recheck(plan, "carol", plan.plan_hash, rotation_service=SimpleNamespace(iam=object()))
    assert result.status == "OUTCOME_UNKNOWN" and result.safe_error_code == code
    assert svc.unresolved(cred.id)


def test_readiness_reasons_cover_every_gate():
    assert evaluate_readiness("DISABLE_ACCESS_KEY", None, NOW)["reasons"] == ["CHANGE_REVIEW_REQUIRED"]
    ready = evaluate_readiness("DISABLE_ACCESS_KEY", validate_review("DISABLE_ACCESS_KEY", review()), NOW)
    assert ready["execution_gate_passed"] and ready["status"] == "READY_FOR_APPROVAL" and ready["confirmed_consumers"] == 1
    stale = review(window_start=(NOW + dt.timedelta(hours=1)).isoformat(), window_end=(NOW + dt.timedelta(hours=2)).isoformat())
    assert "CHANGE_WINDOW_NOT_CURRENT" in evaluate_readiness("DISABLE_ACCESS_KEY", validate_review("DISABLE_ACCESS_KEY", stale), NOW)["reasons"]
    weak = review(business_impact="UNKNOWN", scope_complete=False, replacement_reviewed=False)
    reasons = evaluate_readiness("DISABLE_ACCESS_KEY", validate_review("DISABLE_ACCESS_KEY", weak), NOW)["reasons"]
    assert {"IMPACT_AND_RECOVERY_REVIEW_REQUIRED", "CONSUMER_SCOPE_INCOMPLETE", "REPLACEMENT_REVIEW_REQUIRED"} <= set(reasons)
    assert "EMPTY_CONSUMER_SCOPE" in evaluate_readiness("DISABLE_ACCESS_KEY", validate_review("DISABLE_ACCESS_KEY", review(consumers=[])), NOW)["reasons"]
    pending = review(consumers=[{**review()["consumers"][0], "transition": "PENDING"}])
    assert "CONSUMER_TRANSITION_NOT_CONFIRMED" in evaluate_readiness("DISABLE_ACCESS_KEY", validate_review("DISABLE_ACCESS_KEY", pending), NOW)["reasons"]
    expired = review(consumers=[{**review()["consumers"][0], "valid_until": (NOW - dt.timedelta(minutes=1)).isoformat(),
                                 "confirmed_at": (NOW - dt.timedelta(hours=3)).isoformat()}])
    assert "CONSUMER_EVIDENCE_NOT_CURRENT" in evaluate_readiness("DISABLE_ACCESS_KEY", validate_review("DISABLE_ACCESS_KEY", expired), NOW)["reasons"]
    # emergency containment skips consumer proof but needs an incident
    emergency = evaluate_readiness("DISABLE_ACCESS_KEY", validate_review("DISABLE_ACCESS_KEY", review(mode="EMERGENCY", consumers=[])), NOW)
    assert emergency["reasons"] == ["EMERGENCY_INCIDENT_REQUIRED"]
    ok = evaluate_readiness("DISABLE_ACCESS_KEY", validate_review("DISABLE_ACCESS_KEY", review(mode="EMERGENCY", incident_id=U(9), consumers=[])), NOW)
    assert ok["execution_gate_passed"] and ok["status"] == "EMERGENCY_REVIEW_REQUIRED"
    # deletion needs the irreversible-change acknowledgement; rotation needs PLANNED
    assert "DELETE_PLANNED_ACKNOWLEDGEMENT_REQUIRED" in evaluate_readiness("DELETE_ACCESS_KEY", validate_review("DELETE_ACCESS_KEY", review()), NOW)["reasons"]
    assert evaluate_readiness("DELETE_ACCESS_KEY", validate_review("DELETE_ACCESS_KEY", review(deletion_acknowledged=True)), NOW)["execution_gate_passed"]
    assert "ROTATION_PLANNED_REVIEW_REQUIRED" in evaluate_readiness("PREPARE_ACCESS_KEY_ROTATION", validate_review("PREPARE_ACCESS_KEY_ROTATION", review(mode="EMERGENCY", incident_id=U(9))), NOW)["reasons"]


def test_review_validation_rejects_malformed_references():
    with pytest.raises(ActionPlanError):
        validate_review("DISABLE_ACCESS_KEY", review(scope_evidence_id="not-a-uuid"))
    with pytest.raises(ActionPlanError):
        validate_review("DISABLE_ACCESS_KEY", review(window_end=review()["window_start"]))
    with pytest.raises(ActionPlanError):
        validate_review("DISABLE_ACCESS_KEY", review(consumers=[review()["consumers"][0]] * 2))
    with pytest.raises(ActionPlanError):
        validate_review("DISABLE_ACCESS_KEY", review(consumers=[{**review()["consumers"][0], "environment": "LAB"}]))
    assert validate_review("DISABLE_ACCESS_KEY", None) is None


def test_plan_lifecycle_disable_with_read_back():
    repo = InMemoryRepository()
    cred = credential(repo)
    svc = service(repo, ACTION_EXECUTION_ENABLED="true")
    policy = svc.policy(cred)
    assert policy["can_plan"] and policy["supported_action"] == "DISABLE_ACCESS_KEY" and policy["execution_enabled"]

    plan = svc.create(cred, "", "alice", body())
    assert plan.status == "PENDING_APPROVAL" and plan.user_name == "ci-deployer" and plan.account_id == "123456789012"
    assert len(plan.plan_hash) == 64 and plan.expires_at == NOW + dt.timedelta(hours=24)
    assert plan.adapter_version == "AWS_DISABLE_V1" and plan.policy_revision == "INDEPENDENT_APPROVAL_OPERATIONAL_V2"
    assert svc.policy(cred)["block_reason"] == "ACTION_PLAN_TARGET_LOCKED"  # one unresolved plan per key

    # approval: wrong hash, same identity, then a different admin
    with pytest.raises(ActionPlanError) as info:
        svc.approve(plan, "bob", "0" * 64)
    assert info.value.code == "PLAN_HASH_MISMATCH"
    with pytest.raises(ActionPlanError) as info:
        svc.approve(plan, "alice", plan.plan_hash)
    assert info.value.code == "INDEPENDENT_APPROVAL_REQUIRED"
    approved = svc.approve(plan, "bob", plan.plan_hash)
    assert approved.status == "APPROVED" and approved.approved_by == "bob"

    adapter = FakeAdapter("Active")
    done = svc.execute(approved, "carol", plan.plan_hash, adapter=adapter)
    assert done.status == "VERIFIED" and done.verified_at and done.provider_write_started_at
    assert adapter.writes == [("disable", "ci-deployer", ("AKIAZ5X9K2" "MBV7QP3LN6"))]
    assert svc.policy(cred)["can_plan"] is True  # target released

    public = svc.public(done)
    assert public["status"] == "VERIFIED" and "key_id" not in public and "rotation" not in public
    assert public["readiness"]["execution_gate_passed"] and public["operational_review"]["consumers"]


def test_single_operator_self_approves_only_after_reconfirming_and_never_under_oidc():
    repo = InMemoryRepository()
    cred = credential(repo)
    single = service(repo, AUTH_MODE="local", ACTION_EXECUTION_ENABLED="true")
    assert single.policy(cred)["single_operator"] is True
    assert single.policy(cred)["independent_approval_required"] is False
    plan = single.create(cred, "", "local", body())
    with pytest.raises(ActionPlanError) as info:
        single.approve(plan, "local", plan.plan_hash)
    assert info.value.code == "SELF_APPROVAL_CONFIRMATION_REQUIRED"
    with pytest.raises(ActionPlanError) as info:
        single.approve(plan, "local", "0" * 64, True)
    assert info.value.code == "PLAN_HASH_MISMATCH"
    approved = single.approve(plan, "local", plan.plan_hash, True)
    assert approved.status == "APPROVED" and single.public(approved)["self_approved"] is True

    # The same self-approved plan cannot run once the install uses OIDC identities.
    with pytest.raises(ActionPlanError) as info:
        service(repo, ACTION_EXECUTION_ENABLED="true").execute(approved, "local", plan.plan_hash, adapter=FakeAdapter("Active"))
    assert info.value.code == "INDEPENDENT_APPROVAL_REQUIRED"
    done = single.execute(approved, "local", plan.plan_hash, adapter=FakeAdapter("Active"))
    assert done.status == "VERIFIED"


def test_rotation_service_accepts_self_approval_only_for_single_operator():
    from cremore_aws_provider.remediation.rotation import (
        RotationError,
        RotationPlan,
        RotationService,
    )

    plan = RotationPlan(user_name="u", account_id="123456789012", secret_arn="arn", expected_current_version="v1",
                        old_key_id="k", requested_by="local", approved_by="local")
    with pytest.raises(RotationError, match="ROTATION_TWO_PARTY_REQUIRED"):
        RotationService._require_two_party(plan)
    plan.single_operator = True
    RotationService._require_two_party(plan)


def test_execution_gates_and_unknown_outcomes():
    repo = InMemoryRepository()
    cred = credential(repo)
    svc = service(repo)  # execution disabled
    plan = svc.create(cred, "", "alice", body())
    plan = svc.approve(plan, "bob", plan.plan_hash)
    with pytest.raises(ActionPlanError) as info:
        svc.execute(plan, "carol", plan.plan_hash, adapter=FakeAdapter())
    assert info.value.code == "EXECUTION_DISABLED"

    enabled = service(repo, ACTION_EXECUTION_ENABLED="true")
    # preflight failures never start a write
    absent = enabled.execute(plan, "carol", plan.plan_hash, adapter=FakeAdapter("ABSENT"))
    assert absent.status == "FAILED" and absent.safe_error_code == "KEY_ABSENT" and absent.provider_write_started_at is None

    # a write that raises after starting is OUTCOME_UNKNOWN and rechecked read-only
    cred2 = repo.upsert_credential(Credential(fingerprint="fp2", credential_type="AWS_ACCESS_KEY", provider="aws",
                                              identifier="AKIAZ5X9K2" "MBV7QP3LN7", identifier_hint="h",
                                              principal_arn="arn:aws:iam::123456789012:user/other"))
    plan2 = enabled.create(cred2, "", "alice", body())
    plan2 = enabled.approve(plan2, "bob", plan2.plan_hash)
    flaky = FakeAdapter("Active", fail_write=ConnectionError("reset"))
    unknown = enabled.execute(plan2, "carol", plan2.plan_hash, adapter=flaky)
    assert unknown.status == "OUTCOME_UNKNOWN" and unknown.safe_error_code == "ConnectionError" and unknown.provider_write_started_at
    assert enabled.policy(cred2)["block_reason"] == "ACTION_PLAN_TARGET_LOCKED"
    # recheck never writes; it verifies only the exact intended state
    still_active = enabled.recheck(unknown, "carol", plan2.plan_hash, adapter=FakeAdapter("Active"))
    assert still_active.status == "OUTCOME_UNKNOWN" and still_active.recheck_only and still_active.safe_error_code == "STATE_ACTIVE"
    verified = enabled.recheck(still_active, "carol", plan2.plan_hash, adapter=FakeAdapter("Inactive"))
    assert verified.status == "VERIFIED" and verified.recheck_only


def test_expiry_cancel_and_idempotency():
    repo = InMemoryRepository()
    cred = credential(repo)
    svc = service(repo)
    request = body()
    plan = svc.create(cred, "", "alice", request)
    assert svc.create(cred, "", "alice", request).id == plan.id  # retried lost response
    with pytest.raises(ActionPlanError) as info:
        svc.create(cred, "", "mallory", request)
    assert info.value.code == "IDEMPOTENCY_KEY_REUSED"
    late = ActionPlanService(repo, settings(), now=lambda: NOW + dt.timedelta(hours=25))
    assert late.public(plan)["status"] == "EXPIRED"
    with pytest.raises(ActionPlanError) as info:
        late.approve(plan, "bob", plan.plan_hash)
    assert info.value.code == "PLAN_NOT_PENDING"
    assert late.policy(cred)["can_plan"] is True  # an expired plan no longer locks the key
    cancelled = svc.cancel(plan, "alice")
    assert cancelled.status == "CANCELLED"
    with pytest.raises(ActionPlanError):
        svc.cancel(cancelled, "alice")


def test_delete_requires_inactive_key_acknowledgement_and_its_own_gate():
    repo = InMemoryRepository()
    cred = credential(repo)
    svc = service(repo, ACTION_EXECUTION_ENABLED="true")
    plan = svc.create(cred, "", "alice", body(action_type="DELETE_ACCESS_KEY", operational_review=review(deletion_acknowledged=True)))
    plan = svc.approve(plan, "bob", plan.plan_hash)
    with pytest.raises(ActionPlanError) as info:
        svc.execute(plan, "carol", plan.plan_hash, adapter=FakeAdapter("Inactive"))
    assert info.value.code == "DELETION_DISABLED"
    deleting = service(repo, ACTION_EXECUTION_ENABLED="true", ACTION_DELETION_ENABLED="true")
    still_active = deleting.execute(plan, "carol", plan.plan_hash, adapter=FakeAdapter("Active"))
    assert still_active.status == "FAILED" and still_active.safe_error_code == "KEY_NOT_INACTIVE"
    plan2 = deleting.create(cred, "", "alice", body(action_type="DELETE_ACCESS_KEY", operational_review=review(deletion_acknowledged=True)))
    plan2 = deleting.approve(plan2, "bob", plan2.plan_hash)
    adapter = FakeAdapter("Inactive")
    assert deleting.execute(plan2, "carol", plan2.plan_hash, adapter=adapter).status == "VERIFIED"
    assert adapter.writes == [("delete", "ci-deployer", ("AKIAZ5X9K2" "MBV7QP3LN6"))]
    # an unacknowledged deletion never reaches approval
    unacked = deleting.create(cred, "", "alice", body(action_type="DELETE_ACCESS_KEY"))
    with pytest.raises(ActionPlanError) as info:
        deleting.approve(unacked, "bob", unacked.plan_hash)
    assert info.value.code == "READINESS_GATE_FAILED" and "DELETE_PLANNED_ACKNOWLEDGEMENT_REQUIRED" in str(info.value)


class FakeRotation:
    def __init__(self, fail=None):
        self.fail, self.calls = fail, []

        class Secrets:
            def describe_secret(self_inner, SecretId):
                return {"VersionIdsToStages": {"v-pending": ["AWSPENDING"]}}

        self.secrets = Secrets()

    def prepare(self, plan):
        self.calls.append("prepare")
        if self.fail:
            raise self.fail
        plan.stages += ["CREATED", "STAGED", "VALIDATED", "READBACK"]
        plan.new_key_id, plan.pending_version = ("AKIANEWKEY" "0000000001"), "v-pending"

    def publish(self, plan):
        self.calls.append(("publish", plan.new_key_id, plan.pending_version))
        plan.stages.append("PUBLISHED")


def test_rotation_phases_bind_secret_and_chain_prepare_to_publish():
    repo = InMemoryRepository()
    cred = credential(repo)
    svc = service(repo, ACTION_EXECUTION_ENABLED="true", ACTION_ROTATION_ENABLED="true", ROTATION_SECRET_ARNS=SECRET_ARN)
    rot = review(consumers=[{**review()["consumers"][0], "transition": "PENDING", "authentication_basis": "UNKNOWN",
                             "workload_succeeded": False, "confirmed_at": "0001-01-01T00:00:00Z",
                             "valid_until": "0001-01-01T00:00:00Z"}])
    binding = {"secret_arn": SECRET_ARN, "expected_current_version": "A" * 32}
    with pytest.raises(ActionPlanError) as info:
        svc.create(cred, "", "alice", body(action_type="PREPARE_ACCESS_KEY_ROTATION", operational_review=rot,
                                            rotation={**binding, "secret_arn": SECRET_ARN.replace("app", "other")}))
    assert info.value.code == "ROTATION_SECRET_NOT_ALLOWLISTED"
    prep = svc.create(cred, "", "alice", body(action_type="PREPARE_ACCESS_KEY_ROTATION", operational_review=rot, rotation=binding))
    assert prep.workflow_version == "APPROVED_ROTATION_V1" and prep.adapter_version == "AWS_ROTATION_V1"
    prep = svc.approve(prep, "bob", prep.plan_hash)
    rotation = FakeRotation()
    prep = svc.execute(prep, "carol", prep.plan_hash, rotation_service=rotation)
    assert prep.status == "VERIFIED" and prep.result_kind == "SUCCESSOR_PREPARED_OLD_KEY_ACTIVE"
    assert prep.next_step == "INDEPENDENTLY_APPROVE_PUBLISH" and prep.new_key_id == "AKIANEWKEY" "0000000001"
    assert [e["stage"] for e in prep.rotation_progress] == ["CREATED", "PENDING_WRITE_STARTED", "VALIDATED", "PENDING_CONFIRMED"]
    public = svc.public(prep)
    assert public["rotation"] == binding and "new_key_id" not in public

    # publish must reference that verified preparation, and reuses its candidate
    with pytest.raises(ActionPlanError):
        svc.create(cred, "", "alice", body(action_type="PUBLISH_ACCESS_KEY_ROTATION", operational_review=rot,
                                            rotation={**binding, "preparation_plan_id": str(uuid.uuid4())}))
    pub = svc.create(cred, "", "alice", body(action_type="PUBLISH_ACCESS_KEY_ROTATION", operational_review=rot,
                                              rotation={**binding, "preparation_plan_id": str(prep.id)}))
    pub = svc.approve(pub, "bob", pub.plan_hash)
    pub = svc.execute(pub, "carol", pub.plan_hash, rotation_service=rotation)
    assert pub.status == "VERIFIED" and pub.result_kind == "SUCCESSOR_PUBLISHED_OLD_KEY_ACTIVE"
    assert rotation.calls[-1] == ("publish", ("AKIANEWKEY" "0000000001"), "v-pending")

    # a checked precondition failure is FAILED with the rotation code, not unknown
    from cremore_aws_provider.remediation.rotation import RotationError

    cred2 = repo.upsert_credential(Credential(fingerprint="fp3", credential_type="AWS_ACCESS_KEY", provider="aws",
                                              identifier="AKIAZ5X9K2" "MBV7QP3LN8", identifier_hint="h",
                                              principal_arn="arn:aws:iam::123456789012:user/third"))
    drift = svc.create(cred2, "", "alice", body(action_type="PREPARE_ACCESS_KEY_ROTATION", operational_review=rot, rotation=binding))
    drift = svc.approve(drift, "bob", drift.plan_hash)
    failed = svc.execute(drift, "carol", drift.plan_hash, rotation_service=FakeRotation(fail=RotationError("ROTATION_SECRET_DRIFT")))
    assert failed.status == "FAILED" and failed.safe_error_code == "ROTATION_SECRET_DRIFT" and failed.result_kind == "ROTATION_NOT_COMPLETED"


KEY_ID = "AKIA" + "Z5X9K2MBV7QP3LN6"


@pytest.mark.parametrize("credential_type,identifier,arn,expected", [
    # A key id observed without its secret: disabling or rotating addresses the
    # key by its id, so the missing half does not block the action.
    ("AWS_ACCESS_KEY_ID", KEY_ID, "arn:aws:iam::123456789012:user/ci-deployer", True),
    ("AWS_ACCESS_KEY", KEY_ID, "arn:aws:iam::123456789012:user/ci-deployer", True),
    # A secret alone carries no key id; there is nothing to address.
    ("AWS_SECRET_ACCESS_KEY", None, "arn:aws:iam::123456789012:user/ci-deployer", False),
    # No established owner: the key id alone names no user to act in.
    ("AWS_ACCESS_KEY_ID", KEY_ID, None, False),
    # A role session is not an IAM user with access keys.
    ("AWS_ACCESS_KEY_ID", "ASIA" + KEY_ID[4:], "arn:aws:iam::123456789012:assumed-role/dev/s", False),
])
def test_a_key_id_without_its_secret_is_still_actionable_once_its_owner_is_known(
        credential_type, identifier, arn, expected):
    repo = InMemoryRepository()
    cred = repo.upsert_credential(Credential(
        fingerprint=f"fp-{credential_type}-{arn}", credential_type=credential_type, provider="aws",
        identifier=identifier, principal_arn=arn))
    service = ActionPlanService(repo, settings(), now=lambda: NOW)

    assert service.eligible(cred) is expected
    assert service.policy(cred)["can_plan"] is expected


def trail(repo) -> list[tuple]:
    return sorted(((e.event_type, e.actor, e.target_type, e.from_status, e.to_status, e.note) for e in repo.list_events(100)),
                  key=repr)


def test_every_plan_change_and_every_refused_attempt_is_in_the_audit_trail(action_repo):
    repo = action_repo
    cred = credential(repo)
    svc = service(repo, ACTION_EXECUTION_ENABLED="true")
    with pytest.raises(ActionPlanError):
        svc.create(cred, "", "alice", body(reason_code="BECAUSE"))
    plan = svc.create(cred, "", "alice", body())
    with pytest.raises(ActionPlanError):
        svc.approve(plan, "bob", "0" * 64)
    approved = svc.approve(plan, "bob", plan.plan_hash)
    with pytest.raises(ActionPlanError):
        svc.gate(approved, "carol", "0" * 64)
    svc.execute(approved, "carol", plan.plan_hash, adapter=FakeAdapter("Active"))
    bound = f"plan_hash={plan.plan_hash}"
    assert trail(repo) == sorted([
        ("ACTION_PLAN_REFUSED", "alice", "credential", None, None, "REQUEST REQUEST_INVALID"),
        ("ACTION_PLAN_REQUESTED", "alice", "action_plan", None, "PENDING_APPROVAL",
         f"DISABLE_ACCESS_KEY EXPOSURE_CONTAINMENT {bound}"),
        ("ACTION_PLAN_REFUSED", "bob", "action_plan", "PENDING_APPROVAL", "PENDING_APPROVAL", f"APPROVE PLAN_HASH_MISMATCH {bound}"),
        ("ACTION_PLAN_APPROVED", "bob", "action_plan", "PENDING_APPROVAL", "APPROVED", bound),
        ("ACTION_PLAN_REFUSED", "carol", "action_plan", "APPROVED", "APPROVED", f"EXECUTE PLAN_HASH_MISMATCH {bound}"),
        ("ACTION_PLAN_EXECUTION_STARTED", "carol", "action_plan", "APPROVED", "EXECUTING", bound),
        ("ACTION_PLAN_VERIFIED", "carol", "action_plan", "EXECUTING", "VERIFIED", bound),
    ], key=repr)
    targets = {e.target_id for e in repo.list_events(100) if e.target_type == "action_plan"}
    assert targets == {plan.id}


def test_an_unknown_outcome_its_rechecks_and_a_cancellation_are_audited(action_repo):
    repo = action_repo
    cred = credential(repo)
    svc = service(repo, ACTION_EXECUTION_ENABLED="true")
    plan = svc.create(cred, "", "alice", body())
    approved = svc.approve(plan, "bob", plan.plan_hash)
    unknown = svc.execute(approved, "carol", plan.plan_hash, adapter=FakeAdapter("Active", fail_write=RuntimeError("boom")))
    assert unknown.status == "OUTCOME_UNKNOWN"
    still = svc.recheck(unknown, "carol", plan.plan_hash, adapter=FakeAdapter("Active"))
    svc.recheck(still, "carol", plan.plan_hash, adapter=FakeAdapter("Inactive"))
    events = [e for e in trail(repo) if e[0] != "ACTION_PLAN_REQUESTED"]
    kinds = [e[0] for e in events]
    assert kinds.count("ACTION_PLAN_OUTCOME_UNKNOWN") == 1 and kinds.count("ACTION_PLAN_RECHECKED") == 1
    verified = next(e for e in events if e[0] == "ACTION_PLAN_VERIFIED")
    assert verified[3:5] == ("OUTCOME_UNKNOWN", "VERIFIED") and verified[5].endswith("RECHECK")
    rechecked = next(e for e in events if e[0] == "ACTION_PLAN_RECHECKED")
    assert rechecked[5] == f"plan_hash={plan.plan_hash} STATE_ACTIVE RECHECK"

    other = credential_for(repo, "AKIAZ5X9K2" "MBV7QP3LN7")
    pending = svc.create(other, "", "alice", body())
    svc.cancel(pending, "alice")
    with pytest.raises(ActionPlanError):
        svc.cancel(repo.get_action_plan(pending.id), "alice")
    cancels = [e for e in trail(repo) if e[1] == "alice" and e[0] in ("ACTION_PLAN_CANCELLED", "ACTION_PLAN_REFUSED")]
    assert [e[0] for e in cancels] == ["ACTION_PLAN_CANCELLED", "ACTION_PLAN_REFUSED"]
    assert cancels[1][5].startswith("CANCEL PLAN_NOT_CANCELLABLE")


def credential_for(repo, identifier) -> Credential:
    return repo.upsert_credential(Credential(
        fingerprint="fp-" + identifier, credential_type="AWS_ACCESS_KEY", provider="aws", identifier=identifier,
        identifier_hint="AKIA••••" + identifier[-4:], principal_arn="arn:aws:iam::123456789012:user/ci-other"))


def test_a_plan_change_and_its_audit_row_commit_together(tmp_path, monkeypatch):
    engine = make_engine(f"sqlite+pysqlite:///{(tmp_path / 'atomic.db').as_posix()}")
    create_all(engine)
    try:
        repo = SqlRepository(engine)
        cred = credential(repo)
        svc = service(repo)
        plan = svc.create(cred, "", "alice", body())

        def refuse(self, conn, event, secret=None):
            raise RuntimeError("synthetic audit write failure")

        monkeypatch.setattr(SqlRepository, "_record_event", refuse)
        with pytest.raises(RuntimeError):
            svc.approve(plan, "bob", plan.plan_hash)
        monkeypatch.undo()
        # No approval without its audit row.
        assert repo.get_action_plan(plan.id).status == "PENDING_APPROVAL"
        assert [e.event_type for e in repo.list_events(10)] == ["ACTION_PLAN_REQUESTED"]
    finally:
        engine.dispose()


# --- the owner's approval before execution (cremore.remediation.owner_approval, N2b-2) -------------------------------

def approved_plan(repo, svc, **overrides):
    plan = svc.create(credential(repo), "", "alice", body(**overrides))
    return svc.approve(plan, "bob", plan.plan_hash)


def expose(repo, credential_id, where="public", *, connection=True):
    """An exposure a connection's scan found (or, without ``connection``, one pasted text named)."""
    from cremore.domain.models import Exposure

    exposure = repo.upsert_exposure(Exposure(
        credential_id=credential_id, source_type="github" if connection else "inline", resource_name="acme/app",
        location=f"deploy-{where}.yml", metadata={"exposure": where},
        source_connection_id=uuid.uuid4() if connection else None))
    if repo.get_finding_for_credential(credential_id) is None:
        repo.upsert_finding(credential_id, exposure.id, "HIGH")
    return exposure


def test_an_action_its_users_see_waits_for_the_owner_unless_an_admin_turned_that_off(action_repo):
    svc = service(action_repo, owner_gate=True, ACTION_EXECUTION_ENABLED="true")
    assert svc.installation_policy()["owner_approval_required"] is True
    approved = approved_plan(action_repo, svc)
    with pytest.raises(ActionPlanError) as info:
        svc.execute(approved, "carol", approved.plan_hash, adapter=FakeAdapter("Active"))
    assert (info.value.code, info.value.http_status) == ("OWNER_APPROVAL_REQUIRED", 409)
    assert any(e[0] == "ACTION_PLAN_REFUSED" and e[5].startswith("EXECUTE OWNER_APPROVAL_REQUIRED") for e in trail(action_repo))
    # A decline does not open it either; the owner's approval does.
    owner_approval.record(action_repo, approved, "alice", owner="kim", evidence="mail", decision="decline", note="",
                          now=NOW)
    with pytest.raises(ActionPlanError):
        svc.execute(approved, "carol", approved.plan_hash, adapter=FakeAdapter("Active"))
    owner_approval.record(action_repo, approved, "alice", owner="kim", evidence="mail 2", decision="approve", note="",
                          now=NOW)
    assert svc.execute(approved, "carol", approved.plan_hash, adapter=FakeAdapter("Active")).status == "VERIFIED"


def test_preparing_a_successor_does_not_wait_for_the_owner_and_the_switch_turns_the_wait_off():
    repo = InMemoryRepository()
    svc = service(repo, owner_gate=True, ACTION_EXECUTION_ENABLED="true")
    approved = approved_plan(repo, svc)
    prepare = owner_approval.OWNER_ACTIONS
    assert "PREPARE_ACCESS_KEY_ROTATION" not in prepare and "PUBLISH_ACCESS_KEY_ROTATION" in prepare
    repo.put_setting(owner_approval.KEY, {"required": False}, "ada")
    assert svc.installation_policy()["owner_approval_required"] is False
    assert svc.execute(approved, "carol", approved.plan_hash, adapter=FakeAdapter("Active")).status == "VERIFIED"


def test_an_admin_contains_a_publicly_exposed_key_at_once_and_the_owner_is_told_after(action_repo):
    svc = service(action_repo, owner_gate=True, ACTION_EXECUTION_ENABLED="true")
    approved = approved_plan(action_repo, svc)
    public = svc.public(approved)
    assert public["emergency_eligible"] is False  # no public exposure yet
    with pytest.raises(ActionPlanError) as info:
        svc.emergency(approved, "ada", approved.plan_hash, "공개 저장소에 노출된 키")
    assert info.value.code == "EMERGENCY_NOT_PUBLIC"
    expose(action_repo, approved.credential_id, "private")
    with pytest.raises(ActionPlanError):
        svc.emergency(approved, "ada", approved.plan_hash, "공개 저장소에 노출된 키")
    expose(action_repo, approved.credential_id)
    assert svc.public(approved)["emergency_eligible"] is True
    # A plain execution still waits; an execution claiming an emergency that was never declared waits too.
    with pytest.raises(ActionPlanError):
        svc.execute(approved, "carol", approved.plan_hash, adapter=FakeAdapter("Active"), emergency=True)
    svc.emergency(approved, "ada", approved.plan_hash, "공개 저장소에 노출된 키")
    assert [e for e in trail(action_repo) if e[0] == "ACTION_PLAN_EMERGENCY"] == [
        ("ACTION_PLAN_EMERGENCY", "ada", "action_plan", "APPROVED", "APPROVED",
         f'plan_hash={approved.plan_hash} reason="공개 저장소에 노출된 키"')]
    done = svc.execute(approved, "ada", approved.plan_hash, adapter=FakeAdapter("Active"), emergency=True)
    assert done.status == "VERIFIED"
    shown = svc.public(done)["owner_emergency"]
    assert (shown["by"], shown["reason"], shown["notice_pending"]) == ("ada", "공개 저장소에 노출된 키", True)
    subject, text = owner_approval.notice_message(done, shown, "ko")
    assert subject == "[CreMore] AWS 액세스 키 긴급 차단 알림" and "사유: 공개 저장소에 노출된 키" in text and "http" not in text
    told = owner_approval.noticed(action_repo, done, "carol", channel="mail", recipient="kim@example.com", evidence=None,
                                  note="mail · to=kim@example.com", now=NOW)
    assert told["notice_pending"] is False and told["notice_to"] == "kim@example.com"
    with pytest.raises(owner_approval.OwnerApprovalError):
        owner_approval.noticed(action_repo, done, "carol", channel="mail", recipient="kim@example.com", evidence=None,
                               note="again", now=NOW)


def test_an_emergency_is_only_a_disable_that_still_waits_for_its_owner():
    repo = InMemoryRepository()
    svc = service(repo, owner_gate=True, ACTION_EXECUTION_ENABLED="true", ACTION_DELETION_ENABLED="true")
    deleting = approved_plan(repo, svc, action_type="DELETE_ACCESS_KEY",
                             operational_review=review(deletion_acknowledged=True))
    expose(repo, deleting.credential_id)
    with pytest.raises(ActionPlanError) as info:
        svc.emergency(deleting, "ada", deleting.plan_hash, "공개 저장소에 노출된 키")
    assert info.value.code == "EMERGENCY_ACTION_NOT_ALLOWED"
    svc.cancel(deleting, "alice")
    approved = approved_plan(repo, svc)
    owner_approval.record(repo, approved, "alice", owner="kim", evidence="mail", decision="approve", note="", now=NOW)
    with pytest.raises(ActionPlanError) as info:
        svc.emergency(approved, "ada", approved.plan_hash, "공개 저장소에 노출된 키")
    assert info.value.code == "EMERGENCY_NOT_NEEDED"


def test_whoever_decided_as_the_owner_does_not_also_approve_the_plan():
    repo = InMemoryRepository()
    svc = service(repo, owner_gate=True, ACTION_EXECUTION_ENABLED="true")
    plan = svc.create(credential(repo), "", "alice", body())
    token, expires = owner_approval.new_link(repo, plan, NOW)
    owner_approval.start(repo, plan, "alice", token=token, expires=expires, channel="mail", recipient="bob@example.com",
                         now=NOW, note="mail · to=bob@example.com")
    owner_approval.decide(repo, token, "approve", None, NOW, lambda _id: plan, {"subject": "bob", "email": "bob@example.com"})
    with pytest.raises(ActionPlanError) as info:
        svc.approve(plan, "bob", plan.plan_hash)
    assert info.value.code == "INDEPENDENT_APPROVAL_REQUIRED"
    assert svc.approve(plan, "carol", plan.plan_hash).status == "APPROVED"


def test_the_security_side_cannot_answer_as_the_owner_in_the_ticket_system():
    from cremore.governance import principals
    from cremore.ticketing.contract import Answer, Opened

    repo = InMemoryRepository()
    config = settings(ACTION_EXECUTION_ENABLED="true", FINGERPRINT_KEY="ab" * 32)
    svc = ActionPlanService(repo, config, now=lambda: NOW)
    for subject in ("alice", "bob", "carol"):  # their company sign-ins carried these addresses
        principals.remember(repo, config, subject, f"{subject}@example.com")

    def asked(plan, address):
        """The owner's account in a plugin ticket system, which carries ``address``, is asked; the request id."""
        request = str(uuid.uuid4())
        owner_approval.start_ticket(repo, plan, "alice", system="fake", binding="b", recipient=address,
                                    recipient_marks=[principals.mark(config, address)], request=request,
                                    expires=owner_approval.window(repo, plan, NOW), now=NOW, note="fake")
        owner_approval.ticket_opened(repo, plan, request, "fake", Opened(ticket="1", approval="2", approver="42"),
                                     "alice")
        return request

    def answered_by(plan, address):
        """The owner, asked at ``address`` in the ticket system, approved there."""
        request = asked(plan, address)
        assert owner_approval.ticket_answered(repo, str(plan.id), request, Answer(state="APPROVED", by="42"), NOW,
                                              lambda _id: plan) == "APPROVED"

    plan = svc.create(credential(repo), "", "alice", body())
    asked(plan, "Bob@Example.com")
    with pytest.raises(ActionPlanError) as info:  # bob is still being asked as the owner: he does not approve
        svc.approve(plan, "bob", plan.plan_hash)
    assert info.value.code == "INDEPENDENT_APPROVAL_REQUIRED"
    answered_by(plan, "Bob@Example.com")
    for approver in ("bob", "dave"):  # bob answered as the owner; dave's address was never seen, so cannot be told apart
        with pytest.raises(ActionPlanError) as info:
            svc.approve(plan, approver, plan.plan_hash)
        assert info.value.code == "INDEPENDENT_APPROVAL_REQUIRED"
    approved = svc.approve(plan, "carol", plan.plan_hash)
    assert svc.gate(approved, "carol", approved.plan_hash)["execution_gate_passed"] is True

    # Checked again before execution: an answer can land after the approval that saw none.
    key = repo.upsert_credential(Credential(
        fingerprint="fp-2", credential_type="AWS_ACCESS_KEY", provider="aws", identifier="AKIAZ5X9K2" "MBV7QP3LN7",
        identifier_hint="AKIA••••••••••••3LN7", principal_arn="arn:aws:iam::123456789012:user/ci-deployer"))
    second = svc.create(key, "", "alice", body())
    second = svc.approve(second, "carol", second.plan_hash)
    answered_by(second, "alice@example.com")  # the plan's own requester
    with pytest.raises(ActionPlanError) as info:
        svc.gate(second, "carol", second.plan_hash)
    assert info.value.code == "INDEPENDENT_APPROVAL_REQUIRED"


def test_a_public_label_is_evidence_only_from_a_connection_scan_on_a_live_finding():
    repo = InMemoryRepository()
    svc = service(repo, owner_gate=True, ACTION_EXECUTION_ENABLED="true")
    approved = approved_plan(repo, svc)
    expose(repo, approved.credential_id, connection=False)
    assert owner_approval.publicly_exposed(repo, approved.credential_id) is False  # pasted text labels nothing
    expose(repo, approved.credential_id)
    assert owner_approval.publicly_exposed(repo, approved.credential_id) is True
    finding = repo.get_finding_for_credential(approved.credential_id)
    repo.update_finding_status(finding.id, "FALSE_POSITIVE")
    assert owner_approval.publicly_exposed(repo, approved.credential_id) is False


def test_an_emergency_that_never_ran_leaves_nothing_to_tell_and_only_its_declarer_runs_it():
    repo = InMemoryRepository()
    svc = service(repo, owner_gate=True, ACTION_EXECUTION_ENABLED="true")
    approved = approved_plan(repo, svc)
    expose(repo, approved.credential_id)
    svc.emergency(approved, "ada", approved.plan_hash, "공개 저장소에 노출된 키")
    # Declared, but the provider was never reached (the session was refused): nothing to tell the owner.
    view = svc.public(approved)["owner_emergency"]
    assert (view["applied"], view["notice_pending"]) == (False, False)
    with pytest.raises(owner_approval.OwnerApprovalError):
        owner_approval.noticed(repo, approved, "carol", channel="mail", recipient="kim@example.com", evidence=None,
                               note="x", now=NOW)
    # Someone else's execution cannot borrow the declaration, and its refusal is filed as that emergency.
    with pytest.raises(ActionPlanError) as refused:
        svc.execute(approved, "carol", approved.plan_hash, adapter=FakeAdapter("Active"), emergency=True)
    assert refused.value.code == "OWNER_APPROVAL_REQUIRED"
    assert any(e[0] == "ACTION_PLAN_REFUSED" and e[5].startswith("EMERGENCY OWNER_APPROVAL_REQUIRED") for e in trail(repo))
    done = svc.execute(approved, "ada", approved.plan_hash, adapter=FakeAdapter("Active"), emergency=True)
    view = svc.public(done)["owner_emergency"]
    assert (done.status, view["applied"], view["notice_pending"]) == ("VERIFIED", True, True)
    # The owner who declined is told it was contained despite that.
    owner_approval.record(repo, approved.model_copy(update={"status": "APPROVED"}), "alice", owner="kim",
                          evidence="mail", decision="decline", note="", now=NOW)
    _subject, text = owner_approval.notice_message(done, owner_approval.emergency(repo, done.id), "ko", declined=True)
    assert "소유자가 거절한 조치였지만" in text


def test_the_owner_cannot_also_have_approved_even_when_the_decision_lands_after_the_approval():
    repo = InMemoryRepository()
    svc = service(repo, owner_gate=True, ACTION_EXECUTION_ENABLED="true")
    plan = svc.create(credential(repo), "", "alice", body())
    token, expires = owner_approval.new_link(repo, plan, NOW)
    owner_approval.start(repo, plan, "alice", token=token, expires=expires, channel="mail", recipient="bob@example.com",
                         now=NOW, note="mail · to=bob@example.com")
    before = plan.model_copy(deep=True)  # the plan as the owner's decision read it, before the approval landed
    approved = svc.approve(plan, "bob", plan.plan_hash)  # no decision yet when bob approved
    owner_approval.decide(repo, token, "approve", None, NOW, lambda _id: before, {"subject": "bob", "email": "bob@example.com"})
    with pytest.raises(ActionPlanError) as refused:
        svc.execute(approved, "carol", approved.plan_hash, adapter=FakeAdapter("Active"))
    assert refused.value.code == "INDEPENDENT_APPROVAL_REQUIRED"
