"""Trigger receipts and a consumed approval cannot allocate a second scan budget."""
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import event, func, select

from cremore.db.repository import InMemoryRepository
from cremore.db.schema import scope_plans, trigger_receipts
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import ScanJob, ScopePlan, ScopeProfile


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def approval():
    plan = ScopePlan(id=uuid.uuid4(), kind="source", connection_id=uuid.uuid4(), profile_id=uuid.uuid4(),
        profile_version=4, executable=True, expires_at=datetime.now(UTC) + timedelta(minutes=5))
    job = ScanJob(kind="scope", connection_id=plan.connection_id, payload={"plan_id": str(plan.id)})
    return plan, job


def test_trigger_receipt_replay_returns_original_without_orphan_plan(repo):
    plan, job = approval()
    first, created = repo.enqueue_triggered_scope(plan, job, "a" * 64)
    assert created and repo.get_plan(plan.id).job_id == first.id
    unused_plan = plan.model_copy(update={"id": uuid.uuid4()})
    again, created = repo.enqueue_triggered_scope(unused_plan, job, "a" * 64)
    assert not created and again.id == first.id and len(repo.list_jobs()) == 1
    assert repo.get_plan(unused_plan.id) is None


def test_scope_approval_is_consumed_once_and_validates_version(repo):
    plan, job = approval()
    plan = repo.create_plan(plan)
    first, created = repo.consume_scope_plan(plan.id, 4, job)
    assert created and repo.get_plan(plan.id).job_id == first.id
    again, created = repo.consume_scope_plan(plan.id, 4, job)
    assert again.id == first.id and not created and len(repo.list_jobs()) == 1
    with pytest.raises(ValueError, match="STALE"):
        repo.consume_scope_plan(plan.id, 5, job)
    with pytest.raises(ValueError, match="MISMATCH"):
        repo.consume_scope_plan(plan.id, 4, job.model_copy(update={"connection_id": uuid.uuid4()}))


def test_trigger_failure_does_not_leave_receipt_plan_or_job(repo, monkeypatch):
    plan, job = approval()
    if isinstance(repo, SqlRepository):
        def reject_insert(conn, cursor, statement, parameters, context, executemany):
            if statement.startswith("INSERT INTO scan_jobs"):
                raise RuntimeError("synthetic admission failure")
        event.listen(repo.engine, "before_cursor_execute", reject_insert)
    else:
        def fail(*args, **kwargs):
            raise RuntimeError("synthetic admission failure")
        monkeypatch.setattr(repo, "enqueue_job", fail)
    with pytest.raises(RuntimeError, match="admission failure"):
        repo.enqueue_triggered_scope(plan, job, "b" * 64)
    assert not repo.list_jobs() and repo.get_plan(plan.id) is None
    if isinstance(repo, SqlRepository):
        event.remove(repo.engine, "before_cursor_execute", reject_insert)
        with repo.engine.connect() as conn:
            assert conn.execute(select(func.count()).select_from(trigger_receipts)).scalar_one() == 0
            assert conn.execute(select(func.count()).select_from(scope_plans)).scalar_one() == 0
    else:
        assert repo.trigger_receipts == {}


def test_scheduled_profiles_and_string_epoch_resource_lookup(repo):
    profile = repo.create_scope_profile(ScopeProfile(kind="source", connection_id=uuid.uuid4(), name="scheduled", schedule_minutes=5))
    repo.create_scope_profile(ScopeProfile(kind="source", connection_id=profile.connection_id, name="manual"))
    assert [p.id for p in repo.list_scheduled_profiles()] == [profile.id]
    from cremore.domain.models import Credential, Exposure
    credential = repo.upsert_credential(Credential(fingerprint="synthetic", credential_type="TOKEN"))
    exposure = repo.upsert_exposure(Exposure(credential_id=credential.id, source_type="notion",
        source_connection_id=profile.connection_id, resource_name="page", location="notion://page",
        metadata={"collector_epoch": "notion-page-only-v1", "page_id": "page"}))
    found = repo.exposures_for_resource(profile.connection_id, "notion", "page", "notion://page",
                                       page_id="page", epoch="notion-page-only-v1")
    assert [e.id for e in found] == [exposure.id]
    assert not repo.exposures_for_resource(profile.connection_id, "notion", "page", "notion://page", epoch="old")
    repo.set_exposure_severity(exposure.id, "HIGH", metadata={"risk_facts": {"confidence": "high"}})
    assert repo.exposures_for_credential(credential.id)[0].metadata["risk_facts"] == {"confidence": "high"}
