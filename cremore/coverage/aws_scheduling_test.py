import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event
from types import SimpleNamespace

import pytest
from cremore_aws_provider import aws_access, aws_inventory_settings

from cremore.coverage import JOB_KIND
from cremore.coverage.aws_scheduling import (
    enqueue_aws_inventory,
    ensure_aws_inventory_connections,
    ensure_iam_connection,
    poll_aws_inventory_schedules,
    scheduled_refusal,
)
from cremore.coverage.models import ConnectionSpec
from cremore.coverage.store import CoverageStore
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- fixture re-export
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.db.task_store import TaskStore
from cremore.domain.models import AwsAccount, ScanJob

SETTINGS = SimpleNamespace(scan_schedules_allowed=True)
ACCOUNT = "111111111111"


@pytest.fixture(params=["memory", "sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    if request.param == "postgres":
        return request.getfixturevalue("pg")[1]
    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def setup(repo, account_id=ACCOUNT, **fields):
    values = {"account_id": account_id, "name": "Synthetic account", "access": "RUNTIME_IDENTITY",
              "validation_status": "VALID", "validation_key": "1:1", **fields}
    account = repo.create_aws_account(AwsAccount(**values))
    repo.put_setting(aws_access.APPROVAL_KEYS[aws_access.SCANNER], {"revision": 1}, "admin")
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": True}, "admin")
    return account


class Sessions:
    def __init__(self, repo):
        self.repo = repo

    def refusal(self, account_id, purpose):
        account = next(a for a in self.repo.list_aws_accounts() if a.account_id == account_id)
        approved = aws_access.approval(self.repo, purpose)
        return aws_access.use_refusal(account, purpose, approved), account, approved


def test_single_independent_and_organization_accounts_share_idempotent_schedule(repo):
    setup(repo)
    setup(repo, "222222222222", access="ROLE", scanner_role_arn="arn:aws:iam::222222222222:role/Scanner",
          external_id="synthetic-external")
    setup(repo, "333333333333", source="ORGANIZATION", org_state="ACTIVE", org_present=True)
    now = datetime.now(UTC)
    assert poll_aws_inventory_schedules(repo, SETTINGS, Sessions(repo), now=now)["enqueued"] == 3
    assert poll_aws_inventory_schedules(repo, SETTINGS, Sessions(repo), now=now)["skipped"] == 3
    rows = CoverageStore(repo).list_connections()
    assert {row["spec"]["account_id"] for row in rows} == {ACCOUNT, "222222222222", "333333333333"}
    assert all(row["spec"]["credential_report"] and row["spec"]["last_used"] for row in rows)
    assert len(repo.list_jobs()) == 3


def test_only_scheduled_server_vault_connections_join_the_account_schedule(repo):
    setup(repo)
    store = CoverageStore(repo)
    vault = {"provider": "aws_secrets_manager", "account_id": ACCOUNT, "regions": ["us-east-1"]}
    scheduled, _ = store.create(ConnectionSpec(name="Server", server_collection=True, schedule_minutes=60, **vault), "admin")
    store.create(ConnectionSpec(name="Manual", server_collection=True, **vault), "admin")
    store.create(ConnectionSpec(name="Customer CLI", **vault), "admin")
    assert poll_aws_inventory_schedules(repo, SETTINGS, Sessions(repo))["enqueued"] == 2  # IAM and the scheduled vault
    queued = {job.payload["coverage_connection_id"] for job in repo.list_jobs()}
    assert str(scheduled["id"]) in queued and len(queued) == 2


def test_connection_schedules_are_explicit_and_do_not_enable_legacy_collections(repo):
    setup(repo)
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": False}, "admin")
    store = CoverageStore(repo)
    common = {"account_id": ACCOUNT, "schedule_minutes": 5}
    legacy, _ = store.create(ConnectionSpec(name="Legacy", provider="aws_secrets_manager", server_collection=True,
        regions=["us-east-1"], **common), "admin")
    iam, _ = store.create(ConnectionSpec(name="Opt in", provider="aws_iam", schedule_source="connection", **common), "admin")
    vault, _ = store.create(ConnectionSpec(name="Vault opt in", provider="aws_secrets_manager", server_collection=True,
        regions=["us-east-1"], schedule_source="connection", **common), "admin")
    manual, _ = store.create(ConnectionSpec(name="Manual", provider="aws_cloudtrail", account_id=ACCOUNT,
        regions=["us-east-1"], schedule_source="connection"), "admin")
    sessions = Sessions(repo)
    now = datetime.now(UTC)
    assert poll_aws_inventory_schedules(repo, SETTINGS, sessions, now=now)["enqueued"] == 2
    assert {j.payload["coverage_connection_id"] for j in repo.list_jobs()} == {str(iam["id"]), str(vault["id"])}
    assert str(legacy["id"]) not in {j.payload["coverage_connection_id"] for j in repo.list_jobs()}
    for job in repo.list_jobs():
        repo.complete_job(job.id, objects=0, findings=0)
    assert poll_aws_inventory_schedules(repo, SETTINGS, Sessions(repo), now=now + timedelta(minutes=4))["enqueued"] == 0
    due = max(job.created_at for job in repo.list_jobs()) + timedelta(minutes=5)
    assert poll_aws_inventory_schedules(repo, SETTINGS, Sessions(repo), now=due)["enqueued"] == 2
    assert scheduled_refusal(repo, SETTINGS, ConnectionSpec.model_validate(manual["spec"]))
    assert poll_aws_inventory_schedules(repo, SimpleNamespace(scan_schedules_allowed=False), sessions)["enqueued"] == 0
    assert scheduled_refusal(repo, SimpleNamespace(scan_schedules_allowed=False), ConnectionSpec.model_validate(iam["spec"]))


def test_a_value_reader_schedule_also_needs_the_installation_to_collect_the_account(repo):
    """Owner decision 2026-10-08: periodic value reads need the legacy AWS automatic collection to take the account,
    on top of the connection's schedule, the hard lock, the approval and the feature; on-demand runs are unchanged."""
    setup(repo)
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": False}, "admin")
    store = CoverageStore(repo)
    common = {"account_id": ACCOUNT, "regions": ["us-east-1"], "server_collection": True, "schedule_minutes": 5,
              "schedule_source": "connection"}
    reader, _ = store.create(ConnectionSpec(name="Value reader", provider="aws_secrets_manager",
        references=[f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:app/db-Ab12Cd"],
        value_reader_role="CredentialVaultValueReaderRole", **common), "admin")
    scanner, _ = store.create(ConnectionSpec(name="Scanner reads", provider="aws_ssm", prefixes=["prod"], **common), "admin")
    spec = ConnectionSpec.model_validate(reader["spec"])
    assert scheduled_refusal(repo, SETTINGS, spec) == "VALUE_READER_AUTOMATION_DISABLED"
    assert scheduled_refusal(repo, SETTINGS, ConnectionSpec.model_validate(scanner["spec"])) is None  # unchanged contract
    now = datetime.now(UTC)
    assert poll_aws_inventory_schedules(repo, SETTINGS, Sessions(repo), now=now)["enqueued"] == 1
    assert {job.payload["coverage_connection_id"] for job in repo.list_jobs()} == {str(scanner["id"])}
    # Another account taken in, or the hard lock, still refuses; this account taken in lets it run.
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": True, "account_ids": ["222222222222"]}, "admin")
    assert scheduled_refusal(repo, SETTINGS, spec) == "VALUE_READER_AUTOMATION_DISABLED"
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": True, "account_ids": [ACCOUNT]}, "admin")
    assert scheduled_refusal(repo, SimpleNamespace(scan_schedules_allowed=False), spec) == "AWS_INVENTORY_AUTOMATION_DISABLED"
    assert scheduled_refusal(repo, SETTINGS, spec) is None
    poll_aws_inventory_schedules(repo, SETTINGS, Sessions(repo), now=now)
    assert str(reader["id"]) in {job.payload["coverage_connection_id"] for job in repo.list_jobs()}
    # An on-demand run does not ask the setting; a scheduled one is refused where it is queued.
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": False}, "admin")
    for job in repo.list_jobs():
        repo.complete_job(job.id, objects=0, findings=0)
    assert enqueue_aws_inventory(repo, SETTINGS, Sessions(repo), reader["id"])["enqueued"] is True
    for job in repo.list_jobs():
        repo.complete_job(job.id, objects=0, findings=0)
    with pytest.raises(aws_access.AccessBlocked, match="VALUE_READER_AUTOMATION_DISABLED"):
        enqueue_aws_inventory(repo, SETTINGS, Sessions(repo), reader["id"], scheduled=True, now=now + timedelta(days=1))


def test_schedule_respects_selection_hard_lock_validation_and_explicit_disable(repo):
    account = setup(repo)
    blocked = setup(repo, "222222222222", validation_status="INVALID")
    sessions = Sessions(repo)
    assert poll_aws_inventory_schedules(repo, SETTINGS, sessions)["blocked"] == 1
    assert not any(row["spec"]["account_id"] == blocked.account_id for row in CoverageStore(repo).list_connections())
    row = ensure_iam_connection(repo, account, "admin")
    CoverageStore(repo).change(row["id"], row["revision"], "admin", enabled=False)
    assert poll_aws_inventory_schedules(repo, SETTINGS, sessions)["enqueued"] == 0
    assert CoverageStore(repo).get(row["id"])["enabled"] is False
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": True, "account_ids": [blocked.account_id]}, "admin")
    assert scheduled_refusal(repo, SETTINGS, ConnectionSpec.model_validate(row["spec"]))
    assert poll_aws_inventory_schedules(repo, SimpleNamespace(scan_schedules_allowed=False), sessions)["enqueued"] == 0


def test_failed_account_probe_does_not_prevent_next_approved_account(repo):
    setup(repo)
    setup(repo, "222222222222")
    sessions = Sessions(repo)
    original = sessions.refusal

    def refusal(account_id, purpose):
        if account_id == ACCOUNT:
            raise RuntimeError("synthetic provider failure")
        return original(account_id, purpose)

    sessions.refusal = refusal
    result = poll_aws_inventory_schedules(repo, SETTINGS, sessions)
    assert result == {"enqueued": 1, "skipped": 0, "blocked": 1}
    assert repo.list_jobs()[0].payload["account_id"] == "222222222222"


def test_excluded_departed_and_disabled_accounts_keep_existing_inventory(repo):
    account = setup(repo, source="ORGANIZATION", org_state="ACTIVE", org_present=True)
    row = ensure_iam_connection(repo, account, "admin")
    for change in ({"in_deployment_scope": False}, {"in_deployment_scope": True, "org_present": False},
                   {"org_present": True, "enabled": False}):
        repo.update_aws_account(account.id, **change)
        assert poll_aws_inventory_schedules(repo, SETTINGS, Sessions(repo))["blocked"] == 1
        assert CoverageStore(repo).get(row["id"]) is not None
    assert repo.list_jobs() == []


def test_manual_and_scheduled_enqueue_reuse_jobs_beyond_first_500_and_cancelling(repo):
    account = setup(repo)
    row = ensure_iam_connection(repo, account, "admin")
    first = enqueue_aws_inventory(repo, SETTINGS, Sessions(repo), row["id"])
    for _ in range(501):
        repo.enqueue_job(ScanJob(kind="irrelevant"))
    repeated = enqueue_aws_inventory(repo, SETTINGS, Sessions(repo), row["id"], scheduled=True)
    assert repeated["job_id"] == first["job_id"] and not repeated["enqueued"]
    assert sum(job.kind == JOB_KIND for job in repo.list_jobs(1000)) == 1


def test_interval_receipt_survives_worker_restart_and_completed_job(repo):
    account = setup(repo)
    row = ensure_iam_connection(repo, account, "admin")
    now = datetime.now(UTC)
    first = enqueue_aws_inventory(repo, SETTINGS, Sessions(repo), row["id"], scheduled=True, now=now)
    repo.complete_job(first["job_id"], objects=0, findings=0)
    assert not enqueue_aws_inventory(repo, SETTINGS, Sessions(repo), row["id"], scheduled=True,
                                     now=now + timedelta(hours=1))["enqueued"]
    assert enqueue_aws_inventory(repo, SETTINGS, Sessions(repo), row["id"], scheduled=True,
                                 now=now + timedelta(days=1, seconds=1))["enqueued"]


def test_cloudtrail_is_opt_in_explicit_and_keeps_per_account_connections(repo):
    account = setup(repo)
    assert len(ensure_aws_inventory_connections(repo, SETTINGS, account, "admin")) == 1
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": True, "cloudtrail_enabled": True,
                     "regions": ["us-east-1"], "window_days": 30}, "admin")
    rows = ensure_aws_inventory_connections(repo, SETTINGS, account, "admin")
    assert len(rows) == 2
    assert rows[1]["spec"]["regions"] == ["us-east-1"]
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": True, "cloudtrail_enabled": True,
                     "regions": ["eu-west-1"], "window_days": 40}, "admin")
    updated = ensure_aws_inventory_connections(repo, SETTINGS, account, "admin")[1]
    assert updated["id"] == rows[1]["id"] and updated["revision"] == rows[1]["revision"] + 1
    assert updated["spec"]["regions"] == ["eu-west-1"]
    assert scheduled_refusal(repo, SETTINGS, ConnectionSpec.model_validate(rows[1]["spec"]))


def test_paused_owner_cannot_gain_new_inventory_from_global_cloudtrail_settings(repo):
    from cremore.onboarding.store import ProviderConnectionStore

    account = setup(repo)
    owners = ProviderConnectionStore(repo)
    owner = owners.create({"provider": "aws", "edition": "cloud", "name": "Paused inventory", "target": {},
        "auth_method": "runtime", "secret_refs": {}, "purposes": ["inventory"], "plans": {"inventory": {}},
        "status": "ACTIVE", "disabled_purposes": ["inventory"]}, "admin")
    owners.link(owner["id"], "inventory", "aws_account", account.id)
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": True, "cloudtrail_enabled": True,
        "regions": ["us-east-1"], "window_days": 30}, "admin")
    assert poll_aws_inventory_schedules(repo, SETTINGS, Sessions(repo))["enqueued"] == 0
    assert CoverageStore(repo).list_connections() == []
    # Even a separately enabled inventory row does not override the owner's pause.
    row = ensure_iam_connection(repo, account, "fixture")
    with pytest.raises(aws_access.AccessBlocked, match="PROVIDER_FEATURE_PAUSED"):
        enqueue_aws_inventory(repo, SETTINGS, Sessions(repo), row["id"])


def test_queued_cloudtrail_job_cannot_keep_a_history_window_after_admin_narrows_it(repo):
    setup(repo)
    original = ConnectionSpec(name="History", provider="aws_cloudtrail", account_id=ACCOUNT,
                              regions=["us-east-1"], window_days=30)
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": True, "cloudtrail_enabled": True,
                     "regions": ["us-east-1"], "window_days": 7}, "admin")
    assert scheduled_refusal(repo, SETTINGS, original) == "AWS_INVENTORY_CLOUDTRAIL_SCOPE_CHANGED"
    narrowed = original.model_copy(update={"window_days": 7})
    assert scheduled_refusal(repo, SETTINGS, narrowed) is None


def test_settings_reject_bad_scope_instead_of_silently_enabling_all_accounts():
    for body in ({"enabled": 1}, {"account_ids": ["not-an-account"]}, {"cloudtrail_enabled": True},
                 {"window_days": 91}, {"interval_minutes": 1}, {"unknown": True}):
        with pytest.raises(ValueError):
            aws_inventory_settings.normalize(body)
    repo = InMemoryRepository()
    repo.put_setting(aws_inventory_settings.KEY, {"enabled": True, "account_ids": ["bad"]}, "admin")
    assert not aws_inventory_settings.effective(SETTINGS, repo)
    settings = aws_inventory_settings.normalize({"cloudtrail_enabled": True, "cloudtrail_source": "s3",
        "regions": ["us-east-1"], "trail_bucket": "synthetic-trail", "trail_prefixes": ["AWSLogs/111111111111/"],
        "window_days": 365})
    assert settings["window_days"] == 365


def test_postgres_concurrent_inventory_onboarding_enqueues_one_job(pg):
    _, repo = pg
    account = setup(repo)
    barrier = Barrier(6)

    def submit(_):
        barrier.wait(timeout=15)
        row = ensure_iam_connection(repo, account, "admin")
        return enqueue_aws_inventory(repo, SETTINGS, Sessions(repo), row["id"], scheduled=True)

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(submit, range(6)))
    assert len({r["job_id"] for r in results}) == 1
    assert sum(r["enqueued"] for r in results) == 1
    assert len(CoverageStore(repo).list_connections()) == len(repo.list_jobs()) == 1


def test_postgres_policy_lock_serializes_admin_change_with_inventory_commit(pg):
    from cremore.coverage.job import require_current_access

    _, repo = pg
    account = setup(repo)
    row = ensure_iam_connection(repo, account, "admin")
    spec = ConnectionSpec.model_validate(row["spec"])
    started, committed = Event(), Event()

    def disable():
        started.set()
        repo.put_setting(aws_inventory_settings.KEY, {"enabled": False}, "admin")
        committed.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        with CoverageStore(repo).transaction() as conn:
            bound = TaskStore(repo)._bound(conn)
            require_current_access(bound, ACCOUNT, "1:1", SETTINGS, scheduled_spec=spec)
            future = pool.submit(disable)
            assert started.wait(5)
            assert not committed.wait(0.1)
            assert scheduled_refusal(bound, SETTINGS, spec) is None
        future.result(timeout=10)
    assert committed.is_set()
    with (CoverageStore(repo).transaction() as conn,
          pytest.raises(aws_access.AccessBlocked, match="AWS_INVENTORY_AUTOMATION_DISABLED")):
        require_current_access(TaskStore(repo)._bound(conn), ACCOUNT, "1:1", SETTINGS, scheduled_spec=spec)
