from datetime import UTC, datetime, timedelta

from cremore.coverage.aws_scheduling import enqueue_aws_inventory, poll_aws_inventory_schedules
from cremore.coverage.aws_scheduling_test import ACCOUNT, SETTINGS, Sessions, setup
from cremore.coverage.aws_scheduling_test import repo as repo  # noqa: PLC0414 -- memory/SQL fixture
from cremore.coverage.models import ConnectionSpec
from cremore.coverage.store import CoverageStore
from cremore.db.postgres_scan_test import pg as pg  # noqa: PLC0414 -- isolated PostgreSQL fixture
from cremore.domain.models import ScanJob
from cremore.operations.collection_schedule import for_job
from cremore.scanning import triggers
from cremore.scanning.triggers import poll_schedules
from cremore.scanning.triggers_test import SPREAD, upgraded
from cremore.scanning.triggers_test import (
    no_spread as no_spread,  # noqa: PLC0414 -- full scans due at slot start
)
from cremore.scanning.triggers_test import setup as scope_setup


def test_content_clock_uses_consumed_utc_slots_and_current_approval(repo):
    repo, source, profile, _item, settings = scope_setup(repo=repo)
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    job = ScanJob(kind="scope", payload={"profile_id": str(profile.id)})
    assert for_job(repo, settings, job, now=now)["next_due_at"] == now.isoformat()
    assert poll_schedules(repo, settings, now=now)["enqueued"] == 1
    expected = datetime.fromtimestamp((int(now.timestamp()) // 300 + 1) * 300, UTC)
    assert for_job(repo, settings, job, now=now)["next_due_at"] == expected.isoformat()
    repo.update_connection(source.id, status="DISABLED")
    assert for_job(repo, settings, job, now=now)["enabled"] is False


def test_a_scope_on_the_installation_default_is_due_at_the_anchored_full_scan(repo):
    # No cadence of its own: the daily default full scan from 17:00 UTC (02:00 KST) schedules it.
    repo, _source, profile, _item, settings = scope_setup(repo=repo)
    repo.update_scope_profile(profile.id, schedule_minutes=0, full_scan_minutes=None)
    job = ScanJob(kind="scope", payload={"profile_id": str(profile.id)})
    now = datetime(2026, 10, 10, 3, 0, tzinfo=UTC)
    view = for_job(repo, settings, job, now=now)
    assert view["enabled"] is True and view["minutes"] == 1440 and view["next_due_at"] == now.isoformat()
    assert poll_schedules(repo, settings, now=now)["enqueued"] == 1
    assert for_job(repo, settings, job, now=now)["next_due_at"] == datetime(2026, 10, 10, 17, 0, tzinfo=UTC).isoformat()


def test_the_view_shows_a_full_scan_due_at_the_scopes_spread_time(repo, monkeypatch):
    """The schedule view reads the worker's helper: the next full scan is due at the slot's start plus the scope's
    stable offset, not at the start minute."""
    monkeypatch.setattr(triggers, "full_scan_offset", SPREAD)
    repo, _source, profile, _item, settings = scope_setup(repo=repo)
    profile = repo.update_scope_profile(profile.id, schedule_minutes=0, full_scan_minutes=None)
    job = ScanJob(kind="scope", payload={"profile_id": str(profile.id)})
    now = datetime(2026, 10, 10, 21, 0, tzinfo=UTC)  # after any scope's due time in the 17:00 slot
    assert poll_schedules(repo, settings, now=now)["enqueued"] == 1
    due = datetime(2026, 10, 11, 17, 0, tzinfo=UTC) + timedelta(seconds=SPREAD(profile, 86400))
    assert for_job(repo, settings, job, now=now)["next_due_at"] == due.isoformat()


def test_after_an_upgrade_a_scope_approved_before_it_is_next_due_at_the_next_full_scan_slot(repo):
    """The full-scan slot open at the upgrade is not run for a scope approved before it, so the view shows the next
    slot (17:00 UTC), not now. Without an origin record nothing is skipped: due now."""
    from cremore.scanning import trigger_settings

    repo, _source, profile, _item, settings = scope_setup(repo=repo)
    now = datetime(2026, 10, 10, 10, 0, tzinfo=UTC)
    repo.update_scope_profile(profile.id, schedule_minutes=0, full_scan_minutes=None, approved_at=now - timedelta(days=1))
    upgraded(repo, now)
    job = ScanJob(kind="scope", payload={"profile_id": str(profile.id)})
    slot = datetime(2026, 10, 10, 17, 0, tzinfo=UTC).isoformat()
    assert for_job(repo, settings, job, now=now)["next_due_at"] == slot
    assert poll_schedules(repo, settings, now=now)["enqueued"] == 0
    assert for_job(repo, settings, job, now=now + timedelta(hours=1))["next_due_at"] == slot
    repo.delete_settings_before(trigger_settings.ORIGIN_KEY, now + timedelta(days=3650))
    assert for_job(repo, settings, job, now=now)["next_due_at"] == now.isoformat()


def test_after_an_upgrade_before_the_scopes_due_time_the_view_shows_that_days_full_scan(repo, monkeypatch):
    """Start 17:00 UTC, this scope's offset 3 hours (due 20:00), upgraded at 18:30: the slot was not due at the upgrade,
    so the view shows 20:00 the same day and, at 20:00, due now; once it is queued, the next day's."""
    monkeypatch.setattr(triggers, "full_scan_offset", lambda profile, interval: 3 * 3600)
    repo, _source, profile, _item, settings = scope_setup(repo=repo)
    day = datetime(2026, 10, 10, tzinfo=UTC)
    repo.update_scope_profile(profile.id, schedule_minutes=0, full_scan_minutes=None, approved_at=day)
    upgraded(repo, day + timedelta(hours=18, minutes=30))
    job = ScanJob(kind="scope", payload={"profile_id": str(profile.id)})
    due = day + timedelta(hours=20)
    assert for_job(repo, settings, job, now=day + timedelta(hours=18, minutes=30))["next_due_at"] == due.isoformat()
    assert for_job(repo, settings, job, now=due)["next_due_at"] == due.isoformat()
    assert poll_schedules(repo, settings, now=due)["enqueued"] == 1
    assert for_job(repo, settings, job, now=due)["next_due_at"] == (due + timedelta(days=1)).isoformat()


def test_aws_clock_matches_scheduler_even_after_another_run_and_turning_off(repo):
    setup(repo)
    store = CoverageStore(repo)
    row, _ = store.create(ConnectionSpec(name="Clock", provider="aws_iam", account_id=ACCOUNT,
        schedule_source="connection", schedule_minutes=5), "admin")
    now = datetime.now(UTC)
    queued = enqueue_aws_inventory(repo, SETTINGS, Sessions(repo), row["id"], now=now)
    job = repo.get_job(queued["job_id"])
    expected = max(now, job.created_at) + timedelta(minutes=5)
    assert for_job(repo, SETTINGS, job, now=now)["next_due_at"] == expected.isoformat()
    repo.complete_job(job.id, objects=0, findings=0)
    assert poll_aws_inventory_schedules(repo, SETTINGS, Sessions(repo), now=expected)["enqueued"] == 1
    assert for_job(repo, SETTINGS, job, now=expected)["next_due_at"] == (expected + timedelta(minutes=5)).isoformat()
    store.change(row["id"], row["revision"], "admin", enabled=False)
    assert for_job(repo, SETTINGS, job)["enabled"] is False
