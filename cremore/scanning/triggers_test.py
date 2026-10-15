"""Approved-scope events, schedules and dedicated queue handling without network."""

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.domain.models import Connection, ScanJob, ScopeCatalog, ScopeProfile
from cremore.scanning import scope, trigger_settings, triggers
from cremore.scanning.triggers import (
    cleanup_trigger_receipts,
    enqueue_event,
    poll_policy_sweeps,
    poll_resumable,
    poll_schedules,
    poll_sqs,
)

QUEUE = "https://sqs.us-east-1.amazonaws.com/123456789012/cremore-only"
NOW = datetime.now(UTC)
LONG_AGO = datetime(2000, 1, 1, tzinfo=UTC)
DAY = datetime(2026, 10, 10, tzinfo=UTC)  # pinned: tests on it never compare against the wall clock
SPREAD = triggers.full_scan_offset  # the real spread, for the tests of it; every other test's slots are due at start


@pytest.fixture(autouse=True)
def no_spread(monkeypatch):
    """The tests below read full-scan times at the slot's start: pin every scope's spread (full_scan_offset) to 0.
    The spread's own tests set SPREAD back."""
    monkeypatch.setattr(triggers, "full_scan_offset", lambda profile, interval: 0)


def upgraded(repo, at):
    """As the migration records the upgrade's moment (cremore.db.migrations.schedule_origin), at ``at``."""
    repo.put_setting(trigger_settings.ORIGIN_KEY, {"at": at.isoformat()}, "migration")


def setup(provider="aws", repo=None, name="test", origin=LONG_AGO):
    repo = repo or InMemoryRepository()
    config = {"aws": {"bucket": "bucket"}, "github": {"owner": "owner", "repo": "repo"}, "notion": {},
              "gcp": {"bucket": "bucket"}}[provider]
    connection = repo.create_connection(Connection(provider=provider, name=name, config=config, status="ACTIVE"))
    resource_type = {"aws": "S3_BUCKET", "github": "GITHUB_REPOSITORY", "notion": "NOTION_PAGE",
                     "gcp": "GCS_BUCKET"}[provider]
    reference = {"aws": "bucket", "github": "owner/repo", "notion": "a" * 32, "gcp": "bucket"}[provider]
    item = scope.resource("source", connection.id, resource_type, reference, "test", reference, provider)
    auth = scope.auth_revision("source", connection)
    repo.save_catalog(ScopeCatalog(kind="source", connection_id=connection.id, snapshot_id="snapshot", auth_revision=auth,
                                   items=[item], completeness="COMPLETE"))
    fields = scope.validate_profile_input({"name": "approved", "change_reason": "test", "catalog_snapshot_id": "snapshot",
        "selected_roots": [{"resource_id": item["id"], "all_current_objects": False, "prefixes": ["approved/"],
                            "excluded_prefixes": ["approved/private/"], "paths": ["approved"],
                            "excluded_paths": ["approved/private"], "page_mode": "PAGE_ONLY"}],
        "budgets": {"bytes": 1000, "requests": 1000, "seconds": 1000}, "event_mode": "ENABLED", "schedule_minutes": 5})
    fields.pop("expected_version")
    profile = repo.create_scope_profile(ScopeProfile(kind="source", connection_id=connection.id, state="READY",
                        auth_revision=auth, approved_by="admin", approved_at=NOW, **fields))
    settings = Settings(SCAN_SQS_QUEUE_URL=QUEUE, SCAN_SQS_PROFILE_ID=str(profile.id),
                        SCAN_SQS_DEDICATED_ACKNOWLEDGED=True)
    # Saved as the dashboard saves them: schedules on (their default), the SQS queue switched on by an Admin.
    switch_triggers(repo, schedules_enabled=True, sqs_enabled=True)
    # Migrated long ago (a SQL store's create_all recorded its own moment just now): no slot these tests poll is the
    # one open at an upgrade. ``origin=None`` keeps the moment a test already set, for its second scope.
    if origin is not None:
        upgraded(repo, origin)
    return repo, connection, profile, item, settings


def switch_triggers(repo, **fields):
    """Write the switches PUT /api/v1/settings/scan-triggers would write."""
    unknown = set(fields) - set(trigger_settings.FIELDS)
    assert not unknown, unknown
    repo.put_setting(trigger_settings.KEY, trigger_settings.merged(repo, fields), "admin")


def event(item, **extra):
    return {"event_id": "event-1", "resource_id": item["id"], "keys": ["approved/file"], **extra}


@pytest.mark.parametrize("full,delta", [(60, 0), (360, 5), (1440, 15), (0, 5), (0, 0)])
def test_full_and_incremental_schedules_are_independent_and_durable(full, delta):
    repo, _conn, profile, _item, settings = setup()
    repo.update_scope_profile(profile.id, full_scan_minutes=full, schedule_minutes=delta)
    now = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    first = poll_schedules(repo, settings, now=now)
    assert first["enqueued"] == int(bool(full or delta))
    assert poll_schedules(repo, settings, now=now)["enqueued"] == 0
    if not full and not delta:
        assert not repo.jobs
        return
    job = repo.list_jobs()[0]
    assert job.payload["mode"] == ("RECONCILE" if full else "DELTA")
    assert "reconcile_if_older_than_seconds" not in job.payload
    # While the first run still waits, a later delta slot is answered by it instead of piling up behind it ...
    if delta:
        later = poll_schedules(repo, settings, now=now + timedelta(minutes=delta))
        assert (later["enqueued"], later["coalesced"], len(repo.jobs)) == (0, 1, 1)
    # ... and once it has started, the next slot is queued.
    job.status = "RUNNING"
    if delta:
        before = set(repo.jobs)
        assert poll_schedules(repo, settings, now=now + timedelta(minutes=2 * delta))["enqueued"] == 1
        assert repo.jobs[next(iter(set(repo.jobs) - before))].payload["mode"] == "DELTA"
    if full:
        before = set(repo.jobs)
        assert poll_schedules(repo, settings, now=now + timedelta(minutes=full))["enqueued"] == 1
        assert repo.jobs[next(iter(set(repo.jobs) - before))].payload["mode"] == "RECONCILE"


def test_full_only_schedule_obeys_installation_switch_and_survives_restart():
    from cremore.db.sql import SqlRepository, create_all, make_engine

    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    repo, _conn, profile, _item, settings = setup(repo=SqlRepository(engine))
    repo.update_scope_profile(profile.id, schedule_minutes=0, full_scan_minutes=720)
    assert repo.list_scheduled_profiles()[0].full_scan_minutes == 720
    switch_triggers(repo, schedules_enabled=False)
    assert poll_schedules(repo, settings)["enqueued"] == 0
    switch_triggers(repo, schedules_enabled=True)
    assert poll_schedules(repo, settings, now=NOW)["enqueued"] == 1
    assert poll_schedules(SqlRepository(engine), settings, now=NOW)["enqueued"] == 0
    repo.update_scope_profile(profile.id, full_scan_minutes=0)
    assert repo.list_scheduled_profiles() == [] and repo.list_scheduled_profiles(1440) == []
    # No cadence of its own: listed only while the installation has a full-scan default.
    repo.update_scope_profile(profile.id, full_scan_minutes=None)
    assert repo.list_scheduled_profiles() == [] and [p.id for p in repo.list_scheduled_profiles(1440)] == [profile.id]
    engine.dispose()


@pytest.mark.parametrize("store", ["memory", "sqlite"])
def test_a_scope_without_any_cadence_of_its_own_is_scanned_in_full_by_the_installation_default(store):
    """What nobody configured is still scanned: the default full scan, then nothing more until its next slot;
    the Admin can slow it down or turn it off for the installation, and a scope's own 0 turns it off for that scope."""
    from cremore.db.sql import SqlRepository, create_all, make_engine

    engine = None
    if store == "sqlite":
        engine = make_engine("sqlite:///:memory:")
        create_all(engine)
    repo, _conn, profile, _item, settings = setup(repo=SqlRepository(engine) if engine else None)
    repo.update_scope_profile(profile.id, schedule_minutes=0)
    # Noon UTC: the daily slot began at 17:00 UTC yesterday and the next begins five hours on, whatever the hour now.
    at = NOW.replace(hour=12, minute=0, second=0, microsecond=0)
    assert poll_schedules(repo, settings, now=at) == {"enqueued": 1, "skipped": 0, "coalesced": 0}
    [job] = repo.list_jobs()
    assert (job.payload["mode"], job.payload["requested_by"], job.payload["schedule_kind"]) == ("RECONCILE", "schedule", "full-scan")
    assert poll_schedules(repo, settings, now=at + timedelta(hours=1)) == {"enqueued": 0, "skipped": 1, "coalesced": 0}
    repo.update_scope_profile(profile.id, version=profile.version + 1)  # a new approval is a new scope: due now
    switch_triggers(repo, full_scan_default_minutes=0)
    assert poll_schedules(repo, settings, now=at)["enqueued"] == 0
    switch_triggers(repo, full_scan_default_minutes=1440)
    repo.update_scope_profile(profile.id, full_scan_minutes=0)
    assert poll_schedules(repo, settings, now=NOW)["enqueued"] == 0 and len(repo.list_jobs()) == 1
    if engine is not None:
        engine.dispose()


def test_full_scans_start_at_the_installation_minute_and_incremental_slots_stay_delta():
    """Daily full scans run at 02:00 KST (17:00 UTC), twice daily at 02:00 and 14:00 KST; an incremental slot is a
    DELTA at any hour, midnight UTC included, and no schedule asks for the old reconcile age."""
    repo, _conn, profile, _item, settings = setup()  # schedule_minutes=5, no full-scan cadence of its own
    day = NOW.replace(hour=0, minute=0, second=0, microsecond=0)

    def poll(at):
        before = set(repo.jobs)
        result = poll_schedules(repo, settings, now=at)
        for job in repo.jobs.values():
            assert "reconcile_if_older_than_seconds" not in job.payload
        new = [repo.jobs[i].payload["mode"] for i in set(repo.jobs) - before]
        for job in repo.jobs.values():
            job.status = "SUCCEEDED"
        return result, new

    # The slot that began yesterday at 17:00 UTC has had no full scan yet, so the first poll queues it; the
    # incremental slot of the same moment is answered by that queued full scan.
    assert poll(day + timedelta(hours=16, minutes=55)) == ({"enqueued": 1, "skipped": 0, "coalesced": 1}, ["RECONCILE"])
    assert poll(day + timedelta(hours=17))[1] == ["RECONCILE"]  # 02:00 KST: the next daily full scan
    assert poll(day + timedelta(hours=17, minutes=5))[1] == ["DELTA"]
    assert poll(day + timedelta(days=1))[1] == ["DELTA"]  # midnight UTC is an ordinary incremental slot
    switch_triggers(repo, full_scan_default_minutes=720)
    assert poll(day + timedelta(days=1, hours=5))[1] == ["RECONCILE"]  # 14:00 KST
    assert poll(day + timedelta(days=1, hours=11))[1] == ["DELTA"]
    # Another start minute moves the slots: 09:00 KST is midnight UTC.
    switch_triggers(repo, full_scan_default_minutes=1440, full_scan_start_minute=0)
    assert poll(day + timedelta(days=2))[1] == ["RECONCILE"]
    # Off for the installation, the scope's own cadence still counts from the start minute.
    switch_triggers(repo, full_scan_default_minutes=0)
    assert poll(day + timedelta(days=3))[1] == ["DELTA"]
    repo.update_scope_profile(profile.id, full_scan_minutes=1440)
    assert poll(day + timedelta(days=3, minutes=1))[1] == ["RECONCILE"]


def begun(repo, job, at):
    """Mark a run as claimed at ``at``, as the worker's claim would."""
    if isinstance(repo, InMemoryRepository):
        repo.jobs[job.id].status, repo.jobs[job.id].started_at = "RUNNING", at
        return
    from sqlalchemy import update

    from cremore.db.schema import scan_jobs

    with repo.engine.begin() as conn:
        conn.execute(update(scan_jobs).where(scan_jobs.c.id == job.id).values(status="RUNNING", started_at=at))


@pytest.mark.parametrize("store", ["memory", "sqlite"])
def test_only_a_whole_scope_run_of_this_approval_in_a_covering_mode_answers_a_slot(store):
    from cremore.db.sql import SqlRepository, create_all, make_engine
    from cremore.scanning.triggers import _COVERING

    engine = None
    if store == "sqlite":
        engine = make_engine("sqlite:///:memory:")
        create_all(engine)
    repo, _conn, profile, item, settings = setup(repo=SqlRepository(engine) if engine else None)
    began = NOW - timedelta(minutes=5)

    def answer(mode, receipt="c" * 64, of=profile, auth=profile.auth_revision, since=began):
        return repo.coalesce_scheduled_scope(receipt, of, auth, _COVERING[mode], since)

    assert answer("DELTA") is None
    # A change event's run is not a scheduled one.
    enqueue_event(repo, settings, profile.id, event(item))
    assert answer("DELTA") is None
    repo.update_scope_profile(profile.id, schedule_minutes=5, full_scan_minutes=0)
    assert poll_schedules(repo, settings, now=NOW)["enqueued"] == 1
    delta = next(job for job in repo.list_jobs() if job.payload.get("requested_by") == "schedule")
    # A queued DELTA answers a DELTA slot, never a full scan's, and only under the authorization it was planned with:
    # a renewal keeps the approval's version but not its authorization, and the run is refused when claimed.
    assert answer("RECONCILE") is None and answer("DELTA", auth="renewed") is None
    assert answer("DELTA").id == delta.id
    assert repo.slot_receipt_state("c" * 64, began) == (True, None) and len(repo.list_jobs()) == 2
    # Once begun, it answers a slot that began before it did, never one that began after.
    begun(repo, delta, began + timedelta(minutes=1))
    assert answer("DELTA", receipt="e" * 64).id == delta.id
    assert answer("DELTA", receipt="f" * 64, since=began + timedelta(minutes=2)) is None
    # A new version of the scope is another approval: the old version's run answers none of its slots.
    newer = repo.update_scope_profile(profile.id, version=profile.version + 1)
    assert answer("DELTA", receipt="d" * 64, of=newer) is None
    with pytest.raises(ValueError, match="INVALID_TRIGGER_RECEIPT"):
        answer("DELTA", receipt="not-a-receipt")
    if engine is not None:
        engine.dispose()


def admin_run(repo, settings, profile, at, trigger="BASELINE"):
    """A full read an Admin queued for this approval, as the API queues it."""
    profile, plan, _target, base, source = triggers.prepare_trigger_plan(repo, settings, profile.id, "SCHEDULE", now=at)
    plan.trigger = trigger  # what the API's plan for an Admin's scan carries
    payload = scope.run_payload(plan, profile, base, source)
    payload.update(mode="BASELINE", requested_by=str(uuid.uuid4()))
    return repo.enqueue_job(ScanJob(kind="scope", connection_id=profile.connection_id, payload=payload))


@pytest.mark.parametrize("trigger", ["BASELINE", "RESCAN"])
def test_the_first_scan_an_admin_queued_answers_the_full_scan_and_incremental_slots_beside_it(trigger):
    """Saving a scope queues its first full read; the schedule queues no second read of the same approval beside
    it. A rescan reads part of the scope and answers no slot."""
    repo, _conn, profile, _item, settings = setup()  # every 5 minutes, and the installation's daily full scan
    at = NOW.replace(hour=9, minute=0, second=0, microsecond=0)
    manual = admin_run(repo, settings, profile, at, trigger)
    if trigger == "BASELINE":
        assert poll_schedules(repo, settings, now=at) == {"enqueued": 0, "skipped": 0, "coalesced": 2}
        assert list(repo.jobs) == [manual.id]
    else:
        assert poll_schedules(repo, settings, now=at) == {"enqueued": 1, "skipped": 0, "coalesced": 1}


@pytest.fixture(params=["memory", "sqlite"])
def store(request):
    if request.param == "memory":
        yield InMemoryRepository()
        return
    from cremore.db.sql import SqlRepository, create_all, make_engine

    engine = make_engine("sqlite:///:memory:")
    create_all(engine)
    yield SqlRepository(engine)
    engine.dispose()


def full_scan_slot(repo, settings, profile, at):
    """The receipt of the full-scan slot open at ``at``."""
    cadence = trigger_settings.full_scan(settings, repo)
    [(kind, interval, slot, _mode)] = [s for s in triggers.schedule_slots(profile, at, *cadence) if s[0] == "full-scan"]
    return triggers.slot_receipt(profile, kind, interval, slot, cadence[1])


def created(repo, job, at):
    """Pin when a run was queued, as a run queued at ``at`` would have been."""
    if isinstance(repo, InMemoryRepository):
        repo.jobs[job.id].created_at = at
        return
    from sqlalchemy import update

    from cremore.db.schema import scan_jobs

    with repo.engine.begin() as conn:
        conn.execute(update(scan_jobs).where(scan_jobs.c.id == job.id).values(created_at=at))


@pytest.mark.parametrize("ending", ["cancelled", "failed"])
def test_a_slot_merged_into_a_run_that_was_cancelled_or_failed_is_queued_again_once(store, ending):
    """An analyst starts a full read at 17:00:30 UTC and the 17:00 slot is merged into it. Cancelled (or failed) at
    17:02, that run answers the slot no more: the next poll queues the slot's own full scan, once."""
    repo, _conn, profile, _item, settings = setup(repo=store)
    profile = repo.update_scope_profile(profile.id, schedule_minutes=0)
    start = NOW.replace(hour=17, minute=0, second=0, microsecond=0)
    manual = admin_run(repo, settings, profile, start + timedelta(seconds=30))
    assert poll_schedules(repo, settings, now=start + timedelta(seconds=30)) == {"enqueued": 0, "skipped": 0, "coalesced": 1}
    receipt = full_scan_slot(repo, settings, profile, start)
    assert repo.slot_receipt_state(receipt, start) == (True, None)
    if ending == "cancelled":
        repo.request_job_cancel(manual.id)
    else:
        repo.fail_job(manual.id, "synthetic failure")
    assert repo.slot_receipt_state(receipt, start) == (False, manual.id)
    assert poll_schedules(repo, settings, now=start + timedelta(minutes=2)) == {"enqueued": 1, "skipped": 0, "coalesced": 0}
    assert poll_schedules(repo, settings, now=start + timedelta(minutes=3)) == {"enqueued": 0, "skipped": 1, "coalesced": 0}
    [own] = [job for job in repo.list_jobs() if job.id != manual.id]
    assert (own.payload["mode"], own.payload["requested_by"], own.payload["slot_receipt"]) == ("RECONCILE", "schedule", receipt)
    assert repo.slot_receipt_state(receipt, start) == (True, None)


@pytest.mark.parametrize("pre_upgrade", [False, True])
def test_the_schedules_own_run_cancelled_still_consumes_its_slot(store, pre_upgrade):
    """An operator who cancels the run the schedule queued for a slot skips that slot, as before; so does one who
    cancels a scheduled run the previous version queued in that slot, whose payload names no slot_receipt."""
    repo, conn, profile, _item, settings = setup(repo=store)
    profile = repo.update_scope_profile(profile.id, schedule_minutes=0)
    start = NOW.replace(hour=17, minute=0, second=0, microsecond=0)
    if pre_upgrade:
        _profile, plan, _target, base, source = triggers.prepare_trigger_plan(repo, settings, profile.id, "SCHEDULE", now=start)
        payload = scope.run_payload(plan, profile, base, source)
        payload.update(mode="RECONCILE", requested_by="schedule", schedule_kind="full-scan")
        old, _created = repo.enqueue_triggered_scope(plan, ScanJob(kind="scope", connection_id=conn.id, payload=payload),
                                                     full_scan_slot(repo, settings, profile, start))
        created(repo, old, start + timedelta(seconds=5))
    else:
        assert poll_schedules(repo, settings, now=start)["enqueued"] == 1
    [own] = repo.list_jobs()
    assert ("slot_receipt" in own.payload) is not pre_upgrade
    repo.request_job_cancel(own.id)
    assert poll_schedules(repo, settings, now=start + timedelta(minutes=2)) == {"enqueued": 0, "skipped": 1, "coalesced": 0}
    assert [job.id for job in repo.list_jobs()] == [own.id]


def test_a_slot_merged_into_a_pre_upgrade_scheduled_run_of_an_earlier_slot_reopens_when_it_is_cancelled(store):
    """Yesterday's scheduled full scan, queued by the previous version (no slot_receipt), still waits at 17:00 today
    and absorbs today's slot. That run is yesterday's slot's own, not today's: cancelled, today's slot is queued."""
    repo, conn, profile, _item, settings = setup(repo=store)
    profile = repo.update_scope_profile(profile.id, schedule_minutes=0)
    start = NOW.replace(hour=17, minute=0, second=0, microsecond=0)
    yesterday = start - timedelta(days=1)
    _profile, plan, _target, base, source = triggers.prepare_trigger_plan(repo, settings, profile.id, "SCHEDULE",
                                                                           now=yesterday)
    payload = scope.run_payload(plan, profile, base, source)
    payload.update(mode="RECONCILE", requested_by="schedule", schedule_kind="full-scan")
    old, _created = repo.enqueue_triggered_scope(plan, ScanJob(kind="scope", connection_id=conn.id, payload=payload),
                                                 full_scan_slot(repo, settings, profile, yesterday))
    created(repo, old, yesterday + timedelta(seconds=5))
    assert poll_schedules(repo, settings, now=start + timedelta(seconds=30)) == {"enqueued": 0, "skipped": 0, "coalesced": 1}
    receipt = full_scan_slot(repo, settings, profile, start)
    repo.request_job_cancel(old.id)
    assert repo.slot_receipt_state(receipt, start) == (False, old.id)
    assert poll_schedules(repo, settings, now=start + timedelta(minutes=2)) == {"enqueued": 1, "skipped": 0, "coalesced": 0}
    assert repo.slot_receipt_state(full_scan_slot(repo, settings, profile, yesterday), yesterday) == (True, None)


def test_an_upgrade_runs_no_full_scan_until_the_next_slot_but_a_scope_approved_after_it_does(store):
    """Upgraded at 10:00 UTC: the daily slot that began at 17:00 UTC yesterday has no receipt under this version's
    numbering, and a scope approved before the upgrade does not run it; its 17:00 slot runs as ever. A scope approved
    after the upgrade, inside the same open slot, is scanned at once as before."""
    repo, _conn, profile, _item, settings = setup(repo=store)
    day = NOW.replace(hour=0, minute=0, second=0, microsecond=0)
    repo.update_scope_profile(profile.id, schedule_minutes=0, approved_at=day - timedelta(hours=12))
    upgrade = day + timedelta(hours=10)
    upgraded(repo, upgrade)
    assert poll_schedules(repo, settings, now=upgrade) == {"enqueued": 0, "skipped": 1, "coalesced": 0}
    _repo, _other_conn, other, _other_item, _settings = setup(repo=repo, name="other", origin=None)
    repo.update_scope_profile(other.id, schedule_minutes=0, approved_at=upgrade + timedelta(minutes=30))
    assert poll_schedules(repo, settings, now=upgrade + timedelta(minutes=31)) == {"enqueued": 1, "skipped": 1, "coalesced": 0}
    [first] = repo.list_jobs()
    assert first.payload["profile_id"] == str(other.id)
    assert poll_schedules(repo, settings, now=day + timedelta(hours=16, minutes=59))["enqueued"] == 0
    repo.complete_job(first.id, 0, 0)
    assert poll_schedules(repo, settings, now=day + timedelta(hours=17))["enqueued"] == 2
    assert {job.payload["profile_id"] for job in repo.list_jobs()} == {str(profile.id), str(other.id)}


def test_schedules_locked_at_the_upgrade_run_the_slot_open_when_they_are_unlocked(store):
    """The migration records the upgrade's moment whether schedules are on or locked off, so unlocking them a day
    later runs the slot open then at once, as unlocking always has."""
    repo, _conn, profile, _item, settings = setup(repo=store)
    day = NOW.replace(hour=0, minute=0, second=0, microsecond=0)
    repo.update_scope_profile(profile.id, schedule_minutes=0, approved_at=day - timedelta(hours=12))
    upgrade = day + timedelta(hours=10)
    upgraded(repo, upgrade)
    locked = settings.model_copy(update={"scan_schedules_mode": "disabled"})
    assert poll_schedules(repo, locked, now=upgrade)["enqueued"] == 0
    assert poll_schedules(repo, settings, now=upgrade + timedelta(days=1, hours=2))["enqueued"] == 1


def stale_root(repo, conn, profile):
    """The scope's root was read under the policy before the upgrade: a sweep would re-read it."""
    from cremore.db.scan_store import ScanStore

    plan = scope.build_plan(profile, repo.get_catalog(profile.kind, conn.id), auth=profile.auth_revision, enabled=True)
    [root] = scope.split_roots(plan.roots)
    ScanStore(repo).save_root(scope.root_identity(conn.id, root), conn.id,
                              {"watermark": "read", "detection_digest": "before-the-upgrade"})


def sweeps(repo, settings, at, digest="after-the-upgrade"):
    from types import SimpleNamespace

    return poll_policy_sweeps(repo, settings, SimpleNamespace(detection_policy_digest=digest), now=at)["enqueued"]


@pytest.mark.parametrize("cadence", ["daily", "daily_never_queued", "full_scans_off", "schedules_off"])
def test_after_an_upgrade_a_policy_sweep_waits_for_the_next_full_scan_only_while_one_is_scheduled(store, cadence):
    """A new extraction epoch makes every scanned root's detection digest stale at the upgrade. A scope with a daily
    full scan is not swept until its next slot's full scan has been queued and has ended, so the sweep then finds the
    roots current, and the held sweep consumes no receipt. The schedule polls before the sweep within a worker's tick,
    so a sweep pass a few seconds after 17:00 can come before that slot's poll: it still waits. A slot that is never
    queued holds the sweep one slot at most. A scope that no full scan will re-read (cadence 0, or schedules off) is
    swept at once."""
    from types import SimpleNamespace

    from cremore.db.scan_store import ScanStore

    repo, conn, profile, _item, settings = setup(repo=store)
    day = NOW.replace(hour=0, minute=0, second=0, microsecond=0)
    profile = repo.update_scope_profile(profile.id, schedule_minutes=0, approved_at=day - timedelta(hours=12),
                                        full_scan_minutes=0 if cadence == "full_scans_off" else 1440)
    if cadence == "schedules_off":
        switch_triggers(repo, schedules_enabled=False)
    upgraded(repo, day + timedelta(hours=10))
    plan = scope.build_plan(profile, repo.get_catalog(profile.kind, conn.id), auth=profile.auth_revision, enabled=True)
    [root] = scope.split_roots(plan.roots)
    ScanStore(repo).save_root(scope.root_identity(conn.id, root), conn.id,
                              {"watermark": "read", "detection_digest": "before-the-upgrade"})
    orchestrator = SimpleNamespace(detection_policy_digest="after-the-upgrade")

    def sweep(at):
        return poll_policy_sweeps(repo, settings, orchestrator, now=at)["enqueued"]

    swept = sweep(day + timedelta(hours=10))
    if cadence in ("full_scans_off", "schedules_off"):
        assert swept == 1
        return
    start = day + timedelta(hours=17)
    assert swept == 0 and sweep(start - timedelta(minutes=1)) == 0
    assert sweep(start + timedelta(seconds=3)) == 0  # the slot has begun; its schedule poll has not run yet
    assert not repo.list_jobs()
    if cadence == "daily_never_queued":
        assert sweep(start + timedelta(days=1) - timedelta(seconds=1)) == 0
        assert sweep(start + timedelta(days=1)) == 1
        return
    assert poll_schedules(repo, settings, now=start + timedelta(seconds=8))["enqueued"] == 1
    assert sweep(start + timedelta(seconds=9)) == 0  # queued, not ended: a sweep now would re-read beside it
    assert repo.claim_next_job().payload["mode"] == "RECONCILE"
    assert sweep(start + timedelta(minutes=1)) == 0
    [full] = repo.list_jobs()
    repo.complete_job(full.id, 1, 0)
    assert sweep(start + timedelta(minutes=2)) == 1
    assert sorted(job.payload["mode"] for job in repo.list_jobs()) == ["POLICY_SWEEP", "RECONCILE"]


def test_each_scope_gets_a_stable_full_scan_time_within_four_hours_or_half_its_cadence():
    """One slot's full scans are spread by the scope's id over min(4 hours, half the cadence): two scopes start at
    different times, each the same every day and on every replica; an hourly cadence spreads within 30 minutes."""
    from types import SimpleNamespace

    scopes = [SimpleNamespace(id=uuid.uuid5(uuid.NAMESPACE_URL, f"scope-{n}")) for n in range(50)]
    assert [SPREAD(s, 86400) // 60 for s in scopes[:2]] == [207, 6]  # minutes after the start minute
    daily = [SPREAD(s, 86400) for s in scopes]
    assert all(0 <= offset < 240 * 60 and offset % 60 == 0 for offset in daily) and max(daily) >= 200 * 60
    assert [SPREAD(s, 86400) for s in scopes] == daily and [SPREAD(s, 43200) for s in scopes] == daily  # 12 h: 4 h too
    hourly = [SPREAD(s, 3600) for s in scopes]
    assert all(0 <= offset < 30 * 60 for offset in hourly) and max(hourly) >= 20 * 60


def test_a_full_scan_is_queued_at_its_scopes_due_time_and_not_before(store, monkeypatch):
    """Before start + offset the slot is not due: nothing is queued, merged or skipped for it and it has no receipt.
    At that moment it is queued, under the receipt of the slot's start; the next day at the same time."""
    monkeypatch.setattr(triggers, "full_scan_offset", SPREAD)
    repo, _conn, profile, _item, settings = setup(repo=store)
    profile = repo.update_scope_profile(profile.id, schedule_minutes=0)
    offset = timedelta(seconds=SPREAD(profile, 86400))
    start = NOW.replace(hour=17, minute=0, second=0, microsecond=0)

    def receipt(begins):
        return triggers.slot_receipt(profile, "full-scan", 86400, (int(begins.timestamp()) - 1020 * 60) // 86400, 1020)

    # Yesterday's slot, due at the scope's own time, runs and finishes.
    assert poll_schedules(repo, settings, now=start - timedelta(days=1) + offset)["enqueued"] == 1
    for job in repo.list_jobs():
        repo.complete_job(job.id, 0, 0)
    for day in (0, 1):
        begins = start + timedelta(days=day)
        assert poll_schedules(repo, settings, now=begins + offset - timedelta(seconds=1)) == {
            "enqueued": 0, "skipped": 1, "coalesced": 0}  # the slot before it, answered
        assert repo.slot_receipt_state(receipt(begins), begins) == (False, None)
        assert poll_schedules(repo, settings, now=begins + offset) == {"enqueued": 1, "skipped": 0, "coalesced": 0}
        [job] = [job for job in repo.list_jobs() if job.status == "QUEUED"]
        assert (job.payload["mode"], job.payload["slot_receipt"]) == ("RECONCILE", receipt(begins))
        repo.complete_job(job.id, 0, 0)


def test_an_upgrade_skips_the_open_slot_queues_the_next_at_its_spread_time_and_holds_the_sweep_until_then(
        store, monkeypatch):
    """Upgraded at 10:00 UTC, with the scope's real spread: a scope approved before it skips the slot already due
    then (yesterday's); today's slot is queued at 17:00 plus the scope's spread, not before; its policy sweep waits
    until that full scan has ended and is then queued."""
    monkeypatch.setattr(triggers, "full_scan_offset", SPREAD)
    repo, conn, profile, _item, settings = setup(repo=store, origin=DAY + timedelta(hours=10))
    origin = trigger_settings.schedule_origin(repo, DAY + timedelta(hours=10))
    assert origin == DAY + timedelta(hours=10)
    profile = repo.update_scope_profile(profile.id, schedule_minutes=0, approved_at=origin - timedelta(days=1))
    stale_root(repo, conn, profile)
    due = DAY + timedelta(hours=17, seconds=SPREAD(profile, 86400))
    assert poll_schedules(repo, settings, now=origin) == {"enqueued": 0, "skipped": 1, "coalesced": 0}
    assert sweeps(repo, settings, origin) == 0
    assert poll_schedules(repo, settings, now=due - timedelta(seconds=1))["enqueued"] == 0
    assert sweeps(repo, settings, due - timedelta(seconds=1)) == 0 and not repo.list_jobs()
    assert poll_schedules(repo, settings, now=due)["enqueued"] == 1
    assert sweeps(repo, settings, due + timedelta(seconds=1)) == 0
    [full] = repo.list_jobs()
    repo.complete_job(full.id, 1, 0)
    assert sweeps(repo, settings, due + timedelta(seconds=2)) == 1
    assert sorted(job.payload["mode"] for job in repo.list_jobs()) == ["POLICY_SWEEP", "RECONCILE"]


def test_a_rule_change_after_the_upgrade_is_swept_at_once(store):
    """The first sweep pass records the digest in force after the upgrade and holds; once an Admin changes rules the
    digest differs, the sweep is queued at once, and the change is latched for readers without a digest (events)."""
    repo, conn, profile, item, settings = setup(repo=store)
    day = NOW.replace(hour=0, minute=0, second=0, microsecond=0)
    profile = repo.update_scope_profile(profile.id, schedule_minutes=0, approved_at=day - timedelta(hours=12))
    upgraded(repo, day + timedelta(hours=10))
    stale_root(repo, conn, profile)
    assert sweeps(repo, settings, day + timedelta(hours=11)) == 0
    record = repo.get_setting(trigger_settings.ORIGIN_KEY)["value"]
    assert record["detection_digest"] == "after-the-upgrade" and "rules_changed" not in record
    held, _created = enqueue_event(repo, settings, profile.id, event(item, event_id="before"), now=day + timedelta(hours=11))
    assert held.payload["policy_hold"] is True
    assert sweeps(repo, settings, day + timedelta(hours=11, minutes=1), "an-admin-changed-rules") == 1
    assert repo.get_setting(trigger_settings.ORIGIN_KEY)["value"]["rules_changed"] is True
    after, _created = enqueue_event(repo, settings, profile.id, event(item, event_id="after"), now=day + timedelta(hours=11))
    assert "policy_hold" not in after.payload


def test_a_scope_saved_after_a_fresh_install_is_not_skipped(tmp_path):
    """A new database records its origin when it is created, before any scope exists: a scope saved after it runs
    the open slot at once and holds nothing."""
    from cremore.db.sql import SqlRepository, create_all, make_engine

    engine = make_engine("sqlite+pysqlite:///" + (tmp_path / "fresh.sqlite3").as_posix())
    create_all(engine)
    origin = trigger_settings.schedule_origin(SqlRepository(engine), datetime.now(UTC))
    repo, conn, profile, _item, settings = setup(repo=SqlRepository(engine), origin=None)
    saved = origin + timedelta(minutes=1)
    profile = repo.update_scope_profile(profile.id, schedule_minutes=0, approved_at=saved)
    stale_root(repo, conn, profile)
    assert poll_schedules(repo, settings, now=saved + timedelta(minutes=1))["enqueued"] == 1
    assert sweeps(repo, settings, saved + timedelta(minutes=2)) == 1
    engine.dispose()


def test_a_deleted_origin_skips_and_holds_nothing_and_is_not_recorded_again(store):
    repo, conn, profile, item, settings = setup(repo=store)
    day = NOW.replace(hour=0, minute=0, second=0, microsecond=0)
    profile = repo.update_scope_profile(profile.id, approved_at=day - timedelta(hours=12))
    stale_root(repo, conn, profile)
    repo.delete_settings_before(trigger_settings.ORIGIN_KEY, NOW + timedelta(days=3650))
    if not isinstance(repo, InMemoryRepository):
        from cremore.db.sql import create_all

        create_all(repo.engine)  # a restart runs the migrations again: the row stays gone
    assert repo.get_setting(trigger_settings.ORIGIN_KEY) is None
    at = day + timedelta(hours=10)
    assert poll_schedules(repo, settings, now=at) == {
        "enqueued": 1, "skipped": 0, "coalesced": 1}
    assert all("policy_hold" not in job.payload for job in repo.list_jobs())
    assert sweeps(repo, settings, at) == 1
    job, _created = enqueue_event(repo, settings, profile.id, event(item), now=at)
    assert "policy_hold" not in job.payload and repo.get_setting(trigger_settings.ORIGIN_KEY) is None


def test_an_origin_an_hour_ahead_of_this_clock_is_still_honoured(store):
    """A replica whose clock runs behind the database's still reads the migration's moment and skips the open slot."""
    repo, _conn, profile, _item, settings = setup(repo=store)
    day = NOW.replace(hour=0, minute=0, second=0, microsecond=0)
    repo.update_scope_profile(profile.id, schedule_minutes=0, approved_at=day - timedelta(hours=12))
    upgraded(repo, day + timedelta(hours=11))
    assert poll_schedules(repo, settings, now=day + timedelta(hours=10)) == {"enqueued": 0, "skipped": 1, "coalesced": 0}


def test_a_restarted_workers_first_schedule_poll_still_holds_with_rules_it_has_not_loaded():
    """An installation with a built-in detector turned off records its real digest on the first sweep pass. A worker
    started later polls schedules before its first maintenance tick loads the rules, so its own digest is still the
    default rules'; the held scope's DELTA run is flagged all the same (the schedule reads the record, not the worker)."""
    from cremore.detection import switches
    from cremore.detection.catalog import builtin_definitions
    from cremore.scanning.orchestrator import Orchestrator
    from cremore.worker import JobWorker

    repo, _conn, profile, _item, settings = setup()  # every 5 minutes, and the daily full scan
    switches.set_enabled(repo, builtin_definitions()[0].catalog.id, False, "admin")
    now = datetime.now(UTC)  # poll_triggers reads the wall clock: the slots are placed around it
    minute = (now.hour * 60 + now.minute + 720) % 1440  # the open full-scan slot began about 12 hours ago
    switch_triggers(repo, full_scan_start_minute=minute)
    upgraded(repo, now - timedelta(minutes=1))
    repo.update_scope_profile(profile.id, approved_at=now - timedelta(days=2))
    loaded = Orchestrator(repo, rule_provider=repo.list_rules)
    loaded.refresh_rules()
    trigger_settings.record_upgrade_digest(repo, loaded.detection_policy_digest)
    worker = JobWorker(repo, settings=settings, orchestrator=Orchestrator(repo, rule_provider=repo.list_rules))
    assert worker.orchestrator.detection_policy_digest != loaded.detection_policy_digest  # not loaded yet
    worker._last_trigger_poll = 0
    worker.poll_triggers()
    [delta] = [job for job in repo.list_jobs() if job.payload.get("requested_by") == "schedule"]
    assert (delta.payload["mode"], delta.payload["policy_hold"]) == ("DELTA", True)


def test_an_event_reads_only_the_origin_once_no_hold_can_apply(monkeypatch):
    """A change event of a scope approved after the upgrade, or one past the longest hold (MAX_HOLD), costs one
    settings read for the hold: the origin. A scope still inside it reads the rest."""
    repo, _conn, profile, item, settings = setup()  # every 5 minutes, and the daily full scan
    origin = DAY + timedelta(hours=10)
    upgraded(repo, origin)
    reads = []
    read = repo.get_setting
    monkeypatch.setattr(repo, "get_setting", lambda key: reads.append(key) or read(key))
    hold_keys = {trigger_settings.ORIGIN_KEY, trigger_settings.KEY}

    def hold_reads(name, approved, at):
        repo.update_scope_profile(profile.id, approved_at=approved)
        reads.clear()
        enqueue_event(repo, settings, profile.id, event(item, event_id=name), now=at)
        return [key for key in reads if key in hold_keys]

    assert hold_reads("after", origin + timedelta(minutes=1), origin + timedelta(hours=1)) == [trigger_settings.ORIGIN_KEY]
    late = origin + triggers.MAX_HOLD
    assert hold_reads("late", origin - timedelta(days=1), late) == [trigger_settings.ORIGIN_KEY]
    assert len(hold_reads("held", origin - timedelta(days=1), origin + timedelta(hours=1))) > 1
    assert triggers.MAX_HOLD == timedelta(hours=48)  # 2 x the longest cadence (1440 min); the spread adds nothing
    # The longest real hold reaches it and no further: a daily cadence, the widest offset, an origin at the very moment
    # a slot was due (17:00 + 239 min). That slot was already due, so it is skipped; the next is due a day later and
    # holds one more cadence at most.
    monkeypatch.setattr(triggers, "full_scan_offset", lambda profile, interval: 239 * 60)
    worst = datetime(2026, 10, 10, 20, 59, tzinfo=UTC)
    let_go = worst + timedelta(days=2)
    held = repo.update_scope_profile(profile.id, approved_at=worst - timedelta(days=1))
    cadence = trigger_settings.full_scan(settings, repo)
    assert triggers.sweep_held(repo, held, let_go - timedelta(seconds=1), cadence, worst)
    assert not triggers.sweep_held(repo, held, let_go, cadence, worst) and let_go == worst + triggers.MAX_HOLD


@pytest.mark.parametrize("delta", [60, 15])
def test_a_delta_slot_starting_with_the_full_scan_slot_waits_for_its_spread_time_and_merges_into_it(delta, monkeypatch):
    """Hourly DELTA and the daily full scan due at 17:30 (start 17:00, offset 30 min): the 17:00 DELTA is not queued on
    its own; at 17:30 it merges into the full scan queued then, one run for both, as at 17:00 before the spread. A
    DELTA slot that ends before the full scan is due (every 15 minutes) runs at once, and none is queued twice."""
    monkeypatch.setattr(triggers, "full_scan_offset", lambda profile, interval: 1800)
    repo, _conn, profile, _item, settings = setup()
    repo.update_scope_profile(profile.id, schedule_minutes=delta)
    start = NOW.replace(hour=17, minute=0, second=0, microsecond=0)

    def poll(at):
        before = set(repo.jobs)
        result = poll_schedules(repo, settings, now=at)
        new = sorted(repo.jobs[i].payload["mode"] for i in set(repo.jobs) - before)
        for job in repo.jobs.values():
            job.status = "SUCCEEDED"
        return result, new

    assert poll(start - timedelta(hours=1)) == ({"enqueued": 1, "skipped": 0, "coalesced": 1}, ["RECONCILE"])
    if delta == 15:
        assert poll(start)[1] == ["DELTA"]
        assert poll(start + timedelta(minutes=15))[1] == ["DELTA"]
    else:
        assert poll(start) == ({"enqueued": 0, "skipped": 2, "coalesced": 0}, [])
        assert poll(start + timedelta(minutes=29, seconds=59)) == ({"enqueued": 0, "skipped": 2, "coalesced": 0}, [])
    assert poll(start + timedelta(minutes=30)) == ({"enqueued": 1, "skipped": 0, "coalesced": 1}, ["RECONCILE"])
    assert poll(start + timedelta(minutes=31))[1] == []
    assert poll(start + timedelta(hours=1))[1] == ["DELTA"]


def test_policy_hold_marks_delta_slot_and_change_event_runs_of_held_scopes_only(store):
    """While a scope is held after the upgrade, its DELTA slot runs and change-event runs (EVENT, or the whole-root
    DELTA fallback) carry policy_hold; a BASELINE reread, a full scan and a sweep never do. A scope approved after the
    upgrade, a changed digest, or the first post-upgrade full scan ended ends it."""
    repo, _conn, profile, item, settings = setup(repo=store)  # every 5 minutes, and the daily full scan
    day = NOW.replace(hour=0, minute=0, second=0, microsecond=0)
    profile = repo.update_scope_profile(profile.id, approved_at=day - timedelta(hours=12))
    upgraded(repo, day + timedelta(hours=10))
    at = day + timedelta(hours=11)

    def new_jobs(action):
        before = {job.id for job in repo.list_jobs()}
        action()
        return [job for job in repo.list_jobs() if job.id not in before]

    def poll(when):
        for job in repo.list_jobs():  # a queued run would answer the next slot instead of a new run
            if job.status == "QUEUED":
                repo.complete_job(job.id, 0, 0)
        return new_jobs(lambda: poll_schedules(repo, settings, now=when))

    def signal(of, root, name, **extra):
        return enqueue_event(repo, settings, of.id, event(root, event_id=name, **extra), now=at)[0]

    [delta] = poll(at)  # the open full-scan slot is skipped
    assert (delta.payload["mode"], delta.payload["policy_hold"]) == ("DELTA", True)
    assert sweeps(repo, settings, at) == 0  # records the digest; nothing was read before, so nothing to sweep anyway
    assert signal(profile, item, "exact").payload["policy_hold"] is True
    whole = signal(profile, item, "whole", keys=[])
    assert (whole.payload["mode"], whole.payload["policy_hold"]) == ("DELTA", True)
    reread = enqueue_event(repo, settings, profile.id, event(item, event_id="reread"), now=at, mode="BASELINE")[0]
    assert reread.payload["mode"] == "BASELINE" and "policy_hold" not in reread.payload
    # A scope approved after the upgrade is never held.
    _repo, _other_conn, other, other_item, _settings = setup(repo=repo, name="other", origin=None)
    other = repo.update_scope_profile(other.id, approved_at=day + timedelta(hours=10, minutes=30))
    fresh = poll(at + timedelta(minutes=10))
    assert sorted((job.payload["profile_id"] == str(other.id), job.payload["mode"]) for job in fresh) == [
        (False, "DELTA"), (True, "RECONCILE")]  # the other scope's DELTA slot merges into its full scan
    assert [job.payload["policy_hold"] for job in fresh if job.payload["profile_id"] == str(profile.id)] == [True]
    assert all("policy_hold" not in job.payload for job in fresh if job.payload["profile_id"] == str(other.id))
    assert "policy_hold" not in signal(other, other_item, "other").payload
    # An Admin changed rules: the next sweep pass sees another digest and latches it; nothing is held after it.
    assert sweeps(repo, settings, at + timedelta(minutes=15), "an-admin-changed-rules") == 0
    changed = poll(at + timedelta(minutes=15))
    assert sorted(job.payload["mode"] for job in changed) == ["DELTA", "DELTA"]
    assert all("policy_hold" not in job.payload for job in changed)
    assert "policy_hold" not in signal(profile, item, "after-the-change").payload
    # A full scan never carries the hold.
    at = day + timedelta(hours=17)
    queued = poll(at)
    assert {job.payload["mode"] for job in queued if job.payload["profile_id"] == str(profile.id)} == {"RECONCILE"}
    assert all("policy_hold" not in job.payload for job in queued)
    assert "policy_hold" not in signal(profile, item, "later").payload


def held_after_upgrade(store, schedule_minutes=0):
    """A scope approved before an upgrade at 10:00 UTC, its root read under the old policy; its first full scan after
    the upgrade is the 17:00 slot's. The first sweep pass records the digest after the upgrade and holds."""
    repo, conn, profile, item, settings = setup(repo=store)
    profile = repo.update_scope_profile(profile.id, schedule_minutes=schedule_minutes,
                                        approved_at=DAY - timedelta(hours=12))
    upgraded(repo, DAY + timedelta(hours=10))
    stale_root(repo, conn, profile)
    assert sweeps(repo, settings, DAY + timedelta(hours=10)) == 0
    return repo, profile, item, settings


def hold_at(repo, settings, profile, item, at, name):
    """(sweep queued, change-event run flagged) at ``at``: (False, True) while held, (True, False) once released."""
    flagged = "policy_hold" in enqueue_event(repo, settings, profile.id, event(item, event_id=name), now=at)[0].payload
    return sweeps(repo, settings, at) == 1, flagged


@pytest.mark.parametrize("ending, held", [("QUEUED", True), ("RUNNING", True), ("SUCCEEDED", False),
                                          ("PARTIAL", False), ("FAILED", False), ("CANCELLED", False)])
def test_the_hold_lasts_until_the_first_full_scan_has_ended_however_it_ended(store, ending, held):
    """Queued or running, the first post-upgrade full scan still holds the sweep and flags DELTA slot and change runs:
    beside it they would re-read a stale root whole. Ended in any status it releases them; the schedule's own run that
    failed or was cancelled consumes its slot (no reopening), and releases the hold all the same."""
    repo, profile, item, settings = held_after_upgrade(store, schedule_minutes=5)
    start = DAY + timedelta(hours=17)
    assert poll_schedules(repo, settings, now=start)["enqueued"] == 1  # the 17:00 DELTA slot merges into it
    [full] = repo.list_jobs()
    if ending != "QUEUED":
        begun(repo, full, start + timedelta(seconds=10))
    if ending in ("SUCCEEDED", "PARTIAL"):
        repo.complete_job(full.id, 1, 0, objects_failed=int(ending == "PARTIAL"))
    elif ending == "FAILED":
        repo.fail_job(full.id, "synthetic failure")
    elif ending == "CANCELLED":
        repo.request_job_cancel(full.id)
        repo.finish_cancelled_job(full.id)
    public = scope.run_public(repo.get_job(full.id), "source", profile.connection_id)["status"]
    assert public == {"SUCCEEDED": "COMPLETED"}.get(ending, ending)
    assert repo.slot_receipt_state(full_scan_slot(repo, settings, profile, start), start) == (True, None)
    before = {job.id for job in repo.list_jobs()}
    poll_schedules(repo, settings, now=start + timedelta(minutes=5))
    deltas = [job for job in repo.list_jobs() if job.id not in before]
    if ending == "QUEUED":
        assert deltas == []  # merged into the full scan still waiting
    else:
        [delta] = deltas
        assert delta.payload["mode"] == "DELTA" and ("policy_hold" in delta.payload) is held
    assert hold_at(repo, settings, profile, item, start + timedelta(minutes=6), "check") == (not held, held)


def test_a_merged_run_that_failed_holds_until_the_run_the_next_poll_queues_has_ended(store):
    """The 17:00 slot merged into an Admin's full read, which then failed: the slot reopens and the scope stays held,
    while the slot's own run the next poll queues waits and runs, until it has ended."""
    repo, profile, item, settings = held_after_upgrade(store)
    start = DAY + timedelta(hours=17)
    manual = admin_run(repo, settings, profile, start + timedelta(seconds=30))
    assert poll_schedules(repo, settings, now=start + timedelta(seconds=30)) == {"enqueued": 0, "skipped": 0, "coalesced": 1}
    begun(repo, manual, start + timedelta(seconds=40))
    assert hold_at(repo, settings, profile, item, start + timedelta(minutes=1), "merged") == (False, True)
    repo.fail_job(manual.id, "synthetic failure")
    receipt = full_scan_slot(repo, settings, profile, start)
    assert repo.slot_receipt_state(receipt, start) == (False, manual.id)
    assert hold_at(repo, settings, profile, item, start + timedelta(minutes=2), "reopened") == (False, True)
    assert poll_schedules(repo, settings, now=start + timedelta(minutes=3))["enqueued"] == 1
    [own] = [job for job in repo.list_jobs() if job.payload.get("slot_receipt") == receipt]
    assert hold_at(repo, settings, profile, item, start + timedelta(minutes=4), "queued") == (False, True)
    begun(repo, own, start + timedelta(minutes=5))
    assert hold_at(repo, settings, profile, item, start + timedelta(minutes=6), "running") == (False, True)
    repo.complete_job(own.id, 1, 0)
    assert hold_at(repo, settings, profile, item, start + timedelta(minutes=7), "ended") == (True, False)


def test_a_full_scan_that_never_ends_holds_one_cadence_after_it_was_due_at_most(store):
    repo, profile, item, settings = held_after_upgrade(store)
    start = DAY + timedelta(hours=17)
    assert poll_schedules(repo, settings, now=start)["enqueued"] == 1
    [full] = repo.list_jobs()
    begun(repo, full, start + timedelta(seconds=10))
    bound = start + timedelta(days=1)
    assert hold_at(repo, settings, profile, item, bound - timedelta(seconds=1), "last") == (False, True)
    assert hold_at(repo, settings, profile, item, bound, "bound") == (True, False)


@pytest.mark.parametrize("origin_after_due, runs", [
    (timedelta(seconds=-1), True), (timedelta(0), False), (timedelta(seconds=1), False)])
def test_an_upgrade_skips_a_full_scan_slot_only_if_it_was_already_due(store, monkeypatch, origin_after_due, runs):
    """Daily from 17:00 UTC, this scope due 3 hours later (20:00). Upgraded a second before 20:00, today's slot was not
    due yet: it runs at 20:00 and is the slot the hold waits for. Upgraded at 20:00 or after, it was current and is
    skipped; the hold waits for the next day's."""
    monkeypatch.setattr(triggers, "full_scan_offset", lambda profile, interval: 3 * 3600)
    repo, _conn, profile, _item, settings = setup(repo=store)
    profile = repo.update_scope_profile(profile.id, schedule_minutes=0, approved_at=DAY)
    due = DAY + timedelta(hours=20)
    origin = due + origin_after_due
    upgraded(repo, origin)
    cadence = trigger_settings.full_scan(settings, repo)
    # Nothing queued: sweep_held waits for its first slot until one cadence after that slot is due.
    first_due = due if runs else due + timedelta(days=1)
    let_go = first_due + timedelta(days=1)
    assert triggers.sweep_held(repo, profile, let_go - timedelta(seconds=1), cadence, origin)
    assert not triggers.sweep_held(repo, profile, let_go, cadence, origin)
    assert poll_schedules(repo, settings, now=max(origin, due)) == (
        {"enqueued": 1, "skipped": 0, "coalesced": 0} if runs else {"enqueued": 0, "skipped": 1, "coalesced": 0})


def test_an_upgrade_after_the_start_minute_but_before_the_scopes_due_time_runs_that_days_full_scan(store, monkeypatch):
    """Start 17:00 UTC, this scope's offset 3 hours (due 20:00), upgraded at 18:30: nothing is queued before 20:00, one
    RECONCILE at 20:00 the same day, and the sweep waits until that run has ended."""
    monkeypatch.setattr(triggers, "full_scan_offset", lambda profile, interval: 3 * 3600)
    repo, conn, profile, _item, settings = setup(repo=store)
    profile = repo.update_scope_profile(profile.id, schedule_minutes=0, approved_at=DAY)
    stale_root(repo, conn, profile)
    origin, due = DAY + timedelta(hours=18, minutes=30), DAY + timedelta(hours=20)
    upgraded(repo, origin)
    for at in (origin, due - timedelta(seconds=1)):
        assert poll_schedules(repo, settings, now=at) == {"enqueued": 0, "skipped": 1, "coalesced": 0}
        assert sweeps(repo, settings, at) == 0
    assert not repo.list_jobs()
    assert poll_schedules(repo, settings, now=due) == {"enqueued": 1, "skipped": 0, "coalesced": 0}
    [full] = repo.list_jobs()
    assert (full.payload["mode"], full.payload["slot_receipt"]) == (
        "RECONCILE", full_scan_slot(repo, settings, profile, due))
    assert sweeps(repo, settings, due + timedelta(seconds=1)) == 0
    repo.complete_job(full.id, 1, 0)
    assert sweeps(repo, settings, due + timedelta(seconds=2)) == 1


@pytest.mark.parametrize("began, queued", [(None, 0), (timedelta(seconds=30), 0), (timedelta(minutes=-4), 1)])
def test_a_full_scan_queued_just_before_the_start_minute_answers_that_slot_unless_it_began_before_it(began, queued):
    """The first poll at 16:55 UTC queues the full scan the slot that began yesterday at 17:00 never had. Still
    waiting at 17:00, or begun after it, that run is the 17:00 slot's too; begun at 16:56, it read what was there
    before the slot, and the slot gets a run of its own."""
    repo, _conn, profile, _item, settings = setup()
    repo.update_scope_profile(profile.id, schedule_minutes=0)
    start = NOW.replace(hour=17, minute=0, second=0, microsecond=0)
    assert poll_schedules(repo, settings, now=start - timedelta(minutes=5))["enqueued"] == 1
    [first] = repo.jobs.values()
    if began is not None:
        begun(repo, first, start + began)
    after = poll_schedules(repo, settings, now=start + timedelta(minutes=1))
    assert (after["enqueued"], after["coalesced"], len(repo.jobs)) == (queued, 1 - queued, 1 + queued)


def test_a_run_planned_before_a_credential_renewal_answers_no_slot_after_it():
    """A renewal carries the approval over (same version) under a new authorization. The run queued before it is
    refused when claimed, so the next slot gets a run of its own instead of being folded into it."""
    repo, conn, profile, _item, settings = setup()
    repo.update_scope_profile(profile.id, schedule_minutes=60, full_scan_minutes=0)
    at = NOW.replace(minute=1, second=0, microsecond=0)
    assert poll_schedules(repo, settings, now=at)["enqueued"] == 1
    old = profile.auth_revision
    repo.update_connection(conn.id, secret_ref="renewed-reference")
    renewed = scope.auth_revision("source", repo.get_connection(conn.id))
    repo.update_scope_profile(profile.id, auth_revision=renewed)  # what the renewal's _carry_approvals writes
    later = poll_schedules(repo, settings, now=at + timedelta(hours=1))
    assert (later["enqueued"], later["coalesced"]) == (1, 0)
    assert sorted(job.payload["auth_revision"] for job in repo.jobs.values()) == sorted([old, renewed])
    # The renewed run answers the slot after it while it waits.
    assert poll_schedules(repo, settings, now=at + timedelta(hours=2))["coalesced"] == 1 and len(repo.jobs) == 2


def test_a_refused_scope_is_not_planned_on_every_poll_and_the_refusal_consumes_no_slot(monkeypatch):
    """A paused connection's scope is planned once per open slot and process, then left for REFUSAL_SECONDS; the
    slot stays open, so the scope is scanned in it once it can be, and a new approval is planned at once."""
    from cremore.db import repository

    repo, conn, profile, _item, settings = setup()
    # Every write in one tick of the wall clock, as on hosts whose clock ticks in milliseconds: the re-approval
    # below leaves updated_at as it was and must still be noticed.
    monkeypatch.setattr(repository, "_now", lambda: NOW)
    repo.update_scope_profile(profile.id, schedule_minutes=60, full_scan_minutes=0)
    planned = []
    real = triggers.prepare_trigger_plan
    monkeypatch.setattr(triggers, "prepare_trigger_plan", lambda *args, **kw: planned.append(1) or real(*args, **kw))
    repo.update_connection(conn.id, status="DISABLED")
    at = NOW.replace(minute=1, second=0, microsecond=0)
    for minute in range(3):
        assert poll_schedules(repo, settings, now=at + timedelta(minutes=minute))["enqueued"] == 0
    assert len(planned) == 1 and not repo.jobs and not repo.trigger_receipts
    repo.update_connection(conn.id, status="ACTIVE")
    assert poll_schedules(repo, settings, now=at + timedelta(minutes=3))["enqueued"] == 0
    assert poll_schedules(repo, settings, now=at + timedelta(seconds=triggers.REFUSAL_SECONDS))["enqueued"] == 1
    assert len(planned) == 2
    # Refused in the next slot, then approved again within it: planned on the next poll.
    next(iter(repo.jobs.values())).status = "SUCCEEDED"
    repo.update_connection(conn.id, status="DISABLED")
    assert poll_schedules(repo, settings, now=at + timedelta(hours=1))["enqueued"] == 0
    repo.update_connection(conn.id, status="ACTIVE")
    repo.update_scope_profile(profile.id, approved_at=at + timedelta(hours=1))
    assert poll_schedules(repo, settings, now=at + timedelta(hours=1, minutes=1))["enqueued"] == 1
    assert len(planned) == 4


def test_one_broken_scope_never_stops_the_others_schedules(monkeypatch):
    """A scope whose plan fails unexpectedly (a malformed catalog item) is logged and left for REFUSAL_SECONDS like a
    refused one; every scope after it is still scheduled, and its own slot stays open until it can run."""
    repo, _conn, _profile, _item, settings = setup()
    setup(repo=repo, name="other")
    real, seen = triggers.prepare_trigger_plan, []

    def plan(repo, settings, profile_id, *args, **kw):
        seen.append(str(profile_id))
        if seen[0] == str(profile_id):  # whichever scope is listed first
            raise KeyError("resource_type")
        return real(repo, settings, profile_id, *args, **kw)

    monkeypatch.setattr(triggers, "prepare_trigger_plan", plan)
    at = NOW.replace(hour=12, minute=1, second=0, microsecond=0)
    poll_schedules(repo, settings, now=at)
    broken, [healthy] = seen[0], set(seen) - {seen[0]}
    assert {job.payload["profile_id"] for job in repo.jobs.values()} == {healthy}
    monkeypatch.setattr(triggers, "prepare_trigger_plan", real)
    poll_schedules(repo, settings, now=at + timedelta(minutes=1))
    assert broken not in {job.payload["profile_id"] for job in repo.jobs.values()}
    poll_schedules(repo, settings, now=at + timedelta(seconds=triggers.REFUSAL_SECONDS))
    assert broken in {job.payload["profile_id"] for job in repo.jobs.values()}


def test_full_scan_receipts_name_when_the_slot_began_so_an_upgrade_or_a_new_start_minute_skips_no_run():
    """The previous version numbered full-scan slots from midnight UTC, and a slot number is shared by slots of
    another start minute; a receipt names the slot's start and length instead. The cost is one full scan at once
    after the upgrade for a scope with a cadence of its own."""
    repo, _conn, profile, _item, settings = setup()
    repo.update_scope_profile(profile.id, schedule_minutes=0, full_scan_minutes=1440)
    day = NOW.replace(hour=0, minute=0, second=0, microsecond=0)
    # The receipt the previous version wrote for its run at 00:00 UTC today.
    repo.trigger_receipts[triggers._receipt("full-scan", str(profile.id), profile.version,
                                            int(day.timestamp()) // 86400)] = {"job_id": None, "plan_id": None,
                                                                               "created_at": day}

    def poll(at):
        before = set(repo.jobs)
        poll_schedules(repo, settings, now=at)
        for job in repo.jobs.values():
            job.status = "SUCCEEDED"
        return [repo.jobs[i].payload["mode"] for i in set(repo.jobs) - before]

    assert poll(day + timedelta(hours=18)) == ["RECONCILE"]  # the slot that began at 17:00 UTC has not run
    assert poll(day + timedelta(hours=19)) == []
    # Moved to 09:00 KST (midnight UTC) and back: the slots share numbers, never a start.
    switch_triggers(repo, full_scan_start_minute=0)
    assert poll(day + timedelta(days=1)) == ["RECONCILE"]
    switch_triggers(repo, full_scan_start_minute=1020)
    assert poll(day + timedelta(days=1, hours=17)) == ["RECONCILE"]


def saved_progress(repo, job, *, start="", reached="approved/file", digest="detector-v1"):
    """Persist the same fenced task/root evidence as a committed S3 budget stop."""
    from cremore.db.scan_store import ScanStore
    from cremore.db.task_store import TaskStore

    tasks = TaskStore(repo)
    for root in scope.split_roots(job.payload["roots"]):
        identity = scope.root_identity(job.connection_id, root)
        tasks.enqueue(job.id, identity, {"mode": "BASELINE", "scope": root, "job_payload": job.payload})
        task = tasks.claim(run_id=job.id)
        tasks.checkpoint(task["id"], task["token"], {
            "last_key": reached, "resume_start": start, "detection_digest": digest,
        })
        tasks.finish(task["id"], task["token"], {"stopped_reason": "BUDGET_REQUESTS"})
        ScanStore(repo).save_root(identity, job.connection_id, {
            "resume_after": reached, "resume_detection_digest": digest,
        })


def test_an_event_is_enqueued_once_and_keeps_neither_id_nor_content():
    repo, _conn, profile, item, settings = setup()
    first, created = enqueue_event(repo, settings, profile.id, event(item))
    again, repeated = enqueue_event(repo, settings, profile.id, event(item))
    assert created and not repeated and first.id == again.id
    assert len(repo.jobs) == len(repo.plans) == 1
    job, plan = next(iter(repo.jobs.values())), next(iter(repo.plans.values()))
    assert job.payload["roots"] == plan.roots
    assert job.payload["roots"][0]["exact_keys"] == ["approved/file"]
    assert job.payload["mode"] == "EVENT" and job.payload["verify"] is False
    assert "event_id" not in job.payload
    # Where it came from is recorded as feed, queue or webhook; the runtime keeps requested_by out of the
    # approved scope an event task compares, so runs from different origins still merge.
    assert job.payload["requested_by"] == "webhook"
    from cremore.scanning.triggers import event_origin

    assert [event_origin(o) for o in ("change-feed", "sqs", "pubsub", "servicebus", "notion:hook", "webhook")] == [
        "feed", "queue", "queue", "queue", "webhook", "webhook"]
    runtime = (Path(__file__).resolve().parents[1] / "worker" / "runtime.py").read_text(encoding="utf-8")
    assert '"plan_id", "policy_digest", "not_before", "requested_by", "mode"' in runtime


@pytest.mark.parametrize("change", ["scope", "unknown_field", "missing_id"])
def test_an_event_outside_the_approved_scope_or_shape_enqueues_nothing(change):
    repo, _conn, profile, item, settings = setup()
    payload = event(item)
    if change == "scope":
        payload["keys"] = ["approved/private/secret"]
    if change == "unknown_field":
        payload["raw_content"] = "must not be stored"
    if change == "missing_id":
        payload.pop("event_id")
    with pytest.raises(scope.ScopeError):
        enqueue_event(repo, settings, profile.id, payload)
    assert not repo.jobs and not repo.plans


def test_changed_authorization_or_disabled_profile_blocks_trigger():
    repo, conn, profile, item, settings = setup()
    repo.update_connection(conn.id, secret_ref="changed-reference")
    with pytest.raises(scope.ScopeError):
        enqueue_event(repo, settings, profile.id, event(item))
    assert not repo.jobs


def test_large_event_validates_every_key_then_falls_back_to_approved_delta():
    repo, _conn, profile, item, settings = setup()
    keys = [f"approved/{n}" for n in range(257)]
    job, created = enqueue_event(repo, settings, profile.id, event(item, keys=keys), now=NOW)
    assert created and job.payload["mode"] == "DELTA" and "exact_keys" not in job.payload["roots"][0]
    assert (datetime.fromisoformat(job.payload["not_before"]) - NOW).total_seconds() <= 5
    with pytest.raises(scope.ScopeError):
        enqueue_event(repo, settings, profile.id, event(item, event_id="bad", keys=keys + ["outside"]))
    assert len(repo.jobs) == 1


@pytest.mark.parametrize("provider,allowed,denied,field,exact", [
    ("github", "approved/file", "approved/private/file", "paths", "exact_paths"),
    ("notion", "a" * 32, "b" * 32, "page_ids", "exact_page_ids"),
])
def test_github_and_notion_event_intersection(provider, allowed, denied, field, exact):
    repo, _conn, profile, item, settings = setup(provider)
    payload = {"event_id": "event", "resource_id": item["id"], field: [allowed]}
    job, _ = enqueue_event(repo, settings, profile.id, payload)
    assert job.payload["roots"][0][exact] == [allowed]
    with pytest.raises(scope.ScopeError):
        enqueue_event(repo, settings, profile.id, {**payload, "event_id": "bad", field: [denied]})


def test_a_profile_whose_latest_run_finished_is_not_carried_on_from_an_older_stop():
    """Runs are read newest first. A profile that stopped on a budget and was
    then finished by a later run has nothing left; continuing from the older stop
    would re-read a scope that is already done."""

    repo, _conn, _profile, _item, settings = setup()
    assert poll_schedules(repo, settings, now=NOW)["enqueued"] == 1
    stopped = next(iter(repo.jobs.values()))
    stopped.status = "SUCCEEDED"
    stopped.coverage = {"stopped_reason": "BUDGET_REQUESTS", "objects": 5}
    stopped.payload = {**stopped.payload, "mode": "BASELINE", "verify": None}

    # A later run of the same profile reads the rest and ends cleanly.
    later = stopped.model_copy(deep=True)
    later.id = uuid.uuid4()
    later.created_at = stopped.created_at + timedelta(minutes=1)
    later.coverage = {"objects": 20}
    repo.jobs[later.id] = later

    assert poll_resumable(repo, settings, now=NOW) == {"enqueued": 0, "skipped": 0}
    assert len(repo.jobs) == 2, "nothing was queued for a scope that is finished"


def test_a_later_change_event_run_does_not_stop_a_budget_stopped_sweep_from_carrying_on():
    """An event run reads what changed beside the sweep, not the rest of the scope; only a later sweep supersedes."""
    repo, _conn, profile, item, settings = setup()
    assert poll_schedules(repo, settings, now=NOW)["enqueued"] == 1
    run = next(iter(repo.jobs.values()))
    run.status = "SUCCEEDED"
    run.coverage = {"stopped_reason": "BUDGET_REQUESTS", "objects": 5}
    run.payload = {**run.payload, "mode": "BASELINE", "verify": None}
    saved_progress(repo, run)
    later, _ = enqueue_event(repo, settings, profile.id, event(item), now=NOW)
    later.created_at = run.created_at + timedelta(minutes=1)
    later.status = "SUCCEEDED"
    assert poll_resumable(repo, settings, now=NOW)["enqueued"] == 1
    continuation = max((job for job in repo.jobs.values() if job.payload.get("requested_by") == "resume"),
                       key=lambda job: job.created_at)
    assert continuation.payload["trigger"] == "RESUME" and continuation.payload["mode"] == "BASELINE"


@pytest.mark.parametrize("reconcile_age", [None, 86400])
def test_a_run_stopped_on_its_budget_is_carried_on_exactly_once(reconcile_age):
    """A budget bounds a run, not the scope. Without this an estate larger than
    one budget only finishes if somebody keeps pressing start, and pressing it
    twice would queue the same continuation twice."""

    repo, _conn, profile, _item, settings = setup()
    stopped = next(iter(repo.jobs.values())) if repo.jobs else None
    assert stopped is None, "the fixture starts with no runs"

    assert poll_schedules(repo, settings, now=NOW)["enqueued"] == 1
    run = next(iter(repo.jobs.values()))
    run.status = "SUCCEEDED"
    run.coverage = {"stopped_reason": "BUDGET_REQUESTS", "objects": 5}
    # What an operator actually starts: a first full pass with verification left
    # to the installation's switch rather than forced off.
    run.payload = {**run.payload, "mode": "BASELINE", "verify": None}
    run.payload.pop("reconcile_if_older_than_seconds", None)
    if reconcile_age is not None:
        run.payload["reconcile_if_older_than_seconds"] = reconcile_age
    saved_progress(repo, run)

    carried = poll_resumable(repo, settings, now=NOW)
    assert carried["enqueued"] == 1, carried
    # It continues that run rather than becoming a scheduled scan: a half-read
    # BASELINE stays a BASELINE, so nothing is skipped as unchanged that was
    # never read, and verification stays whatever the operator asked for.
    continuation = max(repo.jobs.values(), key=lambda job: job.created_at)
    assert continuation.payload["mode"] == run.payload["mode"]
    assert continuation.payload.get("verify") == run.payload.get("verify")
    assert continuation.payload.get("reconcile_if_older_than_seconds") == reconcile_age
    # The same stopped run never queues a second continuation, however often
    # the poll runs or however many replicas run it.
    assert poll_resumable(repo, settings, now=NOW)["enqueued"] == 0
    assert len(repo.jobs) == 2

    # A run that ended without a budget stop ends the chain.
    for job in repo.jobs.values():
        job.status = "SUCCEEDED"
        job.coverage = {"objects": 5}
    assert poll_resumable(repo, settings, now=NOW)["enqueued"] == 0
    assert len(repo.jobs) == 2
    assert profile is not None
    # A poller nothing calls carries nothing on.
    from pathlib import Path

    worker_source = (Path(__file__).resolve().parents[1] / "worker" / "worker.py").read_text(encoding="utf-8")
    assert "poll_resumable(self.repo, self.settings)" in worker_source


@pytest.mark.parametrize("provider", ["github", "notion", "gcp"])
def test_budget_stop_without_durable_provider_traversal_does_not_loop(provider):
    repo, _conn, _profile, _item, settings = setup(provider)
    assert poll_schedules(repo, settings, now=NOW)["enqueued"] == 1
    run = next(iter(repo.jobs.values()))
    run.status = "SUCCEEDED"
    run.coverage = {"stopped_reason": "BUDGET_REQUESTS", "objects": 1}
    saved_progress(repo, run)  # An arbitrary last_key is not provider traversal support.
    for _ in range(3):
        assert poll_resumable(repo, settings, now=NOW) == {"enqueued": 0, "skipped": 1}
    assert len(repo.jobs) == 1 and run.coverage["stopped_reason"] == "BUDGET_REQUESTS"


@pytest.mark.parametrize("mode", ["EVENT", "DELTA", "BASELINE"])
def test_budget_stopped_event_preserves_exact_scope_without_a_fake_continuation(mode):
    repo, _conn, profile, item, settings = setup()
    signal = event(item, **({"keys": []} if mode == "DELTA" else {}))
    run, _ = enqueue_event(repo, settings, profile.id, signal, mode=mode)
    run.status = "SUCCEEDED"
    run.coverage = {"stopped_reason": "BUDGET_REQUESTS", "objects": 0}
    saved_progress(repo, run)
    # A change-event run (EVENT or DELTA) is no sweep to carry on; a BASELINE reread is, but has no traversal.
    assert poll_resumable(repo, settings, now=NOW) == {"enqueued": 0, "skipped": int(mode == "BASELINE")}
    assert len(repo.jobs) == 1
    assert run.payload["mode"] == mode
    if mode != "DELTA":
        assert run.payload["roots"][0]["exact_keys"] == ["approved/file"]
    assert run.coverage["stopped_reason"] == "BUDGET_REQUESTS"


@pytest.mark.parametrize("broken", ["missing", "no_progress", "rewound", "stale_cursor", "stale_digest", "overflow", "approval"])
def test_s3_continuation_requires_current_approval_and_durable_advancing_progress(broken):
    from cremore.db.scan_store import ScanStore

    repo, conn, profile, _item, settings = setup()
    assert poll_schedules(repo, settings, now=NOW)["enqueued"] == 1
    run = next(iter(repo.jobs.values()))
    run.status = "SUCCEEDED"
    run.coverage = {"stopped_reason": "BUDGET_REQUESTS", "objects": 1}
    if broken != "missing":
        saved_progress(repo, run, start={"no_progress": "approved/file", "rewound": "approved/z"}.get(broken, ""))
        identity = scope.root_identity(conn.id, scope.split_roots(run.payload["roots"])[0])
        store = ScanStore(repo)
        state = store.root(identity)
        if broken == "stale_cursor":
            state["resume_after"] = "approved/other"
        if broken == "stale_digest":
            state["resume_detection_digest"] = "different-detector"
        if broken == "overflow":
            state["retry_overflow"] = True
        store.save_root(identity, conn.id, state)
        if broken == "approval":
            repo.update_scope_profile(profile.id, version=profile.version + 1)
    assert poll_resumable(repo, settings, now=NOW) == {"enqueued": 0, "skipped": 1}
    assert len(repo.jobs) == 1


def test_schedule_slots_are_idempotent_and_obey_the_switch_and_the_installation_lock():
    repo, _conn, _profile, _item, settings = setup()
    at = NOW.replace(hour=17, minute=1, second=0, microsecond=0)
    assert poll_schedules(repo, settings, now=at) == {"enqueued": 1, "skipped": 0, "coalesced": 1}
    assert poll_schedules(repo, settings, now=at) == {"enqueued": 0, "skipped": 2, "coalesced": 0}
    first = next(iter(repo.jobs.values()))
    assert first.payload["mode"] == "RECONCILE"
    # Each slot has one receipt: a run that already started answers no later slot, and no poll duplicates one.
    first.status = "RUNNING"
    later = poll_schedules(repo, settings, now=at + timedelta(minutes=5))
    assert later == {"enqueued": 1, "skipped": 1, "coalesced": 0} and len(repo.jobs) == 2
    assert len(repo.trigger_receipts) == 3  # the full scan, its coalesced delta slot, the queued delta
    assert poll_schedules(repo, settings, now=at + timedelta(minutes=5))["enqueued"] == 0
    assert {job.payload["mode"] for job in repo.jobs.values()} == {"DELTA", "RECONCILE"}
    for job in repo.jobs.values():
        job.status = "SUCCEEDED"
    switch_triggers(repo, schedules_enabled=False)
    assert poll_schedules(repo, settings, now=at + timedelta(minutes=10))["enqueued"] == 0
    # Locked off by the installation, with the Admin's switch back on.
    switch_triggers(repo, schedules_enabled=True)
    locked = settings.model_copy(update={"scan_schedules_mode": "disabled"})
    assert poll_schedules(repo, locked, now=at + timedelta(minutes=15))["enqueued"] == 0
    assert poll_schedules(repo, settings, now=at + timedelta(minutes=15))["enqueued"] == 1


class Queue:
    def __init__(self, messages, repo):
        self.messages, self.repo = messages, repo
        self.calls = []

    def receive_message(self, **kwargs):
        assert kwargs["QueueUrl"] == QUEUE
        self.calls.append("receive")
        return {"Messages": self.messages}

    def delete_message(self, **kwargs):
        assert kwargs["QueueUrl"] == QUEUE and self.repo.jobs
        self.calls.append("delete")


def message(body):
    return {"MessageId": "message-1", "ReceiptHandle": "receipt-1", "Body": json.dumps(body)}


def test_dedicated_sqs_delete_notification_is_signal_and_ack_follows_durable_enqueue():
    repo, _conn, _profile, _item, settings = setup()
    body = {"Records": [{"eventSource": "aws:s3", "eventName": "ObjectRemoved:Delete",
                         "s3": {"bucket": {"name": "bucket"}, "object": {"key": "approved%2Ffile+name"}}}]}
    queue = Queue([message(body)], repo)
    assert poll_sqs(repo, settings, lambda: queue)["acknowledged"] == 1
    assert queue.calls == ["receive", "delete"]
    job = next(iter(repo.jobs.values()))
    assert job.payload["roots"][0]["exact_keys"] == ["approved/file name"]
    assert job.payload["requested_by"] == "queue"  # where the run came from, for the alert that names it
    # Redelivery is acknowledged even while its durable job is still queued.
    assert poll_sqs(repo, settings, lambda: queue)["acknowledged"] == 1
    assert queue.calls == ["receive", "delete", "receive", "delete"] and len(repo.jobs) == 1
    # A redelivery after it finished is answered by its receipt: no second job.
    job.status = "SUCCEEDED"
    assert poll_sqs(repo, settings, lambda: queue)["acknowledged"] == 1 and len(repo.jobs) == 1
    assert not any("delete" in key for key in next(iter(repo.jobs.values())).payload)


def test_sqs_never_consumes_without_dedicated_ack_and_does_not_ack_failure():
    repo, _conn, _profile, item, settings = setup()
    queue = Queue([message(event(item))], repo)
    # Switched on but not acknowledged as CreMore's own queue: a half-configured
    # trigger reads as off, so nothing is received. The dashboard says why
    # (blocked_by), which is where the person who switched it on is looking.
    unacknowledged = settings.model_copy(update={"scan_sqs_dedicated_acknowledged": False})
    switch_triggers(repo, sqs_dedicated_acknowledged=False)
    assert poll_sqs(repo, unacknowledged, lambda: queue) == {"acknowledged": 0, "failed": 0}
    assert trigger_settings.config(unacknowledged, repo)["sqs"]["blocked_by"] == "SQS_NOT_ACKNOWLEDGED"
    assert not queue.calls
    switch_triggers(repo, sqs_dedicated_acknowledged=True)
    repo.enqueue_triggered_scope = lambda *args: (_ for _ in ()).throw(RuntimeError("database unavailable"))
    assert poll_sqs(repo, settings, lambda: queue) == {"acknowledged": 0, "failed": 1}
    assert queue.calls == ["receive"] and not repo.jobs


def test_cloudtrail_read_events_do_not_create_an_event_loop():
    repo, _conn, _profile, _item, settings = setup()
    queue = Queue([message({"source": "aws.s3", "detail-type": "AWS API Call via CloudTrail",
        "detail": {"eventSource": "s3.amazonaws.com", "eventName": "GetObject",
                   "requestParameters": {"bucketName": "bucket", "key": "approved/file"}}})], repo)
    assert poll_sqs(repo, settings, lambda: queue)["failed"] == 1
    assert queue.calls == ["receive"] and not repo.jobs


def test_trigger_settings_and_inventory_reference_validation():
    _repo, _conn, profile, _item, settings = setup()
    for queue in ("http://sqs.us-east-1.amazonaws.com/123456789012/queue",
                  "https://untrusted.invalid/123456789012/queue", QUEUE + "?redirect=1"):
        with pytest.raises(ValueError):
            settings.model_copy(update={"scan_sqs_queue_url": queue}).validate_scan_triggers()
    identity = f"{profile.connection_id}/bucket"
    pointer = {"manifest_bucket": "inventory", "manifest_key": "reports/config/date/manifest.json"}
    configured = Settings(SCAN_INVENTORY_MANIFESTS=json.dumps({identity: pointer}))
    assert configured.inventory_manifest_bindings == {identity: pointer}
    for value in ({identity: {**pointer, "url": "https://untrusted.invalid"}},
                  {identity: {**pointer, "manifest_key": "https://untrusted.invalid/manifest.json"}},
                  {identity: {**pointer, "manifest_key": "../manifest.json"}}, {"bad/bucket": pointer}, []):
        with pytest.raises(ValueError):
            _ = Settings(SCAN_INVENTORY_MANIFESTS=json.dumps(value)).inventory_manifest_bindings


def test_policy_sweep_never_activates_unscanned_roots_and_receipt_is_stable():
    from types import SimpleNamespace

    from cremore.db.scan_store import ScanStore
    from cremore.worker.runtime import root_identity, split_roots

    repo, _conn, profile, _item, settings = setup()
    roots = [{**profile.selected_roots[0], "prefixes": ["approved/", "not-scanned/"]}]
    repo.update_scope_profile(profile.id, selected_roots=roots)
    catalog = repo.get_catalog(profile.kind, profile.connection_id)
    plan = scope.build_plan(profile, catalog, auth=profile.auth_revision, enabled=True)
    split = split_roots(plan.roots)
    scanned = next(root for root in split if root["prefixes"] == ["approved/"])
    store = ScanStore(repo)
    store.save_root(root_identity(profile.connection_id, scanned), profile.connection_id,
                    {"watermark": NOW.isoformat(), "detection_digest": "old"})
    orchestrator = SimpleNamespace(detection_policy_digest="new")
    assert poll_policy_sweeps(repo, settings, orchestrator)["enqueued"] == 1
    job = next(iter(repo.jobs.values()))
    assert job.payload["mode"] == job.payload["trigger"] == "POLICY_SWEEP"
    assert len(job.payload["roots"]) == 1 and job.payload["roots"][0]["prefixes"] == ["approved/"]
    assert poll_policy_sweeps(repo, settings, orchestrator)["enqueued"] == 0
    assert len(repo.jobs) == len(repo.plans) == 1


def test_policy_profile_pages_are_bounded_and_empty_states_do_not_enqueue():
    from types import SimpleNamespace

    repo, _conn, profile, _item, settings = setup()
    repo.create_scope_profile(profile.model_copy(update={"id": None, "name": "second"}))
    orchestrator = SimpleNamespace(detection_policy_digest="new")
    first = poll_policy_sweeps(repo, settings, orchestrator, limit=1)
    assert first["next_cursor"] and first["skipped"] == 1
    second = poll_policy_sweeps(repo, settings, orchestrator, cursor=first["next_cursor"], limit=1)
    assert second["next_cursor"] is None and second["skipped"] == 1
    assert not repo.jobs
    with pytest.raises(ValueError):
        poll_policy_sweeps(repo, settings, orchestrator, limit=101)


def test_receipt_cleanup_preserves_active_work_and_policy_sweeps():
    repo, _conn, profile, item, settings = setup()
    done, _ = enqueue_event(repo, settings, profile.id, event(item, event_id="done"))
    repo.jobs[done.id].status = "SUCCEEDED"
    policy, _ = enqueue_event(repo, settings, profile.id, event(item, event_id="policy"))
    repo.jobs[policy.id].status = "SUCCEEDED"
    repo.jobs[policy.id].payload["mode"] = "POLICY_SWEEP"
    active, _ = enqueue_event(repo, settings, profile.id, event(item, event_id="active"))
    for receipt in repo.trigger_receipts.values():
        receipt["created_at"] = NOW - timedelta(days=16)
    assert cleanup_trigger_receipts(repo, now=NOW) == 1
    assert {receipt["job_id"] for receipt in repo.trigger_receipts.values()} == {active.id, policy.id}
    assert len(repo.jobs) == len(repo.plans) == 3


def test_trigger_receipt_and_plan_are_atomic_on_sqlite_under_concurrent_delivery(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    from cremore.db.sql import SqlRepository, create_all, make_engine

    engine = make_engine("sqlite+pysqlite:///" + (tmp_path / "triggers.sqlite3").as_posix())
    create_all(engine)
    repo, _conn, profile, item, settings = setup(repo=SqlRepository(engine))
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: enqueue_event(repo, settings, profile.id, event(item)), range(8)))
    assert len({job.id for job, _created in results}) == 1
    assert sum(created for _job, created in results) == 1
    assert len(repo.list_jobs()) == 1
    engine.dispose()


@pytest.mark.parametrize("body", [
    {"source": "aws.s3", "detail-type": "Object Created",
     "detail": {"bucket": {"name": "bucket"}, "object": {"key": "approved/file"}}},
    {"source": "aws.s3", "detail-type": "AWS API Call via CloudTrail",
     "detail": {"eventSource": "s3.amazonaws.com", "eventName": "PutObject",
                "requestParameters": {"bucketName": "bucket", "key": "approved/file"}}},
])
def test_eventbridge_and_cloudtrail_mutation_signals_are_scoped(body):
    repo, _conn, _profile, _item, settings = setup()
    queue = Queue([message(body)], repo)
    assert poll_sqs(repo, settings, lambda: queue)["acknowledged"] == 1
    assert next(iter(repo.jobs.values())).payload["roots"][0]["exact_keys"] == ["approved/file"]


def test_a_message_with_multiple_events_is_acknowledged_after_all_jobs_are_durable(monkeypatch):
    from cremore.domain.models import ScanJob
    from cremore.scanning import triggers

    repo, _conn, _profile, _item, settings = setup()
    monkeypatch.setattr(triggers, "_native_events",
                        lambda body, roots: [{"resource_id": "root-a", "keys": []}, {"resource_id": "root-b", "keys": []}])
    receipts = {}

    def enqueue(_repo, _settings, _profile_id, event, *, receipt_id=None, **_kw):
        # A receipt makes replay idempotent before and after execution.
        if receipt_id in receipts:
            return receipts[receipt_id], False
        job = repo.enqueue_job(ScanJob(kind="scope", payload={"event": event["resource_id"]}))
        receipts[receipt_id] = job
        return job, True

    monkeypatch.setattr(triggers, "enqueue_event", enqueue)
    queue = Queue([message({"Records": []})], repo)
    first = poll_sqs(repo, settings, lambda: queue)
    assert first == {"acknowledged": 1, "failed": 0} and queue.calls == ["receive", "delete"]
    assert len(receipts) == len(repo.jobs) == 2
    # A replay does not add either event twice, even while work is pending.
    assert poll_sqs(repo, settings, lambda: queue) == {"acknowledged": 1, "failed": 0}
    assert queue.calls == ["receive", "delete", "receive", "delete"] and len(receipts) == len(repo.jobs) == 2



def test_an_event_is_durably_queued_while_scanning_and_replay_returns_the_same_job():
    from cremore.domain.models import ScanJob

    repo, _conn, profile, item, settings = setup()
    active = repo.enqueue_job(ScanJob(kind="github", payload={"owner": "o", "repo": "r"}))
    assert repo.claim_next_job().id == active.id
    job, created = enqueue_event(repo, settings, profile.id, event(item))
    assert created and job.id != active.id and len(repo.plans) == len(repo.trigger_receipts) == 1
    assert repo.claim_next_job() is None  # unscoped legacy run must drain first
    again, created = enqueue_event(repo, settings, profile.id, event(item))
    assert not created and again.id == job.id and len(repo.jobs) == 2
    active.status = "SUCCEEDED"
    assert repo.claim_next_job().id == job.id

def test_the_worker_passes_poll_sqs_something_it_can_actually_call():
    """The poll loop swallows every trigger exception, so a plumbing mistake here
    is invisible: SQS would simply never work. Exercise the real wiring."""
    from cremore.worker import JobWorker

    repo, _conn, _profile, item, settings = setup()
    # Disable schedules so this wiring test isolates the queue-created job.
    switch_triggers(repo, schedules_enabled=False)
    queue = Queue([message(event(item))], repo)
    built = []

    def factory():
        built.append(1)
        return queue

    worker = JobWorker(repo, settings=settings, sqs_client_factory=factory)
    worker._last_trigger_poll = 0
    worker.poll_triggers()
    assert queue.calls == ["receive", "delete"] and len(repo.jobs) == 1

    # No binding, no client: a worker that consumes no queue never needs a Region.
    switch_triggers(repo, sqs_enabled=False)
    before = len(built)
    worker._last_trigger_poll = 0
    worker.poll_triggers()
    assert len(built) == before
