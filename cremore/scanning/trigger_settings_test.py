from datetime import UTC, datetime, timedelta

import pytest

from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.scanning import trigger_settings as s

QUEUE = "https://sqs.us-east-1.amazonaws.com/123456789012/cremore-only"
PROFILE = "8a1a2b3c-4d5e-4f60-8123-456789abcdef"


def _settings(**env):
    return Settings(**env)


def _on(repo, **fields):
    repo.put_setting(s.KEY, {**s.stored(repo), **fields}, "admin")
    return repo


def test_schedules_and_change_feeds_run_by_default_and_queues_wait_to_be_bound():
    """Nobody has to sign in for approved scopes to be scanned: an installation that never saved the switches
    scans every scope in full daily from 02:00 KST and reads changes; a queue still needs an Admin to bind it."""
    repo, settings = InMemoryRepository(), _settings()
    assert s.schedules_on(settings, repo) is True and s.change_feeds_on(settings, repo) is True
    assert s.full_scan(settings, repo) == (1440, 1020)
    assert s.sqs_binding(settings, repo) is None
    view = s.config(settings, repo)
    assert view["schedules"] == {"enabled": True, "switch": True, "installation_allows": True,
                                 "full_scan_default_minutes": 1440, "full_scan_start_minute": 1020}
    assert view["change_feeds"]["enabled"] is True and view["sqs"]["enabled"] is False
    assert view["updated_by"] is None
    # Bitbucket is read every 15 minutes unless an Admin says otherwise, every other feed every 5, Notion included.
    assert s.change_feed_minutes(settings, repo) == {"github": 5, "gitlab": 5, "azure_devops": 5, "bitbucket": 15,
                                                     "confluence": 5, "notion": 5}
    _on(repo, change_feed_minutes={"bitbucket": 30, "notion": 10})
    assert s.change_feed_minutes(settings, repo)["bitbucket"] == 30 and s.change_feed_minutes(settings, repo)["notion"] == 10


# Every field the previous version knew, as its merged() wrote them on any save: each switch off unless switched on.
OLD_FIELDS = ("schedules_enabled", *(f"{kind}_{name}" for kind, address in s.QUEUES.items()
                                     for name in ("enabled", "profile_id", address, "dedicated_acknowledged")),
              "change_feeds_enabled", "change_feed_minutes")


def legacy(**switched_on):
    return {**{name: {} if name == "change_feed_minutes" else False if name.endswith(("_enabled", "_acknowledged"))
               else "" for name in OLD_FIELDS}, **switched_on}


@pytest.mark.parametrize("record", [legacy(change_feeds_enabled=True), legacy(), legacy(sqs_enabled=True)])
def test_an_upgraded_record_runs_schedules_and_feeds_whatever_the_previous_version_stored(record):
    """The previous version stored every switch off unless switched on, whatever an Admin changed: that False was
    nobody's choice, so schedules and change feeds run after the upgrade. The installation's hard locks still win."""
    repo, settings = InMemoryRepository(), _settings()
    repo.put_setting(s.KEY, record, "admin")
    assert s.schedules_on(settings, repo) is True and s.change_feeds_on(settings, repo) is True
    assert s.stored(repo)["sqs_enabled"] is record["sqs_enabled"] and s.full_scan(settings, repo) == (1440, 1020)
    locked = _settings(SCAN_SCHEDULES_MODE="disabled", SCAN_CHANGE_FEEDS_MODE="disabled")
    assert s.schedules_on(locked, repo) is False and s.change_feeds_on(locked, repo) is False
    # The first save of this version keeps them on, and an Admin's off from then on stays off.
    repo.put_setting(s.KEY, s.merged(repo, {"sqs_enabled": True}), "admin")
    assert s.schedules_on(settings, repo) is True and s.change_feeds_on(settings, repo) is True
    repo.put_setting(s.KEY, s.merged(repo, {"schedules_enabled": False, "change_feeds_enabled": False}), "admin")
    assert s.schedules_on(settings, repo) is False and s.change_feeds_on(settings, repo) is False


def test_a_record_saved_by_this_version_keeps_its_off_and_reads_absent_cadences_as_defaults():
    repo, settings = InMemoryRepository(), _settings()
    repo.put_setting(s.KEY, {"schedules_enabled": False, "change_feeds_enabled": False, "sqs_enabled": True,
                             "full_scan_default_minutes": 1440}, "admin")
    assert s.schedules_on(settings, repo) is False and s.change_feeds_on(settings, repo) is False
    assert s.stored(repo)["sqs_enabled"] is True and s.full_scan(settings, repo) == (1440, 1020)
    repo.put_setting(s.KEY, {"full_scan_default_minutes": 720, "full_scan_start_minute": 0}, "admin")
    assert s.schedules_on(settings, repo) is True and s.full_scan(settings, repo) == (720, 0)
    # A cadence that no longer validates reads as its default rather than as anything else.
    repo.put_setting(s.KEY, {"full_scan_default_minutes": 90, "full_scan_start_minute": 1440}, "admin")
    assert s.full_scan(settings, repo) == (1440, 1020)


@pytest.mark.parametrize("field, good, bad", [
    ("full_scan_default_minutes", [0, 60, 120, 180, 240, 360, 480, 720, 1440], [90, 1, -1, 2880, True, "1440", None]),
    ("full_scan_start_minute", [0, 540, 1020, 1439], [-1, 1440, 30.5, True, "1020", None]),
])
def test_the_full_scan_default_and_its_start_minute_are_closed_choices(field, good, bad):
    for value in good:
        assert s.normalize({field: value}) == {field: value}
    for value in bad:
        with pytest.raises(s.TriggerSettingError):
            s.normalize({field: value})


def test_a_schedule_the_admin_set_is_honoured_and_the_record_says_who():
    repo = _on(InMemoryRepository(), schedules_enabled=True)
    settings = _settings()
    assert s.schedules_on(settings, repo) is True
    view = s.config(settings, repo)["schedules"]
    assert view["enabled"] is True and view["switch"] is True
    assert s.config(settings, repo)["updated_by"] == "admin"
    # Configuration overrides the switch without erasing it.
    locked = _settings(SCAN_SCHEDULES_MODE="disabled")
    assert s.schedules_on(locked, repo) is False
    assert s.config(locked, repo)["schedules"] == {
        "enabled": False, "switch": True, "installation_allows": False,
        "full_scan_default_minutes": 1440, "full_scan_start_minute": 1020}


def test_a_half_configured_trigger_reads_as_off_and_says_what_is_missing():
    """Failing at the moment a message arrives is the worst time to find out."""
    repo, settings = _on(InMemoryRepository(), sqs_enabled=True), _settings()
    assert s.sqs_binding(settings, repo) is None
    assert s.config(settings, repo)["sqs"]["blocked_by"] == "SQS_NOT_ACKNOWLEDGED"

    _on(repo, sqs_dedicated_acknowledged=True)
    assert s.config(settings, repo)["sqs"]["blocked_by"] == "SQS_PROFILE_NOT_BOUND"
    _on(repo, sqs_profile_id=PROFILE)
    assert s.config(settings, repo)["sqs"]["blocked_by"] == "SQS_QUEUE_URL_MISSING"
    _on(repo, sqs_queue_url=QUEUE)
    assert s.sqs_binding(settings, repo) == {"profile_id": PROFILE, "queue_url": QUEUE}


def test_configuration_pins_a_field_and_the_dashboard_shows_it_as_fixed():
    repo = _on(InMemoryRepository(), sqs_enabled=True, sqs_profile_id=PROFILE,
               sqs_queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/admin-chose",
               sqs_dedicated_acknowledged=True)
    pinned = _settings(SCAN_SQS_QUEUE_URL=QUEUE)
    assert s.sqs_binding(pinned, repo)["queue_url"] == QUEUE
    view = s.config(pinned, repo)["sqs"]
    assert view["queue_url"] == QUEUE and view["queue_url_locked"] is True
    assert view["profile_id_locked"] is False


@pytest.mark.parametrize("queue", [
    "https://untrusted.invalid/q",
    "https://sqs.us-east-1.amazonaws.com:invalid/123456789012/q",
    "https://[sqs.us-east-1.amazonaws.com/123456789012/q",
])
def test_a_stored_value_that_no_longer_validates_turns_its_trigger_off(queue):
    """Consuming an unrecognised queue URL is worse than consuming nothing."""
    repo = InMemoryRepository()
    repo.put_setting(s.KEY, {"sqs_enabled": True, "sqs_dedicated_acknowledged": True,
                              "sqs_profile_id": PROFILE, "sqs_queue_url": queue}, "admin")
    assert s.stored(repo)["sqs_queue_url"] == ""
    assert s.sqs_binding(_settings(), repo) is None
    # A switch this version saved that is not exactly True is not a switch.
    repo.put_setting(s.KEY, {"schedules_enabled": "true", "full_scan_default_minutes": 1440}, "admin")
    assert s.schedules_on(_settings(), repo) is False


def test_an_admin_cannot_store_a_queue_url_cremore_would_not_consume():
    for bad in ("http://sqs.us-east-1.amazonaws.com/123456789012/q",
                "https://untrusted.invalid/123456789012/q",
                QUEUE + "?redirect=1", QUEUE + "#x",
                "https://user:pw@sqs.us-east-1.amazonaws.com/123456789012/q",
                "https://sqs.us-east-1.amazonaws.com:8443/123456789012/q",
                "https://sqs.us-east-1.amazonaws.com:invalid/123456789012/q",
                "https://[sqs.us-east-1.amazonaws.com/123456789012/q",
                "https://sqs.us-east-1.amazonaws.com/12345/q"):
        with pytest.raises(s.TriggerSettingError):
            s.normalize({"sqs_queue_url": bad})
    assert s.normalize({"sqs_queue_url": QUEUE}) == {"sqs_queue_url": QUEUE}


def test_normalize_refuses_unknown_fields_and_non_booleans():
    with pytest.raises(s.TriggerSettingError):
        s.normalize({"schedules_enabled": "yes"})
    with pytest.raises(s.TriggerSettingError):
        s.normalize({"scan_everything": True})
    with pytest.raises(s.TriggerSettingError):
        s.normalize({"sqs_profile_id": "not-a-uuid"})
    assert s.normalize({"sqs_profile_id": ""}) == {"sqs_profile_id": ""}


def test_merged_applies_a_change_without_writing_back_the_audit_fields():
    repo = _on(InMemoryRepository(), schedules_enabled=True, sqs_profile_id=PROFILE)
    value = s.merged(repo, {"sqs_enabled": True})
    assert set(value) == set(s.FIELDS)
    assert value["schedules_enabled"] is True and value["sqs_enabled"] is True
    assert value["sqs_profile_id"] == PROFILE


def test_every_name_the_module_uses_exists_on_the_settings_model():
    """A typo would silently allow a trigger the installation locked, or drop a pin."""
    settings = Settings()
    for name in s.ALLOWED_BY.values():
        assert hasattr(settings, name), name
    for name in s.PINS.values():
        assert hasattr(settings, name), name


ORIGIN = datetime(2026, 10, 11, 10, 0, tzinfo=UTC)


def test_the_schedule_origin_is_only_read_and_only_when_plausible(caplog):
    """The migration records when this version began; a poll or a view only reads it, and no record skips nothing and
    records nothing. A value the migration could not have written skips nothing, and says so in the log with a code
    and times, never the stored text."""
    def warnings():
        found = [r.getMessage() for r in caplog.records if r.name == s.__name__ and r.levelname == "WARNING"]
        caplog.clear()
        return found

    repo = InMemoryRepository()
    assert s.schedule_origin(repo, ORIGIN) is None and repo.get_setting(s.ORIGIN_KEY) is None and not warnings()
    repo.put_setting(s.ORIGIN_KEY, {"at": ORIGIN.isoformat()}, "migration")
    assert s.schedule_origin(repo, ORIGIN + timedelta(days=1)) == ORIGIN
    assert not warnings()
    for value in ({"at": "yesterday"}, {"at": "2026-10-11T10:00:00"}, {"at": "2" * 65}, {"at": 1}, {}):
        repo.put_setting(s.ORIGIN_KEY, value, "x")
        assert s.schedule_origin(repo, ORIGIN) is None, value
        [message] = warnings()
        assert "SCHEDULE_ORIGIN_UNREADABLE" in message and "yesterday" not in message and "2" * 65 not in message
    # Recorded by the database's clock, which a worker's may trail: up to a day ahead is read; further is not this
    # installation's.
    for ahead in (timedelta(hours=1), s.ORIGIN_SKEW):
        repo.put_setting(s.ORIGIN_KEY, {"at": (ORIGIN + ahead).isoformat()}, "migration")
        assert s.schedule_origin(repo, ORIGIN) == ORIGIN + ahead and not warnings()
    ahead = ORIGIN + s.ORIGIN_SKEW + timedelta(seconds=1)
    repo.put_setting(s.ORIGIN_KEY, {"at": ahead.isoformat()}, "migration")
    assert s.schedule_origin(repo, ORIGIN) is None
    assert warnings() == [(f"scan schedule origin ignored: SCHEDULE_ORIGIN_AHEAD_OF_CLOCK (origin {ahead.isoformat()}, "
                           f"now {ORIGIN.isoformat()})")]


def test_the_upgrade_digest_is_recorded_once_and_a_later_change_is_latched():
    repo = InMemoryRepository()
    s.record_upgrade_digest(repo, "a")
    assert repo.get_setting(s.ORIGIN_KEY) is None and s.rules_unchanged(repo, "b")  # no origin: nothing to record
    repo.put_setting(s.ORIGIN_KEY, {"at": ORIGIN.isoformat()}, "migration")
    assert s.rules_unchanged(repo, "anything") and s.rules_unchanged(repo)  # not recorded yet: held
    s.record_upgrade_digest(repo, "a")
    s.record_upgrade_digest(repo, "a")
    assert repo.get_setting(s.ORIGIN_KEY)["value"] == {"at": ORIGIN.isoformat(), "detection_digest": "a"}
    assert s.rules_unchanged(repo, "a") and s.rules_unchanged(repo) and not s.rules_unchanged(repo, "b")
    s.record_upgrade_digest(repo, "b")
    assert repo.get_setting(s.ORIGIN_KEY)["value"] == {"at": ORIGIN.isoformat(), "detection_digest": "a", "rules_changed": True}
    assert not s.rules_unchanged(repo) and not s.rules_unchanged(repo, "a")  # latched: rules changed back still runs


def test_the_migration_records_the_origin_once_by_the_database_clock_and_keeps_one_already_there(tmp_path):
    from sqlalchemy import delete

    from cremore.db.schema import schema_migrations
    from cremore.db.sql import SqlRepository, create_all, make_engine

    engine = make_engine("sqlite+pysqlite:///" + (tmp_path / "origin.sqlite3").as_posix())
    before = datetime.now(UTC).replace(microsecond=0)
    create_all(engine)
    repo = SqlRepository(engine)
    origin = s.schedule_origin(repo, datetime.now(UTC))
    assert before <= origin <= datetime.now(UTC) and repo.get_setting(s.ORIGIN_KEY)["updated_by"] == "migration"
    create_all(engine)  # a restart: the same moment
    assert s.schedule_origin(repo, datetime.now(UTC)) == origin
    # An installation an earlier build recorded on a poll keeps that moment when the migration first runs.
    with engine.begin() as conn:
        conn.execute(delete(schema_migrations).where(schema_migrations.c.version == 14))
    repo.put_setting(s.ORIGIN_KEY, {"at": ORIGIN.isoformat()}, "schedule")
    create_all(engine)
    assert s.schedule_origin(repo, ORIGIN) == ORIGIN
    engine.dispose()
