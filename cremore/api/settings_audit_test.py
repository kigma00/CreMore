"""An installation setting and its audit row are stored together, in memory and SQL (cremore/api/routes/settings.py)."""

import os

import pytest
from cremore_aws_provider import aws_controltower, aws_inventory_settings, aws_sso_settings
from cremore_aws_provider.investigation import investigation_switches
from fastapi.testclient import TestClient

from cremore.api import create_app
from cremore.api.routes.settings import change_note
from cremore.config import Settings
from cremore.db.postgres_scan_test import (
    pg as pg,  # noqa: PLC0414 -- explicit pytest fixture re-export
)
from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.scanning import trigger_settings, verification_switch

TOKEN = "synthetic-admin-" + "x" * 32
QUEUE = "https://sqs.us-east-1.amazonaws.com/123456789012/" + "cremore-only"
SUBSCRIPTION = "projects/synthetic-project/subscriptions/" + "cremore-only"
BUS = "https://synthetic-bus.servicebus.windows.net/" + "cremore-only"
LIFECYCLE = "https://sqs.us-east-1.amazonaws.com/999999999999/" + "cremore-ct"
EXTERNAL_ID = "synthetic-" + "shared-external-id"
TRAIL = "synthetic-" + "trail-bucket"


def _stack(kind, request):
    engine = make_engine("sqlite:///:memory:") if kind == "sqlite" else None
    if engine is not None:
        create_all(engine)
    if kind == "postgres":
        repo = request.getfixturevalue("pg")[1]  # the pg fixture owns and drops its engine and schema
    else:
        repo = SqlRepository(engine) if engine is not None else InMemoryRepository()
    app = create_app(repo=repo, settings=Settings(AUTH_MODE="local", API_TOKEN=TOKEN, FINGERPRINT_KEY="ab" * 32),
                     aws_identity_probe=lambda **kwargs: {"state": "NO_CREDENTIALS"})
    return repo, TestClient(app, headers={"Authorization": "Bearer " + TOKEN}), engine


SQL = ["sqlite"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else [])


@pytest.fixture(params=["memory", *SQL])
def stack(request):
    repo, client, engine = _stack(request.param, request)
    yield repo, client
    client.close()
    if engine is not None:
        engine.dispose()


@pytest.fixture(params=SQL)
def sql_stack(request):
    repo, client, engine = _stack(request.param, request)
    yield repo, client
    client.close()
    if engine is not None:
        engine.dispose()


def _notes(repo):
    return sorted(event.note for event in repo.list_events(100) if event.event_type == "INSTALLATION_SETTING_CHANGED")


def test_a_setting_and_its_audit_row_are_one_write(stack):
    repo, client = stack
    assert client.put("/api/v1/settings/credential-verification", json={"enabled": False}).status_code == 200
    # Schedules are on until switched off, so switching them off is the change the note names.
    assert client.put("/api/v1/settings/scan-triggers", json={"sqs_queue_url": QUEUE, "schedules_enabled": False}).status_code == 200
    assert repo.get_setting(verification_switch.KEY)["value"] == {"enabled": False}
    assert trigger_settings.stored(repo)["sqs_queue_url"] == QUEUE
    assert _notes(repo) == ["credential_verification enabled=off", "scan_triggers schedules_enabled=off sqs_queue_url=set"]
    # A refused change stores nothing and records nothing; a request naming no field changes nothing.
    assert client.put("/api/v1/settings/scan-triggers", json={"sqs_queue_url": "https://example.test/q"}).status_code == 422
    before = repo.get_setting(trigger_settings.KEY)
    assert client.put("/api/v1/settings/scan-triggers", json={}).status_code == 200
    assert client.put("/api/v1/settings/learned-false-positives", json={}).status_code == 200
    assert repo.get_setting(trigger_settings.KEY) == before and len(_notes(repo)) == 2


def test_a_note_names_only_what_changed_and_a_save_changing_nothing_records_nothing(stack):
    """A screen sends its whole form: the note names the fields whose value changed, and saving again changes none."""
    repo, client = stack
    body = {"enabled": True, "account_ids": [], "cloudtrail_enabled": False, "regions": [], "interval_minutes": 60}
    minutes = {"github": 5, "gitlab": 15, "azure_devops": 5, "bitbucket": 5, "confluence": 5}
    for _ in range(2):
        assert client.put("/api/v1/settings/aws-credential-inventory", json=body).status_code == 200
        assert client.put("/api/v1/settings/credential-verification", json={"enabled": False}).status_code == 200
        assert client.put("/api/v1/settings/scan-triggers", json={"change_feed_minutes": minutes}).status_code == 200
    assert _notes(repo) == ["aws_credential_inventory enabled=on interval_minutes=60", "credential_verification enabled=off",
                            "scan_triggers change_feed_minutes=azure_devops:5,bitbucket:5,confluence:5,github:5,gitlab:15"]


def test_of_several_settings_only_those_whose_field_changed_are_stored(stack):
    """One PUT naming two settings, one unchanged: that one keeps its "last changed by", as no note names it."""
    repo, client = stack
    body = {"usage_lookup": True, "secrets_inventory": False}
    assert client.put("/api/v1/settings/aws-investigations", json=body).status_code == 200
    assert repo.get_setting(investigation_switches.USAGE_LOOKUP)["value"] == {"enabled": True}
    assert repo.get_setting(investigation_switches.SECRETS_INVENTORY) is None
    body = {"permission_set": "SyntheticReadOnly", "discovery_enabled": False}
    assert client.put("/api/v1/settings/aws-identity-center", json=body).status_code == 200
    assert repo.get_setting(aws_sso_settings.PERMISSION_SET_KEY)["value"] == {"permission_set": "SyntheticReadOnly"}
    assert repo.get_setting(aws_sso_settings.DISCOVERY_KEY) is None
    assert _notes(repo) == ["aws_identity_center permission_set=set", "aws_investigations usage_lookup=on"]


def test_saving_the_defaults_shown_for_an_unreadable_inventory_setting_rewrites_it(stack):
    repo, client = stack
    repo.put_settings({aws_inventory_settings.KEY: {"interval_minutes": "every hour"}}, "synthetic-admin")
    view = client.get("/api/v1/settings/aws-credential-inventory").json()
    assert view["reason"] == "AWS_INVENTORY_INVALID_SETTINGS" and view["interval_minutes"] == 1440
    fields = ("enabled", "interval_minutes", "account_ids", "cloudtrail_enabled", "cloudtrail_source", "window_days",
              "regions", "trail_bucket", "trail_prefixes")
    assert client.put("/api/v1/settings/aws-credential-inventory", json={k: view[k] for k in fields}).status_code == 200
    assert client.get("/api/v1/settings/aws-credential-inventory").json()["reason"] is None
    assert _notes(repo) == [("aws_credential_inventory enabled=off interval_minutes=1440 account_ids=0 cloudtrail_enabled=off "
                             "cloudtrail_source=event_history window_days=7 regions=0 trail_prefixes=0")]


def test_an_organizations_save_changing_nothing_wakes_no_sweep(stack):
    repo, client = stack
    assert client.put("/api/v1/settings/aws-organizations", json={"external_id": EXTERNAL_ID}).status_code == 200
    woken = repo.get_setting(aws_controltower.EVENT_KEY)["value"]["pending_request"]
    assert client.put("/api/v1/settings/aws-organizations", json={"external_id": EXTERNAL_ID, "excludes": []}).status_code == 200
    assert repo.get_setting(aws_controltower.EVENT_KEY)["value"]["pending_request"] == woken
    assert _notes(repo) == ["aws_org_discovery external_id=set"]


def test_a_save_another_admins_save_overtook_is_refused_not_written_over(stack, monkeypatch):
    """Two Admins save one multi-field setting at once: the later save, built on what it read before the other landed,
    is refused rather than storing its stale copy of the fields it did not change (and its note with it). Whether the
    setting was never saved or already holds values; the stored value decides, not a clock that can hold two saves."""
    from cremore.scanning import learned_fp_settings

    repo, client = stack
    read = learned_fp_settings.stored

    def overtaken_by(other):
        def stored(store):
            value = read(store)  # what this request builds on ...
            store.put_settings({learned_fp_settings.KEY: other}, "synthetic-other-admin")  # ... before this lands
            return value
        return stored

    for before, other in ((None, {"threshold": 0.9}), ({"threshold": 0.9}, {"threshold": 0.9, "max_confidence": "high"})):
        assert (repo.get_setting(learned_fp_settings.KEY) or {}).get("value") == before
        monkeypatch.setattr(learned_fp_settings, "stored", overtaken_by(other))
        answer = client.put("/api/v1/settings/learned-false-positives", json={"min_samples": 5})
        assert answer.status_code == 409 and answer.json()["detail"].startswith("SETTING_CHANGED_MEANWHILE")
        assert repo.get_setting(learned_fp_settings.KEY)["value"] == other and _notes(repo) == []
    monkeypatch.setattr(learned_fp_settings, "stored", read)
    assert client.put("/api/v1/settings/learned-false-positives", json={"min_samples": 5}).status_code == 200
    assert repo.get_setting(learned_fp_settings.KEY)["value"] == {"threshold": 0.9, "max_confidence": "high",
                                                                 "min_samples": 5}


@pytest.fixture(params=["memory"] + (["postgres"] if os.environ.get("CREMORE_TEST_POSTGRES_URL") else []))
def shared_stack(request):
    """Stacks whose saves two threads can run at once (SQLite in memory is one shared connection)."""
    repo, client, _engine = _stack(request.param, request)  # the pg fixture owns its engine
    yield repo, client
    client.close()


def test_two_first_saves_at_once_store_one_and_refuse_the_other(shared_stack, monkeypatch):
    """Both read the setting before either saves it, as two Admins pressing save together on a fresh install: the
    lock row every settings save takes makes the second wait, and it is refused, on PostgreSQL too."""
    import threading

    from cremore.scanning import learned_fp_settings

    repo, client = shared_stack
    read, both_read = learned_fp_settings.stored, threading.Barrier(2, timeout=20)

    def together(store):
        value = read(store)
        both_read.wait()
        return value

    monkeypatch.setattr(learned_fp_settings, "stored", together)
    answers = []

    def save(body):
        answers.append(client.put("/api/v1/settings/learned-false-positives", json=body).status_code)

    threads = [threading.Thread(target=save, args=(body,)) for body in ({"threshold": 0.9}, {"min_samples": 5})]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert sorted(answers) == [200, 409] and len(_notes(repo)) == 1
    assert len(repo.get_setting(learned_fp_settings.KEY)["value"]) == 1  # one save's field, never a merge of two


def test_a_detector_switch_is_stored_with_its_audit_row_only_when_it_changes(stack):
    from cremore.detection.catalog import builtin_definitions

    repo, client = stack
    detector = builtin_definitions()[0].catalog.id
    # Turning on a detector never switched changes nothing: no row, no audit, nobody "switched" it.
    untouched = client.put(f"/api/v1/detection-engine/detectors/{detector}", json={"enabled": True})
    assert untouched.status_code == 200 and untouched.json()["switched_by"] is None
    assert repo.get_setting("detection_detector:" + detector) is None
    for _ in range(2):
        answer = client.put(f"/api/v1/detection-engine/detectors/{detector}", json={"enabled": False})
        assert answer.status_code == 200 and answer.json()["switched_by"]
    assert client.put(f"/api/v1/detection-engine/detectors/{detector}", json={"enabled": True}).status_code == 200
    assert _notes(repo) == [f"detection_detector:{detector} enabled=off", f"detection_detector:{detector} enabled=on"]
    assert client.put("/api/v1/detection-engine/detectors/no-such-detector", json={"enabled": False}).status_code == 404


def test_a_setting_is_not_kept_when_its_audit_row_cannot_be_written(sql_stack, monkeypatch):
    """One transaction on SQL: an audit row that fails takes the setting with it."""
    repo, client = sql_stack

    def refused(self, conn, event, secret=None):
        raise RuntimeError("synthetic audit failure")

    monkeypatch.setattr(SqlRepository, "_record_event", refused)
    with pytest.raises(RuntimeError):
        client.put("/api/v1/settings/credential-verification", json={"enabled": False})
    with pytest.raises(RuntimeError):
        client.put("/api/v1/settings/scan-triggers", json={"sqs_queue_url": QUEUE})
    assert repo.get_setting(verification_switch.KEY) is None and repo.get_setting(trigger_settings.KEY) is None
    from cremore.detection.catalog import builtin_definitions

    detector = builtin_definitions()[0].catalog.id
    with pytest.raises(RuntimeError):
        client.put(f"/api/v1/detection-engine/detectors/{detector}", json={"enabled": False})
    assert repo.get_setting("detection_detector:" + detector) is None


def test_every_settings_note_names_fields_never_their_values(stack):
    repo, client = stack
    for path, body in (
            ("scan-triggers", {"pubsub_subscription": SUBSCRIPTION, "servicebus_queue": BUS, "pubsub_enabled": True}),
            ("aws-organizations", {"external_id": EXTERNAL_ID, "control_tower_enabled": True,
                                   "control_tower_region": "us-east-1", "lifecycle_queue_url": LIFECYCLE}),
            ("aws-credential-inventory", {"enabled": True, "account_ids": ["111111111111"], "cloudtrail_enabled": True,
                                          "cloudtrail_source": "s3", "window_days": 30, "regions": ["us-east-1"],
                                          "trail_bucket": TRAIL, "trail_prefixes": ["AWSLogs/"]}),
            ("aws-investigations", {"usage_lookup": True})):
        response = client.put(f"/api/v1/settings/{path}", json=body)
        assert response.status_code == 200, (path, response.json())
    assert _notes(repo) == [
        ("aws_credential_inventory enabled=on account_ids=1 cloudtrail_enabled=on cloudtrail_source=s3 window_days=30 "
         "regions=1 trail_bucket=set trail_prefixes=1"),
        "aws_investigations usage_lookup=on",
        ("aws_org_discovery external_id=set control_tower_enabled=on control_tower_region=us-east-1 "
         "lifecycle_queue_url=set"),
        "scan_triggers pubsub_enabled=on pubsub_subscription=set servicebus_queue=set"]
    written = " ".join(event.note or "" for event in repo.list_events(100))
    for value in (SUBSCRIPTION, BUS, LIFECYCLE, EXTERNAL_ID, TRAIL, "111111111111", "AWSLogs"):
        assert value not in written, value


@pytest.mark.parametrize(("changes", "plain", "note"), [
    ({"on": True, "off": False}, (), "x on=on off=off"),
    ({"minutes": 15, "threshold": 0.9}, (), "x minutes=15 threshold=0.9"),
    ({"url": QUEUE, "empty": ""}, (), "x url=set empty=cleared"),
    ({"ids": ["111111111111", "222222222222"], "map": {"123456789012": 1}}, (), "x ids=2 map=1"),
    ({"feeds": {"gitlab": 10, "github": 5}}, ("feeds",), "x feeds=github:5,gitlab:10"),
    ({"feeds": {}}, ("feeds",), "x feeds=0"),
    ({"level": "low", "hidden": "secret-like-value"}, ("level",), "x level=low hidden=set"),
])
def test_the_note_builder_shows_a_value_only_where_it_is_told_to(changes, plain, note):
    assert change_note("x", changes, plain) == note
