"""The Admin's alert setup: the webhook address is checked like the SIEM Slack sink's and sealed, a blank one keeps
the saved address, the bot posts only to a channel the contact setup lists, turning alerts on stamps when, the console
address lives once in the contact setup, and every change is audited without its values."""

import datetime as dt
import json

import pytest

from cremore.alerts import setup
from cremore.config import Settings
from cremore.db.repository import InMemoryRepository
from cremore.governance import contact
from cremore.secretstore.sealed import unseal

SETTINGS = Settings(FINGERPRINT_KEY="ab" * 32)
# Built at run time: nothing secret-shaped sits in the source.
WEBHOOK = "https://hooks.slack.com/services/T0ABC1234/B0ABC5678/" + "k" * 24
TOKEN = "xoxb-" + "1" * 12 + "-" + "a" * 24
NOW = dt.datetime(2026, 10, 9, 5, 0, tzinfo=dt.UTC)


def notes(repo) -> list[str]:
    return [event.note for event in repo.list_events(100) if event.event_type == "INSTALLATION_SETTING_CHANGED"]


def with_bot(repo, channels=("#security-alerts", "C0123ABCD9")):
    contact.save(repo, SETTINGS, {"slack": {"token": TOKEN, "allowed_channels": list(channels)},
                                  "allowed_domains": ["example.com"], "console_url": "https://cremore.example.com"}, "admin")


@pytest.mark.parametrize("value", [
    WEBHOOK, "https://hooks.slack-gov.com/services/T1/B1/abc_DEF-123", "HTTPS://HOOKS.SLACK.COM/services/T1/B1/x",
    "https://hooks.slack.com:443/services/T1/B1/x"])
def test_an_incoming_webhook_address_is_taken(value):
    assert setup.webhook_url(value).startswith(("https://hooks.slack.com/services/", "https://hooks.slack-gov.com/services/"))


@pytest.mark.parametrize("value", [
    "http://hooks.slack.com/services/T1/B1/x", "https://hooks.slack.com.evil.example/services/T1/B1/x",
    "https://evil.example/services/T1/B1/x", "https://hooks.slack.com:8443/services/T1/B1/x",
    "https://user@hooks.slack.com/services/T1/B1/x", "https://hooks.slack.com/services/T1/B1/x?y=1",
    "https://hooks.slack.com/services/T1/B1/x#f", "https://hooks.slack.com/services/t1/B1/x",
    "https://hooks.slack.com/services/T1/B1", "https://hooks.slack.com/services/T1/B1/x/y",
    "https://hooks.slack.com/services/T1/B1/%2e", "https://hooks.slack.com/services/T1/B1/x y", "", None, 7,
    "https://hooks.slack.com/services/T1/B1/" + "x" * 600])
def test_anything_else_is_refused(value):
    with pytest.raises(setup.AlertSetupError) as refused:
        setup.webhook_url(value)
    assert refused.value.code == "ALERTS_WEBHOOK_INVALID"


def test_the_webhook_is_sealed_never_shown_and_a_blank_one_keeps_it():
    repo = InMemoryRepository()
    assert setup.public(repo)["enabled"] is False and setup.public(repo)["webhook_saved"] is False
    setup.save(repo, SETTINGS, {"webhook_url": " " + WEBHOOK + " "}, "ada", now=NOW)
    stored = repo.get_setting(setup.KEY)["value"]
    assert WEBHOOK not in json.dumps(stored) and unseal(SETTINGS.sealing_keys, stored["webhook"]) == {"url": WEBHOOK}
    view = setup.public(repo)
    assert view["webhook_saved"] is True and WEBHOOK not in json.dumps(view)
    setup.save(repo, SETTINGS, {"webhook_url": "", "enabled": True}, "ada", now=NOW)
    assert repo.get_setting(setup.KEY)["value"]["webhook"] == stored["webhook"]
    assert setup.config(repo)["enabled_at"] == NOW.isoformat()
    # Saved values in the audit trail are named, never shown.
    assert notes(repo) == ["detection_alerts enabled=on", "detection_alerts webhook_url=set"]
    assert WEBHOOK not in json.dumps(notes(repo))


def test_turning_alerts_on_stamps_when_and_again_after_a_pause():
    repo = InMemoryRepository()
    with pytest.raises(setup.AlertSetupError) as refused:
        setup.save(repo, SETTINGS, {"enabled": True}, "ada")
    assert refused.value.code == "ALERTS_WEBHOOK_REQUIRED" and repo.get_setting(setup.KEY) is None
    setup.save(repo, SETTINGS, {"enabled": True, "webhook_url": WEBHOOK}, "ada", now=NOW)
    setup.save(repo, SETTINGS, {"enabled": True, "min_severity": "HIGH"}, "ada", now=NOW + dt.timedelta(hours=1))
    assert setup.config(repo)["enabled_at"] == NOW.isoformat()  # still on: the same start
    setup.save(repo, SETTINGS, {"enabled": False}, "ada", now=NOW + dt.timedelta(hours=2))
    setup.save(repo, SETTINGS, {"enabled": True}, "ada", now=NOW + dt.timedelta(days=1))
    value = setup.config(repo)
    assert value["enabled_at"] == (NOW + dt.timedelta(days=1)).isoformat()
    # Delivery skips only the time off: the first turn-on and the last turn-off are kept with the new start.
    assert (value["first_enabled_at"], value["disabled_at"]) == (NOW.isoformat(), (NOW + dt.timedelta(hours=2)).isoformat())
    assert notes(repo)[:2] == ["detection_alerts enabled=on", "detection_alerts enabled=off"]
    assert "detection_alerts min_severity=HIGH" in notes(repo)
    # Nothing changed: nothing stored, nothing audited.
    count = len(notes(repo))
    setup.save(repo, SETTINGS, {"enabled": True, "min_severity": "HIGH", "webhook_url": ""}, "ada")
    assert len(notes(repo)) == count


def test_the_bot_posts_only_to_a_channel_the_contact_setup_lists():
    repo = InMemoryRepository()
    with pytest.raises(setup.AlertSetupError) as refused:
        setup.save(repo, SETTINGS, {"transport": "bot", "enabled": True}, "ada")
    assert (refused.value.code, refused.value.http_status) == ("ALERTS_BOT_NOT_SET_UP", 409)
    with_bot(repo)
    for body, code in (({"channel": "#general"}, "ALERTS_CHANNEL_NOT_ALLOWED"),
                       ({"transport": "bot", "enabled": True}, "ALERTS_CHANNEL_REQUIRED")):
        with pytest.raises(setup.AlertSetupError) as refused:
            setup.save(repo, SETTINGS, body, "ada")
        assert refused.value.code == code
    setup.save(repo, SETTINGS, {"transport": "bot", "channel": "C0123ABCD9", "enabled": True}, "ada")
    view = setup.public(repo)
    assert (view["transport"], view["channel"], view["bot_ready"]) == ("bot", "C0123ABCD9", True)
    assert view["channels"] == ["#security-alerts", "C0123ABCD9"]
    assert notes(repo)[0] == "detection_alerts enabled=on transport=bot channel=set"


def test_a_channel_the_contact_setup_dropped_meanwhile_is_refused(monkeypatch):
    from cremore import installation_settings

    repo = InMemoryRepository()
    with_bot(repo)
    real = installation_settings.locked_installation_settings

    def overtaken(bound_repo):  # bob's contact save, dropping the channel, lands between the read and the lock
        saved = bound_repo.get_setting(contact.SETTING_KEY)["value"]
        bound_repo.put_setting(contact.SETTING_KEY, {**saved, "slack": {**saved["slack"],
                                                                         "allowed_channels": ["#security-alerts"]}}, "bob")
        return real(bound_repo)

    monkeypatch.setattr(installation_settings, "locked_installation_settings", overtaken)
    with pytest.raises(setup.AlertSetupError) as refused:
        setup.save(repo, SETTINGS, {"transport": "bot", "channel": "C0123ABCD9", "enabled": True}, "ada")
    assert refused.value.http_status == 409 and refused.value.code.startswith("SETTING_CHANGED_MEANWHILE")
    assert repo.get_setting(setup.KEY) is None


def test_the_console_address_is_kept_once_in_the_contact_setup():
    repo = InMemoryRepository()
    with_bot(repo)
    before = repo.get_setting(contact.SETTING_KEY)["value"]
    setup.save(repo, SETTINGS, {"console_url": "https://CreMore.Internal.example:8443/"}, "ada")
    after = repo.get_setting(contact.SETTING_KEY)["value"]
    assert after == {**before, "console_url": "https://cremore.internal.example:8443"}
    assert setup.public(repo)["console_url"] == contact.channels(repo)["console_url"] == "https://cremore.internal.example:8443"
    assert repo.get_setting(setup.KEY) is None  # the alert setup itself did not change
    assert notes(repo) == ["detection_alerts console_url=set"]
    setup.save(repo, SETTINGS, {"console_url": ""}, "ada")
    assert contact.channels(repo)["console_url"] is None and contact.channels(repo)["slack"] is True
    with pytest.raises(setup.AlertSetupError) as refused:
        setup.save(repo, SETTINGS, {"console_url": "https://cremore.example.com/path"}, "ada")
    assert refused.value.code == "CONTACT_CONSOLE_URL_INVALID"


@pytest.mark.parametrize(("body", "code"), [
    ({"transport": "email"}, "ALERTS_TRANSPORT_INVALID"), ({"min_severity": "SEVERE"}, "ALERTS_MIN_SEVERITY_INVALID"),
    ({"detail": "full"}, "ALERTS_DETAIL_INVALID"), ({"language": "ja"}, "ALERTS_LANGUAGE_INVALID"),
    ({"enabled": "yes"}, "ALERTS_ENABLED_INVALID"), ({"events": []}, "ALERTS_EVENTS_INVALID"),
    ({"events": ["finding.updated"]}, "ALERTS_EVENTS_INVALID"), ({"webhook": "x"}, "ALERTS_SETTINGS_INVALID"),
    ({"webhook_url": "https://example.com/hook"}, "ALERTS_WEBHOOK_INVALID"), ([], "ALERTS_SETTINGS_INVALID")])
def test_a_change_is_checked_before_anything_is_stored(body, code):
    repo = InMemoryRepository()
    with pytest.raises(setup.AlertSetupError) as refused:
        setup.save(repo, SETTINGS, body, "ada")
    assert refused.value.code == code and repo.get_setting(setup.KEY) is None


def test_events_are_a_subset_kept_in_a_fixed_order():
    repo = InMemoryRepository()
    setup.save(repo, SETTINGS, {"events": ["finding.location_added", "finding.created", "finding.created"]}, "ada")
    assert setup.config(repo)["events"] == ["finding.created", "finding.location_added"]
    assert notes(repo) == ["detection_alerts events=2"]
