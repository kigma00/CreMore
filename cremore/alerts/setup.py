"""Slack alerts for new detections: the ``detection_alerts`` setting an Admin keeps in the console.

Alerts go to a Slack Incoming Webhook, whose address is sealed on arrival and never shown again, or through the
contact setup's Slack bot to one of the channels listed there (cremore/governance/contact.py, which also keeps the
console's address that alert links start with). Turning alerts on stamps ``enabled_at`` (and ``first_enabled_at`` the
first time), turning them off ``disabled_at``: delivery skips the history before the first turn-on and what happened
while they were off, never an alert still owed from a time they were on (cremore/alerts/delivery.py).
"""

from __future__ import annotations

import datetime as _dt
import re
from urllib.parse import urlsplit

from cremore.governance import contact
from cremore.secretstore.sealed import seal_fields, unseal

KEY = "detection_alerts"
TRANSPORTS = ("webhook", "bot")
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
DETAILS = ("standard", "minimal")
LANGUAGES = ("ko", "en")
EVENTS = ("finding.created", "finding.reappeared", "finding.location_added")
DEFAULTS = {"enabled": False, "transport": "webhook", "webhook": None, "channel": None, "min_severity": "INFO",
            "detail": "standard", "language": "ko", "events": list(EVENTS), "enabled_at": None,
            "first_enabled_at": None, "disabled_at": None}
_CHOICES = {"transport": TRANSPORTS, "min_severity": SEVERITIES, "detail": DETAILS, "language": LANGUAGES}
_FIELDS = {"enabled", "webhook_url", "channel", "events", "console_url", *_CHOICES}
_SHOWN = ("enabled", "transport", "channel", "min_severity", "detail", "language", "events")
_WEBHOOK_HOSTS = ("hooks.slack.com", "hooks.slack-gov.com")
_WEBHOOK_PATH = re.compile(r"/services/[A-Z0-9]{1,64}/[A-Z0-9]{1,64}/[A-Za-z0-9_-]{1,256}\Z")
_CHANGED_MEANWHILE = "SETTING_CHANGED_MEANWHILE: another admin saved this setting first; reload it and save again"


class AlertSetupError(Exception):
    def __init__(self, code: str, http_status: int = 422) -> None:
        super().__init__(code)
        self.code, self.http_status = code, http_status


def config(repo) -> dict:
    """The saved setup over the defaults; the webhook stays sealed."""
    saved = (repo.get_setting(KEY) or {}).get("value")
    saved = saved if isinstance(saved, dict) else {}
    return {**DEFAULTS, **{key: saved[key] for key in DEFAULTS if key in saved}}


def public(repo) -> dict:
    """The setup as an Admin sees it: whether a webhook is saved, never its address; the bot's channels to choose
    from and the console's address, as the contact setup holds them."""
    value, ready = config(repo), contact.channels(repo)
    return {"enabled": value["enabled"], "transport": value["transport"], "webhook_saved": bool(value["webhook"]),
            "channel": value["channel"], "channels": ready["allowed_channels"], "bot_ready": ready["slack"],
            **{key: value[key] for key in ("min_severity", "detail", "language", "events", "enabled_at")},
            "console_url": ready["console_url"]}


def webhook_url(value) -> str:
    """An Incoming Webhook address, checked as the SIEM Slack sink checks one: https to hooks.slack.com or
    hooks.slack-gov.com on port 443, /services/<team>/<hook>/<token>, no user info, query or fragment."""
    try:
        if (not isinstance(value, str) or not value or len(value) > 512
                or any(not 33 <= ord(c) <= 126 for c in value) or any(c in value for c in "\\?#<>|\"")):
            raise ValueError
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or parsed.hostname not in _WEBHOOK_HOSTS
                or parsed.username is not None or parsed.password is not None
                or parsed.port not in (None, 443) or not _WEBHOOK_PATH.fullmatch(parsed.path)):
            raise ValueError
    except (TypeError, ValueError):
        raise AlertSetupError("ALERTS_WEBHOOK_INVALID") from None
    return f"https://{parsed.hostname}{parsed.path}"


def opened_webhook(settings, value: dict) -> str:
    """The saved webhook address, opened for one send and checked again."""
    if not value.get("webhook"):
        raise AlertSetupError("ALERTS_NOT_CONFIGURED", 409)
    try:
        url = unseal(settings.sealing_keys, value["webhook"]).get("url")
    except Exception:  # noqa: BLE001 -- a value that cannot be opened, or a key store (Vault, KMS) that did not answer
        raise AlertSetupError("ALERTS_SECRET_UNAVAILABLE", 503) from None
    return webhook_url(url)


def save(repo, settings, body, actor: str, *, now=None) -> None:
    """Apply an Admin's change to the fields sent, audited in the transaction that stores it. A blank webhook keeps
    the saved one; the console's address goes to the contact setup; turning alerts on stamps ``enabled_at``."""
    from cremore.installation_settings import locked_installation_settings, setting_changed

    if not isinstance(body, dict) or set(body) - _FIELDS:
        raise AlertSetupError("ALERTS_SETTINGS_INVALID")
    before = repo.get_setting(KEY)
    current, ready = config(repo), contact.channels(repo)
    value = dict(current)
    for field, choices in _CHOICES.items():
        if field in body:
            if body[field] not in choices:
                raise AlertSetupError(f"ALERTS_{field.upper()}_INVALID")
            value[field] = body[field]
    if "enabled" in body:
        if not isinstance(body["enabled"], bool):
            raise AlertSetupError("ALERTS_ENABLED_INVALID")
        value["enabled"] = body["enabled"]
    if "events" in body:
        events = body["events"]
        if not isinstance(events, list) or not events or any(item not in EVENTS for item in events):
            raise AlertSetupError("ALERTS_EVENTS_INVALID")
        value["events"] = [item for item in EVENTS if item in events]
    if "channel" in body:
        channel = body["channel"].strip() if isinstance(body["channel"], str) else body["channel"]
        if channel not in (None, "") and channel not in ready["allowed_channels"]:
            raise AlertSetupError("ALERTS_CHANNEL_NOT_ALLOWED")
        value["channel"] = channel or None
    changes = {field: value[field] for field in _SHOWN if value[field] != current[field]}
    if body.get("webhook_url") not in (None, ""):
        url = webhook_url(body["webhook_url"].strip() if isinstance(body["webhook_url"], str) else body["webhook_url"])
        try:
            value["webhook"] = seal_fields(settings.sealing_keys, {"url": url})
        except Exception:  # noqa: BLE001 -- the key store (Vault, KMS) did not answer: retry later, never a 500
            raise AlertSetupError("ALERTS_SECRET_UNAVAILABLE", 503) from None
        changes["webhook_url"] = "replaced"
    console = ready["console_url"]
    if "console_url" in body:
        try:
            console = contact.console_url(body["console_url"])
        except contact.ContactError as exc:
            raise AlertSetupError(exc.code) from None
        if console != ready["console_url"]:
            changes["console_url"] = console or ""
    if value["enabled"]:
        if value["transport"] == "webhook" and not value["webhook"]:
            raise AlertSetupError("ALERTS_WEBHOOK_REQUIRED")
        if value["transport"] == "bot" and not ready["slack"]:
            raise AlertSetupError("ALERTS_BOT_NOT_SET_UP", 409)
        if value["transport"] == "bot" and value["channel"] not in ready["allowed_channels"]:
            raise AlertSetupError("ALERTS_CHANNEL_REQUIRED")
        if not current["enabled"]:
            value["enabled_at"] = (now or _dt.datetime.now(_dt.UTC)).isoformat()
            value["first_enabled_at"] = current["first_enabled_at"] or value["enabled_at"]
    elif current["enabled"]:
        value["disabled_at"] = (now or _dt.datetime.now(_dt.UTC)).isoformat()
    if not changes:
        return
    with locked_installation_settings(repo) as bound:
        # Checked against what was read above: another admin's save of this setup, or of the contact setup it relies
        # on (the bot, its channels, the console's address), overtook this one.
        if (bound.get_setting(KEY) or {}).get("value") != (before or {}).get("value") or contact.channels(bound) != ready:
            raise AlertSetupError(_CHANGED_MEANWHILE, 409)
        if value != current:
            bound.put_setting(KEY, value, actor)
        if "console_url" in changes:
            contact.set_console_url(bound, console, actor)
        setting_changed(bound, actor, KEY, changes, plain=("transport", "min_severity", "detail", "language"))
