"""Dashboard settings for the scan triggers: schedules, change feeds and the customer's own queues.

A schedule is already an Admin's decision: they set ``schedule_minutes`` on an
approved scope profile. Until now a *second* decision in the environment decided
whether that schedule ever ran, so the dashboard could show a schedule the
installation silently ignored. Queue consumption had the same shape plus the
profile it binds to, which meant pointing it at a different scope profile took a
redeploy.

The environment now ALLOWS each trigger (the default) or hard-locks it off, and
an Admin sets the rest from the dashboard; each ``SCAN_*`` value still pins its
own field for an installation that wants it fixed in configuration. Schedules and
change feeds run until an Admin switches them off in this version: without anyone
signing in, every approved scope is scanned in full daily by default, at the
installation's start minute, and its changes are read as they happen. A queue stays
off until it is switched on and bound.

A trigger is only *effective* when everything it needs is present: for a queue,
a bound approved profile, an explicit address, and the acknowledgement that the
queue is CreMore's own. A half-configured trigger reads as off rather than failing at
the moment a message arrives.
"""

from __future__ import annotations

import logging
import re
import uuid as _uuid
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from cremore.db.migrations import SCHEDULE_ORIGIN_KEY

logger = logging.getLogger(__name__)
KEY = "scan_triggers"
# When this version's database was migrated ({"at": ISO time}, cremore.db.migrations.schedule_origin), and the detection
# policy digest in force after it ("detection_digest", "rules_changed"; record_upgrade_digest). Never written by an Admin.
ORIGIN_KEY = SCHEDULE_ORIGIN_KEY
# Workers start after the migration, so an origin is normally in the past. One later than a reader's clock by more than
# this is not one the migration recorded, and is read as none rather than skipping full scans until then.
ORIGIN_SKEW = timedelta(hours=24)

_QUEUE_HOST = re.compile(r"sqs\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?")
_QUEUE_PATH = re.compile(r"/[0-9]{12}/[A-Za-z0-9_-]+(?:\.fifo)?")
# projects/{project}/subscriptions/{name}: Google's own naming rules for both parts.
_SUBSCRIPTION = re.compile(r"projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/subscriptions/(?!goog)[A-Za-z][A-Za-z0-9._~+%-]{2,254}")
_BUS_NAMESPACE = re.compile(r"[A-Za-z][A-Za-z0-9-]{4,48}[A-Za-z0-9]\.servicebus\.windows\.net")
_BUS_ENTITY = re.compile(r"/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,258}[A-Za-z0-9])?"
                         r"(?:/subscriptions/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,48}[A-Za-z0-9])?)?")

# Each queue CreMore may consume, and the field holding its address. A queue is
# the customer's own and only read: a message is acknowledged after its work is durable.
QUEUES = {"sqs": "queue_url", "pubsub": "subscription", "servicebus": "queue"}
FIELDS = ("schedules_enabled", "full_scan_default_minutes", "full_scan_start_minute",
          *(f"{kind}_{name}" for kind, address in QUEUES.items()
            for name in ("enabled", "profile_id", address, "dedicated_acknowledged")),
          "change_feeds_enabled", "change_feed_minutes")
# The switches that are on until an Admin saves them off. The previous version wrote every switch it had on any save,
# off unless switched on, so a record without the full-scan default (LEGACY_MARK) holds no Admin's choice for these.
ON_BY_DEFAULT = ("schedules_enabled", "change_feeds_enabled")
LEGACY_MARK = "full_scan_default_minutes"
# How often a scope without a full-scan cadence of its own (full_scan_minutes NULL) is scanned in full: off, or
# 24, 12, 8, 6, 4, 3, 2 or 1 times a day. Slots count from the start minute (UTC), 02:00 KST by default.
FULL_SCAN_CHOICES = (0, 60, 120, 180, 240, 360, 480, 720, 1440)
FULL_SCAN_DEFAULT = 1440
FULL_SCAN_START = 1020
# Providers whose repositories, spaces or pages a change feed polls (cremore.scanning.changes), and the minutes
# between looks when an Admin set none: Bitbucket's hourly API allowance is the smallest, so it is read less often.
CHANGE_FEED_PROVIDERS = ("github", "gitlab", "azure_devops", "bitbucket", "confluence", "notion")
FEED_DEFAULT_MINUTES = {"bitbucket": 15}  # every other provider: 5
# Which configuration value pins each field. A trigger's own ALLOW/lock is a
# separate property (``*_allowed``) because it overrides rather than pins.
PINS = {"sqs_profile_id": "scan_sqs_profile_id",
        "sqs_queue_url": "scan_sqs_queue_url",
        "sqs_dedicated_acknowledged": "scan_sqs_dedicated_acknowledged"}
ALLOWED_BY = {"schedules": "scan_schedules_allowed", "sqs": "scan_sqs_allowed",
              "pubsub": "scan_pubsub_allowed", "servicebus": "scan_servicebus_allowed",
              "change_feeds": "scan_change_feeds_allowed"}


class TriggerSettingError(ValueError):
    """A stable code the dashboard can localize, never a raw value."""


def profile_uuid(value) -> str:
    """The canonical form of a bound profile id, or "" when nothing is bound."""
    if not value:
        return ""
    try:
        return str(_uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        raise TriggerSettingError("TRIGGER_PROFILE_INVALID") from None


def queue_url(value) -> str:
    """An explicit AWS queue URL. CreMore never discovers a queue, so this is
    the whole of what it will consume: no credentials, query or non-443 port."""
    if not value:
        return ""
    try:
        parsed = urlsplit(str(value))
        port = parsed.port
    except ValueError:
        raise TriggerSettingError("TRIGGER_QUEUE_URL_INVALID") from None
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.query
            or parsed.fragment or port not in (None, 443)
            or not _QUEUE_HOST.fullmatch(parsed.hostname or "")
            or not _QUEUE_PATH.fullmatch(parsed.path)):
        raise TriggerSettingError("TRIGGER_QUEUE_URL_INVALID")
    return str(value)


def subscription(value) -> str:
    """A Pub/Sub subscription path, ``projects/{project}/subscriptions/{name}``."""
    if not value:
        return ""
    if not isinstance(value, str) or not _SUBSCRIPTION.fullmatch(value):
        raise TriggerSettingError("TRIGGER_SUBSCRIPTION_INVALID")
    return value


def bus_queue(value) -> str:
    """A Service Bus queue or topic subscription URL on the Azure public cloud:
    ``https://{namespace}.servicebus.windows.net/{queue}`` or ``.../{topic}/subscriptions/{name}``."""
    # ponytail: public cloud only; add the sovereign-cloud suffixes when a customer runs there.
    if not value:
        return ""
    try:
        parsed = urlsplit(str(value))
        port = parsed.port
    except ValueError:
        raise TriggerSettingError("TRIGGER_BUS_QUEUE_INVALID") from None
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.query
            or parsed.fragment or port not in (None, 443)
            or not _BUS_NAMESPACE.fullmatch(parsed.hostname or "")
            or not _BUS_ENTITY.fullmatch(parsed.path)):
        raise TriggerSettingError("TRIGGER_BUS_QUEUE_INVALID")
    return str(value)


_ADDRESSES = {"sqs_queue_url": queue_url, "pubsub_subscription": subscription, "servicebus_queue": bus_queue}


def feed_minutes(value) -> dict:
    """How often each provider's change feed is read: 1-1440 minutes; an absent provider uses its default."""
    if not isinstance(value, dict) or set(value) - set(CHANGE_FEED_PROVIDERS):
        raise TriggerSettingError("TRIGGER_CHANGE_FEED_MINUTES_INVALID")
    if any(type(minutes) is not int or not 1 <= minutes <= 1440 for minutes in value.values()):
        raise TriggerSettingError("TRIGGER_CHANGE_FEED_MINUTES_INVALID")
    return dict(value)


def full_scan_minutes(value) -> int:
    """The installation's full-scan cadence for scopes without their own: one of FULL_SCAN_CHOICES (0 is off)."""
    if type(value) is not int or value not in FULL_SCAN_CHOICES:
        raise TriggerSettingError("TRIGGER_FULL_SCAN_MINUTES_INVALID")
    return value


def start_minute(value) -> int:
    """The UTC minute of the day the full-scan slots count from: 0-1439."""
    if type(value) is not int or not 0 <= value < 1440:
        raise TriggerSettingError("TRIGGER_FULL_SCAN_START_INVALID")
    return value


_NUMBERS = {"full_scan_default_minutes": (full_scan_minutes, FULL_SCAN_DEFAULT),
            "full_scan_start_minute": (start_minute, FULL_SCAN_START)}


def normalize(body: dict) -> dict:
    """Validate an Admin's submission into the fields that may be stored."""
    unknown = set(body) - set(FIELDS)
    if unknown:
        raise TriggerSettingError(f"TRIGGER_FIELD_UNKNOWN: {sorted(unknown)}")
    out = {}
    for name in FIELDS:
        if name not in body:
            continue
        value = body[name]
        if name == "change_feed_minutes":
            out[name] = feed_minutes(value)
            continue
        if name in _NUMBERS:
            out[name] = _NUMBERS[name][0](value)
            continue
        if name.endswith(("_enabled", "_acknowledged")):
            if not isinstance(value, bool):
                raise TriggerSettingError(f"TRIGGER_FIELD_NOT_BOOLEAN: {name}")
            out[name] = value
        elif name.endswith("_profile_id"):
            out[name] = profile_uuid(value)
        else:
            out[name] = _ADDRESSES[name](value)
    return out


def stored(repo) -> dict:
    """The Admin's saved choices, with anything unusable read as unset.

    A stored value that no longer validates turns its trigger off rather than
    being honoured: the alternative is consuming an unrecognised queue URL. A
    switch never saved takes its default (ON_BY_DEFAULT), as does one the previous
    version saved (LEGACY_MARK absent); otherwise anything but True is off. A cadence
    that does not validate reads as its default.
    """
    record = repo.get_setting(KEY) or {}
    saved = record.get("value") or {}
    legacy = LEGACY_MARK not in saved
    out = {}
    for name in FIELDS:
        value = saved.get(name)
        if name == "change_feed_minutes":
            try:
                out[name] = feed_minutes(value if value is not None else {})
            except TriggerSettingError:
                out[name] = {}
        elif name in _NUMBERS:
            check, default = _NUMBERS[name]
            try:
                out[name] = check(value)
            except TriggerSettingError:
                out[name] = default
        elif name.endswith(("_enabled", "_acknowledged")):
            out[name] = True if name in ON_BY_DEFAULT and (value is None or legacy) else value is True
        else:
            try:
                out[name] = profile_uuid(value) if name.endswith("_profile_id") else _ADDRESSES[name](value)
            except TriggerSettingError:
                out[name] = ""
    return {**out, "updated_by": record.get("updated_by") or None,
            "updated_at": record.get("updated_at")}


def merged(repo, given: dict) -> dict:
    """The value to store: the saved fields with an Admin's changes applied.

    ``stored`` also reports who last changed it; that belongs to the record, not
    inside it, so it never round-trips back into the value.
    """
    saved = stored(repo)
    return {name: given.get(name, saved[name]) for name in FIELDS}


def allowed(settings, trigger: str) -> bool:
    return bool(getattr(settings, ALLOWED_BY[trigger], True))


def pinned(settings, name: str):
    """The configuration value for a field, or None when it pins nothing."""
    value = getattr(settings, PINS[name], None) if name in PINS else None
    if name.endswith("_acknowledged"):
        return True if value is True else None
    return value or None


def _field(settings, saved: dict, name: str):
    pin = pinned(settings, name)
    return saved[name] if pin is None else pin


def schedules_on(settings, repo, saved: dict | None = None) -> bool:
    saved = stored(repo) if saved is None else saved
    return allowed(settings, "schedules") and saved["schedules_enabled"]


def change_feeds_on(settings, repo, saved: dict | None = None) -> bool:
    saved = stored(repo) if saved is None else saved
    return allowed(settings, "change_feeds") and saved["change_feeds_enabled"]


def change_feed_minutes(settings, repo, saved: dict | None = None) -> dict:
    saved = stored(repo) if saved is None else saved
    return {provider: saved["change_feed_minutes"].get(provider, FEED_DEFAULT_MINUTES.get(provider, 5))
            for provider in CHANGE_FEED_PROVIDERS}


def full_scan(settings, repo, saved: dict | None = None) -> tuple[int, int]:
    """(minutes, start minute): the full-scan cadence of scopes without their own, and where its slots start."""
    saved = stored(repo) if saved is None else saved
    return saved["full_scan_default_minutes"], saved["full_scan_start_minute"]


def _origin_value(repo) -> dict:
    saved = repo.get_setting(ORIGIN_KEY)
    value = (saved or {}).get("value")
    return value if isinstance(value, dict) else {}


def schedule_origin(repo, now: datetime) -> datetime | None:
    """When this version's database was migrated, by the database's clock (cremore.db.migrations.schedule_origin). A scope
    approved before it does not run the full-scan slot already due then, and holds its policy sweeps until the next slot's
    full scan has ended (cremore.scanning.triggers), so an upgrade does not re-read everything at once. No record (a
    deleted row, a memory repository) is None: nothing is skipped or held, and nothing records it again. An unreadable
    value, or one later than ``now`` by more than ORIGIN_SKEW, is None too."""
    saved = repo.get_setting(ORIGIN_KEY)
    if saved is None:
        return None
    value = saved.get("value")
    at = value.get("at") if isinstance(value, dict) else None
    origin = None
    if isinstance(at, str) and len(at) <= 64:
        try:
            origin = datetime.fromisoformat(at)
        except ValueError:
            pass
    if origin is not None and origin.tzinfo is not None and origin <= now + ORIGIN_SKEW:
        return origin
    # Codes and times only, never the stored text. Without an origin nothing is skipped or held.
    ahead = origin is not None and origin.tzinfo is not None
    logger.warning("scan schedule origin ignored: %s (origin %s, now %s)",
                   "SCHEDULE_ORIGIN_AHEAD_OF_CLOCK" if ahead else "SCHEDULE_ORIGIN_UNREADABLE",
                   origin.isoformat() if ahead else "-", now.isoformat())
    return None


def record_upgrade_digest(repo, digest: str) -> None:
    """Add to the origin record the detection policy digest in force after the upgrade, once; and once a later digest
    differs (an Admin changed rules), latch ``rules_changed``, so a reader without the current digest (an event's
    enqueue) stops holding too. Under the record's row lock, so replicas agree on the first digest. No record, no write."""
    value = _origin_value(repo)
    if not value or (value.get("detection_digest") and (value["detection_digest"] == digest or value.get("rules_changed"))):
        return
    from cremore.db.settings_store import locked_settings

    with locked_settings(repo, setting_key=ORIGIN_KEY) as bound:
        value = _origin_value(bound)
        if not value:
            return
        if not value.get("detection_digest"):
            value["detection_digest"] = digest
        elif value["detection_digest"] != digest and not value.get("rules_changed"):
            value["rules_changed"] = True
        else:
            return
        bound.put_setting(ORIGIN_KEY, value, "schedule")


def rules_unchanged(repo, digest: str | None = None) -> bool:
    """Whether the detection policy is still the one in force after the upgrade: not recorded yet counts as unchanged;
    a latched change, or a current ``digest`` other than the recorded one, does not."""
    value = _origin_value(repo)
    recorded = value.get("detection_digest")
    if not recorded:
        return True
    return not value.get("rules_changed") and (digest is None or digest == recorded)


def queue_binding(settings, repo, kind: str, saved: dict | None = None) -> dict | None:
    """``{"profile_id", "queue"}`` when consuming the ``kind`` queue is fully configured.

    ``saved`` lets a caller that already read the record reuse it, so building
    the dashboard view is one settings read rather than one per queue.
    """
    saved = stored(repo) if saved is None else saved
    if not (allowed(settings, kind) and saved[f"{kind}_enabled"]
            and _field(settings, saved, f"{kind}_dedicated_acknowledged")):
        return None
    profile_id = _field(settings, saved, f"{kind}_profile_id")
    address = _field(settings, saved, f"{kind}_{QUEUES[kind]}")
    return {"profile_id": profile_id, "queue": address} if profile_id and address else None


def sqs_binding(settings, repo, saved: dict | None = None) -> dict | None:
    """``{"profile_id", "queue_url"}`` when SQS consumption is fully configured."""
    binding = queue_binding(settings, repo, "sqs", saved)
    return None if binding is None else {"profile_id": binding["profile_id"], "queue_url": binding["queue"]}


def event_profiles(settings, repo) -> set[str]:
    """The profile ids a queue or confirmed Notion subscription delivers to."""
    saved = stored(repo)
    from cremore.scanning.notion_webhooks import public

    return ({binding["profile_id"] for kind in QUEUES
             if (binding := queue_binding(settings, repo, kind, saved)) is not None}
            | {row["profile_id"] for row in public(repo) if row["state"] == "ACTIVE"})


def _queue_view(settings, repo, saved, kind):
    address = QUEUES[kind]
    profile_id = _field(settings, saved, f"{kind}_profile_id")
    value = _field(settings, saved, f"{kind}_{address}")
    acknowledged = bool(_field(settings, saved, f"{kind}_dedicated_acknowledged"))
    binding = queue_binding(settings, repo, kind, saved)
    prefix = kind.upper()
    return {
        "enabled": binding is not None,
        "switch": saved[f"{kind}_enabled"],
        "installation_allows": allowed(settings, kind),
        "profile_id": profile_id,
        "profile_id_locked": pinned(settings, f"{kind}_profile_id") is not None,
        address: value,
        f"{address}_locked": pinned(settings, f"{kind}_{address}") is not None,
        "dedicated_acknowledged": acknowledged,
        "dedicated_acknowledged_locked": pinned(settings, f"{kind}_dedicated_acknowledged") is not None,
        "blocked_by": None if binding or not saved[f"{kind}_enabled"]
        else (f"{prefix}_NOT_ACKNOWLEDGED" if not acknowledged
              else f"{prefix}_PROFILE_NOT_BOUND" if not profile_id
              else f"{prefix}_{address.upper()}_MISSING" if not value else None),
    }


def config(settings, repo) -> dict:
    """The dashboard view: what is live, what an Admin chose, what pins it."""
    saved = stored(repo)
    return {
        "schedules": {
            "enabled": schedules_on(settings, repo, saved),
            "switch": saved["schedules_enabled"],
            "installation_allows": allowed(settings, "schedules"),
            "full_scan_default_minutes": saved["full_scan_default_minutes"],
            "full_scan_start_minute": saved["full_scan_start_minute"],
        },
        "change_feeds": {
            "enabled": change_feeds_on(settings, repo, saved),
            "switch": saved["change_feeds_enabled"],
            "installation_allows": allowed(settings, "change_feeds"),
            "minutes": change_feed_minutes(settings, repo, saved),
        },
        **{kind: _queue_view(settings, repo, saved, kind) for kind in QUEUES},
        "updated_by": saved["updated_by"],
        "updated_at": saved["updated_at"],
    }
