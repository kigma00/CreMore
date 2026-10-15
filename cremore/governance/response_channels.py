"""The Slack channels an Admin approved for exposure-response notices (cremore.governance.response).

A notice to a team's channel mentions the person asked and carries the same masked summary and CreMore link as their
DM; progress replies go to its thread (cremore.governance.response_threads). Every channel is read with
``conversations.info`` when it is saved and again before each post: an archived channel, one shared with another
company (``is_ext_shared`` or ``is_pending_ext_shared``) and a public channel without the Admin's per-channel
``allow_public`` are refused. Channels are never matched to teams by name. Saves are versioned and audited with the
change (RESPONSE_CHANNELS_SAVED: the channel ids and which allow public posts), never with the bot token.
"""

from __future__ import annotations

import datetime as dt
import re
import time
import uuid

from cremore.domain.models import FindingEvent
from cremore.domain.text import unsafe_text
from cremore.governance import contact
from cremore.governance.response import ResponseError

KEY = "response_channels"
TARGET = uuid.uuid5(uuid.NAMESPACE_URL, "cremore:response_channels")
MAX_CHANNELS = 50
CANDIDATE_PAGES, CANDIDATE_LIMIT, CANDIDATE_SECONDS = 10, 200, 10.0
_ID = re.compile(r"[CG][A-Z0-9]{8,12}")


def stored(repo) -> dict:
    value = (repo.get_setting(KEY) or {}).get("value")
    return value if isinstance(value, dict) else {"version": 0, "channels": []}


def approved(repo) -> dict[str, dict]:
    """channel id -> the saved entry ({channel_id, name, is_private, allow_public, checked_at})."""
    return {entry["channel_id"]: entry for entry in stored(repo).get("channels") or []}


def public(repo) -> dict:
    """The Admin's view: every approved channel with its flags, and the version a save must name."""
    value = stored(repo)
    return {"version": value.get("version", 0), "channels": list(value.get("channels") or [])}


def listed(repo) -> dict:
    """The analyst's view (the request form and the routing rule editor): which channels, no Admin details."""
    return {"channels": [{key: entry.get(key) for key in ("channel_id", "name", "is_private")}
                         for entry in stored(repo).get("channels") or []]}


def _name(value) -> str:
    return value if isinstance(value, str) and len(value) <= 80 and not unsafe_text(value) else ""


def info(call, channel_id: str, *, status: int = 422) -> dict:
    """What ``conversations.info`` says of one channel; ResponseError when Slack does not show it to the bot."""
    try:
        payload = call("conversations.info", data={"channel": channel_id})
    except contact.ContactError as exc:
        if exc.code == "SLACK_CHANNEL_NOT_FOUND":
            raise ResponseError("RESPONSE_CHANNEL_NOT_FOUND", status) from None
        raise ResponseError(exc.code, exc.http_status) from None
    found = payload.get("channel")
    if not isinstance(found, dict) or found.get("id") != channel_id:
        raise ResponseError("RESPONSE_CHANNEL_NOT_FOUND", status)
    return {"channel_id": channel_id, "name": _name(found.get("name")), "is_private": found.get("is_private") is True,
            "is_archived": found.get("is_archived") is True,
            "external": found.get("is_ext_shared") is True or found.get("is_pending_ext_shared") is True}


def refusal(found: dict, allow_public: bool) -> str | None:
    """Why no notice may go to the channel as Slack describes it now, or None."""
    if found["is_archived"]:
        return "RESPONSE_CHANNEL_ARCHIVED"
    if found["external"]:
        return "RESPONSE_CHANNEL_EXTERNAL"  # shared with another company: never, whatever the Admin allowed
    if not found["is_private"] and allow_public is not True:
        return "RESPONSE_CHANNEL_PUBLIC_NOT_ALLOWED"
    return None


def check(call, channel_id: str, allow_public: bool, *, status: int = 422) -> dict:
    """The channel as Slack describes it now, when a notice may go there; ResponseError with the refusal otherwise."""
    found = info(call, channel_id, status=status)
    code = refusal(found, allow_public)
    if code:
        raise ResponseError(code, status)
    return found


def save(repo, settings, body, actor: str, *, http_client_factory=None, now=None) -> dict:
    """Replace the approved list, each channel read again from Slack, audited with it. ``body``:
    ``{expected_version, channels: [{channel_id, allow_public}]}``."""
    from cremore.installation_settings import locked_installation_settings

    now = now or dt.datetime.now(dt.UTC)
    expected, entries = body["expected_version"], body["channels"]
    ids = [entry["channel_id"] for entry in entries]
    if len(entries) > MAX_CHANNELS or len(set(ids)) != len(ids) or not all(_ID.fullmatch(item) for item in ids):
        raise ResponseError("RESPONSE_CHANNELS_INVALID", 422)
    if stored(repo).get("version", 0) != expected:
        raise ResponseError("RESPONSE_CHANNELS_CHANGED")
    channels = []
    if entries:
        try:
            with contact.slack_session(repo, settings, http_client_factory=http_client_factory) as call:
                for entry in entries:
                    found = check(call, entry["channel_id"], entry["allow_public"])
                    channels.append({"channel_id": found["channel_id"], "name": found["name"],
                                     "is_private": found["is_private"],
                                     "allow_public": entry["allow_public"] is True and not found["is_private"],
                                     "checked_at": now.isoformat()})
        except contact.ContactError as exc:
            raise ResponseError(exc.code, exc.http_status) from None
    with locked_installation_settings(repo) as bound:
        if stored(bound).get("version", 0) != expected:
            raise ResponseError("RESPONSE_CHANNELS_CHANGED")
        bound.put_setting(KEY, {"version": expected + 1, "channels": channels}, actor)
        shown = ",".join(entry["channel_id"] for entry in channels) or "-"
        public_ids = ",".join(entry["channel_id"] for entry in channels if entry["allow_public"]) or "-"
        bound.record_finding_event(FindingEvent(target_type="response_channels", target_id=TARGET, actor=actor,
                                                event_type="RESPONSE_CHANNELS_SAVED",
                                                note=f"version={expected + 1} channels={shown} allow_public={public_ids}"))
    return public(repo)


def candidates(repo, settings, *, http_client_factory=None, clock=time.monotonic) -> dict:
    """The channels the bot is in, for the Admin to pick from: a bounded read (CANDIDATE_PAGES pages within
    CANDIDATE_SECONDS); ``truncated`` when Slack had more."""
    found, cursor, truncated = [], "", False
    deadline = clock() + CANDIDATE_SECONDS
    try:
        with contact.slack_session(repo, settings, http_client_factory=http_client_factory) as call:
            for page in range(CANDIDATE_PAGES):
                if page and clock() > deadline:
                    truncated = True
                    break
                payload = call("conversations.list", data={"types": "public_channel,private_channel",
                                                           "exclude_archived": "true", "limit": CANDIDATE_LIMIT,
                                                           **({"cursor": cursor} if cursor else {})})
                for item in payload.get("channels") or []:
                    if (isinstance(item, dict) and isinstance(item.get("id"), str) and _ID.fullmatch(item["id"])
                            and item.get("is_member") is True):
                        found.append({"channel_id": item["id"], "name": _name(item.get("name")),
                                      "is_private": item.get("is_private") is True,
                                      "is_ext_shared": item.get("is_ext_shared") is True
                                      or item.get("is_pending_ext_shared") is True})
                meta = payload.get("response_metadata")
                cursor = meta.get("next_cursor") if isinstance(meta, dict) else ""
                if not isinstance(cursor, str) or not cursor:
                    break
            else:
                truncated = True  # pages left unread
    except contact.ContactError as exc:
        raise ResponseError(exc.code, exc.http_status) from None
    return {"channels": found, "truncated": truncated}
