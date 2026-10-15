"""Slack messages for new detections, in Korean or English, standard or minimal (cremore/alerts/delivery.py).

A message names what a security team acts on: severity, credential type and issuer, verification state, where it was
found (content source, connection, resource, location and line), when it was first seen, what started the scan (for a
change event, whether a change feed, the customer's queue or a webhook reported it), how many other places still hold
it, in a standard message the addresses an AWS key was last used from (the usage lookup the credential already has),
and a link into the console. Nothing secret is passed in: no value, masked hint,
redacted line, fingerprint or provider answer. The names that are passed in (connection, resource, location) are
screened like provider facts (cremore.detection.safe_text), and one shaped like a credential is not shown; a URL
location also loses its query, fragment and user info. Every value is plain text (``plain_text`` blocks; &, < and >
escaped as Slack asks of every text object, which it decodes for display; control and bidi characters dropped;
lengths bounded), so a name can neither format, mention nor link.
"""

from __future__ import annotations

import datetime as _dt
import re
from functools import lru_cache
from urllib.parse import urlsplit

from cremore.detection.safe_text import safe_fact_text
from cremore.domain.text import unsafe_text

KST = _dt.timezone(_dt.timedelta(hours=9), "KST")
HEADER_MAX, TEXT_MAX = 150, 3000  # Slack's limits: a header's text, and a section's (and the fallback) text
SOURCES_SHOWN = 3  # addresses a standard alert names; the rest are counted
DIGEST_BUDGET = 6000  # characters of a digest's item text, well under Slack's limits for one message

_TITLES = {"finding.created": ("새 자격증명 노출", "New credential exposure"),
           "finding.location_added": ("새 위치에서 발견", "Found at a new location"),
           "finding.reappeared": ("제거 후 다시 노출", "Exposure reappeared"),
           "finding.severity_raised": ("심각도 상승", "Severity raised")}
_SEVERITY = {"CRITICAL": ("심각", "Critical"), "HIGH": ("높음", "High"), "MEDIUM": ("보통", "Medium"),
             "LOW": ("낮음", "Low"), "INFO": ("정보", "Info"), "NONE": ("없음", "None")}
_STATUS = {"Active": ("활성 확인", "Active"), "Inactive": ("비활성", "Inactive"), "Revoked": ("폐기 확인", "Revoked"),
           "Expired": ("만료됨", "Expired")}
# What started the scan, in the console's words (web/console/views/logs.tsx).
_TRIGGERS = {"MANUAL": ("직접 실행", "Manual"), "SCHEDULE": ("예약", "Scheduled"), "EVENT": ("변경 알림", "Change event"),
             "RESCAN": ("다시 검사", "Rescan"), "POLICY_SWEEP": ("룰 변경 재검사", "Rule change sweep"),
             "RESUME": ("이어서", "Resumed")}
# Where a change event came from, as its run recorded it (cremore.scanning.triggers.event_origin).
_ORIGINS = {"feed": ("피드", "feed"), "queue": ("큐", "queue"), "webhook": ("웹훅", "webhook")}


def render(items: list[dict], *, detail: str, language: str, buttons: bool = True) -> dict:
    """One message: a single alert in full, or a digest of several (delivery.py says which). Without ``buttons`` every
    console link is text only."""
    say = _say(language)
    return _single(items[0], say, detail, buttons) if len(items) == 1 else _digest(items, say, detail, buttons)


def trial_message(console_url: str | None, *, language: str, buttons: bool = True) -> dict:
    """What an Admin's test sends: where alerts will arrive, and the console link they will carry (as text only
    without ``buttons``)."""
    say = _say(language)
    title = say("CreMore Slack 탐지 알림 시험", "CreMore Slack detection alert test")
    lines = [say("새 탐지 알림이 이 채널로 옵니다. 알림에 비밀값은 들어가지 않습니다.",
                 "New detection alerts arrive in this channel. An alert never carries a secret value.")]
    if console_url:
        lines.append(f"{say('콘솔', 'Console')}: {_clean(console_url, 300)}")
    blocks = [{"type": "header", "text": _plain(title)}, {"type": "section", "text": _plain("\n".join(lines))}]
    if console_url and buttons:
        blocks.append({"type": "actions", "elements": [_button(say("콘솔 열기", "Open the console"), console_url + "/",
                                                                "open_console")]})
    return _message(title, blocks)


def _single(item, say, detail, buttons) -> dict:
    title = _title(item, say)
    lines = _lines(item, say, detail)
    link = item.get("link")
    if link:
        lines.append(f"{say('콘솔', 'Console')}: {_clean(link, 600)}")
    blocks = [{"type": "header", "text": _plain(_fit(title, HEADER_MAX))},
              {"type": "section", "text": _plain(_fit("\n".join(lines), TEXT_MAX))}]
    if link and buttons:
        blocks.append({"type": "actions", "elements": [_button(say("콘솔에서 열기", "Open in console"), link, "open_finding")]})
    ids = f"Credential ID {_clean(item['credential_id'], 40)} · {say('이벤트', 'Event')} {_clean(item['event_id'], 40)}"
    blocks.append({"type": "context", "elements": [_plain(ids)]})
    return _message(f"{title} · {lines[0]}", blocks)


def _digest(items, say, detail, buttons) -> dict:
    title = say(f"CreMore 새 탐지 {len(items)}건", f"CreMore: {len(items)} new detections")
    blocks, used = [{"type": "header", "text": _plain(title)}], 0
    for number, item in enumerate(items):
        link = item.get("link")
        tail = [f"{say('콘솔', 'Console')}: {_clean(link, 600)}" if link else f"Credential ID {_clean(item['credential_id'], 40)}",
                f"{say('이벤트', 'Event')} {_clean(item['event_id'], 40)}"]
        text = "\n".join([_title(item, say), *_lines(item, say, detail), *tail])
        if used + len(text) > DIGEST_BUDGET:  # past the budget, the rest go in the short form
            text = "\n".join([_title(item, say), *_lines(item, say, "minimal"), *tail])
        text = _fit(text, TEXT_MAX)
        used += len(text)
        block = {"type": "section", "text": _plain(text)}
        if link and buttons:
            block["accessory"] = _button(say("열기", "Open"), link, f"open_finding_{number}")
        blocks.append(block)
    return _message(title, blocks)


def _lines(item, say, detail) -> list[str]:
    type_name, source = _clean(_type(item, say), 100), _clean(_source(item.get("source_type")), 60)
    if detail == "minimal":
        return [f"{type_name} · {source}"]
    issuer = item.get("provider")
    lines = [f"{say('유형', 'Type')}: {type_name}" + (f" · {say('발급', 'Issuer')}: {_clean(issuer, 60)}" if issuer else ""),
             f"{say('검증', 'Verification')}: {say(*_STATUS.get(item.get('status'), ('미확인', 'Not verified')))}",
             f"{say('발견 위치', 'Found in')}: {source}"
             + (f" · {_name(item['connection'], 100, say)}" if item.get("connection") else "")]
    if item.get("previous_severity"):
        lines.insert(0, f"{say('심각도', 'Severity')}: {_severity(item['previous_severity'], say)} → "
                        f"{_severity(item['severity'], say)}")
    resource, location = item.get("resource"), item.get("location")
    if resource and resource != location:
        lines.append(f"{say('리소스', 'Resource')}: {_name(resource, 200, say)}")
    line = item.get("line") if type(item.get("line")) is int and item["line"] > 0 else None
    if location or line:
        place = _name(_place(location), 500, say) if location else ""
        number = say(f"{line}행", f"line {line}") if line else ""
        lines.append(f"{say('위치', 'Location')}: " + (f"{place} ({number})" if place and number else place or number))
    seen = item.get("first_seen")
    if seen is not None:
        seen = seen.replace(tzinfo=_dt.UTC) if seen.tzinfo is None else seen
        lines.append(f"{say('처음 발견', 'First seen')}: " + say(seen.astimezone(KST).strftime("%Y-%m-%d %H:%M KST"),
                                                                seen.astimezone(_dt.UTC).strftime("%Y-%m-%d %H:%M UTC")))
    if item.get("trigger") in _TRIGGERS:
        started = say(*_TRIGGERS[item["trigger"]])
        origin = _ORIGINS.get(item.get("origin")) if item["trigger"] == "EVENT" else None
        if origin:
            started = say(f"{started}({origin[0]})", f"{started} ({origin[1]})")
        lines.append(f"{say('검사 시작', 'Scan started by')}: {started}")
    if shown := [_source_address(entry, say) for entry in (item.get("sources") or [])[:SOURCES_SHOWN]]:
        # The total counts every distinct address the lookup saw; sources_more: past what it could count, a lower bound.
        # A lower bound with none known past those shown says so without a number ("+0 or more" reads as noise).
        rest, more = max((item.get("sources_total") or 0) - len(shown), 0), bool(item.get("sources_more"))
        tail = (say(f" +{rest:,}" + (" 이상" if more else ""), f" +{rest:,}" + ("+" if more else "")) if rest
                else say(", 더 있을 수 있음", ", possibly more") if more else "")
        lines.append(f"{say('최근 사용 출처', 'Recently used from')}: " + ", ".join(shown) + tail)
    others, more = item.get("others") or 0, bool(item.get("others_more"))  # more: counted from the first rows only
    lines.append(f"{say('다른 열린 위치', 'Other open locations')}: "
                 + say(f"{others:,}곳" + (" 이상" if more else ""), f"{others:,}" + ("+" if more else "")))
    return lines


def _title(item, say) -> str:
    return f"[{_severity(item['severity'], say)}] {say(*_TITLES[item['kind']])}"


def _source_address(entry, say) -> str:
    """An address a lookup saw the key used from, with when; CloudTrail's AWS service hosts are not IP addresses."""
    address = _clean(entry.get("address"), 100)
    text = say(f"AWS 서비스 {address}", f"AWS service {address}") if entry.get("kind") == "AWS_INTERNAL" else address
    try:
        at = _dt.datetime.fromisoformat(entry["last_seen_at"])
    except (KeyError, TypeError, ValueError):
        return text
    at = at.replace(tzinfo=_dt.UTC) if at.tzinfo is None else at
    return f"{text} ({say(at.astimezone(KST).strftime('%Y-%m-%d %H:%M KST'), at.astimezone(_dt.UTC).strftime('%Y-%m-%d %H:%M UTC'))})"


def _severity(value, say) -> str:
    return say(*_SEVERITY.get(value, ("미확인", "Unknown")))


@lru_cache(maxsize=1)
def _type_names() -> dict:
    # The detector catalog's name for each (issuer, type); a pair its detectors name differently has none.
    from cremore.detection.catalog import builtin_definitions

    names: dict = {}
    for definition in builtin_definitions():
        key, name = (definition.catalog.provider, definition.catalog.credential_type), definition.catalog.name
        names[key] = name if names.get(key, name) == name else None
    return names


def _type(item, say) -> str:
    provider, code = item.get("provider"), str(item.get("credential_type") or "")
    if provider == "custom":
        return say("사용자 규칙 일치", "Custom rule match")
    return (_type_names().get((provider, code)) or " ".join(word.capitalize() for word in code.split("_") if word)
            or say("자격증명", "Credential"))


def _source(source_type) -> str:
    from cremore.sources.registry import BY_SOURCE

    module = BY_SOURCE.get(source_type)
    return module.CAPABILITY["name"] if module else str(source_type or "UNKNOWN")


def _place(value: str) -> str:
    """A location as shown: a URL keeps its scheme, host, port and path only."""
    if "://" not in value:
        return value
    try:
        parts = urlsplit(value)
        host, port = parts.hostname or "", f":{parts.port}" if parts.port is not None else ""
    except ValueError:  # an address urlsplit refuses (a port out of range): cut what a token can ride in by hand
        return re.sub(r"^([A-Za-z][A-Za-z0-9+.-]*://)[^/]*@", r"\1", value.split("#", 1)[0].split("?", 1)[0])
    return f"{parts.scheme}://{f'[{host}]' if ':' in host else host}{port}{parts.path}"


def _name(value, limit: int, say) -> str:
    """A name from the scanned source, shown only when it is not shaped like a credential (and short enough to tell)."""
    text = " ".join("".join(" " if unsafe_text(char) else char for char in str(value)).split())
    if safe_fact_text(text) is None:
        return say("(표시하지 않음 · 콘솔에서 확인)", "(not shown · see the console)")
    return _clean(text, limit)


def _clean(value, limit: int) -> str:
    """One plain line: controls and bidi characters dropped, bounded, & < > escaped."""
    text = " ".join("".join(" " if unsafe_text(char) else char for char in str(value)).split())
    text = text if len(text) <= limit else text[:limit - 1] + "…"
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _fit(text: str, limit: int) -> str:
    """Escaped text cut to a Slack limit without splitting an entity."""
    if len(text) <= limit:
        return text
    cut = text[:limit - 1]
    amp = cut.rfind("&")
    return (cut[:amp] if amp != -1 and ";" not in cut[amp:] else cut) + "…"


def _say(language):
    return (lambda ko, en: ko) if language == "ko" else (lambda ko, en: en)


def _plain(text: str) -> dict:
    return {"type": "plain_text", "text": text, "emoji": False}


def _button(label: str, url: str, action: str) -> dict:
    return {"type": "button", "text": _plain(label), "url": url, "action_id": action}


def _message(text: str, blocks: list[dict]) -> dict:
    return {"text": _fit(text, TEXT_MAX), "blocks": blocks, "mrkdwn": False, "parse": "none", "link_names": False,
            "unfurl_links": False, "unfurl_media": False}
