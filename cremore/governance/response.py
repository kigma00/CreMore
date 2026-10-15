"""Exposure cleanup asked of its responder, separate from permission to execute a key action.

The request goes out as a Slack DM or mail carrying a CreMore link (company sign-in: the person answers in CreMore),
as a ticket in a plugin ticket system, or (local sign-in) is recorded as asked outside CreMore. An answer declares
the responder finished cleanup. Only a complete scan started after we received that declaration can verify removal.
Requests and every cycle remain in settings; transitions and their finding events share a transaction. A link token
is never stored: only its digest names the request (``response_link:<sha256>``), and ending a link deletes that.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import logging
import re
import secrets
import time
import uuid
from urllib.parse import urlsplit

from cremore.db.settings_store import locked_settings
from cremore.domain.models import FindingEvent
from cremore.domain.text import unsafe_text
from cremore.governance import contact, playbook
from cremore.remediation.owner_approval import reference_ok
from cremore.ticketing import setup
from cremore.ticketing.contract import ApprovalRequest, TicketError, safe_code

ACTOR = "system:response"
LOCK_KEY = "response:lock"
HEAD_PREFIX = "response:head:"
CYCLE_PREFIX = "response:cycle:"
LINK_PREFIX = "response_link:"
# A team-channel thread's progress cursor (cremore.governance.response_threads), written with the thread itself: every
# thread is found by it until all it is owed was replied, however many requests replaced its own meanwhile.
THREAD_PREFIX = "response:thread:"
HISTORY_LIMIT = 20
SEND_SECONDS = 300  # bounded adapter requests finish first; an expired reservation is never retried
LINK_LIFETIME = dt.timedelta(days=7)
LINK_PATH = "/response#"  # the token is the fragment: never in a server log or a Referer
CHANNELS = ("slack", "mail", "record", "ticket")
LINKED = ("slack", "mail")
ANSWERABLE = ("WAITING_OWNER", "REPORT_REQUIRED", "WAITING_VERIFICATION", "NEEDS_ACTION")
_CODE = re.compile(r"[A-Z0-9_]{1,64}")
_SYSTEM = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")  # secrets.token_urlsafe(32)
_FOREVER = dt.datetime(9999, 1, 1, tzinfo=dt.UTC)  # a cutoff after every write: deletes the one pointer row
_CURRENT_LOCATION = ("OPEN", "ACKNOWLEDGED", "MITIGATING")

logger = logging.getLogger(__name__)


class ResponseError(Exception):
    def __init__(self, code: str, http_status: int = 409):
        super().__init__(code)
        self.code, self.http_status = code, http_status


def _utc(value):
    return value.astimezone(dt.UTC) if value.tzinfo else value.replace(tzinfo=dt.UTC)


def _stamp(value):
    return _utc(value).isoformat()


def _when(value):
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        return _utc(dt.datetime.fromisoformat(value))
    except ValueError:
        return None


def _id(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise ResponseError("RESPONSE_ID_INVALID", 422) from None


def _row(repo, key):
    value = (repo.get_setting(key) or {}).get("value")
    return value if isinstance(value, dict) else {}


def _key(finding_id, request_id):
    return CYCLE_PREFIX + finding_id + ":" + request_id


def _locked(repo):
    # ponytail: one installation lock is adequate for human ticket traffic. If
    # that becomes a throughput limit, split by finding without reversing the
    # scan transaction's lock order; do not add a second queue meanwhile.
    if repo.get_setting(LOCK_KEY) is None:
        repo.claim_slot(LOCK_KEY, 0, ACTOR)
    return locked_settings(repo, setting_key=LOCK_KEY)


def _current(repo, finding_id):
    head = _row(repo, HEAD_PREFIX + finding_id)
    value = head.get("current") or {}
    return head, value


def _finding(repo, finding_id):
    found = repo.get_finding(uuid.UUID(finding_id))
    if found is None:
        raise ResponseError("FINDING_NOT_FOUND", 404)
    return found


def _channel(value):
    """How the cycle was asked; a cycle from before channels was asked in a ticket."""
    return value.get("channel") or "ticket"


def _now(now):
    return _utc(now or dt.datetime.now(dt.UTC))


def _link_expired(value, now):
    """A Slack/mail link takes an answer until its end; a ticket or a record has no link."""
    if _channel(value) not in LINKED:
        return False
    expires = _when((value.get("link") or {}).get("expires_at"))
    return expires is None or expires <= now


def _answerable(value, now):
    return (value.get("state") in ANSWERABLE and not value.get("recurred_at")
            and value.get("completion_version") == 2 and not _link_expired(value, now))


def _public_cycle(value, now):
    if not value:
        return None
    keys = ("request_id", "cycle", "state", "requested_by", "requested_at", "assigned_to", "answered_at",
            "received_at", "answered_by", "verified_at", "last_scan_at", "last_scan_id", "error_code",
            "previous_request_id", "released_at", "released_by", "release_basis", "send_deadline", "ticket_opened_at",
            "recipient", "team", "mapping_basis", "mapping_checked_at", "completion_version", "answer",
            "report", "verification", "removal", "completed_at", "evidence_hash", "report_count", "recurred_at")
    result = {key: value.get(key) for key in keys}
    channel = _channel(value)
    ticket = value.get("ticket") or {}
    result["channel"] = channel
    result["ticket"] = ({key: ticket.get(key) for key in ("system", "ticket", "approval", "approver", "url")}
                        if channel == "ticket" else None)
    # When the link stops taking an answer; never the token or its digest.
    result["link_expires_at"] = (value.get("link") or {}).get("expires_at")
    result["link_expired"] = _link_expired(value, now)
    # The team channel the request was posted in (its thread carries progress), and why a post there failed.
    thread = value.get("thread")
    result["thread"] = {"channel_id": thread.get("channel_id"), "name": thread.get("name")} if thread else None
    result["thread_error"] = value.get("thread_error")
    return result


def _summary(finding, head, value, now):
    state = value.get("state") or ("REVIEWING" if head.get("reviewed_at") or finding.workflow_status == "ACKNOWLEDGED" else
                                   "REMOVED" if finding.all_locations_removed else
                                   "ASSIGNED" if finding.assigned_to else "NEW")
    return {"state": state, "version": head.get("version", 0), "current": _public_cycle(value, now),
            "reviewed_at": head.get("reviewed_at"), "reviewed_by": head.get("reviewed_by")}


def summary(repo, finding_id, *, now=None):
    finding_id = _id(finding_id)
    return _summary(_finding(repo, finding_id), *_current(repo, finding_id), _now(now))


def summaries(repo, findings, *, now=None):
    """Compact records projection, without per-row history reads or network calls."""
    now = _now(now)
    findings = {str(value.id): value for value in findings}
    heads = {row["key"][len(HEAD_PREFIX):]: row["value"] for row in repo.list_settings(HEAD_PREFIX)
             if row["key"][len(HEAD_PREFIX):] in findings}
    out = {}
    for finding_id, finding in findings.items():
        head = heads.get(finding_id, {})
        out[finding_id] = _summary(finding, head, head.get("current") or {}, now)
    return out


def verification_credentials(repo):
    """Keep previously removed locations observable while a response needs verification."""
    credentials = set()
    for entry in repo.list_settings(HEAD_PREFIX):
        if ((entry.get("value") or {}).get("current") or {}).get("state") not in (
                "WAITING_VERIFICATION", "NEEDS_ACTION", "REPORT_REQUIRED", "COMPLETED"):
            continue
        finding = repo.get_finding(uuid.UUID(entry["key"][len(HEAD_PREFIX):]))
        if finding is not None:
            credentials.add(finding.credential_id)
    return credentials


def public(repo, finding_id, *, history_offset=0, now=None):
    """At most twenty cycles per page; older cycles are retained and pageable. ``can_request``: a new request may
    start now (the console's request button follows it)."""
    finding_id = _id(finding_id)
    now = _now(now)
    if type(history_offset) is not int or history_offset < 0:
        raise ResponseError("RESPONSE_OFFSET_INVALID", 422)
    finding = _finding(repo, finding_id)
    head, value = _current(repo, finding_id)
    result = _summary(finding, head, value, now)
    result["can_request"] = _start_refusal(repo, finding, value, now) is None
    rows = [row["value"] for row in repo.list_settings(CYCLE_PREFIX + finding_id + ":")]
    rows.sort(key=lambda row: row["cycle"], reverse=True)
    result.update(history=[_public_cycle(row, now) for row in rows[history_offset:history_offset + HISTORY_LIMIT]],
                  history_total=len(rows), history_offset=history_offset)
    return result


def _save(bound, finding_id, head, value, actor, event, before, note=""):
    bound.put_setting(_key(finding_id, value["request_id"]), value, actor)
    bound.put_setting(HEAD_PREFIX + finding_id, {**head, "version": head.get("version", 0) + 1,
                                                "request_id": value["request_id"], "cycle": value["cycle"],
                                                "current": value}, actor)
    bound.record_finding_event(FindingEvent(
        finding_id=uuid.UUID(finding_id), actor=actor, event_type=event,
        from_status=before, to_status=value["state"],
        note=f"request={value['request_id']} cycle={value['cycle']}" + (" " + note if note else "")))


def _version(head, expected_version):
    if type(expected_version) is not int or expected_version < 0:
        raise ResponseError("RESPONSE_VERSION_INVALID", 422)
    if head.get("version", 0) != expected_version:
        raise ResponseError("RESPONSE_CHANGED")


def _repeat(repo, finding_id, request_id, to, person_ref=None, team=None, channel="ticket", delivery=None):
    previous = _row(repo, _key(finding_id, request_id))
    previous_ref = (previous.get("recipient") or {}).get("person_ref")
    if previous and (previous.get("assigned_to") != to or previous_ref != person_ref or previous.get("team") != team
                     or _channel(previous) != channel
                     or (delivery is not None and previous.get("delivery") != delivery)):
        raise ResponseError("RESPONSE_REQUEST_REUSED")
    return bool(previous)


def _start_refusal(repo, finding, before, now):
    """Why a new request may not start now, or None. A request still waiting may be replaced only when its answer
    can no longer come: its link ended, or its ticket was asked on a ticket system no longer set up (a removed
    built-in one included), whose answers are never read again."""
    if not before:
        return "RESPONSE_ALREADY_REMOVED" if finding.all_locations_removed else None
    state = before.get("state")
    if state in ("NEEDS_ACTION", "REMOVED", "NOT_SENT"):
        return None
    if state in ("WAITING_OWNER", "REPORT_REQUIRED"):
        channel = _channel(before)
        if channel in LINKED and _link_expired(before, now):
            return None
        if channel == "ticket" and (before.get("ticket") or {}).get("binding") != setup.binding(repo):
            return None
    return "RESPONSE_ALREADY_PENDING"


def _startable(repo, finding_id, head, before, expected_version, now):
    _version(head, expected_version)
    finding = _finding(repo, finding_id)
    code = _start_refusal(repo, finding, before, now)
    if code:
        raise ResponseError(code)
    return finding


def _digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _unlinked(bound, value):
    """The cycle with its link ended: the token's pointer is deleted, so the link opens nothing any more."""
    link = value.get("link") or {}
    if not link.get("digest"):
        return value
    bound.delete_settings_before(LINK_PREFIX + link["digest"], _FOREVER)  # the digest is fixed-length: one row
    return {**value, "link": {**link, "digest": ""}}


def _finish_send(repo, finding_id, request_id, actor, *, refs=None, code=None, orphan=None):
    with _locked(repo) as bound:
        head, current = _current(bound, finding_id)
        value = _row(bound, _key(finding_id, request_id))
        if not value:
            return
        same = current.get("request_id") == request_id
        if refs is not None:
            opened_at = _stamp(dt.datetime.now(dt.UTC))
            value = {**value, "ticket": {**value["ticket"], **refs}, "ticket_opened_at": opened_at}
            note = " ".join(f"{key}={value['ticket'][key]}" for key in ("system", "ticket", "approval", "approver"))
            note += f" ticket_opened_at={opened_at}"
            if not same or value["state"] not in ("SENDING", "SEND_UNKNOWN"):
                # An admin may already have confirmed the old ambiguous request
                # absent. Preserve the late external result on that exact cycle.
                bound.put_setting(_key(finding_id, request_id), value, actor)
                if same:
                    bound.put_setting(HEAD_PREFIX + finding_id, {**head, "current": value,
                                                                 "version": head["version"] + 1}, actor)
                bound.record_finding_event(FindingEvent(finding_id=uuid.UUID(finding_id), actor=actor,
                    event_type="RESPONSE_LATE_TICKET_OPENED", note=f"request={request_id} {note}"))
                return
            before = value["state"]
            value.update(state="WAITING_OWNER", error_code=None)
            _save(bound, finding_id, head, value, actor, "RESPONSE_TICKET_OPENED", before, note)
        elif same and value["state"] == "SENDING":
            value = {**value, "state": "SEND_UNKNOWN", "error_code": code}
            if reference_ok(orphan):
                value["ticket"] = {**value["ticket"], "ticket": orphan}
            _save(bound, finding_id, head, value, actor, "RESPONSE_SEND_UNKNOWN", "SENDING", code)


def _finish_link(repo, finding_id, request_id, actor, *, code, delivered=(), thread=None, thread_error=None):
    """How the link's message went out: ``delivered`` names the targets it reached (``dm``, ``channel=<id>``); with
    none, the link is ended (its pointer deleted), ``code`` says why and the request may be asked again. ``code`` with a
    target reached is the DM's failure; a channel post's own failure is ``thread_error``. Only a cycle still sending
    moves."""
    with _locked(repo) as bound:
        head, current = _current(bound, finding_id)
        value = _row(bound, _key(finding_id, request_id))
        if not value or current.get("request_id") != request_id or value.get("state") != "SENDING":
            return  # the deadline reaper ended it meanwhile (and its link with it)
        code = code if code is None or isinstance(code, str) and _CODE.fullmatch(code) else "CONTACT_SEND_ERROR"
        if delivered:
            sent = {**value, "state": "WAITING_OWNER", "error_code": code, "thread": thread, "thread_error": thread_error}
            _save(bound, finding_id, head, sent, actor, "RESPONSE_LINK_SENT", "SENDING",
                  f"via={value['channel']} " + " ".join(delivered))
            if thread:
                bound.put_setting(THREAD_PREFIX + finding_id + ":" + request_id, {"posted": []}, actor)
            return
        code = code or "CONTACT_SEND_ERROR"
        _save(bound, finding_id, head, {**_unlinked(bound, value), "state": "NOT_SENT", "error_code": code,
                                        "thread_error": thread_error}, actor,
              "RESPONSE_NOT_SENT", "SENDING", f"via={value['channel']} code={code}")


def _facts(credential):
    """(issuing service, type, masked identifier) as a message or the link page names the credential: fixed codes
    and a hint that is visibly masked, never the value, a snippet or where it was found."""
    if credential is None:
        return "unknown", "UNKNOWN", "••••"
    provider = credential.provider if _SYSTEM.fullmatch(credential.provider or "") else "unknown"
    kind = credential.credential_type if _CODE.fullmatch(credential.credential_type or "") else "UNKNOWN"
    hint = credential.identifier_hint or ""
    hint = hint[:100] if not unsafe_text(hint) and any(mark in hint for mark in ("•", "…", "*", "...")) else "••••"
    return provider, kind, hint


def _playbook(repo, credential, locale):
    """The request's playbook sections: chosen by the issuing service, whether the credential already ended and the
    kinds of place it is still exposed at (never which places)."""
    if credential is None:
        return playbook.sections("unknown", None, (), "••••", locale)
    provider, _kind, hint = _facts(credential)
    kinds = [playbook.location_kind(exposure.source_type) for exposure in repo.exposures_for_credential(credential.id)
             if exposure.status in _CURRENT_LOCATION]
    return playbook.sections(provider, credential.credential_status, kinds, hint, locale)


def _message(finding_id, request_id, previous, locale, console_url=None, credential=None, steps=None):
    if locale == "ko":
        title = "[CreMore] 노출 자격증명 정리 요청"
        lines = ("이 티켓의 조치 결과 보고 폼에 수행 조치·구체적 사유·수행 시각과 교체 참조를 입력하고 회신해 주세요.",
                 "보고 폼을 지원하지 않는 티켓 시스템은 아래 CreMore 링크의 대응 담당자 탭에서 보고한 뒤 승인해 주세요.",
                 "단순 Okay만으로 완료되지 않습니다. 평문 제거와 기존 키 종료, 계속 사용하면 교체 키의 금고 보관을 검증합니다.",
                 "이 응답은 정리 완료 선언이며 키 폐기·비활성화 등의 실행 승인이 아닙니다.",
                 "CreMore가 응답을 받은 뒤 시작한 후속 검사로 제거 여부를 확인합니다.")
    else:
        title = "[CreMore] Exposed credential cleanup request"
        lines = ("Complete the action report in this ticket, including actions, explanation, time and replacement reference, then reply.",
                 "If this ticket system has no report form, report on the linked CreMore response tab, then approve the ticket.",
                 "Okay alone cannot complete a case. Removal, old-key retirement and replacement storage are independently checked.",
                 "This declares cleanup complete. It does not authorize revoking, disabling, or changing a key.",
                 "CreMore verifies removal with a scan started after receiving your response.")
    refs = (f"CreMore finding: {finding_id}", f"CreMore response request: {request_id}")
    if credential is not None:
        provider, kind, hint = _facts(credential)
        refs += (f"Provider / type: {provider} / {kind}", f"Masked identifier: {hint}")
        if console_url:
            refs += (f"{console_url}/?view=exposed&id=credential%3A{credential.id}&dtab=owner",)
    if previous:
        ticket = previous.get("ticket") or {}
        refs += (f"Previous request: {previous['request_id']} · ticket: {ticket.get('ticket') or '-'}",)
    guide = ("", *playbook.lines(steps, locale), "") if steps else ()
    return ApprovalRequest(title=title, lines=lines + guide + refs, report_required=True)


# The link's message is CreMore's own text: the person asking picks the channel, the recipient and the language only.
_LINK_WORDS = {
    "ko": {"subject": "[CreMore] 노출 자격증명 정리 요청",
           "intro": "보안팀이 노출된 아래 자격증명의 정리를 요청합니다.",
           "credential": "발급 서비스 / 종류", "hint": "식별자(일부 가림)",
           "todo": "할 일: 노출된 곳에서 평문을 지우고 기존 키를 폐기하거나 교체해 새 키를 금고에 보관한 뒤, 링크에서 "
                   "수행한 조치·구체적 사유·수행 시각을 보고해 주세요. 끝내지 못했거나 예외라면 그 사유를 보고해 주세요.",
           "until": "응답 기한(링크 만료)",
           "once": "회사 계정으로 로그인한 뒤 보고합니다. 이 보고는 정리 완료 선언이며 키 폐기·비활성화 등의 실행 승인이 "
                   "아닙니다. CreMore가 보고 뒤에 시작한 검사로 제거 여부를 확인합니다."},
    "en": {"subject": "[CreMore] Exposed credential cleanup request",
           "intro": "The security team asks you to clean up the exposed credential below.",
           "credential": "Issuing service / type", "hint": "Identifier (masked)",
           "todo": "What to do: remove the plaintext where it was exposed, revoke the old key or replace it and store "
                   "the new one in a vault, then report at the link what you did, why, and when. If you could not "
                   "finish, or this is an exception, report that and why.",
           "until": "Answer by (the link expires)",
           "once": "Sign in with your company account to report. A report declares cleanup; it does not authorize "
                   "revoking or disabling a key. CreMore verifies removal with a scan started after your report."},
}


def _link_lines(credential, link, expires, words):
    provider, kind, hint = _facts(credential)
    return [f"{words['credential']}: {provider} / {kind}",
            f"{words['hint']}: {hint}",
            words["todo"],
            f"{words['until']}: {expires.astimezone(dt.UTC):%Y-%m-%d %H:%M} UTC", "",
            link, "", words["once"]]


def _link_message(credential, link, expires, locale, steps=None):
    """(subject, text) of a Slack/mail request in ``locale``: which credential, what to do, by when, the link and the
    playbook. A team channel's notice (``_channel_message``) leaves the playbook to the link page."""
    words = _LINK_WORDS[locale if locale in _LINK_WORDS else "ko"]
    guide = ["", *playbook.lines(steps, locale)] if steps else []
    return words["subject"], "\n".join([words["intro"], "", *_link_lines(credential, link, expires, words), *guide])


_CHANNEL_WORDS = {
    "ko": {"ask": "님, 보안팀이 노출된 아래 자격증명의 정리를 요청합니다. 링크는 요청받은 분만 열 수 있습니다.",
           "thread": "진행 상황은 이 스레드에 기록됩니다.", "someone": "담당자"},
    "en": {"ask": ": the security team asks you to clean up the exposed credential below. Only you can open the link.",
           "thread": "Progress is posted in this thread.", "someone": "The person asked"},
}


def _channel_message(credential, link, expires, locale, user_id, name):
    """A team channel's notice in ``locale``: the person asked (``<@user_id>``, or their escaped name when Slack does
    not know their address), then the DM's masked summary and link. Slack shows it as text; only the mention is markup.
    A name that is an address (the directory's stand-in for a missing display name) is never shown: a generic word is."""
    lang = locale if locale in _LINK_WORDS else "ko"
    words, extra = _LINK_WORDS[lang], _CHANNEL_WORDS[lang]
    who = f"<@{user_id}>" if user_id else contact.slack_text(name if name and "@" not in name else extra["someone"])
    body = "\n".join(["", *_link_lines(credential, link, expires, words), "", extra["thread"]])
    return who + contact.slack_text(extra["ask"] + body)


def _url(value):
    if not isinstance(value, str) or len(value) > 500 or any(ord(c) < 33 or c in '\"\'<>\\' for c in value):
        return None
    try:
        parsed = urlsplit(value)
        return value if (parsed.scheme in ("https", "http") and parsed.hostname
                         and parsed.username is None and parsed.password is None) else None
    except ValueError:
        return None


def request_ticket(repo, settings, finding_id, actor, *, to=None, person_ref=None, team=None, locale="ko",
                   expected_version, request_id, now=None, http_client=None, channel="ticket", transports=None,
                   slack_channel=None, dm=True):
    """Ask the responder to clean up. ``channel``: ``ticket`` (the set-up plugin ticket system; use a constructed
    HTTP client, the caller closes it), ``slack``/``mail`` (company sign-in: a message with a CreMore link, sent with
    ``transports`` as contact.send takes them) or ``record`` (local sign-in: asked outside CreMore, nothing is sent).
    With a link channel, ``slack_channel`` (an Admin-approved channel, cremore.governance.response_channels) also
    gets a notice mentioning the person, whose thread carries progress; ``dm=False`` makes it the only delivery.
    Never retry an uncertain write."""
    finding_id, request_id = _id(finding_id), _id(request_id)
    now = _utc(now or dt.datetime.now(dt.UTC))
    from cremore.governance import response_channels, response_routing

    if channel not in CHANNELS:
        raise ResponseError("RESPONSE_CHANNEL_INVALID", 422)
    if slack_channel is not None and channel not in LINKED:
        raise ResponseError("RESPONSE_SLACK_CHANNEL_NOT_ALLOWED", 422)  # a ticket or a record has no link to post
    if dm is not True and slack_channel is None:
        raise ResponseError("RESPONSE_DELIVERY_REQUIRED", 422)
    oidc = getattr(settings, "auth_mode", "local") == "oidc"
    ready = approved = delivery = None
    if channel in LINKED:
        if not oidc:
            raise ResponseError("RESPONSE_LINK_NEEDS_SIGN_IN")  # no person to sign in: the operator records instead
        ready = contact.channels(repo)
        if (dm and not ready[channel]) or (slack_channel is not None and not ready["slack"]):
            raise ResponseError("CONTACT_CHANNEL_NOT_SET_UP")
        if not ready["console_url"]:
            raise ResponseError("RESPONSE_CONSOLE_URL_NOT_SET")
        if slack_channel is not None:
            approved = response_channels.approved(repo).get(slack_channel)
            if approved is None:
                raise ResponseError("RESPONSE_CHANNEL_NOT_APPROVED", 422)
        delivery = {"dm": dm is True, "slack_channel": slack_channel}
        if to is not None:
            try:
                given = contact.recipients(channel, [to], ready["allowed_domains"], ready["allowed_channels"])
            except contact.ContactError as exc:
                raise ResponseError(exc.code, exc.http_status) from None
            if "@" not in given[0]:
                raise ResponseError("RESPONSE_RECIPIENT_NOT_A_PERSON", 422)  # a channel's members are not the responder
    elif channel == "record" and oidc:
        raise ResponseError("RESPONSE_RECORD_LOCAL_ONLY")  # with company sign-in the person answers themselves
    team = response_routing.clean_team(team)
    recipient = None
    if person_ref is not None:
        person_ref = _id(person_ref)
        # A repeated accepted request remains idempotent after departure or an
        # email change; it never performs a second external send.
        previous = _row(repo, _key(finding_id, request_id))
        if previous and _repeat(repo, finding_id, request_id, previous.get("assigned_to"), person_ref, team, channel,
                                delivery):
            return public(repo, finding_id, now=now)
        recipient = response_routing.resolve(repo, settings, person_ref, now=now)
        if to is not None and to.casefold() != recipient["email"].casefold():
            raise ResponseError("RESPONSE_RECIPIENT_MISMATCH", 422)
        to = recipient["email"]
    elif oidc:
        raise ResponseError("RESPONSE_PERSON_REQUIRED", 422)
    try:
        to = contact.address(to).lower()
        if ready:
            contact.recipients(channel, [to], ready["allowed_domains"])  # only to the domains the admin allowed
    except contact.ContactError as exc:
        raise ResponseError(exc.code, exc.http_status) from None
    _finding(repo, finding_id)
    if _repeat(repo, finding_id, request_id, to, person_ref, team, channel, delivery):
        return public(repo, finding_id, now=now)
    _startable(repo, finding_id, *_current(repo, finding_id), expected_version, now)
    asked = {"to": to, "person_ref": person_ref, "team": team, "recipient": recipient, "locale": locale,
             "expected_version": expected_version, "request_id": request_id, "now": now}
    if channel == "ticket":
        return _ask_ticket(repo, settings, finding_id, actor, http_client=http_client, **asked)
    post = None
    if slack_channel is not None:
        # As Slack describes the channel now: one that turned public, external or archived since it was approved
        # gets nothing.
        try:
            with contact.slack_session(repo, settings, http_client_factory=(transports or {}).get(
                    "http_client_factory")) as call:
                post = response_channels.check(call, slack_channel, approved.get("allow_public") is True, status=409)
        except contact.ContactError as exc:
            raise ResponseError(exc.code, exc.http_status) from None
    return _ask_person(repo, settings, finding_id, actor, channel=channel, console_url=(ready or {}).get("console_url"),
                       transports=transports, delivery=delivery, post=post, **asked)


def _new_cycle(head, before, actor, channel, *, to, team, recipient, request_id, now, locale):
    from cremore.governance import response_routing

    value = {"request_id": request_id, "cycle": head.get("cycle", 0) + 1, "state": "SENDING", "channel": channel,
             "completion_version": 2, "requested_by": actor, "requested_at": _stamp(now), "assigned_to": to,
             "team": team, "send_deadline": _stamp(now + dt.timedelta(seconds=SEND_SECONDS)),
             "previous_request_id": before.get("request_id"), "error_code": None,
             "locale": locale if locale in _LINK_WORDS else "ko"}
    if recipient:
        value.update(recipient=response_routing._profile(recipient), mapping_basis="IDP_PERSON_SELECTED",
                     mapping_checked_at=_stamp(now))
    return value


def _current_recipient(bound, settings, person_ref, to, now):
    from cremore.governance import response_routing

    person = response_routing.resolve(bound, settings, person_ref, now=now)
    if person["email"].casefold() != to:
        raise ResponseError("RESPONSE_RECIPIENT_CHANGED")
    return person


def _ask_ticket(repo, settings, finding_id, actor, *, to, person_ref, team, recipient, locale, expected_version,
                request_id, now, http_client):
    # Read-only adapter work precedes the reservation. Reservation is still checked
    # again under the lock, so concurrent callers can never both send.
    system = None
    try:
        system, name, binding = setup.open_system(repo, settings, http_client)
        if not _SYSTEM.fullmatch(name):
            raise TicketError("TICKET_SYSTEM_ERROR")
        approver = system.find_approver(to)
        if (not reference_ok(approver.id) or not isinstance(approver.addresses, (list, tuple))
                or to not in [a.lower() for a in approver.addresses if isinstance(a, str)]):
            raise TicketError("RESPONSE_APPROVER_INVALID")
        with _locked(repo) as bound:
            head, before = _current(bound, finding_id)
            if _repeat(bound, finding_id, request_id, to, person_ref, team):
                return public(bound, finding_id, now=now)
            finding = _startable(bound, finding_id, head, before, expected_version, now)
            if recipient:
                recipient = _current_recipient(bound, settings, person_ref, to, dt.datetime.now(dt.UTC))
            if setup.binding(bound) != binding:
                raise ResponseError("TICKET_SYSTEM_CHANGED")
            contact.reserve(bound, actor, 1, now)
            value = _new_cycle(head, before, actor, "ticket", to=to, team=team, recipient=recipient,
                               request_id=request_id, now=now, locale=locale)
            value["ticket"] = {"system": name, "binding": binding, "approver": approver.id}
            _unlinked(bound, before)  # a replaced link request's link ends with it
            _save(bound, finding_id, head, value, actor, "RESPONSE_REQUESTED",
                  before.get("state") or _summary(finding, {}, {}, now)["state"], f"to={to} requested_at={_stamp(now)}")
        try:
            credential = repo.get_credential(finding.credential_id)
            opened = system.open_approval(_message(finding_id, request_id, before, locale,
                                                  contact.channels(repo).get("console_url"), credential,
                                                  _playbook(repo, credential, locale)), approver)
            if (not all(reference_ok(getattr(opened, key, None)) for key in ("ticket", "approval", "approver"))
                    or opened.approver != approver.id):
                raise TicketError("RESPONSE_TICKET_REFERENCE_INVALID")
        except Exception as exc:  # noqa: BLE001 -- a write may have succeeded before any error arrived
            code = safe_code(exc)
            orphan = getattr(exc, "ticket", "")
            _finish_send(repo, finding_id, request_id, actor, code=code, orphan=orphan)
            return public(repo, finding_id, now=now)
        _finish_send(repo, finding_id, request_id, actor, refs={"ticket": opened.ticket,
                     "approval": opened.approval, "url": _url(opened.url)})
        return public(repo, finding_id, now=now)
    except (TicketError, contact.ContactError) as exc:
        raise ResponseError(safe_code(exc), getattr(exc, "http_status", 502)) from None
    finally:
        if system is not None:
            system.close()


def _ask_person(repo, settings, finding_id, actor, *, channel, to, person_ref, team, recipient, locale,
                expected_version, request_id, now, console_url, transports, delivery=None, post=None):
    """A Slack/mail request: saved as SENDING with its link under the lock (the hourly budget counted there too), then
    sent outside it: the person's DM unless ``delivery`` says otherwise, and the notice to the checked team channel
    ``post``. A record request is saved as asked; nothing is sent."""
    with _locked(repo) as bound:
        head, before = _current(bound, finding_id)
        if _repeat(bound, finding_id, request_id, to, person_ref, team, channel, delivery):
            return public(bound, finding_id, now=now)
        finding = _startable(bound, finding_id, head, before, expected_version, now)
        if recipient:
            recipient = _current_recipient(bound, settings, person_ref, to, now)
        value = _new_cycle(head, before, actor, channel, to=to, team=team, recipient=recipient,
                           request_id=request_id, now=now, locale=locale)
        if channel == "record":
            value.update(state="WAITING_OWNER", send_deadline=None)
            note = f"record to={to} requested_at={_stamp(now)}"
        else:
            try:
                contact.reserve(bound, actor, 1, now)
            except contact.ContactError as exc:
                raise ResponseError(exc.code, exc.http_status) from None
            token = secrets.token_urlsafe(32)
            expires = now + LINK_LIFETIME
            credential = repo.get_credential(finding.credential_id)
            subject, text = _link_message(credential, console_url + LINK_PATH + token, expires, locale,
                                          _playbook(repo, credential, locale))
            note = (f"{channel} to={to} text={contact.fingerprints(settings, [to], subject, text)[1]} "
                    f"expires={_stamp(expires)} requested_at={_stamp(now)}")
            value.update(link={"expires_at": _stamp(expires), "digest": _digest(token)}, delivery=delivery)
            # Only the token's digest names the request; the token itself is in the message alone.
            bound.put_setting(LINK_PREFIX + value["link"]["digest"], {"finding_id": finding_id, "request_id": request_id},
                              actor)
        _unlinked(bound, before)  # the request it replaces ends its link
        _save(bound, finding_id, head, value, actor, "RESPONSE_REQUESTED",
              before.get("state") or _summary(finding, {}, {}, now)["state"], note)
    if channel == "record":
        return public(repo, finding_id, now=now)
    # Pointers nobody can use any more (twice a link's lifetime old) are dropped as new links are made.
    repo.delete_settings_before(LINK_PREFIX, now - 2 * LINK_LIFETIME)
    transports = transports or {}
    code, delivered, thread, thread_error = None, [], None, None
    if (delivery or {}).get("dm", True):
        try:
            sent = contact.send(repo, settings, channel, [to], subject, text, **transports)
            if sent["delivered"]:
                delivered.append("dm")
            else:
                code = sent["failed"][0]["code"] if sent["failed"] else "CONTACT_NOT_DELIVERED"
        except contact.ContactError as exc:
            code = exc.code
        except Exception as exc:  # noqa: BLE001 -- whatever failed, the message did not go out: its link ends
            logger.warning("response link send failed: %s", type(exc).__name__)
            code = "CONTACT_SEND_ERROR"
    if post is not None:
        try:
            ts = _post_notice(repo, settings, post["channel_id"], credential, console_url + LINK_PATH + token, expires,
                              locale, to, (recipient or {}).get("name"), transports.get("http_client_factory"))
            thread = {"channel_id": post["channel_id"], "name": post["name"], "ts": ts}
            delivered.append(f"channel={post['channel_id']}")
        except contact.ContactError as exc:
            thread_error = exc.code
        except Exception as exc:  # noqa: BLE001 -- the channel notice did not go out; the DM's outcome stands
            logger.warning("response channel notice failed: %s", type(exc).__name__)
            thread_error = "CONTACT_SEND_ERROR"
        if not delivery.get("dm"):
            code = thread_error  # the notice was the only delivery: its failure is the request's
    _finish_link(repo, finding_id, request_id, actor, code=code, delivered=delivered, thread=thread,
                 thread_error=thread_error)
    return public(repo, finding_id, now=now)


_TS = re.compile(r"[0-9]{1,20}\.[0-9]{1,20}")


def _post_notice(repo, settings, channel_id, credential, link, expires, locale, email, name, http_client_factory):
    """Post the team channel's notice, mentioning the person when Slack knows their address (their name otherwise);
    the thread's ``ts``. ContactError when it does not go out. The channel's approval and Slack's description of it are
    read again right before the post (after the DM and the lookup, which can take a while), so a channel that changed
    meanwhile gets nothing. Slack has no check-and-post: a change in the last moment can still be missed."""
    from cremore.governance import response_channels

    with contact.slack_session(repo, settings, http_client_factory=http_client_factory) as call:
        try:
            user = (call("users.lookupByEmail", data={"email": email}).get("user") or {}).get("id")
        except contact.ContactError as exc:
            if exc.code != "SLACK_USERS_NOT_FOUND":
                raise
            user = None
        user_id = user if isinstance(user, str) and re.fullmatch(r"[UW][A-Z0-9]{2,20}", user) else None
        entry = response_channels.approved(repo).get(channel_id)
        if entry is None:
            raise contact.ContactError("RESPONSE_CHANNEL_NOT_APPROVED", 409)
        try:
            response_channels.check(call, channel_id, entry.get("allow_public") is True, status=409)
        except ResponseError as exc:
            raise contact.ContactError(exc.code, exc.http_status) from None
        sent = call("chat.postMessage", json={"channel": channel_id, "link_names": False, "unfurl_links": False,
                                              "unfurl_media": False,
                                              "text": _channel_message(credential, link, expires, locale, user_id, name)})
    ts = sent.get("ts")
    if not isinstance(ts, str) or not _TS.fullmatch(ts):
        raise contact.ContactError("SLACK_REQUEST_REFUSED", 502)
    return ts


def _reap(repo, finding_id, value, now):
    """A send past its deadline never resumes: a ticket's outcome is unknown (an admin releases it), a link that did
    not go out is ended."""
    if value.get("state") != "SENDING" or (_when(value.get("send_deadline")) or now) > now:
        return False
    if _channel(value) in LINKED:
        _finish_link(repo, finding_id, value["request_id"], ACTOR, code="RESPONSE_SEND_TIMED_OUT")
    else:
        _finish_send(repo, finding_id, value["request_id"], ACTOR, code="RESPONSE_SEND_TIMED_OUT")
    return True


def pending(repo, *, now=None):
    """The ticket requests waiting for an answer the ticket sweep reads (cremore.ticketing.sweep). Only a ticket send
    past its deadline is reaped here: ending a link deletes its pointer, and the control process this runs in may not
    delete (its database role has no DELETE on installation_settings); ``sweep`` reaps link sends."""
    now = _utc(now or dt.datetime.now(dt.UTC))
    rows = []
    for head_row in repo.list_settings(HEAD_PREFIX):
        finding_id = head_row["key"][len(HEAD_PREFIX):]
        _, value = _current(repo, finding_id)
        if _channel(value) not in LINKED and _reap(repo, finding_id, value, now):
            continue
        if value.get("state") in ("WAITING_OWNER", "REPORT_REQUIRED") and _channel(value) == "ticket":
            rows.append((finding_id, value))
    return rows


def checked(repo, finding_id, request_id, code):
    code = code if code is None or isinstance(code, str) and _CODE.fullmatch(code) else "TICKET_SYSTEM_ERROR"
    finding_id, request_id = _id(finding_id), _id(request_id)
    with _locked(repo) as bound:
        head, value = _current(bound, finding_id)
        if (value.get("request_id") == request_id and value.get("state") in ("WAITING_OWNER", "REPORT_REQUIRED")
                and value.get("error_code") != code):
            _save(bound, finding_id, head, {**value, "error_code": code}, ACTOR,
                  "RESPONSE_TICKET_CHECKED", value["state"], code or "OK")


def answered(repo, finding_id, request_id, answer, *, system, binding, received_at,
             settings=None, contains_credentials=None):
    """Only the exact recipient's validated report can accompany a completion reply."""
    from cremore.governance import response_reports as reports
    finding_id, request_id = _id(finding_id), _id(request_id)
    if answer.state not in ("APPROVED", "DECLINED"):
        return False
    with _locked(repo) as bound:
        head, value = _current(bound, finding_id)
        ticket = value.get("ticket") or {}
        if (value.get("request_id") != request_id or value.get("state") not in ("WAITING_OWNER", "REPORT_REQUIRED")
                or _channel(value) != "ticket"):
            return False
        code = None
        if ticket.get("system") != system or ticket.get("binding") != binding or setup.binding(bound) != binding:
            code = "TICKET_SYSTEM_CHANGED"
        elif not reference_ok(answer.by) or answer.by != ticket.get("approver"):
            code = "RESPONSE_ANSWERED_BY_OTHER"
        if code:
            if value.get("error_code") != code:
                _save(bound, finding_id, head, {**value, "error_code": code}, ACTOR,
                      "RESPONSE_ANSWER_REFUSED", value["state"], code)
            return False
        received_at = _utc(received_at)
        if received_at < _when(value["requested_at"]):
            return False
        at = _when(answer.at)
        report = value.get("report")
        report_error = None
        if value.get("completion_version") == 2 and answer.report is not None:
            try:
                if not reports.ticket_authorized(bound, settings, value, now=received_at):
                    raise ResponseError("RESPONSE_REPORT_RECIPIENT_REQUIRED", 403)
                if contains_credentials is None:
                    raise ResponseError("RESPONSE_REPORT_SCREENING_UNAVAILABLE")
                normalized = reports.normalize(answer.report, now=received_at,
                    requested_at=_when(value["requested_at"]), contains_credentials=contains_credentials)
                if (normalized["result"] == "DONE") != (answer.state == "APPROVED"):
                    raise ResponseError("RESPONSE_REPORT_ANSWER_MISMATCH")
                actor = f"{system}:user:{answer.by}"
                report_id = str(uuid.uuid5(uuid.UUID(request_id), actor + ":" + reports.digest(normalized)))
                report = reports.store(bound, finding_id, value, normalized, actor, report_id=report_id,
                    now=received_at, basis="TICKET_RECIPIENT_STATEMENT")
                updated = {**value, "report": report, "report_count": max(value.get("report_count", 0), report["version"]),
                           "removal": None, "verification": None}
                _save(bound, finding_id, head, updated, actor, "RESPONSE_REPORT_RECORDED", value["state"],
                      f"report={report_id} hash={report['hash']} version={report['version']}")
                head, value = _current(bound, finding_id)
            except ResponseError as exc:
                report_error = exc.code
        next_state = "WAITING_VERIFICATION" if answer.state == "APPROVED" else "NEEDS_ACTION"
        if value.get("completion_version") == 2 and answer.state == "APPROVED":
            next_state = "REPORT_REQUIRED" if not report else "WAITING_VERIFICATION" if report["result"] == "DONE" else "NEEDS_ACTION"
        if report_error:
            next_state = "REPORT_REQUIRED"
        if (value.get("answer") == answer.state and value.get("state") == next_state
                and value.get("error_code") == report_error):
            return False
        before = value["state"]
        value = {**value, "state": next_state, "answer": answer.state,
                 "answered_by": f"{system}:user:{answer.by}", "answered_at": _stamp(at) if at else None,
                 "received_at": _stamp(received_at), "error_code": report_error}
        _save(bound, finding_id, head, value, value["answered_by"],
              "RESPONSE_CLEANUP_DECLARED" if answer.state == "APPROVED" else "RESPONSE_DECLINED", before,
              f"system={system} ticket={ticket['ticket']} approval={ticket['approval']} "
              f"answered_at={value['answered_at'] or '-'} received_at={value['received_at']}")
        return True


def release_unknown(repo, finding_id, actor, *, expected_version, request_id, confirmed_no_pending_ticket):
    """An admin's explicit assertion permits a new cycle; it is not external proof."""
    finding_id, request_id = _id(finding_id), _id(request_id)
    if confirmed_no_pending_ticket is not True:
        raise ResponseError("RESPONSE_CONFIRMATION_REQUIRED", 422)
    with _locked(repo) as bound:
        head, value = _current(bound, finding_id)
        _version(head, expected_version)
        if value.get("request_id") != request_id or value.get("state") not in ("SEND_UNKNOWN", "SENDING"):
            raise ResponseError("RESPONSE_NOT_UNKNOWN")
        # A live send cannot be released underneath its eventual success result.
        if value["state"] == "SENDING":
            raise ResponseError("RESPONSE_SEND_IN_PROGRESS")
        value = {**value, "state": "NEEDS_ACTION", "released_by": actor,
                 "released_at": _stamp(dt.datetime.now(dt.UTC)), "release_basis": "OPERATOR_CONFIRMED_NO_PENDING_TICKET"}
        _save(bound, finding_id, head, value, actor, "RESPONSE_SEND_RELEASED", "SEND_UNKNOWN",
              "OPERATOR_CONFIRMED_NO_PENDING_TICKET")
    return public(repo, finding_id)


def observe_scan(repo, finding_id, *, removed, observed_at, scan_started_at=None, authoritative=True, scan_id=None):
    """Consume authoritative scan evidence in its existing fenced transaction."""
    if not authoritative or scan_started_at is None or type(removed) is not bool:
        return False
    finding_id = _id(finding_id)
    started, observed = _utc(scan_started_at), _utc(observed_at)
    if observed < started:
        return False
    scan_id = str(scan_id) if scan_id is not None and reference_ok(str(scan_id)) else None
    _, before = _current(repo, finding_id)
    if before.get("completion_version") == 2:
        return _observe_completion_scan(repo, finding_id, removed, started, observed, scan_id)
    if before.get("state") not in ("WAITING_VERIFICATION", "NEEDS_ACTION", "REMOVED"):
        return False
    with _locked(repo) as bound:
        head, value = _current(bound, finding_id)
        state = value.get("state")
        if state == "WAITING_VERIFICATION":
            received = _when(value.get("received_at"))
            if received is None or started <= received:
                return False
            next_state = "REMOVED" if removed else "NEEDS_ACTION"
        elif state == "NEEDS_ACTION" and removed:
            basis = max(filter(None, (_when(value.get(key)) for key in
                        ("requested_at", "received_at", "last_scan_at", "released_at"))))
            if started <= basis:
                return False
            next_state = "REMOVED"
        elif state == "REMOVED" and not removed:
            verified_start = _when(value.get("verified_scan_started_at"))
            # A scan may first confirm the old location absent and later find
            # the credential at a new one. Positive evidence dominates absence
            # within the same run as well as in a later run.
            if verified_start is None or started < verified_start:
                return False
            next_state = "NEEDS_ACTION"
        else:
            return False
        value = {**value, "state": next_state, "last_scan_at": _stamp(observed), "last_scan_id": scan_id}
        if removed:
            value.update(verified_at=_stamp(observed), verified_scan_started_at=_stamp(started))
        _save(bound, finding_id, head, value, "scanner", "RESPONSE_REMOVAL_VERIFIED" if removed else
              "RESPONSE_REAPPEARED" if state == "REMOVED" else "RESPONSE_STILL_EXPOSED", state,
              f"scan_id={scan_id or '-'} scan_started_at={_stamp(started)} observed_at={_stamp(observed)}")
        return True


def start_review(repo, finding_id, actor, *, expected_version, now=None):
    finding_id = _id(finding_id)
    with _locked(repo) as bound:
        head, value = _current(bound, finding_id)
        _version(head, expected_version)
        finding = _finding(bound, finding_id)
        if value or head.get("reviewed_at"):
            return public(bound, finding_id)
        if finding.all_locations_removed or finding.workflow_status in ("FALSE_POSITIVE", "IGNORED"):
            raise ResponseError("RESPONSE_REVIEW_NOT_APPLICABLE")
        at = _stamp(now or dt.datetime.now(dt.UTC))
        bound.put_setting(HEAD_PREFIX + finding_id, {**head, "version": head.get("version", 0) + 1,
                          "reviewed_at": at, "reviewed_by": actor}, actor)
        bound.update_finding_status(uuid.UUID(finding_id), "ACKNOWLEDGED")
        bound.record_finding_event(FindingEvent(finding_id=uuid.UUID(finding_id), actor=actor,
            event_type="RESPONSE_REVIEW_STARTED", from_status="NEW", to_status="REVIEWING", note=f"reviewed_at={at}"))
        return public(bound, finding_id)


def _same_report(bound, finding_id, request_id, report_id, normalized, actor):
    """True when this report id already holds this person's same report (a retry); another use of it is refused."""
    from cremore.governance import response_reports as reports

    previous = _row(bound, reports.PREFIX + finding_id + ":" + request_id + ":" + report_id)
    if previous and (previous["content_hash"] != reports.digest(normalized) or previous["by"] != actor):
        raise ResponseError("RESPONSE_REPORT_ID_REUSED")
    return bool(previous)


def _answer(bound, finding_id, head, value, normalized, actor, *, report_id, now, basis):
    """Record a report and the answer it makes, under the response lock, with their audit rows in one transaction:
    DONE is the responder's APPROVED declaration (WAITING_VERIFICATION), anything else DECLINED (NEEDS_ACTION). A later
    answer adds a report version and replaces the answer."""
    from cremore.governance import response_reports as reports

    report = reports.store(bound, finding_id, value, normalized, actor, report_id=report_id, now=now, basis=basis)
    recorded = {**value, "report": report, "report_count": report["version"], "removal": None, "verification": None,
                "error_code": None}
    _save(bound, finding_id, head, recorded, actor, "RESPONSE_REPORT_RECORDED", value["state"],
          f"report={report_id} hash={report['hash']} version={report['version']}")
    head, recorded = _current(bound, finding_id)
    answer = "APPROVED" if report["result"] == "DONE" else "DECLINED"
    at = _stamp(now)
    answered = {**recorded, "state": "WAITING_VERIFICATION" if answer == "APPROVED" else "NEEDS_ACTION",
                "answer": answer, "answered_by": actor, "answered_at": at, "received_at": at}
    _save(bound, finding_id, head, answered, actor,
          "RESPONSE_CLEANUP_DECLARED" if answer == "APPROVED" else "RESPONSE_DECLINED", recorded["state"],
          f"channel={_channel(value)} report={report_id} answered_at={at}")


def submit_report(repo, settings, finding_id, actor, *, expected_version, request_id, report_id,
                  data, contains_credentials, now=None, verified_email=None):
    """The recipient's report in the console. For a Slack/mail/record request it is also the answer; a ticket
    request's answer still comes from its ticket."""
    from cremore.governance import response_reports as reports

    finding_id, request_id, report_id = _id(finding_id), _id(request_id), _id(report_id)
    now = _utc(now or dt.datetime.now(dt.UTC))
    with _locked(repo) as bound:
        head, value = _current(bound, finding_id)
        if value.get("request_id") != request_id or value.get("completion_version") != 2:
            raise ResponseError("RESPONSE_REQUEST_CHANGED")
        if not reports.authorized(bound, settings, value, actor, verified_email=verified_email):
            raise ResponseError("RESPONSE_REPORT_RECIPIENT_REQUIRED", 403)
        normalized = reports.normalize(data, now=now, requested_at=_when(value["requested_at"]),
                                       contains_credentials=contains_credentials)
        if _same_report(bound, finding_id, request_id, report_id, normalized, actor):
            return public(bound, finding_id, now=now)
        _version(head, expected_version)
        if value.get("recurred_at"):
            raise ResponseError("RESPONSE_NEW_CYCLE_REQUIRED")
        if value["state"] not in ANSWERABLE:
            raise ResponseError("RESPONSE_REPORT_NOT_PENDING")
        basis = "LOCAL_OPERATOR_STATEMENT" if settings.auth_mode == "local" else "VERIFIED_IDP_RECIPIENT"
        if _channel(value) != "ticket":
            if _link_expired(value, now):
                raise ResponseError("RESPONSE_LINK_EXPIRED", 410)
            _answer(bound, finding_id, head, value, normalized, actor, report_id=report_id, now=now, basis=basis)
            return public(bound, finding_id, now=now)
        report = reports.store(bound, finding_id, value, normalized, actor, report_id=report_id, now=now, basis=basis)
        state = "WAITING_OWNER" if not value.get("answer") else "WAITING_VERIFICATION" if (
            value["answer"] == "APPROVED" and report["result"] == "DONE") else "NEEDS_ACTION"
        changed = {**value, "report": report, "report_count": report["version"], "state": state,
                   "removal": None, "verification": None, "error_code": None}
        _save(bound, finding_id, head, changed, actor, "RESPONSE_REPORT_RECORDED", value["state"],
              f"report={report_id} hash={report['hash']} version={report['version']}")
        return public(bound, finding_id, now=now)


# --- the responder's link page (POST /api/v1/response-links/*): the token and the person's own company sign-in ---

def _opened(repo, token):
    """(finding id, head, cycle) a link token belongs to while it is the finding's current request. Anything a guess
    could learn from is the same 404: unknown, ended (not sent) or replaced by a later request."""
    if not isinstance(token, str) or not _TOKEN.fullmatch(token):
        raise ResponseError("RESPONSE_LINK_INVALID", 404)
    digest = _digest(token)
    pointer = _row(repo, LINK_PREFIX + digest)
    finding_id = pointer.get("finding_id")
    head, value = _current(repo, finding_id) if isinstance(finding_id, str) else ({}, {})
    if (not value or value.get("request_id") != pointer.get("request_id")
            or not hmac.compare_digest(str((value.get("link") or {}).get("digest") or ""), digest)):
        raise ResponseError("RESPONSE_LINK_INVALID", 404)
    return finding_id, head, value


def _holder_check(repo, settings, value, holder, now):
    """The signed-in person is the one asked: their verified email is the request's address
    (``response_reports.same_address``, the console report's rule too), and the directory still names that same active
    person there."""
    from cremore.governance import response_reports as reports

    if (not reports.same_address(holder.get("email"), value.get("assigned_to"))
            or not reports.directory_current(repo, settings, value, now=now)):
        raise ResponseError("RESPONSE_LINK_NOT_RECIPIENT", 403)


def _held(repo, settings, token, holder, now):
    finding_id, head, value = _opened(repo, token)
    if _link_expired(value, now):
        raise ResponseError("RESPONSE_LINK_EXPIRED", 410)
    _holder_check(repo, settings, value, holder, now)
    return finding_id, head, value


def _link_public(repo, finding_id, value, holder, now):
    """What the link page shows its holder: the credential by service, type and masked identifier, how many places it
    is still exposed at, the request and their own latest report. Never a value, snippet, location or address."""
    finding = _finding(repo, finding_id)
    credential = repo.get_credential(finding.credential_id)
    provider, kind, hint = _facts(credential)
    report = value.get("report") or {}
    mine = report if report.get("by") == holder["subject"] else None
    return {"finding": {"provider": provider, "credential_type": kind, "identifier_hint": hint,
                        "locations": sum(1 for exposure in repo.exposures_for_credential(finding.credential_id)
                                         if exposure.status in _CURRENT_LOCATION)},
            "request": {"cycle": value["cycle"], "state": value["state"], "requested_at": value["requested_at"],
                        "link_expires_at": (value.get("link") or {}).get("expires_at"),
                        "answer": value.get("answer"), "answered_at": value.get("answered_at")},
            "report": {key: mine.get(key) for key in ("result", "path", "actions", "explanation", "performed_at",
                                                       "replacement_plan_id", "replacement_entity_id", "received_at",
                                                       "version")} if mine else None,
            "can_answer": _answerable(value, now),
            # How to fix it, in both languages: the page picks its own.
            "playbook": {locale: _playbook(repo, credential, locale) for locale in ("ko", "en")}}


def link_view(repo, settings, token, holder, *, now):
    """The request as its link page shows it to the person it went to, until the link's end; reading changes
    nothing (a mail scanner may open it)."""
    now = _utc(now)
    finding_id, _head, value = _held(repo, settings, token, holder, now)
    return _link_public(repo, finding_id, value, holder, now)


def link_answer(repo, settings, token, holder, *, report_id, data, contains_credentials, now):
    """The person's report through their link, recorded with the answer it makes (``_answer``) as their sign-in's
    subject, basis VERIFIED_IDP_RECIPIENT."""
    from cremore.governance import response_reports as reports

    now, report_id = _utc(now), _id(report_id)
    with _locked(repo) as bound:
        finding_id, head, value = _held(bound, settings, token, holder, now)
        if not _answerable(value, now):
            raise ResponseError("RESPONSE_LINK_CLOSED")
        normalized = reports.normalize(data, now=now, requested_at=_when(value["requested_at"]),
                                       contains_credentials=contains_credentials)
        if not _same_report(bound, finding_id, value["request_id"], report_id, normalized, holder["subject"]):
            _answer(bound, finding_id, head, value, normalized, holder["subject"], report_id=report_id, now=now,
                    basis="VERIFIED_IDP_RECIPIENT")
        return _link_public(bound, finding_id, _current(bound, finding_id)[1], holder, now)


def link_finding(repo, settings, token, holder, *, now):
    """The finding a link answers for, while it takes an answer (its report's replacement search is scoped to it)."""
    now = _utc(now)
    finding_id, _head, value = _held(repo, settings, token, holder, now)
    if not _answerable(value, now):
        raise ResponseError("RESPONSE_LINK_CLOSED")
    return _finding(repo, finding_id)


def report_history(repo, finding_id, request_id, *, offset=0):
    from cremore.governance.response_reports import PREFIX

    finding_id, request_id = _id(finding_id), _id(request_id)
    _finding(repo, finding_id)
    rows = [row["value"] for row in repo.list_settings(PREFIX + finding_id + ":" + request_id + ":")]
    rows.sort(key=lambda row: row["version"], reverse=True)
    return {"items": rows[offset:offset + HISTORY_LIMIT], "total": len(rows)}


def _observe_completion_scan(repo, finding_id, removed, started, observed, scan_id):
    with _locked(repo) as bound:
        head, value = _current(bound, finding_id)
        if value.get("completion_version") != 2:
            return False
        report = value.get("report") or {}
        since = max(filter(None, (_when(value.get("requested_at")), _when(value.get("received_at")),
                                  _when(report.get("received_at")))))
        previous = value.get("removal") or {}
        last = _when(previous.get("started_at"))
        if started <= since or (last and started < last):
            return False
        # Positive evidence wins inside the same scan, regardless of arrival order.
        if last == started and (previous.get("removed") is False or previous.get("removed") == removed):
            return False
        removal = {"removed": removed, "started_at": _stamp(started), "at": _stamp(observed), "scan_id": scan_id}
        state = value["state"]
        if not removed and state in ("COMPLETED", "WAITING_VERIFICATION"):
            state = "NEEDS_ACTION"
        elif removed and state != "COMPLETED" and value.get("answer") == "APPROVED" and report.get("result") == "DONE":
            state = "WAITING_VERIFICATION"
        changed = {**value, "state": state, "removal": removal, "last_scan_at": _stamp(observed), "last_scan_id": scan_id}
        if not removed and value.get("completed_at"):
            changed["recurred_at"] = _stamp(observed)
        if changed.get("recurred_at"):
            changed["state"] = "NEEDS_ACTION"
        if removed:
            changed.update(verified_at=_stamp(observed), verified_scan_started_at=_stamp(started))
        if value.get("verification"):
            changed["verification"] = {**value["verification"], "removal": {
                "state": "PASS" if removed else "WAIT", "reason": "COMPLETE_RESCAN", **removal}}
        _save(bound, finding_id, head, changed, "scanner", "RESPONSE_REMOVAL_VERIFIED" if removed else
              "RESPONSE_REAPPEARED" if value["state"] == "COMPLETED" else "RESPONSE_STILL_EXPOSED", value["state"],
              f"scan_id={scan_id or '-'} scan_started_at={_stamp(started)}")
        return True


def reconcile(repo, finding_id, checks, *, expected_version, now):
    from cremore.governance.response_reports import digest

    finding_id = _id(finding_id)
    with _locked(repo) as bound:
        head, value = _current(bound, finding_id)
        if head.get("version", 0) != expected_version or value.get("completion_version") != 2:
            return False
        if value["state"] not in ("WAITING_VERIFICATION", "NEEDS_ACTION", "COMPLETED"):
            return False
        finding = _finding(bound, finding_id)
        complete = (finding.all_locations_removed and not value.get("recurred_at") and value.get("answer") == "APPROVED"
                    and (value.get("report") or {}).get("result") == "DONE"
                    and all(checks.get(k, {}).get("state") in ("PASS", "NA") for k in
                            ("report", "removal", "retirement", "replacement", "vault", "cutover")))
        state = "COMPLETED" if complete else "WAITING_VERIFICATION" if value["state"] == "COMPLETED" else value["state"]
        proof = {"request_id": value["request_id"], "checks": checks, "state": state}
        proof_hash = digest(proof)
        if value.get("evidence_hash") == proof_hash and value["state"] == state:
            return False
        evidence_key = "response:evidence:" + finding_id + ":" + value["request_id"] + ":" + proof_hash
        if not bound.get_setting(evidence_key):
            bound.put_setting(evidence_key, {**proof, "at": _stamp(now)}, ACTOR)
        changed = {**value, "state": state, "verification": checks, "evidence_hash": proof_hash}
        if complete and value["state"] != "COMPLETED":
            changed["completed_at"] = _stamp(now)
        _save(bound, finding_id, head, changed, ACTOR,
              "RESPONSE_COMPLETED" if complete and value["state"] != "COMPLETED" else "RESPONSE_EVIDENCE_UPDATED",
              value["state"], f"evidence={proof_hash}")
        return True


def sweep(repo, settings, orchestrator, *, now=None, clock=time.monotonic):
    """End sends past their deadline, then reevaluate stored proof after scans, inventory, vault collection and
    restarts. The deadline is enforced here because a Slack/mail request needs no ticket system (whose sweep reaps
    ticket sends too)."""
    from cremore.coverage import response_evidence

    now = _utc(now or dt.datetime.now(dt.UTC))
    heads = repo.list_settings(HEAD_PREFIX)
    for row in heads:
        _reap(repo, row["key"][len(HEAD_PREFIX):], (row["value"] or {}).get("current") or {}, now)
    # Threads the progress job (cremore.governance.response_threads) retired: it runs where deleting is not allowed.
    for row in repo.list_settings(THREAD_PREFIX):
        if (row.get("value") or {}).get("retired"):
            repo.delete_settings_before(row["key"], _FOREVER)  # fixed-length key: this one row
    pending = [(row["key"][len(HEAD_PREFIX):], row["value"]) for row in heads
               if (row["value"].get("current") or {}).get("completion_version") == 2
               and (row["value"].get("current") or {}).get("state") in ("WAITING_VERIFICATION", "NEEDS_ACTION", "COMPLETED")]
    if not pending or not repo.claim_slot("response:evidence:sweep", int(now.timestamp()) // 60, ACTOR):
        return 0
    cursor = _row(repo, "response:evidence:cursor").get("last", "")
    pending.sort()
    pending = [p for p in pending if p[0] > cursor] + [p for p in pending if p[0] <= cursor]
    compared = response_evidence.snapshot(repo, settings, orchestrator, now)
    # Snapshot construction has its own bounded reads. Start the case budget
    # afterwards so a large snapshot cannot starve every pending case forever.
    deadline = clock() + 20
    count = 0
    for finding_id, head in pending[:100]:
        if clock() > deadline:
            break
        checks = response_evidence.evaluate(repo, _finding(repo, finding_id), head["current"], compared, now=now)
        count += reconcile(repo, finding_id, checks, expected_version=head["version"], now=now)
        repo.put_setting("response:evidence:cursor", {"last": finding_id}, ACTOR)
    return count
