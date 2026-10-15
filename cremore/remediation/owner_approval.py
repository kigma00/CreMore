"""A credential owner's approval of a key action plan (N2b).

The security team decides that a key must be disabled, deleted or rotated (the plan's own approval); the owner of
the credential accepts the operational impact (this approval).

With company sign-in (OIDC), CreMore sends the owner a link by mail or Slack DM (cremore/governance/contact.py). The
link carries a random token that is stored only as its SHA-256 digest, stops at the earlier of 72 hours and the
plan's own expiry, and holds for the plan as it was asked about: a plan that closed takes no decision, and a new
link ends the previous one. The token alone decides nothing: the person opening it signs in with the company
identity provider, and only the one whose verified email is the address the link went to, and who is not the
person who asked for it, planned or approved the plan, decides, once.

With the local sign-in there is one operator and nobody else can reach the console safely, so no link is sent: the
operator records the approval the owner gave elsewhere (a mail, a ticket) with its reference.

In either mode the approval can be asked in the company's ticket system (cremore.ticketing): a ticket asks the
owner's own account there, and the worker records the answer, counted only from the account asked. With company
sign-in the owner's address must differ from those of the people on the security side of the plan
(cremore.governance.principals), when asking and again before approval and execution.

The request is audited before the message goes out, and every decision or record in the same transaction as the
decision, with the address it went to and the owner's note. State lives in installation settings:
``owner_approval_plan:<plan id>`` is the plan's approval (never the token), ``owner_approval:<digest>`` points a
presented token at its plan.

Execution (cremore.remediation.action_plans) needs the owner's approval for an action that changes what the key's
users see (``OWNER_ACTIONS``) while the installation switch ``owner_approval_required`` is on, which it is unless an
Admin turns it off. A publicly exposed key can still be disabled at once by an Admin with a reason (emergency
containment, ``owner_approval_emergency:<plan id>``), and the owner is then told afterwards.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import re
import secrets

from cremore.domain.models import FindingEvent

PLAN_PREFIX = "owner_approval_plan:"
TOKEN_PREFIX = "owner_approval:"
LOCK_KEY = "owner-approval:lock"
ACTOR = "system:owner-approval"
LINK_LIFETIME = _dt.timedelta(hours=72)
LINK_PATH = "/owner-approval#"  # the token is the fragment: never in a server log or a Referer
OPEN_PLAN = ("PENDING_APPROVAL", "APPROVED")
DECISIONS = {"approve": "APPROVED", "decline": "DECLINED"}
NOTE_MAX = 500
EVIDENCE_MAX = 200
LOCALES = ("ko", "en")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")  # secrets.token_urlsafe(32)
_SHOWN = ("channel", "recipient", "requested_by", "requested_at", "expires_at", "decided_at", "decided_by", "note",
          "evidence", "previous")
_TICKET_SHOWN = ("system", "ticket", "approval", "url", "check_code", "answered_by", "answered_at")
_REFERENCE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_WHEN = re.compile(r"[0-9T:.+Z -]{1,40}")
_CODE = re.compile(r"[A-Z0-9_]{1,64}")
KEY = "owner_approval_required"
EMERGENCY_PREFIX = "owner_approval_emergency:"
# Preparing a successor key changes nothing its users see; disabling, deleting and publishing a new one do, and so
# does disabling or revoking another provider's credential.
OWNER_ACTIONS = ("DISABLE_ACCESS_KEY", "DELETE_ACCESS_KEY", "PUBLISH_ACCESS_KEY_ROTATION",
                 "DISABLE_PROVIDER_CREDENTIAL", "REVOKE_PROVIDER_CREDENTIAL")
EMERGENCY_ACTION = "DISABLE_ACCESS_KEY"
REASON_MIN, REASON_MAX = 10, 500

# The message is CreMore's own text: the person asking picks the channel, the recipient and the language only.
_WORDS = {
    "ko": {
        "subject": "[CreMore] AWS 액세스 키 조치 승인 요청",
        "intro": "보안팀이 아래 AWS 액세스 키에 조치를 하려고 합니다. 업무에 주는 영향을 확인한 뒤 링크에서 승인하거나 거절해 주세요.",
        "action": "조치", "key": "대상 키", "user": "IAM 사용자", "account": "계정", "reason": "사유", "expires": "링크 만료",
        "once": "회사 계정으로 로그인한 뒤 한 번만 결정할 수 있습니다.",
        "ticket_intro": "보안팀이 아래 AWS 액세스 키에 조치를 하려고 합니다. 업무에 주는 영향을 확인한 뒤 이 티켓의 승인 "
                        "요청에서 승인하거나 거절해 주세요.",
        "until": "응답 기한",
        "actions": {"DISABLE_ACCESS_KEY": "액세스 키 비활성화", "DELETE_ACCESS_KEY": "비활성 키 영구 삭제",
                    "PREPARE_ACCESS_KEY_ROTATION": "교체할 새 키 준비", "PUBLISH_ACCESS_KEY_ROTATION": "새 키를 Secret에 게시",
                    "DISABLE_PROVIDER_CREDENTIAL": "자격증명 비활성화",
                    "REVOKE_PROVIDER_CREDENTIAL": "자격증명 영구 폐기"},
        "reasons": {"EXPOSURE_CONTAINMENT": "노출 차단", "SECURITY_INCIDENT": "보안 사고 대응",
                    "OWNER_REQUEST": "담당자 요청", "OWNER_DEPARTED": "소유자 퇴사"},
        # A plan on another provider's credential (cremore.remediation.provider_actions).
        "provider": {
            "subject": "[CreMore] 자격증명 조치 승인 요청",
            "intro": "보안팀이 아래 자격증명에 조치를 하려고 합니다. 업무에 주는 영향을 확인한 뒤 링크에서 승인하거나 거절해 주세요.",
            "ticket_intro": "보안팀이 아래 자격증명에 조치를 하려고 합니다. 업무에 주는 영향을 확인한 뒤 이 티켓의 승인 "
                            "요청에서 승인하거나 거절해 주세요.",
            "key": "대상 자격증명",
            # A revoke that ends one organization's grant, not the credential (provider_actions.REVOKES_WHAT).
            "revokes": {"ORGANIZATION_ACCESS": "조직 접근 회수"}},
    },
    "en": {
        "subject": "[CreMore] Approval asked for an AWS access key action",
        "intro": "The security team plans the action below on an AWS access key. Check its effect on your work, then "
                 "approve or decline it at the link.",
        "action": "Action", "key": "Key", "user": "IAM user", "account": "account", "reason": "Reason",
        "expires": "Link expires", "once": "Sign in with your company account; you decide once.",
        "ticket_intro": "The security team plans the action below on an AWS access key. Check its effect on your "
                        "work, then approve or refuse the approval asked in this ticket.",
        "until": "Answer by",
        "actions": {"DISABLE_ACCESS_KEY": "Disable the access key", "DELETE_ACCESS_KEY": "Delete the inactive key",
                    "PREPARE_ACCESS_KEY_ROTATION": "Prepare a replacement key",
                    "PUBLISH_ACCESS_KEY_ROTATION": "Publish the new key to the Secret",
                    "DISABLE_PROVIDER_CREDENTIAL": "Disable the credential",
                    "REVOKE_PROVIDER_CREDENTIAL": "Revoke the credential for good"},
        "reasons": {"EXPOSURE_CONTAINMENT": "Contain the exposure", "SECURITY_INCIDENT": "Security incident",
                    "OWNER_REQUEST": "The owner asked", "OWNER_DEPARTED": "The owner left"},
        "provider": {
            "subject": "[CreMore] Approval asked for a credential action",
            "intro": "The security team plans the action below on a credential. Check its effect on your work, then "
                     "approve or decline it at the link.",
            "ticket_intro": "The security team plans the action below on a credential. Check its effect on your work, "
                            "then approve or refuse the approval asked in this ticket.",
            "key": "Credential",
            "revokes": {"ORGANIZATION_ACCESS": "Revoke its organization access"}},
    },
}


def _words(plan, locale: str) -> dict:
    """The locale's words, about another provider's credential when the plan names one."""
    words = _WORDS[locale if locale in LOCALES else "ko"]
    return {**words, **words["provider"]} if getattr(plan, "target", None) else words


def _action(plan, words: dict) -> str:
    """The action in the locale's words; a revoke says what it takes away when that is not the credential."""
    revokes = (getattr(plan, "target", None) or {}).get("revokes")
    if plan.action_type == "REVOKE_PROVIDER_CREDENTIAL" and revokes in words.get("revokes", {}):
        return words["revokes"][revokes]
    return words["actions"].get(plan.action_type, plan.action_type)


def _key_line(plan, words: dict) -> str:
    """Which credential: the key and its IAM user, or the provider and the identifiers its own list gives."""
    key = plan.identifier_hint or "-"
    if plan.user_name:
        key += f" ({words['user']} {plan.user_name}, {words['account']} {plan.account_id})"
    target = getattr(plan, "target", None)
    if target:
        from cremore.onboarding import catalog

        try:
            label = catalog.descriptor(target.get("provider"))["label"]
        except catalog.CatalogError:
            label = str(target.get("provider") or "")
        key = f"{label} · {key}"
    return key


# What the owner is told after an emergency containment: what was done to which key, when, by whom's decision, why.
_NOTICE = {
    "ko": {"subject": "[CreMore] AWS 액세스 키 긴급 차단 알림",
           "done": "보안팀이 공개된 곳에 노출된 아래 AWS 액세스 키를 소유자 승인 없이 긴급 차단(비활성화)했습니다.",
           "tried": "보안팀이 공개된 곳에 노출된 아래 AWS 액세스 키의 긴급 차단(비활성화)을 실행했으나 완료를 확인하지 못했습니다.",
           "declined": "소유자가 거절한 조치였지만 공개 노출이라 차단했습니다.",
           "key": "대상 키", "user": "IAM 사용자", "account": "계정", "when": "실행", "why": "사유",
           "next": "이 키를 쓰던 작업이 있으면 새 자격증명으로 바꾸고, 궁금한 점은 보안팀에 문의해 주세요."},
    "en": {"subject": "[CreMore] An AWS access key was contained in an emergency",
           "done": "The security team disabled the AWS access key below, exposed in a public place, without waiting for its "
                   "owner's approval.",
           "tried": "The security team ran an emergency disable of the AWS access key below, exposed in a public place, "
                    "but could not confirm it finished.",
           "declined": "Its owner had declined the action; it was contained because the exposure is public.",
           "key": "Key", "user": "IAM user", "account": "account", "when": "Run at", "why": "Reason",
           "next": "Move anything that used this key to a new credential, and ask the security team about anything else."},
}


class OwnerApprovalError(Exception):
    def __init__(self, code: str, http_status: int = 409) -> None:
        super().__init__(code)
        self.code, self.http_status = code, http_status


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _stamp(value: _dt.datetime) -> str:
    return value.astimezone(_dt.UTC).isoformat()


def _utc(value: _dt.datetime) -> _dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=_dt.UTC)


def _expired(value: dict, now: _dt.datetime) -> bool:
    return _dt.datetime.fromisoformat(value["expires_at"]) <= now


def _locked(repo):
    from cremore.db.settings_store import locked_settings

    if repo.get_setting(LOCK_KEY) is None:
        repo.claim_slot(LOCK_KEY, 0, ACTOR)  # insert-if-absent: racing first writers both find it after
    return locked_settings(repo, setting_key=LOCK_KEY)


def _row(repo, key: str) -> dict | None:
    value = (repo.get_setting(key) or {}).get("value")
    return value if isinstance(value, dict) else None


def _quoted(text: str) -> str:
    """Free text in an audit note, quoted so it cannot pass for another field."""
    return json.dumps(text, ensure_ascii=False)


def _same_plan(value: dict, plan) -> bool:
    return plan is not None and plan.status in OPEN_PLAN and hmac.compare_digest(
        str(plan.plan_hash or ""), str(value.get("plan_hash", "")))


def current(repo, plan_id, now: _dt.datetime) -> dict | None:
    """The plan's owner approval as the console shows it (never the token or its digest)."""
    value = _row(repo, PLAN_PREFIX + str(plan_id))
    if not value:
        return None
    state = "EXPIRED" if value["state"] == "PENDING" and _expired(value, now) else value["state"]
    ticket = value.get("ticket")
    return {"state": state, **{key: value.get(key) for key in _SHOWN},
            "ticket": {key: ticket.get(key) for key in _TICKET_SHOWN} if isinstance(ticket, dict) else None}


def granted(repo, plan) -> bool:
    """Whether the owner approved this plan as it is now (the same plan_hash)."""
    value = _row(repo, PLAN_PREFIX + str(plan.id))
    return bool(value) and value.get("state") == "APPROVED" and hmac.compare_digest(
        str(value.get("plan_hash", "")), str(plan.plan_hash or ""))


def _askable(repo, plan, now: _dt.datetime) -> None:
    if plan.status not in OPEN_PLAN or (plan.expires_at is not None and _utc(plan.expires_at) <= now):
        raise OwnerApprovalError("OWNER_APPROVAL_PLAN_NOT_OPEN")
    if (current(repo, plan.id, now) or {}).get("state") == "APPROVED":
        raise OwnerApprovalError("OWNER_APPROVAL_ALREADY_GRANTED")


def window(repo, plan, now: _dt.datetime) -> _dt.datetime:
    """When a request asked now stops taking a decision, for a plan that can still take the owner's."""
    _askable(repo, plan, now)
    expires = now + LINK_LIFETIME
    if plan.expires_at is not None:
        expires = min(expires, _utc(plan.expires_at))
    return expires


def new_link(repo, plan, now: _dt.datetime) -> tuple[str, _dt.datetime]:
    """(token, when its link stops working) for a plan that can still take the owner's decision."""
    return secrets.token_urlsafe(32), window(repo, plan, now)


def message(plan, link: str, expires: _dt.datetime, locale: str) -> tuple[str, str]:
    """(subject, text) of the request in ``locale``: what is done to which key, why, until when, and the link."""
    words = _words(plan, locale)
    lines = [words["intro"], "",
             f"{words['action']}: {_action(plan, words)}",
             f"{words['key']}: {_key_line(plan, words)}",
             f"{words['reason']}: {words['reasons'].get(plan.reason_code, plan.reason_code)}",
             f"{words['expires']}: {expires.astimezone(_dt.UTC):%Y-%m-%d %H:%M} UTC", "",
             link, "", words["once"]]
    return words["subject"], "\n".join(lines)


def _previous(before: dict | None) -> dict | None:
    """The last decision a new request replaces, kept on the row so a decline stays in view."""
    if not before:
        return None
    if before.get("state") == "DECLINED":
        return {key: before.get(key) for key in ("state", "channel", "recipient", "decided_at", "note", "evidence")}
    return before.get("previous")


def start(repo, plan, actor: str, *, token: str, expires: _dt.datetime, channel: str, recipient: str,
          now: _dt.datetime, note: str) -> None:
    """Record the link, which ends any earlier one, with its audit row, before the message goes out."""
    digest = _digest(token)
    with _locked(repo) as bound:
        before = _row(bound, PLAN_PREFIX + str(plan.id))
        if before and before.get("state") == "APPROVED":
            raise OwnerApprovalError("OWNER_APPROVAL_ALREADY_GRANTED")
        bound.put_setting(TOKEN_PREFIX + digest, {"plan_id": str(plan.id), "expires_at": _stamp(expires)}, actor)
        bound.put_setting(PLAN_PREFIX + str(plan.id), {
            "digest": digest, "state": "PENDING", "plan_hash": plan.plan_hash, "channel": channel,
            "recipient": recipient, "requested_by": actor, "requested_at": _stamp(now), "expires_at": _stamp(expires),
            "decided_at": None, "decided_by": None, "note": None, "evidence": None, "previous": _previous(before)}, actor)
        bound.record_finding_event(FindingEvent(
            target_type="action_plan", target_id=plan.id, actor=actor, event_type="OWNER_APPROVAL_REQUESTED",
            from_status=plan.status, to_status=plan.status, note=note))
    # Pointers nobody can use any more (twice a link's lifetime old) are dropped as new links are made.
    repo.delete_settings_before(TOKEN_PREFIX, now - 2 * LINK_LIFETIME)


def withdraw(repo, plan, token: str, actor: str, note: str) -> None:
    """End a link whose message did not go out: it takes no decision, and the history says why. A decision the
    owner already made through it (the message went out after all) stands."""
    digest = _digest(token)
    with _locked(repo) as bound:
        value = _row(bound, PLAN_PREFIX + str(plan.id))
        if value and value.get("state") == "PENDING" and hmac.compare_digest(str(value.get("digest", "")), digest):
            bound.put_setting(PLAN_PREFIX + str(plan.id), {**value, "state": "NOT_SENT", "digest": ""}, actor)
        bound.record_finding_event(FindingEvent(
            target_type="action_plan", target_id=plan.id, actor=actor, event_type="OWNER_APPROVAL_NOT_SENT",
            from_status=plan.status, to_status=plan.status, note=note))


# --- asking through the company's ticket system (cremore.ticketing) --------------------------------------------------
# The ticket system asks the owner's own account there for its approval; CreMore reads the answer (cremore.ticketing
# .sweep) and counts it only from the account it asked. The owner's address is kept with its mark so plan approval
# and execution can refuse a security-side person who answered as the owner (action_plans).

def ticket_message(plan, expires: _dt.datetime, locale: str) -> tuple[str, tuple[str, ...]]:
    """(title, lines) of the approval asked in a ticket: what is done to which key, why and by when."""
    words = _words(plan, locale)
    title = f"{words['subject']} · {plan.identifier_hint or '-'}"
    return title, (words["ticket_intro"], "",
                   f"{words['action']}: {_action(plan, words)}",
                   f"{words['key']}: {_key_line(plan, words)}",
                   f"{words['reason']}: {words['reasons'].get(plan.reason_code, plan.reason_code)}",
                   f"{words['until']}: {expires.astimezone(_dt.UTC):%Y-%m-%d %H:%M} UTC",
                   f"CreMore plan: {plan.id} · {str(plan.plan_hash)[:16]}")


def start_ticket(repo, plan, actor: str, *, system: str, binding: str, recipient: str, recipient_marks, request: str,
                 expires: _dt.datetime, now: _dt.datetime, note: str) -> None:
    """Record the request, which ends any earlier link or request, with its audit row, before the ticket opens.
    ``recipient_marks``: the marks of every address the account asked carries; ``binding``: the server asked on."""
    with _locked(repo) as bound:
        before = _row(bound, PLAN_PREFIX + str(plan.id))
        if before and before.get("state") == "APPROVED":
            raise OwnerApprovalError("OWNER_APPROVAL_ALREADY_GRANTED")
        bound.put_setting(PLAN_PREFIX + str(plan.id), {
            "digest": "", "state": "PENDING", "plan_hash": plan.plan_hash, "channel": system, "recipient": recipient,
            "recipient_marks": sorted(set(recipient_marks)), "requested_by": actor, "requested_at": _stamp(now),
            "expires_at": _stamp(expires), "decided_at": None, "decided_by": None, "note": None, "evidence": None,
            "previous": _previous(before),
            "ticket": {"request": request, "system": system, "binding": binding, "ticket": None, "approval": None,
                       "approver": None, "url": None, "check_code": None, "answered_by": None, "answered_at": None}},
            actor)
        bound.record_finding_event(FindingEvent(
            target_type="action_plan", target_id=plan.id, actor=actor, event_type="OWNER_APPROVAL_REQUESTED",
            from_status=plan.status, to_status=plan.status, note=note))


def ticket_refused(repo, plan, actor: str, code: str, recipient: str) -> None:
    """A request to ask the owner in the ticket system that was refused before anything was asked (the owner not
    told apart from the security side, an address never seen, the owner's account not found): audited, since an
    attempt to answer as one's own owner is what a reviewer most needs to see."""
    repo.record_finding_event(FindingEvent(
        target_type="action_plan", target_id=plan.id, actor=actor, event_type="ACTION_PLAN_REFUSED",
        from_status=plan.status, to_status=plan.status,
        note=f"OWNER_TICKET {code if _CODE.fullmatch(str(code)) else 'TICKET_SYSTEM_ERROR'} to={recipient} "
             f"plan_hash={plan.plan_hash}"))


def reference_ok(value) -> bool:
    """Whether a ticket system's reference is one CreMore keeps and writes in an audit note."""
    return isinstance(value, str) and bool(_REFERENCE.fullmatch(value))


def _reference(value) -> str:
    if not reference_ok(value):
        raise OwnerApprovalError("OWNER_APPROVAL_TICKET_REFERENCE_INVALID", 502)
    return value


def ticket_opened(repo, plan, request: str, system: str, opened, actor: str) -> None:
    """Keep the system's references on the request they were opened for, audited. A request replaced meanwhile
    keeps its own; the audit row still names the ticket, so a person can close it."""
    refs = {"ticket": _reference(opened.ticket), "approval": _reference(opened.approval),
            "approver": _reference(opened.approver)}
    url = opened.url if (isinstance(opened.url, str) and len(opened.url) <= 500
                         and opened.url.startswith(("https://", "http://"))
                         and not any(c in opened.url for c in " \"'<>\\")) else None
    with _locked(repo) as bound:
        value = _row(bound, PLAN_PREFIX + str(plan.id))
        ticket = (value or {}).get("ticket") or {}
        if value and value.get("state") == "PENDING" and ticket.get("request") == request:
            bound.put_setting(PLAN_PREFIX + str(plan.id), {**value, "ticket": {**ticket, **refs, "url": url}}, actor)
        bound.record_finding_event(FindingEvent(
            target_type="action_plan", target_id=plan.id, actor=actor, event_type="OWNER_APPROVAL_TICKET_OPENED",
            from_status=plan.status, to_status=plan.status,
            note=f"plan_hash={plan.plan_hash} {system} ticket={refs['ticket']} approval={refs['approval']} "
                 f"approver={refs['approver']}"))


def ticket_not_opened(repo, plan, request: str, actor: str, note: str) -> None:
    """End a request whose ticket or approval did not open: it takes no decision, and the history says why."""
    with _locked(repo) as bound:
        value = _row(bound, PLAN_PREFIX + str(plan.id))
        if value and value.get("state") == "PENDING" and (value.get("ticket") or {}).get("request") == request:
            bound.put_setting(PLAN_PREFIX + str(plan.id), {**value, "state": "NOT_SENT"}, actor)
        bound.record_finding_event(FindingEvent(
            target_type="action_plan", target_id=plan.id, actor=actor, event_type="OWNER_APPROVAL_NOT_SENT",
            from_status=plan.status, to_status=plan.status, note=note))


def pending_tickets(repo, now: _dt.datetime) -> list[tuple[str, dict]]:
    """(plan id, request) of every approval asked in a ticket that is still waiting and inside its time."""
    found = []
    for entry in repo.list_settings(PLAN_PREFIX):
        value = entry.get("value")
        ticket = value.get("ticket") if isinstance(value, dict) else None
        if (isinstance(ticket, dict) and value.get("state") == "PENDING" and ticket.get("approval")
                and not _expired(value, now)):
            found.append((entry["key"][len(PLAN_PREFIX):], value))
    return found


def ticket_checked(repo, plan_id: str, request: str, code: str | None) -> None:
    """The last read's failure code (None once a read works), shown on the request; written only on a change."""
    code = code if code is None or _CODE.fullmatch(str(code)) else "TICKET_SYSTEM_ERROR"
    value = _row(repo, PLAN_PREFIX + plan_id)
    ticket = (value or {}).get("ticket") or {}
    if not value or ticket.get("request") != request or ticket.get("check_code") == code:
        return
    with _locked(repo) as bound:
        value = _row(bound, PLAN_PREFIX + plan_id)
        ticket = (value or {}).get("ticket") or {}
        if value and value.get("state") == "PENDING" and ticket.get("request") == request:
            bound.put_setting(PLAN_PREFIX + plan_id, {**value, "ticket": {**ticket, "check_code": code}}, ACTOR)


def ticket_answered(repo, plan_id: str, request: str, answer, now: _dt.datetime, plan_of, *,
                    separate: bool = False) -> str | None:
    """Record the answer the ticket system reports, once, for the plan as it still is; audited with it. Only the
    account asked answers for the owner: another one's answer (a substitute, a group member) ends the request as
    ANSWERED_BY_OTHER. With ``separate`` (company sign-in) the account asked must still be told apart, by
    address, from the people on the security side of the plan as it is now; otherwise the request ends as
    NOT_INDEPENDENT and can be asked again. The state recorded, or None (still waiting, replaced, ended, or the plan
    changed)."""
    if answer.state not in ("APPROVED", "DECLINED"):
        return None
    by = answer.by if isinstance(answer.by, str) and _REFERENCE.fullmatch(answer.by) else ""
    at = answer.at if isinstance(answer.at, str) and _WHEN.fullmatch(answer.at) else ""
    with _locked(repo) as bound:
        value = _row(bound, PLAN_PREFIX + plan_id)
        ticket = (value or {}).get("ticket") or {}
        if not value or value.get("state") != "PENDING" or ticket.get("request") != request or _expired(value, now):
            return None
        plan = plan_of(plan_id)
        if not _same_plan(value, plan):
            return None  # the plan closed or changed: nothing is left to decide
        system = ticket.get("system", "")
        refs = f"{system} ticket={ticket.get('ticket')} approval={ticket.get('approval')}"
        answered = {**ticket, "answered_by": by or None, "answered_at": at or None, "check_code": None}
        refused = None
        if not by or by != ticket.get("approver"):
            refused = ("ANSWERED_BY_OTHER", f"by={by or '-'} asked={ticket.get('approver')}")
        elif separate and not independent(bound, value, plan):
            refused = ("NOT_INDEPENDENT", "reason=SECURITY_SIDE_OR_UNKNOWN_ADDRESS")
        if refused:
            bound.put_setting(PLAN_PREFIX + plan_id, {**value, "state": refused[0], "decided_at": _stamp(now),
                                                    "ticket": answered}, ACTOR)
            bound.record_finding_event(FindingEvent(
                target_type="action_plan", target_id=plan.id, actor=ACTOR, event_type="OWNER_APPROVAL_TICKET_REFUSED",
                from_status=plan.status, to_status=plan.status,
                note=f"plan_hash={plan.plan_hash} {refs} answer={answer.state} {refused[1]}"))
            return refused[0]
        decider = f"{system}:user:{by}"
        bound.put_setting(PLAN_PREFIX + plan_id, {
            **value, "state": answer.state, "decided_at": _stamp(now), "decided_by": decider,
            "evidence": f"{system} ticket #{ticket.get('ticket')} approval #{ticket.get('approval')}",
            "ticket": answered}, ACTOR)
        bound.record_finding_event(FindingEvent(
            target_type="action_plan", target_id=plan.id, actor=decider,
            event_type="OWNER_APPROVAL_GRANTED" if answer.state == "APPROVED" else "OWNER_APPROVAL_DECLINED",
            from_status=plan.status, to_status=plan.status,
            note=f"plan_hash={plan.plan_hash} channel={system} to={value.get('recipient', '')} {refs} "
                 f"answered_at={at or '-'}"))
    return answer.state


def record(repo, plan, actor: str, *, owner: str, evidence: str, decision: str, note: str,
           now: _dt.datetime) -> dict:
    """The local operator's record of the approval the owner gave elsewhere, with its reference; audited with it."""
    if decision not in DECISIONS:
        raise OwnerApprovalError("OWNER_APPROVAL_DECISION_INVALID", 422)
    _askable(repo, plan, now)
    state = DECISIONS[decision]
    with _locked(repo) as bound:
        before = _row(bound, PLAN_PREFIX + str(plan.id))
        if before and before.get("state") == "APPROVED":
            raise OwnerApprovalError("OWNER_APPROVAL_ALREADY_GRANTED")
        bound.put_setting(PLAN_PREFIX + str(plan.id), {
            "digest": "", "state": state, "plan_hash": plan.plan_hash, "channel": "record", "recipient": owner,
            "requested_by": actor, "requested_at": _stamp(now), "expires_at": _stamp(now), "decided_at": _stamp(now),
            "decided_by": actor, "note": note or None, "evidence": evidence, "previous": _previous(before)}, actor)
        bound.record_finding_event(FindingEvent(
            target_type="action_plan", target_id=plan.id, actor=actor, event_type="OWNER_APPROVAL_RECORDED",
            from_status=plan.status, to_status=plan.status,
            note=f"plan_hash={plan.plan_hash} decision={state} owner={_quoted(owner)} evidence={_quoted(evidence)}"
                 + (f" note={_quoted(note)}" if note else "")))
    return current(repo, plan.id, now)


def _opened(repo, token) -> tuple[dict, str]:
    """The plan approval a token belongs to. Anything a guess could learn from is the same 404."""
    if not isinstance(token, str) or not _TOKEN.fullmatch(token):
        raise OwnerApprovalError("OWNER_APPROVAL_LINK_INVALID", 404)
    digest = _digest(token)
    pointer = _row(repo, TOKEN_PREFIX + digest)
    value = _row(repo, PLAN_PREFIX + str(pointer.get("plan_id"))) if pointer else None
    if not value or not hmac.compare_digest(str(value.get("digest", "")), digest):
        raise OwnerApprovalError("OWNER_APPROVAL_LINK_INVALID", 404)  # unknown, or a later link replaced it
    return value, str(pointer["plan_id"])


def _holder_check(value: dict, holder: dict) -> None:
    """The signed-in person is the one the link went to (their verified email is its address). Addresses are
    ASCII (contact.recipients), so an email is compared as ASCII too: Unicode case folding would let a Kelvin sign
    stand in for a K."""
    email = str(holder.get("email", ""))
    if not email.isascii() or not hmac.compare_digest(
            email.lower().encode(), str(value.get("recipient", "")).lower().encode()):
        raise OwnerApprovalError("OWNER_APPROVAL_NOT_RECIPIENT", 403)


def _public(value: dict, plan) -> dict:
    """What the link's page shows: the action on which key and why, and where the decision stands."""
    state = value["state"]
    if state == "PENDING" and not _same_plan(value, plan):
        state = "WITHDRAWN"  # the plan closed: nothing is left to decide
    return {"state": state, "action_type": plan.action_type, "reason_code": plan.reason_code,
            "identifier_hint": plan.identifier_hint, "user_name": plan.user_name, "account_id": plan.account_id,
            # Another provider's credential says which provider, and what a revoke takes away when that is not the
            # credential; its identifiers are in the hint.
            **({"provider": plan.target.get("provider")} if plan.target else {}),
            **({"revokes": plan.target["revokes"]} if plan.target and plan.target.get("revokes") else {}),
            "requested_at": value["requested_at"], "expires_at": value["expires_at"], "decided_at": value.get("decided_at")}


def view(repo, token, now: _dt.datetime, plan_of, holder: dict) -> dict:
    """The request as the link's page shows it to the person it went to, until the link's end; reading decides
    nothing."""
    value, plan_id = _opened(repo, token)
    if _expired(value, now):
        raise OwnerApprovalError("OWNER_APPROVAL_EXPIRED", 410)
    _holder_check(value, holder)
    plan = plan_of(plan_id)
    if plan is None:
        raise OwnerApprovalError("OWNER_APPROVAL_LINK_INVALID", 404)
    return _public(value, plan)


def decide(repo, token, decision, note, now: _dt.datetime, plan_of, holder: dict) -> dict:
    """Record the owner's decision, once, for the plan as it still is; audited with it."""
    if decision not in DECISIONS:
        raise OwnerApprovalError("OWNER_APPROVAL_DECISION_INVALID", 422)
    _value, plan_id = _opened(repo, token)
    digest = _digest(token)
    with _locked(repo) as bound:
        value = _row(bound, PLAN_PREFIX + plan_id)
        if not value or not hmac.compare_digest(str(value.get("digest", "")), digest):
            raise OwnerApprovalError("OWNER_APPROVAL_LINK_INVALID", 404)
        if _expired(value, now):
            raise OwnerApprovalError("OWNER_APPROVAL_EXPIRED", 410)
        _holder_check(value, holder)
        if value["state"] != "PENDING":
            raise OwnerApprovalError("OWNER_APPROVAL_ALREADY_DECIDED")
        plan = plan_of(plan_id)
        if not _same_plan(value, plan):
            raise OwnerApprovalError("OWNER_APPROVAL_PLAN_CHANGED")
        # The owner is someone other than the people on the security side of this plan.
        if holder["subject"] in {value.get("requested_by"), plan.requested_by, plan.approved_by}:
            raise OwnerApprovalError("OWNER_APPROVAL_SAME_PERSON", 403)
        state = DECISIONS[decision]
        decided = {**value, "state": state, "decided_at": _stamp(now), "decided_by": holder["subject"],
                   "note": note or None}
        bound.put_setting(PLAN_PREFIX + plan_id, decided, holder["subject"])
        bound.record_finding_event(FindingEvent(
            target_type="action_plan", target_id=plan.id, actor=holder["subject"],
            event_type="OWNER_APPROVAL_GRANTED" if state == "APPROVED" else "OWNER_APPROVAL_DECLINED",
            from_status=plan.status, to_status=plan.status,
            note=f"plan_hash={plan.plan_hash} channel={value.get('channel', '')} to={value.get('recipient', '')}"
                 + (f" note={_quoted(note)}" if note else "")))
    return _public(decided, plan)


# --- the execution gate (N2b-2) -------------------------------------------------------------------------------------

def switch(repo) -> dict:
    """Whether execution waits for the owner's approval: on unless an Admin turned it off."""
    record = repo.get_setting(KEY)
    value = (record or {}).get("value") or {}
    return {"required": value.get("required", True) is not False, "updated_by": (record or {}).get("updated_by") or None,
            "updated_at": (record or {}).get("updated_at")}


def required(repo) -> bool:
    return switch(repo)["required"]


def set_required(repo, required_: bool, actor: str, target) -> None:
    """An Admin turns the wait on or off; the change and its audit row are one transaction."""
    with _locked(repo) as bound:
        if switch(bound)["required"] != required_:
            bound.put_setting(KEY, {"required": required_}, actor)
            bound.record_finding_event(FindingEvent(
                target_type="owner_approval_policy", target_id=target, actor=actor,
                event_type="OWNER_APPROVAL_POLICY_CHANGED", note=f"required={'on' if required_ else 'off'}"))


def needed(repo, plan) -> bool:
    """Whether executing this plan still waits for its owner."""
    return plan.action_type in OWNER_ACTIONS and required(repo) and not granted(repo, plan)


def owner_decider(repo, plan) -> str | None:
    """The subject who decided as the plan's owner through a link (an operator's record names nobody)."""
    value = _row(repo, PLAN_PREFIX + str(plan.id))
    if (value and value.get("channel") != "record" and not value.get("ticket")
            and value.get("state") in ("APPROVED", "DECLINED")):
        return value.get("decided_by")
    return None


def ticket_owner_marks(repo, plan, *, pending: bool = False) -> set[str]:
    """The address marks (cremore.governance.principals) of the account that answered in the ticket system as the
    plan's owner, or with ``pending`` also of the account still being asked; empty when there is none."""
    value = _row(repo, PLAN_PREFIX + str(plan.id))
    states = ("APPROVED", "DECLINED", "PENDING") if pending else ("APPROVED", "DECLINED")
    if value and value.get("ticket") and value.get("state") in states:
        return set(value.get("recipient_marks") or [])
    return set()


def independent(repo, value: dict, plan) -> bool:
    """Whether the account a ticket asks is told apart, by every address it carries, from each person on the
    security side of the plan (who asked, requested and approved it); a person whose sign-in never carried an
    address cannot be told apart."""
    from cremore.governance import principals

    marks = set(value.get("recipient_marks") or [])
    subjects = [who for who in (value.get("requested_by"), plan.requested_by, plan.approved_by) if who]
    known = principals.marks(repo, subjects)
    return bool(marks) and not any(mark is None or mark in marks for mark in known.values())


def publicly_exposed(repo, credential_id) -> bool:
    """A current exposure of the credential in a public place that a connection's own scan found (not a label
    anyone pasting text can set), on a finding nobody closed as a false positive."""
    finding = repo.get_finding_for_credential(credential_id)
    if finding is None or finding.workflow_status == "FALSE_POSITIVE":
        return False
    return any(exposure.source_connection_id is not None
               and str((exposure.metadata or {}).get("exposure") or "").lower() == "public"
               and exposure.status not in ("REMOVED", "FALSE_POSITIVE")
               for exposure in repo.exposures_for_credential(credential_id))


def emergency(repo, plan_id) -> dict | None:
    """The plan's emergency containment, if an Admin declared one: who, when, why, and whether the owner was told."""
    return _row(repo, EMERGENCY_PREFIX + str(plan_id))


def emergency_applied(repo, plan) -> bool:
    """Whether a declared emergency is what let this plan's provider write start: the write began after the
    declaration while the owner's approval was still missing. A declaration that never ran, or a plan its owner
    approved before it ran, leaves nothing to tell."""
    record = emergency(repo, plan.id)
    started = plan.provider_write_started_at
    if not record or started is None or granted(repo, plan):
        return False
    return _dt.datetime.fromisoformat(record["at"]) <= _utc(started)


def emergency_view(repo, plan) -> dict | None:
    """The emergency as the console shows it: the fields it names, and whether it was applied."""
    record = emergency(repo, plan.id)
    if not record:
        return None
    return {**{key: record.get(key) for key in ("by", "at", "reason", "noticed_at", "noticed_by", "notice_channel",
                                                "notice_to", "notice_evidence")},
            "applied": emergency_applied(repo, plan),
            "notice_pending": bool(record.get("notice_pending")) and emergency_applied(repo, plan)}


def declare_emergency(repo, plan, actor: str, reason: str, now: _dt.datetime) -> None:
    """An Admin's containment of a publicly exposed key without its owner's approval: audited before the provider is
    touched, and the owner is told afterwards once it ran."""
    with _locked(repo) as bound:
        bound.put_setting(EMERGENCY_PREFIX + str(plan.id), {
            "by": actor, "at": _stamp(now), "reason": reason, "notice_pending": True, "noticed_at": None,
            "noticed_by": None, "notice_channel": None, "notice_to": None, "notice_evidence": None}, actor)
        bound.record_finding_event(FindingEvent(
            target_type="action_plan", target_id=plan.id, actor=actor, event_type="ACTION_PLAN_EMERGENCY",
            from_status=plan.status, to_status=plan.status, note=f"plan_hash={plan.plan_hash} reason={_quoted(reason)}"))


def notice_message(plan, record: dict, locale: str, *, declined: bool = False) -> tuple[str, str]:
    """(subject, text) telling the owner what an emergency containment did, in ``locale``; no link."""
    words = _NOTICE[locale if locale in LOCALES else "ko"]
    key = plan.identifier_hint or "-"
    if plan.user_name:
        key += f" ({words['user']} {plan.user_name}, {words['account']} {plan.account_id})"
    at = _dt.datetime.fromisoformat(record["at"]).astimezone(_dt.UTC)
    opening = words["done"] if plan.status == "VERIFIED" else words["tried"]
    lines = [opening + (" " + words["declined"] if declined else ""), "", f"{words['key']}: {key}",
             f"{words['when']}: {at:%Y-%m-%d %H:%M} UTC", f"{words['why']}: {record['reason']}", "", words["next"]]
    return words["subject"], "\n".join(lines)


def noticed(repo, plan, actor: str, *, channel: str, recipient: str, evidence: str | None, note: str,
            now: _dt.datetime) -> dict:
    """Claim the notice of an applied emergency (before CreMore sends it, or as the record of how the owner was
    told); audited with it. A second claim finds nothing pending."""
    with _locked(repo) as bound:
        record = _row(bound, EMERGENCY_PREFIX + str(plan.id))
        if not record or not record.get("notice_pending") or not emergency_applied(bound, plan):
            raise OwnerApprovalError("OWNER_NOTICE_NOT_PENDING")
        bound.put_setting(EMERGENCY_PREFIX + str(plan.id), {
            **record, "notice_pending": False, "noticed_at": _stamp(now), "noticed_by": actor,
            "notice_channel": channel, "notice_to": recipient, "notice_evidence": evidence or None}, actor)
        bound.record_finding_event(FindingEvent(
            target_type="action_plan", target_id=plan.id, actor=actor, event_type="OWNER_NOTIFIED_AFTER",
            from_status=plan.status, to_status=plan.status, note=note))
    return emergency(repo, plan.id)


def notice_not_sent(repo, plan, actor: str, code: str) -> None:
    """A claimed notice whose message did not go out: pending again, and the history says why."""
    with _locked(repo) as bound:
        record = _row(bound, EMERGENCY_PREFIX + str(plan.id))
        if record and not record.get("notice_pending"):
            bound.put_setting(EMERGENCY_PREFIX + str(plan.id), {
                **record, "notice_pending": True, "noticed_at": None, "noticed_by": None, "notice_channel": None,
                "notice_to": None, "notice_evidence": None}, actor)
        bound.record_finding_event(FindingEvent(
            target_type="action_plan", target_id=plan.id, actor=actor, event_type="OWNER_NOTICE_NOT_SENT",
            from_status=plan.status, to_status=plan.status, note=code))
