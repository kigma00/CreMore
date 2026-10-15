"""The owner's approval of a key action plan: a link stored as a digest only, audited before it goes out, decided
once by the signed-in person it went to (not by the people on the security side of the plan), only for a plan still
open, replaced by a newer link that keeps the last decline, and the local operator's record with its evidence."""

import datetime as dt
import json
import uuid

import pytest

from cremore.db.repository import InMemoryRepository
from cremore.db.sql import SqlRepository, create_all, make_engine
from cremore.domain.models import ActionPlan
from cremore.remediation import owner_approval as oa

NOW = dt.datetime(2026, 9, 29, 3, 0, tzinfo=dt.UTC)
KIM = {"subject": "sub-kim", "email": "Kim@Example.com"}


def plan(**changes):
    fields = {"status": "APPROVED", "plan_hash": "a" * 64, "expires_at": NOW + dt.timedelta(days=7),
              "requested_by": "sub-rita", "approved_by": "sub-ada", **changes}
    return ActionPlan(id=uuid.uuid4(), credential_id=uuid.uuid4(), action_type="DISABLE_ACCESS_KEY",
                      identifier_hint="AKIA…WXYZ", user_name="deploy-bot", account_id="123456789012",
                      reason_code="EXPOSURE_CONTAINMENT", **fields)


@pytest.fixture(params=["memory", "sqlite"])
def repo(request):
    if request.param == "memory":
        return InMemoryRepository()
    engine = make_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return SqlRepository(engine)


def audited(repo):
    """Every owner-approval audit row, whichever store: (event type, actor, note)."""
    if isinstance(repo, InMemoryRepository):
        rows = [(e.event_type, e.actor, e.note) for e in repo.finding_events.values()]
    else:
        from sqlalchemy import select

        from cremore.db.schema import finding_events
        with repo.engine.connect() as conn:
            rows = [(row.event_type, row.actor, row.note) for row in conn.execute(select(finding_events))]
    return [row for row in rows if row[0].startswith("OWNER_APPROVAL")]


def link(repo, target, recipient="kim@example.com", channel="mail", now=NOW, actor="sub-rita"):
    token, expires = oa.new_link(repo, target, now)
    oa.start(repo, target, actor, token=token, expires=expires, channel=channel, recipient=recipient, now=now,
             note=f"{channel} · to={recipient}")
    return token


def test_a_link_is_kept_as_a_digest_and_only_its_recipient_decides_once(repo):
    target = plan()
    token = link(repo, target)
    assert len(token) == 43
    stored = json.dumps([repo.get_setting(oa.PLAN_PREFIX + str(target.id)), repo.list_settings(oa.TOKEN_PREFIX)], default=str)
    assert token not in stored
    assert audited(repo) == [("OWNER_APPROVAL_REQUESTED", "sub-rita", "mail · to=kim@example.com")]
    shown = oa.view(repo, token, NOW, lambda _id: target, KIM)  # the address matches whatever its case
    assert shown == {"state": "PENDING", "action_type": "DISABLE_ACCESS_KEY", "reason_code": "EXPOSURE_CONTAINMENT",
                     "identifier_hint": "AKIA…WXYZ", "user_name": "deploy-bot", "account_id": "123456789012",
                     "requested_at": NOW.isoformat(), "expires_at": (NOW + oa.LINK_LIFETIME).isoformat(), "decided_at": None}
    # Someone else signed in, even holding the link, neither reads nor decides.
    other = {"subject": "sub-lee", "email": "lee@example.com"}
    for call in (lambda: oa.view(repo, token, NOW, lambda _id: target, other),
                 lambda: oa.decide(repo, token, "approve", None, NOW, lambda _id: target, other)):
        with pytest.raises(oa.OwnerApprovalError) as refused:
            call()
        assert (refused.value.code, refused.value.http_status) == ("OWNER_APPROVAL_NOT_RECIPIENT", 403)
    assert oa.current(repo, target.id, NOW)["recipient"] == "kim@example.com" and not oa.granted(repo, target)
    decided = oa.decide(repo, token, "approve", "배포 창에 맞춰 진행", NOW + dt.timedelta(hours=1), lambda _id: target, KIM)
    assert decided["state"] == "APPROVED" and oa.granted(repo, target)
    assert oa.current(repo, target.id, NOW)["note"] == "배포 창에 맞춰 진행"
    with pytest.raises(oa.OwnerApprovalError) as again:
        oa.decide(repo, token, "decline", None, NOW + dt.timedelta(hours=2), lambda _id: target, KIM)
    assert again.value.code == "OWNER_APPROVAL_ALREADY_DECIDED"
    # The same approval does not cover another plan content, and a granted approval is not asked again.
    assert not oa.granted(repo, target.model_copy(update={"plan_hash": "b" * 64}))
    with pytest.raises(oa.OwnerApprovalError) as granted:
        oa.new_link(repo, target, NOW)
    assert granted.value.code == "OWNER_APPROVAL_ALREADY_GRANTED"
    assert audited(repo)[1:] == [("OWNER_APPROVAL_GRANTED", "sub-kim",
                                  f'plan_hash={"a" * 64} channel=mail to=kim@example.com note="배포 창에 맞춰 진행"')]


def test_an_email_matches_only_as_the_same_ascii_address(repo):
    target = plan()
    token = link(repo, target)
    # A Kelvin sign folds to "k" under Unicode case folding; it is not kim@example.com.
    for email in (chr(0x212A) + "im@example.com", "kim@example.com.evil.test", "kim@example.co"):
        with pytest.raises(oa.OwnerApprovalError) as refused:
            oa.view(repo, token, NOW, lambda _id: target, {"subject": "sub-x", "email": email})
        assert refused.value.code == "OWNER_APPROVAL_NOT_RECIPIENT", email


@pytest.mark.parametrize("who", ["sub-rita", "sub-ada", "sub-link"])
def test_nobody_on_the_security_side_of_the_plan_decides_as_its_owner(repo, who):
    target = plan()
    token = link(repo, target, "rita@example.com", actor="sub-link")
    with pytest.raises(oa.OwnerApprovalError) as refused:
        oa.decide(repo, token, "approve", None, NOW, lambda _id: target, {"subject": who, "email": "rita@example.com"})
    assert (refused.value.code, refused.value.http_status) == ("OWNER_APPROVAL_SAME_PERSON", 403)
    assert not oa.granted(repo, target)


def test_a_newer_link_ends_the_older_one_and_guesses_learn_nothing(repo):
    target = plan()
    first = link(repo, target)
    second = link(repo, target, "lee@example.com", "slack")
    for token in (first, "x" * 43, "short", None, "a" * 42 + "!"):
        with pytest.raises(oa.OwnerApprovalError) as refused:
            oa.view(repo, token, NOW, lambda _id: target, KIM)
        assert (refused.value.code, refused.value.http_status) == ("OWNER_APPROVAL_LINK_INVALID", 404)
    assert oa.view(repo, second, NOW, lambda _id: target, {"subject": "sub-lee", "email": "lee@example.com"})["state"] == "PENDING"
    assert oa.current(repo, target.id, NOW)["recipient"] == "lee@example.com"


def test_a_link_stops_with_time_and_with_a_closed_plan(repo):
    target = plan(expires_at=NOW + dt.timedelta(hours=10))
    token = link(repo, target)
    assert oa.current(repo, target.id, NOW)["expires_at"] == (NOW + dt.timedelta(hours=10)).isoformat()  # the plan's own end
    later = NOW + dt.timedelta(hours=11)
    assert oa.current(repo, target.id, later)["state"] == "EXPIRED"
    for call in (lambda: oa.view(repo, token, later, lambda _id: target, KIM),
                 lambda: oa.decide(repo, token, "approve", None, later, lambda _id: target, KIM)):
        with pytest.raises(oa.OwnerApprovalError) as refused:  # nothing about the plan after the link's end
            call()
        assert (refused.value.code, refused.value.http_status) == ("OWNER_APPROVAL_EXPIRED", 410)
    token = link(repo, target)
    closed = target.model_copy(update={"status": "CANCELLED"})
    assert oa.view(repo, token, NOW, lambda _id: closed, KIM)["state"] == "WITHDRAWN"
    for changed in (target.model_copy(update={"plan_hash": "c" * 64}), closed, None):
        with pytest.raises(oa.OwnerApprovalError) as refused:
            oa.decide(repo, token, "approve", None, NOW, lambda _id, changed=changed: changed, KIM)
        assert refused.value.code == "OWNER_APPROVAL_PLAN_CHANGED"
    with pytest.raises(oa.OwnerApprovalError) as refused:
        oa.decide(repo, token, "maybe", None, NOW, lambda _id: target, KIM)
    assert refused.value.code == "OWNER_APPROVAL_DECISION_INVALID"
    for closed_plan in (target.model_copy(update={"status": "VERIFIED"}), plan(expires_at=NOW)):
        with pytest.raises(oa.OwnerApprovalError) as refused:
            oa.new_link(repo, closed_plan, NOW)
        assert refused.value.code == "OWNER_APPROVAL_PLAN_NOT_OPEN"


def test_a_new_request_keeps_the_last_decline_and_an_unsent_link_takes_no_decision(repo):
    target = plan(status="PENDING_APPROVAL")
    token = link(repo, target)
    assert oa.decide(repo, token, "decline", "급여 배치가 이 키를 씀", NOW, lambda _id: target, KIM)["state"] == "DECLINED"
    assert not oa.granted(repo, target)
    token = link(repo, target)  # after talking it over, a new link; the decline stays in view
    previous = oa.current(repo, target.id, NOW)["previous"]
    assert (previous["state"], previous["recipient"], previous["note"]) == ("DECLINED", "kim@example.com", "급여 배치가 이 키를 씀")
    oa.withdraw(repo, target, token, "sub-rita", "mail · SMTP_UNAVAILABLE")
    assert oa.current(repo, target.id, NOW)["state"] == "NOT_SENT"
    with pytest.raises(oa.OwnerApprovalError) as refused:
        oa.decide(repo, token, "approve", None, NOW, lambda _id: target, KIM)
    assert refused.value.http_status == 404
    assert [kind for kind, _actor, _note in audited(repo)] == [
        "OWNER_APPROVAL_REQUESTED", "OWNER_APPROVAL_DECLINED", "OWNER_APPROVAL_REQUESTED", "OWNER_APPROVAL_NOT_SENT"]


def test_a_decision_made_before_a_send_is_known_to_have_failed_stands(repo):
    target = plan()
    token = link(repo, target)
    oa.decide(repo, token, "approve", None, NOW, lambda _id: target, KIM)  # the message went out after all
    oa.withdraw(repo, target, token, "sub-rita", "slack · SLACK_UNAVAILABLE")
    assert oa.current(repo, target.id, NOW)["state"] == "APPROVED" and oa.granted(repo, target)


def test_the_local_operator_records_the_owner_approval_with_its_evidence(repo):
    target = plan()
    shown = oa.record(repo, target, "local", owner="김개발 (kim@example.com)", evidence="회신 메일 2026-09-29",
                      decision="approve", note="금요일 이후", now=NOW)
    assert (shown["state"], shown["channel"], shown["recipient"], shown["evidence"]) == (
        "APPROVED", "record", "김개발 (kim@example.com)", "회신 메일 2026-09-29")
    assert oa.granted(repo, target)
    # Free text is quoted: an owner written as 'kim evidence=TICKET-9999' cannot pass for evidence.
    assert audited(repo) == [("OWNER_APPROVAL_RECORDED", "local", (f"plan_hash={'a' * 64} decision=APPROVED "
                              'owner="김개발 (kim@example.com)" evidence="회신 메일 2026-09-29" note="금요일 이후"'))]
    with pytest.raises(oa.OwnerApprovalError) as again:
        oa.record(repo, target, "local", owner="x", evidence="y", decision="decline", note="", now=NOW)
    assert again.value.code == "OWNER_APPROVAL_ALREADY_GRANTED"


def test_the_message_is_cremore_own_text_in_either_language():
    target = plan()
    expires = NOW + dt.timedelta(hours=72)
    subject, text = oa.message(target, "https://cremore.example.com/owner-approval#TOKEN", expires, "ko")
    assert subject == "[CreMore] AWS 액세스 키 조치 승인 요청"
    for line in ("조치: 액세스 키 비활성화", "대상 키: AKIA…WXYZ (IAM 사용자 deploy-bot, 계정 123456789012)", "사유: 노출 차단",
                 "링크 만료: 2026-10-02 03:00 UTC", "https://cremore.example.com/owner-approval#TOKEN"):
        assert line in text.splitlines(), line
    subject, text = oa.message(target, "https://cremore.example.com/owner-approval#TOKEN", expires, "en")
    assert subject.startswith("[CreMore] Approval") and "Action: Disable the access key" in text
    assert oa.message(target, "x", expires, "fr") == oa.message(target, "x", expires, "ko")
