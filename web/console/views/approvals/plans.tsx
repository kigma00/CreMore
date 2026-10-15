"use client";

/* Credential action plans: one plan's card (what it does to which key or credential, who asked and approved, the
 * operational review, the owner's approval, the buttons this person may press), the window that requests a new
 * plan for one credential, and the credential panel's list of its plans. An AWS access key runs at once; another
 * provider's credential is queued and the worker runs it. The server binds every step to the plan's hash. */

import { useRef, useState } from "react";

import { useLocale } from "@/components/locale";
import { DashboardAPIError } from "@/lib/dashboard-api";
import { randomId, reasonText, send, useApi } from "@/console/data";
import { Ic } from "@/console/icons";
import { actorLabel } from "@/console/labels";
import { Modal, useToast } from "@/console/layer";
import { serviceName } from "@/console/logos";
import { fmtDT, rel, type Say, useL } from "@/console/text";
import { AreaField, Banner, Card, CardBody, Fact, Facts, Loading, SelectField, StateChip, TextField } from "@/console/ui";
import {
  ACTION_WORDS, type ActionType, actionWords, type Actor, blankConsumer, blankReview, type Consumer, type CredentialPolicy, isIrreversible, isRotation, NEXT_WORDS,
  OWNER_TONE, OWNER_WORDS, type Plan, type PlanList, planPermissions, planStatus, type Policy, PROVIDER_ACTIONS, READINESS_WORDS, type Reason,
  REASON_WORDS, referenceText, resultCodeWords, RESULT_WORDS, type Review, reviewBody, type Rotation, say, STAGE_WORDS, STATUS_TONE, STATUS_WORDS,
  validRotation,
} from "@/console/views/approvals/model";
import type { ContactChannels } from "@/console/views/integrations/contact-delivery";
import { sharedNote } from "@/console/views/integrations/model";
import { IndependentAuthorization, type SignedApproval } from "./independent-authorization";

type Step = "approve" | "execute" | "recheck" | "cancel";

const isProvider = (plan: Plan) => plan.target?.kind === "provider_credential";

/** The target's second line: an AWS key's IAM user and account, or the provider whose list names the credential. */
function targetLine(plan: Plan, L: Say) {
  if (!isProvider(plan)) return `${plan.user_name} · ${plan.account_id}`;
  return L(`${serviceName(plan.target?.provider)} 발급 목록의 식별자`, `Identifiers from ${serviceName(plan.target?.provider)}'s own list`);
}

/** Everything a provider plan binds about its target and who acts, for whoever approves or runs it. */
function ProviderTarget({ plan }: { plan: Plan }) {
  const L = useL();
  if (!isProvider(plan)) return null;
  return <Fact label={L("공급자 식별자 · 실행 연동", "Provider identifiers · acting integration")}>
    <span className="mono small cell-wrap">{referenceText(plan)}</span>
    <div className="subtle small cell-wrap">{plan.target?.origin} · {plan.target?.connection_name ?? plan.target?.connection_id}
      {plan.target?.auth_method ? ` (${plan.target.auth_method}${plan.target.subject ? ` · ${plan.target.subject}` : ""})` : ""}</div></Fact>;
}

export function PlanCard({ plan, policy, actor, onChanged }: { plan: Plan; policy: Policy; actor: Actor; onChanged: (plan: Plan) => void }) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const [confirm, setConfirm] = useState<Step | null>(null);
  const [asking, setAsking] = useState(false);
  const [urgent, setUrgent] = useState(false);
  const [telling, setTelling] = useState(false);
  const [busy, setBusy] = useState(false);
  const status = planStatus(plan);
  const may = planPermissions(plan, policy, actor, L);
  const rotation = isRotation(plan.action_type);
  const review = plan.operational_review;
  const readiness = plan.readiness;
  const owner = plan.owner_approval;
  const local = policy.auth_mode.toLowerCase() === "local";  // no link: the operator records the owner's approval
  const ticketSystem = policy.owner_ticket_system ?? null;  // the company's ticket system, asked in either mode
  const codeWords = resultCodeWords(plan);
  const [recording, setRecording] = useState(false);
  const run = async (step: Step, selfApproval = false, signedApproval?: SignedApproval) => {
    setBusy(true);
    try {
      const body = step === "cancel" ? {} : { plan_hash: plan.plan_hash,
        ...(signedApproval ? { signed_approval: signedApproval } : {}),
        ...(step === "approve" && selfApproval ? { self_approval_confirmed: true } : {}) };
      const next = await send<Plan>(`action-plans/${plan.id}/${step}`, "POST", body);
      toast({ approve: L("계획을 승인했습니다", "Plan approved"),
        execute: next.status === "QUEUED" ? L("실행을 접수했습니다. 작업자가 곧 실행하고 결과를 확인합니다.", "Execution queued. The worker runs it shortly and reads the result back.")
          : L("실행을 요청했습니다", "Execution requested"),
        recheck: L("상태를 다시 확인하도록 요청했습니다", "Recheck requested"), cancel: L("계획을 취소했습니다", "Plan cancelled") }[step]);
      setConfirm(null);
      onChanged({ ...plan, ...next });
    } catch (reason) { toast(reasonText(reason, L), "bad"); }
    finally { setBusy(false); }
  };
  return <Card level={3} className="plan-card" title={L(...actionWords(plan.action_type, plan.target?.revokes))}
    right={<StateChip tone={STATUS_TONE[status]}>{rotation && status === "VERIFIED" && plan.result_kind ? say(RESULT_WORDS, plan.result_kind, L) : L(...STATUS_WORDS[status])}</StateChip>}>
    <CardBody>
      <Facts>
        <Fact label={isProvider(plan) ? L("대상 자격증명", "Credential") : L("대상 키", "Key")}><span className="mono cell-wrap">{plan.identifier_hint}</span>
          <div className="subtle small">{targetLine(plan, L)}</div></Fact>
        <ProviderTarget plan={plan} />
        <Fact label={L("사유", "Reason")}>{say(REASON_WORDS, plan.reason_code, L)}</Fact>
        <Fact label={L("요청", "Requested")}>{actorLabel(plan.requested_by, L)}<div className="subtle small">{fmtDT(plan.requested_at, locale)}</div></Fact>
        <Fact label={plan.self_approved ? L("승인 · 본인 승인", "Approved · self-approved") : L("승인", "Approved")}>
          {plan.approved_by ? <>{actorLabel(plan.approved_by, L)}<div className="subtle small">{fmtDT(plan.approved_at ?? null, locale)}</div></> : <span className="subtle">{L("대기", "Waiting")}</span>}</Fact>
        <Fact label={L("계획 기한", "Plan expires")}>{fmtDT(plan.expires_at, locale)}<div className="subtle small">{rel(plan.expires_at, locale)}</div></Fact>
        {plan.verified_at ? <Fact label={L("완료 확인", "Verified")}>{fmtDT(plan.verified_at, locale)}</Fact> : null}
      </Facts>
      <div className="plan-hash"><span className="subtle small">{L("승인·실행이 고정되는 내용 해시", "Content hash approval and execution bind to")}</span><code className="mono">{plan.plan_hash}</code></div>
      <div className="ig-section">
        <div className="ig-section-head"><h3>{L("운영 검토", "Operational review")}</h3>
          <StateChip tone={readiness?.execution_gate_passed ? "ok" : "warn"}>{readiness?.execution_gate_passed ? (readiness.status === "EMERGENCY_REVIEW_REQUIRED" ? L("긴급 조치로 준비됨", "Ready as an emergency") : L("준비됨", "Ready")) : L("채울 항목 있음", "Items left")}</StateChip></div>
        {readiness?.reasons.length ? <ul className="md-gaps">{readiness.reasons.map(code => <li key={code}>{say(READINESS_WORDS, code, L)}</li>)}</ul> : null}
        {review ? <Facts>
          <Fact label={L("변경 시간창", "Change window")}>{fmtDT(review.window_start, locale)} – {fmtDT(review.window_end, locale)}</Fact>
          <Fact label={rotation ? L("신고한 사용처", "Declared consumers") : L("전환 확인 / 사용처", "Switched / consumers")}>{rotation ? readiness?.declared_consumers ?? review.consumers.length : `${readiness?.confirmed_consumers ?? 0} / ${readiness?.declared_consumers ?? review.consumers.length}`}</Fact>
          <Fact label={L("조사 범위 근거", "Scope evidence")}><span className="mono small">{review.scope_evidence_id}</span></Fact>
          <Fact label={L("복구 계획 근거", "Recovery evidence")}><span className="mono small">{review.recovery_evidence_id}</span></Fact>
          {review.incident_id ? <Fact label={L("사고", "Incident")}><span className="mono small">{review.incident_id}</span></Fact> : null}
        </Facts> : null}
      </div>
      {owner || may.askOwner ? <div className="ig-section">
        <div className="ig-section-head"><h3>{L("소유자 승인", "Owner approval")}</h3>
          {owner ? <StateChip tone={OWNER_TONE[owner.state]}>{say(OWNER_WORDS, owner.state, L)}</StateChip> : null}</div>
        {owner ? <Facts>
          <Fact label={owner.channel === "record" ? L("소유자", "Owner") : owner.ticket ? L("물은 사람", "Asked") : L("보낸 곳", "Sent to")}><span className="clip">{owner.recipient}</span>
            <div className="subtle small">{channelWord(owner.channel, L)} · {actorLabel(owner.requested_by, L)} · {fmtDT(owner.requested_at, locale)}</div></Fact>
          <Fact label={owner.decided_at ? L("결정", "Decided") : owner.ticket ? L("응답 기한", "Answer by") : L("링크 만료", "Link expires")}>{fmtDT(owner.decided_at ?? owner.expires_at, locale)}</Fact>
          {owner.ticket?.ticket ? <Fact label={L(`${channelWord(owner.channel, L)} 티켓`, `${channelWord(owner.channel, L)} ticket`)}>
            {owner.ticket.url ? <a href={owner.ticket.url} target="_blank" rel="noopener noreferrer">#{owner.ticket.ticket}</a> : `#${owner.ticket.ticket}`}
            <div className="subtle small">{L(`승인 요청 #${owner.ticket.approval}`, `Approval #${owner.ticket.approval}`)}{owner.ticket.check_code ? ` · ${reasonText(new DashboardAPIError(owner.ticket.check_code, 409), L)}` : ""}</div></Fact> : null}
          {owner.state === "ANSWERED_BY_OTHER" ? <Fact label={L("응답한 계정", "Answered by")}>
            <span className="mono small">#{owner.ticket?.answered_by ?? "-"}</span>
            <div className="subtle small">{L("물은 소유자의 계정이 아니라서 인정하지 않았습니다. 다시 요청하세요.", "Not the owner's account that was asked, so it does not count. Ask again.")}</div></Fact> : null}
          {owner.state === "NOT_INDEPENDENT" ? <Fact label={L("응답한 계정", "Answered by")}>
            <span className="mono small">#{owner.ticket?.answered_by ?? "-"}</span>
            <div className="subtle small">{L("이 계정의 주소가 계획을 요청·승인한 사람의 주소와 같거나 구별할 수 없어 인정하지 않았습니다. 다른 소유자에게 다시 요청하세요.",
              "This account's address matches, or cannot be told apart from, someone who requested or approved the plan, so it does not count. Ask the owner again.")}</div></Fact> : null}
          {owner.evidence ? <Fact label={L("승인 근거", "Evidence")}><span className="cell-wrap">{owner.evidence}</span></Fact> : null}
          {owner.note ? <Fact label={L("소유자 메모", "Owner's note")}><span className="cell-wrap">{owner.note}</span></Fact> : null}
          {owner.previous ? <Fact label={L("이전 결정", "Earlier decision")}>{say(OWNER_WORDS, owner.previous.state, L)} · <span className="clip">{owner.previous.recipient}</span>
            <div className="subtle small">{fmtDT(owner.previous.decided_at, locale)}{owner.previous.note ? ` · ${owner.previous.note}` : ""}</div></Fact> : null}
        </Facts> : <p className="meta">{ticketSystem ? L(`${ticketSystem}에 티켓을 열어 소유자의 계정에 승인을 요청할 수 있습니다. `, `You can open a ${ticketSystem} ticket asking the owner's account there to approve. `) : ""}
          {local ? L("소유자에게 받은 승인을 근거(메일·티켓 번호)와 함께 기록합니다.", "Record the approval the owner gave, with its evidence (a mail or ticket number).")
          : L("소유자가 회사 계정으로 로그인해 업무 영향을 확인하고 한 번 결정하는 링크를 보냅니다.", "Send a link the key's owner opens signed in with their company account to check the impact and decide once.")}
          {plan.reason_code === "OWNER_DEPARTED" ? L(" 떠난 사람의 키는 팀장처럼 대신 확인할 사람에게 받습니다.", " For a departed owner's key, ask whoever answers for it now, such as their team lead.") : ""}</p>}
      </div> : null}
      {plan.owner_emergency ? <div className="ig-section">
        <div className="ig-section-head"><h3>{L("긴급 차단", "Emergency containment")}</h3>
          <StateChip tone={plan.owner_emergency.notice_pending ? "warn" : plan.owner_emergency.noticed_at ? "ok" : undefined}>
            {plan.owner_emergency.notice_pending ? L("사후 통지 필요", "Owner to be told") : plan.owner_emergency.noticed_at ? L("소유자에게 알림", "Owner told")
              : L("실행되지 않음", "Not run")}</StateChip></div>
        <Facts>
          <Fact label={L("결정", "Decided")}>{actorLabel(plan.owner_emergency.by, L)}<div className="subtle small">{fmtDT(plan.owner_emergency.at, locale)}</div></Fact>
          <Fact label={L("사유", "Reason")}><span className="cell-wrap">{plan.owner_emergency.reason}</span></Fact>
          {plan.owner_emergency.noticed_at ? <Fact label={L("알린 곳", "Told")}><span className="clip">{plan.owner_emergency.notice_to}</span>
            <div className="subtle small">{channelWord(plan.owner_emergency.notice_channel ?? "record", L)} · {fmtDT(plan.owner_emergency.noticed_at, locale)}</div></Fact> : null}
        </Facts>
      </div> : null}
      {rotation ? <div className="ig-section">
        <div className="ig-section-head"><h3>{L("교체 단계", "Rotation phase")}</h3></div>
        <Facts>
          <Fact label={L("Secret", "Secret")}><span className="mono small cell-wrap">{plan.rotation?.secret_arn}</span></Fact>
          <Fact label={L("기존 AWSCURRENT 버전", "Original AWSCURRENT version")}><span className="mono small">{plan.rotation?.expected_current_version}</span></Fact>
          {plan.next_step ? <Fact label={L("다음 단계", "Next step")}>{say(NEXT_WORDS, plan.next_step, L)}</Fact> : null}
        </Facts>
        {plan.rotation_progress?.length ? <ol className="timeline">{plan.rotation_progress.map((entry, index) => <li key={`${entry.stage}:${index}`}><span className="dot pri" />
          <div className="when num">{fmtDT(entry.recorded_at, locale)}</div><div className="what">{say(STAGE_WORDS, entry.stage, L)}</div></li>)}</ol> : null}
      </div> : null}
      {plan.safe_error_code ? <p className="ig-result bad"><Ic name="alert" size={15} /><span>{codeWords ? `${L(...codeWords)} · ` : ""}
        {L("결과 코드", "Result code")} <span className="mono">{plan.safe_error_code}</span></span></p> : null}
      {may.why ? <p className="meta">{may.why}</p> : null}
      <div className="md-actions">
        {status === "PENDING_APPROVAL" ? <button type="button" className="primary-btn" disabled={busy || !may.approve} onClick={() => setConfirm("approve")}><Ic name="checkCircle" size={15} />{L("승인", "Approve")}</button> : null}
        {status === "APPROVED" ? <button type="button" className="primary-btn" disabled={busy || !may.execute} onClick={() => setConfirm("execute")}><Ic name="play" size={15} />{L("실행 요청", "Request execution")}</button> : null}
        {may.emergency ? <button type="button" className="danger-btn" disabled={busy} onClick={() => setUrgent(true)}><Ic name="alert" size={15} />{L("긴급 차단", "Contain now")}</button> : null}
        {may.notice ? <button type="button" className="ghost-btn" disabled={busy} onClick={() => setTelling(true)}><Ic name="send" size={15} />{L("소유자에게 사후 통지", "Tell the owner")}</button> : null}
        {status === "OUTCOME_UNKNOWN" ? <button type="button" className="ghost-btn" disabled={busy || !may.recheck} onClick={() => policy.independent_authorization_required ? setConfirm("recheck") : void run("recheck")}><Ic name="refresh" size={15} />{L("상태 다시 확인", "Recheck the state")}</button> : null}
        {may.askOwner && (!local || ticketSystem) ? <button type="button" className="ghost-btn" disabled={busy} onClick={() => setAsking(true)}>
          <Ic name="send" size={15} />{owner ? L("소유자에게 다시 요청", "Ask the owner again") : L("소유자에게 승인 요청", "Ask the owner to approve")}</button> : null}
        {may.askOwner && local ? <button type="button" className="ghost-btn" disabled={busy} onClick={() => setRecording(true)}>
          <Ic name="pencil" size={15} />{L("소유자 승인 기록", "Record the owner's approval")}</button> : null}
        {may.cancel ? <button type="button" className="ghost-btn" disabled={busy} onClick={() => void run("cancel")}>{L("계획 취소", "Cancel the plan")}</button> : null}
      </div>
    </CardBody>
    {confirm === "approve" || confirm === "execute" || confirm === "recheck" ? <ConfirmStep key={`${plan.id}:${plan.plan_hash}:${confirm}`} plan={plan} step={confirm} self={confirm === "approve" && policy.single_operator === true && actor.id === plan.requested_by}
      independent={policy.independent_authorization_required === true && confirm !== "approve"}
      busy={busy} onClose={() => setConfirm(null)} onConfirm={(self, signed) => void run(confirm, self, signed)} /> : null}
    {asking ? <OwnerApprovalModal plan={plan} links={!local} ticketSystem={ticketSystem} onClose={() => setAsking(false)}
      onSent={next => { setAsking(false); onChanged({ ...plan, ...next }); }} /> : null}
    {recording ? <OwnerRecordModal plan={plan} onClose={() => setRecording(false)} onSaved={next => { setRecording(false); onChanged({ ...plan, ...next }); }} /> : null}
    {urgent ? <EmergencyModal key={`${plan.id}:${plan.plan_hash}`} plan={plan} independent={policy.independent_authorization_required === true} onClose={() => setUrgent(false)} onDone={next => { setUrgent(false); onChanged({ ...plan, ...next }); }} /> : null}
    {telling ? <OwnerNoticeModal plan={plan} onClose={() => setTelling(false)} onDone={next => { setTelling(false); onChanged({ ...plan, ...next }); }} /> : null}
  </Card>;
}

/** An Admin disables a publicly exposed key at once, without its owner's approval; the owner is told afterwards. */
function EmergencyModal({ plan, independent, onClose, onDone }: { plan: Plan; independent: boolean; onClose: () => void; onDone: (plan: Plan) => void }) {
  const L = useL();
  const toast = useToast();
  const [reason, setReason] = useState("");
  const [sure, setSure] = useState(false);
  const [signed, setSigned] = useState<SignedApproval>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const submit = async () => {
    setBusy(true); setError("");
    try {
      const next = await send<Plan>(`action-plans/${plan.id}/emergency-execute`, "POST", { plan_hash: plan.plan_hash, reason: reason.trim(), ...(signed ? { signed_approval: signed } : {}) });
      toast(next.status === "QUEUED" ? L("긴급 차단을 접수했습니다. 실행 결과를 확인한 뒤 소유자에게 통지하세요.", "Emergency containment queued. Check the execution result before notifying the owner.")
        : next.status === "VERIFIED" ? L("키를 긴급 차단했습니다. 소유자에게 사후 통지합니다.", "The key is contained. Tell the owner next.")
        : L("긴급 차단을 실행했습니다. 결과를 확인하세요.", "The emergency containment ran. Check its result."));
      onDone(next);
    } catch (reason_) { setError(reasonText(reason_, L)); }
    finally { setBusy(false); }
  };
  return <Modal onClose={onClose} labelledBy="emergency-title" size="narrow" dismissable={!busy}>
    <h2 id="emergency-title">{L("긴급 차단", "Contain now")}</h2>
    <Facts>
      <Fact label={L("조치", "Action")}>{L(...actionWords(plan.action_type, plan.target?.revokes))}</Fact>
      <Fact label={L("대상", "Target")}><span className="mono">{plan.identifier_hint}</span><div className="subtle small">{plan.user_name} · {plan.account_id}</div></Fact>
    </Facts>
    <p className="meta">{L("공개된 곳에 노출된 키를 소유자 승인 없이 지금 비활성화합니다. 이 키를 쓰는 작업은 인증에 실패하며, 결정과 사유가 감사 기록에 남습니다.",
      "Disables the publicly exposed key now, without its owner's approval. Anything using it fails to authenticate; the decision and its reason are audited.")}</p>
    <AreaField label={L("사유", "Reason")} value={reason} onChange={setReason} rows={3} maxLength={500} className="short"
      placeholder={L("예: 공개 GitHub 저장소에 노출, 사용 기록 확인됨", "e.g. exposed in a public GitHub repository, use observed")} />
    <label className="check-line"><input type="checkbox" checked={sure} onChange={event => setSure(event.target.checked)} />
      {L("소유자 승인 없이 차단하고, 소유자에게 사후 통지합니다.", "I contain it without the owner's approval and will tell the owner.")}</label>
    {independent ? <IndependentAuthorization planId={plan.id} planHash={plan.plan_hash} mode="emergency" onChange={setSigned} /> : null}
    {error ? <p className="ig-result bad" role="alert"><Ic name="alert" size={15} /><span>{error}</span></p> : null}
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose} disabled={busy}>{L("취소", "Cancel")}</button>
      <button type="button" className="danger-btn" disabled={busy || !sure || reason.trim().length < 10 || independent && !signed} onClick={() => void submit()}>
        {busy ? L("차단 중", "Containing") : L("긴급 차단", "Contain now")}</button>
    </div>
  </Modal>;
}

/** Tell the key's owner what an emergency containment did: CreMore's own mail or Slack DM, or a record of how. */
function OwnerNoticeModal({ plan, onClose, onDone }: { plan: Plan; onClose: () => void; onDone: (plan: Plan) => void }) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const ready = useApi<ContactChannels>("contact-delivery");
  const channels = [...(["mail", "slack"] as const).filter(channel => ready.data?.[channel]), "record" as const];
  const [picked, setPicked] = useState<"mail" | "slack" | "record" | "">("");
  const [to, setTo] = useState("");
  const [evidence, setEvidence] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const channel = picked || channels[0];
  const recording = channel === "record";
  const submit = async () => {
    setBusy(true); setError("");
    try {
      const next = await send<Plan>(`action-plans/${plan.id}/owner-notice`, "POST",
        { channel, to: to.trim(), locale, ...(recording ? { evidence: evidence.trim() } : {}) });
      toast(recording ? L("소유자에게 알린 것을 기록했습니다.", "Recorded that the owner was told.") : L("소유자에게 알렸습니다.", "The owner was told."));
      onDone(next);
    } catch (reason) { setError(reasonText(reason, L)); }
    finally { setBusy(false); }
  };
  return <Modal onClose={onClose} labelledBy="notice-title" size="narrow" dismissable={!busy}>
    <h2 id="notice-title">{L("소유자에게 사후 통지", "Tell the owner")}</h2>
    {!ready.data && !ready.error ? <Loading /> : <>
      <div className="row2">
        <SelectField label={L("알릴 방법", "How")} value={channel} onChange={value => setPicked(value)}
          options={channels.map(id => ({ id, label: channelWord(id, L) }))} />
        <TextField label={recording ? L("소유자", "Owner") : L("소유자 이메일", "Owner's address")} value={to} onChange={setTo}
          inputMode={recording ? "text" : "email"} placeholder={recording ? L("이름 또는 이메일", "Name or address") : "name@example.com"} />
      </div>
      {recording ? <TextField label={L("알린 근거", "Evidence")} value={evidence} onChange={setEvidence} maxLength={200}
        placeholder={L("예: 2026-09-29 전화, 티켓 #1234", "e.g. phone call of 2026-09-29, ticket #1234")} />
        : <p className="meta">{L("무엇을 언제 왜 차단했는지 CreMore 문구로 보냅니다(링크 없음).", "CreMore sends what was contained, when and why, in its own words (no link).")}</p>}
    </>}
    {error ? <p className="ig-result bad" role="alert"><Ic name="alert" size={15} /><span>{error}</span></p> : null}
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose} disabled={busy}>{L("취소", "Cancel")}</button>
      <button type="button" className="primary-btn" disabled={busy || !to.trim() || (recording ? !evidence.trim() : !to.includes("@"))} onClick={() => void submit()}>
        {busy ? L("보내는 중", "Sending") : recording ? L("기록", "Record") : L("보내기", "Send")}</button>
    </div>
  </Modal>;
}

function channelWord(channel: string, L: ReturnType<typeof useL>) {
  // Anything else is the ticket system an approval was asked in (its id).
  return channel === "record" ? L("운영자 기록", "Operator's record") : channel === "mail" ? L("메일", "Mail")
    : channel === "slack" ? "Slack" : channel.toUpperCase();
}

/** The local operator's record of the approval the owner gave outside CreMore (no link: nobody else can reach a
 * local sign-in console safely). */
function OwnerRecordModal({ plan, onClose, onSaved }: { plan: Plan; onClose: () => void; onSaved: (plan: Plan) => void }) {
  const L = useL();
  const toast = useToast();
  const [form, setForm] = useState({ owner: "", evidence: "", decision: "approve" as "approve" | "decline", note: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const set = (change: Partial<typeof form>) => setForm(current => ({ ...current, ...change }));
  const submit = async () => {
    setBusy(true); setError("");
    try {
      const next = await send<Plan>(`action-plans/${plan.id}/owner-approval/record`, "POST",
        { owner: form.owner.trim(), evidence: form.evidence.trim(), decision: form.decision, note: form.note.trim() });
      toast(L("소유자 승인을 기록했습니다.", "The owner's approval is recorded."));
      onSaved(next);
    } catch (reason) { setError(reasonText(reason, L)); }
    finally { setBusy(false); }
  };
  return <Modal onClose={onClose} labelledBy="owner-record-title" size="narrow" dismissable={!busy}>
    <h2 id="owner-record-title">{L("소유자 승인 기록", "Record the owner's approval")}</h2>
    <Facts>
      <Fact label={L("조치", "Action")}>{L(...actionWords(plan.action_type, plan.target?.revokes))}</Fact>
      <Fact label={L("대상", "Target")}><span className="mono">{plan.identifier_hint}</span><div className="subtle small">{plan.user_name} · {plan.account_id}</div></Fact>
    </Facts>
    <div className="row2">
      <TextField label={L("소유자", "Owner")} value={form.owner} onChange={owner => set({ owner })} maxLength={200} placeholder={L("이름 또는 이메일", "Name or address")} />
      <SelectField label={L("결정", "Decision")} value={form.decision} onChange={decision => set({ decision })}
        options={[{ id: "approve" as const, label: L("승인", "Approved") }, { id: "decline" as const, label: L("거절", "Declined") }]} />
    </div>
    <TextField label={L("승인 근거", "Evidence")} value={form.evidence} onChange={evidence => set({ evidence })} maxLength={200}
      placeholder={L("예: 2026-09-29 회신 메일, 티켓 #1234", "e.g. reply mail of 2026-09-29, ticket #1234")} />
    <TextField label={L("소유자 메모 (선택)", "Owner's note (optional)")} value={form.note} onChange={note => set({ note })} maxLength={500} />
    {error ? <p className="ig-result bad" role="alert"><Ic name="alert" size={15} /><span>{error}</span></p> : null}
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose} disabled={busy}>{L("취소", "Cancel")}</button>
      <button type="button" className="primary-btn" disabled={busy || !form.owner.trim() || !form.evidence.trim()} onClick={() => void submit()}>
        {busy ? L("기록 중", "Recording") : L("기록", "Record")}</button>
    </div>
  </Modal>;
}

/** Ask the key's owner to decide on the plan's impact: a link CreMore sends by mail or Slack DM, opened signed in
 * with the company account (``links``), or the company's ticket system asking the owner's own account there. */
function OwnerApprovalModal({ plan, links, ticketSystem, onClose, onSent }: {
  plan: Plan; links: boolean; ticketSystem: string | null; onClose: () => void; onSent: (plan: Plan) => void;
}) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const ready = useApi<ContactChannels>(links ? "contact-delivery" : null);
  const [picked, setPicked] = useState<"mail" | "slack" | "ticket" | "">("");
  const [to, setTo] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const channels: ("mail" | "slack" | "ticket")[] = [...(links ? (["mail", "slack"] as const).filter(channel => ready.data?.[channel]) : []),
    ...(ticketSystem ? ["ticket" as const] : [])];
  const channel = picked || channels[0] || "mail";
  const ticket = channel === "ticket";
  const loading = links && !ready.data && !ready.error;
  const blocked = ticket || loading ? "" : !channels.length ? L("관리자가 연동 > 기타 설정 > 연락 발송에서 메일이나 Slack을 설정하면 보낼 수 있습니다.", "An Admin sets up mail or Slack under Integrations > Other settings > Contact delivery first.")
    : !ready.data?.console_url ? L("관리자가 연락 발송 설정에 콘솔 주소를 넣으면 보낼 수 있습니다.", "An Admin adds the console address to the contact delivery setup first.") : "";
  const submit = async () => {
    setBusy(true); setError("");
    try {
      const next = ticket
        ? await send<Plan>(`action-plans/${plan.id}/owner-approval/ticket`, "POST", { to: to.trim(), locale })
        : await send<Plan>(`action-plans/${plan.id}/owner-approval`, "POST", { channel, to: to.trim(), locale });
      toast(ticket ? L(`${ticketSystem}에 티켓을 열어 소유자에게 승인을 요청했습니다.`, `A ${ticketSystem} ticket asks the owner to approve.`)
        : L("소유자에게 승인 요청을 보냈습니다.", "The approval request went to the owner."));
      onSent(next);
    } catch (reason) { setError(reasonText(reason, L)); }
    finally { setBusy(false); }
  };
  const label = (id: "mail" | "slack" | "ticket") => id === "ticket" ? L(`${ticketSystem} 승인 요청`, `${ticketSystem} approval`)
    : id === "mail" ? L("메일 링크", "Mail link") : L("Slack 링크", "Slack link");
  return <Modal onClose={onClose} labelledBy="owner-ask-title" size="narrow" dismissable={!busy}>
    <h2 id="owner-ask-title">{L("소유자에게 승인 요청", "Ask the owner to approve")}</h2>
    <Facts>
      <Fact label={L("조치", "Action")}>{L(...actionWords(plan.action_type, plan.target?.revokes))}</Fact>
      <Fact label={L("대상", "Target")}><span className="mono">{plan.identifier_hint}</span><div className="subtle small">{plan.user_name} · {plan.account_id}</div></Fact>
    </Facts>
    {loading ? <Loading /> : links && ready.error && !ticketSystem ? <p className="meta">{reasonText(ready.error, L)}</p> : <>
      <div className="row2">
        <SelectField label={L("묻는 방법", "Ask by")} value={channel} onChange={value => setPicked(value)}
          options={(channels.length ? channels : ["mail" as const]).map(id => ({ id, label: label(id) }))} />
        <TextField label={L("소유자 이메일", "Owner's address")} value={to} onChange={setTo} inputMode="email" placeholder="name@example.com" />
      </div>
      {blocked ? <p className="meta">{blocked}</p> : <p className="meta">{ticket
        ? L(`${ticketSystem}에 티켓을 열고 이 주소를 가진 ${ticketSystem} 계정에 승인을 요청합니다. 그 계정의 응답만 인정하며 CreMore가 1분마다 확인합니다. 72시간 또는 계획 기한까지 기다리고, 다시 요청하면 이전 요청의 응답은 인정하지 않습니다.${links ? " 계획을 요청하거나 승인한 사람의 주소로는 물을 수 없습니다." : ""}`,
          `Opens a ${ticketSystem} ticket asking the ${ticketSystem} account with this address to approve. Only that account's answer counts; CreMore checks every minute. It waits 72 hours or until the plan expires; asking again ends the earlier request.${links ? " The address cannot be that of someone who requested or approved the plan." : ""}`)
        : L(`${channel === "slack" ? "Slack DM으로 보냅니다. " : ""}소유자는 이 주소의 회사 계정으로 로그인해야 링크에서 결정할 수 있고, 한 번만 결정합니다. 링크는 72시간 또는 계획 기한까지 쓸 수 있고, 다시 요청하면 이전 링크는 더 쓸 수 없습니다.`,
          `${channel === "slack" ? "It goes as a Slack DM. " : ""}Only this address's company account decides at the link, once. The link works for 72 hours or until the plan expires; asking again ends the earlier link.`)}</p>}
    </>}
    {error ? <p className="ig-result bad" role="alert"><Ic name="alert" size={15} /><span>{error}</span></p> : null}
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose} disabled={busy}>{L("취소", "Cancel")}</button>
      <button type="button" className="primary-btn" disabled={busy || loading || Boolean(blocked) || !channels.length || !to.includes("@")} onClick={() => void submit()}>
        <Ic name="send" size={15} />{busy ? L("보내는 중", "Sending") : ticket ? L("티켓 열기", "Open the ticket") : L("보내기", "Send")}</button>
    </div>
  </Modal>;
}

function ConfirmStep({ plan, step, self, independent, busy, onClose, onConfirm }: { plan: Plan; step: "approve" | "execute" | "recheck"; self: boolean; independent: boolean; busy: boolean; onClose: () => void; onConfirm: (self: boolean, signed?: SignedApproval) => void }) {
  const L = useL();
  const [checked, setChecked] = useState(false);
  const [signed, setSigned] = useState<SignedApproval>();
  const deleting = isIrreversible(plan.action_type);
  const provider = isProvider(plan);
  return <Modal onClose={onClose} labelledBy="plan-confirm-title" size="narrow">
    <h2 id="plan-confirm-title">{step === "approve" ? L("이 계획 승인", "Approve this plan") : step === "recheck" ? L("상태 다시 확인", "Recheck the state") : L("이 계획 실행", "Execute this plan")}</h2>
    <Facts>
      <Fact label={L("조치", "Action")}>{L(...actionWords(plan.action_type, plan.target?.revokes))}</Fact>
      <Fact label={L("대상", "Target")}><span className="mono cell-wrap">{plan.identifier_hint}</span><div className="subtle small">{targetLine(plan, L)}</div></Fact>
      <ProviderTarget plan={plan} />
      <Fact label={L("내용 해시", "Content hash")}><span className="mono small">{plan.plan_hash.slice(0, 16)}…</span></Fact>
    </Facts>
    {step === "execute" ? <p className="meta">{provider
      ? (deleting && plan.target?.revokes === "ORGANIZATION_ACCESS"
        ? L("이 조직이 이 토큰에 준 접근을 회수하며 되살릴 수 없습니다. 토큰으로 이 조직의 리소스를 쓰는 작업은 실패하고, 토큰 자체는 폐기되지 않습니다. 작업자가 조치용 연동으로 실행하고 결과를 다시 읽습니다.",
          "The organization's access for this token is revoked and cannot be restored. Anything using the token on this organization's resources fails; the token itself is not revoked. The worker runs it through the acting integration and reads the result back.")
        : deleting ? L("되살릴 수 없습니다. 이 자격증명을 쓰는 작업은 인증에 실패합니다. 작업자가 조치용 연동으로 실행하고 결과를 다시 읽습니다.",
        "It cannot be undone. Anything using this credential fails to authenticate. The worker runs it through the acting integration and reads the result back.")
        : L("이 자격증명을 쓰는 작업은 인증에 실패합니다. 이미 발급된 단기 토큰은 만료까지 남을 수 있습니다. 작업자가 조치용 연동으로 실행하고 결과를 다시 읽습니다.",
          "Anything using this credential fails to authenticate; short-lived tokens already minted may last until they expire. The worker runs it through the acting integration and reads the result back."))
      : deleting ? L("같은 키는 되살릴 수 없습니다. 이 키를 쓰는 작업은 인증에 실패합니다.", "The same key cannot be restored. Anything still using it fails to authenticate.")
        : isRotation(plan.action_type) ? L("기존 키는 이 단계에서 바뀌지 않습니다.", "The old key does not change in this phase.")
          : L("이 키를 쓰는 작업은 인증에 실패합니다. 기존 STS 세션과 노출된 원본은 따로 정리합니다.", "Anything using this key fails to authenticate. Existing STS sessions and the exposed source are cleaned up separately.")}</p> : null}
    {self ? <label className="check-line"><input type="checkbox" checked={checked} onChange={event => setChecked(event.target.checked)} />
      {L("단독 운영자로서 대상과 내용 해시를 다시 확인했습니다.", "As the only operator, I re-checked the target and the content hash.")}</label> : null}
    {independent && step !== "approve" ? <IndependentAuthorization planId={plan.id} planHash={plan.plan_hash} mode={step} onChange={setSigned} /> : null}
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose}>{L("취소", "Cancel")}</button>
      <button type="button" className={step === "execute" && deleting ? "danger-btn" : "primary-btn"} disabled={busy || (self && !checked) || independent && !signed} onClick={() => onConfirm(self, signed)}>
        {step === "approve" ? L("승인", "Approve") : step === "recheck" ? L("다시 확인", "Recheck") : L("실행 요청", "Request execution")}</button>
    </div>
  </Modal>;
}

/* ---------- requesting a plan ---------- */

const ENVIRONMENTS: [string, [string, string]][] = [["PRODUCTION", ["운영", "Production"]], ["STAGING", ["스테이징", "Staging"]], ["DEVELOPMENT", ["개발", "Development"]], ["DISASTER_RECOVERY", ["재해 복구", "Disaster recovery"]]];
const IMPACTS: [string, [string, string]][] = [["UNKNOWN", ["미확인", "Unknown"]], ["LIMITED", ["제한적", "Limited"]], ["SIGNIFICANT", ["중대", "Significant"]], ["CRITICAL", ["치명적", "Critical"]]];
const TRANSITIONS: [string, [string, string]][] = [["UNKNOWN", ["미확인", "Unknown"]], ["PENDING", ["대기", "Pending"]], ["FAILED", ["실패", "Failed"]], ["SUCCEEDED", ["성공", "Succeeded"]]];
const AUTH: [string, [string, string]][] = [["UNKNOWN", ["미확인", "Unknown"]], ["OLD_FALLBACK", ["기존 자격증명으로 실행", "Old credential fallback"]], ["NEW_CREDENTIAL", ["새 자격증명", "New credential"]]];
type ReviewCheck = "scope_complete" | "unknown_consumers" | "replacement_reviewed" | "impact_accepted" | "stop_criteria_reviewed";
const CHECKS: [ReviewCheck, [string, string]][] = [
  ["scope_complete", ["범위 안의 환경·사용처를 모두 조사했습니다", "Every environment and consumer in scope was surveyed"]],
  ["unknown_consumers", ["아직 모르는 사용처가 있습니다", "Unknown consumers remain"]],
  ["replacement_reviewed", ["대체 인증 방식을 검토했습니다", "The replacement authentication was reviewed"]],
  ["impact_accepted", ["업무 영향을 받아들였습니다", "The business impact is accepted"]],
  ["stop_criteria_reviewed", ["중단·복구 기준을 검토했습니다 (노출된 키는 되살리지 않음)", "Stop and recovery criteria reviewed (the exposed key is never restored)"]],
];

/** Why no plan can be requested now, in the reader's words. */
function blockText(reason: string | undefined, provider: boolean, L: Say, short = false): string {
  if (reason === "ACTION_PLAN_TARGET_LOCKED") return short ? L("끝나지 않은 계획이 있습니다", "An unfinished plan exists")
    : provider ? L("끝나지 않은 계획이 이 자격증명에 걸려 있습니다.", "An unfinished plan already holds this credential.")
      : L("끝나지 않은 계획이 이 키에 걸려 있습니다.", "An unfinished plan already holds this key.");
  if (!provider) return short ? L("IAM 사용자에게 묶인 장기 키만 계획할 수 있습니다", "Only a long-term key bound to an IAM user can be planned")
    : L("IAM 사용자에게 묶인 장기 액세스 키만 계획할 수 있습니다.", "Only a long-term access key bound to an IAM user can be planned.");
  if (reason === "REMEDIATION_NOT_SET_UP") return L("이 자격증명에 조치할 연동이 없습니다. 연동 서비스에서 '승인된 조치 실행'을 따로 연동하세요.",
    "No integration acts on this credential. Connect one for approved actions under Integrations.");
  if (reason === "REMEDIATION_CONNECTION_AMBIGUOUS") return L("이 자격증명에 닿는 조치용 연동이 둘 이상입니다. 하나만 남기세요.",
    "More than one integration for approved actions reaches this credential. Keep one.");
  if (reason === "REMEDIATION_CHECK_REQUIRED") return L("조치용 연동의 권한 점검이 실행할 계정을 확인하지 못했습니다. 연동에서 권한을 다시 확인하세요.",
    "The acting integration's check did not name the account that acts. Check its access again under Integrations.");
  return L("이 자격증명은 조치 계획으로 다룰 수 없습니다.", "This credential cannot be acted on through a plan.");
}

/** The secret a rotation preparation starts with: the one an Admin declared for the key, where the installation allows it. */
export function startSecret(action: ActionType, declared: string | undefined, policy: CredentialPolicy): string {
  return action === "PREPARE_ACCESS_KEY_ROTATION" && declared && (policy.rotation_secret_arns ?? []).includes(declared) ? declared : "";
}

export function PlanModal({ path, name, policy, plans, only, reasons = ["EXPOSURE_CONTAINMENT", "SECURITY_INCIDENT", "OWNER_REQUEST"], provider = false, declared, onClose, onCreated }: {
  /** Where the plan is requested: a discovered key's, a departed owner's key's, or an inventoried credential's action-plans route. */
  path: string; name: string; policy: CredentialPolicy; plans: Plan[]; only?: ActionType[]; reasons?: Reason[];
  /** Another provider's credential: the actions its policy lists, run by the worker through the acting integration. */
  provider?: boolean;
  /** The secret an Admin declared to hold the key: a rotation's secret starts as it where the installation allows it. */
  declared?: string;
  onClose: () => void; onCreated: (plan: Plan) => void;
}) {
  const L = useL();
  const toast = useToast();
  const actions = (Object.keys(ACTION_WORDS) as ActionType[]).filter(kind => (provider
    ? PROVIDER_ACTIONS.includes(kind) && Boolean(policy.supported_actions?.includes(kind))
    : !PROVIDER_ACTIONS.includes(kind) && (kind === "DISABLE_ACCESS_KEY" || policy.supported_actions?.includes(kind))) && (!only || only.includes(kind)));
  const [action, setAction] = useState<ActionType>(() => actions[0] ?? "DISABLE_ACCESS_KEY");
  const [reason, setReason] = useState<Reason>(reasons[0]);
  const [review, setReview] = useState<Review>(() => blankReview());
  const [rotation, setRotation] = useState<Rotation>(() => ({ secret_arn: startSecret(actions[0] ?? "DISABLE_ACCESS_KEY", declared, policy), expected_current_version: "" }));
  const [busy, setBusy] = useState(false);
  // A lost response is retried with the same key, so the server returns the plan it already made.
  const pending = useRef<{ key: string; body: string } | null>(null);
  const rotating = isRotation(action), deleting = isIrreversible(action);
  const prepared = plans.filter(plan => plan.action_type === "PREPARE_ACCESS_KEY_ROTATION" && plan.status === "VERIFIED" && plan.result_kind === "SUCCESSOR_PREPARED_OLD_KEY_ACTIVE" && plan.rotation);
  const set = <K extends keyof Review>(key: K, value: Review[K]) => setReview(current => ({ ...current, [key]: value }));
  const setConsumer = (index: number, change: Partial<Consumer>) => setReview(current => ({ ...current, consumers: current.consumers.map((c, i) => i === index ? { ...c, ...change } : c) }));
  const built = reviewBody(review, action, L);
  const binding = rotating ? rotation : undefined;
  const bindingOk = !rotating || validRotation(action, binding);
  const blocked = !policy.can_plan || (deleting && policy.can_delete === false) || !actions.includes(action);
  const problem = blocked ? blockText(policy.block_reason, provider, L)
    : !bindingOk ? L("Secret과 32–64자 버전 ID를 고르세요.", "Choose the Secret and a 32–64 character version ID.") : built.problem ?? "";
  const submit = async () => {
    if (!built.body || problem) return;
    const body = JSON.stringify({ action_type: action, reason_code: reason, operational_review: built.body, ...(binding ? { rotation: binding } : {}) });
    if (!pending.current || pending.current.body !== body) pending.current = { key: randomId(), body };
    setBusy(true);
    try {
      const plan = await send<Plan>(path, "POST", { ...JSON.parse(body), idempotency_key: pending.current.key });
      pending.current = null;
      toast(L("조치 계획을 요청했습니다. 관리자 승인을 기다립니다.", "Plan requested. It waits for an Admin's approval."));
      onCreated(plan);
    } catch (reason) {
      // A definite answer ends the request; an unanswered one (the network, or the proxy not reaching the API: 502-504)
      // is retried as it was, so the server returns the plan it may already have made.
      const status = (reason as { status?: number }).status;
      if (status && ![502, 503, 504].includes(status)) pending.current = null;
      toast(reasonText(reason, L), "bad");
    } finally { setBusy(false); }
  };
  const words = (pairs: [string, [string, string]][]) => pairs.map(([id, pair]) => ({ id, label: L(...pair) }));
  return <Modal onClose={onClose} labelledBy="plan-new-title" size="wide">
    <h2 id="plan-new-title">{L("조치 계획 요청", "Request an action plan")} <small><span className="clip">{name}</span></small></h2>
    {provider && policy.remediation_connection ? <p className="meta">{L(`승인되면 작업자가 '${policy.remediation_connection.name}' 연동의 자격증명으로 실행하고 결과를 다시 읽습니다.`,
      `Once approved, the worker runs it with the '${policy.remediation_connection.name}' integration's credential and reads the result back.`)}</p> : null}
    {provider && policy.remediation_connection?.shared_with?.length ? <Banner tone="warn" icon="alert">
      {sharedNote({ provider: policy.remediation_connection.provider, auth_method: policy.remediation_connection.auth_method, purposes: ["remediation"],
        credential: { roles: [], reference: false, shared_with: policy.remediation_connection.shared_with } }, L)}</Banner> : null}
    <div className="row2">
      <SelectField label={L("조치", "Action")} value={action} onChange={value => { setAction(value); setRotation({ secret_arn: startSecret(value, declared, policy), expected_current_version: "" }); }}
        options={actions.map(kind => ({ id: kind, label: L(...actionWords(kind, policy.revokes)) }))} />
      <SelectField label={L("사유", "Reason")} value={reason} onChange={setReason}
        options={reasons.map(value => ({ id: value, label: L(...REASON_WORDS[value]) }))} />
    </div>
    {rotating ? <div className="ig-section"><div className="ig-section-head"><h3>{L("교체할 Secret", "Secret to rotate")}</h3></div>
      {action === "PUBLISH_ACCESS_KEY_ROTATION"
        ? <SelectField label={L("완료된 준비 계획", "Verified preparation plan")} value={rotation.preparation_plan_id ?? ""}
          onChange={id => { const chosen = prepared.find(plan => plan.id === id); setRotation(chosen?.rotation ? { ...chosen.rotation, preparation_plan_id: chosen.id } : { secret_arn: "", expected_current_version: "" }); }}
          options={[{ id: "", label: prepared.length ? L("준비 계획 선택", "Choose a preparation plan") : L("완료된 준비 계획이 없습니다", "No verified preparation plan") },
            ...prepared.map(plan => ({ id: plan.id, label: `${plan.rotation?.secret_arn.split(":").pop()} · ${plan.id.slice(0, 8)}` }))]} />
        : <div className="row2">
          <SelectField label={L("허용된 Secret", "Allowed Secret")} value={rotation.secret_arn} onChange={value => setRotation(current => ({ ...current, secret_arn: value }))}
            options={[{ id: "", label: (policy.rotation_secret_arns ?? []).length ? L("Secret 선택", "Choose a Secret") : L("설치에 허용된 Secret이 없습니다", "No Secret is allowed on this installation") },
              ...(policy.rotation_secret_arns ?? []).map(arn => ({ id: arn, label: arn.split(":").slice(-2).join(":") }))]} />
          <TextField label={L("현재 AWSCURRENT 버전 ID", "Current AWSCURRENT version ID")} value={rotation.expected_current_version} maxLength={64}
            onChange={value => setRotation(current => ({ ...current, expected_current_version: value.trim() }))} />
        </div>}
    </div> : null}
    <div className="ig-section"><div className="ig-section-head"><h3>{L("변경 검토", "Change review")}</h3></div>
      <div className="row2">
        <SelectField label={L("방식", "Mode")} value={review.mode} onChange={value => set("mode", value)}
          options={[{ id: "PLANNED" as const, label: L("계획 변경", "Planned change") }, ...(!rotating && !deleting && reason === "SECURITY_INCIDENT" ? [{ id: "EMERGENCY" as const, label: L("긴급 사고 차단", "Emergency containment") }] : [])]} />
        <SelectField label={L("업무 영향", "Business impact")} value={review.business_impact} onChange={value => set("business_impact", value)} options={words(IMPACTS)} />
      </div>
      <div className="row2">
        <div className="field"><label htmlFor="plan-start">{L("변경 시작", "Change starts")}</label><input id="plan-start" type="datetime-local" value={review.window_start} onChange={event => set("window_start", event.target.value)} /></div>
        <div className="field"><label htmlFor="plan-end">{L("변경 종료", "Change ends")}</label><input id="plan-end" type="datetime-local" value={review.window_end} onChange={event => set("window_end", event.target.value)} /></div>
      </div>
      <div className="row2">
        <TextField label={L("조사 범위 근거 ID (변경관리 기록 UUID)", "Scope evidence ID (change record UUID)")} value={review.scope_evidence_id} maxLength={36} onChange={value => set("scope_evidence_id", value.trim())} />
        <TextField label={L("복구 계획 근거 ID (변경관리 기록 UUID)", "Recovery evidence ID (change record UUID)")} value={review.recovery_evidence_id} maxLength={36} onChange={value => set("recovery_evidence_id", value.trim())} />
      </div>
      {review.mode === "EMERGENCY" ? <TextField label={L("사고 ID (UUID)", "Incident ID (UUID)")} value={review.incident_id ?? ""} maxLength={36} onChange={value => set("incident_id", value.trim())} /> : null}
      <div className="plan-checks">{CHECKS.map(([key, pair]) => <label className="check-line" key={key}>
        <input type="checkbox" checked={review[key]} onChange={event => set(key, event.target.checked)} />{L(...pair)}</label>)}</div>
    </div>
    <div className="ig-section"><div className="ig-section-head"><h3>{rotating ? L("신고할 사용처", "Consumers to declare") : L("사용처 확인", "Consumer confirmations")}</h3>
      <button type="button" className="link-btn" disabled={review.consumers.length >= 100} onClick={() => set("consumers", [...review.consumers, blankConsumer()])}><Ic name="plus" size={14} />{L("사용처 추가", "Add a consumer")}</button></div>
      {review.consumers.map((consumer, index) => <div className="plan-consumer" key={index}>
        <div className="row2">
          <TextField label={L("사용처 ID (UUID)", "Consumer ID (UUID)")} value={consumer.consumer_id} maxLength={36} onChange={value => setConsumer(index, { consumer_id: value.trim() })} />
          <TextField label={L("확인 담당자 ID (UUID)", "Owner ID (UUID)")} value={consumer.owner_id} maxLength={36} onChange={value => setConsumer(index, { owner_id: value.trim() })} />
        </div>
        <div className="row2">
          <SelectField label={L("환경", "Environment")} value={consumer.environment} onChange={value => setConsumer(index, { environment: value })} options={words(ENVIRONMENTS)} />
          {!rotating ? <TextField label={L("근거 ID (UUID)", "Evidence ID (UUID)")} value={consumer.evidence_id} maxLength={36} onChange={value => setConsumer(index, { evidence_id: value.trim() })} /> : <div />}
        </div>
        {!rotating ? <>
          <div className="row2">
            <SelectField label={L("전환 결과", "Switch result")} value={consumer.transition} onChange={value => setConsumer(index, { transition: value })} options={words(TRANSITIONS)} />
            <SelectField label={L("실제로 쓴 인증", "Authentication used")} value={consumer.authentication_basis} onChange={value => setConsumer(index, { authentication_basis: value })} options={words(AUTH)} />
          </div>
          <div className="row2">
            <div className="field"><label htmlFor={`plan-confirmed-${index}`}>{L("확인 시각", "Confirmed at")}</label><input id={`plan-confirmed-${index}`} type="datetime-local" value={consumer.confirmed_at} onChange={event => setConsumer(index, { confirmed_at: event.target.value })} /></div>
            <div className="field"><label htmlFor={`plan-valid-${index}`}>{L("근거 유효 종료", "Evidence valid until")}</label><input id={`plan-valid-${index}`} type="datetime-local" value={consumer.valid_until} onChange={event => setConsumer(index, { valid_until: event.target.value })} /></div>
          </div>
          <label className="check-line"><input type="checkbox" checked={consumer.workload_succeeded} onChange={event => setConsumer(index, { workload_succeeded: event.target.checked })} />{L("인증뿐 아니라 업무 동작까지 성공했습니다", "The workload succeeded, not only authentication")}</label>
          <label className="check-line"><input type="checkbox" checked={consumer.scheduled_cycle_checked} onChange={event => setConsumer(index, { scheduled_cycle_checked: event.target.checked })} />{L("예약·저빈도 작업 주기까지 확인했습니다", "Scheduled and rare job cycles were covered")}</label>
        </> : null}
        {review.consumers.length > 1 ? <button type="button" className="link-btn" onClick={() => set("consumers", review.consumers.filter((_, i) => i !== index))}><Ic name="minus" size={14} />{L("이 사용처 빼기", "Remove this consumer")}</button> : null}
      </div>)}
    </div>
    {deleting ? <label className="check-line plan-ack"><input type="checkbox" checked={Boolean(review.deletion_acknowledged)} onChange={event => set("deletion_acknowledged", event.target.checked)} />
      {provider && policy.revokes === "ORGANIZATION_ACCESS" ? L("회수한 조직 접근은 되살릴 수 없음을 확인했습니다", "I acknowledge the organization's access cannot be restored once revoked")
        : provider ? L("되살릴 수 없는 영구 폐기임을 확인했습니다", "I acknowledge it cannot be undone once revoked")
        : L("같은 키를 되살릴 수 없는 영구 삭제임을 확인했습니다", "I acknowledge the same key cannot be restored after deletion")}</label> : null}
    <div className="modal-foot">
      {problem ? <span className="note">{problem}</span> : null}
      <button type="button" className="ghost-btn" onClick={onClose}>{L("취소", "Cancel")}</button>
      <button type="button" className="primary-btn" disabled={busy || Boolean(problem)} onClick={() => void submit()}><Ic name="send" size={15} />{L("계획 요청", "Request the plan")}</button>
    </div>
  </Modal>;
}

/* ---------- a credential's plans, in its panel ---------- */

export function KeyPlans({ credentialId, name, actor, path, only, reasons, provider = false }: {
  credentialId?: string; name: string; actor: Actor;
  /** A departed owner's key plans on its own route, an inventoried credential on its entity's; a discovered key on the credential's. */
  path?: string; only?: ActionType[]; reasons?: Reason[];
  /** Another provider's credential (v2/coverage/inventory/{entity}/action-plans): shown only where a plan can be made or was. */
  provider?: boolean;
}) {
  const L = useL();
  const route = path ?? `credentials/${credentialId}/action-plans`;
  const list = useApi<PlanList>(route, { every: 15_000 });
  // The secret an Admin declared to hold this key (credentials/{id}/management): a rotation starts from it.
  // Only a discovered key's own plans: a departed owner's key (path) or another provider's credential has no declaration.
  const management = useApi<{ reference?: string }>(credentialId && !provider && !path ? `credentials/${credentialId}/management` : null);
  const [open, setOpen] = useState(false);
  const plans = list.data?.plans ?? [];
  const policy = list.data?.policy;
  const remediator = actor.role === "Remediator" || actor.role === "Admin";
  // A credential CreMore cannot act on has no plans to show: nothing is shown for it.
  if (provider && (!policy || (!plans.length && policy.block_reason === "CREDENTIAL_NOT_ELIGIBLE"))) return null;
  return <>
    <Card level={3} title={provider ? L("자격증명 조치", "Credential actions") : L("AWS 키 조치", "AWS key actions")} meta={L(`계획 ${plans.length}건`, `${plans.length} plan${plans.length === 1 ? "" : "s"}`)}
      info={provider ? L("비활성화·폐기는 계획을 요청하고 관리자가 승인한 뒤, 작업자가 조치용 연동으로 실행하고 결과를 다시 읽습니다. 승인과 실행은 계획의 내용 해시에 고정됩니다.",
        "Disable and revoke run as a plan an Admin approves; the worker runs it through the integration set up to act and reads the result back. Approval and execution are bound to the plan's content hash.")
        : L("비활성화·삭제·교체는 계획을 요청하고 관리자가 승인한 뒤 실행합니다. 승인과 실행은 계획의 내용 해시에 고정됩니다.", "Disable, delete and rotate run as a plan an Admin approves; approval and execution are bound to the plan's content hash.")}
      right={policy && remediator ? <button type="button" className="primary-btn" disabled={!policy.can_plan} onClick={() => setOpen(true)}
        data-tip={policy.can_plan ? undefined : blockText(policy.block_reason, provider, L, true)}>
        <Ic name="plus" size={15} />{L("조치 계획 요청", "Request a plan")}</button> : undefined}>
      {policy ? <CardBody>
        <p className="meta">{!policy.execution_enabled ? L("이 설치에서는 승인된 계획의 실행이 꺼져 있습니다.", "Execution of approved plans is off on this installation.")
          : policy.single_operator ? L("단독 운영 설치입니다. 요청한 사람이 대상과 해시를 다시 확인해 승인합니다.", "A single-operator installation: the requester re-checks the target and hash to approve.")
            : L("요청한 사람과 다른 관리자가 승인합니다.", "An Admin other than the requester approves.")}
          {policy.owner_approval_required ? (provider ? L(" 비활성화·폐기는 소유자의 승인도 받은 뒤 실행합니다.", " Disabling and revoking also wait for the owner's approval.")
            : L(" 비활성화·삭제·게시는 키 소유자의 승인도 받은 뒤 실행합니다.", " Disabling, deleting and publishing also wait for the key owner's approval.")) : ""}</p>
        {provider && !policy.can_plan && policy.block_reason !== "ACTION_PLAN_TARGET_LOCKED" ? <p className="meta">{blockText(policy.block_reason, provider, L)}</p> : null}
        {provider && policy.remediation_connection ? <p className="subtle small">{L(`조치용 연동: ${policy.remediation_connection.name}`, `Acting integration: ${policy.remediation_connection.name}`)}</p> : null}
        {!plans.length ? <p className="subtle">{provider ? L("이 자격증명의 조치 계획이 없습니다.", "No action plans for this credential.") : L("이 키의 조치 계획이 없습니다.", "No action plans for this key.")}</p> : null}
      </CardBody> : null}
    </Card>
    {policy ? plans.map(plan => <PlanCard key={plan.id} plan={plan} policy={policy} actor={actor} onChanged={() => list.reload()} />) : null}
    {open && policy ? <PlanModal path={route} name={name} policy={policy} plans={plans} only={only} reasons={reasons} provider={provider}
      declared={management.data?.reference} onClose={() => setOpen(false)} onCreated={() => { setOpen(false); list.reload(); }} /> : null}
  </>;
}
