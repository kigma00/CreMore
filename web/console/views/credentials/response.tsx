"use client";

import { useCallback, useState } from "react";

import { type Locale, useLocale } from "@/components/locale";
import { api } from "@/lib/dashboard-api";
import { isConflict, randomId, reasonCodeText, reasonText, send, type Loaded, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { actorLabel } from "@/console/labels";
import { useToast } from "@/console/layer";
import { type DirectoryPerson, type ResponderRouting, selectablePerson } from "@/console/people";
import type { CredentialRecord, ResponseChannel, ResponseCycle, ResponseState, ResponseSummary } from "@/console/records";
import { fmtDT, type Say, useL } from "@/console/text";
import { Card, CardBody, ErrorLine, Fact, Facts, Field, SelectField, StateChip, StatusTag } from "@/console/ui";
import { ResponderFields, routingTargetKey } from "@/console/views/credentials/response-routing";
import { CompletionEvidence, type EvidenceOptions, ResponseReportForm } from "@/console/views/credentials/response-report";
import type { ContactChannels } from "@/console/views/integrations/contact-delivery";
import type { ResponseChannelOption } from "@/console/views/integrations/response-channels";

const WORDS: Record<ResponseState, [string, string]> = {
  NEW: ["검토 대기", "Pending review"], REVIEWING: ["검토 중", "In review"], ASSIGNED: ["담당자 지정됨", "Assigned"], SENDING: ["대응 요청 발송 중", "Sending request"],
  SEND_UNKNOWN: ["발송 결과 확인 필요", "Delivery needs checking"], NOT_SENT: ["대응 요청 발송 안 됨", "Request not sent"], WAITING_OWNER: ["담당자 회신 대기", "Awaiting response"],
  WAITING_VERIFICATION: ["조치 검증 중", "Verifying remediation"], REPORT_REQUIRED: ["조치 보고 필요", "Action report required"],
  NEEDS_ACTION: ["재조치 필요", "Further action needed"], REMOVED: ["제거 확인 · 완료 미검증", "Removed; completion unverified"], COMPLETED: ["조치 완료", "Remediation complete"],
};

export const responseLabel = (state: ResponseState, L: Say) => WORDS[state] ? L(...WORDS[state]) : state;
export const responseTone = (state: ResponseState) => state === "COMPLETED" ? "ok" as const
  : state === "SEND_UNKNOWN" || state === "NOT_SENT" || state === "NEEDS_ACTION" ? "warn" as const
    : state === "NEW" || state === "ASSIGNED" ? undefined : "running" as const;

/** The ways a request can go now: a CreMore link by Slack or mail on a team installation (company sign-in) whose contact
 * delivery and console address are set, the operator's own record on a local one, and a plugin ticket system once set up. */
export function responseChannels(team: boolean, contact: ContactChannels | undefined, ticketSystem: string | null | undefined): ResponseChannel[] {
  const links = team && contact?.console_url ? (["slack", "mail"] as const).filter(channel => contact[channel]) : [];
  return [...links, ...(team ? [] : ["record" as const]), ...(ticketSystem ? ["ticket" as const] : [])];
}

export function channelWord(channel: ResponseChannel, L: Say) {
  return channel === "slack" ? "Slack" : channel === "mail" ? L("메일", "Mail") : channel === "record" ? L("기록", "Record") : L("티켓 시스템", "Ticket system");
}

/** What the chosen way does, before it is sent. */
export function channelNote(channel: ResponseChannel, L: Say) {
  return channel === "record" ? L("아무것도 보내지 않습니다. 담당자에게 직접 알린 뒤 받은 회신을 이 화면의 조치 결과 보고로 기록합니다.", "Nothing is sent. Tell the person yourself, then record their answer here with Report actions.")
    : channel === "ticket" ? L("회사 티켓 시스템에서 담당자 계정에 요청을 엽니다.", "Opens a request for the person's account in the company ticket system.")
      : L(`${channel === "slack" ? "Slack DM으로" : "메일로"} CreMore 링크를 보냅니다. 담당자는 회사 계정으로 로그인해 CreMore에서 조치를 보고합니다. 링크는 7일 동안 쓸 수 있고, 다시 요청하면 이전 링크는 더 쓸 수 없습니다.`,
        `A ${channel === "slack" ? "Slack DM" : "mail"} carries a CreMore link. The person signs in with their company account and reports in CreMore. The link works for 7 days; asking again ends the earlier link.`);
}

/** A link cycle's expiry, and that a new request may then start. */
export function linkExpiry(cycle: Pick<ResponseCycle, "link_expires_at" | "link_expired">, L: Say, locale: Locale) {
  return `${fmtDT(cycle.link_expires_at, locale)}${cycle.link_expired ? ` · ${L("만료됨 · 다시 요청할 수 있음", "Expired · can be requested again")}` : ""}`;
}

/** Why a request did not go out: the link is void, and the reason's code in words. */
export function notSentText(code: string | null | undefined, L: Say) {
  return L("대응 요청이 나가지 않아 링크를 무효로 했습니다. 원인을 확인한 뒤 다시 요청하세요.", "The request did not go out, so its link no longer works. Check the cause, then request again.")
    + (code ? ` ${reasonCodeText(code, L)}` : "");
}

/** Where a link request goes: the person's own DM (or mail) and/or an approved team channel, or null when neither is
 * chosen. Record and ticket requests carry neither field; no channel means no `slack_channel` key. */
export function deliveryTargets(channel: ResponseChannel, dm: boolean, slackChannel: string): { dm?: boolean; slack_channel?: string } | null {
  if (channel !== "slack" && channel !== "mail") return {};
  return dm || slackChannel ? { dm, ...(slackChannel ? { slack_channel: slackChannel } : {}) } : null;
}

/** The team channel the routing recommends, while it is still approved: for `personRef`, that person's own
 * responsibility rule channel only; before anyone is chosen, the one channel the finding's rules name. */
export function recommendedChannel(routing: ResponderRouting, approved: ResponseChannelOption[], personRef?: string): string {
  const named = personRef === undefined ? [routing.slack_channel?.channel_id]
    : routing.recommendations.filter(entry => entry.person.person_ref === personRef).map(entry => entry.slack_channel?.channel_id);
  return named.find(id => id && approved.some(item => item.channel_id === id)) ?? "";
}

/** A cycle's team-channel post, and why the post or a thread update did not happen. */
export function threadText(thread: { name: string }, L: Say) {
  return L(`#${thread.name} 채널에 알림 · 진행 상황은 스레드에 기록됨`, `Posted in #${thread.name} · progress goes to its thread`);
}
export function threadErrorText(code: string, L: Say) {
  // Slack's restricted_action family (a locked thread, a read-only channel, …) reads as one sentence.
  return L("팀 채널 알림 문제: ", "Team channel notice problem: ") + (code.startsWith("SLACK_RESTRICTED_ACTION")
    ? L("Slack이 그 채널이나 스레드에 글을 쓰지 못하게 막았습니다(잠긴 스레드, 읽기 전용 채널 등).", "Slack does not allow posting in that channel or thread (a locked thread, a read-only channel, …).")
    : reasonCodeText(code, L));
}

/** The person's own DM or mail did not go out while the team channel notice did. Delivery history only: whether the
 * link still works is the link-expiry fact's to say (the code stays on the cycle after the link expires). */
export function dmFailedText(channel: ResponseChannel, code: string, L: Say) {
  return (channel === "mail" ? L("개인 메일은 나가지 않았고 팀 채널 알림만 갔습니다. ", "The mail to the person did not go out; only the team channel notice did. ")
    : L("개인 DM은 나가지 않았고 팀 채널 알림만 갔습니다. ", "The DM to the person did not go out; only the team channel notice did. ")) + reasonCodeText(code, L);
}

export function ResponseTag({ c }: { c: CredentialRecord }) {
  const L = useL();
  if (!c.response || c.status === "fp" || c.status === "ignored") return <StatusTag status={c.status} />;
  return <StateChip tone={responseTone(c.response.state)}>{responseLabel(c.response.state, L)}</StateChip>;
}

export function ResponseCard({ c, response, canEdit, admin, onRescan }: {
  c: CredentialRecord; response: Loaded<ResponseSummary>; canEdit: boolean; admin: boolean; onRescan?: () => void;
}) {
  const L = useL(), locale = useLocale(), toast = useToast(), saved = useSaved();
  const setup = useApi<{ system: string | null; label: string | null }>(canEdit ? "ticket-system" : null);
  const contact = useApi<ContactChannels>(canEdit ? "contact-delivery" : null);
  const routing = useApi<ResponderRouting>(canEdit && c.finding_id ? `findings/${c.finding_id}/response/routing` : null);
  // The approved team channels, on a team installation whose Slack bot is set up (any analyst may read the list).
  const approved = useApi<{ channels: ResponseChannelOption[] }>(canEdit && routing.data && !routing.data.manual_email_allowed && contact.data?.slack ? "response-channels" : null);
  const [historyOffset, setHistoryOffset] = useState(0);
  const history = useApi<ResponseSummary>(c.finding_id && historyOffset > 0 ? `findings/${c.finding_id}/response?history_offset=${historyOffset}` : null);
  const [draft, setDraft] = useState<{ channel: ResponseChannel; to: string; person: DirectoryPerson | null; team: string; manual: boolean; ruleTarget: string;
    slackChannel: string; channelEdited: boolean; dm: boolean; ruleChannel: string; routing: ResponderRouting; version: number; id: string } | null>(null);
  const [release, setRelease] = useState<{ version: number; id: string; confirmed: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  // A refused request is said in the form, which keeps the draft (e.g. a channel that changed since approval: 409).
  const [requestError, setRequestError] = useState("");
  // The version the report form opened on: a report is for the case as it was then.
  const [reportVersion, setReportVersion] = useState<number | null>(null);
  const evidence = useCallback((q: string) => api<EvidenceOptions>(`findings/${c.finding_id}/response/evidence-options?q=${encodeURIComponent(q)}`), [c.finding_id]);
  const summary = response.data ?? c.response;
  if (!summary || !c.finding_id) return response.error ? <Card level={3} title={L("대응 진행", "Response progress")}><CardBody>
    <ErrorLine onRetry={response.reload}>{reasonText(response.error, L)}</ErrorLine></CardBody></Card> : null;
  const current = summary.current;
  const state = summary.state;
  const historyPage = historyOffset > 0 ? history.data : summary;
  // The server says when a new cycle may start (an expired link, a request that did not go out, a moved ticket system …).
  const canRequest = summary.can_request === true;
  const team = routing.data ? !routing.data.manual_email_allowed : false;
  const channels = routing.data ? responseChannels(team, contact.data, setup.data?.system) : [];
  const channelsKnown = Boolean(routing.data) && !contact.loading && !setup.loading;
  const channel = current ? current.channel ?? (current.ticket ? "ticket" : undefined) : undefined;
  const link = channel === "slack" || channel === "mail";
  const changed = draft && draft.version !== summary.version;
  const teamChannels = approved.data?.channels ?? [];
  const targets = draft ? deliveryTargets(draft.channel, draft.dm, draft.slackChannel) : null;
  const channelPick = Boolean(draft && (draft.channel === "slack" || draft.channel === "mail") && teamChannels.length);
  const submit = async () => {
    if (!draft || changed || !targets || (draft.manual ? !draft.routing.manual_email_allowed || !draft.to.trim() : !selectablePerson(draft.person))) return;
    setBusy(true); setRequestError("");
    let ruleSaved = false;
    try {
      if (!draft.manual && draft.person && draft.ruleTarget) {
        const target = draft.routing.targets.find(entry => routingTargetKey(entry) === draft.ruleTarget);
        if (!target) return;
        await send(`findings/${c.finding_id}/response/routing-rule`, "PUT", { kind: target.kind, key: target.key,
          person_ref: draft.person.person_ref, team: draft.team.trim(), expected_version: target.rule?.version ?? 0, ...(draft.ruleChannel ? { channel_id: draft.ruleChannel } : {}) });
        ruleSaved = true;
        setDraft(value => value ? { ...value, ruleTarget: "" } : value);
        saved(); routing.reload();
      }
      const next = await send<ResponseSummary>(`findings/${c.finding_id}/response/ticket`, "POST", {
        channel: draft.channel, ...(draft.manual ? { to: draft.to.trim() } : { person_ref: draft.person!.person_ref, team: draft.team.trim() }),
        ...targets, locale, expected_version: draft.version, request_id: draft.id,
      });
      response.replace(next);
      setDraft(null); saved(); response.reload();
      // A send that did not go out is still an answer (200, NOT_SENT): say so, not "updated".
      if (next.state === "NOT_SENT") toast(notSentText(next.current?.error_code, L), "bad");
      else toast(L("대응 요청 상태를 갱신했습니다.", "Response request updated."));
    } catch (error) { setRequestError((ruleSaved ? L("책임 규칙은 저장됐지만 대응 요청은 보내지 못했습니다. ", "The responsibility rule was saved, but the response request did not go out. ") : "") + reasonText(error, L));
      if (isConflict(error)) { response.reload(); routing.reload(); } }
    finally { setBusy(false); }
  };
  const releaseUnknown = async () => {
    if (!release?.confirmed) return;
    setBusy(true);
    try {
      response.replace(await send<ResponseSummary>(`findings/${c.finding_id}/response/release-unknown`, "POST", {
        expected_version: release.version, request_id: release.id, confirmed_no_pending_ticket: true,
      }));
      setRelease(null); saved(); response.reload();
      toast(L("관리자의 확인을 기록했습니다. 새 요청을 보낼 수 있습니다.", "The admin's confirmation was recorded. A new request can be sent."));
    } catch (error) { toast(reasonText(error, L), "bad"); if (isConflict(error)) response.reload(); }
    finally { setBusy(false); }
  };
  const safeTicketURL = current?.ticket?.url && /^https?:\/\//i.test(current.ticket.url) ? current.ticket.url : null;
  return <Card level={3} title={L("대응 진행", "Response progress")} right={<StateChip tone={responseTone(state)}>{responseLabel(state, L)}</StateChip>}>
    <CardBody>
      <Facts>
        <Fact label={L("내부 대응 담당자", "Internal response owner")}>{c.owner?.name ?? c.owner?.team ?? L("미지정", "Unassigned")}</Fact>
        <Fact label={L("대응 요청 담당자", "Requested responder")}>{current?.recipient?.name ?? current?.assigned_to ?? L("미요청", "Not requested")}
          {current?.recipient ? <div className="meta">{[current.recipient.email, current.recipient.department].filter(Boolean).join(" · ")}</div> : null}
          {current?.team ? <div className="meta">{L("책임 팀: ", "Responsible team: ")}{current.team}</div> : null}</Fact>
        {current ? <Fact label={L("요청 방법", "Sent by")}>{channel ? channelWord(channel, L) : "—"}{link ? <div className="meta">{state === "SENDING" ? L("보내는 중", "Sending")
          : state === "NOT_SENT" ? L("보내지 못함", "Not sent") : L("링크 보냄", "Link sent")}</div> : null}</Fact> : null}
        {current && link && state !== "NOT_SENT" ? <Fact label={L("링크 만료", "Link expires")}><span className={current.link_expired ? "tone-warn" : undefined}>{linkExpiry(current, L, locale)}</span></Fact> : null}
        {current?.thread || current?.thread_error ? <Fact label={L("팀 채널", "Team channel")}>{current.thread ? <span className="cell-wrap">{threadText(current.thread, L)}</span> : "—"}
          {current.thread_error ? <div className="meta tone-warn">{threadErrorText(current.thread_error, L)}</div> : null}</Fact> : null}
        {channel === "ticket" ? <Fact label={L("외부 티켓", "External ticket")}>{current?.ticket?.ticket ? safeTicketURL
          ? <a className="link-btn" href={safeTicketURL} target="_blank" rel="noreferrer">{current.ticket.system} #{current.ticket.ticket}</a>
          : `${current.ticket.system} #${current.ticket.ticket}` : L("티켓 번호 확인 전", "Ticket number not confirmed yet")}</Fact> : null}
        <Fact label={L("요청 시각", "Requested")}>{fmtDT(current?.requested_at, locale)}{current?.requested_by ? <div className="subtle small">{current.requested_by_name || current.requested_by_email || actorLabel(current.requested_by, L)}
          {current.requested_by_name && current.requested_by_email ? <div>{current.requested_by_email}</div> : null}</div> : null}</Fact>
        <Fact label={L("담당자 회신", "Responder replied")}>{fmtDT(current?.answered_at, locale)}{current?.answered_by ? <div className="subtle small" data-tip={current.answered_by}>{current.assigned_to}</div> : null}</Fact>
        <Fact label={L("회신 수신", "Reply received")}>{fmtDT(current?.received_at, locale)}</Fact>
        {channel === "ticket" ? <Fact label={L("티켓 발송 확인", "Ticket delivery confirmed")}>{fmtDT(current?.ticket_opened_at, locale)}</Fact> : null}
        <Fact label={L("마지막 확인 검사", "Last verification scan")}>{fmtDT(current?.last_scan_at, locale)}</Fact>
        <Fact label={L("제거 확인 시각", "Removal confirmed")}>{fmtDT(current?.verified_at, locale)}</Fact>
      </Facts>
      <p className="meta">{L("담당자의 조치 보고를 받은 뒤 평문 제거·기존 키 종료·필요한 교체 키 보관을 확인합니다. 저장된 근거와 회신은 약 1분마다 갱신합니다.", "After the responder's action report, CreMore checks removal, old-key retirement and replacement storage where needed. Saved evidence and replies refresh about once a minute.")}</p>
      {current?.completion_version === 2 ? <CompletionEvidence cycle={current} findingId={c.finding_id} /> : null}
      {canEdit && !current && !summary.reviewed_at && summary.state !== "REVIEWING" ? <button className="ghost-btn" type="button" disabled={busy} onClick={async () => {
        setBusy(true); try { response.replace(await send<ResponseSummary>(`findings/${c.finding_id}/response/review`, "POST", { expected_version: summary.version })); saved(); response.reload(); }
        catch (error) { toast(reasonText(error, L), "bad"); response.reload(); } finally { setBusy(false); }
      }}>{L("검토 시작", "Start review")}</button> : null}
      {current?.recurred_at ? <p className="meta tone-warn">{L("완료 후 다시 발견됐습니다. 새 대응 요청으로 최신 조치 보고와 회신을 받아야 합니다.", "Exposure recurred after completion. Open a new response request for a fresh report and reply.")}</p> : null}
      {summary.can_report && !current?.recurred_at && !current?.link_expired && current?.completion_version === 2 && ["WAITING_OWNER", "REPORT_REQUIRED", "WAITING_VERIFICATION", "NEEDS_ACTION"].includes(state)
        ? <button className="primary-btn" type="button" onClick={() => setReportVersion(summary.version)}>{L(current.report ? "조치 보고 보완" : "조치 결과 보고", current.report ? "Supplement action report" : "Report actions")}</button> : null}
      {reportVersion !== null && current ? <ResponseReportForm changed={summary.version !== reportVersion} evidence={evidence}
        submit={async body => { await send(`findings/${c.finding_id}/response/report`, "POST", { expected_version: reportVersion, request_id: current.request_id, ...body }); }}
        onClose={() => setReportVersion(null)} onSaved={() => { setReportVersion(null); saved(); response.reload(); }} /> : null}
      {state === "SEND_UNKNOWN" ? <p className="meta tone-warn">{L("발송 결과가 불확실하여 중복 발송을 막았습니다. 외부 티켓 시스템에서 생성 여부를 먼저 확인하세요.", "The delivery result is uncertain, so duplicate sending is blocked. Check whether the ticket was created in the external system first.")}</p> : null}
      {state === "NOT_SENT" ? <p className="meta tone-warn">{notSentText(current?.error_code, L)}</p>
        : current?.error_code && (channel === "slack" || channel === "mail") ? <p className="meta tone-warn" role="status">{dmFailedText(channel, current.error_code, L)}</p>
        : current?.error_code ? <p className="meta tone-warn">{L("확인 필요: ", "Needs checking: ")}{reasonCodeText(current.error_code, L)}</p> : null}
      {response.error ? <ErrorLine onRetry={response.reload}>{reasonText(response.error, L)}</ErrorLine> : null}
      {routing.error ? <ErrorLine onRetry={routing.reload}>{reasonText(routing.error, L)}</ErrorLine> : null}
      {draft ? <form onSubmit={event => { event.preventDefault(); void submit(); }}>
        <SelectField label={L("요청 방법", "Send by")} value={draft.channel} onChange={channel => setDraft({ ...draft, channel })} disabled={busy}
          options={channels.map(id => ({ id, label: channelWord(id, L) }))} />
        <p className="meta">{channelNote(draft.channel, L)}</p>
        {channelPick ? <>
          <SelectField label={L("팀 Slack 채널에도 알림", "Also post in a team Slack channel")} value={draft.slackChannel} disabled={busy}
            onChange={slackChannel => setDraft({ ...draft, slackChannel, channelEdited: true })} hint={L("요청과 링크를 채널에 올리고 담당자를 멘션합니다. 진행 상황은 그 글의 스레드에 기록되며, 회신은 링크로만 받습니다.",
              "Posts the request and link in the channel, mentioning the person. Progress goes to the post's thread; answers come only through the link.")}
            options={[{ id: "", label: L("채널에 올리지 않음", "Do not post in a channel") }, ...teamChannels.map(item => ({ id: item.channel_id,
              label: `#${item.name} · ${item.is_private ? L("비공개", "Private") : L("공개", "Public")}` }))]} />
          <label className="check-line"><input type="checkbox" checked={draft.dm} disabled={busy} onChange={event => setDraft({ ...draft, dm: event.target.checked })} />
            {draft.channel === "mail" ? L("개인 메일도 보내기", "Also mail the person") : L("개인 DM도 보내기", "Also DM the person")}</label>
        </> : null}
        {!targets ? <p className="meta tone-warn" role="alert">{L("보낼 곳을 하나 이상 고르세요: 개인 DM(메일) 또는 팀 채널.", "Choose at least one place to send it: the person's DM (mail) or a team channel.")}</p> : null}
        {draft.routing.manual_email_allowed ? <label className="check-line"><input type="checkbox" checked={draft.manual} disabled={busy}
          onChange={event => setDraft({ ...draft, manual: event.target.checked, person: null, to: "", ruleTarget: "" })} />{L("로컬 설치에서 이메일 직접 입력", "Enter an email directly on this local installation")}</label> : null}
        {draft.manual ? <Field label={L("대응 요청 담당자 이메일", "Responder email")} htmlFor="response-to"><input id="response-to" type="email" required maxLength={254} value={draft.to}
          onChange={event => setDraft({ ...draft, to: event.target.value })} /></Field> : <ResponderFields routing={draft.routing} person={draft.person}
          // A prefilled channel belongs to the recommendation it came from: choosing another person takes that person's
          // recommended channel (or none), unless the channel was chosen by hand.
          onChange={person => setDraft(value => value ? { ...value, person, slackChannel: value.channelEdited || !person ? value.slackChannel
            : recommendedChannel(value.routing, teamChannels, person.person_ref) } : value)} team={draft.team} onTeam={team => setDraft(value => value ? { ...value, team } : value)}
          ruleTarget={draft.ruleTarget} onRuleTarget={admin ? ruleTarget => {
            const rule = draft.routing.targets.find(entry => routingTargetKey(entry) === ruleTarget)?.rule?.channel_id;
            setDraft({ ...draft, ruleTarget, ruleChannel: rule && teamChannels.some(item => item.channel_id === rule) ? rule : draft.slackChannel });
          } : undefined} channels={teamChannels} ruleChannel={draft.ruleChannel} onRuleChannel={ruleChannel => setDraft({ ...draft, ruleChannel })} disabled={busy} admin={admin} />}
        {changed ? <p className="meta tone-warn">{L("대응 상태가 변경됐습니다. 입력은 유지했습니다. 취소 후 최신 상태에서 다시 요청하세요.", "The response state changed. Your input is kept. Cancel and request again from the latest state.")}</p> : null}
        {requestError ? <p className="ig-result bad" role="alert"><Ic name="alert" size={15} /><span>{requestError}</span></p> : null}
        <div className="md-actions"><button type="button" className="ghost-btn" disabled={busy} onClick={() => { setDraft(null); setRequestError(""); }}>{L("취소", "Cancel")}</button>
          <button type="submit" className="primary-btn" disabled={busy || !channels.includes(draft.channel) || !targets || (draft.manual ? !draft.to.trim() : !selectablePerson(draft.person)) || Boolean(changed)}>{L("대응 요청 보내기", "Send response request")}</button></div>
      </form> : canEdit && canRequest ? <div className="md-actions"><button type="button" className="primary-btn" disabled={!channels.length || !routing.data || approved.loading || busy}
        onClick={() => { if (routing.data && channels.length) setDraft({ channel: channels[0], to: "", person: null, team: routing.data.assignment?.team ?? "", ruleTarget: "",
          slackChannel: recommendedChannel(routing.data, teamChannels), channelEdited: false, dm: true, ruleChannel: "",
          manual: routing.data.manual_email_allowed && !routing.data.recommendations.length, routing: routing.data, version: summary.version, id: randomId() }); }}>
        {current ? L("대응 다시 요청", "Request response again") : L("대응 요청", "Request response")}</button>
        {channelsKnown && !channels.length ? <span className="meta">{L("관리자가 연동 > 기타 설정 > 연락 발송에서 Slack 또는 메일과 콘솔 주소를 설정하면 대응 요청을 보낼 수 있습니다.",
          "An admin sets up Slack or mail and the console address under Integrations > Other settings > Contact delivery before a request can go out.")}</span> : null}</div> : null}
      {canEdit && onRescan && state === "WAITING_VERIFICATION" ? <button type="button" className="primary-btn" onClick={onRescan}>{L("제거 확인을 위해 다시 검사", "Rescan to verify removal")}</button> : null}
      {admin && state === "SEND_UNKNOWN" ? release ? <div>
        <label className="check-line"><input type="checkbox" checked={release.confirmed} onChange={event => setRelease({ ...release, confirmed: event.target.checked })} />
          {L("외부 티켓이 생성되지 않았거나 기존 티켓을 종료하여 진행 중인 중복 요청이 없음을 확인했습니다.", "I confirmed that no external ticket was created, or closed the existing ticket so no duplicate request remains pending.")}</label>
        <div className="md-actions"><button type="button" className="ghost-btn" disabled={busy} onClick={() => setRelease(null)}>{L("취소", "Cancel")}</button>
          <button type="button" className="primary-btn" disabled={busy || !release.confirmed || release.version !== summary.version} onClick={() => void releaseUnknown()}>{L("확인 기록 후 재요청 허용", "Record confirmation and allow a new request")}</button></div>
      </div> : <button type="button" className="ghost-btn" onClick={() => setRelease({ version: summary.version, id: current?.request_id ?? randomId(), confirmed: false })}>{L("진행 중인 중복 요청 없음 확인", "Confirm no duplicate request is pending")}</button> : null}
      {(summary.history_total ?? summary.history?.length ?? 0) > 1 ? <details><summary>{L("이전 대응 요청", "Previous response requests")}</summary>
        {history.error ? <ErrorLine onRetry={history.reload}>{reasonText(history.error, L)}</ErrorLine> : <ul className="meta">{historyPage?.history?.map(item =>
          <li key={item.request_id}>{fmtDT(item.requested_at, locale)} · {item.assigned_to} · {responseLabel(item.state, L)}</li>)}</ul>}
        {(summary.history_total ?? 0) > 20 ? <div className="md-actions"><button type="button" className="ghost-btn" disabled={historyOffset === 0 || history.loading} onClick={() => setHistoryOffset(Math.max(0, historyOffset - 20))}>{L("이전 페이지", "Previous page")}</button>
          <span className="meta">{historyOffset + 1}–{Math.min(historyOffset + 20, summary.history_total!)} / {summary.history_total}</span>
          <button type="button" className="ghost-btn" disabled={historyOffset + 20 >= summary.history_total! || history.loading} onClick={() => setHistoryOffset(historyOffset + 20)}>{L("다음 페이지", "Next page")}</button></div> : null}
      </details> : null}
    </CardBody>
  </Card>;
}
