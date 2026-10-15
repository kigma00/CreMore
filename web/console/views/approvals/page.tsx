"use client";

/* Action approvals: every AWS key action plan, key rotation, management action and ticket that waits for an
 * approval, an execution or a recheck, newest first. A row opens the record with the step this person may take;
 * the server checks the same rules again. */

import { useMemo, useState } from "react";

import { useLocale } from "@/components/locale";
import { reasonText, send, useApi, useApiPage, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { actorLabel, typeLabel } from "@/console/labels";
import { Drawer, useToast } from "@/console/layer";
import { Logo, serviceName } from "@/console/logos";
import { PageNavigation, usePageHistory } from "@/console/pagination";
import { type CredentialRecord, RECORDS_PATH, type RecordsResponse } from "@/console/records";
import type { ViewProps } from "@/console/shell";
import { DAY, fmtDT, rel, type Say, time, useL } from "@/console/text";
import { Card, CardBody, EmptyRow, ErrorLine, Fact, Facts, Loading, PageHead, Seg, StateChip, Switch, Tabs, Tile, Tiles } from "@/console/ui";
import {
  actionWords, type Actor, MANAGEMENT_PATH, MANAGEMENT_WORDS, type ManagementAction, type Plan, planStatus, PLANS_PATH,
  type Queue, ROTATION_WORDS, type RotationJob, ROTATIONS_PATH, say, STATUS_TONE, STATUS_WORDS,
  STEP_WORDS, type Ticket, TICKET_WORDS, ticketNeedsApproval, type TicketPage, TICKETS_PATH,
} from "@/console/views/approvals/model";
import { PlanCard } from "@/console/views/approvals/plans";

type Kind = "plan" | "rotation" | "management" | "ticket";
type Stage = "approve" | "execute" | "check" | "done" | "closed";
type Item = { kind: Kind; id: string; at: string; stage: Stage; plan?: Plan; job?: RotationJob; action?: ManagementAction; ticket?: Ticket };

function planStage(plan: Plan): Stage {
  const status = planStatus(plan);
  return status === "PENDING_APPROVAL" ? "approve" : status === "APPROVED" || status === "QUEUED" || status === "EXECUTING" ? "execute"
    : status === "OUTCOME_UNKNOWN" || status === "FAILED" || status === "BLOCKED" ? "check" : status === "VERIFIED" ? "done" : "closed";
}
const rotationStage = (job: RotationJob): Stage => job.status === "PUBLISHED" && !job.reconciliation_required ? "done" : "check";
const actionStage = (action: ManagementAction): Stage => action.status === "PENDING" ? "approve" : action.status === "REJECTED" ? "closed" : "done";
const ticketStage = (ticket: Ticket): Stage => ticketNeedsApproval(ticket) ? "approve" : "done";
const STAGE_TONE: Record<Stage, "ok" | "warn" | "partial" | "running" | undefined> = { approve: "warn", execute: "running", check: "partial", done: "ok", closed: undefined };

/** A key id as the other screens show it: the first and last four characters. */
const masked = (key: string) => key.length > 8 ? `${key.slice(0, 4)}••••${key.slice(-4)}` : key;

export function Approvals({ session, route, setParams, go }: ViewProps) {
  const L = useL();
  const locale = useLocale();
  const plans = useApi<Queue>(PLANS_PATH, { every: 30_000 });
  const rotationPage = usePageHistory<string | null>(ROTATIONS_PATH, null);
  const actionPage = usePageHistory<string | null>(MANAGEMENT_PATH, null);
  const ticketPage = usePageHistory<number>(TICKETS_PATH, 0);
  const rotations = useApiPage<RotationJob[]>(`${ROTATIONS_PATH}?limit=100${rotationPage.position ? `&cursor=${encodeURIComponent(rotationPage.position)}` : ""}`, { every: 30_000 });
  const actions = useApiPage<ManagementAction[]>(`${MANAGEMENT_PATH}?limit=100${actionPage.position ? `&cursor=${encodeURIComponent(actionPage.position)}` : ""}`, { every: 30_000 });
  const tickets = useApi<TicketPage>(`${TICKETS_PATH}?offset=${ticketPage.position}`, { every: 60_000 });
  const records = useApi<RecordsResponse>(RECORDS_PATH);
  const [scope, setScope] = useState<"open" | "all">("open");
  const actor: Actor = { id: session.id, role: session.role, ref: session.ref };
  const p = route.params;
  const tab = (["plan", "rotation", "management", "ticket"] as const).find(kind => kind === p.get("kind")) ?? "all";

  const items = useMemo(() => {
    const out: Item[] = [];
    for (const plan of plans.data?.items ?? []) out.push({ kind: "plan", id: `plan:${plan.id}`, at: plan.requested_at, stage: planStage(plan), plan });
    for (const job of rotations.data?.data ?? []) out.push({ kind: "rotation", id: `rotation:${job.id}`, at: job.created_at, stage: rotationStage(job), job });
    for (const action of actions.data?.data ?? []) out.push({ kind: "management", id: `management:${action.id}`, at: action.created_at, stage: actionStage(action), action });
    // Tickets come here only when their playbook asks an independent Admin to approve them.
    for (const ticket of tickets.data?.data.items ?? []) if (ticket.playbook?.config.approval_rule === "INDEPENDENT_ADMIN")
      out.push({ kind: "ticket", id: `ticket:${ticket.id}`, at: ticket.updated_at, stage: ticketStage(ticket), ticket });
    const order: Record<Stage, number> = { approve: 0, execute: 1, check: 2, done: 3, closed: 4 };
    return out.sort((a, b) => order[a.stage] - order[b.stage] || (time(b.at) ?? 0) - (time(a.at) ?? 0));
  }, [plans.data, rotations.data, actions.data, tickets.data]);

  const title = L("조치 승인", "Action approvals");
  const meta = L("Credential 조치를 요청·승인·실행한 기록 · 건수는 현재 불러온 페이지 기준", "Credential actions requested, approved and executed · Counts cover the loaded pages");
  const failed = plans.error;
  if (failed) return <><PageHead title={title} meta={meta} /><ErrorLine onRetry={plans.reload}>{reasonText(failed, L)}</ErrorLine></>;
  if (!plans.data) return <><PageHead title={title} meta={meta} /><Loading /></>;

  const now = Date.now();
  const count = (stage: Stage) => items.filter(item => item.stage === stage).length;
  const doneRecently = items.filter(item => item.stage === "done" && now - (time(item.at) ?? 0) <= 30 * DAY).length;
  const inTab = (item: Item) => tab === "all" || item.kind === tab;
  const rows = items.filter(item => inTab(item) && (scope === "all" || item.stage === "approve" || item.stage === "execute" || item.stage === "check"));
  const selected = items.find(item => item.id === p.get("id"));
  const recordOf = (credentialId?: string | null) => records.data?.items.find(record => record.credential_id === credentialId);
  const findingRecord = (findingId?: string | null) => records.data?.items.find(record => record.finding_id === findingId);
  const reload = () => { plans.reload(); rotations.reload(); actions.reload(); tickets.reload(); };

  return <>
    <PageHead title={title} meta={meta} />
    <Tiles>
      <Tile icon="checkList" tone={count("approve") ? "amber" : "green"} label={L("승인 대기", "Awaiting approval")} value={count("approve")}
        tip={L("관리자·두 번째 담당자의 승인을 기다리는 조치입니다.", "Actions waiting for an Admin's or a second operator's approval.")} onClick={() => { setScope("open"); setParams({ kind: null }); }} />
      <Tile icon="play" tone="blue" label={L("실행 대기", "Awaiting execution")} value={count("execute")}
        tip={L("승인됐고 실행 요청이나 진행을 기다리는 조치입니다.", "Approved actions waiting to be executed or finishing.")} />
      <Tile icon="alert" tone={count("check") ? "red" : "green"} label={L("결과 확인 필요", "Result to check")} value={count("check")}
        tip={L("실패했거나 결과를 다시 확인해야 하는 조치입니다.", "Actions that failed or need their result rechecked.")} />
      <Tile icon="checkCircle" tone="green" label={L("30일 안에 완료", "Done in 30 days")} value={doneRecently}
        tip={L("최근 30일 안에 완료를 확인한 조치입니다.", "Actions verified done in the last 30 days.")} onClick={() => setScope("all")} />
    </Tiles>

    <Tabs value={tab} onChange={value => setParams({ kind: value === "all" ? null : value, id: null })} label={L("조치 종류", "Action kinds")}
      items={[{ id: "all" as const, label: L("전체", "All"), count: items.length },
        { id: "plan" as const, label: L("키 조치", "Key actions"), count: items.filter(item => item.kind === "plan").length },
        { id: "rotation" as const, label: L("키 교체", "Key rotation"), count: items.filter(item => item.kind === "rotation").length },
        { id: "management" as const, label: L("관리 조치", "Management actions"), count: items.filter(item => item.kind === "management").length },
        { id: "ticket" as const, label: L("티켓 승인", "Ticket approvals"), count: items.filter(item => item.kind === "ticket").length }]} />
    <Card className="list-card">
      <div className="list-tools">
        <Seg value={scope} onChange={setScope} label={L("보기", "Show")}
          options={[{ id: "open", label: L("처리할 것", "To handle") }, { id: "all", label: L("전체 기록", "All records") }]} />
        <OwnerPolicy required={plans.data.policy.owner_approval_required === true} admin={session.role === "Admin"} onChanged={plans.reload} />
      </div>
      <div className="table-wrap"><table className="tbl">
        <thead><tr><th>{L("대상", "Target")}</th><th className="col-md">{L("조치", "Action")}</th><th>{L("상태", "Status")}</th>
          <th className="col-sm">{L("요청", "Requested")}</th><th className="col-sm">{L("다음 단계", "Next step")}</th></tr></thead>
        <tbody>
          {rows.length ? rows.map(item => {
            const row = describe(item, L, recordOf, findingRecord);
            return <tr key={item.id} tabIndex={0} aria-selected={selected?.id === item.id} onClick={() => setParams({ id: item.id })}
              onKeyDown={event => { if (event.key === "Enter") setParams({ id: item.id }); }}>
              <td><div className="cred-cell"><Logo id={row.provider} size={28} /><div className="cred-text"><div className="cred-name">{row.target}</div>
                <div className="cred-hint">{row.sub}</div></div></div></td>
              <td className="col-md">{row.action}</td>
              <td><StateChip tone={row.tone}>{row.status}</StateChip></td>
              <td className="col-sm"><span data-tip={fmtDT(item.at, locale)}>{rel(item.at, locale)}</span><div className="subtle small">{row.by}</div></td>
              <td className="col-sm">{nextStep(item, L)}</td>
            </tr>;
          }) : <EmptyRow colSpan={5}>{L("현재 페이지에 조건에 맞는 조치가 없습니다. 다른 페이지도 확인하세요.", "No actions match on these pages. Check other pages as well.")}</EmptyRow>}
        </tbody>
      </table></div>
      <div className="list-foot"><span>{L(`현재 페이지에서 ${rows.length}건`, `${rows.length} actions on the current pages`)}</span></div>
      {(tab === "all" || tab === "rotation") ? <>
        {rotations.error ? <ErrorLine onRetry={rotations.reload}>{reasonText(rotations.error, L)}</ErrorLine> : null}
        <PageNavigation label={L("키 교체 기록", "Key rotation history")} {...rotationPage} loading={rotations.loading}
          hasNext={Boolean(rotations.data?.nextCursor)} next={() => { if (rotations.data?.nextCursor) { rotationPage.next(rotations.data.nextCursor); setParams({ id: null }); } }} />
      </> : null}
      {(tab === "all" || tab === "management") ? <>
        {actions.error ? <ErrorLine onRetry={actions.reload}>{reasonText(actions.error, L)}</ErrorLine> : null}
        <PageNavigation label={L("관리 조치", "Management actions")} {...actionPage} loading={actions.loading}
          hasNext={Boolean(actions.data?.nextCursor)} next={() => { if (actions.data?.nextCursor) { actionPage.next(actions.data.nextCursor); setParams({ id: null }); } }} />
      </> : null}
      {(tab === "all" || tab === "ticket") ? <>
        {tickets.error ? <ErrorLine onRetry={tickets.reload}>{reasonText(tickets.error, L)}</ErrorLine> : null}
        <PageNavigation label={L("티켓 승인", "Ticket approvals")} {...ticketPage} loading={tickets.loading}
          hasNext={tickets.data?.data.next_offset != null} next={() => { const next = tickets.data?.data.next_offset; if (next != null) { ticketPage.next(next); setParams({ id: null }); } }} />
      </> : null}
    </Card>

    {selected ? <ItemDrawer key={`${selected.kind}:${selected.id}`} item={selected} actor={actor} policy={plans.data.policy}
      record={selected.plan ? recordOf(selected.plan.credential_id) : selected.job ? recordOf(selected.job.credential_id) : selected.action ? findingRecord(selected.action.finding_id)
        : selected.ticket ? recordOf(selected.ticket.credential_id) : undefined}
      onClose={() => setParams({ id: null })} onChanged={reload} go={go} /> : null}
  </>;
}

/** Whether key actions wait for their owner's approval: an Admin turns it on or off (audited); others see it. */
function OwnerPolicy({ required, admin, onChanged }: { required: boolean; admin: boolean; onChanged: () => void }) {
  const L = useL();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const label = L("실행 전 소유자 승인", "Owner approval before execution");
  const change = async (next: boolean) => {
    setBusy(true);
    try {
      await send("settings/owner-approval", "PUT", { required: next });
      toast(next ? L("키 조치는 소유자 승인을 받은 뒤 실행합니다.", "Key actions now wait for their owner's approval.")
        : L("키 조치는 소유자 승인 없이 실행할 수 있습니다.", "Key actions now run without their owner's approval."));
      onChanged();
    } catch (reason) { toast(reasonText(reason, L), "bad"); }
    finally { setBusy(false); }
  };
  return <span className="list-switch">
    <span className="subtle small">{label}</span>
    {admin ? <Switch checked={required} onChange={next => void change(next)} label={label} disabled={busy} />
      : <StateChip tone={required ? "ok" : undefined}>{required ? L("켜짐", "On") : L("꺼짐", "Off")}</StateChip>}
  </span>;
}

function describe(item: Item, L: Say, recordOf: (id?: string | null) => CredentialRecord | undefined, findingRecord: (id?: string | null) => CredentialRecord | undefined) {
  if (item.plan) {
    const plan = item.plan, status = planStatus(plan);
    // Another provider's credential names its provider; an AWS key its IAM user and account.
    const other = plan.target?.kind === "provider_credential" ? plan.target.provider ?? "generic" : null;
    return { provider: other ?? "aws", target: plan.identifier_hint,
      sub: other ? serviceName(other) : plan.target?.kind === "departed_owner" ? L(`${plan.user_name} · 퇴사자 키`, `${plan.user_name} · departed owner's key`) : `${plan.user_name} · ${plan.account_id}`,
      action: L(...actionWords(plan.action_type, plan.target?.revokes)), status: L(...STATUS_WORDS[status]), tone: STATUS_TONE[status], by: actorLabel(plan.requested_by, L) };
  }
  if (item.job) {
    const job = item.job;
    return { provider: "aws", target: masked(job.old_key_id) || recordOf(job.credential_id)?.hint || "—", sub: `${job.user_name} · ${job.account_id}`,
      action: L("이전 키 교체 이력", "Legacy key rotation history"), status: say(ROTATION_WORDS, job.status, L), tone: STAGE_TONE[item.stage], by: actorLabel(job.requested_by, L) };
  }
  if (item.action) {
    const record = findingRecord(item.action.finding_id);
    return { provider: record?.provider ?? "generic", target: record?.name || (record ? typeLabel(record.credential_type, L) : L("발견 항목", "Finding")), sub: record?.hint ?? "",
      action: say(MANAGEMENT_WORDS, item.action.action_type, L), status: say(MANAGEMENT_WORDS, item.action.status, L), tone: STAGE_TONE[item.stage], by: actorLabel(item.action.requested_by ?? "", L) };
  }
  const ticket = item.ticket!;
  const record = recordOf(ticket.credential_id);
  return { provider: ticket.provider || "generic", target: record?.name || typeLabel(ticket.credential_type, L), sub: record?.hint ?? serviceName(ticket.provider),
    action: say(TICKET_WORDS, ticket.template_id, L), status: ticketNeedsApproval(ticket) ? L("독립 승인 대기", "Awaiting independent approval") : say(TICKET_WORDS, ticket.status, L),
    tone: STAGE_TONE[item.stage], by: actorLabel(ticket.created_by, L) };
}

function nextStep(item: Item, L: Say) {
  if (item.job) return item.stage === "check" ? L("관리자 상태 확인 필요", "Administrator reconciliation required") : L("읽기 전용 이력", "Read-only history");
  if (item.stage === "approve") return item.kind === "plan" ? L("관리자 승인", "Admin approval") : item.kind === "ticket" ? L("다른 관리자 승인", "Another Admin approves")
    : L("두 번째 담당자 확인", "A second operator confirms");
  if (item.stage === "execute") return planStatus(item.plan!) === "APPROVED" ? L("실행 요청", "Request execution") : L("실행 중", "Executing");
  if (item.stage === "check") return item.plan && planStatus(item.plan) === "OUTCOME_UNKNOWN" ? L("상태 다시 확인", "Recheck the state") : L("원인 확인", "Look into it");
  return <span className="subtle">—</span>;
}

function ItemDrawer({ item, actor, policy, record, onClose, onChanged, go }: {
  item: Item; actor: Actor; policy: Queue["policy"]; record?: CredentialRecord; onClose: () => void; onChanged: () => void; go: ViewProps["go"];
}) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const [busy, setBusy] = useState(false);
  const row = describe(item, L, () => record, () => record);
  const act = async (path: string, body: unknown, done: string) => {
    setBusy(true);
    try { await send(path, "POST", body); toast(done); saved(); onChanged(); }
    catch (reason) { toast(reasonText(reason, L), "bad"); }
    finally { setBusy(false); }
  };
  const remediator = actor.role === "Remediator" || actor.role === "Admin";
  // A shared-token installation has one operator, who confirms their own request by re-checking it.
  const ownAction = Boolean(item.action?.requested_by) && item.action?.requested_by === actor.id;
  const single = policy.single_operator === true;
  const [selfChecked, setSelfChecked] = useState(false);
  return <Drawer label={L(`${row.action} 상세`, `${row.action} details`)} onClose={onClose}>
    <div className="drawer-head">
      <div className="dh-top">
        <div className="dh-logo"><Logo id={row.provider} size={34} /></div>
        <div className="dh-main">
          <div className="md-crumb">{L("조치 승인", "Action approvals")}</div>
          <h2 className="dh-title">{row.action}</h2>
          <div className="dh-badges"><StateChip tone={row.tone}>{row.status}</StateChip><span className="tag mono">{row.target}</span></div>
        </div>
        <div className="dh-actions"><button type="button" className="icon-btn" aria-label={L("상세 닫기", "Close details")} data-tip={L("상세 닫기", "Close details")} onClick={onClose}><Ic name="panelClose" size={19} /></button></div>
      </div>
    </div>
    <div className="drawer-body" id="drawer-body">
      {item.plan ? <PlanCard plan={item.plan} policy={policy} actor={actor} onChanged={() => { saved(); onChanged(); }} /> : null}
      {item.job ? <Card level={3} title={L("이전 키 교체 이력 · 읽기 전용", "Legacy key rotation history · read only")}>
        <CardBody>
          <Facts>
            <Fact label={L("IAM 사용자", "IAM user")}>{item.job.user_name}<div className="subtle small">{item.job.account_id}</div></Fact>
            <Fact label={L("기존 키", "Old key")}><span className="mono">{masked(item.job.old_key_id)}</span></Fact>
            {item.job.new_key_id ? <Fact label={L("새 키", "New key")}><span className="mono">{masked(item.job.new_key_id)}</span></Fact> : null}
            <Fact label={L("Secret", "Secret")}><span className="mono small cell-wrap">{item.job.secret_arn}</span></Fact>
            <Fact label={L("요청", "Requested")}>{actorLabel(item.job.requested_by, L)}<div className="subtle small">{fmtDT(item.job.created_at, locale)}</div></Fact>
            <Fact label={L("승인", "Approved")}>{item.job.approved_by ? actorLabel(item.job.approved_by, L) : <span className="subtle">{L("대기", "Waiting")}</span>}</Fact>
            {item.job.error ? <Fact label={L("결과 코드", "Result code")}><span className="mono">{item.job.error}</span></Fact> : null}
          </Facts>
          <p className="meta">{L("이전 교체 작업은 이력으로만 보관합니다. 새 키 준비·게시에는 자격증명의 조치 계획을 사용하세요.",
            "Legacy rotation jobs are retained as history only. Use the credential's action plans to prepare and publish a replacement key.")}</p>
          {rotationStage(item.job) === "check" ? <p className="meta tone-warn">{L("관리자가 현재 IAM 키와 Secret 상태를 대조해야 합니다. 확인 전에는 새 교체 계획을 실행하지 마세요.",
            "An administrator must reconcile the current IAM keys and Secret state before executing a new rotation plan.")}</p> : null}
        </CardBody>
      </Card> : null}
      {item.action ? <Card level={3} title={L("관리 조치", "Management action")}>
        <CardBody>
          <Facts>
            <Fact label={L("조치", "Action")}>{say(MANAGEMENT_WORDS, item.action.action_type, L)}</Fact>
            <Fact label={L("요청", "Requested")}>{actorLabel(item.action.requested_by ?? "", L)}<div className="subtle small">{fmtDT(item.action.created_at, locale)}</div></Fact>
            <Fact label={L("확인", "Confirmed")}>{item.action.confirmed_by ? actorLabel(item.action.confirmed_by, L) : <span className="subtle">{L("대기", "Waiting")}</span>}</Fact>
            {item.action.note ? <Fact label={L("메모", "Note")}>{item.action.note}</Fact> : null}
          </Facts>
          {item.action.status === "PENDING" ? <p className="meta">{ownAction && single
            ? L("단독 운영 설치입니다. 요청한 사람이 요청 내용을 다시 확인해 확정합니다.", "A single-operator installation: the requester re-checks the request to confirm it.")
            : L("요청한 사람과 다른 담당자가 확인합니다.", "An operator other than the requester confirms.")}</p> : null}
          {item.action.status === "PENDING" && ownAction && single ? <label className="check-line"><input type="checkbox" checked={selfChecked}
            onChange={event => setSelfChecked(event.target.checked)} />{L("요청 내용을 다시 확인했습니다", "I re-checked this request")}</label> : null}
          <div className="md-actions">{item.action.status === "PENDING" ? <button type="button" className="primary-btn" disabled={busy || !remediator || (ownAction && !(single && selfChecked))}
            onClick={() => void act(`management-actions/${item.action!.id}/confirm`, ownAction ? { self_approval_confirmed: true } : undefined,
              L("관리 조치를 확인했습니다", "Management action confirmed"))}><Ic name="checkCircle" size={15} />{L("확인", "Confirm")}</button> : null}</div>
        </CardBody>
      </Card> : null}
      {item.ticket ? <TicketApproval key={`${item.ticket.id}:${item.ticket.version}`} ticket={item.ticket} actor={actor} busy={busy} onApprove={() => void act(`tickets/${item.ticket!.id}/approve`,
        { expected_version: item.ticket!.version, content_digest: item.ticket!.review_digest, confirm: true }, L("티켓 검토를 승인했습니다", "Ticket review approved"))} /> : null}
      {record ? <section className="card"><div className="card-body md-actions">
        <button type="button" className="ghost-btn" onClick={() => go(record.exposed ? "exposed" : "inventory", { id: record.id, ...(item.job ? { dtab: "remed" } : {}) })}><Ic name="key" size={15} />{item.job ? L("조치 계획 보기", "View action plans") : L("Credential 보기", "View the credential")}</button>
      </div></section> : null}
    </div>
  </Drawer>;
}

function TicketApproval({ ticket, actor, busy, onApprove }: { ticket: Ticket; actor: Actor; busy: boolean; onApprove: () => void }) {
  const L = useL();
  const locale = useLocale();
  const [checked, setChecked] = useState(false);
  const pending = ticket.steps.filter(step => step.status === "TODO").length;
  // The approver is an Admin other than the creator and the last editor, over a complete record.
  const why = actor.role !== "Admin" ? L("관리자가 승인합니다.", "An Admin approves.")
    : [ticket.created_by, ticket.updated_by].includes(actor.ref ?? actor.id) ? L("작성자·마지막 수정자와 다른 관리자가 승인합니다.", "An Admin other than the author and the last editor approves.")
      : pending ? L(`검토 전 단계가 ${pending}개 남았습니다.`, `${pending} steps are left to review.`)
        : !ticket.owner_id || !ticket.responsible_team ? L("담당자와 담당 팀을 먼저 정합니다.", "Set the owner and the team first.") : "";
  return <Card level={3} title={say(TICKET_WORDS, ticket.template_id, L)} meta={L(`v${ticket.version}`, `v${ticket.version}`)}>
    <CardBody>
      <Facts>
        <Fact label={L("상태", "Status")}>{say(TICKET_WORDS, ticket.status, L)}</Fact>
        <Fact label={L("담당 팀", "Team")}>{ticket.responsible_team || <span className="subtle">{L("미지정", "Unassigned")}</span>}</Fact>
        <Fact label={L("검토 기한", "Review due")}>{fmtDT(ticket.review_due_at, locale)}</Fact>
        <Fact label={L("승인", "Approval")}>{ticket.internal_approval ? <>{actorLabel(ticket.internal_approval.approved_by, L)}<div className="subtle small">{fmtDT(ticket.internal_approval.approved_at, locale)}</div></>
          : <span className="subtle">{L("대기", "Waiting")}</span>}</Fact>
      </Facts>
      <ol className="ticket-steps">{ticket.steps.map(step => <li key={step.code}><span>{say(STEP_WORDS, step.code, L)}</span>
        <StateChip tone={step.status === "TODO" ? "warn" : "ok"}>{say(STEP_WORDS, step.status, L)}</StateChip></li>)}</ol>
      {ticketNeedsApproval(ticket) ? <>
        {why ? <p className="meta">{why}</p> : <label className="check-line"><input type="checkbox" checked={checked} onChange={event => setChecked(event.target.checked)} />
          {L("이 담당자·체크리스트·기한·근거를 검토했습니다.", "I reviewed this owner, checklist, dates and evidence.")}</label>}
        <div className="md-actions"><button type="button" className="primary-btn" disabled={busy || Boolean(why) || !checked} onClick={onApprove}><Ic name="checkCircle" size={15} />{L("검토 승인", "Approve the review")}</button></div>
      </> : null}
    </CardBody>
  </Card>;
}
