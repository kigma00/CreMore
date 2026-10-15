"use client";

/* Governance on a credential's remediation tab: internal tickets for its finding, whatever service issued it,
 * and management actions a second operator confirms. These are records of the review: nothing here changes
 * the credential at its provider. The server checks roles, versions, independence and text again. */

import { useEffect, useMemo, useState } from "react";

import { useLocale } from "@/components/locale";
import { isConflict, reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { actorLabel } from "@/console/labels";
import { Modal, useToast } from "@/console/layer";
import { PageNavigation, usePageHistory } from "@/console/pagination";
import type { Person } from "@/console/people";
import type { CredentialRecord } from "@/console/records";
import type { ViewProps } from "@/console/shell";
import { fmtDT, type Say, useL } from "@/console/text";
import { Card, CardBody, Fact, Facts, Field, SelectField, StateChip } from "@/console/ui";
import {
  localInput, MANAGEMENT_PATH, MANAGEMENT_WORDS, type ManagementAction, say, STEP_WORDS, type Ticket, TICKET_WORDS,
  ticketNeedsApproval, type TicketPage, TICKETS_PATH,
} from "@/console/views/approvals/model";

type Playbooks = { data: { templates: { id: string; steps: string[] }[] } };
export type TicketDraft = {
  template_id: string; priority: string; service_impact: string; responsible_team: string; owner_id: string; review_due_at: string;
  custom_steps: string[]; independent: boolean;
};

const PRIORITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
const IMPACTS = ["UNKNOWN", "NONE", "LIMITED", "SIGNIFICANT"] as const;
const STEP_STATES = ["TODO", "REVIEWED", "NOT_APPLICABLE"] as const;
const PRIORITY_WORDS: Record<string, [string, string]> = { CRITICAL: ["긴급", "Critical"], HIGH: ["높음", "High"], MEDIUM: ["보통", "Medium"], LOW: ["낮음", "Low"] };
const IMPACT_WORDS: Record<string, [string, string]> = {
  UNKNOWN: ["아직 모름", "Not known yet"], NONE: ["없음", "None"], LIMITED: ["제한적", "Limited"], SIGNIFICANT: ["큼", "Significant"],
};
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A new ticket's fields, due in a week, owned by whoever opens it when the API names them. */
export function blankTicket(ref: string | undefined, now = Date.now()): TicketDraft {
  return { template_id: "PUBLIC_EXPOSURE", priority: "HIGH", service_impact: "UNKNOWN", responsible_team: "", owner_id: ref && UUID.test(ref) ? ref : "",
    review_due_at: localInput(new Date(now + 7 * 86_400_000).toISOString()), custom_steps: [], independent: true };
}

/** The create request, or the first thing that keeps it from being sent. */
export function ticketBody(draft: TicketDraft, findingId: string, L: Say): { body?: Record<string, unknown>; problem?: string } {
  const due = Date.parse(draft.review_due_at);
  if (!Number.isFinite(due)) return { problem: L("검토 기한을 정하세요.", "Choose a review date.") };
  if (draft.owner_id && !UUID.test(draft.owner_id)) return { problem: L("담당자를 목록에서 고르세요.", "Pick the owner from the list.") };
  if (draft.template_id === "CUSTOM" && !draft.custom_steps.length) return { problem: L("검토 단계를 하나 이상 고르세요.", "Pick at least one review step.") };
  const team = draft.responsible_team.trim();
  return { body: {
    finding_id: findingId, template_id: draft.template_id, priority: draft.priority, service_impact: draft.service_impact,
    review_due_at: new Date(due).toISOString(), ...(team ? { responsible_team: team } : {}), ...(draft.owner_id ? { owner_id: draft.owner_id } : {}),
    ...(draft.template_id === "CUSTOM" ? { custom_steps: draft.custom_steps,
      customization: { approval_rule: draft.independent ? "INDEPENDENT_ADMIN" : "NONE", conditions: [] } } : {}),
  } };
}

/** An update carries every reviewed field again: the API reads a field left out as cleared (``owner_id: ""``
 * clears the owner). A security review recorded elsewhere goes back as it is. */
export function ticketUpdate(ticket: Ticket, change: { status?: string; steps?: Ticket["steps"]; responsible_team?: string; owner_id?: string; review_due_at?: string }) {
  const owner = change.owner_id !== undefined ? change.owner_id : ticket.owner_id;
  return {
    expected_version: ticket.version, status: change.status ?? ticket.status, priority: ticket.priority, service_impact: ticket.service_impact,
    responsible_team: change.responsible_team ?? ticket.responsible_team, review_due_at: change.review_due_at ?? ticket.review_due_at,
    ...(owner ? { owner_id: owner } : {}),
    ...(ticket.security_review ? { security_review: ticket.security_review } : {}),
    steps: (change.steps ?? ticket.steps).map(step => ({ code: step.code, status: step.status })),
  };
}

/** Who a ticket names, as this reader knows them: themselves, a person from the directory, or a reference. */
function whoIs(ref: string | undefined, me: string | undefined, people: Person[] | undefined, L: Say) {
  if (!ref) return "";
  if (ref === me) return L("나", "Me");
  return people?.find(person => person.id === ref)?.name ?? actorLabel(ref, L);
}

/** ``actions``: this finding's management actions, from its detail (undefined while it loads). */
export function Governance({ c, me, people, canEdit, go, actions, onChanged }: {
  c: CredentialRecord; me?: string; people?: Person[]; canEdit: boolean; go: ViewProps["go"]; actions?: ManagementAction[]; onChanged: () => void;
}) {
  if (!c.finding_id) return null;
  return <>
    <Tickets c={c} findingId={c.finding_id} me={me} people={people} canEdit={canEdit} go={go} />
    <Management c={c} findingId={c.finding_id} canEdit={canEdit} go={go} actions={actions} onChanged={onChanged} />
  </>;
}

function Tickets({ c, findingId, me, people, canEdit, go }: { c: CredentialRecord; findingId: string; me?: string; people?: Person[]; canEdit: boolean; go: ViewProps["go"] }) {
  const L = useL();
  const path = c.credential_id ? `${TICKETS_PATH}?credential_id=${encodeURIComponent(c.credential_id)}` : null;
  const page = usePageHistory<number>(path, 0);
  const tickets = useApi<TicketPage>(path ? `${path}&offset=${page.position}` : null);
  const [creating, setCreating] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const items = (tickets.data?.data.items ?? []).filter(ticket => ticket.finding_id === findingId);
  return <Card level={3} title={L("내부 티켓", "Internal tickets")} meta={L(`현재 페이지 ${items.length}건`, `${items.length} on this page`)}
    right={canEdit ? <button type="button" className="ghost-btn" onClick={() => setCreating(true)}><Ic name="plus" size={15} />{L("티켓 만들기", "Open a ticket")}</button> : undefined}>
    <CardBody>
      {tickets.error ? <p className="meta tone-bad">{reasonText(tickets.error, L)}</p> : !tickets.data ? <p className="meta">{L("불러오는 중", "Loading")}</p>
        : !items.length ? <p className="meta">{L("현재 페이지에 이 Credential의 티켓이 없습니다. 다른 페이지도 확인하세요.",
          "No ticket for this credential on this page. Check other pages as well.")}</p>
          : <ul className="gov-list">{items.map(ticket => <TicketRow key={ticket.id} ticket={ticket} me={me} people={people} canEdit={canEdit}
            open={openId === ticket.id} onToggle={() => setOpenId(current => current === ticket.id ? null : ticket.id)} onChanged={tickets.reload} go={go} />)}</ul>}
    </CardBody>
    <PageNavigation label={L("내부 티켓", "Internal tickets")} {...page} loading={tickets.loading}
      hasNext={tickets.data?.data.next_offset != null} next={() => { const next = tickets.data?.data.next_offset; if (next != null) { page.next(next); setOpenId(null); } }} />
    {creating ? <TicketModal findingId={findingId} me={me} people={people} onClose={() => setCreating(false)}
      onDone={ticket => { setCreating(false); setOpenId(ticket?.id ?? null); page.reset(); tickets.reload(); }} /> : null}
  </Card>;
}

function TicketRow({ ticket, me, people, canEdit, open, onToggle, onChanged, go }: {
  ticket: Ticket; me?: string; people?: Person[]; canEdit: boolean; open: boolean; onToggle: () => void; onChanged: () => void; go: ViewProps["go"];
}) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const [base, setBase] = useState(ticket);
  const [steps, setSteps] = useState(ticket.steps);
  const [team, setTeam] = useState(ticket.responsible_team);
  const [owner, setOwner] = useState(ticket.owner_id ?? "");
  const [busy, setBusy] = useState(false);
  const reviewed = ticket.steps.filter(step => step.status !== "TODO").length;
  const overdue = ticket.status !== "RESOLVED" && Date.parse(ticket.review_due_at) < Date.now();
  const approval = ticketNeedsApproval(ticket);
  const changed = team !== base.responsible_team || owner !== (base.owner_id ?? "") || steps.some((step, index) => step.status !== base.steps[index]?.status);
  const stale = base.version !== ticket.version;
  const adopt = () => { setBase(ticket); setSteps(ticket.steps); setTeam(ticket.responsible_team); setOwner(ticket.owner_id ?? ""); };
  useEffect(() => {
    // Background updates may refresh a clean row, but never replace unsaved edits or their CAS version.
    if (!changed && stale) { setBase(ticket); setSteps(ticket.steps); setTeam(ticket.responsible_team); setOwner(ticket.owner_id ?? ""); }
  }, [changed, stale, ticket]);
  const blocked = steps.some(step => step.status === "TODO") ? L("검토 전 단계가 남았습니다.", "Steps are left to review.")
    : !team.trim() || !owner ? L("담당 팀과 담당자가 있어야 합니다.", "A team and an owner are needed.")
      : approval ? L("다른 관리자가 이 내용을 먼저 승인해야 합니다.", "Another Admin approves this content first.") : "";
  const save = async (status?: string) => {
    setBusy(true);
    try {
      await send(`${TICKETS_PATH}/${ticket.id}`, "PUT", ticketUpdate(base, { status, steps, responsible_team: team.trim(), owner_id: owner }));
      setBase({ ...base, steps, responsible_team: team, owner_id: owner });
      toast(status === "RESOLVED" ? L("티켓 검토를 마쳤습니다.", "The ticket review is complete.") : L("티켓을 저장했습니다.", "Ticket saved."));
      saved(); onChanged();
    } catch (error) { toast(reasonText(error, L), "bad"); if (isConflict(error)) onChanged(); }
    finally { setBusy(false); }
  };
  return <li className="gov-item">
    <button type="button" className="gov-head" aria-expanded={open} onClick={onToggle}>
      <span className="gov-title"><b>{say(TICKET_WORDS, ticket.template_id, L)}</b>
        <span className="subtle small">{L(`우선순위 ${say(PRIORITY_WORDS, ticket.priority, L)}`, `${say(PRIORITY_WORDS, ticket.priority, L)} priority`)} · {L(`검토 ${reviewed}/${ticket.steps.length}`, `${reviewed}/${ticket.steps.length} reviewed`)}</span></span>
      <span className={overdue ? "tone-bad small" : "subtle small"} data-tip={fmtDT(ticket.review_due_at, locale)}>{overdue ? L("기한 지남", "Overdue") : fmtDT(ticket.review_due_at, locale)}</span>
      <StateChip tone={ticket.status === "RESOLVED" ? "ok" : approval || overdue ? "warn" : "running"}>{approval ? L("승인 대기", "Awaiting approval") : say(TICKET_WORDS, ticket.status, L)}</StateChip>
      <Ic name={open ? "up" : "down"} size={15} />
    </button>
    {open ? <div className="gov-body">
      {stale && changed ? <p className="meta tone-warn">{L("다른 사람이 이 티켓을 변경했습니다. 입력은 유지했습니다.", "Someone changed this ticket. Your input is kept.")} <button type="button" className="link-btn" onClick={adopt}>{L("최신 내용으로 다시 불러오기", "Reload the latest version")}</button></p> : null}
      <Facts>
        <Fact label={L("담당 팀", "Team")}>{ticket.responsible_team || <span className="subtle">{L("미지정", "Unassigned")}</span>}</Fact>
        <Fact label={L("담당자", "Owner")}>{whoIs(ticket.owner_id, me, people, L) || <span className="subtle">{L("미지정", "Unassigned")}</span>}</Fact>
        <Fact label={L("서비스 영향", "Service impact")}>{say(IMPACT_WORDS, ticket.service_impact, L)}</Fact>
        <Fact label={L("작성", "Opened")}>{whoIs(ticket.created_by, me, people, L)}<div className="subtle small">{fmtDT(ticket.created_at, locale)}</div></Fact>
        {ticket.internal_approval ? <Fact label={L("승인", "Approved")}>{whoIs(ticket.internal_approval.approved_by, me, people, L)}
          <div className="subtle small">{fmtDT(ticket.internal_approval.approved_at, locale)}</div></Fact> : null}
      </Facts>
      <ol className="ticket-steps">{steps.map((step, index) => <li key={step.code}><span>{say(STEP_WORDS, step.code, L)}</span>
        {canEdit && ticket.status !== "RESOLVED" ? <select aria-label={L(`${say(STEP_WORDS, step.code, L)} 상태`, `${say(STEP_WORDS, step.code, L)} state`)} value={step.status}
          onChange={event => setSteps(current => current.map((item, at) => at === index ? { ...item, status: event.target.value } : item))}>
          {STEP_STATES.map(state => <option key={state} value={state}>{say(STEP_WORDS, state, L)}</option>)}</select>
          : <StateChip tone={step.status === "TODO" ? "warn" : "ok"}>{say(STEP_WORDS, step.status, L)}</StateChip>}</li>)}</ol>
      {canEdit && ticket.status !== "RESOLVED" ? <>
        <div className="row2">
          <Field label={L("담당 팀", "Team")} htmlFor={`gov-team-${ticket.id}`}>
            <input id={`gov-team-${ticket.id}`} value={team} maxLength={128} onChange={event => setTeam(event.target.value)} placeholder={L("부서 이름", "Team name")} /></Field>
          <OwnerSelect value={owner} onChange={setOwner} me={me} people={people} />
        </div>
        {approval ? <p className="meta">{L("이 플레이북은 작성자·마지막 수정자가 아닌 관리자의 승인이 필요합니다. 저장하면 새 내용에 다시 승인받습니다.",
          "This playbook needs an Admin other than the author and last editor to approve. Saving asks for approval of the new content again.")}
          <button type="button" className="link-btn" onClick={() => go("approvals", { kind: "ticket", id: `ticket:${ticket.id}` })}>{L("조치 승인에서 보기", "View in approvals")}</button></p> : null}
        <div className="md-actions">
          <button type="button" className="ghost-btn" disabled={busy || !changed} onClick={() => void save()}>{L("저장", "Save")}</button>
          <button type="button" className="primary-btn" disabled={busy || Boolean(blocked) || changed} data-tip={changed ? L("먼저 저장하세요.", "Save first.") : blocked || undefined}
            onClick={() => void save("RESOLVED")}><Ic name="checkCircle" size={15} />{L("검토 완료", "Complete the review")}</button>
        </div>
      </> : null}
    </div> : null}
  </li>;
}

function OwnerSelect({ value, onChange, me, people }: { value: string; onChange: (value: string) => void; me?: string; people?: Person[] }) {
  const L = useL();
  const listed = (people ?? []).filter(person => person.state !== "DEPARTED" && UUID.test(person.id));
  const options = [{ id: "", label: L("미지정", "Unassigned") }, ...(me && UUID.test(me) ? [{ id: me, label: L("나", "Me") }] : []),
    ...listed.map(person => ({ id: person.id, label: [person.name, person.department].filter(Boolean).join(" · ") }))];
  // Someone named before and gone from the directory stays chosen, by reference.
  if (value && !options.some(option => option.id === value)) options.push({ id: value, label: actorLabel(value, L) });
  return <SelectField label={L("담당자", "Owner")} value={value} onChange={onChange} options={options} />;
}

function TicketModal({ findingId, me, people, onClose, onDone }: { findingId: string; me?: string; people?: Person[]; onClose: () => void; onDone: (ticket?: Ticket) => void }) {
  const L = useL();
  const toast = useToast();
  const saved = useSaved();
  const playbooks = useApi<Playbooks>("governance/playbooks");
  const [draft, setDraft] = useState(() => blankTicket(me));
  const [busy, setBusy] = useState(false);
  const templates = (playbooks.data?.data.templates ?? []).filter(template => template.id !== "DEPARTED_OWNER");
  const steps = useMemo(() => Array.from(new Set(templates.flatMap(template => template.steps))), [templates]);
  const chosen = templates.find(template => template.id === draft.template_id);
  const built = ticketBody(draft, findingId, L);
  const set = (change: Partial<TicketDraft>) => setDraft(current => ({ ...current, ...change }));
  const create = async () => {
    if (!built.body) return;
    setBusy(true);
    try {
      const made = await send<{ data: Ticket }>(TICKETS_PATH, "POST", built.body);
      toast(L("티켓을 만들었습니다.", "Ticket opened."));
      saved(); onDone(made.data);
    } catch (error) { toast(reasonText(error, L), "bad"); }
    finally { setBusy(false); }
  };
  return <Modal onClose={onClose} labelledBy="ticket-title" size="narrow">
    <h2 id="ticket-title">{L("티켓 만들기", "Open a ticket")}</h2>
    <SelectField label={L("플레이북", "Playbook")} value={draft.template_id} onChange={template_id => set({ template_id })}
      options={templates.length ? templates.map(template => ({ id: template.id, label: say(TICKET_WORDS, template.id, L) })) : [{ id: draft.template_id, label: say(TICKET_WORDS, draft.template_id, L) }]} />
    {draft.template_id === "CUSTOM" ? <fieldset className="field">
      <legend className="lbl">{L("검토 단계", "Review steps")}</legend>
      <div className="check-list">{steps.map(code => <label key={code} className="check-line"><input type="checkbox" checked={draft.custom_steps.includes(code)}
        onChange={event => set({ custom_steps: event.target.checked ? [...draft.custom_steps, code] : draft.custom_steps.filter(item => item !== code) })} />{say(STEP_WORDS, code, L)}</label>)}</div>
      <label className="check-line"><input type="checkbox" checked={draft.independent} onChange={event => set({ independent: event.target.checked })} />
        {L("작성자가 아닌 관리자의 승인을 받아야 완료", "Complete only after an Admin other than the author approves")}</label>
    </fieldset> : chosen ? <p className="meta">{chosen.steps.map(code => say(STEP_WORDS, code, L)).join(" → ")}</p> : null}
    <div className="row2">
      <SelectField label={L("우선순위", "Priority")} value={draft.priority} onChange={priority => set({ priority })}
        options={PRIORITIES.map(id => ({ id, label: say(PRIORITY_WORDS, id, L) }))} />
      <SelectField label={L("서비스 영향", "Service impact")} value={draft.service_impact} onChange={service_impact => set({ service_impact })}
        options={IMPACTS.map(id => ({ id, label: say(IMPACT_WORDS, id, L) }))} />
    </div>
    <div className="row2">
      <Field label={L("담당 팀", "Team")} htmlFor="ticket-team"><input id="ticket-team" value={draft.responsible_team} maxLength={128} data-autofocus
        onChange={event => set({ responsible_team: event.target.value })} placeholder={L("부서 이름", "Team name")} /></Field>
      <OwnerSelect value={draft.owner_id} onChange={owner_id => set({ owner_id })} me={me} people={people} />
    </div>
    <Field label={L("검토 기한", "Review due")} htmlFor="ticket-due"><input id="ticket-due" type="datetime-local" value={draft.review_due_at}
      onChange={event => set({ review_due_at: event.target.value })} /></Field>
    {built.problem ? <p className="meta tone-warn">{built.problem}</p> : null}
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose}>{L("취소", "Cancel")}</button>
      <button type="button" className="primary-btn" disabled={busy || !built.body || !playbooks.data} onClick={() => void create()}>{busy ? L("만드는 중", "Opening") : L("만들기", "Open")}</button>
    </div>
  </Modal>;
}

/** What a second operator confirms for this finding: the owner acknowledged it, or (an AWS key) it is rotated. */
function Management({ c, findingId, canEdit, go, actions, onChanged }: {
  c: CredentialRecord; findingId: string; canEdit: boolean; go: ViewProps["go"]; actions?: ManagementAction[]; onChanged: () => void;
}) {
  const L = useL();
  const locale = useLocale();
  const [asking, setAsking] = useState(false);
  const mine = (actions ?? []).filter(action => action.finding_id === findingId);
  // What the API offers for this credential (governance_presenters.available_actions).
  const offered = ["ACKNOWLEDGE_OWNER", ...(c.credential_type === "AWS_ACCESS_KEY" ? ["ROTATE"] : [])];
  return <Card level={3} title={L("관리 조치", "Management actions")} meta={mine.length ? L(`${mine.length}건`, `${mine.length}`) : undefined}
    right={canEdit ? <button type="button" className="ghost-btn" onClick={() => setAsking(true)}><Ic name="send" size={15} />{L("관리 조치 요청", "Request an action")}</button> : undefined}>
    <CardBody>
      {!actions ? <p className="meta">{L("불러오는 중", "Loading")}</p>
        : !mine.length ? <p className="meta">{L("요청한 관리 조치가 없습니다. 요청은 조치 승인에서 확인합니다.",
          "No management action requested. Each request is confirmed in approvals.")}</p>
          : <ul className="gov-list">{mine.map(action => <li key={action.id} className="gov-item"><div className="gov-head static">
            <span className="gov-title"><b>{say(MANAGEMENT_WORDS, action.action_type, L)}</b>
              <span className="subtle small">{actorLabel(action.requested_by ?? "", L)} · {fmtDT(action.created_at, locale)}{action.note ? ` · ${action.note}` : ""}</span></span>
            <StateChip tone={action.status === "PENDING" ? "warn" : action.status === "REJECTED" ? undefined : "ok"}>{say(MANAGEMENT_WORDS, action.status, L)}</StateChip>
            {action.status === "PENDING" ? <button type="button" className="link-btn" onClick={() => go("approvals", { kind: "management", id: `management:${action.id}` })}>{L("조치 승인에서 보기", "View in approvals")}</button> : null}
          </div></li>)}</ul>}
    </CardBody>
    {asking ? <ManagementModal findingId={findingId} offered={offered} onClose={() => setAsking(false)} onDone={() => { setAsking(false); onChanged(); }} /> : null}
  </Card>;
}

function ManagementModal({ findingId, offered, onClose, onDone }: { findingId: string; offered: string[]; onClose: () => void; onDone: () => void }) {
  const L = useL();
  const toast = useToast();
  const saved = useSaved();
  const [type, setType] = useState(offered[0]!);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const request = async () => {
    setBusy(true);
    try {
      await send(MANAGEMENT_PATH, "POST", { finding_id: findingId, action_type: type, ...(note.trim() ? { note: note.trim() } : {}) });
      toast(L("관리 조치를 요청했습니다. 조치 승인에서 확인합니다.", "Requested. It is confirmed in approvals."));
      saved(); onDone();
    } catch (error) { toast(reasonText(error, L), "bad"); }
    finally { setBusy(false); }
  };
  return <Modal onClose={onClose} labelledBy="management-title" size="narrow">
    <h2 id="management-title">{L("관리 조치 요청", "Request a management action")}</h2>
    <SelectField label={L("조치", "Action")} value={type} onChange={setType} options={offered.map(id => ({ id, label: say(MANAGEMENT_WORDS, id, L) }))} />
    <Field label={L("메모", "Note")} htmlFor="management-note">
      <textarea id="management-note" rows={3} maxLength={500} value={note} onChange={event => setNote(event.target.value)} data-autofocus /></Field>
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose}>{L("취소", "Cancel")}</button>
      <button type="button" className="primary-btn" disabled={busy} onClick={() => void request()}>{busy ? L("요청 중", "Requesting") : L("요청", "Request")}</button>
    </div>
  </Modal>;
}
