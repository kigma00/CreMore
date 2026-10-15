"use client";

/* Owner & team assignment: who answers for each exposed credential, which team investigates it and where that
 * investigation stands (its ownership review). An owner comes from an assignment, CODEOWNERS or an owner an admin
 * registered; a team from the review, else the owner's team, else the owner's IdP department. Several credentials
 * take one owner, or one team, state and due date, at once; the server audits every change. */

import { useMemo, useRef, useState } from "react";

import { useLocale } from "@/components/locale";
import { api, DashboardAPIError } from "@/lib/dashboard-api";
import { hasRole } from "@/lib/dashboard-session";
import { isConflict, reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { typeLabel } from "@/console/labels";
import { Modal, useToast } from "@/console/layer";
import { Logo } from "@/console/logos";
import { type DirectoryPerson, type Person, type ResponderRouting, selectablePerson } from "@/console/people";
import { PersonPicker } from "@/console/people-picker";
import { DirectoryPanel } from "@/console/people-directory";
import { type CredentialRecord, isOpen, RECORDS_PATH, type RecordsResponse } from "@/console/records";
import type { ViewProps } from "@/console/shell";
import { fmtDT, rel, useL } from "@/console/text";
import { Card, Check, EmptyRow, ErrorLine, Field, Loading, PageHead, RiskTag, SearchBox, Seg, SelectField, StateChip, Tabs, TextField, Tile, Tiles } from "@/console/ui";
import { CredentialDrawer, type DTab } from "@/console/views/credentials/drawer";
import { ownerBasis } from "@/console/views/credentials/risk";
import { assignRows, batches, type Filter, FILTERS, NO_TEAM, type Row, shownRows, type TeamFilter, teamsOf } from "@/console/views/assign/model";
import { localInput } from "@/console/views/approvals/model";
import { REVIEW_REASONS, REVIEW_STATUS, reviewStatusText } from "@/console/views/credentials/tabs";
import { responseLabel, responseTone } from "@/console/views/credentials/response";

const TONE: Record<string, "ok" | "warn" | "running" | undefined> = { IN_PROGRESS: "running", WAITING_OWNER: "warn", CLOSED: "ok" };

export function Assign({ session, route, setParams, go }: ViewProps) {
  const L = useL();
  const locale = useLocale();
  const analyst = hasRole(session.role, "Analyst");
  const records = useApi<RecordsResponse>(RECORDS_PATH, { every: 60_000 });
  const engine = useApi<{ detectors: { credential_type: string; name: string }[] }>("detection-engine");
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [modal, setModal] = useState<"review" | "owner" | null>(null);
  const allRef = useRef<HTMLButtonElement>(null);

  const p = route.params;
  const tab = p.get("tab") === "teams" ? "teams" : "credentials";
  const filter: Filter = FILTERS.find(value => value === p.get("f")) ?? "open";
  const team: TeamFilter = p.get("noteam") === "1" ? NO_TEAM : p.get("team");
  const q = p.get("q") ?? "";
  const catalog = useMemo(() => new Map((engine.data?.detectors ?? []).map(d => [d.credential_type, d.name])), [engine.data]);
  const typeName = (c: CredentialRecord) => typeLabel(c.credential_type, L, catalog);
  const name = (c: CredentialRecord) => c.name || typeName(c);

  const rows = useMemo(() => assignRows(records.data?.items ?? [], undefined), [records.data]);
  const open = rows.filter(row => isOpen(row.c));
  const teams = useMemo(() => teamsOf(rows, undefined), [rows]);
  const shown = shownRows(rows, filter, team, q, name);
  // Only what is on screen is acted on: a selection a filter now hides is not sent.
  const chosen = shown.filter(row => picked.has(row.c.id));
  const toggle = (ids: string[], on: boolean) => setPicked(current => {
    const next = new Set(current);
    for (const id of ids) if (on) next.add(id); else next.delete(id);
    return next;
  });
  const allShown = shown.length > 0 && shown.every(row => picked.has(row.c.id));
  const someShown = shown.some(row => picked.has(row.c.id));
  // The control that opened a closed modal or cleared the selection is gone: focus goes back to the list's own.
  const refocus = () => requestAnimationFrame(() => allRef.current?.focus());
  const settle = (ids: string[], all: boolean) => { toggle(ids, false); if (all) { setModal(null); refocus(); } };
  const selected = records.data?.items.find(c => c.id === p.get("id"));

  const head = <PageHead title={L("담당자 및 부서 배정", "Owner & team assignment")}
    meta={L("노출된 Credential마다 대응 담당자와 조사 부서, 조사 상태를 정합니다", "Set the response owner, the investigating team and the review state of every exposed credential")} />;
  if (records.error) return <>{head}<ErrorLine onRetry={records.reload}>{reasonText(records.error, L)}</ErrorLine></>;
  if (!records.data) return <>{head}<Loading /></>;

  const narrow = (next: Filter | null) => setParams({ f: next, tab: null, team: null, noteam: null, q: null });
  return <>
    {head}
    <Tiles>
      <Tile icon="userQ" tone={open.some(row => !row.owner) ? "amber" : "green"} label={L("담당자 미확인", "Owner unknown")}
        value={open.filter(row => !row.owner).length} of={open.length} onClick={() => narrow("unowned")}
        tip={L("지정·CODEOWNERS·관리자가 등록한 담당자 어디에서도 대응 담당자를 찾지 못한 조치 전 Credential입니다.", "Credentials awaiting action with no response owner from an assignment, CODEOWNERS or an owner an admin registered.")} />
      <Tile icon="users" tone={open.some(row => !row.team) ? "amber" : "green"} label={L("부서 미배정", "No team")}
        value={open.filter(row => !row.team).length} onClick={() => narrow("noteam")}
        tip={L("조사 부서도, 담당자의 IdP 부서도 없는 Credential입니다.", "Credentials with no investigating team and no owner department from the IdP.")} />
      <Tile icon="clock" tone="violet" label={L("담당자 응답 대기", "Awaiting response")} value={open.filter(row => row.status === "WAITING_OWNER").length}
        onClick={() => narrow("waiting")} tip={L("담당자에게 확인을 요청하고 기한까지 답을 기다리는 조사입니다.", "Reviews waiting for the owner's answer by a due date.")} />
      <Tile icon="alert" tone={open.some(row => row.overdue) ? "red" : "green"} label={L("기한 지남", "Overdue")} value={open.filter(row => row.overdue).length}
        onClick={() => narrow("overdue")} tip={L("조사 기한이 지났는데 끝나지 않은 조사입니다.", "Reviews past their due date and not completed.")} />
    </Tiles>

    {analyst ? <DirectoryPanel admin={session.role === "Admin"} /> : null}

    <Tabs value={tab} onChange={value => setParams({ tab: value === "credentials" ? null : value })} label={L("배정 보기", "Assignment view")}
      items={[{ id: "credentials" as const, label: L("Credential", "Credentials"), count: open.length }, { id: "teams" as const, label: L("부서", "Teams"), count: teams.filter(t => t.team).length }]} />

    {tab === "credentials" ? <Card className="list-card">
      <div className="list-tools">
        <Seg value={filter} onChange={value => setParams({ f: value === "open" ? null : value })} label={L("보기", "Show")}
          options={[{ id: "open" as const, label: L("조치 전", "Awaiting action") }, { id: "unowned" as const, label: L("담당자 미확인", "Owner unknown") },
            { id: "noteam" as const, label: L("부서 미배정", "No team") }, { id: "waiting" as const, label: L("응답 대기", "Awaiting response") },
            { id: "overdue" as const, label: L("기한 지남", "Overdue") }, { id: "all" as const, label: L("전체", "All") }]} />
        <SearchBox value={q} onChange={value => setParams({ q: value || null }, { replace: true })} label={L("검색", "Search")}
          placeholder={L("Credential, 위치, 담당자, 부서", "Credential, location, owner, team")} />
      </div>
      {team !== null ? <div className="applied"><span className="applied-chip"><span className="wrap-t">{L("부서: ", "Team: ")}{team === NO_TEAM ? L("미배정", "No team") : team}</span>
        <button type="button" onClick={() => setParams({ team: null, noteam: null })} aria-label={L("부서 필터 해제", "Clear team filter")}><Ic name="close" size={13} /></button></span></div> : null}
      <div className="table-wrap"><table className="tbl">
        <thead><tr>
          {/* aria-disabled, not disabled: a save can empty the list while this button holds the focus. */}
          {analyst ? <th className="sel-cell"><button type="button" className="sel-btn" role="checkbox" ref={allRef} aria-checked={allShown ? true : someShown ? "mixed" : false}
            aria-disabled={!shown.length || undefined} aria-label={L("보이는 항목 모두 선택", "Select every row shown")}
            onClick={() => { if (shown.length) toggle(shown.map(row => row.c.id), !allShown); }}><Check on={allShown} mixed={someShown} /></button></th> : null}
          <th>Credential</th><th className="col-md">{L("노출 위치", "Exposed in")}</th><th>{L("대응 담당자", "Owner")}</th><th className="col-sm">{L("부서", "Team")}</th>
          <th className="col-sm">{L("조사 상태", "Review")}</th><th className="col-sm">{L("기한", "Due")}</th><th className="col-sm">{L("위험", "Risk")}</th>
        </tr></thead>
        <tbody>
          {shown.length ? shown.map(row => {
            const place = row.c.exposures.find(e => e.current) ?? row.c.exposures[0];
            const openRow = () => setParams({ id: row.c.id, dtab: "owner" });
            return <tr key={row.c.id} tabIndex={0} aria-selected={selected?.id === row.c.id} onClick={openRow}
              onKeyDown={event => { if (event.key === "Enter" && event.target === event.currentTarget) openRow(); }}>
              {analyst ? <td className="sel-cell" onClick={event => event.stopPropagation()}>
                <button type="button" className="sel-btn" role="checkbox" aria-checked={picked.has(row.c.id)} aria-label={L(`${name(row.c)} 선택`, `Select ${name(row.c)}`)}
                  onClick={() => toggle([row.c.id], !picked.has(row.c.id))}><Check on={picked.has(row.c.id)} /></button></td> : null}
              <td><div className="cred-cell"><Logo id={row.c.provider} size={28} /><div className="cred-text"><div className="cred-name">{name(row.c)}</div>
                <div className="cred-hint">{[typeName(row.c), row.c.hint].filter(Boolean).join(" · ")}</div></div></div></td>
              <td className="col-md">{place ? <span className="cell-wrap">{place.resource_name}{row.c.location_count > 1 ? <span className="subtle"> {L(`외 ${row.c.location_count - 1}곳`, `+${row.c.location_count - 1}`)}</span> : null}</span> : "—"}</td>
              <td>{row.owner ? <>{row.person?.name ?? row.owner}{row.person?.state === "DEPARTED" ? <span className="tag tone-bad" style={{ marginLeft: 6 }}>{L("퇴사", "Left")}</span> : null}
                <div className="subtle small col-sm">{row.c.owner?.name ? ownerBasis(row.c, L) : L("대응 요청 담당자", "Requested responder")}</div></> : <span className="tone-warn">{L("미확인", "Unknown")}</span>}
                {/* A phone has no team or review column: both read under the owner. */}
                <div className="subtle small only-sm">{row.team ?? L("부서 미배정", "No team")}</div>
                <div className="only-sm sm-chip"><StateChip tone={row.c.response ? responseTone(row.c.response.state) : TONE[row.status]}>{row.c.response ? responseLabel(row.c.response.state, L) : reviewStatusText(row.status, L)}</StateChip></div></td>
              <td className="col-sm">{row.team ?? <span className="subtle">{L("미배정", "No team")}</span>}</td>
              <td className="col-sm"><StateChip tone={row.c.response ? responseTone(row.c.response.state) : TONE[row.status]}>{row.c.response ? responseLabel(row.c.response.state, L) : reviewStatusText(row.status, L)}</StateChip></td>
              <td className="col-sm">{row.due ? <span className={row.overdue ? "tone-bad" : undefined} data-tip={fmtDT(row.due, locale)}>{rel(row.due, locale)}</span> : "—"}</td>
              <td className="col-sm"><RiskTag level={row.c.risk} /></td>
            </tr>;
          }) : <EmptyRow colSpan={analyst ? 8 : 7}>{rows.length ? L("조건에 맞는 Credential이 없습니다.", "No credential matches.") : L("노출된 Credential이 없습니다.", "No credential is exposed.")}</EmptyRow>}
        </tbody>
      </table></div>
      {/* Always there, so the first selection is announced too. */}
      {analyst ? <span className="sr" aria-live="polite">{chosen.length ? L(`${chosen.length}개 선택`, `${chosen.length} selected`) : ""}</span> : null}
      {analyst && chosen.length ? <div className="bulk-bar" role="region" aria-label={L("선택한 항목 작업", "Selected rows")}>
        <span className="bulk-count">{L(`${chosen.length}개 선택`, `${chosen.length} selected`)}</span>
        <button type="button" className="ghost-btn" onClick={() => setModal("owner")}><Ic name="userPlus" size={15} />{L("담당자 지정", "Assign owner")}</button>
        <button type="button" className="primary-btn" onClick={() => setModal("review")}><Ic name="users" size={15} />{L("부서·조사 상태 지정", "Set team and review")}</button>
        <button type="button" className="link-btn" onClick={() => { setPicked(new Set()); refocus(); }}>{L("선택 해제", "Clear selection")}</button>
      </div> : null}
      <div className="list-foot"><span>{L(`${shown.length}건`, `${shown.length}`)}</span></div>
    </Card> : <Card className="list-card">
      <div className="table-wrap"><table className="tbl">
        <thead><tr><th>{L("부서", "Team")}</th><th>{L("조치 전", "Awaiting action")}</th><th>{L("담당자 미확인", "Owner unknown")}</th>
          <th>{L("응답 대기", "Awaiting response")}</th><th>{L("기한 지남", "Overdue")}</th><th className="col-sm">{L("조치 끝남", "Closed")}</th></tr></thead>
        <tbody>
          {teams.length ? teams.map(entry => {
            const pick = () => setParams({ tab: null, team: entry.team || null, noteam: entry.team ? null : "1", q: null, f: entry.open ? null : "all" });
            return <tr key={entry.team ? `t:${entry.team}` : "none"} tabIndex={0} onClick={pick} onKeyDown={event => { if (event.key === "Enter") pick(); }}>
              <td>{entry.team ? <span className="cred-name">{entry.team}</span> : <span className="subtle">{L("부서 미배정", "No team")}</span>}</td>
              <td>{entry.open}</td>
              <td>{entry.unowned ? <span className="tone-warn">{entry.unowned}</span> : 0}</td>
              <td>{entry.waiting}</td>
              <td>{entry.overdue ? <span className="tone-bad">{entry.overdue}</span> : 0}</td>
              <td className="col-sm">{entry.done}</td>
            </tr>;
          }) : <EmptyRow colSpan={6}>{L("노출된 Credential이 없습니다.", "No credential is exposed.")}</EmptyRow>}
        </tbody>
      </table></div>
      <div className="list-foot"><span>{L("책임 팀은 명시적 배정 기준입니다. IdP 그룹 구성원 수를 뜻하지 않습니다.", "Responsible teams reflect explicit assignments, not IdP group membership counts.")}</span></div>
    </Card>}

    {modal === "review" ? <ReviewModal rows={chosen} teams={teams.map(entry => entry.team).filter(Boolean)}
      onClose={() => setModal(null)} onDone={settle} /> : null}
    {modal === "owner" ? <OwnerModal rows={chosen} admin={session.role === "Admin"} onClose={() => setModal(null)} onDone={settle} /> : null}
    {selected ? <CredentialDrawer key={selected.id} c={selected} session={session} typeName={typeName(selected)} name={name(selected)} tab={p.get("dtab")}
      setTab={(next: DTab) => setParams({ dtab: next === "overview" ? null : next })} onClose={() => setParams({ id: null, dtab: null })} go={go}
      records={records.data.items} /> : null}
  </>;
}

/** Chosen rows as the count reads: one credential, several credentials. */
function countText(count: number, L: (ko: string, en: string) => string) {
  return L(`${count}개 Credential`, count === 1 ? "1 credential" : `${count} credentials`);
}

/** One value when every row has it, else none. */
function shared<T>(values: T[]): T | undefined {
  const distinct = new Set(values);
  return distinct.size === 1 ? values[0] : undefined;
}

/** One team, review state and due date for every chosen credential, 100 findings a request. What was saved leaves
 * the selection; what was not stays chosen, with the reason. */
function ReviewModal({ rows, teams, people, onClose, onDone }: { rows: Row[]; teams: string[]; people?: Person[]; onClose: () => void; onDone: (ids: string[], all: boolean) => void }) {
  const L = useL();
  const toast = useToast();
  const saved = useSaved();
  // Rows that agree keep what they have; a field they differ on starts empty.
  const [openedRows] = useState(rows);
  const [status, setStatus] = useState<string>(() => shared(rows.map(row => row.c.review?.status ?? "OPEN")) ?? "IN_PROGRESS");
  const [team, setTeam] = useState(() => shared(rows.map(row => row.team ?? "")) ?? "");
  const [due, setDue] = useState(() => { const only = shared(rows.map(row => row.due ?? "")); return only ? localInput(only) : ""; });
  const [reason, setReason] = useState(() => shared(rows.map(row => row.c.review?.closed_reason ?? "")) ?? "");
  const [busy, setBusy] = useState(false);
  const suggestions = Array.from(new Set([...teams, ...(people ?? []).map(person => person.department).filter((value): value is string => Boolean(value))])).sort();
  const problem = status !== "OPEN" && !team.trim() ? L("조사 대기 외에는 담당 부서가 필요합니다.", "A team is required beyond Awaiting review.")
    : new TextEncoder().encode(team.trim()).length > 128 ? L("부서 이름이 너무 깁니다.", "The team name is too long.")
      : status === "WAITING_OWNER" && !due ? L("담당자 응답 대기에는 기한이 필요합니다.", "Awaiting response needs a due date.")
        : status === "CLOSED" && !reason ? L("완료 사유를 고르세요.", "Choose a completion reason.") : "";
  const save = async () => {
    setBusy(true);
    const done: string[] = [];
    try {
      for (const chunk of batches(openedRows)) {
        await send("ownership-reviews/bulk", "POST", {
          items: chunk.map(row => ({ finding_id: row.c.finding_id, revision: row.c.review?.revision ?? 0 })), status, assigned_team: team.trim(),
          due_at: due ? new Date(due).toISOString() : null, closed_reason: status === "CLOSED" ? reason : "" });
        done.push(...chunk.map(row => row.c.id));
      }
      toast(L(`${done.length}건의 부서와 조사 상태를 저장했습니다.`, `Saved the team and review of ${done.length}.`));
      saved(); onDone(done, true);
    } catch (error) {
      // A conflict asks for a reload: fetch now, so applying again uses the current versions.
      if (!done.length) { if (isConflict(error)) saved(); toast(reasonText(error, L), "bad"); return; }
      toast(L(`${done.length}건은 저장했습니다. 선택에 남은 ${rows.length - done.length}건은 저장하지 못했습니다: ${reasonText(error, L)}`,
        `Saved ${done.length}. The ${rows.length - done.length} still selected were not saved: ${reasonText(error, L)}`), "bad");
      saved(); onDone(done, false);
    } finally { setBusy(false); }
  };
  return <Modal onClose={onClose} labelledBy="bulk-review-title" size="narrow" dismissable={!busy}>
    <h2 id="bulk-review-title">{L("부서·조사 상태 지정", "Set team and review")} <small>{countText(rows.length, L)}</small></h2>
    {openedRows.some(old => rows.find(row => row.c.id === old.c.id)?.c.review?.revision !== old.c.review?.revision) ? <p className="meta tone-warn">{L("선택한 항목이 변경됐습니다. 입력은 유지했습니다. 닫고 다시 열어 최신 내용을 확인하세요.", "A selected item changed. Your input is kept. Close and reopen to review the latest version.")}</p> : null}
    <Field label={L("담당 부서", "Team")} htmlFor="br-team">
      <input id="br-team" list="br-teams" value={team} onChange={event => setTeam(event.target.value)} maxLength={128} data-autofocus
        placeholder={L("부서 이름", "Team name")} />
      <datalist id="br-teams">{suggestions.map(value => <option key={value} value={value} />)}</datalist>
    </Field>
    <div className="row2">
      <SelectField label={L("조사 상태", "Review status")} value={status} onChange={setStatus}
        options={Object.keys(REVIEW_STATUS).map(key => ({ id: key, label: L(...REVIEW_STATUS[key]) }))} />
      <div className="field"><label htmlFor="br-due">{L("조사 기한", "Due")}</label><input id="br-due" type="datetime-local" value={due} onChange={event => setDue(event.target.value)} /></div>
    </div>
    {status === "CLOSED" ? <SelectField label={L("완료 사유", "Completion reason")} value={reason} onChange={setReason}
      options={[{ id: "", label: L("사유 선택", "Choose a reason") }, ...Object.keys(REVIEW_REASONS).map(key => ({ id: key, label: L(...REVIEW_REASONS[key]) }))]} /> : null}
    {problem ? <p className="meta tone-warn">{problem}</p> : null}
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose} disabled={busy}>{L("취소", "Cancel")}</button>
      <button type="button" className="primary-btn" disabled={busy || Boolean(problem)} onClick={() => void save()}>{busy ? L("저장 중", "Saving") : L("저장", "Save")}</button>
    </div>
  </Modal>;
}

/** One response owner for every chosen credential, with the basis recorded as a comment on each. */
function OwnerModal({ rows, onClose, onDone, admin }: { rows: Row[]; onClose: () => void; onDone: (ids: string[], all: boolean) => void; admin: boolean }) {
  const L = useL();
  const toast = useToast();
  const saved = useSaved();
  const [person, setPerson] = useState<DirectoryPerson | null>(null);
  const [team, setTeam] = useState("");
  const [basis, setBasis] = useState(L("관리자 지정", "Assigned by admin"));
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const save = async () => {
    if (!selectablePerson(person)) return;
    setBusy(true);
    const note = basis.trim();
    const assigned: string[] = [];
    try {
      // The basis is checked once, before anything is assigned, by the rules its comments are saved under: a
      // refusal then leaves nothing half done.
      const checked = note ? await api<{ contains_credential: boolean; unsafe?: boolean }>("text-check", { method: "POST", body: JSON.stringify({ text: note.slice(0, 2000) }) }) : null;
      if (checked?.contains_credential || checked?.unsafe) {
        toast(reasonText(new DashboardAPIError(checked.contains_credential ? "TEXT_CONTAINS_CREDENTIAL" : "TEXT_CONTROL_CHARACTERS", 422), L), "bad");
        return;
      }
      for (const row of rows) {
        const routing = await api<ResponderRouting>(`findings/${row.c.finding_id}/response/routing`);
        await send(`findings/${row.c.finding_id}/assign`, "POST", { person_ref: person.person_ref, team: team.trim(), expected_version: routing.version });
        assigned.push(row.c.id); setProgress(assigned.length);
        if (note) await send(`findings/${row.c.finding_id}/comments`, "POST", { text: L(`담당자 지정 근거: ${note}`, `Owner assignment basis: ${note}`) });
      }
      toast(L(`${assigned.length}건의 담당자를 ${person.name}님으로 지정했습니다.`, `Assigned ${person.name} to ${assigned.length}.`));
      saved(); onDone(assigned, true);
    } catch (error) {
      if (!assigned.length) { toast(reasonText(error, L), "bad"); return; }
      toast(L(`${assigned.length}건은 담당자를 지정했습니다. 그 뒤의 근거 코멘트나 나머지 지정은 하지 못했습니다: ${reasonText(error, L)}`,
        `Assigned ${assigned.length}. The basis comment or the rest did not go through: ${reasonText(error, L)}`), "bad");
      saved(); onDone(assigned, false);
    } finally { setBusy(false); }
  };
  return <Modal onClose={onClose} labelledBy="bulk-owner-title" size="narrow" dismissable={!busy}>
    <h2 id="bulk-owner-title">{L("담당자 지정", "Assign owner")} <small>{countText(rows.length, L)}</small></h2>
    <PersonPicker label={L("대응 담당자", "Responder")} value={person} onChange={setPerson} disabled={busy} admin={admin} />
    <TextField label={L("명시적 책임 팀 (선택)", "Explicit responsible team (optional)")} value={team} onChange={setTeam} maxLength={100} disabled={busy}
      hint={L("팀 이름은 책임 표시이며 IdP 그룹으로 자동 해석하지 않습니다.", "This team label records responsibility and is not treated as an IdP group.")} />
    <TextField label={L("지정 근거", "Basis")} value={basis} onChange={setBasis} maxLength={200} />
    {busy ? <p className="meta" aria-live="polite">{L(`${progress}/${rows.length} 지정 중`, `Assigning ${progress}/${rows.length}`)}</p> : null}
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose} disabled={busy}>{L("취소", "Cancel")}</button>
      <button type="button" className="primary-btn" disabled={busy || !selectablePerson(person)} onClick={() => void save()}>{L("지정", "Assign")}</button>
    </div>
  </Modal>;
}
