"use client";

/* Audit Log: what happened in CreMore as its append-only trail recorded it (GET audit), what providers reported
 * about their own credentials (v2/coverage/events, never mixed with CreMore's own actions), and whether the trail's
 * hash chain still holds (audit/integrity). An Admin accepts a chain problem they examined, with a reason; the
 * acceptance is itself a row in the chain. ?tab= picks events | provider | chain, ?id= opens a record. */

import { type ReactNode, useEffect, useMemo, useState } from "react";

import { auditActionText, auditActorLabel, auditTargetLabel } from "@/components/labels";
import { enumLabel, useLocale } from "@/components/locale";
import { reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { Drawer, Menu, MenuItem, MenuSep, Modal, useMenu, useToast } from "@/console/layer";
import { Logo, serviceName } from "@/console/logos";
import { actorLabel } from "@/console/labels";
import type { ViewProps } from "@/console/shell";
import { fmtDT, rel, type Say, useL } from "@/console/text";
import { AreaField, Banner, Card, CardBody, Check, cls, EmptyRow, ErrorLine, Fact, Facts, FilterChip, Loading, PageHead, Pager, SearchBox, StateChip, Tabs, TextField, Tile, Tiles } from "@/console/ui";
import { api } from "@/lib/dashboard-api";
import { metadataEvents, type MetadataEvents } from "@/lib/provider-metadata";

export type AuditRow = {
  id: string; actor_id: string; action: string; target_type: string; target_id: string; target_name: string | null;
  from_status: string | null; to_status: string | null; note: string | null; created_at: string; recovered_from_connection?: boolean;
  actor_name?: string | null; actor_email?: string | null;
  actor_profile_basis?: "CURRENT_SIGN_IN" | "EVENT_SNAPSHOT";
  activity?: { method: string; route: string; targets: Record<string, string>; status: number | null; role: string | null; session_basis?: string | null };
};
export type ChainState = "INTACT" | "BROKEN" | "ANCHOR_MISMATCH" | "UNAUTHENTICATED" | "NOT_STARTED";
export type ChainProblem = { kind: string; seq: number | null; event_id: string | null; created_at: string | null; acknowledged: boolean; ack: string | null };
export type Integrity = {
  state: ChainState; checked_at: string; verified_through: number | null; head: { seq: number; mac: string } | null;
  genesis: { seq: number; mac: string } | null; legacy_rows: number; anchors: { count: number; last: { seq: number; at?: string } | null };
  pending: number; problem_count: number; open_problems: number; problems: ChainProblem[];
  unauthenticated: { sealed_count: number; pending_count: number };
  anchor?: { seq: number; state: "MATCHED" | "MISMATCH" | "MISSING" };
};

type Tab = "events" | "provider" | "chain";
type Key = "action" | "actor" | "target";
const KEYS: Key[] = ["action", "actor", "target"];
export const AUDIT_LIMIT = 1000;

export const CHAIN_STATE: Record<ChainState, { tone: "ok" | "warn" | "bad" | undefined; name: [string, string] }> = {
  INTACT: { tone: "ok", name: ["정상", "Intact"] },
  BROKEN: { tone: "bad", name: ["손상", "Broken"] },
  ANCHOR_MISMATCH: { tone: "bad", name: ["앵커 불일치", "Anchor mismatch"] },
  UNAUTHENTICATED: { tone: "warn", name: ["확인할 기록", "Rows to examine"] },
  NOT_STARTED: { tone: undefined, name: ["시작 전", "Not started"] },
};
// What each problem the check names says, in the words an Admin acts on.
export const PROBLEM: Record<string, [string, string, string, string]> = {
  SEQUENCE_GAP: ["기록 누락", "Missing rows", "체인 중간의 위치가 비어 있습니다. 그 자리의 기록이 지워졌습니다.", "Positions in the middle of the chain are empty: the rows there were removed."],
  SEQUENCE_INVALID: ["위치 오류", "Invalid position", "체인에 있을 수 없는 위치의 기록입니다.", "A row sits at a position no chain has."],
  MAC_MISMATCH: ["내용 변경", "Changed row", "봉인한 뒤 내용이 바뀐 기록입니다.", "A row was changed after it was sealed."],
  ANCHOR_CLAIM_MISMATCH: ["앵커 불일치", "Anchor claim mismatch", "앵커가 남긴 체인 머리와 지금 체인이 다릅니다. 기록이 봉인 해제된 뒤 다시 봉인됐습니다.", "The chain no longer matches the head an anchor recorded: rows were unsealed and sealed again."],
  ANCHOR_SEQUENCE_GAP: ["앵커 누락", "Missing anchor", "앵커 기록이 있어야 할 자리가 비어 있습니다.", "An anchor row is missing from its place."],
  CHAIN_REWOUND: ["체인 되감김", "Chain rewound", "worker가 봉인했던 체인 머리가 자리를 잃었습니다.", "The head a worker sealed lost its place."],
  CHAIN_RESET: ["체인 초기화", "Chain reset", "체인이 있던 동안 위치가 모두 사라졌습니다.", "The chain's positions are gone while it existed."],
  GENESIS_MISSING: ["시작 기록 없음", "Genesis missing", "체인의 시작 기록이 없습니다.", "The chain's first row is missing."],
  GENESIS_INVALID: ["시작 기록 오류", "Genesis invalid", "체인의 시작 기록이 올바르지 않습니다.", "The chain's first row is not valid."],
  GENESIS_MOVED: ["시작 기록 이동", "Genesis moved", "체인의 시작 기록이 다른 자리로 옮겨졌습니다.", "The chain's first row moved."],
  KEY_MISMATCH: ["키 불일치", "Key mismatch", "지금 설정과 다른 키로 봉인된 체인입니다.", "The chain was sealed with another key than this installation's."],
  UNAUTHENTICATED: ["CreMore가 쓰지 않은 기록", "Row CreMore did not write", "쓰는 순간의 인증(MAC)이 없는 기록입니다. 업그레이드 중 이전 API가 쓴 기록이면 확인 후 받아들입니다.", "A row without the MAC its writer adds. If an older API wrote it during an upgrade, accept it once examined."],
};
const problemText = (kind: string, L: Say) => {
  const copy = PROBLEM[kind];
  return copy ? { name: L(copy[0], copy[1]), text: L(copy[2], copy[3]) } : { name: kind, text: "" };
};

/** The picked problems still open in the report now: another Admin's acceptance or a new read drops the rest. */
export function stillOpen(picked: string[], open: ChainProblem[]) {
  return picked.filter(key => open.some(problem => problem.ack === key));
}
/** An acceptance reason as the API takes it: one line (the note keeps no line breaks). */
export function oneLine(text: string) {
  return text.replace(/\s+/g, " ").trim();
}

/** Who acted: a CreMore process by name (scanner, the false-positive policy), else the console's reading of it. */
function who(actor: string, locale: "ko" | "en", L: Say) {
  const known = auditActorLabel(actor, locale);
  return known !== actor ? known : actorLabel(actor, L);
}

/** A record's target, as the list names it: its saved label, else its kind and the start of its ID. */
function targetText(row: AuditRow, locale: "ko" | "en") {
  if (row.activity) return `${row.activity.method} ${row.activity.route}`;
  return row.target_name || `${auditTargetLabel(row.target_type, locale)}${row.target_id ? ` · ${row.target_id.slice(0, 8)}` : ""}`;
}

function actorText(row: AuditRow, locale: "ko" | "en", L: Say) {
  return row.actor_name || row.actor_email || who(row.actor_id, locale, L);
}

function noteText(row: AuditRow) {
  return row.activity ? (row.activity.status == null ? "" : `HTTP ${row.activity.status}`) : row.note;
}

export function Audit({ session, route, setParams }: ViewProps) {
  const L = useL();
  const locale = useLocale();
  const p = route.params;
  const tab: Tab = p.get("tab") === "provider" ? "provider" : p.get("tab") === "chain" ? "chain" : "events";
  // Read once and again after any change saved in the console: a poll would ask for a thousand rows every time.
  const rows = useApi<AuditRow[]>(`audit?limit=${AUDIT_LIMIT}`);
  const chain = useApi<Integrity>("audit/integrity");
  const filters = Object.fromEntries(KEYS.map(key => [key, (p.get(`f.${key}`) ?? "").split(",").filter(Boolean)])) as Record<Key, string[]>;
  const q = p.get("q") ?? "";
  const selected = p.get("id");
  const [query, setQuery] = useState(q);
  const menu = useMenu();
  const [menuKey, setMenuKey] = useState<Key>("action");
  useEffect(() => { setQuery(q); }, [q]);
  useEffect(() => {
    const timer = window.setTimeout(() => { if (query !== q) setParams({ q: query || null }); }, 250);
    return () => window.clearTimeout(timer);
  }, [query, q, setParams]);

  const all = useMemo(() => rows.data ?? [], [rows.data]);
  const title = "Audit Log";
  const meta = L("CreMore에서 한 작업과 누가 했는지의 기록", "What was done in CreMore, and by whom");
  if (rows.error) return <><PageHead title={title} meta={meta} /><ErrorLine onRetry={rows.reload}>{reasonText(rows.error, L)}</ErrorLine></>;
  if (!rows.data) return <><PageHead title={title} meta={meta} /><Loading /></>;

  const valueOf = (row: AuditRow, key: Key) => key === "action" ? row.action : key === "actor" ? row.actor_id : row.target_type;
  const nameOf = (key: Key, value: string) => {
    if (key === "action") return auditActionText(value, locale).label;
    if (key !== "actor") return auditTargetLabel(value, locale);
    const row = all.find(item => item.actor_id === value && (item.actor_name || item.actor_email));
    return row ? [actorText(row, locale, L), row.actor_email !== row.actor_name ? row.actor_email : null].filter(Boolean).join(" · ") : who(value, locale, L);
  };
  const needle = q.trim().toLowerCase();
  const matches = (row: AuditRow, skip?: Key) => KEYS.every(key => key === skip || !filters[key].length || filters[key].includes(valueOf(row, key)))
    && (!needle || [row.action, auditActionText(row.action, locale).label, row.actor_id, who(row.actor_id, locale, L), row.target_type,
      row.actor_name ?? "", row.actor_email ?? "", auditTargetLabel(row.target_type, locale), row.target_id, row.target_name ?? "", row.note ?? ""].join(" ").toLowerCase().includes(needle));
  const shown = all.filter(row => matches(row));
  const set = (params: Record<string, string | null>) => setParams(params);
  const toggle = (key: Key, value: string) => {
    const next = filters[key].includes(value) ? filters[key].filter(item => item !== value) : [...filters[key], value];
    set({ [`f.${key}`]: next.length ? next.join(",") : null });
  };
  const menuValues = (key: Key) => {
    const counts = new Map<string, number>();
    for (const row of all.filter(item => matches(item, key))) counts.set(valueOf(row, key), (counts.get(valueOf(row, key)) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  };
  // A filter shows only when the loaded rows differ in it (or it is already applied).
  const offered = KEYS.filter(key => filters[key].length || new Set(all.map(row => valueOf(row, key))).size > 1);
  const actors = new Set(all.map(row => row.actor_id)).size;
  const responses = all.filter(row => row.action.startsWith("FINDING_")).length;
  const latest = all[0];
  const state = chain.data ? CHAIN_STATE[chain.data.state] : undefined;
  const open = selected ? all.find(row => row.id === selected) : undefined;
  const keyName = (key: Key) => ({ action: L("작업", "Action"), actor: L("수행자", "Actor"), target: L("대상", "Target") }[key]);

  return <>
    <PageHead title={title} meta={meta} />
    <Tiles>
      <Tile icon="list" tone="blue" label={L("기록", "Records")} value={all.length} onClick={() => set({ tab: null })}
        tip={L(`최근 ${AUDIT_LIMIT.toLocaleString()}건까지 불러옵니다.`, `The latest ${AUDIT_LIMIT.toLocaleString()} records are loaded.`)} />
      <Tile icon="checkList" tone="amber" label={L("탐지 대응", "Finding actions")} value={responses}
        onClick={() => set({ tab: null, "f.target": "finding" })} tip={L("탐지 결과에 남은 기록입니다. 사람의 검토·오탐·예외와 CreMore의 자동 처리를 함께 셉니다.", "Records on findings: people's reviews, false positives and exceptions, and CreMore's automatic updates.")} />
      <Tile icon="users" tone="violet" label={L("작업 주체", "Actors")} value={actors} tip={L("사람과 CreMore의 자동 작업을 함께 셉니다.", "People and CreMore's own automatic work.")} />
      <Tile icon="shield" tone={state?.tone === "ok" ? "green" : state?.tone === "bad" ? "red" : state?.tone === "warn" ? "amber" : "gray"}
        label={L("해시 체인", "Hash chain")} value={state ? L(...state.name) : chain.error ? "—" : L("확인 중", "Checking")} onClick={() => set({ tab: "chain" })}
        tip={L("기록이 지워지거나 바뀌지 않았는지 키로 봉인한 체인으로 확인합니다.", "A keyed chain shows whether any record was removed or changed.")} />
    </Tiles>
    <Tabs value={tab} label={L("기록 종류", "Record kind")} onChange={next => set({ tab: next === "events" ? null : next, id: null })}
      items={[{ id: "events" as const, label: L("CreMore 기록", "CreMore records"), count: all.length },
        { id: "provider" as const, label: L("공급자 이벤트", "Provider events") },
        { id: "chain" as const, label: L("해시 체인", "Hash chain"), count: chain.data?.open_problems || undefined }]} />

    {tab === "events" ? <Card className="list-card">
      <div className="list-tools">
        <SearchBox id="audit-search" value={query} onChange={setQuery} label={L("기록 검색", "Search records")}
          placeholder={L("작업·수행자·대상·메모로 검색", "Search by action, actor, target or note")} />
      </div>
      {offered.length ? <div className="chips-row">
        {offered.map(key => {
          const n = filters[key].length;
          return <FilterChip key={key} icon={key === "action" ? "checkCircle" : key === "actor" ? "users" : "grid"} label={keyName(key)} count={n}
            onOpen={anchor => { setMenuKey(key); menu.open(anchor); }} onClear={() => set({ [`f.${key}`]: null })} />;
        })}
      </div> : null}
      {q ? <div className="applied"><span className="applied-chip"><span className="wrap-t">{L("검색: ", "Search: ")}{q}</span>
        <button type="button" onClick={() => set({ q: null })} aria-label={L("검색 지우기", "Clear search")}><Ic name="close" size={13} /></button></span></div> : null}
      <div className="table-wrap"><table className="tbl">
        <thead><tr><th>{L("시각", "Time")}</th><th>{L("작업", "Action")}</th><th>{L("수행자", "Actor")}</th>
          <th className="col-md">{L("대상", "Target")}</th><th className="col-sm">{L("메모", "Note")}</th></tr></thead>
        <tbody>
          {shown.length ? shown.map(row => <tr key={row.id} tabIndex={0} aria-selected={selected === row.id} onClick={() => set({ id: row.id })}
            onKeyDown={event => { if (event.key === "Enter") set({ id: row.id }); }}>
            <td className="nowrap"><span data-tip={fmtDT(row.created_at, locale)}>{rel(row.created_at, locale)}</span></td>
            <td><b>{auditActionText(row.action, locale).label}</b>{row.recovered_from_connection ? <div className="ig-sub">{L("저장된 연결 기록", "Saved connection record")}</div> : null}</td>
            <td><span className="wrap-t">{actorText(row, locale, L)}</span>{row.actor_email && row.actor_email !== actorText(row, locale, L) ? <div className="ig-sub wrap-t">{row.actor_email}</div> : null}</td>
            <td className="col-md"><span className="wrap-t" data-tip={row.target_id || undefined}>{targetText(row, locale)}</span></td>
            <td className="col-sm"><span className="clip subtle">{noteText(row) ?? ""}</span></td>
          </tr>) : <EmptyRow colSpan={5}>{all.length ? L("조건에 맞는 기록이 없습니다. 필터를 줄여 보세요.", "No records match. Try removing some filters.") : L("아직 기록이 없습니다.", "Nothing has been recorded yet.")}</EmptyRow>}
        </tbody>
      </table></div>
      <div className="list-foot"><span>{L(`${shown.length}건`, `${shown.length} records`)}</span>
        <span>{latest ? L(`최근 기록 ${rel(latest.created_at, locale)} · 최근 ${AUDIT_LIMIT.toLocaleString()}건까지 보입니다`, `Latest ${rel(latest.created_at, locale)} · shows the latest ${AUDIT_LIMIT.toLocaleString()}`) : null}</span></div>
    </Card> : tab === "provider" ? <ProviderEvents params={p} set={set} />
      : <Chain chain={chain} admin={session.role === "Admin"} />}

    {menu.anchor ? <Menu anchor={menu.anchor} onClose={menu.close} restore={menu.opener} label={keyName(menuKey)}>
      {menuValues(menuKey).map(([value, count]) => <MenuItem key={value} checked={filters[menuKey].includes(value)}
        end={<span className="num">{count}</span>} onSelect={() => toggle(menuKey, value)}>{nameOf(menuKey, value)}</MenuItem>)}
      {filters[menuKey].length ? <><MenuSep /><MenuItem className="pri" onSelect={() => { set({ [`f.${menuKey}`]: null }); menu.close(); }}>{L("선택 해제", "Clear selection")}</MenuItem></> : null}
    </Menu> : null}

    {open && tab === "events" ? <RecordDrawer row={open} onClose={() => set({ id: null })} /> : null}
  </>;
}

function RecordDrawer({ row, onClose }: { row: AuditRow; onClose: () => void }) {
  const L = useL();
  const locale = useLocale();
  const action = auditActionText(row.action, locale);
  const actor = actorText(row, locale, L);
  const status = (value: string | null) => value ? <>{enumLabel(value, locale)} <span className="mono subtle">{value}</span></> : L("기록 없음", "Not recorded");
  const facts: [string, ReactNode][] = [
    [L("작업 코드", "Action code"), <span className="mono" key="code">{row.action}</span>],
    [L("수행자", "Actor"), actor === row.actor_id ? <span className="mono">{row.actor_id}</span> : <>{actor} <span className="mono subtle">{row.actor_id}</span></>],
    [L("대상", "Target"), <>{auditTargetLabel(row.target_type, locale)}{row.target_name ? ` · ${row.target_name}` : ""}</>],
    [L("대상 ID", "Target ID"), row.target_id ? <span className="mono">{row.target_id}</span> : L("기록 없음", "Not recorded")],
    [L("변경 전", "Before"), status(row.from_status)],
    [L("변경 후", "After"), status(row.to_status)],
    [L("시각", "Time"), <>{fmtDT(row.created_at, locale)} <span className="mono subtle">{row.created_at}</span></>],
    [L("기록 ID", "Record ID"), <span className="mono">{row.id}</span>],
    [L("기록 출처", "Source"), row.recovered_from_connection ? L("저장된 연결 기록(원래 감사 기록 없음)", "Saved connection record (no audit row of its own)") : L("감사 기록", "Audit record")],
  ];
  if (row.actor_email) facts.splice(2, 0, [L("이메일", "Email"), <span className="wrap-t">{row.actor_email}</span>]);
  if (row.actor_profile_basis === "CURRENT_SIGN_IN") facts.push([L("이름·이메일 근거", "Name and email source"), L("같은 수행자 ID의 최근 검증된 로그인", "Latest verified sign-in for this actor ID")]);
  if (row.activity) facts.push(
    [L("요청", "Request"), <span className="mono wrap-t">{targetText(row, locale)}</span>],
    [L("HTTP 결과", "HTTP result"), row.activity.status ?? L("아직 결과 없음", "No result yet")],
    [L("작업 당시 역할", "Role at the time"), row.activity.role ?? "—"],
    ...Object.entries(row.activity.targets).map(([key, value]): [string, ReactNode] => [key, <span className="mono wrap-t">{value}</span>]),
  );
  return <Drawer label={L(`${action.label} 기록`, `${action.label} record`)} onClose={onClose}>
    <div className="drawer-head">
      <div className="dh-top">
        <div className="dh-logo"><span className="ig-cm"><Ic name="list" size={20} /></span></div>
        <div className="dh-main">
          <div className="md-crumb">Audit Log</div>
          <h2 className="dh-title">{action.label}</h2>
          <div className="dh-badges"><span className="tag">{actor}</span><span className="tag">{rel(row.created_at, locale)}</span></div>
        </div>
        <div className="dh-actions"><button type="button" className="icon-btn" aria-label={L("상세 닫기", "Close details")} data-tip={L("상세 닫기", "Close details")} onClick={onClose}><Ic name="panelClose" size={19} /></button></div>
      </div>
    </div>
    <div className="drawer-body" id="drawer-body">
      <section className="card"><div className="card-body">
        <p>{action.description}</p>
        {row.note === "LOCATIONS_REMOVED_KEY_RETIREMENT_UNCONFIRMED" ? <p>{L("기록된 노출 위치가 모두 없어졌습니다. 자격증명 자체의 폐기는 확인되지 않았습니다.", "Every recorded exposure location is gone. The credential itself was not confirmed retired.")}</p> : null}
      </div></section>
      <section className="card"><div className="card-head"><h3>{L("기록 내용", "Record")}</h3></div><div className="card-body">
        <Facts>{facts.map(([label, value]) => <Fact key={label} label={label}>{value}</Fact>)}</Facts>
      </div></section>
      <section className="card"><div className="card-head"><h3>{L("사유·메모", "Reason or note")}</h3></div><div className="card-body">
        <p className={row.note ? "wrap-t" : "subtle"} style={row.note ? { whiteSpace: "pre-wrap" } : undefined}>
          {noteText(row) || L("사유나 메모가 기록되지 않았습니다.", "No reason or note was recorded.")}</p>
      </div></section>
    </div>
  </Drawer>;
}

/* ---------- what providers reported ---------- */

// How the provider tied an event to an object, and how sure that tie is (lib/provider-metadata.ts checks both).
const BASIS: Record<string, [string, string]> = {
  PROVIDER_ID: ["공급자 ID", "Provider ID"], PROVIDER_EXPLICIT: ["공급자가 명시", "Named by the provider"],
  AUDIT_REFERENCE: ["감사 로그 참조", "Audit log reference"], IDENTIFIER: ["식별자", "Identifier"], CANDIDATE: ["후보", "Candidate"],
  POLICY: ["정책", "Policy"], UNKNOWN: ["알 수 없음", "Unknown"],
};
const CONFIDENCE: Record<string, [string, string]> = {
  EXACT: ["정확히 일치", "Exact"], IDENTIFIER: ["식별자 일치", "Identifier match"], CANDIDATE: ["후보", "Candidate"], UNKNOWN: ["알 수 없음", "Unknown"],
};

const UNREADABLE = "UNREADABLE";

function ProviderEvents({ params, set }: { params: URLSearchParams; set: (params: Record<string, string | null>) => void }) {
  const L = useL();
  const locale = useLocale();
  const provider = params.get("pe.provider") ?? "", eventType = params.get("pe.event") ?? "";
  const size = [25, 50, 100].includes(Number(params.get("pe.size"))) ? Number(params.get("pe.size")) : 50;
  const page = Math.max(0, Number(params.get("pe.page") ?? 0) || 0);
  const [data, setData] = useState<MetadataEvents | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [tick, setTick] = useState(0);
  const [eventQuery, setEventQuery] = useState(eventType);
  const menu = useMenu();
  const [menuKey, setMenuKey] = useState<"provider" | "event">("provider");
  useEffect(() => { setEventQuery(eventType); }, [eventType]);
  useEffect(() => {
    let live = true;
    const query = new URLSearchParams({ offset: String(page * size), limit: String(size) });
    if (provider) query.set("provider", provider);
    if (eventType) query.set("event_type", eventType);
    setError(null); setData(null);  // rows of the last filter never stand under this one
    api<unknown>(`v2/coverage/events?${query}`).then(value => {
      if (!live) return;
      try { setData(metadataEvents(value)); } catch { setError(UNREADABLE); }
    }).catch(reason => { if (live) setError(reason); });
    return () => { live = false; };
  }, [provider, eventType, page, size, tick]);

  if (error) return <Card className="list-card"><CardBody>
    <ErrorLine onRetry={() => setTick(value => value + 1)}>{error === UNREADABLE ? L("공급자 이벤트 응답을 읽지 못했습니다.", "The provider events answer could not be read.") : reasonText(error, L)}</ErrorLine>
    {provider || eventType ? <button type="button" className="ghost-btn" style={{ marginTop: 10 }} onClick={() => set({ "pe.provider": null, "pe.event": null, "pe.page": null })}>
      {L("필터 지우기", "Clear filters")}</button> : null}
  </CardBody></Card>;
  if (!data) return <Loading />;
  const providers = data.facets?.provider ?? [];
  const events = data.facets?.event_type ?? data.event_types;
  const partialChoices = data.facets_truncated === true || data.event_types_truncated === true;
  const chips: { key: "provider" | "event"; name: string; on: string; values: string[] }[] = [
    { key: "provider" as const, name: L("공급자", "Provider"), on: provider, values: providers },
    { key: "event" as const, name: L("이벤트", "Event"), on: eventType, values: events },
  ].filter(chip => chip.on || chip.values.length > 1 || (partialChoices && chip.key === "event"));
  const choose = (key: "provider" | "event", value: string | null) => set({ [key === "provider" ? "pe.provider" : "pe.event"]: value, "pe.page": null });
  return <Card className="list-card">
    <CardBody><Banner icon="info">{L("공급자가 자기 자격증명에 대해 보고한 기록입니다. CreMore에서 한 작업은 'CreMore 기록'에 있고, 공급자의 보관 기간과 연동이 읽는 범위 안의 기록만 옵니다.",
      "What providers reported about their own credentials. CreMore's own actions are under CreMore records; only what the provider keeps, within what the integration reads, arrives here.")}</Banner></CardBody>
    {partialChoices || (eventType && !events.includes(eventType)) ? <CardBody>
      {partialChoices ? <Banner tone="warn" icon="info">{L("조회 한도로 필터 선택지가 일부만 표시됩니다. 목록에 없는 이벤트도 정확한 이름을 입력해 조회할 수 있습니다.",
        "Filter choices are partial because of the lookup limit. You can still look up an unlisted event by its exact name.")}</Banner> : null}
      <form onSubmit={event => { event.preventDefault(); choose("event", eventQuery || null); }}>
        <TextField label={L("이벤트 이름 직접 조회", "Look up an event by name")} value={eventQuery} onChange={setEventQuery} maxLength={128}
          placeholder={L("공급자가 기록한 정확한 이벤트 이름", "Exact event name recorded by the provider")} />
        <div className="md-actions">
          <button type="submit" className="ghost-btn" disabled={!eventQuery || eventQuery === eventType}>{L("조회", "Look up")}</button>
          {eventType ? <button type="button" className="ghost-btn" onClick={() => choose("event", null)}>{L("이벤트 필터 해제", "Clear event filter")}</button> : null}
        </div>
      </form>
    </CardBody> : null}
    {chips.length ? <div className="chips-row">
      {chips.map(chip => <button type="button" key={chip.key} className={cls("fchip", chip.on && "on")} onClick={event => { setMenuKey(chip.key); menu.open(event.currentTarget); }}>
        <Ic name={chip.key === "provider" ? "grid" : "activity"} size={15} />
        <span>{chip.name}{chip.on ? `: ${chip.key === "provider" ? serviceName(chip.on, chip.on) : chip.on}` : ""}</span><Ic name="down" size={14} />
      </button>)}
    </div> : null}
    <div className="table-wrap"><table className="tbl">
      <thead><tr><th>{L("발생", "Occurred")}</th><th>{L("공급자", "Provider")}</th><th>{L("이벤트", "Event")}</th>
        <th className="col-md">{L("대상", "Object")}</th><th className="col-sm">{L("연결 근거", "Match basis")}</th></tr></thead>
      <tbody>
        {data.items.length ? data.items.map(item => {
          const side = item.subject ?? item.target;
          return <tr key={item.id}>
            <td className="nowrap">{item.occurred_at ? <span data-tip={fmtDT(item.occurred_at, locale)}>{rel(item.occurred_at, locale)}</span> : <span className="subtle">{L("보고 없음", "Not reported")}</span>}</td>
            <td><span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><Logo id={item.provider} size={22} />{serviceName(item.provider, item.provider)}</span></td>
            <td><span className="mono wrap-t">{item.event_type}</span></td>
            <td className="col-md">{side ? <span className="mono wrap-t">{side.object_id}</span> : <span className="subtle">{L("지목한 대상 없음", "No object named")}</span>}</td>
            <td className="col-sm"><span className="subtle">{L(...(BASIS[item.match_basis] ?? [item.match_basis, item.match_basis]))} · {L(...(CONFIDENCE[item.confidence] ?? [item.confidence, item.confidence]))}</span></td>
          </tr>;
        }) : <EmptyRow colSpan={5}>{provider || eventType ? L("조건에 맞는 이벤트가 없습니다.", "No events match.")
          : L("공급자 이벤트를 모은 연동이 없거나, 모은 기간 안에 이벤트가 없습니다.", "No integration has collected provider events, or none fell in the collected window.")}</EmptyRow>}
      </tbody>
    </table></div>
    <Pager page={page} pages={Math.max(1, Math.ceil(data.total / size))} size={size} total={data.total}
      onPage={next => set({ "pe.page": next ? String(next) : null })} onSize={next => set({ "pe.size": next === 50 ? null : String(next), "pe.page": null })} />
    {menu.anchor ? <Menu anchor={menu.anchor} onClose={menu.close} restore={menu.opener} label={menuKey === "provider" ? L("공급자", "Provider") : L("이벤트", "Event")}>
      {(menuKey === "provider" ? providers : events).map(value => <MenuItem key={value} checked={(menuKey === "provider" ? provider : eventType) === value}
        onSelect={() => { choose(menuKey, value); menu.close(); }}>{menuKey === "provider" ? serviceName(value, value) : value}</MenuItem>)}
      {(menuKey === "provider" ? provider : eventType) ? <><MenuSep /><MenuItem className="pri" onSelect={() => { choose(menuKey, null); menu.close(); }}>{L("선택 해제", "Clear selection")}</MenuItem></> : null}
    </Menu> : null}
  </Card>;
}

/* ---------- the hash chain ---------- */

function Chain({ chain, admin }: { chain: ReturnType<typeof useApi<Integrity>>; admin: boolean }) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const [picked, setPicked] = useState<string[]>([]);
  const [accepting, setAccepting] = useState(false);
  const [anchorSeq, setAnchorSeq] = useState("");
  const [anchorMac, setAnchorMac] = useState("");
  const [anchor, setAnchor] = useState<Integrity["anchor"] | null>(null);
  const [checking, setChecking] = useState(false);
  if (chain.error) return <ErrorLine onRetry={chain.reload}>{reasonText(chain.error, L)}</ErrorLine>;
  if (!chain.data) return <Loading label={L("체인을 처음부터 확인하는 중", "Walking the chain from its start")} />;
  const report = chain.data;
  const state = CHAIN_STATE[report.state];
  const acceptable = (problem: ChainProblem) => admin && !problem.acknowledged && Boolean(problem.ack);
  const open = report.problems.filter(acceptable);
  const chosen = stillOpen(picked, open);
  const checkAnchor = async () => {
    setChecking(true);
    try {
      const answer = await api<Integrity>(`audit/integrity?anchor_seq=${encodeURIComponent(anchorSeq.trim())}&anchor_mac=${encodeURIComponent(anchorMac.trim().toLowerCase())}`);
      setAnchor(answer.anchor ?? null);
    } catch (reason) { toast(reasonText(reason, L), "bad"); } finally { setChecking(false); }
  };
  const anchorName = { MATCHED: L("일치", "Matches"), MISMATCH: L("다름", "Differs"), MISSING: L("그 위치까지 체인이 없음", "The chain is shorter") };
  return <>
    <Card title={L("체인 상태", "Chain state")} className="list-card" right={<button type="button" className="ghost-btn" onClick={chain.reload}><Ic name="refresh" size={15} />{L("다시 읽기", "Read again")}</button>}
      meta={L(`${rel(report.checked_at, locale)} 확인 · 1분 동안 같은 결과를 씁니다`, `Checked ${rel(report.checked_at, locale)} · served for a minute`)}>
      <CardBody>
        <div style={{ marginBottom: 12 }}><StateChip tone={state.tone}>{L(...state.name)}</StateChip></div>
        <Facts>
          <Fact label={L("확인한 끝 위치", "Verified through")}>{report.verified_through ?? "—"}</Fact>
          <Fact label={L("체인 머리", "Head")}>{report.head ? <span className="mono">#{report.head.seq} · {report.head.mac.slice(0, 16)}…</span> : "—"}</Fact>
          <Fact label={L("시작 기록", "Genesis")}>{report.genesis ? <span className="mono">#{report.genesis.seq}</span> : "—"}</Fact>
          <Fact label={L("앵커", "Anchors")}>{report.anchors.count ? L(`${report.anchors.count}개 · 마지막 #${report.anchors.last?.seq ?? "—"}`, `${report.anchors.count} · last #${report.anchors.last?.seq ?? "—"}`) : L("없음", "None")}</Fact>
          <Fact label={L("봉인 대기", "Waiting to be sealed")}>{report.pending}</Fact>
          <Fact label={L("체인 이전 기록", "Rows before the chain")}>{report.legacy_rows}</Fact>
          <Fact label={L("CreMore가 쓰지 않은 기록", "Rows CreMore did not write")}>{L(`봉인됨 ${report.unauthenticated.sealed_count} · 대기 ${report.unauthenticated.pending_count}`, `${report.unauthenticated.sealed_count} sealed · ${report.unauthenticated.pending_count} waiting`)}</Fact>
          <Fact label={L("문제", "Problems")}>{L(`열린 문제 ${report.open_problems} · 전체 ${report.problem_count}`, `${report.open_problems} open of ${report.problem_count}`)}</Fact>
        </Facts>
      </CardBody>
    </Card>
    <Card title={L("찾은 문제", "Problems found")} className="list-card" meta={report.problem_count > report.problems.length ? L(`처음 ${report.problems.length}개가 보입니다`, `The first ${report.problems.length} are shown`) : undefined}
      right={admin && open.length ? <button type="button" className="primary-btn" disabled={!chosen.length} onClick={() => setAccepting(true)}>
        <Ic name="checkCircle" size={15} />{L(`확인 처리 ${chosen.length}`, `Accept ${chosen.length}`)}</button> : undefined}>
      <div className="table-wrap"><table className="tbl">
        <thead><tr>{admin && open.length ? <th className="sel-cell">
          <button type="button" className="sel-btn" role="checkbox" aria-checked={chosen.length === open.length ? true : chosen.length ? "mixed" : false}
            aria-label={L("받아들일 수 있는 문제 모두 선택", "Select every problem that can be accepted")}
            onClick={() => setPicked(chosen.length === open.length ? [] : open.map(item => item.ack!))}><Check on={chosen.length === open.length} mixed={chosen.length > 0 && chosen.length < open.length} /></button></th> : null}
          <th>{L("문제", "Problem")}</th><th>{L("위치", "Position")}</th><th className="col-md">{L("기록", "Row")}</th><th>{L("상태", "State")}</th></tr></thead>
        <tbody>
          {report.problems.length ? report.problems.map((problem, index) => {
            const text = problemText(problem.kind, L);
            const key = problem.ack ?? `${problem.kind}:${problem.seq ?? problem.event_id ?? index}`;
            return <tr key={key}>
              {admin && open.length ? <td className="sel-cell">{acceptable(problem) ? <button type="button" className="sel-btn" role="checkbox"
                aria-checked={chosen.includes(problem.ack!)} aria-label={L(`${text.name} 선택`, `Select ${text.name}`)}
                onClick={() => setPicked(chosen.includes(problem.ack!) ? chosen.filter(item => item !== problem.ack) : [...chosen, problem.ack!])}>
                <Check on={chosen.includes(problem.ack!)} /></button> : null}</td> : null}
              <td><b>{text.name}</b>{text.text ? <div className="ig-sub">{text.text}</div> : null}</td>
              <td className="num">{problem.seq ? `#${problem.seq}` : "—"}</td>
              <td className="col-md">{problem.event_id ? <span className="mono wrap-t">{problem.event_id}</span> : "—"}{problem.created_at ? <div className="ig-sub">{fmtDT(problem.created_at, locale)}</div> : null}</td>
              <td>{problem.acknowledged ? <StateChip tone="ok">{L("확인 처리됨", "Accepted")}</StateChip>
                : problem.ack ? <StateChip tone="warn">{L("열림", "Open")}</StateChip>
                  : <StateChip tone="bad" tip={L("체인 전체의 문제라 받아들일 수 없습니다.", "A problem of the whole chain cannot be accepted.")}>{L("열림", "Open")}</StateChip>}</td>
            </tr>;
          }) : <EmptyRow colSpan={admin && open.length ? 5 : 4}>{L("찾은 문제가 없습니다.", "No problem was found.")}</EmptyRow>}
        </tbody>
      </table></div>
    </Card>
    <Card title={L("밖에 둔 체인 머리와 대조", "Compare with a head kept elsewhere")} className="list-card"
      info={L("SIEM이 받은 audit.chain_anchor 이벤트의 위치와 MAC을 넣으면, 그 뒤로 체인이 다시 쓰이지 않았는지 확인합니다.", "Enter the position and MAC of an audit.chain_anchor event your SIEM received to check the chain was not rewritten since.")}>
      <CardBody>
        <div className="row2">
          <TextField label={L("위치", "Position")} value={anchorSeq} onChange={value => { setAnchorSeq(value); setAnchor(null); }} inputMode="numeric" placeholder="1024" />
          <TextField label="MAC" value={anchorMac} onChange={value => { setAnchorMac(value); setAnchor(null); }} placeholder={L("64자리 16진수", "64 hex digits")} maxLength={64} />
        </div>
        <div className="md-actions" style={{ marginTop: 12 }}>
          <button type="button" className="ghost-btn" disabled={checking || !/^[1-9][0-9]*$/.test(anchorSeq.trim()) || !/^[0-9a-fA-F]{64}$/.test(anchorMac.trim())}
            onClick={() => void checkAnchor()}><Ic name="shield" size={15} />{L("대조", "Compare")}</button>
          {anchor ? <StateChip tone={anchor.state === "MATCHED" ? "ok" : "bad"}>{L(`#${anchor.seq} · `, `#${anchor.seq} · `)}{anchorName[anchor.state]}</StateChip> : null}
        </div>
      </CardBody>
    </Card>
    {accepting ? <AcceptModal items={chosen} onClose={() => setAccepting(false)} onDone={count => {
      setAccepting(false); setPicked([]); chain.reload(); saved();
      toast(L(`문제 ${count}개를 확인 처리했습니다`, `Accepted ${count} problem${count === 1 ? "" : "s"}`));
    }} /> : null}
  </>;
}

function AcceptModal({ items, onClose, onDone }: { items: string[]; onClose: () => void; onDone: (count: number) => void }) {
  const L = useL();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async () => {
    setBusy(true); setError(null);
    try {
      const answer = await send<{ acknowledged: number }>("audit/integrity/acknowledge", "POST", { items, reason: oneLine(reason) });
      onDone(answer.acknowledged);
    } catch (reason) { setError(reasonText(reason, L)); } finally { setBusy(false); }
  };
  return <Modal onClose={onClose} labelledBy="ack-title" dismissable={!busy}>
    <h2 id="ack-title">{L("문제 확인 처리", "Accept problems")}</h2>
    <p className="ig-sub">{L(`확인한 문제 ${items.length}개를 받아들입니다. 받아들인 기록 자체가 체인에 남고, 그 기록이나 범위가 바뀌면 문제가 다시 열립니다.`,
      `Accepts the ${items.length} problem${items.length === 1 ? "" : "s"} you examined. The acceptance is itself a row in the chain, and a problem opens again when its row or extent changes.`)}</p>
    {error ? <Banner tone="bad" icon="alert">{error}</Banner> : null}
    <AreaField label={L("사유", "Reason")} value={reason} onChange={setReason} rows={3} maxLength={500}
      placeholder={L("예: 업그레이드 중 이전 API가 쓴 기록임을 배포 기록으로 확인", "e.g. confirmed from the deployment log that an older API wrote these during the upgrade")} />
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose} disabled={busy}>{L("취소", "Cancel")}</button>
      <button type="button" className="primary-btn" disabled={busy || !oneLine(reason)} onClick={() => void submit()}>{L("확인 처리", "Accept")}</button>
    </div>
  </Modal>;
}
