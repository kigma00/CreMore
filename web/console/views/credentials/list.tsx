"use client";

/* Credentials: exposed ones, every tracked one, or those stored in a vault. Filters, sort, search
 * and the open credential live in the URL, so a view can be shared by its link; column choice and
 * saved views are per device. */

import { type ReactNode, useEffect, useMemo, useState } from "react";

import { hasRole } from "@/lib/dashboard-session";
import { CHECK_BY, type CheckKey, isCheck } from "@/console/checks";
import { reasonText, useApi } from "@/console/data";
import { Ic, type IconName } from "@/console/icons";
import { kindLabel, typeLabel, visLabel } from "@/console/labels";
import { Menu, MenuItem, MenuLabel, MenuSep, Modal, useMenu, useToast } from "@/console/layer";
import { Logo, serviceName } from "@/console/logos";
import { assignedPerson } from "@/console/people";
import { type CredentialRecord, daysTo, exposureService, hasWrite, isExposed, isRemoved, type Kind, RECORDS_PATH, type RecordsResponse, worstVis } from "@/console/records";
import type { ViewProps } from "@/console/shell";
import { downloadCsv, useL } from "@/console/text";
import { Card, EmptyRow, ErrorLine, FilterChip, InfoTip, Loading, PageHead, Pager, Pill, RISK_RANK, RiskTag, SearchBox, statusLabel, TabCards, Tabs, TextField, verifyLabel, VerifyTag } from "@/console/ui";
import { Expiry } from "@/console/views/credentials/cells";
import { CredentialDrawer } from "@/console/views/credentials/drawer";
import { IssuedItemModal } from "@/console/views/credentials/issued";
import { ownerBasis, verifyBasis } from "@/console/views/credentials/risk";
import { responseLabel, ResponseTag } from "@/console/views/credentials/response";
import type { ResponseState } from "@/console/records";

type Tab = "exposed" | "removed" | "all" | "vault";
type SortKey = "name" | "owner" | "type" | "where" | "risk" | "verify" | "expires" | "status";
type Sort = { key: SortKey; dir: "asc" | "desc" };
type FilterKey = "provider" | "type" | "verify" | "where" | "vis" | "scope" | "risk" | "owner" | "status";
type SavedView = { name: string; filters: Partial<Record<FilterKey, string[]>>; check: CheckKey | null; q: string; tab: Tab; cat: string };

const FILTER_KEYS: FilterKey[] = ["provider", "type", "verify", "where", "vis", "scope", "risk", "owner", "status"];
const COLS: { key: SortKey; size?: "col-sm" | "col-md" }[] = [
  { key: "name" }, { key: "owner", size: "col-sm" }, { key: "type", size: "col-md" }, { key: "where", size: "col-sm" },
  { key: "risk" }, { key: "verify", size: "col-md" }, { key: "expires", size: "col-md" }, { key: "status" },
];
const VERIFY_ORDER: Record<string, number> = { active: 5, unknown: 4, inactive: 3, expired: 2, failed: 1, revoked: 0 };
const STATUS_ORDER: Record<string, number> = { pending: 6, review: 5, action: 4, done: 3, ignored: 2, fp: 1 };
const DEFAULT_SORT: Sort[] = [{ key: "risk", dir: "desc" }, { key: "name", dir: "asc" }];
const PREFS = "cremore.console.credentials.v1";

function readPrefs(): { hidden: SortKey[]; views: SavedView[]; size: number } {
  try {
    const value = JSON.parse(window.localStorage.getItem(PREFS) || "{}");
    return {
      hidden: Array.isArray(value.hidden) ? value.hidden.filter((key: string) => COLS.some(col => col.key === key && key !== "name")) : [],
      views: Array.isArray(value.views) ? value.views.filter((view: SavedView) => view && typeof view.name === "string").slice(0, 30) : [],
      size: [25, 50, 100].includes(value.size) ? value.size : 50,
    };
  } catch {
    return { hidden: [], views: [], size: 50 };
  }
}

function parseSort(value: string | null): Sort[] {
  if (!value) return DEFAULT_SORT;
  const out = value.split(",").map(part => part.split(":")).filter(([key, dir]) => COLS.some(col => col.key === key) && (dir === "asc" || dir === "desc"))
    .map(([key, dir]) => ({ key: key as SortKey, dir: dir as "asc" | "desc" }));
  return out.length ? out.slice(0, 3) : DEFAULT_SORT;
}

export function Credentials({ session, route, go, setParams }: ViewProps) {
  const L = useL();
  const toast = useToast();
  const records = useApi<RecordsResponse>(RECORDS_PATH, { every: 60_000 });
  const engine = useApi<{ detectors: { credential_type: string; name: string }[] }>("detection-engine");
  const orgRules = useApi<{ credential_type: string; name: string }[]>("rules");
  const [prefs, setPrefs] = useState<{ hidden: SortKey[]; views: SavedView[]; size: number }>({ hidden: [], views: [], size: 50 });
  useEffect(() => { setPrefs(readPrefs()); }, []);
  const savePrefs = (next: typeof prefs) => {
    setPrefs(next);
    try { window.localStorage.setItem(PREFS, JSON.stringify(next)); } catch { /* per device */ }
  };
  const [saveView, setSaveView] = useState<string | null>(null);
  const [filterKey, setFilterKey] = useState<FilterKey | null>(null);
  const [filterQ, setFilterQ] = useState("");
  const filterMenu = useMenu(), viewsMenu = useMenu(), colsMenu = useMenu();

  const p = route.params;
  const defaultTab: Tab = route.view === "exposed" ? "exposed" : "all";
  const tab: Tab = p.get("tab") === "vault" ? "vault" : p.get("tab") === "removed" ? "removed" : p.get("tab") === "exposed" ? "exposed" : p.get("tab") === "all" ? "all" : defaultTab;
  const cat = (["token", "apikey", "cloud", "other"].includes(p.get("cat") ?? "") ? p.get("cat") : "all") as Kind | "all";
  const q = p.get("q") ?? "";
  const check = isCheck(p.get("check")) ? p.get("check") as CheckKey : null;
  const showFP = p.get("fp") === "1";
  const hideFP = tab === "exposed" && !showFP;
  const sort = parseSort(p.get("sort"));
  const page = Math.max(0, Number(p.get("page") || 0) || 0);
  const selected = p.get("id");
  const filters = useMemo(() => {
    const out: Partial<Record<FilterKey, string[]>> = {};
    for (const key of FILTER_KEYS) {
      const value = route.params.get(`f.${key}`);
      if (value) out[key] = value.split(",").filter(Boolean);
    }
    return out;
  }, [route.params]);

  // Detectors and organization rules name the type they report under.
  const catalog = useMemo(() => new Map([...(engine.data?.detectors ?? []), ...(orgRules.data ?? [])].map(d => [d.credential_type, d.name])), [engine.data, orgRules.data]);
  const all = records.data?.items;
  const typeName = (c: CredentialRecord) => typeLabel(c.credential_type, L, catalog);
  const name = (c: CredentialRecord) => c.name || typeName(c);
  const now = Date.now();

  const FDEF: Record<FilterKey, { label: string; icon: IconName; get: (c: CredentialRecord) => string[]; name: (v: string) => string; logo?: boolean }> = {
    provider: { label: L("발급 서비스", "Issuer"), icon: "key", get: c => [c.provider], name: v => serviceName(v), logo: true },
    type: { label: L("유형", "Type"), icon: "token", get: c => [c.credential_type], name: v => typeLabel(v, L, catalog) },
    verify: { label: L("활성 여부", "Activity"), icon: "activity", get: c => [c.verification.state], name: v => verifyLabel(v as never, L) },
    where: { label: L("노출 위치", "Found in"), icon: "scan", get: c => { const current = c.exposures.filter(e => e.current || e.removal_pending); return current.length ? Array.from(new Set(current.map(e => exposureService(e.source_type)))) : ["none"]; },
      name: v => v === "none" ? L("노출 없음", "Not exposed") : serviceName(v), logo: true },
    vis: { label: L("공개 범위", "Visibility"), icon: "globe", get: c => { const current = c.exposures.filter(e => e.current); return current.length ? Array.from(new Set(current.map(e => e.visibility))) : ["none"]; },
      name: v => v === "none" ? L("노출 없음", "Not exposed") : visLabel(v, L) },
    scope: { label: L("권한", "Permissions"), icon: "lockOpen", get: c => [!c.scopes ? "unknown" : hasWrite(c) ? "write" : "read"],
      name: v => ({ write: L("쓰기·관리", "Write/admin"), read: L("읽기 전용", "Read-only"), unknown: L("미확인", "Unknown") } as Record<string, string>)[v] ?? v },
    risk: { label: L("위험도", "Risk"), icon: "bolt", get: c => [c.risk], name: v => ({ critical: L("심각", "Critical"), high: L("높음", "High"), medium: L("보통", "Medium"), low: L("낮음", "Low"), info: L("정보", "Info") } as Record<string, string>)[v] ?? v },
    owner: { label: L("대응 담당자", "Response owner"), icon: "user", get: c => [c.owner?.name || c.owner?.team || "none"], name: v => v === "none" ? L("미확인", "Unknown") : v },
    status: { label: L("처리 상태", "Status"), icon: "checkCircle", get: c => [c.status === "fp" || c.status === "ignored" ? c.status : c.response?.state ?? c.status ?? "none"], name: v => v === "none" ? L("노출 없음", "Not exposed") : v === v.toUpperCase() ? responseLabel(v as ResponseState, L) : statusLabel(v as never, L) },
  };

  const base = useMemo(() => (all ?? []).filter(c => tab === "exposed" ? isExposed(c) : tab === "removed" ? isRemoved(c) : tab === "vault" ? c.vault.state === "stored" : true), [all, tab]);
  const inCat = (c: CredentialRecord) => cat === "all" || c.kind === cat;
  const matches = (c: CredentialRecord, except?: FilterKey) => {
    if (hideFP && c.status === "fp") return false;
    if (check && !CHECK_BY[check].test(c, now)) return false;
    const needle = q.trim().toLowerCase();
    if (needle) {
      const hay = [c.name, c.hint, typeName(c), c.credential_type, serviceName(c.provider), c.owner?.name, c.owner?.team, c.issuer?.name, ...c.tags,
        ...c.exposures.map(e => `${e.resource_name} ${e.location}`)].filter(Boolean).join(" ").toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    for (const key of FILTER_KEYS) {
      if (key === except) continue;
      const chosen = filters[key];
      if (chosen?.length && !FDEF[key].get(c).some(value => chosen.includes(value))) return false;
    }
    return true;
  };
  const sortValue = (c: CredentialRecord, key: SortKey): number | string => {
    switch (key) {
      case "name": return name(c).toLowerCase();
      case "owner": return c.owner?.name?.toLowerCase() ?? "￿";
      case "type": return typeName(c);
      case "where": return c.exposures.filter(e => e.current).length;
      case "risk": return RISK_RANK[c.risk];
      case "verify": return VERIFY_ORDER[c.verification.state] ?? 0;
      case "expires": return c.expiry === "date" ? daysTo(c.expires_at) ?? 1e9 : c.expiry === "none" ? 1e12 : 1e12 + 1;
      case "status": return c.response && c.status !== "fp" && c.status !== "ignored"
        ? ({ NEW: 10, REVIEWING: 9, ASSIGNED: 8, SEND_UNKNOWN: 7, NOT_SENT: 7, NEEDS_ACTION: 6, REPORT_REQUIRED: 5, SENDING: 4, WAITING_OWNER: 3, WAITING_VERIFICATION: 2, REMOVED: 1, COMPLETED: 0 }[c.response.state] ?? 0) : STATUS_ORDER[c.status ?? ""] ?? 0;
    }
  };
  const rows = base.filter(inCat).filter(c => matches(c)).sort((a, b) => {
    for (const s of sort) {
      const va = sortValue(a, s.key), vb = sortValue(b, s.key);
      if (va < vb) return s.dir === "asc" ? -1 : 1;
      if (va > vb) return s.dir === "asc" ? 1 : -1;
    }
    return 0;
  });
  const pages = Math.max(1, Math.ceil(rows.length / prefs.size));
  const shown = rows.slice(Math.min(page, pages - 1) * prefs.size, (Math.min(page, pages - 1) + 1) * prefs.size);

  const set = (changes: Record<string, string | null>) => setParams({ page: null, ...changes });
  const toggleFilter = (key: FilterKey, value: string) => {
    const current = filters[key] ?? [];
    const next = current.includes(value) ? current.filter(v => v !== value) : [...current, value];
    set({ [`f.${key}`]: next.length ? next.join(",") : null });
  };
  const clearFilters = () => set({ ...Object.fromEntries(FILTER_KEYS.map(key => [`f.${key}`, null])), check: null, q: null, fp: tab === "exposed" ? "1" : null });
  const applyView = (view: SavedView) => {
    set({ ...Object.fromEntries(FILTER_KEYS.map(key => [`f.${key}`, view.filters[key]?.length ? view.filters[key]!.join(",") : null])),
      check: view.check, q: view.q || null, tab: view.tab === defaultTab ? null : view.tab, cat: view.cat === "all" ? null : view.cat });
    toast(L("보기를 적용했습니다.", "View applied."));
  };
  const onSort = (key: SortKey) => {
    const first = key === "name" || key === "owner" || key === "type" ? "asc" : "desc";
    const next = [...sort];
    const index = next.findIndex(s => s.key === key);
    if (index < 0) { next.push({ key, dir: first }); if (next.length > 3) next.shift(); }
    else if (next[index].dir === first) next[index] = { key, dir: first === "asc" ? "desc" : "asc" };
    else next.splice(index, 1);
    set({ sort: next.length ? next.map(s => `${s.key}:${s.dir}`).join(",") : null });
  };
  const exportCsv = () => {
    const header = [L("이름", "Name"), L("유형", "Type"), L("발급 서비스", "Issuer"), L("가린 식별자", "Masked identifier"), L("대응 담당자", "Response owner"),
      L("위험", "Risk"), L("활성 여부", "Activity"), L("처리 상태", "Status"), L("만료", "Expires"), L("노출 위치 수", "Locations"), L("처음 발견", "First found")];
    const lines = rows.map(c => [name(c), typeName(c), serviceName(c.provider), c.hint, c.owner?.name ?? c.owner?.team, c.risk, verifyLabel(c.verification.state, L, c.verification.basis),
      FDEF.status.name(FDEF.status.get(c)[0]), c.expires_at ?? c.expiry, c.exposures.filter(e => e.current).length, c.first_seen_at]);
    downloadCsv(`cremore-credentials-${new Date().toISOString().slice(0, 10)}.csv`, [header, ...lines]);
    toast(L(`${rows.length}건을 CSV로 내려받았습니다.`, `Downloaded ${rows.length} rows as CSV.`));
  };

  const title = L("Credential", "Credentials");
  // An item opened by its link (search) reads on its own, whether or not the list has loaded.
  const entity = p.get("entity");
  const issued = entity ? <IssuedItemModal key={entity} entityId={entity} onClose={() => setParams({ entity: null })} /> : null;
  if (!all && records.loading) return <><PageHead title={title} /><Loading />{issued}</>;
  if (!all) return <><PageHead title={title} /><ErrorLine onRetry={records.reload}>{reasonText(records.error, L)}</ErrorLine>{issued}</>;

  const counts = { exposed: all.filter(isExposed).length, removed: all.filter(isRemoved).length, all: all.length, vault: all.filter(c => c.vault.state === "stored").length };
  const catCount = (kind: Kind | "all") => base.filter(c => kind === "all" || c.kind === kind).length;
  const activeFilters = FILTER_KEYS.filter(key => filters[key]?.length);
  const nFilters = activeFilters.length + (check ? 1 : 0) + (hideFP ? 1 : 0);
  const colLabel: Record<SortKey, string> = { name: L("Credential", "Credential"), owner: L("대응 담당자", "Response owner"), type: L("유형", "Type"), where: L("노출 위치", "Found in"),
    risk: L("위험", "Risk"), verify: L("활성 여부", "Activity"), expires: L("만료", "Expires"), status: L("처리 상태", "Status") };
  const cols = COLS.filter(col => !prefs.hidden.includes(col.key));
  const open = selected ? all.find(c => c.id === selected) ?? null : null;

  const filterValues = (key: FilterKey) => {
    const counted = new Map<string, number>();
    for (const c of base.filter(inCat).filter(c => matches(c, key))) for (const v of FDEF[key].get(c)) counted.set(v, (counted.get(v) ?? 0) + 1);
    for (const c of base.filter(inCat)) for (const v of FDEF[key].get(c)) if (!counted.has(v)) counted.set(v, 0);
    const needle = filterQ.toLowerCase();
    return Array.from(counted).filter(([v]) => !needle || FDEF[key].name(v).toLowerCase().includes(needle)).sort((a, b) => b[1] - a[1]);
  };

  const cell = (c: CredentialRecord, key: SortKey): ReactNode => {
    const current = c.exposures.filter(e => e.current);
    switch (key) {
      case "name": return <td key={key}><div className="cred-cell"><Logo id={c.provider} size={30} />
        <div className="cred-text"><div className="cred-name">{name(c)}</div><div className="cred-hint mono">{c.hint ?? c.issued?.object_id ?? ""}</div></div></div></td>;
      case "owner": {
        const person = assignedPerson(c);
        return <td key={key} className="col-sm">{c.owner?.name
        ? <Pill tip={[c.owner.team ?? person?.department, person?.email, L("근거: ", "basis: ") + ownerBasis(c, L)].filter(Boolean).join(" · ")}>{person?.name ?? c.owner.name}</Pill>
        : c.owner?.team ? <Pill tip={ownerBasis(c, L)}>{c.owner.team}</Pill>
          : <Pill unknown tip={L("대응 담당자를 찾지 못했습니다", "No response owner found") + (c.issuer ? L(`. 소유 계정: ${c.issuer.name}`, `. Owning account: ${c.issuer.name}`) : "")}>{L("미확인", "Unknown")}</Pill>}</td>;
      }
      case "type": return <td key={key} className="col-md"><span className="cell-wrap">{typeName(c)}</span></td>;
      case "where": return <td key={key} className="col-sm">{current.length
        ? <span className="where-cell">{Array.from(new Set(current.map(e => exposureService(e.source_type)))).map(w => <Logo key={w} id={w} size={24} />)}
          {worstVis(c) === "public" ? <span className="vis vis-public">{visLabel("public", L)}</span> : null}</span>
        : <span className="subtle cell-wrap">{c.removal_pending_location_count ? L("다른 연결의 제거 확인 대기", "Awaiting removal confirmation from other connections") : isRemoved(c) ? L("제거됨", "Removed") : c.exposed ? L("노출 위치 확인 중", "Exposure locations not confirmed") : L("노출 없음", "Not exposed")}</span>}
        {current.length > 0 && Boolean(c.removal_pending_location_count) ? <div className="subtle small cell-wrap">{L("다른 연결의 제거 확인 대기", "Awaiting removal confirmation from other connections")}</div> : null}</td>;
      case "risk": return <td key={key}><RiskTag level={c.risk} /></td>;
      case "verify": return <td key={key} className="col-md"><VerifyTag state={c.verification.state} basis={c.verification.basis} tip={verifyBasis(c, L)} /></td>;
      case "expires": return <td key={key} className="col-md"><Expiry c={c} /></td>;
      case "status": return <td key={key}><ResponseTag c={c} /></td>;
    }
  };

  return <>
    <PageHead title={title} meta={L(`${all.length}건`, `${all.length} records`)} />
    <TabCards value={tab} label={L("Credential 범위", "Credential scope")} onChange={next => set({ tab: next === defaultTab ? null : next, cat: null, id: null, fp: null })}
      items={[{ id: "exposed", label: L("노출된 Credential", "Exposed credentials"), value: counts.exposed, icon: "alert", tone: "red" },
        { id: "removed", label: L("제거 확인된 노출", "Removed exposures"), value: counts.removed, icon: "checkCircle", tone: "green" },
        { id: "all", label: L("전체 Credential", "All credentials"), value: counts.all, icon: "key", tone: "blue" },
        { id: "vault", label: L("Vault 보관", "Stored in Vault"), value: counts.vault, icon: "vault", tone: "green" }]} />
    <Tabs value={cat} label={L("Credential 유형", "Credential type")} onChange={next => set({ cat: next === "all" ? null : next })}
      items={(["all", "token", "apikey", "cloud", "other"] as const).map(kind => ({ id: kind, label: kind === "all" ? L("전체", "All") : kindLabel(kind, L), count: catCount(kind) }))} />
    <Card className="list-card">
      <div className="list-tools">
        <SearchBox id="cred-search" value={q} onChange={value => set({ q: value || null })} label={L("Credential 검색", "Search credentials")}
          placeholder={L("이름·식별자·노출 위치로 검색", "Search by name, identifier or location")} />
        <div className="tool-btns">
          <button type="button" className="ghost-btn" onClick={event => viewsMenu.open(event.currentTarget)}><Ic name="star" size={15} /><span className="clip">{L("저장된 보기", "Saved views")}</span></button>
          <button type="button" className="icon-btn bordered" aria-label={L("열 설정", "Columns")} data-tip={L("열 설정", "Columns")} onClick={event => colsMenu.open(event.currentTarget)}><Ic name="columns" size={17} /></button>
          <button type="button" className="icon-btn bordered" aria-label={L("내보내기", "Export")} data-tip={L("CSV 내보내기", "Export CSV")} onClick={exportCsv} disabled={!rows.length}><Ic name="download" size={17} /></button>
          <button type="button" className="ghost-btn" onClick={clearFilters} data-tip={nFilters ? L("필터 모두 지우기", "Clear all filters") : undefined}>
            <Ic name="filter" size={15} />{L("필터", "Filters")} {nFilters ? <><span className="filter-count">{nFilters}</span><Ic name="xCircle" size={15} /></> : null}
          </button>
        </div>
      </div>
      <div className="chips-row">
        {FILTER_KEYS.map(key => {
          const n = filters[key]?.length ?? 0;
          return <FilterChip key={key} icon={FDEF[key].icon} label={FDEF[key].label} count={n}
            onOpen={anchor => { setFilterKey(key); setFilterQ(""); filterMenu.open(anchor); }} onClear={() => set({ [`f.${key}`]: null })} />;
        })}
      </div>
      {nFilters || q ? <div className="applied">
        {hideFP ? <span className="applied-chip"><span className="clip">{L("오탐 제외", "False positives hidden")}</span>
          <button type="button" onClick={() => set({ fp: "1" })} aria-label={L("오탐 제외 해제", "Show false positives")}><Ic name="close" size={13} /></button></span> : null}
        {check ? <span className="applied-chip"><span className="clip">{L("점검 항목: ", "Check: ")}{CHECK_BY[check].title(L)}</span>
          <button type="button" onClick={() => set({ check: null })} aria-label={L("점검 항목 필터 해제", "Clear check filter")}><Ic name="close" size={13} /></button></span> : null}
        {activeFilters.map(key => <span className="applied-chip" key={key}><span className="clip">{FDEF[key].label}: {filters[key]!.map(v => FDEF[key].name(v)).join(", ")}</span>
          <button type="button" onClick={() => set({ [`f.${key}`]: null })} aria-label={L("필터 해제", "Clear filter")}><Ic name="close" size={13} /></button></span>)}
        {q ? <span className="applied-chip"><span className="clip">{L("검색: ", "Search: ")}{q}</span>
          <button type="button" onClick={() => set({ q: null })} aria-label={L("검색 지우기", "Clear search")}><Ic name="close" size={13} /></button></span> : null}
        <button type="button" className="link-btn" onClick={() => setSaveView(check ? CHECK_BY[check].title(L) : L("새 보기", "New view"))}>{L("보기로 저장", "Save as view")}</button>
      </div> : null}
      <div className="table-wrap" id="list-scroll">
        <table className="tbl">
          <thead><tr>{cols.map(col => {
            const index = sort.findIndex(s => s.key === col.key);
            return <th key={col.key} className={col.size} aria-sort={index === 0 ? (sort[0].dir === "asc" ? "ascending" : "descending") : undefined}>
              <span className="th-in"><button type="button" onClick={() => onSort(col.key)}>{colLabel[col.key]}
                {index >= 0 ? <><Ic name={sort[index].dir === "asc" ? "up" : "down"} size={13} /><sup>{index + 1}</sup></> : null}</button>
                {col.key === "risk" ? <InfoTip text={L("노출 정도와 악용 가능성 근거로 정합니다. 상세의 위험 분석에서 규칙을 볼 수 있습니다.", "Set from exposure and misuse evidence. See the rules under Risk analysis in the detail panel.")} /> : null}</span>
            </th>;
          })}</tr></thead>
          <tbody>
            {shown.map(c => <tr key={c.id} tabIndex={0} aria-selected={selected === c.id}
              onClick={() => setParams({ id: c.id, dtab: null })} onKeyDown={event => { if (event.key === "Enter") setParams({ id: c.id, dtab: null }); }}>
              {cols.map(col => cell(c, col.key))}
            </tr>)}
            {!shown.length ? <EmptyRow colSpan={cols.length}>{all.length ? L("조건에 맞는 Credential이 없습니다. 필터를 줄여 보세요.", "No credentials match. Try removing some filters.") : L("아직 수집된 Credential이 없습니다.", "No credentials collected yet.")}</EmptyRow> : null}
          </tbody>
        </table>
      </div>
      <Pager page={Math.min(page, pages - 1)} pages={pages} size={prefs.size} total={rows.length} onPage={next => setParams({ page: next ? String(next) : null })}
        onSize={size => { savePrefs({ ...prefs, size }); setParams({ page: null }); }} />
    </Card>

    {filterMenu.anchor && filterKey ? <Menu anchor={filterMenu.anchor} onClose={filterMenu.close} restore={filterMenu.opener} label={FDEF[filterKey].label}>
      <label className="menu-search"><Ic name="search" size={15} /><span className="sr">{L("검색", "Search")}</span>
        <input value={filterQ} onChange={event => setFilterQ(event.target.value)} placeholder={L("검색", "Search")} /></label>
      {filterValues(filterKey).map(([value, count]) => <MenuItem key={value} checked={(filters[filterKey] ?? []).includes(value)} end={<span className="num">{count}</span>}
        onSelect={() => toggleFilter(filterKey, value)}>
        {FDEF[filterKey].logo && value !== "none" ? <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><Logo id={value} size={20} />{FDEF[filterKey].name(value)}</span> : FDEF[filterKey].name(value)}
      </MenuItem>)}
      {filters[filterKey]?.length ? <><MenuSep /><MenuItem className="pri" onSelect={() => { set({ [`f.${filterKey}`]: null }); filterMenu.close(); }}>{L("선택 해제", "Clear selection")}</MenuItem></> : null}
    </Menu> : null}

    {viewsMenu.anchor ? <Menu anchor={viewsMenu.anchor} onClose={viewsMenu.close} restore={viewsMenu.opener} label={L("저장된 보기", "Saved views")}>
      <MenuLabel>{L("기본 보기", "Default views")}</MenuLabel>
      <MenuItem icon="star" onSelect={() => { viewsMenu.close(); applyView({ name: "", filters: {}, check: null, q: "", tab: defaultTab, cat: "all" }); }}>{L("기본 보기", "Default")}</MenuItem>
      <MenuItem icon="star" onSelect={() => { viewsMenu.close(); applyView({ name: "", filters: { vis: ["public"] }, check: "active", q: "", tab: "exposed", cat: "all" }); }}>{L("공개 노출 · 활성", "Public · active")}</MenuItem>
      <MenuSep /><MenuLabel>{L("저장한 보기", "Saved views")}</MenuLabel>
      {prefs.views.length ? prefs.views.map((view, index) => <MenuItem key={`${view.name}:${index}`} icon="star"
        end={<span role="button" tabIndex={0} aria-label={L("보기 삭제", "Delete view")} onClick={event => { event.stopPropagation(); savePrefs({ ...prefs, views: prefs.views.filter((_, i) => i !== index) }); }}><Ic name="close" size={13} /></span>}
        onSelect={() => { viewsMenu.close(); applyView(view); }}>{view.name}</MenuItem>)
        : <div className="menu-item" aria-disabled="true"><span className="mi-text">{L("아직 없습니다. 필터를 고르고 '보기로 저장'을 누르세요.", "None yet. Pick filters and click Save as view.")}</span></div>}
    </Menu> : null}

    {colsMenu.anchor ? <Menu anchor={colsMenu.anchor} onClose={colsMenu.close} restore={colsMenu.opener} label={L("열 설정", "Columns")}>
      <MenuLabel>{L("표시할 열", "Columns to show")}</MenuLabel>
      {COLS.filter(col => col.key !== "name").map(col => <MenuItem key={col.key} checked={!prefs.hidden.includes(col.key)}
        onSelect={() => savePrefs({ ...prefs, hidden: prefs.hidden.includes(col.key) ? prefs.hidden.filter(k => k !== col.key) : [...prefs.hidden, col.key] })}>{colLabel[col.key]}</MenuItem>)}
    </Menu> : null}

    {saveView !== null ? <SaveViewModal initial={saveView} onClose={() => setSaveView(null)} onSave={viewName => {
      savePrefs({ ...prefs, views: [...prefs.views, { name: viewName, filters, check, q, tab, cat }].slice(-30) });
      setSaveView(null);
      toast(L(`'${viewName}' 보기를 저장했습니다.`, `Saved view '${viewName}'.`));
    }} /> : null}

    {open ? <CredentialDrawer key={open.id} c={open} session={session} typeName={typeName(open)} name={name(open)} tab={route.params.get("dtab")}
      setTab={next => setParams({ dtab: next === "overview" ? null : next })} onClose={() => setParams({ id: null, dtab: null })} go={go} records={all} /> : null}
    {selected && !open && records.data ? <MissingSelection onClose={() => setParams({ id: null, dtab: null })} /> : null}
    {issued}
  </>;
}

function SaveViewModal({ initial, onClose, onSave }: { initial: string; onClose: () => void; onSave: (name: string) => void }) {
  const L = useL();
  const [value, setValue] = useState(initial);
  return <Modal onClose={onClose} labelledBy="save-view-title" size="narrow">
    <h2 id="save-view-title">{L("보기로 저장", "Save as view")}</h2>
    <TextField label={L("보기 이름", "View name")} value={value} onChange={setValue} autoFocus maxLength={60} />
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose}>{L("취소", "Cancel")}</button>
      <button type="button" className="primary-btn" disabled={!value.trim()} onClick={() => onSave(value.trim())}>{L("저장", "Save")}</button>
    </div>
  </Modal>;
}

function MissingSelection({ onClose }: { onClose: () => void }) {
  const L = useL();
  const toast = useToast();
  useEffect(() => { toast(L("선택한 Credential을 찾을 수 없습니다.", "The selected credential was not found."), "bad"); onClose(); }, [L, onClose, toast]);
  return null;
}
