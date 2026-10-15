"use client";

/* Metadata coverage: for each credential type an inventory lists, which key metadata the provider's
 * API gives (as the provider module declares it in the connection catalog), why a field can be empty,
 * how much of each field the collected tokens fill, and how the type is collected. */

import { type ReactNode, useEffect, useMemo, useRef, useState } from "react";

import { useLocale } from "@/components/locale";
import { reasonText, useApi } from "@/console/data";
import { Ic, Tick } from "@/console/icons";
import { Drawer, Menu, MenuLabel, MenuSep, useMenu } from "@/console/layer";
import { Logo } from "@/console/logos";
import { type CredentialRecord, creatorLabel, iamPolicyLabel, lastUseGap, RECORDS_PATH, type RecordsResponse } from "@/console/records";
import type { ViewProps } from "@/console/shell";
import { fmtDay, rel, type Say, useL } from "@/console/text";
import { Card, cls, DTabs, ErrorLine, Fact, Facts, FilterChip, InfoTip, Loading, PageHead, verifyLabel } from "@/console/ui";
import { CreatorSummary } from "@/console/views/credentials/cells";
import { IAMPolicySummary } from "@/console/views/credentials/permissions";
import { methodShort } from "@/console/views/integrations/copy";
import { GitHubCollections } from "@/console/views/integrations/github-export";
import {
  type Catalog, CATALOG_PATH, CONNECTIONS_PATH, type Descriptor, type Health, HEALTH_PATH, healthOf, INVENTORY_FIELDS,
  type InventoryField, type InventoryType, issuerProvider, label, lastRun, type ProviderConnection, scheduleLabel,
} from "@/console/views/integrations/model";

type State = "yes" | "part" | "no";
const STATE_OF: Record<string, State> = { Y: "yes", P: "part", N: "no" };
type Row = { key: string; d: Descriptor; t: InventoryType };
type Tab = "fields" | "tokens" | "method";

const FIELD_TEXT: Record<InventoryField, { key: string; name: [string, string]; type: [string, string]; about: [string, string] }> = {
  id: { key: "id", name: ["ID", "ID"], type: ["문자열", "String"], about: ["공급자가 붙인 고유 번호입니다. 다시 수집해도 같은 토큰을 한 건으로 묶는 기준입니다.", "The provider's unique ID. It keeps the same token as one record across runs."] },
  name: { key: "name", name: ["이름", "Name"], type: ["문자열", "String"], about: ["사람이 붙인 이름이나 설명입니다. 담당자가 무엇인지 알아보는 첫 단서입니다.", "The name or note someone gave it. The first clue for owners."] },
  created: { key: "created_at", name: ["생성일", "Created"], type: ["날짜", "Date"], about: ["발급된 날짜입니다. 오래된 토큰을 찾는 데 씁니다.", "When it was issued. Used to find old tokens."] },
  expires: { key: "expires_at", name: ["만료일", "Expires"], type: ["날짜", "Date"], about: ["쓸 수 없게 되는 날짜입니다. 만료일 없는 토큰을 가려냅니다.", "When it stops working. Flags tokens with no expiry."] },
  scopes: { key: "scopes", name: ["권한", "Scopes"], type: ["목록", "List"], about: ["공급자가 보고한 범위·제한·정책 요약입니다. 실제 접근 성공이나 최종 유효 권한과는 구분합니다.", "Provider-reported scopes, restrictions and policy summaries; distinct from successful access or effective permissions."] },
  creator: { key: "created_by", name: ["생성자", "Created by"], type: ["사람·신원", "Person/identity"], about: ["목록 또는 정확히 연결된 생성 감사 기록의 신원입니다. 소유자·대응 담당자와 다를 수 있습니다.", "Identity explicitly reported by the listing or linked creation audit event; may differ from the owner and responder."] },
  owner: { key: "owner", name: ["소유자", "Owner"], type: ["사람·계정", "Person/account"], about: ["토큰이 묶인 사용자·봇·서비스 계정입니다.", "The user, bot or service account it belongs to."] },
  last_used: { key: "last_used_at", name: ["마지막 사용", "Last used"], type: ["날짜", "Date"], about: ["공급자 보고 또는 수집한 로그·사용량의 마지막 관측입니다. 빈 값은 미사용을 뜻하지 않습니다.", "Last provider-reported or collected log/metric observation. A missing value does not establish non-use."] },
  state: { key: "state", name: ["상태", "Status"], type: ["값", "Enum"], about: ["활성·폐기·만료 여부입니다.", "Whether it is active, revoked or expired."] },
};
const STATE_NAME: Record<State, [string, string]> = { yes: ["지원", "Supported"], part: ["일부", "Partial"], no: ["미지원", "Unsupported"] };
const STATE_TIP: Record<State, [string, string]> = {
  yes: ["공급자 API가 이 값을 줍니다.", "The provider API returns this value."],
  part: ["조건이 맞을 때만 줍니다(권한·요금제·감사 로그 등).", "Returned only under some conditions (permissions, plan, audit logs)."],
  no: ["현재 수집 경로에서 지원하지 않습니다. 공급자 API와 구현의 제한은 항목별 사유를 확인하세요.", "Not supported by the current collection path; see the field reason for API and implementation limits."],
};

export const stateAt = (t: InventoryType, i: number): State => STATE_OF[t.support[i]] ?? "no";
export const counts = (t: InventoryType) => {
  const out = { yes: 0, part: 0, no: 0 };
  INVENTORY_FIELDS.forEach((_, i) => { out[stateAt(t, i)]++; });
  return out;
};

function why(t: InventoryType, field: InventoryField, L: Say) {
  const reason = t.reasons[field];
  return reason ? L(reason[0], reason[1]) : L(...STATE_TIP[stateAt(t, INVENTORY_FIELDS.indexOf(field))]);
}

/** A collected token's value for one key field, or null when it carries none. */
export function valueOf(c: CredentialRecord, field: InventoryField, L: Say, locale: "ko" | "en"): string | null {
  switch (field) {
    case "id": {
      const id = c.issued?.object_id ? c.issued.object_id.split(":").pop() || c.issued.object_id : null;
      // A key whose ID is its own identifier (an AWS access key ID) shows masked, as the list shows it.
      return id && c.hint && id.length > 8 && c.hint.startsWith(id.slice(0, 4)) && c.hint.endsWith(id.slice(-4)) ? c.hint : id;
    }
    case "name": return c.name;
    case "created": return c.created_at ? fmtDay(c.created_at, locale) : null;
    case "expires": return c.expiry === "none" ? L("만료일 없음", "No expiry") : c.expires_at ? fmtDay(c.expires_at, locale) : null;
    case "scopes": return c.scopes?.length ? c.scopes.map(scope => scope.name).join(", ")
      : c.issued?.iam_policies?.status === "COMPLETE" || c.issued?.iam_policies?.policy_names.length ? iamPolicyLabel(c, L) : null;
    case "creator": return c.issued?.provider === "aws_iam" ? c.issued.creator?.arn ?? null : c.issued?.creator_name ?? null;
    case "owner": return c.issuer?.name ?? null;
    case "last_used": return c.last_used ? `${rel(c.last_used.at, locale)}${c.last_used.basis === "METRIC_INTERVAL"
      ? L(" · 사용량 관측 구간", " · observed metric interval") : c.last_used.basis === "AUDIT_OBSERVED"
      ? L(" · 수집된 감사 로그 기준", " · collected audit evidence") : ""}` : null;
    case "state": return c.verification.state !== "unknown" ? verifyLabel(c.verification.state, L, c.verification.basis) : null;
  }
}

export function fieldDisplay(c: CredentialRecord, t: InventoryType, field: InventoryField, L: Say, locale: "ko" | "en") {
  // A known absence (IAM long-term keys have no expiry) is more precise than unsupported.
  if (field === "expires" && c.expiry === "none") return L("만료일 없음", "No expiry");
  if (field === "creator" && c.issued?.provider === "aws_iam") return creatorLabel(c, L);
  if (stateAt(t, INVENTORY_FIELDS.indexOf(field)) === "no") return why(t, field, L);
  if (field === "scopes" && !c.scopes?.length && c.issued?.provider === "aws_iam") return iamPolicyLabel(c, L);
  if (field === "last_used" && !c.last_used) return lastUseGap(c, L) ?? L("공급자가 값을 제공하지 않음", "Not reported by the provider");
  // A partly supported field without a value says when it has one (an option to turn on, a log to collect).
  return valueOf(c, field, L, locale) ?? (t.reasons[field] ? why(t, field, L) : L("공급자가 값을 제공하지 않음", "Not reported by the provider"));
}

function Cell({ t, i, big }: { t: InventoryType; i: number; big?: boolean }) {
  const L = useL();
  const field = INVENTORY_FIELDS[i], state = stateAt(t, i);
  const tip = `${L(...FIELD_TEXT[field].name)} · ${L(...STATE_NAME[state])} — ${why(t, field, L)}`;
  if (state === "yes") return <span className="mdc yes" data-tip={tip}><Ic name="checkCircle" size={big ? 16 : 17} />{big ? <span>{L("지원", "Supported")}</span> : <span className="sr">{L("지원", "Supported")}</span>}</span>;
  if (state === "part") return <span className="mdc part" data-tip={tip}><Ic name="halfCircle" size={16} /><span>{L("일부", "Partial")}</span></span>;
  return <span className="mdc no" data-tip={tip}>{L("미지원", "Unsupported")}</span>;
}

export function Metadata({ route, setParams, go, can }: ViewProps) {
  const L = useL();
  const locale = useLocale();
  const catalog = useApi<Catalog>(CATALOG_PATH);
  const connections = useApi<ProviderConnection[]>(CONNECTIONS_PATH, { every: 60_000 });
  const records = useApi<RecordsResponse>(RECORDS_PATH, { every: 60_000 });
  const health = useApi<Health>(HEALTH_PATH, { every: 60_000 });
  const svc = route.params.get("svc") ?? "all";
  const q = route.params.get("q") ?? "";
  const shownFields = (route.params.get("f.fields") ?? "").split(",").filter((f): f is InventoryField => (INVENTORY_FIELDS as readonly string[]).includes(f));
  const states = (route.params.get("f.states") ?? "").split(",").filter((s): s is State => s === "yes" || s === "part" || s === "no");
  const selected = route.params.get("id");
  const tab = (["fields", "tokens", "method"] as const).find(item => item === route.params.get("dtab")) ?? "fields";
  const [query, setQuery] = useState(q);
  const menu = useMenu();
  const [menuKey, setMenuKey] = useState<"fields" | "states">("fields");
  useEffect(() => { setQuery(q); }, [q]);
  useEffect(() => {
    const timer = window.setTimeout(() => { if (query !== q) setParams({ q: query || null }); }, 250);
    return () => window.clearTimeout(timer);
  }, [query, q, setParams]);

  const all = useMemo<Row[]>(() => (catalog.data?.providers ?? []).flatMap(d =>
    (d.purposes.inventory?.types ?? []).map(t => ({ key: `${d.provider}:${t.id}`, d, t }))), [catalog.data]);
  const visible = shownFields.length ? INVENTORY_FIELDS.filter(f => shownFields.includes(f)) : [...INVENTORY_FIELDS];
  const active = useMemo(() => new Map((connections.data ?? []).filter(c => c.status === "ACTIVE" && c.plans.inventory)
    .map(c => [c.provider, c] as const)), [connections.data]);
  const tokens = useMemo(() => {
    const byType = new Map<string, CredentialRecord[]>();
    for (const c of records.data?.items ?? []) {
      if (!c.issued?.type) continue;
      const key = `${issuerProvider(c.issued.provider)}:${c.issued.type}`;
      byType.set(key, [...(byType.get(key) ?? []), c]);
    }
    // A type another provider's collections list (a Microsoft connection's Azure DevOps PATs) counts those.
    for (const { key, d, t } of all) {
      if (byType.has(key)) continue;
      const listed = (t.match ?? []).flatMap(rule => [rule.provider ?? []].flat()).map(issuerProvider).filter(provider => provider !== d.provider);
      const found = listed.flatMap(provider => byType.get(`${provider}:${t.id}`) ?? []);
      if (found.length) byType.set(key, found);
    }
    return byType;
  }, [records.data, all]);

  if (catalog.error) return <><PageHead title={L("메타데이터 수집 현황", "Metadata coverage")} /><ErrorLine onRetry={catalog.reload}>{reasonText(catalog.error, L)}</ErrorLine></>;
  if (!catalog.data) return <><PageHead title={L("메타데이터 수집 현황", "Metadata coverage")} /><Loading /></>;

  const matches = (row: Row, skipStates = false) => {
    if (svc !== "all" && row.d.provider !== svc) return false;
    const needle = q.trim().toLowerCase();
    if (needle && !`${label(row.t, L)} ${label(row.d, L)} ${row.t.label}`.toLowerCase().includes(needle)) return false;
    if (!skipStates && states.length) return visible.some(f => states.includes(stateAt(row.t, INVENTORY_FIELDS.indexOf(f))));
    return true;
  };
  const rows = all.filter(row => matches(row));
  const scoped = all.filter(row => svc === "all" || row.d.provider === svc);
  const total = { yes: 0, part: 0, no: 0 }, missing = new Map<InventoryField, number>();
  scoped.forEach(row => INVENTORY_FIELDS.forEach((field, i) => {
    const state = stateAt(row.t, i);
    total[state]++;
    if (state === "no") missing.set(field, (missing.get(field) ?? 0) + 1);
  }));
  const cells = scoped.length * INVENTORY_FIELDS.length;
  const worst = [...missing.entries()].sort((a, b) => b[1] - a[1])[0];
  const collected = scoped.reduce((sum, row) => sum + (tokens.get(row.key)?.length ?? 0), 0);
  // A provider collects when a connection runs its inventory or its tokens are already listed.
  const collecting = (provider: string) => active.has(provider) || all.some(row => row.d.provider === provider && (tokens.get(row.key)?.length ?? 0) > 0);
  const notConnected = scoped.filter(row => !collecting(row.d.provider)).length;
  const services = [...new Map(all.map(row => [row.d.provider, row.d])).values()];
  const set = (params: Record<string, string | null>) => setParams(params);
  const toggle = (key: "fields" | "states", value: string) => {
    const current = key === "fields" ? shownFields : states;
    const next = current.includes(value as never) ? current.filter(item => item !== value) : [...current, value];
    set({ [`f.${key}`]: next.length ? next.join(",") : null });
  };

  const tiles: { label: string; value: ReactNode; icon: "key" | "checkCircle" | "minusCircle" | "download"; tone: string; tip: string }[] = [
    { label: L("토큰 종류", "Token types"), value: scoped.length, icon: "key", tone: "t-blue",
      tip: notConnected ? L(`아직 연동하지 않은 서비스의 토큰 종류 ${notConnected}종을 포함합니다.`, `Includes ${notConnected} token types from services not connected yet.`)
        : L("모두 연동된 서비스의 토큰 종류입니다.", "All from connected services.") },
    { label: L("대표 메타데이터 지원", "Key metadata supported"), value: `${cells ? Math.round(total.yes / cells * 100) : 0}%`, icon: "checkCircle", tone: "t-green",
      tip: L(`대표 메타데이터 9개 기준 · 지원 ${total.yes} · 일부 ${total.part} · 미지원 ${total.no}`, `Across the 9 key fields · ${total.yes} supported · ${total.part} partial · ${total.no} unsupported`) },
    { label: L("가장 많이 빠지는 항목", "Most often missing"), value: worst ? L(...FIELD_TEXT[worst[0]].name) : "—", icon: "minusCircle", tone: "t-amber",
      tip: worst ? L(`${FIELD_TEXT[worst[0]].name[0]} · 토큰 종류 ${worst[1]}종에서 미지원`, `${FIELD_TEXT[worst[0]].name[1]} · unsupported in ${worst[1]} token types`) : L("미지원 항목이 없습니다.", "Nothing is unsupported.") },
    { label: L("수집한 토큰", "Tokens collected"), value: records.data ? collected : "—", icon: "download", tone: "t-violet",
      tip: L("발급 목록에서 수집한 토큰 수입니다.", "Tokens collected from issuance inventories.") },
  ];

  const row = selected ? all.find(item => item.key === selected) : undefined;

  return <>
    <PageHead title={L("메타데이터 수집 현황", "Metadata coverage")} meta={L("토큰 종류별로 수집하는 메타데이터", "Metadata collected per token type")} />
    <ServicePills services={services} all={all} collecting={collecting} value={svc} onChange={value => set({ svc: value === "all" ? null : value })} />
    <div className="tiles md-tiles">
      {tiles.map(tile => <div className="tile md-tile" tabIndex={0} key={tile.label} data-tip={tile.tip}>
        <span className={`tile-ic ${tile.tone}`}><Ic name={tile.icon} size={19} /></span>
        <span className="tile-text"><span className="tile-label" style={{ display: "block" }}>{tile.label}</span>
          <span className="tile-value num" style={{ display: "block" }}>{tile.value}<Ic name="info" size={13} className="tile-i" /></span></span>
      </div>)}
    </div>
    <Card className="list-card md-card">
      <div className="list-tools">
        <label className="search"><Ic name="search" size={17} /><span className="sr">{L("토큰 종류 검색", "Search token types")}</span>
          <input id="md-search" placeholder={L("토큰 종류·서비스로 검색", "Search by token type or service")} value={query} onChange={event => setQuery(event.target.value)} /></label>
        <div className="md-legend">{(["yes", "part", "no"] as State[]).map(state => <span key={state} data-tip={L(...STATE_TIP[state])}>
          {state === "yes" ? <span className="mdc yes"><Ic name="checkCircle" size={15} /></span> : state === "part" ? <span className="mdc part"><Ic name="halfCircle" size={15} /></span>
            : <span className="mdc no">{L("미지원", "No")}</span>}{L(...STATE_NAME[state])}</span>)}</div>
      </div>
      <div className="chips-row">
        {([["fields", "columns", L("메타데이터 항목", "Metadata fields"), shownFields.length], ["states", "halfCircle", L("지원 상태", "Support status"), states.length]] as const).map(([key, icon, name, n]) =>
          <FilterChip key={key} icon={icon} label={name} count={n}
            onOpen={anchor => { setMenuKey(key); menu.open(anchor); }} onClear={() => set({ [`f.${key}`]: null })} />)}
      </div>
      <div className="table-wrap"><table className="tbl md-tbl">
        <thead><tr>
          <th>{L("토큰 종류", "Token type")}</th>
          {visible.map(field => <th className="mdh" key={field}><span className="th-in">{L(...FIELD_TEXT[field].name)}<InfoTip text={L(...FIELD_TEXT[field].about)} /></span></th>)}
          <th className="md-strip">{L("지원 현황", "Support")}</th><th className="col-sm">{L("수집", "Collected")}</th>
        </tr></thead>
        <tbody>
          {rows.length ? rows.map(item => {
            const c = counts(item.t), n = tokens.get(item.key)?.length ?? 0, on = collecting(item.d.provider);
            const edition = item.t.editions?.length ? item.d.editions.filter(e => item.t.editions!.includes(e.id)).map(e => label(e, L)).join(", ") : "";
            return <tr key={item.key} tabIndex={0} aria-selected={selected === item.key} onClick={() => set({ id: item.key, dtab: null })}
              onKeyDown={event => { if (event.key === "Enter") set({ id: item.key, dtab: null }); }}>
              <td><div className="md-type"><Logo id={item.d.provider} size={30} /><div className="md-type-text"><b>{label(item.t, L)}</b>
                <span className="ig-sub">{label(item.d, L)}{edition ? ` · ${edition}` : ""}{on ? "" : ` · ${L("미연동", "Not connected")}`}</span></div></div></td>
              {visible.map(field => <td className="mdc-td" key={field}><Cell t={item.t} i={INVENTORY_FIELDS.indexOf(field)} /></td>)}
              <td className="md-strip"><div className="md-strip-cells">{visible.map(field => {
                const state = stateAt(item.t, INVENTORY_FIELDS.indexOf(field));
                return <span key={field} className={`md-sq ${state}`} data-tip={`${L(...FIELD_TEXT[field].name)} · ${L(...STATE_NAME[state])}`} />;
              })}</div><span className="md-strip-n">{L(`미지원 ${c.no}`, `${c.no} unsupported`)}</span></td>
              <td className="col-sm md-sum"><span className="num">{L(`지원 ${c.yes}/9`, `${c.yes}/9`)}</span><br />
                {on ? item.t.snapshot_only ? L("스냅샷별 관측", "Snapshot observations") : L(`${n}건 수집`, `${n} collected`) : <span className="subtle">{L("미연동", "Not connected")}</span>}</td>
            </tr>;
          }) : <tr><td colSpan={visible.length + 3} className="empty-row">{L("조건에 맞는 토큰 종류가 없습니다. 필터를 줄여 보세요.", "No token types match. Try removing some filters.")}</td></tr>}
        </tbody>
      </table></div>
      <div className="list-foot"><span>{L(`${rows.length}종`, `${rows.length} types`)}</span><span>{L("줄을 누르면 자세히 봅니다", "Select a row for details")}</span></div>
    </Card>

    {menu.anchor ? <Menu anchor={menu.anchor} onClose={menu.close} restore={menu.opener} label={menuKey === "fields" ? L("메타데이터 항목", "Metadata fields") : L("지원 상태", "Support status")}>
      {menuKey === "fields" ? <>
        <MenuLabel>{L("표에 보일 항목", "Columns to show")}</MenuLabel>
        {INVENTORY_FIELDS.map(field => <button type="button" role="menuitemcheckbox" aria-checked={shownFields.includes(field)} className="menu-item" key={field} onClick={() => toggle("fields", field)}>
          <span className={shownFields.includes(field) ? "check on" : "check"}>{shownFields.includes(field) ? <Tick /> : null}</span>
          <span className="mi-text"><span>{L(...FIELD_TEXT[field].name)}</span><span className="person-sub">{L(...FIELD_TEXT[field].about)}</span></span></button>)}
      </> : <>
        <MenuLabel>{L("보이는 항목 중 하나라도 이 상태인 토큰 종류", "Token types with any visible field in this state")}</MenuLabel>
        {(["no", "part", "yes"] as State[]).map(state => {
          const n = all.filter(item => matches(item, true) && visible.some(f => stateAt(item.t, INVENTORY_FIELDS.indexOf(f)) === state)).length;
          return <button type="button" role="menuitemcheckbox" aria-checked={states.includes(state)} className="menu-item" key={state} onClick={() => toggle("states", state)}>
            <span className={states.includes(state) ? "check on" : "check"}>{states.includes(state) ? <Tick /> : null}</span>
            <span className="mi-text"><span>{L(...STATE_NAME[state])}</span><span className="person-sub">{L(...STATE_TIP[state])}</span></span><span className="end num">{n}</span></button>;
        })}
      </>}
      {(menuKey === "fields" ? shownFields : states).length ? <><MenuSep /><button type="button" className="menu-item pri" onClick={() => { set({ [`f.${menuKey}`]: null }); menu.close(); }}>{L("선택 해제", "Clear selection")}</button></> : null}
    </Menu> : null}

    {row ? <TypeDrawer row={row} tab={tab} conn={active.get(row.d.provider)} collecting={collecting(row.d.provider)} tokens={tokens.get(row.key) ?? []} health={health.data}
      onTab={value => set({ dtab: value === "fields" ? null : value })} onClose={() => set({ id: null, dtab: null })}
      onOpenToken={id => go("inventory", { id })}
      onIntegrate={() => { const conn = active.get(row.d.provider); go("sources", conn ? { edit: conn.id } : { connect: row.d.provider }); }}
      canIntegrate={can("sources")} locale={locale} /> : null}
  </>;
}

function ServicePills({ services, all, collecting, value, onChange }: {
  services: Descriptor[]; all: Row[]; collecting: (provider: string) => boolean; value: string; onChange: (value: string) => void;
}) {
  const L = useL();
  const scroller = useRef<HTMLDivElement>(null);
  const [edges, setEdges] = useState({ left: false, right: false });
  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const measure = () => setEdges({ left: el.scrollLeft > 2, right: el.scrollLeft + el.clientWidth < el.scrollWidth - 2 });
    measure();
    el.addEventListener("scroll", measure, { passive: true });
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    return () => { el.removeEventListener("scroll", measure); observer.disconnect(); };
  }, [services.length]);
  useEffect(() => {
    // Keep the chosen service in view after a reload or a narrow screen.
    scroller.current?.querySelector<HTMLElement>('[aria-pressed="true"]')?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [value]);
  const nudge = (direction: number) => { const el = scroller.current; if (el) el.scrollBy({ left: direction * Math.max(160, el.clientWidth * 0.7), behavior: "smooth" }); };
  const pills = [{ id: "all", d: null as Descriptor | null }, ...services.map(d => ({ id: d.provider, d }))];
  return <div className={cls("md-pills-wrap", edges.left && "can-l", edges.right && "can-r", !edges.left && !edges.right && "fits")}>
    <button type="button" className="md-pills-nav prev" onClick={() => nudge(-1)} disabled={!edges.left} aria-label={L("앞의 서비스 보기", "Previous services")}><Ic name="left" size={16} /></button>
    <div className="md-pills" ref={scroller} role="group" aria-label={L("서비스로 거르기", "Filter by service")}>
      {pills.map(pill => <button type="button" key={pill.id} className="md-pill" aria-pressed={value === pill.id} onClick={() => onChange(pill.id)}>
        {pill.d ? <Logo id={pill.d.provider} size={20} /> : <Ic name="grid" size={16} />}
        <span>{pill.d ? label(pill.d, L) : L("전체", "All")}</span>
        <span className="count num">{pill.d ? all.filter(row => row.d.provider === pill.id).length : all.length}</span>
        {pill.d && !collecting(pill.d.provider) ? <span className="md-pill-off" data-tip={L("아직 연동하지 않은 서비스입니다.", "Not connected yet.")}>{L("미연동", "Off")}</span> : null}
      </button>)}
    </div>
    <button type="button" className="md-pills-nav next" onClick={() => nudge(1)} disabled={!edges.right} aria-label={L("뒤의 서비스 보기", "More services")}><Ic name="right" size={16} /></button>
  </div>;
}

function TypeDrawer({ row, tab, conn, collecting, tokens, health, onTab, onClose, onOpenToken, onIntegrate, canIntegrate, locale }: {
  row: Row; tab: Tab; conn: ProviderConnection | undefined; collecting: boolean; tokens: CredentialRecord[]; health: Health | undefined;
  onTab: (tab: Tab) => void; onClose: () => void; onOpenToken: (id: string) => void; onIntegrate: () => void; canIntegrate: boolean; locale: "ko" | "en";
}) {
  const L = useL();
  const { d, t } = row;
  const c = counts(t);
  const method = conn ? d.auth_methods.find(item => item.id === conn.auth_method) : undefined;
  const last = conn ? lastRun(healthOf(conn, health?.items)) : null;
  const schedule = conn?.plans.inventory?.schedule_minutes;
  const permission = t.permission ? d.purposes.inventory?.permissions?.find(p => p.id === t.permission) : undefined;
  const tabs: { id: Tab; label: string; count?: number }[] = [
    { id: "fields", label: L("메타데이터 항목", "Metadata fields"), count: INVENTORY_FIELDS.length },
    { id: "tokens", label: t.snapshot_only ? L("관측 행", "Observed rows") : L("수집된 토큰", "Collected tokens"), count: t.snapshot_only ? undefined : tokens.length },
    { id: "method", label: L("수집 방법", "How it's collected") },
  ];
  const integrate = canIntegrate ? <button type="button" className={conn ? "ghost-btn" : "primary-btn"} onClick={onIntegrate}>
    <Ic name={conn ? "sliders" : "plug"} size={16} />{conn ? L("연동 설정 열기", "Open integration settings") : L("연동하기", "Connect")}</button> : null;

  let body: ReactNode;
  if (tab === "tokens") {
    body = t.snapshot_only && conn ? <GitHubCollections connections={conn.children} snapshotType={t.export_type} /> : tokens.length ? tokens.map(token => <section className="md-tok" key={token.id}>
      <div className="md-tok-head"><Logo id={token.provider} size={24} />
        <button type="button" className="link-btn" onClick={() => onOpenToken(token.id)}>{token.name || label(t, L)} <Ic name="right" size={14} /></button>
        {token.hint ? <span className="tag mono">{token.hint}</span> : null}</div>
      <dl className="md-kv">{INVENTORY_FIELDS.map((field, i) => {
        if (field === "name" && d.provider === "aws" && t.id === "access_key") return null;
        const state = stateAt(t, i);
        return <div key={field}><dt>{L(...FIELD_TEXT[field].name)}</dt>
          <dd className={state === "no" ? "subtle" : undefined}>{field === "scopes" && !token.scopes?.length && token.issued?.provider === "aws_iam"
            ? <IAMPolicySummary c={token} /> : field === "creator" && token.issued?.provider === "aws_iam"
              ? <CreatorSummary c={token} /> : fieldDisplay(token, t, field, L, locale)}</dd></div>;
      })}</dl>
    </section>) : <section className="card md-empty">
      <p>{collecting ? L("아직 이 종류로 수집된 토큰이 없습니다.", "No tokens of this type have been collected yet.") : L("서비스를 연동하면 이 종류의 토큰을 가져옵니다.", "Connect the service to collect tokens of this type.")}</p>
      {!conn ? integrate : null}
    </section>;
  } else if (tab === "method") {
    const gaps = INVENTORY_FIELDS.map((field, i) => ({ field, state: stateAt(t, i) })).filter(item => item.state !== "yes");
    body = <>
      <section className="card"><div className="card-head"><h3>{L("수집 정보", "Collection details")}</h3></div><div className="card-body">
        <Facts>
          <Fact label={L("연동 상태", "Integration")}>{conn ? L("연동됨", "Connected") : collecting ? L("수집 기록 있음", "Collected before") : L("미연동", "Not connected")}</Fact>
          <Fact label={L("연동 방식", "Method")}>{conn ? methodShort(method, L) : "—"}</Fact>
          {d.provider !== "github" ? <Fact label={L("수집 주기", "Schedule")}>{typeof schedule === "number" ? scheduleLabel(schedule, L) : "—"}</Fact> : null}
          <Fact label={L("필요 권한", "Permission needed")} tip={L("이 토큰 종류를 읽는 데 필요한 권한입니다.", "Permission needed to read this token type.")}>
            {permission ? <span className={cls("tag", /^[\x21-\x7e]+$/.test(permission.id) && permission.label === permission.id && "mono")}>{label(permission, L)}</span> : "—"}</Fact>
        </Facts>
        {t.description ? <p className="md-note">{L(t.description_ko ?? t.description, t.description)}</p> : null}
      </div></section>
      {d.provider === "github" && conn ? <section className="card"><div className="card-body"><GitHubCollections connections={conn.children} /></div></section> : null}
      {gaps.length ? <section className="card"><div className="card-head"><h3>{L("비어 있을 수 있는 항목", "Fields that may be empty")}</h3></div><div className="card-body">
        <ul className="md-gaps">{gaps.map(gap => <li key={gap.field}><b>{L(...FIELD_TEXT[gap.field].name)}</b> · {L(...STATE_NAME[gap.state])} — {why(t, gap.field, L)}</li>)}</ul>
      </div></section> : null}
      {integrate ? <section className="card"><div className="card-body md-actions">{integrate}</div></section> : null}
    </>;
  } else {
    body = <section className="card"><div className="card-head wrap"><h3>{L("대표 메타데이터", "Key metadata")}</h3>
      <span className="meta">{tokens.length ? L(`수집한 ${tokens.length}건 기준 채움 정도`, `Fill rate across ${tokens.length} collected`) : L("수집한 토큰 없음", "No tokens collected")}</span></div>
      <div className="card-body md-fields">{INVENTORY_FIELDS.map((field, i) => {
        const state = stateAt(t, i), filled = tokens.filter(token => valueOf(token, field, L, locale) !== null).length;
        const pct = tokens.length ? Math.round(filled / tokens.length * 100) : 0;
        return <div className={`md-field ${state}`} key={field}>
          <div className="mf-top"><span className="mono mf-name">{FIELD_TEXT[field].key}</span><span className="tag">{L(...FIELD_TEXT[field].type)}</span><Cell t={t} i={i} big /></div>
          <div className="mf-desc"><b>{L(...FIELD_TEXT[field].name)}</b> — {L(...FIELD_TEXT[field].about)}</div>
          {state !== "no" && tokens.length ? <div className="mf-fill"><span className="bar"><span style={{ width: `${pct}%` }} /></span>
            <span className="num">{L(`값 있음 ${filled}/${tokens.length}`, `${filled}/${tokens.length} filled`)}</span></div> : null}
          {state !== "yes" ? <div className="mf-why"><Ic name="info" size={14} /><span>{why(t, field, L)}</span></div> : null}
        </div>;
      })}</div></section>;
  }

  return <Drawer label={L(`${label(t, L)} 상세`, `${label(t, L)} details`)} onClose={onClose}>
    <div className="drawer-head">
      <div className="dh-top">
        <div className="dh-logo"><Logo id={d.provider} size={34} /></div>
        <div className="dh-main">
          <div className="md-crumb">{label(d, L)} › {L("발급 목록", "Inventory")} › {L("토큰 종류", "Token type")}</div>
          <h2 className="dh-title">{label(t, L)}</h2>
          <div className="dh-badges">
            <span className="tag">{L(`지원 ${c.yes} · 일부 ${c.part} · 미지원 ${c.no}`, `${c.yes} yes · ${c.part} partial · ${c.no} no`)}</span>
            <span className="tag">{conn ? `${L("연동됨 · ", "Connected · ")}${methodShort(method, L)}` : collecting ? L("수집 기록 있음", "Collected before") : L("미연동", "Not connected")}</span>
            {last ? <span className="tag">{L("마지막 수집 ", "Last run ")}{rel(last, locale)}</span> : null}
          </div>
        </div>
        <div className="dh-actions"><button type="button" className="icon-btn" aria-label={L("상세 닫기", "Close details")} data-tip={L("상세 닫기", "Close details")} onClick={onClose}><Ic name="panelClose" size={19} /></button></div>
      </div>
      <DTabs value={tab} items={tabs} onChange={onTab} label={L("상세 탭", "Detail tabs")} />
    </div>
    <div className="drawer-body" id="drawer-body">{body}</div>
  </Drawer>;
}
