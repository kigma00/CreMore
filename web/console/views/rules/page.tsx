"use client";

/* Detection rules: the detectors CreMore ships and the rules this organization wrote, in one list
 * with filters, sort and pages. A row opens its pattern in plain words and in pieces. An
 * organization rule is written, copied from any rule, tried on a sample in the browser, changed and
 * deleted here; turning a rule off leaves it out from the next scan. */

import { type CSSProperties, Fragment, type KeyboardEvent, type ReactNode, useEffect, useMemo, useState } from "react";

import { useLocale } from "@/components/locale";
import { reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic, type IconName } from "@/console/icons";
import { actorLabel } from "@/console/labels";
import { Menu, MenuItem, MenuLabel, MenuSep, Modal, useMenu, useToast } from "@/console/layer";
import { Logo, serviceName } from "@/console/logos";
import { exposureService } from "@/console/records";
import type { ViewProps } from "@/console/shell";
import { fmtDay, type Say, useL } from "@/console/text";
import { Card, cls, EmptyRow, ErrorLine, FilterChip, InfoTip, Loading, PageHead, type Risk, riskLabel, RiskTag, SearchBox, Switch } from "@/console/ui";
import * as rx from "@/console/views/rules/regex";
import { DashboardAPIError } from "@/lib/dashboard-api";
import { CONTENT_SOURCE_TYPES } from "@/lib/source-types";

export type Category = "token" | "apikey" | "secret" | "account" | "privkey" | "conn" | "webhook" | "other";
export const CATEGORIES: Category[] = ["token", "apikey", "secret", "account", "privkey", "conn", "webhook", "other"];
const TYPE_NAME: Record<Category, [string, string]> = {
  token: ["토큰", "Token"], apikey: ["API 키", "API key"], secret: ["시크릿", "Secret"], account: ["계정·비밀번호", "Account & password"],
  privkey: ["개인 키·인증서", "Private key & certificate"], conn: ["연결 문자열", "Connection string"], webhook: ["웹훅 URL", "Webhook URL"], other: ["기타", "Other"],
};
const TYPE_ABOUT: Record<Category, [string, string]> = {
  token: ["사람이나 봇 대신 API를 부르는 값입니다. PAT·봇 토큰·세션 토큰 등.", "Values that call APIs on behalf of a person or bot: PATs, bot tokens, session tokens."],
  apikey: ["서비스가 발급한 키 문자열입니다. 보통 계정이나 프로젝트 하나에 묶입니다.", "Key strings a service issues, usually tied to one account or project."],
  secret: ["앱·연동이 쓰는 비밀값입니다. 클라이언트 시크릿·서명 키 등.", "Secrets apps and integrations use: client secrets, signing keys."],
  account: ["아이디·비밀번호, 비밀번호 해시, URL 안의 계정 정보입니다.", "Usernames and passwords, password hashes, credentials inside URLs."],
  privkey: ["SSH·TLS·서명용 개인 키와 인증서입니다.", "Private keys and certificates for SSH, TLS or signing."],
  conn: ["DB·서비스 주소 안에 비밀값이 들어간 연결 문자열입니다.", "Connection strings with a secret inside the address."],
  webhook: ["주소만 알면 메시지를 보낼 수 있는 웹훅 URL입니다.", "Webhook URLs that let anyone with the address post messages."],
  other: ["위 분류에 들지 않는 값입니다.", "Values that fit none of the above."],
};
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
type Severity = typeof SEVERITIES[number];
const PINNED = ["github", "gitlab", "bitbucket", "aws", "gcp", "azure", "atlassian", "slack", "notion", "stripe", "sendgrid"];
const STRATEGY: Record<string, [string, string]> = {
  prefix: ["공급자가 공개한 고유 접두사와 길이로 찾습니다.", "Matches the provider's documented prefix and length."],
  label: ["설정 이름(예: DATADOG_API_KEY=) 바로 옆의 값을 찾습니다. 값 모양만으로는 구별하기 어려운 키에 씁니다.", "Finds the value right next to a config name (e.g. DATADOG_API_KEY=). Used for keys that can't be told apart by shape alone."],
  format: ["공급자가 공개한 값 형식으로 찾습니다.", "Matches the provider's documented value format."],
  "assignment context (quoted literal or bare value)": ["설정 이름 뒤에 따옴표로 묶었거나 그대로 적은 값을 찾습니다.", "Finds a quoted or bare value assigned to a config name."],
  "adjacent multipart assignment with exact token boundaries": ["나란히 적힌 여러 부분(예: 키 ID와 비밀 키)을 정확한 경계로 함께 찾습니다.", "Finds adjacent parts, such as a key ID and its secret, with exact boundaries."],
  "exact identifier boundaries; paired occurrences excluded": ["식별자를 정확한 경계로 찾고, 짝과 함께 적힌 경우는 짝 룰이 맡습니다.", "Finds the identifier with exact boundaries; occurrences next to their pair are left to the pair rule."],
  "AWS secret field with exact value boundaries; paired occurrences excluded": ["AWS 비밀 키 항목의 값을 정확한 경계로 찾고, 키 ID와 함께 적힌 경우는 짝 룰이 맡습니다.", "Finds the AWS secret key field's value with exact boundaries; occurrences next to a key ID are left to the pair rule."],
  "bounded labelled token; complete same-input session components linked separately": ["이름 붙은 토큰을 정해진 길이로 찾고, 같은 입력의 세션 구성요소는 따로 묶습니다.", "Finds a labelled token of bounded length; session components in the same input are linked separately."],
  "bounded secret shape": ["길이가 정해진 비밀값 모양으로 찾습니다.", "Matches a secret shape of bounded length."],
  "signed version and signature in one query": ["한 쿼리 문자열 안의 서명 버전과 서명을 함께 찾습니다.", "Finds a signed version and its signature in one query string."],
  "userinfo component": ["URL 안의 사용자 정보(아이디:비밀번호)를 찾습니다.", "Finds the user information (user:password) inside a URL."],
  "RFC 7617 base64(user:pass)": ["Basic 인증 값의 base64(아이디:비밀번호)를 찾습니다(RFC 7617).", "Finds base64(user:password) in a Basic authorization value (RFC 7617)."],
  "RFC 6750 bearer scheme": ["Bearer 인증 값의 토큰을 찾습니다(RFC 6750).", "Finds the token in a Bearer authorization value (RFC 6750)."],
  "bcrypt modular-crypt format": ["bcrypt 비밀번호 해시 형식으로 찾습니다.", "Matches the bcrypt password-hash format."],
};

export type Detector = {
  id: string; name: string; provider: string; credential_type: string; category: string; description: string; confidence: string;
  keywords: string[]; strategy: string; patterns: string[]; enabled: boolean; source_url?: string; switched_by?: string; switched_at?: string;
};
export type OrgRule = {
  id: string; name: string; description: string; enabled: boolean; keywords: string[]; pattern: string; severity: string; revision: number;
  scope_sources: string[]; include_globs: string[]; exclude_globs: string[]; exclude_words: string[]; provider_candidates: string[];
  category?: string | null; updated_by?: string | null; updated_at: string;
};
export type Rule = {
  id: string; builtin: boolean; name: string; desc: string; cat: string; type: Category; kw: string[]; patterns: string[]; on: boolean;
  detector?: Detector; org?: OrgRule;
};

const asCategory = (value: string | null | undefined): Category => (CATEGORIES as string[]).includes(value ?? "") ? value as Category : "other";

/** Organization rules first, then the shipped detectors, in the list's one shape. */
export function rulesOf(detectors: Detector[], org: OrgRule[]): Rule[] {
  return [
    ...org.map(r => ({ id: `custom-${r.id}`, builtin: false, name: r.name, desc: r.description, cat: r.provider_candidates[0] || "custom",
      type: asCategory(r.category), kw: r.keywords, patterns: [r.pattern], on: r.enabled, org: r })),
    ...detectors.map(d => ({ id: d.id, builtin: true, name: d.name, desc: d.description, cat: d.provider || "generic",
      type: asCategory(d.category), kw: d.keywords, patterns: d.patterns, on: d.enabled, detector: d })),
  ];
}

export function catLabel(p: string, L: Say) {
  if (p === "custom") return L("사내 자체 형식", "In-house format");
  if (p === "generic") return L("공통 형식", "Generic formats");
  if (p === "gcp") return "Google Cloud";
  if (p === "aws") return "AWS";
  return serviceName(p);
}

type FilterKey = "creator" | "type" | "cat" | "state";
const FILTER_KEYS: FilterKey[] = ["creator", "type", "cat", "state"];
type Filters = Partial<Record<FilterKey, string[]>>;
const FILTER_ICON: Record<FilterKey, IconName> = { creator: "users", type: "tag", cat: "grid", state: "checkCircle" };

export function filterValue(key: FilterKey, r: Rule): string {
  return key === "creator" ? (r.builtin ? "builtin" : "org") : key === "type" ? r.type : key === "cat" ? r.cat : r.on ? "on" : "off";
}

function filterName(key: FilterKey, value: string, L: Say): string {
  if (key === "creator") return value === "builtin" ? L("CreMore 기본", "CreMore built-in") : L("우리 조직", "Our organization");
  if (key === "type") return L(...TYPE_NAME[asCategory(value)]);
  if (key === "state") return value === "on" ? L("활성화", "Enabled") : L("비활성화", "Disabled");
  return catLabel(value, L);
}

export function matches(r: Rule, filters: Filters, q: string, L: Say, except?: FilterKey) {
  for (const key of FILTER_KEYS) {
    const chosen = filters[key];
    if (key !== except && chosen?.length && !chosen.includes(filterValue(key, r))) return false;
  }
  const needle = q.trim().toLowerCase();
  return !needle || `${r.name} ${r.id} ${catLabel(r.cat, L)} ${r.kw.join(" ")}`.toLowerCase().includes(needle);
}

type SortKey = "name" | "type" | "cat";

export function sortRules(rows: Rule[], key: SortKey, dir: "asc" | "desc", L: Say) {
  const sign = dir === "asc" ? 1 : -1;
  const value = (r: Rule): string | number => key === "cat" ? catLabel(r.cat, L).toLowerCase() : key === "type" ? CATEGORIES.indexOf(r.type) : r.name.toLowerCase();
  return [...rows].sort((a, b) => {
    if (a.builtin !== b.builtin) return a.builtin ? 1 : -1;
    const x = value(a), y = value(b);
    return x < y ? -sign : x > y ? sign : 0;
  });
}

const SCOPES = CONTENT_SOURCE_TYPES.map(type => type);
const SCOPE_NAME: Record<string, string> = { s3: "Amazon S3", gcp: "Cloud Storage", azure_blob: "Azure Blob Storage", azure_devops: "Azure DevOps" };
const scopeName = (type: string) => SCOPE_NAME[type] ?? serviceName(exposureService(type));

const safeUrl = (url: string | undefined) => url && /^https:\/\//i.test(url) ? url : null;
const hostOf = (url: string) => { try { return new URL(url).host; } catch { return url; } };

export function Rules({ route, setParams }: ViewProps) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const engine = useApi<{ detectors: Detector[] }>("detection-engine");
  const org = useApi<OrgRule[]>("rules");
  const p = route.params;
  const q = p.get("q") ?? "";
  const filters: Filters = Object.fromEntries(FILTER_KEYS.map(key => [key, (p.get(`f.${key}`) ?? "").split(",").filter(Boolean)]));
  const [sortKey, sortDir] = ((p.get("sort") ?? "name:asc").split(":") as [SortKey, "asc" | "desc"]);
  const size = [20, 50, 100].includes(Number(p.get("size"))) ? Number(p.get("size")) : 20;
  const [query, setQuery] = useState(q);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState<string | null>(null);
  const [modal, setModal] = useState<null | { kind: "edit"; mode: "regex" | "copy"; edit: Rule | null; from: Rule | null } | { kind: "delete"; rule: Rule }>(null);
  const filterMenu = useMenu();
  const [filterKey, setFilterKey] = useState<FilterKey>("creator");
  const [filterQ, setFilterQ] = useState("");
  useEffect(() => { setQuery(q); }, [q]);
  useEffect(() => {
    const timer = window.setTimeout(() => { if (query !== q) setParams({ q: query || null, page: null }); }, 250);
    return () => window.clearTimeout(timer);
  }, [query, q, setParams]);

  const all = useMemo(() => rulesOf(engine.data?.detectors ?? [], org.data ?? []), [engine.data, org.data]);
  // Shipped detectors with a documented prefix recognise a real value in a sample.
  const realShapes = useMemo(() => (engine.data?.detectors ?? []).filter(d => d.strategy === "prefix")
    .flatMap(d => d.patterns.map(pattern => rx.toJsRe(pattern)).filter((re): re is RegExp => re !== null)), [engine.data]);

  const title = L("탐지 룰 설정", "Detection rules");
  const meta = L("조직의 탐지 룰을 관리합니다", "Manage your organization's detection rules");
  if (engine.error || org.error) return <><PageHead title={title} meta={meta} />
    <ErrorLine onRetry={() => { engine.reload(); org.reload(); }}>{reasonText(engine.error || org.error, L)}</ErrorLine></>;
  if (!engine.data || !org.data) return <><PageHead title={title} meta={meta} /><Loading /></>;

  const set = (params: Record<string, string | null>) => setParams({ page: null, ...params });
  const rows = sortRules(all.filter(r => matches(r, filters, q, L)), sortKey, sortDir, L);
  const pages = Math.max(1, Math.ceil(rows.length / size));
  const page = Math.min(pages, Math.max(1, Number(p.get("page")) || 1));
  const shown = rows.slice((page - 1) * size, page * size);
  const off = all.filter(r => !r.on).length;
  const orgCount = all.filter(r => !r.builtin).length;
  const toggleFilter = (key: FilterKey, value: string) => {
    const current = filters[key] ?? [];
    const next = current.includes(value) ? current.filter(v => v !== value) : [...current, value];
    set({ [`f.${key}`]: next.length ? next.join(",") : null });
  };
  const only = (key: FilterKey, value: string) => set(Object.fromEntries(FILTER_KEYS.map(k => [`f.${k}`, k === key ? value : null])));
  const onSort = (key: SortKey) => set({ sort: sortKey === key ? `${key}:${sortDir === "asc" ? "desc" : "asc"}` : `${key}:asc` });
  const expand = (id: string) => setOpen(current => { const next = new Set(current); if (next.has(id)) next.delete(id); else next.add(id); return next; });

  const toggle = async (r: Rule) => {
    setBusy(r.id);
    try {
      if (r.builtin) {
        await send(`detection-engine/detectors/${encodeURIComponent(r.id)}`, "PUT", { enabled: !r.on });
        engine.replace({ ...engine.data!, detectors: engine.data!.detectors.map(d => d.id === r.id ? { ...d, enabled: !r.on } : d) });
      } else {
        const changed = await send<OrgRule>(`rules/${r.org!.id}`, "PUT", { enabled: !r.on });
        org.replace(org.data!.map(rule => rule.id === changed.id ? changed : rule));
      }
      toast(r.on ? L(`'${r.name}' 룰을 껐습니다. 다음 검사부터 쓰지 않습니다.`, `Disabled '${r.name}'. Skipped from the next scan.`)
        : L(`'${r.name}' 룰을 다시 켰습니다.`, `Enabled '${r.name}' again.`));
      saved();
    } catch (error) { toast(reasonText(error, L), "bad"); }
    finally { setBusy(null); }
  };

  const tiles: { id: string; label: string; value: number; icon: IconName; tone: string; tip: string; act: () => void }[] = [
    { id: "builtin", label: L("CreMore 기본 룰", "Built-in rules"), value: all.length - orgCount, icon: "shield", tone: "t-blue",
      tip: L("공급자 공개 문서를 기준으로 만든 기본 룰입니다. 누르면 이 룰만 봅니다.", "Built-in rules written from provider docs. Click to show only these."), act: () => only("creator", "builtin") },
    { id: "org", label: L("우리 조직 룰", "Our rules"), value: orgCount, icon: "pencil", tone: "t-violet",
      tip: L("사내에서 발급하는 토큰·키 형식을 찾으려고 직접 만든 룰입니다. 누르면 이 룰만 봅니다.", "Rules you made for token and key formats issued in-house. Click to show only these."), act: () => only("creator", "org") },
    { id: "off", label: L("꺼 둔 룰", "Disabled rules"), value: off, icon: "minusCircle", tone: off ? "t-amber" : "t-gray",
      tip: L("다음 검사부터 쓰지 않는 룰입니다. 누르면 이 룰만 봅니다.", "Rules skipped from the next scan. Click to show only these."), act: () => only("state", "off") },
  ];

  const menuValues = (key: FilterKey) => {
    const counts = new Map<string, number>();
    for (const r of all) {
      const value = filterValue(key, r);
      counts.set(value, (counts.get(value) ?? 0) + (matches(r, filters, q, L, key) ? 1 : 0));
    }
    return counts;
  };
  const menuItem = (key: FilterKey, value: string, count: number) => <MenuItem key={value} checked={(filters[key] ?? []).includes(value)}
    end={<span className="num">{count}</span>} onSelect={() => toggleFilter(key, value)}>
    {key === "cat" ? <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><CatMark cat={value} size={20} />{catLabel(value, L)}</span>
      : key === "type" ? <><span>{filterName(key, value, L)}</span><span className="person-sub">{L(...TYPE_ABOUT[asCategory(value)])}</span></> : filterName(key, value, L)}
  </MenuItem>;
  const filterLabel: Record<FilterKey, string> = { creator: L("생성자", "Created by"), type: L("유형", "Type"), cat: L("카테고리", "Category"), state: L("상태", "Status") };
  const activeFilters = FILTER_KEYS.filter(key => filters[key]?.length);

  const th = (key: SortKey, label: string, className?: string) => <th className={className} aria-sort={sortKey === key ? (sortDir === "asc" ? "ascending" : "descending") : undefined}>
    <button type="button" onClick={() => onSort(key)}>{label}{sortKey === key ? <Ic name={sortDir === "asc" ? "up" : "down"} size={13} /> : null}</button></th>;
  const pageButton = (target: number, icon: IconName, label: string, disabled: boolean) =>
    <button type="button" className="icon-btn" aria-label={label} disabled={disabled} onClick={() => set({ page: target > 1 ? String(target) : null })}><Ic name={icon} size={16} /></button>;

  return <>
    <PageHead title={title} meta={meta} />
    <div className="tiles rules-tiles">
      {tiles.map(tile => <button type="button" className="tile" key={tile.id} data-tip={tile.tip} onClick={tile.act}>
        <span className={`tile-ic ${tile.tone}`}><Ic name={tile.icon} size={19} /></span>
        <span className="tile-text"><span className="tile-label" style={{ display: "block" }}>{tile.label}</span>
          <span className="tile-value num" style={{ display: "block" }}>{tile.value}<Ic name="info" size={13} className="tile-i" /></span></span>
      </button>)}
    </div>
    <Card className="list-card rules-card">
      <div className="list-tools">
        <SearchBox id="rule-search" value={query} onChange={setQuery} label={L("룰 검색", "Search rules")} placeholder={L("룰 이름·ID·서비스·키워드로 검색", "Search by name, ID, service or keyword")} />
        <div className="tool-btns">
          <button type="button" className="primary-btn" data-tip={L("사내에서 발급하는 토큰·키 형식을 찾는 룰을 만듭니다.", "Create a rule for token or key formats your company issues.")}
            onClick={() => setModal({ kind: "edit", mode: "regex", edit: null, from: null })}><Ic name="plus" size={16} />{L("룰 만들기", "New rule")}</button>
        </div>
      </div>
      <div className="chips-row">
        {FILTER_KEYS.map(key => {
          const n = filters[key]?.length ?? 0;
          return <FilterChip key={key} icon={FILTER_ICON[key]} label={filterLabel[key]} count={n}
            onOpen={anchor => { setFilterKey(key); setFilterQ(""); filterMenu.open(anchor); }} onClear={() => set({ [`f.${key}`]: null })} />;
        })}
      </div>
      {activeFilters.length || q ? <div className="applied">
        {activeFilters.map(key => {
          const values = filters[key]!;
          return <span className="applied-chip" key={key}><span className="wrap-t">{filterLabel[key]}: {values.slice(0, 3).map(v => filterName(key, v, L)).join(", ")}{values.length > 3 ? ` +${values.length - 3}` : ""}</span>
            <button type="button" onClick={() => set({ [`f.${key}`]: null })} aria-label={L("필터 해제", "Clear filter")}><Ic name="close" size={13} /></button></span>;
        })}
        {q ? <span className="applied-chip"><span className="wrap-t">{L("검색: ", "Search: ")}{q}</span>
          <button type="button" onClick={() => set({ q: null })} aria-label={L("검색 지우기", "Clear search")}><Ic name="close" size={13} /></button></span> : null}
        <button type="button" className="link-btn" onClick={() => set({ q: null, ...Object.fromEntries(FILTER_KEYS.map(key => [`f.${key}`, null])) })}>{L("모두 지우기", "Clear all")}</button>
      </div> : null}
      <div className="table-wrap"><table className="tbl rules-tbl">
        <thead><tr>
          <th className="rule-chev-h"><span className="sr">{L("펼치기", "Expand")}</span></th>
          {th("name", L("룰 이름", "Rule"))}{th("type", L("유형", "Type"), "col-md")}{th("cat", L("카테고리", "Category"), "col-sm")}
          <th className="col-sm">{L("생성자", "Created by")}</th><th>{L("상태", "Status")}</th>
          <th className="rule-acts-h"><span className="sr">{L("작업", "Actions")}</span></th>
        </tr></thead>
        <tbody>
          {shown.length ? shown.map(r => <RuleRow key={r.id} rule={r} open={open.has(r.id)} busy={busy === r.id} onExpand={() => expand(r.id)} onToggle={() => toggle(r)}
            onCopy={() => setModal({ kind: "edit", mode: "copy", edit: null, from: r })} onEdit={() => setModal({ kind: "edit", mode: "regex", edit: r, from: null })}
            onDelete={() => setModal({ kind: "delete", rule: r })} locale={locale} />)
            : <EmptyRow colSpan={7}>{L("조건에 맞는 룰이 없습니다. 필터를 줄여 보세요.", "No rules match. Try removing some filters.")}</EmptyRow>}
        </tbody>
      </table></div>
      <div className="pager">
        <span className="num">{L(`총 ${rows.length}개`, `${rows.length} ${rows.length === 1 ? "rule" : "rules"}`)}</span>
        <div className="pager-r">
          <label className="pager-size">{L("페이지당", "Per page")} <select value={size} onChange={event => set({ size: event.target.value === "20" ? null : event.target.value })}>
            {[20, 50, 100].map(n => <option key={n} value={n}>{n}</option>)}</select></label>
          <span className="num">{L(`${page} / ${pages} 페이지`, `Page ${page} of ${pages}`)}</span>
          <span className="pager-btns">
            {pageButton(1, "first", L("첫 페이지", "First page"), page === 1)}
            {pageButton(page - 1, "left", L("이전 페이지", "Previous page"), page === 1)}
            {pageButton(page + 1, "right", L("다음 페이지", "Next page"), page === pages)}
            {pageButton(pages, "last", L("마지막 페이지", "Last page"), page === pages)}
          </span>
        </div>
      </div>
    </Card>

    {filterMenu.anchor ? <Menu anchor={filterMenu.anchor} onClose={filterMenu.close} restore={filterMenu.opener} label={filterLabel[filterKey]}>
      <FilterMenuBody filterKey={filterKey} counts={menuValues(filterKey)} query={filterQ} onQuery={setFilterQ} item={menuItem} />
      {filters[filterKey]?.length ? <><MenuSep /><MenuItem className="pri" onSelect={() => { set({ [`f.${filterKey}`]: null }); filterMenu.close(); }}>{L("선택 해제", "Clear selection")}</MenuItem></> : null}
    </Menu> : null}

    {modal?.kind === "edit" ? <RuleModal key={`${modal.edit?.id ?? ""}:${modal.from?.id ?? ""}:${modal.mode}`} mode={modal.mode} edit={modal.edit} from={modal.from} all={all}
      realShapes={realShapes} onClose={() => setModal(null)}
      onSaved={(name, created, revision) => {
        setModal(null);
        saved();
        if (created) { setOpen(new Set([`custom-${created}`])); set({}); }
        toast(created ? L(`'${name}' 룰을 만들었습니다. 우리 조직 룰 목록에 펼쳐 두었습니다.`, `Created '${name}'. It's expanded among your rules.`)
          : L(`'${name}' 룰을 고쳤습니다(버전 ${revision}). 다음 검사부터 적용합니다.`, `Updated '${name}' (revision ${revision}). It applies from the next scan.`));
      }} /> : null}
    {modal?.kind === "delete" ? <DeleteModal rule={modal.rule} onClose={() => setModal(null)} onDeleted={() => {
      const rule = modal.rule;
      setModal(null);
      setOpen(current => { const next = new Set(current); next.delete(rule.id); return next; });
      saved();
      toast(L(`'${rule.name}' 룰을 삭제했습니다. 이미 찾은 탐지 결과는 남아 있습니다.`, `Deleted '${rule.name}'. Findings it already produced are kept.`));
    }} /> : null}
  </>;
}

function FilterMenuBody({ filterKey, counts, query, onQuery, item }: {
  filterKey: FilterKey; counts: Map<string, number>; query: string; onQuery: (value: string) => void;
  item: (key: FilterKey, value: string, count: number) => ReactNode;
}) {
  const L = useL();
  if (filterKey !== "cat") {
    const order = filterKey === "creator" ? ["org", "builtin"] : filterKey === "type" ? CATEGORIES : ["on", "off"];
    return <>{order.filter(value => counts.has(value)).map(value => item(filterKey, value, counts.get(value)!))}</>;
  }
  const needle = query.trim().toLowerCase();
  const values = [...counts.keys()].filter(value => !needle || catLabel(value, L).toLowerCase().includes(needle));
  const pinned = values.filter(value => value === "custom" || PINNED.includes(value))
    .sort((a, b) => a === "custom" ? -1 : b === "custom" ? 1 : PINNED.indexOf(a) - PINNED.indexOf(b));
  const rest = values.filter(value => !pinned.includes(value)).sort((a, b) => catLabel(a, L).localeCompare(catLabel(b, L)));
  const limit = needle ? 80 : 40;
  return <>
    <label className="menu-search"><Ic name="search" size={15} /><span className="sr">{L("서비스 검색", "Search services")}</span>
      <input value={query} onChange={event => onQuery(event.target.value)} placeholder={L("서비스 검색", "Search services")} /></label>
    {pinned.length ? <><MenuLabel>{L("사내·연동 서비스", "In-house & integrations")}</MenuLabel>{pinned.map(value => item("cat", value, counts.get(value)!))}</> : null}
    {rest.length ? <><MenuLabel>{L("그 밖의 SaaS", "Other SaaS")}</MenuLabel>{rest.slice(0, limit).map(value => item("cat", value, counts.get(value)!))}</> : null}
    {rest.length > limit ? <MenuLabel>{L(`검색하면 ${rest.length - limit}곳을 더 볼 수 있습니다`, `Search to see ${rest.length - limit} more`)}</MenuLabel> : null}
    {!values.length ? <MenuLabel>{L("찾는 서비스가 없습니다", "No services found")}</MenuLabel> : null}
  </>;
}

function IconAction({ icon, label, onClick, disabledTip }: { icon: IconName; label: string; onClick?: () => void; disabledTip?: string }) {
  return disabledTip ? <button type="button" className="icon-btn" aria-disabled="true" aria-label={label} data-tip={disabledTip} onClick={event => event.stopPropagation()}><Ic name={icon} size={17} /></button>
    : <button type="button" className="icon-btn" aria-label={label} data-tip={label} onClick={event => { event.stopPropagation(); onClick?.(); }}><Ic name={icon} size={17} /></button>;
}

/** A category's mark: the service's logo, or a pencil for an in-house format. */
function CatMark({ cat, size }: { cat: string; size: number }) {
  const L = useL();
  return cat === "custom" ? <span className="logo glyph" style={{ "--s": `${size}px` } as CSSProperties}><Ic name="pencil" size={Math.round(size * 0.62)} /></span>
    : <Logo id={cat} size={size} label={catLabel(cat, L)} />;
}

function CatCell({ cat }: { cat: string }) {
  const L = useL();
  if (cat === "custom") return <span className="tag org-tag"><Ic name="pencil" size={13} />{catLabel(cat, L)}</span>;
  return <span className="rule-cat"><Logo id={cat} size={20} label={catLabel(cat, L)} /><span className="wrap-t">{catLabel(cat, L)}</span></span>;
}

function RuleRow({ rule: r, open, busy, onExpand, onToggle, onCopy, onEdit, onDelete, locale }: {
  rule: Rule; open: boolean; busy: boolean; onExpand: () => void; onToggle: () => void; onCopy: () => void; onEdit: () => void; onDelete: () => void; locale: "ko" | "en";
}) {
  const L = useL();
  const key = (event: KeyboardEvent) => { if ((event.key === "Enter" || event.key === " ") && event.target === event.currentTarget) { event.preventDefault(); onExpand(); } };
  return <>
    <tr className={cls("rule-row", !r.builtin && "org", !r.on && "off")} tabIndex={0} aria-expanded={open} onClick={onExpand} onKeyDown={key}>
      <td className="rule-chev"><Ic name={open ? "down" : "right"} size={16} /></td>
      <td><div className="rule-name">{r.name}</div><div className="rule-id mono">{r.id}</div>
        <div className="rule-sub">{catLabel(r.cat, L)} · {L(...TYPE_NAME[r.type])}</div></td>
      <td className="col-md"><span className="tag" data-tip={L(...TYPE_ABOUT[r.type])}>{L(...TYPE_NAME[r.type])}</span></td>
      <td className="col-sm"><CatCell cat={r.cat} /></td>
      <td className="col-sm"><span className={cls("tag", !r.builtin && "org-tag")}>{r.builtin ? "CreMore" : L("우리 조직", "Our org")}</span></td>
      <td onClick={event => event.stopPropagation()}><Switch checked={r.on} disabled={busy} onChange={onToggle} label={`${r.name} ${r.on ? L("끄기", "disable") : L("켜기", "enable")}`}
        tip={r.on ? L("켜져 있음 · 누르면 다음 검사부터 이 룰을 쓰지 않습니다", "On · click to skip this rule from the next scan") : L("꺼져 있음 · 누르면 다시 씁니다", "Off · click to use it again")} /></td>
      <td className="rule-acts">{r.builtin ? <>
        <IconAction icon="copy" label={L("가져와서 사내용으로 수정", "Copy and customize")} onClick={onCopy} />
        <IconAction icon="pencil" label={L("룰 수정", "Edit rule")} disabledTip={L("기본 룰은 직접 고칠 수 없습니다. 가져와서 사본을 수정하세요.", "Built-in rules can't be edited. Copy one and edit the copy.")} />
        <IconAction icon="trash" label={L("룰 삭제", "Delete rule")} disabledTip={L("기본 룰은 삭제할 수 없습니다. 끄기만 할 수 있습니다.", "Built-in rules can't be deleted, only disabled.")} />
      </> : <>
        <IconAction icon="copy" label={L("가져와서 새 룰로 수정", "Copy into a new rule")} onClick={onCopy} />
        <IconAction icon="pencil" label={L("룰 수정", "Edit rule")} onClick={onEdit} />
        <IconAction icon="trash" label={L("룰 삭제", "Delete rule")} onClick={onDelete} />
      </>}</td>
    </tr>
    {open ? <tr className="rule-more"><td colSpan={7}><RuleDetail rule={r} locale={locale} /></td></tr> : null}
  </>;
}

function Pattern({ expr, label }: { expr: string; label?: string }) {
  const L = useL();
  const tree = rx.parse(expr), words = rx.parts(tree, L);
  return <>
    <div className="rd-block"><div className="rd-lbl">{label ? `${L("값 형식 (쉽게 읽기)", "Value format (plain words)")} · ${label}` : L("값 형식 (쉽게 읽기)", "Value format (plain words)")}
      <InfoTip text={L("정규식을 사람이 읽기 쉬운 말로 풀었습니다. 굵은 글씨가 찾아서 보고하는 값입니다.", "The pattern in plain words. The bold part is the value that gets reported.")} /></div>
      <div className="rd-read">{words.value || "—"}</div>
      {words.label ? <div className="rd-sub">{L("앞에 오는 이름: ", "Preceded by: ")}{words.label}</div> : null}</div>
    <div className="rd-block"><div className="rd-lbl">{label ? `${L("정규식", "Pattern")} · ${label}` : L("정규식", "Pattern")}
      <InfoTip text={L("조각에 마우스를 올리면 뜻이 나옵니다. 파란 테두리가 값 부분, 점선은 묶음입니다.", "Hover a piece to see what it means. The blue outline is the value; dashed lines are groups.")} /></div>
      <div className="rx"><Chips alts={tree} /></div></div>
  </>;
}

function Chips({ alts }: { alts: rx.Alts }) {
  const L = useL();
  return <>{alts.map((list, index) => <Fragment key={index}>
    {index ? <span className="rxc alt" data-tip={L("또는: 양쪽 중 하나", "OR: either side")}>|</span> : null}
    {list.map((node, at) => <Chip key={at} node={node} />)}
  </Fragment>)}</>;
}

function Chip({ node }: { node: rx.RxNode }) {
  const L = useL();
  const quant = node.q ? <span className="rxc q" data-tip={rx.quantTip(node.q, L)}>{node.q.raw}</span> : null;
  if (node.t === "group") {
    const tip = rx.groupTip(node, L);
    const tone = node.kind === "named" && node.name === "secret" ? "sec" : rx.isBound(node) ? "bd" : node.kind === "look" ? "bad" : null;
    return <span className={cls("rxg", tone)}><span className="rxc g" data-tip={tip}>{node.open}</span><Chips alts={node.alts} />
      {node.closed ? <span className="rxc g" data-tip={tip}>)</span> : null}{quant}</span>;
  }
  return <><span className={`rxc ${node.t}`} data-tip={rx.nodeTip(node, L)}>{node.raw}</span>{quant}</>;
}

function RuleDetail({ rule: r, locale }: { rule: Rule; locale: "ko" | "en" }) {
  const L = useL();
  const d = r.detector, o = r.org;
  const fp: [string, string] = o ? ["high", L("높음", "High")] : ({ high: ["low", L("낮음", "Low")], medium: ["med", L("보통", "Medium")], low: ["high", L("높음", "High")] } as Record<string, [string, string]>)[d?.confidence ?? ""] ?? ["med", "—"];
  const strategy = o ? L("우리 조직이 직접 쓴 정규식으로 찾습니다.", "Matches with a pattern your organization wrote.")
    : STRATEGY[d?.strategy ?? ""] ? L(...STRATEGY[d!.strategy]) : d?.strategy ?? "—";
  const side: [string, ReactNode, string?][] = [
    [L("매칭 방식", "How it matches"), strategy, L("이 룰이 값을 어떻게 알아보는지입니다.", "How this rule recognizes a value.")],
    [L("오탐 가능성", "False-positive risk"), <span className={`fp fp-${fp[0]}`}>{fp[1]}</span>,
      L("값 모양만으로 확신할 수 있는 정도입니다. 고유 접두사가 있으면 낮고, 설정 이름에 기대면 높습니다. 발견 후 검증을 켜면 실제 확인 결과가 우선합니다.", "How sure the shape alone makes us. Low with a unique prefix, higher when relying on a config name. Verification, when on, overrides this.")],
  ];
  if (o) {
    side.push([L("심각도", "Severity"), <RiskTag level={o.severity.toLowerCase() as Risk} />, L("이 룰로 찾은 노출을 얼마나 급하게 다룰지 정합니다.", "How urgently exposures found by this rule are handled.")]);
    side.push([L("검사 위치", "Scan locations"), o.scope_sources.length ? o.scope_sources.map(scopeName).join(", ") : L("연결된 모든 위치", "All connected locations")]);
    side.push([L("제외 단어", "Excluded words"), o.exclude_words.length ? o.exclude_words.join(", ") : "—", L("같은 줄에 이 단어가 있으면 무시합니다.", "Ignored when the same line contains one of these words.")]);
    side.push([L("제외 경로", "Excluded paths"), o.exclude_globs.length ? <span className="mono">{o.exclude_globs.join(", ")}</span> : "—"]);
    if (o.include_globs.length) side.push([L("검사 경로", "Included paths"), <span className="mono">{o.include_globs.join(", ")}</span>, L("이 경로 패턴에 맞는 파일에서만 씁니다.", "Only files matching these path patterns are checked.")]);
    side.push([L("수정", "Last change"), [L(`버전 ${o.revision}`, `Revision ${o.revision}`), fmtDay(o.updated_at, locale), actorLabel(o.updated_by, L)].filter(Boolean).join(" · ")]);
  } else {
    const url = safeUrl(d?.source_url);
    if (url) side.push([L("근거 문서", "Source"), <a href={url} target="_blank" rel="noopener noreferrer">{hostOf(url)} <Ic name="ext" size={13} /></a>,
      L("룰을 만들 때 참고한 공급자 공개 문서입니다.", "The provider document this rule was written from.")]);
    if (d?.switched_at) side.push([L("켜고 끈 기록", "Switched"), [r.on ? L("켬", "On") : L("끔", "Off"), fmtDay(d.switched_at, locale), actorLabel(d.switched_by, L)].filter(Boolean).join(" · ")]);
  }
  side.push([L("룰 ID", "Rule ID"), <span className="mono">{r.id}</span>]);
  return <div className="rule-detail">
    <div className="rd-main">
      <div className="rd-block"><div className="rd-lbl">{L("설명", "Description")}{r.builtin ? <span className="tag">{L("원문", "Original")}</span> : null}</div>
        <p>{r.desc || "—"}</p></div>
      {r.patterns.map((pattern, index) => <Pattern key={index} expr={pattern} label={r.patterns.length > 1 ? String(index + 1) : undefined} />)}
      <div className="rd-block"><div className="rd-lbl">{L("키워드", "Keywords")}
        <InfoTip text={L("파일에 이 단어 중 하나가 있을 때만 정규식을 돌립니다. 검사가 빨라지고 오탐이 줄어듭니다.", "The pattern only runs on files containing one of these words. Faster and fewer false positives.")} /></div>
        {r.kw.length ? <div className="pill-wrap">{r.kw.map(word => <span className="tag mono" key={word}>{word}</span>)}</div>
          : <span className="subtle">{L("없음 · 모든 파일에서 정규식을 돌립니다", "None · the pattern runs on every file")}</span>}</div>
    </div>
    <dl className="rd-side">{side.map(([label, value, tip]) => <div key={label}><dt>{label}{tip ? <> <InfoTip text={tip} /></> : null}</dt><dd>{value}</dd></div>)}</dl>
  </div>;
}

/* ---------- creating, copying and changing a rule ---------- */

type Form = { name: string; desc: string; type: Category; cat: string; sev: Severity; expr: string; kw: string; scope: string[]; exWords: string; exPaths: string };

export function formOf(rule: Rule | null, copy: boolean, L: Say): Form {
  if (!rule) return { name: "", desc: "", type: "token", cat: "custom", sev: "HIGH", expr: "", kw: "", scope: [], exWords: "", exPaths: "" };
  const o = rule.org;
  return {
    name: copy ? rule.name + L(" (사내용)", " (custom)") : rule.name, desc: rule.desc, type: rule.type, cat: rule.cat,
    sev: (SEVERITIES as readonly string[]).includes(o?.severity ?? "") ? o!.severity as Severity : "HIGH", expr: rule.patterns[0] ?? "", kw: rule.kw.join(", "),
    scope: o ? [...o.scope_sources] : [], exWords: o ? o.exclude_words.join(", ") : "", exPaths: o ? o.exclude_globs.join(", ") : "",
  };
}

/** The request body for a form; a copy of an organization rule keeps the paths it was limited to. */
export function bodyOf(form: Form, from: Rule | null) {
  return {
    name: form.name.trim(), description: form.desc.trim(), category: form.type, provider_candidates: form.cat === "custom" ? [] : [form.cat],
    severity: form.sev, pattern: form.expr.trim(), keywords: rx.splitList(form.kw), scope_sources: form.scope,
    exclude_words: rx.splitList(form.exWords), exclude_globs: rx.splitList(form.exPaths),
    ...(from?.org ? { include_globs: from.org.include_globs } : {}),
  };
}

const RULE_ERRORS: [RegExp, [string, string]][] = [
  [/^name is required/, ["룰 이름을 1~128자로 입력하세요.", "Enter a rule name of 1–128 characters."]],
  [/^(?:RULE_NAME_TAKEN|rule .+ already exists$|already exists)/, ["같은 이름의 룰이 이미 있습니다.", "A rule with that name already exists."]],
  [/^severity must be/, ["심각도를 고르세요.", "Choose a severity."]],
  [/^category must be/, ["유형을 고르세요.", "Choose a type."]],
  [/^keywords must be/, ["키워드는 32개까지, 각 64자 이하로 입력하세요.", "Use up to 32 keywords of 64 characters."]],
  [/must be up to 32 strings/, ["제외 단어와 경로는 32개까지, 각 256자 이하로 입력하세요.", "Use up to 32 excluded words or paths of 256 characters."]],
  [/^scope_sources may only/, ["검사 위치를 다시 고르세요.", "Choose the scan locations again."]],
  [/^pattern is required/, ["정규식을 입력하세요.", "Enter a pattern."]],
  [/regex engine/, ["서버에서 정규식 엔진을 쓸 수 없어 룰을 받지 않습니다.", "The server's regex engine is unavailable, so rules are refused."]],
  [/at most 1000/, ["정규식은 1000자 이하로 쓰세요.", "Keep the pattern to 1000 characters."]],
  [/lookaround/, ["앞뒤 살피기·역참조는 쓸 수 없습니다.", "Lookaround and backreferences are not allowed."]],
  [/does not compile/, ["정규식에 문법 오류가 있습니다.", "The pattern has a syntax error."]],
  [/trivial input|empty string/, ["정규식이 너무 넓습니다. 빈 값이나 흔한 문장에도 걸립니다.", "The pattern is too broad; it matches empty or everyday text."]],
];

function ruleError(error: unknown, L: Say) {
  if (error instanceof DashboardAPIError && (error.status === 422 || error.status === 409)) {
    const found = RULE_ERRORS.find(([pattern]) => pattern.test(error.message));
    if (found) return L(...found[1]);
  }
  return reasonText(error, L);
}

function RuleModal({ mode: initialMode, edit, from: initialFrom, all, realShapes, onClose, onSaved }: {
  mode: "regex" | "copy"; edit: Rule | null; from: Rule | null; all: Rule[]; realShapes: RegExp[];
  onClose: () => void; onSaved: (name: string, created: string | null, revision: number) => void;
}) {
  const L = useL();
  const toast = useToast();
  const [mode, setMode] = useState(initialMode);
  const [from, setFrom] = useState<Rule | null>(initialFrom);
  const [form, setForm] = useState<Form>(() => formOf(edit ?? initialFrom, Boolean(initialFrom), L));
  const [pick, setPick] = useState("");
  const [sample, setSample] = useState("");
  const [synthetic, setSynthetic] = useState(false);
  const [advanced, setAdvanced] = useState(Boolean(edit));
  const [verdict, setVerdict] = useState<{ expr: string; error: string | null } | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const put = (changes: Partial<Form>) => { setForm(current => ({ ...current, ...changes })); setError(""); };

  // The server compiles the pattern alone with RE2 and says whether it would accept it.
  const expr = form.expr.trim();
  const judgeable = Boolean(expr) && expr.length <= 1000 && !rx.UNSAFE.test(expr);
  useEffect(() => {
    if (!judgeable) return;
    let stale = false;
    const timer = window.setTimeout(() => {
      send("rules/new/test", "POST", { rule: { name: "pattern check", pattern: expr }, fixture_id: "NEUTRAL_TEXT" })
        .then(() => { if (!stale) setVerdict({ expr, error: null }); })
        .catch(reason => { if (!stale && reason instanceof DashboardAPIError && reason.status === 422) setVerdict({ expr, error: reason.message }); });
    }, 350);
    return () => { stale = true; window.clearTimeout(timer); };
  }, [expr, judgeable]);

  const taken = all.some(r => !r.builtin && r.org!.id !== edit?.org?.id && r.name === form.name.trim());
  const checks = rx.ruleChecks(form, taken, verdict?.expr === expr ? { state: "done", error: verdict.error } : { state: judgeable ? "pending" : "idle" }, L);
  const valid = checks.every(check => check.ok === true);
  const tree = expr ? rx.parse(expr) : null, words = tree ? rx.parts(tree, L) : null;
  const found = sample ? rx.hits(form.expr, sample, rx.splitList(form.exWords)) : null;
  const looksReal = !synthetic && Boolean(sample) && realShapes.some(re => { re.lastIndex = 0; return re.test(sample); });

  const save = async () => {
    if (!valid || saving) return;
    setSaving(true);
    try {
      const body = bodyOf(form, from);
      const result = await send<{ id: string; revision: number }>(edit ? `rules/${edit.org!.id}` : "rules", edit ? "PUT" : "POST", body);
      onSaved(body.name, edit ? null : result.id, result.revision);
    } catch (reason) { setError(ruleError(reason, L)); }
    finally { setSaving(false); }
  };
  const synth = () => {
    if (!rx.toJsRe(form.expr)) { toast(L("정규식을 먼저 고치세요.", "Fix the pattern first.")); return; }
    setSample(`# ${L("합성 예시 · 가짜 값", "Synthetic example · fake value")}\n${rx.synth(form.expr)}\n`);
    setSynthetic(true);
  };
  const choose = (rule: Rule) => { setFrom(rule); setForm(formOf(rule, true, L)); setSample(""); setSynthetic(false); setError(""); };

  const heading = <h2 id="rule-modal-title">{edit ? L("룰 수정", "Edit rule") : L("새 룰 만들기", "New rule")}{edit ? <> <small>{edit.name}</small></> : null}</h2>;
  const tabs = edit ? null : <div className="mtabs" role="tablist">
    <button type="button" role="tab" aria-selected={mode === "regex"} data-tip={L("정규식을 직접 써서 새 형식을 찾습니다.", "Write a pattern for a new format.")}
      onClick={() => { setMode("regex"); if (from) { setFrom(null); setForm(formOf(null, false, L)); } }}>{L("정규식 직접 입력", "Write a pattern")}</button>
    <button type="button" role="tab" aria-selected={mode === "copy"} data-tip={L("이미 있는 룰을 가져와 사본을 고칩니다. 원본은 그대로 둡니다.", "Copy an existing rule and edit the copy. The original stays as is.")}
      onClick={() => setMode("copy")}>{L("기존 룰 가져와서 수정", "Customize an existing rule")}</button>
  </div>;
  const foot = (withSave: boolean) => <div className="modal-foot">
    <button type="button" className="ghost-btn" onClick={onClose}>{L("취소", "Cancel")}</button>
    {withSave ? <button type="button" className="primary-btn" disabled={!valid || saving} onClick={save}>{edit ? L("변경 저장", "Save changes") : L("룰 만들기", "Create rule")}</button> : null}
  </div>;

  if (mode === "copy" && !from) {
    const needle = pick.trim().toLowerCase();
    const list = all.filter(r => !needle || `${r.name} ${r.id} ${catLabel(r.cat, L)}`.toLowerCase().includes(needle));
    const builtins = all.filter(r => r.builtin).length;
    return <Modal onClose={onClose} labelledBy="rule-modal-title" className="rule-modal">
      {heading}{tabs}
      <p className="re-cap">{L(`기본 룰 ${builtins}개와 우리 조직 룰 중에서 고릅니다. 원본은 그대로 두고, 사본을 우리 조직 룰로 만들어 고칩니다.`, `Pick from ${builtins} built-in rules and your own. The original stays as is; you edit a copy saved as your rule.`)}</p>
      <label className="search re-q"><Ic name="search" size={16} /><span className="sr">{L("가져올 룰 검색", "Search rules to copy")}</span>
        <input value={pick} data-autofocus onChange={event => setPick(event.target.value)} placeholder={L("예: GitHub, Slack webhook, AWS", "e.g. GitHub, Slack webhook, AWS")} /></label>
      <div className="re-pick">
        {list.length ? list.slice(0, 8).map(r => <button type="button" className="re-pick-row" key={r.id} data-tip={r.desc} onClick={() => choose(r)}>
          <CatMark cat={r.builtin ? r.cat : "custom"} size={24} />
          <span className="re-pick-text"><b>{r.name}</b><span className="ig-sub">{r.builtin ? catLabel(r.cat, L) : L("우리 조직", "Our org")} · {L(...TYPE_NAME[r.type])}</span></span>
          <span className="re-pick-go">{L("가져오기", "Use")}<Ic name="right" size={14} /></span>
        </button>) : <div className="re-empty">{L("찾는 룰이 없습니다. 다른 이름으로 검색해 보세요.", "No rules found. Try another name.")}</div>}
        {list.length > 8 ? <div className="re-empty">{L(`상위 8개만 보입니다. 검색어를 더 넣으면 좁혀집니다(전체 ${list.length}개).`, `Showing the top 8 of ${list.length}. Type more to narrow down.`)}</div> : null}
      </div>
      {foot(false)}
    </Modal>;
  }

  const cats = ["custom", ...PINNED];
  if (!cats.includes(form.cat)) cats.push(form.cat);
  const status = !sample ? <span className="ig-sub">{L("예시 문장을 넣으면 걸리는 부분을 표시합니다. 브라우저 안에서만 시험하고 저장하지 않습니다.", "Add a sample to highlight what matches. It runs only in this browser and is never saved.")}</span>
    : found === null ? <span className="ig-sub">{L("정규식을 먼저 고치세요.", "Fix the pattern first.")}</span>
      : (() => {
        const used = found.filter(hit => !hit.skip).length, skipped = found.length - used;
        let at = 0;
        const preview: ReactNode[] = [];
        found.forEach((hit, index) => {
          preview.push(sample.slice(at, hit.start), <mark key={index} className={hit.skip ? "skip" : undefined}>{sample.slice(hit.start, hit.end)}</mark>);
          at = hit.end;
        });
        preview.push(sample.slice(at));
        return <>
          {used ? <span className="ig-result ok"><Ic name="checkCircle" size={15} />{L(`${used}곳에서 걸림`, `${used} ${used === 1 ? "match" : "matches"}`)}{skipped ? L(` · 제외 단어로 ${skipped}곳 무시`, ` · ${skipped} ignored by excluded words`) : ""}</span>
            : <span className="ig-result none"><Ic name="minusCircle" size={15} />{skipped ? L("제외 단어로 모두 무시됨", "All ignored by excluded words") : L("걸리는 곳 없음", "No match")}</span>}
          {found.length ? <pre className="re-preview">{preview}</pre> : null}
        </>;
      })();

  return <Modal onClose={onClose} labelledBy="rule-modal-title" className="rule-modal">
    {heading}{tabs}
    {from ? <div className="re-from"><Ic name="copy" size={15} /><span>{L("가져온 룰: ", "Based on: ")}<b>{from.name}</b> · {from.builtin ? catLabel(from.cat, L) : L("우리 조직", "Our org")}</span>
      <button type="button" className="link-btn" onClick={() => { setFrom(null); setPick(""); }}>{L("다른 룰 고르기", "Pick another")}</button></div> : null}
    <div className="row2">
      <div className="field"><label htmlFor="re-name">{L("룰 이름", "Rule name")} <InfoTip text={L("목록과 알림에 보이는 이름입니다. 128자까지, 다른 룰과 겹치면 안 됩니다.", "Shown in the list and alerts. Up to 128 characters and unique.")} /></label>
        <input id="re-name" maxLength={128} value={form.name} data-autofocus onChange={event => put({ name: event.target.value })} placeholder={L("예: 사내 결제 게이트웨이 키", "e.g. In-house payment gateway key")} /></div>
      <div className="field"><label htmlFor="re-type">{L("유형", "Type")} <InfoTip text={CATEGORIES.map(c => `${L(...TYPE_NAME[c])}: ${L(...TYPE_ABOUT[c])}`).join(" / ")} /></label>
        <select id="re-type" value={form.type} onChange={event => put({ type: event.target.value as Category })}>
          {CATEGORIES.map(c => <option key={c} value={c}>{L(...TYPE_NAME[c])}</option>)}</select></div>
    </div>
    <div className="field"><label htmlFor="re-desc">{L("설명 (Description)", "Description")} <InfoTip text={L("무엇을 찾는 룰인지, 걸리면 누구에게 알려야 하는지 적어 두면 대응할 때 도움이 됩니다.", "Say what the rule finds and who to tell when it fires.")} /></label>
      <textarea id="re-desc" className="short" rows={3} value={form.desc} onChange={event => put({ desc: event.target.value })}
        placeholder={L("예: 결제팀 게이트웨이 호출용 키. 발견되면 결제팀에 알립니다.", "e.g. Payments gateway key. Notify the payments team when found.")} /></div>
    <div className="row2">
      <div className="field"><label htmlFor="re-cat">{L("카테고리", "Category")} <InfoTip text={L("어느 서비스의 값인지 고릅니다. 사내에서 만든 형식이면 '사내 자체 형식'을 고르세요.", "Which service the value belongs to. Choose 'In-house format' for your own formats.")} /></label>
        <select id="re-cat" value={form.cat} onChange={event => put({ cat: event.target.value })}>{cats.map(c => <option key={c} value={c}>{catLabel(c, L)}</option>)}</select></div>
      <div className="field"><label htmlFor="re-sev">{L("심각도", "Severity")} <InfoTip text={L("이 룰로 찾은 노출을 얼마나 급하게 다룰지 정합니다. 우리 조직 룰에만 있습니다.", "How urgently exposures found by this rule are handled. Only for your own rules.")} /></label>
        <select id="re-sev" value={form.sev} onChange={event => put({ sev: event.target.value as Severity })}>
          {SEVERITIES.map(s => <option key={s} value={s}>{riskLabel(s.toLowerCase() as Risk, L)}</option>)}</select></div>
    </div>
    <div className="field"><label htmlFor="re-expr">{L("정규식", "Pattern")} <InfoTip text={L("RE2 문법을 씁니다. 앞뒤 살피기·역참조는 쓸 수 없습니다. (?P<secret>…)로 값 부분을 표시하면 그 부분만 지문으로 남기고, 표시가 없으면 걸린 부분 전체를 값으로 봅니다.", "Uses RE2 syntax, so no lookaround or backreferences. Mark the value with (?P<secret>…) to fingerprint only that part; otherwise the whole match is the value.")} /></label>
      <textarea id="re-expr" className="mono short" rows={3} spellCheck={false} value={form.expr} onChange={event => put({ expr: event.target.value })} placeholder="(?P<secret>demo_[A-Za-z0-9]{32})" /></div>
    <div className="re-live">
      {tree && words ? <><div className="re-read"><div className="rd-lbl">{L("쉽게 읽기", "In plain words")}</div><b>{words.value || "—"}</b>
        {words.label ? <div className="ig-sub">{L("앞에 오는 이름: ", "Preceded by: ")}{words.label}</div> : null}</div>
        <div className="rx"><Chips alts={tree} /></div></> : null}
      <ul className="re-checks">{checks.map(check => <li key={check.label} className={check.ok === null ? "na" : check.ok ? "ok" : "bad"}>
        <Ic name={check.ok === null ? "minusCircle" : check.ok ? "checkCircle" : "xCircle"} size={15} />
        <span>{check.label}{check.why && check.ok === false ? <span className="why">{check.why}</span> : null}</span></li>)}</ul>
    </div>
    <div className="field"><label htmlFor="re-sample">{L("예시 문장으로 시험", "Test with a sample")} <InfoTip text={L("실제 값 대신 가짜 값을 쓰세요. '합성 예시 넣기'는 정규식에서 가짜 값을 만들어 줍니다.", "Use fake values instead of real ones. 'Insert synthetic sample' builds a fake value from the pattern.")} /></label>
      <textarea id="re-sample" className="mono short" rows={3} spellCheck={false} value={sample} onChange={event => { setSample(event.target.value); setSynthetic(false); }}
        placeholder={L("예: PAYMENT_KEY = (가짜 값)", "e.g. PAYMENT_KEY = (fake value)")} />
      <div className="re-test-bar">
        <button type="button" className="ghost-btn" onClick={synth} data-tip={L("정규식 모양대로 가짜 값을 만들어 넣습니다. 실제 값이 아닙니다.", "Builds a fake value in the pattern's shape. Not a real value.")}>
          <Ic name="wand" size={15} />{L("합성 예시 넣기", "Insert synthetic sample")}</button>
        <div className="re-test" aria-live="polite">
          {looksReal ? <span className="ig-result bad"><Ic name="alert" size={15} />{L("실제 값으로 보입니다. 가짜 값으로 시험하세요.", "This looks like a real value. Test with fake values.")}</span> : null}
          {status}
        </div>
      </div></div>
    <button type="button" className="re-adv-toggle" aria-expanded={advanced} onClick={() => setAdvanced(value => !value)}>
      <Ic name={advanced ? "up" : "down"} size={15} />{L("고급 설정", "Advanced")} <span className="ig-sub">{L("키워드·검사 위치·제외 조건", "Keywords, locations, exclusions")}</span></button>
    {advanced ? <div className="re-adv">
      <div className="field"><label htmlFor="re-kw">{L("키워드", "Keywords")} <InfoTip text={L("파일에 이 단어 중 하나가 있을 때만 정규식을 돌립니다. 검사가 빨라지고 오탐이 줄어듭니다. 쉼표로 구분, 최대 32개.", "The pattern only runs on files containing one of these words. Faster and fewer false positives. Comma-separated, up to 32.")} /></label>
        <input id="re-kw" value={form.kw} onChange={event => put({ kw: event.target.value })} placeholder="demo_pay_, dpl_" /></div>
      <div className="field"><span className="lbl">{L("검사 위치", "Scan locations")} <InfoTip text={L("고른 곳에서만 이 룰을 씁니다. 하나도 고르지 않으면 연결된 모든 위치를 검사합니다.", "Use this rule only in the chosen places. Choose none to scan every connected location.")} /></span>
        <div className="re-scope">{SCOPES.map(type => {
          const on = form.scope.includes(type);
          return <button type="button" role="checkbox" aria-checked={on} key={type} onClick={() => put({ scope: on ? form.scope.filter(s => s !== type) : [...form.scope, type] })}>
            <Logo id={exposureService(type)} size={18} />{scopeName(type)}</button>;
        })}</div></div>
      <div className="row2">
        <div className="field"><label htmlFor="re-exw">{L("제외 단어", "Excluded words")} <InfoTip text={L("같은 줄에 이 단어가 있으면 무시합니다. 예: example, test, dummy", "Ignored when the same line has one of these words. e.g. example, test, dummy")} /></label>
          <input id="re-exw" value={form.exWords} onChange={event => put({ exWords: event.target.value })} placeholder="example, dummy" /></div>
        <div className="field"><label htmlFor="re-exp">{L("제외 경로", "Excluded paths")} <InfoTip text={L("이 경로 패턴에 맞는 파일은 검사하지 않습니다. 예: **/test/**, *.md", "Files matching these path patterns are skipped. e.g. **/test/**, *.md")} /></label>
          <input id="re-exp" value={form.exPaths} onChange={event => put({ exPaths: event.target.value })} placeholder="**/test/**, *.md" /></div>
      </div>
    </div> : null}
    {error ? <p className="ig-result bad" role="alert"><Ic name="alert" size={15} />{error}</p> : null}
    {foot(true)}
  </Modal>;
}

function DeleteModal({ rule, onClose, onDeleted }: { rule: Rule; onClose: () => void; onDeleted: () => void }) {
  const L = useL();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const remove = async () => {
    setBusy(true);
    try { await send(`rules/${rule.org!.id}`, "DELETE"); onDeleted(); }
    catch (reason) { setError(reasonText(reason, L)); setBusy(false); }
  };
  return <Modal onClose={onClose} labelledBy="rule-del-title" size="narrow">
    <h2 id="rule-del-title">{L("룰 삭제", "Delete rule")} <small>{rule.name}</small></h2>
    <p className="re-cap">{L("삭제하면 다음 검사부터 이 룰을 쓰지 않습니다. 이미 찾은 탐지 결과와 이력은 남습니다. 잠시 멈추려면 삭제 대신 끄기를 쓰세요.", "Deleting stops this rule from the next scan. Findings and history it produced are kept. To pause it instead, turn it off.")}</p>
    {error ? <p className="ig-result bad" role="alert"><Ic name="alert" size={15} />{error}</p> : null}
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose}>{L("취소", "Cancel")}</button>
      <button type="button" className="danger-btn" disabled={busy} onClick={remove}><Ic name="trash" size={16} />{L("삭제", "Delete")}</button>
    </div>
  </Modal>;
}
