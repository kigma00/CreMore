"use client";

/* Credential overview: counts, collection coverage, exposure, remediation progress, risk checks,
 * credential types and where exposures were found. Every number comes from the credential list
 * and the connections this installation has. */

import { type ReactNode, useEffect, useMemo, useState } from "react";

import { useLocale } from "@/components/locale";
import { hasRole } from "@/lib/dashboard-session";
import { CHECKS, type CheckKey, openTrend, stats } from "@/console/checks";
import { reasonText, useApi } from "@/console/data";
import { Ic, type IconName } from "@/console/icons";
import { kindLabel, typeLabel, visLabel } from "@/console/labels";
import { Menu, MenuItem, MenuLabel, useMenu } from "@/console/layer";
import { Logo, serviceName } from "@/console/logos";
import { type CredentialRecord, countable, exposureService, isRemoved, RECORDS_PATH, type RecordsResponse, VIS_ORDER } from "@/console/records";
import type { ViewProps } from "@/console/shell";
import { cnt, fmtDT, rel, time, useL } from "@/console/text";
import { Banner, BarList, Card, CardBody, cls, Donut, ErrorLine, Gauge, InfoTip, Loading, MiniToggle, PageHead, Sparkline, SubBar, Tile, Tiles } from "@/console/ui";

type ProviderConnection = { id: string; provider: string; name: string; status: string; purposes: string[]; target: Record<string, unknown>; children: { kind: string; purpose: string }[] };
type Health = { items: { last_success_at: string | null }[] };

const CARDS = ["conn", "risk", "remed", "controls", "types", "where"] as const;
type CardId = (typeof CARDS)[number];
const PREFS = "cremore.console.dashboard.v1";

// Where an integration's exposure scans look, by provider.
const SCAN_PLACES: Record<string, string[]> = {
  github: ["github"], gitlab: ["gitlab"], bitbucket: ["bitbucket"], confluence: ["confluence"], notion: ["notion"],
  aws: ["s3"], gcp: ["gcs"], azure: ["azure"], azure_devops: ["azure_devops"],
};

type Prefs = { hidden: CardId[]; checks: CheckKey[]; risk: "donut" | "bars"; remed: "gauge" | "trend"; providers: string[] };
const DEFAULTS: Prefs = { hidden: [], checks: [], risk: "donut", remed: "gauge", providers: [] };

function readPrefs(): Prefs {
  try {
    const value = JSON.parse(window.localStorage.getItem(PREFS) || "{}");
    const list = (raw: unknown) => (Array.isArray(raw) ? raw.filter((item): item is string => typeof item === "string") : []);
    return {
      hidden: list(value.hidden).filter((id): id is CardId => (CARDS as readonly string[]).includes(id)),
      checks: list(value.checks).filter((id): id is CheckKey => CHECKS.some(check => check.key === id)),
      risk: value.risk === "bars" ? "bars" : "donut", remed: value.remed === "trend" ? "trend" : "gauge",
      providers: list(value.providers),
    };
  } catch {
    return DEFAULTS;
  }
}

export function Dashboard({ session, go }: ViewProps) {
  const L = useL();
  const locale = useLocale();
  const records = useApi<RecordsResponse>(RECORDS_PATH, { every: 60_000 });
  const connections = useApi<ProviderConnection[]>("provider-connections", { every: 60_000 });
  const health = useApi<Health>("operations/connections", { every: 60_000 });
  const catalog = useApi<{ providers: { provider: string; purposes: Record<string, unknown> }[] }>("provider-connections/catalog");
  const [prefs, setPrefs] = useState<Prefs>(DEFAULTS);
  useEffect(() => { setPrefs(readPrefs()); }, []);
  const save = (next: Prefs) => {
    setPrefs(next);
    try { window.localStorage.setItem(PREFS, JSON.stringify(next)); } catch { /* per-device convenience */ }
  };
  const filterMenu = useMenu(), layoutMenu = useMenu(), checksMenu = useMenu();
  const admin = hasRole(session.role, "Admin");

  const all = records.data?.items;
  const providersPresent = useMemo(() => Array.from(new Set((all ?? []).map(c => c.provider))).sort(), [all]);
  const chosen = prefs.providers.filter(p => providersPresent.includes(p));
  const items = useMemo(() => (all ?? []).filter(c => !chosen.length || chosen.includes(c.provider)), [all, chosen]);
  const s = useMemo(() => stats(items), [items]);
  const now = Date.now();

  if (!all && records.loading) return <><PageHead title={L("Credential 관리 현황", "Credential overview")} /><Loading /></>;
  if (!all) return <><PageHead title={L("Credential 관리 현황", "Credential overview")} /><ErrorLine onRetry={records.reload}>{reasonText(records.error, L)}</ErrorLine></>;

  const lastCollected = (health.data?.items ?? []).map(item => item.last_success_at).filter((v): v is string => Boolean(v))
    .sort((a, b) => (time(b) ?? 0) - (time(a) ?? 0))[0];
  const active = (connections.data ?? []).filter(c => c.status === "ACTIVE");
  const withPurpose = (purpose: string) => Array.from(new Set(active.filter(c => c.purposes.includes(purpose)).map(c => c.provider)));
  // An inventory also counts when its collection predates provider connections: its rows say so.
  const inventory = Array.from(new Set([...withPurpose("inventory"), ...all.filter(c => c.issued).map(c => c.provider)]));
  const exposure = withPurpose("exposure"), vaults = withPurpose("vault");
  const places = Array.from(new Set([...exposure.flatMap(p => SCAN_PLACES[p] ?? [p]),
    ...active.filter(c => c.provider === "azure" && c.purposes.includes("exposure") && c.target.devops_project).map(() => "azure_devops")]));
  const usageProviders = Array.from(new Set((all).filter(c => c.issued && c.last_used).map(c => c.provider)));
  const usageOff = inventory.filter(p => !usageProviders.includes(p));
  // A connected provider that keeps secrets too, whose secret store is not compared yet.
  const keepsSecrets = new Set((catalog.data?.providers ?? []).filter(d => d.purposes.vault).map(d => d.provider));
  const vaultGap = Array.from(new Set(active.map(c => c.provider))).filter(p => keepsSecrets.has(p) && !vaults.includes(p));
  const ownerOf = (provider: string) => active.find(c => c.provider === provider);
  const inventoryGap = exposure.filter(p => !inventory.includes(p) && p !== "confluence");

  const go2 = (tab: "exposed" | "all" | "vault", extra: Record<string, string | null> = {}) =>
    go(tab === "exposed" ? "exposed" : "inventory", { tab: tab === "vault" ? "vault" : null, ...extra });

  const tiles: { label: string; value: string | number; icon: IconName; tone: "blue" | "red" | "violet" | "amber" | "teal" | "green" | "pink"; tip: string; act: () => void }[] = [
    { label: L("추적 중인 Credential", "Tracked credentials"), value: s.total, icon: "key", tone: "blue", act: () => go2("all"),
      tip: L("발급 목록과 노출 검사에서 찾은 Credential 전체입니다.", "Every credential found in issuance inventories and exposure scans.") },
    { label: L("노출된 Credential", "Exposed credentials"), value: s.exposed, icon: "alert", tone: "red", act: () => go2("exposed"),
      tip: L("검사한 위치에서 값이 발견된 Credential입니다(오탐 제외). 조치 상황은 '대응 진행률'에서 봅니다.", "Credentials whose value was found in a scanned location (false positives excluded). See 'Remediation progress' for their status.") },
    { label: kindLabel("token", L), value: s.token, icon: "token", tone: "violet", act: () => go2("all", { cat: "token" }),
      tip: L("PAT·봇 토큰처럼 API를 부르는 토큰입니다. 누르면 목록으로 갑니다.", "Tokens that call APIs, such as PATs and bot tokens. Click to open the list.") },
    { label: kindLabel("apikey", L), value: s.apikey, icon: "api", tone: "amber", act: () => go2("all", { cat: "apikey" }),
      tip: L("서비스가 발급한 API 키입니다. 누르면 목록으로 갑니다.", "API keys issued by services. Click to open the list.") },
    { label: kindLabel("cloud", L), value: s.cloud, icon: "cloud", tone: "teal", act: () => go2("all", { cat: "cloud" }),
      tip: L("AWS 액세스 키·GCP 서비스 계정 키 같은 클라우드 키입니다. 누르면 목록으로 갑니다.", "Cloud keys such as AWS access keys and GCP service account keys. Click to open the list.") },
    { label: L("Vault 보관", "Stored in Vault"), value: s.vault, icon: "vault", tone: "green", act: () => go2("vault"),
      tip: L("같은 값이 Vault에 보관된 것으로 지문 대조가 된 Credential입니다.", "Credentials whose value is confirmed in Vault by fingerprint matching.") },
    { label: L("사용 기록 수집", "Usage logs"), value: `${usageProviders.filter(p => inventory.includes(p)).length}/${inventory.length}`, icon: "activity", tone: "pink",
      act: () => admin ? go("sources") : go("inventory"),
      tip: usageOff.length
        ? L(`마지막 사용 시각을 보고하는 발급 목록 연동 수입니다. ${usageOff.map(p => serviceName(p)).join("·")}은 사용 기록이 없어 '미사용'으로 판단하지 않습니다.`, `Issuance inventories that report last use. ${usageOff.map(p => serviceName(p)).join(", ")} report none, so nothing there is treated as unused.`)
        : L("마지막 사용 시각을 보고하는 발급 목록 연동 수입니다.", "Issuance inventories that report last use.") },
  ];

  const pctExp = s.total ? Math.round(s.exposed / s.total * 100) : 0;
  const byIssuer = new Map<string, number>();
  for (const c of items.filter(countable)) byIssuer.set(c.provider, (byIssuer.get(c.provider) ?? 0) + 1);
  const exposureHistory = items.filter(c => c.exposed && c.status !== "fp");
  const removedCount = exposureHistory.filter(isRemoved).length;
  const completedCount = exposureHistory.filter(c => c.response?.state === "COMPLETED").length;
  const pct = exposureHistory.length ? Math.round(completedCount / exposureHistory.length * 100) : 0;
  const trend = openTrend(items, now);
  const kinds = [["token", "var(--s1)"], ["apikey", "var(--s4)"], ["cloud", "var(--s3)"], ["other", "var(--s6)"]] as const;
  const loc = new Map<string, number>(), visCount: Record<string, number> = { public: 0, org: 0, internal: 0, private: 0 };
  const recent: { c: CredentialRecord; e: CredentialRecord["exposures"][number] }[] = [];
  for (const c of items.filter(countable)) {
    for (const e of c.exposures.filter(e => e.current)) {
      const where = exposureService(e.source_type);
      loc.set(where, (loc.get(where) ?? 0) + 1);
      if (e.visibility in visCount) visCount[e.visibility]++;
      recent.push({ c, e });
    }
  }
  recent.sort((a, b) => (time(b.e.first_seen_at) ?? 0) - (time(a.e.first_seen_at) ?? 0));
  const name = (c: CredentialRecord) => c.name || typeLabel(c.credential_type, L);
  const shown = (id: CardId) => !prefs.hidden.includes(id);
  const otherTypes = Array.from(new Set(items.filter(c => c.kind === "other").map(c => typeLabel(c.credential_type, L)))).slice(0, 2);

  const conn = <Card className="area-conn" title={L("수집 연결 현황", "Collection coverage")}
    right={admin ? <button type="button" className="link-btn" onClick={() => go("sources")}>{L("관리", "Manage")} <Ic name="right" size={15} /></button> : undefined}>
    <CardBody>
      <ConnRow icon="key" title={L("발급 목록 수집", "Issuance inventory")} logos={inventory}
        tip={L("발급 서비스가 보고한 키·토큰 목록을 가져옵니다.", "Pulls the keys and tokens each issuer reports.")}
        miss={inventory.length === 0 ? L("연결한 발급 목록이 없습니다", "No issuance inventory connected")
          : inventoryGap.length ? L(`${inventoryGap.map(p => serviceName(p)).join("·")} 발급 목록 연결 안 됨`, `${inventoryGap.map(p => serviceName(p)).join(", ")} inventory not connected`) : null}
        action={admin && (inventory.length === 0 || inventoryGap.length) ? () => go("sources") : undefined} actionLabel={L("연결하기", "Connect")} />
      <ConnRow icon="scan" title={L("노출 검사 위치", "Exposure scan locations")} logos={places}
        tip={L("코드·문서·버킷에서 평문으로 적힌 값을 찾습니다.", "Finds plaintext values in code, documents and buckets.")}
        miss={places.length === 0 ? L("연결한 노출 검사가 없습니다", "No exposure scan connected") : null}
        action={admin && places.length === 0 ? () => go("sources") : undefined} actionLabel={L("연결하기", "Connect")} />
      <ConnRow icon="vault" title={L("Vault 대조", "Vault matching")} logos={vaults.map(p => p === "aws" ? "awssm" : p)}
        tip={L("Vault에 같은 값이 보관돼 있는지 지문으로 대조합니다. 값은 읽지 않습니다.", "Matches fingerprints to see whether Vault holds the same value. Values are never read.")}
        miss={vaultGap.length ? L(`${vaultGap.map(p => vaultName(p, L)).join("·")} 연결 안 됨`, `${vaultGap.map(p => vaultName(p, L)).join(", ")} not connected`)
          : vaults.length === 0 ? L("연결한 Vault가 없습니다", "No vault connected") : null}
        action={admin && (vaultGap.length || vaults.length === 0) ? () => (vaultGap.length === 1 ? go("sources", { connect: vaultGap[0], purpose: "vault" }) : go("vaults")) : undefined}
        actionLabel={L("연결하기", "Connect")} />
      <ConnRow icon="activity" title={L("사용 기록", "Usage logs")} logos={usageProviders}
        tip={L("마지막 사용 시각과 사용 주체를 확인합니다.", "Shows when and by whom a credential was last used.")}
        miss={usageOff.length ? L(`${usageOff.map(p => serviceName(p)).join("·")} 사용 기록 없음`, `${usageOff.map(p => serviceName(p)).join(", ")}: no usage records`) : null}
        action={admin && usageOff.length && ownerOf(usageOff[0]) ? () => go("sources", { edit: ownerOf(usageOff[0])!.id }) : undefined} actionLabel={L("연결 방법", "How to connect")} />
    </CardBody>
  </Card>;

  const risk = <Card className="area-risk" title={L("노출 현황", "Exposure overview")}
    right={<MiniToggle value={prefs.risk} label={L("보기 방식", "View")} onChange={value => save({ ...prefs, risk: value })}
      options={[{ id: "donut", icon: "halfCircle", label: L("비율", "Ratio") }, { id: "bars", icon: "list", label: L("서비스별", "By issuer") }]} />}>
    <CardBody>
      {prefs.risk === "donut" ? <>
        <div className="donut-wrap"><Donut segments={[{ value: s.exposed, color: "var(--crit)" }, { value: s.total - s.exposed, color: "var(--line-strong)" }]}
          center={<>{L("추적 중", "Tracked")}<b className="num">{s.total}</b></>} /></div>
        <div className="legend">
          <div className="legend-row"><span className="sw" style={{ background: "var(--crit)" }} />
            <button type="button" onClick={() => go2("exposed")}><span className="clip">{L("노출 확인", "Exposed")}</span>{" "}
              <InfoTip text={L(`검사한 위치에서 값이 발견된 Credential입니다. 오탐으로 처리한 ${s.fp}건은 셈하지 않습니다.`, `Credentials whose value was found in a scanned location. ${s.fp} false positive${s.fp === 1 ? " is" : "s are"} not counted.`)} /></button>
            <span className="num">{s.exposed}</span><span className="pct num">({pctExp}%)</span></div>
          <div className="legend-row"><span className="sw" style={{ background: "var(--line-strong)" }} />
            <button type="button" onClick={() => go2("all", { "f.where": "none" })}><span className="clip">{L("노출 관측 없음", "Not observed")}</span>{" "}
              <InfoTip text={L("연결한 위치를 검사한 범위에서 발견되지 않은 Credential입니다.", "Credentials not found in the locations the connected scans cover.")} /></button>
            <span className="num">{s.total - s.exposed}</span><span className="pct num">({s.total ? 100 - pctExp : 0}%)</span></div>
        </div>
      </> : <>
        <div className="section-label">{L("발급 서비스별 노출 Credential", "Exposed credentials by issuer")}</div>
        {byIssuer.size ? <BarList color="var(--crit)" rows={Array.from(byIssuer).sort((a, b) => b[1] - a[1]).map(([provider, value]) => ({
          key: provider, value, name: <><Logo id={provider} size={18} /><span className="clip">{serviceName(provider)}</span></> }))} />
          : <div className="meta">{L("노출된 Credential이 없습니다.", "No exposed credentials.")}</div>}
      </>}
    </CardBody>
  </Card>;

  const remed = <Card className="area-remed" title={L("자격증명 대응 현황", "Credential response status")}
    info={L("담당자 보고·승인과 평문 제거, 기존 키 종료, 필요한 교체 키 보관을 모두 확인한 조치 완료 비율입니다. 과거 제거 확인만 있는 항목은 완료에 포함하지 않습니다.", "Completion requires an owner report and approval, plaintext removal, old-key retirement and replacement storage where needed. Legacy removal-only records do not count as completed.")}
    right={<MiniToggle value={prefs.remed} label={L("보기 방식", "View")} onChange={value => save({ ...prefs, remed: value })}
      options={[{ id: "gauge", icon: "activity", label: L("진행률", "Progress") }, { id: "trend", icon: "history", label: L("추이", "Trend") }]} />}>
    <CardBody>
      {prefs.remed === "gauge"
        ? <div className="gauge-wrap"><Gauge percent={pct} /><div className="gauge-inner"><div className="gauge-value num">{pct}%</div>
          <div className="gauge-cap">{L("조치 완료 ", "Completed ")}{completedCount}/{exposureHistory.length}</div></div></div>
        : <><div className="section-label">{L("미조치 노출 추정 (최근 8주)", "Estimated open exposures (last 8 weeks)")}</div><Sparkline values={trend} />
          <div className="meta">{L(`현재 미조치 ${s.open}건 · 과거는 발견·종료 시각 기준 추정이며 제거·재발견 이력을 완전히 반영하지 못합니다.`, `Currently open: ${s.open}. Historical points are estimated from first-found and closed dates and do not fully reconstruct removal or recurrence.`)}</div></>}
      <div className="remed-list">
        <RemedRow label={L("조치 완료 / 대응 대상", "Completed / response cases")} value={`${completedCount}/${exposureHistory.length}`} tone="tone-ok" />
        <RemedRow label={L("제거 확인 / 전체 노출 이력", "Removal confirmed / all exposure history")} value={`${removedCount}/${exposureHistory.length}`} tone="tone-ok" />
        <RemedRow label={L("폐기 확인", "Revocation confirmed")} value={items.filter(c => countable(c) && c.verification.state === "revoked").length} />
        <RemedRow label={L("진행 중", "In progress")} value={`${s.review + s.action}/${s.exposed}`} tone="tone-warn" />
        <RemedRow label={L("검토 중", "In review")} value={s.review} />
        <RemedRow label={L("조치 중", "Remediating")} value={s.action} />
        <RemedRow label={L("미착수", "Not started")} value={`${s.pending}/${s.exposed}`} tone="tone-bad" />
        <RemedRow label={L("검토 대기", "Pending review")} value={s.pending} />
        <RemedRow label={L("그중 소유자 미확인", "…of which owner unknown")} value={s.pendingNoOwner} />
      </div>
    </CardBody>
  </Card>;

  const controls = <Card className="area-controls" title={L("점검 항목", "Risk checks")}
    right={<button type="button" className="link-btn" onClick={event => checksMenu.open(event.currentTarget)}>{L("구성", "Customize")} <Ic name="sliders" size={15} /></button>}>
    <CardBody><div className="controls">
      {CHECKS.filter(check => !prefs.checks.includes(check.key)).map(check => {
        const n = items.filter(c => check.test(c, now)).length;
        const exposedCheck = ["public", "active", "novault", "org"].includes(check.key);
        return <button type="button" key={check.key} className={cls("control", check.hot && n > 0 && "hot")}
          onClick={() => go2(exposedCheck ? "exposed" : "all", { check: check.key })}>
          <span className="c-ic"><Ic name={check.icon} size={18} /></span>
          <span className="c-text"><span className="c-title">{check.title(L)}</span><span className="c-sub">{cnt(n, locale)}</span></span>
          {check.hot && n > 0 ? <span className="dot" /> : null}
          <InfoTip text={check.tip(L)} />
        </button>;
      })}
      {usageOff.length ? <button type="button" className="control nodata" onClick={() => admin ? go("sources") : undefined}>
        <span className="c-ic"><Ic name="activity" size={18} /></span>
        <span className="c-text"><span className="c-title">{L("마지막 사용 판단", "Last-use checks")}</span>
          <span className="c-sub">{L(`${usageOff.map(p => serviceName(p)).join("·")} 사용 기록 없음`, `${usageOff.map(p => serviceName(p)).join(", ")}: no usage records`)}</span></span>
      </button> : null}
    </div></CardBody>
  </Card>;

  const types = <Card className="area-types" title={L("Credential 유형", "Credential types")}>
    <CardBody>
      <div className="donut-wrap"><Donut segments={kinds.map(([id, color]) => ({ value: s[id], color }))} center={<>{L("전체", "Total")}<b className="num">{s.total}</b></>} /></div>
      <div className="legend">
        {kinds.map(([id, color]) => <div className="legend-row" key={id}><span className="sw" style={{ background: color }} />
          <button type="button" onClick={() => go2("all", { cat: id })}><span className="clip">{kindLabel(id, L)}{id === "other" && otherTypes.length ? ` (${otherTypes.join(", ")})` : ""}</span></button>
          <span className="num">{s[id]}</span><span className="pct num">({s.total ? Math.round(s[id] / s.total * 100) : 0}%)</span></div>)}
      </div>
    </CardBody>
  </Card>;

  const where = <Card className="area-where" title={L("노출 위치", "Exposure locations")} meta={<span className="clip">{L("검사 범위 안에서 발견된 곳", "Found within scan coverage")}</span>}>
    <CardBody><div className="where-grid">
      <div>
        <div className="section-label">{L("위치별 노출 건수", "Exposures by location")}</div>
        {loc.size ? <BarList rows={Array.from(loc).sort((a, b) => b[1] - a[1]).map(([place, value]) => ({
          key: place, value, name: <><Logo id={place} size={18} /><span className="clip">{serviceName(place)}</span></> }))} />
          : <div className="meta">{L("발견된 노출 위치가 없습니다.", "No exposure locations found.")}</div>}
        <div className="section-label where-vis-label">{L("공개 범위별", "By visibility")}</div>
        <div className="vis-chips">{VIS_ORDER.map(v => <span key={v} className={`vis vis-${v} tag`}>{visLabel(v, L)} <b className="num">{visCount[v]}</b></span>)}</div>
      </div>
      <div>
        <div className="section-label">{L("최근 발견", "Recently found")}</div>
        <div className="recent">
          {recent.slice(0, 5).map(({ c, e }) => <button type="button" key={`${c.id}:${e.resource_name}:${e.location}`} data-tip={`${e.resource_name} · ${e.location}`}
            onClick={() => go("exposed", { id: c.id })}>
            <Logo id={exposureService(e.source_type)} size={26} />
            <span className="r-text"><span className="t1">{name(c)}</span><span className="t2">{e.resource_name} · {e.location}</span></span>
            <span className="meta">{rel(e.first_seen_at, locale, now)}</span>
          </button>)}
          {!recent.length ? <div className="meta">{L("아직 발견된 노출이 없습니다.", "No exposures found yet.")}</div> : null}
        </div>
      </div>
    </div></CardBody>
  </Card>;

  const cards: Record<CardId, ReactNode> = { conn, risk, remed, controls, types, where };
  const cardName: Record<CardId, string> = { conn: L("수집 연결 현황", "Collection coverage"), risk: L("노출 현황", "Exposure overview"),
    remed: L("대응 진행률", "Remediation progress"), controls: L("점검 항목", "Risk checks"), types: L("Credential 유형", "Credential types"), where: L("노출 위치", "Exposure locations") };

  return <>
    <PageHead title={L("Credential 관리 현황", "Credential overview")} meta={lastCollected ? L(`마지막 수집 ${fmtDT(lastCollected, locale)}`, `Last collected ${fmtDT(lastCollected, locale)}`) : undefined} />
    <SubBar>
      <button type="button" className="ghost-btn" onClick={event => filterMenu.open(event.currentTarget)} disabled={providersPresent.length < 2}
        aria-disabled={providersPresent.length < 2 || undefined}>
        <Ic name="filter" size={16} />{L("필터", "Filters")}{chosen.length ? <span className="filter-count">{chosen.length}</span> : null}
      </button>
      <button type="button" className="ghost-btn" onClick={event => layoutMenu.open(event.currentTarget)}><Ic name="columns" size={16} />{L("화면 구성", "Customize")}</button>
      {chosen.length ? <span className="applied-chip"><span className="clip">{L("발급 서비스: ", "Issuer: ")}{chosen.map(p => serviceName(p)).join(", ")}</span>
        <button type="button" onClick={() => save({ ...prefs, providers: [] })} aria-label={L("필터 해제", "Clear filter")}><Ic name="close" size={13} /></button></span> : null}
    </SubBar>
    {filterMenu.anchor ? <Menu anchor={filterMenu.anchor} onClose={filterMenu.close} restore={filterMenu.opener} label={L("발급 서비스 필터", "Issuer filter")}>
      <MenuLabel>{L("발급 서비스", "Issuer")}</MenuLabel>
      {providersPresent.map(p => <MenuItem key={p} checked={chosen.includes(p)} onSelect={() => save({ ...prefs, providers: chosen.includes(p) ? chosen.filter(x => x !== p) : [...chosen, p] })}
        end={all.filter(c => c.provider === p).length}>{serviceName(p)}</MenuItem>)}
    </Menu> : null}
    {checksMenu.anchor ? <Menu anchor={checksMenu.anchor} onClose={checksMenu.close} restore={checksMenu.opener} label={L("점검 항목 구성", "Customize checks")}>
      <MenuLabel>{L("표시할 점검 항목", "Checks to show")}</MenuLabel>
      {CHECKS.map(check => <MenuItem key={check.key} checked={!prefs.checks.includes(check.key)}
        onSelect={() => save({ ...prefs, checks: prefs.checks.includes(check.key) ? prefs.checks.filter(x => x !== check.key) : [...prefs.checks, check.key] })}>{check.title(L)}</MenuItem>)}
    </Menu> : null}
    {layoutMenu.anchor ? <Menu anchor={layoutMenu.anchor} onClose={layoutMenu.close} restore={layoutMenu.opener} label={L("화면 구성", "Customize")}>
      <MenuLabel>{L("표시할 카드", "Cards to show")}</MenuLabel>
      {CARDS.map(id => <MenuItem key={id} checked={shown(id)} onSelect={() => save({ ...prefs, hidden: shown(id) ? [...prefs.hidden, id] : prefs.hidden.filter(x => x !== id) })}>{cardName[id]}</MenuItem>)}
    </Menu> : null}
    {!all.length ? <Banner>{admin ? L("연동 서비스를 연결하면 발급 목록과 노출 검사 결과가 여기에 모입니다.", "Connect integrations and their inventories and scan results gather here.")
      : L("아직 수집된 Credential이 없습니다.", "No credentials collected yet.")}</Banner> : null}
    {records.data && !records.data.complete ? <Banner tone="warn" icon="alert">{L("대조 한도를 넘어 일부 Credential만 셌습니다.", "The comparison limit was reached, so only part of the credentials were counted.")}</Banner> : null}
    <Tiles>{tiles.map(tile => <Tile key={tile.label} icon={tile.icon} tone={tile.tone} label={tile.label} value={tile.value} tip={tile.tip} onClick={tile.act} />)}</Tiles>
    <div className={cls("dash-grid", prefs.hidden.length > 0 && "custom")}>{CARDS.filter(shown).map(id => <div key={id} style={{ display: "contents" }}>{cards[id]}</div>)}</div>
  </>;
}

// The secret store a provider keeps, by the name people call it.
const VAULT_NAMES: Record<string, [string, string]> = {
  aws: ["AWS Secrets Manager", "AWS Secrets Manager"], gcp: ["GCP Secret Manager", "GCP Secret Manager"], azure: ["Azure Key Vault", "Azure Key Vault"],
  gitlab: ["GitLab CI 변수", "GitLab CI variables"], github: ["GitHub Actions 시크릿", "GitHub Actions secrets"],
};
function vaultName(provider: string, L: (ko: string, en: string) => string) {
  const known = VAULT_NAMES[provider];
  return known ? L(...known) : serviceName(provider);
}

function ConnRow({ icon, title, logos, tip, miss, action, actionLabel }: {
  icon: IconName; title: string; logos: string[]; tip: string; miss?: string | null; action?: () => void; actionLabel?: string;
}) {
  return <div className="conn-row">
    <span className="conn-ic"><Ic name={icon} size={18} /></span>
    <div className="conn-text">
      <div className="conn-title">{title} <InfoTip text={tip} /></div>
      {logos.length ? <div className="logo-row">{logos.map(id => <Logo key={id} id={id} size={24} />)}</div> : null}
      {miss ? <div className="conn-miss"><Ic name="lockOpen" size={13} /><span>{miss}</span>
        {action ? <a href="?view=sources" onClick={event => { event.preventDefault(); action(); }}>{actionLabel}</a> : null}</div> : null}
    </div>
  </div>;
}

function RemedRow({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return <div className={cls("remed-row", tone && `head ${tone}`)}><span>{label}</span><span className="num">{value}</span></div>;
}
