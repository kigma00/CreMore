"use client";

/* Integrations: the services connected, the services that can be connected, secret stores and other
 * settings, in the design's layout. A provider connection is one row; its state comes from the
 * health of the records it owns (operations/connections) and from its permission check. */

import { type ReactNode, useEffect, useMemo, useState } from "react";

import { useLocale } from "@/components/locale";
import { reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic, type IconName } from "@/console/icons";
import { Menu, MenuItem, MenuLabel, MenuSep, Modal, useMenu, useToast } from "@/console/layer";
import { Logo, markOf } from "@/console/logos";
import { RECORDS_PATH, type RecordsResponse } from "@/console/records";
import type { ViewProps } from "@/console/shell";
import { fmtDT, rel, useL } from "@/console/text";
import { Banner, Card, cls, Empty, ErrorLine, Loading, PageHead, Seg, Tile, Tiles } from "@/console/ui";
import { TextModal } from "@/console/views/credentials/modals";
import { capName, CUSTOMER_SIDE, description, methodShort } from "@/console/views/integrations/copy";
import {
  type Catalog, type CollectionEntry, forCollectionEntry, CATALOG_PATH, CONNECTIONS_PATH, type Descriptor, type Health, HEALTH_PATH, healthOf,
  enabledPurposes, inEntryView, inventoryCount, label, lastRun, onboardingText, peopleDirectoryBlock, type ProviderConnection, type Purpose, PURPOSE_ORDER,
  rowState, scanEntryOf, sharedFix, sharedNote, shortName, type Suggestion, SUGGESTIONS_PATH, suggestionText,
} from "@/console/views/integrations/model";
import {
  accountFeatures, accountNote, accountOwner, badges, CONNECTION_FIXES, contentOwner, contentStartable, live, liveIn, sectionCounts,
  runnableIn, sectionsOf, sectionState, sectionView, SECTIONS,
} from "@/console/views/integrations/sections";
import { readProfiles, scopedCount, scopeTargets, unitOf } from "@/console/views/integrations/scope";
import { MACHINE_PATH, MachineIdentityModal, machineState, type MachineView } from "@/console/views/integrations/machine";
import { enterpriseReady, GitHubEnterpriseModal } from "@/console/views/integrations/github-enterprise";
import { type ContactChannels, ContactDeliveryModal, contactState } from "@/console/views/integrations/contact-delivery";
import { TicketSystemModal, ticketState, type TicketSystemStatus } from "@/console/views/integrations/ticket-system";
import { type ResponseChannelOption, ResponseChannelsModal, responseChannelsState } from "@/console/views/integrations/response-channels";
import { DOMAIN_STATUS_PATH, type DomainList, DomainsModal, domainState } from "@/console/views/integrations/domains";
import { ReachModal, reachKind } from "@/console/views/integrations/reach";
import { TargetsModal } from "@/console/views/integrations/targets";
import { collectConnection } from "@/console/views/integrations/collect";
import { ConnectWizard, type WizardOpen } from "@/console/views/integrations/wizard";

type Category = "all" | "code" | "cloud" | "saas" | "detect";
// The catalog's categories on this screen; vault and identity providers are reached from the side cards.
const SHOWN: Category[] = ["code", "cloud", "saas"];
const CAP_ICON: Record<Purpose, IconName> = { inventory: "key", exposure: "scan", vault: "vault", identity: "users", remediation: "shield" };
const CAP_CLASS: Record<Purpose, string> = { inventory: "inv", exposure: "scan", vault: "vault", identity: "idp", remediation: "act" };
// Detection-only services the design shows as cards; the rest are counted on the last card.
const DETECT_CARDS = ["slack", "stripe", "sentry"];
const NOT_A_SERVICE = new Set(["generic", "database"]);

type Engine = { detectors: { provider: string; enabled: boolean }[] };
type Siem = { destinations: { destination: string }[]; exporter_active: boolean };

export function Integrations({ session, route, go, setParams, can }: ViewProps) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const catalog = useApi<Catalog>(CATALOG_PATH);
  const [fast, setFast] = useState(false);
  const connections = useApi<ProviderConnection[]>(CONNECTIONS_PATH, { every: fast ? 5_000 : 30_000 });
  const health = useApi<Health>(HEALTH_PATH, { every: 60_000 });
  const records = useApi<RecordsResponse>(RECORDS_PATH, { every: 60_000 });
  const engine = useApi<Engine>("detection-engine");
  const siem = useApi<Siem>(session.role === "Admin" ? "siem/status" : null);
  const [cat, setCat] = useState<Category>("all");
  const [wizard, setWizard] = useState<WizardOpen | null>(null);
  const [targetsFor, setTargetsFor] = useState<ProviderConnection | null>(null);
  const [enterpriseFor, setEnterpriseFor] = useState<ProviderConnection | null>(null);
  const [reachFor, setReachFor] = useState<ProviderConnection | null>(null);
  const [machineOpen, setMachineOpen] = useState(false);
  const machine = useApi<MachineView>(session.role === "Admin" ? MACHINE_PATH : null);
  const [contactOpen, setContactOpen] = useState(false);
  const delivery = useApi<ContactChannels>(session.role === "Viewer" ? null : "contact-delivery");
  const [ticketOpen, setTicketOpen] = useState(false);
  const tickets = useApi<TicketSystemStatus>(session.role === "Viewer" ? null : "ticket-system");
  const [channelsOpen, setChannelsOpen] = useState(false);
  const responseChannels = useApi<{ channels: ResponseChannelOption[] }>(session.role === "Viewer" ? null : "response-channels");
  const [domainsOpen, setDomainsOpen] = useState(false);
  const domainList = useApi<DomainList>(session.role === "Viewer" ? null : DOMAIN_STATUS_PATH);
  const suggested = useApi<{ items: Suggestion[] }>(session.role === "Admin" ? SUGGESTIONS_PATH : null);
  const [confirm, setConfirm] = useState<{ c: ProviderConnection; action: "disable" | "delete" } | null>(null);
  const [renaming, setRenaming] = useState<ProviderConnection | null>(null);
  const [menuFor, setMenuFor] = useState<{ c: ProviderConnection; entry: CollectionEntry } | null>(null);
  // ``people``: a menu of people directories, where a team install takes only the sign-in IdP.
  const [chooser, setChooser] = useState<{ title: string; providers: string[]; people?: boolean; entry?: CollectionEntry } | null>(null);
  const rowMenu = useMenu();
  const chooserMenu = useMenu();

  useEffect(() => { setFast(Boolean(connections.data?.some(c => c.status === "CHECKING"))); }, [connections.data]);

  // How many repositories, buckets or pages each running exposure scan has in its approved scope.
  const [scopes, setScopes] = useState<Map<string, { count: number; unit: string }>>(new Map());
  useEffect(() => {
    const running = (connections.data ?? []).filter(c => c.status === "ACTIVE" && c.plans.exposure && c.feature_enabled?.exposure !== false);
    let live = true;
    Promise.all(running.map(async c => {
      const targets = scopeTargets(c);
      const counts = await Promise.all(targets.map(target => readProfiles(target).then(page => scopedCount(page.profiles)).catch(() => 0)));
      return [c.id, { count: counts.reduce((sum, n) => sum + n, 0), unit: unitOf(targets[0]?.sourceType ?? c.provider, L) }] as const;
    })).then(entries => { if (live) setScopes(new Map(entries)); });
    return () => { live = false; };
  }, [connections.data, L]);

  // Links into this screen: ?connect=<provider>, ?edit=<connection>&step=2, and the Google return. ``entry``
  // (account | exposure) keeps a link's flow on its side, as a provider's return page sends it back.
  useEffect(() => {
    const oauth = route.params.get("gcp_oauth"), editing = route.params.get("edit"), connect = route.params.get("connect");
    const asked = route.params.get("entry");
    const entry: CollectionEntry | undefined = asked === "account" || asked === "exposure" ? asked : undefined;
    // An account found by search opens the integration that reaches it.
    const account = route.params.get("account");
    if (account && connections.data) {
      const owner = connections.data.find(c => c.children.some(child => child.id === account));
      setParams({ account: null });
      if (owner) { setWizard({ id: owner.id }); return; }
    }
    if (oauth) { setWizard({ oauth }); setParams({ gcp_oauth: null }); }
    else if (editing) {
      const step = Number(route.params.get("step"));
      setWizard({ id: editing, ...(step === 1 || step === 2 || step === 3 ? { step } : {}), ...(entry ? { entry } : {}) });
      setParams({ edit: null, step: null, entry: null });
    } else if (connect) {
      if (!catalog.data) return; // the link is followed once the catalog says what replaced what
      const purpose = route.params.get("purpose");
      if (purpose === "exposure" && connect !== "website" && !entry) {
        // Content starts from an existing owner, including when reached by an old deep link.
        setParams({ connect: null, purpose: null });
        document.getElementById("ig-content")?.scrollIntoView({ behavior: "smooth" });
        toast(L("콘텐츠 검사 위치에서 연결된 계정을 선택하세요. 계정이 없으면 먼저 연결해 주세요.",
          "Choose a connected account under content scan connections. Connect an account first if needed."));
        return;
      }
      // A link to a replaced provider opens the one that replaced it, with the same feature.
      const replaced = catalog.data.providers.find(d => d.provider === connect)?.replaced_by;
      setWizard({ provider: replaced ?? connect, ...(entry ? { entry } : {}),
        ...(purpose ? { purpose } : entry === "exposure" ? { purpose: "exposure" } : {}) });
      setParams({ connect: null, purpose: null, entry: null });
    }
  }, [route.params, setParams, connections.data, catalog.data, toast, L]);

  const providers = useMemo(() => new Map((catalog.data?.providers ?? []).map(d => [d.provider, d])), [catalog.data]);
  // What a new connection is made with: a provider another replaced (Entra ID people -> Microsoft) is not offered.
  // A provider started elsewhere (websites, from the domain screen) is not a card of the grid.
  const offered = useMemo(() => (catalog.data?.providers ?? []).filter(d => !d.replaced_by && !d.entry && d.auth_methods.some(m => m.new_setup !== false)), [catalog.data]);
  const order = useMemo(() => (catalog.data?.providers ?? []).map(d => d.provider), [catalog.data]);
  const list = useMemo(() => [...(connections.data ?? [])].sort((a, b) =>
    (order.indexOf(a.provider) - order.indexOf(b.provider)) || a.name.localeCompare(b.name)), [connections.data, order]);
  const items = records.data?.items;
  const healthItems = health.data?.items;

  const refreshError = catalog.error ?? connections.error;
  // useApi keeps the last good result. Keep its editors mounted too, including unsaved auth input.
  if ((!catalog.data || !connections.data) && refreshError) return <><PageHead title={L("연동 서비스", "Integrations")} />
    <ErrorLine onRetry={() => { catalog.reload(); connections.reload(); }}>{reasonText(refreshError, L)}</ErrorLine></>;
  if (!catalog.data || !connections.data) return <><PageHead title={L("연동 서비스", "Integrations")} /><Loading /></>;

  const states = new Map(list.map(c => [c.id, rowState(c, healthOf(c, healthItems), L, undefined, providers.get(c.provider))]));
  const connectedProviders = new Set(list.filter(c => liveIn(c)).map(c => c.provider));
  const issues = list.filter(c => ["warn", "partial", "setup"].includes(states.get(c.id)!.tone)).length;
  const issued = (items ?? []).filter(r => r.issued).length;
  const scanPlaces = list.filter(c => c.status === "ACTIVE" && c.feature_enabled?.exposure !== false).reduce((sum, c) => sum + (scopes.get(c.id)?.count ?? 0), 0);
  const newest = lastRun(list.flatMap(c => healthOf(c, healthItems)));
  const byProvider = (provider: string) => list.filter(c => c.provider === provider);
  // The domains a website integration already scans; a new one starts with the others.
  const scannedDomains = new Set(byProvider("website").flatMap(c => (Array.isArray(c.target.domains) ? c.target.domains : [])
    .filter((name): name is string => typeof name === "string")));

  const openConnect = (provider: string, entry?: CollectionEntry) => setWizard({ provider, entry, ...(entry === "exposure" ? { purpose: "exposure" } : {}) });
  const openChooser = (element: HTMLElement, title: string, ids: string[], people = false, entry?: CollectionEntry) => { setChooser({ title, providers: ids, people, entry }); chooserMenu.open(element); };
  const inEntry = (c: ProviderConnection, entry?: CollectionEntry) => !entry || entry === "account" || c.purposes.includes("exposure");
  // The account card offers connections with account features; content reuses a credential owner, then checks its read access.
  const eligible = (provider: string, entry: CollectionEntry) => byProvider(provider).filter(c =>
    entry === "account" ? accountOwner(c, providers.get(provider)) : contentOwner(c));
  // An existing connection opened from a card or its chooser: content on a credential that cannot read content is a new sign-in.
  const openExisting = (c: ProviderConnection, entry?: CollectionEntry) => {
    const method = providers.get(c.provider)?.auth_methods.find(m => m.id === c.auth_method);
    if (entry === "exposure" && !method?.purposes.includes("exposure")) setWizard({ provider: c.provider, edition: c.edition, entry: "exposure", purpose: "exposure" });
    else setWizard({ id: c.id, ...(entry ? { entry } : {}), ...(!inEntry(c, entry) ? { addPurpose: "exposure" } : {}) });
  };

  async function run(c: ProviderConnection, action: "check" | "enable" | "disable" | "delete" | "collect", purposes?: Purpose[]) {
    try {
      if (action === "check") { await send(`${CONNECTIONS_PATH}/${c.id}/check`, "POST"); toast(L("권한 확인을 요청했습니다", "Access check requested")); }
      else if (action === "enable") { await send(`${CONNECTIONS_PATH}/${c.id}/enable`, "POST"); toast(L("연동을 다시 켰습니다", "Integration turned back on")); }
      else if (action === "disable") { await send(`${CONNECTIONS_PATH}/${c.id}/disable`, "POST"); toast(L("연동을 해제했습니다. 수집 기록은 남아 있습니다", "Integration disconnected. Its collection records are kept")); }
      else if (action === "delete") { await send(`${CONNECTIONS_PATH}/${c.id}`, "DELETE"); toast(L("연동을 지웠습니다", "Integration deleted")); }
      else await collectNow(c, purposes);
      saved();
    } catch (reason) {
      toast(onboardingText(reason instanceof Error ? reason.message : "", [], L) ?? reasonText(reason, L), "bad");
    }
  }

  // "Collect now": every owned record of the row's section that runs from here -- a server collection, and a run of
  // each approved exposure scope (a place without one is left until its scope is set).
  async function collectNow(c: ProviderConnection, purposes?: Purpose[]) {
    const results = await collectConnection(c, undefined, purposes);
    const started = results.filter(result => !result.error).length;
    const customer = results.filter(result => result.error?.startsWith("VAULT_COLLECTION_RUNS_IN_CUSTOMER_ENVIRONMENT")).length;
    const failed = results.length - started - customer;
    if (started) toast(L(`수집을 시작했습니다 (${started}건)`, `Collection started (${started})`));
    if (customer) toast(L("고객 환경의 CLI가 실행할 때 수집합니다", "Collected when the CLI in your environment runs"));
    if (failed) toast(L(`${failed}건은 시작하지 못했습니다`, `${failed} could not start`), "bad");
    if (!results.length) toast(L("여기서 바로 실행할 수집이 없습니다", "Nothing here runs on demand"));
  }

  const fix = (c: ProviderConnection, kind: NonNullable<ReturnType<typeof rowState>["fix"]>) => {
    if (kind === "resume") setWizard({ id: c.id });
    else if (kind === "reauth") setWizard({ id: c.id, step: 2 });
    else if (kind === "credential") setWizard({ id: sharedFix(c), step: 2 });
    else if (kind === "recheck") void run(c, "check");
    else go("scans", { connection: c.id });
  };
  const fixLabel = { resume: L("이어서 설정", "Continue setup"), reauth: L("인증 갱신", "Renew"), credential: L("자격증명 바꾸기", "Change credential"),
    recheck: L("권한 다시 확인", "Check again"), logs: L("자세히", "Details") };
  const credentialLabel = (c: ProviderConnection) => (sharedFix(c) === c.id ? fixLabel.credential : L("조치 연동 열기", "Open the acting integration"));

  /* ---------- tiles ---------- */

  const pageProviders = offered;
  const tiles = <Tiles className="ig-tiles">
    <Tile icon="plug" tone="blue" label={L("연동된 서비스", "Connected services")} value={connectedProviders.size} of={pageProviders.length}
      tip={L(`연동 가능한 서비스 ${pageProviders.length}개 중 ${connectedProviders.size}개를 연동했습니다.`, `${connectedProviders.size} of ${pageProviders.length} available services are connected.`)}
      onClick={() => document.getElementById("ig-conn")?.scrollIntoView({ behavior: "smooth", block: "start" })} />
    <Tile icon="alert" tone={issues ? "amber" : "green"} label={L("확인 필요", "Needs attention")} value={issues}
      tip={L("인증 만료가 다가오거나 수집이 일부 실패했거나 설정을 마치지 않은 연동입니다.", "Integrations with expiring sign-in, partly failed collection or unfinished setup.")}
      onClick={() => document.getElementById("ig-conn")?.scrollIntoView({ behavior: "smooth", block: "start" })} />
    <Tile icon="key" tone="violet" label={L("발급 목록에서 수집", "From issuance inventories")} value={records.data ? issued : "—"}
      tip={L("발급 목록에서 가져온 Credential 수입니다. 누르면 목록으로 갑니다.", "Credentials pulled from issuance inventories. Click to open the list.")}
      onClick={() => go("inventory", { "f.provider": [...new Set((items ?? []).filter(r => r.issued).map(r => r.provider))].join(",") || null })} />
    <Tile icon="scan" tone="teal" label={L("노출 검사 위치", "Exposure scan locations")} value={scanPlaces}
      tip={L("노출을 검사하는 저장소·버킷·페이지 수입니다.", "Repositories, buckets and pages scanned for exposures.")}
      onClick={() => document.getElementById("ig-conn-exposure")?.scrollIntoView({ behavior: "smooth", block: "start" })} />
  </Tiles>;

  /* ---------- connected services ---------- */

  const sectionTitle: Record<CollectionEntry, string> = { account: L("계정·발급 목록 연결", "Account and inventory connections"),
    exposure: L("콘텐츠 검사 위치 연결", "Content scan connections") };
  const sectionShort: Record<CollectionEntry, string> = { account: L("계정", "account"), exposure: L("콘텐츠 검사", "content scan") };
  const badgeWord = { on: L("켜짐", "on"), off: L("꺼짐", "off"), missing: L("권한 부족", "missing access"), pending: L("설정 중", "setting up") };
  const head = <div className="ig-row head" aria-hidden="true">
    <span>{L("서비스", "Service")}</span><span>{L("기능", "Features")}</span><span>{L("연동 방식", "Method")}</span>
    <span>{L("상태", "Status")}</span><span>{L("마지막 수집", "Last run")}</span><span>{L("수집 결과", "Results")}</span><span />
  </div>;
  // One row per connection and section it has features in; an AWS account with inventory and S3 scans is in both.
  const row = (c: ProviderConnection, entry: CollectionEntry) => {
    const d = providers.get(c.provider);
    const state = sectionState(c, entry, healthItems, L, d);
    // Connection-wide fixes (and the shared-credential line) once, on the first of its rows.
    const first = sectionsOf(c, d)[0] === entry;
    const last = lastRun(healthOf(sectionView(c, entry), healthItems));
    const method = d?.auth_methods.find(item => item.id === c.auth_method);
    const edition = d && d.editions.length > 1 && d.editions[0].id !== c.edition ? d.editions.find(item => item.id === c.edition) : undefined;
    const results: ReactNode[] = [];
    const scope = scopes.get(c.id);
    const unscoped = entry === "exposure" && live(c, "exposure") && scope !== undefined && scope.count === 0;
    if (c.status === "ACTIVE") {
      if (entry === "account" && c.plans.inventory) {
        const n = inventoryCount(d, c, items);
        results.push(<button type="button" key="inv" className="link-btn" onClick={() => go("inventory", { "f.provider": c.provider })}>{L(`Credential ${n}개`, `${n} credential${n === 1 ? "" : "s"}`)}</button>);
      }
      if (entry === "exposure" && c.plans.exposure && scope?.count) results.push(<span key="exp" className="ig-sub">{L(`${scope.unit} ${scope.count}개`, `${scope.count} ${scope.unit}`)}</span>);
      if (state.tone === "running" && !last) results.splice(0, results.length, <span key="first" className="ig-sub">{L("첫 수집 중", "First run in progress")}</span>);
    }
    const fixShown = state.fix && (first || !CONNECTION_FIXES[state.fix]) && (state.fix !== "logs" || can("scans"));
    return <div className="ig-row" key={`${c.id}:${entry}`}>
      <div className="ig-svc"><Logo id={c.provider} size={34} />
        <div className="ig-svc-text"><b>{d ? label(d, L) : c.provider}{edition ? <> <span className="ig-sub">{label(edition, L)}</span></> : null}</b>
          <span className="ig-sub">{shortName(d, c)}</span></div></div>
      <div className="ig-feat"><span className="ig-lbl">{L("기능", "Features")}</span>
        <div className="ig-caps">{badges(c, entry, d, L, sectionCounts(d, c, scope?.count)).map(b => {
          // What a held feature lacks is part of the badge's text for a screen reader, and its tooltip on focus.
          const lacks = b.state === "missing" ? (b.missing.length ? L(`없는 권한: ${b.missing.join(", ")}`, `Missing: ${b.missing.join(", ")}`)
            : L("권한 확인을 통과하지 못했습니다", "The access check did not pass")) : null;
          return <span key={b.purpose} className={cls("cap", b.state === "on" ? CAP_CLASS[b.purpose] : b.state === "missing" ? "warn" : "det")} data-state={b.state}
            tabIndex={lacks ? 0 : undefined}
            data-tip={lacks ?? (b.state === "off" ? L("기능 꺼짐 · 설정과 이력은 유지", "Feature off · settings and history kept") : b.state === "pending" ? L("아직 시작하지 않았습니다", "Not started yet") : undefined)}>
            <Ic name={CAP_ICON[b.purpose]} size={14} /><span className="clip">{capName(b.purpose, L, b.count ?? 0)} · {badgeWord[b.state]}</span>
            {lacks ? <span className="sr"> · {lacks}</span> : null}</span>;
        })}</div></div>
      <div className="ig-auth"><span className="ig-lbl">{L("연동 방식", "Method")}</span>
        <span className="tag" data-tip={method ? label(method, L) : undefined}><Ic name={method && (method.renewal === "AUTOMATIC" || method.renewal === "ROTATES" || method.renewal === "REFRESH") && !CUSTOMER_SIDE.has(method.id) ? "shield" : CUSTOMER_SIDE.has(c.auth_method) ? "server" : "key"} size={13} />{methodShort(method, L)}</span></div>
      <div className="ig-st"><span className={cls("igs", state.tone)}><span className="dot" />{state.label}</span>
        {state.choose ? <div className="ig-note">{state.note} <button type="button" className="link-btn" onClick={() => setWizard({ id: c.id, entry: "exposure" })}>{L("검사 위치 고르기", "Choose scan locations")}</button></div>
          : unscoped && (state.tone === "ok" || state.tone === "running")
            ? <div className="ig-note">{L("노출 검사 범위를 정하지 않았습니다", "No exposure scan scope is set")} <button type="button" className="link-btn" onClick={() => setTargetsFor(c)}>{L("검사 대상 정하기", "Choose targets")}</button></div>
            : state.note ? <div className="ig-note">{state.note}{fixShown ? <> <button type="button" className="link-btn" onClick={() => fix(c, state.fix!)}>
              {state.fix === "credential" ? credentialLabel(c) : fixLabel[state.fix!]}</button></> : null}</div> : null}
        {/* A credential shared across collecting and acting stays in view whatever else the row says. */}
        {first && state.fix !== "credential" && c.status !== "DISABLED" && sharedNote(c, L) ? <div className="ig-note">{sharedNote(c, L)} <button type="button" className="link-btn"
          onClick={() => fix(c, "credential")}>{credentialLabel(c)}</button></div> : null}</div>
      <div className="ig-last"><span className="ig-lbl">{L("마지막 수집", "Last run")}</span>
        {last ? <span data-tip={fmtDT(last, locale)}>{rel(last, locale)}</span> : <span className="subtle">—</span>}</div>
      <div className="ig-res"><span className="ig-lbl">{L("수집 결과", "Results")}</span>{results.length ? results : <span className="subtle">—</span>}</div>
      <div className="ig-more"><button type="button" className="icon-btn" aria-label={L(`${c.name} · ${sectionShort[entry]} 연동 메뉴`, `${c.name} · ${sectionShort[entry]} integration menu`)} aria-haspopup="menu"
        onClick={event => { setMenuFor({ c, entry }); rowMenu.open(event.currentTarget); }}><Ic name="dots" size={18} /></button></div>
    </div>;
  };
  const empty: Record<CollectionEntry, [string, string]> = {
    account: [L("연결한 계정·발급 목록이 없습니다", "No account or inventory is connected"),
      L("아래 계정·발급 목록 연결에서 서비스를 골라 발급 목록·Secret 저장소·사람 목록을 연결하세요.", "Choose a service under account and inventory connections below to connect its inventory, secret stores or people.")],
    exposure: [L("연결한 콘텐츠 검사 위치가 없습니다", "No content scan location is connected"),
      L("아래 콘텐츠 검사 위치 연결에서 저장소·버킷·페이지를 검사할 서비스를 고르세요.", "Choose a service under content scan connections below to scan its repositories, buckets or pages.")],
  };
  const conn = SECTIONS.map(entry => {
    const members = list.filter(c => sectionsOf(c, providers.get(c.provider)).includes(entry));
    return <Card key={entry} className="ig-conn" id={entry === "account" ? "ig-conn" : "ig-conn-exposure"} headClass="wrap" title={sectionTitle[entry]}
      meta={members.length ? L(`연동 ${members.length}개`, `${members.length} integration${members.length === 1 ? "" : "s"}`) : undefined}>
      {members.length ? <div className="ig-list">{head}{members.map(c => row(c, entry))}</div> : <Empty title={empty[entry][0]}>{empty[entry][1]}</Empty>}
    </Card>;
  });

  /* ---------- available services ---------- */

  const detectProviders = [...new Set((engine.data?.detectors ?? []).map(item => item.provider))]
    .filter(provider => !providers.has(provider) && !NOT_A_SERVICE.has(provider));
  const detectCards = DETECT_CARDS.filter(provider => detectProviders.includes(provider));
  const detectRest = detectProviders.filter(provider => !detectCards.includes(provider)).length;
  const catName: Record<Category, string> = { all: L("전체", "All"), code: L("코드 저장소", "Code hosting"), cloud: L("클라우드", "Cloud"), saas: L("협업 도구", "Collaboration"), detect: L("노출 탐지만 지원", "Detection only") };
  const groups = (["code", "cloud", "saas", "detect"] as Category[]).filter(group => cat === "all" || cat === group).map(group => {
    if (group === "detect") {
      if (!detectCards.length && !detectRest) return null;
      return <div className="ig-group" key={group}>
        <div className="ig-group-title">{catName.detect} <span className="info-dot" tabIndex={0} role="img" aria-label={L("노출 검사에서 이 서비스들의 키를 찾습니다. 발급 목록·만료일·소유자는 연동하는 서비스에서만 가져옵니다.", "Exposure scans find these services' keys. Inventory, expiry and owners come only from connected services.")}
          data-tip={L("노출 검사에서 이 서비스들의 키를 찾습니다. 발급 목록·만료일·소유자는 연동하는 서비스에서만 가져옵니다.", "Exposure scans find these services' keys. Inventory, expiry and owners come only from connected services.")}><Ic name="info" size={15} /></span></div>
        <div className="ig-grid">
          {detectCards.map(provider => <button type="button" key={provider} className="ig-card detect"
            onClick={() => toast(L(`${markOf(provider)?.name ?? provider} 키는 노출 검사에서 찾습니다. 발급 목록 연동은 지원하지 않습니다.`, `${markOf(provider)?.name ?? provider} keys are found by exposure scans. Inventory integration is not offered.`))}>
            <span className="ig-card-top"><Logo id={provider} size={36} /><span className="ig-card-name">{markOf(provider)?.name ?? provider}</span><span className="ig-badge soon">{L("탐지 룰", "Rules")}</span></span>
            <span className="ig-card-desc">{L("노출된 키를 찾는 탐지 룰이 적용돼 있습니다.", "Detection rules for exposed keys are active.")}</span>
            <span className="ig-caps"><span className="cap det"><Ic name="shield" size={14} /><span className="clip">{L("노출 탐지 룰", "Detection rules")}</span></span></span>
          </button>)}
          {detectRest ? <button type="button" className="ig-card detect" onClick={() => (can("rules") ? go("rules") : toast(L(`그 밖의 ${detectRest}개 서비스 키도 노출 검사에서 찾습니다.`, `Keys of ${detectRest} more services are also found by exposure scans.`)))}>
            <span className="ig-card-top"><span className="conn-ic"><Ic name="sliders" size={18} /></span><span className="ig-card-name">{L(`그 밖의 서비스 ${detectRest}개`, `${detectRest} more services`)}</span></span>
            <span className="ig-card-desc">{L("AI·결제·메시징·패키지 레지스트리 등의 키를 탐지 룰로 찾습니다.", "Detection rules find keys for AI, payment, messaging, package registries and more.")}</span>
            {can("rules") ? <span className="ig-card-cta">{L("탐지 룰 보기", "View detection rules")}<Ic name="right" size={15} /></span> : null}
          </button> : null}
        </div>
      </div>;
    }
    // A provider whose new setups offer no account feature (Confluence) is reached from its content card only.
    const cards = pageProviders.filter(d => d.category === group && d.provider !== "website" && accountFeatures(d).length);
    if (!cards.length) return null;
    return <div className="ig-group" key={group}>
      <div className="ig-group-title">{catName[group]}</div>
      <div className="ig-grid">{cards.map(d => {
        const own = eligible(d.provider, "account");
        const note = accountNote(d, L);
        return <CatalogCard key={d.provider} d={forCollectionEntry(d, "account")} caps={accountFeatures(d)}
          on={byProvider(d.provider).some(c => liveIn(c, "account"))} count={own.length} menu={own.length > 0}
          text={`${L("발급 목록·관리 메타데이터를 연결합니다. 콘텐츠 검사는 아래에서 별도로 설정합니다.", "Connect issuance and management metadata. Configure content scans separately below.")}${note ? ` ${note}` : ""}`}
          onOpen={element => own.length ? openChooser(element, label(d, L), [d.provider], false, "account") : openConnect(d.provider, "account")} />;
      })}</div>
    </div>;
  });
  // Apps the company IdP (Microsoft Entra) already lists, for services with no connection yet: a nudge, from stored inventory.
  const suggestions = (suggested.data?.items ?? []).filter(item => providers.has(item.provider) && !byProvider(item.provider).length);
  const catalogSection = <section className="ig-catalog">
    <div className="ig-sec-head"><h2>{L("계정·발급 목록 연결", "Account and inventory connections")}</h2>
      <span className="meta">{L("계정 연결만으로 콘텐츠 검사를 시작하지 않습니다", "Connecting an account does not start content scanning")}</span></div>
    {suggestions.length ? <div className="ig-suggest" role="note">
      <span className="ig-suggest-title"><Ic name="users" size={16} />{L("회사 IdP에 이미 있는 서비스", "Services your company IdP already has")}</span>
      <div className="pill-wrap">{suggestions.map(item => <button type="button" className="ghost-btn" key={item.provider} data-tip={suggestionText(item, L)}
        aria-label={`${L(`${label(providers.get(item.provider)!, L)} 연동`, `Connect ${label(providers.get(item.provider)!, L)}`)} · ${suggestionText(item, L)}`}
        onClick={() => openConnect(item.provider)}><Logo id={item.provider} size={18} />{L(`${label(providers.get(item.provider)!, L)} 연동`, `Connect ${label(providers.get(item.provider)!, L)}`)}</button>)}</div>
    </div> : null}
    <Seg className="ig-seg" label={L("분류", "Category")} value={cat} onChange={setCat}
      options={(["all", ...SHOWN, "detect"] as Category[]).map(id => ({ id, label: catName[id] }))} />
    {groups}
    {cat !== "detect" ? <div className="ig-group" id="ig-content">
      <div className="ig-sec-head"><h2>{L("콘텐츠 검사 위치 연결", "Content scan connections")}</h2>
        <span className="meta">{L("버킷·저장소·페이지의 읽기 권한과 검사 범위를 확인합니다. 연결된 계정이 있으면 그 신원을 다시 씁니다", "Check read access and select buckets, repositories or pages, reusing a connected account where there is one")}</span></div>
      <div className="ig-grid">{pageProviders.filter(d => d.purposes.exposure && (cat === "all" || d.category === cat)).map(d => {
        const own = eligible(d.provider, "exposure");
        const entryName = scanEntryOf(d, L);
        const names = [...new Set((d.purposes.exposure?.scans ?? []).map(s => label(s, L)))].join(" · ");
        return <CatalogCard key={`scan-${d.provider}`} d={forCollectionEntry(d, "exposure")} caps={["exposure"]} title={entryName.title} logo={entryName.logo}
          text={names || L("승인한 위치의 평문 노출 검사", "Scan approved locations for exposed credentials")}
          disabled={!contentStartable(d, own.length)} on={byProvider(d.provider).some(c => live(c, "exposure"))} count={own.length} menu={own.length > 1}
          onOpen={element => own.length > 1 ? openChooser(element, entryName.title, [d.provider], false, "exposure")
            : own.length ? openExisting(own[0], "exposure") : openConnect(d.provider, "exposure")} />;
      })}</div>
    </div> : null}
  </section>;

  /* ---------- side cards ---------- */

  const vaultProviders = pageProviders.filter(d => d.category === "vault");
  const vaultRows = list.filter(c => providers.get(c.provider)?.category === "vault");
  const vaultConnections = vaultRows.filter(c => c.status === "ACTIVE" && enabledPurposes(c).length).length;
  const vault = <Card className="ig-side" headClass="wrap" title={L("Secret 저장소", "Secret stores")}
    right={can("vaults") ? <button type="button" className="link-btn" onClick={() => go("vaults")}>{L("Secret 저장소로", "Go to Secret stores")} <Ic name="right" size={15} /></button> : undefined}>
    <div className="card-body"><div className="ig-side-row">
      <div className="logo-row">{vaultProviders.map(d => <Logo key={d.provider} id={d.provider} size={28} tip={label(d, L)} />)}<Logo id="awssm" size={28} /><Logo id="gcp" size={28} tip="GCP Secret Manager" /></div>
      <p className="ig-side-text">{L("노출된 값이 금고에 보관돼 있는지 지문으로 대조합니다. AWS·GCP·Azure·GitHub·GitLab의 비밀 저장소는 그 서비스 연동에서 함께 고릅니다.", "Checks by fingerprint whether an exposed value is kept in a vault. The secret stores of AWS, GCP, Azure, GitHub and GitLab are chosen in that service's integration.")}</p>
    </div>
      {vaultRows.slice(0, 3).map(c => {
        const d = providers.get(c.provider);
        const state = states.get(c.id)!;
        return <button type="button" key={c.id} className="ig-other" onClick={() => setWizard({ id: c.id })}>
          <Logo id={c.provider} size={34} />
          <span className="ig-other-text"><b>{shortName(d, c) || (d ? label(d, L) : c.name)}</b><span className="ig-sub">{d ? label(d, L) : c.provider}</span></span>
          <span className={cls("igs", state.tone)}><span className="dot" />{state.label}</span><Ic name="right" size={16} />
        </button>;
      })}
      {vaultRows.length > 3 ? <p className="ig-sub ig-side-more">{L(`그 밖에 ${vaultRows.length - 3}곳`, `${vaultRows.length - 3} more`)}</p> : null}
      <div className="ig-side-foot">
        <span className="ig-sub">{vaultConnections ? L(`금고 ${vaultConnections}곳 연동`, `${vaultConnections} vault${vaultConnections === 1 ? "" : "s"} connected`) : L("연동한 금고 없음", "No vault connected")}</span>
        <button type="button" className="link-btn" onClick={event => openChooser(event.currentTarget, L("금고 연동", "Connect a vault"), vaultProviders.map(d => d.provider))}><Ic name="plus" size={15} />{L("금고 연동하기", "Connect a vault")}</button>
      </div>
    </div>
  </Card>;

  // Directories: the identity providers, those whose connection also reads people, and a replaced one while
  // a connection of it still runs.
  const idpProviders = [...pageProviders.filter(d => d.category === "identity").map(d => d.provider),
    ...pageProviders.filter(d => d.category !== "identity" && d.purposes.identity).map(d => d.provider),
    ...catalog.data.providers.filter(d => d.replaced_by && d.purposes.identity && byProvider(d.provider).length).map(d => d.provider)];
  const idpConnected = list.filter(c => c.status === "ACTIVE" && c.plans.identity && c.feature_enabled?.identity !== false).length;
  const authMode = (session as typeof session & { auth_mode?: string }).auth_mode;
  const siemCount = siem.data?.destinations.length ?? 0;
  const others: { icon: IconName; title: string; text: string; state: string; on: (element: HTMLElement) => void }[] = [
    { icon: "shield", title: L("CreMore 로그인", "CreMore sign-in"), text: L("직원이 회사 계정(IdP)으로 CreMore에 로그인합니다.", "Staff sign in to CreMore with their company account (IdP)."),
      state: authMode === "oidc" ? L("IdP 로그인 사용 중", "IdP sign-in on") : L("로컬 로그인", "Local sign-in"),
      on: () => (can("settings") ? go("settings", { section: "login" }) : toast(L("로그인 방식은 설치 설정(CREMORE_AUTH_MODE)에서 정합니다.", "The sign-in mode is set in the installation's configuration (CREMORE_AUTH_MODE)."))) },
    { icon: "users", title: L("디렉터리 동기화", "Directory sync"), text: L("사람의 계정 상태를 가져와 퇴사자가 만든 Credential을 찾습니다.", "Imports people's account state to find credentials made by people who left."),
      state: idpConnected ? L(`${idpConnected}곳 연동`, `${idpConnected} connected`) : L("설정 안 됨", "Not set up"),
      on: element => openChooser(element, L("디렉터리 연동", "Connect a directory"), idpProviders, true) },
    { icon: "globe", title: L("도메인 검증", "Domain verification"), text: L("외부 노출 검사 대상 도메인을 소유했는지 확인합니다.", "Confirms you own the domains used for external exposure checks."),
      state: domainState(domainList.data, L),
      on: () => (session.role === "Admin" ? setDomainsOpen(true) : toast(L("도메인 검증은 관리자가 설정합니다.", "An admin sets up domain verification."))) },
    { icon: "key", title: L("기계 신원 (회사 IdP)", "Machine identity (company IdP)"),
      text: L("CreMore가 AWS·GCP·Azure·Vault에 회사 IdP의 기계 토큰으로 접근합니다.", "CreMore reaches AWS, GCP, Azure and Vault with the company IdP's machine token."),
      state: machineState(machine.data, L), on: () => setMachineOpen(true) },
    { icon: "webhook", title: L("SIEM 전송 · 전체 서비스 공통", "SIEM delivery · all services"), text: L("한 번 설정하면 현재와 새로 연결하는 모든 SaaS·클라우드의 CreMore 이벤트를 보냅니다.", "Configure once to send CreMore events for every current and future SaaS and cloud connection."),
      state: siemCount ? L(`${siemCount}곳으로 전송`, `${siemCount} destination${siemCount === 1 ? "" : "s"}`) : L("설정 안 됨", "Not set up"),
      on: () => (can("operations") ? go("operations", { section: "siem" }) : toast(L("SIEM 목적지는 설치 설정에서 정합니다.", "SIEM destinations are set in the installation's configuration."))) },
    { icon: "send", title: L("연락 발송", "Contact delivery"), text: L("CreMore가 담당자에게 메일·Slack으로 직접 연락합니다.", "CreMore contacts owners itself by mail and Slack."),
      state: contactState(delivery.data, L),
      on: () => (session.role === "Admin" ? setContactOpen(true) : toast(L("연락 발송은 관리자가 설정합니다.", "An admin sets up contact delivery."))) },
    { icon: "send", title: L("대응 알림 채널", "Response channels"), text: L("노출 대응 요청을 담당 팀의 Slack 채널에도 올리고 진행 상황을 스레드에 기록합니다.", "Also post response requests in the responsible team's Slack channel, with progress in its thread."),
      state: responseChannelsState(responseChannels.data, L),
      on: () => (session.role === "Admin" ? setChannelsOpen(true) : toast(L("대응 알림 채널은 관리자가 정합니다.", "An admin chooses the response channels."))) },
    { icon: "list", title: L("티켓 시스템", "Ticket system"), text: L("회사 티켓 시스템에서 노출 대응 완료 응답과 별도의 키 조치 소유자 승인을 받습니다.", "Receive exposure cleanup replies and separate key-action owner approvals through the company ticket system."),
      state: ticketState(tickets.data, L),
      on: () => (session.role === "Admin" ? setTicketOpen(true) : toast(L("티켓 시스템은 관리자가 설정합니다.", "An admin sets up the ticket system."))) },
  ];
  const other = <Card className="ig-side" title={L("기타 설정", "Other settings")}>
    <div className="card-body">{others.map(item => <button type="button" key={item.title} className="ig-other" onClick={event => item.on(event.currentTarget)}>
      <span className="conn-ic"><Ic name={item.icon} size={18} /></span>
      <span className="ig-other-text"><b>{item.title}</b><span className="ig-sub">{item.text}</span></span>
      <span className="ig-other-state">{item.state}</span><Ic name="right" size={16} />
    </button>)}</div>
  </Card>;

  /* ---------- menus and dialogs ---------- */

  const target = menuFor?.c;
  const menuEntry = menuFor?.entry ?? "account";
  const menuPurposes = PURPOSE_ORDER.filter(p => inEntryView(p, menuEntry));
  const runnable = target ? runnableIn(target, menuEntry) : false;
  const rowMenuNode = rowMenu.anchor && target ? <Menu anchor={rowMenu.anchor} onClose={rowMenu.close} restore={rowMenu.opener} label={L("연동 메뉴", "Integration menu")}>
    {target.status === "ACTIVE" ? <MenuItem icon="refresh" disabled={!runnable} tip={runnable ? undefined : L("여기서 바로 실행할 수집이 없습니다", "Nothing here runs on demand")}
      onSelect={() => { rowMenu.close(); void run(target, "collect", menuPurposes); }}>{L("지금 수집", "Collect now")}</MenuItem> : null}
    {menuEntry === "exposure" && live(target, "exposure") ? <MenuItem icon="scan" onSelect={() => { rowMenu.close(); setTargetsFor(target); }}>{L("검사 대상 설정", "Scan targets")}</MenuItem> : null}
    {target.status !== "DISABLED" ? <MenuItem icon="settings" onSelect={() => { rowMenu.close(); setWizard({ id: target.id, entry: menuEntry }); }}>{L("수집 범위·인증 설정", "Scope & sign-in settings")}</MenuItem> : null}
    {target.status !== "DISABLED" && target.purposes.length > 0 ? <MenuItem icon="bolt" onSelect={() => { rowMenu.close(); void run(target, "check"); }}>{L("권한 다시 확인", "Check access again")}</MenuItem> : null}
    {session.role === "Admin" && enterpriseReady(target) ? <MenuItem icon="users" onSelect={() => { rowMenu.close(); setEnterpriseFor(target); }}>{L("엔터프라이즈 조직에 설치", "Install on enterprise organizations")}</MenuItem> : null}
    {session.role === "Admin" && target.status !== "DISABLED" && reachKind(target) ? <MenuItem icon="grid" onSelect={() => { rowMenu.close(); setReachFor(target); }}>{L("연결 대상 현황", "Connected targets")}</MenuItem> : null}
    <MenuItem icon="pencil" onSelect={() => { rowMenu.close(); setRenaming(target); }}>{L("이름 바꾸기", "Rename")}</MenuItem>
    {can("scans") ? <MenuItem icon="list" onSelect={() => { rowMenu.close(); go("scans", { connection: target.id }); }}>{L("수집·탐지 현황 보기", "View collection & detection status")}</MenuItem> : null}
    <MenuSep />
    {target.status === "DISABLED" ? <>
      <MenuItem icon="play" onSelect={() => { rowMenu.close(); void run(target, "enable"); }}>{L("다시 켜기", "Turn back on")}</MenuItem>
      <MenuItem icon="trash" className="danger" disabled={target.children.length > 0}
        tip={target.children.length ? L("수집 기록이 있는 연동은 지울 수 없습니다", "An integration with collection records cannot be deleted") : undefined}
        onSelect={() => { rowMenu.close(); setConfirm({ c: target, action: "delete" }); }}>{L("삭제", "Delete")}</MenuItem>
    </> : <MenuItem icon="stop" className="danger" onSelect={() => { rowMenu.close(); setConfirm({ c: target, action: target.children.length ? "disable" : "delete" }); }}>{L("연동 해제", "Disconnect")}</MenuItem>}
  </Menu> : null;

  const loaded = catalog.data;
  const signInIdp = loaded.sign_in_idp ?? null;
  const chooserNode = chooserMenu.anchor && chooser ? <Menu anchor={chooserMenu.anchor} onClose={chooserMenu.close} restore={chooserMenu.opener} label={chooser.title}>
    <MenuLabel>{chooser.title}</MenuLabel>
    {chooser.providers.flatMap(provider => (chooser.entry ? eligible(provider, chooser.entry) : byProvider(provider)).map(c => <MenuItem key={c.id} end={<span className={cls("igs", states.get(c.id)!.tone)}><span className="dot" />{states.get(c.id)!.label}</span>}
      onSelect={() => { chooserMenu.close(); openExisting(c, chooser.entry); }}>
      <Logo id={c.provider} size={18} /> {c.name}{!inEntry(c, chooser.entry) ? (providers.get(c.provider)?.auth_methods.find(m => m.id === c.auth_method)?.purposes.includes("exposure")
        ? L(" · 이 계정에 기능 추가", " · add to this account") : L(" · 콘텐츠 읽기용 추가 인증", " · additional content sign-in")) : null}</MenuItem>))}
    {chooser.entry !== "exposure" && chooser.providers.some(provider => (chooser.entry ? eligible(provider, chooser.entry) : byProvider(provider)).length) ? <MenuSep /> : null}
    {chooser.providers.filter(() => chooser.entry !== "exposure").map(provider => {
      const d = providers.get(provider);
      if (!d || d.replaced_by) return null;
      // A team install reads people from the IdP people sign in with: that one opens filled in, the others say why not.
      const block = chooser.people ? peopleDirectoryBlock(loaded, d, null, L) : null;
      const signIn = chooser.people && signInIdp?.provider === provider ? signInIdp : null;
      return <MenuItem key={`new-${provider}`} icon="plus" disabled={Boolean(block)} tip={block ?? undefined}
        onSelect={() => { chooserMenu.close(); if (signIn) setWizard({ provider, purpose: "identity", target: signIn.target ?? {} }); else openConnect(provider, chooser.entry); }}>
        {chooser.providers.length > 1 ? label(d, L) : L("새 연동 추가", "Add another integration")}{signIn ? L(" · 로그인에 쓰는 IdP", " · the sign-in IdP") : null}</MenuItem>;
    })}
  </Menu> : null;

  return <>
    <PageHead title={L("연동 서비스", "Integrations")} meta={newest ? L(`마지막 수집 ${fmtDT(newest, locale)}`, `Last collected ${fmtDT(newest, locale)}`) : undefined} />
    {refreshError ? <Banner tone="warn" icon="alert">{L("목록을 갱신하지 못했습니다. 마지막 조회 결과와 입력 내용을 유지합니다.", "Could not refresh the list. The last loaded list and your input are kept.")}
      {" "}{reasonText(refreshError, L)}{" "}<button type="button" className="link-btn" onClick={() => { catalog.reload(); connections.reload(); }}>{L("다시 불러오기", "Reload")}</button></Banner> : null}
    {tiles}
    {conn}
    {catalogSection}
    <div className="ig-side-grid">{vault}{other}</div>
    {rowMenuNode}
    {chooserNode}
    {wizard ? <ConnectWizard key={JSON.stringify(wizard)} catalog={catalog.data} open={wizard} onClose={() => { setWizard(null); connections.reload(); }} go={go} can={can} admin={session.role === "Admin"}
      health={healthItems} onNext={provider => { setWizard({ provider }); connections.reload(); health.reload(); }}
      connected={[...connectedProviders]}
      onMachineIdentity={session.role === "Admin" ? () => { setWizard(null); setMachineOpen(true); } : undefined} /> : null}
    {machineOpen ? <MachineIdentityModal onClose={() => { setMachineOpen(false); machine.reload(); }} /> : null}
    {contactOpen ? <ContactDeliveryModal onClose={() => { setContactOpen(false); delivery.reload(); }} /> : null}
    {channelsOpen ? <ResponseChannelsModal onClose={() => { setChannelsOpen(false); responseChannels.reload(); }} /> : null}
    {ticketOpen ? <TicketSystemModal onClose={() => { setTicketOpen(false); tickets.reload(); }} /> : null}
    {domainsOpen ? <DomainsModal scans={byProvider("website").length} scanned={scannedDomains}
      onClose={() => { setDomainsOpen(false); domainList.reload(); }}
      onConnect={fresh => {
        // A new scan starts with the verified domains no scan reads yet; the wizard's check asks the DNS state again.
        setDomainsOpen(false); domainList.reload(); setWizard({ provider: "website", target: { domains: fresh.join("\n") } });
      }} /> : null}
    {targetsFor ? <TargetsModal conn={targetsFor} onClose={() => { setTargetsFor(null); connections.reload(); }} go={go} can={can} /> : null}
    {enterpriseFor ? <GitHubEnterpriseModal conn={enterpriseFor} onClose={() => { setEnterpriseFor(null); connections.reload(); }} /> : null}
    {reachFor ? <ReachModal conn={reachFor} onClose={() => setReachFor(null)} /> : null}
    {renaming ? <TextModal title={L("이름 바꾸기", "Rename")} label={L("연동 이름", "Integration name")} initial={renaming.name} ok={L("저장", "Save")} maxLength={120}
      onClose={() => setRenaming(null)} onSave={async value => {
        try { await send(`${CONNECTIONS_PATH}/${renaming.id}`, "PATCH", { name: value, expected_revision: renaming.revision }); setRenaming(null); saved(); toast(L("이름을 바꿨습니다", "Renamed")); }
        catch (reason) { toast(onboardingText(reason instanceof Error ? reason.message : "", [], L) ?? reasonText(reason, L), "bad"); }
      }} /> : null}
    {confirm ? <ConfirmModal c={confirm.c} action={confirm.action} d={providers.get(confirm.c.provider)} both={sectionsOf(confirm.c, providers.get(confirm.c.provider)).length > 1} onClose={() => setConfirm(null)}
      onConfirm={async () => { await run(confirm.c, confirm.action); setConfirm(null); }} /> : null}
  </>;
}

/** ``caps``: the features the card connects; ``menu``: whether opening it shows a chooser of connections. */
function CatalogCard({ d, caps, on, count, menu, onOpen, title, text, logo, disabled = false }: { d: Descriptor; caps: Purpose[]; on: boolean; count: number; menu: boolean;
  onOpen: (element: HTMLElement) => void; title?: string; text?: string; logo?: string; disabled?: boolean }) {
  const L = useL();
  return <button type="button" className={cls("ig-card", on && "is-on")} disabled={disabled} onClick={event => onOpen(event.currentTarget)} aria-haspopup={menu ? "menu" : undefined}>
    <span className="ig-card-top"><Logo id={logo ?? d.provider} size={36} />
      <span className="ig-card-name">{title ?? label(d, L)}</span>
      {on ? <span className="ig-badge on"><Ic name="checkCircle" size={13} />{L("연동됨", "Connected")}</span> : null}</span>
    <span className="ig-card-desc">{text ?? description(d, L)}</span>
    <span className="ig-caps">{caps.map(p => <span key={p} className={cls("cap", CAP_CLASS[p])}><Ic name={CAP_ICON[p]} size={14} /><span className="clip">{capName(p, L, p === "inventory" ? d.purposes.inventory?.types?.length : 0)}</span></span>)}</span>
    <span className="ig-card-cta">{disabled ? L("먼저 계정을 연결하세요", "Connect an account first") : count ? L("설정 보기", "View settings") : L("연동하기", "Connect")}<Ic name="right" size={15} /></span>
  </button>;
}

function ConfirmModal({ c, d, action, both, onClose, onConfirm }: {
  c: ProviderConnection; d: Descriptor | undefined; action: "disable" | "delete"; both: boolean; onClose: () => void; onConfirm: () => Promise<void>;
}) {
  const L = useL();
  const [busy, setBusy] = useState(false);
  const name = d ? label(d, L) : c.provider;
  return <Modal onClose={onClose} labelledBy="ig-confirm" size="narrow">
    <h2 id="ig-confirm">{action === "delete" ? L("연동 삭제", "Delete integration") : L("연동 해제", "Disconnect")} <small><span className="clip">{c.name}</span></small></h2>
    <p className="re-cap">{action === "delete"
      ? L(`${name} 연동을 지웁니다. 저장한 인증 정보도 함께 지웁니다.`, `Deletes the ${name} integration together with its stored credential.`)
      : L(`${name}에서 수집을 멈춥니다. 지금까지 수집한 기록은 남고, 다시 켜면 이어서 수집합니다.`, `Stops collecting from ${name}. Records collected so far are kept, and turning it back on continues collecting.`)}</p>
    {both ? <p className="re-cap">{L("이 연동은 계정·발급 목록 연결과 콘텐츠 검사 위치 연결에 함께 있어 두 곳이 모두 멈춥니다.",
      "This integration is listed under both account and inventory connections and content scan connections: both stop.")}</p> : null}
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose}>{L("취소", "Cancel")}</button>
      <button type="button" className="danger-btn" disabled={busy} data-autofocus
        onClick={async () => { setBusy(true); try { await onConfirm(); } finally { setBusy(false); } }}>{action === "delete" ? L("삭제", "Delete") : L("연동 해제", "Disconnect")}</button>
    </div>
  </Modal>;
}
