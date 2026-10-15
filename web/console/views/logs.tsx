"use client";

/* Collection and detection logs: every run the worker holds -- exposure scans, inventory and vault
 * collections, access checks and catalog refreshes -- with the integration it belongs to, its state,
 * what it read and found, and why it failed or waits. A run opens in a panel that can stop it or run
 * it again. ?connection= narrows the list to one integration (the integrations screen links here). */

import { type ReactNode, useEffect, useMemo, useState } from "react";

import { useLocale } from "@/components/locale";
import { failureCodeLabel, holdText, metadataReasonsText, scanDurationText } from "@/components/labels";
import { reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { Drawer, Menu, MenuItem, MenuSep, useMenu, useToast } from "@/console/layer";
import { Logo } from "@/console/logos";
import type { ViewProps } from "@/console/shell";
import { downloadJson, fmtDT, rel, type Say, useL } from "@/console/text";
import { Card, cls, DTabs, EmptyRow, ErrorLine, Fact, Facts, FilterChip, Loading, PageHead, SearchBox, StateChip, Tabs, Tile, Tiles } from "@/console/ui";
import { CUSTOMER_SIDE } from "@/console/views/integrations/copy";
import { CONNECTIONS_PATH, type ProviderConnection } from "@/console/views/integrations/model";
import { TargetsModal } from "@/console/views/integrations/targets";
import { api, DashboardAPIError } from "@/lib/dashboard-api";
import { hasRole } from "@/lib/dashboard-session";
import { CONTENT_SOURCE_TYPES } from "@/lib/source-types";

export type Run = {
  id: string; status: string; kind: string; mode?: string; trigger_type?: string; connection_id: string | null;
  connection_kind?: string; profile_id?: string; provider_connection_id?: string; coverage_connection_id?: string; finding_id?: string;
  resources_succeeded: number; resources_failed: number; findings_total: number;
  metadata_items?: number; count_basis?: string;
  duration_seconds: number | null; bytes?: number | null; requests?: number | null; skipped?: number | null;
  skipped_unchanged?: number | null; skipped_unsupported?: number | null; skipped_media?: number | null;
  extraction_reasons?: Record<string, number>;
  roots_failed?: number | null; stopped_reason?: string | null; error: string | null;
  // An upgrade's change run (cremore/worker/runtime.py policy_hold): roots it did not read whole under the new rules,
  // and whether nothing else left it partial.
  policy_held_roots?: number; policy_held_only?: boolean;
  created_at: string; started_at: string | null; completed_at: string | null;
  progress?: { done: number; total: number; running: number; queued: number };
  hold?: { code: string; next_attempt_at?: string | null; waiting_tasks?: number };
  failures?: { root: string; code: string }[];
  // The metadata runs a finished inventory or vault collection stored: its report and export.
  coverage_run_ids?: string[];
};

export type Group = "scan" | "collect" | "check" | "catalog";
const GROUPS: Group[] = ["scan", "collect", "check", "catalog"];
const GROUP_NAME: Record<Group, [string, string]> = {
  scan: ["노출 검사", "Exposure scans"], collect: ["발급 목록·금고 수집", "Inventory & vault"], check: ["권한·인증 확인", "Checks"], catalog: ["목록 가져오기", "Catalog refresh"],
};
const KINDS: Record<string, { group: Group; name: [string, string] }> = {
  scope: { group: "scan", name: ["노출 검사", "Exposure scan"] },
  inline: { group: "scan", name: ["붙여 넣은 텍스트 검사", "Pasted text scan"] },
  "catalog-refresh": { group: "catalog", name: ["목록 가져오기", "Catalog refresh"] },
  "credential-check": { group: "check", name: ["인증 확인", "Sign-in check"] },
  "provider-check": { group: "check", name: ["권한 확인", "Access check"] },
  "finding-context": { group: "check", name: ["소유·접근 확인", "Ownership and access check"] },
  "aws-role-check": { group: "check", name: ["AWS 역할 확인", "AWS role check"] },
  "github-secret-scanning": { group: "check", name: ["GitHub 비밀 탐지 알림 가져오기", "GitHub secret scanning alerts"] },
  "provider-credential-action": { group: "check", name: ["승인된 조치 실행", "Approved action run"] },
  "provider-metadata-inventory": { group: "collect", name: ["발급 목록·금고 수집", "Inventory & vault collection"] },
  // The schema-1 coverage job also runs Vault/OpenBao and secret-manager server reads, not only AWS issuers.
  "aws-credential-inventory": { group: "collect", name: ["AWS 발급·금고 수집", "AWS & vault collection"] },
  "credential-usage": { group: "collect", name: ["AWS 사용 기록 수집", "AWS usage collection"] },
  "customer-collection": { group: "collect", name: ["고객 환경 CLI 수집", "Customer-side collection"] },
};
export const kindOf = (kind: string) => KINDS[kind] ?? { group: "scan" as Group, name: ["노출 검사", "Exposure scan"] as [string, string] };

export type State = "queued" | "running" | "done" | "partial" | "failed" | "cancelled";
const STATE: Record<string, State> = {
  QUEUED: "queued", RUNNING: "running", CANCELLING: "running", SUCCEEDED: "done", COMPLETED: "done", PARTIAL: "partial",
  FAILED: "failed", CANCELLED: "cancelled",
};
export const stateOf = (status: string): State => STATE[status] ?? "queued";
const STATE_NAME: Record<State, [string, string]> = {
  queued: ["대기", "Queued"], running: ["진행 중", "Running"], done: ["완료", "Done"], partial: ["일부 완료", "Partly done"],
  failed: ["실패", "Failed"], cancelled: ["취소됨", "Cancelled"],
};
const STATE_TONE: Record<State, string> = { queued: "setup", running: "running", done: "ok", partial: "partial", failed: "partial", cancelled: "off" };
const MODE: Record<string, [string, string]> = { BASELINE: ["전체", "Full"], DELTA: ["변경분", "Changes"], RECONCILE: ["대조", "Reconcile"] };
const TRIGGER: Record<string, [string, string]> = {
  MANUAL: ["직접 실행", "Manual"], SCHEDULE: ["예약", "Scheduled"], EVENT: ["변경 알림", "Change event"], RESCAN: ["다시 검사", "Rescan"],
  POLICY_SWEEP: ["룰 변경 재검사", "Rule change sweep"], RESUME: ["이어서", "Resumed"],
};
const DAY = 86_400_000;

/** A run a customer-side CLI uploaded (it is not a job of this installation), as the list shows runs. */
export type StoreRun = { id: string; status: string; reasons?: string[]; item_count: number; started_at: string; finished_at: string | null; completeness?: string | null };
const UPLOADED: Record<string, string> = { COMPLETE: "SUCCEEDED", PARTIAL: "PARTIAL", FAILED: "FAILED" };
export function uploadedRun(run: StoreRun, childId: string, metadata = false): Run {
  const seconds = run.finished_at ? (Date.parse(run.finished_at) - Date.parse(run.started_at)) / 1000 : null;
  return { id: run.id, status: run.finished_at ? UPLOADED[run.status] ?? "FAILED" : "RUNNING", kind: "customer-collection", connection_id: childId,
    resources_succeeded: run.item_count, resources_failed: 0, findings_total: 0, duration_seconds: seconds, error: run.reasons?.[0] ?? null,
    created_at: run.started_at, started_at: run.started_at, completed_at: run.finished_at,
    ...(metadata ? { metadata_items: run.item_count, count_basis: "COMMITTED_METADATA_RECORDS" } : {}),
    // An uploaded metadata run is itself the stored run its report and export read.
    ...(metadata && run.finished_at ? { coverage_run_ids: [run.id] } : {}) };
}

/* A collection's report: what each read (operation) of a stored metadata run did, as the adapter reported it. */
export type OperationReport = {
  status: string; reasons: string[]; pages: number; received_records: number; saved_records: number; expected_records?: number | null;
  scope: { kind: string; id: string }; provenance: { operation: string; resource_id?: string | null };
};
const REPORT_STATUS: Record<string, [string, string, "ok" | "partial" | "bad" | undefined]> = {
  COMPLETE: ["완료", "Complete", "ok"], PARTIAL: ["일부 완료", "Partly done", "partial"], FAILED: ["실패", "Failed", "bad"],
  UNSUPPORTED: ["지원 안 함", "Unsupported", undefined], UNKNOWN: ["알 수 없음", "Unknown", undefined], NOT_REQUESTED: ["요청 안 함", "Not requested", undefined],
};
export function reportStatus(status: string, L: Say): [string, "ok" | "partial" | "bad" | undefined] {
  const known = REPORT_STATUS[status];
  return known ? [L(known[0], known[1]), known[2]] : [status, undefined];
}
/** What one read took in, in a few words: received, saved and, where the service said, expected. */
export function reportCounts(report: OperationReport, L: Say): string {
  const expected = report.expected_records ?? null;
  return L(`받음 ${report.received_records} · 저장 ${report.saved_records}${expected !== null ? ` · 예상 ${expected}` : ""}`,
    `${report.received_records} received · ${report.saved_records} saved${expected !== null ? ` · ${expected} expected` : ""}`);
}

/** What each read of a stored run did, from the run's operation reports alone. */
export function ReportList({ items, total }: { items: { id: string; body: OperationReport }[]; total: number }) {
  const L = useL();
  const locale = useLocale();
  if (!items.length) return <p className="subtle">{L("이 실행은 수집 보고를 남기지 않았습니다.", "This run left no collection report.")}</p>;
  return <ul className="md-gaps">{items.map(({ id, body }) => { const [text, tone] = reportStatus(body.status, L); return <li key={id}>
    <b className="mono">{body.provenance.operation}</b> <StateChip tone={tone}>{text}</StateChip>
    <span className="subtle"> · {body.scope.kind}:{body.scope.id}{body.provenance.resource_id ? ` · ${body.provenance.resource_id}` : ""}</span>
    {/* A reason in words with its code kept, for support and search. */}
    <div className="ig-sub">{reportCounts(body, L)}{body.reasons.length ? ` · ${metadataReasonsText(body.reasons, locale)}` : ""}</div>
  </li>; })}{total > items.length ? <li className="subtle">{L(`외 ${total - items.length}건`, `and ${total - items.length} more`)}</li> : null}</ul>;
}

function RunReport({ runId, exportable }: { runId: string; exportable: boolean }) {
  const L = useL();
  const toast = useToast();
  const view = useApi<{ records: { items: { id: string; body: OperationReport }[]; total: number } }>(`v2/coverage/runs/${runId}?record_type=operation_report&limit=100`);
  const [busy, setBusy] = useState(false);
  const download = async () => {
    setBusy(true);
    try { downloadJson(`cremore-collection-${runId}.json`, await api<unknown>(`v2/coverage/runs/${runId}/export?format=native`)); }
    catch (reason) { toast(reasonText(reason, L), "bad"); } finally { setBusy(false); }
  };
  // A run whose records were removed (a people directory's history past its retention) is gone; retrying will not help.
  const gone = view.error instanceof DashboardAPIError && view.error.status === 404;
  return <section className="card">
    <div className="card-head"><h3>{L("수집 보고", "Collection report")}</h3>
      {exportable && view.data ? <button type="button" className="ghost-btn" disabled={busy} onClick={() => void download()}><Ic name="download" size={15} />{L("원본 형식으로 받기", "Download in the service's format")}</button> : null}</div>
    <div className="card-body">
      {gone ? <p className="subtle">{L("이 실행의 기록은 남아 있지 않습니다.", "This run's records are no longer kept.")}</p>
        : view.error ? <ErrorLine onRetry={view.reload}>{reasonText(view.error, L)}</ErrorLine> : !view.data ? <Loading />
          : <ReportList items={view.data.records.items} total={view.data.records.total} />}
    </div>
  </section>;
}

/** The integration a run belongs to: the provider connection that owns its record. */
export type Owner = { conn: ProviderConnection; child?: string };
export function owners(connections: ProviderConnection[]): Map<string, Owner> {
  const out = new Map<string, Owner>();
  for (const conn of connections) {
    out.set(conn.id, { conn });
    for (const child of conn.children) out.set(child.id, { conn, child: child.name ?? undefined });
  }
  return out;
}
export const ownerOf = (run: Run, map: Map<string, Owner>) =>
  map.get(run.provider_connection_id ?? "") ?? map.get(run.connection_id ?? "") ?? map.get(run.coverage_connection_id ?? "");

function errorText(code: string, L: Say, locale: "ko" | "en") {
  return failureCodeLabel(code, locale) || L("알 수 없는 오류", "Unknown error");
}

const metadataRun = (run: Run) => run.kind === "provider-metadata-inventory"
  || (run.kind === "customer-collection" && run.count_basis === "COMMITTED_METADATA_RECORDS");
function itemCount(run: Run): number | null {
  if (!metadataRun(run)) return run.resources_succeeded;
  return run.count_basis === "COMMITTED_METADATA_RECORDS" && typeof run.metadata_items === "number"
    && Number.isSafeInteger(run.metadata_items) && run.metadata_items >= 0 ? run.metadata_items : null;
}

/** What a run read and found, in a few words. */
export function resultOf(run: Run, L: Say): string {
  const group = kindOf(run.kind).group;
  const count = itemCount(run);
  if (stateOf(run.status) === "queued" || (stateOf(run.status) === "failed" && !count)) return "—";
  if (metadataRun(run)) return count === null ? L("메타데이터 수 미확인", "Metadata count unavailable")
    : L(`메타데이터 ${count}개`, `${count} metadata records`);
  if (group === "check") return run.error ? L("확인하지 못함", "Not checked") : L("확인함", "Checked");
  if (group === "catalog") return L(`${run.resources_succeeded}곳 확인`, `${run.resources_succeeded} listed`);
  if (group === "collect") return L(`항목 ${run.resources_succeeded}개`, `${run.resources_succeeded} items`);
  const parts = [L(`읽은 곳 ${run.resources_succeeded}`, `${run.resources_succeeded} read`)];
  if (run.findings_total) parts.push(L(`새 노출 ${run.findings_total}`, `${run.findings_total} new`));
  if (run.resources_failed) parts.push(L(`실패 ${run.resources_failed}`, `${run.resources_failed} failed`));
  return parts.join(" · ");
}

/** A run partial only for the upgrade hold: it waits, as planned, for the scope's post-upgrade full scan. */
const heldOnly = (run: Run) => stateOf(run.status) === "partial" && run.policy_held_only === true;
const HELD: [string, string] = ["업그레이드 후 첫 전체 검사 전이라 전체를 다시 읽지 않았습니다", "Not re-read whole until the post-upgrade full scan"];

/** Whether a run counts as failed or finished in part, a planned upgrade hold aside. */
export const troubled = (run: Run) => ["failed", "partial"].includes(stateOf(run.status)) && !heldOnly(run);

/** The note under a run's state in the list: why it waits, failed or stopped short, or how far it got. */
export function rowNote(run: Run, L: Say, locale: "ko" | "en"): string | null {
  const state = stateOf(run.status);
  if (run.hold) return holdText(run.hold.code, locale).title;
  if (run.error && (state === "failed" || state === "partial")) return errorText(run.error, L, locale);
  if (heldOnly(run)) return L(...HELD);
  if (state === "running" && run.progress) return L(`${run.progress.done}/${run.progress.total} 진행`, `${run.progress.done}/${run.progress.total} done`);
  return null;
}

export function Logs({ session, route, setParams, go, can }: ViewProps) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const [fast, setFast] = useState(false);
  const runs = useApi<Run[]>("scan-runs", { every: fast ? 5_000 : 30_000 });
  const connections = useApi<ProviderConnection[]>(CONNECTIONS_PATH);
  const p = route.params;
  const group = (GROUPS as string[]).includes(p.get("kind") ?? "") ? p.get("kind") as Group : "all";
  const states = (p.get("f.state") ?? "").split(",").filter(Boolean);
  const services = (p.get("f.svc") ?? "").split(",").filter(Boolean);
  // The "Failed in 7 days" tile's own list: exactly the runs it counts (a planned upgrade hold aside).
  const failedRecently = p.get("f.failed") === "7d";
  const connection = p.get("connection");
  const q = p.get("q") ?? "";
  const selected = p.get("id");
  const [query, setQuery] = useState(q);
  const menu = useMenu();
  const [menuKey, setMenuKey] = useState<"state" | "svc">("state");
  // Choosing what an exposure scan reads, and starting it, from where its runs are read.
  const scanMenu = useMenu();
  const [targetsFor, setTargetsFor] = useState<ProviderConnection | null>(null);
  useEffect(() => { setQuery(q); }, [q]);
  useEffect(() => {
    const timer = window.setTimeout(() => { if (query !== q) setParams({ q: query || null }); }, 250);
    return () => window.clearTimeout(timer);
  }, [query, q, setParams]);
  useEffect(() => { setFast(Boolean(runs.data?.some(run => ["queued", "running"].includes(stateOf(run.status))))); }, [runs.data]);

  // Collections a customer-side CLI runs arrive as uploaded runs of their records.
  const [uploads, setUploads] = useState<Run[]>([]);
  useEffect(() => {
    const children = (connections.data ?? []).filter(c => CUSTOMER_SIDE.has(c.auth_method))
      .flatMap(c => c.children.filter(child => child.kind === "metadata" || child.kind === "coverage"));
    let live = true;
    Promise.all(children.map(child => api<{ items: StoreRun[] }>(child.kind === "metadata"
      ? `v2/coverage/connections/${child.id}/runs?limit=20` : `coverage/connections/${child.id}/runs?limit=20`)
      .then(page => page.items.map(item => uploadedRun(item, child.id, child.kind === "metadata"))).catch(() => [] as Run[])))
      .then(groups => { if (live) setUploads(groups.flat()); });
    return () => { live = false; };
  }, [connections.data, runs.data]);

  const map = useMemo(() => owners(connections.data ?? []), [connections.data]);
  const title = L("수집·탐지 현황", "Collection & detection status");
  const meta = L("수집과 노출 검사를 실행한 기록", "Runs of collections and exposure scans");
  if (runs.error) return <><PageHead title={title} meta={meta} /><ErrorLine onRetry={runs.reload}>{reasonText(runs.error, L)}</ErrorLine></>;
  if (!runs.data) return <><PageHead title={title} meta={meta} /><Loading /></>;

  const all = [...runs.data, ...uploads].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  const serviceOf = (run: Run) => ownerOf(run, map)?.conn.provider ?? (run.kind === "inline" ? "inline" : "");
  const inConnection = (run: Run) => !connection || ownerOf(run, map)?.conn.id === connection;
  const needle = q.trim().toLowerCase();
  const now = Date.now();
  const recent = (run: Run) => now - Date.parse(run.created_at) <= 7 * DAY;
  const matches = (run: Run, skip?: "state" | "svc" | "group") => inConnection(run)
    && (skip === "group" || group === "all" || kindOf(run.kind).group === group)
    && (skip === "state" || !states.length || states.includes(stateOf(run.status)))
    && (skip === "svc" || !services.length || services.includes(serviceOf(run)))
    && (!failedRecently || (recent(run) && troubled(run)))
    && (!needle || `${ownerOf(run, map)?.conn.name ?? ""} ${ownerOf(run, map)?.child ?? ""} ${L(...kindOf(run.kind).name)} ${run.error ?? ""}`.toLowerCase().includes(needle));
  const rows = all.filter(run => matches(run));
  const scoped = all.filter(inConnection);
  const active = scoped.filter(run => ["queued", "running"].includes(stateOf(run.status))).length;
  const failed = scoped.filter(run => recent(run) && troubled(run)).length;
  const found = scoped.filter(run => recent(run) && kindOf(run.kind).group === "scan").reduce((sum, run) => sum + (run.findings_total || 0), 0);
  const lastDone = scoped.filter(run => ["done", "partial"].includes(stateOf(run.status)) && run.completed_at)
    .map(run => run.completed_at!).sort().at(-1) ?? null;
  const set = (params: Record<string, string | null>) => setParams(params);
  const toggle = (key: "state" | "svc", value: string) => {
    const current = key === "state" ? states : services;
    const next = current.includes(value) ? current.filter(item => item !== value) : [...current, value];
    set({ [`f.${key}`]: next.length ? next.join(",") : null });
  };
  const owner = connection ? map.get(connection)?.conn : undefined;
  const open = selected ? all.find(run => run.id === selected) : undefined;
  const menuValues = (key: "state" | "svc") => {
    const counts = new Map<string, number>();
    for (const run of all.filter(item => matches(item, key))) {
      const value = key === "state" ? stateOf(run.status) : serviceOf(run);
      if (value) counts.set(value, (counts.get(value) ?? 0) + 1);
    }
    return [...counts.entries()];
  };

  const scannable = (connections.data ?? []).filter(c => c.status === "ACTIVE" && c.plans.exposure);
  return <>
    <PageHead title={title} meta={meta}>
      {can("sources") && scannable.length ? <button type="button" className="primary-btn logs-scan" onClick={event => scanMenu.open(event.currentTarget)}>
        <Ic name="scan" size={16} />{L("검사 대상 설정", "Scan targets")}</button> : null}
    </PageHead>
    <Tiles>
      {/* Like the failed tile: its list is what it counts, every run kind, service and search of this scope. */}
      <Tile icon="activity" tone="blue" label={L("진행 중", "In progress")} value={active}
        onClick={() => set({ "f.state": "running,queued", "f.failed": null, "f.svc": null, kind: null, q: null })}
        tip={L("지금 실행 중이거나 차례를 기다리는 작업입니다. 서로 다른 연결은 worker 동시 실행 수만큼 함께 검사하고, 한 연결 안에서는 변경 알림 검사가 전체 검사와 나란히 돕니다. 같은 버킷·저장소·페이지는 동시에 두 번 읽지 않습니다.",
          "Runs going on or waiting their turn. Different connections scan at the same time up to the worker concurrency, and within one connection a change-event scan runs beside a full scan. The same bucket, repository or page is never read twice at once.")} />
      {/* Its list is what it counts: every run kind, service and search of this integration's scope. */}
      <Tile icon="alert" tone={failed ? "amber" : "green"} label={L("최근 7일 실패", "Failed in 7 days")} value={failed}
        onClick={() => set({ "f.failed": "7d", "f.state": null, "f.svc": null, kind: null, q: null })}
        tip={L("최근 7일 동안 실패했거나 일부만 끝난 작업입니다. 업그레이드 후 첫 전체 검사를 기다리는 변경분 실행은 세지 않습니다.",
          "Runs that failed or finished only in part in the last 7 days. Change runs waiting for the post-upgrade full scan are not counted.")} />
      <Tile icon="scan" tone="teal" label={L("최근 7일 새 노출", "New exposures in 7 days")} value={found} onClick={() => set({ kind: "scan", "f.state": null, "f.failed": null })}
        tip={L("최근 7일 동안 노출 검사가 새로 찾은 노출 수입니다.", "Exposures the exposure scans found in the last 7 days.")} />
      <Tile icon="clock" tone="violet" label={L("마지막 완료", "Last finished")} value={lastDone ? rel(lastDone, locale) : "—"}
        tip={lastDone ? fmtDT(lastDone, locale) : L("아직 끝난 작업이 없습니다.", "No run has finished yet.")} />
    </Tiles>
    <Tabs value={group} label={L("작업 종류", "Run kind")} onChange={next => set({ kind: next === "all" ? null : next })}
      items={[{ id: "all" as const, label: L("전체", "All"), count: all.filter(run => matches(run, "group")).length },
        ...GROUPS.map(item => ({ id: item, label: L(...GROUP_NAME[item]), count: all.filter(run => matches(run, "group") && kindOf(run.kind).group === item).length }))]} />
    <Card className="list-card">
      <div className="list-tools">
        <SearchBox id="log-search" value={query} onChange={setQuery} label={L("로그 검색", "Search logs")} placeholder={L("연동 이름·작업·오류 코드로 검색", "Search by integration, run or error code")} />
      </div>
      <div className="chips-row">
        {(["state", "svc"] as const).map(key => {
          const n = (key === "state" ? states : services).length;
          const name = key === "state" ? L("상태", "Status") : L("서비스", "Service");
          return <FilterChip key={key} icon={key === "state" ? "checkCircle" : "grid"} label={name} count={n}
            onOpen={anchor => { setMenuKey(key); menu.open(anchor); }} onClear={() => set({ [`f.${key}`]: null })} />;
        })}
      </div>
      {owner || failedRecently || q ? <div className="applied">
        {owner ? <span className="applied-chip"><span className="wrap-t">{L("연동: ", "Integration: ")}{owner.name}</span>
          <button type="button" onClick={() => set({ connection: null })} aria-label={L("연동 필터 해제", "Clear integration filter")}><Ic name="close" size={13} /></button></span> : null}
        {failedRecently ? <span className="applied-chip"><span className="wrap-t">{L("최근 7일 실패", "Failed in 7 days")}</span>
          <button type="button" onClick={() => set({ "f.failed": null })} aria-label={L("최근 7일 실패 필터 해제", "Clear the failed in 7 days filter")}><Ic name="close" size={13} /></button></span> : null}
        {q ? <span className="applied-chip"><span className="wrap-t">{L("검색: ", "Search: ")}{q}</span>
          <button type="button" onClick={() => set({ q: null })} aria-label={L("검색 지우기", "Clear search")}><Ic name="close" size={13} /></button></span> : null}
      </div> : null}
      <div className="table-wrap"><table className="tbl">
        <thead><tr><th>{L("시작", "Started")}</th><th>{L("연동", "Integration")}</th><th className="col-md">{L("작업", "Run")}</th>
          <th>{L("상태", "Status")}</th><th className="col-sm">{L("결과", "Result")}</th><th className="col-sm">{L("소요 시간", "Duration")}</th></tr></thead>
        <tbody>
          {rows.length ? rows.map(run => {
            const who = ownerOf(run, map), kind = kindOf(run.kind), state = stateOf(run.status), note = rowNote(run, L, locale);
            const when = run.started_at ?? run.created_at;
            return <tr key={run.id} tabIndex={0} aria-selected={selected === run.id} onClick={() => set({ id: run.id, dtab: null })}
              onKeyDown={event => { if (event.key === "Enter") set({ id: run.id, dtab: null }); }}>
              <td><span data-tip={fmtDT(when, locale)}>{rel(when, locale)}</span></td>
              <td><div className="cred-cell"><Logo id={serviceOf(run) || "generic"} size={28} />
                <div className="cred-text"><div className="cred-name">{who?.conn.name ?? (run.kind === "inline" ? L("붙여 넣은 텍스트", "Pasted text") : L("연동 밖의 작업", "Outside integrations"))}</div>
                  {who?.child ? <div className="cred-hint">{who.child}</div> : null}</div></div></td>
              <td className="col-md">{L(...kind.name)}{kind.group === "scan" && run.mode && MODE[run.mode] ? <div className="ig-sub">{L(...MODE[run.mode])} · {L(...(TRIGGER[run.trigger_type ?? ""] ?? ["직접 실행", "Manual"]))}</div> : null}</td>
              <td><span className={cls("igs", STATE_TONE[state])}><span className="dot" />{L(...STATE_NAME[state])}</span>
                {note ? <div className="ig-note">{note}</div> : null}</td>
              <td className="col-sm">{resultOf(run, L)}</td>
              <td className="col-sm num">{scanDurationText(run.duration_seconds, locale)}</td>
            </tr>;
          }) : <EmptyRow colSpan={6}>{all.length ? L("조건에 맞는 기록이 없습니다. 필터를 줄여 보세요.", "No runs match. Try removing some filters.") : L("아직 실행한 작업이 없습니다.", "Nothing has run yet.")}</EmptyRow>}
        </tbody>
      </table></div>
      <div className="list-foot"><span>{L(`${rows.length}건`, `${rows.length} runs`)}</span><span>{L("최근 200건까지 보입니다", "Shows the latest 200 runs")}</span></div>
    </Card>

    {menu.anchor ? <Menu anchor={menu.anchor} onClose={menu.close} restore={menu.opener} label={menuKey === "state" ? L("상태", "Status") : L("서비스", "Service")}>
      {menuValues(menuKey).sort((a, b) => b[1] - a[1]).map(([value, count]) => <MenuItem key={value} checked={(menuKey === "state" ? states : services).includes(value)}
        end={<span className="num">{count}</span>} onSelect={() => toggle(menuKey, value)}>
        {menuKey === "state" ? L(...STATE_NAME[value as State]) : <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><Logo id={value} size={20} />{connections.data?.find(c => c.provider === value)?.name.split(" · ")[0] ?? value}</span>}
      </MenuItem>)}
      {(menuKey === "state" ? states : services).length ? <><MenuSep /><MenuItem className="pri" onSelect={() => { set({ [`f.${menuKey}`]: null }); menu.close(); }}>{L("선택 해제", "Clear selection")}</MenuItem></> : null}
    </Menu> : null}

    {scanMenu.anchor ? <Menu anchor={scanMenu.anchor} onClose={scanMenu.close} restore={scanMenu.opener} label={L("검사할 연동", "Integration to scan")}>
      {scannable.map(c => <MenuItem key={c.id} onSelect={() => { scanMenu.close(); setTargetsFor(c); }}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><Logo id={c.provider} size={20} />{c.name}</span></MenuItem>)}
    </Menu> : null}
    {targetsFor ? <TargetsModal conn={targetsFor} onClose={() => { setTargetsFor(null); runs.reload(); }} go={go} can={can} /> : null}

    {open ? <RunDrawer key={open.id} run={open} owner={ownerOf(open, map)} canAct={hasRole(session.role, "Analyst")} admin={session.role === "Admin"} tab={p.get("dtab") === "failures" ? "failures" : "summary"}
      onTab={value => set({ dtab: value === "summary" ? null : value })} onClose={() => set({ id: null, dtab: null })}
      onSettings={can("sources") ? (id => go("sources", { edit: id })) : undefined}
      onChanged={message => { toast(message); saved(); }} onError={reason => toast(reasonText(reason, L), "bad")} /> : null}
  </>;
}

/** The collection a schema 2 inventory or vault collection job belongs to: its controls act through it. */
export function collectionOf(run: Run): string | null {
  return run.kind === "provider-metadata-inventory" ? run.coverage_connection_id ?? null : null;
}

// Content scans stop while running (cremore.sources.registry CONTENT_SCAN_KINDS: each source's jobs, a scope run, pasted text);
// usage reads also stop while running; other jobs withdraw only while queued (cremore/api/routes/sources.py).
const STOPS_RUNNING: ReadonlySet<string> = new Set([...CONTENT_SOURCE_TYPES, "github-org", "scope", "inline", "credential-usage"]);

/** How a run is stopped, or null where it cannot be: a collection through its collection, a content scan while it runs,
 * any other job only while queued; never an upload from a customer-side CLI (it is not a job here) or an approved plan's
 * run (it is withdrawn by cancelling the plan). */
export function stopPath(run: Run): string | null {
  const state = stateOf(run.status);
  if (run.kind === "customer-collection" || run.kind === "provider-credential-action" || (state !== "queued" && state !== "running")
    || run.status === "CANCELLING") return null;
  const collection = collectionOf(run);
  if (collection) return `v2/coverage/connections/${collection}/collect/stop`;
  if (run.kind === "scope") return `scan-runs/${run.id}/cancel`;
  return state === "queued" || STOPS_RUNNING.has(run.kind) ? `source-scan-jobs/${run.id}/cancel` : null;
}

/** The stored runs whose report a run shows: a finished (or stopped, or failed) collection's. */
export function reportRuns(run: Run): string[] {
  const state = stateOf(run.status);
  return state === "queued" || state === "running" ? [] : run.coverage_run_ids ?? [];
}

type LiveCollection = { id: string; collection_paused: boolean; latest_job: { id: string } | null };

/** Whether a collection's pause, resume and stop act on this run: only while it runs and is still the collection's
 * current job (the server acts on that one, so a finished run must not reach a newer job). */
export function controls(run: Run, current: LiveCollection | undefined): boolean {
  const state = stateOf(run.status);
  return (state === "queued" || state === "running") && run.status !== "CANCELLING" && current?.latest_job?.id === run.id;
}

function RunDrawer({ run, owner, canAct, admin, tab, onTab, onClose, onSettings, onChanged, onError }: {
  run: Run; owner: Owner | undefined; canAct: boolean; admin: boolean; tab: "summary" | "failures"; onTab: (tab: "summary" | "failures") => void; onClose: () => void;
  onSettings?: (id: string) => void; onChanged: (message: string) => void; onError: (reason: unknown) => void;
}) {
  const L = useL();
  const locale = useLocale();
  const [busy, setBusy] = useState(false);
  const kind = kindOf(run.kind), state = stateOf(run.status);
  const provider = owner?.conn.provider ?? (run.kind === "inline" ? "inline" : "generic");
  const failures = run.failures ?? [];
  const act = async (work: () => Promise<unknown>, message: string) => {
    setBusy(true);
    try { await work(); onChanged(message); } catch (reason) { onError(reason); } finally { setBusy(false); }
  };
  // A collection is paused, let go on and stopped through itself; whether it is paused is the server's word, and the
  // controls show only while this run is the collection's current job (they act on that one).
  const collection = collectionOf(run);
  const active = state === "queued" || state === "running";
  const live = useApi<{ items: LiveCollection[] }>(collection && active && canAct ? "v2/coverage/connections" : null, { every: 5_000 });
  const current = live.data?.items.find(item => item.id === collection);
  const controllable = controls(run, current);
  const paused = Boolean(current?.collection_paused);
  const control = (action: "pause" | "resume") => act(() => send(`v2/coverage/connections/${collection}/collect/${action}`, "POST"),
    action === "pause" ? L("수집을 일시 정지했습니다", "Paused the collection") : L("수집을 재개했습니다", "Resumed the collection"));
  const stop = stopPath(run);
  const cancel = () => act(() => send(stop!, "POST"), L("작업을 멈추도록 요청했습니다", "Asked the run to stop"));
  // A people-directory collection's runs are an Analyst's to read (cremore/api/metadata_coverage.py PEOPLE); none
  // has an export in a service's own format.
  const child = owner?.conn.children.find(item => item.id === (run.coverage_connection_id ?? run.connection_id));
  const people = child?.purpose === "identity";
  // Below Analyst, a report shows only once its collection is known not to be a people directory.
  const reports = !canAct && (!child || people) ? [] : reportRuns(run);
  // Running again: the same scope, collection, catalog or check.
  const again = kind.group === "scan" && run.kind === "scope" && run.profile_id ? () => act(async () => {
    const plan = await send<{ plan_id: string; executable: boolean; profile_version: number }>(`scan-scope-profiles/${run.profile_id}/preview`, "POST");
    if (!plan.executable) throw new Error("SCOPE_PLAN_NOT_EXECUTABLE");
    await send("scan-runs", "POST", { plan_id: plan.plan_id, profile_version: plan.profile_version, mode: run.mode ?? "BASELINE" });
  }, L("같은 범위로 다시 검사를 시작했습니다", "Started the same scope again"))
    : collection ? () => act(() => send(`v2/coverage/connections/${collection}/collect`, "POST"), L("수집을 다시 시작했습니다", "Collection started again"))
      : run.kind === "catalog-refresh" && run.connection_id ? () => act(() => send(`connections/${run.connection_kind ?? "source"}/${run.connection_id}/resources/refresh`, "POST"), L("목록을 다시 가져오도록 요청했습니다", "Asked to refresh the list"))
        : run.kind === "provider-check" && run.provider_connection_id && admin ? () => act(() => send(`provider-connections/${run.provider_connection_id}/check`, "POST"), L("권한 확인을 다시 요청했습니다", "Access check requested again"))
          : run.kind === "finding-context" && run.finding_id ? () => act(() => send(`findings/${run.finding_id}/context`, "POST"), L("소유·접근 확인을 다시 요청했습니다", "Ownership and access check requested again"))
          : undefined;
  const facts: [string, ReactNode][] = [
    [L("작업", "Run"), L(...kind.name) + (run.mode && MODE[run.mode] && kind.group === "scan" ? ` · ${L(...MODE[run.mode])}` : "")],
    [L("실행 방식", "Started by"), L(...(TRIGGER[run.trigger_type ?? ""] ?? ["직접 실행", "Manual"]))],
    [L("대기 시작", "Queued"), fmtDT(run.created_at, locale)],
    [L("시작", "Started"), run.started_at ? fmtDT(run.started_at, locale) : "—"],
    [L("끝", "Finished"), run.completed_at ? fmtDT(run.completed_at, locale) : "—"],
    [L("소요 시간", "Duration"), scanDurationText(run.duration_seconds, locale)],
  ];
  if (kind.group === "scan") {
    facts.push([L("읽은 곳", "Read"), String(run.resources_succeeded)], [L("읽지 못한 곳", "Not read"), String(run.resources_failed)],
      [L("새로 찾은 노출", "New exposures"), String(run.findings_total)]);
    const skipped = (run.skipped_unchanged ?? 0) + (run.skipped_unsupported ?? 0) + (run.skipped_media ?? 0);
    if (skipped) facts.push([L("건너뜀", "Skipped"), L(`${skipped}곳 (바뀌지 않음 ${run.skipped_unchanged ?? 0} · 미지원 형식 ${run.skipped_unsupported ?? 0} · 미디어 ${run.skipped_media ?? 0})`,
      `${skipped} (unchanged ${run.skipped_unchanged ?? 0} · unsupported ${run.skipped_unsupported ?? 0} · media ${run.skipped_media ?? 0})`)]);
    if (run.extraction_reasons && Object.keys(run.extraction_reasons).length) facts.push([
      L("문서 읽기 제한", "Document reading limits"),
      Object.entries(run.extraction_reasons).map(([reason, count]) => `${failureCodeLabel(reason, locale)} · ${count}`).join(" / "),
    ]);
    if (run.requests) facts.push([L("요청 수", "Requests"), String(run.requests)]);
  } else if (kind.group !== "check") facts.push([metadataRun(run) ? L("메타데이터", "Metadata records") : L("항목", "Items"),
    itemCount(run) === null ? L("미확인", "Unavailable") : String(itemCount(run))]);
  if (run.stopped_reason) facts.push([L("멈춘 이유", "Stopped because"), failureCodeLabel(run.stopped_reason, locale)]);
  if (heldOnly(run)) facts.push([L("일부만 읽은 이유", "Why only in part"), L(...HELD)]);
  if (run.error) facts.push([L("오류", "Error"), <><span>{failureCodeLabel(run.error, locale)}</span> <span className="mono subtle">{run.error}</span></>]);

  const tabs = [{ id: "summary" as const, label: L("요약", "Summary") }, { id: "failures" as const, label: L("실패 상세", "Failures"), count: failures.length }];
  const hold = run.hold ? holdText(run.hold.code, locale) : null;
  return <Drawer label={L(`${L(...kind.name)} 상세`, `${L(...kind.name)} details`)} onClose={onClose}>
    <div className="drawer-head">
      <div className="dh-top">
        <div className="dh-logo"><Logo id={provider} size={34} /></div>
        <div className="dh-main">
          <div className="md-crumb">{owner?.conn.name ?? L("연동 밖의 작업", "Outside integrations")}{owner?.child ? ` › ${owner.child}` : ""}</div>
          <h2 className="dh-title">{L(...kind.name)}</h2>
          <div className="dh-badges"><span className={cls("igs", STATE_TONE[state])}><span className="dot" />{L(...STATE_NAME[state])}</span>
            <span className="tag">{rel(run.started_at ?? run.created_at, locale)}</span></div>
        </div>
        <div className="dh-actions"><button type="button" className="icon-btn" aria-label={L("상세 닫기", "Close details")} data-tip={L("상세 닫기", "Close details")} onClick={onClose}><Ic name="panelClose" size={19} /></button></div>
      </div>
      <DTabs value={tab} items={tabs} onChange={onTab} label={L("상세 탭", "Detail tabs")} />
    </div>
    <div className="drawer-body" id="drawer-body">
      {tab === "summary" ? <>
        {hold ? <section className="card"><div className="card-body"><div className="ig-result none"><Ic name="clock" size={16} /><span><b>{hold.title}</b> · {hold.action}</span></div></div></section> : null}
        <section className="card"><div className="card-head"><h3>{L("실행 정보", "Run")}</h3></div><div className="card-body">
          <Facts>{facts.map(([label, value]) => <Fact key={label} label={label}>{value}</Fact>)}</Facts>
          {state === "running" && run.progress ? <div className="mf-fill" style={{ marginTop: 12 }}><span className="bar"><span style={{ width: `${run.progress.total ? Math.round(run.progress.done / run.progress.total * 100) : 0}%` }} /></span>
            <span className="num">{L(`${run.progress.done}/${run.progress.total} 진행 · 실행 ${run.progress.running} · 대기 ${run.progress.queued}`, `${run.progress.done}/${run.progress.total} · ${run.progress.running} running · ${run.progress.queued} waiting`)}</span></div> : null}
        </div></section>
        <section className="card"><div className="card-body md-actions">
          {canAct && controllable ? <button type="button" className="ghost-btn" disabled={busy}
            onClick={() => void control(paused ? "resume" : "pause")}><Ic name={paused ? "play" : "pause"} size={15} />{paused ? L("재개", "Resume") : L("일시 정지", "Pause")}</button> : null}
          {run.status === "CANCELLING" ? <button type="button" className="ghost-btn" disabled><Ic name="stop" size={15} />{L("멈추는 중", "Stopping")}</button>
            : canAct && stop && (!collection || controllable) ? <button type="button" className="ghost-btn" disabled={busy} onClick={() => void cancel()}><Ic name="stop" size={15} />{L("작업 멈추기", "Stop the run")}</button> : null}
          {canAct && again && !active ? <button type="button" className="primary-btn" disabled={busy} onClick={() => void again()}><Ic name="refresh" size={15} />{L("다시 실행", "Run again")}</button> : null}
          {owner && onSettings ? <button type="button" className="ghost-btn" onClick={() => onSettings(owner.conn.id)}><Ic name="sliders" size={15} />{L("연동 설정 열기", "Open integration settings")}</button> : null}
        </div></section>
        {reports.map(id => <RunReport key={id} runId={id} exportable={!people} />)}
      </> : <section className="card"><div className="card-head"><h3>{L("읽지 못한 곳", "What could not be read")}</h3></div><div className="card-body">
        {failures.length ? <ul className="md-gaps">{failures.map((failure, index) => <li key={`${failure.root}:${index}`}><b className="mono">{failure.root}</b> · {failureCodeLabel(failure.code, locale)} <span className="mono subtle">{failure.code}</span></li>)}</ul>
          : <p className="subtle">{run.error ? failureCodeLabel(run.error, locale)
            : run.resources_failed ? L(`읽지 못한 곳이 ${run.resources_failed}곳 있습니다. 곳별 사유는 이 실행 기록에 남아 있지 않습니다.`, `${run.resources_failed} places could not be read. This run kept no reason per place.`)
              : L("실패한 곳이 없습니다.", "Nothing failed.")}</p>}
      </div></section>}
    </div>
  </Drawer>;
}
