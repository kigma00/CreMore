"use client";

/* Operations: whether CreMore is still watching. Every connection's sign-in, expiry and last collection in one
 * vocabulary (operations/connections; an Admin enters an expiry where the provider reports none), SIEM delivery per
 * destination (a test event, followed; held deliveries released) and the workers' beats and queue (operations/status).
 * Read every 15 seconds. ?section=siem opens at SIEM delivery (Integrations > Other settings links here). */

import { useEffect, useState } from "react";

import { failureCodeLabel } from "@/components/labels";
import { type Locale, useLocale } from "@/components/locale";
import { connectionAuthReason } from "@/lib/credential-lifecycle";
import { reasonCodeText, reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { Modal, useToast } from "@/console/layer";
import { Logo, serviceName } from "@/console/logos";
import type { ViewProps } from "@/console/shell";
import { fmtDay, fmtDT, rel, type Say, sayIn, useL } from "@/console/text";
import { Banner, Card, CardBody, EmptyRow, ErrorLine, Loading, PageHead, Seg, StateChip, TextField, Tile, Tiles } from "@/console/ui";
import { expiryAt, expiryDay, HEALTH_PATH, type HealthItem } from "@/console/views/integrations/model";
import { api } from "@/lib/dashboard-api";

export type SiemDestination = {
  destination: string; pending: number; held: number; oldest_pending_at: string | null; last_seen_at: string | null;
  last_success_at: string | null; last_failure_at: string | null; last_error_code: string | null; consecutive_failures: number;
  exporter_active: boolean; backlogged: boolean;
};
export type SiemStatus = { destinations: SiemDestination[]; exporter_active: boolean };
export type WorkerInstance = { worker_id: string; host: string | null; version: string | null; started_at: string | null; beat_at: string | null; alive: boolean };
export type OperationsAlert = { code: string; resource_type: string; resource_id: string; provider?: string; failing_roots?: number;
  failing_since?: string; error_codes?: string[]; last_run_at?: string | null; owed_replies?: number; open_threads?: number };
export type OperationsStatus = {
  worker: { alive: number; observed: number; last_beat_at: string | null; queue_delay_seconds: number | null; queued_jobs: number;
    running_jobs: number; heartbeat_interval_minutes: number; instances: WorkerInstance[] };
  alerts?: OperationsAlert[];
};

/** A team install (people sign in through the company IdP) whose collection rides on one person's sign-in somewhere:
 * it stops when that sign-in ends (cremore/operations/health.alerts). */
export const humanSessionOnTeamInstall = (status: OperationsStatus | null | undefined) =>
  Boolean(status?.alerts?.some(alert => alert.code === "HUMAN_SESSION_IN_SERVER_DEPLOYMENT"));
// Why a connection's change feed has kept failing for over an hour (cremore/operations/health.feed_alerts).
export const FEED_REASON: Record<string, [string, string]> = {
  CHANGE_FEED_RATE_LIMITED: ["요청 제한", "rate limited"], CHANGE_FEED_UNAVAILABLE: ["공급자 장애", "provider outage"],
  CHANGE_FEED_FAILING: ["조회 실패", "lookups failing"],
};
export const feedAlerts = (status: OperationsStatus | null | undefined) => (status?.alerts ?? []).filter(alert => FEED_REASON[alert.code]);
/** A failing change feed in words: whose, why, since when, and that the change scans of its failing targets wait until a
 * look succeeds. `item` is the connection's health row, which names it and says whether any scan is scheduled; without
 * it the text promises no scan. */
export function feedAlertText(alert: OperationsAlert, item: HealthItem | undefined, locale: Locale, now = Date.now()) {
  const L = sayIn(locale);
  const service = serviceName(alert.provider);
  const who = item ? L(`${service} 연결 ‘${item.name}’`, `${service} connection ‘${item.name}’`) : L(`${service} 연결`, `a ${service} connection`);
  const since = fmtDT(alert.failing_since, locale, undefined, now);
  const roots = alert.failing_roots ?? 1;
  const why = L(...(FEED_REASON[alert.code] ?? FEED_REASON.CHANGE_FEED_FAILING));
  const [ko, en] = !item ? ["있습니다.", "."]
    : item.freshness === "NOT_SCHEDULED" ? ["있고, 예약 검사도 없어 직접 검사하기 전까지 그 대상의 바뀐 내용을 읽지 않습니다.", ", and no scan is scheduled, so nothing reads their changes until someone scans."]
    : ["있고, 예약 검사(기본 매일 전체 검사)는 계속 돕니다.", "; scheduled scans (a full scan daily by default) still run."];
  return L(`${who}의 변경 감지가 ${since}부터 실패하고 있습니다(${why}). 실패하는 대상 ${roots}곳의 변경 검사는 조회가 성공할 때까지 멈춰 ${ko}`,
    `The change feed of ${who} has failed since ${since} (${why}). Change scans of the ${roots} failing target${roots === 1 ? "" : "s"} wait until a look succeeds${en}`);
}
// The response requests' team-channel thread job (cremore/governance/response_threads.alerts).
export const threadAlerts = (status: OperationsStatus | null | undefined) =>
  (status?.alerts ?? []).filter(alert => alert.code === "RESPONSE_THREADS_STOPPED" || alert.code === "RESPONSE_THREADS_FAILING");
/** The thread job in words: it stopped running (where it runs), or replies wait (why, and what to check). */
export function threadAlertText(alert: OperationsAlert, locale: Locale, now = Date.now()) {
  const L = sayIn(locale);
  const since = fmtDT(alert.failing_since, locale, undefined, now);
  if (alert.code === "RESPONSE_THREADS_STOPPED") {
    const n = alert.open_threads ?? 1;
    return L(`대응 요청의 팀 채널 스레드에 진행 상황을 올리는 작업이 ${since}부터 돌지 않았습니다(열린 스레드 ${n}개). 혼합 worker나 역할을 나눈 설치의 control 프로세스가 이 작업을 1분마다 실행하니, 그 프로세스가 도는지 확인하세요.`,
      `The job that posts progress to response requests' team channel threads has not run since ${since} (${n} open thread${n === 1 ? "" : "s"}). The mixed worker, or a split deployment's control process, runs it every minute: check that it is running.`);
  }
  const n = alert.owed_replies ?? 1;
  const code = alert.error_codes?.[0];
  // The shared SLACK_SCOPE_MISSING text is about the channel checks only; here chat:write may be what is missing.
  const text = code === "SLACK_SCOPE_MISSING" ? L("Slack 봇에 필요한 권한이 없습니다.", "The Slack bot lacks a scope it needs.")
    : code ? reasonCodeText(code, L) : "";
  const why = text ? L(` 마지막 오류: ${text}`, ` Last error: ${text}`) + (/[.!?]$/.test(text) ? "" : ".") : "";
  return L(`대응 요청의 팀 채널 스레드에 올릴 진행 기록 ${n}건이 ${since}부터 올라가지 않고 있습니다.${why} 연동 서비스 > 기타 설정 > 연락 발송의 Slack 봇 토큰과 권한(chat:write·channels:read·groups:read)을 확인하세요. 해결되면 밀린 기록을 순서대로 올립니다.`,
    `${n} progress repl${n === 1 ? "y has" : "ies have"} waited since ${since} to go to response requests' team channel threads.${why} Check the Slack bot token and its scopes (chat:write, channels:read, groups:read) under Integrations > Other settings > Contact delivery. Once fixed, what waited goes out in order.`);
}
export type Delivery = { destination: string; attempts: number; delivered_at: string | null; held_at: string | null; error_code: string | null };
type Tone = "ok" | "warn" | "bad" | "running" | undefined;

// The health vocabulary (cremore/operations/health.py), as the list and the SIEM events say it.
export const HEALTH: Record<string, { name: [string, string]; tone: Tone }> = {
  READY: { name: ["정상", "Ready"], tone: "ok" }, EXPIRING: { name: ["만료 임박", "Expiring"], tone: "warn" },
  REAUTH_REQUIRED: { name: ["재인증 필요", "Sign in again"], tone: "bad" }, PERMISSION_LIMITED: { name: ["권한 부족", "Permission missing"], tone: "bad" },
  SECRET_UNAVAILABLE: { name: ["인증 정보 읽기 실패", "Secret unavailable"], tone: "bad" }, DISABLED: { name: ["중지됨", "Stopped"], tone: undefined },
  UNKNOWN: { name: ["아직 모름", "Not yet known"], tone: undefined },
  FRESH: { name: ["최신", "Up to date"], tone: "ok" }, STALE: { name: ["오래됨", "Out of date"], tone: "warn" },
  NEVER_COLLECTED: { name: ["수집 전", "Never collected"], tone: "warn" }, NOT_SCHEDULED: { name: ["예약 없음", "Not scheduled"], tone: undefined },
  COMPLETE: { name: ["완료", "Complete"], tone: "ok" }, PARTIAL: { name: ["일부 완료", "Partial"], tone: "warn" },
  FAILED: { name: ["실패", "Failed"], tone: "bad" }, NOT_COLLECTED: { name: ["미수집", "Not collected"], tone: undefined },
};
export const RENEWAL: Record<string, [string, string]> = {
  AUTO: ["자동 갱신", "Renews itself"], MANUAL: ["사람이 교체", "Replaced by a person"], HUMAN_SESSION: ["사람의 로그인 세션", "A person's sign-in"],
  EXTERNAL: ["고객 환경 수집기가 보유", "Held by your collector"], UNKNOWN: ["갱신 방식 모름", "Renewal not known yet"],
};
// Reasons the health list gives itself (cremore/operations/health.py); a connection's sign-in reason and a collector's
// own code read as elsewhere in the console.
export const HEALTH_REASON: Record<string, [string, string]> = {
  AUTH_EXPIRING: ["인증 만료가 다가옵니다", "The sign-in expires soon"],
  AUTH_FRESHNESS_UNKNOWN: ["인증이 아직 확인되지 않았습니다", "The sign-in is not confirmed yet"],
  NO_CREDENTIAL: ["인증 정보가 없습니다", "No credential is set"],
  CREDENTIAL_REJECTED: ["공급자가 인증 정보를 거절했습니다", "The provider rejected the credential"],
  AWS_LOGIN_REQUIRED: ["CreMore의 AWS 로그인이 필요합니다", "CreMore needs to sign in to AWS"],
  AWS_SCANNER_IDENTITY_CHANGED: ["승인한 AWS 신원과 지금 신원이 다릅니다", "The AWS identity differs from the approved one"],
  GCP_OAUTH_OFFLINE_ACCESS_REQUIRED: ["Google에 다시 로그인해 오프라인 접근을 허용해야 합니다", "Sign in to Google again and allow offline access"],
  GCP_AMBIENT_CREDENTIALS_REQUIRED: ["worker에 Google Cloud 기본 인증(ADC)이 필요합니다", "The worker needs Google Cloud Application Default Credentials"],
  AZURE_KEY_VAULT_AMBIENT_CREDENTIALS_REQUIRED: ["worker에 Azure 기본 인증(관리 ID 등)이 필요합니다", "The worker needs ambient Azure credentials, such as a managed identity"],
  SCAN_FAILED: ["검사가 실패했습니다", "The scan failed"],
  COLLECTION_FAILED: ["수집이 실패했습니다", "The collection failed"],
  ACCOUNT_NOT_VALIDATED: ["계정 접근을 아직 확인하지 못했습니다", "Access to the account is not confirmed yet"],
};
export function healthReason(code: string, locale: "ko" | "en"): string {
  const own = HEALTH_REASON[code];
  if (own) return locale === "ko" ? own[0] : own[1];
  return connectionAuthReason(code, locale) || failureCodeLabel(code, locale);
}
/** The last day an Admin may enter: the API takes up to ten years ahead (cremore/api/routes/misc.py). */
export function latestExpiryDay(today: string) {
  const [year, month, day] = today.split("-").map(Number);
  return expiryDay(new Date(year + 10, month - 1, day).toISOString());
}
/** Whether an entered day can be saved: a real calendar day from today to ten years ahead. */
export function expiryValid(day: string, today: string) {
  const at = /^\d{4}-\d{2}-\d{2}$/.test(day) ? expiryAt(day) : null;
  // 2027-02-30 parses as March 2: only a day that reads back as itself is a real one.
  return at !== null && expiryDay(at) === day && day >= today && day <= latestExpiryDay(today);
}
export const KIND: Record<string, [string, string]> = {
  CONTENT: ["노출 검사", "Exposure scan"], METADATA: ["발급 목록", "Issuance inventory"], VAULT: ["금고", "Vault"],
  AWS_ACCOUNT: ["AWS 계정", "AWS account"], AWS_INVENTORY: ["AWS 발급 목록", "AWS inventory"],
};
const ATTENTION = ["EXPIRING", "REAUTH_REQUIRED", "PERMISSION_LIMITED", "SECRET_UNAVAILABLE"];

/** A record that needs a look: its sign-in, expiry or data, unless it is stopped. */
export function needsAttention(item: HealthItem) {
  return item.auth_state !== "DISABLED" && (ATTENTION.includes(item.auth_state) || item.freshness === "STALE" || item.last_status === "FAILED");
}
/** Only a credential that does not renew itself and whose provider gave no date takes one an Admin enters. */
export function acceptsOperatorExpiry(item: HealthItem) {
  return item.auth_state !== "DISABLED" && item.auth_renewal !== "AUTO" && item.expires_source !== "PROVIDER";
}
export function duration(seconds: number, L: Say) {
  if (seconds < 60) return L(`${seconds}초`, `${seconds}s`);
  if (seconds < 3600) return L(`${Math.round(seconds / 60)}분`, `${Math.round(seconds / 60)} min`);
  if (seconds < 172_800) return L(`${Math.round(seconds / 3600)}시간`, `${Math.round(seconds / 3600)} h`);
  return L(`${Math.round(seconds / 86_400)}일`, `${Math.round(seconds / 86_400)} days`);
}
const word = (code: string, L: Say) => (HEALTH[code] ? L(...HEALTH[code].name) : code);

/** A test event at each destination the exporter reported (one not tried yet reads as waiting); settled once every
 * destination delivered or held it. */
export function testOutcome(deliveries: Delivery[], names: string[]) {
  const all = [...new Set([...names, ...deliveries.map(row => row.destination)])];
  const rows = all.map(name => deliveries.find(row => row.destination === name)
    ?? { destination: name, attempts: 0, delivered_at: null, held_at: null, error_code: null });
  const settled = rows.length > 0 && rows.every(row => Boolean(row.delivered_at || row.held_at));
  return { rows, settled, held: rows.some(row => Boolean(row.held_at)), delivered: settled && rows.every(row => Boolean(row.delivered_at)) };
}

export function Operations({ route, setParams, go, can }: ViewProps) {
  const L = useL();
  const locale = useLocale();
  const health = useApi<{ items: HealthItem[] }>(HEALTH_PATH, { every: 15_000 });
  const siem = useApi<SiemStatus>("siem/status", { every: 15_000 });
  const status = useApi<OperationsStatus>("operations/status", { every: 15_000 });
  const [editing, setEditing] = useState<HealthItem | null>(null);
  const section = route.params.get("section");
  const only = route.params.get("attention") === "1";
  // SIEM delivery sits under the health list: scroll to it once the cards above it have their height.
  const ready = [health, siem, status].every(read => Boolean(read.data || read.error));
  useEffect(() => {
    if (section === "siem" && ready) document.getElementById("ops-siem")?.scrollIntoView({ block: "start" });
  }, [section, ready]);

  const title = L("운영 상태", "Operations");
  const meta = L("CreMore가 계속 지켜보고 있는지", "Whether CreMore is still watching");
  if (health.error && siem.error && status.error) return <><PageHead title={title} meta={meta} /><ErrorLine onRetry={() => { health.reload(); siem.reload(); status.reload(); }}>{reasonText(health.error, L)}</ErrorLine></>;
  if (!health.data && !siem.data && !status.data) return <><PageHead title={title} meta={meta} /><Loading /></>;

  const items = health.data?.items ?? [];
  const attention = items.filter(needsAttention);
  const severe = attention.some(item => ATTENTION.slice(1).includes(item.auth_state));
  const destinations = siem.data?.destinations ?? [];
  const worker = status.data?.worker;
  const filterable = attention.length > 0 && attention.length < items.length;
  const shown = filterable && only ? attention : items;
  const siemValue = !destinations.length ? L("보고 없음", "Not reported") : siem.data?.exporter_active ? L("전송 중", "Running") : L("응답 없음", "Not seen");
  const siemBad = destinations.length > 0 && (!siem.data?.exporter_active || destinations.some(row => row.backlogged));

  return <>
    <PageHead title={title} meta={meta} />
    {humanSessionOnTeamInstall(status.data) ? <Banner tone="warn" icon="alert">
      {L("이 설치의 AWS 수집이 한 사람의 IAM Identity Center 로그인에 기대고 있어, 그 로그인이 끝나면 멈춥니다. CreMore가 AWS에 닿는 신원을 서버 역할(EC2·쿠버네티스)이나 기계 신원(회사 IdP)으로 바꾸고, 권한 세트로 읽는 계정은 멤버 역할로 옮기세요.",
        "AWS collection here rides on one person's IAM Identity Center sign-in and stops when it ends. Have CreMore reach AWS as the server (an instance or pod role) or the machine identity (company IdP), and move accounts read through a permission set to the member role.")}
    </Banner> : null}
    {feedAlerts(status.data).map(alert => <Banner key={alert.resource_id} tone="warn" icon="alert">
      {feedAlertText(alert, items.find(item => item.kind === "CONTENT" && item.id === alert.resource_id), locale)}</Banner>)}
    {threadAlerts(status.data).map(alert => <Banner key={alert.code} tone="warn" icon="alert">{threadAlertText(alert, locale)}</Banner>)}
    <Tiles>
      <Tile icon="plug" tone={!health.data ? "gray" : severe ? "red" : attention.length ? "amber" : "green"} label={L("확인할 연동", "Needs attention")}
        value={health.data ? attention.length : "—"} of={health.data ? items.length : undefined}
        onClick={filterable ? () => setParams({ attention: only ? null : "1" }) : undefined}
        tip={L("인증·만료·수집 실패·오래된 데이터 중 하나가 있는 연결입니다.", "Connections with a sign-in, expiry, failed collection or out-of-date data to look at.")} />
      <Tile icon="activity" tone={!destinations.length ? "gray" : siemBad ? "red" : "green"} label={L("SIEM 전송", "SIEM delivery")} value={siem.data ? siemValue : "—"}
        onClick={() => document.getElementById("ops-siem")?.scrollIntoView({ behavior: "smooth", block: "start" })}
        sub={destinations.some(row => row.backlogged) ? L("밀린 목적지가 있습니다", "A destination is behind") : destinations.length ? L(`목적지 ${destinations.length}곳`, `${destinations.length} destination${destinations.length === 1 ? "" : "s"}`) : undefined} />
      <Tile icon="server" tone={!worker?.observed ? "gray" : worker.alive ? "green" : "red"} label={L("살아 있는 worker", "Workers alive")}
        value={worker ? worker.alive : "—"} of={worker ? worker.observed : undefined}
        sub={worker?.last_beat_at ? L(`마지막 신호 ${rel(worker.last_beat_at, locale)}`, `Last beat ${rel(worker.last_beat_at, locale)}`) : undefined} />
      <Tile icon="clock" tone={worker?.queue_delay_seconds != null && worker.queue_delay_seconds > 3600 ? "amber" : "blue"} label={L("가장 오래 기다린 작업", "Oldest waiting job")}
        value={!worker ? "—" : worker.queue_delay_seconds == null ? L("없음", "None") : duration(worker.queue_delay_seconds, L)}
        sub={worker ? L(`대기 ${worker.queued_jobs} · 실행 ${worker.running_jobs}`, `${worker.queued_jobs} queued · ${worker.running_jobs} running`) : undefined}
        onClick={can("scans") ? () => go("scans", { "f.state": "queued,running" }) : undefined} />
    </Tiles>

    <Card title={L("연결 상태", "Connection health")} className="list-card"
      info={L("노출 검사·발급 목록·금고·AWS 계정을 같은 기준으로 봅니다.", "Exposure scans, inventories, vaults and AWS accounts in one vocabulary.")}
      right={filterable ? <Seg value={only ? "attention" : "all"} label={L("보기", "Show")} onChange={next => setParams({ attention: next === "attention" ? "1" : null })}
        options={[{ id: "all", label: L(`전체 ${items.length}`, `All ${items.length}`) }, { id: "attention", label: L(`확인할 것 ${attention.length}`, `To look at ${attention.length}`) }]} /> : undefined}>
      {health.error ? <CardBody><ErrorLine onRetry={health.reload}>{reasonText(health.error, L)}</ErrorLine></CardBody>
        : !health.data ? <CardBody><Loading /></CardBody> : <div className="table-wrap"><table className="tbl">
        <thead><tr><th>{L("연결", "Connection")}</th><th>{L("인증·만료", "Sign-in and expiry")}</th>
          <th>{L("데이터", "Data")}</th><th className="col-sm">{L("마지막 수집", "Last collection")}</th><th><span className="sr">{L("작업", "Actions")}</span></th></tr></thead>
        <tbody>
          {shown.length ? shown.map(item => <tr key={item.key}>
            <td><div className="cred-cell"><Logo id={item.provider} size={28} /><div className="cred-text"><div className="cred-name">{item.name}</div>
              <div className="cred-hint">{L(...(KIND[item.kind] ?? [item.kind, item.kind]))}{item.auth_renewal ? ` · ${L(...(RENEWAL[item.auth_renewal] ?? [item.auth_renewal, item.auth_renewal]))}` : ""}</div></div></div></td>
            <td><StateChip tone={HEALTH[item.auth_state]?.tone}>{word(item.auth_state, L)}</StateChip>
              {item.auth_reason ? <div className="ig-note">{healthReason(item.auth_reason, locale)}</div> : null}
              {item.expires_at ? <div className={item.expiry_stage !== "NONE" ? "ig-note" : "ig-sub"} data-tip={fmtDT(item.expires_at, locale)}>
                {L(`만료 ${fmtDay(item.expires_at, locale)}`, `Expires ${fmtDay(item.expires_at, locale)}`)}
                {" · "}{item.expires_source === "OPERATOR" ? L("관리자 입력", "entered by an Admin") : L("공급자 보고", "from the provider")}
                {item.expiry_stage !== "NONE" ? ` · ${item.expiry_stage === "EXPIRED" ? L("만료됨", "expired") : item.expiry_stage === "D3" ? L("3일 이내", "within 3 days") : L("14일 이내", "within 14 days")}` : ""}</div> : null}</td>
            <td><StateChip tone={HEALTH[item.freshness]?.tone}>{word(item.freshness, L)}</StateChip>
              {item.last_success_at ? <div className="ig-sub" data-tip={fmtDT(item.last_success_at, locale)}>{L(`성공 ${rel(item.last_success_at, locale)}`, `Succeeded ${rel(item.last_success_at, locale)}`)}</div> : null}</td>
            <td className="col-sm"><StateChip tone={HEALTH[item.last_status]?.tone}>{word(item.last_status, L)}</StateChip>
              {item.last_failure_code ? <div className="ig-note">{healthReason(item.last_failure_code, locale)}</div> : null}</td>
            <td>{acceptsOperatorExpiry(item) ? <button type="button" className="ghost-btn" onClick={() => setEditing(item)}>
              <Ic name="hourglass" size={15} />{item.expires_source === "OPERATOR" ? L("만료일 변경", "Change expiry") : L("만료일 입력", "Enter expiry")}</button> : null}</td>
          </tr>) : <EmptyRow colSpan={5}>{L("등록된 연결이 아직 없습니다.", "No connection is registered yet.")}</EmptyRow>}
        </tbody>
      </table></div>}
    </Card>

    <SiemCard siem={siem} />
    <Workers worker={worker} error={status.error} reload={status.reload} loading={!status.data && !status.error} />
    {editing ? <ExpiryModal item={editing} onClose={() => setEditing(null)} onDone={() => { setEditing(null); health.reload(); }} /> : null}
  </>;
}

function ExpiryModal({ item, onClose, onDone }: { item: HealthItem; onClose: () => void; onDone: () => void }) {
  const L = useL();
  const toast = useToast();
  const saved = useSaved();
  const [day, setDay] = useState(item.expires_source === "OPERATOR" ? expiryDay(item.expires_at) : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const today = expiryDay(new Date().toISOString());
  const save = async (value: string | null) => {
    setBusy(true); setError(null);
    try {
      await send(`operations/connections/${encodeURIComponent(item.key)}/expiry`, "PUT", { expires_at: value });
      saved(); toast(value ? L("만료일을 저장했습니다", "Saved the expiry") : L("입력한 만료일을 지웠습니다", "Cleared the entered expiry"));
      onDone();
    } catch (reason) { setError(reasonText(reason, L)); } finally { setBusy(false); }
  };
  return <Modal onClose={onClose} labelledBy="expiry-title" size="narrow" dismissable={!busy}>
    <h2 id="expiry-title">{L("만료일", "Expiry")} <small>{item.name}</small></h2>
    <p className="ig-sub">{L("공급자가 만료일을 알려 주지 않는 자격증명입니다. 입력한 날의 끝에 만료된 것으로 보고 14일·3일 전에 알립니다.",
      "The provider reports no expiry for this credential. It counts as expired at the end of the day you enter, with notices 14 and 3 days before.")}</p>
    {error ? <Banner tone="bad" icon="alert">{error}</Banner> : null}
    <TextField label={L("만료일", "Expires on")} type="date" value={day} onChange={setDay} min={today} max={latestExpiryDay(today)} required
      hint={day && !expiryValid(day, today) ? L("오늘부터 10년 안의 날짜를 넣습니다.", "Enter a day from today to ten years ahead.") : undefined} />
    <div className="modal-foot">
      {item.expires_source === "OPERATOR" ? <button type="button" className="ghost-btn" disabled={busy} onClick={() => void save(null)} style={{ marginRight: "auto" }}>{L("지우기", "Clear")}</button> : null}
      <button type="button" className="ghost-btn" onClick={onClose} disabled={busy}>{L("취소", "Cancel")}</button>
      {/* Only a real day is sent: an unreadable one must never become "clear the entered expiry". */}
      <button type="button" className="primary-btn" disabled={busy || !expiryValid(day, today)} onClick={() => { const at = expiryAt(day); if (at) void save(at); }}>{L("저장", "Save")}</button>
    </div>
  </Modal>;
}

function SiemCard({ siem }: { siem: ReturnType<typeof useApi<SiemStatus>> }) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const [test, setTest] = useState<{ id: string; deliveries: Delivery[]; tries: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const destinations = siem.data?.destinations ?? [];
  const names = destinations.map(row => row.destination);
  const outcome = test ? testOutcome(test.deliveries, names) : null;
  useEffect(() => {
    if (!test || test.tries >= 20 || testOutcome(test.deliveries, names).settled) return;
    // The exporter picks a test event up within its poll; the deliveries are asked every 3 seconds, 20 times at most.
    const timer = window.setTimeout(async () => {
      let deliveries = test.deliveries;
      try { deliveries = (await api<{ deliveries: Delivery[] }>(`siem/events/${encodeURIComponent(test.id)}/deliveries`)).deliveries; } catch { /* asked again */ }
      setTest(current => current && current.id === test.id ? { ...current, deliveries, tries: current.tries + 1 } : current);
    }, 3000);
    return () => window.clearTimeout(timer);
  }, [test, names.join("\n")]); // eslint-disable-line react-hooks/exhaustive-deps
  const act = async (work: () => Promise<unknown>, done: string) => {
    setBusy(true);
    try { await work(); saved(); toast(done); } catch (reason) { toast(reasonText(reason, L), "bad"); } finally { setBusy(false); }
  };
  const sendTest = () => act(async () => {
    const queued = await send<{ event_id: string }>("siem/test-event", "POST");
    setTest({ id: queued.event_id, deliveries: [], tries: 0 });
  }, L("테스트 이벤트를 보냈습니다", "Sent a test event"));
  const release = (destination: string) => act(async () => {
    await send(`siem/destinations/${encodeURIComponent(destination)}/release-held`, "POST");
    siem.reload();
  }, L("보류한 전송을 다시 보냅니다", "Held deliveries are sent again"));
  const state = (row: Delivery) => row.delivered_at ? L("전달됨", "delivered") : row.held_at ? L("보류", "held") : L("대기", "waiting");
  return <Card id="ops-siem" title={L("SIEM 전송", "SIEM delivery")} className="list-card"
    info={L("SIEM 목적지는 설치 전체에 한 번 설정합니다. 현재와 앞으로 연결할 모든 SaaS·클라우드의 CreMore 이벤트에 공통 적용됩니다.",
      "Configure SIEM destinations once for the installation. They receive CreMore events for every current and future SaaS and cloud connection.")}
    right={destinations.length ? <button type="button" className="ghost-btn" disabled={busy} onClick={() => void sendTest()}><Ic name="activity" size={15} />{L("테스트 이벤트 보내기", "Send a test event")}</button> : undefined}>
    {siem.error ? <CardBody><ErrorLine onRetry={siem.reload}>{reasonText(siem.error, L)}</ErrorLine></CardBody> : !siem.data ? <CardBody><Loading /></CardBody> : <>
      {test && outcome ? <CardBody><Banner icon="activity" tone={outcome.held ? "warn" : outcome.delivered ? "ok" : undefined}>
        <b>{L("테스트 이벤트", "Test event")}</b> <span className="mono">{test.id.slice(0, 8)}</span>{" · "}
        {!test.deliveries.length && test.tries >= 20 ? L("exporter가 가져가지 않았습니다", "The exporter has not picked it up")
          : outcome.rows.map(row => `${row.destination}: ${state(row)}${row.error_code ? ` (${failureCodeLabel(row.error_code, locale)})` : ""}`).join(" · ")}
      </Banner></CardBody> : null}
      <div className="table-wrap"><table className="tbl">
        <thead><tr><th>{L("목적지", "Destination")}</th><th>{L("상태", "State")}</th><th>{L("대기", "Waiting")}</th><th>{L("보류", "Held")}</th>
          <th className="col-md">{L("마지막 성공", "Last success")}</th><th className="col-sm">{L("연속 실패", "Failures in a row")}</th><th><span className="sr">{L("작업", "Actions")}</span></th></tr></thead>
        <tbody>
          {destinations.length ? destinations.map(row => <tr key={row.destination}>
            <td><b className="mono">{row.destination}</b></td>
            <td>{!row.exporter_active ? <StateChip tone="bad" tip={L("exporter가 2분 넘게 응답하지 않았습니다.", "The exporter has not reported for two minutes.")}>{L("응답 없음", "Not seen")}</StateChip>
              : row.backlogged ? <StateChip tone="warn">{L("밀림", "Behind")}</StateChip> : <StateChip tone="ok">{L("정상", "Keeping up")}</StateChip>}</td>
            <td className="num">{row.pending}{row.oldest_pending_at ? <div className="ig-sub">{L(`가장 오래된 것 ${rel(row.oldest_pending_at, locale)}`, `Oldest ${rel(row.oldest_pending_at, locale)}`)}</div> : null}</td>
            <td className="num">{row.held}</td>
            <td className="col-md">{row.last_success_at ? <span data-tip={fmtDT(row.last_success_at, locale)}>{rel(row.last_success_at, locale)}</span> : "—"}</td>
            <td className="col-sm num">{row.consecutive_failures}{row.last_error_code ? <div className="ig-note">{failureCodeLabel(row.last_error_code, locale)}</div> : null}</td>
            <td>{row.held ? <button type="button" className="ghost-btn" disabled={busy} onClick={() => void release(row.destination)}>
              <Ic name="refresh" size={15} />{L(`보류 ${row.held}건 다시 보내기`, `Retry ${row.held} held`)}</button> : null}</td>
          </tr>) : <EmptyRow colSpan={7}>{L("설치 공통 SIEM 목적지 파일로 cremore-siem을 실행하면 모든 연동의 이벤트를 전송합니다. SaaS·클라우드마다 따로 설정할 필요가 없습니다.",
            "Run cremore-siem with the installation's destination file to send events from every connection. No per-SaaS or per-cloud setup is needed.")}</EmptyRow>}
        </tbody>
      </table></div>
    </>}
  </Card>;
}

function Workers({ worker, error, reload, loading }: { worker: OperationsStatus["worker"] | undefined; error: unknown; reload: () => void; loading: boolean }) {
  const L = useL();
  const locale = useLocale();
  const instances = worker?.instances ?? [];
  return <Card title="Worker" className="list-card"
    info={worker ? L(`worker마다 1분마다 생존 신호를 남기고, 그중 하나가 ${worker.heartbeat_interval_minutes}분마다 SIEM에 platform.heartbeat를 보냅니다. 끊기면 SIEM에서 경보를 겁니다.`,
      `Each worker records a beat every minute; one sends platform.heartbeat to the SIEM every ${worker.heartbeat_interval_minutes} min. Alert on it in the SIEM when it stops.`) : undefined}>
    {error ? <CardBody><ErrorLine onRetry={reload}>{reasonText(error, L)}</ErrorLine></CardBody> : loading ? <CardBody><Loading /></CardBody> : <div className="table-wrap"><table className="tbl">
      <thead><tr><th>{L("호스트", "Host")}</th><th>{L("상태", "State")}</th><th>{L("마지막 신호", "Last beat")}</th>
        <th className="col-md">{L("시작", "Started")}</th><th className="col-sm">{L("버전", "Version")}</th></tr></thead>
      <tbody>
        {instances.length ? instances.map(row => <tr key={row.worker_id}>
          <td><b>{row.host || row.worker_id.slice(0, 8)}</b><div className="ig-sub mono">{row.worker_id.slice(0, 8)}</div></td>
          <td>{row.alive ? <StateChip tone="ok">{L("살아 있음", "Alive")}</StateChip> : <StateChip tone="bad">{L("신호 없음", "No beat")}</StateChip>}</td>
          <td>{row.beat_at ? <span data-tip={fmtDT(row.beat_at, locale)}>{rel(row.beat_at, locale)}</span> : "—"}</td>
          <td className="col-md">{row.started_at ? fmtDT(row.started_at, locale) : "—"}</td>
          <td className="col-sm">{row.version ?? "—"}</td>
        </tr>) : <EmptyRow colSpan={5}>{L("최근 하루 동안 생존 신호를 남긴 worker가 없습니다.", "No worker has recorded a beat in the last day.")}</EmptyRow>}
      </tbody>
    </table></div>}
  </Card>;
}
