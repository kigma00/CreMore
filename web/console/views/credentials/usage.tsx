"use client";

/* 사용 기록 (usage records) in the credential panel. The key facts give every credential its last use and the record
 * it comes from (an issuance inventory's last-used field, an organization audit log). Where the service can be asked
 * about one credential on demand -- a discovered AWS access key: CloudTrail event history (management events of the
 * last 90 days, in the owning account's enabled Regions) and IAM's last-used record, read with the approved
 * scanning identity -- this card runs that lookup and shows what it saw: when, over which window and Regions, the
 * calls by service, what they do and the latest ones. A lookup that did not finish never reads as "no calls". */

import { useEffect, useRef, useState } from "react";

import { useLocale } from "@/components/locale";
import type { CredentialIdentityPolicies, CredentialUsage, CredentialUsageEvent } from "@/lib/dashboard-types";
import { reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { useToast } from "@/console/layer";
import { type CredentialRecord, sourceLabel } from "@/console/records";
import { fmtDT, type Say, useL } from "@/console/text";
import { Banner, Card, CardBody, ErrorLine, Fact, Facts, Loading, StateChip } from "@/console/ui";

/** The snapshot the API serves: its region discovery can also be CAPPED or FAILED, and a lookup also keeps the
 * principal's identity policies. */
export type Usage = Omit<CredentialUsage, "region_discovery_status"> & {
  region_discovery_status?: string; identity_policies?: CredentialIdentityPolicies;
};

/** Whether this credential's service answers a lookup about it now: a discovered AWS access key (AKIA/ASIA). */
export function usageLookup(c: CredentialRecord): boolean {
  return c.provider === "aws" && Boolean(c.credential_id) && /^(AKIA|ASIA)/.test(c.hint ?? "");
}

/** A session key (ASIA) is looked up in the account of the principal its verification named; without one there is no
 * account to ask. A long-lived key (AKIA) is found in the connected accounts' own IAM. */
export function needsPrincipal(c: CredentialRecord, principal: string | null | undefined): boolean {
  return /^ASIA/.test(c.hint ?? "") && !principal;
}

const service = (event: CredentialUsageEvent) => event.event_source.replace(/\.amazonaws\.com$/, "") || "?";

/** The calls grouped by the service they went to, busiest first: calls, writes, denials and the latest time. */
export function byService(events: CredentialUsageEvent[]) {
  const out = new Map<string, { service: string; calls: number; writes: number; denied: number; last: string | null }>();
  for (const event of events) {
    const row = out.get(service(event)) ?? { service: service(event), calls: 0, writes: 0, denied: 0, last: null };
    row.calls += 1;
    if (event.access_mode === "WRITE") row.writes += 1;
    if (event.outcome === "DENIED") row.denied += 1;
    if (event.event_time && (!row.last || event.event_time > row.last)) row.last = event.event_time;
    out.set(row.service, row);
  }
  return [...out.values()].sort((a, b) => b.calls - a.calls || a.service.localeCompare(b.service));
}

/** Why a lookup did not finish, as the codes it recorded (region discovery and each Region's). */
export function failureCodes(u: Usage): string[] {
  return [...new Set([u.region_discovery_error, ...(u.coverage ?? []).map(item => item.error_code)].filter((code): code is string => Boolean(code)))];
}

/** What a lookup's status means for this card, in words; null when it finished as asked. Only someone who can run the
 * lookup is told to run it again. */
export function usageStatusText(u: Usage, L: Say, canLookup: boolean): string | null {
  if (u.refresh_job && ["QUEUED", "RUNNING", "CANCELLING"].includes(u.refresh_job.status)) {
    if (u.refresh_job.error_code && u.refresh_job.error_code !== "USAGE_PAGINATION_PENDING")
      return L(`수집이 대기 중입니다 (${u.refresh_job.error_code}). 저장한 위치부터 이어서 읽습니다.`,
        `Collection is waiting (${u.refresh_job.error_code}). It resumes from the saved position.`);
    return L("백그라운드에서 페이지를 이어서 수집하고 있습니다. 이 화면을 닫아도 계속됩니다.",
      "Collecting pages in the background. Collection continues after this panel closes.");
  }
  if (u.refresh_job && ["FAILED", "CANCELLED"].includes(u.refresh_job.status))
    return L(`수집이 중단됐습니다${u.refresh_job.error_code ? ` (${u.refresh_job.error_code})` : ""}. 저장된 기록은 유지합니다.`,
      `Collection stopped${u.refresh_job.error_code ? ` (${u.refresh_job.error_code})` : ""}. Saved evidence is retained.`);
  switch (u.collection_status) {
    case "NOT_COLLECTED": return canLookup
      ? L("아직 조회하지 않았습니다. 조회하면 이 키를 가진 계정의 CloudTrail 이벤트 기록(최근 90일 관리 이벤트, 켜 둔 리전)과 IAM 마지막 사용 기록을 백그라운드에서 읽습니다.",
        "Not looked up yet. A background lookup reads CloudTrail event history (management events of the last 90 days, in enabled Regions) and IAM's last-used record in the account that holds the key.")
      : L("아직 조회하지 않았습니다.", "Not looked up yet.");
    case "ACCOUNT_UNVERIFIED": return L("이 기록은 키를 가진 계정을 확인하기 전에 모았습니다.", "This record was gathered before the account holding the key was confirmed.")
      + (canLookup ? L(" 다시 조회하면 그 계정에서 새로 모읍니다.", " Looking it up again gathers it from that account.") : "");
    case "PARTIAL": {
      const parts = [L(`리전 ${u.regions_discovered}곳 중 ${u.regions_complete}곳을 다 읽었습니다`, `${u.regions_complete} of ${u.regions_discovered} Regions were read in full`)];
      if (u.region_discovery_status === "FALLBACK") parts.push(L("켜 둔 리전 목록을 읽지 못해 기본 리전을 읽었습니다", "the enabled Regions could not be listed, so the default ones were read"));
      if (u.region_discovery_status === "CAPPED") parts.push(L(`켜 둔 리전 가운데 ${u.regions_discovered}곳까지만 읽었습니다`, `only ${u.regions_discovered} of the enabled Regions were read`));
      if (u.regions_failed) parts.push(L(`${u.regions_failed}곳은 읽지 못했습니다`, `${u.regions_failed} could not be read`));
      const codes = failureCodes(u);
      if (u.regions_capped) {
        const limit = u.events_per_region ?? 100; // snapshots saved before the higher limit
        if (codes.includes("TIME_LIMIT_REACHED")) {
          parts.push(L("수집 시작 후 6시간이 지나 중단했습니다", "Collection stopped six hours after it began"));
        } else if (codes.includes("REQUEST_LIMIT_REACHED")) {
          parts.push(L(`조회 예산 ${u.request_limit}회에 도달했습니다`, `The ${u.request_limit}-request budget was reached`));
        } else if (codes.includes("BYTE_LIMIT_REACHED") || codes.includes("PAGE_LIMIT_REACHED")) {
          parts.push(L(`${u.regions_capped}곳은 페이지 또는 저장 크기 한도에 도달했습니다`,
            `${u.regions_capped} reached the page or saved-size limit`));
        } else parts.push(L(`${u.regions_capped}곳은 리전마다 호출 ${limit}건까지만 담았습니다`,
          `${u.regions_capped} ${u.regions_capped === 1 ? "holds" : "hold"} only ${u.regions_capped === 1 ? "its" : "their"} first ${limit} calls`));
      }
      if (codes.length) parts.push(L(`사유: ${codes.join(", ")}`, `Reasons: ${codes.join(", ")}`));
      return `${parts.join(" · ")}.`;
    }
    case "FAILED": {
      const codes = failureCodes(u);
      return L("조회하지 못했습니다", "The lookup did not finish") + (codes.length ? ` (${codes.join(", ")})` : "")
        + (canLookup ? L(". 다시 조회해 보세요.", ". Look it up again.") : ".");
    }
    default: return null;
  }
}

/** What a lookup saw, from its snapshot alone (the card fetches it). */
export function UsageBody({ u, canLookup }: { u: Usage; canLookup: boolean }) {
  const L = useL();
  const locale = useLocale();
  const status = usageStatusText(u, L, canLookup);
  // No count where there is nothing to count from: a lookup that failed, or an unconfirmed record that holds no calls.
  const failed = u.collection_status === "FAILED" || (u.collection_status === "ACCOUNT_UNVERIFIED" && !u.events.length);
  const services = u.summary ? Object.values(u.summary.services).sort((a, b) => b.calls - a.calls || a.service.localeCompare(b.service)) : byService(u.events);
  const total = u.summary?.events ?? u.events.length;
  const latest = u.events.slice(0, 20);  // newest first, as the API sorts them
  const denied = u.summary?.denied ?? u.events.filter(event => event.outcome === "DENIED").length;
  const observed = u.techniques?.observed ?? [];
  return <>
    {status ? u.collection_status === "NOT_COLLECTED" ? <p className="ig-sub">{status}</p>
      : u.collection_status === "PARTIAL" && !["QUEUED", "RUNNING", "CANCELLING"].includes(u.refresh_job?.status ?? "") ? <details className="usage-status">
        <summary>
          <StateChip tone="warn">{L("부분 수집", "Partial collection")}</StateChip>
          <span className="usage-status-counts">
            <span>{L(`리전 완료 ${u.regions_complete}/${u.regions_discovered}`, `Regions complete ${u.regions_complete}/${u.regions_discovered}`)}</span>
            {u.regions_failed ? <span>{L(`조회 실패 ${u.regions_failed}`, `${u.regions_failed} failed`)}</span> : null}
            {u.regions_capped ? <span>{L(`한도 도달 ${u.regions_capped}`, `${u.regions_capped} capped`)}</span> : null}
          </span>
          <span className="usage-status-toggle">{L("상세 사유", "Details")}<Ic name="down" size={14} /></span>
        </summary>
        <p>{status}</p>
      </details> : <Banner tone="warn" icon="alert">{status}</Banner> : null}
    {u.collection_status !== "NOT_COLLECTED" ? <Facts>
      <Fact label={L("조회 기간", "Window")}>{u.window_start && u.window_end ? `${fmtDT(u.window_start, locale)} ~ ${fmtDT(u.window_end, locale)}` : "—"}</Fact>
      <Fact label={L("읽은 리전", "Regions read")}>{`${u.regions_complete}/${u.regions_discovered}`}</Fact>
      <Fact label={L("관측된 호출", "Calls observed")}>{failed && !total ? "—" : L(`${total}건${denied ? ` · 거부 ${denied}건` : ""}`, `${total}${denied ? ` · ${denied} denied` : ""}`)}</Fact>
    </Facts> : null}
    {services.length ? <div className="usage-block">
      <h4 className="usage-head">{L("서비스별 호출", "Calls by service")}</h4>
      <ul className="pill-wrap usage-services">{services.map(row => <li className="tag" key={row.service}>
        {row.service} · {L(`${row.calls}건`, String(row.calls))}{row.writes ? L(` · 쓰기 ${row.writes}`, ` · ${row.writes} write`) : ""}{row.denied ? L(` · 거부 ${row.denied}`, ` · ${row.denied} denied`) : ""}
        {row.last ? L(` · 마지막 ${fmtDT(row.last, locale)}`, ` · last ${fmtDT(row.last, locale)}`) : ""}</li>)}</ul>
    </div> : null}
    {observed.length ? <div className="usage-block">
      <h4 className="usage-head">{L("호출이 하는 일", "What the calls do")}</h4>
      <ul className="pill-wrap usage-services">{observed.map(item => <li className="tag" key={item.technique_id}>{item.technique_name} · {L(`${item.events}건`, String(item.events))}
        <span className="subtle"> ({item.technique_id})</span></li>)}</ul>
    </div> : null}
    {latest.length ? <div className="usage-block">
      <h4 className="usage-head">{L(`최근 호출 · ${total}건 중 ${latest.length}건`, `Latest calls · ${latest.length} of ${total}`)}</h4>
      {u.summary ? <p className="ig-sub">{L("전체 호출은 집계하고, 상세 기록은 최근 100건까지 보관합니다.", "All calls are counted; detailed records retain up to the latest 100 calls.")}</p> : null}
      <div className="sub-scroll"><table className="sub-tbl">
        <thead><tr><th>{L("시각", "Time")}</th><th>{L("서비스", "Service")}</th><th>{L("동작", "Action")}</th><th>{L("리전", "Region")}</th><th>{L("출처", "Source")}</th><th>{L("결과", "Result")}</th></tr></thead>
        <tbody>{latest.map((event, index) => <tr key={event.event_id || `${event.event_time}-${event.event_name}-${index}`}>
          <td className="num nowrap" data-label={L("시각", "Time")}>{fmtDT(event.event_time, locale)}</td>
          <td className="nowrap" data-label={L("서비스", "Service")}>{service(event)}</td>
          <td data-label={L("동작", "Action")}><code className="mono cell-wrap">{event.event_name}</code>{event.access_mode === "WRITE" ? <> <span className="vis vis-org small">{L("쓰기", "write")}</span></> : null}</td>
          <td className="nowrap" data-label={L("리전", "Region")}>{event.region}</td>
          <td className="nowrap" data-label={L("출처", "Source")}>{event.source_address ? <span className="mono">{sourceLabel(event.source_address, event.source_address_kind, L)}</span> : <span className="subtle">—</span>}</td>
          <td className="nowrap" data-label={L("결과", "Result")}>{event.outcome === "DENIED" ? <span className="tone-warn">{L("거부", "Denied")}</span>
            : event.outcome === "SUCCEEDED" ? L("성공", "Succeeded") : <span className="subtle">—</span>}</td>
        </tr>)}</tbody>
      </table></div>
    </div> : u.collection_status === "COMPLETE" ? <p className="ig-sub">{L("조회 기간의 관리 이벤트에 이 키로 한 호출이 없습니다.", "No management event in the window was made with this key.")}</p> : null}
  </>;
}

export function UsageCard({ c, canLookup, principal }: { c: CredentialRecord; canLookup: boolean; principal?: string | null }) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const view = useApi<Usage>(usageLookup(c) ? `credentials/${c.credential_id}/usage` : null, { every: 5000 });
  const [busy, setBusy] = useState(false);
  const u = view.data;
  const evidenceRevision = JSON.stringify([c.credential_id, u?.identity_policies?.collected_at,
    u?.potential_access?.evaluated_at, u?.refresh_job?.status]);
  const seenEvidence = useRef<string | null>(null);
  useEffect(() => {
    if (!u) return;
    if (seenEvidence.current !== null && seenEvidence.current !== evidenceRevision) saved();
    seenEvidence.current = evidenceRevision;
  }, [evidenceRevision, saved, u]);
  if (!usageLookup(c)) return null;
  const blocked = needsPrincipal(c, principal);
  // A session key's principal is known once its detail loads (undefined until then): no note meanwhile.
  const pending = blocked && principal === undefined;
  const lookup = async () => {
    setBusy(true);
    try {
      await send(`credentials/${c.credential_id}/usage/refresh?background=true`, "POST", {});
      saved();  // the snapshot, and the credential's last use, read again
      toast(L("사용 기록 수집을 접수했습니다", "Usage collection queued"));
    } catch (reason) { toast(reasonText(reason, L), "bad"); } finally { setBusy(false); }
  };
  const running = Boolean(u?.refresh_job && ["QUEUED", "RUNNING", "CANCELLING"].includes(u.refresh_job.status));
  const stop = async () => {
    setBusy(true);
    try { await send(`source-scan-jobs/${u!.refresh_job!.id}/cancel`, "POST", {}); saved(); }
    catch (reason) { toast(reasonText(reason, L), "bad"); } finally { setBusy(false); }
  };
  return <Card level={3} headClass="wrap" title={L("사용 기록", "Usage")}
    meta={u?.collected_at ? L(`${fmtDT(u.collected_at, locale)} 조회 · AWS CloudTrail·IAM`, `Looked up ${fmtDT(u.collected_at, locale)} · AWS CloudTrail and IAM`) : L("AWS CloudTrail·IAM", "AWS CloudTrail and IAM")}
    right={canLookup && !blocked ? <button type="button" className="ghost-btn" disabled={busy || u?.refresh_job?.status === "CANCELLING"}
      onClick={() => void (running ? stop() : lookup())}>
      <Ic name={running ? "stop" : "refresh"} size={15} />{busy ? L("처리 중", "Working") : running ? L("수집 중지", "Stop collection") : L("지금 조회", "Look up now")}</button> : undefined}>
    <CardBody>
      {canLookup && blocked && !pending ? <p className="ig-sub">{L("세션 키는 검증으로 발급 주체를 확인한 뒤 조회할 수 있습니다.", "A session key can be looked up once its verification names its principal.")}</p> : null}
      {view.error ? <ErrorLine onRetry={view.reload}>{reasonText(view.error, L)}</ErrorLine>
        : !u ? <Loading /> : <UsageBody u={u} canLookup={canLookup && !blocked} />}
    </CardBody>
  </Card>;
}
