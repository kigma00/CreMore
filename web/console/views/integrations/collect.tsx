"use client";

import { reasonText, send, useApi } from "@/console/data";
import { useLocale } from "@/components/locale";
import { fmtDT, useL } from "@/console/text";
import { featureName } from "@/console/views/integrations/copy";
import { type EnterpriseExport, GitHubExportStatus } from "@/console/views/integrations/github-export";
import type { ProviderConnection, Purpose } from "@/console/views/integrations/model";
import { readProfiles, scopeTargets } from "@/console/views/integrations/scope";

export type CollectionRequest = { key: string; purpose: Purpose; name: string; jobId?: string; error?: string };

/** Shared by onboarding and Collect now. Existing APIs own approval and job deduplication. ``purposes``: only these
 * features' collections (one section of the connection). */
export async function collectConnection(c: ProviderConnection, retry?: Set<string>, purposes?: Purpose[]): Promise<CollectionRequest[]> {
  const requests: CollectionRequest[] = [];
  const tasks = new Map<string, { purpose: Purpose; name: string; run: () => Promise<{ job_id?: string; id?: string }> }>();
  for (const child of c.children) {
    if (c.feature_enabled?.[child.purpose] === false || (purposes && !purposes.includes(child.purpose))) continue;
    const path = child.kind === "metadata" ? `v2/coverage/connections/${child.id}/collect`
      : child.kind === "coverage" ? `coverage/connections/${child.id}/collect` : null;
    if (path) tasks.set(path, { purpose: child.purpose, name: child.name ?? child.id, run: () => send(path, "POST") });
  }
  for (const target of c.feature_enabled?.exposure === false || (purposes && !purposes.includes("exposure")) ? [] : scopeTargets(c)) {
    const key = `exposure:${target.id}`;
    if (retry && ![...retry].some(k => k === key || k.startsWith(`${key}:`))) continue;
    try {
      const profiles = (await readProfiles(target)).profiles.filter(p => p.selected_roots.length);
      if (!profiles.length) throw new Error("SCOPE_SELECTION_REQUIRED");
      for (const profile of profiles) tasks.set(`${key}:${profile.id}`, { purpose: "exposure", name: `${target.name} · ${profile.name}`, run: async () => {
        const plan = await send<{ plan_id: string; executable: boolean }>(`scan-scope-profiles/${profile.id}/preview`, "POST");
        if (!plan.executable) throw new Error("SCOPE_PLAN_NOT_EXECUTABLE");
        return send<{ id: string }>("scan-runs", "POST", { plan_id: plan.plan_id, profile_version: profile.version, mode: "BASELINE" });
      } });
    } catch (error) {
      requests.push({ key, purpose: "exposure", name: target.name, error: error instanceof Error ? error.message : "REQUEST_FAILED" });
    }
  }
  for (const [key, task] of tasks) {
    if (retry && !retry.has(key) && !(task.purpose === "exposure" && retry.has(key.slice(0, key.lastIndexOf(":"))))) continue;
    try {
      const result = await task.run();
      if (!result.job_id && !result.id) throw new Error("REQUEST_FAILED");
      requests.push({ key, purpose: task.purpose, name: task.name, jobId: result.job_id ?? result.id });
    } catch (error) {
      requests.push({ key, purpose: task.purpose, name: task.name, error: error instanceof Error ? error.message : "REQUEST_FAILED" });
    }
  }
  return requests;
}

function CollectionRun({ request }: { request: CollectionRequest }) {
  const L = useL();
  const locale = useLocale();
  const run = useApi<{ status: string; enterprise_export?: EnterpriseExport | null;
    schedule: { minutes: number; next_due_at: string | null; enabled: boolean } | null }>(
    request.jobId ? `scan-runs/${request.jobId}` : null, { every: 5000 });
  const names: Record<string, string> = { QUEUED: L("수집 대기", "Queued"), RUNNING: L("수집 중", "Collecting"),
    SUCCEEDED: L("수집 완료", "Completed"), PARTIAL: L("부분 수집", "Partial"), FAILED: L("수집 실패", "Failed"),
    CANCELLED: L("취소됨", "Cancelled"), CANCELLING: L("취소 중", "Cancelling") };
  const schedule = run.data?.schedule;
  return <div className="ig-section">
        <b>{featureName(request.purpose, L)} · {request.name}</b>
        <p>{request.error ? reasonText(new Error(request.error), L) : run.error ? L("실행 상태를 확인하지 못했습니다", "Could not read run status")
          : run.data ? names[run.data.status] ?? run.data.status : L("실행 요청 접수 · 상태 확인 중", "Run requested · checking status")}</p>
        {schedule?.enabled && schedule.next_due_at ? <p className="ig-sub">{L("다음 예약 실행 가능 시각", "Next scheduled eligibility")}: {fmtDT(schedule.next_due_at, locale)}
          <br />{L("진행 중인 작업·권한·서버 상태에 따라 늦어질 수 있습니다.", "Active work, access and server availability can delay collection.")}</p> : null}
        {schedule && !schedule.enabled ? <p className="ig-sub">{L("자동 수집이 꺼져 있거나 일시 중지되었습니다.", "Automatic collection is off or paused.")}</p> : null}
        {run.data?.enterprise_export ? <GitHubExportStatus state={run.data.enterprise_export} /> : null}
  </div>;
}

export function CollectionProgress({ requests }: { requests: CollectionRequest[] }) {
  return <div className="ig-section" aria-live="polite">{requests.map(request => <CollectionRun key={request.key} request={request} />)}</div>;
}
