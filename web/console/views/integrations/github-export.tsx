"use client";

import { useState } from "react";

import { useLocale } from "@/components/locale";
import { codeText, reasonText, useApi } from "@/console/data";
import { fmtDT, useL } from "@/console/text";
import { ErrorLine, Loading, StateChip } from "@/console/ui";
import { type Child, scheduleLabel } from "@/console/views/integrations/model";

/** Public projection only: no export handle, signed URL or token digest. */
export type EnterpriseExport = {
  stage?: string; as_of?: string; submitted_at?: string; next_create_at?: string; last_success_at?: string;
  error?: string; creation_allowed?: boolean; reuse_available?: boolean; request_blocked_reason?: string | null;
};

export function GitHubExportStatus({ state }: { state: EnterpriseExport }) {
  const L = useL();
  const locale = useLocale();
  const names: Record<string, string> = {
    reserved: L("생성 요청 대기", "Awaiting submission"), submitting: L("생성 요청 중", "Submitting"),
    queued: L("GitHub에서 준비 중", "Preparing at GitHub"), reading: L("결과 수집 중", "Reading export"),
    complete: L("결과 수집 완료", "Export collected"), quota_wait: L("생성 한도 대기", "Waiting for export allowance"),
    submission_unknown: L("생성 요청 결과 미확인", "Submission outcome unknown"),
    rejected: L("생성 요청 거절", "Submission rejected"), failed: L("결과 수집 실패", "Export collection failed"),
  };
  const stage = state.stage;
  return <div className="ig-section" aria-live="polite">
    <b>{L("Enterprise 전체 인벤토리 상태", "Enterprise inventory export status")}</b>{" "}
    <StateChip tone={stage === "complete" ? "ok" : ["failed", "rejected"].includes(stage ?? "") ? "bad" : "partial"}>
      {names[stage ?? ""] ?? L("아직 수집하지 않음", "Not collected yet")}
    </StateChip>
    <dl className="md-kv">
      {state.as_of ? <div><dt>{L("데이터 기준 시각", "Data as of")}</dt><dd>{fmtDT(state.as_of, locale)}</dd></div> : null}
      {state.last_success_at ? <div><dt>{L("마지막 수집 성공", "Last successful collection")}</dt><dd>{fmtDT(state.last_success_at, locale)}</dd></div> : null}
      {state.next_create_at && !state.creation_allowed ? <div><dt>{L("새 결과 생성 가능 시각", "Next export eligibility")}</dt><dd>{fmtDT(state.next_create_at, locale)}</dd></div> : null}
    </dl>
    {state.reuse_available ? <p className="ig-sub">{L("지금 다시 수집하면 위 기준 시각의 기존 결과를 읽습니다. 새 결과는 생성 가능 시각 이후 요청합니다.",
      "Collecting now reuses the export with the timestamp above. A new export can be requested after the eligibility time.")}</p> : null}
    {state.request_blocked_reason ? <p className="ig-sub">{codeText(state.request_blocked_reason, L)}</p>
      : state.error ? <p className="ig-sub">{L("마지막 오류", "Last error")}: {codeText(state.error.toUpperCase(), L)}</p> : null}
    <p className="ig-sub">{L("같은 Enterprise의 연결들이 생성 한도를 공유합니다. CreMore는 새 결과 생성을 24시간에 한 번으로 제한하며 GitHub의 대기 응답이 있으면 더 기다립니다.",
      "Connections to the same Enterprise share the allowance. CreMore creates at most one new export per 24 hours and waits longer when GitHub requests it.")}</p>
  </div>;
}

type Collection = {
  id: string; enabled: boolean; spec: { name: string; provider: string; schedule_minutes: number };
  enterprise_export?: EnterpriseExport;
};

/** Read actual child schedules so legacy mixed jobs and later edits stay accurate. */
export function GitHubCollections({ connections, snapshotType }: { connections: Child[]; snapshotType?: string }) {
  const L = useL();
  const collections = useApi<{ items: Collection[] }>("v2/coverage/connections", { every: 5000 });
  if (collections.error) return <ErrorLine onRetry={collections.reload}>{reasonText(collections.error, L)}</ErrorLine>;
  if (!collections.data) return <Loading />;
  const ids = new Set(connections.filter(c => c.kind === "metadata" && c.purpose === "inventory").map(c => c.id));
  const rows = collections.data.items.filter(c => c.spec.provider === "github" && ids.has(c.id));
  return <section className="ig-section">
    {!snapshotType ? <b>{L("수집별 주기와 현황", "Collection schedules and status")}</b> : null}
    {rows.filter(row => !snapshotType || row.enterprise_export !== undefined).map(row => <div className="ig-section" key={row.id}>
      <b>{row.spec.name}</b><p className="ig-sub">{L("수집 주기", "Schedule")}: {scheduleLabel(row.spec.schedule_minutes, L)}
        {!row.enabled ? ` · ${L("중지됨", "Disabled")}` : ""}</p>
      {!snapshotType && row.enterprise_export ? <GitHubExportStatus state={row.enterprise_export} /> : null}
      {row.enterprise_export !== undefined ? <GitHubExportRows key={snapshotType ?? "all"} connectionId={row.id} credentialType={snapshotType} /> : null}
    </div>)}
  </section>;
}

type ExportRows = {
  run: { id: string; status: string; finished_at: string | null } | null;
  current_revision: boolean; total: number; next_offset: number | null;
  items: { id: string; kind: string; as_of: string | null; metadata: Record<string, unknown>;
    permissions?: { name: string; actions: string[] }[] }[];
};

/** Snapshot row IDs are navigation positions, never credential identity or evidence of uniqueness. */
export function GitHubExportRows({ connectionId, credentialType }: { connectionId: string; credentialType?: string }) {
  const L = useL(), locale = useLocale();
  const [page, setPage] = useState<{ offset: number; run?: string }>({ offset: 0 });
  const query = new URLSearchParams({ offset: String(page.offset), limit: "50" });
  if (page.run) query.set("run_id", page.run);
  if (credentialType) query.set("credential_type", credentialType);
  const result = useApi<ExportRows>(`v2/coverage/connections/${connectionId}/github-export-rows?${query}`,
    { every: page.run ? undefined : 60_000 });
  if (result.error) return <ErrorLine onRetry={result.reload}>{reasonText(result.error, L)}</ErrorLine>;
  if (!result.data) return <Loading />;
  const data = result.data;
  const names: Record<string, string> = {
    github_app_installation: L("App 발급 주체", "App issuing principal"), federated_jti: "Federated JTI",
    classic_pat: "Classic PAT", fine_grained_pat: "Fine-grained PAT", oauth_app_user_token: "OAuth App token",
    github_app_user_token: "GitHub App user token", ssh_key: "SSH key",
  };
  return <section className="ig-section" aria-label={L("식별자 없는 Export 관측", "Export observations without stable identifiers")}>
    <b>{L("스냅샷 관측 행", "Snapshot observations")}</b>
    <p className="ig-sub">{L("고정 ID가 없어 고유 자격증명 수에 더하지 않습니다. 각 행은 선택한 수집 결과의 관측이며 다른 수집 결과와 합치지 않습니다.",
      "These rows have no stable ID and do not increase unique credential counts. Each is an observation in the selected snapshot; rows are not merged across snapshots.")}</p>
    {data.run ? <>
      <p className="ig-sub">{L(`관측 ${data.total}행`, `${data.total} observed rows`)} · {data.run.status === "COMPLETE" ? L("수집 완료", "Complete collection") : L("부분 수집", "Partial collection")}
        {data.run.finished_at ? ` · ${fmtDT(data.run.finished_at, locale)}` : ""}</p>
      {!data.current_revision ? <p className="meta tone-warn">{L("과거 수집 결과입니다. 현재 범위의 상태나 부재를 증명하지 않습니다.", "Historical collection. It does not establish the current scope's state or absence.")}</p> : null}
      {data.items.map(item => <section className="md-tok" key={item.id}>
        <b>{names[String(item.metadata.credential_type)] ?? L("유형 미확인", "Unknown type")}</b>
        <dl className="md-kv">
          {item.as_of ? <div><dt>{L("데이터 기준 시각", "Data as of")}</dt><dd>{fmtDT(item.as_of, locale)}</dd></div> : null}
          {([["display_name", L("이름", "Name")], ["owner", L("소유자", "Owner")], ["application", L("앱", "Application")],
            ["credential_state", L("공급자 보고 상태", "Provider-reported state")], ["created_at", L("생성 시각", "Created")],
            ["expires_at", L("만료 시각", "Expires")], ["last_used_at", L("마지막 사용", "Last used")]] as const).map(([key, label]) =>
            <div key={key}><dt>{label}</dt><dd className="cell-wrap">{typeof item.metadata[key] === "string"
              ? key.endsWith("_at") ? fmtDT(String(item.metadata[key]), locale) : String(item.metadata[key]) : L("미제공", "Not provided")}</dd></div>)}
          <div><dt>{L("보고된 권한", "Reported permissions")}</dt><dd className="cell-wrap">
            {item.permissions?.length ? <div style={{ maxHeight: 160, overflow: "auto" }} tabIndex={0}>
              {item.permissions.map((permission, i) => <div key={i}>{permission.name}{permission.actions.length ? `: ${permission.actions.join(", ")}` : ""}</div>)}
            </div> : L("미제공", "Not provided")}
          </dd></div>
        </dl>
      </section>)}
      {!data.items.length ? <p className="ig-sub">{L("이 수집 결과에 해당 관측 행이 없습니다. 전체 자격증명의 부재를 뜻하지 않습니다.", "No matching rows in this collection. This does not mean no credentials exist.")}</p> : null}
      <div className="modal-foot">
        <button className="ghost-btn" type="button" disabled={page.offset === 0} onClick={() => setPage({ run: data.run!.id, offset: Math.max(0, page.offset - 50) })}>{L("이전", "Previous")}</button>
        <button className="ghost-btn" type="button" disabled={data.next_offset === null} onClick={() => setPage({ run: data.run!.id, offset: data.next_offset! })}>{L("다음", "Next")}</button>
        <button className="ghost-btn" type="button" onClick={() => { setPage({ offset: 0 }); result.reload(); }}>{L("최근 수집 보기", "View latest collection")}</button>
      </div>
    </> : <p className="ig-sub">{L("아직 Enterprise Export 수집 결과가 없습니다.", "No Enterprise export has been collected yet.")}</p>}
  </section>;
}
