"use client";

import { useContext, useState } from "react";

import { useLocale } from "@/components/locale";
import { DashboardAPIError } from "@/lib/dashboard-api";
import { ChangesContext, reasonText, send, useApi } from "@/console/data";
import { Ic } from "@/console/icons";
import { serviceName } from "@/console/logos";
import { type DirectoryPage, type DirectoryState } from "@/console/people";
import { fmtDT, type Say, useL } from "@/console/text";
import { Card, CardBody, ErrorLine } from "@/console/ui";
import { scheduleLabel } from "@/console/views/integrations/model";

const STATES: Record<string, [string, string]> = {
  READY: ["로그인 IdP의 최신 사람 목록", "Current people from the sign-in IdP"],
  NOT_CONFIGURED: ["로그인 IdP의 사람 목록 연결이 필요합니다.", "Connect the sign-in IdP's people directory."],
  PROFILES_DISABLED: ["연결에서 이름·이메일 보관을 켜야 담당자를 고를 수 있습니다.", "Enable name and email profiles on the directory connection to select a responder."],
  NOT_SYNCED: ["사람 목록의 첫 수집이 필요합니다.", "The first directory collection is required."],
  SYNCING: ["사람 목록을 수집 중입니다.", "The directory is being collected."],
  PARTIAL: ["사람 목록이 부분 수집되어 담당자 선택이 제한됩니다.", "The directory is incomplete, so responder selection is restricted."],
  STALE: ["사람 목록이 오래됐습니다. 다시 수집한 후 선택하세요.", "The directory is stale. Collect it again before selecting a responder."],
  UNAVAILABLE: ["사람 목록의 수집 상태를 확인할 수 없습니다.", "Directory availability could not be confirmed."],
};
export const directoryText = (state: { status: string } | undefined, L: Say) => state ? L(...(STATES[state.status] ?? STATES.UNAVAILABLE)) : "";
export const directoryCollecting = (state: DirectoryState | undefined) => state?.sources?.some(source =>
  ["QUEUED", "RUNNING", "CANCELLING"].includes(source.collection_status ?? "") || source.status === "SYNCING") ?? false;

/** Reads report stored inventory. Only an explicit click queues the existing metadata collection. */
export function DirectoryStatus({ directory, onReload, admin = false, disabled = false }: {
  directory: DirectoryState; onReload: () => void; admin?: boolean; disabled?: boolean;
}) {
  const L = useL(), locale = useLocale(), { authLost } = useContext(ChangesContext);
  const [busy, setBusy] = useState<string | null>(null), [error, setError] = useState<unknown>(), [requested, setRequested] = useState(false);
  const refresh = async (id: string) => {
    if (busy || disabled) return;
    setBusy(id); setError(undefined); setRequested(false);
    try {
      await send(`v2/coverage/connections/${encodeURIComponent(id)}/collect`, "POST");
      setRequested(true); onReload();
    } catch (reason) {
      setError(reason);
      if (reason instanceof DashboardAPIError && reason.status === 401) authLost(reason);
    } finally { setBusy(null); }
  };
  return <div className="people-directory">
    <p className={`meta ${directory.usable ? "" : "tone-warn"}`}>{directoryText(directory, L)}</p>
    {(directory.sources ?? []).map(source => {
      const name = source.name || serviceName(source.provider);
      const status = source.collection_status;
      const collecting = ["QUEUED", "RUNNING", "CANCELLING"].includes(status ?? "") || source.status === "SYNCING";
      return <div className="people-directory-source" key={source.connection_id}>
        <div className="cell-wrap"><strong>{name}</strong>
          <div className="meta">{source.observed_at ? L(`마지막 수집 ${fmtDT(source.observed_at, locale)}`, `Last collected ${fmtDT(source.observed_at, locale)}`) : L("아직 수집하지 않았습니다", "Not collected yet")}</div>
          <div className="meta">{typeof source.schedule_minutes === "number" ? scheduleLabel(source.schedule_minutes, L) : L("갱신 주기 미확인", "Refresh schedule unavailable")}
            {collecting ? ` · ${status === "QUEUED" ? L("갱신 대기 중", "Refresh queued") : status === "CANCELLING" ? L("중지 중", "Stopping") : L("갱신 중", "Refreshing")}` : ""}</div>
          {source.status !== directory.status ? <div className="meta tone-warn">{directoryText(source, L)}</div> : null}
        </div>
        <div className="md-actions">
          <button type="button" className="ghost-btn" disabled={disabled || !!busy || collecting}
            aria-label={`${L("지금 갱신", "Refresh now")} · ${name}`} onClick={() => void refresh(source.connection_id)}>
            <Ic name="refresh" size={14} />{busy === source.connection_id ? L("요청 중…", "Requesting…") : L("지금 갱신", "Refresh now")}</button>
          {admin && source.provider_connection_id ? <a className="link-btn" href={`/?view=sources&edit=${encodeURIComponent(source.provider_connection_id)}&step=3`}
            target="_blank" rel="noopener noreferrer">{L("자동 갱신 설정 (새 탭)", "Refresh settings (new tab)")}</a> : null}
        </div>
      </div>;
    })}
    {requested ? <p className="meta" role="status">{L("갱신을 요청했습니다. 완료되면 목록에 반영됩니다.", "Refresh requested. The list updates when collection finishes.")}</p> : null}
    {error ? <p className="meta tone-warn" role="alert">{reasonText(error, L)}</p> : null}
  </div>;
}

/** A small directory summary on assignment screens; polling reads only the local projection. */
export function DirectoryPanel({ admin = false }: { admin?: boolean }) {
  const L = useL(), result = useApi<DirectoryPage>("people?q=&limit=1");
  return <Card className="list-card" title={L("대응 담당자 목록", "Responder directory")}><CardBody>
    {result.error ? <ErrorLine onRetry={result.reload}>{reasonText(result.error, L)}</ErrorLine> : null}
    {result.data ? <DirectoryStatus directory={result.data.directory} admin={admin} onReload={result.reload} />
      : !result.error ? <p className="meta">{L("목록 상태 확인 중…", "Checking the directory…")}</p> : null}
  </CardBody></Card>;
}
