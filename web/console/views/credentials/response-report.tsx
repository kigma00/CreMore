"use client";

import { useId, useState } from "react";

import { useLocale } from "@/components/locale";
import { reasonText, randomId, useApi, useRead } from "@/console/data";
import { Ic } from "@/console/icons";
import { Modal } from "@/console/layer";
import type { ResponseCycle, ResponseReport } from "@/console/records";
import { fmtDT, type Say, useL } from "@/console/text";
import { ErrorLine, Field, SelectField, StateChip } from "@/console/ui";

const ACTIONS: Record<string, [string, string]> = {
  REMOVE_PLAINTEXT: ["노출 위치의 평문 제거", "Remove exposed plaintext"], REVOKE: ["기존 키 폐기", "Retire old key"],
  ROTATE: ["새 키로 교체", "Replace with a new key"], STORE_REPLACEMENT: ["교체 키를 금고에 보관", "Store replacement in a vault"],
  CUTOVER: ["사용처를 새 키로 전환", "Switch consumers to the replacement"], DISABLE: ["임시 비활성화", "Temporarily disable"],
};
const CHECKS: Record<string, [string, string]> = {
  report: ["담당자 보고·회신", "Owner report and reply"], removal: ["평문 제거", "Plaintext removal"],
  retirement: ["기존 키 사용 종료", "Old credential retired"], replacement: ["교체 자격증명 연결", "Replacement linked"],
  vault: ["교체 키 현재 금고 보관", "Replacement currently stored in vault"], cutover: ["사용처 전환 보고", "Consumer cutover statement"],
};
const REASONS: Record<string, [string, string]> = {
  OWNER_REPORT_AND_APPROVAL: ["담당자 보고와 수행 완료 회신을 확인합니다.", "Requires the owner's report and a reply that the actions were done."],
  OWNER_REPORT_REQUIRED: ["구체적인 조치 보고가 필요합니다.", "A concrete action report is required."],
  COMPLETE_RESCAN_REQUIRED: ["보고·회신 후 시작한 완전한 재검사가 필요합니다.", "Requires a complete rescan started after the report and reply."],
  COMPLETE_RESCAN: ["승인된 검사 범위의 후속 검사 근거입니다.", "Evidence from the authorized follow-up scan."],
  ISSUER_RETIREMENT_PROOF_REQUIRED: ["발급자의 명시적 종료 상태 또는 승인된 폐기 작업의 확인 근거가 필요합니다.", "Requires explicit issuer retirement or a verified approved revocation."],
  REPLACEMENT_PROOF_REQUIRED: ["승인된 교체 작업 또는 같은 발급 범위의 새 자격증명을 연결하세요.", "Link an approved rotation or a replacement in the same issuer scope."],
  CURRENT_VALUE_STORAGE_REQUIRED: ["현재 값의 일치 근거가 필요합니다. 식별자만 일치하거나 부분·과거 수집이면 완료하지 않습니다.", "Requires current value proof; identifier-only, partial or historical matches cannot complete this check."],
  OWNER_STATEMENT: ["담당자의 진술이며 자동 실행 검증은 아닙니다.", "An owner statement, not independently verified execution."],
  IDENTIFIER_ONLY_REQUIRES_REVIEW: ["키 ID만 발견했습니다. 비밀값 노출과 구별하여 별도 검토해야 합니다.", "Only a key ID was found. Review separately from secret exposure."],
  PROVIDER_READBACK: ["승인된 작업 뒤 발급자에게 종료 상태를 확인했습니다.", "Retirement was read back after the approved action."],
  EXPLICIT_ISSUER_STATE: ["최신 발급 목록의 명시적 폐기·만료 상태입니다.", "Explicit retirement or expiry from current issuer evidence."],
  APPROVED_ROTATION_BINDING: ["승인된 교체 작업이 기존 키와 새 키를 연결합니다.", "An approved rotation binds the old and new keys."],
  OWNER_DECLARED_INVENTORY_REFERENCE: ["담당자가 정확한 발급 항목으로 교체 관계를 신고했습니다.", "The owner declared the relationship using exact inventoried references."],
  IMMUTABLE_ROTATION_VERSION: ["확인된 교체 버전과 현재 금고 수집이 일치합니다.", "The verified immutable replacement version matches current vault collection."],
  COMPATIBLE_VALUE_MATCH: ["호환되는 값 지문·공급자 digest로 현재 보관을 확인했습니다.", "Current storage is supported by compatible value or provider-digest evidence."],
  REPLACEMENT_EXPOSURE_REVIEW_REQUIRED: ["교체 키의 노출 여부를 확인해야 합니다. 새 노출 또는 조회 한도에 도달했습니다.", "Review replacement exposure: a new exposure was found or the lookup limit was reached."],
};
const words = (map: Record<string, [string, string]>, key: string, L: Say) => map[key] ? L(...map[key]) : key;

/** A report as the console or a response link gives it; the link's copy names no basis, so none is shown. */
export function ReportText({ report }: { report: Pick<ResponseReport, "version" | "performed_at" | "actions" | "explanation" | "received_at"> & { basis?: string } }) {
  const L = useL(), locale = useLocale();
  const basis = report.basis === undefined ? null : report.basis === "TICKET_RECIPIENT_STATEMENT" ? L("티켓에서 받은 담당자 회신", "Responder report received in ticket")
    : report.basis === "LOCAL_OPERATOR_STATEMENT" ? L("로컬 운영자 기록", "Local operator statement") : L("지정 IdP 담당자", "Designated IdP responder");
  return <div className="response-report-copy">
    <p className="meta">{[`${L("보고 버전", "Report version")} ${report.version}`, fmtDT(report.performed_at, locale), basis].filter(Boolean).join(" · ")}</p>
    <p>{report.actions.length ? report.actions.map(a => words(ACTIONS, a, L)).join(" · ") : L("아직 수행한 조치 없음", "No actions performed yet")}</p>
    <p className="response-explanation">{report.explanation}</p>
    <p className="meta">{L("서버 수신", "Received by server")}: {fmtDT(report.received_at, locale)}</p>
  </div>;
}

export function CompletionEvidence({ cycle, findingId }: { cycle: ResponseCycle; findingId: string }) {
  const L = useL(), locale = useLocale();
  const [historyOpen, setHistoryOpen] = useState(false), [offset, setOffset] = useState(0);
  const history = useApi<{ items: ResponseReport[]; total: number }>(historyOpen ? `findings/${findingId}/response/reports?request_id=${cycle.request_id}&offset=${offset}` : null);
  return <>
    <div className="check-list response-evidence" aria-label={L("조치 완료 검증", "Remediation completion checks")}>
      {Object.entries(CHECKS).map(([key, label]) => {
        const check = cycle.verification?.[key];
        return <div key={key} className="card">
          <div className="md-actions"><strong>{L(...label)}</strong><StateChip tone={check?.state === "PASS" ? "ok" : check?.state === "NA" ? undefined : "warn"}>
            {check?.state === "PASS" ? L("확인", "Confirmed") : check?.state === "NA" ? L("해당 없음", "Not required") : L("검증 필요", "Evidence needed")}</StateChip></div>
          {check ? <p className="meta">{words(REASONS, check.reason, L)} {check.at ? fmtDT(check.at, locale) : ""}</p> : null}
          {check?.reference ? <p className="meta cell-wrap">{check.reference}</p> : null}
        </div>;
      })}
    </div>
    {cycle.completed_at ? <p className="meta">{L("최근 완료 판정", "Last completion decision")}: {fmtDT(cycle.completed_at, locale)}</p> : null}
    {cycle.report ? <><ReportText report={cycle.report} />{(cycle.report_count ?? 0) > 1 ? <button className="ghost-btn" onClick={() => setHistoryOpen(true)}>{L("이전 보고 이력", "Previous reports")}</button> : null}</> : null}
    {historyOpen ? <Modal labelledBy="response-history-title" onClose={() => setHistoryOpen(false)}>
      <h2 id="response-history-title">{L("조치 보고 이력", "Action report history")}</h2>
      {history.error ? <ErrorLine onRetry={history.reload}>{reasonText(history.error, L)}</ErrorLine> : history.data?.items.map(report => <ReportText key={report.id} report={report} />)}
      <div className="md-actions"><button className="ghost-btn" disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 20))}>{L("이전", "Previous")}</button>
        <button className="ghost-btn" disabled={offset + 20 >= (history.data?.total ?? 0)} onClick={() => setOffset(offset + 20)}>{L("다음", "Next")}</button>
        <button className="primary-btn" onClick={() => setHistoryOpen(false)}>{L("닫기", "Close")}</button></div>
    </Modal> : null}
  </>;
}

/** What a report says; who it is for (the request and its version) is the caller's to add. */
export type ReportBody = {
  report_id: string; result: ResponseReport["result"]; path: ResponseReport["path"]; actions: string[]; explanation: string; performed_at: string;
  replacement_plan_id?: string; replacement_entity_id?: string;
};
export type EvidenceOptions = { plans: { id: string; action: string; status: string; verified_at: string | null }[]; entities: { id: string; label: string; provider: string }[]; truncated: boolean };

/** The action report, sent by `submit` (the console's report, or the person's own answer at a response link) with the
 * replacement choices read by `evidence` (a stable function of the search text). `changed` keeps the input and stops
 * the send when the case moved on since the form opened. */
export function ResponseReportForm({ submit, evidence, changed = false, onClose, onSaved }: {
  submit: (body: ReportBody) => Promise<void>; evidence: (q: string) => Promise<EvidenceOptions>; changed?: boolean; onClose: () => void; onSaved: () => void;
}) {
  const L = useL();
  const [id] = useState(randomId), kind = useId();
  const [result, setResult] = useState<ResponseReport["result"]>("DONE");
  const [path, setPath] = useState<ResponseReport["path"]>("RETIRED");
  const [actions, setActions] = useState<string[]>([]), [explanation, setExplanation] = useState("");
  const [at, setAt] = useState(""), [reference, setReference] = useState(""), [q, setQ] = useState(""), [search, setSearch] = useState("");
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  // every:0: the person asks for the list with the search button; nothing reads it again behind their back.
  const options = useRead<EvidenceOptions>(path === "REPLACED" ? search : null, evidence, `evidence${kind}`, { every: 0 });
  const send = async () => {
    setBusy(true); setError("");
    try {
      await submit({ report_id: id, result, path, actions, explanation, performed_at: new Date(at).toISOString(),
        ...(path === "REPLACED" && reference ? { [reference.startsWith("plan:") ? "replacement_plan_id" : "replacement_entity_id"]: reference.slice(reference.indexOf(":") + 1) } : {}),
      }); onSaved();
    } catch (failure) { setError(reasonText(failure, L)); } finally { setBusy(false); }
  };
  return <Modal onClose={onClose} labelledBy="response-report-title" dismissable={!busy}>
    <h2 id="response-report-title">{L("조치 결과 보고", "Report remediation actions")}</h2>
    <p className="meta">{L("실제로 수행한 내용만 보고하세요. 비밀번호·토큰·비밀값은 입력할 수 없습니다.", "Report only actions actually performed. Never enter passwords, tokens or secret values.")}</p>
    <form onSubmit={event => { event.preventDefault(); void send(); }}>
      <div className="row2"><SelectField label={L("처리 결과", "Result")} value={result} onChange={setResult} disabled={busy}
        options={[{ id: "DONE", label: L("수행 완료 · 검증 요청", "Actions done; request verification") }, { id: "INCOMPLETE", label: L("미완료 · 추가 조치 필요", "Incomplete; more action needed") }, { id: "EXCEPTION", label: L("예외 검토 요청", "Request exception review") }]} />
        <SelectField label={L("처리 경로", "Resolution path")} value={path} onChange={value => { setPath(value); setReference(""); }} disabled={busy}
          options={[{ id: "RETIRED", label: L("사용 종료 · 기존 키 폐기", "Retire; no longer needed") }, { id: "REPLACED", label: L("계속 사용 · 새 키로 교체", "Replace; still needed") }, { id: "EXCEPTION", label: L("키 ID만 노출 등 별도 검토", "Separate review, e.g. identifier-only exposure") }]} /></div>
      <fieldset className="field" disabled={busy}><legend>{L("실제로 수행한 조치", "Actions performed")}</legend>
        {Object.entries(ACTIONS).map(([key, labels]) => <label className="check-line" key={key}><input type="checkbox" checked={actions.includes(key)} onChange={e => setActions(e.target.checked ? [...actions, key] : actions.filter(a => a !== key))} />{L(...labels)}</label>)}
      </fieldset>
      {path === "REPLACED" ? <>
        <Field label={L("발급 항목 검색", "Search inventoried credentials")} htmlFor="report-search"><div className="md-actions"><input id="report-search" value={q} maxLength={200} onChange={e => setQ(e.target.value)} /><button type="button" className="ghost-btn" onClick={() => setSearch(q)}>{L("검색", "Search")}</button></div></Field>
        <SelectField label={L("교체 작업 또는 새 자격증명", "Rotation or replacement credential")} value={reference} onChange={setReference} disabled={busy || options.loading}
          options={[{ id: "", label: L("선택하세요", "Select") }, ...(options.data?.plans ?? []).map(p => ({ id: `plan:${p.id}`, label: `${L("승인 교체 작업", "Approved rotation")} · ${p.id.slice(0, 8)} · ${p.status}` })),
            ...(options.data?.entities ?? []).map(e => ({ id: `entity:${e.id}`, label: `${e.provider} · ${e.label}` }))]} />
        {options.error ? <ErrorLine onRetry={options.reload}>{reasonText(options.error, L)}</ErrorLine> : null}
        <p className="meta">{L("같은 발급 범위의 정확한 항목을 선택합니다. 이 선택은 교체 관계에 대한 담당자 진술이며, 금고의 현재 값 보관은 별도로 검증합니다.", "Select the exact object in the same issuer scope. This declares the replacement relationship; current vault storage is checked separately.")}</p>
        {options.data?.truncated ? <p className="meta">{L("목록이 많습니다. 검색어로 범위를 좁혀주세요.", "More items exist. Narrow the search.")}</p> : null}
      </> : null}
      <Field label={L("구체적인 조치 사유·방법 (20자 이상)", "Action explanation and method (at least 20 characters)")} htmlFor="report-explanation"><textarea id="report-explanation" required minLength={20} maxLength={2000} rows={4} value={explanation} onChange={e => setExplanation(e.target.value)} disabled={busy} /></Field>
      <Field label={L("수행 시각 (현재 시간대)", "Performed at (local time zone)")} htmlFor="report-at"><input id="report-at" type="datetime-local" required value={at} onChange={e => setAt(e.target.value)} disabled={busy} /></Field>
      {changed ? <p className="meta tone-warn">{L("상태가 변경됐습니다. 입력은 유지됩니다. 닫고 최신 상태에서 다시 보고하세요.", "The case changed. Your input is preserved. Close and reopen using the latest state.")}</p> : null}
      {error ? <p className="ig-result bad" role="alert"><Ic name="alert" size={15} /><span>{error}</span></p> : null}
      <div className="md-actions"><button type="button" className="ghost-btn" disabled={busy} onClick={onClose}>{L("취소", "Cancel")}</button><button className="primary-btn" type="submit" disabled={busy || changed || (result === "DONE" && (!actions.length || (path === "REPLACED" && !reference)))}>{L("보고 기록", "Record report")}</button></div>
    </form>
  </Modal>;
}
