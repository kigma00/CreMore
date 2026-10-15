"use client";

/* Issuance and storage records: an administrator links a trusted issuance or rotation record to an
 * issued credential and a vault location that CreMore actually collected (a run, batch and item).
 * A record is evidence an administrator submitted -- it never stands for a value match, current
 * storage or a usable credential -- and revoking it keeps its history. */

import { useEffect, useRef, useState } from "react";

import { useLocale } from "@/components/locale";
import { randomId, reasonText, send, useApi } from "@/console/data";
import { Ic } from "@/console/icons";
import { Modal, useToast } from "@/console/layer";
import { Logo } from "@/console/logos";
import { fmtDT, useL } from "@/console/text";
import { Card, EmptyRow, ErrorLine, Loading } from "@/console/ui";
import { api } from "@/lib/dashboard-api";

type Anchor = { run_id: string; batch_index: number; item_index: number };
export type Locator = { anchor: Anchor; connection_id: string; connection_name: string; provider: string; reference: string; version: string; entity_id?: string; identifier?: string };
type Page<T> = { items: T[]; total: number; offset: number; limit: number };
type Connection = { id: string; name: string; provider: string; enabled: boolean; revision: number };
type Run = { id: string; status: string; started_at: string; finished_at: string | null; revision: number };
export type Receipt = {
  id: string; source_system: string; source_record_id: string; stored_at: string; submitted_at: string; submitted_by: string;
  revoked_at: string | null; revoked_by: string | null; issuer: Locator; vault: Locator; applicable: boolean; reasons: string[]; state: string;
};

const RECEIPTS = "coverage/storage-receipts";

/** The request body a receipt form sends; the same attempt keeps its id so a retry is not a second record. */
export function receiptBody(issuer: Locator, vault: Locator, form: { system: string; record: string; stored: string }) {
  return { issuer: issuer.anchor, vault: vault.anchor, source_system: form.system.trim(), source_record_id: form.record.trim(),
    stored_at: new Date(form.stored).toISOString() };
}

export function Receipts({ admin }: { admin: boolean }) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const [offset, setOffset] = useState(0);
  const page = useApi<Page<Receipt>>(`${RECEIPTS}?offset=${offset}&limit=20`);
  const [adding, setAdding] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const revoke = async (receipt: Receipt) => {
    setBusy(receipt.id);
    try { await send(`${RECEIPTS}/${encodeURIComponent(receipt.id)}/revoke`, "POST"); toast(L("저장 이력을 철회했습니다. 이력은 남아 있습니다.", "Storage record revoked. Its history is kept.")); page.reload(); }
    catch (reason) { toast(reasonText(reason, L), "bad"); }
    finally { setBusy(null); }
  };
  return <Card className="list-card" title={L("발급·저장 이력", "Issuance and storage records")}
    info={L("신뢰하는 발급·교체 기록을 수집된 발급 Credential과 저장소 위치에 연결합니다. 값 일치와는 따로 셉니다.", "Links a trusted issuance or rotation record to a collected credential and vault location. Counted apart from value matches.")}
    right={admin ? <button type="button" className="ghost-btn" onClick={() => setAdding(true)}><Ic name="plus" size={15} />{L("이력 추가", "Add a record")}</button> : undefined}>
    {page.error ? <ErrorLine onRetry={page.reload}>{reasonText(page.error, L)}</ErrorLine> : !page.data ? <Loading /> : <>
      <div className="table-wrap"><table className="tbl">
        <thead><tr><th>{L("원본 기록", "Source record")}</th><th>{L("발급 Credential", "Issued credential")}</th><th>{L("저장소 위치", "Vault location")}</th>
          <th className="col-sm">{L("저장 시각", "Stored at")}</th><th>{L("상태", "State")}</th>{admin ? <th className="rule-acts-h"><span className="sr">{L("작업", "Actions")}</span></th> : null}</tr></thead>
        <tbody>
          {page.data.items.length ? page.data.items.map(receipt => <tr key={receipt.id}>
            <td><div className="cred-name">{receipt.source_system}</div><div className="cred-hint mono">{receipt.source_record_id}</div></td>
            <td><div className="cred-cell"><Logo id={receipt.issuer.provider} size={24} /><div className="cred-text"><div className="cred-name">{receipt.issuer.connection_name}</div>
              <div className="cred-hint mono">{receipt.issuer.identifier || receipt.issuer.reference}</div></div></div></td>
            <td><div className="cred-cell"><Logo id={receipt.vault.provider} size={24} /><div className="cred-text"><div className="cred-name">{receipt.vault.connection_name}</div>
              <div className="cred-hint mono">{receipt.vault.reference}{receipt.vault.version ? ` · ${receipt.vault.version}` : ""}</div></div></div></td>
            <td className="col-sm"><span data-tip={L(`제출 ${fmtDT(receipt.submitted_at, locale)} · ${receipt.submitted_by}`, `Submitted ${fmtDT(receipt.submitted_at, locale)} · ${receipt.submitted_by}`)}>{fmtDT(receipt.stored_at, locale)}</span></td>
            <td><span className={receipt.revoked_at ? "igs off" : receipt.applicable ? "igs ok" : "igs setup"}><span className="dot" />
              {receipt.revoked_at ? L("철회됨", "Revoked") : receipt.applicable ? L("적용 중", "Applies") : L("과거 범위", "Earlier scope")}</span>
              {receipt.revoked_at ? <div className="ig-note">{fmtDT(receipt.revoked_at, locale)} · {receipt.revoked_by}</div> : null}</td>
            {admin ? <td className="rule-acts">{!receipt.revoked_at ? <button type="button" className="icon-btn" aria-label={L("저장 이력 철회", "Revoke the record")}
              data-tip={L("철회해도 Credential이 폐기되거나 저장소 값이 지워지지 않습니다.", "Revoking does not revoke the credential or delete the stored value.")}
              disabled={busy === receipt.id} onClick={() => void revoke(receipt)}><Ic name="xCircle" size={17} /></button> : null}</td> : null}
          </tr>) : <EmptyRow colSpan={admin ? 6 : 5}>{L("제출한 저장 이력이 없습니다.", "No storage record has been submitted.")}</EmptyRow>}
        </tbody>
      </table></div>
      {page.data.total > page.data.limit ? <div className="pager"><span className="num">{L(`총 ${page.data.total}건`, `${page.data.total} records`)}</span>
        <div className="pager-r"><span className="pager-btns">
          <button type="button" className="icon-btn" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 20))} aria-label={L("이전 페이지", "Previous page")}><Ic name="left" size={16} /></button>
          <button type="button" className="icon-btn" disabled={offset + page.data.items.length >= page.data.total} onClick={() => setOffset(offset + 20)} aria-label={L("다음 페이지", "Next page")}><Ic name="right" size={16} /></button>
        </span></div></div> : null}
    </>}
    {adding ? <AddReceipt onClose={() => setAdding(false)} onSaved={() => { setAdding(false); setOffset(0); page.reload(); toast(L("저장 이력을 기록했습니다", "Storage record saved")); }} /> : null}
  </Card>;
}

function AddReceipt({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const L = useL();
  const connections = useApi<{ items: Connection[] }>(`${RECEIPTS}/connections`);
  const [issuer, setIssuer] = useState<Locator>();
  const [vault, setVault] = useState<Locator>();
  const [form, setForm] = useState({ system: "", record: "", stored: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const attempt = useRef<{ body: string; id: string } | null>(null);
  const valid = Boolean(issuer && vault && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(form.system.trim())
    && /^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,127}$/.test(form.record.trim()) && form.stored);
  const save = async () => {
    if (!issuer || !vault || !valid) return;
    setBusy(true); setError("");
    try {
      const body = JSON.stringify(receiptBody(issuer, vault, form));
      if (attempt.current?.body !== body) attempt.current = { body, id: randomId() };
      await send(RECEIPTS, "POST", { ...JSON.parse(body), id: attempt.current.id });
      attempt.current = null;
      onSaved();
    } catch (reason) { setError(reasonText(reason, L)); }
    finally { setBusy(false); }
  };
  return <Modal onClose={onClose} labelledBy="receipt-title" className="rule-modal">
    <h2 id="receipt-title">{L("발급·저장 이력 추가", "Add an issuance and storage record")}</h2>
    <p className="re-cap">{L("CreMore가 실제로 수집한 발급 Credential과 저장소 위치를 고르고, 그 둘을 잇는 원본 기록을 적습니다. 메타데이터만 제출하며, 나중에 철회해도 Credential이 폐기되거나 저장소 값이 지워지지 않습니다.",
      "Choose an issued credential and a vault location CreMore collected, and name the source record that links them. Only metadata is submitted; revoking later does not revoke the credential or delete the stored value.")}</p>
    {connections.error ? <ErrorLine onRetry={connections.reload}>{reasonText(connections.error, L)}</ErrorLine> : !connections.data ? <Loading /> : <div className="row2">
      <Picker role="issuer" connections={connections.data.items} select={setIssuer} />
      <Picker role="vault" connections={connections.data.items} select={setVault} />
    </div>}
    <div className="row2">
      <div className="field"><label htmlFor="rc-system">{L("발급·교체 시스템 ID", "Issuance or rotation system ID")}</label>
        <input id="rc-system" maxLength={64} value={form.system} onChange={event => setForm({ ...form, system: event.target.value })} placeholder="vault-rotation" /></div>
      <div className="field"><label htmlFor="rc-record">{L("원본 기록 ID", "Source record ID")}</label>
        <input id="rc-record" maxLength={128} value={form.record} onChange={event => setForm({ ...form, record: event.target.value })} placeholder="rotation/2026-09-28/123" /></div>
    </div>
    <div className="row2"><div className="field"><label htmlFor="rc-stored">{L("원본 기록의 저장 시각", "Storage time in the source record")}</label>
      <input id="rc-stored" type="datetime-local" value={form.stored} onChange={event => setForm({ ...form, stored: event.target.value })} /></div></div>
    {error ? <p className="ig-result bad" role="alert"><Ic name="alert" size={15} />{error}</p> : null}
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose}>{L("취소", "Cancel")}</button>
      <button type="button" className="primary-btn" disabled={!valid || busy} onClick={() => void save()}>{L("이력 기록", "Save the record")}</button>
    </div>
  </Modal>;
}

function Picker({ role, connections, select }: { role: "issuer" | "vault"; connections: Connection[]; select: (item: Locator | undefined) => void }) {
  const L = useL();
  const locale = useLocale();
  const [connection, setConnection] = useState("");
  const [run, setRun] = useState("");
  const [runs, setRuns] = useState<Page<Run> | null>(null);
  const [items, setItems] = useState<Page<Locator> | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let live = true;
    setRuns(null); setRun(""); setItems(null); select(undefined); setFailed(false);
    if (connection) api<Page<Run>>(`${RECEIPTS}/connections/${encodeURIComponent(connection)}/runs?offset=0&limit=20`)
      .then(value => { if (live) setRuns(value); }).catch(() => { if (live) setFailed(true); });
    return () => { live = false; };
  }, [connection, select]);
  useEffect(() => {
    let live = true;
    setItems(null); select(undefined); setFailed(false);
    if (run) api<Page<Locator>>(`${RECEIPTS}/observations?run_id=${encodeURIComponent(run)}&role=${role}&offset=0&limit=100`)
      .then(value => { if (live) setItems(value); }).catch(() => { if (live) setFailed(true); });
    return () => { live = false; };
  }, [run, role, select]);
  const title = role === "issuer" ? L("발급 Credential", "Issued credential") : L("저장소 위치", "Vault location");
  return <div className="field">
    <span className="lbl">{title}</span>
    <select aria-label={L(`${title} 연결`, `${title} connection`)} value={connection} onChange={event => setConnection(event.target.value)}>
      <option value="">{L("수집 연결 고르기", "Choose a collection")}</option>
      {connections.map(item => <option key={item.id} value={item.id} disabled={!item.enabled}>{item.name}</option>)}
    </select>
    {runs ? <select aria-label={L(`${title} 수집`, `${title} run`)} value={run} onChange={event => setRun(event.target.value)}>
      <option value="">{L("끝난 수집 고르기", "Choose a finished run")}</option>
      {runs.items.map(item => <option key={item.id} value={item.id} disabled={!item.finished_at || !["COMPLETE", "PARTIAL"].includes(item.status)}>{fmtDT(item.started_at, locale)} · {item.status === "COMPLETE" ? L("완료", "Complete") : item.status === "PARTIAL" ? L("일부", "Partial") : item.status}</option>)}
    </select> : null}
    {items ? items.items.length ? <select aria-label={L(`${title} 항목`, `${title} item`)} defaultValue="" onChange={event => select(items.items.find(item => JSON.stringify(item.anchor) === event.target.value))}>
      <option value="">{L("항목 고르기", "Choose an item")}</option>
      {items.items.map(item => <option key={JSON.stringify(item.anchor)} value={JSON.stringify(item.anchor)}>{item.identifier || item.reference}{item.version ? ` · ${item.version}` : ""}</option>)}
    </select> : <span className="meta">{L("이 수집에 연결할 항목이 없습니다.", "This run has nothing to link.")}</span> : null}
    {failed ? <span className="meta">{L("불러오지 못했습니다. 권한과 연결 범위를 확인하세요.", "Could not load. Check access and the connection scope.")}</span> : null}
  </div>;
}
