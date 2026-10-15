"use client";

/* The company's ticket system (cremore/ticketing), in the design's integration window: which system, where it is,
 * the OAuth client and the service account CreMore signs in as. Secrets are sent once and never shown again; a
 * check signs in and reads what asking needs. An owner's approval of a key action can then be asked there. */

import { useEffect, useState } from "react";

import { DashboardAPIError } from "@/lib/dashboard-api";
import { reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { Modal, useToast } from "@/console/layer";
import { type Say, useL } from "@/console/text";
import { Banner, Loading, SelectField, TextField } from "@/console/ui";

export const TICKET_PATH = "settings/ticket-system";

export type TicketField = { name: string; label: string; label_ko: string; kind: "url" | "text" | "number" | "secret"; required: boolean; hint: string };
export type TicketSystemView = {
  systems: { id: string; label: string; fields: TicketField[] }[];
  current: { system: string; values: Record<string, string | number | null>; secrets_saved: string[] } | null;
};
/** What any analyst may read: the system an owner's approval can be asked in. */
export type TicketSystemStatus = { system: string | null; label: string | null };

export function ticketState(status: TicketSystemStatus | undefined, L: Say): string {
  return status?.label ?? L("설정 안 됨", "Not set up");
}

type Form = { system: string; values: Record<string, string> };

function formOf(view: TicketSystemView): Form {
  const current = view.current;
  const values: Record<string, string> = {};
  for (const [name, value] of Object.entries(current?.values ?? {})) values[name] = value === null || value === undefined ? "" : String(value);
  return { system: current?.system ?? "", values };
}

/** The fields as the window lays them out: an address on its own line, the others two to a line. */
export function rows(fields: TicketField[]): TicketField[][] {
  const out: TicketField[][] = [];
  for (const field of fields) {
    const last = out[out.length - 1];
    if (field.kind !== "url" && last && last.length === 1 && last[0].kind !== "url") last.push(field);
    else out.push([field]);
  }
  return out;
}

/** The body a save sends: plain values, and only the secrets typed now (a blank one keeps the saved one). */
export function ticketBody(form: Form, fields: TicketField[]) {
  if (!form.system) return { system: null };
  const values: Record<string, string> = {};
  const secrets: Record<string, string> = {};
  for (const field of fields) {
    const value = (form.values[field.name] ?? "").trim();
    if (field.kind === "secret") { if (value) secrets[field.name] = value; } else values[field.name] = value;
  }
  return { system: form.system, values, secrets };
}

export function TicketSystemModal({ onClose }: { onClose: () => void }) {
  const L = useL();
  const toast = useToast();
  const saved = useSaved();
  const view = useApi<TicketSystemView>(TICKET_PATH);
  const [form, setForm] = useState<Form | null>(null);
  const [busy, setBusy] = useState<"" | "save" | "check">("");
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { if (view.data && !form) setForm(formOf(view.data)); }, [view.data, form]);

  const head = <h2 id="ts-title"><span className="ig-cm"><Ic name="list" size={18} /></span>{L("티켓 시스템", "Ticket system")} <small>{L("대응 응답·소유자 승인", "Response replies and owner approval")}</small></h2>;
  if (!view.data || !form) {
    return <Modal onClose={onClose} labelledBy="ts-title" className="integ mi">
      {head}{view.error ? <Banner tone="bad" icon="alert">{reasonText(view.error, L)}</Banner> : <Loading />}
      <div className="modal-foot"><button type="button" className="ghost-btn" onClick={onClose}>{L("닫기", "Close")}</button></div>
    </Modal>;
  }
  const data = view.data;
  const system = data.systems.find(item => item.id === form.system) ?? null;
  const same = data.current?.system === form.system;
  const set = (name: string, value: string) => setForm(current => current ? { ...current, values: { ...current.values, [name]: value } } : current);

  async function save() {
    setBusy("save"); setError(null);
    try {
      const next = await send<TicketSystemView>(TICKET_PATH, "PUT", ticketBody(form!, system?.fields ?? []));
      view.replace(next); setForm(formOf(next)); saved();
      toast(form!.system ? L("티켓 시스템 설정을 저장했습니다.", "Ticket system saved.") : L("티켓 시스템을 쓰지 않습니다.", "No ticket system is used."));
    } catch (reason) { setError(reasonText(reason, L)); }
    finally { setBusy(""); }
  }

  async function check() {
    setBusy("check"); setError(null);
    try {
      const result = await send<{ ok: boolean; code: string | null }>(`${TICKET_PATH}/check`, "POST", {});
      if (result.ok) toast(L("로그인하고 티켓·사용자를 읽었습니다.", "Signed in and read tickets and users."));
      else setError(reasonText(new DashboardAPIError(result.code ?? "TICKET_SYSTEM_ERROR", 409), L));
    } catch (reason) { setError(reasonText(reason, L)); }
    finally { setBusy(""); }
  }

  return <Modal onClose={onClose} labelledBy="ts-title" className="integ mi" dismissable={!busy}>
    {head}
    <p className="ig-sub mi-intro">{L("키 조치의 소유자 승인과, 고를 때는 노출 대응 요청을 회사 티켓 시스템에서 받습니다. CreMore가 지정한 계정에 티켓을 열고 응답을 1분마다 읽어 기록합니다. 대응 완료 응답 뒤에는 재스캔으로 제거 여부를 확인하며, 키 조치는 별도 승인 절차를 따릅니다. 인증 비밀값은 저장 후 다시 보여 주지 않습니다.",
      "Receive key-action owner approvals, and exposure response requests when chosen, through the company ticket system. CreMore opens a ticket for the specified account and reads its answer every minute. A rescan verifies removal after a cleanup reply; key actions follow their separate approval process. Sign-in secrets are never shown again once saved.")}</p>
    {error ? <Banner tone="bad" icon="alert" onClose={() => setError(null)}>{error}</Banner> : null}

    <div className="ig-section">
      <div className="ig-section-head"><h3>{L("시스템", "System")}</h3></div>
      <SelectField label={L("티켓 시스템", "Ticket system")} value={form.system} onChange={value => setForm({ system: value, values: value === data.current?.system ? formOf(data).values : {} })}
        options={[{ id: "", label: L("쓰지 않음", "None") }, ...data.systems.map(item => ({ id: item.id, label: item.label }))]} />
      {!data.systems.length ? <p className="ig-hint"><Ic name="info" size={15} /><span>{L("설치된 티켓 시스템 플러그인이 없습니다. 플러그인 패키지를 설치하고 TICKET_SYSTEM_PLUGINS에 허용하면 여기서 고를 수 있습니다.",
        "No ticket-system plugin is installed. Install a plugin package and allow it in TICKET_SYSTEM_PLUGINS to choose it here.")}</span></p> : null}
    </div>

    {system ? <div className="ig-section">
      <div className="ig-section-head"><h3>{L("연결", "Connection")}</h3></div>
      {rows(system.fields).map(row => <div key={row[0].name} className={row.length > 1 ? "row2" : undefined}>
        {row.map(field => <TextField key={field.name} label={L(field.label_ko, field.label) + (field.required ? "" : L(" (선택)", " (optional)"))}
          value={form.values[field.name] ?? ""} onChange={value => set(field.name, field.kind === "number" ? value.replace(/\D/g, "").slice(0, 10) : value)}
          masked={field.kind === "secret"} inputMode={field.kind === "number" ? "numeric" : field.kind === "url" ? "url" : "text"}
          placeholder={field.kind === "secret" ? (same && data.current?.secrets_saved.includes(field.name) ? L("저장된 값 유지 · 바꿀 때만 입력", "Keep the saved value · enter only to replace") : L("여기에 붙여 넣기", "Paste here"))
            : field.hint || undefined} />)}
      </div>)}
      <p className="meta">{L("연결 값을 바꾸면 비밀값을 다시 입력합니다.", "Changing a connection value needs the secrets again.")}</p>
    </div> : null}

    <div className="modal-foot">
      {data.current ? <button type="button" className="ghost-btn" disabled={Boolean(busy) || !same} onClick={() => void check()}>
        <Ic name="refresh" size={15} />{busy === "check" ? L("확인 중", "Checking") : L("연결 확인", "Check the connection")}</button> : null}
      <button type="button" className="ghost-btn" style={{ marginLeft: "auto" }} onClick={onClose} disabled={Boolean(busy)}>{L("닫기", "Close")}</button>
      <button type="button" className="primary-btn" disabled={Boolean(busy)} onClick={() => void save()}>{busy === "save" ? L("저장 중", "Saving") : L("저장", "Save")}</button>
    </div>
  </Modal>;
}
