"use client";

import { useState } from "react";

import { reasonText, send, useApi, useSaved } from "@/console/data";
import { useL } from "@/console/text";
import { Banner, Card, CardBody, Loading } from "@/console/ui";
import { api } from "@/lib/dashboard-api";

type Binding = { id: string; profile_id: string; state: string; expires_at?: string | null; last_received_at?: string | null;
  probe?: { digest: string; workspace_id: string; subscription_id: string; integration_id: string } | null };
type View = { bindings: Binding[]; profiles: { id: string; name: string; connection: string }[] };

export function NotionWebhooks() {
  const L = useL();
  const view = useApi<View>("settings/notion-webhooks", { every: 5000 });
  const saved = useSaved();
  const [profile, setProfile] = useState("");
  const [verified, setVerified] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const base = "settings/notion-webhooks";
  const act = async (work: () => Promise<unknown>, message: string) => {
    setBusy(true); setError(null); setNotice(null);
    try { await work(); view.reload(); saved(); setNotice(message); }
    catch (reason) { setError(reasonText(reason, L)); }
    finally { setBusy(false); }
  };
  return <Card title={L("Notion 변경 알림", "Notion change notifications")} className="list-card"
    info={L("Notion의 서명을 확인하고 승인된 페이지만 검사합니다. 서버의 이 경로는 로그인 화면 없이 HTTPS로 접근 가능해야 합니다.",
      "Verifies Notion signatures and scans approved pages only. This HTTPS route must be reachable without the login screen.")}>
    <CardBody>
      {error || view.error ? <Banner tone="bad" icon="alert">{error ?? reasonText(view.error, L)}</Banner> : null}
      {notice ? <Banner tone="ok" icon="info">{notice}</Banner> : null}
      {!view.data ? <Loading /> : <>
        <div className="set-grid wide">
          <div className="field"><label htmlFor="notion-event-profile">{L("Notion 검사 범위", "Notion scan scope")}</label>
            <select id="notion-event-profile" value={profile} disabled={busy} onChange={event => setProfile(event.target.value)}>
              <option value="">{L("승인된 범위 선택", "Choose an approved scope")}</option>
              {view.data.profiles.map(row => <option key={row.id} value={row.id}>{row.connection} · {row.name}</option>)}
            </select>
          </div>
          <button className="ghost-btn" disabled={busy || !profile} onClick={() => void act(() => send(base, "POST", { profile_id: profile }),
            L("주소를 복사해 Notion 연결 설정의 Webhooks에 등록하세요.", "Copy the URL into Webhooks in your Notion connection settings."))}>
            {L("수신 주소 만들기", "Create receiving URL")}</button>
        </div>
        {!view.data.profiles.length ? <p className="set-note">{L("연동 서비스 → 검사 대상에서 Notion의 ‘변경되면 검사’를 켜고 저장하세요.",
          "Enable Scan when it changes in the Notion integration's scan targets and save.")}</p> : null}
        {view.data.bindings.map(row => <div key={row.id} className="set-row">
          <div className="set-text"><b>{view.data?.profiles.find(p => p.id === row.profile_id)?.name ?? L("저장된 검사 범위", "Saved scan scope")}</b>
            <p>{row.state === "ACTIVE" ? L("활성 · 서명된 변경 알림을 수신합니다", "Active · receiving signed changes")
              : row.state === "WAITING" ? L("Notion의 최초 검증 요청을 기다리는 중 · 30분 이내 설정", "Waiting for Notion verification · finish within 30 minutes")
              : L("Notion에서 구독을 검증한 뒤, 선택한 페이지를 수정해 서명된 알림을 확인하세요.", "Verify the subscription in Notion, then edit a selected page to receive a signed event.")}</p>
            <div className="actions">
              <button className="ghost-btn" disabled={busy} onClick={() => void act(() => navigator.clipboard.writeText(
                new URL(`/api/v1/hooks/notion/${row.id}`, window.location.origin).href), L("수신 주소를 복사했습니다.", "Receiving URL copied."))}>
                {L("수신 주소 복사", "Copy receiving URL")}</button>
              {row.state === "PENDING" ? <button className="ghost-btn" disabled={busy} onClick={() => void act(async () => {
                const token = await api<{ verification_token: string }>(`${base}/${row.id}/verification`);
                await navigator.clipboard.writeText(token.verification_token);
              }, L("검증 토큰을 복사했습니다. Notion의 Verify subscription에 붙여넣으세요.", "Verification token copied. Paste it into Verify subscription in Notion."))}>
                {L("검증 토큰 복사", "Copy verification token")}</button> : null}
              <button className="ghost-btn" disabled={busy} onClick={() => void act(() => send(`${base}/${row.id}`, "DELETE"),
                L("알림 연결을 해제했습니다. 검사 이력은 유지됩니다.", "Notification binding removed. Scan history is retained."))}>{L("연결 해제", "Disconnect")}</button>
            </div>
            {row.state === "PENDING" ? <>
              <label className="set-check"><input type="checkbox" checked={Boolean(verified[row.id])} onChange={e => setVerified(v => ({ ...v, [row.id]: e.target.checked }))} />
                {L("Notion에서 이 구독의 검증을 완료했습니다", "I verified this subscription in Notion")}</label>
              <p className="meta">{row.probe ? L("서명된 확인 알림을 받았습니다.", "A signed confirmation event was received.") : L("서명된 확인 알림 대기 중", "Waiting for a signed confirmation event")}</p>
              <button className="primary-btn" disabled={busy || !verified[row.id] || !row.probe} onClick={() => void act(() => send(`${base}/${row.id}/confirm`, "POST",
                { verified_in_notion: true, probe_digest: row.probe?.digest }), L("자동 변경 검사를 활성화했습니다.", "Automatic change scans enabled."))}>
                {L("확인하고 활성화", "Confirm and enable")}</button>
            </> : null}
          </div>
        </div>)}
      </>}
    </CardBody>
  </Card>;
}
