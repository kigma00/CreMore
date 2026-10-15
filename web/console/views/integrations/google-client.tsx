"use client";

import { useState } from "react";
import { reasonText, send, useApi } from "@/console/data";
import { Ic } from "@/console/icons";
import { useToast } from "@/console/layer";
import { Logo } from "@/console/logos";
import { useL } from "@/console/text";
import { TextField } from "@/console/ui";
import { type Descriptor, label } from "@/console/views/integrations/model";

export type GoogleClient = { configured: boolean; client_id?: string; redirect_uri?: string; source?: "SETTING" | "DASHBOARD"; locked?: boolean };
const GOOGLE_CREDENTIALS = "https://console.cloud.google.com/auth/clients";

/** The Google OAuth client the sign-in uses, made by an admin in Google Cloud and saved here (its secret sealed),
 * unless GCP_OAUTH_* settings pin one. */
export function GoogleClientSetup({ current, onSaved, onCancel }: { current: GoogleClient | undefined; onSaved: () => void; onCancel?: () => void }) {
  const L = useL();
  const [clientId, setClientId] = useState(current?.client_id ?? "");
  const [secret, setSecret] = useState("");
  const [redirect, setRedirect] = useState(current?.redirect_uri ?? (typeof window === "undefined" ? "" : `${window.location.origin}/gcp/oauth/callback`));
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const toast = useToast();
  // Only the saved client keeps its secret when none is typed; another client ID needs its own.
  const keepsSecret = !!current?.configured && current.source === "DASHBOARD" && clientId.trim() === current.client_id;
  async function save() {
    setBusy(true); setProblem(null);
    try {
      await send("v2/gcp/oauth/client", "PUT", { client_id: clientId.trim(), client_secret: secret.trim(), redirect_uri: redirect.trim() });
      setSecret(""); onSaved();
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "";
      setProblem(message.includes("GCP_OAUTH_SETUP_REQUIRED")
        ? L("클라이언트 ID(…apps.googleusercontent.com), 시크릿, /gcp/oauth/callback으로 끝나는 리디렉션 URI를 확인하세요.",
          "Check the client ID (…apps.googleusercontent.com), the secret and a redirect URI ending in /gcp/oauth/callback.")
        : reasonText(reason, L));
    } finally { setBusy(false); }
  }
  return <div className="ig-google-setup">
    <b>{L("Google 로그인 앱 설정", "Set up the Google sign-in app")}</b>
    <p className="ig-sub">{L("Google Cloud 콘솔의 Google Auth Platform에서 브랜딩과 대상(모두 조직 사람이면 내부, 외부 앱은 7일 뒤 멈추는 테스트가 아니라 프로덕션)을 정하고, 클라이언트에서 웹 애플리케이션을 만들어 승인된 리디렉션 URI에 아래 주소(공개 도메인의 https 주소, 이 PC에서만 쓰면 http://localhost)를 넣은 뒤 클라이언트 ID와 시크릿을 입력합니다. Google은 시크릿을 만들 때 한 번만 보여 줍니다. 여기서는 암호화해 저장하고 다시 보여 주지 않습니다.",
      "In Google Cloud console's Google Auth Platform, set Branding and Audience (Internal when everyone is in your organization; an External app must be In production, as testing stops after 7 days), then under Clients create a Web application with the redirect URI below (https on a public domain, or http://localhost when used only on this PC) and enter its client ID and secret. Google shows the secret only when it is created; it is stored encrypted here and never shown again.")}</p>
    <div className="ig-google-actions">
      <a className="ghost-btn" href={GOOGLE_CREDENTIALS} target="_blank" rel="noopener noreferrer"><Ic name="ext" size={15} />{L("Google Cloud 콘솔 열기", "Open Google Cloud console")}</a>
      <button type="button" className="ghost-btn" onClick={() => { void navigator.clipboard?.writeText(redirect); toast(L("리디렉션 URI를 복사했습니다", "Redirect URI copied")); }}>
        <Ic name="copy" size={15} />{L("리디렉션 URI 복사", "Copy the redirect URI")}</button>
    </div>
    <TextField label={L("리디렉션 URI", "Redirect URI")} value={redirect} onChange={setRedirect} />
    <TextField label={L("클라이언트 ID", "Client ID")} value={clientId} onChange={setClientId} placeholder="…apps.googleusercontent.com" />
    <TextField label={keepsSecret ? L("클라이언트 시크릿 (바꿀 때만)", "Client secret (only to change it)") : L("클라이언트 시크릿", "Client secret")}
      value={secret} onChange={setSecret} masked />
    {problem ? <span className="ig-result bad" role="status"><Ic name="alert" size={16} />{problem}</span> : null}
    <div className="ig-google-actions">
      <button type="button" className="primary-btn" disabled={busy || !clientId.trim() || !redirect.trim() || (!keepsSecret && !secret.trim())}
        onClick={() => void save()}><Ic name="checkCircle" size={15} />{busy ? L("저장 중", "Saving") : L("저장", "Save")}</button>
      {onCancel ? <button type="button" className="link-btn" onClick={onCancel}>{L("취소", "Cancel")}</button> : null}
    </div>
  </div>;
}

export function GoogleConsent({ d, approved, perms, busy, onApprove }: { d: Descriptor; approved: boolean; perms: string[]; busy: boolean; onApprove: () => void }) {
  const L = useL();
  const status = useApi<GoogleClient>("v2/gcp/oauth/status");
  const [editing, setEditing] = useState(false);
  const client = status.data;
  const setup = client && !client.locked && (!client.configured || editing);
  const name = label(d, L);
  const unique = Array.from(new Set(perms));
  return <div className="ig-consent">
    <div className="ig-consent-logos"><span className="ig-cm"><Ic name="shield" size={22} /></span><Ic name="right" size={16} /><Logo id={d.provider} size={34} /></div>
    <b>{L(`CreMore가 ${name} 접근 승인을 요청합니다`, `CreMore is asking to access ${name}`)}</b>
    <p className="ig-sub">{L("Google은 Google Cloud 전체 접근(cloud-platform 범위) 승인을 묻습니다. CreMore는 로그인한 계정의 IAM 역할이 허용하는 일을 할 수 있으니, 아래 권한만 가진 계정으로 로그인하세요.",
      "Google asks to approve full Google Cloud access (the cloud-platform scope): CreMore can do whatever the signed-in account's IAM roles allow, so sign in with an account that holds only the permissions below.")}</p>
    {unique.length ? <ul>{unique.map(id => <li key={id}><Ic name="checkCircle" size={15} /><span className="mono">{id}</span></li>)}</ul> : null}
    {approved ? <>
      <div className="ig-result ok"><Ic name="checkCircle" size={16} />{L("Google에서 승인했습니다", "Approved in Google")}</div>
      <button type="button" className="link-btn" disabled={busy} onClick={onApprove}>{L("다른 계정으로 다시 승인", "Approve with another account")}</button>
    </> : setup ? <GoogleClientSetup current={client} onSaved={() => { setEditing(false); status.reload(); }}
        onCancel={client?.configured ? () => setEditing(false) : undefined} />
      : client?.configured === false ? <div className="ig-result bad"><Ic name="alert" size={16} />
      <span>{L("Google 로그인 앱 설정이 서버에 고정돼 있지만 올바르지 않습니다. 관리자가 API 서버의 GCP_OAUTH_CLIENT_ID·GCP_OAUTH_CLIENT_SECRET·GCP_OAUTH_REDIRECT_URI를 고쳐야 합니다.",
        "The Google sign-in app is pinned on the server but not valid. An administrator fixes GCP_OAUTH_CLIENT_ID, GCP_OAUTH_CLIENT_SECRET and GCP_OAUTH_REDIRECT_URI on the API server.")}</span></div>
      : <>
        <button type="button" className="primary-btn" disabled={busy || client?.configured !== true} onClick={onApprove}><Ic name="ext" size={16} />{L("Google에서 승인", "Approve in Google")}</button>
        <div className="ig-sub ig-sso-note">{L("Google 로그인 화면으로 이동했다가, 승인하면 이 화면으로 돌아와 권한을 확인합니다.", "You go to Google's sign-in and come back here to check access once approved.")}</div>
        {client?.configured && client.source === "DASHBOARD" ? <button type="button" className="link-btn" onClick={() => setEditing(true)}>
          {L(`Google 로그인 앱 바꾸기 (${client.client_id ?? ""})`, `Change the Google sign-in app (${client.client_id ?? ""})`)}</button> : null}
      </>}
  </div>;
}
