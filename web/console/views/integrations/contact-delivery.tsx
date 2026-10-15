"use client";

/* Owner contact that CreMore sends itself (cremore/governance/contact.py), in the design's integration window:
 * the company's SMTP relay, a Slack bot, the domains messages may go to, and the console's address that links in
 * owner approval requests start with. The relay password and the bot token are sent once and never shown again;
 * a test message shows the setup working. */

import { type ReactNode, useEffect, useState } from "react";

import { DashboardAPIError } from "@/lib/dashboard-api";
import { reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { Modal, useToast } from "@/console/layer";
import { type Say, useL } from "@/console/text";
import { AreaField, Banner, Check, cls, Loading, SelectField, TextField } from "@/console/ui";

export const CONTACT_PATH = "settings/contact-delivery";

type MailView = { host: string; port: number; security: string; username: string; from_address: string; from_name: string; password_saved: boolean };
export type ContactView = {
  mail: MailView | null; slack: { token_saved: boolean; allowed_channels: string[] } | null; allowed_domains: string[]; slack_scopes: string[];
  hourly_recipients: number; console_url: string | null;
  /** Owner approval links go out only with company sign-in; only then does the console address matter. */
  owner_links?: boolean;
};
/** What the contact window reads (any analyst): the channels CreMore sends on, and where to. */
export type ContactChannels = { mail: boolean; slack: boolean; allowed_domains: string[]; allowed_channels: string[]; console_url?: string | null };

/** Which channels CreMore sends on, for the integrations card. */
export function contactState(view: ContactChannels | undefined, L: Say): string {
  const on = [view?.mail ? L("메일", "Mail") : "", view?.slack ? "Slack" : ""].filter(Boolean);
  return on.length ? on.join(" · ") : L("설정 안 됨", "Not set up");
}

type Form = {
  mail: boolean; host: string; port: string; security: string; username: string; password: string; from_address: string; from_name: string;
  slack: boolean; token: string; channels: string; domains: string; console: string;
};

function formOf(view: ContactView | undefined): Form {
  const mail = view?.mail;
  return {
    mail: Boolean(mail), host: mail?.host ?? "", port: String(mail?.port ?? 587), security: mail?.security ?? "starttls", username: mail?.username ?? "",
    password: "", from_address: mail?.from_address ?? "", from_name: mail?.from_name ?? "",
    slack: Boolean(view?.slack), token: "", channels: (view?.slack?.allowed_channels ?? []).join(", "), domains: (view?.allowed_domains ?? []).join(", "),
    console: view?.console_url ?? "",
  };
}

/** The words of a list the admin typed: separated by commas, semicolons, spaces or lines. */
export function listOf(text: string): string[] {
  return Array.from(new Set(text.split(/[\s,;]+/).map(item => item.trim()).filter(Boolean)));
}

/** The body a save sends; an empty password or token keeps the saved one. */
export function contactBody(form: Form) {
  return {
    mail: form.mail ? { host: form.host.trim(), port: Number(form.port), security: form.security, username: form.username.trim(),
      password: form.password, from_address: form.from_address.trim(), from_name: form.from_name.trim() } : null,
    slack: form.slack ? { token: form.token.trim(), allowed_channels: listOf(form.channels) } : null,
    allowed_domains: listOf(form.domains.toLowerCase()),
    console_url: form.console.trim(),
  };
}

export function ContactDeliveryModal({ onClose }: { onClose: () => void }) {
  const L = useL();
  const toast = useToast();
  const saved = useSaved();
  const view = useApi<ContactView>(CONTACT_PATH);
  const [form, setForm] = useState<Form | null>(null);
  const [busy, setBusy] = useState<"" | "save" | "test">("");
  const [error, setError] = useState<string | null>(null);
  const [trial, setTrial] = useState<{ channel: "mail" | "slack"; to: string }>({ channel: "mail", to: "" });
  useEffect(() => { if (view.data && !form) setForm(formOf(view.data)); }, [view.data, form]);

  const head = <h2 id="cd-title"><span className="ig-cm"><Ic name="send" size={18} /></span>{L("연락 발송", "Contact delivery")} <small>{L("메일 · Slack", "Mail · Slack")}</small></h2>;
  if (!view.data || !form) {
    return <Modal onClose={onClose} labelledBy="cd-title" className="integ mi">
      {head}{view.error ? <Banner tone="bad" icon="alert">{reasonText(view.error, L)}</Banner> : <Loading />}
      <div className="modal-foot"><button type="button" className="ghost-btn" onClick={onClose}>{L("닫기", "Close")}</button></div>
    </Modal>;
  }
  const data = view.data;
  const set = (change: Partial<Form>) => setForm(current => current ? { ...current, ...change } : current);

  async function save() {
    setBusy("save"); setError(null);
    try {
      const next = await send<ContactView>(CONTACT_PATH, "PUT", contactBody(form!));
      view.replace(next); setForm(formOf(next)); saved();
      toast(L("연락 발송 설정을 저장했습니다.", "Contact delivery saved."));
    } catch (reason) { setError(reasonText(reason, L)); }
    finally { setBusy(""); }
  }

  async function test() {
    setBusy("test"); setError(null);
    try {
      const sent = await send<{ delivered: string[]; failed: { to: string; code: string }[] }>(`${CONTACT_PATH}/test`, "POST", { channel: trial.channel, to: trial.to.trim() });
      if (sent.delivered.length) toast(L("시험 메시지를 보냈습니다.", "Test message sent."));
      else setError(reasonText(new DashboardAPIError(sent.failed[0]?.code ?? "CONTACT_NOT_DELIVERED", 502), L));
    } catch (reason) { setError(reasonText(reason, L)); }
    finally { setBusy(""); }
  }

  const channelCard = (key: "mail" | "slack", title: string, text: string, fields: ReactNode) =>
    <div className={cls("mi-cloud", form[key] && "on")} key={key}>
      <button type="button" className="ig-feat-card" role="checkbox" aria-checked={form[key]} onClick={() => set({ [key]: !form[key] } as Partial<Form>)}>
        <Check on={form[key]} /><span className="ig-feat-text"><span className="t">{title}</span><span className="d">{text}</span></span>
      </button>
      {form[key] ? <div className="mi-fields">{fields}</div> : null}
    </div>;

  return <Modal onClose={onClose} labelledBy="cd-title" className="integ mi" dismissable={!busy}>
    {head}
    <p className="ig-sub mi-intro">{L(`담당자에게 연락할 때 CreMore가 메일과 Slack 메시지를 직접 보냅니다. 메시지에는 비밀값을 넣지 않고, 허용한 도메인의 주소와 여기에 적은 Slack 채널로만 보내며, 한 사람이 한 시간에 ${data.hourly_recipients}곳까지 보냅니다. 보낸 기록은 Credential 이력에 남습니다.`,
      `CreMore sends mail and Slack messages itself when you contact an owner. Messages carry no secret value, go only to addresses in the allowed domains and to the Slack channels listed here, at most ${data.hourly_recipients} recipients an hour per person, and each send is in the credential's history.`)}</p>
    {error ? <Banner tone="bad" icon="alert" onClose={() => setError(null)}>{error}</Banner> : null}

    <div className="ig-section">
      <div className="ig-section-head"><h3>{L("보낼 방법", "How to send")}</h3></div>
      <div className="mi-clouds">
        {channelCard("mail", L("메일 (SMTP)", "Mail (SMTP)"), L("회사 메일 서버를 거쳐 보냅니다.", "Sent through the company's mail server."), <>
          <div className="row2">
            <TextField label={L("SMTP 서버", "SMTP server")} value={form.host} onChange={value => set({ host: value })} placeholder="smtp.example.com" />
            <TextField label={L("포트", "Port")} value={form.port} onChange={value => set({ port: value.replace(/\D/g, "").slice(0, 5) })} inputMode="numeric" />
          </div>
          <SelectField label={L("보안 연결", "Security")} value={form.security} onChange={value => set({ security: value, port: value === "tls" ? "465" : form.port === "465" ? "587" : form.port })}
            options={[{ id: "starttls", label: "STARTTLS" }, { id: "tls", label: L("TLS (암시적)", "TLS (implicit)") }, { id: "none", label: L("암호화 안 함 (사내 릴레이)", "None (internal relay)") }]} />
          <div className="row2">
            <TextField label={L("계정 (선택)", "Account (optional)")} value={form.username} onChange={value => set({ username: value })} />
            <TextField label={L("비밀번호", "Password")} value={form.password} masked onChange={value => set({ password: value })}
              placeholder={data.mail?.password_saved ? L("저장된 값 유지 · 바꿀 때만 입력", "Keep the saved value · enter only to replace") : L("계정이 있을 때 입력", "Enter when there is an account")} />
          </div>
          <div className="row2">
            <TextField label={L("보내는 주소", "From address")} value={form.from_address} onChange={value => set({ from_address: value })} placeholder="security@example.com" inputMode="email" />
            <TextField label={L("보내는 사람 이름 (선택)", "From name (optional)")} value={form.from_name} onChange={value => set({ from_name: value })} placeholder={L("보안팀", "Security team")} />
          </div>
        </>)}
        {channelCard("slack", "Slack", L("Slack 봇이 사람에게는 DM으로, 채널에는 메시지로 보냅니다.", "A Slack bot messages people directly and posts to channels."), <>
          <TextField label={L("봇 토큰 (xoxb-)", "Bot token (xoxb-)")} value={form.token} masked onChange={value => set({ token: value })}
            placeholder={data.slack?.token_saved ? L("저장된 값 유지 · 바꿀 때만 입력", "Keep the saved value · enter only to replace") : L("여기에 붙여 넣기", "Paste here")} />
          <AreaField label={L("보낼 수 있는 채널 (선택)", "Channels it may post to (optional)")} value={form.channels} onChange={value => set({ channels: value })} rows={2}
            placeholder="#security-alerts, C0123ABCD9" hint={L("여기에 적은 채널로만 보냅니다. 채널 ID(C…)는 이름이 바뀌어도 그대로입니다. 사람에게는 허용한 도메인의 주소로 찾아 DM을 보냅니다.",
              "Posts go only to channels listed here; a channel ID (C…) stays the same when the name changes. People are found by an address in the allowed domains and messaged directly.")} />
          <p className="ig-hint"><Ic name="info" size={15} /><span>{L(`봇에 필요한 권한: ${data.slack_scopes.join(", ")}. 채널로 보내려면 봇을 그 채널에 초대합니다.`,
            `The bot needs: ${data.slack_scopes.join(", ")}. Invite the bot to a channel to post there.`)}</span></p>
          {data.slack_scopes.includes("channels:read") || data.slack_scopes.includes("groups:read") ? <p className="ig-hint"><Ic name="info" size={15} /><span>{L("channels:read · groups:read: 대응 알림 채널이 공개인지 비공개인지, 외부 회사와 공유되거나 보관되지 않았는지 저장할 때와 올리기 전마다 Slack에서 확인하는 데 씁니다. 이 권한이 없으면 개인 DM은 그대로 보내고 채널 알림만 막습니다(SLACK_SCOPE_MISSING).",
            "channels:read · groups:read: used to check with Slack, on save and before every post, that a response channel is private or allowed public, not shared with another company and not archived. Without them DMs still go out; only channel posts are refused (SLACK_SCOPE_MISSING).")}</span></p> : null}
        </>)}
      </div>
    </div>

    <div className="ig-section">
      <div className="ig-section-head"><h3>{L("받을 수 있는 도메인", "Domains that may receive")}</h3></div>
      <AreaField label={L("메일 주소의 도메인", "Mail address domains")} value={form.domains} onChange={value => set({ domains: value })} rows={2}
        placeholder="example.com, corp.example.com" hint={L("여기에 있는 도메인의 주소로만 메일과 Slack DM을 보냅니다. 하위 도메인은 따로 적습니다.",
          "Mail and Slack direct messages go only to addresses in these domains. List subdomains separately.")} />
    </div>

    {data.owner_links ? <div className="ig-section">
      <div className="ig-section-head"><h3>{L("승인 링크", "Approval links")}</h3></div>
      <TextField label={L("콘솔 주소", "Console address")} value={form.console} onChange={value => set({ console: value })}
        placeholder={typeof window === "undefined" ? "https://cremore.example.com" : window.location.origin} inputMode="url"
        hint={L("소유자 승인 요청과 노출 대응 요청에 넣는 링크가 이 주소로 시작합니다. 받는 사람은 회사 계정으로 로그인해 이 주소를 엽니다.",
          "Links in owner approval and exposure response requests start with this address. Recipients open it signed in with their company account.")} />
    </div> : null}

    <div className="ig-section">
      <div className="ig-section-head"><h3>{L("시험 발송", "Send a test")}</h3></div>
      <div className="row2 ig-fields">
        <SelectField label={L("채널", "Channel")} value={trial.channel} onChange={channel => setTrial(current => ({ ...current, channel }))}
          options={[{ id: "mail" as const, label: L("메일", "Mail") }, { id: "slack" as const, label: "Slack" }]} />
        <TextField label={L("받는 곳", "Send to")} value={trial.to} onChange={to => setTrial(current => ({ ...current, to }))}
          placeholder={trial.channel === "mail" ? "name@example.com" : L("이메일 또는 #채널", "Address or #channel")} />
      </div>
      {(trial.channel === "mail" ? data.mail : data.slack) ? null
        : <p className="meta">{L("이 채널을 저장한 뒤에 시험할 수 있습니다.", "Save this channel first to test it.")}</p>}
      <button type="button" className="ghost-btn" disabled={Boolean(busy) || !trial.to.trim() || !(trial.channel === "mail" ? data.mail : data.slack)}
        onClick={() => void test()}>
        <Ic name="send" size={15} />{busy === "test" ? L("보내는 중", "Sending") : L("시험 메시지 보내기", "Send a test message")}</button>
    </div>

    <div className="modal-foot">
      <button type="button" className="ghost-btn" style={{ marginLeft: "auto" }} onClick={onClose} disabled={Boolean(busy)}>{L("닫기", "Close")}</button>
      <button type="button" className="primary-btn" disabled={Boolean(busy)} onClick={() => void save()}>{busy === "save" ? L("저장 중", "Saving") : L("저장", "Save")}</button>
    </div>
  </Modal>;
}
