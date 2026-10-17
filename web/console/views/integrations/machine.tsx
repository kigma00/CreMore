"use client";

/* The installation's machine identity from the organization's IdP, in the design's integration window:
 * the IdP app, the clouds that trust its tokens, what each API and worker process holds now, a token
 * fetched on demand (its non-secret claims only) and the commands that make each cloud trust it.
 * The client secret is sent once and never shown again (cremore/identity/machine.py). */

import { type ReactNode, useEffect, useState } from "react";

import { reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { Modal, useToast } from "@/console/layer";
import { rel, type Say, useL } from "@/console/text";
import { useLocale } from "@/components/locale";
import { Banner, Check, cls, Loading, SelectField, StateChip, TextField } from "@/console/ui";
import { type GuideStep, SetupGuide } from "@/console/views/integrations/guide";

export const MACHINE_PATH = "settings/machine-identity";

type Idp = { token_url: string; client_id: string; auth_method: string; token_field: string; scope: string | null; audience: string | null };
type Binding = { enabled: boolean; scope: string | null; audience: string | null };
type TokenState = { state: "READY" | "FAILED" | "PENDING"; code: string | null; expires_in?: number; claims?: { iss?: string; sub?: string; aud?: string | string[] } };
type Process = { process: string; revision: number | null; error: string | null; tokens: Record<string, TokenState>; reported_at?: string };
export type MachineView = {
  configured: boolean; revision: number; secret_saved: boolean; idp: Idp | null;
  aws: (Binding & { role_arn: string }) | null;
  processes: Process[]; test: { tokens: Record<string, TokenState>; tested_by?: string; revision?: number; state?: string; safe_error_code?: string } | null;
};

const CLOUDS = ["aws"] as const;
type Cloud = typeof CLOUDS[number];

/** Which clouds the identity reaches, for the integrations card. */
export function machineState(view: MachineView | undefined, L: Say): string {
  if (!view?.configured) return L("설정 안 됨", "Not set up");
  const on = CLOUDS.filter(cloud => view[cloud]?.enabled).map(() => "AWS");
  return on.length ? on.join(" · ") : L("꺼짐", "Off");
}

/** A process reports under "api:<host>" or "worker:<id>"; the screen names the kind. */
export function processName(name: string, L: Say) {
  return name.startsWith("api:") ? L("API", "API") : name.startsWith("worker:") ? L("워커", "Worker") : name;
}

/** The state of one binding across the processes that reported in the last day. */
export function bindingState(view: MachineView, name: string, now = Date.now()) {
  const recent = view.processes.filter(item => !item.reported_at || now - Date.parse(item.reported_at) < 86_400_000);
  const states = recent.map(item => ({ process: item.process, token: item.tokens[name] })).filter(item => item.token);
  if (!states.length) return { tone: "none" as const, states };
  if (states.some(item => item.token.state === "FAILED")) return { tone: "bad" as const, states };
  if (states.every(item => item.token.state === "READY")) return { tone: "ok" as const, states };
  return { tone: "running" as const, states };
}

const CODE: Record<string, [string, string]> = {
  MACHINE_IDENTITY_SECRET_REQUIRED: ["클라이언트 비밀을 입력하세요.", "Enter the client secret."],
  MACHINE_IDENTITY_TOKEN_URL_INVALID: ["토큰 URL은 https 주소여야 합니다.", "The token URL must be an https address."],
  MACHINE_IDENTITY_CLIENT_ID_INVALID: ["클라이언트 ID를 확인하세요.", "Check the client ID."],
  MACHINE_IDENTITY_AWS_ROLE_ARN_INVALID: ["IAM 역할 ARN을 확인하세요(arn:aws:iam::계정:role/이름).", "Check the IAM role ARN (arn:aws:iam::account:role/name)."],
  MACHINE_IDENTITY_SCOPE_INVALID: ["scope를 확인하세요.", "Check the scope."],
  MACHINE_IDENTITY_AUDIENCE_INVALID: ["audience를 확인하세요.", "Check the audience."],
  MACHINE_IDENTITY_CHANGED: ["다른 관리자가 먼저 저장했습니다. 다시 열어 주세요.", "Another admin saved first. Open it again."],
  MACHINE_IDENTITY_NOT_CONFIGURED: ["먼저 IdP 앱과 믿을 곳을 저장하세요.", "Save the IdP app and where it is trusted first."],
  OAUTH_TOKEN_REQUEST_FAILED: ["IdP가 토큰을 주지 않았습니다. 클라이언트 ID·비밀·scope를 확인하세요.", "The IdP gave no token. Check the client ID, secret and scope."],
  OAUTH_CLIENT_SECRET_UNAVAILABLE: ["저장한 클라이언트 비밀을 열 수 없습니다.", "The saved client secret cannot be opened."],
};

export function codeText(code: string | null | undefined, L: Say) {
  if (!code) return "";
  const known = CODE[code.split(":", 1)[0]];
  return known ? L(known[0], known[1]) : code;
}

type Form = {
  token_url: string; client_id: string; secret: string; auth_method: string; token_field: string; scope: string; audience: string;
  aws: boolean; role_arn: string;
};

function formOf(view: MachineView | undefined): Form {
  return {
    token_url: view?.idp?.token_url ?? "", client_id: view?.idp?.client_id ?? "", secret: "",
    auth_method: view?.idp?.auth_method ?? "client_secret_post", token_field: view?.idp?.token_field ?? "access_token",
    scope: view?.idp?.scope ?? "", audience: view?.idp?.audience ?? "",
    aws: Boolean(view?.aws?.enabled), role_arn: view?.aws?.role_arn ?? "",
  };
}

/** The body a save sends; an empty secret keeps the saved one. */
export function machineBody(form: Form, revision: number) {
  const blank = (value: string) => value.trim() || null;
  return {
    expected_revision: revision,
    idp: { token_url: form.token_url.trim(), client_id: form.client_id.trim(), auth_method: form.auth_method, token_field: form.token_field,
      scope: blank(form.scope), audience: blank(form.audience) },
    client_secret: form.secret.trim() || null,
    aws: { enabled: form.aws, role_arn: form.role_arn.trim() },
  };
}

const TITLE: Record<Cloud, [string, string]> = { aws: ["AWS", "AWS"] };

export function MachineIdentityModal({ onClose }: { onClose: () => void }) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const view = useApi<MachineView>(MACHINE_PATH, { every: 15_000 });
  const setup = useApi<{ steps: Record<string, string> }>(view.data?.configured ? `${MACHINE_PATH}/setup` : null);
  const [form, setForm] = useState<Form | null>(null);
  const [formRevision, setFormRevision] = useState<number | null>(null);
  const [busy, setBusy] = useState<"" | "save" | "test">("");
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { if (view.data && !form) { setForm(formOf(view.data)); setFormRevision(view.data.revision); } }, [view.data, form]);
  const copy = (text: string) => navigator.clipboard?.writeText(text).then(() => toast(L("복사했습니다", "Copied")), () => toast(L("복사하지 못했습니다", "Could not copy"), "bad"));

  const head = <h2 id="mi-title"><span className="ig-cm"><Ic name="shield" size={18} /></span>{L("기계 신원", "Machine identity")} <small>{L("회사 IdP", "Company IdP")}</small></h2>;
  if (!view.data || !form) {
    return <Modal onClose={onClose} labelledBy="mi-title" className="integ mi">
      {head}{view.error ? <Banner tone="bad" icon="alert">{reasonText(view.error, L)}</Banner> : <Loading />}
      <div className="modal-foot"><button type="button" className="ghost-btn" onClick={onClose}>{L("닫기", "Close")}</button></div>
    </Modal>;
  }
  const data = view.data;
  const set = (change: Partial<Form>) => setForm(current => current ? { ...current, ...change } : current);
  const anyOn = form.aws;
  const needsSecret = anyOn && !data.secret_saved && !form.secret.trim();

  async function save() {
    setBusy("save"); setError(null);
    try {
      const next = await send<MachineView>(MACHINE_PATH, "PUT", machineBody(form!, formRevision!));
      view.replace(next); setForm(formOf(next)); setFormRevision(next.revision); saved(); setup.reload();
      toast(L("기계 신원을 저장했습니다. 수집 프로세스가 새 토큰을 자동으로 받습니다.", "Machine identity saved. The collection process fetches fresh tokens automatically."));
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "";
      setError(codeText(message, L) || reasonText(reason, L));
    } finally { setBusy(""); }
  }

  async function test() {
    setBusy("test"); setError(null);
    try {
      const next = await send<MachineView>(`${MACHINE_PATH}/test`, "POST");
      view.replace(next); setup.reload();
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "";
      setError(codeText(message, L) || reasonText(reason, L));
    } finally { setBusy(""); }
  }

  const tested = data.test?.tokens ?? {};
  const testQueued = data.test?.state === "QUEUED" && data.test.revision === data.revision;
  const bindingNames: Cloud[] = CLOUDS.filter(cloud => data[cloud]?.enabled);
  const steps: GuideStep[] = Object.entries(setup.data?.steps ?? {}).map(([name, script]) => ({
    key: name, title: L("AWS가 이 IdP를 믿게 하기", "Make AWS trust this IdP"),
    text: L("IAM OIDC 공급자와 이 IdP를 믿는 역할을 만들고, AWS 연결 확인으로 신원을 승인합니다.", "Create the IAM OIDC provider and a role trusting this IdP, then approve it with the AWS connection test."),
    actions: [{ kind: "copy" as const, label: L("명령 복사", "Copy commands"), text: script }],
  }));

  const cloudCard = (cloud: Cloud, fields: ReactNode) => <div className={cls("mi-cloud", form[cloud] && "on")} key={cloud}>
    <button type="button" className="ig-feat-card" role="checkbox" aria-checked={form[cloud]} onClick={() => set({ [cloud]: !form[cloud] } as Partial<Form>)}>
      <Check on={form[cloud]} /><span className="ig-feat-text"><span className="t">{L(...TITLE[cloud])}</span>
        <span className="d">{L("AWS 연동이 이 IdP 토큰으로 IAM 역할을 맡습니다.", "The AWS integration assumes an IAM role with this IdP token.")}</span></span>
      {data[cloud]?.enabled ? <BindingChip view={data} name={cloud} L={L} /> : null}
    </button>
    {form[cloud] ? <div className="mi-fields">{fields}</div> : null}
  </div>;

  return <Modal onClose={onClose} labelledBy="mi-title" className="integ mi" dismissable={!busy}>
    {head}
    <p className="ig-sub mi-intro">{L("CreMore가 회사 IdP의 기계 토큰으로 AWS에 접근합니다. 실행 프로세스가 토큰을 갱신합니다.",
      "CreMore reaches AWS with a machine token from your company IdP. Runtime processes renew the token automatically.")}</p>
    {error ? <Banner tone="bad" icon="alert" onClose={() => setError(null)}>{error}</Banner> : null}
    {formRevision !== data.revision ? <Banner tone="warn" icon="alert">{L("설정이 변경됐습니다. 입력은 유지했습니다. 최신 내용을 확인하고 다시 적용하세요.", "The settings changed. Your input is kept. Review the latest version and apply again.")}
      <button type="button" className="link-btn" onClick={() => { setForm(formOf(data)); setFormRevision(data.revision); }}>{L("최신 내용으로 다시 불러오기", "Reload the latest version")}</button></Banner> : null}

    <div className="ig-section">
      <div className="ig-section-head"><h3>{L("IdP 앱", "IdP app")}</h3></div>
      <div className="row2 ig-fields">
        <TextField label={L("토큰 URL", "Token URL")} value={form.token_url} onChange={value => set({ token_url: value })} placeholder="https://acme.okta.com/oauth2/aus.../v1/token" />
        <TextField label={L("클라이언트 ID", "Client ID")} value={form.client_id} onChange={value => set({ client_id: value })} />
        <TextField label={L("클라이언트 비밀", "Client secret")} value={form.secret} masked onChange={value => set({ secret: value })}
          placeholder={data.secret_saved ? L("저장된 값 유지 · 바꿀 때만 입력", "Keep the saved value · enter only to replace") : L("여기에 붙여 넣기", "Paste here")} />
        <SelectField label={L("클라이언트 인증", "Client authentication")} value={form.auth_method} onChange={value => set({ auth_method: value })}
          options={[{ id: "client_secret_post", label: "client_secret_post" }, { id: "client_secret_basic", label: "client_secret_basic" }]} />
        <TextField label={L("scope (선택)", "Scope (optional)")} value={form.scope} onChange={value => set({ scope: value })} placeholder="cremore.workload" />
        <TextField label={L("audience (선택)", "Audience (optional)")} value={form.audience} onChange={value => set({ audience: value })} placeholder="api://cremore" />
        <SelectField label={L("쓸 토큰", "Token to use")} value={form.token_field} onChange={value => set({ token_field: value })}
          options={[{ id: "access_token", label: "access_token" }, { id: "id_token", label: "id_token" }]} />
      </div>
      <p className="ig-hint"><Ic name="info" size={15} /><span>{L("회사 IdP에서 client credentials 앱을 등록하고 AWS 역할이 해당 IdP를 신뢰하도록 설정합니다.",
        "Register a client credentials app in your IdP and configure the AWS role to trust it.")}</span></p>
    </div>

    <div className="ig-section">
      <div className="ig-section-head"><h3>{L("이 신원을 믿을 곳", "Where this identity is trusted")}</h3></div>
      <div className="mi-clouds">
        {cloudCard("aws", <TextField label={L("이 IdP를 믿는 IAM 역할 ARN", "IAM role ARN trusting this IdP")} value={form.role_arn} onChange={value => set({ role_arn: value })}
          placeholder="arn:aws:iam::123456789012:role/CreMoreIdp" />)}
      </div>
    </div>

    {bindingNames.length ? <div className="ig-section">
      <div className="ig-section-head"><h3>{L("지금 받은 토큰", "Tokens now")}</h3>
        <button type="button" className="link-btn ig-all" disabled={Boolean(busy) || testQueued} onClick={() => void test()}><Ic name="bolt" size={14} />{busy === "test" || testQueued ? L("수집 프로세스 확인 중", "Checking collection process") : L("토큰 받아 보기", "Fetch a token now")}</button></div>
      {data.test?.state === "FAILED" ? <Banner tone="bad" icon="alert">{L("토큰 확인에 실패했습니다. 수집 프로세스의 신원 설정을 확인하세요.", "Token check failed. Review the collection process identity configuration.")}</Banner> : null}
      <div className="mi-tokens">{bindingNames.map(name => {
        const now = tested[name];
        const aud = now?.claims?.aud;
        return <div className="mi-token" key={name}>
          <b>{L(...TITLE[name])}</b>
          <BindingChip view={data} name={name} L={L} />
          {now ? now.state === "READY" ? <span className="ig-sub">{L("받아 봄", "Fetched")} · iss <span className="mono">{now.claims?.iss ?? "—"}</span> · sub <span className="mono">{now.claims?.sub ?? "—"}</span>
            {aud ? <> · aud <span className="mono">{Array.isArray(aud) ? aud.join(", ") : aud}</span></> : null}
            {now.expires_in ? L(` · ${Math.round(now.expires_in / 60)}분 유효`, ` · valid ${Math.round(now.expires_in / 60)} min`) : null}</span>
            : <span className="ig-result bad"><Ic name="alert" size={15} />{codeText(now.code, L)}</span> : null}
        </div>;
      })}</div>
      {data.processes.length ? <p className="ig-sub mi-processes">{data.processes.map(item => `${processName(item.process, L)} ${item.reported_at ? rel(item.reported_at, locale) : ""}`).join(" · ")}</p> : null}
    </div> : null}

    <SetupGuide steps={steps} onCopy={copy} />

    <div className="modal-foot">
      <span className="note">{L("클라이언트 비밀은 암호화해 저장하고 다시 보여 주지 않습니다.", "The client secret is stored encrypted and never shown again.")}</span>
      <button type="button" className="ghost-btn" disabled={Boolean(busy)} onClick={onClose}>{L("닫기", "Close")}</button>
      <button type="button" className="primary-btn" disabled={Boolean(busy) || !form.token_url.trim() || !form.client_id.trim() || needsSecret}
        data-tip={needsSecret ? L("클라이언트 비밀을 입력하세요.", "Enter the client secret.") : undefined} onClick={() => void save()}>
        {busy === "save" ? L("저장 중", "Saving") : L("저장", "Save")}</button>
    </div>
  </Modal>;
}

function BindingChip({ view, name, L }: { view: MachineView; name: string; L: Say }) {
  const state = bindingState(view, name);
  const tip = state.states.map(item => `${processName(item.process, L)}: ${item.token.state}${item.token.code ? ` · ${codeText(item.token.code, L)}` : ""}`).join(" / ");
  if (state.tone === "none") return <StateChip tip={L("실행 프로세스가 아직 이 토큰을 보고하지 않았습니다", "No runtime process has reported this token yet")}>{L("대기", "Waiting")}</StateChip>;
  if (state.tone === "bad") return <StateChip tone="bad" tip={tip}>{L("받지 못함", "Not fetched")}</StateChip>;
  if (state.tone === "ok") return <StateChip tone="ok" tip={tip}>{L("사용 중", "In use")}</StateChip>;
  return <StateChip tone="running" tip={tip}>{L("받는 중", "Fetching")}</StateChip>;
}
