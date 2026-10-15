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
  aws: (Binding & { role_arn: string }) | null; gcp: (Binding & { provider: string; service_account: string }) | null;
  azure: (Binding & { tenant: string; client_id: string }) | null; vault: { name: string; scope: string | null; audience: string | null }[];
  processes: Process[]; test: { tokens: Record<string, TokenState>; tested_by?: string; revision?: number; state?: string; safe_error_code?: string } | null;
};

const CLOUDS = ["aws", "gcp", "azure"] as const;
type Cloud = typeof CLOUDS[number];

/** Which clouds the identity reaches, for the integrations card. */
export function machineState(view: MachineView | undefined, L: Say): string {
  if (!view?.configured) return L("설정 안 됨", "Not set up");
  const on = CLOUDS.filter(cloud => view[cloud]?.enabled).map(cloud => ({ aws: "AWS", gcp: "GCP", azure: "Azure" })[cloud]);
  if (view.vault.length) on.push("Vault");
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
  MACHINE_IDENTITY_GCP_PROVIDER_INVALID: ["워크로드 아이덴티티 공급자 이름을 확인하세요(//iam.googleapis.com/projects/번호/…/providers/이름).", "Check the workload identity provider (//iam.googleapis.com/projects/number/…/providers/name)."],
  MACHINE_IDENTITY_GCP_ACCOUNT_INVALID: ["서비스 계정 이메일을 확인하세요.", "Check the service account e-mail."],
  MACHINE_IDENTITY_AZURE_TENANT_INVALID: ["테넌트 ID(GUID)를 확인하세요.", "Check the tenant ID (GUID)."],
  MACHINE_IDENTITY_AZURE_CLIENT_INVALID: ["앱 등록의 클라이언트 ID(GUID)를 확인하세요.", "Check the app registration's client ID (GUID)."],
  MACHINE_IDENTITY_VAULT_NAME_INVALID: ["Vault 토큰 이름은 영문·숫자·-·_로 씁니다.", "Name Vault tokens with letters, digits, - and _."],
  MACHINE_IDENTITY_VAULT_NAME_REPEATED: ["같은 Vault 토큰 이름이 두 번 있습니다.", "A Vault token name is repeated."],
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
  aws: boolean; role_arn: string; gcp: boolean; provider: string; service_account: string;
  azure: boolean; tenant: string; azure_client: string; vault: { name: string; audience: string }[];
};

function formOf(view: MachineView | undefined): Form {
  return {
    token_url: view?.idp?.token_url ?? "", client_id: view?.idp?.client_id ?? "", secret: "",
    auth_method: view?.idp?.auth_method ?? "client_secret_post", token_field: view?.idp?.token_field ?? "access_token",
    scope: view?.idp?.scope ?? "", audience: view?.idp?.audience ?? "",
    aws: Boolean(view?.aws?.enabled), role_arn: view?.aws?.role_arn ?? "",
    gcp: Boolean(view?.gcp?.enabled), provider: view?.gcp?.provider ?? "", service_account: view?.gcp?.service_account ?? "",
    azure: Boolean(view?.azure?.enabled), tenant: view?.azure?.tenant ?? "", azure_client: view?.azure?.client_id ?? "",
    vault: (view?.vault ?? []).map(item => ({ name: item.name, audience: item.audience ?? "" })),
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
    gcp: { enabled: form.gcp, provider: form.provider.trim(), service_account: form.service_account.trim() },
    azure: { enabled: form.azure, tenant: form.tenant.trim(), client_id: form.azure_client.trim() },
    vault: form.vault.filter(item => item.name.trim()).map(item => ({ name: item.name.trim(), audience: blank(item.audience) })),
  };
}

const TITLE: Record<Cloud | "vault", [string, string]> = {
  aws: ["AWS", "AWS"], gcp: ["Google Cloud", "Google Cloud"], azure: ["Microsoft Azure", "Microsoft Azure"], vault: ["Vault·OpenBao", "Vault and OpenBao"],
};

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
  const anyOn = form.aws || form.gcp || form.azure || form.vault.some(item => item.name.trim());
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
  const bindingNames: (Cloud | string)[] = [...CLOUDS.filter(cloud => data[cloud]?.enabled), ...data.vault.map(item => `vault:${item.name}`)];
  const steps: GuideStep[] = Object.entries(setup.data?.steps ?? {}).map(([name, script]) => ({
    key: name, title: name.startsWith("vault:") ? L(`${name.slice(6)} Vault가 이 IdP를 믿게 하기`, `Make the ${name.slice(6)} Vault trust this IdP`)
      : L(`${L(...TITLE[name as Cloud])}가 이 IdP를 믿게 하기`, `Make ${L(...TITLE[name as Cloud])} trust this IdP`),
    text: name === "aws" ? L("IAM OIDC 공급자와 이 IdP를 믿는 역할을 만들고, 멤버 계정 역할을 맡을 권한을 줍니다. 그다음 AWS 연동에서 연결 확인으로 이 신원을 승인합니다.",
      "Create the IAM OIDC provider and a role trusting this IdP, allowed to assume member account roles. Then approve the identity with Test connection in the AWS integration.")
      : name === "gcp" ? L("워크로드 아이덴티티 풀과 이 IdP의 OIDC 공급자를 만들고 서비스 계정 가장 권한을 줍니다.", "Create the workload identity pool and this IdP's OIDC provider, and grant impersonation of the service account.")
        : name === "azure" ? L("앱 등록에 이 IdP 토큰을 믿는 연합 자격증명을 추가합니다.", "Add a federated credential trusting this IdP's token to the app registration.")
          : L(`Vault 연결의 JWT 로그인에서 토큰 파일 이름을 idp-${name.slice(6)}로 둡니다.`, `Set the Vault connection's JWT login token file to idp-${name.slice(6)}.`),
    actions: [{ kind: "copy" as const, label: L("명령 복사", "Copy commands"), text: script }],
  }));

  const cloudCard = (cloud: Cloud, fields: ReactNode) => <div className={cls("mi-cloud", form[cloud] && "on")} key={cloud}>
    <button type="button" className="ig-feat-card" role="checkbox" aria-checked={form[cloud]} onClick={() => set({ [cloud]: !form[cloud] } as Partial<Form>)}>
      <Check on={form[cloud]} /><span className="ig-feat-text"><span className="t">{L(...TITLE[cloud])}</span>
        <span className="d">{({ aws: L("AWS 연동이 이 IdP 토큰으로 IAM 역할을 맡습니다.", "The AWS integrations assume an IAM role with this IdP's token."),
          gcp: L("GCP의 ADC 연동이 워크로드 아이덴티티 연동으로 읽습니다.", "The GCP ADC integrations read through workload identity federation."),
          azure: L("Azure·Entra ID의 워크로드 신원 연동이 앱 등록으로 읽습니다.", "The Azure and Entra ID workload identity integrations read as the app registration.") })[cloud]}</span></span>
      {data[cloud]?.enabled ? <BindingChip view={data} name={cloud} L={L} /> : null}
    </button>
    {form[cloud] ? <div className="mi-fields">{fields}</div> : null}
  </div>;

  return <Modal onClose={onClose} labelledBy="mi-title" className="integ mi" dismissable={!busy}>
    {head}
    <p className="ig-sub mi-intro">{L("CreMore가 AWS·GCP·Azure·Vault에 회사 IdP가 발급한 기계 토큰으로 접근합니다. 클라우드마다 키를 두지 않고, 신원을 사용하는 실행 프로세스가 토큰을 스스로 갱신합니다.",
      "CreMore reaches AWS, GCP, Azure and Vault with a machine token from your company IdP. No key is kept per cloud; the processes using this identity renew their tokens automatically.")}</p>
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
      <p className="ig-hint"><Ic name="info" size={15} /><span>{L("Okta는 사용자 지정 인증 서버의 client credentials 서비스 앱, Keycloak은 서비스 계정을 켠 client, Entra ID는 앱 등록을 씁니다. Entra가 발급한 토큰은 Azure 자신의 연동에는 쓸 수 없습니다.",
        "Okta: a client-credentials service app on a custom authorization server. Keycloak: a client with service accounts. Entra ID: an app registration, whose tokens cannot federate into Azure itself.")}</span></p>
    </div>

    <div className="ig-section">
      <div className="ig-section-head"><h3>{L("이 신원을 믿을 곳", "Where this identity is trusted")}</h3></div>
      <div className="mi-clouds">
        {cloudCard("aws", <TextField label={L("이 IdP를 믿는 IAM 역할 ARN", "IAM role ARN trusting this IdP")} value={form.role_arn} onChange={value => set({ role_arn: value })}
          placeholder="arn:aws:iam::123456789012:role/CreMoreIdp" />)}
        {cloudCard("gcp", <>
          <TextField label={L("워크로드 아이덴티티 공급자", "Workload identity provider")} value={form.provider} onChange={value => set({ provider: value })}
            placeholder="//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/cremore/providers/idp" />
          <TextField label={L("가장할 서비스 계정 (선택)", "Service account to impersonate (optional)")} value={form.service_account}
            onChange={value => set({ service_account: value })} placeholder="cremore-reader@project.iam.gserviceaccount.com" />
        </>)}
        {cloudCard("azure", <div className="row2">
          <TextField label={L("테넌트 ID", "Tenant ID")} value={form.tenant} onChange={value => set({ tenant: value })} />
          <TextField label={L("앱 등록 클라이언트 ID", "App registration client ID")} value={form.azure_client} onChange={value => set({ azure_client: value })} />
        </div>)}
        <div className={cls("mi-cloud", form.vault.length > 0 && "on")}>
          <div className="mi-vault-head"><b>{L(...TITLE.vault)}</b>
            <span className="ig-sub">{L("Vault 연결의 JWT 로그인이 idp-이름 파일로 이 IdP 토큰을 씁니다.", "A Vault connection's JWT login uses this IdP's token from the idp-<name> file.")}</span>
            <button type="button" className="link-btn" onClick={() => set({ vault: [...form.vault, { name: "", audience: "" }] })}><Ic name="plus" size={14} />{L("토큰 추가", "Add a token")}</button></div>
          {form.vault.map((item, index) => <div className="row2 mi-vault-row" key={index}>
            <TextField label={L("이름", "Name")} value={item.name} onChange={value => set({ vault: form.vault.map((row, at) => at === index ? { ...row, name: value } : row) })} placeholder="pay" />
            <TextField label={L("audience (선택)", "Audience (optional)")} value={item.audience} onChange={value => set({ vault: form.vault.map((row, at) => at === index ? { ...row, audience: value } : row) })} />
            <button type="button" className="icon-btn" aria-label={L("이 토큰 빼기", "Remove this token")} onClick={() => set({ vault: form.vault.filter((_, at) => at !== index) })}><Ic name="trash" size={16} /></button>
          </div>)}
          {data.vault.length ? <div className="mi-vault-states">{data.vault.map(item => <span key={item.name} className="ig-sub">idp-{item.name} <BindingChip view={data} name={`vault:${item.name}`} L={L} /></span>)}</div> : null}
        </div>
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
          <b>{name.startsWith("vault:") ? `Vault · ${name.slice(6)}` : L(...TITLE[name as Cloud])}</b>
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
