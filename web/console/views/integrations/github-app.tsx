"use client";

/* A GitHub App made from a manifest (cremore.onboarding.github_app). The wizard posts the manifest the API
 * wrote to GitHub's "new GitHub App" page of the organization; GitHub sends the admin back here with a code the
 * API exchanges (the App's key goes from GitHub to CreMore, never through this browser); the admin installs the
 * App on the organization and comes back here again; the API finds that installation with the App's own JWT and
 * makes the connection, which the wizard then shows at its access check. The flow is bound to this tab
 * (sessionStorage) and to a key only it holds. */

import { useEffect, useRef, useState } from "react";

import { type Locale, LocaleContext } from "@/components/locale";
import { Ic } from "@/console/icons";
import { type Say, useL } from "@/console/text";
import type { CollectionEntry } from "@/console/views/integrations/model";
import { api, DashboardAPIError } from "@/lib/dashboard-api";

export const GITHUB_APP_STORAGE = "cremore.github.app.pending";
// Where GitHub sends the admin back: after the App is made (with a code) and after it is installed.
export const RETURN_PATH = "/github/app";

type Pending = { session_id: string; state: string; browser_key: string; expires_at: string; install_url?: string; onboarding?: boolean; entry?: CollectionEntry };
type Started = { session_id: string; state: string; expires_at: string; form_url: string; manifest: Record<string, unknown> };
/** `entry` is the console card the flow began from; it stays in this tab and is not sent to the API. */
export type AppRequest = { provider_connection_id?: string; edition: string; purposes?: string[]; target: Record<string, unknown>; name?: string;
  onboarding?: boolean; installation_purposes?: string[]; entry?: CollectionEntry };

export function pendingApp(): Pending | null {
  try {
    const value = JSON.parse(sessionStorage.getItem(GITHUB_APP_STORAGE) || "null");
    if (value && typeof value.session_id === "string" && typeof value.state === "string" && typeof value.browser_key === "string"
      && Date.parse(value.expires_at) > Date.now()) {
      // Only the two console cards go back into the address; anything else in the store is dropped.
      if (value.entry !== "exposure" && value.entry !== "account") delete value.entry;
      return value;
    }
  } catch { /* An unavailable browser store means starting this flow again. */ }
  return null;
}

/** Whether the browser store now holds exactly `value` (or nothing): the flow cannot come back without it. */
function remember(value: Pending | null) {
  try {
    if (value) sessionStorage.setItem(GITHUB_APP_STORAGE, JSON.stringify(value));
    else sessionStorage.removeItem(GITHUB_APP_STORAGE);
    return sessionStorage.getItem(GITHUB_APP_STORAGE) === (value ? JSON.stringify(value) : null);
  } catch {
    return false;
  }
}

// What dashboard-api reads a body that is not JSON as: a sign-in page the proxy answered instead of the API.
const NOT_JSON = "Invalid server response";

async function post<T>(path: string, body: Record<string, unknown>): Promise<T> {
  const data = await api<T & { error?: unknown }>(path, { method: "POST", body: JSON.stringify(body) });
  // A 200 page (a sign-in redirect the browser followed) is not the API's answer.
  if (data?.error === NOT_JSON) throw new DashboardAPIError("GITHUB_APP_SIGN_IN_EXPIRED", 401);
  return data;
}

function browserKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The manifest as GitHub takes it: what the API wrote, with this CreMore's own address to come back to (the
 * App asks for no webhook; GitHub requires an address all the same). */
export function manifestFor(manifest: Record<string, unknown>, origin: string) {
  const back = `${origin}${RETURN_PATH}`;
  return { ...manifest, url: origin, redirect_url: back, setup_url: back, hook_attributes: { url: back, active: false } };
}

/** Whether the page the manifest is posted to is the "new App" page of an organization on the GitHub the
 * connection names (github.com, or its GHE.com or Enterprise Server host). */
export function trustedForm(formUrl: string, host?: unknown) {
  try {
    const url = new URL(formUrl);
    const raw = typeof host === "string" ? host.trim() : "";
    const input = new URL(raw ? (raw.includes("://") ? raw : `https://${raw}`) : "https://github.com");
    if (input.protocol !== "https:" || input.port || input.username || input.password || input.pathname !== "/" || input.search || input.hash) return false;
    const expected = ["github.com", "api.github.com", "www.github.com"].includes(input.hostname) ? "github.com"
      : input.hostname.startsWith("api.") && input.hostname.endsWith(".ghe.com") ? input.hostname.slice(4) : input.hostname;
    return url.protocol === "https:" && url.hostname === expected && !url.port && !url.username && !url.password
      && /^\/organizations\/[A-Za-z0-9-]{1,39}\/settings\/apps\/new$/.test(url.pathname);
  } catch {
    return false;
  }
}

/** Leave for GitHub with the manifest; the page comes back to RETURN_PATH. Nothing leaves this page unless the
 * page is GitHub's own and the flow is held in this tab's store. */
export async function startGitHubApp({ entry, ...request }: AppRequest): Promise<void> {
  const key = browserKey();
  const started = await post<Started>("github/app-manifest/start", { browser_key: key, ...request });
  const refused = !trustedForm(started.form_url, request.target.host) ? "GITHUB_APP_RESPONSE_INVALID"
    : !remember({ session_id: started.session_id, state: started.state, browser_key: key, expires_at: started.expires_at, ...(request.onboarding ? { onboarding: true } : {}),
      ...(entry === "exposure" || entry === "account" ? { entry } : {}) })
      ? "GITHUB_APP_STORAGE_UNAVAILABLE" : null;
  if (refused) {
    // Told, not waited for: the refusal shows at once, and keepalive lets the cancel finish if the reader leaves.
    // Best effort: the API drops an unfinished flow at its TTL all the same.
    void api("github/app-manifest/cancel", { method: "POST", body: JSON.stringify({ session_id: started.session_id, browser_key: key }), keepalive: true }).catch(() => {});
    throw new DashboardAPIError(refused, refused === "GITHUB_APP_RESPONSE_INVALID" ? 502 : 409);
  }
  const form = document.createElement("form");
  form.method = "post";
  form.action = started.form_url;
  const input = document.createElement("input");
  input.type = "hidden";
  input.name = "manifest";
  input.value = JSON.stringify(manifestFor(started.manifest, window.location.origin));
  form.append(input);
  document.body.append(form);
  form.submit();
}

const CODES: Record<string, [string, string]> = {
  GITHUB_APP_SESSION_EXPIRED: ["이 흐름이 만료됐거나 다른 브라우저에서 시작됐습니다. 연동 화면에서 다시 시작하세요.", "This flow expired or began in another browser. Start again from the integrations screen."],
  GITHUB_APP_SESSION_STAGE: ["이미 처리한 단계입니다. 연동 화면에서 상태를 확인하세요.", "This step was already done. Check the integration on the integrations screen."],
  GITHUB_APP_STATE_INVALID: ["GitHub에서 돌아온 요청이 이 흐름의 것이 아닙니다. 다시 시작하세요.", "The request back from GitHub does not belong to this flow. Start again."],
  GITHUB_MANIFEST_CODE_EXPIRED: ["GitHub의 코드가 만료됐거나 이미 쓰였습니다(1시간). 다시 시작하세요.", "GitHub's code expired or was already used (one hour). Start again."],
  GITHUB_MANIFEST_REFUSED: ["GitHub가 App 만들기를 거절했습니다. 조직 소유자 계정인지 확인하세요.", "GitHub refused to make the App. Check that you are an organization owner."],
  GITHUB_APP_CREATED_ON_ANOTHER_ACCOUNT: ["App이 연동할 조직이 아닌 다른 계정에 만들어졌습니다.", "The App was made on another account than the organization to connect."],
  GITHUB_APP_NOT_INSTALLED: ["아직 조직에 설치되지 않았습니다. 설치를 마친 뒤 다시 확인하세요.", "The App is not installed on the organization yet. Install it, then check again."],
  GITHUB_APP_UNAVAILABLE: ["GitHub에 연결하지 못했습니다. 잠시 뒤 다시 시도하세요.", "GitHub could not be reached. Try again shortly."],
  GITHUB_APP_REJECTED: ["GitHub가 App의 키를 받아들이지 않았습니다.", "GitHub did not accept the App's key."],
  GITHUB_APP_SIGN_IN_EXPIRED: ["CreMore 로그인이 만료됐습니다. 다시 로그인한 뒤 연동 화면에서 다시 시작하세요.", "Your CreMore sign-in expired. Sign in again, then start again from the integrations screen."],
  GITHUB_APP_STORAGE_UNAVAILABLE: ["이 브라우저가 탭 저장소(sessionStorage)를 막고 있어 GitHub에서 돌아올 수 없습니다. 저장소를 허용하거나 일반 창에서 다시 시작하세요.",
    "This browser blocks tab storage (sessionStorage), so the flow cannot come back from GitHub. Allow it or use a regular window, then start again."],
  GITHUB_APP_RESPONSE_INVALID: ["CreMore 서버의 응답이 예상과 달라 GitHub로 이동하지 않았습니다. 다시 시작하세요.", "CreMore's answer was not as expected, so nothing was sent to GitHub. Start again."],
  GITHUB_APP_REQUEST_INVALID: ["App 연동 요청이 올바르지 않습니다. 연동 화면에서 다시 시작하세요.", "The App request is not valid. Start again from the integrations screen."],
  GITHUB_APP_BROWSER_KEY_INVALID: ["이 브라우저가 흐름을 묶을 키를 만들지 못했습니다. 페이지를 새로 고친 뒤 다시 시작하세요.", "This browser could not make the key that binds the flow. Reload the page, then start again."],
  GITHUB_ORGANIZATION_INVALID: ["GitHub 조직 이름이 올바르지 않습니다. 조직의 로그인 이름(영문·숫자·하이픈)을 넣으세요.", "The GitHub organization name is not valid. Enter its login (letters, digits and hyphens)."],
  EDITION_UNKNOWN: ["이 설치가 모르는 GitHub 제품입니다. 연동 화면에서 제품을 다시 고르세요.", "This installation does not know that GitHub product. Choose the product again on the integrations screen."],
};

export function appErrorText(code: string, L: Say) {
  const known = CODES[code];
  return known ? L(known[0], known[1]) : L(`App 연동을 마치지 못했습니다. (${code})`, `The App could not be connected. (${code})`);
}

export function codeOf(error: unknown) {
  // The proxy's sign-in page (HTML) or a refused session instead of the API's answer: the sign-in ran out on the way.
  if (error instanceof DashboardAPIError && (error.status === 401 || (error.message === NOT_JSON && error.status < 500))) return "GITHUB_APP_SIGN_IN_EXPIRED";
  const message = error instanceof Error ? error.message : "";
  const code = message.split(/[\s:]/, 1)[0];
  return /^[A-Z][A-Z0-9_]{2,100}$/.test(code) ? code : "GITHUB_APP_UNAVAILABLE";
}

type Phase = { kind: "working"; step: "start" | "convert" | "complete" } | { kind: "install"; url: string } | { kind: "error"; code: string; install?: string };

/** The page GitHub sends the admin back to: after the App is made (a code) and after it is installed. */
export function GitHubAppReturn() {
  const L = useL();
  const once = useRef(false);
  const [phase, setPhase] = useState<Phase>({ kind: "working", step: "start" });

  async function complete(flow: Pending) {
    setPhase({ kind: "working", step: "complete" });
    try {
      const done = await post<{ provider_connection_id?: string; onboarding_session_id?: string }>("github/app-manifest/complete",
        { session_id: flow.session_id, browser_key: flow.browser_key });
      if (flow.onboarding) {
        if (!done.onboarding_session_id || !/^[0-9a-f-]{36}$/i.test(done.onboarding_session_id)) throw Error("GITHUB_APP_RESPONSE_INVALID");
        // Only the binding and draft reference pass through the browser. The API owns the App key.
        sessionStorage.setItem("cremore:onboarding:github:new", JSON.stringify({ id: done.onboarding_session_id, key: flow.browser_key }));
        remember(null);
        window.location.replace(`/?view=sources&connect=github${flow.entry === "exposure" ? "&entry=exposure" : ""}`);
        return;
      }
      if (!done.provider_connection_id || !/^[0-9a-f-]{36}$/i.test(done.provider_connection_id)) throw Error("GITHUB_APP_RESPONSE_INVALID");
      remember(null);
      window.location.replace(`/?view=sources&edit=${encodeURIComponent(done.provider_connection_id)}&step=2${flow.entry ? `&entry=${encodeURIComponent(flow.entry)}` : ""}`);
    } catch (failure) {
      const code = codeOf(failure);
      setPhase(code === "GITHUB_APP_NOT_INSTALLED" && flow.install_url ? { kind: "install", url: flow.install_url } : { kind: "error", code, install: flow.install_url });
    }
  }

  useEffect(() => {
    if (once.current) return;
    once.current = true;
    const query = new URLSearchParams(window.location.search);
    window.history.replaceState(null, "", RETURN_PATH);
    const flow = pendingApp();
    if (!flow) { setPhase({ kind: "error", code: "GITHUB_APP_SESSION_EXPIRED" }); return; }
    const code = query.get("code");
    if (!code) { void complete(flow); return; }
    if (query.get("state") !== flow.state) { setPhase({ kind: "error", code: "GITHUB_APP_STATE_INVALID" }); return; }
    setPhase({ kind: "working", step: "convert" });
    post<{ install_url?: unknown }>("github/app-manifest/convert", { session_id: flow.session_id, browser_key: flow.browser_key, state: flow.state, code })
      .then(made => {
        if (typeof made.install_url !== "string" || !made.install_url.startsWith("https://")) throw Error("GITHUB_APP_RESPONSE_INVALID");
        remember({ ...flow, install_url: made.install_url });
        window.location.assign(made.install_url); // install on the organization; GitHub comes back here
      })
      .catch(failure => setPhase({ kind: "error", code: codeOf(failure) }));
  // Read once per visit; the locale does not restart a flow.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const flow = typeof window === "undefined" ? null : pendingApp();
  return <main className="gh-return">
    <div className="gh-return-card" role="status">
      <span className="gh-return-ic"><Ic name={phase.kind === "error" ? "alert" : "key"} size={20} /></span>
      <h1>{L("GitHub App 연동", "GitHub App connection")}</h1>
      {phase.kind === "working" ? <p className="gh-return-line"><span className="spinner" aria-hidden="true" />{{
        start: L("처리하고 있습니다", "Working"), convert: L("GitHub가 만든 App을 받고 있습니다", "Receiving the App GitHub made"),
        complete: L("조직에 설치된 App을 확인하고 있습니다", "Checking the App's installation on the organization") }[phase.step]}</p> : null}
      {phase.kind === "install" ? <>
        <p>{L("App을 만들었습니다. 조직에 설치를 마친 뒤 다시 확인하세요.", "The App is made. Install it on the organization, then check again.")}</p>
        <div className="gh-return-acts">
          <a className="primary-btn" href={phase.url}><Ic name="ext" size={15} />{L("조직에 설치", "Install on the organization")}</a>
          {flow ? <button type="button" className="ghost-btn" onClick={() => void complete(flow)}><Ic name="refresh" size={15} />{L("설치 확인", "Check the installation")}</button> : null}
        </div>
      </> : null}
      {phase.kind === "error" ? <>
        <p className="gh-return-bad">{appErrorText(phase.code, L)}</p>
        <div className="gh-return-acts">
          {phase.install ? <a className="ghost-btn" href={phase.install}><Ic name="ext" size={15} />{L("조직에 설치", "Install on the organization")}</a> : null}
          {flow?.install_url && phase.code !== "GITHUB_APP_SESSION_EXPIRED" && phase.code !== "GITHUB_APP_SIGN_IN_EXPIRED"
            ? <button type="button" className="ghost-btn" onClick={() => void complete(flow)}><Ic name="refresh" size={15} />{L("설치 결과 다시 확인", "Check installation again")}</button> : null}
          {phase.code === "GITHUB_APP_SIGN_IN_EXPIRED"
            ? <a className="primary-btn" href="/?view=sources"><Ic name="key" size={15} />{L("다시 로그인", "Sign in again")}</a>
            : <a className="ghost-btn" href="/?view=sources"><Ic name="left" size={15} />{L("연동 화면으로", "Back to integrations")}</a>}
        </div>
      </> : null}
    </div>
  </main>;
}

/** The return page in the reader's saved language (the console's own setting). */
export function GitHubAppPage() {
  const [locale, setLocale] = useState<Locale>("ko");
  useEffect(() => {
    try {
      const saved = window.localStorage.getItem("cremore.locale");
      if (saved === "ko" || saved === "en") setLocale(saved);
    } catch { /* the default language stays */ }
  }, []);
  return <LocaleContext.Provider value={locale}><GitHubAppReturn /></LocaleContext.Provider>;
}
