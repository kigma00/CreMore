/* A Google sign-in for a GCP provider connection, as the browser keeps it while it is away at Google.
 *
 * The browser key binds the server's session to this browser; the state proves the callback belongs to
 * it. Both stay in sessionStorage (this tab only) until the flow completes or is abandoned. Tokens
 * never reach the browser: the callback hands the authorization code to the API. */

import { api } from "@/lib/dashboard-api";

export const STORAGE = "cremore.gcp.oauth.pending";
export type Session = { session_id: string; state: string; browser_key: string; expires_at: string; locale: "ko" | "en"; onboarding_id?: string };

// The integrations screen a Google approval returns to; it finishes the flow from ?gcp_oauth=.
export const CONSOLE_RETURN = "/?view=sources";

export function pending(): Session | null {
  try {
    const value = JSON.parse(sessionStorage.getItem(STORAGE) || "null");
    if (value && typeof value.session_id === "string" && typeof value.state === "string"
      && typeof value.browser_key === "string" && Date.parse(value.expires_at) > Date.now()) return value;
  } catch { /* An unavailable browser store requires restarting this flow. */ }
  return null;
}

export function binding(session: Session) { return { session_id: session.session_id, browser_key: session.browser_key }; }

export function errorCode(error: unknown) {
  const message = error instanceof Error ? error.message : "";
  const code = message.split(":", 1)[0].trim();
  return /^[A-Z][A-Z0-9_]{2,100}$/.test(code) ? code : "GCP_OAUTH_REQUEST_FAILED";
}

function browserKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Leave for Google to approve read access for one provider connection (auth method google_oauth). */
export async function startSignIn(connectionId: string, locale: "ko" | "en", draftKey?: string): Promise<void> {
  const key = draftKey ?? browserKey();
  const result = await api<{ session_id: string; state: string; expires_at: string; authorization_url: string }>("v2/gcp/oauth/start", {
    method: "POST", body: JSON.stringify({ browser_key: key, connection_id: connectionId, connection_kind: draftKey ? "onboarding" : "provider" }),
  });
  const url = new URL(result.authorization_url);
  if (url.origin !== "https://accounts.google.com" || url.pathname !== "/o/oauth2/v2/auth") throw Error("GCP_OAUTH_RESPONSE_INVALID");
  const session: Session = { session_id: result.session_id, state: result.state, expires_at: result.expires_at,
    browser_key: key, locale, ...(draftKey ? { onboarding_id: connectionId } : {}) };
  sessionStorage.setItem(STORAGE, JSON.stringify(session));
  window.location.assign(url.href);
}

/** At the callback, back from Google: hand the authorization code to the API once, then return to the
 * integrations screen, which completes the flow. Returns the error code when it cannot. */
export async function finishSignIn(query: URLSearchParams): Promise<string | null> {
  const session = pending();
  if (!session || query.get("state") !== session.state) return "GCP_OAUTH_STATE_INVALID";
  if (query.has("error") || !query.get("code")) {
    // Told, not waited for: a slow answer does not hold the page on its spinner, and keepalive lets it finish if the
    // reader leaves at once.
    void api("v2/gcp/oauth/cancel", { method: "POST", body: JSON.stringify(binding(session)), keepalive: true }).catch(() => {});
    sessionStorage.removeItem(STORAGE);
    return "GCP_OAUTH_CONSENT_CANCELLED";
  }
  try {
    await api("v2/gcp/oauth/finish", { method: "POST", body: JSON.stringify({ ...binding(session), state: session.state, code: query.get("code") }) });
  } catch (failure) {
    sessionStorage.removeItem(STORAGE);
    return errorCode(failure);
  }
  window.location.replace(`${CONSOLE_RETURN}&gcp_oauth=${encodeURIComponent(session.session_id)}`);
  return null;
}

/** Back from Google: attach the approval to its connection, which then checks its access again.
 * Returns the provider connection's id. */
export async function completeSignIn(sessionId: string): Promise<string> {
  const result = await complete(sessionId);
  if (!result.provider_connection_id) throw Error("GCP_OAUTH_RESPONSE_INVALID");
  return result.provider_connection_id;
}

export async function completeDraftSignIn(sessionId: string): Promise<string> {
  const result = await complete(sessionId);
  if (!result.onboarding_session_id) throw Error("GCP_OAUTH_RESPONSE_INVALID");
  return result.onboarding_session_id;
}

async function complete(sessionId: string) {
  const session = pending();
  if (!session || session.session_id !== sessionId) throw Error("GCP_OAUTH_SESSION_EXPIRED");
  const result = await api<{ provider_connection_id?: string; onboarding_session_id?: string }>("v2/gcp/oauth/complete", { method: "POST", body: JSON.stringify(binding(session)) });
  sessionStorage.removeItem(STORAGE);
  return result;
}
