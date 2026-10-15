"use client";

/* Where Google returns a GCP sign-in: the authorization code goes to the API once, the address loses it at once, and
 * the browser goes back to the integrations screen; a refused or foreign callback says why and goes nowhere. It looks
 * like the page GitHub returns an App to (gh-return). */

import { useEffect, useRef, useState } from "react";

import { type Locale, LocaleContext } from "@/components/locale";
import { CONSOLE_RETURN, finishSignIn, pending } from "@/console/gcp-oauth";
import { Ic } from "@/console/icons";
import { sayIn } from "@/console/text";

const WORDS: Record<string, [string, string]> = {
  GCP_OAUTH_STATE_INVALID: ["이 응답은 이 브라우저에서 시작한 Google 연결의 것이 아니거나 시간이 지났습니다.",
    "This answer is not for a Google connection started in this browser, or it has expired."],
  GCP_OAUTH_CONSENT_CANCELLED: ["Google에서 승인하지 않았습니다.", "Google approval was not given."],
};

/** The language the sign-in started in, or else the console's saved one. */
function startedIn(): Locale {
  const session = pending();
  if (session) return session.locale;
  try {
    const saved = window.localStorage.getItem("cremore.locale");
    if (saved === "ko" || saved === "en") return saved;
  } catch { /* the default language stays */ }
  return "ko";
}

export function GcpOAuthCallback() {
  const once = useRef(false);
  const [error, setError] = useState("");
  const [locale, setLocale] = useState<Locale>("ko");
  useEffect(() => {
    if (once.current) return;
    once.current = true;
    const query = new URLSearchParams(window.location.search);
    // The code is single use: it leaves the address before anything else runs.
    window.history.replaceState(null, "", window.location.pathname);
    setLocale(startedIn());
    void finishSignIn(query).then(code => { if (code) setError(code); });
  }, []);
  const L = sayIn(locale);
  return <LocaleContext.Provider value={locale}>
    <main className="gh-return">
      <div className="gh-return-card">
        <span className="gh-return-ic"><Ic name={error ? "alert" : "key"} size={20} /></span>
        <h1>{L("Google 연결", "Google connection")}</h1>
        {error ? <>
          <p className="gh-return-bad" role="alert">{WORDS[error] ? L(...WORDS[error])
            : L("연결을 마치지 못했습니다. 연동 서비스에서 다시 시작하세요.", "The connection could not be completed. Start again under Integrations.")}
            {" "}<code className="mono">{error}</code></p>
          <div className="gh-return-acts">
            <a className="primary-btn" href={CONSOLE_RETURN}><Ic name="left" size={15} />{L("연동 서비스로 돌아가기", "Back to Integrations")}</a>
          </div>
        </> : <p className="gh-return-line" role="status"><span className="spinner" aria-hidden="true" />{L("Google 승인을 마치는 중", "Completing the Google approval")}</p>}
      </div>
    </main>
  </LocaleContext.Provider>;
}
