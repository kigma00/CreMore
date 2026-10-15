"use client";

/* The page a responder opens from the exposure-response link CreMore sent by Slack DM or mail
 * (cremore/governance/response.py). As on the owner-approval page, the token is the URL fragment: it never reaches a
 * server log or a Referer, the page reads it once and takes it off the address bar, and it talks to the API only
 * through /api/response-link with the person's own company sign-in (no console session). Opening the page changes
 * nothing; the person answers with the console's own report form. */

import { useCallback, useEffect, useRef, useState } from "react";

import { type Locale, LocaleContext, useLocale } from "@/components/locale";
import { DashboardAPIError } from "@/lib/dashboard-api";
import { reasonText } from "@/console/data";
import { Ic } from "@/console/icons";
import { typeLabel } from "@/console/labels";
import { serviceName } from "@/console/logos";
import type { ResponseReport, ResponseState } from "@/console/records";
import { fmtDT, useL } from "@/console/text";
import { Fact, Facts } from "@/console/ui";
import { responseLabel } from "@/console/views/credentials/response";
import { type EvidenceOptions, type ReportBody, ReportText, ResponseReportForm } from "@/console/views/credentials/response-report";
import { tokenOf } from "@/console/views/owner-approval";

/** POST /api/v1/response-links/view: what the person may see, never a secret, a snippet, a path or another's address. */
export type ResponseLinkView = {
  /** `locations`: the credential's exposures still open. */
  finding: { provider: string; credential_type: string; identifier_hint: string; locations: number };
  request: { cycle: number; requested_at: string; link_expires_at: string; state: ResponseState; answer: "APPROVED" | "DECLINED" | null; answered_at: string | null };
  /** This person's latest report on the request, if any (no id, author or basis). */
  report: (Pick<ResponseReport, "result" | "path" | "actions" | "explanation" | "performed_at" | "received_at" | "version">
    & { replacement_plan_id: string | null; replacement_entity_id: string | null }) | null;
  can_answer: boolean;
  /** How to fix it, by language: the issuer's revocation guide, clean-up per kind of place and vault steps, as plain text. */
  playbook?: Record<Locale, { title: string; steps: string[]; link: [string, string] | null }[]>;
};

async function call<T>(action: "view" | "answer" | "evidence-options", body: Record<string, unknown>): Promise<T> {
  const response = await fetch(`/api/response-link/${action}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    // The company sign-in's session cookie goes along (behind oauth2-proxy nothing passes without it).
    cache: "no-store", credentials: "same-origin", referrerPolicy: "no-referrer",
  });
  const data = await response.json().catch(() => ({}));
  // The same error the console's requests raise, so the report form and the page word it alike.
  if (!response.ok) throw new DashboardAPIError(typeof data?.error === "string" ? data.error : "RESPONSE_LINK_UNAVAILABLE", response.status);
  return data as T;
}

const HEAD: Record<string, [string, string]> = {
  RESPONSE_LINK_EXPIRED: ["링크가 만료됐습니다", "The link expired"],
  RESPONSE_LINK_INVALID: ["쓸 수 없는 링크입니다", "This link cannot be used"],
  RESPONSE_LINK_NOT_RECIPIENT: ["요청을 받은 사람만 열 수 있습니다", "Only the person asked can open this"],
  RESPONSE_LINK_CLOSED: ["회신을 받지 않는 요청입니다", "This request takes no answer now"],
};
const ASKED: [string, string] = ["노출 자격증명 정리 요청", "Cleanup asked for an exposed credential"];

type Phase = { kind: "loading" } | { kind: "shown"; view: ResponseLinkView } | { kind: "error"; error: unknown };

export function ResponseLink() {
  const L = useL(), locale = useLocale();
  const token = useRef("");
  const [phase, setPhase] = useState<Phase>({ kind: "loading" });
  const [reporting, setReporting] = useState(false);
  const [answered, setAnswered] = useState(false);

  useEffect(() => {
    if (token.current) return;
    token.current = tokenOf(window.location.hash);
    window.history.replaceState(null, "", window.location.pathname);  // the token leaves the address bar and history
    if (!token.current) { setPhase({ kind: "error", error: new DashboardAPIError("RESPONSE_LINK_INVALID", 404) }); return; }
    call<ResponseLinkView>("view", { token: token.current }).then(view => setPhase({ kind: "shown", view }))
      .catch(error => setPhase({ kind: "error", error }));
  }, []);

  const evidence = useCallback((q: string) => call<EvidenceOptions>("evidence-options", { token: token.current, ...(q ? { q } : {}) }), []);
  const answer = async (body: ReportBody) => {
    setPhase({ kind: "shown", view: await call<ResponseLinkView>("answer", { token: token.current, ...body }) });
    setAnswered(true);
  };

  const view = phase.kind === "shown" ? phase.view : null;
  // The stable code a refusal carries ("CODE" or "CODE: sentence").
  const code = phase.kind === "error" && phase.error instanceof DashboardAPIError ? phase.error.message.split(":", 1)[0].trim() : "";
  const head = view ? view.report ? L("회신했습니다", "You answered") : view.can_answer ? L(...ASKED) : L(...HEAD.RESPONSE_LINK_CLOSED)
    : HEAD[code] ? L(...HEAD[code]) : L(...ASKED);
  return <main className="gh-return">
    <div className="gh-return-card owner-link">
      <span className="gh-return-ic"><Ic name={phase.kind === "error" ? "alert" : view?.report ? "checkCircle" : "key"} size={20} /></span>
      <h1>{head}</h1>
      {phase.kind === "loading" ? <p className="gh-return-line" role="status"><span className="spinner" aria-hidden="true" />{L("요청을 불러오고 있습니다", "Loading the request")}</p> : null}
      {phase.kind === "error" ? <p className="gh-return-bad" role="alert">{reasonText(phase.error, L)}</p> : null}
      {view ? <>
        {view.can_answer && !view.report ? <p>{L("보안팀이 아래 자격증명이 노출된 곳을 정리해 달라고 요청했습니다. 실제로 한 조치를 보고해 주세요. 수행 완료를 보고하면 CreMore가 다시 검사해 제거를 확인합니다.",
          "The security team asked you to clean up where the credential below is exposed. Report what you actually did. When you report it done, CreMore rescans to confirm the removal.")}</p> : null}
        {!view.can_answer && !view.report ? <p>{L("최신 상태는 보안팀에 확인하세요.", "Ask the security team about its current state.")}</p> : null}
        {answered ? <p className="gh-return-line" role="status"><Ic name="checkCircle" size={15} />{L("회신을 기록했습니다.", "Your answer is recorded.")}</p> : null}
        <Facts>
          <Fact label={L("서비스", "Service")}>{serviceName(view.finding.provider)}</Fact>
          <Fact label={L("유형", "Type")}>{typeLabel(view.finding.credential_type, L)}</Fact>
          <Fact label={L("식별자 (가림)", "Identifier (masked)")}><span className="mono cell-wrap">{view.finding.identifier_hint}</span></Fact>
          <Fact label={L("현재 노출 위치", "Current exposed locations")}>{view.finding.locations}</Fact>
          <Fact label={L("요청", "Request")}>{L(`${view.request.cycle}차 · `, `Cycle ${view.request.cycle} · `)}{fmtDT(view.request.requested_at, locale)}
            <div className="subtle small">{responseLabel(view.request.state, L)}</div></Fact>
          <Fact label={L("링크 만료", "Link expires")}>{fmtDT(view.request.link_expires_at, locale)}</Fact>
          {view.request.answer ? <Fact label={L("회신", "Answer")}>{view.request.answer === "APPROVED" ? L("수행 완료", "Done") : L("추가 조치 필요", "More action needed")}
            <div className="subtle small">{fmtDT(view.request.answered_at, locale)}</div></Fact> : null}
        </Facts>
        {view.playbook?.[locale]?.length ? <section aria-labelledby="playbook-head">
          <h2 id="playbook-head" className="guide-head">{L("조치 방법", "How to fix it")}</h2>
          {view.playbook[locale].map((section, index) => <div className="guide" key={index}>
            <div className="guide-head">{section.title}</div>
            <ol>{section.steps.map((step, n) => <li key={n}>{step}</li>)}</ol>
            {section.link && section.link[1].startsWith("https://") ? <div className="guide-note">
              <a href={section.link[1]} target="_blank" rel="noopener noreferrer">{section.link[0]} <Ic name="ext" size={13} /></a></div> : null}
          </div>)}
        </section> : null}
        {view.report ? <ReportText report={view.report} /> : null}
        {view.can_answer ? <div className="gh-return-acts">
          <button type="button" className="primary-btn" onClick={() => setReporting(true)}>
            {view.report ? L("조치 보고 보완", "Supplement action report") : L("조치 결과 보고", "Report actions")}</button>
        </div> : null}
      </> : null}
    </div>
    {reporting && view ? <ResponseReportForm submit={answer} evidence={evidence} onClose={() => setReporting(false)} onSaved={() => setReporting(false)} /> : null}
  </main>;
}

/** The page in the reader's saved console language, else the browser's (as the owner-approval page). */
export function ResponseLinkPage() {
  const [locale, setLocale] = useState<Locale>("ko");
  useEffect(() => {
    try {
      const saved = window.localStorage.getItem("cremore.locale");
      if (saved === "ko" || saved === "en") { setLocale(saved); return; }
    } catch { /* no saved language */ }
    if (!navigator.language.toLowerCase().startsWith("ko")) setLocale("en");
  }, []);
  return <LocaleContext.Provider value={locale}><ResponseLink /></LocaleContext.Provider>;
}
