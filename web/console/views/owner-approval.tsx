"use client";

/* The page a key's owner opens from the link CreMore sent (cremore/remediation/owner_approval.py). The link's token
 * is the URL fragment, so it never reaches a server log or a Referer; the page reads it once, takes it off the
 * address bar and talks to the API only through /api/owner-approval (no console session). Opening the page decides
 * nothing: a mail scanner that opens links only reads the request. */

import { useEffect, useRef, useState } from "react";

import { type Locale, LocaleContext, useLocale } from "@/components/locale";
import { Ic } from "@/console/icons";
import { serviceName } from "@/console/logos";
import { fmtDT, type Say, useL } from "@/console/text";
import { AreaField, Fact, Facts } from "@/console/ui";
import { ACTION_WORDS, type ActionType, actionWords, type Reason, REASON_WORDS, say } from "@/console/views/approvals/model";

export type LinkState = "PENDING" | "APPROVED" | "DECLINED" | "EXPIRED" | "WITHDRAWN";
export type LinkView = {
  state: LinkState; action_type: ActionType; reason_code: Reason; identifier_hint: string; user_name: string; account_id: string;
  /** Another provider's credential says which provider; an AWS key has none. */
  provider?: string;
  /** What a revoke takes away when that is not the credential itself. */
  revokes?: string;
  requested_at: string; expires_at: string; decided_at: string | null;
};

/** The token in a link's fragment (secrets.token_urlsafe(32)), or "" for anything else. */
export function tokenOf(hash: string) {
  const value = hash.startsWith("#") ? hash.slice(1) : hash;
  return /^[A-Za-z0-9_-]{43}$/.test(value) ? value : "";
}

const CODES: Record<string, [string, string]> = {
  OWNER_APPROVAL_LINK_INVALID: ["이 링크는 쓸 수 없습니다. 더 새로운 링크가 나갔거나 링크 주소가 잘렸습니다.", "This link cannot be used: a newer one was sent, or the address was cut off."],
  OWNER_APPROVAL_ALREADY_DECIDED: ["이 요청은 이미 결정됐습니다.", "This request was already decided."],
  OWNER_APPROVAL_EXPIRED: ["링크가 만료됐습니다. 보안팀에 새 링크를 요청하세요.", "The link expired. Ask the security team for a new one."],
  OWNER_APPROVAL_PLAN_CHANGED: ["보안팀이 이 요청을 거둬들였습니다.", "The security team withdrew this request."],
  OWNER_APPROVAL_NOTE_INVALID: ["메모에 보이지 않는 문자가 있습니다.", "The note has hidden characters."],
  OWNER_APPROVAL_SIGN_IN_REQUIRED: ["회사 계정으로 로그인한 뒤 링크를 다시 여세요.", "Sign in with your company account, then open the link again."],
  OWNER_APPROVAL_NOT_RECIPIENT: ["링크를 받은 사람의 회사 계정으로 로그인해야 결정할 수 있습니다.", "Only the person the link went to decides, signed in with their company account."],
  OWNER_APPROVAL_SAME_PERSON: ["이 계획을 요청하거나 승인한 사람은 소유자로 결정할 수 없습니다.", "Someone who asked for or approved this plan cannot decide as its owner."],
  OWNER_APPROVAL_EMAIL_UNVERIFIED: ["로그인한 계정에서 확인된 이메일을 받지 못했습니다. 관리자에게 문의하세요.", "The sign-in did not give a verified email. Ask your administrator."],
  OWNER_APPROVAL_LINK_NEEDS_SIGN_IN: ["이 설치에서는 링크로 결정할 수 없습니다. 보안팀에 직접 알려 주세요.", "This installation takes no decisions by link. Tell the security team directly."],
  TEXT_CONTAINS_CREDENTIAL: ["메모에 비밀값으로 보이는 내용이 있어 받지 않았습니다. 그 부분을 빼고 다시 보내세요.", "The note looks like it holds a secret value, so it was not taken. Remove that part and send again."],
};

export function linkErrorText(code: string, L: Say) {
  const known = CODES[code];
  return known ? L(known[0], known[1]) : L("요청을 처리하지 못했습니다. 잠시 뒤 다시 시도하세요.", "The request could not be handled. Try again shortly.");
}

async function call(action: "view" | "decide", body: Record<string, string>): Promise<LinkView> {
  const response = await fetch(`/api/owner-approval/${action}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    // The company sign-in's session cookie goes along (behind oauth2-proxy nothing passes without it).
    cache: "no-store", credentials: "same-origin", referrerPolicy: "no-referrer",
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw Error(typeof data?.detail === "string" ? data.detail : "OWNER_APPROVAL_UNAVAILABLE");
  return data as LinkView;
}

const HEAD: Record<LinkState, [string, string]> = {
  PENDING: ["자격증명 조치 승인 요청", "Approval asked for a credential action"], APPROVED: ["승인했습니다", "You approved"],
  DECLINED: ["거절했습니다", "You declined"], EXPIRED: ["링크가 만료됐습니다", "The link expired"],
  WITHDRAWN: ["거둬들인 요청입니다", "The request was withdrawn"],
};

type Phase = { kind: "loading" } | { kind: "shown"; view: LinkView } | { kind: "error"; code: string };

export function OwnerApprovalLink() {
  const L = useL();
  const locale = useLocale();
  const token = useRef("");
  const [phase, setPhase] = useState<Phase>({ kind: "loading" });
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<"" | "approve" | "decline">("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (token.current) return;
    token.current = tokenOf(window.location.hash);
    window.history.replaceState(null, "", window.location.pathname);  // the token leaves the address bar and history
    if (!token.current) { setPhase({ kind: "error", code: "OWNER_APPROVAL_LINK_INVALID" }); return; }
    call("view", { token: token.current }).then(view => setPhase({ kind: "shown", view }))
      .catch(failure => setPhase({ kind: "error", code: failure instanceof Error ? failure.message : "" }));
  }, []);

  async function decide(decision: "approve" | "decline") {
    setBusy(decision); setError("");
    try {
      setPhase({ kind: "shown", view: await call("decide", { token: token.current, decision, note: note.trim() }) });
    } catch (failure) {
      setError(linkErrorText(failure instanceof Error ? failure.message : "", L));
    } finally { setBusy(""); }
  }

  const view = phase.kind === "shown" ? phase.view : null;
  return <main className="gh-return">
    <div className="gh-return-card owner-link">
      <span className="gh-return-ic"><Ic name={phase.kind === "error" ? "alert" : view && view.state !== "PENDING" ? "checkCircle" : "key"} size={20} /></span>
      <h1>{view ? L(...HEAD[view.state]) : L("자격증명 조치 승인 요청", "Approval asked for a credential action")}</h1>
      {phase.kind === "loading" ? <p className="gh-return-line" role="status"><span className="spinner" aria-hidden="true" />{L("요청을 불러오고 있습니다", "Loading the request")}</p> : null}
      {phase.kind === "error" ? <p className="gh-return-bad" role="alert">{linkErrorText(phase.code, L)}</p> : null}
      {view ? <>
        {view.state === "PENDING" ? <p>{view.provider
          ? L("보안팀이 아래 자격증명에 조치를 하려고 합니다. 업무에 주는 영향을 확인한 뒤 승인하거나 거절해 주세요. 한 번만 결정할 수 있습니다.",
            "The security team plans the action below on a credential. Check its effect on your work, then approve or decline. You decide once.")
          : L("보안팀이 아래 AWS 액세스 키에 조치를 하려고 합니다. 업무에 주는 영향을 확인한 뒤 승인하거나 거절해 주세요. 한 번만 결정할 수 있습니다.",
            "The security team plans the action below on an AWS access key. Check its effect on your work, then approve or decline. You decide once.")}</p> : null}
        {view.state === "EXPIRED" ? <p>{L("보안팀에 새 링크를 요청하세요.", "Ask the security team for a new link.")}</p> : null}
        <Facts>
          <Fact label={L("조치", "Action")}>{ACTION_WORDS[view.action_type] ? L(...actionWords(view.action_type, view.revokes)) : view.action_type}</Fact>
          <Fact label={view.provider ? L("대상 자격증명", "Credential") : L("대상 키", "Key")}><span className="mono cell-wrap">{view.identifier_hint}</span>
            {view.provider ? <div className="subtle small">{serviceName(view.provider)}</div>
              : view.user_name ? <div className="subtle small">{L(`IAM 사용자 ${view.user_name} · 계정 ${view.account_id}`, `IAM user ${view.user_name} · account ${view.account_id}`)}</div> : null}</Fact>
          <Fact label={L("사유", "Reason")}>{say(REASON_WORDS, view.reason_code, L)}</Fact>
          <Fact label={view.decided_at ? L("결정", "Decided") : L("링크 만료", "Link expires")}>{fmtDT(view.decided_at ?? view.expires_at, locale)}</Fact>
        </Facts>
        {view.state === "PENDING" ? <>
          <AreaField label={L("보안팀에 남길 메모 (선택)", "Note to the security team (optional)")} value={note} onChange={setNote} rows={3} maxLength={500} className="short"
            placeholder={L("예: 금요일 배포 뒤에 진행해 주세요", "e.g. Please go ahead after Friday's release")} />
          {error ? <p className="gh-return-bad" role="alert">{error}</p> : null}
          <div className="gh-return-acts">
            <button type="button" className="primary-btn" disabled={Boolean(busy)} onClick={() => void decide("approve")}>
              <Ic name="checkCircle" size={15} />{busy === "approve" ? L("보내는 중", "Sending") : L("승인", "Approve")}</button>
            <button type="button" className="ghost-btn" disabled={Boolean(busy)} onClick={() => void decide("decline")}>
              {busy === "decline" ? L("보내는 중", "Sending") : L("거절", "Decline")}</button>
          </div>
        </> : null}
      </> : null}
    </div>
  </main>;
}

/** The page in the reader's saved console language, else the browser's. */
export function OwnerApprovalPage() {
  const [locale, setLocale] = useState<Locale>("ko");
  useEffect(() => {
    try {
      const saved = window.localStorage.getItem("cremore.locale");
      if (saved === "ko" || saved === "en") { setLocale(saved); return; }
    } catch { /* no saved language */ }
    if (!navigator.language.toLowerCase().startsWith("ko")) setLocale("en");
  }, []);
  return <LocaleContext.Provider value={locale}><OwnerApprovalLink /></LocaleContext.Provider>;
}
