"use client";

/* Reading and changing data. Every request goes through the Next.js proxy (lib/dashboard-api),
 * which attaches the credential; the API decides authorization and the console follows it.
 *
 * useApi reads one path, keeps the last good answer while a refresh is in flight, polls when
 * asked and reloads whenever any change anywhere in the console is saved (useSaved). A 401/403
 * on a read hands control back to the session gate.
 */

import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";

import { api, apiPage, type APIPage, DashboardAPIError } from "@/lib/dashboard-api";
import type { Say } from "@/console/text";

type Changes = { revision: number; saved: () => void; authLost: (error: DashboardAPIError) => void };

export const ChangesContext = createContext<Changes>({ revision: 0, saved: () => {}, authLost: () => {} });

export function useSaved() {
  return useContext(ChangesContext).saved;
}

// Screens that mount together often read the same path; they share one request.
const inflight = new Map<string, Promise<unknown>>();

function shared<T>(path: string, revision: number, read: (path: string) => Promise<T>, kind: string): Promise<T> {
  // A read begun before a save cannot satisfy the read after that save.
  const key = `${kind}:${revision}:${path}`;
  const pending = inflight.get(key);
  if (pending) return pending as Promise<T>;
  const request = read(path).finally(() => inflight.delete(key));
  inflight.set(key, request);
  return request;
}

export type Loaded<T> = {
  data: T | undefined;
  error: unknown;
  loading: boolean;
  reload: () => void;
  replace: (value: T) => void;
};

export function useApi<T>(path: string | null, options: { every?: number } = {}): Loaded<T> {
  return useRead<T>(path, api<T>, "json", options);
}

export function useApiPage<T>(path: string | null, options: { every?: number } = {}): Loaded<APIPage<T>> {
  return useRead<APIPage<T>>(path, apiPage<T>, "page", options);
}

/** useApi with the reading done by `read` (which must be a stable function): a page outside the console session reads
 * its own way. `kind` keeps its shared requests apart from other readers of the same key. */
export function useRead<T>(path: string | null, read: (path: string) => Promise<T>, kind: string, options: { every?: number }): Loaded<T> {
  const { revision, authLost } = useContext(ChangesContext);
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState<boolean>(path !== null);
  const [tick, setTick] = useState(0);
  const generation = useRef(0);
  const shown = useRef<string | null>(null);
  const hasValue = useRef(false);
  // every:0 is an explicit, user-triggered lookup; it must not call a provider on focus or a save elsewhere.
  const readRevision = options.every === 0 ? 0 : revision;
  const every = options.every === 0 ? 0 : Math.min(options.every ?? 10_000, 10_000);

  useEffect(() => {
    if (path === null) { setData(undefined); setError(null); hasValue.current = false; shown.current = null; setLoading(false); return; }
    let cancelled = false;
    const current = ++generation.current;
    if (shown.current !== path) { setData(undefined); setError(null); hasValue.current = false; shown.current = path; }
    setLoading(!hasValue.current);
    shared<T>(path, readRevision, read, kind).then(value => {
      if (cancelled || current !== generation.current) return;
      hasValue.current = true;
      setData(value); setError(null); setLoading(false);
    }).catch(reason => {
      if (cancelled || current !== generation.current) return;
      if (reason instanceof DashboardAPIError && reason.status === 401) authLost(reason);
      setError(reason); setLoading(false);
    });
    return () => { cancelled = true; };
  }, [path, tick, readRevision, authLost, read, kind]);

  useEffect(() => {
    if (!every || path === null) return;
    const refresh = () => {
      if (document.visibilityState === "visible") setTick(value => value + 1);
    };
    const timer = window.setInterval(refresh, every);
    window.addEventListener("focus", refresh);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("focus", refresh);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [every, path]);

  const reload = useCallback(() => setTick(value => value + 1), []);
  const replace = useCallback((value: T) => {
    // A mutation's authoritative result must not be overwritten by an older read still in flight.
    generation.current++;
    hasValue.current = true;
    setData(value); setError(null); setLoading(false);
  }, []);
  const currentPath = shown.current === path;
  return { data: currentPath ? data : undefined, error: currentPath ? error : null,
    loading: currentPath ? loading : path !== null, reload, replace };
}

/** A change request with a JSON body. Throws DashboardAPIError with the server's reason. */
export function send<T>(path: string, method: "POST" | "PUT" | "PATCH" | "DELETE", body?: unknown): Promise<T> {
  return api<T>(path, { method, body: body === undefined ? undefined : JSON.stringify(body) });
}

/** A random UUID (RFC 4122 version 4). crypto.randomUUID needs a secure context, which an installation reached over plain
 * http on another host is not; getRandomValues works everywhere. */
export function randomId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function isConflict(error: unknown) {
  return error instanceof DashboardAPIError && error.status === 409;
}

// Refusals an operator can reach, by the stable code the API puts first ("CODE: sentence").
const REASONS: Record<string, [string, string]> = {
  SIGNED_AUTHORIZATION_INVALID: ["승인 파일의 서명·기한·대상이 맞지 않습니다. 현재 계획의 승인 요청 파일을 다시 받아 별도 승인 환경에서 서명하세요.",
    "The approval file's signature, expiry or target does not match. Download the current plan's request and have it signed on the independent approval system."],
  SIGNED_AUTHORIZATION_ALREADY_USED: ["이미 사용한 승인 파일입니다. 실행 결과를 확인하고, 새 실행이 필요하면 새 승인을 받으세요.",
    "This approval file has already been used. Check the execution result and obtain a new approval if another execution is needed."],
  AWS_READ_PENDING: ["수집 프로세스가 아직 조회 중입니다. 작업자 상태를 확인한 뒤 다시 확인하세요.", "The collection process is still reading. Check the worker status, then check again."],
  RESPONSE_CHANGED: ["대응 상태가 변경됐습니다. 최신 상태를 확인한 뒤 다시 요청하세요.", "The response state changed. Review the latest state and request again."],
  RESPONSE_REPORT_TEXT_INVALID: ["20~2,000자의 구체적인 조치 사유를 입력하세요. 비밀값·HTML·숨김 문자는 저장할 수 없습니다.", "Enter a concrete explanation of 20–2,000 characters without secrets, HTML or hidden characters."],
  RESPONSE_REPORT_ANSWER_MISMATCH: ["수행 완료 보고에는 승인, 미완료·예외 보고에는 거절 응답이 필요합니다.", "Approve a completed action report; decline an incomplete or exception report."],
  RESPONSE_REPORT_SCREENING_UNAVAILABLE: ["보고 내용의 비밀값 검사가 준비되지 않았습니다. 서버 상태를 확인하세요.", "Report content screening is unavailable. Check the worker status."],
  RESPONSE_REPORT_TIME_INVALID: ["요청 시각부터 현재까지 실제 수행한 시각을 입력하세요.", "Enter the actual action time between the request and now."],
  RESPONSE_REPORT_ACTIONS_REQUIRED: ["선택한 처리 경로의 필수 조치를 모두 수행해야 완료 검증을 요청할 수 있습니다.", "Complete the required actions for the selected path before requesting verification."],
  RESPONSE_REPLACEMENT_REQUIRED: ["교체 작업 또는 새 발급 자격증명을 선택하세요.", "Select the rotation or replacement credential."],
  RESPONSE_REPORT_RECIPIENT_REQUIRED: ["대응 요청을 받은 동일 IdP 담당자만 보고할 수 있습니다. 현재 사람 목록과 로그인 계정을 확인하세요.", "Only the designated responder in the same IdP may report. Check the current directory and signed-in account."],
  RESPONSE_NEW_CYCLE_REQUIRED: ["완료 후 재발견된 항목입니다. 새 대응 요청을 보내야 합니다.", "This case recurred after completion. Send a new response request."],
  RESPONSE_REPORT_INVALID: ["처리 결과·조치·사유·수행 시각을 확인하세요.", "Check the result, actions, explanation and action time."],
  RESPONSE_REPORT_REFERENCE_INVALID: ["교체 참조가 올바르지 않습니다. 목록에서 정확한 항목을 다시 선택하세요.", "The replacement reference is invalid. Select the exact item again."],
  RESPONSE_REPORT_NOT_PENDING: ["현재 회차에서는 조치 보고를 받을 수 없습니다. 최신 대응 상태를 확인하세요.", "This cycle cannot accept a report. Check the latest response state."],
  RESPONSE_REQUEST_CHANGED: ["대응 회차가 바뀌었습니다. 최신 요청에서 보고하세요.", "The response cycle changed. Report against the latest request."],
  RESPONSE_REPORT_ID_REUSED: ["이미 접수한 보고와 내용이 다릅니다. 새 보고로 다시 제출하세요.", "This differs from an already accepted report. Submit it as a new report."],
  RESPONSE_REPORT_LIMIT: ["이 회차의 보고 한도에 도달했습니다. 새 대응 요청을 사용하세요.", "This cycle reached its report limit. Use a new response request."],
  RESPONSE_ALREADY_PENDING: ["진행 중인 대응 요청이 있습니다. 회신과 검사 결과를 먼저 확인하세요.", "A response request is already pending. Check its reply and scan result first."],
  RESPONSE_ALREADY_REMOVED: ["모든 노출 위치에서 제거가 확인됐습니다.", "Removal was confirmed at every exposed location."],
  RESPONSE_REQUEST_REUSED: ["이미 사용한 요청입니다. 최신 상태에서 새 요청을 여세요.", "This request was already used. Open a new request from the latest state."],
  RESPONSE_PERSON_REQUIRED: ["로그인 IdP에서 대응 담당자를 선택하세요.", "Select a responder from the sign-in IdP."],
  RESPONSE_RECIPIENT_CHANGED: ["선택한 담당자의 신원 또는 이메일이 변경됐습니다. 다시 선택하세요.", "The selected responder's identity or email changed. Select them again."],
  RESPONSE_RECIPIENT_MISMATCH: ["선택한 사람과 수신자가 일치하지 않습니다. 다시 선택하세요.", "The selected person and recipient do not match. Select the person again."],
  RESPONSE_TEAM_INVALID: ["책임 팀 이름을 100자 이내로 입력하세요.", "Enter a responsible team name within 100 characters."],
  RESPONSE_RULE_TARGET_INVALID: ["현재 발견 위치나 발급 계정에 속하지 않는 책임 규칙 대상입니다.", "The rule target is not a current location or issuing account for this finding."],
  DIRECTORY_CURSOR_EXPIRED: ["디렉터리가 변경됐습니다. 처음부터 다시 검색하세요.", "The directory changed. Restart the search."],
  DIRECTORY_QUERY_INVALID: ["이름·이메일·부서 검색어를 확인하세요.", "Check the name, email or department search query."],
  DIRECTORY_IDENTITY_AMBIGUOUS: ["같은 신원 정보가 여러 계정에 연결되어 자동 추천을 멈췄습니다. 담당자를 직접 선택하세요.", "The same identity evidence belongs to multiple accounts. Select the responder explicitly."],
  DIRECTORY_IDENTITY_KEY_UNAVAILABLE: ["신원 대조 키를 사용할 수 없어 자동 추천을 하지 못했습니다. 담당자를 직접 선택할 수 있습니다.", "The identity matching key is unavailable. You can still select a responder explicitly."],
  DIRECTORY_MATCH_LIMIT: ["신원 대조 후보가 한도를 초과했습니다. 담당자를 직접 선택하세요.", "The identity match candidate limit was reached. Select the responder explicitly."],
  PERSON_DIRECTORY_CHANGED: ["선택 중 디렉터리가 변경됐습니다. 최신 목록에서 다시 선택하세요.", "The directory changed during selection. Select again from the latest directory."],
  PERSON_REFERENCE_INVALID: ["로그인 IdP 목록에서 사람을 다시 선택하세요.", "Select a person again from the sign-in IdP directory."],
  PERSON_NOT_AVAILABLE: ["현재 로그인 IdP에서 이 사람을 확인하지 못했습니다.", "This person could not be confirmed in the current sign-in IdP."],
  PERSON_INACTIVE: ["비활성 계정은 대응 담당자로 선택할 수 없습니다.", "An inactive account cannot be selected as responder."],
  PERSON_NO_CONTACT: ["이 사람의 이메일이 수집되지 않았습니다.", "No email has been collected for this person."],
  PERSON_AMBIGUOUS_EMAIL: ["같은 이메일을 가진 계정이 여러 개입니다. IdP의 중복을 확인하세요.", "Several accounts share this email. Review the duplicate accounts in the IdP."],
  PERSON_STALE: ["사람 정보가 오래됐습니다. IdP 목록을 다시 수집한 후 선택하세요.", "This person's information is stale. Collect the IdP directory again before selecting them."],
  PERSON_PARTIAL: ["사람 목록이 부분 수집되었습니다. 수집 상태를 해결한 후 선택하세요.", "The directory is incomplete. Resolve the collection status before selecting a responder."],
  PERSON_NOT_SYNCED: ["IdP 사람 목록을 먼저 수집하세요.", "Collect the IdP people directory first."],
  PERSON_UNAVAILABLE: ["이 사람의 현재 디렉터리 상태를 확인할 수 없습니다.", "This person's current directory status could not be confirmed."],
  RESPONSE_APPROVER_INVALID: ["외부 티켓 시스템에서 대응 담당자 이메일을 확인하지 못했습니다.", "The responder email could not be confirmed in the external ticket system."],
  RESPONSE_TICKET_REFERENCE_INVALID: ["외부 티켓의 참조를 확인하지 못했습니다.", "The external ticket reference could not be confirmed."],
  RESPONSE_ANSWERED_BY_OTHER: ["지정한 담당자와 다른 사람이 회신했습니다.", "Someone other than the designated responder replied."],
  RESPONSE_CONFIRMATION_REQUIRED: ["외부 시스템에서 진행 중인 중복 요청이 없음을 직접 확인해야 합니다.", "You must personally confirm that no duplicate request is pending in the external system."],
  RESPONSE_NOT_UNKNOWN: ["현재 요청은 발송 결과 확인 대상이 아닙니다. 최신 상태를 확인하세요.", "This request no longer needs its delivery result checked. Review the latest state."],
  RESPONSE_SEND_IN_PROGRESS: ["대응 요청을 발송 중입니다. 결과를 기다리세요.", "The response request is being sent. Wait for its result."],
  RESPONSE_SEND_TIMED_OUT: ["발송 확인 시간이 지났습니다. 티켓 시스템이면 중복 요청 전에 외부 티켓을 확인하고, Slack·메일이면 링크를 무효로 했으니 다시 요청하세요.", "Delivery confirmation timed out. For a ticket system, check the external ticket before asking again; for Slack or mail the link was voided, so request again."],
  // A response request by a CreMore link (Slack DM or mail) or the local operator's record.
  RESPONSE_LINK_NEEDS_SIGN_IN: ["로컬 로그인 설치에서는 대응 링크를 쓰지 않습니다. 담당자의 회신은 기록으로 남깁니다.", "A local sign-in installation sends no response links: record the person's answer instead."],
  RESPONSE_LINK_SIGN_IN_REQUIRED: ["회사 계정으로 로그인한 뒤 링크를 다시 여세요.", "Sign in with your company account, then open the link again."],
  RESPONSE_LINK_EMAIL_UNVERIFIED: ["로그인한 계정에서 확인된 회사 이메일을 받지 못했습니다. 관리자에게 문의하세요.", "The sign-in did not give a verified company email. Ask your administrator."],
  RESPONSE_LINK_INVALID: ["이 링크는 쓸 수 없습니다. 더 새로운 요청이 나갔거나 요청이 거둬졌거나 링크 주소가 잘렸습니다.", "This link cannot be used: a newer request was sent, the request was withdrawn, or the address was cut off."],
  RESPONSE_LINK_EXPIRED: ["링크가 만료됐습니다. 보안팀에 새 요청을 받으세요.", "The link expired. Ask the security team for a new request."],
  RESPONSE_LINK_NOT_RECIPIENT: ["요청을 받은 사람의 회사 계정으로 로그인해야 회신할 수 있습니다.", "Only the person the request went to answers, signed in with their company account."],
  RESPONSE_LINK_CLOSED: ["이 요청은 지금 회신을 받지 않습니다. 최신 상태는 보안팀에 확인하세요.", "This request takes no answer now. Ask the security team about its current state."],
  RESPONSE_RECORD_LOCAL_ONLY: ["기록은 로컬 로그인 설치에서만 씁니다. 회사 로그인 설치는 Slack이나 메일 링크로 요청합니다.", "Recording is for local sign-in installations only. With company sign-in, ask by a Slack or mail link."],
  RESPONSE_CONSOLE_URL_NOT_SET: ["관리자가 연락 발송 설정에 콘솔 주소를 넣으면 보낼 수 있습니다.", "An Admin adds the console address to the contact delivery setup first."],
  RESPONSE_RECIPIENT_NOT_A_PERSON: ["대응 요청은 사람에게만 보냅니다. 채널이 아닌 담당자를 고르세요.", "A response request goes to a person, not a channel. Choose the responder."],
  // Response channels: a team's Slack channel a request is also posted in (phase 2).
  RESPONSE_CHANNEL_NOT_FOUND: ["Slack 채널을 찾지 못했거나 봇이 볼 수 없습니다. 채널 ID를 확인하고 봇을 채널에 초대하세요.", "The Slack channel was not found or the bot cannot see it. Check the channel ID and invite the bot."],
  RESPONSE_CHANNEL_ARCHIVED: ["보관된 Slack 채널에는 올리지 않습니다.", "An archived Slack channel is not used."],
  RESPONSE_CHANNEL_EXTERNAL: ["외부 회사와 공유된 Slack 채널에는 올리지 않습니다.", "A Slack channel shared with another company is never used."],
  RESPONSE_CHANNEL_PUBLIC_NOT_ALLOWED: ["공개 채널입니다. 관리자가 대응 알림 채널에서 이 채널을 공개 채널로 허용해야 올립니다.", "This is a public channel. An admin must allow it as public under Response channels first."],
  RESPONSE_CHANNEL_NOT_APPROVED: ["대응 알림 채널로 승인한 채널만 쓸 수 있습니다.", "Only a channel approved under Response channels can be used."],
  SLACK_SCOPE_MISSING: ["Slack 봇에 channels:read와 groups:read 권한이 없어 채널을 확인할 수 없습니다. DM은 그대로 보냅니다.", "The Slack bot lacks channels:read and groups:read, so channels cannot be checked. DMs still go out."],
  RESPONSE_CHANNELS_CHANGED: ["다른 관리자가 먼저 대응 알림 채널을 바꿨습니다. 창을 닫았다 다시 열어 최신 목록에서 다시 저장하세요.", "Another admin changed the response channels first. Close and reopen this window, then save again from the latest list."],
  RESPONSE_CHANNELS_INVALID: ["채널 ID는 C 또는 G로 시작하는 대문자·숫자 9~13자이고, 같은 채널은 한 번만, 50개까지 넣을 수 있습니다.", "Channel IDs are 9–13 capital letters and digits starting with C or G, each listed once, at most 50."],
  RESPONSE_SLACK_CHANNEL_NOT_ALLOWED: ["팀 채널 알림은 Slack·메일 링크 요청에서만 보냅니다. 기록이나 티켓 요청에는 채널을 고를 수 없습니다.", "A team channel notice goes only with a Slack or mail link request, not with a record or a ticket."],
  RESPONSE_DELIVERY_REQUIRED: ["보낼 곳을 하나 이상 고르세요: 개인 DM(메일) 또는 팀 채널.", "Choose at least one place to send it: the person's DM (mail) or a team channel."],
  CONTACT_SEND_ERROR: ["보내는 중 알 수 없는 오류가 났습니다. 잠시 뒤 다시 요청하세요.", "An unexpected error stopped the send. Request again shortly."],
  SLACK_IS_ARCHIVED: ["보관된 Slack 채널이라 올리지 못했습니다.", "The Slack channel is archived, so nothing was posted."],
  SLACK_MSG_TOO_LONG: ["Slack이 메시지가 너무 길다고 거절했습니다.", "Slack refused the message as too long."],
  SLACK_THREAD_NOT_FOUND: ["Slack에서 그 글의 스레드를 찾지 못했습니다(글이 지워졌을 수 있습니다).", "Slack could not find the post's thread (the post may have been deleted)."],
  SLACK_CANNOT_REPLY_TO_MESSAGE: ["Slack이 그 글에 답글을 달 수 없다고 거절했습니다.", "Slack does not allow replies to that post."],
  ANNOTATIONS_CHANGED: ["다른 사람이 먼저 바꿨습니다. 새로 불러온 내용에서 다시 적용하세요.", "Someone changed this first. Apply your change again on the reloaded version."],
  FINDING_NOT_ACKNOWLEDGED: ["검토를 시작한 뒤에 바꿀 수 있습니다.", "Start the review first."],
  TEXT_CONTAINS_CREDENTIAL: ["비밀값으로 보이는 문자열이 있어 저장하지 않았습니다. 지운 뒤 다시 저장하세요.", "It contains what looks like a secret value, so it was not saved. Remove it and save again."],
  TEXT_CONTROL_CHARACTERS: ["입력할 수 없는 문자가 있습니다.", "It contains characters that cannot be saved."],
  TAG_INVALID: ["태그는 40자 이내의 글자로 입력하세요.", "Use a tag of up to 40 characters."],
  DUE_DATE_OUT_OF_RANGE: ["회신 기한은 오늘부터 1년 안으로 정하세요.", "Choose a reply date within a year from today."],
  DETECTOR_UNKNOWN: ["없는 탐지 룰입니다.", "That detection rule does not exist."],
  RESCAN_OUT_OF_SCOPE: ["이 위치는 승인된 검사 범위 밖이라 다시 검사할 수 없습니다.", "This location is outside the approved scan scope, so it cannot be rescanned."],
  WEBSITE_SCOPE_PATH_INVALID: ["웹사이트 검사 범위의 경로는 '/'로 시작하는 URL 경로여야 합니다(?·# 없이). 범위를 고친 뒤 다시 하세요.", "A website scan scope path must be a URL path starting with '/' (no ? or #). Fix the scope, then try again."],
  RULE_NAME_TAKEN: ["같은 이름의 룰이 이미 있습니다.", "A rule with that name already exists."],
  SECOND_OPERATOR_REQUIRED: ["요청한 사람이 아닌 다른 담당자가 승인·확인해야 합니다.", "An operator other than the requester has to approve or confirm this."],
  SELF_APPROVAL_CONFIRMATION_REQUIRED: ["단독 운영 설치에서는 요청한 사람이 내용을 다시 확인해야 합니다.", "On a single-operator installation, the requester re-confirms it."],
  CONNECTION_DISABLED: ["사용 중지된 연동입니다. 먼저 다시 켜세요.", "This integration is turned off. Turn it on first."],
  JOB_NOT_STOPPABLE: ["이미 끝난 작업입니다.", "This job has already finished."],
  SCOPE_PLAN_STALE: ["실행 계획이 만료됐습니다. 다시 준비하세요.", "The plan expired. Prepare it again."],
  SCOPE_VERSION_CONFLICT: ["다른 사람이 먼저 저장했습니다. 새로 불러온 뒤 다시 적용하세요.", "Someone saved first. Reload and apply again."],
  SETTING_CHANGED_MEANWHILE: ["다른 관리자가 그사이 이 설정을 저장했습니다. 새로 불러온 뒤 다시 저장하세요.", "Another admin saved this setting in the meantime. Reload it and save again."],
  AWS_LOGIN_REQUIRED: ["CreMore의 AWS 로그인이 필요합니다.", "CreMore needs to sign in to AWS."],
  VERIFICATION_LOCKED: ["이 설치는 검증을 설정에서 끈 상태로 고정했습니다.", "This installation keeps verification off in its configuration."],
  TRIGGER_LOCKED: ["이 설치는 이 트리거를 설정에서 고정했습니다.", "This installation fixes this trigger in its configuration."],
  TRIGGER_FIELD_PINNED: ["이 설치는 이 항목을 설정에서 고정했습니다.", "This installation fixes this field in its configuration."],
  LEARNED_FP_LOCKED: ["이 설치는 자동 오탐 처리를 설정에서 고정했습니다.", "This installation fixes auto-triage in its configuration."],
  THRESHOLD_LOCKED: ["이 설치는 닮은 정도 기준을 설정에서 고정했습니다.", "This installation fixes the similarity in its configuration."],
  MIN_SAMPLES_LOCKED: ["이 설치는 필요한 확정 수를 설정에서 고정했습니다.", "This installation fixes the confirmations needed in its configuration."],
  MAX_CONFIDENCE_LOCKED: ["이 설치는 닫을 수 있는 신뢰도를 설정에서 고정했습니다.", "This installation fixes the confidence it may close in its configuration."],
  TRIGGER_QUEUE_URL_INVALID: ["SQS 큐 URL은 https://sqs.<리전>.amazonaws.com/<계정 12자리>/<큐 이름> 형식입니다.", "An SQS queue URL is https://sqs.<region>.amazonaws.com/<12-digit account>/<queue name>."],
  TRIGGER_SUBSCRIPTION_INVALID: ["Pub/Sub 구독은 projects/<프로젝트>/subscriptions/<이름> 형식입니다.", "A Pub/Sub subscription is projects/<project>/subscriptions/<name>."],
  TRIGGER_BUS_QUEUE_INVALID: ["Service Bus 주소는 https://<네임스페이스>.servicebus.windows.net/<큐> 또는 .../<토픽>/subscriptions/<이름> 형식입니다.", "A Service Bus address is https://<namespace>.servicebus.windows.net/<queue> or .../<topic>/subscriptions/<name>."],
  TRIGGER_CHANGE_FEED_MINUTES_INVALID: ["변경 감지 주기는 1분부터 1,440분까지입니다.", "A change feed runs every 1 to 1,440 minutes."],
  TRIGGER_PROFILE_INVALID: ["범위 프로필을 다시 고르세요.", "Choose the scope profile again."],
  TRIGGER_PROFILE_NOT_APPROVED: ["승인된 범위 프로필만 묶을 수 있습니다.", "Only an approved scope profile can be bound."],
  INVESTIGATION_LOCKED: ["이 설치는 이 조사를 설정에서 고정했습니다.", "This installation fixes this investigation in its configuration."],
  AUTH_SETTINGS_FIXED_WHILE_IN_USE: ["연결된 수집이 있는 동안에는 인증 방식을 바꿀 수 없습니다.", "The sign-in method cannot change while collections use it."],
  CONTENT_SOURCE_ALREADY_EXISTS: ["같은 대상의 노출 검사가 이미 있습니다.", "An exposure scan of the same target already exists."],
  REVISION_CONFLICT: ["다른 사람이 먼저 바꿨습니다. 새로 불러온 뒤 다시 적용하세요.", "Someone changed this first. Reload and apply again."],
  REVIEW_REVISION_CONFLICT: ["다른 사람이 먼저 조사 상태를 바꿨습니다. 새로 불러온 뒤 다시 적용하세요.", "Someone changed a review first. Reload and apply again."],
  ASSIGNED_TEAM_TOO_LONG: ["부서 이름이 너무 깁니다.", "The team name is too long."],
  ASSIGNED_TEAM_INVALID: ["부서 이름은 글자로 입력하세요.", "Enter the team name as text."],
  ASSIGNEE_INVALID: ["담당자는 200자 이내의 한 줄로, 비밀값 없이 입력하세요.", "Enter the owner as one line of up to 200 characters, without secret values."],
  NOT_FOUND: ["찾을 수 없습니다.", "Not found."],
  SIEM_NOT_CONFIGURED: ["이 설치에서 이벤트를 받아 가는 SIEM·웹훅 출력이 없습니다. 설정에서 SIEM 전송을 연결하세요.", "No SIEM or webhook destination takes events from this installation. Connect SIEM delivery in settings."],
  MANAGEMENT_ACTION_INVALID: ["이 Credential에 요청할 수 없는 조치입니다.", "This action cannot be requested for this credential."],
  MANAGEMENT_NOTE_INVALID: ["메모는 500자 이내의 글로 적으세요.", "Write the note as text of up to 500 characters."],
  MANAGEMENT_ACTION_NOT_PENDING: ["이미 확인했거나 닫힌 요청입니다.", "This request was already confirmed or closed."],
  WORKFLOW_VERSION_CONFLICT: ["다른 사람이 먼저 티켓을 바꿨습니다. 새로 불러온 뒤 다시 적용하세요.", "Someone changed the ticket first. Reload and apply again."],
  WORKFLOW_FIELDS_INVALID: ["티켓 항목을 확인하세요. 담당 팀은 128자 이내의 글로, 주소나 비밀값 없이 적습니다.", "Check the ticket fields. The team is text of up to 128 characters, without addresses or secret values."],
  WORKFLOW_DATE_INVALID: ["검토 기한을 확인하세요.", "Check the review date."],
  WORKFLOW_RESOLUTION_BLOCKED: ["모든 단계를 검토하고 담당 팀과 담당자를 정해야 완료할 수 있습니다.", "Review every step and set a team and an owner to complete it."],
  WORKFLOW_APPROVAL_REQUIRED: ["다른 관리자가 이 내용을 먼저 승인해야 합니다.", "Another Admin approves this content first."],
  WORKFLOW_PLAYBOOK_INVALID: ["플레이북 설정을 확인하세요.", "Check the playbook settings."],
  WORKFLOW_STEP_INVALID: ["검토 단계를 확인하세요.", "Check the review steps."],
  // Owner contact that CreMore sends itself (N2a).
  CONTACT_CHANNEL_NOT_SET_UP: ["이 채널은 CreMore 발송이 설정되지 않았습니다. 관리자가 연동 서비스의 기타 설정 > 연락 발송에서 설정합니다.",
    "This channel is not set up. An admin sets it up under Integrations > Other settings > Contact delivery."],
  CONTACT_RECIPIENT_NOT_ALLOWED: ["허용한 도메인의 주소와 허용한 Slack 채널로만 보낼 수 있습니다.", "Only addresses in the allowed domains and the allowed Slack channels can receive it."],
  CONTACT_RATE_LIMITED: ["한 시간에 보낼 수 있는 수를 넘었습니다. 잠시 뒤 다시 보냅니다.", "You reached the hourly sending limit. Send again later."],
  CONTACT_TIMED_OUT: ["보내는 데 시간이 너무 걸려 멈췄습니다.", "Sending took too long and stopped."],
  CONTACT_SLACK_CHANNELS_INVALID: ["Slack 채널은 #이름(소문자) 또는 채널 ID로 적습니다.", "List Slack channels as #name (lower case) or channel ID."],
  SMTP_AUTH_UNSUPPORTED: ["메일 서버가 로그인을 지원하지 않습니다. 계정을 비우거나 보안 연결을 바꿉니다.", "The mail server does not offer sign-in. Leave the account empty or change the security setting."],
  CONTACT_ADDRESS_INVALID: ["받는 주소를 확인하세요.", "Check the recipient address."],
  CONTACT_RECIPIENTS_INVALID: ["받는 곳은 1곳부터 20곳까지입니다.", "Send to 1 to 20 recipients."],
  CONTACT_SUBJECT_INVALID: ["제목은 200자 이내의 한 줄로 적습니다.", "The subject is one line of up to 200 characters."],
  CONTACT_MESSAGE_INVALID: ["내용은 4,000자 이내의 글로 적습니다.", "The message is text of up to 4,000 characters."],
  CONTACT_SECRET_UNAVAILABLE: ["저장한 비밀번호나 토큰을 열 수 없습니다. 관리자가 다시 저장합니다.", "The saved password or token cannot be opened. An admin saves it again."],
  CONTACT_NOT_DELIVERED: ["아무 곳에도 보내지 못했습니다.", "It was not delivered anywhere."],
  CONTACT_DOMAINS_REQUIRED: ["메일을 쓰려면 받을 수 있는 도메인을 하나 이상 적습니다.", "List at least one domain that may receive mail."],
  CONTACT_DOMAINS_INVALID: ["도메인을 확인하세요(예: example.com).", "Check the domains (for example example.com)."],
  CONTACT_CONSOLE_URL_INVALID: ["콘솔 주소는 https://cremore.example.com처럼 경로 없이 적습니다.", "Enter the console address without a path, like https://cremore.example.com."],
  // The owner's approval of a key action plan (N2b).
  OWNER_APPROVAL_CONSOLE_URL_NOT_SET: ["관리자가 연락 발송 설정에 콘솔 주소를 넣으면 보낼 수 있습니다.", "An Admin adds the console address to the contact delivery setup first."],
  OWNER_APPROVAL_ALREADY_GRANTED: ["소유자가 이미 이 계획을 승인했습니다.", "The owner already approved this plan."],
  OWNER_APPROVAL_PLAN_NOT_OPEN: ["승인 대기나 실행 대기인 계획만 소유자에게 물을 수 있습니다.", "Only a plan awaiting approval or execution can go to the owner."],
  OWNER_APPROVAL_LINK_NEEDS_SIGN_IN: ["로컬 로그인 설치에서는 링크를 보내지 않습니다. 소유자에게 받은 승인을 기록합니다.", "A local sign-in installation sends no links: record the approval the owner gave."],
  OWNER_APPROVAL_RECORD_LOCAL_ONLY: ["회사 로그인 설치에서는 소유자가 링크에서 직접 결정합니다.", "With company sign-in, the owner decides at the link themselves."],
  OWNER_APPROVAL_RECIPIENT_NOT_A_PERSON: ["소유자 승인은 채널이 아니라 사람의 이메일로 보냅니다.", "An owner approval goes to a person's address, not a channel."],
  OWNER_APPROVAL_EVIDENCE_REQUIRED: ["소유자와 승인 근거를 적습니다.", "Enter the owner and the evidence."],
  OWNER_APPROVAL_OWNER_INVALID: ["소유자 이름에 보이지 않는 문자가 있습니다.", "The owner's name has hidden characters."],
  OWNER_APPROVAL_EVIDENCE_INVALID: ["승인 근거에 보이지 않는 문자가 있습니다.", "The evidence has hidden characters."],
  OWNER_APPROVAL_NOTE_INVALID: ["메모에 보이지 않는 문자가 있습니다.", "The note has hidden characters."],
  OWNER_APPROVAL_REQUIRED: ["키 소유자의 승인을 받아야 실행할 수 있습니다.", "The key's owner approves before it runs."],
  EMERGENCY_NOT_PUBLIC: ["공개된 곳에 지금 노출된 키만 긴급 차단할 수 있습니다.", "Only a key exposed in a public place now can be contained in an emergency."],
  EMERGENCY_NOT_NEEDED: ["소유자 승인이 이미 있어 평소처럼 실행합니다.", "The owner already approved: execute as usual."],
  EMERGENCY_ACTION_NOT_ALLOWED: ["긴급 차단은 키 비활성화만 할 수 있습니다.", "An emergency can only disable a key."],
  // Another provider's credential (P1, cremore/remediation/provider_actions.py).
  REMEDIATION_NOT_SET_UP: ["이 자격증명에 조치할 연동이 없습니다. 연동 서비스에서 '승인된 조치 실행'을 따로 연동하세요.", "No integration acts on this credential. Connect one for approved actions under Integrations."],
  REMEDIATION_CONNECTION_AMBIGUOUS: ["이 자격증명에 닿는 조치용 연동이 둘 이상입니다. 하나만 남기세요.", "More than one integration for approved actions reaches this credential. Keep one."],
  REMEDIATION_NEEDS_ITS_OWN_CONNECTION: ["'승인된 조치 실행'은 다른 기능과 따로 연동합니다.", "Approved actions are connected on their own, apart from other features."],
  REMEDIATION_CHECK_REQUIRED: ["조치용 연동의 권한 점검이 실행할 계정을 확인하지 못했습니다. 연동에서 권한을 다시 확인하세요.", "The acting integration's check did not name the account that acts. Check its access again under Integrations."],
  CREDENTIAL_NOT_ELIGIBLE: ["이 자격증명은 조치 계획으로 다룰 수 없습니다.", "This credential cannot be acted on through a plan."],
  CREDENTIAL_NOT_FOUND: ["이 자격증명을 찾지 못했습니다. 목록을 새로 불러오세요.", "This credential was not found. Reload the list."],
  ACTION_NOT_SUPPORTED_FOR_CREDENTIAL: ["이 자격증명에는 그 조치를 할 수 없습니다.", "That action is not available for this credential."],
  PROVIDER_PLAN_RUNS_IN_WORKER: ["이 계획은 작업자가 실행합니다. 실행을 다시 요청하세요.", "The worker runs this plan. Request execution again."],
  PLAN_NOT_QUEUEABLE: ["이 계획은 바로 실행합니다.", "This plan runs at once."],
  RECHECK_ALREADY_QUEUED: ["이미 요청한 상태 확인을 작업자가 처리하고 있습니다.", "The worker is already rechecking this plan."],
  // The company's domains (N4, cremore/domains.py).
  DOMAIN_INVALID: ["도메인 형식이 맞지 않습니다. 예: example.com (주소·경로·포트 없이)", "That is not a domain. For example example.com, without an address, path or port."],
  DOMAIN_EXISTS: ["이미 추가한 도메인입니다.", "That domain is already added."],
  DOMAIN_LIMIT: ["도메인은 100개까지 추가할 수 있습니다.", "Up to 100 domains can be added."],
  DOMAIN_NOT_FOUND: ["이 도메인을 찾지 못했습니다. 목록을 새로 불러오세요.", "This domain was not found. Reload the list."],
  DOMAIN_CHANGED: ["확인하는 동안 도메인이 바뀌었습니다. 다시 확인하세요.", "The domain changed while it was being asked about. Verify again."],
  DNS_SERVERS_INVALID: ["설치 설정 DOMAIN_DNS_SERVERS에 IP 주소가 아닌 값이 있습니다.", "The installation's DOMAIN_DNS_SERVERS holds something that is not an IP address."],
  EMERGENCY_REASON_REQUIRED: ["긴급 차단 사유를 10자 이상 적습니다.", "Give the emergency reason in at least 10 characters."],
  EMERGENCY_REASON_INVALID: ["사유에 보이지 않는 문자가 있습니다.", "The reason has hidden characters."],
  OWNER_NOTICE_NOT_PENDING: ["소유자에게 이미 알렸습니다.", "The owner was already told."],
  // The owner's approval asked in the company's ticket system (T1).
  OWNER_APPROVAL_SAME_PERSON: ["계획을 요청하거나 승인한 사람은 소유자로 승인할 수 없습니다.", "Someone who requested or approved the plan cannot approve as its owner."],
  OWNER_APPROVAL_ACTOR_EMAIL_UNKNOWN: ["계획을 요청·승인한 사람 중 회사 로그인에 이메일이 없던 사람이 있어 소유자와 구별할 수 없습니다. 그 사람이 로그인한 뒤 다시 요청합니다.",
    "Someone who requested or approved the plan never signed in with an address, so the owner cannot be told apart from them. Ask again after they sign in."],
  OWNER_APPROVAL_RECIPIENT_INVALID: ["소유자 이메일을 확인하세요.", "Check the owner's address."],
  OWNER_APPROVAL_TICKET_REFERENCE_INVALID: ["티켓 시스템이 알아볼 수 없는 번호를 돌려줬습니다.", "The ticket system answered with a reference CreMore cannot keep."],
  TICKET_SYSTEM_NOT_SET_UP: ["관리자가 연동 서비스의 기타 설정 > 티켓 시스템을 먼저 설정합니다.", "An admin sets up Integrations > Other settings > Ticket system first."],
  TICKET_SYSTEM_CHANGED: ["요청을 연 티켓 시스템(주소)을 더 쓰지 않아 응답을 읽지 않습니다. 다시 요청하세요.", "The ticket system (address) it was asked on is no longer used, so its answer is not read. Ask again."],
  TICKET_SYSTEM_UNAVAILABLE: ["이 티켓 시스템은 이 설치에서 쓸 수 없습니다.", "This ticket system is not available in this installation."],
  TICKET_SYSTEM_SECRET_REQUIRED: ["비밀값을 입력합니다. 연결 값을 바꾸면 다시 입력해야 합니다.", "Enter the secrets. Changing a connection value needs them again."],
  TICKET_SYSTEM_SECRET_INVALID: ["비밀값은 1,024자 이내로, 보이지 않는 문자 없이 입력합니다.", "Enter secrets of up to 1,024 characters, without hidden characters."],
  TICKET_SYSTEM_SECRET_UNAVAILABLE: ["저장한 비밀값을 열 수 없습니다. 관리자가 다시 저장합니다.", "The saved secrets cannot be opened. An admin saves them again."],
  TICKET_SYSTEM_SETUP_INVALID: ["티켓 시스템 설정을 확인하세요.", "Check the ticket system setup."],
  TICKET_SYSTEM_ERROR: ["티켓 시스템이 알 수 없는 오류를 돌려줬습니다.", "The ticket system reported an unknown error."],
  CONTACT_MAIL_INVALID: ["메일 서버 설정을 확인하세요. 계정과 비밀번호는 영문·숫자·기호로 적습니다.", "Check the mail server settings. The account and password are ASCII."],
  CONTACT_MAIL_PASSWORD_REQUIRED: ["계정이 있으면 비밀번호를 입력합니다.", "Enter the password for the account."],
  CONTACT_SLACK_TOKEN_INVALID: ["Slack 봇 토큰(xoxb-로 시작)을 확인하세요.", "Check the Slack bot token (starting with xoxb-)."],
  CONTACT_SLACK_TOKEN_REQUIRED: ["Slack 봇 토큰을 입력합니다.", "Enter the Slack bot token."],
  CONTACT_CHANNEL_INVALID: ["채널을 고르세요.", "Choose a channel."],
  SMTP_AUTH_FAILED: ["메일 서버가 로그인을 거절했습니다.", "The mail server refused the sign-in."],
  SMTP_UNAVAILABLE: ["메일 서버에 연결하지 못했습니다.", "Could not reach the mail server."],
  SMTP_RECIPIENTS_REFUSED: ["메일 서버가 받는 주소를 모두 거절했습니다.", "The mail server refused every recipient."],
  SMTP_RECIPIENT_REFUSED: ["메일 서버가 이 주소를 거절했습니다.", "The mail server refused this address."],
  SMTP_STARTTLS_UNSUPPORTED: ["메일 서버가 STARTTLS를 지원하지 않습니다. 보안 연결 방식을 바꿉니다.", "The mail server does not support STARTTLS. Change the security setting."],
  SLACK_INVALID_AUTH: ["Slack 봇 토큰이 맞지 않습니다.", "The Slack bot token is not valid."],
  SLACK_TOKEN_REVOKED: ["Slack 봇 토큰이 폐기됐습니다.", "The Slack bot token was revoked."],
  SLACK_MISSING_SCOPE: ["Slack 봇에 필요한 권한(chat:write, im:write, users:read.email)이 없습니다.", "The Slack bot lacks a needed scope (chat:write, im:write, users:read.email)."],
  SLACK_USERS_NOT_FOUND: ["Slack에서 이 주소의 사용자를 찾지 못했습니다.", "No Slack user has this address."],
  SLACK_USER_NOT_FOUND: ["Slack에서 이 주소의 사용자를 찾지 못했습니다.", "No Slack user has this address."],
  SLACK_REQUEST_REFUSED: ["Slack이 요청을 거절했습니다.", "Slack refused the request."],
  SLACK_RESPONSE_LIMIT: ["Slack의 응답이 너무 커서 읽지 않았습니다.", "Slack's answer was too large to read."],
  SLACK_CHANNEL_NOT_FOUND: ["Slack 채널을 찾지 못했습니다.", "The Slack channel was not found."],
  SLACK_NOT_IN_CHANNEL: ["봇이 그 채널에 들어가 있지 않습니다.", "The bot is not in that channel."],
  SLACK_RATE_LIMITED: ["Slack 요청 한도에 걸렸습니다. 잠시 뒤 다시 보냅니다.", "Slack's rate limit was reached. Send again shortly."],
  SLACK_UNAVAILABLE: ["Slack에 연결하지 못했습니다.", "Could not reach Slack."],
  // The audit trail's hash chain (cremore/operations/audit_integrity.py).
  AUDIT_RECORDING_UNAVAILABLE: ["감사 기록을 저장하지 못했습니다. 작업이 이미 처리됐을 수 있으니 상태를 확인한 뒤 다시 시도하세요.", "Could not save the audit receipt. The action may have completed; check its state before retrying."],
  AUDIT_CHECK_RUNNING: ["체인을 확인하는 중입니다. 잠시 뒤 다시 합니다.", "The chain is being checked. Try again shortly."],
  AUDIT_ACK_NOT_OPEN: ["지금 열려 있지 않은 문제가 있습니다. 체인을 다시 읽은 뒤 고르세요.", "Some of these problems are no longer open. Read the chain again and choose again."],
  AUDIT_ACK_INVALID: ["받아들일 문제를 1개부터 100개까지 고르세요.", "Choose 1 to 100 problems to accept."],
  AUDIT_ACK_REASON_REQUIRED: ["사유를 500자 이내로 적습니다.", "Give a reason of up to 500 characters."],
  ANCHOR_INVALID: ["위치는 1 이상의 숫자, MAC은 64자리 16진수로 넣습니다.", "Enter the position as a number from 1 and the MAC as 64 hex digits."],
  INVALID_COVERAGE_REQUEST: ["이 조건으로는 찾을 수 없습니다. 필터를 지우고 다시 보세요.", "These filters cannot be used. Clear them and try again."],
  // AWS settings (cremore/api/routes/settings.py, cremore/api/routes/aws.py).
  EXTERNAL_ID_LOCKED: ["이 설치는 ExternalId를 설정에서 고정했습니다.", "This installation fixes the ExternalId in its configuration."],
  EXTERNAL_ID_NOT_SET: ["StackSet의 공유 ExternalId를 먼저 저장합니다.", "Save the StackSet's shared ExternalId first."],
  EXTERNAL_ID_TEMPLATE_LENGTH: ["역할 템플릿은 16~128자의 ExternalId만 받습니다. 새 값을 저장합니다.", "The role template takes an ExternalId of 16 to 128 characters. Save a new one."],
  OU_IDS_LOCKED: ["이 설치는 대상 OU를 설정에서 고정했습니다.", "This installation fixes the OUs in its configuration."],
  EXCLUDES_LOCKED: ["이 설치는 제외 계정을 설정에서 고정했습니다.", "This installation fixes the excluded accounts in its configuration."],
  AWS_CONTROL_TOWER_INVALID_SETTINGS: ["Control Tower 홈 리전과 수명주기 큐 URL(https://sqs.<리전>.amazonaws.com/<계정>/<큐>)을 확인합니다.", "Check the Control Tower home Region and the lifecycle queue URL (https://sqs.<region>.amazonaws.com/<account>/<queue>)."],
  AWS_CONTROL_TOWER_SEPARATE_QUEUE_REQUIRED: ["수명주기 큐는 스캔 트리거의 SQS 큐와 다른 큐여야 합니다.", "The lifecycle queue must differ from the scan trigger's SQS queue."],
  PERMISSION_SET_LOCKED: ["이 설치는 권한 세트를 설정에서 고정했습니다.", "This installation fixes the permission set in its configuration."],
  PERMISSION_SET_NOT_CHOSEN: ["권한 세트를 먼저 저장합니다.", "Save a permission set first."],
  AWS_INVENTORY_INVALID_SETTINGS: ["수집 설정을 확인합니다. 간격·기간·리전·계정·버킷과 prefix가 맞아야 합니다.", "Check the collection settings: the interval, window, Regions, accounts, bucket and prefixes."],
  AWS_SCANNER_IDENTITY_NOT_APPROVED: ["CreMore가 쓰는 AWS 신원을 먼저 승인합니다(AWS 연동의 연결 확인).", "Approve the AWS identity CreMore runs as first (Test connection in the AWS integration)."],
  IDENTITY_NOT_APPROVED: ["CreMore가 쓰는 AWS 신원을 먼저 승인합니다(AWS 연동의 연결 확인).", "Approve the AWS identity CreMore runs as first (Test connection in the AWS integration)."],
  AWS_ORGANIZATION_ID_INVALID: ["조직 ID는 o-로 시작하는 10~32자의 소문자·숫자입니다.", "An organization ID is o- followed by 10 to 32 lower-case letters or digits."],
  SSO_CACHE_NOT_WRITABLE: ["~/.aws/sso/cache에 쓸 수 없어 로그인을 이어 갈 수 없습니다.", "~/.aws/sso/cache cannot be written to keep the sign-in."],
  NOT_AN_IDENTITY_CENTER_IDENTITY: ["CreMore가 IAM Identity Center 권한 세트로 로그인해 있지 않습니다.", "CreMore is not signed in with an IAM Identity Center permission set."],
  IDENTITY_CENTER_START_URL_REQUIRED: ["AWS 프로필에 IAM Identity Center 시작 URL이 없습니다.", "The AWS profile has no IAM Identity Center start URL."],
  IDENTITY_CENTER_REGION_REQUIRED: ["AWS 프로필에 IAM Identity Center 리전이 없습니다.", "The AWS profile has no IAM Identity Center Region."],
  PERMISSION_SET_INVALID: ["저장된 권한 세트 이름이 올바르지 않습니다. 권한 세트를 다시 저장합니다.", "The saved permission set name is not valid. Save the permission set again."],
  AWS_REGION_INVALID: ["설치 설정 AWS_REGION이 AWS 리전 이름이 아닙니다.", "The installation's AWS_REGION is not an AWS Region name."],
  // Why CreMore cannot open a session in a key's account (cremore_aws_provider/aws_sessions.py, aws_access.py).
  ACCOUNT_OWNER_UNKNOWN: ["연결한 AWS 계정 가운데 이 키를 보고한 계정이 없습니다. 그 계정을 AWS 연동에 넣거나, 키 쌍 전체로 먼저 검증합니다.", "No connected AWS account reported this key. Add that account to an AWS integration, or verify the complete key pair first."],
  ACCOUNT_NOT_CONNECTED: ["이 키의 계정이 AWS 연동에 없습니다. 그 계정을 AWS 연동에 넣습니다.", "The key's account is not in an AWS integration. Add that account to one."],
  ACCOUNT_DISABLED: ["이 키의 계정은 AWS 연동에서 꺼져 있습니다.", "The key's account is turned off in its AWS integration."],
  ACCOUNT_NOT_VALIDATED: ["이 계정의 접근을 아직 확인하지 못했습니다. AWS 연동에서 권한을 다시 확인합니다.", "Access to this account is not confirmed yet. Check access again in the AWS integration."],
  REVALIDATION_REQUIRED: ["계정의 역할·ExternalId·권한 세트나 승인한 신원이 바뀌어 이 계정의 접근을 다시 확인해야 합니다.", "The account's role, ExternalId or permission set, or the approved identity, changed, so access to this account must be checked again."],
  ASSUME_ROLE_DENIED: ["이 계정의 역할을 맡지 못했습니다. 역할과 신뢰 정책을 확인합니다.", "The account's role could not be assumed. Check the role and its trust policy."],
  AWS_IDENTITY_CHANGED: ["CreMore의 AWS 신원이 승인한 신원과 다릅니다. 승인한 신원으로 다시 로그인하거나, AWS 연동의 연결 확인에서 지금 신원을 승인합니다.", "CreMore's AWS identity differs from the approved one. Sign in again as the approved identity, or approve the current one with Test connection in the AWS integration."],
  AWS_IDENTITY_UNAVAILABLE: ["CreMore의 AWS 신원을 확인하지 못했습니다. CreMore 실행 환경의 AWS 로그인과 프로필을 확인한 뒤 다시 시도합니다.", "CreMore's AWS identity could not be confirmed. Check the AWS sign-in and profile where CreMore runs, then try again."],
  ACCOUNT_MISMATCH: ["이 계정에서 얻은 신원이 다른 계정에 속해 있습니다. 등록한 계정 ID와 역할을 확인합니다.", "The identity obtained for this account belongs to a different account. Check the registered account ID and role."],
  ACCESS_NOT_CONFIGURED: ["이 계정에는 이 용도로 쓸 접근 방식(역할 또는 권한 세트)이 정해지지 않았습니다.", "This account has no access (a role or a permission set) set up for this purpose."],
  AWS_SSO_SESSION_UNKNOWN: ["승인할 때의 IAM Identity Center 디렉터리를 알 수 없습니다. 신원을 다시 승인합니다.", "The IAM Identity Center directory of the approval is unknown. Approve the identity again."],
  AWS_SSO_SESSION_CHANGED: ["IAM Identity Center 로그인이 승인한 디렉터리와 다릅니다.", "The IAM Identity Center sign-in is in a different directory from the approved one."],
  OUT_OF_DEPLOYMENT_SCOPE: ["이 계정은 Organizations 배포 범위 밖입니다.", "This account is outside the Organizations deployment scope."],
  ORG_ACCOUNT_REMOVED: ["이 계정은 AWS Organizations에서 빠졌습니다.", "This account has left the AWS Organization."],
  ORG_STATE_UNKNOWN: ["AWS Organizations가 이 계정의 상태를 알려 주지 않아 쓰지 않습니다.", "AWS Organizations did not report this account's state, so it is not used."],
  ORG_ACCOUNT_SUSPENDED: ["AWS Organizations에서 이 계정은 정지되어 있습니다.", "This account is suspended in AWS Organizations."],
  ORG_ACCOUNT_PENDING_CLOSURE: ["AWS Organizations에서 이 계정은 해지 대기 중입니다.", "This account is pending closure in AWS Organizations."],
  ORG_ACCOUNT_CLOSED: ["AWS Organizations에서 이 계정은 해지되었습니다.", "This account is closed in AWS Organizations."],
  ORG_ACCOUNT_PENDING_ACTIVATION: ["AWS Organizations에서 이 계정은 아직 활성화되지 않았습니다.", "This account is not activated yet in AWS Organizations."],
  SSO_ASSIGNMENT_REMOVED: ["IAM Identity Center 로그인에 이 계정이 더 이상 할당되어 있지 않습니다.", "The IAM Identity Center sign-in is no longer assigned to this account."],
  // Why an account's access is not checked (aws_access.validation_refusal) or moved (POST aws/accounts/{id}/promote).
  ORG_ACCOUNT_GONE: ["이 계정은 AWS Organizations에서 빠졌거나 해지되어 확인하지 않습니다.", "This account left or was closed in AWS Organizations, so it is not checked."],
  SSO_ASSIGNMENT_GONE: ["IAM Identity Center 로그인에 이 계정이 더 이상 할당되어 있지 않아 확인하지 않습니다.", "The IAM Identity Center sign-in is no longer assigned to this account, so it is not checked."],
  NOT_AN_IDENTITY_CENTER_ACCOUNT: ["IAM Identity Center 권한 세트로 닿는 계정만 멤버 역할로 바꿉니다.", "Only an account reached through an IAM Identity Center permission set is moved to a member role."],
  SSO_ROLE_NOT_ASSIGNED: ["이 계정에서 권한 세트로 자격증명을 받지 못했습니다. 권한 세트가 이 계정에 할당되어 있는지 확인합니다.", "No credentials could be obtained with the permission set in this account. Check that the permission set is assigned in it."],
  PERMISSION_SET_MISMATCH: ["받은 자격증명이 정해 둔 권한 세트와 다릅니다. AWS 연동에서 권한을 다시 확인합니다.", "The credentials received are a different permission set from the chosen one. Check access again in the AWS integration."],
  NO_PERMISSION_SET_RECORDED: ["이 계정에 쓸 권한 세트가 기록되어 있지 않습니다.", "No permission set is recorded for this account."],
  NO_ROLE_RECORDED: ["이 계정에 역할이 기록되어 있지 않습니다.", "No role is recorded for this account."],
  NO_EXTERNAL_ID: ["이 계정에 ExternalId가 기록되어 있지 않습니다.", "No ExternalId is recorded for this account."],
  CALLER_IDENTITY_FAILED: ["이 계정에서 얻은 신원을 읽지 못했습니다. AWS 연동에서 권한을 다시 확인합니다.", "The identity obtained for this account could not be read. Check access again in the AWS integration."],
  WORKER_AWS_NOT_CONFIGURED: ["작업자에 AWS 접근이 설정되어 있지 않습니다.", "The worker has no AWS access configured."],
  AWS_ACCESS_NOT_CONFIGURED: ["이 API에는 AWS 세션을 여는 설정이 없습니다.", "This API has no AWS session set up."],
  // An inventory or vault collection's run (cremore/api/metadata_coverage.py).
  CONNECTION_DISABLED_OR_MISSING: ["이 수집이 꺼져 있거나 없어졌습니다.", "This collection is turned off or gone."],
  GITHUB_EXPORT_QUOTA_WAIT: ["Enterprise 전체 인벤토리 생성 한도로 대기 중입니다. 수집 현황의 새 결과 생성 가능 시각 이후 다시 요청하세요.", "The Enterprise export allowance is exhausted. Request again after the next eligibility time shown in collection status."],
  GITHUB_EXPORT_SUBMISSION_UNKNOWN: ["이전 생성 요청의 결과를 확인하지 못했습니다. 중복 생성을 막기 위해 생성 가능 시각까지 기다립니다.", "The previous export submission could not be confirmed. Wait until the next eligibility time to avoid duplicate creation."],
  GITHUB_INVENTORY_API_CHANGED_RECOLLECT: ["GitHub 목록 API 변경으로 이전 수집을 종료했습니다. 기존 근거는 보존했습니다. 다시 수집하면 새 Export API로 시작합니다.", "The previous collection was closed because GitHub changed its inventory API. Evidence was preserved. Collect again to start with the Export API."],
  GITHUB_INSTALLATION_CHECK_NEEDS_A_FINISHED_COLLECTION: ["설치 확인은 지금 설정으로 끝난 수집이 있어야 합니다. 수집이 끝난 뒤 다시 확인합니다.", "An installation check needs a finished collection of the current settings. Check again once one has finished."],
  METADATA_COLLECTION_NOT_RUNNING: ["이 수집은 지금 진행 중이 아닙니다. 새로 불러와 상태를 확인합니다.", "This collection is not running now. Reload to see its state."],
  NATIVE_EXPORT_UNSUPPORTED: ["이 서비스의 수집은 원본 형식으로 내보내지 않습니다.", "This service's collection has no export in its own format."],
  NATIVE_EXPORT_LIMIT_USE_RECORD_PAGES: ["이 실행은 기록이 너무 많아(1만 건 또는 8MB 초과) 원본 형식으로 한 번에 내보내지 않습니다.", "This run holds too many records (over 10,000 or 8 MB) to export in the service's format at once."],
  USAGE_LOOKUP_OFF: ["실제 사용 내역 조회가 꺼져 있습니다. 관리자가 AWS 연동 설정의 '발견한 Credential 조사 기능'에서 켭니다.", "Observed use is off. An Admin turns it on in an AWS integration's settings, under 'Investigations of discovered credentials'."],
  SECRETS_INVENTORY_OFF: ["Secrets Manager 인벤토리가 꺼져 있습니다. 관리자가 AWS 연동 설정의 '발견한 Credential 조사 기능'에서 켭니다.", "The Secrets Manager inventory is off. An Admin turns it on in an AWS integration's settings, under 'Investigations of discovered credentials'."],
  SECRET_METADATA_UNAVAILABLE: ["AWS에서 이 Secret의 저장 정보를 읽지 못했습니다.", "AWS did not return this secret's storage details."],
  CONNECTION_REVISION_CONFLICT: ["수집 설정이 그사이 바뀌었습니다. 새로 불러온 뒤 다시 시도하세요.", "The collection changed in the meantime. Reload and try again."],
  MANAGEMENT_REVISION_CONFLICT: ["다른 관리자가 먼저 보관 위치를 바꿨습니다. 새로 불러온 뒤 다시 지정하세요.", "Another Admin changed where the key is kept first. Reload and set it again."],
};
// A request the API's schema refused (cremore/api/http_support.py), in words.
const INVALID_REQUEST = "request body or parameters are invalid";
// An AWS account CreMore may not use now (cremore/api/aws_support.py open_account_session): "<code>: AWS <purpose>
// access to account <id> is not available". A code not worded above still reads as a sentence, with the code.
const ACCOUNT_REFUSAL = /^([A-Z0-9_]+): AWS [a-z]+ access to account \S+ is not available$/;

/** A code an answer carries (not a refusal), in words; null when there are none for it. */
export function codeText(code: string | null | undefined, L: Say): string | null {
  const known = code ? REASONS[code] : undefined;
  return known ? L(known[0], known[1]) : null;
}

/** What a failed request means, in the reader's language. */
export function reasonCodeText(code: string, L: Say): string {
  const known = REASONS[code];
  return known ? L(...known) : code;
}

export function reasonText(error: unknown, L: Say): string {
  if (error instanceof DashboardAPIError) {
    const text = error.message || "";
    const code = text.split(":", 1)[0].trim();
    const known = REASONS[code];
    if (known) return L(known[0], known[1]);
    const refused = ACCOUNT_REFUSAL.exec(text)?.[1];
    if (refused) return L(`CreMore가 지금 이 AWS 계정을 쓸 수 없습니다 (${refused}).`, `CreMore cannot use this AWS account now (${refused}).`);
    if (error.status === 422 && text === INVALID_REQUEST) return L("입력한 값을 확인하세요.", "Check the values you entered.");
    // "SCAN_SCHEDULES_MODE=disabled locks …": an installation lock refused without a code of its own.
    if (/^[A-Z_]+_MODE=disabled\b/.test(text)) return L(`이 설치는 설정(${text.split("=", 1)[0]})에서 이 기능을 꺼 두었습니다.`, `This installation keeps this off in its configuration (${text.split("=", 1)[0]}).`);
    if (error.status === 401) return L("로그인이 필요합니다.", "Sign in again.");
    if (error.status === 403) return L("이 작업을 할 권한이 없습니다.", "You do not have permission for this.");
    if (error.status === 404) return L("찾을 수 없습니다.", "Not found.");
    if (error.status === 409) return text.includes(":") ? text.slice(text.indexOf(":") + 1).trim() : L("다른 작업과 충돌했습니다. 새로 불러온 뒤 다시 시도하세요.", "It conflicted with another change. Reload and try again.");
    if (error.status >= 500) return L("서버가 요청을 처리하지 못했습니다. 잠시 후 다시 시도하세요.", "The server could not complete the request. Try again shortly.");
    return text || L("요청을 처리하지 못했습니다.", "The request could not be completed.");
  }
  return L("서버에 연결하지 못했습니다.", "Could not reach the server.");
}
