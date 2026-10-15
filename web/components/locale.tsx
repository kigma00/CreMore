/* Which language the dashboard is speaking, and the words it uses for the
 * codes the API returns.
 *
 * Every user-facing string is written at its call site in both languages --
 * `localize(locale, english, korean)` -- so a reader sees what a screen
 * actually says rather than a key to look up elsewhere. Only the API's own
 * enumerations are tabulated here, because the same code appears on many
 * screens and must read the same way on each.
 *
 * `enumLabel` falls back to the raw code. An untranslated status is then
 * visible as itself rather than as a blank or a wrong word.
 */

import { createContext, useContext } from "react";

import { formatDisplayTimestamp } from "@/components/display-timezone";

export type Locale = "ko" | "en";

export const LocaleContext = createContext<Locale>("ko");

export const localize = (locale: Locale, english: string, korean: string) =>
  locale === "ko" ? korean : english;

export function useLocale() {
  return useContext(LocaleContext);
}

export const localizedEnums: Record<string, string> = {
  ACTIVE: "활성",
  ENABLED: "사용 중",
  ACTION_REQUIRED: "조치 필요",
  CANCELLED: "취소됨",
  CAPPED: "한도 도달",
  COMPLETE: "완료",
  COMPLETED: "완료",
  CONNECTED: "연결됨",
  CRITICAL: "심각",
  DISABLED: "비활성",
  DETECTED: "탐지됨",
  FAILED: "실패",
  FALSE_POSITIVE: "오탐",
  HIGH: "높음",
  IGNORED: "제외됨",
  INACTIVE: "비활성",
  INVALID: "유효하지 않음",
  ISOLATED: "분리됨",
  LEARNING: "학습 중",
  LOW: "낮음",
  MEDIUM: "보통",
  NOT_CONFIGURED: "미설정",
  PARTIAL: "일부 완료",
  PENDING: "확인 중",
  PROFILE_READY: "프로필 준비",
  REGISTERED: "등록됨",
  DASHBOARD_UNSUPPORTED: "대시보드 실행 미지원",
  QUEUED: "대기 중",
  READY: "준비됨",
  ACCOUNT_UNVERIFIED: "계정 미확인",
  LOGIN_REQUIRED: "로그인 필요",
  ERROR: "오류",
  NO_CREDENTIALS: "AWS 로그인 없음",
  REMOVED: "제거됨",
  RESOLVED: "해결됨",
  RUNNING: "실행 중",
  SUPERVISED: "관리 중",
  UNKNOWN: "확인 안 됨",
  VALID: "유효",
  VERIFIED: "검증됨",
  NOT_VERIFIED: "미검증",
  RESTRICTED: "권한 제한",
  REJECTED: "인증 거부",
  INDETERMINATE: "판정 불가",
  UNSUPPORTED: "미지원",
  REVOKED: "연결 사용 중단",
  EXPIRED: "만료됨",
  EXPIRING_SOON: "곧 만료",
  SCANNING: "스캔 중",
  ENRICHING: "정보 보강 중",
  CANCELLING: "중지 요청 중",
  BATCH: "일괄 수집",
  STREAM: "연속 수집",
  INPUT: "입력 수집",
  COMPOSITE: "복합 수집",
  ANALYSIS: "분석",
  INVENTORY: "조직 인벤토리",
  OBSERVED: "실제 관측",
  INFERRED: "추론",
  POTENTIAL: "잠재 권한",
  READ: "읽기",
  WRITE: "쓰기",
  SUCCEEDED: "성공",
  DENIED: "거부됨",
  REMEDIATING: "조치 중",
  OPEN: "미해결",
  TRIAGED: "분류 완료",
  NOT_COLLECTED: "미수집",
  NOT_FOUND_OR_NOT_VISIBLE: "없음 또는 접근 불가 · 미확인",
  MANAGEMENT: "관리 이벤트",
  DATA: "데이터 이벤트",
  EVENT_HISTORY: "이벤트 기록",
  CLOUDTRAIL_LAKE: "CloudTrail Lake",
  OPTIONAL: "선택 기능",
  EXPOSURE: "노출 지점",
  CREDENTIAL: "자격증명",
  SESSION: "세션",
  IDENTITY: "인증 주체",
  WORKLOAD: "워크로드",
  ACTION: "작업",
  RESOURCE: "리소스",
};

export function enumLabel(value: string, locale: Locale) {
  const normalized = value.toUpperCase();
  return locale === "ko"
    ? localizedEnums[normalized] || value.replaceAll("_", " ")
    : value.toLowerCase().replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase());
}

export function when(value?: string, locale: Locale = "en") {
  return formatDisplayTimestamp(value, locale);
}

export function bytes(value: number) {
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let n = value / 1024,
    i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(n < 10 ? 1 : 0)} ${units[i]}`;
}
