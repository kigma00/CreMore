/* The overview's risk checks and counts, shared with the credential list's check filter. */

import type { IconName } from "@/console/icons";
import { type CredentialRecord, countable, ended, expSoon, hasWrite, isOpen, noExpiry, ownerless, recordStatus, stale } from "@/console/records";
import type { Say } from "@/console/text";
import { time } from "@/console/text";

export type CheckKey = "public" | "active" | "novault" | "org" | "write" | "noexp" | "soon" | "stale" | "noowner";

export type Check = { key: CheckKey; icon: IconName; hot: boolean; title: (L: Say) => string; tip: (L: Say) => string; test: (c: CredentialRecord, now: number) => boolean };

export const CHECKS: Check[] = [
  { key: "public", icon: "globe", hot: true, title: L => L("공개 위치에 노출", "Exposed in public locations"),
    tip: L => L("로그인 없이 볼 수 있는 저장소·페이지에서 발견된 Credential입니다.", "Found in repositories or pages anyone can see without signing in."),
    test: c => isOpen(c) && c.exposures.some(e => e.current && e.visibility === "public") },
  { key: "active", icon: "alert", hot: true, title: L => L("활성 확인된 노출", "Exposed and confirmed active"),
    tip: L => L("노출된 뒤 발급 서비스에 조회해 지금도 인증되는 것을 확인했습니다.", "The issuer confirmed these still authenticate after exposure."),
    test: c => isOpen(c) && c.verification.state === "active" },
  { key: "novault", icon: "vault", hot: true, title: L => L("Vault에 없는 노출", "Exposed and not in Vault"),
    tip: L => L("노출됐는데 연결한 Vault에서 같은 값을 찾지 못했습니다. 교체한 값은 Vault에 넣어야 합니다.", "The connected Vaults don't hold these exposed values. Put the replacement in Vault."),
    test: c => isOpen(c) && c.vault.state === "none" },
  { key: "org", icon: "users", hot: false, title: L => L("조직 전체 공유 문서에 노출", "Exposed in org-wide documents"),
    tip: L => L("Notion·Confluence처럼 조직 전체가 볼 수 있는 문서에서 발견됐습니다.", "Found in Notion or Confluence documents the whole organization can open."),
    test: c => isOpen(c) && c.exposures.some(e => e.current && e.visibility === "org") },
  { key: "write", icon: "key", hot: false, title: L => L("쓰기·관리 권한 보유", "Write or admin access"),
    tip: L => L("코드 push, 결제, 배포처럼 변경할 수 있는 권한이 있는 Credential입니다.", "Credentials that can change code, payments or deployments."),
    test: c => hasWrite(c) && !ended(c) && c.status !== "fp" },
  { key: "noexp", icon: "hourglass", hot: false, title: L => L("만료일 없음", "No expiry date"),
    tip: L => L("발급 서비스가 만료일을 두지 않았거나 만료일 없이 발급했습니다.", "The issuer set no expiry, or it was issued without one."),
    test: c => noExpiry(c) },
  { key: "soon", icon: "clock", hot: false, title: L => L("30일 안에 만료", "Expires within 30 days"),
    tip: L => L("곧 만료되어 교체 계획이 필요한 Credential입니다.", "Expiring soon and needing a rotation plan."),
    test: (c, now) => expSoon(c, now) },
  { key: "stale", icon: "sleep", hot: false, title: L => L("90일 이상 미사용", "Unused for 90+ days"),
    tip: L => L("사용 기록을 수집한 서비스에서 90일 넘게 쓰이지 않았습니다. 폐기 후보입니다.", "Not used for over 90 days in services that report usage. Candidates for revocation."),
    test: (c, now) => stale(c, now) },
  { key: "noowner", icon: "userQ", hot: false, title: L => L("소유자 미확인", "Owner unknown"),
    tip: L => L("대응 담당자를 찾지 못했습니다. 발급자나 노출 위치 작성자에게 먼저 문의하세요.", "No response owner found. Ask the issuer or the author of the exposed location first."),
    test: c => ownerless(c) && !ended(c) && c.status !== "fp" },
];

export const CHECK_BY = Object.fromEntries(CHECKS.map(check => [check.key, check])) as Record<CheckKey, Check>;

export function isCheck(value: string | null): value is CheckKey {
  return Boolean(value && value in CHECK_BY);
}

export type Stats = {
  total: number; exposed: number; open: number; token: number; apikey: number; cloud: number; other: number; vault: number;
  done: number; review: number; action: number; pending: number; pendingNoOwner: number; fp: number;
};

export function stats(items: CredentialRecord[]): Stats {
  const exposed = items.filter(countable);
  return {
    total: items.length, exposed: exposed.length, open: items.filter(isOpen).length,
    token: items.filter(c => c.kind === "token").length, apikey: items.filter(c => c.kind === "apikey").length,
    cloud: items.filter(c => c.kind === "cloud").length, other: items.filter(c => c.kind === "other").length,
    vault: items.filter(c => c.vault.state === "stored").length,
    done: exposed.filter(c => recordStatus(c) === "done" || recordStatus(c) === "ignored").length,
    review: exposed.filter(c => recordStatus(c) === "review").length,
    action: exposed.filter(c => recordStatus(c) === "action").length,
    pending: exposed.filter(c => recordStatus(c) === "pending").length,
    pendingNoOwner: exposed.filter(c => recordStatus(c) === "pending" && ownerless(c)).length,
    fp: items.filter(c => c.status === "fp").length,
  };
}

/** Past points estimate first-found/closed dates; the final point is the current authoritative open count. */
export function openTrend(items: CredentialRecord[], now = Date.now(), weeks = 8): number[] {
  const week = 7 * 86_400_000;
  return Array.from({ length: weeks }, (_, index) => {
    const end = now - (weeks - 1 - index) * week;
    if (index === weeks - 1) return items.filter(isOpen).length;
    return items.filter(c => {
      if (!c.exposed) return false;
      const found = time(c.first_seen_at);
      if (found === null || found > end) return false;
      const closed = time(c.resolved_at);
      return closed === null || closed > end;
    }).length;
  });
}
