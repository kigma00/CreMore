/* Risk rules and remediation guides for one credential, from the evidence its row carries.
 * A rule without evidence stays visible as "no evidence yet" rather than being dropped. */

import { serviceName } from "@/console/logos";
import { awsPermissionEvidence, type CredentialRecord, ended, expSoon, hasWrite, lastUseGap, noExpiry, ownerless, revoked, stale, worstVis } from "@/console/records";
import { DAY, fmtDT, rel, time, type Say } from "@/console/text";
import type { Locale } from "@/components/locale";
// The same file ships with the server (cremore/governance/remediation_guides.json) so requests can carry the playbook.
import guides from "@/console/views/credentials/guides.json";

export type Axis = "exposure" | "likelihood" | "unknown";
export type Tone = "bad" | "warn" | "good" | "unknown";
export type Remedy = "revoke" | "cleanup" | "vault" | "scope";
export type Rule = { id: string; axis: Axis; tone: Tone; label: string; desc: string; cat: string; evidence: string; remedy: Remedy | null };

/* ---------- risk score evidence (cremore/risk/model.py) ---------- */

const SCORE_DIMENSION: Record<string, [string, string]> = {
  exploitability: ["악용 가능성", "Exploitability"], credential_impact: ["Credential 영향", "Credential impact"],
  privilege_scope: ["권한 범위", "Privilege scope"], exposure: ["노출 정도", "Exposure"],
};
const SCORE_REASON: Record<string, [string, string]> = {
  verification_valid: ["검증에서 활성 확인", "Confirmed active by verification"],
  verification_restricted: ["검증에서 제한된 활성 확인", "Confirmed active with restrictions"],
  verification_unknown: ["검증 결과를 판정하지 못함", "Verification was inconclusive"],
  verification_not_attempted: ["유효성 검증을 하지 않음", "Not verified"],
  verification_invalid: ["검증에서 무효 확인", "Confirmed invalid"],
  verification_expired: ["검증에서 만료 확인", "Confirmed expired"],
  aws_root_principal: ["AWS 루트 계정으로 인증됨", "Authenticates as the AWS root principal"],
  aws_iam_privilege_escalation_allowed: ["시뮬레이션에서 권한 상승 동작 허용", "Simulation allows privilege escalation"],
  aws_iam_high_impact_actions_allowed: ["시뮬레이션에서 삭제·비밀 읽기·코드 변경 허용", "Simulation allows destructive, secret-reading or code-changing actions"],
  aws_iam_write_actions_allowed: ["시뮬레이션에서 쓰기·생성·실행 허용", "Simulation allows write, create or execute actions"],
  aws_iam_read_only_actions_allowed: ["시뮬레이션한 작업 중 읽기만 허용", "Only reads allowed among simulated actions"],
  aws_iam_no_high_impact_actions_allowed: ["시뮬레이션한 고위험 작업 허용 없음", "No simulated high-impact action allowed"],
  github_limited_scope: ["제한된 GitHub 권한", "Limited GitHub scopes"],
  github_broad_or_admin_scope: ["광범위·관리자 GitHub 권한", "Broad or admin GitHub scope"],
  github_write_scope: ["GitHub 쓰기 권한", "GitHub write scope"],
  github_sensitive_scope: ["민감한 GitHub 기능 권한", "Sensitive GitHub feature scope"],
  github_scope_semantics_incomplete: ["해석 규칙이 없는 GitHub 권한 포함", "Includes GitHub scopes without a reviewed rule"],
  provider_scope_semantics_not_implemented: ["이 서비스의 권한 해석 규칙 없음", "No rule reads this provider's permissions"],
  privilege_scope_unknown: ["권한 위험도를 평가할 근거 부족", "Insufficient evidence to score permission risk"],
  direct_public_exposure: ["공개 위치에 노출", "In a public location"],
  inherited_public_exposure: ["상위 설정으로 공개된 위치에 노출", "Public through an inherited setting"],
  internal_plaintext_exposure: ["내부 위치에 평문으로 노출", "Plaintext in an internal location"],
  exposure_unknown: ["도달 범위를 판정하지 못함", "Reachability undetermined"],
};
const SCORE_MISSING: Record<string, [string, string]> = {
  exposure_not_observed: ["노출 도달 범위", "Exposure reachability"],
  provider_permission_interpretation_structure_insufficient: ["권한 위험도 평가 근거", "Evidence for permission risk scoring"],
  provider_permission_interpreter_implementation_required: ["권한 해석 규칙", "A permission interpretation rule"],
  aws_secret_component_not_observed: ["AWS 시크릿 키 관측", "The AWS secret key"],
  aws_identifier_not_observed: ["AWS 키 ID 관측", "The AWS key ID"],
  provider_validity_not_confirmed: ["발급 서비스의 유효성 확인", "Validity from the issuer"],
};

/** One scored line ("exposure 2/15 exposure_unknown") in the reader's words. */
export function scoreLine(line: string, L: Say, typeName: (type: string) => string) {
  const [dimension = "", points = "", ...rest] = line.split(" ");
  let reason = rest.join(" ");
  const several = reason.endsWith("_multiple_occurrences");
  if (several) reason = reason.slice(0, -"_multiple_occurrences".length);
  const known = SCORE_REASON[reason];
  const text = known ? L(known[0], known[1])
    : reason.startsWith("credential_type_") ? L(`${typeName(reason.slice(16).toUpperCase())} 유형`, `${typeName(reason.slice(16).toUpperCase())} type`)
      : reason.replaceAll("_", " ");
  return { dimension: L(...(SCORE_DIMENSION[dimension] ?? [dimension, dimension])), points, text: text + (several ? L(" · 여러 곳", " · several places") : "") };
}

export function missingEvidence(code: string, L: Say) {
  const known = SCORE_MISSING[code.toLowerCase()];
  return known ? L(known[0], known[1]) : code.toLowerCase().replaceAll("_", " ");
}

// Sources that keep earlier versions: git history and page history.
const VERSIONED = new Set(["github", "gitlab", "bitbucket", "azure_devops", "notion", "confluence"]);

export function inHistory(sourceType: string) {
  return VERSIONED.has(sourceType);
}

const ACCESS_BASIS: Record<string, [string, string]> = {
  GITHUB_REPOSITORY_COLLABORATORS: ["GitHub 저장소 협업자 목록", "GitHub repository collaborators"],
  GITLAB_PROJECT_MEMBERS: ["GitLab 프로젝트 멤버 목록", "GitLab project members"],
  CONFLUENCE_PAGE_RESTRICTIONS: ["Confluence 페이지 제한 목록", "Confluence page restrictions"],
  BITBUCKET_REPOSITORY_PERMISSIONS: ["Bitbucket 저장소 권한 목록", "Bitbucket repository permissions"],
  AZURE_DEVOPS_REPOSITORY_ACL: ["Azure DevOps 저장소 ACL", "Azure DevOps repository ACL"],
  GCS_BUCKET_IAM_OBJECT_ACL: ["GCS 버킷 IAM·개체 ACL", "GCS bucket IAM and object ACL"],
  AWS_S3_POLICY_ACL: ["AWS S3 정책·ACL", "AWS S3 policy and ACL"],
  AZURE_BLOB_CONTAINER_ACCESS: ["Azure Blob 컨테이너 접근 설정", "Azure Blob container access configuration"],
};

/** Where a list of people with access came from, in words. */
export function accessBasis(basis: string | null | undefined, L: Say): string {
  return L(...(ACCESS_BASIS[basis ?? ""] ?? ["코드 호스트 목록", "Code host list"]));
}

/** Why this person or team is the response owner, in words. */
export function ownerBasis(c: CredentialRecord, L: Say): string {
  const basis = c.owner?.basis;
  return basis === "ASSIGNED" ? L("관리자 지정", "Assigned by an analyst") : basis === "BUSINESS_OWNER" ? L("업무 소유자로 등록", "Registered business owner")
    : basis === "CODEOWNERS" ? `CODEOWNERS${c.owner?.where ? ` · ${c.owner.where}` : ""}` : L("담당 팀", "Responsible team");
}

export function verifyBasis(c: CredentialRecord, L: Say): string {
  const service = serviceName(c.provider);
  const { state, basis, reason } = c.verification;
  if (!c.exposed && state === "unknown") return L("노출되지 않아 검증 대상 아님", "Not exposed, so not verified");
  if (basis === "ISSUER_REPORTED") return L(`${service} 발급 목록의 상태`, `State in the ${service} inventory`);
  if (basis === "LINKED_PAIR_ACTIVE_VERIFICATION") return L("같은 키 쌍의 인증 확인", "Authentication check of the same key pair");
  if (reason === "NOT_REQUESTED") return L("발견 Credential 검증이 꺼져 있음", "Discovered-credential verification is off");
  if (reason && /ONLY$/.test(reason)) return L("키의 일부만 노출돼 검증할 수 없음", "Only part of the key was exposed, so it cannot be verified");
  if (reason && reason.includes("NOT_SUPPORTED")) return L("이 유형은 검증하지 않음", "This type is not verified");
  if (basis === "ACTIVE_VERIFICATION") {
    if (state === "active") return L(`${service} 인증 확인`, `${service} authentication check`);
    if (state === "failed") return L(`${service}이(가) 인증을 거부함`, `${service} rejected authentication`);
    if (state === "expired") return L(`${service}에서 만료로 확인`, `${service} reports it expired`);
    return L(`${service} 검증 결과를 판정하지 못함`, `${service} verification was inconclusive`);
  }
  if (basis === "IAM_OWNER_LOOKUP") return L("소유 계정의 IAM 기록", "IAM record of the owning account");
  if (basis === "IAM_INVENTORY") return L("IAM 발급 목록", "IAM inventory");
  return L("검증 기록 없음", "No verification record");
}

export function usageBasis(c: CredentialRecord, L: Say): string {
  if (!c.last_used) return usageGap(c, L);
  if (c.last_used.basis === "ISSUER_REPORTED") return L(`${serviceName(c.provider)} 발급 목록의 마지막 사용 시각`, `Last use in the ${serviceName(c.provider)} inventory`);
  if (c.last_used.basis === "METRIC_INTERVAL") return L("사용량이 관측된 마지막 구간의 끝입니다. 정확한 호출 시각은 아닙니다.", "End of the last observed positive metric interval, not an exact request time.");
  if (c.last_used.basis === "AUDIT_OBSERVED") return L("수집한 감사 로그가 이 자격증명을 명시한 마지막 사용입니다. 전체 사용 이력을 보장하지 않습니다.", "Last collected audit use explicitly naming this credential, not a complete use history.");
  return L(`${serviceName(c.provider)} 사용 기록`, `${serviceName(c.provider)} usage record`);
}

export function usageGap(c: CredentialRecord, L: Say): string {
  if (c.issued?.provider === "aws_iam" && c.issued.last_used_status === "NO_INFORMATION") return L("IAM 조회는 완료됐지만 마지막 사용 시각이 없습니다. 아직 사용하지 않았거나 IAM 추적 범위에 기록이 없을 수 있습니다.", "IAM lookup completed without a last-use timestamp. The key may be unused, or no use was recorded within IAM tracking.");
  const reason = lastUseGap(c, L);
  if (reason) return reason;
  return c.issued ? L(`${serviceName(c.provider)} 발급 목록에 사용 기록이 없음`, `The ${serviceName(c.provider)} inventory reports no usage`)
    : L(`${serviceName(c.provider)} 사용 기록을 연결하지 않음`, `${serviceName(c.provider)} usage logs are not connected`);
}

export function vaultWhere(c: CredentialRecord): string {
  return c.vault.where.map(place => [serviceName(place.provider, place.provider), place.reference || place.connection].filter(Boolean).join(" · ")).join(", ");
}

export function rulesFor(c: CredentialRecord, L: Say, locale: Locale, now = Date.now()): Rule[] {
  const rules: Rule[] = [];
  const iam = awsPermissionEvidence(c);
  const add = (axis: Axis, tone: Tone, label: string, desc: string, cat: string, evidence: string, remedy: Remedy | null) =>
    rules.push({ id: `${c.id}:${rules.length}`, axis, tone, label, desc, cat, evidence, remedy });
  const SCOPE = L("노출 범위", "Exposure scope"), VALID = L("유효성", "Validity"), PERM = L("권한", "Permissions"),
    LIFE = L("수명", "Lifetime"), USE = L("사용", "Usage"), MGMT = L("관리", "Management"), OWN = L("책임", "Ownership");
  const current = c.exposures.filter(e => e.current);
  const vis = worstVis(c);
  const first = current.map(e => e.first_seen_at).filter(Boolean).sort()[0] ?? null;
  if (vis === "public") add("exposure", "bad", L("공개 위치에 노출", "Exposed in a public location"), L("로그인 없이 누구나 볼 수 있는 위치에서 값이 발견됐습니다. 이미 복사됐다고 보고 폐기해야 합니다.", "Found where anyone can see it without signing in. Assume it was copied and revoke it."), SCOPE, `${L("노출 검사", "Exposure scan")} · ${fmtDT(first, locale)}`, "revoke");
  if (vis === "org") add("exposure", "warn", L("조직 전체가 볼 수 있는 문서", "Document visible to the whole org"), L("조직 구성원 누구나 볼 수 있는 문서에 값이 있습니다.", "The value sits in a document every member can open."), SCOPE, L("노출 검사 · 공유 설정 조회", "Exposure scan · sharing settings"), "cleanup");
  if (vis === "internal") add("exposure", "warn", L("그룹 내부 위치에 노출", "Exposed inside a group"), L("그룹 구성원이 볼 수 있는 저장소에 값이 있습니다.", "The value is in a repository group members can see."), SCOPE, L("노출 검사 · 프로젝트 공개 범위", "Exposure scan · project visibility"), "cleanup");
  if (vis === "private") add("exposure", "good", L("접근이 제한된 위치", "Restricted location"), L("비공개 저장소·버킷이라 볼 수 있는 사람이 제한됩니다.", "A private repository or bucket, so few people can see it."), SCOPE, L("노출 검사 · 위치 공개 범위", "Exposure scan · location visibility"), null);
  if (current.some(e => inHistory(e.source_type))) add("exposure", "warn", L("변경 이력에 남음", "Kept in change history"), L("파일이나 페이지에서 지워도 이전 커밋·페이지 기록으로 볼 수 있습니다.", "Deleting it from the file or page still leaves it in earlier commits or page history."), SCOPE, L("노출 검사 · 이력을 보관하는 위치", "Exposure scan · a location that keeps history"), "cleanup");
  if (current.length > 1) add("exposure", "warn", L(`여러 위치에 노출 (${current.length}곳)`, `Exposed in ${current.length} places`), L("같은 값이 서로 다른 위치에서 발견됐습니다. 모두 정리해야 합니다.", "The same value was found in several places. Every one needs cleanup."), SCOPE, L("노출 검사", "Exposure scan"), "cleanup");
  const verifyAt = c.verification.at ? ` · ${fmtDT(c.verification.at, locale)}` : "";
  if (c.verification.state === "active") add("likelihood", "bad", L("활성 상태 확인", "Confirmed active"), L("발급 서비스에 조회해 지금도 인증되는 것을 확인했습니다.", "The issuer confirmed it still authenticates."), VALID, verifyBasis(c, L) + verifyAt, "revoke");
  if (c.verification.state === "revoked") add("likelihood", "good", L("폐기 확인", "Revocation confirmed"), L("발급 서비스에서 더 이상 인증되지 않습니다.", "The issuer no longer accepts it."), VALID, verifyBasis(c, L) + verifyAt, null);
  if (c.verification.state === "failed") add("likelihood", "good", L("인증 실패", "Authentication failed"), L("발급 서비스가 이 값을 거부했습니다. 예시 값이거나 이미 폐기된 값입니다.", "The issuer rejected this value. It is an example or already revoked."), VALID, verifyBasis(c, L) + verifyAt, null);
  if (c.verification.state === "inactive") add("likelihood", "good", L("비활성 상태", "Inactive"), L("발급 서비스에서 비활성으로 표시돼 있습니다.", "The issuer marks it inactive."), VALID, verifyBasis(c, L) + verifyAt, null);
  if (c.verification.state === "expired") add("likelihood", "good", L("만료됨", "Expired"), L("만료돼 더 이상 인증되지 않습니다.", "It has expired and no longer authenticates."), VALID, verifyBasis(c, L) + verifyAt, null);
  if (c.scopes?.length && hasWrite(c) && !revoked(c)) add("likelihood", "warn", L("쓰기·관리 scope 관측", "Write or admin scopes observed"), `${L("발급자가 보고한 scope입니다. 대상 리소스·정책·조건에 따라 실제 접근이 달라집니다: ", "Issuer-reported scopes; actual access depends on resources, policies and conditions: ")}${c.scopes.filter(s => s.write).map(s => s.name).join(", ")}`, PERM, L("발급 서비스의 권한 정보", "Permission info from the issuer"), "scope");
  if (c.scopes?.length && !hasWrite(c)) add("likelihood", "unknown", L("읽기 scope 관측", "Read scopes observed"), L("보고된 scope에서 쓰기 항목을 식별하지 못했습니다. 실제 쓰기 권한이 없다는 보장은 아닙니다.", "No write scope was identified in the reported scopes. This does not prove an absence of effective write access."), PERM, L("발급 서비스의 권한 정보", "Permission info from the issuer"), null);
  if (noExpiry(c)) add("likelihood", "warn", L("만료일 없음", "No expiry date"), L("직접 폐기하기 전까지 계속 쓸 수 있습니다.", "It keeps working until someone revokes it."), LIFE, L("발급 목록의 만료일 필드", "Expiry field in the issuance inventory"), "scope");
  if (expSoon(c, now)) {
    const days = Math.ceil(((time(c.expires_at) ?? now) - now) / DAY);
    add("likelihood", "good", L(`${days}일 뒤 만료`, `Expires in ${days} days`), L("만료일이 가까워 노출 기간이 짧습니다.", "The expiry is close, which keeps the exposure window short."), LIFE, L("발급 목록의 만료일 필드", "Expiry field in the issuance inventory"), null);
  }
  const used = time(c.last_used?.at);
  if (used !== null && now - used < 7 * DAY) add("likelihood", "warn", L(`최근 사용 (${rel(c.last_used!.at, locale, now)})`, `Used recently (${rel(c.last_used!.at, locale, now)})`), L("최근에도 쓰이고 있어 폐기 전에 사용처를 확인해야 합니다.", "It is still in use, so find where before revoking it."), USE, usageBasis(c, L), "revoke");
  if (stale(c, now)) add("likelihood", "warn", L("90일 이상 미사용", "Unused for 90+ days"), L("오래 쓰이지 않았습니다. 폐기해도 영향이 적을 가능성이 큽니다.", "Unused for a long time. Revoking it is likely low impact."), USE, usageBasis(c, L), "revoke");
  if (c.vault.state === "stored") add("likelihood", "good", L("Vault에서 관리 중", "Managed in Vault"), L("Vault에 같은 값이 있어 교체할 때 사용처를 빨리 찾을 수 있습니다.", "Vault holds the same value, so its users are quick to find when rotating."), MGMT, vaultWhere(c), null);
  if (c.vault.state === "none" && !revoked(c)) add("likelihood", "warn", L("Vault에 없음", "Not in Vault"), L("연결한 Vault에서 같은 값을 찾지 못했습니다. 사용처를 파악하기 어렵습니다.", "The connected Vaults don't hold this value, which makes its users hard to find."), MGMT, L("연결한 Vault와의 지문 대조", "Fingerprint matching against the connected vaults"), "vault");
  if (c.verification.state === "unknown" && c.exposed) add("unknown", "unknown", L("활성 여부 미확인", "Activity unknown"), L("검증하지 않았습니다. 비활성이라고 판단하지 마세요.", "Not verified. Do not treat it as inactive."), VALID, verifyBasis(c, L), null);
  if (iam.policyObserved) add("likelihood", iam.broadPolicy ? "warn" : "unknown",
    iam.broadPolicy ? L("광범위 IAM 정책 관측", "Broad IAM policy observed") : L("IAM 정책 관측", "IAM policies observed"),
    L("주체에 연결된 정책입니다. 거부 정책·조건·권한 경계·SCP를 반영한 실제 접근 권한과는 다릅니다.", "Attached policies; effective access also depends on denies, conditions, boundaries and SCPs."),
    PERM, `${iam.policies.join(", ") || L("연결 정책 없음", "No attached policies")}${iam.historical ? L(" · 과거 관측", " · historical") : iam.partial ? L(" · 부분 수집", " · partial") : ""}`, "scope");
  if (iam.simulationObserved) add("likelihood", iam.actions.some(a => a.risk !== "READ") ? "warn" : "unknown",
    L("정책 시뮬레이션 수집됨", "Policy simulation collected"),
    L("리소스 *와 요청 조건 없는 시뮬레이션입니다. 조건 누락·리소스 정책·SCP·세션·KMS의 미평가 근거는 권한 상세에서 확인하세요. 실제 접근이나 낮은 권한을 확정하지 않습니다.", "Simulation on resource * without request context. Review missing context and unevaluated resource policies, SCPs, session and KMS evidence in permission details. This does not establish effective access or low privilege."),
    PERM, L(`시뮬레이션 결과${iam.partial ? " · 부분 수집" : ""}`, `Simulation results${iam.partial ? " · partial" : ""}`), "scope");
  if (!c.scopes?.length && !iam.policyObserved && !iam.simulationObserved) add("unknown", "unknown", L("권한 범위 미확인", "Permissions unknown"), L("발급 서비스에서 권한 정보를 받지 못했습니다.", "The issuer provided no permission info."), PERM, c.issued ? L("발급 목록에 권한 정보 없음", "No permission info in the inventory") : L("발급 목록 없음", "No issuance inventory"), null);
  if (!c.last_used && !ended(c)) add("unknown", "unknown", c.issued?.provider === "aws_iam" && c.issued.last_used_status === "NO_INFORMATION" ? L("마지막 사용 시각 없음", "No last-use timestamp") : L("마지막 사용 미확인", "Last use unknown"), usageGap(c, L), USE, usageGap(c, L), null);
  if (ownerless(c) && !ended(c)) add("unknown", "unknown", L("대응 담당자 미확인", "Response owner unknown"), L("대응 담당자를 찾지 못했습니다.", "No response owner was found."), OWN, L("CODEOWNERS·태그·관리자 지정 없음", "No CODEOWNERS, tag or admin assignment"), null);
  if (c.vault.state === "unknown") add("unknown", "unknown", L("Vault 보관 미확인", "Vault storage unknown"), vaultUnknownText(c, L), MGMT, vaultUnknownText(c, L), null);
  return rules;
}

function vaultUnknownText(c: CredentialRecord, L: Say) {
  const reasons = c.vault.reasons;
  if (reasons.includes("NO_VAULT_CONNECTED")) return L("연결한 Vault가 없습니다.", "No vault is connected.");
  if (reasons.includes("VAULT_SCOPE_NOT_CONFIRMED")) return L("Vault 대조 범위를 아직 확정하지 않았습니다.", "The vault matching scope is not confirmed yet.");
  if (reasons.some(r => r.startsWith("PARTIAL_AWS"))) return L("키의 일부만 노출돼 대조하지 않았습니다.", "Only part of the key was exposed, so it was not matched.");
  if (c.vault.basis === "NOT_COMPARED") return L("이 항목은 Vault와 대조하지 않았습니다.", "This item is not matched against Vault.");
  return L("Vault 대조를 마치지 못했습니다.", "Vault matching has not finished.");
}

export function axisLevel(rules: Rule[], axis: Axis, L: Say): { cls: string; text: string } {
  const list = rules.filter(rule => rule.axis === axis);
  const bad = list.filter(rule => rule.tone === "bad").length, warn = list.filter(rule => rule.tone === "warn").length;
  if (!list.length) return { cls: "l-none", text: L("근거 없음", "No evidence") };
  if (bad >= 1 && bad + warn >= 2) return { cls: "l-high", text: L("높음", "High") };
  if (bad >= 1 || warn >= 2) return { cls: "l-mid", text: L("보통", "Medium") };
  return { cls: "l-low", text: L("낮음", "Low") };
}

type Pair = [string, string];
type Guide = { title: Pair; link: [string, string, string] | null; steps: Pair[] };

// Revocation guides by issuer. {name} is the credential, {issuer} its issuing account, {hint} its masked value.
// JSON arrays are typed as string[]; the file's shape is checked by the server's playbook test.
const GUIDES = guides as unknown as { revoke: Record<string, Guide>; generic: Guide;
  cleanup: Record<"git" | "doc" | "bucket" | "web", Pair[]>; vault: Pair[]; scope: Pair[] };
const { revoke: REVOKE, generic: GENERIC, cleanup: CLEANUP, vault: VAULT_STEPS, scope: SCOPE_STEPS } = GUIDES;

export type RemedItem = { id: Remedy; title: string; rule: string; people: string[]; steps: string[]; link: [string, string] | null };

export function locKind(sourceType: string): "git" | "doc" | "bucket" | "web" {
  if (["github", "gitlab", "bitbucket", "azure_devops"].includes(sourceType)) return "git";
  if (["notion", "confluence"].includes(sourceType)) return "doc";
  if (sourceType === "website") return "web";
  return "bucket";
}

export function remediationFor(c: CredentialRecord, L: Say): RemedItem[] {
  const pick = (pair: [string, string]) => L(pair[0], pair[1]);
  const items: RemedItem[] = [];
  const owner = c.owner?.name ? [c.owner.name] : [];
  if (!["revoked", "failed", "inactive", "expired"].includes(c.verification.state)) {
    const guide = REVOKE[c.provider] ?? GENERIC;
    items.push({ id: "revoke", title: pick(guide.title), rule: c.verification.state === "active" ? L("활성 상태 확인", "Confirmed active") : L("활성 여부 미확인", "Activity unknown"),
      people: owner, steps: guide.steps.map(pick), link: guide.link ? [L(guide.link[0], guide.link[1]), guide.link[2]] : null });
  }
  const current = c.exposures.filter(e => e.current);
  if (c.exposed && current.length) {
    const kinds = Array.from(new Set(current.map(e => locKind(e.source_type))));
    items.push({ id: "cleanup", title: L("노출 원본과 이력 정리", "Clean up the source and its history"),
      rule: worstVis(c) === "public" ? L("공개 위치에 노출", "Exposed in a public location") : L("변경 이력에 남음", "Kept in change history"),
      people: Array.from(new Set(current.map(e => e.author).filter((name): name is string => Boolean(name)))),
      steps: kinds.flatMap(kind => CLEANUP[kind].map(pick)), link: null });
  }
  if (c.vault.state === "none" && !revoked(c)) items.push({ id: "vault", title: L("새 값을 Vault로 옮기기", "Move the new value into Vault"), rule: L("Vault에 없음", "Not in Vault"), people: owner, steps: VAULT_STEPS.map(pick), link: null });
  if ((hasWrite(c) || noExpiry(c)) && !revoked(c) && c.status !== "fp") items.push({ id: "scope", title: L("권한 줄이고 만료일 두기", "Reduce permissions and set an expiry"),
    rule: hasWrite(c) ? L("쓰기·관리 권한 보유", "Has write or admin access") : L("만료일 없음", "No expiry date"), people: owner, steps: SCOPE_STEPS.map(pick), link: null });
  return items;
}

export function fillSteps(step: string, name: string, issuer: string, hint: string) {
  const escape = (value: string) => value.replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]!));
  return step.replaceAll("{name}", escape(name)).replaceAll("{issuer}", escape(issuer)).replaceAll("{hint}", escape(hint));
}

export function plainSteps(steps: string[], name: string, issuer: string, hint: string) {
  // These static guides use only b/code formatting. The result is plain text for copying.
  return steps.map((step, index) => `${index + 1}. ${step.replaceAll("<b>", "").replaceAll("</b>", "")
    .replaceAll("<code>", "").replaceAll("</code>", "").replaceAll("{name}", name).replaceAll("{issuer}", issuer).replaceAll("{hint}", hint)}`).join("\n");
}
