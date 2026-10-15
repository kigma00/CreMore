"use client";

/* The AWS identity CreMore runs as. Every AWS integration CreMore reaches itself goes through it: the admin
 * who tests an AWS connection approves it, and each account's read-only role trusts only that identity. The
 * collector reports its identity every minute. Legacy installations also compare the API's own identity.
 *
 * The wizard shows it the way every provider shows its credential: a line in the sign-in pane, a result
 * under "Test connection", and the policy among the setup steps. Nothing here is a screen of its own. */

import type { Say } from "@/console/text";
import { onboardingText } from "@/console/views/integrations/model";

type Runtime = {
  state: string; kind?: string | null; account_id?: string | null; caller_arn?: string | null; principal_arn?: string | null;
  permission_set?: string | null; requires?: string | null; error_code?: string | null;
  credential_source?: string | null;
  renewal_health?: { state: string; certificate_expires_at?: string; error_code?: string } | null;
};
type Approved = {
  kind?: string | null; account_id?: string | null; principal_arn?: string | null; permission_set?: string | null;
  approved_by?: string | null; approved_at?: string | null; source?: string | null;
};
type Diagnosis = { reason: string | null; workload?: string | null; requested_profile?: string | null; profiles?: string[] };
export type AwsIdentityView = {
  identity_source?: "api" | "collector";
  api: Runtime; worker: Runtime | null; sign_in: Diagnosis | null; worker_stale: boolean; same_identity: boolean;
  approvable: string | null; approved: Approved | null; hold: string | null; policy: unknown; permission_set_policy: unknown;
  sign_in_here?: boolean;
};

export const IDENTITY_PATH = "aws/scanner-identity";

export function kindName(kind: string | null | undefined, permissionSet: string | null | undefined, L: Say) {
  if (kind === "IDENTITY_CENTER") return `IAM Identity Center · ${permissionSet ?? ""}`;
  return kind === "IAM_USER" ? L("IAM 사용자", "IAM user") : kind === "IAM_ROLE" ? L("IAM 역할", "IAM role")
    : kind === "ROOT" ? L("루트 사용자", "Root user") : kind ?? "";
}

/** Who can approve what, from the view: the fields the approval needs and whether it is offered. */
export function approval(view: AwsIdentityView, admin: boolean) {
  const needs = view.api.requires ?? null;
  const replaceable = !view.approved || view.hold === "AWS_SCANNER_IDENTITY_CHANGED" || view.approved.source === "SETTING";
  return { needs, offered: admin && (view.approvable === null || Boolean(needs)) && replaceable };
}

/** Whether testing a connection has to approve the identity first: none is approved, or CreMore now runs as
 * another identity than the approved one. An identity pinned by the installation's settings stays. */
export function needsApproval(view: AwsIdentityView): boolean {
  return !view.approved || view.hold === "AWS_SCANNER_IDENTITY_CHANGED";
}

/** The identity in a few words: its kind and account. */
export function identityText(view: AwsIdentityView, L: Say): string | null {
  const who = !needsApproval(view) ? view.approved : view.api.state === "READY" ? view.api : null;
  if (!who) return null;
  const renewal = view.api.renewal_health;
  const source = view.api.credential_source === "roles-anywhere" ? " · IAM Roles Anywhere" : "";
  const expiry = renewal?.state === "EXPIRING" ? L(` · 인증서 만료 예정: ${renewal.certificate_expires_at?.slice(0, 10) ?? ""}`,
    ` · Certificate expires: ${renewal.certificate_expires_at?.slice(0, 10) ?? ""}`) : "";
  return `${kindName(who.kind, who.permission_set, L)} · ${who.account_id ?? ""}${source}${expiry}`;
}

const REFUSALS: Record<string, [string, string]> = {
  WORKER_IDENTITY_UNKNOWN: ["워커가 AWS 신원을 보고하지 않았습니다. 워커를 실행하면 1분 안에 보고합니다.", "The worker has not reported its AWS identity. A running worker reports it within a minute."],
  WORKER_IDENTITY_MISMATCH: ["API와 워커가 서로 다른 AWS 신원으로 실행 중입니다. 같은 로그인을 쓰도록 맞추세요.", "The API and the worker run as different AWS identities. Give them the same sign-in."],
  ROOT_CREDENTIALS_REFUSED: ["루트 사용자 자격증명은 쓸 수 없습니다. CreMore를 IAM 역할(EC2·ECS·EKS 역할, 웹 신원, IAM Roles Anywhere)로 실행하세요.", "Root credentials are refused. Run CreMore as an IAM role (an EC2, ECS or EKS role, web identity, or IAM Roles Anywhere)."],
  UNSUPPORTED_IDENTITY: ["이 종류의 AWS 신원은 쓸 수 없습니다.", "This kind of AWS identity cannot be used."],
  ROLE_ARN_REQUIRED: ["이 신원이 쓰는 IAM 역할의 전체 ARN을 입력하세요.", "Enter the full ARN of the IAM role this identity uses."],
  IDENTITY_CENTER_REGION_REQUIRED: ["IAM Identity Center 리전을 입력하세요.", "Enter the IAM Identity Center Region."],
  NO_CREDENTIALS: ["CreMore에 AWS 로그인이 없습니다.", "CreMore has no AWS sign-in."],
  LOGIN_REQUIRED: ["CreMore의 AWS 로그인이 만료됐습니다.", "CreMore's AWS sign-in expired."],
  ERROR: ["CreMore의 AWS 신원을 확인하지 못했습니다.", "CreMore could not check its AWS identity."],
};

const SIGN_IN: Record<string, [string, string]> = {
  AWS_SSO_SESSION_REQUIRED: ["AWS 프로필에 IAM Identity Center 세션(sso-session)이 없습니다. 한 번 aws configure sso로 만든 뒤 여기서 로그인하세요.",
    "The AWS profile has no IAM Identity Center session (sso-session). Create it once with aws configure sso, then sign in here."],
  AWS_SSO_LOGIN_UNAVAILABLE: ["IAM Identity Center가 응답하지 않았습니다. 잠시 뒤 다시 로그인하세요.", "IAM Identity Center did not answer. Sign in again shortly."],
  AWS_SIGN_IN_PRESENT: ["CreMore에 이미 동작 중인 AWS 로그인이 있습니다. 동작 중인 로그인은 여기서 바꾸지 않습니다.", "CreMore already has a working AWS sign-in. A working sign-in is not replaced from here."],
  AWS_SSO_LOGIN_SOLO_ONLY: ["팀 설치에서는 여기서 AWS에 로그인하지 않습니다. 서버 역할이나 기계 신원(회사 IdP)으로 연결하세요.",
    "A team install does not sign in to AWS from here. Connect it as the server role or the machine identity (company IdP)."],
  AWS_LOGIN_REQUIRES_WORKER: ["이 설치에서는 수집 프로세스의 AWS 신원을 설정하세요.", "Configure the collection process's AWS identity for this installation."],
  SSO_CACHE_NOT_WRITABLE: ["로그인을 저장할 ~/.aws/sso/cache에 쓸 수 없습니다. 이 폴더를 쓰기 가능하게 연결하세요.", "~/.aws/sso/cache cannot be written to keep the sign-in. Mount it writable."],
  EXPIRED: ["승인 시간이 지났습니다. 다시 로그인하세요.", "The approval window passed. Sign in again."],
  DENIED: ["AWS 접근 포털에서 거절했습니다.", "It was denied in the AWS access portal."],
  FAILED: ["로그인을 마치지 못했습니다. 다시 로그인하세요.", "The sign-in did not finish. Sign in again."],
};

/** What stopped a sign-in from the dashboard. */
export function signInText(code: string | null | undefined, L: Say): string {
  const known = SIGN_IN[(code ?? "").split(/[\s:]/, 1)[0]];
  return known ? L(known[0], known[1]) : L("로그인을 마치지 못했습니다.", "The sign-in did not finish.");
}

export function refusalText(message: string, L: Say, source?: AwsIdentityView["identity_source"] | "remediator") {
  const code = message.split(/[\s:]/, 1)[0];
  if (source === "collector" && code === "WORKER_IDENTITY_UNKNOWN") return L(
    "수집 프로세스의 최신 AWS 신원 보고가 없습니다. 수집 프로세스가 실행 중인지 확인하세요.",
    "There is no recent AWS identity report from the collection process. Check that it is running.");
  if (source === "collector" && code === "WORKER_IDENTITY_MISMATCH") return L(
    "입력한 역할 또는 리전이 수집 프로세스의 신원 보고와 다릅니다. 수집 프로세스의 AWS 설정을 확인하세요.",
    "The supplied role or Region differs from the collection process's identity report. Check its AWS configuration.");
  if (source === "remediator" && code === "WORKER_IDENTITY_UNKNOWN") return L(
    "조치 프로세스의 최신 AWS 신원 보고가 없습니다. 조치 프로세스가 실행 중인지 확인하세요.",
    "There is no recent AWS identity report from the remediation process. Check that it is running.");
  if (source === "remediator" && code === "WORKER_IDENTITY_MISMATCH") return L(
    "입력한 역할 또는 리전이 조치 프로세스의 신원 보고와 다릅니다. 조치 프로세스의 AWS 설정을 확인하세요.",
    "The supplied role or Region differs from the remediation process's identity report. Check its AWS configuration.");
  const known = REFUSALS[code];
  if (known) return L(known[0], known[1]);
  if (code.startsWith("WORKER_")) return L("워커 프로세스가 AWS에 로그인하지 못했습니다.", "The worker process cannot sign in to AWS.");
  return onboardingText(message, [], L);
}

/** Why the identity cannot be used now, as a result line, what to do and the command that does it; ``signIn``
 * when an admin can sign in to IAM Identity Center from here instead of the command. */
export type IdentityIssue = { text: string; fix?: string; code?: string; signIn?: boolean };

export const SSO_LOGIN_PATH = "aws/sso-login";
export type SsoLoginStart = { session_id: string; user_code: string; verification_uri_complete: string; expires_at: string; interval: number };
export type SsoLoginState = { state: "PENDING" | "DONE" | "EXPIRED" | "DENIED" | "FAILED"; code: string | null };

function signInIssue(diagnosis: Diagnosis, L: Say, source?: AwsIdentityView["identity_source"]): IdentityIssue {
  const profile = diagnosis.requested_profile;
  switch (diagnosis.reason) {
    case "WORKLOAD_IDENTITY_UNAVAILABLE":
      return { text: L(`AWS 워크로드 신원을 쓸 수 없습니다 · ${diagnosis.workload ?? ""}`, `The AWS workload identity is unavailable · ${diagnosis.workload ?? ""}`),
        fix: source === "collector" ? L("수집 프로세스의 인스턴스 프로필·IMDSv2 접근 또는 ServiceAccount의 AWS 신뢰·토큰 마운트를 확인하세요.",
          "Check the collection process's instance profile and IMDSv2 access, or its ServiceAccount's AWS trust and token mounts.")
          : L("EC2는 인스턴스 프로필과 컨테이너의 IMDSv2 접근(컨테이너는 응답 홉 제한 2)을, EKS는 API·워커 ServiceAccount의 IRSA 신뢰나 Pod Identity 연결과 토큰 마운트를 확인하세요.",
            "On EC2, check the instance profile and the container's IMDSv2 access (a container needs response hop limit 2). On EKS, check the ServiceAccounts' IRSA trust or Pod Identity association and token mounts.") };
    case "AWS_CONFIG_NOT_MOUNTED":
      return { text: L("CreMore가 AWS CLI 설정을 찾지 못했습니다", "CreMore cannot see an AWS CLI configuration"),
        fix: L("AWS_CONFIG_DIR을 AWS CLI 디렉터리로 지정하고 스택을 다시 올리세요.", "Point AWS_CONFIG_DIR at your AWS CLI directory and bring the stack up again."),
        code: `# .env\nAWS_CONFIG_DIR=${L("<홈 디렉터리>", "<your home>")}/.aws\nAWS_PROFILE=${profile || "your-profile"}\n\ndocker compose up -d` };
    case "AWS_CONFIG_UNREADABLE":
      return { text: L("AWS 디렉터리는 연결됐지만 읽지 못합니다", "The AWS directory is mounted but cannot be read"),
        fix: L("macOS·Linux에서는 컨테이너가 본인 계정으로 실행되도록 .env에 추가하고 스택을 다시 올리세요.", "On macOS and Linux, make the containers run as you in .env, then bring the stack up again."),
        code: `printf 'CREMORE_UID=%s\\nCREMORE_GID=%s\\n' "$(id -u)" "$(id -g)" >> .env\n\ndocker compose up -d` };
    case "PROFILE_NOT_IN_CONFIG":
      return { text: L(`AWS_PROFILE이 가리키는 프로필이 설정에 없습니다: ${profile ?? ""}`, `AWS_PROFILE names a profile that is not configured: ${profile ?? ""}`),
        fix: L(`CreMore가 볼 수 있는 프로필: ${diagnosis.profiles?.length ? diagnosis.profiles.join(", ") : "없음"}. .env의 AWS_PROFILE을 고친 뒤 스택을 다시 올리세요.`,
          `Profiles CreMore can see: ${diagnosis.profiles?.length ? diagnosis.profiles.join(", ") : "none"}. Correct AWS_PROFILE in .env, then bring the stack up again.`) };
    case "NO_CACHED_SIGN_IN":
    case "SIGN_IN_EXPIRED":
      return { text: L("AWS 로그인이 없습니다", "There is no AWS sign-in"),
        fix: L("여기서 IAM Identity Center에 로그인하거나, CreMore를 실행하는 컴퓨터에서 명령으로 로그인하세요. 재시작하지 않아도 반영됩니다.",
          "Sign in to IAM Identity Center here, or with the command on the computer running CreMore. It is picked up without a restart."),
        // The device code works whether or not that computer has a browser (the default sign-in opens one there).
        code: profile ? `aws sso login --use-device-code --profile ${profile}` : "aws sso login --use-device-code", signIn: true };
    default:
      return { text: L("CreMore가 쓸 수 있는 AWS 로그인이 없습니다", "CreMore has no usable AWS sign-in"),
        fix: source === "collector" ? L("수집 프로세스의 로그에서 원인을 확인하세요.", "Check the collection process's logs for the cause.")
          : L("API 컨테이너 로그에서 원인을 확인하세요.", "Check the API container's logs for the cause.") };
  }
}

/** What stops the identity from being used or approved now; ``approving`` adds what an approval needs. A team install
 * (``sign_in_here`` false) offers no sign-in: it reaches AWS as the server, never as one person. */
export function identityIssue(view: AwsIdentityView, L: Say, approving: boolean): IdentityIssue | null {
  if (view.api.renewal_health?.state === "ERROR" || (!view.worker_stale && view.worker?.renewal_health?.state === "ERROR")) return {
    text: L("Roles Anywhere 서버 인증 설정을 확인해야 합니다.", "The Roles Anywhere server identity needs attention."),
    fix: L("서버 관리자에게 인증서·개인키·파일 권한·도우미 해시와 AWS 신뢰·네트워크를 확인하도록 요청하세요. 복구 후 다시 확인하면 반영됩니다.",
      "Ask the server administrator to check the certificate, key, file permissions, helper hash, AWS trust and network. Check again after recovery."),
  };
  if (view.sign_in_here === false && (view.api.state === "NO_CREDENTIALS"
    || ["AWS_CONFIG_NOT_MOUNTED", "NO_CACHED_SIGN_IN", "PROFILE_NOT_IN_CONFIG"].includes(view.sign_in?.reason ?? ""))) {
    return { text: L("서버의 AWS 신원 설정이 필요합니다.", "The server's AWS identity needs to be configured."),
      fix: L("아래에서 CreMore 서버의 실행 위치를 선택하고 초기 설정을 진행하세요.", "Choose where the CreMore server runs below and complete its initial setup.") };
  }
  const issue = issueOf(view, L, approving);
  if (!issue?.signIn || view.sign_in_here !== false) return issue;
  return { text: issue.text,
    fix: L("팀 설치에서는 여기서 AWS에 로그인하지 않습니다. 사람의 로그인 대신 서버 역할(EC2·쿠버네티스)이나 기계 신원(회사 IdP)으로 연결하세요.",
      "A team install does not sign in to AWS from here. Instead of a person's sign-in, connect it as the server: an instance or pod role, or the machine identity (company IdP).") };
}

function issueOf(view: AwsIdentityView, L: Say, approving: boolean): IdentityIssue | null {
  if (view.sign_in) return signInIssue(view.sign_in, L, view.identity_source);
  if (view.hold === "AWS_LOGIN_REQUIRED") return { text: L("AWS 로그인이 만료됐습니다", "The AWS sign-in expired"),
    fix: L("여기서 다시 로그인하거나, CreMore를 실행하는 컴퓨터에서 명령으로 로그인하세요. 멈춘 AWS 수집은 1분 안에 이어집니다.",
      "Sign in again here, or with the command on the computer running CreMore. Paused AWS collection resumes within a minute."),
    code: "aws sso login --use-device-code", signIn: true };
  if (!approving) return null;
  if (view.api.state !== "READY") return { text: refusalText(view.api.error_code ?? view.api.state, L, view.identity_source) ?? view.api.state };
  if (view.approvable && !view.api.requires) return { text: refusalText(view.approvable, L, view.identity_source) ?? view.approvable };
  const worker = view.worker_stale ? null : view.worker;
  if (!worker) return { text: refusalText("WORKER_IDENTITY_UNKNOWN", L, view.identity_source) ?? "" };
  if (worker.state !== "READY") return { text: refusalText("WORKER_" + worker.state, L, view.identity_source) ?? worker.state };
  if (!view.same_identity) return { text: refusalText("WORKER_IDENTITY_MISMATCH", L, view.identity_source) ?? "" };
  return null;
}
