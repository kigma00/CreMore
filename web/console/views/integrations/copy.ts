/* The words the integrations screen says about each provider: a card description, a short name for
 * each auth method and the hint under its fields. What a provider offers comes from the catalog;
 * a provider missing here still works and gets a description made from its features. */

import type { Descriptor, Method, Purpose } from "@/console/views/integrations/model";
import { josa, type Say } from "@/console/text";

const DESCRIPTIONS: Record<string, [string, string]> = {
  github: ["조직의 Credential 목록을 가져오고 저장소 코드를 검사합니다.", "Lists organization credentials and scans repository code."],
  aws: ["IAM 액세스 키와 Secrets Manager·Parameter Store 목록을 가져오고 S3 버킷을 검사합니다.", "Pulls IAM access keys and Secrets Manager and Parameter Store entries, and scans S3 buckets."],
  notion: ["연결에 공유된 페이지를 검사하고 Enterprise 조직의 토큰·MCP 연결 목록을 가져옵니다.", "Scans pages shared with the connection and pulls an Enterprise workspace's tokens and MCP connections."],
  slack: ["조직이 승인한 앱과 그 권한 범위를 가져옵니다. 토큰·웹훅 값은 읽지 않습니다.", "Lists approved apps and their scopes. No token or webhook value is read."],
};

export function description(d: Descriptor, L: Say): string {
  const known = DESCRIPTIONS[d.provider];
  if (known) return L(known[0], known[1]);
  const names = (Object.keys(d.purposes) as Purpose[]).map(p => featureName(p, L));
  return L(`${josa(names.join(" · "), "을/를")} 지원합니다.`, `Supports ${names.join(", ")}.`);
}

export function featureName(p: Purpose, L: Say) {
  return { inventory: L("발급 목록 수집", "Issuance inventory"), exposure: L("평문 노출 검사", "Plaintext exposure scan"),
    vault: L("Secret 저장소 대조", "Secret store comparison"), identity: L("사람 목록", "People directory"),
    remediation: L("승인된 조치 실행", "Approved actions") }[p];
}

export function capName(p: Purpose, L: Say, count = 0) {
  if (p === "inventory" && count) return L(`발급 목록 ${count}종`, `Inventory · ${count} type${count === 1 ? "" : "s"}`);
  if (p === "exposure" && count) return L(`노출 검사 ${count}곳`, `Scan · ${count} location${count === 1 ? "" : "s"}`);
  return { inventory: L("발급 목록", "Inventory"), exposure: L("노출 검사", "Exposure scan"),
    vault: L("Secret 대조", "Secret comparison"), identity: L("사람 목록", "People"), remediation: L("조치", "Actions") }[p];
}

export function featureText(p: Purpose, name: string, L: Say, provider = "") {
  return {
    inventory: L(`${name}에서 발급한 토큰·키의 권한·만료일·생성자를 가져옵니다. 값 원문은 받지 않습니다.`, `Pulls scopes, expiry and creators of tokens and keys ${name} issued. Raw values are never received.`),
    exposure: L("코드·문서·버킷에 평문으로 적힌 값을 찾습니다. 찾은 값은 지문으로만 남깁니다.", "Finds values written in plaintext in code, documents and buckets. Only fingerprints are kept."),
    vault: L(`${name}에 보관한 비밀의 목록을 가져와 노출된 값이 보관돼 있는지 대조합니다.`, `Lists the secrets kept in ${name} to check whether exposed values are stored there.`),
    identity: L("사용자 계정이 살아 있는지 가져와 퇴사자가 만든 Credential을 찾습니다.", "Pulls whether user accounts are active to find credentials made by people who left."),
    remediation: L(`승인된 조치 계획만 이 자격증명으로 ${name}의 키·토큰을 비활성화·폐기하거나 조직 접근을 회수합니다. 다른 기능과 따로 연동합니다.`,
      `Only approved action plans use this credential to disable or revoke keys and tokens in ${name}, or revoke their organization access. Connected on its own.`),
  }[p];
}

const SHORT: Record<string, [string, string]> = {
  github_app: ["GitHub App", "GitHub App"], token: ["토큰", "Token"], access_token: ["토큰", "Token"], http_token: ["토큰", "Token"],
  api_token: ["API 토큰", "API token"], server_token: ["토큰", "Token"], api_key: ["API 키", "API key"],
  integration: ["통합 토큰", "Integration token"], organization_bot: ["조직 봇", "Org bot"],
  role: ["계정별 수집 역할", "Per-account collection roles"], sso: ["SSO", "SSO"], runtime: ["서버 권한 직접 사용", "Direct server permissions"], customer_cli: ["고객 CLI", "Customer CLI"],
  adc: ["ADC", "ADC"], google_oauth: ["Google 로그인", "Google sign-in"], workload_identity: ["워크로드 신원", "Workload identity"],
  certificate: ["앱 인증서", "App certificate"],
  kubernetes: ["K8s 로그인", "K8s login"], jwt: ["JWT 로그인", "JWT login"], private_key_jwt: ["서비스 앱", "Service app"],
  oauth_client: ["클라이언트", "Client"], jsonl: ["JSON Lines", "JSON Lines"], reader: ["읽기 플러그인", "Reader plugin"],
};

export function methodShort(method: Pick<Method, "id" | "label" | "label_ko"> | undefined, L: Say) {
  if (!method) return "—";
  const known = SHORT[method.id];
  return known ? L(known[0], known[1]) : L(method.label_ko, method.label);
}

// Methods where CreMore never holds the credential: the customer's own environment reads.
export const CUSTOMER_SIDE = new Set(["customer_cli", "jsonl", "reader"]);

const HINTS: Record<string, [string, string]> = {
  "github:github_app": ["GitHub에서 만든 App이면 값이 저장돼 있습니다. 직접 등록한 App이면 조직에 설치한 뒤 App ID(또는 Client ID), 설치 ID, 개인 키(PEM)를 입력합니다. 감사 로그 토큰(엔터프라이즈 소유자의 클래식 PAT, read:audit_log)은 엔터프라이즈 감사 이벤트나 토큰 digest를 쓸 때만 넣습니다.", "An App made on GitHub has its values stored already. For an App you registered, install it in the org, then enter its App ID (or Client ID), installation ID and private key (PEM). Add the audit log token (an enterprise owner's classic PAT, read:audit_log) only for Enterprise audit events or token digests."],
  "github:token": ["아래 권한이 있는 개인 액세스 토큰을 입력합니다. 사람 목록은 조직 Owner(엔터프라이즈의 SSO 신원을 읽으면 엔터프라이즈 Owner)가 발급한 클래식 토큰이어야 합니다.",
    "Enter a personal access token with the permissions below. For people it must be a classic token of an org owner (of an enterprise owner when reading the enterprise's SSO identities)."],
  "notion:integration": ["내부 연결(이전 이름: 내부 통합)의 API 토큰을 입력합니다. 검사할 페이지마다 ••• 메뉴 → 연결 추가에서 이 연결을 고르세요.",
    "Enter the API token of an internal connection (formerly internal integration). On each page to scan, open ••• → Add connections and pick this connection."],
  "notion:organization_bot": ["조직 소유자가 조직 콘솔에서 만든 조직 봇 토큰을 입력합니다. 아래 범위만 주세요(personal-access-token:write-high-impact는 폐기용 연결에만).",
    "Enter an organization bot token an organization owner creates in the organization console, with only the scopes below (personal-access-token:write-high-impact only on the connection that revokes)."],
  "slack:token": ["조직에 설치한 앱의 사용자 토큰(xoxp-)만 받습니다. 봇 토큰(xoxb-)과 교체되는 토큰(xoxe.)은 받지 않습니다. CreMore는 목록만 읽고 Slack에 아무것도 올리거나 바꾸지 않습니다. admin.teams:read는 선택이며, 있으면 조직의 워크스페이스를 하나씩 고를 수 있습니다.",
    "Only the user token (xoxp-) of an app installed on the organization is taken; bot tokens (xoxb-) and rotating tokens (xoxe.) are not. CreMore only reads lists and posts or changes nothing in Slack. admin.teams:read is optional: with it single workspaces of the organization can be picked."],
  "aws:role": ["서버 신원 → 각 계정의 수집 역할로 전환하여 한 개 또는 여러 계정을 읽습니다. 역할 전환 권한·대상 역할의 신뢰가 필요합니다. EC2·EKS뿐 아니라 온프레미스·일반 Kubernetes에서도 AWS가 신뢰하는 OIDC 토큰을 자동 갱신하도록 구성하면 사용할 수 있습니다.",
    "Server identity → a collection role in each account, for one or multiple accounts. Requires assume-role permission and target trust. Works on EC2/EKS and on premises or general Kubernetes with automatically renewed OIDC tokens trusted by AWS."],
  "aws:sso": ["IAM Identity Center 권한 세트로 계정에 접근합니다. 비워 두면 이 설치의 기본 권한 세트를 씁니다.", "Accounts are reached through an IAM Identity Center permission set. Leave it empty to use this installation's default one."],
  "aws:runtime": ["추가 수집 역할로 전환하지 않고 서버 신원 자신의 권한으로 해당 AWS 계정 한 개를 읽습니다. 수집 권한을 그 신원에 부여합니다. 온프레미스·일반 Kubernetes도 가능하지만 먼저 AWS가 신뢰하는 OIDC 토큰을 자동 갱신하도록 구성해야 합니다.",
    "Reads the server identity's single AWS account using its own collection permissions, without assuming an additional collection role. Also works on premises or general Kubernetes with automatically renewed OIDC tokens trusted by AWS."],
};

export function methodHint(provider: string, method: Method, L: Say): string | null {
  if (CUSTOMER_SIDE.has(method.id)) return L("고객 환경에서 CreMore CLI(cremore-coverage)가 읽고 지문만 올립니다. 연동을 마치면 수집기 토큰을 한 번 보여 줍니다.",
    "The CreMore CLI (cremore-coverage) reads in your own environment and uploads fingerprints only. The collector token is shown once when you finish.");
  const known = HINTS[`${provider}:${method.id}`];
  return known ? L(known[0], known[1]) : null;
}

export function renewalTag(method: Method, L: Say): { text: string; tip: string } {
  if (CUSTOMER_SIDE.has(method.id)) return { text: L("CreMore 보관 없음", "Not held by CreMore"), tip: L("자격증명은 고객 환경에만 있습니다. CreMore는 수집기 토큰으로 결과만 받습니다.", "The credential stays in your environment. CreMore only receives results with a collector token.") };
  return {
    AUTOMATIC: { text: L("자동 갱신", "Renews itself"), tip: L("읽을 때마다 새 자격증명을 받습니다. 만료일을 관리하지 않아도 됩니다.", "A fresh credential is minted for each read. There is no expiry to manage.") },
    EXPIRES: { text: L("만료일 관리", "Has an expiry"), tip: L("토큰에 만료일이 있습니다. 만료 전에 새 토큰으로 바꾸세요.", "The token expires. Replace it before it does.") },
    ROTATES: { text: L("자동 교체", "Rotates itself"), tip: L("만료 전에 CreMore가 스스로 새 토큰으로 바꿉니다. 토큰에 교체 범위(self_rotate)가 있어야 합니다.", "CreMore replaces the token itself before it expires. The token needs the self_rotate scope.") },
    REFRESH: { text: L("갱신 토큰", "Refresh token"), tip: L("로그인으로 받은 갱신 토큰으로 계속 읽습니다. 공급자가 그 토큰을 끊으면 다시 로그인합니다.", "Reads continue with the refresh token from the sign-in; when the provider ends it, sign in again.") },
    NONE: { text: L("만료 없음", "No expiry"), tip: L("만료되지 않는 자격증명입니다. 필요 없어지면 발급한 곳에서 폐기하세요.", "This credential does not expire. Revoke it where it was issued once it is no longer needed.") },
  }[method.renewal];
}
