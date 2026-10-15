/* The words the integrations screen says about each provider: a card description, a short name for
 * each auth method and the hint under its fields. What a provider offers comes from the catalog;
 * a provider missing here still works and gets a description made from its features. */

import type { Descriptor, Method, Purpose } from "@/console/views/integrations/model";
import { josa, type Say } from "@/console/text";

const DESCRIPTIONS: Record<string, [string, string]> = {
  github: ["조직에 승인된 PAT·SSH 키·배포 키와 Actions 비밀 목록을 가져오고 저장소 코드를 검사합니다.", "Pulls PATs, SSH keys and deploy keys approved for the org and its Actions secrets, and scans repository code."],
  gitlab: ["그룹·프로젝트의 액세스 토큰과 CI 변수 목록을 가져오고 저장소 코드를 검사합니다.", "Pulls access tokens and CI variables of groups and projects, and scans repository code."],
  bitbucket: ["프로젝트 HTTP 액세스 토큰(Data Center)이나 SSH·배포 키(Cloud) 목록을 가져오고 저장소 코드를 검사합니다.",
    "Pulls project HTTP access tokens (Data Center) or SSH and deploy keys (Cloud), and scans repository code."],
  azure_devops: ["개인 액세스 토큰으로 조직의 PAT 목록을 가져오고 Azure Repos 코드를 검사합니다. Entra에 연결된 조직은 Microsoft 연동에서 함께 연결합니다.",
    "With a personal access token, pulls the org's PATs and scans Azure Repos code. An organization connected to Entra ID joins the Microsoft integration instead."],
  aws: ["IAM 액세스 키와 Secrets Manager·Parameter Store 목록을 가져오고 S3 버킷을 검사합니다.", "Pulls IAM access keys and Secrets Manager and Parameter Store entries, and scans S3 buckets."],
  gcp: ["서비스 계정 키·API 키와 Secret Manager 목록을 가져오고 Cloud Storage 버킷을 검사합니다.", "Pulls service account keys, API keys and Secret Manager entries, and scans Cloud Storage buckets."],
  azure: ["앱 등록 하나로 Entra ID의 앱 비밀·인증서와 사람 목록, Azure 스토리지 키·Key Vault, Azure DevOps PAT를 가져오고 Blob·Azure Repos를 검사합니다.",
    "One app registration pulls Entra ID app secrets, certificates and people, Azure storage keys and Key Vault entries, and Azure DevOps PATs, and scans blobs and Azure Repos."],
  confluence: ["공간의 페이지와 첨부 파일에서 평문으로 적힌 값을 찾습니다.", "Finds plaintext values in a space's pages and attachments."],
  atlassian: ["조직 관리 API로 사용자 API 토큰·API 키 목록을 가져옵니다.", "Pulls user API tokens and API keys through the organization admin API."],
  notion: ["연결에 공유된 페이지를 검사하고 Enterprise 조직의 토큰·MCP 연결 목록을 가져옵니다.", "Scans pages shared with the connection and pulls an Enterprise workspace's tokens and MCP connections."],
  slack: ["조직이 승인한 앱(감사 로그 옵션을 켜면 설치한 앱까지)과 그 권한 범위가 뜻하는 봇 토큰·사용자 토큰·수신 웹훅을 목록으로 가져옵니다. 토큰·웹훅 값은 읽지 않습니다.",
    "Lists the apps the organization approved (and, with the audit log option, installed) and the bot-token, user-token and webhook access their scopes imply. No token or webhook value is read."],
  entra_id: ["사용자 계정 상태를 가져와 퇴사자가 만든 Credential을 찾습니다.", "Pulls user account state to find credentials made by people who left."],
  okta: ["사용자 계정 상태를 가져와 퇴사자가 만든 Credential을 찾습니다.", "Pulls user account state to find credentials made by people who left."],
  keycloak: ["사용자 계정 상태를 가져와 퇴사자가 만든 Credential을 찾습니다.", "Pulls user account state to find credentials made by people who left."],
  vault: ["KV 비밀을 지문으로 읽어 노출된 값이 보관돼 있는지 대조합니다.", "Reads KV secrets as fingerprints to check whether exposed values are kept there."],
  openbao: ["KV 비밀을 지문으로 읽어 노출된 값이 보관돼 있는지 대조합니다.", "Reads KV secrets as fingerprints to check whether exposed values are kept there."],
  external_vault: ["그 밖의 금고를 CreMore CLI로 지문만 내보내 대조합니다.", "Compares any other vault through fingerprints the CreMore CLI exports."],
  website: ["DNS로 확인된 회사 도메인의 페이지·스크립트·소스맵에서 평문으로 적힌 값을 찾습니다.",
    "Finds plaintext values in the pages, scripts and source maps of the company's DNS-verified domains."],
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
    exposure: provider === "website"
      ? L("웹 페이지·스크립트·소스맵에 평문으로 적힌 값을 찾습니다. 찾은 값은 지문으로만 남깁니다.", "Finds values written in plaintext in web pages, scripts and source maps. Only fingerprints are kept.")
      : L("코드·문서·버킷에 평문으로 적힌 값을 찾습니다. 찾은 값은 지문으로만 남깁니다.", "Finds values written in plaintext in code, documents and buckets. Only fingerprints are kept."),
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
  "gitlab:token": ["아래 범위로 그룹 또는 프로젝트 액세스 토큰(GitLab.com은 Premium·Ultimate)을 발급해 입력합니다. GitLab.com Free는 그룹 서비스 계정의 개인 액세스 토큰을, 인스턴스 전체는 관리자의 개인 액세스 토큰(Admin Mode가 켜져 있으면 admin_mode 범위도)을 씁니다. 역할은 그룹 Owner, 프로젝트 Maintainer가 필요합니다. self_rotate 범위를 주면 만료 전에 CreMore가 스스로 새 토큰으로 바꿉니다.",
    "Issue a group or project access token (GitLab.com: Premium or Ultimate) with the scopes below. On GitLab.com Free use a group service account's personal access token; for the whole instance an administrator's personal access token (plus admin_mode when Admin Mode is on). The role needed is the group's Owner or the project's Maintainer. With the self_rotate scope CreMore replaces it itself before it expires."],
  "confluence:token": ["Data Center는 그 공간의 보기 권한만 가진 전용 사용자의 개인 액세스 토큰을 입력합니다. Cloud는 서비스 계정의 범위 지정 API 토큰(read:space·read:page·read:attachment·read:content-details, 모두 :confluence)을 쓰고 주소를 https://api.atlassian.com/ex/confluence/<Cloud ID>/wiki로 입력합니다. 개인 API 토큰은 받지 않습니다.",
    "Data Center: a personal access token of a dedicated user with View on the space only. Cloud: a service account's scoped API token (read:space, read:page, read:attachment and read:content-details, all :confluence), with the address https://api.atlassian.com/ex/confluence/<cloud ID>/wiki. Personal API tokens are not taken."],
  "bitbucket:access_token": ["Bitbucket Cloud Premium의 워크스페이스 액세스 토큰을 발급해 입력합니다. 검사는 저장소 읽기와 계정 읽기, 발급 목록은 배포 키를 읽도록 저장소 관리도 필요합니다.",
    "Issue a workspace access token (Bitbucket Cloud Premium). Scanning needs Repositories: Read and Account: Read; the inventory also needs Repositories: Admin for deploy keys."],
  "bitbucket:http_token": ["프로젝트의 HTTP 액세스 토큰을 발급해 입력합니다. 검사는 프로젝트 읽기, 액세스 토큰 목록은 프로젝트 관리 권한이 필요합니다.",
    "Issue a project HTTP access token: Project read for scanning, Project admin to list access tokens."],
  "bitbucket:api_token": ["Bitbucket 범위를 지정해 만든 API 토큰(read:user·read:workspace·read:repository, 발급 목록은 read:ssh-key도, 모두 :bitbucket)과 그 계정의 이메일을 입력합니다. 개인 토큰이므로 Premium이면 워크스페이스 액세스 토큰을 권장합니다.",
    "Enter an API token made with Bitbucket scopes (read:user, read:workspace and read:repository, plus read:ssh-key for the inventory, all :bitbucket) and that account's e-mail. It is a personal token; on Premium a workspace access token is preferred."],
  "atlassian:api_key": ["조직 설정 → API 키에서 범위를 지정해 만든 API 키를 입력합니다: read:keys:admin, read:tokens:admin, read:service-accounts-tokens:admin(OAuth 클라이언트 포함). 최대 1년 뒤 만료됩니다.",
    "Enter an API key made with scopes under Organization settings → API keys: read:keys:admin, read:tokens:admin and read:service-accounts-tokens:admin (which covers OAuth clients too). It expires within a year."],
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
  "gcp:adc": ["CreMore 워커의 신원(ADC)으로 읽습니다. Google Cloud에서는 연결된 서비스 계정을, 그 밖에서는 워크로드 아이덴티티 제휴를 쓰고, 워커에 GOOGLE_APPLICATION_CREDENTIALS 키 파일이나 gcloud 사용자 로그인을 두지 마세요. 그 신원에 아래 권한을 주세요.",
    "Reads with the worker's identity (ADC): the attached service account on Google Cloud, Workload Identity Federation elsewhere. Do not point GOOGLE_APPLICATION_CREDENTIALS at a key or use a gcloud user login on the worker. Grant that identity the permissions below."],
  "gcp:google_oauth": ["Google 로그인으로 받은 갱신 토큰으로 읽습니다. 승인을 거두거나, 앱이 테스트 상태의 외부 앱이면 7일 뒤, Google Cloud 세션 길이 정책의 기간이 지나면(정책에서 신뢰할 수 있는 앱을 예외로 두고 CreMore 클라이언트를 신뢰함으로 표시하면 제외), 6개월 동안 쓰지 않으면 멈추며 그때는 다시 로그인합니다.",
    "Reads with the refresh token from the Google sign-in. It stops if the approval is revoked, after 7 days for an External app in Testing, when your Google Cloud session-length policy runs out (unless the policy exempts Trusted apps and CreMore's client is marked Trusted), or after 6 months unused; then sign in again."],
  "google_workspace:service_account_delegation": ["최고 관리자가 관리 콘솔 > 보안 > 액세스 및 데이터 관리 > API 제어 > 도메인 전체 위임 관리에서 서비스 계정의 클라이언트 ID에 https://www.googleapis.com/auth/admin.directory.user.readonly(사람이 Google로 로그인하면 https://www.googleapis.com/auth/admin.directory.group.member.readonly도)를 허용합니다. 적용까지 최대 24시간 걸릴 수 있습니다. 키 프로젝트에서 Admin SDK API를 켜세요. 사용자 관리 키는 조직 정책(iam.serviceAccountKeyExpiryHours)이 없으면 만료되지 않습니다. 정책으로 만료를 정하고 그 날짜를 넣어 두면 만료 전에 알리며, 새 키로 바꾼 뒤 이전 키를 지우세요.",
    "A super admin authorizes the service account's client ID under Admin console > Security > Access and data control > API controls > Manage Domain Wide Delegation with https://www.googleapis.com/auth/admin.directory.user.readonly (plus https://www.googleapis.com/auth/admin.directory.group.member.readonly when people sign in with Google); it can take up to 24 hours. Enable the Admin SDK API in the key's project. A user-managed key does not expire without an organization policy (iam.serviceAccountKeyExpiryHours): set one, enter its date to be reminded before it ends, and delete the old key after switching to a new one."],
  "azure:certificate": ["앱 등록 하나로 Entra ID·Azure·Azure DevOps를 읽습니다. 워커가 관리 ID나 워크로드 신원 연합을 쓸 수 없을 때의 방식입니다. 애플리케이션(클라이언트) ID를 넣고 CreMore가 만든 인증서를 앱에 올리면, 만료 전에 CreMore가 스스로 새 인증서로 바꿉니다.",
    "One app registration reads Entra ID, Azure and Azure DevOps, for a worker that cannot use a managed identity or workload identity federation. Enter its application (client) ID and upload the certificate CreMore makes; CreMore replaces it itself before it expires."],
  "azure:workload_identity": ["CreMore 워커의 워크로드 신원 또는 관리 ID로 읽습니다. 관리 ID는 포털의 API 권한 화면이 없어 권한 있는 역할 관리자가 설정 도우미의 명령으로 Microsoft Graph 앱 역할을 할당합니다(연합 자격 증명을 붙인 앱 등록이면 그 앱의 API 권한에서 추가하고 관리자 동의). Azure 역할도 그 신원에 줍니다.",
    "Reads with the worker's workload identity or managed identity. A managed identity has no API permissions page in the portal, so a Privileged Role Administrator assigns the Microsoft Graph app roles with the setup commands (an app registration with a federated credential adds them under its API permissions with admin consent). Give the identity the Azure roles too."],
  "entra_id:workload_identity": ["CreMore 워커의 워크로드 신원 또는 관리 ID로 읽습니다. 그 신원에 아래 권한을 주세요.", "Reads with the worker's workload identity or managed identity. Grant it the permissions below."],
  "azure_devops:token": ["이 조직 범위의 개인 액세스 토큰을 아래 범위만, 가장 짧은 만료로 발급합니다. 모든 조직용(전역) PAT는 2026년 12월 1일부터 쓸 수 없습니다. Microsoft Entra에 연결된 조직의 저장소 검사와 PAT 목록은 Microsoft 연결로도 할 수 있습니다.",
    "Issue a personal access token scoped to this organization with only the scopes below and the shortest expiry. PATs for all accessible organizations (global PATs) stop working on 1 December 2026. For an organization connected to Microsoft Entra ID, the Microsoft connection also scans repositories and lists PATs."],
  "azure_devops:server_token": ["아래 범위로 개인 액세스 토큰을 가장 짧은 만료로 발급해 입력합니다.", "Issue a personal access token with the scopes below and the shortest expiry."],
  "vault:kubernetes": ["CreMore 워커가 역할로 로그인해 읽습니다. 토큰 파일은 VAULT_CONNECTION_TOKEN_DIR 안의 파일 이름입니다.", "The worker logs in with the role and reads. The token file is a file name inside VAULT_CONNECTION_TOKEN_DIR."],
  "vault:jwt": ["CreMore 워커가 역할로 로그인해 읽습니다. 토큰 파일은 VAULT_CONNECTION_TOKEN_DIR 안의 파일 이름입니다.", "The worker logs in with the role and reads. The token file is a file name inside VAULT_CONNECTION_TOKEN_DIR."],
  "vault:token": ["루트 토큰이 아니라 읽기 전용 정책의 토큰을 쓰세요. CreMore는 토큰을 갱신하지 않으므로 TTL이 끝나면 멈춥니다. 토큰은 암호화해 저장하고 이 연결의 주소로만 보냅니다.",
    "Use a token of a read-only policy, never a root token. CreMore does not renew it, so it stops at the end of its TTL. The token is stored encrypted and sent only to this connection's address."],
  "openbao:kubernetes": ["CreMore 워커가 역할로 로그인해 읽습니다. 토큰 파일은 VAULT_CONNECTION_TOKEN_DIR 안의 파일 이름입니다.", "The worker logs in with the role and reads. The token file is a file name inside VAULT_CONNECTION_TOKEN_DIR."],
  "openbao:jwt": ["CreMore 워커가 역할로 로그인해 읽습니다. 토큰 파일은 VAULT_CONNECTION_TOKEN_DIR 안의 파일 이름입니다.", "The worker logs in with the role and reads. The token file is a file name inside VAULT_CONNECTION_TOKEN_DIR."],
  "openbao:token": ["루트 토큰이 아니라 읽기 전용 정책의 토큰을 쓰세요. CreMore는 토큰을 갱신하지 않으므로 TTL이 끝나면 멈춥니다. 토큰은 암호화해 저장하고 이 연결의 주소로만 보냅니다.",
    "Use a token of a read-only policy, never a root token. CreMore does not renew it, so it stops at the end of its TTL. The token is stored encrypted and sent only to this connection's address."],
  "okta:made_key": ["CreMore가 개인 키를 만들어 암호화해 두고, 서비스 앱에는 공개 키(JWK)만 붙여 넣습니다. 개인 키는 화면에 나오지 않습니다.",
    "CreMore makes the private key and keeps it encrypted; only the public key (JWK) is pasted into the service app. The private key is never shown."],
  "okta:private_key_jwt": ["개인 키로 인증하는 서비스 앱을 만들고 클라이언트 ID와 개인 키를 입력합니다.", "Create a service app that authenticates with a private key, then enter its client ID and key."],
  "keycloak:oauth_client": ["서비스 계정을 켠 클라이언트의 ID와 시크릿을 입력합니다.", "Enter the ID and secret of a client with service accounts enabled."],
  "confluence:service_account": ["CreMore가 이 클라이언트로 1시간짜리 액세스 토큰을 받아 Atlassian API 게이트웨이(api.atlassian.com)에만 보냅니다. 시크릿은 암호화해 저장합니다.",
    "CreMore takes one-hour access tokens with this client and sends them only to the Atlassian API gateway (api.atlassian.com). The secret is stored encrypted."],
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
