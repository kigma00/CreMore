/* Names for the codes the API returns, in both languages. A code without a name here shows the
 * detector catalog's name when the screen has it, else the code in words. */

import type { Say } from "@/console/text";

const TYPES: Record<string, [string, string]> = {
  AWS_ACCESS_KEY: ["AWS 액세스 키", "AWS access key"],
  AWS_ACCESS_KEY_ID: ["AWS 액세스 키 ID", "AWS access key ID"],
  AWS_SECRET_ACCESS_KEY: ["AWS 시크릿 액세스 키", "AWS secret access key"],
  AWS_SESSION_TOKEN: ["AWS 세션 토큰", "AWS session token"],
  AWS_SERVICE_CREDENTIAL: ["AWS 서비스 전용 자격 증명", "AWS service-specific credential"],
  GITHUB_TOKEN: ["GitHub 토큰", "GitHub token"],
  GITHUB_CLASSIC_PAT: ["개인 액세스 토큰(classic)", "Personal access token (classic)"],
  GITHUB_FINE_GRAINED_PAT: ["세분화 PAT(fine-grained)", "Fine-grained PAT"],
  GITHUB_SSO_AUTHORIZED_CREDENTIAL: ["SSO 승인 자격 증명", "SSO-authorized credential"],
  GITHUB_SSH_KEY: ["SSH 키(SSO 승인)", "SSH key (SSO-authorized)"],
  GITHUB_DEPLOY_KEY: ["배포 키", "Deploy key"],
  GITHUB_OAUTH_TOKEN: ["OAuth 앱 토큰", "OAuth app token"],
  GITHUB_APP_USER_TOKEN: ["GitHub App 사용자 토큰", "GitHub App user token"],
  GITHUB_APP_INSTALLATION: ["GitHub App 설치", "GitHub App installation"],
  GITLAB_PERSONAL_ACCESS_TOKEN: ["개인 액세스 토큰(PAT)", "Personal access token (PAT)"],
  GITLAB_RUNNER_TOKEN: ["Runner 인증 토큰", "Runner authentication token"],
  GITLAB_PIPELINE_TRIGGER_TOKEN: ["파이프라인 트리거 토큰", "Pipeline trigger token"],
  GITLAB_SERVICE_ACCOUNT_TOKEN: ["서비스 계정 PAT", "Service account PAT"],
  GITLAB_GROUP_ACCESS_TOKEN: ["그룹 액세스 토큰", "Group access token"],
  GITLAB_PROJECT_ACCESS_TOKEN: ["프로젝트 액세스 토큰", "Project access token"],
  GITLAB_DEPLOY_TOKEN: ["배포 토큰", "Deploy token"],
  GITLAB_ERROR_TRACKING_KEY: ["오류 추적 클라이언트 키", "Error tracking client key"],
  GITLAB_AGENT_TOKEN: ["Kubernetes 에이전트 토큰", "Kubernetes agent token"],
  GITLAB_SSH_KEY: ["SSH 키", "SSH key"],
  GITLAB_DEPLOY_KEY: ["배포 키", "Deploy key"],
  GITLAB_FEED_TOKEN: ["피드 토큰", "Feed token"],
  GITLAB_OAUTH_SECRET: ["OAuth 앱 시크릿", "OAuth application secret"],
  GITLAB: ["GitLab 토큰", "GitLab token"],
  BITBUCKET_TOKEN: ["Bitbucket 액세스 토큰", "Bitbucket access token"],
  BITBUCKET_HTTP_ACCESS_TOKEN: ["HTTP 액세스 토큰", "HTTP access token"],
  BITBUCKET_SSH_KEY: ["SSH 키", "SSH key"],
  BITBUCKET_DEPLOY_KEY: ["배포 키", "Deploy key"],
  ATLASSIAN_TOKEN: ["Atlassian API 토큰", "Atlassian API token"],
  ATLASSIAN_API_TOKEN: ["API 토큰", "API token"],
  ATLASSIAN_ADMIN_API_KEY: ["조직 관리자 API 키", "Organization admin API key"],
  ATLASSIAN_SERVICE_ACCOUNT_TOKEN: ["서비스 계정 API 토큰", "Service account API token"],
  ATLASSIAN_OAUTH_CLIENT: ["서비스 계정 OAuth 클라이언트", "Service account OAuth client"],
  NOTION_TOKEN: ["Notion 통합 토큰", "Notion integration token"],
  NOTION_PERSONAL_ACCESS_TOKEN: ["Notion 개인 액세스 토큰", "Notion personal access token"],
  NOTION_MCP_CONNECTION: ["Notion MCP 연결", "Notion MCP connection"],
  AZURE_DEVOPS_PAT: ["Azure DevOps 개인 액세스 토큰", "Azure DevOps personal access token"],
  AZURE_ENTRA_CLIENT_SECRET: ["Entra 클라이언트 시크릿", "Entra client secret"],
  AZURE_CERTIFICATE: ["Entra 앱 인증서", "Entra app certificate"],
  AZURE_CLIENT_SECRET: ["Entra 앱 비밀", "Entra app secret"],
  AZURE_SAS_TOKEN: ["Azure Storage SAS 토큰", "Azure Storage SAS token"],
  AZURE_STORAGE_KEY: ["Azure Storage 계정 키", "Azure Storage account key"],
  GCP_SERVICE_ACCOUNT: ["서비스 계정 키(JSON)", "Service account key (JSON)"],
  GCP_API_KEY: ["Google Cloud API 키", "Google Cloud API key"],
  GCP_OAUTH_CLIENT_SECRET: ["OAuth 클라이언트 시크릿", "OAuth client secret"],
  SLACK_TOKEN: ["Slack 토큰", "Slack token"],
  SLACK_BOT_TOKEN: ["Slack 봇 토큰", "Slack bot token"],
  SLACK_USER_TOKEN: ["Slack 사용자 토큰", "Slack user token"],
  SLACK_WEBHOOK: ["Slack 웹훅 URL", "Slack webhook URL"],
  DISCORD_WEBHOOK: ["Discord 웹훅 URL", "Discord webhook URL"],
  DISCORD_BOT_TOKEN: ["Discord 봇 토큰", "Discord bot token"],
  TELEGRAM_BOT_TOKEN: ["Telegram 봇 토큰", "Telegram bot token"],
  STRIPE_SECRET_KEY: ["Stripe 시크릿 키", "Stripe secret key"],
  STRIPE_WEBHOOK_SECRET: ["Stripe 웹훅 시크릿", "Stripe webhook secret"],
  SENDGRID_API_KEY: ["SendGrid API 키", "SendGrid API key"],
  MAILGUN_API_KEY: ["Mailgun API 키", "Mailgun API key"],
  TWILIO_API_KEY: ["Twilio API 키", "Twilio API key"],
  TWILIO_AUTH_TOKEN: ["Twilio 인증 토큰", "Twilio auth token"],
  OPENAI_API_KEY: ["OpenAI API 키", "OpenAI API key"],
  ANTHROPIC_API_KEY: ["Anthropic API 키", "Anthropic API key"],
  DATADOG_API_KEY: ["Datadog API 키", "Datadog API key"],
  DATADOG_APP_KEY: ["Datadog 앱 키", "Datadog application key"],
  CLOUDFLARE_API_TOKEN: ["Cloudflare API 토큰", "Cloudflare API token"],
  DIGITALOCEAN_TOKEN: ["DigitalOcean 토큰", "DigitalOcean token"],
  HEROKU_API_KEY: ["Heroku API 키", "Heroku API key"],
  NPM_TOKEN: ["npm 액세스 토큰", "npm access token"],
  PYPI_TOKEN: ["PyPI API 토큰", "PyPI API token"],
  DOCKER_TOKEN: ["Docker 액세스 토큰", "Docker access token"],
  OKTA_API_TOKEN: ["Okta API 토큰", "Okta API token"],
  VAULT_TOKEN: ["Vault 토큰", "Vault token"],
  CONSUL_TOKEN: ["Consul 토큰", "Consul token"],
  NOMAD_TOKEN: ["Nomad 토큰", "Nomad token"],
  TERRAFORM_CLOUD_TOKEN: ["Terraform Cloud 토큰", "Terraform Cloud token"],
  SHOPIFY_TOKEN: ["Shopify 액세스 토큰", "Shopify access token"],
  MONGODB_ATLAS_KEY: ["MongoDB Atlas 키", "MongoDB Atlas key"],
  JWT: ["JWT 토큰", "JSON Web Token"],
  PRIVATE_KEY: ["개인 키", "Private key"],
  PASSWORD_HASH: ["비밀번호 해시", "Password hash"],
  GENERIC_PASSWORD: ["하드코딩된 비밀번호", "Hardcoded password"],
  GENERIC_API_KEY: ["일반 API 키", "Generic API key"],
  GENERIC_SECRET: ["일반 비밀값", "Generic secret"],
  BASIC_AUTH_URL: ["URL에 포함된 인증 정보", "Credentials in a URL"],
  HTTP_BASIC_AUTH: ["HTTP Basic 인증 정보", "HTTP Basic credentials"],
  HTTP_BEARER_TOKEN: ["HTTP Bearer 토큰", "HTTP bearer token"],
  DB_CONNECTION_STRING: ["DB 연결 문자열", "Database connection string"],
  DATABASE_URL: ["DB 연결 문자열", "Database connection string"],
  ISSUED_CREDENTIAL: ["발급 자격 증명", "Issued credential"],
  OPAQUE_VALUE: ["비밀값", "Secret value"],
};

export function typeLabel(type: string, L: Say, catalog?: Map<string, string>): string {
  const known = TYPES[type];
  if (known) return L(known[0], known[1]);
  const fromCatalog = catalog?.get(type);
  if (fromCatalog) return fromCatalog;
  if (/^CUSTOM_RULE_[0-9A-F]{64}$/.test(type)) return L("조직 룰 일치", "Organization rule match");
  return type.split("_").filter(Boolean).map(word => word[0] + word.slice(1).toLowerCase()).join(" ") || L("자격 증명", "Credential");
}

export const KIND_LABEL: Record<"token" | "apikey" | "cloud" | "other", [string, string, string, string]> = {
  // plural ko, plural en, one ko, one en
  token: ["액세스 토큰", "Access tokens", "액세스 토큰", "Access token"],
  apikey: ["API 키", "API keys", "API 키", "API key"],
  cloud: ["클라우드 키", "Cloud keys", "클라우드 키", "Cloud key"],
  other: ["기타", "Other", "기타", "Other"],
};

export function kindLabel(kind: keyof typeof KIND_LABEL, L: Say, one = false) {
  const words = KIND_LABEL[kind];
  return one ? L(words[2], words[3]) : L(words[0], words[1]);
}

export function visLabel(vis: string, L: Say) {
  return ({ public: L("공개", "Public"), org: L("조직 전체 공유", "Org-wide"), internal: L("그룹 내부", "Group only"),
    private: L("비공개", "Private"), unknown: L("미확인", "Unknown") } as Record<string, string>)[vis] ?? vis;
}

const LOCAL_ACTOR = "00000000-0000-0000-0000-000000000001";

/** Who did something: the local operator, a CreMore process, or the account name as recorded. */
export function actorLabel(actor: string | null | undefined, L: Say) {
  if (!actor) return "";
  if (actor === LOCAL_ACTOR) return L("로컬 관리자", "Local admin");
  if (actor === "scanner") return L("검사", "Scan");
  if (actor === "worker") return L("작업자", "Worker");
  if (actor === "api") return L("CreMore API", "CreMore API");
  if (actor === "aws-inventory") return L("AWS 발급 목록 수집", "AWS inventory collection");
  if (/^[a-z0-9-]+-schedule$/.test(actor)) return L("예약 작업", "Scheduled job");
  if (actor.startsWith("system:")) return L("시스템", "System");
  // A reference kept instead of a name (tickets keep actors as UUIDs) reads by its first eight characters.
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(actor)) return L(`사용자 ${actor.slice(0, 8)}`, `User ${actor.slice(0, 8)}`);
  return actor;
}

export function roleLabel(role: string, L: Say) {
  return ({ Viewer: L("조회자", "Viewer"), Analyst: L("분석가", "Analyst"), Remediator: L("조치 담당자", "Remediator"),
    Admin: L("관리자", "Admin") } as Record<string, string>)[role] ?? role;
}
