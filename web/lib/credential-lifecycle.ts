// Read-only projections from the server. These facts never grant action authority.
export type LifecycleLocale = "ko" | "en";
export type CredentialClassification = {
  type_id?: string;
  classification_status: "REVIEWED" | "AMBIGUOUS" | "UNCLASSIFIED";
  candidate_type_ids: string[];
  provider?: string;
  basis: string;
  semantics_revision: string;
};
export type LifecycleSource = { url: string; reviewed_at: string; scope: string };
export type LifecycleEffect = { action: string; effect: string; derived_token_effect: string; reversible: boolean; conditions: string[] };
export type CredentialLifecycle = {
  evaluated_at: string;
  review_status: "CURRENT" | "STALE" | "UNREVIEWED";
  expiration_model: "NONE_BY_DEFAULT" | "PROVIDER_DEFINED" | "FIXED_DEFAULT" | "UNKNOWN";
  default_ttl_seconds?: number;
  actual_expiry_status: "UNKNOWN" | "ELAPSED" | "NOT_ELAPSED";
  facts_freshness: "UNKNOWN" | "FRESH" | "STALE";
  limitations: string[];
  sources: LifecycleSource[];
  effects: LifecycleEffect[];
};
export type ActionCapabilities = {
  mode: "SHADOW";
  would_block: boolean;
  reasons: string[];
  management_scope: "UNPROVEN";
  support: {
    detection: "SUPPORTED" | "UNKNOWN";
    metadata: "SAVED_EVIDENCE_ONLY";
    permission: "NOT_EVALUATED";
    relationship: "NOT_IMPLEMENTED";
    action: "NOT_ENABLED";
    validation: "DOCUMENTED_MOCK_ONLY" | "UNREVIEWED";
  };
};

const copy = (locale: LifecycleLocale, en: string, ko: string) => locale === "ko" ? ko : en;
export function connectionAuthReason(code: string | undefined, locale: LifecycleLocale) {
  if (code === "SOURCE_SECRET_UNAVAILABLE") code = "SECRET_UNAVAILABLE";
  const labels: Record<string, [string, string]> = {
    AUTH_WAITING: ["Publish the expected authentication metadata, then retry the connection check.", "예상 인증 메타데이터를 게시한 뒤 연결을 다시 점검하세요."],
    AUTH_EXPIRED: ["The recorded authentication expired. Refresh or reauthenticate before retrying.", "기록된 인증이 만료되었습니다. 갱신 또는 재인증 후 다시 시도하세요."],
    AUTH_LIFETIME_TOO_SHORT: ["The remaining authentication lifetime cannot cover this job.", "남은 인증 수명으로 이 작업을 완료할 수 없습니다."],
    IDENTITY_MISMATCH: ["The supplied identity does not match the configured connection.", "공급된 신원이 연결 설정과 일치하지 않습니다."],
    SECRET_UNAVAILABLE: ["The worker could not obtain the configured connection secret.", "Worker가 설정된 연결 비밀정보를 가져오지 못했습니다."],
    SOURCE_PROFILE_INVALID: ["The connection's configuration is unavailable or invalid. Ask an administrator to correct the connection, then rerun the connection check.", "연결 설정을 사용할 수 없거나 유효하지 않습니다. 관리자가 연결을 수정한 뒤 연결을 다시 점검하세요."],
    REAUTH_REQUIRED: ["Refresh the connection authentication through its configured provider.", "설정된 공급자를 통해 연결 인증을 갱신하세요."],
    GCP_ADC_NOT_CONFIGURED: ["Configure Google ADC on the collection worker. A browser login is separate.", "수집 Worker에 Google ADC 인증을 설정하세요. 브라우저 로그인과 별도입니다."],
    GCP_ADC_REFRESH_FAILED: ["The worker could not refresh Google ADC. Check its identity and authentication configuration.", "Worker의 Google ADC 갱신에 실패했습니다. 신원과 인증 설정을 확인하세요."],
    GCP_OAUTH_REAUTH_REQUIRED: ["Google authorization expired or was revoked. Reconnect Google; automatic collection is paused.", "Google 인증이 만료되었거나 해제되었습니다. Google 연결·재인증을 진행하세요. 자동 수집은 일시 중단됩니다."],
    GCP_OAUTH_SCOPE_REQUIRED: ["Required Google permissions were not granted. Reconnect Google and review the requested access.", "필요한 Google 권한에 동의하지 않았습니다. Google 연결·재인증에서 요청 권한을 확인하세요."],
    GCP_OAUTH_SETUP_REQUIRED: ["The API server's Google OAuth application needs configuration.", "API 서버의 Google OAuth 앱 설정을 확인하세요."],
    // Token-service outages and throttling wait and resume the collection (GCP TRANSIENT_AUTH_CODES).
    GCP_OAUTH_NETWORK_OR_RESPONSE_FAILED: ["Google authentication could not be reached. Collection waits and resumes automatically.", "Google 인증 서비스에 접근하지 못했습니다. 수집은 기다렸다가 자동으로 이어집니다."],
    GCP_OAUTH_RATE_LIMITED: ["Google's token service asked to wait. Collection resumes automatically.", "Google 토큰 서비스가 잠시 기다리라고 응답했습니다. 수집은 자동으로 이어집니다."],
    GCP_OAUTH_TEMPORARILY_UNAVAILABLE: ["Google's token service is temporarily unavailable. Collection resumes automatically.", "Google 토큰 서비스가 일시적으로 응답하지 않습니다. 수집은 자동으로 이어집니다."],
    GCP_AUTH_DEPENDENCY_MISSING: ["Install the Google authentication dependencies in the worker image.", "Worker 이미지에 Google 인증 의존성을 설치하세요."],
    GCP_AUTH_NETWORK_FAILED: ["The worker could not reach Google's authentication service. Collection waits and resumes automatically.", "Worker가 Google 인증 서비스에 접근하지 못했습니다. 수집은 기다렸다가 자동으로 이어집니다."],
    GCP_ADC_TOKEN_UNAVAILABLE: ["Google ADC did not return an access token.", "Google ADC가 액세스 토큰을 반환하지 않았습니다."],
    PERMISSION_DENIED_OR_API_DISABLED: ["Check the worker identity's IAM access and the project's enabled APIs.", "Worker 신원의 IAM 권한과 프로젝트 API 활성화 상태를 확인하세요."],
    GCP_ACCESS_NOT_ESTABLISHED: ["No successful GCP inventory API read has been recorded.", "GCP 인벤토리 API 조회 성공 기록이 없습니다."],
    GCP_AUTHENTICATION_FAILED: ["Google rejected the worker's authentication. Refresh ADC and retry.", "Google이 Worker 인증을 거부했습니다. ADC를 갱신한 뒤 다시 점검하세요."],
    GCP_PERMISSION_DENIED_OR_API_DISABLED: ["Check the worker identity's IAM access and the project's enabled APIs.", "Worker 신원의 IAM 권한과 프로젝트 API 활성화 상태를 확인하세요."],
  };
  return code && labels[code] ? copy(locale, ...labels[code]) : "";
}
