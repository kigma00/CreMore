# 공식 문서 대조 — 확인한 계약과 구현에 반영할 내용

확인일: **2026-09-21**. 공개 공식 문서의 관련 API, 권한, 응답, 페이지 처리 항목을 직접 읽고, 고정된 팀원 소스와 대조했다. 공식 문서 전체의 모든 문장을 읽었다는 뜻은 아니다. 고객 계정이나 수집한 자격증명으로 공급자 API를 시험하지 않았다.

**읽는 법:** 각 항목의 ‘공식 계약’은 공급자 설명, ‘코드와 추천’은 현재 구현과 통합 제안이다. 문서가 상충하거나 현재 설치 환경을 확인하지 못한 사항은 별도 검증 대상으로 남긴다. 추천 구현 순서는 [통합 설계](../INTEGRATION_DESIGN_REVISED.md), 전체 소스 근거는 공급자별 보고서를 따른다.

코드 표기의 `DEV/GL/GCP/GH/S`는 [구현 계약 §1](implementation-contract.md)의 고정 SHA다. `AT`는 Atlassian SHA `11c44f2afdf0874f736eb30018992bd9855fd2d9`이며 경로는 저장소 루트 기준이다. GL/GCP의 경로 prefix는 각각의 상세 보고서를 따른다.

## GitLab

### GL1. 일반 PAT와 그룹 자격증명 목록은 범위가 다르다

공식 자료: [Personal access tokens](https://docs.gitlab.com/api/personal_access_tokens/), [Groups: Credentials inventory management](https://docs.gitlab.com/api/groups/#credentials-inventory-management).

- **공식 계약:** 일반 PAT 목록은 관리자가 instance 토큰을 볼 수 있고, 일반 사용자는 자신의 토큰을 본다. `user_id` 필터가 있다. 그룹 `/manage/personal_access_tokens`, `/manage/resource_access_tokens`는 **GitLab.com, Premium/Ultimate, 최상위 그룹 Owner** 계약이다. 18.6 도입, 18.7 GA 이력이 있다.
- **코드와 추천:** `GL:gitlab_inventory/collector.py:53`은 일반 PAT 요청에 자신의 `user_id`를 넣고, `:167`은 최상위 그룹의 manage 조회를 추가한다. 관리자 연결만으로 전사 PAT 전수 수집이라고 표시하지 않는다. self-managed에서 manage API까지 지원한다고 추정하지 않는다.

### GL2. 그룹, 프로젝트 토큰과 서비스 계정

공식 자료: [Group access tokens](https://docs.gitlab.com/api/group_access_tokens/), [Project access tokens](https://docs.gitlab.com/api/project_access_tokens/), [Service accounts](https://docs.gitlab.com/api/service_accounts/).

- **공식 계약:** 그룹/프로젝트 access token과 서비스 계정 PAT의 읽기 경로가 있다. 그룹 서비스 계정 PAT 목록은 17.11 도입 이력이 있다. 계정 목록 권한과 토큰 목록 권한, 설치 버전은 별도로 확인해야 한다.
- **코드와 추천:** 관찰한 계정, 그룹, 프로젝트에 대한 후속 조회, owner/issuer와 source provenance를 보존한다. 같은 PAT의 여러 조회 경로를 별도 발급 건수로 세지 않는다. 현재 10종류의 token family와 추가 수집 경로를 구분한다. 근거: `GL:gitlab_inventory/collector.py:93`, `GL:gitlab_inventory/model.py:74`.

### GL3. Deploy token과 pipeline trigger

공식 자료: [Deploy tokens](https://docs.gitlab.com/api/deploy_tokens/), [Pipeline trigger 목록](https://docs.gitlab.com/api/pipeline_triggers/#list-project-trigger-tokens).

- **공식 계약:** deploy token은 그룹, 프로젝트 조회 외에 관리자용 instance 목록도 있지만 팀원은 그룹, 프로젝트 경로를 사용한다. Trigger는 생성자가 조회하면 전체 token, 다른 사용자가 조회하면 4문자로 축약된 token이 응답에 포함될 수 있다.
- **코드와 추천:** `GL:gitlab_inventory/model.py:38`의 값 제거를 유지한다. 관리정보 조회도 비밀값을 포함할 수 있으므로 허용 필드만 저장한다. 축약된 token을 실제 값의 일치 근거로 사용하지 않는다.

### GL4. Kubernetes agent와 error-tracking client key

공식 자료: [Agent token 목록](https://docs.gitlab.com/api/cluster_agents/#list-all-agent-tokens), [Error-tracking client key 목록](https://docs.gitlab.com/api/error_tracking/#list-all-project-client-keys).

- **공식 계약:** agent 목록은 active token만 반환하고, revoked token의 상세는 404다. Error tracking 응답에는 `public_key`, `sentry_dsn`이 있다.
- **코드와 추천:** `GL:gitlab_inventory/collector.py:186`의 수집 범위와 sanitizer를 보존한다. 목록 부재를 폐기로 자동 판정하지 않는다. 공개 ingest 정보와 관리용 인증정보는 서로 다른 종류로 표시한다.

### GL5. GraphQL 보완은 선택 기능이다

공식 자료: [GraphQL PipelineTrigger](https://docs.gitlab.com/api/graphql/reference/#pipelinetrigger).

- **공식 계약:** `canAccessProject`, `expiresAt`, `hasTokenExposed`, `lastUsed`, `owner` 필드가 문서화돼 있다. `Project.pipelineTriggers`는 **Experiment**로 표시된다.
- **코드와 추천:** `GL:gitlab_inventory/collector.py:199`의 GraphQL 보완, 부분 성공 처리를 보존한다. 실패해도 REST 관찰을 잃지 않으며, 모든 설치 버전의 필수 계약으로 강제하지 않는다.

## GCP

### GC1. 서비스 계정 키 목록에서 private key를 복원할 수 없다

공식 자료: [keys.list](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/list), [ServiceAccountKey](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys).

- **공식 계약:** `keyTypes`를 생략하면 모든 키 유형을 조회한다. `privateKeyData`는 생성 응답에서만, `publicKeyData`는 get 응답에서만 제공된다.
- **코드와 추천:** `GCP:cremore_gcp/collector.py:204`와 `GCP:cremore_gcp/linkage.py:20`의 metadata, 정확한 ID 연결을 인수한다. 계정/키 목록과 private key 노출을 다른 사실로 표시한다.

### GC2. API key 목록, 원문, 소속 조회는 별개다

공식 자료: [API keys.list](https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/list), [lookupKey](https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/keys/lookupKey).

- **공식 계약:** 목록은 global만 지원하며 key string을 반환하지 않는다. `showDeleted`는 최근 30일 삭제분이다. `lookupKey`는 key string으로 프로젝트/resource name을 찾으며 `apikeys.keys.lookup` 권한을 요구한다.
- **코드와 추천:** `GCP:cremore_gcp/collector.py:285`, `GCP:cremore_gcp/linkage.py:61`을 별도 capability로 취급한다. Lookup 결과는 소속 연결 근거이며 인증 성공이나 호출 가능 서비스의 증명이 아니다. 영구 삭제 이력 전수를 제공한다고 표시하지 않는다.

### GC3. 지역 발견, 버전 목록, 값 접근

공식 자료: [locations.list](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.locations/list), [Regional versions.list](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.locations.secrets.versions/list), [Regional versions.access](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.locations.secrets.versions/access).

- **공식 계약:** locations는 서비스가 지원하는 위치 목록이다. 그 지역에 고객 Secret이 존재한다는 증거는 아니다. 버전 목록에는 값이 없고, 값 접근 권한은 별도다. `latest`는 가장 최근 생성된 버전이다.
- **코드와 추천:** `GCP:cremore_gcp/collector.py:349`는 project를 기준으로 지원 지역을 발견해 순회한다. **현재 CLI에서 지역을 직접 선택한다는 기존 표현은 정정한다.** 지역 선택은 통합 온보딩에 추가할 기능이다. 모든 enabled 버전 또는 latest가 실제 서비스에 배포된 값이라고 추정하지 않는다.

### GC4. Secret 버전은 불변이고 CRC는 전송 무결성이다

공식 자료: [Add a secret version](https://docs.cloud.google.com/secret-manager/docs/add-secret-version), [Data integrity](https://docs.cloud.google.com/secret-manager/docs/data-integrity).

- **공식 계약:** “Secret data is immutable.” 값을 바꾸려면 새 버전을 만든다. CRC32C는 payload의 데이터 무결성 검사다.
- **코드와 추천:** `GCP:cremore_gcp/watch.py:258`의 cached 값 재사용은 확인했지만 **동일 Secret 버전의 payload 변경을 놓친다는 설명은 잘못된 가정**이다. 새 버전, latest/alias 이동, enable/disable/destroy와 마지막 성공한 값 읽기 시각을 검증한다. Cached 값은 과거 증거이며 현재 접근 성공으로 갱신하지 않는다. CRC는 기존 credential HMAC을 대체하지 않는다.

### GC5. 감사가 없다는 것과 사용하지 않았다는 것은 다르다

공식 자료: [Secret Manager audit logging](https://docs.cloud.google.com/secret-manager/docs/audit-logging), [Cloud Audit Logs](https://docs.cloud.google.com/logging/docs/audit), [서비스 계정 감사 예시](https://docs.cloud.google.com/iam/docs/audit-logging/examples-service-accounts#logs-authn).

- **공식 계약:** AccessSecretVersion은 Data Access/DATA_READ다. BigQuery 외의 Data Access 로그는 기본 비활성이다. `serviceAccountKeyName`은 정확한 키 reference이나 일부 서비스는 기록하지 않는다.
- **코드와 추천:** `GCP:cremore_gcp/relations.py:75`의 시간창, 로그 근거와 key 미상 상태를 보존한다. 온보딩에 로그 활성, 조회 권한을 표시하고, 미관측을 미사용, 미노출로 확정하지 않는다. IAM allow는 가능한 접근이며 관측 사용과 분리한다. 현재 Secret 관계 수집은 global 범위다(`GCP:cremore_gcp/relations.py:587`).

### GC6. API 사용량의 지연과 세부 label 확인

공식 자료: [Monitored resources: consumed_api](https://docs.cloud.google.com/monitoring/api/resources#tag_consumed_api), [Service runtime metrics](https://docs.cloud.google.com/monitoring/api/metrics_gcp_p_z#gcp-serviceruntime).

- **공식 계약:** `credential_id`와 `api/request_count`가 있다. 모든 GCP API에 해당 metric이 제공되는 것은 아니며 60초 sampling 후 최대 1,800초 지연될 수 있다.
- **코드와 추천:** `GCP:cremore_gcp/relations.py:340`의 `apikey:{uid}` 문자열 형식은 **코드에서 사용하지만 이번 두 공식 페이지에서 직접 확정하지 못했다.** 실제 metric descriptor/허용된 fixture를 확인하는 조건을 남긴다. 데이터 없음, 0을 미사용 증명으로 표시하지 않는다.

## GitHub

### GH1. Enterprise 자격증명 목록의 identity와 완전성

공식 자료: [Enterprise token inventory](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/token-inventory?apiVersion=2026-03-10).

- **공식 계약:** `GET /enterprises/{enterprise}/credentials`와 App의 `Enterprise credentials` read 권한을 확인했다. 현재 기업 접근 항목 외에 `member_owned_only`도 포함한다. **“there is no total count.”** `Link`의 opaque cursor로 페이지를 조회한다.
- `inventory_id`는 같은 자격증명도 응답 간 바뀔 수 있다. Credential ID는 유형 안에서만 고유하며 ID가 없는 종류도 있다. `token_issuer_principal`은 실제 발급 token이 아니다. `permissions=null`과 `{}`도 다른 의미다.
- **코드와 추천:** `GH:github-api-collector/cremore_collectors/json_evidence.py:189`의 종류, 관계 의미를 보존한다. 안정 공급자 ID가 없으면 실행 내 관찰로 저장한다. Enterprise에 total_count 검사를 강제하지 않는다. 코드가 읽는 `x-github-enterprise-credentials-*` header의 필수 계약은 공개 문서에서 확인하지 못했다. 존재할 때 보존할 선택 증거이지, 부재만으로 실패, 완전성을 확정할 기준이 아니다.

### GH2. 조직 목록, 설치, Actions는 전사 토큰 발급 목록과 다르다

공식 자료: [Organization API](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs?apiVersion=2026-03-10), [PAT와 요청](https://docs.github.com/en/rest/orgs/personal-access-tokens?apiVersion=2026-03-10), [Enterprise installations](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/organization-installations?apiVersion=2026-03-10), [App 접근 repositories](https://docs.github.com/en/rest/apps/installations?apiVersion=2026-03-10), [Deploy keys](https://docs.github.com/en/rest/deploy-keys/deploy-keys?apiVersion=2026-03-10).

- **공식 계약:** SSO 목록은 해당 조직에 승인된 자격증명이다. 조직 fine-grained PAT 목록은 GitHub Apps 전용이며 PAT 읽기 권한을 요구한다. 목록의 route ID와 장기 token ID가 다를 수 있다. 승인 요청, 앱 설치, 부여 가능한 저장소, 실제 부여된 저장소는 별도 정보다.
- **코드와 추천:** 루트의 조직 단독 모드, `--only`, pending 요청과 repository 관계를 모두 인수한다. `GH:cremore_collectors/collectors/fine_grained_pat.py:204`, `GH:github-api-collector/cremore_collectors/supplemental.py:53`의 ID 역할과 context를 유지한다. 총수 검사는 total_count를 제공하는 installations, repositories, Actions runs/jobs 응답에만 적용한다. 저장소 단위 Actions도 포함한다.

Actions 자료: [Permissions](https://docs.github.com/en/rest/actions/permissions?apiVersion=2026-03-10), [Workflow runs](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10), [Workflow jobs](https://docs.github.com/en/rest/actions/workflow-jobs?apiVersion=2026-03-10), [GITHUB_TOKEN](https://docs.github.com/en/actions/concepts/security/github_token).

기본 GITHUB_TOKEN 정책은 각 job의 최종 권한, 원문이 아니다. 필터를 사용하는 runs 검색은 최대 1,000개 제한이 있다. 팀원은 관찰한 `run_attempt`의 jobs를 수집한다. **루트에만 있는 선택 run/job을 보존**하되 모든 과거 attempt 수집으로 확대해 설명하지 않는다(`GH:cremore_collectors/collectors/github_token.py:409`).

### GH3. 감사 페이지 처리와 문서 내 인증 불일치

공식 자료: [Enterprise audit endpoint](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/audit-log?apiVersion=2026-03-10), [Audit API 사용과 페이지 예시](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/using-the-audit-log-api-for-your-enterprise), [Token으로 수행한 사건 식별](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/identifying-audit-log-events-performed-by-an-access-token), [Org audit events](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization).

- **공식 계약:** 일반 조회는 `include=web|git|all`을 안내하며 Git 사건 보존은 7일이다. 현재 팀원 요청은 `web`다. 공급자 SHA-256 `hashed_token`은 사건을 수행한 토큰의 연결 근거이며 CreMore HMAC이 아니다. 사건 대상 토큰과 수행 토큰을 구분한다. 조직 접근 철회가 전역 token 폐기라는 뜻도 아니다.
- **새로 확인한 코드 공백:** 공식 예시의 `after=<cursor>&before=`를 `GH:github-api-collector/cremore_collectors/validation.py:99`가 거절한다. 순수 함수 합성 비교에서 after만 있으면 성공, 빈 before를 더하면 `invalid_pagination_link`였다. 빈 반대 방향 cursor를 정규화하되 host/경로/동일 기업 범위 검사는 유지한다.
- **미확정:** endpoint 페이지 상단의 classic-only 안내와 같은 페이지의 App token/`Enterprise administration` read 표가 상충한다. Token-hash 검색과 Git 사건의 안내도 동일 조건의 보장을 확정하기 어렵다. 팀원 App 경로를 임의 삭제하거나 검증 완료로 바꾸지 않고, 승인 시험 tenant의 인증, 검색 조건 확인을 남긴다.

### GH4. Cloud, ghe.com, GHES와 인증 버전

공식 자료: [App API](https://docs.github.com/en/enterprise-cloud@latest/rest/apps/apps?apiVersion=2026-03-10), [JWT 생성](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app), [Installation 인증](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation), [API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions), [Breaking changes](https://docs.github.com/en/rest/about-the-rest-api/breaking-changes), [GHES API 주소](https://docs.github.com/en/enterprise-server@3.22/rest/using-the-rest-api/getting-started-with-the-rest-api).

- **공식 계약:** Enterprise installation token은 repository 접근 권한이 없다. `2026-03-10`은 공식 지원 API 버전이다. Cloud 문서는 `api.SUBDOMAIN.ghe.com`, GHES는 `HOSTNAME/api/v3`을 안내한다. JWT의 App ID 사용도 허용된다.
- **코드와 추천:** `DEV:cremore/github_hosts.py:49`, `DEV:cremore/github_auth.py:67`을 재사용하고 팀원 요청, 페이지, identity의 public-host 고정을 함께 고친다. **ghe.com은 공급자 문서가 있으나 팀원 구현이 빠진 경우**다. 콘텐츠 클라이언트 전체의 API 버전을 일괄 변경할 필요는 없다.
- **미확정:** GHES 3.22의 같은 token-inventory 문서 경로는 404였다. 이 사실만으로 API 미존재를 단정하지 않는다. 설치 버전별 metadata 계약을 확인한 뒤 지원으로 표시한다.

## Atlassian과 Bitbucket

### AT1. Cloud 관리 API 17개 연산과 권한 차이

공식 자료: [API Access 소개](https://developer.atlassian.com/cloud/admin/api-access/rest/intro/), [API key](https://developer.atlassian.com/cloud/admin/api-access/rest/api-group-api-key/), [API token](https://developer.atlassian.com/cloud/admin/api-access/rest/api-group-api-token/), [Service account](https://developer.atlassian.com/cloud/admin/api-access/rest/api-group-service-account/), [OAuth client](https://developer.atlassian.com/cloud/admin/api-access/rest/api-group-oauth-client/), [Managed users](https://developer.atlassian.com/cloud/admin/organization/rest/api-group-users/#api-v1-orgs-orgid-users-get), [User manage](https://developer.atlassian.com/cloud/admin/user-management/rest/api-group-manage/), [Profile](https://developer.atlassian.com/cloud/admin/user-management/rest/api-group-profile/), [User API tokens](https://developer.atlassian.com/cloud/admin/user-management/rest/api-group-api-tokens/), [Admin scopes](https://developer.atlassian.com/cloud/admin/scopes/).

- **공식 계약:** 관리자 key는 Bearer로 사용한다. 서비스 계정 목록은 Preview다. OAuth count는 읽기 POST이며 명세에 request body가 없다. 조직 관리와 사용자 관리는 역할, 권한 범위가 다르다.
- **대조 결과:** 아래 API Access, Organizations, User management의 OpenAPI로 **팀원 17개 route/method 전부 대응**을 확인했다. `AT:atlassian_collector/read_operations.py:10`의 정규화 source5개는 이17개에 포함된다. Count/detail에는 credential ID가 없어도 정상이다.
- **미확정:** API-key endpoint/OpenAPI는 `read:keys:admin`, 공통 scope 표는 `read:tokens:admin` 설명에 key 목록/count를 포함한다. Endpoint별 scope를 우선 안내하고 실환경 확인을 남긴다. 팀원 과거 service-account 404, OAuth count 400은 문서의 존재만으로 해결되지 않았다. 관찰된 OAuth 배열 variant도 전체 목록으로 확정하지 않는다.

### AT2. Bitbucket Cloud 26개와 인증 방식

공식 자료: [REST 소개, 인증, 페이지 처리](https://developer.atlassian.com/cloud/bitbucket/rest/intro/), [SSH](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-ssh/), [Deployments](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-deployments/), [Pipelines](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-pipelines/), [API tokens](https://support.atlassian.com/bitbucket-cloud/docs/api-tokens/).

- **공식 계약:** 개인 API token은 **email+Basic**, OAuth 등의 해당 access token은 Bearer 방식이다. `next`는 불투명한 페이지 위치이며 size/page는 선택 필드다. Pipeline SSH key pair GET은 private key를 제외한다.
- **대조 결과:** Cloud OpenAPI와 core22+Runner4의 **26개 GET 전부 대응**을 확인했다. `AT:atlassian_collector/http.py:124`는 인증이 필요한 요청에서 Bearer만 지원한다. `DEV:cremore/collectors/enterprise.py:40`, `DEV:cremore/source_config.py:75`의 기존 Basic/Bearer 선택 의미를 metadata에 재사용하고, 기존 OIDC 설정, JWKS 두 연산의 무인증 처리는 유지한다. 콘텐츠 전용 URL 조립까지 공유하지는 않는다.
- **추천:** 공개키, OIDC trust를 노출 credential 수로 합산하지 않는다. Cloud resource-token, 일반 OAuth consumer의 전수 목록은 이번 계약 확인 범위에 없다. 공급자에게 API가 없다고 단정하지 않는다.

### AT3. Runner의 다음 페이지

공식 자료: [Pipelines의 Runner API](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-pipelines/), [공식 autoscaler 안내](https://support.atlassian.com/bitbucket-cloud/docs/autoscaler-for-runners-on-kubernetes/), [안내가 연결한 공개 소스의 고정 버전](https://bitbucket.org/bitbucketpipelines/runners-autoscaler/src/ea224f807f42f81c5763781f3c1b2b141b303406/autoscaler/clients/bitbucket/base.py).

- **확인한 내용:** 공개 명세의 Runner4개와, 공식 안내가 연결한 공개 코드의 `/internal/...`, 응답 next 순회를 함께 확인했다. Autoscaler의 제한된 지원 범위를 모든 내부 API의 안정 계약으로 확대하지 않는다.
- **코드와 추천:** `AT:atlassian_collector/read_operations.py:63`의 exact-path 검사는 해당 next를 거절한다. 첫 공개 endpoint 이후 **동일 workspace/repository를 확인한 Runner 다음 페이지에 한해** 허용한다. 모든 internal URL 허용이나 반환 URL의 임의 재작성은 피한다. 기존 차단 테스트는 안전 경계를 유지하면서 같은 자원의 여러 페이지를 받는 인수 테스트로 보완한다.

### AT4. Cloud Enterprise와 Data Center는 다른 제품이다

공식 자료: [Bitbucket DC HTTP tokens](https://confluence.atlassian.com/bitbucketserver/http-access-tokens-939515499.html), [관리](https://confluence.atlassian.com/bitbucketserver/managing-http-access-tokens-1005339986.html), [DC10.0 Authentication REST](https://developer.atlassian.com/server/bitbucket/rest/v1000/api-group-authentication/), [Jira/Confluence PAT](https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html).

- **공식 계약:** DC10.0에는 `/rest/access-tokens/latest/` 아래 user/project/repository별 목록, 상세 **GET6개**가 있다. 페이지는 start/limit/nextPageStart 방식이다. 명세의 `RestAccessToken`은 id/name/createdDate를 명시한다.
- **추천:** 현재 양쪽 코드에 없는 metadata adapter의 후속 후보로 둔다. 권한, 만료, last-used를 이 schema만으로 약속하지 않는다. 기존 Cloud/DC 콘텐츠 기능을 유지하고 설치 버전별 목록 권한을 확인한다. Confluence/Jira DC PAT와 관리자 화면은 확인했지만 버전별 관리자 REST 전체 목록 계약은 미확정이다.

경로/method 대조에 사용한 공식 명세:

| 명세 | 확인한 부분 | 받은 본문의 SHA-256 |
|---|---|---|
| [API Access](https://dac-static.atlassian.com/cloud/admin/api-access/swagger.v3.json?_v=1.0.23) | 사용 연산13개 | `eb9c7a84b5353f9a4a44ece2c892d7064cf07c6a2657a48c752fec3523240b88` |
| [Organizations](https://dac-static.atlassian.com/cloud/admin/organization/swagger.v3.json?_v=1.234.173) | managed users1개 | `c2e5d2903268aadd28a6de1e82d09a7aa410a05d328139f5bf01bef443e68807` |
| [User management](https://dac-static.atlassian.com/cloud/admin/user-management/swagger.v3.json?_v=1.48.23) | user GET3개 | `cc21935862dd9eaa5fa4cf76b261a79de1572d39417daaf16e399deea84c705f` |
| [Bitbucket Cloud](https://dac-static.atlassian.com/cloud/bitbucket/swagger.v3.json?_v=2.300.192) | GET26개 | `5faacee02bacc835ed865aac8a3b5fee8686b9d095e46e187ad54e9cd2d268c7` |
| [Bitbucket DC10.0](https://developer.atlassian.com/server/bitbucket/10.0.swagger.v3.json) | token GET6개, schema | `7be638eefc1e780d78051f4f332561a740211a4453a29079a6e382d2aa67104a` |

명세 대응은 경로, method, 정의된 필드의 확인이다. 실제43개 연산 성공, customer 권한, 이전 기록의 오류 해소를 증명하지 않는다.

## Slack과 외부 Vault

### SL1. 메시지, 스레드, Enterprise workspace 범위

공식 자료: [history](https://docs.slack.dev/reference/methods/conversations.history/), [replies](https://docs.slack.dev/reference/methods/conversations.replies/), [list](https://docs.slack.dev/reference/methods/conversations.list/), [Conversations API](https://docs.slack.dev/apis/web-api/using-the-conversations-api/).

- **공식 계약:** 현재 replies 문서는 Bot/User 양쪽 scope를 안내한다. 과거의 ‘공개/비공개 thread는 User token만 가능’이라는 설명을 현재 사실로 쓰지 않는다. 실제 읽기 범위는 token kind, scope, 멤버십에 달린다. 조직 전체 token의 list에는 `team_id`가 필요하다. 빈 페이지여도 next_cursor가 있을 수 있다.
- **코드와 추천:** `S:app/socket_mode.py:118`은 `team_id`를 전달하지 않는다. 조직 연결과 workspace별 작업을 구분하고, 같은 채널 이름/메시지 시각이 다른 workspace와 충돌하지 않게 한다. 설정된 수집 연결의 실제 권한 결과를 기록한다.

### SL2. 앱 배포 유형에 따른 rate와 Socket Mode

공식 자료: [Web API rate limits](https://docs.slack.dev/apis/web-api/rate-limits/), [현재 rate 변경 안내](https://docs.slack.dev/changelog/2025/05/29/rate-limit-changes-for-non-marketplace-apps/), [Socket Mode](https://docs.slack.dev/apis/events-api/using-socket-mode/).

- **공식 계약:** 새 비Marketplace 상용 배포 앱/설치의 history/replies는 각각 1회/분, 최대, 기본15건이다. Marketplace, 내부 고객 제작 앱은 Tier3다. 현재 변경 안내는 기존 외부 배포 앱의 기존 설치를 새 제한에서 제외한다. Socket Mode는 public Marketplace에 등록할 수 없다고 안내한다.
- **코드와 추천:** 팀원 `limit=200`을 모든 연결의 계약으로 고정하지 않는다. 앱/워크스페이스/method 기준의 한도와 `Retry-After`를 작업 재개 시각에 반영한다. 내부 Socket과 배포용 HTTP Events 모드를 구분한다. EC2/EKS에 설치했다는 사실만으로 내부 앱 예외를 받는다고 표시하지 않는다.

### SL3. 이벤트 ACK와 복구

공식 자료: [Events API](https://docs.slack.dev/apis/events-api/), [Socket Mode](https://docs.slack.dev/apis/events-api/using-socket-mode/).

- **공식 계약:** HTTP Events는 3초 이내 응답과 제한된 재시도를 안내하며 best-effort다. Socket은 envelope ACK, 연결 갱신이 필요하다. 두 전송 방식의 재시도 시간표가 같다고 가정하지 않는다.
- **코드와 추천:** `S:app/socket_mode.py:459`는 저장 전 ACK, `S:app/main.py:67`은 동기 처리 후 HTTP 응답이다. 새 영속 수신 기록→ACK→worker 처리 순서를 설계한다. 기존의 최근 시간창만 재조회하면 오래된 root의 새 thread reply 복구를 보장하지 못한다(`S:app/socket_mode.py:513`). 재조회 범위와 메시지 revision, 알림 outbox를 함께 구현한다.

### SL4. 승인 앱, 감사, 설치 사건

공식 자료: [approved.list](https://docs.slack.dev/reference/methods/admin.apps.approved.list/), [Audit Logs](https://docs.slack.dev/admins/audit-logs-api/), [Audit methods](https://docs.slack.dev/reference/audit-logs-api/methods-actions-reference/), [app_installed](https://docs.slack.dev/reference/events/app_installed/), [app_uninstalled_team](https://docs.slack.dev/reference/events/app_uninstalled_team/).

- **공식 계약:** 승인 앱은 설치 앱 목록이 아니다. **Enterprise 조직 Admin 또는 Owner가 조직 전체에 설치한 앱의 User token**과 `admin.apps:read`를 요구하며 `certified=false` 기본값은 certified 앱을 제외한다. Audit은 **Enterprise Owner User token, auditlogs:read, 조직 설치** 조건이고 조직 Admin token은 지원하지 않는다고 명시한다.
- 두 설치 사건은 조직 전체 설치 앱만 구독할 수 있고 제거 사건은 `admin.apps:read`도 필요하다. Audit API는 메시지 내용을 제공하지 않는다.
- **코드와 추천:** `S:app/slack_admin_inventory.py:67`의 기본 응답을 전체 승인 자산으로 표현하지 않는다. 필요한 certified 범위, 중복 제거와 source별 권한을 기록한다. `S:app/slack_audit.py:72`의 앱/scope/token 관련 action 선택은 Slack 전체 감사 수집이 아니다.

### SL5. 소유 토큰의 역할, 수명주기와 GovSlack

공식 자료: [Token 종류](https://docs.slack.dev/authentication/tokens/), [Rotation](https://docs.slack.dev/authentication/using-token-rotation/), [OAuth access](https://docs.slack.dev/reference/methods/oauth.v2.access/), [OAuth exchange](https://docs.slack.dev/reference/methods/oauth.v2.exchange/), [Configuration rotate](https://docs.slack.dev/reference/methods/tooling.tokens.rotate/), [Auth revoke](https://docs.slack.dev/reference/methods/auth.revoke/), [Slack CLI 인증](https://docs.slack.dev/tools/slack-cli/guides/authorizing-the-slack-cli/).

- **공식 계약:** 회전을 사용하는 OAuth access token은 12시간, refresh는 일회 사용 후 짧은 grace가 있다. 회전을 사용하지 않는 장기 access token까지 같은 만료를 적용하지 않는다. Configuration은 별도 token 계열이다. Workflow 완료는 상태 변경이고 Service CLI token과 일반 User token도 같은 관리 계약이 아니다. `auth.revoke(test=1)`은 실제 폐기는 하지 않지만 외부 API 호출이다.
- **코드와 추천:** 팀원의 명시 소유 토큰 관리, 관찰 시각, 실패 의미를 보존한다. Access/refresh의 원자적 저장과 교체 후 저장 실패 복구는 새 구현이 필요하다. 발견된 후보를 own-token으로 자동 등록하지 않는다. DPAPI 자료는 원 Windows 사용자 환경에서 이행한다. 원문이 없는 과거 지문은 legacy scheme으로 유지한다.
- **미확정:** GovSlack은 `slack-gov.com`을 쓰지만 팀원 HTTP 호출은 일반 도메인 고정이다. `auth.revoke`의 코드 POST와 현재 method/SDK GET 안내의 호환성도 시험이 남았다. 둘을 이미 검증된 지원/실패로 단정하지 않는다.

### SL6. 외부 Vault 목록과 값 대조, Azure 회전 시각

공식 자료: [AWS ListSecrets](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html), [GetSecretValue](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html), [GCP secrets.list](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/list), [versions.access](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions/access), [Azure SecretClient](https://learn.microsoft.com/en-us/python/api/azure-keyvault-secrets/azure.keyvault.secrets.secretclient?view=azure-python), [SecretProperties](https://learn.microsoft.com/en-us/python/api/azure-keyvault-secrets/azure.keyvault.secrets.secretproperties?view=azure-python), [Vault KV v2](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2), [Vault API](https://developer.hashicorp.com/vault/api-docs), [OpenBao KV v2](https://openbao.org/docs/api/secret/kv/kv-v2/).

- **공식 계약:** 목록 metadata와 값 읽기는 별개다. AWS ListSecrets는 최근5분 변경을 반영하지 못할 수 있다. Azure의 목록에는 secret value가 없고 버전 목록도 별도다. Vault/OpenBao LIST/GET metadata는 payload가 아니다.
- **정정:** Azure `updated_on`은 수정 시각이다. 값을 바꾸지 않는 property 수정도 가능하므로 `S:app/cloud_secrets_inventory.py:167`의 근거 없는 `last_rotated_at` 매핑을 제거하고 미확인으로 둔다. 코드가 이미 저장하는 `updated_at`은 유지한다. 태그의 회전 정보는 운영자 선언으로 표시한다.
- **추천:** AWS/GCP/Vault는 develop 기존 어댑터에 metadata를 보완하고, Azure는 새 metadata 공급자로 추가한다. 외부 금고에 같은 값이 있는지는 기존 값 지문, 범위, 마지막 확인으로 판단한다. `DEV:cremore/secretstore/vault.py:169`는 현재 CAS를 전달하지 않는다. 공식 CAS 기능의 존재를 제품의 구현 완료로 바꾸지 않는다. OpenBao의 최신 확장도 버전별 계약이며 공통 어댑터에 이미 구현됐다고 표시하지 않는다.

## 이번 확인으로 해결되지 않은 것

고객별 라이선스, 설치 버전, 실제 권한, quota, GitHub 감사 인증 문서의 상충, Atlassian 과거400/404, 배열 완전성, GCP metric label의 정확한 값, GovSlack, Data Center의 미구현 metadata는 구현 또는 실환경 검증이 남았다. 공개 문서의 경로 존재와 원본 오프라인 테스트 통과는 이 조건을 대신하지 않는다.

조회한 HTML/JSON, 추출 텍스트, 최종 URL, HTTP 상태, 조회 시각, SHA-256과 상세 조사 메모는 조사용 `work/integration-review/`에 보관했다. 공유 문서에는 위 공식 URL, 핵심 계약, 고정 소스 근거와 미확정 사항을 남겼다.
