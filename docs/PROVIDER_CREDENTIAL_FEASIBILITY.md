# 공급자별 자격증명 인벤토리·노출·금고 대조 기술 검토

확인일: **2026-09-25**. 공식 공개 문서와 공식 OpenAPI를 직접 조회하고 현재 `refactoring` 작업 트리와 대조했다.
이 문서는 기술 가능성 평가다. 고객 계정에서의 실제 API 동작 검증이나 기능 구현 완료 보고서가 아니다.
Self-Managed/Data Center는 고객의 설치 버전, Cloud는 요금제·조직 관리 범위·권한에 따라 지원이 달라진다.
공개 문서에서 확인하지 못한 기능은 `미확인`으로 표시하며 `불가능`과 구분한다.

> **코드 기준 주의:** 아래의 코드 비교는 조사 시작 시점의 기준선이다. 이후 공급자 구현이 진행되어
> 현재 작업 트리와 차이가 있다. 통합 내용·실행 검증·남은 작업은
> [구현·검증 기록](PROVIDER_INVENTORY_IMPLEMENTATION.md)을 확인한다. 공식 API 가능성과 구현 완료는 별개다.

## 1. 목표와 판단

CreMore의 목표는 서로 다른 세 자료를 연결하는 것이다.

1. **발급 인벤토리**: 공급자가 관리하는 키·토큰의 식별자, 소유자, 범위, 상태, 생성·만료·사용 시각.
2. **노출 관측**: 허용된 저장소·문서·객체에서 발견한 평문 자격증명과 발견 위치.
3. **금고 관리 근거**: 기업 금고의 현재/과거 버전 값, 또는 금고가 자격증명을 발급·관리했다는 이력.

이 구조는 기술적으로 가능하다. 다만 **모든 공급자의 모든 자격증명을 전수 열거하고, 모든 항목을
금고와 정확하게 연결하는 보편적 기능은 보장할 수 없다.** 일부 공급자는 토큰 원문·비교용 지문을
반환하지 않으며, Azure SAS처럼 발급 자체를 추적하지 않는 자격증명도 있다.

| 원하는 판정 | 필요한 증거 | 판정의 한계 |
| --- | --- | --- |
| 노출되었고 금고에도 저장됨 | 노출값과 허용된 금고 버전 값의 호환되는 지문 일치 | 발급 인벤토리에 해당 토큰이 없어도 가능. 과거 버전 일치와 현재 저장을 구분 |
| 노출되었으나 금고에서 찾지 못함 | 선언한 금고 범위의 정상·완전·최신 수집과 동일 비교 계약 | 기업 어디에도 없다고 확대하지 않음. 권한 거절·부분 수집은 `UNKNOWN` |
| 발급되어 있지만 금고에서 찾지 못함 | 발급 항목과 금고 내용을 연결할 공통 ID·값 지문·신뢰 가능한 저장 이력 | 불투명 토큰의 이름·소유자·시간만으로는 정확한 연결 및 부재를 보장하지 못함 |
| 금고가 동적으로 발급·관리함 | 발급 이력·lease·소유 관계 | KV에 정적으로 저장됨과 다른 상태. KV에 없다는 이유로 관리 누락 처리하면 안 됨 |

발급 항목의 **식별자 일치**, **비밀값 일치**, **인증 결과**, **서비스 권한**은 서로 다른 증거다.
예를 들어 키 ID가 맞아도 함께 발견한 비밀키가 진짜 키인지는 별개이며, 값이 금고와 같아도 현재 사용 가능한지는 별개다.
콘텐츠가 발견된 공급자와 자격증명의 발급 공급자도 다르다. Notion 문서에서 AWS 키가 발견될 수 있다.

## 2. 공급자별 요약

| 공급자 | 공식적으로 확인한 발급 인벤토리 | 주요 제약 | 조사 시작 시점 CreMore와의 차이 |
| --- | --- | --- | --- |
| AWS | IAM 사용자 키·credential report, 조직 계정 발견 | 키 원문 재조회 불가. STS 전체 활성 세션 목록 API 없음 | 계정별 schema 1 경로 존재. IAM/로그 관측을 모든 임시 토큰의 전수 목록으로 해석하면 안 됨 |
| GitHub | Enterprise Cloud credential inventory, 조직 fine-grained PAT·SSO 승인·deploy key | 기업/조직 범위가 다름. 일부 항목만 비교용 hash 제공 | 인벤토리 API는 연결됐으나 hash를 제외하고 finding에는 후보만 제공 |
| GitLab | 관리자 PAT·deploy token, 그룹/프로젝트 token, GitLab.com 기업 사용자 인벤토리 | 호스팅·요금제·관리자/Owner·enterprise user 범위 | 여러 수집 경로 구현. 인스턴스 전체 PAT·CI 변수 값·일반 발급→금고 연결은 추가 작업 |
| GCP | 서비스 계정 키·API keys·Secret Manager | 프로젝트별 권한. SA 비밀키 재조회 불가. 단기 토큰 전수 목록 아님 | 프로젝트 단위 수집·선택적 값 지문화 존재. 조직 발견·finding 식별자 연결 통합은 추가 작업 |
| Azure | Entra 앱/SP 자격증명, Storage 계정 키, Key Vault | SAS 전수 발급 목록 불가. Entra client secret 재조회 불가 | 현재 Key Vault secrets 메타데이터 중심. Entra·Storage·값 대조는 미구현 |
| Atlassian Cloud | 조직 API key·사용자 API token·서비스 계정 token/OAuth client | 조직 관리 범위·개별 기능 entitlement. Bitbucket까지 완전 포괄 여부 미확인 | 여러 admin 수집 구현. 불투명 값의 일반 exact 연결은 없음 |
| Bitbucket Cloud | SSH/deploy 공개키·리소스 | access-token 목록 REST API 지원 미확인. secured CI 변수 값 비공개 | 공개키/리소스 수집 중심. 토큰 전수 인벤토리 완료로 표시하면 안 됨 |
| Bitbucket Data Center | 사용자·프로젝트·저장소 HTTP access-token 목록 | 설치 버전·DC license·관리 권한. 원문 재조회 불가 | DC 프로젝트 HTTP access-token metadata 수집 구현(프로젝트 범위만, [Atlassian](../atlassian/README.md)) |
| Confluence Data Center | 관리자 PAT 목록 UI | 안정된 전체 목록 REST 계약은 이번 조사로 미확인 | 콘텐츠 스캔 지원과 발급 인벤토리 지원을 구분 |
| Notion | Enterprise Admin PAT 목록, 별도 MCP 연결 목록 | Enterprise 전용. PAT 원문 비공개. 모든 integration/token 종류를 포괄하지 않음 | Enterprise 조직 봇으로 PAT·MCP 연결 metadata 수집 구현([Notion](../notion/README.md)) |
| Slack | Enterprise Grid 승인 앱과 scope의 token type(bot/user), 감사 로그의 앱 설치·제거 | 설치된 앱 목록 API 없음(승인≠설치). 토큰 값·웹훅 URL·사용 기록 비공개. Enterprise Grid·조직 관리자 필요 | 발급 인벤토리 없음(콘텐츠 탐지기만). 2026-09-28 추가(아래 10절) |
| Vault / OpenBao | KV 목록·버전·값, 별도 service-token accessor·lease metadata | list와 read 권한 분리. batch token 전수 열거 제약. 동적 관리와 KV 저장은 다름 | 명시한 KV 범위의 고객 측 지문화 경로 존재. 동적 발급 인벤토리는 미구현 |

## 3. AWS

- [IAM ListAccessKeys](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html)는 특정 IAM 사용자 access key의 ID·상태·생성 시각을 반환한다.
  사용자 목록을 순회하는 계정별 수집이 가능하다.
- [Credential report](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html)는 계정의 사용자와 자격증명 상태를 보완한다.
  root 상태와 개별 IAM 키의 식별자 목록을 동일한 자료로 취급하지 않는다.
- [Access key 관리](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)는 secret access key를 생성 때만 조회할 수 있다고 명시한다.
  따라서 키 ID 연결은 가능하지만 발급 목록만으로 secret 값 대조까지 끝나는 것은 아니다.
- [Organizations ListAccounts](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccounts.html)로 계정을 발견할 수 있다.
  management account 또는 delegated administrator 범위이며, 발견이 각 계정의 IAM 읽기 승인을 대신하지 않는다.
  Organizations가 없는 단일/독립 계정은 명시적 계정 연결로 처리할 수 있다.
- [STS 공식 작업 목록](https://docs.aws.amazon.com/STS/latest/APIReference/API_Operations.html)에는 모든 활성 세션을 열거하는 API가 없다.
  [임시 자격증명 문서](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)는 요청 시 동적으로 생성되고 만료됨을 설명한다.
  역할·신뢰 설정·발급/사용 로그의 관측과 실제 토큰 전수 목록을 구별한다.
- [CloudTrail Event history](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)는 최근 90일 관리 이벤트이며 계정·리전 단위다.
  관측되지 않았다는 사실을 미발급 또는 미사용으로 확정할 수 없다.
- [Secrets Manager GetSecretValue](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html)는 허용된 secret 버전 값을 반환한다.
  승인된 값 읽기와 지문화에 기반한 노출값 대조는 가능하다.

**판단:** 장기 IAM 키 인벤토리와 금고 비교는 가능하다. 모든 STS 세션까지 동일한 완전성을 약속하면 안 된다.

## 4. GitHub

[Enterprise credential inventory](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/token-inventory)는
2026-03-10 API 버전에서 기업에 승인된 자격증명 및 기업 구성원 소유 자격증명을 조회한다.
classic/fine-grained PAT, OAuth/GitHub App user token, SSH key, App installation, federated credential을 포함한다.
설치·연합 신뢰 설정과 실제 단일 비밀 토큰은 다른 종류의 객체다.

- Enterprise Owner 또는 `View enterprise credentials` 권한이 필요하다.
  classic PAT/OAuth는 `read:enterprise`, GitHub App은 `Enterprise credentials: read` 권한을 사용한다.
- `hashed_token`은 제공되지 않으면 null이다. 형식은 문서에 없어 **Base64로 표현한 SHA-256 토큰 해시로 가정**한다
  ([token inventory](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/token-inventory), github/README.md와 같은 가정).
  이 값이 제공되는 항목은 발견값과 외부 인증 없이 정확한 값 연결이 기술적으로 가능하다.
- SSH는 공개키 지문을 제공한다. `credential_id`는 credential type 안에서 유일하므로 기업·유형 경계도 필요하다.
- 공급자 SHA-256과 CreMore의 keyed fingerprint/HMAC은 서로 다른 비교 계약이다. 그대로 비교하면 안 된다.
- 이 결론은 Enterprise Cloud 문서 기준이다. GHES는 설치 버전의 API 지원을 별도로 확인해야 한다.

일반 조직에서는 [fine-grained PAT 목록](https://docs.github.com/en/rest/orgs/personal-access-tokens#list-fine-grained-personal-access-tokens-with-access-to-organization-resources),
[SSO 승인 목록](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#list-saml-sso-authorizations-for-an-organization),
[deploy key 목록](https://docs.github.com/en/rest/deploy-keys/deploy-keys)을 조합할 수 있다.
이것을 모든 구성원이 가진 모든 개인 토큰의 목록으로 확대하면 안 된다. SSO 목록의 토큰 끝자리만으로 값 일치를 확정해서도 안 된다.

[Actions Secrets API](https://docs.github.com/en/rest/actions/secrets)는 조직·저장소·환경 secret의 이름·시각·접근 범위를 조회하지만 값을 반환하지 않는다.
따라서 Actions secret 이름과 Vault 경로가 비슷하다는 이유로 같은 자격증명이 저장됐다고 증명할 수 없다.
신뢰 가능한 발급·저장 기록이 별도로 필요하다.

**조사 시작 당시 코드:** `github/backend/cremore_github_provider/metadata/adapter.py`는 enterprise endpoint를 사용한다.
`projection.py`는 `hashed_token`을 allowlist에서 제외하고 비밀 모양의 필드로 차단한다.
`cremore/coverage/metadata_correlation.py`는 후보만 반환한다. Actions secret 실제 목록 수집도 추가 작업이다.
즉 **정확한 연결이 모두 API상 불가능하다는 기존 일반화는 수정해야 한다.**

## 5. GitLab

- [PAT API](https://docs.gitlab.com/api/personal_access_tokens/): 인스턴스 관리자는 전체 PAT를, 일반 사용자는 자신의 PAT만 조회한다.
  ID·사용자·scope·활성/폐기·생성/만료/사용 시각 등을 수집할 수 있다. 토큰 원문은 일반 목록 응답이 아니다.
  Self-Managed/Dedicated 관리자 범위와 GitLab.com 고객 권한을 구분해야 한다.
- [Groups credentials inventory management](https://docs.gitlab.com/api/groups/#credentials-inventory-management):
  GitLab.com **Premium/Ultimate**, top-level group Owner가 enterprise users의 PAT 및 그룹/프로젝트 token 등을 수집할 수 있다.
  18.7 GA이며 외부 협업자 모두가 enterprise user인 것은 아니다.
  [Credentials inventory UI](https://docs.gitlab.com/user/group/credentials_inventory/)의 Ultimate 요금제 설명과 API 요금제를 혼동하지 않는다.
- [Group access token](https://docs.gitlab.com/user/group/settings/group_access_tokens/),
  [Project access token](https://docs.gitlab.com/user/project/settings/project_access_tokens/): GitLab.com은 Premium/Ultimate,
  Self-Managed/Dedicated는 모든 라이선스에서 지원한다. 그룹 Owner/프로젝트 Maintainer 등의 권한이 필요하다.
  생성 이후 원문 재조회는 불가하므로 불투명 token 값과 목록 ID를 일반 메타데이터만으로 무조건 연결할 수는 없다.
- [Deploy tokens API](https://docs.gitlab.com/api/deploy_tokens/): 프로젝트/그룹 범위 및 Self-Managed/Dedicated 관리자 전체 목록을 제공한다.
- [Admin Token information API](https://docs.gitlab.com/api/admin/token/)에는 관리자 신원으로 제출된 토큰의 정보를 식별하는 기능이 있다.
  발견 토큰 자체로 인증하는 방식이나 오프라인 비교와는 다른 처리다. 페이지 상단은 Self-Managed/Experiment,
  조회 절은 17.8 GA로 표시되어 있으므로 고객 버전의 지원 상태를 확인해야 한다. 이 조사에서 호출하지 않았다.
- [Project variables](https://docs.gitlab.com/api/project_level_variables/)와
  [Group variables](https://docs.gitlab.com/api/group_level_variables/) API의 GET 응답에는 `value`가 있다.
  따라서 승인된 CI 변수 값의 지문 대조는 기술적으로 가능하다. `masked`와 `hidden`은 구분해야 하며,
  [hidden 설명](https://docs.gitlab.com/ci/variables/#hide-a-cicd-variable)의 UI 제한만으로 모든 버전의 API 값 반환 여부를 확정하지 않는다.

**조사 시작 당시 코드:** self PAT·그룹/프로젝트 token·service account·managed-group 등의 수집이 있다.
인스턴스 전체 PAT 수집은 현재 self 범위 제한과 별개로 확장할 수 있다. CI 변수 값 대조와 범용 발급→금고 연결은 미구현이다.

## 6. GCP

- [서비스 계정 키 목록](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/list)은
  `iam.serviceAccountKeys.list` 권한으로 키 식별자·유형·상태·시각을 제공한다.
  [키 리소스](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys)는
  user-managed private key를 보관하지 않으며 `privateKeyData`는 생성 응답에만 제공한다고 명시한다.
  [JSON 키 형식](https://docs.cloud.google.com/iam/docs/keys-create-delete)의 `client_email`과 `private_key_id`로 발급 항목을 식별할 수 있다.
  이것은 비밀키 자체의 정합성 검증과 구별한다.
- [API keys.list](https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/list),
  [getKeyString](https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/getKeyString)은 프로젝트별 목록과 별도 권한의 키값 조회를 제공한다.
  따라서 API key는 발급값과 금고값의 지문 비교까지 가능하다.
  [lookupKey](https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/keys/lookupKey)는 수집기 관리 권한으로 key string의 프로젝트/리소스를 확인하는 별도 기능이다.
- [Secret Manager 목록](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/list)과
  [버전 값 접근](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions/access)은 권한이 분리된다.
  `latest`는 최근 생성 버전이며 과거 버전 전체를 수집했다는 뜻이 아니다.
- [Resource Manager projects.list](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/list)는 직계 자식만 반환하므로 조직/폴더 재귀가 필요하다.
  [projects.search](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/search)는 호출자에게 보이는 프로젝트만 반환하며 eventual consistency다.
  프로젝트 발견과 개별 키/secret 접근 권한은 별개다.
- [IAM Credentials 리소스](https://docs.cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts)는 영속 자료가 없다고 명시하고 발급/서명 작업을 제공한다.
  모든 살아 있는 OAuth/OIDC 토큰의 목록 API로 해석할 수 없다.
  [Workload Identity Federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation)은 장기 키 대신 단기 토큰을 쓰는 방식이다.

**조사 시작 당시 코드:** 프로젝트별 SA key/API key/Secret Manager 수집과 선택적 값 지문화가 있다.
`link_service_account_key` helper는 존재하지만 finding 자동 연결 경로에 통합되지 않았다.
조직/폴더 프로젝트 발견도 추가 구현 대상이다. Secret 접근 로그는 그 자격증명이 Secret 안에 저장됐다는 증거가 아니다.
조사 당시 GCP에는 `include_values`·`store_values` 전용 원문 저장 옵션이 있었다.
2026-10-02 변경으로 원문 저장·관리자 조회는 폐기했다. `include_values`로 승인된 값을 메모리에서 읽고
HMAC 지문과 필요한 메타데이터만 남긴다. 과거 원문·백업은 [별도 이관](integration/GCP_TOTAL_GUIDE_KO.md#과거-원문-저장-설치의-이관) 대상이다.

## 7. Azure / Entra

- Microsoft Graph v1.0의 [applications](https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0)와
  [servicePrincipals](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0)를 통해
  `Application.Read.All` 등 승인된 권한으로 앱/SP 자격증명 메타데이터를 수집할 수 있다.
- [passwordCredential](https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential?view=graph-rest-1.0)은
  `keyId`·표시명·기간·3자 hint를 제공한다. `secretText`는 최초 생성 때만 반환하며 나중에 복구할 수 없다.
  client secret 원문만으로 특정 `keyId`를 수동적으로 정확하게 연결한다고 보장할 수 없다.
  [keyCredential](https://learn.microsoft.com/en-us/graph/api/resources/keycredential?view=graph-rest-1.0)은 공개 인증서/식별자 기반 연결이 가능하다.
- [Federated identity credentials](https://learn.microsoft.com/en-us/graph/api/federatedidentitycredential-list?view=graph-rest-1.0)는 신뢰 설정이며 발급된 단기 토큰의 목록이 아니다.
- Key Vault 2025-07-01의 [Get Secrets](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secrets/get-secrets?view=rest-keyvault-secrets-2025-07-01)는 식별자·속성,
  [Get Secret](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret/get-secret?view=rest-keyvault-secrets-2025-07-01)은 별도 `secrets/get` 권한의 실제 값을 제공한다.
  값 지문화는 기술적으로 가능하다. [Get Key](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-key/get-key?view=rest-keyvault-keys-2025-07-01)는 공개 부분만 반환하고 대칭키 재료를 반환하지 않는다.
- [구독별 Vault 목록](https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults/list-by-subscription?view=rest-keyvault-keyvault-2024-11-01)으로 다중 Vault 발견이 가능하다.
  Graph tenant, ARM subscription, Key Vault data-plane 권한은 분리된다.
- [Storage listKeys](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list-keys?view=rest-storagerp-2025-01-01)는 승인된 관리 권한으로 계정 키값을 반환한다.
  이 키들은 Entra 앱 인벤토리와 별도 자격증명 종류다.
- [SAS 공식 설명](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview)은
  **“The SAS token is not tracked by Azure Storage in any way.”**라고 명시하고 발급 개수를 알려주는 API도 없다고 설명한다.
  과거에 발급된 모든 SAS 목록을 API 추가만으로 복원하는 것은 불가능하다. 고객 발급 시스템의 기록·사용 로그·노출 관측으로 범위를 한정해야 한다.
- [Managed identities](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)는 개발자가 자격증명을 직접 관리하지 않는 방식이다.
  금고 미저장 경고를 일괄 적용할 대상이 아니다.

**조사 시작 당시 코드:** Azure adapter는 한 Vault의 secrets 메타데이터 중심이며 값 읽기/값 match를 명시적으로 거절한다.
Entra·Storage 발급 인벤토리와 Key Vault 값 지문화는 공급자 한계가 아닌 제품 구현 공백이다.

## 8. Atlassian / Bitbucket / Confluence

### Atlassian Cloud

[API Token](https://developer.atlassian.com/cloud/admin/api-access/rest/api-group-api-token/),
[API Key](https://developer.atlassian.com/cloud/admin/api-access/rest/api-group-api-key/),
[Service Account](https://developer.atlassian.com/cloud/admin/api-access/rest/api-group-service-account/),
[OAuth Client](https://developer.atlassian.com/cloud/admin/api-access/rest/api-group-oauth-client/) 공식 API로
조직의 사용자 token, admin key, 서비스 계정 token 및 OAuth client 메타데이터를 수집할 수 있다.
필요 scope는 각각 `read:tokens:admin`, `read:keys:admin`, `read:service-accounts-tokens:admin` 등이다.
OAuth client 목록이 모든 access/refresh token의 목록은 아니다.

[사용자별 token 관리](https://developer.atlassian.com/cloud/admin/user-management/rest/api-group-api-tokens/)는
조직 관리 계정 경계를 따른다. [admin API key 안내](https://support.atlassian.com/organization-administration/docs/manage-an-organization-with-the-admin-apis/)는
Organization admin·All plans로 설명하지만 이것이 개별 서비스 계정·정책 기능의 모든 entitlement를 보장하지는 않는다.
일부 서비스 계정 작업은 Preview다. 원문 token은 목록에 없고, admin API key도 생성 이후 복구할 수 없다.

[공식 API Access OpenAPI](https://dac-static.atlassian.com/cloud/admin/api-access/swagger.v3.json)와 설명에서
조직 token 목록이 Bitbucket-scoped 사용자 token을 완전히 포함하는지는 이번 조사로 확정하지 못했다.
동일 Atlassian 계정이라고 coverage를 자동으로 합치면 안 된다.

### Bitbucket Cloud

[Access tokens](https://support.atlassian.com/bitbucket-cloud/docs/access-tokens/)에는 repository/project/workspace token이 있으며
project/workspace는 Premium 범위다. 원문은 생성 이후 다시 볼 수 없다.
[API tokens](https://support.atlassian.com/bitbucket-cloud/docs/using-api-tokens/)는 App passwords를 대신한다. App passwords는
2026-07-28에 완전히 중단됐고([변경 기록](https://developer.atlassian.com/cloud/bitbucket/changelog/)), Bitbucket API에 쓰는 API token은
범위(scope)를 지정해 만들어야 한다.
이 문서는 조직의 managed-user API token 생성 제한이 Bitbucket에는 적용되지 않는다고 명시한다.

[현행 공식 OpenAPI](https://dac-static.atlassian.com/cloud/bitbucket/swagger.v3.json)의 전체 170개 paths에서는
token/password 목록 경로를 확인하지 못했다. **공개 REST 기반 토큰 인벤토리 지원은 미확인**으로 남긴다.
공식 지원 확인 없이 내부 UI API를 수집 계약으로 삼거나 전체 토큰 목록 수집을 약속하면 안 된다.
SSH·deploy 공개키 및 리소스 목록은 별도로 수집할 수 있다.

[Pipelines API](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-pipelines/)와 OpenAPI는
secured 변수의 값이 REST API에 노출되지 않는다고 명시한다. 이름/metadata 수집은 가능하지만 값 대조는 불가하다.

### Data Center

[Bitbucket 10.4 Authentication REST](https://developer.atlassian.com/server/bitbucket/rest/v1004/api-group-authentication/)와
[10.4 OpenAPI](https://dac-static.atlassian.com/server/bitbucket/10.4.swagger.v3.json)에는
사용자·프로젝트·저장소별 HTTP access-token 목록 API가 있다.
목록의 `RestAccessToken`과 생성 때 원문을 반환하는 `RestRawAccessToken`이 구분된다.
[HTTP access token 안내](https://confluence.atlassian.com/bitbucketserver/http-access-tokens-939515499.html)의 DC license·관리 권한과 설치 버전을 확인해야 한다.

[Confluence PAT 안내](https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html)는
Confluence 7.9+ PAT와 Data Center 관리자의 전체 PAT 목록 UI를 설명한다.
2026-09-25 재조회에서 [현행 REST 진입점](https://developer.atlassian.com/server/confluence/rest/intro/)은
10.2.18로 연결되며 11.0.0도 안내한다. 공식 [10.2.18 OpenAPI](https://dac-static.atlassian.com/server/confluence/10.2.18.swagger.v3.json)와
[11.0.0 OpenAPI](https://dac-static.atlassian.com/server/confluence/11.0.0.swagger.v3.json)의 각 148개 paths에서
관리자 전체 PAT 목록 operation을 확인하지 못했다. PAT 안내의 생성 POST와 관리자 목록 UI만으로
전체 목록 GET의 버전·권한·페이지 처리 계약을 추정할 수 없다. 안정된 공식 전체 목록 REST 지원은 미확인이다.

**조사 시작 당시 코드:** Atlassian Cloud admin 수집은 상당 부분 구현되어 있다. Bitbucket Cloud는 공개키/리소스 중심이며,
Data Center metadata는 콘텐츠 스캔과 별개로 미지원이다. 공급자 폴더 통합은 가능하지만 Cloud/DC의 인증·기능 차이는 보존해야 한다.

## 9. Notion

[Admin API 소개](https://developers.notion.com/reference/admin/intro)는 **Enterprise plan 전용**이며 조직 owner가 발급한 organization bot token을 사용한다고 명시한다.
[PAT 목록 API](https://developers.notion.com/reference/admin/list-personal-access-tokens)는
`personal-access-token:read` scope로 workspace의 active/expired/revoked PAT와 ID·생성자·생성/만료/사용 시각을 반환한다.
[현재 Admin 버전](https://developers.notion.com/reference/admin/versioning)은 **2026-06-01**이다.

PAT 목록은 **토큰값을 반환하지 않는다**. `last_used_at` 갱신은 최대 시간당 한 번이므로 실시간 사용 여부가 아니다.
[PAT 가이드](https://developers.notion.com/guides/get-started/personal-access-tokens)는 관리자도 타인의 token 값을 볼 수 없으며,
생성자 역시 생성 시에만 복사할 수 있다고 명시한다. PAT 원문에서 목록 ID로 변환하는 공식 수동적 매핑 규칙은 이번 조사로 확인하지 못했다.

[MCP client connection 목록](https://developers.notion.com/reference/admin/list-mcp-client-connections)은 별도 scope로 제공되며
workspace-owned internal connection을 포함하지 않는다. PAT와 MCP 연결을 수집해도 모든 internal integration secret,
OAuth access/refresh token, organization bot token을 포괄했다고 말할 수 없다.

콘텐츠도 인증 방식에 따라 범위가 다르다. internal connection은 공유받은 페이지를 대상으로 하고,
PAT는 생성자가 접근할 수 있는 콘텐츠를 대상으로 한다. [Search](https://developers.notion.com/reference/post-search)는
연결에 공유된 pages/data sources를 발견하는 API이며 전체 workspace 본문에서 비밀 문자열을 검색해주는 API가 아니다.
[Enterprise export](https://developers.notion.com/reference/admin/enqueue-space-export)는 별도 `workspace:export` 권한과 사용자를 요구한다.

**조사 시작 당시 코드:** 콘텐츠 수집과 연결 신원 확인은 있다. PAT 화면/타입과 달리 공통 metadata registry에 Notion adapter가 없다.
따라서 **Enterprise PAT 인벤토리는 기술적으로 가능하지만 backend가 미구현인 상태**다.

## 10. Slack

확인일: 2026-09-28. [admin.apps.approved.list](https://docs.slack.dev/reference/methods/admin.apps.approved.list)는
Enterprise 조직 관리자·owner의 **user token**과 `admin.apps:read`로 조직(`enterprise_id`) 또는 워크스페이스(`team_id`)에서
승인된 앱을 cursor 페이지(limit 1–1000, Tier 2)로 준다. 항목은 앱 ID·이름·개발 주체·내부 앱 여부, scope별
`name`·`token_type`(bot/user)·민감 여부, `date_updated`, `last_resolved_by`(승인자 ID와 종류)다. Admin API가 꺼진 팀은
`feature_not_enabled`, 관리자가 아니면 `not_an_admin`, 조직에 설치하지 않은 관리 앱은
`app_management_app_not_installed_on_org`로 거절한다. Web API는 거절을 HTTP 200의 `ok: false`로도 준다.

- **승인은 설치가 아니다.** 공개 admin API에는 설치된 앱이나 발급된 토큰을 나열하는 메서드가 없다
  (승인·제한·요청 목록만 있다). 승인 목록의 앱이 실제 토큰을 가졌는지는 목록만으로 알 수 없다.
- [Audit Logs API](https://docs.slack.dev/admins/audit-logs-api/)는 Enterprise 전용이고 `auditlogs:read`를 요청하는 앱은
  **Owner가 조직 수준으로 설치**해야 한다. `/audit/v1/logs`는 `oldest`·`latest`·`limit`(최대 9,999)·`action`(최대 30개)·
  `actor`·`entity`로 거른다. [action 목록](https://docs.slack.dev/reference/audit-logs-api/methods-actions-reference)에는
  `app_installed`, `app_uninstalled`, `app_scopes_expanded`, `app_token_preserved`, `bot_token_upgraded`,
  `bot_token_downgraded`, `org_app_workspace_added/removed`가 있고, [schema](https://api.slack.com/audit/v1/schemas)의 app
  entity는 ID·이름·배포 여부·디렉터리 승인·workflow 앱 여부·`scopes`·`bot_scopes`를 준다. 이 기록으로 설치·제거 상태,
  설치일·설치자를 채울 수 있다.
- **토큰 사용 기록은 없다.** 앱·토큰 action 중 토큰이 쓰였음을 기록하는 항목은 확인하지 못했다. 마지막 사용은 비운다.
- 토큰 값·수신 웹훅 URL은 어떤 API로도 돌려주지 않는다. 노출된 `xoxb-`·웹훅을 값이나 digest로 목록 행과 연결할 수 없다.
- 사용자 토큰은 사용자마다 승인해 생기므로 앱 단위 목록은 개별 사용자 토큰의 전수 목록이 아니다.
- Enterprise Grid가 아닌 워크스페이스는 [team.integrationLogs](https://docs.slack.dev/reference/methods/team.integrationLogs)
  (`admin` user scope)가 앱·서비스(수신 웹훅 포함)의 추가·제거 이력과 채널을 준다. 이 경로는 구현하지 않았다.

**구현(2026-09-28):** [slack/README.md](../slack/README.md). 승인 앱을 봇 토큰·사용자 토큰·수신 웹훅 행으로 나누고,
선택적 감사 로그(최근 90일)로 설치 상태·설치일·설치자를 채우며, 감사 로그에만 있는 설치 앱도 행으로 남긴다.
실제 Slack 조직에서의 검증은 하지 않았다.

## 11. Vault / OpenBao

[Vault KV v2](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2)와
[OpenBao KV v2](https://openbao.org/docs/api/secret/kv/kv-v2/)는 목록·metadata·버전 값 읽기를 제공한다.
LIST는 값을 반환하지 않으며 읽기 권한이 별도로 필요하다. 허용된 값을 고객 환경에서 지문화하면 노출값과 비교할 수 있다.
현재 버전만 검사한 결과를 모든 과거 버전 검사로 표시해서는 안 된다.

[Vault namespaces](https://developer.hashicorp.com/vault/docs/enterprise/namespaces)는 Enterprise 기능이다.
[OpenBao namespaces](https://openbao.org/docs/concepts/namespaces/)도 공식 지원하므로 두 제품을 완전히 같은 요금제/버전 계약으로 취급하지 않는다.

[Vault token API](https://developer.hashicorp.com/vault/api-docs/auth/token)와
[OpenBao token API](https://openbao.org/docs/api/auth/token/)에는 service-token accessor 목록 및 metadata 조회가 있다.
목록에는 `sudo` capability가 필요하고, accessor 조회는 token 원문을 반환하지 않는다.
[Vault token 모델](https://developer.hashicorp.com/vault/docs/concepts/tokens) 및
[OpenBao token 모델](https://openbao.org/docs/concepts/tokens/)의 batch token은 별도 저장 추적이 없고 accessor도 없다.
따라서 service-token 목록을 모든 token 종류의 전수 목록으로 해석하면 안 된다.

[Vault lease API](https://developer.hashicorp.com/vault/api-docs/system/leases)는 lease ID·기간·갱신 metadata를 제공한다.
lease 목록은 동적 자격증명의 원문 보관 목록이 아니다. 동적 자격증명은 KV에 없어도 Vault가 정상적으로 발급·관리할 수 있다.

**조사 시작 당시 코드:** 명시한 namespace/mount/prefix의 KV1/KV2 현재 값을 고객 측 CLI에서 지문화해 전달한다.
전역 자동 발견·KV2 모든 과거 버전·service-token/동적 lease 인벤토리는 별도 추가 작업이다.

## 12. CreMore에 적용할 판단 기준

조사 시작 당시 공통 `metadata_correlation.py`는 비-AWS 발급 항목을 후보로만 연결한다.
모든 공급자가 식별자를 제공하지 않고 모든 발급 API가 비교 가능한 값을 반환하지 않는다는 주석은 지나치게 넓다.
GitHub enterprise hash, GCP 키 식별자/API key 값, Azure Storage 키값처럼 공식적인 예외가 있다.
반대로 단일 후보가 있다는 사실만으로 정확히 일치한다고 표시해서도 안 된다.

실제 구현 시에는 기존 공급자 모듈과 공통 저장/비교 경계를 유지하면서 다음을 반영해야 한다.

1. **지원 범위를 자격증명 종류 단위로 선언한다.** 예: Notion 전체 지원이 아니라 Enterprise PAT 목록 지원.
   지원 API 버전·요금제·인증 주체·승인 scope·이번 수집의 완전성을 함께 기록한다.
2. **증거 종류를 구분한다.** 발급 ID 연결, 실제 값 일치, 발급→금고 저장 기록, 후보/미확인은 다른 상태다.
   이름·끝자리·동일 소유자·비슷한 시간만으로 정확한 일치를 만들지 않는다.
3. **값을 다시 조회할 수 없는 공급자는 발급·저장 시 연결 기록이 유용하다.**
   공급자/tenant/credential ID와 금고 경로·버전·발급 시스템 근거를 함께 남길 수 있다.
   기존에 기록 없이 생성된 모든 토큰을 사후에 복원할 수 있다는 보장은 없다.
4. **금고 범위와 버전을 선언한다.** 권한 부족·실패·미지원·미수집은 부재가 아니다.
   `금고에서 찾지 못함`은 선언한 범위/시점에 관한 결과다.
5. **보관 정책을 자격증명 종류에 맞춘다.** 장기 정적 비밀, workload identity, 임시 토큰, Vault 동적 발급을 구분한다.
   모든 임시 토큰을 금고에 저장하도록 요구하는 정책은 적절하지 않다.

공식 근거가 명확한 추가 구현 후보는 Notion Enterprise PAT backend, Azure Entra metadata와 Key Vault 값 대조,
GCP 조직 발견 및 식별자 연결, GitHub 제공 hash의 별도 비교 계약, GitLab 관리자/그룹 범위와 CI 저장소 연동이다.
Bitbucket Cloud 전체 토큰 목록과 Confluence DC 전체 목록 REST는 공식 지원 범위 확인이 먼저다.

공통 정규화 스키마 전환은 [기존 설계](UNIFIED_METADATA_CONTRACT.md)의 별도 작업이다.
이 검토만으로 DB migration이나 공급자 인증/수집 범위가 변경되지는 않는다.

## 13. 이번 검토의 검증 범위

- 공식 사이트의 현행 문서/공식 OpenAPI 본문을 읽어 API·필드·권한·한계를 확인했다.
- 현재 registry, metadata projection/correlation, 공급자 descriptor와 관련 구현을 대조했다.
- 최초 가능성 검토 단계에서는 제품 코드·설정·DB를 변경하지 않고 이 문서만 추가했다. 이후 구현 단계와 검증은 별도 기록으로 관리한다.
- 고객 로그인, 실제 발급/발견 자격증명 사용, 운영 DB 접근, 실제 금고 값 읽기, 공급자 실환경 테스트는 수행하지 않았다.
- 문서상 지원과 고객 환경의 동작 보장은 구분한다. 계약/라이선스 또는 설치 버전이 다른 환경은 별도 확인이 필요하다.
