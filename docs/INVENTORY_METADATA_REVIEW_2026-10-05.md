# 인벤토리·감사 메타데이터 재검토 및 AWS 인증 비교

기준: 2026-10-05, `integration/saas-structure`, 기준 커밋 `564df841d97fa51f3435873b526414ac527363c4` 이후 작업 트리.
대상: 온보딩 catalog에 등록된 모든 공급자, 수집기·권한 점검·저장 projection·콘솔 표시.
코드 및 합성 응답 검증이며 고객 실계정 검증·운영 배포 완료 보고가 아니다.

## 1. AWS의 두 선택은 서버 종류가 아닌 권한을 사용하는 방식

| 구분 | 계정별 수집 역할 (`role`) | 서버 권한 직접 사용 (`runtime`) |
| --- | --- | --- |
| 흐름 | 서버의 기본 AWS 신원 → STS AssumeRole → 대상 계정의 수집 역할 | 서버에 제공된 AWS 역할 신원 자신의 권한으로 수집 |
| 대상 | 단일 계정, 독립 다중 계정, Organizations에서 발견 후 승인한 계정 | 그 신원이 속한 한 계정 |
| 수집 권한의 위치 | 각 대상 계정의 수집 역할 | 서버의 기본 역할 |
| 추가 설정 | 서버에 역할 전환 권한, 대상 역할에 신뢰 관계·읽기 정책. 기존 ExternalId·계정 승인을 유지 | 기본 역할에 읽기 정책. 별도 대상 수집 역할은 불필요 |
| 기능 차이 | 선택한 기능과 최종 역할 권한이 결정 | 선택한 기능과 기본 역할 권한이 결정 |
| 적합한 경우 | 조직·여러 계정, 계정별 권한 분리 | 작은 단일 계정 PoC, 이미 적절한 수집 역할을 쓰는 서버 |

두 방식 모두 IAM 목록·정책·CloudTrail·선택한 금고 대조를 수행할 수 있다. 방식을 고르는 것만으로
모든 기능의 권한이 부여되지는 않는다. Organizations 계정 목록을 읽는 권한도 계정 내부를 읽는 권한이 아니다.

| 실행 환경 | 두 방식 사용 조건 | 현재 코드의 근거·한계 |
| --- | --- | --- |
| EC2 | 인스턴스 프로파일의 IAM 역할 | SDK `iam-role` 자동 갱신 |
| EKS | IRSA 또는 EKS Pod Identity를 Pod에 제공 | `assume-role-with-web-identity` / `container-role`; 클러스터 역할 설치는 별도 |
| ECS | 태스크 역할 | `container-role` 자동 갱신 |
| 온프레미스 VM·물리 서버 | AWS가 신뢰하는 OIDC 발급자·역할·aud/sub 조건 및 자동 갱신 토큰 파일 | 회사 IdP 기계 신원 또는 외부 워크로드 토큰을 설정해야 함. AWS 밖이라는 이유로 불가능하지 않음 |
| 일반 Kubernetes | 신뢰 가능한 서비스 계정 OIDC 발급자/JWKS, projected token 갱신, IAM OIDC 역할 | Kubernetes만 설치했다고 AWS 신원이 생기지 않음. AWS가 issuer/JWKS를 확인할 수 있어야 함 |

현재 `aws_identity.server_workload_source`는 위 세 SDK 갱신 경로 및 그 경로로 끝나는 역할 체인을
확인한다. 사람 SSO, 고정 IAM 키, 임의 `credential_process`는 무인 갱신 경로로 인정하지 않는다.
2026-10-05 당시 IAM Roles Anywhere의 `credential_process`는 미지원이었다. 2026-10-06에
고정 브리지·인증서/hash 점검·SDK 갱신·배포 설정을 추가했다.
현재 지원과 실제 검증 범위는 [무인 운영 지침](UNATTENDED_DEPLOYMENT.md)을 따른다.

24시간 운영은 API·worker·스케줄러와 DB가 계속 실행되고, 토큰 발급·네트워크·시간 동기화·읽기 권한이
유지되는 조건이다. 기본 토큰/SDK 임시 권한을 자동 갱신하며 브라우저 로그인 상태와 무관하다.
회사 IdP의 임의 OAuth access token이 모두 AWS에서 허용되는 것은 아니다. AWS가 검증 가능한
OIDC JWT와 일치하는 issuer/audience/subject 신뢰 조건이 필요하다. 회사 IdP 앱의 클라이언트
시크릿을 사용하는 구성은 그 인증정보를 봉인 보관한다. 수집 대상 비밀 원문 보관과는 다른 계약이다.

코드: `aws/backend/cremore_aws_provider/aws_identity.py`, `aws_sessions.py`, `cremore/identity/machine.py`.

## 2. 확인된 결함과 변경

| 영역 | 원인 | 변경 및 의미 |
| --- | --- | --- |
| GCP 감사·사용량 | 관계 수집기는 있었지만 온보딩 선택이 없고 금고 기능에 묶임 | 발급 목록만으로도 `audit_logs`·`api_metrics` 선택 가능. 로그와 지표를 분리하고 필요한 권한을 점검 |
| GCP 생성자 | 서비스 계정 키·API key 생성 로그 연결 누락 | 성공한 생성 이벤트의 정확한 키 이름·프로젝트·actor를 확인해 `created_by` 저장. privateKeyData·keyString 및 원문 응답은 버림 |
| GCP 금고 | 리전별 수집기가 마법사에서 선택되지 않음 | 리전 선택을 기존 regional collector에 연결. 글로벌 시크릿도 포함. regional 로그·정책 관계는 리전을 식별자에 유지 |
| GCP IAM | 서비스 계정의 직접 프로젝트 역할 근거 누락 | `service_account_iam`에서 직접 allow-role 바인딩을 후보 관계로 저장. 상속·deny·조건을 평가한 유효 권한이 아님 |
| GCP 사전 점검 | 실제 수행하는 API key 목록·공개키 조회 권한 일부 누락 | `apikeys.keys.list`, `iam.serviceAccountKeys.get`, 선택별 Logging/Monitoring/IAM/location 권한 반영 |
| GCP 계정 ID | 키 리소스의 서비스 계정 부분을 이메일만 허용하여 숫자 uniqueId를 거절 | 이번 계정 목록의 명시적 uniqueId↔이메일과 검증한 프로젝트만 정규화. 재개 시 저장된 동일 실행 관측에서 복원. 알 수 없거나 충돌한 ID를 추정하지 않음 |
| Azure 사용 근거 | 앱 자격증명 목록만 수집하여 키별 로그인 근거 없음 | 선택적 Graph **beta** 서비스 주체 sign-in. 성공+app ID+credential key ID가 목록과 정확히 연결될 때만 사용 이벤트 |
| Azure 생성자 | directory audit의 credential 추가 actor 누락 | 선택적 v1.0 `directory_audits`. 성공한 이벤트의 앱/SP·정확한 추가 key ID·명시적 actor가 현재 목록과 연결될 때만 `created_by`. 모호하거나 지원하지 않는 변경 형식은 제외 |
| Azure 금고·앱 옵션 | 기존 키·인증서·버전·soft-delete·공개 인증서·federation 수집 기능이 마법사에서 누락 | 기존 수집기에 옵션 연결. Key Vault 추가 권한은 해당 endpoint에서 확인. 공개 인증서 대조는 공개 DER 동일성만 뜻함 |
| GitHub | 조직 감사 수집기가 있어도 조직 온보딩에서 켤 수 없음 | `audit_events`, 기간, 실제 조직 audit endpoint 권한 점검 추가. Enterprise 감사와 중복 요청 방지 |
| Atlassian | OAuth client 수집기가 있어도 온보딩 선택 없음. 조직 조회 성공만으로 목록 권한 추정 | OAuth 목록 옵션 추가, 실제 각 목록 endpoint 점검 |
| 공통 화면 | `{name, metadata:{state,value}}` 정규화 필드를 일반 JSON처럼 읽어 날짜·scopes 일부 누락 | 기존 정규화 필드의 값과 상태를 해석하여 API·콘솔에 전달 |
| 생성자/소유자 | 일부 화면에서 소유자를 생성자로 재사용 | 명시적 생성자·생성 관계만 표시. 근거가 없으면 소유자로 채우지 않음 |
| 마지막 사용 | 별도 관계/이벤트는 저장됐지만 공통 인벤토리에 미반영 | 완료·부분 완료 실행의 정확한 `used`/`token_activity`만 집계. 실행 중·실패·생성/소유/정책 관계 제외 |
| 지원표 | 미지원의 사유를 모두 공급자 API 탓으로 설명 | 현재 수집 경로의 지원 여부로 표현. GCP·Azure의 조건부 사용/생성 근거와 API 제한을 구분 |

메타데이터 수집 현황의 9개 항목·상세 값·권한 툴팁은 같은 descriptor/API projection을 사용한다.
감사 로그는 관측된 호출, Monitoring은 사용량이 있는 **구간**이다. 구간 끝을 정확한 호출 시각으로
표현하지 않으며, 빈 로그·기간 밖의 이벤트·권한 거절을 미사용이나 삭제로 판단하지 않는다.

## 3. 전체 공급자별 실제 범위와 남은 제한

아래는 검토 결과다. “기존”은 코드 경로가 있다는 뜻이며 이번에 실계정에서 실행했다는 뜻이 아니다.

| 공급자 | 인벤토리·감사 경로 | 금고 또는 비밀 저장소 | 남은 제한 |
| --- | --- | --- | --- |
| AWS | 기존 IAM 사용자 키, 정책 메타데이터·선택적 잠재 권한, credential report, CloudTrail 생성/사용 근거, Organizations/Control Tower 발견 | Secrets Manager 현재·선택적 과거 버전, SSM Parameter Store | 전체 활성 STS 세션 목록 불가. Event History는 기간·리전·이벤트 종류 제한. S3 trail은 별도 범위·권한 필요. KMS 키는 비밀값 보관 목록과 다름 |
| GCP | 서비스 계정·사용자/Google 관리 키·API keys, 조직/폴더 발견. Audit Logs 생성/사용·Monitoring, 직접 프로젝트 IAM 후보 | 글로벌·선택한 regional Secret Manager, 버전·선택적 메모리 지문화 | Data Access 로그 설정·키 이름의 실제 포함 여부에 의존. 정책은 후보 근거이며 범용 서비스 계정 유효 IAM 권한 평가는 미구현. KMS 키 관리 목록은 별도 미구현 영역 |
| Microsoft/Azure | Entra 앱/SP secret·인증서, ARM 구독/스토리지, DevOps PAT. federation/공개 인증서, 키별 sign-in과 directory audit 생성자 | Key Vault secrets·keys·certificates, 선택적 버전/삭제/공개 DER 및 secret 값 지문화 | 키별 sign-in 식별자는 Graph beta. directory audit는 지원하는 KeyDescription의 명시적 키 추가만 연결. Azure Monitor/Key Vault 접근 로그와 Managed HSM 별도 인벤토리는 미구현. SAS 전수 목록/앱 secret 원문 재조회는 제공되지 않음 |
| GitHub | 조직 FGPAT·SSO 승인 자격증명·deploy key, Enterprise credential inventory, 감사 이벤트·선택적 digest. 이번에 조직 감사 옵션 연결 | Actions secrets는 메타데이터만 | Enterprise·GHES 버전·App 권한·감사 토큰·보존 기간 조건. Actions 원문 불가. 소유/SSO 승인 actor를 생성자로 사용하지 않음 |
| GitLab | instance/group/project 및 Enterprise user token, SSH/deploy key, 선택 감사 이벤트. 기존 옵션과 child 연결 확인 | 승인한 CI 변수 값 메모리 지문화 | 제품/요금제·admin/Owner 범위. Audit가 모든 토큰 호출을 전수 기록한다고 보장하지 않음 |
| Atlassian Cloud | 조직 API keys, 관리 계정·서비스 계정 API tokens, 이번에 OAuth client 선택 연결 | 별도 범용 금고 기능 없음 | 조직 entitlement·실제 endpoint 제공 여부에 의존. 일부 OAuth 필드는 실험 관측에 기반한 기존 수집 계약. 모든 조직에서 제공 보장 없음 |
| Confluence | 콘텐츠 검사; Cloud 발급 목록은 Atlassian 관리 범위 | 없음 | DC 전체 PAT 목록용 안정적 공개 REST 계약은 확인되지 않음. 일반 감사 로그가 token ID를 명시하지 않으면 키별 사용으로 연결할 수 없음 |
| Bitbucket | Cloud 공개 SSH/deploy key·리소스, DC HTTP access-token inventory | CI 보안 변수 원문 API 제한 | Cloud access token 전수 목록 지원은 미확인. DC 버전/라이선스 조건. 미확인을 불가능으로 단정하지 않음 |
| Notion | Enterprise Admin PAT·MCP 연결 목록; 일반·Enterprise 내부 integration은 콘텐츠 검사 | 없음 | 일반 요금제 계정 인증 후 콘텐츠 추가 가능. 조직 봇과 페이지 읽기 토큰은 별개. 모든 integration/token 목록은 아님. 별도 Enterprise 감사 webhook 수신은 사용자 결정으로 범위 제외 |
| Slack | Enterprise Grid 승인 앱의 token type/scope·웹훅 종류와 선택적 설치 감사 근거 | 없음 | 승인≠설치. 실제 토큰 값/웹훅 URL/키별 마지막 사용을 주는 API가 아님 |
| Vault/OpenBao | KV1/KV2, 선택적 service-token accessor·lease metadata | KV 현재·선택적 버전의 메모리 지문화 | accessor/lease는 동적 관리 근거이며 KV 값 일치가 아님. batch token 전수 열거/모든 secrets engine 발급 이력은 지원 아님 |
| Okta·Keycloak | 사람 목록/퇴사자 점검, 선택적 IdP 앱 이름·상태 발견 | 공급자 연결용 인증정보 봉인 | 추가 API token/client secret 인벤토리·범용 감사 로그 수집은 사용자 결정으로 범위 제외. Keycloak의 기존 사용자 비활성화·삭제 이벤트는 퇴사자 점검 근거로 유지 |
| Google Workspace | 디렉터리 사람/역할 그룹·IdP 연결 근거 | 없음 | GCP IAM 키 인벤토리와 다른 계약. OAuth grant·범용 감사 로그 수집은 사용자 결정으로 범위 제외 |
| Website | 확인한 회사 도메인 콘텐츠 노출 검사 | 없음 | 발급자/금고 인벤토리 공급자가 아님 |

요청한 검토에서 발견한 구체적인 연결 누락은 위와 같이 수정했다. 그러나 이 변경을 “모든 공급자의
모든 감사 로그·모든 비밀 관리 제품을 완전히 수집”하는 구현으로 해석하면 안 된다. 남은 기술적 제한에는
별도 로그 저장소/수집 계약이나 정확한 키별 귀속 규칙이 필요하다. 임의 감사 actor를 생성자로 넣거나,
서비스 계정의 활동을 그 계정의 모든 키 사용으로 확장하는 방식으로 빈 칸을 채우지 않는다.

2026-10-05 사용자 결정: Notion의 추가 감사 로그와 Okta·Keycloak·Workspace의 추가 토큰/감사 수집은
핵심 흐름에서 제외했다. 해당 확장은 계획뿐이었고 제거할 런타임 구현은 없었다. 기존 Notion Enterprise
PAT·MCP 인벤토리와 IdP의 로그인·담당자·퇴사자 점검 기능은 유지한다. 상세 범위는
[제품 선택·수집 목적 분리](EDITION_AND_COLLECTION_ONBOARDING.md)에 기록하며 제외 항목을 미완료 작업으로 세지 않는다.

## 4. 기존 연결 적용과 운영

1. 기존 공급자 연결의 기능/설정 편집에서 필요한 새 옵션을 선택한다. 새 옵션은 기본 해제다.
2. GCP는 Audit Logs/Monitoring 및 해당 프로젝트 권한·로그 활성화를 확인한다. regional Secret Manager는 위치를 선택한다.
3. Azure sign-in은 Graph beta 사용·로그 이용 조건·`AuditLog.Read.All` 관리자 동의를 확인한다. directory audit도 같은 권한의 실제 endpoint를 별도로 점검한다.
4. GitHub/Atlassian도 권한 확인을 다시 수행한다. 추가 권한 거절·미확인은 성공으로 처리하지 않는다.
5. 저장 후 인벤토리를 다시 수집한다. 기존 데이터의 미수집 칸이 과거 기록만으로 자동 채워지지는 않는다.

DB schema 이관은 없다. 새 필드는 선택적 projection이고 기존 연결·관측·감사 이력을 유지한다.
새 조회가 부담되면 연결 편집에서 해당 옵션을 해제하고 기존 수집으로 복귀한다. 이미 기록한
과거 사용 근거는 삭제하지 않으며, “현재 사용 가능”으로 해석하지 않는다.
수집한 비밀값·원문 응답·로그 본문은 저장하지 않는다. 공급자에 로그인하는 봉인 인증정보는 별도 계약이다.

## 5. 공식 자료와 판정 근거

이번 구현에서는 아래 GCP/Graph 공식 정의를 확인했다. 그 밖의 공급자는 기존
[기술 가능성 근거](PROVIDER_CREDENTIAL_FEASIBILITY.md)와 실제 등록·호출 경로를 대조했다.
공식 기능 가능성과 현재 코드 구현·실환경 검증은 각각 구분한다.

- [AWS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html), [AssumeRoleWithWebIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)
- [EKS IRSA](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html), [EKS Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html)
- [GCP AuditLog authenticationInfo](https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog): `serviceAccountKeyName`을 명시한 호출만 키별 사용 근거
- [IAM 감사 이벤트](https://cloud.google.com/iam/docs/audit-logging): `google.iam.admin.v1.CreateServiceAccountKey`
- [서비스 계정 키 목록](https://cloud.google.com/iam/docs/keys-list-get): IAM 키 리소스 이름과 계정별 목록 계약
- [GCP metrics](https://cloud.google.com/monitoring/api/metrics_gcp_p_z): `serviceruntime.googleapis.com/api/request_count`는 DELTA 구간이며 지연 가능
- [Graph signIn v1.0](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0) / [beta](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta): 키별 ID `servicePrincipalCredentialKeyId`는 beta에 존재
- [Graph sign-in 목록](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta): 애플리케이션 권한과 필터·로그 이용 조건
- [Graph directoryAudit](https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0): initiatedBy·targetResources의 명시적 변경 근거만 사용. KeyDescription 형식 전체를 고정 계약으로 가정하지 않음
- [Notion Admin API](https://developers.notion.com/reference/admin/intro): 활성 Enterprise 요금제에만 제공하며 조직 봇 토큰 사용. 2026-10-05 공식 소개 재확인. 별도 감사 webhook 수신은 이번 제품 범위에서 제외
- [Azure Managed HSM](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview): 임의 비밀값 저장소가 아닌 암호화 키 관리 서비스
- [Key Vault Audit Logs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azkvauditlogs): 별도 진단 로그 목적지·접근 권한 필요

## 6. 검증

아래 표는 초기 인벤토리 변경 스냅샷의 실행 기록이다. 이후 edition/계정 분리와 GCP/Azure 보강의
최신 검증은 [제품 선택·수집 목적 분리](EDITION_AND_COLLECTION_ONBOARDING.md#검증-2026-10-05)에 기록한다.

| 검증 | 결과 |
| --- | --- |
| 온보딩 전체, GCP metadata, Azure Entra/Key Vault, GitHub metadata, Atlassian, 공통 API/store, worker 통합·공급자 경계 | **1,536 passed, 78 skipped, 272 subtests passed** (`output/inventory-review-python-tests.log`) |
| 이후 GCP 숫자 계정 ID 회귀·공급자 재검사 | **219 passed, 19 subtests passed** (`output/inventory-review-gcp-final.log`) |
| 웹 전체 단위 검사 | **274 passed** (`output/inventory-review-web-tests.log`) |
| 문구 변경 후 console 단위 재검사 | **36 passed** |
| TypeScript / Next.js production build | 통과 |
| 브라우저 `console-auth-first`, `console-metadata-popover` | **2/2 통과** |
| 변경 Python Ruff / `git diff --check` | 통과 |

78 skip은 Windows에서 POSIX `O_NOFOLLOW`/uid 검사가 필요한 Atlassian 검사 57개와
`CREMORE_TEST_POSTGRES_URL`이 없는 PostgreSQL 검사 21개다. SQLite·메모리 저장소는 실행했다.
GCP 숫자 계정 회귀는 수정 전 2개 실패(`INVALID_KEY_IDENTIFIER`, `UNMATCHED_SERVICE_ACCOUNT_KEY_NAME`),
수정 후 동일 저장소/API 통합 경로에서 통과했다. 테스트 내부 최소 합성 입력만 사용했다.
실계정 수집·장시간 연속 갱신·Linux/PostgreSQL·운영 배포는 이번 실행 대상에 포함하지 않았다.
