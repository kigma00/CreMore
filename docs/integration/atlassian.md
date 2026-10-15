# Atlassian 브랜치 통합 사실 조사

고정 소스의 사실 조사다. 제품 전체의 최종 결합 결정은 [통합 설계](../INTEGRATION_DESIGN_REVISED.md), 판독 범위는 [파일별 대장](source-inventory.csv)을 따른다.

2026-09-23 갱신: 아래의 서비스 계정 404, OAuth count 400·본문 없음, OAuth 배열 응답 기록은 조사 당시 사실이다. 현재 계약과 동작은 [Preview API 계약 반영 기록](atlassian-preview-contract.md)을 따른다.

## 1. 고정 기준과 검토 범위

- 팀원 Atlassian: **11c44f2afdf0874f736eb30018992bd9855fd2d9** (publish/develop_atlassian).
- 비교 develop: **71ea52ad933708b7fb851f590ab7162d7f7ed35f**.
- Atlassian 트리 82개 파일, 744,111 bytes, 17,396 lines. Python 29개, Markdown 26개, JSON 26개, .gitignore 1개.
- Python 전체(제품 모듈, 스크립트, 실험, 테스트), Markdown 전체, .gitignore, 테스트 fixture JSON은 모든 줄을 읽었다. 총 57개 파일이다.
- 증거 JSON 25개는 전체를 재귀 파싱하여 키, 형식, 건수, 출처 필드를 확인했다. 민감한 샘플 값의 불필요한 열람을 피하기 위해 개인정보를 포함할 수 있는 원본 샘플 값의 모든 leaf를 개별 판독하지 않았다. 따라서 이들 25개를 전체 내용 정독으로 표기하지 않는다.
- 파일별 git blob, bytes, lines, 판독 범위: [source-inventory.csv](source-inventory.csv). 증거 JSON 구조: [검증 기록](verification.md).
- 현재 브랜치 전환, 병합, push, 제품 코드 수정, 실제 공급자 API 호출, 고객 인증정보 사용은 수행하지 않았다. 과거 실환경 증거와 이번 오프라인 재검증을 구분한다.

**핵심 판정:** 팀원 브랜치는 Atlassian Cloud 및 Bitbucket Cloud의 자격증명 관련 **발급처 메타데이터, 공개키, 인증 관계 수집 CLI**다. develop의 Confluence 문서, Bitbucket 저장소 콘텐츠 노출 수집기를 대신하는 구현이 아니다. 이 두 기능을 같이 보존해야 한다. 팀원 메타데이터 계약을 develop의 기존 AWS 중심 Coverage Observation에 그대로 넣으면 식별자 검증 실패, 주체/스코프/계약 불확실성 손실, 공개키의 잘못된 노출 계수 문제가 발생한다.

## 2. 실행 경로와 정확한 호출 API

| 모듈 / 진입점 | 실제 역할과 보존할 동작 | 근거 |
|---|---|---|
| atlassian_collector.__main__ → cli.main(argv=None, *, directory=None) | --sources / --discovery / --accounts 상호 배타. accounts는 명시적 profile 필수. 연결 파일 읽기 → CloudClient → 수집 → 비공개 파일 저장 → 값 없는 stdout 요약 | A01, A02 |
| collector.collect(client, sources=None, *, now=utc_now) | 선택 source 정규화, 중복 관찰 묶기, OAuth 연결 후보를 schema_version=3 결과로 생성. 기본 3개 source, OAuth 2개 opt-in | A03, A04 |
| collector.collect_source(client, source, now=utc_now) | 페이지/레코드/오류 상태를 source별로 보존. 실패 전까지 얻은 관찰 유지. 배열/페이지 계약 차이를 명시 | A03 |
| discovery.collect_discovery(client, *, max_targets=50, now=utc_now) | Cloud 17종 연산의 페이지별 메타데이터 snapshot 및 field catalog. 목록에서 관찰한 service account/OAuth 및 user.id, createdBy.id, serviceAccount.id로 후속 조회. managed-account 목록의 account_id에 한정하는 것은 별도 collect_accounts | A05, A06 |
| discovery.collect_accounts(client, *, max_targets=50, now=utc_now) | 관리 계정 목록에서 확인한 ID만 관리 권한, 프로필, token 조회. 일반 discovery와 별도 인증 운용 가능 | A05 |
| discovery.collect_operation(client, operation, *, identifier=None, body=None, now=utc_now, specs=READ_OPERATIONS) | 고정 연산 실행, 응답 형태 검증, URL/cursor 페이지 처리, snapshot, omission, 상태, 건수 기록 | A05 |
| bitbucket.collect_bitbucket(client, max_targets=50, now=utc_now, *, runners_only=False) | workspace에 한정한 core 22종 또는 runners 4종. runner 모드는 저장소 발견 연산도 사용. 전체 26종을 항상 한 실행에서 부르는 구조가 아님 | A07 |
| BearerReadClient(key, limits=None, *, opener=None, clock=..., wall_clock=..., sleep=..., jitter=...) | 고정 원점 transport, redirect 금지, 응답 1MiB 한도, 전역 요청, 시간 예산, bounded retry | A08 |
| CloudClient(org_id, key, limits=None, *, token_page_size=20, **kwargs) | fetch(source, query), read_metadata(operation, *, identifier=None, body=None, cursor=None, next_url=None). 두 POST는 count 전용이며 생성, 수정 호출이 아님 | A08, A06 |
| BitbucketClient(workspace, token, limits=None, *, page_size=20, **kwargs) | read_metadata(operation, *, identifier=None, body=None, cursor=None, next_url=None). body/cursor 입력은 거부. 경로에 {key_id}가 있는 경우 identifier는 관찰한 parent/key 두 값 tuple/list, {target}만 있는 detail은 단일 문자열. 고정 Bitbucket 경로이며 OIDC 2종은 최초 요청부터 public/no auth. 응답의 issuer/jwks/token endpoint 링크를 따라가지 않음 | A07 |
| normalize(source, record, observed_at, *, allow_service_oauth_variant=False) | 필드 존재, null, 타입 불일치, 시간 형식, 주체 출처를 보존하는 source별 계약 변환 | A09 |
| group_inventory(observations), oauth_link_candidates(inventory) | 단일 조회 조직 안의 (record_contract, provider_id)로 그룹화. 충돌 필드와 모든 관찰 유지. 다른 OAuth 계약의 같은 ID는 확정 병합 대신 후보 | A09 |
| metadata_snapshot(value, *, sensitive_values=(), max_nodes=100000, max_depth=32, reason_codes=()) | 알려진 secret 필드명/현재 인증값/PEM, Basic, Bearer 형태 등을 제거. 알려지지 않은 메타데이터 필드는 보존. 임의 자유문자열 전체에 대한 secret-free 증명은 아님 | A10 |
| save_private(directory, result) | 0700 디렉터리, 0600 임시 파일, 소유자/심볼릭 링크 검사, hardlink 기반 원자적 공개. POSIX 파일 API 의존 | A11 |

Limits의 기본값은 max_pages=50, max_records=5000, max_requests=100, max_seconds=120, timeout=15, retries=2, max_retry_wait=30이다. 요청 예산은 source와 재시도 사이에서 공유된다. retry는 429 / 500 / 502 / 503 / 504 및 transport 실패에 한정되고 Retry-After/reset 정보를 반영한다. 오류 응답 본문이나 예외 원문을 일반 결과에 넣지 않는다. 이 동작은 develop transport로 옮길 때 회귀 기준이다. [A08]

CLI 종료 코드는 완료 0, 불완전 수집 1, 구성/저장/예상하지 못한 오류 2, interrupt 130이다. stdout에는 ID, 이름, email, scope 값, cursor, 응답 본문을 내보내지 않으며, 상세 결과 파일은 별도 비공개 저장 대상이다. [A02, A03]

## 3. 구현되어 있는 수집 범위

### 3.1 Atlassian Cloud 17종

아래 다섯 list source는 normalized inventory에도 사용한다. 정규화 기본 선택은 1–3, 4–5는 명시적으로 선택해야 한다. discovery는 별도 report 계약이다. API Access 기준 prefix는 /admin/api-access/v1/orgs/{org_id}/ 이다. [A04, A06]

| # | operation | HTTP / 상대 경로 또는 별도 절대 경로 | 결과 의미 |
|---|---|---|---|
| 1 | admin-api-keys | GET api-keys | 관리자 API key 메타데이터, cursor |
| 2 | org-api-tokens | GET api-tokens | 조직 API token 메타데이터, cursor |
| 3 | service-account-api-tokens | GET service-accounts/api-tokens | 서비스 계정 token 배열; #2와 같은 token 계약의 ID 중복은 관찰로 통합 |
| 4 | service-account-oauth-clients | GET service-accounts/oauth-clients | 서비스 계정 OAuth client 배열 |
| 5 | org-oauth-clients | GET oauth-clients | 문서형 cursor 계약과 관찰된 배열 variant 구분. 배열은 unverified 유지 |
| 6 | admin-api-key-count | GET api-keys/count | 정수 count |
| 7 | org-api-token-count | GET api-tokens/count | 정수 count |
| 8 | org-oauth-client-count | POST oauth-clients/count | 읽기 count. body 없음. 보관된 실환경 결과는 400 |
| 9 | service-accounts | GET service-accounts | items 목록과 URL 페이지. 보관된 실환경 결과는 404 |
| 10 | service-account-token-counts | POST service-accounts/count | 관찰한 service account ID 배열만 count 요청. 배치 1–100 |
| 11 | service-account-api-tokens-by-account | GET service-accounts/{identifier}/api-tokens | 관찰한 계정별 token 배열 |
| 12 | service-account-oauth-clients-by-account | GET service-accounts/{identifier}/oauth-clients | 관찰한 계정별 OAuth 배열 |
| 13 | oauth-client-detail | GET oauth-clients/{identifier} | 관찰한 client 상세 |
| 14 | managed-accounts | GET /admin/v1/orgs/{org_id}/users | 관리 계정 목록, URL 페이지 |
| 15 | user-management-permissions | GET /users/{identifier}/manage | 해당 관리 계정에 대한 관리 가능성 메타데이터 |
| 16 | user-profile | GET /users/{identifier}/manage/profile | 해당 관리 계정 프로필 |
| 17 | user-api-tokens | GET /users/{identifier}/manage/api-tokens | 해당 관리 계정 token 목록 |

후속 대상은 수집 결과에 실제 나타난 식별자만 사용한다. service-accounts 목록이 실패해도 token/OAuth에서 관찰한 serviceAccount ID의 후속 조회는 중단하지 않는다. 각 종류의 max_targets와 전체 요청/시간 예산에 걸리면 생략 이유가 남는다. 관리 계정 전용 모드는 첫 managed-accounts 목록에서 받은 ID만 사용한다. [A05]

이 메타데이터는 label/status/created/expires/lastActive/scopes, user/serviceAccount/createdBy의 서로 다른 역할, provider ID, 출처 계약을 다룬다. **원문 API token, 관리자 secret, OAuth client secret을 발급 API에서 복원하는 기능은 없다.** 토큰 목록 또는 OAuth client 목록은 그 주체에 발급된 모든 사용 가능 access token을 보장하지 않는다. [A04, A09, A12]

### 3.2 Bitbucket Cloud 26종

기준 원점은 https://api.bitbucket.org/2.0 이다. 아래 22종 core와 4종 runners를 구분한다. ID, repository, project, user 후속 조회는 선택 workspace에서 관찰한 대상에 한정한다. [A07]

| 분류 | operations | 보존해야 하는 의미 |
|---|---|---|
| 현재 사용자 / workspace / 대상 발견 (5) | current-user, workspace, workspace-members, projects, repositories | 조회 주체, workspace, 후속 조회 대상 발견 |
| workspace 공개 인증 정보 (3) | workspace-gpg-key, workspace-oidc-configuration, workspace-oidc-keys | 공개 서명키와 OIDC trust metadata. OIDC 두 연산은 공개 조회 |
| 사용자 (5) | user-profile, user-ssh-keys, user-ssh-key-detail, user-gpg-keys, user-gpg-key-detail | SSH/GPG 공개키, label, owner, fingerprint 등. GPG direct subkey 상세까지, 무한 재귀 없음 |
| project (3) | project-detail, project-deploy-keys, project-deploy-key-detail | project 공개 deploy key 메타데이터 |
| repository / pipelines (6) | repository-detail, repository-deploy-keys, repository-deploy-key-detail, pipeline-ssh-key, pipeline-known-hosts, pipeline-known-host-detail | repository deploy key, pipeline SSH 공개 부분, known-host trust |
| Runner 별도 모드 (4) | workspace-runners, workspace-runner-detail, repository-runners, repository-runner-detail | Runner 상태/label/인증 관계의 client ID, audience, token endpoint 등; client secret 제거 |

공개키 복원 예외는 알려진 컨텍스트에만 제한된다. generic key는 기본적으로 제거하고, SSH wire format 및 허용된 GPG/public 필드만 복원한다. known-host의 algorithm과 wire 내부 algorithm도 확인한다. JWK의 private/symmetric parameter는 제거한다. Runner 응답에 OAuth client 관계가 나타나도 이를 일반 OAuth consumer 전체 목록으로 해석하지 않는다. Runner OFFLINE/UNREGISTERED를 자격증명 폐기로 변환하지 않는다. [A07, A10, A13]

**없는 범위:** Bitbucket resource access token 전체 목록, workspace SSH 전체 목록, 일반 OAuth consumer 전체 목록, Data Center PAT 인벤토리, Bitbucket 파일 내용/commit history/이슈/변수 원문, Confluence 페이지/첨부 내용, Jira 이슈 내용. 이 중 Bitbucket, Confluence 콘텐츠 수집은 develop이 별도로 담당한다. [A07:273–287, A12:63–79, B01]

## 4. 팀원 구현에서 특히 유지해야 하는 의미 계약

1. **필드 상태 보존.** missing / null / present / invalid_type은 다르다. null lastActiveAt은 미사용 증거가 아니며 null expiresAt도 무기한 증거가 아니다. ISO 문자열과 epoch-ms 원값, UTC 변환값을 구분한다. [A09:15–113]
2. **주체 역할 보존.** user/serviceAccount와 createdBy를 합치지 않는다. 전용 service-account 관찰과 ID 일치가 있어야 principal_kind를 올릴 수 있다. API token 일반 목록만으로 서비스 계정이라고 가정하지 않는다. [A09:42–154]
3. **문서형과 관찰형 계약 보존.** org OAuth 배열이 service-account 계약 형태인지는 명시적 필드 표지로 판단한다. 시간 형식만으로 계약을 추정하지 않는다. 혼합된 표지는 경고다. documented org OAuth에는 관찰하지 않은 owner/scope/expiry를 생성하지 않는다. [A04, A09]
4. **식별 충돌 보존.** 한 조직 안에서 같은 record_contract/provider ID만 그룹화한다. 모든 원본 관찰, source, conflict_fields를 유지한다. scope 순서는 비교할 때만 정렬하고 원 관찰 순서는 남긴다. 다른 계약의 같은 OAuth ID는 확정 결합하지 않는다. [A09:116–163]
5. **부분 성공 보존.** 한 source 실패가 앞선 관찰을 버리지 않는다. 누락 next, 반복 cursor, 중복 ID, 응답 형태 불일치, 예산 한도, 실패/대상 없음 각각을 상태, 이유로 남긴다. [A03, A05]
6. **완료 의미 제한.** normalized schema3의 run_status=complete는 선택 API의 완료 조건이다. inventory_complete는 항상 false다. 조직의 모든 자격증명, 대규모 배열 상한, 원자적 시점의 전체 상태를 증명하지 않는다. [A03:105–143, A14:97]
7. **snapshot과 inventory 구분.** discovery schema1의 페이지 snapshot은 공급자별 shape을 보존한다. saved_records는 list 요소 수이고 scalar/detail 응답은 0일 수 있다. 0이 데이터 없음이라는 뜻이 아니며, snapshot 하나를 credential 하나로 변환하면 안 된다. [A05]
8. **상태와 검증 분리.** ACTIVE/ALLOWED/disabled=false 같은 공급자 필드는 실제 인증 성공 증거가 아니다. 공개 SSH/GPG/JWKS/known-host 정보 역시 secret 노출 증거가 아니다. [A09, A13]

## 5. develop와의 비교 및 통합 시 필요한 경계

| 현재 develop 소유 계층 | 팀원에 추가된 기능 / 충돌 | 통합 설계에 필요한 처리 | 근거 |
|---|---|---|---|
| EnterpriseCollector 콘텐츠 수집 | develop은 Confluence Cloud/DC 페이지, 첨부, Bitbucket Cloud/DC 고정 revision 파일을 CollectedObject(resource, data)로 전달. 팀원은 메타데이터 수집 | 기존 콘텐츠 수집을 보존하고 메타데이터 수집 목적을 별도 등록. JSON을 콘텐츠 탐지기로 밀어 넣어 노출 결과를 만들어서는 안 됨 | B01, B02, A03, A05, A07 |
| SourceConfig / Connection scopes | develop의 bitbucket/confluence scope는 콘텐츠 대상이며 atlassian admin metadata scope는 없음 | 조직 관리자 metadata, managed-account metadata, Bitbucket core, Runner의 대상, 권한을 표현할 연결 schema 필요. 같은 브랜드라도 인증을 자동 공유하지 않음 | B03, B04, A02, A15 |
| secretstore / admin 연결 API | develop은 sealed token 또는 secret_ref를 받아 worker에 주입. 팀원 CLI는 .local 비공개 JSON의 평문 인증값 | 팀원 프로토콜을 develop secret resolution에 연결. 서버 안에서 CLI subprocess와 로컬 profile 파일을 우회 통로로 추가하지 않음. 기존 프로필 무대체 정책은 보존 | B05, B06, A15 |
| Coverage ConnectionSpec | aws_iam/cloudtrail/secretsmanager/ssm, vault/openbao/gcpSM만 허용 | 새 발급처 metadata 연결 유형 또는 목적 확장 필요. 기존 Vault 연결을 Atlassian metadata 저장소로 오용하지 않음 | B07:64–82 |
| Coverage Observation | 엄격한 AWS 중심 필드; identifier regex가 ':'/'{'/'}'를 허용하지 않음. owner 역할, scopes, report type, record contract, 관찰 충돌 필드가 없음 | provider/entity kind/scope identity와 typed provider metadata를 지원하는 발급처 관찰 계약 필요. 임의 metadata dict만 붙여 strict secret-free 경계를 없애는 방식은 부적합 | B07:150–195, A09 |
| Coverage Finish / in_scope | COMPLETE/PARTIAL/FAILED만 허용; 조직/Bitbucket workspace 범위 검증 없음 | teammate unverified를 잃지 않도록 별도 completeness/reasons 저장. transport 종료 상태를 PARTIAL로 매핑하더라도 원 상태 보존. 서버가 provider/조직/workspace 범위를 검증 | B07:223–268 |
| Credential / Exposure / Finding | Credential은 탐지 secret fingerprint+type 식별. Exposure는 내용 위치. Finding은 credential에 연결 | provider metadata ID를 secret HMAC으로 가장하지 않음. 발급처 entity의 identity는 provider/environment/org 또는 workspace/object kind/provider ID 조합. 실제 결정적 연결 증거가 없으면 detected secret과 미연결 유지 | B08, B09, A09 |
| Coverage 저장 / run protocol | revision, batch index, idempotency, 완료/만료, 마지막 관찰 이력 보유 | teammate 관찰을 이 프로토콜에 맞춰 append하고 실패/인증 만료가 이전 관찰을 지우지 않게 설계. 부분 결과를 완전한 부재 증거로 사용하지 않음 | B10, A03, A05 |
| Worker / collect API | 서버 수집 job은 현재 IAM, CloudTrail. 시작, 승인, lease checkpoint, abort 경로 존재 | 메타데이터 job routing, lease 취소 지점, 페이지/재시도 중 checkpoint 연결. 단발 collect 함수를 호출하는 것만으로 장시간 실행 취소가 구현되는 것은 아님 | B11, B12 |
| Dashboard | provider registry에 Confluence/Bitbucket 콘텐츠 카드 있음. Coverage UI는 AWS/Vault 중심 | 콘텐츠 노출, 발급처 metadata, Vault 관리 증거의 의미를 분리하여 한 제품 흐름으로 표시. detail에는 source/owner role/필드 충돌/최근 성공/불완전 이유. 공개키, known-host를 노출 건수 KPI로 합산하지 않음 | B13, B14, B15 |
| 패키징 / 테스트 | develop wheel은 cremore만 포함. pytest testpaths도 cremore만. teammate는 top-level atlassian_collector/scripts/tests | 단순 Git merge로 런타임 설치와 CI 실행까지 완료되지 않음. 패키지 위치/상대 import를 명시적으로 통합하거나 패키징 범위를 추가하고 설치 산출물 테스트 필요 | B16, A01, A07:18 |
| 파일 저장 / 배포 | teammate storage는 os.getuid, O_DIRECTORY, O_NOFOLLOW, dir_fd, chmod 권한에 의존 | native Windows에서 직접 실행하는 CLI는 별도 대응 필요. Windows 호스트의 Linux Docker는 이번 테스트로 동작 확인. 서버 DB 저장 경로는 기존 worker/DB를 활용 | A11, A15 |

기존 develop에는 Atlassian/Bitbucket **탐지 패턴**과 Bitbucket token의 HTTP verifier가 있다. 이는 팀원 관리자 inventory API와 다른 기능이다. 기존 탐지 지원을 이유로 metadata inventory가 이미 구현되어 있다고 판단해서는 안 된다. [B17, B18]

Vault와의 관계에서도 이 수집 결과만으로 NO_VAULT_MATCH를 만들 수 없다. 공급자 ID, 공개키 fingerprint, 이름/email은 secret 값의 HMAC과 다른 증거다. 메타데이터가 없거나 source가 부분 실패했다는 이유로 미관리 자격증명이라고 단정할 수 없다. 이 구분은 사용자 목표인 '조직이 가진 Vault의 관리 증거와 실제 노출의 교집합/차집합'을 보존하기 위한 데이터 의미 조건이다. [A09, B07, B08]

## 6. 확인된 공백과 실제 Git 충돌

### 실제 동작 공백

- **Runner 다중 페이지:** validate_next_url은 HTTPS origin뿐 아니라 path도 정확히 같아야 한다. 공급자가 돌려주는 같은 workspace의 /internal/... Runner next는 현재 CLI에서 차단된다. test_bitbucket_runners.py:65–76도 이를 partial, 한 요청으로 기대한다. 별도 과거 진단에서 2페이지 성공했다는 문서는 **현재 CLI 수정 완료 증거가 아니다**. slug/UUID의 같은 resource binding을 확인하는 좁은 provider 처리 및 repository Runner 다중 페이지 검증이 필요하다. 모든 URL을 허용하거나 opaque next를 임의로 재작성하는 통합은 현재 경계의 손실이다. [A06:63–74, A16, A17]
- **Cloud 공급자 계약:** service-accounts 404, org OAuth count 400, org OAuth 배열 응답의 완전성은 해결된 코드로 표시할 수 없다. 마지막 문서도 그대로 미확정으로 남긴다. 공급자 응답 실패를 빈 목록으로 바꾸면 안 된다. [A12, A17]
- **운영 runtime:** 독립 HTTP server/router, DB, scheduler, lease/cancellation, Dashboard, Vault adapter, 노출 scan, 능동 유효성 검사, 교차 소스 secret 결합은 이 branch에 없다. [전체 트리, A12:93]
- **제품/edition:** 구현 수집은 Atlassian Cloud 및 Bitbucket Cloud다. Data Center metadata collector가 없으며 develop의 콘텐츠 DC 지원이 이를 채우지 않는다. [A12:63–79, B01]
- **개인/민감 metadata 저장:** snapshot은 알 수 없는 필드도 보존하는 조사 도구다. 알려진 secret 제거만으로 임의 provider free text를 일반 API, audit, dashboard에 노출할 수 있다고 보증하지 않는다. allowlisted typed fields와 제한된 원본 증거 저장 경계가 필요하다. [A10, A11]

### 실제 textual merge 충돌

고정 ref 기준 git merge-tree 조사 결과 Atlassian은 다음 두 파일이 충돌한다. 전체 충돌 결과는 [검증 기록](verification.md)에 있다.

| 파일 | 실제 충돌 | 보존 대상 |
|---|---|---|
| .gitignore | add/add | 팀원 .local/private 결과 보호와 develop의 기존 비밀, 빌드, runtime ignore 모두 |
| README.md | content | develop 제품 진입 설명 및 팀원 metadata 수집 기능/지원 한계를 함께 반영. 한쪽 파일 전체 선택으로 해결하지 않음 |

제품 코드에 textual conflict가 적다는 사실은 구조 충돌이 작다는 뜻이 아니다. 위 Coverage 계약, identity, secret storage, worker, 설치/테스트 discovery는 추가 파일로 들어와도 동작 충돌 또는 기능 누락을 일으킨다.

## 7. 검증 결과와 보존할 테스트

이번 재검증: **148 tests, 0 failures, 0 errors, OK; unittest elapsed 0.148s.** 기존 로컬 cremore-python 이미지 ID 2540e311713b, --pull never, --network none, --read-only, /tmp tmpfs, pinned source read-only bind mount로 실행했다. 고객 설정, 인증 파일은 마운트하지 않았다.

    docker run --rm --pull never --network none --read-only --tmpfs /tmp -e PYTHONDONTWRITEBYTECODE=1 --mount 'type=bind,source=C:\Users\admin\Desktop\cremore\work\integration-review\atlassian-snapshot,target=/review,readonly' --workdir /review --entrypoint python 2540e311713b -B -m unittest discover -s tests -q

| 테스트 파일 | 개수 | 주요 검증 의미 |
|---|---:|---|
| tests/test_bitbucket.py | 22 | workspace bounded discovery, public/private SSH/GPG/JWK 구분, OIDC 고정 public 경로, snapshot, targets, summary |
| tests/test_bitbucket_runners.py | 9 | core/runners 분리, 관찰한 runner followup, secret redaction, 예산, 현재 내부 next 차단 동작 |
| tests/test_collector.py | 17 | 기본 정규화, 누락/null/타입/시간, source 상태, grouping 및 요약 |
| tests/test_collector_cli.py | 7 | CLI 결과/exit, 비공개 저장 및 stdout 비노출, 실패 경로 |
| tests/test_collector_http.py | 11 | 고정 origin/path, 제한된 retry/Retry-After, 요청/시간/응답 크기 예산, 비밀 미반향 |
| tests/test_collector_oauth.py | 24 | OAuth 두 계약/관찰형 배열, owner 역할, 시간/boolean/null, 후보와 중복, 문서 밖 형태의 unverified |
| tests/test_connection_profiles.py | 8 | profile 경로 제한, 기존 파일 보존, 다른 조직 fallback 금지, 심볼릭 링크/비대화형 입력 거부 |
| tests/test_cursor_contract.py | 14 | cursor loop, 한도 terminal 조건, 순서 변경, 중복 ID 관찰, 미완료/실패 및 contract drift |
| tests/test_discovery.py | 20 | 고정 연산, 형태별 snapshot, 후속 ID, count 비교, size 모순/변화, redaction/한도 |
| tests/test_managed_accounts.py | 8 | 관리 계정 목록 출처 제한, 빈/실패/partial 구분, 명시 profile, 네 GET 범위, management reason 코드 |
| tests/test_probe_cloud.py | 8 | 초기 probe 값 비저장, 빈/denied/not-found 구분, 계약 불일치, private config, bounded GET |
| **합계** | **148** | 테스트 내용 전체 판독 및 오프라인 실행 확인 |

테스트는 공급자 실제 환경 또는 develop 통합 완료를 증명하지 않는다. 특히 Runner 테스트의 통과는 현재 제한을 그대로 검증한 결과이므로 Runner 다중 페이지 완료 근거로 사용할 수 없다.

통합 후 추가로 필요한 acceptance 증거:

1. 17 Cloud / 26 Bitbucket 연산 registry와 각 mode, 인증 분리가 보존되고 허용된 원점/대상 밖 요청이 차단됨.
2. 같은 token의 API별 중복 관찰은 연결하고 다른 조직/종류의 같은 ID는 분리됨. owner, creator, scope, 계약 충돌, 후보 상태가 DB 재시작 후 보존됨.
3. missing/null/invalid/provider raw status를 실제 검증, 위험점수, 금고 관리 여부로 임의 승격하지 않음.
4. 실패, 만료, 예산 중단, unverified가 UI에 드러나고 이전 성공 관찰이 삭제되거나 새 성공으로 오인되지 않음.
5. stale lease/취소/replay/중복 batch가 잘못된 run을 확정하지 못하고 연결 폐기 후 이전 감사 이력은 유지됨.
6. Run snapshot의 예상 밖 자유문자열, 현재 인증값, private key parameter가 일반 API/로그로 나오지 않음. 허용 public key와 임의 generic key를 구분함.
7. 실제 설치 wheel과 CI가 새 모듈 및 기존 148개 테스트를 포함함. 기존 develop 콘텐츠 탐지/Confluence, Bitbucket Cloud/DC 경로와 UI 기능이 회귀하지 않음.
8. 새로운 Runner next 대응을 넣는 경우 같은 resource binding만 허용하고 foreign host/workspace/repository는 계속 거부함. archived 진단과 actual integrated runtime 결과를 분리함.

## 8. 복사, 적용 후보의 위치

아래는 구현 담당자가 구현 단계의 소유권을 결정할 때 사용할 후보이며, 이 검토에서 실제 이동하지 않았다.

| 팀원 원본 | 가져올 핵심 | develop 쪽 접점 / 필요한 수정 |
|---|---|---|
| atlassian_collector/specs.py, read_operations.py | source/operation 계약 및 field allowlist | 새로운 metadata provider 패키지. 기존 content scope와 목적 분리 |
| atlassian_collector/metadata.py | type-preserving normalization, grouping, OAuth candidate 의미 | typed issuer observations + provider-scoped identity. 단일 org 그룹 함수를 글로벌 ID로 쓰지 않음 |
| atlassian_collector/collector.py, discovery.py | 부분 결과, source별 상태, 관찰 기반 bounded followup | worker의 실행/lease/run 저장 경로에 adapter, typed metadata upload 계약 필요 |
| atlassian_collector/bitbucket.py | 26 operation, core/runners 분리, public key handling | 기존 EnterpriseCollector.bitbucket은 보존. CLI 및 scripts import를 runtime core에서 분리 |
| atlassian_collector/http.py | bounded retry, fixed route, response limit의 의미 | 기존 RequestBudget/취소/관측 체계와 조화. URL scope 검증 유지 |
| atlassian_collector/snapshot.py | bounded recursive snapshot 및 알려진 secret 제거 | 일반 API schema 대신 제한된 상세 증거 경계. 안전한 typed field만 UI 전달 |
| scripts/*, atlassian_collector/cli.py, storage.py | 독립 실행/조사 재현 가능성 | 제품 연결은 secretstore/resolver 및 admin 연결 API. POSIX CLI를 제품의 유일 실행 경로로 삼지 않음 |
| tests/*, tests/fixtures/*, experiments/cursor_collection.py | 전체 148 회귀 테스트, cursor 계약 실험 | 패키지 import 변경에 맞춰 테스트 위치를 정하고 기존 pytest discovery에 포함 |
| docs/* 및 evidence JSON | API별 지원/미지원 근거와 계약 출처 | 운영 artifact, 고객 데이터와 구분한 개발 증거. 과거 카운트/진단 성공을 현재 runtime 기능으로 승격하지 않음 |

## 9. 근거 레지스터

각 ID의 commit:path:line은 고정 revision 기준이다. 행 구간이 표시된 경우 해당 시작 행과 이어지는 함수/블록을 의미한다. 아래의 모든 Atlassian source 파일은 전체 판독했다.

| ID | 고정 소스 근거 |
|---|---|
| A01 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:atlassian_collector/__init__.py:3–6; 11c44f2afdf0874f736eb30018992bd9855fd2d9:atlassian_collector/__main__.py:1–3 |
| A02 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:atlassian_collector/cli.py:16–64 |
| A03 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:atlassian_collector/collector.py:10–156 |
| A04 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:atlassian_collector/specs.py:3–52 |
| A05 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:atlassian_collector/discovery.py:11–317 |
| A06 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:atlassian_collector/read_operations.py:10–74 |
| A07 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:atlassian_collector/bitbucket.py:20–353 |
| A08 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:atlassian_collector/http.py:25–230 |
| A09 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:atlassian_collector/metadata.py:15–163 |
| A10 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:atlassian_collector/snapshot.py:14–111 |
| A11 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:atlassian_collector/storage.py:9–33 |
| A12 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:docs/collection-support-matrix-2026-09-20.md:3–93 |
| A13 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:docs/bitbucket-runners-2026-09-20.md:3–25 |
| A14 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:docs/collector-usage.md:62–97 |
| A15 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:scripts/connection_profile.py:6–16; 11c44f2afdf0874f736eb30018992bd9855fd2d9:scripts/probe_cloud.py:74–90; 11c44f2afdf0874f736eb30018992bd9855fd2d9:scripts/bitbucket_connection.py:14–62; 11c44f2afdf0874f736eb30018992bd9855fd2d9:scripts/configure_local.py:19–52 |
| A16 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:tests/test_bitbucket_runners.py:65–76 |
| A17 | 11c44f2afdf0874f736eb30018992bd9855fd2d9:docs/internet-research-2026-09-20.md:9–33,73–79 |
| B01 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:cremore/collectors/enterprise.py:30–141,184–249,299–389 |
| B02 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:cremore/collectors/base.py:17–33,86–97; 71ea52ad933708b7fb851f590ab7162d7f7ed35f:cremore/worker/factory.py:24–53 |
| B03 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:cremore/source_config.py:6–8,27–33,62–94 |
| B04 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:cremore/domain/connections.py:23–28,35–70,86–123 |
| B05 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:cremore/secretstore/resolver.py:49–104 |
| B06 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:cremore/api/app.py:141–155,431–497 |
| B07 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:cremore/coverage/models.py:64–82,150–195,223–268 |
| B08 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:cremore/domain/models.py:63–146 |
| B09 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:cremore/db/schema.py:69–98 |
| B10 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:cremore/coverage/store.py:36–59,176–200,222–296 |
| B11 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:cremore/coverage/job.py:29–84 |
| B12 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:cremore/api/coverage.py:70–105,189–216 |
| B13 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:web/app/provider-registry.ts:56–67 |
| B14 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:web/app/credential-coverage.tsx:12–14,87–103,139–157 |
| B15 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:web/app/connection-ui.tsx:60–86 |
| B16 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:pyproject.toml:14,37–44,55–56 |
| B17 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:cremore/detection/catalog.py:603–607,1050–1054 |
| B18 | 71ea52ad933708b7fb851f590ab7162d7f7ed35f:cremore/detection/verify/http.py:365–368 |

## 10. 신뢰도와 남은 확인 범위

- **높음:** 고정 branch의 구현 범위, 함수 흐름, 결과 계약, 상태, 설치/테스트 연결 공백, native POSIX 의존은 전체 코드 판독으로 확인했다. 148개 오프라인 테스트 결과도 이번 검토에서 직접 확인했다.
- **높음:** 기존 develop과의 콘텐츠/metadata 역할 차이 및 Coverage schema incompatibility는 위 파일/행에서 직접 비교했다.
- **제한:** 팀원의 과거 API 진단은 저장된 출처, 상태, 구조를 검토한 것이다. 후속 조사에서 공개 공식 문서와 OpenAPI를 직접 읽었지만 고객 API를 호출하지 않았다. Cloud, Bitbucket 원격 상태는 live verification 완료로 보고하지 않는다.
- **제한:** 증거 JSON 25개는 구조, provenance 검토이며 모든 샘플 원문 값의 정독이 아니다. observed-field-catalog는 43개 연산, API별 1,105개 필드 경로의 목록으로 확인했으며 contains_values=false, is_common_normalized_schema=false, is_exhaustive_provider_schema=false이다. 필드 수가 자격증명 수 또는 완전한 공급자 schema라는 의미는 아니다.
- **제한:** develop은 Atlassian 접점만 비교했다. enterprise.py, collectors/base.py, worker/factory.py, source_config.py, domain/connections.py, secretstore/resolver.py, coverage/models.py, coverage/job.py, coverage/store.py, api/coverage.py, 위 web 3개 파일 및 pyproject.toml은 전체 판독했다. domain/models.py, db/schema.py, api/app.py, detection/catalog.py, detection/verify/http.py는 관련 구간만 판독했다. 로컬 비교 snapshot에 복사된 coverage/collect.py는 이 하위 조사에서 판독하지 않았으며 주 조사에서 판독한 develop 접점이다.
- **의도적 미실행:** 실제 credential validation, 고객 데이터 scan, provider write, OAuth/token 발급, Runner 등록, 기존 .local/profile 열람, 브랜치 이동 또는 병합. 테스트는 모의 입력과 network-none 환경에 한정했다.

최종 설계 담당자에게 필요한 결정은 메타데이터 저장 계약/identity/런타임 소유권/대시보드 노출 방식이다. 이 사실 조사에서 팀원 구현을 이유 없이 develop 계약으로 축소하거나 팀원 CLI를 제품 전체로 대체하는 결정을 미리 내리지 않았다.

## 11. 공식 문서 대조 보완

2026-09-21 공식 문서 및 OpenAPI를 직접 읽고 **Cloud17 + Bitbucket26의 모든 route/method 대응**을 확인했다. [공식 근거 AT1–AT4](official-docs.md#atlassian과-bitbucket)에 문서 URL과 명세 SHA를 남겼다. 기존 148개 테스트를 다시 실행하거나 고객 API를 호출한 결과는 아니다.

- **인증 보완:** 개인 Bitbucket API token은 email+Basic이 공식 방식이다. 팀원 `BearerReadClient`는 인증이 필요한 요청에서 Bearer만 지원하므로 기존 develop의 `auth_type` 의미를 metadata 연결에 재사용한다. OIDC 설정, JWKS 두 연산의 무인증 처리는 유지한다. OAuth 등의 Bearer와 구분하고 콘텐츠 URL 조립은 별개로 유지한다.
- **Runner 보완:** 공식 next 계약과 autoscaler 공개 소스에서 internal 페이지 이동을 확인했다. 기존 exact-path 제한을 모든 internal 허용으로 바꾸지 말고 동일 workspace/repository를 확인한 Runner 다음 페이지에 한정해 보완한다.
- **미해결 사항:** 관리자 key scope 공통 표와 endpoint/OpenAPI가 상충한다. Endpoint의 `read:keys:admin`을 기준으로 안내하되 실제 권한 확인을 남긴다. Service-account404, OAuth count400, 배열 완전성도 해결 완료로 바꾸지 않는다.
- **Data Center 후보:** Bitbucket DC10.0에 개인, 프로젝트, 저장소 token의 목록/상세 GET6개가 공식적으로 있다. 양쪽 코드 모두 metadata adapter는 없으며 후속 구현이다. 명세의 id/name/createdDate 외 필드는 반드시 제공된다고 약속하지 않는다. Confluence/Jira DC 관리자 REST 전수 계약은 버전별 확인이 남았다.
- **저장 조건:** count/detail, field catalog, 원본 상태, owner/creator, 상충 관찰을 보존한다. 공식 경로가 있다는 이유로 선택 API 성공을 전사 전체 수집으로 표시하지 않는다.
