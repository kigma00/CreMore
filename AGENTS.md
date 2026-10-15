# CreMore 팀 공통 AI 작업 지침

이 문서는 저장소 전체의 공통 진입 지침이다. 새 AI 세션에서 작업 전에
[팀 코딩 지침](docs/AI_TEAM_CODING_GUIDE.md)을 읽고, 변경 영역의 실제 코드와 대조한다.
팀에 배포할 때는 두 문서를 같은 저장소 버전으로 제공한다. 문서 첨부만으로 코드 확인을 대신하지 않는다.
하위 디렉터리의 `AGENTS.md`는 해당 영역의 추가 지침이다. 특히 `web/` UI 작업에는
[web/AGENTS.md](web/AGENTS.md)와 설치된 `web/node_modules/next/dist/docs/`의 관련 문서를 적용한다.
사용자에게 이미 받은 작업 범위·승인과 상위 실행 지침을 우선하며, 같은 승인을 반복해서 요청하지 않는다.

## 작업 시작

1. `git status --short --branch`로 현재 branch와 미커밋 변경을 확인한다. 다른 사람의 변경을 덮어쓰거나 되돌리지 않는다.
2. 목표, 담당 공급자/기능, 수정 허용·제외 경로, 유지할 계약, 완료 검증을 작업 범위로 정한다.
   사용자 요청과 기존 작업 카드에서 확인되는 내용은 그대로 사용한다.
3. `rg`로 관련 구현·호출자·모델·테스트를 찾아 입력부터 API/UI/저장까지 동작과 불변 조건을 추적한다.
4. 기존 소유자·helper·주입 지점을 먼저 재사용한다. 실제 필요 없는 공통 계층·패키지·프레임워크를 추가하지 않는다.
5. 병렬 작업은 공급자별 branch/worktree와 파일 소유권을 나눈다. 공통 파일을 여러 담당자가 동시에 수정하지 않는다.

## 담당 경계

| 작업 | 담당자가 구현하는 위치 | 공통 통합 지점 |
| --- | --- | --- |
| 공급자 연결(온보딩) | `<vendor>/backend/cremore_<vendor>_provider/onboarding.py`의 descriptor·자격증명 정규화·권한 점검·레코드 함수와 테스트 | `cremore/onboarding/catalog.py`의 `MODULES`, 공급자 연결 모델·API·`provider-check` 작업 |
| 콘텐츠 수집 | `<vendor>/backend/cremore_<vendor>_provider/`의 source·content/collectors·catalog와 테스트 | `cremore/sources/registry.py`, 승인·인증·작업/저장 계약 |
| 공급자 연결 화면 | 연결 마법사·목록은 onboarding descriptor로 콘솔이 그린다. 공급자에 꼭 필요한 화면·문구만 `web/console/views/integrations/`의 모듈(`guide.tsx` 설정 안내, `copy.ts` 문구, `aws-settings.tsx`·`github-app.tsx` 등)과 `web/tests/console-*.test.cjs` | `web/console/views/integrations/model.ts`(catalog 규칙·`FAMILIES`), 공개 응답/source 인식(`web/lib/source-types.ts`), `web/public/logos/`·`web/console/logo-set.ts` |
| schema 2 메타데이터 수집 | `<vendor>/backend/cremore_<vendor>_provider/metadata/`의 adapter·descriptor·정규화·테스트; Azure Entra는 `entra/`, ARM은 `arm/` | `cremore/coverage/providers/__init__.py`, 공통 spec·record·runtime 계약 |
| AWS schema 1 인벤토리 | `aws/backend/cremore_aws_provider/`의 IAM·CloudTrail·조직/Control Tower·STS 구성요소 결합, 콘솔의 AWS 설정·대상 화면(`web/console/views/integrations/aws-settings.tsx`·`aws-identity.tsx`·`reach.tsx`) | `cremore/coverage/`의 모델·저장·스케줄·상관분석, API·worker 연결 |
| schema 1 금고 수집 | `vault/backend/cremore_vault_provider/`의 KV·관리 메타데이터, `aws/backend/cremore_aws_provider/`의 Secrets Manager·SSM, `gcp/backend/cremore_gcp_provider/coverage.py`의 Secret Manager | 기존 `ConnectionSpec`·`Observation`, 공통 해시·저장·상관분석 계약 |
| SIEM 연동 | 별도 출력 패키지와 자체 테스트; 공개 `cremore.siem`의 `SinkProvider`·`Sink`·`DeliveryError` 사용 | 설치형 entry point와 목적지 설정; 이벤트·발신 대기열 변경은 플랫폼 담당 |
| 티켓 시스템(소유자 승인·노출 대응 요청) | 별도 어댑터 패키지와 자체 테스트; 공개 `cremore.ticketing.contract`의 `TicketSystemProvider`·`TicketError` 사용(내장 시스템은 없다. 기본 경로는 연락 발송의 Slack·메일 링크) | `cremore.ticket_systems` entry point와 `TICKET_SYSTEM_PLUGINS` 허용; 요청·응답 기록·분리 검사는 플랫폼의 `owner_approval`·`governance/response`([소유자 승인·대응 요청](docs/TICKET_SYSTEMS.md)) |
| 공급자 자격증명 조치 | `<vendor>/backend/cremore_<vendor>_provider/remediation.py`의 참조·지원 조치·연결 범위·상태 읽기·쓰기와 테스트, onboarding의 `remediation` 용도 | `cremore/remediation/provider_actions.py`의 `MODULES`, 계획·승인·worker 실행 계약([공급자 자격증명 조치](docs/PROVIDER_ACTIONS.md)) |
| 플랫폼 | 공통 승인·인증·scope·API·DB·리스·이벤트 계약과 테스트 | 공급자 담당자의 변경을 통합하고 기존 소비자 호환성 검증 |

콘텐츠 수집, 메타데이터 수집, SIEM 출력은 별도 계약이다. 콘텐츠/metadata는 명시적으로 등록하며
외부 수집 플러그인 자동 탐색은 없다. 콘텐츠 소스·AWS 계정·수집 연결은 공급자 연결의 4단계로만 만들고
자격증명은 공급자 연결이 소유한다([공급자 연결](docs/ONBOARDING.md)). 레코드를 직접 만드는 등록 경로를 다시 두지 않는다. SIEM만 설치한 `cremore.siem_sinks` 출력 패키지를
명시적으로 활성화해 사용한다. 이 기능은 비신뢰 코드를 격리하는 sandbox가 아니다.

## 실제 공급자 디렉터리

최상위 소유자는 `aws/`, `gcp/`, `github/`, `gitlab/`, `notion/`, `atlassian/`, `azure/`, `vault/`, `okta/`, `keycloak/`, `slack/`, `website/`이다.
`okta/`·`keycloak/`은 퇴사자 점검의 IdP 사용자 수집과, 연동 제안에 쓰는 IdP 앱 목록 수집(이름·상태만)만 소유한다. Google Workspace 디렉터리는 `gcp/`의 `workspace/`가 소유한다.
`slack/`은 Enterprise Grid 앱 발급 목록만 소유하고 전용 UI가 없다.
`website/`는 확인된 회사 도메인(`cremore/domains.py`)의 외부 노출 검사만 소유하고 전용 UI가 없다. 요청 경계(확인된 도메인·
주소 규칙·연결 고정)는 이 폴더의 `fetch.py`·`addresses.py`에 있고, 다른 곳에서 사이트를 읽는 경로를 따로 만들지 않는다.
Confluence·Bitbucket은 공유 구현을 가진 `atlassian/` 안에서 나눈다. OpenBao는 `vault/`의 KV 계약을 쓴다.
Atlassian 묶음(`confluence`·`bitbucket`·`atlassian`)은 콘솔 `web/console/views/integrations/model.ts`의 `FAMILIES`가 연결 화면에서 함께 보여 주는 표시 묶음이다.
기존 `confluence`·`bitbucket`의 source_type·job·scope·API 식별자를 `atlassian`으로 바꾸지 않는다.
Python 구현과 공급자 전용 테스트는 `backend/cremore_<vendor>_provider/`에 둔다. 공급자 폴더에는 UI가 없다. 연결 화면은 onboarding descriptor로
콘솔(`web/console/`)이 그리고, 공급자 고유 화면이 꼭 필요하면 콘솔의 `views/integrations/`에 둔다(2026-10-01 이전 대시보드와 `<vendor>/web/` 삭제).
GCP의 플랫폼 독립 `gcp/standalone/cremore_gcp/`는 같은 wheel에 포함한다. 식별자·값 검증·매칭은
이 패키지의 함수를 제품에서도 재사용하며 공통 함수를 복제하지 않는다. GCP·GitLab의 독립 CLI는 2026-09-27 삭제했다.
공통 API·권한·DB·작업 수명·scope·SIEM은 `cremore/`, 공통 웹 화면·타입·UI는 루트 `web/` 소유다.
공급자마다 서버·Docker·의존성 설치를 만들지 않는다. 한 제품에서 라이브러리 함수를 직접 호출한다.
공급자의 원자적 설정 갱신은 `cremore.db.settings_store.locked_settings`를 사용한다. DB 테이블·SQL·
행 잠금·private 저장소 메서드를 공급자에 복제하지 않으며 기존 동시성 보호를 유지한다.

새 공급자를 넣을 때는 실제 필요한 구현만 만들고, 기존 등록(`cremore/onboarding/catalog.py`의 `MODULES` 포함)과 함께 `pyproject.toml`의 wheel/pytest 경로,
Python Docker COPY를 반영한다. 웹 빌드 설정은 바꾸지 않는다(연결 화면은 descriptor로, 고유 화면은 콘솔 모듈로 붙는다).
등록·빌드 파일은 통합 담당자가 소유해 병렬 개발의 충돌을 줄인다.
세부 소유 경계·호환 원칙은 [공급자 디렉터리 보고서](docs/PROVIDER_DIRECTORY_REVIEW.md)를 따른다.

## 공급자 추가와 공통 변경

- 콘텐츠 모듈의 설정 검증·job/scope 변환·수집기 조립·목록 조회와 연결 폼을 정하는 descriptor의 field·permission은
  공급자 담당자가 소유한다. 기존 `cremore/sources/<provider>.py` 등은 호환 경로이므로 새 구현을 넣지 않는다. 상세 계약과 절차는 팀 지침 7절을 따른다.
- 공통 등록은 프로그램이 새 모듈을 인식하도록 연결하는 작업이다. backend 등록(`MODULES` 등)과 콘솔에 필요한 표시(로고·안내 문구) 변경도
  작업 범위에 배정하고 통합 담당자가 합친다. 등록 목록을 소비자마다 복제하거나 호환 facade에 공급자별 분기를 추가하지 않는다.
- 기존 인증·범위·저장 계약을 재사용할 수 있는지 먼저 확인한다. 새 인증 방식, scope 의미,
  공개 응답/source 인식, job kind 또는 DB 구조가 필요하면 관련 공통 소비자까지 추적한다.
  콘솔의 콘텐츠 source 목록(규칙의 적용 범위, 수집 로그의 실행 중지 대상)은 `web/lib/source-types.ts` 한 곳에서 읽고
  backend registry와 parity 검사(`cremore/sources/module_contract_test.py`)로 묶인다. credential 검사(연결 비밀 해석)는 registry 등록만으로 확장되지 않는다.
- 새 job kind는 `CONTENT_SCAN_KINDS`뿐 아니라 기존 DB의 active-scan partial unique index와
  migration을 검토한다. Python 상수 수정만으로 설치된 index는 갱신되지 않는다. 동시 enqueue 동작도 검증한다.
- 필요한 공통 변경은 대상 파일·이유·호환 영향·검증 방법을 정리해 플랫폼 담당자와 통합한다.
  이미 배정된 변경은 진행한다. 범위 밖의 공통 계약 변경이 필요하면 그 변경을 조정하고,
  의존하지 않는 담당 모듈 작업은 계속한다. 기존 승인·검증을 우회해 기능을 붙이지 않는다.
- 기존 출력 계약 안의 새 SIEM은 별도 패키지와 목적지 설정으로 추가한다. 이벤트 필드/버전이나
  재시도·발신 대기열 계약을 바꾸는 작업은 별도로 다룬다. [SIEM 지침](docs/SIEM_INTEGRATION.md)을 따른다.

모든 공급자가 폴더 추가만으로 완성되는 구조라고 가정하지 않는다. 실제 지원 기능과 남은 통합 작업을 명시한다.
전체 수집 메타데이터의 [공통 정규화 설계](docs/UNIFIED_METADATA_CONTRACT.md)는 목표 계약이다.
현재 schema 1·schema 2·콘텐츠 catalog의 통합 전환은 미구현이며, 기존 API·권한·저장 계약을 유지한다.

### 발급 인벤토리·노출·금고의 근거

발급 공급자와 콘텐츠 발견 위치는 별개다. GitLab에서 발견한 GCP 키를 GitLab 발급 자격증명으로
분류하거나 콘텐츠 URL에서 발급 조직·tenant를 추정하지 않는다. `metadata_correlation.py`의 노출 연결과
`issuer_coverage.py`의 발급 목록→금고 비교는 외부 인증 없는 근거 연결이며, 미노출 자격증명에 가짜 finding을 만들지 않는다.
명시적 식별자, 호환되는 값 지문, 공급자 제공 digest, 연결 후보를 구별한다. 식별자 일치·provider 상태·
마지막 사용·TTL은 값 일치나 현재 유효성·권한 검증을 대신하지 않는다. 비공개 digest는 공개 응답·export에 노출하지 않는다.

`storage_receipts.py`의 발급·저장 이력은 관리자 제출 근거다. 실제 수집된 발급/금고 관측의
run·batch·item 위치에 고정하며 수집기 토큰으로 등록하지 못한다. UUID 재제출은 멱등이고 철회해도
이력을 보존한다. 범위 변경·중지·철회는 적용 불가로 표시하며 값 일치·현재 보관·활성 상태로 승격하지 않는다.
공통 API/UI가 이력을 소비하고 공급자 모듈에 별도 receipt SQL/테이블을 만들지 않는다.
Entra↔Key Vault의 `PUBLIC_CERTIFICATE_MATCH`는 실제 공개 DER의 SHA-256 동일성만 뜻한다.
공급자 `public_certificates.certificate_evidence`를 재사용하고 임의 thumbprint를 대체 근거로 쓰지 않는다.
공개 인증서 연결은 개인키 보관이나 인증 권한을 입증하지 않으며 비밀값 일치율에 포함하지 않는다.
`PUBLIC_CERTIFICATE_NOT_OBSERVED`는 확인된 범위에서 선택한 Key Vault 인증서 조회가 모두 최신·완료이고
같은 공개 DER이 없다는 뜻이며, 개인키가 다른 곳에 없다는 증거가 아니다.
후속 공개 인증서 조회가 실패하면 이미 저장된 근거를 과거 관측으로 유지한다. 조회 SQL은
`MetadataStore.latest_finished_observation`을 재사용하고 공급자나 비교 함수에 복제하지 않는다.

퇴사자 점검([docs/LEAVER_CHECK.md](docs/LEAVER_CHECK.md))의 IdP 수집기(`okta`·`entra_id`·`keycloak`·`google_workspace`·`github_identity`)는 공통
`cremore/identity/idp.py` 위의 공급자 조회 함수이고 매칭에 쓰는 이메일·로그인은 keyed digest로만 저장한다. 사람 정보 보관
(`options.keep_profiles`, 마법사의 `people_details`)을 켠 연결은 표시·연락용 이름·이메일·부서·직함을 사실로 함께 남기며
`GET /api/v1/people`(analyst)이 이를 모은다. 매칭은 이 값을 쓰지 않는다. 사람이 회사 IdP로 로그인하는 팀 설치(`AUTH_MODE=oidc`)의
사람 목록 연결은 그 로그인 IdP 자신이어야 한다(`cremore/onboarding/sign_in.py`, IdP 온보딩 모듈의 `sign_in_target`, GitHub 신원 연결 예외).
Google 로그인은 토큰에 그룹이 없어 worker가 Workspace 역할 그룹 구성원을 digest로 읽고 API가 그것으로 역할을 정한다
(`cremore/identity/sign_in_groups.py`, API는 자격증명을 열지 않는다). 공급자는 발급 목록 행의 소유
계정을 `credential_owner(row)`로 알려 준다(registry의 `owners`, schema 1은 `V1_OWNERS`). 소유자 함수는 정확한 근거
(`SAML_NAME_ID`·`SCIM_EXTERNAL_ID`·`EXTERNAL_UID`·`IDP_OBJECT_ID`·`VERIFIED_EMAIL`)와 후보(`PROVIDER_LOGIN`)를 구분해야 하며
이름 유사성으로 연결하지 않는다. 폐기는 기존 조치 계획 승인으로만 한다: AWS 액세스 키, 그리고 발급 목록에 있는
GCP 사용자 관리 서비스 계정 키, GitLab 토큰, Notion PAT, Azure DevOps PAT와 GitHub 세분화 PAT의 조직 접근
([공급자 자격증명 조치](docs/PROVIDER_ACTIONS.md)). 다른 공급자의 조치는 worker만 그 전용 연결(`remediation` 용도)의
자격증명을 열어 실행하며, API는 자격증명을 열지 않는다. 폐기가 자격증명이 아닌 조직 접근만 끝내면 모듈의 `REVOKES`로
밝히고 화면·소유자 요청이 그 말로 적는다.

현재 schema 2는 [Notion](notion/README.md)의 Enterprise PAT·MCP 연결 메타데이터,
[Azure](azure/README.md)의 Key Vault·Entra·ARM·Azure DevOps PAT 목록, [GitHub](github/README.md)의 발급 목록·선택적 token digest·
감사 로그 토큰 사용 요약·Actions secrets 메타데이터, [GCP](gcp/README.md)의 프로젝트 인벤토리와 조직/폴더 discovery,
[Slack](slack/README.md)의 승인 앱별 봇·사용자 토큰·수신 웹훅 목록(선택적 감사 로그 설치 기록)을 각각의 계약으로 지원한다.
GCP 인증은 Worker ADC·workload identity 외에 대시보드 Google OAuth(`auth_type=google_oauth`)도 쓴다. OAuth 앱 설정
(`GCP_OAUTH_*` 또는 대시보드에 봉인 저장한 앱)은 API 서버 전용이고 Worker는 봉인 참조로 작업마다 토큰을 받으며 ADC로 대체하지 않는다.
공급자가 공개하지 않는 token 값·전체 임시 세션 목록까지 수집한다고 가정하지 않는다. Discovery는 후속 범위 승인이 아니다.
메타데이터 권한과 값 읽기 권한을 분리하며 값 읽기는 연결의 capability·옵션·승인 범위를 모두 검사한다.
값 읽기 기능을 켤 때의 권한·운영 조건 합의안은 [값 읽기 정책(제안)](docs/SECRET_VALUE_READING_POLICY.md)을 따른다.
GCP를 포함해 수집한 비밀 원문은 메모리에서만 처리한다. 가역 암호화·Base64 형태도 보관하지 않으며,
HMAC 지문과 필요한 메타데이터만 남긴다. 공급자 연결에 쓰는 인증 자격증명의 봉인 저장은 별도 계약이다.

[Vault/OpenBao](vault/README.md)의 KV 값·선택적 KV2 이력과 [AWS Secrets Manager](aws/README.md)의
현재·선택적 과거 버전은 schema 1 금고 계약이다. Vault token accessor·lease의 `MANAGED` 메타데이터는
KV의 `VALUE` 일치나 외부 공급자의 발급 근거가 아니다. 과거 일치·부분 수집·권한 거절·미지원 목록은
현재 금고 보관이나 부재로 단정하지 않는다. API가 제공한 최신/이전 버전 근거와 불확실성을 보존한다.
목록 밖 금고는 `external_vault`(JSON Lines·`cremore.vault_readers` 플러그인)로 대조하며, 부재 판정의 근거 수준
(`API_LISTING`·`READER_REPORTED`·`OPERATOR_DECLARED`)을 섞지 않는다. 다른 Vault 클러스터의 서버 읽기는 연결 자신의
로그인만 쓰고 설치의 비밀 저장소 신원을 쓰지 않는다([범용 금고](docs/EXTERNAL_VAULT.md)).
공식 API·권한·제품별 제약은 [기술 가능성 근거](docs/PROVIDER_CREDENTIAL_FEASIBILITY.md),
진행 상태와 실제 검증 범위는 [공급자 인벤토리 구현 기록](docs/PROVIDER_INVENTORY_IMPLEMENTATION.md)을 확인한다.
문서에 계약이 있다는 사실을 전체 공급자 지원·실환경 검증 완료로 보고하지 않는다.

### AWS schema 1 인벤토리

무인 실행의 IAM Roles Anywhere는 `roles_anywhere.py`의 운영자 고정 `credential_process` 브리지로만
지원한다. helper SHA-256·파일 권한·인증서/키·만료를 검사하고 임시 자격증명은 SDK에만 전달한다.
대시보드 요청으로 실행 명령이나 helper 경로를 등록하지 않는다. 신원 실패는 수집 보류와 연결 상태에
반영하며 다른 호스트 신원으로 대체하지 않는다. 배포·교체·검증 한계는
[무인 운영 지침](docs/UNATTENDED_DEPLOYMENT.md)을 따른다.

`aws/backend/cremore_aws_provider/`에는 AWS 담당 코드와 함께 **플랫폼 보안 흐름**이 있다. 아래 모듈은 API·CLI·Worker가
직접 쓰므로 변경하려면 플랫폼 담당자의 공동 검토가 필요하다(외부 검토 2026-09-26). 플랫폼으로 옮기는 작업은 별도로 한다.

- 봉인 키: `kms` — `SEALING_KMS_KEY_ID` 마스터 키 복호화
- 로그인·세션: `aws_identity`, `aws_sso`, `aws_sso_login`, `aws_sso_settings`, `aws_sso_discovery`, `aws_sessions`, `worker_session`
  (`aws_sso_login`, 콘솔의 "AWS에서 로그인": 소유자 검토·승인 2026-10-02, 1인 설치 `AUTH_MODE=local`에서만 동작하고 팀 설치는 API가 거절)
- 계정 접근 승인·조직: `aws_access`, `aws_org_context`, `aws_org_discovery`, `aws_org_settings`, `aws_controltower`
- 키 조치: `remediation/`(교체·비활성화), 읽기 전용 보장: `aws_readonly`
- 발견 자격증명 검증: `detection/verify/`(서명·STS), `detection/session_material`
- 잠재 권한 평가: `investigation/`
- DB 기반 인벤토리 화면: `inventory_view` — 공급자 폴더에서 유일하게 import만으로 DB 계층을 로드한다
  (`provider_boundaries_test.py`의 `REVIEWED_DB_MODULES`)

AWS 계정별 인벤토리는 schema 1의 `aws_iam`·`aws_cloudtrail` 연결을 사용한다. 단일·독립 다중 계정·
Organizations 계정은 같은 승인·수집 경로를 쓰며, Control Tower는 선택적 정보 조회·재발견 신호다.
기존 설치 전체 자동 수집은 기본 비활성이고 관리자가 `/api/v1/settings/aws-credential-inventory`에서 설정한다.
온보딩에서 명시한 새 주기는 연결의 `schedule_source=connection`으로 실행한다. 기존 설정을 자동 전환하지
않으며 설치의 schedule hard lock·계정 승인·기능 중지는 두 경로에 모두 적용한다.
계정 발견·조직 가입·이벤트 수신은 scanner 접근 승인을 대신하지 않는다. Event History와 S3 로그의
계정·리전·기간·권한·불완전 수집 근거를 보존한다. 설정·권한은 [AWS 인벤토리 계약](docs/AWS_CREDENTIAL_INVENTORY_PLAN.md)을 따른다.
STS 평문 세 요소 결합(지문·바인딩)은 외부 호출 없이 수행하며 식별자·키 쌍·완전 세션 지문 일치를 구분한다.
현재 코드에는 완전한 세션에 대한 조건부 인증 확인 경로가 있다. 저장된 결과는 확인 시점의 인증 근거이며,
구성요소 관측·만료 전 상태만으로 현재 유효성이나 서비스 권한을 확정하지 않는다. 원문 토큰은 저장하지 않는다.
역할 정책의 잠재 권한 평가는 실제 STS 세션의 서비스 사용 권한 검증이 아니다. 후자는 미구현이며,
실제 인증 경로의 동작 검증 여부도 별도로 기록한다. [STS 기술 평가](docs/AWS_STS_VERIFICATION.md)를 따른다.

## 반드시 유지할 규칙

- 서버의 권한·승인 scope·외부 origin/path 검증을 유지한다. UI 표시 여부로 권한을 대신하지 않는다.
- 감사 기록(`finding_events`)은 추가만 한다. 저장소의 `record_finding_event`(SQL은 같은 트랜잭션의 `_record_event`)로만 쓰고
  행을 수정·삭제하지 않는다. finding·credential도 지우지 않는다(감사 행이 `ON DELETE CASCADE`로 함께 지워진다).
  쓰는 순간의 MAC과 worker의 해시 체인 봉인이 이를 전제로 한다(`cremore/db/audit_chain.py`, 키는 `AUDIT_CHAIN_KEY` 또는 `FINGERPRINT_KEY`).
- 수집한 비밀 원문·토큰·외부 응답을 DB·파일·로그·finding·job·checkpoint·SIEM 이벤트에 넣지 않는다.
  암호화해 복구 가능한 형태도 금지한다. GCP의 과거 원문 저장 예외와 관리자 값 조회 API는 폐기했다.
  기존 설치의 원문 행·백업·WAL·복제본은 [GCP 이관 절차](docs/integration/GCP_TOTAL_GUIDE_KO.md#과거-원문-저장-설치의-이관)에 따라 별도로 정리한다.
- 요청·크기·시간·페이지 예산, 취소, lease fencing, 저장과 cursor commit 순서, 원자적 갱신을 보존한다.
  부분 수집·권한 거절·실패를 빈 목록이나 리소스 삭제 증거로 처리하지 않는다.
- vendor SDK는 공급자 경계 안에 둔다. domain에 SDK/API를, 순수 model/types/loader에 React feature를 import하지 않는다.
  기존 공개 import·API·native export·설정·DB 호환성을 조용히 바꾸지 않는다.
- UI는 기존 컴포넌트·토큰을 재사용하고 한국어/영어, light/dark, 키보드·초점 동작을 유지한다.
- 기본 검증에는 fake client와 합성 데이터를 사용한다. 실제 공급자 호출·발견 자격증명 검증·SIEM 전송·운영 DB 접근은
  작업에 명시된 별도 환경과 허용 범위가 있을 때만 수행한다.

## 검증과 완료

변경한 동작을 증명하는 작은 검사를 먼저 실행하고 영향에 맞게 넓힌다. 기존 테스트 도구를 사용한다.
아래는 선택 예시이며 매 작업마다 모두 실행하라는 뜻이 아니다. 전체 명령·설치 조건은 팀 지침 10절이 기준이다.

| 변경 | 실행 위치 | 기본 검사 예시 |
| --- | --- | --- |
| 공급자 연결 | 저장소 루트 | `python -m pytest cremore/onboarding cremore/provider_boundaries_test.py -q` |
| 콘텐츠 모듈 | 저장소 루트 | `python -m pytest cremore/sources/module_contract_test.py cremore/domain/connections_test.py -q` |
| scope/worker | 저장소 루트 | `python -m pytest cremore/scanning/scope_test.py cremore/worker/runtime_test.py -q` |
| metadata runtime | 저장소 루트 | `python -m pytest cremore/coverage/collector_runtime_test.py cremore/api/metadata_comparison_test.py -q` |
| 공급자→worker→DB·API 및 근거 연결 | 저장소 루트 | `python -m pytest cremore/coverage/provider_worker_integration_test.py cremore/coverage/metadata_linkage_test.py -q` |
| 저장 이력·공개 인증서 근거 | 저장소 루트 | `python -m pytest cremore/coverage/storage_receipts_test.py cremore/api/storage_receipts_test.py cremore/coverage/certificate_coverage_test.py -q` |
| SIEM core | 저장소 루트 | `python -m pytest cremore/siem -q` 및 외부 출력 패키지의 자체 검사 |
| 웹 | `web/` | `npm test`, `npx tsc --noEmit`, `npm run build`; UI 동작 변경 시 관련 `npm run test:browser` 검사 |
| 모든 변경 | 저장소 루트 | `git diff --check`와 최종 diff 검토 |

구조 변경을 받은 뒤 저장소 루트에서 `python -m pip install -e ".[dev,gcp,azure]"`를 다시 실행한다.
단일 wheel에 공급자 라이브러리를 함께 설치하며, 임의 `sys.path` 수정으로 설치를 대신하지 않는다.
Python 변경에는 변경 파일의 Ruff 검사와 해당 공급자 회귀 검사도 포함한다. pytest 실행 시
AWS metadata 자동 조회를 끈다: Bash는 `AWS_EC2_METADATA_DISABLED=true`,
PowerShell은 `$env:AWS_EC2_METADATA_DISABLED='true'`를 사용한다.
PostgreSQL 검사는 `CREMORE_TEST_POSTGRES_URL`로 지정한 격리된 일회용 DB에서만 실행한다.
DB 이름은 `cremore_test`, 접속 host는 `localhost`/`127.0.0.1`, PostgreSQL은 16 이상이어야 한다.
POSIX 검사는 WSL 또는 Linux Docker의 Linux 파일시스템에서 실행한다. GCP 인증 검사는
`.[dev,gcp]`, Azure 인증 모듈은 `.[azure]`, 브라우저 검사는 Chrome이 필요하다. 기본 Python Docker
이미지는 잠금 파일로 GCP·Azure 인증 의존성을 모두 설치한다. Docker의 격리 조건은 팀 지침 10절을 따른다.
문서만 변경했다면 링크·참조 경로·명령과 diff를 확인하며 불필요한 전체 실행은 하지 않는다.
계정이 연결되지 않은 오픈소스 개발에서는 합성 client·격리 DB·브라우저·설치 검사를 기본 완료
검증으로 삼고 실계정 연동은 별도 미검증 항목으로 기록한다. 현재 CI는 PR·수동 실행이다.
PR에서는 웹 검사와 공급자 경계·콘텐츠 계약 검사(`boundaries` job)가 자동으로 돌고, 브랜치 push만으로는
실행되지 않는다. 전체 검사(PostgreSQL·설치본·브라우저·컨테이너)는 머지할 대상 ref에서 수동 실행한다.

완료 보고에는 변경 파일과 이유, 실제 실행한 검사와 결과, 미실행·skip 및 남은 통합 작업을 적는다.
설정한 CI와 실제 통과한 CI를 구별하고, 검증하지 않은 기능·호환성·성능 개선을 완료로 보고하지 않는다.
공개 계약·사용법·공급자 추가 절차가 바뀌면 팀 지침과 해당 문서를 함께 갱신한다.
기존 구조 리팩터링 결과는 [검증 보고서](docs/REFACTOR_REPORT.md)의 대상 커밋과 후속 검증 절을 확인한다.
세 브랜치 통합(`integration/saas-structure`)의 변경 근거·측정·다른 환경 검증 절차와 프롬프트는
[SaaS 구조 통합 기록](docs/integration/SAAS_STRUCTURE_INTEGRATION_KO.md)을 확인한다.
AWS 인벤토리 후속 변경의 실행 증거·미검증 환경은 [AWS 인벤토리 검증 기록](docs/AWS_INVENTORY_IMPLEMENTATION.md)을 확인한다.
현재 공급자 확장·저장 이력·공개 인증서의 구현 상태와 마지막 검증은
[공급자 인벤토리 구현 기록](docs/PROVIDER_INVENTORY_IMPLEMENTATION.md)의 인수 목록·후속 검증 절을 확인한다.
과거 보고서의 검사 수·미실행 상태를 현재 결과로 재사용하지 않는다.

## 새 AI 작업에 전달할 내용

이 파일과 팀 코딩 지침을 같은 저장소에서 사용하고, 요청에 다음을 명시한다.

- 구현 목표와 담당 공급자/기능
- 수정 허용 경로와 다른 팀원이 맡은 경로
- 유지할 계약과 필요한 검증
- 공통 등록·인증·scope·DB 변경을 함께 맡는지, 별도 통합 담당자가 맡는지

구체적인 작업 카드 예시는 팀 지침 13절을 사용한다. 담당 범위가 명확한 작업은 반복 확인 없이 진행한다.
