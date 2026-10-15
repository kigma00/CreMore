# 공급자 전체 인벤토리 구현·검증 기록

최신 후속: [2026-10-05 인벤토리·감사 메타데이터 재검토](INVENTORY_METADATA_REVIEW_2026-10-05.md).
GCP/Graph/GitHub/Atlassian의 신규 선택 옵션, 공통 표시 보완, 실제 검증과 남은 공급자 제한은 이 기록을 따른다.
후속 제품/요금제 선택·계정/콘텐츠 분리, GCP API-key 생성·프로젝트 IAM 후보, Azure directory audit 및
합성 검증은 [제품 선택·수집 목적 분리](EDITION_AND_COLLECTION_ONBOARDING.md)에도 기록한다.

시작: 2026-09-25. 기준은 현재 `refactoring` 작업 트리이며 기존 미커밋 변경을 보존한다.
공식 지원 근거는 [공급자별 기술 검토](PROVIDER_CREDENTIAL_FEASIBILITY.md), 소유 경계는
[팀 지침](AI_TEAM_CODING_GUIDE.md)이다. 공식 API의 지원 범위, 코드 구현, 합성 검증, 실환경 검증을 구분한다.
아래 구현은 로컬에 통합되었다. 기존 Linux 전체·PostgreSQL 및 Python 3.14 결과는 아래의
기준 스냅샷 기록이며 마지막 추가 기능의 증거는 후속 검증 절에서 따로 기록한다.
실제 공급자 환경은 미검증이다. 이 문서의 검사는 커밋 전 로컬 작업 트리에서 실행했으며
브랜치에 게시되었다는 사실을 원격 CI 통과로 해석하지 않는다.
사용자는 현재 계정을 연결하지 않은 오픈소스 개발 단계임을 확인했다. 아래 합성·격리 검증은
배포할 코드의 개발 검증이며, 실제 계정 연동 검증과 구분한다.

## 사용자 목표

모든 SaaS·클라우드에 대해 논의·조사한 부분을 빠짐없이 구현하고 검증한다. 팀 코드 지침에 따라
공급자별 모듈에서 구현하며 Bitbucket과 Confluence를 Atlassian 상위로 묶어 스캔에도 반영한다.
현재 저장소와 조사에 등장한 AWS, GitHub, GitLab, GCP, Azure, Atlassian/Bitbucket/Confluence,
Notion, Vault/OpenBao를 모두 포함한다. 아래 목록의 일부 통과를 전체 완료로 간주하지 않는다.
추가 요구: 기업 금고에는 **AWS Secrets Manager**도 포함하며, 그 안에 보관된 타 공급자의 자격증명도 대조한다.

## 인수 목록

| ID | 요구사항 | 현재 상태·완료에 필요한 증거 |
| --- | --- | --- |
| P01 | AWS 단일·독립 다중·Organizations IAM/관측 인벤토리 | 기존 schema 1 IAM·Credential Report·최근 사용·CloudTrail·조직/Control Tower 경로 유지. 인증 상태를 확인한 시점과 임시 구성요소 관측을 구분. 전체 회귀에 포함 |
| P02 | GitHub enterprise/org 발급 목록·공개키·Actions secret metadata | Enterprise opt-in `hashed_token`을 설치 키로 지문화. Actions 조직/저장소/환경 목록·선택 저장소 권한 수집. Actions 비밀값은 조회하지 못함 |
| P03 | GitLab 관리자·그룹·프로젝트·서비스 계정·deploy/SSH key 인벤토리 | 기존 수집기에 명시적 instance PAT/deploy token/deploy key/사용자 SSH, enterprise 사용자 SSH, project deploy key 경로 추가. 인스턴스 관리자 preflight·origin 범위 검증 |
| P04 | GitLab CI 변수 저장소 대조 | 정확히 승인한 group/project의 `ci_variables`를 보완 수집. `vault_value` 및 `include_values`일 때만 지문 보존. 하위 그룹 발견은 값 접근 승인이 아님. worker→memory/SQLite→공개 응답 검증 |
| P05 | GCP 조직·폴더·프로젝트 발견과 키/Secret Manager 수집 | 조직/폴더 재귀 발견 `discovery` 추가. 발견만으로 프로젝트 값 수집 승인 불가. 같은 JSON 객체의 PEM·client_email·private_key_id를 결합해 식별자 근거 연결 |
| P06 | Azure Entra 앱/SP 자격증명·인증서·연합 신뢰 metadata | `azure/entra` 모듈과 registry/UI/worker 연결. 확인된 tenant에서 Graph metadata 수집. client secret 원문·전체 OAuth 토큰 목록 아님 |
| P07 | Azure Key Vault secrets/versions 값 지문화 | API 2025-07-01, 기본 metadata와 선택적 현재/과거 값 지문화. 동일 vault/version 경계 및 nextLink 검증. 원문 DB 저장 없음 |
| P08 | Azure 구독/Vault 발견·Storage 키·KV keys/certificates | `azure/arm` 구독/Vault/Storage 발견, 정확히 승인한 Storage의 `listKeys` 지문화. KV 키/인증서 및 버전/삭제 목록 metadata. 발견과 값 접근 승인 분리 |
| P09 | Atlassian Cloud admin key/token/service-account/OAuth metadata | 기존 공식 admin API 경로 유지·회귀 확인. 조직 관리 범위와 source별 부분 수집 이유 보존. Bitbucket 전체 토큰까지 포함한다고 주장하지 않음 |
| P10 | Bitbucket Data Center 발급 인벤토리 | DC 10.4 공식 REST 사용자/프로젝트/저장소 HTTP token metadata 수집. 명시적 context path·scope 검증. canonical native export·실행 비교·실패 scope 선택 재수집 지원. 재수집은 첫 페이지부터 시작하며 비선택 범위는 NOT_REQUESTED. 원문 재조회 불가 |
| P11 | Bitbucket Cloud·Confluence DC 전체 토큰 목록 | 현행 공식 OpenAPI 재조사 완료. 안정된 전체 목록 REST 지원 미확인으로 구현하지 않음. Cloud 170 paths, Confluence 10.2.18/11.0.0 각 148 paths 조사. UI·내부 endpoint를 공개 API로 추정하지 않음 |
| P12 | Notion Enterprise PAT 및 관리 연결 metadata | API 2026-06-01 PAT와 선택적 MCP 연결 목록, workspace 범위·paging·재개·export/비교 구현. 기존 연결되지 않은 UI를 실제 metadata 화면으로 변경. 원문/비교 hash 없음 |
| P13 | Vault/OpenBao KV 범위·버전·동적 관리 증거 | KV2 선택 버전/이전 버전과 한도, service-token accessor·명시 lease prefix metadata. `MANAGED`는 KV 값 일치와 별도. batch token 제약·실패한 lookup 보존 |
| P14 | 발급↔노출↔금고 증거 기반 연결 | GitHub 제공 hash·호환 값 지문·GCP SA 식별자 연결. 발급 목록에만 있는 객체도 표시하며 가짜 finding 생성 안 함. 내용이 발견된 저장소를 발급 tenant로 추정하지 않음 |
| P15 | 수집 실패·미지원·부분·권한 부족·stale 표시 | 불완전 수집에서 부재 확정 차단. 과거 KV 버전/관리 전용 연결 false absence 수정. 과거 발급 관측의 일치 근거와 최신성(`current_evidence`) 분리 |
| P16 | Atlassian 상위 아래 Bitbucket/Confluence 스캔·연결 표시 | 등록·연결·catalog·governance·scan을 부모 Atlassian으로 그룹화. 기존 하위 source/job/scope 식별자 보존. 한국어/영어·light/dark·좁은 화면 브라우저 검증 |
| P17 | 공통 등록·라이브러리 설치·빌드·배포 | 한 wheel·정적 registry·기존 공통 runtime 사용. 기본 Docker image의 Azure extra 누락 수정; 기존 pin 변경 없이 4개 의존성 추가. wheel/import·build·native 배포 render 검증 |
| P18 | 전체 검증 | 아래 실행 결과 참고. 이전 전체6050개·3.14회귀781개·각 버전 후속367개는 기준 스냅샷 기록. 마지막 DC/receipt/certificate 변경은 Linux3.12+PostgreSQL512개, Python3.14 110개 통과. 모두 skip0. 검사 수는 중복되므로 합산하지 않음 |
| P19 | 문서 | AGENTS·팀 지침·공급자 README·가능성 보고서·현재 기록 동기화. 통합 정규화 DB migration은 이번 작업에 포함하지 않음 |
| P20 | 실제 공급자 환경 검증 | 미실행. 사용자가 오픈소스 개발 단계로 현재 계정 미연결임을 확인. 공급자 계정·조직·workspace와 연결 권한이 준비된 뒤 별도 통합 검증. 공식 문서/합성/DB/브라우저 통과와 구분 |
| P21 | AWS Secrets Manager 기업 금고 연동 | schema 1 현재/이전 버전 및 명시 버전 한도 지원. AWS 계정·리전·ARN·버전 응답 검증, 부분/권한 실패 보존. 타 공급자 지문과 대조하고 과거 일치는 별도 표시 |
| P22 | 발급·회전 저장 이력으로 관측 연결 | 관리자 제출 API·UI·DB 구현. schema 1/2의 실제 수집 관측 위치를 고정. 멱등성·철회·범위 변경·비활성 처리, 행별 lazy 조회. 값 일치와 현재 보관의 증거로 승격하지 않음 |
| P24 | Slack Enterprise Grid 앱 발급 목록 | 2026-09-28. 공식 문서만 근거로 새로 작성(되돌린 GPL 브랜치 코드 없음). 승인 앱을 봇·사용자 토큰·수신 웹훅 행으로, 선택적 감사 로그로 설치 상태·설치일·설치자. 승인≠설치, 토큰 값·웹훅 URL·사용 기록 없음. 아래 "Slack 발급 목록" 절 |
| P23 | Entra↔Key Vault 공개 인증서 연결 | 명시적 opt-in 공개 DER 읽기와 SHA-256 비교. PUBLIC_CERTIFICATE_MATCH는 공개 인증서만의 연결. 개인키 보관/인증 권한 미증명. 이후 공개 조회 실패 시 과거 근거를 유지하며 현재성은 제거 |

## 완료로 숨기면 안 되는 제약

- 공급자 API가 제공하지 않는 과거 전수 목록을 만들 수 없다. Azure SAS, 모든 활성 STS/OAuth 세션,
  Vault/OpenBao batch token 등의 제약을 사실대로 유지한다. 목록이 없다는 이유로 빈 인벤토리 성공을 만들지 않는다.
- 불투명 token의 이름·끝자리·생성자만으로 값 일치나 금고 부재를 확정하지 않는다.
- 실제 발견 자격증명을 외부 서비스에 재사용하는 인증·권한 검증의 확장/실행은 이 작업에서 진행하지 않는다.
  기존 관측 근거·공급자 상태·오프라인 지문 대조와 구분한다.
- 비밀 원문은 일반 finding/job/checkpoint/로그/SIEM에 저장하지 않는다. 당시 남아 있던 GCP 전용 저장 예외는
  2026-10-02 폐기했다. 현재는 가역 암호화 형태도 보관하지 않으며 HMAC 지문과 필요한 메타데이터만 남긴다.

## 작업 격리와 검증 기록

현재 작업 트리를 보존한 로컬 snapshot `46983c60ec2ce86fae6bd520917f444b57e35dce`로 공급자별 worktree를 만들었다.
원래 branch/index는 변경하지 않았다. Notion backend, Azure backend, Atlassian UI의 파일 소유권을 분리했으며
공통 모델·등록·저장·상관분석·API는 통합 담당자가 변경한다. provider 변경분만 원래 작업 트리에 통합한다.

실행한 검사 결과는 해당 변경분을 통합·확인한 뒤 이 절에 추가한다. 계획된 검사와 통과한 검사를 구분한다.

### 실행한 검사

| 검사 | 실제 결과·경계 |
| --- | --- |
| Windows `python -m pytest -q -ra` | 최초 통합 실행 **5883 passed, 80 skipped, 6 failed, 278 subtests passed**. 6실패는 갱신 전 기대값 5사례와 합성 fixture의 토큰 문자열 규칙 1사례. 실패를 통과로 숨기지 않음 |
| Linux 전체 `python -m pytest -q -ra` | 마지막 schema 2 수정 직전 스냅샷. Python **3.12.14**, PostgreSQL **17.11**, **6050 passed, 0 skipped, 354 subtests passed** (697.45초). source/temp는 Linux FS, 격리 네트워크, repository secret 검사 포함. 기존 Starlette/httpx deprecation warning 1개 |
| Python 3.14 배포 런타임 회귀 | 마지막 schema 2 수정 직전 스냅샷. 동일 기본 이미지 계열 Python **3.14.7** 및 잠금 runtime 의존성, 신규 공급자/core/API/DB 23개 경로 **781 passed, 0 skipped, 64 subtests passed** (173.54초). Starlette/AnyIO deprecation warning 2개 |
| 최종 수정 후 Linux 회귀 | Python **3.12.14: 367 passed, 0 skipped** (178.84초), **3.14.7: 367 passed, 0 skipped** (173.32초). PostgreSQL 17.11 포함. 모델/저장/API/runtime/대조·세 공급자 projection·catalog·repository secret 검사 15개 경로. 기존 deprecation warning 각각 1개/2개 |
| 실패 관련 파일 5개 후속 회귀 | **158 passed**. GitLab의 새 vault capability를 unsupported라고 기대한 검사를 수정하고, AWS 조건부 기능 선언과 인증 미수행을 구분. 실제 인증 코드 추가·호출 없음 |
| `cremore/repository_secrets_test.py` | fixture를 런타임 결합 문자열로 고친 뒤 **1 passed**. 저장소 검사 예외 추가/탐지 약화 없음 |
| 금고 scope 회귀+인접 검사 | **156 passed, 1 skipped**. 신규 memory/SQLite 26사례 포함. skip은 이 실행에서 PostgreSQL URL 미설정 |
| 발급 근거 최신성+API/worker 회귀 | **81 passed, 0 skipped**. 최신·부분·후속 빈 결과·실패·실행 중·중지·범위 변경·stale 16사례 포함 |
| 신규 provider worker 통합 | Notion/Azure **14 passed**, GitLab **12 passed**. memory/SQLite의 합성 수집→저장→응답/대조 경로. GitHub/GCP는 별도 공급자 검사와 위 전체 회귀에 포함 |
| `npm test` | **499 passed, 0 skipped** |
| `npm run test:browser` | **26/26 synthetic browser proofs passed**. 네트워크 차단, 실제 Chrome. 신규 GCP 발견 모드 승인 경계·관리 전용 금고 UI 포함 |
| `npm run build` | Next.js 16.3.4 생산 빌드 및 TypeScript 통과. 마지막 과거 근거 표시 변경 후 재실행도 통과 |
| 마지막 보관 대조 브라우저 검사 | saved issuer 값 일치와 과거 시점 표시, 관리 전용/이전 버전/편집 보존, KO/EN·light/dark·320/390/980/1440px 검사 통과. 외부 요청 0 |
| 기존 native Helm/Compose render | **70 passed, 0 skipped**. 설정 render이며 고객 OIDC 로그인을 검증한 것은 아님 |
| 설치/import 관련 pytest | **9 passed** |
| checkout 외부 wheel 설치/import | 마지막 schema 2 수정까지 포함해 재빌드한 wheel로 adapter 9개/source 7개/신규 모듈 14개/CLI 4개·순수 helper 6개 통과. socket/DNS 차단. SHA256 `7f9004942e5238b03bc5de43da6ba0b67d97efd49e82b471b468683eee4071ad` |
| 수정 requirements 설치 | `--require-hashes --only-binary :all:` 설치와 `pip check` 통과. 기존 pin 변경/제거 0개 |
| default Python Docker build/import | 마지막 수정까지 포함한 잠금 파일 hash 검증과 build 통과. network none/read-only/uid65532에서 Azure/Vault/AWS 신규 모듈 import·세션 지문 필드·재귀 공개 응답 제거 검사 통과. 실제 공급자 인증 없음 |
| Linux POSIX 집중 검사 | **490 passed, 342 subtests passed, 0 skipped** |
| 일회용 PostgreSQL 집중 검사 | PostgreSQL 17.11·`cremore_test`·loopback·tmpfs·network none, **165 passed, 0 skipped**, 잔여 테스트 schema 0 |
| 독립 CLI | Linux GitLab **162 passed**, GCP **48 passed** |
| Ruff | 플랫폼·모든 provider backend 및 변경 Python 파일 155개 통과. Linux에서 추가 발견한 QA shebang/실행 권한 불일치 3개는 Python 모듈 실행 계약에 맞게 shebang 제거 |
| 문서·diff | 주요 문서 로컬 링크 59개 모두 존재, 공식 외부 링크 81개 수록. `git diff --check` 통과 |

Linux 전체 로그는 `.git/inventory-linux-full.log`, Python 3.14 회귀는 `.git/inventory-python314.log`,
최종 두 버전 후속은 `.git/inventory-delta312.log`·`.git/inventory-delta314.log`,
최종 Docker 증거는 `.git/inventory-product-build-final.log`·`.git/inventory-product-import-final.log`,
최종 wheel 설치/import는 `.git/inventory-wheel-final.log`, Windows 실행 로그는 `.git/inventory-python-windows.log`, 실패 후속은 `.git/inventory-corrections.log`,
저장소 문자열 검사는 `.git/inventory-repository-secrets.log`, 웹은 `.git/inventory-web-unit.log`와
`.git/inventory-browser.log`에 있다. `.git/` 로그는 로컬 증거이며 배포/commit 대상이 아니다.
개별/전체 검사 수는 서로 중복되므로 합산하지 않는다.
추가로 루트 전체 `ruff check .`는 변경하지 않은 독립 GCP/GitLab 기존 파일의 진단 80개가 남아 실패한다.
이번 수정 경로와 제품 backend lint 통과를 저장소 모든 legacy 파일의 lint 통과로 확대하지 않는다.

전체 검사 소스 archive SHA256은 `d1e735d37688c6b9a1435be1c732afc431625e73af9324c440b57972980d5904`,
최종 수정 archive SHA256은 `ea2100db240a0d387a4825e0ce096d6698167160aa20dd94e5bfca31c3bbfe6a`다.
최종 제품 이미지는 `cremore-inventory-product-proof:20260925-final`이며 manifest digest는
`sha256:865237563d8b5ec4546c99f5f81c4a691faab031471be7c26454aab279a0489b`다.
검사 뒤 일회용 DB의 잔여 test schema 0개를 확인하고 해당 검증 컨테이너를 제거했다.
기존 두 제품 스택과 DB는 정상 실행 상태이며 운영 데이터·볼륨은 변경하지 않았다.

### 정합성·비공개 근거

- GitHub 공급자 hash는 공급자 모듈의 순수 helper를 import하며 원문 hash 대신 설치 키 HMAC을 저장한다.
  finding의 `issuer_comparison`, schema 2의 `PROVIDER_DIGEST`/`provider_digest`는 일반 API와 SIEM에 노출하지 않는다.
  기존 schema 2의 일반 keyed `value_match.fingerprint` 공개 계약은 유지한다.
- GCP SA는 bounded JSON 안의 같은 객체에 속한 PEM·ID만 결합한다. 복수 ID는 임의 선택하지 않는다.
  식별자 일치가 비밀값·현재 인증·권한 확인을 뜻하지 않는다.
- bare Azure Storage key 등 라벨 없는 금고 문자열은 bounded `OPAQUE_VALUE` 지문으로 이미 알려진 값을 대조한다.
  공급자/종류를 추정하거나 새 노출을 만들지 않으며 미해석 값의 불완전성 근거를 지우지 않는다.
- `NO_VAULT_MATCH`는 확인된 현재 금고 범위·호환 비교 계약·최신 수집 조건에서만 사용한다.
  과거 버전, 원문 비교 불가, 관리 metadata 전용 연결은 이 판정을 성립시키지 않는다.
- `MANAGEMENT` 행과 집계는 노출·KV 보관 일치율에서 분리한다. TTL·정책·lease 관측은 현재 사용 가능성 증거가 아니다.
- 새 수동적 발급 연결 근거를 위해 탐지 계약의 `ENGINE_EPOCH`를 7로 올렸다. 기존 DB·finding을 삭제하거나
  원문을 복원하지 않는다. 이전 관측에 새 비교 근거가 없거나 engine/policy/key 계약이 다르면 후보/미확인으로
  남고, 정확한 새 대조에는 동일 계약으로 다시 수집한 금고/발급 자료와 새 노출 관측이 필요하다.
- 마지막 구조 검토에서 schema 2가 완전 STS 세션 지문을 잃던 문제를 수정했다. 동일한 선택적 필드·검증을
  공통 record에 두고 Azure/GitLab/GCP 공급자 함수가 전달한다. 공통 저장/대조를 복제하지 않는다.
  이 지문은 공개 metadata/API/native export에서 제거하며 외부 인증 호출을 추가하지 않는다.
- 최신 수집이라도 현재 버전을 확인하지 못한 저장 객체는 현재 부재를 확정하지 않는다. 같은 객체의 CURRENT
  근거와 과거/UNKNOWN 버전을 함께 수집한 경우는 구분하고, 다른 객체의 CURRENT로 대신하지 않는다.
  GCP schema 2는 ENABLED 버전 목록만으로 `latest`를 단정하지 않는다. 명시적 최신 값 조회는 기존 schema 1
  `gcp_secret_manager` 연결에서 지원하며 그 현재 값은 별도 긍정 대조에 사용할 수 있다.

### 남은 검증과 외부 제약

- 전체 6050개와 Python 3.14의 781개는 마지막 schema 2 세션·버전 수정 직전 스냅샷 기준이다.
  변경 범위의 Python 3.12/3.14 후속 367개 검사는 각각 통과했다. 최종 수정 뒤 전체 suite를 반복한 결과는 아니다.
- 실제 공급자 테넌트, 제품 라이선스별 권한, OIDC 로그인, 실제 SIEM 목적지 수신은 미검증이다.
  Docker는 합성 API·DB·패키징을 검증하며 고객 권한과 API entitlement를 대신하지 않는다.
  현재는 사용자가 확인한 오픈소스 개발 단계로 실제 공급자 계정이 연결되지 않았다.
  여기서 테넌트는 GitHub 조직·Notion workspace·Azure 디렉터리처럼 공급자 내 회사별 사용 공간을 뜻한다.
  계정 연결 이후 확인할 사항은 설치 버전/요금제의 API 지원, 부여된 scope/권한, 실제 응답과 페이지 처리,
  명시한 금고 범위의 값 읽기 및 저장된 결과다. 원문 자격증명은 공개 이슈·로그·문서에 넣지 않는다.
- Bitbucket Cloud 전체 토큰·Confluence DC 전체 PAT 자동 목록은 공식 계약 미확인으로 미구현이다.
  전체 STS/OAuth 세션, Azure SAS, batch token 전수 열거도 보장하지 않는다.
- 공통 정규화의 schema 1/schema 2/catalog 통합 migration은 별도 과제다. 발급→금고 저장 이력 제출은
  구현했지만 존재하지 않는 과거 이력을 복원하거나 외부 회전 시스템의 이력을 자동 발견하지 않는다.
- 원격 CI는 이번 로컬 검증에서 실행하지 않았다. 현재 CI는 PR 또는 수동 실행이며 전체 검사는
  수동 실행이 필요하다. `refactoring`에 push하는 것만으로 전체 CI가 실행되지는 않는다.

## 발급·저장 이력 API

`cremore/coverage/storage_receipts.py`는 관리자가 신뢰하여 제출한 원본 발급·회전 이력과 실제 수집 관측을
연결한다. 제품이 외부 원본 이력의 진위를 검증한 것으로 표현하지 않는다. 비밀 원문은 받지 않는다.

| API | 권한·동작 |
| --- | --- |
| `GET /api/v1/coverage/storage-receipts` | 로그인 사용자 조회. offset/limit, schema 2 `issuer_entity_id` 또는 schema 1 `issuer_connection_id`+`issuer_identifier` 필터 |
| `POST /api/v1/coverage/storage-receipts` | 관리자 등록. 같은 UUID·같은 내용 재시도는 기존 결과 반환, 다른 내용은 409 |
| `POST /api/v1/coverage/storage-receipts/{id}/revoke` | 관리자 철회. 원본과 철회 시각/주체 보존. 실제 자격증명/금고 변경 없음 |
| `GET /api/v1/coverage/storage-receipts/connections` | 관리자 관측 선택용 연결 목록; 비밀 참조 없음 |
| `GET /api/v1/coverage/storage-receipts/connections/{id}/runs` | 관리자 수집 이력 페이지; raw 계약/토큰 없음 |
| `GET /api/v1/coverage/storage-receipts/observations?run_id=...&role=issuer` | 관리자 발급/금고 후보 조회. role은 issuer 또는 vault; 원문/비교 지문 없음 |

등록 본문은 `id`(UUID), `issuer`와 `vault` 각각의 `{run_id, batch_index, item_index}`,
`source_system`, `source_record_id`, `stored_at`을 받는다. 관측은 COMPLETE/PARTIAL로 끝난 수집에
실제로 포함되어야 하고 현재 연결 revision·승인 범위·provider record 계약을 재검증한다.
`source_system`은 64자 이내 영숫자·점·밑줄·하이픈 ID, `source_record_id`는 128자 이내 ID이며
추가로 콜론·슬래시·@를 허용한다. 시간은 timezone이 있는 과거 시각이다. 제출 시각·주체는 서버가 기록한다.
수집기 토큰으로 등록할 수 없다. UI는 연결→수집→관측 순으로 선택하며 재시도에 같은 UUID를 사용한다.

`STORAGE_RECORDED`는 저장 이력이 있다는 뜻이다. 철회·범위 변경·비활성 뒤에는 `applicable=false`와
이유를 반환한다. 값 일치·현재 보관·현재 인증 상태나 기존 노출/금고 일치율을 바꾸지 않는다.
발급 행의 「연결된 저장 이력」과 별도 「발급·저장 이력」 패널에서 조회한다. 외부 발급 시스템이
등록 API를 호출하도록 연결할 수 있지만 제품이 시스템별 webhook/signature를 자동 인식하지는 않는다.

DB는 기존 `create_all`의 additive 경로로 빈 `coverage_storage_receipts` 테이블과 조회 인덱스 두 개만
추가한다. 기존 schema 1/2 collection·batch·entity·finding 행과 relation 계약은 유지한다. 이전 제품
버전으로 rollback하면 새 테이블은 사용하지 않으며 데이터를 삭제할 필요가 없다. 운영 backup·배포
절차는 기존 정책을 따르고 테스트는 격리 DB에서 수행한다.

## 마지막 추가 기능 후속 검증

기존 6050/781/367 검사 및 이전 wheel·Docker digest는 P22/P23·DC 후속 기능 이전의 기준 증거다.
최종 변경 검증 결과는 이 절에 기록하며 과거 총계와 합산하지 않는다.

- 새 storage receipt DB/API·인증서 집중 검사: 최초 104 passed. 인증서 조회 실패 후 이력 보존
  수정과 API 공개 인증서 필터를 포함한 후속 certificate/API 검사: 58 passed.
- Bitbucket DC 및 인접 runtime/API: Windows 310 passed, 57 skipped, 240 subtests.
  57 skip은 기존 POSIX private-file 검사이며 Linux 실행 결과와 구분한다.
- 저장 이력 브라우저: Admin 선택/등록/응답 유실 후 동일 UUID 재시도/조회/철회, Viewer 조회 전용,
  한국어/영어·light/dark·1440/390px 통과. 긴 원본 이력 ID의 모바일 넘침을 수정했다.
- 최종 Linux Python3.12.14 + PostgreSQL17.11: **512 passed, 0 skipped, 316 subtests passed** (81.69초).
  receipt DB/API·인증서·metadata store·Atlassian 전체 backend를 실행했다. 기존 Windows POSIX skip도
  이 실행에서는 통과했다. 실제 신규 테이블의 PostgreSQL 등록/조회/철회와 공개 인증서 과거 조회 포함.
- 최종 Python3.14.7: 새 receipt/certificate/API **110 passed, 0 skipped** (21.90초).
  최초 실행은 시스템 Python을 가리켜 pytest가 없었으며 이미지의 `/app/venv/bin/python`으로 수정하여 통과했다.
- `npm test`: **500 passed, 0 skipped**. `npx tsc --noEmit` 및 Next production build 통과.
  마지막 UI 변경 뒤 `credential-coverage`와 `storage-receipts` 실제 Chrome 검증 **2/2 통과**.
  schema1/2 실제 발급 행의 필터·lazy 조회·철회 후 갱신·공개 인증서 상태/제한 설명까지 포함한다.
- 플랫폼·모든 공급자 backend Ruff 및 `git diff --check` 통과. 최종 실행에는 기존 upstream
  Starlette/httpx 경고 1개, Python3.14에는 AnyIO 경고도 있으며 기능 실패로 숨기지 않는다.

최종 Linux 입력 1131개 파일의 archive SHA256은
`9f0cbbe76000983324f9f32eaab3126bbe7447cee28070c49f52fb163a41b420`이다.
로컬 증거는 `.git/inventory-final-proof/manifest.json`, `.git/inventory-final312.log`,
`.git/inventory-final314.log`, `.git/inventory-web-unit-final.log`, `.git/inventory-web-build-final.log`다.
소스/임시 파일은 Linux FS, DB는 network none·tmpfs·포트 미공개이며 시험 프로세스만 동일 network
namespace의 127.0.0.1로 접속했다. 실행 후 잔여 시험 schema는 0개다.
마지막 수정 뒤 기존 전체6050개를 다시 실행한 결과는 아니며, 이전 Docker 제품 이미지는 이번 추가 기능
전의 산출물이다. 배포에는 현재 소스로 새 제품 이미지를 빌드해야 한다.

최종 wheel SHA256은 `47ffa77bdd14f2993723c5bf6b64acf9f0e66817a496323d75fed44a25bd9d79`다.
격리 build로 생성한 wheel을 별도 venv에 설치하고 checkout 밖에서 신규/수정 모듈 6개가 실제
설치 경로에서 import되는 것을 확인했다. socket/DNS는 차단했다. 로컬 build-isolation 비활성
시도는 Hatchling 미설치로 실패하여 표준 격리 build로 전환했고 정상 완료했다.
증거는 `.git/inventory-final-wheel-build.log`와 `.git/inventory-final-wheel-import.log`다.
시험 snapshot 뒤 변경은 이 결과 문서뿐임을 파일 hash로 확인했다. 일회용 PostgreSQL 컨테이너는
생성 ID를 확인하여 제거했으며 기존 두 제품 스택과 DB는 정상 상태로 유지했다.

## 대조 판정 후속 수정 (2026-09-25)

공급자별 현황 점검에서 코드로 고칠 수 있다고 확인한 다섯 가지를 수정했다. 공급자 API가
값·해시·목록을 주지 않아 생기는 제약(GitLab·Atlassian·Notion·Entra secret의 발급→금고 판정 등)은
그대로이며 이 절의 수정으로 해소되지 않는다.

| 커밋 | 변경 | 계약 영향 |
| --- | --- | --- |
| `f55eb36` | 중지한 금고 연결을 대조 범위에서 제외 | 범위 revision이 바뀌어 관리자가 다시 확인하기 전까지 부재 판정은 막힌다. 중지한 금고의 일치는 과거 근거로만 남는다 |
| `ab320f3` | GCP 서비스 계정 키의 키 ID 부재 판정 | AWS 키 ID와 같은 `IDENTIFIER_NOT_OBSERVED`. 금고에 키 ID가 없거나 모호한 서비스 계정 키 값이 있으면 `VAULT_SERVICE_ACCOUNT_KEY_UNIDENTIFIED`로 `UNKNOWN` |
| `126935a` | 발급 판정 요약과 `origin` 필터 | `summary.issued`·`issued_in_vault`·`issued_not_in_vault`·`issued_unknown` 추가(기존 키 유지). 관측된 STS 세션은 세지 않는다. 필터는 목록만 좁힌다 |
| `08fe61a` | S3·Notion DELTA의 변경 없는 객체 노출 관측 갱신 | 목록에서 watermark 이전 수정 시각으로 다시 본 기존 노출 위치만 `last_seen_at` 갱신. 읽기·제거 규칙은 그대로이며 Inventory·EVENT는 제외. 24시간 최신성 기준은 유지 |
| `86f11b8` | Microsoft Entra client secret 탐지기 | `AZURE_ENTRA_CLIENT_SECRET`(provider `azure`)는 Entra 발급 목록의 후보로만 연결. 엔진 digest가 바뀌므로 배포 뒤 금고 재수집·재스캔 전까지 부재 판정은 `UNKNOWN` |

실행한 검사(Windows, Python 3.12.9, Node 24.18.0, 로컬 작업 트리):

- 수정별 회귀 테스트는 수정 전 실패와 수정 후 통과를 각각 확인했다.
- 전체 `python -m pytest -q -ra`: **6167 passed, 80 skipped, 278 subtests passed** (607초).
  skip은 POSIX private-file 57개, `CREMORE_TEST_POSTGRES_URL` 미설정 21개, POSIX flock 2개다.
- 탐지 전체와 저장소 비밀 검사: **2854 passed**. 플랫폼·모든 공급자 backend Ruff 통과.
- 웹: `npx tsc --noEmit`, `npm test` **500 passed**, `npm run build` 통과, `npm run test:browser`
  **27/27 synthetic browser proofs passed**(실제 Chrome, 네트워크 차단). 새 근거 종류 필터와 발급 요약 타일 확인 포함.

이번 절의 검사는 Linux·PostgreSQL·Python 3.14 실행, Docker 이미지·wheel 재빌드, 원격 CI,
실제 공급자 계정 검증을 포함하지 않는다. 커밋은 로컬 `refactoring` 브랜치에 있다.

## 원문 전송 없는 후속 수정 (2026-09-25~26)

원문을 저장하거나 발급처로 새로 보내지 않고 할 수 있는 항목(🟢·🔵)을 구현했다. 발견 값을 공급자에 보내거나
그 값으로 인증해야 하는 항목은 정책 결정 대상으로 남겼다.

| 커밋 | 변경 | 경계 |
| --- | --- | --- |
| `a8c5a7c` | 자체 GitLab이 등록된 설치에서 GitLab 밖에서 발견한 GitLab 토큰을 GitLab.com으로 보내지 않음 | 관리자 교차 호스트 검증에서만 전송하며 그 거절은 `INDETERMINATE`. 원문 전송이 줄어드는 수정 |
| `af42ea0` | Azure SAS 탐지(`AZURE_SAS_TOKEN`), 서명된 필드 기록, Storage 계정 이름으로 키 항목 연결 | 서명은 지문으로만 보관. 어느 키가 서명했는지는 확정하지 않음 |
| `5272825` | 기존 검증이 받은 소유자로 GitHub·GitLab·Notion 발급 후보를 `OWNER`로 우선 표시 | 새 요청 없음. 같은 소유자일 뿐 같은 토큰이 아니므로 `match_count` 불변 |
| `d7fc95c` | Entra 인증서 `PUBLIC_CERTIFICATE_NOT_OBSERVED` | 범위 확인·선택한 Key Vault 인증서 조회 전체의 최신·완료가 조건. 개인키 부재가 아님 |
| `2e35a32` | Azure client-secret 설정 이름 옆의 이전 형식 Entra secret 중간 신뢰도 탐지 | `Q~` 형식은 기존 탐지기만 보고하여 중복 없음 |

이번에 구현하지 않은 🟢·🔵 항목과 이유:

- AWS·Vault 금고의 서버 수집: 금고 값은 고객 환경에서 수집한다는 문서화된 계약을 바꾸는 결정이 먼저다.
- SAS 서명 키 확인: 서명 재계산의 정확성을 보장할 공식 SDK 검증 벡터가 없다(문서 예시는 키를 공개하지 않는다).
- GitLab.com 토큰 ID(`/personal_access_tokens/self`): 공식 문서가 요구 scope와 그룹·프로젝트 토큰 지원을 밝히지 않아
  기존 검증 엔드포인트를 실계정 확인 없이 바꾸지 않았다.
- GitHub 감사 로그 연결: 현재 수집은 자격증명 관리 이벤트만 남겨 노출 토큰의 활동과 연결되지 않는다.
  토큰 인증 이벤트의 요약 저장 또는 조회용 공급자 해시 보관 중 하나를 정해야 한다.
- Azure Blob·DevOps 콘텐츠 스캔: 새 공급자 추가 규모이며 등록·빌드 통합이 필요하다.
- GCP Secret Manager 경로 정리, API 키 권한, 자동 수집·KV 버전: 설계 정리 또는 고객 설정이다.

새 탐지기(SAS, 이전 형식 Entra secret)로 엔진 digest가 바뀌었다. 배포 뒤 금고 재수집과 재스캔 전까지
부재 판정은 `UNKNOWN`이다.

실행한 검사(Windows, Python 3.12.9, Node 24.18.0, 로컬 작업 트리, 마지막 커밋 `2e35a32` 기준):

- 수정마다 수정 전 실패와 수정 후 통과를 확인했다.
- 전체 `python -m pytest -q -ra`: **6195 passed, 80 skipped, 278 subtests passed** (665.76초).
  skip은 POSIX private-file 57개, `CREMORE_TEST_POSTGRES_URL` 미설정 21개, POSIX flock 2개다.
- 플랫폼·모든 공급자 backend Ruff 통과. 저장소 비밀 검사가 새 탐지기로 저장소 파일을 오탐하지 않음을 포함한다.
- 웹: `npx tsc --noEmit`, `npm test` **500 passed**, `npm run build` 통과, `npm run test:browser` **27/27 passed**.

Linux·PostgreSQL·Python 3.14 실행, Docker 이미지·wheel 재빌드, 원격 CI, 실제 공급자 계정 검증은 포함하지 않는다.

## 남은 🟢·🔵 항목 전체 진행 (2026-09-26)

앞 절에서 미구현으로 남긴 항목과 새 콘텐츠 공급자를 모두 구현했다. 발견 값을 공급자에 새로 보내거나 그 값으로
인증하는 항목(🟠)은 여전히 정책 결정 대상이다.

| 커밋 | 변경 | 경계 |
| --- | --- | --- |
| `959f419` | GitLab.com 검증 엔드포인트를 `/personal_access_tokens/self`로 바꿔 토큰 ID·소유자·scope·만료를 기록하고, 그 ID로 GitLab.com 발급 목록의 PAT 계열 항목을 `IDENTIFIER`/`PROVIDER_VERIFIED_TOKEN_ID`로 연결. 소유자 순위의 `observation.metadata.user_id` 경로와 인스턴스 한정 수정 | 기존과 같은 1회 요청·같은 호스트. GitLab 소스 코드로 모든 scope 허용을 확인했으나 실계정 미검증 |
| `d8146e0` | GitHub 감사 로그의 토큰 사용 요약(`token_activity`)과 발견 조회의 `token_activity` | `include_provider_hashes`·`include_audit_events` opt-in. 설치 키로 만든 digest만 비공개 `ProviderEvent.value_match`에 두고 원래 hash는 버림. 항목 ID로 겹치는 수집 창을 한 번만 셈. 미발견은 미사용 근거가 아님(REST는 Git 이벤트 미반환) |
| `51c2a0b` | Azure SAS를 서명한 Storage 키 확인(`VALUE`/`SAS_SIGNATURE`) | ARM `storage_keys` 수집 중 메모리의 키로 공식 string-to-sign을 재계산. 결과 지문은 비공개 `signed_fingerprints`. 계정 SAS·Blob/Files/Queue 서비스 SAS(2015-04-05+)만. Azure가 발급한 SAS로는 미검증 |
| `77627df` | AWS Secrets Manager·SSM 서버 수집(`server_collection`) | 기존 AWS 인벤토리 작업·스캐너 승인 pin·리스를 재사용하고 이 작업만 값 읽기 허용 목록(`VAULT_OPERATIONS`)을 씀. 옵션이 없으면 기존 409 |
| `d415e93` | 설치의 `SECRET_STORE_URL`과 같은 Vault/OpenBao 서버 수집 | 기존 비밀 저장소 신원을 같은 주소에만 보내며 토큰을 저장하지 않음. 다른 주소는 요청 없이 실패. 주기 수집 없음 |
| `aaab297` | GCP Secret Manager 두 경로(고객 CLI·schema 2 worker)의 선택 기준 문서·폼 안내 | 계약 변경 없음 |
| `8714a7c` | Azure Blob Storage 콘텐츠 소스, active-scan 부분 인덱스의 종류 목록 기록(`schema_migrations` 7)과 재생성 | worker Azure 신원, 비밀 미저장, ETag `If-Match` 고정 읽기 |
| `1c06fff` | Azure DevOps Repos 콘텐츠 소스 | 암호화 PAT, 기본 브랜치 커밋의 정확한 ref 고정, blob objectId 읽기. Azure DevOps Server·TFVC 미지원 |

배포 시 주의:

- 설치된 active-scan 인덱스는 시작할 때 새 콘텐츠 종류(`azure_blob`·`azure_devops`)를 포함하도록 한 번 재생성된다.
  활성 콘텐츠 스캔이 둘 이상이면 기존과 같이 하나로 줄어들 때까지 미룬다.
- 이번 배치는 탐지 정의와 엔진 epoch를 바꾸지 않았다. 같은 미배포 시리즈의 SAS·이전 형식 Entra 탐지기가 엔진
  digest를 이미 바꿨으므로, 배포 뒤 금고 재수집과 재스캔 전까지 부재 판정은 `UNKNOWN`이다. 그 재스캔에서 서비스
  SAS의 서명 경로 필드도 채워진다.
- 서버 금고 수집은 연결별 opt-in이다. 스캐너 역할(AWS)이나 설치의 비밀 저장소 신원(Vault)에 대상 범위의 값 읽기
  권한을 별도로 부여해야 하며, 권한이 없으면 부분 수집으로 남는다.

실행한 검사(Windows, Python 3.12.9, Node 24.18.0, 로컬 작업 트리, 마지막 커밋 `1c06fff` 기준):

- 수정마다 새 회귀 테스트가 수정 전 실패하고 수정 후 통과함을 확인했다(SAS 워커 경로는 변경을 되돌려 실패 확인).
- 전체 `python -m pytest -q -ra`: **6257 passed, 80 skipped, 278 subtests passed** (691.27초).
  skip은 POSIX private-file 57개, `CREMORE_TEST_POSTGRES_URL` 미설정 21개, POSIX flock 2개다.
- 플랫폼·모든 공급자 backend Ruff 통과(`gcp/standalone`의 기존 17건은 이번 변경과 무관하며 검사 범위 밖).
- 웹: `npx tsc --noEmit`, `npm test` **500 passed**, `npm run build` 통과, `npm run test:browser` **27/27 passed**.

Linux·PostgreSQL·Python 3.14 실행, Docker 이미지·wheel 재빌드, 원격 CI, 실제 공급자 계정(GitHub Enterprise·
GitLab.com·Azure·AWS·Vault) 검증은 포함하지 않는다. PostgreSQL에서의 인덱스 재생성은 SQLite 합성 검사로만 확인했다.

## 추가 🟢·🔵 항목 (2026-09-26 후속)

앞 절 이후 새로 드러난 공백과 남은 🟢·🔵 항목을 구현했다. 🟠(발견 값을 발급처로 보내거나 그 값으로 인증)과
설치·클라우드 계정 설정은 포함하지 않는다.

| 커밋 | 변경 | 경계 |
| --- | --- | --- |
| `7a92471` | Azure DevOps PAT 탐지기 `azure-devops-pat-v1` | Purview 정의의 84자·`AZDO` 서명 형식. 만료된 52자 구형은 제외. 엔진 digest 변경 |
| `7ced8e5` | 설치 자체 Vault/OpenBao 서버 수집의 주기 실행 | 연결의 `schedule_minutes`(5분 이상)와 설치의 스케줄 허용 설정이 모두 필요. 수동 수집도 영수증을 남김 |
| `5c14977` | GitHub Git 이벤트(clone·fetch·push)의 토큰 사용 기록 | REST `include=git`, GitHub의 7일 보존에 맞춘 별도 `git_audit` 작업. 키 digest 요약에만 반영 |
| `1da4105` | Table 서비스 SAS와 구형 서비스 SAS의 서명 키 확인 | 문서의 버전별 형식(Blob 2012-02-12+, Queue·Table 2013-08-15+, Files 2015-02-21+) |
| `6e50de3` | Azure DevOps Server(`base_url`, REST 5.0)와 지정 브랜치 스캔 | Services 주소 고정, 노출 위치에 인스턴스 포함(`INSTANCE_SOURCES`) |
| `fb989d3` | Azure DevOps TFVC 스캔(`AZURE_DEVOPS_TFVC`) | 최신 변경집합에 목록·읽기 고정, 프로젝트 루트 밖 경로는 실패 |
| `dd1765b` | Azure DevOps PAT 발급 목록(schema 2 `azure_devops`) | Graph 사용자→Token Admin. 값·해시가 없어 후보 연결만, 금고 판정 불가 |
| `b426425` | 저장소 비밀 검사에 걸린 새 탐지기 테스트 샘플 수정 | 테스트 URL을 실행 시 조립 |

실행한 검사(Windows, Python 3.12.9, Node 24.18.0, 로컬 작업 트리, 마지막 코드 커밋 `b426425` 기준):

- 새 회귀 테스트는 모두 수정 전 실패와 수정 후 통과를 확인했다.
- 전체 `python -m pytest -q -ra`: **6295 passed, 80 skipped, 278 subtests passed** (840.32초).
  skip은 POSIX private-file 57개, `CREMORE_TEST_POSTGRES_URL` 미설정 21개, POSIX flock 2개다. 첫 실행에서 저장소 비밀 검사가 새 테스트 샘플을 탐지해 `b426425`로 고친 뒤 다시 실행한 결과다.
- 플랫폼·모든 공급자 backend Ruff 통과.
- 웹: `npx tsc --noEmit`, `npm test` **500 passed**, `npm run build` 통과, `npm run test:browser` **27/27 passed**.

Linux·PostgreSQL·Python 3.14 실행, Docker 이미지 재빌드, 원격 CI, 실제 Azure DevOps(Services·Server)·GitHub
Enterprise·Azure Storage·Vault 계정 검증은 포함하지 않는다. TFVC·Token Admin 응답 형식은 공식 REST 문서의 정의로만 맞췄다.

### UI 점검 후속 (2026-09-26)

위 항목과 앞 절의 기능이 화면에 반영됐는지, 웹 전체에서 공급자·소스·자산 유형·자격증명 종류·사유 코드를
나열하거나 표시하는 곳을 백엔드가 내보내는 값과 대조했다. 사유·fact·제한 사항처럼 코드를 그대로 보여 주도록
설계된 목록은 다른 공급자와 같은 방식이므로 그대로 두었다.

| 커밋 | 변경 |
| --- | --- |
| `bd8b440` | GitHub 토큰 사용 기록 안내가 "Git 이벤트 미포함"으로 남아 있던 것을 각 수집 직전 7일의 Git 이벤트 포함으로 고침. 연동 문서에 `git_audit` 행 추가 |
| `e1ee0ea` | 연결 카드·발견·관리 목록 배지에 `azure_blob`·`azure_devops` 코드 대신 공급자 이름 표시 |
| `729173c` | Azure Blob·DevOps 발견의 원본 링크 없음을 "위치 정보 미기록"이 아닌 `SOURCE_LINK_NOT_SUPPORTED`(링크 미제공)로 표시 |
| `53161bb` | Azure DevOps PAT·Azure SAS·Entra client secret 자격증명 종류와 `azure` 공급자 이름, Blob 연결의 "Worker Azure 신원" 표시 |
| `45497d2` | 연결 관리의 신고 폼(목적·신고 환경·인증 방식)을 Azure Blob·DevOps 연결에도 표시 |

남은 차이: Azure Blob·DevOps 발견의 원본 링크는 이 시점에 없었다(아래 후속에서 Azure DevOps Git만 추가).
실행 중인 로컬 Docker 화면은 이 변경 이전 이미지이며, 실제 화면 확인은 재빌드 후에 가능하다.

실행한 검사(Windows, Python 3.12.9, Node 24.18.0, 로컬 작업 트리, 마지막 코드 커밋 `45497d2` 기준):

- 새 회귀 검사는 모두 수정 전 실패와 수정 후 통과를 확인했다.
- 전체 `python -m pytest -q -ra`: **6296 passed, 80 skipped, 278 subtests passed** (789.89초).
  skip 80개는 앞 절과 같은 수이며, 이 Windows 환경에서 실행하지 않는 POSIX 전용 검사와 `CREMORE_TEST_POSTGRES_URL`이 필요한 PostgreSQL 검사다.
- 변경한 Python 파일 Ruff 통과.
- 웹: `npx tsc --noEmit`, `npm test` **501 passed**, `npm run build` 통과, `npm run test:browser` **27/27 passed**.

문서: 루트 README의 지원 소스·schema 2 공급자·금고 보관 대조·사용 순서·개발 설치 extra·릴리스 노트를 현재 코드에 맞췄고,
`azure/README.md`에서 새 절 삽입으로 밀려난 Key Vault 인증 문단을 Key Vault 절로 옮겼으며, `docs/ARCHITECTURE.md`의
소스 목록과 탐지기 수(867)를 고쳤다. 문서의 각 주장은 별도 검토 단계에서 코드와 대조했다.

### GitLab Self-managed 토큰 ID 확인 (2026-09-26 후속)

자체 호스팅 GitLab 소스에서 발견한 GitLab PAT를 **그 소스의 등록된 인스턴스**의
`/api/v4/personal_access_tokens/self`에만 보내 토큰 ID·소유자·scope·만료를 기록한다. GitLab.com 검증과 같은 1회 요청이다.

- 전송 조건
  - 기존 검증 스위치가 켜져 있어야 한다.
  - 주소는 등록된 연결의 `base_url`이다(콘텐츠에서 읽은 URL은 쓰지 않는다). 등록 규칙을 다시 검사하고,
    호스트가 등록된 GitLab 연결의 호스트여야 한다.
  - 리다이렉트는 따르지 않는다. GitLab.com으로는 보내지 않는다.
- 결과
  - 검증되면 `verification_host`를 기록한다.
  - 거절은 `INDETERMINATE`(`REJECTED_ON_SELF_MANAGED_GITLAB_OTHER_HOSTS_UNCHECKED`)다.
  - 원문은 저장하지 않는다.
- 연결
  - `PROVIDER_VERIFIED_TOKEN_ID`는 (검증한 인스턴스, 토큰 ID) 쌍이 발급 항목의 (`instance`, native ID)와 같을 때만 만든다.
  - 호스트 기록이 없는 기존 결과는 GitLab.com으로 취급한다.
  - 소유자 순위도 검증한 호스트의 발급 항목에만 적용한다.
  - 수정 전 연결 코드는 다른 호스트에서 검증된 토큰 ID를 GitLab.com의 같은 번호 토큰에 잘못 연결했다.
    자체 호스팅 검증이 없던 동안에는 드러나지 않았다.
- 남긴 것: GitLab 밖에서 발견한 토큰을 자체 호스팅 인스턴스에 교차 검증하는 경로.
  기존처럼 교차 호스트 검증에서도 GitLab.com만 확인한다.

실행한 검사
- 새 검증기·연결 테스트는 수정 전 코드에서 4개가 실패했다.
- 수정 후 GitLab 관련 16개가 통과했고, `cremore/detection`·연결·finding·수집기·위험도·GitLab·스캔·worker 통합 **3,330 passed**다.

### Azure DevOps 원본 링크 (2026-09-26 후속)

Azure DevOps Git 발견의 원본 링크를 탐지한 커밋에 고정한 파일 보기
(`{인스턴스}/{조직}/{프로젝트}/_git/{저장소}?path=/{경로}&version=GC{커밋}&_a=contents`)로 만든다. Services와
Server(가상 디렉터리·컬렉션 포함) 모두 노출에 기록된 `source_instance`에서 만들며, 웹은 같은 origin·경로 모양·
`GC`+40자 커밋·`path`·`_a=contents` 외의 쿼리가 없는 링크만 연다. Microsoft 문서가 명시하는 것은 브랜치 표기
`version=GB<브랜치>`(기본 브랜치 변경 문서)와 커밋 페이지(Commits REST의 `remoteUrl`)이며, 커밋 표기 `GC`는
공식 문서와 실제 조직에서 확인하지 않았다. 줄 번호 파라미터는 근거가 없어 넣지 않았다. TFVC·Blob은 문서화된
링크 형식이 없어 계속 `SOURCE_LINK_NOT_SUPPORTED`다.

실행한 검사: 새 회귀 검사의 수정 전 실패(서버 1·웹 2)와 수정 후 통과, `cremore/api` **373 passed**,
변경 파일 Ruff, 웹 `npx tsc --noEmit`, `npm test` **502 passed**, `npm run build` 통과, `npm run test:browser` **27/27 passed**.

## Slack 발급 목록 (2026-09-28)

2026-09-22에 Slack 통합(메시지 수집)을 되돌린 뒤, 사용자 결정으로 **발급 목록 수집만** Slack 공식 공개 문서를 근거로 새로
작성했다. 되돌린 GPLv3 브랜치의 코드는 쓰지 않았다. 구현은 [slack/README.md](../slack/README.md), API 근거는
[기술 가능성 10절](PROVIDER_CREDENTIAL_FEASIBILITY.md)에 있다.

- 연결: 조직(`E…`) 또는 워크스페이스(`T…`) ID, 조직 관리자 사용자 토큰(`xoxp-`). 봇 토큰·교체 토큰(`xoxe.`)은 거절한다.
  권한 점검은 `auth.test`(대상 조직 일치), `admin.apps.approved.list`, 감사 로그를 각각 한 번 읽는다.
- 수집: `audit_events`(선택, 최근 90일) → `approved_apps` → `installed_apps`(선택). 승인 앱을 봇 토큰·사용자 토큰·
  수신 웹훅 행(`bot:`·`user:`·`hook:`)으로 나누고, 감사 로그의 위치별 설치·제거로 상태·설치일·설치자를 채운다.
  감사 로그에만 있는 설치 앱도 행으로 남긴다.
- 제약: 승인은 설치가 아니다(감사 로그가 없으면 상태 `UNKNOWN`). 토큰 값·웹훅 URL·사용 기록·만료일은 Slack이 주지 않는다.
  사용자 토큰은 앱 단위 행이다. Enterprise Grid가 아닌 워크스페이스(`team.integrationLogs`)는 구현하지 않았다.
- 등록: `cremore/onboarding/catalog.py` `MODULES`, `cremore/coverage/providers/__init__.py`(`comparison=True`),
  `pyproject.toml` wheel·pytest 경로, Python Dockerfile COPY, 경계 검사 허용 목록, 공통 사실 이름 6개
  (`developer_type`·`is_internal`·`approved_at`·`approved_by`·`last_change`·`last_change_at`).
  콘솔은 전용 UI 없이 카탈로그로 카드(협업 도구)·마법사·메타데이터 현황을 그린다.

실행한 검사
- Slack 전용 12개(합성 MockTransport: 행 분리, 감사 로그 병합·위치별 상태·도착 순서 무관, 워크스페이스 필터, 거절·429 대기·
  감사 실패 시 부분 결과, 재개·중복 방지, 계약 위반 거절, 자격증명 모양 이름 제외, 실행 비교·export, 마법사 토큰·점검·활성화·계획 변경).
- 공급자 매트릭스·경계·온보딩 215개, 웹 `tsc`·`npm test` 552개, `npm run build` 통과.
- 브라우저(개발 API·합성 점검): 협업 도구 카드, 마법사 3단계(봇 토큰 거절 문구 포함)·활성화, 메타데이터 현황의 Slack 3종.
- 백엔드 전체(PostgreSQL 포함): 7,431 passed, 62 skipped, 실패 15개. 실패는 모두 수집기 카탈로그의 등록 순서 검사
  (`cremore/coverage/providers/catalog_test.py`)가 Slack을 몰라서였고, 목록을 고친 뒤 `cremore/coverage/providers`·Slack·
  경계 검사 117개가 통과했다. 이후 감사 로그 병합(위치별 상태·항목별 최신 기준)을 고친 Slack 코드는 전용 12개로 다시 확인했다.
- 실제 Slack 조직·토큰으로의 인증·수집은 하지 않았다(P20과 같음).

## 2026-10-06 GitHub Export 후속 구현 검증

`integration/saas-structure` 미커밋 작업 트리에서 비동기 Enterprise Export·한도 공유·재개·메모리 전용
정규화·권한/주기·관측 행 표시와 노출 접근자 목록의 이어 읽기를 검증했다. 고정 ID 없는 관측은
고유 자격증명 집계에서 제외하지만 정확한 호환 지문으로 기존 노출과 금고 값에 연결한다.
승인 범위 변경·취소·인증 실패를 확인하며 부분 결과를 완전한 접근 목록으로 표시하지 않는다.

범위·실행 로그·실환경 미검증 경계는 [이번 검증 목록](../GATES.md)의 2026-10-06 표를 따른다.
핵심 회귀 722 passed(17 PostgreSQL skip은 별도 실행), PostgreSQL 포함 후속 266 passed,
과거/현재 관측 32 passed, 공급자 경계 73 passed, 웹 275 passed, 브라우저 4/4,
TypeScript/production build·변경 Python Ruff·diff 검사가 통과했다. 서로 겹치는 검사 수다.
실제 GitHub Enterprise API·운영 DB·배포는 이 결과에 포함하지 않는다.

## 2026-10-07 권한 판정 확장 (AWS·GCP·Azure)

발급 목록의 자격증명이 "무엇을 할 수 있는지"를 공급자별 공식 API로 넓혔다. 근거·한계는
[권한 평가의 근거와 한계](PERMISSION_ASSESSMENT.md)를 따른다.

- AWS(6fa2fafe): `*`에서 허용 근거가 없던 작업을 주체 정책에 적힌 리소스 ARN으로 다시 시뮬레이션하고, IAM 사용자는 같은
  계정 S3·Secrets Manager 리소스 정책의 명시적 거부를 반영한다(`assessment_version=3`).
- GCP(4f31bcd5): `effective_access`로 사용자 관리 키가 있는 서비스 계정마다 Policy Troubleshooter v3에 고위험 권한 11개를
  묻는다. 상속·거부 정책·그룹·조건을 Google이 판정하고, 주체 접근 경계는 v3가 평가하지 않는다.
- Azure: `app_permissions`(애플리케이션 권한·Entra 역할)와 `app_azure_roles`(Azure 역할)로 앱 비밀·인증서가 로그인하는
  서비스 주체의 부여 목록을 붙인다. 판정 API가 없어 부여만 읽으며 거부 할당·PIM eligible·그룹으로 받은 Entra 역할은 없다.

검증은 합성 응답·격리 저장소·브라우저 fixture로만 했다. 실제 AWS·Google·Microsoft 계정 호출, 특히 GCP 프로젝트의
`testIamPermissions`가 `iam.denypolicies.*`를 받는지와 Azure 루트 관리 그룹의 `assignedTo` 하위 범위 포함 여부는 미검증이다.
