# 인증 후 수집 범위를 선택하는 온보딩 설계안

2026-10-02 설계, 2026-10-03 구현·검증. 최초 구현은 `integration/saas-structure`의 `a3e4557`이며,
후속 변경과 배포 증거는 아래 실행 기록에 이어 적는다.
아래 **현재 구현 범위**가 완료 범위이며, 뒤의 설계·가능성 표는 전체 목표와 제약을 설명한다.
실제 고객 계정의 권한이나 제품별 API 응답을 검증한 결과는 아니다. 코드 검증과 팀 서버 배포는 아래 실행 기록에서 구분한다.

## 현재 구현 범위

공통 흐름은 인증 → 기능 선택 → 권한 확인 → 수집 범위 → 최종 확인·저장이다.
기능 선택의 하단 버튼으로 계정·조직을 조회하고, 권한 단계에서 대상·옵션을 정한 뒤 하단 `권한 확인·다음`을 누른다.
필수 권한과 리소스 목록 조회가 성공하면 범위 선택으로 이동한다. 거절·미확인·조회 실패는 현재 단계에서
설명하고 재시도한다. 별도의 본문 내 점검 버튼은 없다. 새로고침 시에도 서버의 점검·범위 승인 상태에 맞춰 복원한다.
인증 초안은 실제 연결과 분리하며 선택 전 콘텐츠 스캔을 시작하지 않는다. 필수 권한의 거절·미확인은 다음 단계에서 서버가 차단한다.
권한이 선택한 기능·대상에 종속되면 그 선택 뒤 검사하며, 모든 기능의 권한을 인증 전에 요구하지 않는다.

| 공급자 | 새 흐름의 인증·대상 | 기존 설정을 유지하는 경로 |
| --- | --- | --- |
| AWS | 승인된 서버 workload → 현재 계정 또는 Organizations 계정 목록 → 선택 계정 scanner 역할·리전·S3 버킷 | OIDC 신뢰·scanner 역할·ExternalId 배포는 사전 준비. 개인 SSO·customer CLI는 신규 연결에서 제외 |
| GitHub | App 만들기·설치 → 설치된 조직 다중 선택, classic PAT 조직 목록. Enterprise 소유 App은 기존 일괄 설치 흐름 연결 | fine-grained PAT 조직 자동 발견 미지원. Enterprise 일괄 설치는 enterprise 설치·관리 권한 필요 |
| GitLab | token 신원 → 그룹·프로젝트, 여러 root를 한 소유자에 저장 | 별도 공급자 인증 설정이 필요한 경로 |
| Notion | 일반 integration의 워크스페이스 → 공유 페이지·DB 행 | Enterprise 조직 봇·발급/PAT/MCP 목록 경로 |
| GCP | Worker ADC·Google OAuth → 프로젝트, 콘텐츠는 기존 Storage 목록 helper | 조직/폴더 관리용 별도 설정. customer CLI는 신규 연결에서 제외 |
| Microsoft | 인증서·workload identity → tenant·구독·Storage·Key Vault. DevOps PAT → 지정 조직/컬렉션의 프로젝트 | 한 tenant 신원으로 임의 tenant 전체를 찾지 않음. DevOps 조직/Server 주소는 인증 접속 정보로 필요 |
| Okta / Keycloak | 생성키·private key JWT의 Okta 조직 / OAuth client의 설정된 realm | 인증에 필요한 앱·서버·realm 준비는 사용자 설정 |
| Google Workspace | 서비스 계정 위임·도메인 관리자 인증 → 해당 도메인 | 도메인 위임 설정 자체는 사용자 설정 |
| Slack | `auth.test` → Enterprise 및 `admin.teams.list`의 workspace 다중 선택·개별 소속/권한 검사 | workspace 발견에 조직 설치 앱의 `admin.teams:read` 필요. 메시지 수집은 미지원 |
| Vault / OpenBao | token·Kubernetes·JWT → KV mount, private CA 지원. metadata/data capability 별도 검사 | 서버 주소·namespace·인증 role·JWT 파일 이름은 인증 접속 정보. customer CLI는 신규 연결에서 제외 |
| Atlassian | Confluence Cloud/DC token·서비스 계정 OAuth → space. Bitbucket Cloud 사용자/workspace token, DC 서비스 사용자 HTTP token → workspace/project. 조직 API key → 조직 | workspace token은 해당 workspace만 접근. DC 프로젝트/저장소 전용 토큰은 사용자 전체 목록을 제공하지 않음. 주소·workspace bootstrap 유지 |

자동 목록을 제공하지 않는 방식은 같은 설정 과정에서 기존 설정 단계를 사용하고 필요한 입력을 명시한다. 서버 주소·도메인·tenant·앱 등록처럼 인증에 필요한 정보는 여전히 필요하다.
GitHub fine-grained PAT의 빈 조직 응답을 대상 없음으로 해석하지 않고 미지원 사유를 표시한다.
Notion 조치의 실제 revoke 권한, GitLab 선택적 self-rotate, customer CLI 업로더의 서버 미보유 권한은
descriptor에서 비필수로 선언한다. 미확인을 GRANTED로 바꾸지 않으며 실행 시 기존 승인·권한 계약을 따른다.

값 읽기 권한을 안전한 사전 API로 확인하지 못하는 경우는 미확인으로 차단한다. 현재 AWS 서버 금고의
Secrets Manager·SSM 값 읽기 신규 활성화와 Azure의 Key Vault 값 읽기·Storage listKeys 옵션이 해당한다.
AWS customer CLI 업로드 경로는 유지하며, Azure는 값 읽기 옵션을 끄면 메타데이터를 연결할 수 있다.
기존 활성 연결을 이 검사만으로 중지하지 않는다. GCP는 `testIamPermissions`로 실제 켜질 값 읽기 권한을
확인한다. 목록 조회·IAM 정책 시뮬레이션 결과는 리소스 정책·조건·KMS·모든 하위 객체의 실제 접근을
보장하지 않으므로 실행 시 권한 검증과 부분 수집 근거도 유지한다.

공통 구현은 `cremore/onboarding/sessions.py`, `session_store.py`, `targets.py`, `permissions.py`와
`web/console/views/integrations/auth-first.tsx`다. 기존 `provider-check`, catalog helper, Menu·Modal·MultiSelectField를 재사용한다.
AWS 인증 단계는 서버 신원을 표시하고, 미승인·변경된 신원은 관리자가 `신원 승인·인증 확인`으로 먼저 승인한다.
기존 scanner-identity API의 API·Worker 동일 신원 검사를 유지하며 승인 실패 시 초안을 만들지 않는다. 재승인 후에는 이전 승인 revision에 묶인 초안을 재사용하지 않는다.
API·워커는 각각 같은 SDK 세션으로 역할 신원과 자격증명 갱신 출처(`credential_source`)를 확인한다. 워커는 이 출처를 인증 검사와 상태 보고에도 전달한다. 역할 ARN만으로 무인 갱신을 인정하지 않으며, 실제 `build_worker`와 작업 처리 경로를 쓰는 CLI 회귀 검사에서 두 AWS 방식의 허용·거절을 확인한다.
신원이 없는 서버는 실행 위치별 초기 설정 안내를 먼저 표시하며, 회사 IdP 설정을 닫아도 연동 입력을 유지한다.
역할 ARN은 기존 IAM 조회로 자동 확인하고, 조회 권한이 없으면 자기 역할 조회 정책을 안내한다. 직접 입력은 고급 설정이다([서버 신원 설정](MACHINE_IDENTITY.md)).
드롭다운은 화면을 밀지 않는 레이어이며 검색·모두 선택/해제·200개씩 표시를 지원한다. 기존 연결도 같은 인증으로 기능 추가·대상 추가/제외가 가능하다.
기존 대상의 세부 범위·제외·실행 설정을 보존한다. 다중 scope profile 또는 조회되지 않은 기존 항목은 기존 검사 대상 편집기로 안내한다.

- 초안·권한 근거는 30분, 관리자 subject·브라우저 키와 revision에 결합한다. 브라우저에는 초안 ID·바인딩만 저장한다.
- 조회 작업은 요청마다 취소·fencing을 확인하며 한 실행 100회·120초다. root 목록 최대 10,000개, 선택 root 최대 100개다.
- root는 공급자 cursor로 이어 읽는다. 콘텐츠 목록은 기존 catalog의 제한·부분 상태를 사용하며 가지별 무제한 이어 읽기는 추가하지 않았다.
- v1 단일 target은 그대로 읽고, v2는 명시적 `roots`와 선택적 기능별 `purposes`를 가진다. 인증정보 갱신은 소유자에서 한 번만 한다.
- 최종 확정은 연결·자식·catalog·승인 scope·감사·초안 참조 이전을 한 트랜잭션에 저장한다. 동시 확정은 같은 결과를 반환하고 scope 변경은 CAS로 보호한다.
- 제거한 대상은 이력을 유지하고 갱신·전체 재개·늦은 인증 검사로 재활성화하지 않는다. 원문 수집값은 저장하지 않는다.

실행 검증과 미검증 조건은 이 문서의 마지막 검증 기록을 따른다. fake 기반 기능 검증과 운영 배포 확인을 구분한다.

목표는 **서비스 선택 → 인증 → 사용할 기능 선택과 목록 권한 확인 → 수집 범위 선택과 권한 확인 → 검토·시작**이다.
발급 목록 수집·평문 노출 검사·Secret 저장소 대조·사람 목록·승인된 조치 실행 카드도 인증 뒤에 설정한다.
계정 ID·프로젝트 ID·스페이스 키를 사용자가 찾아 적는 과정을 지원 가능한 인증 경로에서 없앤다.
인증 성공만으로 다음 단계나 수집 시작을 허용하지 않는다. 해당 단계에 필요한 권한이 부족하거나 확인되지 않으면 이유와 해결 방법을 먼저 보여 준다.

대부분의 공급자에 적용할 수 있지만, 모든 인증 방식에서 모든 대상을 자동으로 찾을 수 있는 것은 아니다.
사설 서버 주소, OAuth 앱 등록, 위임할 도메인, AWS 역할 신뢰 설정처럼 인증을 성립시키는 정보·설정은 필요할 수 있다.
공급자가 목록을 제공하지 않는 경로를 수동 ID 입력으로 대체하고 자동 온보딩이 완성됐다고 표시하지 않는다.

## 여러 인증이 필요한 기능을 한 번에 설정하기

2026-10-03 후속 수정은 기능 선택을 한 인증 방식의 교집합으로 제한하던 화면을 바꾼다.
인증 뒤 공급자의 지원 기능을 함께 선택하고, 같은 인증으로 가능한 기능은 함께 점검한다.
다른 인증이나 별도 조치 신원이 필요한 기능은 같은 설정 과정의 후속 단계에서 인증한다.
서버의 자격증명 소유자는 계속 분리된다. 한 화면에서 설정한다는 이유로 수집 토큰을 조치 토큰으로 복사하지 않는다.
중간에 취소하면 이미 저장한 기능은 유지하고 아직 마치지 않은 기능을 구분한다.

GitHub는 인증 화면에서 App 만들기·설치를 시작할 수 있다. 설치 권한은 사용자가 선택하며,
실제 수집 기능·대상 선택 및 권한 검증은 설치 뒤 수행한다. App 키는 기존 서버 교환·봉인 경로를 사용한다.
조치용 App은 별도 설치이고 조직 PAT 접근 철회에 필요한 쓰기 권한을 명시한다. 읽기 전용 App과 혼합하지 않는다.

| 공급자 | 같은 인증으로 가능한 기능 | 별도 인증·제품 조건 |
| --- | --- | --- |
| GitHub | App: 노출·발급·Actions secrets 메타데이터·조직의 사람(GitHub.com·Enterprise Cloud, Members 읽기), classic PAT: 노출·사람 | 엔터프라이즈 사람 목록과 GHE.com·Server는 소유자 classic PAT(2026-10-08), 감사 로그는 별도 읽기 토큰. 조치는 별도 App. Enterprise API 조건 유지 |
| GitLab | token: 노출·발급·금고 메타데이터 | 조치는 별도 인증. 인스턴스 목록은 관리자·판 조건 유지 |
| Notion | integration: 페이지 노출 검사 | Enterprise 조직 봇: PAT·MCP 발급 목록. 조치는 별도 인증. 봇의 workspace UUID 자동 열거 미지원 |
| Confluence / Bitbucket / Atlassian | Confluence: 노출, Bitbucket: 노출·발급 | Atlassian 조직 발급 목록은 별도 조직 API key. Cloud/DC의 인증·API 차이 유지 |
| AWS | scanner 역할·서버 workload: 노출·발급·금고 | 조치는 기존 별도 승인 역할. SSO·고객 CLI는 기존 연결 호환만 유지 |
| GCP | ADC·Google OAuth: 노출·발급·금고 | 조치는 별도 인증. Workspace 사람 목록은 도메인 위임 인증. 프로젝트와 조직/폴더 발견은 구분 |
| Azure | 앱 인증서·workload identity: 노출·발급·금고·사람 | Azure DevOps는 별도 PAT. Server는 노출, Cloud는 지원 발급·별도 조치 추가 |
| Vault / OpenBao / 외부 금고 | 금고 대조 | Vault/OpenBao는 token·Kubernetes·JWT 서버 수집. 외부 금고 JSONL/reader 제출은 별도 근거 계약 |
| Okta / Keycloak / Google Workspace | 사람 목록과 지원 앱 목록 옵션 | 로그인 IdP 일치·조직/realm/도메인 제약 유지. 일반 콘텐츠 검사 기능은 없음 |
| Slack | Enterprise Grid 앱 발급 목록 | 메시지 콘텐츠 수집기는 현재 없음. 기능 선택 변경으로 새 수집기가 생기지 않음 |
| 웹사이트 | 확인된 회사 도메인의 노출 검사 | 공급자 인증 대신 도메인 확인·승인된 주소 범위를 사용 |

Enterprise 여부는 일반 콘텐츠 검사를 금지하는 조건이 아니다. 해당 콘텐츠 수집기를 제공하는 공급자는
추가 발급·사람·조치 기능과 함께 설정할 수 있다. API가 공개하지 않는 목록이나 지원하지 않는 기능은
추가 토큰만 입력하면 동작하는 것으로 표시하지 않는다.

## 설치 장소와 무인 인증

AWS는 테스트 배포 장소이며 제품의 필수 호스팅 환경이 아니다. 회사 VM·물리 서버·Kubernetes의
API·worker·DB·웹도 같은 제품을 실행한다. 회사 인프라에서 AWS를 수집할 때도 사람이 `aws sso login`을
반복하지 않는다. 기존 [기계 신원](MACHINE_IDENTITY.md)의 OIDC/JWT 갱신과 SDK의
`AssumeRoleWithWebIdentity` → 선택 계정 `AssumeRole`을 사용한다. EC2 역할·container role도 같은
서버 신원 계약이며, 설치 호스트가 아니라 검증된 인증 출처와 대상 계정 권한을 검사한다.
Organizations 조회가 거절되거나 조직에 속하지 않은 경우, OU 제한이나 이어받기 cursor가 없는 첫 조회에만
서버 자신의 계정과 활성 ROLE 등록 계정을 부분 목록으로 제공한다. 제외 계정·조직 중지 상태는 유지하며
각 계정의 STS 역할 접근 증명 전에는 등록하지 않는다. 새 계정의 ExternalId는 초안에서 생성·고정하고
현재 승인 신원을 신뢰하는 CloudFormation 설정값을 선택 계정별로 안내한다. 이미 배포된 역할은 신뢰 대상과
ExternalId를 비교하며, 기존 역할의 경로를 추측하거나 새 역할로 교체하지 않는다.
금고 값 읽기의 필수 권한은 여전히 사전 점검으로 입증되지 않으면 차단한다. 목록 조회나 IAM 시뮬레이션을
값 읽기/KMS 복호화의 실제 권한으로 승격하지 않는다.

Organizations 밖의 다른 독립 AWS 계정은 목록 자동 발견을 가장하지 않는다. 인증 화면의 기존 설정 경로에서
계정·scanner 역할의 신뢰를 직접 준비하고 같은 서버 신원으로 연결할 수 있다. 이 경로에는 Organizations
조회 권한이 필요하지 않으며 계정마다 서버 로그인 신원을 바꾸지 않는다.

| 공급자/경로 | 무인 수집 인증과 남는 자격증명 | 인증 외에 필요한 접속·권한 조건 |
| --- | --- | --- |
| AWS | EC2/container/web identity 또는 고정 Roles Anywhere 브리지의 자동 갱신 STS. 고정 AWS 키 불필요 | 사내 OIDC/PKI 발급·갱신·AWS 신뢰, 계정별 scanner 역할·ExternalId. 임의 credential_process는 거절. [무인 운영 설정·검증 범위](UNATTENDED_DEPLOYMENT.md) 참고 |
| GCP | workload ADC/WIF 우선. Google OAuth는 봉인 refresh token으로 access token 갱신 | 프로젝트 권한·OAuth 앱 설정. ADC 파일 자체가 단기 workload인지 개인/키 기반인지는 배포 책임 |
| Azure / Entra | workload federation 우선. 대안 앱 인증서는 봉인하고 기존 갱신 계약 사용 | tenant 및 앱 신뢰·Graph/ARM 권한. Entra 단독 기존 연결도 보존 |
| GitHub | App 설치 access token 자동 발급. App 개인 키는 봉인 보관 | App 설치·선택 조직 권한. classic PAT 필요 기능은 별도 봉인 토큰 |
| GitLab | 봉인 토큰, 지원·선택한 self-rotate만 자동 교체 | 서버·토큰 scope. 모든 토큰을 자동 갱신한다고 표시하지 않음 |
| Notion | integration 또는 Enterprise 조직 봇 토큰 봉인 | 공유 페이지 권한 또는 workspace UUID·Admin API. 일반 workspace 열거 API가 없어 Enterprise 범위를 추정하지 않음 |
| Confluence | 서비스 계정 OAuth access token 갱신 또는 봉인 API/PAT | 사이트·Cloud ID/서버 정보와 읽기 scope |
| Bitbucket | 봉인 workspace/API/DC HTTP token | 토큰에 묶인 workspace/서버·권한. 사용자 토큰과 workspace 토큰의 API 차이 유지 |
| Atlassian | 봉인 조직 API key | 조직 관리 범위·만료 전 교체 |
| Azure DevOps | 봉인 PAT | 조직/컬렉션 주소·기능별 scope·만료 전 교체 |
| Slack | 조직 관리자 앱의 봉인 user token | Enterprise Grid·조직 설치·관리 scope. 12시간 rotating token은 refresh 흐름 미구현으로 명확히 거절 |
| Vault / OpenBao | Kubernetes·JWT 로그인과 토큰 갱신 우선, 대안 봉인 token | 연결별 주소·role·namespace·CA·갱신되는 JWT 파일. 설치용 금고 신원과 수집용 금고 신원을 섞지 않음 |
| Google Workspace | 도메인 위임 서비스 계정으로 단기 토큰 발급, 필요한 개인 키 봉인 | 도메인 관리자 위임·허용 scope |
| Okta | 서비스 앱 private key JWT로 단기 access token 발급, 앱 키 봉인 | 조직 주소·앱 등록·관리 scope |
| Keycloak | 서비스 계정 client credentials로 access token 갱신, client secret 봉인 | 서버·realm·관리 권한 |
| 외부 금고 | JSONL/reader의 기존 제출 인증 | 외부 수집기를 지속 실행할 책임은 배포자에게 있음. 서버 자동 수집으로 표시하지 않음 |
| 웹사이트 | 공급자 로그인 불필요 | 확인된 회사 도메인과 명시적 주소/검사 범위 승인 |

`new_setup: false`인 인증은 신규 연결과 다른 방법에서의 전환을 API도 거절한다.
기존 연결의 같은 인증정보 교체·중지·유지보수는 보존하며, 기존 SSO/CLI 연결을 자동 삭제·이관하지 않는다.
상시 운영은 credential 자동 갱신뿐 아니라 worker·scheduler 실행, 공급자까지의 HTTPS 통신,
IdP 발급/신뢰·필수 권한·만료 전 교체와 장애 감시가 모두 필요하다. 사내 완전 폐쇄망에서 외부 SaaS를
연결 없이 읽을 수 있다는 의미는 아니다. 실계정 24시간 연속 운전은 별도 운영 검증이다.

연결 인증정보는 기존 `secretstore/sealed.py`의 AES-256-GCM·nonce·인증된 키 식별자·키 교체를 재사용한다.
AWS KMS는 선택 사항이며 사내 Vault/OpenBao의 봉인 마스터도 지원한다. 마스터와 DB/백업 접근을 분리하고
권한을 제한한다. 설정된 KMS/Vault가 실패하면 평문 저장이나 다른 키로 자동 우회하지 않는다.
이 계약은 연결 인증정보에만 적용한다. **수집·탐지한 비밀 원문은 복구 가능한 암호문을 포함해 저장하지 않는다.**

## 사용자가 보게 될 흐름

| 단계 | 화면과 사용자 동작 | 다음 단계 조건 |
| --- | --- | --- |
| 1 서비스와 인증 | 제품·판·인증 방식 선택 후 로그인 또는 토큰·앱 인증. 필요한 접속 정보만 입력. 확인된 계정·조직 표시 | 신원·접속 대상과 인증 확인에 필요한 최소 권한 확인 완료. 수집 기능을 미리 선택하지 않음 |
| 2 사용할 기능 | 인증 결과를 바탕으로 발급 목록·노출 검사·금고 대조·사람 목록·조치 카드를 표시하고 사용자 선택 | 선택한 기능이 현재 판·인증 방식·신원에서 지원되고 범위 목록 조회에 필요한 권한 확인 완료 |
| 3 수집 범위 | 선택한 기능의 계정·조직 → 프로젝트·리전 → 저장소·페이지 목록에서 체크. 수집 옵션도 여기서 선택 | 선택한 대상·옵션에 필요한 권한 점검 완료 |
| 4 검토와 시작 | 선택 범위·기능·주기·값 읽기 여부·추가/제외 내용을 검토하고 저장 또는 시작 | 서버가 최신 인증·목록·권한·범위 버전을 다시 확인하고 원자적으로 확정 |

예를 들어 AWS는 인증한 계정 또는 접근 가능한 계정 목록을 보여 주고, 그 안에서 활성 리전·버킷과 수집 기능을 고른다.
Notion 개인 연결은 토큰의 워크스페이스를 확인하고 **그 연결에 공유된 페이지**를 고른다.
GitHub App은 확인된 설치의 조직·저장소를 보여 준다. 목록 조회만으로 App 설치 범위를 확대하지 않는다.
한 대상만 확인되면 자동으로 표시하되, 하위 콘텐츠 전체나 값 읽기를 자동 승인하지 않는다.

기능 카드에는 `사용 가능`, `권한 추가 필요`, `대상 선택 후 확인`, `현재 인증 방식으로 미지원`, `제품 조건 미충족`을 구별해 표시한다.
권한 부족 카드를 이유 없이 회색으로만 막지 않는다. 필요한 권한과 보완 방법을 열어 볼 수 있고, 보완 후 같은 화면에서 재확인할 수 있어야 한다.
아직 대상이 없어 확인할 수 없는 수집 권한은 `대상 선택 후 확인`으로 표시하며, 범위 선택 뒤 검토 화면에 넘어가기 전에 점검한다.
인증 직후 어떤 수집 기능도 자동 활성화하지 않는다. 지원 기능 표시가 그 기능의 실제 권한 확인 완료를 뜻하지 않는다.

인증 방식 선택 화면에는 각 방식으로 지원할 수 있는 기능을 설명만 한다. 기능 체크를 인증의 선행 조건으로 두지 않는다.
OAuth 동의·앱 설치에 권한 선언이 필요한 경우 최초에는 인증 확인에 필요한 최소 권한을 사용하고,
기능 선택 후 추가 권한 동의·앱 설정 변경이 필요하면 선택을 유지한 채 그 절차로 이어 준다.
공급자가 추가 동의를 지원하지 않으면 해당 기능에 필요한 권한을 갖춘 토큰·앱으로 교체하도록 안내한다.
이를 피하려고 처음부터 모든 기능의 권한을 요청하거나 서로 다른 인증 방식의 기능을 한 인증으로 제공한다고 표시하지 않는다.
GitHub App manifest의 권한과 GCP OAuth의 요청 scope도 이 두 시점에 맞게 조정해야 한다.

`승인된 조치 실행` 선택도 인증 뒤에 제공하지만, 수집 연결과 별도 인증 연결이어야 한다는 계약은 유지한다.
현재 수집 인증을 조치용으로 자동 복사하거나 권한을 확대하지 않는다. 별도 조치 연결이 필요하면 카드에서 이유와 설정 경로를 안내한다.
`사람 목록`은 인증 후 확인한 신원과 팀 로그인 IdP 조건을 함께 보여 준다.

목록은 검색·계층형 체크박스·다중 선택을 기본으로 한다. 짧고 정해진 선택지는 드롭다운으로 제공한다.
`조회된 항목 모두 선택`과 `모두 해제`, 선택 수, 조회 진행 상태를 제공한다. 수천 개 항목을 한 드롭다운에 넣지 않는다.
드롭다운과 상세 패널은 기존 `Menu`·`Drawer` 레이어를 사용해 본문을 밀지 않고, 화면 경계·스크롤·키보드·초점 복귀를 처리한다.
한국어/영어와 밝은/어두운 테마를 유지한다. 사용자 화면에 JSON이나 내부 API 필드를 입력시키지 않는다.

## 권한 부족을 단계 이동 전에 처리

인증, 목록 조회, 수집 권한은 각각 다른 근거다. 로그인 성공, 토큰의 scope 문자열, 목록 API 하나의 성공으로 나머지를 통과시키지 않는다.
[check.py](../cremore/onboarding/check.py)는 `GRANTED`, `MISSING`, `NOT_REPORTED`, `ERROR`를 구분하며,
[permissions.py](../cremore/onboarding/permissions.py)는 [service.activate](../cremore/onboarding/service.py)를 포함한
신규·확대 경로에서 단계별 필수 항목을 판정한다. 버튼 비활성화만으로 구현하지 않는다.

| 검사 시점 | 확인할 항목 | 실패했을 때 |
| --- | --- | --- |
| 인증 후 기능 화면에 들어가기 전 | 인증 신원·대상 서버 일치와 최소 인증 확인 권한. 이 시점에는 수집 기능 미선택 | 인증 실패·최소 확인 권한 부족이면 진행 차단. 아직 선택하지 않은 수집 기능의 권한은 요구하지 않음 |
| 기능 선택 후 범위 화면에 들어가기 전 | 선택 기능의 계정/조직 등 상위 목록 권한. 대상 없이 확인 가능한 필수 수집 권한도 함께 점검 | 부족한 권한·영향받는 기능·공급자 설정 방법·재확인 버튼 표시. 필수 항목이 남아 있으면 다음 단계 차단 |
| 범위 화면에서 대상·옵션을 고를 때 | 해당 대상의 하위 목록과 실제 사용할 수집 API 권한. 값 읽기·감사 로그 등 선택 옵션은 선택했을 때만 | 실패한 대상/기능을 표시. 사용자에게 권한 보완 또는 해당 선택 제외를 제공하고 자동 제외하지 않음 |
| 검토 화면의 저장·시작 | 선택 전체의 최신 권한 근거, 인증 revision, 목록 snapshot, 선택·계획 digest와 기존 승인 조건 | 오래된 결과면 재확인. 필수 권한 부족·미확인은 활성화 거절. 재시도해도 중복 연결이나 반쪽 승인이 생기지 않음 |

권한 오류 화면에는 다음을 함께 보여 준다. 예시는 설계용이며 현재 계정에 실제로 부족하다는 뜻이 아니다.

| 표시 | 예시 |
| --- | --- |
| 인증 결과 | AWS 인증은 성공했습니다 |
| 부족한 작업 | `ec2:DescribeRegions` |
| 영향 | 활성 리전 목록을 불러올 수 없습니다 |
| 대상과 근거 | 선택한 계정 / 리전 조회 API에서 AccessDenied / 확인 시각 |
| 해결 | 연결 역할에 이 작업의 조회 권한을 허용한 뒤 다시 확인하세요 |
| 동작 | 권한 설정 안내, 다시 확인. 해결 전 다음 단계 차단 |

단순한 403으로 정확한 정책 원인까지 알 수 있는 것은 아니다. IAM 정책·SCP·권한 경계·조건·앱 승인·리소스 공유·제품 라이선스를 구별할 근거가 없으면
`이 API 조회가 거절됨, 원인 정책은 확인되지 않음`이라고 적는다. 실제 확인한 작업명과 가능한 해결 절차를 제공하고, 특정 정책이 빠졌다고 추측하지 않는다.
네트워크 오류·만료·호출 제한은 권한 부족과 별도로 표시한다. 재인증 또는 재시도할 문제를 권한 추가로 안내하지 않는다.

기존 상태 네 가지를 재사용하고 결과에 단계, 대상, 기능/옵션, 검사한 작업, 근거 종류, 확인 시각, 안전한 사유 코드를 붙인다.
`GRANTED`는 그 검사 범위의 근거이고, 정책 선언·capability 조회·실제 API 성공은 구분한다.
`NOT_REPORTED`와 `ERROR`는 필수 권한 통과가 아니다. 선택하지 않은 옵션의 권한은 해당 판정에서 제외한다.
필수인 값을 읽거나 변경해야만 권한을 입증할 수 있고 안전한 권한 조회도 없다면, 확인 완료로 꾸미지 않고 해당 기능을 비활성 초안으로 남긴다.
이 제약으로 자동 설정을 제공할 수 없는 인증 방식은 별도로 표시한다. 권한 확인을 위해 비밀값 읽기·키 폐기·리소스 생성 같은 시험 동작을 하지 않는다.

가능한 경우 공급자의 안전한 권한 조회를 사용한다. 예를 들어 Vault는 `/sys/capabilities-self`로 선택한 경로의 capability를 확인할 수 있다.
목록 조회 성공만으로 값 읽기까지 승인하지 않는다. AWS 정책 시뮬레이션도 조건·리소스 정책·조직 정책까지 포함한 모든 실제 접근을 보장하는 근거로 표시하지 않는다.
온보딩 이후 권한이 바뀔 수 있으므로 수집기의 실행 시 검증과 실패 처리는 그대로 유지한다.

## 공급자별 적용 가능성과 제약

`가능`은 해당 API 경로로 구현할 수 있다는 의미다. 현재 마법사에 구현됐거나 모든 판·토큰 조합을 실환경 검증했다는 뜻은 아니다.
`조건부`는 인증 방식·상위 설치 정보·추가 목록 권한이 필요하다는 뜻이고, `보류`는 자동 열거의 근거가 부족한 경로다.
각 판의 기존 콘텐츠/인벤토리/IdP 지원 범위를 확대한다고 가정하지 않는다.

| 공급자와 인증 경로 | 인증 후 선택할 목록 | 판정과 필요한 작업 |
| --- | --- | --- |
| AWS 설치 신원 | STS로 확인한 자기 계정 → 활성 리전·S3 버킷·지원 수집 기능 | **가능.** `GetCallerIdentity`는 신원만 확인하며 모든 계정·수집 권한을 주지 않음. 활성 리전 조회 거절을 기본 리전 전체 접근 가능으로 바꾸지 않음 [1] |
| AWS Identity Center·Organizations | 사용자에게 배정된 계정 또는 조회 가능한 조직 계정 → 계정별 역할 → 하위 대상 | **조건부.** 계정 목록과 각 scanner 역할 접근을 따로 확인. Organizations 목록은 계정 접근 승인이 아님. 팀 설치의 로컬 전용 SSO 로그인 금지를 유지 [1] |
| AWS 직접 멤버 역할 | 설치 과정에서 확인한 계정·역할 → 하위 대상 | **조건부.** 임의 외부 계정 역할을 토큰만으로 찾을 수 없음. 역할 설치 결과로 계정 ID·역할 ARN·ExternalId를 전달받는 설정 도우미 필요. 이 설치 경로 없이는 무입력 연결 완료를 약속하지 않음 |
| GitHub App | 인증된 설치 → 조직·허용된 저장소 | **가능.** 기존 App 설치 흐름과 저장소 catalog 재사용. 설치 목록/권한과 사용자가 관리할 수 있는 설치를 대조하며 비공개 키 소유만으로 임의 설치 접근을 허용하지 않음 [2] |
| GitHub PAT·Enterprise | 토큰 종류에 맞게 확인한 조직·저장소, 지원되는 신원 수집 대상 | **조건부.** classic/fine-grained PAT의 목록 API 지원·owner 권한·SSO 승인을 구별. GHE.com/Server의 주소는 필요. 엔터프라이즈 상위 목록을 모든 PAT에서 열거할 수 있다고 가정하지 않음. GHE.com IdP의 enterprise 필수 조건 유지 [2] |
| GitLab Cloud·Self-Managed·Dedicated | 보이는 그룹·프로젝트 → 저장소·기능 | **가능/조건부.** 그룹 목록 API가 존재. 토큰별 범위와 `read_api` 등 실제 작업 권한을 점검. 사설 서버 주소는 필요하고 인스턴스 전체 발급 목록은 관리자·지원 판 조건을 유지 [3] |
| Notion 일반 페이지 검사 | 토큰의 워크스페이스 → 공유된 페이지·데이터 소스와 지원 하위 항목 | **가능.** bot 응답의 workspace 정보와 기존 search/catalog 재사용. 읽기 capability와 공유 범위를 구별하고 검색 결과를 워크스페이스 전체 페이지로 표현하지 않음. PAT의 사용자 응답을 bot 응답과 동일시하지 않음 [4] |
| Notion Enterprise PAT·MCP 목록 | 조직 봇이 접근하는 워크스페이스 → 선택한 발급 유형 | **보류.** 공개 Admin OpenAPI에서 일반적인 전체 워크스페이스 목록 API를 확인하지 못함. legal hold에 속한 워크스페이스 목록은 대체 근거가 아님. 검증 가능한 설치 정보 또는 공식 일반 목록 API가 필요. 별도 내부 통합 토큰의 workspace를 조직 봇의 권한 근거로 사용하지 않음 [4] |
| Confluence Cloud | 인증한 사이트 → 볼 수 있는 스페이스 → 페이지 | **가능.** space 목록과 `read:space:confluence` 등 인증 방식별 권한 연결. 현재 서비스 계정 OAuth와 토큰 인증을 유지. 사이트 주소를 자동 획득할 수 없는 방식에는 인증 접속 정보가 필요 [5] |
| Confluence Data Center | 서버 → 스페이스 → 페이지 | **조건부.** 기존 지정 공간 수집 앞에 공간 목록 추가. 설치 버전·인증 방식별 REST 계약 검증 필요. Cloud endpoint를 그대로 사용하지 않음 |
| Bitbucket Cloud | 사용자 토큰이 접근하는 워크스페이스 → 저장소 | **가능.** workspace 목록 API 사용. OAuth `account`와 API token `read:workspace:bitbucket` 등 인증 방식별 요구를 구별 [6] |
| Bitbucket Data Center | 서버 → 프로젝트 → 저장소 | **조건부.** 현재 지정 프로젝트 경로 앞에 프로젝트 목록 추가. 설치 버전별 API·프로젝트 권한을 추가 검증 |
| Atlassian 조직 | 조직 관리 API 키가 볼 수 있는 조직 → 지원 발급 유형 | **가능.** `/admin/v1/orgs` 공식 목록 API 확인. 콘텐츠 토큰과 조직 관리 API 키의 권한을 혼동하지 않음 [7] |
| GCP Google OAuth·ADC·workload identity | 접근 가능한 프로젝트, 지원 조직/폴더 → 버킷·수집 기능 | **가능/조건부.** 기존 OAuth 프로젝트 목록을 마법사에 연결하고 다른 인증도 같은 선택 흐름에 통합. `projects.search`는 `resourcemanager.projects.get`이 있는 프로젝트를 반환하며 결과가 지연될 수 있음. 조직·폴더 열거는 별도 권한이고 하위 수집 승인이 아님 [8] |
| Microsoft Azure 앱 인증서·workload identity | 인증한 tenant → 구독 → Storage Account·Key Vault → 컨테이너 | **가능/조건부.** ARM 목록 재사용. tenant/client 설정이나 관리자 동의는 인증 준비. ARM 조회 성공이 Blob·Key Vault 데이터 읽기를 보장하지 않음. Graph의 앱·사람 목록은 별도 권한과 목적 [9] |
| Azure DevOps Services | 확인한 조직 → 프로젝트 → Git·TFVC 등 지원 콘텐츠 | **조건부.** 프로젝트 목록 API 존재. Accounts API는 owner/member ID와 인증 방식 조건이 있으므로 모든 PAT·서비스 주체에서 조직 자동 열거가 된다고 가정하지 않음. 조직 설치 컨텍스트 또는 검증된 계정 조회 경로 필요 [10] |
| Azure DevOps Server | 인증한 서버·컬렉션 → 프로젝트 → 지원 콘텐츠 | **조건부.** 사설 주소·컬렉션 컨텍스트가 필요하고 버전별 목록 API 검증 필요. Server에 Cloud 전용 PAT 발급 목록 기능을 추가하지 않음 |
| Slack Enterprise Grid | 확인한 조직 → 워크스페이스 → 승인 앱 발급 유형 | **조건부.** `admin.teams.list`에는 `admin.teams:read`와 조직 수준 설치 조건이 필요. 현재 `admin.apps:read`만으로는 부족. 일반 Slack 메시지 수집은 지원 대상이 아님 [11] |
| Vault 서버 읽기 | 인증한 주소·namespace → KV 마운트 → 경로 | **조건부.** `/sys/mounts` 조회와 경로 LIST, 선택 경로 read capability를 각각 확인. KV 버전은 목록에서 판별. namespace나 로그인 mount 등 인증 컨텍스트는 필요할 수 있음. 목록 단계에서는 값을 읽지 않음 [12] |
| OpenBao 서버 읽기 | 인증한 클러스터 → 지원 KV 마운트·경로 | **조건부.** 기존 Vault 계열 계약을 재사용하되 OpenBao의 지원 버전·목록·capability 응답은 별도 검증. Vault 문서만으로 독립 검증 완료를 선언하지 않음 |
| Okta | 인증한 조직 → 사람 목록·앱 목록의 지원 옵션 | **조건부.** 조직 주소와 서비스 앱 설정 필요. 하나의 조직 인증으로 다른 Okta 조직을 열거하지 않음. API scope와 앱에 부여한 관리자 역할을 함께 확인. 임의 사용자 일부만 수집하는 기능은 현재 계약에 없음 |
| Keycloak | 인증한 issuer·realm, 권한이 있으면 보이는 realm → 사람·앱 목록 옵션 | **조건부.** Admin API의 `/admin/realms`는 보이는 realm 목록. 단일 realm 서비스 계정에 교차 realm 관리자 권한을 요구하지 않음. 로그인 issuer/realm 컨텍스트는 필요 [13] |
| Google Workspace | 위임·로그인 설정으로 확인한 customer/domain → 사람·앱 목록의 지원 옵션 | **조건부.** 위임 계정과 도메인 설정 필요. Directory API의 customer/domain 범위를 사용하며 일반 Google 로그인만으로 조직 디렉터리 권한을 얻지 않음 [14] |
| Entra 사람 목록 | Microsoft 연결의 확인된 tenant → 사람 목록 옵션 | **가능/조건부.** 새 연결은 `azure` 경로를 사용. 호환용 `entra_id`를 새 마법사 공급자로 부활시키지 않음. 팀의 로그인 IdP 일치 제약 유지 |
| GCP·Vault·OpenBao 고객 CLI, 기타 금고 | 고객 환경이 보고한 목록·선언 범위 | **서버 자동 열거 대상 아님.** 서버에 해당 공급자 인증이 없음. 기존 CLI 수집 경로를 명확히 구별하고 API 확인 완료로 표시하지 않음. 별도 목록 보고 기능 없이는 무입력 범위 선택 미지원 |
| 웹사이트 | DNS로 확인한 도메인 → 승인 가능한 시작 페이지 | **별도 흐름.** 공급자 로그인이 없음. 검증된 도메인 목록은 선택식으로 재사용하되 임의 사이트 탐색으로 시작 URL을 만들어 내지 않음. 전체 사이트맵 자동 탐색은 이 설계의 완료 조건이 아님 |

사람 목록 연결은 팀 설치의 로그인 IdP와 일치해야 한다. Okta 로그인으로 GitHub·Notion 수집 권한을 얻는 것은 아니다.
디렉터리 일부를 볼 수 있다는 이유로 전체 인원을 수집했다고 표시하거나 퇴사자 부재의 근거로 쓰지 않는다.
`remediation`은 기존처럼 별도 인증 연결과 승인된 조치 계획을 사용한다. 수집 온보딩에 변경 권한을 묶지 않는다.
조치 권한을 안전하게 검증할 수 없는 인증 방식에서는 비활성 설정까지 저장할 수 있지만, 검증된 자동 조치 준비 완료로 표시하지 않는다.

## 현재 구조에서 바꿀 부분

단순히 마법사 순서를 바꾸는 것으로는 목표를 달성할 수 없다.
[service.create](../cremore/onboarding/service.py)는 전체 target을 먼저 검증하고,
`activate`는 수집 자식 레코드를 만들며 일정에 따라 수집을 시작할 수 있다.
[scope.ts](../web/console/views/integrations/scope.ts)의 기존 초기 경로도 활성화 후 범위를 설정한다.
**목록을 보기 위해 먼저 활성화하는 방식은 사용하지 않는다.**

### 인증 초안과 조회

플랫폼 온보딩에 수명이 제한된 인증 세션을 추가한다. 별도 인증 서비스나 공급자별 서버는 만들지 않는다.
아직 수집 target이 없는 상태이므로 기존 유효한 `ProviderConnection`의 필수 target 검증을 느슨하게 만들지 않는다.
세션은 관리자·브라우저 세션, 공급자·판·인증 방식·접속 컨텍스트, 봉인된 연결 인증정보, revision과 만료 시각을 소유한다.
최초 인증 세션에는 목적 선택이 없어도 된다. 인증 뒤의 기능 선택에서 목적을 확정하며, 기존 `create`의 필수 purposes를 채우려고
모든 목적이나 가짜 기본 목적을 보내지 않는다. 현재 `methodsFor`·마법사·App/OAuth 시작 요청의 목적 선행 의존을 함께 수정한다.
기능을 추가·제외하면 필요한 권한·목록·계획 digest를 다시 계산한다. 자격증명이 같으면 인증 입력을 반복시키지 않고,
권한 확대를 위해 재인증·자격증명 교체가 발생하면 이전 권한 결과와 목록을 무효화해 다시 확인한다.
인증정보는 최종 연결 확정 시 한 소유자에게 이전하며, 취소·만료 후 초안의 비밀 참조를 정리한다. 감사 이벤트는 남긴다.
GCP OAuth의 기존 actor/browser binding·state·만료·callback 검증은 재사용하고 우회하지 않는다.

새 메타데이터 조회는 기존 worker 작업·비밀 해석·bounded client·리스·취소·fencing을 사용한다.
API는 작업 접수와 정규화한 결과 제공을 맡고, 기존 OAuth 프로토콜 처리를 제외한 새 공급자 조회를 API 안에 넣지 않는다.
공급자 `onboarding.py`가 인증 컨텍스트와 목록 권한·상위 대상 조회를 소유하고, 콘텐츠 하위 목록은 기존
[sources registry](../cremore/sources/registry.py)와 [scanning.catalog](../cremore/scanning/catalog.py)를 재사용한다.
발급 인벤토리 전체 수집기나 값 읽기 경로를 사전 조회 용도로 실행하지 않는다.

세션의 목록 snapshot은 항목 ID·종류·표시 이름·상위 ID·provider ID·조회 상태·시각 등 허용된 메타데이터만 보관한다.
목록에 나타난다는 사실과 선택 가능 여부를 구별하고, 거절된 가지의 원인을 안전한 코드로 보존한다.
원문 응답·페이지 본문·비밀값·토큰은 snapshot·작업·로그·감사 기록에 넣지 않는다.
목록의 provider ID와 endpoint는 신뢰 경계에서 다시 검증한다. provider 응답의 URL도 임의 외부 요청 주소로 사용하지 않는다.

상위 조직·tenant 항목을 기존 콘텐츠 전용 `CatalogStore`에 억지로 저장하지 않는다.
세션 snapshot과 실제 콘텐츠 catalog는 구분한다. 확정 때 콘텐츠 항목은 최종 source UUID를 사용해 다시 정규화하고,
동일 provider ID의 선택 근거를 서버가 연결한다. 임시 ID를 승인 scope에 그대로 넣거나 이름으로 대상을 재매칭하지 않는다.

### 여러 대상의 인증정보 소유

**같은 공급자·판·인증 컨텍스트로 선택한 여러 root는 하나의 ProviderConnection이 인증정보를 소유한다.**
root마다 서로 독립적으로 갱신하는 연결에 같은 토큰을 복사하지 않는다.
특히 GitLab 회전은 이전 토큰을 폐기할 수 있어 복제된 연결 중 하나의 갱신이 다른 연결을 깨뜨린다.
기존 [renewal](../cremore/onboarding/renewal.py)의 단일 소유자 갱신과 모든 자식 참조 갱신을 유지한다.
GitHub App의 기존 설치별 동기화 규칙도 유지하며, 인증 컨텍스트가 다른 설치·tenant를 무조건 하나로 합치지 않는다.

이를 위해 영구 target은 버전을 명시한 형태로 확장한다. 제안하는 새 형태는 인증 컨텍스트와 정규화된 root 목록을 담고,
각 목적의 계획은 그중 승인할 root ID를 명시한다. 공급자별 기존 단일 target 검증은 root마다 재사용한다.
공통 `targets_of(record)` 변환 지점에서 기존 단일 target을 한 개의 root로 해석한다. 새로운 root 목록의 첫 항목만 구형 소비자에게 넘기는 호환 처리는 금지한다.
자식 수집 레코드 식별은 안정적인 provider/target ID로 하고 목록 순서·표시 이름 변경으로 중복 생성되지 않게 한다.
현재 이름을 사용해 수집 레코드를 대조하는 `children.update`의 소비자도 함께 이관한다.

이 변경은 화면 전용 작업이 아니다. 생성·점검·계획 변경·자식 조립·갱신·IdP 일치 검사·조치 범위·공개 응답·승인 digest를 함께 수정해야 한다.
서로 다른 인증이 필요한 대상은 같은 마법사에서 추가 인증을 안내하되 각각의 소유 연결을 유지한다.
목표에 필요하지 않은 범용 자격증명 공유 서비스는 추가하지 않는다.

### 서버 작업과 최종 확정

| 작업 | 서비스의 책임 |
| --- | --- |
| 인증 세션 생성·변경 | 관리자 권한·소유자·origin·판·방법 검증, 봉인, CAS. 인증 변경 시 이전 목록·검사 무효화 |
| 인증 확인·기능 선택·목록 조회 요청 | 기능 미선택 상태에서는 최소 인증만 확인. 기능 선택 뒤 필요한 목록 권한 결정, worker에 큐잉. 같은 revision의 진행 작업 중복 방지 |
| 목록 페이지 조회·선택 저장 | 세션에 속한 snapshot·정확한 항목 ID만 허용. 다른 사용자/공급자의 ID, 변조된 부모·cursor 거절 |
| 선택 권한 확인·검토안 생성 | 실제 선택한 root·기능·옵션을 정규화하고 목적별 검사. 선택·계획·인증·snapshot을 포함한 digest 저장 |
| 최종 확정 | 재검증 후 연결·자식·승인 범위·일정·감사를 원자적으로 저장. idempotency로 재전송 시 같은 결과 반환 |

기존 온보딩 서비스와 등록 라우트 아래에 위 작업을 추가하며 콘텐츠/coverage 레코드를 직접 만드는 별도 등록 API를 만들지 않는다.
공개 API의 새 target 표현은 버전으로 구별한다. 오래된 클라이언트의 쓰기가 새 다중 target을 단일 target으로 덮어쓰지 못하게 거절한다.
권한 gate는 신규 확정뿐 아니라 기존 `activate`, 기능 추가, 계획·범위 확대의 서비스 경로에서도 적용한다. 구형 API를 통한 우회를 남기지 않는다.
현재 [check_digest](../cremore/onboarding/service.py)는 방법·인증 참조·목적·target을 포함하지만 최종 선택 옵션까지 묶지 않는다.
새 검사 근거에는 판·인증 revision·정규화한 대상·계획·목록 snapshot·유효기간을 함께 묶는다.

최종 트랜잭션 전에 외부 조회를 마치고, 안에서는 결과의 유효성과 revision을 확인한다. 네트워크를 기다리며 DB 잠금을 잡지 않는다.
선택만 저장할 때는 작업을 시작하지 않는다. 저장·시작을 선택했을 때만 확정된 범위를 기존 scheduler/queue가 실행한다.
AWS ExternalId·역할 설치에는 별도 비활성 준비 레코드를 허용하되, 그것이 접근 승인이나 수집 활성화가 되지 않게 한다.
기존 AWS SSO/Organizations 발견 함수가 로컬 계정 등록까지 수행하는 경로는 읽기 전용 목록 단계와 분리한다.

## 큰 조직과 반복적인 범위 수정

처음에 모든 계정·모든 하위 리소스를 재귀 조회하지 않는다. 상위 목록을 페이지로 가져오고 펼친 가지의 목록을 읽는다.
조회별 페이지·개수·시간·요청 예산, 재시도 간격, 취소와 계속 조회를 지원하고 현재 수집 예산을 무제한으로 바꾸지 않는다.
콘텐츠의 기존 한도인 한 페이지 최대 200개, 승인 root 최대 10,000개를 재사용하며 한도 도달을 완료로 표시하지 않는다.
미조회·부분 조회·권한 거절·미지원·정상 빈 목록을 서로 구별한다. 실패한 조회로 저장된 대상을 삭제하거나 부재를 확정하지 않는다.

전체 선택은 현재 확인한 snapshot의 항목 집합에 고정한다. 전체 페이지를 고르는 기능은 목록 조회가 완료된 뒤에만 제공하며,
부분 목록에서는 `조회된 N개 선택`이라고 적는다. 앞으로 생길 항목, 아직 보지 않은 페이지, 선택하지 않은 계정으로 범위를 자동 확대하지 않는다.
거절된 필수 가지나 점검 미완료 대상이 선택에 남으면 다음 단계가 막힌다. 사용자가 이를 명시적으로 제외한 뒤 확인된 대상만 진행할 수 있다.
일부 대상만으로 의미가 바뀌는 사람 목록·조직 전체 판정은 해당 계약이 허용하지 않으면 부분 선택으로 진행할 수 없다.

이미 연결한 인증은 만료·변경되지 않았다면 재입력시키지 않는다. 현재 승인 범위를 먼저 표시하고 목록 새로 고침으로 추가/제외를 고른다.
추가는 새 대상·옵션의 권한 검사를 거친다. 제외·중지는 부족한 조회 권한 때문에 막지 않되 관리자 승인과 버전 검사를 유지한다.
진행 중 작업에도 현재 승인 scope·리스 검증을 적용하고 다음 페이지/요청부터 제외한 범위를 읽지 않게 한다. 이미 진행 중인 외부 요청을 되돌렸다고 표시하지 않는다.
범위에서 빠진 자료와 감사 이력은 삭제하지 않는다. 새 조회 실패 때 이전 승인 범위를 자동으로 교체하지 않는다.

[targets.tsx](../web/console/views/integrations/targets.tsx)의 선택·추가/제외 비교·검토·snapshot/version 검사를 최초 연결에도 재사용한다.
target의 ID 목록을 바꾸는 UI와 수집 옵션 UI가 서로 다른 승인 상태를 만들지 않도록 최종 검토에서 함께 확정한다.
서비스·판·인증 변경 시 이전 선택을 적용하지 않는다. 새 목록과 일치해 복구 가능한 선택은 사용자에게 다시 보여 주고 확인받는다.

## 구현 순서와 인수 조건

| 순서 | 담당 경로와 작업 | 완료 조건 |
| --- | --- | --- |
| 1 공통 경계 | `cremore/onboarding/`, API routes, worker, DB migration. 인증 세션·단계별 permission gate·snapshot·다중 target·원자적 확정 | 아래 서버 계약 검사가 통과하고 기존 단일 target 읽기·갱신이 유지됨. 실수집 전까지 활성 자식·일정이 생기지 않음 |
| 2 최초 흐름 검증 | AWS·Notion 페이지·GCP의 기존 목록과 콘솔 wizard/targets 연결 | 기능 카드는 인증 뒤에만 설정. 인증부터 범위 선택까지 ID 직접 입력 없이 완료. 권한 거절·추가 동의·재확인·범위 수정·취소를 브라우저에서 증명 |
| 3 나머지 지원 경로 | GitHub·GitLab·Atlassian·Azure·Slack·Vault·IdP의 공급자별 onboarding/catalog와 테스트 | 판·인증 방식별 API 근거와 필요한 권한을 구현·검증한 조합만 새 흐름으로 공개 |
| 4 미확인 경로 | Notion Enterprise 상위 목록, DevOps 조직 발견의 토큰별 지원, 사설 제품 버전·CLI 목록 보고 | 공식 계약·안전한 구현 근거 확보 전 자동 지원으로 표기하지 않음. 이 단계가 남으면 전체 공급자 무입력 완료로 보고하지 않음 |

공통 코드를 여러 공급자 담당자가 중복 구현하지 않는다. 새로운 SDK/패키지는 이 설계만을 위해 추가하지 않는다.
공급자별 완료 표에는 공식 API 확인, fake 테스트, 실계정 검증을 따로 기록한다.

필수 회귀 검사는 다음과 같다. 기본은 fake client·테스트 내부 최소 입력이며 실제 토큰이나 수집값을 fixture로 저장하지 않는다.

1. 인증 성공 + 목록 필수 권한 부족이면 다음 단계 API 거절. 필수 수집 권한 부족·미확인은 확정 거절. 선택하지 않은 옵션 권한은 차단하지 않음.
2. 일반 AccessDenied를 근거 없는 정책명으로 표현하지 않음. 만료·네트워크·429·부분 목록·정상 0건의 UI/API 상태 구별.
3. 다른 세션의 항목, 위조된 root/부모/cursor, 허용되지 않은 origin, 만료 snapshot, 변경된 인증·판·계획으로 확정 거절.
4. 목록 조회 중 비밀값·본문·변경 API 호출 0회. 최종 승인 전 실제 수집 0회. API/worker 오류와 감사 로그에 토큰·원문 응답이 없음.
5. 확정 재전송·동시 수정·worker 재시작에서 중복 자식/반쪽 scope 없음. 실패 시 활성 일정이 남지 않음. 취소·lease fencing 유지.
6. 한 토큰으로 여러 root를 선택한 뒤 갱신은 한 번만 수행되고 모든 자식이 새 참조를 사용. GitLab 회전·Azure 인증서·GCP OAuth·GitHub 설치 갱신의 기존 계약 유지.
7. 최종 source UUID로 재정규화한 scope가 선택한 provider ID만 가리킴. 같은 표시 이름·root 순서 변경으로 대상이 바뀌지 않음.
8. 부분 조회 상태의 전체 선택은 조회된 집합에만 적용. 추가·제외 시 최신 scope를 실행기에 반영하고 과거 관측·감사 이력 보존.
9. 기능 미선택 상태로 인증 가능하고 기능 카드는 인증 뒤에 설정됨. 최초에 모든 기능의 권한을 요청하지 않으며, 기능 추가 동의·토큰 교체 뒤 선택 유지와 오래된 근거 무효화를 검증.
10. 브라우저에서 인증→기능 선택→권한 안내→재확인→목록 선택→검토를 검증. 다중 선택·검색·모두 해제·좁은 화면·레이어·키보드·두 언어/테마 확인.

실행 검증은 변경 영역의 onboarding·scope·worker·공급자 계약 검사와 웹 tsc/관련 브라우저 검사부터 시작한다.
DB 이관·동시성은 저장소 규칙의 격리 PostgreSQL에서 검증한다. 실제 실행 결과는 마지막 검증 기록에 따로 적는다.

## 호환과 배포

기존 활성 연결·scope·관측·일정을 새 흐름에 맞춰 일괄 재생성하지 않는다. 먼저 구형/신형 target을 모두 읽는 API·worker·갱신 코드를 배포하고,
모든 소비자 버전을 확인한 뒤 새 형태 쓰기를 허용한다. 버전이 섞인 worker가 모르는 target을 단일 대상으로 처리하지 않도록 schema/version guard가 필요하다.
신규/확대 변경에는 새 권한 gate를 적용하되 기존 활성 연결은 실패 상태를 표시하고 현재 실행 시 권한 검증을 유지한다.
구형 권한 결과를 소급해 최신 검증 완료로 바꾸지 않는다. 제거·중지 경로는 항상 사용할 수 있게 유지한다.

롤백은 새 생성·확대 쓰기를 중단하고 두 형태를 읽을 수 있는 호환 버전으로 한다. 다중 target을 첫 target 하나로 축소하는 다운마이그레이션은 금지한다.
일회용 세션만 만료 정리하고 영구 연결·finding·credential·감사 행을 삭제하지 않는다.
구현 때 [ONBOARDING](ONBOARDING.md), [팀 지침](AI_TEAM_CODING_GUIDE.md), API 계약과 공급자별 안내를 같은 버전으로 갱신한다.

현재 schema 변경은 `create_all`에 등록된 추가 테이블 `provider_onboarding_sessions`다. 기존 행을 다시 만들지 않는다.
API·worker를 함께 갱신해야 하며 구버전 worker와 혼용한 배포는 지원하지 않는다. 이미 v2 연결을 저장했다면 구버전으로 단순 롤백하지 않는다.

## 실행 검증 기록 (2026-10-03)

아래 기능 검사는 fake client를 사용하며 실제 AWS·Notion·SaaS 호출이나 운영 DB를 사용하지 않았다.
팀 서버 배포의 상태·DB 확인은 뒤의 별도 배포 기록에 적었다.
아래 검사 집합은 서로 겹치므로 숫자를 합산하지 않는다. 전체 저장소/CI가 통과했다는 뜻도 아니다.

| 검사 | 실제 결과 |
| --- | --- |
| 공통 onboarding·API·scope·경계·DB 상태·worker 회귀 | 780 passed, 3 skipped. skip 3개는 격리 PostgreSQL 환경을 요구하며 아래 별도 실행에 포함 |
| 공급자 11개 디렉터리 + 콘텐츠 계약·공통 연결·worker·상관분석 | 2,049 passed, 66 skipped, 282 subtests passed. 별도 PostgreSQL이 필요한 Control Tower 7개, Windows에서 지원하지 않는 POSIX 파일/락 검사 59개는 미실행 |
| sessions + GCP OAuth, 격리 PostgreSQL 17 지정 | 54 passed. 동시 완료에서 소유자·scope 한 번 생성, scope CAS 한 승자, OAuth binding 포함 |
| 기존 scope 보존·누락 거절 후속 sessions 검사 | 20 passed, 2 skipped. 이 실행의 skip 2개는 위 별도 PostgreSQL 검사에서 통과한 동시성 검사 |
| 후속 공급자 discovery 검사 | 33 passed. AWS `ec2:DescribeRegions` 거절 시 단계 차단·작업명 안내·원문 응답 미노출 포함 |
| 웹 Node | 228 passed, skip 없음 |
| 실제 React/CSS + fake API 브라우저 | 인증→거절/재확인→정확한 scope 저장, 새로고침 복원, 생성키 재시도, 기존 연결 편집, KO/EN·light/dark·360px·overlay·Escape 초점 복귀 통과 |
| 기존 Google OAuth callback 브라우저 | state 검증·취소·한 번 전달·언어 처리 통과 |
| 정적 검사 | 변경 Python Ruff, TypeScript `tsc --noEmit`, Next production build, `git diff --check` 통과 |

공통·공급자 광역 회귀 후 scope 보존·조회 거절 안내를 보완하고 해당 집중 검사를 다시 실행했다.
주요 명령은 다음과 같다(PowerShell pytest 전 `AWS_EC2_METADATA_DISABLED=true`).

```text
python -m pytest cremore/onboarding cremore/api/onboarding_routes_test.py cremore/api/gcp_oauth_test.py cremore/api/dashboard_test.py cremore/scanning/scope_test.py cremore/provider_boundaries_test.py cremore/db/scan_state_test.py cremore/worker/runtime_test.py -q -rs -p no:cacheprovider
python -m pytest aws/backend github/backend gitlab/backend notion/backend gcp/backend azure/backend atlassian/backend okta/backend keycloak/backend slack/backend vault/backend cremore/sources/module_contract_test.py cremore/domain/connections_test.py cremore/coverage/provider_worker_integration_test.py cremore/coverage/metadata_linkage_test.py -q -rs -p no:cacheprovider
python -m pytest cremore/onboarding/sessions_test.py cremore/api/gcp_oauth_test.py -q -rs -p no:cacheprovider
node tests/console-auth-first.browser.cjs
node tests/console-gcp-oauth.browser.cjs
npx tsc --noEmit
npm run build
```

PostgreSQL 검사는 작업 전용 tmpfs 컨테이너의 `127.0.0.1:54392/cremore_test`만 사용했다.
이 최초 검사 시점에는 팀 사이트 배포가 남아 있었다. 이후 배포 결과는 아래에 기록한다.
실계정 수집 API 검증, POSIX 검사와 전체 컨테이너 CI는 수행하지 않았다.

### 최종 검토 후 회귀 (2026-10-03)

독립 검토에서 찾은 초안 새로고침·OAuth 재시도·만료 취소, 검사 후 목록 이어 읽기,
혼합 KV 버전·구독별 옵션, 변경된 수집 좌표의 대상 제외, 값 읽기·GitHub 소유자 미확인 승격을 수정했다.
각 수정은 fake 또는 실제 React/CSS의 회귀 검사로 증명했다.

- 공통 onboarding: 425 passed, PostgreSQL opt-in 2 skipped. 이후 GitHub 소유자 수정은 아래 집중 검사에서 재검증.
- GCP·Azure·온보딩 묶음: 652 passed, 16 subtests passed.
- AWS·온보딩 묶음: 870 passed, PostgreSQL opt-in 9 skipped(Control Tower 7개 포함).
- GitHub·권한 점검 묶음: 276 passed.
- sessions·GCP OAuth: 새 격리 PostgreSQL 17 `127.0.0.1:54393/cremore_test`에서 68 passed, skip 없음. 검사 컨테이너 제거 완료.
- 웹: Node 228 passed, auth-first 브라우저 회귀·tsc 통과. 여러 root의 필드·옵션 합집합과 검사 완료 초안 복원 포함.
- 변경 Python Ruff·공백 검사 통과. 위 검사 집합의 수는 중복되므로 합산하지 않는다.

### 최초 팀 서버 배포 기록 (2026-10-03, a3e4557)

`a3e45571dfa92387e290853bc91977e16f377167`을 브랜치에 push하고 해당 커밋의 `git archive`만으로
Python·웹 이미지를 빌드했다. 실행 이미지의 Python 패키지 파일 전체가 소스 archive와 해시까지 일치하며,
새 온보딩 catalog·session 테이블 import가 외부 네트워크 없는 컨테이너에서 통과했다.
추가 API·공급자 경계·DB 상태·worker 회귀는 164 passed, skip 없음이다.

- 이 배포 당시 [팀 사이트](https://test.cremore.site/)의 API·worker·web이 모두 `team-a3e4557`, 동일 revision으로 실행됨을 확인했다. 현재 실행 버전을 나타내는 기록은 아니다.
- 실행 전 기존 환경변수·마운트와 대조하고 Okta, AWS workload config, GCP WIF, 비밀 봉인·지문 키를 보존했다.
- 앱을 중지하고 기존 PostgreSQL 17 DB의 custom-format 백업을 생성한 뒤 TOC를 읽어 확인했다.
  서버 백업은 `/opt/cremore-backups/team-a3e4557.dump`에 권한을 제한해 보관한다. 실제 복원 연습은 수행하지 않았다.
- API·worker를 먼저 교체하고 새 `provider_onboarding_sessions` 테이블·revision·API 401을 확인한 뒤 web을 열었다.
  기존 DB·볼륨·관측·감사 행은 삭제하거나 변환하지 않았다.
- API·web·oauth2-proxy 상태 확인 통과. 외부 비로그인 요청은 Okta authorize로 302 이동한다.
  기존 관리자 세션·이름/이메일 표시와 인증 → 기능 → 범위·권한 → 확인 순서의 Notion 화면을 실제 사이트에서 확인했다.
- 임시 전달 S3 버킷·객체와 해당 객체만 읽는 IAM 정책을 제거했다. 배포 때문에 실제 SaaS 연결·스캔은 만들지 않았다.

v2 연결 저장 후 구버전으로 단순 복귀하지 않는다. 장애 시 새 쓰기를 중지하고 v1/v2를 모두 읽는 호환 버전으로 수정한다.
백업 복원은 배포 이후 변경을 잃을 수 있으므로 별도 복구 결정 없이 자동 실행하지 않는다.
위 기록은 수동 로컬 검사·실제 배포 증거이며 원격 전체 CI 또는 모든 공급자 실계정 검증 완료를 의미하지 않는다.

### 상시 인증·기능 선택 후속 검증 (2026-10-03)

현재 후속 변경은 같은 브랜치에서 기능별 중지/재개, 추가 인증을 포함한 연속 설정,
AWS 서버 workload와 Organizations, GitHub 조직별 App 설치 토큰, Slack workspace 목록을 검증했다.
사내 서버 AWS 경로는 실제 botocore에 fake STS를 주입해 projected JWT 교체와 만료 후 재발급을 확인했다.
회사 인프라에서의 실계정 24시간 연속 운전이나 실제 GitHub 다중 조직 설치를 수행한 기록은 아니다.

- 통합 Python 검사: 1,743 passed, 2 failed. 실패는 기존 AWS 승인 fixture와 GitHub 단일 조직 토큰 cache 호환을 수정하고 각각 재검사했다.
- 후속 onboarding/session/조치 PostgreSQL 포함 검사: 182 passed, 2 failed. 같은 설정의 기능 재개가 인증 근거를 지우던 회귀를 수정했다.
  수정 뒤 해당 memory/SQLite 검사와 GitHub 다중 조직·기존 source/scope 유지 묶음은 18 passed이다.
- SIEM 공통 출력: 격리 PostgreSQL 포함 248 passed. 봉인 저장·기계 신원·토큰 갱신·Slack 집중 검사: 112 passed.
- 독립 검토: AWS 계정 disable 경쟁조건과 GitHub 선택적 enterprise 추론 6 passed,
  GitHub 단일 두 번째 조직·기존 source/scope·설치 바인딩 후속 16 passed.
- 웹 Node 254 passed, tsc 통과. 인증 후 범위 선택·추가 인증 설정 브라우저 검사 통과.
  동시 검사 부하 중 설정 브라우저의 12초 timeout 1회를 관측했으며 단독 재실행은 통과했다.
- 변경 Python Ruff와 공백 검사 통과. 검사 묶음은 중복되므로 수를 합산하지 않는다.

배포에는 커밋 archive의 이미지만 사용하고 실행 revision·설정·마운트·DB 백업을 확인한다.
배포 확인 전 로컬 통과를 서버 적용 완료로 간주하지 않는다. 후속 발견 위치 접근 목록은
[별도 계약·검증 기록](EXPOSURE_ACCESS.md)을 따른다.

### 로컬 Linux의 사내 설치 경로 검증 (2026-10-03)

현재 작업 소스를 Linux 파일시스템에 복사해 wheel을 새로 만들고 오프라인 설치한 뒤
Python 3.14.7·PostgreSQL 17에서 225개 검사를 통과했다(실패·skip 없음).
검사 컨테이너는 Windows bind mount·AWS metadata·외부 네트워크·운영 DB를 사용하지 않았다.
PostgreSQL은 별도 network-none namespace의 loopback과 tmpfs에 두었고 검사 후 전용 컨테이너를 정리했다.

- 실제 botocore 갱신 경로와 fake STS: projected JWT 교체와 만료 후 갱신, 직접 workload 신원·member role 두 모드.
- 봉인 연결 정보와 checkpoint를 저장한 Python 프로세스를 종료하고 새 프로세스에서 복원.
  로컬 sealing key를 사용했으며 저장된 SQLite에 합성 token 원문이 없음을 확인했다.
- 만료 lease 재점유, 이전 token의 쓰기 거절, 기존 cursor 재개, worker/runtime·metadata/CloudTrail 사용 기록의
  commit fencing과 PostgreSQL 동시성.

실행한 기존 검사: `aws_sessions_test.py::test_on_prem_web_identity_refreshes_without_metadata_or_personal_login`,
`worker_session_test.py`, `secretstore/sealed_test.py`, `db/task_store_test.py`, `worker/runtime_test.py`,
`coverage/metadata_job_test.py`, `coverage/credential_usage_test.py`, `coverage/postgres_metadata_test.py`, `db/postgres_scan_test.py`.
검사 wheel SHA-256은 `61de6eacb300ff7e9aa7f10b94a36ba69b6256f91a18732721e42e8a8e929e11`이다.

이는 시계 진행·프로세스 재시작을 통한 복구 검증이다. 실제 24시간 운전, 회사 IdP JWT 발급/갱신과
AWS trust/권한, 사내 DNS·proxy·TLS, 호스트 재부팅·정전 복구는 별도 실환경 검증이 필요하다.
검사용 의존성 이미지와 배포용 새 이미지의 검증 결과도 구분한다.

## 공식 문서 근거

확인 기준일은 2026-10-02다. 아래는 제품 기능·API 가능성의 근거이며 현재 계정 권한이나 CreMore 실환경 동작의 증거가 아니다.

- [1] AWS [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html), [Identity Center ListAccounts](https://docs.aws.amazon.com/singlesignon/latest/PortalAPIReference/API_ListAccounts.html).
- [2] GitHub [App installation APIs](https://docs.github.com/en/rest/apps/installations), [authenticated user organizations](https://docs.github.com/en/rest/orgs/orgs#list-organizations-for-the-authenticated-user). 토큰 종류별 endpoint 제한을 따른다.
- GitHub [Enterprise organization installations](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/organization-installations): enterprise 소유 App의 enterprise 설치와 `Enterprise organization installations: write`가 필요하다. 전체 저장소 App 설치 동의와 CreMore 콘텐츠 검사 범위 승인은 별개다.
- [3] GitLab [Groups API](https://docs.gitlab.com/api/groups/).
- [4] Notion [Search](https://developers.notion.com/reference/post-search), [token identity](https://developers.notion.com/reference/get-self.md), [Admin API](https://developers.notion.com/reference/admin/intro.md), [Admin scopes](https://developers.notion.com/reference/admin/scopes.md), [Admin OpenAPI](https://developers.notion.com/openapi-adminApi.json).
- [5] Confluence Cloud [Space API](https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-space/). Data Center 버전별 권한 계약은 별도 확인 대상이다.
- [6] Bitbucket Cloud [Workspaces API](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-workspaces/). Data Center의 프로젝트 API와 동일하지 않다.
- Bitbucket [workspace access token](https://support.atlassian.com/bitbucket-cloud/docs/workspace-access-tokens/), [permissions](https://support.atlassian.com/bitbucket-cloud/docs/workspace-access-token-permissions/), [DC HTTP access tokens](https://confluence.atlassian.com/bitbucketserver/http-access-tokens-939515499.html): workspace token은 사용자 `/user` 조회와 다르고, DC 프로젝트/저장소 토큰은 서비스 사용자 토큰과 동일한 목록을 주지 않는다.
- [7] Atlassian [Organization APIs](https://developer.atlassian.com/cloud/admin/organization/rest/api-group-orgs/).
- [8] GCP [projects.search](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/search).
- [9] Azure [Subscriptions List](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/list?view=rest-resources-2022-12-01).
- [10] Azure DevOps [Projects List](https://learn.microsoft.com/en-us/rest/api/azure/devops/core/projects/list?view=azure-devops-rest-7.1), [Accounts List](https://learn.microsoft.com/en-us/rest/api/azure/devops/account/accounts/list?view=azure-devops-rest-7.1).
- [11] Slack [admin.teams.list](https://docs.slack.dev/reference/methods/admin.teams.list/).
- [12] Vault [mounts](https://developer.hashicorp.com/vault/api-docs/system/mounts), [capabilities-self](https://developer.hashicorp.com/vault/api-docs/system/capabilities-self). OpenBao는 독립 실검증 대상이다.
- [13] Keycloak [Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html).
- [14] Google Workspace [Directory users.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/list).
