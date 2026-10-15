# 실계정 검증 체크리스트

작성 2026-10-08 · 브랜치 `integration/saas-structure`

공급자 연결 마법사(콘솔 "연동 서비스")와 2026-10-07에 넓힌 "자격증명이 할 수 있는 일"(AWS 잠재 권한
`assessment_version` 3, GCP `effective_access`, Microsoft `app_permissions`·`app_azure_roles`), 2026-10-08 변경(퇴사자 점검,
GitHub 사람 목록의 App, AWS KMS 키 정책, Microsoft 워커 신원 등)을 시험 계정에서 확인하는 목록이다. 지금까지의 검증은 합성
응답·fake client·격리 저장소·브라우저 fixture뿐이며 실제 공급자 호출은 하지 않았다([공급자 인벤토리 구현 기록](PROVIDER_INVENTORY_IMPLEMENTATION.md)의
2026-10-07 절, [권한 평가의 근거와 한계](PERMISSION_ASSESSMENT.md)의 검증 기록).

공급자마다 준비 → 마법사 → 권한 확인 정상 결과 → 첫 수집 후 정상 결과 → 문제 신호 → 정리 순서다. 모든 항목은 체크박스다.
정상 항목은 확인하면 체크하고, 문제 신호는 실제로 본 것만 체크해 마지막 "기록" 표에 상세 코드와 함께 남긴다.
"(2026-10-07)" 표시는 CHANGELOG `Unreleased` 첫 묶음 중 2026-10-07 변경("연결 마법사의 공급자 안내와 권한 점검을 …",
"권한 판정을 넓혔습니다", "금고 대조의 지문 계약을 …")을 확인하는 항목이다. "(2026-10-08)" 표시는 그 위에 더한 2026-10-08
변경(퇴사자 점검, GitHub 사람 목록의 App, AWS KMS 키 정책, Parameter Store 안내, Microsoft 워커 신원, AWS 값 읽기 역할, GitHub
Server의 SSO 승인 유형, GitLab `extern_uid`)과 CHANGELOG에 따로 적히지 않은 GitHub SSO 승인 토큰 유형 수정을 확인하는 항목이다.
웹사이트 노출 검사(`website`)와 범용 금고(`external_vault`)는 다루지 않는다.

시작 전 규칙:

- [ ] 시험용 테넌트·프로젝트·조직·계정만 쓴다. 운영 계정과 운영 데이터에는 연결하지 않는다.
- [ ] 각 절에 적힌 권한·역할·범위만 준다. 확인을 통과시키려고 더 넓은 역할을 주지 않는다. 다음 넓은 권한은 그 항목을 시험할
  때만, 시험 조직·계정에서만 준다: Azure DevOps Project Collection Administrators, 스토리지 키 지문의 Reader and Data Access,
  Bitbucket `Repositories: Admin`(배포 키)·Data Center 프로젝트 관리(토큰 목록), Google Workspace 도메인 전체 위임, GCP 조직 수준
  Security Reviewer·Deny Reviewer, Azure 루트 관리 그룹의 사용자 지정 역할(Azure 리소스 액세스 관리 상승 포함), Keycloak
  `view-clients`(26.8.0 전), Vault `auth/token/accessors`의 `sudo`.
- [ ] 토큰·키·시크릿·개인 키는 마법사의 입력 칸(또는 마법사가 봉인하는 흐름)에만 넣는다. 채팅·이슈·문서·스크린샷·
  이 체크리스트의 메모에 붙이지 않는다. 예외는 "실효 권한 검증 > AWS 잠재 권한"과 그 설정을 쓰는 "g"다(노출 검사로 발견된
  키가 있어야 동작한다). 그 항목의 지시대로 일회용 키만 쓰고 끝나면 삭제한다.
- [ ] 내려받은 키 파일(GitHub App 개인 키 .pem, Workspace 서비스 계정 키 JSON)은 마법사에 넣은 뒤 지운다. 시험이 끝나면 만든
  키·토큰·앱 등록·서비스 계정·역할 할당·도메인 전체 위임·OAuth 승인을 지우거나 철회한다. 절마다 마지막에 정리 항목을 둔다.
- [ ] 값 읽기 옵션(`read_values`, Microsoft `storage_key_accounts`, AWS `ssm_prefixes`)은 그 항목을 시험할 때만 켠다.
  값을 읽는 것이 기본인 수집(Vault·OpenBao KV, GitLab CI 변수 목록)은 시험 값만 둔 곳을 대상으로 한다.
- [ ] 결과는 화면 문구를 그대로 적는다. 화면은 아는 상세 코드를 문장으로만 보여 준다(모르는 코드만 그대로, `HTTP_400`은
  `HTTP 400`). 그래서 코드는 연결을 저장한 뒤 `GET /api/v1/provider-connections/{id}`의 `checks.results.<기능>.items[].detail`에서
  옮겨 적는다. 저장 전 초안이면 브라우저 개발자 도구의 `onboarding-sessions/<id>/read` 응답을 본다. 공급자 응답 본문, 토큰,
  개인 정보는 적지 않는다.

## 공통 확인

화면: 연동 서비스(`?view=sources`)의 "계정·발급 목록 연결"(발급 목록·금고 대조·사람 목록·조치)과 "콘텐츠 검사 위치 연결"(노출
검사: 그 공급자의 계정 연결이 있어야 열린다)에서 연다. 계정 목록에는 코드 저장소·클라우드·협업 도구 서비스만 있으므로
Vault·OpenBao는 서비스 목록 아래 `Secret 저장소` 카드의 `금고 연동하기`로, Okta·Keycloak·Google Workspace 사람 목록은
`기타 설정` 카드의 `디렉터리 동기화`로만 연다. 새 연결 마법사는 제품 선택(제품이 여럿일 때) → 인증 → 기능 → 권한 확인 →
수집 범위 → 최종 확인이다. 저장한 연결의 `수집 범위·인증 설정`은 `수집 범위` → `인증` → `확인` 단계이고, `인증` 단계에
"필요한 권한" 태그와 `연결 확인`·`권한 다시 확인` 버튼이 있다.

- [ ] 워커가 실행 중이다(운영 상태 `?view=operations`). 새 연결 마법사에서 워커가 돌지 않으면 "인증된 접근 권한과 목록을
  확인하고 있습니다…"가 계속 보이다가 30분 뒤 초안이 만료된다. "권한 확인이 끝나지 않았습니다. …"는 저장한 연결의
  `수집 범위·인증 설정`에서 `연결 확인`·`권한 다시 확인`을 누르고 150초가 지나면 나온다.
- [ ] 인증 단계의 하단 버튼(`인증 확인`, AWS 미승인 신원은 `신원 승인·인증 확인`, CreMore가 키를 만드는 방식은 `인증키
  만들기` → `키 등록 완료·인증 확인`, GitHub 새 App은 `GitHub에서 App 만들기·설치`) 뒤 기능 단계로 넘어간다. 실패하면
  빨간 배너에 상세 코드의 문구가 나온다.
- [ ] 기능 단계: 기능 카드에 "현재 인증으로 권한 확인" 또는 "추가 인증: …"이 보인다. `승인된 조치 실행`은 다른 기능과 같은
  연결로 묶이지 않는다. 함께 고르면 카드에 "추가 인증: … · 조치 전용 연결"이 보이고, 현재 연결을 저장한 뒤 조치 전용 연결로
  이어서 인증한다. `승인된 조치 실행`만 고르면 지금 초안을 닫고 조치 전용 인증 단계로 다시 시작한다.
  `대상 불러오기`로 인증된 신원이 보는 계정·조직·프로젝트 목록이 나온다.
- [ ] 권한 확인 단계: 대상과 "수집 옵션"(기능이 둘 이상이면 "<기능 이름> 옵션")을 고르고 `권한 확인·다음`을 누르면 "필수
  권한"에 고른 기능·옵션의 필수 권한만 나온다. 모두 확인됐을 때만 수집 범위로 넘어가고, 아니면 "선택한 기능의 필수 권한을
  부여한 뒤 다시 확인하세요…" 배너와 함께 머문다.
- [ ] 새 연결 마법사의 "필수 권한"은 필수 권한만 보여 준다. 확인되면 `<권한 이름> · 확인됨`, 아니면
  `<권한 이름> · <subject> <상세 문구>`다(상세 코드가 없는 거절은 `MISSING`·`NOT_REPORTED`가 그대로 보인다). 상태 단어(있음·
  없음·알 수 없음·확인 실패), 권한 ID, 확인된 행의 subject, 비필수 권한은 저장한 연결의 `수집 범위·인증 설정` → `인증` 단계
  "필요한 권한" 태그에 마우스를 올려야 보인다(`권한 ID · 상태 · 상세 문구 · subject`, 권한마다 첫 답 하나). 꺼 둔 옵션의
  권한은 어느 화면에도 나오지 않는다. 아래 절의 `iam_read` 같은 권한 ID는 이 툴팁과 API에서 보는 이름이고, "확인됨"은 새
  마법사의 `<권한 이름> · 확인됨`이다.
- [ ] 권한 결과 네 가지(API의 `status`)를 구별한다. `GRANTED`(툴팁 "있음"). `MISSING`(툴팁 "없음": 공급자가 거절, 주로
  401·403). `NOT_REPORTED`(툴팁 "알 수 없음": 공급자가 이 자격증명으로는 답하지 않거나 CreMore가 사전 점검으로 확인하지 않는
  권한. 예: 값 읽기 `VALUE_READ_PERMISSION_NOT_CHECKED`, Notion 폐기 `CONFIRMED_WHEN_RUN`, 401·403이 아닌 HTTP 응답
  `HTTP_400`·`HTTP_404`(화면 `HTTP 400`·`HTTP 404`), 답이 오지 않은 항목 `NOT_CHECKED`("확인하지 않음")). `ERROR`(툴팁
  "확인 실패": 질문 자체가 실패). 꺼 둔 옵션의 `ADMIN_EVENTS_OFF`·`NOT_SELECTED`는 화면에 없고 API에만 있다.
- [ ] 필수 권한이 `GRANTED`가 아니면(`NOT_REPORTED` 포함) 활성화가 `REQUIRED_PERMISSIONS_NOT_GRANTED`("필수 권한을 확인하지
  못했습니다…")로 거절된다. `required: false` 항목과 꺼진 옵션의 권한은 막지 않는다.
- [ ] 점검 결과는 30분 동안만 쓰인다. 대상·옵션을 바꾸거나 30분이 지나면 `PERMISSION_CHECK_REQUIRED`("현재 선택의 권한을
  다시 확인해야 합니다.")가 나온다.
- [ ] 새 연결 마법사는 인증 단계의 첫 버튼(`인증 확인`·`인증키 만들기` 등)부터 `연동 저장`까지 30분 안에 끝내야 한다. 지나면
  초안이 만료돼(`ONBOARDING_SESSION_EXPIRED` "인증 초안이 만료되었습니다. 인증부터 다시 시작하세요.") 인증부터 다시 한다.
  스택 배포·인증서 업로드·역할 전파처럼 밖에서 하는 일은 미리 준비해 둔다.
- [ ] (2026-10-07) 여러 옵션이 함께 쓰는 권한은 그중 한 옵션을 꺼도 필요한 권한에서 빠지지 않는다. 예: GCP
  `resourcemanager.projects.getIamPolicy`는 `service_account_iam`을 꺼도 `effective_access`가 켜져 있으면 남는다.
- [ ] 최종 확인: "실행 설정"의 기능별 수집 주기(`<기능 이름> · 수집 주기`. 수집 옵션 단계에는 주기가 없다), `저장 후 선택한
  기능의 최초 수집 실행`, 하단 `연동 저장`(또는 `연동 저장·수집 시작`) → "연동 설정을 저장했습니다" → `확인·계속` → (다른
  인증이 필요한 기능을 골랐으면 그 인증) → "선택한 기능의 설정을 마쳤습니다" → `연동 현황 보기`.
- [ ] 연동 현황 행이 `수집 중`("첫 수집을 기다리고 있습니다") → `정상`으로 바뀐다(`권한 다시 확인` 중에는 `권한 확인 중`).
  수집 범위를 정하지 않은 연결은 `설정 중`이다. `확인 필요`(권한 N개 없음·만료 임박·재인증), `일부 실패`(권한 부족·부분
  수집·실패 코드), `기능 모두 중지`, `중지됨`, `계정 연결됨`(인증만 저장)도 구별된다.
- [ ] 행 메뉴 `지금 수집`, `권한 다시 확인`, `수집 범위·인증 설정`, `연결 대상 현황`(관리자, 지원 공급자), `수집·탐지 현황
  보기`가 동작한다.
- [ ] 수집·탐지 현황(`?view=scans`)에서 첫 실행이 끝나고, 메타데이터 수집 실행의 "수집 보고"에 읽기(operation)마다 `완료`·
  `일부 완료`·`실패`와 사유 코드가 보인다(메타데이터 수집 실행만. 노출 검사 실행은 `읽은 곳`·`읽지 못한 곳`·`실패 상세`로
  본다). 보고의 사실(`selection`·`error_counts` 등)은 `GET /api/v2/coverage/runs/{run_id}?record_type=operation_report` 응답에 있다.
- [ ] Credential 목록(`?view=inventory`)에 발급 목록 항목이 유형별로 보인다. 행을 열면 "개요" 탭에 "권한과 접근 범위" 카드
  (서비스·권한·할 수 있는 일, 쓰기 권한은 `쓰기` 표시)와 "핵심 정보"(소유 계정·발급일·만료·마지막 사용·Vault 보관·활성
  여부)가 있다.
- [ ] 패널 메뉴 `발급 항목 보기`에 "서비스·수집 위치", "상태", "이 항목을 관측한 수집", "권한과 범위" 표(이름·효과·동작·
  리소스), "현재 관측"이 나온다.
- [ ] 메타데이터 수집 현황(`?view=metadata`): 유형마다 9개 항목(ID·이름·생성일·만료일·권한·생성자·소유자·마지막 사용·상태)이
  `지원`·`일부`·`미지원`으로 보이고 툴팁에 사유가 있다. 아래 공급자 절의 "첫 수집 후" 표기와 같아야 한다.
- [ ] (2026-10-07) `일부` 항목에 값이 없으면 값이 언제 생기는지(옵션 켜기, 로그 수집 등) 사유가 보인다.
- [ ] (2026-10-07) 금고 대조: 2026-10-06 이후 스캔한 노출과 수집한 금고를 다시 스캔·수집한 뒤, 같은 값을 둔 Credential의
  "핵심 정보" `Vault 보관`이 `대조 안 함`이 아니라 `보관 확인`이다. 고객 환경 해셔(`FINGERPRINT_CONTRACT_MISMATCH`)는 기존
  `customer_cli` 연결과 범용 금고만 쓰므로 이 문서 범위 밖이다.
- [ ] 같은 자격증명을 수집 연동과 `승인된 조치 실행` 연동에 함께 쓰면 두 행이 `확인 필요`가 된다. 수집 행에는 "조치 연동
  '…'도 이 자격증명을 씁니다 · 수집용은 따로 두세요", 조치 행에는 "수집 연동 '…'도 이 자격증명을 씁니다 · 조치용은 따로
  두세요"가 나온다(GCP ADC는 "…워커 자신의 Google Cloud 신원(ADC)을 씁니다 · …"). 시험에서는 조치용 자격증명을 따로 둔다
  (GCP는 조치 연결을 Google 로그인으로).
- [ ] 팀 설치(`AUTH_MODE=oidc`)에서 사람 목록은 로그인 IdP(같은 조직·테넌트·렐름)만 연결된다. 다른 IdP는
  `PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP`로 거절된다. 1인 설치는 어떤 IdP든 연결한다.

근거: web/console/views/integrations/auth-first.tsx, wizard.tsx, model.ts, page.tsx, setup.ts, web/console/views/credentials/tabs.tsx,
issued.tsx, drawer.tsx, web/console/views/metadata.tsx, logs.tsx, web/console/nav.ts, cremore/onboarding/catalog.py, check.py,
permissions.py, probe.py, sessions.py, cremore/api/routes/onboarding.py, cremore/api/metadata_coverage.py, docs/ONBOARDING.md,
docs/AUTH_FIRST_ONBOARDING_DESIGN.md, CHANGELOG.md

## AWS

### 준비

- [ ] CreMore API와 워커가 같은 서버 워크로드 신원으로 실행된다(EC2 인스턴스 역할, ECS·EKS 역할, 또는 사내 서버의 회사 IdP
  기계 신원 OIDC→STS). 개인 SSO·고정 키로는 새 연결을 만들 수 없다(`AWS_SERVER_WORKLOAD_IDENTITY_REQUIRED`).
- [ ] (2026-10-07, EC2에서 컨테이너로 실행할 때) IMDSv2 응답 홉 제한이 2다:
  `aws ec2 modify-instance-metadata-options --instance-id <ID> --http-put-response-hop-limit 2`.
- [ ] 서버 역할에 자기 역할을 읽는 `iam:GetRole`이 있다. 설정 도우미에 "서버 역할 자동 확인 권한 설정"이 보이면 `자기 역할
  조회 정책 복사`의 정책을 넣고 `AWS 신원 다시 확인`을 누른다.
- [ ] 관리자가 인증 단계의 `신원 승인·인증 확인`으로 서버 AWS 신원을 승인했다.
- [ ] 서버 역할에 설정 도우미 "CreMore 신원에 역할 맡기 권한 주기"의 인라인 정책(`정책 복사`)을 넣었다.
  (2026-10-07) 이 정책의 `Condition`은 등록 계정과 지금 연결하는 계정(`aws:ResourceAccount`)만, 모두 한 조직이면 그
  조직(`aws:ResourceOrgID`)을 가리킨다. 계정을 더하면 그때 보이는 정책으로 바꾼다.
- [ ] (조직 목록, 선택) Organizations 위임 관리자(권장) 또는 관리 계정의 서버 역할에 `조직 목록 조회 정책 복사`의
  `organizations:ListAccounts`·`ListAccountsForParent`·`ListOrganizationalUnitsForParent`·`ListRoots`·`DescribeOrganization`이
  있다(2026-10-07 OU 탐색 권한 추가).
- [ ] 대상 계정마다 그 계정 관리자가 CloudFormation 스택을 만들 수 있다(템플릿 `member-account-role.yaml`, 스택 `cremore-scanner`,
  역할 `CredentialExposureScannerRole`). 계정마다의 명령과 ExternalId는 마법사의 권한 확인 단계에서 나온다(아래 마법사 절).
- [ ] (2026-10-07, `AWS_ONBOARDING_TEMPLATE_URL`에 S3의 HTTPS 템플릿을 설정한 설치만) 등록 계정의 역할 안내(계정 ID·ExternalId)에
  `CloudFormation에서 만들기` 링크(`…/cloudformation/home?region=…#/stacks/create/review?…`)가 `CLI 명령 복사` 옆에 보인다(스택을
  처음 만들 때만).
- [ ] 발급 목록용으로 시험 계정에 IAM 사용자 1명 이상(액세스 키 1개 이상)이 있다. `IAM 정책 메타데이터 수집`은 기본으로
  켜져 있고 권한 점검이 첫 사용자의 정책을 읽는다.
- [ ] CloudTrail을 시험하면 선택 리전의 `cloudtrail:LookupEvents`가 있다(일반 AWS의 IAM 전역 이벤트는 `us-east-1` 포함).
- [ ] 노출 검사(S3)용 시험 버킷·접두사가 있다. SSE-KMS 객체는 `kms:Decrypt`(템플릿의 `EnableKmsDecrypt`·`KmsKeyArns`)도
  필요하다.
- [ ] (`현재 서버 권한 직접 사용(단일 계정)`을 시험할 때) 서버 신원에 설정 도우미 "CreMore 신원에 읽기 정책 넣기"의 정책을
  넣었다. 서버 신원의 계정 하나만 연결된다.
- [ ] (2026-10-08, 금고 값 대조를 시험할 때) 시험 계정에 가짜 값의 Secrets Manager 시크릿 1개 이상과, 필요하면 시험 경로
  (예: `/cremore-test/`) 아래 SecureString 파라미터 1개를 만든다. 같은 가짜 값을 노출 검사 대상(시험 버킷)에도 둔다.

### 마법사

- [ ] 계정·발급 목록 연결 → Amazon Web Services → `계정별 수집 역할 사용(권장)`. `현재 서버 권한 직접 사용(단일 계정)`은
  고급이고, `IAM Identity Center 권한 세트`·`고객 AWS 환경의 CreMore CLI`는 새 연결에서 고를 수 없다.
- [ ] 기능 `발급 목록 수집` → `대상 불러오기`: Organizations의 ACTIVE 계정이 나온다(작업 한 번에 최대 200개, `다음 목록
  불러오기`). 목록 권한이 없으면 등록 계정과 서버 자신의 계정만 나오고 `AWS_ORGANIZATIONS_NOT_AVAILABLE` 안내가 뜬다. 목록
  없이 하려면 인증 단계의 `계정 ID로 직접 연결`.
- [ ] (2026-10-07) 새 계정의 수집 역할은 마법사 안에서 만든다. `대상 불러오기` 뒤 '연동 대상'에서 계정을 고르면 권한 확인
  단계 설정 도우미에 "<계정 ID> · 수집 역할 설정"이 나온다. 여기에 `역할 설정값 복사`(ExternalId 포함)와 `역할 만들기 명령
  복사`(템플릿 `member-account-role.yaml`, 스택 `cremore-scanner`)가 있다. 그 계정 관리자가 같은 도우미의 `템플릿 받기`로 받은
  `member-account-role.yaml`이 있는 폴더에서 명령을 실행한 뒤 `권한 확인·다음`을 다시 누른다. 새 계정의 ExternalId는 초안마다
  새로 만드는 무작위 값이다(조직 설정에 StackSet용 ExternalId가 있으면 그 값). 그래서 초안이 만료되거나 마법사를 다시 열면
  바뀌고, 그때는 새 초안의 `역할 만들기 명령 복사`를 다시 실행해 같은 스택을 갱신한다(명령은 `aws cloudformation deploy`). 이미
  등록된 계정은 자기 ExternalId를 유지한다(`역할 설정값 복사` 값과 맞춘다).
- [ ] 수집 옵션: `IAM 정책 메타데이터 수집`(기본 켬), `CloudTrail 수집 사용`. 켜면 `CloudTrail 조회를 키 생성 이벤트로
  제한`(기본 켬), `CloudTrail 리전`(필수), `CloudTrail 조회 기간(일)`(1~90)이 나온다.
- [ ] 최종 확인의 "발견한 자격증명 조사" 스위치(`발견한 키의 실제 사용 내역`·`잠재 접근 권한 시뮬레이션`·`Secrets Manager
  인벤토리·메타데이터`)는 설치의 모든 AWS 연결에 적용된다(관리자에게만 보인다. `Secrets Manager 인벤토리·메타데이터`는 Secret
  저장소 대조를 골랐을 때만 나온다). 잠재 권한은 "실효 권한 검증 > AWS 잠재 권한"에서 시험한다.
- [ ] 노출 검사: 콘텐츠 검사 위치 연결 → `Amazon S3` → 버킷·접두사 선택.
- [ ] (2026-10-08) `Secret 저장소 대조` 계획에서 `별도 값 읽기 역할로 값 읽기`를 켜면 `값 읽기 역할 이름`(기본
  `CredentialVaultValueReaderRole`)·`대조할 시크릿 ARN`·`고객 관리형 KMS 키 ARN`이 나타나고, 끄면 숨는다. 시험 시크릿의 전체
  ARN(끝 여섯 글자 포함)을 적으면 계정의 `역할 만들기 명령 복사`에 `EnableVaultValueRead=true`와 `VaultSecretArns`·
  `VaultParameterPathArns`(고른 리전마다 경로와 `경로/*`)·`VaultKmsKeyArns`가 채워진다. 그 명령으로 스택을 만들거나, 이미 만든
  계정은 같은 명령으로 갱신한다.

### 권한 확인 정상 결과

- [ ] 계정마다 `scanner_access`(계정 스캐너 접근)가 확인된다(subject 계정 ID는 툴팁에서 본다).
- [ ] 발급 목록: `iam_read`(IAM 사용자 목록(iam:ListUsers)), `iam_policy_read`(IAM 사용자·그룹 정책 조회)가 확인된다.
  CloudTrail을 켰으면 고른 리전마다 `cloudtrail_read`(CloudTrail 이벤트 조회)가 확인된다.
- [ ] 노출 검사: `list_buckets`(S3 버킷 목록)가 확인된다.
- [ ] 알려진 동작, `Secret 저장소 대조`: `secrets_list`가 확인돼도 `secrets_values`(Secrets Manager 값 읽기)는 확인되지 않는다.
  수집 역할 이름이 템플릿 기본값 `CredentialExposureScannerRole`이면 상세는 `AWS_SCANNER_ROLE_DENIES_SECRET_VALUES`("CreMore의
  CloudFormation 템플릿은 수집 역할의 Secrets Manager 값 읽기(GetSecretValue)를 명시적으로 거부하며, 허용을 더해도 바뀌지
  않습니다. 금고 대조를 빼고 다시 확인하세요.")다. 다른 역할이나 `현재 서버 권한 직접 사용`이면 `VALUE_READ_PERMISSION_NOT_CHECKED`다.
  `Parameter Store 경로 접두어`를 넣으면 `ssm_list`(Parameter Store 파라미터 목록(ssm:DescribeParameters, 이름만))가 확인된다.
  `ssm_values`(Parameter Store 값 복호화 읽기)는 같은 템플릿 역할이면 `AWS_SCANNER_TEMPLATE_GRANTS_NO_PARAMETER_VALUES`("CreMore의
  CloudFormation 템플릿은 수집 역할에 Parameter Store 값 읽기(GetParametersByPath)를 주지 않고, 사전 점검은 값을 읽어 권한을
  확인하지 않습니다. 경로를 비우고 다시 확인하세요."), 아니면 `VALUE_READ_PERMISSION_NOT_CHECKED`다. 두 행 모두 필수라 활성화가
  막히는 것이 현재 코드의 정상 결과다.
- [ ] (2026-10-08) 위 두 행은 수집 역할로 값을 읽으려 할 때의 결과다. `별도 값 읽기 역할로 값 읽기`를 켜면 목록 권한
  (`secrets_list`·`ssm_list`)은 묻지 않고 `secrets_values`(경로를 넣었으면 `ssm_values`도)가 값 읽기 역할로 확인된다. 점검은 그
  역할을 맡아 본 뒤 적은 시크릿·경로마다 `iam:SimulatePrincipalPolicy`로 판단하며 값을 읽지 않는다(CloudTrail에 세션 이름
  `cremore-vault-check`의 `AssumeRole`과 `SimulatePrincipalPolicy`가 남고, `GetSecretValue`·`ListSecrets`는 없다). 스택에 넣지 않은 시크릿을 하나 적으면
  `VALUE_READER_POLICY_DENIES`, 그 계정의 시크릿을 하나도 적지 않으면 `AWS_SECRET_ARNS_REQUIRED`, 스택을 갱신하기 전이면
  `VALUE_READER_ASSUME_DENIED`다. 권한 경계·SCP로 막으면 `VALUE_READER_POLICY_EXPLICITLY_DENIED`다([설계안](AWS_VAULT_VALUE_READER_DESIGN.md)).

### 첫 수집 후 정상 결과

- [ ] `IAM 사용자 액세스 키`: 지원 ID·생성일·소유자·마지막 사용·상태. 일부 권한("발급 목록의 IAM 정책 메타데이터 수집을 켜면
  사용자·그룹 정책을 읽습니다. 실제 접근 권한 검증은 아닙니다"), 생성자("선택한 리전·기간의 CloudTrail CreateAccessKey
  이벤트에서 키 ID가 일치할 때 확인합니다"). 미지원 이름("액세스 키에는 이름이 없습니다"), 만료일("액세스 키에는 만료일이
  없습니다").
- [ ] `서비스 전용 Credential`(CodeCommit·Keyspaces 사용자 이름·비밀번호, Amazon Bedrock·Claude Platform on AWS·CloudWatch·
  CloudWatch Logs 장기 API 키): 지원 ID·이름·생성일·소유자·상태. 일부 권한("어느 서비스에 쓰는지만 줍니다"). 미지원
  만료일("API 키의 만료일(ExpirationDate)은 수집하지 않으며, 만료된 키는 상태(Expired)로 보입니다"), 생성자("이 자격증명
  종류의 생성자 대조는 지원하지 않습니다"), 마지막 사용("마지막 사용을 주지 않습니다").
- [ ] 액세스 키의 "권한과 접근 범위" 카드에 정책 이름, `Allow 문장에 적힌 작업 · N개`, "거부 문장 N개 · 조건부 문장 N개 ·
  권한 경계 …", "IAM 사용자·그룹 정책의 조회 결과입니다. … 실제 접근 권한이 아닙니다."가 나온다.
- [ ] CloudTrail을 켰으면 "핵심 정보"의 `키 생성자`가 CreateAccessKey 근거로 채워진다(조회 기간 안에 만든 키만).
- [ ] (2026-10-07, 해당 키가 있을 때만) 만료된(Expired) Bedrock·CloudWatch API 키가 있어도 IAM 수집이 `일부 완료`가 되지 않고
  그 키의 상태가 Expired로 보인다.
- [ ] S3 노출 검사 실행이 고른 버킷·접두사의 객체를 읽는다(수집·탐지 현황의 `읽은 곳`·`읽지 못한 곳`).
- [ ] (2026-10-08, 값 읽기 역할) 금고 수집이 적은 시크릿만 읽는다(시크릿 목록을 읽지 않는다). CloudTrail에 수집 역할의
  `AssumeRole`(세션 이름 `cremore-vault-<연결 ID>`)과 그 세션의 `GetSecretValue`가 남고 수집 역할 자신의 `GetSecretValue`는
  없다. 시험 버킷에서 발견한 같은 값의 Credential은 금고 대조가 일치로 보인다. 원문 값은 화면·로그 어디에도 없다. 수집이
  `완료`면 Secret 저장소(`?view=vaults`)에서 이 수집의 목록 근거가 "운영자가 전체라고 선언함"이다(목록을 읽지 않고 적은 ARN만
  읽었으므로. 이름 없는 값이 섞여 `일부 완료`면 "—"다).
- [ ] (2026-10-08, 값 읽기 역할) 설치의 AWS 자동 수집 설정이 그 계정을 넣지 않으면 그 금고의 주기 수집은 돌지 않고
  (`VALUE_READER_AUTOMATION_DISABLED`), `지금 수집`은 돈다.

### 문제 신호

- [ ] `ASSUME_ROLE_DENIED`: 서버가 수집 역할을 맡지 못함 → 역할의 신뢰 대상·ExternalId와 서버의 `sts:AssumeRole`(위 인라인
  정책)을 역할 설정값과 비교한다.
- [ ] `SCANNER_ACCESS_REQUIRED`: 계정 접근이 막혀 나머지 권한은 아직 확인하지 않음 → `scanner_access`부터 해결한다.
- [ ] `ACCESS_DENIED`(그 읽기 거절), `REQUEST_FAILED`(요청 실패).
- [ ] `IAM_POLICY_READ_DENIED`(수집 역할의 GetUser·List/GetUserPolicy·List/GetGroupPolicy·GetPolicy·GetPolicyVersion),
  `IAM_POLICY_NO_USER_TO_CHECK`(IAM 사용자가 없음 → 옵션을 끄거나 사용자 추가), `IAM_POLICY_COLLECTION_DISABLED`(설치의
  `IAM_POTENTIAL_ACCESS_MODE=disabled`), `IAM_POLICY_CHECK_LIMIT`, `IAM_POLICY_READ_FAILED`.
- [ ] `AWS_SCANNER_IDENTITY_NOT_APPROVED`(신원 승인 전), `AWS_SCANNER_IDENTITY_CHANGED`(승인한 신원과 지금 신원이 다름 → 다시
  승인), `AWS_SERVER_WORKLOAD_IDENTITY_REQUIRED`, `RUNTIME_IDENTITY_IS_ONE_ACCOUNT`.
- [ ] `AWS_ORGANIZATIONS_ACCESS_DENIED`(조직 목록 거절, OU 제한이나 다음 페이지 포함), `AWS_MEMBER_ROLE_SETUP_REQUIRED`,
  `AWS_ACCOUNT_SETTINGS_CHANGED`, `AWS_ACCOUNT_NOT_DISCOVERED`, `ACCOUNT_REGISTERED_WITH_ANOTHER_ACCESS`,
  `ACCOUNT_ALREADY_REGISTERED`.
- [ ] `AWS_REGIONS_ACCESS_DENIED`: 직접 사용 방식에서 `ec2:DescribeRegions`가 거절됨.
- [ ] `WORKER_AWS_NOT_CONFIGURED`: 워커에 AWS 설정이 없음.
- [ ] 연동 행의 "CreMore의 AWS 로그인이 필요합니다"(`AWS_LOGIN_REQUIRED`) 또는 "승인한 AWS 신원과 지금 신원이 다릅니다".
- [ ] (2026-10-07, 기존 1인 설치의 IAM Identity Center 연결만) AWS 로그인 안내 명령이 `aws sso login --use-device-code`다. 팀
  설치에서는 `AWS_SSO_LOGIN_SOLO_ONLY`로 거절된다. 코드는 스캔 권한 세트만 가진 시험 전용 IAM Identity Center 사용자로
  승인한다(승인한 사람이 CreMore의 AWS 신원이 된다).
- [ ] (2026-10-07, 유럽 주권 클라우드 계정이 있을 때만) `aws-eusc` 계정과 리전 `eusc-de-east-1`이 인식된다(리전 목록에 있다).

### 정리

- [ ] 연동 서비스에서 시험 연동을 `연동 해제`한다. 시험 계정의 IAM 사용자·액세스 키와 시험 버킷 객체를 지운다.
- [ ] 시험용으로만 만든 `cremore-scanner` 스택, 서버 역할에 넣은 인라인 정책(역할 맡기·조직 목록·읽기 정책), 기기 인증에 쓴
  시험 IAM Identity Center 사용자를 지운다.

근거: aws/backend/cremore_aws_provider/onboarding.py, onboarding_discovery.py, onboarding_roles.py, aws_org_discovery.py,
aws_identity.py, cremore/api/aws_support.py, cremore/config.py, web/console/views/integrations/guide.tsx, aws-identity.tsx,
aws-settings.tsx, auth-first.tsx, model.ts, copy.ts, aws/README.md, docs/AWS_VAULT_VALUE_READER_DESIGN.md,
docs/AUTH_FIRST_ONBOARDING_DESIGN.md, CHANGELOG.md

## Google Cloud

### 준비

- [ ] 조직에 속한 시험 프로젝트 1개(실효 판정은 조직 수준 역할이 필요하다).
- [ ] 인증 신원: 워커의 ADC(권장. Google Cloud에서는 연결된 서비스 계정, 그 밖에서는 Workload Identity Federation. 마법사
  안내대로 워커에 `GOOGLE_APPLICATION_CREDENTIALS` 키 파일이나 gcloud 사용자 로그인을 두지 않는다) 또는 Google 로그인(고급).
- [ ] 운영자 PC에는 연결된 서비스 계정이 없다. 로컬 안내([GCP ADC 설정](integration/GCP_ADC_SETUP_KO.md))는 `gcloud auth
  application-default login`(사람의 사용자 ADC)을 워커에 마운트하고, 마법사 안내는 사용자 로그인을 두지 말라고 한다. 어느 쪽을
  썼는지 기록하고, 사용자 ADC로 시험하면 아래 프로젝트 수준 권한만 가진 시험 전용 Google 계정으로 로그인한다.
- [ ] (Google 로그인을 시험할 때, 2026-10-07) Google Cloud 콘솔의 Google Auth Platform에서 브랜딩·대상(조직 사람만이면 내부,
  외부 앱은 테스트가 아닌 프로덕션. 테스트 상태는 7일 뒤 멈춘다)을 정하고, 클라이언트에서 웹 애플리케이션을 만들어 승인된
  리디렉션 URI에 `…/gcp/oauth/callback`을 넣었다. 클라이언트 ID·시크릿(Google이 만들 때 한 번만 보여 줌)은 마법사의 "Google
  로그인 앱 설정"에만 넣는다.
- [ ] 프로젝트 수준 권한(연결 신원):
  - 발급 목록: `iam.serviceAccounts.list`, `iam.serviceAccountKeys.list`, `iam.serviceAccountKeys.get`, `apikeys.keys.list`
    (선택 `resourcemanager.projects.get`, `serviceusage.services.get`).
  - Secret 저장소 대조: `secretmanager.secrets.list`, `secretmanager.versions.list`와 위 발급 목록 4개(한 수집이 두 기능을 같이
    읽는다). 리전을 고르면 `secretmanager.locations.list`.
  - 노출 검사: `storage.buckets.list`, `storage.objects.list`, `storage.objects.get`.
  - 옵션: `audit_logs` → `logging.logEntries.list`·`logging.privateLogEntries.list`, `api_metrics` → `monitoring.timeSeries.list`,
    `service_account_iam` → `resourcemanager.projects.getIamPolicy`, `secret_iam`(금고) →
    `resourcemanager.projects.getIamPolicy`·`secretmanager.secrets.getIamPolicy`·`iam.roles.get`, `effective_access` → "실효 권한
    검증 > GCP".
  - 값 읽기(시험할 때만): `apikeys.keys.getKeyString`, `secretmanager.versions.access`.
- [ ] (2026-10-07) `승인된 조치 실행`(별도 연결)은 네 권한만 담은 사용자 지정 역할: `iam.serviceAccounts.get`,
  `iam.serviceAccountKeys.get`, `iam.serviceAccountKeys.disable`, `iam.serviceAccountKeys.delete`.
  `roles/iam.serviceAccountKeyAdmin`은 키 생성까지 허용하므로 쓰지 않는다. 수집 연결이 워커 ADC면 조치 연결은 `Google 로그인`으로
  따로 둔다. 둘 다 ADC면 수집용 워커 신원이 키 비활성화·삭제 권한까지 갖게 되고 두 행이 공유 경고를 보인다.
- [ ] API 사용 설정: IAM, API Keys, Secret Manager, Service Usage, Cloud Resource Manager(권한 점검의 `testIamPermissions`와 대상
  조회 `projects.search`. 서비스 계정(ADC)의 프로젝트나 Google 로그인 앱의 프로젝트에서 켜져 있어야 한다). 옵션을 시험하면
  Cloud Logging(`audit_logs`)·Cloud Monitoring(`api_metrics`), 노출 검사는 Cloud Storage.
- [ ] 시험 데이터: 사용자 관리 서비스 계정 키 1개 이상, API 키 1개(제한 있는 키와 없는 키), 시험 값만 담은 시크릿 1개.

### 마법사

- [ ] 계정·발급 목록 연결 → Google Cloud → `워크로드 신원 또는 서비스 계정(ADC)`(권장) 또는 `Google 로그인`(고급, 기능 단계
  버튼이 `Cloud 접근 동의·대상 불러오기`).
- [ ] (Google 로그인) `인증 확인`의 첫 동의는 `openid`·`email`만 묻는다. 기능을 고른 뒤 `Cloud 접근 동의·대상 불러오기`에서
  `https://www.googleapis.com/auth/cloud-platform`까지 다시 묻는다.
- [ ] (Google 로그인) 위 "프로젝트 수준 권한"만 가진 시험 전용 Google 계정으로 승인한다(CreMore는 그 계정의 IAM 역할이 허용하는
  일을 갱신 토큰으로 계속 할 수 있다). 소유자·개인·운영 계정으로 승인하지 않고, 끝나면 Google 계정에서 승인을 철회한다.
- [ ] 대상: `projects.search`로 보이는 ACTIVE 프로젝트에서 시험 프로젝트를 고른다.
- [ ] 수집 옵션: `노출 발견값과 대조하도록 키·시크릿 값 읽기`(끔), `삭제된 API 키 포함`(기본 켬), `Cloud Audit Logs: 서비스
  계정 키 사용 근거`, `Cloud Monitoring: API 키 사용 구간`, `서비스 계정의 프로젝트 IAM 역할`, `키가 있는 서비스 계정: 고위험
  권한의 실효 판정(Policy Troubleshooter)`, `감사 로그·사용량 조회 기간(일)`. 금고는 `선택한 시크릿: IAM 정책 접근 후보`, `리전별
  Secret Manager 위치(글로벌 시크릿은 기본 포함)`.
- [ ] (선택) 조직·폴더의 하위 프로젝트 찾기: `다른 인증·기존 설정`에서 범위 `조직(하위 프로젝트 찾기)` 또는 `폴더(하위 프로젝트
  찾기)`와 번호를 넣는다. 발급 목록만 가능하고(`GCP_DISCOVERY_IS_INVENTORY_ONLY`) 권한은 `resourcemanager.projects.list`·
  `resourcemanager.folders.list`다. 수집 보고에 `gcp.resource_manager.projects`·`gcp.resource_manager.folders`가 보이고, 찾은
  프로젝트는 맥락 항목으로만 남아 Credential 목록에 새 항목이 생기지 않는다.
- [ ] (2026-10-07) 기존 설정 화면(`다른 인증·기존 설정`, 저장한 연결의 `수집 범위·인증 설정`)의 Google 승인 상자에 "Google은
  Google Cloud 전체 접근(cloud-platform 범위) 승인을 묻습니다…"가 있고, Google 동의 화면이 실제로 Cloud 전체 접근을 묻는다(요청
  범위 `openid`·`email`·`https://www.googleapis.com/auth/cloud-platform`).
- [ ] 노출 검사(GCS): 콘텐츠 검사 위치 연결 → `Google Cloud · 콘텐츠 검사` → 그 계정 연결(`… · 이 계정에 기능 추가`) → 프로젝트
  → 4단계 "조회된 검사 대상"에서 시험 버킷을 고른다. 수집·탐지 현황에 `GCS · <프로젝트>` 실행이 끝난다.

### 권한 확인 정상 결과

- [ ] 고른 기능·옵션의 권한 이름(예: `iam.serviceAccounts.list`)마다 확인된다. 점검은 프로젝트의 `testIamPermissions` 한 번이고
  권한마다 GRANTED·MISSING이 따로 나온다(없는 권한은 상세 없이 `MISSING`).
- [ ] `resourcemanager.projects.get`·`serviceusage.services.get`은 비필수라 없음이어도 다음 단계로 간다(새 마법사에는 없고
  툴팁에서 본다).
- [ ] `승인된 조치 실행`: 네 권한이 확인된다. Google 로그인이면 첫 권한(`iam.serviceAccounts.get`) 태그 툴팁의 subject가
  `google:<이메일>`이다(`수집 범위·인증 설정`). ADC는 Google tokeninfo가 확인된 이메일을 줄 때만 subject가 붙고, 그 밖에는
  비어 있다.

### 첫 수집 후 정상 결과

- [ ] `서비스 계정 키`(사용자 관리·Google 관리): 지원 ID·생성일·만료일·소유자·상태. 일부 권한("키는 서비스 계정의 IAM 권한을
  그대로 씁니다. 실효 판정을 켜면 Policy Troubleshooter가 프로젝트에서 허용한 고위험 권한을 보여 줍니다"), 생성자("감사 로그의
  성공한 생성 응답이 이 키 ID를 명시한 경우에만 연결합니다"), 마지막 사용("감사 로그에서 이 키 ID가 명시된 성공한 사용만
  연결합니다. 빈 기간은 미사용 증거가 아닙니다"). 미지원 이름("키에는 이름이 없습니다").
- [ ] `API 키`: 지원 ID·이름·생성일·상태. 일부 권한("API·앱 제한을 둔 키만 제한 내용을 줍니다"), 생성자, 소유자("서비스 계정에
  묶은 키만 줍니다"), 마지막 사용("Cloud Monitoring에서 이 키 UID의 사용량이 관측된 마지막 구간입니다…"). 미지원 만료일("API
  키에는 만료일이 없습니다").
- [ ] (2026-10-07) 메타데이터 수집 현황 → `서비스 계정 키` 행 → "수집된 토큰" 탭에서 값이 없는 키의 "권한"이 위 사유(실효
  판정을 켜면 …)로 보인다.
- [ ] (2026-10-07) 권한 표의 쓰기·읽기 표시는 권한 이름의 동사로 정해진다: `secretmanager.versions.access`·`storage.objects.get`은
  읽기, `iam.serviceAccountKeys.create`·`iam.serviceAccounts.actAs`는 `쓰기`. "권한과 접근 범위" 카드에는 "접근 가능"인 권한만
  나온다.
- [ ] 금고: Secret 저장소(`?view=vaults`) 목록에 이 수집과 마지막 수집 시각이 보인다(값 읽기를 껐으면 값 대조는 없다).

### 문제 신호

- [ ] 모든 행이 `<권한> · 이 조회가 거절되었습니다. 표시된 작업의 권한·리소스 공유·조직 정책을 확인하세요.`(`HTTP_403`, 상태
  `MISSING`).
- [ ] 모든 행이 `HTTP 400`(툴팁에서는 `알 수 없음`): 요청 자체가 거부됨. `effective_access`를 켰을 때만 나오면 "문서로 확정하지
  못한 항목 확인법 a"로 간다.
- [ ] `GCP_PROJECT_LIST_HTTP_403`(대상 조회 거절: Cloud Resource Manager API·프로젝트 접근·조직 정책), `GCP_SIGN_IN_REQUIRED`,
  `GCP_OAUTH_SETUP_REQUIRED`, `GCP_OAUTH_STATE_INVALID`, `GCP_AUTH_RESPONSE_INVALID`.
- [ ] `GCP_VALUE_CHOICES_SET_BY_THE_PROJECT_COLLECTION`: 발급 목록과 금고의 값 읽기 선택이 다름(한 프로젝트를 한 수집이 읽는다).
- [ ] 수집 실패 코드: 인증 실패는 실행 전체가 `실패`이고 `GCP_ADC_NOT_CONFIGURED`·`GCP_ADC_REFRESH_FAILED`·
  `GCP_ADC_TOKEN_UNAVAILABLE`이다. 읽기 거절은 그 읽기만 `일부 완료`이고 `PERMISSION_DENIED`·`API_DISABLED`·
  `PERMISSION_DENIED_OR_API_DISABLED`(접두어 없음)다. `GCP_PERMISSION_DENIED_OR_API_DISABLED`는 노출 검사 위치의 신원 점검과
  Google 로그인 토큰 요청에서 나온다. `UNRESOLVED_ITEMS`는 값 대조에서 확정하지 못한 항목이 남을 때다(GCP 통합 가이드 8절).
- [ ] Google 로그인 수집이 멈춤: 승인 철회, 테스트 상태 외부 앱의 7일, Google Cloud 세션 길이 정책, 6개월 미사용 → 다시
  로그인한다.

### 정리

- [ ] 시험 서비스 계정 키·API 키·시크릿을 지우고, 조치용 사용자 지정 역할과 그 바인딩, 시험으로 준 프로젝트 권한을 회수한다.
- [ ] Google 로그인을 시험했으면 Google 계정에서 CreMore 승인을 철회하고 시험용 OAuth 클라이언트를 지운다. 사용자 ADC를 썼으면
  `gcloud auth application-default revoke`로 지운다.

근거: gcp/backend/cremore_gcp_provider/onboarding.py, oauth.py, remediation.py, gcp_auth.py, metadata/adapter.py, gcp/README.md,
docs/integration/GCP_TOTAL_GUIDE_KO.md, GCP_ADC_SETUP_KO.md, docs/PROVIDER_ACTIONS.md, cremore/api/gcp_oauth.py,
web/console/views/integrations/copy.ts, google-client.tsx, auth-first.tsx, model.ts, page.tsx, web/console/views/metadata.tsx,
cremore/api/credential_records.py, CHANGELOG.md

## Google Workspace (사람 목록)

### 준비

- [ ] 이 수집 전용 서비스 계정과 키(JSON). 키가 있는 Google Cloud 프로젝트에서 Admin SDK API를 사용 설정했다.
- [ ] (2026-10-07) 최고 관리자가 관리 콘솔 > 보안 > 액세스 및 데이터 관리 > API 제어 > 도메인 전체 위임 관리에서 서비스 계정의
  클라이언트 ID에 `https://www.googleapis.com/auth/admin.directory.user.readonly`(전체 URL)를 허용했다. 적용까지 최대 24시간.
  사람이 Google 계정으로 콘솔에 로그인하는 팀 설치면 `https://www.googleapis.com/auth/admin.directory.group.member.readonly`도.
  클라이언트 ID에는 이 범위만 허용한다.
- [ ] 위임받을 계정은 시험 도메인의 이 수집 전용 최고 관리자다(일부 조직 단위만 보는 관리자는 거절된다). 사람이 로그인하지
  않게 두고 2단계 인증을 강제한다.

### 마법사

- [ ] 기타 설정 → 디렉터리 동기화 → Google Workspace → `서비스 계정(도메인 전체 위임)`. `기본 도메인`, `위임받을 최고 관리자
  이메일`, `서비스 계정 키(JSON)`(JSON 파일 내용 그대로, 넣은 뒤 키 파일은 지운다).
- [ ] 수집 옵션 `사람 이름·이메일·부서 보관(담당자·연락 대상 표시)`(기본 켬, 시험 도메인 사용자만 둔다). 실행 설정의
  `사람 목록 · 수집 주기` 기본 `60분마다`.

### 권한 확인 정상 결과

- [ ] `users_read`(`…/admin.directory.user.readonly` 도메인 전체 위임)가 확인된다. 점검은 삭제된 사용자 목록과 전체 사용자
  목록을 모두 읽어야 확인됨이 된다.

### 첫 수집 후 정상 결과

- [ ] 퇴사자 Credential(`?view=leavers`)의 "IdP 연결" 표에 이 연결(`Google Workspace · <도메인>`)이 `정상`과 마지막 수집 시각으로
  보이고, 수집·탐지 현황의 실행이 `완료`다.

### 문제 신호

- [ ] `GOOGLE_WORKSPACE_DELEGATION_NOT_ALLOWED`: 위임 미허용. 새 마법사는 `인증 확인` 배너에 허용 안내("최고 관리자가 관리 콘솔 >
  보안 > … 이 클라이언트 ID에 … 범위를 허용해야 함(적용까지 최대 24시간)")를 보인다. 허용할 클라이언트 ID는 키 JSON의
  `client_id`다(저장한 연결의 권한 확인에서는 subject로도 나온다).
- [ ] `GOOGLE_WORKSPACE_ADMIN_NOT_SUPER_ADMIN`, `GOOGLE_WORKSPACE_ADMIN_OUTSIDE_DOMAIN`, `GOOGLE_WORKSPACE_ADMIN_INVALID`.
- [ ] `GOOGLE_WORKSPACE_API_NOT_ENABLED`(Admin SDK API), `GOOGLE_WORKSPACE_TOKEN_REFUSED`(키·관리자 주소),
  `GOOGLE_WORKSPACE_KEY_INVALID`, `GOOGLE_WORKSPACE_ACCESS_DENIED`, `GOOGLE_WORKSPACE_RATE_LIMITED`.

### 정리

- [ ] 서비스 계정 키와 도메인 전체 위임 항목을 함께 지운다. 시험용으로 만든 수집 전용 최고 관리자 계정을 지운다.

근거: gcp/backend/cremore_gcp_provider/workspace/onboarding.py, workspace/identity.py, gcp/README.md, docs/LEAVER_CHECK.md,
web/console/views/integrations/copy.ts, model.ts, web/console/views/leavers/page.tsx, CHANGELOG.md

## Microsoft (Entra ID · Azure · Azure DevOps)

### 준비

- [ ] 시험 테넌트. 인증은 `앱 등록 인증서(CreMore가 만들고 교체)`(워커가 관리 ID·워크로드 신원 연합을 쓸 수 없을 때, 공용
  클라우드만) 또는 `워크로드 신원 또는 관리 ID`.
- [ ] 인증서 방식: Microsoft Entra 관리 센터의 앱 등록에서 새 등록(이 조직 디렉터리만, 리디렉션 URI 없음) 또는 Azure Cloud
  Shell(Bash)에서 `만들기 명령 복사`(`az ad app create … --sign-in-audience AzureADMyOrg`, `az ad sp create`). 마법사에서
  `인증키 만들기` 뒤 받은 인증서를 '인증서 및 비밀 → 인증서 → 인증서 업로드' 또는 `올리기 명령 복사`
  (`az ad app credential reset --id <앱> --append --cert …`)로 올렸다. 올라가는 것은 공개 인증서뿐이다. 명령을 붙여 넣기 전에
  `az account show --query tenantId -o tsv`가 시험 테넌트인지 확인한다. `인증키 만들기`부터 업로드·관리자 동의를 거쳐
  `연동 저장`까지 30분 안에 마친다(초안 만료).
- [ ] Microsoft Graph 애플리케이션 권한(권한 확인 단계 설정 도우미의 "Microsoft Graph 권한과 관리자 동의"): Application.Read.All
  (인증서 교체·앱 목록), Organization.Read.All(발급 목록), User.Read.All(사람 목록), AuditLog.Read.All(로그인·감사 옵션을 켤
  때만), RoleManagement.Read.Directory(`app_permissions`를 켤 때만). 관리자 동의는 권한 있는 역할 관리자, 명령의
  admin-consent 줄은 전역 관리자.
- [ ] (2026-10-07, 관리 ID일 때) 포털에 API 권한 화면이 없으므로 "Microsoft Graph 앱 역할 할당"의 명령
  (`az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$MI/appRoleAssignments" …`)을 권한 있는 역할
  관리자가 Cloud Shell(Bash)에서 `MI`에 신원의 개체(주체) ID를 넣고 실행했다.
- [ ] (2026-10-08, `워크로드 신원 또는 관리 ID`) 워커의 `azure-identity`가 1.24 이상이다(`python -m pip show azure-identity`).
  워커 환경에 사람 계정의 `AZURE_USERNAME`·`AZURE_PASSWORD`를 두지 않는다.
- [ ] Azure 역할("Azure 역할 할당", 그 범위의 소유자·사용자 액세스 관리자·역할 기반 액세스 제어 관리자가 실행): 구독 `Reader`
  (발급 목록), 스토리지 계정 `Storage Blob Data Reader`(노출 검사), Key Vault마다 `Key Vault Reader`(Azure RBAC 권한 모델, 금고),
  값 대조 때만 `Key Vault Secrets User`, 키 지문을 읽을 스토리지 계정에만 `Reader and Data Access`(그 키로 계정의 모든 데이터에
  접근 가능). 예전 액세스 정책 모델 Key Vault는 비밀 List(키·인증서를 고르면 키 List, 인증서 List·Get), 값 대조 때만 비밀 Get.
- [ ] (2026-10-07) 대상을 여러 개 고르면 "Azure 역할 할당" 명령에 고른 구독·스토리지·Key Vault마다 줄이 생긴다.
- [ ] `대상 불러오기` 전에 연결 신원에 시험 구독 Reader를 직접 준다: `az role assignment create --assignee <앱 ID> --role "Reader"
  --scope /subscriptions/<구독 ID>`(관리 ID는 `--assignee-object-id <개체 ID> --assignee-principal-type ServicePrincipal`). 주지 않으면
  발급 목록 대상은 `Entra ID · <테넌트 ID>` 하나뿐이고, 노출 검사·금고에는 "조회된 대상이 없습니다. 공유 범위와 목록 조회 권한을
  확인하세요."가 나온다.
- [ ] 로그인 기록(`credential_sign_ins`)은 Microsoft Entra ID P1 또는 P2 테넌트에서 시험한다. P1·P2가 없는 테넌트로는 아래 문제
  신호의 라이선스 문구를 확인한다.
- [ ] (Azure DevOps, 선택) 조직이 이 테넌트의 Microsoft Entra에 연결돼 있다. 조직 설정 → 사용자에서 앱(서비스 주체)을 Basic
  액세스로 추가하고 검사할 프로젝트에 넣었다. PAT 목록은 Project Collection Administrators 그룹(조직 설정 → 권한)만 읽으며,
  그 그룹에서 앱은 조직 전체 관리자가 되어 사용자 PAT를 폐기할 수도 있다(시험 조직만).
- [ ] 앱 자격증명 권한(`app_permissions`·`app_azure_roles`)은 "실효 권한 검증 > Azure 앱 자격증명 권한"에서 준비한다.

### 마법사

- [ ] 계정·발급 목록 연결 → Microsoft. 인증 단계에 테넌트 ID. 인증서 방식은 애플리케이션(클라이언트) ID → `인증키 만들기` →
  인증서 업로드 → `키 등록 완료·인증 확인`.
- [ ] 기능: 발급 목록 수집, Secret 저장소 대조(Key Vault), 사람 목록. 평문 노출 검사(스토리지 계정)는 계정 연결이 정상이 된 뒤
  `콘텐츠 검사 위치 연결` → `Microsoft · 콘텐츠 검사`에서 그 연결을 골라(`… · 이 계정에 기능 추가`) 더한다.
- [ ] 새 마법사에는 Azure DevOps 입력이 없다. `Azure DevOps 조직(선택)`은 인증 단계 하단 `다른 인증·기존 설정`으로 열리는 기존
  설정 화면의 '연동 대상'에 넣고 `연결 확인`으로 점검한다. 새 마법사의 대상 조회는 Azure DevOps 프로젝트를 내놓지 않으므로,
  Azure DevOps 프로젝트 노출 검사를 켠 화면 경로를 기록한다.
- [ ] 발급 목록 옵션: `자격증명 로그인 기록(Microsoft Graph 베타)`, `디렉터리 감사: 자격증명 생성자`, `감사 기록 조회 기간(일)`,
  `앱 자격증명이 할 수 있는 일: 애플리케이션 권한·Entra 역할`, `앱 자격증명이 할 수 있는 일: Azure 역할`, `앱 워크로드 신원 연합
  설정`, `Key Vault 대조용 공개 인증서`, `신원이 볼 수 있는 구독 목록도 수집`, `키 지문을 읽을 스토리지 계정(리소스 ID)`(값 읽기,
  시험할 때만).
- [ ] 금고 옵션: `노출 발견값과 대조하도록 시크릿 값 읽기`(끔), `리소스 버전 목록 포함`, `복구 가능한 삭제 리소스 포함`, `키
  메타데이터(키 원문 제외)`, `인증서 메타데이터`, `Entra 대조용 공개 인증서(인증서 목록 포함)`.
- [ ] 사람 목록: 수집 옵션 `사람 이름·이메일·부서 보관(담당자·연락 대상 표시)`, 실행 설정의 `사람 목록 · 수집 주기` 기본
  `60분마다`.
- [ ] (2026-10-07) 로그인·감사 옵션을 켜면 "Microsoft Graph 권한과 관리자 동의" 명령의 `--api-permissions`에 AuditLog.Read.All
  (`b0afded3-3588-46d8-8b3d-9842eff778da=Role`)이 들어가고, 끄면 빠진다.

### 권한 확인 정상 결과

- [ ] 발급 목록: `applications_read`(Application.Read.All), `organization_read`(Organization.Read.All) 확인됨. 구독을 골랐으면
  `subscription_read`(구독 읽기 권한자) 확인됨(subject 구독 ID는 툴팁). 구독 없이 Entra 대상만 고르면 `subscription_read` 행이
  나오지 않는다.
- [ ] 옵션: `credential_sign_ins`(AuditLog.Read.All, P1·P2 테넌트)·`directory_audits`(AuditLog.Read.All), `role_management_read`
  (RoleManagement.Read.Directory), `root_role_assignments`(테넌트 루트 관리 그룹의 역할 할당·정의 읽기), `subscriptions_list`
  확인됨.
- [ ] Azure DevOps 조직을 넣었으면(기존 설정 화면) `graph_read`, `token_administration` 확인됨(실제 목록 호출로 확인한다. Graph
  사용자 목록이 거절됐거나 비어 있으면 `token_administration`은 "확인할 사용자 없음"(`NO_USER_TO_ASK_ABOUT`)이고, 거절이면 먼저
  `graph_read`가 거절된다).
- [ ] 노출 검사(콘텐츠 검사 위치 연결에서 더한 뒤): `blob_read`(Storage Blob 데이터 읽기 권한자) 또는 `code_read`(Azure DevOps
  코드(읽기)). 인증서 방식이면 `applications_read`도.
- [ ] 금고: Key Vault마다 `key_vault_list`, 옵션별 `key_vault_keys`·`key_vault_certificates`·`key_vault_deleted`·
  `key_vault_public_certificates` 확인됨.
- [ ] 사람 목록: `users_read`(User.Read.All) 확인됨.
- [ ] 알려진 동작: `노출 발견값과 대조하도록 시크릿 값 읽기`나 `키 지문을 읽을 스토리지 계정`을 켜면 `key_vault_values`·
  `storage_keys_read`가 "현재 사전 점검으로 값 읽기 권한을 확인할 수 없습니다. …"(`VALUE_READ_PERMISSION_NOT_CHECKED`)라
  활성화가 막힌다. 값 읽기를 끄면 메타데이터는 연결된다.
- [ ] (2026-10-08) 워커 신원은 사람의 로그인을 쓰지 않는다. 관리 ID·워크로드 신원(`AZURE_FEDERATED_TOKEN_FILE`)·환경 변수
  서비스 주체(`AZURE_CLIENT_SECRET`·`AZURE_CLIENT_CERTIFICATE_PATH`)가 없는 호스트에서, 시험 계정으로 `az login`한 같은 OS
  사용자로 워커를 실행하고 `워크로드 신원 또는 관리 ID`로 `인증 확인`을 누른다. 정상: 인증이 실패하고(빨간 배너의 코드를
  기록한다) 그 계정의 테넌트로 대상 목록이 나오지 않는다. 실패: 그 사람의 신원으로 인증·대상 조회·수집이 된다. 끝나면
  `az logout`한다.

### 첫 수집 후 정상 결과

- [ ] `앱 등록 비밀`·`앱 등록 인증서`: 지원 ID·이름·생성일·만료일. 일부 권한("비밀에는 권한 범위가 없고 앱의 권한을 따릅니다. 앱
  권한 옵션을 켜면 …"), 생성자("선택한 디렉터리 감사 로그에서 키 ID의 추가와 실행자가 정확히 확인될 때만 연결합니다"), 마지막
  사용("선택한 Graph 베타 로그인 로그에 앱·키 ID가 명시된 성공한 사용만 연결합니다. AuditLog.Read.All과 Microsoft Entra ID P1
  또는 P2가 필요합니다"), 상태("상태를 주지 않아 만료일로만 판단합니다"). 미지원 소유자("사람이 아니라 앱 등록에 묶입니다").
- [ ] `스토리지 계정 키`(키 지문을 읽도록 정한 계정만): 지원 ID·이름·생성일·권한. 미지원 만료일("스토리지 키에는 만료일이
  없습니다"), 생성자, 소유자, 마지막 사용, 상태.
- [ ] `Azure DevOps 개인 액세스 토큰(PAT)`(DevOps 조직을 넣었을 때): 지원 ID·이름·생성일·만료일·권한·생성자·소유자·상태. 미지원
  마지막 사용("마지막 사용을 주지 않습니다").
- [ ] 사람 목록: 퇴사자 Credential의 "IdP 연결" 표에 이 연결(`Entra ID · people`)이 `정상`과 마지막 수집 시각으로 보인다.
- [ ] 연동 행이 "인증서 자동 교체 실패"나 "인증서가 만료됐습니다"로 바뀌지 않는다(교체는 만든 지 약 120일 뒤부터라 이번
  시험에서는 볼 수 없다. 이전 인증서 삭제 실패는 행에 나오지 않고 감사 기록에만 남는다).

### 문제 신호

- [ ] (2026-10-07) `AZURE_ENTRA_PREMIUM_REQUIRED`: "테넌트에 Microsoft Entra ID P1 또는 P2가 없어 Graph로 로그인 로그를 읽을 수
  없음 · 라이선스를 더하거나 이 옵션을 끔". 권한이 아니라 라이선스 문제다.
- [ ] `AZURE_ROOT_MANAGEMENT_GROUP_NOT_FOUND`(툴팁에서는 `알 수 없음`): "테넌트 루트 관리 그룹이 아직 없음 · Azure Portal의 관리
  그룹 화면에서 관리 그룹 사용을 시작하면 만들어지며, 쓰지 않으면 Azure 역할 옵션을 끔".
- [ ] 로그인 오류는 `인증 확인`·`키 등록 완료·인증 확인`의 빨간 배너에 나오고, 저장 뒤 `권한 다시 확인`에서는 모든 행이 `확인
  실패`다: `AZURE_CERTIFICATE_NOT_REGISTERED`, `AZURE_APPLICATION_NOT_FOUND`, `AZURE_TENANT_NOT_FOUND`, `AZURE_APPLICATION_DISABLED`,
  `AZURE_SERVICE_PRINCIPAL_MISSING`, `AZURE_RESOURCE_NOT_IN_TENANT`, `AZURE_CLOCK_SKEW`, `AZURE_TOKEN_REFUSED`,
  `AZURE_TOKEN_UNAVAILABLE`, `AZURE_CERTIFICATE_INVALID`.
- [ ] `AZURE_TARGET_LIST_ACCESS_DENIED`(대상 조회: 구독 Reader와 조건), `KEY_VAULT_REQUIRED`(기존 설정 화면에서 Key Vault 없이
  금고를 고름), `HTTP_403`, Azure DevOps의 `HTTP_203`(로그인 페이지 응답 = 거절, 화면 `HTTP 203`).
- [ ] 생성 단계 거절: `AZURE_CLIENT_ID_INVALID`, `AZURE_TENANT_ID_INVALID`, `AZURE_EXPOSURE_TARGET_REQUIRED`(기존 설정 화면에서
  대상 없이 노출 검사를 고름), `AZURE_DEVOPS_ORGANIZATION_REQUIRED`. `AZURE_STORAGE_KEYS_NEED_THE_SUBSCRIPTION`·`AZURE_KEY_VAULT_REQUIRED`는
  앞선 권한 게이트(`REQUIRED_PERMISSIONS_NOT_GRANTED`)가 먼저 막아 화면에 나오지 않는다.
- [ ] 인증서 교체 실패: `AZURE_APPLICATION_READ_REQUIRED`, `AZURE_ADD_KEY_REFUSED`(인증서 수명 정책이나 CA 발급 인증서만 받는
  정책. CreMore 인증서는 자체 서명), `AZURE_REMOVE_KEY_REFUSED`(행에는 나오지 않고 감사 기록에만 남는다).

### 정리

- [ ] 시험 앱 등록·서비스 주체·보안 그룹·역할 할당·루트 관리 그룹의 `CreMore Role Assignment Reader`와 그 할당·액세스 관리
  상승·Azure DevOps의 앱 사용자와 PAT를 지운다. 워커 신원 시험에 쓴 호스트에서는 `az logout`한다.

근거: azure/backend/cremore_azure_provider/onboarding.py, onboarding_discovery.py, app_certificate.py, metadata/transport.py,
azure/README.md, web/console/views/integrations/guide.tsx, copy.ts, model.ts, page.tsx, wizard.tsx, cremore/onboarding/check.py,
service.py, docs/ONBOARDING.md, docs/AUTH_FIRST_ONBOARDING_DESIGN.md, pyproject.toml, CHANGELOG.md

## Azure DevOps (개인 액세스 토큰 연결)

Microsoft Entra에 연결되지 않은 조직과 Azure DevOps Server용이다. Entra에 연결된 조직은 위 Microsoft 연결로도 된다.

### 준비

- [ ] (2026-10-07) 그 조직 범위의 PAT를 아래 범위만, 가장 짧은 만료로 만든다. 모든 조직용(전역) PAT는 2026년 12월 1일부터 쓸
  수 없다.
- [ ] 범위: 노출 검사 `Code (read)`, 발급 목록 `Graph (read)`와 Token Administration(프로젝트 컬렉션 관리자의 PAT. 모든 사용자
  PAT를 조회·폐기하며 읽기 전용이 없다).
- [ ] `승인된 조치 실행`(별도 연결): 프로젝트 컬렉션 관리자의 PAT(`vso.tokenadministration`). 점검의 두 행(`Graph(읽기)`,
  `토큰 관리(목록·폐기, 프로젝트 컬렉션 관리자)`)이 모두 확인돼야 한다. 이 범위 하나로 `graph_read`가 없음이면 `Graph(읽기)`를
  더하고 결과를 기록한다.

### 마법사

- [ ] 계정·발급 목록 연결 → Azure DevOps → '제품 선택'의 `제품·요금제`에서 `Azure DevOps Services`(이 마법사의 기능은 발급 목록
  수집·승인된 조치 실행) 또는 `Azure DevOps Server`(서버 주소, `계정 연결 저장`까지만). 노출 검사는 `콘텐츠 검사 위치 연결`의
  `Azure DevOps · 콘텐츠 검사`에서 `대상 불러오기`가 보여 주는 프로젝트를 골라 더한다.

### 권한 확인 정상 결과

- [ ] 발급 목록: `graph_read`(Graph(읽기)), `token_administration`(토큰 관리(모든 사용자 PAT 조회·폐기, 프로젝트 컬렉션 관리자))
  확인됨. 노출 검사: `code_read`(코드(읽기)) 확인됨. 조치 연결은 한 사용자의 토큰 목록만 읽고 아무것도 폐기하지 않는다.

### 첫 수집 후 정상 결과

- [ ] `개인 액세스 토큰(PAT)`: 지원 ID·이름·생성일·만료일·권한·생성자·소유자·상태. 미지원 마지막 사용.

### 문제 신호

- [ ] `HTTP_203`(화면 `HTTP 203`)·`HTTP_401`·`HTTP_403`(거절), `NO_USER_TO_ASK_ABOUT`, `AZURE_DEVOPS_PROJECT_REQUIRED`,
  `AZURE_DEVOPS_TOKEN_INVALID`, `AZURE_DEVOPS_ORGANIZATION_INVALID`.

### 정리

- [ ] 시험 PAT(수집·조치)를 폐기한다.

근거: azure/backend/cremore_azure_provider/onboarding.py, onboarding_devops_discovery.py, azure/README.md, docs/PROVIDER_ACTIONS.md,
web/console/views/integrations/copy.ts, wizard.tsx, CHANGELOG.md

## GitHub

### 준비

- [ ] 시험 조직과 그 조직의 소유자 계정. 권장 인증은 GitHub App: 마법사의 `새 App 자동 설정`(`조직`을 넣고 그 아래
  `GitHub에서 App 만들기·설치`를 누른다. 조직 소유자가 GitHub에서 만들기·설치를 승인하면 App ID·설치 ID·개인 키를 자동으로
  받는다) 또는 `이미 만든 App 정보 입력`(App ID 또는 Client ID, 설치 ID, 개인 키(PEM)). 직접 입력에 쓴 개인 키 .pem 파일은
  넣은 뒤 지운다.
- [ ] 새 App이면 `App 설치 권한 선택`에서 시험할 기능의 읽기 권한을 고른다(아무것도 고르지 않으면 기본 인증만 요청한다).
  (2026-10-08) `사람 목록 읽기 권한`은 GitHub.com·Enterprise Cloud에서만 나온다.
- [ ] App 권한(모두 읽기): 노출 검사 `Metadata: read`·`Contents: read`. 발급 목록 `Organization administration: read`·
  `Personal access tokens: read`·`Personal access token requests: read`·`Repository administration: read (deploy keys)`. 금고
  `Organization secrets: read`·`Repository secrets: read`·`Environments: read`·`Actions: read (lists environments)`(2026-10-07
  추가). (2026-10-08) 사람 목록은 조직 권한 `Members: read`. App을 조직에 설치했다.
- [ ] (2026-10-08) 사람 목록(조직의 SAML SSO 신원)의 인증은 둘 중 하나다. GitHub.com·Enterprise Cloud에서는 GitHub App(권장, 위
  `Members: read`, 사람이 떠나도 멈추지 않는 기계 자격증명) 또는 조직 소유자의 classic PAT, 범위 `read:org`만(SAML SSO 승인).
  엔터프라이즈 SSO 신원(EMU·엔터프라이즈 SAML·Server 인스턴스 SAML)이면 엔터프라이즈 소유자의 classic PAT `read:enterprise`와
  새 마법사의 조직 목록(`GET /user/orgs`)용 `read:org`를 쓴다(App으로는 읽지 못한다). `admin:org`·`admin:enterprise`는 주지 않는다.
- [ ] (2026-10-08) GHE.com(데이터 상주)·Enterprise Server에서는 마법사가 사람 목록에 App을 내놓지 않는다(사람 목록 카드가 "추가
  인증: 개인 액세스 토큰"이고, App 만들기 요청에 사람 목록을 넣으면 `AUTH_METHOD_NOT_FOR_PURPOSES`로 거절된다). 이 두 제품의
  사람 목록은 토큰 방식만 검증 대상이다.
- [ ] (선택, 엔터프라이즈) 대상에 엔터프라이즈를 넣으면 `Enterprise credentials: 읽기`가 있는 엔터프라이즈 설치(Export API,
  Enterprise Cloud)와, 감사 이벤트·토큰 digest에는 엔터프라이즈 소유자의 classic PAT `read:audit_log`(감사 로그 토큰). 이 토큰은
  `엔터프라이즈 감사 로그 토큰(클래식, read:audit_log)` 칸에 넣는다. 이 칸은 `이미 만든 App 정보 입력`이나 저장 뒤 `수집 범위·인증
  설정`에 있고 `새 App 자동 설정`에는 없다.
- [ ] `승인된 조치 실행`(별도 App): 조직 권한 `Personal access tokens: write`를 가진 조치 전용 App.
- [ ] 시험 데이터: 조직이 승인한 세분화 PAT, 배포 키, Actions 시크릿(조직·저장소·환경), (SAML SSO 조직이면) SSO 승인된 classic
  PAT·SSH 키, (2026-10-08) SSO 승인된 OAuth 앱 토큰(예: GitHub CLI 로그인)과 GitHub App 사용자 토큰. 모두 시험 구성원 계정으로
  만든다.

### 마법사

- [ ] 계정·발급 목록 연결 → GitHub, 제품 `GitHub.com`·`GitHub Enterprise Cloud`·`GitHub Enterprise Cloud 데이터 상주(GHE.com)`·
  `GitHub Enterprise Server`(GHE.com·Server는 `서버 주소`가 필요하다). 대상은 App이 설치된 조직(여러 개 가능. 중지된 설치와
  개인 계정은 빠진다). GitHub 마법사에는 `다른 인증·기존 설정` 링크가 없다.
- [ ] 발급 목록 옵션: `엔터프라이즈 전체 자격증명 인벤토리`(엔터프라이즈 입력 시. 설명은 "Enterprise Cloud의 Export
  API입니다(GHE.com·Server 지원은 GitHub이 아직 밝히지 않았습니다)…"), `엔터프라이즈 감사 이벤트(감사 로그 토큰 필요)`,
  `조직 감사 이벤트`, `감사 로그 조회 기간(일)`, `엔터프라이즈 감사 로그의 토큰 digest(감사 로그 토큰 필요)`. 실행 설정에는
  `발급 목록 수집 · 수집 주기`와 함께 `엔터프라이즈 전체 인벤토리 주기(분, 0이면 수동)`(엔터프라이즈 인벤토리를 켰을 때)·
  `감사 로그 수집 주기(분, 0이면 수동)`(감사 옵션을 켰을 때)가 나온다.
- [ ] (2026-10-08) 사람 목록: GitHub.com·Enterprise Cloud의 App 연결은 사람 목록 카드에 "현재 인증으로 권한 확인"이 보인다. 토큰
  방식은 인증 방식 `개인 액세스 토큰`이다. 수집 옵션 `조직 대신 엔터프라이즈의 SSO 신원 읽기…`(GHE.com은 기본 켬)는 엔터프라이즈
  신원을 읽을 때만 켜고, 그때는 토큰 방식(엔터프라이즈 소유자 PAT)으로 연결한다.
- [ ] (2026-10-08) GHE.com 사람 목록: 토큰 방식의 `대상 불러오기`가 `AUTH_FIRST_ENTERPRISE_DISCOVERY_UNSUPPORTED`("이 인증으로
  Enterprise 목록을 자동 조회할 수 없습니다. 기존 설정에서 연결하세요.")로 멈춘다. 새 마법사로는 GHE.com 사람 목록 연결을 만들지
  못하는 것이 현재 동작이다(GitHub 마법사에는 `다른 인증·기존 설정` 링크도 없다). 이 문구가 나오는지 확인하고, 다른 화면
  경로로 연결할 수 있으면 그 경로를 기록한다.
- [ ] 노출 검사: 콘텐츠 검사 위치 연결 → `GitHub · 콘텐츠 검사` → 저장소 선택.

### 권한 확인 정상 결과

- [ ] `installation`(조직에 설치됨)이 확인된다(subject 조직 이름은 툴팁).
- [ ] 기능별 App 권한 행(`metadata`, `contents`, `organization_administration`, `organization_personal_access_tokens`,
  `organization_personal_access_token_requests`, `administration`, `organization_secrets`, `secrets`, `environments`)이 확인된다.
  (2026-10-07) 금고는 `actions`(Actions: 읽기(환경 목록))도 확인돼야 한다.
- [ ] `조직 감사 이벤트`를 켜면 `org_audit_read`(조직 감사 로그 읽기) 확인됨(조직 감사 API가 열린 요금제만). 엔터프라이즈 감사
  이벤트·토큰 digest를 켜면 `enterprise_audit_read`(엔터프라이즈 감사 로그 읽기). 엔터프라이즈 인벤토리면
  `enterprise_credentials_read`가 확인되고, 툴팁 상세는 "엔터프라이즈 설치의 자격증명 목록 읽기 권한을 확인했습니다."
  (`ENTERPRISE_INSTALLATION_PERMISSION_CONFIRMED`)다.
- [ ] (2026-10-08) 사람 목록(App): `installation`, `members`(구성원: 읽기(조직 구성원·팀, CreMore는 SAML SSO 신원만 읽음))
  확인됨. 점검은 `members: read` 하나만 받은 설치 토큰으로 GraphQL에 조직 SAML 신원의 개수만 묻고 신원 자체는 읽지 않는다.
- [ ] (2026-10-08) GitHub.com·Enterprise Cloud 조직에 설치한 GitHub App(Members 읽기)으로 조직 SAML SSO 신원(externalIdentities)을
  읽는다: 설치 토큰이 GraphQL `organization.samlIdentityProvider.externalIdentities`를 실제로 돌려주는지(`members` 확인됨, 첫 수집
  뒤 퇴사자 Credential "IdP 연결" 표에 이 연결이 `정상`), SAML을 설정하지 않은 조직에서 `GITHUB_IDENTITY_SAML_NOT_ENABLED`("GitHub이
  이 조직의 SAML 신원 공급자를 보여 주지 않음 · …")가 나오는지 확인한다.
- [ ] 사람 목록(토큰): 조직 소유자 토큰이면 `admin_org`, 엔터프라이즈 SSO 신원이면 `read_enterprise` 확인됨. (2026-10-07)
  엔터프라이즈 결제 관리자(소유자 아님)의 토큰은 토큰에 `read:enterprise`가 있고 대상에 엔터프라이즈가 있으며 엔터프라이즈
  신원 읽기를 켰을 때 `read_enterprise`가 "소유자 계정이 아님"(`NOT_AN_OWNER`)이다(소유자 확인은 `ownerInfo`). 그 범위가 없으면
  상세 없는 `MISSING`이다.
- [ ] 조치 App: `organization_personal_access_tokens_write` 확인됨(설치 정보로 판단하며 아무것도 회수하지 않는다).

### 첫 수집 후 정상 결과

- [ ] `세분화 PAT(fine-grained)`: 지원 ID·이름·만료일·권한·소유자·마지막 사용·상태. 일부 생성일("조직 접근이 승인된 시각만
  줍니다. 엔터프라이즈 인벤토리를 연결하면 생성일을 줍니다"). 미지원 생성자("목록의 소유자·승인자를 생성자로 추정하지 않습니다…").
- [ ] `Classic PAT(SSO 승인)`: 지원 ID·이름·만료일·권한·소유자·마지막 사용. 일부 생성일(SSO 승인 시각만), 상태("승인된 동안 목록에
  있고, 폐기되면 목록에서 빠집니다"). 미지원 생성자.
- [ ] `OAuth 앱 토큰(SSO 승인)`: 일부 생성일·상태. 미지원 만료일("OAuth 앱 토큰에는 만료일이 없습니다"), 생성자.
- [ ] `GitHub App 사용자 토큰(SSO 승인)`: 일부 생성일·만료일("토큰 만료를 켠 앱의 토큰만 만료일이 있습니다")·상태. 미지원 생성자.
- [ ] (2026-10-08) SSO 승인된 OAuth 앱 토큰과 GitHub App 사용자 토큰이 Credential 목록에서 "SSO 승인 자격 증명"이 아니라 각각
  "OAuth 앱 토큰", "GitHub App 사용자 토큰" 유형으로 보인다.
- [ ] `SSH 키(SSO 승인)`: 일부 생성일·상태. 미지원 만료일, 권한("SSH 키는 사용자의 권한을 그대로 씁니다"), 생성자.
- [ ] (2026-10-08) Enterprise Server 연결: 마법사의 인벤토리 유형에 SSO 승인 4종(Classic PAT·OAuth 앱 토큰·GitHub App 사용자
  토큰·SSH 키)이 보이지 않고, 조직 수집이 SSO 승인 목록을 읽지 않아 그 읽기 실패로 `일부 완료`가 되지 않는다.
- [ ] `배포 키`: 지원 ID·이름·생성일·권한·마지막 사용·상태. 일부 생성자("추가한 사람을 기록한 키만 줍니다"). 미지원 만료일,
  소유자("사람이 아니라 저장소에 묶입니다").
- [ ] `GitHub App 설치`: 지원 ID·이름·생성일·권한·상태. 미지원 만료일·생성자·소유자·마지막 사용.
- [ ] (Enterprise Cloud·GHE.com Export) `App 발급 주체(Export 관측)`·`Federated JTI(Export 관측)`: 스냅샷 관측 행이며 ID는 미지원
  ("안정적인 개별 식별자가 없어…"·"고정 ID가 없어…").
- [ ] 금고: 조직·저장소·환경 Actions 시크릿의 이름·시각 메타데이터(원문·암호문 없음).
- [ ] (2026-10-08) 사람 목록: 퇴사자 Credential의 "IdP 연결" 표에 이 연결이 "계정 신원 연결"로 보인다(표는 IdP 사람 목록
  연결이 하나 이상일 때 나온다). GitHub 로그인과 IdP 사람의 연결은 "퇴사자 점검" 절에서 확인한다.

### 문제 신호

- [ ] `INSTALLED_ON_ANOTHER_ACCOUNT`(다른 계정에 설치됨), `INSTALLATION_UNREADABLE`, `GITHUB_APP_REJECTED`,
  `GITHUB_APP_READ_ONLY_REFUSED`(읽기 전용 토큰 거절 · App 권한 확인), `GITHUB_APP_TOKEN_NOT_READ_ONLY`.
- [ ] `GITHUB_TOKEN_REJECTED`, `CLASSIC_TOKEN_REQUIRED`, `NOT_AN_OWNER`, `TARGET_NOT_VISIBLE`(구성원이 아니거나 SAML SSO 승인 전),
  `TARGET_OWNER_NOT_CHECKED`, `NO_REPOSITORY_TO_READ`, `WRITE_REQUIRED`(조치 App에 쓰기 없음).
- [ ] (2026-10-08) 사람 목록(App)의 `members`: "GitHub이 이 조직의 SAML 신원 공급자를 보여 주지 않음 · …"
  (`GITHUB_IDENTITY_SAML_NOT_ENABLED`: 조직 자체 SAML SSO 없음, 관리 사용자·엔터프라이즈 SAML), "접근 거부"(`ACCESS_DENIED`:
  GitHub이 `FORBIDDEN`으로 거절), "GitHub가 App이나 그 설치를 거절함"(`GITHUB_APP_REJECTED`: 토큰 발급 거절), 상세 없는
  `MISSING`(설치에 Members 읽기 없음). 엔터프라이즈 신원 읽기를 켠 App 연결은 `read_enterprise`가 "클래식 토큰 필요"
  (`CLASSIC_TOKEN_REQUIRED`)라 활성화되지 않는다. `GITHUB_IDENTITY_ENTERPRISE_NEEDS_AN_OWNER_TOKEN`은 API 직접 호출에서만 나온다.
  수집의 토큰 발급 실패는 `GITHUB_IDENTITY_APP_*`(예: `GITHUB_IDENTITY_APP_REJECTED`)로 남는다.
- [ ] (2026-10-08) Enterprise Server의 토큰 방식 사람 목록 수집이 `GITHUB_IDENTITY_SAML_NOT_ENABLED`로 끝나는지 확인한다(조직
  SAML SSO는 Enterprise Cloud 기능이고 Server의 SAML은 인스턴스 전체에 둔다).
- [ ] Enterprise Server 사람 목록(인스턴스 SAML): 새 마법사 1단계(인증 전)에서 서버 주소와 엔터프라이즈를 넣고 엔터프라이즈 소유자
  classic PAT(`read:enterprise`, `read:org`)로 인증한다. `read:org`가 없으면 `연결 확인`이 성공하면서 `GITHUB_TOKEN_READ_ORG_REQUIRED`를 경고한다. `대상 불러오기`의 조직 행에 엔터프라이즈가 실리고, `조직 대신 엔터프라이즈의 SSO 신원
  읽기`를 켠 수집이 `COMPLETE`로 끝나며, 사람 목록의 GitHub 로그인이 IdP 사람과 SAML NameID·SCIM 사용자 이름으로 이어지는지
  확인한다. SAML을 켜지 않은 인스턴스는 `GITHUB_IDENTITY_SAML_NOT_ENABLED`다.
- [ ] `GITHUB_ENTERPRISE_CREDENTIALS_READ_REQUIRED`, `GITHUB_ENTERPRISE_AUDIT_TOKEN_REQUIRED`,
  `GITHUB_ENTERPRISE_EXPORT_EDITION_UNSUPPORTED`(Server), `GITHUB_AUDIT_TOKEN_MUST_BE_A_CLASSIC_PAT`,
  `GITHUB_AUDIT_TOKEN_NEEDS_AN_ENTERPRISE`, `GITHUB_IDENTITY_GHE_COM_READS_THE_ENTERPRISE`.
- [ ] `연결 확인`(인증 단계)은 classic PAT에 `read:org`·`write:org`·`admin:org`·`user`가 모두 없으면 `GITHUB_TOKEN_READ_ORG_REQUIRED`,
  세분화 PAT면 `AUTH_FIRST_FINE_GRAINED_DISCOVERY_UNSUPPORTED`를 성공과 함께 경고(노란 배너)한다. 계정 연결만 저장은 되고,
  `대상 불러오기`가 각각 `GITHUB_ORGANIZATIONS_HTTP_403`·`AUTH_FIRST_FINE_GRAINED_DISCOVERY_UNSUPPORTED`로 멈춘다. 범위가 있어도
  조직 접근·SSO 승인이 없으면 `GITHUB_ORGANIZATIONS_HTTP_403`이다.
- [ ] GitHub.com Free·Team 조직에서 SSO 승인 목록(`credential-authorizations`) 읽기가 거절되면 그 읽기는 실패로 남고 빈 목록으로
  보지 않는다.

### 정리

- [ ] 시험 App(조치 App 포함)의 조직 설치를 지우고 App을 삭제한다. 시험 classic PAT·감사 로그 토큰을 폐기하고, 시험 세분화
  PAT·배포 키·Actions 시크릿과 SSO 승인(OAuth 앱 토큰·GitHub App 사용자 토큰 포함)을 철회한다.

근거: github/backend/cremore_github_provider/onboarding.py, onboarding_export.py, identity/directory.py, github/README.md,
cremore/onboarding/catalog.py, github_app.py, cremore/api/credential_records.py, docs/LEAVER_CHECK.md,
web/console/views/integrations/auth-first.tsx, copy.ts, model.ts, web/console/labels.ts, CHANGELOG.md

## GitLab

### 준비

- [ ] 제품·요금제를 확인한다(`GitLab.com`·`GitLab Self-Managed`·`GitLab Dedicated`, Free / Premium / Ultimate. Dedicated에는 요금제
  칸이 없다). GitLab.com Free는 그룹·프로젝트 액세스 토큰을 만들 수 없어 그룹 서비스 계정의 개인 액세스 토큰을 쓴다. 시험
  그룹·프로젝트만 쓴다.
- [ ] 토큰: 그룹 또는 프로젝트 액세스 토큰, 범위 `read_api`(노출 검사는 `read_repository`도, 선택 `self_rotate`). (2026-10-07)
  역할은 그룹 Owner, 프로젝트 Maintainer. 그룹 CI 변수는 그룹 Owner. `self_rotate`(또는 `api`)가 있으면 CreMore가 수명의 마지막
  3분의 1(최대 30일)에 토큰을 교체하고 GitLab은 이전 토큰을 즉시 폐기하므로, 이 토큰은 CreMore 전용으로 둔다.
- [ ] 인스턴스 전체(Self-Managed·Dedicated, 발급 목록만): 인증 단계 하단 `다른 인증·기존 설정`으로 들어가 `범위`에서 `인스턴스
  전체(관리자)`를 고른다. 토큰은 관리자의 개인 액세스 토큰, 범위는 `read_api`(Admin Mode면 `admin_mode`도)만.
- [ ] `승인된 조치 실행`(별도 연결): 시험 그룹·프로젝트 전용 토큰에 `api` 범위와 그룹 Owner·프로젝트 Maintainer 역할. 인스턴스
  관리자의 `api` 토큰은 이 문서에서 만들지 않는다.
- [ ] 시험 데이터: 그룹·프로젝트 액세스 토큰, 배포 토큰, 파이프라인 트리거 토큰, 시험 값만 넣은 CI 변수(변수 목록 응답에 값이
  포함된다).

### 마법사

- [ ] 계정·발급 목록 연결 → GitLab, 제품·요금제, (Self-Managed·Dedicated) 서버 주소, 토큰. (2026-10-07) 대상 목록의 프로젝트는
  토큰 사용자가 구성원인 것만 나온다(`membership=true`). 그룹은 GitLab 기본값(관리자가 아니면 속한 그룹)으로 읽는다.
- [ ] 발급 목록 옵션: `감사 이벤트(토큰 사용·변경 기록)`(유료), `프로젝트 배포 키도 수집`(프로젝트), `그룹 기업 사용자의 SSH
  키도 수집`(GitLab.com 그룹, 유료). 인스턴스 범위(기존 설정 화면)에서는 `가져올 Credential 유형`의 `개인 액세스 토큰(PAT)`·
  `배포 토큰`·`SSH 키`·`배포 키` 체크박스로 고른다.
- [ ] 금고: `노출 발견값과 대조하도록 변수 값 읽기`(끔. 켜면 값 대조(지문화)).

### 권한 확인 정상 결과

- [ ] `read_api`(read_api 범위) 확인됨. 노출 검사면 `read_repository`.
- [ ] (2026-10-07) 그룹 대상이면 `owner`(그룹 Owner 역할), 프로젝트 대상이면 `maintainer`(프로젝트 Maintainer 역할) 확인됨.
- [ ] `self_rotate`는 비필수다(새 마법사에는 없고 툴팁에서 본다). 없으면 툴팁이 `없음` + "없으면 만료 전에 직접 새 토큰을
  넣어야 함"(`TOKEN_RENEWED_BY_HAND`)이어도 다음으로 간다.
- [ ] 인스턴스 범위: `instance_admin` 확인됨. 조치: `api`(툴팁 subject `user:<id>`)와 역할 행 확인됨.

### 첫 수집 후 정상 결과

- [ ] `개인 액세스 토큰(PAT)`(GitLab.com 유료 그룹의 기업 사용자 또는 인스턴스 `개인 액세스 토큰(PAT)` 선택): 9개 항목 모두 지원.
- [ ] `서비스 계정 PAT`·`그룹 액세스 토큰`·`프로젝트 액세스 토큰`: 생성자만 일부("감사 이벤트를 켜면 생성 기록에서 채웁니다"),
  나머지 지원.
- [ ] `배포 토큰`: 지원 ID·이름·만료일·권한·상태. 일부 생성자. 미지원 생성일("배포 토큰 API가 생성일을 주지 않습니다"),
  소유자("사람 계정에 묶이지 않습니다"), 마지막 사용.
- [ ] `파이프라인 트리거 토큰`: 일부 만료일("만료일은 이를 지원하는 GitLab 버전에서만 줍니다"). 미지원 권한, 상태("상태를 주지
  않고, 삭제되면 목록에서 빠집니다").
- [ ] `오류 추적 클라이언트 키`: 지원 ID·상태, 일부 생성자, 나머지 미지원.
- [ ] `Kubernetes 에이전트 토큰`: 일부 상태("목록 API가 활성 토큰만 줍니다"). 미지원 만료일·권한·소유자.
- [ ] `SSH 키`(옵션): 일부 권한("인증·서명 용도만 줍니다"), 미지원 상태. `배포 키`(옵션): 미지원 생성자·소유자·마지막 사용·상태.
- [ ] 금고: CI 변수 메타데이터(값 읽기를 끄면 값 대조 없음).

### 문제 신호

- [ ] `ACCESS_LEVEL_TOO_LOW`("필요한 역할보다 낮은 권한"), `TARGET_NOT_VISIBLE`, `NOT_AN_ADMINISTRATOR`(Admin Mode면 `admin_mode`
  범위도), `API_SCOPE_REQUIRED`(조치), `HTTP_401`.
- [ ] `GITLAB_GROUPS_LIST_HTTP_403`·`GITLAB_PROJECTS_LIST_HTTP_403`(대상 조회: `read_api` 또는 `api`와 접근).
- [ ] `GITLAB_INSTANCE_SCOPE_IS_INVENTORY_ONLY`, `GITLAB_INSTANCE_SCOPE_NEEDS_SELF_MANAGED`, `GITLAB_INSTANCE_SOURCES_REQUIRED`(기존
  설정 화면에서만). `GITLAB_FEATURE_REQUIRES_PAID_PLAN`, `GITLAB_DEDICATED_REQUIRES_ULTIMATE`(API 직접 호출에서만).
- [ ] 자동 교체: `GITLAB_SELF_ROTATE_SCOPE_REQUIRED`, `GITLAB_TOKEN_REVOKED`, `GITLAB_ROTATION_UNCERTAIN`, `GITLAB_ROTATION_REFUSED`,
  `RENEWAL_INTERRUPTED`(연동 행 `확인 필요`, 새 토큰을 넣는다). `GITLAB_TOKEN_REVOKED`는 하루 한 번 하는 토큰 확인에서도 "토큰 확인
  실패 · …"로 나온다.

### 정리

- [ ] 시험 토큰(수집·조치·인스턴스 관리자)을 폐기하고 시험 CI 변수를 지운다.

근거: gitlab/backend/cremore_gitlab_provider/onboarding.py, gitlab/README.md, docs/PROVIDER_ACTIONS.md,
web/console/views/integrations/copy.ts, model.ts, wizard.tsx, CHANGELOG.md

## Confluence

### 준비

- [ ] Cloud(권장): Atlassian 관리의 디렉터리 → 서비스 계정에서 서비스 계정을 만들고 Confluence 앱 접근을 준다. 검사할 공간의
  공간 설정 → 권한에서 보기 권한을 준다. 서비스 계정의 자격증명 만들기 → OAuth 2.0에서 `read:space:confluence`·
  `read:page:confluence`·`read:attachment:confluence`·`read:content-details:confluence`를 고른다(시크릿은 만든 직후에만 보인다).
- [ ] (2026-10-07) Cloud의 `API 토큰` 방식은 서비스 계정의 범위 지정 API 토큰(같은 네 범위)만 받는다(토큰을 Bearer로 보낸다).
  주소는 `https://api.atlassian.com/ex/confluence/<Cloud ID>/wiki`이고 `<Cloud ID>`는 `https://<사이트>/_edge/tenant_info`의
  `cloudId`다. 개인 API 토큰은 받지 않는다.
- [ ] Data Center: 그 공간의 보기 권한만 가진 전용 사용자의 개인 액세스 토큰.
- [ ] 시험 공간에 페이지 1개 이상(첨부 파일 1개 이상).

### 마법사

- [ ] 계정·발급 목록 연결 → Confluence로 계정을 인증·저장(`계정 연결 저장`, 행 상태 `계정 연결됨`)한 뒤 콘텐츠 검사 위치 연결 →
  `Confluence · 콘텐츠 검사`에서 공간을 고른다. 인증 방식 `서비스 계정(OAuth 2.0)`(Cloud) 또는 `API 토큰`, 주소 `Confluence
  주소`.

### 권한 확인 정상 결과

- [ ] 서비스 계정: `read:space:confluence(공간)`, `read:page:confluence(페이지 본문)`, `read:attachment:confluence(첨부 파일)`,
  `read:content-details:confluence(변경 감지·작성자)` 확인됨. 점검은 공간, 첫 페이지 목록, 첫 페이지의 첨부 목록, CQL 검색을
  차례로 읽는다.
- [ ] API 토큰: `read_space`(공간 읽기(Cloud: read:space:confluence)), `read_content`(페이지 읽기(Cloud: read:page:confluence))
  확인됨.

### 첫 수집 후 정상 결과

- [ ] 노출 검사 실행이 공간의 페이지 본문과 첨부 파일을 읽는다(수집·탐지 현황). 발급 목록 유형은 없다.

### 문제 신호

- [ ] `CONFLUENCE_SPACE_NOT_VISIBLE`("공간이 없거나 서비스 계정에 보기 권한이 없음": 서비스 계정 점검이 공간에서 404를 받을 때만.
  401·403은 `HTTP_401`·`HTTP_403`), `CONFLUENCE_NO_PAGE_TO_TRY`("공간에 확인할 페이지가 없음", 첨부 행. 툴팁 `알 수 없음`),
  `NOT_CHECKED`.
- [ ] `ATLASSIAN_OAUTH_TOKEN_REFUSED`(클라이언트 ID·시크릿), `ATLASSIAN_OAUTH_UNAVAILABLE`, `ATLASSIAN_OAUTH_CLIENT_INVALID`,
  `CONFLUENCE_GATEWAY_ADDRESS_INVALID`, `CONFLUENCE_CLOUD_ID_UNAVAILABLE`, `CONFLUENCE_CLOUD_SPACE_ID_AND_WIKI_BASE_REQUIRED`,
  `AUTHENTICATION_REQUIRED`, `TARGET_INCOMPLETE`.

### 정리

- [ ] 서비스 계정의 OAuth 2.0 자격증명·범위 지정 API 토큰과 Data Center 개인 액세스 토큰을 지운다.

근거: atlassian/backend/cremore_atlassian_provider/onboarding.py, cloud_api.py, atlassian/README.md,
web/console/views/integrations/guide.tsx, copy.ts, model.ts, page.tsx, CHANGELOG.md

## Bitbucket

### 준비

- [ ] Cloud: 워크스페이스 액세스 토큰(Bitbucket Cloud Premium). 검사는 `Repositories: Read`·`Account: Read`, 발급 목록은 배포 키를
  읽는 `Repositories: Admin`도. 또는(고급) Bitbucket 범위로 만든 API 토큰(`read:user`·`read:workspace`·`read:repository`, 발급
  목록은 `read:ssh-key`도, 모두 `:bitbucket`)과 그 계정의 이메일. `Repositories: Admin`·프로젝트 관리는 넓은 권한이다. 배포 키·토큰
  목록을 시험할 때만 시험 워크스페이스·프로젝트의 토큰에 주고, 끝나면 폐기한다.
- [ ] Data Center: 프로젝트 HTTP 액세스 토큰. 검사는 프로젝트 읽기, 토큰 목록은 프로젝트 관리.
- [ ] 시험 데이터: 배포 키(저장소·프로젝트), 구성원 SSH 키(Cloud), HTTP 액세스 토큰(Data Center).

### 마법사

- [ ] 계정·발급 목록 연결 → Bitbucket, 제품 `Bitbucket Cloud` / `Bitbucket Data Center`. 워크스페이스 액세스 토큰은 인증 단계에
  워크스페이스, Data Center는 서버 주소를 넣는다. (2026-10-07) API 토큰 방식은 워크스페이스 목록을 `/2.0/user/workspaces`에서
  읽는다.

### 권한 확인 정상 결과

- [ ] 계정 연결(발급 목록): `list_access_tokens`(키·토큰 읽기(Cloud: 계정 읽기, 배포 키는 저장소 관리; Data Center: 프로젝트
  관리)) 확인됨. 노출 검사(콘텐츠 검사 위치 연결): `read_repositories`(저장소 읽기) 확인됨.

### 첫 수집 후 정상 결과

- [ ] `HTTP 액세스 토큰`(Data Center): 지원 ID·이름·생성일. 미지원 만료일·권한·생성자·소유자·마지막 사용·상태("목록 API가 …
  주지 않습니다").
- [ ] `SSH 키`(Cloud): 지원 ID·이름·생성일·만료일·생성자·소유자·마지막 사용. 미지원 권한("SSH 키는 사용자의 권한을 그대로
  씁니다"), 상태.
- [ ] `배포 키`(Cloud): 지원 ID·이름·생성일·마지막 사용. 일부 생성자("프로젝트 배포 키만 만든 사람을 줍니다"). 미지원 만료일,
  권한("Bitbucket 배포 키는 읽기 전용뿐입니다"), 소유자, 상태. 배포 키가 안 나오면 수집 보고의 `project-deploy-keys`·
  `repository-deploy-keys` 사유를 기록한다.

### 문제 신호

- [ ] `BITBUCKET_API_TOKEN_EMAIL_REQUIRED`, `MALFORMED_RESPONSE`, `PAGINATION_INVALID`, `HTTP_401`·`HTTP_403`, `HTTP_404`(화면
  `HTTP 404`).

### 정리

- [ ] 시험 토큰(특히 `Repositories: Admin`·프로젝트 관리 토큰)을 폐기하고 시험 배포 키·SSH 키를 지운다.

근거: atlassian/backend/cremore_atlassian_provider/onboarding.py, metadata/bitbucket.py, atlassian/README.md,
web/console/views/integrations/copy.ts, CHANGELOG.md

## Atlassian 조직

### 준비

- [ ] 조직 설정 → API 키에서 범위를 지정한 API 키: `read:keys:admin`, `read:tokens:admin`, `read:service-accounts-tokens:admin`
  (OAuth 클라이언트 포함). 최대 1년 뒤 만료된다.
- [ ] 서비스 계정 목록은 조직별 Preview 활성화가 필요하다(README).

### 마법사

- [ ] 계정·발급 목록 연결 → Atlassian 조직, 제품 `Atlassian Cloud` / `Atlassian Cloud Enterprise`. API 키를 넣으면 조직 목록에서
  조직을 고른다. 옵션 `조직·서비스 계정 OAuth 클라이언트 포함`. 인증과 조직 목록은 `https://api.atlassian.com/admin/v1/orgs`를,
  권한 점검과 수집은 `https://api.atlassian.com/admin/api-access/v1/orgs/<조직 ID>/…`를 읽는다. `HTTP_401`·`HTTP_403`이면 어느
  호출인지 기록한다.
- [ ] Confluence·Bitbucket·Atlassian 조직은 `계정·발급 목록 연결`의 카드로 각각 연결한다. 새 마법사의 완료 화면에는 다른
  서비스를 이어서 연동하는 버튼이 없다(`다른 인증·기존 설정`으로 연 화면의 완료에만 있다).

### 권한 확인 정상 결과

- [ ] (2026-10-07) `organization_admin`(조직 관리자 API 키)이 확인된다. 점검이 읽는 세 경로(`api-keys`·`api-tokens`·
  `service-accounts/api-tokens`)의 행은 `GET /api/v1/provider-connections/{id}`의 `checks.results.inventory.items`에서만 따로
  보인다. OAuth 옵션이면 `oauth_clients_read`(조직·서비스 계정 OAuth 클라이언트 목록) 행 2개도 확인된다.

### 첫 수집 후 정상 결과

- [ ] `사용자 API 토큰`: 일부 권한("범위를 지정해 만든 토큰만 권한을 줍니다"), 미지원 생성자("목록의 계정은 소유자입니다…"),
  나머지 지원.
- [ ] `조직 API 키`: 일부 상태("상태를 주지 않아 만료일로만 판단합니다"), 미지원 소유자("사람이 아니라 조직에 묶입니다").
- [ ] `서비스 계정 API 토큰`: 일부 권한, 미지원 생성자("만든 관리자를 주지 않습니다").
- [ ] `서비스 계정 OAuth 클라이언트`(옵션): 미지원 마지막 사용.

### 문제 신호

- [ ] `HTTP_401`·`HTTP_403`(화면은 각 문장), `HTTP_404`(화면 `HTTP 404`, 툴팁 `알 수 없음`), `MALFORMED_RESPONSE`,
  `TARGET_INCOMPLETE`, `ATLASSIAN_ORGANIZATION_ID_INVALID`.

### 정리

- [ ] 시험 API 키를 지운다.

근거: atlassian/backend/cremore_atlassian_provider/onboarding.py, metadata/specs.py, metadata/http.py, atlassian/README.md,
web/console/views/integrations/copy.ts, model.ts, wizard.tsx, docs/ONBOARDING.md, CHANGELOG.md

## Notion

### 준비

- [ ] (2026-10-07) 페이지 검사: 내부 연결(이전 이름: 내부 통합)의 API 토큰. 검사할 페이지마다 ••• 메뉴 → 연결 추가에서 이
  연결을 고른다.
- [ ] Enterprise 발급 목록: 조직 소유자가 조직 콘솔에서 만든 조직 봇 토큰, 범위 `personal-access-token:read`(MCP 옵션은
  `mcp-client-connection:read`도)와 워크스페이스 ID(UUID). 이 문서의 시험에는 `personal-access-token:write-high-impact`를 주지
  않는다(주면 그 토큰으로 PAT를 되돌릴 수 없게 폐기할 수 있다).
- [ ] 시험 데이터: 연결을 추가한 시험 페이지 1개 이상, (Enterprise) PAT 1개.

### 마법사

- [ ] 제품 `Free / Plus / Business`(페이지 검사용 계정만) 또는 `Enterprise`. `내부 연결 토큰(이전 이름: 내부 통합)`으로 계정을
  저장한 뒤 콘텐츠 검사 위치 연결에서 공유된 페이지를 고른다. 하위 페이지는 따로 고른다.
- [ ] Enterprise 발급 목록은 `조직 봇 토큰(Enterprise)`(인증 단계에 워크스페이스 ID). 옵션 `개인 액세스 토큰`(기본 켬),
  `MCP 연결 목록(Enterprise)`(끔).
- [ ] 조치 연결: 기능 단계에서 `승인된 조치 실행`만 고른다. 지금 초안을 닫고 조치 전용 인증으로 이어지며 조직 봇 토큰을 다시
  넣는다.

### 권한 확인 정상 결과

- [ ] 노출 검사: `read_content`(콘텐츠 읽기 기능), `pages_shared`(연결에 공유된 페이지(••• → 연결 추가)) 확인됨.
- [ ] 발급 목록: `workspace_tokens` 확인됨. MCP 옵션이면 `mcp_connections`도.
- [ ] 조치(`승인된 조치 실행`만 고른 조치 전용 연결, 시험 토큰은 `personal-access-token:read`만): `workspace_tokens` 확인됨.
  점검이 폐기를 시도하지 않으므로 `revoke_tokens`(비필수)는 그 범위 없이도 `CONFIRMED_WHEN_RUN`이다(새 마법사에는 없고 `수집
  범위·인증 설정` 툴팁에서 본다).

### 첫 수집 후 정상 결과

- [ ] `개인 액세스 토큰`: 미지원 권한("목록 API가 토큰의 기능(capabilities)을 주지 않습니다…"), 나머지 지원.
- [ ] `MCP 연결`(옵션): 미지원 만료일·권한("연결된 워크스페이스만 주고 권한 범위는 주지 않습니다")·상태.
- [ ] 노출 검사 실행이 고른 페이지를 읽는다.

### 문제 신호

- [ ] `NO_PAGE_SHARED_WITH_INTEGRATION`("연결에 공유된 페이지 없음": 페이지 검색 `/v1/search`가 실패해도 나오므로 `read_content`의
  상세를 먼저 본다), `WORKSPACE_ID_REQUIRED`·`NOTION_WORKSPACE_ID_REQUIRED`, `NOTION_INVENTORY_SOURCES_REQUIRED`(두 목록을 모두 끔),
  `NOTION_TOKEN_INVALID`, `HTTP_401`·`HTTP_403`.

### 정리

- [ ] 시험 페이지에서 연결을 빼고 내부 연결을 지운다. 시험 조직 봇 토큰을 폐기한다.

근거: notion/backend/cremore_notion_provider/onboarding.py, notion/README.md, docs/EDITION_AND_COLLECTION_ONBOARDING.md,
docs/PROVIDER_ACTIONS.md, web/console/views/integrations/copy.ts, auth-first.tsx, CHANGELOG.md

## Slack

### 준비

- [ ] Slack Enterprise Grid 조직(그 밖의 Slack은 지원하지 않는다).
- [ ] 마법사 설정 도우미의 `Slack에서 앱 만들기` 링크로 앱을 만든다(매니페스트: 사용자 범위 `admin.apps:read`, 조직 설치에
  필요한 봇 범위 `team:read`, 토큰 교체 꺼짐. 새 마법사의 매니페스트에는 감사 로그 범위가 들어가지 않는다). 앱 설정의 Install
  App에서 조직(Enterprise organization)에 설치한다(조직 관리자 또는 조직 소유자). OAuth & Permissions의 User OAuth
  Token(`xoxp-`)을 넣는다. 이 토큰은 설치한 관리자로 동작하므로 시험이 끝나면 앱을 조직에서 제거한다.
- [ ] 감사 로그 옵션을 시험할 때만 User Token Scopes에 `auditlogs:read`를 더하고 조직 소유자(Owner)가 다시 설치한다.
- [ ] (선택) 워크스페이스 하나를 대상으로 고르려면 `admin.teams:read`도 준다.
- [ ] (수신 웹훅 행을 보려면) `incoming-webhook` 범위를 가진 다른 승인 앱이 시험 조직에 있다.

### 마법사

- [ ] 계정·발급 목록 연결 → Slack → `관리자 앱 토큰`. (2026-10-07) `admin.teams:read`가 없으면 대상 목록에 조직(`E…`) 하나만
  나온다(`대상 불러오기`는 `SLACK_TEAMS_READ_REQUIRED`를 내지 않고 조직을 대상으로 내놓는다). 있으면 워크스페이스(`T…`)도 나온다.
- [ ] 옵션 `감사 로그로 설치자·설치일·설치 상태 확인(최근 90일)`.

### 권한 확인 정상 결과

- [ ] `admin_apps_read`(admin.apps:read 범위(조직 관리자)) 확인됨. 감사 옵션이면 `auditlogs_read` 확인됨(끄면 그 행은 화면에
  없고 API에만 `NOT_SELECTED`로 있다).

### 첫 수집 후 정상 결과

- [ ] `봇 토큰`: 지원 ID·이름·권한. 일부 생성일·생성자("감사 로그 옵션을 켜면 설치 기록에서 채웁니다"), 상태. 미지원 만료일,
  소유자("사람이 아니라 앱에 묶입니다"), 마지막 사용("Slack은 토큰 사용 기록을 주지 않습니다").
- [ ] `사용자 토큰`: 지원 ID·이름·권한, 일부 상태, 나머지 미지원.
- [ ] `수신 웹훅`: 지원 ID·이름, 일부 생성일·생성자·상태, 미지원 만료일·권한("메시지를 올릴 채널은 주지 않습니다")·소유자·마지막
  사용.
- [ ] 감사 로그를 끄면 "핵심 정보"의 `활성 여부`가 `미확인`, `발급 항목 보기`의 상태가 `APPROVED`다. 켜면 설치된 앱은
  `발급처 상태: 활성`·`활성 · INSTALLED`, 제거된 앱은 `발급처 상태: 폐기`·`폐기됨 · UNINSTALLED`다.

### 문제 신호

- [ ] `SLACK_ADMIN_USER_TOKEN_REQUIRED`(봇 토큰 `xoxb-` 등), `SLACK_ROTATING_TOKEN_NOT_SUPPORTED`(`xoxe.`), `SLACK_TOKEN_INVALID`,
  `SLACK_ORGANIZATION_ID_INVALID`(`다른 인증·기존 설정`의 ID 칸에서만).
- [ ] `SLACK_SCOPE_MISSING`, `NOT_AN_ADMINISTRATOR`(화면은 GitLab 문장 "관리자 계정이 아님(GitLab Admin Mode가 켜져 있으면
  admin_mode 범위도 필요)"을 그대로 보인다), `SLACK_ENTERPRISE_REQUIRED`, `SLACK_APP_NOT_INSTALLED_ON_ORGANIZATION`,
  `SLACK_TOKEN_REJECTED`, `SLACK_ANOTHER_ORGANIZATION`, `TARGET_NOT_VISIBLE`, `RATE_LIMITED`.
- [ ] `SLACK_TEAMS_READ_REQUIRED`: `admin.teams:read` 없이 저장한 워크스페이스(`T…`) 대상을 다시 확인할 때만 나온다.
  `SLACK_WORKSPACES_NOT_CONFIRMED`.

### 정리

- [ ] 시험 앱을 조직에서 제거해 토큰을 폐기하고 앱을 지운다.

근거: slack/backend/cremore_slack_provider/onboarding.py, slack/README.md, web/console/views/integrations/guide.tsx, copy.ts,
model.ts, web/console/views/credentials/issued.tsx, tabs.tsx, web/console/ui.tsx, CHANGELOG.md

## HashiCorp Vault · OpenBao

### 준비

- [ ] 시험 클러스터와 KV 마운트. KV 값은 메모리에서 읽어 지문으로만 남지만 시험 값만 둔다.
- [ ] 읽기 전용 정책(2026-10-07 경로 기준): 목록은 접두어 끝에 `/`를 붙인 경로(`secret/metadata/team-a/`, 마운트 전체면
  `secret/metadata/`, KV v1은 `<마운트>/<접두어>/`)에서 판단하므로 `path "secret/metadata/team-a/*" { capabilities = ["list"] }`처럼
  접두어에 건다. 값은 `<마운트>/data/<접두어>/*`의 `read`(KV v1은 `<마운트>/<접두어>/*`). 대상 조회는 `sys/mounts`의 `read`(점검에서는
  비필수지만 새 마법사의 `대상 불러오기`는 이것 없이 `VAULT_MOUNTS_ACCESS_DENIED`로 멈춘다).
- [ ] 옵션별 정책: 이전 KV 버전은 `<마운트>/metadata/<접두어>/*`의 `read`. 서비스 토큰 accessor는 `auth/token/accessors`의 `sudo`·
  `list`와 `auth/token/lookup-accessor`의 `update`(`sudo`는 시험 정책에만 주고 끝나면 뺀다). lease 접두어는
  `sys/leases/lookup/<접두어>/`의 `sudo`·`list`와 `sys/leases/lookup`의 `update`.
- [ ] 인증: `쿠버네티스 로그인(서버 읽기)`·`JWT 로그인(서버 읽기)`(권장. 역할, 인증 마운트, `VAULT_CONNECTION_TOKEN_DIR` 안의 토큰
  파일 이름. 워커에 이 설정이 없으면 `VAULT_CONNECTION_TOKEN_DIR_NOT_CONFIGURED`) 또는 `Vault 토큰(서버 읽기)`(고급. 루트 토큰
  금지, CreMore가 갱신하지 않아 TTL이 끝나면 멈춘다).
- [ ] namespace는 Vault Enterprise·HCP Vault Dedicated와 OpenBao에서 쓴다(Vault Community 화면에는 칸이 없다). 공개 신뢰
  인증서가 아니면 클러스터 CA(PEM)를 준비한다.

### 마법사

- [ ] 연동 서비스의 `Secret 저장소` 카드 → `금고 연동하기` → HashiCorp Vault 또는 OpenBao, 제품(`Vault Community` / `Vault
  Enterprise` / `HCP Vault Dedicated`). 인증 단계에 `클러스터 주소`, `네임스페이스`, `클러스터 CA 인증서`. 대상은 `sys/mounts`의 KV
  마운트. 새 마법사는 `경로 접두어`를 묻지 않고 마운트 전체로 점검한다. 접두어로 시험하려면 `다른 인증·기존 설정`에서 `KV
  마운트`와 `경로 접두어(비우면 마운트 전체)`를 적는다.
- [ ] 옵션: `이전 KV 버전도 대조`, `비밀당 버전 수`, `서비스 토큰 accessor(메타데이터, 토큰 값 아님)`, `동적 시크릿 lease 접두어`.

### 권한 확인 정상 결과

- [ ] `login`(연결 자체 로그인) 확인됨.
- [ ] (2026-10-07) `kv_list`·`kv_read`가 확인된다. 툴팁 subject는 새 마법사(마운트 전체)면 `secret/metadata/`·`secret/data/*`,
  기존 설정 화면에서 접두어 `team-a`를 적으면 `secret/metadata/team-a/`·`secret/data/team-a/*`다.
- [ ] (2026-10-07) 옵션을 켰으면 `kv_history`·`token_accessors`·`leases`가 경로마다 확인된다. 빠지면 활성화가 막힌다.
- [ ] `mounts_read`는 비필수다(새 마법사에는 없고 툴팁에서 본다).

### 첫 수집 후 정상 결과

- [ ] Secret 저장소(`?view=vaults`)의 `연결한 저장소` 표에 이 금고가 `정상`과 `마지막 수집` 시각으로 보인다(수집 `완료`는
  수집·탐지 현황에서 본다). 토큰 accessor·lease는 금고 값 일치로 세지 않는 관리 목록이다(`MANAGED`는 API에만 있다).

### 문제 신호

- [ ] `ROOT_TOKEN_NOT_RECOMMENDED`(로그인 행 툴팁 "루트 권한 토큰 · 읽기 전용 정책의 토큰을 권장". 루트 토큰을 일부러 만들지
  않는다), `LOGIN_REQUIRED`, 로그인 `없음` + 로그인 오류 코드.
- [ ] `VAULT_MOUNTS_ACCESS_DENIED`, `VAULT_LOGIN_ROLE_AND_TOKEN_FILE_REQUIRED`, `VAULT_TLS_CA_MUST_BE_A_PEM_CERTIFICATE`,
  `VAULT_PATH_INVALID`, `VAULT_CONNECTION_TOKEN_DIR_NOT_CONFIGURED`. `CREDENTIAL_REFERENCE_NOT_ALLOWED`(토큰 방식에 `vault://` 참조),
  `VAULT_NAMESPACE_REQUIRES_ENTERPRISE`, `VAULT_MOUNT_REQUIRED`, `VAULT_PERMISSION_PATH_LIMIT`는 API 직접 호출에서만 나온다.

### 정리

- [ ] 시험 정책·역할·토큰을 지우거나 폐기하고, `sudo`를 준 시험 정책을 뺀다.

근거: vault/backend/cremore_vault_provider/onboarding.py, connection_login.py, vault/README.md,
web/console/views/integrations/copy.ts, model.ts, page.tsx, web/console/views/vaults/page.tsx, CHANGELOG.md

## Okta

### 준비

- [ ] (2026-10-07) Okta 관리 콘솔의 Applications and Resources → Applications → Create App Integration에서 API Services 앱을 만들고
  General 탭의 클라이언트 ID를 준비한다.
- [ ] (`서비스 앱(CreMore가 만든 키)`) 마법사에서 `인증키 만들기` 뒤 앱의 General → Client Credentials → Edit에서 Public key /
  Private key를 고르고 Add key에 `공개 키 복사`의 키를 붙여 넣고 저장한다.
- [ ] (2026-10-07) Okta API Scopes 탭에서 `okta.users.read`를 Grant한다(Grant는 Super Admin만 가능). Admin roles 탭에서 사용자
  보기만 있는 역할(사용자 정의 역할 View users and their details, 리소스 세트 모든 사용자)을, 쓸 수 없으면 Read-only
  Administrator를 준다.
- [ ] 앱 목록 옵션을 시험하면 `okta.apps.read`를 Grant하고 역할에 View applications and their details, 리소스 세트에 모든 앱을
  더한다(View client credentials는 주지 않는다).

### 마법사

- [ ] 기타 설정 → 디렉터리 동기화 → Okta → `서비스 앱(CreMore가 만든 키)`(권장) 또는 `개인 키 서비스 앱`. `Okta 조직 호스트`
  (`acme.okta.com`), 클라이언트 ID. `서비스 앱(CreMore가 만든 키)`은 `인증키 만들기` → 공개 키 등록 → `키 등록 완료·인증 확인`,
  `개인 키 서비스 앱`은 개인 키를 넣고 `인증 확인`.
- [ ] 수집 옵션: `사람 이름·이메일·부서 보관(담당자·연락 대상 표시)`(기본 켬, 시험 org 사용자만 둔다), `조직의 앱 목록을 읽어
  연동할 서비스 제안`(기본 끔). 실행 설정의 `사람 목록 · 수집 주기` 기본 `5분마다`.

### 권한 확인 정상 결과

- [ ] `users_read`(okta.users.read) 확인됨. 앱 목록 옵션이면 `apps_read`(okta.apps.read(앱 목록 옵션))도.

### 첫 수집 후 정상 결과

- [ ] 퇴사자 Credential의 "IdP 연결" 표에 이 연결이 `정상`과 마지막 수집 시각으로 보인다.
- [ ] 앱 목록을 켰으면 하루 한 번 도는 별도 수집(`Okta · <호스트> · apps`)이 생기지만 "IdP 연결" 표에는 나오지 않는다. 그 수집이
  끝나면 관리자의 연동 서비스 상단 `회사 IdP에 이미 있는 서비스`에 미연동 서비스가 `<서비스> 연동` 버튼으로 나온다.

### 문제 신호

- [ ] `OKTA_TOKEN_REFUSED`(공개 키·클라이언트 ID·권한), `OKTA_TOKEN_UNAVAILABLE`, `OKTA_ACCESS_DENIED`(`okta.users.read`·
  `okta.apps.read`와 관리자 역할), `OKTA_CLIENT_ID_INVALID`, `OKTA_PRIVATE_KEY_INVALID`, `OKTA_ORGANIZATION_HOST_INVALID`.

### 정리

- [ ] 시험 서비스 앱을 지우거나 키를 비활성화하고, Grant한 API 범위와 관리자 역할을 회수한다.

근거: okta/backend/cremore_okta_provider/onboarding.py, okta/README.md, docs/LEAVER_CHECK.md, cremore/onboarding/suggestions.py,
web/console/views/integrations/guide.tsx, model.ts, page.tsx, CHANGELOG.md

## Keycloak

### 준비

- [ ] 렐름에 서비스 계정을 켠 confidential client를 만들고 서비스 계정에 realm-management `view-users`를 준다. 관리 이벤트를
  읽으면 `view-events`도 준다. 클라이언트 목록 옵션의 `view-clients`는 Keycloak 26.8.0 전에는 클라이언트 시크릿도 보이므로,
  26.8.0 이상이거나 클라이언트 시크릿이 시험 값뿐인 시험 렐름에서만 켜고 끝나면 뺀다.
- [ ] (2026-10-07) 관리 이벤트 옵션은 Keycloak 26.2 이상이 필요하고, Realm settings → Events → Admin events settings에서 Save
  events·Include representation을 켠다.

### 마법사

- [ ] 기타 설정 → 디렉터리 동기화 → Keycloak, 제품 `Keycloak` / `Keycloak(호스팅)`. 인증 단계에 `Keycloak 주소`(`https://호스트[:포트]`만),
  `렐름`, `경로 접두어(예전 버전: /auth)`, 클라이언트 ID·시크릿.
- [ ] 수집 옵션: `사람 이름·이메일·부서 보관(담당자·연락 대상 표시)`, `렐름의 클라이언트 목록을 읽어 연동할 서비스 제안`(끔),
  `관리 이벤트 읽기(Keycloak 26.2 이상, …)`. 실행 설정의 `사람 목록 · 수집 주기` 기본 `60분마다`.

### 권한 확인 정상 결과

- [ ] `view_users` 확인됨. 관리 이벤트를 켜면 `view_events` 확인됨(끄면 그 행은 화면에 없고 API에만 `ADMIN_EVENTS_OFF`로 있다).
  클라이언트 목록을 켜면 `view_clients` 확인됨.

### 첫 수집 후 정상 결과

- [ ] 퇴사자 Credential의 "IdP 연결" 표에 이 연결이 `정상`과 마지막 수집 시각으로 보인다(Keycloak 26.3 로컬 Docker에서
  2026-09-28에 사용자 목록·관리 이벤트 수집을 확인한 적이 있다).

### 문제 신호

- [ ] `KEYCLOAK_ADDRESS_INVALID`(주소는 `https://호스트[:포트]`만, `/auth`는 경로 접두어 칸), `KEYCLOAK_REALM_INVALID`,
  `KEYCLOAK_PATH_INVALID`, `KEYCLOAK_CLIENT_INVALID`, `KEYCLOAK_TOKEN_REFUSED`, `KEYCLOAK_ACCESS_DENIED`,
  `KEYCLOAK_VIEW_CLIENTS_REQUIRED`.

### 정리

- [ ] 시험 client를 지우고 서비스 계정에 준 `view-events`·`view-clients`를 뺀다.

근거: keycloak/backend/cremore_keycloak_provider/onboarding.py, keycloak/README.md, docs/LEAVER_CHECK.md,
web/console/views/integrations/model.ts, CHANGELOG.md

## 퇴사자 점검 (2026-10-08)

사람 목록 연결(Okta·Keycloak·Google Workspace·Microsoft 사람 목록과 GitHub 사람 목록)이 모이면 "퇴사자 Credential"
(`?view=leavers`, Analyst 이상)이 퇴사한 사람과 그 사람이 남긴 Credential을 보여 준다([퇴사자 점검](LEAVER_CHECK.md)).
`지금 점검`은 관리자에게만 보인다. "연결 후보" 탭에는 퇴사한 사람과의 후보만 오른다.

### 준비

- [ ] 위 절의 안내대로 IdP 사람 목록 연결 하나 이상(둘이면 아래 두 IdP 항목도 시험한다: 예 Keycloak과 Google Workspace. 두 IdP는
  1인 설치(`AUTH_MODE=local`)에서만 연결된다)과 SAML SSO 시험 조직의 GitHub 사람 목록 연결이 `정상`이다. Keycloak 시험 사용자는
  `Email verified`를 켠다(Keycloak은 확인된 이메일만 대조 키로 남긴다).
- [ ] 퇴사는 시험 IdP 사용자를 비활성화·삭제해서만 만든다. 실제 직원 계정은 건드리지 않는다. 시험 사용자마다 시험 GitHub
  조직의 구성원 계정(SAML SSO로 연결)과 그 계정의 Credential 하나(예: 조직이 승인한 세분화 PAT)를 두고, GitHub 발급 목록 수집이
  그 Credential을 읽고 있다.

### 정상 결과

- [ ] "IdP 연결" 표에 IdP 사람 목록 연결은 "재직 상태", GitHub 사람 목록 연결은 "계정 신원 연결"로 보이고 상태가 `정상`이다.
- [ ] GitHub SAML·SCIM 신원은 같은 종류의 값과만 정확히 잇는다: SAML NameID는 IdP 사용자 ID·로그인·이메일, SCIM 사용자 이름은
  로그인·이메일, SAML·SCIM 이메일은 이메일과만. 시험 사용자를 비활성화하고 수집이 끝난 뒤 `지금 점검`을 누르면 그 Credential이
  "남은 Credential" 탭에 오르고, 상세의 `연결 근거`가 그 값의 종류(예: "확인된 이메일", "SAML NameID")다.
- [ ] 다른 종류의 값으로만 맞는 퇴사자(예: GitHub 신원의 SAML·SCIM 이메일이 Keycloak 시험 사용자의 이메일이 아니라 이메일 모양의
  사용자 이름과만 같음)는 자동으로 잇지 않고 "연결 후보" 탭("확정할 연결")에 오른다.
- [ ] 같은 업무 이메일을 가진 시험 사용자가 두 IdP에 있으면 GitHub 신원이 두 사람과 모두 이어지고 "연결 후보"에 오르지 않는다.
  한 IdP에서만 비활성화하고 `지금 점검`을 누르면 그 Credential 상세의 `IdP 상태`에 "IdP마다 상태가 다릅니다"가, 사유에 "IdP마다
  재직 상태가 다릅니다"가 보인다.
- [ ] 이메일이 다른 두 IdP의 시험 사용자 A·B에게 같은 신원 값(예: Keycloak 렐름 두 개에 같은 사용자 이름 `dana`, GitHub 신원의
  SAML NameID 또는 SCIM 사용자 이름 `dana`. Google Workspace는 사용자 ID·이메일만 대조 키로 남겨 로그인 값이 닿지 않는다)이
  닿으면 자동으로 잇지 않는다. A·B와 그 GitHub 신원 값은 두 IdP의 첫 수집이 끝난 뒤에 만든다(값이 A 한 사람에게만 닿는 동안
  5분마다 도는 점검이 이으면 그 연결이 남아 후보로 오르지 않는다). A를 비활성화하고 `지금 점검`을 누르면 "연결 후보" 탭에 그
  GitHub 계정과 A가 오른다. 관리자가 `같은 사람`으로 확정하면 다음 점검부터 그 Credential이 "남은 Credential"에 오르고 `연결
  근거`가 "관리자 확정"이다. B가 활성이면 사유에 "IdP마다 재직 상태가 다릅니다"도 붙는다.
- [ ] (2026-10-08) GitLab 사용자의 `extern_uid`(GitLab에 연결한 SAML·LDAP·OIDC 등 외부 로그인이 준 값)를 읽는 GitLab 인스턴스
  연결이 있으면 같은 규칙(한 사람에게만 닿을 때만 자동 연결)을 따른다. 이메일이 다른 두 IdP의 사람에게 닿아도 GitLab이 확인한
  기본 이메일이 그중 한 사람을 정확히 가리키면 그 사람과는 `연결 근거` "확인된 이메일"로 이어지고, 다른 사람은 "연결 후보"에 오른다.
  Bitbucket Cloud 로그인을 연결한 시험 사용자는 Bitbucket 사용자 이름이 다른 사람의 Keycloak 사용자 이름과 같아도 그 사람과 잇지
  않는다(GitLab 사용자 이름까지 같으면 "연결 후보"에만 오른다). GitHub 로그인의 `extern_uid`는 숫자 사용자 ID다.
- [ ] 퇴사 시각: 관리 이벤트를 켠 Keycloak 연결에서 시험 사용자를 비활성화하고 그 연결의 수집이 `완료`로 끝난 뒤 `지금 점검`을
  누르면 "퇴사자" 탭의 "퇴사 시각 근거"가 "관리 이벤트 시각"이다. 그 연결의 가장 최근 실행이 `완료`가 아니면 이벤트를 쓰지
  않는다(`GET /api/v1/leavers/summary`의 `reasons`에 `IDP_EVENTS_NOT_CURRENT`).
- [ ] 퇴사 시각: 관리 이벤트를 끈 Keycloak 연결에서 시험 사용자를 삭제하면 근거가 "목록에서 처음 빠진 수집 시각"이고, 퇴사 시각(값에
  마우스를 올리면 보이는 시각)이 그 사용자가 빠진 수집 실행이 끝난 시각과 같다(시작 시각이 아니다).
- [ ] 퇴사 시각: 관리 이벤트를 켠 Keycloak에서 퇴사로 본 시험 사용자를 다시 활성화했다가 비활성화하면 새 비활성화의 시각이 퇴사
  시각이 된다.

### 문제 신호

- [ ] `PARTIAL`: 목록을 끝까지 읽지 못하면(목록당 10만 행 한도, 읽는 중 변경) 점검이 판정·연결을 바꾸지 않는다. 화면 배너
  "마지막 점검이 목록을 끝까지 읽지 못해 판정·연결을 새로 내리지 않았습니다(…). 판정과 연결은 마지막으로 끝까지 마친 점검의
  결과이고, 끝까지 읽은 IdP의 재직 상태는 반영했습니다."와 `지금 점검`의 알림 "목록을 끝까지 읽지 못해 판정을 바꾸지
  않았습니다"가 나오고, 괄호 안에 목록 이름(예: "IdP 사람 목록 한도 초과", "발급 목록 읽는 중 변경")이 보인다. 요약 API의
  `status`·`reasons`(`IDP_PEOPLE_LIMIT_REACHED`·`ISSUED_CREDENTIALS_CHANGED_WHILE_READ`·`DIRECTORY_ACCOUNTS_LIMIT_REACHED`·
  `COVERAGE_REPORT_LIMIT_REACHED` 등)를 기록한다. 시험 규모로는 일부러 만들 수 없으므로 나타날 때만 기록한다.

### 정리

- [ ] 시험 IdP 사용자와 시험 GitHub 구성원의 Credential을 지운다. 관리자가 내린 연결 결정(확정·거절)은 감사 기록으로 남고,
  퇴사자 행은 보존 기간("IdP 연결" 표 머리의 `퇴사 후 N일 보관`) 뒤 정리된다.

근거: cremore/identity/leavers.py, cremore/api/routes/leavers.py, web/console/views/leavers/page.tsx, docs/LEAVER_CHECK.md,
CHANGELOG.md

## 실효 권한 검증 (AWS·GCP·Azure)

세 공급자 모두 "실제 요청의 성공"을 확인하지 않는다. AWS는 정책 시뮬레이션, GCP는 Google의 판정, Azure는 부여 목록이다
([권한 평가의 근거와 한계](PERMISSION_ASSESSMENT.md)).

### AWS 잠재 권한 (`assessment_version` 3)

설정:

- [ ] 대상은 노출 검사로 발견된 AWS 액세스 키(AKIA/ASIA)다. 발급 목록에만 있는 키는 정책 메타데이터만 보이고 시뮬레이션하지
  않는다. 일회용 시험 키: 시험 계정에 시험 정책만 붙인 IAM 사용자를 만들고 그 키를 비공개 시험 위치(시험 버킷·저장소)에 둔 뒤
  노출 검사로 발견되게 한다. 확인이 끝나면 키와 사용자를 삭제한다.
- [ ] 설치 스위치(최종 확인의 "발견한 자격증명 조사"): `발견한 키의 실제 사용 내역`(`AWS_USAGE_LOOKUP_MODE`)과 `잠재 접근 권한
  시뮬레이션`(`IAM_POTENTIAL_ACCESS_MODE`)을 켠다.
- [ ] 그 키의 계정 IAM 발급 목록이 최신·완전해야 키 소유자가 정해진다.
- [ ] 수집 역할에 `iam:SimulatePrincipalPolicy`, IAM 정책 읽기, `s3:GetBucketPolicy`, `secretsmanager:GetResourcePolicy`,
  (2026-10-08) `kms:GetKeyPolicy`가 있다. 멤버 역할 템플릿(`KmsKeyPolicyRead`)과 단일 계정 템플릿은 이 계정의 키
  (`arn:<파티션>:kms:*:<계정>:key/*`)에만 주고, IAM Identity Center 권한 세트·`현재 서버 권한 직접 사용`의 읽기 정책(`정책 복사`)에도
  들어 있다. 2026-10-08 전에 만든 `cremore-scanner` 스택은 새 템플릿으로 갱신한다(갱신 전에는 키 정책을 읽지 못해 "키 정책을 읽지
  못한 키"로 보인다).
- [ ] Credential 패널의 "사용 기록" 카드에서 `지금 조회`(Analyst 이상).

정상 결과:

- [ ] "권한과 접근 범위" 카드의 `정책 시뮬레이션 · 평가 N개`에 "선별한 작업 · 리소스 *와 주체 정책에 적힌 리소스 N개 · 요청 조건
  미입력. 실제 접근 권한은 평가하지 않았습니다."와 작업마다 "허용 (잠재 권한)", "지정 리소스 N개에서 허용 (잠재 권한)"(그 아래
  ARN), "명시적 거부 (시뮬레이션)", "허용 근거 없음 (시뮬레이션)", "조직: … · 권한 경계: …"가 보인다.
- [ ] `assessment_version` 3 결과에는(역할 키도) "IAM 사용자는 주체 정책에 ARN 하나로 적힌 같은 계정 S3 버킷·Secrets Manager
  시크릿·KMS 키의 정책도 함께 시뮬레이션하고, KMS 키는 키 정책이 IAM 정책에 사용 허용을 위임하거나 사용자에게 직접 허용하는지도
  확인합니다…"가 보인다.
- [ ] `GET /api/v1/credentials/{credential_id}/usage`의 `potential_access`에 `assessment_version: 3`, `resource_arns`(`*`와 지정
  ARN), `named_resources[]`(`resource`·`actions`·`allowed`·`explicit_deny`·`missing_context_values`·`resource_policy`가
  `EVALUATED`/`NONE`/`NOT_READ`/`NOT_SUPPORTED`, (2026-10-08) 값이 있을 때만 `key_policy_blocks`·`conditional`),
  `named_resources_complete`가 있다.
- [ ] (2026-10-08) IAM 사용자의 정책이 KMS 키 하나를 키 ARN으로 적어 `kms:Decrypt`를 허용하면 그 키의 키 정책을 읽는다. 키 정책이
  계정에 위임하지도 사용자를 직접 허용하지도 않으면 작업 아래에 "키 정책에 막힌 키: <ARN>"이 보이고, 다른 키에서 허용되지
  않았으면 판단이 "IAM 정책은 허용, KMS 키 N개의 키 정책에 막힘 (시뮬레이션)"이다. 키 정책을 읽지 못한 키는 "키 정책을 읽지 못한
  키(주체 정책만으로 판단): <ARN>", 조건부로만 허용되면 "요청 조건에 따라 다름: <ARN> (<조건 키>)"가 보인다. 구체적인 시험은
  "문서로 확정하지 못한 항목 확인법 g".
- [ ] (2026-10-08) 알려진 동작: 주체 정책이 키를 별칭 ARN(`arn:aws:kms:<리전>:<계정>:alias/<이름>`)이나 리전 자리에 `*`가 든
  ARN(`arn:aws:kms:*:<계정>:key/*`)으로만 적으면 지정 리소스로 시뮬레이션하지 않아 `kms:Decrypt`가 "허용 근거 없음 (시뮬레이션)"으로
  남는다.
- [ ] 정책에 적힌 ARN이 25개를 넘으면 "정책에 적힌 리소스가 많아 앞의 25개만 시뮬레이션했습니다."가 보인다.
- [ ] 위험 분석 탭 "노출 단계" 카드의 "권한"이 관측됨이다(정책을 읽었으면 "IAM 정책 N개", 시뮬레이션만 있으면 "시뮬레이션 ·
  잠재 허용 N개").

문제 신호:

- [ ] `USAGE_LOOKUP_OFF`(501, 사용 내역 조회 꺼짐), `ACCOUNT_OWNER_UNKNOWN`(409, IAM 발급 목록으로 소유자를 정하지 못함),
  `AWS_LOGIN_REQUIRED`(409). 조회가 실행 중이면 버튼이 `수집 중지`로 바뀐다.
- [ ] "권한 시뮬레이션을 마치지 못했습니다(코드)", "권한 시뮬레이션이 일부 작업만 판단했습니다", "시뮬레이션에 필요한 조건 입력이
  없습니다…", "이전 시뮬레이션은 누락된 조건 정보를 보존하지 않았습니다…"(오래된 저장 결과 → 다시 조회).
- [ ] `resource_policy: NOT_READ`(버킷 정책·키 정책 읽기 실패, 다른 계정 리소스, `*`·`?`가 든 ARN) 또는 `NOT_SUPPORTED`(역할
  주체 등).

### GCP 실효 판정 (`effective_access`)

설정:

- [ ] 연결 신원에 조직 수준 Security Reviewer(`roles/iam.securityReviewer`)와 Deny Reviewer(`roles/iam.denyReviewer`)를 준다
  (시험 조직에서만).
- [ ] 그룹으로 받은 권한까지 보려면 Workspace 관리자 역할의 그룹 읽기 권한(Workspace Admin API `groups.read`)을 준다.
- [ ] Policy Troubleshooter API를 연결 신원의 프로젝트(Google 로그인은 OAuth 앱 프로젝트)에서 사용 설정한다.
- [ ] 시험 프로젝트에 사용자 관리 키가 있는 서비스 계정을 둔다. 판정 대상은 수집마다 계정 이메일 순 최대 20개다. 가능하면
  고위험 권한 중 하나를 프로젝트에서 받은 계정, 거부 정책으로 그 권한을 막은 계정, 그룹으로 역할을 받은 계정을 각각 둔다.
- [ ] 수집 옵션 `키가 있는 서비스 계정: 고위험 권한의 실효 판정(Policy Troubleshooter)`을 켠다.

정상 결과:

- [ ] 권한 확인: `resourcemanager.projects.getIamPolicy`, `iam.roles.get`, `iam.denypolicies.get`, `iam.denypolicies.list`가 확인된다
  (점검은 프로젝트의 `testIamPermissions`만 묻고 조직·폴더의 역할 자체는 점검하지 않는다).
- [ ] 키의 `발급 항목 보기` "권한과 범위"에 11개 권한(`iam.serviceAccountKeys.create`, `iam.serviceAccounts.actAs`,
  `iam.serviceAccounts.getAccessToken`, `resourcemanager.projects.setIamPolicy`, `secretmanager.versions.access`,
  `cloudkms.cryptoKeyVersions.useToDecrypt`, `storage.objects.delete`, `cloudfunctions.functions.update`, `run.services.update`,
  `compute.instances.create`, `storage.objects.get`)이 리소스 `project: projects/<프로젝트>`로 보이고, 효과가 "접근 가능"·"접근
  불가"·"정보 부족으로 판정 불가"·"요청 조건에 따라 다름"·"판정하지 못함" 중 하나다. 거부 정책이 막으면 "거부 정책 적용"이 붙는다.
- [ ] "권한과 접근 범위" 카드에는 "접근 가능"(`CAN_ACCESS`)인 권한만 한국어 설명(예: "서비스 계정 키 새로 만들기")과 함께 보인다.
- [ ] 같은 계정의 사용자 관리 키마다 같은 답이 붙고, Google 관리 키에는 붙지 않는다.
- [ ] 수집 보고 `gcp.service_account_keys`는 키 목록을 끝까지 읽었으면 판정 실패와 무관하게 `완료`다. 사실 `selection`에
  "effective access answered for N accounts with user-managed keys, M not evaluated (limit 20…)", `effective_access`에 상태별 개수,
  `error_counts`에 `troubleshooter_<코드>`가 있다.

문제 신호:

- [ ] 모든 답이 "정보 부족으로 판정 불가"(`unknown_info`): 조직 수준 검토자 역할이 빠졌다.
- [ ] "판정하지 못함" + "API가 꺼져 있음"(`api_disabled`, 그 계정의 나머지는 묻지 않는다) 또는 "권한이 없거나 API가 꺼져 있음".
  `selection`의 "stopped after <코드>"는 한 계정의 호출이 모두 실패해 이후 계정을 묻지 않았다는 뜻이다.
- [ ] 그룹으로 받은 권한이 "정보 부족으로 판정 불가": 그룹 읽기 권한이 없다.
- [ ] 권한 확인의 모든 행이 `HTTP 400`(툴팁에서는 `알 수 없음`): 아래 "a"로 원인을 가린다.

정리:

- [ ] 조직 수준 Security Reviewer·Deny Reviewer와 Workspace 그룹 읽기 권한을 회수하고, 시험 거부 정책·서비스 계정·그룹을 지운다.

### Azure 앱 자격증명 권한 (`app_permissions`·`app_azure_roles`)

설정:

- [ ] `app_permissions`: Graph 애플리케이션 권한 RoleManagement.Read.Directory(기존 Application.Read.All에 더해)와 관리자 동의.
- [ ] `app_azure_roles`: 권한 확인 단계 설정 도우미 "Azure 역할 할당"의 `역할 명령 복사`에 든 두 줄을 실행한다.
  `az role definition create --role-definition '{"Name":"CreMore Role Assignment Reader",…,"Actions":["Microsoft.Authorization/roleAssignments/read","Microsoft.Authorization/roleDefinitions/read"],"AssignableScopes":["/providers/Microsoft.Management/managementGroups/<테넌트 ID>"]}'`와
  `az role assignment create … --role "CreMore Role Assignment Reader" --scope /providers/Microsoft.Management/managementGroups/<테넌트 ID>`.
- [ ] 테넌트 루트 관리 그룹(ID = 테넌트 ID)이 있다. 관리 그룹을 처음 쓸 때 만들어지며, 전역 관리자가 Azure 리소스 액세스 관리를
  켜면 그 범위의 사용자 액세스 관리자가 된다. Azure 역할은 Azure 글로벌 클라우드에서만 켤 수 있다.
- [ ] 시험 앱(비밀 또는 인증서가 있는 앱 등록)과 그 서비스 주체에 읽기 전용 애플리케이션 권한 1개(예: User.Read.All), 읽기 전용
  Entra 역할 1개(예: Directory Readers), 구독에 직접 준 `Reader`, 그룹으로 받은 `Reader`를 준다. 판정 대상은 수집마다 서비스 주체
  개체 ID 순으로 최대 50개이므로 서비스 주체가 50개 이하인 시험 테넌트를 쓴다.

정상 결과:

- [ ] 권한 확인: `role_management_read`(전역 관리자 역할 정의 읽기), `root_role_assignments`(루트 관리 그룹의 `atScope()` 역할 할당
  목록)가 확인된다.
- [ ] 시험 앱의 비밀·인증서 Credential의 "권한과 접근 범위"에 `<API 이름>: <권한>`(예: `Microsoft Graph: User.Read.All`), Entra 역할
  이름(관리 단위·앱 범위면 `<역할> · <범위>`), Azure 역할 `<역할> · <범위>`(예: `Reader · /subscriptions/…`)가 보인다. 쓰기·읽기는
  범위가 아니라 역할·권한 이름으로 정해진다(Contributor는 `쓰기`, Reader는 읽기).
- [ ] `발급 항목 보기`: 종류 `권한`·`역할`, 효과 "허용", 그룹으로 받은 Azure 역할은 "그룹으로 받음", 조건이 있으면 "조건부 할당".
- [ ] 수집 보고 `app_access`는 `완료`이고 사실 `selection`이 "… for N of M service principals with sign-in credentials (limit 50);
  K credentials without a listed service principal" 형식이다. 읽기 실패가 자격증명 목록과 실행 상태를 부분으로 바꾸지 않는다.

문제 신호:

- [ ] 효과 "알 수 없음" 항목 하나(이름 `app_role_assignment`·`directory_role_assignment`·`azure_role_assignment`)와 오류 "권한
  없음"·"인증 실패"·"요청 실패". `selection`의 "not asked again after <종류> <코드>"는 모든 서비스 주체에서 되풀이될 실패라 다시
  묻지 않았다는 뜻이다.
- [ ] 점검의 `AZURE_ROOT_MANAGEMENT_GROUP_NOT_FOUND`, 수집의 Azure 역할 `http_404`: 루트 관리 그룹이 없다.
- [ ] "권한이 250개를 넘어 나머지는 보관하지 않음", 역할 정의를 못 읽은 할당은 `Azure role <ID>`로 보인다.

정리:

- [ ] 시험 앱에 준 애플리케이션 권한·Entra 역할·Azure 역할 할당, `CreMore Role Assignment Reader` 정의와 할당, Azure 리소스
  액세스 관리 상승을 되돌린다.

근거: aws/backend/cremore_aws_provider/investigation/potential_access.py, investigation/usage.py, aws_identity.py,
deploy/cloudformation/member-account-role.yaml, single-account.yaml, cremore/api/routes/findings.py,
gcp/backend/cremore_gcp_provider/metadata/effective_access.py, metadata/adapter.py,
azure/backend/cremore_azure_provider/entra/permissions.py, onboarding.py, web/console/views/credentials/permissions.tsx,
issued.tsx, tabs.tsx, usage.tsx, web/console/views/integrations/aws-settings.tsx, guide.tsx, cremore/api/credential_records.py,
docs/PERMISSION_ASSESSMENT.md, gcp/README.md, azure/README.md, aws/README.md

## 문서로 확정하지 못한 항목 확인법

### a. GCP: `testIamPermissions`가 `iam.denypolicies.get`·`iam.denypolicies.list`를 받는가

[권한 평가의 근거와 한계](PERMISSION_ASSESSMENT.md) 검증 기록과 구현 기록 2026-10-07 절이 미검증으로 적었다.

- [ ] 1) 조직에 속한 시험 프로젝트로 Google Cloud 연결을 만들고 발급 목록 수집을 고른다. 권한 확인 단계에서 `effective_access`를
  끈 채 `권한 확인·다음`을 눌러 기본 행이 확인됨 또는 `MISSING`으로 답하는지 본다(기준선).
- [ ] 2) `키가 있는 서비스 계정: 고위험 권한의 실효 판정(Policy Troubleshooter)`을 켜고 다시 `권한 확인·다음`을 누른다.
- [ ] 정상: 네 행(`resourcemanager.projects.getIamPolicy`, `iam.roles.get`, `iam.denypolicies.get`, `iam.denypolicies.list`)이 각각
  확인됨 또는 `MISSING`으로 답하고 기본 행은 1)과 같다.
- [ ] 실패: 기본 행을 포함한 모든 행이 `HTTP 400`(툴팁에서는 `알 수 없음`)이다(점검은 한 요청으로 모든 권한을 묻고, 401·403이
  아닌 응답은 모든 행에 `NOT_REPORTED`와 `HTTP_400`을 남긴다). 1)로 돌아가 옵션을 끄면 다시 정상으로 답한다.
- [ ] (선택) Cloud Shell(Bash)에서 같은 API로 확인한다(로그인한 gcloud 계정 기준이라 확인됨·없음은 연결 신원과 다를 수 있고,
  400 여부만 본다):
  `curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" -d '{"permissions":["iam.denypolicies.get","iam.denypolicies.list"]}' "https://cloudresourcemanager.googleapis.com/v1/projects/<PROJECT_ID>:testIamPermissions"`.
  정상: `permissions` 배열(또는 빈 객체)이 온다. 실패: HTTP 400 오류.

### b. Azure: 루트 관리 그룹의 `assignedTo('<서비스 주체 개체 ID>')`가 하위 범위 할당까지 돌려주는가

[azure/README](../azure/README.md)와 [권한 평가의 근거와 한계](PERMISSION_ASSESSMENT.md)가 실제 테넌트에서 확인하지 않았다고
적었다(REST 문서의 "at, above or below the scope"는 `principalId eq` 필터에 대한 설명이고, `assignedTo`의 하위 범위 반환은 이
시험으로 확인한다).

- [ ] 1) 비밀이 있는 시험 앱의 서비스 주체에 구독 하나의 `Reader`를 직접 준다(`az role assignment create --assignee <앱 ID>
  --role "Reader" --scope /subscriptions/<구독 ID>`). 쓰기 역할은 이 시험에 필요 없다.
- [ ] 2) 보안 그룹을 만들어 그 서비스 주체를 구성원으로 넣고, 그 그룹에 같은 구독의 리소스 그룹 하나에 대한 `Reader`를 준다.
- [ ] 3) Microsoft 연결에 `앱 자격증명이 할 수 있는 일: Azure 역할`을 켜고(위 "Azure 앱 자격증명 권한" 설정), 역할 전파를 기다린 뒤
  `지금 수집`한다.
- [ ] 정상: 시험 앱 비밀의 "권한과 접근 범위"에 `Reader · /subscriptions/<구독 ID>`와 `Reader · /subscriptions/<구독 ID>/resourceGroups/<리소스
  그룹>`이 모두 보이고, `발급 항목 보기`에서 리소스 그룹 쪽 행에 "그룹으로 받음"이 붙는다.
- [ ] 실패: 두 행이 없거나 하나만 있다(루트 관리 그룹 범위의 할당만 돌아옴), 또는 효과 "알 수 없음"의 `azure_role_assignment`가
  오류와 함께 남는다. 기록에 어느 경우인지 적는다.
- [ ] 4) 정리: 두 역할 할당과 시험 보안 그룹을 지운다.

### c. Azure: 사용자 지정 역할 명령이 Azure Cloud Shell(Bash)에서 그대로 실행되는가

검증 기록이 "실제 Cloud Shell에서 그대로 실행되는지는 확인하지 않았다"고 적었다.

- [ ] 1) 권한 확인 단계 설정 도우미 "Azure 역할 할당"의 `역할 명령 복사`를 그대로 Azure Cloud Shell(Bash)에 붙여 넣는다. 실행자는
  루트 관리 그룹에서 역할 할당 권한이 있는 사람(소유자 또는 사용자 액세스 관리자)이다.
- [ ] 2) `az role definition create --role-definition '<JSON>'` 줄이 수정 없이 끝나는지 본다.
- [ ] 3) 이어지는 `az role assignment create … --role "CreMore Role Assignment Reader" --scope /providers/Microsoft.Management/managementGroups/<테넌트 ID>`
  줄이 역할을 찾지 못하면 몇 분 뒤 그 줄만 다시 실행한다(안내 문구대로 새 역할이 퍼지는 데 몇 분 걸린다).
- [ ] 정상: 두 줄이 수정 없이 끝나고(할당은 재시도 후 포함), `권한 확인·다음`에서 `root_role_assignments`가 확인된다.
- [ ] 실패: 따옴표·JSON 해석 오류로 정의 줄이 그대로 실행되지 않는다, 재시도해도 할당이 실패한다, 또는 점검이 `HTTP_403`("이
  조회가 거절되었습니다. …")·`AZURE_ROOT_MANAGEMENT_GROUP_NOT_FOUND`다. 오류 문구에서 비밀이 아닌 부분만 기록한다.

### d. AWS: 명시적 거부 버킷 정책이 있는 IAM 사용자에 대해 `EXPLICIT_DENY`가 나오는가

구현은 IAM 사용자일 때 같은 계정 버킷 정책을 `ResourcePolicy`로 넣는다. 실제 AWS 호출로는 확인하지 않았다(합성 응답만).

- [ ] 1) 시험 계정에 버킷 `<버킷>`과 객체 `<키>`를 만든다. IAM 사용자 `<사용자>`에 인라인 정책 하나만 붙인다: `s3:GetObject`를
  `arn:aws:s3:::<버킷>/<키>`에만 허용(`*`에는 허용이 없어야 지정 리소스 시뮬레이션이 돈다).
- [ ] 2) 대조군: 버킷 정책 없이 "AWS 잠재 권한" 설정대로 그 사용자 키를 발견시키고 `지금 조회`한다. 정상이면 `s3:GetObject`가
  "지정 리소스 1개에서 허용 (잠재 권한)"과 그 ARN으로 보이고, API의 `named_resources[]`에 `resource: arn:aws:s3:::<버킷>/<키>`,
  `allowed`에 `s3:GetObject`, `resource_policy: NONE`이 있다.
- [ ] 3) 버킷 정책에 그 사용자 ARN을 주체로 `arn:aws:s3:::<버킷>/<키>`의 `s3:GetObject`를 `Deny`하는 문장을 넣고 다시 `지금 조회`한다.
- [ ] 정상: 같은 `named_resources[]` 항목에 `explicit_deny: ["s3:GetObject"]`, `resource_policy: "EVALUATED"`가 있고, 화면의
  `s3:GetObject`는 "허용 근거 없음 (시뮬레이션)"이다(지정 리소스에서 허용되지 않음).
- [ ] 실패: `resource_policy`가 `EVALUATED`인데 `explicit_deny`가 비어 있고 여전히 "지정 리소스 1개에서 허용"이다(거부가 반영되지
  않음), 또는 `NOT_READ`(버킷 정책을 읽지 못함 → 수집 역할의 `s3:GetBucketPolicy`·버킷 소유 계정 확인).
- [ ] (선택) 같은 계정 관리자가 AWS CloudShell에서 교차 확인한다. 먼저
  `aws s3api get-bucket-policy --bucket <버킷> --query Policy --output text > bucket-policy.json`으로 정책 파일을 만들고,
  `aws iam simulate-principal-policy --policy-source-arn <사용자 ARN> --action-names s3:GetObject --resource-arns arn:aws:s3:::<버킷>/<키> --resource-policy file://bucket-policy.json`.
  정상: `EvalDecision`이 `explicitDeny`.
- [ ] 끝나면 시험 키·사용자·버킷 정책, 시험 위치에 둔 키 파일, `bucket-policy.json`을 지운다.

### e. Bitbucket: `/2.0/user/workspaces` 응답 모양과 SSH 키 목록

워크스페이스 목록은 2026-04-14에 없어진 `/2.0/workspaces` 대신 `/2.0/user/workspaces`를 읽는다(2026-10-07). 코드는 행이
워크스페이스 자체이거나 `workspace`를 가진 구성원 정보인 두 모양을 모두 받지만 합성 응답으로만 검사했다. SSH 키는 구성원마다
`/users/{user}/ssh-keys`로 읽으며, 수집기는 `workspace-ssh-keys`를 공개 목록 계약이 미확인인 항목(`public_listing_contract_unverified`)
으로 표시한다. README는 실제 tenant 호출을 하지 않았다고 적었다.

- [ ] 1) `Atlassian API 토큰과 이메일`(고급) 방식으로 인증하고 `대상 불러오기`를 누른다(워크스페이스 액세스 토큰 방식은 이 목록을
  부르지 않는다).
- [ ] 정상: 그 계정이 속한 워크스페이스가 이름(없으면 slug)으로 모두 나오고, 고르면 대상의 워크스페이스가 그 slug다.
- [ ] 실패: `MALFORMED_RESPONSE`·`PAGINATION_INVALID`, 속한 워크스페이스가 빠짐, 이름·slug가 빈 행.
- [ ] 2) 시험 구성원 계정마다(API 토큰 방식은 토큰을 낸 계정 포함) 이 시험용으로 새로 만든 SSH 공개 키를 하나씩 등록하고 발급
  목록을 수집한다. API 토큰 방식(`read:ssh-key` 포함)과 워크스페이스 액세스 토큰 방식을 따로 시험한다. 워크스페이스 액세스
  토큰은 구성원 목록으로만 키를 찾는다.
- [ ] 정상(기록): Credential 목록의 `SSH 키`에 어느 구성원의 키가 보이는지 방식별로 적는다. 유형 설명이 "Bitbucket이 이 토큰에
  보여 주는 만큼"이므로 보이는 범위 자체가 확인 결과다.
- [ ] 실패: 토큰 계정 자신의 키도 없거나, 수집 보고의 `user-ssh-keys`·`user-ssh-key-detail`이 `실패`·`일부 완료`(403 등)다.
- [ ] 3) 정리: 등록한 SSH 키와 시험 토큰을 지운다.

### f. 그 밖에 2026-10-07·2026-10-08 변경 중 실환경 미검증으로 적힌 것

- [ ] Confluence Cloud 서비스 계정의 범위 지정 API 토큰(Bearer, 게이트웨이 주소): atlassian/README가 "실제 Atlassian 조직에서는
  검증하지 않았다". `API 토큰` 방식으로 연결해 `read_space`·`read_content`가 확인되면 정상, `HTTP_401`·`HTTP_403`이면 실패(개인 API
  토큰을 넣지 않았는지 먼저 확인). 토큰이 거절되면 `인증 확인`이 먼저 `…/wiki/rest/api/user/current`를 읽으므로 그 코드가 인증
  단계의 빨간 배너에 나온다. `<Cloud ID>`는 `https://<사이트>/_edge/tenant_info`의 `cloudId`다.
- [ ] Microsoft 연결의 서비스 주체로 Azure DevOps Token Admin PAT 목록 읽기: azure/README가 "실제 조직에서 확인하지 않았다".
  Project Collection Administrators에 넣은 앱으로 `token_administration`이 확인되면 정상, 거절(`HTTP_203`·`HTTP_401`·`HTTP_403`)이나
  "확인할 사용자 없음"(`NO_USER_TO_ASK_ABOUT`: Graph 사용자 목록이 거절됐거나 비어 있음)이면 실패.
- [ ] GitHub 사람 목록의 소유자 확인(`viewerCanAdminister`·`ownerInfo`): github/README가 "실제 조직·엔터프라이즈로는 확인하지
  않았다". 조직 소유자 토큰의 `admin_org` 확인됨, 엔터프라이즈 소유자 토큰의 `read_enterprise` 확인됨, `read:enterprise`를 가진
  결제 관리자 토큰(대상에 엔터프라이즈, 엔터프라이즈 신원 읽기 켬)의 `NOT_AN_OWNER`가 나오면 정상. 결제 관리자가 `read:enterprise`
  classic PAT를 만들 수 있는지도 기록한다.
- [ ] (2026-10-08) GitHub App의 조직 SAML 신원 읽기: github/README가 "실제 GitHub 조직에서 App으로 읽는 것은 실환경 검증 항목"이라
  적었다. GitHub 절의 항목(설치 토큰이 `organization.samlIdentityProvider.externalIdentities`를 돌려주는지, SAML 미설정 조직의
  `GITHUB_IDENTITY_SAML_NOT_ENABLED`)으로 확인한다.
- [ ] (2026-10-08) GHE.com의 Enterprise 전체 자격증명 목록(Export): GitHub의 출시 공지는 Enterprise Cloud만 적었고 CreMore는 같은
  API 문서를 따르는 GHE.com 연결에도 허용한다. GHE.com 시험 엔터프라이즈에서 `enterprise_credentials_read`가 확인되고 첫 Export
  수집이 `완료`면 정상, 생성 요청이 404 등으로 거절되면 실패로 기록한다.
- [ ] Slack 인증·수집 전체(시험 조직에서만): slack/README가 "실제 Slack 조직에서의 인증·수집은 검증하지 않았다".
  `admin.teams:read` 없이 조직만 대상으로 나오고 `admin_apps_read`가 확인되며 승인 앱이 봇 토큰·사용자 토큰·수신 웹훅 행으로
  나오면 정상.
- [ ] Okta 실제 조직 연동(시험 org에서만): okta/README가 "실환경 검증 항목". Super Admin이 Grant한 `okta.users.read`로
  `users_read`가 확인되고 사람 목록 수집이 `완료`면 정상.
- [ ] Vault·OpenBao 실제 서버의 정책 판단: vault/README가 "실제 서버·namespace별 ACL·제품 버전·Enterprise 라이선스 조건은 합성
  테스트로 검증되지 않는다". 새 마법사에서는 `secret/metadata/*`의 `list`로 `kv_list`가 subject `secret/metadata/`에서, 기존 설정
  화면에서 접두어 `team-a`를 적으면 `secret/metadata/team-a/*`의 `list`로 subject `secret/metadata/team-a/`에서 확인되면 정상. 같은
  정책인데 그 행이 `MISSING`이면 실패.
- [ ] GitLab 역할 확인: gitlab/README가 "실제 API 권한·버전·라이선스 조합은 … 후속 확인". Owner 역할 그룹 토큰의 `owner`, Developer
  역할 그룹 토큰의 `ACCESS_LEVEL_TOO_LOW`가 각각 나오면 정상.
- [ ] 승인된 조치(GCP 키 비활성화·삭제, GitLab·Notion·Azure DevOps 토큰 폐기, GitHub 조직 접근 회수): PROVIDER_ACTIONS가
  "실제 … 환경에서는 검증하지 않았다". 이 문서 범위에서는 조치 연결의 권한 확인까지만 하고, 실제 실행은 설치의
  `ACTION_EXECUTION_ENABLED`가 켜진 시험 설치에서 시험 조직의 시험 자격증명으로만 따로 한다. 키 영구 삭제와 토큰 폐기·조직 접근
  회수는 되돌릴 수 없어 `ACTION_DELETION_ENABLED`도 켜야 한다(API와 워커에 같은 값). 꺼져 있으면 `DELETION_DISABLED`다. GCP 키
  비활성화는 `ACTION_EXECUTION_ENABLED`만 있으면 된다.
- [ ] AWS `aws sso login --use-device-code` 기기 인증(기존 1인 설치만): aws/README가 "합성 OIDC로만 검증했다". 스캔 권한 세트만
  가진 시험 전용 IAM Identity Center 사용자로 AWS 접근 포털에서 코드를 승인하면 AWS 신원 화면의 로그인 경고가 사라지면 정상(승인한
  사람이 CreMore의 AWS 신원이 된다).

### g. AWS: KMS 키 정책 판정과 시뮬레이터 응답 (2026-10-08)

[권한 평가의 근거와 한계](PERMISSION_ASSESSMENT.md) 검증 기록이 실제 AWS 계정의 `GetKeyPolicy`·시뮬레이터 응답(키 정책을 넣은
시뮬레이션의 결정, `SourcePolicyType` 문자열, 리전·계정 자리에 `*`가 든 ARN을 `ResourceArns`로 받는지)을 확인하지 않았다고
적었다(합성 응답만).

- [ ] 1) 준비: "AWS 잠재 권한" 설정을 마친다(수집 역할 스택은 `kms:GetKeyPolicy`가 든 템플릿으로 갱신). 시험 계정에 대칭 KMS 키
  세 개를 만든다. 세 키 정책 모두 키를 만드는 시험 관리자 역할에 키 관리(`kms:*`) 문장을 둔다(빠지면 키를 관리할 수 없게 된다).
  - 키 A: 기본 키 정책(`arn:aws:iam::<계정>:root`에 `kms:*`, IAM 정책 위임).
  - 키 B: root 위임 문장 없이, 수집 역할(`CredentialExposureScannerRole`) ARN에 `kms:GetKeyPolicy`만 허용하는 문장을 더한 키 정책.
  - 키 C: root 위임 문장도 수집 역할 문장도 없는 키 정책.
  - 시험 전용 IAM 사용자 `<사용자>`에는 인라인 정책 하나만 붙인다: `kms:Decrypt`를 키 A의 키 ARN
    (`arn:aws:kms:<리전>:<계정>:key/<키 ID>`)에만 허용. 이 사용자의 액세스 키를 "AWS 잠재 권한" 설정대로 발견시킨다.
- [ ] 2) `지금 조회`. 정상: `kms:Decrypt`가 "지정 리소스 1개에서 허용 (잠재 권한)"과 키 A ARN이다. API `named_resources[]`의 키 A
  항목은 `resource_policy: "EVALUATED"`, `allowed: ["kms:Decrypt"]`다.
- [ ] 3) 인라인 정책의 리소스를 키 B ARN으로 바꾸고 `지금 조회`. 정상: "IAM 정책은 허용, KMS 키 1개의 키 정책에 막힘
  (시뮬레이션)"과 "키 정책에 막힌 키: <키 B ARN>". API는 `resource_policy: "EVALUATED"`, `key_policy_blocks: ["kms:Decrypt"]`,
  `allowed: []`다.
- [ ] 4) 키 C ARN으로 바꾸고 `지금 조회`. 정상: "지정 리소스 1개에서 허용 (잠재 권한)"과 "키 정책을 읽지 못한 키(주체 정책만으로
  판단): <키 C ARN>". API는 `resource_policy: "NOT_READ"`다.
- [ ] (선택) 인라인 정책의 리소스를 이 계정의 AWS 관리형 키(예: `aws/secretsmanager`)의 키 ARN으로 바꾸고 `지금 조회`. 정상:
  "요청 조건에 따라 다름: <ARN> (<조건 키>)"가 보이고(AWS 관리형 키 정책의 조건 키는 `kms:CallerAccount`·`kms:ViaService`) API의
  그 항목에 `conditional: ["kms:Decrypt"]`가 있다. 괄호 안의 조건 키를 기록한다.
- [ ] 실패: 2)가 `NOT_READ`다(수집 역할 스택의 `kms:GetKeyPolicy` 확인), 3)이 허용으로 남는다(키 정책 판정이 반영되지 않음), 또는
  "권한 시뮬레이션을 마치지 못했습니다(코드)"가 보인다.
- [ ] 5) (기록) 같은 계정 관리자가 AWS CloudShell에서 시뮬레이터 응답을 직접 본다(읽기 전용):
  `aws kms get-key-policy --key-id <키 A ARN> --policy-name default --query Policy --output text > key-a.json`,
  `aws iam simulate-principal-policy --policy-source-arn <사용자 ARN> --action-names kms:Decrypt --resource-arns <키 A ARN> --resource-policy file://key-a.json`.
  `EvalDecision`과 `MatchedStatements[].SourcePolicyType`·`SourcePolicyId`(결과 맨 위와 `ResourceSpecificResults` 안)를 기록한다.
  사용자 ARN을 `Principal`로 `kms:Decrypt`를 허용하는 문장 하나만 담은 `user-grant.json`을 `--resource-policy`로 넣어 한 번 더
  실행하고 같은 값을 기록한다(키의 실제 정책은 바꾸지 않는다). 키 정책 문장이 결정에 들어간 행의 `SourcePolicyType`이
  `Resource Policy`인지 `resource`인지 적는다(API 참조의 유효값은 `resource`, 예시 응답은 `Resource Policy`).
- [ ] 6) (기록) `aws iam simulate-principal-policy --policy-source-arn <사용자 ARN> --action-names kms:Decrypt --resource-arns "arn:aws:kms:*:<계정>:key/*"`를
  실행해 이 ARN을 받는지(결과가 오는지, `InvalidInput` 오류인지) 적는다. 받으면 그런 문장도 지정 리소스로 시뮬레이션할 수 있다는
  근거다.
- [ ] 7) 정리: 인라인 정책·IAM 사용자·액세스 키(시험 위치의 파일 포함)를 지우고, 세 키는 삭제를 예약한다(대기 기간 최소 7일).
  `key-a.json`·`user-grant.json`을 지운다.

근거: docs/PERMISSION_ASSESSMENT.md, docs/PROVIDER_INVENTORY_IMPLEMENTATION.md, docs/PROVIDER_ACTIONS.md, cremore/onboarding/probe.py,
gcp/backend/cremore_gcp_provider/onboarding.py, azure/backend/cremore_azure_provider/entra/permissions.py,
aws/backend/cremore_aws_provider/investigation/potential_access.py, atlassian/backend/cremore_atlassian_provider/onboarding.py,
metadata/bitbucket.py, atlassian/README.md, azure/README.md, github/README.md, slack/README.md, okta/README.md, vault/README.md,
gitlab/README.md, aws/README.md, cremore/remediation/action_plans.py, cremore/config.py, web/console/views/integrations/guide.tsx,
web/console/views/credentials/permissions.tsx, CHANGELOG.md

## 기록

| 항목 | 결과(정상/문제) | 상세 코드 | 날짜 | 메모 |
| --- | --- | --- | --- | --- |
| 공통 확인 |  |  |  |  |
| AWS 권한 확인 |  |  |  |  |
| AWS 첫 수집 |  |  |  |  |
| AWS 금고 값 대조 차단 (2026-10-08) |  |  |  |  |
| GCP 권한 확인 |  |  |  |  |
| GCP 첫 수집 |  |  |  |  |
| Google Workspace 권한 확인 |  |  |  |  |
| Google Workspace 첫 수집 |  |  |  |  |
| Microsoft 권한 확인 |  |  |  |  |
| Microsoft 첫 수집 |  |  |  |  |
| Microsoft 워커 신원 (2026-10-08) |  |  |  |  |
| Azure DevOps 권한 확인 |  |  |  |  |
| Azure DevOps 첫 수집 |  |  |  |  |
| GitHub 권한 확인 |  |  |  |  |
| GitHub 첫 수집 |  |  |  |  |
| GitHub 사람 목록 App (2026-10-08) |  |  |  |  |
| GitHub SSO 승인 토큰 유형 (2026-10-08) |  |  |  |  |
| GitLab 권한 확인 |  |  |  |  |
| GitLab 첫 수집 |  |  |  |  |
| Confluence 권한 확인 |  |  |  |  |
| Confluence 첫 수집 |  |  |  |  |
| Bitbucket 권한 확인 |  |  |  |  |
| Bitbucket 첫 수집 |  |  |  |  |
| Atlassian 조직 권한 확인 |  |  |  |  |
| Atlassian 조직 첫 수집 |  |  |  |  |
| Notion 권한 확인 |  |  |  |  |
| Notion 첫 수집 |  |  |  |  |
| Slack 권한 확인 |  |  |  |  |
| Slack 첫 수집 |  |  |  |  |
| Vault·OpenBao 권한 확인 |  |  |  |  |
| Vault·OpenBao 첫 수집 |  |  |  |  |
| Okta 권한 확인 |  |  |  |  |
| Okta 첫 수집 |  |  |  |  |
| Keycloak 권한 확인 |  |  |  |  |
| Keycloak 첫 수집 |  |  |  |  |
| 퇴사자 점검 (2026-10-08) |  |  |  |  |
| 실효 권한: AWS |  |  |  |  |
| 실효 권한: AWS KMS 키 정책 (2026-10-08) |  |  |  |  |
| 실효 권한: GCP |  |  |  |  |
| 실효 권한: Azure |  |  |  |  |
| 확정 못한 항목 a (GCP 거부 정책 권한) |  |  |  |  |
| 확정 못한 항목 b (Azure `assignedTo`) |  |  |  |  |
| 확정 못한 항목 c (Azure 역할 명령) |  |  |  |  |
| 확정 못한 항목 d (AWS 버킷 정책 거부) |  |  |  |  |
| 확정 못한 항목 e (Bitbucket 목록) |  |  |  |  |
| 확정 못한 항목 f |  |  |  |  |
| 확정 못한 항목 g (AWS KMS 시뮬레이터) |  |  |  |  |
|  |  |  |  |  |
