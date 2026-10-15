# 다른 공급자 자격증명의 승인형 조치 (P1)

AWS 액세스 키와 같은 조치 계획 계약으로 다른 공급자가 발급한 자격증명을 비활성화하거나 폐기한다
(`cremore/remediation/provider_actions.py`). 대상은 CreMore가 이미 **발급 목록으로 수집한 자격증명**이고,
공급자 자신의 목록이 주는 ID로만 지정한다. 원문 값은 받지도 쓰지도 않는다.

| 공급자 | 대상 | 조치 | 되돌림 |
| --- | --- | --- | --- |
| Google Cloud | 사용자 관리 서비스 계정 키 | 비활성화(`keys:disable`), 비활성화된 키의 영구 삭제(`keys.delete`) | 비활성화는 되돌릴 수 있고 삭제는 되돌릴 수 없다 |
| GitLab | 그룹·프로젝트 액세스 토큰, 그룹·프로젝트 배포 토큰, (관리자 연결) 개인·서비스 계정 PAT | 폐기(`DELETE`) | 되돌릴 수 없다 |
| Notion | Enterprise 워크스페이스의 개인 액세스 토큰 | 폐기(`DELETE /admin/v1/spaces/{space}/personal_access_tokens/{id}`) | 되돌릴 수 없다 |
| GitHub | 조직이 승인한 세분화 PAT의 **조직 접근** | 조직 접근 회수(`POST /orgs/{org}/personal-access-tokens/{pat_id}`, `{"action":"revoke"}`) | 회수한 접근은 되살릴 수 없다. 토큰 자체는 폐기되지 않고, 소유자는 조직에 접근을 다시 요청할 수 있다(조직 소유자가 새로 승인) |
| Azure DevOps | 조직 사용자의 PAT | 폐기(`POST …/_apis/tokenadmin/revocations`) | 되돌릴 수 없다 |

Google이 관리하는 키, 원문 값이 있어야 하는 API(GitHub `/credentials/revoke`, GitLab `/admin/token`), 앱 단위 해제(Slack),
Entra 인증서, Notion MCP 연결, GitHub Classic PAT·SSO 승인은 자동 조치하지 않는다. 소유자가 직접 폐기하고 다음 수집이 그 상태를
확인한다. 새 값을 돌려주는 교체·재발급 API는 부르지 않는다.

## 1. 조치용 연동 만들기

연동 서비스 > 서비스 > **새 연동 추가** > **승인된 조치 실행**. 이 기능은 **다른 기능과 따로 연동**한다
(수집·검사에 쓰지 않는 전용 자격증명, `REMEDIATION_NEEDS_ITS_OWN_CONNECTION`). 4단계는 아무 수집도 만들지 않는다.

- **Google Cloud** (프로젝트 하나): worker의 ADC 또는 Google 로그인. 권한 점검은 `projects.testIamPermissions`로
  `iam.serviceAccounts.get`, `iam.serviceAccountKeys.get`·`.disable`·`.delete`를 묻고(무엇도 바꾸지 않는다), Google이 알려 주면
  실행 계정(토큰 정보의 확인된 이메일, 토큰은 URL이 아닌 본문으로 보냄)을 보고한다. 역할은 이 네 권한만 담은 사용자 지정 역할로 준다
  (`roles/iam.serviceAccountKeyAdmin`은 키 생성까지 허용해 그 프로젝트의 어느 서비스 계정으로든 인증할 수 있다).
  ADC를 쓰면 worker의 신원이 쓰기 권한을 가지므로, 쓰기 권한은 조치할 프로젝트에만 준다. ADC 토큰은 보통 이메일을 알려 주지
  않아 계정에 묶이지 않는다(로그인 방식만 묶인다).
- **GitLab**: `api` 범위 토큰과 폐기하는 사람에게 GitLab이 요구하는 역할. 그룹은 Owner, 프로젝트는 Maintainer,
  인스턴스 전체(Self-Managed·Dedicated)는 관리자다. 점검은 토큰 자신(`/personal_access_tokens/self`)과 멤버 역할만 읽는다.
  Admin Mode를 켠 인스턴스의 관리자 토큰에는 `admin_mode` 범위도 필요하다.
  그룹 연결은 그 그룹 범위의 수집이 나열한 토큰(하위 그룹·프로젝트 포함)에 닿고, 다른 사용자의 PAT에는 닿지 않는다.
- **Notion** (워크스페이스 하나): Enterprise 조직 봇 토큰. 범위 `personal-access-token:read`(다시 읽기)와
  `personal-access-token:write-high-impact`(폐기)가 모두 필요하다. Notion의 범위는 서로를 포함하지 않는다. 점검은 목록 읽기만 하고,
  폐기 범위는 폐기해 봐야 알 수 있어 `NOT_REPORTED`(`CONFIRMED_WHEN_RUN`)로 둔다. 범위가 없으면 첫 실행이 `NOTION_PERMISSION_DENIED`로
  실패하고 아무것도 바뀌지 않는다.
- **GitHub** (조직 하나): 조직 권한 "Personal access tokens: write"를 가진 **GitHub App**. 이 API는 GitHub App만 부를 수 있다.
  점검은 설치 토큰을 받아 GitHub이 알려 주는 권한을 비교하고(무엇도 회수하지 않음), 설치된 조직을 실행 계정으로 보고한다.
  다른 계정에 설치된 App은 실행 계정을 보고하지 않아 계획을 만들 수 없다. 실행 때의 설치 토큰은 이 권한 하나만 요청한다.
- **Azure DevOps** (Services 조직 하나): 프로젝트 컬렉션 관리자의 PAT, 범위 `vso.tokenadministration`. 같은 범위가 목록과 폐기를
  모두 허용하므로, 점검은 조직 사용자 한 명의 토큰 목록을 읽어 확인한다. Azure DevOps Server는 이 API가 없다.

한 자격증명에 닿는 조치용 연동은 **하나**여야 한다(`REMEDIATION_NOT_SET_UP`, `REMEDIATION_CONNECTION_AMBIGUOUS`).
실행 계정을 알려 주는 로그인(GitLab 토큰, GCP Google 로그인, GitHub App)인데 점검이 계정을 확인하지 못했으면, 권한을 다시 확인할
때까지 계획을 만들 수 없다(`REMEDIATION_CHECK_REQUIRED`).

## 2. 흐름

1. Credential 상세 > 조치 > **자격증명 조치**에서 remediator가 계획을 요청한다(운영 검토, 폐기는 영구 폐기 확인).
   계획 해시에 공급자의 참조(GCP: 프로젝트·서비스 계정·키 ID, GitLab: 토큰 종류·ID·소유 그룹/프로젝트, Notion: 워크스페이스·
   토큰 ID·만든 사람, GitHub: 조직·승인 ID·토큰 ID, Azure DevOps: 조직·authorization ID·소유자 descriptor)와 조치용 연동,
   그 연동의 로그인 방식, 권한 점검이 보고한 실행 계정(GitLab 토큰의 사용자, GitHub App이 설치된 조직)이 묶인다. 계획 카드와 확인
   창이 모두 보여 준다. 폐기가 자격증명이 아니라 조직의 접근만 끝내면(GitHub) 계획이 그 사실(`target.revokes`:
   `ORGANIZATION_ACCESS`)을 묶고, 화면·소유자 승인 요청·티켓이 "조직 접근 회수"로 적는다.
   끝나지 않은 계획은 공급자에서의 신원(GCP 서비스 계정·키 ID, GitLab 토큰 ID 공간)에 하나만 걸리므로, 같은 자격증명을 어느
   수집이 어디서 나열했든 결과가 불확실한 쓰기를 다른 계획으로 다시 하지 않는다.
2. 다른 관리자가 승인하고, 설치가 요구하면 소유자가 승인한다(링크·티켓·로컬 기록, [티켓 시스템](TICKET_SYSTEMS.md)).
   긴급 차단은 AWS 키 비활성화만 할 수 있다.
3. **실행 요청**은 API가 자격증명을 열지 않고 worker 작업(`provider-credential-action`)으로 넘긴다(`202`, `QUEUED`,
   감사 `ACTION_PLAN_QUEUED`). 작업과 상태 변경은 한 트랜잭션이다. 이 작업은 스캔 작업 취소로 거둘 수 없고, 거두려면 remediator가
   계획을 취소한다(감사 기록). 실행 스위치(`ACTION_EXECUTION_ENABLED`, 폐기는 `ACTION_DELETION_ENABLED`)는 worker도 다시 확인하므로
   API와 worker에 같은 값을 준다(Helm은 `config.actionExecutionEnabled`·`actionDeletionEnabled`를 두 컨테이너에 전달한다).
4. worker는 모든 실행 조건(승인, 소유자 승인, 설치 스위치, 운영 검토, 기한)을 다시 확인한 뒤에만 **계획이 묶은 조치용 연동**의
   자격증명을 연다. 연동이 멈췄거나, 자격증명을 바꾼 뒤 점검이 끝나지 않았으면(`REMEDIATION_CONNECTION_UNAVAILABLE`), 로그인 방식이나
   실행 계정이 승인 때와 다르면(`REMEDIATION_CONNECTION_CHANGED`) 열지 않는다. 그다음 현재 상태를 읽고(쓰지 않음), 계정에 묶인
   계획이면 자격증명이 지금도 그 계정으로 동작하는지 공급자에 묻고(GitLab `/personal_access_tokens/self`, Google 토큰 정보,
   GitHub `/app/installations/{id}`의 계정), 조건을 한 번 더 확인하고, 쓰고, 다시 읽는다. GCP는 서비스 계정이 계획의 프로젝트
   소속인지(`GCP_ACCOUNT_NOT_IN_PROJECT`)도 먼저 확인한다.
   - 이미 원하는 상태·만료·없음: 쓰지 않고 `FAILED`(`CREDENTIAL_ALREADY_DISABLED`·`_REVOKED`·`CREDENTIAL_EXPIRED`·`CREDENTIAL_ABSENT`)
   - GCP 키 영구 삭제는 비활성화된 키만(`CREDENTIAL_NOT_DISABLED`)
   - GCP는 계획이 가리킨 바로 그 키 이름(`projects/…/serviceAccounts/…/keys/…`)이 돌아올 때만 상태로 인정한다
   - GitLab의 404는 조치용 토큰이 그 토큰의 그룹·프로젝트를 볼 수 있을 때만 "없음"이다(`GITLAB_TARGET_NOT_VISIBLE`)
   - Notion은 토큰을 만든 사람의 토큰 목록(`creator_ids`)을, Azure DevOps는 소유자 descriptor 아래 목록을 끝까지 읽고서야
     "없음"으로 본다. GitHub은 조직의 승인 목록을 토큰 ID(`token_id[]`)로 걸러 읽고, 걸러지지 않은 목록은 없음의 근거로 쓰지
     않는다(`GITHUB_GRANT_UNREADABLE`). 토큰이 만료돼도 승인이 목록에 있으면 회수한다(토큰과 함께 접근이 돌아올 수 있음).
     목록의 주인(워크스페이스·조직·소유자)이 404면 없음이 아니다(`NOTION_WORKSPACE_NOT_VISIBLE`,
     `GITHUB_ORGANIZATION_NOT_VISIBLE`, `AZURE_DEVOPS_OWNER_NOT_VISIBLE`)
   - Azure DevOps는 폐기를 반영하는 데 최대 1시간이 걸린다. 쓰기 뒤 아직 유효로 읽히면 `OUTCOME_UNKNOWN`(`STATE_ACTIVE`)이고,
     나중에 상태 다시 확인으로 닫는다
   - 공급자가 분명히 거절(400·401·403·404)하거나 요청이 닿지 않음(로그인 실패, 연결 실패): `FAILED`, 그 밖의 실패나 다시 읽은
     상태가 다르면 `OUTCOME_UNKNOWN`
   - 쓰기와 확인 사이에 worker가 멈추면 `OUTCOME_UNKNOWN`(`EXECUTION_INTERRUPTED`), 실행 전에 멈추면 `FAILED`(`WORKER_ERROR`).
     작업이 계획을 정리하지 못하고 끝났으면(리스 한도 등) worker가 1분마다 같은 규칙으로 정리한다
5. `OUTCOME_UNKNOWN`은 **상태 다시 확인**(worker가 읽기만 함, 요청마다 `ACTION_PLAN_RECHECK_REQUESTED`, 한 번에 하나)으로만
   닫는다. 다시 실행하지 않는다.
   - 과거 AWS PREPARE 계획이 후속 키·pending 버전·쓰기 단계 없이 멈춘 경우, 조치 세션의 `ListAccessKeys`를 끝까지 읽어
     실행/쓰기 시작 시각 5분 전(AWS와 CreMore의 시계 차이) 이후에 생성된 다른 키가 없으면 `FAILED`(`result_kind=ROTATION_NOT_COMPLETED`)로 닫는다.
     이후 별도 승인을 받는 비활성화 계획을 만들 수 있다. 다른 새 키가 있으면 `ROTATION_UNRECORDED_KEY_EXISTS`로
     `OUTCOME_UNKNOWN`을 유지하며 그 키를 채택하거나 삭제하지 않는다. 시작 시각이 없거나 목록·생성 시각을 확인하지
     못한 경우도 미확정으로 남긴다. 재확인 결과는 기존 감사 경로로 추가하며 과거 기록을 수정하지 않는다.

모든 단계는 감사 기록(`ACTION_PLAN_*`)에 남고, 응답·로그·작업에는 공급자 응답 본문이나 토큰이 들어가지 않는다.
worker는 작업이 끝나면 연 자격증명을 지운다.

## 3. 한계

- 비활성화·폐기는 이미 발급된 단기 자격증명(GCP 액세스 토큰 등)을 끊지 않는다. 노출 원본 정리도 따로 한다.
- GitLab.com의 기업 사용자 PAT(그룹 자격증명 관리 API)는 아직 자동 조치하지 않는다(단건 조회가 없어 확인 방법을 정하지 못함).
- GitHub 조직 접근 회수는 그 조직에 대한 접근만 끝낸다. 토큰은 개인 저장소나 다른 조직에서 계속 쓸 수 있고, 소유자가 다시
  요청하면 조직 소유자가 새로 승인할 수 있다. 토큰 자체 폐기는 소유자가 한다.
- Azure DevOps 조치용 연동(PAT)은 실행 계정에 묶이지 않는다(로그인 방식만 묶인다). 소유자가 조직을 떠나 목록을 읽을 수 없으면
  확인하지 못한다(`AZURE_DEVOPS_OWNER_NOT_VISIBLE`). 소유자 descriptor는 이 변경 뒤 수집한 목록부터 저장되므로, 그 전에 수집한
  토큰은 다음 수집 뒤에 계획할 수 있다.
- `OUTCOME_UNKNOWN` 계획은 그 자격증명을 계속 잡고 있어 새 계획을 만들 수 없다. 폐기가 끝내 반영되지 않으면(예: Azure DevOps가
  계속 유효로 보여 줌) 공급자 화면에서 직접 폐기한 뒤 **상태 다시 확인**으로 닫는다.
- 조치용 자격증명은 전용으로 둔다. 같은 자격증명을 수집(노출 검사·발급 목록·금고·사람 목록) 연동에도 쓰면 매일 도는 수집이
  폐기 권한을 가진 자격증명을 연다. CreMore는 이를 막지 않고 알린다: 두 연동의 연동 현황 행(확인 필요)과 자격증명을 넣는 단계,
  이 조치 연동으로 만드는 계획 창에 경고가 뜬다(API `credential.shared_with`, `remediation_connection.shared_with`).
  - 비교는 worker의 권한 확인이 남긴 키 기반 지문(`checks.credential_marks`: 설치의 지문 키로 만든 HMAC, 화면·API에 나오지
    않는다)으로 한다. 토큰은 그 값, GitHub App은 App(그 키로 어느 설치의 토큰이든 만들 수 있다), GCP ADC는 worker 자신의 신원,
    Google 로그인은 Google이 알려 준 계정이다. 지금의 자격증명으로 확인한 결과만 비교하고(바꾼 뒤 다시 확인하기 전에는 비교하지
    않는다), 중지한 연동은 뺀다. 이번에 신원을 읽지 못한 점검은 같은 자격증명의 이전 지문을 유지하고, 유지할 것도 없으면 하루
    뒤 다시 점검한다. 이 기능 전에 점검한 연동은 worker가 1분에 몇 개씩 한 번 더 점검해 지문을 남긴다(`system:onboarding`,
    조치 용도를 가진 공급자의 연동만: 다른 공급자의 자격증명은 조치 연동과 겹칠 수 없다).
  - 워커 자신의 Google Cloud 신원(ADC)은 수집 쪽에서 바꿀 수 없으므로, 두 쪽 모두 조치 연동을 Google 로그인으로 따로 두라고
    안내하고 수집 쪽 버튼은 조치 연동을 연다.
  - GitHub의 노출 검사·조직 발급 목록 수집·권한 확인은 설치 토큰을 읽기 권한으로만 받는다. 설치가 가진 권한을 모두 read로 낮춰
    요청하고(쓰기만 있는 `workflows`·`profile`, CreMore가 읽지 않는 `organization_copilot_seat_management`는 뺀다), GitHub이
    read 밖의 권한을 담아 준 토큰은 쓰지 않는다. GitHub이 read 요청을 거절하면 `GITHUB_APP_READ_ONLY_REFUSED`로 멈춘다.
    조치 연동의 권한 확인도 쓰기 수준을 설치 정보에서 읽고 쓰기 토큰을 만들지 않는다. 같은 App을 조치에도 쓰면 키 자체는 쓰기
    토큰을 만들 수 있으므로 경고는 그대로 뜬다.
  - **엔터프라이즈 설치의 토큰은 예외**로 설치가 가진 권한을 그대로 받는다. 토큰 요청 문서가 조직·저장소 권한만 적고 있어,
    GitHub이 엔터프라이즈 권한을 read로 받는지 확인하지 못했다(실제 GitHub Enterprise Cloud에서 확인할 항목).
  - 엔터프라이즈 조직 설치 화면(API)은 조치 연동을 받지 않는다. 조치 연동의 App 키는 승인된 계획을 실행하는 worker만 연다.
  - Azure DevOps의 발급 목록 수집 PAT는 같은 범위(`vso.tokenadministration`)가 목록과 폐기를 함께 허용하므로 본래 폐기 권한을
    가진다.
- 실제 GCP·GitLab·Notion·GitHub·Azure DevOps 환경에서는 검증하지 않았다. 합성 응답으로만 검증했다
  (`cremore/remediation/provider_actions_test.py`). 같은 키를 두 번 비활성화하거나 이미 폐기된 토큰을 다시 폐기할 때 공급자가 주는
  응답 코드는 문서에 없어, 쓰기 전에 상태를 읽어 판단한다. Azure DevOps가 폐기한 토큰을 목록에 무효로 남기는지 빼는지, GitHub의
  `token_id[]` 필터 표기는 공식 명세로만 확인했다(둘 다 처리한다).

## 4. 공급자 모듈 계약

공급자 폴더의 `remediation.py`가 구현하고 `cremore/remediation/provider_actions.py`의 `MODULES`에 명시적으로 등록한다.
공급자 모듈은 `cremore.remediation`을 import하지 않는다(그 패키지는 AWS 모듈을 불러온다). 오류는 자체 예외에
고정 `code`와 `refused`(아무것도 바뀌지 않은 거절)를 담는다.

| 이름 | 뜻 |
| --- | --- |
| `ADAPTER_VERSION` | 계획에 기록하는 어댑터 버전 |
| `DISABLE_BEFORE_REVOKE` | 비활성화된 것만 폐기(GCP) |
| `SUBJECT_METHODS` | 점검이 실행 계정을 알려 주는 로그인 방식. 이런 연동은 점검이 계정을 확인한 뒤에만 쓴다 |
| `REVOKES` | 폐기가 자격증명이 아니라 다른 것을 끝낼 때 그 대상(`ORGANIZATION_ACCESS`: GitHub 조직 접근). 계획에 묶이고 화면이 그렇게 적는다 |
| `whoami(connection, secrets, client)` | 지금 실행 계정(점검이 `subject`로 보고한 형태). 계정에 묶인 계획은 이 값이 같을 때만 쓴다 |
| `reference(entity, record)` | 저장된 목록 항목과 현재 기록으로 만든 참조, `hint`(식별자만, 숨김·방향 제어 문자는 버림), `key`(공급자에서의 신원만: 어느 수집이 어디서 나열했는지는 넣지 않음, 계획 잠금의 기준), 조치할 수 없으면 None |
| `actions(reference)` | 지원 조치 |
| `covers(connection, reference)` | 조치용 연동이 닿는지 |
| `state(connection, secrets, reference, client)` | `ACTIVE`·`DISABLED`·`EXPIRED`·`REVOKED`·`ABSENT` |
| `apply(connection, secrets, reference, action, client)` | 쓰기 |

연동 마법사에는 공급자 descriptor의 `remediation` 용도(권한 점검, `children()`은 빈 목록)를 더한다. 점검 항목의 `subject`로
실행 계정을 보고하면 계획이 그 계정에 묶인다. 요청이 공급자에 닿지 않은 실패(연결 실패)는 `refused=True`로 알린다.
