# github 공급자 소유 영역

발급 목록의 `audit_events` 옵션은 기존 조직 감사 수집기를 활성화한다(기본 해제).
선택 시 실제 조직 audit endpoint 접근을 사전 점검하며 버전·요금제·권한 조건을 우회하지 않는다.
`audit_days`는 1–180일이며 공급자의 실제 보존 기간을 늘리지 않는다. Enterprise 감사 토큰/digest 계약은
유지하고 조직 감사가 별도 실행되면 Enterprise child에서 중복하지 않는다. 생성자를 소유자로 추정하지 않는다.
세부 지원·검증은 [2026-10-05 재검토](../docs/INVENTORY_METADATA_REVIEW_2026-10-05.md)를 따른다.

## Enterprise Export 수집과 상태 (2026-10-05)

고정 식별자가 없는 Export 행은 `inventory:export:` 관측으로 보존하되 공통 인벤토리의
고유 항목 집계에서 제외한다. App 발급 주체와 Federated JTI는 메타데이터 화면의 별도 유형으로
표시하고, 연결별 `github-export-rows` API에서 최근 스냅샷을 페이지로 읽는다. 다음 페이지는
같은 실행 ID를 고정하며 수집 결과·설정이 바뀌면 과거 근거임을 표시한다. 이전 관측과 감사
이력은 삭제하지 않는다. `record_page`의 식별자 접두어 필터는 저장소가 소유하고 공급자에
SQL을 복제하지 않는다. 감사 연결 화면은 각 원본 수집의 완료 시각·부분 수집 여부를 함께 보여 준다.

서명 URL 다운로드는 요청 URL을 INFO/DEBUG 로그로 출력하는 클라이언트를 거치지 않는다.
표준 라이브러리 HTTPS 연결로 검증한 IP에 접속하고 원래 호스트의 인증서·SNI를 검증한다.
각 리디렉션은 주소 검증을 다시 거치며 인증 헤더·쿠키·환경 프록시를 상속하지 않는다.
공급자 API 호출 경로는 기존 HTTP 클라이언트를 유지한다.

전체 목록은 `POST /enterprises/{enterprise}/credentials/exports`로 생성하고,
`GET .../exports/{export_id}`로 준비 상태를 확인한다. 302로 받은 서명 URL은 API 인증정보를
전달하지 않는 별도 HTTPS 연결에서 읽는다. CSV는 메모리에서 제한된 크기로 정규화하며
원본 CSV·서명 URL·공급자 토큰 해시를 파일, DB, 작업 상태에 저장하지 않는다.
수동 파일 업로드·다운로드는 온보딩에 없다. App 설치의 `Enterprise credentials: read`를
확인하고, Enterprise Cloud와 GHE.com(같은 Enterprise Cloud API 문서를 따른다) 연결에서만 새 전체 목록 연결을 허용한다.
GitHub의 출시 공지는 Enterprise Cloud만 적었으므로 GHE.com에서의 동작은 실환경 검증 항목이다.
Server의 다른 조직 API 지원을 근거로 Export 지원을 가정하지 않는다.

새 온보딩은 조직 발급 목록(`schedule_minutes`), Enterprise 전체 목록
(`enterprise_schedule_minutes`, 기본 1440분), 선택한 조직·Enterprise 감사
(`audit_schedule_minutes`, 기본 60분)를 별도 수집 연결로 만든다.
감사 전용 연결은 `github_inventory=false`이며 Export를 생성하지 않는다.
기존 혼합 연결은 자동으로 분리하지 않고 명시적으로 편집할 때 전환한다.

동일 호스트·Enterprise의 수동/예약 실행은 플랫폼의 `github_exports.py` 예약을 공유한다.
GitHub가 정확한 일일 숫자를 공표하지 않으므로 **CreMore 자체 보수적 제한**으로
24시간에 새 생성 한 번을 허용한다. 공급자의 더 긴 대기 응답을 존중하며, 확인된 Export가
있으면 수동 재수집은 같은 기준 시각의 결과를 읽는다. 요청 결과가 불명확하면 중복 생성하지 않는다.
상태 API의 `enterprise_export`는 단계·`as_of`·마지막 성공·다음 생성 가능 시각과 재사용 여부만
노출하며 export ID와 다운로드 URL은 노출하지 않는다. 화면도 이 기준 시각과 실제 연결별 주기를 표시한다.

`github-audit-links`는 같은 공급자 연결의 같은 호스트·tenant·명시적 범위에 속한
최신 완료/부분 완료 인벤토리와 감사 실행을 대조한다. `sources`에 각 실행과 revision 상태를
반환한다. 다른 소유자·중지한 기능·변경한 형제 연결은 합치지 않고, 인벤토리와 감사 중 어느 쪽이
갱신되어도 대조 캐시를 갱신한다. 이 연결은 정확한 식별자 근거이며 현재 유효성 검증이 아니다.

이전 버전의 `github_inventory` 기본값이 없던 조직 체크포인트는 다른 설정이 동일할 때만
이어 읽는다. 폐기된 JSON 목록 API 체크포인트는 `GITHUB_INVENTORY_API_CHANGED_RECOLLECT`로
부분 종료하고 기존 근거를 보존한다. 다음 수동/예약 수집은 새 Export에서 시작하며,
옛 목록 페이지와 새 스냅샷을 한 실행으로 섞거나 업그레이드 중 외부 생성 요청을 하지 않는다.
실계정 실행·GitHub 한도·Server 버전 호환성은 합성 검사와 별도로 검증해야 한다.

GitHub 콘텐츠·App 인증·host 경계·metadata 구현을 소유한다. Python 구현과 전용 테스트는 `backend/cremore_github_provider/`에 있다.
공통 플랫폼이 해당 라이브러리 함수를 직접 호출하며 제품의 Python wheel 하나에 함께 설치된다.

이 폴더에는 UI가 없다. 연결 화면은 `backend/`의 onboarding descriptor로 콘솔(`../web/console/`)이 그린다.

루트에서 `python -m pip install -e ".[dev,gcp]"`로 개발 설치 후
`python -m pytest github/backend -q`로 전용 합성 회귀를 실행한다.
실제 호출은 별도로 지정한 환경·범위에서만 수행한다.

Native metadata export의 `organizations[org].sources[kind]`는 같은 source의 모든
저장소 작업을 집계한다. 일부 작업이 실패하면 성공한 마지막 작업으로 완료를 덮어쓰지 않고,
페이지·건수를 합산하며 오류 코드는 `error` 문자열에 쉼표로 구분해 보존한다.
여러 endpoint를 합친 요약의 `endpoint`는 `null`이고, 각 작업의 endpoint·결과는
기존 `enterprise.tasks`에 남는다. 단일 작업의 출력 필드와 값은 유지한다.

[공통 AGENTS](../AGENTS.md), [팀 지침](../docs/AI_TEAM_CODING_GUIDE.md),
[실제 디렉터리·등록·빌드 경계](../docs/PROVIDER_DIRECTORY_REVIEW.md)를 먼저 읽는다.
UI 작업에는 [web 지침](../web/AGENTS.md)과 설치된 Next 문서도 적용한다.
공통 API·DB·권한·scope·작업 수명·SIEM 계약과 registry는 플랫폼 담당자와 나누어 작업한다.

## 콘텐츠 스캔

- 저장소 전체의 BASELINE 스캔은 고정한 커밋의 tarball 하나를 받아 트리의 blob SHA와 같은 파일만 쓴다(압축 256 MiB·
  전개 1 GiB·파일 200,000개 한도). 시간 한도 120초는 GitHub 응답을 기다린 시간만 세고, 받은 파일을 검사하는 시간은
  세지 않는다. tarball 전체는 30분까지다. Enterprise Server·GHE.com도 tarball 리다이렉트가 서버 자신의 API·웹 호스트에
  머물면 같은 방식으로 읽는다. 다른 호스트(서브도메인 격리의 `codeload.{호스트}` 등)로 가면 따라가지 않는다. 한도를 넘거나
  실패하면 남은 파일만 blob API로 읽는다.
- 그 밖의 스캔은 blob을 API로 읽는다. 탐지 캐시에 있는 blob SHA는 받지 않고 나머지는 8개까지 동시에 읽는다. 요청 예산·
  취소 확인은 스캔 소유 스레드가 처리하며, GitHub App 설치 토큰은 동시에 읽는 동안에도 한 번만 발급한다.
- REST 요청은 origin과 자격증명마다 초당 10개를 넘지 않게 보낸다(GitHub 보조 한도: REST 엔드포인트당 분당 약 900점, 동시
  요청 100개). 자격증명은 GitHub App이면 그 설치(앱 ID·설치 ID)로, 개인 액세스 토큰이면 토큰으로 구분하며 키에는
  다이제스트만 남는다. 그래서 한 App 설치의 여러 루트 작업·변경 감지가 새 설치 토큰을 받아도 같은 간격을 나눠 쓴다. worker의
  공유 pacing 저장소가 있으면 모든 프로세스가 같은 간격을 지키고, 없으면 프로세스 안에서 지킨다. 보조 한도(403·429와
  `Retry-After`, 또는 `X-RateLimit-Remaining: 0`과 `X-RateLimit-Reset`)를 받으면 그 자격증명의 모든 읽기와 프로세스가 같은
  대기(cooldown)를 지키며, 대기 합계가 120초 안이면 GET을 다시 보낸다(기다리는 동안에도 취소·요청 가드를 확인한다). 그보다
  길면 그 읽기는 실패로 남는다. 변경 감지는 worker 제어 루프에서 돌므로 cooldown을 기다리지 않는다: 대기 중이거나 자기
  요청이 한도를 받으면(이때도 스캔용 cooldown은 건다) 그 루트의 조회를 바로 `SOURCE_RATE_LIMITED`로, 502·503·504를 받으면
  `SOURCE_UNAVAILABLE`로 끝내고 커서를 그대로 두어 다음 조회에서 다시 묻는다. 스캔은 502·503·504를 10초 안에서 다시
  시도하고, 쓰기 요청은 다시 보내지 않는다.
- 변경 감지 커서는 `"<커밋 SHA> <ETag>"`다(ETag가 없거나 형식이 맞지 않으면 SHA만). 브랜치 head를
  `If-None-Match`로 묻고 304면 바뀌지 않은 것으로 끝낸다(GitHub는 304를 요청 한도에 세지 않는다). `HEAD` 범위는
  기본 브랜치 이름을 먼저 묻는다. 이전 형식 `"<커밋 SHA>"` 커서도 그대로 읽으며 다음 조회에서 새 형식으로 바뀐다.
  head가 움직였으면 compare API가 바뀐 파일을 정한다.

## 자격증명 9종의 수집 범위

GitHub 자격증명 9종 중 한 건씩 목록으로 보이는 것은 6종이다. App 설치와 Actions `GITHUB_TOKEN`은 설치·정책
단위로만 보이고, GitHub App refresh token은 조회할 수 없다. 어느 경우에도 토큰 원문과 개인키는 수집하지 않는다.

| 자격증명 | 수집하는 곳 | 보이지 않는 것 |
| --- | --- | --- |
| classic PAT | Enterprise 인벤토리(`classic_pat`), 조직 SSO 승인(`org_sso`) | 토큰 원문 |
| fine-grained PAT | Enterprise 인벤토리(`fine_grained_pat`), 조직 승인 목록과 접근 저장소(`org_fgpat`) | 승인 대기 요청(`org_pat_requests`)은 `request`로 남기며 발급 자격증명으로 세지 않는다 |
| OAuth App 사용자 토큰 | Enterprise 인벤토리(`oauth_app_user_token`), 조직 SSO 승인 | 토큰 원문 |
| GitHub App 사용자 토큰 | Enterprise 인벤토리(`github_app_user_token`), 조직 SSO 승인 | 토큰 원문. 수집용 App을 설치한다고 발급되지 않는다 |
| 사용자 SSH 키 | Enterprise 인벤토리(`ssh_key`, 공개키 지문), 조직 SSO 승인 | 개인키 |
| 배포 키 | Enterprise 인벤토리에는 없다. App 설치가 접근하는 저장소마다 `repo_deploy_keys`로 읽고 공개키의 SHA-256 지문만 남긴다 | 설치 범위 밖 저장소, 개인키 |
| GitHub App 설치 | Enterprise 인벤토리의 설치 행(`inventory:<id>`), Enterprise·조직의 설치 목록 | 요청마다 발급되는 [설치 토큰](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)(1시간 유효)의 목록 |
| Actions `GITHUB_TOKEN` | 조직·저장소의 Actions 권한 정책, 옵션을 켜면 실행·job 정보(`include_actions`, `actions_run_days`) | [job마다 만들어져 job이 끝나면 만료되는](https://docs.github.com/en/actions/concepts/security/github_token) 토큰의 목록과 값 |
| GitHub App refresh token | 수집하지 않는다 | 사용자 토큰(8시간)을 갱신하는 [6개월 유효 값](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens)이며 이를 나열하는 API가 없다 |

[Enterprise 인벤토리](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/token-inventory)의
federated credential처럼 9종 밖의 유형은 다른 유형으로 바꾸지 않고 행별 식별자로 보관한다. 요청마다 발급되는
설치 토큰, job별 `GITHUB_TOKEN`, refresh token은 발급 목록에 나오지 않으므로 발급 목록→금고 비교의 대상이 아니다.
목록에 없다는 것이 발급되지 않았다는 근거는 아니다.

## Actions 시크릿 메타데이터

기존 `github` schema 2 연결의 `inventory`에 `vault_metadata` capability를 추가하고 아래 source를
명시적으로 선택한다. 기존 연결의 빈 `sources` 기본 동작은 유지하며 시크릿 조회 권한을 자동으로 넓히지 않는다.

| source | 실제 읽기 범위 | GitHub App 권한 |
| --- | --- | --- |
| `org_actions_secrets` | 조직 시크릿 이름·시각·visibility; selected 시크릿의 허용 저장소 목록 | 조직 Secrets: read |
| `repo_actions_secrets` | App 설치가 접근 가능한 저장소의 시크릿 이름·시각 | 저장소 Secrets: read |
| `environment_actions_secrets` | App 설치가 접근 가능한 저장소의 environment 목록과 환경별 시크릿 이름·시각 | 저장소 Actions: read (environment 목록) + Environments: read (환경 시크릿) |

조직/저장소/environment의 같은 이름은 별도 `vault_item`으로 저장한다. 시크릿 원문이나 암호문을
반환하는 기능이 아니며, `updated_at`을 비밀값 회전 증거로 해석하지 않는다. selected repository 관계는
시크릿에 접근할 수 있는 저장소에 관한 공급자 선언이며 발급 자격증명 값이 해당 시크릿에 저장됐다는 증거가 아니다.

환경 이름은 공식 계약에 따라 단일 경로 요소로 URL 인코딩한다. 공급자 응답의 URL을 따라가지 않고
검증된 조직/저장소/시크릿 이름에서 GET 경로를 만든다. host·페이지 링크·저장된 task의 scope를 HTTP 이전에 검증한다.
App의 enterprise 설치 토큰과 organization 설치 토큰을 구분한다. Enterprise에서 발견한 조직은 저장된 조직 발견
레코드로 재개하며 다른 조직으로 바뀐 checkpoint를 받아들이지 않는다.

`total_count`와 누적 응답 수가 다르거나 수집 중 count가 바뀌면 부분 수집으로 남긴다. 403/404·페이지 한도·
레코드 한도는 빈 금고의 근거가 아니다. 페이지·요청·레코드/응답 크기·취소·리스/원자적 commit은 공통 계약을 사용한다.

## 수집 범위 옵션

schema 2 `github` 연결의 옵션이다. 공통 `MetadataOptions`에 있지만 다른 공급자에서는 기본값만 허용한다.

| 옵션 | 기본값 | 뜻과 제한 |
| --- | --- | --- |
| `enterprise_only` | `false` | Enterprise 모드에서 조직 발견과 조직 source를 건너뛰고 Enterprise 인벤토리(와 선택한 Enterprise 감사)만 읽는다. `sources`·`include_actions`·조직 감사와 함께 쓸 수 없다. |
| `audit_scope` | `both` | `both`: Enterprise 감사가 끝나면 조직 감사를 생략하고, 읽지 못하면 조직 감사로 대신한다(Enterprise 성공으로 표시하지 않음). `enterprise`: Enterprise 감사만 읽고 대신하지 않는다. `organization`: 조직 감사만 읽으며 Enterprise 감사·Git 감사를 요청하지 않는다. `include_audit_events`가 필요하고 조직 모드에서는 `enterprise`를 쓸 수 없다. |
| `actions_run_days` | 없음 | Actions run 조회 기간(1–365일). 비우면 이전처럼 감사 조회 기간을 따른다. `include_actions` 또는 `repo_actions_runs` source가 필요하다. |
| `run_time_limit_minutes` | 없음 | 한 실행의 벽시계 상한(1–300분; 저장소는 실행을 시작 후 6시간까지만 받는다). 실행 시작부터 요청 한도 대기까지 포함해 재며, 넘으면 다음 페이지를 읽지 않고 이미 읽은 레코드를 남긴 채 `PARTIAL`·`TIME_BUDGET_EXCEEDED`로 끝낸다. 읽지 못한 작업은 빈 결과가 아니다. |

## 사람 목록: GitHub 로그인과 IdP 사람 잇기 (`identity/`)

GitHub 토큰은 로그인으로만 소유자를 알려 준다. 그 로그인이 IdP의 누구인지는 GitHub의 외부 신원(GraphQL
`externalIdentities`)이 알려 준다. 한 조직에는 아래 둘 중 하나만 해당하므로, 사람 목록 연결은 그중 하나를 읽는다.

- **조직의 SAML SSO 신원**(기본): 조직의 SAML NameID·SCIM 사용자 이름·이메일과 그 신원을 쓰는 로그인을 읽는다.
  인증은 둘 중 하나다.
  - **GitHub App**(GitHub.com·Enterprise Cloud에서 권장, 사람이 떠나도 계속 동작하는 기계 자격증명): 조직에 설치한 App에
    조직 권한 "Members"(읽기, `members`, 조직 구성원·팀 읽기)를 준다. 발급 목록·금고·노출 검사에 쓰는 App과 같은 App이어도
    되며, 그때도 사람 목록 수집 토큰은 `members: read` 하나로 좁힌다. GHE.com·Enterprise Server에서는 마법사가 사람 목록에
    App을 내놓지 않는다(카탈로그의 `purpose_editions`). 수집할 때마다 그 조직의 설치
    (`GET /orgs/{조직}/installation`)를 App JWT로 다시 확인하고, 설치 토큰은 `members: read` 하나만 요청해 받는다
    (`GitHubAppTokenSource(permissions={"members": "read"}, organization=...)`). 토큰 발급 실패는
    `GITHUB_IDENTITY_APP_*`(예: Members 권한이 없어 거절되면 `GITHUB_IDENTITY_APP_REJECTED`)로 남는다.
  - **조직 소유자의 classic PAT**(`read:org`, `admin:org`도 됨, SAML SSO 승인): 그 사람이 소유자에서 빠지거나 퇴사하면
    수집이 멈춘다.
  - GraphQL 한도(기본 한도는 200 응답의 오류와 `x-ratelimit-remaining: 0`, 보조 한도는 200·403의 `retry-after`·
    `x-ratelimit-reset` 또는 그 메시지, [GraphQL 한도](https://docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api))는
    거절이 아니라 `GITHUB_IDENTITY_RATE_LIMITED`로 기다렸다가(`WAITING`, 최대 1시간) 같은 커서에서 이어 읽는다.
- **엔터프라이즈의 SSO 신원**(계획의 "조직 대신 엔터프라이즈의 SSO 신원 읽기", GitHub Enterprise Cloud·GHE.com·Enterprise
  Server에서 대상에 엔터프라이즈를 넣으면 나온다. GHE.com은 관리 사용자만 있어 기본으로 켜진다): 엔터프라이즈 관리 사용자(EMU)이거나
  엔터프라이즈에 SAML을 설정해 조직의 SAML을 대신하는 경우, 그리고 SAML을 인스턴스에 설정하는 Enterprise Server다(GitHub이 인스턴스
  SAML을 엔터프라이즈의 SAML 공급자로 답하고, Server 스키마에는 `oidcProvider`가 없어 SAML만 묻는다:
  [GHES 3.22 EnterpriseOwnerInfo](https://docs.github.com/en/enterprise-server@3.22/graphql/reference/objects#enterpriseownerinfo)).
  엔터프라이즈 소유자의 classic PAT(`read:enterprise` 또는 `admin:enterprise`. 새 마법사는 그 전에 조직 목록
  ([`GET /user/orgs`](https://docs.github.com/en/enterprise-server@3.22/rest/orgs/orgs#list-organizations-for-the-authenticated-user),
  classic PAT는 `read:org` 또는 `user`)을 읽으므로 `read:org`도 필요하다. 없으면 인증 단계의 `연결 확인`이 성공과 함께
  `GITHUB_TOKEN_READ_ORG_REQUIRED`를 경고하고(계정 연결만 저장할 수는 있다), `대상 불러오기`는 `GITHUB_ORGANIZATIONS_HTTP_403`이다)로
  엔터프라이즈의 SAML 또는 OIDC 공급자(`enterprise.ownerInfo`)가 아는 로그인(관리 사용자는 `핸들_단축코드`)과 IdP가
  프로비저닝한 SCIM 사용자 이름·이메일을 읽는다. 기본 SCIM 매핑에서는 Entra의 UPN, Okta의 앱 사용자 이름이 SCIM 사용자
  이름으로 온다. GitHub App으로는 읽을 수 없다(GitHub이 엔터프라이즈 소유자와 그 classic PAT에게만 보여 준다). App 연결에서
  이 선택을 켜면 권한 점검이 `read_enterprise`를 `MISSING`(`CLASSIC_TOKEN_REQUIRED`)으로 답해 활성화되지 않고, 수집 설정을
  직접 바꾸어 App에 엔터프라이즈 범위를 주면 `GITHUB_IDENTITY_ENTERPRISE_NEEDS_AN_OWNER_TOKEN`으로 거절된다. 관리 사용자만 있는
  GHE.com의 사람 목록은 App으로 연결할 수 없다.

매칭에 쓰는 IdP 쪽 값(NameID·SCIM 사용자 이름·이메일)은 keyed digest로만 남고, 퇴사자 점검이 IdP 사람의 로그인·이메일
digest와 정확히 맞을 때만 잇는다. 사람 정보 보관(`people_details`, 기본 켜짐)을 켜면 표시·연락용 이름과 이메일은 따로 사실로
남는다(매칭에는 쓰지 않는다). 관리 로그인을 IdP 사용자 이름에서 계산하지 않는다. GitHub의 정규화는 기호를 `-`로 바꾸고 도메인을
버리므로, 계산한 로그인이 다른 사람의 계정일 수 있다([사용자 이름 규칙](https://docs.github.com/en/enterprise-cloud@latest/admin/managing-iam/iam-configuration-reference/username-considerations-for-external-authentication)).
토큰 방식의 권한 점검은 토큰의 범위(`X-OAuth-Scopes`)와 GraphQL의 `viewerCanAdminister`(조직)·`ownerInfo`(엔터프라이즈, 소유자에게만 보이며
`viewerIsAdmin`과 달리 결제 관리자를 소유자로 치지 않는다)로 두 권한
(`admin_org`, `read_enterprise`)을 함께 답하고, 콘솔은 계획에서 고른 쪽만 센다. 소유자가 아니면 `NOT_AN_OWNER`, 토큰에게
대상이 보이지 않으면(구성원이 아니거나 SAML SSO 승인 전) `TARGET_NOT_VISIBLE`이다.
App 방식의 권한 점검은 `installation`(설치된 조직), `members`, `read_enterprise`를 답한다. 설치가 `members:read`를 가졌으면
수집과 같은 `members: read` 하나짜리 토큰으로 GraphQL에 조직 SAML 신원의 **개수만** 묻는다
(`organization.samlIdentityProvider.externalIdentities(first: 1) { totalCount }`, 신원 자체는 읽지 않는다). 개수가 오면
`members`는 `GRANTED`다. 조직에 자체 SAML SSO가 없으면(관리 사용자·엔터프라이즈 SAML) `MISSING`(`GITHUB_IDENTITY_SAML_NOT_ENABLED`),
GitHub이 `FORBIDDEN`으로 거절하면 `MISSING`(`ACCESS_DENIED`), HTTP 401·403이면 `MISSING`(`HTTP_401`·`HTTP_403`), 그 밖의 HTTP
응답이나 형식이 다른 응답은 `NOT_REPORTED`(`HTTP_<상태>`·`REQUEST_FAILED`), 요청을 보내지 못하면 `ERROR`(`REQUEST_FAILED`)다.
그 토큰을 받지 못하면 `members`는 토큰 발급 코드(`GITHUB_APP_*`)로 답한다. `members:read`가 없으면 GitHub에 묻지 않고 `MISSING`이다.
`read_enterprise`는 App에게 늘 `MISSING`(`CLASSIC_TOKEN_REQUIRED`)이며 엔터프라이즈 신원을 고른 계획에서만 센다.
실제 조직·엔터프라이즈로는 확인하지 않았다(합성 응답만).

권한 근거(2026-10-08 확인): GitHub GraphQL 스키마의 객체 설명. GitHub.com([fpt](https://docs.github.com/public/fpt/schema.docs.graphql))·
Enterprise Cloud([ghec](https://docs.github.com/public/ghec/schema.docs.graphql))·Enterprise Server 3.20
([ghes-3.20](https://docs.github.com/public/ghes-3.20/schema.docs-enterprise.graphql))이 같은 문구다.
- `ExternalIdentity`(노드 자체, 그 `samlIdentity`·`scimIdentity`·`user` 포함): 조직에 SAML을 설정했으면 조직 소유자, 조직
  소유자의 `read:org`·`admin:org` classic PAT, members 읽기 또는 쓰기 권한의 설치 토큰을 가진 GitHub App에게 보인다.
  엔터프라이즈에 SAML을 설정했으면 엔터프라이즈 소유자와 그 `read:enterprise`·`admin:enterprise` classic PAT에게만 보인다.
- `Organization.samlIdentityProvider`·`OrganizationIdentityProvider`: 위의 조직 쪽 세 주체.
- `Enterprise.ownerInfo`·`EnterpriseIdentityProvider`·`OIDCProvider`: 엔터프라이즈 소유자와 그 classic PAT만(App 없음).
- 설치 토큰의 권한 이름은 `members`(조직 팀·구성원, `read`·`write`)다([설치 토큰 만들기](https://docs.github.com/en/enterprise-cloud@latest/rest/apps/apps#create-an-installation-access-token-for-an-app)).

한계: Enterprise Server는 SAML을 인스턴스 전체에 설정하고 조직 SAML SSO(Enterprise Cloud 기능)가 없어, 이 조직 읽기는 두 방식
모두 `GITHUB_IDENTITY_SAML_NOT_ENABLED`로 끝난다고 본다(실제 Server로는 확인하지 않았다). Server의 인스턴스 SAML 신원은 위의
엔터프라이즈 SSO 신원으로 읽는다. 스키마는 공개 대상을
객체 단위로 적고 `nameId` 같은 필드별 제한은 적지 않는다. 값이 비어 오면 그 값의 연결 근거만 빠지고 다른 값으로 추정하지
않는다. App에게 공급자가 `null`로만 오면 점검은 자체 SAML이 없다고 답한다(GitHub 응답으로는 숨김과 구별되지 않는다).
실제 GitHub 조직에서 App으로 읽는 것은 실환경 검증 항목이다.

## App 만들기(매니페스트)

연결 마법사의 GitHub App 방식은 "GitHub에서 만들기"가 기본이다([GitHub App 매니페스트](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest)).
`app_manifest.py`가 비공개(`public: false`)·웹훅 없음·명시적으로 고른 설치 권한만 담은 매니페스트를 쓰고, 브라우저가
자기 주소(`url`·`redirect_url`·`setup_url`)를 채워 조직의 새 App 페이지(`/organizations/{조직}/settings/apps/new`, GHE.com·
Enterprise Server는 그 호스트)로 보낸다. 조직 소유자가 만들기를 누르면 GitHub가 한 시간짜리 코드와 state를 붙여 CreMore의
`/github/app`로 돌려보내고, API만 `POST /app-manifests/{code}/conversions`로 App ID와 개인 키를 받는다(인증 없음, 201). 키는
브라우저·클립보드를 거치지 않고 흐름의 세션에 봉인되며, 함께 오는 client secret·webhook secret은 보관하지 않는다. App 소유자가
연결할 조직이 아니면 거절한다(`GITHUB_APP_CREATED_ON_ANOTHER_ACCOUNT`).

이어서 설치 페이지(`/apps/{slug}/installations/new`, Enterprise Server는 `/github-apps/…`)에서 조직에 설치하면 GitHub가 다시
`/github/app`로 보낸다. 리디렉션의 `installation_id`는 위조될 수 있어 쓰지 않고, API가 App JWT로 `GET /app/installations`를 읽어
그 조직(`target_type=Organization`) 설치를 찾는다. 설치 전이면 `GITHUB_APP_NOT_INSTALLED`로 답하고 다시 확인할 수 있다. 찾으면
인증 우선 흐름(`start`의 `onboarding: true`)은 세 값을 같은 관리자·브라우저에 묶인 인증 초안에 봉인 저장하고
`onboarding_session_id`를 반환한다. 인증 후 기능·대상·범위를 선택하고 권한 점검을 통과해야 실제 연결을 확정한다.
설치 시의 조직은 App을 만들 위치이고, 초안의 수집 대상은 인증된 설치 조회로 다시 확인한다.
기존 API 흐름은 공급자 연결을 만들거나 자격증명만 바꾸고 `provider_connection_id`를 반환하는 계약을 유지한다.

새 흐름의 `installation_purposes`는 명시적인 설치 권한 선택이며, 실제 수집 기능 선택과 다르다.
`exposure`·`inventory`·`vault`·`identity`는 읽기 권한만 요청하며(`identity`는 `members: read` 하나), 빈 배열은 추가 수집
권한을 요청하지 않는 기본 인증 App이다. 이 App은 설치돼 있어도 읽기 권한이 없으므로, 권한 점검은 설치를 확인하고 고른 기능이
요구하는 읽기 권한을 하나씩 없음으로 보여 준다(빈 권한 요청은 설치의 모든 권한을 받으므로 토큰을 만들지 않는다).
`identity`는 App이 사람 목록을 읽는 판(GitHub.com·Enterprise Cloud)에서만 받는다.
조치 전용은 `['remediation']`만 허용하고 별도 이름 `CreMore Actions …`와
`organization_personal_access_tokens: write`를 요청한다. 읽기 목적과 혼합하면 거절한다.
조치 App은 세분화 PAT의 조직 접근 철회용이며 토큰 자체의 전역 폐기를 뜻하지 않는다. 기존 조치 계획 승인이 필요하다.
어느 설치 권한을 골라도 인증 초안의 `purposes`·`plans`는 비어 있으며, 수집·조치 인증정보 소유자를 자동으로 합치지 않는다.
초안 생성·원래 흐름의 봉인 삭제·완료 참조는 하나의 트랜잭션이며 재요청은 같은 ID를 반환한다.

흐름은 시작한 관리자와 브라우저 키 해시, GitHub가 돌려주는 state에 묶이고, 마지막 단계에서 한 시간 동안 설치 설정
(`github_app_manifest:<id>`)에 남는다. 코드는 한 번만 교환한다. 직접 등록한 App의 값을 넣는 방식도 그대로 있다.

## 엔터프라이즈의 다른 조직에 설치

엔터프라이즈를 적은 GitHub App 연결은 같은 App을 엔터프라이즈의 다른 조직에 설치하고 조직마다 연결을 만든다
(`enterprise_install.py`, `cremore/onboarding/github_enterprise.py`, 연동 메뉴의 "엔터프라이즈 조직에 설치"). 설치는 GitHub가 한다.
엔터프라이즈 계정에 설치된 App이 엔터프라이즈 권한 "Enterprise organization installations"(Read and write)를 가지면
`POST /enterprises/{엔터프라이즈}/apps/organizations/{조직}/installations`로 조직에 App을 설치한다
([조직 설치 API](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/organization-installations),
GitHub Enterprise Cloud 공개 프리뷰, Enterprise Server 3.19 문서에 있음). CreMore의 App은 스스로를 설치한다.

GitHub에서 한 번 하는 일(매니페스트로는 엔터프라이즈 App이나 엔터프라이즈 권한을 만들 수 없다):

1. App 소유자가 App 설정의 Advanced → Transfer ownership에서 엔터프라이즈로 옮긴다. 공개 범위가 internal이 되어 엔터프라이즈의
   모든 조직에 설치할 수 있고, 기존 조직 설치는 그대로다.
2. App의 Permissions → Enterprise permissions에서 "Enterprise organization installations"를 Read and write로 바꾼다.
3. 엔터프라이즈 소유자가 App을 엔터프라이즈 계정에 설치한다. 엔터프라이즈 설치는 조직·저장소 권한 없이 조직 설치만 관리한다.

그다음 관리자가 조직을 고르거나 자동 설치를 켠다. 원래 연결이 수집 중(활성, 계획 있음)이어야 한다
(`GITHUB_ENTERPRISE_SOURCE_NOT_ACTIVE`). worker 하나가 1분마다 처리한다.

- 먼저 원래 연결마다 GitHub에 묻지 않는 일을 한다. 점유가 10분을 넘긴 조직을 대기로 되돌리고, 권한 점검을 마친 조직 연결을
  원래 연결의 계획(주기 등, `token_digests` 제외)으로 활성화하며(허용되지 않은 권한이 있으면 `NEEDS_REVIEW`), 원래 연결의 키가
  바뀌었으면 사본에 넣는다. 원래 연결이 중지되면 중지된 동안의 첫 worker 주기에 그 대기와 자동 설치를 멈추고(`GITHUB_ENTERPRISE_STOPPED_WITH_SOURCE`, 메모에 버린 조직), 다시 켜도
  새로 요청한 조직만 설치한다.
- 그다음 GitHub 작업을 한다. 매분 다른 원래 연결부터 시작하고, 원래 연결 하나에 최대 15초, 한 번에 최대 20초를 쓴다(시간은 호출 사이에
  확인하고, 호출 하나는 10초 제한). 조직 목록을 읽은 원래 연결은 적어도 한 곳을 처리한다. 엔터프라이즈의 조직 목록은 10분 동안
  다시 쓰되, 저장한 목록에 없는 조직이나 App이 이미 설치된 조직을 판단하기 전에는 그 주기에 한 번 새로 읽는다.
- 엔터프라이즈가 설치할 수 있다고 알려 준 조직에만 App을 저장소 전체(`repository_selection: all`)로 설치한다. 목록에 없는 조직은
  이미 설치가 있어도 연결하지 않는다(`GITHUB_ORGANIZATION_NOT_IN_ENTERPRISE`). 목록이 1,000개 이상이면 잘린 목록으로 판단하지 않고
  멈춘다(`GITHUB_LIST_TRUNCATED`).
- 같은 App ID·키와 그 조직의 설치 ID로 공급자 연결을 만들고 권한 점검을 요청한다. 엔터프라이즈 전체 인벤토리는 원래 연결에만 두므로
  새 연결에는 `enterprise`와 감사 로그 토큰을 넣지 않는다. 발급 목록 수집은 활성화와 함께 시작하고, 저장소 내용 검사는 조직마다 검사
  대상을 정한 뒤 시작한다(승인 범위는 그대로).
- 자동 설치는 켠 뒤 처음 확인할 때(그 시간의 첫 확인) 조직 목록을 기준으로 삼고, 그 뒤에 새로 생긴 조직만 한 시간마다 대기에 넣는다.
  끄면 자동으로 대기에 넣고 아직 시작하지 않은 조직을 뺀다. 관리자가 대기를 취소한 조직(`POST …/cancel`)은 자동 설치가 다시 넣지
  않는다. 취소와 끄기는 중지된 연결에서도 된다.
- 조직 하나는 worker 하나만 설치한다. 대기 행을 잠금 안에서 `INSTALLING`으로 점유하고, 연결을 만들기 직전에 점유가 아직 자기 것인지
  확인한다. GitHub의 일시적인 통신 오류·429·5xx 또는 한 원래 연결의 목록이 제 몫의 시간 안에 끝나지 않으면(`GITHUB_TOO_SLOW`)
  그 원래 연결은 15분 쉬었다가 다시 시도한다. 일시 오류로 끝난 설치 점유는 기존 만료 처리로 다시 대기에 들어가고, 재시도는 설치
  목록 확인부터 시작해 응답을 받지 못한 성공한 설치를 다시 만들지 않는다. 설치 호출의 권한 부족·명시적인 거절은 조직별 실패로 남는다.
  조직 연결은 선택한 계획의 필수 권한이 모두 허용되면 활성화한다(고르지 않은 감사 로그 같은 선택 권한의 미확인은 막지 않는다).

App 키는 원래 연결의 봉인 자격증명에서만 꺼내며, `vault://` 참조 연결은 조직마다 설치 ID가 달라 쓸 수 없다
(`GITHUB_ENTERPRISE_SEALED_CREDENTIAL_REQUIRED`). 조직 연결마다 App 키의 봉인 사본을 가지며, 상태에 만든 연결과 넣은 사본을 기록한다.
원래 연결의 키를 바꾸면 worker가 같은 App ID로 만든 사본 가운데 그 뒤 관리자가 다른 자격증명으로 바꾸지 않은 것에 새 키를 넣는다
(`GITHUB_ENTERPRISE_KEY_PROPAGATED`). 원래 연결을 중지해도 조직 연결은 그대로이므로 각 연결에서 중지한다. 엔터프라이즈 설치 토큰은
호출하는 동안 메모리에만 두고 쓰고 나면 폐기한다(`DELETE /installation/token`). 상태 조회는 30초 동안 같은 답을 돌려준다.

상태는 설치 설정 `github_enterprise:<연결 ID>`에 둔다. 요청·취소·자동 설치 켬/끔·자동 대기·설치·설치 실패·연결·활성화·키 반영·원래
연결 중지로 인한 멈춤은 감사 기록(`GITHUB_ENTERPRISE_INSTALL_REQUESTED`, `…_INSTALL_CANCELLED`, `…_AUTO_INSTALL_ON/OFF`,
`…_AUTO_QUEUED`, `…_ORG_INSTALLED`, `…_ORG_INSTALL_FAILED`, `…_ORG_CONNECTED`, `…_ORG_ACTIVATED`, `…_KEY_PROPAGATED`,
`…_STOPPED_WITH_SOURCE`)에 남는다. worker가 한 일은 `system:github-enterprise`가 하고 메모에 요청한 사람을 적는다. 실패한 조직 결과는
30일 뒤, 또는 1,000개를 넘으면 오래된 것부터 지운다. 자동 설치가 켜져 있으면 지운 조직은 새 조직으로 보지 않는다. 실제 GitHub 엔터프라이즈에서는 검증하지 않았고 합성 GitHub로만 검사했다.

## App 신원(App ID·Client ID)

App JWT의 발급자(`iss`)는 숫자 App ID 또는 App의 Client ID(`Iv1.`+16진수, `Iv23`+영숫자) 중 하나다
(GitHub REST 문서 "Generating a JSON Web Token"). 등록 양식·`GITHUB_APP_ID` 필드는 둘 다 받는다.
설치 응답은 숫자 App ID만 담으므로 metadata 수집은 매 실행의 첫 작업으로 `GET /app`을 App JWT로 읽어
돌아온 `id` 또는 `client_id`가 설정값과 같은지 확인하고, 설치 대조에는 그 숫자 ID를 쓴다. 다르면
(`GITHUB_APP_IDENTITY_MISMATCH`) 설치 토큰을 하나도 요청하지 않고 수집을 멈춘다. 이 확인이 멈추거나
키로 서명할 수 없으면(`GITHUB_APP_PRIVATE_KEY_INVALID`·`GITHUB_APP_ID_INVALID`) 실행은 `FAILED`로 끝나고
작업도 실패로 표시된다. 다른 읽기에서 멈춘 경우(예: 조직 읽기의 401)는 읽은 결과를 남긴 `PARTIAL`이다.

확인한 App은 `app:<숫자 ID>` context 레코드(slug·이름·소유자·Client ID·App이 요청하는 권한)로 남고
native export의 `enterprise.app`에 들어간다. App이 **요청하는** 권한이며 각 설치가 수락한 권한과 다를 수 있다.
콘텐츠 연결의 점검도 App 방식이면 `GET /app`을 확인해 다른 App의 키는 거부한다. App 이름은 점검 결과에
기록하지 않는다: 점검 결과의 소유자·워크스페이스는 스캔 승인 revision(`cremore.scanning.scope.auth_revision`)에
들어가므로, 같은 자격증명의 승인된 스캔 범위가 다시 검토 대상이 되지 않게 한다. 등록은 저장 후 점검하는 기존
흐름을 유지하며, 점검 실패가 이미 저장된 자격증명을 되돌리거나 바꾸지는 않는다.

## 필요 권한과 조직별 설치 상태

`metadata/permissions.py`의 `SOURCE_PERMISSIONS`가 조직 설치에 필요한 App 권한을 읽기 항목(task kind)마다 적는다
(GitHub REST "Permissions required for GitHub Apps"). descriptor의 `source_permissions`로 Enterprise 연결 화면과
조직 목록에 표로 보인다. Enterprise 인벤토리·설치 가능 조직은 Enterprise 설치를, Enterprise 감사 로그는
classic PAT를 쓰므로 이 표에 없다.

Enterprise 설치로 읽는 항목과 그 App에 줄 Enterprise 권한은 다음과 같다(GitHub REST
[Organization installations](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/organization-installations)).
`enterprise_only`이면 인벤토리만 읽는다.

| Enterprise 읽기 | 경로 | Enterprise App 권한 |
| --- | --- | --- |
| 자격증명 인벤토리 | `POST /enterprises/{enterprise}/credentials/exports`, `GET .../exports/{export_id}` | Enterprise credentials: read |
| 설치 가능 조직 | `GET /enterprises/{enterprise}/apps/installable_organizations` | Enterprise organization installations: read |
| 조직의 접근 가능 저장소 | `GET .../apps/installable_organizations/{org}/accessible_repositories` | Enterprise organization installation repositories: read |
| 조직의 App 설치 | `GET .../apps/organizations/{org}/installations` | Enterprise organization installations: read |
| 조직 설치의 저장소 | `GET .../apps/organizations/{org}/installations/{installation_id}/repositories` | Enterprise organization installation repositories: read |

위 표의 두 조직 설치 권한(Enterprise organization installations·installation repositories)을 요청한 App은
그 App을 소유한 Enterprise만 설치할 수 있다
([GitHub App 권한 선택](https://docs.github.com/en/enterprise-cloud@latest/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)).
권한이 없으면 해당 읽기는 403 실패로 남는다. 조직 목록의 `health`는 조직 설치의 권한만 비교하므로 이 누락은 보이지 않는다.
권한 이름은 GitHub 문서 기준이며 실제 설치로는 확인하지 않았다.

수집 중 조직 토큰을 받기 전에 읽는 `GET /orgs/{org}/installation` 응답을 버리지 않고 `github.installation`
레코드(설치 ID·권한·저장소 선택·정지 시각)로 남긴다. 이 레코드는 App이 자기 설치를 조회한 근거인 context
`appInstallation:<설치 ID>`이며, 조직·Enterprise 설치 목록이 기록하는 설치 엔티티(`installation:<설치 ID>`)를 다른
모양으로 한 번 더 관측하지 않는다. 정지된 설치는 기록한 뒤 토큰을 요청하지 않는다
(`ORGANIZATION_INSTALLATION_SUSPENDED`). 조직 목록의 `health`는 이 레코드의 권한을 그 조직이 실제로 실행한 읽기
(아직 읽지 않은 조직은 설정상 하게 될 읽기: 저장소별 읽기·PAT 저장소 같은 후속 읽기 포함, Enterprise 감사 로그를 대신할 때만 도는 조직 감사 제외)와 비교한다: 정지가 먼저이고, 필요한 권한 이름이 없으면 `limited`,
모두 있으면 `permissions_present`다. 설치 조회가 403/404로 실패하면 `unknown`이며 미설치로 단정하지 않는다.
권한 이름 비교일 뿐 수집 가능성 검증이 아니다(`api_access_verified: false`).
조직 SSO 승인(`GET /orgs/{org}/credential-authorizations`)과 조직 감사 로그(`GET /orgs/{org}/audit-log`)는 GitHub의
[App 권한 표](https://docs.github.com/en/enterprise-cloud@latest/rest/authentication/permissions-required-for-github-apps)에서
Organization "Administration"(read)으로 설치 토큰도 읽는다. 다만 조직 SAML SSO는 Enterprise Cloud 기능이고 GitHub.com
Free·Team과 Enterprise Server의 REST 문서에는 `credential-authorizations`가 없다. 실제 설치에서는 확인하지 않았으며, 거절되면
그 읽기는 실패로 남고 빈 목록으로 보지 않는다. Enterprise Server에는 이 목록도 Enterprise 자격증명 Export도 없어서, 마법사는
Server 연결의 인벤토리 유형에 SSO 승인 4종(Classic PAT·OAuth 앱 토큰·GitHub App 사용자 토큰·SSH 키)을 내놓지 않고 메타데이터
화면은 이 4종의 제품에서 Server를 뺀다. 수집기도 Server 조직에서는 이 목록을 읽지 않는다(`options.sources`에 `org_sso`를 적으면
읽으며, 그 실패는 실패로 남는다). GitHub.com 연결은 Enterprise Cloud 조직일 수 있어 그대로 둔다.

## 세분화 PAT의 조직 접근 회수 (`remediation.py`)

조직이 승인한 세분화 PAT(`fgpat:{org}:{pat_id}`)는 승인된 조치 계획으로 **조직 접근을 회수**한다
(`POST /orgs/{org}/personal-access-tokens/{pat_id}`, `{"action": "revoke"}`,
[공급자 자격증명 조치](../docs/PROVIDER_ACTIONS.md)). 토큰 자체는 폐기되지 않아 다른 곳에서 계속 쓸 수 있고, 소유자는
조직에 접근을 다시 요청할 수 있다(조직 소유자가 새로 승인). 계획·화면·소유자 요청은 이를 "조직 접근 회수"로 적는다.
이 API는 GitHub App만 부를 수 있으므로, 조치는 조직 권한 "Personal access tokens: write"를 가진 App의 전용 연결
(`remediation` 용도)로만 한다. 점검은 설치 정보(`GET /app/installations/{id}`)의 권한과 설치된 조직을 읽고, 계획은 그 조직에
묶인다. 실행 때의 설치 토큰은 이 권한 하나만 요청한다(`GitHubAppTokenSource(permissions=...)`).

노출 검사·조직 발급 목록 수집·권한 점검의 설치 토큰은 읽기 전용이다(`read_only=True`): 설치가 가진 권한을 모두 `read`로
낮춰 요청하고(쓰기만 있는 `workflows`·`profile`, 읽지 않는 `organization_copilot_seat_management`는 뺀다), GitHub이 `read`
밖의 권한을 담아 준 토큰은 쓰지 않는다(`GITHUB_APP_TOKEN_NOT_READ_ONLY`). GitHub이 read 요청을 거절하면
`GITHUB_APP_READ_ONLY_REFUSED`다. 사람 목록 수집의 설치 토큰은 `members: read` 하나만 요청한다. 엔터프라이즈 설치의 토큰은
엔터프라이즈 권한을 read로 받는지 확인하지 못해 설치의 권한을 그대로 받는다. 같은 App을 조치 연동에도 쓰면 두 연동에 경고가 뜬다. 그 키로는 어느 설치의 쓰기 토큰이든 만들 수 있기
때문이다([공급자 자격증명 조치](../docs/PROVIDER_ACTIONS.md) 3절). 실행 전후로 조직의 승인 목록을
토큰 ID(`token_id[]`)로 걸러 읽으며, 걸러진 목록에 없을 때만 회수된 것으로 본다(걸러지지 않은 목록은 근거로 쓰지 않는다).
Classic PAT·SSO 승인, 원문 값이 필요한 `/credentials/revoke`는 자동 조치하지 않는다. 공식 근거(2026-09-30 확인):
[Personal access tokens](https://docs.github.com/en/rest/orgs/personal-access-tokens).

## 설치 확인(자격증명 수집 없음)

조직 목록의 `App 설치 목록 새로고침`과 조직별 `설치 재확인`은
`POST /api/v2/coverage/connections/{id}/github-installation-check`(`{}` 또는 `{"org": "<조직>"}`)로 요청한다.
일반 metadata 작업이지만 GitHub의 재수집(`plan_recollection`)으로 허용하는 유일한 형태이며 자격증명은 읽지 않는다.
같은 revision의 마지막 완료 수집이 관측한 조직만 대상이고, 모르는 조직이나 다른 재수집은 거부한다.
Enterprise 연결은 해당 Enterprise의 설치 토큰으로 현재 `installable_organizations`를 먼저 읽는다.
저장된 조직 목록만으로 새 조회 범위를 승인하지 않으며, 현재 소속을 확인하지 못한 조직의 설치 조회는 거부하고
상태를 `unknown`으로 남긴다. 이 확인도 기존 요청·페이지·시간 한도와 worker checkpoint를 사용한다.
이전 버전에서 진행 중이던 설치 확인은 새 실행으로 다시 요청해야 하며, 일반 수집의 checkpoint는 유지된다.
조직 하나는 App JWT로 `GET /orgs/{org}/installation`을, 전체는 `GET /app/installations`를 읽어 알던 조직과
Enterprise의 설치만 기록한다. 다른 계정의 설치는 보고서의 받은 수(`received_records`)에만 들어가고 저장하지 않는다.
설치 확인 실행의 모든 보고서는 `collection_mode: installation_check`이다.

조직 목록은 마지막 수집 위에 그 뒤의 설치 확인을 오래된 순서로 덮어쓴다(설치 확인이 몇 번 이어져도 그 앞의 수집을
찾는다). 새 조회가 403/404로 실패하면 이전 관측 대신 `unknown`이 되며, 설치 목록을 끝까지 읽은(COMPLETE) 경우에도
그 확인이 대상으로 삼은 조직(보고서의 `organization`)만 목록에 없을 때 `not_installed`로 표시한다. 설치 확인 실행은
다음 재수집의 기준이 될 수 없다(`GITHUB_INSTALLATION_CHECK_NEEDS_A_COLLECTION_BASE`): 기준은 수집이어야 한다.

## 제품 밖에서 수집하기(CLI)

`python -m cremore_github_provider.metadata.cli`는 제품의 GitHub 어댑터를 운영자 PC에서 그대로 실행한다.
develop_github의 `collect.py`처럼 웹·DB 없이 돌지만 별도 출력 계약을 만들지 않는다:
워커가 저장했을 schema 2 레코드를 그대로 남긴다. 새 console script는 추가하지 않았다.

| 명령 | 하는 일 |
| --- | --- |
| `check` | spec(`MetadataConnectionSpec` JSON 또는 `config`가 저장한 파일)과 App ID/Client ID·PEM을 네트워크 없이 검사한다. `--online`이면 `GET /app` 한 번으로 App을 확인한다. |
| `collect --out DIR` | `DIR`에 `records.jsonl`·`checkpoint.json`(공급자 checkpoint와 그것이 덮는 레코드 수)·`run.json`을 쓴다. 같은 명령을 다시 실행하면 checkpoint에서 이어가고, checkpoint 뒤에 남은 레코드는 버리고 다시 읽어 중복되지 않는다. 요청 한도에서는 기다리거나 `--no-wait`이면 종료 코드 3으로 멈춘다. |
| `export --out DIR` | native view(조직별 레코드·Enterprise 인벤토리·감사 연결)를 출력한다. |
| `config` | `CREMORE_COLLECTOR_TOKEN`으로 연결의 spec(비밀 참조 없음)·revision·계약을 받아 저장한다. |
| `submit` | 끝난 `DIR`을 schema 2 수집기 API(`/api/v2/coverage/collector/{id}`)로 보낸다. 외부 제출은 아래 범위 제한을 적용하므로 일반 `collect` 결과 전체를 그대로 제출할 수 없다. 같은 디렉터리의 재시도는 같은 실행(request id)으로 처리된다. |

외부 수집기 제출에서는 각 entity·relation·event의 `identity`·`subject`·`target` 키 자체에 승인된 조직 또는
Enterprise 범위가 들어 있어야 한다. `inventory:…`·`installation:…`·`principal:…`·`app:…` 같은 전역 ID는
`scope`나 조회 경로를 덧붙여도 허용하지 않는다(`METADATA_OUTSIDE_APPROVED_SCOPE`). 한 엔드포인트라도
전역 ID인 관계도 거절한다. 엔티티가 없는 보고서는 승인 범위의 실제 API 경로가 필요하다.
일반 CLI `collect` 결과에는 전역 App 정보가 포함되므로 전체 실행의 `submit`은 현재 지원하지 않는다.
전체 수집은 대시보드에서 서버 worker로 실행한다. 로컬 `collect`·`export`와 worker의 정상 수집은 유지하며,
이 제한을 피하려고 ID를 바꾸거나 기존 entity key·지문 계약을 변경하지 않는다. 거절된 배치 전체는
저장·엔티티 요약 갱신 전에 검사하며, 실행 접수 행만 남을 수 있다.

비밀값은 `--private-key-file`·`--audit-token-file` 또는 환경변수(`GITHUB_APP_ID`·`GITHUB_APP_PRIVATE_KEY_BASE64`)로만 받고
실행 디렉터리에 쓰지 않는다. 페이지에 비밀값이 섞이면 쓰기 전에 멈춘다(`PROVIDER_AUTH_VALUE_IN_METADATA`).
공급자 digest(`include_provider_hashes`)는 제품의 지문 키가 필요하므로 거부한다. API 주소는 HTTPS(또는 localhost)만 받는다.

## Enterprise 공급자 해시 비교

API 버전은 `2026-03-10`이고, Enterprise Server 메타데이터 수집만 GHES 3.20 이하가 받는 `2022-11-28`을 보낸다(그 버전이 빼는
필드는 읽지 않는다). Enterprise 인벤토리는 Enterprise owner 또는 View enterprise credentials 권한과
연결 방식에 맞는 Enterprise credentials: read 권한을 요구한다. 이 인벤토리는 2026-09-21 Enterprise Cloud에서
[정식 출시](https://github.blog/changelog/2026-09-21-github-enterprise-adds-credential-inventory-exports/)되었고
GHES는 이후 버전에서 지원 예정이다. 설정 화면의 내보내기는 쓰지 않고 같은 데이터를 REST API로 받는다.

인벤토리 API 문서는 `hashed_token`을 nullable 문자열로만 표기하고 형식을 설명하지 않는다. 구현은
[감사 로그 문서](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/identifying-audit-log-events-performed-by-an-access-token)가
명시한 **표준 Base64로 인코딩한 SHA-256**과 같다고 보며, 실제 Enterprise 응답으로 확인하기 전까지는 추정이다.
원문 토큰도, 기존 CreMore credential HMAC도 아니다. Enterprise 모드의 `issuer_digest` capability와 `include_provider_hashes=true`를
명시적으로 활성화한 경우에만 비교 근거를 만든다.

`metadata/digest_evidence.py`의 계약:

```text
provider_digest = strict_base64_decode(hashed_token)  # 정확히 32 bytes, canonical standard Base64
private_digest = HMAC-SHA256(fingerprint_key, b"cremore/github-token-sha256/v1\x00" + provider_digest)
scheme = "github-token-sha256/hmac-sha256-v1"
```

수동적 탐지 측 비교는 이미 메모리에 있는 자격증명의 **정확한 원문 bytes**를 SHA-256 처리한 후 동일한
`comparison_fingerprint(provider_digest, key)`를 사용한다. 공백 제거·대소문자 변환을 추가하지 않는다.
원래 Base64 해시는 facts·checkpoint·native export에 저장하지 않는다. 설치별 keyed digest만 기존 비공개
`EntityObservation.value_match` 경계에 `PROVIDER_DIGEST`로 전달한다. key ID·탐지/정책 digest·읽은 시점과
인벤토리 엔티티 식별자(아래)를 reference로 함께 보존한다. 이 증거는 현재 인증·실효 권한 검증이 아니다.

인벤토리 엔티티 식별자: 문서상 `inventory_id`는 같은 자격증명이라도 응답마다 달라질 수 있고, `credential_id`는
`credential_type`과 함께일 때만 고유하다. 그래서 classic·fine-grained PAT, OAuth·GitHub App 사용자 토큰은
`inventory:<credential_type>:id:<credential_id>`, SSH 키는 `inventory:ssh_key:fingerprint:<지문>`(SHA256은 끝의 `=` 제거,
MD5는 소문자)으로 식별한다. 행별 식별자가 없는 App 설치·federated JTI·principal만 `inventory:<inventory_id>`를 쓰며,
이 값은 실행마다 달라질 수 있다. 이전 형식(`inventory:<inventory_id>`)으로 쌓인 엔티티는 과거 관측으로 남는다.

null/미제공 hash를 빈 hash로 대체하지 않는다. 잘못된 hash는 원문 없이 누락 사유를 남기고 부분 수집으로 표시한다.
Enterprise 응답의 truncated/incomplete 등 header도 최종 `PARTIAL`에 반영한다.

### Enterprise 감사 로그의 인증

Enterprise 감사 로그(`/enterprises/{enterprise}/audit-log`, Git 감사 포함)는
[문서](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/audit-log)상 classic 개인 액세스
토큰(`read:audit_log`, Enterprise 관리자)으로 인증한다. GitHub 담당자가 실제 Enterprise에서 호출했을 때도 App 설치
토큰은 403, classic PAT는 200이었다(develop_github의 수집 범위 문서, 2026-09-27). 한 Enterprise의 관측이지만
App 설치 토큰은 보내지 않는다. 연결의 선택
비밀 역할 `audit_token`에 classic PAT(`ghp_`)를 두면 그 토큰을 Enterprise 감사 작업에만 쓴다(Enterprise 모드,
`audit` capability, `audit_scope`가 `organization`이 아닐 때만 허용). GitHub 공급자 연결의 2단계에서 App과 함께
`audit_token`을 넣으면([공급자 연결](../docs/ONBOARDING.md)) 받는 즉시 별도 역할로 봉인하고, 4단계가 만드는 Enterprise
수집에 감사 이벤트를 켠다. 바꿀 때는 `PUT /api/v1/provider-connections/{id}/credential`이다. 값은 응답·로그·checkpoint에 남지 않는다.

토큰이 없으면 Enterprise 감사 작업은 요청 없이 `GITHUB_ENTERPRISE_AUDIT_TOKEN_REQUIRED`로 실패를 기록하고,
`audit_scope=both`이면 조직 감사가 대신 실행된다. 설정한 토큰을 Worker가 해석하지 못하면(예: 봉인 키 변경) 실행 전체가
아니라 Enterprise 감사 작업만 `GITHUB_ENTERPRISE_AUDIT_TOKEN_UNAVAILABLE`로 실패한다(descriptor의
`optional_secret_roles`). `installation_id`도 선택 역할이다: 관리정보 수집은 조직마다 App 설치를 조회하므로 이 값을 쓰지 않는다.
연결 폼은 두 역할에 "(선택)"을 표시한다. App ID·개인 키를 해석하지 못하면 이전처럼 실행이 `METADATA_SECRET_UNAVAILABLE`로 실패한다. classic PAT 형식이 아니면 `..._INVALID`로 보내지 않는다.
401·403은 `GITHUB_ENTERPRISE_AUDIT_TOKEN_REJECTED`로 그 작업만 실패시키고 App으로 읽는 나머지 수집은 계속된다.

감사 로그의 다음 페이지 링크는 [문서](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/using-the-audit-log-api-for-your-enterprise)대로
`after=<cursor>&before=`처럼 cursor 두 개를 함께 담으므로 감사 로그 경로에서만 그 쌍을 허용한다. 다른 목록의
다음 링크는 cursor 하나만 바뀌어야 한다.

### 감사 이벤트와 자격증명의 연결

native export(`/api/v2/coverage/runs/{id}/export?format=native`)의 `enterprise.audit_links`는 한 실행에서 읽은
GitHub 감사 항목을 그 항목이 가리키는 자격증명에 **정확한 식별자로만** 연결한다(develop_github CLI의 규칙).

| 감사 항목 | 식별자 | 관계 |
| --- | --- | --- |
| `personal_access_token.access_granted`·`access_revoked`·`request_created` | `user_programmatic_access_id` = fine-grained PAT id(인벤토리 `credential_id`, 조직 목록 `token_id`) | `target` |
| `org_credential_authorization.*` | 관리 토큰 해시(`managed_hashed_token`, 설치별 keyed, 공급자 해시 opt-in) = 인벤토리 `hashed_token` | `target` |
| `org_credential_authorization.*`, `oauth_credential_type=OauthAccess` | `token_id` = OAuth·GitHub App 사용자 토큰 `credential_id`(두 유형이 한 번호 공간을 공유) | `associated` |
| `org_credential_authorization.*`, `public_key.*` | SSH 지문(저장소가 있으면 저장소+지문 = Deploy key) | `target` |

한 자격증명을 여러 source(Enterprise 인벤토리, 조직 SSO·fine-grained PAT 목록)가 보고하면 유형+GitHub id 또는
지문으로 하나의 후보로 묶는다. 이름·소유자·제목·시각·일반 `token_id`로는 연결하지 않는다. 후보가 둘 이상이면
`ambiguous_reference`, 정확한 식별자가 없으면 `no_exact_reference`, 이번 실행에서 관측하지 않은 자격증명이면
`no_observed_credential`로 `unmatched`에 남긴다. 연결이 없다는 것은 이벤트가 없다는 뜻이 아니고, 이벤트가 없다는
것은 미사용의 근거가 아니다. 관리 토큰 해시는 SSO 승인 이벤트의 비공개 `value_match`에만 두며(플랫폼 규칙이 이
이벤트에만 허용) 응답·export에 나가지 않는다. 토큰 사용 요약(`token_activity`)은 기존처럼 export에서 제외하고
발견 토큰 상세에서만 보여준다. 레코드 자체의 `target`은 공급자가 적은 참조 그대로이며, 연결은 export 시점에 계산한다.
`user_programmatic_access_id`는 토큰 ID라 승인(grant) ID로 이름 붙은 fine-grained PAT 엔터티와 번호가 겹칠 수 있어 저장 기록의
`target`으로 쓰지 않고 위 export 조인에서만 쓴다.

조직 목록 화면의 `감사 기록과 자격증명 연결`은 `GET /api/v2/coverage/connections/{id}/github-audit-links`
(`relation=target|associated|unmatched`, `credential_type`, 페이지)를 읽는다. 마지막 수집 실행의 기록으로 같은 규칙을
다시 계산해 기록마다 연결된 자격증명과 근거(또는 미연결 사유)를 한 행씩 보여준다. 관계·유형 선택지는 불러온 결과에
있는 값만, 둘 이상일 때만 표시한다. 비공개 digest는 응답에 없다. 계산에는 조인에 필요한 필드만 남기고(기록 크기의
약 20%), 끝난 실행은 한 번 계산한 결과로 페이지·필터를 처리한다. 감사 기록이 5만 건을 넘는 실행은 이 보기 대신
실행 기록 페이지로 본다(`GITHUB_AUDIT_LINKS_LIMIT_USE_RECORD_PAGES`). 조인 입력과 펼친 행의 JSON 크기도 각각
8 MiB 이내여야 한다. 같은 자격증명의 개체 목록이 여러 행에 반복되는 크기도 포함하며, 초과하면 일부를 정상
결과처럼 반환하지 않고 같은 오류로 실행 기록 페이지를 안내한다.

조직 현황·감사 연결 요약의 본수집 탐색은 최근 실행 100개 이내로 제한된다. 이후 설치 점검을 현황에 적용할 때는
전체 점검을 합쳐 레코드 10,000개·JSON 8 MB까지 처리한다. 이력을 일부만 적용한 현황은 반환하지 않으며,
초과 시 `GITHUB_INSTALLATION_HISTORY_LIMIT_USE_RUN_PAGES`(409)를 반환한다. 전체 이력은 기존 연결의 `/runs`와
실행별 레코드 페이지에서 계속 읽을 수 있다. 새 전체 수집을 실행하면 새로운 기준 현황을 만든다.

연결 확인의 계정·scope와 공급자 secret-scanning 알림의 표시 필드는 필드 이름뿐 아니라 값도 검사한다.
인증에 쓴 토큰·알림의 원문 값·알려진 비밀 패턴 및 제한된 디코딩 결과를 포함한 필드는 저장하지 않는다.
연결 확인의 신원 근거가 거절되면 `UNSAFE_RESPONSE_METADATA`로 미확정 처리한다.

### 감사 로그의 토큰 사용 요약

같은 opt-in에 `audit` capability와 `include_audit_events=true`를 함께 켜면, 감사 로그 페이지에서
`hashed_token`이 있는 항목(토큰으로 수행된 웹·API 이벤트)을 위 계약으로 keyed digest로 바꾼 뒤 원래 hash는 버린다.
페이지마다 토큰별로 `event_type="token_activity"` 요약 이벤트 하나를 만들며 facts에는 항목 수·처음/마지막 시각·
동작·저장소·수행 계정·`programmatic_access_type`·GitHub 항목 ID(`_document_id`)만 남긴다. keyed digest는
`ProviderEvent.value_match`(`PROVIDER_DIGEST`, reference=요약 event ID)에만 두고 공개 응답·native export에서 제외한다.
native 감사 목록은 GitHub 원래 항목만 유지한다.

발견된 GitHub 토큰의 `/api/v2/coverage/findings/{id}`는 노출의 비공개 `github_token_digest`와 key ID·탐지/정책
digest가 모두 호환되는 요약만 합쳐 `token_activity`(항목 수, 처음/마지막 시각, 동작·저장소·수행 계정)를 돌려준다.
수집 창이 겹쳐 같은 항목을 다시 읽어도 항목 ID로 한 번만 센다. 이는 공급자가 기록한 사용 이력이며 현재 유효성·
권한 검증이 아니다.

Git clone·fetch·push도 토큰으로 인증하면 같은 hash를 남긴다. 이 opt-in에서는 웹 감사 로그와 별도로
`include=git` 감사 로그를 읽는 `git_audit` 작업을 추가한다. GitHub가 Git 이벤트를 7일만 보관하므로
[보존 기간](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/about-the-audit-log-for-your-enterprise)에
맞춰 최근 7일(수집 창과의 교집합)만 읽고, Git 항목은 자격증명 이벤트가 아니므로 토큰 사용 요약에만 들어간다.
SSH 키·배포 키로 한 Git 작업처럼 토큰 hash가 없는 항목은 연결되지 않는다.
없으면 `NO_TOKEN_ACTIVITY_COLLECTED`를 붙이되 미사용 근거로 쓰지 않는다: 수집 기간·보존 기간 밖 항목과
형식이 잘못된 hash는 포함되지 않는다.

공식 근거(2026-09-25 확인):
[Enterprise token inventory](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/token-inventory),
[Actions secrets](https://docs.github.com/en/rest/actions/secrets),
[Environments](https://docs.github.com/en/rest/deployments/environments).

## 노출 파일의 담당·접근 정보

`context.py`의 `exposure_context`는 노출이 확인된 파일마다 소스 연결의 자격증명으로 다음을 읽는다(GET만 사용).
플랫폼의 `finding-context` 작업(`cremore/governance/ownership.py`)이 호출하며 결과 저장은 플랫폼이 맡는다.

- CODEOWNERS: 탐지한 커밋 기준으로 `.github/CODEOWNERS`, 루트 `CODEOWNERS`, `docs/CODEOWNERS` 중 처음 있는 파일
  (`GET /repos/{owner}/{repo}/contents/{path}`, raw). 파일에 일치한 담당자만 남기고 원문은 저장하지 않는다.
- 마지막 작성자: `GET /repos/{owner}/{repo}/commits?path=…&sha=…&per_page=1`의 작성자 이름·이메일·로그인·시각.
- 접근 가능 인원: `GET /repos/{owner}/{repo}/collaborators?affiliation=all`(100명씩 3쪽 단위로 이어 읽고 최대 100쪽/10,000명, 역할 포함).
  GitHub는 저장소에 write·maintain·admin 권한이 있는 계정(조직 저장소는 조직 구성원)에게만 이 목록을 준다.
  classic token은 `repo`·`read:org`가 필요하다. 거절되면 `FORBIDDEN` 이유로 남기고 빈 목록으로 바꾸지 않는다.

공식 근거(2026-09-28 확인): [List repository collaborators](https://docs.github.com/en/rest/collaborators/collaborators#list-repository-collaborators).

전용 테스트는 `python -m pytest github/backend/cremore_github_provider/metadata/tests -q`로 실행한다.
fake transport 또는 `httpx.MockTransport`와 합성 자료만 사용한다. 실제 GitHub 자격증명 인증이나 발견 토큰
전송/권한 탐색은 수행하지 않는다. 실환경 App 설치·권한·edition 차이는 별도 승인된 환경에서 검증해야 한다.


2026-10-06 후속: GitHub 접근 목록은 `finding-context` worker가 3페이지마다 정규화한 사람 목록과
다음 위치를 같은 리스 트랜잭션에 저장한 뒤 큐로 돌려준다. 새 worker도 이어 읽으며 연결·승인 범위를
매 요청과 저장 직전에 확인한다. 총 700요청·1시간 상한, 후속 실패의 부분 근거를 유지한다.
고정 ID 없는 Export 행은 고유 인벤토리 집계에서 제외하지만, 호환되는 정확한 비공개 지문으로
기존 노출에 연결할 수 있다. 이 연결은 인증 성공이 아니며 새 자격증명 행을 만들지 않는다.
금고 값과의 정확한 지문 일치도 기존 coverage API의 `ISSUANCE` 관측 근거로 유지한다.
이 행은 `issued.snapshot_observation=true`이며 고유 발급 수·발급 전용 수·금고 보관율의
분모에서 제외한다. 지문 계약이 다르면 연결하지 않고, 과거 일치를 현재 보관이나 부재로 바꾸지 않는다.
