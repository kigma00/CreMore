# Changelog

## Unreleased — selective and incremental asset scanning

- 구현된 SaaS·클라우드 기능 전체를 점검해 결함을 고쳤습니다(새 기능 없음, 합성 fake·격리 DB로만 검증, 실계정 미검증).
  - 발급 목록·대조: IAM 수집이 도는 중이거나 실패·부분 종료해도 발급된 AWS 키가 사라지지 않고 현재가 아닌 근거로 남습니다. 긴 IAM·
    CloudTrail 수집은 scanner 세션이 만료되기 전에 갱신합니다. 자격증명 목록은 값 일치만 `stored`로 읽고, 발급처의 최신 수집에 없는
    상태를 현재로 보이지 않으며, GitHub 승인·인가 시각을 생성 시각으로 쓰지 않습니다. 같은 감사 이벤트를 매 수집이 다시 저장해도
    공급자 이벤트 목록에는 한 번만 나옵니다. schema 1 수집 작업(AWS·Vault·Secrets Manager)은 수집 로그에 실제 상태(`PARTIAL`)와
    저장한 항목 수를 보이고 이름이 `AWS 발급·금고 수집`입니다. 결과 없이 끝난 권한 점검은 "점검 중"이 아니라 실패한 점검으로 보입니다.
  - AWS: 쓰기 전에 실패한 키 교체 계획은 닫을 수 없는 `OUTCOME_UNKNOWN`이 아니라 `FAILED`이고, AWSCURRENT 확인 전에 확인됐다고
    적지 않습니다. 설치가 끈 Organizations·SSO 발견은 수동 요청도 `409 AWS_DISCOVERY_DISABLED`입니다. 불완전한 빈 CloudTrail 조회는
    "사용 없음"으로 보이지 않고, 권한 외 오류는 거부 수로 세지 않습니다. S3 Inventory의 `IsDeleteMarker`, `aws-eusc` 파티션, JSON
    이스케이프된 STS 값, 권한 경계·SCP 거부 분류를 바로잡았습니다.
  - Vault/OpenBao: 토큰 accessor·lease 공백이 KV 실행을 부분으로 만들지 않고, 네임스페이스 접미사(`.<id>`)가 붙은 accessor도
    읽으며, accessor·lease ID는 관리자에게만 보입니다. 빈 LIST(404)는 키 0개이고 삭제·파기된 최신 KV2 버전은 읽기 실패가 아닙니다.
  - GitHub: ID로 된 다음 페이지 링크를 따라 목록·감사 로그를 끝까지 읽고, Enterprise Export의 진행·실패 상태와 Retry-After를 따르며,
    GHES에는 API 버전 `2022-11-28`을 보냅니다. 엔터프라이즈 다른 조직 설치는 선택한 계획의 필수 권한이 허용되면 활성화합니다.
    퇴사자 점검이 퇴사자의 SSO 인가 SSH 키(`public_key`)도 보고합니다.
  - GCP: 값 읽기가 목록의 이름·날짜·삭제 상태를 덮지 않고, 키에 대한 관리 감사 동작을 그 키의 사용으로 세지 않으며,
    `validBeforeTime`이 지난 서비스 계정 키는 `EXPIRED`입니다. Workspace 토큰 엔드포인트의 `access_denied`는 도메인 전체 위임 미허용
    (`GOOGLE_WORKSPACE_DELEGATION_NOT_ALLOWED`)으로 읽습니다.
  - Azure: 실패한 Key Vault 값 읽기가 목록 상태를 바꾸지 않고, 비활성 시크릿은 `SECRET_DISABLED`로 남기며, 부모 목록이 불완전한
    버전 목록은 부분 수집입니다. 유니코드 리소스 그룹 이름의 저장소 계정도 승인할 수 있습니다. Entra 자격증명의 `startDateTime`은
    생성 시각이 아니라 `not_before`입니다.
  - GitLab·Notion·Slack·웹사이트: GitLab `/users` keyset 페이지, 확장 인벤토리의 SSH·deploy 키, Self-Managed·Dedicated에서 GitLab.com
    전용 목록으로 생기던 부분 수집을 고쳤습니다. Notion 콘솔의 동작하지 않던 "하위 페이지 포함" 토글을 없앴고 빈 MCP 목록을 완전한
    목록으로 보지 않습니다. Slack 감사 페이지 한도·제거 판정·자리표시 행위자, 웹사이트 크기 한도를 바로잡았습니다.
  - Confluence Cloud 첨부는 토큰을 더 받지 않는 `downloadLink`(CHANGE-2735) 대신 문서화된 REST 다운로드(`/rest/api/content/{pageId}/
    child/attachment/{id}/download`, 302로 본문)로 읽습니다. https 리디렉션 최대 2번, 토큰은 사이트·게이트웨이 origin에만 보내고,
    사이트 밖 리디렉션은 이름이 공인 주소로만 풀릴 때 확인한 주소로 고정해 연결합니다(loopback·메타데이터·사설 주소는
    `CONFLUENCE_DOWNLOAD_ADDRESS_REFUSED`, 그 밖에 `CONFLUENCE_DOWNLOAD_REDIRECT_INVALID`·`CONFLUENCE_DOWNLOAD_REDIRECT_LIMIT`).
    실제 Cloud 사이트에서는 검증하지 않았습니다.
    Confluence Cloud 변경 감지는 공간 ID가 아니라 공간 키로 CQL을 찾고(전에는 늘 "변경 없음"), DC 첨부는 자기 버전으로 이름 붙습니다.
    Atlassian API Access의 마지막 페이지(`next` 없음), Bitbucket 저장소 `slug`·DC 토큰 생성 시각(epoch ms), `BLOCKED` API 토큰
    (되돌릴 수 있는 정책이라 끝난 상태가 아님), 역슬래시 경로 파일, bearer 토큰의 `/user` 조회, 재개한 범위의 부분 상태를 바로잡았습니다.
  - 사람 목록·탐지 알림: Keycloak 사용자 목록은 시작·끝 사용자 수가 읽은 수와 같을 때만 완전합니다(`KEYCLOAK_USER_COUNT_MISMATCH`,
    `KEYCLOAK_LISTING_SHIFTED`). 완전한 목록에서 빠진 사람은 `DEPARTED`로 보입니다. Okta `*.okta.mil`을 인식합니다. Slack 탐지
    알림은 다른 연결이 이미 가진 위치를 새 위치로 다시 알리지 않고, 시험 메시지는 버튼 없이 한 번 다시 보냅니다.
  - 보류했던 12건(합성 fake로만 검증, 실계정 미검증):
    - AWS: 마지막 사용 조회(GetAccessKeyLastUsed)의 거절·throttling·잘못된 응답이 "사용 없음"으로 보이거나 예전 마지막 사용을 새 관측
      시각으로 다시 내보이지 않습니다(사용 기록의 선택 `last_used`에 상태·관측 시각·안전한 코드). S3 객체·버킷 ARN은 승인된 scanner의
      partition(`aws-us-gov`·`aws-cn`·`aws-eusc`)을 쓰고, 승인 partition이 없으면 `AWS_PARTITION_UNAVAILABLE`로 막습니다. 예전 버전이
      `OUTCOME_UNKNOWN`으로 남긴 후속 키 없는 교체 준비 계획은 재확인이 `ListAccessKeys`를 끝까지 읽어, 실행 시작 5분 전(시계 차이) 이후 만든 다른 키가
      없으면 `FAILED`로 닫고(새 비활성화 계획 가능) 있으면 `ROTATION_UNRECORDED_KEY_EXISTS`로 둡니다.
    - GitHub: GraphQL 한도를 받은 사람 목록 읽기는 거절이 아니라 기다렸다가 이어 읽습니다(`GITHUB_IDENTITY_RATE_LIMITED`, `WAITING`).
      권한 없이 설치된 기본 App의 권한 점검은 "설치 거절" 대신 설치를 확인하고 고른 기능의 빠진 읽기 권한을 보여 줍니다(토큰을 만들지
      않음). GHE.com·Server의 조직 목록이 `FIELD_INVALID:host`로 실패하지 않고, PAT 인증이 엔터프라이즈를 이어 받아 엔터프라이즈 SSO
      신원(Enterprise Server의 인스턴스 SAML 포함)을 읽을 수 있습니다. classic PAT에 `read:org`가 없거나 세분화 PAT면 인증 단계가
      성공과 함께 경고하고, 그 경고는 마법사가 넘어간 다음 단계에서도 보입니다.
    - GCP: 삭제된 API 키(30일 안 복원 가능)의 값을 Google이 400·404로 거절하면 그 키의 사유로만 남고(권한 거절·잘못된 응답·범위 미확인은 그대로 부분 수집) 살아 있는 키의 값 대조를 부분 수집으로
      만들지 않습니다(주면 다른 키처럼 대조).
    - Azure: Entra 사람 목록은 토큰의 `tid`를 읽을 수 없으면 `/organization`으로 테넌트를 확인한 뒤에만 사용자를 읽습니다
      (`ENTRA_ID_TENANT_MISMATCH`·`ENTRA_ID_TENANT_UNVERIFIED`, 선택 권한 `Organization.Read.All`은 활성화를 막지 않음). ARM 금고 목록의
      다음 페이지(`/resources`)에 속성이 없는 금고는 금고 ID로 다시 읽어 버리지 않습니다(같은 권한·요청 예산, 실패는 사유 있는 부분 수집).
    - 문서: 퇴사자 점검 문서의 사람 목록 API(계정마다 한 행, 로그인 IdP만, `DEPARTED`)와 Keycloak 완전성 규칙을 실제 동작에 맞췄습니다.
- 노출 대응 요청에 조치 플레이북이 함께 갑니다. Slack DM·메일과 티켓 시스템(Jira 등) 본문, 그리고 링크 화면에 발급 서비스별 폐기·재발급
  단계와 콘솔 바로 가기, 아직 노출된 곳의 종류(저장소·문서·버킷·웹)별 정리 단계, 새 값의 금고 보관 단계가 들어갑니다(팀 채널 공지는
  링크만). 내용은 콘솔 자격증명 상세의 조치 가이드와 같은 데이터에서 나오며(`web/console/views/credentials/guides.json`, 서버 사본
  `cremore/governance/remediation_guides.json`, 같은지 시험으로 확인), 이름·발급 계정은 고정된 말로 바꾸고 마스킹 식별자만 씁니다.
  이미 끝난(비활성·폐기·만료) 자격증명에는 폐기 단계를 넣지 않습니다. `POST /api/v1/response-links/view`가 `playbook`(ko·en)을 돌려줍니다.
- 노출 대응 요청과 키 조치의 소유자 승인을 Jira 이슈로도 보낼 수 있습니다(설치형 플러그인 `packages/cremore-ticket-jira`, Jira Cloud와
  Data Center/Server, REST API v2). Python 이미지에 들어 있고 API·worker에 `TICKET_SYSTEM_PLUGINS=jira`를 두면 연동 서비스의 티켓 시스템
  설정에서 고를 수 있습니다(`docker-compose.yml`·격리 compose·Helm `config.ticketSystemPlugins`, 기본은 빈 값).
  - CreMore는 소유자를 이메일로 찾아(정확히 같은 활성 계정 하나, 배정 가능한지 먼저 확인) 그 사람에게 배정한 이슈를 만들고, 소유자가
    이슈를 설정한 승인 상태(예: `Done`)로 옮기면 승인, 거절 상태(예: `Won't Do`)로 옮기면 거절로 읽습니다. 응답한 계정은 가장 최근
    상태 변경 기록의 작성자이며 그 변경의 상태 id가 지금 상태와 같아야 합니다. 물은 계정이 아닌 사람이 옮기면 받아들이지 않습니다.
  - Jira에는 보고 폼이 없어, 노출 대응을 Jira에서 완료로 옮기면 `REPORT_REQUIRED`가 되고 담당자가 CreMore에서 조치 결과를 보고합니다.
  - Cloud는 사용자 계정의 클래식 API 토큰과 그 이메일을 씁니다(Atlassian 서비스 계정의 범위 지정 토큰은 지원하지 않음). Cloud는 기본적으로
    이메일을 숨기므로 소유자의 이메일 공개 범위와 사이트의 "사용자 이메일 표시"가 맞아야 하고, 아니면 `JIRA_USER_EMAIL_HIDDEN`으로
    거절합니다. 연결 확인은 서비스 계정의 프로젝트 권한(조회·이슈 만들기·배정·사용자 찾기)과 이슈 유형·상태를 확인합니다.
  - 실제 Jira 사이트에서는 검증하지 않았습니다(합성 Jira로만 시험).
- 연동 서비스를 `계정·발급 목록 연결`과 `콘텐츠 검사 위치 연결` 두 묶음으로 정리했습니다.
  - 계정 카드는 새 연결 제품 중 계정 기능(발급 목록·금고 대조·사람 목록·조치)이 있는 곳에만 보이고, 기능을 지원하는 제품을
    적습니다(Notion: `Enterprise 전용`; Confluence는 계정 카드 없음). `연동됨`은 그 묶음의 기능이 실제로 돌 때만 붙어, 콘텐츠 검사만
    연결한 Notion이 계정 카드를 `연동됨`으로 만들지 않습니다.
  - 콘텐츠 카드(AWS는 `Amazon S3`)는 AWS 말고는 계정 없이 바로 시작하고, 다시 쓸 계정이 하나면 바로 엽니다. 콘텐츠 흐름에는 기능
    선택이 없습니다(`인증 → 권한 확인 → 검사 범위 → 최종 확인`). 이미 연결한 계정에 더하면 기존 기능은 `유지`로 그대로 둡니다.
    여기서 새로 고른 대상(예: GitHub 조직)은 노출 검사에만 쓰여 계정의 발급 목록 등이 그 대상으로 넓어지지 않고, 연결을 다시 편집해도
    그대로입니다(`inspect`의 `target_purposes`, 서버가 같은 규칙을 검사). 연결을 편집할 때 지금 수집 중인 대상이 이번 목록에 없으면
    (다음 페이지, 중지된 설치) 지운 것으로 보지 않고 계속하지 않습니다(`ONBOARDING_EXISTING_TARGET_NOT_LISTED`, 초안의
    `previous_unlisted`). 그만 수집하려면 `유지할 기존 대상`에서 직접 뺍니다. Google 로그인·GitHub App으로 나갔다 와도 시작한 카드로
    돌아옵니다.
  - 연동 현황도 두 묶음으로 나눠 연결마다 기능 배지(`켜짐`·`꺼짐`·`권한 부족`·`설정 중`)를 보여 주고, AWS 발급 목록과 S3 검사는 두
    묶음에 각각 나옵니다. `지금 수집`·`검사 대상 설정`·`수집 범위·인증 설정`은 그 행의 묶음에만 적용됩니다.
  - 기능별 필요한 권한을 인증 전·기능 카드 아래·권한 확인 뒤에 같은 목록으로 보여 줍니다(`선택`·`대상에 따라`·`위와 같음` 표시,
    catalog 선언만 사용).
  - 권한이 일부 부족해도 통과한 기능(과 대상)은 켭니다. 인증 후 흐름의 `준비된 기능만 계속`·`통과한 대상만 계속`은 세션의
    목적·대상을 줄이고(`POST onboarding-sessions/{id}/inspect`가 목적의 부분집합을 받음, 보류 기능은 `held_purposes`, 감사
    `ONBOARDING_PURPOSES_NARROWED`), 기존 설정 마법사도 통과한 기능만 켭니다. 보류 기능은 검토·완료 화면에 남아 다시 확인 후 켭니다.
    서버의 선택·완료·활성화 권한 검사는 그대로입니다.
  - GitHub `새 App 자동 설정`은 실제로는 방식 선택이어서 눌러도 아무 일이 없었습니다. 이제 방식은 선택지로 보이고, 시작 버튼
    `GitHub에서 App 만들기·설치`가 `조직` 칸 바로 아래에서 비활성 이유를 함께 보여 줍니다. 탭 저장소가 막혔거나 응답 주소가 GitHub의
    새 App 화면이 아니면 떠나지 않고 오류를 보여 주며, 돌아오는 길에 로그인이 만료되면 `다시 로그인`을 안내합니다. 콘텐츠 카드에서
    만드는 App은 저장소 읽기(`Contents: read`)를 처음부터 요청합니다.
- 연동 서비스의 `Amazon S3` 카드가 AWS 로고 대신 S3 로고를 씁니다. 이미 연결한 계정을 카드에서 열면 그 카드의 기능만 보입니다.
  `Amazon S3`(콘텐츠 검사) 카드는 노출 검사와 버킷 검사 범위만, `Amazon Web Services`(계정) 카드는 발급 목록·금고 대조처럼 노출
  검사가 아닌 기능만 보여 주며, 화면에서 빠진 기능은 저장할 때 그대로 유지합니다. 꺼 둔 기능을 다시 켤 때 마지막 권한 점검이
  30분보다 오래됐거나 끈 뒤라 `현재 선택의 권한을 다시 확인해야 합니다`로 거절되면, 콘솔이 권한 점검을 요청해 끝나기를 기다린 뒤
  한 번 다시 켭니다.
- 노출 대응 요청을 Slack DM(또는 메일)의 CreMore 링크로 보냅니다(회사 로그인 설치). 담당자는 링크를 열어 회사 로그인을 하고
  CreMore에서 조치 결과를 보고하며, 그 보고가 응답(완료는 승인, 미완료·예외는 거절)을 함께 기록합니다. 링크는 7일 유효하고
  요청받은 사람(확인된 이메일, 사람 목록의 같은 활성 사용자)만 열 수 있으며 CreMore 역할은 필요 없습니다. 서버에는 토큰의 digest만
  남습니다. 보내지 못하면 `NOT_SENT`로 링크를 무효로 하고 다시 요청할 수 있습니다. 로컬 설치는 `기록`으로 회차를 열고 운영자가
  회신을 남깁니다. 미완료·예외 보고는 수행 조치 없이 낼 수 있습니다.
- 대응 요청을 담당 팀의 기존 Slack 채널에도 올릴 수 있습니다. 관리자가 승인한 채널만 쓰고(봇 권한 `channels:read`·`groups:read`로
  저장·발송·스레드 기록 때마다 확인), 기본은 비공개 채널만이며 공개 채널은 채널마다 명시적으로 허용해야 합니다. 다른 회사와 공유한
  채널과 보관된 채널은 거절합니다. 글은 담당자를 멘션하고, 그 스레드에 진행 상황(응답, 제거 확인, 재노출, 완료, 다시 요청, 링크 만료)이
  정해진 문장으로 달립니다. 스레드 댓글은 응답으로 읽지 않습니다. 대응 책임 규칙에 알림 채널을 정하면 요청할 때 미리 채워집니다.
- 팀 채널 스레드 진행 기록 작업이 멈추면 운영 상태(`GET /api/v1/operations/status`)와 콘솔 **운영 상태** 화면에 경고가 뜹니다.
  열린 스레드가 있는데 1시간 넘게 실행이 없으면 `RESPONSE_THREADS_STOPPED`(혼합 worker나 control 프로세스가 돌지 않음), 실행은
  되는데 올리지 못한 글이 1시간 넘게 남으면 `RESPONSE_THREADS_FAILING`(밀린 글 수, 가장 오래된 시각, 마지막 오류 코드)입니다. 이를 위해
  작업은 열린 스레드가 있으면 올릴 글이 없어도 1분마다 상태(`response:threads:state`의 `owed`·`owed_since`)를 남깁니다. 설치 단위
  경고라 경고 100개 상한에 잘리지 않고, SIEM·Slack으로는 보내지 않습니다.
- 내장 GLPI 티켓 시스템과 시험 구성(`deploy/glpi-test`)을 제거했습니다. 티켓 시스템은 설치형 플러그인으로만 붙습니다. DB 이관
  15가 GLPI로 저장한 티켓 시스템 설정과 봉인된 자격증명을 지우고, GLPI로 보낸 대기 중 소유자 승인은 만료되며, GLPI로 보낸 대응
  요청은 다시 요청할 수 있습니다. 과거 감사 기록은 그대로입니다.
- 업그레이드 직후 모든 범위를 한꺼번에 다시 읽지 않습니다. DB 이관(스키마 기록 버전 14)이 업그레이드 시각을 DB 시계로 한 번
  기록하고(`scan_schedule_origin`, 새 설치는 DB를 만들 때), 그 전에 승인된 범위는 그때 이미 접수 시각(슬롯 시작 + 범위의 분산)이
  지난 전체 검사 슬롯을 건너뜁니다. 분산 시간대 안에 업그레이드하면 접수 시각이 아직 오지 않은 범위는 그날 검사합니다. 문서 추출
  버전 4로 생기는 정책 재검사도 전체 검사 주기가 있는 그 범위들에는 업그레이드 뒤 첫 전체 검사가 끝날 때까지(성공·부분·실패·취소
  모두) 미뤄, 그 전체 검사가 새 정책으로 먼저 한 번에 읽습니다. 그 사이(전체 검사가 도는 동안 포함) 변경분 슬롯과 변경 이벤트
  실행(`policy_hold`)은 탐지 정책이 바뀌었다는 이유로 전체 읽기가 되지 않습니다(S3·Notion은 바뀐 것만 읽고, 캐시형 공급자의 변경분은
  그 전체 검사로 미룹니다). 새로 접수하는 실행은 업그레이드 뒤 48시간이 지나면 보류하지 않습니다. 이 보류로 생긴 부분
  실행은 운영 상태의 `JOB_PARTIAL`이나 연결 상태의 일부 실패로 세지 않습니다. 업그레이드 뒤 관리자가 규칙을 바꾸면 보류를 끝내
  바로 재검사합니다. 기록을 지우면 보류 없이 평소대로 검사하고, worker 시계보다 24시간 넘게 앞선 기록은 무시합니다. 역할을 나눈
  설치의 런타임은 버전 14까지 이관되지 않은 DB에서 시작하지 않습니다.
- 매일 전체 검사가 범위마다 고정된 시각에 나눠 시작합니다. 시작 시각부터 `min(4시간, 주기/2)` 안에서 범위 ID로 정하며(기본
  02:00~06:00 KST), 콘솔의 다음 예정 시각과 설정 안내도 이 시각을 보여 줍니다. 전체 검사 슬롯 시작과 함께(또는 그 뒤에) 시작해
  그 전체 검사 시각 뒤에 끝나는 변경분 슬롯은 따로 돌지 않고 그 전체 검사에 합쳐집니다.
- 업그레이드 보류로만 불완전한 실행은 실행 목록에 `policy_held_roots`·`policy_held_only`, 작업 목록에 `POLICY_HELD`로 나오고,
  콘솔의 "최근 7일 실패" 칸과 그 칸을 눌러 여는 목록(이제 그 칸이 센 실행만, 최근 7일만 보여 줌)에서 빠지며 실행 행과 상세에 이유가
  표시됩니다. 다시 읽지 못한 이전 실패 키가 남은 실행은 그대로 실패로 세고, 같은 작업의 이전 시도에서 실패 목록이 넘친 실행은
  `RETRY_STATE_OVERFLOW`로 멈춘 것으로 보고합니다. "진행 중" 칸도 누르면 다른 필터를 풀어 그 칸이 센 실행을 그대로 보여 줍니다.
- 예약 슬롯이 합쳐진 다른 실행(관리자의 첫 검사, 다른 슬롯의 예약 실행)이 취소되거나 실패하면 그 슬롯이 다시 열려 다음 폴링이
  여러 worker 사이에서도 한 번만 다시 접수합니다(슬롯 자신의 예약 실행을 취소하면 지금처럼 그 슬롯은 소비). 검사 요청이 이미
  대기·실행 중인 같은 범위 실행을 찾을 때 최근 작업 200개가 아니라 그 범위·버전의 실행을 직접 조회해, 변경 이벤트가 많이
  쌓여도 전체 검사를 두 번 넣지 않습니다.
- 변경 스캔에 길을 내준 S3 전체 검사가 이어서 끝까지 읽으면, 양보 전에 읽은 앞부분의 열린 노출 위치도 `HEAD`로 하나씩 확인해
  404인 것만 제거로 확정합니다(시도당 최대 1,000곳을 실행마다 다른 위치부터, 확인하는 동안은 양보하지 않음, 거절·요청 제한은
  아무것도 확정하지 않음, 새 권한 없음). S3 GET이 404로 답한 키도 실패로 세지 않고 사라진 것으로 확정하며, Inventory 실행도 그
  결과를 반영합니다. Notion 계획 단계의 머리글 조회는 5초마다 걸린 시간을 저장해 worker가 죽어도 실행 시간 예산을 거의 덜 세지
  않습니다.
- 최근 사용 출처의 건수와 `+N`이 저장된 최근 이벤트 100개가 아니라 사용 기록 조회가 읽은 모든 이벤트를 셉니다(요약
  `summary.sources`, 주소 모양인 값 최대 256곳). 콘솔도 5곳 뒤에 `+N곳`을 붙이고, 하한이면 "이상"을, 셀 수 있는 곳이 더 없으면
  "더 있을 수 있음"을 붙이며, `credential-records`에 `recent_sources_total`·`recent_sources_more`를 더했습니다. 이 요약은
  AGENTS.md의 플랫폼 공동 검토 대상인 `investigation/usage_pages.py`에 들어갑니다.
- 변경 조회가 1시간 넘게 실패하는 연결은 운영 상태(`GET /api/v1/operations/status`)와 콘솔 운영 상태 화면에 경고로 나옵니다
  (`CHANGE_FEED_RATE_LIMITED`·`CHANGE_FEED_UNAVAILABLE`·`CHANGE_FEED_FAILING`). 실패하는 대상의 변경 검사가 조회가 성공할 때까지
  멈춰 있고 예약 검사는 계속 돈다는 것을 알려 줍니다. SIEM·Slack으로는 보내지 않습니다.
- Helm의 worker 메모리 한도 기본값을 2Gi에서 3Gi로 올렸고(작업 프로세스 2개가 큰 문서를 함께 읽으면 약 1.9GiB), Compose의
  PostgreSQL은 `max_connections=200`으로 띄웁니다(작업 프로세스당 DB 연결 약 10개). 외부 DB는 200 이상으로 설정하세요.
- AWS 액세스 키의 사용 기록 조회(CloudTrail)가 이미 저장해 둔 출발 주소를 보여 줍니다. 조회가 키 소유 계정에서 실행된 경우에만
  최근 사용 출처(주소·종류·마지막 시각·건수, 최대 5곳)를 `credential-records`의 `recent_sources`로 내려 주고, 콘솔의 인벤토리 상세와
  노출 자격증명 패널의 "마지막 사용" 옆, 사용 기록 표의 이벤트별 "출처" 열에 표시합니다. AWS 서비스가 대신 호출한 주소
  (`*.amazonaws.com`)는 IP가 아니라 "AWS 서비스"로 적습니다. Slack 탐지 알림은 "자세히"에서만 최근 사용 출처 최대 3곳과 시각(한국어
  KST, 영어 UTC)을 한 줄로 적고 더 있으면 `+N`을 붙이며, "간단히"와 소유 계정 밖에서 조회한 기록에는 넣지 않습니다. 공급자를 새로
  호출하지 않고 이미 읽은 자격증명 행에서 만들며, 알림 채널을 볼 수 있는 사람이 이 주소를 보게 되므로 `docs/SLACK_ALERTS.md`에
  명시했습니다.
- Excel(BIFF8)의 메모·텍스트 상자 글과 수식 문자열 결과가 CONTINUE 레코드로 이어질 때 경계에서 끊기던 값을 이어 붙여 검사합니다
  (`EXTRACTOR_EPOCH` 4: 배포 뒤 한 번 이전에 검사한 루트를 다시 검사). Azure DevOps TFVC 항목의 캐시 이름은 목록의 MD5 대신
  변경집합과 경로로 정해, 같은 변경집합에서 MD5가 충돌하는 파일이 다른 파일의 결과로 건너뛰어지지 않습니다(TFVC 항목은 한 번
  다시 읽습니다). 변경 조회기가 공급자 502·503·504를 받으면 요청 제한(`SOURCE_RATE_LIMITED`)과 구별해 `SOURCE_UNAVAILABLE`로
  끝냅니다(동작은 같고 커서를 그대로 둡니다).
- 변경 스캔에 길을 내준 S3 전체 검사가 이어서 목록을 끝까지 읽으면 이어 읽은 지점 뒤에서 사라진 객체의 노출을 제거로 확정합니다.
  정책 재검사가 기다리는 동안 다른 전체 검사가 같은 루트를 현재 정책으로 이미 다시
  읽었고 실패한 키가 없으면 그 루트를 읽지 않고 끝내, 업그레이드 직후 정책 재검사와 매일 전체 검사가 같은 버킷을 두 번 읽지
  않습니다(열린 미검사 사유는 그대로 보고). 실패한 키 재시도는 작업마다 한 번만 하고(양보 뒤 이어지는 시도는 커서 앞의 실패
  키를 다시 읽지 않고 실패로 남김), 크기 한도를 넘는 객체는 본문을 읽기 전에 거절하며, 읽지 못한 객체도 커서를 옮깁니다.
  Notion 실행의 계획 단계 머리글 조회 시간은 실행 시간 예산에서 빼되 루트마다 최소 1초를 남기고, 예산을 다 쓴 루트들이 서로의
  남은 몫을 기다리기만 하던 경우에는 예산 중단(이어서 검사)으로 끝냅니다.
- 무인 검사 변경분을 다시 검토해 고쳤습니다. 찾은 자격증명을 검증할 검사 요청(관리자의 첫 검사, "지금 수집")에는 검증하지
  않는 예약 전체 검사로 답하지 않고 따로 실행하며, 중간부터 이어 읽는 실행(`RESUME`)이나 정책 재검사도 검사 요청에 답하지
  않습니다. 한 범위의 계획이 예상하지 못한 오류(깨진 catalog 항목)로 실패해도 오류 종류만 로그에 남기고 다른 범위의 예약
  검사·변경 조회를 계속합니다(그 범위는 5분 뒤 다시 계획하고 슬롯은 소비하지 않습니다). 변경 조회 회차의 20초가 지나면 진행 중인
  Notion 검색 조회도 다음 요청을 하지 않고 덜 읽은 root를 변경분으로 검사해, 긴 조회가 관리 루프를 붙잡아 생존 검사로
  재시작되지 않습니다. Slack 알림 회차는 종료 신호를 받는 즉시 새 메시지를 멈춥니다. 예약 검사를 끄고 변경 조회기만 켜 두면
  조회기가 놓친 변경을 잡는 검사가 없다는 점을 문서에 적었습니다.
- Slack 탐지 알림이 worker에서 실제로 나갑니다. worker가 자기 스레드에서 약 1초마다 대기열을 보내며(혼합 worker는 관리 루프 옆,
  역할을 나눈 배포는 control 프로세스), 회차가 예외로 끝나면 간격을 두 배씩(최대 60초) 늘립니다. 종료할 때는 새 메시지를 시작하지
  않고 보내던 한 통만 마쳐 ACK한 뒤(최대 15초), 가져온 나머지를 바로 돌려놓아 다음 프로세스가 임대를 기다리지 않고 보냅니다.
  역할을 나눈 설치는 `python -m cremore.db.privileges grant --schema cremore`를 다시 실행하고 control
  egress에 Slack을 열어야 합니다. Notion 전체·증분 검사는 계획 단계에서 승인 페이지의 머리글을 검색 한 번으로 받아 페이지당 요청
  1회로 읽고(실행 요청 예산에서 차감), 검사 밖의 Notion 호출(카탈로그·연결 점검·탐지 맥락·변경 피드)도 같은 DB 간격을 함께
  지킵니다. 같은 S3 버킷의 변경 스캔이 긴 전체 검사 뒤에서 기다리면 전체 검사가 읽은 만큼 저장하고 길을 내준 뒤 이어서 진행합니다
  (마지막으로 끝까지 읽은 검사가 3일 안인 루트만). 실행 커버리지는 부분 검사·미검사 사유 수와 계획 단계의 요청을 함께 셉니다.
- 로그인한 사람이 없어도 서버가 연동한 모든 승인 범위를 매일 한 번 전체 검사합니다. 설치 기본값은 하루 1번 02:00 KST이고,
  관리자가 환경 설정 > 스캔 시작 조건에서 하루 1·2·3·4·6·8·12·24번 또는 끄기와 시작 시각을 고르며, 검사 대상마다 따로 정하거나
  "설치 기본값"을 따르게 합니다. 예약 검사·변경 감지 스위치는 저장한 적이 없거나 이전 버전이 저장한 설정이면(이전 버전에서 끈
  경우도) 켜짐으로 읽으므로, 업그레이드하면 매일 02:00 KST 전체 검사가 시작됩니다. 업그레이드 때 이미 접수 시각이 지난 전체 검사
  슬롯은 그 전에 승인된 범위에서 한 번 건너뛰어 첫 예약 전체 검사는 그 뒤 처음 오는 범위별 시각에 돕니다(위 "업그레이드 직후" 항목). 업그레이드
  뒤 끄면 그 뒤의 실행만 막힙니다(이 버전에서 끈 값은 유지, 잠금이 항상 우선). 증분 슬롯은 항상 변경분(DELTA)만 읽고, 같은 대상의
  예약 실행이나 관리자가 넣은 첫 전체 검사가 아직 대기 중이면 새 슬롯은 그 실행에 합칩니다. 전체 검사 receipt는 슬롯이 시작한
  시각으로 정해 시작 시각 변경 뒤에도 실행을 건너뛰지 않습니다. 변경 피드에 Notion을 더하고 공급자별 확인
  간격(Bitbucket 15분, 나머지 5분)을 바꿀 수 있으며, 한 회차는 20초 안에서만 새 확인을 시작해 worker의 다른 확인이 멈추지
  않습니다. 새 연동은 변경 감지 스캔(피드·큐·웹훅)이 기본으로 켜지고 마법사 마지막 단계에서 끌 수 있습니다. 변경 이벤트
  실행은 출처(피드·큐·웹훅)를 기록해 Slack 알림에 적고, 예산으로 멈춘 전체 검사는 그 사이 변경 이벤트 실행이 있어도 이어서
  진행합니다. 운영 상태와 수집 실행의 다음 예정 시각도 설치 기본값과 고정 시각을 따릅니다.
- 저장소·페이지 소스의 재검사와 변경 감지가 빨라졌습니다. GitHub는 저장소 전체를 archive 한 번으로 읽을 때 시간 한도를
  네트워크 대기 시간만 120초로 세고(전체 30분 상한), Enterprise Server·GHE.com도 같은 호스트로 리디렉션되면 archive를 씁니다.
  파일 단위 읽기는 8개씩 겹쳐 읽되 토큰(GitHub App은 설치)마다 초당 10회를 프로세스 사이에서 함께 지키고, 보조 요청
  제한(403·429)은 읽기 쪽에서 최대 120초까지 함께 기다렸다가 다시 시도합니다. 변경 감지는 브랜치 head를 ETag 조건부 요청으로
  확인해 바뀌지 않았으면 본문 없는 304로 끝납니다(커서 `<sha> <ETag>`, 예전 sha 커서도 그대로). 모든 변경 피드는 요청 제한이나
  서버 오류(5xx)를 받으면 기다리지 않고 커서를 그대로 둔 채 다음 확인으로 넘기므로, worker의 예약·큐 확인이 멈추지 않습니다. Bitbucket 증분 검사는 저장한 commit 이후 diff에 나온 파일만 읽고 나머지는 이전 revision으로 캐시가
  답합니다(합성: 파일 400개 중 1개 변경 시 요청 411회 → 14회). 전체 검사는 최신 commit의 모든 파일을 다시 읽어 diff가 잘려도
  하루 안에 바로잡고, diff가 잘리거나 실패·이력 재작성·예산 중지처럼 불확실하면 모두 읽습니다. Confluence는 페이지 본문
  revision(`<ID>:<버전>`, 라이브 문서 제외)으로 바뀌지 않은 페이지를 캐시가 답하고 첨부를 8개씩 동시에 읽습니다. Azure DevOps
  TFVC는 항목 revision(변경집합과 정확한 경로의 해시)으로 캐시하고 변경집합 피드로 바뀐 경로만 검사합니다. GCS는
  목록을 한 번에 1,000개씩 받습니다(2,500개: 25회 → 3회). 공통으로 GET의 502·503·504 재시도(호출자가 선택), GCP·Azure·GitHub
  App·Atlassian 토큰 갱신을 여러 읽기 스레드에서 한 번만 하고, 바이트 예산은 실제로 읽은 객체만 셉니다.
- 새 탐지를 보안팀 Slack으로 바로 알립니다(콘솔 **환경 설정 > 스캔 시작 조건 > Slack 탐지 알림**, Admin). Incoming
  Webhook(받는 즉시 봉인, `hooks.slack.com`·`hooks.slack-gov.com` 주소만) 또는 연락 발송에 설정한 Slack 봇과 그 허용 채널
  중 하나로 보내고, 최소 심각도·자세히/간단히·한국어/영어·이벤트 종류를 고르며 시험 메시지와 전달 상태를 카드에서 봅니다.
  새 자격증명 노출·새 위치·제거 후 재노출과, 기준보다 낮아 걸러졌다가 기준 이상으로 오른 finding("심각도 상승")을
  알립니다. 메시지에는 심각도·유형·발급 공급자·검증 상태·연결·리소스·위치와 줄·처음 발견 시각·검사를 시작한 것·다른 열린
  위치 수·콘솔 상세 링크·ID가 들어가고 비밀값·가린 값·지문·공급자 응답은 들어가지 않습니다(자격증명처럼 보이는 이름은 가리고
  URL의 query는 뺌). 탐지와 같은 트랜잭션에 기록된 SIEM 대기열 이벤트를 목적지 `cremore.slack-alerts`로 읽고 Slack이 받았다고
  답한 뒤에만 처리 완료하므로 저장된 탐지가 빠지지 않습니다(최소 한 번 전달). 4건 이상이면 최대 15건씩 묶고, 설치 전체에서
  1.1초에 한 통과 Slack의 `Retry-After`를 DB로 함께 지키며, Slack 전체 장애(5xx·시간 초과·인증·채널)는 그 회차를 멈추고
  보류 없이 지수 간격으로 다시 보냅니다. 회차는 커서 이후 이벤트와 받지 않은 전달 행만 읽습니다(새 부분 인덱스
  `siem_deliveries_owed`, 스키마 기록 버전 13). 처음 켜기 전과 꺼 둔 동안의 기록은 보내지 않습니다. 콘솔 주소는 연락
  발송과 한 곳(`contact_delivery.console_url`)에 저장합니다. CreMore 자신의 목적지(`cremore.*`)는 SIEM 상태·백로그 경고·
  finding 전달 목적지 수에서 빠집니다. `finding.location_added`·`finding.reappeared` 이벤트의 심각도가 아직 없으면
  finding의 심각도를 씁니다. 연락 발송 봇은 Slack 5xx를 수신자 한 명의 거절이 아니라 Slack 장애로 처리합니다.
- 다시 검사할 때 바뀌지 않은 객체는 읽지 않습니다. 탐지가 없는 S3 객체도 GET에서 본 revision으로 캐시하므로(이전에는 캐시하지
  않아 매일 전체 검사가 버킷 전체를 다시 내려받음) 바뀐 것이 없는 전체 검사는 객체를 하나도 내려받지 않습니다. 캐시 행은
  위치로 저장하고 조회할 때 revision을 비교해, 객체가 바뀌어도 행을 지우고 다시 쓰지 않습니다. 검증을 켠 실행도 탐지가 없던
  캐시는 그대로 쓰고 탐지가 있던 객체만 다시 읽습니다. 같은 바이트면 결과가 같은 추출 한계(크기·개수 한도, 암호화, 지원하지 않는
  형식 등)는 더 이상 실패로 세지 않아 기준선과 마지막 전체 검사 시각을 막지 않고 매 실행마다 다시 읽히지도 않습니다. 이런 객체는
  `partially_inspected`와 루트의 `inspection_gaps`로 계속 보고하고 루트 커버리지는 완전으로 표시하지 않습니다. 파서가 죽은 객체는
  반복해서 재시도하지 않지만 캐시하지도 않아 다음 전체 검사가 다시 읽습니다. 요청 예산은 트랜잭션 한 번에 최대 64건씩 잡고,
  진행 확인은 초당 한 번만 하며, 탐지 없는 객체는 64개 또는 1초 단위로 묶어 한 트랜잭션에 기록합니다. S3·GitLab·Bitbucket·
  Azure Blob·Azure DevOps·GCS 수집은 다음 객체를 최대 16개까지 8개씩 동시에 미리 내려받습니다(합쳐서 256MiB 이하; 추출·탐지·DB
  기록은 목록 순서대로 한 스레드에서). 합성 측정(`scripts/benchmark_worker_scan.py`, 메모리 저장소, GET 지연 20ms, 객체 308개):
  바뀐 것 없는 재검사 0.04초·내려받기 0회, 읽기 직렬 2.05초 → 동시 0.27초(약 7.5배).
- 문서 추출은 POSIX에서 문서마다 새 Python을 띄우지 않고, 파서를 미리 올린 작은 서버가 문서마다 자식 프로세스를 fork해 같은
  메모리·시간 한도 안에서 읽습니다(합성 측정 문서당 약 5~9ms, 이전 약 340~430ms; Windows는 이전 방식). 문서마다 새 프로세스에서
  읽고, 서버는 다음 문서 전에 입력·응답 버퍼를 0으로 지웁니다. 실행 파일·SQLite·알 수 없는 바이너리는 8자 이상의 ASCII·UTF-16LE
  문자열을 뽑아 검사하고, 그 안에 압축·암호화 컨테이너 표식이 있으면 미완료로 표시합니다. UTF-8이 아닌 텍스트는 CP949로 읽고,
  ASCII가 하나라도 사라지면 latin-1 읽기도 함께 검사합니다. 옛 Excel·PowerPoint·HWP 3는 문자열로 읽되 매크로·내장 개체·압축
  본문·암호화가 있으면 미완료로, 그 밖의 OLE 복합 파일은 내장 콘텐츠 미검사로 표시합니다. OLE 파일은 파일 바이트가 아니라
  스트림마다 섹터 순서대로 이어 읽고, Excel 공유 문자열 표는 CONTINUE 레코드 경계에서 잘린 문자열을 이어 붙여 디코딩합니다(파일
  바이트를 그대로 읽으면 경계에 걸친 토큰이 둘로 끊겨 탐지되지 않음). 오디오·비디오·글꼴·PSD 등은 미디어로 건너뛰고, 앞에
  공백·BOM·NUL만 있는 PDF도 PDF로 읽습니다. 추출 방식이 바뀌어(`EXTRACTOR_EPOCH` 4) 배포 뒤 한 번은 이전에 검사한 모든 루트를
  다시 검사합니다.
- worker 컨테이너 하나가 작업 프로세스 여러 개를 함께 돌립니다(`WORKER_CONCURRENCY`; 0이면 PostgreSQL에서 쓸 수 있는 CPU 수와
  4 중 작은 값, SQLite는 1; Helm 기본 2). 관리 프로세스는 작업을 맡지 않고 스캔과 상관없이 5초마다 예약·변경 감지·고객 큐를,
  60초마다 유지보수를 돌립니다. 그래서 서로 다른 공급자·연결의 스캔이 동시에 돌고, 긴 스캔 중에도 예약과 이벤트 확인이 멈추지
  않습니다. 작업은 우선순위 다음으로 이미 돌고 있는 작업이 적은 실행부터 고르므로 오래된 큰 실행이 다른 연결을 막지 않습니다.
  같은 연결이라도 변경 이벤트로 시작한 실행은 별도 레인이라 진행 중인 전체·증분 스캔과 함께 돌 수 있습니다(같은 버킷·저장소·
  페이지는 여전히 한 번에 하나). 스키마 기록 버전 12가 인덱스를 바꾸며, 같은 연결·레인에 실행 중인 작업이 둘 이상이면(연결 없는
  옛 작업이 다른 작업과 함께 실행 중인 경우 포함) 바꾸지 않습니다. 작업 프로세스가 죽으면
  다시 띄우고 30분 동안 응답이 없으면 교체하며, 모든 작업 프로세스가 연달아 죽으면 상태 파일 갱신을 멈추고 종료해 재시작되게
  합니다. 작업 프로세스마다 머신 신원 토큰 디렉터리를 따로 씁니다. Helm worker 메모리 기본값은 요청 512Mi·한도 2Gi,
  `shareProcessNamespace`는 값으로 켜며 기본은 꺼짐입니다.
- Notion 수집은 검색으로 미리 받은 페이지 정보(제목·주소·수정 시각, `page_meta`)가 있으면 페이지마다 Markdown 요청 한 번만
  씁니다(없으면 머리글 한 번을 더). 본문을 읽은 뒤 머리글을 다시 확인하던 요청은 없앴습니다: 실행 시작 시각이 기준선이라 읽는
  중 바뀐 페이지는 다음 실행이 다시 읽습니다. 증분 실행은 5분 안에 받은 검색 정보로 수정 시각이 기준선보다 12분(검색 지연
  10분·분 단위 반올림·시계 오차 각 1분) 넘게 앞선 페이지를 요청 없이 건너뜁니다. 수집·카탈로그·자격증명 점검·연결 마법사의
  모든 Notion 호출이 연결별 초당 2.5회 제한과 429·529 `Retry-After` 재시도를 함께 씁니다. 변경 감지(`changes_since_batch`)는
  검색을 수정 시각 순으로 읽어 승인한 페이지 중 바뀐 것만 그 페이지 검사로 넣고(15분 겹침, 삭제는 추정하지 않음), 요청 예산이
  모자라면 다 읽지 못한 루트를 전체 증분 검사로 넘깁니다. 합성 측정: 500페이지 전체 검사 505회 요청(약 202초; 공유 5,000페이지
  중 500페이지 승인이면 775회), 5페이지 변경 검사 11회(약 4.4초).
- S3 내용을 읽을 때 worker 자신의 AWS 신원 재증명(새 SDK 세션, STS·IAM 호출 2회, 설정 기록)을 요청마다 하지 않고, 작업의
  계정마다 45초에 한 번과 역할 자격증명을 새로 받을 때만 합니다. 객체 하나에 AWS 호출이 세 번씩 나가던 비용이 없어집니다.
  신원이 바뀌면 45초 안에 읽기가 멈춥니다(전에는 다음 요청에서). 계정·승인·revision·로그인 확인은 그대로 요청마다, 스트림
  읽기 앞뒤와 결과 저장 트랜잭션 안에서 하므로 계정 비활성화·승인 철회는 다음 요청부터 거절됩니다. 여러 읽기 스레드가 신원
  재증명을 한 번만 하고, 재사용한 자격증명에는 열기 직후의 중복 확인을 하지 않습니다.
- 탐지엔진은 내용마다 키워드 964개를 하나씩 찾는 대신 RE2 검색 한 번으로 돌릴 탐지기를 고릅니다. 한 위치에서 시작하는 가장
  긴 키워드를 모든 시작 위치마다 찾고 그 안에 든 키워드를 함께 세므로, 겹치는 키워드도 빠뜨리지 않고 예전과 같은 탐지기를 같은
  순서로 고릅니다. 키워드가 아주 빽빽한 내용은 예전 방식으로 마무리합니다. 탐지 결과와 탐지 정책 digest는 그대로이며, 저장소
  파일 600개(약 7MB)에서 탐지기 고르기가 약 6.5배, 9MB 번들 JS에서 약 33배 빨라졌습니다(`scripts/bench_engine_routing.py`).
- 운영자가 적은 시크릿만 읽는 AWS·GCP Secret Manager 수집(`references`, AWS 값 읽기 역할 포함)은 끝까지 읽었다는 근거를
  "저장소 API가 목록 전체를 줌"이 아니라 "운영자가 전체라고 선언함"(`OPERATOR_DECLARED`)으로 기록합니다. 그 수집은 시크릿 목록을
  읽지 않으므로, "금고에 없음" 판정도 운영자가 적은 목록 기준이라고 표시합니다(다음 수집부터, Parameter Store는 그대로 API 목록).
- AWS 금고 계획은 Parameter Store 접두어에 `~`·`@`·`+`·`=`·`:`가 있거나 `.`·`..`만으로 된 구간이 있으면 계획 단계에서
  `AWS_PARAMETER_PATH_INVALID`로 거절합니다. 앞의 문자는 연동 입력란은 받아 주지만 Parameter Store 이름도 CloudFormation 스택도
  받지 않아, 전에는 수집이 그 리전 전체를 실패로 끝내거나 값 읽기 역할의 권한 확인이 넣을 수 없는 경로를 "스택 목록에 넣으라"고
  안내했습니다. `.`·`..` 구간은 CreMore 수집 범위 규칙이 받지 않아 전에는 활성화 때에야 실패했습니다. 이미 그런 접두어가 저장된
  계획은 다시 확인할 때 이 코드로 거절되므로, 그 접두어를 빼고 저장합니다.
- AWS 금고 대조는 별도 값 읽기 역할로 서버에서 값을 읽을 수 있습니다([설계안](docs/AWS_VAULT_VALUE_READER_DESIGN.md) B).
  두 CloudFormation 템플릿에서 `EnableVaultValueRead`를 켜면 같은 스택의 수집 역할만 ExternalId로 맡을 수 있는
  `CredentialVaultValueReaderRole`이 생깁니다. 이 역할은 스택에 적은 시크릿 ARN·Parameter Store 경로·KMS 키(Secrets Manager·
  Parameter Store를 거친 복호화만)만 읽고, 목록 밖 시크릿은 명시적으로 거부해 조직 전체에 열린 리소스 정책이 있어도 읽지
  않습니다. 연결 마법사의 금고 계획에서 값 읽기 역할을 켜고 대상을 적으면 역할 만들기 명령에 매개변수가 채워집니다. 계획은
  연결의 모든 계정을 함께 보고 검사하고(계정·리전 밖 ARN과 키, IAM 정책 크기 한도), 권한 확인은 역할을 맡아 본 뒤 적은
  시크릿·경로를 모두 `iam:SimulatePrincipalPolicy`로 판단해 값을 읽지 않으며 권한 경계·SCP 같은 명시적 거부는 따로 알립니다.
  서버 수집은 수집 역할 세션에서 이 역할을 15분씩 맡아(만료 5분 전에 다시 맡음) 적은 시크릿만 읽고, 수집 역할 자체는 여전히
  값을 읽지 않습니다. 주기 수집은 설치의 AWS 자동 수집 설정이 그 계정을 허용할 때만 돕니다(`VALUE_READER_AUTOMATION_DISABLED`).
  계정별 수집 역할 연결에서만 쓰며, 실제 AWS 계정 동작은 실환경 검증 항목입니다.
- 퇴사자 점검과 대응 담당자 추천은 GitLab 사용자의 외부 로그인 중 다른 서비스 계정(`identities[].provider`가 `github`·`gitlab`·
  `bitbucket`·`atlassian_oauth2`·`salesforce`·`alicloud` 등)의 uid를 연결 값으로 쓰지 않습니다. 그 uid는 그 서비스의 계정 ID나
  사용자 이름이라, Bitbucket 사용자 이름이 IdP 로그인과 우연히 같을 때 다른 사람과 이어지던 일을 막습니다. 이름을 따로 붙인
  SAML·OpenID Connect 로그인은 그대로 씁니다.
- 마법사는 GitHub Enterprise Server 연결의 인벤토리 유형에 SSO 승인 4종(Classic PAT·OAuth 앱 토큰·GitHub App 사용자 토큰·SSH
  키)을 내놓지 않고, 메타데이터 화면은 이 4종의 제품에서 Server를 뺍니다. Server의 REST API에는 조직 SAML SSO 승인 목록도
  Enterprise 자격증명 Export도 없습니다. 수집기도 Server 조직에서는 이 목록을 읽지 않습니다(이전에는 이 읽기의 실패로 매 수집이
  부분 완료로 끝났습니다).
- 퇴사자 점검은 GitLab 사용자의 `extern_uid`(GitLab에 연결한 SAML·LDAP·OIDC 등 외부 로그인이 준 값)가 이메일이 다른 여러
  IdP의 사람에게 닿으면 GitHub SAML·SCIM 신원처럼 자동으로 잇지 않고 후보로 둡니다. GitLab이 확인한 기본 이메일이 정확히
  가리키는 사람은 그대로 잇습니다. 대응 담당자 추천도 GitHub 신원 값을 같은 종류의 IdP 값(SCIM 사용자 이름은 로그인·이메일,
  이메일은 이메일)과만 맞춥니다.
- 퇴사자 점검은 GitHub SAML·SCIM 신원이 여러 IdP의 서로 다른 사람(이메일이 다름)에게 닿으면 자동으로 잇지 않고 후보로
  둡니다. 같은 이메일로 두 IdP에 있는 사람은 한 사람으로 잇습니다. 모든 목록을 끝까지 읽으며, 끝까지 읽지 못한 평가는
  연결·판정을 바꾸지 않는 `PARTIAL`로 끝나고 그 이유를 요약 API와 "퇴사자 Credential" 화면에 보여 줍니다(끝까지 읽은 IdP의
  사람 상태는 저장하고, 보존 정리는 다음 완전한 평가까지 미룹니다). 목록에서 처음 빠진 사람의 퇴사 시각은 그 수집이 끝난
  시각이고, Keycloak 관리 이벤트로 재활성화를 본 뒤에는 그 뒤의 새 비활성화 시각을 씁니다. 금고 대조 보고의 행 한도가
  CloudTrail 기록을 자르면 AWS 키 생성자는 "조회 미완료"로 표시합니다.
- GitHub 사람 목록(조직의 SAML SSO 신원)을 GitHub App의 조직 권한 Members(읽기)로도 읽습니다(GitHub.com·Enterprise Cloud).
  수집 토큰은 그 조직 설치에서 `members: read` 하나만 받습니다. 엔터프라이즈 신원(EMU·엔터프라이즈 SAML)은 지금처럼
  엔터프라이즈 소유자의 classic PAT로 읽고, GHE.com·Server에서는 마법사가 사람 목록에 App을 내놓지 않습니다(Server는 조직
  SAML이 없어 어느 방식으로도 읽지 못하는 것으로 봅니다).
- AWS 잠재 권한은 IAM 사용자의 정책에 키 ARN으로 적힌 같은 계정 KMS 키의 키 정책도 읽어(`kms:GetKeyPolicy`, 두
  CloudFormation 템플릿과 IAM Identity Center 권한 세트 정책에 추가) 시뮬레이션합니다. 읽은 키 정책이 IAM 정책 위임도
  사용자 직접 허용도 하지 않으면 그 허용을 세지 않고 "키 정책에 막힘"으로, 조건부로만 허용하면 "요청 조건에 따라 다름"으로
  보여 줍니다. 정책의 별칭 ARN은 키 사용을 허용하지 않으므로 지정 리소스에서 빼고, 지정 리소스의 누락된 조건 키
  (`ResourceSpecificResults`)도 반영합니다. 키 정책을 읽지 못한 키(스택·권한 세트를 갱신하기 전, 또는 키 정책이 수집 역할에
  `GetKeyPolicy`를 주지 않은 키)는 이전처럼 IAM 정책만으로 판단하고 "키 정책을 읽지 못한 키"로 표시합니다.
- AWS 연결 점검은 CreMore의 CloudFormation 템플릿이 수집 역할에 Parameter Store 값 읽기(`GetParametersByPath`)를
  주지 않는다고 알립니다(`AWS_SCANNER_TEMPLATE_GRANTS_NO_PARAMETER_VALUES`). 서버에서 값을 대조하려면 별도 값 읽기 역할(위)을
  켭니다.
- Microsoft 워커 신원은 환경의 서비스 주체·워크로드 ID·관리 ID만 쓰고, 호스트의 사람 로그인(Azure CLI·PowerShell·azd·
  VS Code·공유 토큰 캐시·브라우저·Windows 계정 브로커)은 쓰지 않습니다. 마지막으로 로그인한 사람의 신원으로 수집되지
  않습니다. `azure` 추가 설치는 `azure-identity` 1.24 이상을 요구합니다.
- 연결 마법사의 공급자 안내와 권한 점검을 공식 문서(2026-10-07 확인)와 다시 대조했습니다.
  - Atlassian: 조직 API 점검이 수집기와 다른 경로(`/admin/v1`)를 부르던 것을 `/admin/api-access/v1`로 고쳤습니다.
    Bitbucket 작업공간 목록은 2026-04-14에 없어진 `/2.0/workspaces` 대신 `/2.0/user/workspaces`를 읽습니다.
    Confluence Cloud 토큰은 Bearer로 보내므로 서비스 계정 API 토큰만 받는다고 안내합니다.
  - Notion: 이름을 "내부 연결(이전 이름: 내부 통합)"으로 바꾸고, 페이지는 ••• → 연결 추가로 공유한다고 안내합니다.
  - Slack: 대상 조회는 `admin.teams:read`가 없으면 조직 자체만 대상으로 내놓습니다(마법사의 앱은 `admin.apps:read`만 요청).
  - Vault·OpenBao: 목록 권한은 접두어 끝에 `/`를 붙인 경로로 확인합니다. 이전 버전·accessor·lease 옵션이 읽는 곳도 점검해,
    권한이 빠졌으면 활성화를 막습니다.
  - Keycloak: 관리 이벤트 옵션에 26.2 이상이라는 요건을 표시합니다.
  - Okta: 메뉴 경로를 고치고, API 범위는 Super Admin만 부여할 수 있다고 안내합니다.
  - GitHub: App의 금고 연결은 환경 목록에 필요한 Actions: 읽기를 요구합니다. 엔터프라이즈 소유자 확인은 `ownerInfo`로
    하여 결제 관리자를 소유자로 보지 않습니다.
  - GitLab: 역할을 확인합니다(그룹 Owner, 프로젝트 Maintainer, 그룹 CI 변수는 Owner). 대상 조회는 구성원으로 속한
    프로젝트만 읽습니다.
  - Google Cloud·Workspace: Google 로그인 동의는 Google Cloud 전체 접근(cloud-platform)을 묻는다고 알리고, 로그인 앱 설정을
    Google Auth Platform(대상·클라이언트, 시크릿은 만들 때 한 번만 표시) 기준으로 안내합니다. 도메인 전체 위임은 최고 관리자가
    전체 URL 범위로 허용하며(최대 24시간), 키 조치는 키 생성까지 허용하는 `roles/iam.serviceAccountKeyAdmin` 대신 네 권한만 담은
    사용자 지정 역할을 씁니다.
  - Microsoft: 로그인·감사 옵션을 켜면 Graph 명령에 AuditLog.Read.All을 더하고, P1·P2 라이선스가 없는 테넌트는 권한이 아니라
    라이선스 문제로 알립니다. 관리 ID에는 Graph 앱 역할 할당 명령을, Azure 역할은 범위의 역할 할당 권한자가 실행하는 명령을
    따로 주며, 선택한 모든 구독·스토리지·Key Vault에 대해 만듭니다. Key Vault RBAC·Reader and Data Access·Token Admin(조회·폐기)과
    Azure DevOps 조직 범위 PAT(전역 PAT는 2026-12-01 중단)를 바로 안내합니다.
  - AWS: CloudFormation 수집 역할은 `GetSecretValue`를 명시적으로 거부하므로 금고 대조가 막히는 이유를 그대로 알립니다.
    조직 목록 정책에 OU 탐색 권한을 더하고, 만료된(Expired) Bedrock·CloudWatch API 키가 IAM 수집을 미완료로 만들지 않습니다.
    컨테이너의 IMDSv2 홉 제한, `aws sso login --use-device-code`, 무작위 ExternalId, 문서화된 빠른 생성 링크를 씁니다.
    공동 검토 모듈(`aws_identity` 등)의 읽기 정책 누락·AssumeRole 범위를 담당자 검토로 고치고 유럽 주권 클라우드
    (`aws-eusc`)의 리전·ARN을 인식합니다.
- 권한 판정을 넓혔습니다. AWS 잠재 권한은 `*`에서 허용 근거가 없던 작업을 주체 정책에 적힌 리소스 ARN(최대 25개)으로
  다시 시뮬레이션하고, IAM 사용자는 같은 계정 S3 버킷·Secrets Manager 정책의 명시적 거부까지 반영합니다(`assessment_version=3`).
  GCP는 인벤토리 옵션 `effective_access`로 사용자 관리 키가 있는 서비스 계정(수집마다 최대 20개)에 Policy
  Troubleshooter로 고위험 권한 11개를 묻고, 상속·거부 정책·그룹·조건을 반영해 허용된 권한을 키의 권한 표에 보여 줍니다.
  GCP 권한의 쓰기·읽기 표시는 권한 이름의 동사로 정합니다(`secretmanager.versions.access`는 읽기). 연결 점검은 여러
  옵션이 함께 쓰는 권한을 그중 한 옵션이 꺼졌다고 숨기지 않습니다.
  Microsoft는 옵션 `app_permissions`(애플리케이션 권한·Entra 역할)와 `app_azure_roles`(Azure 역할)로 앱 비밀·인증서마다
  그 서비스 주체가 받은 것을 권한 표에 보여 줍니다(서비스 주체 최대 50개). Azure 역할은 역할 할당·정의만 읽는 사용자
  지정 역할을 테넌트 루트 관리 그룹에 주고 그룹으로 받은 할당까지 읽으며, 읽기 실패는 자격증명에 알 수 없음으로 남고
  수집 상태를 부분으로 바꾸지 않습니다. 메타데이터 표의 일부 지원 항목은 값이 없을 때 언제 값이 생기는지 사유를 보여 줍니다.
- 금고 대조의 지문 계약을 문서 추출 정책과 분리했습니다(`coverage_policy_digest`). 문서 추출을 넣으면서 계약에 파서
  버전까지 섞여, 고객 환경 해셔가 `FINGERPRINT_CONTRACT_MISMATCH`로 수집을 거절하고 노출·금고 대조가
  `EXPOSURE_COMPATIBILITY_NOT_CONFIRMED`(UNKNOWN)가 되던 문제입니다. 그 사이(2026-10-06 이후)에 스캔한 노출과 수집한
  금고는 다시 스캔·수집하면 대조됩니다.

- GLPI 대응 티켓에서 필수 조치 결과·사유·수행 시각을 작성하고 승인/거절을 한 번에 제출합니다. 동봉 플러그인이 서버에서도 누락을 차단하고, CreMore는 정확한 담당자와 보고를 재검증해 불변 보고·감사 이력으로 남깁니다. 단순 승인만으로 조치 완료되지 않습니다.
- 신규 Okta 사람 목록은 기본 5분마다 수집합니다. 담당자 배정·퇴사자 화면과 담당자 선택에 마지막 수집·대기 상태·지금 갱신을 표시하고, 관리자는 기존 연결 계획에서 갱신 주기를 변경할 수 있습니다.
- 대응 담당자를 같은 로그인 IdP에서 검색·페이지 선택하고, 발송 직전에 현재 신원·활성 상태·이메일을 다시 확인합니다. 정확한 발급 소유자 근거만 추천하며 수동 배정·위치/발급 계정 책임 규칙은 버전 검사와 감사 이력을 유지합니다.
- 발견 위치의 접근 근거를 Confluence·Bitbucket·Azure Repos Git·S3·GCS·Blob으로 확대합니다. 주체·그룹·정책과 허용/거부·공개 접근·부분 수집을 구분하며 모든 실효 독자나 실제 열람 이력으로 단정하지 않습니다.
- 연동 기능을 함께 선택하고 추가 인증을 같은 설정 과정에서 이어갈 수 있습니다. GitHub App 자동 만들기·설치를 인증 화면에 복원하고, 기존 연결은 기능별 중지·재개 상태를 범위·인증 갱신 뒤에도 유지합니다.
- SIEM 공통 전송에 자동 대응 제거 확인·재출현 상태를 포함합니다. 한 목적지 설정이 현재와 이후의 모든 공급자 연동에 적용됨을 화면에 명시합니다.
- AWS Organizations·GitHub App·Slack Grid의 다중 계정/조직 목록과 선택별 권한 검사를 연결합니다. Vault workload/private CA, Confluence 서비스 계정, Bitbucket·Azure DevOps의 지원 서버 인증도 인증 후 목록 선택을 사용합니다.
- 새 상시 수집 연결에서 개인 AWS SSO·고객 CLI 경로를 제외하고 기존 연결은 보존합니다. 사내 서버의 AWS 수집은 기존 OIDC→STS 자동 갱신 경로를 사용하며, 호스팅 위치와 수집 대상·봉인 키 저장소를 분리합니다.
- 발견 위치별 접근 근거에 검색·연결 구분·CSV를 추가합니다. GitHub 협업자와 GitLab 구성원·역할, 공개 범위·부분 조회·미지원 위치를 구분하고 현재 승인 범위를 매 요청 재확인합니다. 실제 열람 이력이나 모든 실효 독자 목록으로 표시하지 않습니다.

- Separate active credential exposure from removed-location history, preserving
  one credential identity across rescans and restoring reappearing locations.
  Reconcile renamed Notion pages by page identity after a complete comparable read.
- Add ticketed exposure response: the recipient's completion means awaiting scan
  verification. Subsequent scan evidence determines removal or further action;
  each request cycle and transition retains its audit evidence. Idempotent sends,
  version checks and an explicit unknown-delivery state prevent blind retries.
- Refresh mounted console reads automatically and after returning to a tab,
  without repeating manual provider investigations or overwriting unsaved edits.

- Removed saved demo and synthetic data files and their generators. Regression
  checks construct only the inputs they need during test execution; this cleanup
  does not delete data from existing application databases.

### Collected secrets stay in memory

- Removed GCP `store_values`/`keep_values` and the admin `gcp-values` read API.
  Collected secret values are never retained, including reversible ciphertext or
  Base64; HMAC fingerprints and necessary metadata remain. Provider authentication
  credentials keep their separate sealed-storage contract.
- Value reads and existing `value_match` correlation remain available. Successful
  payload reads, including binary and empty values, use private HMAC evidence for
  change detection only when the scheme and key identity match. These fingerprints
  are excluded from public responses and exports.
- Legacy storage options no longer enable storage. Existing plaintext rows and
  backups require the [GCP cleanup procedure](docs/integration/GCP_TOTAL_GUIDE_KO.md#과거-원문-저장-설치의-이관);
  a code upgrade alone does not remove historical secrets, WAL or replicas.

### Continuous operations

Design: [docs/CONTINUOUS_OPERATIONS_DESIGN.md](docs/CONTINUOUS_OPERATIONS_DESIGN.md).

- Connection health: content, vault/metadata and AWS account connections share one
  vocabulary (`auth_state`, `auth_renewal`, provider- or operator-entered expiry with
  14/3-day stages, last success/failure, `freshness`) at `GET /api/v1/operations/connections`;
  an Admin records an expiry the provider does not report at
  `PUT /api/v1/operations/connections/{key}/expiry` (audited).
- Operational SIEM events: `connection.auth_failed|auth_recovered|auth_expiring` and
  `collection.failed|stale|recovered`, sent only when a connection's state changes and
  evaluated by one worker replica per minute. Schema migration 8 lets
  `siem_events.finding_id` be NULL for events that are about no finding.
- Liveness: every worker records a database beat each minute; one replica queues
  `platform.heartbeat` every `OPERATIONS_HEARTBEAT_MINUTES` (default 5). A SIEM alerts
  when it stops. `/api/v1/operations/status` shows live workers and queue delay.
- SIEM delivery operations: the exporter records per-destination status
  (`siem_destination_status`; grant it INSERT/UPDATE), an optional `max_attempts` holds an
  event after that many failures (default 0 keeps retrying), and Admin routes show status,
  send a `siem.test` event, follow its deliveries and release held ones. Splunk HEC uses one
  sourcetype per event family (`cremore:finding` unchanged).
- SIEM backlog and retention: `siem.delivery_backlog` / `siem.delivery_recovered` tell the
  other destinations when one falls behind (held events, 5 consecutive failures or a
  15-minute wait); `/api/v1/operations/status` raises `SIEM_DELIVERY_BACKLOG` and
  `SIEM_EXPORTER_INACTIVE`. One worker an hour prunes events every active destination
  received: heartbeats and test events after 7 days, the rest only with
  `SIEM_EVENT_RETENTION_DAYS` (default 0 keeps them).
- Deployment: including `deploy/compose/siem/compose.yml` now runs the exporter
  always-on and hardened (no profile flag; read-only, `no-new-privileges`); the
  public overlay guide adds it for shared servers. The Helm chart gains an
  optional `siem` exporter Deployment with its own database Secret, token Secret,
  NetworkPolicy egress ports and a heartbeat-file liveness probe.
- Generic vaults ([docs/EXTERNAL_VAULT.md](docs/EXTERNAL_VAULT.md)): an `external_vault`
  connection names its product and declared path scope. `cremore-coverage --input FILE|-`
  fingerprints a JSON Lines export in the customer environment (request bodies carry
  fingerprints only); `--declare-complete` is the operator's statement that the export holds the
  whole declared scope, and only then can "not in the vault" be concluded, labelled
  `OPERATOR_DECLARED`. Installed `cremore.vault_readers` plugins read a vault directly when named in
  `CREMORE_VAULT_READERS` (`READER_REPORTED`); `kubernetes_secrets` is built in. Coverage runs record
  `completeness` (additive nullable column) and `GET /api/v1/coverage` reports the weakest basis in
  scope as `absence_basis`.
- Departed-owner check ([docs/LEAVER_CHECK.md](docs/LEAVER_CHECK.md)): new identity collections `okta` (service app
  with `private_key_jwt`, DPoP when the app requires it), `entra_id` (`User.Read.All`), `keycloak` (service account,
  optional admin events) and `github_identity` (organization SAML/SCIM identities), which keep emails and logins only as
  keyed digests. Provider `credential_owner` functions (GitHub, GitLab, Azure DevOps, Atlassian, Notion, AWS IAM) name
  who owns each issued credential; exact links, administrator-confirmed candidates, four verdicts
  (`USED_AFTER_DEPARTURE`, `ACTIVE`, `REVOKED_OR_EXPIRED`, `UNKNOWN`) with exposure and vault state, the
  `identity.credential_orphaned` SIEM event, `DEPARTED_OWNER` tickets (tickets may now be about a credential with no
  finding: `orphan_ref`, migration 9) and AWS key disable plans with reason `OWNER_DEPARTED` through the existing
  approval. `LEAVER_RETENTION_DAYS` (default 365) deletes a departed person's data; identity collection history is kept
  30 days. Azure DevOps token owners now keep the Entra `originId`; GitLab keeps a user's SAML `identities`.
- Change feeds ([docs/CHANGE_FEEDS.md](docs/CHANGE_FEEDS.md)): the worker asks GitHub, GitLab, Azure DevOps,
  Bitbucket Cloud and Data Center what changed since the last commit it saw, and Confluence which pages moved, every
  5 minutes by default (per provider, `change_feed_minutes`). Only the named files are read; a list the provider
  cannot finish reads the whole root, a force push reads it from scratch, and an event scope without a schedule gets
  a daily reconcile. Admins switch it at `PUT /api/v1/settings/scan-triggers` (`change_feeds_enabled`; on by
  default since the scheduling entry at the top of this list); `SCAN_CHANGE_FEEDS_MODE=disabled` locks it. Cursors live in the new `scan_change_cursors` table. Bitbucket Data
  Center connections take an optional `max_changes` (the server's `page.max.changes`, default 1,000).
- Incremental reads: GitLab and Azure DevOps blob IDs, GCS generations, Azure Blob ETags and Confluence attachment
  versions now reuse earlier results like GitHub and S3 did, and a worker scan never downloads an unchanged object.
- Queue events: the SQS consumer is now shared by the customer's own Pub/Sub subscription and Service Bus queue or
  topic subscription (`pubsub_*`, `servicebus_*` settings, `SCAN_PUBSUB_MODE`, `SCAN_SERVICEBUS_MODE`). It reads Cloud
  Storage notifications, Event Grid blob events, Azure DevOps `git.push` hooks and GitHub, GitLab and Bitbucket push
  webhooks; a push wakes the repository's change feed, or rereads the repository when the feed has no cursor.
- Machine identity ([docs/MACHINE_IDENTITY.md](docs/MACHINE_IDENTITY.md)): the Helm chart's
  `azure.workloadIdentity` labels the API and worker pods and annotates their ServiceAccounts for
  AKS workload identity, and `vaultConnections.tokens` projects one audience-bound token per external
  Vault cluster into the worker (`VAULT_CONNECTION_TOKEN_DIR`), with `vaultConnections.egress`.
  Off Kubernetes, `cremore-token-refresher` keeps IdP client-credentials tokens current in files
  (atomic, 0600, refreshed at half life, backing off without dropping the last token), and
  `deploy/compose/identity/` passes them to AWS web identity, Azure workload identity federation, GCP
  Workload Identity Federation and Vault logins. The SIEM exporter mounts destination certificates
  (`SIEM_TLS_DIR` in Compose, `siem.tlsSecretName` in Helm).
- SIEM events (additive to schema v1): every event carries a random per-installation
  `installation_id` (shown at `GET /api/v1/siem/status`); `finding.updated` reports triage,
  verification-status and scan-rollup changes in the same transaction; `audit.action` sends each
  person's audit-trail action with a derived `actor_ref` and no names, e-mails or notes;
  `coverage.verdict_changed` reports changed vault verdicts from a five-minute worker slot
  (baseline first, suspended while the vault scope is unconfirmed, at most 500 per pass). New
  `coverage_verdicts` table.
- SIEM transports: `http_json` authenticates with a Bearer/`ApiKey` token, an API key header,
  environment-sourced custom headers or OAuth 2.0 client credentials (cached, refreshed after a
  401), and can send a one-element array with fixed query parameters (Sentinel Logs Ingestion API)
  or address `{event_id}` with 409-as-delivered (Elasticsearch `_create`). New `syslog_tls` sink:
  RFC 5424 over TLS with RFC 5425 octet counting (or LF), JSON, CEF or LEEF 2.0 bodies, verified
  TLS 1.2+ and optional mutual TLS. A destination's `format: "ocsf"` sends OCSF 1.3.0 Detection
  Finding / API Activity where a class fits. LogScale gains a `family` tag; HTTP 401/403 is
  recorded as `AUTH_FAILED`. Field mapping per SIEM: [docs/SIEM_FIELD_MAPPING.md](docs/SIEM_FIELD_MAPPING.md).
- Other Vault/OpenBao clusters can be read by the worker with the connection's own login
  (`server_auth`: Kubernetes or JWT from a file under `VAULT_CONNECTION_TOKEN_DIR`, or a token
  sealed on arrival by its provider connection), a pinned CA (`tls_ca_pem`) and no redirects. The
  installation's secret-store identity is never used for them.
- Dashboard: an Admin `Operations` tab (`?tab=operations`) shows connection health with the
  attention filter and operator expiry entry, SIEM delivery per destination with a test
  event followed to delivery and held-event retry, and worker liveness; Korean and English,
  light and dark, keyboard operable.
- Provider connections ([docs/ONBOARDING.md](docs/ONBOARDING.md)) replace the four registration
  windows. One provider connection is one identity and one credential shared by every purpose it
  serves -- exposure scans, the issued-credential inventory, vault reads and IdP identities -- and
  every provider connects through the same four steps at `/api/v1/provider-connections`: choose the
  provider, edition and purposes from the catalog (permission checklist, auth methods in recommended
  order); enter the target and credential (sealed on arrival, or one `vault://` reference whose
  `reference_keys` the catalog names); a `provider-check` worker job checks each purpose's
  permissions and stores statuses only; step 4 creates the content sources, AWS accounts and
  collections each purpose runs on, in one transaction, from per-purpose plans (value reads,
  previous versions, audit events, instance-wide GitLab lists, GCP organization/folder discovery,
  Azure subscription discovery and Storage key fingerprints, Vault token accessors and leases).
  A new credential re-points every owned record; the auth method and its public settings are fixed
  once records exist. A new connection takes over the records of a disabled one (content sources
  keep their history, AWS accounts their ExternalId). AWS connections with `adopt_discovered` take in
  the accounts Identity Center and Organizations sweeps register and apply their saved plans. AWS,
  GCP (Secret Manager) and Vault can be read by the CreMore CLI in the customer's environment with
  collector tokens. New tables `provider_connections` and `provider_connection_children`.
- Credential list: `GET /api/v1/credential-records` returns one row per credential -- every finding
  and every issued credential an inventory listed (schema 2 collections and AWS IAM keys). An issued
  credential joins the finding of the same credential by the evidence the vault comparison uses
  (keyed value fingerprint, GitHub token digest, a single GCP key ID, AWS key ID) under the current
  fingerprint key; the rest are their own rows. Each row carries the triage status, verification,
  issuer facts (name, created, expiry, last use, scopes), the vault comparison verdict and the
  analyst annotations. Nothing calls a provider and no digest leaves the server.
- Finding annotations (new table `finding_annotations`): tags, the review stage of an acknowledged
  finding (`review`/`action`; any status transition clears it), remediation step states with
  comments, and the latest owner contact (channel, template, recipient count, reply-by date; the
  message is composed and sent outside CreMore). Every change is revision-guarded and recorded in the
  finding's history; comments are events. Free text the detection engine finds a credential in is
  refused, and `POST /api/v1/text-check` checks a draft without keeping it.
- New console (`/console`, replacing the dashboard at `/` when complete): the approved console design with
  its rail, page head controls (search, help, notifications, language, theme), credential overview,
  and the credential list with filters, sort, columns, saved views, CSV export and the five-tab
  credential panel (access map, exposures with original-source links, permissions, key facts, issuer
  links, risk rules, exposure stages, ownership review, owner contact, remediation steps with guides,
  history). Status changes, tags, comments, assignment, contact records and rescans write through the
  finding routes. Pretendard (SIL OFL 1.1) ships with it. Credential rows add `acknowledged_at` and
  `resolved_at`.
- Console owner and team assignment (`?view=assign`): tiles for credentials without an owner or a team, waiting
  for the owner and overdue; selected credentials take one team, review state and due date
  (`ownership-reviews/bulk`, 100 per request with each row's revision) or one response owner; the team tab
  counts each team's open, ownerless, waiting, overdue and closed credentials and IdP members, and opens the list
  for that team. A row opens the credential on its ownership tab. Only rows the current filter shows are acted on;
  what a later batch could not save stays selected with the reason. Each saved ownership review is now an audit
  event (`OWNERSHIP_REVIEW_UPDATED`, the team JSON-quoted in its note) in the same transaction, sent to the SIEM
  as `audit.action` with the review's own states. A team name, an assignee and a tag must be one line of plain
  text (no control, format, bidi or line-separator characters, no letters that draw nothing such as Hangul
  fillers) without a secret-shaped value, since they go into the audit trail; comments and step comments keep
  lines and tabs under the same rule (`text-check` reports it as `unsafe`). A modal no longer takes focus back
  when the list behind it refreshes, and Tab brings focus back into a modal when the control that had it was
  disabled or removed.
- Console integrations: provider connections are listed with their collecting features, sign-in
  method, state (from the owned records' health and the permission check: healthy, needs attention
  with the expiry or re-authentication, partly failed, collecting, setting up, stopped), last run and
  results, with collect now, settings, check again, rename and disconnect/turn on/delete. The catalog
  cards and the three-step wizard are built from `GET /api/v1/provider-connections/catalog`: features,
  target and options follow each field's edition and `when` rules; the credential (or a `vault://`
  reference) is sealed on "Test connection", which then follows the worker's permission check; review
  activates the chosen features with their plan and schedule, and a collector token is shown once.
  GCP Google sign-in returns to the console (`gcp/web/oauth-session.ts`), AWS member-role connections
  show each account's ExternalId, CloudFormation link and CLI command. Secret stores, directory sync
  (IdP connections) and SIEM delivery sit beside the catalog. The rail keeps every screen of the design.
- Brand logos are each brand's own mark (`web/public/logos`, sources and licences in `SOURCES.md`):
  Microsoft's published Azure and Entra icons, Slack's and Keycloak's own site marks, and Simple Icons
  16.33.0 for the other providers the detectors know. What is not a brand shows a line icon.
- Inventory token types: each provider module declares the credential types its inventory lists
  (`purposes.inventory.types` in the connection catalog) with, for nine key fields (ID, name,
  created, expiry, scopes, creator, owner, last use, state), whether the provider's API returns it
  always, only sometimes or never, and why a field can be empty. The catalog refuses a declaration
  without a reason for a partial or missing field, with an unknown match key, or outside the
  provider's inventory. Credential rows carry `issued.type`; an inventory's public keys and app
  installations are rows only when their type is declared.
- Console metadata coverage: every declared token type per service with its key-field support,
  filters by field and support state, the share of supported fields, the field most often missing
  and the tokens collected. A type's panel shows how full each field is across the collected tokens,
  each token's values, and how the type is collected (connection, method, schedule, permission,
  fields that can be empty) with a link to the connection.
- Organization rules say what their value is (`category`: token, API key, secret, account, private key,
  connection string, webhook URL, other; new nullable `custom_rules.category`) and who last changed them
  (`updated_by`, set from the caller; new nullable `custom_rules.updated_by`). Their matches take that
  type in the credential list, which names them by the rule. `GET /api/v1/rules` adds `credential_type`.
- Console detection rules: the built-in detectors and the organization's rules in one list with
  filters (creator, type, category, status), search, sort and pages; turning a rule off leaves it out
  from the next scan. A row opens its description, the value it reports in plain words, the pattern in
  pieces that say what each means, keywords and how it matches. Rules are written, copied from any
  rule, changed and deleted in the design's form: the server's RE2 check answers as the pattern is
  typed, a synthetic value in the pattern's shape can be inserted, and a sample is tried in the browser
  only, with a warning when it looks like a real value.
- Inventory types declare where they are listed (`when`) and how they are collected (`plan`: always, or through
  a bool, list or choices plan option); exposure purposes declare what a scan reads (`scans`). The connect
  wizard shows the design's "credential types to collect" (switching a bound type sets its plan option),
  "where to scan" and "scan scope": everything the account can see, or names and paths with wildcards
  (`selection-drafts` takes `patterns`). After activation the console lists each place's catalog, saves the
  matches as the approved scope and starts the first run; an integration row asks for a scope when none is
  set, counts the types and places it collects, and "Collect now" runs the approved scopes.
- Console collection and detection logs: every run the worker holds (exposure scans, inventory and vault
  collections, access and sign-in checks, catalog refreshes) and the runs a customer-side CLI uploaded,
  with the integration it belongs to, state, what it read and found, duration and the reason it failed or
  waits; tabs by kind, status and service filters, and a panel that stops a run or runs it again.
  `GET /api/v1/scan-runs` names a run's `connection_kind`, `profile_id` and `provider_connection_id`;
  `GET /api/v1/coverage/connections/{id}/runs` lists a schema 1 collection's runs (no batches or contract).
- Console secret stores: the stores values are compared with (state, last collection, items, listing basis,
  collect now, settings), the comparison scope an Admin confirms or undoes and what still holds the
  "not in a store" verdict, the credentials no confirmed store holds, and issuance and storage records an
  Admin adds from collected issuer and vault observations and revokes. The overview's vault row names the
  secret stores of connected providers that are not compared yet and opens their wizard at that feature;
  the usage row links to the integration that could report last use.
- People from the IdP integrations: an Okta, Entra ID, Keycloak or GitHub SAML/SCIM integration with "keep people's
  names, emails and departments" (new `options.keep_profiles`; on by default for new integrations, off for existing ones
  until an Admin turns it on) keeps each person's display name, email, department and title as facts; matching still uses
  keyed digests only. `GET /api/v1/people` (Analyst and up) lists them, one person per email across IdPs, with the state
  the departed-owner check saw. The console shows owners by name and team, offers the directory when assigning an owner
  (people who left are not offered and are flagged), and fills in the mail address when contacting someone.
- Who can act on an exposed file (GitHub, GitLab): a `finding-context` job reads, with the source connection's own
  credential and GET requests only, the file's CODEOWNERS owners (GitHub and GitLab syntax, GitLab sections and default
  owners), the last commit that changed it and the repository's collaborators or project members (up to 300 people). The
  worker queues it every 10 minutes for open findings with none or one older than 7 days; `GET/POST
  /api/v1/findings/{id}/context` (Analyst and up) shows and refreshes it. The CODEOWNERS text is never kept, and a refused
  or missing list is a reason code, never an empty list. Credential rows carry the CODEOWNERS owner (basis `CODEOWNERS`
  and the file that names them), each file's author by name and how many people can read the repository; the ownership
  review's CODEOWNERS candidates come from the same read. The console shows the author column, the people with access
  (notify them, export them as CSV), the access map's people node and the cleanup step's people; both CSV exports keep a
  cell that opens with `=`, `+`, `-` or `@` as text.
- AWS IAM Identity Center sign-in from the dashboard: where the wizard said to run `aws sso login` (no sign-in, or
  it expired), an admin can press "AWS에서 로그인". The API does what `aws sso login --use-device-code` does --
  RegisterClient (public, `sso:account:access`), StartDeviceAuthorization for the profile's sso-session, then
  CreateToken once the admin approves the code in the AWS access portal -- and saves the token where the command
  does, the session's `~/.aws/sso/cache` file, through botocore's cache writer, so the worker uses and refreshes it
  as before (`cremore_aws_provider/aws_sso_login.py`, `POST /api/v1/aws/sso-login/{start,poll}`). The pending
  client secret and device code stay sealed in installation settings, bound to that admin; only the outcome stays;
  started and finished attempts are audited. Verified with a synthetic OIDC and a scratch home only. After the owner's
  review (2026-10-02) it works on a single operator's install alone (`AUTH_MODE=local`): whoever approves the code
  becomes the identity CreMore runs as, so a team install answers both steps `409 AWS_SSO_LOGIN_SOLO_ONLY`, the
  identity view says `sign_in_here: false` and the console points to the server's own role or the machine identity
  instead of the button. The Operations screen now says at the top when a team install still leans on a person's
  sign-in (`HUMAN_SESSION_IN_SERVER_DEPLOYMENT`, which the API computed and no screen showed); the installation's own
  alerts now lead the operations status and are never cut by its cap of 100 on the rest.
- GitHub: CreMore's App on the other organizations of the enterprise (recommendation O-C2). Once the App
  belongs to the enterprise, holds "Enterprise organization installations: read and write" and is installed on
  the enterprise account (three steps in GitHub, which its manifest flow cannot do), an admin of an active App
  connection picks organizations, cancels waiting ones, or turns on auto-install for organizations that appear
  after its first look, from the integration's menu. One worker a minute:
  - first, for every source and without asking GitHub, re-queues stale claims, activates checked organizations
    with the source's plans, puts a replaced source key into the copies it made (not ones an admin changed since),
    and stops the queue and auto-install of a stopped source;
  - then, starting with a different source each minute and within 15 seconds a source (20 a tick), installs the
    same App on a few organizations the enterprise lists
    (`POST /enterprises/{e}/apps/organizations/{org}/installations`, public preview) and connects each with its
    own installation and a sealed copy of the key.
  Each organization is claimed by one worker and checked again before it is connected; a source GitHub refuses or
  answers too slowly waits 15 minutes; enterprise tokens are revoked after use and the organization list is reused
  for ten minutes, read again before deciding on an organization it does not list or where the App already is.
  Routes: `GET/POST/PUT /api/v1/provider-connections/{id}/github-enterprise[/install|/cancel|/auto]`
  (Admin). Verified against a synthetic GitHub only.
- Governance on the credential panel's remediation tab (R10d): internal tickets for any finding, whatever service
  issued its credential (the aws/github/notion limit is gone; a custom playbook's provider condition takes any
  provider slug), opened with a playbook, team, owner and review date, their checklist reviewed and completed in
  place (a save keeps a recorded security review and starts over from any newer version; "Unassigned" clears the
  owner); ticket free text now refuses what hides or reorders text and lone surrogates. Management actions are
  requested there (only what the credential offers, a note without secrets) and confirmed once by another
  operator in approvals: the change and its audit row commit together, a confirmation that lost a race is refused,
  refusals are audited (`MANAGEMENT_ACTION_REFUSED`), and on a shared-token installation the one operator confirms
  their own request by re-checking it. "Send webhook event" in the panel's actions asks first, then sends the
  finding as it stands to every SIEM and webhook destination as the new event `finding.forwarded` (no names; one
  event per person, finding and minute; audited in the same transaction; `409 SIEM_NOT_CONFIGURED` when no
  destination was reported in 30 days). The session names the reference tickets keep for the person (`ref`), so
  approvals compare the author with the approver correctly.
- Owner contact sent by CreMore itself (N2a): an admin sets up mail through the company's SMTP relay (STARTTLS,
  TLS or an internal relay without TLS) and a Slack bot under Integrations > Other settings > Contact delivery,
  with the domains and the Slack channels messages may go to, and sends a test. The relay password and the bot
  token are sealed and never shown again; a saved password is kept only for the same relay, port, security and
  account. When a channel is set up, the contact window sends the message itself (mail, a Slack DM found by
  address, or a listed channel; at most 20 recipients and 200 an hour per person, a one-line subject and plain
  text the credential detector finds no secret in; Slack mention and link markup is sent as text) and records the
  contact; the mail app or the clipboard stays available for anyone else. The history shows each send
  (`OWNER_CONTACT_SENT`: channel, template, count, reply-by date and keyed digests of the recipients and the text)
  or failure (`OWNER_CONTACT_FAILED` with the code, also for the hour's limit), never the text or the addresses.
  With NetworkPolicy on, list the relay in the Helm value `contactDelivery.smtpEgress`. Verified with a fake relay
  and a fake Slack API only.
- The owner of an AWS key approves a key action plan (N2b). With company sign-in (OIDC), a remediator has CreMore
  send the owner, from the plan's card, its own text (mail or a Slack DM to a person's address in the allowed
  domains, Korean or English) with a link to `/owner-approval` that starts with the console address an admin sets
  in the contact delivery setup. The token is the link's fragment (never in a server log or a Referer), kept only as
  a digest, and stops after 72 hours or at the plan's expiry; a new link ends the earlier one and keeps the last
  decline in view. The token alone decides nothing: the owner signs in with the company identity provider (no
  CreMore role needed), and only the person whose verified email is the address the link went to, and who did not
  ask for, plan or approve the plan, reads it and decides, once, on a button press, with an optional note (no secret
  value). With the local sign-in no link goes out (exposing that console would hand out admin access); the operator
  records the approval the owner gave elsewhere with its evidence (a mail or ticket reference). The request is
  audited before the message goes out (`OWNER_APPROVAL_REQUESTED` with the address, never the token), a message
  that did not go out ends its link (`OWNER_APPROVAL_NOT_SENT`), and decisions and records are written with their
  audit rows (`OWNER_APPROVAL_GRANTED`/`_DECLINED` by the owner's subject, `OWNER_APPROVAL_RECORDED`) with the
  address and the note. The plan's card shows the state, who was asked, the decision, the note and the evidence.
  Verified with a fake relay and a fake identity provider only.
- Key actions wait for their owner (N2b-2): disabling, deleting and publishing a key run only after its owner
  approved the plan (`OWNER_APPROVAL_REQUIRED` otherwise; preparing a successor changes nothing its users see and
  does not wait), while the installation asks for it, which it does unless an Admin turns it off on the approvals
  page (`OWNER_APPROVAL_POLICY_CHANGED`, in the same transaction as the change); the older rotation jobs are not
  prepared or published meanwhile (rotate through PREPARE and PUBLISH plans). Whoever decided as the owner does not also approve the plan, checked again at execution. An
  Admin can still disable a key that a connection's scan found in a public place (not a false positive) at once
  with a reason (emergency containment, `ACTION_PLAN_EMERGENCY`, audited before the provider is touched; only the
  declaring Admin's request runs as it); once that ran, the card asks for the owner to be told, by CreMore's own
  mail or Slack DM (no link) or a record of how (`OWNER_NOTIFIED_AFTER`, claimed before the message goes out,
  `OWNER_NOTICE_NOT_SENT` when it does not).
- Owners can approve key actions in the company's ticket system, GLPI 11 first (T1, docs/TICKET_SYSTEMS.md). An
  Admin sets it up under Integrations > Other settings > Ticket system (its secrets sealed and never shown again, a
  check that signs in; `TICKET_SYSTEM_SAVED`/`_CHECKED`). A remediator asks the owner in a ticket, in either sign-in
  mode: CreMore opens a GLPI request that asks the owner's own GLPI account for GLPI's approval, audited before it
  opens (`OWNER_APPROVAL_TICKET_OPENED` with the ticket), and the worker reads the answer every minute (within 20
  seconds, only from the server it was asked on) and records it only from that account (`OWNER_APPROVAL_GRANTED`/
  `_DECLINED` by `glpi:user:<id>`; another account's answer ends the request, `OWNER_APPROVAL_TICKET_REFUSED`). The
  account asked is never CreMore's own service account. With company sign-in each sign-in's verified email is kept
  as a keyed digest, and neither the owner's address nor any address the owner's GLPI account carries may be that
  of whoever asked, requested or approved the plan: when asking, when the answer arrives, and again before approval
  and execution. Asking uses the person's hourly contact limit. Other systems plug in through
  `cremore.ticket_systems` (allowed by `TICKET_SYSTEM_PLUGINS`). Verified with a synthetic GLPI only.
- A sign-in whose `email_verified` is `"false"` or `0` counts as unverified, as `false` did, for owner links too.
- Other providers' credentials are acted on through the same approved plans (P1, docs/PROVIDER_ACTIONS.md): a
  Google Cloud user-managed service-account key is disabled, then (disabled, with the deletion acknowledgement and
  `ACTION_DELETION_ENABLED`) deleted; a GitLab group or project access token or deploy token, or through an
  instance administrator's connection a personal or service account token, is revoked. A plan is made on the
  inventoried credential (Credential details > Remediation > Credential actions,
  `/api/v2/coverage/inventory/{entity_id}/action-plans`) and binds the provider's own identifiers and the one
  integration set up to act on it, with its sign-in method and the account its check named; one unresolved plan
  reserves the credential by its identity at the provider, however many inventories list it and from wherever. The
  credential that acts is its own integration (the new `remediation` purpose, `REMEDIATION_NEEDS_ITS_OWN_CONNECTION`),
  checked without changing anything (GCP `testIamPermissions`, GitLab's token scopes and member role). Execution and
  recheck are queued for the worker (`202`, `QUEUED`, `ACTION_PLAN_QUEUED`; a recheck `ACTION_PLAN_RECHECK_REQUESTED`,
  one at a time), which alone opens that credential: it checks everything again, reads the state, asks the provider
  whether the credential still acts as the approved account, writes and reads back; a clear refusal or a request that
  never reached the provider fails, anything else is only ever rechecked. A GitLab 404 counts as gone only while the
  token's group or project is visible; a GCP key must belong to the plan's project. A run that ends without settling
  its plan is settled within a minute. The job cannot be withdrawn as a scan (cancel the plan). Helm now gives the
  worker the plan execution switches too. The owner's approval, the approvals
  queue and the owner's link and ticket name the provider and the credential. Verified with synthetic GCP and GitLab
  APIs only.
- Approved plans also revoke a Notion Enterprise personal access token (an organization bot with the read and
  `write-high-impact` scopes, read back among its creator's tokens), an Azure DevOps personal access token (a Project
  Collection Administrator's token with `vso.tokenadministration`; a revocation Azure DevOps shows only later leaves
  the plan to a recheck) and a GitHub fine-grained token's access to an organization (a GitHub App with "Personal
  access tokens: write", bound to the organization it is installed on). That last one ends the organization's grant,
  not the token: the plan says so (`target.revokes`: `ORGANIZATION_ACCESS`), and the console, the owner's link and
  ticket call it "Revoke its organization access". The Azure DevOps inventory now keeps each token owner's subject
  descriptor (`owner.subject`), where a revoke reads the token back; tokens listed before it are planned after the
  next collection. Verified with synthetic Notion, GitHub and Azure DevOps APIs only.
- One credential that both collects and acts is shown, not refused (docs/PROVIDER_ACTIONS.md section 3). The
  worker's permission check keeps keyed digests of what the credential is (the token; for a GitHub App the App,
  whose key mints any installation's token; for Google Cloud ADC the worker's own identity; for a Google sign-in the
  account), never shown; a remediation integration and a running scan or collection whose checks of their current
  credentials match are named on each other (`credential.shared_with`, "Needs attention" with "Change credential"),
  where the credential is entered, and in the action plan window (`remediation_connection.shared_with`); for Google
  Cloud ADC the acting integration is the one to move to Google sign-in. Integrations checked before this are checked
  once more by the worker, a few a minute. GitHub scans, organization inventory collections and permission checks now
  take read-only installation tokens: every permission the installation holds is asked for at read (write-only
  `workflows` and `profile`, and Copilot seat management, left out), a refusal is `GITHUB_APP_READ_ONLY_REFUSED`, and
  a token GitHub grants with more is not used (`GITHUB_APP_TOKEN_NOT_READ_ONLY`); a remediation check reads the write
  level from the installation instead of minting a token that may write. An enterprise installation's token still
  holds what the installation does (unconfirmed whether GitHub takes enterprise permissions at read). The enterprise
  organization screen no longer opens a remediation integration's App key in the API. Verified with synthetic
  GitHub, GitLab and Google APIs only.
- The company's domains are verified by DNS (N4a, docs/DOMAIN_VERIFICATION.md), for the web exposure scan that
  follows. An Admin adds a domain under Integrations > Other settings > Domain verification (IDNA 2008 names, up to
  100); CreMore makes a random challenge for it and shows the record to publish
  (`_cremore-challenge.<domain>` TXT `cremore-domain-verification=<challenge>`), which only this installation's
  challenge satisfies. CreMore asks the DNS of the network it runs in (`DOMAIN_DNS_SERVERS` names other servers by
  address, checked at start-up), so an intranet's zones verify too; a verified domain covers its subdomains. One
  worker replica asks again daily: a record gone or changed, or a week without any answer, lapses the domain with a
  new challenge and its internal sites switched off (the old record is public, so whoever registers an expired
  domain could publish it again), and only the new record and an Admin's check bring it back. A domain confirmed
  more than a week ago covers nothing. Names an address parser reads as an IP (`127.0x1`) are refused. Each domain
  has an "allow internal sites" switch for the coming scan. Analysts see the domains' state (`GET /api/v1/domains`);
  every change is audited with it (`DOMAIN_*`; the daily check only on a change, as `system:domains`). New
  dependency: dnspython (ISC). Verified with a synthetic DNS only.
- The web exposure scan (N4b, website/README.md): Domain verification's "Set up the scan" makes a `website`
  integration of the verified domains and their start pages (no sign-in; not listed among the services), one
  content source per domain. A run reads the start pages, the scripts they load and the original sources their
  source maps carry (a `SourceMap` header, a trailing `sourceMappingURL`, inline maps included), each scanned as its
  own object; a finding in a map source is located as `<map URL>!/<source>` and is `public` or `internal` by the
  addresses it came from. Every request and redirect goes only to a host a domain verified now covers, on the default
  port or one the start pages name, when every address the name resolves to is public (or private, where the domain
  allows internal sites; never loopback, link-local, metadata or platform addresses), over a connection pinned to
  the checked address unless the worker's environment names a proxy. A response is read raw within the size bound
  and a 60-second deadline (identity or one gzip layer; the connection is closed at the deadline), and https is never
  followed down to http. Scripts on other hosts are left alone; links are not followed; a site read from its pages
  never retires a location, and a location is kept without its query. Approved scopes bound every request and
  redirect by URL path (`/admin/`; an entry that is not one stops the scan's plan, `WEBSITE_SCOPE_PATH_INVALID`,
  before any run) and a rescan reads the finding's page, script or map again; whether a rescan's location is in the
  approved scope is decided by the same test the run applies (`scope_allows`), so a rescan is neither refused for a
  location the run would read nor accepted for one it would skip. The worker no longer logs request URLs (httpx at
  WARNING). Verified with a synthetic DNS and site only.
- The console's Audit Log, Operations and Settings screens (R11). Audit Log: CreMore's records with filters that
  follow the data and a record drawer, what providers reported about their own credentials, and the hash chain
  (state, problems, an Admin accepting the open ones they examined with a one-line reason, comparing a head kept
  elsewhere); every event type and target reads in both languages. Operations: connection health in one vocabulary
  with an Admin's expiry for credentials whose provider gives none (a real day up to ten years ahead), SIEM delivery
  per destination (a test event followed at each destination, held deliveries released) and the workers. Settings:
  how people sign in (`GET /api/v1/settings/sign-in`, read-only), this device's display timezone, the verification
  switches, what starts a scan (schedules, change feeds paced per provider, the SQS, Pub/Sub and Service Bus
  queues bound to an approved scope profile), auto-triage by learned false positives with its profiles, and what
  the installation holds itself. Scan targets gain "Scan when it changes" (the profile's `event_mode`), which a queue
  or change feed needs; an untouched schedule or event choice keeps each place's own. Every installation-settings PUT
  is now audited in the same transaction as `INSTALLATION_SETTING_CHANGED`, naming the fields whose value changed and
  never an address or identifier (a PUT that changes no value stores nothing and records nothing), and so is an Admin's
  stop or sample reset of a learned false-positive profile, and turning a built-in detector off or on. These saves
  take turns on one lock row, so two Admins saving one setting at once never lose a change: a save built on the setting
  as it read it (scan triggers, auto-triage, the AWS organization and inventory settings) is refused with
  `409 SETTING_CHANGED_MEANWHILE` once another Admin's save overtook it, a first save included.
- The AWS installation settings live in the common connect wizard, where the other providers' choices are (AWS is one
  provider; no menu or screen of its own), for an Admin: what to collect ends with the automatic issuance inventory
  (schedule, accounts, CloudTrail) when that feature is chosen and the read-only investigations of discovered
  credentials (observed use, potential access, Secrets Manager metadata); the sign-in ends with how the other accounts
  come in for the chosen method (AWS Organizations with the member role: the StackSet's shared ExternalId, OU scope,
  excluded accounts, Control Tower, the sweep and its deployment; the default permission set's assigned accounts with
  IAM Identity Center) and the identity key actions run as. The parts stay mounted across steps and methods, so an
  edit not saved yet is kept; each saves at once, as the note under it says. A dialog's focus trap now includes
  `<details>` headings.
  `GET /api/v1/aws/onboarding/organization?organization_id=` returns the service-managed StackSet
  that deploys the member role to the OU scope, trusting the approved scanner identity only from inside the
  organization and with the shared ExternalId (16-128 characters, as the template takes), and leaving the excluded
  accounts out (`AccountFilterType=DIFFERENCE`; AWS's automatic deployment does not follow that filter for accounts
  that join or move between the target OUs later, which the screen says); it calls nothing in AWS. A saved ExternalId
  shorter than the template takes no longer blocks other Organizations fields, turning CloudTrail off keeps the saved
  trail bucket and prefixes, and re-approving the key action identity asks first. Of the settings one PUT names only
  those whose value changed are stored, an Organizations save that changes nothing wakes no sweep, and saving the
  defaults shown for an unreadable AWS inventory setting rewrites it. An S3 Inventory manifest binding may name the
  registered AWS account an AWS integration reaches its buckets through.
- Usage records in the console's credential panel: under the key facts (last use and its basis, for every service),
  a credential whose service answers about one credential on demand -- a discovered AWS access key -- gets a usage card
  that runs the lookup (Analyst; `POST /api/v1/credentials/{id}/usage/refresh`; management events of the last 90 days
  in up to 25 enabled Regions) and shows what it saw: when, over which window and Regions, the calls by service with
  writes and denials, what they do and the latest ones. A lookup that did not finish says why and never reads as "no
  calls"; a session key waits for a verification naming its principal; a lookup the installation keeps off, or a key
  no connected account reported, reads in words, as do the AWS account session refusals.
- Issued items open where they are linked from. The credential panel's issuance links, its menu (now "View the issued
  item") and search's issued and stored objects pointed at a screen that does not read the item; they now open the item
  itself (`GET /api/v2/coverage/inventory/{entity}`), from search even before the credential list has loaded: where it
  was collected (the tenant only when the service confirmed it), its state, when it was first and last observed, the
  collections that saw it and why their view may be dated, its permissions, and the fields of its current and last
  successful observation as the service returned them (a field not kept, or malformed, says why in words).
  The permissions card of a discovered AWS access key, for which AWS reports no scopes, lists what its usage lookup
  read: the key principal's identity policies, each with what it allows as the backend counts it (every action only for
  an unconditional `*` on `*`; NotAction and NotResource as every action or resource but those; a permissions boundary
  as the most the others may allow, never a grant), and the high-impact actions IAM's policy simulator allows, as
  potential access tagged with the simulator's risk. Beside them: a root key, a quarantine AWS attached (a leak AWS
  found), an allow-all or deny-all policy, a reading that stopped short or was cut to its first 300 statements, a
  session key's role, a simulation that did not run, and a principal with no policy attached.
- A people directory is for Analysts on every read, as `GET /api/v1/people` and the departed-owner lists are. A
  people-directory collection says who is employed, since when, and -- keeping profiles -- their name, email,
  department and title; any signed-in role could read that through the schema 2 inventory, an entity, a run and its
  exports, the provider events and search. Below Analyst its people are now left out of `GET /api/v2/coverage/inventory`
  and `/api/v1/search` (counts and facets too) and its changes out of `GET /api/v2/coverage/events`; the entity and the
  collection's runs, exports and comparisons are refused (`403`). The stored records are unchanged.
- Collection runs are run from the logs. "Stop the run" on a running schema 2 inventory or vault collection asked the
  job cancel route, which withdraws such a job only while it is queued, so the collection went on; it now stops through
  the collection (`POST /api/v2/coverage/connections/{id}/collect/stop`), and the run panel can pause it and resume it
  (`.../collect/pause`, `.../resume`), showing the pause as the server holds it and acting only on the collection's
  current job, for Analysts (a Viewer sees no controls). A collection that finished, stopped or failed shows its report
  -- what each read did, received and saved, and why it stopped short, in words with the code -- and downloads its
  export in the service's own format where the service has one. `GET /api/v1/scan-runs` names the stored runs such a
  collection wrote or closed (`coverage_run_ids`); a customer-side upload is its own stored run. Stop is offered only
  where the job can be stopped (not a running schema 1 inventory or check, never an upload or an approved plan's run),
  an access check is run again by an Admin, the role and secret-scanning checks are named in the list, and an
  operator's pause reads as one in the run list.
- Connected targets: an integration that reaches targets of its own lists them with each one's checks, from one item
  of its menu (Admin; not on a turned-off integration), the same frame for every such provider. An AWS integration's
  accounts show whether CreMore can use each for scanning and for key actions, and why not -- an account turned off
  or blocked by discovery (left the organization, outside the StackSet scope, assignment removed) reads as not used,
  whatever its last check said. A scanning check is answered by the worker (the list is read again until it is, for
  two minutes at most) and a key-action check by the API; without an approved key-action identity it says to approve
  that one. A member-role account gets its key-action role here (the console had no way to set it) and its stack is
  updated with the CLI command; an Organizations StackSet account is not offered one. A member-role account CreMore
  cannot use yet shows its deployment. A permission-set account, which only scans, moves to a member role here after
  a second click (scanning waits for the new role, and the move cannot be undone), with the assume-role policy an
  IAM Identity Center sign-in then needs. A GitHub inventory's organizations -- and, with an enterprise, the
  enterprise's -- show this App's installation on each (permissions missing by name, suspended, not installed, or not
  confirmed and why) and how their reads last ended, with an installation check once a collection of the current
  settings has finished, how many audit log events were linked to a credential, and when the organization list was
  cut short or not read in full. A Google Cloud project's collection shows its changes and the objects it observed (an
  organization or folder inventory discovers projects and has no such view).
- The console has browser proofs of its own (`web/tests/console-*.browser.cjs`, run with `npm run test:browser`):
  every screen on the rail and a credential's panel in Korean and English, light and dark, at 360, 768 and 1440
  pixels, and the flows the dashboard's proofs covered -- search, storage records, rescans, key deletion plans, the
  audit log, Notion database rows, the credential list, the display timezone and late answers. They run the console
  with its own stylesheet and Pretendard, from minimal inputs constructed during each proof by
  `web/tests/console-proof.cjs` and the proof itself, with the browser's clock starting at a fixed time. They fail on
  any unexpected write, unanswered read, request
  off the page or page error, and, where they check layout, on a page, panel or dialog that scrolls sideways or leaves
  the screen. They found and fixed, in the console: the assignment screen's segmented filter and the credential
  panel's ownership tab (a long ARN) scrolled sideways at 360 pixels, and the search box at 320; a details panel opened
  from search or by a click on its row did not close on Escape (nothing had focus, or the row kept it) -- Escape now
  closes it from anywhere but a text field beside it -- and Escape on a dialog above a panel closed the panel too once
  the list behind it refreshed; an Escape that only ended Korean input being composed closed the panel, dialog or menu
  around the field; storage records and action plans could not be saved on an installation reached over
  plain http on another host (`crypto.randomUUID` needs a secure context); clearing a filter chip from the keyboard
  dropped focus to the top of the page (credentials, rules, audit log, logs and metadata coverage); and an action plan
  request the proxy could not deliver (502-504) was sent again under a new key, so the server refused it instead of
  returning the plan it may already have made.
- The console is the web application now. It opens at `/` (an address kept from `/console` is redirected there with
  its query, and the old `/demo` page's address too), and the dashboard it replaced is removed: its screens
  (`web/app/(legacy)`, `web/features`, the `/demo` page), the provider UI folders (`aws/web`, `gcp/web`, `github/web`, `gitlab/web`, `notion/web`, `atlassian/web`,
  `azure/web`), the components, brand images, Tailwind setup and generated dark theme only it used, and its tests and browser
  proofs. Vendor folders hold no UI: the console draws each connection wizard from the provider's onboarding
  descriptor, so adding a provider changes no web build setting (no `@providers` alias, Tailwind source, stylesheet
  order or Docker COPY). The shared code the console keeps lost what only the dashboard used. The page Google returns
  a GCP sign-in to looks like the console's GitHub App return page and speaks the language the sign-in started in
  (or the console's saved one). AGENTS.md, the team guide, the READMEs, the architecture and provider directory
  notes and the GCP sign-in guide describe the console.
- Secret stores keep their details in the console. A store with details of its own opens them from its row on the
  Secret stores screen: an AWS Secrets Manager store the server collects, its account's secrets in the installation's
  region and whether each rotates (the Secrets Manager inventory, where the installation keeps it on, and where to turn
  it on otherwise); a store a customer-side CLI collects, its collector token, re-issued by an Admin after a second
  click that says the comparison scope is then confirmed again, and shown once (the details do not close on Escape
  while it shows). The credentials no confirmed store holds page on fifty at a time. In an AWS access key's panel an
  Admin declares which of the installation's allowlisted Secrets Manager secrets holds the key
  (`GET/PUT/DELETE /api/v1/credentials/{id}/management`, shown only where the installation allowlists any) and, with
  the inventory on, reads that secret's storage details (rotation, the current version, the day it was last read;
  never the value); a rotation plan for the key starts from the declared secret where the installation allows
  rotating into it.
- Google Workspace is a directory for the departed-owner check (`google_workspace`, Integrations > Directory
  sync): a Google Cloud service account with domain-wide delegation of `admin.directory.user.readonly` acts as the
  super administrator named in the connection (an administrator of that domain, confirmed by `isAdmin` on every
  run; one limited to some organizational units is refused, since its complete listing would make everyone else
  look gone) and reads the users deleted in the last 20 days, then every domain's users, up to 250,000 people.
  Suspended, archived and deleted users count as departed; emails and aliases are kept only as keyed digests
  (names, departments and titles only when the connection keeps people's details). The key file's own token
  address is never used and the signed assertion lives five minutes. Google's 403 rate limits wait and retry, and
  a Cloud project without the Admin SDK API says so. The access check reads both listings and names the client ID
  the admin console must allow when the delegation is missing; the key's expiry can be entered for a warning.
  Verified with a synthetic Google only.
- An identity collection runs only on CreMore's worker: a collector token cannot start or close a run
  (`IDENTITY_COLLECTION_IS_WORKER_ONLY`), since its records would all be refused, an empty run would still become
  the latest and closing the worker's run half-way would make everyone not yet listed look gone. Absence from a
  complete listing counts as a departure only for the collection's current directory and only for people it last
  saw itself: two collections of one directory no longer call each other's people departed, and a collection
  pointed at another directory leaves the first one's people as they were.
- Key action plans are audited: requesting, approving, starting, verifying, failing, an unknown outcome, each
  recheck and cancelling a plan are audit events (`ACTION_PLAN_*`, target `action_plan`, note `plan_hash=…`)
  committed in the same transaction as the plan change, and every refused request, approval, execution, recheck
  or cancellation is `ACTION_PLAN_REFUSED` with the action and the refusal code, including refusals of the AWS
  session after the plan's own gate. They reach the SIEM as `audit.action` with the plan's statuses.
- The audit trail is tamper-evident (docs/ENTERPRISE_HARDENING.md section 6).
  - The API and worker MAC each audit row as they write it, and one worker seals the rows each minute into a keyed
    hash chain.
  - The key comes from the new optional `AUDIT_CHAIN_KEY`, else from `FINGERPRINT_KEY`, and is never in the
    database. New columns: `entry_mac`, `chain_seq`, `chain_mac`; migration 10 makes the chain position unique.
  - The first seal takes in every older row and then starts the chain with `AUDIT_CHAIN_STARTED`. A chain whose
    start or anchors remain is never started again.
  - Each hour an `AUDIT_CHAIN_ANCHORED` row in the chain claims the head, which catches rows un-sealed and sealed
    again. While the worker runs, a moved head is recorded as `AUDIT_CHAIN_REWOUND`.
  - `GET /api/v1/audit/integrity` (Analyst) reports every problem, not only the first, including rows put at a
    position no chain has (which the table also refuses). One check runs at a time.
    `POST /api/v1/audit/integrity/acknowledge` (Admin) accepts problems open now by their `ack` key, as a chained
    row. It binds the row's content; a gap's extent and both sides of it; an unauthenticated row's ID and content,
    whether sealed or waiting.
  - On PostgreSQL, sealing and the hourly check run in the worker's own thread, clear of its liveness beat.
    Authentication checks begin at the first start row the sealer wrote. A start row it did not write is
    `GENESIS_INVALID` and moves nothing; rows sealed again in front of the start move it (`GENESIS_MOVED`). A
    running worker never starts a chain again, even when its rewind record is removed.
  - Once an hour `audit.chain_anchor` (and the worker's log) carries the result, the chain's start, the anchor
    number and the head for SIEM rules. It has severity 9 unless `INTACT`; in CEF, `cs3` is chainState, `cs2`
    genesisMac and `cn2` anchorNo.
  - Upgrade the API and worker together.
- The Google sign-in app set up in the dashboard: a GCP connection that signs in with Google and finds no OAuth
  client asks for it in that step (redirect URI filled in from the dashboard's address, client ID, client secret)
  and goes on to the sign-in. `PUT /api/v2/gcp/oauth/client` (Admin) seals the secret in installation settings,
  never returns it, keeps the saved secret when a new redirect URI comes without one and audits
  `GCP_OAUTH_CLIENT_SAVED`. `GCP_OAUTH_*` settings still win: with any of them set the dashboard shows the client
  ID and refuses a change (`409 GCP_OAUTH_CLIENT_PINNED`). `GET /api/v2/gcp/oauth/status` adds `client_id`,
  `source` (`SETTING`|`DASHBOARD`) and `locked`. Verified with a synthetic client; nothing reaches Google.
- The integrations page suggests services the company IdP already lists: a Microsoft connection's Entra inventory
  stores the applications and service principals it collected (gallery SSO apps included) with their display
  names, and a service CreMore connects
  whose name appears there, with no connection of it yet, is offered above "연동 가능 서비스" with the app names it
  came from (`GET /api/v1/provider-connections/suggestions`, stored inventory only, a hint never used for access or
  scope decisions). Okta and Keycloak people-directory connections offer the same from their own app list: the
  wizard's app list option (off unless chosen) adds a collection of its own, run at most once a day with the same
  credential, that reads the Okta organization's app integrations (`okta.apps.read`, ACTIVE and INACTIVE listed
  separately) or the realm's clients (`view-clients`, the realm's built-in clients left out). Of each app only its id,
  label or name, catalog name (`app_slug`) or client ID (`client_id`) and state are kept, as an `installation` that
  the people directory and the departed-owner check never read; credentials, settings and, before Keycloak 26.8.0,
  the client secrets `view-clients` returns are never read out of a row, and Okta's client secret endpoint is never
  called. The permission check asks for each scope with its own token, and Keycloak's checks `view-clients` by looking
  up the public account console and admin CLI clients alone. A list it cannot read never makes the people listing
  partial, and a list switched off suggests nothing. The departed-owner check now reads a person's absence only from a
  run whose user listing proves it complete, so a people collection switched to the app list departs nobody; the
  departed-owner page leaves app lists out of its IdP sources.
- On a team install (`AUTH_MODE=oidc`) the people directory is the IdP people sign in with (owner decision
  2026-10-02): a connection that reads people must be the same Okta organization, Entra tenant, Keycloak realm or
  Google Workspace as `OIDC_ISSUER_URL` names. Each IdP's onboarding module says what an issuer names
  (`sign_in_target`). Making the connection, starting its people collection and turning a stopped one back on refuse
  any other (`409 PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP`, or `PEOPLE_DIRECTORY_SIGN_IN_IDP_UNKNOWN` for an issuer no IdP
  CreMore reads people from names), and the coverage API no longer re-points the collection a connection made to
  another directory or turns it back on behind its connection (`409 PEOPLE_DIRECTORY_BELONGS_TO_PROVIDER_CONNECTION`).
  A Google issuer names no Workspace, so the Google Workspace people directory already reading people sets the domain
  (an abandoned draft does not). A directory made before the switch keeps
  running and is flagged (`sign_in_problem`, "Needs attention" in the console). GitHub's identity link is exempt. The
  catalog's `sign_in_idp` lets the console open the sign-in IdP filled in from "Directory sync" and close the others
  with the reason. A single operator's install takes any directory. A Keycloak address is now kept as the collection
  keeps it (host in lower case, no default port, no path: `KEYCLOAK_ADDRESS_INVALID`). An Okta org authorization
  server on a custom domain is not recognized.
- Google sign-in gets its console roles from Workspace groups (owner decision 2026-10-02). A Google ID token carries
  no groups claim, so on a team install whose issuer is `https://accounts.google.com` the role groups
  (`OIDC_*_GROUP`, set to group addresses) are read from Google Workspace instead. The worker reads their members,
  people in groups inside them included, every five minutes through the Google Workspace people connection
  (`members.list`, with a token holding `admin.directory.group.member.readonly` alone) and keeps only keyed digests
  of the addresses. The API gives a role to a token whose verified address belongs to that Workspace domain (`hd`)
  and to a role group, comparing ASCII addresses only. It publishes which groups it maps and never opens a credential.
  Each group is read on its own, so one that cannot be read grants nothing and holds no other back. When no group can
  be read the last membership is kept for an hour; a cause on this side (no people connection, a credential that
  cannot be opened, a delegation, admin or key Workspace no longer accepts) ends it at once. Settings > Sign-in says
  why (`role_groups` of `GET /api/v1/settings/sign-in`). Before any read, and after that hour, nobody gets a role. An
  owner approval link opens, with Google sign-in, only for a verified account of that Workspace.
- A GitHub token's owner is linked to the IdP person for Enterprise Managed Users and enterprise SAML too (owner
  decision 2026-10-02, "IdP로 잇는 방법 추가"). With the target's enterprise named on Enterprise Cloud, the GitHub
  people-directory plan offers "read the enterprise's SSO identities instead of the organization's" (on by default
  on GHE.com, which has managed users only and so needs the enterprise from the start); one source applies to an
  organization, never both. It reads the enterprise's SAML or OIDC provider (`enterprise.ownerInfo`
  `externalIdentities`) with an enterprise owner's classic PAT (`read:enterprise`): each login (for managed users
  `handle_shortcode`) with the SCIM user name and emails the IdP provisioned it with. The matching values are kept as
  keyed digests and link exactly to the IdP person's login or email; with people details on (the default) the name
  and email are also kept for display. A managed login is never derived from the IdP user name, since the login
  GitHub's normalization computes can be someone else's. The organization's SAML SSO identities now need `read:org`
  only (GitHub's schema: `read:org` or `admin:org`). The permission check also asks whether the token's user owns
  the organization (`viewerCanAdminister`) and the enterprise (`ownerInfo`), each only of a token holding its
  scope: `NOT_AN_OWNER`, or `TARGET_NOT_VISIBLE` when GitHub hides it (not a member, or not authorized for SAML
  SSO); the console counts the chosen source's scope only, and the wizard counts and sends only the options the
  edition and target offer. A slug or login GitHub does not know reads `GITHUB_IDENTITY_ENTERPRISE_NOT_FOUND` or
  `..._ORGANIZATION_NOT_FOUND`. Onboarding descriptors gain `unless` (a permission needed only while a bool plan
  choice is off or not offered) and `edition_defaults` (a plan field's default per edition). Verified with synthetic
  responses only.
- A token that expires (renewal `EXPIRES` with a secret field: Atlassian organization API keys, Bitbucket and
  Confluence tokens, PATs -- not AWS Identity Center's sign-in) takes the date it was made with in the wizard's
  sign-in step, unless the provider reports one. The date (the end of that day where the admin is, as on the
  Operations page) is stored as the operator expiry of every owned record that takes one: after a new connection
  starts collecting, or together with a replaced token (a token replaced without a date clears the old one); a
  record it could not be saved on is a warning on the done step, never a failed start. The row and the
  notification bell warn 14 and 3 days ahead ("인증 만료 N일 전", once per connection). A connection not read yet
  (`UNKNOWN`) is now `EXPIRING` within those days as well. Atlassian's services connect one after another: the done
  step of a new Confluence, Bitbucket or organization connection offers the ones not connected yet, once the
  exposure scan scope is saved. A Vault/OpenBao connection that logs in with its own token now counts as renewed
  by hand (it counted as renewing itself when the installation's secret store used Kubernetes auth), so its
  entered expiry is kept.
- Okta: CreMore makes the service app's key (auth method `made_key`, first in the wizard). The admin enters the
  client ID and presses "키 만들기"; a 2048-bit RSA key is made, its private JWK sealed at once, and only the public
  JWK (kid = RFC 7638 thumbprint) is kept in `target.generated` and shown to paste into the app (General -> Client
  Credentials -> Add key), with the steps to grant okta.users.read and the Read-only Administrator role. The
  private key never passes through the admin's screen or clipboard. Entering a key Okta generated stays available.
  A key (or Microsoft certificate) made again keeps the earlier one's public name (`previous`: kid or thumbprint),
  because the provider keeps it valid until it is removed there: the setup steps say which one to deactivate and
  delete, and the audit note carries both names. Records that could not move to a new credential (`not_updated`)
  now show in the wizard. The Okta steps ask for a role that only views users (Read-only Administrator only where
  custom roles are not available).
- Slack: the wizard's setup steps make the organization's admin app from a manifest link
  (`api.slack.com/apps?new_app=1&manifest_json=`): user scope `admin.apps:read` (and `auditlogs:read` only with the
  audit log option), organization-wide install (`org_deploy_enabled`, with the one bot scope `team:read` it needs),
  token rotation off; then install it on the organization (the Owner, for audit logs) and enter the user token.
  A connection that already holds a token is told to add `auditlogs:read` to that app instead. A permission may name
  the bool plan option it serves (`option`, validated by the catalog): the check still answers it, and the console
  leaves it out of the needed permissions and the missing count while the option is off, so a Slack connection
  without the audit log option no longer reads as missing a permission.
- Confluence Cloud connects as an organization service account (auth method `service_account`): the admin enters
  the OAuth 2.0 client ID and secret, which are sealed; the worker takes 60-minute access tokens with the client
  credentials grant and sends every read to the Atlassian API gateway
  (`https://api.atlassian.com/ex/confluence/{cloudId}` plus the site's own path), the site being asked only for its
  cloud ID (`/_edge/tenant_info`, unauthenticated). The check reads each scope the account needs
  (`read:space`, `read:page`, `read:attachment`, `read:content-details` on Confluence); the wizard's steps name them.
  A worker process shares one token per client across the scan's page tasks, tells a refused client
  (`ATLASSIAN_OAUTH_TOKEN_REFUSED`) from an unanswered one (`ATLASSIAN_OAUTH_UNAVAILABLE`, via the new `retryable`
  flag of `cremore.oauth_client`'s `OAuthTokenError`, still a `ValueError("OAUTH_TOKEN_FAILED")`) and waits a minute
  after a failure; the cloud ID lookup and the grant count against the scan's request budget. The envelope becomes a
  token only for a Confluence source. The `token` method is unchanged.
- GitLab tokens rotate themselves (renewal kind `ROTATES`): with the `self_rotate` (or `api`) scope the worker reads
  the token's expiry once a day and, in the last third of its life, takes its successor from GitLab's self-rotate
  (group, project or personal endpoint; a 90-day token, 30 days when the instance refuses that). The successor is
  sealed at once, every record follows it and approved scan scopes carry over. Because GitLab revokes the old token
  at once and a rotation retried with a revoked token revokes the whole token family, the attempt is marked before
  it starts, the token is asked about itself first, only a clear refusal moves on, and an interrupted
  (`RENEWAL_INTERRUPTED`) or uncertain (`GITLAB_ROTATION_UNCERTAIN`) rotation is never tried again with the old
  token -- the row asks for a new token. The check lists `self_rotate`; a new credential clears the renewal record.
- GitHub App made on GitHub from the wizard ("GitHub에서 만들기"): CreMore writes a private, webhook-free manifest
  with only the read permissions the chosen features need; the organization owner presses Create and Install on
  GitHub. The API alone exchanges GitHub's code for the App ID and private key (the client and webhook secrets are
  never kept), finds the installation on the organization with the App's JWT instead of trusting the redirect, and
  stores the same sealed credential typed values would make, then asks for the check. The flow is bound to the admin,
  a browser key and GitHub's state; the code is exchanged once. Typing an App's values stays available.
- One Microsoft connection ("Microsoft", provider `azure`): a single app registration reaches Entra ID (app secrets
  and certificates, and people -- the separate Entra ID people connection is no longer offered; existing ones keep
  running), Azure (subscription, storage keys, Key Vault, blobs) and an Azure DevOps organization connected to the
  tenant (repositories and the organization's PATs, instead of a personal access token). The recommended sign-in is a
  certificate CreMore makes (`generated` methods, `generate` in the onboarding module contract): only the public
  certificate is shown (`target.generated`) and uploaded; collections sign in with `private_key_jwt` and one sealed
  envelope. The worker renews it 60 days before expiry with Microsoft Graph `addKey` (proof of possession signed by the
  current key), re-points every record, re-checks, and removes the old certificate a day later (`removeKey`);
  `checks.renewal` says how it went and the row asks for attention when it failed or the certificate expired. The wizard
  makes the certificate, shows its thumbprint and validity, and fills setup steps with `az` commands (app registration,
  certificate upload, Graph permissions and admin consent, Azure roles, Azure DevOps). The inventory check now asks for
  Organization.Read.All, which the Entra app inventory needs to confirm the tenant. Catalog `when` values take `"*"`
  (any value set) and descriptors may name `replaced_by`.
- Machine identity from the company IdP, set in the dashboard ("기타 설정 → 기계 신원"): the IdP client-credentials
  app (the secret sealed, never returned) and the clouds that trust it -- AWS through an IAM role
  (`AssumeRoleWithWebIdentity`), GCP through a workload identity provider (an external-account configuration the
  process writes), Azure through an app registration's federated credential, Vault/OpenBao JWT logins through
  `idp-<name>` token files. Every API and worker process keeps the tokens current itself (no refresher container,
  overlay or environment variable), points the SDKs at them only once a token exists and gives a turned-off cloud
  its own values back, and reports per token its state and non-secret claims. "Fetch a token now" and the setup
  steps (IAM OIDC provider and role, workload identity pool and provider, federated credential, Vault JWT role)
  are filled from those claims. The AWS, GCP ADC, Azure/Entra workload identity and Vault JWT sign-in steps offer
  it among their setup steps. Changes are audited as `MACHINE_IDENTITY_CHANGED`.
- Console scan targets: one window for every provider (integration rows, the row menu and the logs page) lists what each
  place of an exposure scan can read -- an AWS account's buckets, a source's repositories, pages or databases -- with search,
  kind and "chosen" filters, lets an Admin choose only listed readable resources and narrow them (bucket and Blob container
  prefixes to read or skip, a repository's branch and paths, TFVC paths, a Notion page with its subpages, a Notion
  database's chosen rows), catches the server's refusals before saving, and reviews the choice with its schedule and reason
  before "Save" or "Save and scan now" (exact ids against the catalog snapshot seen; a busy scan slot saves only).
- The connect wizard's sign-in step has the same parts for every provider: method tabs, fields, hint, setup steps, "Test
  connection" and its result, permissions. AWS lost its own panels: CreMore's AWS identity is a hint line, "Test
  connection" approves it when none is approved or it changed, sign-in problems read as a check result with the fix, and
  the policy and each account's member role are setup steps.
- Console departed owners ("퇴사자 Credential"): the credentials people the IdPs show as gone left behind, by verdict,
  with the person named from the IdP directory (`GET /api/v1/people` now lists every merged IdP user reference as
  `refs`), the departed people and their linked accounts, and the login-only links an Admin confirms or rejects (a
  decided link leaves the candidates and the summary count at once). An Admin runs the check now; a departed person's
  AWS access key is disabled through the same plan window (disable only, reason `OWNER_DEPARTED`). A departed owner's
  key reads masked like every other key (`AKIA••••MNOP`).
- Console action approvals: every AWS key action plan (disable, delete, prepare and publish a rotation), key rotation
  job, management action and ticket whose playbook needs an independent Admin, in one queue with what waits for an
  approval, an execution or a recheck (`GET /api/v1/action-plans` lists every credential's plans). A record opens with
  the step this person may take: approving binds the plan's content hash (a single-operator install re-confirms its own
  plan), execution follows the installation switches, a rotation and a management action wait for a second operator,
  and a ticket for an Admin other than its author and last editor. The credential panel's remediation tab lists an AWS
  access key's plans and requests a new one with its operational review (change window, evidence references, consumer
  confirmations) and, for a rotation, the allowed Secret. A UUID-shaped actor reads as "User" and its first eight characters.
- The same context names the last editor of an exposed Notion page (the page's `last_edited_by`, named through the
  users API when the integration may read user information) and of a Confluence page or attachment (its current
  version's author), and the last commit or changeset that changed an exposed Bitbucket (Cloud, Data Center) or Azure
  DevOps (Git, TFVC) file, each read in the connection's own workspace, space, project or organization only. These
  hosts have no CODEOWNERS file, and no member list is read for them.
- Slack joins the integrations (issuance inventory, Enterprise Grid; `slack/backend/cremore_slack_provider/`), written
  fresh from Slack's public documentation. An organization admin's user token lists the apps the organization or one
  workspace approved (`admin.apps.approved.list`); each app is a bot token, a user token and an incoming webhook row as its
  scopes' token types say. The optional audit log (last 90 days, `auditlogs:read`) gives whether an app is installed or
  removed, its install date and installer, and the apps installed outside the approved list. The approved list does not
  say an app is installed, and Slack returns no token value, webhook URL or token use, so those stay empty. The wizard's
  check asks `auth.test`, the approved list and the audit log; Slack's `ok: false` refusals read as codes.
- An active integration's plan can change: `PUT /api/v1/provider-connections/{id}/plans/{purpose}` applies
  what changed between the old and the new plan to the collections it describes from their next run (keeping
  their credential references, edits made on them since and whether they run), creates what only the new plan
  describes (a collector token once), turns back on what an earlier change turned off and turns off, never
  deletes, what only the old plan described; a collection two purposes share follows either plan. The console
  wizard edits a collecting feature's credential types, options and schedule and saves them this way.
- The AWS integration's sign-in step shows the AWS identity the API and the worker run as, how to fix a missing
  sign-in and the permission it needs, and an Admin approves it there before the connection test; AWS has no
  screen of its own.
- A collection the store refused while a feature was activated returned an error without its code; the
  refusal now reads as the store's code.
- The dashboard proxy passes a `204` answer through; it used to report such a delete as `502`
  (the API had already carried it out).
- Console tables keep the design's row height: the design is drawn in quirks mode, where a table does
  not take the page's line height.
- Built-in detectors can be turned off by an Admin (`PUT /api/v1/detection-engine/detectors/{id}`).
  Scans leave them out from the next rule refresh and the detection digest changes, so cached results
  and vault comparisons follow; exposures a turned-off detector found are not removed by rescans.
  The customer-side `cremore-coverage` hasher compiles the same detectors. `GET /api/v1/detection-engine`
  adds each detector's category, keywords, match strategy, patterns and on/off state.

### Renamed to cremore

Everything that could still be renamed before the first public release is
`cremore`: the Python package and distribution, the console scripts
(`cremore-api`, `cremore-worker`), the Helm chart and its resource suffix
(`<release>-cremore-api`), the PostgreSQL database and role, the CloudFormation
stack onboarding suggests, the container images, the dashboard proxy's
environment (`CREMORE_API_URL`, `CREMORE_AUTH_MODE`, `CREMORE_API_TOKEN`,
`CREMORE_ALLOWED_HOSTS`), the browser storage keys, the oauth2-proxy cookie, the
OIDC group defaults, the detection engine name (`cremore-native`), the risk
policy version and the UUID namespaces derived from a prefix.

Values that leave the installation or are written to the database moved with
them: the STS role session names a provider records in CloudTrail, the
credential fingerprint and risk digest domains, and the action-plan semantics
revision. Changing those domains makes earlier digests unreproducible.

Nothing migrates from the old names, because nothing was published under them.
A database volume or a member-account stack created against a pre-release
checkout does not line up with this one; start those again.

### Also in this release

- The three read-only AWS investigations, the scan triggers, the auto-triage
  policy and the S3 Inventory bindings are all switched and configured in the
  dashboard; the environment only allows or hard-locks them. Retired variables
  are named at start-up rather than ignored.
- Every refusal an operator can reach carries a stable code and is read in their
  language; a test holds the API and the dashboard to the same list.
- `cremore/api/no_raw_secret_test.py` seeds a finding whose secret it knows and
  reads every GET route the API registers, so the product's central promise is
  enforced rather than spot-checked.
- `cremore/cli/` is covered: `build_app` and `build_worker` are exercised without a
  database, AWS or a server, which is where a service handed over in the wrong
  shape used to fail silently inside a poll loop.
- The dashboard is no longer one 8,000-line file. Ten modules now, with the AWS
  accounts screen in its own.
- The scan wizard keeps its step list and buttons on screen instead of scrolling
  them away above and below a step that is several screens tall.
- Atlassian Cloud's OAuth client count is asked for the discovered service
  accounts, at most 100 IDs a request, as Atlassian support confirmed
  (ECOHELP-167001); the empty POST it sent before is rejected. The count is
  compared only with those accounts' listed clients, and the top-level OAuth
  array is read as a confirmed shape whose paging is still unverified.
- The console runs on Next.js 16.3.8, the current release, which fixes
  GHSA-vcvr-r3jv-pc5j in `next/og` (CreMore does not import it). The web
  dependency audit (`npm audit --audit-level=high`) passes again.
- A provider response in a charset that refuses replacement characters (`idna`) is read as UTF-8 instead of failing
  the request (`cremore/http_client.py`).
- Rescanning one location of an Azure DevOps repository, a Confluence page or a website is no longer refused when it is
  confirmed (`SCOPE_PLAN_STALE`): the recheck of a confirmed plan expects the ref the rescan chose for every source
  that scopes by path, not only GitHub, GitLab and Bitbucket. A rescan under a scope entry that cannot bound a read
  says so (`WEBSITE_SCOPE_PATH_INVALID`), and an event's paths are judged by the same test as a rescan's.

### Settings an operator can reach without editing the deployment

An installation that cannot edit its `.env` -- a security officer running the
open-source build inside a company, or anyone on a cluster who is not the
platform team -- could not use features the dashboard showed them. Each of these
now follows one rule: the environment ALLOWS a feature (the default) or
hard-locks it off, and the switch itself is an Admin's, recorded with who
changed it and when.

- Auto-triage of learned false positives: `LEARNED_FP_MODE` plus
  `GET`/`PUT /api/v1/settings/learned-false-positives` (switch, similarity
  threshold, sample floor, confidence ceiling). Each `LEARNED_FP_*` value still
  pins its own field. `LearnedFPService` reads the policy live, so a change
  reaches a running worker.
- The three read-only AWS investigations -- observed use, IAM potential access,
  Secrets Manager inventory and metadata: `IAM_POTENTIAL_ACCESS_MODE`,
  `AWS_USAGE_LOOKUP_MODE`, `AWS_SECRETS_INVENTORY_MODE` plus
  `GET`/`PUT /api/v1/settings/aws-investigations`. All three default off, so an
  upgrade adds no AWS calls until somebody asks for one, and an analyst can turn
  one on mid-investigation. Every path that can reach AWS reads the switch per
  request, including the worker's privilege scoring and both inventory routes.
- Scan triggers: `SCAN_SCHEDULES_MODE` and `SCAN_SQS_MODE` plus
  `GET`/`PUT /api/v1/settings/scan-triggers`, which also carries the queue URL,
  the approved profile a trigger is bound to, and the acknowledgement that the
  queue is CreMore's own. `GET /api/v1/settings/scan-triggers/bindable-profiles`
  lists exactly what a PUT accepts, so a binding is chosen rather than typed as a
  UUID. A trigger switched on but not fully configured reads as off and says what
  is missing instead of failing when a message arrives.

### Connection credentials can be re-keyed

`FINGERPRINT_KEY` did two jobs that want opposite things: it keys stored
fingerprints, which must never rotate or every recorded match is orphaned, and
it was also the master that sealed every connection token, which must be able to
rotate. The sealed format carried no key identifier either, so an installation
could not hold two keys at once -- changing the master made every stored
credential unreadable at once, with nothing to say which key was missing.

New credentials are sealed as `sealed:v2:<key_id>:...`, where `key_id` is a
16-hex HKDF name for the master that sealed it (a KDF output, not a hash of the
key) and is authenticated with the ciphertext, so it cannot be edited to point at
another key the installation holds. `SEALING_KEY` sets that master;
`SEALING_KEY_PREVIOUS` (comma separated) lists keys that may open a stored
credential but never seal a new one. A credential that cannot be opened names the
key id it needed, because an operator has to know which key to restore.

**Nothing changes for an existing installation.** With `SEALING_KEY` unset the
master is derived from `FINGERPRINT_KEY` exactly as before and `sealed:v1:`
credentials keep opening; only newly sealed ones record which key sealed them.
Set `SEALING_KEY` to stop `FINGERPRINT_KEY` being the token master, and rotate by
moving the old value into `SEALING_KEY_PREVIOUS`.

### The sealing master can live in AWS KMS instead of on this disk

`SEALING_KMS_KEY_ID` names a customer master key and `SEALING_KEY_CIPHERTEXT`
holds a data key encrypted under it, so what an installation keeps is a
ciphertext. A copy of `.env` or of the database is worth nothing on its own:
recovering the master takes `kms:Decrypt` on that CMK, which is granted to the
workload identity the process already runs as -- an EC2 instance profile, an ECS
task role, EKS IRSA, or an operator's `aws sso login` session. Produce one
without the plaintext key ever existing outside KMS:

    aws kms generate-data-key-without-plaintext \
      --key-id <cmk> --key-spec AES_256 --query CiphertextBlob --output text

The CMK is named on every Decrypt rather than left to the ciphertext, so a blob
swapped for one encrypted under a different key is refused instead of quietly
opening; the client is read-only wrapped, so this path can call `Decrypt` and
nothing else; a CMK that returns fewer than 32 bytes is refused rather than used
as a weak master; and failures report a fixed code instead of the SDK's detail.
KMS is reached when a credential is sealed or a worker starts, never per scan,
and never at start-up -- a worker whose connections are all `vault://` needs no
sealing key and should not fail to boot when KMS is unreachable.

Compose passes the settings to both the API and the worker from `.env`; the
chart takes `config.sealing.*` for the KMS ciphertext and
`applicationSecret.sealingKey` / `sealingKeyPrevious` for a hex master held in
the existing Secret. Setting none of them changes nothing.
[docs/CREDENTIAL_ROOTS.md](docs/CREDENTIAL_ROOTS.md) says which to choose.

### Or in the Vault an installation already runs

`SEALING_KEY_VAULT_PATH` (`config.sealing.vaultPath`) reads the master from a KV
v2 path under the configured mount, whose `SEALING_KEY_VAULT_FIELD` -- `key` by
default -- holds 32 or more random bytes as hex:

    vault kv put secret/cremore/sealing-key key="$(openssl rand -hex 32)"

This is the one case where the API is wired into the secret store. The worker
resolves every connection's `vault://` reference; the API resolves none, and
until now received no store access at all. But the API is what seals a
credential an operator types into the dashboard, so it has to read the same
master the worker later opens it with. The deployment keeps that narrow: in
Compose `SEALING_VAULT_TOKEN` is the API's token and `SECRET_STORE_TOKEN` the
worker's, and in the chart `secretStore.kubernetes.sealingRole` (or
`sealingTokenKey`) lets the API log in under a policy that reads only the
sealing path, while the worker keeps the one that reads connection references.
A path whose field is missing, is not hex, or decodes to fewer than 32 bytes is
refused rather than used; a sealing path configured without a store reachable
from this process is refused at start-up rather than at the first credential.

Rotate by writing a new master and moving the old path into
`SEALING_KEY_VAULT_PATH_PREVIOUS`, which opens stored credentials but seals no
new one. An installation with Vault can also skip sealing entirely by storing
the provider token in Vault and giving the connection a `vault://` reference,
which has always worked and needs no master at all.

The worker's Vault client construction moved into
`cremore.secretstore.vault.kv_from_settings`, so both processes build one the
same way rather than from two copies of the same twenty lines.

### Or in this computer's OS keychain

An operator with neither AWS nor Vault can still keep the master off disk. A
container cannot reach the host's DPAPI, Keychain or Secret Service -- those are
Win32 and Security.framework calls, and the containers are Linux -- so the value
is exported into the environment for one `docker compose up` instead. Compose
prefers the shell environment over `.env`, which is what makes this work and is
now pinned by a test, because a Compose that ever preferred the file would
quietly go back to sealing under whatever `.env` holds.

README "4. (선택) 봉인 키를 디스크에 두지 않기" has the command for each platform:
`security` on macOS, `secret-tool` on Linux, and DPAPI through
`ConvertFrom-SecureString` on Windows, all built in except libsecret-tools.
Windows still leaves a file, but it holds no plaintext and only that Windows
account can decrypt it.

The limit is worth stating: this has no unattended restart. Somebody has to be
signed in and run the command. An installation that uses AWS should prefer the
KMS root above, which restarts unattended and behaves the same on all three
platforms.

### Removed

- **The old dashboard** and its `/demo` page: the console at `/` replaces them (see "The console is the web
  application now" above). The provider UI folders (`<vendor>/web/`) and the web's Tailwind setup went with it.
- **Registration endpoints outside the provider connection wizard**:
  `POST /api/v1/source-connections`, `POST /api/v1/connections`,
  `POST /api/v1/aws/accounts`, `/api/v1/aws/accounts/onboarding` (POST) and
  `/api/v1/aws/accounts/bulk`, `POST /api/v1/coverage/connections` and its
  `PUT`/`DELETE .../vault-token`, `POST /api/v2/coverage/connections`,
  `POST /api/v2/coverage/github/enterprise-connections` and
  `PUT`/`DELETE .../github-enterprise-audit-token`, and
  `POST /api/v2/coverage/gcp/from-source/{id}`. Reads, collection, scope selection
  and scans keep their routes. A connection's credential is changed on its
  provider connection; the collection and content PATCH routes refuse credential
  and sign-in changes with `CREDENTIAL_BELONGS_TO_PROVIDER_CONNECTION`.
- **The standalone GCP and GitLab command-line tools.** `gcp/standalone`'s
  inventory, relations, API key matching, plaintext Secret export and watcher CLIs
  (and the modules only they used), and `gitlab/standalone` entirely. The product
  collects both through the common worker; `cremore_gcp` keeps the identifier,
  value-reader and matching functions the product imports.
- **The signed event webhook (`POST /api/v1/scan-events/{profile_id}`) and its
  `SCAN_EVENTS_*` settings.** It could not accept a provider's own webhook --
  GitHub signs the body alone with its own secret and names a repository, while
  the endpoint wanted `timestamp + "." + body` signed with CreMore's key, a
  catalog root UUID and a flat path list -- so using it meant each organisation
  writing and operating a translating adapter. It was also the only route on the
  API with no OIDC or token authentication. The dedicated SQS queue takes S3
  notifications, EventBridge and CloudTrail signals with no translation, and a
  five-minute schedule covers the rest with no infrastructure.
  **Upgrade:** if you built an adapter, move that source onto the dedicated
  queue (`scanning.sqs`) or a profile schedule.

### Upgrading

- **The web console moves to `/`.** `/console` and `/demo` redirect there (a `/console` address keeps its query);
  a bookmark of the old dashboard (`/?tab=...`) opens the console's overview.
- **Start a new database.** Connections registered through the removed endpoints
  are not converted to provider connections (there is no compatibility layer
  before the first public release); connect each provider again through the wizard.
- Retired environment variables are ignored silently by the settings model, so
  start-up now names each one it finds and says what replaced it. It warns rather
  than refusing, and **what the variable used to enable follows the dashboard
  switch's own default** -- off until switched on, so an installation that was
  consuming a queue with `SCAN_SQS_ENABLED=true` stops, except schedules
  (`SCAN_SCHEDULES_ENABLED`), which are on unless switched off.
- Helm: `config.iamPotentialAccessEnabled`, `awsSecretsInventoryEnabled` and
  `awsUsageLookupEnabled` become `...Mode`; `scanning.schedulesEnabled` becomes
  `scanning.schedulesMode`; `scanning.sqs.enabled` becomes `scanning.sqs.mode`;
  `scanning.events` is gone. `scanning.sqs.queueURL`, `profileId` and
  `dedicatedAcknowledged` are now optional pins rather than required together.

- Multi-account AWS onboarding no longer needs `AWS_ONBOARDING_TEMPLATE_URL` or
  `AWS_SCANNER_PRINCIPAL_ARN` (config and Helm no longer require them as a pair).
  An Admin approves the AWS identity the API and worker run as
  (`GET`/`PUT /api/v1/aws/scanner-identity`): IAM Identity Center permission set
  (any IdP), IAM role or IAM user; root is refused and STS session ARNs are never
  stored. Each account gets a CLI deploy command (and a quick-create link when a
  template URL is set); one AWS provider connection registers many at once.
- `member-account-role.yaml` adds `TrustedPrincipalType` (`CentralRole` default
  keeps existing stacks, `IamRole`, `IamUser`, `IdentityCenter`),
  `TrustedPrincipalArn`, `IdentityCenterAccountId` and `TrustedPrincipalPattern`.
  The API image packages the template (`GET /api/v1/aws/onboarding/template`).
- Role validation runs in the worker (`aws-role-check` job) and records
  `validation_detail`/`validated_at`. The worker reports its AWS identity every
  minute; AWS tasks wait with `AWS_LOGIN_REQUIRED` (sign-in expired, including
  mid-scan) or `AWS_SCANNER_IDENTITY_CHANGED` without spending retry attempts and
  resume from checkpoints. Compose sets `AWS_EC2_METADATA_DISABLED=true`.
- AWS investigations and key actions now run in the account they concern.
  Observed use, IAM potential access (API and worker), Secrets Manager metadata
  and inventory, key disable/delete and their rechecks open a session through
  the account's member role (or an explicit `RUNTIME_IDENTITY` account) and
  refuse with a safe code (`ACCOUNT_NOT_CONNECTED`, `ACCOUNT_OWNER_UNKNOWN`,
  `REVALIDATION_REQUIRED`, `AWS_IDENTITY_CHANGED`, …) instead of calling AWS with
  the process identity. Previously another account's key could be recorded as
  `COMPLETE` with no events, and a delete recheck could read `ABSENT` in the wrong
  account. **Upgrade:** register the runtime identity's own account (`access:
  RUNTIME_IDENTITY`) to keep investigating it; every account is revalidated
  automatically; the service factories passed to `create_app` now receive the
  account session.
- Validation results are purpose-scoped (`scanner`, `remediation`) and stored
  compare-and-set under `<access revision>:<approval revision>`; a late result
  from an older revision is discarded, a trust change only invalidates the
  purposes that trust it, and account `PATCH` can no longer set
  `validation_status`. The worker re-queues stale checks and waits (instead of
  recording `INVALID`) when its sign-in expired.
- Separate remediation identity: `AWS_REMEDIATION_PROFILE`,
  `GET`/`PUT /api/v1/aws/remediation-identity`, and member template parameters
  `RemediationTrustedPrincipalType`/`Arn`/`IdentityCenterAccountId`/`Pattern`
  (default `CentralRole` keeps existing stacks).
- Rotation runs only in the `RUNTIME_IDENTITY` account with a same-account
  secret and is refused before any AWS call otherwise; PUBLISH requires the
  authorization pin recorded at PREPARE (`access_pin`), so rotations prepared
  before this release cannot be published.
- Usage snapshots record `collected_account_id`/`collected_via`; older ones are
  served as `ACCOUNT_UNVERIFIED`. IAM privilege signals record the evaluated
  account, and a one-time rescore marks scores from unproven evaluations
  `PRIVILEGE_ACCOUNT_UNVERIFIED` (prior score kept).
- Scanner role validation no longer falls back to the calling identity's
  `GetCallerIdentity` when `AssumeRole` returns no assumed user.
- Finding detail and list now return the fields the dashboard renders, all from
  saved evidence: `credential.governance` (verification outcome at check time,
  provider owner, owner-account usage), `credential.credential_metadata`
  (principal, expiry, provider-reported scopes; for AWS keys, key creation and
  status from `iam:ListAccessKeys`, last use, CloudTrail use and the IAM policy
  evaluation, only when collected in the owner account), and per exposure
  `detection_details` (explainable model score, policy and per-axis points) and
  `source_location` (line and a link opening the S3 console object, the GitHub
  blob at the scanned commit and line, or the Notion page with the viewer's own
  provider access). Previously these panels showed "unavailable" and no score.
- GitHub and Notion verification record the owner login/id/type (Notion bot
  workspace) and GitHub's token expiry header.
- GitHub Enterprise Server: a GitHub connection can carry an enterprise host
  (`enterprise_host` on registration, stored in config). Verification, the
  capability probe, the resource catalog/scan and the finding's open-original
  link all use that host's API (`https://HOST/api/v3`) and web base, instead of
  hardcoding github.com. A discovered token is checked against the host of the
  connection it was found on. With `CREDENTIAL_CROSS_HOST_VERIFICATION=enabled`
  and `GITHUB_ENTERPRISE_HOSTS`, a token rejected by that host is retried on the
  other registered hosts (and github.com) so a token that lives elsewhere is
  confirmed rather than shown inactive; when a lone host rejects and other hosts
  exist but cross-host is off, the verdict is inconclusive ("rejected on this
  host, others unchecked"), never a false "inactive". The `credential-check`
  action also uses the connection's host.
- Capability probing and cross-host verification are now dashboard switches
  (`GET`/`PUT /api/v1/settings/capability-probe` and `.../cross-host-verification`),
  read at the start of each scan like the verification switch. Both default off;
  the env `*_MODE` value allows them (default) or hard-locks them off, and both
  require verification. The scan reads the live switches through a per-scan
  verifier config, so an Admin turns them on or off without restarting the worker.
- The Scans tab now lists connection scan history (S3/GitHub/Notion runs) as
  expandable cards showing duration (with detection-engine seconds), objects
  scanned, findings, failures, what was excluded (unchanged/reused, unsupported,
  archived, submodules), bytes and requests, and the run mode. `/api/v1/scan-runs`
  carries this coverage detail. The scan dialog's per-scope run list is collapsed
  and points here.
- A run that is queued or running shows real progress from its tasks
  (`done/total`) as a percentage gauge, and — new — a **hold banner** when the
  run is parked waiting on an external condition (AWS sign-in expired, identity
  changed, account revalidation, scan budget). The banner names the reason in
  plain language, says what the operator should do, and shows the next retry
  time and how many tasks are waiting, instead of only showing "running".
  `/api/v1/scan-runs` exposes `progress` and `hold` for active runs (backed by a
  new `TaskStore.run_states`).
- A scan run will not start a duplicate: if the same profile version is already
  queued or running in the same mode, the run request returns that active run
  instead of scanning the same scope again (in addition to the existing
  per-plan idempotency).
- Optional capability probe: because a GitHub fine-grained PAT and a Notion
  integration do not report their permissions, `CREDENTIAL_CAPABILITY_PROBE_MODE=enabled`
  (off by default; needs verification enabled) makes a few fixed read-only
  calls with a *verified* discovered token to record what it can reach
  (GitHub: read repositories/organizations/gists; Notion: read shared content,
  with a bounded count). Each probe is stored as ALLOWED/DENIED/UNREACHABLE and
  shown in finding detail; the token is used only after it verifies, never for a
  write, and the count is a floor, not a full inventory.
- A GitHub connection scoped to a personal account name now lists and scans
  all of its repositories, like an organization. The token's own account
  includes private repositories (`/user/repos`); another user's account lists
  only public ones and is marked incomplete. Previously only organizations
  worked, and the dashboard form (which accepts no `owner/repo`) could not
  register a personal account at all.
- AWS keys: the usage refresh also reads the identity policies IAM actually
  grants the verified principal (user inline/managed, group, role behind an
  assumed-role session, permissions boundary) with the scanner session in the
  owner account, never with the discovered key. Finding detail shows each
  policy's statements (effect, actions, resources, condition keys; condition
  values are not stored) and a headline such as "every action explicitly
  denied" or "administrator level". **Upgrade:** update the member/single
  account stack; the scanner role gains `iam:List/GetUserPolicy`,
  `iam:ListAttachedUserPolicies`, `iam:ListGroupsForUser`,
  `iam:List/GetGroupPolicy`, `iam:ListAttachedGroupPolicies`, `iam:GetRole`,
  `iam:List/GetRolePolicy`, `iam:ListAttachedRolePolicies`, `iam:GetPolicy` and
  `iam:GetPolicyVersion` (read-only). Without them the view reads `FAILED`
  with `AccessDenied`.
- The same place found through overlapping connections (an account and one of
  its repositories) is one location: the findings list count, the detail's
  location list (with `source_connection_ids`) and the risk model's
  occurrence count use distinct `source_type`/`resource_name`/`location`/
  `object_version`. Previously each connection added a duplicate location and
  raised the score with `multiple_occurrences`. Exposure rows stay per
  connection; a one-time rescore recounts stored scores.
- Scan budget: a root that runs out of its share takes the unused shares of
  finished sibling roots (the run total is unchanged) instead of stopping early.
- Dashboard: the finding kicker reads "Plaintext credential exposure", the
  location panel drops coordinate and masked-context jargon, AWS keys show the
  IAM policy evaluation in the metadata grid, and the scan scope review shows
  each bucket's whole-object checkbox outside the collapsed options. Common
  credential types (GitHub/Notion tokens, hardcoded passwords, API keys,
  connection strings) have localized names, and metadata of a rejected or
  unsupported check reads "not returned"/"not supported" instead of "not collected".
- `DEPLOYMENT_MODE` / Helm `deploymentMode` are removed. Start-up and chart
  validation now enforce only CreMore-owned guarantees: a 32-byte
  `FINGERPRINT_KEY` in every installation (previously optional with
  `AUTH_MODE=local`), no built-in API token and well-formed values. API TLS, database
  `sslmode`, OIDC issuer scheme, role group layout, Vault URL scheme, Ingress,
  NetworkPolicy and OIDC scopes are no longer enforced. Empty OIDC role values
  grant nothing. Existing Helm values files still install; `auth.mode: local`
  fails rendering because the chart ships only the oauth2-proxy path.
- Provider verification of discovered credentials is on by default. An Admin
  switches it installation-wide from the dashboard (`GET`/`PUT
  /api/v1/settings/credential-verification`, stored in the new
  `installation_settings` table and read when each scan starts).
  `CREDENTIAL_VERIFICATION_MODE=disabled` locks it off; the
  `CREDENTIAL_VERIFICATION_ACKNOWLEDGED` setting and Helm
  `verificationAcknowledged` value are no longer used. The test suite forces
  verification off so tests never contact providers.
- Connection tokens can be entered directly (dashboard `credential_token`, API
  `token`) and are sealed with AES-256-GCM under an HKDF key derived from
  `FINGERPRINT_KEY`; the API returns only a `sealed:v1` marker. Vault/OpenBao
  `vault://` references keep working and are no longer required for private
  GitHub/Notion scans. Changing `FINGERPRINT_KEY` makes sealed tokens unreadable.
- Docker Compose can reuse the operator's AWS CLI login for S3 scans, including
  IAM Identity Center: set `AWS_CONFIG_DIR` (and `AWS_PROFILE`). Config and
  credentials mount read-only; only the `sso/cache` and `login/cache` token
  caches are writable so botocore refreshes sessions in place. Host paths are
  never auto-created, and `CREMORE_UID`/`CREMORE_GID` run api and worker as the
  host user on macOS and Linux. Setup commands cover Windows, macOS and Linux.
- Shared-token (`AUTH_MODE=local`) installs have one operator: an action plan may
  be self-approved after an explicit re-confirmation (`self_approval_confirmed`)
  and is recorded as `self_approved`. OIDC installs still require a different
  approver, and a self-approved plan cannot execute under OIDC.
- Security: with shared-token authentication the dashboard proxy now refuses
  requests whose Host is not `localhost`, `127.0.0.1`, `[::1]` or listed in
  `CREMORE_ALLOWED_HOSTS`. Previously a web page using DNS rebinding could read
  findings and perform Admin actions through the local dashboard.
  `X-Forwarded-Host` is not trusted for this check.
- The web image no longer ships `sharp`/libvips (LGPL-3.0): `next/image` was
  unused, so image optimization is disabled (`/_next/image` now returns 404) and
  CI checks the standalone output. Unused Simple Icons logo files were removed.
- Removed the unused `CREDENTIAL_FORCE_ACTIVE_VERIFICATION` and
  `CREDENTIAL_VERIFICATION_ALLOW_CONTENT_ENDPOINTS` settings; no verifier read
  them, and every verifier calls a fixed provider URL.
- Approved scope runs now support `BASELINE`, `DELTA`, `RECONCILE`, and explicit
  S3 `INVENTORY` modes through the existing preview/run API. Root catalogs are
  normalized and paged; selection exclusions and priorities are applied before
  content reads. Kubernetes remains optional.
- Durable root tasks add PostgreSQL SKIP LOCKED claims, leases, heartbeat,
  bounded retries, current-owner write fencing, idempotent membership and
  queued-only event coalescing. Coverage exposes stage timings and cache reuse;
  committed-object counters include retry processing, not unique global assets.
- S3 uses overlap watermarks plus failed-key retries; optional existing CSV
  Inventory comparisons are explicitly `INVENTORY_REPORT_ONLY`, do not advance
  normal root watermarks and cannot establish whole-bucket coverage.
- GitHub pins a commit, uses blob-SHA passive cache (including empty results),
  bounded tree fallback and whole-repository streaming tarballs with blob-hash
  verification/fallback. Cross-origin redirects strip authentication/cookies.
  Submodules and arbitrary compressed assets are unsupported coverage.
- Initial scans avoid oversized GitHub archive read buffers, repeated S3
  timestamp normalization and repeated adjacent-root hashing. Same-repository
  bindings are reused; distinct lease-fenced repositories remain isolated.
  Object limits, archive integrity checks and Notion consistency checks remain.
- Detection selects keyword-matching rules once per content view and reuses
  that ordered selection for masking and detection. All-candidate masking,
  decoder precedence, output caps and the passive detection digest are unchanged.
- Notion no longer folds child-page/database bodies into their parent. Children
  require independent approval and reads. Legacy `collector_epoch` observations
  require source reconfirmation; search omissions and 404 do not retire them.
  Operators may see old parent-path evidence retained until rechecked, and new
  child-path evidence only when that child is separately approved and readable.
- Exposure removal no longer auto-resolves a finding. `all_locations_removed`
  is separate from the workflow; key rotation/revocation and historical copies
  still require review. `SignatureDoesNotMatch` is indeterminate and a rejected
  verification is not proof of revocation. Stored-evidence rescoring preserves
  manual decisions and flags missing historical facts as `NEEDS_RESCAN`.
- Optional schedules, one profile-bound normalized HMAC webhook, and one
  explicitly acknowledged dedicated SQS queue are wired into the worker/API.
  Native GitHub/Notion webhook protocols are not implemented by that endpoint.
  No source infrastructure is automatically created or overwritten; S3 Batch
  Operations remains deferred.
- AWS source clients enforce exact-operation read allowlists, onboarding
  templates add source-write Deny controls, and STS scanner sessions refresh
  in memory. Archived S3 reads are skipped without restoring objects; directly
  readable `GLACIER_IR` objects are still scanned. HTTP 429 retries are bounded.
- **Upgrade action required for populated installations:** stop every API and
  worker writer, verify a restorable backup, then run the offline version-2
  identity migration. It archives duplicates, preserves both exposure reference
  paths, adds unique/index constraints and requeues interrupted jobs (terminal
  credential checks require a new check). Startup does not perform this data
  consolidation. See [the upgrade/rollback runbook](docs/SCANNING_IMPLEMENTATION.md#기존-설치본-오프라인-업그레이드).
- Implementation tests and deployment validation are distinct. See the
  [implementation checklist and verification record](docs/SCANNING_IMPLEMENTATION.md)
  for confirmed local proof and remaining external release gates.

## 0.1.0 — first Apache-2.0 release

This is the first public release. Everything in the repository is the
project's own work, distributed under Apache-2.0. See [`LICENSING.md`](LICENSING.md).

### Detection engine (`cremore/detection/`)
- 859 detectors written from provider documentation (`source_url`
  on every entry): distinctive-prefix formats, label-gated formats, and generic
  credentials (hardcoded passwords/secrets/API keys, Basic-auth URLs and
  headers, PEM private keys, password hashes).
- Linear-time regex backend (RE2) with a stdlib fallback; the catalog audit
  proves every pattern is RE2-safe, unique, and never matches trivial input.
- Confidence tiers (high / medium / low), structural validators (entropy,
  Luhn, Basic-auth decode), decoders (base64, UTF-16, escapes, HTML entities),
  false-positive policy, keyed fingerprints and masked hints — raw secrets
  never leave the engine.
- 64 provider verification rules (AWS STS SigV4 + documented read-only HTTP
  checks), off by default.

### Platform
- Evidence-based risk model v5 with explainable evidence and overrides.
- Collectors for S3, GitHub (repository and organisation) and Notion.
- Postgres-backed scan-job queue and worker; connection onboarding with
  secret-reference resolution (OpenBao/Vault KV v2).
- GitHub App installation tokens and Vault/OpenBao Kubernetes workload tokens
  are issued and refreshed in memory; legacy PAT/static-token paths remain compatible.
- Governance: assignment, acknowledge/resolve/reopen, audit trail, reviews,
  two-party management actions.
- Read-only AWS investigation (IAM potential access, Secrets Manager
  inventory) and approved two-phase AWS key rotation (PREPARE/PUBLISH).
- FastAPI service with local-token or OIDC authentication and role gating;
  Next.js dashboard on the same `/api/v1` contract.

### Deployment
- One Python container image (`cremore-api` / `cremore-worker`), Docker Compose for
  local use, and a production Helm chart (OIDC via oauth2-proxy, internal TLS,
  NetworkPolicy, typed opt-ins for every mutating capability).
- OIDC refresh-token sessions and an Admin-only operational status roll-up for
  connection authentication and queued/running/failed/partial work.
- Provider verification is gated by `CREDENTIAL_VERIFICATION_MODE` (+
  `CREDENTIAL_VERIFICATION_ACKNOWLEDGED`).

### Dependency and browser-test cleanup
- Removed dependencies the code does not use: the `uvicorn[standard]` extras
  (websockets, watchfiles, httptools, uvloop, YAML logging), `pyyaml` and
  `mypy`. The web app's dependencies are all in use and its lockfile is
  already minimal.
- Playwright is a pinned dev dependency: `npm run test:browser` runs the 16
  synthetic browser proofs in headless Chrome, and CI runs them on every push.
- Security runs actionlint over every workflow, so a workflow GitHub would
  reject (as a job-level `runner` context once did) fails loudly.
- All browser proofs hand module maps and fixtures to the page as data and
  inject only fixed loader code. Every synthetic browser proof runs green in
  Chrome; three that had drifted from the current UI (collapsed mobile
  navigation, the rescan `verify` field and its second checkbox) now match it.

### CI and container hardening
- The platform image builds on a digest-pinned Chainguard (Wolfi) Python 3.14
  pair: dependencies are installed in the `-dev` image and only the virtual
  environment is copied onto the minimal runtime (no shell, package manager
  or OS utilities, pip removed). The image scans clean for HIGH/CRITICAL
  vulnerabilities instead of carrying unpatched Debian packages.
- oauth2-proxy is built against `google.golang.org/grpc` v1.83.2
  (CVE-2026-84445).
- CI tests Python 3.12 and 3.14, fetches the digest-pinned Helm image before
  the chart test, and CodeQL runs the security-extended queries and fails on
  any security finding even where code scanning uploads are unavailable.
- Dependabot now tracks pip, the Dockerfiles under `deploy/docker` and `web`,
  and GitHub Actions.
- The platform image installs from hash-pinned lock files
  (`requirements.txt`, `requirements-build.txt` for the hatchling build
  backend) and runs `pip check`; the security workflow audits both locks.
- oauth2-proxy also takes `golang.org/x/crypto` v0.56.0 (CVE-2026-56855,
  CVE-2026-78662); the web runtime moves to a newer distroless digest.
- The web and oauth2-proxy images declare `USER 65532:65532`, and the Helm
  pods set `runAsUser`/`runAsGroup` 65532. Every workflow action is pinned
  by commit SHA.
- The repository carries no credential-shaped values: test fixtures are split
  into string pieces that join at run time, and a test scans every tracked file
  with the platform's own engine. The API has no built-in admin token
  (`AUTH_MODE=local` needs an `API_TOKEN` of at least 32 characters), and
  Compose reads `API_ADMIN_TOKEN` and `POSTGRES_PASSWORD` from an untracked `.env`.

### Dark mode
- The dashboard follows the operating-system theme, or a per-device choice
  (system / light / dark) in the header. An inline script applies a saved
  choice before the first paint, so there is no flash of the wrong palette.
- Semantic tokens have hand-tuned dark values; every other colour literal in
  the stylesheets reads a generated dark token (`web/scripts/theme-tokens.cjs`,
  OKLCH lightness mapping that keeps hue) while light mode renders unchanged.
  Vendor logos keep a light tile in both themes. A test fails when a new
  colour has no dark token.

### Dashboard redesign for security officers
- A design-system layer (`web/app/design-system.css`, tokens in
  `globals.css`) restyles the console: one cool-gray family with a single
  teal accent, severity as the only loud color, Geist for Latin text and
  numbers (Hangul falls through to Pretendard), tabular figures, quiet
  hairline panels, pill controls with press feedback, staggered entry motion
  (off under `prefers-reduced-motion`), skeleton loading, dashed empty states.
- The overview opens with a security-posture strip: open findings with a
  severity bar and legend, critical, verified-active, awaiting first review
  and latest-scan coverage, followed by the priority queue and recent scans.
  Tab summaries, the findings queue and the finding detail share the same
  primitives.
- Fixed: opening a finding detail crashed the dashboard against this API
  because `credential` was served as the stored record rather than the
  dashboard's contract (`type`, `status`, `observed_providers`,
  `secret_stored`, `source_scope`, `aws_account`, exposure `provider`/scope).

### Learned false-positive profiles (opt-in)
- `LEARNED_FP_ENABLED`: an Analyst's false-positive decision becomes one sample
  per exposure — redacted path and line-shape features only, never the match,
  identifier, hint or fingerprint. Samples aggregate per (account or
  connection, source type, detector, credential type). A profile activates
  after `LEARNED_FP_MIN_SAMPLES` confirmations from at least two analysts and
  auto-triages a repeat whose weighted-Jaccard similarity reaches
  `LEARNED_FP_THRESHOLD`: the finding moves to `FALSE_POSITIVE` with the
  profile named in its resolution and an `AUTO_FALSE_POSITIVE` audit event.
  Verified, public or above-ceiling-confidence (`LEARNED_FP_MAX_CONFIDENCE`)
  detections are never auto-triaged. Reopening an auto-triaged finding
  contradicts the profile: it is deactivated and relearned from scratch.
  `GET /rules/learned-fp` (Admin) lists profiles; `/deactivate` and `/reset`
  control them. Helm: `config.learnedFalsePositivesEnabled`.

### Scan-scope selection and exact-location rescan
- Resource catalog per connection: a metadata-only `catalog-refresh` job lists
  what the connection's own identity can see (`ListBuckets`/`HeadBucket`,
  GitHub repository metadata, Notion search) — never content. The catalog is
  filterable and cursor-paged; an approved provider reference can be confirmed
  through the connection; Notion supports an explicit title search. An empty
  or never-collected catalog is labelled as such, never as "no resources".
- Selection drafts freeze every current match of a query into exact ids;
  Admin-approved scope profiles are versioned (`expected_version`), pinned to
  the catalog snapshot they were reviewed against and to the connection's
  authorization revision; per-resource options cover S3 prefixes (an explicit
  all-objects approval is required), GitHub pinned refs and path roots, and
  Notion page boundaries / data-source rows. Exclusions always win.
- Preview builds a fixed, expiring plan (known vs unresolved roots, warnings,
  policy digest, executable flag); a run executes exactly that plan through
  per-root collectors under the byte / request / time budgets and reports
  observed coverage (attempted / succeeded / failed / skipped / bytes /
  requests, budget stops). A scoped run never retires exposures it did not
  visit. Re-submitting the same plan returns the same run.
- Finding rescan: one exposure's current location, only inside an approved
  profile of the connection it was found through, with optional provider
  verification where the deployment enables it.
- Connected AWS accounts are read through their member scanner role
  (`sts:AssumeRole` with the ExternalId), never with the worker's identity.

### Connection lifecycle, secret-manager mapping, internal tickets
- Connection credential ledger: every credential check is recorded as an
  append-only sequence of REQUESTED → CLAIMED_FOR_CHECK → TERMINAL events with
  the job status and outcome (`/source-connections/{id}/verification-history`,
  cursor-paged). Stopping the use of a connection (`/credential/revoke`)
  disables it, withdraws queued work and returns the provider's own
  revocation guidance — the platform never revokes a token at the provider.
  Blast radius lists the resources and findings reached through a connection.
- Optional secret-manager mapping: an Admin may declare an allowlisted
  Secrets Manager ARN (`SECRET_MANAGER_ALLOWED_REFERENCES`) as where a
  discovered credential is *possibly* stored; the platform only ever reads
  metadata (`DescribeSecret`, `ListSecretVersionIds`; tags and description are
  omitted by policy) and never compares values.
- Internal response tickets and playbooks (`/tickets`, `/governance/playbooks`):
  fixed review checklists per template, operator declarations only (owner,
  team, due date, evidence, optional SaaS security review) with optimistic
  versioning. A CUSTOM ticket freezes its playbook at creation — up to 12
  steps, applicability conditions that must match the saved finding, and an
  INDEPENDENT_ADMIN rule under which a different Admin approves the exact
  reviewed content (content digest) before resolution; any edit invalidates
  the approval. Free text is rejected when it looks like a token, URL or
  command. Nothing here executes a provider change.
- Helm: `config.secretManagerAllowedReferences` (API-only).

### AWS observed use and approved key actions
- Observed use for a discovered AWS key (`AWS_USAGE_LOOKUP_ENABLED`):
  CloudTrail event history filtered by the exact access key id across every
  enabled region (90-day window, per-region coverage with CAPPED/FAILED
  states), IAM `GetAccessKeyLastUsed`, and the curated IAM potential-access
  evaluation when enabled. The snapshot is stored on the credential.
- Approved IAM key action plans: disable, delete (inactive keys only, its own
  `ACTION_DELETION_ENABLED` gate) and the prepare/publish rotation phases.
  A plan binds the exact target and operational review into a content hash;
  a different Admin approves it; a Remediator executes it against the same
  hash before it expires. Readiness (change window, consumer confirmations,
  impact/recovery review) is re-evaluated at approval and execution. Writes
  are followed by a read-back: only the proven state is `VERIFIED`; anything
  else is `OUTCOME_UNKNOWN` and can only be rechecked, never retried.
- Helm: `config.awsUsageLookupEnabled`, `actionExecutionEnabled`,
  `actionDeletionEnabled`, `rotationSecretArns`, `onboardingTemplateURL`;
  any credential-mutating execution requires production, OIDC and
  NetworkPolicy. The worker never receives execution switches.

### Dashboard workflows completed
- Triage: findings can be marked false positive or ignored (audited, reopenable).
- Ownership reviews per finding (team, due date, status, close reason) with a
  bulk update and an optimistic revision guard.
- Custom regex rules: create/edit/delete, sample and synthetic-fixture tests,
  scope by source type / path globs / exclusion words, operator-assigned
  severity. Patterns must be RE2-safe and non-trivial; matches are reported
  under the `custom` provider, never as a provider credential. Rules compile
  into the engine per job.
- Credential check (`CREDENTIAL_CHECK` job): one read-only identity call per
  provider records status, identity and scopes on the connection — never the
  token. The registration form takes an optional `vault://` reference.
- Initial-release behavior auto-resolved findings left without a location as
  `REMOVED_BY_RESCAN`. The Unreleased change above replaces this with separate
  exposure-presence tracking; it no longer treats source removal as revocation.

### Review fixes (dashboard ↔ API contract, coverage honesty)
- The dashboard now works against this API: session roles use the dashboard's
  names (`Admin`… — previously `OWNER`, which disabled every admin panel),
  `GET /source-types` is the catalog object the registration form reads, and
  the Sources tab's register → scan → job list → cancel flow, the audit log,
  connection declarations/capability projection, AWS account onboarding
  (CloudFormation quick-create link + STS role validation) are real endpoints.
  Every other path the dashboard was designed for answers `501` with a reason.
- Findings from every provider are shown: the dashboard's presentation guard
  had hidden any finding not issued by AWS/GitHub/Notion (856 of the 859
  detectors' results) and the detector catalog with it.
- A scan whose scope cannot be listed (no credentials, access denied, missing
  bucket/repository, unauthorised workspace) is recorded as **FAILED** with a
  stable code (`S3_LIST_FAILED`, `GITHUB_TREE_UNAVAILABLE`,
  `GITHUB_ORG_LIST_FAILED`, `NOTION_SEARCH_FAILED`) instead of a clean, empty
  success; listed-but-unreadable objects are counted and mark the run
  **PARTIAL**. Only error *codes* and exception class names are persisted.
- Queued jobs can be cancelled (`CANCELLED`); the schema gains additive nullable
  columns (`scan_jobs.objects_failed`, `aws_accounts.external_id/declaration`)
  that `create_all` adds in place on upgrade.
- Local shared-token comparison is constant-time; errors carry `error` as well
  as `detail`; CI runs every web suite; build artefacts and the unused pnpm
  lockfile are no longer tracked.

### Public-distribution scrub
- No real account IDs, organisation or bucket names, secrets or internal
  documents remain; every example uses placeholders (`123456789012`,
  `example-org`, `example-bucket`). Third-party engine artwork was removed;
  the dashboard identifies the native engine with a neutral mark.
