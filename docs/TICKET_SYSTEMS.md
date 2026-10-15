# 소유자 승인과 노출 대응 요청 (Slack·메일 링크, 팀 채널, 티켓 시스템 플러그인)

키 조치 계획(비활성화·삭제·새 키 게시)은 보안팀의 승인과 별도로 키 소유자의 승인을 기다린다
([소유자 승인](API.md), `owner_approval_required`). 노출된 Credential의 **대응 프로세스**는 담당자에게 조치를 요청하고
그 회신과 재스캔으로 완료를 확인한다. 두 흐름 모두 기본 경로는 같다.

- **회사 로그인 설치(`AUTH_MODE=oidc`)**: CreMore의 연락 발송(Slack 봇 DM 또는 메일)이 받는 사람에게 CreMore 링크를 보낸다.
  받은 사람은 링크를 열어 회사 로그인을 하고 CreMore 화면에서 승인·거절하거나 조치 결과를 보고한다.
- **로컬 로그인 설치**: 사람마다 로그인이 없으므로 운영자가 받은 회신을 기록한다(소유자 승인의 `record`, 대응 요청의 `record`).
- **회사 티켓 시스템**: 설치형 플러그인(아래 "티켓 시스템 플러그인")으로만 붙는다. 내장 티켓 시스템은 없다. 저장소에는 Jira 플러그인
  패키지가 있다(아래 "Jira 플러그인").
  GLPI 내장 어댑터와 시험 구성(`deploy/glpi-test`)은 2026-10-12에 제거했다(아래 "GLPI를 쓰던 설치").

결정과 감사 기록은 CreMore에 남는다. 링크 토큰은 URL fragment로만 전달하고 서버에는 digest만 저장한다.

## 1. 준비

연동 서비스 > 기타 설정 > **연락 발송**(관리자):

| 항목 | 값 |
| --- | --- |
| Slack 봇 토큰 | `xoxb-`로 시작하는 봇 토큰. 권한은 `chat:write`, `im:write`, `users:read.email`, 팀 채널 알림을 쓰려면 `channels:read`, `groups:read`도(없으면 DM만 동작하고 채널 기능은 `SLACK_SCOPE_MISSING`) |
| 메일 | SMTP 설정(선택) |
| 허용 도메인 | 받는 사람의 이메일 도메인 |
| 콘솔 주소 | 링크가 가리키는 CreMore 주소. 없으면 링크 요청을 거절한다 |

- Slack 봇은 받는 사람을 회사 이메일로 찾는다(`users.lookupByEmail`). Slack 계정의 이메일이 회사 로그인 이메일과 같아야 한다.
- 링크 페이지(`/owner-approval`, `/response`)는 CreMore 그룹 없이 회사 로그인만으로 열린다. IdP 클라이언트가 그 사람의 로그인을
  허용하고 토큰에 `email`을 넣어야 한다. `email_verified`가 거짓이면 거절한다. Google 로그인은 회사 Workspace 계정만 연다.
- 요청은 메일·Slack 연락과 같은 1인당 시간당 한도를 쓴다(`CONTACT_RATE_LIMITED`).

## 노출 대응 요청과 재스캔 확인

analyst가 노출된 Credential 상세의 **대응 프로세스**에서 담당자와 보내는 방법을 고른다.

| 보내는 방법 | 설치 | 동작 |
| --- | --- | --- |
| Slack / 메일 | 회사 로그인 | 담당자에게 CreMore 링크를 보낸다. 링크는 요청 시각부터 7일 유효하다 |
| 기록 | 로컬 로그인 | 보내지 않고 회차를 연다. 운영자가 담당자의 회신을 보고 폼으로 기록한다(`LOCAL_OPERATOR_STATEMENT`) |
| 티켓 시스템 | 플러그인을 설정한 설치 | 플러그인이 티켓을 열고 worker가 1분마다 응답을 읽는다(아래 플러그인 계약) |

### 담당자 선택

팀 설치의 대응 요청은 임의 이메일 대신 `person_ref`를 받는다. 로그인에 쓰는 IdP의 사람 목록을
연결하고 `people_details`를 켜서 완전하게 수집해야 한다. 화면은 이름·이메일·부서로 25명씩 검색하고,
서버는 발송 직전에 현재 연결/기능/대상·24시간 이내 완전 수집·활성 상태·유일한 이메일을 다시 검사한다.
수집 중지·대상 변경·퇴사·부분 수집·중복 이메일은 발송을 막는다. 이미 접수된 요청의 멱등 재시도는 새 발송을 만들지 않는다.

발급 목록의 정확한 소유자 근거와 명시적 책임 규칙은 추천에 쓰인다. 이름 유사성·생성자·사용자명 후보는
확정 소유자가 아니다. 사용자가 지정한 담당자는 다음 수집이 덮어쓰지 않는다. 책임 팀은 표시용 명시 값이며
팀 전체나 IdP 그룹에 일괄 발송하지 않는다. 담당자 참조·당시 프로필·책임 팀·매핑 근거/시각을 회차에 남긴다.
검색·추천·배정 API와 업그레이드 절차는 [담당자 매핑](IDP_RESPONSE_ROUTING_REVIEW.md)을 따른다.

### 담당자가 하는 일

1. Slack DM(또는 메일)에서 발급 서비스·유형·마스킹 식별자, 해야 할 일, 기한, 링크와 **조치 플레이북**을 받는다. 플레이북은 콘솔
   자격증명 상세의 조치 가이드와 같은 내용이다(`web/console/views/credentials/guides.json`, 서버 사본 `cremore/governance/remediation_guides.json`,
   두 파일이 같은지 시험으로 확인): 발급 서비스별 폐기·재발급 단계와 콘솔 바로 가기, 아직 노출된 곳의 종류(저장소·문서·버킷·웹)별 정리
   단계, 새 값의 금고 보관 단계. 이름·발급 계정은 고정된 말로 바꾸고 마스킹 식별자만 쓴다. 팀 채널 공지에는 넣지 않고(링크 화면에
   있음), 티켓 시스템(Jira 등)으로 요청하면 티켓 본문에 같이 넣는다. 비밀값·본문 조각·노출 위치 경로는 보내지 않는다.
   링크 화면도 같은 플레이북을 보여 준다.
2. 링크를 열고 회사 로그인을 한다. 로그인의 확인된 이메일이 요청받은 담당자 이메일과 같고, 사람 목록에서 그 사람이 아직
   같은 이메일의 활성 사용자일 때만 화면이 열린다. 보는 것만으로는 아무것도 기록하지 않는다(메일 검사기 대비).
3. **조치 결과 보고**를 작성해 제출한다. 처리 결과(완료·미완료·예외), 경로(폐기·교체·예외), 수행한 조치, 20~2,000자의 구체적 사유,
   수행 시각을 받고, 교체를 완료했으면 교체 작업 또는 새 발급 항목 참조도 받는다. 미완료·예외는 수행 조치 없이도 사유·시각을 반드시
   제출하고, 완료만 경로별 수행 조치를 모두 요구한다. 사유에 자격증명이 들어 있으면 거절한다.
4. 완료 보고는 담당자의 승인(`APPROVED`)으로, 미완료·예외 보고는 거절(`DECLINED`)로 함께 기록된다. 이후 다시 제출하면 새 보고
   버전으로 보완한다.

이는 담당자의 **처리 완료 진술**이며 키 폐기 또는 노출 제거의 증명이 아니다. 보고 버전과 수신 시각은 보존되고 감사에는 hash·참조가 남는다.

| 근거 | 자동 처리 상태 |
| --- | --- |
| 아직 요청하지 않은 발견 / 명시적 검토 시작 | 검토 대기 / 검토 중 (`REVIEWING`) |
| 링크 발송 완료 / 기록 회차 시작 | 담당자 응답 대기 (`WAITING_OWNER`) |
| 발송 실패 / 발송이 5분 안에 끝나지 않음 | 보내지 못함 (`NOT_SENT`), 링크는 무효이고 다시 요청할 수 있다 |
| 티켓 시스템 플러그인에서 승인만 응답 | 조치 보고 필요 (`REPORT_REQUIRED`) |
| 담당자의 완료 보고 | 조치 검증 중 (`WAITING_VERIFICATION`) |
| 완료 응답을 수신한 뒤 시작한 스캔에서도 발견 / 미완료·예외 보고 | 재조치 필요 (`NEEDS_ACTION`) |
| 새 회차의 평문 제거·기존 키 종료·필요한 교체 키 금고 보관까지 확인 | 조치 완료 (`COMPLETED`) |
| 기존 v1 회차에서 모든 노출 위치가 제거됨 | 과거 제거 확인 (`REMOVED`), 새 조치 완료와 구분 |
| 제거됐던 자격증명이 같은 위치 또는 다른 위치에 다시 등장 | 재조치 필요, 현재 노출 목록에 복귀 |

기존 자격증명 지문과 위치 upsert를 재사용한다. 재스캔 때 같은 자격증명을 추가 행으로 만들지 않는다.
현재 노출과 제거 이력을 분리하며 제거는 노출 위치에 관한 판단이다. 키 자체의 폐기·유효성은 별도 근거다.
실패·누락·권한 거절·검사 제외는 제거 증거가 아니며, 아직 읽지 않은 위치는 기존 상태를 유지한다.
완료 응답 전에 시작한 스캔은 그 응답의 사후 검증에 쓰지 않는다.
새 보고를 보완하면 제거 검증도 다시 해야 한다. 완료 후 재발견은 새 회차를 요구하며 이전 회신으로 재완료하지 않는다.
발급자가 종료 또는 값 비교 근거를 제공하지 않으면 검증 필요로 남는다. 구체적인 AND 조건과 공급자 제한은
[대응 완료 기준](RESPONSE_COMPLETION_DESIGN.md)을 따른다. 보고·응답은 공급자 조치 실행 승인을 대신하지 않는다.
부분 수집이라도 실제로 다시 발견한 값은 현재 노출 근거다. 제거 판정에 필요한 완전성 조건과 구분한다.

### 팀 채널 알림과 스레드 진행 기록

대응 요청은 담당자 개인 DM과 함께(또는 대신) 담당 팀의 기존 Slack 채널에도 알릴 수 있다. 응답과 책임은 여전히 지정된
담당자 한 명이며, 링크 화면은 그 사람만 열 수 있다.

- **채널 승인(관리자)**: 연동 서비스 > 기타 설정 > **대응 알림 채널**에서 봇이 들어가 있는 채널을 고르거나 채널 ID를 넣는다.
  CreMore는 Slack의 `conversations.info`로 채널을 확인한다. 보관된 채널과 다른 회사와 공유한 채널(Slack Connect)은 항상 거절하고,
  공개 채널은 관리자가 그 채널에 공개 허용을 명시적으로 켠 경우에만 쓴다(기본은 비공개만). 이 확인에는 봇 권한
  `channels:read`·`groups:read`가 필요하다. 채널 이름으로 팀을 자동 연결하지 않는다.
- **팀 연결**: 대응 책임 규칙(위치·계정별 책임 팀)에 알림 채널을 함께 정하면 요청할 때 그 채널이 미리 채워진다.
- **요청**: 채널에 담당자를 멘션한 글(발급 서비스·유형·마스킹 식별자·기한·링크)을 올린다. 개인 DM은 기본으로 함께 보내며 끌 수 있다.
  보내기 직전에 채널을 다시 확인하고, 그사이 공개·외부 공유·보관으로 바뀐 채널에는 보내지 않는다. DM은 갔는데 채널 글만 실패하면
  요청은 그대로 진행되고 실패 코드를 표시한다. 채널만으로 보냈는데 실패하면 `NOT_SENT`다.
- **스레드 진행 기록**: 그 글의 스레드에 CreMore가 상태 변화(담당자 응답, 제거 확인, 노출 잔존·재출현, 조치 완료, 다시 요청, 링크 만료)를
  정해진 문장으로 단다. 상태가 그대로인 반복 스캔에는 달지 않는다. 보고 사유·이메일·위치 경로·링크는 쓰지 않는다. 1분마다 Slack 탐지
  알림과 같은 역할의 한 worker만 보내며, 글마다 보내기 직전에 승인과 채널을 다시 확인한다. 채널이나 스레드가 거절하면(잠긴 스레드,
  읽기 전용 채널 등) 그 글만 건너뛰고 `thread_error`를 남기며, Slack 장애·요청 제한·봇 권한 누락은 다음 분에 다시 보낸다.
  CreMore는 스레드 댓글을 읽지 않으므로 스레드 대화는 응답으로 기록되지 않는다.
- **운영 경고**: 열린 스레드가 있으면 이 작업은 올릴 것이 없어도 1분마다 실행 시각·오류·밀린 글 수와 가장 오래된 글의 시각을
  `response:threads:state`에 남긴다. 운영 상태(`GET /api/v1/operations/status`, 콘솔 **운영 상태** 배너)는 이것만 읽어, 열린 스레드가
  있는데 1시간 넘게 실행이 없으면 `RESPONSE_THREADS_STOPPED`(혼합 worker나 control 프로세스가 돌지 않음), 실행은 되는데 밀린 글이
  1시간 넘게 남으면 `RESPONSE_THREADS_FAILING`(마지막 오류 코드 포함)을 띄운다. 설치 단위 경고라 경고 100개 상한에 잘리지 않으며,
  SIEM·Slack으로는 보내지 않는다.
- 채널 확인과 게시는 Slack에서 한 번에 일어나지 않는다. 확인 직후 게시 사이(요청 한 번의 왕복)에 공개·외부 공유로 바뀐 채널은
  그 한 글을 받을 수 있다. 담당자를 Slack에서 찾지 못하면 이름으로 쓰되, 이메일처럼 보이는 이름은 "담당자"로 바꾼다.

### 다시 요청

재조치가 필요하거나 보내지 못했으면 기존 요청 이력을 보면서 **다시 요청**할 수 있다. 다시 요청할 수 있는 경우는
`NEEDS_ACTION`·`REMOVED`·`NOT_SENT`, 링크가 만료된 응답 대기 회차, 지금 설정과 다른 티켓 서버로 보낸 응답 대기 회차다.
새 요청은 이전 요청을 참조하는 별도 회차이며 이전 회차의 링크는 무효가 된다. 이미 응답을 기다리는 유효한 요청을 중복 발송하거나
스캔마다 자동 발송하지 않는다. 화면은 서버가 계산한 `can_request`로 버튼을 연다.
동일 요청 UUID는 멱등이고 버전 충돌은 409다. 외부 쓰기 전에 요청을 예약·감사 기록한다.

티켓 시스템 플러그인으로 보낸 결과가 불명확하면 `SEND_UNKNOWN`으로 남기고 자동 재전송하지 않는다. 관리자가 외부 시스템에서
티켓이 생성되지 않았거나 기존 티켓을 종료해 진행 중인 중복 요청이 없음을 확인한 경우에만 확인 사실을 감사 기록하고 재요청을
허용한다. 이 확인은 운영자의 진술로 남으며 시스템이 미생성을 증명한 것으로 표시하지 않는다. Slack·메일 링크는 실패하면 링크를
무효로 만들고 `NOT_SENT`로 끝나므로 이 확인이 필요 없다.

`cremore/governance/response.py`가 설정 저장소의 회차별 기록과 상태를 소유한다.
상태 전환과 `FindingEvent`는 같은 트랜잭션에 기록한다. 담당자, 요청자, 보내는 방법, 요청 시각, 링크 만료,
응답 시각, CreMore 수신 시각, 스캔·검증 시각을 구분한다. 최근 회차는 상세에 표시하고
과거 회차와 감사 증적은 보존한다. 비밀값은 저장하지 않으며 명시적인 보고 형식만 검증 후 보관한다.
같은 회신의 반복 조회는 보고/감사 이력을 추가하지 않는다. 보고 근거는 회사 로그인 수신자(`VERIFIED_IDP_RECIPIENT`),
로컬 운영자 기록(`LOCAL_OPERATOR_STATEMENT`), 티켓 시스템 응답(`TICKET_RECIPIENT_STATEMENT`)으로 구별한다.

콘솔의 열린 조회 화면은 10초 주기와 탭 복귀·저장 후 새 조회로 갱신한다. 편집 중인 입력은 보존하고,
다른 사용자가 먼저 저장한 경우 처음 읽은 버전으로 충돌을 검출한다.

## 키 조치의 소유자 승인

remediator가 계획 카드에서 "소유자에게 승인 요청"을 고른다.

- **Slack / 메일 링크(회사 로그인)**: 소유자에게 72시간(또는 계획 기한까지) 유효한 링크를 보낸다. 소유자는 회사 로그인 후 승인·거절한다.
  로그인 이메일이 링크를 받은 주소와 같아야 하며, 계획을 요청·승인한 사람은 소유자로 결정할 수 없다.
- **기록(로컬 로그인)**: 운영자가 소유자의 회신을 근거와 함께 기록한다.
- **티켓 시스템(플러그인)**: 플러그인이 소유자 본인의 계정에 승인을 요청하고 worker가 1분마다 응답을 읽는다. **물은 계정의 응답만**
  소유자 결정으로 기록한다(`OWNER_APPROVAL_GRANTED`/`_DECLINED`, 행위자 `<system>:user:<id>`). 대리 승인자나 그룹 구성원의 응답은
  인정하지 않는다(`ANSWERED_BY_OTHER`). 요청은 72시간 또는 계획 기한까지 유효하고, 관리자가 티켓 시스템의 주소를 바꾸면
  (`TICKET_SYSTEM_CHANGED`) 그 뒤의 응답은 기록하지 않는다.

**보안 측과 소유자 분리(티켓 시스템 경로)**: 회사 로그인 설치에서 CreMore는 로그인마다 확인된 이메일을 주체별 keyed digest로 남긴다.
- 요청한 사람, 계획 요청자, 계획 승인자 중 로그인에 주소가 없던 사람이 있으면 구별할 수 없어 거절한다(`OWNER_APPROVAL_ACTOR_EMAIL_UNKNOWN`).
- 입력한 주소와, 찾은 티켓 시스템 계정이 가진 **모든 주소** 중 하나라도 그들의 주소와 같으면 거절한다(`OWNER_APPROVAL_SAME_PERSON`).
- 응답을 기록할 때와 계획 승인·실행 전에 다시 비교하고, 같거나 구별할 수 없으면 결정으로 인정하지 않는다
  (`NOT_INDEPENDENT`, `INDEPENDENT_APPROVAL_REQUIRED`).

## 티켓 시스템 플러그인 (어댑터 계약)

`cremore.ticketing`의 계약을 따르는 설치형 패키지를 entry point 그룹 `cremore.ticket_systems`로 등록하고, 설치 환경 변수
`TICKET_SYSTEM_PLUGINS`(쉼표로 구분한 id)에 적은 것만 관리자가 연동 서비스 > 기타 설정 > **티켓 시스템**에서 고를 수 있다.
목록을 읽을 때는 어댑터 코드를 실행하지 않는다. 이 기능은 비신뢰 코드를 격리하는 sandbox가 아니다.
비밀값은 저장할 때 봉인하고 다시 보여 주지 않는다. 저장·확인은 비밀값 없이 감사 기록(`TICKET_SYSTEM_SAVED`·`TICKET_SYSTEM_CHECKED`)에 남는다.

- `TicketSystemProvider(id, label, fields, build, validate, api_version=1)`: `fields`는 관리자가 넣는 값(`url`·`text`·`number`·`secret`)이다.
  `validate(values)`는 비밀이 아닌 값을 정규화하고 잘못된 값은 코드를 담은 `ValueError`로 거절한다.
  `build(values, secrets, http_client)`는 저장소 없이 시스템을 만든다.
- 시스템: `check()`, `find_approver(address) -> Approver(id, addresses)`(그 주소를 가진 활성 계정 하나와 그 계정의 모든 주소,
  어댑터 자신의 계정은 거절), `open_approval(ApprovalRequest(title, lines), Approver) -> Opened(ticket, approval, approver, url)`,
  `answer(Opened) -> Answer(state: WAITING|APPROVED|DECLINED, by, at, report=None)`, `close()`. 실패는 고정 코드의 `TicketError(code, retryable, ticket)`로만 알린다(응답 본문을 넣지 않는다).
- `ApprovalRequest.report_required`는 기본 false이며 대응 완료 요청만 true다. 기존 실행 승인 계약은 그대로다.
  `Answer.report`는 선택적 비신뢰 dict이며 기존 보고 필드(result/path/actions/explanation/performed_at/교체 참조)를 쓴다.
  어댑터는 명시적 형식을 정규화할 뿐, 권한·사유·비밀값·완료 근거 검증을 대신하지 않는다. 보고를 받지 않는 어댑터는 None을 유지한다.
  보고가 없는 승인은 `REPORT_REQUIRED`로 남고 담당자는 CreMore의 보고 폼으로 보완한다.
- CreMore는 코드(`[A-Z0-9_]{1,64}`, 아니면 `TICKET_SYSTEM_ERROR`), 참조(`[A-Za-z0-9_.:-]{1,64}`)와 주소(`http(s)://`)를 검사한 뒤에만
  응답·저장·감사 기록에 쓴다.
- worker는 기다리는 티켓 회차가 있을 때만 1분마다(한 번에 20초까지, 시스템이 응답하지 않으면 그 분은 멈춘다) 응답을 읽는다.
  웹훅은 받지 않는다. 계획이 실행되거나 끝나도 외부 티켓을 닫거나 후속 글을 달지 않는다.

## Jira 플러그인 (`packages/cremore-ticket-jira`)

Jira Cloud와 Data Center/Server를 REST API v2(`/rest/api/2/`) 한 경로로 쓴다. 종류는 시스템을 만들 때마다 한 번
`GET /rest/api/2/serverInfo`의 `deploymentType`으로 판단한다. 먼저 로그인 없이 묻고(Cloud는 익명 호출로 문서화), 401·403이면 한 번
로그인해 다시 묻는다. 계정 id는 Cloud `accountId`, Data Center 사용자 `key`다.
Python 이미지(`deploy/docker/python.Dockerfile`)에 wheel로 들어가지만 `TICKET_SYSTEM_PLUGINS=jira`를 API·worker 양쪽에 두어야 고를 수 있다.
배포 파일은 이 값을 기본 빈 값으로 노출한다: `docker-compose.yml`·`.env.example`, `deploy/compose/isolated/compose.yml`·`.env.example`,
Helm `config.ticketSystemPlugins`(API·worker 컨테이너).
패키지 사용법·검사 명령은 [패키지 README](../packages/cremore-ticket-jira/README.md)를 본다.

**먼저 확인할 조건 (Cloud)**

- **토큰**: Atlassian **사용자 계정**의 클래식(범위 없는) API 토큰을 그 계정 이메일과 함께, 사이트 주소(`https://<site>.atlassian.net`)로 쓴다.
  Atlassian "서비스 계정"의 범위 지정(scoped) 토큰은 `api.atlassian.com` 게이트웨이(`/ex/jira/<cloudId>`)로만 쓰이므로 지원하지 않는다.
  `url`에 `api.atlassian.com`을 넣으면 `JIRA_URL_INVALID`로 거절한다. CreMore 전용 사용자 계정을 만들어 쓴다.
- **이메일 공개**: Jira Cloud는 기본적으로 다른 사용자의 이메일을 숨긴다. 소유자를 이메일로 찾으려면
  ① 각 소유자의 Atlassian 프로필 "이메일 주소" 공개 범위가 CreMore 계정이 볼 수 있게 되어 있고,
  ② 사이트의 일반 구성(General configuration) "사용자 이메일 표시(User email visibility)"가 숨김(Hidden)·마스킹(Masked)이 아니어야 한다.
  그렇지 않으면 `JIRA_USER_EMAIL_HIDDEN`으로 거절되므로 Slack·메일 링크로 요청한다.

| 설정 | 값 |
| --- | --- |
| `url` | 사이트 주소(`https://acme.atlassian.net`, `https://jira.corp.example/jira`). http/https, 계정·쿼리·fragment 없이. 끝의 `/`는 지운다. `api.atlassian.com`은 거절 |
| `email` | Cloud: CreMore가 쓰는 Atlassian 사용자 계정의 이메일. 있으면 Basic `email:토큰`, 비우면 Bearer 개인 액세스 토큰(Data Center 8.14 이상). Cloud(`*.atlassian.net` 또는 `deploymentType=Cloud`)에서 비우면 `JIRA_EMAIL_REQUIRED` |
| `token`(비밀) | Cloud 클래식 API 토큰 또는 Data Center 개인 액세스 토큰. 봉인 저장 |
| `project` | 프로젝트 키 `[A-Z][A-Z0-9_]{1,19}` |
| `issue_type` | 만들 이슈 유형(예 `Task`) |
| `approved_statuses`·`declined_statuses` | 쉼표로 구분한 상태 이름 1~10개(예 `Done`, `Won't Do`). 대소문자 구분 없이 비교하며 두 목록이 겹치면 `JIRA_STATUSES_OVERLAP` |

**CreMore 계정 권한**: 전역 "Browse users and groups"(Data Center "Browse Users"), 대상 프로젝트의 "Browse projects"·"Create issues"·
"Assign issues". 승인을 받을 소유자는 그 프로젝트에서 "Assignable user"·"Browse projects"·"Transition issues"가 있어야 한다.
연결 확인(`check`)은 `/myself`, `GET /mypermissions?projectKey=<키>&permissions=BROWSE_PROJECTS,CREATE_ISSUES,ASSIGN_ISSUES,USER_PICKER`
(Cloud·Data Center 같은 호출, 없는 권한은 `JIRA_PERMISSION_<권한>_MISSING`), `/project/{key}`, `/project/{key}/statuses`를 읽어
이슈 유형과 설정한 모든 상태가 그 유형의 워크플로에 있는지 본다(`JIRA_ISSUE_TYPE_NOT_FOUND`, `JIRA_STATUS_NOT_FOUND`).

**소유자 찾기**: Cloud `GET /user/search?query=<주소>`, Data Center `?username=<주소>`(`maxResults=10`). 결과가 10명으로 꽉 차면 다음
페이지에 같은 주소의 다른 계정이 있을 수 있어 `JIRA_USER_AMBIGUOUS`로 거절한다. 이메일이 정확히 같은(ASCII 소문자, `@` 포함) 활성 계정
하나만 쓴다. 없으면 `JIRA_USER_NOT_FOUND`, 여럿이면 `JIRA_USER_AMBIGUOUS`, CreMore 계정 자신이면 `JIRA_USER_IS_SERVICE_ACCOUNT`.
이메일이 숨겨졌거나 마스킹된(`user at example dot com`) 계정만 있고 일치하는 계정이 없으면 추측하지 않고 `JIRA_USER_EMAIL_HIDDEN`.
계정 id가 `[A-Za-z0-9_.:-]{1,64}`가 아니면(예: 로그인 이름이 key인 오래된 Server 계정의 `@`) `JIRA_USER_REFERENCE_UNSUPPORTED`.
찾은 계정은 요청을 예약하기 전에 `GET /user/assignable/search?project=<키>`(Cloud `accountId`, Data Center `username`)로 배정 가능한지
확인하고, 아니면 `JIRA_USER_NOT_ASSIGNABLE`로 거절한다(예약 뒤의 실패는 `SEND_UNKNOWN`이 되어 수동 해제가 필요하기 때문이다).

**이슈**: 소유자에게 배정한 이슈 하나를 만든다(Data Center는 만들기 전에 `GET /user?key=`로 사용자 이름을 찾는다). 요약은 한 줄
250자 이내, 설명은 CreMore 문장을 하나의 `{noformat}` 블록으로 넣어 마크업·링크가 동작하지 않는다. 줄 전체가
`https?://[A-Za-z0-9._~:/?#=&%-]+`인 줄(CreMore 보고 링크)만 블록 뒤에 그대로 두어 Jira가 링크로 보여 준다. 블록의 마지막 두 줄은
"마치면 이 이슈를 <승인 상태> 상태로, 할 수 없으면 <거절 상태> 상태로 옮겨 주세요."와
"When done, move this issue to <승인 상태>; if you cannot, move it to <거절 상태>."이다(상태가 여럿이면 ` / `로 잇는다).
이슈가 생긴 뒤 응답을 쓸 수 없으면 이슈 키를 실패에 남겨(`TicketError(ticket=<키>)`) 대응 요청의 `SEND_UNKNOWN`에 그 이슈가 보이고
사람이 Jira에서 닫는다.

**소유자의 응답**: 배정된 이슈를 승인 상태로 옮기면 승인, 거절 상태로 옮기면 거절이다. worker는 이슈 번호(id)로
`GET /issue/{id}?fields=status&expand=changelog`를 읽는다. 승인·거절은 지금 상태의 **이름**으로 정하고, 응답한 계정은 **가장 최근의 상태 변경**
기록 하나의 작성자다. 그 변경의 `to`(상태 id)가 지금 상태의 id와 같아야 하며, 아니거나 상태 변경 기록이 없으면(처음부터 그 상태로
만들어진 경우 등) `JIRA_ANSWER_AUTHOR_UNKNOWN`이다. 더 오래된 상태 변경으로 대신하지 않는다. 상태 id로 비교하므로 상태 이름이 바뀌거나
번역되어 변경 기록의 이름이 달라도 맞게 판단한다.
물은 계정이 아닌 사람이 옮기면 키 조치 승인은 `ANSWERED_BY_OTHER`로 끝나고, 대응 요청은 `RESPONSE_ANSWERED_BY_OTHER`로 거절해 계속 기다린다.
변경 기록이 한 번에 다 오지 않으면 Cloud는 최신 100개 페이지(`/issue/{id}/changelog`)만 읽어 그 안의 상태 변경만 믿는다(먼저 받은 오래된
부분은 쓰지 않는다: 읽지 않은 중간에 다른 사람의 이동이 있을 수 있다). 그 페이지가 세어 둔 끝부분과 맞지 않거나 그 안에 상태 변경이 없으면,
그리고 Data Center는 그 API가 없어, `JIRA_CHANGELOG_TOO_LONG`으로 판단하지 않는다.
Jira는 보고 폼이 없어 `Answer.report`는 항상 없다. 그래서 노출 대응 요청을 Jira에서 완료(승인 상태)로 옮기면 `REPORT_REQUIRED`가 되고,
담당자가 CreMore 링크의 대응 담당자 탭에서 조치 결과를 보고해야 재스캔 확인으로 넘어간다. 거절 상태는 `NEEDS_ACTION`이다.
댓글·설명·응답 본문은 저장하거나 돌려주지 않는다.

**오류 코드**: 401 `JIRA_TOKEN_REFUSED`, 403 `JIRA_PERMISSION_MISSING`, 404 `JIRA_NOT_FOUND`, 400 `JIRA_REQUEST_REFUSED`,
408·429·5xx `JIRA_UNAVAILABLE`(다시 시도), JSON이 아닌 응답이나 압축된 응답 `JIRA_INVALID_RESPONSE`, 1 MiB 초과 `JIRA_RESPONSE_TOO_LARGE`,
그 밖은 `JIRA_HTTP_<상태>`. 리다이렉트는 따르지 않는다(SSO 로그인 페이지로 보내는 프록시는 `JIRA_HTTP_302` 등). 각 대기는 15초,
호출 하나(응답 헤더와 본문 전체)는 30초를 넘으면 `JIRA_UNAVAILABLE`이다. 호출은 작업 스레드에서 돌고, 30초가 지나면 그 연결의 소켓을
닫아(shutdown) 헤더를 아주 느리게 보내는 서버에 막힌 읽기도 끝낸다. 그래서 호출마다 새 연결(`Connection: close`)을 쓴다.
본문은 압축 없이(`Accept-Encoding: identity`) 받아 도착하는 대로 센다.

검증은 합성 Jira(`httpx.MockTransport`)와 루프백의 합성 HTTP 서버(헤더를 끝없이 흘리는 서버)만 썼다. 실제 Jira Cloud·Data Center 사이트,
실제 권한 구성과 이메일 공개 설정은 검증하지 않았다.

## GLPI를 쓰던 설치

- 이관 15가 GLPI 티켓 시스템 설정(`ticket_system`, 봉인된 GLPI 자격증명 포함)을 지운다. 다른 플러그인 설정은 그대로 둔다.
- GLPI로 보낸 대기 중 소유자 승인은 읽지 않고 72시간(또는 계획 기한) 안에 만료된다. 필요하면 Slack·메일 링크로 다시 요청한다.
- GLPI로 보낸 대응 요청 회차는 지금 설정과 다른 티켓 서버의 회차가 되어 **다시 요청**할 수 있다.
- 과거 결정·보고·감사 기록(`glpi:user:<id>` 행위자 포함)은 그대로 보존한다. GLPI 서버의 티켓은 CreMore가 닫지 않으므로 GLPI에서 정리한다.

## 알려진 한계

- 링크 응답에는 회사 로그인이 필요하다. 로컬 설치는 운영자 기록으로만 회신을 남긴다.
- Slack DM은 봇이 이메일로 찾을 수 있는 사람에게만 간다. 찾지 못하거나 보내지 못하면 `NOT_SENT`로 남고 다시 요청한다
  (요청 API는 이때도 `200`이며 상태와 코드를 돌려준다).
- 링크는 API 프로세스가 보낸다. 역할을 나눈 설치는 API의 나가는 연결에 `slack.com`(또는 SMTP relay)을 열어야 한다
  ([격리 네트워크 계약](../deploy/compose/isolated/NETWORK_CONTRACT.md)). 스레드 진행 기록은 Slack 탐지 알림과 같은 역할이 보낸다.
- 14일이 지난 링크 포인터는 새 링크를 만들 때 정리되므로, 아주 오래된 링크는 만료(`410`) 대신 쓸 수 없는 링크(`404`)로 보인다.
- 요청한 analyst가 자기 자신을 담당자로 지정하면 스스로 회신할 수 있다(대응 회신은 실행 승인이 아니다).
- 실제 Slack 워크스페이스로의 발송과 실제 담당자의 응답은 개발 검증에 포함하지 않았다(fake 전송과 합성 IdP).

### 2026-10-12 Slack 링크·팀 채널 전환 검증 (`7e134099`)

- 전체 Python 검사(격리 PostgreSQL 포함) 11,620개 중 11,525개 통과, 95개 skip, 실패 0.
- 웹 단위 검사 338개, TypeScript, Next production build, 브라우저 검사 31개(링크 화면·대응 알림 채널 편집기 포함, 한국어/영어·
  light/dark·360/1440·키보드만) 통과. Helm 차트 검사 111개 통과.
- 보안·백엔드·콘솔 독립 검토의 지적(채널 확인과 게시 사이의 변경, 콘솔 회신의 이메일 비교, 이름 자리의 주소 노출, control 역할의
  삭제 권한, 반복 스캔의 스레드 글, 잠긴 스레드의 정체, 봇 권한 누락 때 글 버림 등)을 고치고 각각 회귀 검사와 되돌림 확인을 했다.
- 실제 Slack 워크스페이스·메일·IdP와 실제 담당자 응답은 검증하지 않았다(fake 전송과 합성 데이터).
- 같은 날 GLPI 시험 설치(로컬 Docker와 AWS 시험 인스턴스의 `/opt/cremore-glpi-test`, 볼륨·이미지·비밀 파일)를 지웠다.
  Cloudflare 터널의 `glpi-test.cremore.site` 공개 호스트와 DNS 레코드는 Cloudflare 계정에서 따로 지운다.

### 2026-10-03 구현 검증 (GLPI 시기 기록)

대응 티켓 API·상태 전이·스캔 제거/재출현·worker·저장 트랜잭션의 관련 검사
571개를 통과했다. 메모리·SQLite 및 로컬 격리 PostgreSQL 17의 동시성/회귀 검사를 포함한다.
웹 단위 검사 231개, TypeScript 검사, 대응 흐름·목록·상세·재스캔 및 인증 우선 화면의
브라우저 검사를 통과했다. fake 티켓/공급자 응답으로 검증했으며 실제 외부 티켓 발송·응답은
이번 개발 검증에 포함하지 않았다. 코드 배포와 실제 티켓 시스템 연결 검증은 별도다.

동일 날짜 `c1fbb16`을 `integration/saas-structure`에 푸시하고 `test.cremore.site`의
API·worker·web에 배포했다. 이미지는 커밋 archive에서 빌드했고 설치 wheel의 모든 소스 해시를
대조했다. 세 컨테이너 revision·health와 익명 API 401을 확인했다. 배포 전 새 DB 백업을 만들었으며
테스트 초기화 뒤 새로 입력된 데이터는 재삭제하지 않았다. 임시 전송 bucket과 IAM 권한은 정리했다.

SIEM 목적지는 설치 전체의 공통 설정이다. 새 공급자마다 다시 설정하지 않는다.
대응 요청·발송·응답뿐 아니라 worker의 발송 불확실 상태와 스캔의 제거 확인·재출현도 기존
`audit.action`으로 공통 발신 대기열에 원자적으로 기록한다. 대응 상태 코드는 그대로 전달하되
메시지 본문·주소·담당자 이메일·링크·감사 메모는 전송하지 않는다. 내부 finding/audit 참조와 시각으로 증적을 연결한다.

### 2026-10-03 동일 IdP 담당자·접근 근거 후속 검증

후속 구현의 core·대응·identity·ticketing·API·projection 검사 403개와 온보딩·공급자/콘텐츠/API
경계 검사 563개가 통과했다(총 966개, skip 없음). 격리 PostgreSQL 17을 포함하고 공급자 호출은 fake다.
웹 단위 264개와 TypeScript, 대응자·대응·접근 근거·메타데이터 팝오버 브라우저 검사 4개가 통과했다.
명시적 담당자 해제 뒤 과거 티켓 수신자가 현재 담당자로 재등장하는 문제도 수정하고 관련 50개를 재검증했다.
별도 Linux 컨테이너에서는 225개가 skip 없이 통과했다. JWT 교체·만료, 프로세스 재시작 뒤 봉인 인증
복원·checkpoint 재개·오래된 lease 거절을 검사했으며 실제 24시간 연속 실행·사내 IdP/STS 실계정 검증은 아니다.
검사 묶음은 서로 겹치므로 전체 고유 테스트 수로 합산하지 않는다.
