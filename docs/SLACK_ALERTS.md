# Slack 탐지 알림

CreMore는 새 탐지를 보안팀의 Slack 채널로 바로 알린다. 콘솔에서 켜고, 보낼 곳과 내용을 고르고, 시험 메시지와
전달 상태를 확인한다. 별도 exporter 프로세스·설정 파일·환경변수가 필요 없다. 구현은 `cremore/alerts/`이고
API는 `cremore/api/routes/alerts.py`, 콘솔 카드는 `web/console/views/settings-alerts.tsx`다.
Slack 발급 목록 수집기(`slack/backend/`)와는 다른 기능이다.

알림이 되는 사건은 세 가지다.

| 이벤트 | 알림 제목 |
| --- | --- |
| `finding.created` | 새 자격증명 노출 |
| `finding.location_added` | 새 위치에서 발견 (이미 있는 자격증명이 새 위치에서 나옴. 다른 연결·계정이 이미 열린 위치를 다시 읽은 행은 알리지 않는다) |
| `finding.reappeared` | 제거 후 다시 노출 |

보낼 최소 심각도를 정하면, 그 기준에 걸러졌다가 나중에 기준 이상으로 오른 finding도 "심각도 상승"으로 알린다
(아래 설정 2).

세 이벤트는 finding·노출을 저장하는 같은 DB 트랜잭션에서 [SIEM 발신 대기열](SIEM_INTEGRATION.md)
(`siem_events`)에 기록된다. 알림 채널은 이 대기열의 목적지 `cremore.slack-alerts`로 읽으므로 저장된 탐지가
알림에서 빠지지 않는다. 같은 위치에서 변화 없이 반복 탐지한 스캔은 새 이벤트를 만들지 않는다.

## 설정

콘솔의 **환경 설정 > 스캔 시작 조건**(`?view=settings&section=triggers`) 맨 아래 **Slack 탐지 알림**
카드에서 관리자(Admin)가 설정한다. 모든 저장은 감사 기록(`INSTALLATION_SETTING_CHANGED`,
`detection_alerts …`)에 바뀐 필드 이름만 남고 값은 남지 않는다.

1. **보낼 곳**을 고른다.
   - **Incoming Webhook**: Slack 앱의 Incoming Webhooks에서 채널을 골라 만든 주소를 붙여 넣는다.
     `https`, 호스트 `hooks.slack.com` 또는 `hooks.slack-gov.com`, 포트 443, 경로
     `/services/<영대문자·숫자>/<영대문자·숫자>/<토큰>`만 받고 사용자 정보·query·fragment가 있으면 거절한다
     (SIEM Slack 패키지와 같은 검사). 주소는 받는 즉시 설치의 봉인 키로 봉인해 저장하고 다시 보여 주지 않는다.
     화면과 API는 저장 여부(`webhook_saved`)만 알려 준다. 빈 칸으로 저장하면 저장된 주소를 유지한다.
   - **Slack 봇**: 연동 서비스 > 연락 발송에 설정한 Slack 봇이 그 설정의 허용 채널 중 하나로
     `chat.postMessage`를 보낸다. 봇 토큰은 연락 발송 설정에만 있고 알림 설정에 복사하지 않는다.
     봇에는 `chat:write` 권한이 필요하고, 채널에 봇을 초대해야 보낼 수 있다. 허용 목록에서 빠진 채널로는 보내지 않는다.

   보내는 방법을 바꿀 때 카드는 새 방법의 주소 칸이나 채널을 먼저 보여 주고, 저장하면 방법과 그 주소·채널을
   함께 저장한다. 그래서 알림을 켜 둔 채로 바꿀 수 있다.
2. **보낼 심각도**: 모든 탐지(기본)·낮음 이상·보통 이상·높음 이상·심각만. 새 위치의 심각도가 아직 매겨지지
   않았으면 최대 1분 동안 매겨지기를 기다렸다가 그 심각도로 판단한다. 그래도 없으면 기준과 관계없이 finding의
   심각도로 보낸다. 기준보다 낮아 걸러진 finding이 나중에 기준 이상으로 오르면(`finding.updated`의 `ROLLUP` 변경)
   "심각도 상승" 알림을 보낸다. 같은 회차에 같은 finding의 위치 알림이 지금 finding의 심각도 이상으로 나가면 그
   알림만 보낸다. 위치 알림이 더 낮으면(새 위치는 낮음인데 다른 위치가 검증되어 높음으로 오른 경우) 상승 알림도 보낸다.
   알려진 제한: 상승 알림은 그 위치 알림이 나갈 것으로 보고 처리 완료한다. 그 위치 알림이 실패한 뒤 나중에 메시지
   없이 처리 완료되면(그 이벤트 종류를 빼거나, 오탐으로 닫거나, 심각도가 낮게 다시 매겨진 경우) 상승은 알리지 않는다.
3. **내용**: 자세히(기본) 또는 간단히. **메시지 언어**: 한국어(기본, 시각은 KST) 또는 영어(시각은 UTC).
4. **콘솔 주소**: 알림의 콘솔 링크가 이 주소로 시작한다. 연락 발송의 승인 링크와 같은 설정 한 곳
   (`contact_delivery.console_url`)에 저장되어 어느 쪽에서 바꿔도 같다. `scheme://host[:port]`만 받는다.
   비워 두면 알림에 링크 대신 Credential ID와 이벤트 ID가 들어간다.
5. **켜기**: 보낼 곳이 저장되어 있어야 켤 수 있다. 처음 켜기 전에 쌓인 이벤트와 꺼 둔 동안의 이벤트는 보내지
   않는다. 끄기 전에 보내지 못한 알림은 다시 켜면 보낸다(아래 "지난 기록").
6. **시험 메시지**: 저장한 설정으로 API 프로세스가 지금 한 통을 보낸다. 대기열을 거치지 않지만 알림과 같은
   1.1초 간격과 Slack의 `Retry-After` 대기를 지킨다(대기 중이면 보내지 않고 `DELIVERY_RATE_LIMITED`).
   Slack이 내용을 거절하면(콘솔 주소가 localhost·IP라 버튼을 받지 않는 경우 등) 알림의 짧은 형태처럼 버튼 없이 한 번 더
   보낸다. 그 뒤에는 다시 보내지 않는다. 결과(`delivered`, `error_code`)를 바로 보여 주고 감사 기록
   (`DETECTION_ALERTS_TESTED`)에 결과 코드만 남긴다. 켜기 전에도 보낼 수 있다.

이벤트 종류는 API의 `events`로 세 가지 중 일부만 고를 수 있다(기본: 전부). 카드는 고르지 않고, 저장된 종류를 설명에 보여 준다.

| API (Admin 전용) | 내용 |
| --- | --- |
| `GET /api/v1/settings/detection-alerts` | 설정(비밀값 없이 `webhook_saved`, 봇이 보낼 수 있는 `channels`, `bot_ready`, `console_url`, `enabled_at`)과 `status`(`pending`·`oldest_pending_at`·`last_seen_at`·`last_success_at`·`last_failure_at`·`last_error_code`·`consecutive_failures`) |
| `PUT /api/v1/settings/detection-alerts` | 보낸 필드만 바꾼다: `enabled`, `transport`(`webhook`·`bot`), `webhook_url`, `channel`, `min_severity`(`INFO`·`LOW`·`MEDIUM`·`HIGH`·`CRITICAL`), `detail`(`standard`·`minimal`), `language`(`ko`·`en`), `events`, `console_url` |
| `POST /api/v1/settings/detection-alerts/test` | 시험 메시지 한 통: `{delivered, error_code}` |

다른 관리자가 그사이 같은 설정이나 이 설정이 기대는 연락 발송 설정(봇·허용 채널·콘솔 주소)을 저장했으면
`SETTING_CHANGED_MEANWHILE`(409)로 거절한다. 그래서 허용 목록에서 막 빠진 채널로 알림을 켜지 않는다.

## 메시지 내용

**자세히**는 다음을 담는다.

- 제목: `[심각도] 새 자격증명 노출`처럼 이벤트 종류와 심각도
- 유형(탐지 카탈로그의 이름)과 발급 공급자
- 검증 상태: 보내는 시점의 자격증명 상태(활성 확인·비활성·폐기 확인·만료됨·미확인)
- 발견 위치: 콘텐츠 공급자와 연결 이름, 리소스(저장소·버킷·스페이스·페이지 제목), 위치(경로·키·페이지 URL)와 줄
- 처음 발견: 그 위치를 처음 본 시각
- 검사 시작: 그 위치를 찾은 스캔을 시작한 것(직접 실행·예약·변경 알림·다시 검사·룰 변경 재검사·이어서).
  변경 알림은 출처를 함께 적는다: `변경 알림(피드)`·`변경 알림(큐)`·`변경 알림(웹훅)`(영어 `Change event (feed)`·
  `(queue)`·`(webhook)`). 출처는 작업 payload의 `requested_by`(`feed`·`queue`·`webhook`)이며, 출처를 기록하기 전에
  접수된 작업은 "변경 알림"으로만 적는다.
- 다른 열린 위치 수: 같은 자격증명이 제거·오탐이 아닌 상태로 남은 다른 위치의 수
- 최근 사용 출처: AWS 액세스 키의 사용 기록 조회(CloudTrail)가 이미 저장해 둔 이벤트의 출발 주소 중 가장 최근 3곳과
  마지막으로 본 시각(한국어 KST, 영어 UTC). 더 있으면 조회가 읽은 모든 이벤트의 서로 다른 주소 수에서 3을 뺀 `+N`을 붙이고,
  그 수가 하한이면(주소가 256곳을 넘었거나 2026-10-11 전에 저장한 조회) `+N 이상`(영어 `+N+`)으로 적는다. 하한인데 보인 곳
  밖에 센 주소가 없으면 숫자 없이 `더 있을 수 있음`(영어 `possibly more`)을 붙인다
  (`최근 사용 출처: 203.0.113.5 (2026-10-10 14:36 KST), … +2`, 영어 `Recently used from`). 사용 기록이 키 소유 계정에서
  조회된 것이 아니거나 주소가 없으면 줄을 넣지 않는다.
  AWS 서비스가 대신 호출한 주소(`*.amazonaws.com`)는 `AWS 서비스 <호스트>`(영어 `AWS service <host>`)로 적는다. 이 줄은
  보내는 시점에 이미 읽은 자격증명 행에서 만들며 공급자를 다시 호출하지 않는다.
- 콘솔 링크: 버튼과 주소 글자. `<콘솔 주소>/?view=exposed&id=credential%3A<credential UUID>`로 기존 상세를 연다.
  링크는 접근 권한을 주지 않으며 열린 콘솔이 기존 로그인·역할 검사를 한다.
- Credential ID와 이벤트 ID: 같은 이벤트가 두 번 보이면 이벤트 ID로 알아본다.
- "심각도 상승" 알림은 `심각도: 낮음 → 심각`처럼 이전과 지금의 심각도를 첫 줄에 적고, finding의 대표 위치를 보여 준다.

**간단히**는 심각도·유형·콘텐츠 공급자·콘솔 링크(와 ID)만 담는다(최근 사용 출처 없음).

한 번에 보낼 알림이 1~3건이면 한 건씩, 4건 이상이면 최대 15건씩 묶은 요약 메시지(`CreMore 새 탐지 N건`)로
보낸다. 요약의 각 항목에도 같은 내용, 이벤트 ID와 열기 버튼이 있다. 요약 항목 글자가 6,000자를 넘으면 나머지
항목은 간단한 형태로 적어 메시지가 Slack 한도에 한참 못 미치게 한다. 메시지는 보내는 시점에 DB에서 다시 읽어
만든다. 그래서 검증 결과·연결 이름 같은 최신 상태가 들어가고, 이벤트 자체에는 이름·경로를 넣지 않는다. 알림은
자기 위치와 finding의 대표 위치만 id로 읽고, 자격증명의 모든 위치를 읽지 않는다. 다른 열린 위치 수는 열린 위치
행을 처음 1,000개까지만 읽어 세고, 그보다 많으면 `1,000곳 이상`·`1,000+`처럼 센 수에 "이상"을 붙인다.

## 개인정보와 보안 경계

- 비밀값, 가린 값(hint), 가려진 줄(redacted line), 지문(fingerprint), 공급자의 응답 원문은 메시지에 넣지 않는다.
  메시지를 만드는 코드는 이 값들을 읽지 않는다.
- 조치에 필요한 리소스 이름·경로·페이지 제목·페이지 URL과 연결 이름은 넣는다. 알림 채널을 볼 수 있는 사람은
  이 위치 정보를 본다. 위치 정보를 볼 수 있는 사람만 있는 채널을 고른다.
- 최근 사용 출처 줄에는 키가 쓰인 출발 주소(IP)가 그대로 들어간다. 알림 채널을 볼 수 있는 사람은 이 주소를 본다.
  **간단히** 알림에는 넣지 않는다. 주소는 키를 쓴 곳의 단서이며 사용자나 위치를 확정하지 않는다.
- 연결 이름·리소스·위치는 공급자 정보와 같은 검사(`cremore.detection.safe_text`)를 거친다. 자격증명처럼 보이는
  값(또는 검사하기에 너무 긴 값)은 `(표시하지 않음 · 콘솔에서 확인)`으로 바꾼다.
- URL 위치는 scheme·호스트·포트·경로만 남기고 query·fragment·사용자 정보를 뺀다. 토큰이 실릴 수 있는 자리다.
- 모든 블록은 `plain_text`이고 제어·방향 지정 문자를 지우고 길이를 Slack 한도 안으로 자른다. `&`·`<`·`>`는 Slack이
  모든 텍스트 객체에 요구하는 대로 이스케이프하며, Slack은 표시할 때 되돌린다(보이는 링크 글자를 복사해도 그대로다).
  파일·페이지 이름이 서식·mention·링크로 해석되지 않는다. `mrkdwn`·`link_names`·링크/미디어 미리보기를 끈다.
- 보낼 때 분석가가 오탐으로 닫은 finding이나 오탐인 위치는 보내지 않는다(자동 오탐 처리 포함). finding을 오탐으로
  닫은 시각(`resolved_at`, 없으면 이벤트 시각)부터 10초가 안 됐으면 학습한 오탐 프로필이 곧 다시 열 수 있으므로,
  그 알림은 잠시 기다렸다가 판단한다.
- 알려진 제한: 자동 오탐 처리로 닫혀 알림 없이 처리 완료된 finding이 그 뒤(10초 이후) 재평가로 다시 열려도 그 알림을
  다시 보내지 않는다. 다시 열린 finding은 콘솔에서 확인한다.
- webhook 주소·봇 토큰·Slack 응답 본문은 로그·대기열·감사 기록에 남지 않는다. 실패는 고정 오류 코드만 남는다.
  알림을 보내는 모듈은 HTTP 클라이언트의 요청 URL 로그(httpx INFO)를 끈다.
- 알림은 관측 근거이며 자격증명의 현재 유효성·권한 검증을 뜻하지 않는다.

## 전달 보장과 운영

- **놓치지 않음**: 이벤트는 탐지와 같은 트랜잭션에서 기록되고, Slack이 받았다고 답한 뒤에만 그 메시지의
  이벤트를 처리 완료(ACK)한다. Incoming Webhook은 HTTP 200과 본문 `ok`, 봇은 `ok: true`가 성공이다.
- **최소 한 번(at-least-once)**: Slack이 받은 뒤 응답이 사라지거나 ACK 전에 프로세스가 멈추면 같은 메시지가
  다시 보일 수 있다. 처리 중 멈춘 이벤트는 임대(300초)가 끝나면 다시 보낸다. 이벤트 ID로 중복을 알아본다.
- **정해지지 않은 상태로 건너뛰지 않음**: 심각도가 아직 매겨지지 않은 위치(이벤트 시각부터 최대 60초)와 오탐으로
  닫은 지 10초가 안 된 finding의 알림은 건너뛰지 않고 2초 뒤에 다시 판단한다. 이 대기는 시도 수에 넣지 않는다.
- **재시도**: 메시지 하나만의 거절로 정해 둔 것은 Webhook의 HTTP 400·413·422와 봇의 `invalid_blocks`·
  `invalid_blocks_format`·`msg_too_long`·`msg_blocks_too_long`·`no_text`·`too_many_attachments`·`invalid_arguments`다.
  그 밖의 실패(429, Webhook이나 봇의 HTTP 5xx, 봇의 `internal_error`·`fatal_error`·`service_unavailable`, 시간 초과,
  연결 실패, 인증 거절, 없어진 Webhook, 채널 문제, 여기서 모르는 코드)는 모든 메시지가 같은 거절을 받는 것으로 보고
  그 회차를 멈춘다. 그래서 Slack 장애 중에는 회차마다 요청이 한 번만 나간다. 시도한 메시지의 이벤트는
  `min(3600, 5×2^시도 수)`초 뒤(Slack의 `Retry-After`가 더 길면 그만큼) 다시 보내고, 시도하지 않은 이벤트는 시도
  수에 넣지 않고 `Retry-After`만큼(없으면 2초) 미룬다. 그래서 장애 동안 남은 알림이 차례로 한 번씩 시도되며 모두의
  재시도 간격이 늘어난다. 429를 받으면 그 시간 동안 모든 워커 복제본과 시험 메시지가 Slack으로 보내지 않는다(DB
  간격 줄의 대기). 메시지 하나만의 거절은 요약을 한 건씩 나누고, 짧은 형태로 다시 보내고, 그래도 안 되면 그 알림만
  재시도하며 나머지 알림은 계속 보낸다. 짧은 형태는 콘솔 링크를 버튼 없이 주소 글자로만 담으므로 Slack이 버튼에
  받지 않는 콘솔 주소(localhost·IP 등)여도 나간다. 짧은 형태가 나가면 그 회차의 나머지 메시지도 버튼 없이 보낸다.
  보류(held)하지 않고 성공할 때까지 계속 보낸다.
- **회차 시간 제한**: 회차는 알림을 가져온 뒤 257.5초(임대 300초 − 응답 대기 10초 − 간격 대기 2.5초 − 여유 30초)가
  지나면 새로 시도하지 않는다. 남은 알림은 시도 수에 넣지 않고 바로 다음 회차로 돌려놓는다. 그래서 마지막 메시지의
  응답도 임대가 끝나기 전에 와서 처리 완료가 늦어 같은 알림이 다시 나가는 일이 없다.
- **보내지 않고 처리하는 것**: 알림이 아닌 이벤트(감사·상태 변경·heartbeat 등)와 고르지 않은 이벤트 종류는 회차마다
  한 문장(INSERT … SELECT)으로 한꺼번에 처리 완료한다. 기준보다 낮은 심각도와 오탐은 한 건씩 판단해 메시지 없이 ACK한다.
- **보내는 프로세스**: 회차는 worker의 자기 스레드에서 약 1초마다 돈다. 혼합(`mixed`) worker는 관리 루프 옆 스레드에서, 역할을
  나눈 배포는 control 프로세스의 스레드에서 보낸다. 그 배포에서 webhook 주소와 봇 토큰을 여는 제어 봉인 키와 전달 행 쓰기 권한을
  가진 worker 역할은 control뿐이고, 수집·조치 프로세스와 작업 프로세스는 보내지 않는다. 트리거 폴링·유지보수가 오래 걸려도 알림이
  늦지 않는다.
  회차 자체가 예외로 끝나면(DB 권한·연결 같은 문제) 예외 종류만 로그에 남기고 다음 회차를 두 배씩(최대 60초) 늦추며, 한 번
  성공하면 1초로 돌아온다. Slack의 거절·장애는 예외가 아니라 회차 안에서 알림별로 다시 보낸다(아래 "재시도").
  종료할 때(SIGTERM·SIGINT, 관리 루프 종료) 진행 중인 회차는 새 메시지를 시작하지 않는다. 보내던 한 통만 마쳐 ACK하고, 가져온
  나머지는 시도 수에 넣지 않고 바로 돌려놓아 다음 프로세스가 임대(300초)를 기다리지 않고 보낸다. 멈춤은 신호를 받는 즉시 진행
  중인 회차에 전해지고(관리 루프가 티켓 확인 같은 긴 일을 마칠 때까지 기다리지 않는다), 그 한 통(공유 간격 대기와 Slack 응답)을
  최대 15초 기다린다. 격리 Compose의 control
  서비스는 `stop_grace_period: 30s`로 이를 기다린다. 보내던 일이 15초를 넘기면(늦은 Slack 응답, 거절된 메시지를 짧은 형태로 다시
  보내는 중) 가져온 알림은 임대가 끝난 뒤 나가고 그 한 통은 두 번 갈 수 있다(최소 한 번 전달).
- **역할을 나눈 설치의 준비**: control DB 역할에 `siem_deliveries`·`siem_destination_status`·`scan_request_pacing` 쓰기와
  `aws_accounts` 읽기(메시지의 계정 이름), API 역할에 시험 메시지의 `scan_request_pacing` 쓰기가 필요하다. 업그레이드 뒤
  `python -m cremore.db.privileges grant --schema cremore`를 다시 실행한다([DB 역할](../deploy/postgres/README.md)). control
  egress에 Slack HTTPS(Incoming Webhook은 `hooks.slack.com`·`hooks.slack-gov.com`, 봇은 `slack.com`)를 연다
  ([네트워크 계약](../deploy/compose/isolated/NETWORK_CONTRACT.md)). 그 전에는 회차가 권한·연결 오류로 실패해 간격을 늘리며
  재시도하고 알림은 대기열에 남는다. 시험 메시지는 API가 보내므로 Incoming Webhook을 쓰면 API egress에도 그 호스트를 연다
  (봇은 연락 발송이 이미 연 `slack.com`). 열지 않으면 알림은 나가도 시험은 `HTTP_DELIVERY_FAILED`·`DELIVERY_TIMEOUT`으로 실패한다.
- **속도와 비용**: 메시지는 설치 전체에서 1.1초에 한 통으로 제한되며,
  이 간격은 DB(`scan_request_pacing`)로 모든 워커 복제본이 함께 지킨다. 한 회차는 두 가지만 읽는다.
  1. 새 이벤트: 이 이벤트마다 한 문장(INSERT … SELECT)으로 전달 행을 만든다. 알림이 될 수 있는 이벤트는 받지 않은
     행으로, 나머지는 보내지 않고 처리 완료로 만든다. 30초마다 한 번은 커서부터 읽는다(전체 읽기). 커서는 직전
     회차보다 5분 앞이고, 시계가 앞서 갔다가 돌아와도 지금보다 5분 앞을 넘지 않는다. 그 사이의 회차는 직전에 읽은
     가장 새 이벤트 시각보다 5초 앞부터만 읽는다(빠른 읽기). 켜기나 한 시간 확인이 커서를 옮긴 회차는 전체 읽기다.
  2. 아직 받지 않은 전달 행 최대 100건: 부분 인덱스 `siem_deliveries_owed`(목적지, `available_at`,
     `delivered_at IS NULL`)로 찾는다.

  빠른 읽기가 놓치는 것은 가장 새 이벤트보다 5초 넘게 늦게 커밋된 이벤트뿐이다. 그 이벤트는 30초 안에 오는 다음
  전체 읽기가 찾는다(약 4분 30초까지 늦은 커밋). 그보다 늦게 기록된 이벤트(늦은 커밋, 시계가 느린 호스트)는 한
  시간마다, 마지막 확인 시각이 미래로 보이면 바로, 전체 기록을 한 번 확인해 찾는다. 그래서 보존 기록이 길어도,
  몇 분 사이에 이벤트가 몰려도, Slack 장애로 알림이 오래 밀려 있어도 회차가 가볍다. SQLite 측정: 받지 않은 알림
  뒤에 이벤트 10만 건이 있을 때 회차 약 17 ms·상태 약 9 ms, 5분 안에 이벤트 10만 건이 몰렸을 때 빠른 읽기 회차
  약 45 ms(전체 읽기는 약 0.65초). 인덱스가 없으면 결과는 같지만 받지 않은 행을 찾으려고 목적지의 전달 행을 모두
  읽는다(SQLite 10만 건에서 회차마다 약 0.5초). 처음 켤 때 지난 기록을 처리 완료로 표시하는 한 번은 기록 수에
  비례한다(SQLite 20만 건에서 약 6초). 여러 워커 복제본이 같은 범위를 함께 읽어도 행을 같은 순서(이벤트 시각,
  ID)로 넣으므로 PostgreSQL에서 서로 교착(deadlock)하지 않고 기다린다. 상태 기록(`detection_alerts:history`)의 커서가
  비었거나 시각이 아니면 처음 켠 시각부터 다시 읽는다. 이미 있는 전달 행은 그대로라 같은 알림이 다시 나가지 않는다.
- **지난 기록**: 처음 켤 때 그 전에 쌓인 이벤트를, 다시 켤 때 마지막으로 꺼 둔 동안의 이벤트를 보내지 않은 채 처리
  완료로 표시한다(`SiemOutbox.skip_before`, 켤 때마다 한 번). 이벤트 시각은 PostgreSQL에서도 DB가 아니라 그 이벤트를
  쓴 프로세스(API·워커)의 시계다. 그래서 두 경계를 5분(늦은 기록을 기다리는 시간과 같다)씩 보내는 쪽으로 옮긴다.
  시계가 5분까지 앞선 프로세스가 끄기 직전에 쓴 탐지도 다시 켜면 보낸다. 놓치기보다 한 통 더 보내는 쪽이다. 끈 뒤
  10분 안에 다시 켜면 그사이의 이벤트도 보낸다. 끄기 전에 보내지 못했거나 아직 확인하지 않은 알림은 다시 켜면
  보낸다. 꺼 두면 대기열을 전혀 읽지 않는다.
- **상태**: 카드의 상태 줄과 `GET …/detection-alerts`의 `status`가 대기 수, 워커가 마지막으로 확인한 시각,
  마지막 성공·실패, 실패 코드, 연속 실패 수를 보여 준다. 받지 않은 전달 행과 커서 이후 아직 행이 없는 이벤트만
  세며 카드는 1분마다 다시 읽는다. 워커가 2분 넘게 확인하지 않으면 그렇게 표시한다.
- **SIEM과의 관계**: CreMore 자신의 목적지(`cremore.`로 시작하는 이름)는 SIEM 상태(`/api/v1/siem/status`), 운영
  상태의 SIEM 경고와 `siem.delivery_backlog`, finding 전달의 목적지 수에서 빠진다. 켜 두고 보고하는 동안에는
  SIEM 보존 정리의 활성 목적지이므로 받은 이벤트만 정리된다. 30일 동안 보고가 없으면(꺼 둔 경우) 정리에서 제거된
  목적지로 본다.
- Slack 장애 중에는 같은 Slack으로 장애 알림을 받을 수 없다. 이 채널의 실패(폐기된 webhook, 채널에서 빠진 봇, 연락 발송
  허용 목록에서 빠진 채널 등)는 운영 상태(`/api/v1/operations/status`)와 SIEM 목적지에 나타나지 않는다. 설정 > 검사 트리거의
  카드 상태 줄이나 `GET /api/v1/settings/detection-alerts`의 `status`(`pending`·`last_failure_at`·`last_error_code`·
  `consecutive_failures`)를 관제에서 읽는다.

## SIEM 패키지 경로 (`packages/cremore-siem-slack`)

기존 설치형 출력 패키지도 그대로 쓸 수 있다. 별도 `cremore-siem` exporter가 같은 발신 대기열을 자기
destination ID로 읽어 Incoming Webhook으로 보낸다. 내장 알림 채널과 함께 켜면 탐지마다 메시지가 두 통 간다.

- 메시지는 이벤트의 코드와 내부 UUID(심각도·발급 공급자·자격증명 종류·finding/노출 ID·소스 연결 ID·줄)만 담고
  파일명·리소스 이름·경로를 담지 않는다. `finding.forwarded`와 `siem.test`도 보낸다.
- webhook 주소는 exporter 전용 비밀 환경변수 `SLACK_ALERT_WEBHOOK_URL`로 주고, [예제 설정](../deploy/siem/slack.example.json)의
  `dashboard_base_url`에 콘솔 HTTPS origin을 넣는다. `allow_plugins`에 `slack_alerts`, destination의 `format`은 `native`다.
- 새 destination ID는 보존된 이벤트부터 받으므로 과거 알림이 한 번에 올 수 있다. 재시도·보류(`max_attempts`)·
  `release-held`·exporter 생존 확인은 [SIEM 지침](SIEM_INTEGRATION.md)을 따른다.
- [침해 이후 피해 제한 계약](POST_COMPROMISE_CONTAINMENT.md)대로 exporter에는 SIEM DB 역할·Slack 발송 비밀·승인한
  egress만 준다.

```bash
python -m pip install -e '.[dev,gcp,azure]'
python -m pip install --no-deps -e packages/cremore-siem-slack
cremore-siem --list-sinks
AWS_EC2_METADATA_DISABLED=true python -m pytest packages/cremore-siem-slack -q
```

## 검증 범위

가짜 Incoming Webhook·가짜 Slack Web API와 메모리·SQLite 저장소(PostgreSQL은
`CREMORE_TEST_POSTGRES_URL`이 있을 때)로 검사한다. 실제 Slack 송신·workspace 권한·채널 수신·운영 DB는
별도 배포 검증이다.

```bash
AWS_EC2_METADATA_DISABLED=true python -m pytest cremore/alerts cremore/worker/supervisor_test.py cremore/db/privileges_test.py -q
AWS_EC2_METADATA_DISABLED=true python -m pytest cremore/api/alerts_routes_test.py cremore/api/contact_routes_test.py cremore/siem -q
(cd web && node --test tests/console-alerts.test.cjs && npx tsc --noEmit)
```

PowerShell에서는 pytest 전에 `$env:AWS_EC2_METADATA_DISABLED='true'`를 설정한다.
