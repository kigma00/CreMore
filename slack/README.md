# slack 공급자 소유 영역

Slack Enterprise Grid 조직의 앱 발급 목록 메타데이터를 소유한다. Python 구현과 전용 테스트는
`backend/cremore_slack_provider/`에 있다. 공통 플랫폼이 라이브러리 함수를 직접 호출하며 제품의 Python wheel
하나에 함께 설치된다. 전용 UI는 없다. 콘솔이 연결 카탈로그(`cremore/onboarding/catalog.py`)의 descriptor로
연동 카드·마법사·발급 목록 유형을 그린다.

루트에서 `python -m pip install -e ".[dev,gcp,azure]"`로 개발 설치 후
`python -m pytest slack/backend -q`로 전용 합성 회귀를 실행한다. 실제 Slack 호출은 별도로 지정한 환경·범위에서만 수행한다.

[공통 AGENTS](../AGENTS.md), [팀 지침](../docs/AI_TEAM_CODING_GUIDE.md),
[실제 디렉터리·등록·빌드 경계](../docs/PROVIDER_DIRECTORY_REVIEW.md)를 먼저 읽는다.
공통 API·DB·권한·scope·작업 수명·SIEM 계약과 registry는 플랫폼 담당자와 나누어 작업한다.

이 구현은 Slack 공식 공개 문서만 근거로 새로 작성했다. 2026-09-22에 되돌린 Slack 통합 브랜치(GPLv3)의 코드는 쓰지 않는다.
메시지 수집·실시간 이벤트·알림 발송은 이 공급자의 범위가 아니다. 콘텐츠의 Slack 토큰·웹훅 탐지는 기존 탐지기
(`slack-token-v1`, `slack-webhook-v1`)가 맡는다.

## 연결 마법사

| 항목 | 계약 |
| --- | --- |
| 대상 | 조직 ID(`E…`) 또는 그 조직의 워크스페이스 ID(`T…`) 하나 |
| 인증 | 조직에 설치한 앱의 **조직 관리자 사용자 토큰**(`xoxp-`). 봇 토큰(`xoxb-`)은 관리 API가 받지 않아 거절하고, 토큰 교체가 켜진 앱의 `xoxe.` 토큰은 12시간 뒤 멈추므로 거절한다 |
| 권한 점검 | `auth.test`로 토큰의 조직이 대상과 같은지 확인한 뒤 `admin.apps.approved.list`(limit 1)와 감사 로그(`/audit/v1/logs`, limit 1)를 읽는다. Slack은 거절을 HTTP 200의 `ok: false`로도 주므로 본문의 error를 코드로 바꾼다. `auditlogs_read`는 감사 로그 옵션에 묶여(`option: audit_events`) 옵션이 꺼져 있으면 콘솔이 필요한 권한으로 세지 않는다 |
| 계획 | `schedule_minutes`, `audit_events`(기본 꺼짐: 최근 90일 감사 로그로 설치 상태·설치일·설치자 확인) |
| 수집 레코드 | schema 2 metadata 연결 하나(`Slack · <ID> · apps`, 초당 0.3 요청). 계획 변경은 다음 실행부터 따른다 |

### 앱 만들기(매니페스트 링크)

마법사의 설정 도우미가 [매니페스트 링크](https://docs.slack.dev/app-manifests/configuring-apps-with-app-manifests/)
(`https://api.slack.com/apps?new_app=1&manifest_json=…`)로 앱을 만든다(`web/console/views/integrations/guide.tsx`의
`slackManifest`). 관리자는 워크스페이스를 고르고 만들기만 누르면 된다.

- 사용자 범위: `admin.apps:read`, 감사 로그 옵션을 켰을 때만 `auditlogs:read`. `admin.teams:read`는 선택이다. 있으면 대상 조회가
  조직의 워크스페이스(`admin.teams.list`)를 하나씩 보여 주고, 없으면 조직 자체만 대상으로 내놓는다(조직 전체 승인 목록에는
  워크스페이스 목록이 필요 없다). 워크스페이스 하나를 대상으로 고른 연결의 점검은 그 범위가 있어야 한다.
  [admin.teams.list](https://docs.slack.dev/reference/methods/admin.teams.list)
- `settings.org_deploy_enabled: true`: 관리 API는 조직에 설치한 앱에서만 동작한다. 조직 설치에는 봇 범위가 하나 있어야 하므로
  ([조직용 앱](https://docs.slack.dev/enterprise/developing-for-enterprise-orgs/)) `team:read`와 봇 사용자를 둔다. 봇 토큰은 쓰지 않는다
- `settings.token_rotation_enabled: false`: 교체되는 토큰은 12시간 뒤 멈춘다
- 그다음 앱 설정의 Install App에서 조직에 설치하고(감사 로그 옵션이면 조직 Owner가 설치해야 `auditlogs:read`가 승인된다)
  OAuth & Permissions의 User OAuth Token(`xoxp-`)을 넣는다. 권한 점검이 조직 설치·범위·관리자 여부를 코드로 알려 준다
- 토큰이 이미 저장된 연결에서 감사 로그 옵션을 켜면 새 앱이 아니라 그 앱의 User Token Scopes에 `auditlogs:read`를 더하고
  Owner가 다시 설치하도록 안내한다

## 발급 목록 메타데이터

`metadata/adapter.py`의 `collect_pages`, `validate_spec`, `validate_record`가 기존 schema 2 `CollectorRuntime`·
worker·저장 계약을 사용한다. 작업은 `SOURCES` 순서로 진행한다.

1. `audit_events`(감사 로그 옵션을 켰을 때): `GET https://api.slack.com/audit/v1/logs`를 앱 수명주기 action
   (`app_installed`, `app_uninstalled`, `app_scopes_expanded`, `app_token_preserved`, `bot_token_upgraded`,
   `bot_token_downgraded`, `org_app_workspace_added`, `org_app_workspace_removed`)으로만 읽는다. 실행을 시작할 때 정한
   기간(`oldest`·`latest`)을 체크포인트에 고정하고, 앱별 요약(최근 설치·설치자, 위치별 설치/제거, 마지막 변경)만 남긴다.
   설치 상태는 위치(워크스페이스·조직)마다 가장 최근 설치·제거로 정하고, 한 곳이라도 설치돼 있으면 설치로 본다.
   이벤트가 오는 순서와 무관하다. 워크스페이스 대상이면 다른 워크스페이스의 이벤트는 뺀다. 요약은 앱 5,000개,
   앱당 위치 20곳까지이며 넘치면 오래된 제거 기록부터 버리고 설치된 위치는 버리지 않는다.
2. `approved_apps`: `GET https://slack.com/api/admin.apps.approved.list`(`enterprise_id` 또는 `team_id`, cursor).
   승인된 앱 하나가 scope의 token type에 따라 **봇 토큰**(`bot:`), **사용자 토큰**(`user:`), `incoming-webhook`
   scope가 있으면 **수신 웹훅**(`hook:`) 행이 된다. 앱 ID·이름·scope·개발 주체·내부 앱 여부·승인 시각·승인자를 남긴다.
3. `installed_apps`(감사 로그 옵션을 켰을 때): 감사 로그에 설치된 것으로 남았지만 승인 목록에 없는 앱의 행.

- 승인 목록은 **설치 여부를 주지 않는다.** 감사 로그 요약이 없으면 상태는 `APPROVED`/`UNKNOWN`이고, 감사 로그에서 한 곳이라도
  설치로 남으면 `INSTALLED`→`ACTIVE`(근거 `PROVIDER_REPORTED`)다. 제거만 관측됐을 때는 연결 대상 자체(조직 ID 또는 워크스페이스 ID)의
  제거가 있어야 `UNINSTALLED`→`REVOKED`로 보고, 다른 위치의 제거만 있으면 기간 창 이전의 설치가 남았을 수 있어 `APPROVED`/`UNKNOWN`으로 둔다.
- 설치일·설치자는 봇 토큰·웹훅에만 채운다. 사용자 토큰은 사용자마다 따로 승인하므로 앱 단위 행이며, 어떤 사용자가
  승인했는지·언제 승인했는지는 주지 않는다. 감사 로그의 대체 행위자 `USLACKUSER`·`USLACKSECURITY`는 설치자로 남기지 않는다.
- Slack은 토큰 값·웹훅 URL·토큰 사용 기록을 주지 않는다. 만료일도 주지 않는다. 행은 노출 발견값과 값·digest로
  대조할 수 없고(`credential_match: UNAVAILABLE`), 마지막 사용은 비어 있다.
- 요청/페이지/레코드/응답 바이트 예산과 취소를 검사한다. 429(`Retry-After`)·일시 오류는 `WAITING`으로 반환하고
  worker가 재시도한다. 거절·부분 수집·순환 cursor·잘못된 항목을 빈 목록의 증거로 처리하지 않는다. 감사 로그의 `limit`은
  낙관적이어서 같은 시각의 이벤트로 넘칠 수 있으므로 페이지당 Slack 상한 9,999건까지 받는다(승인 목록은 요청한 크기를 넘으면 거절).
- 체크포인트는 설정 해시·기간·앱 요약·저장 레코드 수를 대조하고, 재개하면 저장된 레코드를 다시 검증해 중복을 막는다.
- 원문 토큰·응답 본문·알 수 없는 필드(이름은 해시 경로만)·설명·링크·아이콘은 보관하지 않는다. 자격증명처럼 보이는
  앱 이름은 앱 ID로 대신하고 누락 사유만 남긴다. 감사 로그의 이메일은 읽지 않는다.
- `proves_completeness`는 정상 종료된 **해당 조직·워크스페이스의 승인 앱 목록**만 뜻한다. 감사 로그는 기간 창이므로
  완전성을 증명하지 않으며, `_compare_runs`는 완전한 승인 목록이 있을 때만 목록에서 빠진 앱을 부재로 본다.

공식 근거(2026-09-28 확인): [admin.apps.approved.list](https://docs.slack.dev/reference/methods/admin.apps.approved.list),
[auth.test](https://docs.slack.dev/reference/methods/auth.test),
[Audit Logs API](https://docs.slack.dev/admins/audit-logs-api/),
[Audit Logs API methods & actions](https://docs.slack.dev/reference/audit-logs-api/methods-actions-reference),
[audit 객체 schema](https://api.slack.com/audit/v1/schemas).
실제 Slack 조직에서의 인증·수집은 검증하지 않았다. 검증 범위는 [구현 기록](../docs/PROVIDER_INVENTORY_IMPLEMENTATION.md)을 따른다.
