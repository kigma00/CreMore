# Slack 브랜치 통합 근거 보고서

분석 대상은 `48ea164345f0df32ec25d0e11af72fccb7786f9a`(이하 **S**), 기준 develop은 `71ea52ad933708b7fb851f590ab7162d7f7ed35f`(이하 **D**)다. 아래 `S:경로:줄`, `D:경로:줄`은 이 고정 커밋의 원문을 가리킨다. 실제 구현과 테스트를 읽고 비교한 결과이며, README의 실서비스 검증 서술은 별도로 구분했다. 브랜치 전환, 병합, 커밋, 푸시, 프로덕션 코드 수정은 하지 않았다.

## 1. 확인 범위와 결론

- S의 **95/95 tracked 파일, 770,877 bytes, 14,863줄**을 모두 읽었다. 읽기 대장 `slack-inventory.json`에 파일별 blob SHA, 크기, 전체 줄 범위가 있다. 대장상 미독 파일은 0개다. LICENSE도 전문을 읽었다.
- 읽은 S 원문을 `slack-source/`에 고정 추출했다. 오프라인 테스트 후 **95개 blob 모두 원 커밋과 동일**함을 SHA-1 Git blob 계산으로 확인했다.
- 원본 `python -m unittest discover -s tests -v`: **196개 통과, skip 0**, Windows Python 3.12.9. 기존 시스템에 Slack SDK가 없어 `slack-deps/`에 slack-sdk 3.44.1만 따로 설치했다. 실제 `.env` 로딩을 막고 공급자 환경변수를 제거했으며, 합성 signing/HMAC만 제공했다. 외부 DNS와 접속은 Python audit hook으로 차단했다. Windows asyncio의 내부 socketpair에 필요한 IP loopback 연결만 허용했다.
- 첫 실행의 6개 오류는 이 분석의 가드가 Windows asyncio 내부 loopback까지 막아서 발생했다. 제품 소스 변경 없이 가드만 고친 뒤 196개가 통과했다. 최초 로그도 `slack-tests-initial-harness.log`에 보존했다. 최종 로그, 명령, 시각은 `slack-tests.log`, `slack-test-result.json`이다.
- 별도로 D/S의 **원본 탐지 엔진을 인증 요청 없이 합성 입력 50개로 비교**했다. D는 RE2 사용, `verify=False`, 외부 접속 차단 상태였다. `slack-passive-parity.py/json`에 방법과 결과가 있다. 이는 후보 탐지 차이의 증거이며 유효한 자격증명 또는 실서비스 지원을 증명하지 않는다.
- Slack은 `app/`의 독립 FastAPI + SQLAlchemy + SQLite/여러 JSON + 단일 프로세스 관리 앱이다. D의 `cremore/` worker/DB/React 대시보드에 이미 연결된 Slack 공급자는 없다. D에는 Slack 토큰, webhook 탐지 규칙과 일반 auth.test 검증 규칙만 있다.
- 보존할 가치가 큰 기능은 메시지 수집, 권한별 수집 범위/부분 실패, 발견 알림, Enterprise 앱, 감사 메타데이터, **명시적으로 연결/관측한 소유 토큰의 수명주기 및 안전한 저장, 재검사, 명시적 교체/폐기**다. `app/` 디렉터리를 복사하는 것만으로 통합 완료가 되지 않는다.
- D가 S 탐지의 상위집합이라는 주장은 틀리다. 전체 규칙 개수와 무관하게 누락 형식과 캡처 범위 차이가 실제 있다. 반대로 S만 채택하면 D의 Slack webhook 및 AWS 구성요소, 디코더, 공통 정책을 잃는다.

## 2. 기능 보존, 통합 결정표

|기능|현재 구현과 연결 상태|D와의 관계|develop_total 통합 결정|
|---|---|---|---|
|현재 메시지 실시간 수집|Socket Mode 수신, Events API 서명 검증, `message_changed` 내부 메시지 처리. 일반 사용자 `text`를 탐지한다. S:`app/socket_mode.py:453`, S:`app/main.py:24`, S:`app/event_processor.py:84`, S:`app/event_processor.py:215`|D collector/job/provider 목록에 Slack 없음|`slack` 연결, 리소스, 스캔 종류를 추가하고 메시지를 D `CollectedObject`와 `ResourceRef`로 변환. HTTP 수신과 Socket 수신이 같은 영속 이벤트/탐지 경로 사용|
|과거 이력/스레드|`conversations.list/history/replies` cursor 반복. public/private, 선택적 DM/MPIM, archived 포함. S:`app/socket_mode.py:118`, `:139`, `:237`|D `Collector`의 failed_objects/authoritative_listing, RequestBudget과 결합 필요|팀원의 실제 페이지, 스레드 순회와 부분 권한 처리를 살려 승인 채널/기간, 요청, 바이트, 시간 예산, 재개 체크포인트 추가|
|부분 권한 진단|통합 types 조회가 missing_scope면 type별 재시도. 접근 불가/부분 수집과 필요한 scope 표시. S:`app/socket_mode.py:176`, `app/scan_coverage.py:16`|D 작업이력/스캔 부분 실패에 넣을 수 있으나 DTO 변환은 새 구현|`unknown/unavailable/partial/complete`를 분리. 미수집 채널을 탐지 없음 또는 노출 해소로 처리하지 않음|
|수동/자동 수집 전환|대시보드 start/stop/scan/monitoring, 900초 기본 주기, 현재 프로세스의 thread, Event 제어. S:`app/dashboard.py:406`, `:489`, `:531`, `app/socket_mode.py:501`|D durable job 방식과 생명주기 충돌|수동 실행, 주기적 이력 재확인, 실시간 subscription을 별도 job/lease로 저장. 대시보드 종료나 세션 만료와 무관하게 운영 상태 유지|
|채널 자동 참여|옵션 활성 시 `conversations.join` 실제 호출. S:`app/socket_mode.py:49`|D 읽기 범위 승인만으로 자동 허용하면 의미 변경|기능은 명시적 연결 정책, 별도 권한/감사 이벤트로 제공. 초기 연결의 묵시적 자동 쓰기로 이식하지 않음|
|발견 알림|SQL AlertDelivery queued/failed/delivered, 발견 메시지에 thread 댓글, 종류별 설명, 토큰 원문, 마스크를 댓글에 넣지 않음. S:`app/slack_client.py:58`, `app/alert_delivery.py:21`, `app/models.py:52`|D 내부 조치/감사와 별도 외부 쓰기|알림 기능 유지. connection+workspace+channel+message+policy 기준 중복키와 영속 outbox/재시도/감사. 과거 이력 대량 댓글은 명시 정책|
|발견 후 조치 추천|provider별 안내와 `pending_manual_review` JSON 큐. 발견된 자격증명을 자동 폐기하지 않음. S:`app/remediation.py:21`, `:38`|D Finding/ManagementAction와 용어, 저장소 중복|D finding drawer/조치 제안으로 옮김. 조치 추천과 실제 실행 상태를 구분. 발견으로 소유 토큰 폐기 권한을 자동 부여하지 않음|
|연결한 토큰의 검증|bot/admin/audit User auth.test, App-Level apps.connections.open. 연결한 토큰만 체크. S:`app/known_token_inventory.py:26`, `:126`|D 연결 확인과 발견 후보 검증을 분리해야 함|D `Connection.credential_evidence`에 연결 건강도. 유형별 checker 유지. 마지막 성공 사실과 최신 조회 실패를 별도로 보존|
|재시작 후 소유 토큰 모니터|DPAPI token store, HMAC key/config 저장, OwnedTokenSupervisor를 FastAPI lifespan에서 시작. S:`app/owned_token_supervisor.py:24`, `app/dashboard.py:1046`|D worker/secret_ref로 재구현 필요|모니터 기능 유지하되 DB 스케줄/lease 및 D 비밀 참조 체계로 이동. 수집기 stop과 토큰 모니터 stop의 의미를 UI에서 분리|
|관측 사용자 표시 이름|검증된 bot workspace와 같은 workspace에서만 users.info, 이름의 credential 패턴 제거, 하루 refresh. S:`app/authorized_user_names.py:20` 및 `app/token_lifecycle.py:193`|D principal/사용자 표시와 연결 가능하지만 발급자 증명은 아님|이름, 조회시각, users.info 출처를 보존하고 email을 새로 수집하지 않음. authorized user/업무 owner/내부 발급자를 섞지 않음|
|OAuth 신규 응답 수집|state 10분, 일회적 파일 claim, 앱 ID 검사, DPAPI에 토큰을 보존한 뒤 metadata 기록, User scopes용 승인 URL. S:`app/oauth_capture.py:99`, `:149`, `:231`|D의 기존 연결/RBAC에 Slack OAuth callback/state를 신규 구현. D GitHub App 인증은 OAuth callback 기반이 아님|팀원 provenance/일회성 state/영속 저장 우선 의미를 유지. D 세션, 역할, 대상 connection에 state를 결속하고 공유 DB에서 consume. Bot용 승인 UI도 필요하면 명시 확장|
|토큰 수명주기|10가지 type, source/last_observation_source, actor/time의 근거, family/rotation parent, 상태 이력, 시간 경과 만료. S:`app/token_lifecycle.py:31`, `:267`, `:368`, `:539`, `:593`, `:621`|D 일반 CredentialStatus만으로는 정보 손실|확장된 provider credential observation/event 테이블로 보존. Credential의 현재 상태는 이력에서 산출. raw가 없는 관측도 저장. family는 로컬 추론 관계이며 Slack installation ID와 구분|
|수동 portal import|configuration access/refresh와 User token. app/issuer/time/pairing을 확인한 것처럼 만들지 않음. S:`app/configuration_token_import.py:29`, `app/portal_user_token_import.py:20`|D 연결 입력, 비밀 저장/API 역할에 수용 가능|기능 유지. 선언/관측/검증 evidence를 분리. import 직후 observed_unverified, 명시 검증 사실만 승격. 같은 key/reimport, terminal 상태 보호|
|OAuth/configuration 교체|oauth.v2.exchange, oauth.v2.access refresh, tooling.tokens.rotate 라이브러리. 오류 시 새 토큰을 호출자가 안전하게 복구하도록 redacted repr 결과 객체. 자동 scheduler/일반 dashboard route는 없음. S:`app/oauth_rotation.py:1`, `app/tooling_rotation.py:1`|D generic rotation UI만 연결해 자동화 완료라 할 수 없음|명시적 소유, 앱/워크스페이스, 정확한 토큰 관계를 확인하는 action adapter. 교체 API 성공 후 저장 실패 recovery와 재시도 불가/불확정 상태를 설계. 평소 검증은 refresh를 소비하지 않음|
|OAuth token revoke|정확한 HMAC와 관측 type/source, portal app 확인. 기본 dry-run도 Slack auth.revoke(test=1)를 실제 호출. 장기 bot은 대상 아님. S:`app/token_revocation.py:44`|D 조치 승인/감사 모델에 연결 가능. 현재 일반 조치 경로에 연결되지 않음|팀원 제한을 그대로 typed action capability로 보존. 대상별 사전 확인, 승인, 실행, 결과/불확정, 감사를 연결. dry-run의 실제 외부 호출 사실 표시|
|Service token CLI|절대경로 Slack CLI, ticket/challenge 발급, auth.test best effort, DPAPI 보존. revoke는 commit 없으면 호출하지 않음. 원문이 CLI process argument로 전달되는 제한 명시. S:`app/service_token_cli.py:54`, `:165`|D Linux 최소 이미지에 Slack CLI 없음|로컬/운영자용 명시 도구로 보존. CLI 설치, 실행 파일 검증, 원문 프로세스 인자 노출 경계를 해결하기 전 웹 공용 revoke 버튼에 임의 연결하지 않음|
|Workflow token 관측|서명/Socket 이벤트 function_executed의 xwfp, 앱/워크스페이스/실행 ID 및 actor basis. event_time+15분은 정책상 만료 상한, 실제 발급시각 아님. S:`app/workflow_lifecycle.py:16`, `app/token_lifecycle.py:593`|D에 동등한 모델 없음|관측 기능 보존. 임시 토큰 자체를 일반 발견 토큰으로 오인하지 않음. lifecycle evidence에 정책 만료와 실제 검사시각 구분|
|Workflow 실험 완료|정해진 `cremore_token_probe` callback만 functions.completeSuccess 쓰기 수행, 중복 방지 기록. S:`app/workflow_probe.py:20`, `:40`; 예시 YAML|운영 콘텐츠 수집과 다른 실험 action|테스트 전용 모드로 보존. 운영 앱의 임의 function 실행 자동 완료 기능으로 확장하지 않음|
|Enterprise 승인 앱 목록|admin.apps.approved.list cursor. approved_for_install≠installed; approval actor≠owner. S:`app/slack_admin_inventory.py:67`, `:94`|D source inventory와 다른 관리 메타데이터|Slack 관리 인벤토리 하위 화면/API에 provenance 그대로 수용. 라이선스/역할/워크스페이스 접근 가능 범위를 명시하고 미설정도 빈 성공 목록과 구분|
|Enterprise 감사, 설치 이벤트|AuditLogs 액션 allowlist, API checkpoint/1시간 overlap/ID dedup. app_installed/app_uninstalled_team Socket events, 앱+워크스페이스와 시간순 결합. S:`app/slack_audit.py:72`, `:121`, `app/slack_app_events.py:37`|D 사용자 활동 감사와 공급자 감사는 다른 사건|외부 provider event 저장, 조회 모델로 통합. D 내부 actor audit와 origin 구분. HTTP 경로도 설치 이벤트를 같은 경로로 라우팅|
|Developer portal 메타데이터|수동 관측 JSON allowlist→combined snapshot. 실제 portal scraper/API 수집기 아님. S:`app/slack_snapshot.py:171`|등록 정보/선언 입력으로 수용 가능|`manual/imported` evidence로 남김. API 실측으로 표시하지 않음|
|별도 Vault/클라우드 메타데이터|AWS list_secrets, GCP list_secrets, Azure list_properties_of_secrets, Vault KVv2 metadata만. 명시 --include-secret-managers에서 실행. S:`app/cloud_secrets_inventory.py:48`, `:96`, `:143`, `app/vault_inventory.py:51`, `app/security_inventory.py:75`|D 이미 AWS/GCP/Vault/OpenBao coverage 별도. Azure는 D ConnectionSpec에 없음|같은 공급자를 중복 앱으로 운영하지 않음. metadata/lifecycle 추천을 D coverage adapter에 흡수. Azure 메타데이터 기능은 누락 없이 별도 capability로 수용하되 value match 완료로 표시하지 않음|
|통합 snapshot/export|발견, 승인 앱, 감사, 설치 이벤트, developer metadata, known token/lifecycle, 수집 범위의 출처/시간과 한계를 결합. S:`app/slack_snapshot.py:353`|D API/DB projection로 만들 수 있음|JSON의 provenance/empty-vs-not-collected 의미와 안전한 export를 보존. 복수 JSON을 별도 진실 원장으로 유지하지 않음|
|평문 개발 캡처|raw candidate `value`를 로컬 JSON 저장, 전체 메시지는 저장하지 않음. CLI default false이나 dashboard default true. S:`app/plaintext_capture.py:43`, `app/dashboard.py:61`|D sanitized finding/secret_ref 원칙과 충돌|일반 운영 수집의 평문 보관은 끔. 필요한 개발용 capture는 격리된 로컬 테스트 기능과 명시 정책, 보존 기간으로만 보존. 운영 UI, 로그, DB에 원문을 섞지 않음|
|로그 초기화|정지 확인 후 SQL finding/alert/sender와 capture/queue/coverage 정리, 기본 processed ledger 유지. S:`app/dashboard.py:604`; 테스트 :673|D 감사와 노출 이력 연속성 파괴 가능|사용자 화면 필터/보존정책, 명시 관리 작업으로 설계. 기존 clear를 공용 버튼으로 복제하지 않음. 보존/삭제 범위, 중복 ledger 영향, 감사 기록과 트랜잭션 경계 필요|
|로컬 테스트 bridge, 전송|loopback/Host/Origin/CSRF 제한 test bridge, RSA OAEP Node handoff, stdin receiver/recovery, disposable User revoke helper. S:`app/token_test_bridge.py:64`, `scripts/token_transfer.mjs:1`, `app/token_transfer_receiver.py:24`, `app/test_user_token_revoke.py:20`|운영 백엔드 계약 아님|회귀 QA/로컬 migration 보조로 보존. 공용 API route로 노출하지 않음. Node/Windows python 경로와 입력 크기 제한을 별도 정리|

## 3. 탐지 규칙 16개 비교와 보존 정책

S의 모든 규칙은 `app/detector.py:26-78`, exact-span 우선 분류는 `:88-109`, placeholder 제외는 `:112-114`다. D는 `cremore/detection/catalog.py`, 공통 FP/decoder/RE2 engine을 쓴다. 아래의 permissive 형식은 조직 콘텐츠에서 검토할 **후보**로 보존하되, provider가 유효하다고 보증하는 형식이나 자동 검증 대상이라고 승격하지 않는다. 출처 규칙 ID, 원 분류, 통합 canonical type과 신뢰도를 같이 보존한다.

|S rule|D 근거|확인된 차이, 통합 요구|
|---|---|---|
|github_token, gh[pousr] 최소30|D catalog:431-436, 정확36|30자 형식은 S 양성/D 음성, 36은 둘 다 양성. S의 permissive 관측을 review rule로 보존. canonical GITHUB_TOKEN과 legacy provenance|
|github_fine_grained_token 최소30|D catalog:433-435, 22_59 구조|단순30 payload는 S만 양성. 정상22_59는 둘 다. 기존 짧은/불완전 후보도 사라지지 않도록 원 규칙/partial evidence 보존|
|aws_access_key_id AKIA/ASIA16|D catalog:346-367 및 AWS pair 구성|식별자 단독 포착은 둘 다. D는 type-domain을 넣어 ID/SAK/pair를 구분. S의 high confidence가 ‘실제 사용 가능’은 아님. D material_kind, 점수, 부분 구성요소 의미 유지|
|slack_token|D catalog:500-505|xoxb/a/p/r/s는 D에도 있음. **xoxc, xoxd, xwfp, xoxe refresh는 S만 양성. xoxe.xoxb / xoxe.xoxp는 D가 내부 xoxb/p 부분만 포착**. S 전체 캡처를 우선하고 suffix 중복 제거. xapp는 D가 더 엄격한 구조, xox token D 길이 상한72. 포맷/역할은 lifecycle 발급 출처 없이 과도하게 추정하지 않음|
|openai_api_key sk(-proj) 최소20|D catalog:467-472|D는 내장 T3BlbkFJ 구간을 요구, S는 더 넓음. 없는 예시는 S만 양성. broad sk를 모든 경우 OpenAI 확정으로 분류하지 않고 기존 관측 보존 및 검토 근거 표시|
|google_api_key AIza+35|D catalog:370-374|합성 정상 형태 둘 다 같은 전체값. google_api_key→GCP_API_KEY 매핑|
|gitlab_token glpat 최소20|D catalog:437-441 정확20|20은 둘 다, 26 payload는 S만. 정확한 공급자 형식 추가는 다른 GitLab 브랜치와 함께 결정. permissive 관측도 보존|
|npm_token 최소30|D catalog:546-550 정확36|30은 S만,36은 둘 다. 기존 관측/명확한 형식 구분|
|stripe_api_key sk/rk live/test 최소16|D catalog:444-448 live 최소24|S의 **test**, 짧은 live 후보가 D에서 사라짐. test mode를 명시하고 후보를 보존; test와 live 위험도를 같게 취급하지 않음|
|sendgrid_api_key 두 payload 각최소20|D catalog:512-516 정확22, 43|20, 20 예시 S만. canonical 구조와 permissive 후보 구분|
|telegram_bot_token 숫자8-10 + payload최소30|D catalog:538-543 AA접두32-33, keyword filter|AA가 없는 합성 예시 S만. D keyword 전처리도 비교 대상. S의 standalone 관측을 잃지 않도록 parity test|
|json_web_token 세 구간 각최소8|D catalog:643-649 두번째도 eyJ, 최소10|두번째 JSON prefix가 없는 예시 S만. JWT 여부/비밀 여부는 별도 evidence. 원값 유효성 증명 아님|
|bearer_token opaque20|D catalog에 같은 generic Bearer rule 없음|prefix 없는 bearer 예시 S만. 명시 contextual rule로 이식, 크기 제한/FP annotation 포함|
|generic_credential_assignment|D catalog:1364-1414|S에는 refresh_token, Slack app/bot/user token 라벨, signing/client secret 포함. **refresh_token, Slack app/bot/user opaque는 11/24자 모두 S만**. signing/client secret 11자 S만,24자는 D generic secret과 겹침. S는8+, 일부 placeholder drop, D는 분류별 min/max, literal/reference, entropy 정책. 키워드만 병합하지 말고 캡처/quote/경계/표현식 의미까지 회귀|
|database_uri_password|D catalog:635-642 DB_CONNECTION_STRING|S는 비밀번호만, D는 userinfo+host URI. **서로 지문 재료가 다름**. S legacy password만으로 full URI credential을 구성하면 안 됨. 원문 재수집 전에는 password-component/legacy 타입 보존|
|pem_private_key|D catalog:650-657|S arbitrary key header, 0..20k body, D 정해진 종류, 최소50, 선언 span8192. 30자 body는 S만. **9,000자 body 테스트는 둘 다 전체 캡처**였으므로 span8192만 보고 D가 모두 잘라낸다고 쓰면 안 됨. RE2의 counted-repeat 제한을 고려해 bounded scan/검증으로 의미를 옮김|

역방향 누락도 있다. bare Slack incoming webhook는 **D만 양성**이었다(D catalog:507-510). D 공통 decoder, AWS 부분키/조합, false-positive 정책, 위험 점수/검증 연속성은 S 앱으로 교체하지 않는다. 서로 다른 역할의 토큰을 regex 접두만으로 무조건 auth.test 호출 대상으로 묶어서도 안 된다. D 현재 HTTP verify spec은 Slack `ok:false` 전체를 rejection marker로 사용한다(D:`cremore/detection/verify/http.py:114-117`). S 연결 checker의 invalid_auth / token_expired / missing_scope / transport 구분을 보존하고, **이 분석에서는 발견 후보에 대한 라이브 호출을 전혀 수행하지 않았다**.

## 4. 데이터, 동작 충돌과 필요한 수정

### 4.1 Credential identity와 기존 데이터

S `app/repository.py:17-18` 및 token store/lifecycle은 `HMAC(key, raw)`다. D `cremore/detection/fingerprint.py:14-29`는 `HMAC(key, b'cremore-credential-fingerprint-v1\x00' + material)`이다. domain 끝은 NUL 1바이트이며 문자 역슬래시와 숫자 0이 아니다. AWS partial material에는 추가 type domain이 있다(D engine:371-390). 키가 같아도 동일 지문이 아니며, old HMAC에서 새 HMAC를 계산할 수 없다.

통합 import는 `(legacy_source_sha, legacy_store_id, legacy_record_id, fingerprint_scheme, key_epoch)`를 보존하고 멱등 키로 삼아야 한다. DPAPI의 원문이 **해당 Windows 보안 컨텍스트에서 복구 가능한 명시 소유 토큰**은 그 환경에서 메모리 재지문, D secret backend 재암호화 후 원문을 버린다. 원문 없는 findings는 독립 legacy 관측으로 가져오고, 마스크/짧은 token_id(대시보드에는12자)를 identity로 쓰지 않는다. 64자 full HMAC도 스킴, 키, material이 다르면 직접 equality join하지 않는다. 메시지/원문을 나중에 정당한 범위에서 재관측했을 때에만 확정 alias를 만들 수 있다.

S SQL에는 processed_events, credential_findings, sender_metadata, alert_deliveries만 있고 tenant/connection/run/workspace 파티션이 없다(S:`app/models.py:13-62`). `history:{channel}:{ts}`도 installation/workspace가 빠져 있다. D의 source_connection_id 및 source_scan_id 모델(D models:98-128)에 명시적으로 매핑한다. source와 credential provider는 별도다: Slack 메시지 속 AWS 키는 source_type=slack, credential provider=aws다.

권장 리소스 식별은 installation/connection + team_id + channel_id + message_ts, content revision은 편집 시각 또는 canonical content hash다. thread root/author/origin(history/events)/visibility/관측시각은 안전한 metadata로 남긴다. `private Slack channel`을 public 인터넷 노출과 같은 exposure로 치환하지 않으며 Slack Connect/DM/승인한 workspace 접근 조건은 별도 분류다. URI/permalink를 만들더라도 사용자 입력 URL로 credential을 전송하지 않는다.

### 4.2 실시간/이력의 일관성

- S 실시간, 이력 event ID가 달라 같은 메시지 finding이 두 번 생긴다. 댓글은 channel+ts로 줄이지만 finding identity는 아직 통합되지 않았다(S event_processor:98-110; 관련 테스트는 이를 전제로 함). 이벤트 delivery dedupe와 content revision dedupe를 분리해야 한다.
- S는 secret 없는 메시지도 processed로 기록한다. 같은 history ID를 재수집하면 새 탐지 결과를 계산해도 SQL finding을 추가하지 않는다(S event_processor:112-144). 따라서 오프라인 중 편집된 과거 메시지에 새 노출이 생겼을 때 이력 스캔이 놓칠 수 있다. 문서 버전별 upsert/관측을 설계해야 한다.
- 자동 이력 재확인은 기본 두 interval(30분) 범위다(S socket_mode:513-525). 그보다 오래된 root에 새 reply가 달렸을 때 root가 최근 history에 없으면 polling만으로 못 찾는다. durable event ingest + watch thread/reconcile 범위 정책을 명시해야 하며 전체 조직/전기간 완전수집이라고 표시하면 안 된다.
- Socket Mode는 ack 후 처리한다(S socket_mode:459-464). ack 직후 프로세스가 죽으면 공급자 재전송을 기대하기 어렵다. 큐/DB의 영속 수신 후 ACK, 제한된 처리시간, backpressure, 중복 처리 테스트 필요.
- daemon thread per alert와 처리 직후 송신/상태쓰기 사이에 중복, 유실 창이 있다(S socket_mode:34-46, alert_delivery:21-36). DB outbox, claim/lease, 알림 dedupe를 D worker에 연결한다.
- 429 Retry-After 처리/지속 체크포인트가 명시되어 있지 않다. SDK의 모든 기본값을 운영 보장으로 간주하지 말고 HTTP/Socket endpoint별 제한, 타임아웃, 재시도와 부분 실패를 integration test한다.
- bot_id/subtype 메시지를 건너뛰므로 bot 게시/일부 file-share 텍스트를 포함한 모든 콘텐츠를 지원하지 않는다(S event_processor:84). 파일 첨부 본문, canvas, blocks/attachments 다운로드 수집기는 없다. 이를 수집 범위 UI에 정확히 적고 이후 확장을 별도 capability로 설계한다.

### 4.3 수명주기, 검증 연속성

토큰 status는 공급자 자격증명에 대한 관측이고 dashboard 로그인 세션/수집용 토큰 상태와 독립이다. S가 가진 `issued_at_basis`, `expires_at_basis`, `authorized_user_id_basis`, `last_checked_at`, `last_observed_at`, `status_history`, source/last_observation_source, family/parent를 모두 보존한다. 알 수 없는 issuer/issue-time는 null이다. 로컬 import 시각, Slack 정책 상한, Slack 실제 응답 iat/exp를 같은 값으로 취급하지 않는다.

`sync_connected_inventory`에는 오래된 snapshot이 최신 check를 덮어쓰지 않는 방어가 있고 테스트도 있다(S token_lifecycle:638-675; test_token_lifecycle:232). 그러나 일반 `observe_token`은 `last_observed_at`만 max로 합치고 status/last_checked_at에는 같은 guard가 없다(S token_lifecycle:304-356). 새 이벤트 모델에서는 observed_at/check_at/source priority에 따라 현재 상태를 산출하고 늦게 온 사건도 이력에는 남겨야 한다. transport/missing_scope 실패는 마지막 성공 검증 증거 삭제가 아니며, time-expired, rotated, revoked, completed의 근거가 다르다.

S lifecycle reader는 JSON 오류/읽기 실패/wrong kind를 빈 원장으로 바꾼다(S:174-183). 이후 쓰기에서 기존 이력이 덮어써질 수 있으므로 import/운영 데이터 저장은 오류를 ‘자료 없음’으로 삼지 않아야 한다. 이력은 현재 최대30건, known-check history는20건이므로 기존 제한을 감사 전체 이력 요구로 오인하면 안 된다.

S의 `app/file_lock.py`는 Windows msvcrt/POSIX fcntl advisory lock을 제공하고 lifecycle 및 encrypted store의 교차 프로세스 갱신을 보호한다. 두 프로세스가 합성 토큰24개를 모두 보존하는 원본 테스트도 통과했다. 그러나 이것을 분산 DB transaction 또는 모든 JSON 파일의 동시성 보장으로 확대해 설명하면 안 된다. atomic 파일 rename, 프로세스 thread lock, 파일 lock, 원격 replica 간 lease는 서로 다른 보장이다.

소유 토큰과 발견 토큰은 별도 권한 영역이다. 연결/발급/import한 토큰의 확인, 교체, 폐기 수단을 보존하되, Slack 메시지에서 얻은 후보를 소유 토큰 저장소에 자동 등록하거나 여러 후보를 무차별 조합하여 라이브 호출하는 흐름을 만들지 않는다. regex만으로 service/user/configuration token의 소유, 발급 관계를 단정하지 않는다.

### 4.4 Vault 연계와 제품 목표

S의 own-token inventory/lifecycle은 `observed_or_connected_tokens_only`다(S token_lifecycle:187). 조직이 발급한 모든 Slack 토큰이나 모든 관리자 계정에 접근해 전체 발급 목록을 수집하는 기능이 아니다. 승인 앱 목록도 설치/토큰 보유 사실의 전수 대장이 아니다.

사용자가 원한 중심은 외부 Vault 관리와 노출의 교차 판정이다. 따라서 Slack 소유 토큰 관리 기능을 ‘회사 발급 대장’으로 중심화하지 말고 **연결 자격증명/명시 관측의 선택적 증거원**으로 통합한다. 회사 외부 Vault에 관리됨, CreMore가 자신의 연결에 암호화 보관함, 목록에서 메타데이터만 확인됨, 값이 일치함, 권한 없어 모름은 각기 다른 상태다.

S cloud/Vault 메타데이터 수집만으로 ‘이 노출값이 Vault에 있다/없다’를 판정할 수 없다. D `coverage.ConnectionSpec`의 AWS Secrets Manager/Vault/OpenBao/GCP 등과 canonical scheme을 공유하는 값 지문 관측 경로를 사용하고, 미조회/부분 수집/신선도 만료에서 ‘관리 안 됨’ 단정이 나오지 않도록 한다(D coverage models:16,64-80). Azure metadata-only 목록은 해당 capability 자체로 보존하고 value correlation은 별도 구현 범위다. S의 기간별 rotation/expiry 추천은 metadata evidence로 보존한다.

## 5. D 계약에 수용할 위치

현재 존재하는 파일/계약과 새로 필요한 변경을 구분한다.

|영역|기존 D 계약/파일|Slack 수용 시 필요한 변경|
|---|---|---|
|공급자 연결|`cremore/domain/connections.py:23-28,35-73,86-123`, `Connection` models:149-170|slack provider/config 검사/job_kind, workspace/enterprise/app identifiers, 모드, 승인 channel 범위, 선택 feature 정책. config에 raw secret 저장 금지|
|secret resolution|`cremore/secretstore/resolver.py:49-104`, `sealed.py:47-68`|기존 sealed helper는 **단일 token** JSON만 쓴다. Slack bot/app/signing/admin/audit/OAuth/config refresh 슬롯을 그냥 token 하나에 합치면 안 됨. 역할별 reference와 typed resolver/secure backend write/CAS/recovery 계약 추가|
|collector|`cremore/collectors/base.py:17-26,52-97`, `worker/factory.py:25-119,122-212`|slack content adapter, request budget, max size, failed_objects, authoritative_listing, approved channel scope, manual/delta/realtime job 분리|
|탐지|`cremore/detection/catalog.py`, `engine.py`|50-case parity를 수용하고 S 원래16개 rule을 모두 매핑. 전사 공통 탐지 엔진에서 원 분류/format provenance와 canonical material 보존|
|DB|`Credential`, `Exposure`, `Finding`, `Connection`, `ManagementAction`, `FindingEvent`|content observation은 기존 모델, Slack installation/token lifecycle/provider audit/event inbox/outbox, checkpoint 등 새로운 fact는 migrations로 확장. 단순 임의 JSON 필드에 모든 의미를 숨기지 않음|
|coverage|`cremore/coverage/models.py`, collect/store/correlation 경로|managed inventory와 exposure 동등성에 필요한 scheme/evidence/source freshness를 맞춤. 소유 토큰 presence 자체는 외부 Vault value match가 아님|
|인증/권한|`cremore/api/auth.py:1-34` viewer/analyst/remediator/admin, OIDC/shared local auth|모든 신규 read/write route는 D의 역할에 연결. callback/event는 provider-authenticated 공개 수신만 최소 노출. loopback check는 인증/권한의 대체가 아님|
|대시보드|`web/app/provider-registry.ts:14-24,26-68`, connection-ui/scan-scope/scan-activity/credential-management/governance/audit 영역|공급자 descriptor/아이콘, 연결 단계, 스캔 범위, 작업 상세, 메시지 노출 위치, own token lifecycle drawer, Enterprise metadata 화면에 수용. S HTML iframe 병치는 통합이 아님|

D에 이미 Slack `ui-primitives` 표시 라벨은 있지만 ProviderDescriptor union/PROVIDERS에 없다. 백엔드 provider 허용 목록 및 secret resolver/factory도 없다. 아이콘만 추가하는 것으로 활성화되지 않는다. D의 일반 connection metadata 하나만으로 S 다중 credential role와 async state 관리를 끝낼 수 없다.

대시보드는 기존 밀도/페이지네이션, 필터, 상세 drawer를 따르고, 연결 상태, 콘텐츠 수집 범위, 관리 인벤토리 조회 상태, 소유 토큰 검증 상태를 나란히 보여준다. S 현재 findings500/apps500/audit100 상한과 3초마다 8개 API Promise.all은 큰 조직에서 목록 누락/한 API 실패의 전 화면 영향이 있으므로 pagination, 개별 fetch error, 취소/갱신 정책으로 바꾼다. legacy clear 대신 내부 감사 연결을 유지한다. 내부 audit actor와 Slack actor, approval actor, owner, authorized user도 구분한다.

## 6. 의존성, 라이선스, 배포의 실제 충돌

고정 커밋 `merge-tree` 결과 실제 충돌 파일은 `.env.example`, `.gitignore`, `LICENSE`, `README.md`, `requirements.txt`다. Python 패키지 경로가 다르므로 생산 코드에 textual conflict가 적은 것이 아키텍처가 양립한다는 뜻은 아니다.

|파일/경계|객관적인 사실|통합 결정|
|---|---|---|
|LICENSE|D는 Apache License 2.0 전문(201줄), pyproject도 Apache-2.0. S는 GNU GPL v3 전문(674줄)|임의 ours/theirs 교체 금지. 코드별 출처/공지 보존과 원저작자, 팀의 통합 배포 라이선스 결정을 기록해야 함. 이 보고서는 법적 호환 가능 여부나 재라이선스 권한을 단정하지 않음|
|requirements.txt|S 6개 범위: fastapi>=0.115,<1; uvicorn[standard]>=0.30,<1; SQLAlchemy>=2,<3; psycopg[binary]>=3.2,<4; slack-sdk>=3.36,<4; python-dotenv>=1,<2. D는 pyproject로 생성한 해시 잠금 파일|D pyproject에 필요한 SDK를 통합하고 lock 재생성/pip check/SBOM. S requirements로 덮으면 reproducibility, 나머지 dependencies 소실. uvicorn standard extras가 Slack Socket SDK에 정말 필요한지 별도 검토; 그냥 extras 추가 불필요|
|현재 잠금과 검증 환경|D locked fastapi0.141.1/uvicorn0.52.4/python-dotenv1.2.3/sqlalchemy2.0.52. 이번 테스트 host는 fastapi0.128.2/uvicorn0.52.0/python-dotenv1.2.2/sqlalchemy2.0.52/psycopg3.3.5, SDK3.44.1|196 통과는 현 host 증거. D 최종 lock/Python3.14 Linux 조합은 아직 테스트하지 않았고 integration gate에 포함|
|optional cloud SDK|S requirements-cloud: boto3>=1.35,<2, google-cloud-secret-manager>=2.20,<3, azure-identity>=1.17,<2, azure-keyvault-secrets>=4.8,<5|D AWS/GCP existing adapter 중복 회피. Azure metadata capability 사용 시만 적합한 optional dep. SDK 실제 통합 테스트는 이번 196 fake suite와 별도|
|.gitignore|S는 .env/.venv/__pycache__/pyc/*.db/.local 6줄. D는 .env.*, 키파일, DB, logs, work, web output 등 훨씬 넓음|D 보호 규칙을 유지하고 S `.local/`를 명시 추가. 평문 capture, DPAPI, OAuth state, RSA transfer 파일 모두 ignored/protected. S theirs만 선택하면 기존 보호가 사라짐|
|.env.example|S는 signing/HMAC와 bot/app/admin/audit/OAuth/config, interval/output file, optional cloud manager 구성. D FINGERPRINT_KEY와 다름|새 설정은 D typed settings/secret_ref 정책에 매핑. HMAC key를 connection마다 UI 입력해 제각각 identity 만들지 않음. 실제 .env는 분석, 복사, 출력하지 않음|
|Windows DPAPI|`app/owned_token_store.py:54-56,110-111`은 sys.platform!=win32에서 거부. local config/runtime key도 DPAPI. capture_from_env는 secure store 없으면 구성되지 않음(:261-263)|네이티브 Windows 소유 토큰 지속관리와 메시지 수집 자체의 플랫폼 지원을 구분. 기존 토큰 DB를 Linux에 파일 복사해도 복호화 가능한 것이 아님|
|Docker/EC2/EKS|D Dockerfile은 Chainguard Linux minimal 이미지, 주석상 Python3.14(`deploy/docker/python.Dockerfile:4-8,32`). Slack branch 자체 Docker/K8s manifest 없음|Windows 위 Docker Desktop의 Linux 컨테이너도 DPAPI 사용 불가. portable secret backend와 API/worker 분리, 스케줄/lease, DB migration 후 검증. SQLite/JSON을 공유 PVC에 놓는 것만으로 multiworker 완료 아님|
|callback/UI 공개|S dashboard 일부 read/start/stop은 auth/loopback guard 없음(`app/dashboard.py:1081-1118,1256-1294`). OAuth callback-only 서버는 별도로 좁게 구성(`app/oauth_callback_app.py:29-76`)|S local dashboard를 기업 인그레스에 그대로 노출하면 안 됨. D 인증 UI/API에 이식하고 callback/event 수신 경로만 별도 provider 인증. proxy forwarded client/Host 의미도 검증|

S README의 disposable OAuth User issue/exchange/refresh/revoke 실측 서술은 팀원 보고다. 이 분석이 재실행한 것은 아니며, 실제 Enterprise 권한, 공개 OAuth redirect, Workflow 플랜, Service CLI 실운영은 **미검증**이다. `SLACK_TOKEN_INVENTORY.md:3`의 App-Level 미검증 표기는 최신 코드가 apps.connections.open을 호출하는 것과 달라 현재 동작 설명으로 그대로 가져오면 안 된다.

## 7. 통합 순서와 완료 기준

1. **출처, 라이선스/스키마 결정**: 고정 SHA 보존, feature/rule matrix와 import manifest 확보. 라이선스 결정을 기록하고 팀원 기능별 목적지/보존 형태를 확정한다.
2. **수동 콘텐츠 수집**: Slack typed connection, secret slots, approved channels, collector, common engine, DB/대시보드 조합. 기존 S partial scopes/history/replies/manual semantics와 16 rules를 보존한다.
3. **영속 실시간/주기 실행, 알림**: signature/event inbox, Socket lease, ACK/queue 경계, checkpoint, outbox, 정책/RBAC/감사. edited history/old-thread-reply/권한 철회/재시작 회귀.
4. **소유 토큰 metadata, secure storage, 모니터**: Windows import와 portable backend, evidence history, status continuity, typed check. Enterprise inventory/audit와 별도 coverage.
5. **명시 issuance/import/rotation/revoke**: 안전한 저장/복구와 provenance를 통합해 기존 teammate 기능을 노출. Service/Workflow/test bridge는 적합한 로컬/QA 면으로 보존. 자동 실행 범위를 발견 후보까지 확대하지 않음.
6. **운영 배포, 마이그레이션 리허설**: 최종 locked 환경과 Linux container/EC2/EKS 모델, 다중 workspace/동시 worker, 롤백, 보존, 감사, UI 대량 목록 검증.

각 단계에서 ‘팀원 기능 보존’은 capability parity로 확인한다. 독립 HTML, 전역 JSON, 위험한 기본값을 그대로 보존하는 것이 기능 우선의 뜻은 아니다. 초기 범위를 줄일 경우 삭제처럼 숨기지 말고 마지막 표에서 의도된 보존 위치/후속 gate를 명시한다.

필수 acceptance gates:

- 16개 S rule positive cases와 D-only webhook/decoders/AWS partial가 모두 유지되고, rotating Slack token이 suffix로 잘리지 않는다. 발견 수뿐 아니라 full material HMAC, classification, redacted span을 비교한다.
- 같은 이벤트 재전송/실시간+history/편집/동일 메시지 다른 workspace/여러 connection에서 정확한 occurrence identity와 단일 알림. 새 credential이 생긴 편집은 놓치지 않는다.
- cursor page/replies, archived, DM scope, missing_scope fallback, 429, timeout, API outage, cancel, budget exhaustion에서 완료/부분/실패와 미수집 항목이 정확하다.
- checkpoint 도중 종료, ACK 직후 종료, outbox 송신 직후 종료, 동시 worker, 가동 후 재시작에서 무음 유실/무한 중복 방지. 이전 complete inventory를 partial로 덮어서 ‘노출 없음’을 만들지 않는다.
- 관리 UI 세션 만료, 수집 credentials 만료, 토큰 확인 실패가 기존 노출/검증 증거/점수, 이력을 지우지 않는다. 늦게 온 snapshot과 terminal status 보호.
- own-token 검사는 refresh를 소비하지 않으며 유형별 반환 상태를 보존. app-level WebSocket URL/manifest/full provider error/실제 raw token이 UI, 로그, 예외/422 validation body, 감사, snapshot에 나타나지 않는다.
- OAuth state 일회성/만료/앱, workspace, connection, 운영자 binding, callback 재시도, 저장 실패, 교체 성공/저장 실패, 불확정 응답 recovery. 새 secret durable before successful completion.
- 연결 bot이 rotating bot 형태일 때 onboarding과 owned token store가 처리하도록 보완(현재 S dashboard:416 및 owned_token_store:165-181은 xoxb만 허용). token refresh 교체가 실제 수집 clients의 다음 요청에도 반영된다.
- 정확한 owned token/app/source/권한, 승인, 감사가 없으면 revoke/rotate/join/chat write가 발생하지 않는다. auth.revoke dry-run과 Service revoke dry-run의 서로 다른 외부 호출 의미 표시.
- DPAPI migration은 원래 Windows context에서 수행, wrong-key/corrupt file/partial import에서 원본과 이력 보존. masked-only/legacy fingerprint는 잘못 cross-correlate하지 않는다.
- 복수 JSON/SQL import가 원본 count/history/provenance를 보존하고 재실행해도 중복 없음. 원장 읽기 오류가 empty-success가 되지 않는다. rollback 방법과 import batch audit가 있다.
- 기업 외부 Vault 없음/권한 없음/미조회/부분 조회/신선도 만료를 구별. own store presence나 metadata row만으로 Vault value-managed/NOT_FOUND를 선언하지 않는다.
- D RBAC/OIDC local/hosted 인증 전 범위 적용, 익명 관리 요청 차단. 공개 callback과 관리 API 분리. no plaintext default, 로그/오류 redaction, backend별 비밀 회전/복구 증거.
- 대시보드 대량 pagination/부분 fetch 실패/작업 상세/필터, drawer 접근성 및 기존 source provider 회귀. S 원본196개를 적합한 D contract tests로 이식해 의미 변화를 명시.
- 최종 dependency lock, Python3.14 Linux container, PostgreSQL migrations, restart/leader lease를 검증. 현재196 통과를 이 최종 통합 검증의 대체로 사용하지 않는다.

## 8. 증거 산출물

- [전체 판독 대장](source-inventory.csv): 고정 95개 파일의 blob, 범위.
- [수동 검증 없는 탐지 비교](passive-detection-comparison.csv): 합성 50개의 type, 캡처 동등성, 원문 값 제외.
- [검증 기록](verification.md): 원본 테스트, 환경, 격리 방법, 한계.
- 조사 과정의 source snapshot, 상세 로그, 가드, 재현 스크립트는 git 제외 `work/integration-review/`에만 보관했다. 운영 데이터가 아니다.

이 검증은 정적 코드, 원본 오프라인 테스트, passive 탐지 비교다. 실제 Slack/GCP/AWS/Azure/Vault API, 회사 credential 상태, 고객 DB/log, 라이브 이벤트, OAuth 교체/폐기는 호출하거나 읽지 않았다.

## 9. 공식 문서 대조 보완

2026-09-21 Slack, AWS, GCP, Azure, Vault, OpenBao 공식 문서를 읽고 관련 메서드, 권한, 상태 의미를 대조했다. [공식 근거 SL1–SL6](official-docs.md#slack과-외부-vault)에 URL과 판단을 정리했다. 기존 196개 테스트와 합성50개 비교를 재사용했으며 실제 연결 token으로 API를 호출하지 않았다.

- 현재 replies 문서는 Bot/User scope 양쪽을 안내한다. 과거 User-only 설명을 현재 확정 사실로 쓰지 않는다. Org-wide list에는 team_id가 필요한데 현재 함수는 전달하지 않는다.
- 신규 비Marketplace 상용 설치와 Marketplace/내부 앱의 rate를 구분한다. 현재 changelog는 기존 외부 설치를 새 제한에서 제외한다. 고정 limit200이나 과거 시행 예정일을 모든 설치의 현재 계약으로 적용하지 않는다.
- Approved Apps의 certified 기본 필터, Enterprise Owner User token이 필요한 Audit, org-wide 설치 사건을 구분한다. 기본 승인 목록, 현재 감사 필터로 조직의 모든 앱/감사를 수집했다고 표시하지 않는다.
- Events는 best-effort다. 저장 전 Socket ACK와 동기 HTTP 처리를 영속 수신→ACK→worker로 통합하고, 오래된 thread reply 복구, 알림 outbox를 구현한다. Socket Mode와 public Marketplace HTTP Events 운영도 구분한다.
- **Azure 수정 필요:** `S:app/cloud_secrets_inventory.py:167`의 updated_on은 회전 시각이 아니다. 기존 updated_at을 유지하고 last_rotated_at 매핑은 제거해 미확인으로 둔다. 회전 태그는 운영자 선언으로 표시한다. 목록 metadata가 있으므로 Vault 값 일치까지 완료된 것으로 표시하지 않는다.
- OAuth access/refresh 원자적 갱신, 실패 복구는 새 작업이다. 기존 develop Vault.write에 CAS가 구현됐다고 가정하지 않는다. GovSlack 도메인, auth.revoke method 호환성은 별도 검증 대상으로 남긴다.
