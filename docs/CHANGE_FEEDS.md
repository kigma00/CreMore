# 변경 감지 스캔

승인된 스코프에서 바뀐 것만 읽는다. 설계 근거는 [통합 운영 설계 4.3절](CONTINUOUS_OPERATIONS_DESIGN.md#43-c-주기변경-감지-스캔)과
결정 5다. 구현은 `cremore/scanning/changes.py`(변경 조회기), `cremore/scanning/triggers.py`(큐 소비),
공급자 폴더의 `changes_since`·`changes_since_batch`·`queue_changes` 함수다.

새 작업 종류는 없다. 변경 조회기와 큐 알림은 모두 기존 이벤트 경로(`enqueue_event` → scope 작업)로 들어가므로
활성 스캔 인덱스와 마이그레이션은 그대로다. 결과는 네 가지 중 하나다.

| 결과 | 뜻 |
| --- | --- |
| `EVENT` | 공급자가 이름을 알려 준 파일·객체만 읽는다(승인 경로 안, 256개 이하) |
| `DELTA` | root 전체를 다시 나열하고 바뀐 것만 읽는다. 목록의 리비전이 같은 객체는 이전 결과를 재사용한다 |
| `BASELINE` | 이력이 다시 쓰였다(강제 푸시, 사라진 커밋). root를 처음부터 읽고, 없어진 위치를 정리한다 |
| 없음 | 바뀐 곳이 승인 경로 밖이거나, 읽을 새 내용이 없다 |

## 1. 켜기

1. 스코프 profile의 `event_mode`가 `ENABLED`여야 한다. 새 연동은 온보딩 마지막 단계의 "변경되면 검사"가
   기본으로 켜져 있어, 변경 조회기·큐 알림·웹훅 중 하나라도 있는 리소스(S3, GCS, Azure Blob, 코드 저장소,
   TFVC, Confluence, Notion)를 고른 새 profile은 `ENABLED`로 저장된다(`complete.change_scans`, 기본 `true`).
   웹사이트처럼 변경 신호가 없는 리소스만 고른 profile과 기존 profile의 값은 바꾸지 않는다.
2. 변경 조회기는 설치에서 기본으로 켜져 있다. 설정을 저장한 적 없는 설치와 이전 버전이 저장한 설정(`full_scan_default_minutes`가
   없는 기록. 이전 버전은 무엇을 저장하든 모든 스위치를 꺼짐 기본값과 함께 기록했다)은 켜진 것으로 읽는다. 이 버전에서
   관리자가 `PUT /api/v1/settings/scan-triggers`의 `change_feeds_enabled: false`로 끈 값은 꺼진 채 둔다.
   공급자별 주기 기본값은 Bitbucket 15분, 나머지(GitHub, GitLab, Azure DevOps, Confluence, Notion) 5분이며
   `change_feed_minutes`(`{"github": 15, "notion": 10}`처럼, 1~1440분)로 공급자마다 바꾼다.
3. 설치 전체에서 막을 때만 `SCAN_CHANGE_FEEDS_MODE=disabled`(Helm `scanning.changeFeedsMode`)를 쓴다.

변경 조회기·큐·웹훅이 만든 작업은 payload의 `requested_by`에 출처(`feed`·`queue`·`webhook`)를 남기고,
Slack 탐지 알림의 "검사 시작"이 이를 `변경 알림(피드)`·`(큐)`·`(웹훅)`으로 적는다. 런타임은 이 값을 이벤트 task의
승인 범위 비교에서 빼므로 출처가 다른 같은 root의 이벤트도 한 task로 합쳐진다.

## 2. 변경 조회기

worker가 5초마다 도는 트리거 폴링에서 주기가 된 root를 묻는다. 요청 예산은 root당 60회다.

| 공급자 | 변경을 아는 방법 | 전체 다시 읽기(`DELTA`) | 처음부터(`BASELINE`) |
| --- | --- | --- | --- |
| GitHub | 브랜치 head를 조건부 요청(커서 `"<sha> <ETag>"`, 304면 바뀌지 않음)으로 묻고 compare API(`old...new`) | 비교 파일이 300개(상한)일 때 | `diverged`·`behind`, 지난 커밋 404 |
| GitLab | 커밋 조회, `merge_base`, `compare?straight=true` | `compare_timeout`, 변경 1,000개(상한) | 병합 기준이 지난 head가 아님, 지난 커밋 없음(`merge_base` 400·404) |
| Azure DevOps Git | ref의 objectId, `diffs/commits`(100개씩) | `allChangesIncluded: false`, 2,000개 초과 | `commonCommit`가 지난 head가 아님, `behindCount` > 0, 지난 커밋 없음 |
| Azure DevOps TFVC | `$/{project}`의 최신 changeset(커서), 이후 changeset(최대 30개)의 변경 목록 | changeset·변경 수 상한 초과, 폴더 이름 변경·삭제·분기, 대소문자에 따라 승인 범위가 달라지는 경로 | - |
| Bitbucket Cloud | 커밋, `merge-base`, `diffstat/{new}..{old}?topic=false` | HTTP 555(계산 시간 초과) | 병합 기준 이동, 지난 커밋 404 |
| Bitbucket Data Center | 커밋, `changes?since&until` | 항목 수가 연결 설정 `max_changes`(기본 1,000)에 이름, 마지막 페이지에 못 감, 디렉터리 항목 | 지난 커밋 404·400 |
| Confluence | CQL `lastmodified >= now("-Nm")`(5분 겹침)과 페이지 버전 | 마지막 조회가 7일보다 오래됨 | - |
| Notion | `POST /v1/search`를 최근 수정 순으로 걸어 지난 조회 시작 이후 수정된 승인 페이지(15분 겹침) | 한 번의 조회 예산으로 창을 다 걷지 못함, 마지막 조회가 2일보다 오래됨 | - |

- 첫 조회는 현재 위치만 기록한다. 그 root의 상태를 만든 스캔이 현재를 이미 다뤘다.
- 커서는 결과 작업이 DB에 등록된 뒤에만 움직인다. 다른 스캔이 실행 중이어도 작업은 항상 영속 접수된다. 조회·접수 실패에는 커서를 옮기지 않아 그 root의 다음 조회(주기 뒤)가 같은 변경을 다시 본다. 한 root의 실패는 그 root에만 기록되고 나머지 root는 같은 회차에서 계속 조회한다.
- 바뀐 이름이 이벤트 검사에 거절되면(제어 문자가 든 이름, 4 KiB가 넘는 경로) 그 root의 변경분(`DELTA`) 검사를 접수하고 커서를 옮긴다. 커서의 `reason`에 거절 코드(`EVENT_INVALID_PAYLOAD`)가 남는다. 이름 하나 때문에 같은 커서에서 매번 거절되어 그 root의 변경 감지가 멈추지 않게 하려는 것이다.
- 변경 조회는 worker의 관리 루프에서 돌므로 기다리지 않는다. 요청 제한(429, GitHub 보조 제한)을 받은 조회는 그 자리에서 `SOURCE_RATE_LIMITED`(Notion은 `NOTION_RATE_LIMITED`)로, 서버 오류(502·503·504)를 받은 조회는 `SOURCE_UNAVAILABLE`로 끝나고 커서를 그대로 둔다. GitHub·Notion의 공유 대기(cooldown)는 같은 토큰을 쓰는 검사에도 적용되지만 조회 자신은 기다리지 않는다.
- 실패가 이어지는 동안 커서에는 첫 실패 시각(`failing_since`)이 남고, 다음 조회가 성공하면 오류와 함께 지워진다. 한동안 조회하지 않은 root(변경 조회기를 껐거나 범위를 멈춘 경우)는 다시 실패하면 새로 센다. 한 root가 1시간 넘게 실패하면 운영 상태(`GET /api/v1/operations/status`의 경고, 콘솔 **운영 상태** 화면의 배너)에 그 연결의 경고가 뜬다. 실패한 root가 모두 요청 제한이면 `CHANGE_FEED_RATE_LIMITED`, 모두 공급자 장애(502·503·504)면 `CHANGE_FEED_UNAVAILABLE`, 그 밖이나 섞이면 `CHANGE_FEED_FAILING`이다. 변경 조회기가 꺼졌거나, 범위가 준비 상태가 아니거나 변경 검사가 꺼졌거나, 연결이 중지됐거나, 공급자 주기 + 1시간 동안 조회하지 않은 root에는 띄우지 않는다. 그동안 실패하는 root의 변경 검사는 조회가 성공할 때까지 멈추고(같은 연결의 다른 root는 계속 돈다), 예약 검사(기본 매일 전체 검사)는 계속 돈다. SIEM 이벤트나 Slack으로는 보내지 않는다.
- 한 회차는 첫 조회를 시작한 뒤 20초(`PASS_SECONDS`)가 지나면 새 연결·root의 조회를 시작하지 않고, 진행 중인 여러 쪽 조회(Notion 검색)도 다음 요청을 하지 않는다. Notion은 그때까지 읽은 범위만 답하고 덜 읽은 root는 `NOTION_FEED_BUDGET`으로 그 root의 변경분(`DELTA`)을 검사한다. 한 root만 보는 조회는 `BUDGET_REQUESTS`로 끝나고 커서를 그대로 둔다. 시작하지 못한 root는 커서를 그대로 두고 다음 회차에서 마지막 조회가 오래된 순서대로 먼저 조회한다(폴링 결과의 `deferred`). 조회할 root를 고르는 계획 시간은 이 20초에 들어가지 않는다. 한 범위의 계획이 예상하지 못한 오류(깨진 catalog 항목)로 실패하면 오류 종류만 로그에 남기고 다음 범위로 넘어간다.
- 삭제·이름 변경은 GitHub만 정확한 경로로 없어진 것을 확인한다. 다른 공급자는 `DELTA`로 전체 목록을 보고 정리한다.
- Data Center의 `UNKNOWN` 변경은 바뀐 파일로 읽는다.
- 변경 조회기는 바뀐 것만 읽는다. 놓친 변경은 예약 검사의 전체 검사가 잡는다: 전체 검사 주기를 따로 정하지 않은
  범위(`full_scan_minutes` null)는 설치 기본값(기본 매일 1회, 02:00 KST부터)을 따른다([스캔 운영](SCANNING_IMPLEMENTATION.md#스케줄)).
  변경 조회기가 만들던 일일 `RECONCILE`(`requested_by: change-feed`)은 없어졌다. 그래서 예약 검사를 끄거나
  (`SCAN_SCHEDULES_MODE=disabled`, 대시보드 스위치, 설치 기본 전체 검사 0) 범위의 전체 검사를 0으로 둔 경우에는 변경 조회기가
  놓친 변경(예: Notion 검색 반영이 15분 겹침보다 늦은 경우)을 다시 바뀌거나 누가 검사하기 전까지 읽지 않는다.

## 3. 증분 읽기

목록에 나오는 리비전으로 이미 스캔한 결과를 재사용한다. worker 스캔은 읽기를 미루므로 바뀌지 않은 객체는 내려받지 않는다.

| 공급자 | 리비전 | 재사용 기준 |
| --- | --- | --- |
| GitHub, GitLab, Azure DevOps | git blob ID | 내용 자체(다른 경로의 같은 blob도 재사용) |
| GCS | generation | 위치 |
| Azure Blob | ETag | 위치 |
| Confluence 첨부 | 첨부 ID와 버전 | 위치 |
| S3 | ETag | 위치(기존) |
| Bitbucket Cloud / Data Center | 고정 commit | 같은 경로만 재사용 |

Notion은 기준 시각(watermark)과 페이지 revision을 사용한다. Markdown 우선 읽기·탐지 페이지의
블록 위치 확인·3개 fetch worker·동일 인증 전체의 DB 기반 초당 2.5회 제한을 사용한다.
Bitbucket은 고정 commit과 경로를 함께 사용한다. commit을 blob ID처럼 다른 경로에 재사용하지 않는다.

## 4. 큐 이벤트

공급자 알림을 **고객이 만든 전용 큐**로 보내면 CreMore가 읽는다. 이 큐 방식은 공개 수신 엔드포인트 없이 동작하며,
큐·토픽·알림 설정을 만들지 않는다. 큐 하나는 승인된 스코프 profile 하나에 묶인다.

| 큐 | 설정 필드 | 주소 | worker 신원에 줄 권한 |
| --- | --- | --- | --- |
| AWS SQS | `sqs_*` | `https://sqs.{region}.amazonaws.com/{account}/{name}` | 그 큐의 `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:ChangeMessageVisibility` |
| Google Pub/Sub | `pubsub_*` | `projects/{project}/subscriptions/{name}` | 그 구독의 `roles/pubsub.subscriber`(Application Default Credentials) |
| Azure Service Bus | `servicebus_*` | `https://{namespace}.servicebus.windows.net/{queue}` 또는 `.../{topic}/subscriptions/{name}`(Azure 공용 클라우드) | 그 엔터티의 "Azure Service Bus Data Receiver"(`DefaultAzureCredential`) |

관리자가 `{kind}_enabled`, `{kind}_profile_id`, 주소, `{kind}_dedicated_acknowledged`(이 큐는 CreMore 전용)를 넣어야 켜진다.
하나라도 비면 꺼진 것으로 읽고 대시보드가 `blocked_by`로 알린다. 설치 잠금은 `SCAN_SQS_MODE`, `SCAN_PUBSUB_MODE`,
`SCAN_SERVICEBUS_MODE`다.

- 한 번에 최대 10개를 받는다. SQS는 대기 없이, Pub/Sub는 `returnImmediately`로, Service Bus는 peek-lock(대기 1초)으로 받는다.
- 메시지가 요청한 작업이 모두 DB에 등록된 뒤에만 ACK한다(SQS 삭제, Pub/Sub `acknowledge`, Service Bus 잠금 메시지 삭제).
- 다른 스캔이 실행 중이어도 작업을 영속 대기열에 접수한 뒤 ACK한다. 서로 다른 연결은 worker 동시 실행 수만큼 함께
  실행하고, 한 연결 안에서는 변경 알림 실행이 진행 중인 전체 검사와 나란히 돈다(같은 버킷·저장소·페이지는 동시에 두 번
  읽지 않는다). 실패한 접수에는 ACK하지 않으며 기존 재전달 계약을 유지한다.
- 형식이 틀리거나 범위 밖이거나 등록에 실패한 메시지는 ACK하지 않는다. 큐의 재전달 한도와 DLQ(데드레터) 정책을 운영한다.
- Service Bus가 돌려준 잠금 URL이 그 엔터티의 메시지 주소가 아니면 토큰을 보내지 않는다. Pub/Sub 응답은 4 MiB,
  메시지 본문은 128 KiB까지만 읽는다.

### 읽는 알림

| 알림 | 보내는 방법 | 결과 |
| --- | --- | --- |
| S3 이벤트 알림, EventBridge 객체 이벤트, CloudTrail 쓰기 | S3·EventBridge → SQS | 객체 키 `EVENT`(기존. 승인 prefix 밖 키는 메시지를 거절) |
| Cloud Storage 알림 | 버킷 알림 → Pub/Sub | `OBJECT_FINALIZE`·`OBJECT_METADATA_UPDATE`는 키 `EVENT`, `OBJECT_DELETE`·`OBJECT_ARCHIVE`는 `DELTA`, 새 세대로 바뀐 삭제·보관과 `OBJECT_INITIALIZE`는 없음 |
| Blob Storage 이벤트(Event Grid·CloudEvents 스키마) | Event Grid → Service Bus | `BlobCreated`는 키 `EVENT`, `BlobDeleted`·`BlobRenamed`·폴더 이름 변경·삭제는 `DELTA`, 계층 변경·폴더 생성·진행 중인 복사는 없음 |
| Azure DevOps `git.push` 서비스 후크 | 서비스 후크 → Service Bus | 코드 저장소 규칙(아래) |
| GitHub `push` 웹후크 | 고객의 중계기 → 큐 | 코드 저장소 규칙. `forced`면 `BASELINE` |
| GitLab `push` 웹후크 | 고객의 중계기 → 큐 | 코드 저장소 규칙. 태그 푸시는 없음 |
| Bitbucket Cloud `repo:push`, Data Center `repo:refs_changed` | 고객의 중계기 → 큐 | 코드 저장소 규칙. Cloud의 `forced`면 `BASELINE` |
| 일반 이벤트 `{resource_id, keys \| paths \| page_ids}` | 어느 큐든 | 그 경로의 `EVENT`, 256개 초과면 `DELTA` |

코드 저장소 규칙: 푸시 알림의 커밋 목록은 상한이 있어(GitHub 2,048개, GitLab 20개) 파일 목록을 믿지 않는다.
그 저장소의 변경 조회기가 켜져 있고 커서가 있으면 조회기를 깨워 같은 폴링에서 compare가 바뀐 파일과 강제 푸시를 판단한다.
그렇지 않으면 저장소를 `DELTA`로 다시 읽는다(바뀌지 않은 blob은 재사용). 읽는 브랜치가 아닌 푸시, 태그, 삭제된 브랜치는
작업 없이 ACK한다. 승인 범위 밖 저장소·버킷·컨테이너의 알림은 ACK하지 않는다. Cloud Storage·Blob의 승인 prefix 밖 객체는
작업 없이 ACK한다.

## 5. 공급자 함수

공급자 모듈이 선택적으로 정의한다. 없으면 그 공급자는 예약 스캔을 쓴다.

- `changes_since(payload, root, cursor, *, http_client, request_budget) -> Changes`: 커서 이후 바뀐 경로. 커서는 커밋
  (GitLab, Bitbucket, Azure DevOps Git), `"<sha> <ETag>"`(GitHub, sha만 있는 이전 커서도 읽음), 최신 changeset ID(TFVC)다.
- `changes_since_batch(payload, roots, states, *, http_client, request_budget) -> {resource_id: Changes}`: 한 번의 조회가
  여러 root에 답할 때(Confluence, Notion).
- `queue_changes(body, attributes, roots) -> {resource_id: Changes} | {} | None`: 큐 알림. `None`은 자기 알림이 아님,
  `{}`는 읽을 것이 없음, 범위 밖 리소스는 `CollectorError("EVENT_OUT_OF_SCOPE")`.
- `REVISION_CACHE = True`: 목록의 리비전이 내용을 나타낸다. `CONTENT_ADDRESSED = True`: 리비전이 git blob ID다.

`Changes`와 브랜치 판정(`pushed`), 저장소 다시 읽기(`reread`)는 순수 모듈 `cremore/collectors/changes.py`에 있다.

## 6. 검증

- `cremore/scanning/changes_test.py`: 기본 켜짐과 관리자의 끄기·설치 잠금, 첫 조회, 변경 파일만 읽기, 이력 재작성의
  `BASELINE`, 알 수 없는 목록의 `DELTA`, 승인 경로 밖 변경, 조회·접수 실패 시 커서 유지, 공급자별 주기, 출처 `feed` 기록,
  놓친 변경을 설치의 전체 검사가 잡음, Notion 검색 조회기.
- `cremore/scanning/trigger_settings_test.py`: 공급자별 기본 주기(Bitbucket 15분, 나머지 5분), 저장한 끄기 유지.
- `cremore/scanning/queues_test.py`: 큐 세 종류의 바인딩·잠금·주소 검증, Cloud Storage 알림, 범위 밖·형식 오류 거절,
  실행 중에도 영속 접수 후 ACK, 푸시의 `DELTA`·`BASELINE`, 변경 조회기 깨우기, worker 연결, 출처 `queue` 기록.
- `cremore/onboarding/sessions_test.py`: 새 연동 범위의 `event_mode` 기본 `ENABLED`, 마지막 단계 토글, 기존 범위 유지.
- 공급자: `github/.../changes_test.py`, `gitlab/.../changes_test.py`, `azure/.../devops_changes_test.py`,
  `atlassian/.../tests/test_changes.py`(Bitbucket Cloud·Data Center의 한도·555·지난 커밋 없음, Confluence),
  `gcp/.../pubsub_test.py`, `azure/.../servicebus_test.py`(잠금 URL 검증, Event Grid 두 스키마).
- 증분 읽기: `cremore/collectors/enterprise_test.py`(바뀌지 않은 GitLab blob은 다시 내려받지 않음),
  `cremore/worker/runtime_test.py`(`BASELINE`을 요청한 이벤트가 없어진 위치를 정리).
- 모두 합성 서버와 가짜 큐로 검증했다. 실제 공급자 API, Pub/Sub, Service Bus, Event Grid와의 연동은 실환경 검증 항목이다.
