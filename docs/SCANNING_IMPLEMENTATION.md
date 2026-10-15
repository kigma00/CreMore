# 대규모 자산 스캔: 확정 설계와 구현 기록

이 문서는 2026-09-15까지 합의한 구현 기준이다. 체크되지 않은 항목은
완료를 뜻하지 않는다. 운영 중인 외부 계정/버킷/큐/데이터베이스에 대한
배포나 데이터 변경은 이 저장소의 구현·로컬 검증과 별개다.

### 이름 변경 전 사전 배포 DB

`e1ac9ba`(2026-09-19)는 배포 전 CEP 이름을 CreMore로 바꾸면서 HMAC 도메인도
변경했다. 당시 커밋은 CEP 데이터베이스의 연속 업그레이드를 지원하지 않는다고 명시한다.
그 이전 체크아웃에서 만든 DB가 있다면 현재 코드로 바로 재스캔하지 않는다. 동일 자격증명이
새 식별자로 생겨 기존 노출의 제거 이력이 잘못 분리될 수 있다. 원문을 저장하지 않는 계약상
저장된 digest만으로 새 digest를 계산할 수 없으며 자동 변환 도구는 제공하지 않는다.
그런 설치는 writer를 중지하고 원본 DB·감사 이력을 보존한 채 별도 이관 검토가 필요하다.
현재 CreMore DB의 지문 도메인을 되돌리거나 감사/credential 행을 지워 우회하지 않는다.

## 목표와 경계

담당자가 승인한 bucket/prefix, repository/path, Notion page만 검사한다.
최초 기준 검사 이후 변경된 내용 위주로 다운로드·탐지한다. 실패/미검사는
안전함으로 표시하지 않는다. 원본과 원문 키는 저장하지 않고 마스킹된
탐지 결과만 저장한다. 하나의 설치는 하나의 신뢰 경계다.

기업의 기존 S3 알림, CloudTrail selector, Inventory, EventBridge 규칙,
공유 SQS를 수정하거나 소비하지 않는다. 큐·웹훅 연동은 기본 비활성화이며
운영자가 승인한 전용 큐/웹훅만 사용한다. 예약 검사(매일 전체 검사)와 공급자 API의
변경 조회기는 기본으로 켜져 있다. Kubernetes는 필수가 아니다.
S3 Batch Operations는 계측 후 필요할 때 도입할 선택적 후속 기능이며,
이번 기본 실행 경로에 AWS Lambda/Redis/Kafka/Alembic을 추가하지 않는다.

## 담당자 운영 절차

1. [README의 실행·연결 예제](../README.md#실제-소스-연결과-작업-흐름)로 API/worker/DB를 준비한다. Kubernetes는 선택이며 DB 큐에 Redis/Kafka가 필요하지 않다.
2. 계정·연결에 최소 읽기 권한을 부여하고 catalog를 갱신한다. catalog는 내용 스캔이 아니라 metadata 조회다. `source` 연결과 연결된 AWS account의 `aws` 종류를 구분한다.
3. catalog의 정확한 root ID를 선택하고 Admin이 profile을 저장한다. 필터 결과는 현재 ID로 고정되며 미래 자산이나 검색에서 누락된 자산을 승인하지 않는다.
4. Analyst가 preview의 `executable`, 미확인 root, 경고, 15분 만료 시각을 확인한 뒤 `/api/v1/scan-runs`를 실행한다. 같은 plan/mode 재전송은 같은 run을 반환한다. 다른 mode/새 실행은 새 preview가 필요하다.
5. `GET /api/v1/scan-runs/{run_id}/coverage`에서 완료·부분·실패와 미검사 사유를 확인한다. 큐 등록/작업 성공/자산 범위 완전성을 같은 의미로 해석하지 않는다.

### 전체·변경분 검사 주기와 설치 기본값 (2026-10-10)

로그인한 사람이 없어도 서버가 승인된 모든 범위를 정기적으로 전체 검사한다. 범위마다 전체 검사
`full_scan_minutes`와 변경분 `schedule_minutes`를 따로 저장한다. 전체 검사는 0(끔) 또는 60~1440분이고
null이면 설치 기본값을 따른다. 변경분은 0(끔) 또는 5~43200분이다. 전체 검사는 선택한 전체 범위를 다시
나열하는 `RECONCILE`이며 동일 리비전의 정상 결과는 재사용한다. 변경분 슬롯은 시각과 관계없이 항상 `DELTA`다.

설치 기본값은 관리자가 환경 설정 > 스캔 시작 조건(`PUT /api/v1/settings/scan-triggers`)에서 정한다.

| 필드 | 값 | 기본값 |
| --- | --- | --- |
| `full_scan_default_minutes` | 0(끔), 60·120·180·240·360·480·720·1440(하루 24·12·8·6·4·3·2·1회) | 1440(하루 1회) |
| `full_scan_start_minute` | 전체 검사 슬롯이 시작하는 UTC 분(0~1439). 콘솔은 표시 시간대의 시각으로 보여 주고 고른다 | 1020(02:00 KST) |

- 전체 검사 슬롯 k는 시작 분 + k × 주기에 시작한다. 하루 1회면 매일 그 시각, 하루 2회면 그 시각과 12시간 뒤다.
  범위에 따로 정한 전체 검사 주기도 같은 시작 분부터 센다. 다만 범위마다 고정된 시간만큼 늦게 접수한다(분산):
  범위 ID의 SHA-256을 `min(240분, 주기/2)`로 나눈 나머지(분)다. 하루 1·2회면 시작 시각부터 4시간 안(기본 02:00~06:00 KST),
  하루 3회 4시간, 4회 3시간, 6회 2시간, 8회 90분, 12회 1시간, 24회 30분 안이다. 범위마다 매일·모든 worker에서 같은 시각이다.
  접수 시각 전의 슬롯은 아직 열리지 않은 것으로 본다(접수·합치기·건너뛰기 모두 하지 않는다). receipt,
  "슬롯 시작 뒤에 시작한 실행이 답한다", 합치기, 변경분 덮기는 그대로 슬롯 시작 시각을 기준으로 한다. receipt가 슬롯마다
  한 번만 접수하므로 여러 worker가 함께 폴링해도 중복되지 않는다. 시작 분을 바꾸면 그 시각부터 새 슬롯을 센다. receipt는
  슬롯이 시작한 시각으로 정하므로 시작 분 변경 직후에도 실행을 건너뛰지 않는다(그 직후 한 번은 바로 접수할 수 있다).
  업그레이드 때 이미 접수 시각이 지난 슬롯은 아래 "업그레이드 주의"대로 한 번 건너뛴다. 콘솔의 다음 예정 시각은 이 접수 시각이다.
- 범위 주기의 우선순위: 범위의 `full_scan_minutes`(0이면 그 범위만 끔) → null이면 설치 기본값.
  `list_scheduled_profiles(full_scan_default)`가 기본값이 켜진 동안 null 범위를 예약 대상으로 나열한다.
- 예약 검사는 더 이상 UTC 날짜가 바뀌는 첫 변경분 슬롯을 `RECONCILE`로 바꾸거나 `reconcile_if_older_than_seconds`를
  넣지 않는다. 이전에 접수된 작업의 이 값은 런타임과 재개가 그대로 따른다.
- 합치기: 범위의 예약 작업 중 같거나 더 강한 mode(`RECONCILE` ≥ `DELTA`)가 아직 `QUEUED`이면 새 슬롯을 접수하지
  않고 그 슬롯의 receipt가 대기 중인 작업을 가리킨다(폴링 결과의 `coalesced`). 대기 작업은 슬롯이 시작된 뒤에
  실행되므로 슬롯이 요구한 현재 상태를 읽는다. 관리자가 넣은 첫 전체 검사(`BASELINE`, 온보딩의 "지금 수집" 포함)와
  슬롯 시작 뒤에 시작한 전체 검사도 그 슬롯에 답하므로 새 연동을 두 번 연달아 전부 읽지 않는다. 같은 profile 버전과
  `auth_revision`의 작업만 합친다(승인 갱신 뒤에는 새 작업을 접수). 같은 시간 슬롯의 전체 검사로 덮이는 변경분도 중복
  접수하지 않는다. 전체 검사 슬롯이 시작한 때나 그 뒤에 시작해 그 전체 검사의 접수 시각 뒤에 끝나는 변경분 슬롯은 따로 접수하지
  않고 기다렸다가, 접수 시각에 함께 접수되는 전체 검사에 합친다(분산 전 시작 시각과 같이 한 실행). 접수 시각 전에 끝나는 변경분
  슬롯은 바로 접수하고, 그 전체 검사가 접수되지 않으면(업그레이드 건너뛰기 등) 기다린 변경분은 접수 시각에 따로 접수한다.
  반대로 범위 저장과 첫 검사 요청 사이에 예약 폴링이 전체 검사를 먼저 넣었으면, 첫 검사 요청
  (`POST /api/v1/scan-runs`의 `BASELINE`)은 같은 승인의 그 예약 실행(대기 또는 실행 중)을 돌려준다. 다만 검증이 켜진
  설치에서 찾은 자격증명을 검증할 요청에는 검증하지 않는 실행(예약 실행은 항상 검증하지 않는다)으로 답하지 않고 요청을
  따로 실행한다. 검사 요청에 답하는 것은 전체 범위 실행(`trigger` `BASELINE`·`SCHEDULE`)뿐이다. 변경 이벤트 실행,
  finding 다시 검사, 정책 재검사는 자기 경로만 읽고 중간부터 이어 읽는 실행(`RESUME`)은 범위 전체를 읽지 않으므로 어떤 검사
  요청에도 답하지 않는다. 승인·연결 상태로 계획이 거절된 범위는 매 폴링마다 다시 계획하지 않고 잠시(5분, 범위 행과 승인
  시각별로) 기억하며, 슬롯은 소비하지 않는다. 계획이 예상하지 못한 오류(깨진 catalog 항목)로 실패한 범위도 오류 종류만
  로그에 남기고 같은 5분 동안 건너뛰며, 다른 범위의 예약은 계속한다.
- 슬롯이 다른 실행(관리자가 넣은 첫 검사, 다른 슬롯의 예약 실행, 슬롯 시작 뒤에 시작한 전체 실행)에 합쳐진 뒤 그 실행이
  `CANCELLED`·`FAILED`로 끝나면 슬롯은 다시 열린다. 다음 폴링이 조건에 맞는 다른 실행에 합치거나 자기 실행을 접수하며,
  receipt를 이전 작업 ID와 맞을 때만 바꾸므로 여러 worker가 함께 폴링해도 한 번만 접수한다. 예약 실행에는 자기 슬롯의
  receipt(`slot_receipt`)가 남고, 슬롯의 자기 실행을 운영자가 취소하면 지금처럼 그 슬롯은 소비된다(이 필드가 없는 이전
  버전의 예약 실행은 그 슬롯이 시작된 뒤에 접수된 경우만 자기 실행으로 본다).
- 폴링은 목록에 나온 범위의 슬롯 receipt부터 확인하고, 열린 슬롯이 있을 때만 승인 범위·catalog로 계획을 만든다.
- 서버 중단 기간의 슬롯을 모두 재생하지 않고 현재 슬롯을 접수한다. 과거 작업의 재개는 원래 검사 mode를 유지한다.

**업그레이드 주의**: 예약 검사(`schedules_enabled`)·변경 조회기(`change_feeds_enabled`) 스위치는 저장한 적 없는 설치와
이전 버전이 저장한 설정(`full_scan_default_minutes`가 없는 기록)에서 켜진 것으로 읽는다. 이전 버전은 어떤 값을 저장하든 모든
스위치를 꺼짐 기본값과 함께 기록했기 때문에, 그 `false`는 관리자의 선택으로 볼 수 없다. 따라서 업그레이드하면 전체 검사
주기를 따로 정하지 않은 모든 승인 범위에 매일 02:00 KST부터 전체 검사가 켜진다. 업그레이드 시각은 DB 이관(스키마 기록
버전 14 `scan_schedule_origin`)이 DB 시계(`now()`)로 한 번 기록한다(`installation_settings`의 `scan_schedule_origin`).
오프라인 업그레이드(`python -m cremore.db.migrations`), 격리 배포의 스키마 준비(`python -m cremore.db.startup`), 일반 시작의
`create_all`이 모두 이 이관을 거치고, 새 설치는 DB를 만들 때 기록하므로 그 뒤 저장한 범위는 건너뛰지 않는다. 격리 배포의
런타임은 버전 14가 없으면 시작하지 않는다(`DATABASE_MIGRATIONS_INCOMPLETE`). 그 전에 승인된 범위는 그때 이미 접수 시각(슬롯
시작 + 범위의 분산)이 지난 전체 검사 슬롯 하나를 건너뛰고, 첫 예약 전체 검사는 업그레이드 뒤 처음 오는 접수 시각이다(기본 다음
날 02:00~06:00 KST의 범위별 시각. 그 시간대 안에 업그레이드하면 접수 시각이 아직 오지 않은 범위는 그날 검사한다). 전체 검사 주기를
따로 정한 범위도 같다. 업그레이드 뒤 저장하거나 다시 승인한 범위는 이전과 같이 열린 슬롯에서 바로 검사한다. `EXTRACTOR_EPOCH` 4로
탐지 정책이 바뀌어 생기는 정책 재검사도, 전체 검사 주기가 있는(예약 검사가 켜진) 그 범위들에는 그 첫 슬롯의 전체 검사가 끝날
때까지 접수하지 않는다. 성공·부분·실패·취소 어느 쪽으로 끝나도 보류가 풀린다(슬롯 자신의 예약 실행은 실패·취소돼도 슬롯을 다시
열지 않으므로 그 끝남이 보류를 푼다). 그 슬롯이 관리자의 첫 검사나 다른 슬롯의 실행에 합쳐졌다가 그 실행이 실패·취소되면 슬롯이
다시 열리고, 다음 폴링이 접수한 실행이 끝날 때까지 보류가 이어진다. 어느 경우든 그 슬롯의 접수 시각부터 주기 하나가 지나면 풀린다.
그 슬롯의 전체 검사가 새 정책으로 다시 읽고, 정책 재검사는 이미 다시 읽은 root를 읽지 않는다. 전체 검사가 꺼진 범위(주기 0,
예약 검사 꺼짐·잠금)는 바로 정책 재검사를 받는다. 그 기간(전체 검사가 도는 동안 포함)의 변경분 슬롯과
변경 이벤트 실행에는 `policy_hold`가 붙어, 탐지 정책이 바뀌었다는 이유만으로 전체 읽기가 되지 않는다(아래 "실행 종류와 해제
근거"). 업그레이드 뒤 첫 정책 재검사 확인(약 1분 안)이 그때의 탐지 정책 digest를 같은 기록에 남기고, 그 뒤 관리자가 규칙을 바꿔
digest가 달라지면 다음 확인(약 1분 안)이 `rules_changed`를 고정해 모든 보류를 끝내고 바로 정책 재검사를 넣는다(규칙을 되돌려도
다시 보류하지 않는다). 예약·변경 이벤트 접수는 worker의 규칙이 아니라 이 기록만 읽으므로, 막 시작해 규칙을 아직 읽지 않은 worker도
같게 판단한다. 새로 접수하는 실행은 기록 시각부터 48시간(가장 긴 주기 1,440분의 2배) 뒤에는 보류하지 않는다. 이 48시간과
규칙 변경 뒤 약 1분은 접수 판단의 경계다: 이미 `policy_hold`를 달고 대기 중이거나 중단 뒤 재개되는 실행은 그 뒤에 돌아도 보류된
채 바뀐 것만 읽거나 읽지 않는다. 그런 실행도 새 정책을 확정하지 않으므로 이후 전체 검사나 정책 재검사가 그 root를 다시 읽는다.
이 기록 행만 지우면(이관 버전 14 기록은 남은 채) 아무것도 건너뛰거나 보류하지 않고 평소대로 검사하며, 다시 기록하지 않는다. 버전 14
이전의 백업을 복원하면 다음 시작이 복원 시각을 새로 기록해 업그레이드처럼 한 번 더 건너뛰고 보류한다.
worker 시계보다 24시간 넘게 앞선 기록은 믿지 않고 경고 로그(`SCHEDULE_ORIGIN_AHEAD_OF_CLOCK`)를 남긴다. 원하지 않으면 관리자가
환경 설정 > 스캔 시작 조건에서 기본 주기를 끄거나 바꾸고 예약 검사나 변경 조회기 자체를 끌 수 있다. 이 버전에서 관리자가
저장한 `false`는 그대로 꺼진 채 둔다. 반드시 막아야 하는 설치는 아래 운영자 잠금을 쓴다. 잠근 채 업그레이드하고 나중에 풀면,
풀 때 열려 있는 슬롯은 바로 접수된다.

`SCAN_SCHEDULES_MODE=disabled` 운영자 잠금은 모든 예약 검사를 막는다. 신규 범위의 기본 예산은 기존 대상 편집기와 같은
500 GiB·200만 요청·6시간이다. 운영자는 범위 크기와 공급자 제한에 맞춰 줄일 수 있다. 주기는 승인 범위를 넓히지 않으며
기존 연결의 승인·버전 검사를 쓴다. 온보딩의 마지막 단계는 전체 검사 주기(기본: 설치 기본값)와 "변경되면 검사"(기본: 켜짐)를
보여 준다. 검사 대상 편집기는 하루 1·2·3·4·6·8·12·24회, 끄기, 설치 기본값을 고르게 한다.

배포 시 API/worker를 함께 갱신하고 offline migration과 DB 역할 grant를 적용한다. nullable
`scope_profiles.full_scan_minutes`와 `scan_request_pacing`을 추가하며 기존 감사·탐지는 삭제하지 않는다.
여러 worker가 같은 Notion 인증을 쓰면 DB 시계와 행 잠금으로 초당 2.5회 제한 및 429 대기를 공유한다.
네트워크 대기 중 DB 잠금을 잡지 않는다. 독립 스캔은 worker 컨테이너의 동시 실행 수(`WORKER_CONCURRENCY`)와
worker 복제본(Compose scale 또는 Helm replicas.worker)만큼 함께 실행한다.

### 연결별 동시 실행과 중지

콘텐츠 스캔은 실행 중에도 **대기열에 접수**한다. 서로 다른 연결은 worker 동시 실행 수만큼 함께 처리하고, 한 연결 안에서는 레인마다 부모 작업 하나가 실행된다: 변경 알림 실행(event 레인)은 진행 중인 전체·예약 검사(sweep 레인)와 나란히 돌며, 같은 버킷·저장소·페이지는 root 잠금으로 동시에 두 번 읽지 않는다. 등록된 `CONTENT_SCAN_KINDS` 전체에 적용하며 자격증명 점검·catalog 갱신·AWS 역할 점검은 콘텐츠 실행 슬롯을 차지하지 않는다. 실행 시 기존 승인·범위·자격증명 검사를 유지하며 root의 리스·잠금·예산도 그대로 적용한다.

- 수동 시작은 `202`로 접수하고 스케줄·이벤트의 중복 전달은 기존 receipt로 같은 작업을 반환한다. 큐 메시지는 필요한 작업을 모두 영속 저장한 뒤 ACK한다. `GET /api/v1/scan-runs`에서 대기·실행 상태를 확인한다. 호환용 `/api/v1/scan-activity`는 가장 오래된 활성 작업 하나를 반환하며 신규 시작을 막는 신호가 아니다.
- PostgreSQL은 짧은 부모 작업 점유 트랜잭션에서 advisory lock을 사용한다. 실제 외부 읽기 중에는 이 잠금을 잡지 않는다. `scan_jobs_one_running_connection` 인덱스가 같은 연결·레인의 `RUNNING`·`CANCELLING` 중복을 막는다. 연결 ID가 없는 옛 작업은 모든 콘텐츠 실행과 충돌하도록 보수적으로 직렬화한다. 오래된 무범위 작업이 기다리면 그 뒤의 콘텐츠 작업을 잠시 대기시켜 굶주림을 방지한다. 메타데이터 등 비콘텐츠 작업은 계속 실행할 수 있다.
- 같은 S3 root의 변경 이벤트 작업이 진행 중인 전체·증분 검사(이어서 할 수 있는 sweep) 뒤에서 root 잠금을 기다리면, sweep은 지금까지 읽은 객체를 커밋하고 checkpoint와 함께 대기열로 돌아간다(`YIELDED_TO_EVENT`: 시도 수를 쓰지 않는 연기, 리스 해제, 기다리는 작업마다 한 번). 이벤트 작업이 먼저 돌고 sweep은 마지막으로 커밋한 키 다음부터 이어간다. sweep은 시작 위치를 지나 처음 커밋한 뒤 5초(`YIELD_SECONDS`)가 지나야 기다리는 작업을 살피므로, 이벤트가 끊이지 않아도 시도마다 cursor가 나아간다. 마지막으로 끝까지 읽은 전체 검사(`last_reconcile`)가 3일 안인 root에서만 양보한다. 실패 키(이전 실행이 읽지 못한 키 포함)는 task마다 한 번만 다시 읽는다. 처음부터 읽는 sweep은 목록에서 읽고, root 상태의 이어갈 위치(`resume_after`)에서 시작하는 task(예산 중단 뒤의 `RESUME`, 그 위치를 이어받은 예약 `RECONCILE`·`DELTA`·`POLICY_SWEEP`)는 목록 전에 그 위치 이하의 실패 키를 읽는다. 그 결과는 시작 위치를 지난 첫 커밋과 함께 checkpoint(`retried`)에 남고, 그 커밋 전에 멈춘 시도 뒤에는 다시 읽는다. 양보나 리스 만료 뒤 같은 task의 다음 시도는 cursor 이하의 실패 키를 다시 읽지 않고, 실패로 유지해 다음 실행이 다시 읽게 하며 이 실행의 수에 한 번 센다(가장 최근 거절이 보관이면 `skipped_archived`, 아니면 `failed`). 읽지 못한 객체도 실패로 커밋되면 cursor가 그 뒤로 간다. 양보 사이에 다른 실행이 root의 실패 목록을 바꾸면 그 목록을 다시 합치므로, 이 task가 이미 다시 읽어 성공한 키가 한 번 더 실패로 남고 세어질 수 있다(다음 실행이 다시 읽는다). 양보 직전에 미리 읽었지만 커밋하지 못한 객체(동시 읽기 창, 최대 8개)는 실패 여부와 관계없이 다음 시도가 다시 읽는다. 모든 GET은 응답이 알린 크기가 읽기 상한보다 크면 내용을 받지 않고 실패로 남긴다(목록 크기로 이미 실패한 키를 다시 읽을 때 포함). 양보한 실행은 이어서 끝난 실행이라 미검사 사유를 교체하지 않고, 이어간 키 앞부분의 제거는 위치마다 HEAD로 사라진 것을 확인한 것만 확정하므로(아래 "실행 종류와 해제 근거"), 첫 검사와 이벤트가 끊이지 않는 root도 적어도 3일에 한 번은 한 번의 시도로 끝까지 읽는다. 양보 사이에 다른 실행이 기록한 미검사 사유(`inspection_gaps`)는 이어지는 시도로 옮겨 잃지 않는다. 예산으로 멈춘 시도는 쓰지 않은 예약을 마지막으로 커밋된 checkpoint에 되돌려 쓰므로, 마지막 저장이 실패해 되돌린 객체를 cursor가 지나치지 않는다.
- 대기 중 스캔의 중지는 즉시 `CANCELLED`가 되어 슬롯을 놓는다. 실행 중 스캔은 `CANCELLING`이 된다. 이후 새 task는 생성·점유되지 않고, 그 실행의 checkpoint·결과 저장은 DB에서 거부된다(중지 요청보다 먼저 시작된 한 객체의 저장은 먼저 커밋될 수 있다). 모든 task가 멈춘 뒤 `CANCELLED`로 확정되며, 그때 슬롯이 풀린다. 늦게 도착한 완료·실패는 이 상태를 덮어쓰지 않는다.
- 이관 버전 11은 기존 전역 인덱스를 연결별 실행 인덱스로 바꾼다. 기존 API·worker를 중지하고 이관한 뒤 같은 버전으로 재시작한다. 대기 작업·감사 이력은 삭제하지 않는다. 같은 연결의 실행 중 작업이 둘 이상이거나 무범위 작업과 다른 작업이 함께 실행 중인 옛 설치는 먼저 해당 실행을 종료해야 한다. 강화 배포의 런타임 DDL 금지는 유지하며 별도 migration 계정으로 적용한다. 구버전으로 되돌리려면 새 작업 접수를 멈추고 대기·실행 작업을 처리한 후 전역 슬롯 제약을 다시 검증해야 하므로 바이너리만 바꾸는 롤백은 지원하지 않는다.

호환용 `/api/v1/connections/{id}/scan`과 연결 전체 스캔은 profile 선택이 아닌 **연결 설정 전체**를 대상으로 한다. 정밀한 범위 통제가 필요한 운영은 위의 승인 profile 경로를 사용한다. 프로필 저장·변경 시 `expected_version`을 보내며, 연결 권한 변경 후에는 재승인이 필요하다.

### 범위·우선순위·예산

| 대상 | profile의 `selected_roots` 설정 | 주의 |
| --- | --- | --- |
| S3 | `resource_id`, `prefixes`, `excluded_prefixes` | prefix는 문자열 접두사. 전 객체 승인은 `all_current_objects: true`로 명시 |
| GitHub | `resource_id`, `ref`, `paths`, `excluded_paths` | path는 파일/디렉터리 경계. ref를 실행 시 commit SHA로 고정; 과거 전체 history 스캔 아님 |
| Notion | `resource_id`, `page_mode`, `descendant_ids` | `PAGE_ONLY`, `PAGE_WITH_DESCENDANTS`, `DATA_SOURCE_SELECTED_PAGES`; 명시적으로 선택한 child/page만 |
| 공통 | `excluded_ids`, root별 `priority` | 제외 우선. priority는 -1000~1000, 큰 값 먼저. 미래 하위 페이지 자동 포함은 미지원 |

profile의 `budgets`는 **bytes, requests, seconds 모두 양의 정수**다. 상한은 각각 1 TiB, 10,000,000회, 7일이며 이것은 처리량 보장이 아니라 입력 상한이다. 한 profile은 최대 10,000 root, catalog 페이지는 최대 200개다. discovery에도 최대 1,000,000개와 별도의 응답·요청 상한이 있으므로 `PARTIAL`/`unknown_remainder`를 확인한다. 더 큰 범위는 profile을 분리한다.

root 작업은 S3의 겹치지 않는 선택 prefix, GitHub repository, Notion page 단위다. 현재 예산은 run 총량을 root 수에 따라 **고정 분배**한다. 몫을 다 쓴 root는 끝난 다른 root가 쓰지 않은 몫만 넘겨받고, 끝나지 않은 다른 root가 있으면 그 뒤로 물러나 기다린다. 끝나지 않은 다른 root가 모두 그렇게 몫을 기다리는 중이면 기다리지 않고 예산 중단으로 끝난다(서로를 영원히 기다리지 않는다). 시간 예산 역시 전체 실행의 완료 SLA가 아니다. API로 root `priority`를 저장할 수 있으나 별도의 고급 우선순위 UI를 전제로 하지 않는다. 서로 다른 대상은 worker를 늘려 병렬 처리하고, 동일 bucket/repo/page는 쓰기 충돌을 막기 위해 직렬화한다. S3의 한 prefix를 자동으로 수천 동시 range shard로 나누는 구현은 아니다.

Notion 페이지 root가 있는 `BASELINE`·`RECONCILE`·`DELTA` 실행은 계획 단계에서 승인 페이지들의 머리글을 검색 한 번의 순회로 받는다(공급자 `plan_metadata`). 연결의 봉인 자격증명은 worker의 `plan_reader`가 스캔과 같은 방식으로 worker 안에서만 열고, 요청은 스캔과 같은 DB 간격(초당 2.5회·429 대기)을 지킨다. 순회 요청과 순회에 걸린 시간은 실행의 `requests`·`seconds` 예산에서 먼저 내고 남은 몫을 root에 나눈다. 요청은 보내기 전에 그때까지 걸린 시간과 함께 계획 작업 checkpoint에 예약하고, 그 사이에도 마지막 저장 뒤 5초(`WALK_SAVE_SECONDS`)가 지나면 다음 요청 전에 걸린 시간을 저장하므로, 계획이 다시 돌아도 요청을 실제보다 덜 세지 않고 앞선 순회의 시간은 한 번만 낸다(worker가 죽으면 최대 5초와 요청 한 번의 시간만 덜 센다). 순회는 root마다 요청 한 번과 1초를 남긴다. 그만큼도 남지 않으면 순회하지 않고, 순회 중 남은 시간이 그 아래로 내려가면 찾은 만큼으로 멈춘다. 마지막 요청이 길어 넘쳐도 root 몫은 root마다 1초 아래로 내려가지 않는다(승인 총량보다 많이 주지는 않는다). 각 페이지 root에는 자기 페이지의 정보(`page_meta`: `url`·`title`·`last_edited_time`·`observed_at` 문자열, 8 KiB 이하)만 넘기고 수집기는 그 페이지의 머리글 요청을 건너뛴다. 예산 소진과 Notion 오류는 찾은 만큼만 쓰고, 그 밖의 실패(자격증명 해석 등)는 정보 없이 계획한다. 정보를 받지 못한 페이지는 자기 머리글을 읽는다. 실행의 중지·승인 변경·리스 상실은 계획을 멈춘다. 변경 이벤트 실행은 순회하지 않는다. 실행 커버리지의 `requests`는 계획 작업의 요청(끝나지 못한 계획은 예약한 수)을 포함하고, root 결과의 `partially_inspected`·`inspection_gaps`를 합친다(어느 root의 목록이 잘렸으면 `inspection_gaps_overflow`).

### 실행 종류와 해제 근거

| mode | 현재 구현 |
| --- | --- |
| `BASELINE` | 승인 범위 현재 목록을 열거하고 검사. 유효한 passive cache는 재사용 가능 |
| `DELTA` | S3/Notion watermark보다 최근 항목 및 실패 키 재검사, GitHub blob SHA 재사용. 기준 checkpoint/탐지 정책이 없거나 바뀌면 기준 검사가 필요 |
| `RECONCILE` | 현재 승인 범위를 다시 대조. 버킷의 모든 과거 버전이나 Git 이력을 조사하는 뜻은 아님 |
| `INVENTORY` | S3만, 아래에 지정한 기존 보고서 비교. `coverage_basis=INVENTORY_REPORT_ONLY`, `root_coverage_complete=false` |
| `EVENT` | 내부 트리거 작업. 지정한 현재 위치를 읽거나 승인 root DELTA로 합침. root baseline/watermark를 확정하지 않음 |
| `POLICY_SWEEP` | 내부 저우선순위 작업. 변경된 탐지 정책에 영향받을 수 있는 기존 스캔 root 재검사; 새 자산을 최초 승인/활성화하지 않음 |

**업그레이드 보류(`policy_hold`)**: 탐지 정책 digest가 바뀐 root(watermark가 있고 실패 목록 overflow가 없는 root)에 `DELTA`나 `EVENT`의 root 전체 변경분(`full_delta`)이 오면 평소에는 `BASELINE`(전체 읽기)이 된다. 업그레이드 보류 중인 범위의 변경분 슬롯과 변경 이벤트 실행에는 `policy_hold: true`가 붙고(`cremore.scanning.triggers.upgrade_hold`), 그런 실행은 전체 읽기로 바뀌지 않는다. S3·Notion은 watermark 뒤에 바뀐 것과 이전 실패 키만 현재 정책으로 읽는다(`reconcile_if_older_than_seconds`로 `RECONCILE`이 되지도 않는다). 캐시로 재사용하는 나머지 공급자(GitHub·GitLab·Bitbucket·Confluence·GCS·Azure Blob·Azure DevOps·웹사이트)는 아무것도 읽지 않고 공급자도 부르지 않는다. 정확한 경로만 읽는 `EVENT`는 그대로 그 경로를 읽는다. 보류된 실행은 새 정책을 확정하지 않는다: `detection_digest`·`last_reconcile`·root의 이어갈 위치를 쓰지 않고, 미검사 사유는 더하기만 한다(S3·Notion 변경분은 watermark를 옮긴다). 결과에는 `policy_held: 1`과 `root_coverage_complete: false`가 남아, 보류가 끝난 뒤의 전체 검사나 정책 재검사가 그 root를 다시 전부 읽는다. 그동안 변경 조회가 없는 캐시형 root는 바뀐 내용을 다음 전체 검사에서 읽는다(기본 최대 하루).

보류로만 불완전한 실행은 `PARTIAL`로 남되 실패로 세지 않는다. 작업 결과는 보류된 root 수(`policy_held`)를 더하고, 보류 말고는 실패·건너뛴 객체·미검사 사유·overflow·예산 중단이 없을 때만 `policy_held_only`를 붙인다. 실행 목록(`GET /api/v1/scan-runs`)은 `policy_held_roots`·`policy_held_only`를, 작업 목록(`GET /api/v1/source-scan-jobs`)은 `POLICY_HELD`를 보여 주고, 운영 상태는 그 실행에 `JOB_PARTIAL`을 내지 않으며 연결 상태도 일부 실패로 보지 않는다. 아무것도 읽지 않는 캐시형 root도 다시 읽지 못한 이전 실패 키(root의 것과, 같은 작업의 이전 시도가 남긴 것)는 실패로 세고, 같은 작업의 이전 시도에서 실패 목록이 상한을 넘었으면 다른 실행처럼 `RETRY_STATE_OVERFLOW`로 멈춘 것으로 보고하므로 그런 실행은 `policy_held_only`가 되지 않는다. 콘솔의 "최근 7일 실패" 칸과 그 목록은 `policy_held_only` 실행을 빼고, 실행 행과 상세는 전체를 다시 읽지 않은 이유를 보여 준다.

실제로 완독한 객체에서 이전 탐지가 사라지면 DELTA/EVENT에서도 해당 exposure를 제거 표시할 수 있다. 반대로 S3·Notion DELTA가 기존 노출이 있는 객체를 목록에서 watermark 이전 수정 시각으로 다시 보면 읽지 않고도 그 노출의 `last_seen_at`을 갱신한다. 금고 대조의 노출 최신성은 이 관측 시각을 쓴다. Inventory·EVENT 경로는 이 갱신을 하지 않는다. 목록에서 사라졌다는 이유로 제거하려면 **해당 범위의 완전하고 권위 있는 목록**이 필요하다. 실패한 읽기, Notion 검색 누락/404, 이벤트의 삭제 필드, Inventory의 과거 부재만으로는 충분하지 않다. Notion의 `collector_epoch`가 없거나 오래된 부모 경로 노출은 자동 해제하지 않으며 실제 재탐지/출처 재확인이 필요하다.

S3에서 예산 중단이나 양보 뒤 이어간 실행은 승인 prefix마다 이어간 키(`StartAfter`)부터 끝까지 나열한다. 그 나열을 끝까지 마친 시도는 이어간 키 **다음**의 승인 범위(제외 prefix 밖)에서 목록에 없는 기존 노출 위치를 제거로 확정한다. 이어간 키 이하의 위치는, 나열한 객체를 모두 커밋한 뒤 이 시도가 나열하지도 다시 읽지도 않은 승인 범위의 감시 위치(열린·검증 노출과 root의 이전 실패 키)를 `HEAD`로 하나씩 확인해 404(`404`·`NoSuchKey`·`NotFound`)인 것만 제거로 확정한다(root의 실패 키 목록과 이 실행의 실패 수에서도 뺀다). 거절(403)·요청 제한·그 밖의 오류는 아무것도 확정하지 않는다. 확인은 한 시도에 최대 1,000개(`MAX_REMOVAL_CHECKS`)이고 실행의 요청 예산에서 낸다. 후보가 그보다 많으면 노출을 먼저, 그다음 이전 실패 키를, 각각 실행 ID의 digest로 정한 위치부터 확인하므로 같은 실행의 시도는 같은 위치를, 다른 실행은 대개 다른 위치를 본다. 그 사이 예산이 떨어지면 확인만 조용히 멈추고 이미 404로 확인한 것만 확정하며, 남은 위치는 다음 전체 검사가 맡는다. 확인하는 동안에는 기다리는 변경 스캔에 양보하지 않는다(중지·승인·리스·시간 예산은 확인마다 본다). GET이 404로 답한 키도 실패가 아니라 사라진 것으로 확정한다. scanner 역할에 새 권한은 필요 없다(`s3:GetObject`가 HeadObject를 포함하고, 읽기 전용 허용 목록에 `head_object`가 있다). 나열을 끝까지 마치지 못하고 멈춘 시도(예산·양보)는 HEAD 확인도 목록 기반 확정도 하지 않는다(GET 404 확정은 유지). "전체 root를 나열했다"는 판단(미검사 사유 교체, `last_reconcile`, provider 상태)은 이어간 실행에 적용하지 않는다.

`all_locations_removed=true`는 저장된 현재 위치에서 노출이 사라졌다는 뜻이지 credential 폐기 완료가 아니다. finding의 역사적 위험도/대표 증거와 수동 FP·무시·해결 판단을 보존한다. Git history·S3 이전 버전·이미 복제된 자격증명에 대한 대응은 별도로 수행한다. `rejected`나 `SignatureDoesNotMatch`만으로 키 교체/폐기 완료를 선언하지 않는다.

### S3 증분과 Inventory

S3 객체 노출 ARN과 카탈로그 bucket ARN은 worker가 검사 대상 계정의 현재 scanner 승인을 확인한
partition(`aws`, `aws-us-gov`, `aws-cn`, `aws-eusc`)으로 만든다. 일반 수집·승인 root·Inventory의
하위 객체 읽기와 카탈로그에 같은 신뢰 값을 전달하며, 작업 payload의 partition이나 region으로 추정하지 않는다.
승인이 거절되거나 partition이 없거나 지원되지 않으면 운영 수집을 차단한다. 읽기 전용·계정 소유자 검사는 유지한다.
계정 등록 전 온보딩 카탈로그도 검증된 scanner 승인의 partition을 쓰고, 세션을 여는 동안 승인 revision이
바뀌면 목록을 읽지 않는다. 직접 주입하는 수집기·카탈로그의 기존 기본값은 상용 `aws`로 유지한다.
기존 저장 ARN을 일괄 수정하지 않으며 다음 수집·카탈로그 갱신부터 적용한다.

일반 DELTA는 승인 prefix의 `ListObjectsV2`를 수행하고 스캔 시작 watermark와 **5분 겹침 구간**으로 후보를 고른다. 일반 목록 revision은 ETag+Size+LastModified다. VersionId는 실제 GET/Inventory 등에서 제공될 때 활용하며 모든 객체에 버전 조회 HEAD를 추가하지 않는다. 실패/미검사 키는 수정 시각과 관계없이 재대상이다. 실패 키 10,000개 또는 직렬화 256,000 bytes 상한을 넘으면 overflow를 유지하고 trustworthy checkpoint 전진을 중단한다. 다음 일반 실행은 누락될 수 있는 오래된 키까지 전체 복구 검사하며, 충분한 예산으로 완전하게 복구되기 전에는 overflow를 해제하지 않는다. 목록 비용까지 줄여야 할 때 기존 Inventory를 보조 경로로 사용한다.

Inventory는 기존 **CSV 또는 CSV.gz** 보고서만 지원한다. Parquet/ORC는 명시적으로 실패하며, 새 보고서 설정을 만들거나 최신 manifest를 자동 탐색하지 않는다. 운영자가 worker에 정확한 참조를 주입한다. 아래 UUID·bucket·manifest는 실제 승인 값으로 바꾸고 원문 자격증명은 넣지 않는다.
All versions CSV의 AWS schema 필드명은 `VersionId`, `IsLatest`, `IsDeleteMarker`다.
이 경우 최신 live 객체만 현재 GET으로 읽고, 삭제 marker는 현재 HEAD로 부재를 확인한 뒤에만 제거 근거로 사용한다.

```bash
export SCAN_INVENTORY_MANIFESTS='{"11111111-1111-4111-8111-111111111111/example-bucket":{"manifest_bucket":"example-inventory","manifest_key":"reports/config/2026-09-15/manifest.json"}}'
```

worker가 새 환경을 받도록 재시작한 뒤 S3 승인 profile로 preview를 만들고 다음 body를 `/api/v1/scan-runs`에 보낸다. API 인증/실행 방법은 README 예제와 같다.

```json
{"plan_id":"<new-preview-plan-id>","profile_version":1,"mode":"INVENTORY"}
```

보고서가 바뀔 때마다 `manifest_key`를 갱신한다. 같은 설정/탐지 정책으로 성공한 이전 보고서만 자동 비교 기준으로 삼고, 처음이나 정책/범위가 달라진 경우 그 보고서 범위를 다시 검사한다. manifest의 source/destination, schema, timestamp, 보고서 크기/MD5를 검증한다. source role에는 승인 원본과 정확한 manifest/report 객체의 읽기 권한이 필요하며, 암호화가 요구할 때만 제한된 KMS 권한을 별도로 검토한다.

**Inventory 목적지 bucket(`manifest_bucket`)도 검사 대상 계정 소유여야 한다.** AWS 자체는 다른 계정의 목적지를 허용하지만,
현재 worker는 manifest와 report를 읽을 때 `ExpectedBucketOwner`를 검사 대상 계정으로 고정한다. 다른 계정 소유 bucket은
교차 계정 읽기 권한이 있어도 403 AccessDenied가 나며, 현재 `INVENTORY_INVALID_REPORT`와 AccessDenied detail로 보고된다.
같은 계정 소유 목적지를 사용해야 하며, 권한 추가만으로 이 소유자 제약을 해제할 수 없다.
([AWS 목적지 조건](https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-inventory.html#storage-inventory-buckets),
[GetObject 소유자 확인](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html#API_GetObject_RequestParameters))

**보고서에는 원본 Inventory prefix 필터가 보장되어 있지 않고 생성 지연도 있다.** 따라서 완료된 보고서 처리도 전체 bucket 검사 완료가 아니다. 일반 root watermark를 전진시키지 않는다. 보고서에서 사라진 *기존 finding 경로*만 현재 HEAD로 재확인하며, AccessDenied는 부재가 아니다. 보고서 이후에 생긴 객체와 보고서 밖 범위는 일반 DELTA/RECONCILE로 확인한다. S3 Batch Operations, 보고서 생성, bucket notification/CloudTrail selector 변경은 이번 구현에 없다.

### 스케줄

Admin이 profile의 `schedule_minutes`(변경분, 5~43,200, `0`은 꺼짐)와 `full_scan_minutes`(전체, 60~1,440, `0`은 꺼짐, null은 설치 기본값)를 저장한다. profile의 다른 선택/예산 필드도 함께 보존하고 PATCH 시 현재 `expected_version`을 보낸다.

예약 검사는 기본으로 켜져 있다. 관리자가 대시보드에서 끄거나(`PUT /api/v1/settings/scan-triggers` → `schedules_enabled: false`) 설치 기본 전체 검사 주기·시작 시각(`full_scan_default_minutes`, `full_scan_start_minute`)을 바꾼다. 배포 환경은 이 기능을 허용(기본)하거나 잠글 뿐이다.

```bash
# 설치 전체에서 예약 실행을 막을 때만 필요하다. 기본값은 enabled다.
export SCAN_SCHEDULES_MODE=disabled
```

worker는 현재 슬롯마다 한 번만 durable 등록한다. 변경분 슬롯은 UTC 자정부터 세는 `DELTA`, 전체 검사 슬롯은 설치의 시작 분부터 세는 `RECONCILE`이다. worker 중단 동안 놓친 **모든 과거 슬롯을 재생하는 cron 서비스는 아니며**, 재개 후 현재 슬롯을 처리한다. 다른 스캔이 실행 중이어도 슬롯의 작업은 대기열에 접수되고, 같은 범위의 예약 작업 중 같거나 더 강한 mode가 아직 대기 중이면 그 작업이 슬롯을 맡는다(합치기). 슬롯이 지나가면 재생하지 않는다. 다음에 실제로 실행되는 스캔은 그 시점의 현재 상태를 확인할 뿐, 그 사이에 생겼다 사라진 내용 같은 중간 변경 이력은 복원하지 않는다. 권한이 바뀌거나 profile이 준비되지 않았으면 자동 실행하지 않는다.

### 전용 SQS

**기존 Lambda/업무 파이프라인 큐를 공유 소비하면 메시지를 빼앗는다.** CreMore만 소비하는 별도 큐를 조직 담당자가 먼저 만들거나 제공해야 한다. 기존 EventBridge rule을 수정하는 대신 별도 rule/target을 승인받아 추가할 수 있지만 이것도 외부 인프라 변경이며 CreMore가 자동 수행하지 않는다. queue policy, DLQ, redrive/보존기간과 비용은 조직 운영자가 구성한다.

큐 URL, 승인 profile, "이 큐는 CreMore 전용"이라는 확인은 Admin이 대시보드에서 입력한다(`PUT /api/v1/settings/scan-triggers` → `sqs_enabled`, `sqs_profile_id`, `sqs_queue_url`, `sqs_dedicated_acknowledged`). 확인 주체가 설정 기록에 남는다는 점에서 환경변수보다 낫다. 네 값 중 하나라도 비면 트리거는 꺼진 것으로 읽고 큐를 건드리지 않으며, 대시보드가 `blocked_by`로 무엇이 빠졌는지 알린다. 폴링 때마다 현재 바인딩을 읽으므로 변경에 재배포가 필요 없다.

```bash
export AWS_REGION=us-east-1
# 선택: 설치 전체에서 큐 소비를 막거나, 값을 설정에 고정할 때만 필요하다.
export SCAN_SQS_MODE=disabled
export SCAN_SQS_PROFILE_ID='11111111-1111-4111-8111-111111111111'
export SCAN_SQS_QUEUE_URL='https://sqs.us-east-1.amazonaws.com/123456789012/cremore-only'
export SCAN_SQS_DEDICATED_ACKNOWLEDGED=true
```

한 worker는 한 큐/승인 profile에 바인딩되며 profile의 `event_mode`도 켜야 한다. worker의 기초 AWS 신원에 **해당 큐만** `sqs:ReceiveMessage`, `sqs:DeleteMessage`를 부여한다. source S3 read-only client와 별개의 소비 경로이며 다른 큐의 메시지를 발견·수신하지 않는다. S3 notification, EventBridge S3 object 변경, CloudTrail mutation 신호와 정규화된 body를 지원한다. `LookupEvents`로 S3 data event를 수집하는 기능은 아니고 읽기 이벤트는 재스캔 루프 방지를 위해 거부한다. SNS envelope를 자동 해제하는 범용 수신기도 아니다.

한 번에 최대 10개, visibility 60초, long-poll 대기 없이 수신한다. 모든 파생 작업이 durable 등록된 뒤에만 delete한다. 다른 콘텐츠 스캔이 실행 중이어도 메시지를 수신하고 작업을 대기열에 접수한다. 한 메시지가 여러 root 이벤트를 담으면 모두 등록한 뒤 delete한다. 등록 중 실패해 재전달되면 이미 등록된 이벤트는 receipt로 반환되고 남은 이벤트만 등록된다. 형식/권한/DB 실패는 ACK하지 않으므로 큐의 redrive 정책(`maxReceiveCount`)·DLQ와 실패 경보를 운영해야 한다. 스캔 완료 전에 ACK하는 이유는 실행 책임이 이미 DB 큐로 넘어갔기 때문이다. 메시지 payload 자체는 credential·원본 내용 전달 수단이 아니다.

### 변경 조회기와 다른 큐

코드 저장소(Azure DevOps TFVC 포함)·Confluence 공간·Notion 페이지는 변경 조회기로, GCS·Azure Blob·코드 저장소 알림은
고객의 Pub/Sub·Service Bus 큐로도 받을 수 있다. 변경 조회기는 기본으로 켜져 있고 공급자별 주기는 Bitbucket 15분,
나머지 5분이다. 새 연동의 범위는 "변경되면 검사"(`event_mode: ENABLED`)가 켜진 채 저장된다. 변경 조회는 worker 관리
루프에서 돌므로 요청 제한·서버 오류를 기다리지 않고 다음 조회로 넘기며, 한 회차는 첫 조회부터 20초 안에서만 새 조회를
시작한다(남은 root는 다음 회차에 먼저, 폴링 결과의 `deferred`). 켜는 방법과 공급자별 규칙은 [변경 감지 스캔](CHANGE_FEEDS.md)에 있다.

### 데이터 보존·성능·인증

원문은 DB/로그에 남기지 않지만 **경로, 실패 키, root 이름, 마스킹된 증거도 민감한 metadata**다. DB·백업·worker 임시 디렉터리를 같은 보안 등급으로 관리한다. HMAC identity/index는 경로 암호화가 아니며 `exposures.location`은 분석·재검사를 위한 원래 경로다.

| 저장/처리 | 현재 제한 및 운영 의미 |
| --- | --- |
| Root 상태 | 실패 키 최대 10,000개/직렬화 256,000 bytes, root JSON 문자열 크기 상한 2,000,000; 정상 S3 객체마다 영구 row를 만들지 않음. overflow는 전체 복구 성공 전까지 유지 |
| Passive cache | 연결/source root + subject/revision + engine digest. GitHub 빈 결과 캐시, S3 finding이 있는 결과만. 결과당 직렬화 최대 128,000 bytes |
| Cache 정리 | SQL에서 14일/100,000 row를 목표로 매 maintenance에 최대 1,000개 삭제. 동시 쓰기 사이의 초과 가능; 하드 DB byte quota 아님 |
| Trigger receipt | 15일보다 오래된 terminal 작업 receipt를 최대 10,000개씩 정리. active와 POLICY_SWEEP receipt 보존; job/plan은 삭제하지 않음 |
| Evidence/catalog/task | 자동 전역 보존기간·DB 용량 상한 없음. 조직별 보존/백업/용량 정책 필요. 과거 catalog JSON도 호환 증거로 남을 수 있음 |
| GitHub archive | 압축 256 MiB, 확장 1 GiB, 200,000 member, 120초, 압축비 제한. 일반 파일을 메모리에서 SHA 검증하며 디스크 추출 안 함 |
| Inventory | manifest 4 MiB, 최대 10,000 report file/10,000,000 row, 압축 4 GiB/확장 8 GiB, 비교 SQLite 2 GiB, 300초. 보고서 이름/revision만 private 임시 DB에 저장 후 정리 |
| 일반 내용 | 객체 기본 50 MiB(`MAX_OBJECT_SIZE_MB`), 엔진 탐지 상한 시 미완료. ZIP/gzip 등 일반 압축 객체는 추출 지원하지 않음 |

cache는 원본 보관소가 아니다. 누락/만료되면 승인된 원본을 다시 읽는다. GitHub cache는 경로 필터 **전** passive 결과를 저장하여 이름 변경 시 현재 경로 규칙을 다시 적용한다. live verification은 cache를 우회하며, 명시적으로 켜고 확인(acknowledge)한 설치에서만 동작한다. risk/severity/learned FP 변경은 저장 근거로 전역 재점수를 진행하고, 근거가 없는 구버전 row는 기존 점수와 `NEEDS_RESCAN`을 유지한다. 규칙 패턴/경로 scope 변경은 이미 검사한 승인 root의 낮은 우선순위 재스윕을 유발한다. 재스윕 root 작업이 시작될 때 그 root를 다른 전체 실행(예: 같은 범위의 예약 `RECONCILE`)이 이미 현재 정책으로 남김없이 다시 읽었으면, 즉 root 상태에 watermark가 있고 `detection_digest`가 현재 정책과 같으며(재스윕을 접수하지 않는 기준) 실패 키와 실패 목록 overflow가 없으면 수집기를 만들지 않고 아무것도 읽지 않은 채 끝난다(`policy_current: 1`, 앞선 시도의 수, root의 열린 미검사 사유는 다른 실행처럼 `inspection_gaps`·`root_coverage_complete=false`로 보고). 실패 키가 남은 root는 재스윕이 그대로 읽는다. 영향 root의 자동 세부 glob 최적화까지 보장하지 않는다.

worker는 120초 task lease를 갱신하고 최대 3회 시도한다. 현재 소유자가 아닌 worker는 결과·해제·checkpoint·완료를 쓸 수 없다. 종료 후 lease 만료 회수는 정상 복구 경로지만, 실패한 작업이 무한 재실행되지는 않는다. S3는 durable key checkpoint로 재개하고 GitHub는 재열거할 수 있다. checkpoint는 탐지 정책 digest에 바인딩되어 재시도 사이 규칙이 달라지면 처음부터 열거하되 **이미 소모한 예산은 복원하지 않는다**. 예산이 부족하면 새 승인 run이 필요하다. `count_basis=COMMITTED_OBJECT_ATTEMPTS`는 재시도를 포함하므로 고유 객체 총수로 보고하지 않는다.

`timings.listing_seconds`는 iterator에서 다음 객체를 받는 수집 시간이며 eager Notion/정확한 S3 읽기/archive 다운로드가 포함될 수 있다. `download_seconds`는 lazy loader 시간, `engine_seconds`/`persistence_seconds`는 계측된 엔진/저장 구간이다. 네 값이 모든 네트워크·DB·대기 시간을 정확히 분할하거나 합산하는 청구 metric은 아니다. `requests`는 기록된 논리 SDK/API 호출로 botocore 내부 HTTP 재시도까지 별도로 세지는 않는다. 최초/재스캔의 동일 승인 범위에서 이 값과 `reused`, 예산 중단, DB 용량을 함께 비교한 뒤 worker 수를 조정한다.

AWS member scanner role 세션은 `DeferredRefreshableCredentials`로 재발급하고 비밀값은 메모리에만 둔다. 기초 AWS 신원도 instance/task/workload role로 공급해야 한다. 사람이 복사한 만료 STS 환경변수의 자동 재발급까지 해주지는 않는다. GitHub App 및 Vault/OpenBao Kubernetes 로그인도 메모리 기반 갱신이며 provider 장애·권한 철회·Notion 토큰 교체·IdP 최대 세션 만료는 운영 대응이 필요하다.

Compose는 위 `SCAN_*` 변수를 실행 프로세스 환경에서 API/worker로 전달한다. 별도 `.env` 파일은 필수가 아니며, 렌더링된 `docker compose config`에는 주입한 비밀값도 포함되므로 출력물을 공유하지 않는다. Helm은 `scanning.schedulesMode`, `scanning.sqs`, `scanning.inventoryManifests`로 설정하며 정확한 매핑과 예제는 [Helm 운영 안내](../deploy/helm/README.md#optional-scan-schedules-events-and-inventory)에 있다. `*_MODE`는 트리거를 허용(기본)하거나 잠글 뿐이고 실제 스위치는 대시보드에 있다. 예약 검사와 변경 조회기는 관리자가 끄지 않는 한 켜져 있고(업그레이드 직후 포함, 위 "업그레이드 주의"), 큐는 관리자가 연결·확인하기 전까지 꺼져 있다. 업그레이드 뒤에도 꺼 둬야 하는 설치는 `disabled`로 잠근다. 배포 환경을 못 건드리는 담당자도 대시보드에서 트리거를 쓸 수 있다. web에는 스캔 설정을 전달하지 않는다. VM은 프로세스 service 환경과 조직의 secret 주입을 사용한다. 어느 방식도 승인 profile이나 외부 큐/규칙을 자동으로 생성하지 않는다.

## 완료 체크리스트

체크는 해당 코드 경로가 구현되어 있음을 뜻한다. 마지막 검증 기록의 실제 실행 결과와 별개이며, 실제 고객 계정·규모·배포 검증 완료를 뜻하지 않는다.

### 0a — 규모와 무관한 정확성·안전

- [x] worker는 필요한 reconciliation 뒤에 성공을 기록한다.
- [x] UNKNOWN placeholder upsert가 기존 exposure 점수를 지우지 않는다.
- [x] 정상 스캔과 복구가 동일한 결정적 집계 함수를 사용한다.
- [x] 최고 점수 동률이면 현재 대표 유지, 아니면 안정적인 ID 순서다.
- [x] UNKNOWN이 섞이면 기존 finding을 자동 강등하지 않고, 더 높은 확정 점수만 올린다.
- [x] 노출이 모두 제거되면 역사적 대표/점수를 유지하고 별도 nullable 상태를 기록한다.
- [x] 상태/대표/점수의 실제 변경과 감사 기록은 함께 커밋한다.
- [x] 원장·connection 증거·credential-check 최종 상태는 함께 커밋한다.
- [x] 논리 작업의 (job_id, stage)는 중복 기록하지 않는다. 필수 최종 원장 실패 시 성공하지 않는다.
- [x] Notion child_page/child_database는 별도 승인 자산으로 끊는다.
- [x] Notion 검색 누락과 404만으로 노출을 해제하지 않는다.
- [x] collector_epoch를 명시적으로 저장한다. 없는 행은 legacy, 실제 재탐지 때만 갱신한다.
- [x] 노출 제거로 finding을 자동 RESOLVED 처리하지 않는다. 수동 판정은 보존한다.
- [x] SignatureDoesNotMatch는 INDETERMINATE이며 rejected도 폐기 완료의 증거로 쓰지 않는다.
- [x] scanner SDK 정확한 operation allowlist, 원본 쓰기 명시적 IAM Deny, 회귀 테스트를 제공한다.
- [x] 429는 Retry-After와 제한된 backoff를 지킨다.
- [x] InvalidObjectState는 SKIPPED_ARCHIVED/미검사, GLACIER_IR은 읽는다.

근거: `cremore/worker/worker.py`, `cremore/db/scan_state.py`, `cremore/db/sql.py`, `cremore/collectors/notion.py`, `cremore/aws_readonly.py`, `cremore/http_client.py`와 해당 회귀 테스트. 기존 IAM 역할에 새 Deny가 자동 배포된다는 뜻은 아니다.

### 0b — 데이터·병렬화 전제

- [x] 수집/lazy 다운로드/탐지/저장 시간을 계측하고 내용·키를 metric label에 넣지 않는다. 정확한 wire-time 분리는 별도 계측이 필요하다.
- [x] 기존 advisory lock을 재사용하는 번호형 migration ledger를 제공한다.
- [x] offline 중복 정리, identity_key backfill, unique 제약과 참조 보존을 검증한다.
- [x] findings.primary_exposure_id와 fp_samples.exposure_id를 보존/재지정하고 검증한다.
- [x] credentials/findings/exposures 저장은 원자적 upsert다.
- [x] 탐지마다 전체 exposure를 읽는 경로를 COUNT와 최대값 조회로 대체한다.

근거: `cremore/db/migrations.py`, `cremore/db/sql.py`, `cremore/db/postgres_scan_test.py`, `cremore/scanning/service.py`.

### 1 — 작은 작업·복구·우선순위

- [x] 승인된 root를 부모 실행/자식 task로 분할하며 작업 발행과 체크포인트를 함께 저장한다.
- [x] task PK는 재시도 동안 유지하고 run/root/시작 경계는 중복 발행하지 않는다.
- [x] PostgreSQL SKIP LOCKED, 우선순위, lease/heartbeat/재시도 상한을 구현한다.
- [x] lease 소유권이 바뀐 worker의 결과·해제·완료 쓰기를 차단한다.
- [x] 이벤트 병합 경계별 대기 하나/대상별 실행 하나와 대기 payload의 안전한 병합을 보장한다. 독립 승인 profile을 서로 합치지 않는다.

근거: `cremore/db/task_store.py`, `cremore/worker/runtime.py`, SQL/memory runtime 및 실제 PostgreSQL 동시성 테스트. 범용 원격 shard enumerator 서비스는 추가하지 않았다.

### 2 — 선택 정책·카탈로그

- [x] root 단위 정규화된 catalog와 작업 membership, 페이지 조회를 사용한다.
- [x] 기존 profile/preview/승인을 재사용하고 포함·제외·우선순위·예산을 적용한다.
- [x] 승인/권한/규칙 변경 시 계획과 재사용 범위를 재검증한다.

근거: `cremore/db/catalog_store.py`, `cremore/scanning/scope.py`, `cremore/api/catalog_run_test.py`, `cremore/scanning/scope_execution_test.py`.

### 3 — 증분과 증거 기반 reconciliation

- [x] 재시도 키(run/task)와 재사용 키(asset/revision/detection digest)를 분리한다.
- [x] root checkpoint와 finding/실패 객체만 유지한다. S3의 빈 결과별 영구 행은 만들지 않는다.
- [x] checkpoint는 안전한 시작 시점/겹침 구간을 사용하며 모든 쓰기가 끝난 뒤 전진한다.
- [x] 실패/미검사 키는 오래된 수정 시각이어도 재대상이다. 개수/byte overflow는 전체 복구까지 유지하며 digest가 바뀐 재시도는 열거를 다시 시작한다.
- [x] 실제 완독 객체에서 사라진 노출은 실행 종류와 무관하게 해제할 수 있다.
- [x] 목록 부재 해제에는 해당 범위의 권위 있는 완전 목록이 필요하다.
- [x] Notion 완독/빈 페이지/부분 읽기를 구분하고 현재 epoch만 페이지 단위로 해제한다.
- [x] 탐지 digest는 실제 탐지 입력만 포함한다. 규칙/규칙 scope 변경은 기존 root를 낮은 우선순위로 재스윕하며 새 선택 범위는 새 기준 검사가 필요하다.
- [x] 경로 필터 전 passive 마스킹 결과를 재사용하고 현재 경로 정책/위험도/FP를 재적용한다.
- [x] GitHub만 빈 SHA 결과도 캐시한다. 실시간 검증 요청은 캐시를 우회한다.
- [x] 재점수 근거를 보존하고 수동 FP/무시/해결 판정을 덮어쓰지 않는다.

근거: `cremore/db/scan_store.py`, `cremore/scanning/service.py`, `cremore/scanning/orchestrator.py`, `cremore/scanning/rescore.py`, `cremore/worker/runtime.py`.

### 4 — 플랫폼별 가속

- [x] 기존 S3 Inventory manifest를 비교하고 보고서 범위의 원본 목록 조회 비용을 줄인다. 전체 bucket/watermark 완료로 표시하지 않는다.
- [x] 일반 S3 목록 revision은 ETag+Size+LastModified이며, VersionId는 제공될 때만 사용한다.
- [x] GitHub tree/blob SHA 기준 변경을 확인하고 truncated 열거를 예산 내 보완한다.
- [x] 전체 저장소 읽기 승인에서만 commit SHA로 고정한 tarball을 사용한다.
- [x] tar 멤버를 디스크에 풀지 않고 제한된 크기로 읽어 Git blob hash를 검증한다.
- [x] export-ignore/변형/누락은 blob API로 보완하고 submodule은 미검사로 표시한다.
- [x] redirect의 origin 변경에 인증 헤더를 보내지 않고 허용 목적지/크기/시간을 제한한다.
- [x] Notion page별 수정 정보와 검색 겹침 구간을 사용한다.

근거: `cremore/collectors/{s3,inventory,github,github_archive,notion}.py` 및 provider fake 테스트. 실제 대규모 공급자 계정 성능/요금은 별도 검증 대상이다.

### 5 — 선택적 이벤트·스케줄

- [x] 전용 SQS·Pub/Sub·Service Bus는 크기·승인 범위·재전송을 검증한다. 범용 공개 webhook은 사용하지 않는다. Notion만 공식 원문 서명을 검증하는 전용 수신 경로와 관리자 구독 확인을 제공한다([설정](NOTION_CHANGE_WEBHOOKS.md)). 코드 저장소는 변경 조회기 또는 검증된 중계기를 통한 전용 큐를 사용한다.
- [x] 이벤트는 현재 상태 검사 신호이며, 이벤트 순서/삭제만으로 노출을 해제하지 않는다.
- [x] 같은 객체 이벤트는 병합하고 root 키 집합 상한 초과 시 root DELTA로 전환한다.
- [x] 작업의 durable 등록 후에만 메시지를 ACK/delete한다.
- [x] 실행 중 새 이벤트는 후속 작업을 남기고 debounce를 유한하게 제한한다. 큐 지연 SLA는 별도다.
- [x] 승인 profile의 스케줄과 주기적 reconciliation을 실행한다.

근거: `cremore/scanning/triggers.py`, `cremore/scanning/trigger_settings.py`, `cremore/db/task_store.py`, `cremore/worker/worker.py`. 외부 인프라 provisioning은 구현 범위 밖이다.

## 기존 설치본 오프라인 업그레이드

새 DB는 startup에서 v1/v2를 준비한다. 데이터가 있는 구버전 DB는 additive schema(v1)와 데이터 정리(v2)를 분리한다. 새 코드는 v2 완료 전 새 스캔 쓰기를 차단한다. PostgreSQL 15의 `NULLS NOT DISTINCT`에 의존하지 않고 nullable `identity_key`와 일반 unique index를 사용한다. **현재 절차는 온라인 migration이 아니며 `CREATE INDEX CONCURRENTLY`를 사용하지 않는다.**

1. 릴리스 image digest, 현재 API/worker 버전, DB 버전, replica 수, 설정/Secret 참조와 작업 상태를 기록한다. 실행 중인 rollout/GitOps/HPA/cron/수동 CLI 등 writer를 다시 살릴 자동화도 점검 시간 동안 중지한다.
2. 사용자 유입을 유지보수 상태로 전환하고 **API·worker·inline scan·credential check를 포함한 모든 writer**를 멈춘다. worker만 멈추거나 기존 RUNNING 스캔이 끝날 때까지 기다리는 방식은 충분하지 않다. Compose 예: `docker compose stop api worker`. Kubernetes는 실제 이름을 확인하여 API/worker Deployment를 각각 0으로 줄이고 파드 종료를 확인한다. DB는 유지한다. source provider 설정은 변경하지 않는다.
3. writer 종료를 확인한 뒤 복원 가능한 DB 전체 백업을 만든다. DB 밖의 동일 `FINGERPRINT_KEY`, 인증/Secret 참조와 이전 image를 안전하게 보관한다. **덤프 목록 확인만으로 복원 검증이 끝나는 것이 아니다.** 별도 격리 DB에 시험 복원하고 대표 finding/참조를 확인한다. 백업에는 민감한 metadata가 있으므로 암호화/접근 통제를 적용한다.
4. 새 코드의 일회성 migration 프로세스만 실행한다. 운영 DB URL은 secret manager가 `DATABASE_URL`로 공급하며 CLI 인자/로그에 넣지 않는다. `--offline`/`--backup-confirmed`는 프로세스 종료나 백업 유효성을 자동 입증하는 플래그가 아니라 운영자 확인이다.
5. 아래 DB 검증을 수행하고 migration 출력/ledger를 보관한다. 중단된 일반 `RUNNING` 작업은 v2 트랜잭션에서 `QUEUED`로 되돌리고 카운터를 초기화한다. 이미 TERMINAL 원장을 가진 credential-check는 무작정 반복하지 않고 `FAILED`/`INTERRUPTED_TERMINAL_CHECK_REQUIRES_NEW_JOB`로 남긴다. 담당자가 새 check를 요청해야 한다.
6. 모든 API/worker가 **같은 새 릴리스**임을 확인하고 재시작한다. 구버전 writer를 섞으면 identity/lease 계약이 깨질 수 있다. 새 코드의 root task는 lease 만료 후 회수되며 작업별 최대 시도 횟수를 따른다. migration v2가 이미 있으면 명령은 no-op이므로 이후의 일반 장애를 복구하는 만능 재큐잉 명령이 아니다.
7. 기존 finding 수·대표 노출 참조, 스캔 큐, scope 소량 BASELINE/DELTA/RECONCILE과 coverage를 확인한다. 저장 근거 기반 재점수와 `repair_finding_rollup`은 worker에서 수행한다. 별도 공개 aggregate-repair CLI나 과거 평가 시각 복원 기능은 없다. 근거가 부족한 historical finding은 재검사 필요로 남긴다.
8. 문제가 있으면 모든 새 writer를 다시 멈추고 아래 rollback 경계를 따른다. 데이터 백업과 코드 버전을 함께 복구한 뒤에만 서비스를 재개한다.

일반 PostgreSQL 클라이언트가 준비된 **Bash** 예제다. `PGSERVICE=cremore`는 사전에 조직이 구성한 대상 DB의 libpq service 설정을 사용한다. SQLAlchemy용 `DATABASE_URL`과 같은 대상인지 DB명/주소를 먼저 확인하며 두 자격증명은 출력하지 않는다.

```bash
export PGSERVICE=cremore
psql --no-psqlrc --set ON_ERROR_STOP=1 -c 'SELECT current_database(), inet_server_addr(), version();'
pg_dump --format=custom --file=cremore-before-v2.dump
pg_restore --list cremore-before-v2.dump > cremore-before-v2.contents.txt
# 위 백업을 별도 격리 DB에 시험 복원하고, 모든 writer 정지를 재확인한 뒤에만:
python -m cremore.db.migrations --offline --backup-confirmed
psql --no-psqlrc --set ON_ERROR_STOP=1 -c 'SELECT version, name FROM schema_migrations ORDER BY version;'
```

기대 ledger는 `1: additive_scan_observation_schema`, `2: offline_identity_and_check_lifecycle`다. 명령은 500행 keyset batch로 메모리를 제한하지만 데이터 정리 전체는 단일 offline 트랜잭션이므로 큰 DB에서는 WAL·인덱스·백업 여유 공간과 충분한 점검 시간이 필요하다. 신규 컬럼/schema 확장은 별도 트랜잭션으로 이미 남을 수 있고, **v2 데이터 처리 실패 시 v2 변경은 rollback**된다.

다음 검증 쿼리는 수동 확인용이며 데이터를 변경하지 않는다. 반환되는 missing/duplicate/reference 수는 0이어야 한다.

```sql
SELECT COUNT(*) AS missing_identity FROM exposures WHERE identity_key IS NULL;
SELECT identity_key, COUNT(*) FROM exposures
GROUP BY identity_key HAVING COUNT(*) > 1;
SELECT COUNT(*) AS broken_primary_reference
FROM findings f LEFT JOIN exposures e ON e.id = f.primary_exposure_id
WHERE f.primary_exposure_id IS NOT NULL AND e.id IS NULL;
SELECT COUNT(*) AS broken_fp_reference
FROM fp_samples s LEFT JOIN exposures e ON e.id = s.exposure_id
WHERE s.exposure_id IS NOT NULL AND e.id IS NULL;
SELECT table_name, COUNT(*) FROM migration_archive GROUP BY table_name;
SELECT status, COUNT(*) FROM scan_jobs GROUP BY status;
```

migration은 중복 exposure의 원본/변경된 `findings.primary_exposure_id`·`fp_samples.exposure_id` 참조와 check 원장을 `migration_archive`에 보존하고 canonical row로 연결한다. 이 archive는 감사/복구 조사 보조 자료이지 자동 역 migration 도구가 아니다. 중복을 정리하며 실제 row는 줄어드므로 단순 총 row 수 불변을 검증 기준으로 삼지 않는다.

**Rollback:** writer를 모두 정지한 채 검증한 전체 백업을 *분리된 복구 DB*로 복원하고 이전 image·설정·동일 fingerprint key를 함께 연결한다. 확인 후 트래픽을 전환한다. 새 버전이 쓰기 재개한 뒤의 데이터는 pre-upgrade 백업에 없으므로 별도 보존/합의 없이 버리면 안 된다. 원래 DB나 migration archive를 즉시 삭제하지 않는다. 스키마/컬럼을 수작업으로 drop하거나 v2 ledger만 지우고 구버전을 재시작하는 것은 rollback이 아니다.

## 검증 기록

실제 실행한 명령, 결과, 미검증 외부 환경은 구현 완료 시 아래에 기록한다.
fake provider/SQLite 통과를 실제 AWS/Notion/GitHub 또는 PostgreSQL 배포 검증으로
표현하지 않는다. 배포·과금·외부 인프라 생성은 자동으로 수행하지 않는다.

- 시작 상태: main, README.md의 기존 온보딩/운영 안내 변경을 보존하고 이번 스캔 안내를 추가했다. 문서 작업은 커밋·push·실서비스 배포를 수행하지 않는다.
- 2026-09-15 최종 전체 Python: `python -m pytest -q` → **3211 passed, 8 skipped** (94.39초). 부분 객체 실패 중복 집계 수정과 최종 배포 설정 반영 뒤 실행한 결과다. 생략된 8개는 아래의 별도 PostgreSQL opt-in 테스트다.
- DB/재점수 담당 검증: 실제 **PostgreSQL 16.15**의 격리된 localhost 테스트 DB를 포함한 DB/rescore 범위 **129 passed**. 동시 upsert, lease fencing, offline 참조 보존, cursor/audit rollback 포함. 생성한 테스트 컨테이너·데이터는 정리했다. 이는 고객 운영 DB migration 검증이 아니다.
- 웹: `npm test` → **353 passed**, TypeScript `--noEmit` 및 Next.js production build 통과. 이 검증 뒤 웹 소스는 변경하지 않았다.
- 배포: `node --test deploy/helm/tests/chart.test.cjs` → **41 passed, 0 skipped**. 로컬 image로 외부 네트워크 없이 Helm을 렌더링했다. Compose는 운영자 `.env`를 읽지 않는 합성 환경에서 Inventory 변수 미설정/빈 값 → `{}`, 명시 JSON → 원문 그대로 전달됨을 확인했다. 이벤트 키는 Helm의 기존 Secret 참조만 허용하고 API/worker에만 전달된다. 실제 배포나 외부 큐 소비는 수행하지 않았다.
- 패키징: 격리된 임시 가상환경에 기존 `requirements-build.txt`를 `--require-hashes`로 설치하고 `pip wheel --no-deps --no-build-isolation` 성공. 이름 변경 후 2026-09-19 재실행: `cremore-0.1.0-py3-none-any.whl`의 185개 항목에서 runtime/migration/event/Inventory 모듈 포함과 `.env` 미포함을 확인했다. SHA256: `db18cc650022e019c1b5ef2e0e0b439027b4f46285f9ea8f396eb8c691400830`. 호스트/프로젝트 의존성은 변경하지 않았고 임시 증명 디렉터리는 삭제했다.
- 후속 root runtime 회귀 **18 passed**, 선택적 scope/finding-rescan/Notion data-source 브라우저 증명 **3/3 passed**. 실패 목록 overflow 복구 및 정책 변경 checkpoint 재개를 포함한다.
- 최종 리뷰에서 실패 목록 overflow 표시가 지워지는 경로와 탐지 정책 변경 후 이전 suffix cursor를 사용하는 경로를 로컬 재현하고 수정했다. SQL/memory 회귀에서 누락된 실패 키 재검사와 새 정책의 처음부터 재검사를 확인했다. 부분 읽기는 기존 노출을 유지하며 승인된 정상 BASELINE/DELTA/EVENT는 계속 동작한다.
- `python -m ruff check cremore --select E9,F63,F7,F82` 통과, 추가 파일/변경 줄의 확장 Ruff 진단 0개. 저장소 전체 확장 Ruff에는 기존 171개 스타일·예외 처리 경고가 남아 있으며 전체 Ruff 통과로 표현하지 않는다. `python -m pip check` 통과; 패키지 의존성 추가 없음.
- 문서에 기재한 첫 번째 빠른 회귀 명령을 실제 실행: **100 passed in 18.05s**. 상대 링크/코드 fence/PowerShell 예제 구문 검사 및 `git diff --check` 통과. 예제의 실제 고객 계정 호출·배포·migration은 실행하지 않았다.
- 현재 문서에 대응하는 빠른 회귀 범위:

```bash
python -m pytest cremore/api/catalog_run_test.py cremore/scanning/triggers_test.py cremore/scanning/scope_execution_test.py cremore/collectors/github_test.py cremore/collectors/inventory_test.py cremore/worker/runtime_test.py cremore/db/migrations_test.py -q
python -m pytest cremore -q
```

- PostgreSQL 증명은 기본 실행에서 opt-in으로 skip된다. **삭제 가능한 localhost `cremore_test` DB에만** 조직 테스트 설정으로 `CREMORE_TEST_POSTGRES_URL`을 주입한 뒤 `python -m pytest cremore/db/postgres_scan_test.py -q`를 실행한다. 테스트는 임의 생성 schema를 만들고 삭제하므로 운영 DB를 지정하면 안 된다.
- [x] 최종 리뷰 수정 이후 전체 Python/웹/배포 게이트 재확인. 웹은 검증한 소스 상태를 유지하고 Python과 배포 템플릿은 후속 변경 후 재실행했다.
- [ ] 실제 승인된 AWS/GitHub/Notion, 조직 IAM/Vault/OIDC/SQS/Inventory/egress 환경 smoke test.
- [ ] 대표 대규모 데이터셋의 최초/재스캔 시간, 요청 비용, DB/WAL/임시 디스크 용량 측정 및 rollout·rollback 리허설.
- [x] `SECURITY.md` 정책 문구 변경은 2026-09-15 사용자 승인 후 [SECURITY_POLICY_UPDATE.patch](SECURITY_POLICY_UPDATE.patch)와 동일하게 반영했다. 위치 제거와 키 폐기를 구분하고 승인 범위·읽기 전용·lease 원칙을 명시하며 보안 예외를 추가하지 않았다.

후속 확인: [공개 준비·성능 보고서](OPEN_SOURCE_SCAN_PERFORMANCE.md)에 1만 개·4KiB·1% 변경의 S3/GitHub/Notion 로컬 비교, 원시 측정값, S3 최초 스캔 측정 정정·프로파일, 10만 객체 시간 계산 예시와 운영 모드 검증의 정확한 의미를 기록했다. 이 로컬 측정은 위의 실제 고객 계정·대규모 운영 부하 검증 항목을 완료 처리하는 근거가 아니다. 잠금파일 Python·웹 의존성 audit는 작성 시점 알려진 취약점 0건이었으며, 최종 hosted CI·이미지·공개 이력 검증은 별도로 남는다.
