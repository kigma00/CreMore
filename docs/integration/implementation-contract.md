# develop_total 구현 계약 — DB, 실행, API, 이행

기준일: **2026-09-21**. 상태: **소스 분석, 원본 오프라인 검증 완료, 제품 통합 구현 전**.

`develop`의 제품 구조와 기존 기능을 기반으로 다섯 팀원 브랜치를 합친다. 동일 기능이 겹치거나 기존 구현에 기능이 빠졌다면 **팀원의 기능, 상세 정보, 동작 의미를 우선 보존**하고 기존 API, worker, DB, 대시보드에 맞춘다. 독립 실행 프로세스, SQLite/JSON, HTML 화면까지 각각 운영해야 한다는 뜻은 아니다. 기능별 수용 위치와 검증 증거를 남긴다.

이번 산출물은 `develop_total`의 설계 문서다. `develop`의 코드, ref는 변경하지 않았고 팀원 코드를 병합, 배포하거나 실제 공급자 API로 자격증명을 검사하지 않았다.

## 1. 분석 기준과 근거

### 고정 revision

| 구분 | 분석한 commit |
|---|---|
| `develop`, `publish/develop` | `71ea52ad933708b7fb851f590ab7162d7f7ed35f` |
| 작업 시작 시 `develop_total` | `77ae109eb201be44798086e2b43eb1879fb488b4` |
| 최종 확인한 `develop_total`의 기존 커밋 | `0186f12e0c21c82fe65f2a8d48e732d86c73d840` |
| `publish/develop_gitLab` | `972eac277c015898d1785cd74f710243e4788e5c` |
| `publish/develop_gcp` | `3d79ccbef4ad51a7e7b9e0f73eabb1ac478c5ade` |
| `publish/develop_github` | `bfb97fb1f6147439904045824fa1a756c2768655` |
| `publish/develop_atlassian` | `11c44f2afdf0874f736eb30018992bd9855fd2d9` |
| `publish/develop_slack` | `48ea164345f0df32ec25d0e11af72fccb7786f9a` |

원격은 `publish`의 `https://github.com/y4rvin/CreMore.git`다. 별도 `origin`과 혼동하지 않는다. 작업 시작의 `develop_total`은 `develop`과 제품 코드가 같고 통합 설계 문서만 달랐다. 읽기 쉬운 추천안은 [통합 설계](../INTEGRATION_DESIGN_REVISED.md), 상세 구현 조건은 이 부록을 기준으로 한다.

최종 확인에서는 후속 문서 커밋 `21e4da7`, `36761d2`, `0186f12`와 `docs/BRANCH_FUNCTIONS.md`도 확인했다. 모두 문서 변경이며 기존 커밋은 되돌리지 않았다. 추가 기능 목록은 보존하면서 이번 검증과 다른 집계, 범위 설명을 정정했다. 이번 설계/부록 변경은 아직 커밋, 푸시하지 않은 작업트리 변경이다.

GCP만 최근 develop 계열의 공통 조상 `6cabc6b351274a4da5340bb18c8d081caa9f899b`에 모듈을 추가했다. 나머지 네 브랜치는 초기 `CreMore_github/` 트리의 `6d2cd3a9ee4f91c87951c0752fb5d15325fadb79`에서 갈라진 독립 프로그램이다.

### 실제 판독 범위

| 브랜치 | 추적 파일 / 팀원 기능 판독 | 방식 | 상세 보고서 |
|---|---|---|---|
| GitLab | 13 / 13 | 소스, 테스트, 예제, 설정 전체 | [GitLab](gitlab.md) |
| GCP | 390 / 신규 24 | 조상 대비 추가 24개 전체. 나머지 366개는 조상 트리 | [GCP](gcp.md) |
| GitHub | 83 / 83 | 63개 고유 blob 전체, 20개는 동일 blob 확인 | [GitHub](github.md) |
| Atlassian | 82 / 82 | 소스, 테스트, 문서 등 57개 전체, 증거 JSON 25개는 구조, 출처 검토 | [Atlassian과 Bitbucket](atlassian.md) |
| Slack | 95 / 95 | 전체, 테스트 후 원본 95개 blob 동일성 확인 | [Slack](slack.md) |

팀원 독립 트리, 추가 모듈 **297개 파일을 모두 분류**했다. 모든 팀원 소스 코드를 읽었으며, Atlassian의 개인/고객 샘플 증거 JSON 25개는 모든 값을 정독했다고 주장하지 않는다. [파일별 판독 대장](source-inventory.csv)에 commit, path, blob, 줄 수, 읽기 상태를 남긴다.

`develop`의 397개 파일을 이번에 전부 새로 읽었다는 주장은 아니다. 콘텐츠 collector, 인증/비밀 참조, coverage, task lease, 관련 domain/API/UI, 패키징, 배포 접점을 읽었다. [기준 코드 판독 범위](baseline-read-scope.csv)는 주 조사에서 전체/일부를 읽은 범위를 구분한다. 각 상세 보고서에는 추가 비교한 기준 코드와 행 근거가 있다.

코드 구현 사실, 팀원의 과거 진단, 원본 오프라인 검증, 공개 공식 문서 확인, 향후 실환경 검증을 구분한다. 2026-09-21 후속 조사에서 [공식 문서 및 OpenAPI](official-docs.md)의 관련 계약을 직접 읽고 대조했다. 실제 기업 계정 권한과 API 성공 여부는 검증하지 않았다.

## 2. 기존 제품과 데이터 의미

### 유지할 develop 구조

현재 제품은 Next.js 대시보드, FastAPI, 공통 Python worker, SQLAlchemy/PostgreSQL, 기존 작업 큐/lease/checkpoint, 감사, 역할 권한을 사용한다. 콘텐츠의 노출은 `Credential`–`Exposure`–`Finding`, 금고 및 AWS 발급/사용 근거는 coverage 연결/run/batch가 담당한다.

| 책임 | 기준 코드 접점 | 유지할 의미 |
|---|---|---|
| S3, GitHub, Notion, GitLab, GCS, Confluence, Bitbucket 콘텐츠 | `cremore/worker/factory.py:25`, `cremore/source_config.py:1` | 팀원 metadata로 콘텐츠 노출 탐지를 교체하지 않음 |
| 노출, 검증, 업무 처리 | `cremore/domain/models.py:63`, `:98`, `:131` | 발견 위치, 검증 사실, 연결 상태의 연속성 |
| Vault 대조 | `cremore/coverage/collect.py:1`, `:313`, `hasher.py:1`, `correlation.py:1` | AWS SM/SSM, Vault/OpenBao, GCP SM 경로 재사용 |
| 작업, 동시성 | `cremore/db/task_store.py:240`, `:361`, `:433`, `:660` | DB lease/fencing, checkpoint, 취소, 재시작 |
| 수집 인증 | `cremore/secretstore/resolver.py:49`, `cremore/domain/connections.py:35` | config/job에 값 대신 참조, 실행 때 resolve |
| 사용자 인증, 감사 | `cremore/api/auth.py:1`, `cremore/domain/models.py:285` | local/OIDC, viewer/analyst/remediator/admin, 대상별 감사 |
| event/schedule | `cremore/scanning/triggers.py:58`, `:133` | 승인 scope, receipt, event enqueue를 Slack에 확장 |
| 대시보드 | `web/app/provider-registry.ts:1`, `connection-ui.tsx:1`, `credential-coverage.tsx:1` | 연결, 탐지, 작업, 보관대조, 감사의 단일 제품 흐름 |

위 기준 경로는 모두 고정 `develop` SHA다. 같은 파일명이라는 이유로 팀원의 별도 프로그램과 덮어쓰지 않는다.

### 분리해야 하는 증거

| 데이터 | 예 | 판정 원칙 |
|---|---|---|
| 수집용 인증정보 | App PEM, Slack bot/app token, Vault token | 연결 운영 비밀. 발견된 유출 credential과 분리 |
| 발급처 credential metadata | PAT ID, SA key ID | 원문 값, 유효성, 노출을 자동 추론하지 않음 |
| 주체, 설치, 정책, 요청 | 서비스 계정, installation, Actions policy, pending PAT | 실제 발급 토큰 수에 합산하지 않음 |
| Vault container/version | Secret, Secret version | 보관 위치. payload 전체와 credential material은 다름 |
| 실제 노출 | Slack 메시지의 AWS 키 | 콘텐츠 공급자와 credential 발급자가 다를 수 있음 |
| 상태, 사용 근거 | 검증 성공, API active, 감사 접근, IAM allow | 근거, 시각, 범위를 각각 유지 |

**선행 수정:** `cremore/coverage/correlation.py:59` 및 `web/app/credential-coverage.tsx:147`는 `aws_iam/aws_cloudtrail` 외 공급자를 사실상 Vault로 분류한다. 새 issuer 이름만 추가하면 금고 범위, 미관리 판정이 틀어진다. 명시적인 목적과 레코드 종류로 바꾼다.

## 3. 브랜치별 인수 설계의 위치

공통점, 차이점, 신규 기능, 충돌 해결, 담당자 작업, 완료 조건은 [읽기 쉬운 통합 설계 §2–6](../INTEGRATION_DESIGN_REVISED.md)에 정리했다. 전체 기능과 코드 위치는 [GitLab](gitlab.md), [GCP](gcp.md), [GitHub](github.md), [Atlassian과 Bitbucket](atlassian.md), [Slack](slack.md) 보고서가 인수 기준이다.

공식 API, 권한, 페이지 처리, 응답 의미는 [공식 문서 대조](official-docs.md)에 별도로 정리했다. 아래 계약은 팀원 기능을 기존 제품 안에 저장, 실행, 조회하기 위한 구현 제안이다.

## 4. 공통 계약과 저장 설계

이 절 이후 새 모델, 경로, 필드는 **구현 제안**이다. 이미 존재하는 API라고 해석하지 않는다.

### 기존 coverage의 확장

`cremore/coverage/`가 발급, 보관, 사용 관찰을 소유하므로 확장한다. 콘텐츠는 기존 collectors/scanning 책임이다. 새 독립 DB, 범용 plugin framework, 공급자별 스케줄러는 만들지 않는다.

1. schema1, collector token, revision, run sequence, batch digest/한도는 호환 유지한다.
2. schema2에 provider/host/edition/정확한 scope와 허용 capability를 명시한다. 필요한 목적은 발급처 inventory, Vault 관찰, 사용/관계 근거다. GCP처럼 함께 수집해도 레코드별 의미를 분리한다.
3. v1 provider는 명시 매핑한다. IAM=발급, CloudTrail=사용, 알려진 SM/SSM/Vault/OpenBao/GCP-SM=금고. unknown provider→금고 fallback을 제거한다.
4. v2는 `entity_observation`, `relation`, `provider_event`, `operation_report`를 구분하고 provider+record/object kind별 엄격한 필드 모델을 둔다. v1 VALUE/IDENTIFIER 등의 의미는 유지한다.
5. 서버가 연결별 허용 host/tenant/group/project/workspace, 레코드 종류를 재검사한다. collector의 provider 문자열만 신뢰하지 않는다.

| 필수 정보 | 내용/이유 |
|---|---|
| Identity | provider+canonical origin+공급자 tenant/scope+object kind/record contract+provider ID. self-managed 동명 ID, 계약 충돌 방지 |
| Provenance | connection/revision/run/source operation/resource reference/observed_at/provider-generated-at. 전체 URL의 secret query는 저장하지 않음 |
| Object kind | credential/principal/installation/policy/request/context/public-key/trust/vault item/version. KPI 분리 |
| Facts | present/explicit-null/missing/invalid 및 owner/creator/actor/authorized user 역할. team 필드 의미 보존 |
| State | provider 원상태, 정규화 상태, basis, check/observe/effective time. listed-active와 인증 성공 분리 |
| Details | typed permissions/scopes/repo grants/restrictions/conflicts/omitted field paths. 문자열 한 칸으로 축소 금지 |
| Relation/event | subject/target/kind/match basis/confidence/window. GCP 관계, GitHub audit, Slack lifecycle |
| Coverage | source+scope+window별 COMPLETE/PARTIAL/FAILED/UNSUPPORTED/UNKNOWN, 원본 상태, 이유. 선택 source 완료≠전사 완료 |
| Operation report | ID 없는 count/detail, 페이지 shape, field catalog, 수신/저장 건수, count 비교 결과. 객체 생성과 독립적으로 run/source에 귀속 |
| Value match | scheme/key identifier/material kind/exact-vs-candidate. ID, suffix, 공개키, provider hash와 HMAC 구분 |

canonical identity는 확인된 provider tenant/host/object namespace가 같을 때만 공유한다. 각각의 관찰은 connection에 귀속한다. tenant가 확인되지 않으면 connection 범위로 격리한다. 기존 제품에 없는 다중 고객 SaaS 권한 격리를 이미 지원한다고 가정하지 않는다.

unknown object는 분류 전 metadata로 보존하되 credential/Vault/exact match로 집계하지 않는다. arbitrary provider 응답을 일반 API로 통과시키지 않는다. typed allowlist, 크기/깊이/필드 수 제한 후 보관하며 생략한 필드 경로, 이유, 계약 버전을 남긴다.

### PostgreSQL 구조

기존 `coverage_connections/runs/batches`, `scan_jobs/tasks`, 감사 테이블을 재사용한다. 파일 snapshot 전체를 매번 검색하지 않도록 **두 조회용 테이블**을 추가한다.

| 제안 테이블 | 책임/제약 |
|---|---|
| `coverage_entities` | provider 객체의 안정 identity와 현재 요약. canonical identity unique. 기존 노출용 `credentials`와 별도이며 가짜 secret fingerprint를 만들지 않음 |
| `coverage_records` | immutable typed observation/event/relation/operation report, provenance. unique(run,batch,item), source event ID/digest 중복 방지, subject/target, 시간, provider, scope 인덱스. operation report는 entity 참조 없이 run/source에 귀속 가능 |

batches는 수신 순서, 멱등성, 정규화 batch 재처리 근거, 새 테이블은 같은 transaction에서 갱신되는 조회 projection이다. 별도 진실 원장이 아니다. 페이지 관찰, 자식 작업, checkpoint는 원자적으로 저장하고 실패하면 모두 rollback한다. 이력에서 projection을 재구성할 수 있어야 한다.

Atlassian scalar/detail 응답의 `saved_records=0`은 정상 결과일 수 있다. count 비교의 `proves_completeness=false`, 값 없는 field catalog, 페이지별 shape/생략 이유를 operation report에 보존한다. 가짜 credential/entity를 만들지 않고 run 상세/API/export에서 왕복 검증한다.

`latest`는 마지막 도착 순서가 아니다. 공급자 시각, 관찰 시각, source 계약, scope 완료 여부를 보고 상충 관찰을 유지한다. 늦은 사건이 최신 검증/폐기 근거를 덮지 않는다. 현재 정보와 마지막 성공 관찰을 함께 제공한다.

SQL과 in-memory 테스트 저장의 계약도 같아야 한다. `TaskStore.fenced`의 memory rollback 목록에 새 상태를 포함한다. 기존 `finalize_runs`의 content 중심 집계도 metadata 항목, source별 partial, run reference를 잃지 않게 확장한다.

### 노출–금고 대조의 판정

| 근거 | 말할 수 있는 것 | 추론하면 안 되는 것 |
|---|---|---|
| 노출+현재 Vault 값의 동일 HMAC | 선언 Vault에서 같은 값 관측 | 현재 유효/안전 보장 |
| 노출+완주, 최신, 같은 scheme의 Vault 범위에 match 없음 | 선언/확인 범위에서 미일치 | 회사의 모든 Vault 어디에도 없음 |
| Vault 미조회/권한 부족/partial/stale | 관리 여부 미확인, 이유 | 미관리 확정 |
| 발급처 metadata만 있음 | 발급처 관측, 노출/보관 별도 미확인 | 유출 또는 Vault 부재 |
| ID/suffix/owner/name 유사 | 식별자 근거 또는 후보 | 값 일치, 인증 성공 |
| CreMore own-token store에 있음 | 수집/운영용 보관 | 기업 외부 Vault에 관리됨 |

노출 없이 발급처 목록을 조회할 수 있어야 한다. 모르는 원문을 복원하거나 여러 후보 조합으로 자동 인증해 공백을 채우지 않는다. 정확한 관측 identity, 허용된 Vault 값 HMAC, audit의 명시 관계를 사용한다. 발급, 보관, 노출, 사용 가능성은 독립 증거다.

지문은 기존 `cremore/detection/fingerprint.py`를 재사용한다. Slack raw HMAC, GitHub scoped SHA256, 공개키 지문, GCP blob digest는 같지 않다. scheme/key/material이 다르면 문자열 equality로 확정 연결하지 않는다.

## 5. 실행, 인증, 재개

### 공통 worker

기존 `aws-credential-inventory` job/payload를 유지한다. 비-AWS metadata에는 별도 job kind를 추가해 같은 coverage 실행 경로로 보낸다. 이미 있는 task mode `INVENTORY`를 재사용한다. `github-org/gitlab/gcp` 등의 content job은 재정의하지 않는다.

공급자 core는 제안 `cremore/coverage/providers/{gitlab,gcp,github,atlassian,slack}`에 배치한다. 작은 경우 모듈, GitHub처럼 기존 다중 모듈이 필요한 경우 package를 사용한다. provider별 endpoint/cursor/정규화 의미를 무리하게 하나의 알고리즘으로 합치지 않는다.

흐름: 연결/revision 확인 → 비밀 resolve → source I/O → typed normalization → lease-fenced batch/checkpoint → source 완료 → 조회 projection. HTTP 동안 DB lock을 잡지 않는다. 취소, lease 상실, scope/인증 revision 변경 후 publish하지 않는다.

초기에는 같은 연결 수집을 직렬화한다. 여러 연결이 GitHub App quota 등을 공유하면 검증된 app/installation 범위의 lock/budget을 쓴다. 프로세스 전역 dict를 EKS 공유 한도라고 가정하지 않는다. 추가 병렬화는 실제 병목을 측정한 뒤 한다.

429/Retry-After, 권한 만료, 제공자 장애는 safe reason/retry time으로 남긴다. 재개 대기는 checkpoint를 유지한다. 실패를 빈 성공으로 바꾸지 않는다. 장시간 수집은 기존 coverage run의 6시간 만료, 명시 예산을 적용하고 만료된 run에 계속 쓰지 않는다.

### 인증과 운영 비밀

config/task에는 값 대신 참조를 둔다. 현재 단일 token용 sealed helper가 Slack 다중 슬롯, App PEM bundle, rotation recovery를 모두 지원한다고 가정하지 않는다.

| 공급자 | 인증 수용 |
|---|---|
| GitHub | 기존 host-aware App token source + 팀원의 enterprise/org installation discovery, 검증 |
| GitLab | token 참조 + `/user` principal pin + instance/scope pin |
| GCP | ADC 실행 주체, project/location, metadata 권한과 value-access 권한 분리 |
| Atlassian | 조직 관리자, managed account, Bitbucket/Runner의 역할별 연결. Bitbucket 개인 API token은 email+Basic, 해당 Bearer 종류는 별도 선택. 기존 auth_type 의미 재사용 |
| Slack | bot/app/signing/admin/audit/OAuth/configuration별 secret refs, typed resolver. 명시 own-token에만 관리 기능 |

secret 갱신에는 backend별 version/CAS, 원자성, lease, 복구 계약을 추가 구현, 검증한다. 현재 `cremore/secretstore/vault.py:169`의 write는 CAS 인자를 제공하지 않으므로 기존 지원으로 간주하지 않는다. 교체 API 성공 후 저장 실패는 recovery 상태로 남긴다. 불확정 쓰기를 읽기 재시도처럼 반복하지 않는다. UI나 수집 인증 만료로 과거 노출 검증 기록을 초기화하지 않는다.

### Slack 실시간, 알림

- Socket/서명 검증 HTTP Events는 같은 영속 수신 경로를 쓴다. workspace/connection/event ID를 기록한 뒤 ACK하고 worker가 처리한다.
- 기존 trigger receipt는 본문 큐가 아니다. 안전하게 재조회할 수 있으면 메시지 reference만 task에 넣는다. replay에 원문이 필요한 승인 이벤트는 제한 크기, 짧은 보존기간의 **암호화 inbox payload**와 키 관리/expiry/복구가 필요하다. raw message/token을 task JSON에 넣지 않는다.
- event delivery 중복과 content revision은 별개다. `(connection, workspace, channel, message_ts, revision)`으로 history/실시간/편집을 일관되게 처리한다. 과거 processed ID 때문에 새 편집 노출을 놓치지 않는다.
- 오래된 thread reply, archived, DM/MPIM, 접근 상실/삭제의 coverage를 명시한다. 지원하지 않는 file/canvas, 모든 bot 메시지까지 수집한다고 하지 않는다.
- 팀원 `AlertDelivery`의 의미를 현재 DB에 **새 영속 outbox로 구현**한다. 기존 develop에 outbox가 있다는 뜻은 아니다. dedupe, claim/lease, 재시도, 송신 후 불확정을 기록하고 외부 API가 보장하지 않는 exactly-once를 약속하지 않는다.
- join/댓글/교체/폐기/Workflow 완료는 읽기 수집과 별도 capability다. 명시 대상, 정책, RBAC, 승인, 감사에 연결한다. dry-run도 외부 요청이 있는 경우 표시한다.

## 6. API, 대시보드, 온보딩

### API 제안

현재 `/api/v1/coverage/...`와 AWS inventory route는 유지한다. 새 구조는 strict v1을 조용히 느슨하게 바꾸지 않고 **제안 `/api/v2/coverage`**로 추가한다. store/worker는 공유한다.

| 제안 경로 | 책임/권한 |
|---|---|
| `/api/v2/coverage/connections` | purpose/capability, host, scope. 생성은 공급자 연결 4단계(`/api/v1/provider-connections`)이고 참조는 공급자 연결이 소유한다. Admin, revision 충돌 검사, 변경 감사 |
| `.../connections/{id}/collect` | Admin이 승인한 고정 scope/capability의 재수집은 Analyst 이상. scope, 값 접근, 권한 확대는 Admin 설정 변경부터 수행 |
| `/api/v2/coverage/collector/{id}/...` | versioned config/start/batches/finish. 연결 전용 machine token, 다른 scope 제출 거절 |
| `/api/v2/coverage/inventory` 및 `/{id}` | 페이지, 필터, 객체, 권한, 관계, 이력. 기존 조회 권한, 값 원문 없음 |
| `/api/v2/coverage/runs/{id}` | source별 진행/미조회/실패/재개, safe reasons |
| 기존 findings/coverage projection 확장 | 노출과 새 metadata의 관계를 exact/identifier/candidate/usage별 표시 |

이 경로는 아직 구현되지 않았다. metadata-only run의 계약을 값 대조와 구분하고, 값 비교에는 기존 scheme, engine/policy/key 호환 검사를 유지한다. 기존 v1 payload replay가 통과해야 한다.

**대시보드 프록시도 함께 수정해야 한다.** 현재 `api()`는 `/api/backend/...`를 호출하고 Next.js 프록시는 이를 `/api/v1/...`로 고정해서 전달한다. 새 화면만 v2 응답 타입으로 바꾸면 연결되지 않는다. 추천은 기존 프록시에 명시적인 `/api/backend/v2/coverage/...` 경로를 추가하여 고정된 `/api/v2/coverage/...`로 전달하는 것이다. 나머지 기존 경로는 v1 동작을 유지한다. 같은 인증, local Host 제한, OIDC 처리, 동일 출처 쓰기 검사, 본문 한도, no-store 정책을 사용하며 브라우저가 임의 upstream 주소를 지정하지 못하게 한다.

근거: `DEV:web/app/dashboard-api.ts:12`, `DEV:web/app/api/backend/[...path]/route.ts:47`, `DEV:web/app/api/backend/[...path]/route.ts:83`.

### 화면 수용

화면별 사용자 흐름은 [통합 설계 §8](../INTEGRATION_DESIGN_REVISED.md#8-대시보드와-운영의-최종-모습)을 따른다. 기존 `develop`의 Next.js 화면, 테마, 표, 접기, 상세 패널을 기준으로 구현한다. 아래는 실제 코드 위치에 맞춘 작업 분담이다.

| 담당 위치 | 현재 코드의 제약 | 구현할 변경 |
|---|---|---|
| `page.tsx`, `dashboard-types.ts` | 탭, URL 파서, 제목, 오류 의존성과 AWS 응답 타입이 고정됨 | AWS 메뉴를 공급자 관리 목록으로 확장하고 `?tab=aws-inventory`는 AWS 선택 별칭으로 유지. 기존 AWS 타입에 다른 공급자 payload를 넣지 않음 |
| `page.tsx`의 `currentSource`와 화면 데이터 적재 | Slack이 연결, 작업, 카탈로그 필터에서 제외됨. AWS 목록 오류는 accounts에 의존 | 서버의 지원 목적과 화면 허용 목록을 맞추고 Slack을 연결. 선택한 공급자의 데이터만 조회하고 다른 공급자 오류와 분리 |
| 제안 `provider-inventory.tsx` | 현재 AWS 목록은 이미 받은 배열을 50개씩 나눔. 공통 공급자 목록 컴포넌트는 없음 | v2 관리 객체의 서버 검색, 필터, 정렬, 페이지 및 상세를 담당하는 패널 추가. 기존 AWS 상세 정보와 종류별 근거는 보존 |
| `provider-registry.ts`, `ui-primitives.tsx` | registry는 콘텐츠 공급자 설명용. 공식 이미지 매핑에는 Slack/Azure가 없음 | Slack 콘텐츠 설명과 필요한 로고 추가. Azure metadata를 콘텐츠 수집 지원으로 표시하지 않음. 기존 `PanelTitle`, `Status`, `ProviderBadge`, `ModalSurface` 재사용 |
| `connection-ui.tsx`, `connection-governance.tsx`, `scan-scope.tsx` | 콘텐츠 수집 중심의 연결 및 범위 흐름 | 설치 형태, 목적, 인증 역할, 목적별 권한, 관리정보 범위 추가. metadata-only 연결에 콘텐츠 스캔을 강제하지 않음 |
| `secret-manager-workspace.tsx`, `secret-inventory.tsx`, `credential-coverage.tsx` | Admin 작업공간, AWS 전용 metadata 검사, non-AWS=Vault 필터 | Vault 작업공간과 AWS 기존 경로 유지. v2의 명시 목적과 금고 제품별 모델 사용, 신규 issuer의 Vault 오분류 제거 |
| 탐지 상세, `credential-governance.tsx`, `finding-risk.ts` | 기존 노출, 검증, 위험 근거 표시 | 관리 객체/Vault/사용 근거의 상세 이동 추가. 공급자 active와 저장된 검증 결과를 다른 필드로 표시하고 배지와 점수의 근거를 일치시킴 |
| `global-search.tsx`와 `page.tsx` 검색 선택 처리 | 서버 검색은 있으나 결과 선택은 현재 탭만 열고 hit.id를 사용하지 않음 | 검색 종류에 관리 객체를 추가하고 공급자 및 객체 ID로 정확한 상세를 연다. 미허용 그룹의 항목과 건수를 반환하지 않는 계약 유지 |
| `page.tsx`의 스캔 및 감사 화면 | 콘텐츠 실행 요약과 CreMore 행동 이력이 중심 | 목적별 작업 상세와 읽지 못한 항목 표시. 공급자 감사는 별도 종류/필터로 제공하고 내부 감사의 actor/target과 혼동하지 않음 |

현재 구현과 제안을 구분하는 주요 코드 근거:

- 탐색과 필터: `DEV:web/app/page.tsx:158`, `DEV:web/app/page.tsx:703`, `DEV:web/app/page.tsx:738`, `DEV:web/app/page.tsx:784`, `DEV:web/app/page.tsx:4979`. Findings는 currentSource가 아니라 별도 자격증명 필터를 사용한다.
- 목록과 검색: `DEV:web/app/page.tsx:2398`, `DEV:web/app/page.tsx:2462`, `DEV:web/app/page.tsx:1470`, `DEV:web/app/global-search.tsx:31`, `DEV:web/app/dashboard-types.ts:271`.
- 공통 표현: `DEV:web/app/ui-primitives.tsx:86`, `DEV:web/app/ui-primitives.tsx:111`, `DEV:web/app/ui-primitives.tsx:172`, `DEV:web/app/layout.tsx:3`, `DEV:web/app/design-system.css:379`.
- Vault와 연결: `DEV:web/app/secret-inventory.tsx:30`, `DEV:web/app/secret-inventory.tsx:164`, `DEV:web/app/secret-manager-workspace.tsx:21`, `DEV:web/app/credential-coverage.tsx:67`, `DEV:web/app/connection-ui.tsx:60`.

**적재와 성능:** 기존 전역 주기 갱신에 모든 공급자의 전체 인벤토리를 추가하지 않는다. 선택한 공급자, 필터, 페이지만 조회하고 상세는 선택 시 가져온다. 새 인벤토리의 서버 페이지 조회는 신규 구현이며, 기존 AWS/Findings 배열의 client-side 분할을 전사 전체 검색으로 표현하지 않는다. API의 전체 건수, 필터 결과 수, 현재 페이지 수를 구분한다. 기존 credential coverage는 이미 offset/limit 조회를 사용하므로 이 형태를 참고한다.

**역할과 세션:** 현재 Vault 작업공간은 Admin 전용이지만 기존 coverage/AWS inventory 읽기 API는 로그인 사용자에게 제공된다. 조회, 재수집, 연결 설정, 외부 조치의 권한을 나눠 기존 서버 계약과 맞춘다. AWS 갱신 UI는 Analyst/Admin만 표시하지만 API의 Analyst 이상에는 Remediator도 포함된다. UI의 비교를 기존 `hasRole(role, "Analyst")`로 통일하고 역할별 테스트의 기대값도 수정한다. 새 조치 권한을 조회 권한에서 추론하지 않는다. 근거: `DEV:web/app/page.tsx:2485`, `DEV:web/app/dashboard-session.ts:18`, `DEV:cremore/api/coverage.py:49`, `DEV:cremore/api/coverage.py:168`, `DEV:cremore/api/auth.py:203`.

수집용 인증 실패는 마지막 성공 근거와 함께 표시한다. 로그인 만료/권한 철회는 보호된 클라이언트 상태를 지우고 재인증하도록 하되 서버의 검증, 점수, 이력을 초기화하지 않는다. 늦은 응답이 다른 사용자/연결/필터의 화면을 덮지 않도록 기존 취소 및 세션 변경 보호를 유지한다. 폐기된 연결은 일반 목록에서 숨기고 과거 관찰과 감사로 조회한다.

**온보딩:** 공급자/edition → 목적 → host/조직/project/workspace → 역할별 secret reference/workload identity → API/권한 확인 → 범위/예산/값 접근 확인 → 첫 수집 → 항목별 결과 확인 순서다. 계정 metadata를 읽었다는 사실이 모든 콘텐츠와 비밀값을 읽을 수 있다는 뜻은 아니다. 읽기 조회와 수집 실행, 외부 쓰기는 별도 동작으로 제공하며 화면 마운트가 수집을 시작하지 않는다. `github-org` 설명도 실제 콘텐츠 작업 의미에 맞춘다.

**UI 인수 조건:** 기존 합성 UI 테스트를 확장한다. 이번 문서 보완에서 아래 테스트를 실행했다는 의미는 아니다.

1. 탐색/기존 URL/한영 라벨/공식 로고/상세창 포커스: `DEV:web/tests/dashboard.test.cjs:63`, `DEV:web/tests/dashboard.test.cjs:389`.
2. AWS 기존 정보, 새 공급자 타입, 역할별 읽기/갱신/설정, 실제 서버 페이지 및 총수: `DEV:web/tests/dashboard.test.cjs:1760`. 기존 Remediator 제외 기대값은 서버 계약에 맞게 수정한다.
3. 세션 만료/권한 철회/늦은 응답, 기존 저장 검증과 점수의 연속성: `DEV:web/tests/dashboard.test.cjs:1192`, `DEV:web/tests/verification-sync.browser.cjs:1`.
4. 정확한 검색 결과 상세 이동, 권한 없는 그룹/건수 비표시, 부분 검색 설명: `DEV:web/tests/global-search.test.cjs:14`.
5. 기존 1440px/390px 합성 화면 검증에 많은 연결, 긴 경로, 여러 배지, 표 상세, 오류/미수집/실제 빈 결과, 테마, 언어, 키보드 조작을 추가: `DEV:web/tests/dashboard-density.browser.cjs:201`.
6. v1 기존 경로와 새 v2 coverage의 프록시 대상, 인증/동일 출처/본문 한도/실패 응답 유지: `DEV:web/tests/proxy.test.cjs:1`. 새 목록 API와 API 요청의 scope도 함께 검증한다.

팀원 HTML iframe이나 별도 dashboard 서버는 추가하지 않는다. 필요한 신규 화면 로직은 기존 디자인을 쓰는 컴포넌트로 분리하며, 전체 스타일과 테마를 교체하지 않는다. UI 구현을 완료하려면 해당 테스트, web build, 합성 브라우저 확인을 통과해야 한다.

## 7. Enterprise와 운영 환경

| 제품 | 코드로 확인한 범위 | 남은 지원 gate |
|---|---|---|
| GitHub.com/Enterprise Cloud | 팀원 org/enterprise/audit, api.github.com 고정 | App 권한, 조직 가시성. 모든 토큰 registry 보장 없음 |
| ghe.com | develop content/auth host-aware, 공식 Cloud API origin 확인 | 팀원 metadata host 고정 해소, fixture, 시험 tenant 검증 필요 |
| GHES | develop content/auth host-aware | metadata의 설치 버전별 계약 미확인. 문서404를 API 미존재로 단정하지 않음 |
| GitLab.com/self-managed | HTTPS custom origin, 그룹, 프로젝트별 metadata | `/manage/...`는 현재 GitLab.com Premium/Ultimate, 최상위 그룹 Owner 계약. 자체 설치에 동일 지원 선언 금지 |
| Atlassian Cloud/Enterprise | 조직 관리/managed-account metadata | source별 불확실성, 400/404, 권한 범위 |
| Confluence/Bitbucket Data Center | develop 콘텐츠 | Bitbucket DC10.0 token 목록/상세 GET6개는 공식 확인, metadata adapter는 미구현. Confluence 관리자 목록은 버전별 계약 확인 필요 |
| Bitbucket Cloud | core22/Runner4 | Runner pagination, resource token/OAuth 전수 목록 아님 |
| GCP | 명시 project, ADC, 지원 위치 목록을 읽어 지역 자동 순회 | 지역 선택 UI는 신규 제안. org/folder 전수 discovery 없음, relations global 한계 |
| Slack/Enterprise | 메시지, approved apps, Audit, 관측 own tokens | org-wide team_id, certified 필터, Owner 감사 인증, 배포별 rate 보완. GovSlack endpoint는 미구현 |
| AWS/Vault/OpenBao/GCP SM | develop 값 대조 + 팀원 metadata | 선언한 mount/namespace/version/scope에서만 판정 |
| Azure Key Vault | Slack metadata collector | updated_at 유지, 근거 없는 last_rotated_at 제거. 회전 태그는 선언 근거. value match는 미구현 |

기존 Compose, EC2 instance-profile override, Helm/OIDC/IRSA/Pod Identity 설정을 재사용한다. 배포 경로가 있다는 사실과 팀원 프로그램의 해당 환경 검증 완료는 다르다.

| 환경 | 기반/필수 조건 |
|---|---|
| 로컬 Linux Docker | 기존 Compose. POSIX CLI 또는 공통 DB 수용, 로컬 callback, secret 경계 |
| native Windows 도구 | Slack DPAPI, GCP lock. GitLab fcntl, Atlassian POSIX 제한 표시, DPAPI import는 원래 사용자 |
| EC2 | `deploy/compose/ec2-instance-profile.yml`. provider secrets, role 분리, DB/키 백업, portable token store, OIDC/TLS |
| EKS | `deploy/helm/values.yaml`. replica간 task/Socket lease, DB checkpoint/OAuth state, identity, egress, nonroot/read-only 검증 |

Windows 위 Linux Docker에도 DPAPI는 없다. SQLite/JSON을 공유 PVC에 두는 것만으로 분산 운영이 되지 않는다. GitHub 5-service, GCP watcher, Slack FastAPI를 기본 배포에 추가하지 않고 기존 이미지에 기능을 패키징한다.

현재 wheel/Dockerfile은 `cremore/`만 포함하고 실행 이미지는 Python3.14 Linux다. 루트에 팀원 폴더만 붙이면 설치되지 않는다. CI는 Python3.12/3.14, `pytest cremore/` 중심이고 push trigger는 main이다. 통합 테스트를 실제 탐색 경로에 넣고 `develop_total` PR 또는 명시 trigger로 검증한다. `unittest` 이름 자체가 pytest 비호환인 것은 아니다.

## 8. Git 통합 절차

### 실제 충돌

고정 head로 `git merge-tree --write-tree --name-only`를 실행했다. worktree/ref를 변경하지 않았다. 전체 목록은 [검증 기록](verification.md)에 있다.

| 브랜치 | 충돌 경로 수 | 내용 |
|---|---:|---|
| GCP | 0 | Git clean, runtime/데이터 호환은 별도 |
| GitLab | 2 | `.gitignore`, `README.md` modify/delete |
| Atlassian | 2 | `.gitignore`, `README.md` |
| GitHub | 14 | root 설정, README, 과거 tree rename/delete, collector 두 경로 |
| Slack | 5 | `.env.example`, `.gitignore`, `LICENSE`, `README.md`, `requirements.txt` |

팀원끼리 10쌍도 검사했다. GitHub와 초기 branch 사이에는 `credential_dashboard/queries.py`와 collector rename 충돌도 있다. 두 head의 판정이며 순차 병합 후 다시 확인한다.

### 구현 시 지킬 순서

1. 이 설계를 `develop_total`의 기준점으로 보존한다. 시작 시 원격 변경과 pinned SHA를 비교하고 새 delta가 있으면 추가 분석한다.
2. `develop`에서 checkout/reset/merge하지 않는다. `develop_total` 또는 그 작업용 worktree에서만 진행한다.
3. branch별 이력이 남는 병합을 `--no-commit` 상태에서 검토한다. 변경, 삭제, rename을 source inventory와 대조한다. blanket `-X theirs`나 root 일괄 복사를 사용하지 않는다.
4. 기능 충돌은 팀원 의미, 범위를 우선 수용한다. README, ignore, 의존성, 권리 문제는 아래 정책으로 해결한다.
5. source 반입과 제품 연결 변경을 검토 가능한 commit으로 구분한다. 연결/회귀 전의 중간 commit은 배포 가능한 통합판이라 하지 않는다.
6. 이동된 module과 목적지를 기능 인수표에 기록한다. CLI/QA/예제/공지 보존. 고객 증거 JSON을 이미지나 fixture에 무조건 포함하지 않고 출처와 비식별 fixture를 구분한다.
7. 최종 team SHA들의 ancestor 포함, 인수표 미처리0, `develop` SHA 동일성을 확인한다.

| 유형 | 해결 정책 |
|---|---|
| 동일 provider 기능 | 팀원 상세 기능, 오류 의미 우선 + 기존 콘텐츠/검증 유지 |
| README | 제품 진입 문서와 팀원별 기능/제약 문서를 합침 |
| ignore | 양쪽 비밀/출력 보호 합집합, 실제 제품 package 설치 확인 |
| requirements | pyproject의 필요한 선언 합치기→해시 lock 재생성. baseline lock을 팀원 파일로 덮지 않음 |
| package/중복 blob | 동일 구현 통합, 서로 다른 runtime의 기능 계약은 보존 |
| GCP 조상 제품 파일 | 조상 대비 delta만 병합, 최신 develop을 옛 snapshot으로 복구하지 않음 |
| LICENSE | 출처/고지 보존, 팀의 배포 권한, 라이선스 결정 후 반입/배포 |

## 9. 공통 인수 조건

구현 순서는 [통합 설계 §7](../INTEGRATION_DESIGN_REVISED.md#7-공통-구현-순서)을 따른다. 다음 항목은 모든 단계에 적용하는 상세 인수 조건이다.

Service CLI/Workflow probe/개발 capture는 적합한 로컬/QA 도구로 보존하는 것이 완료 형태다. 운영 공개 API가 될 필요는 없다. 구현 중 범위를 줄이면 인수표에서 보류 이유, 완료 조건을 명시하며 통합 완료로 숨기지 않는다.

공통 acceptance:

1. **기능:** 각 상세 표의 목적지/증거가 있다. GitHub context/run-job, GCP relations, Runner, Slack Azure/own-token 등 부속 기능 누락0.
2. **Identity/정보:** 다른 host/scope/kind의 같은 ID 분리, 같은 객체의 다중 출처 보존. missing/null/invalid, owner/issuer, candidate/exact, entity 없는 count/field-catalog/operation report가 DB/API/export 왕복.
3. **완전성:** denied/404/shape drift/429/cursor loop/총수 불일치/예산/stale에서 빈 성공, 폐기, 미관리 확정 금지.
4. **연속성:** 세션 만료/재시작/늦은 event/partial이 검증, 노출, 점수, 성공 이력을 초기화하지 않음. badge와 점수의 동일 근거.
5. **비밀/권한:** 원문/PEM이 config/task/evidence/log/API error/export에 없음. 역할 위반, 다른 connection token, scope 밖 요청 거절.
6. **작업:** stale lease/취소/중복 batch/checkpoint 전후 장애/401/429/대기에서 유실, 중복 확정 방지, HTTP 동안 DB lock 없음.
7. **이행:** legacy import 멱등, 잘못된 지문 조인 없음, 원본/감사/FK 보존, rollback 후 기존 제품 정상.
8. **UI:** 대량 페이지/필터, 긴 값, 좁은 화면, 키보드, 작업 상세, 부분 fetch 실패. 공개키/정책을 노출 KPI에 합산하지 않음.
9. **설치:** wheel import, Python3.12/3.14, lock/pip check, PostgreSQL migration, web tests/build/browser proof, Helm render, restart, 두 worker 경쟁.
10. **공급자:** 승인 시험 tenant의 edition/version/권한별 read 경로 확인. live 조치는 별도 명시 승인, 소유 시험 대상. 오프라인 통과만으로 전사 전수/모든 Enterprise 지원 선언 금지.

## 10. 데이터 이행, 복구

실제 팀원 운영 DB/JSON은 열람하지 않았다. 사용 자료가 없다고 가정하거나 자동 삭제하지 않는다. 코드 이식과 운영 데이터 import를 분리한다.

- 입력마다 branch SHA, export/schema version, store ID, snapshot hash, 원본 record ID를 기록한다. dry-run에서 건수, 관계, 변환 불가, 누락을 먼저 보고한다.
- GitLab SQLite, GitHub SQLite/JSON, Atlassian snapshot, GCP watch, Slack SQL/lifecycle 자료의 중복 관찰, 사건, 현재성, 불확실성을 보존한다.
- raw가 없는 Slack HMAC/DB password component는 legacy scheme/material로 남긴다. 마스크로 재지문하지 않는다. DPAPI는 원래 Windows 컨텍스트에서 승인된 secret backend로 이행한다.
- GCP 평문 state는 필요하고 허용된 경우 메모리에서만 HMAC을 만든다. 일반 import/export에 값을 섞지 않고 blob digest와 credential hash를 구분한다.
- additive schema와 v1 호환으로 시작한다. 구버전 writer가 v2 상태를 잘못 확정하지 못하게 한다. 백업/복구 가능성을 확인한다.
- 기존 numbered migration ledger/DB lock/offline backfill 패턴을 사용한다. populated DB의 파괴적 backfill을 시작 시 자동 수행하지 않는다. fixture DB에서 재실행, 중간 실패, rollback을 검증한다.
- rollback은 새 job/capability 중단과 v1 경로 복귀가 기본이다. 새 관찰을 즉시 삭제하지 않는다. 데이터 복구가 필요하면 검증한 백업과 import manifest를 사용한다.

## 11. 이번 검증과 남은 작업

| 검증 | 결과 |
|---|---|
| GitLab Linux | 23/23 통과 |
| GitLab Windows | 21통과, failure1/error1: fcntl 의존 |
| GCP | 39/39 통과 |
| Atlassian Linux | 148/148 통과 |
| GitHub 루트/JSON | 49/49 + 45/45, 중복9, 고유85 |
| Slack Windows | 196/196, skip0 |
| Slack passive 비교 | 합성50개, 양쪽 원본, RE2, verify=False |
| GitHub 추가 합성 | context/generated-at 유실, Org 총수 불일치, JSON Actions 경로 공백 확인. 후속 공식 감사 cursor 순수 함수 비교2개 별도 |
| 공개 공식 문서 | GitLab/GCP/GitHub/Atlassian/Slack, Vault 관련 계약 대조. 고객 API 호출 없음 |
| Git 병합 판정 | develop 대비5개, 팀원끼리10쌍, 실제 worktree 병합 없음 |

대표 환경의 **500개 테스트 실행 통과, 중복을 뺀 고유 테스트491개**다. GitLab Windows 진단과 Slack 가드 수정 전 실패는 별도 기록했다. 이는 **통합 제품 전체 테스트 통과 수가 아니다**.

실제 코드 병합, develop 전체 테스트 재실행, 최종 lock/Linux 이미지의 팀원 기능, 운영 DB import, 기업 계정 권한, 실제 배포는 미실행이다. 구현 gate에 포함했다.

코드만으로 결정할 수 없는 것은 Slack 권리/라이선스, legacy 운영 자료 유무, 기업별 edition, API 권한, 보존기간, 실시간/외부 쓰기 정책이다. 확인되지 않은 항목을 구현 완료로 처리하지 않는다.

## 12. 산출물과 완료 판정

- [GitLab](gitlab.md), [GCP](gcp.md), [GitHub](github.md), [Atlassian과 Bitbucket](atlassian.md), [Slack](slack.md): 기능, 모듈, 공백, 충돌, 소스 행 근거.
- [파일별 판독 대장](source-inventory.csv), [기준 코드 판독 범위](baseline-read-scope.csv): 읽기 범위 재확인.
- [검증, 충돌 기록](verification.md): 실행 환경, 결과, 한계, 모든 충돌 경로.
- [공식 문서 대조](official-docs.md): 공식 계약, 코드 차이, 추천, 미확정 항목.
- [기존 기능 목록](../BRANCH_FUNCTIONS.md): 이전 정적 조사 기록을 보존하고 확인된 오류를 정정한 참고 자료. 현재 결정은 이 설계와 branch별 상세 보고서를 따른다.

설계 완료는 분석, 근거, 목적지, 검증 조건을 갖춘 상태다. **제품 통합 완료는 모든 기능 인수와 공통 acceptance를 통과한 뒤 선언한다.**
