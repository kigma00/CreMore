# develop_total 통합 현황 — 구현한 것과 남은 것 전부

기준일: **2026-09-21** / 브랜치: `develop_total` / 기준 commit: `9b56f1f` 위 20개 commit (`publish/develop_total`에 push됨)

이 문서는 [통합 설계](../INTEGRATION_DESIGN_REVISED.md)가 제시한 8단계에 대해 **무엇을 구현했고, 무엇을 의도적으로 다르게 했으며, 무엇이 남아 있는지**를 빠짐없이 적는다. 단계별 실행 기록은 [진행 기록](implementation-progress.md), 공급자별 상세는 각 수용 기록에 있다.

읽는 순서:

- 지금 상태만 알고 싶다면 [1. 한눈에 보기](#1-한눈에-보기)
- 무엇이 들어왔는지 알고 싶다면 [3. 구현한 것](#3-구현한-것)
- 무엇을 해야 하는지 알고 싶다면 [5. 남은 것](#5-남은-것)과 [6. 검증하지 않은 것](#6-검증하지-않은-것)

---

## 1. 한눈에 보기

| 단계 | 내용 | 상태 | 규모 | 검사 |
|---|---|:---:|---|---|
| 0 | 기준 갱신, publish/develop 병합 | 완료 | — | — |
| 1 | 공통 schema 2 모델·저장·projection | 완료 | 1,300줄 | 16 (API) |
| 2 | 목적별 범위·인증·worker 실행 | 완료 | 200줄 | 위와 동일 |
| 3 | GitLab 관리 목록 | 완료 | 14 모듈 / 4,181줄 | 110 |
| 4 | GCP 인벤토리·값·관계 | 완료 | 9 모듈 / 2,775줄 | 108 |
| 5 | Atlassian · Bitbucket | 완료 | 32 모듈 / 6,613줄 | 228 (+57 skip) |
| 6 | GitHub 조직 + Enterprise | 완료 | 8 모듈 / 2,126줄 | 61 |
| 7 | Slack + Azure Key Vault | **Azure만 완료 · Slack 전부 제외** | 원본 13,345줄 | 61 (Azure) |
| 8 | 대시보드·API·프록시 | 완료 | 1,900줄 | 95 + 브라우저 3 |

전체: **202개 파일, +43,083줄 / −114줄** (`git diff --shortstat 9b56f1f..HEAD`, 이 commit 포함). Slack 철회로 15개 파일이 빠졌다

```text
python -m pytest cremore -q     → 4464 passed, 68 skipped, 257 subtests
python -m ruff check cremore    → All checks passed
cd web && npm test              → 447 passed
cd web && npm run build         → 성공
cd web && npm run test:browser  → 19/19 통과
```

---

## 2. Codex 세션에서 인수한 상태와 고친 것

Codex는 commit 없이 작업트리에만 남긴 채 중단됐고, 진행 기록에는 "0단계만 완료"라고 적혀 있었다. 실제로는 1·2·3·5단계가 상당 부분 구현돼 있었으나 다음이 깨진 상태였다.

| 문제 | 원인 | 조치 |
|---|---|---|
| 파이썬 테스트 **67개 실패** | Atlassian native CLI의 POSIX 전용 파일 보호(`O_DIRECTORY`, `O_NOFOLLOW`, `st_uid`, mode 0700) 시험 54개가 Windows에서 `AttributeError` | 보호를 완화하지 않고 Windows에서만 skip. GitLab이 이미 쓰던 `skipUnless(os.name == "posix")` 방식과 동일 |
| `auth_test` 404→409 회귀 | `require_v1`이 없는 연결에 `CONNECTION_NOT_FOUND`를 던져 기존 경로별 상태 코드를 바꿈 | schema 2 여부만 판정하고, 없는 행의 처리는 각 경로의 기존 계약에 맡김 |
| `sql_test` 실패 | 새 `metadata_coverage` migration을 DDL 순서 계약 테스트에 반영하지 않음 | 같은 transaction-scoped lock 안의 단계로 테스트에 추가 |
| schema 2 API에 **테스트 0개** | 미작성 | `cremore/api/metadata_coverage_test.py` 16개 + `auth_test.py` 역할 검사 5건 추가 |
| **native export 실행 불가** | 저장된 contract snapshot에는 비밀 참조가 없는데 GitLab export가 그것을 다시 요구 | 읽기 경로(`collecting=False`)에서는 인증 절반을 검사하지 않음 |
| 브라우저 검증 3개 실패 | 병합해 온 develop의 노출 경로 작업이 남긴 것 | 아래 §3.6 참조 |
| 작업트리 CRLF 오염 | `.gitattributes`는 LF인데 일부 파일이 CRLF | 추적 파일 105개를 LF로 정규화. git 저장 내용은 변화 없음 |

---

## 3. 구현한 것

### 3.1 공통 계약 (1·2단계)

`cremore/coverage/metadata_models.py`, `metadata_store.py`, `metadata_job.py`, `cremore/api/metadata_coverage.py`, `cremore/db/migrations.py`

**schema 1을 바꾸지 않고 schema 2를 나란히 추가했다.** v1 연결의 경로, payload 재생, 상태 코드는 그대로이며, v1과 v2 연결은 서로의 경로에서 보이지도 수정되지도 않는다.

레코드 4종:

| 종류 | 답하는 질문 |
|---|---|
| `entity_observation` | 공급자가 어떤 객체를 알고 있는가 |
| `relation` | 어떤 주체가 무엇을 소유·사용·접근 가능한가 |
| `provider_event` | 공급자 감사에 어떤 사건이 기록됐는가 |
| `operation_report` | 어디까지 읽었고 무엇을 못 읽었는가 |

지키는 경계:

- **필드는 허용 목록이다.** 승인되지 않은 이름은 값이 아니라 경로와 이유만 omission으로 남는다. 없음·null·형식 오류는 서로 다른 상태다.
- **공급자 상태는 검증이 아니다.** `state_basis`는 `PROVIDER_REPORTED`이고 조회 API의 `verification`은 항상 `NOT_PERFORMED`다.
- **비밀은 저장되지 않는다.** 값은 GCP만, `include_values` + 값 capability가 함께 켜진 경우에만 읽고, 기존 detection 엔진의 HMAC 지문으로 바꾼 뒤 버린다. checkpoint·facts·operation report는 secret 모양 문자열을 거절한다.
- **DB 변경은 추가뿐이다.** 조회용 projection 테이블 2개만 기존 DDL과 같은 transaction-scoped lock 안에서 만들어진다.

실행 흐름 (기존 worker 재사용):

```
연결/revision 확인 → 비밀 resolve → 공급자 I/O(트랜잭션 밖)
→ typed 정규화 → lease-fenced batch + checkpoint 원자 commit → 조회 projection
```

취소·revision 변경·lease 상실 뒤에는 아무것도 publish하지 않는다. 429·공급자 장애는 부분 결과가 아니라 `WAITING` 페이지와 재시도 시각이다. 완료한 source는 재개할 때 다시 읽지 않는다.

**API 16개 경로** (`/api/v2/coverage/…`):

```
GET    providers                                  공급자 카탈로그
GET    connections                                목록 (비밀 참조 미표시)
POST   connections                                생성 (Admin)
GET    connections/{id}                           상세 (Admin)
PATCH  connections/{id}                           변경 (Admin, revision 충돌 검사)
GET    connections/{id}/runs                      실행 이력
POST   connections/{id}/collect                   수집 요청 (Analyst 이상)
GET    collector/{id}                             machine 설정 (연결 전용 token)
POST   collector/{id}/runs                        machine run 시작
PUT    collector/{id}/runs/{run}/batches          machine batch 제출
POST   collector/{id}/runs/{run}/finish           machine run 종료
GET    inventory                                  서버 페이지·필터·검색
GET    inventory/{entity}                         객체 상세
GET    runs/{run}                                 실행 상세
GET    runs/{run}/export?format=records|native    native JSON 재구성
GET    runs/{run}/compare/{other}                 두 실행 비교
```

### 3.2 GitLab (3단계) — [수용 기록](gitlab-adoption.md)

`cremore/coverage/providers/gitlab/` · 14 모듈 / 4,181줄 · **110 tests**

- 토큰 10종, 승인 group/project BFS, 필드 우선순위, 감사 해석과 생성자·소유자 분리를 그대로 보존.
- SQLite·CLI·POSIX 파일 잠금 대신 공통 lease/checkpoint. 원본 CLI와 SQLite 저장은 QA fixture로 남겨 원본 86개 시나리오를 같은 코드에 대해 실행.
- **의도적으로 좁힌 것 2가지**: Cloud 전용 managed endpoint는 Self-Managed/Dedicated에서 요청 자체를 거절한다(실패를 만들지 않는다). "비밀 이외 모든 필드 보존"은 공통 허용 목록으로 바뀌고 그 차이는 export의 `normalization_omissions`가 밝힌다.

### 3.3 GCP (4단계) — [수용 기록](gcp-adoption.md)

`cremore/coverage/providers/gcp/` · 9 모듈 / 2,775줄 · **108 tests**

- 서비스 계정·키, API key와 제약, global·지역 Secret, 모든 버전과 상태, 감사 기반 secret 접근, 서비스 계정 활동, API key 요청량 metric, IAM allow 정책.
- **근거 종류가 섞이지 않는다**: 관측된 접근(`used`/EXACT), 공급자 귀속(metric), 가능한 접근(`can_access`/POLICY/CANDIDATE)이 서로 다른 레코드다. 빈 감사 창은 "미사용"이 아니라 **미확인**이며 모든 report가 그 문장을 담는다.
- **값은 남지 않는다**: CRC32C 검증 후 HMAC 지문으로 바꾸고 버린다. reference는 연결 scope의 project를 가리키도록 정규화한다. destroyed/disabled 버전에는 값 요청을 보내지 않는다. 서비스 계정 읽기는 **공개 인증서**이며 private key는 생성 응답에만 존재한다.
- watcher 프로세스와 로컬 JSON 상태 파일 대신, 두 실행 사이의 `compare_records`가 변화 어휘(discovered / state_changed / metadata_changed / value_collected / value_changed / no_longer_listed)를 계산한다. **부재는 그 source를 완주한 경우에만 판단한다.**
- 남은 제한: **관계 수집은 global Secret만** 대상이다. 지역 Secret이 있으면 `REGIONAL_SECRET_RELATIONS_UNSUPPORTED`를 실행 사유로 남긴다.

### 3.4 Atlassian · Bitbucket (5단계) — [수용 기록](atlassian-adoption.md)

`cremore/coverage/providers/atlassian/` · 32 모듈 / 6,613줄 · **228 tests (+57 POSIX skip)**

- 45개 read operation, Runner·branch restriction 포함. generator가 한 페이지를 돌려준 뒤 다음 요청 전에 제어를 반환하므로 취소와 lease 상실이 원본 오류 정리에 삼켜지지 않는다.
- 인증은 공급자 계약을 따른다: 개인 Bitbucket API token은 Bearer 또는 email+Basic(참조 분리), 실패 후 다른 방식으로 전환하지 않음, 공개 OIDC·JWKS에는 인증을 보내지 않음.
- ID 없는 count, 403, 빈 성공, 미수집이 서로 다른 결과로 남고 `inventory_complete`는 항상 false다. Runner의 OFFLINE은 폐기가 아니다.

### 3.5 GitHub (6단계) — [수용 기록](github-adoption.md)

`cremore/coverage/providers/github/` · 8 모듈 / 2,126줄 · **61 tests**

- 원본의 두 프로그램(조직 수집기 / Enterprise 엔진, 동일 blob 20개)을 **하나의 연결의 두 모드**로 합쳤다. 어느 한쪽만 고르면 잃던 기능이 없다.
- Enterprise task graph가 엔진이다. 한 페이지를 트랜잭션 밖에서 읽고, 그 페이지에서만 후속 task를 만들고, 레코드와 task 상태를 함께 commit한다. JSON 상태 디렉터리·page 파일·프로세스 잠금은 없앴다.
- **host 고정을 제거했다.** API base는 기존 `github_hosts` 해석이고, 페이지 링크는 그 host에서만 허용한다. edition과 host가 어긋나면 연결 자체를 거절한다. GHES와 ghe.com이 콘텐츠 스캔과 같은 경로로 관리정보를 읽는다.
- 종류를 섞지 않는다: SSH/deploy key는 `public_key`, 앱 설치는 `installation`, 승인 대기는 `request`, 정책은 `policy` — 발급된 자격증명으로 집계하지 않는다. App permission은 임의 필드명이 아니라 typed permission이다. 응답의 `token`·`temp_clone_token`·저장소 permission flag는 저장하지 않는다.
- Enterprise credentials 응답에는 `total_count`가 없으므로 어떤 report도 완전성을 주장하지 않는다. 완전성 헤더는 경고로 남는다. 설치가 없는 조직은 1회만 기록하고 재시도하지 않으며, Enterprise 감사가 완주하면 조직 감사는 그 이유를 담은 report를 남긴다.

### 3.6 대시보드 (8단계)

`web/app/provider-inventory.tsx`, `web/app/provider-metadata.ts`, `cremore/coverage/providers/catalog.py`

- **공급자 카탈로그**가 edition, scope 종류, 인증 역할, 모드, 한계를 알려준다. adapter가 설치되지 않은 공급자는 목록에 없고, 화면은 `validate_spec`이 거절할 조합을 제안할 수 없다.
- **프록시는 `/api/backend/v2/coverage/…` 한 경로만** v2로 보낸다. 다른 v2 namespace, 빈 segment, `..`는 404다.
- **기존 `?tab=aws-inventory` 링크는 그대로** 동작하고 AWS가 선택된 상태로 열린다. 같은 화면에서 다른 공급자를 고르면 schema 2 패널이 열린다.
- **서버가 페이지·필터·검색을 처리한다.** "1200건 중 50건"은 서버가 센 수다. 필터는 조회된 행이 실제로 다를 때만 나타난다.
- **네 가지 상태가 네 자리에 있다**: 연결 인증 / 수집 결과 / 공급자 상태 / 유효성 검증(항상 미검증). 읽지 못한 source는 이유와 함께 미수집으로, 한 번도 실행하지 않은 연결은 "수집한 적 없음"으로 표시한다.
- 조회는 로그인한 모든 역할, 수집 실행은 Analyst 이상, 연결 설정은 Admin — 서버 계약과 같다. vault 경로는 Admin에게 되돌려 보이고(포인터), sealed 값은 가려지며, 목록은 둘 다 보이지 않는다.

**함께 고친 병합 유래 결함 3건** (브라우저 검증 16/19 → 19/19):

1. `verification-sync`: 새 `exposure-surface` 읽기가 stub되지 않아 차단됨 → 빈 그룹으로 stub.
2. `dashboard-density`: 같은 읽기에서 `undefined.length` 예외로 검사 176개 중 1개만 실행 → stub 추가.
3. `dashboard-density`: 탐지 상세가 **'노출 위치'보다 '진행 단계'를 앞에** 둬서 밀도 검사 136건 위반 → 노출 경로는 노출 위치에서 파생되므로 위치를 앞으로 되돌림(nav·본문 모두).

---

## 4. 설계와 다르게 한 결정

| 항목 | 설계 | 실제 | 이유 |
|---|---|---|---|
| 8단계 순서 | 7 → 8 | **8을 먼저** | UI 없이는 완성된 4개 공급자가 운영자에게 전혀 보이지 않는다 |
| AWS 탭 | 새 탭 신설 검토 | **기존 `aws-inventory` 탭 확장** | URL 호환을 별도 처리 없이 그대로 유지 |
| `FactWriter` | 공급자별 구현 | **`providers/facts.py`로 공용화** | GitLab 구현이 이미 범용. GCP·GitHub가 재사용 |
| GCP 인증 | ADC | **ADC / workload identity만, secret_refs 금지** | 저장된 token은 ADC 주체의 두 번째 사본이 된다 |
| GCP `principal_pin` | — | **거절** | 실행 중 ADC 주체를 다시 읽지 않으므로 검증하지 않은 고정을 검증으로 표시할 수 없다 |
| GitHub `principal_pin` | — | **거절** | 같은 이유 |
| Atlassian POSIX 시험 | — | **Windows skip** | 보호를 완화하지 않는다. 제품 경로는 세 OS 모두 검사 |

---

## 5. 남은 것

### 5.1 7단계: Slack과 Azure — **Azure(7d) 완료 · Slack 전부 제외**

원본 `publish/develop_slack` · 13,345줄. 설계 §6에서도 4단계로 나눈 유일한 공급자다.

| 하위 | 내용 | 원본 위치 | 걸림돌 |
|---|---|---|---|
| **7a** | 메시지 수집을 기존 탐지 제품에 연결 | `app/socket_mode.py`(536), `app/detector.py`(125) | **철회(2026-09-22 결정)**. 구현했다가 전부 되돌렸다. [아래 7a 항목](#7a-슬랙-콘텐츠-수집--철회2026-09-22) 참조 |
| **7b** | 실시간 수신·편집·알림 | `app/event_processor.py`(237), `app/dashboard.py`(1319) | **제외(2026-09-22 결정)**. 새로 만들어야 함: DB 수신 기록 후 ACK, 암호화 inbox, dedupe·claim/lease·재시도를 갖춘 영속 outbox. 기존 develop에 outbox가 없다 |
| **7c** | 앱·감사·소유 토큰 관리정보 | `app/slack_admin_inventory.py`(158), `app/slack_audit.py`(165), `app/known_token_inventory.py`(304), `app/token_lifecycle.py`(675), `app/owned_token_store.py`(347), `app/oauth_capture.py`(276) | **제외(2026-09-22 결정)**. schema 2로 옮기는 부분은 기존 공급자와 같은 패턴. OAuth state 1회 사용, 교체 성공 후 저장 실패의 복구 상태는 새 구현 |
| ~~7d~~ | ~~Azure Key Vault metadata~~ | — | **완료**. [아래 7d 항목](#7d-azure-key-vault-완료) 참조 |

공식 문서로 확인한 보완점(설계 §6)과 처리 상태:

Slack을 다시 시작한다면 아래는 여전히 확인된 보완점이다. 지금은 구현 대상이 아니다.

- 조직 전체 token의 `conversations.list`에는 `team_id`가 필요하다.
- history/replies 제한은 앱 배포 유형에 따라 다르다. 모든 연결에 같은 속도·페이지 수를 가정하면 안 된다.
- 승인 앱 조회의 `certified` 기본 필터 때문에 기본 응답을 전체 승인 앱으로 단정하면 안 된다.
- 감사 수집은 별도 Enterprise Owner User token, 권한, 조직 설치 조건이 필요하다.

#### 7a 슬랙 콘텐츠 수집 — **철회(2026-09-22)**

한 번 구현해서 commit했다가 **전부 되돌렸다**. 되돌린 것:

| 되돌린 것 | 원래 commit |
|---|---|
| 대화 수집기(`cremore/collectors/slack.py`)와 그 58개 검사 | `e80750d` |
| 연결·범위 검증, `auth.test` 자격증명 점검, job kind, 노출 메타데이터 키 | `e80750d` |
| 등록 양식·공급자 facet·노출 출처 필터·검증 이력·폐기 안내의 Slack | `1d9ba76` |
| Slack 토큰 탐지기 3종(`xoxe.`/`xoxe-` 회전 토큰, `xwfp-`, `xoxc-`/`xoxd-`)과 대조표 50건 | `38faa31` |

**남긴 것**: Slack과 무관한 탐지 2건이다. 회전 토큰(`refresh_token`)과 `app/bot/user_token` 이름의 일반 대입 탐지, 그리고 RFC 6750 bearer 자격증명 탐지다. 둘 다 특정 공급자의 형식이 아니라 어디에나 나오는 형식이므로, 함께 지우면 Slack과 상관없는 탐지 범위가 줄어든다. 원래 regex에 있던 `slack[_-]?` 접두 그룹만 뺐다.

**되돌리지 않은 것**: `slack-token-v1`·`slack-webhook-v1` 탐지기와 그 검증기는 이 통합 **이전부터 제품에 있던 것**이다. 통합 작업을 되돌리는 것과 제품 기능을 지우는 것은 다르므로 그대로 둔다. 스캔한 내용물에서 Slack 토큰을 찾는 능력은 유지된다.

되살리려면 세 commit을 revert하면 된다. 아래 [보존한 판단](#되돌리기-전에-확인한-것)은 다시 구현할 때 필요한 내용이라 기록만 남긴다.

##### 되돌리기 전에 확인한 것

Slack 브랜치에서 보존했던 판단과, 공식 문서로 고쳤던 점이다. 다시 구현한다면 같은 결론이 필요하다.

- **목록이 곧 범위다.** 대화 목록을 전혀 읽지 못하면 스캔은 FAILED다. 빈 워크스페이스로 보고하지 않는다.
- **`missing_scope`는 빈 워크스페이스가 아니다.** 종류별로 다시 목록을 요청하고, 여전히 거부하는 종류는 Slack이 요구한 scope 이름과 함께 기록한다. 목록은 어떤 채널을 읽기 전에 항상 완료하므로, scope 대체 경로가 같은 채널을 두 번 읽지 않는다.
- **목록에 없던 대화 · 읽기를 거부한 대화 · 읽었는데 없던 대화는 서로 다르다.** 마지막만 '자격증명 없음'이다.
- DM 행은 읽을 수 있어도 `is_member`가 없을 수 있으므로, 이름 있는 채널만 멤버십으로 건너뛴다.
- 조직 전체 token의 `conversations.list`에 `team_id`가 필요하다. 없으면 두 워크스페이스의 같은 이름 채널이 한 대화가 된다.
- `limit=200`은 계약이 아니라 요청이다. `auth.test`는 잘못된 토큰에도 HTTP 200에 `ok: false`를 준다.
- 모든 Slack 메시지는 `internal` 노출이다. 비공개 채널·DM·외부 공유 채널 어느 것도 인터넷에서 닿지 않는다.
- **회전 토큰 지문 오류**: `xoxe.xoxb-…`에서 안쪽 `xoxb-` 부분만 매칭하면, 교체로 발급된 토큰과 접미사가 같은 무관한 봇 토큰이 같은 지문이 된다. 다시 구현한다면 긴 형식을 먼저 두고 통째로 잡아야 한다.

#### 7d Azure Key Vault (완료)

원본이 한 가지를 잘못 말하고 있었다: `updated_on`을 `last_rotated_at`으로 매핑했다. `updated_on`은 비밀의 **속성이 마지막으로 바뀐 시각**이다 — 태그 수정, 활성화, 만료 변경 모두 이 값을 움직인다. 회전으로 기록하면 값이 그대로인데도 "최근에 교체됨"이라고 말하게 된다.

| 결정 | 구현 |
|---|---|
| `updated_on`은 `updated_at`으로만 기록 | 공유 fact 허용 목록에 `last_rotated_at`이라는 이름 자체가 없다. 실수로도 쓸 수 없다 |
| 태그의 회전 설정은 기록하지 않음 | 태그는 운영자가 객체에 쓴 선언이고 공급자의 상태가 아니다. `/tags`를 사유와 함께 omission으로 남긴다 |
| 회전 정책은 '확인 불가'로 보고 | Key Vault 데이터 평면은 **비밀**의 회전 정책을 공개하지 않는다. 모든 report가 `SECRET_ROTATION_POLICY_NOT_PUBLISHED_BY_THE_DATA_PLANE`를 달고 나간다 |
| 회전을 정직하게 볼 수 있는 곳 | 버전이다. 버전 하나는 실제로 새 값이 설정된 시각이다. 버전은 수집하되 해석은 하지 않는다 |
| 연결 1개 = 금고 1개 | scope와 endpoint가 같은 금고를 가리켜야 한다. 아니면 읽지 않은 금고 밑에 레코드가 쌓인다 |
| `nextLink`는 cursor만 사용 | 공급자가 준 URL을 따라가면 bearer 토큰이 승인하지 않은 host로 간다 |
| 값 경로 없음 | 값을 돌려주는 경로는 transport에서 아예 도달할 수 없고, `value_match`를 단 레코드는 거부된다 |

native export는 저장된 레코드에서 다시 만들되, 잘못된 필드는 빼고 `omitted` 목록에 무엇을 왜 뺐는지 남긴다. Azure Key Vault는 **관리정보 전용**이라 소스 등록 화면에 나타나지 않는다. 61 tests.

**Slack 전부 제외**: 7a를 되돌리면서 Slack은 이 통합에서 완전히 빠졌다. 배포 권한과 고지의 라이선스 결정(Slack 브랜치 **GPLv3** ↔ 제품 **Apache-2.0**)은 여전히 팀 결정으로 남아 있고, 이제는 그 결정 없이도 제품 배포물에 Slack 브랜치에서 온 코드가 들어 있지 않다.

### 5.2 화면에 남은 것

| 항목 | 현재 | 필요한 것 |
|---|---|---|
| ~~전역 검색~~ | — | **완료**. `managed_object` 검색 종류를 추가했고, 결과가 객체 자신의 id를 들고 있어 그 객체 상세가 바로 열린다. 미허용 그룹이 항목·건수를 돌려주지 않는 계약은 그대로다 |
| ~~탐지 상세 연결~~ | — | **완료**. 탐지 상세에 '확인할 관리 객체' 카드를 추가했고, 각 행이 그 객체의 인벤토리 상세로 연결된다 |
| ~~감사 화면~~ | — | **완료**. 공급자 사건은 별도 패널이며 합치지 않는다. 응답이 스스로 '공급자가 보고한 것'이라고 선언하지 않으면 화면이 거부한다. 정렬은 수집 시각이 아니라 사건 발생 시각 |
| ~~연결 화면 wizard~~ | 화면만 있고 서버가 없었음 | **완료**. [아래 연결 설정 항목](#연결-설정-화면-완료) 참조 |
| Slack 소스 허용 목록 | 다시 빠짐 | **제외(2026-09-22)**. 등록 양식·facet·필터·검증 이력에서 Slack을 되돌렸다 |
| ~~Azure 로고~~ | 공식 원본 미확보 | **중립 문자 배지로 표시**. 다른 로고는 원본 URL·바이트·고지를 보존한 것만 넣는 기준이라, 같은 기준으로 받아 두지 않은 Azure는 로고를 넣지 않았다(당시 `web/public/brands/PROVENANCE.md`, 2026-10-01 이전 대시보드와 함께 삭제; 콘솔의 로고 출처는 [logos/SOURCES.md](../../web/public/logos/SOURCES.md)). 콘텐츠 수집 지원으로는 표시하지 않는다 — 소스 등록 화면에 아예 없다 |

#### 연결 설정 화면 (완료)

**wizard는 공급자가 아니라 연결에 붙는다.** 서버가 받는 `kind`는 둘뿐이다.

| kind | 대상 |
|---|---|
| `aws` | AWS 계정 |
| `source` | v1 콘텐츠 연결 — s3 · github · notion · gitlab · gcp · confluence · bitbucket |

여기에 schema 2 관리정보 연결(gitlab · gcp · github · atlassian · bitbucket · azure_key_vault)은 **자기 경로**로 같은 요약을 받는다(`/api/v2/coverage/connections/{id}/setup`). v1 machinery에 억지로 끼우지 않았다. 콘텐츠 목록·대상 선택·승인 범위가 없는 연결이라 그 세 단계는 **미완료가 아니라 해당 없음**으로 나가고, 그것이 설계의 완료 조건("관리 목록만 선택한 연결에 콘텐츠 스캔을 강제하지 않음")을 구조로 만족시킨다.

**무엇이 없었나.** 화면은 7단계 요약·체크포인트 양식·조사 패널을 이미 그리고 있었지만 서버가 없었다. `/capabilities`는 `onboarding` 블록을 보낸 적이 없고, `/onboarding`·`/probe`는 존재하지 않았으며, `management_only`는 브라우저 타입에만 있었다. 그래서 패널은 항상 fallback 분기로 떨어졌고 '조사 시작' 버튼은 405를 받았다.

**무엇이 들어갔나.** 근거는 이미 저장된 것에서만 읽는다 — 선언, 자격증명 점검, 카탈로그 스냅샷, 승인된 범위, 저장된 체크포인트. 화면을 여는 것으로는 아무것도 기록되지 않는다.

| 판단 | 이유 |
|---|---|
| 비밀을 보관하는 것은 인증이 아니고, 거부된 점검도 인증이 아니다 | 공급자가 받아들인 점검만 그 단계를 완료한다 |
| 수집한 적 없는 카탈로그는 빈 카탈로그가 아니다 | 0건은 '자산 없음'이 아니다 |
| 없는 시각은 없는 것이다 | null은 '기록된 시각: 없음'으로 읽히고, 대시보드는 그런 응답을 렌더링하지 않고 거부한다 |
| 체크포인트는 그것이 서술하는 근거에 묶인다 | 관리자가 본 것을 기록하는 것이다. 버전이나 근거가 바뀌었으면 덮어쓰기가 아니라 충돌이다 |
| EXECUTION_CHOICE는 digest에서 제외 | 그 단계가 곧 체크포인트다. 포함하면 저장할 때마다 스스로를 무효화한다 |

**조사(4단계 durable investigation)는 만들지 않았다.** PROBE→CATALOG→INVENTORY→BASELINE_RUN을 서버에서 계속 진행하고 재개·취소하는 기능이며, 설계 §8의 화면 완료 조건에 들어 있지 않은 별도 기능이다. 대신 **서버가 없다고 말하고 화면은 그 버튼을 없앴다** — 항상 실패하는 조작은 없는 것보다 나쁘다. 재개할 때는 `investigation: "AVAILABLE"`을 보내면 기존 컴포넌트가 그대로 살아난다.

payload 모양은 `web/tests/connection-setup.fixture.json` **한 파일로 양쪽에서 고정**한다. `cremore/api/connection_setup_test.py`가 API가 그것을 만든다고 주장하고, `web/tests/connection-onboarding.test.cjs`가 대시보드의 실제 projection을 그것에 돌린다.

### 5.3 correlation / 위험 모델에 남은 것

| 항목 | 상태 |
|---|---|
| 노출 ↔ 관리 목록 연결 | **후보 연결 완료** (`coverage/metadata_correlation.py`, `GET /api/v2/coverage/findings/{id}`). 공급자가 토큰 안에 식별자를 공개하지 않으므로 **정확 일치는 값 대조 경로에만 존재**하며, 이 화면은 후보와 그 한계만 말한다 |
| GCP 식별자 매칭 | `match_service_account_key`는 구현·검증됨. **native export 형식**을 입력으로 받으므로 후보 연결(위)과는 다른 경로다. 서비스 계정 JSON을 운영자가 제출하는 흐름이 필요하고 아직 없다 |
| GCP `match_api_key` | 구현·검증됨. **후보값을 Google에 보내는 외부 요청**이므로 운영자 명시 승인 흐름이 필요하고 현재 수집 중에는 호출하지 않음 |
| 위험 점수 | 관리정보를 점수에 반영하지 않음(설계상 별도 결정 사항) |

### 5.4 운영·배포에 남은 것

| 항목 | 상태 |
|---|---|
| PostgreSQL migration 실제 실행 | 미검증. SQLite/in-memory로만 검사 |
| 여러 worker의 lease 경쟁 | 미검증 |
| 로컬 Docker / EC2 / EKS 배포 | 미검증 |
| 최종 wheel·이미지, 의존성 lock | 미검증 |
| Python 3.14 전체 회귀 | 미검증 (3.12에서 검사) |
| GCP extra (`google-auth`) | `pyproject.toml`의 `gcp` extra에 이미 있음. 설치되지 않으면 `INSTALL_CREMORE_GCP_EXTRA` |
| 옛 SQLite/JSON 자료 이행 | **팀 결정 사항**. 이행 스크립트 없음 |

---

## 6. 검증하지 않은 것

**모든 공급자 검사는 합성 transport다.** 실제 계정에 요청을 보낸 적이 없다.

따라서 다음은 이 작업으로 입증되지 않는다.

- 실제 GitLab(버전·요금제·역할별 API 가시성), GCP(ADC 권한 조합, 감사 로그 활성화 여부), Atlassian(tenant·edition·관리자 권한, 기존에 관측된 400/404의 원인), GitHub(조직·Enterprise 권한, GHES 버전별 관리 endpoint, ghe.com tenant)
- Enterprise 감사 인증은 공식 문서 안에서도 안내가 상충한다. 승인된 시험 계정으로 확인해야 한다.
- Bitbucket DC 10.0의 HTTP token 목록·상세 6개, Cloud resource-token 전체 목록, Confluence DC 관리자 목록은 **어느 쪽 코드에도 없다**. 후속 구현 후보다.

**68개 skip의 정확한 의미**: Atlassian native CLI가 비공개 파일을 저장할 때 쓰는 POSIX 전용 보호(`O_DIRECTORY`, `O_NOFOLLOW`, mode 0700, `st_uid`)의 시험이다. Windows에는 대응 기능이 없으므로 **보호를 완화하는 대신 건너뛴다**. Linux에서는 모두 실행되고, 제품 경로(공통 adapter)는 세 OS 모두에서 검사한다.

---

## 7. commit 목록

```
d5efa96  Put a server behind the connection setup screen
e21e389  Record what shipped, what was deliberately left, and what is deferred
50545d5  Collect Azure Key Vault metadata without inventing a rotation
7f7e161  Show what a provider reported without calling it an action taken here
35d617c  Make the managed inventory findable by search
5a84d9a  Bring the status record up to what is actually built
a09b1b0  Point a finding at the managed objects it could be, without claiming a match
1d9ba76  Let an operator register and triage a Slack workspace
e80750d  Read Slack conversations with the scanner that reads every other source
38faa31  Stop fingerprinting a rotating Slack token as its inner token
3284321  Write down the whole integration: what shipped and what did not
21ad3d0  Record what the integration has actually run, phase by phase
3412ea0  Put the collected provider metadata on the dashboard
95e7c04  Adopt both GitHub collectors into one host-aware provider
22bc9ae  Adopt the GCP inventory, value reads and relationship evidence
97f89da  Adopt the Atlassian and Bitbucket metadata collectors
cd10755  Adopt the GitLab token inventory into the shared collection runtime
ee4ec87  Store provider metadata beside exposures instead of inside them
```

`develop`은 변경하지 않았다.

---

## 8. 다음 사람이 가장 먼저 할 일

1. **라이선스 결정** — Slack 브랜치의 GPLv3를 제품 Apache-2.0 배포물에 어떻게 처리할지. 지금 배포물에는 Slack 브랜치 코드가 없으므로 배포를 막지는 않지만, Slack을 다시 하려면 먼저 정해야 한다.
2. **승인된 시험 계정 확보** — 위 §6의 미검증 항목은 전부 실제 계정이 있어야 답이 나온다. 공급자별로 최소 1개씩.
3. **PostgreSQL에서 migration 1회 실행** — 추가 방식이라 위험은 낮지만, 중간 실패·재실행·구버전 복귀를 실제로 시험해야 한다.
4. **7b·7c 재개 여부 결정** — 2026-09-21에 보류했다. 1번(라이선스)이 정해지기 전에는 재개해도 배포 조건이 확정되지 않는다.
5. **durable investigation** — 만들지 않았다. 필요하면 4단계 상태기계(재개·취소·시도 횟수·작업 연결)를 서버에 만들고 `investigation: "AVAILABLE"`을 보내면 된다. 화면 쪽은 이미 있다.
