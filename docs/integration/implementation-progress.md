# develop_total 구현 진행 기록

기준일: 2026-09-21. [통합 설계](../INTEGRATION_DESIGN_REVISED.md) §7의 단계 번호를 그대로 쓴다. 각 절은 **실제로 실행한 검사와 그 결과**만 적는다.

## 0. 구현 기준 갱신 (완료)

| 항목 | 정확한 revision 또는 결과 |
|---|---|
| 시작 develop_total | `cb459c1a4de4d11414968629f69d81298ea76e69` |
| 시작 및 종료 develop | `a6ffdd656e839ab12ab09a28bbc7b5af87d0e97a` |
| 병합한 publish/develop | `a6ffdd656e839ab12ab09a28bbc7b5af87d0e97a` |
| 갱신 후 develop_total | `9b56f1f57479d5ceab8d69e0f7529b1fdb07bdba` |
| 병합 결과 | 충돌 없이 완료. `.gitignore`는 자동 결합 |
| 원격 변경 | push 없음. develop ref 이동 없음 |

## 단계별 현황

| 단계 | 내용 | 상태 | 근거 |
|---|---|---|---|
| 1 | 공통 schema 2 저장·실행·API | **완료** | `cremore/coverage/metadata_*.py`, `cremore/api/metadata_coverage.py`, `cremore/db/migrations.py` |
| 2 | 목적별 범위·인증·실행 연결 | **완료** | `MetadataConnectionSpec`, `metadata_job.resolve_slots`, `TaskStore` lock/lease |
| 3 | GitLab | **완료** | [수용 기록](gitlab-adoption.md) · 110 tests |
| 4 | GCP | **완료** | [수용 기록](gcp-adoption.md) · 108 tests |
| 5 | Atlassian / Bitbucket | **완료** | [수용 기록](atlassian-adoption.md) · 285 tests |
| 6 | GitHub 조직 + Enterprise | **완료** | [수용 기록](github-adoption.md) · 61 tests |
| 7 | Slack 콘텐츠 → 실시간·알림 → 관리정보·소유 토큰 → Azure | **Azure(7d)만 완료 · Slack 전부 제외** | `coverage/providers/azure_key_vault/` · 61 tests |
| 8 | 대시보드·API·프록시 | **완료** | `web/app/provider-inventory.tsx`, `/api/v2/coverage/providers`, `/api/v2/coverage/findings/{id}` |

## 1–2단계: 공통 계약

schema 1은 그대로 두고 schema 2를 **나란히** 추가했다. v1 연결의 경로, payload 재생, 상태 코드는 바뀌지 않으며, v1·v2 연결은 서로의 경로에서 보이지도 수정되지도 않는다(`cremore/api/metadata_coverage_test.py`).

- 레코드 4종: `entity_observation`, `relation`, `provider_event`, `operation_report`.
- 필드는 허용 목록이다. 승인되지 않은 이름은 값이 아니라 경로와 이유만 omission으로 남고, 없음·null·형식 오류는 서로 다른 상태로 남는다.
- 공급자 상태는 `PROVIDER_REPORTED`이며 검증이 아니다. 조회 API의 `verification`은 항상 `NOT_PERFORMED`다.
- 실행은 기존 worker의 `INVENTORY` task mode와 연결 lock을 쓴다. 공급자 I/O는 트랜잭션 밖에서 하고, 한 페이지의 레코드와 그 다음 cursor를 같은 트랜잭션에서 commit한다. 취소·revision 변경·lease 상실 뒤에는 아무것도 publish하지 않는다.
- DB 변경은 조회용 projection 테이블 2개 추가뿐이며, 기존 DDL과 같은 transaction-scoped lock 안에서 만들어진다.

## 3–6단계: 공급자별 수용

각 공급자의 원본 판독 범위, 보존한 의미, 공식 문서로 확인한 제한, 실행한 검사는 공급자별 수용 기록에 있다.

| 공급자 | 패키지 | 모드·범위 | 값 접근 |
|---|---|---|---|
| GitLab | `coverage/providers/gitlab` | group/project/user, 토큰 10종 | 없음 |
| GCP | `coverage/providers/gcp` | project 1개, global·지역 Secret, 관계 4종 | 선택. HMAC 지문만 저장 |
| Atlassian·Bitbucket | `coverage/providers/atlassian` | 조직 6모드, 45개 read operation | 없음 |
| GitHub | `coverage/providers/github` | organization·enterprise 두 모드, GHES·ghe.com | 없음 |

공통 원칙: 읽지 못한 source는 그 이유가 붙은 report로 남고 '없음'으로 바뀌지 않는다. 429와 공급자 장애는 부분 결과가 아니라 `WAITING`과 재시도 시각이다. 완료한 source는 재개할 때 다시 읽지 않는다.

## 8단계: 대시보드

- `/api/v2/coverage/providers`가 공급자별 edition, scope 종류, 인증 역할, 모드, 한계를 알려준다. adapter가 설치되지 않은 공급자는 목록에 없다.
- Next.js 프록시는 `/api/backend/v2/coverage/...` 한 경로만 v2로 보낸다. 다른 v2 namespace와 빈 segment, `..`는 404다(`web/tests/proxy.test.cjs`).
- 기존 `?tab=aws-inventory` 링크는 그대로 동작하고 AWS가 선택된 상태로 열린다. 같은 화면에서 다른 공급자를 고르면 schema 2 패널이 열린다.
- 검색·필터·페이지는 서버가 처리한다. 필터는 조회된 행이 실제로 다를 때만 나타난다.
- 연결 인증, 수집 결과, 공급자 상태, 유효성 검증을 각각 다른 자리에 표시한다. 읽지 못한 source는 이유와 함께 미수집으로, 한 번도 실행하지 않은 연결은 '수집한 적 없음'으로 표시한다.
- 조회는 로그인한 모든 역할, 수집 실행은 Analyst 이상, 연결 설정은 Admin이다. 서버 계약과 같다.

## 탐지 상세 ↔ 관리 목록

`GET /api/v2/coverage/findings/{id}`가 한 탐지 결과에 대해 **그 공급자에서 이 자격증명을 관리하고 있을 수 있는 객체**를 돌려준다. 일치 판정이 아니며, 왜 좁힐 수 없는지를 함께 돌려준다: 이 공급자들은 토큰 안에 식별자를 공개하지 않고, 인벤토리는 값을 돌려주지 않는다. 값 일치는 기존 `/api/v1/findings/{id}/coverage`에만 있으며 이 화면은 그것을 다시 계산하지 않는다.

목록을 쓸 수 있게 만드는 두 가지: GHES 객체는 github.com 객체와 다른 설치이므로 노출이 기록한 호스트의 인벤토리하고만 대조하고(두 설치에 걸치면 어느 쪽으로도 좁히지 않는다고 말한다), 사용 기록이 있는 후보는 없는 후보와 구분한다(GitHub은 감사 사건, GCP는 로그에서 뽑은 관계로 기록하므로 둘 다 센다. 0은 '수집된 사용 기록 없음'이지 '사용된 적 없음'이 아니다).

## 감사 화면: 공급자 사건은 합치지 않는다

`GET /api/v2/coverage/events`가 공급자에서 읽은 사건을 돌려주고, 감사 화면은 그것을 **별도 패널**로 보여준다. 둘은 성격이 다른 근거다. 로컬 감사 기록은 이 설치에서 누군가 수행한 작업이고 구조상 완전하다. 공급자 사건은 공급자가 돌려준 것이며 공급자의 보관 기간과 연결이 읽을 수 있던 범위로 제한된다 — 그래서 사건이 없다는 것이 아무 일도 없었다는 근거가 아니고, 비어 있을 때도 그 말을 화면에 적는다.

그 경계는 응답이 직접 선언한다(`boundary`). 선언하지 않은 응답은 화면이 렌더링하지 않고 거부한다. 각 행은 공급자가 그 사건을 어느 객체에 어떻게 묶었는지도 함께 들고 있다 — candidate로 묶인 사건은 그 객체에 대한 사건이 아니다.

정렬은 발생 시각 기준이다. `provider_event`에는 자체 effective 시각이 없어 한 batch의 두 사건이 id로 정렬되던 것을, projection에서 `occurred_at`이 곧 '공급자에서 참이던 시각'이 되도록 고쳤다.

## 연결 설정 화면

wizard는 **공급자가 아니라 연결에 붙는다**. 서버가 받는 `kind`는 `aws`(AWS 계정)와 `source`(s3 · github · notion · gitlab · gcp · confluence · bitbucket) 둘뿐이고, schema 2 관리정보 연결은 v1 machinery에 끼우는 대신 자기 경로로 같은 요약을 받는다.

화면은 이미 7단계를 그리고 있었지만 서버가 없었다. `/capabilities`는 `onboarding` 블록을 보낸 적이 없고, `/onboarding`·`/probe`는 존재하지 않았으며 `management_only`는 브라우저 타입에만 있었다. 그래서 패널은 항상 fallback으로 떨어졌고 '조사 시작' 버튼은 405를 받았다.

근거는 이미 저장된 것에서만 읽는다. 비밀을 보관하는 것은 인증이 아니고 거부된 점검도 인증이 아니며, 수집한 적 없는 카탈로그는 빈 카탈로그가 아니고, 없는 시각은 null이 아니라 없는 것이다. 체크포인트는 그것이 서술하는 근거에 묶이므로 근거가 움직이면 덮어쓰기가 아니라 충돌이다.

관리정보 전용 연결에서는 콘텐츠 목록·대상 선택·승인 범위가 **해당 없음**으로 나가고, 요약도 '선택 대상 0개'가 아니라 '설계상 없음'이라고 적는다. 빠진 것이 아니기 때문이다.

서버에서 계속 진행하는 4단계 조사(PROBE→CATALOG→INVENTORY→BASELINE_RUN)는 만들지 않았다. 화면이 그 버튼을 없앴고 서버가 `investigation: "NOT_AVAILABLE"`이라고 말한다 — 항상 실패하는 조작은 없는 것보다 나쁘다.

payload 모양은 `web/tests/connection-setup.fixture.json` 한 파일로 양쪽에서 고정한다.

## 화면 마무리

- 전역 검색에 `managed_object` 종류를 더했다. 결과가 객체 자신의 id를 들고 있어 그 객체 상세가 바로 열린다. 미허용 그룹이 항목·건수를 돌려주지 않는 계약은 그대로다.
- schema 2 표(인벤토리·연결·공급자 사건)와 새 패널 2개에 스타일을 넣었다. 공급자 식별자는 길다. 전부 줄바꿈으로 처리하고 가로 스크롤을 만들지 않는다 — 휴대폰에서 가로 스크롤은 옆에 있는 '사유'를 가린다.
- Azure Key Vault는 공식 로고 원본을 기존 기준(원본 URL 확인·바이트 보존·고지 보관)으로 받아 두지 않았으므로 중립 문자 배지로 표시한다. 관리정보 전용이라 소스 등록 화면에는 아예 없다.

### 이번 단계에서 함께 고친 것

- schema 2 API에 테스트가 하나도 없었다. `cremore/api/metadata_coverage_test.py` 16개와 `auth_test.py`의 역할 검사 5건을 추가했다.
- native export가 실행될 수 없었다. 저장된 contract snapshot에는 비밀 참조가 없는데 GitLab export가 그것을 다시 요구했다. 읽기 경로에서는 인증 절반을 검사하지 않도록 고쳤다.
- 병합해 온 develop의 노출 경로 작업 때문에 브라우저 검증 3개가 실패하고 있었다. 하나는 stub하지 않은 읽기에서 예외로 죽었고, 하나는 탐지 상세의 구역 순서가 '노출 위치'보다 '진행 단계'를 앞에 두어 밀도 검사를 어겼다. 지금은 19개 전부 통과한다.

## 7단계: Slack(전부 제외)과 Azure

Slack은 설계 §6에서도 4단계로 나눈 유일한 공급자다. 7a를 한 번 구현했다가 되돌렸고, 7b·7c는 착수하지 않았다. 7d(Azure Key Vault)만 남았다.

| 하위 단계 | 내용 | 비고 |
|---|---|---|
| 7a | Slack 콘텐츠 수집을 기존 탐지 제품에 연결 | **철회(2026-09-22)**. 수집기·연결·화면·Slack 토큰 탐지기 3종을 전부 되돌렸다. Slack과 무관한 탐지 2건(`refresh_token`·`app/bot/user_token` 일반 대입, RFC 6750 bearer)과 통합 이전부터 있던 `slack-token-v1`·`slack-webhook-v1`은 남겼다 |
| 7b | 실시간 수신·편집·알림 | **제외(2026-09-22)**. DB 수신 기록 후 ACK, 암호화 inbox, 새 영속 outbox가 필요하다 |
| 7c | 관리정보·소유 토큰 | **제외(2026-09-22)**. 앱·감사·소유 토큰 관측을 schema 2로. OAuth state 1회 사용, 교체 후 저장 실패의 복구 상태 |
| ~~7d~~ | ~~Azure Key Vault metadata~~ | **완료**. `updated_on`은 속성 변경 시각이라 `updated_at`으로만 기록한다. `last_rotated_at`은 공유 fact 허용 목록에 이름 자체가 없어 실수로도 쓸 수 없다. 태그의 회전 설정은 운영자 선언이므로 사유와 함께 omission으로 남기고, 회전을 정직하게 볼 수 있는 곳(버전)은 수집하되 해석하지 않는다 |

Slack 브랜치의 GPLv3와 제품의 Apache-2.0 사이의 배포 권한·고지 결정은 아직 팀 결정으로 남아 있다. 지금 배포물에는 Slack 브랜치에서 온 코드가 없다.

## 실행한 검사

```text
python -m pytest cremore -q          # 4464 passed, 68 skipped, 257 subtests
python -m ruff check cremore         # All checks passed
cd web && npm test                   # 447 passed
cd web && npm run build              # 성공
cd web && npm run test:browser       # 19/19 통과
```

68개 skip은 Atlassian native CLI의 POSIX 전용 파일 보호(`O_NOFOLLOW`, `O_DIRECTORY`, uid·mode 검사) 시험이다. Windows에는 대응 기능이 없으므로 보호를 완화하는 대신 건너뛴다. Linux에서는 모두 실행된다. 제품 경로(공통 adapter)는 세 OS 모두에서 검사한다.

## 아직 검증하지 않은 것

- 실제 공급자 계정(GitLab, GCP, Atlassian, Bitbucket, GitHub 조직·Enterprise·GHES·ghe.com)에서의 권한과 응답. 모든 검사는 합성 transport다.
- PostgreSQL에서의 migration 실행, 여러 worker의 lease 경쟁, 실제 배포(로컬 Docker·EC2·EKS).
- 최종 wheel·이미지, 의존성 lock, Python 3.14 전체 회귀.
- 기존 SQLite/JSON 자료의 이행 여부는 팀 결정으로 남아 있다.

`develop`에는 변경하지 않았다. `develop_total`은 `publish` 원격에 push했다.

## Slack 제외 결정 (2026-09-21 보류 → 2026-09-22 전부 제외)

9월 21일에 7b·7c를 보류했고, 9월 22일에 **Slack 전부**를 빼기로 했다. 한 번 commit했던 7a(`38faa31`, `e80750d`, `1d9ba76`)를 되돌렸다.

되돌린 것: 대화 수집기와 58개 검사, 연결·범위 검증과 `auth.test` 자격증명 점검, job kind와 노출 메타데이터 키, 등록 양식·facet·필터·검증 이력의 Slack, Slack 토큰 탐지기 3종과 대조표 50건.

남긴 것: Slack과 무관한 탐지 2건이다. `refresh_token`·`app/bot/user_token` 이름의 일반 대입 탐지와 RFC 6750 bearer 자격증명 탐지이며, 어느 것도 특정 공급자의 형식이 아니라 함께 지우면 Slack과 상관없는 탐지 범위가 줄어든다. regex에 있던 `slack[_-]?` 접두 그룹만 뺐다. 통합 이전부터 제품에 있던 `slack-token-v1`·`slack-webhook-v1` 탐지기와 검증기도 그대로 둔다 — 통합 작업을 되돌리는 것과 제품 기능을 지우는 것은 다르다.

다시 하려면 세 commit을 revert하면 된다. 다시 구현할 때 필요한 판단은 [통합 현황](INTEGRATION_STATUS.md) §5.1에 남겼다.
