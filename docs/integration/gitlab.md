# GitLab 브랜치 상세 분석

기준일: 2026-09-21. `GL`은 `972eac277c015898d1785cd74f710243e4788e5c`, `DEV`는 `71ea52ad933708b7fb851f590ab7162d7f7ed35f`다. 아래 GitLab 상대 경로의 공통 prefix는 `collectors/gitlab/collector_v1/`다. `GL:gitlab_inventory/collector.py:45`는 이 prefix를 붙인 고정 commit의 45행을 뜻한다.

13개 추적 파일 전체를 읽었다. 구성 예제, 출력 예제, demo, 테스트도 포함한다. 파일별 blob과 읽기 범위는 [판독 대장](source-inventory.csv), 전체 제품 결합 결정은 [통합 설계](../INTEGRATION_DESIGN_REVISED.md)에 있다.

## 1. 실제 기능과 흐름

이 브랜치는 GitLab 발급처의 **토큰 메타데이터 인벤토리 CLI**다. 저장소 파일 내용 수집이나 노출 탐지기는 아니다. `cli.main` → `Config` → `Http` → `Collector.initialize/run` → SQLite `Store` → JSONL export로 실행된다. 현재 사용자와 구성 digest가 같은 실행만 재개하며, 페이지 관찰, 후속 작업, checkpoint를 한 트랜잭션으로 저장한다.

| 파일 | 실제 책임 | 통합 시 보존할 내용 |
|---|---|---|
| `gitlab_inventory/config.py` | HTTPS origin, 명시 group/project 숫자 ID, 수집 옵션, 한도 | 사전에 정한 instance, 대상, 요청 예산 |
| `gitlab_inventory/cli.py` | collect/resume/export/compare 및 프로세스 lock | 재개 구성/주체 일치 검사, 완료/실패 의미 |
| `gitlab_inventory/collector.py` | 작업 생성, REST/GraphQL 페이지 처리, 관찰 생성 | 아래 10 family, 대상 확장 범위, 부분 성공 |
| `gitlab_inventory/http.py` | REST/GraphQL 제한 transport | 같은 원점, API 경로, redirect/proxy 차단, TLS, rate/retry/페이지 검사 |
| `gitlab_inventory/model.py` | identity, 필드 상태, 소유자, 발급자 정규화 | endpoint 중복 통합과 출처별 사실 보존 |
| `gitlab_inventory/storage.py` | tasks/pages/records/observations/assets/errors, 비교/export | 페이지 단위 원자성, 관찰 이력, 부재의 제한된 의미 |
| `gitlab_inventory/demo.py`, 예제 JSON | 원본 브랜치의 합성 API, 입력/출력 설명 | 당시 분석 자료다. 현재 제품에서는 2026-10-02 demo·데이터 파일을 제거했고 회귀 검사의 최소 입력만 테스트 내부에서 만든다 |
| `tests/test_collector.py` | 23개 회귀 사례 | 실제 Linux에서 통과한 원본 계약 |
| `__init__.py`, `__main__.py`, `.gitignore` | 패키지, 진입점, 출력 제외 | 제품 namespace로 이동 시 진입점, 비밀 파일 보호 유지 |

근거: `GL:gitlab_inventory/cli.py:48`, `GL:gitlab_inventory/collector.py:45`, `GL:gitlab_inventory/storage.py:14`.

## 2. 수집하는 객체와 범위

**서로 다른 family는 10개다.** Enterprise PAT나 통합 resource API는 추가 수집 경로이며 별도 토큰 종류로 중복 집계하지 않는다.

| family | 주요 경로 | 범위와 한계 |
|---|---|---|
| `personal_access_token` | `/personal_access_tokens`; `/groups/{id}/manage/personal_access_tokens` | 첫 경로는 현재 사용자. enterprise 경로는 지정 최상위 group에 한정 |
| `group_service_account_pat` | `/groups/{id}/service_accounts/{id}/personal_access_tokens` | 관찰한 group service account |
| `project_service_account_pat` | `/projects/{id}/service_accounts/{id}/personal_access_tokens` | 관찰한 project service account |
| `group_access_token` | `/groups/{id}/access_tokens` | 명시, 발견된 group |
| `project_access_token` | `/projects/{id}/access_tokens` | 명시, 발견된 project |
| `group_deploy_token` | `/groups/{id}/deploy_tokens` | group 범위 |
| `project_deploy_token` | `/projects/{id}/deploy_tokens` | project 범위 |
| `pipeline_trigger_token` | `/projects/{id}/triggers` + 고정 GraphQL query | 소유자, 생성/마지막 사용 정보 등 보완. token 원문 저장 목적 아님 |
| `error_tracking_client_key` | `/projects/{id}/error_tracking/client_keys` | error tracking key metadata |
| `kubernetes_agent_token` | `/projects/{id}/cluster_agents/{id}/tokens` | 관찰한 agent별 token metadata |

추가 `/groups/{id}/manage/resource_access_tokens` 응답은 resource 종류/ID를 사용해 기존 group/project token identity로 정규화한다. 명시 group에서 하위 group과 project를 따라가되 공유 project는 `with_shared=false`로 제외한다. `parent_id`가 명시적으로 null인 group만 최상위로 판정한다. 필드가 없으면 최상위라고 추측하지 않는다.

`/user` 수집 주체, subgroup/project/agent 발견, owner/issuer 참조에 실제 등장한 user의 추가 metadata도 asset으로 보존한다. 이를 자격증명 개수에 더하지 않는다. 관리 권한이 있어도 모든 사용자의 PAT를 자동 열거하는 구현은 아니며 PAT 상세는 현재 principal의 항목에 제한된다. GraphQL의 명시 type GlobalID와 양의 숫자 ID 검증, 제외한 credential 필드 경로와 안전한 진단 코드도 정규화 계약에 포함한다.

근거: `GL:gitlab_inventory/collector.py:18`, `:53`, `:93`, `:167`, `:186`, `:199`; `GL:gitlab_inventory/model.py:74`.

## 3. 의미, 저장, 오류 계약

- **Identity:** 자체 PAT, enterprise PAT, service-account PAT가 같은 PAT ID를 가리키면 namespace 규칙으로 묶는다. group/project resource token, deploy token은 범위를 포함한다. 이름으로 중복 제거하지 않는다.
- **사실:** owner와 issuer는 다르다. 값 있음, 명시 null, 필드 누락을 보존하며 이름에서 소유자를 만들어내지 않는다.
- **부분 성공:** GraphQL의 일부 오류가 있어도 유효 관찰을 유지한다. 실패한 페이지의 다음 cursor를 확정하지 않는다. 401은 남은 호출을 멈추고, 독립 작업의 일반 실패는 다른 작업까지 폐기하지 않는다.
- **Resume:** HTTP는 DB 트랜잭션 밖에서 수행한다. 받은 페이지, 관찰, 자식 작업, 다음 checkpoint는 원자적으로 저장한다. 설정/수집 principal 변경 시 기존 실행의 재개를 거절한다.
- **통신:** REST Link/X-Next/offset, GraphQL cursor의 반복, 잘못된 next, 한도를 확인한다. 429/5xx를 제한 재시도하고 긴 Retry-After는 재개 가능한 실패로 남긴다. 오류 본문을 결과에 반향하지 않는다.
- **비교:** `newly_observed`는 새로 발급됐다는 뜻이 아니다. 완주 source에서 이번에 안 보이면 `not_observed`, 불완전 source라면 `observation_unknown`이다. 양쪽 모두 곧바로 폐기 판정하지 않는다.
- **Sanitizer 한계:** `sanitize`는 재귀적인 고정 필드명 차단 방식이다. 임의 free text의 모든 secret이 제거된다는 보장은 없다. 제품으로 옮길 때 typed field allowlist와 값 비반향 검증을 함께 적용해야 한다.

근거: `GL:gitlab_inventory/model.py:38`, `:74`, `:89`; `GL:gitlab_inventory/collector.py:199`, `:224`, `:258`; `GL:gitlab_inventory/storage.py:190`; `GL:gitlab_inventory/http.py:1`.

## 4. develop과의 차이, 충돌, 통합 결정

| 접점 | develop에 있는 것 | 팀원에 있는 추가 기능 | 설계 결정 |
|---|---|---|---|
| GitLab 수집 | 선택 project/ref/path의 파일 콘텐츠 → 노출 탐지 | 발급처의 10 family metadata | 둘 다 유지. 기존 `gitlab` content job 의미를 바꾸지 않음 |
| Scope | 콘텐츠 project/path config | group 계층, enterprise/manage, service account | 별도 inventory purpose와 정확한 instance/group/project 범위 |
| 인증 | `secret_ref`/sealed 값을 worker에서 resolve | CLI token, `/user` principal pin | 기존 secret 경계 사용, principal pin은 추가 보존 |
| 작업 | PostgreSQL task lease, 취소, checkpoint | SQLite 작업 그래프/페이지 원자성 | 기존 task/store에 수용. CLI 파일 lock을 EKS 동시 실행 제어로 사용하지 않음 |
| 관찰 | 엄격한 AWS 중심 coverage row | token 종류별 구조, 여러 출처, 필드 상태 | versioned typed observation. 문자열 label 하나로 축소하지 않음 |
| 대시보드 | GitLab 콘텐츠 연결, 노출, 금고 비교 | UI 없음 | 기존 화면에 발급처 목록, 상세 출처, 완주 범위 추가 |
| Vault 대조 | 값 HMAC, 식별자 후보 구분 | metadata만 수집 | 목록에 존재한다는 이유로 값 일치/유효성/노출을 만들지 않음 |
| 배포 | Linux 이미지, 로컬/EC2/EKS 구조 | `fcntl` CLI lock | worker 경로는 DB lease로 전환. 독립 native Windows CLI 지원은 별도 보완 필요 |

기준 접점: `DEV:cremore/source_config.py:1`, `DEV:cremore/domain/connections.py:86`, `DEV:cremore/worker/factory.py:170`, `DEV:cremore/coverage/models.py:64`, `DEV:cremore/coverage/correlation.py:59`, `DEV:cremore/db/task_store.py:240`, `:660`.

Git textual 충돌은 `.gitignore` add/add와 `README.md` modify/delete다. 팀원이 루트 제품 README를 제거한 사실을 제품 기능 삭제 의도로 해석하지 않는다. 팀원 기능은 새 package로 보존하고 제품 README와 ignore 보호 규칙은 병합한다.

## 5. 직접 검증과 남은 범위

Windows Python 3.12의 `python -B -m unittest discover -s tests -q`는 23개 중 21개 통과, failure 1개, error 1개였다. 두 실패 모두 `cli.py:72`의 `fcntl` import 때문이다. CLI demo와 emergency-lock 테스트가 영향을 받았다.

동일 snapshot을 기존 Linux 이미지의 일회성 컨테이너에서 실행했을 때 **23/23 통과**했다. 외부 네트워크는 차단했고 실제 GitLab token이나 고객 설정을 사용하지 않았다.

```text
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,noexec,size=64m --mount type=bind,source=C:\Users\admin\Desktop\cremore\work\integration-review\gitlab-snapshot,target=/review,readonly --workdir /review --entrypoint python cremore-python:latest -B -m unittest discover -s tests -q
```

HTTPS custom origin 설정은 self-managed transport 경로가 존재한다는 증거다. 모든 GitLab edition/version/tier에서 모든 endpoint가 제공되거나 현재 인증 주체가 조직의 모든 토큰을 볼 수 있다는 증거는 아니다. 이 부분은 공급자 지원표와 승인된 시험 계정의 검증 항목으로 남긴다.

통합 완료 조건은 10 family, 모든 source provenance, null/missing, scope identity, 부분 성공, 동일 principal resume의 보존, Windows/Linux 실행 범위의 정확한 표기, stale lease의 쓰기 차단, 중복 페이지의 idempotency, 기존 GitLab 콘텐츠 스캔 회귀 없음이다. 원본 오프라인 테스트와 공개 공식 문서 대조를 수행했으며 제품 통합, 실제 GitLab API 검증은 하지 않았다.

## 6. 공식 문서 대조 보완

2026-09-21 [공식 근거 GL1–GL5](official-docs.md#gitlab)를 실제로 읽고 다음 범위를 확인했다.

- 일반 PAT API는 관리자에게 instance 목록을 제공할 수 있지만 팀원 코드는 자기 `user_id`로 제한한다. 관리자 연결과 전사 열거 기능을 구분한다.
- 그룹 `/manage/...`는 GitLab.com Premium/Ultimate의 최상위 그룹 Owner 계약이다. self-managed의 지원으로 일반화하지 않는다.
- Trigger 응답에는 생성자에 따라 전체 token 또는 4문자 축약값이 포함될 수 있다. 값 제거를 유지하고 축약값으로 exact match를 만들지 않는다.
- Agent token 목록은 active만 반환하며 GraphQL `Project.pipelineTriggers`는 Experiment다. 부재, 부분 성공의 기존 의미를 보존한다.

그룹/프로젝트 access token, 서비스 계정 PAT, deploy token, error-tracking client key의 공식 읽기 경로도 대조했다. 설치 버전, 요금제, 실제 권한 검증은 남아 있다.
