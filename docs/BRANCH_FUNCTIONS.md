# 팀원 브랜치 기능 목록

기존 정적 기능 목록을 보존한 참고 자료다. 이 목록의 최초 작성 단계에서는 테스트를 실행하지 않았다.
2026-09-21 후속 검토에서는 모든 팀원 소스 판독, 원본 오프라인 테스트, 합성 비교를 수행했다.
공식 계약의 후속 대조는 [공식 문서 대조](integration/official-docs.md)에 있다. 현재 통합 결정과 근거는 [통합 설계](INTEGRATION_DESIGN_REVISED.md), [브랜치별 상세 보고서](integration/verification.md), [파일별 판독 대장](integration/source-inventory.csv)을 따른다.
아래의 확인된 집계, 범위 오류는 후속 검증과 맞게 정정했으며 실제 공급자 운영 검증과는 구분한다.

---

## 1. `develop_gitLab` — been

### 1.1 수집 대상 (10 family, 표는 12개 수집 경로)

| family | endpoint | 비고 |
|---|---|---|
| `personal_access_token` (자기) | `/personal_access_tokens` | |
| `personal_access_token` (enterprise) | `/groups/{id}/manage/personal_access_tokens` | 최상위 그룹만 |
| `group_service_account_pat` | `/groups/{id}/service_accounts/{id}/personal_access_tokens` | |
| `project_service_account_pat` | `/projects/{id}/service_accounts/{id}/personal_access_tokens` | |
| `group_access_token` | `/groups/{id}/access_tokens` | |
| `project_access_token` | `/projects/{id}/access_tokens` | |
| `group_deploy_token` | `/groups/{id}/deploy_tokens` | |
| `project_deploy_token` | `/projects/{id}/deploy_tokens` | |
| `pipeline_trigger_token` | `/projects/{id}/triggers` + GraphQL | GraphQL로 `hasTokenExposed`, `lastUsed` 보강 |
| `error_tracking_client_key` | `/projects/{id}/error_tracking/client_keys` | 상세 조회 없음 |
| `kubernetes_agent_token` | `/projects/{id}/cluster_agents/{id}/tokens` | agent 발견 후 |
| 통합 resource token | `/groups/{id}/manage/resource_access_tokens` | 단독 API와 같은 키로 정규화 |

부수 자산: `/user`(수집 주체), `/groups/{id}/subgroups`, `/groups/{id}/projects`,
`/projects/{id}/cluster_agents`, `/users/{id}`(소유자, 발급자 참조에 등장한 사용자만).

### 1.2 식별 (`model.identity`)

- PAT 3경로(자기, enterprise, 서비스계정)는 **같은 ID 공간**이므로 `personal_access_token`
  네임스페이스로 합치고 scope를 비운다.
- group/project access token → `resource_access_token` 네임스페이스 + `{kind, id}`.
- group/project deploy token → `deploy_token` 네임스페이스 + `{kind, id}`.
- 통합 API 응답의 `resource_type`/`resource_id`로 단독 API와 **동일한 키를 재구성**한다.
- `native_id`는 양의 정수만 받고, GraphQL GlobalID는 `gid://gitlab/{명시한 타입}/` 접두사가
  있을 때만 변환한다. 아니면 `ValueError`.

### 1.3 비밀 제거 (`model.sanitize`)

- `SECRET_KEYS` 16종(`token`, `runners_token`, `client_secret`, `public_key`, `sentry_dsn` …).
- `normalized_key()`가 camelCase→snake_case 변환 후 대조 → GraphQL, REST 양쪽에 같은 규칙 적용.
- 제거한 필드의 **경로**(`a.b[3].token`)를 `excluded_credential_fields`로 남긴다.
- **주의**: `public_key`를 제거하므로 SSH/deploy 키를 공개키 지문으로 조인할 수 없다.
  manifest의 `limitations`에 명시돼 있다.

### 1.4 사실 vs 추정 (`model.metadata_view`)

- 관찰을 `(observed_at, source_id)` 순으로 병합하되 **응답에 없는 필드는 덮어쓰지 않는다.**
- `owner`/`issuer` 각각 `observed` / `null` / `not_provided` 3상태.
- `owner`는 `user_id`, evidence 문자열은 `"user_id (token owner; not necessarily creator)"`.
  `issuer`는 `created_by_user_id`/`createdByUser`. **소유자와 생성자를 섞지 않는다.**
- `name`은 `{value, status}` 구조. Trigger의 `description`을 `name`으로 바꾸지 않는다.

### 1.5 HTTP (`http.py`)

- `NoRedirect`로 3xx 거부 → `PRIVATE-TOKEN`이 다른 호스트로 새지 않음.
- `checked_url`: 동일 origin + 경로 allowlist(`/api/v4/`, `/api/graphql`) + userinfo, fragment 거부.
- `ProxyHandler({})`로 환경 프록시 차단.
- `TokenBucket`(rate/capacity, 시계, sleep 주입 가능).
- 재시도는 429/500/502/503/504만. 401은 즉시 실패 + 수집 루프 중단.
- `Retry-After` > 60초면 자지 않고 `RETRY_LATER`로 남겨 `--resume`에 맡김.
- TLS 검증 실패 전용 코드 + "검증을 끄지 말라" 안내.
- HTML 오류 페이지는 `INVALID_JSON`으로 실패(빈 목록으로 바꾸지 않음).
- `next_page`: Link → `X-Next-Page` → 보수적 offset. **총 건수 헤더는 종료 조건으로 안 씀**
  (GitLab.com이 생략하므로).
- `PAGINATION_SCOPE_CHANGED`: 다음 페이지 경로가 바뀌면 중단.

### 1.6 실행, 저장 (`collector.py`, `storage.py`)

- BFS 작업 큐(`tasks` 테이블, `stable_id(spec)`로 중복 방지).
- **HTTP는 트랜잭션 밖, 페이지 저장, 후속 큐, 체크포인트는 같은 트랜잭션 안.**
- 순환 탐지: REST는 URL, GraphQL은 cursor 해시를 `pages` 테이블에 기록.
- GraphQL 부분 오류 시 **유효 관찰은 저장하되 cursor를 전진시키지 않는다**(누락 은폐 방지).
- `graphql_diagnostics`: 서버 오류 전문 대신 `[A-Za-z_][A-Za-z0-9_]{0,100}` 스키마 이름과
  line/column만 남긴다.
- 오류에 `code_location`(traceback의 file:line:function) 기록.
- 재개 시 `principal_id`와 config 해시 대조 → 다른 계정, 다른 설정의 출력을 덮지 않음.
- 스키마: `settings` / `tasks` / `pages` / `records`(토큰 1개=1행) / `observations`(출처별 원본) /
  `assets` / `errors`.
- 출력: `inventory.jsonl`, `coverage.jsonl`, `assets.jsonl`, `errors.jsonl`,
  `changes.jsonl`(`--previous` 지정 시), `manifest.json`.
- JSONL은 tmp + `fsync` + atomic replace. 파일 0600, 디렉터리 0700.

### 1.7 변화 판정 (`storage.compare`)

- `newly_observed` + `not_necessarily_newly_issued: True`
- `metadata_changed` + 바뀐 필드 목록(존재 여부와 값을 함께 비교)
- `not_observed`: **완료된** 동일 소스가 반환하지 않음
- `observation_unknown`: 소스 미완료, 미예약
- 전부 `revocation_inferred: False`. **폐기를 추정하지 않는다.**

### 1.8 권한, 범위 자제

- 관리자 권한이 있어도 전체 사용자 PAT를 훑지 않는다.
- PAT 상세는 `item["user_id"] == principal_id`일 때만 조회.
- `state=active` 같은 임의 필터를 붙이지 않는다.
- `with_shared=false`, `include_subgroups=false`로 공유 프로젝트 중복 방지.
- `parent_id`가 명시적 null일 때만 최상위 그룹 판정. 필드가 없으면
  `TOP_LEVEL_GROUP_UNCONFIRMED` 노트.
- 설정은 미지의 키를 거부하고, `base_url`은 경로, 계정정보 없는 HTTPS origin만 허용.
  토큰은 환경 변수로만 받는다(argv 불가).
- `demo` 서브커맨드로 계정 없이 합성 응답 검증 가능.

---

## 2. `develop_gcp` — Codex

### 2.1 객체 모델

| `object_type` | 대상 | `credential_type` |
|---|---|---|
| `principal` | 서비스 계정 | `None` |
| `credential` | SA 키 | `service_account_user_managed_key` / `..._system_managed_key` |
| `credential` | API 키 | `api_key` |
| `vault_item` | Secret Manager 항목(글로벌, 리전) | `None` |
| `vault_version` | Secret 버전 | `secret_version` |

### 2.2 인벤토리 (`collector.py`)

- 서비스 계정: `disabled`
- SA 키: `validAfterTime`, `validBeforeTime`, `disabled`, `keyOrigin`(`USER_PROVIDED`/`GOOGLE_PROVIDED`),
  **`disableReason` 3종 allowlist** — `USER_INITIATED` / **`EXPOSED`** / **`COMPROMISE_DETECTED`**
- API 키: `showDeleted=true`로 조회, `deleted_at`, `api_key_uid`, `created_at`, `updated_at`,
  `client_restriction_type`(`none`/`ambiguous`/`unknown`), `api_target_count`, `serviceAccountEmail`
- Secret: `created_at`, `expires_at`, `next_rotation_time`
- 리전 Secret: `secretmanager.{region}.rep.googleapis.com`, 이름의 리전과 교차 검증
- `_service_state`로 API 활성 상태를 조회하되 **"서비스 상태가 아니라 목록 응답이 커버리지를
  증명한다"**. `_resolved_error`가 `permission_denied_or_api_disabled`를 상태와 결합해 둘로 가름.
- `_pages`: `page_token_cycle`, `page_limit_reached`, 이미 모은 행 유무로 `partial`/`error` 구분
- `_time`/`_status`/`_safe_string`으로 타입, 형식 검증 후에만 복사

### 2.3 전송 안전 (`AdcTransport`)

- ADC(Application Default Credentials), `allow_redirects=False`
- **`post_readonly`가 정확히 2개 엔드포인트만 정규식 완전일치로 허용**:
  `logging.googleapis.com/v2/entries:list`,
  `cloudresourcemanager.googleapis.com/v1/projects/{id}:getIamPolicy`
- `ApiError`는 코드만 보관. 응답 본문, URL, 토큰을 남기지 않음
  (google-auth/requests 오류가 토큰 포함 URL을 품을 수 있어 `raise ... from None`)
- 상태 코드 매핑: 403→`api_disabled`/`permission_denied_or_api_disabled`, 401→`authentication_failed`,
  429→`rate_limited`, 5xx→`provider_unavailable`

### 2.4 감시 (`watch.py`)

- 누적 상태 파일 + **append-only 이벤트 배열**(`sequence` 번호 부여)
- `lifecycle_state`: `active` / `disabled` / `destroyed` / `deleted` / `no_longer_listed` / `unknown`
- 이벤트 6종: `discovered`, `state_changed`, `metadata_changed`, `value_collected`,
  `value_changed`, `no_longer_listed`
- `_path_complete()`: **부재는 해당 경로가 완전히 나열된 경우에만 의미**를 갖고, Secret 버전은
  부모 Secret 경로까지 재귀 확인
- 상태 파일 잠금(`_state_lock`), 스키마, 프로젝트 불일치 시 거부

### 2.5 관계 그래프 (`relations.py`, 604줄 전수)

세 증거 출처를 하나의 엣지 모델로 합친다.

| 출처 | 엔드포인트 | 산출 관계 |
|---|---|---|
| 감사 로그 | `logging.googleapis.com/v2/entries:list` | `secret_access_observed`, `secret_version_access_observed`, `service_account_key_secret_access_observed`, `service_account_key_version_access_observed`, `service_account_activity_observed`, `service_account_key_activity_observed` |
| 사용량 지표 | `monitoring.googleapis.com/v3/.../timeSeries` (`serviceruntime.../api/request_count`, `resource.labels.credential_id="apikey:{uid}"`) | `api_key_requests_observed` |
| IAM 정책 | 프로젝트 + Secret별 `getIamPolicy`(v3) | `policy_allows_secret_version_access` |

**엣지 구조**: `source_id`, `target_id`, `relation`, `evidence_class`, `evidence_source`,
`evidence_id`, `first_observed_at`, `last_observed_at`, `collection_scope`,
`collection_status`, `coverage_path`, `id`(sha256[:24]).

- **`evidence_class` 3종**: `observed_access`(로그, 지표) / `policy_possible`(직접 주체 + 무조건
  바인딩) / `unconfirmed`(group, domain, allUsers 같은 확장 불가 주체이거나 조건부 바인딩).
  모든 IAM 엣지에 `effective_access: "not_evaluated"`를 붙인다 — GCP에는 AWS
  `SimulatePrincipalPolicy` 같은 유효 권한 평가가 없으므로 평가했다고 주장하지 않는다.
- **감사 로그를 전송 경계에서 투영한다.** `protoPayload`가 protobuf `Any`라 Google이 중첩
  응답 마스크를 거부하므로, 역직렬화 직후 `request`/`response`/`metadata`를 버리고
  `serviceName`, `methodName`, `resourceName`, `status`,
  `authenticationInfo.{principalEmail, serviceAccountKeyName}`만 남긴다.
- **키 단위 귀속**: `serviceAccountKeyName`을 `_key_id()`로 검증(프로젝트 별칭 일치 +
  키 소유 이메일이 호출 주체와 일치)한 뒤에만 SA 키 → 대상 엣지를 만든다.
- 성공한 호출만 엣지가 된다. 실패는 `failed_secret_access_attempt` 이슈로 계수.
- 로그 타임스탬프가 창 밖이면 `log_outside_window`로 버린다.
- **커스텀 역할 해석**: allowlist에 없으면 `iam.googleapis.com/v1/{role}`을 조회해
  `includedPermissions`에 `secretmanager.versions.access`가 있는지 확인하고 캐시한다.
  해석 실패는 `unresolved_role` 이슈 + **해당 바인딩을 건너뛴다**(추정하지 않음).
- 지표 포인트는 창 안이어야 하고 `int64Value`가 음수 아닌 정수여야 한다(불리언 거부).
- **`"no_series_means": "unknown_not_unused"`** — 지표가 없다고 미사용이 아니라고
  커버리지 출력에 직접 기록한다.
- 마지막에 모든 엣지에 해당 `coverage_path`의 상태를 `collection_status`로 찍는다.
- `secret_index`: Secret별로 `observed_access` > `policy_possible` > `unknown` 우선순위 판정 +
  `missing_logs_mean: "unknown_not_unused"` + 두 커버리지 상태 인라인.
- `query_secret()`은 짧은 이름이 모호하면 거부한다.

### 2.6 조인 (`linkage.py`)

```
match_service_account_key(inventory, candidate)
  → identifier_match | ambiguous_inventory
  | not_found_in_complete_scope | unknown_in_partial_scope | invalid_candidate
  (validity 항상 "unverified")
```
- `client_email` + `private_key_id`만 읽고 **후보값을 절대 반환하지 않는다**
- 프로젝트는 인벤토리에서 취하고 후보에서 추론하지 않는다
- `match_api_key`: 후보를 Google `keys:lookupKey`에 전송(→ develop의 검증기 스위치 대상),
  `lookup_found_not_in_inventory`까지 구분

### 2.7 ★ 평문 영속화 (차단 항목)

```python
# secret_values.py: {"status": "collected", "value": value}
# watch.py: {"value": value, "value_encoding": "utf-8", "value_kind": "api_key_string"}
```
- 저장 대상: API 키 문자열, SA 공개키, Secret 페이로드(UTF-8 평문 / 바이너리 base64)
- **값 캐싱**: 한 번 읽은 값은 `value_read_status: "cached"`로 재사용되어
  **공급자에서 파기된 뒤에도 상태 파일에 남는다**
- 별도 `secret_values.py`에는 CRC32C, 65536바이트 상한, 비 UTF-8 거부가 있다. watcher는 binary를 base64로도 표현하므로 두 출력 경로를 구분한다.

### 2.8 CLI

`cli`(메타데이터 인벤토리) / `watch_cli`(`--once`, `--interval-seconds`, `--state`, `--max-pages`) /
`relations_cli` / `api_key_cli`(`--source-file`) / `secret_values_cli`.
`Dockerfile.watch` + `compose.watch.yml`(`restart: unless-stopped`).
테스트는 `unittest`(6파일, 796줄).

---

## 3. `develop_github` — G0r4ni8

**구조 정정**: 두 트리는 중복이 아니다. **수집기 코어는 공유하고 오케스트레이션이 두 갈래**다.

| | 공유(blob 동일) | 고유 |
|---|---|---|
| 루트 `cremore_collectors/` | 수집기 8종 + `collectors/__init__.py` + `collectors/_http.py` + `registry.py` | `service.py`, `coordinator.py`, `transport.py`, `auth.py`, `runner.py`, `contracts.py`, `create_service_key.py`, `__main__.py` (MSA 5서비스) |
| `github-api-collector/cremore_collectors/` | 〃 | `cli.py`, `collector.py`, `gateway.py`, `json_pipeline.py`, `json_store.py`, `json_evidence.py`, `json_export.py`, `supplemental.py`, `validation.py` (Enterprise 재개형 JSON CLI) |

11개 파일이 blob 해시까지 동일하고, 각 트리의 고유 모듈 8~9개가 서로 다른 실행 모델이다.
README도 JSON CLI 쪽을 "API 수집 → Audit log 연결 → JSON 저장"의 권장 경로로 안내한다.

### 3.1 수집기 8종 (양쪽 공유)

| kind | endpoint | 핵심 필드 |
|---|---|---|
| `classic_pat` | `/orgs/{org}/credential-authorizations` | `token_last_eight`, `scopes`, `credential_authorized_at`, `credential_accessed_at`, `authorized_credential_expires_at` |
| `oauth_app_token` | 같은 endpoint | `credential_type` 필터만 다름 |
| `github_app_user_token` | 같은 endpoint | 〃 |
| `user_ssh_key` | 같은 endpoint | 〃 |
| `fine_grained_pat` | `/orgs/{org}/personal-access-tokens` (+`-requests`) | `permissions`, `repository_selection`, `token_expired`, `token_expires_at`, `token_last_used_at`, 저장소 목록, 요청의 `reason` |
| `github_app_installation_token` | `/orgs/{org}/installations` | 설치 `permissions`, `events`. **"발급된 토큰 목록이 아님"을 docstring에 명시** |
| `deploy_key` | `/repos/{org}/{repo}/keys` | `verified`, `read_only`, `last_used`, `enabled` + **SSH 지문** |
| `github_token` | Actions 정책 | `default_workflow_permissions`, `can_approve_pull_request_reviews`, `run_workflows_from_fork_pull_requests`, `send_write_tokens_to_workflows`, `require_approval_for_fork_pr_workflows` |

앞의 4종은 **SAML SSO 승인 목록** 하나에서 `credential_type`으로 갈린다. Classic PAT 등의 조직 전수 발급 목록과는 다르며 fine-grained PAT 목록 경로와 구분한다. `github_token.py`는 발급된 토큰이 아니라 **Actions 권한 정책**을
읽는다고 docstring에 명시한다.

### 3.2 SSH 공개키 지문 (`deploy_key.public_key_metadata`)

- `algorithm base64blob` 분해 → base64 디코드(`validate=True`)
- **wire format 내부의 길이 접두 알고리즘 이름이 접두사와 일치하는지 검증**
- `SHA256:` + base64(sha256(blob)), 패딩 제거 → `ssh-keygen -lf`와 같은 값
- 실패 시 `key_metadata_error`를 남기고 나머지 메타데이터는 보존
- **develop에 없는 조인 키.** GitLab 브랜치는 반대로 `public_key`를 버린다.

### 3.3 범위 이탈 방지 (공유 `_http.py` + 각 reader)

- `validate_url(url, path)`이 scheme+netloc+**path**까지 고정 → 페이지네이션이 요청 엔드포인트를
  벗어날 수 없음
- `next_page`가 형식 불량 + **`next` rel 중복(모호)** 도 거부
- fine-grained PAT의 저장소 조회는 응답의 `repositories_url`을 따르지 않고 `id`로 경로를 **구성**
- 저장소 응답은 `owner.login` / `name` 정규식 / `full_name == org/name` 3중 대조
- `allowed_path` 정규식으로 reader별 허용 경로 한정
- `redact(value, token)`이 결과 전체(딕셔너리 키 포함)에서 수집 토큰을 재귀 치환

### 3.4 예산, 중단

- `max_pages` + `max_requests` 공유 예산, `requests_used` 집계
- 레이트 리밋 판정: 429 **또는** 403 + (`x-ratelimit-remaining: 0` 또는 `retry-after`)
- 401, 레이트 리밋 시 `stop_reason` 설정 → 이후 수집기는 `skipped_after_{reason}`으로 건너뜀
- `credential_type_counts`로 **보인 모든 종류의 건수**를 세고 그중 대상만 투영
- 토큰은 `getpass` + `GetPassWarning`을 error로 승격(숨김 입력 불가 터미널이면 실행 거부)

### 3.5 MSA 경로 (루트 트리)

- `contracts.py`: `SCHEMA_VERSION=1`, `MAX_BODY_BYTES=64KiB`,
  `INTEGER_BOUNDS`(max_pages 1000 / max_requests 5000 / run_days 365),
  `validate_job()`이 **비밀, URL, 미선언 옵션을 거부**
- `registry.py`: 고정 어댑터만 해석, 호출자 제공 import 경로 거부,
  `options_for()`가 수집기별 허용 옵션 화이트리스트
- `coordinator.py`: App JWT → Org installation token, "서비스 URL은 관리자 설정이며 사용자
  입력이 아니다", 설치 토큰은 헤더로만 이동
- `service.py`: **"예외를 절대 렌더링하지 않는다 — 서드파티 오류가 자격증명을 품을 수 있다"**,
  `json.dumps(result, allow_nan=False)`로 결과 형태 검증, 내부 bearer 키 32~4096 출력 가능 ASCII
- 5개 서비스: `sso-authorizations`(4종) / `fine-grained-pat` / `app-installations` /
  `deploy-keys` / `actions-context` + `Dockerfile.collectors` + `compose.collectors.yaml`

### 3.6 Enterprise JSON 파이프라인 (`github-api-collector/`)

**`gateway.py`** — GitHub.com 전용 전송. docstring이 금지 목록을 명시한다:
"자격증명 수명주기 변경, 임의 URL, 리다이렉트, 오류 본문 로깅, 환경 프록시,
audit-stream 설정, export-job POST를 일절 허용하지 않는다."
`validate_operation(method, path, enterprise, payload)`로 작업 allowlist.

**`json_pipeline.py`** — 재개 가능한 API→audit 파이프라인. 원자적 JSON 파일만 사용,
`REQUEST_INTERVAL = 2.2`초 페이싱, 작업 트리(`add_tasks`/`refresh`/`open_scan`),
`collect_enterprise(job_id, manager, restart)`.

**`json_evidence.py`** — **자격증명 인벤토리와 감사 로그의 상관분석**. 이 브랜치의 최대 자산.

- `_TOKEN_FIELDS` 약 60개: `credential_state`, `authorization_state`,
  **`effective_access_state`**, `state_reason`, `expiry_status`, `expiry_unknown`,
  **`past_expiration_policy` + `past_expiration_policy_basis`**(근거 필드),
  `never_expires`, `age_days`, `credential_instance_count`, `enterprise_authorized`,
  `authorization_count`, `authorized_organizations`, `public_key_last_used`, `key_algorithm` …
- `_AUDIT_FIELDS` 약 60개: `programmatic_access_type`, `token_id`, `token_scopes`,
  `managed_token_id`, `managed_oauth_access_id` 등과 함께
  **before/after 쌍** — `old_permissions`/`permissions`, `old_scopes`/`scopes`,
  `old_token_expiration`/`token_expiration`, `previous_state`/`new_state`, `old_access`/`access`.
  **감사 로그에서 자격증명 변경 이력을 복원한다.**
- 자격증명 액션 분류: `_CREDENTIAL_ACTION` 정규식(13개 네임스페이스),
  `_FG_ACTIONS`(fine-grained PAT 승인/철회/요청), `_SSO_ACTIONS`(SSO 승인/해제/폐기),
  `_KEY_ACTIONS`(public_key 생성, 삭제, 검증, 검증실패 7종)
- `_TYPE_ALIASES`로 `oauth_app_token`→`oauth_app_user_token`, `user_ssh_key`→`ssh_key` 정규화
- `_safe()`: 깊이 8 제한, dict 1000키, list 10000항목, 문자열 16384자 상한,
  `_SECRET_KEYS` 정규식(`hashed_token`, `pem` 포함) + `{token, app_jwt, key, raw, raw_value}` 차단,
  모든 문자열에 `safe_report`(GitHub 토큰 패턴 스크럽) 적용

**`json_store.py`** — 원자적 JSON 전용("No database, SQL, or hidden database cache"),
`TOKEN_PATTERN`(`gh[pousr]_`, `github_pat_`)으로 보고서에서 토큰 스크럽.

**`validation.py`** — `INVENTORY_FLAGS` **5종 불완전성 플래그**:
`incomplete-results`, `truncated`, `sources-unavailable`, `metadata-incomplete`,
`expiry-incomplete`. + 동일 엔드포인트 페이지네이션 검증.

**`supplemental.py`** — "한 페이지는 증거이지, 조직 전체를 스캔했다는 선언이 아니다."

### 3.7 SQLite 저장, 조회 모듈 (`credential_dashboard/`, 웹 서버 아님)

SQLite: `organizations` / `collection_runs`(`content_hash` UNIQUE, `raw_json`, `complete`,
`interrupted`) / `collection_results`(run×kind) / `collection_checks`(경로별 endpoint,
http_status, records_collected, error_json) / `repositories` / `repository_observations`.
**run → result → check 3계층 부분 실패 기록**은 develop의 커버리지 모델보다 세밀하다.

## 4. `develop_atlassian` — 양승빈_tmp

### 4.1 2계층 구조

| 계층 | 모듈 | 역할 |
|---|---|---|
| discovery | `discovery.py` + `snapshot.py` | **선택, 정규화 전** 공급자 원본을 편집본으로 보존 + 필드 카탈로그 |
| collector | `collector.py` + `metadata.py` + `specs.py` | 문서화 필드만 선택, 정규화 |

### 4.2 수집 소스 (`specs.SOURCES`)

| source | path | kind | 페이징 |
|---|---|---|---|
| `admin-api-keys` | `api-keys` | `admin_api_key` | cursor |
| `org-api-tokens` | `api-tokens` | `api_token` | cursor |
| `service-account-api-tokens` | `service-accounts/api-tokens` | `api_token` | 배열 |
| `service-account-oauth-clients` | `service-accounts/oauth-clients` | `service_account_oauth_client` | 배열 |
| `org-oauth-clients` | `oauth-clients` | `org_oauth_client` | cursor, `epoch_ms`, 배열 변종 허용 |

기본 활성은 앞 3개(`DEFAULT_SOURCES`) — OAuth 두 소스는 "조직 endpoint의 페이지네이션이
아직 미검증"이라 opt-in.

`read_operations.py`에는 위 정규화 source를 포함해 총 17개 명명 작업이 있다: 각종 `count` 엔드포인트(POST 2개는
**카운트만 반환**), `service-accounts`, `service-account-{api-tokens,oauth-clients}-by-account`,
`oauth-client-detail`, `managed-accounts`(`/admin/v1/orgs/{org}/users`),
`user-{management-permissions,profile,api-tokens}`.

### 4.3 편집 (`snapshot.metadata_snapshot`)

- `secret_name()`: 비영숫자 제거 + 소문자화 후 집합 대조 **및 접미사 규칙**
  (`endswith` token/secret/keyvalue/secretvalue/accesstoken, `contains` password/privatekey/clientsecret)
- **JWK 개인 파라미터 차단**: `"kty" in item or parent_name == "keys"`이면 `d,p,q,dp,dq,qi,oth,k` 차단
- **값 레벨 탐지**: `PRIVATE KEY-----`, `PGP PRIVATE KEY BLOCK`, `^\s*(bearer|basic)\s+\S+`,
  호출자가 넘긴 `sensitive_values`(수집기 자신의 토큰)를 이름, 값 양쪽에서 부분 문자열 대조
- **과편집 방지**: `reason.key`가 `MANAGEMENT_REASON_CODES` 8종 문서화 enum이면 보존
- 경계: `max_nodes=100000`, `max_depth=32`, `truncated_nodes` 집계,
  꼬리 마커 `while marker in item: marker += "_"`로 키 충돌 회피
- 필드 이름과 생략 상태는 남기고 값만 `{"_cremore_omitted": "sensitive_value"}`로 치환
- `field_catalog()`: 경로→타입 카탈로그, **JSON Pointer 이스케이프**(`~0`/`~1`)

### 4.4 정규화 (`metadata.normalize`) — 필드별 상태 보존

- 필드마다 **4상태**: `missing` / `null` / `present` / **`invalid_type`**
  (gitLab의 3상태보다 한 단계 더 세분)
- 필드 부류별 타입 검사: `scopes`는 list[str], `epoch_ms` 지정 필드는 int,
  `booleans` 지정 필드는 bool, 나머지는 str. 어기면 `invalid_type` + `invalid_type:{name}` 경고
- 필수 필드가 `missing`/`null`이면 `required_missing:` / `required_null:` 경고
- 시각 필드는 `normalized_utc`를 덧붙이고, 파싱 실패 시 `invalid_timestamp:` 경고.
  ISO와 epoch milliseconds를 spec에 따라 구분 처리
- **변종 판별을 필드 계약으로만 한다.** 조직 OAuth endpoint가 서비스 계정 형태를 반환하면
  `clientName`+`serviceAccount` 대 `name`/`status`/`updatedAt` 존재로 계약을 고르고,
  둘 다면 `ambiguous_oauth_record_contract`. 주석이 **"타임스탬프 크기, 타입으로 고르지 않는다"**
  고 명시한다
- 상태 enum 검증: api_token `ALLOWED/BLOCKED/EXPIRED`, org_oauth_client `ACTIVE/REVOKED/EXPIRED`.
  벗어나면 버리지 않고 `unknown_status:` 경고
- `parent_states` 별도 추적. nullable TokenUser도 객체가 있으면 `id`/`name`을 요구
- 파생값은 `expired_at_observation` **하나뿐**이고, 어느 한쪽이 불명이면 `None`
- `comparison_value()`가 `normalized_utc`를 빼고 `scopes`를 정렬 → 재정규화 잡음이
  거짓 변경으로 잡히지 않게 한다

### 4.5 커버리지 4상태 (`collector.collect_source`)

- `complete` / `partial` / `failed` / **`unverified`**
- `coverage_basis`: `cursor` / `documented_array` / `undocumented_array`
- 카운터 4종: `received_records`, `accepted_records`, `invalid_records`, `duplicate_observations`
- `links` 객체가 없으면 `missing_pagination_contract` **실패**(완료로 간주하지 않음). `links.next`가 없거나 null이면 마지막 쪽이다
  (API Access 문서: 다음 결과가 있을 때만 `next` cursor가 들어 있다)
- cursor: 문자열, ≤8192, 반복 시 `repeated_cursor`
- **`invalid_records`가 있으면 페이지네이션이 끝나도 완료로 올리지 않는다**
- 중복 ID → `unverified` + `duplicate_ids`(조용히 dedup하지 않음)
- 레코드의 org가 조회 org와 다르면 `queried_org_mismatch:{field}` 경고(버리지 않음)
- 예외 시 "예외 텍스트, URL, cursor, 인증을 절대 포함하지 않는다" + 소비한 요청 수는 보정

### 4.5.1 Bitbucket (`bitbucket.py`) — 26개 작업

| 범주 | 작업 |
|---|---|
| 워크스페이스 | `workspace`, `workspace-members`, `projects`, `repositories`, `current-user` |
| GPG | `workspace-gpg-key`(PGP 공개키 번들), `user-gpg-keys`/`-detail`(`fields=+key,+subkeys`) |
| SSH | `user-ssh-keys`/`-detail` |
| Deploy key | `project-deploy-keys`/`-detail`, `repository-deploy-keys`/`-detail` |
| Pipeline | `pipeline-ssh-key`(key_pair), `pipeline-known-hosts`/`-detail` |
| Runner | `workspace-runners`/`-detail`, `repository-runners`/`-detail` |
| OIDC | `workspace-oidc-configuration`, `workspace-oidc-keys`(JWKS) — `public: True` 표시 |

`shape`에 `public_key_bundle`(PGP 블록 형식 검증), `jwks`(`keys` 배열)가 따로 있고,
`snapshot.py`의 JWK, PEM 값 차단이 여기서 실제로 쓰인다.
develop의 Bitbucket 지원은 콘텐츠 수집(③축)뿐이다.

### 4.5.2 HTTP (`http.py`) / 작업 allowlist (`read_operations.py`)

- `BASE_URL = https://api.atlassian.com/admin/api-access/v1`, `MAX_BYTES = 1MiB`
- `Limits` 7개 전부 범위 검증(max_pages 1~1000, max_records 1~100000, max_requests 1~1000,
  retries 0~5, max_seconds 1~600, timeout 0.1~30, max_retry_wait 0~60)
- `NoRedirect`, `RETRY_STATUSES = {429,500,502,503,504}`
- `validate_next_url`: 공백, 제어문자, 역슬래시 거부, ≤8192, 동일 origin + 동일 리소스 경로
- `operation_url`: `{identifier}` 자리에는 `[A-Za-z0-9:|_-]{1,128}`만
- 총 17개 명명 작업 allowlist. POST 2개는 **카운트만 반환**하는 엔드포인트임을 docstring에 명시

### 4.6 식별 제안 (`docs/metadata-contract.md`)

`(provider, environment, queried_org_id, source_kind, provider_id)`.
`source_kind`는 endpoint 이름이 아니라 **객체 종류**. 실측으로 동일 token ID, 동일 user ID가
일반 목록과 서비스 계정 전용 목록 양쪽에 1건씩 나타난 사례를 기록하고, 두 endpoint를 별도
유형으로 세면 중복된다고 결론.

### 4.7 증거 자산

`docs/` 분석 20편 + `docs/evidence/` 실측 JSON 25개(4,068줄짜리 필드 카탈로그 포함).
공급자 명세와 실측의 **모순을 그대로 기록**한다(`keyType` 명세 모순, 실제 누락, 상태 enum
상속 모순, 조직 OAuth의 epoch ms vs ISO 문자열).

저자 명시: **"현재 출력 구조는 이 저장소 내부 계약이며 팀 공통 schema가 아니다."**

---

## 5. `develop_slack` — CreMore Slack Bot

43개 `app/*.py`. 기능군으로 나눈다.

### 5.1 Slack 실시간 (기존 develop의 scope event/schedule 경로에 확장 필요)

| 모듈 | 기능 |
|---|---|
| `socket_mode.py` | Socket Mode 러너. **공개 Request URL 불필요**(인바운드 포트 안 열어도 됨) |
| `main.py` | Events API FastAPI 엔드포인트, `v0=` HMAC 서명 검증 |
| `event_processor.py` | 실시간 이벤트, 과거 backfill 공통 처리 |
| `alert_delivery.py` | 스레드 경보 1건 백그라운드 전송 |
| `slack_client.py` | Web API 클라이언트. "경보 텍스트에 자격증명 값이 절대 들어가면 안 됨" |
| `scan_coverage.py` | backfill 진행 보고(비민감) |

### 5.2 수명주기 원장 (`token_lifecycle.py`)

- **토큰 유형 10종**: `bot_oauth`, `user_oauth`, `app_level`, `workflow`,
  `rotating_bot_access`, `rotating_user_access`, `oauth_refresh`,
  `configuration_access`, `configuration_refresh`, `service`
- **출처 7종**: `oauth.v2.access`, `oauth.v2.exchange`, `tooling.tokens.rotate`,
  `workflow_runtime`, `slack_cli`, `connected_api_check`, `developer_portal_import`
- **상태 12종**: `issued_unverified`, `observed_unverified`, `valid_at_check`,
  `authentication_rejected`, `invalid_at_check`, `verification_failed`, `invalid_format`,
  `not_verified_app_level`, `rotated`, `revoked`, `completed`, `expired_by_time`
- **근거(basis) 필드**: `authorized_user_id_basis`(6종), `issued_at_basis`(2종),
  `expires_at_basis`(3종 — `slack_iat` / `response_expires_in` / `slack_policy_upper_bound`).
  **시각 필드마다 "어디서 온 값인지"를 기록한다.**
- **회전 계보**: `token_family_id` + `rotation_parent_id` → 회전 전후 토큰을 잇는다.
  **develop에 없는 Slack token-family 계보 모델이다.**
- `raw_token`은 즉시 HMAC 지문으로 바뀌고 64-hex id만 저장. 원문은 레코드에 들어가지 않음
- `RLock` + `file_lock.py` 교차 프로세스 잠금
- "알 수 없는 Slack 측 발급자를 지어내지 않는다"

### 5.3 인벤토리 (①축)

| 모듈 | 대상 |
|---|---|
| `known_token_inventory.py` | 이 앱에 **명시적으로 설정된** 토큰만 |
| `slack_admin_inventory.py` | Enterprise 앱 인벤토리. **앱 시크릿을 요청하지 않음** |
| `slack_audit.py` / `audit_monitor.py` | Enterprise 감사 로그(최소 수집 / 지속 감시) |
| `enterprise_collection.py` | 1회성 Enterprise 메타데이터, 인메모리 자격증명 |
| `slack_app_events.py` | 조직 전역 앱 수명주기 관측(allowlist 기반) |
| `slack_snapshot.py` | 관측 결과를 편집된 JSON 1개로 export |
| `security_inventory.py` | Enterprise + Vault 인벤토리 CLI |

### 5.4 금고 (②축)

- `vault_inventory.py`: HashiCorp **Vault KV v2 메타데이터만** 재귀 나열
  (`created_time`, `updated_time`, `current_version`, `oldest_version`, `max_versions`,
  `delete_version_after`). `/data/` 값은 읽지 않음
- `cloud_secrets_inventory.py`: 팀 소유 클라우드 시크릿 메타데이터 어댑터.
  "`get_secret_value`/`access_secret_version`을 호출하지 않으므로 침해된 로컬 대시보드가
  이 수집기로 값을 표시할 수 없다"
- `secret_lifecycle.py`: 메타데이터 기반 정책 평가 → `expired`(critical) /
  `expires_soon`(high, 기본 30일) 경보

> **주의**: develop은 이미 `cremore/coverage/collect.py:collect_kv()`로 Vault/OpenBao KV를
> **값 지문 방식(B안)** 으로 수집하며 `cremore-coverage` 진입점도 있다. Slack 쪽은 C안
> (값 미접근)이라 **노출↔금고 일치 판정을 할 수 없다.** develop 쪽이 이 목적에는 더 강하다.
> Slack의 metadata/lifecycle 정책 필드와 Azure Key Vault metadata 지원도 인수해야 한다. metadata-only 근거는 value match로 바꾸지 않는다.

### 5.5 발급, 회전, 폐기 (쓰기 동작 포함)

- `oauth_capture.py`: OAuth 교환 시점 메타데이터 포착.
  `validate_redirect_uri()`는 HTTPS 또는 **포트가 명시된 localhost**만 허용하고
  userinfo, query, fragment를 거부하며 경로가 `/`로 시작해야 한다.
  자격증명은 HTTP Basic 헤더로 보내고 오류 원문은 `raise ... from None`으로 차단.
  docstring: "OAuth 코드, client secret, access/refresh 토큰이 이 모듈이 반환하는 URL이나
  로그 출력에 절대 들어가면 안 된다."
- `oauth_rotation.py` / `oauth_callback_app.py`: 명시적 refresh, 공개 콜백(로컬 대시보드 비노출)
- `tooling_rotation.py`: configuration token 회전
- `workflow_lifecycle.py` / `workflow_probe.py`: 자체 단기 workflow 토큰 포착,
  전용 테스트 워크플로 단계만 완료 처리
- `token_revocation.py` / `test_user_token_revoke.py`: **실제 폐기 호출**(`auth.revoke`).
  일회용 테스트 토큰을 정확한 ID로만 폐기
- `owned_token_{store,monitor,supervisor}.py`: DPAPI 저장 + 재시작 안전 주기 점검
- import 경로: `configuration_token_import`, `portal_user_token_import`, `service_token_cli`,
  `token_test_bridge`(루프백 전용), `token_transfer_receiver`(stdin)

### 5.6 대응 큐 (`remediation.py`)

공급자별 권장 조치 13종을 매핑한다 — develop에 없는 내용이다.

| credential_type | provider | recommended_action |
|---|---|---|
| `aws_access_key_id` | AWS IAM | `deactivate_then_rotate` |
| `google_api_key` | Google Cloud | `restrict_or_rotate` |
| `stripe_api_key` | Stripe | `roll_key` |
| `database_uri_password` | Database | `rotate_password` |
| `pem_private_key` | PKI | `replace_keypair` |
| github/gitlab/slack/openai/sendgrid/npm/telegram | 각 공급자 | `revoke_and_reissue` |

작업은 `status: "pending_manual_review"`로 큐에 쌓이고 **지문만 저장**한다. 실행하지 않는다.
매핑에 없으면 `("Unknown provider", "manual_investigation")`.

### 5.7 탐지, 저장 (develop과 중복)

- `detector.py`의 16개 규칙과 develop은 서로 완전한 상위/부분집합이 아니다. 합성50개 비교에서 Slack 전용 형식과 rotating token 캡처 차이, develop 전용 webhook을 확인했다. [규칙별 근거](integration/slack.md)와 [비교 결과](integration/passive-detection-comparison.csv)에 따라 둘 다 보존한다.
- `models.py`: `ProcessedEvent` / `Finding`(`credential_findings`) / `SenderMetadata` /
  `AlertDelivery`. `Finding`은 `masked_value` + `fingerprint` + `text_start/end` + `status`로
  **원문을 저장하지 않는다**
- `event_processor.process_message`: 봇, subtype 메시지 제외, **전체 메시지 텍스트 미저장**.
  실시간과 과거 backfill이 같은 메시지에 다른 event_id를 쓰므로
  `(channel_id, message_ts)`로 조인해 `AlertDelivery` 상태가 `queued`/`delivered`면
  중복 경보를 막는다. findings가 지워졌는데 dedupe 원장만 남은 경우 고아 레코드를
  다시 만들지 않는다
- `repository.py`: "마스킹된 표시값과 지문만 받는다"
- `dashboard.py`(67KB, 라우트 20개) + `templates/dashboard.html`: 로컬 전용 FastAPI.
  `_safe_capture_metadata()`가 channel/sender/message/event 4개 섹션의 허용 필드만 통과시키고
  모든 문자열에서 원문을 `[REDACTED]`로 치환

### 5.8 ★ develop과 어긋나는 두 지점

**지문 파생식** — Slack: `hmac.new(hmac_key.encode(), raw.encode(), sha256)` (8개 모듈에서 확인).
develop: `hmac.new(key, b"cremore-credential-fingerprint-v1\x00" + material, sha256)`.
**도메인 구분자가 없어 두 체계의 지문이 맞지 않는다.** 통일 전에는 Slack 탐지 결과를
develop의 노출, 금고 관측과 조인할 수 없다.

**마스킹 폭** — Slack `mask_value()`는 길이에 따라 `≤12` 전체 마스크 /
`<24` → `4+8+2` / `≥24` → `8+8+4`로 나뉜다. **길이 구간이 드러난다.**
develop `mask_hint()`는 고정 폭(`MASK_WIDTH=4`)을 쓰는데, 주석에 "가변 폭 마스크는 길이를
누설한다"고 명시된 의도적 선택이다.

### 5.9 이식 제외 후보

- `plaintext_capture.py` — 스스로 "프로덕션에서 절대 활성화 금지" 경고
- DPAPI 의존 **3개 모듈**(`owned_token_store`, `local_runtime_key`, `local_oauth_config`)
  + `token_test_bridge` — Windows 의존 경로는 Linux Docker/EC2/EKS에 그대로 이식할 수 없으므로 native Windows 도구 및 이행 경로와 구분
  > 정정: `file_lock.py`는 `msvcrt`/`fcntl`로 **크로스 플랫폼**이다. 로컬 파일 인프라 전체가
  > Windows 전용이라는 앞선 서술은 틀렸다.
- 외부 의존성 `slack_sdk` 추가 여부 확인 필요

### 5.10 관측 한계

`slack_audit.is_security_relevant_action()`은 `("app","scope","token","oauth","integration",
"credential","api_key")` 부분 문자열로 감사 액션을 거른다. **걸러낸 액션의 수를 기록하지
않으므로** github의 `credential_type_counts` 같은 "무엇을 안 가져갔는지"가 남지 않는다.
`AUDIT_OVERLAP = 1시간`으로 폴링 간 공백을 방지한다.

## 6. 브랜치 간 수렴

소통 없이 개발했는데 같은 문제를 반복해서 풀었다.

### 6.1 "같은 자격증명이 두 목록에 나타난다"

| 브랜치 | 해법 |
|---|---|
| gitLab | `identity()` 네임스페이스 병합 + 통합 API의 `resource_type`/`resource_id`로 키 재구성 |
| atlassian | `source_kind`를 endpoint가 아닌 **객체 종류**로 정의, 실측 중복 사례 기록 |
| github | SSO 승인 목록 1개를 `credential_type`으로 4종 분기 |

### 6.2 "부재는 완전히 나열된 경우에만 의미"

| 브랜치 | 구현 |
|---|---|
| gitLab | `not_observed` vs `observation_unknown` + `revocation_inferred: False` |
| gcp | `_path_complete()` 부모 경로 재귀 확인 후에만 `no_longer_listed` |
| github | `complete` + `pages_succeeded` + `stop_reason` 전파 |
| atlassian | `invalid_records` 있으면 완료 불가, `missing_pagination_contract` |
| develop(오늘) | `NOT_IN_ACCOUNT` vs `NOT_CHECKED` |

### 6.3 "식별자만으로 조인하되 사용 가능성은 주장하지 않는다"

| 브랜치 | 구현 |
|---|---|
| gcp | `match_service_account_key()` — `validity: "unverified"` 고정 |
| github | `token_last_eight`, SSH `SHA256:` 지문 |
| develop(오늘) | `principal_arn_source: IAM_OWNER_LOOKUP`, 컴포넌트 지문 동등성 |

### 6.4 "관측된 사용과 가능한 접근은 다르다"

| 브랜치 | 관측 | 가능 |
|---|---|---|
| gcp | Cloud Logging `AccessSecretVersion` + Monitoring 요청 수 | 프로젝트, Secret `getIamPolicy` |
| develop | CloudTrail + `GetAccessKeyLastUsed` | `SimulatePrincipalPolicy` |

### 6.5 전송 안전

각 브랜치가 전송 경계를 구현했으나 보장 범위는 다르다. 특히 Slack SDK 경로의 429/요청 예산, 지속 checkpoint를 다른 CLI와 동등하게 보장한다고 할 수 없다. provider별 상세 보고서의 구현 사실을 인수하고 기존 bounded request/task 예산과 연결한다.

---

## 7. develop에 없는 기능 (통합 시 순증)

| 기능 | 출처 | 비고 |
|---|---|---|
| GitLab 10 family 발급 인벤토리 | gitLab | develop의 GitLab은 콘텐츠 수집만 |
| 식별자 네임스페이스 병합 규칙 | gitLab | 통합 API↔단독 API 중복 제거 |
| GCP 발급 인벤토리 + 4종 객체 모델 | gcp | `principal`/`credential`/`vault_item`/`vault_version` |
| GCP `disableReason: EXPOSED / COMPROMISE_DETECTED` | gcp | **공급자가 직접 주는 노출 신호** |
| 자격증명 변화 이벤트 원장 | gcp `watch` | 6종 이벤트, append-only |
| GCP 관계 그래프 | gcp `relations` | 로그, 지표, IAM 3출처, `evidence_class` 3종 |
| 커스텀 IAM 역할 권한 해석 | gcp `relations` | `includedPermissions` 조회 + 캐시, 미해석은 건너뜀 |
| GitHub Org 관리 메타데이터 8분류 | github | installation, 정책 context는 실제 발급 토큰 수와 구분 |
| SSH 공개키 `SHA256:` 지문 | github `deploy_key` | `ssh-keygen -lf`와 동일. develop에 없는 조인 키 |
| GitHub Actions 권한 정책 수집 | github `github_token` | **develop은 문서에만 있고 코드 없음** |
| **감사 로그 ↔ 자격증명 상관분석** | github `json_evidence` | before/after 쌍으로 변경 이력 복원 |
| Enterprise 재개형 스캔 파이프라인 | github `json_pipeline` | 원자적 JSON, 요청 페이싱 |
| 불완전성 플래그 5종 | github `validation` | `incomplete-results`/`truncated`/`sources-unavailable`/`metadata-incomplete`/`expiry-incomplete` |
| run/result/check 3계층 부분 실패 | github `credential_dashboard` | develop보다 세밀 |
| 구조 단위 응답 편집(JWK, PEM, Bearer) | atlassian `snapshot` | develop 마스킹은 줄/값 단위 |
| 필드 카탈로그(JSON Pointer) | atlassian `field_catalog` | |
| 필드 4상태 + 커버리지 4상태 | atlassian | `invalid_type`, `unverified` + `coverage_basis` |
| Atlassian 정규화 5소스, 이를 포함한 17 read operation | atlassian | |
| Bitbucket 26작업(SSH, GPG, deploy, pipeline, runner, OIDC) | atlassian `bitbucket` | develop은 콘텐츠 수집만 |
| 실시간 이벤트 감시(Socket Mode) | slack | Slack Socket 수신은 신규이며 기존 scope event/schedule을 확장. 인바운드 포트 불필요 |
| 토큰 수명주기 원장(10유형, 12상태, basis) | slack `token_lifecycle` | |
| 회전 계보(`token_family_id`/`rotation_parent_id`) | slack | develop에 없는 Slack token-family 계보 |
| 시크릿 수명주기 정책 평가 | slack `secret_lifecycle` | `expired`/`expires_soon` 경보 |
| 공급자별 권장 조치 매핑 13종 | slack `remediation` | |

---

## 8. 현재 근거와 미확인 범위

이 목록의 최초 작성은 정적 조사였다. **2026-09-21 후속 조사에서 그때의 부분 판독을 보완**해 팀원 코드 전체 판독, 원본 오프라인 테스트 500회(고유491개), 합성 비교, 실제 Git 충돌 및 공개 공식 문서 대조를 수행했다. [검증 기록](integration/verification.md)과 [판독 대장](integration/source-inventory.csv)이 현재 기준이다.

공식 문서에 따른 정정은 [공식 문서 대조](integration/official-docs.md)에 모았다. 특히 GCP는 지역 자동 발견, Secret 버전 불변성, GitHub는 Enterprise total_count 부재, 공식 감사 cursor, ghe.com, Bitbucket은 Basic 인증, DC6개 후보, Slack은 team_id, 배포별 rate, Azure 수정/회전 시각 구분을 반영해야 한다.

아직 하지 않은 것은 제품 코드 병합, 통합 테스트, 고객 API 권한 검증, 운영 자료 이행, 실제 배포다. 이 목록의 기능 수는 제품 통합 완료 수가 아니다. 구현 결정은 [읽기 쉬운 통합 설계](INTEGRATION_DESIGN_REVISED.md)를 따른다.
