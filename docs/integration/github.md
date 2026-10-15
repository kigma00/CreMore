# develop_github 전체 읽기 및 develop 통합 사실 보고서

작성 기준: 2026-09-21. 팀원 브랜치 `publish/develop_github`는 **bfb97fb1f6147439904045824fa1a756c2768655**에 고정했다. 비교 기준 `develop`은 **71ea52ad933708b7fb851f590ab7162d7f7ed35f**다. 이하 `GH:`와 `DEV:` 인용은 각각 이 전체 SHA를 뜻하며 `SHA:path:line`로 바로 조회할 수 있다. 체크아웃, 병합, 배포, 외부 API 호출 없이 `git show`로 읽었다.

## 1. 조사 범위와 실제 검증

- 추적 파일 **83개**, Python 파일 **70개**. 총 9,982줄이다.
- blob 기준 **63개 고유 파일**, 고유 Python blob **50개**, 고유 내용 7,585줄을 전부 읽었다. 같은 blob인 20개 파일은 동일성을 Git object ID로 확인하고 원본의 전체 읽기를 재사용했다. 문서→예제/manifest→진입점→호출 경로→모든 테스트 순서로 읽었다.
- 8개 수집기, `collectors/__init__.py`, `_http.py`, registry, 8개 query wrapper, `test_collector_modules.py`가 두 트리에서 바이트 단위로 같다. 나머지 `cremore_collectors` 최상위 모듈은 서로 다른 프로그램이다.
- 임시 추출은 `work/integration-review/github-snapshot/`에만 했다. 실행 자료, 실제 `.env`, PEM, 고객 데이터는 읽지 않았다. 공개 테스트 키 fixture는 테스트 표식 및 내용을 읽되 값을 출력하지 않았다.
- 루트 `python -B -m unittest discover -s tests -v`: **49/49 통과**. JSON 하위 패키지에서 같은 명령: **45/45 통과**. 공통 모듈 테스트 9개가 중복이므로 합산 실행 94개 / 서로 다른 테스트 메서드 85개다. 현재 호스트 Python에서 실행했으며 Docker 재배포 결과라고 주장하지 않는다. GitHub 요청은 FakeOpener/FakeGateway로 대체했고 일부 서비스 계약 테스트만 loopback HTTP를 사용했다.
- 추가 합성 입력으로 4가지 구현 공백을 확인했다: API generated-at 유실, pending PAT context의 최종 export 유실, repository total_count 불일치 미검출, JSON 런타임 workflow runs 미지원. 아래 §7에 소스와 관측값을 적었다.
- 실제 GitHub Enterprise 고객 계정의 권한, endpoint 가용성, 요금제, 대규모 완주, GitHub App PEM으로 인증한 사실은 없다. 후속 조사에서 공개 공식 문서 22개 URL의 관련 API, 권한, 응답 항목을 직접 읽었다. §11과 [GH1–GH4](official-docs.md#github)에 대조 결과를 기록했다.

전체 파일별 blob/read-status는 본문 끝 표와 `source-inventory.csv`에 있다.

## 2. 무엇을 만든 브랜치인가

이 브랜치는 GitHub에서 **자격증명 관리 메타데이터와 감사 이벤트를 수집하는 프로그램**이다. 저장소 파일 본문 유출 탐지기, 노출 토큰의 현재 유효성 검사기, 토큰 발급 대장, 웹 대시보드는 아니다. 실제 프로그램이 두 개 있으므로 둘을 하나로 표현하면 기능을 과장하거나 빠뜨리게 된다.

| 실행 경로 | 실제 진입점/흐름 | 저장/배포 | 기능 경계 |
|---|---|---|---|
| 기존 Org CLI | `run_all.py` → `runner.main` → `run_batch` → `collect_all` → 8개 fetch 함수 | stdout JSON, 내부 DB 쓰기 없음 | Org 한 곳, optional pending requests/run-job. Enterprise/Audit 없음 |
| 기존 MSA 모드 | 동일 runner `--execution-mode services` → `collect_services` → `ServiceClient.collect` → `POST /v1/collect` → `run_job` → 동일 fetch 함수 | 동일 이미지의 5 WSGI 서비스, 동기 HTTP | 서비스별 격리, backpressure, 배치 예산. 영속 큐/재개 없음 |
| 최신 JSON CLI | `github-api-collector/collect.py` → `cli.main` → `Collector` → `collect_enterprise` → `process_page`/`handle_page`/정규화 → `export_evidence` | 단일 프로세스 JSON 파일, OS lock, 페이지 checkpoint, 신규 output 폴더 | Enterprise 인벤토리 + Org 보완 + Audit 상관관계. 기존 MSA/SQLite와 연결되지 않음 |
| 호환성 저장 모듈 | `credential_dashboard.storage.normalize_report(path, original)` 및 `queries.inventory(path, org=None, run_id=None)` | SQLite immutable snapshot | CLI/HTTP 서비스가 직접 부르지 않음. 테스트가 결과 저장 호환성만 증명. 웹 서버가 아님 |

근거: `GH:README.md:9`, `GH:cremore_collectors/runner.py:106`, `GH:cremore_collectors/runner.py:137`, `GH:cremore_collectors/coordinator.py:133`, `GH:cremore_collectors/service.py:18`, `GH:github-api-collector/cremore_collectors/cli.py:58`, `GH:github-api-collector/cremore_collectors/json_pipeline.py:142`, `GH:credential_dashboard/storage.py:105`.

## 3. 수집 기능을 실제 endpoint와 결과 의미로 분해

| 분류 | 실제 구현과 endpoint | 수집 정보 | 통합 후에도 지켜야 할 의미 |
|---|---|---|---|
| Classic PAT | `fetch_classic_pats(org, token, *, max_pages=1000, opener=None)` / `/orgs/{org}/credential-authorizations` | SSO 승인 ID, 원 자격증명 ID, owner login, scopes, 승인/접근/만료 시각, 마지막 8문자 | 개인의 모든 PAT가 아님. suffix는 정확한 식별/전체 fingerprint가 아님 |
| OAuth App user token | `fetch_oauth_app_tokens` / 같은 SSO endpoint | `credential_type == "OAuth app token"` 투영 | OAuth 앱 client secret, 전체 OAuth 토큰 목록이 아님 |
| GitHub App user token | `fetch_github_app_user_tokens` / 같은 SSO endpoint | `credential_type == "GitHub app token"` 투영 | installation token과 다름. 빈 scopes를 권한 없음으로 해석하지 않음 |
| User SSH key | `fetch_user_ssh_keys` / 같은 SSO endpoint | SSH key SSO 승인 metadata, fingerprint | 모든 직원 공개키 인벤토리 아님. 실제 SSH 개인키, repo별 권한 없음 |
| Fine-grained PAT | `fetch_fine_grained_pats(org, token, *, include_requests=False, max_pages=1000, max_requests=5000, opener=None)` / `/personal-access-tokens`, `/personal-access-tokens/{id}/repositories` | token ID와 승인 record ID 구분, owner, permissions, 만료, last-used, repo 범위 | repository 조회 route는 `id`, 장기 token identity는 `token_id`. 승인 대기 요청은 별도 context |
| App installation | `fetch_installation_metadata` / `/orgs/{org}/installations`, `/installation/repositories` | installation, app, permissions, suspension, 수집 토큰 접근 repo | 발급된 installation token 목록 아님. 수집 토큰 repo를 다른 설치에 붙이지 않음 |
| Deploy key | `fetch_deploy_keys` / 설치 접근 repo→`/repos/{org}/{repo}/keys` | ID, title, read_only/enabled, created/last_used, 공개키 알고리즘, SHA256 지문 | 공개키 원문 저장 안 함. SSH wire bytes를 해시. repo+key ID/지문으로 scope 분리 |
| Actions `GITHUB_TOKEN` | `fetch_github_token_context(org, token, *, include_runs=False, run_days=7, max_pages=1000, max_requests=5000, opener=None, now=None)` | 조직/저장소 workflow 기본 권한, Actions 정책, 비공개 repo fork PR 정책; 선택 run/job 컨텍스트 | 발급 토큰 수, 실제 job effective permissions, 토큰 유효성을 확정하지 않음. workflow 실행/log 내용 수집 없음 |
| Enterprise credential inventory | 최신 JSON `process_page(kind=inventory)` / `/enterprises/{enterprise}/credentials` | API가 반환한 credential 및 token_issuer_principal, owner, 권한, state, expiration, 승인 조직 | 추가 종류를 고정 8개로 잘라내지 않음. 코드의 generated/truncated/incomplete header는 관측될 때의 보완 근거이며 공식 필수 계약은 미확인. token issuer principal은 발급 토큰과 분리 |
| Enterprise org/installation context | `seed_org_tasks`, `handle_page` / `/apps/installable_organizations`, `/apps/organizations/{org}/installations`, 접근 repo routes | 설치 가능 조직, 조직별 설치, 설치별 repo, 부여 가능한 repo | accessible_repositories는 실제 grant라고 단정하지 않음 |
| Audit log | `audit_path` / Enterprise audit, 실패 시 Org audit | 기본 최근 180일 `include=web`, credential 관련/사용 hash 있는 이벤트, actor/IP/대상/시각 | Git events 아님. 보존 기간 밖 복구 없음. Org fallback 성공≠기업 전체 audit 완주 |
| Git audit | `git_audit` 작업: `audit_path(..., include="git")` / Enterprise audit | 수집 창의 마지막 7일 clone·fetch·push 중 `hashed_token` 있는 항목의 키 digest `token_activity` 요약 | Enterprise의 `include_audit_events`+`include_provider_hashes` opt-in만. GitHub가 Git 이벤트를 7일만 보관. credential 이벤트·원래 hash로 저장하지 않음 |

수집기 근거: `GH:cremore_collectors/collectors/classic_pat.py:23,40`, `GH:cremore_collectors/collectors/oauth_app_token.py:28,38`, `GH:cremore_collectors/collectors/github_app_user_token.py:28,39`, `GH:cremore_collectors/collectors/user_ssh_key.py:31,40`, `GH:cremore_collectors/collectors/fine_grained_pat.py:204,216`, `GH:cremore_collectors/collectors/github_app_installation_token.py:70,230`, `GH:cremore_collectors/collectors/deploy_key.py:75,115,252`, `GH:cremore_collectors/collectors/github_token.py:344`.

최신 JSON 근거: `GH:github-api-collector/cremore_collectors/json_pipeline.py:81,95,113`, `GH:github-api-collector/cremore_collectors/supplemental.py:53,203,256,270`.

## 4. 인증, 통신, 작업, 이력의 실제 구현

**루트 경로:** PEM 파일과 숫자 App ID→RS256 JWT→`GET /app`, `/app/installations`→사용자가 선택하거나 요청 Org와 일치하는 installation→`POST /app/installations/{id}/access_tokens`. JWT/설치 토큰은 메모리, 토큰은 결과에서 제거. `IssuingSession`이 허용 route, HTTPS host, redirect 금지를 감싼다. standalone `auth.api_request` 자체는 이 guard를 갖지 않으므로 통합 때 이를 직접 네트워크 helper로 노출하지 않는다. 근거 `GH:cremore_collectors/auth.py:47,87,118,201`, `GH:cremore_collectors/runner.py:86,137`.

루트 local 모드는 fetch마다 별도 예산/별도 HTTP다. 네 SSO 수집기의 공유 요청 cache와 집계 예산은 서비스의 `TaskOpener`를 주입했을 때 생긴다. `collect_all`은 `opener`를 주입하지 않는다. `TaskOpener`는 GET/API host/token scope 고정, 응답 8MiB, cache 32MiB, 240초 협력 deadline, 물리 요청 최대 5,000; 같은 job 안에서만 응답 재사용. 서비스는 body 64KiB, 명시 schema/options, 중복 JSON key/NaN 거부, service bearer 검증, 단기 token 별도 header, 동시 작업 기본 1, 과부하 503. 전체 metadata 예산은 기본 5,000이며 인증 요청은 제외. timeout은 취소가 아니므로 미확정 allocation을 차감하고 자동 재시도하지 않는다. 근거 `GH:cremore_collectors/runner.py:106`, `GH:cremore_collectors/transport.py:59,111`, `GH:cremore_collectors/service.py:113`, `GH:cremore_collectors/coordinator.py:161`.

**최신 JSON 경로:** Enterprise별/Org별 installation lookup에서 target type/account/app ID/suspended 상태를 검증하고 단기 토큰을 발급한다. Org는 별도 설치가 있어야 한다. cache 최대 16 scope, 실제 만료 120초 전/최장 2,400초 갱신. 2.2초 pacing, 실행당 기본 1,000 HTTP attempts/1,800초(인증 포함), rate limit `retry_at` 영속화, token/PEM 영속화 안 함. 허용 GET route와 설치토큰 POST만 존재하며 환경 proxy를 신뢰하지 않고 redirect를 거부한다. `api.github.com` 고정, API version `2026-03-10`. 팀원 구현의 GHES 및 `*.ghe.com` 요청은 현재 미지원이다. ghe.com은 공식 Cloud 주소가 있으므로 provider 미지원이 아니라 host 이식 공백이다. 근거 `GH:github-api-collector/cremore_collectors/gateway.py:45,106`, `GH:github-api-collector/cremore_collectors/collector.py:40,68`, `GH:github-api-collector/cremore_collectors/json_pipeline.py:155,164`.

스캔 상태는 같은 Enterprise/App 및 같은 options에서만 재개된다. UUID scan 디렉터리 아래 JSON 페이지를 fsync 후 atomic replace하고 checkpoint를 다음에 전진시켜, checkpoint 쓰기 직전 장애는 저장된 페이지 재처리로 복구한다. API 수집 priority 10/20/50 후 audit 80/90. 완료한 Enterprise audit만 Org audit fallback을 `covered_by_enterprise`로 표시한다. `--new-scan`은 이전 이력을 지우지 않는다. export는 새 폴더만 허용하고 `summary.json`을 완료 표식으로 마지막에 쓴다. 모든 저장 scan의 evidence를 메모리에 다시 구축하므로 데이터 규모에 비례한 메모리/파일 수 한계가 있다. 자동 scheduler/영속 분산 큐/여러 worker lease/전역 installation limiter는 없다. 근거 `GH:github-api-collector/cremore_collectors/collector.py:11`, `GH:github-api-collector/cremore_collectors/json_store.py:62`, `GH:github-api-collector/cremore_collectors/json_pipeline.py:56,203,210,230`, `GH:github-api-collector/cremore_collectors/json_export.py:21,37`.

Docker는 **기존 루트 MSA만** 패키징한다. Python 3.12 slim, uid 10001, read-only FS/tmpfs/cap_drop/no-new-privileges, 5개 내부 서비스에 공개 host port 없음, Coordinator에만 App PEM secret. JSON CLI는 이 Docker 이미지로 배포되지 않는다. DB/기존 dashboard는 compose에 없다. `GH:Dockerfile.collectors:7`, `GH:compose.collectors.yaml:3,49,80`.

## 5. 식별, 상관관계, 상태 의미

최신 JSON은 metadata allowlist를 투영하고 원 토큰, 원 token hash, PEM을 보관하지 않는다. `normalize_inventory`의 식별자는 종류/enterprise 범위로 구분한다. PAT/user-token 계열은 `credential_id`, user SSH는 지문, deploy key는 repo+ID/지문, installation은 org+installation, policy는 org+repo. 안정 식별자가 없으면 `scan_id`에 종속된 identity다. 응답의 `inventory_id`는 cross-scan identity가 아니다. 근거 `GH:github-api-collector/cremore_collectors/json_evidence.py:189,227`.

Audit 관계는 `used_by`와 `target`을 구분한다. `hashed_token`은 사용 주체이고, Fine-grained PAT의 `user_programmatic_access_id`/SSO `managed_hashed_token`/정확한 SSH 지문은 지원 이벤트에서만 target이다. 이벤트 종류, 조직, repo에 맞는 match key 후보가 정확히 하나일 때만 연결한다. 이름, owner, 시간, 통상 `token_id`만으로 대상에 연결하지 않는다. raw hash는 enterprise scope를 붙여 SHA256 재해시하지만 **HMAC이 아니다**. `GH:github-api-collector/cremore_collectors/json_evidence.py:110,160,368`.

이 엔진은 **metadata↔audit 매칭만** 수행한다. develop의 노출 fingerprint↔GitHub inventory 매칭 구현은 없다. Classic PAT `token_last_eight`를 정확 match key로 쓰는 코드도 없다. suffix를 설계에서 정확한 매칭 근거로 승격하면 안 된다. 현재 JSON `_TOKEN_FIELDS` whitelist에는 suffix도 없어 최종 JSON에서는 제거된다. `GH:github-api-collector/cremore_collectors/json_evidence.py:11,241`.

API 상태와 audit 사건은 나란히 남긴다. 조직 접근 revoke가 token 자체 삭제/만료를 뜻하지 않고, audit actor가 owner를 뜻하지 않는다. 최신 수집에서 안 보인 entity도 과거 관찰로 남고 absence로 삭제하지 않는다. 설치/정책은 실제 토큰 수로 집계하지 않는다. 근거 `GH:github-api-collector/cremore_collectors/json_evidence.py:382`, `GH:github-api-collector/cremore_collectors/json_export.py:49`, 테스트 `GH:github-api-collector/tests/test_json_pipeline.py:62,241,273`.

## 6. develop와 충돌, 중복, 추가점: 실제 연결 위치

| 경계 | develop 구현 | 팀원 우선으로 가져올 기능 | 통합 요구 |
|---|---|---|---|
| 콘텐츠 vs 인벤토리 | `build_collector`→`GitHubCollector`/`GitHubOrgCollector`→`CollectedObject`→`ScanService`→`Orchestrator.scan_resource`; 파일 내용과 노출을 생성 | Enterprise/Org 자격증명 관리 인벤토리, audit, 설치/정책 context | 메타데이터를 파일로 직렬화해 Engine에 보내거나 기존 content collector를 교체하면 안 됨. 별도 인벤토리 job과 typed 결과 모델 필요 |
| `github-org` 명칭 | `job_kind_for(conn)`이 org 전체 **콘텐츠** 스캔에 이미 반환; `factory.py:88`에 실제 구현 | 팀원 조직 인벤토리 | 같은 job-kind를 metadata 의미로 재정의하면 기존 연결 재실행이 깨짐. 기존 alias 의미 유지하고 명확히 다른 inventory task capability 사용 |
| App 인증 | `GitHubAppTokenSource(client_factory, app_id, installation_id, private_key_base64, *, base_url, now)`와 callable token, 만료전 갱신 | enterprise/org installation discovery 및 App/account scope 검증 | auth/token 보관은 기존 resolver/sealed boundary, scope discovery/검증은 팀원 로직. token 발급 API version/host를 capability별로 명시 |
| 비밀 보관 | connection config에 secret 금지, `vault://` 및 `sealed:v1` worker resolve. App fields는 Vault에서 읽을 수 있음 | 파일 PEM을 직접 읽는 CLI | 웹 입력에 PEM path를 무작정 추가하지 않음. 메모리 App credential provider를 재사용; 현재 `seal_token`은 token만 지원하므로 App bundle 암호화/onboarding은 별도 명시 구현 필요 |
| 호스트 | `normalize_host`, `api_base`: github.com/GHES `/api/v3`/ghe.com `api.*`; connection payload로 전달 | public GitHub inventory/audit | 콘텐츠 enterprise 지원을 제거하지 않음. metadata capability를 host/edition/API version별로 제한, unsupported와 denied 구분. 문자열 host만 바꿔 GHES도 된다고 표시 금지 |
| Coverage 계약 | `ConnectionSpec.provider`는 AWS IAM/CloudTrail/SM/SSM/Vault/OpenBao/GCP-SM만 허용. `Observation`은 VALUE/IDENTIFIER/ISSUED/USAGE 등 평면형 | permission 구조, API observation, audit relation, installation/policy/request context | 현재 모델에 쑤셔 넣으면 정보 손실. versioned provider metadata schema + 기존 bounded submission/connection authorization 패턴 확장 필요 |
| Coverage 의미 | HMAC fingerprint equality, issuer ID와 vault VALUE 분리. `aws_iam/aws_cloudtrail`만 issuer로 분류 | metadata/audit rehashed SHA256 | 해시 체계가 다르므로 그대로 비교 금지. GitHub를 provider 목록에만 추가하면 vault로 오분류되므로 issuer/context capability도 확장 |
| DB | 기존 repository SQL/in-memory 및 migration, finding/exposure/verification continuity | JSON immutable observation/checkpoint/audit/link 모델, SQLite snapshot 호환 | 테이블명 `credentials` 충돌, 서로 다른 identity 의미. teammate SQLite schema를 기존 DB에 직접 실행 금지. typed inventory/observation/event/link를 기존 persistence 계층에 추가하거나 명시 import 경로 설계 |
| UI/API | Admin source connection, Analyst content scan/credential check; existing coverage 화면은 보관대조. `/coverage/.../collect`는 AWS만 | GitHub inventory/contexts/audit/coverage 뷰와 실제 실행 버튼 | 기존 dashboard 안에 기능별 탭/목록으로 노출. token inventory 상태, scanner auth, 노출 verification 세 축 분리. revoked connection 숨김/감사 이력 정책 유지 |
| 리스크/조치 | 실제 exposure 기반 위험, 저장 검증 이력. rotation 실행 경로는 AWS 중심 | 기간, 권한, last-used metadata, metadata 위험 signal | 단순 inventory row를 유출 finding으로 만들지 않음. 새로운 metadata 위험 signal은 근거/시각과 분리 표시. GitHub revoke/rotate는 팀원에도 구현 안 되어 있어 자동 버튼을 만들 근거 없음 |

핵심 근거:

- `DEV:cremore/collectors/github.py:67,155,225,357`: pinned commit/tree, scope paths, repo visibility, lazy blob, request budget, truncated tree fallback. commit history 전체 탐색은 구현되어 있지 않다.
- `DEV:cremore/collectors/github_archive.py:81`: public GitHub archive는 pinned tree blob hash로 확인하고 실패시 blob API fallback. enterprise에서 archive 최적화는 사용하지 않는다 (`github.py:256`).
- `DEV:cremore/domain/connections.py:35,86,113`; `DEV:cremore/worker/factory.py:25,74,88,170`; `DEV:cremore/scanning/service.py:51`; `DEV:cremore/scanning/orchestrator.py:145`.
- `DEV:cremore/github_auth.py:67,160`; `DEV:cremore/github_hosts.py:24,49`; `DEV:cremore/secretstore/resolver.py:49,78`; `DEV:cremore/secretstore/sealed.py:47`.
- `DEV:cremore/coverage/models.py:64,150,198,230`; `DEV:cremore/coverage/correlation.py:16,59,79,132`; `DEV:cremore/api/coverage.py:70,84,189`.
- `DEV:cremore/api/dashboard.py:1160,1210,1238`는 실제 source onboarding/scan/connection-auth endpoint이며 GitHub Enterprise credential-inventory endpoint가 아니다.
- `DEV:web/app/provider-registry.ts:37`는 content provider descriptor. `DEV:web/app/connection-ui.tsx:40`에는 `github-org`를 metadata inventory라고 설명하는 문구가 있지만, backend source capability에는 `github-org` 등록이 없고 worker의 그 job-kind는 content scan이다 (`DEV:cremore/api/dashboard.py:113`, `DEV:cremore/worker/factory.py:88`). UI copy 존재를 구현 근거로 삼으면 안 된다. `connection-ui.tsx:39`의 wiki/Gist/issue/PR 설명도 현재 native `GitHubCollector`의 범위 증거가 아니다.
- `DEV:cremore/collectors/credential_check.py:54`는 scanner 연결 credential의 `/user` 또는 installation repo 응답을 확인한다. 이것은 수집한 모든 credential의 유효성을 검사했다는 의미가 아니다.
- `DEV:cremore/domain/credential_semantics/reviewed.json:70`는 기존 `GITHUB_TOKEN` subtype이 저장되지 않아 ambiguous임을 선언한다. teammate 종류를 가져오더라도 기존 exposure에 근거 없는 subtype을 소급 채우지 않는다.

## 7. 팀원 기능 우선 적용과 동시에 고쳐야 할 명확한 공백

아래는 팀원 기능을 버릴 이유가 아니라 통합 과정에서 기능을 보존, 완성할 정확한 요건이다.

1. **두 패키지 이름 충돌:** root와 하위 폴더 모두 `cremore_collectors`다. 동시에 Python path에 두면 어느 runtime이 import되는지가 working directory에 따라 바뀐다. 중복 20 blob은 공통 구현 하나로 모으되 CLI/서비스/JSON contracts는 유지해야 한다. `GH:README.md:14`, registry dynamic import `GH:cremore_collectors/registry.py:25`.
2. **context의 최종 산출물 유실:** `process_page`는 `contexts`를 보존하지만 `EvidenceIndex.add_page`는 api_records/audit_events만 읽는다. pending requests, unknown SSO, 부여 가능한 repo context는 최종 6 JSON 파일에 별도 표출되지 않는다. 합성 pending request page에서 `contexts=1`, index credentials=0, `hasattr(index,"contexts")=False`. 통합 DB/API/UI는 이 context도 저장/조회해야 한다. `GH:github-api-collector/cremore_collectors/supplemental.py:216,229,276`, `GH:github-api-collector/cremore_collectors/json_pipeline.py:104`, `GH:github-api-collector/cremore_collectors/json_evidence.py:346`, `GH:github-api-collector/cremore_collectors/json_export.py:42`.
3. **generated-at 보존 누락:** `_inventory_headers`가 generated-at를 검증/파싱하지만 `process_page`가 warnings만 복사한다. 합성 valid generated-at는 반환 page에 남지 않았다. 관측된 서버 snapshot 기준시각과 로컬 관측시각을 별도 저장해야 한다. 이 custom header의 공식 필수 제공 계약은 확인되지 않았으므로 header가 있는 경우의 전달 공백이다. `GH:github-api-collector/cremore_collectors/validation.py:42`, `GH:github-api-collector/cremore_collectors/json_pipeline.py:115`.
4. **Org 총수 완주 근거 부족:** root deploy/install/Actions 수집은 total_count와 누적 row 수를 확인하지만 JSON supplemental `_rows`는 dict에서 list만 꺼내며 total_count를 보존/검증하지 않는다. `{total_count:20,repositories:[]}`가 오류 없이 terminal page가 되고 `records_seen=1`(dict를 1로 셈)이었다. 결과 개수, page 개수, 완주 판정을 구분하고 total/duplicate IDs를 검사하는 root semantics를 합쳐야 한다. `GH:github-api-collector/cremore_collectors/supplemental.py:94`, `GH:github-api-collector/cremore_collectors/json_pipeline.py:112,225`, `GH:cremore_collectors/collectors/deploy_key.py:207,242`, `GH:cremore_collectors/collectors/github_app_installation_token.py:222`.
5. **Actions run/job 기능을 잃을 위험:** root는 optional runs/jobs를 수집하지만 JSON CLI에 include-runs 옵션과 gateway route가 없다. 합성 `validate_operation`은 runs route를 `unlisted_read_endpoint`로 거부했다. JSON 경로를 선택하더라도 팀원 root의 이 기능은 보존 항목으로 따로 옮기거나 선택기능으로 명시해야 한다. `GH:cremore_collectors/collectors/github_token.py:409`, `GH:github-api-collector/cremore_collectors/cli.py:21`, `GH:github-api-collector/cremore_collectors/gateway.py:61`.
6. **partial key metadata 손실:** deploy_key projector가 malformed public key를 `key_metadata_error`로 남기지만 JSON `_TOKEN_FIELDS`가 이를 포함하지 않는다. root는 이런 key를 collection incomplete로 계산한다. JSON는 정규화 후 gap 이유와 incomplete 의미가 사라질 수 있다. `GH:cremore_collectors/collectors/deploy_key.py:75,244`, `GH:github-api-collector/cremore_collectors/supplemental.py:246`, `GH:github-api-collector/cremore_collectors/json_evidence.py:11`.
7. **host/tenant identity 경계:** teammate UID는 enterprise slug/kind/key로 생성하며 GitHub host 또는 CreMore tenant/connection이 없다. public .com 단독 파일 scope에서는 동작하지만 다중 instance 지원시 동명 enterprise/동일 숫자 ID 충돌 방지 차원을 추가해야 한다. 보안담당자 로컬/EC2/EKS 모두 기존 DB owner/lease 권한과 묶어야 한다. `GH:github-api-collector/cremore_collectors/json_evidence.py:242`, `GH:github-api-collector/cremore_collectors/json_pipeline.py:60`.
8. **검증 및 발급/보관대조와의 연결은 신규 작업:** root/JSON 어디에도 저장소 content scanner, webhook receiver, exposure detection, risk engine, credential revoke/rotate API, frontend가 없다. `credential_dashboard` 명칭이나 `GitHub token context` 명칭으로 구현되었다고 표시하지 않는다. metadata state를 기존 verification record로 쓰면 세션/이력 무결성이 깨진다.
9. **배포 이행:** 기존 서비스 5개와 신규 JSON pipeline을 모두 운영 배포에 추가하는 것은 현재 구조의 필수 조건이 아니다. 기본 통합 실행은 기존 worker/job/persistence boundary를 사용할 수 있고, 서비스 격리가 필요하면 root service 모드를 옵션으로 유지할 수 있다. 어떤 선택이든 root run/job 기능, JSON 재개, strict matching, contexts는 기능 인수표에서 누락 없이 보존해야 한다. 파일 checkpoint만 EKS 여러 replica가 동시에 접근하도록 올리는 것은 현재 OS lock/단일 writer 가정과 맞지 않는다.

## 8. 실제 존재하는 API와 복사할 소스 위치

다음은 구현 시 존재한다고 가정해도 되는 **현재 API**다. 다른 inventory endpoint나 generic adapter는 현재 존재하지 않는다.

```python
# GH:cremore_collectors/registry.py:25,33
get_collector(kind)
options_for(kind, options)

# GH:github-api-collector/cremore_collectors/supplemental.py:53,163
seed_org_tasks(enterprise, org)
handle_page(task, items_or_dict)

# GH:github-api-collector/cremore_collectors/json_evidence.py:227,264,316
normalize_inventory(enterprise, scan_id, items, observed_at, source='enterprise_inventory')
normalize_report(enterprise, scan_id, report, observed_at)
normalize_audit(enterprise, items, observed_at, source_endpoint)

# GH:github-api-collector/cremore_collectors/json_pipeline.py:142
collect_enterprise(job_id, manager, restart=False)

# DEV:cremore/github_auth.py:70
GitHubAppTokenSource(client_factory, app_id, installation_id, private_key_base64,
                     *, base_url='https://api.github.com', now=None)

# DEV:cremore/secretstore/resolver.py:49
inject_secret(kind, payload, resolver, *, github_client_factory=None)
```

복사/재사용할 패턴은 metadata projection+exact-match (`GH:github-api-collector/cremore_collectors/json_evidence.py:160,189,227,368`), bounded page adapter (`GH:github-api-collector/cremore_collectors/supplemental.py:53,123,163`), checkpoint commit ordering (`GH:github-api-collector/cremore_collectors/json_pipeline.py:210`), 저장 권한/감사/범위검사 submission (`DEV:cremore/api/coverage.py:189` 및 `DEV:cremore/coverage/store.py:176,222,251`), auth resolver (`DEV:cremore/secretstore/resolver.py:78`), 기존 source UI evidence continuity (`DEV:web/app/connection-ui.tsx:69,76`)다. 마지막 coverage store의 함수 위치는 signature 검색으로 확인했고 구현 전체 읽기는 주 조사 담당으로 남긴다.

## 9. 통합 인수 게이트

1. **기능 인수표:** 8개 Org 종류, pending requests, optional Actions runs/jobs, Enterprise 추가 종류, installations/policies/repo contexts, API→audit 순서, exact used_by/target, unmatched, checkpoints/re-export를 fixture별로 보존한다. 테스트는 49+45 원본 계약을 새 namespace에 연결해 유지한다.
2. **기존 콘텐츠 회귀:** 같은 repo/ref/path의 `GitHubCollector` 결과, pinned archive fallback, request cap, lazy cache, partial/reconcile, saved verification가 바뀌지 않는다. 기존 `github-org` job payload replay는 콘텐츠 스캔이다.
3. **정확한 identity:** host+installation/enterprise namespace, PAT record ID≠token ID, user SSH≠deploy key, installation/policy/request≠발급 토큰, raw hash≠HMAC, suffix-only 관계≠exact match, 이름/owner/시간의 우연 일치≠target을 각각 증명한다.
4. **정직한 coverage:** denied/404/rate-limited/truncated/unknown/gap을 0건 성공으로 합치지 않는다. total_count 불일치, 중복 ID, generated-at 이상, disabled/freshness/scope 변경을 표출한다. Org fallback으로 Enterprise 완료를 선언하지 않는다.
5. **신뢰 경계:** App credential은 config/job/log/API response에 평문 저장하지 않는다. 인벤토리/audit API는 declared host/scope만 호출하고 lifecycle 쓰기 함수는 포함하지 않는다. 기존 Admin/Analyst/Viewer와 machine token ownership을 유지한다.
6. **DB/API/UI:** context도 import/export round-trip에서 사라지지 않는다. metadata observation/현재성, scanner auth, exposure validation을 별개 필드와 시각으로 보여준다. 페이지네이션/long path/한영/좁은 화면 및 실행 중 취소/재개 상태를 확인한다. DB migration rollback은 기존 findings/audits/connections를 그대로 보존한다.
7. **운영:** EC2 단일 worker와 EKS 동시 worker에서 한 inventory 작업을 중복 실행/덮어쓰기 하지 않는다. restart/retry-at/lease 만료/partial 저장의 재시도 중복을 확인한다. 5-service 모드를 유지하는 경우 TLS/개별 service budget/timeout 미확정 처리도 보존한다.
8. **외부 제공자 검증:** 별도 승인된 staging GitHub.com Enterprise에 대해 각 endpoint/API version/permission을 fixture와 대조한다. ghe.com은 공식 Cloud 계약을 바탕으로 host 이식, fixture, 시험 gate를 둔다. GHES metadata는 설치 버전별 계약 확인이 남았다고 표시한다. 이번 오프라인 테스트 통과만으로 해당 서비스의 지원을 선언하지 않는다.

## 10. 신뢰도와 남은 정보

브랜치 코드, 테스트의 존재/호출/저장/계약에 대한 신뢰도는 높다. 83개 전체 파일을 확인했고 두 테스트 경로를 실행했다. 기존 develop 비교는 위 인용한 GitHub collector/auth/host/resolver/scan/coverage model/correlation를 전체 읽고, API/UI/semantics의 관련 구간을 읽었다. develop 전체 소스, 모든 팀원 브랜치와의 DB/UI 종합 충돌은 주 조사 범위다. Git tree 병합 충돌도 주 조사에서 수행한 merge-tree 결과를 사용해야 하며 단순 README 충돌이라고 가정하지 않는다.

공개 공식 문서의 해당 API, 권한, 응답, 버전을 후속 대조했다. 실제 고객 API 응답은 확인하지 않았으므로 고객별 가용성, 권한, 라이선스와 GHES 버전별 계약은 별도 검증으로 남긴다. "기관 전체의 모든 발급 토큰"이나 "현재 활성 인증 확인" 또는 "모든 이벤트의 정확 매칭"을 보장할 수 있는 구현은 아니다.

## 11. 공식 문서 대조로 확정, 정정한 내용

[공식 근거 GH1–GH4](official-docs.md#github)는 2026-09-21 공개 문서, 응답 schema를 직접 읽은 결과다.

1. **Enterprise에는 total_count가 없다.** §7의 총수 보완은 그 필드를 제공하는 Org installations/repositories/Actions에 적용한다. `inventory_id`는 응답 간 바뀔 수 있으므로 안정 identity로 삼지 않는다.
2. **감사 페이지 추가 공백:** 공식 예시의 `after=<cursor>&before=`가 현재 `next_path`에서 거절된다(`GH:github-api-collector/cremore_collectors/validation.py:99`). 순수 함수 두 입력 비교로 확인했다. 빈 반대 cursor만 정규화하고 host/경로/동일 기업 검사는 유지한다. 이 비교는 앞선 94개 실행과 별도다.
3. **기업 인증 구분:** Enterprise installation token에는 repository 접근이 없다. Org 단독 모드를 유지하고 enterprise/org 설치를 기능별로 연결한다. API `2026-03-10`은 공식 지원 버전이다. 기존 콘텐츠 client 전체를 일괄 변경할 이유는 없다.
4. **감사 인증 문서 상충:** endpoint 상단은 classic-only, 같은 페이지의 권한 표는 App token과 Enterprise administration read를 안내한다. 승인 시험 tenant 검증을 남기며 팀원 경로를 임의 제거하지 않는다. 현재 코드는 include=web이고 API 자체에는 git/all도 있다.
5. **host 지원 구분:** ghe.com은 공식 `api.SUBDOMAIN.ghe.com` 주소를 확인했다. 팀원 public-host 고정을 고치는 구현이 필요하다. GHES 동일 inventory 문서404만으로 API 미존재를 단정하지 않는다.
6. **기능 인수 범위:** 승인 요청, 선택 항목, root Actions run/job을 보존한다. 공식 runs 필터 검색은 최대 1,000개이며 현재 코드는 관찰한 attempt의 jobs만 수집한다. 감사의 수행 토큰과 사건 대상 토큰도 서로 다른 관계로 저장한다.

공개 공식 문서 확인과 고객 API 성공은 다르다. Custom inventory header의 필수 계약, Git token-hash 검색 범위, GHES 버전별 metadata는 미확정이다.

## 부록: 전체 파일 읽기 인벤토리

아래 표는 자동으로 검증한 pinned Git blob ID와 읽기 상태다. `FULL`은 전체 내용을 읽었고 `SAME`은 같은 blob인 다른 경로의 전체 읽기 및 바이트 동일성 확인으로 대체했다. fixture는 공개 테스트용 값의 출력만 생략했다.

| 경로 | blob | 줄 | 읽기 상태 |
|---|---|---:|---|
| `.dockerignore` | `89ded83caf8b91b92df0639626d1c15936f012f8` | 24 | FULL |
| `.gitignore` | `508e82d3e861800608d9dfd9628143111e0dc40c` | 23 | FULL |
| `Dockerfile.collectors` | `3ae0e07467ae6ef951d149dbf233fa9b0ce7b326` | 13 | FULL |
| `README.md` | `1c9ae032562d90bf616681de9611b7d43c39e74b` | 241 | FULL |
| `compose.collectors.yaml` | `8a07927aa954407b3afd612891a2361bc6aaae1f` | 84 | FULL |
| `config/collectors.services.json` | `f17c0c0745a5a60ce53217fa1f886bbb6c93df69` | 10 | FULL |
| `credential_dashboard/__init__.py` | `02c959d5de38e7e4dd1bb4e4b060b007b7ca9e65` | 1 | FULL |
| `credential_dashboard/queries.py` | `18a801856958c8e9aeb6438f77b8d803f960682e` | 99 | FULL |
| `credential_dashboard/schema.sql` | `79ab8f26b6926c70fb50e48d4ba1f98fd9331a39` | 80 | FULL |
| `credential_dashboard/storage.py` | `e501b9ce02e8f2a93062856b266fef6aec7f1a41` | 247 | FULL |
| `cremore_collectors/__init__.py` | `15abd03b8bb4e5aa9da5c6aabc5090d24b055ed6` | 3 | FULL |
| `cremore_collectors/__main__.py` | `1a695ba849ae82b602d2b2658f46f31fd580f5b0` | 3 | FULL |
| `cremore_collectors/auth.py` | `ff9c76d12b8a35efe32326708ccd6921c58368e4` | 215 | FULL |
| `cremore_collectors/collectors/__init__.py` | `0b372c3beaef656c4cc8a0e750e0419d7c03cd56` | 5 | FULL |
| `cremore_collectors/collectors/_http.py` | `9b714a2ea68c669c78f05bf29be71c7ed84a8b36` | 62 | FULL |
| `cremore_collectors/collectors/classic_pat.py` | `206df480e5af672bdd0f55e4e85041d1f1e6c05d` | 157 | FULL |
| `cremore_collectors/collectors/deploy_key.py` | `80b7f6a333da7a164303ea1c654c0330675dbad4` | 306 | FULL |
| `cremore_collectors/collectors/fine_grained_pat.py` | `6df2173cc00e76de2093554600345be30b41e262` | 291 | FULL |
| `cremore_collectors/collectors/github_app_installation_token.py` | `1bd4e2d8137c477d799577874eb59381430e0487` | 279 | FULL |
| `cremore_collectors/collectors/github_app_user_token.py` | `8a7422374b8473b27e49a5e8aaea0d08eedf3e6f` | 171 | FULL |
| `cremore_collectors/collectors/github_token.py` | `d19f36afe5143dc7aba590003df4f2b9d0ef51ce` | 461 | FULL |
| `cremore_collectors/collectors/oauth_app_token.py` | `9024535d896d08cee7de036494694fec37328700` | 170 | FULL |
| `cremore_collectors/collectors/user_ssh_key.py` | `2c52d5a6a71245c678f7cf43c09eb0f66c96068d` | 166 | FULL |
| `cremore_collectors/contracts.py` | `5f6d6fc75269ed7593f9d7ea274f9809f026fd6a` | 62 | FULL |
| `cremore_collectors/coordinator.py` | `0e34efefc47355550c614e4acb9952f4068a6ab8` | 196 | FULL |
| `cremore_collectors/create_service_key.py` | `c092e9dda0524e92b8aaaabab0b9b843f7e2760f` | 24 | FULL |
| `cremore_collectors/registry.py` | `35a6f6b362ada70b3db509d01e434bbab51dc709` | 43 | FULL |
| `cremore_collectors/runner.py` | `0c9a460d8c4191126c85bf197beba3cdebcbce35` | 298 | FULL |
| `cremore_collectors/service.py` | `b0a4a881b767838bf5cac92e653f2e827ac4e784` | 169 | FULL |
| `cremore_collectors/transport.py` | `3d98f517433df1c1b1bcb17e23f9b9efaf7a3bef` | 161 | FULL |
| `github-api-collector/.gitignore` | `84a04a0074ef1ba91d6d4130ed9728c26fa797e8` | 9 | FULL |
| `github-api-collector/README.md` | `796f15abcea1b54c27a2f4c7e24bea9dcb158533` | 218 | FULL |
| `github-api-collector/collect.py` | `d28079f0815d9088b75bab120b86c7c9295cfab4` | 5 | FULL |
| `github-api-collector/cremore_collectors/__init__.py` | `fc5e70a56f24318967ae9d33f3a39e1e8c64ca2d` | 3 | FULL |
| `github-api-collector/cremore_collectors/cli.py` | `4fd10a1ebaf5947bfc4cb6c7b7aa2f669540092f` | 88 | FULL |
| `github-api-collector/cremore_collectors/collector.py` | `fbb39341340bc844eb7220e47ff2d84f10d5560d` | 75 | FULL |
| `github-api-collector/cremore_collectors/collectors/__init__.py` | `0b372c3beaef656c4cc8a0e750e0419d7c03cd56` | 5 | SAME → `cremore_collectors/collectors/__init__.py` |
| `github-api-collector/cremore_collectors/collectors/_http.py` | `9b714a2ea68c669c78f05bf29be71c7ed84a8b36` | 62 | SAME → `cremore_collectors/collectors/_http.py` |
| `github-api-collector/cremore_collectors/collectors/classic_pat.py` | `206df480e5af672bdd0f55e4e85041d1f1e6c05d` | 157 | SAME → `cremore_collectors/collectors/classic_pat.py` |
| `github-api-collector/cremore_collectors/collectors/deploy_key.py` | `80b7f6a333da7a164303ea1c654c0330675dbad4` | 306 | SAME → `cremore_collectors/collectors/deploy_key.py` |
| `github-api-collector/cremore_collectors/collectors/fine_grained_pat.py` | `6df2173cc00e76de2093554600345be30b41e262` | 291 | SAME → `cremore_collectors/collectors/fine_grained_pat.py` |
| `github-api-collector/cremore_collectors/collectors/github_app_installation_token.py` | `1bd4e2d8137c477d799577874eb59381430e0487` | 279 | SAME → `cremore_collectors/collectors/github_app_installation_token.py` |
| `github-api-collector/cremore_collectors/collectors/github_app_user_token.py` | `8a7422374b8473b27e49a5e8aaea0d08eedf3e6f` | 171 | SAME → `cremore_collectors/collectors/github_app_user_token.py` |
| `github-api-collector/cremore_collectors/collectors/github_token.py` | `d19f36afe5143dc7aba590003df4f2b9d0ef51ce` | 461 | SAME → `cremore_collectors/collectors/github_token.py` |
| `github-api-collector/cremore_collectors/collectors/oauth_app_token.py` | `9024535d896d08cee7de036494694fec37328700` | 170 | SAME → `cremore_collectors/collectors/oauth_app_token.py` |
| `github-api-collector/cremore_collectors/collectors/user_ssh_key.py` | `2c52d5a6a71245c678f7cf43c09eb0f66c96068d` | 166 | SAME → `cremore_collectors/collectors/user_ssh_key.py` |
| `github-api-collector/cremore_collectors/gateway.py` | `405d69b3ea7c132f8fe3e23e04c264bd5da1b833` | 141 | FULL |
| `github-api-collector/cremore_collectors/json_evidence.py` | `25b92b8bcfa1ddfd548db6382b1177d4eacf3670` | 401 | FULL |
| `github-api-collector/cremore_collectors/json_export.py` | `00844634882db2f11f2eabafea659e2ce6e44baa` | 59 | FULL |
| `github-api-collector/cremore_collectors/json_pipeline.py` | `de622a9ca032052b7f5baac38a0bece7da33d87b` | 275 | FULL |
| `github-api-collector/cremore_collectors/json_store.py` | `7a7b50fa0620a34c20dec60014228aa36066bac1` | 77 | FULL |
| `github-api-collector/cremore_collectors/registry.py` | `35a6f6b362ada70b3db509d01e434bbab51dc709` | 43 | SAME → `cremore_collectors/registry.py` |
| `github-api-collector/cremore_collectors/supplemental.py` | `58d3e9d112b263f91edd92b6bd326f17f506bc1a` | 289 | FULL |
| `github-api-collector/cremore_collectors/validation.py` | `9c1192b07697ebb47d5fb6f49ff73b470f215fe2` | 110 | FULL |
| `github-api-collector/query_classic_pat.py` | `dcd037a782ee1773cdef53e628f6231548d536ed` | 7 | FULL |
| `github-api-collector/query_deploy_key.py` | `5dfbd10bd13a045a00e656495381f6ca5d1a3029` | 7 | FULL |
| `github-api-collector/query_fine_grained_pat.py` | `59162dafcfa05f3bf175acf22d42ffd1e3a55dc6` | 7 | FULL |
| `github-api-collector/query_github_app_installation_token.py` | `0a1385d2bb3badcf553a42ac7d9a020a52c71da5` | 7 | FULL |
| `github-api-collector/query_github_app_user_token.py` | `93b621c7f6e35e973c97a4fe84df0b545167657b` | 7 | FULL |
| `github-api-collector/query_github_token.py` | `2463e78eb2a607d5803f09529572c608249e3c91` | 7 | FULL |
| `github-api-collector/query_oauth_app_token.py` | `1d1fff2b86900b4e194081910f4407c0ac14847d` | 7 | FULL |
| `github-api-collector/query_user_ssh_key.py` | `0fa10a6084b1481c5aa2300829d6f4cacdc37c99` | 7 | FULL |
| `github-api-collector/requirements.txt` | `08c810d523f28e8954f45f7441dc977df2299687` | 2 | FULL |
| `github-api-collector/tests/fixtures.py` | `ef429b08a3a751fe94507305e766d2f8c61577fd` | 77 | FULL |
| `github-api-collector/tests/test_collector_modules.py` | `3204a676accbbc634233e40f868193986b4a6f42` | 230 | FULL |
| `github-api-collector/tests/test_json_pipeline.py` | `58eb74c2512d552ce6abc89a3eaea8eb1c9bffa7` | 282 | FULL |
| `github-api-collector/tests/test_supplemental.py` | `8c1d46c4793f459cd223a1676bf7a19babe08727` | 180 | FULL |
| `github_app_auth.py` | `8e82127f463cf4d3ecb73c494d25e09fc0720b85` | 2 | FULL |
| `query_classic_pat.py` | `dcd037a782ee1773cdef53e628f6231548d536ed` | 7 | SAME → `github-api-collector/query_classic_pat.py` |
| `query_deploy_key.py` | `5dfbd10bd13a045a00e656495381f6ca5d1a3029` | 7 | SAME → `github-api-collector/query_deploy_key.py` |
| `query_fine_grained_pat.py` | `59162dafcfa05f3bf175acf22d42ffd1e3a55dc6` | 7 | SAME → `github-api-collector/query_fine_grained_pat.py` |
| `query_github_app_installation_token.py` | `0a1385d2bb3badcf553a42ac7d9a020a52c71da5` | 7 | SAME → `github-api-collector/query_github_app_installation_token.py` |
| `query_github_app_user_token.py` | `93b621c7f6e35e973c97a4fe84df0b545167657b` | 7 | SAME → `github-api-collector/query_github_app_user_token.py` |
| `query_github_token.py` | `2463e78eb2a607d5803f09529572c608249e3c91` | 7 | SAME → `github-api-collector/query_github_token.py` |
| `query_oauth_app_token.py` | `1d1fff2b86900b4e194081910f4407c0ac14847d` | 7 | SAME → `github-api-collector/query_oauth_app_token.py` |
| `query_user_ssh_key.py` | `0fa10a6084b1481c5aa2300829d6f4cacdc37c99` | 7 | SAME → `github-api-collector/query_user_ssh_key.py` |
| `requirements-collectors.txt` | `5a3616df22e64370c7d21898c505376a830fb570` | 4 | FULL |
| `run_all.py` | `194e3c756b0f12e09ddd50c20d99d15412f04b49` | 7 | FULL |
| `tests/fixtures/collector-service-key.txt` | `3bb75d32395b1ec826ef932ba2b9cc713366dd10` | 1 | 공개 테스트 fixture 확인; 값 미출력 |
| `tests/test_collector_modules.py` | `3204a676accbbc634233e40f868193986b4a6f42` | 230 | SAME → `github-api-collector/tests/test_collector_modules.py` |
| `tests/test_collector_service.py` | `554838c9d8ea8ce703b95c5bd36238b1af78e8be` | 349 | FULL |
| `tests/test_coordinator.py` | `a960aaf9f02884f3e5436187014c45825c9cc3c0` | 513 | FULL |
| `tools/verify_collectors.ps1` | `2b608dc92d2020a173e07ef88ed3da4ed126b348` | 68 | FULL |
