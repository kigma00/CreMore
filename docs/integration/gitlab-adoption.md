# GitLab 최신 브랜치 수용 기록

## v0.11.1 연동 업데이트 (2026-09-22)

현재 플랫폼 수집기는 v0.11.1 동작을 공통 Worker 구조에 반영한다. 아래 v0.6.0 수용 기록은 최초 이식의 출처이며, 현재 버전을 뜻하지 않는다. 추가 원본 커밋은 `18bccee1b2a33491d7da138d1a23ca298eed6e6c`다.

- 기존 토큰 ID, 메타데이터 정책, 소유자/발급자 분리와 공통 PostgreSQL 페이지 커밋·lease·재개 계약을 유지한다.
- `/users/:id`에 단일 0.5 rps 버킷을 적용한다. 전역 버킷과 함께 전송 직전에 허가를 차감하고 재시도에도 적용한다. 대기는 Worker 취소 확인을 유지한다.
- 탐색/토큰 목록 → 상세 → 사용자 → 감사 순서로 실행한다. 제한 분류별 heap을 사용하며 사용자 조회 허가를 기다리는 동안 준비된 다른 작업을 실행한다. 429 backoff는 우회하지 않는다.
- 감사 생성 근거의 미조회·불완전 조회·범위 밖·생성일 미확인·미발견·발견을 schema 1.4에 기록한다. 기존 1.0~1.3 JSON/JSONL 비교를 지원한다.
- coverage note 중복 판정은 hash map으로 수행한다. 페이지 실패 시 note와 작업 인덱스도 롤백한다. 토큰 출력 조립은 `inventory_view.py`로 분리한다.
- 플랫폼에 있던 응답 ID 검증, 인증 query 거부, 모든 페이지의 고정 범위 검증을 보존한다. 독립 CLI의 SQLite WAL과 터미널 진행 막대는 공통 DB/대시보드 Worker에 복사하지 않는다.
- 기존 연결의 명시적 감사 기간(null 포함)은 유지한다. 독립 CLI의 90일 기본값을 기존 플랫폼 연결에 소급 적용하지 않는다. 30/60/90/180일 또는 null을 API 옵션으로 지정할 수 있다.
- GitLab 연결 화면의 `audit` 선택·해제를 `include_audit_events` 실행 옵션에 연결한다. 기존 연결의 체크 상태도 실제 실행 옵션을 기준으로 표시한다. 다른 공급자의 감사 옵션 처리에는 적용하지 않는다.
- `audit.creation_evidence`를 공통 fact 허용 목록에 반영한다. 범위의 시작·끝 시각이 공통 깊이 6 제한으로 소실되지 않도록 기존 JSON pointer 표현(`/audit/creation_evidence`)을 사용하고, GitLab 내보내기에서 원래 중첩 구조로 복원한다. 비밀값 필터·노드 수·깊이 제한은 유지하며 같은 경로를 중복 표현한 입력은 거절한다.

검증: 변경 전 GitLab 테스트 112개 통과. 변경 후 GitLab 142개와 26개 subtest, GitHub·GCP·Azure Key Vault·Atlassian/Bitbucket 공통 어댑터를 포함한 선택 회귀는 총 389개와 42개 subtest가 통과했다. 감사 폼 회귀를 포함한 UI 단위 테스트 463개와 Next.js 프로덕션 빌드도 통과했다. 새 회귀는 native 재구성 결과뿐 아니라 Worker가 저장할 fact에서 생성 근거·범위·null 보존을 직접 비교한다.

2026-09-22 로컬 Docker의 동일 연결에서 감사 비활성 실행(17:29 KST)과 활성 실행(17:59 KST)을 비교했다.

| 측정 | 감사 비활성 | 감사 활성 |
|---|---:|---:|
| 최종 토큰 / 보조 자산 | 12 / 8 | 12 / 8 |
| 발급자 확인 | API 1개 | API 1개 + 감사 5개 |
| 완료 작업 / 실패 작업 | 34 / 0 | 38 / 0 |
| 소요 시간 | 31.874초 | 33.019초 |
| 저장 레코드 | 83 | 114 |

토큰 ID와 소유자는 유지됐으며 추가 발급자 5개는 Deploy token 4개와 Project access token 1개다. 감사 응답 21건 중 토큰 관련 6건을 보존·매핑하고 15건을 필터링했다. 저장 레코드에는 자산 관측, 작업 보고와 감사 관측이 포함되므로 토큰 개수와 다르다. 두 번의 실행은 요청량이 달라 전체 성능 향상률을 입증하지 않는다. 다른 SaaS 실계정 검증과 운영 서버 반영도 이 결과로 입증하지 않는다.

감사 활성 실행의 native 생성 근거는 `not_searched` 2개, `found` 6개, `searched_not_found` 3개, `searched_not_found_range_unverifiable` 1개다. 개인 PAT의 User 감사는 수집 범위 밖이며, 나머지 미발견을 GitLab의 이벤트 미제공으로 단정하지 않는다. 이 실행에서 공통 저장 fact의 `creation_evidence` 누락을 발견해 위 변환을 수정했다. 합성 회귀와 기존 토큰 12개의 메모리 재변환을 확인한 뒤 로컬 API와 Worker를 갱신했다. 기존 실행의 저장 레코드는 소급 수정하지 않았다.

수정 후 18:22:45~18:23:15 KST의 실제 재수집(`051291fd-dd12-41f2-b4ef-8f4806967c84`, 동일 연결 revision 2)은 COMPLETE였다. 30.573초, 작업 38개 완료/실패 0개, 저장 레코드 114개로 끝났으며 토큰 12개·보조 자산 8개·발급자 6개를 유지했다. 이전 감사 활성 실행과 토큰 추가·제거 및 소유자/발급자 ID·상태 변경은 모두 0개다. 토큰 12개 모두 실제 저장 레코드, 최신 실행을 가리키는 대시보드 조회 응답, native 내보내기의 `creation_evidence` 전체가 일치했고 해당 필드의 omission은 0개였다. 미조회 2개와 생성일 미제공 5개의 범위 판정은 null, 생성 시각을 포함한 5개는 true로 유지됐다. 이 단일 재실행의 시간 차이를 성능 향상률로 해석하지 않는다.

통합 기준은 `develop_total`의 `0804933`을 유지한다. 이후 `main`에 반영된 다른 SaaS 변경은 이번 작업에 가져오지 않는다.

내부 성능 비교(같은 로컬 환경, 네트워크 제외): 2,000개 note 삽입은 변경 전 7.505초 → 변경 후 0.0069초(3회 중앙값), 작업 큐 완료 처리는 0.0527초 → 0.0265초(1회). 이는 API 수집 전체 속도 향상률이 아니다. 기준 코드는 `0804933`의 storage.py이며 양쪽 동일 입력을 사용했다.


기준일: 2026-09-21. 대상은 `publish/develop_gitLab`의 `744c48c877737ee9bee0cba0de571f1de4da9ead`다. 원본 수집기 버전은 0.6.0, 내보내기 schema는 1.2다. [기존 설계안](../INTEGRATION_DESIGN_REVISED.md), [기존 GitLab 분석](gitlab.md), [공통 구현 계약](implementation-contract.md)은 과거 분석 시점의 기록으로 유지한다. 이 문서는 최신 소스 수용 내용과 이번 검증 범위를 설명한다.

## 최신 소스에서 추가 확인한 내용

설계가 참조한 `972eac277c015898d1785cd74f710243e4788e5c`와 비교하면 22개 파일이 추가되거나 변경됐다. 최신 tree의 추적 파일 25개를 모두 읽었다. README에만 의존하지 않고 실제 수집, 저장, 비교 코드와 86개 원본 테스트를 확인했다.

| 변경 | 제품에서 보존한 의미 |
|---|---|
| Group/Project 감사 API와 기간 분할 | 명시적으로 켠 경우에만 조회한다. 30일 창과 경계 중복, keyset 다음 페이지, 고정된 실행 시작 시각을 유지한다. 조회 창을 GitLab의 보존 기간으로 해석하지 않는다. |
| 토큰 감사 식별 | `event_name`, `event_type`, 대상 종류, 공식 ID, 실제 scope를 함께 확인한다. 같은 이름, 같은 숫자만으로 연결하지 않는다. Agent ID를 Agent token ID로 바꾸지 않는다. |
| 생성 감사 보강 | API가 반환한 소유자와 생성 감사의 발급자를 분리한다. 생성 이벤트가 유일한 근거일 때만 발급자를 보강하고, 상충하면 미확정으로 남긴다. |
| 원천 필드 우선순위 | detail REST, list REST, resource REST, GraphQL 순서로 우선한다. 재개 순서나 수집 시각이 대표값을 바꾸지 않는다. 중첩 객체도 같은 규칙으로 합친다. |
| 저장 전 정책 | 비밀 필드, DSN, 고객이 제외한 프로필 필드를 영속화 전에 제거한다. `hasTokenExposed`는 query와 저장 대상에서 제외한다. |
| 출력과 비교 | native 1.2 구조, JSON 배열, 업무 순서의 키 정렬, 1.0/1.1/1.2 JSON 및 JSONL 비교를 공통 DB 관찰에서 재구성한다. 미관측을 폐기로 표시하지 않는다. |
| 전송 제한과 출처 | TLS, 동일 origin, 리다이렉트 금지, 응답 바이트 제한, 요청 예산, 429 회로 차단, 재시도 대기, 코드 digest를 유지한다. |

## 수용 위치

원본 경로의 공통 접두사는 `collectors/gitlab/collector_v1/`다. 운영 패키지는 [cremore/coverage/providers/gitlab](../../cremore/coverage/providers/gitlab/)이다.

| 원본 파일 | 수용 위치와 처리 |
|---|---|
| `.gitignore` | 원본의 로컬 결과, 인증 설정 제외 의도를 확인했다. 원본의 로컬 출력 디렉터리를 제품 상태 저장소로 들여오지 않는다. |
| `README.md` | 실행 범위, 한계, 권한 설명을 이 문서와 공통 연결 계약에 대응시켰다. |
| `METADATA_AND_JSON_V0_6.md` | native 필드와 출력 설명을 `normalization.py`, `storage.py`, `presentation.py`에 대응시켰다. |
| `REVIEW_FIXES_V0_5.md` | 수정 의도를 실제 0.6 소스와 원본 회귀로 대조했다. 과거 설명을 현재 구현 상태로 복제하지 않았다. |
| `config.example.json`, `config.validation.example.json` | 비밀 없는 옵션을 공통 `MetadataOptions`와 `adapter._config`에 대응시켰다. 실제 연결은 기존 secret reference를 사용한다. |
| `examples/inventory.example.json` | 출력 schema를 확인했다. 제품 데이터로 적재하지 않았다. 당시 사용한 demo·예제 데이터 파일은 2026-10-02 제거했고 회귀 검사에 필요한 최소 입력만 테스트 내부에서 만든다. |
| `gitlab_inventory/__init__.py` | 버전 0.6.0과 출처를 유지하고 공통 공개 함수를 노출한다. |
| `gitlab_inventory/__main__.py`, `gitlab_inventory/cli.py` | 제품 진입점은 공통 worker다. 원본 CLI는 `tests/_qa_cli.py`에 QA fixture로 보존했다. |
| `gitlab_inventory/audit.py` | `audit.py`: 기간, 이벤트 해석, 모호성, 생성자 보강을 수용했다. |
| `gitlab_inventory/collector.py` | `collector.py`: 10개 유형, BFS, 페이지 처리, 사용자 보강, 감사 수집을 수용했다. |
| `gitlab_inventory/config.py` | `config.py`: 옵션 검증과 재개 fingerprint를 수용했다. |
| `gitlab_inventory/demo.py` | 당시에는 실제 계정이 없는 합성 transport로 수용했다. 운영 demo 모듈·생성기는 2026-10-02 제거하고 테스트에 필요한 최소 fake만 테스트 내부에 둔다. |
| `gitlab_inventory/handlers.py` | `handlers.py`: 원천 분류와 필드 우선순위를 유지한다. |
| `gitlab_inventory/http.py` | `http.py`: 읽기 전용 전송, 페이지 링크, rate limit 처리를 수용했다. 취소 callback을 추가했다. |
| `gitlab_inventory/metadata_policy.py` | `metadata_policy.py`: 원본의 객체별 제외 규칙을 유지한다. |
| `gitlab_inventory/model.py` | `model.py`: ID 공간, secret 제거, 중첩 병합, 소유자와 발급자 구분을 유지한다. |
| `gitlab_inventory/presentation.py` | `presentation.py`: native JSON 표시 순서를 내보내기에 적용한다. |
| `gitlab_inventory/provenance.py` | `provenance.py`: 실제 설치 패키지 파일의 digest를 계산한다. 원본 채택 SHA와 실행 코드 digest를 별도로 기록한다. |
| `gitlab_inventory/storage.py` | 원본 SQLite 구현은 `tests/_qa_storage.py`에서만 사용한다. 운영 `storage.py`는 공통 DB 관찰로 복구하는 메모리 view다. |
| `tests/test_collector.py`, `tests/test_audit.py`, `tests/test_hardening.py`, `tests/test_metadata_policy.py` | 같은 이름의 GitLab 패키지 테스트로 옮겼다. 원본 86개 시나리오를 유지하고 import, 포맷, OS 전용 조건만 조정했다. |

새 파일 `adapter.py`는 공통 lease와 체크포인트 연결, `normalization.py`는 typed fact 변환, `tests/test_adapter.py`는 통합 회귀를 담당한다. 별도의 SQLite, JSON 상태 파일, 별도 운영 프로세스는 만들지 않는다. 원본 문서와 예제 자체는 고정된 Git revision에서 계속 확인할 수 있다.

## 지원하는 목록과 해석

| 유형 | 주 조회 경로와 조건 |
|---|---|
| Personal access token | `/personal_access_tokens?user_id=<수집 계정>`; 관리자가 연결해도 다른 모든 사용자를 자동 조회하지 않는다. Cloud enterprise 조회는 별도 옵션이다. |
| Group service account PAT | 승인 그룹의 service account 목록과 해당 계정의 PAT 목록 |
| Project service account PAT | 승인 프로젝트의 service account 목록과 해당 계정의 PAT 목록 |
| Group access token | `/groups/:id/access_tokens`; Cloud 상위 그룹의 통합 목록은 별도 옵션 |
| Project access token | `/projects/:id/access_tokens`; 개별 목록과 통합 목록의 공식 resource ID를 맞춘다. |
| Group deploy token | `/groups/:id/deploy_tokens` |
| Project deploy token | `/projects/:id/deploy_tokens` |
| Pipeline trigger token | `/projects/:id/triggers`와 선택적 GraphQL 보강. 반환된 token 값은 제거한다. |
| Error tracking client key | `/projects/:id/error_tracking/client_keys`의 ID와 상태만 관리한다. `public_key`, `sentry_dsn` 원문은 저장하지 않는다. |
| Kubernetes agent token | 프로젝트의 Agent와 Agent token 목록. 목록이 active-only이므로 사라졌다는 사실을 폐기로 바꾸지 않는다. |

PAT의 ID는 instance 전역 공간으로 묶고 실제로 관측한 모든 scope를 따로 남긴다. Resource access token, deploy token, trigger, Agent token은 공급자의 namespace와 실제 자산 scope를 함께 쓴다. 같은 숫자의 PAT와 resource token을 같은 자격증명으로 가정하지 않는다.

`ACTIVE`, `REVOKED` 등은 `PROVIDER_REPORTED` 관찰이다. 발견된 secret으로 인증을 시도한 결과가 아니다. 이 adapter는 노출 후보 조합이나 인증 검증을 수행하지 않는다. Vault 등록 여부와 노출 결과의 연결은 공통 증거 모델의 후속 판단이다.

## 공통 실행과 경계

공개 함수는 `collect_pages`, `validate_spec`, `validate_record`, `validate_machine_record`, `export_records`, `compare_records`다. 두 내보내기 함수에는 같은 실행의 공통 DB record를 전달한다. `spec=`를 전달하면 승인된 옵션까지 manifest에 포함한다. API route와 대시보드 연결은 공통 구현 담당의 별도 통합 범위다.

worker는 `collect_pages`가 반환한 record와 checkpoint를 기존 `TaskStore.fenced` 안에서 함께 반영한다. 공급자 HTTP는 그 트랜잭션 밖에서 실행한다. `read_records`는 재개할 때 한 번만 호출하여 이미 commit한 typed 관찰을 복구한다. 매 페이지마다 전체 실행을 재생하지 않는다. 메모리 view는 변경된 항목만 복사하는 rollback journal을 사용한다.

실패한 페이지의 관찰과 후속 작업은 함께 롤백한다. 완료된 source는 재개 시 다시 읽지 않는다. 최종 감사 대조와 관계 투영에도 cursor가 있어 중간에 멈춰도 이어갈 수 있다. 재인증 `/user` 결과가 이미 관찰한 `/users/:id` 프로필을 덮어쓰지 않는다. 수집 계정이 바뀌면 기존 결과를 덮지 않고 실패한다.

`RETRY_LATER`, `RATE_LIMIT_CIRCUIT_OPEN`, 재시도 후 `RATE_LIMITED`는 source 오류와 체크포인트를 반환한 뒤 `WAITING`으로 일시 정지한다. 긴 서버 대기 시각은 `retry_not_before`에 남긴다. worker가 일찍 재개해도 그 시각 전에는 공급자 HTTP를 보내지 않는다. 승인된 요청, 페이지, 레코드 한도 도달은 `PARTIAL`이다. 인증 실패는 재인증 성공이나 폐기로 바꾸지 않는다.

요청 제한은 한 worker 수집 시도의 HTTP 재시도를 포함한다. 페이지 제한은 같은 실행의 복구된 source 페이지를 합산한다. 레코드 제한은 자격증명 개수만이 아니라 원천 관찰, operation report, 최종 관찰과 관계까지 센다. 자산 수, 단일 record 크기, 페이지 크기, 2 MB checkpoint 제한도 확인한다. 한도를 넘어간 페이지는 이전 commit 위치를 유지한다.

공통 fact는 임의 JSON 문자열이 아니다. 승인된 이름의 재귀 노드만 저장하며 null, 미제공, 잘못된 값, 빈 객체와 빈 배열을 구분한다. 알려지지 않은 원본 필드는 `UNAPPROVED_METADATA_FIELD`, 크기나 값 제한은 별도 omission으로 남긴다. 따라서 원본의 “비밀값 이외의 모든 새 필드 보존”은 공통 저장 경계에서 승인된 필드만 보존하는 규칙으로 바뀐다. 내보내기의 `normalization_omissions`와 manifest가 그 차이를 명시한다. 필수 ID나 source 구조까지 소실되면 완전 수집으로 표시하지 않는다.

내부 worker의 승인된 BFS와 외부 machine 제출은 신뢰 범위가 다르다. 일반 검증은 origin, tenant, native namespace, endpoint, ID와 상태의 일관성을 확인한다. 외부 제출은 여기에 실제 관찰 scope와 명시적으로 승인된 scope의 일치를 요구한다. `group:10` 라벨이나 업로드한 `contains` 관계만으로 `project:100` 또는 `group:20`을 승인할 수 없다. 외부 `user:self` 제출에는 검증하여 고정한 숫자 principal이 필요하다. machine에서 별도 사용자 프로필을 가져오려는 경우에도 승인 범위가 없으면 거절되므로 연결 옵션과 수집 대상을 그에 맞춰야 한다.

## 공식 문서에 따라 적용한 제한

2026-09-21 공개 공식 문서를 확인했다. 인증된 고객 API나 고객 파일은 사용하지 않았다.

- [Personal access tokens](https://docs.gitlab.com/api/personal_access_tokens/), [Service accounts](https://docs.gitlab.com/api/service_accounts/): own PAT 조회와 서비스 계정 조회를 구분한다.
- [Groups](https://docs.gitlab.com/api/groups/), [Group access tokens](https://docs.gitlab.com/api/group_access_tokens/), [Project access tokens](https://docs.gitlab.com/api/project_access_tokens/): `/groups/:id/manage/...`는 GitLab.com Premium/Ultimate 상위 그룹 Owner 범위다. Self-Managed와 Dedicated에서 `include_enterprise_pat`는 거절한다. Cloud 전용 resource 통합 목록 요청은 `UNSUPPORTED`로 기록하고 개별 group/project 목록은 계속 수집한다. 해당 옵션을 끄면 그 미지원 요청은 수집 범위에서 제외된다.
- [Deploy tokens](https://docs.gitlab.com/api/deploy_tokens/), [Pipeline triggers](https://docs.gitlab.com/api/pipeline_triggers/): trigger 목록의 전체 token 또는 일부 문자열을 일치 근거로 사용하지 않는다.
- [Cluster agents](https://docs.gitlab.com/api/cluster_agents/), [Error tracking](https://docs.gitlab.com/api/error_tracking/): Agent token의 active-only 목록과 client key 메타데이터의 한계를 유지한다.
- [GraphQL reference](https://docs.gitlab.com/api/graphql/reference/): pipeline trigger 보강은 선택적이며 실험 필드와 schema 오류가 REST 관찰을 없애지 않는다.
- [Audit API](https://docs.gitlab.com/api/audit_events/), [Audit event types](https://docs.gitlab.com/user/compliance/audit_event_types/), [Audit events](https://docs.gitlab.com/user/compliance/audit_events/): Premium/Ultimate와 역할별 가시성 차이가 있다. Group Owner와 Project Maintainer 이상의 가시성을 같은 것으로 추정하지 않는다. Group의 Developer/Maintainer는 자신의 행동만 볼 수 있다. PAT의 User 범위 이벤트는 현재 Group/Project 수집만으로 모두 확인할 수 없다. 공식 보존 설명은 무기한이며, 30일은 한 요청의 기간 제한이다.
- [Rate limits](https://docs.gitlab.com/administration/settings/user_and_ip_rate_limits/): `RateLimit-Reset`은 UNIX 시각, `RateLimit-ResetTime`은 HTTP 날짜로 해석한다. `Retry-After` 대기를 무시하지 않는다.

버전, 요금제, 역할, 고객 설정별 실제 API 가시성은 합성 시험으로 입증할 수 없다. 모든 조직 자격증명, User/Instance 감사, streaming-only 이벤트, 저장소 콘텐츠나 런타임 secret까지 수집한다는 의미로 `COMPLETE`를 사용하지 않는다. GitLab 저장소 콘텐츠 스캔은 기존 콘텐츠 수집기의 별도 기능이다.

## 검증과 인수

원본 최신 snapshot의 86개 테스트와 이식 코어의 동일 86개 테스트를 각각 Linux에서 통과시켰다. 공통 adapter 회귀 24개도 Windows에서 통과했다. 최종 합성 suite는 native 86개와 adapter 24개, 총 110개다.

주요 회귀는 10개 유형, 상세 필드 우선순위, 감사 생성자와 owner 분리, 모호한 참조, 실제 ID 불일치, 고정 사용자 필터의 페이지 이탈, GraphQL 실패, 페이지 원자성, 수집 중간과 최종화 중간 재개, 계정 변경, 실패 source 재시도, 긴 429 대기, 취소, sidecar DB 미사용, 명시 scope 검사, legacy JSON/JSONL 비교, null과 omission의 구분을 포함한다. Native와 공통 view의 실제 inventory 내용도 승인된 필드 정책을 적용한 뒤 대조한다.

실행 명령:

```text
python -B -m unittest discover -s cremore/coverage/providers/gitlab/tests -t .
python -m ruff check cremore/coverage/providers/gitlab
python -m ruff format --check --quiet cremore/coverage/providers/gitlab
```

Linux 검증은 `cremore-python:latest`의 Python 3.14.7, 네트워크 없는 읽기 전용 컨테이너와 합성 snapshot을 사용한다. 임시 파일은 별도 tmpfs에만 쓴다. 원본 POSIX CLI 잠금 시험 2개는 Windows에서만 명시적으로 skip하며 Linux에서는 모두 실행한다. 최종 이미지, 공통 API 권한과 lease 경쟁, 실제 기업 GitLab 연결, dashboard 동작은 이 패키지 검증과 구분해서 확인해야 한다.
