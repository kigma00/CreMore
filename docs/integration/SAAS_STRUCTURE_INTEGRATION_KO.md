# SaaS 구조 통합 기록 (`integration/saas-structure`)

> 작성 2026-09-26. 기준 `refactoring` `6616dae`. 다른 로컬 환경에서 이 문서 하나로 통합의 목적·변경·검증 방법을
> 파악하도록 썼다. 마지막 절(§8)은 다른 환경의 AI에게 그대로 붙여 넣는 검증·피드백 요청 프롬프트다.

## 1. 목적

- **CreMore**는 조직의 평문 자격증명 노출을 찾아 마스킹된 증거와 위험도로 대응을 돕는 자체 호스팅 보안 플랫폼이다.
  - 공급자가 보고한 **발급 목록**, 콘텐츠 스캔으로 찾은 **평문 노출**, 기업 **금고** 보관, 이 세 집합을 대조한다.
  - 가장 중요한 판정은 "발급했는데 금고에 없음"이다.
- 팀원마다 담당 SaaS(공급자)가 다르다. 각자 자기 공급자의 수집기(콘텐츠 스캔, 메타데이터·인벤토리, 금고 수집)를
  **독립적으로 고도화**할 수 있어야 한다.
- 이번 통합은 세 브랜치를 하나로 모은다.

  | 약칭 | 브랜치 | 통합 방식 |
  |---|---|---|
  | R | `refactoring` (`6616dae`) | 기준. 공급자별 최상위 디렉터리(`<vendor>/backend`, `<vendor>/web`) 구조 |
  | G | `codex/gcp-dashboard-oauth` (`ea2207b`) | 기능 커밋 2개를 cherry-pick. 대시보드 Google OAuth로 GCP 연결 |
  | S | `refactor/saas-libraries` (`8287dcd`) | 코드 이동은 가져오지 않았다. 경계 원칙과 검증 방식만 R 구조에 맞게 옮겼다 |

- 지킬 조건: SaaS별 수집기 기능이 이전과 같아야 한다. 경계와 함수 호출에서 오류나 성능 악화가 없어야 한다.
  - 예외: 나노초 단위의 차이, 또는 단일 수집기의 미미한 저하로 전체 기능이나 시간이 좋아지는 경우

## 2. 변경 목록

| 커밋 | 단계 | 내용 | 근거 |
|---|---|---|---|
| `064c15d` | PR-0 | 실수로 추적되던 `.omc/` 세션 파일 제거, `.gitignore` 추가 | 로컬 AI 도구 상태가 저장소에 섞여 있었다 |
| `16ea6b0` `143c4e0` | PR-1 | G의 GCP 대시보드 OAuth 온보딩(원작자 M3rcy1028) | 충돌 3곳을 해결했다: `db/schema.py`(두 테이블 공존), GCP `descriptor.py`(`google_oauth`와 조직·폴더 scope), `provider-inventory.tsx` |
| `311c626` | PR-1 | GCP discovery가 OAuth 사용자 토큰으로 조회 | 의미 충돌. R의 조직·폴더 discovery가 G의 `google_oauth` 연결에서도 worker ADC로 조회했다. 새 회귀 테스트 3개 중 2개가 수정 전 코드에서 실패했다 |
| `089f856` | PR-2 | `CoverageError` → `cremore/coverage/errors.py`, fact helper → `cremore/coverage/facts.py`, 순수 helper import | 공급자 모듈이 import만 해도 SQLAlchemy·coverage store·공급자 등록표를 로드했다(S의 경계 원칙) |
| `aec56f9` | PR-3 | `cremore/provider_boundaries_test.py` | S 방식의 새 프로세스 경계 검사를 R 구조에 맞게 옮겼다 |
| `12061a3` | PR-1 후속 | G의 요청 모델 이름을 `GcpOAuthStart`·`GcpOAuthFinish`로 변경 | OpenAPI 컴포넌트 이름 충돌. 수집기 경로의 공개 스키마 `Start`·`Finish`가 순서에 따라 OAuth 본문으로 바뀌었다 |
| `a9b34ce` | PR-5 | 소스 목록을 등록표에서 파생 | 새 콘텐츠 소스를 넣으려면 backend 3곳·웹 8곳의 복사본을 고쳐야 했다 |
| `826da28` | PR-4 | `AdapterRegistration.machine_guard` | `spec.provider == "gitlab"` 하드코딩 제거(S의 설계). guard가 없으면 어댑터를 불러올 때 실패한다 |
| `be8652c` | PR-6 | `scripts/installed_check.py`, 전체 CI 단계 | S의 설치본 검사를 wheel 패키지 10개에 맞게 옮겼다 |
| `5de815e` | 도구 | `scripts/bench_imports.py`, `scripts/bench_collectors.py` | 두 소스 트리를 같은 방법으로 측정한다 |
| `9f950a3` | 리뷰 후속 | 웹 parity를 부분집합으로 바꾸고 경계 테스트 보강(공급자 누락 검사, 상대 경로, SDK 판정) | 독립 리뷰 M1·L1·L2·L3 |
| `ed5467c` | 리뷰 후속 | `installed_check.py`: 패키지 목록을 pyproject에서 읽고, `-z`·루트 `.gitignore` 사용, `-O` 거부 | 리뷰 L2·L4 |
| `7f8c943` | 리뷰 후속 | GCP OAuth 요청 모델 5개 모두 `GcpOAuth*` | 리뷰 L5. 공개 전에 일반 이름 충돌 가능성 제거 |
| `2e4db59` | 리뷰 후속 | 옮긴 import 15곳과 `INSTANCE_SCOPED` 9곳 주석, 방어 분기 주석, 선언 위치 정리 | 리뷰 L7·L8·L9·L10(주석 요구사항) |
| `8e92cfe` | 문서 | 이 통합 기록, AGENTS.md 링크, 팀 지침(절차·명령 보완) | 리뷰 M1·M2·L6·L11 |
| `39aacff` | CI 후속 | GCP 서비스 계정 키 식별자 검사를 키 모양 문자열 없이 수행 | 첫 전체 CI에서 api 이미지의 Trivy가 주석 문자열을 비밀로 오탐했다(`2243dfb`부터 있던 문제) |
| `5c88cc5` | 기능 | GitLab Self-managed 토큰을 발견된 등록 인스턴스에서만 검증 | 인벤토리 현황 검토 결과. gitlab.com으로 보내지 않고 (인스턴스, 토큰 ID) 쌍으로 발급 목록과 연결한다 |
| `570d0e7` | 1차 리뷰 ① | Google 토큰 서비스의 일시 오류(429·5xx·네트워크)를 WAITING으로 대기·재개 | 첫 갱신 실패는 FAILED로 끝났고, 수집 중 실패는 PARTIAL로 남으며 토큰 요청을 반복했다 |
| `52e05da` | 1차 리뷰 ②·2-1 | 등록표·API·worker import 경로의 선택 SDK 금지, 공급자 간 import 금지 테스트 | 현재 위반은 0건이지만 막는 검사가 없었다 |
| `de7c6a9` | 1차 리뷰 ③ | `bench_collectors`가 모든 표본과 재개 상태·요청 순서를 비교 | 첫 표본만 비교했고 시각을 필드 구분 없이 가렸다 |
| `c595e94` | 1차 리뷰 ④ | GCP OAuth API 테스트를 PostgreSQL에서도 실행, 한 세션의 동시 완료 경쟁 검사 | 행 잠금을 없앤 변이가 8/8 실패한다 |
| `af6f4c7` `3d59233` | 2차 리뷰 ① | S의 schema 2 PostgreSQL 게시·재개 테스트와 콘텐츠 계약 테스트 이식, Azure Blob·DevOps 추가 | 공통 `object()`는 범위 검사를 대신하지 않는다. 공급자별 범위 변이가 각 5건씩 실패한다 |
| `ffd80c3` | 2차 리뷰 ② | CI 설치본을 운영 이미지와 같은 해시 lock으로 설치, 설치본 테스트, PR 경계 job | 운영과 다른 버전의 패키지로 검사했다 |
| `b72e76e` | 2차 리뷰 ④ | AWS 폴더의 플랫폼 흐름을 공통 검토 대상으로 명시, import 시 DB를 로드하는 모듈 고정 | 예외는 `inventory_view` 하나다 |
| `c9f3f45` | 2차 리뷰 ⑤ | GitHub 비밀 참조 해석을 worker로 이동 | GitHub 라이브러리의 플랫폼 import에서 `cremore.secretstore.resolver`가 빠졌다 |
| `482c514` `823a1c3` | 2차 리뷰 ⑥ | finding 상세는 가벼운 한 번의 읽기와 보이는 행의 상세만, SAS 후보는 3번의 일괄 조회 | PostgreSQL 1,462→484 ms(인벤토리 1만 행), 11,149→128 ms(SAS finding 1,000건) |
| `e4f01ce` | 2차 리뷰 ⑦ | Azure DevOps 목록이 응답 상한을 넘으면 폴더 단위로 나눠 조회 | 큰 저장소는 스캔 전체가 실패했다 |
| `fac0b7f` | 2차 리뷰 ⑨ | 비밀값을 읽는 선택 기능의 운영 정책(제안) | 팀 합의가 필요하다 |
| 이 문서 커밋 | 2차 리뷰 ⑧ | 기준 구조 결정 기록, 리뷰 후속과 최종 검증 결과 | |

바뀐 코드에는 `Integration` 또는 "three-way integration"으로 시작하는 주석을 달아 이유를 적었다.
옛 import 경로(`cremore.coverage.store.CoverageError`, `cremore.coverage.providers.facts`, `cremore.db.scan_state.INSTANCE_SOURCES`)는 같은 객체로 유지된다.

## 3. 통합 후 공급자 담당자가 고치는 곳

### 콘텐츠 source

1. `<vendor>/backend/cremore_<vendor>_provider/<...>source.py`
   - 기존 속성에 `INSTANCE_SCOPED`를 더한다. 자체 호스팅 인스턴스마다 같은 리소스 이름이 반복되면 `True`다(필수 속성).
2. `cremore/sources/registry.py`에 모듈을 등록한다(한 줄).
3. **같은 변경에서** `web/lib/source-types.ts`에 source type을 한 줄 추가한다.
   - 콘솔의 규칙 범위와 수집 로그가 읽는 목록이다. backend 목록과 값·순서가 같아야 한다(`module_contract_test.py`)
4. (2026-10-01부터) 연결 화면은 onboarding descriptor로 콘솔이 그린다. 이전의 `web/features/connections/providers/registry.ts`
   등록과 `provider-registration.test.cjs`는 이전 대시보드와 함께 삭제됐다

다음은 **자동으로 파생**되므로 따로 고치지 않는다.
- 노출 위치 계산의 `INSTANCE_SOURCES`
- coverage API의 `source_type` 필터
- 사용자 규칙의 `scope_sources` 검증
- 콘솔이 `web/lib/source-types.ts`에서 읽는 목록(규칙 범위·수집 로그)

다만 기존 순서를 고정하는 호환 테스트의 기대값은 새 source에 맞게 함께 고친다:
`cremore/sources/module_contract_test.py`, `cremore/detection/custom_test.py`(오류 메시지).

### metadata adapter

1. 어댑터 모듈에 `collect_pages`·`validate_spec`·`validate_record`를 구현한다.
   - 외부 제출 scope 검증이 필요하면 `validate_machine_record`도 구현한다.
2. `cremore/coverage/providers/__init__.py`의 `AdapterRegistration`에 선택 기능을 선언한다.
   - `value_context`, `recollection`, `comparison`, `machine_guard`
3. 플랫폼 계약은 DB 계층 없이 import된다: `cremore.coverage.errors`, `facts`, `metadata_models`, `collector_runtime`.
   - 새 플랫폼 모듈에 의존하려면 리뷰를 거쳐 `provider_boundaries_test.py`의 `PLATFORM_IMPORTS`에 추가한다.
   - 다른 SaaS의 SDK를 로드하면 경계 테스트가 실패한다.
4. 새 공급자 디렉터리(`<vendor>/backend`)를 만들면 `provider_boundaries_test.py`의 `PLATFORM_IMPORTS`와 `PROVIDER_MODULES`에 추가한다.
   - 빠뜨리면 `test_every_provider_library_is_covered`가 실패한다
   - 경로 목록은 `pyproject.toml`에서 읽으므로 따로 고치지 않는다

### 진행 중인 공급자 브랜치를 이 브랜치에 합칠 때

| 이전 | 이후 | 안 바꾸면 |
|---|---|---|
| `from cremore.coverage.store import CoverageError` (공급자 모듈) | `from cremore.coverage.errors import CoverageError` | 옛 경로도 같은 클래스라 동작은 한다. 다만 import만으로 DB 계층이 로드되어 경계 테스트가 실패한다 |
| `from cremore.coverage.providers.facts import ...` | `from cremore.coverage.facts import ...` | 옛 경로는 별칭이라 동작하지만, 어댑터 등록표를 실행해 경계·허용 목록 테스트가 실패한다 |
| `from cremore.source_config import path, https_base` | `from cremore.sources.validation import path, https_base` | 콘텐츠 등록표 전체가 로드되어 경계 테스트가 실패한다 |
| source 모듈에 `INSTANCE_SCOPED` 없음 | `INSTANCE_SCOPED = True/False` 선언 | 등록표 import가 `AttributeError`로 실패한다(API·worker·`cremore.db` 모두) |
| GitLab처럼 기계 제출에 추가 검증이 필요한 어댑터 | `AdapterRegistration(..., machine_guard=True)`와 `validate_machine_record` | guard 선언 없이도 동작은 이전과 같다. guard를 선언하고 함수가 없으면 그 공급자의 모든 metadata 작업이 `METADATA_ADAPTER_UNAVAILABLE`로 멈춘다 |

### 여전히 공통 검토가 필요한 변경

- 새 인증 방식
- scope 의미
- job kind와 DB의 active-scan partial index·migration
- 연결 비밀 해석
- 누락 리소스를 삭제로 추론하는 기능

## 4. 검증 결과

(측정 환경: Windows 11, Python 3.12.9. 기준선은 `6616dae`를 가리키는 별도 worktree에서 같은 도구로 쟀다.
시간 측정은 `5de815e`에서 했다. 그 뒤의 첫 리뷰 후속 변경(§4.7)은 주석·모델 이름·테스트·검사 도구뿐이었다.
그 뒤 1차·2차 리뷰 후속(§4.8)은 동작을 바꾼다. `fac0b7f`에서 전체 pytest(PostgreSQL 포함), 수집 digest,
설치본 검사, 웹 검사를 다시 확인했다.)

### 4.1 테스트

두 트리에서 전체 pytest를 같은 방법으로 실행했다(각 트리로 `PYTHONPATH` 고정, junit 기록).
- 기준선 `6616dae`: 6,296 통과, 80 skip, 697초
- 통합본: **6,382 통과, 80 skip, 실패 0**, 691초

| 영역 | 테스트 기준선 → 통합본 | 통과 | skip | 실패 | 합계 시간(초) 기준선 → 통합본 |
|---|---|---|---|---|---|
| atlassian | 345 → 345 | 288 → 288 | 57 → 57 | 0 → 0 | 3.5 → 3.6 |
| aws | 412 → 412 | 405 → 405 | 7 → 7 | 0 → 0 | 18.0 → 16.8 |
| azure | 260 → 260 | 260 → 260 | 0 → 0 | 0 → 0 | 12.0 → 10.4 |
| gcp | 193 → 211 | 193 → 211 | 0 → 0 | 0 → 0 | 3.3 → 2.6 |
| github | 163 → 163 | 163 → 163 | 0 → 0 | 0 → 0 | 1.9 → 1.5 |
| gitlab | 170 → 170 | 168 → 168 | 2 → 2 | 0 → 0 | 90.9 → 75.3 |
| notion | 93 → 93 | 93 → 93 | 0 → 0 | 0 → 0 | 0.2 → 0.2 |
| vault | 51 → 51 | 51 → 51 | 0 → 0 | 0 → 0 | 8.5 → 6.5 |
| platform (cremore/) | 4689 → 4757 | 4675 → 4743 | 14 → 14 | 0 → 0 | 549.6 → 564.8 |
| 합계 | 6376 → 6462 | 6296 → 6382 | 80 → 80 | 0 → 0 | 688.0 → 681.7 |

- GCP를 뺀 공급자 7개는 테스트 수·통과·skip이 기준선과 같다. 늘어난 테스트(GCP·플랫폼)는 모두 통과했다.
  - GCP +18: G의 OAuth 15개, discovery OAuth 회귀 3개
  - 플랫폼 +68: G의 OAuth API 22개, 경계 43개, source 목록·OpenAPI 이름·`machine_guard` 각 1개
- 두 junit의 테스트 ID(모듈·이름)를 비교했을 때 **기준선에서 없어진 테스트는 0개**다(`pytest --collect-only` 비교도 같음).
- skip 80개는 두 트리가 같다: Windows에서 돌 수 없는 POSIX 검사 59개, PostgreSQL URL 미설정 21개.
- 플랫폼 영역 시간이 늘어난 것은 새 테스트 모듈(경계 25.4초, OAuth API 22.0초) 때문이다.
  - 기존 테스트 모듈만 합치면 549.6초에서 517.4초로 줄었다
- Helm 차트 테스트와 ruff 전체 검사 결과는 §4.6에 적었다.
- 리뷰 후속 뒤 `fac0b7f`(외부 요청 차단: 프록시를 닫힌 포트로 지정)
  - PostgreSQL URL 없이: **6,497 통과, 83 skip, 실패 0**
  - 일회용 PostgreSQL 17(`cremore_test`, localhost)로: **6,619 통과, 59 skip, 실패 0**. 남은 skip은 Windows에서 돌 수 없는 POSIX 검사다

### 4.2 수집기 출력 동등성과 시간

`scripts/bench_collectors.py --repeat 15`. 모든 공급자 라이브러리가 테스트용 합성 transport로 실제 수집을 돈다(네트워크·DB 없음).
표의 시간은 15회 중앙값이고, 괄호 안은 최소값이다.

| 시나리오 | 기준선 ms | 통합본 ms | 비율 | 항목 수 | 출력 digest |
|---|---|---|---|---|---|
| `gitlab.metadata.demo` | 484.9 (388.1) | 500.2 (380.2) | 1.03 | 110 → 110 | 같음 |
| `github.metadata.org` | 21.1 (15.6) | 12.5 (11.5) | 0.60 | 26 → 26 | 같음 |
| `github.metadata.enterprise` | 29.8 (24.6) | 28.3 (19.9) | 0.95 | 39 → 39 | 같음 |
| `gcp.metadata.inventory` | 7.6 (6.0) | 5.8 (5.2) | 0.76 | 27 → 27 | 같음 |
| `gcp.metadata.values` | 8.9 (6.4) | 7.1 (6.1) | 0.79 | 29 → 29 | 같음 |
| `azure.key_vault.metadata` | 2.9 (2.2) | 2.4 (1.7) | 0.85 | 12 → 12 | 같음 |
| `atlassian.metadata.inventory` | 4.7 (2.9) | 3.1 (2.6) | 0.65 | 6 → 6 | 같음 |
| `atlassian.metadata.discovery` | 19.6 (15.7) | 10.4 (9.8) | 0.53 | 21 → 21 | 같음 |
| `atlassian.metadata.accounts` | 4.0 (3.1) | 1.6 (1.6) | 0.40 | 3 → 3 | 같음 |
| `atlassian.metadata.bitbucket` | 14.1 (12.0) | 8.4 (8.0) | 0.59 | 17 → 17 | 같음 |
| `atlassian.metadata.runners` | 3.8 (3.1) | 3.1 (3.0) | 0.82 | 5 → 5 | 같음 |
| `atlassian.metadata.branch_restrictions` | 2.6 (2.2) | 2.2 (2.2) | 0.84 | 3 → 3 | 같음 |
| `azure.devops_tokens.metadata` | 1008.4 (993.4) | 1008.5 (991.8) | 1.00 | 3 → 3 | 같음 |
| `notion.metadata` | 3.9 (1.8) | 2.1 (1.4) | 0.52 | 4 → 4 | 같음 |
| `azure.devops.content` | 2.8 (1.1) | 1.1 (0.8) | 0.38 | 3 → 3 | 같음 |
| `gitlab.content` | 1.0 (0.6) | 0.9 (0.6) | 0.94 | 3 → 3 | 같음 |

- 위 표의 digest(첫 측정 도구): **16/16 동일**, 항목 수 동일
  - 이 도구는 `status`·`records`만 비교했다. 예열과 마지막 반복만 비교했고, 실행 시각 ±2시간의 시각을 필드 구분 없이 가렸다
  - 외부 검토(2026-09-26)가 이 한계를 지적해 도구를 고쳤다(§4.7). 이 표만으로 checkpoint·요청 순서까지 같다고 볼 수는 없다
- **고친 도구로 다시 비교: 16/16 동일**, 모든 반복이 같은 digest, 시나리오별 요청 수 동일(합계 138회)
  - 이전 판에 적은 "합계 174회"는 잘못 옮긴 값이다. 두 결과 파일의 합계는 모두 138회다
  - 비교 대상: 모든 페이지의 `status`·`records`·checkpoint·이유·대기 시간, fake transport가 기록한 요청 순서
  - 시각은 실행이 찍는 필드(`observed_at`, `started_at` 등, 두 번 실행해 찾음)만 가린다. 만료 시각 같은 다른 시각은 그대로 비교한다
  - GitLab 코드 출처(커밋·파일 해시)는 코드 버전이라 계속 가린다
  - 비교 대상 커밋은 `6616dae`와 리뷰 반영 중인 HEAD다. OAuth 일시 오류·GitLab Self-managed 경로는 이 시나리오들이 거치지 않는다
  - `fac0b7f`에서 다시 비교: **16/16 동일**, 요청 수 합계 138회로 같다. Azure DevOps 목록 분할은 응답 상한을 넘을 때만 동작해 이 시나리오의 요청이 그대로다
- 중앙값 합계: 1,620 → 1,598 ms (비율 0.986)
  - 비율 1 이상인 GitLab demo(1.03)와 Azure DevOps PAT(1.00)는 공급자 속도 제한 대기가 시간의 대부분이다
  - GitLab demo의 최소값은 오히려 줄었다
- 수집 코드 자체는 바꾸지 않았다. 짧은 시나리오가 빨라진 이유는 추정이다.
  - 공급자 모듈만 쓰는 프로세스에 SQLAlchemy 객체가 없어 GC 비용이 줄어든 영향으로 본다
  - DB 계층이 항상 로드되는 worker 프로세스에서는 이 차이를 기대하지 않는다

### 4.3 import 경계와 시간

`scripts/bench_imports.py --runs 7`. 모듈마다 새 interpreter에서 import하고, 7회 중앙값(괄호: 최소값)과 로드된 모듈을 기록한다.

| 모듈 | 기준선 ms | 통합본 ms | 비율 | 로드 모듈 수 | DB 계층·등록표 로드: 기준선 → 통합본 |
|---|---|---|---|---|---|
| `cremore_gitlab_provider.metadata.adapter` | 1573 (1213) | 644 (608) | 0.41 | 414 → 261 | `cremore.coverage.providers`, `cremore.coverage.store`, `sqlalchemy` → 없음 |
| `cremore_github_provider.metadata.adapter` | 1583 (1319) | 959 (723) | 0.61 | 459 → 300 | `cremore.coverage.providers`, `cremore.coverage.store`, `sqlalchemy` → 없음 |
| `cremore_gcp_provider.metadata.adapter` | 1411 (1289) | 646 (562) | 0.46 | 410 → 249 | `cremore.coverage.providers`, `cremore.coverage.store`, `sqlalchemy` → 없음 |
| `cremore_atlassian_provider.metadata.adapter` | 1347 (1259) | 1031 (762) | 0.77 | 401 → 266 | `cremore.coverage.store`, `sqlalchemy` → 없음 |
| `cremore_azure_provider.metadata.adapter` | 1333 (1250) | 835 (570) | 0.63 | 398 → 236 | `cremore.coverage.providers`, `cremore.coverage.store`, `sqlalchemy` → 없음 |
| `cremore_azure_provider.entra.adapter` | 1569 (1413) | 851 (535) | 0.54 | 398 → 237 | `cremore.coverage.providers`, `cremore.coverage.store`, `sqlalchemy` → 없음 |
| `cremore_azure_provider.arm.adapter` | 1529 (1107) | 771 (671) | 0.50 | 407 → 248 | `cremore.coverage.providers`, `cremore.coverage.store`, `sqlalchemy` → 없음 |
| `cremore_azure_provider.devops_tokens.adapter` | 1620 (1119) | 622 (489) | 0.38 | 397 → 235 | `cremore.coverage.providers`, `cremore.coverage.store`, `sqlalchemy` → 없음 |
| `cremore_notion_provider.metadata.adapter` | 1779 (1392) | 568 (514) | 0.32 | 397 → 235 | `cremore.coverage.providers`, `cremore.coverage.store`, `sqlalchemy` → 없음 |
| `cremore.coverage.collector_runtime` | 1343 (1200) | 686 (549) | 0.51 | 367 → 230 | `cremore.coverage.store`, `sqlalchemy` → 없음 |
| `cremore.coverage.providers` | 1317 (1148) | 642 (596) | 0.49 | 392 → 255 | `cremore.coverage.providers`, `cremore.coverage.store`, `sqlalchemy` → `cremore.coverage.providers` |
| `cremore.coverage.metadata_models` | 729 (608) | 652 (573) | 0.89 | 228 → 228 | 없음 → 없음 |
| `cremore.sources.registry` | 33 (26) | 39 (28) | 1.16 | 88 → 88 | 없음 → 없음 |
| `cremore.worker.worker` | 1485 (1241) | 1423 (1197) | 0.96 | 426 → 426 | `cremore.db`, `cremore.worker`, `sqlalchemy` → `cremore.db`, `cremore.worker`, `sqlalchemy` |
| `cremore.api.app` | 2370 (1881) | 2046 (1861) | 0.86 | 640 → 640 | `cremore.api`, `cremore.db`, `sqlalchemy` → `cremore.api`, `cremore.db`, `sqlalchemy` |

- **metadata 어댑터 9개**: 모두 SQLAlchemy·coverage store·어댑터 등록표를 로드하지 않게 됐다
  - 로드 모듈이 135~162개 줄었고, 시간 비율은 0.32~0.77이다
  - `collector_runtime`과 어댑터 등록표(`cremore.coverage.providers`)도 DB 계층 없이 import된다
- 콘텐츠 수집기 6개(GitLab·GCP·Confluence·Bitbucket·Azure Blob·Azure DevOps)
  - 호환 모듈 `cremore.source_config`를 거쳐 로드되던 콘텐츠 등록표(모든 공급자 source 모듈)가 빠져 모듈이 16개 줄었다
  - 시간 비율: 0.70~0.99
- source 모듈 9개와 schema 1 수집기·coverage 모듈 6개는 로드 모듈 수가 기준선과 같다(그래프 변화 없음)
- API·worker는 원래 DB 계층을 쓰므로 로드 모듈 수가 같다(640, 426). 시간 차이는 측정 편차 범위다.

7회 측정에서 비율이 1.05를 넘은 6개 모듈은 기준선과 통합본을 번갈아 21회씩 다시 쟀다.

| 모듈 | 기준선 중앙값(최소) ms | 통합본 중앙값(최소) ms | 비율 | import 그래프 안의 변경 모듈 |
|---|---|---|---|---|
| `cremore_gcp_provider.coverage` | 586.3 (417.5) | 629.2 (369.4) | 1.07 | 없음 |
| `cremore_aws_provider.collectors.s3` | 76.6 (44.8) | 62.6 (43.9) | 0.82 | 없음 |
| `cremore_atlassian_provider.confluence_source` | 16.6 (11.2) | 17.4 (11.4) | 1.05 | 자기 파일의 `INSTANCE_SCOPED` 한 줄 |
| `cremore.sources.registry` | 33.8 (25.8) | 30.7 (24.4) | 0.91 | `INSTANCE_SOURCES` 한 줄과 source 모듈 상수 |
| `cremore_notion_provider.collectors.notion` | 167.6 (127.1) | 179.0 (118.4) | 1.07 | 없음 |
| `cremore_aws_provider.coverage` | 715.1 (569.5) | 707.1 (602.8) | 0.99 | 없음 |

- 교차 측정에서 비율은 0.82~1.07이다
  - 1을 넘은 `gcp coverage`와 `notion` 수집기는 최소값이 오히려 통합본에서 더 낮다
  - 같은 모듈이 측정마다 1.07~1.29로 흔들렸다
- 셋은 import 그래프 안에 바뀐 모듈이 하나도 없어 통합이 원인일 수 없다(측정 편차)
- `confluence_source`의 +0.8 ms(최소값 +0.2 ms)는 상수 한 줄 추가에 해당하는 수준이다. 요구사항의 "미세한 차이" 예외에 들어간다

### 4.4 설치본(wheel)

- `scripts/installed_check.py` **통과**
  - 절차: `uv build --wheel --offline`으로 빌드 → 새 venv에 `--no-deps --no-index` 설치 → 저장소 밖에서 `python -I`로 실행
  - 패키지 10개의 포장 파일이 소스와 정확히 같다
  - 어댑터 10개, 콘텐츠 source 9개, 호환 경로 108개, 진입점 4개가 확인됐고, 오프라인 GitLab 수집이 58페이지를 돌았다
- 부정 검사: 포장된 리소스(`response-fields.json`)를 지우거나 추가 파일을 남기면 실패한다
- `fac0b7f`: `installed_check.py` 통과, `installed_tests.py` **1,782 통과, 66 skip, 9 제외, 실패 0**
  - 로컬에서는 해시 lock 설치를 재현하지 못했다(lock의 패키지가 모두 캐시에 있지 않았고 내려받지 않았다). 의존성은 시스템 site-packages를 썼다. lock 설치는 원격 CI가 확인한다
- 설치본 기준 경계: 어댑터 등록표와 어댑터 10개를 한 프로세스에서 import(3회)

  | wheel | 시간 | 모듈 수 | SQLAlchemy / coverage store |
  |---|---|---|---|
  | 기준선 `6616dae` | 1,711~1,937 ms | 534 | 로드 / 로드 |
  | 통합본 | 1,216~1,398 ms | 407 | 미로드 / 미로드 |

### 4.5 공개 API (`/openapi.json`)

- 기준선과 통합본의 OpenAPI 문서를 비교했다
  - 경로: 163개 → 169개. 추가된 6개는 모두 GCP OAuth(`/api/v2/gcp/oauth/*`)이다
  - **기존 경로 변경 0**
  - 스키마 추가 5개(`GcpOAuthStart`, `GcpOAuthFinish`, `GcpOAuthSession`, `GcpOAuthProjects`, `GcpOAuthComplete`), 변경은 `MetadataConnectionSpec.auth_type`에 `google_oauth` 추가 1건이다
- coverage `source_type` enum은 기준선과 같다(등록표에서 파생한 뒤에도 값·순서 동일)
- 통합 과정에서 G의 `Start`·`Finish`가 기존 수집기 스키마 이름을 밀어내는 문제를 찾아 고쳤다(`12061a3`)
  - 수정 전 코드에서는 회귀 테스트가 실패한다
  - 리뷰 후 나머지 일반 이름(`Session`, `Projects`, `Complete`)도 공개 전에 `GcpOAuth` 접두사로 바꿨다

### 4.6 웹과 경계 테스트

- 웹: tsc 통과, 단위 504개 통과, 빌드 통과, 브라우저 검사 28/28 통과
  - PR-5 상태에서 실행했고, G의 Google 연결 화면 검사를 포함한다
  - 그 뒤 웹 변경은 `570d0e7`의 대기 사유 문구뿐이다. `fac0b7f`에서 tsc, 단위 504개, 빌드를 다시 통과했다. 브라우저 검사는 로컬에서 다시 돌리지 않았다(원격 CI의 browser job)
- Helm 차트 테스트 71개 통과(최종 HEAD). ruff 전체 검사(`cremore`, 공급자 backend 8개, `scripts`) 통과, `git diff --check` 통과
- `cremore/provider_boundaries_test.py` 43개 통과
  - 공급자 모듈 31개의 새 프로세스 경계, 호환 경로 108개, 오프라인 수집 6종, 공급자별 플랫폼 import 허용 목록

### 4.7 독립 코드 리뷰

통합 diff(`6616dae..5de815e`, 문서 포함)를 별도 리뷰어가 검토했다.
- 판정은 COMMENT(차단 사유 없음)였다. CRITICAL 0, HIGH 0, MEDIUM 2, LOW 11
- 동작 보존(OpenAPI, 파생 목록 값·순서, 탐지 digest, 옮긴 코드의 AST 동일성), import 순환·비용, 보안 영역에서는 지적이 없었다

반영한 것
- 웹 parity 검사가 모든 backend source에 UI를 강제하던 문제
  - 웹 등록표는 `CONTENT_SOURCE_TYPES`의 부분집합이면 된다
  - backend 목록과 웹 상수의 일치는 유지한다
- 로컬 설치본 검사 절차가 이전 설치를 다시 검사할 수 있던 문제
  - 새 임시 dist, `venv --clear`
  - 벤치마크 결과를 저장소 밖에 쓴다
- 경계 테스트
  - checkout 경로에 `tests`/`qa`가 있으면 허용 목록 검사를 건너뛰던 문제를 고쳤다(상대 경로 사용)
  - 새 `<vendor>/backend`가 목록에서 빠지면 실패하는 검사를 추가했다
  - PyJWT·protobuf 같은 범용 라이브러리를 SaaS SDK로 보지 않게 했다
- `installed_check.py`
  - wheel 패키지 목록을 `pyproject.toml`에서 읽는다
  - `git ls-files -z`와 루트 `.gitignore`만 써서 hatchling과 같게 맞췄다
  - `-O` 실행을 거부한다
- GCP OAuth 요청 모델 5개의 OpenAPI 이름을 모두 `GcpOAuth*`로 통일했다
- 주석
  - 옮긴 import 15곳과 `INSTANCE_SCOPED` 9곳에 이유·의미를 적었다
  - `validate_record`의 방어 분기를 설명했다
- 문서
  - 기존 순서를 고정하는 호환 테스트도 함께 갱신해야 한다는 점
  - OS별 skip 기준
  - guard 누락 시 동작
  - 진행 중인 공급자 브랜치를 합칠 때의 이전 표(§3)

남긴 것(리뷰어도 차단 사유가 아니라고 봤다)
- 전체 CI의 30분 제한 안에 wheel 검사가 들어가는지는 첫 수동 실행에서 확인한다
- `_lazy_oauth_token`은 잠금이 없다. 현재 요청이 순차적이라 문제없다. 병렬 요청을 도입하면 토큰 갱신이 중복될 수 있다

### 4.8 1차·2차 리뷰 후속 (2026-09-26)

외부 리뷰 두 건의 지적을 코드와 재현으로 다시 확인한 뒤 고쳤다. 커밋은 §2 표에 있다.

| 리뷰 | 지적 | 확인 결과 | 조치와 근거 |
|---|---|---|---|
| 1차 ① | GCP 토큰 갱신의 일시 오류 | 실제 결함 | 수정 전: 첫 갱신 429·503 → FAILED, 수집 중 429 → PARTIAL과 토큰 요청 8회. 수정 후 WAITING(Retry-After 120초 반영), 토큰 요청 2회. 새 테스트 8개가 수정 전 코드에서 실패 |
| 1차 ② | 등록표가 선택 SDK를 끌어올 위험 | 설계 위험(현재 위반 0) | 등록표·`cremore.db`·API·worker import를 `google.*`·`azure.identity` 차단 상태에서 검사 |
| 1차 2-1 | 공급자 간 import, PR 검사 | 공백(현재 위반 0) | 공급자 간 import 금지 테스트, PR마다 도는 `boundaries` job |
| 1차 ③ | 수집 비교 도구의 한계 | 도구 결함 | 모든 표본·checkpoint·이유·대기 시간·요청 순서 비교. 기준선 대비 16/16 동일 |
| 1차 ④ | OAuth 동시성의 PostgreSQL 검사 없음 | 공백 | PostgreSQL에서 한 세션을 6개 요청이 동시에 완료해도 연결 1개. 행 잠금 제거 변이 8/8 실패 |
| 2차 ① | S의 검사 이식 | 부분 타당. 실제 공백은 Azure Blob·DevOps | 콘텐츠 계약 90개(Azure 2종 추가), schema 2 PostgreSQL 2개. 공급자별 범위 변이가 각 5건 실패 |
| 2차 ② | CI 설치본이 운영 lock과 다름 | 타당 | Docker와 같은 lock 설치·`--no-deps`·`pip check`, 설치본 테스트 추가 |
| 2차 ③ | 원격 전체 CI | `8e92cfe`에서 이미 실행 | §5. `5b7ec41`에서 다시 실행해 모든 job 통과 |
| 2차 ④ | AWS 폴더의 플랫폼 기능 | 타당 | AGENTS.md에 공통 검토 모듈 명시, import 시 DB 로드 모듈을 테스트로 고정. CODEOWNERS는 팀 GitHub 계정이 필요해 보류 |
| 2차 ⑤ | GitHub 라이브러리의 비밀 해석 | 부분 타당 | 해석은 worker, GitHub 라이브러리는 해석된 자격증명으로 조회만 한다 |
| 2차 ⑥ | finding 상세·SAS 조회 성능 | 기준선부터 있던 비용. 측정 후 개선 | 일회용 PostgreSQL 합성 데이터: 1,462→484 ms, 11,149→128 ms. 이전 조회와 결과가 같은지 테스트한다(SAS는 메모리·SQLite·PostgreSQL) |
| 2차 ⑦ | Azure DevOps 큰 저장소 | 타당 | 응답 상한 초과 시 같은 커밋·변경집합으로 폴더 단위 조회. 루트 밖 경로는 요청하지 않음. 새 테스트 3개가 수정 전 코드에서 실패 |
| 2차 ⑧ | 기준 구조 결정 | 팀 결정 | §5 |
| 2차 ⑨ | 비밀값 읽기 기능의 정책 | 팀 결정 | [정책 제안](../SECRET_VALUE_READING_POLICY.md) |

- 2차 리뷰의 "worker 로드 모듈 467 → 407"은 `6616dae` 기준으로 재현되지 않았다. 이 기록의 측정은 426 → 426이다(§4.3).
- 모든 새 테스트는 fake transport·합성 데이터만 쓴다. 외부 요청을 막은 상태에서 전체 pytest를 돌렸다.

### 4.9 develop_github 기능 이식 (2026-09-26~27)

`origin/develop_github`(`da1bc3a`, GitHub 담당자의 독립 수집기)는 git으로 합치지 않았다. 루트에 두 번째 웹·compose·
같은 이름의 `cremore_collectors` 패키지를 되살리고 충돌 9건이 난다. 대신 파일 183·CLI 인수 142·경로 43·API 37·
테스트 176을 기능 72개로 전수 대조하고, 우리에게 없거나 부족한 기능을 이 브랜치의 구조로 옮겼다.

| 묶음 | 커밋 | 내용 |
|---|---|---|
| A·B·C | `f4ab0a9` `f8bee25` `5e2a8bf` `52fa140` `01df17a` | 감사 로그 두 cursor, 안정 식별자, 수집 범위 옵션, Enterprise 감사 classic PAT(봉인), 감사↔자격증명 정확 연결 |
| E | `e462c55` | App ID 또는 Client ID, 매 수집 `GET /app` 신원 확인·기록, 콘텐츠 연결 점검의 App 확인 |
| H | `fe74768` `9eb2705` `d70d43a` | 읽기 항목별 필요 권한 표·조직별 설치 상태, 설치 확인 실행(자격증명 수집 없음), 감사 연결 보기 |
| D | `896d874` `041becb` | 실행 시간 상한, 메타데이터 수집 일시중지·재개·중지 |
| F | `95ae835` `876b595` | github-org 안내 정정, 제품 어댑터를 쓰는 CLI(수집기 API 제출 포함) |
| 보정 | `70933b5` | 경계 허용 목록(GitHub의 `cremore.coverage.errors`) |

공통(플랫폼) 파일 변경 — 플랫폼 담당 검토 대상:

- `cremore/coverage/metadata_models.py`: GitHub 전용 옵션 4개(`actions_run_days`·`audit_scope`·`enterprise_only`·`run_time_limit_minutes`, 다른 공급자는 기본값만), 관리 토큰 해시 규칙
- `cremore/api/metadata_coverage.py`: Enterprise 감사 PAT 봉인, 설치 확인 요청, 감사 연결 보기, 수집 일시중지·재개·중지, 조직 목록의 설치 확인 덮어쓰기
- `cremore/coverage/metadata_job.py`·`cremore/db/task_store.py`: 일시중지(설정 `metadata_collection_pause:<연결>`)와 중지한 실행 닫기
- `cremore/coverage/providers/__init__.py`: GitHub 재수집 등록(설치 확인만)
- `cremore/provider_boundaries_test.py`·`cremore/coverage/collector_runtime_test.py`: 위 등록에 맞춘 허용 목록·기대값
- 웹 공통: `provider-inventory.tsx`(옵션 입력·수집 제어 버튼), `provider-metadata.ts`, `source-setup.tsx`, `sources.tsx`

검증(`d70d43a`):

- 전체 pytest(외부 요청 차단, 일회용 PostgreSQL 17): 6,678 통과, 59 skip(Windows에서 돌 수 없는 POSIX 검사), 실패 0. 리뷰 후속(`760d9b0`) 뒤 6,692 통과, 같은 59 skip, 실패 0
- 새 테스트는 변경 전 코드에서 실패함을 확인했다: E의 새 테스트는 변경 전 소스에서 모두 실패(가져오기 실패 포함), 나머지는 기능별 변이 26건이 모두 테스트에 걸렸다
- 웹: 단위 510 통과, `tsc --noEmit`·`npm run build` 통과. 브라우저 검사는 GitHub 화면용 시나리오가 없어 돌리지 않았다
- 기능 대조 재검사: 72개 중 동일 47·우리가 더 발전 6·해당 없음 19, 부분 구현·미구현 0. 검사기가 틀린 입력 8종을 모두 잡는지도 확인했다

미검증:

- 실제 GitHub 호출(App 신원, 설치 목록, 조직 설치 권한)은 하지 않았다. 필요 권한 표의 권한 이름은 GitHub REST 문서 기준이며 실제 설치와 대조하지 않았다
- 원격 CI와 push는 공통 파일 검토 뒤로 보류했다

#### 4.9.1 리뷰 후속 (2026-09-27)

이식한 코드를 자체 재현과 독립 리뷰(결론을 모르는 별도 리뷰어)로 다시 검토했다. 높음·중간 지적과 불필요한 추가를
고쳤고, 각 수정은 수정 전 코드에서 실패하는 테스트로 확인했다.

| 지적 | 문제 | 수정 | 커밋 |
|---|---|---|---|
| 높음 | 연결 점검이 App 이름을 `workspace`에 기록 → 스캔 승인 revision이 바뀌어 승인된 범위가 모두 `NEEDS_SCOPE_REVIEW` | 기록하지 않음(App 확인·다른 키 거부는 유지) | `2028d27` |
| 높음 | 옵션 추가로 모든 공급자의 scope digest가 바뀜 → 저장 이력(receipt)이 업그레이드 전 연결의 새 실행을 계속 거부, 대기 중 실행 실패, 업그레이드 전후 비교·재수집 거부 | 저장된 계약을 오늘의 모델로 읽어 비교(`same_contract`·`scope_matches`) | `8061349` |
| 중간 | 설치 확인이 20번 넘게 이어지면 조직 목록이 비고 추가 확인 거부 | 수집 실행을 찾을 때까지 실행 목록을 넘김 | `6b444ea` |
| 중간 | 일반 재수집에 설치 확인 실행을 기준으로 주면 모든 조직을 미설치로 표시 | 확인 실행은 기준 불가, 목록은 대상 조직만 미설치로 판정 | `6b444ea` |
| 중간 | 일시중지가 저장소의 실행 수명(6시간)을 넘기면 실행 실패, 실행 시간 상한 360분 이상은 적용 불가 | 수명 10분 전 부분 완료로 닫음(`METADATA_COLLECTION_PAUSE_EXPIRED`), 상한 300분. GitHub 어댑터가 일시중지를 실패로 기록하던 경로도 차단 | `5f0549e` |
| 중간 | 감사 연결 보기가 요청마다 실행 전체를 다시 읽고 계산(상한 없음) | 조인에 필요한 필드만(약 20%), 감사 기록 5만 건 상한, 끝난 실행은 한 번 계산한 결과 재사용 | `d2bb88e` |
| 불필요 | 백엔드가 제공하지 않는 github-org 화면 수정 | 되돌림 | `ed46b12` |
| 불필요 | 쓰지 않는 별칭, 저장되지 않는 `account_login`, 조직 목록 응답의 권한 표 중복, 조직 연결의 감사 토큰 입력 | 제거·Enterprise 연결에만 표시 | `760d9b0` |

남은 것(이번 범위 밖):
- 낮음 지적은 4.9.2에서 고쳤다
- 문서와 어긋나는 가정: GitHub 문서의 App 설치 토큰 사용 가능 목록에 SSO 승인(`/orgs/{org}/credential-authorizations`)과 조직 감사(`/orgs/{org}/audit-log`)가 없다(문서상 classic PAT·OAuth의 `read:org`·`read:audit_log`). 이식한 어댑터는 두 source를 App 토큰으로 읽으므로 실계정에서는 실패할 가능성이 높다. 조직용 PAT 지원 여부는 설계 결정이고 실계정 확인이 필요하다
- 업그레이드 때 대기 중이던 수집은 자체 checkpoint를 전체 digest로 고정하는 공급자(GitHub·GCP·Azure·Notion)에서 한 번 실패한다([수집기 라이브러리](../METADATA_COLLECTOR_LIBRARIES.md))
- GitHub CLI 정리는 사용자 결정에 따라 뒤로 미룸

#### 4.9.2 낮음 지적 수정 (2026-09-27)

리뷰어의 낮음 지적 L2~L7을 고쳤다(L1은 `5f0549e`). 각 수정의 새 테스트가 수정 전 코드에서 실패함을 변이로 확인했다.

| 지적 | 문제 | 수정 | 커밋 |
|---|---|---|---|
| L2 | 잘못된 App 키·다른 App의 키로도 실행이 `PARTIAL`(작업 성공)으로 끝남 | `GET /app` 확인이 멈추거나 App 자격 코드가 나오면 실행 `FAILED`(작업 실패). 다른 읽기의 중단은 `PARTIAL` 유지 | `eb8f28e` |
| L3 | 감사 토큰이 없어도 삭제 요청이 revision을 올림 | 지울 토큰이 없으면 연결을 그대로 반환 | `5a2348c` |
| L4 | 선택 비밀 `audit_token`을 해석하지 못하면 실행 전체 실패 | descriptor의 `optional_secret_roles`: 해석 못 한 선택 역할은 빼고, Enterprise 감사만 `GITHUB_ENTERPRISE_AUDIT_TOKEN_UNAVAILABLE`로 실패 | `97ee021` |
| L5 | 실행이 열리기 전의 일시중지는 무기한(연결의 작업 자리를 차지), 점검마다 설정을 별도 트랜잭션으로 읽음 | 일시중지 요청 시각부터 실행 수명과 같은 시간이 지나면 작업을 `METADATA_COLLECTION_PAUSE_EXPIRED`로 끝냄. 일시중지는 점검과 같은 트랜잭션에서 읽음 | `3b73f93` |
| L6 | 읽지 않은 조직의 권한 상태가 시작 읽기만 보고, Enterprise 감사를 대신할 뿐인 조직 감사를 셈 | 저장소별 읽기·후속 읽기까지 계획에 넣고(페이지 처리와 같은 함수), 대체용 조직 감사는 제외. 계획과 실제 생성 작업을 비교하는 테스트 추가 | `8c67c9b` |
| L7 | 이 App의 설치 조회가 조직 설치 목록과 같은 `installation:<ID>`를 다른 모양으로 한 번 더 관측 | App 자신의 조회는 context `appInstallation:<ID>` 근거로 분리 | `c11d228` |

공통(플랫폼) 파일 변경: `cremore/coverage/metadata_auth.py`·`collector_runtime.py`·`providers/__init__.py`(선택 비밀 역할),
`metadata_job.py`(일시중지 기한·트랜잭션), `cremore/api/metadata_coverage.py`(감사 토큰 삭제), `provider-inventory.tsx`(일시중지 안내 문구).

검증(`c11d228`): 전체 pytest(외부 요청 차단, 일회용 PostgreSQL 17) 6,707 통과, 59 skip(Windows에서 돌 수 없는 POSIX 검사), 실패 0.
영향 스위트(GitHub·coverage·api·worker·db·scanning·경계) 통과, 웹 단위 511·`tsc --noEmit`·`npm run build` 통과. 변이 24건이 모두 새 테스트에 걸렸다.

남은 것:
- 사소한 지적: 무관한 작업이 진행 중이어도 설치 확인 요청이 202를 반환, `audit_pair`가 비어 있지 않은 `before`를 받음
- 새로 찾은 기존 문제: native export의 조직 보기에 조직 App 설치 목록(`org_installations`)과 Enterprise 설치 목록 레코드가 들어가지 않는다(`snapshot._owner`가 `account.login`을 보지 않음). 이식 전부터 있던 동작이며, 고치려면 Enterprise·조직 목록이 같은 설치를 여러 번 기록하는 것을 설치 ID로 합쳐야 한다

#### 4.9.3 CloudTrail S3 읽기 범위·UI 공백·CLI 정리·Atlassian #35 이식 (2026-09-27)

| 변경 | 내용 | 커밋 |
|---|---|---|
| CloudTrail S3 읽기 | 설정 prefix 아래 전체를 읽던 것을 문서화된 경로 형식(`AWSLogs/[<조직 ID>/]<계정 ID>/CloudTrail/<리전>/<날짜>/`)대로 연결 계정·설정 리전·기간(하루 여유)만 나열·다운로드. 합성 측정: 계정 20개 조직에서 한 계정 요청 21,922→33, 계정 100개는 5만 객체 후 `LOG_OBJECT_LIMIT`로 실패하던 것이 33 요청에 완료 | `057aa9a` |
| 감사 연결 보기 | 5만 건 한도 오류를 일반 불러오기 실패로 보이던 것을 한도·대안 안내로 | `7d7654f` |
| native export | 모든 공급자의 끝난 실행 상세에 JSON 받기 버튼(에디션 선언 우선), 1만 건·8MB 한도 안내 | `fbb891f` |
| 사유 코드 | 플랫폼·GitHub 사유와 작업 오류 코드를 한국어·영어 문구와 코드로 표시, 다른 코드는 그대로 | `fbb891f` |
| 선택 비밀 역할 | 연결 폼에 "(선택)" 표시. GitHub는 `installation_id`도 선택(관리정보 수집이 쓰지 않음) | `fbb891f` |
| CLI 정리 | GCP 독립 CLI 5개와 그것들만 쓰던 모듈 5개·ADC transport·문서·requirements, `gitlab/standalone` 전체 삭제. `cremore_gcp`는 제품이 쓰는 `linkage`·`resources`·`transport`·`values`만 유지. GitHub·Atlassian CLI는 유지 | `25c9f98` |
| Atlassian Preview 계약 | main에만 있던 `be22471`(PR #35)을 이동된 `atlassian/backend/cremore_atlassian_provider/`로 이식(병합 없음). OAuth count를 발견한 서비스 계정 ID 배열(요청당 최대 100)로 요청하고 요청 계정의 목록과만 비교, OAuth 배열은 `pagination_contract_unverified`, 토큰 발급자·계정 필드 보존. 한 배치가 다른 배치의 계정 수를 돌려주는 경우의 회귀를 추가하고 Atlassian README·기록·CHANGELOG를 확인된 계약으로 갱신. PR #36(작업 재개 안내 문서)은 사용자 결정으로 제외 | `f4fbb5d` |

검증: 전체 pytest(외부 요청 차단, 일회용 PostgreSQL 17) 6736 통과, 59 skip(Windows에서 돌 수 없는 POSIX 검사), 실패 0.
웹 단위 517·`tsc --noEmit`·`npm run build` 통과. S3 변이 7건·UI 변이 13건·Atlassian 이식 변이 6건이 모두 테스트에 걸렸고,
CLI 잔여 참조 검사가 삭제된 모듈 이름을 넣은 음성 대조를 잡는다. 실제 S3 버킷·조직 trail, Atlassian 조직과 브라우저 화면은 확인하지 않았다.

main 반영: 사용자 결정으로 main을 이 브랜치와 같은 커밋으로 맞춘다. main에만 있던 #35·#36 커밋은 `git merge -s ours`로
이력에만 남고 파일은 이 브랜치 그대로다(#36의 작업 재개 문서·README 안내 제외). 같은 날 커밋 메시지의 공동 작성자 표기를
지우면서 main과 갈라진 뒤의 커밋 ID가 모두 바뀌었다. 커밋마다 트리·작성자·날짜는 같고, 문서의 ID는 새 ID로 고쳤다.
이전 ID는 [커밋 ID 대응표](COMMIT_ID_MAP_2026-09-27.md)에서 찾는다.

## 5. 남은 일과 미검증

- **실제 공급자 호출은 검증하지 않았다.** 모든 수집 검사는 합성 transport·fake client로 했다(팀 규칙).
- 로컬 skip(`fac0b7f`, Windows)
  - PostgreSQL URL 없이 83개. 일회용 PostgreSQL을 지정하면 59개(Windows에서 돌 수 없는 POSIX 검사)
  - 둘 다 전체 CI(Linux, PostgreSQL 서비스)에서 돈다
- 전체 CI(수동 `workflow_dispatch`)
  - `8e92cfe`에서 처음 실행했다(run 36228409611). python 3.12·3.14(각 약 13분), web, browser, 컨테이너 2개는 통과했다
  - api 컨테이너는 Trivy 비밀 검사가 코드 주석의 문자열을 오탐해 실패했다. `39aacff`에서 고쳤다
  - 리뷰 후속을 포함한 `5b7ec41`에서 다시 실행했다(run 36237584059). **모든 job 통과**
    - python 3.12·3.14(Linux, PostgreSQL 서비스): pytest 6,678 통과·skip 0, 해시 lock 설치본 검사 통과, 설치본 테스트 1,848 통과·9 제외, 독립 GitLab·GCP 도구 테스트 통과
    - 소요 시간: python 3.12 약 16분, 3.14 약 15분(제한 30분)
    - web, browser, boundaries, 컨테이너 3개(api·web·oauth2-proxy, Trivy 포함) 통과
- 보류한 항목
  - GitLab 독립 도구 일원화: GitLab 담당자의 결정이 필요하다
  - 계약 패키지 분리: 외부 배포 요구가 없다
  - 공급자 선언형 옵션·fact 이름: fact 허용 목록은 비밀값 저장을 막는 안전장치라 설계만 남겼다
  - `.github/CODEOWNERS`: AWS 공통 검토 모듈의 검토자를 지정하려면 팀의 GitHub 계정이 필요하다
  - AWS 폴더의 로그인·세션·승인·키 조치 기능을 플랫폼으로 옮기는 일: 공통 검토 대상으로 명시만 했다
  - AWS·Vault 서버 수집의 별도 신원: [정책 제안](../SECRET_VALUE_READING_POLICY.md)의 팀 결정 뒤에 정한다

### 기준 구조 결정 (2차 리뷰 ⑧, 제안)

- 제안: 이 브랜치(R의 공급자별 디렉터리 구조 + S의 경계 원칙·검사)를 기준 구조로 삼는다.
- S(`refactor/saas-libraries`)의 코드는 합치지 않는다. 폴더 구조가 달라 함께 합칠 수 없다.
  - S의 검사 중 필요한 것은 옮겼다: 새 프로세스 경계, 설치본 검사, `machine_guard`, 콘텐츠 계약 테스트, schema 2 PostgreSQL 테스트
- 리뷰가 병합 전 조건으로 든 세 가지
  - ① 검사 이식: 완료(`af6f4c7`, `3d59233`)
  - ② CI 설치본을 운영 lock 기준으로: 완료(`ffd80c3`). lock 설치는 원격 CI에서 확인한다
  - ③ 원격 전체 CI: `5b7ec41`에서 모든 job 통과(위 CI 항목)
- `main` 병합은 팀의 명시적 승인 뒤에 한다. 이 기록은 그 결정을 대신하지 않는다.

## 6. 다른 환경에서 검증하기

Windows·macOS·Linux 모두 저장소 루트에서 실행한다. 준비:

```bash
git fetch origin
git switch integration/saas-structure
python -m pip install -e ".[dev,gcp,azure]"
git worktree add ../cm-baseline 6616dae
```

Bash(macOS·Linux):

```bash
export AWS_EC2_METADATA_DISABLED=true
python -m pytest -q -ra
python -m pytest -q cremore/provider_boundaries_test.py cremore/sources/module_contract_test.py cremore/api/app_test.py
python -m ruff check cremore aws/backend gcp/backend github/backend gitlab/backend notion/backend atlassian/backend azure/backend vault/backend scripts
out=$(mktemp -d)   # results and the wheel stay outside the checkout
python scripts/bench_imports.py --root ../cm-baseline --runs 7 --output "$out/imports_before.json"
python scripts/bench_imports.py --root . --runs 7 --output "$out/imports_after.json"
python scripts/bench_collectors.py --root ../cm-baseline --repeat 15 --output "$out/collectors_before.json"
python scripts/bench_collectors.py --root . --repeat 15 --output "$out/collectors_after.json"
# Installed wheel, built and installed like CI and the production image (hash-pinned locks).
python -m venv --clear "$out/build" && "$out/build/bin/pip" install --require-hashes -r requirements-build.txt
"$out/build/bin/pip" wheel --no-deps --no-build-isolation -w "$out/dist" .
python -m venv --clear "$out/venv" && "$out/venv/bin/pip" install --require-hashes --only-binary :all: -r requirements.txt
"$out/venv/bin/pip" install --no-deps "$out"/dist/cremore-*.whl && "$out/venv/bin/pip" check
(cd "$out" && "$out/venv/bin/python" -I "$OLDPWD/scripts/installed_check.py" --source "$OLDPWD")
"$out/venv/bin/pip" install "pytest>=8.3" "jsonschema>=4.23" "rfc3339-validator>=0.1.4"
(cd "$out" && "$out/venv/bin/python" -I -X utf8 "$OLDPWD/scripts/installed_tests.py")
(cd web && npm ci --ignore-scripts && npm test && npx tsc --noEmit && npm run build)
```

PowerShell(Windows):

```powershell
$env:AWS_EC2_METADATA_DISABLED = 'true'
python -m pytest -q -ra
python -m pytest -q cremore/provider_boundaries_test.py cremore/sources/module_contract_test.py cremore/api/app_test.py
python -m ruff check cremore aws/backend gcp/backend github/backend gitlab/backend notion/backend atlassian/backend azure/backend vault/backend scripts
$out = (New-Item -ItemType Directory -Path (Join-Path $env:TEMP "cremore-check-$(Get-Random)")).FullName
python scripts/bench_imports.py --root ..\cm-baseline --runs 7 --output "$out\imports_before.json"
python scripts/bench_imports.py --root . --runs 7 --output "$out\imports_after.json"
python scripts/bench_collectors.py --root ..\cm-baseline --repeat 15 --output "$out\collectors_before.json"
python scripts/bench_collectors.py --root . --repeat 15 --output "$out\collectors_after.json"
python -m venv --clear "$out\build"; & "$out\build\Scripts\pip" install --require-hashes -r requirements-build.txt
& "$out\build\Scripts\pip" wheel --no-deps --no-build-isolation -w "$out\dist" .
python -m venv --clear "$out\venv"; & "$out\venv\Scripts\pip" install --require-hashes --only-binary :all: -r requirements.txt
& "$out\venv\Scripts\pip" install --no-deps (Get-ChildItem "$out\dist\cremore-*.whl").FullName; & "$out\venv\Scripts\pip" check
$repo = (Get-Location).Path; Push-Location $out
& "$out\venv\Scripts\python" -I "$repo\scripts\installed_check.py" --source $repo
& "$out\venv\Scripts\pip" install "pytest>=8.3" "jsonschema>=4.23" "rfc3339-validator>=0.1.4"
& "$out\venv\Scripts\python" -I -X utf8 "$repo\scripts\installed_tests.py"; Pop-Location
Push-Location web; npm ci --ignore-scripts; npm test; npx tsc --noEmit; npm run build; Pop-Location
```

판정 기준
- pytest: 실패 0.
  - Windows에서 `CREMORE_TEST_POSTGRES_URL` 없이 돌리면 skip은 83개다(POSIX 59, PostgreSQL 24)
  - Linux·macOS는 POSIX 검사가 실행되고, URL을 설정하면 PostgreSQL 검사도 실행된다
- 전체 CI(수동 실행)의 python job 제한 시간은 30분이다. wheel 검사가 추가됐으므로 첫 실행에서 시간을 확인한다.
- 수집 digest: `bench_collectors` 결과의 시나리오별 `digest`가 기준선과 같아야 한다. 다르면 수집 데이터가 바뀐 것이다.
- import: 공급자 모듈에 `sqlalchemy`·`cremore.coverage.store`가 없어야 한다. 시간은 환경마다 다르므로 같은 기계의 두 트리를 비교한다.
- 설치본 검사: `installed wheel check passed`가 출력되고 `installed_tests.py`가 실패 0으로 끝나야 한다.
  - 설치본 테스트는 저장소 파일(`deploy/` 템플릿, 소스 트리)이 필요한 AWS 테스트 9개를 이름으로 제외한다(스크립트에 목록과 이유)
- 메모: lock 설치는 패키지를 내려받는다. 오프라인에서는 lock의 패키지가 모두 캐시에 있어야 한다.

## 7. 참고

- 공통 작업 지침: [AGENTS.md](../../AGENTS.md), [팀 코딩 지침](../AI_TEAM_CODING_GUIDE.md)(콘텐츠 source 추가 절차, 검증 명령 10절)
- GCP 대시보드 OAuth 설명서: [GCP_DASHBOARD_OAUTH_KO.md](GCP_DASHBOARD_OAUTH_KO.md)(2026-09-26 통합 기록 포함)

## 8. 검증·피드백 요청 프롬프트

아래를 다른 로컬 환경의 AI 코딩 도구에 그대로 붙여 넣는다.

````text
CreMore 저장소의 `integration/saas-structure` 브랜치를 검증하고 피드백해 줘. 답변은 한국어로 한다.

[배경]
- CreMore는 평문 자격증명 노출을 찾아 대응을 돕는 자체 호스팅 보안 플랫폼이다.
  공급자 발급 목록 × 평문 노출 × 금고 보관을 대조한다. 핵심 판정은 "발급했는데 금고에 없음"이다.
- 팀원마다 담당 SaaS가 다르다. 이 브랜치는 공급자별 수집기를 독립적으로 고도화할 수 있도록 세 브랜치를 통합했다.
  - 기준: refactoring 6616dae
  - codex/gcp-dashboard-oauth: 기능 cherry-pick
  - refactor/saas-libraries: 경계 원칙·검증 방식만 이식
- 먼저 AGENTS.md, docs/AI_TEAM_CODING_GUIDE.md, docs/integration/SAAS_STRUCTURE_INTEGRATION_KO.md를 끝까지 읽는다.
  문서 설명을 근거로 쓰지 말고 실제 코드와 대조한다.

[지킬 규칙]
- 실제 공급자 API 호출, 발견한 자격증명 검증, 운영 DB 접근을 하지 않는다. 합성 데이터와 fake client만 쓴다.
- 비밀값·토큰을 로그나 출력에 남기지 않는다.
- 코드를 고치지 말고, commit·push도 하지 않는다. 문제를 찾으면 재현 방법과 함께 보고만 한다.
- `git status --short --branch`로 브랜치와 작업 트리가 깨끗한지 먼저 확인한다.

[검증할 것]
1. 통합 문서 §6의 명령을 이 환경의 OS에 맞게 실행한다.
   - 전체 pytest, 경계·계약 테스트, ruff
   - 기준선 worktree(6616dae)와의 bench_imports·bench_collectors 비교
   - 설치본(wheel) 검사, 웹 테스트·타입 검사·빌드
2. 통합 문서 §4의 수치와 이 환경의 결과를 비교한다. 수집 digest는 반드시 같아야 한다.
   - 시간 차이는 기준선 대비 비율로 본다.
   - 악화가 있으면 모듈·시나리오 이름과 수치를 적는다.
3. 다음 변경을 코드로 직접 확인한다.
   - GCP discovery: `google_oauth` 연결은 사용자 OAuth 토큰만 쓰고 worker ADC로 대체하지 않는가
     (`gcp/backend/cremore_gcp_provider/metadata/adapter.py`)
   - 옛 import 경로가 새 정의와 같은 객체인가
     (`CoverageError`, `cremore.coverage.providers.facts`, 호환 경로 108개)
   - 공급자 모듈 import가 DB 계층·API·다른 SaaS SDK를 로드하지 않는가
   - `/openapi.json`: 기존 경로 변경이 없고, 차이는 GCP OAuth 경로 6개·`GcpOAuth*` 스키마 5개·`google_oauth` 추가뿐인가
   - `INSTANCE_SOURCES`·API `source_type`·규칙 `scope_sources`·웹 source 목록이 등록표에서 파생되고, 값·순서가 이전과 같은가
   - `machine_guard`: GitLab만 True이고, guard가 없는 어댑터는 로드할 때 실패하는가
   - 리뷰 후속(§4.8): GCP 토큰 일시 오류가 WAITING으로 재개되는가, GitLab Self-managed 토큰 검증이 등록 인스턴스에만
     요청하는가, Azure DevOps 목록 분할이 루트 밖 경로를 요청하지 않는가, finding 상세·SAS 일괄 조회 결과가 이전과 같은가
4. 구조 피드백: 새 SaaS 담당자가 콘텐츠 source나 metadata adapter를 추가할 때 고쳐야 하는 파일이 문서 §3과 같은가?
   공통 파일 수정이 더 필요한 곳이 있으면 적는다.

[보고 형식]
- 환경: OS, Python·Node 버전, 실행한 명령
- 결과표: 항목 | 기대 | 실제 | 판정(통과/실패/미실행)
- 성능표: 기준선 대비 import·수집 시간 비율, digest 일치 여부
- 발견한 문제: 파일:줄, 재현 방법, 영향, 제안
- 구조 피드백과 질문
- 실행하지 못한 검사와 그 이유(예: Windows의 POSIX 검사, PostgreSQL URL 없음)
````
