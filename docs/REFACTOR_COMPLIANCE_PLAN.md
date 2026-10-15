# 두 개발 지침 준수 보완 계획

기준 커밋: `daab6b6112870c975d240c6f7f89b4e1d6d1c098` (2026-09-23).
이 문서는 보완 계획과 그 실행 결과를 함께 기록한다. 사용자 요구는 전체 구조 확인과 함께
유지보수·SaaS/cloud 확장·스타일 소유·실제 코드 중복을 두 지침에 맞게 개선하는 것이다.

## 확인한 기준 상태

* 보완 작업 시작 시 기존 최종 inventory 615개 파일의 SHA-256이 소스와 모두 일치했다.
* 전체 140,424행: 제품·배포 89,715행, 테스트·독립 QA 참조 50,709행.
* Python 437개 파일을 AST로 읽고, 제품 모듈 256개의 정적 import 관계를 조사했다.
  Domain의 vendor/HTTP framework import, 하위 계층의 API/worker 역참조,
  독립 CLI의 플랫폼 내부 import는 발견되지 않았다.
* Frontend TypeScript 77개 파일과 CSS 5개 파일을 실제 TypeScript/PostCSS parser로 조사했다.
  pure lib의 React view 역참조와 정적 inline style은 없었다.
* CSS 9,505행 중 `web/styles/globals.css`가 7,891행이다. 파일 전체가 전역 관심사만
  소유하지 않으며 여러 기능과 공통 UI의 규칙, 뒤에 덧붙인 override가 섞여 있다.
* 공급자 metadata 계약·명시적 registry는 이미 존재한다. 콘텐츠 수집, metadata 수집,
  저장/인증 및 UI 등록 경로를 각각 추적하고 실제 확장에 필요한 수정 지점을 검증한다.

## 요구사항과 완료 증거

원문은 `AI_ALWAYS_ON_PROJECT_CODING_GUIDE.md`의 99개 절과
`POST_REFACTOR_AI_TEAM_GUIDE_REQUIREMENT.md`의 61개 절이다. 조건부 예시는 실제
소비자가 있는 경우에 적용하며, 존재하지 않는 결제/LLM/plugin 제품을 새로 만들지 않는다.

| 요구 영역 | 작업과 완료 증거 |
| --- | --- |
| 전체 소스·실제 구조 우선 | 현재 inventory·import graph·실제 호출 경로와 원문 160개 절 대응표 |
| 모듈 책임·공개 API | 책임 경계별 변경, 기존 공개 import/HTTP/CLI/저장 계약 검사 |
| Python 타입·오류·설정·DB | 실제 경계의 모델/입출력과 원자성 검토, 관련 회귀 및 전체 Python 검사 |
| SaaS/cloud 확장 | 콘텐츠/metadata 각각의 계약→등록→인증/설정→저장→UI→문서 흐름, 합성 어댑터 계약 검증 |
| UI 구성·공유 코드 | 실제 독립 책임을 가진 화면/데이터/컴포넌트 분리, 기존 동작·접근성 유지 |
| CSS·Tailwind·theme | 전역 파일은 reset/font/token/body/접근성만 소유, 기능/공통 UI 스타일은 소유 경로로 이전, 반복 override 정리, 기존 스타일 순서와 light/dark·반응형·focus 동작 검증 |
| 코드 규모·중복 | 동일 집계 기준으로 전/후 비교. 파일 이동·주석/공백 축약·테스트 삭제를 중복 감소로 계산하지 않음 |
| 패키지·독립 CLI | 독립 설치/배포와 지원 Python 버전 보존, 정확히 동일한 구현과 독립 QA 참조를 구분 |
| 자동 검증 | 중요한 소유/확장/스타일 경계의 재발 방지 검사와 실제 설정된 lint/type/test/build 명령 |
| 협업·후속 개발 | 팀 가이드·README·아키텍처·추가 절차를 최종 코드에 맞게 수정, 경로/명령/예제 검증 |

## 실행 순서

1. 전체 조사 결과에서 실제 위반·조건부 적용·이미 충족을 구분하고 변경 전 증거를 고정한다.
2. CSS를 먼저 책임별로 정리한다. 화면 기능/디자인을 임의로 변경하지 않고 실제 중복 규칙을 제거한다.
3. 공급자와 공통 기능의 확장 경로에서 확인된 결합·중복을 해당 소유자에서 정리한다.
4. 구조 변경이 필요한 화면/타입/공개 경계를 같은 원칙으로 개선하고 회귀 검사를 실행한다.
5. 실제 최종 상태에서 160개 절을 다시 대조하고 전체 검증·소스 집계·팀 문서를 갱신한다.

검증은 합성 fixture·로컬 DB/브라우저와 읽기 전용 구조 분석을 사용한다. 실계정 수집,
발견 credential 사용, 배포·cloud mutation은 이 작업의 검증에 포함하지 않는다.
안전성·접근성·호환성·실패 처리·의미 있는 테스트를 줄여 행 수를 맞추지 않는다.

## 최종 상태 (2026-09-24)

현재 소스 636개 파일·140,422행을 실제 읽기 장부와 대조해 전체 범위·SHA-256 일치를 확인했다.
원문 99개·61개 절을 [160행 대응표](REFACTOR_REQUIREMENTS_MATRIX.md)에 연결했다.
최종 수치·전체 변경·검증 범위는 [보고서](REFACTOR_REPORT.md)가 기준이다.

| 영역 | 구현·확인 근거 |
| --- | --- |
| 스타일 소유 | globals는 7,891→201행; feature/components/shell로 책임 이전. 미사용 규칙77개·덮어쓴 속성315개 제거. layout import를 theme·browser가 재사용 |
| 스타일 보존 | 분리안138지점 차이0; production 재생138지점은 동등한 background-position 0표현79건 외 차이0 |
| 의존 방향 | schema→catalog 역참조 제거·테이블 객체 동일성 유지. checkpoint 규칙은 순수 task_state로 옮겨 metadata의 DB 로딩 결합 제거 |
| 데이터 조회 | metadata 40객체 SQL165→9회, 1객체9→9회. memory/SQL 상태·tenant·부분/실패 parity 검사 |
| 공통 규칙 | path_under·fetch_json·rule_detection_policy·entropy·GitLab audit view·AWS cache·SQL CRUD/search에서 기존 소유자 재사용, 이전 alias/입출력 유지 |
| 원자성·감사 | AWS 목적별 승인 revision/값/수행자 원자 저장과 legacy1→2 처리; 경쟁 회귀4실패→통과. memory revoke/cancel 감사 이전 상태 보존 |
| 정확한 경계 | malformed queue URL 오류 정규화. 원문 노출 검사에서 건너뛰던4개 GET 경로 보강. Azure 선택 extra와 실제 SSO cache 조건 문서화 |
| UI·검사 의미 | native 검색 dialog·focus복귀, 중복 polling/terminal중지, 같은 탭 탐색·공통 시각 표시, 온보딩 BFF/storage차단 처리. effect 미실행 SSR 검사를 browser로 교체 |
| 표시 정확성 | secret rotation 미확인/비활성, 계정 열거 범위, 시각과 회전 결과 구별. user-agent에서 CloudShell/IP소유자를 추정하지 않음 |
| 독립 패키지 | GCP 관계 grouping O(S×E)→O(S+E), 순서/상태 보존. GCP46개·지원 POSIX GitLab162개 통과; 플랫폼 내부 runtime 의존 추가 없음 |
| 팀 문서 | 실제 소유자/API/소비자·콘텐츠/metadata별 확장 경로·env 조건·CSS 순서·협업 카드·migration 전제·실행 명령을 현재 코드와 대조 |

FastAPI 호환 수정 전 로컬 전체 검증은 Python4,892통과/69skip/266subtests였다. 웹474통과, 브라우저21/21,
TypeScript·production build, Helm/Compose70개, wheel413파일 바이트 일치·CLI3개 검증이다.
전체 브라우저 실행 후반의 secret 정적 표시 변경은 최신 한/영 렌더링 검사와 build로 검증했다.
Ruff는 원본123건→119건, 새로운 진단0건이며 기존 전체 lint 위반을 숨기지 않는다.

행 수는 최초138,165행보다2,257행 많다. 제품·배포는88,982→89,194(+212),
테스트·독립 참조는49,183→51,228(+2,045)이다. 보완 시작140,424행보다는2행 줄었다.
파일 이동·주석/공백 축약·테스트 삭제를 로직 중복 감소로 계산하지 않는다.

API의 설치 단위 권한은 SaaS 고객 격리가 아니며 일부 v1 전체 조회·큰 JSX·동적 타입·
provider별 여러 등록 지점은 남아 있다. 이를 부분 적용/제약으로 대응표에 남겼다.

첫 원격 CI는 최신 FastAPI에서 제거된 `ModelField.type_` 참조로 API5개 검사가 실패했다.
공개 `field_info.annotation`으로 수정하고 수정 전 실패하는 회귀1개를 추가했다.
기존/최신 FastAPI 각각 영향156개 검사가 통과했다. 두 번째 CI는7개 job 모두 통과했으나
JSON Schema 의존성 누락으로3개 검사가 skip되어 dev extra에 jsonschema/RFC3339 의존성을 선언했다.

최종 코드·설정 커밋 `7dd0b3e8577d0d37bed40fef7e015ba09afccf3d`를 origin/refactoring에 push했고,
[세 번째 CI 35888643039](https://github.com/y4rvin/CreMore/actions/runs/35888643039)의7개 job 모두 통과했다.
Python3.12/3.14 각각4,977통과·0skip·342subtests이며 격리 PostgreSQL17과 POSIX 경로를 포함한다.
두 버전에서 독립 GitLab162개/GCP46개, 웹474개·브라우저21개·Helm70개,
TypeScript·production build·컨테이너3종 build/설정된 보안 검사도 통과했다.
기존 upstream TestClient deprecation 경고1건씩은 남아 있다.

README의 설치·개발 명령·인증 소유자·확장 제약을 최신화하고 이를 포함해 wheel을 다시 검증했다.
이후 커밋은 README·최종 보고 문서만 포함하며 검증된 제품 코드·검사·설정은 동일하다.
문서 커밋 push와 원격 SHA 일치는 종료 시 확인한다. 실계정 수집·발견 credential 사용·
배포·cloud mutation은 검증 범위에 포함하지 않는다.
