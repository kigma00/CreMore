# Work Summary

대상: `y4rvin/CreMore`의 `refactoring` 브랜치. 비교 기준은
`9d5dc8415544b265f6bacba23d950fc74009d549`, 검증일은 2026-09-24이다.
이 보고서는 기존 전체 소스 분석 후 수행한 구조·정확성·UI·문서 변경과 로컬·원격 검증을 기록한다.
검증 범위는 `d96bb8d`까지의 리팩터링이다. 이후 SIEM 출력 연동과 공급자 설명 소유권 보완은
[별도 구현 보고서](SIEM_IMPLEMENTATION_REPORT.md)를 기준으로 한다.
실계정 수집, 발견 자격증명의 실제 사용 검증, cloud mutation, 배포는 수행하지 않았다.
`c13b5b7` 이후 7건의 수정과 최신 검증 범위는 마지막 15절에 별도로 기록한다.

## 1. Existing Project Structure Analyzed

변경 전에 원본 source inventory **603개 파일, 138,165행** 전체를 읽고 확인했다.
실행 설정·schema·fixture는 별도 **43개 파일, 9,572행의 렌더링**으로 확인했다.
큰 Atlassian response contract는 4,214개 pointer를 분해한 뒤 원본과 손실 없이
재구성되는지 확인했다. 두 사용자 지침 문서도 읽었고 원본을 보존했다.

분석은 API·domain/DB·scanning/worker·detection/risk·content collectors·공급자 metadata·
AWS access/investigation·governance/remediation·secretstore·dashboard·독립 CLI·배포를 포함한다.
모든 파일을 검토했다는 것은 모든 파일을 수정했다는 뜻은 아니다. 이미 적절한 모듈 경계,
독립 QA reference, 공급자별 상이한 replay 계약은 유지했다.

구조 변경 전에 [REFACTOR_PLAN](REFACTOR_PLAN.md)을 작성했다. 보완 계획은
[REFACTOR_COMPLIANCE_PLAN](REFACTOR_COMPLIANCE_PLAN.md)에 기록했다. 최종 **636개 source 파일,
140,422행**의 실제 읽기 기록·전체 범위와 현재 SHA-256을 합쳐 누락 없이 확인했다.
AST/inventory만으로 완독을 주장하지 않았다. 변경된 파일은 이전 완독본과 전체 변경을 다시 대조했다.
두 원문의 99개·61개 절은 [160행 요구사항 대응표](REFACTOR_REQUIREMENTS_MATRIX.md)에
구현·문서·검증 근거와 부분 적용/조건부 제약을 각각 연결했다.

### 소스 규모

동일한 물리 행 집계 기준을 사용했다. 문서·dependency lock·생성 결과·로컬 로그는 제외하고,
원본 inventory와 새 source 파일을 비교했다. 테스트 경로를 먼저 분류하므로 독립 CLI의
테스트도 아래 `Tests` 행에 들어간다.

| 구분 | 변경 전 | 변경 후 | 차이 |
| --- | ---: | ---: | ---: |
| Platform Python | 54,017 | 54,528 | +511 |
| Dashboard 제품 코드 | 25,688 | 25,388 | −300 |
| 독립 GitLab 제품 코드 | 3,491 | 3,491 | 0 |
| 독립 GCP 제품 코드 | 1,923 | 1,898 | −25 |
| 배포·도구 | 3,863 | 3,889 | +26 |
| Tests | 48,273 | 50,318 | +2,045 |
| 독립 QA 참조 `_qa_storage.py`, `_qa_cli.py` | 910 | 910 | 0 |
| **총계** | **138,165** | **140,422** | **+2,257** |

**전체 행 수는 줄지 않았다.** 실제 반복 로직은 통합했지만 안전장치와 회귀 검사 추가가
삭제량보다 컸다. 제품·배포 부분은 88,982→89,194행(+212), 테스트·참조는
49,183→51,228행(+2,045)이다. 대규모 행 감소를 달성했다고 주장하지 않는다.
원본의 약 35.6%가 테스트·독립 참조였으며 이를 제품 중복으로 보고 삭제하지 않았다.

보완 시작 커밋 `daab6b6`의 140,424행과 비교하면 총 2행 감소했다. 이때 제품·배포는
521행 줄고 테스트·참조는 519행 늘었다. 최초 기준과 보완 기준을 혼합하지 않는다.
`api/app.py`는 824→325행, AWS 화면은 1,458→1,091행, rules 화면은 415→335행이 됐다.
이 수치는 책임 이동의 결과이며 그 자체를 전체 코드 감소로 계산하지 않았다.

## 2. Existing Patterns Reused

* 기존 `DashboardContext`, route registrar, presenter와 모듈별 서비스 주입을 재사용했다.
* `scanning/scope.py`의 승인 scope·resource mapping을 root identity의 소유자로 사용했다.
* 메모리 lock, SQL transaction·conditional update·row lock을 사용해 원자성을 확보했다.
* 기존 `PageResult`, `MetadataPage`, provider fact/omission/report 모델을 확장했다.
* 기존 `ModalSurface`, native dialog focus 처리, locale·순수 dashboard model·API client를 재사용했다.
* 기존 fake transport, memory/SQLite fixture, Node test·Playwright proof에서 실패 경로를 검증했다.

새 framework·범용 plugin registry·별도 microservice·배포 library를 도입하지 않았다.

## 3. Problems Found

| 문제 | 관측·영향 |
| --- | --- |
| 역방향 의존 | source route가 app의 credential helper, trigger가 worker의 순수 root identity, loader가 React 화면에 의존 |
| UI 패널·상태 | dialog overlay 안의 불투명 surface 누락, 좁은 화면 overflow, 이전 요청이 최신 선택을 덮어씀 |
| 부분 스캔 접수 | 일부 성공 후 실패가 생기면 수락된 job 정보가 사라지거나 중복 실행 가능 |
| 원자성 | 여러 settings/ownership writes, ticket revision, 조치 target reservation이 경쟁 요청에서 불일치 가능 |
| 재개·예산 | 공급자 cursor가 저장보다 먼저 전진하거나 오류에서 사라짐; 실패 요청 미집계·완전 수집 오판 |
| 증거 | 권한/로그/값 증거의 부분·unknown을 거절·부재·변경으로 확정하는 경로 |
| 탐지·오탐 | 여러 줄 redaction 누락, 출력 cap보다 앞선 verification 작업, 일부 위치만 고려한 자동 FP |
| 비밀 경계 | malformed Vault/reference/envelope 입력, raw provider 오류, 구성만으로 디스크 부재를 주장하는 설명 |
| 반복 소유 | 여러 pagination·오류 라벨·byte 표시·resource selector 구현 |

회귀 추가 후 수정 전 실패를 확인한 영역에는 tickets, action/rotation, secretstore,
scope/runtime, provider resume, investigation 및 독립 GCP가 있다. 원본 baseline 자체의
독립 GitLab Python 3.10 authorizer cleanup 오류도 별도로 확인했다.

## 4. Changes Made

* API 조립에서 connection credential 입력, finding route, HTTP middleware/error 처리를 분리했다.
* settings·ownership review batch의 사전 검증/원자적 저장과 ticket/action/finding CAS를 보강했다.
* metadata 재개 cursor·committed counter·실패 요청 예산·부분 report 전파를 수정했다.
* 저장된 정책/엔진 digest와 재개·재점수화를 연결하고 누락된 과거 증거를 `NOT_RECORDED`로 표시했다.
* 다중 줄 마스킹과 lazy detection 결과 처리를 수정하고 자동 FP에 모든 active exposure를 반영했다.
* 불투명·scrollable dialog surface, 요청 취소·세대 검증, 부분 접수·이력 오류 UI를 수정했다.
* README·아키텍처·credential roots·개발 지침과 배포 주석을 실제 구현에 맞췄다.
* 전역 CSS를 기능·공통 UI·shell 소유자로 나누고 미사용 규칙 77개와 덮어쓰인 속성 315개를 제거했다.
* schema→catalog 역참조와 metadata 모델의 DB 결합을 없애고 페이지 단위 metadata 조회를 합쳤다.
* AWS 승인 revision 저장을 원자적으로 바꾸고 감사 기록·잘못된 URL 처리·미확인 UI 의미를 보완했다.
* 경로 판정·탐지 정책·entropy·GitHub JSON 조회·SQL CRUD/search의 기존 소유자를 재사용했다.

## 5. Architecture / Boundary Changes

`cremore/api/app.py`는 조립을 맡고 `connection_credentials.py`, `finding_routes.py`,
`http_support.py`, 기존 presenter가 각각 입력·등록·HTTP·응답을 소유한다.
기존 app 이름과 worker root helper는 compatibility export로 남겼다.

`web/lib/dashboard-types.ts`와 `dashboard-model.ts`는 공유 계약·순수 계산을 소유한다.
GitHub/Notion 인벤토리는 connections feature, finding 증거는 findings feature로 이동했다.
loader가 React view를 참조하지 않으며 overview/findings가 rules UI를 경유하지 않는다.

Catalog 테이블은 `db/schema.py`가 소유하며 기존 catalog import는 동일 객체를 재노출한다.
순수 checkpoint 규칙은 `task_state.py`가 소유해 metadata 모델을 읽을 때 SQLAlchemy를 로딩하지 않는다.
Domain의 vendor/웹 framework import, 하위 계층의 API/worker 역참조, 독립 CLI의 플랫폼 내부 import는
최종 AST 분석에서 발견되지 않았다. 지연 import까지 모두 없앴다는 주장은 아니다.

플랫폼 GCP와 독립 GCP는 각각 자기 package 안에서 페이지 loop를 통합했다.
두 제품 사이에 runtime 의존을 새로 만들지 않았다. AWS IAM pagination은
`aws_pagination.py`, 수집기/AWS의 안전한 오류 code는 `aws_identity.py`를 공유한다.

## 6. Python Changes

요청 validation 오류는 원문 input/context·임의 dictionary key·raw 메시지를 제외한다.
메모리/SQL settings와 ownership review는 batch 전체를 검증하고 원자적으로 갱신한다.
티켓은 live memory model을 snapshot하고 expected revision으로 CAS한다.

Action plan의 미해결 상태·대상 예약은 domain/repository 소유다. SQL은 credential row를
잠그고 SQLite는 쓰기 transaction을 먼저 확보한다. 동일 idempotency key의 다른 요청을 거절하며,
expected status CAS로 실행 중복을 막는다. 회전은 현재 version/key drift를 재확인하고,
쓰기 후 불확실성은 target을 예약한 `OUTCOME_UNKNOWN`으로 유지한다. 조정은 읽기만 한다.

ScanRuntime은 예산 중단 시 cursor·failed prefix·committed counters를 함께 보존한다.
root identity golden vector를 유지했다. detection 의미 변경에 따라 `ENGINE_EPOCH`는
4→5, 저장 context redaction version은 2→3으로 올렸다. 이전 context는 새 기준으로
읽기 노출을 막되 저장된 evidence를 파괴적으로 재작성하지 않는다.

Learned FP는 모든 active exposure의 scope·내부 노출·검증 증거·같은 profile을 확인한다.
유효성을 잃은 **자동** 결정만 재개방하고 수동 결정을 유지한다. timestamp가 같을 수 있어
상태·resolution도 CAS에 포함했다. 다른 profile의 오래된 자동 resolution을 유지하지 않는다.

Vault는 base URL·mount·logical path·token·응답 구조를 검증하고 redirect를 거절한다.
봉인 파서는 버전·키 ID·strict base64를 검사한다. 구성 현황은 현재·이전 opener와 passphrase를
포함하고 `PROCESS_CONFIGURATION`/`disk_persistence: UNKNOWN`으로 관측 범위를 명시한다.

HTTP 검증의 일반 403·Slack 비인증 실패·혼합 host 결과는 확정적 무효로 취급하지 않는다.
Slack은 root JSON boolean을 검사하고 scope/오류 사실은 길이·문자 제한을 적용한다.
새 endpoint·추가 probe·실제 credential 검증 실행은 추가하지 않았다.

AWS 승인은 `save_approval`→`put_revisioned_setting`이 목적별 revision·값·수행자를 함께 저장한다.
메모리는 기존 lock, SQL은 placeholder 삽입·row lock·update를 하나의 transaction으로 처리한다.
동시 승인 8개가 모두 revision 1을 받던 회귀는 수정 전 4개 실패, 수정 후 통과했다.
revision이 없는 과거 승인은 1로 취급하므로 새 승인은 2가 되어 기존 검증을 무효화한다.
로컬 관련 검사는 30개 통과·PostgreSQL 9개 skip이었다. 이후 최종 원격 전체 검사에서
격리 PostgreSQL 17의 동시성 검사까지 실행해 통과했다(§12).

Metadata 페이지의 연결·관측 run·최근 상태를 묶어 조회해 합성 SQLite의 40개 객체에서
SQL 실행이 165→9회로 줄었다(1개 객체는 9→9회). 전체 운영 처리량의 측정은 아니다.
SQL 검색/연결 CRUD/조치 lock은 기존 helper를 재사용했고 같은 관련 검사 48개가 전후 통과했다.
수집기의 `path_under`, GitHub `fetch_json`, `rule_detection_policy`, Shannon entropy는
각 실제 공통 소유자로 통합했다. 이전 private alias와 문자열/raw bytes 의미는 보존한다.

## 7. Frontend Changes

`ModalSurface`가 overlay와 불투명 panel을 함께 렌더링한다. `panelClassName`과 drawer variant를
구분하고 기존 focus/Escape/backdrop/dirty-close를 유지했다. AWS, rules, scans, metadata,
GCP, GitHub, Notion 호출부를 이 계약으로 정리했다. 좁은 viewport에서 패널과 표를 스크롤한다.

QuickScan은 generation/AbortController로 이전 응답을 버린다. Multi-start는 성공 receipt와
실패 선택을 함께 보존하며 중복 접수를 막고 실행 화면을 실제 run ID에 연결한다.
이력 로드 실패는 빈 기록으로 숨기지 않고 재시도 가능한 오류로 표시한다.

로컬 credential 화면은 보유 입력·외부 원본·프로세스 메모리·이전 opener를 구분한다.
모든 로드 실패를 관리자 권한 부족으로 표시하던 설명을 고쳤다. Source slicing만으로
무조건 통과하던 테스트와 이전 문구를 찾던 browser selector도 실제 소유자·문구에 맞췄다.

UI proof는 컴파일된 Tailwind와 모든 기존 stylesheet를 사용했다. Modal의 wide/mobile·dark
스크린샷을 육안 검토했고, browser 검사는 light/dark, KO/EN, 390px/1440px, focus·overflow·
contrast·provider inventory·scan scope를 포함한다. 외부 공급자 요청은 합성 proof에서 거절한다.

`globals.css`는 7,891→201행으로 전역 기본값·토큰·접근성만 소유한다. 기능 CSS는 해당 feature,
공통 UI/evidence는 components, shell은 app에 둔다. 파일 이동 자체를 감소로 계산하지 않는다.
`layout.tsx`의 import 순서를 `scripts/stylesheets.cjs`가 theme 생성기와 browser bundle에도 전달한다.
분리안의 138개 computed-style checkpoint는 차이가 없었다. 최종 production CSS 재생에서는
동등한 `background-position`의 0 표현 차이 79건 외에 차이가 없었다.

전역 검색은 기존 native dialog helper를 재사용해 focus·Escape·복귀를 보장한다.
Provider inventory의 중복 polling을 한 timer로 합치고 terminal 상태에서 멈춘다.
AWS 템플릿 다운로드는 인증된 BFF 경로를 쓰고 sessionStorage 차단도 온보딩을 막지 않는다.
GitHub 안내는 실제 암호화 token/PEM 등록 흐름과 일치시켰다.
Secret UI는 미확인 rotation과 비활성, 설정 참조와 계정 열거를 구별한다. 시각만으로 회전 성공/실패를,
user-agent만으로 CloudShell 또는 IP 소유자를 단정하지 않는다.
효과가 실행되지 않는 SSR 검사를 API 오류 동작의 증거로 쓰던 부분은 실제 browser 검사로 옮겼다.

## 8. Library / Package Decisions

새 필수 runtime dependency나 public package를 추가하지 않았다. 기존 Azure 인증 구현에 필요한
`azure` 선택 extra를 선언하고 기본 GCP 이미지와 별도의 잠금·빌드 절차를 문서화했다. 기존 모듈·표준 라이브러리·설치된
FastAPI/SQLAlchemy/httpx/React를 사용했다. `cremore` wheel과 세 설치 CLI, private Next 앱,
두 독립 CLI 경계를 유지했다. 독립 GitLab의 3.10+ POSIX 지원을 위해 테스트 cleanup만 수정했다.

차트 검사는 기본 digest-pinned Docker 경로를 유지하면서 검증된 native Helm 3.17.2를
`CREMORE_HELM_BINARY`로 지정할 수 있게 했다. Docker engine이 unavailable인 개발 환경에서도
같은 assertion으로 Helm/Compose를 render할 수 있고, 다른 Helm 버전은 거절한다.
이 변경은 배포 런타임 의존성 추가가 아니다.

## 9. Provider / Adapter Changes

* **GCP:** shared page loop, durable cursor, 실패 요청 집계, audit/metric window 고정,
  record-budget acceptance 이후 상태 전진, bounded base64·checksum, public certificate envelope.
* **GCP 저장/비교:** 한 객체의 모든 fingerprint를 순서 독립적으로 비교한다. scheme/key/engine/policy
  계약과 수집 완전성이 같을 때만 값 변경을 확정한다. 기존 단일 fingerprint projection을 유지하고
  JSON-serializable 증거를 사용해 memory/SQL/public read 경로를 함께 검증했다.
* **Azure:** run에 source PARTIAL 전파, cursor·예산 유지, malformed row 집계, page cycle/limit,
  pinned vault와 요청 secret에 속하는 ID만 관측으로 수락.
* **GitHub:** record-budget 거절 시 task/cursor 미전진, App token source 해석, factory 생성 client와
  주입된 공유 client의 수명 구분. 여러 조직의 설치 토큰을 실제 MockTransport 경로로 검증.
* **AWS 조사:** bounded IAM pages, 완전한 simulation action 집합, malformed 정책/로그/Secret metadata의
  보수적 처리. region fallback·cap은 account-wide 완전성을 주장하지 않는다.
* **독립 GCP:** 세 page loop와 값 decoding/checksum 통합, malformed prior state 거절,
  반복 collect의 이전 결과 누적 제거, ambiguous UID의 단일 credential 귀속 방지,
  프로젝트 숫자 alias 유지, 입력 파일의 읽기 전 크기 제한.
  정렬된 관계를 한 번 index해 grouping을 O(S×E)에서 O(S+E)로 바꾸고 결과 순서/상태를 유지했다.
* **GitLab/Atlassian:** 기존 provider-specific field/provenance/replay/export 구조를 검토하고 보존했다.
  이를 GCP/Azure의 더 단순한 cursor 형식으로 통일하지 않았다.

## 10. Open-Source Extension Points

실제 extension point는 `Collector`/`CollectedObject`, `CollectorRuntime`/`CollectionContext`,
명시적 provider registration, secret resolver, `create_app` 주입, UI primitives·theme/locale다.
팀 지침은 새 SaaS/cloud provider의 spec→adapter→등록→scope→test→UI→문서 절차를 설명한다.
콘텐츠와 metadata의 추가 절차는 다르다. UI registry 하나를 수정하면 새 provider가 완성되지는 않으며,
factory·지원 kind·spec allowlist·API·UI의 실제 연결 지점을 함께 바꿔야 한다.

현재 AI model/payment/mail provider와 외부 plugin lifecycle, 공개 npm component override는 없다.
Credential 탐지기의 provider 이름을 해당 vendor의 제품 통합으로 오해하지 않도록 명시했다.

## 11. Compatibility

**192개 HTTP route의 path·method·등록 순서를 원본과 비교해 동일함을 확인했다.**
CLI 이름, public detection/secretstore exports, scope/root identity, catalog ID/순서,
AES-GCM v1 읽기·v2 쓰기, 이전 opener, native schema/CLI를 유지했다.
DB 테이블·컬럼 migration은 추가하지 않았다. SQLite의 naive timestamp는 UTC로 복원한다.

의도된 변경은 malformed 입력 거절, 409 경쟁 갱신, PARTIAL/UNKNOWN 판정, 안전한 오류,
과거 context 숨김, 정책 변경 후 재스캔, 자동 FP 재개방이다. 기존 스캔의 잘못된 성공·무효·
삭제 판정을 호환성이라는 이유로 유지하지 않았다. 수동 결정과 과거 저장 evidence는 보존한다.

운영 rollback은 변경 전 image/source와 DB backup을 함께 보관하는 기존 절차를 따른다.
새 epoch로 만든 cache는 구버전과 공유해 성능/동일성을 가정하지 않는다. 이전 버전으로 내리면
이번에 수정한 오류가 다시 노출될 수 있다. source checkout만으로 cloud 작업을 되돌릴 수는 없다.

## 12. Validation

최종 명령과 전제는 [팀 지침의 검증 절](AI_TEAM_CODING_GUIDE.md#10-테스트빌드-명령)에 있다.
이번 작업의 원본 baseline은 Python 4,669 passed/70 skipped/266 subtests, frontend 469 unit,
20 browser proofs, 독립 GCP 39 passed, 독립 GitLab 161 passed/1 cleanup error였다.

최종 코드·설정 커밋 `7dd0b3e8577d0d37bed40fef7e015ba09afccf3d`의
[원격 CI 35888643039](https://github.com/y4rvin/CreMore/actions/runs/35888643039)는
**7개 job 모두 통과**했다. 격리 PostgreSQL 17과 POSIX 경로를 포함한 결과다.
리팩터링 마감 커밋 `d96bb8d`까지의 후속 변경은 README와 최종 보고 문서이며 제품 코드·검사·설정은 동일하다.

| 최종 원격 검사 | 결과 |
| --- | --- |
| Linux Python 3.12 / 3.14 전체 pytest | 각각 **4,977 passed, 0 skipped, 342 subtests passed**; upstream TestClient deprecation 경고 1건씩 |
| 독립 GitLab / GCP unittest | Python 두 버전에서 각각 **162 / 46 passed** |
| 웹 단위 / TypeScript / production build | **474 passed**, 타입 검사·빌드 통과 |
| 실제 브라우저 검사 | **21/21 passed** |
| Helm/Compose chart test | **70 passed**, pinned Helm container 사용 |
| API / web / oauth2-proxy container | 세 이미지 build·설정된 보안 검사 통과; 이미지 게시·배포 없음 |

아래는 로컬 검증 기록이다. FastAPI 호환 수정 전 전체 실행과 수정 후 영향 검사를 구분한다.

| 검사 | 결과·범위 |
| --- | --- |
| `python -m pytest cremore -q --tb=short -ra` | **4,892 passed, 69 skipped, 266 subtests passed**, Windows Python 3.12.9, 1,307.50초; 이후 FastAPI 호환 수정은 아래 별도 검사 |
| `web`: `npm test` | **474 passed**, 0 skipped |
| `web`: `npx tsc --noEmit` | 통과 |
| `web`: `npm run build` | Next production build 통과 |
| `web`: `npm run test:browser` | **21/21 passed**, 전체 runner exit 0; 아래 실행 시점 범위 참고 |
| 독립 GCP unittest | **46 passed** |
| 독립 GitLab unittest | **162 passed**, WSL Ubuntu/Python 3.10.12 |
| Helm/Compose chart test | **70 passed**, SHA-256 확인한 Helm 3.17.2 native binary + Compose CLI로 실제 render |
| Python wheel | build 성공; **413개 패키지 파일 현재 바이트 일치**, 세 CLI import/callable 및 Azure/dev/gcp extras 검증 |
| 공개 route·guide 예제 | 192 route 동일; Azure spec 문서 예제를 I/O 없이 실행 |
| Ruff 전체 비교 | 원본 **123건**, 최종 **119건**, 새 진단 **0건**; 전체 lint는 기존 위반 때문에 통과 상태가 아님 |
| Source AST·`git diff --check` | 통과 |

69개 skip은 PostgreSQL URL 미설정 **10**, Windows에서 POSIX native CLI 검사 **59**다.
선택 Google auth 의존성을 설치해 해당 두 검사는 이번 전체 실행에 포함했다.
별도 POSIX GitLab 전체 실행은 성공했으나 이 결과로 Windows에서
skip된 Atlassian 검사까지 실행했다고 보지 않는다. 로컬에서는 실 PostgreSQL 동시성 검증을 실행하지 못했다.
이 환경 차이는 위 최종 원격 전체 실행에서 PostgreSQL·POSIX 검사와 함께 확인했다.

브라우저 전체 실행 시작 후의 마지막 secret 정적 표시 변경은 최종 소스의 한국어·영어
렌더링 단위 검사와 production build로 검증했다. 최종 원격 브라우저 21개 검사는 이 변경까지 포함한다.
Windows에서는 직접 Node CLI로 npm scripts와 같은 unit/tsc/build/browser 명령을 실행했다.
최신 README를 반영해 다시 만든 wheel의 SHA-256은
`0eac14eb12cc5d33b1769b7fdc62ce1ca8e90d32d2bfd2c5860af9ecde874c37`이다.
413개 패키지 파일과 README metadata가 현재 내용에 일치하며 세 CLI와 extras를 다시 확인했다.

Docker Desktop engine의 `/info`가 HTTP 500을 반환해 컨테이너 build·pinned Helm image 실행은
할 수 없었다. Helm native 대안으로 실제 template·lint assertion을 실행했고 컨테이너 build는
최종 원격 CI에서 확인했다. 배포, IdP 로그인, 실제 workload 인증은 실행하지 않았다. 별도 Python type checker와
frontend ESLint script는 저장소에 설정되어 있지 않다.

수동 CI의 Python 3.12/3.14 job에 digest-pinned PostgreSQL 17 임시 service와 GCP extra,
독립 GitLab/GCP 검사를 연결했고 위 최종 실행에서 실제 통과를 확인했다.
컨테이너 job은 `push: false`이고 배포하지 않는다.

첫 원격 실행 `35884516807`에서 web/browser와 컨테이너3종은 통과했지만 Python 두 버전은
동일한5개 API 검사에서 실패했다. 최신 FastAPI0.141.1이 없앤 `ModelField.type_`를
검증 오류 처리에서 참조한 것이 원인이었다. 기존0.128.2의 property와 동일한
`field.field_info.annotation`을 직접 사용하도록 수정했고 dependency를 낮추지 않았다.
공개 FieldInfo만 가진 경우의 회귀1개를 추가해 수정 전 실패를 확인했다. 수정 후 영향3개 suite는
기존 FastAPI0.128.2에서156개, 격리한0.141.1/Pydantic2.13.5/Starlette1.7.0에서도156개 통과했다.
후자는 기존 httpx TestClient의 upstream deprecation 경고1건이 있다. 임의 key/input/context는
계속 오류 응답에서 제외하고 선언된 alias·숫자 index는 유지한다. 두 번째 원격 CI35886562438은7개 job 모두 통과했고 Python3.12/3.14 각각4,974개 통과,
3개 skip·278subtests였다. skip은 jsonschema 미설치로 생긴 기존 출력 계약 검사였다.
이를 실행하기 위해 dev extra에 jsonschema와 해당 schema의 date-time 검사에 필요한
rfc3339-validator를 선언했다. runtime 의존성/잠금은 바꾸지 않았다. 존재하지 않는
requirements-dev.txt 안내는 실제 .[dev]로 고쳤다. schema 구조와 Windows에서 실행 가능한2개/3subtests는 통과했다.
최종 세 번째 CI에서는 기존 skip 3개도 실행되어 Python 두 버전 모두 skip 없이 통과했다.


통합 검증 중 발견한 GCP 저장 JSON 형식/legacy fingerprint와 GitHub 공유 client 조기 종료는
수정 후 65개 통합·인증 검사 및 최종 전체 suite로 재검증했다. 검사 실패를 삭제하거나
실패한 검사를 skip으로 바꿔 통과시키지 않았다. 원본 GitLab cleanup만 지원 Python에 맞췄다.

SQLi/XSS 관련 실제 경계는 bound SQL, enum/정렬 allowlist, JSX escaping, URL/origin 검증,
request/auth/RBAC·로그 redaction 검사로 검토했다. 이 검증은 모든 가능한 취약점의 부재나
실제 공급자 계약의 영구적 일치를 보장하는 주장이 아니다.

## 13. Remaining Technical Debt

* **전체 행 감소:** 중복 소유는 줄였으나 전체 source 행은 증가했다. 더 큰 감소에는
  실제 미사용 기능·지원 계약을 별도 결정해야 하며, 테스트 삭제·동작 축소로 수치를 맞추지 않았다.
* Ruff baseline 잔여 119건이 있다. 독립 package의 Python 지원 버전과 exception 계약을 고려해
  검토해야 한다. 상위 제품의 Python 3.12 rewrite를 3.10 지원 CLI에 일괄 적용하면 안 된다.
* 일부 주입 타입은 `Any`/동적 provider protocol이며 큰 JSX/기능 CSS 파일이 남아 있다.
  전역 stylesheet의 책임은 분리했지만 cascade 변경에는 실제 compiled-stack UI proof가 필요하다.
* 설치 단위 권한은 SaaS 고객 격리가 아니다. 일부 v1 목록/통계의 전체 조회와 content scan
  admission 한계도 남아 있다. 구조 정리만으로 대규모 다중 고객 운영을 보장하지 않는다.
* 실제 IdP 로그인·공급자 권한·workload identity·운영 배포는 미검증이다. 합성 검사와
  격리 PostgreSQL·컨테이너 build 통과를 실계정 운영 검증으로 해석하지 않는다.
* 독립 GCP ADC transport의 전체 응답 streaming byte cap/session 수명 관리와 오래된
  malformed 외부 snapshot의 더 넓은 검증은 후속 검토 대상이다. 현재 페이지 수·payload decode
  경계가 전체 네트워크 응답 메모리 한도를 대신하지 않는다.
* Native package와 통합 adapter에는 독립 배포·source provenance를 위한 반복이 남아 있다.
  독립 QA 참조까지 공통화하는 것은 검증 독립성을 잃으므로 자동 최적화 대상이 아니다.

## 14. Recommended Next Steps

향후 코드 변경에도 전체 CI와 해당 계약 검사를 유지한다. 운영 적용 전 backup과
staging의 OIDC·workload identity·provider별 권한을 검증한다. 이는 완료한 합성·로컬·원격 CI와 별개다.

행 감소를 위한 후속 작업은 실제 사용 feature와 호환 계약을 기준으로 우선순위를 정한다.
주석·테스트·지원 provider를 단순 삭제하지 말고, 반복 구현이 발생하는 소유 경계를 계속 줄인다.

### Team AI Guide

생성: [docs/AI_TEAM_CODING_GUIDE.md](AI_TEAM_CODING_GUIDE.md).
최종 directory/package map, Python·React·TypeScript·Tailwind/Next 규칙, public/internal imports,
provider별 계약·등록, library/package 결정, config/DB/error/logging/security, 접근성,
검증 명령·환경 전제, customization, multi-agent 소유 경계, Common Recipes와 AI Agent Quick Start를 포함한다.
실제 경로·공개 심볼·provider/API 목록을 코드와 대조했다. API 문서의 in-memory 예제 두 개와
네트워크 없는 Azure spec 예제를 실행했다. 존재하지 않던 config 테스트 참조와 Next 로그인
소유권 설명을 바로잡았고 실제 offline migration 명령·backup 전제를 추가했다(명령 실행은 하지 않음).
미실행 환경과 지원하지 않는 plugin/UI override는 대응표와 위 검증 절에 구분했다.

이 보고서·계획·팀 지침은 커밋에 포함한다. 해당 커밋의 `origin/refactoring` push 및 원격 SHA
일치는 작업 종료 메시지에서 기록한다. 보고서 자체에 아직 만들지 않은 commit SHA를 예측해 넣지 않는다.

## 15. 2026-09-24 후속 최종 검토

대상은 `c13b5b7` 이후 아래 7건의 수정이다. 이전 절의 역사적 검사 수치·원격 CI 결과를
이번 변경의 검증으로 대신하지 않았다. 백엔드, UI/API, 패키징을 독립적으로 교차 검토했다.

| 수정 | 책임 파일·검증한 동작 |
| --- | --- |
| GitHub native source 집계 | `github/backend/cremore_github_provider/metadata/snapshot.py`: 여러 저장소의 실패·페이지·건수 보존, 입력 순서 독립, 단일 결과 호환 |
| 작업 완료 지연 | `cremore/db/task_store.py`: canonical member가 끝난 부모를 먼저 선별한 뒤 limit 적용, 취소·빈 작업·공유 task·실패 처리 유지 |
| 인벤토리 50건 이후 이동 | `web/features/connections/provider-inventory.tsx`: 실제 API의 offset/limit/total로 50→100→137건 이동 |
| 필터 해제 불가 | 같은 UI 파일: 선택한 객체 종류·사건 공급자·사건 유형을 빈 결과나 조회 실패에도 해제 |
| 공급자·목적 필터 누락 | `cremore/coverage/metadata_store.py`, `web/lib/provider-metadata.ts`, 같은 UI 파일: 실제 저장자료의 facets를 추가하고 기존 counts/event_types 의미 유지 |
| Azure sovereign 인증 | `azure/backend/cremore_azure_provider/metadata/transport.py`, `adapter.py`: 검증된 origin별 scope·authority 선택, 기존 token 주입 유지 |
| SQL 검색 문자 해석 | `cremore/db/sql.py`: `%`, `_`, escape 문자를 literal substring으로 검색하며 목록과 total에 동일 조건 적용 |

각 책임 파일의 회귀 검사와 팀 지침·metadata 응답 문서·GitHub/Azure README를 함께 갱신했다.
DB migration이나 의존성·배포 설정 변경은 없다.

| 최종 검증 | 결과·한계 |
| --- | --- |
| 전체 제품 Python | 루트에서 `python -B -m pytest -p no:cacheprovider -q -rs`: **5,158 passed, 71 skipped, 278 subtests passed**, 929.51초. `AWS_EC2_METADATA_DISABLED=true`, `PYTHONDONTWRITEBYTECODE=1` 적용 |
| 독립 GCP | `gcp/standalone`에서 `python -B -m unittest discover -s tests -v`: **48 passed** |
| Web unit·TypeScript·Next build | 같은 제품 소스에서 `npm test` 484 passed, `npx tsc --noEmit`, `npm run build` 통과; 마지막 단위 fixture 정정 후 관련 30개 재통과 |
| 합성 Chrome | provider-inventory, scoped-controls, audit-details 통과; 마지막 검사는 KO/EN과 1440/390/320px 포함, 실제 서버·외부 요청 없음 |
| 제품·공급자 Ruff | `cremore`와 8개 공급자 `backend` 전체 통과 |
| 독립 GCP Ruff | 기존 17건 잔여; `git diff HEAD -- gcp/standalone`이 비어 기존 코드임을 확인. 전체 저장소 lint 통과로 보고하지 않음 |
| 현재 wheel | 오프라인 build 성공, 10개 패키지의 615개 파일이 현재 소스와 바이트 일치; 수정된 공급자·공통 모듈 포함 |

71개 skip은 격리 PostgreSQL 미설정 12개와 Windows에서 실행할 수 없는 POSIX 검사 59개다.
제품 pytest는 `pyproject.toml`의 플랫폼·8개 공급자 testpaths를 모두 수집했다.
독립 GitLab의 POSIX suite는 이번에 재실행하지 않았다. 최종 diff 검사도 통과했으며,
이번 교차 검토에서 수정한 7건 외에 추가 기능 결함은 발견하지 못했다.

이 버전의 실제 Docker build/기동, PostgreSQL, 실계정·OIDC·workload 인증·SIEM 전송·운영 배포는
실행하지 않았다. 이전 원격 CI 결과는 이 버전에 적용하지 않으며 이번 원격 CI도 실행하지 않았다.

## 16. 2026-09-24 Docker 환경 추가 검증

15절의 제품 코드 커밋 `296cf33a3fea6cf787c7cd1b4a7e493db6dc6561`를 대상으로,
Docker Desktop 복구 후 미실행 항목을 추가 검증했다. 사용자 승인에 따라 재시작했으며,
기동을 막던 Windows IPC socket 디렉터리는 백업 이름으로 보존하고 새 디렉터리로 교체했다.
기존 서비스가 다시 기동한 것을 확인했다. 기존 DB·볼륨은 삭제하지 않았다.

| 추가 검증 | 실제 결과 |
| --- | --- |
| PostgreSQL 17.11 | `postgres_scan_test.py`, coverage 동시 제출 1건, `postgres_outbox_test.py`: **12 passed**, 34.07초; 기존 TestClient 의존성 deprecation 경고 1건 |
| Linux POSIX | Atlassian 전체와 GitLab POSIX 2건: **289 passed, 316 subtests passed, 0 skipped**, 10.41초; Windows에서 skip한 59건 포함 |
| 독립 GitLab | Linux에서 `python -B -m unittest discover -s tests -v`: **162 passed**, 15.121초 |
| 제품 Python 이미지 | `deploy/docker/python.Dockerfile` build 성공; nonroot API `/healthz` HTTP 200·`status=ok`, worker heartbeat 갱신 확인 |
| Web 이미지 | `web/Dockerfile` build 성공(Next production build·TypeScript 포함); nonroot 서버 `/healthz` HTTP 200·`status=ok` |
| OAuth 이미지 | `deploy/docker/oauth2-proxy.Dockerfile` build 성공; 버전 출력·합성 설정 기동·`/ping` HTTP 200·`OK` 확인 |

기존 **71개 skip(PostgreSQL 12개·POSIX 59개)은 모두 실제 실행해 통과**했다.
전체 Python suite를 다시 실행한 결과는 아니며, 15절의 Windows 전체 검사에 위 환경별 검사를
추가한 것이다. 이번 검사에서 제품 코드 수정은 필요하지 않았다.

PostgreSQL은 digest를 고정한 별도 컨테이너의 `cremore_test` DB와 tmpfs를 사용했다.
시험 컨테이너가 이 DB의 network namespace를 공유해 `127.0.0.1`로 접속했으며,
localhost·DB 이름 제한을 유지했다. 생성한 임시 schema가 모두 정리된 것도 확인했다.
테스트 이미지는 해당 커밋의 `git archive`와 `.[dev,gcp]`로 만들고 POSIX 파일은 Linux `/tmp`에 뒀다.
기동 검사는 합성 설정·tmpfs·외부 네트워크 차단으로 수행했으며 host port나 기존 DB를 쓰지 않았다.
빌드 중 패키지 다운로드에는 네트워크를 사용했다. Web의 첫 `npm ci`는 `ECONNRESET`으로
실패했지만 동일 빌드 재시도로 통과했다. 소스·의존성·Dockerfile 변경은 없었다.
검증에 사용한 컨테이너는 모두 종료·제거했고, 빌드한 이미지는 로컬에 보존했다.

로컬 원본 증거는 `.git/docker-postgres.log`, `.git/docker-posix.log`,
`.git/docker-gitlab.log`, `.git/docker-build.log`, `.git/docker-python-build.log`,
`.git/docker-python-smoke.json`, `.git/docker-web-build.log`, `.git/docker-web-build-retry.log`,
`.git/docker-web-smoke.log`, `.git/docker-oauth-build.log`, `.git/docker-oauth-smoke.json`에 보관했다.
이 로그들은 Git에 포함하지 않으며, 결과와 범위만 이 보고서에 기록한다.

실계정 공급자 호출, 실제 IdP/OIDC 로그인·workload 인증, 외부 SIEM 전송, 전체 서비스 간
통합 배포는 이번 검증에 포함하지 않았다. 컨테이너별 기동 성공을 이 통합 검증으로 대신하지 않는다.
이번 원격 CI는 실행하지 않았다.
