# 두 개발 지침 요구사항 대응표

기준: 2026-09-24 리팩터링 마감 커밋 `d96bb8d`. 이후 SIEM 연동 보완은
[후속 보고서](SIEM_IMPLEMENTATION_REPORT.md)를 본다. 원문
[AI_ALWAYS_ON_PROJECT_CODING_GUIDE](AI_ALWAYS_ON_PROJECT_CODING_GUIDE.md)의 99개 절과
[POST_REFACTOR_AI_TEAM_GUIDE_REQUIREMENT](POST_REFACTOR_AI_TEAM_GUIDE_REQUIREMENT.md)의 61개 절을
각각 A01–A99, P01–P61로 연결한다. 절 제목은 원문 그대로이며 각 절당 한 행이다.
아래 소유 경로·수치·판정은 위 기준 커밋 당시의 기록이다. 현재 소유 경로는
[팀 지침](AI_TEAM_CODING_GUIDE.md)과 [디렉터리 보고서](PROVIDER_DIRECTORY_REVIEW.md),
최신 실행 결과는 [검증 보고서](REFACTOR_REPORT.md)의 후속 검증 절을 따른다.

**적용 확인**은 해당 범위의 구현·개발 규칙·문서 근거가 확인됐다는 뜻이다. 모든 실행 경로의
무결함이나 전체 요구사항 완전 충족을 인증하지 않는다. **부분 적용**에는 남은 실제 제약을,
**조건부**에는 현재 없는 능력 또는 후속 결정이 필요한 적용 조건을 적었다.
최종 판정은 **적용 확인 128개·부분 적용 16개·조건부 16개**이며 검증 대기 항목은 없다.
부분 적용과 조건부 항목을 완전 충족으로 합산하지 않는다.

소유 경로는 저장소 루트 기준이며, `팀 가이드`는 `docs/AI_TEAM_CODING_GUIDE.md`다.
성능 숫자는 특정 합성 fixture의 관측이고 운영 처리량을 뜻하지 않는다. 검사 수는 범위가 겹치므로
합산하지 않는다. 과거 리팩터링 보고의 검사 결과는 이번 보완의 최종 실행 결과와 구별한다.
실행 명령·통과/실패/skip/미실행의 최종 근거는 [REFACTOR_REPORT](REFACTOR_REPORT.md),
진행 계획과 변경 근거는 [REFACTOR_COMPLIANCE_PLAN](REFACTOR_COMPLIANCE_PLAN.md)을 함께 본다.

## 상시 개발 지침: 99개 절

| ID | 원문 절 | 판정 | 실제 소유 코드·문서 | 검증 근거·남은 제약 |
| --- | --- | --- | --- | --- |
| A01 | 1. ALWAYS-ON RULE | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §13·Quick Start<br>`docs/REFACTOR_COMPLIANCE_PLAN.md` | 작업 전 소유자·기존 구현·import·설정·검사 확인을 상시 절차로 명시했다. 이번 보완의 원문 두 문서와 적용 범위를 보존한다. |
| A02 | 2. SOURCE-CODE-FIRST PRINCIPLE | 적용 확인 | `docs/REFACTOR_PLAN.md`<br>`docs/ARCHITECTURE.md` | 실제 cremore/web/독립 CLI 구조와 import를 먼저 조사했다. 예시용 core/packages 폴더를 새로 강제하지 않았다. |
| A03 | 3. EXISTING PROJECT STRUCTURE MUST BE ANALYZED FIRST | 적용 확인 | `docs/REFACTOR_COMPLIANCE_PLAN.md`<br>`docs/REFACTOR_REPORT.md` | 현재636개 소스/140,422행의 실제 읽기 범위와 최종 SHA-256을 합쳐 누락0을 확인했다. AST/inventory만 완독으로 간주하지 않으며 변경분은 이전 완독본과 전체 diff를 대조했다. |
| A04 | 4. PROJECT INVENTORY FIRST | 적용 확인 | `docs/REFACTOR_PLAN.md`<br>`docs/AI_TEAM_CODING_GUIDE.md` §2 | 기존 파일·진입점·책임 inventory와 최종 소유자 표를 구분한다. 보완 시작 시점의 615개 파일 집계는 최종 파일 수가 아니다. |
| A05 | 5. DO NOT INVENT DIRECTORY NAMES BEFORE ANALYSIS | 적용 확인 | `cremore/api/routes`<br>`web/features`<br>`docs/REFACTOR_COMPLIANCE_PLAN.md` | 기존 API/feature 소유 경계를 사용했다. CSS는 기존 feature·components·app에 배치했으며 선호 이름을 위한 전체 디렉터리 교체는 없다. |
| A06 | 6. PROJECT-SPECIFIC REDESIGN | 적용 확인 | `docs/REFACTOR_COMPLIANCE_PLAN.md`<br>`cremore/task_state.py` | 실제 metadata checkpoint의 DB 역의존을 순수 task_state 소유자로 옮기는 등 현재 경로에 맞춰 계획·구현했다. |
| A07 | 7. ARCHITECTURE MAP BEFORE REFACTORING | 적용 확인 | `docs/REFACTOR_PLAN.md`<br>`docs/ARCHITECTURE.md` | app/dashboard/routes, worker/factory, metadata runtime, page/features/lib 흐름을 먼저 기록했다. 개선 근거를 실제 책임 혼재·역의존·중복에 연결했다. |
| A08 | 8. MODULAR MONOLITH IS THE DEFAULT | 적용 확인 | `pyproject.toml`<br>`web/package.json`<br>`docker-compose.yml` | Python API/worker와 Next 앱의 기존 제품 구성을 유지한다. 기존 독립 CLI를 설명하며 microservice 분리를 추가하지 않았다. |
| A09 | 9. MODULE OWNERSHIP | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §2<br>`cremore/api/routes`<br>`web/features` | 서비스·HTTP·presenter·저장소와 기능별 UI/CSS 소유자를 명시했다. 기능 변경 시 모델·저장·API·UI의 공동 계약 검토는 여전히 필요하다. |
| A10 | 10. FEATURE / MODULE PUBLIC API | 부분 적용 | `docs/API_LIBRARIES.md`<br>`cremore/detection/__init__.py`<br>`cremore/secretstore/__init__.py` | 공개 exports와 내부 재사용 진입점을 구분하고 기존 호환 alias를 유지했다. 모든 내부 모듈이 단일 facade를 갖지는 않으며 의도된 테스트 private 접근도 남아 있다. |
| A11 | 11. PYTHON IS THE DEFAULT BACKEND LANGUAGE | 적용 확인 | `pyproject.toml`<br>`collectors/gitlab/collector_v1`<br>`gcp-connector/requirements.txt` | 제품 Python 3.12+, GitLab 3.10+ POSIX, 독립 GCP 3.11+의 서로 다른 실행 조건을 보존했다. backend 언어를 교체하지 않았다. |
| A12 | 12. PYTHON PACKAGE STRUCTURE | 적용 확인 | `cremore`<br>`collectors/gitlab/collector_v1`<br>`gcp-connector`<br>`docs/AI_TEAM_CODING_GUIDE.md` §3 | 플랫폼 wheel과 두 독립 모듈의 설치·수명·의존 경계를 구분했다. 독립 CLI에 플랫폼 내부 import를 도입하지 않았다. |
| A13 | 13. PYTHON FUNCTION DESIGN | 적용 확인 | `cremore/detection/custom.py`<br>`cremore/aws_access.py`<br>`cremore/scanning/orchestrator.py` | rule_detection_policy와 save_approval에 같은 규칙의 소유자를 두고 호출자는 workflow를 구성한다. 함수 수나 행 수만 줄이기 위한 합병은 하지 않았다. |
| A14 | 14. PYTHON TYPE HINTS | 부분 적용 | `cremore/api/route_context.py`<br>`cremore/coverage/metadata_models.py`<br>`docs/AI_TEAM_CODING_GUIDE.md` §5 | typed context·Pydantic/dataclass 계약과 경계 검증을 사용한다. 기존 Any/외부 JSON/동적 SDK 타입은 남아 있고 Python type checker gate는 없다. |
| A15 | 15. PYTHON DATA MODELS | 적용 확인 | `cremore/domain/models.py`<br>`cremore/coverage/metadata_models.py`<br>`cremore/api/http_support.py` | 기존 Pydantic/dataclass와 공개 presenter 경계를 재사용했다. 새 모델 라이브러리를 혼합하지 않았다. |
| A16 | 16. PYTHON IMPORTS | 적용 확인 | `cremore/db/schema.py`<br>`cremore/task_state.py`<br>`cremore/collectors/base.py` | schema→catalog 역의존과 metadata→DB 불필요 의존을 제거하고 provider 공통 path_under를 중립 소유자로 옮겼다. scope 규칙은 scanning 소유를 유지한다. |
| A17 | 17. PYTHON PURE FUNCTIONS | 적용 확인 | `cremore/task_state.py`<br>`cremore/scanning/scope.py`<br>`cremore/detection/validators.py` | checkpoint 검증·root identity·Shannon entropy가 I/O 없는 소유 함수다. 관련 회귀에서 저장/재개, 문자·raw bytes 경계를 확인했다. |
| A18 | 18. PYTHON DEPENDENCY INJECTION | 적용 확인 | `cremore/api/route_context.py`<br>`cremore/worker/factory.py`<br>`cremore/coverage/collector_runtime.py` | 실제 repository·transport·collector 조립 지점을 재사용한다. 소비되지 않는 DashboardContext 필드 7개를 제거했고 작은 함수마다 DI 객체를 만들지 않았다. |
| A19 | 19. PYTHON PROTOCOL / ABC | 적용 확인 | `cremore/collectors/base.py`<br>`cremore/coverage/collector_runtime.py`<br>`cremore/db/repository.py` | 기존 Collector/runtime/repository 계약을 사용한다. 단일 구현을 위해 추가 interface 계층을 만들지 않았다. |
| A20 | 20. PYTHON ERROR HANDLING | 적용 확인 | `cremore/api/http_support.py`<br>`cremore/scanning/trigger_settings.py`<br>`docs/AI_TEAM_CODING_GUIDE.md` §5 | 계층별 기존 오류와 안전한 HTTP envelope를 사용한다. 잘못된 queue URL은 원시 ValueError 대신 기존 TriggerSettingError/미설정 상태로 처리하는 회귀를 보강했다. |
| A21 | 21. PYTHON CONFIGURATION | 적용 확인 | `cremore/config.py`<br>`cremore/source_config.py`<br>`.env.example` | Settings가 alias/default/기동 안전성 검증을 소유한다. 소스별 입력은 source_config에서 검증하며 새 설정에 배포 전달·예제 갱신 절차를 둔다. |
| A22 | 22. PYTHON TESTING | 적용 확인 | `pyproject.toml`<br>`collectors/gitlab/collector_v1/tests`<br>`gcp-connector/tests` | 플랫폼 pytest와 독립 unittest 관례를 보존했다. DB·API·provider·순수 규칙 검사를 사용하며 POSIX/선택 의존성 skip은 통과로 합산하지 않는다. |
| A23 | 23. FRONTEND DEFAULT STACK | 적용 확인 | `web/package.json`<br>`web/tsconfig.json`<br>`web/styles/tailwind.css` | React/strict TypeScript/Tailwind 4를 유지한다. 기존 Node 테스트·빌드 도구의 cjs를 불필요하게 제품 TypeScript로 재작성하지 않았다. |
| A24 | 24. NEXT.JS IS OPTIONAL, NOT MANDATORY | 적용 확인 | `web/app`<br>`web/package.json`<br>`web/AGENTS.md` | 이미 사용 중인 Next.js 16.3.4 App Router와 해당 버전 지침을 따른다. 리팩터링 때문에 새 framework를 도입하지 않았다. |
| A25 | 25. WHEN NEXT.JS MAKES SENSE | 적용 확인 | `web/app/api/backend`<br>`web/lib/dashboard-session.ts`<br>`docs/AI_TEAM_CODING_GUIDE.md` §1 | Next는 페이지 렌더링·서버 프록시·인증 전달을 맡고, OIDC 로그인/cookie는 배포 oauth2-proxy가 소유한다. 존재하지 않는 SEO/SSG 요구를 도입 근거로 꾸미지 않는다. |
| A26 | 26. WHEN REACT + VITE MAY BE SIMPLER | 조건부 | `web/package.json`<br>`docs/AI_TEAM_CODING_GUIDE.md` §1 | 새 SPA framework 선택 시 고려할 규칙이다. 현재 Next 인증 전달/BFF 소비자가 있으므로 Vite 전환을 이번 변경에 포함하지 않는다. |
| A27 | 27. PYTHON BACKEND + NEXT.JS | 적용 확인 | `web/app/api/backend`<br>`cremore/api/app.py`<br>`docs/ARCHITECTURE.md` | Next는 인증 전달/BFF, Python은 권한·업무·DB·공급자 책임을 유지한다. 브라우저 API layer는 같은 backend 계약을 호출한다. |
| A28 | 28. NEXT.JS DECISION RULE | 적용 확인 | `web/package.json`<br>`docs/AI_TEAM_CODING_GUIDE.md` §1 | 기존 Next 사용과 실제 server 책임을 확인하고 유지했다. 새로운 framework 비교·migration은 별도 요구가 있을 때 판단한다. |
| A29 | 29. REACT COMPONENT RULES | 적용 확인 | `web/app/page.tsx`<br>`web/features`<br>`web/lib/dashboard-api.ts` | page는 화면 조합과 공유 상태 연결을 맡고 기능 UI·API·모델은 기존 소유자로 분리한다. 일부 큰 feature 화면까지 모두 작아졌다는 주장은 하지 않는다. |
| A30 | 30. REACT COMPONENT EXTRACTION | 적용 확인 | `web/components/ui-primitives.tsx`<br>`web/features/findings/finding-evidence.tsx` | ModalSurface 등 반복 UI와 finding 증거 표시의 독립 책임을 재사용한다. 작은 JSX마다 새 component/package를 만들지 않는다. |
| A31 | 31. REACT HOOK RULE | 적용 확인 | `web/components/display-timezone.tsx`<br>`web/components/locale.tsx`<br>`web/lib/dashboard-model.ts` | locale/timezone은 React hook, 순수 표시·집계 계산은 모델 함수가 소유한다. 계산만 하는 함수를 hook으로 포장하지 않는다. |
| A32 | 32. FRONTEND STATE OWNERSHIP | 적용 확인 | `web/lib/dashboard-loader.ts`<br>`web/app/page.tsx`<br>`docs/AI_TEAM_CODING_GUIDE.md` §6 | 로컬 상태·폼·서버 요청·선택 상태를 구별하고 props/callback, abort/요청 세대로 오래된 응답을 거부한다. 새 전역 store는 추가하지 않았다. |
| A33 | 33. FRONTEND API ACCESS | 적용 확인 | `web/lib/dashboard-api.ts`<br>`web/app/api/backend`<br>`web/features/aws/aws-accounts.tsx` | 공통 API 오류·proxy 경로를 재사용한다. AWS 조직 템플릿 링크도 인증된 backend proxy를 거치도록 수정하고 렌더링 회귀를 추가했다. |
| A34 | 34. TAILWIND DEFAULT | 부분 적용 | `web/styles/tailwind.css`<br>`web/features`<br>`docs/AI_TEAM_CODING_GUIDE.md` §6 | Tailwind utilities를 지원하지만 기존 화면의 소유 CSS도 유지한다. Preflight 미사용·unlayered cascade를 문서화했으며 전 스타일을 Tailwind로 바꿨다고 주장하지 않는다. |
| A35 | 35. INLINE STYLE RULE | 적용 확인 | `web/features`<br>`web/tests/theme.test.cjs`<br>`docs/AI_TEAM_CODING_GUIDE.md` §6 | 정적 스타일은 CSS/class로 소유하고 inline은 실제 runtime 값에 한정한다. 초기 TS 분석에서 정적 inline style이 없음을 확인했으며 최종 UI 검증은 별도 보고한다. |
| A36 | 36. GLOBAL CSS | 적용 확인 | `web/styles/globals.css`<br>`web/app/layout.tsx`<br>`web/scripts/stylesheets.cjs` | 전역 기본값·토큰·접근성 외의 규칙을 feature/components/shell로 이전했다. import 순서가 cascade 기준이며 stylesheet 검사로 누락·중복을 막는다. |
| A37 | 37. DESIGN SYSTEM | 적용 확인 | `web/components/ui-primitives.tsx`<br>`web/components/ui.css`<br>`web/components/ui-appearance.css` | 기존 공통 primitive와 appearance 소유자를 유지하고 업무 UI는 feature에 둔다. 외부 UI package를 새로 만들지 않았다. |
| A38 | 38. COMMON CODE VS LIBRARY | 적용 확인 | `cremore/collectors/base.py`<br>`cremore/detection/custom.py`<br>`docs/AI_TEAM_CODING_GUIDE.md` §11 | 실제 다중 호출 규칙만 기존 소유 helper로 승격했다. path/탐지 정책 재사용을 별도 배포 라이브러리 생성과 혼동하지 않는다. |
| A39 | 39. WHEN TO CREATE AN INTERNAL LIBRARY | 조건부 | `docs/AI_TEAM_CODING_GUIDE.md` §3·11<br>`pyproject.toml` | 새 내부 배포 package는 독립 소비자·소유권·안정 API·검사/빌드 이익이 확인될 때만 제안한다. 이번 helper 추출에는 독립 package 필요가 없었다. |
| A40 | 40. WHEN TO PUBLISH A LIBRARY | 조건부 | `docs/AI_TEAM_CODING_GUIDE.md` §3·11<br>`web/package.json` | 외부 소비가 확인된 경우 공개 배포를 검토한다. 현재 web은 private 앱이며 feature나 UI를 npm package로 공개하지 않는다. |
| A41 | 41. RECOMMENDED LIBRARY CATEGORIES | 조건부 | `docs/AI_TEAM_CODING_GUIDE.md` §3 | core/ui/provider-sdk 등의 예시 이름은 선택지다. 실제 cremore wheel·독립 CLI를 설명하고 존재하지 않는 package 목록을 만들지 않았다. |
| A42 | 42. CORE PACKAGE | 적용 확인 | `cremore/task_state.py`<br>`cremore/scanning/scope.py`<br>`docs/AI_TEAM_CODING_GUIDE.md` §11 | 순수 checkpoint와 scope 규칙은 의미가 있는 기존 소유자를 갖는다. 모든 타입·비즈니스 규칙을 담는 새 core/common 통합 파일은 만들지 않았다. |
| A43 | 43. UI PACKAGE | 조건부 | `web/components/ui-primitives.tsx`<br>`web/package.json` | 공통 UI는 앱 내부 재사용이다. 외부 소비·exports·versioning 계약이 없는 공개 UI SDK를 현재 지원 기능으로 문서화하지 않는다. |
| A44 | 44. PROVIDER SDK | 조건부 | `cremore/coverage/providers/__init__.py`<br>`docs/METADATA_COLLECTOR_LIBRARIES.md` | 기존 provider 계약/등록은 내부 플랫폼 확장 경계다. 독립 SDK 배포는 소비자·호환 정책이 확인된 뒤 제안하며 앱 내부 DB를 SDK로 노출하지 않는다. |
| A45 | 45. PLUGIN SDK | 조건부 | `docs/AI_TEAM_CODING_GUIDE.md` §8·12 | runtime plugin lifecycle/registry 생태계는 없다. 가상의 Plugin SDK·private DB 접근을 이번 리팩터링에 추가하지 않는다. |
| A46 | 46. PACKAGE PUBLIC API | 적용 확인 | `cremore/api/__init__.py`<br>`cremore/detection/__init__.py`<br>`cremore/secretstore/__init__.py` | 명시적인 공개 entry와 호환 alias를 유지한다. 최신 wheel의 413개 파일 일치 및 3 CLI callable import를 확인했으며 private npm exports는 없다. |
| A47 | 47. PACKAGE EXTRACTION CHECKLIST | 조건부 | `docs/AI_TEAM_CODING_GUIDE.md` §11 | 새 library 제안 전에 소비자·책임·exports·의존·검사·build·호환성을 적도록 했다. 독립 배포 이익이 없는 이번 공통 규칙은 모듈로 유지한다. |
| A48 | 48. AVOID PACKAGE SOUP | 적용 확인 | `pyproject.toml`<br>`web/package.json`<br>`docs/AI_TEAM_CODING_GUIDE.md` §3 | 작은 helper/컴포넌트마다 package를 추가하지 않았다. 기존 독립 GitLab/GCP 경계는 서로 다른 CLI·출력·설치 계약 때문에 유지한다. |
| A49 | 49. OPEN-SOURCE EXTENSIBILITY | 부분 적용 | `docs/AI_TEAM_CODING_GUIDE.md` §12<br>`cremore/config.py`<br>`web/styles/globals.css` | 설정·theme token·provider 주입 확장은 가능하다. 공개 component override나 plugin API가 없고 일부 UI/브랜딩은 source 변경이 필요하다. |
| A50 | 50. CONFIGURATION OVER FORKING | 부분 적용 | `cremore/config.py`<br>`deploy/helm/values.yaml`<br>`docs/AI_TEAM_CODING_GUIDE.md` §9·12 | 운영 설정과 공급자 선택을 기존 config로 처리한다. 제품명/header/sidebar 전체가 런타임 config로 대체되는 제품은 아니다. |
| A51 | 51. UI OVERRIDE | 부분 적용 | `web/app/page.tsx`<br>`web/components/ui-primitives.tsx`<br>`docs/AI_TEAM_CODING_GUIDE.md` §12 | 내부 props/composition은 지원하지만 외부 Header/Sidebar override API는 없다. 해당 UI 변경은 소유 component 수정과 browser proof가 필요하다고 명시했다. |
| A52 | 52. HEADLESS LOGIC | 조건부 | `web/lib/dashboard-model.ts`<br>`web/lib/dashboard-loader.ts`<br>`docs/AI_TEAM_CODING_GUIDE.md` §6 | 순수 계산과 요청 수명은 UI에서 분리되어 있다. 완전한 외부 UI 대체 요구가 없는 모든 feature를 headless API로 만들지는 않았다. |
| A53 | 53. PROVIDER / ADAPTER | 적용 확인 | `cremore/collectors/base.py`<br>`cremore/coverage/providers`<br>`cremore/secretstore/resolver.py` | 콘텐츠·metadata·secret-reference 능력의 서로 다른 계약을 보존했다. domain에 vendor SDK를 넣거나 모든 공급자를 하나의 만능 interface로 합치지 않았다. |
| A54 | 54. COMPOSITION ROOT | 적용 확인 | `cremore/api/app.py`<br>`cremore/worker/factory.py`<br>`cremore/coverage/providers/__init__.py` | 구체 구현은 조립/registry에서 선택한다. 신규 콘텐츠 공급자는 factory·source mapping·지원 kind·UI 등록도 함께 검토해야 한다. |
| A55 | 55. VENDOR RESPONSE NORMALIZATION | 적용 확인 | `cremore/coverage/metadata_models.py`<br>`cremore/coverage/providers/github/normalization.py`<br>`cremore/api/finding_presenters.py` | 공급자 ID/JSON을 정규화하고 공개 응답은 presenter가 소유한다. native GitLab의 보존 정책과 schema2 allowlist는 다른 계약이므로 임의 통합하지 않았다. |
| A56 | 56. VENDOR ERROR NORMALIZATION | 적용 확인 | `cremore/aws_identity.py`<br>`cremore/api/http_support.py`<br>`web/lib/dashboard-api.ts` | bounded error code→안전한 HTTP 오류→DashboardAPIError 흐름을 사용한다. 알 수 없는 수집·쓰기 결과를 성공/부재로 바꾸지 않는다. |
| A57 | 57. ERROR HANDLING | 적용 확인 | `cremore/scanning/trigger_settings.py`<br>`cremore/remediation`<br>`docs/AI_TEAM_CODING_GUIDE.md` §4·5 | 잘못된 입력·인증/권한·충돌·일시 실패를 구별한다. 회전의 OUTCOME_UNKNOWN과 읽기 전용 reconciliation을 보존하고 blanket exception 성공 처리 금지를 명시했다. |
| A58 | 58. LOGGING | 적용 확인 | `cremore/api/http_support.py`<br>`cremore/worker`<br>`docs/AI_TEAM_CODING_GUIDE.md` §5 | 기존 Python logger에 job/run/connection ID·고정 코드만 남기는 규칙을 적었다. body·credential·전체 SDK 예외를 기록하지 않으며 모든 로그 안전성을 새로 인증한 것은 아니다. |
| A59 | 59. CONFIG / ENV | 적용 확인 | `cremore/config.py`<br>`.env.example`<br>`web/app/api/backend` | backend secret과 browser 공개 설정을 분리한다. API_ADMIN_TOKEN 설치 입력→API_TOKEN 전달과 RETIRED_ENV 호환 정책을 문서화했다. |
| A60 | 60. NAMING | 적용 확인 | `cremore/task_state.py`<br>`cremore/detection/custom.py`<br>`docs/AI_TEAM_CODING_GUIDE.md` §13 | 함수/파일의 실제 책임을 드러내는 checkpoint·rule_detection_policy 등의 이름을 사용하고 Python/TS 관례를 기록했다. 관련 없는 전역 rename은 하지 않았다. |
| A61 | 61. BOOLEAN NAMING | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §13<br>`cremore/config.py` | boolean은 상태/허용/판단의 의미가 드러나는 기존 이름을 유지한다. 공개 config 이름을 접두사 미관만으로 바꾸지 않았다. |
| A62 | 62. READABILITY FIRST | 적용 확인 | `gcp-connector/cremore_gcp/relations.py`<br>`cremore/aws_sessions.py` | 한 번 만든 관계 index와 기존 세션 캐시 흐름의 중복을 읽을 수 있는 단계로 정리했다. 공백 축약·한 줄 표현으로 감소 수치를 만들지 않는다. |
| A63 | 63. COMMENTS | 적용 확인 | `deploy/helm/values.yaml`<br>`docker-compose.yml`<br>`gcp-connector/cremore_gcp/collector.py` | Helm opt-in과 public Compose hard-disable의 이유/한계, GCP metadata와 별도 value/watch 차이를 실제 동작에 맞춰 고쳤다. |
| A64 | 64. TEST STRATEGY | 적용 확인 | `pyproject.toml`<br>`web/tests`<br>`deploy/helm/tests/chart.test.cjs` | 순수/API/repository/provider·브라우저·package 검증을 구분한다. 현재 Helm 70개 통과, 독립 GCP 46개와 POSIX GitLab 162개 통과; 최종 전체 실행은 보고서 기준이다. |
| A65 | 65. CHARACTERIZATION TEST | 적용 확인 | `gcp-connector/tests/test_relations.py`<br>`cremore/aws_access_test.py`<br>`web/tests/global-search.browser.cjs` | GCP 출력 순서를 수정 전 characterization으로 고정했고 AWS 승인 경쟁·dialog 회귀는 실패 전/통과 후 근거를 남겼다. 실제 provider 대신 합성 fixture를 사용했다. |
| A66 | 66. OPEN-SOURCE PUBLIC API COMPATIBILITY | 적용 확인 | `docs/API_LIBRARIES.md`<br>`docs/AI_TEAM_CODING_GUIDE.md` §3·11<br>`cremore/api/app.py` | HTTP/CLI/env/저장 형식/import를 호환 경계로 다룬다. 기존 app·수집 helper alias를 유지하고 route·공개 import 검사를 둔다. |
| A67 | 67. SEMANTIC VERSIONING | 조건부 | `pyproject.toml`<br>`.github/workflows/release.yml`<br>`collectors/gitlab/collector_v1` | 새 release는 수행하지 않았다. 플랫폼 0.1.0과 독립 GitLab 0.11.1/schema1.4를 구별하고 version/호환 변경은 별도 release 판단으로 남긴다. |
| A68 | 68. DEPRECATION | 적용 확인 | `cremore/collectors/github.py`<br>`cremore/scanning/orchestrator.py`<br>`cremore/aws_access.py` | 기존 _under/_fetch_json·policy alias를 보존하고 신규 호출자는 실제 공개 소유자를 사용한다. next_revision은 호환 예상값이며 저장은 atomic save_approval을 사용한다. |
| A69 | 69. COLLABORATION | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §13<br>`docs/REFACTOR_COMPLIANCE_PLAN.md` | API/DB·engine·frontend·독립 패키지/배포로 실제 파일 ownership을 나눴다. 공용 CI의 추가 수정은 coordinator 소유로 넘겼다. |
| A70 | 70. CONTRACT-FIRST PARALLEL WORK | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §13<br>`cremore/coverage/metadata_models.py` | 병렬 작업에서 public/저장/등록 계약과 유지할 동작을 먼저 공유했다. 공통 계약 변경은 담당자 간 합의 후 통합하는 절차를 문서화했다. |
| A71 | 71. REDUCE CONFLICT HOTSPOTS | 적용 확인 | `cremore/api/routes`<br>`web/app/layout.tsx`<br>`web/features` | 도메인 route와 기능 CSS 소유를 분리해 중앙 파일 충돌 범위를 줄였다. layout import 순서는 한 소유자가 관리하는 의도된 조립 경계다. |
| A72 | 72. MULTI-AGENT WORK CARD | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §13 | 실제 GitHub metadata 작업 카드에 goal/허용·금지 파일/계약/검증/DoD/handoff를 넣었다. 다른 공급자·DB schema·독립 CLI로 임의 확장하지 않는 범위다. |
| A73 | 73. DIRECTORY RENAMING | 적용 확인 | `docs/REFACTOR_PLAN.md`<br>`cremore`<br>`web/features` | 기존 디렉터리명을 유지하고 책임이 필요한 곳만 분리했다. 구조 개선을 폴더명 교체와 동일시하지 않는다. |
| A74 | 74. FILE RENAMING | 적용 확인 | `web/app/layout.tsx`<br>`web/scripts/stylesheets.cjs`<br>`web/tests/stylesheets.test.cjs` | CSS 소유 이동에 따라 import·theme 생성기·브라우저 harness를 함께 갱신했다. 파일 이동 자체는 중복/행 감소 근거가 아니다. |
| A75 | 75. DO NOT COPY GENERIC ARCHITECTURE BLINDLY | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §2·3 | 현재 cremore/worker/coverage/web 이름으로 책임과 의존을 설명한다. 예시의 domain/application/packages 구조를 새로 덮어쓰지 않았다. |
| A76 | 76. NEW DEPENDENCY RULE | 적용 확인 | `pyproject.toml`<br>`docs/AI_TEAM_CODING_GUIDE.md` §13 | 이미 구현된 Azure workload 인증에 필요한 optional azure extra를 선언했다. 기본 설치 강제나 새 UI helper dependency 없이 wheel metadata를 확인했다. |
| A77 | 77. SECURITY | 부분 적용 | `cremore/api/auth.py`<br>`cremore/api/no_raw_secret_test.py`<br>`docs/AI_TEAM_CODING_GUIDE.md` §9 | server 권한·원문 배제·secret boundary 검사를 보강했다. 이 작업은 전체 보안 인증이 아니며 GCP 명시적 value 저장/독립 export 예외와 설치 단위 권한 한계를 문서화했다. |
| A78 | 78. ACCESSIBILITY | 부분 적용 | `web/components/ui-primitives.tsx`<br>`web/components/global-search.tsx`<br>`web/tests/global-search.browser.cjs` | native dialog·Escape·focus 진입/복귀를 실제 browser 회귀로 보강했다. 전체 UI의 WCAG 적합성 인증은 수행하지 않았으며 label/대비/좁은 화면 규칙을 유지한다. |
| A79 | 79. PERFORMANCE | 부분 적용 | `cremore/coverage/metadata_store.py`<br>`gcp-connector/cremore_gcp/relations.py`<br>`web/features/connections/provider-inventory.tsx` | metadata 40객체 SQL 165→9회, 관계 grouping O(S×E)→O(S+E), 중복 polling 개선을 근거와 분리해 기록한다. v1 전체 목록·단일 content slot·watch 누적 rewrite 제한은 남는다. |
| A80 | 80. DOCUMENTATION | 적용 확인 | `README.md`<br>`docs/API_LIBRARIES.md`<br>`docs/METADATA_COLLECTOR_LIBRARIES.md` | 목적·사용·입출력·오류·확장·호환 경계를 실제 코드로 설명한다. 독립 CLI 출력과 플랫폼 API를 같은 계약으로 문서화하지 않는다. |
| A81 | 81. README RECOMMENDATION | 적용 확인 | `README.md`<br>`web/README.md`<br>`docs/AI_TEAM_CODING_GUIDE.md` | 설치·구조·설정·provider·개발/검사·호환 안내를 역할별 문서로 연결했다. SSO mount와 optional Azure·고객 격리 한계를 실제 지원 범위로 수정했다. |
| A82 | 82. CONTRIBUTING | 적용 확인 | `CONTRIBUTING.md`<br>`docs/AI_TEAM_CODING_GUIDE.md` §10·11·13 | 기여 문서와 팀 지침에서 실제 pip/npm·검사·public boundary·shared 승격·provider/UI 변경 절차를 안내한다. 없는 formatter/typecheck gate를 가정하지 않는다. |
| A83 | 83. ARCHITECTURE DECISION RECORD | 조건부 | `docs/ARCHITECTURE.md`<br>`docs/REFACTOR_PLAN.md`<br>`docs/REFACTOR_REPORT.md` | 중요 경계·기존 framework 유지·package 미분리 근거는 이 문서들에 기록한다. 별도 ADR 디렉터리는 필수로 신설하지 않았다. |
| A84 | 84. MANDATORY PRE-CODING CHECKLIST | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` Quick Start<br>`docs/REFACTOR_COMPLIANCE_PLAN.md` | 코드 작성 전 guide/status/소유자/유사 구현/모든 호출자/계약·검사 확인을 명시했다. 정적 inventory를 관련 원문 읽기의 대체로 취급하지 않는다. |
| A85 | 85. MANDATORY PRE-REFACTOR CHECKLIST | 적용 확인 | `docs/REFACTOR_PLAN.md`<br>`docs/REFACTOR_COMPLIANCE_PLAN.md` | inventory·entry·import·provider·public 계약·검사 환경·이름 유지 근거를 먼저 조사했다. 이후 발견한 실제 누락은 보완 작업과 최종 matrix에 별도 반영한다. |
| A86 | 86. PROJECT-SPECIFIC REFACTOR PLAN FORMAT | 적용 확인 | `docs/REFACTOR_PLAN.md`<br>`docs/REFACTOR_COMPLIANCE_PLAN.md` | 실제 경로별 문제/소유 변경/호환/검증을 계획에 기록했다. 본 대응표는 원문 절과 그 실행·제약을 연결한다. |
| A87 | 87. INCREMENTAL REFACTOR ORDER | 적용 확인 | `docs/REFACTOR_COMPLIANCE_PLAN.md`<br>`docs/REFACTOR_REPORT.md` | 기존 동작 확인→좁은 변경→해당 회귀→공유 경계 확인 순서로 진행했다. final suite·문서·집계가 끝나기 전에는 전체 완료로 판정하지 않는다. |
| A88 | 88. VALIDATION | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §10<br>`.github/workflows/ci.yml` | 최종 코드115993e의 원격 CI35888643039는7개 job 모두 통과했다. Python3.12/3.14 각각4977통과·0skip·342subtests, PostgreSQL/POSIX·독립 CLI·웹474·브라우저21·Helm70·컨테이너3종을 확인했다. 최신 README를 포함한 wheel도 재검증했다. |
| A89 | 89. VALIDATION REPORTING | 적용 확인 | `docs/REFACTOR_REPORT.md`<br>`docs/AI_TEAM_CODING_GUIDE.md` §10 | 통과/실패/skip/미실행을 구분한다. Windows 제약·WSL 통과·기존 Ruff 위반·최초 CI 실패와 최종 원격 통과를 기록했다. 실계정·IdP·운영 배포 미검증도 숨기지 않는다. |
| A90 | 90. AI MUST NOT CHANGE SILENTLY | 적용 확인 | `docs/REFACTOR_REPORT.md`<br>`cremore/aws_access.py`<br>`cremore/db/repository.py` | 기존 계약을 고정하고 발견한 승인 revision 경쟁·감사 기록/오류 처리 수정은 명시적으로 보고한다. schema/env/framework를 몰래 변경하는 방식은 사용하지 않는다. |
| A91 | 91. NEXT.JS MIGRATION IS A SEPARATE DECISION | 조건부 | `web/package.json`<br>`docs/AI_TEAM_CODING_GUIDE.md` §1 | Next.js는 기존 구성이다. 새 도입/제거 migration은 요구·route·배포·세션 영향을 별도 결정해야 하며 이번 변경에 포함하지 않는다. |
| A92 | 92. DEFAULT FRONTEND RECOMMENDATION | 조건부 | `web/package.json`<br>`docs/AI_TEAM_CODING_GUIDE.md` §1 | 미정 framework에 대한 기본 추천이다. 이미 Next BFF/인증 전달을 쓰는 프로젝트에 Vite 추천을 기계적으로 적용하지 않는다. |
| A93 | 93. OPEN-SOURCE CONTRIBUTOR EXPERIENCE | 부분 적용 | `README.md`<br>`docs/AI_TEAM_CODING_GUIDE.md` §7·10·12 | 로컬 실행·검사·provider 추가·token 변경 절차를 제공한다. UI override/plugin·무수정 provider 설치 생태계는 없고 일부 등록과 UI 수정은 source 변경이 필요하다. |
| A94 | 94. STABLE CORE, REPLACEABLE EDGES | 부분 적용 | `cremore/domain`<br>`cremore/coverage/providers`<br>`cremore/db`<br>`docs/AI_TEAM_CODING_GUIDE.md` §3·7 | domain/계약과 교체 가능한 provider·repository 경계를 개선했다. 공급자별 capability와 registration은 명시적이며 모든 UI/인증 기능이 plugin처럼 교체되지는 않는다. |
| A95 | 95. DO NOT OVER-ENGINEER | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §11·13<br>`cremore/task_state.py` | 실제 중복/역의존 문제만 소유 helper·파일로 해결했다. microservice/event bus/plugin/만능 SDK/전면 headless/불필요 package를 추가하지 않았다. |
| A96 | 96. FINAL ARCHITECTURE PRINCIPLE | 부분 적용 | `docs/ARCHITECTURE.md`<br>`docs/AI_TEAM_CODING_GUIDE.md`<br>`docs/REFACTOR_REPORT.md` | 유지보수 경계·테스트 가능성·확장 절차는 구체적으로 개선했다. 잔존 Any/큰 feature/전체 조회·설치 단위 tenancy 때문에 확장성이 완성됐다고 단정하지 않는다. |
| A97 | 97. REQUIRED AI FINAL REPORT | 적용 확인 | `docs/REFACTOR_REPORT.md` | 14개 보고 영역과 팀 가이드 검증을 로컬·최종 원격 결과·최초/보완 기준별 규모·잔여 제약으로 갱신했다. 검사 대상115993e와 이후 문서만 바뀐 커밋의 범위를 구분한다. |
| A98 | 98. FINAL ALWAYS-ON PROMPT | 부분 적용 | `docs/AI_TEAM_CODING_GUIDE.md`<br>`docs/REFACTOR_REQUIREMENTS_MATRIX.md` | 상시 prompt의 실제 구조·언어·계약·검증·협업 원칙을 팀 지침에 구체화했다. 본 표의 부분 적용/조건부 제약까지 함께 전달해야 한다. |
| A99 | 99. FINAL ONE-SENTENCE RULE | 부분 적용 | `docs/AI_TEAM_CODING_GUIDE.md`<br>`docs/REFACTOR_REPORT.md` | 실제 Python/React/Next/경로·계약을 존중한 modular monolith 개선이다. 전체 규칙 완전 충족이나 SaaS 고객 격리/대규모 운영 준비 완료를 의미하지 않는다. |

## 후속 팀 지침 요구: 61개 절

| ID | 원문 절 | 판정 | 실제 소유 코드·문서 | 검증 근거·남은 제약 |
| --- | --- | --- | --- | --- |
| P01 | 1. 리팩토링 완료의 필수 산출물 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` | 필수 산출물이 존재하고 현재 작업 트리 기준으로 갱신했다. 문서 생성 자체를 전체 리팩터링 완료 증거로 사용하지 않는다. |
| P02 | 2. 이 문서의 역할 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §2·3·11·13 | 다음 개발자/AI가 책임·imports·계약·변경 순서·검증을 재사용하는 개발 규칙이다. 설치 설명은 README로 연결한다. |
| P03 | 3. 반드시 실제 저장소를 다시 분석한 후 작성 | 적용 확인 | `docs/REFACTOR_COMPLIANCE_PLAN.md`<br>`docs/AI_TEAM_CODING_GUIDE.md` | 최종636개 소스의 읽기 hash/range가 모두 일치한다. 문서 경로·공개 심볼·CSS/인증/배포 계약을 재대조하고 실제 API 예제2개와 Azure spec 예제를 I/O 없이 검증했다. |
| P04 | 4. Generic Folder Name 사용 금지 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §2 | cremore/api, coverage/providers, web/features, 두 독립 CLI 등 실제 이름을 쓴다. 코드 예시는 존재하는 계약·경로를 사용한다. |
| P05 | 5. 문서 첫 부분에 프로젝트 요약 필수 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §1<br>`pyproject.toml`<br>`web/package.json` | 제품 목적·Python/Next/React/TS/Tailwind·pip/npm·실제 checker/테스트/배포 구성을 첫 부분에 명시했다. 미설정 도구도 구별한다. |
| P06 | 6. 실제 아키텍처 설명 필수 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §2·3<br>`docs/ARCHITECTURE.md` | API·worker·domain·DB·content·metadata·UI·독립 CLI의 실제 책임과 흐름을 설명한다. 독립 GCP를 플랫폼 통합으로 오인하지 않게 했다. |
| P07 | 7. Dependency Direction 명시 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §3<br>`cremore/task_state.py`<br>`cremore/scanning/scope.py` | 조립→서비스/저장/provider와 feature→pure lib 방향을 명시했다. domain vendor 침투·하위 API 역참조·metadata의 DB 역참조 금지를 실제 소유자와 연결한다. |
| P08 | 8. 모듈별 책임 표 필수 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §2<br>`docs/API_LIBRARIES.md` | 모듈 책임 표에 진입점·소비자·변경 시 공동 확인 항목을 보완했다. 내부 재사용 API와 외부 package API를 구분한다. |
| P09 | 9. Public API 규칙 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §3·11<br>`cremore/api/__init__.py` | 공개 exports/CLI/HTTP/env/저장 형식의 호환 경계를 설명한다. 신규 코드는 실제 소유자, 외부 코드는 공식 entry를 쓰며 기존 alias는 보존한다. |
| P10 | 10. Python 개발 규칙 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §1·5·13<br>`pyproject.toml` | Python 버전·pip·Pydantic/dataclass·type hint·순수 규칙·DI·오류·logger·테스트·naming을 실제 코드 기준으로 설명한다. 별도 typecheck/format gate는 없다고 적었다. |
| P11 | 11. Python 신규 기능 추가 절차 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §11<br>`cremore/api/routes`<br>`cremore/db` | 유사 구현 검색→규칙/모델/서비스→repository/provider 필요→route/presenter→권한/오류/회귀→문서 절차가 실제 경로를 따른다. |
| P12 | 12. React / TypeScript / Tailwind 개발 규칙 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §6<br>`web/lib`<br>`web/features` | TS/React·props/callback·요청 수명·loading/error/empty·모델과 hook·Tailwind/소유 CSS·접근성을 실제 소유 경로와 연결한다. |
| P13 | 13. Next.js 여부 명확히 기록 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §1<br>`web/app/api/backend` | Next 사용 여부·버전·App Router·BFF/인증 전달 역할을 명시했다. Vite/공개 npm UI library라고 기술하지 않는다. |
| P14 | 14. React Component 추가 절차 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §6·11<br>`web/components/ui-primitives.tsx` | 실제 ModalSurface/DialogHead TS 예시와 feature 배치·공유 승격·KO/EN·theme·키보드 검증 절차가 있다. |
| P15 | 15. Tailwind / CSS 규칙 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §6<br>`web/app/layout.tsx`<br>`web/features/governance/governance-workflow.module.css` | Tailwind 진입·Preflight 미사용·tokens·CSS owner/order·Module·동적 inline·class 결합 관례를 명시했다. clsx/tailwind-merge/CVA 미설치도 정확히 적었다. |
| P16 | 16. Shared Code 규칙 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §11<br>`cremore/scanning/scope.py`<br>`web/components` | domain-neutral·실제 독립 소비자·순수/안정 책임이 있을 때 기존 소유자로 승격한다. domain 규칙을 shared/common dump로 보내지 않는다. |
| P17 | 17. Library / Package 구조 설명 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §3<br>`pyproject.toml`<br>`web/package.json` | cremore wheel·탐지/secretstore exports·내부 API/metadata·private web·독립 GitLab/GCP의 목적/소비/검사/호환을 구분했다. |
| P18 | 18. 신규 Library/Package 추가 규칙 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §11 | 새 package 제안에 소비자·책임·공개 exports·dependency·test/build·version/호환 정책을 요구한다. 폴더와 독립 배포 package를 구별한다. |
| P19 | 19. Provider Architecture 전체 설명 필수 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §7·8<br>`cremore/worker/factory.py`<br>`cremore/coverage/providers/__init__.py` | 콘텐츠·metadata·auth·secretstore의 실제 능력/선택 경계를 설명한다. 모든 저장·vendor 기능을 동일 provider interface로 일반화하지 않는다. |
| P20 | 20. 현재 Provider 목록 작성 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §7<br>`cremore/coverage/providers`<br>`cremore/collectors` | 실제 공급자 목록과 capability·계약/조립·설정·테스트 표를 보완했다. Azure metadata-only와 Atlassian/Bitbucket·독립 CLI 범위를 구별한다. |
| P21 | 21. 신규 SaaS / Cloud Provider 추가 절차 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §7<br>`cremore/source_config.py`<br>`cremore/worker/factory.py` | SaaS/cloud 추가의 spec→adapter→정규화→등록→검사→문서를 명시하고 콘텐츠는 kind/catalog/scope/API/UI까지 별도 추적한다. Azure를 콘텐츠 factory에 잘못 등록하지 않는다. |
| P22 | 22. 신규 Provider에서 하면 안 되는 것 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §7·13<br>`cremore/domain` | domain SDK 침투·원문 응답/오류 전파·scope 재라벨링·불완전 결과 성공 처리·테스트 약화 금지를 실제 경계로 명시했다. |
| P23 | 23. Provider Contract 확장 규칙 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §7<br>`cremore/coverage/providers/gcp`<br>`cremore/coverage/providers/atlassian` | 공통 기능·optional capability·vendor 내부 기능을 먼저 구별한다. value_context/recollection 사례로 무조건 공통 메서드 확대를 피하도록 했다. |
| P24 | 24. Python Provider 예시를 실제 코드로 제공 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §7<br>`cremore/coverage/metadata_models.py`<br>`cremore/coverage/providers/__init__.py` | 실제 MetadataConnectionSpec/collector_for를 사용한 Azure spec 검증 Python 예제가 있다. validate_spec만 실행하며 collect의 외부 I/O와 구분한다. |
| P25 | 25. AI / LLM Provider 추가 규칙 | 조건부 | `docs/AI_TEAM_CODING_GUIDE.md` §8 | 현재 LLM 호출/streaming/tool API는 없다. 탐지 catalog의 OpenAI credential 패턴을 AI provider 통합으로 오인하지 않으며 미래 요구·입출력·비용·fake 검증 절차만 적었다. |
| P26 | 26. Auth Provider 추가 규칙 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §8<br>`cremore/api/auth.py`<br>`web/lib/dashboard-session.ts` | local/OIDC·issuer/JWKS/audience/group 매핑과 서버 권한 검사를 실제 계약으로 설명한다. OIDC 로그인/cookie는 배포 oauth2-proxy가 맡는다. 새 방식은 API/web cookie·CSRF·role 경계를 함께 검토한다. |
| P27 | 27. Payment Provider 추가 규칙 | 조건부 | `docs/AI_TEAM_CODING_GUIDE.md` §8 | 결제 provider는 없다. Stripe credential 탐지는 결제 통합이 아니며 존재하지 않는 Payment contract/factory를 만들지 않는다. |
| P28 | 28. Storage Provider 추가 규칙 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §8<br>`cremore/secretstore/resolver.py`<br>`cremore/db/repository.py` | SQL 저장소·콘텐츠 reader·비밀 참조를 구별한다. S3 수집기를 upload/delete용 StorageProvider로 바꾸지 않고 Vault/KMS·sealed 호환 확장 절차를 설명한다. |
| P29 | 29. Database / ORM 규칙 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §5<br>`cremore/db/schema.py`<br>`cremore/db/migrations.py` | 실제 SQLAlchemy/repository/memory·transaction/CAS·connection 수명·bound query·SQLite/opt-in PostgreSQL을 설명한다. 긴 외부 I/O 동안 write transaction 유지 금지를 적었다. |
| P30 | 30. Database 변경 절차 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §5·11<br>`cremore/db/migrations.py` | domain→schema→SQL/memory→presenter/UI·legacy NULL/JSON·번호/backup/offline/rollback을 따라 변경한다. 존재하지 않는 Alembic 명령을 만들지 않았다. |
| P31 | 31. Config / Environment Variable 규칙 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §9<br>`cremore/config.py`<br>`.env.example` | 주요 env의 용도·필수 조건/default·비밀 여부·backend 보관을 보완했다. Settings.validate_safety와 Compose/Helm 전달·예제·검사 갱신 위치를 명시한다. |
| P32 | 32. Error Handling Guide | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §5<br>`cremore/api/http_support.py`<br>`web/lib/dashboard-api.ts` | 실제 CoverageError/TicketError/SecretRefError/AwsLoginRequired 등과 bounded code→HTTP envelope→DashboardAPIError 흐름을 적었다. 인증/충돌/일시 실패/빈 상태를 구분한다. |
| P33 | 33. Logging Guide | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §5<br>`cremore/api/http_support.py` | logging 모듈 logger·job/run/connection 맥락·고정 코드와 금지 payload를 설명한다. 새로운 로깅 서비스나 전체 vendor 예외 덤프를 권하지 않는다. |
| P34 | 34. Testing Guide | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §10<br>`pyproject.toml`<br>`web/package.json` | backend 계층·Node 단위·실제 browser·독립 unittest·배포/패키지 검증 경로/명령과 선택 환경 조건을 기록했다. remote 실행과 local 실행을 구분한다. |
| P35 | 35. Provider Contract Test Guide | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §7·10<br>`cremore/coverage/providers/metadata_resume_test.py`<br>`cremore/coverage/tests/atlassian` | fake response 등록, pages/replay/errors/cancel/budget/identity 계약과 live opt-in 경계를 설명한다. Atlassian 24파일/6,366행을 읽었고 JSON Schema/date-time 검사도 최종 Linux 전체 실행에 포함해 통과했다. |
| P36 | 36. Public Package Test Guide | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §3·10·11<br>`pyproject.toml` | wheel build/public import/CLI·독립 package 검사 절차를 적었다. 최신 wheel 413파일 일치·3 CLI import를 확인했으며 공개 TS 선언 배포는 해당 없음이다. |
| P37 | 37. Frontend 신규 Feature 절차 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §6·11<br>`web/features/connections`<br>`web/lib/dashboard-types.ts` | 기존 feature/types/API→props·상태/순수 함수→소유 style→loading/error/empty·접근성→검사→공개 영향 순서를 실제 경로로 제시한다. |
| P38 | 38. Backend 신규 Feature 절차 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §5·11<br>`cremore/api/route_context.py`<br>`cremore/api/routes` | 기존 도메인 규칙·presenter·repository를 찾고 실제 context 의존성만 추가한다. 역할/잘못된 입력/성공/legacy/경쟁 검사를 포함한 절차다. |
| P39 | 39. 신규 공통 UI 추가 규칙 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §11<br>`web/components/ui-primitives.tsx` | 두 독립 feature에서 실제 사용하고 domain-neutral·안정 props/theme/접근성을 가진 UI만 기존 공통 소유자로 승격한다. |
| P40 | 40. 신규 Shared Utility 규칙 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §11<br>`cremore/scanning/scope.py`<br>`web/components/locale.tsx` | scope identity·provider page loop·번역/표시의 실제 소유자를 예로 들었다. 도메인 의미가 다른 중복 유사 코드를 공통 util로 합치지 않는다. |
| P41 | 41. Plugin / Extension 규칙 | 조건부 | `docs/AI_TEAM_CODING_GUIDE.md` §12 | runtime plugin 계약/등록/lifecycle은 없다. 존재하지 않는 지원 기능을 문서로 만들지 않으며 private DB import를 확장 API로 노출하지 않는다. |
| P42 | 42. Theme / Customization Guide | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §12<br>`web/styles/globals.css`<br>`web/app/layout.tsx` | 색상·간격·radius·브랜딩·언어/시간·공통 UI·허용 범위·provider의 실제 변경 위치와 검사/제약을 나열했다. |
| P43 | 43. Core 수정 없이 가능한 Customization 표 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §12<br>`cremore/config.py`<br>`web/components/ui-primitives.tsx` | customization 표에서 token/config/provider 주입과 source 수정이 필요한 UI를 구별한다. 지원하지 않는 header/sidebar override·plugin을 지원한다고 쓰지 않는다. |
| P44 | 44. Architecture Guardrails | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §3·13 | private deep import·domain SDK·static inline/global dump·shared dump·silent API/schema/env/framework 변경·package 남발을 금지한다. 기존 내부 import와 외부 공개 계약은 구별한다. |
| P45 | 45. Dependency 추가 규칙 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §10·13<br>`pyproject.toml`<br>`web/package-lock.json` | 중복·유지보수·보안/라이선스·runtime/bundle/설치 부담을 검토하고 pip/npm 및 manifest/lockfile 동시 갱신 위치를 명시한다. 선택 extra 설치 명령을 제공한다. |
| P46 | 46. 신규 Package 제안 절차 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §11 | consumer·책임·public API·의존 방향·내부/외부 여부·test/build·versioning을 제안에 넣게 했다. 현재 내부 helper를 독립 package로 배포하지 않는다. |
| P47 | 47. Package Deep Import 금지 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §3<br>`cremore/detection/__init__.py`<br>`cremore/secretstore/__init__.py` | 외부 consumer는 공식 공개 entry를 사용하고 내부 신규 코드는 실제 소유자를 import한다. 의도된 private 테스트가 외부 지원 API를 뜻하지 않는다고 설명한다. |
| P48 | 48. Naming Convention | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §13<br>`web/features/scans/scan-dialog.tsx`<br>`web/lib/dashboard-model.ts` | Python module/class/function/constant/private/test와 TS component/hook/type/utility/test naming을 실제 파일 예로 제시했다. |
| P49 | 49. AI Agent 작업 시작 체크리스트 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` Quick Start | guide/AGENTS/status→소유 module·호출자·계약·테스트/style/package 영향 확인의 작업 시작 절차가 있다. 후속 세션에도 원문 두 문서와 대응표를 연결한다. |
| P50 | 50. AI Agent가 코드 작성 전 해야 할 검색 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §11·Quick Start | 함수/UI/type/provider/util/config 작성 전에 rg로 기존 규칙·모델·presenter·repository와 소비자를 찾도록 명시했다. |
| P51 | 51. AI Agent가 하지 말아야 할 것 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §13 | generic 구조 덮어쓰기·중복·private 침투·silent 계약 변경·framework/library 남발·shared dump·검사 삭제와 허위 행 감소 보고를 금지한다. |
| P52 | 52. Multi-Agent Collaboration | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §13 | owned boundary/허용·금지 파일/public contract/validation을 지정하고 공용 파일 동시 대규모 수정과 무합의 계약 변경을 피하도록 했다. |
| P53 | 53. AI 작업 카드 예시 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §13<br>`cremore/coverage/providers/github` | GitHub metadata 페이지 실패 회귀의 실제 작업 카드를 보완했다. 허용/금지 파일·cursor/PARTIAL 계약·synthetic red/green·DoD·coordinator handoff가 있다. |
| P54 | 54. Validation Command Reference | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §10<br>`pyproject.toml`<br>`web/package.json` | 복사 가능한 pytest/Ruff/npm test/tsc/build/browser/unittest/wheel/Helm/diff 명령과 PowerShell·POSIX·옵션 의존성을 기록했다. 없는 lint/type/format 명령을 추측하지 않는다. |
| P55 | 55. Definition of Done for Team AI Work | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md` §13 | 소유자·기존 패턴·모든 호출/저장/public 계약·회귀/정적/build/UI·문서/설정·미검증 공개를 DoD로 둔다. 명령 존재와 실제 통과를 구별한다. |
| P56 | 56. README와 AI Guide 역할 구분 | 적용 확인 | `README.md`<br>`docs/AI_TEAM_CODING_GUIDE.md` | README는 설치/제품 사용, 팀 guide는 코드 변경/경계/확장·검증 절차를 담당한다. 서로 연결하되 목적을 혼동하지 않는다. |
| P57 | 57. 리팩토링 AI가 마지막에 반드시 해야 할 일 | 적용 확인 | `docs/AI_TEAM_CODING_GUIDE.md`<br>`docs/REFACTOR_REPORT.md` | 최종 트리의 읽기 범위·검사/build·실제 경로/API/provider·문서 예제를 대조했다. 최종 보고에 팀 가이드 경로·원격 CI7개 job 통과·미검증 운영 환경을 포함한다. |
| P58 | 58. 리팩토링 AI에게 주는 최종 강제 프롬프트 | 부분 적용 | `docs/AI_TEAM_CODING_GUIDE.md`<br>`docs/REFACTOR_REQUIREMENTS_MATRIX.md` | 필수40개 주제를 현재 코드·Common Recipes·Quick Start에 연결했다. LLM/payment/plugin은 현재 없는 조건부 기능이다. 최신 소스 재검토·로컬·원격 검증을 완료했으며 실제 구조의 부분 적용 제약은 남겼다. |
| P59 | 59. 리팩토링 최종 보고에도 포함 | 적용 확인 | `docs/REFACTOR_REPORT.md`<br>`docs/AI_TEAM_CODING_GUIDE.md` | 최종 보고에 guide 경로·구조/언어/provider/package/검사/customization/협업 범위와 문서 검증을 기록했다. 로컬 실행과 검사 대상 commit의 원격 결과를 구분한다. |
| P60 | 60. 리팩토링 완료 조건에 포함 | 적용 확인 | `docs/REFACTOR_REPORT.md`<br>`docs/REFACTOR_COMPLIANCE_PLAN.md` | guide·최종636개 소스 읽기·Quick Start·Recipes·README 최신화·wheel 확인을 마쳤다. 코드115993e를 push했고 최종 CI35888643039의7개 job 통과를 확인했다. 이후 변경은 최종 문서만 포함한다. |
| P61 | 61. 최종 원칙 | 부분 적용 | `docs/AI_TEAM_CODING_GUIDE.md`<br>`docs/REFACTOR_REQUIREMENTS_MATRIX.md` | 다음 개발자가 같은 소유자·계약·검증 절차로 변경할 근거를 만들었다. 부분 적용/조건부/미검증 항목도 넘겨야 하며 문서 존재만으로 안전한 확장 완료를 보장하지 않는다. |
