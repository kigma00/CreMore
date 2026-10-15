# POST_REFACTOR_AI_TEAM_GUIDE_REQUIREMENT.md
## 리팩토링 완료 직후 반드시 생성해야 하는 팀 공용 AI 바이브코딩 지침

> **목적**
>
> 이 문서는 리팩토링 자체를 위한 규칙이 아니다.
>
> 리팩토링이 완료된 직후, 리팩토링을 수행한 AI가 반드시 **현재 프로젝트 전용의 상세 개발 지침서**를 생성하도록 요구하는 문서다.
>
> 그 결과물은 다른 개발자들이 각자의 AI 코딩 에이전트에 첨부하여 신규 기능 개발, 버그 수정, UI 개발, Provider 추가, 라이브러리 확장, 테스트 작성 등 모든 후속 작업에서 동일한 구조와 규칙을 유지하기 위한 **Single Source of Truth** 역할을 해야 한다.
>
> 중요한 원칙:
>
> - Generic Template만 제공하면 안 된다.
> - 반드시 리팩토링이 끝난 **실제 저장소**를 다시 읽고 작성한다.
> - 실제 디렉토리명, 실제 Python package명, 실제 frontend path, 실제 import 방식, 실제 Public API, 실제 Provider 이름, 실제 build/test 명령을 사용한다.
> - 문서의 모든 예시는 가능하면 실제 프로젝트 코드와 경로를 사용한다.
> - 다른 팀원이 새 채팅/새 AI Agent에서 이 문서 하나만 첨부해도 프로젝트의 핵심 개발 규칙을 이해할 수 있을 정도로 상세해야 한다.

---

# 1. 리팩토링 완료의 필수 산출물

리팩토링이 완료되면 AI는 반드시 다음 파일을 생성해야 한다.

권장 파일명:

```text
AI_TEAM_CODING_GUIDE.md
```

또는 프로젝트 문서 convention에 맞춰:

```text
docs/AI_TEAM_CODING_GUIDE.md
docs/engineering/AI_TEAM_CODING_GUIDE.md
```

등의 실제 프로젝트 경로를 선택한다.

파일 위치는 기존 프로젝트 문서 구조를 먼저 확인한 뒤 결정한다.

---

# 2. 이 문서의 역할

`AI_TEAM_CODING_GUIDE.md`는 리팩토링 이후 모든 팀원과 AI Agent가 참고하는 **상시 개발 규칙**이어야 한다.

다음 작업 모두에 적용한다.

```text
신규 Feature
Bug Fix
Backend API
Python Business Logic
React Component
Frontend Page
Tailwind Styling
Database Access
Provider 추가
SaaS 연동
Cloud 연동
AI Provider 연동
Auth Provider 연동
Payment Provider 연동
Storage Provider 연동
Library/Package 추가
Plugin/Extension 추가
Refactoring
Testing
Documentation
Configuration
```

---

# 3. 반드시 실제 저장소를 다시 분석한 후 작성

리팩토링 직후 AI는 문서를 바로 작성하지 말고 먼저 **완료된 상태의 저장소를 다시 Inventory** 해야 한다.

확인해야 할 항목:

```text
최상위 디렉토리
Backend root
Python package root
Frontend root
Entry Point
Routing
API
Feature/Module
Public API
Internal API
Shared code
Reusable libraries/packages
Provider interfaces
Vendor adapters
Database layer
Config
Environment variables
React components
Hooks
State management
Tailwind/CSS
Tests
Fixtures
Build scripts
Lint/typecheck commands
Release/package config
Docs
```

리팩토링 전 구조가 아니라 **리팩토링 완료 후 최종 구조**를 기준으로 작성한다.

---

# 4. Generic Folder Name 사용 금지

실제 프로젝트에 없는 이름을 문서에서 기본 구조처럼 사용하지 않는다.

예를 들어 실제 프로젝트가:

```text
server/
client/
lib/
connectors/
```

라면 문서에서도 그 이름을 사용한다.

아래 이름은 실제 프로젝트에 존재할 때만 사용한다.

```text
src
features
shared
domain
application
infrastructure
integrations
packages
```

문서는 실제 프로젝트 전용이어야 한다.

---

# 5. 문서 첫 부분에 프로젝트 요약 필수

`AI_TEAM_CODING_GUIDE.md` 첫 부분에는 다음을 명시한다.

```text
# Project Overview

Backend:
- Python 3.x
- 실제 framework
- 실제 dependency manager

Frontend:
- TypeScript
- React
- Tailwind CSS
- 실제 build/framework: Vite / Next.js / etc.

Architecture:
- Modular Monolith
- 실제 module boundary 설명

Database:
- 실제 DB / ORM

Major External Providers:
- 실제 SaaS / Cloud 목록

Reusable Packages:
- 실제 package 목록

Testing:
- 실제 test framework

Package Manager:
- 실제 도구
```

버전은 실제 config를 확인해서 기록한다. 추측 금지.

---

# 6. 실제 아키텍처 설명 필수

문서에 리팩토링 후의 아키텍처를 명확히 설명한다.

반드시 포함:

```text
애플리케이션 진입점
Backend 주요 Layer
Frontend 주요 Layer
Feature/Module Boundary
Shared 영역
Library/Package Boundary
Provider/Adapter Boundary
Config 위치
Test 위치
Public API 위치
```

가능하면 실제 경로를 사용한 ASCII 구조를 제공한다.

```text
<실제-project-root>/
├─ <실제-backend-path>/
│  ├─ ...
├─ <실제-frontend-path>/
│  ├─ ...
└─ ...
```

---

# 7. Dependency Direction 명시

문서에는 프로젝트의 실제 의존 방향을 적는다.

개념 예:

```text
Frontend Page
    ↓
Frontend Feature API
    ↓
Python HTTP API
    ↓
Application Logic
    ↓
Domain
    ↓
Repository / Provider Contract
    ↑
Adapter
```

최종 문서에서는 실제 프로젝트 구조에 맞게 수정한다.

---

# 8. 모듈별 책임 표 필수

각 주요 Module/Feature의 책임을 표로 정리한다.

| Module | 실제 경로 | 책임 | 외부에 공개하는 API | 수정 시 주의점 |
|---|---|---|---|---|
| Users | 실제 경로 | 계정/프로필 | 실제 export | Auth 영향 |
| Orders | 실제 경로 | 주문 | 실제 API | 결제 영향 |
| Billing | 실제 경로 | 과금 | 실제 API | 금액 계산 |

최종 문서에서는 실제 프로젝트 Module을 사용한다.

---

# 9. Public API 규칙

다른 Module에서 접근 가능한 Public API를 명확히 적는다.

Python 예:

```python
from project.orders import create_order
```

TypeScript 예:

```ts
import { OrderTable } from "@/actual/path";
```

문서에 다음을 반드시 명시한다.

```text
허용된 import
금지된 deep import
Internal path
Public path
```

---

# 10. Python 개발 규칙

프로젝트 Backend가 Python이므로 실제 Python 규칙을 상세히 적는다.

포함:

```text
Python version
Backend framework
Formatter
Linter
Type checker
Test framework
Dependency manager
Package layout
Import convention
Type hint convention
Error handling
Logging
Config
Repository convention
Provider interface style
```

실제 사용 도구만 기록한다.

---

# 11. Python 신규 기능 추가 절차

팀원이 Python 기능을 추가할 때 순서를 명시한다.

```text
1. 기존 동일/유사 기능 검색
2. 소유 Module 확인
3. Public API 영향 확인
4. Domain/Application 위치 결정
5. DB 접근이면 기존 Repository 방식 사용
6. 외부 연동이면 기존 Provider 방식 사용
7. Type hint 작성
8. Test 작성
9. Public API 필요 시 export 추가
10. 실제 validation 명령 실행
```

실제 경로/파일 예시를 함께 제공한다.

---

# 12. React / TypeScript / Tailwind 개발 규칙

문서에는 실제 Frontend 구조를 상세히 설명한다.

반드시 포함:

```text
React component 위치
Page 위치
Feature component 위치
Shared UI 위치
Hook 위치
API client 위치
State ownership
Type 위치
Tailwind convention
Global CSS 위치
Design token 위치
```

실제 프로젝트 디렉토리명을 사용한다.

---

# 13. Next.js 여부 명확히 기록

문서 작성 시 실제 프로젝트가 `Next.js`인지 `React + Vite`인지 명시한다.

Next.js를 사용한다면 실제 사용 방식만 설명한다.

```text
App Router / Pages Router
Server Component
Client Component
Route Handler
Frontend server responsibility
Python backend와의 역할 분담
```

Next.js가 아니면 Next.js 사용법을 문서에 넣지 않는다.

---

# 14. React Component 추가 절차

```text
Feature-specific UI
→ 해당 Feature 내부

여러 독립 Feature가 사용하는 범용 UI
→ shared UI 또는 실제 UI package

업무 개념을 포함하는 UI
→ shared로 이동하지 않음
```

실제 경로를 예로 든다.

---

# 15. Tailwind / CSS 규칙

반드시 프로젝트 전용 styling 규칙을 문서화한다.

포함:

```text
Tailwind version/config
class helper
CVA 사용 여부
Global CSS 경로
Design Token
Theme
CSS Module 사용 여부
Inline style 허용 기준
```

정적 스타일은 Tailwind를 기본으로 한다.
Runtime 계산값은 inline style 허용 가능.

---

# 16. Shared Code 규칙

현재 프로젝트의 실제 Shared 영역을 설명한다.

다음 기준을 반드시 포함한다.

```text
한 Module에서 사용
→ Module 내부

독립 Module 여러 곳에서 사용 + Domain neutral
→ Shared 후보

업무 Rule
→ 소유 Domain/Public API 유지

Vendor-specific
→ Provider/Adapter 영역
```

현재 프로젝트에서 이미 shared로 이동된 대표 사례도 예시로 제공한다.

---

# 17. Library / Package 구조 설명

리팩토링 결과 내부 또는 공개 Library/Package가 있다면 모두 설명한다.

각 Package마다:

```text
이름
실제 경로
목적
Internal/Public
Public Export
허용 Consumer
금지된 Import
Dependency
Test
Build
Versioning
```

을 작성한다.

---

# 18. 신규 Library/Package 추가 규칙

다음 조건을 만족할 때만 새 Package를 고려한다.

```text
여러 독립 Consumer
명확한 책임
안정적인 API
독립 Test 가능
Dependency Boundary 개선
외부 Open-source Consumer 가치
```

다음 이유만으로 Package 생성 금지:

```text
파일이 많음
중요해 보임
깔끔해 보임
미래에 쓸 것 같음
```

---

# 19. Provider Architecture 전체 설명 필수

현재 프로젝트에서 외부 시스템을 어떻게 격리하는지 상세히 적는다.

```text
Business/Application
        ↓
Provider Contract
        ↑
Vendor Adapter
```

최종 문서에서는 실제 프로젝트 경로를 사용한다.

---

# 20. 현재 Provider 목록 작성

실제 Provider를 표로 작성한다.

| Capability | Contract | Current Adapter | Config | Test |
|---|---|---|---|---|
| Storage | 실제 interface | 실제 adapter | 실제 config | 실제 test |
| Email | 실제 interface | 실제 adapter | 실제 config | 실제 test |
| Payment | 실제 interface | 실제 adapter | 실제 config | 실제 test |
| AI | 실제 interface | 실제 adapter | 실제 config | 실제 test |

존재하지 않는 Capability를 억지로 추가하지 않는다.

---

# 21. 신규 SaaS / Cloud Provider 추가 절차

이 항목은 다른 팀원이 자주 참고할 수 있으므로 매우 상세하게 작성한다.

```text
1. 동일 capability의 기존 Provider Contract 확인
2. Contract가 새 Provider에도 충분한지 검토
3. Vendor SDK 설치 필요 여부 판단
4. Vendor Adapter 작성
5. Vendor request/response를 내부 타입으로 변환
6. Vendor Error를 내부 Error로 변환
7. Config schema에 Provider 설정 추가
8. 실제 Composition Root / Factory에 등록
9. Business Logic 수정 없이 동작하는지 확인
10. Provider Contract Test 실행
11. Integration Test 작성
12. .env.example 또는 실제 예제 설정 갱신
13. 개발자 문서 갱신
14. Open-source 사용자용 사용법 갱신
```

최종 문서에서는 위 단계를 실제 파일 경로로 바꿔 쓴다.

예:

```text
Contract:
<actual path>

Adapter directory:
<actual path>

Provider factory/composition:
<actual path>

Config schema:
<actual path>

Contract tests:
<actual path>
```

---

# 22. 신규 Provider에서 하면 안 되는 것

명확히 금지한다.

```text
Business Logic 안에서 Vendor SDK 직접 import
Vendor별 Domain 복제
Provider 선택 if/else를 여러 Business file에 분산
Vendor Response를 Application 전체에 노출
Vendor Error를 UI까지 그대로 전달
Secret를 코드에 하드코딩
새 Provider 때문에 기존 Public Contract를 불필요하게 깨뜨림
```

---

# 23. Provider Contract 확장 규칙

새 Provider가 기존 Contract로 표현되지 않을 때 먼저 묻는다.

```text
새 capability가 모든 Provider에 공통인가?
기존 Contract가 Vendor-specific하게 잘못 설계됐는가?
Optional capability로 분리할 수 있는가?
별도 Provider Contract가 더 자연스러운가?
```

Vendor 하나 때문에 공통 Contract를 거대하게 만들지 않는다.

개념 예:

```text
StorageProvider
MultipartUploadProvider
SignedUrlProvider
```

---

# 24. Python Provider 예시를 실제 코드로 제공

문서 생성 AI는 현재 프로젝트에 맞는 실제 예제를 넣는다.

개념 예:

```python
class EmailProvider(Protocol):
    def send(
        self,
        message: EmailMessage,
    ) -> EmailResult:
        ...
```

최종 문서에서는 실제 클래스명, 실제 import, 실제 경로, 실제 typing style을 사용한다.

---

# 25. AI / LLM Provider 추가 규칙

AI/LLM Provider가 존재하면 별도 항목을 만든다.

반드시 설명:

```text
Provider contract
Model selection 위치
API key config
Request normalization
Response normalization
Streaming 처리
Tool/function calling 처리
Timeout/retry policy
Token/cost logging policy
PII handling
Fallback 여부
Test double/fake provider
```

OpenAI/Anthropic/Gemini 등 Vendor별 로직은 Adapter 안에 유지한다.

---

# 26. Auth Provider 추가 규칙

Auth Provider가 교체 가능하다면 설명:

```text
Identity normalization
User ID mapping
Session/token boundary
Role/permission mapping
Callback handling
Secret config
Frontend login integration
Backend authorization responsibility
```

Domain User가 Vendor User 객체에 의존하지 않게 한다.

---

# 27. Payment Provider 추가 규칙

결제가 있다면:

```text
Payment contract
Currency/amount representation
Idempotency
Payment status normalization
Webhook verification
Vendor error mapping
Refund contract
Test/sandbox configuration
Secret handling
```

실제 프로젝트에 해당하는 항목만 작성한다.

---

# 28. Storage Provider 추가 규칙

Storage가 있다면 실제 Contract 범위를 문서화한다.

가능한 항목:

```text
upload
download/read
delete
metadata
public/private access
signed URL
content type
size limit
key/path convention
```

지원하지 않는 기능을 문서상 Contract로 만들지 않는다.

---

# 29. Database / ORM 규칙

실제 DB와 ORM을 문서화한다.

포함:

```text
Repository path
ORM model path
Migration path
Transaction convention
Session/connection ownership
Query convention
Test DB
```

---

# 30. Database 변경 절차

```text
1. Domain requirement 확인
2. Migration 작성
3. Backward compatibility 확인
4. Model/Repository 수정
5. Test 수정
6. Fixture 수정
7. API 영향 확인
8. Rollback/배포 순서 필요 여부 확인
```

실제 migration tool과 명령을 적는다.

---

# 31. Config / Environment Variable 규칙

실제 Config 파일과 validation 위치를 문서화한다.

주요 env var는 가능하면 다음 정보를 포함한다.

```text
이름
용도
Required/Optional
Backend/Frontend
Secret 여부
Default 여부
```

새 env var 추가 시 함께 갱신할 위치:

```text
config schema
.env.example 또는 equivalent
docs
tests
deployment config if applicable
```

---

# 32. Error Handling Guide

프로젝트 실제 Error 흐름을 설명한다.

```text
Vendor Error
↓
Infrastructure Error
↓
Application Error
↓
API Error Response
↓
Frontend Error Presentation
```

실제 Exception class, Error Code, mapping 위치를 기록한다.

---

# 33. Logging Guide

실제 Logger를 기록한다.

포함:

```text
logger import
log level
structured fields
request/user context
민감정보 금지 규칙
Provider logging
```

---

# 34. Testing Guide

실제 테스트 위치와 명령을 상세히 적는다.

Backend:

```text
unit
integration
repository
provider contract
API
```

Frontend:

```text
unit
component
hook
integration
E2E if used
```

---

# 35. Provider Contract Test Guide

새 Provider 구현자가 동일한 Contract Test를 통과하도록 한다.

문서에서:

```text
Contract Test 위치
새 Adapter를 Test suite에 등록하는 방법
Fake credential 처리
Integration Test opt-in 방법
```

을 설명한다.

---

# 36. Public Package Test Guide

공개 Package가 있다면:

```text
build
type generation
import smoke test
consumer example
package exports
```

검증 방법을 기록한다.

---

# 37. Frontend 신규 Feature 절차

```text
1. 기존 Feature/Component 검색
2. 소유 Module 결정
3. API 필요 여부 확인
4. Types 정의 또는 기존 Type 재사용
5. UI Component 작성
6. React-specific behavior는 Hook
7. Pure 계산은 일반 함수
8. Tailwind 적용
9. Loading/Error/Empty state
10. Accessibility 확인
11. Test 작성
12. Public export 필요 여부 확인
```

최종 문서에는 실제 경로를 사용한다.

---

# 38. Backend 신규 Feature 절차

```text
1. 기존 유사 기능 검색
2. 소유 Module 결정
3. Domain Rule 확인
4. Input/Output type 정의
5. Pure logic 우선 작성
6. Application workflow 작성
7. Repository/Provider 필요 여부 결정
8. API endpoint 연결
9. Error mapping
10. Test 작성
11. Public API 영향 확인
```

---

# 39. 신규 공통 UI 추가 규칙

Shared UI 또는 UI package로 올리기 전:

```text
두 개 이상의 독립 Feature에서 실제 사용?
Domain-neutral?
업무 개념 없음?
API가 충분히 안정적?
Theme/token 적용 가능?
Accessibility 만족?
```

아니면 Feature 내부에 유지한다.

---

# 40. 신규 Shared Utility 규칙

Shared 후보:

```text
Domain-neutral
Pure
Stable
Independent reuse
```

Domain 소유 유지 예:

```text
calculateRefund
canCancelSubscription
determineInvoiceStatus
```

---

# 41. Plugin / Extension 규칙

Plugin 구조가 실제 존재하는 경우에만 작성한다.

문서화:

```text
Plugin contract
Registration
Plugin context
Lifecycle
Allowed APIs
Forbidden internal APIs
Error isolation
Version compatibility
```

Plugin이 내부 DB/Private Service를 직접 import하지 않게 한다.

---

# 42. Theme / Customization Guide

오픈소스 사용자가 바꿀 수 있는 것을 실제 코드 기준으로 나열한다.

예:

```text
Brand name
Logo
Colors
Radius
Fonts
Header
Sidebar
Provider
Feature flags
```

각각 실제 변경 위치/API를 적는다.

---

# 43. Core 수정 없이 가능한 Customization 표

예:

| Customization | Supported Method | Actual Path/API |
|---|---|---|
| Theme | token/config | 실제 위치 |
| Header | component override | 실제 API |
| Storage | provider | 실제 contract |
| Email | provider | 실제 contract |

Open-source contributor에게 중요한 표이므로 실제 프로젝트 기준으로 채운다.

---

# 44. Architecture Guardrails

팀 전체 금지 사항을 명시한다.

```text
다른 Module internal deep import 금지
Vendor SDK를 Domain에 import 금지
Static inline CSS 남용 금지
Global CSS dumping 금지
shared/common/helper dumping 금지
Public API 무단 변경 금지
DB schema 무단 변경 금지
Framework 무단 교체 금지
Package 남발 금지
```

---

# 45. Dependency 추가 규칙

Python / Frontend dependency 추가 시 확인:

```text
기존 dependency 중복 여부
maintenance
security
license
bundle/runtime impact
open-source install burden
```

실제 dependency manager 명령을 기록한다.

---

# 46. 신규 Package 제안 절차

```text
1. Consumer 목록
2. 책임
3. Public API
4. Dependency graph
5. Internal/Public 여부
6. Test plan
7. Build plan
8. Versioning/compatibility plan
```

부터 작성한다.

---

# 47. Package Deep Import 금지

Python:

```python
from project_sdk import Provider
```

TypeScript:

```ts
import { Button } from "@project/ui";
```

공식 entry point를 사용한다.

---

# 48. Naming Convention

실제 프로젝트의 Naming Convention을 기록한다.

Python:

```text
module
class
function
constant
private member
test file
```

TypeScript:

```text
component
hook
type/interface
utility
test file
```

기존 좋은 사례를 실제 파일명으로 보여준다.

---

# 49. AI Agent 작업 시작 체크리스트

다른 팀원의 AI가 코딩을 시작할 때 항상 확인:

```text
[ ] AI_TEAM_CODING_GUIDE.md 읽음
[ ] 작업 대상 Module 확인
[ ] 실제 관련 코드 검색
[ ] 기존 유사 구현 확인
[ ] Public/Internal Boundary 확인
[ ] Provider/Repository 규칙 확인
[ ] Test convention 확인
[ ] Styling convention 확인
[ ] Library/package 영향 확인
```

---

# 50. AI Agent가 코드 작성 전 해야 할 검색

```text
새 함수 전에 유사 함수 검색
새 Component 전에 유사 UI 검색
새 Type 전에 기존 Type 검색
새 Provider 전에 기존 Contract 검색
새 Utility 전에 shared/library 검색
새 Config 전에 기존 Config 검색
```

중복 구현을 먼저 방지한다.

---

# 51. AI Agent가 하지 말아야 할 것

```text
Generic architecture를 프로젝트에 덮어쓰기
기존 convention 무시
동일 기능 중복 구현
Module internal deep import
Public API 임의 변경
DB schema 임의 변경
환경변수 이름 임의 변경
Provider Contract 임의 변경
새 Framework 임의 도입
새 Library 남발
거대한 shared/common 생성
```

---

# 52. Multi-Agent Collaboration

여러 AI Agent를 동시에 사용하는 경우 각 Agent에 다음을 지정한다.

```text
Owned Boundary
Allowed Files
Forbidden Files
Public Contract
Validation
```

같은 공용 파일을 동시에 대규모 수정하지 않는다.
Contract 변경은 먼저 합의한다.

---

# 53. AI 작업 카드 예시

최종 프로젝트 지침서에는 실제 프로젝트 경로를 사용한 예시를 넣는다.

```text
Title:
Add new storage provider

Owned Boundary:
<actual provider directory>

Allowed Files:
- ...

Forbidden Files:
- core business modules

Contract:
- <actual StorageProvider>

Tests:
- <actual command>

Definition of Done:
- adapter added
- config added
- contract test passed
- docs updated
```

---

# 54. Validation Command Reference

문서 안에 실제 명령을 복사 가능한 형태로 제공한다.

```bash
# Backend format
<actual command>

# Backend lint
<actual command>

# Backend typecheck
<actual command>

# Backend tests
<actual command>

# Frontend lint
<actual command>

# Frontend typecheck
<actual command>

# Frontend tests
<actual command>

# Frontend build
<actual command>
```

추측 금지.

---

# 55. Definition of Done for Team AI Work

일반 작업 완료 조건:

```text
기존 convention 준수
소유 Module에 코드 위치
Public API 영향 검토
중복 구현 없음
Vendor leakage 없음
Type/lint/test/build 관련 검사 완료
Docs 필요 시 업데이트
Compatibility risk 보고
```

---

# 56. README와 AI Guide 역할 구분

README:

```text
사람이 프로젝트를 설치하고 이해하는 문서
```

AI_TEAM_CODING_GUIDE:

```text
개발자와 AI가 코드를 어떻게 추가/수정해야 하는지에 대한 상세 규칙
```

둘은 일부 중복될 수 있지만 역할이 다르다.

---

# 57. 리팩토링 AI가 마지막에 반드시 해야 할 일

```text
1. 최종 Repository 다시 분석
2. AI_TEAM_CODING_GUIDE.md 생성
3. 실제 경로/명령 검증
4. Public API/Provider 목록 검증
5. 다른 AI가 이해할 수 있는 실제 예시 포함
6. 새 Feature/Provider/Library 추가 절차 포함
7. 금지 규칙 포함
8. 팀 Validation 명령 포함
9. Open-source Customization 방법 포함
10. 생성한 문서 경로를 최종 보고
```

---

# 58. 리팩토링 AI에게 주는 최종 강제 프롬프트

```text
After the refactoring is complete, you MUST create a detailed,
project-specific AI_TEAM_CODING_GUIDE.md for all future developers
and AI coding agents.

This is a required deliverable of the refactoring.
The refactoring is not considered complete without this guide.

Do not generate a generic architecture guide.

Re-scan the final repository after all refactoring changes are complete.

Use the real:
- directory names,
- Python package names,
- frontend paths,
- module names,
- library/package names,
- public APIs,
- provider contracts,
- vendor adapters,
- config locations,
- environment variables,
- test locations,
- build/lint/typecheck commands,
- package manager commands,
- styling conventions.

The guide must be detailed enough that another developer can start
a completely new AI coding session, attach this single document,
and make changes that remain consistent with this repository.

The guide MUST explain:

1. Project technology stack
2. Final architecture
3. Final directory structure
4. Responsibility of every major module
5. Dependency direction
6. Public API vs internal API
7. Python backend coding conventions
8. React/TypeScript/Tailwind conventions
9. Whether Next.js is used, and its actual role if it is used
10. Shared-code promotion rules
11. Internal and published library/package boundaries
12. How imports must be written
13. Provider/Adapter architecture
14. Existing provider list
15. Step-by-step instructions for adding a new SaaS provider
16. Step-by-step instructions for adding a new cloud provider
17. Step-by-step instructions for adding an AI provider
18. Step-by-step instructions for adding auth/payment/storage providers where those capabilities exist
19. Response/error normalization rules
20. Configuration and environment-variable rules
21. Database/repository rules
22. Error handling
23. Logging
24. Testing strategy
25. Exact validation commands
26. How to add a backend feature
27. How to add a frontend feature
28. How to add a reusable UI component
29. How to add shared utility code
30. How and when to create a new library/package
31. How to publish or expose a public package if applicable
32. Open-source customization methods
33. Theme/component/provider/plugin extension points
34. Security boundaries
35. Accessibility conventions
36. Naming conventions
37. Forbidden patterns
38. Multi-agent collaboration rules
39. Definition of Done
40. Real examples using this repository's actual paths.

For new providers, include a concrete project-specific procedure:

- locate the existing capability contract,
- implement the new adapter in the actual provider directory,
- keep the vendor SDK inside that adapter,
- normalize vendor request/response types,
- normalize vendor errors,
- add validated configuration,
- register the implementation in the actual composition/factory location,
- preserve business/domain code,
- add contract/integration tests,
- update example environment configuration,
- update user/developer documentation.

If the new vendor requires behavior that the existing contract cannot express,
do not immediately add vendor-specific methods to the common contract.

First determine whether:
- the capability is truly common,
- it should be a separate optional capability contract,
- or it should remain vendor-specific inside the adapter.

The guide must explicitly prohibit:
- vendor SDK imports in core business logic,
- cross-module deep imports,
- dumping code into shared/common/helpers,
- unnecessary package creation,
- silent public API changes,
- silent database-schema changes,
- silent framework migrations,
- static inline-style proliferation,
- giant global CSS files.

For libraries/packages, describe every actual package with:
- purpose,
- public/internal status,
- public exports,
- allowed consumers,
- dependency direction,
- test/build command,
- versioning/compatibility expectations.

For Python, document the actual:
- Python version,
- dependency manager,
- formatter,
- linter,
- type checker,
- test framework,
- package/import convention.

For the frontend, document the actual:
- React setup,
- TypeScript setup,
- Tailwind setup,
- Vite/Next.js/other framework,
- component locations,
- hook locations,
- API-client locations,
- state-management convention,
- styling convention.

Do not mention Next.js as part of the project if it is not actually used.

Use real file paths and real commands.
Do not use generic placeholder paths where the repository provides
specific information.

At the end, include a compact "AI Agent Quick Start" section containing:
- what document to read,
- what files to inspect before coding,
- what imports are allowed,
- where new backend code goes,
- where new frontend code goes,
- how providers are added,
- how shared/library code is promoted,
- which validation commands must run.

Also include a "Common Recipes" section with project-specific examples for:
- adding a backend feature,
- adding a React component,
- adding a provider,
- adding an environment variable,
- adding a database field/migration if applicable,
- adding a reusable library/package,
- exposing a new public API.

This guide becomes the standing coding instruction for the repository
after refactoring.
```

---

# 59. 리팩토링 최종 보고에도 포함

리팩토링 AI의 최종 보고에는 다음을 반드시 적는다.

```text
## Team AI Guide

Created:
<실제 AI_TEAM_CODING_GUIDE.md 경로>

Includes:
- final architecture
- actual directory map
- Python conventions
- React/TypeScript/Tailwind conventions
- provider extension guide
- library/package guide
- testing commands
- open-source customization guide
- multi-agent collaboration rules

Status:
- paths verified
- commands verified where executable
- public APIs reviewed
- provider list reviewed
```

---

# 60. 리팩토링 완료 조건에 포함

다음 조건을 만족하지 않으면 리팩토링을 완료로 보고하지 않는다.

```text
[ ] 코드 리팩토링 완료
[ ] 주요 테스트/빌드 검증
[ ] 실제 최종 구조 재분석
[ ] AI_TEAM_CODING_GUIDE.md 생성
[ ] 실제 Directory/Package 이름 반영
[ ] 실제 Provider 목록 반영
[ ] 신규 Provider 추가 절차 작성
[ ] Library/Package 규칙 작성
[ ] Python 개발 규칙 작성
[ ] Frontend 개발 규칙 작성
[ ] Open-source customization 설명
[ ] 정확한 Validation 명령 작성
[ ] AI Agent Quick Start 작성
[ ] Common Recipes 작성
```

---

# 61. 최종 원칙

> **리팩토링의 끝은 코드가 깨끗해진 시점이 아니라, 다음 개발자와 다음 AI Agent가 같은 구조적 원칙을 이해하고 유지하면서 안전하게 기능을 추가할 수 있는 시점이다.**
>
> 따라서 리팩토링 완료 직후 생성되는 `AI_TEAM_CODING_GUIDE.md`는 선택 문서가 아니라 리팩토링의 필수 산출물이다.
