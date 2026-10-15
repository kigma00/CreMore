# AI_ALWAYS_ON_PROJECT_CODING_GUIDE.md
## 상시 참조 개발 지침 · Project-Aware Architecture · Python Backend · TypeScript/React/Tailwind Frontend · Optional Next.js

> **중요**
>
> 이 문서는 리팩토링할 때만 사용하는 문서가 아니다.
>
> AI는 이 저장소에서 **코드를 작성, 수정, 리팩토링, 기능 추가, 버그 수정, 테스트 추가, 라이브러리 분리, UI 작성, API 작성** 등 어떤 개발 작업을 수행하든 **항상 이 문서를 먼저 참고해야 한다.**
>
> 이 문서의 가장 중요한 원칙은 다음 두 가지다.
>
> 1. **일반적인 예시 구조를 프로젝트에 억지로 적용하지 않는다.**
> 2. **반드시 현재 저장소의 실제 구조와 소스코드를 충분히 분석한 뒤, 이 프로젝트에 맞는 이름과 디렉토리 구조로 설계한다.**
>
> 기본 기술 방향:
>
> - **Backend / Core Language:** Python
> - **Frontend Language:** TypeScript
> - **Frontend UI:** React
> - **Styling:** Tailwind CSS
> - **Next.js:** 프로젝트 요구와 기존 구조에 따라 선택적으로 사용
> - **Architecture:** Modular Monolith 우선
> - **Open Source:** Core 수정 없이 확장 가능한 구조
> - **External Vendors:** Provider / Adapter로 격리
> - **Reusable Code:** 필요한 경우 내부 라이브러리 / 패키지로 분리
>
> 이 문서는 예시 폴더명을 "정답"으로 정의하지 않는다.
>
> 실제 저장소의 구조가 항상 우선한다.

---

# 1. ALWAYS-ON RULE

AI는 모든 개발 요청에서 이 문서를 상시 규칙으로 적용한다.

다음 작업 모두 포함:

```text
신규 기능 개발
버그 수정
리팩토링
UI 추가
API 추가
DB 연동
SaaS 연동
Cloud 연동
AI Provider 연동
테스트 작성
성능 개선
패키지 분리
공통 코드 추출
오픈소스 확장 기능 추가
문서화
```

AI는 작업 시작 전 반드시 다음을 확인한다.

```text
현재 작업이 어느 모듈의 책임인지
기존 코드가 같은 문제를 어떻게 해결하고 있는지
기존 Naming Convention
기존 Directory Convention
기존 Import Convention
기존 Public API
기존 Test Convention
기존 Error Handling Convention
기존 Configuration Convention
기존 Styling Convention
기존 Provider/Adapter Convention
```

새로운 방식이 기존 방식보다 명백하게 낫고 프로젝트 전체에 적용할 가치가 없다면,
단일 작업에서 새로운 패턴을 임의로 도입하지 않는다.

---

# 2. SOURCE-CODE-FIRST PRINCIPLE

AI는 아키텍처 문서의 예시 구조보다 **실제 소스코드**를 우선한다.

잘못된 접근:

```text
이 문서에 features/가 있으니
현재 프로젝트에 features/를 새로 만든다.
```

올바른 접근:

```text
현재 프로젝트 구조 분석
↓
기존 책임과 import 관계 파악
↓
현재 프로젝트의 naming/structure 확인
↓
필요한 경계만 개선
↓
현재 프로젝트 스타일에 맞춰 재설계
```

이 문서의 폴더명은 개념 설명용이다.

다음 이름들은 절대 강제 규칙이 아니다.

```text
src/
features/
shared/
core/
domain/
application/
infrastructure/
integrations/
packages/
```

현재 프로젝트가 다음처럼 되어 있다면:

```text
backend/
frontend/
modules/
services/
common/
libs/
```

AI는 그 이름을 먼저 이해하고,
필요한 경우 그 구조 안에서 개선한다.

---

# 3. EXISTING PROJECT STRUCTURE MUST BE ANALYZED FIRST

리팩토링 또는 구조 변경 전에 AI는 저장소를 전체적으로 조사한다.

가능한 범위에서 다음을 빠짐없이 확인한다.

```text
최상위 디렉토리
모든 주요 소스 디렉토리
애플리케이션 Entry Point
Python package 구조
Frontend entry point
라우팅 구조
API 구조
Domain / Business Logic
Service
Repository
DB 접근
ORM
External Provider
SaaS/Cloud SDK
React Components
Hooks
State Management
Tailwind / CSS
Config
Environment Variables
Tests
Fixtures
Scripts
Build Config
Package Manager
Python dependency manager
Frontend dependency manager
CI/CD
Docker
Docs
Public API
Library/Package exports
Plugin/Extension API
```

AI는 일부 파일만 보고 전체 구조를 추측하지 않는다.

---

# 4. PROJECT INVENTORY FIRST

구조 변경 전 먼저 Project Inventory를 만든다.

예:

```text
Project Root
├─ backend/
│  ├─ app/
│  ├─ api/
│  ├─ models/
│  ├─ services/
│  └─ ...
│
├─ frontend/
│  ├─ components/
│  ├─ pages/
│  └─ ...
│
├─ tests/
├─ scripts/
└─ ...
```

그 다음 각 영역의 책임을 기록한다.

예:

```text
backend/app
→ application bootstrap

backend/api
→ HTTP endpoint

backend/services
→ current application logic

frontend/components
→ current reusable React components
```

그 후에야 리팩토링 구조를 제안한다.

---

# 5. DO NOT INVENT DIRECTORY NAMES BEFORE ANALYSIS

AI는 프로젝트를 분석하기 전에 다음과 같은 결론을 내리지 않는다.

```text
무조건 src/features로 바꾸자
무조건 domain 폴더를 만들자
무조건 packages/core를 만들자
무조건 services 폴더를 없애자
무조건 components/ui를 만들자
```

먼저 현재 구조를 이해해야 한다.

새 디렉토리가 필요한 경우 반드시 다음 질문을 한다.

```text
현재 디렉토리로 책임 분리가 가능한가?
새 디렉토리가 실제 Boundary를 명확하게 하는가?
팀원이 새 구조를 이해하기 쉬운가?
기존 import를 대량으로 깨뜨릴 가치가 있는가?
오픈소스 사용자가 더 쉽게 이해할 수 있는가?
```

---

# 6. PROJECT-SPECIFIC REDESIGN

리팩토링 계획은 반드시 **현재 프로젝트의 실제 디렉토리명**을 사용한다.

나쁜 계획:

```text
features/orders/service.ts를 만든다.
```

현재 프로젝트가 Python backend이고 다음 구조라면:

```text
server/order/
```

계획도 실제 이름을 사용한다.

예:

```text
server/order/application.py
server/order/repository.py
server/order/providers/
```

또는 기존 Naming Convention이:

```text
server/order_service.py
```

라면 그 스타일을 먼저 고려한다.

AI는 Generic Template를 그대로 복사하지 않는다.

---

# 7. ARCHITECTURE MAP BEFORE REFACTORING

AI는 대규모 수정 전에 현재 구조를 요약한다.

예:

```text
frontend/pages/UserPage.tsx
├─ API request
├─ form state
├─ business validation
├─ modal
└─ styling

backend/services/order_service.py
├─ pricing rule
├─ SQL query
├─ Stripe call
├─ S3 upload
└─ email send
```

이를 기반으로 실제 개선 지점을 정한다.

---

# 8. MODULAR MONOLITH IS THE DEFAULT

이 프로젝트의 기본 구조 방향은 **Modular Monolith**이다.

목표:

```text
한 제품
한 저장소 또는 한 Workspace
명확한 Module Boundary
명확한 Public API
명확한 Dependency Direction
필요한 Library/Package 분리
```

Microservice를 목표로 하지 않는다.

네트워크 서비스 분리는 기본 리팩토링 목표가 아니다.

---

# 9. MODULE OWNERSHIP

각 기능 영역은 명확한 책임을 가져야 한다.

개념 예:

```text
users
orders
billing
auth
files
notifications
```

실제 프로젝트에서는 기존 명칭을 우선 사용한다.

각 모듈은 가능한 한 자신의:

```text
Business Logic
Application Logic
Data Access
Types
Tests
UI if applicable
```

을 소유한다.

---

# 10. FEATURE / MODULE PUBLIC API

다른 모듈이 내부 구현을 직접 참조하지 않도록 한다.

Python 예:

```python
# order/__init__.py or order/public.py

from .application import create_order
from .models import Order

__all__ = [
    "create_order",
    "Order",
]
```

다른 모듈:

```python
from order import create_order
```

내부 파일을 직접 가져오는 것을 최소화한다.

```python
# Avoid when it crosses a module boundary
from order.internal.private_mapper import normalize_order
```

TypeScript 예:

```ts
import {
  createOrder,
  type Order,
} from "@/order/public";
```

---

# 11. PYTHON IS THE DEFAULT BACKEND LANGUAGE

Backend 및 Core 로직은 Python을 기본 언어로 한다.

AI는 특별한 이유 없이 Python backend 기능을:

```text
Node.js
Go
Rust
Java
```

등으로 재작성하지 않는다.

Python 버전과 dependency manager는 반드시 현재 저장소를 확인한다.

예:

```text
pyproject.toml
poetry.lock
uv.lock
requirements.txt
Pipfile
```

현재 프로젝트의 도구를 우선한다.

---

# 12. PYTHON PACKAGE STRUCTURE

Python의 실제 package 구조를 먼저 분석한다.

일반적인 예시는 가능하지만 강제하지 않는다.

개념 예:

```text
backend/
└─ app/
   ├─ users/
   ├─ orders/
   ├─ billing/
   ├─ integrations/
   └─ shared/
```

또는 Workspace/Library가 필요하다면:

```text
packages/
├─ project_core/
├─ project_provider_sdk/
└─ project_testing/
```

실제 naming은 프로젝트에 맞춘다.

---

# 13. PYTHON FUNCTION DESIGN

함수는 하나의 명확한 책임을 가진다.

예:

```python
def calculate_order_total(
    items: list[OrderItem],
) -> Money:
    ...
```

다음과 같은 함수는 분리를 검토한다.

```python
def process_everything(data):
    ...
```

상위 함수는 Workflow처럼 읽히게 한다.

```python
def create_order(command: CreateOrderCommand) -> Order:
    validate_order(command)

    products = load_products(command.items)
    total = calculate_order_total(products)

    authorize_payment(total)

    order = save_order(command, products, total)
    send_order_notification(order)

    return order
```

---

# 14. PYTHON TYPE HINTS

신규/수정 Python 코드에는 가능한 한 명확한 type hint를 사용한다.

```python
def get_user(user_id: UserId) -> User | None:
    ...
```

다음을 최소화한다.

```python
Any
dict[str, Any]
untyped **kwargs
magic tuple
```

단, 외부 라이브러리 제약 때문에 불가피하면 이유를 남긴다.

---

# 15. PYTHON DATA MODELS

프로젝트에서 사용하는 표준을 먼저 확인한다.

가능한 예:

```text
dataclass
Pydantic
TypedDict
NamedTuple
ORM model
```

새로운 모델 라이브러리를 임의로 혼합하지 않는다.

Domain Model과 API Schema가 다른 책임이라면 필요한 경우 분리한다.

---

# 16. PYTHON IMPORTS

Import 방향을 명확하게 유지한다.

좋은 예:

```python
from project.orders import create_order
```

Boundary를 넘는 deep import는 피한다.

```python
from project.orders.internal.mapping.private import _map_order
```

순환 import가 발생하면 단순히 local import로 숨기기 전에
Module Boundary 자체를 다시 검토한다.

---

# 17. PYTHON PURE FUNCTIONS

계산 로직은 가능한 한 Pure Function으로 유지한다.

```python
def calculate_discount(
    amount: Decimal,
    membership: Membership,
) -> Decimal:
    if membership is Membership.VIP:
        return amount * Decimal("0.8")

    return amount
```

DB, HTTP, 환경변수, 현재 시간 등의 의존성을 계산 로직 안에 숨기지 않는다.

---

# 18. PYTHON DEPENDENCY INJECTION

의미 있는 외부 의존성은 명시적으로 전달한다.

예:

```python
class OrderApplication:
    def __init__(
        self,
        orders: OrderRepository,
        payments: PaymentProvider,
    ) -> None:
        self._orders = orders
        self._payments = payments
```

모든 작은 함수에 객체 DI를 강제하지 않는다.

---

# 19. PYTHON PROTOCOL / ABC

교체 가능한 구현에 계약이 필요하면 현재 프로젝트 스타일에 따라:

```text
typing.Protocol
abc.ABC
plain callable contract
```

중 가장 단순한 방식을 선택한다.

예:

```python
from typing import Protocol

class StorageProvider(Protocol):
    def upload(
        self,
        file: UploadFile,
    ) -> StoredFile:
        ...
```

Interface를 위한 Interface를 만들지 않는다.

---

# 20. PYTHON ERROR HANDLING

다음을 피한다.

```python
try:
    ...
except Exception:
    pass
```

또한:

```python
except Exception as exc:
    print(exc)
```

로 끝내지 않는다.

Error ownership을 명확히 한다.

개념:

```text
Vendor Error
↓
Infrastructure/Application Error
↓
API/UI Error
```

---

# 21. PYTHON CONFIGURATION

환경변수를 코드 곳곳에서 직접 읽지 않는다.

현재 프로젝트 방식에 따라 중앙 Config를 사용한다.

예:

```python
settings.database_url
settings.storage_provider
```

새 설정은 startup 단계에서 validation하는 것을 우선한다.

---

# 22. PYTHON TESTING

현재 프로젝트의 테스트 프레임워크를 먼저 확인한다.

일반적으로 Python 프로젝트에서는 pytest를 사용할 수 있지만,
이미 다른 표준이 있으면 현재 방식을 따른다.

테스트 대상:

```text
Pure Domain Logic
Application Use Case
Repository Integration
Provider Contract
Public API
Regression
```

---

# 23. FRONTEND DEFAULT STACK

Frontend 기본 방향:

```text
TypeScript
React
Tailwind CSS
```

AI는 특별한 이유 없이 JavaScript 신규 코드를 추가하지 않는다.

기존 파일이 JavaScript여도 리팩토링 범위와 위험을 고려해 점진적으로 TypeScript로 옮긴다.

---

# 24. NEXT.JS IS OPTIONAL, NOT MANDATORY

Next.js는 React 자체의 필수 구성 요소가 아니다.

**기존 프로젝트가 Next.js를 사용하면 그 구조를 존중하고 Next.js 규칙을 따른다.**

기존 프로젝트가 Next.js가 아니라면,
리팩토링을 이유로 Next.js를 자동 도입하지 않는다.

---

# 25. WHEN NEXT.JS MAKES SENSE

다음 요구가 명확하면 Next.js를 고려할 수 있다.

```text
SEO가 중요함
Server-side Rendering 필요
Static Generation 필요
Route 기반 Server Rendering 필요
React Server Components를 활용할 실질적 이유가 있음
Frontend Route/File Convention의 가치가 큼
공개 웹사이트 / Landing / Content Page 비중이 큼
Frontend 단의 server rendering/bff 기능이 필요함
```

---

# 26. WHEN REACT + VITE MAY BE SIMPLER

다음 성격이면 Next.js가 반드시 필요하지 않다.

```text
Admin Dashboard
Internal Tool
SPA
Authenticated Application
SEO 중요도가 낮음
Python API Backend가 명확함
Frontend가 Client Application 역할 중심
```

이 경우:

```text
React
TypeScript
Tailwind
Vite 또는 현재 Build Tool
Python Backend
```

구조가 더 단순할 수 있다.

---

# 27. PYTHON BACKEND + NEXT.JS

Python backend를 사용한다고 Next.js를 사용할 수 없는 것은 아니다.

가능한 구조:

```text
Browser
↓
Next.js Frontend
↓
Python API Backend
↓
Database / Providers
```

이 경우 Next.js는:

```text
React rendering
Routing
SSR/SSG
Frontend composition
```

을 담당하고,

Python은:

```text
Business Logic
API
Database
Auth backend
Provider integration
```

을 담당할 수 있다.

단, Business Logic을 Python과 Next.js server code에 중복 작성하지 않는다.

---

# 28. NEXT.JS DECISION RULE

AI는 다음 순서로 판단한다.

```text
1. 현재 프로젝트가 Next.js인가?
   → Yes: 유지

2. 현재 프로젝트가 React/Vite인가?
   → 특별한 요구 없으면 유지

3. SEO/SSR/SSG가 실제 요구인가?
   → Yes: Next.js 검토

4. Python backend가 이미 모든 server responsibility를 담당하는가?
   → Yes: 단순 SPA도 충분한지 검토

5. Next.js 도입으로 얻는 가치가 migration/build complexity보다 큰가?
```

Next.js는 "React 프로젝트니까"라는 이유만으로 추가하지 않는다.

---

# 29. REACT COMPONENT RULES

Page-level component는 Composition 중심으로 유지한다.

```tsx
export function UserPage() {
  return (
    <PageLayout>
      <UserHeader />
      <UserFilters />
      <UserTable />
      <UserPagination />
      <UserEditModal />
    </PageLayout>
  );
}
```

하나의 Page에 다음을 모두 넣지 않는다.

```text
API logic
Business validation
Form logic
Modal implementation
Table implementation
Filtering
Sorting
Pagination
Vendor SDK
Styling
```

---

# 30. REACT COMPONENT EXTRACTION

다음 경우 분리한다.

```text
반복 UI
독립 책임
자체 State
자체 Event
재사용
별도 Test 가치
긴 JSX가 전체 흐름을 가림
```

작은 JSX 조각 모두를 Component로 만들지는 않는다.

---

# 31. REACT HOOK RULE

React-specific state/lifecycle 재사용은 Hook으로 만든다.

예:

```text
useUsers
useOrderFilters
useUploadFile
```

Pure 계산은 Hook이 아니다.

```text
calculateTotal
validateOrder
formatAddress
```

---

# 32. FRONTEND STATE OWNERSHIP

다음을 구분한다.

```text
Local UI State
Server State
Form State
URL State
Global Client State
```

모든 State를 하나의 Global Store에 넣지 않는다.

---

# 33. FRONTEND API ACCESS

React Component에서 raw API 호출을 반복하지 않는다.

프로젝트 구조에 맞는 API layer를 둔다.

예:

```text
frontend/users/api.ts
```

또는 실제 프로젝트 convention에 맞는 위치.

---

# 34. TAILWIND DEFAULT

정적 Styling은 Tailwind를 기본으로 한다.

```tsx
<button className="rounded-lg px-4 py-2 font-medium">
  Save
</button>
```

---

# 35. INLINE STYLE RULE

진짜 runtime 계산값에만 사용한다.

```tsx
<div
  style={{
    transform: `translate(${x}px, ${y}px)`,
  }}
/>
```

정적:

```text
padding
margin
color
background
border
radius
font
```

등은 Tailwind 또는 필요한 CSS class를 사용한다.

---

# 36. GLOBAL CSS

Global CSS에는 전역 Concern만 둔다.

```text
Reset
Font
Root Token
Body Default
Global Accessibility
Theme Variable
```

Feature CSS를 하나의 파일에 몰아넣지 않는다.

---

# 37. DESIGN SYSTEM

재사용 UI는 현재 규모에 따라:

```text
shared/ui
```

또는:

```text
packages/ui
```

등으로 관리할 수 있다.

실제 프로젝트 이름을 분석하고 적용한다.

예:

```text
Button
Input
Dialog
Card
Tooltip
Tabs
Badge
```

도메인 특화 UI는 Feature에 유지한다.

---

# 38. COMMON CODE VS LIBRARY

공통으로 사용된다는 사실만으로 Library로 만들지 않는다.

단계:

```text
Feature-local code
↓
Shared module
↓
Internal library/package
↓
Published open-source library
```

각 단계는 실제 필요가 있을 때만 승격한다.

---

# 39. WHEN TO CREATE AN INTERNAL LIBRARY

다음이 맞으면 내부 Library/Package를 고려한다.

```text
여러 독립 Module이 사용
책임이 명확함
API가 어느 정도 안정적
독립 Test 가능
의존성 Boundary가 개선됨
독립 Ownership이 유리함
여러 App Entry Point에서 재사용
```

---

# 40. WHEN TO PUBLISH A LIBRARY

Open-source 사용자가 직접 사용할 가치가 있을 때만 Public Package를 고려한다.

예:

```text
UI library
Provider SDK
Plugin SDK
Public contracts
Reusable client SDK
```

Business feature 전체를 이유 없이 Public Package로 만들지 않는다.

---

# 41. RECOMMENDED LIBRARY CATEGORIES

프로젝트 규모에 따라 다음을 고려할 수 있다.

```text
core
ui
contracts
provider-sdk
plugin-sdk
testing
config
```

실제 package명은 프로젝트 이름과 기존 convention을 사용한다.

---

# 42. CORE PACKAGE

`core`는 쓰레기통이 아니다.

가능한 내용:

```text
Stable Primitive
Core Contract
Small Domain-neutral Runtime
Extension Contract
```

다음은 무조건 core로 보내지 않는다.

```text
모든 Business Logic
모든 Type
모든 Utility
모든 Config
```

---

# 43. UI PACKAGE

외부에서도 재사용 가치가 있는 Design System이라면:

```text
ui package
```

를 고려한다.

Public API는 명시적으로 관리한다.

```ts
import {
  Button,
  Dialog,
} from "@project/ui";
```

Private path import를 문서화하지 않는다.

---

# 44. PROVIDER SDK

오픈소스 사용자가 자신만의 Provider를 구현할 필요가 있다면:

```text
provider-sdk
```

를 고려한다.

예:

```python
class StorageProvider(Protocol):
    ...
```

또는 TypeScript consumer가 구현해야 하는 계약이라면 TS SDK 형태도 가능하다.

Provider SDK에는 내부 Application 구현을 넣지 않는다.

---

# 45. PLUGIN SDK

실제 Plugin 생태계가 필요할 때만 만든다.

포함 가능:

```text
Plugin Contract
Plugin Context
Registry Contract
Extension Metadata
```

Private DB access 등을 노출하지 않는다.

---

# 46. PACKAGE PUBLIC API

Public Package는 deliberate export surface를 가진다.

TypeScript:

```ts
import { Button } from "@project/ui";
```

Python:

```python
from project_provider_sdk import StorageProvider
```

다음처럼 내부 경로를 요구하지 않는다.

```python
from project_provider_sdk.internal.base._storage import StorageProvider
```

---

# 47. PACKAGE EXTRACTION CHECKLIST

Library/Package 분리 전에 확인한다.

```text
실제 독립 Consumer가 있는가?
책임을 한 문장으로 설명할 수 있는가?
Public API가 안정적인가?
독립 Test가 가능한가?
Open-source 사용자가 직접 소비하는가?
Dependency Boundary가 실제 개선되는가?
Circular Dependency를 만들지 않는가?
Build/Release 복잡성보다 가치가 큰가?
```

---

# 48. AVOID PACKAGE SOUP

다음처럼 너무 작은 Package를 남발하지 않는다.

```text
packages/date-utils
packages/string-utils
packages/order-validation
packages/button-size
packages/misc-common
```

Package는 Folder보다 비용이 크다.

먼저 Module/Folder로 충분한지 판단한다.

---

# 49. OPEN-SOURCE EXTENSIBILITY

일반적인 커스터마이징을 위해 사용자가 Core를 Fork하지 않게 한다.

확장 방법 우선순위:

```text
Configuration
↓
Theme / Token
↓
Composition
↓
Slot
↓
Component Override
↓
Strategy Function
↓
Provider / Adapter
↓
Hook / Event
↓
Plugin / Registry
```

가능한 가장 단순한 확장 방법을 선택한다.

---

# 50. CONFIGURATION OVER FORKING

예:

```ts
createApp({
  branding: {
    appName: "Custom Product",
  },
});
```

Python:

```python
app = create_app(
    AppConfig(
        storage_provider="local",
    )
)
```

Config가 하나의 거대한 Object가 되지 않도록 책임별로 나눈다.

---

# 51. UI OVERRIDE

예:

```tsx
<App
  components={{
    Header: CustomHeader,
  }}
/>
```

또는 Composition:

```tsx
<AppShell
  header={<CustomHeader />}
/>
```

---

# 52. HEADLESS LOGIC

Open-source 사용자가 UI를 완전히 교체할 수 있어야 할 때만:

```text
useDataTable
DataTable UI
```

처럼 Logic과 View를 분리하는 것을 고려한다.

---

# 53. PROVIDER / ADAPTER

SaaS/Cloud/Vendor Integration은 필요한 경우 Provider 뒤로 격리한다.

Python 예:

```python
class EmailProvider(Protocol):
    def send(
        self,
        message: EmailMessage,
    ) -> EmailResult:
        ...
```

Implementations:

```text
SesEmailProvider
SendGridEmailProvider
ConsoleEmailProvider
```

Business Logic은 구체 Provider를 몰라야 한다.

---

# 54. COMPOSITION ROOT

구체 구현 선택은 App startup에 가깝게 둔다.

Python 예:

```python
email_provider = create_email_provider(settings)

application = Application(
    email_provider=email_provider,
)
```

Business Logic 안에서:

```python
if provider == "ses":
    ...
elif provider == "sendgrid":
    ...
```

같은 분기가 반복되지 않게 한다.

---

# 55. VENDOR RESPONSE NORMALIZATION

Vendor response를 전체 코드에 퍼뜨리지 않는다.

예:

```text
Stripe Response
AWS Response
OpenAI SDK Response
```

Adapter에서 프로젝트 내부 모델로 변환한다.

---

# 56. VENDOR ERROR NORMALIZATION

Vendor Error도 필요한 경우 내부 Error로 변환한다.

```text
VendorTimeout
AWSException
StripeError
```

↓

```text
StorageUnavailableError
PaymentFailedError
ProviderUnavailableError
```

---

# 57. ERROR HANDLING

Error 처리 정책을 일관되게 유지한다.

Python:

```python
try:
    ...
except Exception:
    pass
```

금지에 가깝게 취급한다.

Frontend에서도 모든 Error를 `console.log`만 하고 끝내지 않는다.

---

# 58. LOGGING

프로젝트 Logger convention을 따른다.

민감정보를 Log에 포함하지 않는다.

Python과 Frontend 각각 적절한 Logger를 사용하되,
공통 Correlation/Context가 필요하면 명확한 Contract를 둔다.

---

# 59. CONFIG / ENV

Python backend의 secret와 frontend public config를 구분한다.

Server Secret가 frontend bundle에 들어가지 않게 한다.

환경변수 이름 변경은 Public Compatibility 문제로 간주할 수 있으므로 함부로 바꾸지 않는다.

---

# 60. NAMING

이름은 Intent를 드러낸다.

피해야 할 이름:

```text
data
temp
obj
info
thing
misc
helper
manager
doStuff
processEverything
```

좋은 예:

```text
user_profile
payment_result
order_items
calculate_invoice_total
create_user_session
```

TypeScript:

```text
userProfile
paymentResult
orderItems
calculateInvoiceTotal
```

---

# 61. BOOLEAN NAMING

Python:

```text
is_active
has_permission
can_delete
should_retry
```

TypeScript:

```text
isActive
hasPermission
canDelete
shouldRetry
```

---

# 62. READABILITY FIRST

짧은 코드보다 읽히는 코드를 우선한다.

중간 변수와 의미 있는 함수명을 적극 활용한다.

과도한 one-liner, nested comprehension, clever generic abstraction을 피한다.

---

# 63. COMMENTS

Comment는 "무엇"보다 "왜"를 설명한다.

좋은 예:

```python
# Legacy provider may return inactive users,
# so authorization re-checks state here.
```

---

# 64. TEST STRATEGY

## Python Backend

```text
Unit
Integration
Repository
Provider Contract
API
Regression
```

## Frontend

```text
Pure Utility
Component
Hook
Integration
Critical User Flow
```

## Published Library

```text
Package Build
Public Import
Type Declaration
Documented Example
Contract
```

---

# 65. CHARACTERIZATION TEST

Spaghetti Code를 크게 건드리기 전에 현재 동작을 Test로 고정한다.

우선:

```text
Auth
Permission
Payment
Billing
Data Mutation
Critical Calculation
External Integration
```

---

# 66. OPEN-SOURCE PUBLIC API COMPATIBILITY

다음은 Public API로 간주할 수 있다.

```text
Python Package Import
TypeScript Package Export
HTTP API
Config Key
Environment Variable
Provider Contract
Plugin Contract
Published React Component Props
CLI Option
Persistent Data Format
```

변경 전에 Consumer impact를 분석한다.

---

# 67. SEMANTIC VERSIONING

Public Library를 배포한다면:

```text
Patch
→ Compatible Bug Fix

Minor
→ Backward-compatible Feature

Major
→ Breaking Change
```

를 기본적으로 고려한다.

현재 프로젝트의 release convention이 있으면 그것을 우선한다.

---

# 68. DEPRECATION

Public API를 즉시 삭제하지 않는다.

Python 예:

```python
# Deprecated: use create_storage_provider instead.
```

TypeScript:

```ts
/**
 * @deprecated Use createStorageProvider instead.
 */
```

Migration Path를 제공한다.

---

# 69. COLLABORATION

여러 사람이 분담할 수 있도록 Boundary를 명확히 한다.

예:

```text
Backend Auth
Backend Orders
Frontend Orders
Shared UI
Provider Integrations
Public SDK
```

실제 디렉토리 기준으로 Ownership을 정의한다.

---

# 70. CONTRACT-FIRST PARALLEL WORK

병렬 작업 전에 Contract를 먼저 정한다.

Python:

```python
class PaymentProvider(Protocol):
    ...
```

TypeScript:

```ts
export interface PaymentFormProps {
  ...
}
```

그 후 서로 다른 작업자가 독립 구현한다.

---

# 71. REDUCE CONFLICT HOTSPOTS

다음 파일이 모두가 수정하는 병목이 되면 분리를 검토한다.

```text
routes.py
services.py
types.ts
globals.css
config.ts
index.ts
```

책임별로 나누면 Git conflict도 줄어든다.

---

# 72. MULTI-AGENT WORK CARD

각 AI 작업에는 다음을 명시한다.

```text
Title:
Goal:
Owned Boundary:
Existing Directory Names:
Allowed Files:
Forbidden Files:
Dependencies:
Public API:
Behavior to Preserve:
Validation Commands:
Definition of Done:
Compatibility Risk:
```

AI는 담당 범위를 넘어서는 Opportunistic Refactor를 최소화한다.

---

# 73. DIRECTORY RENAMING

Directory Rename은 비용이 크다.

다음이 명확한 경우에만 한다.

```text
현재 이름이 책임을 심각하게 오해하게 함
중복/충돌을 만들고 있음
Open-source 사용자에게 혼란을 줌
Package Boundary를 명확히 할 필요
```

단순히 AI가 선호하는 Naming으로 바꾸지 않는다.

---

# 74. FILE RENAMING

File rename 역시:

```text
Import 영향
Git history
Docs
Tests
Public imports
External consumers
```

를 확인한다.

---

# 75. DO NOT COPY GENERIC ARCHITECTURE BLINDLY

다음은 참고용일 뿐이다.

```text
domain/
application/
infrastructure/
features/
shared/
packages/
```

현재 프로젝트가 더 적절한 이름을 이미 사용한다면 기존 이름을 유지한다.

Architecture는 Folder Name이 아니라 책임과 Dependency로 판단한다.

---

# 76. NEW DEPENDENCY RULE

새 Python/Frontend Library를 추가하기 전 확인한다.

```text
표준 기능으로 해결 가능?
기존 Dependency가 이미 해결?
Maintenance 상태?
Security?
License?
Bundle/Runtime Cost?
Open-source 사용자의 설치 부담?
```

인기 있다는 이유만으로 추가하지 않는다.

---

# 77. SECURITY

MUST:

```text
Secret 하드코딩 금지
Frontend에 Server Secret 노출 금지
Authorization server-side 검증
민감정보 Log 금지
Open-source 공개 전 Secret 검사
```

---

# 78. ACCESSIBILITY

React Shared UI는:

```text
Semantic HTML
Keyboard
Focus
Label
ARIA
Contrast
```

를 고려한다.

---

# 79. PERFORMANCE

Premature Optimization은 피한다.

하지만 확인:

```text
Python N+1
불필요한 DB query
React re-render
중복 API request
큰 bundle
거대한 import
Provider client 재생성
```

---

# 80. DOCUMENTATION

Open-source에서 Public API는 문서가 필요하다.

최소:

```text
Purpose
Install/Import
Usage
Input
Output
Error
Customization
Compatibility
```

---

# 81. README RECOMMENDATION

```text
Overview
Quick Start
Architecture
Project Structure
Backend
Frontend
Configuration
Customization
Providers
Libraries / Packages
Plugins if supported
Development
Testing
Contribution
Migration
Release / Compatibility
```

---

# 82. CONTRIBUTING

포함 권장:

```text
Python setup
Frontend setup
Package manager
Formatting
Lint
Typecheck
Tests
Module boundary
Public API
Shared promotion
Library extraction
Provider implementation
UI component contribution
PR policy
```

---

# 83. ARCHITECTURE DECISION RECORD

중요 결정은 ADR을 고려한다.

예:

```text
docs/adr/
├─ modular-monolith.md
├─ python-backend-boundaries.md
├─ frontend-architecture.md
├─ provider-adapters.md
├─ library-extraction.md
└─ nextjs-decision.md
```

---

# 84. MANDATORY PRE-CODING CHECKLIST

AI는 코드를 쓰기 전에 매번 관련 범위에서 확인한다.

```text
[ ] 이 문서를 읽었는가?
[ ] 현재 프로젝트 실제 디렉토리를 확인했는가?
[ ] 관련 기존 구현을 검색했는가?
[ ] 기존 Naming Convention을 확인했는가?
[ ] 기존 Import 방식을 확인했는가?
[ ] 기존 Test 방식을 확인했는가?
[ ] Public API 영향이 있는가?
[ ] Shared/Library로 보낼 이유가 실제로 있는가?
[ ] Vendor dependency가 침투하지 않는가?
[ ] Frontend라면 TypeScript/React/Tailwind 기준을 따르는가?
[ ] Next.js를 사용하는 프로젝트인지 확인했는가?
```

---

# 85. MANDATORY PRE-REFACTOR CHECKLIST

구조 변경 전:

```text
[ ] Repository Inventory 작성
[ ] 관련 디렉토리 전체 파악
[ ] 주요 파일과 Entry Point 파악
[ ] Import 관계 파악
[ ] Circular Dependency 확인
[ ] External Provider 파악
[ ] Public API 파악
[ ] Tests 파악
[ ] Build/Lint/Typecheck 명령 파악
[ ] 기존 Directory Naming 유지 가능성 검토
[ ] Project-specific 구조로 계획 작성
```

---

# 86. PROJECT-SPECIFIC REFACTOR PLAN FORMAT

AI의 계획은 Generic Folder가 아니라 실제 경로를 사용해야 한다.

```text
# Current Structure
- 실제 경로
- 현재 책임

# Problems
- 실제 파일/모듈의 문제

# Proposed Structure
- 실제 프로젝트 naming을 사용한 새 경로

# Import Changes
- 기존 import
- 변경 import

# Public API
- 유지
- 추가
- 변경 없음/변경 있음

# Validation
- 실제 실행할 명령
```

---

# 87. INCREMENTAL REFACTOR ORDER

권장:

```text
1. 실제 코드 전체 구조 파악
2. Public Contract 파악
3. Test 확보
4. Naming/Responsibility 개선
5. Pure Function 분리
6. Module Boundary 개선
7. Repository/Provider 격리
8. React Component/Hook 분리
9. Tailwind/CSS 정리
10. Shared 승격 검토
11. Library/Package 추출 검토
12. Public Export 정리
13. Contract Test
14. Build/Test/Lint/Typecheck
15. Dead Code 제거
16. Docs 업데이트
```

---

# 88. VALIDATION

사용 가능한 실제 명령만 사용한다.

Python:

```text
formatter
linter
type checker
unit tests
integration tests
```

Frontend:

```text
formatter
eslint
TypeScript typecheck
component tests
build
```

Package:

```text
package build
public import test
type declaration generation
documented example compile
```

실제 tool 이름은 저장소 설정을 확인한다.

예를 들어 `ruff`, `mypy`, `pyright`, `pytest`, `eslint`, `tsc` 등을
프로젝트 확인 없이 임의로 가정하지 않는다.

---

# 89. VALIDATION REPORTING

AI는 다음을 구분해서 보고한다.

```text
실행했고 통과
실행했고 실패
실행할 수 없었음
해당 없음
```

"문제 없어 보임"을 "Test 통과"라고 쓰지 않는다.

---

# 90. AI MUST NOT CHANGE SILENTLY

명시적 요구 없이 변경 금지:

```text
Business Rule
Auth Behavior
Permission Policy
DB Schema
Persistent Data
Public Python API
Published TypeScript API
Environment Variable Name
Provider Contract
Plugin Contract
User-visible Workflow
Framework Migration
React → Next.js Migration
Vite → Next.js Migration
```

---

# 91. NEXT.JS MIGRATION IS A SEPARATE DECISION

Next.js 도입은 일반 리팩토링에 포함시키지 않는다.

다음은 별도 Architecture Decision이다.

```text
Why Next.js?
SEO requirement?
SSR/SSG requirement?
Migration cost?
Routing impact?
Deployment impact?
Python API relationship?
Existing React architecture impact?
Open-source contributor complexity?
```

이 분석 없이 Next.js를 추가하지 않는다.

---

# 92. DEFAULT FRONTEND RECOMMENDATION

프로젝트가 아직 Framework를 결정하지 않았고 다음 조건이라면:

```text
Python backend
Authenticated web app
Dashboard / SaaS application
SEO 낮음
Client-side interaction 중심
```

기본적으로:

```text
React
TypeScript
Tailwind
Vite 또는 현재 Build Tool
```

이 충분히 단순하고 좋은 선택일 수 있다.

반대로 Public Web/SEO/SSR 요구가 강하면 Next.js를 검토한다.

---

# 93. OPEN-SOURCE CONTRIBUTOR EXPERIENCE

Open-source 사용자는 가능한 한 다음을 쉽게 할 수 있어야 한다.

```text
로컬 실행
Backend Test
Frontend Test
UI 교체
Theme 변경
Provider 구현
Public Library import
Plugin 추가 if supported
```

Core를 직접 수정하는 것이 정상적인 확장 방법이 되어서는 안 된다.

---

# 94. STABLE CORE, REPLACEABLE EDGES

```text
Stable Core
├─ Business Rules
├─ Public Contracts
└─ Stable Primitives

Replaceable Edges
├─ UI
├─ Theme
├─ SaaS Providers
├─ Cloud Providers
├─ Database Adapters
└─ Optional Plugins
```

---

# 95. DO NOT OVER-ENGINEER

다음을 자동으로 도입하지 않는다.

```text
모든 곳에 DDD
모든 곳에 Repository
모든 곳에 Interface
모든 곳에 Factory
모든 곳에 Event Bus
모든 곳에 Plugin
모든 Folder의 Package화
모든 Component의 Headless화
Next.js 자동 도입
```

구체적인 문제를 해결할 때만 Pattern을 적용한다.

---

# 96. FINAL ARCHITECTURE PRINCIPLE

이 프로젝트의 최종 목표는 "특정 예시 폴더 구조"가 아니다.

목표는:

```text
실제 프로젝트 구조를 정확히 이해하고

그 프로젝트의 언어
그 프로젝트의 Framework
그 프로젝트의 디렉토리명
그 프로젝트의 Naming Convention
그 프로젝트의 Public API
그 프로젝트의 Build/Test 환경

을 존중하면서

책임
Boundary
Dependency
Readability
Testability
Extensibility

를 개선하는 것이다.
```

---

# 97. REQUIRED AI FINAL REPORT

모든 중요한 작업 후 다음 형식을 사용한다.

```text
# Work Summary

## 1. Existing Project Structure Analyzed
- 실제 확인한 주요 디렉토리
- 관련 Entry Point
- 현재 Naming Convention

## 2. Existing Patterns Reused
- 기존 방식 중 유지한 것

## 3. Problems Found
- 실제 코드 기준 문제점

## 4. Changes Made
- 실제 파일/경로

## 5. Architecture / Boundary Changes
- Module
- Public API
- Dependency direction

## 6. Python Changes
- functions
- types
- repository/provider
- errors/config

## 7. Frontend Changes
- TypeScript
- React components/hooks
- Tailwind/CSS
- state ownership

## 8. Library / Package Decisions
- extracted
- not extracted
- reason
- public/internal status

## 9. Provider / Adapter Changes
- contracts
- vendor implementations

## 10. Open-Source Extension Points
- config
- theme
- components
- providers
- plugins

## 11. Compatibility
- public API impact
- config impact
- migration impact

## 12. Validation
- executed commands
- pass/fail/not-run

## 13. Remaining Technical Debt
- remaining issues

## 14. Recommended Next Steps
- ordered next work
```

---

# 98. FINAL ALWAYS-ON PROMPT

AI coding agent에게 아래를 항상 함께 제공할 수 있다.

```text
Always use AI_ALWAYS_ON_PROJECT_CODING_GUIDE.md as a standing instruction
for every coding task in this repository, not only for refactoring tasks.

Before writing or modifying code, inspect the existing repository
and understand the relevant source completely enough to avoid inventing
a generic architecture that does not match this project.

Do not blindly create directories named features, shared, core,
domain, application, infrastructure, integrations, or packages
just because they appear in architectural examples.

First inspect:
- the actual directory names,
- current Python package structure,
- current frontend structure,
- current import relationships,
- current public APIs,
- current tests,
- current build/lint/typecheck setup,
- current naming conventions,
- current provider integrations,
- current styling conventions.

Then design the change using THIS PROJECT'S existing vocabulary,
directory names, framework conventions, and ownership boundaries.

Python is the default backend/core language.

For backend work:
- prefer Python,
- use type hints,
- keep business calculations pure where practical,
- keep external dependencies explicit,
- isolate replaceable vendors behind providers/adapters when justified,
- respect the existing Python package and dependency-management conventions.

For frontend work:
- use TypeScript,
- use React,
- use Tailwind for static styling,
- keep pages focused on composition,
- extract meaningful components,
- use custom hooks only for React-specific reusable behavior,
- keep pure calculations as ordinary functions,
- minimize global CSS and static inline styles.

Next.js is optional.
If this repository already uses Next.js, respect its conventions.
If it does not, do not introduce Next.js merely as part of refactoring.
Treat migration to Next.js as a separate architecture decision
that requires a concrete need such as SEO, SSR, SSG, or other
project-specific rendering requirements.

If React + TypeScript + Tailwind with the current build tool
already satisfies the product requirements, keep the simpler stack.

Common code:
- keep it in its owning module by default,
- move it to shared only when genuinely domain-neutral and reused,
- consider an internal library/package only when it has a coherent,
  stable responsibility and multiple independent consumers,
- publish a library only when external open-source consumers
  have a real reason to import it directly.

Library/package work:
- distinguish normal folders, shared modules, internal packages,
  and published packages,
- do not turn every folder into a package,
- keep package public exports explicit,
- prevent deep imports into package internals,
- avoid circular package dependencies,
- validate public imports and type/build outputs.

Open-source extensibility:
- normal customization should not require core source modifications,
- prefer configuration, themes, composition, component overrides,
  provider interfaces, and only then plugins when truly needed,
- keep public extension APIs small and stable.

Collaboration:
- preserve clear ownership boundaries,
- reuse existing project conventions,
- minimize edits outside the owned area,
- define contracts before parallel implementations,
- avoid giant shared files that cause merge conflicts.

Never silently change:
- business rules,
- authentication/authorization behavior,
- database schema,
- persistent data formats,
- public APIs,
- environment variable names,
- provider/plugin contracts,
- framework choices,
- user-visible workflows.

After meaningful changes, run the actual validation commands
that exist in the repository.

Never claim a validation passed unless it was actually executed.

When reporting work, use actual project paths and names.
Do not describe the project using generic placeholder directories
unless those directories genuinely exist in the repository.
```

---

# 99. FINAL ONE-SENTENCE RULE

> **AI는 모든 코딩 작업에서 이 문서를 상시 참조하고, Python을 기본 Backend/Core 언어로, TypeScript + React + Tailwind를 기본 Frontend 스택으로 사용하되, Next.js는 실제 요구 또는 기존 프로젝트 사용 여부에 따라 선택하며, 어떤 Generic Template도 그대로 강제하지 않고 반드시 현재 저장소의 실제 소스코드·디렉토리·Import·Public API·Test·Build 구조를 먼저 분석한 뒤 그 프로젝트 고유의 이름과 구조를 사용해 읽기 쉽고 협업 가능하며 오픈소스 확장이 가능한 Modular Monolith로 개선한다.**
