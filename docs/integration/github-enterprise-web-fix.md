# GitHub Enterprise 조직 탐색과 관리정보 수집 연결

기준: `goranie_bug`의 `08049335791f65c8fe7aa07ada13fe6dd4edbede`.

이 브랜치를 별도 작업 디렉터리에 체크아웃해 조사했다. 이전 수정 기준과 비교했을 때 GitHub/API/웹 관련 원본은 동일하고 Confluence 수집기와 해당 테스트만 달랐다. GitHub 수정사항만 적용했으며 Confluence 변경은 그대로 유지했다.

## 해결한 문제

일반 GitHub 소스의 프로필은 Organization/개인 계정 또는 저장소다. Enterprise slug를 이 프로필에 넣어도 하위 Organization 조회로 전환되지 않았다. 이번 수정은 기존 GitHub App 참조에서 별도 Enterprise 관리정보 연결을 만들고 기존 `provider-metadata-inventory` Worker를 실행하는 경로를 제공한다.

기존 공급자 관리 목록의 범용 설정 화면에서도 Enterprise 관리정보 연결을 직접 만들 수 있었지만, 일반 GitHub 소스 등록과는 연결되어 있지 않았다. 또한 조직 발견 기록만으로는 조직별 결과가 만들어지지 않았다. 수정 전 합성 응답으로 두 조직(`CreMore-1`, `CreMore-2`)을 발견한 뒤 후속 조직 API 보고 없이 스냅샷을 만들면 `organizations`가 빈 객체가 되는 것을 재현했다. 이는 운영 App 권한 실패 여부와 별개로 확인한 코드 결함이다.

## 사용 흐름

1. **연결된 소스 → 기존 GitHub 연결 → Enterprise 조직·Credential 연결**을 선택한다.
2. GitHub Enterprise URL의 `/enterprises/` 뒤 slug를 입력한다. 기존 소스의 조직 이름이나 Enterprise Server 호스트를 자동으로 Enterprise 이름으로 추정하지 않는다.
3. **Enterprise 관리정보 연결**을 누르면 App 비밀 참조를 재사용하는 별도 관리정보 연결이 만들어진다. 같은 소스·Enterprise로 반복 요청하면 기존 연결을 반환한다.
4. **조직·Credential 관리정보 수집**을 누른다. 등록만으로 수집이 시작되지는 않는다.
5. **공급자 관리 목록 열기 → 조직별 수집 상태**에서 조직 조회와 각 조직의 조회 결과를 확인한다. Credential 레코드는 같은 관리 목록의 기존 목록·상세 화면에 나타난다.

기존 GitHub 관리정보 연결도 **조직별 수집 상태** 버튼으로 조회할 수 있다. 전체 조직을 다시 수집하는 버튼을 제공하며 조직 하나만 선택해 재수집하는 기능은 이번 변경에 포함하지 않았다.

## 동작과 인증

- 신규 API: `POST /api/v2/coverage/github/enterprise-connections`.
- 입력은 `source_connection_id`와 명시적 `enterprise` slug다. 관리자만 등록할 수 있다.
- 신규 조회 API: `GET /api/v2/coverage/connections/{id}/github-organizations?offset=0&limit=50`.
- 호스트는 기존 소스 설정을 그대로 사용한다. GitHub.com, GHES, ghe.com의 edition을 구분한다.
- App ID와 Base64 PEM 개인키의 **저장소 참조**만 재사용한다. API가 비밀을 해독하거나 응답·작업 payload에 복사하지 않는다.
- Worker는 기존 bundle의 `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY_BASE64` 또는 v2 역할명 `app_id`, `private_key`를 읽는다. 일반 PAT의 `token` 필드는 App 역할로 대체하지 않는다.
- 저장된 PAT로 확인되는 소스, 참조 없는 소스, 중지된 소스, GitHub가 아닌 소스는 등록을 거절한다. 기존 Vault 참조는 Worker가 App bundle 필드를 확인한다.
- 새 관리정보 연결은 별도로 관리된다. 기존 소스 연결을 중지해도 별도 관리정보 연결을 자동 중지하지 않으며, 수집 중지는 해당 관리정보 연결에서 수행한다.
- 기존 관리정보 연결을 재요청해도 설정이나 중지 상태를 덮어쓰지 않는다. 참조·설정이 달라졌으면 기존 관리정보 설정을 확인하도록 오류를 반환한다.
- DB 스키마 변경 및 마이그레이션은 없다.

## 조직과 오류 표시

- 조직 발견 기록만 있고 후속 API를 아직 읽지 못했어도 조직 이름을 유지한다.
- 설치/권한 오류는 조직별 항목에 남는다. 조직 발견 성공을 Credential 조회 성공으로 표시하지 않는다.
- 동일 조직·수집 항목에 속한 여러 저장소 중 일부 조회가 실패하면, 뒤의 성공이 앞의 실패를 지우지 않는다.
- 연결 범위가 변경된 후의 이전 실행 결과는 과거 결과로 표시한다.
- Worker 오류는 관리정보 연결 행에도 표시한다. 연결·실행 상태를 새로 읽는 버튼과 진행 중 작업의 상태 갱신을 제공한다.
- 기존 `catalog-refresh`의 화면 이름을 “조직 인벤토리”에서 “자산 목록 갱신”으로 수정했다.

## 검증

- Python: GitHub 수집기, 관리정보 API, 새 연결/조직 조회, 카탈로그 테스트 **114개 통과**.
- 프런트엔드: 새 화면, 공급자 관리 목록, 대시보드 회귀 테스트 **199개 통과**.
- 수정 Python 파일 Ruff 검사 통과.
- 이 브랜치에서 Next.js `build --webpack` production build 및 TypeScript 검사 통과. 기본 Turbopack 빌드는 로컬에서 재사용한 `node_modules` 연결이 작업 디렉터리 밖을 가리켜 실패했으며, 코드 컴파일 실패와 구분한다.
- 실제 App 인증 모듈과 HTTP adapter를 `httpx.MockTransport`로 연결하여 Enterprise + 조직 두 개의 독립적인 설치 인증과 각 조직 PAT 메타데이터 조회를 검증했다. 외부 GitHub 요청은 없다.
- 이전 동일 GitHub 수정본의 로컬 합성 웹 화면에서 Enterprise 등록 → 수집 예약 → 공급자 관리 목록 이동 → 정상/실패/미수집 조직 표시를 직접 확인했다. 이번 브랜치에서는 프런트엔드 회귀 테스트와 빌드를 다시 수행했다. 반복 가능한 화면 fixture는 `web/tests/github-enterprise-preview.cjs`다.

운영 배포와 실제 조직 수집은 수행하지 않았다. 운영 반영 시 API/Worker와 웹을 함께 업데이트해야 하며, 실제 App의 Enterprise 및 조직 설치·조회 권한은 해당 환경에서 확인해야 한다.
