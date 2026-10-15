# 제품 선택과 수집 목적 분리

작업 기준: 2026-10-05, `integration/saas-structure` 작업 트리.
상태: 제품 선택·계정/콘텐츠 분리 구현. 남은 검토 항목과 사용자 결정으로 제외한 범위를 구분한다.

## 사용자 흐름

1. 연동 서비스는 `계정·발급 목록 연결`과 `콘텐츠 검사 위치 연결` 두 묶음의 카드와, 같은 두 묶음으로 나눈 연동 현황을 보여 준다
   (2026-10-12, [공급자 연결](ONBOARDING.md#연동-서비스-화면-2026-10-12)).
2. 제품/배포 형태/요금제가 실제 지원 기능에 영향을 주면 인증 전에 선택한다. 계정 카드는 계정 기능이 있는 제품만 보여 주고
   하나뿐이면 선택을 건너뛴다.
3. 계정 카드: 인증 → 선택한 제품에서 가능한 계정 기능 → 권한 확인 → 대상 선택 → 최종 확인. 콘텐츠 카드는 기능 선택 없이
   인증 → 권한 확인 → 검사 범위 → 최종 확인이다.
4. 계정 연결은 콘텐츠 검사 기능을 선택하거나 자동 실행하지 않는다. S3·GCS·Blob·저장소·페이지 검사는 별도 카드에서 시작한다.
5. 추가 인증은 선택한 제품 안에서만 이어진다. 다른 edition으로 자동 변경하지 않는다.
6. 기존 혼합 연결·승인 scope·이력·예약 작업은 자동 분리/삭제하지 않는다. 기존 연결의 명시적 편집은 유지한다.

제품 선택은 라이선스 보유나 권한의 증거가 아니다. 실제 endpoint 권한 확인 실패는 다음 단계를 막는다.
AWS/GCP의 조직 여부를 Enterprise 요금제로 취급하지 않는다. Azure처럼 사용자별 라이선스와 로그 보존이
섞인 제품은 관련 API 기능 조건을 별도로 설명하며 모든 tenant의 권한을 추정하지 않는다.
관측 로그의 actor·대상·성공 상태가 정확히 연결되는 경우만 생성/사용 근거로 기록한다.

## 일반 계정과 Enterprise

Notion Free/Plus/Business에는 계정 기능이 없으므로 계정 카드에 나오지 않는다. 이 요금제는 콘텐츠 카드에서 내부 연결 토큰(이전 이름:
내부 통합)으로 바로 인증하고 공유된 페이지·읽기 권한·범위를 확인한다. 2026-10-12 이전에 계정 카드에서 인증만 저장한 연결은 그대로
두며, 연동 현황의 콘텐츠 묶음에 `계정 인증만 완료`로 나오고 `검사 위치 고르기`가 기존 봉인 자격증명을 재사용해 재인증한다.
Notion 계정 카드는 Enterprise만 다루며(`Enterprise 전용: 발급 목록·조치`), Enterprise도 페이지 읽기용 내부 연결 토큰으로 계정만
연결할 수 있다. 조직 관리 권한을 강제로 요구하지 않는다.
PAT·MCP 인벤토리는 Enterprise 조직 봇 인증을 사용한다. 이 토큰은 콘텐츠 읽기를 대신하지 않으므로
콘텐츠 추가 시 **콘텐츠 읽기용 추가 인증**으로 안내하고 같은 edition 안에 별도 자격증명 소유 연결을
만든다. 두 토큰의 신원을 동일하다고 단정하거나 중지·갱신 수명을 자동으로 묶지 않는다.

콘텐츠 카드는 다시 쓸 연결이 있거나, AWS가 아니고 먼저 인증하는 새 연결 방식(`auth_first`, `new_setup` 허용)이 노출 검사를 지원하면
열린다. AWS는 S3를 계정의 역할로 읽으므로 계정을 먼저 연결해야 한다. 다시 쓸 연결이 하나면 바로 열고, 여럿이면 먼저 고른다.
웹사이트는 공급자 로그인 대신 기존 도메인 소유 검증을 사용한다.

## 저장·활성화 계약

`onboarding-sessions/{id}/complete`의 `authentication_only:true`는 인증 성공 상태에서만 허용한다.
이름 외 수집·예약 설정은 거절하며 owner를 `CHECKED`, 빈 purposes/plans로 저장한다. source·scope·
수집 주기·scan 작업은 만들지 않는다. 계정 인증 감사는 남기고 초안의 인증 참조는 완료 시 비운다.
완료 재전송은 같은 owner를 반환한다. 권한 확인 API는 빈 목적의 무의미한 성공을 만들지 않는다.
콘텐츠 추가는 기존 `/targets/draft`에서 동일 owner를 재인증하고 권한·scope·revision·트랜잭션 검증을
모두 거쳐 활성화한다. 기능을 추가하기 전의 인증 전용 owner는 수집/자동 갱신 작업을 실행하지 않는다.

구형 Notion `cloud`, Vault `self_managed`는 새 연결에서 제외하지만 기존 연결 유지보수는 허용한다.
제품을 바꾼 새 흐름은 다른 제품의 초안·권한을 재사용하지 않는다. OAuth/App 복귀도 초안의 제품·목적을
확인한다. DB 이관은 없다. 기존 혼합 연결을 자동 분리하지 않는다.

## 공급자별 제품 조건

| 공급자 | 인증 전 선택·적용 |
| --- | --- |
| Notion | 일반 / Enterprise. 일반도 페이지 읽기 가능, PAT·MCP/폐기는 Enterprise와 해당 scope 필요 |
| GitLab | .com / Self-Managed / Dedicated 및 요금제. .com Free는 그룹·프로젝트 토큰 목록 제외, Self-Managed Free는 지원. 유료 감사/Enterprise PAT 조건 구분. 구형 미기록 요금제 유지 |
| GitHub | .com / Enterprise Cloud / GHE.com / GHES. 기존 enterprise 전용 목록·인증 조건 유지. 설치 버전·권한은 실제 점검 |
| Atlassian | Cloud / Enterprise Cloud. Confluence·Bitbucket은 Cloud / DC. 조직 관리 endpoint·인증과 콘텐츠 권한 각각 점검 |
| Vault / OpenBao | Community / Enterprise / HCP Dedicated. Vault namespace는 Enterprise/HCP만 허용. OpenBao 자체 namespace 계약 유지 |
| Azure / DevOps | Azure는 통합 tenant, DevOps는 Services / Server. 로그 라이선스·API 조건은 해당 옵션에 명시 |
| AWS / GCP | 단일 클라우드 제품. 조직·계정·프로젝트는 인증 후 발견하며 Enterprise 요금제로 취급하지 않음 |
| Slack | 현재 앱 인벤토리는 Enterprise Grid. 일반 Slack 콘텐츠 수집을 제공한다고 표시하지 않음 |
| Okta / Workspace / Keycloak | 로그인·담당자 디렉터리·퇴사자 점검에 필요한 기존 제품·배포 형태. 추가 자격증명 인벤토리·범용 감사 로그 수집은 범위 제외 |
| 외부 금고 / Website | 기존 금고 제출 계약 / 도메인 소유 검증 유지 |

공식 근거는 [공급자 기술 검토](PROVIDER_CREDENTIAL_FEASIBILITY.md)와 후속 확인을 함께 사용한다.

- [GitLab 그룹 토큰](https://docs.gitlab.com/user/group/settings/group_access_tokens/),
  [프로젝트 토큰](https://docs.gitlab.com/user/project/settings/project_access_tokens/):
  GitLab.com은 Premium/Ultimate, Self-Managed/Dedicated는 모든 라이선스 등급에서 제공.
- [Notion 연결](https://developers.notion.com/docs/authorization),
  [Notion Admin API](https://developers.notion.com/reference/admin/intro): 콘텐츠 공유와 Enterprise 조직 관리를 구분.
  Admin API는 활성 Enterprise 요금제의 조직·workspace에만 제공하며 조직 봇 토큰으로 인증한다.
- [Vault namespace](https://developer.hashicorp.com/vault/docs/enterprise/namespaces): Enterprise 기능.

## 인수 항목

- [x] 현재 catalog 제품/라이선스 조건 검토와 근거 기록
- [x] 인증 전 제품 선택, 지원 기능/인증 방식 필터 및 서버 검증
- [x] 계정·검사 카드 분리, 신규 계정 연결의 scan 미생성·미실행 회귀
- [x] 제품/목적 변경 시 이전 draft·plan·권한 근거가 재사용되지 않음
- [x] 기존 연결 및 OAuth/GitHub App 복귀·추가 인증 합성 회귀
- [x] GCP API key 생성 actor, 서비스 계정 IAM 정책 후보 근거, regional Secret Manager 관계 보강
- [x] Azure directory audit의 정확한 credential 생성 actor 연결
- [x] Azure Key Vault 접근 로그·Managed HSM의 핵심 흐름 적합성 검토 (아래 범위 판정)
- [x] 구현한 범위의 API/UI 공통 metadata projection·지원표 최신화
- [x] 변경 범위의 합성 회귀·웹/브라우저·Linux/PostgreSQL 검증과 결과 기록

추가 Notion/IdP 확장은 아래 사용자 범위 결정에 따라 작업 목록에서 제외했다.
그 밖의 기술적 제한은 `INVENTORY_METADATA_REVIEW_2026-10-05.md`와 함께 확인한다.
공급자가 제공하지 않는 전수 목록, 키별 귀속 불가능한 로그는 임의 데이터로 채우지 않는다.

## 핵심 흐름과 제외 범위 (2026-10-05)

사용자 결정에 따라 다음 추가 수집기는 구현 대상에서 제외한다. 코드의 descriptor·등록·조회 경로를
확인한 결과 모두 제안 단계였으며 삭제할 런타임 구현은 없었다. 미완료 과제나 향후 구현 약속으로 남기지 않는다.

- Notion Enterprise 별도 감사 webhook 수신.
- Okta API-token 목록·System Log 수집.
- Keycloak 추가 자격증명 목록·범용 감사 로그 수집.
- Google Workspace OAuth grant·범용 감사 로그 수집.

기존 Notion **Enterprise PAT·MCP 연결 인벤토리**는 유지한다. 일반 요금제는 공유한 페이지의
콘텐츠 검사를 지원하며 Enterprise도 같은 콘텐츠 검사 경로를 사용할 수 있다. MCP 연결은 개별
access/refresh token 전수 목록이 아니다. 일반 요금제의 조직 인벤토리는 서버에서도 거절한다.

IdP는 로그인·역할 판정·담당자 목록/연결·퇴사자 점검을 지원한다. Keycloak의 기존 선택적
`USER UPDATE/DELETE` 관리 이벤트는 사용자 비활성화·삭제 시각의 근거이므로 유지한다.
기존 Okta·Keycloak의 선택적 앱 이름/상태 조회는 연동 제안용이며 토큰·client secret 인벤토리가 아니다.
이번 범위 결정은 해당 보조 기능이나 이미 남긴 감사 이력을 삭제하는 변경이 아니다.

## 검증 (2026-10-05)

기준: `564df841d97fa51f3435873b526414ac527363c4` 이후의 미커밋 작업 트리. 실제 공급자를 호출하지 않았다.

| 실행 | 결과·증거 |
| --- | --- |
| 웹 전체 단위 검사 | 275 passed (`output/edition-web-unit-final.log`); 이후 테스트를 실제 auth-first descriptor 조건에 맞춘 설정 회귀 24 passed (`output/edition-web-setup-final.log`) |
| TypeScript / Next production build | 통과 (`output/edition-typecheck-final.log`, `output/edition-web-build-final.log`) |
| 브라우저 | `console-auth-first`, `console-gcp-oauth`, `console-integration-edit` 통과. `console-edition-entry`는 native select를 option.click으로 누르던 테스트를 selectOption으로 수정 후 통과 (`output/edition-browser-complete.log`, `output/edition-browser-entry-final.log`) |
| 계정·metadata 저장소 PostgreSQL 포함 회귀 | 75 passed (`output/edition-postgres-final.log`) |
| 온보딩 PostgreSQL 선택 검사 | 13 passed, 500 deselected (`output/edition-onboarding-postgres.log`); Linux 실행에서 생략한 PostgreSQL 항목 포함 |
| Linux Python 3.14 | 온보딩·GCP metadata·Azure Entra·Atlassian·공급자 경계: 1,253 passed, 8 PostgreSQL skipped, 311 subtests passed. 1개 계약 검사에서 build-stage 이미지에 제외된 웹 원본이 없어 실패. 그 파일을 시험 환경에 복사 후 동일 계약 검사 5 passed (`output/edition-linux-tests.log`, `output/edition-linux-contract.log`) |
| 후속 공급자/API 선택 검사 | 71 passed, PostgreSQL 14 skipped (`output/edition-providers-final.log`). 생략한 API PostgreSQL 회귀를 별도로 실행해 14 passed, 39 deselected (`output/edition-records-postgres.log`) |
| 수정 Python Ruff / diff 공백 검사 | 통과 (`output/edition-ruff-final.log`, `git diff --check`) |

Linux 검사는 이 작업의 build-stage 이미지에서 editable 설치 후 외부 네트워크를 끊고 uid 65532로,
Windows bind mount 없는 Linux 파일시스템에서 실행했다. PostgreSQL은 별도 tmpfs 컨테이너의
`127.0.0.1:55439/cremore_test`와 테스트별 임시 schema만 사용했다. 기존 제품 DB·컨테이너는 건드리지 않았다.
이는 Linux 설치·회귀 검증이며 런타임 이미지 배포·고객 환경 24시간 갱신 검증을 대신하지 않는다.
커밋·push·운영 서버 배포는 이 검증에 포함하지 않는다.

2026-10-06 범위 판정: 기존 Key Vault의 secret/certificate/key 메타데이터와 승인된 값 대조는 유지한다.
Managed HSM은 임의 secret 저장소가 아니므로 평문 자격증명의 발급·금고 대조를 위해 새 공급자로 추가하지 않는다.
Key Vault 진단 로그는 금고 리소스의 접근 조사 자료이며 그 안에 보관된 외부 자격증명의 사용 이력이 아니다.
핵심 흐름에 필요한 항목만 구현하라는 사용자 결정에 따라 별도 Monitor 진단 로그 수집기도 이번 범위에서 제외한다.
이 판정은 해당 기능을 구현했다는 뜻이 아니며, 기존 지원표의 미지원 표시는 유지한다.
Notion·IdP의 추가 token/audit 수집은 위 사용자 결정으로 제외했으며 남은 작업이 아니다.
현재 상태와 기술적 조건은 [인벤토리 재검토](INVENTORY_METADATA_REVIEW_2026-10-05.md)에 남겼다.

### Notion·IdP 범위 재확인 (2026-10-05)

이번 범위 정리는 문서 4개만 수정했으며 수집기·등록·운영 설정을 변경하지 않았다.
`AWS_EC2_METADATA_DISABLED=true`로 Notion `onboarding_test.py`, Okta·Keycloak의
`tests/test_identity.py`, Workspace `identity_test.py`를 실행해 **65 passed**를 확인했다.
HTTP fake와 메모리 저장소 검증이며 실계정·운영 DB 검증은 아니다.
수정 문서의 로컬 참조 69개와 `git diff --check`를 확인했다.
