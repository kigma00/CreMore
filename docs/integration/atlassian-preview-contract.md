# Atlassian Preview API 계약 반영 — 2026-09-23

지원 문의 ECOHELP-167001의 답변과 소유한 실습 조직의 실제 응답을 공통 수집기에 반영했다. 이 문서는 기존 [인수 기록](atlassian-adoption.md)의 서비스 계정 404 및 OAuth 계약 미확인 항목을 갱신한다.

## 확인된 계약과 변경

| 연산 | 확인 결과 | 수집기 동작 |
|---|---|---|
| `GET /service-accounts` | 조직별 Preview 플래그가 필요하다. 지원팀이 실습 조직에 활성화한 뒤 200, `items/links/total` 응답을 받았다. | 기존 페이지 수집기를 사용하고 `atlassianId`로 후속 조회 대상을 발견한다. 다른 조직의 403/404를 성공이나 빈 목록으로 바꾸지 않는다. |
| `POST /oauth-clients/count` | 서비스 계정 ID의 JSON 배열이 필수다. 응답은 `validServiceAccountIds`의 계정별 `credentialsCount`와 `invalidServiceAccountIds`다. | 계정 발견 이후 두 count 연산을 실행한다. 한 요청에 최대 100개로 제한하고, 발견한 대상이 없으면 요청하지 않는다. OAuth의 대규모 배치 지원까지 실환경 검증한 것은 아니다. |
| `GET /oauth-clients` | 지원팀이 최상위 배열을 확인했다. 실습에서는 `pageSize=1`과 `20` 모두 동일한 2개를 반환했다. | 배열 및 기존 `data/links` 형식을 읽는다. 배열은 `pagination_contract_unverified`로 기록하고 임의의 다음 페이지를 만들지 않는다. |
| OAuth 목록·상세의 메타데이터 | 실제 서비스 계정 형태에는 `clientName`, `serviceAccount`, `createdBy`, ISO 문자열 `createdAt` 등이 있다. | 명시된 메타데이터 필드와 문자열 생성 시각을 공통 DB에 보존한다. 과거 숫자 생성 시각도 읽을 수 있다. |
| API token의 발급자·계정 정보 | 실제 응답은 기존 허용 목록보다 많은 `createdBy`, `user.appType`, `user.userStatus` 정보를 반환한다. | 이미 OAuth에서 사용하는 사용자 메타데이터 필드에 한해 허용 목록을 보완한다. 임의 필드 및 비밀 원문을 허용하는 변경은 아니다. |

개수 비교의 범위는 `comparison_scope=requested_service_accounts`다. 요청한 계정들의 count를 합하고, 같은 계정에 속한 목록 항목만 비교한다. 누락·중복·요청하지 않은 계정·invalid 응답·실패를 0으로 해석하지 않는다. 계정을 알 수 없는 목록 행이 있으면 일치 여부도 미확인으로 둔다. 배치별 실패를 이전 배치 성공으로 덮지 않는다. 개수가 일치해도 `proves_completeness=false`와 `inventory_complete=false`를 유지한다.

## 공통 실행 및 보관

실행 경로는 기존 `JobWorker → metadata_job → Atlassian adapter → MetadataStore`다. 별도 제품 DB나 별도 worker를 추가하지 않았고 DB 마이그레이션도 필요하지 않다.

- 서비스 계정 목록·개수 조회까지 실행하려면 Atlassian 연결의 `options.mode`가 `discovery`여야 한다. `inventory`는 선택한 자격증명 목록을 정규화하는 모드다.
- `include_account_reads=false`로 개인 계정 관리 API는 분리할 수 있다. 이번 실습 검증도 이 설정을 사용했다.
- 인증은 worker가 해석하는 `secret_refs.token`으로 전달한다. 관리자 키 원문을 연결 설정, 결과, 로그에 저장하지 않는다.
- 공통 DB에는 entity observation과 operation report, 페이지 및 요청 대상 문맥을 저장한다. native snapshot은 이 레코드들에서 다시 구성할 수 있다.
- OAuth 목록과 상세는 서로 다른 기존 record contract를 사용한다. DB entity 행 수를 곧바로 고유한 실제 자격증명 개수로 해석하지 않는다.

새 코드를 배포한 뒤에는 **새 discovery 수집 실행**을 시작한다. 예전 본문 없는 OAuth count 실패 기록만 선택해 재수집하면 계정 ID 배열이 없으므로 거절된다. 과거 이력을 수정하거나 요청 대상을 추측하지 않는다. 새 count 실패 기록은 `requested_account_ids`를 보존하므로 동일한 계정 배치로 재수집할 수 있다.

## 검증과 남은 제한

합성 테스트는 실제 형태의 서비스 계정 및 OAuth 응답을 공통 worker로 실행해 메모리/SQLite DB 저장, 인벤토리 조회, native replay까지 확인한다. 101개 계정의 배치 분할, 빈 대상, 실패·누락 count, 재수집 대상 보존, 인증값 미저장을 별도로 검증한다.

Python 3.12에서 Atlassian 전체 테스트와 공통 metadata worker/API 회귀 **374개, subtest 316개 통과, skip 0**. JSON Schema 검증용 `jsonschema`, `rfc3339-validator`는 Git 제외 QA 디렉터리에 설치했다. 실행 명령은 `python -m pytest cremore/coverage/tests/atlassian cremore/coverage/metadata_job_test.py cremore/api/metadata_coverage_test.py -q`다.

실환경 검증은 소유한 실습 조직에서 기존 관리자 Key B를 사용했다. 요청 한도 30, 재시도 0, 계정별 대상 한도 5, 개인 계정 관리 조회 제외 조건으로 수행했다. 서비스 계정 1개, OAuth 클라이언트 2개와 계정별 count 2개 일치, 토큰 메타데이터의 공통 SQLite 저장을 확인했다. 원문 응답·인증정보·개인정보가 포함된 실습 자료는 Git에 넣지 않는다.

최종 검증 시각은 **2026-09-23 08:16 UTC (17:16 KST)**다. 실제 HTTP 요청 14회 모두 200이었고, 공통 레코드 44개를 저장한 뒤 DB에서 다시 읽었다. 서비스 계정 목록, OAuth count 및 두 클라이언트 상세는 `complete`; 조직 OAuth 목록은 페이지 계약 미확인으로 `unverified`였다. 코드의 전체 실행 결과는 `SUCCEEDED`, 수집 범위 상태는 아래 제한 때문에 `PARTIAL`이다.

`SUCCEEDED`는 작업 처리 성공이며, 조직의 모든 정보를 완전 수집했다는 뜻이 아니다. OAuth 페이지 계약 미확인과 관리자 키 응답의 제외 필드 때문에 전체 수집 상태는 보수적으로 `PARTIAL`일 수 있다. 관리자 키의 `token` 원문은 계속 제거하며, 아직 허용하지 않은 `revocationDate`·`revokedBy`도 omission으로 남긴다.

이 검증은 실습 조직과 로컬 SQLite를 대상으로 했다. 다른 조직의 Preview 가입, 대규모 OAuth 페이지 동작, 운영 PostgreSQL 및 EC2 재배포까지 검증한 것은 아니다.

2026-09-27 `integration/saas-structure` 반영: 공급자 디렉터리 이동 후 같은 변경을 `atlassian/backend/cremore_atlassian_provider/metadata/`와 `tests/test_preview_contract.py`에 옮겼다. 위 명령의 현재 경로는 `python -m pytest atlassian/backend/cremore_atlassian_provider cremore/coverage/metadata_job_test.py cremore/api/metadata_coverage_test.py -q`이며 Windows에서 400개 통과(배치가 다른 배치의 계정 수를 돌려주는 경우의 회귀 1개 추가), 57개 skip(POSIX 전용 native CLI QA)이다. 실환경 재검증은 하지 않았다.

## 근거

- Atlassian 지원 답변 ECOHELP-167001 및 2026-09-23 실습 조직 재검증.
- [Service Account API](https://developer.atlassian.com/cloud/admin/api-access/rest/api-group-service-account/)
- [OAuth Client API](https://developer.atlassian.com/cloud/admin/api-access/rest/api-group-oauth-client/)
- [API Token API](https://developer.atlassian.com/cloud/admin/api-access/rest/api-group-api-token/)

공개 문서의 고정본은 `response-fields.json`에 유지하고, 지원 답변 및 관측으로 확인한 차이는 `field_contract.py`와 회귀 테스트에 명시했다. 지원팀이 확인한 계약과 실습에서만 관측한 추가 필드를 구분한다.
