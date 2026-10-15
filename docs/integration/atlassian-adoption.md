# Atlassian와 Bitbucket 구현 인수 기록

기준일: 2026-09-21. 반입 원본은 `publish/develop_atlassian`의 `49abdc11a998f61917e151ab276e84c7a21815ea`이다. 기존 설계의 `11c44f2` 이후 변경도 포함했다. 기존 `develop`의 Confluence와 Bitbucket 콘텐츠 수집은 별도 기능으로 유지한다.

2026-09-23 갱신: 실습 조직의 Preview 활성화 후 서비스 계정 404와 OAuth count 요청 계약을 확인하고 공통 수집기에 반영했다. 현재 동작과 남은 제한은 [Preview API 계약 반영 기록](atlassian-preview-contract.md)을 따른다. 아래 오프라인 인수 기록은 당시 검증 범위를 보존한다.

## 반입 범위와 제품 연결

팀원 코드는 `cremore/coverage/providers/atlassian/`으로 옮겼다. 원본 Python 모듈 19개, 설정과 진단 스크립트 5개, 오프라인 cursor 실험 1개를 보존했다. 고객 계정의 `docs/evidence` 자료는 반입하지 않았다. 원본 브랜치에는 별도 LICENSE 파일이 없었다. 배포 권리와 프로젝트 고지의 최종 확인은 공통 패키징 단계에서 수행한다.

| 기능 | 설치된 코드 | 제품에서 사용하는 방식 |
|---|---|---|
| Cloud 정규화 인벤토리 | `collector.py`, `metadata.py`, `specs.py` | `adapter.collect_pages`의 `inventory` 모드 |
| Cloud 전체 관리정보 | `discovery.py`, `read_operations.py` | `discovery` 모드. 계정 관리 조회의 포함 여부를 명시 |
| 분리된 managed account 연결 | `discovery.iter_accounts` | `accounts` 모드. 해당 조직 목록에서 관측한 account_id만 후속 조회 |
| Bitbucket 기본 관리정보 | `bitbucket.py` | `bitbucket` 모드 |
| Runner 조회와 UUID pagination 검증 | `bitbucket.py`, `runner_pagination.py` | `runners` 모드 |
| 저장소 branch restriction 목록과 상세 | `bitbucket.py` | `branch_restrictions` 모드 |
| 중복, 잘못된 ID, 원본 JSON 타입 | `identities.py` | typed report의 품질 지표와 source 관측으로 보존 |
| 저장 결과 비교 | `compare.py`, `replay.compare_records` | 공통 DB에 저장된 두 실행의 동일 범위와 순차 시간 창을 비교 |
| 선택 재수집 | `recollect.py`, `replay.plan_recollection`, `adapter.collect_pages` | 실패 또는 부분 조회를 기본 선택. 필요 시 unverified 포함. 항상 첫 페이지부터 읽으며 관측된 대상만 조회 |
| 읽기 진단과 로컬 job manifest | `jobs.py` | 진단 변환 함수는 재사용 가능. native CLI와 manifest는 명시적으로 실행하는 QA 도구 |
| private 파일 CLI | `cli.py`, `compare.py`, `jobs.py`, `recollect.py`, `storage.py`, `connections.py`, `jsonio.py` | 제품 worker는 사용하지 않음. 명시 실행한 로컬 QA에만 사용 |
| 설정과 제한된 probe | `qa/` | `python -m cremore.coverage.providers.atlassian.qa.<module>`로 명시 실행. import 시 계정 조회와 파일 저장 없음 |

제품 수집은 공통 registry, `MetadataConnectionSpec`, 공통 task lease와 DB를 사용한다. provider 폴더에 독립 서비스, 별도 worker, watcher, DB를 추가하지 않는다. native CLI의 기본 private 출력 위치는 현재 작업 디렉터리의 `.local`이다. 원본 POSIX 파일 권한 검사를 유지하므로 Windows native CLI 파일 저장의 지원을 선언하지 않는다. 공통 DB adapter의 전송과 변환은 Windows에서도 합성 검증했다.

## 최신 브랜치와 공식 계약

현재 카탈로그는 Cloud 17개, Bitbucket 28개로 합계 45개 읽기 operation이다. 이전 설계의 Bitbucket 26개에 branch restriction 목록과 상세 2개가 추가됐다. Cloud의 두 POST는 개수 조회이며 공급자 변경 작업이 아니다.

Bitbucket 기본 22개, Runner 4개, branch restriction 2개를 구분한다. Runner와 branch restriction 모드는 저장소 discovery를 선행한다. Runner의 내부 UUID next URL은 먼저 공개 workspace와 repository 응답에서 확인한 같은 리소스 UUID일 때만 허용한다. next URL이나 오류에서 새로운 UUID를 학습하지 않는다.

2026-09-21에 확인한 공식 OpenAPI는 아래와 같다. 패키지의 `response-fields.json`에는 문서에서 추출한 operation별 응답 property 경로와 타입, 원본 SHA-256이 있다. 고객 응답은 포함하지 않는다.

| 공식 문서 | 원본 SHA-256 |
|---|---|
| [API Access](https://dac-static.atlassian.com/cloud/admin/api-access/swagger.v3.json) | `eb9c7a84b5353f9a4a44ece2c892d7064cf07c6a2657a48c752fec3523240b88` |
| [Organizations](https://dac-static.atlassian.com/cloud/admin/organization/swagger.v3.json) | `c2e5d2903268aadd28a6de1e82d09a7aa410a05d328139f5bf01bef443e68807` |
| [User management](https://dac-static.atlassian.com/cloud/admin/user-management/swagger.v3.json) | `cc21935862dd9eaa5fa4cf76b261a79de1572d39417daaf16e399deea84c705f` |
| [Bitbucket](https://dac-static.atlassian.com/cloud/bitbucket/swagger.v3.json) | `5faacee02bacc835ed865aac8a3b5fee8686b9d095e46e187ad54e9cd2d268c7` |

[공식 Bitbucket API token 가이드](https://support.atlassian.com/bitbucket-cloud/docs/using-api-tokens/)는 개인 scoped API token의 Bearer와 Basic을 모두 설명한다. 따라서 원본 Bearer 기본값을 유지하고 명시적인 Basic만 추가했다. Basic은 username과 password secret reference를 분리한다. 인증 오류 이후 다른 방식으로 전환하지 않는다. 공개 OIDC discovery와 JWKS에는 첫 요청부터 인증을 보내지 않는다.

## 변환과 복구에서 보존하는 의미

`steps.py`의 generator는 실제 응답 페이지를 얻은 뒤 다음 요청 전에 제어권을 반환한다. 기존 동기 함수는 generator를 소비하여 원래 결과 형식을 유지한다. worker의 취소와 lease 실패는 native의 오류 정리 코드에 삼켜지지 않는다. HTTP 재시도 대기는 취소가 가능한 1초 이하 구간으로 나눈다.

`projection.py`는 페이지 header, 행, normalized 관측, operation 종료, scope 종료를 공통 typed record로 내보낸다. 한 record에 native 전체 실행 JSON을 넣지 않는다. `field_contract.py`는 provider와 operation별 공식 응답 경로 및 명시된 native 변형만 허용한다. 알 수 없는 필드, 잘못된 타입, 길이와 깊이 제한은 omission으로 남긴다. machine 제출에도 같은 경계를 적용한다. URL userinfo 및 token, API key, password, signature가 있는 query 또는 fragment는 DB에 저장하지 않는다.

문서에 없는 OAuth 배열 형태는 원본의 `unverified` 의미를 유지한다. 부분 결과, 403, 404, 예상 개수 불일치, 중복 ID, 미수집, 빈 성공 응답을 서로 구분한다. `inventory_complete`는 항상 false이며 조직의 모든 자격증명을 수집했다는 의미로 사용하지 않는다.

공개 SSH, GPG, JWKS, OIDC, known-host, 정책, Runner 정보는 노출된 secret으로 분류하지 않는다. token의 공급자 상태와 CreMore가 저장한 자격증명 유효성 검증은 다른 근거다. Runner의 OFFLINE과 UNREGISTERED를 자격증명 폐기로 바꾸지 않는다.

재시작 시 공통 DB의 완료된 source attempt만 다시 사용한다. 중단한 operation은 새 attempt로 첫 페이지부터 읽는다. `source`, `attempt`, 페이지 번호와 행 번호를 typed context에 남긴다. 과거 attempt는 이력에 유지하지만 export와 compare에서 새로운 페이지와 합치지 않는다. `current_record_status`는 abandoned attempt를 현재 상태로 승격하지 않고, partial 관측을 마지막 성공으로 바꾸지 않는다.

범위는 origin, 연결 tenant, 승인된 조직 또는 workspace와 object 종류를 포함한다. 같은 문자열 ID만으로 다른 호스트나 조직을 합치지 않는다. caller identity를 조직 ID로 만들지 않는다. 현재 adapter는 실행 중 principal 계약을 바꾸지 않기 위해 principal 미검증 상태를 유지한다. 따라서 principal pin은 실제 요청 전에 거부한다.

선택 재수집은 이전 scope 전체를 완료한 새 인벤토리로 표현하지 않는다. 새 시간 창, 선택한 읽기 operation, 이전 실행 불변을 표시한다. Runner 재수집은 새 repository discovery로 UUID 근거를 확인한다. 저장한 next URL을 새 실행의 시작점으로 사용하지 않는다.

## 검증

`cremore/coverage/tests/atlassian/`에는 원본 합성 테스트와 공통 adapter 회귀를 둔다. 원본 JSON schema 2개와 합성 예제만 옮겼다.

2026-09-21 Linux Python 3.14 검증: **285 tests 통과, 316 subtests 통과, skip 0**. `cremore-coverage-proof:20260920` 컨테이너에 소스를 읽기 전용으로 mount하고 `--network none`에서 실행했다. pytest, jsonschema, rfc3339-validator는 QA 전용 디렉터리에 격리 설치하여 공급했다. 고객 API, dotenv, 기존 고객 파일을 사용하지 않았다.

공통 adapter 회귀에는 6개 모드, 45개 operation 카탈로그, 페이지 반환 전후 취소, 재시도 중 취소, 첫 페이지 재시작, 완료 source 건너뛰기, abandoned attempt의 현재 상태 제외, schema3 상태, 개수와 빈 결과, 403, 비교와 선택 재수집, 공개 GPG와 빈 배열, Basic과 무인증 OIDC, secret reference 분리, operation 외 필드 거절, URL 자격증명 제거가 포함된다. Ruff format 및 check를 통과했다.

이 기록의 테스트 수는 Atlassian 패키지 검증 결과다. 공통 API의 권한과 lease 경쟁, 전체 PostgreSQL migration, dashboard, wheel, Python 3.12/3.14 전체 제품 회귀, 최종 이미지와 실제 배포 검증을 대신하지 않는다. 공통 API의 native export, compare, 선택 재수집 연결은 공통 구현 담당과 함께 최종 통합 검증해야 한다. 진단 변환 함수의 보존과 대시보드에서 진단 작업을 실행할 수 있다는 것은 별개다.

## 확인되지 않은 공급자 범위

- Cloud service account 목록의 Preview와 고객 tenant 권한 차이, 기존 시험에서 관측한 400/404의 원인은 이번 오프라인 검증으로 해결했다고 주장하지 않는다.
- API-access key 권한과 User management 권한을 동일하게 취급하지 않는다. 계정 조회를 분리한 연결과 `include_account_reads`를 유지한다.
- Bitbucket branch restriction의 token 참조는 workspace, project, repository의 모든 access token 목록이 아니다. native의 `public_listing_contract_unverified`를 보존한다.
- Bitbucket와 Confluence Data Center의 관리정보 adapter는 이 패키지에서 지원하지 않는다. 기존 콘텐츠 연결의 지원과 구분한다.
- 실제 기업 tenant, edition, 관리자 권한과 제한별 검증은 승인된 시험 연결이 있어야 한다. 오프라인 테스트 통과를 모든 Enterprise 환경의 지원 완료로 표현하지 않는다.
