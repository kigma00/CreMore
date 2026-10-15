# GCP 브랜치 상세 분석

> 이 문서는 2026-09-21 설계 기록이다. 이후 연결·자동 수집·값 저장 구현과 현재 사용법은 [GCP 통합 가이드](GCP_TOTAL_GUIDE_KO.md)를 참조한다.

기준일: 2026-09-21. `GCP`는 `3d79ccbef4ad51a7e7b9e0f73eabb1ac478c5ade`, `DEV`는 `71ea52ad933708b7fb851f590ab7162d7f7ed35f`다. 아래 GCP 상대 경로의 공통 prefix는 `gcp-connector/`다.

팀원 변경은 공통 조상 `6cabc6b351274a4da5340bb18c8d081caa9f899b`에 대한 **24개 새 파일**이다. 이 24개 전체를 읽었으며 `relations.py` 604행, 모든 CLI, 6개 테스트 파일, 기술 문서, SVG도 포함한다. 나머지 366개는 조상 트리이며 팀원이 새로 만든 구현으로 세지 않았다. [판독 대장](source-inventory.csv)과 [통합 설계](../INTEGRATION_DESIGN_REVISED.md)를 함께 참조한다.

## 1. 별도 기능 경로

| 경로 | 실제 기능 | 저장, 출력 |
|---|---|---|
| `cli.py` → `collector.GcpCollector.collect` | 프로젝트별 서비스 계정, 키, API key, Secret metadata | 제한된 필드의 inventory JSON |
| `watch_cli.py` → `watch.poll_once/collect_observations/merge_state` | 주기 관찰, 글로벌, 리전 Secret/모든 버전, 값 수집과 변화 이벤트 | **값을 포함할 수 있는 JSON state**, 로컬 lock, 이벤트 누적 |
| `secret_values_cli.py` → `secret_values.py` | 별도의 글로벌 latest Secret 값 수집 | **평문 export**. watcher와 범위가 같지 않음 |
| `relations_cli.py` → `relations.RelationshipCollector` | 로그, metric, IAM allow-policy로 관계 수집 및 조회 | 관계/coverage JSON |
| `api_key_cli.py` → `linkage.match_api_key` | Google lookupKey를 통한 정확한 API key 리소스 연결 | 일치/모호/미확인 관계. 사용 가능성 검증 아님 |
| `linkage.match_service_account_key` | JSON 필드의 client_email+private_key_id로 inventory 연결 | 로컬 정확 identity 비교, validity는 unverified |
| `Dockerfile.watch`, `compose.watch.yml` | 독립 watcher 배포 | 기존 제품 API/worker/DB와 연결되지 않음 |

근거: `GCP:cremore_gcp/collector.py:156`, `:204`; `GCP:cremore_gcp/watch.py:183`, `:297`, `:354`; `GCP:cremore_gcp/secret_values.py:23`; `GCP:cremore_gcp/relations.py:75`; `GCP:cremore_gcp/linkage.py:20`, `:61`.

## 2. 실제 수집 범위와 해석

| 대상 | 구현 범위 | 보존할 제한 |
|---|---|---|
| 서비스 계정 | 지정 프로젝트의 principal metadata | 계정은 자격증명 개수에 합산하지 않음 |
| 서비스 계정 키 | USER_MANAGED 및 SYSTEM_MANAGED metadata | 공개키/시스템 키와 유출 private key는 다름. provider exposed/compromise 사유는 공급자 관찰 |
| API key | `showDeleted=true`, resource ID, UID, 제한, 상태 | resource ID와 UID를 혼동하지 않음. metric은 UID 사용 |
| Secret metadata | 글로벌 및 지원 위치 목록에서 발견한 지역의 Secret | vault container이며 자체로 유출 credential 아님 |
| Secret version | watcher는 모든 버전 열거, enabled 값 읽기 | enabled와 current/latest는 다름. disabled/destroyed는 값 접근 대상과 구분 |
| Secret bytes | CRC32C 검사, UTF-8 또는 binary 표현 | payload digest는 자격증명 fingerprint와 다른 증거 |
| 수집 상태 | source별 complete/partial/error, 페이지 한도/반복, API 상태 | 한 API의 오류로 다른 source의 성공을 지우지 않음. 빈 목록과 미수집 구분 |

ADC의 cloud-platform scope를 사용하지만 실제 가시성은 IAM, 프로젝트 선택, 서비스 활성화 상태에 제한된다. API key string이나 Secret payload 접근 권한은 metadata 목록 권한과 별도다. 현재 구현은 프로젝트 중심이며 organization/folder 전체 발견, 완전한 IAM Deny 해석, 일반 OAuth 발급 토큰 registry가 아니다.

`watch._lifecycle`는 disabled가 없으면 active로 둘 수 있다. 통합에서는 이 값을 `provider_state`와 그 근거로 남기고 인증 성공을 뜻하는 기존 verification 필드로 쓰지 않는다. [GCP:cremore_gcp/watch.py:170]

## 3. 관계 수집기 전체 판독 결과

`relations.py`는 단순 부속 도구가 아니라 팀원이 추가한 주요 기능이다. 604행 전체를 읽었다.

| 관계 | 사용하는 근거 | 확정할 수 있는 것 / 없는 것 |
|---|---|---|
| principal → Secret/version 사용 | 성공한 AccessSecretVersion 감사 로그 | 해당 principal의 관측된 접근. key 이름이 없으면 특정 SA key로 연결하지 않음 |
| SA key → 사용 | 로그의 정확한 serviceAccountKeyName | 명시된 key에 한해 연결. 같은 account/시간만으로 key 추측 금지 |
| API key → service 사용량 | API key UID 기반 request_count metric | 관찰한 서비스/건수. 호출 principal은 unknown. 0/데이터 없음은 미사용 증명 아님 |
| principal → Secret 잠재 접근 | project/Secret IAM allow policy | possible/unconfirmed. 조건, 그룹, 도메인, deny, 상속을 모두 계산한 유효 권한 아님 |

로그 본문은 필요한 필드로 곧바로 투영한다. 허용 POST는 Logging entries:list 및 project getIamPolicy처럼 읽기 연산이다. IAM allow relation과 실제 사용 relation을 합산하거나 같은 badge로 보여주지 않는다.

관계 엔진의 custom-role 해석도 보존한다. 정해진 역할로 판단할 수 없으면 해당 역할의 `includedPermissions`에서 Secret version access 권한을 확인해 캐시하고, 해석 실패는 `unresolved_role`로 남긴다. 모든 IAM 관계는 effective access가 평가되지 않았음을 유지한다. `query_secret`의 모호한 짧은 이름 거절, 로그/metric 시간창, 실패 호출 계수, 잘못된 metric 값 검사도 인수 대상이다.

**지역 범위 차이:** watcher는 regional Secret을 지원하지만 relations의 Secret regex와 scope는 `one_project_global_secrets`다. regional Secret이 inventory에 보인다는 이유로 관계 분석까지 완료라고 표시하면 안 된다. 초기 통합에서는 정확한 범위를 표시하고 지역 관계 parity를 별도 완료 항목으로 남긴다.

근거: `GCP:cremore_gcp/collector.py:55`; `GCP:cremore_gcp/relations.py:14`, `:75`, `:587`.

## 4. 현재 구현의 구체적 공백

1. **평문 영속화:** `_read_value`가 API key string, Secret payload를 반환하고 watcher JSON state가 이를 저장한다. standalone secret_values도 평문 export다. 기존 제품의 secret-free coverage/history/API에 이 파일을 그대로 넣을 수 없다. 값 수집 능력은 유지하되 worker 메모리에서 기존 hasher로 변환한 뒤 값은 내보내지 않는 경로로 바꾼다. [GCP:cremore_gcp/watch.py:116,354; GCP:cremore_gcp/secret_values.py:23]
2. **값 확인 시각과 버전 선택:** `merge_state`에 `value_changed` 분기는 있으나 보통 poll은 기존 object의 cached value를 재사용한다. 공식 계약상 Secret 값은 버전별로 불변이므로, 동일 버전 payload가 바뀐다는 이전 설명은 정정한다. 새 버전, latest/alias 이동, enable/disable/destroy와 마지막 성공한 값 읽기 시각을 관리해야 한다. Cached 값은 과거 읽기 증거이며 현재 접근 성공이 아니다. 이벤트 이름만으로 rotation 추적 완료라 하지 않는다. [GCP:cremore_gcp/watch.py:258,297]
3. **재시작, 대용량:** 전체 state JSON과 event 배열을 계속 읽고 쓰는 단일 writer 구조다. EKS 여러 worker가 동일 파일을 쓰도록 배포하면 안 된다. 기존 run/task checkpoint, DB 이력을 사용한다. [GCP:cremore_gcp/watch.py:297,354]
4. **최신 버전 의미:** 모든 enabled version이 현재 배포된 비밀이라는 뜻은 아니다. current/selected/historical/unknown을 분리하여 기존 coverage의 current value match 의미를 보존한다.
5. **binary 구분:** baseline hasher는 UTF-8 secret 탐지를 전제로 한다. binary payload의 변화 digest를 credential HMAC인 것처럼 제출하면 안 된다. 처리하지 못한 binary는 값 읽음과 credential matching 미지원 상태를 별개로 남긴다.
6. **lookup 경계:** API-key lookup은 후보를 Google의 고정 endpoint로 전송하는 별도 동작이다. inventory 수집만 켰다는 이유로 자동 실행하지 않는다. 저장된 허용 inventory, 로컬 exact ID 근거를 먼저 사용하며, 원격 linkage를 제품에 넣을 때는 목적, 범위, 스위치, 값 비반향을 명시한다. API key를 여러 조합으로 인증해보는 기능이 아니다. [GCP:cremore_gcp/linkage.py:61]

## 5. develop과의 결합 결정

| develop 접점 | 현재 존재하는 기능 | 팀원 기능을 우선 보존할 부분 | 통합 방법 |
|---|---|---|---|
| GCS content collector | 선택 bucket/object 내용의 노출 탐지 | 팀원은 이 기능을 대체하지 않음 | `gcp` content job 유지 |
| `coverage.collect.collect_gcp` | global Secret metadata 및 selected/latest 값의 HMAC | regional, 모든 버전, CRC32C, 상태, 변화 이벤트 | 기존 GCP vault path를 확장하고 같은 비밀을 두 별도 스케줄러가 중복 수집하지 않게 함 |
| `coverage.hasher` | `verify=False`, 공통 HMAC, 평문 비저장 | API-key/SA-key local linkage 및 값 관측 | 실제 credential material에만 동일 scheme 사용. 공개키/blob digest는 별도 종류 |
| Coverage 계약 | flat Observation, AWS 중심 issuer/usage | principal, credential, vault item/version, 관계, 이벤트 | v2 typed record와 목적별 coverage. 새 GCP issuer를 vault로 오분류하지 않음 |
| worker/tasks | lease, cancel, page checkpoint, revision | watcher resume, 6종 변화 사건 | 기존 worker의 bounded poll job으로 수행, 이벤트를 DB에 누적, 페이지 조회 |
| 대시보드 | GCS 연결, vault 비교 | SA/API key inventory, 관측 사용, 잠재 접근, 변화 이력 | 현재 상태, 근거시각, 관측 범위별 표시, 계정/비밀/키의 KPI 분리 |
| 배포 | 공통 Python 이미지, GCP optional dependency | ADC, watcher runtime | installed package로 편입, ADC credential source는 worker secret 경계, Linux wheel smoke test |

근거: `DEV:cremore/coverage/collect.py:313`; `DEV:cremore/coverage/hasher.py:1`; `DEV:cremore/detection/fingerprint.py:1`; `DEV:cremore/coverage/correlation.py:59`; `DEV:cremore/worker/factory.py:170`; `DEV:pyproject.toml:1`.

기존 GCP optional dependency는 google-auth를 이미 포함한다. 팀원 requirements와 호환 범위를 확인해 기존 잠금 파일을 재생성한다. 새로운 SDK, 별도 watch microservice가 반드시 필요하다는 근거는 없다.

## 6. 이력 이행과 검증

watch의 여섯 사건 `discovered`, `state_changed`, `metadata_changed`, `value_collected`, `value_changed`, `no_longer_listed`를 보존한다. 완주한 경로의 부재만 no_longer_listed 후보로 삼고, 버전의 부모 경로 완주 조건도 함께 검사한다. 이것을 revoked로 변환하지 않는다. [GCP:cremore_gcp/watch.py:283,297]

기존 standalone JSON이 실제 운영에 사용됐는지는 이번에 확인하지 않았다. 있다면 import 시 원본 위치, schema, hash, source run을 남기고, 평문을 다시 읽어도 되는 승인된 경로에서만 메모리로 HMAC을 만든다. 변환 불가능한 기존 digest는 legacy scheme 그대로 남긴다. 고객 원본 파일을 자동 삭제하거나 마스크로 exact match를 만들어내지 않는다.

이번에는 고정 snapshot에서 Windows Python의 아래 명령으로 **39/39 테스트 통과**를 확인했다. fake transport를 사용하며 실제 GCP 인증, 프로젝트 수집은 실행하지 않았다.

```text
python -B -m unittest discover -s tests -q
```

통합 인수 조건: 기존 39개 회귀 계약, global/regional/all-version metadata, CRC 실패와 access denied의 부분 성공, 새 버전, 선택 대상 변화, 마지막 값 확인 시각, history와 current 구분, 비밀이 DB/log/API에 남지 않음, exact SA-key/API-key 관계와 unverified 유지, metric/allow-policy/실사용의 구분, lease 재개, 중복 사건 방지, 기존 GCS 노출과 GCP vault 대조의 회귀 없음이다. 지역별 관계 확장 및 공급자 실환경 권한은 오프라인 통과와 별도로 검증해야 한다.

## 7. 공식 문서 대조 보완

2026-09-21 공개 공식 문서에서 확인한 계약은 [GC1–GC6](official-docs.md#gcp)에 정리했다. 이전 39개 오프라인 테스트 결과를 재사용했으며 실제 프로젝트 API 호출은 없다.

- 현재 CLI는 프로젝트를 선택하며 `collector.py:349`에서 지원 지역을 발견해 순회한다. 지역 선택 UI는 통합 시 추가할 기능이다. 지원 위치 목록은 해당 지역에 Secret이 존재한다는 증거가 아니다.
- SA private key는 생성 응답에서만 받을 수 있다. API-key 목록에는 key string이 없고 `showDeleted`는 최근 30일 삭제분이다. 원문 복원, 영구 삭제 이력 전수 기능으로 설명하지 않는다.
- Secret 버전 불변성에 맞춰 §4의 cached-value 설명을 정정했다. CRC32C는 전송 무결성이며 credential 동일값 판정이 아니다.
- Data Access 감사의 활성, 권한, 기간, 일부 서비스의 key 이름 미기록, metric 미제공, 최대 1,800초 지연을 결과 해석에 반영한다.
- 코드의 `credential_id="apikey:{uid}"` 세부 문자열은 읽은 공식 metric 페이지에서 직접 확정하지 못했다. 실제 descriptor/허용 fixture 확인을 별도 인수 조건으로 남긴다.
