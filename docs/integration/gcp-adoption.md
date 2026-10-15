# GCP 수용 기록

기준일: 2026-09-21. 대상은 `publish/develop_gcp`의 `3d79ccbef4ad51a7e7b9e0f73eabb1ac478c5ade`다. 원본 인벤토리 schema는 0.3, 관계 및 watcher schema는 0.1이다. [기존 설계안 §3](../INTEGRATION_DESIGN_REVISED.md#3-gcp), [기존 GCP 분석](gcp.md), [공통 구현 계약](implementation-contract.md)은 설계 시점의 기록으로 유지한다. 이 문서는 수용 내용과 이번 검증 범위를 설명한다.

> 2026-10-02 후속 정책: 아래는 당시 수용 기록이다. 이후 추가했던 `store_values`·`keep_values` 원문 보관과
> 관리자 값 조회 API는 폐기했다. 현재는 수집 메모리에서 HMAC 지문으로 바꾸며 가역 암호화 보관도 금지한다.
> 기존 원문 행·백업·WAL·복제본의 정리는 [현재 GCP 가이드](GCP_TOTAL_GUIDE_KO.md#과거-원문-저장-설치의-이관)를 따른다.

## 수용 위치

원본 경로의 공통 접두사는 `gcp-connector/cremore_gcp/`다. 운영 패키지는 [cremore/coverage/providers/gcp](../../cremore/coverage/providers/gcp/)다.

| 원본 파일 | 수용 위치와 처리 |
|---|---|
| `collector.py` | `collector.py`: 서비스 계정, 서비스 계정 키, API key, global/지역 Secret, 위치 목록의 endpoint와 허용 필드, coverage 어휘를 그대로 유지했다. 목록 함수는 한 페이지를 돌려준 뒤 다음 요청 전에 제어를 반환하는 generator로 바꿨다. |
| `collector.py`의 `AdcTransport` | `transport.py`: 별도 `requests` 세션 대신 제품의 `bounded_request`와 기존 ADC token 소스를 사용한다. 허용 host 목록, 응답 바이트 한도, 요청 예산, 취소, 429 회로 차단, `Retry-After` 해석을 추가했다. 실패는 고정 코드만 남기고 URL, 본문, token을 보존하지 않는다. |
| `secret_values.py`, `watch.py`의 `_read_value` | `values.py`: CRC32C 검증, base64 한도, 버전 이름 대조, API key string과 서비스 계정 공개 인증서 읽기를 유지했다. 값은 bytes로만 반환하고 저장하지 않는다. |
| `relations.py` | `relations.py`: 감사 로그 기반 secret 접근, 서비스 계정 활동, API key 요청량 metric, IAM allow 정책의 4개 근거와 `observed_access`/`policy_possible`/`unconfirmed` 구분을 유지했다. 로그 응답의 `request`, `response`, `metadata`는 transport 직후 버린다. |
| `linkage.py` | `linkage.py`: `client_email`+`private_key_id` 식별자 일치와 원격 `keys:lookupKey` 조회를 유지했다. 후보값은 반환하지 않으며 일치는 발급 사실이지 인증 성공이 아니다. |
| `watch.py`의 상태 병합, `_state_lock`, `DEFAULT_STATE` | `snapshot.py`의 `compare_records`: 변화 어휘(`discovered`, `state_changed`, `metadata_changed`, `value_collected`, `value_changed`, `no_longer_listed`)를 공통 run 두 개 사이의 비교로 계산한다. 로컬 JSON 상태 파일, 파일 잠금, 별도 watcher 프로세스는 만들지 않는다. |
| `cli.py`, `watch_cli.py`, `relations_cli.py`, `api_key_cli.py`, `secret_values_cli.py` | 제품 진입점은 공통 worker와 `/api/v2/coverage`다. 원본 CLI의 출력 계약은 `snapshot.native_snapshots`가 records에서 재구성한다. |
| `tests/` 6개 | `tests/`의 동일 시나리오로 옮기고 공통 adapter 회귀를 추가했다. |

## 연결 계약

| 항목 | 값 |
|---|---|
| provider / origin / edition | `gcp` / `https://googleapis.com` / `cloud` |
| 인증 | `adc` 또는 `workload_identity`. **secret reference를 두지 않는다.** worker의 ADC 주체가 곧 수집 주체다 |
| scope | `project` 한 개. 원본과 같이 `one_project` 범위다 |
| capability | `inventory`(필수), `vault_metadata`, `relations`, `public_keys`, `vault_value`, `issuer_value` |
| 지역 | `options.locations`에 명시한 지역만 수집한다. 공급자가 지원하지 않는 지역을 요청하면 `REQUESTED_LOCATION_NOT_SUPPORTED`로 PARTIAL이 된다 |
| 감사 창 | `options.audit_lookback_days` 1–30일. 지정하지 않으면 24시간 |
| 값 접근 | `options.include_values`와 값 capability를 함께 켤 때만 수행한다 |

`principal_pin`은 거절한다. 실행 중 ADC 주체를 다시 읽지 않으므로 검증하지 않은 고정을 검증으로 표시할 수 없다. 따라서 run contract의 `principal_verified`는 항상 false다.

## 공식 문서에 따라 유지한 제한

- [Service account keys](https://cloud.google.com/iam/docs/keys-create-delete), [`projects.serviceAccounts.keys`](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/list): private key는 생성 응답에만 있다. 목록과 상세는 공개 인증서만 준다. `public_keys` capability를 켠 경우에만 그 인증서를 읽고 `public_key` fact로 남긴다.
- [API Keys API](https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/list): 목록은 key string을 주지 않는다. `getKeyString`은 별도 읽기이며 `issuer_value` capability에서만 호출한다. `showDeleted`는 최근 30일 삭제분이므로 `options.include_deleted`로 분리했다.
- [Secret Manager](https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets/list), [versions.access](https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions/access): 버전 목록과 값 읽기는 서로 다른 권한이다. 버전 값은 불변이므로 새 버전, 상태 변화, 마지막 확인 시각만 변화로 본다. `DISABLED`, `DESTROYED` 버전에는 값 요청을 보내지 않는다.
- [지역 Secret](https://cloud.google.com/secret-manager/docs/regional-secrets-overview): 지역 endpoint는 공급자 응답이 아니라 승인된 지역 문법에서만 만든다.
- [Cloud Audit Logs](https://cloud.google.com/logging/docs/audit), [entries.list](https://cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list): 감사 로그가 꺼져 있거나 보존 기간을 지나면 빈 결과가 온다. 빈 창은 **미사용이 아니라 미확인**이며 모든 operation report에 그 문구를 남긴다.
- [Cloud Monitoring `request_count`](https://cloud.google.com/monitoring/api/metrics_gcp): metric은 지연되며 caller identity를 주지 않는다. `caller_identity`는 항상 `unknown`이다.
- [`getIamPolicy`](https://cloud.google.com/resource-manager/reference/rest/v1/projects/getIamPolicy): allow 정책은 **가능한 접근**이지 실제 접근이 아니다. 조건부 바인딩과 group/domain/allUsers 구성원은 `unconfirmed`로 남기고 `effective_access`는 `not_evaluated`다.

현재 관계 수집은 **global Secret만** 대상으로 한다. 지역 Secret이 인벤토리에 있으면 `REGIONAL_SECRET_RELATIONS_UNSUPPORTED`를 실행 사유로 남긴다.

## 공통 저장 경계

2026-09-22 보완 당시에는 연결·주기 수집·별도 평문 값 저장을 추가했다. 원문 저장은 현재 폐기했으며,
현행 사용법은 [GCP 통합 기술 명세와 사용 설명서](GCP_TOTAL_GUIDE_KO.md)를 따른다.

- 인벤토리 객체는 `principal`, `credential`, `vault_item`, `vault_version`으로 나뉘고 목적은 각각 `issuer_inventory`와 `vault_metadata`다. 일반 PAT를 금고로 분류하지 않는 것과 같은 이유로, 서비스 계정 키와 API key를 금고 항목으로 집계하지 않는다.
- Secret의 `labels`와 `annotations`는 고객이 정한 키와 자유 문구다. 개수만 남기고 `/labels` omission을 기록한다.
- 공통 관리정보 경로에서는 값을 기존 `cremore/detection` 엔진과 `coverage/hasher.py`로 HMAC 지문으로 바꾼다. 2026-09-22 당시에는 GCP의 `store_values=true` 연결이 별도 `gcp_values` 테이블에도 값을 보존하고 관리자 API에서 반환했다(2026-10-02 폐기). `value_match.reference`는 연결 scope의 project로 정규화한다. 읽지 못한 값은 `UNRESOLVED`, 인식하지 못한 payload는 `UNRECOGNIZED_MATERIAL`로 남는다.
- 공급자 상태는 `PROVIDER_REPORTED`다. 이 adapter는 어떤 자격증명도 인증해 보지 않는다.

## 실행과 재개

단계는 `services → service_accounts → service_account_keys → api_keys → secret_manager → secret_manager_locations → secret_manager_regional → secret_versions → values → relations_*` 순서이며, 완료한 단계는 체크포인트의 `done`에 남아 재개할 때 다시 읽지 않는다. 페이지 단위 목록은 page token까지 이어서 재개한다. 재개에 필요한 작업 목록(계정, 금고, 버전, API key)은 체크포인트가 아니라 이미 commit한 typed record에서 복원한다.

429, 회로 차단, 공급자 장애는 부분 결과가 아니라 `WAITING` 페이지와 재시도 시각으로 남긴다. 요청, 페이지, 레코드 한도 도달은 `PARTIAL`이다. 요청 예산은 재시작을 가로질러 합산한다. 연결 설정이 바뀌면 이전 체크포인트를 `GCP_CHECKPOINT_MISMATCH`로 거절한다.

## 검증

```text
python -m pytest cremore/coverage/providers/gcp -q
python -m ruff check cremore/coverage/providers/gcp
```

2026-09-21 Windows Python 3.12 기준 **108개 통과, skip 0**. 합성 transport만 사용했고 실제 GCP 계정, ADC 자격증명, 고객 파일은 사용하지 않았다.

회귀 범위: endpoint 허용 목록과 userinfo/외부 host 거절, 403의 `SERVICE_DISABLED` 구분, 429 재시도와 회로 차단, 요청 예산과 재시도 포함 계산, 취소, page token 순환과 페이지 한도, 잘못된 식별자 계수, 키 종류와 공개키 경계, 지역 Secret의 지역 대조, 버전 상태 3종, CRC 불일치와 과대 payload, 값 지문과 원문 비저장, 참조의 project 정규화, 관계 4종의 근거 구분과 빈 창의 의미, 역할 해석과 조건부 바인딩, native inventory/관계 재구성, 금고별 버전 coverage, 두 run 비교의 `no_longer_listed` 판정과 미완주 source 제외, 중단 후 재개의 레코드 동일성과 요청 합계, 완료한 run의 재요청 없음, 변경된 연결의 체크포인트 거절이다.

실제 기업 GCP 프로젝트, ADC 권한 조합, 감사 로그 활성화 여부, 대시보드 연결은 이 패키지 검증과 구분해서 확인해야 한다.
