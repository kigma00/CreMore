# vault 공급자 소유 영역

신규 Vault는 Community / Enterprise / HCP Vault Dedicated를 인증 전에 선택한다. namespace는
Enterprise/HCP에서만 표시·허용한다. 기존 `self_managed` 연결의 유지보수와 OpenBao namespace 지원은
유지한다. 요금제 선택이 실제 API 접근 권한 확인을 대신하지 않는다.

Vault/OpenBao KV·토큰 소스·원문 해시 수집 구현(전용 UI 없음)을 소유한다. Python 구현과 전용 테스트는 `backend/cremore_vault_provider/`에 있다.
공통 플랫폼이 해당 라이브러리 함수를 직접 호출하며 제품의 Python wheel 하나에 함께 설치된다.

루트에서 `python -m pip install -e ".[dev,gcp]"`로 개발 설치 후
`python -m pytest vault/backend -q`로 전용 합성 회귀를 실행한다.
실제 호출은 별도로 지정한 환경·범위에서만 수행한다.

[공통 AGENTS](../AGENTS.md), [팀 지침](../docs/AI_TEAM_CODING_GUIDE.md),
[실제 디렉터리·등록·빌드 경계](../docs/PROVIDER_DIRECTORY_REVIEW.md)를 먼저 읽는다.
UI 작업에는 [web 지침](../web/AGENTS.md)과 설치된 Next 문서도 적용한다.
공통 API·DB·권한·scope·작업 수명·SIEM 계약과 registry는 플랫폼 담당자와 나누어 작업한다.

## KV 보관과 동적 관리 인벤토리

2026-09-25 공식 문서를 확인한 schema 1 수집 계약이다. 기본 동작은 명시된 namespace·mount·prefix의
KV 최신 값을 연결 자신의 로그인으로 worker가 읽어 지문화하는 것이다(기존 고객 측 CLI 연결은 유지).
`coverage.collect_kv`가 기존 공통 `Collection`·`hash_value`를
재사용하며, 모든 값은 공급자 종류에 관계없이 공통 탐지기에 전달한다. 예를 들어 Vault에 보관한 GitHub
토큰도 GitHub fingerprint가 된다. 반환 observation·API batch에는 비밀 원문을 넣지 않는다.

| 선택 기능 | ConnectionSpec 설정 | 공식 read 계약 및 한계 |
| --- | --- | --- |
| KV v1 최신 값 | 기존 `mounts[].kv_version=1` | 버전 이력이 없다. 과거 버전을 요청하면 `KV1_VERSION_HISTORY_UNSUPPORTED` 근거를 남기며 조용히 최신 조회로 대체하지 않는다 |
| KV v2 특정 버전 | `version_selector="3"`처럼 양의 정수 문자열 | `GET /<mount>/data/<path>?version=3`. 반환 version 일치 여부를 검사한다. 최신 metadata를 추가 확인하지 않은 특정 버전은 CURRENT로 추정하지 않는다 |
| KV v2 과거 버전 | `include_previous_versions=true`, `max_versions_per_secret=20` | `GET /<mount>/metadata/<path>`의 `current_version`·`versions`를 조회하고 최신부터 지정 한도까지 version을 고정해 읽는다. 기본 selector `latest`와만 함께 사용한다 |
| Service-token 관리 목록 | `include_token_accessors=true` | `LIST /auth/token/accessors` → `POST /auth/token/lookup-accessor`. 목록은 `sudo` 및 list, 조회는 해당 endpoint 권한이 필요하다. POST는 metadata 조회이며 생성·갱신·폐기가 아니다 |
| Dynamic lease 관리 목록 | `lease_prefixes=["database/creds/app"]` | `LIST /sys/leases/lookup/<prefix>`를 명시 prefix 아래에서 순회한 뒤 `POST /sys/leases/lookup`을 호출한다. list에는 `sudo`가 필요하며 lookup 권한은 별도다 |

KV2의 soft-deleted/destroyed 버전은 `UNRESOLVED`와 `DELETED`/`DESTROYED`를 보존한다.
이력 metadata에서 확인된 버전은 값 요청을 생략하고, 최신·특정 버전 read의 404도 응답의
version·삭제 metadata로 확인되면 `VERSION_UNAVAILABLE`로 남긴다. 값·custom metadata는 보관하지 않는다.
미래 `deletion_time`은 예약된 삭제일 수 있어 이미 삭제됐다고 판정하지 않는다. 서버의
`max_versions` 정책으로 사라진 과거 버전은 복원할 수 없다. metadata 권한 부족, 특정 version read 거절,
버전 한도·공통 요청/레코드 한도는 불완전 수집 근거로 남긴다. 수집은 원자적 provider snapshot이 아니므로
읽는 동안 버전·권한이 바뀔 수 있다. 현재/과거 구분은 조회 시점의 공급자 metadata에 근거한다.

관리 목록은 `MANAGED` evidence이며 `vault_managed.kind`가 `SERVICE_TOKEN` 또는 `DYNAMIC_LEASE`다.
이는 KV 보관 값 일치(`VALUE`)도 외부 SaaS 발급 전체 목록(`ISSUED`)도 아니다. 다음 필드만 선택한다:
공급자가 반환한 issue/expiry 시간, RFC3339 `last_renewal`(Unix 초인 `last_renewal_time`은 사용하지 않음),
TTL, renewable, service-token policy 이름.
TTL에서 현재 활성 여부나 만료 시간을 만들어내지 않으며 `state`·`version_state`는 `UNKNOWN`이다.
응답의 token ID·password·임의 meta·raw response는 버린다. accessor와 lease ID는 관리 참조로 보존하므로
일반 로그로 흘리지 않고 관리자용 inventory 경계에서 취급해야 한다.

`MANAGED`의 `reference`는 token의 경우 `auth/token/accessors/<accessor>`이고 `mount=auth/token`이다.
lease는 `reference=<lease_id>`, `mount=<첫 경로 구성요소>`다. namespace는 승인된 `spec.namespaces`와
일치해야 하고 lease ID는 `lease_prefixes` 하위여야 한다. 목록에 보였지만 lookup이 실패한 handle은
`vault_managed.lookup_status=FAILED`와 고정 reason으로 보존한다(관리 행은 `UNKNOWN`).
실패한 lookup에는 시간·TTL·policy를 넣지 않는다. 목록 자체가 거절됐으면 빈 성공으로 처리하지 않는다.
LIST(GET의 `list=true` 포함)가 404와 `{"errors":[]}`를 반환한 경우만 빈 목록으로 처리한다.
존재하지 않는 mount의 `no handler for route` 등 오류 메시지가 있는 404·권한 거절·잘못된 응답은
수집 실패로 유지한다. 기존 mount 안의 빈 접두어와 존재하지 않는 접두어는 이 LIST 응답만으로 구별할 수 없다.
관리 LIST 실패는 `TOKEN_ACCESSOR_LIST_FAILED`·`LEASE_LIST_FAILED`, lookup 실패는
`TOKEN_ACCESSOR_LOOKUP_FAILED`·`LEASE_LOOKUP_FAILED` 실행 코드로 구분한다. 개별 lookup의 구체적인
고정 오류 코드는 해당 `MANAGED` 행에 남긴다. 이 관리 범위의 실패를 KV 부재 근거로 사용하지 않는다.

Batch token은 서버에 개별 저장되지 않고 accessor도 없으므로 전수 목록을 조회할 수 없다.
accessor 수집에는 `BATCH_TOKEN_INVENTORY_UNSUPPORTED` 근거를 항상 남긴다. Service-token 목록이
성공해도 전체 token inventory가 완전하다고 선언하지 않는다. 관리 기능은 기본 비활성이다.
수집기 자체는 KV mount 없이 명시한 management scope만 받을 수 있지만, 연결 마법사는 관리 옵션을 켜도
KV mount를 하나 이상 요구한다(`VAULT_MOUNT_REQUIRED`). 수집기는 mount/namespace를 자동 발견하지 않으며
실제 lease 발급·갱신·폐기도 하지 않는다.

공통 계약은 `cremore/coverage/models.py`, KV는 `coverage.py`, HTTP는 `inventory_http.py`,
accessor·lease는 `managed_inventory.py`가 소유한다. 동일 요청/레코드 예산·취소 callback을 공유하고
redirect를 따르지 않는다. 고객 측 기존 CLI는 서버에서 받은 ConnectionSpec의 옵션을 그대로 전달한다.
따라서 별도 CLI 명령/서버/DB 테이블을 추가하지 않는다.

기존 연결의 호환 경로로, `endpoint`가 설치의 `SECRET_STORE_URL`과 같고 관리자가 `server_collection=true`를
켜며 연결 자신의 `server_auth`가 없으면 worker가 같은 `collect_kv`를 설치의 기존 비밀 저장소
신원(`kv_from_settings`: 토큰 또는 Kubernetes 인증)으로 실행한다. 신규 연결 설정은 이 경로를 쓰지 않는다.
그 신원은 같은 주소에만 보내고 연결·DB·job에 저장하지 않으며, 주소가 다르면 요청 없이
`VAULT_SERVER_IDENTITY_NOT_CONFIGURED`로 실패한다. 그 신원의 정책에 승인한 마운트·접두사의 읽기
(`list`·`read`, KV v2 `metadata`)만 추가한다. `schedule_minutes`(5분 이상)를 정하면 설치의 스케줄 허용
설정(`scan_schedules_allowed`)이 켜져 있는 동안 그 간격으로 수집하며, 수동 수집도 다음 주기를 늦춘다.
신규 Vault·OpenBao 연결은 worker가 연결 자신의 로그인(`kubernetes`·`jwt`·`token`)으로 읽는 서버 수집만
설정할 수 있다(`server_auth`, `connection_login.py`). 고객 측 CLI(`customer_cli`)는 기존 연결만 유지하며,
새 연결에 선택하면 `AUTH_METHOD_RETIRED_FOR_NEW_CONNECTIONS`로 거절된다. Kubernetes·JWT 로그인은
`VAULT_CONNECTION_TOKEN_DIR` 안의 파일 이름만
받고(디렉터리 밖 실제 경로·설치 자신의 토큰 파일은 거절), 토큰 로그인은 API로 봉인한 값을 연다. TLS는 연결의
`tls_ca_pem`이 있으면 그 CA만 신뢰하고 리다이렉트는 따르지 않는다. 이때 설치의 비밀 저장소 신원은 같은 주소라도
쓰지 않는다. 사용법은 [범용 금고 문서](../docs/EXTERNAL_VAULT.md#6-다른-vaultopenbao-클러스터의-서버-읽기)를 따른다.

연결 마법사의 권한 점검(`sys/capabilities-self`)은 수집이 실제로 묻는 경로에서 확인한다. 목록은 접두어 끝에 `/`를 붙인
경로(`secret/metadata/team-a/`, 마운트 전체면 `secret/metadata/`)다. Vault가 목록 요청을 그 경로로 판단하므로 정책은
`path "secret/metadata/team-a/*" { capabilities = ["list"] }`처럼 접두어에 건다([정책](https://developer.hashicorp.com/vault/docs/concepts/policies)).
대상 조회에는 `sys/mounts`의 `read`가 필요하다. 옵션을 켜면 그 옵션이 읽는 곳도 점검해 활성화를 막는다:
- 이전 KV 버전: `<마운트>/metadata/<접두어>/*`의 `read`;
- 서비스 토큰 accessor: `auth/token/accessors`의 `sudo`·`list`와 `auth/token/lookup-accessor`의 `update`(Vault는 이 권한을 엄격히 통제하라고 권고);
- lease 접두어: `sys/leases/lookup/<접두어>/`의 `sudo`·`list`와 `sys/leases/lookup`의 `update`.
루트 권한으로 읽히면 로그인 항목에 `ROOT_TOKEN_NOT_RECOMMENDED`를 붙인다. 읽기 전용 정책의 토큰을 쓴다. CreMore는 토큰을
갱신하지 않으므로 토큰 방식은 TTL이 끝나면 멈춘다(서버 읽기는 Kubernetes·JWT 로그인을 권장).
플랫폼은 MANAGED를 VALUE 매칭·금고 부재 판정에서 분리하여 소비한다. 관리 범위의 실행 코드
(`BATCH_TOKEN_INVENTORY_UNSUPPORTED`, accessor·lease의 목록·lookup 실패, 중복 식별자)는 실행 reasons와
관리 행에 남지만 KV 실행의 상태·완전성 근거(`API_LISTING`)·금고 범위 차단 사유에는 쓰지 않는다
(`cremore/coverage/store.py`의 `VAULT_MANAGEMENT_REASONS`). schema 1의 선택적 `provider_digest`는 GitHub VALUE 전용 private HMAC 비교 근거이며,
생성·매칭·API 비공개 처리는 공통 hasher/플랫폼이 소유한다. 원래 fingerprint 계약은 유지된다.

공식 근거(위 날짜 HTTP 200 확인):

- [Vault KV v2](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2), [OpenBao KV v2](https://openbao.org/docs/api/secret/kv/kv-v2/)
- [Vault token API](https://developer.hashicorp.com/vault/api-docs/auth/token), [OpenBao token API](https://openbao.org/docs/api/auth/token/)
- [Vault leases API](https://developer.hashicorp.com/vault/api-docs/system/leases), [OpenBao leases API](https://openbao.org/docs/api/system/leases/)
- [Vault token 모델](https://developer.hashicorp.com/vault/docs/concepts/tokens), [OpenBao token 모델](https://openbao.org/docs/concepts/tokens/)

실제 서버·namespace별 ACL·제품 버전·Enterprise 라이선스 조건은 합성 테스트로 검증되지 않는다.
코드 검증은 fake HTTP로 수행하며, 노출된 자격증명을 로그인·검증 요청에 재사용하지 않는다.
