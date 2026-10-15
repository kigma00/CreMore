# 범용 금고 연결과 다른 Vault 클러스터의 서버 읽기

CreMore가 기본 수집기를 갖지 않은 금고(CyberArk, Delinea, 1Password, Doppler, Akeyless, Bitwarden,
Keeper, Infisical, 쿠버네티스 Secret, SOPS 파일 등)도 노출 결과와 대조한다. 기존 금고 대조와 같은
고객 환경 해셔를 쓰므로 값은 고객 환경에서 지문(HMAC)으로 바뀌고 원문은 보내지 않는다.
설계 근거는 [통합 운영 설계 4.7절](CONTINUOUS_OPERATIONS_DESIGN.md#47-범용-금고-연결)과 결정 9·10이다.

## 1. 부재 판정의 근거 수준

"금고에 없음"은 대조 범위의 모든 금고가 선언 범위를 빠짐없이 읽었을 때만 나온다. 금고마다 그것을 아는
방법이 다르며, 판정에는 범위 안에서 가장 약한 근거가 붙는다(`absence_basis`).

| 근거 | 뜻 | 쓰는 곳 |
| --- | --- | --- |
| `API_LISTING` | 기본 수집기가 금고 API로 목록을 끝까지 읽었다 | AWS Secrets Manager(목록을 읽는 수집)·SSM, Vault·OpenBao, GCP Secret Manager(목록을 읽는 수집), 관리정보 연결의 값 읽기 |
| `READER_REPORTED` | 설치한 읽기 플러그인이 자기 목록을 끝까지 읽었다고 보고했다 | `reader`를 지정한 외부 금고 |
| `OPERATOR_DECLARED` | 운영자가 선언 범위를 모두 내보냈거나 정했다고 확인했다 | JSON Lines 입력 외부 금고, 운영자가 적은 시크릿만 읽는 AWS·GCP Secret Manager 수집(`references`, AWS 값 읽기 역할 포함. 목록을 읽지 않는다) |

운영자가 확인하지 않은 JSON Lines 실행은 `COMPLETENESS_NOT_DECLARED`로 `PARTIAL`이 되고 부재 판정은
`UNKNOWN`으로 남는다. 선언 범위 밖의 항목은 읽지도 보내지도 않으며 CLI 결과의 `outside_declared_scope`
개수로만 알려 준다. 검출기가 이름을 붙이지 못한 값(예: DB 비밀번호)은 기존 금고와 똑같이 불투명 지문으로
대조하고 `UNRECOGNIZED_MATERIAL`로 실행을 `PARTIAL`로 만든다.

## 2. 외부 금고 연결 등록

Admin이 공급자 연결 마법사([공급자 연결](ONBOARDING.md))로 `external_vault`를 연결한다. 4단계 응답의
`collector_token`은 한 번만 나오며 고객 환경 CLI에만 넣는다.

```http
POST /api/v1/provider-connections
{"provider": "external_vault", "name": "플랫폼팀 1Password", "purposes": ["vault"], "auth_method": "jsonl",
 "target": {"product": "1Password", "prefixes": ["prod", "shared/ci"]}}

POST /api/v1/provider-connections/{id}/check
POST /api/v1/provider-connections/{id}/activate   {"purposes": {"vault": {}}}
```

| 필드 | 설명 |
| --- | --- |
| `target.product` | 제품 이름(자유 입력, 필수). 표시용이며 대조 방식은 바꾸지 않는다 |
| `target.prefixes` | 선언 범위. 경로 접두사 목록이며 `""` 하나는 내보낸 전체를 뜻한다 |
| `auth_method` | `jsonl`이면 JSON Lines 입력, `reader`면 `credential.reader`에 적은 읽기 플러그인으로만 읽는다 |

예산·신선도(`max_records`, `max_value_bytes`, `freshness_hours`)는 만들어진 수집 연결을 PATCH로 바꾼다.

등록한 금고는 다른 금고처럼 대조 범위 확인(`PUT /api/v1/coverage/scope`) 대상이 된다.

## 3. JSON Lines 입력

한 줄에 JSON 객체 하나를 쓴다. 다른 키가 있거나 형식이 틀린 줄은 내용을 출력하지 않고
`INPUT_LINE_INVALID`로 세며, 실행은 `PARTIAL`이 된다.

| 키 | 필수 | 형식 |
| --- | --- | --- |
| `path` | 예 | 금고 안 경로. `/`로 나누며 `.`·`..`·역슬래시는 쓸 수 없다 |
| `value` | 예 | 문자열, 또는 문자열 값만 가진 객체(한 항목의 여러 필드) |
| `version` | 아니요 | 버전 문자열(256자 이하) |
| `updated_at` | 아니요 | 시간대가 있는 ISO 8601 시각 |
| `state` | 아니요 | `CURRENT`(기본) 또는 `PREVIOUS` |

같은 `path`·`version`이 두 번 나오면 둘 다 금고의 값이라고 볼 수 없어 `INPUT_DUPLICATE_ENTRY`로 표시한다.

```bash
export CREMORE_COLLECTOR_TOKEN=...   # 연결 등록 응답의 collector_token
export FINGERPRINT_KEY=...           # 설치의 지문 키(16진수)
cremore-coverage --api-url https://cremore.example.com --connection-id <연결 ID> \
  --input export.jsonl --declare-complete
```

`--input -`는 표준 입력을 읽는다. 내보내기 결과를 파일로 남기지 않으려면 파이프로 넘기고, 쓴 파일이
있으면 실행 후 지운다. `--declare-complete`는 이 입력이 선언 범위의 전부일 때만 붙인다.

## 4. 제품별 내보내기

아래 명령은 각 제품의 공식 문서·소스로 확인했다(2026-09-28). 출력은 모두 `jq -c`로 위 형식의 한 줄
객체로 바꾼다. 선언 범위와 같은 경로 접두사가 되도록 `path` 앞부분을 정한다.

| 제품 | 내보내기 | 변환 |
| --- | --- | --- |
| Doppler | `doppler secrets download --no-file --format json -p <프로젝트> -c <config>` ([CLI](https://docs.doppler.com/docs/cli)) | `jq -c 'to_entries[] \| {path: ("<프로젝트>/<config>/" + .key), value}'` |
| Infisical | `infisical export --env=prod --path=/ --format=json` ([export](https://infisical.com/docs/cli/commands/export)). 배열 원소는 `key`·`value`·`secretPath`를 가진다 | `jq -c '.[] \| {path: ("prod" + .secretPath + "/" + .key \| gsub("/+"; "/")), value}'` |
| Bitwarden Secrets Manager | `bws secret list <프로젝트 ID> --output json` ([bws](https://bitwarden.com/help/secrets-manager-cli/)). 원소는 `key`·`value`·`projectId`·`revisionDate`를 가진다 | `jq -c '.[] \| {path: (.projectId + "/" + .key), value, updated_at: .revisionDate}'` |
| 1Password | `op item list --vault <볼트> --format json`의 각 `id`에 `op item get <id> --vault <볼트> --reveal --format json` ([op item](https://www.1password.dev/cli/reference/management-commands/item)) | `jq -c '{path: ("<볼트>/" + .title), value: ([.fields[] \| select(.value != null) \| {(.label): .value}] \| add), version: (.version \| tostring), updated_at}'` |
| Akeyless | `akeyless list-items --path /prod --json`의 각 정적 비밀에 `akeyless get-secret-value --name <이름>` ([CLI](https://docs.akeyless.io/docs/cli-reference)) | 이름에서 앞 `/`를 뺀 값을 `path`, `last_version`을 `version`, `modification_date`를 `updated_at`으로 |
| CyberArk Conjur | `conjur list -k variable`의 각 ID에 `conjur variable get -i <ID>` ([conjur-cli-go](https://github.com/cyberark/conjur-cli-go)) | 변수 ID의 경로 부분을 `path`로 |
| Delinea DevOps Secrets Vault | `dsv secret search -q <접두사> --limit <n>`(`--cursor`로 다음 쪽)의 각 경로에 `dsv secret read --path <경로> -e json` ([secret](https://docs.delinea.com/online-help/devops-secrets-vault/usage/cli-ref/secret.htm)) | `path`, `data`를 `value`, `version`, `lastModified`를 `updated_at`으로 |
| Keeper | Commander `export --format json` ([내보내기](https://docs.keeper.io/en/keeperpam/commander-cli/command-reference/import-and-export-commands), [JSON 형식](https://docs.keeper.io/en/keeperpam/commander-cli/command-reference/import-and-export-commands/json-import)) | `jq -c '.records[] \| {path: ("keeper/" + .title), value: ({password, login} + (.custom_fields // {}) \| with_entries(select(.value \| type == "string")))}'` |
| 쿠버네티스 Secret | 내장 읽기 플러그인 `kubernetes_secrets`를 쓴다(5절) | — |
| SOPS 파일 | `sops decrypt --output-type json secrets.enc.yaml` ([사용법](https://getsops.io/docs/usage/common-operations/), [고급](https://getsops.io/docs/usage/advanced/)) | `jq -c 'to_entries[] \| {path: ("sops/secrets/" + .key), value: (.value \| tostring)}'` |

여러 명령을 이어 붙이는 제품은 목록이 끝까지 나왔는지(페이지·권한 거절)를 운영자가 확인한 뒤에만
`--declare-complete`를 붙인다. 목록 명령이 권한 부족으로 일부만 돌려준 경우는 선언하지 않는다.

## 5. 읽기 플러그인

설치형 패키지가 특정 금고를 직접 읽게 한다. SIEM 출력 플러그인과 같은 방식이다.

- entry point 그룹은 `cremore.vault_readers`, 이름은 `[a-z][a-z0-9_-]{0,63}`이다. 목록을 볼 때는 플러그인
  코드를 실행하지 않는다.
- 내장 읽기 플러그인이 아니면 `CREMORE_VAULT_READERS`(쉼표 구분)에 이름이 있을 때만 불러온다.
  없으면 `VAULT_READER_NOT_ENABLED`로 실행을 `FAILED`로 닫는다. 비신뢰 코드를 격리하는 장치는 아니다.
- entry point는 `ReaderProvider(id, api_version=1, build)`를 `PROVIDER`로 내보낸다. `build(options)`가 돌려준
  객체의 `entries(prefixes)`는 `VaultEntry(path, value, version, updated_at, state)`를 내고, 다 읽은 뒤
  `complete`로 선언 범위를 끝까지 나열했는지 알린다. 연결의 `reader`와 같은 플러그인만 쓴다.
- 플러그인의 예외 문구는 내보내지 않고 `READER_FAILED`로만 남긴다. 목록이 끝나지 않았으면
  `READER_LISTING_INCOMPLETE`다. 선택값은 `--reader-option KEY=VALUE`로 준다.

내장 `kubernetes_secrets`는 고객의 `kubectl`로 `kubectl get secrets -o json`을 실행한다([Secret](https://kubernetes.io/docs/concepts/configuration/secret/)).
선언 범위의 접두사는 네임스페이스(`prod`) 또는 네임스페이스/Secret(`prod/db`)이고, `""`는
`--all-namespaces`다. 항목 경로는 `네임스페이스/Secret/키`, 버전은 `resourceVersion`이다. 네임스페이스 하나라도
RBAC가 거절하면 빈 목록이 아니라 불완전한 목록이다. 선택값은 `context`와 `kubectl`(실행 파일 경로)뿐이다.

```bash
cremore-coverage --api-url https://cremore.example.com --connection-id <연결 ID> --reader-option context=prod-cluster
```

## 6. 다른 Vault·OpenBao 클러스터의 서버 읽기

신규 Vault·OpenBao 연결은 worker가 연결 자신의 로그인(`kubernetes`·`jwt`·`token`)으로 읽는 서버 수집만 설정할 수 있다.
고객 환경 CLI(`customer_cli`)는 기존 연결만 유지하며, 신규 연결에서는 `AUTH_METHOD_RETIRED_FOR_NEW_CONNECTIONS`로 거절된다.
설치의 비밀 저장소 신원은 이 연결에 쓰지 않으며, 같은 주소라도 연결 자신의 로그인을 쓴다. 공급자 연결 마법사에서 인증
방식으로 로그인을 고르고, 관리 옵션(토큰 accessor·lease)을 켜도 KV mount를 하나 이상 고른다(`VAULT_MOUNT_REQUIRED`).

```json
{"provider": "vault", "name": "결제 클러스터", "purposes": ["vault"], "auth_method": "kubernetes",
 "target": {"address": "https://vault-pay.example.com", "mounts": ["secret"], "kv_version": "2",
            "prefixes": ["payments"], "tls_ca_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"},
 "credential": {"role": "cremore-reader", "token_file": "vault-pay"}}
```

4단계 계획은 `schedule_minutes`, `previous_versions`·`max_versions`(KV v2), `token_accessors`, `lease_prefixes`다.

| 인증 방식 | 로그인 | 준비 |
| --- | --- | --- |
| `kubernetes` | `POST /v1/auth/<mount>/login`에 역할과 서비스 계정 토큰 ([쿠버네티스 인증](https://developer.hashicorp.com/vault/api-docs/auth/kubernetes)) | 그 클러스터를 audience로 한 projected 토큰을 `VAULT_CONNECTION_TOKEN_DIR/<token_file>`에 마운트 |
| `jwt` | `POST /v1/auth/<mount>/login`에 역할과 JWT ([JWT 인증](https://developer.hashicorp.com/vault/api-docs/auth/jwt)) | IdP 토큰 갱신기나 projected 토큰이 같은 디렉터리의 파일을 최신으로 유지 |
| `token` | 봉인된 토큰 | `credential.token`. 도착 즉시 봉인하고 응답하지 않는다. `vault://` 참조는 받지 않는다(`CREDENTIAL_REFERENCE_NOT_ALLOWED`). 바꿀 때는 `PUT /api/v1/provider-connections/{id}/credential` |

- 연결은 파일 경로가 아니라 `VAULT_CONNECTION_TOKEN_DIR` 안의 **파일 이름**만 가진다. 실제 경로가 그 디렉터리
  밖을 가리키면(심볼릭 링크 포함) `VAULT_CONNECTION_TOKEN_FILE_OUTSIDE_DIRECTORY`, 설치 자신의 로그인
  토큰 파일이면 `VAULT_CONNECTION_TOKEN_FILE_REFUSED`, 디렉터리 설정이 없으면
  `VAULT_CONNECTION_TOKEN_DIR_NOT_CONFIGURED`로 요청 없이 실패한다.
- `namespace`는 Vault Enterprise 네임스페이스 안의 인증 마운트에 로그인할 때 쓴다.
- TLS는 항상 검증한다. `tls_ca_pem`이 있으면 그 CA만 신뢰한다(인증서만 받으며 개인 키는 거절). 리다이렉트는
  따르지 않는다.
- 수집 연결 수정(PATCH) 본문으로 다른 `secret_refs`나 `server_auth`를 보낼 수 없다
  (`CREDENTIAL_BELONGS_TO_PROVIDER_CONNECTION`). 생략하거나 조회 화면의 `configured`를 그대로 돌려주면 기존 값을 유지한다.
- Vault 정책은 승인한 마운트·접두사의 `read`·`list`(KV v2는 `metadata`)만 준다. 예:

```hcl
path "secret/data/payments/*"     { capabilities = ["read"] }
path "secret/metadata/payments/*" { capabilities = ["list", "read"] }
```

설치 자신의 비밀 저장소를 읽는 기존 방식(`server_auth` 없음, 주소가 `SECRET_STORE_URL`과 같음)은 그대로다.

## 7. 확인한 범위

합성 테스트(`cremore/coverage/external_vault_test.py`)로 요청 본문에 원문이 없음, 선언 없는 실행은 부재를 확정하지
않음, 선언한 실행의 `OPERATOR_DECLARED` 근거, 금고 여럿의 가장 약한 근거, 플러그인 로드와 허용 목록 밖 거절,
연결 자신의 로그인·설치 신원 미사용·디렉터리 밖 토큰 파일 거절·리다이렉트 미추종·연결 CA를 검증한다.
실제 제품(CyberArk, 1Password 등)과 실제 Vault 클러스터·쿠버네티스 인증은 실환경 검증 항목이다.
