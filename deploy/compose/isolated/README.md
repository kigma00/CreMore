# 격리 Compose 배포

이 디렉터리의 `compose.yml` 하나로 API, 수집 worker, 조치 worker, 제어 worker, SIEM,
web, OIDC proxy, TLS gateway를 실행한다. DB는 별도로 관리하는 PostgreSQL 16 이상이다.
기존 `docker-compose.yml`, public/identity/secret-store overlay와 **합치지 않는다**.
예전 overlay의 공용 DB·키·클라우드 신원 mount가 강화 경계를 다시 합칠 수 있다.

이 배포는 호스트의 Linux 컨테이너를 대상으로 한다. 렌더 통과는 방화벽, 실제 OIDC 로그인,
공급자 권한·갱신, SIEM 수신이 검증되었다는 뜻이 아니다. 운영자 네트워크 인수 조건은
[NETWORK_CONTRACT.md](NETWORK_CONTRACT.md)에 있다. 이 조건을 적용할 수 없다면 배포하지 않는다.

## 역할과 신뢰 경계

| 프로세스 | DB 로그인 | 가진 비밀 / 읽기 전용 파일 | 허용된 외부 목적 |
| --- | --- | --- | --- |
| API | API 전용 | 공개 recipient 정책, 제어 봉인 키, 승인 **공개** 검증 키 | DB, IdP/JWKS, 승인된 제어 OAuth 교환 |
| collector | collector 전용 | collector 개인키, collector 클라우드 신원 | 승인된 수집·신원 갱신·DB |
| remediator | remediator 전용 | remediator 개인키·클라우드 신원, 승인 **공개** 검증 키 | 승인된 조치·신원 갱신·DB |
| control | control 전용 | 제어 봉인 키, 공개 recipient 정책 | DB, 설정한 티켓 시스템 |
| SIEM | SIEM 전용 | 목적지 전용 token 또는 TLS 인증서 | DB, 지정된 외부 수신기·그 token endpoint |
| migrate | migration 전용 | DB CA만 | 유지보수 시 DB |
| web | 없음 | 없음 | 내부 API |
| oauth2-proxy | 없음 | OIDC client/cookie secret | 내부 web, IdP |
| gateway | 없음 | 서버 TLS 인증서와 개인키 | 내부 OIDC proxy, HTTPS 응답 |

기존 지문·감사 계약 때문에 API와 세 worker는 같은 `FINGERPRINT_KEY`와 `AUDIT_CHAIN_KEY`를
가진다. connector 복호화 키는 역할별로 나뉜다. 독립 승인 서명 개인키는 이 호스트 밖에서 관리하며,
어느 컨테이너에도 주지 않는다. API가 enqueue 전 검증하고 remediator가 실행 전 다시 검증한다.
수집 worker는 조치 작업을 실행하지 않는다. 제어 worker는 클라우드 신원을 갖지 않는다.

모든 서비스는 UID/GID `65532:65532`, read-only rootfs, `cap_drop: ALL`,
`no-new-privileges`, 제한된 tmpfs로 실행한다. gateway의 8443만 호스트 443에 게시한다.
Docker socket, host network/PID, 호스트 home, 공용 credential 디렉터리를 mount하지 않는다.
DB 테이블 권한은 [PostgreSQL 역할 분리](../../postgres/README.md)를 따른다.

**호스트 root·Docker 관리자·배포 secret 파일 관리자는 신뢰 주체다.** 같은 호스트의 컨테이너
분리는 이 관리자의 파일/메모리/환경 조회나 컨테이너 재구성을 막지 않는다. UID가 같다는 것은
서로의 파일을 공유해도 된다는 뜻이 아니다. 파일 ACL·서로 다른 mount 원본·별도 DB/클라우드
신원을 유지한다. Docker inspect와 Compose 렌더는 환경변수 secret을 드러낼 수 있다.
DB에 허용된 상태 쓰기, API 제어 비밀, 그 역할에 승인된 외부 접근의 위험도 남는다.

## 파일과 환경 준비

1. 같은 소스 revision에서 만든 검토된 Python/web/OIDC 이미지를 준비한다. 이 revision은
   `ISOLATED_DEPLOYMENT`, 실행 역할, 공개키 봉인, 독립 승인, DB startup 검사를 지원해야 한다.
   Python은 기존 [Dockerfile](../../docker/python.Dockerfile), OIDC proxy는 기존
   [Dockerfile](../../docker/oauth2-proxy.Dockerfile), web은 [Dockerfile](../../../web/Dockerfile)을 쓴다.
   Caddy 2의 검토된 digest도 정한다. repo와 64자리 SHA-256을 따로 입력하므로 가변 tag로 실행하지 않는다.
2. [.env.example](.env.example)을 저장소 밖의 `/etc/cremore-isolated/isolated.env` 등으로 복사한다.
   배포 관리자만 읽도록 `0600`으로 보호한다. 모든 빈 필수 값과 예시 주소·비밀번호를 바꾼다.
   비밀번호는 URL 인코딩하며 `$` 등이 있는 dotenv 값은 single quote로 감싼다.
   Compose 자체를 실행하는 셸의 같은 이름 변수는 env 파일보다 우선하므로 오염 없는 배포 세션을 쓴다.
3. 파일 경로는 **Docker daemon 호스트의 절대 경로**다. 모든 bind는 읽기 전용이고 누락된 경로를
   자동 생성하지 않는다. Linux에서 root 소유·group `65532`의 디렉터리 `0750`, 비밀 파일 `0640`처럼
   컨테이너 UID가 읽되 쓰지 못하게 준비한다. 공개 파일도 무결성을 보호한다. Windows bind에서
   Linux permission 검증을 대신하지 않는다. custom CA가 필요한 IdP/공급자는 검토된 이미지의
   시스템 trust store에 CA를 넣는다. TLS 검증을 끄지 않는다.
4. gateway TLS 디렉터리에는 `fullchain.pem`, `privkey.pem`을 넣는다. `PUBLIC_HOST`는 scheme/port/path
   없는 인증서 hostname이다. `PUBLIC_BIND_IP`의 기본 예시는 loopback이므로 외부 공개 시 승인된 host
   interface로 바꾼다. 자동 ACME·HTTP port·Caddy admin API는 꺼져 있다. 운영자가 인증서를 갱신하고
   gateway를 재생성한다. HTTP redirect도 없으므로 사용자는 `https://`로 접속한다.
5. OIDC 앱 callback을 `https://<PUBLIC_HOST>/oauth2/callback`으로 등록한다. client secret과
   32 random bytes의 base64url cookie secret은 proxy만 받는다. API는 issuer/JWKS/audience/expiry를
   직접 검증하고 그룹을 역할로 매핑한다. `API_TOKEN`/`CREMORE_API_TOKEN`은 비어 있다.
   공개 issuer/audience/그룹 설정은 worker에도 전달해 로그인 IdP 검사·그룹 동기화가 같은 계약을 쓴다.
   IdP에 따라 `OIDC_SCOPES`, 그룹 claim·역할 그룹을 설정한다. 그룹 claim 없는 Google 로그인은 기존
   [로그인 IdP 그룹 계약](../../../docs/LEAVER_CHECK.md)을 따라 Workspace 신원 수집도 구성한다.

공개 recipient 정책은 `version: 1`, `recipients` 목록을 가진 JSON이다. 각 항목에
`purpose`(`collector` 또는 `remediator`), `provider`, 정규화된 `authority`, RSA 공개 PEM의
`public_keys` 목록을 둔다. private JSON은 `{"version":1,"private_keys":[...]}`이고 해당 역할에
배정된 RSA 개인 PEM만 넣는다. 키는 RSA 3072 bit 이상, purpose/provider/authority마다 별개다.
정확한 binding은 [현재 구현](../../../cremore/secretstore/isolation.py)의 `credential_binding`과
공급자 descriptor에서 도출한다. 임의 tenant/host 추측이나 wildcard 항목을 쓰지 않는다.
이 파일들은 운영자가 오프라인 키 관리로 준비한다. API에는 private JSON을 주지 않는다.

`REMEDIATION_APPROVAL_PUBLIC_KEY_PATH`는 그 정책의 RSA 키와 다른 **Ed25519 public PEM**이다.
오프라인 승인자만 서명 개인키를 가진다. 키 교체나 recipient 정책 변경 후에는 해당 프로세스를
재시작하고 성공·거부 경로를 확인한다. 기존 봉인 데이터가 있으면 먼저 정지·backup 후
[봉인 이관](../../../cremore/secretstore/migrate.py)을 수행한다. 기존 설치의 fingerprint/audit 키를
새 예시 키로 덮어쓰지 않는다. schema 이관만으로 봉인 데이터가 전환되지는 않는다.

## 역할별 클라우드 신원과 갱신

`COLLECTOR_CLOUD_IDENTITY_DIR`와 `REMEDIATOR_CLOUD_IDENTITY_DIR`는 **서로 다른 원본 디렉터리**다.
각 컨테이너에는 자신의 디렉터리만 `/run/cloud-identity`로 보인다. cloud를 사용하지 않는 역할도
빈 전용 디렉터리를 준비할 수 있다. 사용하지 않는 공급자 파일을 넣을 필요는 없다.
root home, `~/.aws`, 관리자의 개인 ADC, 같은 클라우드 주체를 두 역할에 공유하지 않는다.

| 방식 | 각 역할 디렉터리의 파일 / 환경 입력 |
| --- | --- |
| AWS projected web identity | `aws/token`; 역할별 `*_AWS_ROLE_ARN`, `*_AWS_WEB_IDENTITY_TOKEN_FILE=/run/cloud-identity/aws/token` |
| AWS Roles Anywhere | `aws/config`, `aws/roles-anywhere.json`, `aws/certificate.pem`, `aws/private.pem`, `bin/aws_signing_helper`; `*_AWS_ROLES_ANYWHERE_CONFIG=/run/cloud-identity/aws/roles-anywhere.json` |
| GCP ADC/WIF | `gcp/adc.json`; WIF `credential_source.file`은 `/run/cloud-identity/gcp/token` 같은 이 디렉터리의 projected JWT를 지정 |
| Azure projected identity | `azure/token`; 서로 다른 `*_AZURE_CLIENT_ID`와 필요한 `*_AZURE_TENANT_ID` |
| Vault audience token | collector의 `vault/<connection token filename>`; 연결 자신의 audience/역할로 발급 |

AWS는 metadata 조회가 꺼지고 shared credentials 파일은 `/dev/null`이다. AWS 설정은
`/run/cloud-identity/aws/config`의 `[default]`를 사용한다. Roles Anywhere의 설정은 다음과 같다.

```ini
[default]
region = ap-northeast-2
credential_process = /app/venv/bin/python -m cremore_aws_provider.roles_anywhere --config /run/cloud-identity/aws/roles-anywhere.json
```

[기존 Roles Anywhere JSON](../identity/roles-anywhere.example.json)의 `helper`를
`/run/cloud-identity/bin/aws_signing_helper`로, certificate/private_key도 위 경로로 바꾸고 검증된
helper SHA-256과 역할별 trust anchor/profile/role ARN을 넣는다. helper는 해당 Linux 아키텍처용
실행 파일이어야 한다(`0750` 등). AWS projected identity의 두 환경변수는 이 방식에서는 비운다.

외부 issuer/refresher가 projected JWT와 인증서를 만료 전에 갱신해야 한다. 이 Compose에는
두 역할의 발급 신원을 공유하는 refresher를 넣지 않는다. 같은 디렉터리 안의 파일을 원자적으로
교체하며 mount 원본 디렉터리 자체는 교체하지 않는다. 디렉터리를 mount하므로 다음 SDK 갱신이
새 파일을 읽을 수 있다. 신원 발급·갱신 실패가 다른 신원으로 대체되지 않도록 host/metadata egress도
차단한다. 실제 24시간 갱신·만료/실패 복구는 각 공급자의 허용된 환경에서 별도 인수한다.

## DB·SIEM과 실행 순서

DB CA bundle을 `DATABASE_CA_PATH`로 제공한다. 여섯 DB URL은 같은 전용 DB/schema에 연결하되,
서로 다른 로그인과 `sslmode=verify-full&sslrootcert=/run/cremore/database-ca.pem`을 사용한다.
DB admin URL은 Compose 입력에 없다. 런타임 로그인은 schema 소유자·superuser가 될 수 없다.
`prepare` → migration → `grant` 순서와 유지보수·backup 조건은
[PostgreSQL 문서](../../postgres/README.md)가 기준이다.

SIEM은 기존 `cremore-siem` exporter와 [설정 예시](../../siem/http-json.example.json)를 쓴다.
원하는 기존 adapter를 선택하고 `token_env`(OAuth이면 `client_secret_env`)를
`SIEM_DESTINATION_TOKEN`으로 바꾼다. 원문 token을 JSON에 넣지 않는다. TLS 파일 경로는
`/etc/cremore-siem/` 아래를 쓴다. certificate-only sink는 token을 비워도 된다. 출력 token은 해당
수신기 ingest에만 제한하고 collector/provider token을 재사용하지 않는다. 여러 독립 목적지에 다른
token이 필요하면 각각의 SIEM 서비스·DB 역할·egress/환경 목록을 별도로 검토한다.
이 단일 목적지 구성에 범용 secret env 파일을 추가하지 않는다.

아래 명령은 저장소 루트에서 실행하는 Linux shell 예시다. Compose v2.20 이상이 필요하다.
네트워크 운영자가 [네트워크 계약](NETWORK_CONTRACT.md)을 먼저 인수하고, DB 관리자가 같은
애플리케이션 설치본의 `python -m cremore.db.privileges prepare --schema cremore`를 별도 실행한다.

```sh
# 출력에 secret을 렌더하지 않고 필수 변수와 YAML만 검증한다.
docker compose --env-file /etc/cremore-isolated/isolated.env \
  -f deploy/compose/isolated/compose.yml config --quiet

# 최초 설치 또는 런타임을 정지한 유지보수 창: migration 로그인만 받는 일회성 프로세스.
docker compose --env-file /etc/cremore-isolated/isolated.env \
  -f deploy/compose/isolated/compose.yml --profile migration run --rm --no-deps migrate

# 이 사이에 DB 관리자가 별도 세션으로 privileges grant --schema cremore를 실행한다.
docker compose --env-file /etc/cremore-isolated/isolated.env \
  -f deploy/compose/isolated/compose.yml up -d
```

일반 `up`은 migration profile을 실행하지 않는다. Compose는 비활성 profile의 변수도 치환하므로
관리자 env 파일에는 migration URL도 필요하지만, 일반 서비스 환경/mount에는 전달되지 않는다.
CLI·env 파일을 다루는 배포 관리자는 신뢰 주체다. rollout 뒤 migration credential을 회수/교체하고
다음 유지보수 때 새 값을 준비한다. DB schema/권한 검사가 실패하면 런타임은 종료한다.
`ISOLATED_DEPLOYMENT=false`나 공용 관리자 DB로 우회하지 않는다.

운영 중 `ps`/health 상태, 외부 SIEM heartbeat 미수신, token 갱신 실패, deny 로그를 감시한다.
외부 수신기의 보존·무결성·접근권한과 미수신 경보는 해당 시스템에서 관리한다. 이 Compose가
DB/outbox를 변경 불가능한 외부 감사 저장소로 만들지는 않는다. 노출 사고 시 역할별 DB/클라우드/
SIEM credential과 세션을 회수하고 새 키·승인 정책으로 복구한다.

## 로컬 검증

```sh
node --test deploy/compose/isolated/tests/compose.test.cjs
git diff --check
```

검사는 빈 env 파일과 합성 값으로 `docker compose config --format json`만 실행한다. 서비스나
네트워크를 생성하지 않고 이미지 pull·DB·공급자·IdP·SIEM 호출도 하지 않는다. 역할별 env/mount/DB,
외부 network 필수값, 하드닝, migration profile, OIDC 전달, legacy 설정 비상속을 확인한다.
실제 image 기동·CA/권한·방화벽 차단·신원 갱신은 이 렌더 검사의 범위 밖이다.
