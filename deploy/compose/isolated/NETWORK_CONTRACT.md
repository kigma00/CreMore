# 외부 네트워크 운영자 계약

이 Compose는 **사전 프로비저닝하고 접근 정책을 검증한 외부 네트워크**만 역할별 egress에 쓴다.
network 이름이 비어 있으면 렌더가 실패하고, 지정한 network가 없으면 서비스 시작이 실패한다.
Compose가 egress용 bridge를 자동 생성하거나 default network로 대체하지 않는다.
그러나 `external: true`, network 이름·label·존재 자체는 트래픽 차단 기능이 아니다.
**일반 Docker bridge 생성만으로 아래 계약을 충족하지 않는다.**

운영자는 호스트 방화벽·검증된 network driver·강제 egress gateway 중 자신의 환경에 맞는
수단으로 아래 조건을 구현하고 인수 증거를 보존한다. 이 저장소는 운영 호스트 방화벽을 변경하지 않는다.

## 허용 흐름

각 외부 network는 서로 다른 이름/실제 네트워크이고 다른 역할/비관련 컨테이너를 넣지 않는다.
설치별 **정확한 목적지 주소·포트·DNS 이름**으로 이 표를 채워 승인한다. `0.0.0.0/0:443`,
`::/0:443`, 전체 cloud address range 또는 전체 기업망을 허용 목록으로 쓰지 않는다.
주소가 바뀌는 SaaS는 검증된 FQDN/L7 egress 제어 또는 운영자가 갱신하는 정확한 address set을 쓴다.
HTTP_PROXY 환경변수만 설정하고 직접 연결이 열려 있으면 강제가 아니다.

| Compose network / 역할 | 허용할 새 외부 연결 |
| --- | --- |
| `edge` / gateway | 없음. 승인된 client→호스트 TCP 443→gateway 8443 및 그 응답만 |
| `api-egress` | 전용 DB TCP 5432, IdP discovery/JWKS HTTPS, 실제 설정한 제어 OAuth endpoint HTTPS, 연락 발송을 켰다면 Slack HTTPS(`slack.com`, 소유자 승인·대응 요청 링크와 사후 통지, 팀 채널 확인)·SMTP relay, Slack 탐지 알림을 Incoming Webhook으로 보낸다면 그 시험 메시지용 `hooks.slack.com` 또는 `hooks.slack-gov.com` HTTPS(시험 메시지는 API가 보낸다. 봇으로 보내면 연락 발송의 `slack.com`), 티켓 시스템 플러그인을 설정했다면 그 티켓 API HTTPS(요청할 때 티켓을 연다) |
| `collector-egress` | 전용 DB TCP 5432, 선택한 공급자·수집 origin HTTPS, 해당 역할의 STS/WIF/identity 갱신 endpoint |
| `remediator-egress` | 전용 DB TCP 5432, 승인 조치 공급자 HTTPS, 해당 역할의 STS/WIF/identity 갱신 endpoint |
| `control-egress` | 전용 DB TCP 5432, 실제 설정한 티켓 API HTTPS, Slack 탐지 알림이나 대응 요청의 팀 채널 스레드 기록을 켰다면 Slack HTTPS(Incoming Webhook은 `hooks.slack.com` 또는 `hooks.slack-gov.com`, 봇은 `slack.com`) |
| `siem-egress` | 전용 DB TCP 5432, 지정한 외부 SIEM 수신 endpoint/port와 필요 시 그 OAuth token endpoint |
| `oidc-egress` | 설정된 IdP discovery/authorization-code 교환/JWKS endpoint HTTPS |
| `migration-egress` | 유지보수 중에만 전용 DB TCP 5432 |

DNS가 필요한 역할은 `CREMORE_DNS_SERVER`의 관리되는 resolver에 UDP/TCP 53만 추가 허용한다.
resolver도 승인된 목적지 이름만 해석하고 임의 DNS 외부 전달/DoH/DoT 우회를 막는다. Docker embedded
DNS가 custom DNS로 전달하는 흐름도 같은 정책을 적용한다. gateway와 web은 내부 서비스 이름
해석만 필요하다. IdP login page로 가는 사용자의 브라우저 흐름은 컨테이너 egress와 별개다.

Compose가 만드는 `gateway-oidc`, `oidc-web`, `web-api`는 `internal: true`다. 참여 서비스는 각각
gateway/proxy, proxy/web, web/API 두 개뿐이다. 연결은 gateway→proxy:4180→web:3000→API:8080이다.
Docker 내부 network는 그 두 컨테이너 간 양방향 접근을 허용한다. 이는 해당 홉의 신뢰 경계이며,
방화벽이 L7 사용자 권한을 보장한다고 주장하지 않는다. API가 bearer를 독립 검증한다.

## 차단과 유지 조건

- 허용 목록 외 IPv4 **및 IPv6** 새 연결을 기본 차단한다. IPv6를 관리하지 않으면 호스트/driver에서
  확실히 비활성화한다. 컨테이너 DNS name, 직접 IP, 다른 route 모두 같은 차단을 받는다.
- metadata/link-local(예: `169.254.169.254`, `169.254.170.2`, IPv6 link-local), loopback을 우회하는
  host gateway, Docker API/SSH, cloud metadata 이름, 비관련 RFC1918/ULA망과 lateral peer 접근을 막는다.
  허용 DB/IdP가 사설 주소인 경우 해당 주소·포트만 예외다. Docker host INPUT 경로와 bridge forwarding
  경로를 함께 다룬다. `DOCKER-USER`에만 규칙이 있다는 사실로 host INPUT 차단을 가정하지 않는다.
- Docker의 NAT/forward accept보다 먼저 정책이 적용되게 하고, published port가 host firewall을
  우회하는 경로도 인수한다. 컨테이너 주소 변경·재생성·Docker/host 재시작 후에도 적용한다.
- 네트워크 정책 로드 실패 시 해당 역할을 차단한 채 시작을 막는다. 허용 정책이 붙기 전 열린
  bridge에 서비스를 붙였다가 나중에 규칙을 적용하지 않는다. 운영자는 일반 bridge로 이름만
  맞춰 만들지 않는다. 전용 driver 또는 host boot/start gate에서 이 순서를 강제한다.
- 클라우드 IAM/role 자체도 collector 읽기/조치용 remediator를 분리하고 각 목적 범위로 줄인다.
  HTTPS 목적지 허용은 tenant·API 동작 제한을 대신하지 않는다. 허용된 endpoint 악용·DNS 기반
  외부 유출 가능성을 없앤다고 주장하지 않으며 필요 시 L7 정책/수신 측 통제를 더한다.

## 운영 전 인수 증거

배포 운영자는 network 이름과 역할·정책 revision·검사 시각을 기록한다. 각 역할과 동일한 namespace/
network attachment의 **자격증명 없는 합성 검사 프로세스**에서 다음을 확인한다.

1. 승인된 DB TCP/TLS·IdP/공급자/SIEM TLS handshake와 내부 서비스 hop이 필요한 역할에서만 통과한다.
   실제 공급자 변경 API, 수집 credential, 실사용 데이터는 이 네트워크 검사에 쓰지 않는다.
2. 운영자가 소유한 별도 미허용 test endpoint, 다른 역할의 network peer, host management/metadata
   경로로의 새 연결이 실패한다. IPv4/IPv6·TCP/UDP·직접 IP·DNS 경로를 따로 확인하고 deny counter와
   함께 기록한다. metadata 응답 body를 읽거나 token을 요청하지 않는다.
3. 서비스 재생성·Docker/host 재시작 뒤 같은 결과인지, 정책 서비스 중지 시 fail closed인지 확인한다.
   검사 과정에서 의도적으로 넓은 허용 규칙을 넣지 않는다.
4. CA 오류, 외부 신원 갱신 실패, SIEM 미수신 경보를 승인된 시험환경에서 확인한다. migration network는
   유지보수 외에는 닫고 migration login도 회수한다.

이 인수는 `docker compose config` 테스트로 대체되지 않는다. 방화벽을 관리하지 못하는 일반
Docker Desktop 설치는 렌더/합성 개발 검사에만 사용하고 이 외부 egress 보장을 보고하지 않는다.
