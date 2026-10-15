# cremore-ticket-jira

CreMore가 키 조치의 소유자 승인과 노출 대응 요청을 Jira 이슈로 묻는 티켓 시스템 플러그인이다(Jira Cloud, Data Center/Server).
공개 계약 `cremore.ticketing.contract`만 쓰고 `cremore.ticket_systems` entry point(`jira`)로 등록한다.
동작·권한·오류 코드는 [티켓 시스템 문서의 "Jira 플러그인"](../../docs/TICKET_SYSTEMS.md#jira-플러그인-packagescremore-ticket-jira)을 따른다.

## 먼저 확인할 조건 (Jira Cloud)

- **토큰**: Atlassian **사용자 계정**의 클래식(범위 없는) API 토큰을 그 계정 이메일과 함께, 사이트 주소(`https://<site>.atlassian.net`)로 쓴다.
  Atlassian "서비스 계정"의 범위 지정 토큰(`api.atlassian.com` 게이트웨이)은 지원하지 않으며, `api.atlassian.com` 주소는 거절한다.
- **이메일 공개**: Jira Cloud는 기본적으로 다른 사용자의 이메일을 숨긴다. 소유자를 이메일로 찾으려면 각 소유자의 프로필 "이메일 주소"
  공개 범위가 CreMore 계정이 볼 수 있게 되어 있고, 사이트 일반 구성의 "사용자 이메일 표시(User email visibility)"가 숨김·마스킹이
  아니어야 한다. 아니면 `JIRA_USER_EMAIL_HIDDEN`으로 거절되므로 Slack·메일 링크로 요청한다.

Data Center는 이메일을 비우고 개인 액세스 토큰(Bearer, 8.14 이상)을 쓴다.

## 설치와 켜기

```bash
python -m pip install -e '.[dev,gcp,azure]'
python -m pip install --no-deps -e packages/cremore-ticket-jira
```

API와 worker 양쪽 환경에 `TICKET_SYSTEM_PLUGINS=jira`를 둔다(`docker-compose.yml`·`.env.example`, 격리 Compose, Helm
`config.ticketSystemPlugins`가 이 값을 기본 빈 값으로 노출한다). 그 뒤 관리자가 연동 서비스 > 기타 설정 > **티켓 시스템**에서
Jira를 고르고 사이트 주소, (Cloud) 계정 이메일, 토큰, 프로젝트 키, 이슈 유형, 승인·거절 상태를 저장한 뒤 연결을 확인한다.
연결 확인은 CreMore 계정의 권한(`/mypermissions`)과 이슈 유형·상태를 확인한다.
Python 이미지(`deploy/docker/python.Dockerfile`)는 이 패키지를 wheel로 함께 설치한다.

## 소유자가 하는 일

자기에게 배정된 이슈를 승인 상태(예 `Done`)로 옮기면 승인, 거절 상태(예 `Won't Do`)로 옮기면 거절이다.
CreMore는 이슈의 가장 최근 상태 변경 기록에서 그 상태로 옮긴 계정을 읽고, 물은 계정의 응답만 인정한다. Jira에는 보고 폼이 없으므로
노출 대응 요청의 완료는 CreMore 링크(이슈 설명 끝의 링크)의 대응 담당자 탭에서 조치 결과를 보고해야 끝난다(`REPORT_REQUIRED`).

## 검사

합성 Jira(`httpx.MockTransport`)만 쓴다. 실제 Jira 사이트나 계정에 접속하지 않는다.

```bash
AWS_EC2_METADATA_DISABLED=true python -m pytest packages/cremore-ticket-jira/tests -q -p no:cacheprovider
```
