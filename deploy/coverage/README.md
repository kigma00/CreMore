# 고객 금고 수집기 운영

대시보드의 **Secret manager → Credential coverage**에서 금고 연결과 허용 범위를
등록한다. 저장 시 한 번 표시되는 연결 ID와 제출 토큰을 고객 환경에 전달한다.
금고 원문은 이 환경에서만 읽고 `verify=False`로 탐지하며, API에는 지문·식별자·위치·
버전·완전성만 제출한다. 수집 결과만으로 새 노출 finding을 만들지 않는다.
AWS Secrets Manager·SSM은 연결에서 서버 수집을 켜면 이 수집기 없이 CreMore worker가 승인된 스캐너
역할로 수집한다([aws/README.md](../../aws/README.md#secrets-manager-보관-값-수집)). 설치의 `SECRET_STORE_URL`과
같은 Vault/OpenBao도 worker의 기존 신원으로 수집할 수 있다([vault/README.md](../../vault/README.md)).
그 밖의 금고는 이 수집기를 쓴다.

## 설치와 실행

Python 3.12 이상에서 이 저장소의 `pip install '.[gcp]'`를 사용하거나
`deploy/docker/python.Dockerfile`로 API/worker와 같은 버전의 이미지를 빌드한다.
서로 다른 엔진·규칙·지문 키·정책의 제출은 거부된다.

환경의 비밀 주입 기능으로 다음 값을 전달한다. 셸 히스토리나 문서에 실제 값을 쓰지 않는다.

| 값 | 공급 위치 |
|---|---|
| `CREMORE_COLLECTOR_TOKEN` | 해당 연결의 제출 전용 토큰. 교체하면 이전 토큰은 즉시 무효 |
| `FINGERPRINT_KEY` | API/worker와 같은 hex HMAC 키, 별도 보안 채널로 전달 |
| AWS 인증 | SDK 기본 체인: 로컬 프로필, EC2 instance profile, IRSA/Pod Identity |
| Vault/OpenBao 인증 | `VAULT_TOKEN` 또는 Vault Agent의 파일 sink를 가리키는 `VAULT_TOKEN_FILE` |
| GCP 인증 | ADC. Workload Identity Federation 또는 승인된 서비스 계정 |

```sh
cremore-coverage --api-url https://cremore-api.example.internal --connection-id CONNECTION_UUID
```

`--api-url`은 `/api/v1`을 제외한 **API 원점**이다. 브라우저용 OIDC proxy 주소는
제출 토큰 인증을 처리하지 않는다. API의 HTTPS 경로에 사설 네트워크/VPN 또는 제한된
ingress로 접근시킨다. 고객 CA는 `SSL_CERT_FILE`로 전달하며 인증서 검증을 끄지 않는다.
로컬 단일 프로세스 검증에만 `http://localhost:8080`을 허용한다.

종료 코드 0은 선언 범위 수집 완료, 2는 부분/실패 결과 제출 완료, 1은 실행/제출 실패다.
전송 오류는 같은 실행 UUID·배치·종료 요청으로 최대 3회 재시도한다. 원문은 로그나
재시도 파일에 저장하지 않는다. 중단된 실행은 최대 6시간 후 새 실행으로 대체할 수 있고,
그동안 이전 관측을 현재 보관으로 판정하지 않는다. 연결 범위를 변경하면 재수집해야 한다.

**키 전달의 신뢰 경계:** 현재 `FINGERPRINT_KEY`는 저장된 연결 인증정보의 암호화 키 파생에도
사용된다(`SEALING_KEY`로 분리 가능). 감사 기록 체인의 키도 `AUDIT_CHAIN_KEY`를 두지 않으면 이 키에서 파생한다.
따라서 고객 해셔는 이 설치의 신뢰받는 운영 구성요소여야 한다. 신뢰 영역이 다른
조직은 별도 설치·DB·키를 사용한다. 키 교체 후 양쪽 노출과 금고를 재수집해야 하며,
이전 키의 미일치를 미보관으로 처리하지 않는다. 제출 API는 이 키를 내려주지 않는다.

## 공급자별 읽기 권한과 차이

| 공급자 | 수집 범위와 필요한 권한 |
|---|---|
| AWS Secrets Manager | 명시 계정·리전·ARN/경로. 목록 사용 시 `ListSecrets`, 해당 ARN의 `GetSecretValue`, 고객 KMS 키 사용 시 제한된 `kms:Decrypt`. 기본 `AWSCURRENT`; 다른 stage는 과거 근거 |
| SSM Parameter Store | 명시 계정·리전·경로의 `GetParametersByPath`와 복호화 권한. 경로 재귀 권한의 의미를 확인하고 허용 경로만 부여 |
| Vault Enterprise/HCP Dedicated/OpenBao | 지정 namespace·KV mount·경로의 LIST/READ. KV v2는 metadata LIST와 data READ, KV v1은 해당 경로 LIST/READ. 동적 secrets engine은 수집하지 않음 |
| GCP Secret Manager | global 프로젝트 범위의 목록과 선택 버전 access. 명시 secret 목록 사용 시 프로젝트 전체 list 권한 불필요. `latest`를 현재 근거로 사용; 숫자/alias는 현재성 미확인 |
| IAM/CloudTrail | 값 접근 없는 별도 metadata 수집. 대시보드에서 승인한 AWS 계정으로 worker 실행 가능. IAM `ListUsers`, `ListAccessKeys`; 선택 시 `ListServiceSpecificCredentials`, credential report. CloudTrail `LookupEvents`는 선택 리전/1–90일 관리 이벤트 |

플랫폼 scanner 역할의 Secrets Manager 값 읽기 **Deny는 그대로 유지**한다. 금고 읽기
권한은 이 고객 수집기 신원에만 부여한다. SDK의 실제 계정 ID가 선언과 다르면 중단한다.
읽기 거부·삭제된 버전·알 수 없는 형식·페이지/항목 한도는 부분 수집이다.
API 완료는 조직 전체 자격증명을 회수했다는 뜻이 아니다.

## 주기 실행

- 로컬/EC2: 운영체제의 기존 스케줄러로 위 명령을 실행한다. 주기는 연결의 유효 시간
  (기본 24시간)보다 짧게 잡고 한 연결의 중복 실행을 막는다. 파일 sink와 키 파일은
  실행 사용자만 읽을 수 있게 한다. 정상 종료뿐 아니라 코드 1/2와 미실행을 감시한다.
- EKS: [cronjob.yaml](cronjob.yaml)은 6시간 간격, 동시 실행 금지, 30분 기한의 예제다.
  `cremore-coverage` ConfigMap에 `CREMORE_API_URL`, `CREMORE_CONNECTION_ID`를 두고,
  같은 이름의 Secret에 `CREMORE_COLLECTOR_TOKEN`, `FINGERPRINT_KEY`를 주입한다.
  ServiceAccount `cremore-coverage`에 수집기 전용 IRSA/Pod Identity association을 설정한다.
  Vault는 기존 Vault Agent의 auto-auth/token sink와 읽기 전용 공유 volume을 추가하고
  `VAULT_TOKEN_FILE`을 설정한다. GCP는 기존 ADC federation 구성/volume을 연결한다.
  API/worker의 ServiceAccount나 scanner 역할에 금고 값 접근을 합치지 않는다.
- 네트워크: DNS, API HTTPS, 선언한 금고 HTTPS만 허용한다. Pod Identity 사용 시 agent
  `169.254.170.23:80`/`[fd00:ec2::23]:80` 접근을 별도로 확인한다. 사설 CA와 프록시,
  HCP private endpoint, namespace 정책은 설치 환경에서 검증해야 한다.

## 대시보드 서버를 EC2/EKS에 설치

- EC2: 기본 Compose에 [서버 TLS/OIDC overlay](../compose/reverse-proxy/README.md)를
  적용한다. instance profile을 사용하면 [ec2-instance-profile.yml](../compose/ec2-instance-profile.yml)을
  마지막 overlay로 추가한다. API/worker에서 CLI 파일을 사용하지 않고 IMDS를 활성화한다.
  IMDSv2 필수, 컨테이너 접근/hop limit, 승인한 runtime role 일치를 실제 호스트에서 확인한다.
  DB/API/worker/web은 `restart: unless-stopped`이며 DB 영속 volume과 백업을 운영한다.
- EKS: [Helm chart](../helm/README.md)에 기존 OIDC/DB/TLS/ServiceAccount 설정을 넣는다.
  Pod Identity를 사용할 경우 `networkPolicy.eksPodIdentity=true`로 agent 경로를 허용한다.
  IRSA는 projected web-identity token과 STS HTTPS 접근을 사용한다.
- 화면 흐름: 배포 → 관리자 로그인 → 실행 신원 확인/승인 → 계정 접근 검증 → 콘텐츠
  카탈로그 → 범위 승인 → 스캔. 금고는 별도 coverage 연결 → 고객 해셔 실행 → 금고 범위
  확인 → 대조 결과 조회 순서다. 호스팅 자체가 EC2 파일·EKS Pod 내부 수집 권한은 아니다.

합성 테스트와 Compose/Helm 렌더링은 실제 배포·IdP 로그인·토큰 갱신·노드 재시작 검증을
대신하지 않는다. 이 저장소의 구현 검증에서 실제 고객 계정에 접근하거나 배포하지 않았다.

## Bitbucket 콘텐츠 연결

금고 연결과 별도로 **Sources → 새 공급자 연결 등록 → Bitbucket**을 선택한다.
Cloud는 `workspace/repository`, Data Center는 `project/repository`를 입력한다.
`/repository`를 생략하면 해당 workspace/project의 목록을 수집하고, 스캔할 저장소를
범위 화면에서 명시적으로 선택한다. Data Center 개인 project는 `~사용자/repository`다.

- Cloud: API 원점은 `https://api.bitbucket.org`다. OAuth/access token Bearer 또는
  API token Basic을 선택한다. API token에는 Atlassian 이메일이 필요하다.
- Data Center: 사내 HTTPS 주소와 context path를 입력하고 PAT Bearer를 사용한다.
  토큰에는 선택 저장소의 메타데이터·파일 읽기 권한만 부여한다. 제품 버전과 토큰 종류에
  따라 필요한 permission/scope가 다르므로 실제 API 응답으로 확인한다.
- 인증값은 기존 worker 환경의 `BITBUCKET_TOKEN`, 지원하는 비밀 참조 또는 암호화된
  연결 토큰 공급 방식을 사용한다. 토큰 갱신은 해당 공급 방식에서 수행한다.
- 등록은 연결/선언 저장과 인증 점검을 접수한다. **설정 계속 → 메타데이터 카탈로그 수집
  → 범위 선택·저장 → 스캔**을 수행한다. 검사 ref는 commit SHA로 고정한다.
- 전체 Git 이력·LFS 본문·submodule·pipeline 산출물은 읽지 않는다. 접근 실패·페이지
  한도·파일 읽기 실패가 있으면 완전한 미노출 결과로 해석하지 않는다.

화면의 **제품·인증 방식 선언**은 운영자가 적는 설명이며 실제 endpoint나 권한을
바꾸지 않는다. 실제 연결 값은 공급자 등록 항목과 worker의 인증 공급 방식에 저장된다.
Cloud/Data Center의 인증·페이지네이션·원본 링크·등록 흐름은 합성 테스트로 검증했으며,
실제 설치 버전과 SSO/접근 정책·CA·토큰 갱신은 고객 환경에서 확인해야 한다.
