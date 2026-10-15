# 온프레미스·Kubernetes 무인 운영

`ISOLATED_DEPLOYMENT=true`의 [분리 배포](POST_COMPROMISE_CONTAINMENT.md)에서는 아래의
공유 API/worker 신원 설명 대신 **collector 수집 신원과 remediator 조치 신원을 분리**한다.
API/control에는 클라우드 신원을 주지 않는다. 기존 IdP 자동 갱신은 collector에서 실행하며
remediator는 배포에 고정된 별도 workload identity/인증서 경로를 쓴다.

2026-10-06 구현 기준. 설치 장소와 수집 대상은 별개다. 웹 브라우저 로그인은 API 이용자의
인증이며 수집기는 API·worker의 기계 신원으로 동작한다. worker와 DB가 살아 있고 승인된
연결의 주기가 켜져 있어야 예약 수집·티켓 응답 확인·IdP 갱신·SIEM 전달이 계속된다.
아래 예시는 인증 선택을 설명하며 DB·TLS·OIDC·백업·네트워크 설정은 기존
[배포 지침](../deploy/helm/README.md)과 [기계 신원](MACHINE_IDENTITY.md)을 함께 적용한다.

## 실행 환경별 선택

| 설치 환경 | AWS 신원 | 자동으로 갱신하는 주체 |
|---|---|---|
| EC2 | 인스턴스 역할, `ec2-instance-profile.yml` | IMDSv2와 AWS SDK |
| EKS | IRSA 또는 Pod Identity | kubelet/웹훅·Pod Identity agent와 SDK |
| 다른 Kubernetes | projected ServiceAccount OIDC 토큰을 AWS IAM OIDC 공급자와 역할에 연결 | kubelet이 JWT 교체, SDK가 STS 갱신 |
| 온프레미스 VM·컨테이너 | 회사 IdP 기계 토큰 또는 IAM Roles Anywhere 인증서 | 내장/별도 토큰 갱신기 또는 signing helper와 SDK |

어느 경로든 서버 신원 하나로 승인된 여러 계정의 scanner 역할을 맡을 수 있다.
`서버 권한 직접 사용`은 그 신원이 속한 계정이고, `계정별 역할`은 대상 계정의 역할을
AssumeRole하는 차이다. 신원 발견은 대상 계정·범위 승인이나 부족한 IAM 권한을 대신하지 않는다.
API와 worker는 같은 승인 신원이어야 한다. 새 팀 연결에 사람 SSO·고정 IAM 키를 쓰지 않는다.

GCP는 ADC의 workload federation, Azure는 workload identity, Vault/OpenBao는 연결별
Kubernetes/JWT/AppRole 로그인 등 기존 갱신 경로를 쓴다. SaaS는 서버에서 저장된 연결 인증을
사용하므로 AWS에 설치해야 한다는 제약은 없다. 다만 PAT·API 토큰·앱 서명 키·OAuth refresh
token 등 공급자가 요구하는 인증정보의 유효기간·권한 취소는 별도 관리해야 한다. 공급자가
갱신 API를 주지 않는 PAT까지 제품이 자동 발급할 수 있다는 뜻은 아니다.

## 일반 Kubernetes의 AWS OIDC

IAM에 클러스터의 HTTPS OIDC issuer를 등록하고 audience와 두 ServiceAccount의 정확한
subject를 역할 신뢰에 제한한다. issuer discovery/JWKS는 AWS가 접근할 수 있어야 한다.
API·worker 역할에 자기 역할의 `iam:GetRole`과 선택한 수집/AssumeRole 권한을 준다.

```yaml
aws:
  webIdentity:
    enabled: true
    roleArn: arn:aws:iam::123456789012:role/cremore/Scanner
    audience: sts.amazonaws.com
    expirationSeconds: 3600
```

차트는 API·worker에만 `/run/cremore-aws-identity/token`을 projected volume으로 연결한다.
웹에는 토큰이 없다. kubelet이 파일을 교체하며 SDK가 새 파일을 읽는다. IRSA 어노테이션,
Pod Identity 설정, Roles Anywhere와 동시에 켜지 않는다. EKS Pod Identity는 AWS 외부
Kubernetes에서 사용할 수 없지만 OIDC 경로는 사용할 수 있다.

## IAM Roles Anywhere

AWS 장기 액세스 키 대신 PKI 인증서와 개인키로 짧은 STS 자격증명을 받는다.
임시 자격증명은 SDK 메모리에서만 사용하고, 개인키는 배포 관리자가 보호한다.
AWS signing helper 자체는 PKCS#11·TPM 래핑 키·암호화된 PKCS#8 키를 지원하지만, CreMore의 내장 브리지는
현재 PEM 인증서와 암호화되지 않은 PEM 개인키 파일만 넘긴다. 그래서 개인키 보호는 아래의 파일 권한과
호스트·Secret 저장소 관리에 달려 있다.

1. AWS Roles Anywhere에 조직 CA trust anchor와 profile을 만들고 전용 IAM 역할을 허용한다.
   역할 신뢰는 `rolesanywhere.amazonaws.com`에 필요한 `sts:AssumeRole`, `sts:TagSession`,
   `sts:SetSourceIdentity`를 허용하되 trust anchor ARN/계정 및 인증서 subject 조건으로 제한한다.
   profile의 역할·세션 정책과 역할의 수집 권한을 최소 범위로 정한다.
2. 공식 [AWS signing helper](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html)를
   배포 아키텍처에 맞게 확보하고, AWS가 릴리스마다 공개하는 SHA-256과 대조해 승인한 바이너리의 SHA-256을 고정한다. 제품은 임의
   URL에서 helper를 내려받거나 대시보드 입력으로 실행 명령을 만들지 않는다.
3. [`roles-anywhere.example.json`](../deploy/compose/identity/roles-anywhere.example.json)을 복사하여
   helper 경로·SHA-256·인증서·키와 실제 trust anchor/profile/role ARN을 설정한다.
   모두 절대 경로이고 ARN의 partition·리전·계정 관계를 검사한다.
4. [`roles-anywhere.aws-config`](../deploy/compose/identity/roles-anywhere.aws-config)를 `aws-config`라는
   이름으로 같은 보호 디렉터리에 둔다. SDK의 `credential_process`가 고정 브리지를 호출한다.
   기본 이미지의 Python은 `/app/venv/bin/python`이다. 사용자 이미지에서 경로를 바꾸면
   동일 인터프리터의 절대 경로로 프로필도 바꾼다.

Linux 파일은 root 또는 프로세스 UID 소유이고 group/world 쓰기를 금지한다. 개인키는
0600 또는 프로세스 전용 그룹의 0440으로 읽게 한다. 기본 제품 UID/GID는 65532이다.
호스트/Secret 저장소에서 개인키 접근·백업·감사를 관리하고 Git·로그·일반 환경변수에 넣지 않는다.
helper와 설정 경로 및 상위 디렉터리는 배포 관리자만 교체할 수 있게 보호한다.

### Docker Compose

보호 디렉터리 안에 `aws-config`, `roles-anywhere.json`, `certificate.pem`, `private.pem`을 둔다.
JSON의 컨테이너 내부 경로는 예제를 따른다.

```bash
export AWS_ROLES_ANYWHERE_DIRECTORY=/srv/cremore/roles-anywhere
export AWS_SIGNING_HELPER_PATH=/srv/cremore/bin/aws_signing_helper
docker compose -f docker-compose.yml \
  -f deploy/compose/identity/aws-roles-anywhere.yml up -d
```

두 마운트는 API·worker에만 읽기 전용으로 연결된다. 없던 호스트 경로를 자동 생성하지 않는다.
정적 AWS 키·웹 신원·SSO 프로필과 함께 사용하지 않는다. 인증 선택을 바꿀 때 회사 IdP
기계 신원의 AWS 항목도 끄거나 같은 방식으로 정리한다.

### Kubernetes

승인된 signing helper를 API·worker 이미지에 포함한다. 기본 이미지는 shell이나 다운로드
도구가 없으므로 시작 스크립트에서 내려받지 않는다. 예를 들어 검증한 helper가 있는
빌드 컨텍스트에서 다음 파생 이미지를 만들고 서명·digest 고정 후 배포한다.

```dockerfile
ARG CREMORE_IMAGE
FROM ${CREMORE_IMAGE}
COPY --chown=0:0 --chmod=0555 aws_signing_helper /opt/aws_signing_helper
```

`CREMORE_IMAGE`에는 사용 중인 API 또는 worker의 검증된 image digest를 지정한다.
설정 JSON의 hash도 이 바이너리와 일치해야 한다. Secret은 외부 Secret 관리 도구 또는
제한된 관리자 경로로 준비한다. 파일의 내용이나 생성 명령의 결과를 로그에 남기지 않는다.

```yaml
aws:
  rolesAnywhere:
    enabled: true
    secretName: cremore-roles-anywhere
```

Secret 키는 위 네 파일 이름과 같아야 한다. 차트는 전체 Secret 디렉터리를 0440으로
마운트하고 `subPath`를 사용하지 않는다. 개인키를 저장하는 Kubernetes Secret은 그 자체로
암호화 금고가 아니다. etcd 저장 암호화, RBAC, 백업 암호화 또는 외부 Secret 관리가 필요하다.

## 갱신·장애·교체

- SDK가 세션 만료 전에 helper를 다시 실행한다. 브리지는 매 호출마다 설정/hash/인증서
  유효기간/키 일치를 확인하고, 최대 30초·32 KiB stdout으로 제한한다. stderr·원문 응답은
  기록하지 않는다. 임시 자격증명과 유효한 만료 시각이 없으면 거절한다.
- 인증서 교체는 PKI 운영자의 책임이다. 인증서와 대응 키를 같은 버전으로 교체한다.
  Kubernetes는 하나의 Secret 갱신을 사용한다. Compose는 두 파일 교체 중 잠깐 불일치하면
  안전하게 갱신 실패하고 다음 호출에서 회복한다. helper가 실행되는 동안 교체도 실패할 수
  있으므로 임시 세션·인증서가 만료하기 전에 충분한 여유를 둔다.
- worker는 인증서 만료 30일 전부터 `EXPIRING`, 만료·키 불일치·helper hash 변경은
  `REAUTH_REQUIRED`로 알린다. 짧은 STS 세션의 정상 갱신과 PKI 인증서의 갱신 책임을 구분한다.
  오류를 해결하면 다음 신원 확인에서 회복한다. role 자체가 바뀌면 관리자 재승인이 필요하다.
- 회사 IdP 토큰도 수명의 절반에 갱신하고 실패 시 제한된 backoff로 재시도한다. 초기 토큰
  실패나 설정 변경 때 호스트의 다른 계정으로 대체하지 않는다. 토큰 저장 실패 때는 이전
  토큰 경로를 차단하고 복구 후 재시도한다. 이미 발급된 SDK 세션은 공급자 만료까지 남을
  수 있으며 설정 변경이 공급자의 세션 즉시 폐기를 뜻하지 않는다.
- Compose restart 정책, Kubernetes probes, DB의 작업 lease/checkpoint를 그대로 쓴다.
  네트워크·IdP 장애 중 성공 수집을 보장하지 않는다. 부분/실패를 빈 목록 또는 삭제로
  처리하지 않고 작업·연결 상태에 남긴다. SIEM은 기존 outbox 재시도를 사용한다.

## 검증 범위

합성 인증서·가짜 IdP/STS 및 실제 SDK 프로세스 호출로 갱신·재시작·인증서 교체·거절을
검사한다. Linux 파일 권한과 설치 wheel 경로, Compose/Helm 렌더링도 별도 검사한다.
이 검사는 실제 AWS Roles Anywhere 계정 연결, 고객 Kubernetes 클러스터 적용, PKI 자동 발급,
24시간 wall-clock 연속 가동, 다중 노드 HA 또는 SLA를 입증하지 않는다. 운영 전 해당 환경에서
인증서 교체와 공급자 권한·망·시각 동기화 및 최소 하루 예약 수집을 확인해야 한다.

### 이번 변경의 실행 증거

- Windows 합성 인증·상태·worker 회귀: **157 passed, 2 skipped**. 두 skip은 Linux 파일
  권한 및 실행 파일 검사이며 아래 설치본 검사에서 실행했다.
- Linux: 현재 wheel을 제품 이미지에 설치하고 UID/GID 65532, 읽기 전용 root, 외부 망 없음으로
  실행했다. Roles Anywhere·토큰 갱신기·기계 신원·연결 상태 검사가 통과했다. helper만 합성
  프로그램이며 SDK → 별도 Python 브리지 → helper의 실제 subprocess 경로를 사용했다.
  테스트의 가짜 실행 파일을 위해 일회용 `/tmp`만 exec를 허용했다. 운영 설정을 바꾸지 않았다.
- `node --test deploy/helm/tests/chart.test.cjs`: **110 passed**. 기본 배포·신원 선택 충돌·
  projected JWT/Secret 마운트·웹 비노출·Compose 읽기 전용 마운트를 확인했다.
- 전체 웹 검사 **279 passed**, TypeScript와 production build 통과. 최종 갱신 오류 표시 변경
  후 관련 UI 검사·TypeScript·build를 다시 실행했다. 변경 Python Ruff 및 diff 검사도 통과했다.
- 접근자 목록은 별도 회귀 **109 passed** 및 KO/EN 브라우저 검사, 권한 근거는 **372 passed,
  17 PostgreSQL skipped, 19 subtests passed** 및 브라우저 검사로 확인했다. 각 묶음에는
  중복 검사가 있으므로 합산한 고유 검사 수로 표현하지 않는다.

실행 명령은 `roles_anywhere_test.py`, `machine_test.py`, `token_refresher_test.py`,
`health_test.py`, `worker_test.py`의 fake-client 회귀와 차트 테스트를 사용했다.
기존 FastAPI/Starlette deprecation 경고가 있으며 이번 변경의 실패는 아니다.
보안 CSV 두 개의 행별 대조와 운영상 예외는 [대조 보고서](SECURITY_CSV_REVIEW_2026-10-06.md),
권한 계산의 추가 지원 한계는 [권한 근거](PERMISSION_ASSESSMENT.md)를 참고한다.
