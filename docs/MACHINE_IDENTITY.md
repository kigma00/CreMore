# 기계 신원: 사람 세션 없이 수집하기

사람은 IdP로 대시보드에 로그인하고, 수집은 CreMore 서버의 워크로드 신원으로 한다. 담당자가 퇴사하거나 브라우저 세션이
만료돼도 수집은 계속된다. 설계 근거는 [통합 운영 설계 4.2절](CONTINUOUS_OPERATIONS_DESIGN.md#42-idp-연동)이다.
CreMore는 이미 각 클라우드 SDK의 기본 인증 경로(AWS botocore 기본 세션, `DefaultAzureCredential`, `google.auth.default`)를
쓰므로 아래 설정은 대부분 **배포 설정 연결**이다. 연결 상태 화면은 이런 연결을 `AUTO` 갱신으로, PC의 AWS SSO 세션은
`HUMAN_SESSION`으로 보여 주며 운영 배포에서 사람 세션이면 경고한다.

## 0. 대시보드에서 설정 (권장)

연동 서비스 화면의 "기타 설정 → 기계 신원 (회사 IdP)"에서 관리자가 설정한다(`/api/v1/settings/machine-identity`, admin).
배포 파일·환경변수·토큰 갱신기 컨테이너가 필요 없고, API와 워커 프로세스가 각자 토큰을 받아 자기만 읽는 디렉터리
(`CREMORE_MACHINE_IDENTITY_DIR`, 기본은 임시 디렉터리의 `cremore-identity`)에 0600으로 두며 수명의 절반에서 갱신한다
([`cremore/identity/machine.py`](../cremore/identity/machine.py), 갱신 규칙은 아래 토큰 갱신기와 같다).

AWS 연동의 인증 단계에서 서버 신원이 없으면 실행 위치(EC2·쿠버네티스·사내 서버/다른 클라우드)를 먼저 선택한다.
사내 서버는 이 화면에서 회사 IdP 기계 신원 설정을 열고, 닫으면 원래 연동의 입력을 유지한 채 신원을 다시 조회한다.
AWS의 OIDC 공급자·역할 신뢰와 서버의 역할 연결은 인프라 관리자가 최초 한 번 설정해야 한다.
그 뒤 담당자는 자동 조회된 신원을 승인하고 기능·대상을 선택하며, 신원 설정만으로 수집 범위를 승인하지 않는다.

서버 역할에는 **자기 역할만 조회하는 `iam:GetRole`** 권한을 포함한다. IAM 응답으로 경로까지 포함한 ARN을 자동 확인하며,
STS 세션 ARN에서 IAM 역할 경로를 추측하지 않는다. 기존 설치가 이 조회를 거절하면 인증 화면의 조회 정책을 역할에 추가하고
`AWS 신원 다시 확인`을 누른다. 직접 ARN 입력은 조회 권한을 허용할 수 없는 설치의 고급 설정으로 남긴다.
기계 신원 설정의 AWS 생성 명령과 중앙 실행 역할 템플릿은 자기 역할 ARN에 한정한 조회 권한을 포함한다.

| 설정 | 넣는 값 | 프로세스가 SDK에 주는 것 |
| --- | --- | --- |
| IdP 앱 | 토큰 URL(https), 클라이언트 ID, 클라이언트 비밀(봉인 저장, 다시 보여 주지 않음), `client_secret_post`·`client_secret_basic`, 선택 scope·audience, `access_token`·`id_token` | — |
| AWS | 이 IdP를 믿는 IAM 역할 ARN | `AWS_ROLE_ARN`·`AWS_WEB_IDENTITY_TOKEN_FILE`. 이 설치의 AWS 로그인(프로필·키·SSO 캐시·인스턴스 메타데이터)은 쓰지 않는다 |
| GCP | 워크로드 아이덴티티 공급자(`//iam.googleapis.com/projects/…/providers/…`), 선택 서비스 계정 | 프로세스가 만든 외부 계정 구성(`GOOGLE_APPLICATION_CREDENTIALS`, `credential_source.file`) |
| Azure | 테넌트 ID, 앱 등록 클라이언트 ID(audience 기본 `api://AzureADTokenExchange`) | `AZURE_CLIENT_ID`·`AZURE_TENANT_ID`·`AZURE_FEDERATED_TOKEN_FILE` |
| Vault·OpenBao | 토큰 이름과 선택 audience | `VAULT_CONNECTION_TOKEN_DIR`(배포가 정하지 않았으면 프로세스의 `vault` 디렉터리)의 `idp-이름` 파일. Vault 연결의 JWT 로그인 토큰 파일을 이 이름으로 둔다 |

- 설정된 클라우드는 첫 토큰 발급 전부터 그 신원에 고정한다. 발급 실패 때 호스트의 다른 신원으로
  대체하지 않는다. 재시작·설정 변경에서 이전 파일을 비우며 저장 실패는 차단하고 재시도한다.
  끈 클라우드는 프로세스 원래의 값으로 되돌린다. 수명의 절반에 갱신하며 만료 뒤 재시도 폭주를 방지한다.
- 프로세스는 상태(`machine_identity.status.<프로세스>`)에 토큰마다 상태·오류 코드·남은 수명과 비밀이 아닌 클레임
  (`iss`·`sub`·`aud`)만 남긴다. "토큰 받아 보기"(`POST …/test`)도 같은 것만 돌려주고 토큰 원문은 어디에도 남지 않는다.
- 클레임은 설정 도우미(`GET …/setup`)가 클라우드별 신뢰 설정 명령(IAM OIDC 공급자와 역할, 워크로드 아이덴티티 풀·공급자,
  Entra 연합 자격 증명, Vault JWT 역할)에 채워 넣는 데만 쓴다. 서명 검증은 각 클라우드가 한다.
- 변경은 감사 로그에 `MACHINE_IDENTITY_CHANGED`로 남는다(비밀 없음). 7일 넘게 보고하지 않은 프로세스의 상태는 지운다.
- AWS 신원이 바뀌면 이전에 승인한 신원과 달라지므로 AWS 연동의 "연결 확인"이 새 신원을 승인한다. 쿠버네티스에서는
  아래 서비스 계정 토큰 경로가 IdP 장애의 영향을 받지 않으므로 여전히 먼저 쓴다.

## 1. 쿠버네티스(Helm)

| 대상 | 설정 | 근거 |
| --- | --- | --- |
| AWS | IRSA: `serviceAccounts.api.annotations`·`worker.annotations`에 `eks.amazonaws.com/role-arn`. EKS Pod Identity: 클러스터에서 연결을 만들고 `networkPolicy.eksPodIdentity: true`. 스캐너 역할 고정은 `config.scannerPrincipalArn` | [IAM OIDC federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html) |
| GCP | GKE 워크로드 신원(서비스 계정 어노테이션 `iam.gke.io/gcp-service-account`) 또는 외부 계정 설정 Secret(`gcp.adcSecretName`) | [Workload Identity Federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation) |
| Azure | `azure.workloadIdentity.enabled: true`, `clientId`(Entra 앱), 선택 `tenantId`. API·worker 파드에 `azure.workload.identity/use: "true"` 라벨과 서비스 계정 어노테이션이 붙고, 웹훅이 `AZURE_FEDERATED_TOKEN_FILE`을 넣는다. Entra 앱에 서비스 계정마다 연합 자격 증명(subject `system:serviceaccount:<네임스페이스>:<서비스 계정>`, audience `api://AzureADTokenExchange`)을 만든다 | [AKS 워크로드 신원](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview) |
| 설치의 비밀 저장소(Vault·OpenBao) | `secretStore.authMode: kubernetes`(audience가 묶인 projected 토큰) | [Kubernetes auth](https://developer.hashicorp.com/vault/api-docs/auth/kubernetes) |
| 다른 Vault 클러스터 | `vaultConnections.tokens`에 클러스터마다 `name`·`audience`. worker의 `VAULT_CONNECTION_TOKEN_DIR/<name>`에 그 audience로 묶인 토큰이 생기고, 연결의 `server_auth.token_file`이 이름을 가리킨다. 포트가 443이 아니면 `vaultConnections.egress`로 연다 | [범용 금고 6절](EXTERNAL_VAULT.md#6-다른-vaultopenbao-클러스터의-서버-읽기) |

쿠버네티스 서비스 계정 토큰은 IdP 장애의 영향을 받지 않으므로 클러스터에서는 이 경로를 먼저 쓴다.

## 2. 서버 한 대(Docker Compose): 배포 파일로 설정

0절의 대시보드 설정을 쓰지 않을 때의 방법이다.

EC2에서는 [`deploy/compose/ec2-instance-profile.yml`](../deploy/compose/ec2-instance-profile.yml)이 인스턴스 역할(IMDSv2)을 쓴다.
그 밖의 서버에서는 IdP의 client credentials 토큰을 **토큰 갱신기**(`cremore-token-refresher`)가 파일로 유지하고,
각 SDK가 그 파일을 읽는다.

```bash
docker compose -f docker-compose.yml -f deploy/compose/identity/refresher.yml \
  -f deploy/compose/identity/aws-web-identity.yml up -d
```

| 파일 | 넣는 값 | SDK가 읽는 것 |
| --- | --- | --- |
| [`refresher.yml`](../deploy/compose/identity/refresher.yml) | `IDENTITY_REFRESHER_CONFIG`(설정 JSON의 절대 경로), `IDP_CLIENT_SECRET` | 공유 볼륨 `/run/cremore-identity`(API·worker는 읽기 전용). worker의 `VAULT_CONNECTION_TOKEN_DIR`은 `/run/cremore-identity/vault` |
| [`aws-web-identity.yml`](../deploy/compose/identity/aws-web-identity.yml) | `AWS_ROLE_ARN` | `AWS_WEB_IDENTITY_TOKEN_FILE`로 `AssumeRoleWithWebIdentity`([SDK 설정](https://docs.aws.amazon.com/sdkref/latest/guide/feature-assume-role-credentials.html)) |
| [`azure-workload-identity.yml`](../deploy/compose/identity/azure-workload-identity.yml) | `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` | `AZURE_FEDERATED_TOKEN_FILE`([WorkloadIdentityCredential](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.workloadidentitycredential)) |
| [`gcp-workload-identity.yml`](../deploy/compose/identity/gcp-workload-identity.yml) | `GCP_WIF_CONFIG`(자격 증명 구성 파일) | `GOOGLE_APPLICATION_CREDENTIALS`, 구성의 `credential_source.file` |

토큰 갱신기 설정([예제](../deploy/compose/identity/refresher.example.json))은 토큰마다 `name`, `token_url`(HTTPS), `client_id`,
`client_secret_env` 또는 `client_secret_file`(매번 다시 읽어 교체에 재시작이 필요 없다), 선택 `scope`·`audience`,
`auth_method`(`client_secret_post`·`client_secret_basic`), `token_field`(`access_token`·`id_token`), `directory`를 받는다.
클라우드 토큰은 `/run/cremore-identity/cloud`, Vault 연결 토큰은 `/run/cremore-identity/vault`처럼 **용도별 디렉터리**를
나눠, Vault 연결이 클라우드 토큰 파일을 가리킬 수 없게 한다. 토큰은 임시 파일에 쓴 뒤 한 번에 바꾸고(0600), 수명의
절반에서 갱신한다. 갱신에 실패하면 이전 토큰을 만료 전까지 두고 5초부터 두 배씩(최대 5분) 다시 시도하며, 로그에는 토큰
이름과 고정 코드만 남긴다. `--once`는 한 번 갱신하고 결과를 종료 코드(0 성공, 2 실패)로 알린다.

## 3. IdP와 클라우드 신뢰 설정

| IdP | 기계용 앱 | 근거 |
| --- | --- | --- |
| Okta | 사용자 지정 인증 서버의 client credentials 서비스 앱과 사용자 지정 scope | [Client Credentials](https://developer.okta.com/docs/guides/implement-grant-type/clientcreds/main/) |
| Keycloak | 서비스 계정을 켠 confidential client. 토큰의 `aud`는 audience mapper로 정한다 | [Service accounts](https://www.keycloak.org/docs/latest/server_admin/index.html) |
| Entra ID | client credentials 앱 등록. AWS·GCP 연동에 쓸 수 있고, Azure 자신의 연합에는 Entra 발급 토큰을 쓸 수 없다 | [Workload identity federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation) |

| 클라우드 | 신뢰 설정 | 근거 |
| --- | --- | --- |
| AWS | IAM OIDC 자격 증명 공급자(IdP 발급자 URL, audience)와 `sts:AssumeRoleWithWebIdentity`를 허용하는 역할. 신뢰 정책 조건에 `aud`·`sub`를 고정 | [IAM OIDC](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html) |
| GCP | 워크로드 아이덴티티 풀의 OIDC 공급자(속성 매핑 `google.subject=assertion.sub`)와 서비스 계정 가장 권한. 구성 파일은 `gcloud iam workload-identity-pools create-cred-config ... --credential-source-file=/run/cremore-identity/cloud/gcp` | [다른 IdP와 연합](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-providers), [create-cred-config](https://docs.cloud.google.com/sdk/gcloud/reference/iam/workload-identity-pools/create-cred-config) |
| Azure | Entra 앱의 연합 자격 증명(발급자, subject, audience `api://AzureADTokenExchange`) | [신뢰 만들기](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust) |
| Vault·OpenBao | JWT 인증 방식의 역할(`bound_audiences`, `bound_subject`, 읽기 전용 정책) | [JWT/OIDC auth](https://developer.hashicorp.com/vault/docs/auth/jwt) |

## 4. 확인한 범위

합성 검증: 토큰 갱신기(`cremore/cli/token_refresher_test.py`: 원자적 쓰기, 절반 수명 갱신, 실패 시 이전 토큰 유지와
재시도, 비밀 파일 교체, 로그에 비밀·토큰 없음), Helm 렌더링(Azure 라벨·어노테이션, Vault 연결 토큰, 거절 규칙)과 Compose
구성(`deploy/helm/tests/chart.test.cjs`). kind 클러스터에서 API·worker·SIEM 출력기의 실제 기동을 확인한다. 실제 AWS·GCP·Azure·
Okta·Keycloak 연동은 실환경 검증 항목이다.
