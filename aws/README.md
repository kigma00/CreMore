# aws 공급자 소유 영역

S3·IAM/CloudTrail·Secrets Manager·KMS·스캐너 신원·승인된 AWS 실행 구현을 소유한다. Python 구현과 전용 테스트는 `backend/cremore_aws_provider/`에 있다.
공통 플랫폼이 해당 라이브러리 함수를 직접 호출하며 제품의 Python wheel 하나에 함께 설치된다.

이 폴더에는 UI가 없다. 연결 화면은 `backend/`의 onboarding descriptor로 콘솔(`../web/console/`)이 그린다.

루트에서 `python -m pip install -e ".[dev,gcp]"`로 개발 설치 후
`python -m pytest aws/backend -q`로 전용 합성 회귀를 실행한다.
실제 호출은 별도로 지정한 환경·범위에서만 수행한다.

[공통 AGENTS](../AGENTS.md), [팀 지침](../docs/AI_TEAM_CODING_GUIDE.md),
[실제 디렉터리·등록·빌드 경계](../docs/PROVIDER_DIRECTORY_REVIEW.md)를 먼저 읽는다.
UI 작업에는 [web 지침](../web/AGENTS.md)과 설치된 Next 문서도 적용한다.
공통 API·DB·권한·scope·작업 수명·SIEM 계약과 registry는 플랫폼 담당자와 나누어 작업한다.

S3 catalog·콘텐츠·연결 인증 점검은 등록한 계정의 `AccountSessions`를 함께 사용한다.
역할 ARN이 없는 기존 SSO 연결도 해당 계정의 권한 세트 세션으로 읽으며, 서버 기본 신원은
명시적으로 승인·검증한 `RUNTIME_IDENTITY` 계정에만 쓴다. 작업에 계정 식별자가 없으면 거절한다.
요청·페이지·인증 갱신 시 현재 신원과 계정 승인 상태를 다시 확인하고, 결과 저장은 같은 승인 revision과
리스에 묶는다. 버킷 API에는 `ExpectedBucketOwner`로 연결 계정을 지정하므로 다른 계정의 버킷은 읽지 않는다.
단일 계정·중앙 실행 신원의 CloudFormation 템플릿은 신뢰 대상에 정확한 IAM 역할·사용자 ARN만 받는다.
계정 번호·root ARN·와일드카드·STS 세션 ARN은 거절하며, Identity Center의 제한된 패턴 신뢰는
기존 `member-account-role.yaml` 설정을 사용한다.

발견한 액세스 키 식별자만으로 사용 이력을 새로 고칠 때는 현재의 완전한 IAM 발급 목록에서
동일한 키의 소유 계정을 확인한다. 모든 연결 계정에 동기 IAM 조회를 보내지 않는다.
근거가 없거나 오래됐거나 부분 수집·충돌·조회 한도가 있으면 소유자를 미확인으로 남기고,
IAM 목록 갱신 또는 완전한 키 쌍의 인증 확인을 안내한다. 확인된 계정의 기존 승인과 사용 이력
백그라운드 작업을 그대로 사용하며, 발급 목록의 소유자 근거를 자격증명 인증 성공으로 표시하지 않는다.

## 새 서버 연결: 자동 갱신되는 워크로드 신원

새 연결은 개인 SSO 로그인이나 고정 액세스 키 없이 실행되는 서버 역할을 사용한다.
설치 장소와 수집 대상은 별개다. AWS 밖의 사내 서버·Kubernetes에서도 적절한 workload federation을
구성하면 사용할 수 있다. 현재 SDK에서 확인하는 갱신 경로는 EC2 인스턴스 역할, ECS/EKS 컨테이너 역할,
web identity, 그리고 이 신원에 기반한 역할 체인이다. 개인 SSO·환경 변수/파일의 고정 키·MFA에 의존하는
역할 체인은 새 연결에서 거절한다. IAM Roles Anywhere는 배포 관리자가 SHA-256으로 고정한
signing helper를 `cremore_aws_provider.roles_anywhere` 브리지로 실행하는 `credential_process`와
그 역할 체인을 지원한다. 임의 프로그램의 무인 갱신은 인정하지 않는다. PEM 인증서·개인키
검사와 매 갱신 재읽기, 만료 경고·실패 복구, Compose/Helm 설정은
[무인 운영 지침](../docs/UNATTENDED_DEPLOYMENT.md)을 따른다.

사내 서버에는 기존 [기계 신원 설정](../docs/MACHINE_IDENTITY.md)의
[`refresher.yml`](../deploy/compose/identity/refresher.yml)과
[`aws-web-identity.yml`](../deploy/compose/identity/aws-web-identity.yml)을 사용할 수 있다.
AWS 역할의 OIDC 신뢰에 발급자·audience·subject를 제한하고, projected JWT 파일을 발급자/리프레셔가
만료 전에 자동 교체해야 한다. SDK는 새 JWT로 서버 STS 세션을 갱신하고, 선택 멤버 역할도 만료 전에
다시 AssumeRole한다. 메타데이터 비활성 환경에서 JWT·서버 STS·멤버 STS 교체는 fake STS와 SDK로 검증하며,
실제 사내 서버에서 24시간 연속 운영을 확인했다는 뜻은 아니다.

1. API와 worker에 같은 서버 역할을 제공하고 AWS 신원 설정에서 승인한다. 이전 승인에 SDK 갱신 경로
   정보가 없으면 신원을 다시 승인한다. CreMore가 서버 역할이나 AWS 권한을 자동으로 만들지는 않는다.
2. **계정별 수집 역할 사용(권장)**은 서버 신원 하나가 각 계정의 수집 전용 역할을 맡아 단일·다중 계정을 읽는다.
   서버에는 역할 전환 권한을, 대상 역할에는 이 서버 신원을 허용하는 신뢰 정책을 설정한다.
   **현재 서버 권한 직접 사용(단일 계정)**은 추가 역할 전환 없이 서버 신원에 직접 준 수집 권한으로 그 신원의 계정 하나를 읽는다.
   두 방식 모두 임시 자격증명을 자동 갱신하며, 서버가 설치된 장소와 수집 대상 계정은 별개다.
   조직 계정 자동 목록에는 조직 관리/위임 계정의 `organizations:ListAccounts`와 선택한 멤버 역할에 대한
   `sts:AssumeRole` 권한이 필요하다. OU 제한을 설정했다면 OU·소속 계정 목록 조회 권한도 필요하다.
3. 조직의 대상 계정에는 scanner 멤버 역할을 사전 배포하고, 조직 설정에 StackSet과 같은 ExternalId를
   지정한다. 기존 계정의 사용자 지정 역할 ARN·ExternalId는 그대로 쓴다. 다른 접근 방식의 기존 계정을
   자동 변환하지 않는다. 역할 설치가 없거나 신뢰 정책이 맞지 않으면 선택 후 권한 검사에서 중단한다.
4. 인증 후 읽은 조직의 ACTIVE 계정을 선택한다. 목록은 200개씩 추가로 읽으며 목록 조회만으로 계정·검사
   범위를 등록하지 않는다. 선택 계정별 STS 계정 일치·용도별 권한·S3 목록을 확인한 후 최종 승인 때
   계정과 선택 범위를 함께 저장한다. 임시 STS 자격증명·외부 오류 원문은 저장하지 않는다.

Organizations 밖의 독립 계정들은 AWS API로 함께 열거할 수 없다. 같은 **계정별 수집 역할 사용(권장)** 인증에서
직접 설정 링크를 열어 계정 ID를 지정하고, 표시된 계정별 역할 신뢰·ExternalId 설정을 대상 계정에 배포한다.
서버 역할은 그대로 유지하며 각 독립 계정의 scanner 역할로 AssumeRole한다. 이 경로에는 Organizations
권한이 필요 없고, 계정별 권한 확인과 최종 범위 승인을 거쳐야 수집할 수 있다.

온보딩 작업의 요청 100회·120초 예산은 그대로 적용한다. 많은 계정이나 버킷을 한 번에 선택해 예산을
넘으면 완료하지 않으며 범위를 나누어 연결해야 한다. 조직 목록 읽기가 부분 수집이면 이를 표시한다.
목록 조회는 리소스 접근 승인이나 선택하지 않은 계정의 수집 승인이 아니다.

## 기존 설치의 IAM Identity Center 로그인

이전 운영자 PC 설치(Compose, `AWS_CONFIG_DIR`)는 활성 프로필의 `sso-session` 로그인을 사용했다.
기존 연결의 점검·갱신 경로는 유지하지만 새 연결에서는 SSO·고객 측 CLI 인증을 선택할 수 없다.
기존 설치의 로그인이 없거나 만료되면 AWS 신원 화면의 "AWS에서 로그인"을 쓸 수 있다(`aws_sso_login.py`, 관리자만).
1인 설치(`AUTH_MODE=local`)에서만 동작한다(소유자 검토·승인 2026-10-02). 사람이 회사 IdP로 로그인하는 팀 설치는 시작·조회를
`409 AWS_SSO_LOGIN_SOLO_ONLY`로 거절하고 버튼을 보이지 않는다. 코드를 승인한 사람이 모두의 AWS 신원이 되기 때문이며, 팀 설치는
서버 역할(EC2 인스턴스·쿠버네티스 파드 역할)이나 기계 신원(회사 IdP)으로 AWS에 접근한다.

- API가 `aws sso login --use-device-code`와 같은 기기 인증을 한다: SSO OIDC `RegisterClient`(공개 클라이언트,
  `sso:account:access` 범위라 갱신 토큰이 온다) → `StartDeviceAuthorization`(프로필의 시작 URL) → 관리자가 AWS 접근 포털에서
  코드를 승인 → `CreateToken`(device_code).
- 토큰은 명령이 두는 곳, 즉 그 세션의 `~/.aws/sso/cache` 파일에 botocore의 캐시 작성기로 원자적으로 저장된다. 워커를 포함해
  그 캐시를 읽는 모든 프로세스가 전과 같이 쓰고 갱신한다. CreMore DB에는 토큰을 두지 않는다.
- 승인을 기다리는 동안의 비밀 부분(클라이언트 시크릿, 기기 코드)은 설치 설정에 봉인되어 시작한 관리자에게만 묶이고,
  끝나면(`DONE`·`EXPIRED`·`DENIED`·`FAILED`) 결과만 남는다. 감사 이벤트 `AWS_SSO_LOGIN_STARTED`·`AWS_SSO_LOGIN_<결과>`.
- 로그인이 없거나 만료됐을 때만 시작한다. 동작 중인 로그인은 여기서 바꾸지 않는다(`AWS_SIGN_IN_PRESENT`): 코드를 승인한
  사람이 곧 CreMore(와 같은 캐시를 쓰는 호스트 CLI)가 실행되는 신원이 되기 때문이다. 감사 이벤트 `AWS_SSO_LOGIN_DONE`의
  메모에 승인한 사용자의 세션 ARN이 남는다. 코드는 스캔에 필요한 권한 세트만 가진 전용 IAM Identity Center 사용자로 승인한다.
- 프로필에 `sso-session`이 없으면 `AWS_SSO_SESSION_REQUIRED`(한 번 `aws configure sso`), 캐시에 쓸 수 없으면
  `SSO_CACHE_NOT_WRITABLE`. AWS의 https 인증 링크만 보인다. 합성 OIDC로만 검증했다.

## Secrets Manager 보관 값 수집

`coverage.collect_aws_vault`는 기존 schema 1 고객 측 수집 경로를 사용한다.
Secrets Manager 목록·값 처리는 `secret_inventory.py`에 있고 SSM 경로·기존 공개 import는 유지한다.

관리자가 Secrets Manager·SSM 연결에 `server_collection=true`를 명시하면 같은 함수를 CreMore worker가
실행한다(선택적 `schedule_minutes`). [값 읽기 역할](#값-읽기-역할)을 지정하지 않은 연결은 계정 스캐너 세션으로 읽는다.
스캐너의 기본 `READ_OPERATIONS`는 그대로이며,
이 작업만 `aws_readonly.VAULT_OPERATIONS`(Secrets Manager 목록·메타데이터 + `get_secret_value`,
SSM `get_parameters_by_path`)로 감싼 클라이언트를 받는다. 쓰기·회전 API는 두 목록 모두에 없다.
고객은 수집 신원에 승인한 비밀 ARN·파라미터 경로에 한정한 `secretsmanager:GetSecretValue`
(이력 수집 시 `ListSecretVersionIds`, 목록 수집 시 `ListSecrets`)·`ssm:GetParametersByPath`와 해당 KMS 키의
`kms:Decrypt`를 부여해야 한다. CreMore가 주는 CloudFormation 스캐너 역할(`deploy/cloudformation/*.yaml`)은
`ScannerMutationDeny`로 `GetSecretValue`·`BatchGetSecretValue`를 명시적으로 거부하므로 그 역할에 허용을 더해도
Secrets Manager 값은 읽히지 않는다([명시적 거부 우선](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)).
마법사는 템플릿이 만든 수집 역할(`CredentialExposureScannerRole`)의 금고 대조를 `AWS_SCANNER_ROLE_DENIES_SECRET_VALUES`로,
Parameter Store 경로 대조를 `AWS_SCANNER_TEMPLATE_GRANTS_NO_PARAMETER_VALUES`(템플릿에 `GetParametersByPath`가 없음)로 알린다.
값을 읽어 권한을 확인하지 않으므로 다른 역할의 값 읽기 권한은 점검에서 미확인으로 남는다. 템플릿 역할로 서버에서
값을 대조하려면 아래 값 읽기 역할을 쓴다.
권한이 없으면 부분 수집으로 남고 부재로 판정하지 않는다.
`hash_value` 공통 탐지기에 값을 전달하므로 AWS 금고에 보관된 GitHub 등 다른 공급자의 자격증명도
원문 없이 해당 credential type·fingerprint로 반환된다. 실제 발견 자격증명을 외부 인증에 쓰지 않는다.

기본 `version_selector=latest`는 `GetSecretValue(VersionStage=AWSCURRENT)`이며,
`AWSPREVIOUS`나 다른 staging label도 지정할 수 있다. `include_previous_versions=true`는
먼저 AWSCURRENT를 수집한 다음 `ListSecretVersionIds(IncludeDeprecated=True)`를 페이지별로 읽고
추가 버전을 `VersionId`로 고정해 수집한다. 기본 한도 `max_versions_per_secret=20`은 현재 버전을
포함하며, 초과하면 `SECRET_VERSION_LIMIT`로 PARTIAL이다. 이력 옵션과 별도 stage selector를
동시에 지정하지 않는다. Stage가 AWSCURRENT/AWSPREVIOUS라고 공급자가 반환한 경우에만
CURRENT/PREVIOUS이며, label 없는 과거 버전은 UNKNOWN이다.

SecretString은 문자열, boto3 SecretBinary는 이미 decode된 bytes로 처리한다. 임의 binary를
비밀로 가정하지 않으며 UTF-8/탐지기 미지원은 기존 unresolved 근거로 남긴다. 비밀 원문이나
공급자의 오류 응답을 observation/log에 저장하지 않는다. 반환 ARN과 요청 계정·리전·full ARN,
명시 VersionId/VersionStage 일치를 검사한다. 명시 reference는 그 ARN의 리전에만 전달한다.
잘못된/누락된 목록 shape, 반복 cursor, 권한 거절, 요청·레코드 한도는 빈 COMPLETE가 아니다.
이력 조회가 실패해도 이미 지문화한 현재 버전 관측은 보존한다. SDK/API 목록은 원자적 snapshot이
아니고, Secret 회전·stage 이동·삭제가 수집 도중 발생할 수 있으므로 전 계정 전체 자격증명 보관의
영구적 완전성을 증명하지 않는다. ListSecrets는 최근 변경의 반영이 지연될 수 있다.

2026-09-25 공식 문서 직접 확인:

- [ListSecrets](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html): 계정·리전의 목록, NextToken 및 eventual consistency.
- [ListSecretVersionIds](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecretVersionIds.html): 버전 목록, IncludeDeprecated와 별도 조회 권한.
- [GetSecretValue](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html): VersionId/VersionStage, SecretString/SecretBinary, `secretsmanager:GetSecretValue` 및 고객 KMS 키 사용 시 `kms:Decrypt`.

기본 수집에 목록 조회 권한, 과거 버전 추가에는 `secretsmanager:ListSecretVersionIds` 권한이 필요하다.
명시 ARN만 지정하면 전체 ListSecrets 권한은 필요하지 않다. 그 수집은 목록을 읽지 않으므로 끝까지 읽었다는 근거를
`OPERATOR_DECLARED`(운영자가 적은 목록 기준, 금고 화면의 "운영자가 전체라고 선언함")로 기록한다. 그 금고가 들어간
"금고에 없음" 판정도 이 근거를 단다([범용 금고](../docs/EXTERNAL_VAULT.md) 1절). 고객의 실제 IAM/KMS 정책과 운영 계정 호출은
합성 테스트로 검증되지 않았으며, 전용 fake-client 테스트가 계정·리전·응답·version·페이지 경계를 검증한다.

### 값 읽기 역할

[설계](../docs/AWS_VAULT_VALUE_READER_DESIGN.md)의 선택지 B다(2026-10-08 구현, 실계정 미검증). 수집 역할(스캐너)은 계속
값을 읽지 못하고, 금고 수집 작업만 같은 계정의 별도 값 읽기 역할을 역할 연쇄로 맡아 값을 읽는다.

- **역할이 하는 일**: 스택에 적은 `VaultSecretArns`의 `secretsmanager:GetSecretValue`·`DescribeSecret`·`ListSecretVersionIds`,
  `VaultParameterPathArns`의 `ssm:GetParametersByPath`, `VaultKmsKeyArns`의 `kms:Decrypt`(`kms:ViaService`가
  `secretsmanager.*.amazonaws.com`·`ssm.*.amazonaws.com`, 중국 파티션은 `….amazonaws.com.cn`일 때만)뿐이다. 시크릿 목록(`ListSecrets`)은 없다.
  목록 밖의 시크릿은 명시적으로 거부한다(`VaultValueReaderListedSecretsOnly`, 목록이 비면 모든 시크릿). 그래서 조직 전체에 열린
  리소스 정책(Principal `*`와 `aws:PrincipalOrgID`)을 가진 시크릿도 목록에 없으면 읽지 못한다. KMS에는 이런 거부를 두지 않는다
  (AWS 관리형 키는 목록에 없다). 스캐너의 변경 거부 목록(값 읽기만 뺌), 쓰지 않는 값 읽기(`BatchGetSecretValue`, `ssm:GetParameter`·
  `GetParameters`·`GetParameterHistory`), Parameter Store 변경(`PutParameter`·`DeleteParameter*`·라벨·태그·리소스 정책)도 거부한다
  (`VaultValueReaderDeny`). 같은 스택의 스캐너 역할 ARN만 기존 `ExternalId`로 맡을 수 있다. `GetParametersByPath`는 요청한 경로로
  인가되므로 경로 ARN은 `…:parameter/prod`와 `…:parameter/prod/*`를 함께 적는다.
- **켜기**: 마법사의 금고 대조에서 "별도 값 읽기 역할로 값 읽기"를 켜고 역할 이름(기본 `CredentialVaultValueReaderRole`)·
  시크릿 전체 ARN(끝의 여섯 글자 포함, 계정마다 하나 이상)·고객 관리형 KMS 키 ARN(같은 계정)을 적는다. 설정 도우미의 역할 만들기
  명령·설정값·CloudFormation 링크(연동 대상 현황의 계정별 배포 포함)에 `EnableVaultValueRead=true`와 그 계정의 목록(Parameter Store 경로는
  고른 리전마다)이 채워져 처음 배포 때 함께 만들어진다. 이미 배포한 스택은 같은 `aws cloudformation deploy` 명령으로 갱신한다(빠진 매개변수는
  기존 값을 쓴다). `single-account.yaml`은 스캐너 신뢰에 ExternalId가 없어 켤 때 CreMore가 그 계정에 등록한 ExternalId를 `ExternalId`로
  줘야 한다. StackSet(조직)은 계정마다 ARN이 달라 계정별 매개변수 재정의가 필요하며 조직 안내 명령은 이를 채우지 않는다.
- **계획 검사**: 계획을 정규화할 때(점검 요청·활성화·계획 변경, `cremore.onboarding.targets.normalize_plan`이 부르는 `plan_problem`)
  연결의 모든 대상 계정을 한꺼번에 보고 거절한다. 계정별 수집 역할이 아닌 연결(`VALUE_READER_NEEDS_ROLE_ACCESS`), 잘못된 역할
  이름(`VALUE_READER_ROLE_INVALID`)·시크릿 ARN(`AWS_SECRET_ARNS_INVALID`)·KMS 키(`AWS_KMS_KEY_ARNS_INVALID`), 연결 계정이나 고른 리전
  밖의 시크릿(`AWS_SECRET_ARN_OUTSIDE_SCOPE`)·키(`AWS_KMS_KEY_ARN_OUTSIDE_SCOPE`), 시크릿이 없는 계정(`AWS_SECRET_ARNS_REQUIRED`), 역할 정책이
  IAM 한도를 넘는 계정(`AWS_VALUE_READER_POLICY_TOO_LARGE`)이다. Parameter Store 접두어는 값 읽기 역할과 상관없이 모든 금고 계획에서
  구간마다 영문·숫자와 `._-`만, `.`·`..`가 아닌 구간만 받는다(`AWS_PARAMETER_PATH_INVALID`). 연동 입력란은 `~@+=:`도 받지만 SSM 이름과
  스택은 받지 않아, 읽으면 그 리전 수집이 실패하고 스택에도 적을 수 없기 때문이다. `.`·`..` 구간은 CreMore 수집 범위 규칙
  (`cremore/coverage/models.py`의 `scope_path`)이 받지 않는다. 역할의 인라인 정책은 합쳐서 10,240자(공백 제외)이고 고정 부분이 약 2,900자다.
  시크릿 ARN은 허용과 목록 밖 거부에 두 번, 경로는 `/*`와 함께, 키는 한 번 들어가므로 계정마다 이 목록이 6,500자를 넘으면 거절한다.
  보통 길이(약 90자)의 시크릿은 계정당 30개 정도다. 하위 레코드는 대상마다 그 계정의 ARN만 가지며, 나중에 자동 발견으로 들어온 계정은
  다른 계정의 ARN을 무시하고 적은 시크릿이 없으면 Secrets Manager를 대조하지 않는다.
- **수집**: spec의 `value_reader_role`이 있으면 `cremore/coverage/job.py`가 첫 값 읽기 때 `AccountSessions.value_reader`로
  스캐너 세션을 지금처럼 연 뒤(승인·계정 접근·신원 검사 모두, 계정 접근 방식은 자격증명을 받기 전에 확인)
  `arn:<partition>:iam::<계정>:role/<이름>`을 그 자격증명과 ExternalId로 맡는다(900초, `RoleSessionName=cremore-vault-<수집 연결 ID>`로
  CloudTrail에서 구별). 맡은 계정을 확인하고 클라이언트는 `VAULT_OPERATIONS`만 허용한다. 계정별 수집 역할(`ROLE`)만 되며 다른 접근 방식은
  `VALUE_READER_NEEDS_ROLE_ACCESS`다. 요청마다 만료 5분 전이면 다시 맡으므로 만료된 자격증명으로 읽지 않는다. 맡기 실패
  (`VALUE_READER_ASSUME_DENIED`, `AWS_LOGIN_REQUIRED`, `AWS_ACCESS_REVISION_CHANGED`)는 실행의 이유 코드로 남는 부분·실패 수집이며 부재
  근거가 아니다. Secrets Manager는 적은 ARN만 읽고 모두 읽었을 때만 완전하다.
- **주기 수집**: 값 읽기 역할로 읽는 금고는 연결 자신의 주기(5분 이상)에 더해 설치의 스케줄 잠금(`SCAN_SCHEDULES_MODE`), 계정
  스캐너 승인, 기능 중지, 그리고 설치의 AWS 자동 수집 설정(`/api/v1/settings/aws-credential-inventory`의 `enabled`와 `account_ids`)이
  이 계정을 허용할 때만 주기로 돈다(소유자 결정 2026-10-08). 이 설정이 계정을 허용하지 않으면 예약하지 않고, 대기열 넣기·실행 시작·
  실행 중 확인에서 `VALUE_READER_AUTOMATION_DISABLED`로 거절한다. 요청할 때의 수집은 이 설정과 무관하다. 값 읽기 역할이 없는
  `schedule_source=connection` 수집은 지금처럼 이 설정을 보지 않는다.
- **권한 확인**: 값과 목록을 읽지 않는다(값 읽기 역할을 켜면 스캐너의 `secrets_list`·`ssm_list` 점검은 묻지도 요구하지도 않으므로
  목록 권한이 없는 `single-account.yaml`도 활성화할 수 있다). 스캐너가 값 읽기 역할을 맡아 신뢰를 확인하고(실패하면 그 코드로 거부),
  스캐너의 `iam:SimulatePrincipalPolicy`로 그 역할의 정책을 계정에 적은 모든 시크릿의 `GetSecretValue`와 모든 경로·리전의
  `GetParametersByPath`에 대해 자원별로 시뮬레이션한다(호출당 20개). 모두 허용이면 확인이고, 하나라도 허용하지 않으면 거부다.
  스택 목록에 없는 경우(목록 밖 거부 포함)는 `VALUE_READER_POLICY_DENIES`, 권한 경계·SCP·다른 명시적 거부는
  `VALUE_READER_POLICY_EXPLICITLY_DENIED`, 조건 값 부족·조회 실패·잘린 응답은 미확인이다. 점검 항목에는 코드만 남으므로 거부된 자원
  수는 나오지 않는다. 시크릿의 리소스 정책, KMS 키 정책과 실제 복호화는 시뮬레이션이 확인하지 않는다.
  `implicitDeny`도 IAM의 `AllowedByPermissionsBoundary=false` 또는 `AllowedByOrganizations=false` 근거가 있으면
  `VALUE_READER_POLICY_EXPLICITLY_DENIED`로 분류한다. 자원별 `ResourceSpecificResults`가 있으면 그 판단을 사용한다.
- **한계**: 역할 연쇄 세션은 최대 1시간이다. KMS는 Secrets Manager·Parameter Store를 거친 복호화만 되고, 고객 관리형 키는
  `VaultKmsKeyArns`에 적어야 한다(AWS 관리형 키는 필요 없다). 값 읽기 역할을 끄면 스캐너가 다시 읽게 되므로 권한 확인을 통과해야
  한다(템플릿 역할이면 금고 기능을 중지한다). 실제 AWS 계정에서 배포·호출을 검증하지 않았다.
