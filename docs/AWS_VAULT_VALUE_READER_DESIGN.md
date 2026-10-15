# AWS 금고 값 대조용 값 읽기 역할 (설계안)

> 작성 2026-10-08. **상태: 결정됨(2026-10-08, 6절), 구현됨(실계정 미검증, 2026-10-08, 7절).**
> 관련 규칙: [값 읽기 정책(제안)](SECRET_VALUE_READING_POLICY.md), [AWS 공급자](../aws/README.md),
> AGENTS.md의 AWS 공동 검토 모듈(`aws_access`·`aws_sessions`·`worker_session`).

## 1. 지금 막혀 있는 것

- AWS Secrets Manager·Parameter Store 서버 수집(`server_collection=true`)은 **계정 스캐너 세션**으로 값을 읽는다.
  `cremore/coverage/job.py`가 `aws_sessions.open(account, SCANNER)`로 세션을 열고, 이 작업에만
  `aws_readonly.VAULT_OPERATIONS`(`get_secret_value`, `get_parameters_by_path`)를 허용한 클라이언트를 준다.
- CreMore가 배포하는 스캐너 역할(`deploy/cloudformation/member-account-role.yaml`, `single-account.yaml`)은
  `ScannerMutationDeny`에서 `secretsmanager:GetSecretValue`·`BatchGetSecretValue`를 **명시적으로 거부**한다.
  명시적 거부는 어떤 허용으로도 풀리지 않으므로, 템플릿 역할로는 Secrets Manager 값 대조가 항상 실패한다.
  연결 점검은 이것을 `AWS_SCANNER_ROLE_DENIES_SECRET_VALUES`로 알린다(`aws/backend/cremore_aws_provider/onboarding.py`).
- Parameter Store는 템플릿 역할에 `ssm:GetParametersByPath`가 없다(`member-account-role.yaml`은 이름 목록
  `ssm:DescribeParameters`만, `single-account.yaml`은 Parameter Store 권한 자체가 없다).
  KMS는 `EnableKmsDecrypt=true`일 때 지정한 키에 조건 없는 `kms:Decrypt`만 준다.
- 값 읽기 정책 3.4는 "가능하면 신원을 나눈다"를 권하지만, 현재 AWS 서버 수집은 스캐너 역할을 함께 쓰고
  별도 신원을 지원하지 않는다. 서버가 값 권한을 가지면 안 되는 환경에는 고객 측 CLI 수집을 안내한다.

## 2. 목표와 지킬 것

- 스캐너 세션은 계속 값을 읽지 못한다(현재 거부를 유지).
- 값은 금고 수집 작업에서만, 별도 역할로, 승인한 정확한 시크릿·경로·키에서만 읽는다.
- 값 처리 계약은 바꾸지 않는다: 메모리에서 HMAC 지문만 남기고 원문·가역 형태를 저장하지 않는다.
- 고객 측 CLI 수집(값이 고객 환경에 머묾)은 계속 대안으로 둔다.

## 3. 선택지

| | A. 현재 유지 | B. 스캐너에서 역할 연쇄 (권장) | C. 별도 승인 목적 |
|---|---|---|---|
| 서버가 읽는 값 | 없음(고객 CLI만) | 값 읽기 역할을 만든 계정의 지정 대상만 | 같음 |
| 승인·DB 변경 | 없음 | 스캐너 승인을 그대로 씀, DB 변경 없음 | `aws_access`에 새 목적, 계정 테이블 열·마이그레이션, 승인 화면 |
| 값 역할을 맡는 주체 | — | 같은 계정의 스캐너 역할만 | 워커 신원(또는 값 전용 워커)을 직접 신뢰 |
| 분리 수준 | 가장 높음 | 스캐너 세션 자체는 값 권한 없음. 스캐너가 값 역할을 맡을 수 있음 | 스캐너와 완전히 분리 |
| 작업량 | 없음 | 중간 | 큼 |

## 4. 권장안 B의 구성

### 4.1 CloudFormation (`member-account-role.yaml`, `single-account.yaml`)

새 매개변수(모두 기본 꺼짐): `EnableVaultValueRead`(`false`), `VaultValueReaderRoleName`
(`CredentialVaultValueReaderRole`), `VaultSecretArns`, `VaultParameterPathArns`, `VaultKmsKeyArns`(쉼표 목록).

새 역할(조건 `EnableVaultValueRead`):

- **신뢰:** 같은 계정의 스캐너 역할 ARN 하나와 기존 `ExternalId`. `MaxSessionDuration: 3600`.
- **허용:**
  - `secretsmanager:GetSecretValue`·`DescribeSecret`·`ListSecretVersionIds` → `VaultSecretArns`만.
  - `ssm:GetParametersByPath` → `VaultParameterPathArns`만. 이 작업은 반환되는 파라미터가 아니라 **요청한 경로**로
    인가되므로 경로 ARN(예: `arn:aws:ssm:*:123456789012:parameter/prod`)을 그대로 지정한다.
    수집기는 `Path="/<prefix>", Recursive=True, WithDecryption=True`로 읽는다(`aws/backend/cremore_aws_provider/coverage.py`).
  - `kms:Decrypt` → `VaultKmsKeyArns`만, 조건 `kms:ViaService`가 `secretsmanager.*.amazonaws.com` 또는
    `ssm.*.amazonaws.com`일 때(서비스를 거친 복호화만, 임의 암호문 복호화 불가).
- **거부:** 스캐너와 같은 변경 작업 목록, 쓰지 않는 값 읽기 경로
  (`secretsmanager:BatchGetSecretValue`, `ssm:GetParameter`·`GetParameters`·`GetParameterHistory`).

스캐너 역할 추가(조건 `EnableVaultValueRead`): `sts:AssumeRole` → 값 읽기 역할 ARN 하나만.

### 4.2 코드 (플랫폼, AWS 공동 검토 모듈 포함)

- `aws_sessions`: 스캐너 세션에서 같은 계정의 값 읽기 역할로 AssumeRole한다. 세션 이름에 연결 ID를 넣어
  CloudTrail에서 구별한다. 그 세션으로는 `VAULT_OPERATIONS` 클라이언트만 만든다.
- `cremore/coverage/job.py`: 금고 서버 수집 연결에 값 읽기 역할이 지정되면 그 세션으로 읽는다. 지정이 없으면
  지금처럼 스캐너 세션으로 읽는다(템플릿 역할이면 거부). 역할 연쇄 세션은 최대 1시간이므로 체크포인트마다
  남은 시간을 보고 다시 맡는다. 스캐너 승인·계정 승인·기능 중지 확인은 그대로 적용한다.
- 온보딩(AWS 금고 목적): 옵션 "값 읽기 역할 사용", 역할 이름(기본값), 대상 시크릿 ARN·경로.
  연결 점검은 **값을 읽지 않고** 확인한다.
  1. 스캐너 → 값 읽기 역할 AssumeRole 성공(데이터 읽기 없음)
  2. 값 읽기 역할에 대한 `iam:SimulatePrincipalPolicy`로 첫 시크릿 ARN의 `GetSecretValue`, 첫 경로의
     `GetParametersByPath` 허용 여부
- 연결 안내: 대상 목록으로 CloudFormation 매개변수 값을 채운 스택 갱신 명령.
- 테스트: 가짜 STS·Secrets Manager·SSM으로만. 실계정 호출 없음.

### 4.3 조직(StackSet)

계정마다 시크릿 ARN이 달라 StackSet 매개변수 재정의가 필요하다. 대안은 태그 기반(ABAC)이다:
`cremore:compare=true` 태그가 달린 시크릿만 `secretsmanager:ResourceTag/cremore:compare` 조건으로 허용한다.
이 경우 태그를 바꿀 수 있는 사람이 대상에 넣을 수 있으므로 SCP로 그 태그의 변경을 제한해야 한다.

## 5. 위험과 완화

| 위험 | 완화 |
|---|---|
| 워커가 값 읽기 역할을 맡을 수 있다 | 대상 ARN·경로·키 한정, 목록 밖 시크릿의 명시적 거부(리소스 정책으로 넓어지지 않음), KMS 서비스 경유 조건, 주기 실행은 연결 자신의 주기에 더해 설치의 AWS 자동 수집 설정이 그 계정을 허용하고 계정 승인·스케줄 잠금·기능 중지가 모두 허용할 때만(6절 결정 3), CloudTrail 세션 이름, 연결별 켜기 기록(값 읽기 정책 3.2) |
| 역할 연쇄 세션 1시간 한도 | 체크포인트마다 남은 시간 확인 후 다시 맡기 |
| 기존 스택은 새 역할이 없다 | 스택 갱신 안내, 역할 지정이 없으면 지금 동작 그대로 |
| 태그 기반을 고르면 태그 조작으로 대상이 늘 수 있다 | SCP로 태그 변경 제한, 또는 ARN 목록 방식 |

## 6. 결정 (2026-10-08, 담당자)

1. 선택지: **B**(스캐너에서 같은 계정의 값 읽기 역할로 역할 연쇄).
2. 대상 지정: **ARN·경로·키 목록**(스택 매개변수). 태그 기반(ABAC)은 쓰지 않는다.
3. 주기 수집: **허용**. 연결 자신의 주기(값 읽기 정책 3.6의 5분 이상)에 더해 설치의 AWS 자동 수집 설정
   (`/api/v1/settings/aws-credential-inventory`의 `enabled`와 `account_ids`)이 그 계정을 허용하고, 계정 스캐너 승인, 스케줄 잠금
   (`SCAN_SCHEDULES_MODE`), 기능 중지가 모두 허용할 때만 주기로 돈다. 설정이 계정을 허용하지 않으면 `VALUE_READER_AUTOMATION_DISABLED`로
   거절한다(`cremore/coverage/aws_scheduling.py`의 `scheduled_refusal`과 주기 예약). 요청할 때의 수집은 이 설정과 무관하다.
   값 읽기 역할이 없는 `schedule_source=connection` 수집은 이 설정을 보지 않는다(AGENTS.md 계약 그대로).
4. 켜기 승인: **AWS 계정 관리자의 스택 배포**(`EnableVaultValueRead`와 대상 목록)와 **CreMore 관리자의 연결 옵션 켜기**를
   두 승인으로 본다. CreMore 안에 별도의 두 번째 승인 흐름은 두지 않는다. 이유와 기간은 팀 변경 기록에 남긴다
   (CreMore에는 켠 사람이 감사 기록으로 남는다). 1인 설치에서도 같은 방식이다.
5. 배포 시점: 값 읽기 역할은 **처음 스택을 만들 때 함께 만든다.** 연결 마법사에서 금고 대조와 대상을 고르면 역할 생성
   명령에 그 매개변수를 채워 준다. 스택 갱신은 이미 배포한 계정에 더하거나 대상을 바꿀 때만 쓴다. 권한은 수집 역할에
   직접 주지 않고 별도 역할에 둔다(수집 세션은 계속 값 권한이 없다).
6. 완전성 근거: 적은 시크릿 ARN만 읽는 Secrets Manager 수집은 목록을 읽지 않으므로 `OPERATOR_DECLARED`(운영자가 적은 목록
   기준)로 기록한다(`cremore/coverage/store.py`, 같은 이유로 `references`를 준 GCP Secret Manager 수집도). 경로 아래를 API로
   나열하는 Parameter Store는 `API_LISTING` 그대로다.

## 7. 구현 (2026-10-08, 실계정 미검증)

4절을 다음과 같이 구현했다. 4절과 달라졌거나 정한 세부만 적는다. 운영 안내는 [AWS 공급자](../aws/README.md#값-읽기-역할)에 있다.

- **템플릿**: 두 템플릿 모두 4.1의 매개변수와 `VaultValueReaderRole`을 두고 스택 설명에 값 읽기 역할을 적는다. 목록마다 조건
  (`HasVaultSecretArns` 등)으로 정책을 나눠 빈 목록이면 그 정책을 빼고, 매개변수 패턴이 와일드카드 시크릿·키와 경로 전체(`parameter/*`)를
  거절한다. 시크릿 ARN 패턴은 서버와 같다(알려진 파티션 `aws`·`aws-us-gov`·`aws-cn`·`aws-eusc`와 끝의 여섯 글자).
  거부 정책(`VaultValueReaderDeny`)은 스캐너 목록에서 `GetSecretValue`만 뺀 것(그대로 두면 역할이 값을 못 읽는다)에
  `ssm:GetParameter`·`GetParameters`·`GetParameterHistory`와 Parameter Store 변경을 더한다. 4.1의 허용은 역할 자신의 정책일 뿐이라
  조직 전체에 열린 리소스 정책의 시크릿도 읽을 수 있으므로 `VaultValueReaderListedSecretsOnly`가 목록 밖 시크릿(목록이 비면 전부)의
  세 작업을 거부한다. KMS에는 두지 않는다(AWS 관리형 키). `kms:ViaService`는 중국 파티션의 `….amazonaws.com.cn`도 받는다.
  `single-account.yaml`은 스캐너 신뢰에 ExternalId가 없어 선택 매개변수 `ExternalId`를 더했고, 켤 때 빈 값을 Rule이 거절한다.
- **세션**: 값 읽기 역할은 `aws_sessions.chain_value_reader`로만 맡는다. 등록 계정은 `AccountSessions.value_reader(account, role_name, label)`이
  스캐너 세션을 지금처럼 연 뒤(접근 방식이 `ROLE`이 아니면 자격증명을 받기 전에 `VALUE_READER_NEEDS_ROLE_ACCESS`) 부르고, 아직 등록 전인
  초안의 점검은 `onboarding_roles.open_reader`가 초안의 스캐너 세션과 ExternalId로 부른다. 같은 파티션·계정의 역할을 그 자격증명·
  ExternalId·`DurationSeconds=900`·`RoleSessionName=cremore-vault-<label>`로 맡고 맡은 계정을 확인한다. `via`는 `VALUE_READER_ROLE`이며
  그 세션의 클라이언트는 목적과 상관없이 `VAULT_OPERATIONS`로만 감싼다. 맡기 실패는 `VALUE_READER_ASSUME_DENIED`, 잘못된 이름은
  `VALUE_READER_ROLE_INVALID`다. 캐시하지 않는다.
- **수집**: schema 1 `ConnectionSpec.value_reader_role`(AWS 서버 수집만)이 있으면 `cremore/coverage/job.py`가 첫 값 읽기 때 역할을
  맡고, 요청마다 남은 시간이 5분 이하면 다시 맡는다(4.2의 "체크포인트마다"를 요청 단위로 했다). 실패는 실행의 이유 코드가 된다.
  Secrets Manager는 기존 `references`(정확한 시크릿 ARN)를 비교 범위로 쓰고 값 읽기 역할이면 필수다(목록 조회 없음).
- **온보딩**: 금고 계획에 `value_reader`·`value_reader_role`·`secret_arns`·`kms_key_arns`. 계획 정규화 때 모든 대상 계정을 함께 보고
  (`plan_problem`) 계정별 수집 역할, ARN·키의 형식과 계정·리전, 계정마다 시크릿 하나 이상, 역할 정책 크기(계정마다 목록 6,500자,
  IAM 인라인 한도 10,240자)를 검사한다. Parameter Store 경로 형식(구간마다 `[A-Za-z0-9_.-]`, `.`·`..` 구간 없음,
  `AWS_PARAMETER_PATH_INVALID`)은 값 읽기 역할과 상관없이 모든 금고 계획에서 검사한다. 하위 레코드는 그 계정의 ARN만 가지고 다른 계정의 ARN은 무시하므로, 자동 발견으로 나중에 들어온
  계정의 인계가 막히지 않는다(시크릿이 없으면 Secrets Manager를 대조하지 않는다). 값 읽기 역할을 켜면 스캐너의 목록 점검
  (`secrets_list`·`ssm_list`)은 `unless: value_reader`로 요구하지도 묻지도 않는다. 점검은 맡기→시뮬레이션이며 적은 모든 시크릿과 모든
  경로·리전을 자원별로 시뮬레이션한다(호출당 20개, 하나라도 허용하지 않으면 거부). 스택 목록 밖이면 `VALUE_READER_POLICY_DENIES`,
  권한 경계·SCP·다른 명시적 거부는 `VALUE_READER_POLICY_EXPLICITLY_DENIED`다. 역할 생성 명령·설정값과 CloudFormation 링크는 설정
  도우미와 연동 대상 현황이 계획으로 채운다. 값 읽기 역할 항목은 `value_reader`를 켰을 때만 보인다.
- **하지 않은 것**: StackSet 안내 명령의 계정별 매개변수, 시뮬레이션에서 리소스·KMS 키 정책 확인, 점검 항목에 거부된 자원 수 표시
  (점검 결과는 코드만 담는다), 실계정 배포·호출 검증.

## 근거

- [Parameter Store가 값 조회를 인가하는 방식](https://docs.aws.amazon.com/systems-manager/latest/userguide/ps-retrieval-authorization.html):
  `GetParametersByPath`는 요청한 경로로 인가된다(2026-10-08 확인).
- IAM 정책 평가에서 명시적 거부는 허용보다 우선한다.
- 역할 연쇄 세션은 최대 1시간이다(IAM 역할 사용 문서).
