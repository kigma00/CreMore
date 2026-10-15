# AWS 계정별 인벤토리와 선택적 Control Tower 연동

단일 계정, 여러 독립 계정, Organizations 전체·선택 OU 계정은 같은 계정별 IAM 인벤토리
수집기를 사용한다. 계정 발견은 접근 승인이 아니다. 계정 등록, scanner 신원 승인,
역할·ExternalId·실제 대상 계정 검증을 통과한 계정만 수집한다.

## 자동 수집 설정

관리자가 `/api/v1/settings/aws-credential-inventory`에서 설정한다. 새 설치와 업그레이드 모두
`enabled=false`다. `SCAN_SCHEDULES_MODE=disabled`는 자동 수집을 잠근다.

| 필드 | 기본값·의미 |
| --- | --- |
| `enabled` | `false`; 자동 IAM 인벤토리 생성·최초 수집·반복 수집을 허용 |
| `interval_minutes` | `1440`; 5~10080분 |
| `account_ids` | `[]`; 모든 **승인된 등록 계정**. 선택 시 12자리 AWS 계정 ID 목록이며 내부 UUID가 아님 |
| `cloudtrail_enabled` | `false`; 선택한 관측 범위의 세션 발급·사용 수집 |
| `regions` | `[]`; CloudTrail을 켜면 명시해야 하는 리전 목록 |
| `window_days` | `7`; Event History는 최대 90일, S3 로그는 최대 3650일 |
| `cloudtrail_source` | `event_history` 또는 `s3` |
| `trail_bucket`, `trail_prefixes` | S3 로그 모드의 명시적 버킷·비어 있지 않은 prefix 범위 |

IAM·CloudTrail 연결과 작업은 계정별로 분리된다. 이미 실행 중인 해당 연결의 작업은 재사용한다.
CloudTrail 로그에 다른 계정의 이벤트가 포함돼도 각 계정 수집기의 범위를 넓히지 않는다.
수동 새로고침은 자동 수집 switch와 별개지만 같은 승인·연결·작업 중복 검사를 사용한다.
명시적으로 비활성화한 연결은 자동으로 다시 활성화하지 않는다.

Organizations 설정은 기존 `/api/v1/settings/aws-organizations`를 사용한다.
`auto_validate`를 켜면 신규 계정과 역할 준비가 지연돼 검증에 실패한 계정을 후속 sweep에서 검증한다.
제외·OU 범위 이탈·조직 탈퇴·비활성 계정은 이후 수집이 차단되며 기존 계정과 관측은 보존된다.
OU 정보 조회가 거절되거나 일부만 성공하면 이전 성공 경로를 보존하고 `PARTIAL`로 표시한다.

## 중앙 S3 CloudTrail 로그 범위

S3 모드는 각 **대상 계정의 승인된 scanner role**로 `ListObjectsV2`와 `GetObject`를 호출한다.
별도 로그 계정 역할을 자동으로 assume하지 않는다. `member-account-role.yaml`과
`single-account.yaml`에는 S3 목록·객체 읽기 identity policy가 있으나, 다른 계정의 중앙 로그 버킷은
버킷 소유자가 해당 scanner role을 resource policy에 허용해야 한다. 조직 가입이나 앱 설정만으로
cross-account 권한이 생기지 않는다. 다음은 합성 계정의 한 디렉터리만 허용하는 버킷 정책 예다.
실제 버킷·partition·role·prefix로 바꾸고 기존 CloudTrail 쓰기 정책에 병합한다.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListApprovedAccountTrail",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111111111111:role/CredentialExposureScannerRole"},
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::example-central-trail",
      "Condition": {"StringLike": {"s3:prefix": ["AWSLogs/o-example/111111111111/CloudTrail/*"]}}
    },
    {
      "Sid": "ReadApprovedAccountTrail",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111111111111:role/CredentialExposureScannerRole"},
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example-central-trail/AWSLogs/o-example/111111111111/CloudTrail/*"
    }
  ]
}
```

이 예의 연결은 `trail_bucket=example-central-trail`,
`trail_prefixes=["AWSLogs/o-example/111111111111/CloudTrail"]`를 사용한다.
조직 trail의 실제 객체 경로와 승인된 리전을 먼저 대조한다. 계정마다 서로 다른 최소 prefix가
필요하면 계정별 CloudTrail 연결에 지정한다. 전역 자동 수집 설정의 prefix는 선택한 계정들에
공통 적용되며 계정 ID template을 자동 치환하지 않는다. 필요한 리전·기간 디렉터리로 좁히면
과거 로그가 요청·객체 예산을 먼저 소진하는 것을 줄인다. 예산 소진은 불완전 수집으로 표시한다.

SSE-KMS 로그에는 정확한 customer-managed key에 대한 scanner `kms:Decrypt` identity policy와
KMS key policy의 cross-account 허용이 추가로 필요하다. 멤버 템플릿은
`EnableKmsDecrypt=true`와 실제 `KmsKeyArns`를 명시하며 기본 sentinel을 교체해야 한다.
단일 계정 템플릿은 이 선택 입력을 제공하지 않으므로 운영자가 해당 역할의 정확한 키 권한을
별도로 관리한다. KMS·버킷 정책 거절을 빈 목록이나 로그 부재로 처리하지 않는다.

## Control Tower 정보 조회

Organizations 설정의 `control_tower_enabled=false`가 기본값이다. 켤 때
`control_tower_region`에 **Control Tower 홈 리전**을 명시한다.
관리 계정 ID는 `organizations:DescribeOrganization`, OU 관계는
`ListRoots`·`ListAccountsForParent`·`ListOrganizationalUnitsForParent`에서 읽는다.

Control Tower 호출은 별도로 등록·승인·검증된 **관리 계정의 scanner session**을 사용한다.
Organizations delegated administrator라는 사실만으로 관리 계정의 Control Tower 접근이
허용되지는 않는다. 관리 계정이 제외돼 있다면 자동 등록하지 않으므로 필요한 경우 별도로 등록한다.
접근이 불가능하면 Control Tower context에 실패를 표시하고 다른 계정의 IAM 수집은 계속한다.

사용할 관리 계정 역할 템플릿의 `EnableControlTowerContext=true`는 다음 읽기 권한을 추가한다.
기본값은 `false`다. 역할 설치와 승인은 운영자가 수행하며 애플리케이션이 권한을 배포하지 않는다.

- `controltower:ListBaselines`
- `controltower:ListEnabledBaselines`
- `controltower:GetEnabledBaseline`

`AWSControlTowerBaseline`만 등록 근거로 사용한다. ConfigBaseline·BackupBaseline 등 다른 baseline을
OU 등록 근거로 세지 않는다. `ListEnabledBaselines(includeChildren=true)`와 `GetEnabledBaseline`을
통해 OU와 계정 child baseline 상태를 별도로 읽는다. 등록 OU에 속한다는 사실만으로 해당 계정의
enrollment 성공을 추정하지 않으며, 목록에서 관측하지 못한 경우는 `NOT_OBSERVED`다.

## 계정 준비 이벤트

선택적으로 [control-tower-events.yaml](control-tower-events.yaml)을 **관리 계정·홈 리전**에 배포한다.
활성 CloudTrail trail의 logging이 필요하다. 이 템플릿은 별도 전용 SQS queue, DLQ, EventBridge rule을
만들며 다른 업무 queue를 재사용하지 않는다. `ConsumerRoleArn`은 정확한 worker IAM role ARN이다.

중앙 worker의 identity policy에도 출력된 queue ARN에 대한 `sqs:ReceiveMessage`,
`sqs:DeleteMessage`, `sqs:GetQueueAttributes`가 필요하다. `security-account.yaml`의 선택적
`ControlTowerLifecycleQueueArn`으로 이 권한을 지정할 수 있다. Cross-account queue 사용 시
identity policy와 템플릿 queue resource policy 둘 다 필요하다.

Organizations 설정에 출력된 URL을 `lifecycle_queue_url`로 저장하고
`lifecycle_queue_acknowledged=true`로 전용 queue임을 확인한다. Queue 리전은 Control Tower 홈
리전과 같아야 하며 콘텐츠 스캔 SQS queue와 같은 URL을 사용할 수 없다.
`SCAN_SQS_MODE=disabled`는 이 소비도 잠근다. DLQ에 쌓인 미지원·실패 이벤트는 운영자가 확인한다.

지원하는 이벤트는 `CreateManagedAccount`, `UpdateManagedAccount`, OU 등록/해제,
baseline enable/reset/update/disable의 성공 완료 이벤트다. Source, management account, home region,
CloudTrail service-event 형식과 완료 상태를 검증한다. 원문 이벤트나 API 응답은 저장하지 않는다.
최대 128개 최근 event ID와 하나의 재발견 요청만 보관하며, 요청을 영속 저장한 뒤 메시지를 ACK한다.
재발견에 실패하면 요청을 보존한다. 이벤트는 역할 승인을 대신하지 않는다.
이벤트가 누락돼도 기존 Organizations 정기 polling이 같은 흐름을 실행한다.

## 검증 범위와 문서

구현 검사는 fake Organizations·Control Tower·SQS와 memory/SQLite 저장소를 사용한다.
실제 AWS 배포·권한·이벤트 전달·고객 CloudTrail 데이터는 이 검사로 검증된 것이 아니다.

- [ListEnabledBaselines](https://docs.aws.amazon.com/controltower/latest/APIReference/API_ListEnabledBaselines.html)
- [GetEnabledBaseline](https://docs.aws.amazon.com/controltower/latest/APIReference/API_GetEnabledBaseline.html)
- [Baseline 유형과 계정 상속](https://docs.aws.amazon.com/controltower/latest/userguide/types-of-baselines.html)
- [Lifecycle 이벤트·CloudTrail 선행 조건](https://docs.aws.amazon.com/controltower/latest/userguide/lifecycle-events.html)
