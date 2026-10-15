# AWS 자격증명 인벤토리 구현 범위와 운영 계약

기준: 2026-09-25 작업 트리의 구현. 최초 후속 계획을 현재 코드의 수집 경로·사용법·한계로 갱신했다.
실제 실행 결과와 남은 검증은 [AWS 인벤토리 검증 기록](AWS_INVENTORY_IMPLEMENTATION.md)을 따른다.
이 문서의 구현 설명은 운영 AWS 배포·권한·고객 데이터 검증을 대신하지 않는다.

## 1. 목적과 담당 경계

발급 인벤토리, 콘텐츠의 평문 노출, Vault·Secret Manager의 보관 근거를 연결한다.
AWS IAM·CloudTrail은 기존 **schema 1** `ConnectionSpec`·`Observation`·coverage 저장 경로를 사용한다.
schema 2 metadata adapter 등록과 구별하며, [전체 정규화 설계](UNIFIED_METADATA_CONTRACT.md)의 DB·API 전환은 미구현이다.

| 소유자 | 구현 위치·책임 |
| --- | --- |
| AWS 공급자 | `aws/backend/cremore_aws_provider/iam_inventory.py`, `usage_inventory.py`: IAM·CloudTrail 수집·선별·정규화 |
| AWS 공급자 | 같은 패키지의 `aws_inventory_settings.py`, `aws_org_discovery.py`, `aws_org_context.py`, `aws_controltower.py`: 설정·계정 발견·조직/Control Tower 근거 |
| AWS 탐지·화면 | 같은 패키지의 `detection/session_material.py`: 평문 STS 결합; 화면은 콘솔의 공통 연동·Credential 화면(2026-10-01 `aws/web/` 삭제) |
| 플랫폼 통합 | `cremore/coverage/`: 모델·저장·스케줄·작업·값 해싱·상관분석; `cremore/api/`·`worker/`·`detection/`: 공통 진입점과 계약 |
| SIEM | 기존 별도 출력 계약. 인벤토리 기능이 SIEM 설정이나 이벤트 버전을 자동 변경하지 않음 |

공급자별 서버나 별도 DB는 없다. AWS SDK·응답 해석을 공통 domain으로 옮기지 않는다.
새 인증·scope·저장·공개 응답 변경은 해당 공통 소비자까지 플랫폼 담당자가 통합한다.

## 2. IAM 발급 인벤토리

| 항목 | 현재 구현 | 해석·한계 |
| --- | --- | --- |
| IAM 사용자·Access Key | `ListUsers`·`ListAccessKeys` 페이지 수집, 계정·소유자·상태·생성일 | IAM의 기존 Secret Access Key 원문은 반환하지 않음 |
| Credential Report | 일반 사용자·루트 행의 비밀번호 설정·MFA·키 슬롯·인증서·보고서 생성 시각 | 키 슬롯에는 AccessKeyId가 없어 특정 키로 추정하지 않음; 보고서 생성 대기·갱신 시차 유지 |
| 마지막 사용 | 선택적 `GetAccessKeyLastUsed`; 기존 조사 정규화 helper 재사용 | 거절·실패·정보 없음·미요청을 구분하며 실패해도 발급 키 관측 보존 |
| 서비스 전용 자격증명 | 선택적 `ListServiceSpecificCredentials` 전체 페이지 수집 | 식별자·서비스·상태 등 메타데이터이며 비밀번호 원문 수집이 아님 |
| 작업별 결과 | 목록·보고서·마지막 사용의 요청 수·관측 수와 COMPLETE/PARTIAL/FAILED/NOT_REQUESTED | 실패·잘못된 목록·예산 소진을 빈 정상 목록이나 부재 증거로 처리하지 않음 |

자동 생성하는 IAM 연결은 서비스 자격증명·Credential Report·마지막 사용 수집을 요청한다.
기존 사용자 지정 연결은 해당 선택과 범위를 유지한다. 서버·SDK 설치는 루트 `pyproject.toml`의 요구 버전을 따른다.

노출 상세의 동기·백그라운드 사용 조사도 IAM 결과를 선택적 `usage_snapshot.last_used`에 저장한다.
`status`는 `AVAILABLE`·`NO_INFORMATION`·`DENIED`·`FAILED`·`NOT_REQUESTED`이며, `observed_at`은
IAM 조회 관측 시각이다. 실패에는 안전한 `error_code`만 남기고 원문 응답·오류 메시지는 저장하지 않는다.
`AVAILABLE`일 때만 `at`·`service`·`region`과 기존 자격증명 마지막 사용 열을 갱신한다.
정보 없음은 `NOT_OBSERVED`와 `NO_INFORMATION` 한계로, 거절·실패·미요청 및 상태 없는 구형 관측은
`NOT_COLLECTED`로 표시한다. 실패 뒤 남은 이전 마지막 사용 열을 새 조회 시각의 근거로 재표시하지 않는다.
scanner 로그인 만료는 기존 `AWS_LOGIN_REQUIRED` 경로를 유지하며 이전 관측을 덮어쓰지 않는다.

## 3. 계정 구성과 사용법

Organizations 없는 단일 계정, 여러 독립 등록 계정, Organizations 전체 또는 선택 OU·하위 OU 계정이
같은 계정별 수집 경로를 쓴다. 먼저 계정을 등록하고 scanner 목적의 신원 승인, 역할·ExternalId,
실제 대상 계정 일치를 확인한다. 조직 가입이나 계정 발견만으로 멤버 계정 수집 권한이 생기지 않는다.

| API | 사용·권한 |
| --- | --- |
| `GET /api/v1/settings/aws-credential-inventory` | 인증된 사용자가 자동 수집 설정·유효 상태 조회 |
| `PUT /api/v1/settings/aws-credential-inventory` | admin이 아래 설정 변경 |
| `GET /api/v1/aws/accounts/{account_id}/credential-inventory` | 인증된 사용자가 계정별 저장 인벤토리·수집 상태 조회 |
| `POST /api/v1/aws/accounts/{account_id}/credential-inventory/refresh` | analyst/admin이 승인된 계정의 IAM·선택 CloudTrail 수집 요청 |
| `GET` / `PUT /api/v1/settings/aws-organizations` | 조직·OU·제외 계정·선택 Control Tower 설정 조회 / admin 변경 |
| `GET /api/v1/findings/{finding_id}/coverage` | 인증된 사용자가 노출과 인벤토리·Vault의 연결 근거 조회 |

계정 경로의 `{account_id}`는 내부 UUID다. 아래 `account_ids`는 **12자리 AWS 계정 ID**다.
수동 새로고침은 자동 수집 switch와 별개지만 같은 승인·연결·작업 중복·리스 검사를 거친다.
기존 실행 중 작업을 재사용하고, 명시적으로 비활성화한 연결을 자동 복구하지 않는다.

인증 우선 온보딩의 마지막 검토에서 설정한 새 AWS 주기는 연결의 `schedule_source=connection`과
`schedule_minutes`로 실행한다. 아래 설치 전체 설정은 `schedule_source=installation`인 기존 연결에
유지한다. 연결이 소유한 주기는 0이면 수동이고, 설치 hard lock·계정 접근 승인·기능 중지·연결 revision을
항상 재검사한다. 기존 연결에서 주기를 변경하면 같은 수집 레코드를 재사용하며 명시적 비활성 상태를 보존한다.

| 자동 수집 필드 | 기본값·의미 |
| --- | --- |
| `enabled` | `false`; 최초·반복 수집 opt-in. `SCAN_SCHEDULES_MODE=disabled`이면 켤 수 없음 |
| `interval_minutes` | `1440`; 허용 범위 5~10080분 |
| `account_ids` | `[]`; 승인된 등록 계정 전체. 값이 있으면 그 계정만 자동 수집 |
| `cloudtrail_enabled` | `false`; 발급·사용 이벤트 수집을 별도 요청 |
| `regions` | `[]`; CloudTrail을 켜면 명시해야 하는 리전 |
| `window_days` | `7`; Event History 1~90일, S3 로그 1~3650일 |
| `cloudtrail_source` | `event_history`; `s3`를 선택하면 아래 로그 범위 필요 |
| `trail_bucket`, `trail_prefixes` | S3 모드의 버킷·비어 있지 않은 디렉터리 prefix 목록 |

설정과 승인 확인 뒤 worker가 계정별 연결을 준비하고 최초·정기 수집을 등록한다. 자동 작업은 실행·체크포인트에서도
최신 설정과 승인 revision을 확인한다. 계정·리전·prefix를 좁혔을 때 이미 큐에 있던 작업도 이전 범위를 계속 쓰지 못한다.
S3 prefix는 선택한 계정들에 공통 적용된다. trail prefix, `AWSLogs`, `AWSLogs/<조직 ID>`, 계정·리전 경로 중 무엇을 줘도
수집기는 CloudTrail의 문서화된 경로(`<prefix>/AWSLogs/[<조직 ID>/]<계정 ID>/CloudTrail/<리전>/<YYYY>/<MM>/<DD>/`)를 따라
그 연결의 계정·설정 리전·수집 기간(하루 여유 포함)의 파일만 나열·다운로드한다. 조직 전체 prefix를 모든 계정에 같이 써도
각 계정은 자기 경로만 읽으며, 기간 이전 이력은 다시 읽지 않는다. 다른 계정·리전을 가리키는 prefix에서는 읽을 것이 없다.
`AWSLogs` 아래가 CloudTrail 경로 형식이 아닌 디렉터리는 예전처럼 prefix 전체를 읽는다. 넓은 prefix의 직접 로그나
표준 경로와 섞인 보관 디렉터리가 있으면 하위 이름 일부만으로 표준 배치를 단정하지 않고 승인 prefix 전체로
복귀한다. 이때도 계정·리전·기간 및 요청·파일 예산을 적용하며, 예산 초과는 부분 수집으로 남긴다.

Organizations의 `auto_validate`는 신규 계정과 역할 준비 지연으로 실패한 계정의 후속 검증을 지원한다.
제외·범위 이탈·탈퇴·비활성 계정은 과거 기록을 보존하고 후속 수집을 차단한다. 불완전한 조직 응답으로 탈퇴를 추정하지 않는다.
OU 정보 수집 실패 시 이전 경로를 보존하고 불완전 상태를 표시한다.

Control Tower는 선택 기능이다. Organizations 설정에서 `control_tower_enabled`, 홈 리전 `control_tower_region`을 지정한다.
관리 계정의 별도 승인된 scanner session으로 `AWSControlTowerBaseline`의 OU·계정 상태를 읽으며 OU 소속만으로 계정 등록 성공을 추정하지 않는다.
선택적 전용 SQS의 `lifecycle_queue_url`·`lifecycle_queue_acknowledged`는 성공 lifecycle 이벤트로 재발견을 앞당긴다.
이벤트 누락은 정기 발견으로 보완한다. `AWS_ORG_DISCOVERY_MODE`·`SCAN_SQS_MODE`의 잠금과 기존 접근 승인을 유지한다.

## 4. CloudTrail과 평문 STS 구성요소 결합

`usage_inventory.py`는 호출자의 사용 관측과 STS 발급 응답에 있는 새 ASIA ID의 발급 관측을 구분한다.
허용된 키 ID·발급/수신 계정·역할/세션 ARN·호출 주체·발급/만료 시각·이벤트 출처만 남긴다.
사용 이벤트를 키 ID로 연결하며 중복을 제거하고, 동일 이벤트의 충돌·잘못된 응답·수집 한도는 불완전 근거로 남긴다.
발급 응답에 키가 없으면 세션을 만들어 내지 않고, 사용 흔적만 있으면 만료를 미상으로 유지한다.

| 경로 | 범위 |
| --- | --- |
| Event History | 명시한 계정·리전, 최근 90일 이내 관리 이벤트. 데이터 이벤트·전체 STS 발급 목록이 아님 |
| S3 trail 로그 | 명시한 버킷·prefix·계정·리전·기간의 JSON/gzip 로그. 데이터 이벤트는 실제 trail 설정이 수집한 경우만 포함 |

S3는 요청·객체·레코드·압축 전후 크기 예산을 지키고 다른 계정·범위의 이벤트를 제외한다.
CloudTrail에는 모든 활성 STS 세션을 열거하는 API가 없다. EC2·ECS·Lambda·SSO 등 발급 경로에 따라 관측 가능성이 다르다.
만료 전·만료됨·만료 미상을 구분하되, 만료 전 상태로 현재 인증 가능성을 확정하지 않는다.

Event History 인벤토리도 동일 리전의 다음 페이지 요청 전에 0.55초를 기다리고 승인·취소를 다시 확인한다.
[LookupEvents 제한](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)은 계정·리전별 초당 2회이며,
다른 작업과 공유하는 전역 요청 제한기는 아니므로 동시 조회의 throttling에는 SDK의 제한된 재시도가 적용된다.

노출 상세의 `USED` 단계와 마지막 성공 관측의 `NOT_OBSERVED`는 소유 계정 조회가 `COMPLETE`일 때만 표시한다.
실패·진행 중·부분 조회에서 이벤트가 없으면 `NOT_COLLECTED`와 수집 상태를 표시한다. 이미 관측한 호출은 부분 조회에서도 보존한다.
[CloudTrail의 errorCode](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)는
권한 거절만 뜻하지 않는다. 알려진 권한 오류만 `DENIED`로 집계하고, 기타 서비스 오류는 기존 `UNKNOWN` 값으로 남긴다.
키별 조사 이벤트의 `error_code`는 유지하며, 오류가 있는 호출을 성공한 사용으로 표시하지 않는다.
키별 조사의 출처 주소 `AWS Internal`·`*.amazonaws.com`·`*.amazonaws.com.cn`은 `AWS_INTERNAL`로 분류한다.

평문 탐지는 같은 JSON 객체 또는 연속된 env/profile 설정 블록의 AccessKeyId·SecretAccessKey·SessionToken만 결합한다.
구성요소 순서가 달라도 처리하지만 객체·profile 경계를 넘겨 조합하지 않는다. 중복 필드·서로 다른 토큰의 충돌은 AMBIGUOUS, 토큰 미결합은 UNBOUND로 남긴다.
기존 ID+SecretAccessKey fingerprint를 유지하며, 완전한 세 요소에는 별도의 keyed session fingerprint를 사용한다.
원문 토큰을 저장하거나 API에 내보내지 않으며 공개 응답에는 구성요소 완전성과 연결 근거만 제공한다.

현재 코드에는 완전한 STS 세션의 조건부 인증 확인 경로가 있다. 저장된 결과는 확인 시점의 인증 근거이고,
IAM 장기 키의 `Active`/`Inactive` 관리 상태나 이후 시점의 사용 가능성을 보장하지 않는다.
**실제 STS 세션으로 서비스별 접근 권한을 검사하는 기능은 미구현이다.**
세 요소 결합, 저장된 인증 결과, 과거 CloudTrail 성공, 만료 전 상태, 역할 정책의 POTENTIAL 결과는 각각 다른 근거다.
전체 세션 정책·조직 정책·resource 정책·condition을 반영한 현재 권한 판정기로 표현하지 않는다.
세부 의미와 기존 조사 기능의 한계는 [STS 기술 평가](AWS_STS_VERIFICATION.md)를 따른다.

## 5. 발급·노출·Vault 연결

| 연결 근거 | 의미 |
| --- | --- |
| `IDENTIFIER` | 정확한 AWS 키 ID로 발급·사용 메타데이터 연결. 비밀값 동일성·현재 유효성 증명이 아님 |
| `VALUE_FINGERPRINT` | 기존 비교 계약의 값 지문 일치. 부분 구성요소 관측은 완전 자격증명 일치로 승격하지 않음 |
| `KEY_PAIR_FINGERPRINT` | STS의 ID+SecretAccessKey만 일치. 세션 상태는 PAIR_ONLY이며 완전 세션 MATCHED가 아님 |
| `SESSION_FINGERPRINT` | 동일한 keyed 비교 계약에서 결합된 세 요소가 일치. 현재 인증·권한 검증 결과가 아님 |

Finding coverage의 `inventory_matches`는 정확한 AWS ID, 수집 출처·시각·상태·최신성을 함께 제공한다.
이전 인벤토리 근거도 보존하며 응답 제한에 걸리면 전체 개수와 잘림 여부를 명시한다.
등록 계정의 현재 접근 거부는 `access_reasons`로 수집 당시의 `collection_reasons`와 구분하고
인벤토리 `current_evidence`를 낮춘다. 과거 식별자 연결과 별도 Vault 값 일치는 보존하며,
미등록 외부 수집기는 기존 연결 scope·수집 최신성 계약을 유지한다.
식별자 연결로 기존 자격증명의 활성/검증 상태를 덮어쓰지 않는다.

발급 목록에 없는 노출을 외부 자격증명으로 판정하지 않는다. `issuance_only`는 발급 ID에 대응하는
노출 ID가 없다는 집계이며 Vault 미등록 증명이 아니다. 임시 자격증명은 장기 Vault 보관이 필요하지 않을 수 있으므로
`TEMPORARY_CREDENTIAL_NOT_EXPECTED_IN_VAULT`를 보존한다. 미매칭만으로 관리 누락·위험을 확정하지 않는다.
Vault 동적 발급·lease 연결은 현재 KV 수집과 다른 미구현 기능이다.

## 6. 권한·호환·검증 경계

IAM 수집에는 선택한 작업에 맞는 `iam:ListUsers`, `iam:ListAccessKeys`, `iam:ListServiceSpecificCredentials`,
`iam:GenerateCredentialReport`, `iam:GetCredentialReport`, `iam:GetAccessKeyLastUsed`가 필요하다.
Event History는 `cloudtrail:LookupEvents`, S3는 대상 계정의 승인된 scanner role에 범위가 지정된
`s3:ListBucket`·`s3:GetObject` 권한을 사용한다. 중앙 로그 계정 역할로 자동 전환하지 않는다.
교차 계정 버킷 resource policy와 SSE-KMS의 정확한 key policy·복호화 권한은 운영자가 별도로 구성한다.

Control Tower는 관리 계정 역할의 `controltower:ListBaselines`·`ListEnabledBaselines`·`GetEnabledBaseline`을 사용한다.
Lifecycle queue는 worker의 `sqs:ReceiveMessage`·`DeleteMessage`·`GetQueueAttributes`와 전용 queue policy가 필요하다.
단일/멤버 역할·중앙 버킷·KMS·Control Tower·SQS 배포 조건은 [운영 지침](../deploy/cloudformation/control-tower-events.md)을 따른다.
앱 설정은 IAM 역할이나 인프라를 배포하지 않는다.

기존 schema 1 JSON에 추가 증거를 담으며 기존 필드가 없는 기록을 미확인으로 다룬다. 새 세션 지문은
VALUE·AWS_ACCESS_KEY·정확한 ASIA ID에만 허용하고, 제출된 세션의 수신 계정·출처·이벤트 참조를 연결 scope와 대조한다.
서버 권한·승인·요청 예산·취소·lease fencing·원문 비저장 계약을 유지한다. 전체 정규화/DB 전환과 Atlassian 스캔 통합의 보류 범위는 바꾸지 않는다.

검증은 fake client·합성 데이터로 IAM 페이지/오류, 계정 구성·일정·제외, STS 발급/사용·교차 계정·만료,
평문/Vault의 식별자·값·세션 비교, 공개 응답의 비밀 비노출을 다룬다.
명령·실제 결과·skip·미검증 환경은 [검증 기록](AWS_INVENTORY_IMPLEMENTATION.md)에만 최신 상태로 기록한다.

## 코드·공식 문서 근거

- [AWS 수집 진입점](../aws/backend/cremore_aws_provider/coverage.py)
- [IAM 수집기](../aws/backend/cremore_aws_provider/iam_inventory.py), [CloudTrail 수집기](../aws/backend/cremore_aws_provider/usage_inventory.py)
- [AWS 자동 수집](../cremore/coverage/aws_scheduling.py), [상관분석](../cremore/coverage/correlation.py)
- [평문 STS 결합](../aws/backend/cremore_aws_provider/detection/session_material.py)
- [AWS STS API](https://docs.aws.amazon.com/STS/latest/APIReference/API_Operations.html)
- [IAM·STS CloudTrail 기록](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)
- [CloudTrail Event History 범위](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
