# 권한 평가의 근거와 한계

확인 기준: 2026-10-07. 정책 이름, Allow 문장, 역할 연결, 정책 시뮬레이션,
실제 요청의 성공은 서로 다른 근거다. 이 변경은 기존 수집 경로의 근거 보존과
해석을 보완한다. 전체 공급자의 최종 실효 권한 평가기를 구현한 것은 아니다.

## AWS: 현재 구현

`investigation/potential_access.py`는 승인된 소유 계정의 scanner IAM client로
기존 20개 작업을 `SimulatePrincipalPolicy`에 보낸다. 발견된 키로 인증하거나
목록에 있는 서비스 작업을 실행하지 않는다. 첫 요청은 `ResourceArns=["*"]`이며
`ContextEntries`를 제공하지 않는다. STS 세션 ARN은 기존 경로로
해당 역할을 조회·시뮬레이션하며 실제 세션을 재현하지 않는다.

`*` 요청은 `arn:aws:s3:::*`나 특정 버킷처럼 서비스 ARN으로 쓴 문장과 맞지 않는다. 그래서
`*`에서 허용 근거가 없던 작업은 주체 자신의 Allow 문장에 적힌 ARN(최대 25개, NotAction·NotResource·권한
경계 제외)으로 다시 시뮬레이션한다(2026-10-07, `assessment_version=3`). 그중 하나에서 허용되면
`decision=ALLOWED`, `resource_scope=NAMED`와 그 ARN을 남긴다. IAM 사용자이면 같은 계정 S3 버킷의
버킷 정책(`ExpectedBucketOwner`로 소유 계정 확인), 같은 계정 Secrets Manager 시크릿의 리소스 정책,
같은 계정 KMS 키의 키 정책(`kms:GetKeyPolicy`, 2026-10-08)을 `ResourcePolicy`로 함께 넣어 명시적 거부를 반영한다.
API는 역할 주체의 리소스 정책을 받지 않으므로 역할은 리소스 정책 없이 시뮬레이션한다. ARN 패턴(`*`·`?`)은
정책 하나를 가리키지 않아 읽지 않는다. 지정 리소스의 누락된 조건 키는 API가 `ResourceSpecificResults`에 주므로
그곳까지 읽는다.

KMS는 주체 정책만으로 키 사용을 허용하지 않는다. 키 정책이 계정 자신(`arn:…:iam::<계정>:root` 또는 계정 ID)에게 그 작업을
허용해 IAM 정책에 위임했거나 키 정책 문장이 사용자(또는 모두, `*`)를 직접 허용해야 한다
([기본 키 정책](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html)). 시뮬레이터가 넣어 준 키 정책을 이
규칙대로 평가하는지는 실계정으로 확인하지 않았으므로, 시뮬레이터가 허용한 KMS 작업은 읽은 키 정책 본문으로 다시 가른다.

- 조건 없는 위임 문장 또는 사용자·모두에게 조건 없이 직접 허용한 문장이 그 작업을 덮음, 또는 시뮬레이터가 키 정책 문장이
  결과를 정했다고 답함(`MatchedStatements`의 `SourcePolicyType`이 `Resource Policy`·`resource`이거나 `SourcePolicyId`가
  `ResourcePolicy`): 허용.
- 그런 문장이 조건부뿐(예: AWS 관리형 키의 `kms:ViaService`·`kms:CallerAccount`): 허용으로 세지 않고 그 조건 키를
  `missing_context_values`에 남긴다(화면: "요청 조건에 따라 다름").
- 위임도 직접 허용도 없음: `key_policy_blocks`에 남기고 허용으로 세지 않는다(화면: "키 정책에 막힘").

키 정책은 주체 정책에 키 ARN 하나로 적힌 키만 읽는다. 리소스 `*`나 ARN 패턴으로 허용된 KMS 작업은 키 정책을 보지 않는다.
`kms:GetKeyPolicy`도 키 정책이 결정하므로, 수집 역할에 위임하지도 수집 역할을 직접 허용하지도 않은 키는 읽지 못한다
(`NOT_READ`). 그 키에서는 주체 정책만으로 판단하고 화면에 "키 정책을 읽지 못한 키"로 적는다. 그래서 "키 정책에 막힘"은
키 정책을 읽은 키에서만 나온다. 별칭 ARN(`alias/…`)은 키 사용 권한을 주지 않으므로 지정 리소스로 시뮬레이션하지 않는다.
리전·계정 자리에 `*`가 든 ARN(예: `arn:aws:kms:*:<계정>:key/*`)은 이 판정의 ARN 형식에 맞지 않아 지정 리소스로 시뮬레이션하지
않으며, 그런 문장만으로 허용된 작업은 "허용 근거 없음"으로 남는다. ARN별 결과(`named_resources`: 허용·명시적 거부·누락된
조건 키·키 정책이 막은 작업·리소스 정책 상태 `EVALUATED`/`NONE`/`NOT_READ`/`NOT_SUPPORTED`)를 공개 응답에 남긴다. 주체
정책을 모두 읽지 못하면 이 단계를 건너뛰고 `*` 결과만 남긴다.

기존 사용 기록 갱신 API와 worker를 그대로 사용한다. 소유 계정·주체의 정확한
연결, scanner 승인, 설치의 잠재 권한 스위치, 요청 예산·리스·취소 계약을 유지한다.
수집한 결과의 `collection_status=COMPLETE`는 요청과 작업 목록의 수집 완료이며
실효 권한이 완전히 평가됐다는 뜻이 아니다.

| 근거 | 저장·표시 | 해석 |
| --- | --- | --- |
| `EvalDecision` | 기존 `ALLOWED`, `EXPLICIT_DENY`, `IMPLICIT_DENY` 보존 | 주어진 시뮬레이션 입력의 결과. 명시적 거부와 허용 근거 없음도 상세에 표시 |
| `MissingContextValues` | 제한된 조건 키 이름만 `missing_context_values`에 저장 | 조건값은 저장하지 않음. 하나라도 있으면 위험 점수의 권한 근거로 채택하지 않음 |
| `OrganizationsDecisionDetail.AllowedByOrganizations` | 반환한 bool만 `organizations_allowed`에 저장 | 없으면 미확인. 조직 정책이 없거나 허용한다는 뜻으로 바꾸지 않음 |
| `PermissionsBoundaryDecisionDetail.AllowedByPermissionsBoundary` | 반환한 bool만 `permissions_boundary_allowed`에 저장 | 역할/사용자의 boundary 결과. 실제 STS session policy와 구별 |
| 실제 요청 권한 | `effective_access=NOT_EVALUATED` | 실제 서비스 요청의 성공·실패를 단정하지 않음 |

`resource_arns=["*"]`, `request_context=NOT_SUPPLIED`,
`assessment_status=MISSING_CONTEXT` 또는 `SIMULATION_ONLY`를 공개 응답에 추가한다.
컨텍스트가 없거나 layer 결과와 모순되는 Allow는 화면의 잠재 허용 요약에서 제외한다.
잘못된 응답은 부분/실패 근거이며 빈 조건 목록이나 완전한 거부 결과로 바꾸지 않는다.

`assessment_version=2`는 실제 조건 누락을 보존하는 응답 버전이다. 이전 버전은
모든 작업의 조건 목록을 빈 배열로 저장했으므로, 저장된 시뮬레이션으로 점수를 다시
계산할 때 v2와 v3만 채택한다. v3의 `NAMED` 허용도 같은 위험 분류로 점수에 들어간다. 과거 행·시각·결정은 삭제하거나 변조하지 않고 다시 수집해야
현재 평가가 가능하다고 표시한다. DB migration은 없다. 기존 인증 관측과 별개의
시뮬레이션이며 인증 상태·토큰 scopes를 바꾸지 않는다.

현재 평가가 남기는 미확인 영역:

- 지정 리소스 평가는 주체 자신의 정책에 적힌 ARN만 본다. 다른 계정이 리소스 정책으로 준 권한,
  25개를 넘는 ARN(`named_resources_complete=false`)은 확인하지 않는다.
- 리소스 정책은 IAM 사용자의 같은 계정 S3 버킷·Secrets Manager 시크릿·KMS 키 정책 중 ARN 하나로 적힌 것만 넣는다. 그 밖의
  리소스 정책, `*`·패턴으로 허용된 작업의 리소스 정책, 읽지 못한 정책, 역할의 리소스 정책, KMS grant(정책에 없는 사용을
  허용할 수 있음), 암호화 context와 종속 권한을 종합한 결과가 아니다.
- AWS 현재 문서는 SCP 조건과 리소스 범위, cross-account 시뮬레이션을 지원한다고 설명한다.
  다만 실제 요청 context를 여기서는 제공하지 않는다. AWS가 일부 principal/organization
  context를 자동 채우더라도 실제 세션 태그·요청 조건과 동일하다고 볼 수 없다.
- **SCP 평가의 누락된 조건 키는 AWS가 반환하지 않는다.** 따라서 빈
  `missing_context_values`만으로 모든 조건이 평가됐다고 결론 내리지 않는다.
- IAM role의 리소스 정책 시뮬레이션과 RCP는 공식 API의 지원 밖이다.
  VPC endpoint policy, role chaining, 여러 resource policy 등은 실제 결과와 다를 수 있다.
- 정책 이름이나 광범위 Allow는 실제 관리자 접근의 증거가 아니다. deny/boundary 요약도
  읽은 정책의 문장 근거이며 현재 서비스 접근 또는 조치 완료를 보장하지 않는다.

점수의 기존 20개 작업별 위험 분류는 잠재 권한 분류로 유지한다. 조건이 누락된 수집·부분
수집·오래된 v1 저장 결과는 미평가 신호가 된다. 조건 목록이 비어 있는 v2 점수도
시뮬레이션 범위의 휴리스틱이며 실제 최소/최대 권한의 증명이 아니다.

## GCP: 현재 구현

`metadata/relations.py`는 승인된 프로젝트/Secret Manager 리소스에서 읽은 로컬
Allow policy를 관계로 만든다. 직접 service account/user 멤버의 무조건 binding은
`policy_possible`, 조건이 있거나 그룹/도메인/공개 멤버가 포함되면 `unconfirmed`다.
서비스 계정 키에 연결한 프로젝트 역할도 조건부이면 `unconfirmed`다. 조건 필드가
비어 있거나 비정상이어도 무조건 Allow로 승격하지 않는다. 정책 원문/조건값은 보관하지 않는다.

관계는 공통 schema 2에서 항상 `confidence=CANDIDATE`이며
`effective_access=not_evaluated`다. 다음 사실은 shared `MetadataFact` 허용 목록,
정규화, 저장된 관측, native export를 통과해 보존된다.

| 사실 | 값 |
| --- | --- |
| `inherited_policies` | `not_evaluated` — 조직·폴더의 상속 정책은 수집하지 않음 |
| `deny_policies` | `not_evaluated` |
| `principal_access_boundaries` | `not_evaluated` |
| `membership_resolution` | 직접 멤버이면 `direct_member`, 그 외 `not_evaluated` |
| `condition_evaluation` | 조건 필드가 있으면 `not_evaluated`, 없으면 `not_present` |

단일 프로젝트의 빈 binding/실패한 조회는 접근 불가나 상위 권한 부재를 증명하지 않는다.
감사 로그의 과거 성공한 접근은 `observed_access`로 따로 남으며 현재 권한으로 승격하지 않는다.
관계는 직접 binding만 다룬다. 상속·deny·그룹을 반영한 판정은 아래 `effective_access`가 Google에 묻는다.

### 서비스 계정 키의 실효 판정 (2026-10-07)

인벤토리 옵션 `effective_access`(연결 화면 "키가 있는 서비스 계정: 고위험 권한의 실효 판정")를 켜면
사용자 관리 키가 있는 서비스 계정마다 Policy Troubleshooter v3 `iam:troubleshoot`에 고위험 권한 11개를
`//cloudresourcemanager.googleapis.com/projects/<project>`에 대해 묻는다(`metadata/effective_access.py`).
Google이 프로젝트와 상위 폴더·조직의 allow 정책, deny 정책, 그룹 구성원, 조건을 함께 평가한 답이다.
연결 자신의 신원으로 호출하며 발견된 키로 인증하지 않는다. 한 수집에서 계정 최대 20개(계정 이메일 순, 계정당
요청 11번, 재시도 제외)에 묻고, 나머지 계정은 키 목록 보고서의 `selection`에 미평가로 센다. 키는
계정의 권한을 그대로 쓰므로 같은 답을 그 계정의 사용자 관리 키마다 `MetadataPermission`으로 붙인다. Google 관리
키는 대상이 아니다.

| 답 | 키의 권한 `effect` | 콘솔 |
| --- | --- | --- |
| `CAN_ACCESS` | `ALLOW` | 자격증명의 "권한과 접근 범위" 표와 발급 항목 상세 |
| `CANNOT_ACCESS` | `DENY` | 발급 항목 상세에 "접근 불가" |
| `UNKNOWN_INFO`·`UNKNOWN_CONDITIONAL` | `UNKNOWN` | 발급 항목 상세에 "정보 부족으로 판정 불가"·"요청 조건에 따라 다름" |
| 호출 실패·상태 없는 응답 | `UNKNOWN` | 발급 항목 상세에 "판정하지 못함"과 오류 |

| 사실 | 값 |
| --- | --- |
| `effective_access` | `can_access`·`cannot_access`·`unknown_info`·`unknown_conditional`, 호출이 실패하면 `not_evaluated` |
| `inherited_policies`·`membership_resolution` | `evaluated`(Troubleshooter가 상위 정책과 그룹을 평가에 넣음), 실패하면 `not_evaluated` |
| `deny_policies` | `denyAccessState`의 `denied`·`not_denied`·`unknown_conditional`·`unknown_info`, 없으면 `not_reported`, 실패하면 `not_evaluated` |
| `condition_evaluation` | 답이 `UNKNOWN_CONDITIONAL`이면 `unknown_conditional`, 실패하면 `not_evaluated`, 그 외 `evaluated` |
| `principal_access_boundaries` | `not_evaluated` — v3는 주체 접근 경계 정책을 평가하지 않는다(v3beta만 설명) |
| `error_code` | 실패한 호출의 코드(`api_disabled`·`permission_denied_or_api_disabled`·`invalid_response` 등) |

권한과 설정: 연결 신원에 조직 수준의 Security Reviewer(`roles/iam.securityReviewer`)와 Deny Reviewer
(`roles/iam.denyReviewer`)가 필요하다. 상위 정책을 볼 수 없으면 Google이 `UNKNOWN_INFO`를 돌려주고 그대로
미확인으로 남는다. 그룹이 들어간 binding·deny 규칙은 Workspace Admin API의 `groups.read` 권한이 없으면
Google이 unknown으로 답한다. 연결 점검은 프로젝트의 `testIamPermissions`로
`resourcemanager.projects.getIamPolicy`·`iam.roles.get`·`iam.denypolicies.get`·`iam.denypolicies.list`만 확인하며
조직·폴더의 역할은 점검하지 않는다. Policy Troubleshooter API는 연결 신원의 프로젝트(Google 로그인은 OAuth 앱
프로젝트)에서 켠다. `SERVICE_DISABLED`(`api_disabled`)를 받으면 그 계정의 나머지 권한을 더 묻지 않는다. 한 계정의
호출이 모두 실패하면(오류 종류와 무관) 이후 계정은 묻지 않고 `selection`에 가장 많이 나온 오류로
"stopped after <code>"를 남긴다.

실패 처리: 403 등 실패한 호출은 그 권한만 `UNKNOWN`과 `not_evaluated`·`error_code`로 남기고, 키 목록 보고서의
`error_counts`에 `troubleshooter_<code>`로 센다. 보고서의 `effective_access` 사실은 답의 상태별 개수다(모두
`unknown_info`이면 조직 수준 검토자 역할이 빠진 것). 판정은 키 목록의 보강이므로 키 목록의 `COMPLETE`/`PARTIAL`을
바꾸지 않는다. 429·5xx는 다른 GCP 읽기처럼 cursor를 유지하고 기다렸다가 이어 가며, 재개한 계정을 두 번 세지
않는다(체크포인트는 마지막으로 끝낸 계정까지의 개수를 복사해 둔다).

남는 미확인 영역:

- 프로젝트 기준으로만 묻는다. 버킷·시크릿·키링 같은 개별 리소스의 정책으로만 준 권한은 보지 않는다.
- 고정된 11개 권한 밖은 묻지 않는다.
- 주체 접근 경계 정책이 `CAN_ACCESS`로 나온 권한을 실제로는 막을 수 있다(v3가 평가하지 않음).
- 계정 이메일 순으로 앞의 20개에만 묻는다. 사용 중지된 계정도 이 한도에 들어간다.
- 직전 수집에서 허용으로 나온 권한도 이번 수집이 실패하면 이번 관측에는 알 수 없음으로 남는다.
- Troubleshooter는 Cloud Storage ACL, VPC Service Controls를 평가하지 않는다. 조직 정책 제약도 판정에 없다.
- 요청 context를 주지 않으므로 시각·IP 등에 걸린 조건은 `UNKNOWN_CONDITIONAL`로 남는다.
- 실제 요청의 성공 여부를 확인한 결과가 아니다.

## Azure: 앱 자격증명의 권한 (2026-10-07)

Azure에는 임의 주체의 실효 접근을 판정하는 공개 API가 없다(`Microsoft.Authorization/permissions`는 호출자 자신의
권한만 준다). 그래서 Entra 발급 목록은 판정 대신 **부여 목록**을 읽는다. 앱 비밀·인증서는 그 앱의 서비스 주체로
로그인하므로, 서비스 주체마다 다음을 읽어 그 자격증명들에 `MetadataPermission`(`ALLOW`)으로 붙인다
(`azure/backend/cremore_azure_provider/entra/permissions.py`, 단계 `app_access`).

| 옵션 | 종류 | `kind` | 근거(`evidence_source`) | 범위 |
| --- | --- | --- | --- | --- |
| `app_permissions` | 애플리케이션 권한(앱 역할 할당) | `permission` | `app_role_assignment` | 테넌트 전체. 기본 액세스(빈 앱 역할)는 제외 |
| `app_permissions` | Entra 역할 | `role` | `directory_role_assignment` | 서비스 주체에 직접 준 활성 할당(`directoryScopeId`) |
| `app_azure_roles` | Azure 역할 | `role` | `azure_role_assignment` | 테넌트 루트 관리 그룹에서 `assignedTo`, 그룹으로 받은 할당 포함 |

해석:

- 애플리케이션 권한은 부여가 곧 사용 가능 권한이다. 워크로드 ID 조건부 액세스로 토큰 발급이 막히는 경우와, Exchange의
  애플리케이션 RBAC·SharePoint `Sites.Selected`처럼 리소스 쪽에서 범위를 좁히는 설정은 판정에 없다.
- Entra 역할은 역할 할당 가능 그룹으로 받은 것과 PIM eligible 할당을 포함하지 않는다(`membership_resolution=direct_member`).
- Azure 역할의 조건(ABAC)은 `condition_present`로만 남고 원문은 저장하지 않는다. 거부 할당은 읽지 않는다
  (`deny_policies=not_evaluated`). 역할 이름만 남기며 역할 정의의 작업 목록을 펼치지 않는다. 콘솔의 쓰기·읽기 표시는
  역할 이름으로 정하고 범위(` · ` 뒤)는 보지 않는다.
- 루트 관리 그룹에서 `assignedTo`가 하위 구독·리소스 그룹·리소스의 할당까지 돌려주는지는 실제 테넌트에서 확인하지
  않았다(REST 문서는 `principalId eq` 필터에 대해 "at, above or below the scope"를 적는다).
- 다중 테넌트 앱이 다른 테넌트에서 받은 권한, Azure Lighthouse 위임은 보지 않는다.
- 읽기 실패는 종류마다 `UNKNOWN` 항목 하나와 `error_code`로 남아 빈 목록과 구별된다. 모든 서비스 주체에서 되풀이될
  실패(`permission_denied`·`authentication_failed`·`request_failed`, Azure 역할의 `http_404`)는 다시 묻지 않는다.
  250개를 넘는 권한은 `UNKNOWN` 항목을 남기고 `permissions_truncated` 항목을 붙인다.
- 단계 보고서는 끝까지 돌면 `COMPLETE`이고 `selection`·`error_counts` 사실로 읽은 범위와 실패를 남긴다. 저장 계층은
  `COMPLETE`가 아닌 종료 보고서가 하나라도 있으면 실행을 `PARTIAL`로 만들므로(`cremore/coverage/store.py`의 `finish`),
  보강 단계의 실패가 자격증명 목록과 실행 상태를 부분 수집으로 바꾸지 않도록 이렇게 둔다. 서비스 주체가 목록에 없는
  자격증명과 한도 밖 서비스 주체의 자격증명은 권한 정보 없이 남고 보고서에 개수가 남는다.
- 권한: `app_permissions`는 Application.Read.All(기존)과 RoleManagement.Read.Directory, `app_azure_roles`는 역할 할당·정의
  읽기만 담은 사용자 지정 역할을 테넌트 루트 관리 그룹에 준다. 루트 관리 그룹은 관리 그룹을 처음 쓸 때 만들어진다.
  연결 점검은 전역 관리자 역할 정의 읽기와 루트 관리 그룹의 `atScope()` 역할 할당 목록으로 확인하며, 404는
  `AZURE_ROOT_MANAGEMENT_GROUP_NOT_FOUND`로 알린다.

## 구체적 요청 평가를 추가할 때 필요한 경로

기존 `POST /api/v1/credentials/{id}/usage/refresh`는 credential owner와 조회 설정에
묶여 있으며 resource/action/context 입력 모델이 없다. 기존 background `credential-usage`
작업도 같은 고정 목록을 쓴다. 수동 조건 입력을 무시한 채 이 응답을 최종 실효 평가로
이름만 바꾸는 것은 지원하지 않는다.

추가 구현은 별도의 명시적 평가 요청 계약이 필요하다. 저장된 신원에서 선택한
principal, 승인된 연결과 정확한 resource, 제한된 action/permission, 요청 시각 및 허용된
context를 바인딩하고 API 역할·현재 scope를 worker 실행 시 다시 검사해야 한다.
공급자가 반환한 판단/미확인/수집 실패를 분리하고 provider 원문·비밀 조건값을 저장하지
않는 저장 및 public projection도 필요하다.

AWS는 구체적인 resource/context와 지원되는 경우의 resource policy를 기존
`SimulatePrincipalPolicy` 입력에 전달할 수 있다. 역할의 resource policy, RCP와 실제
session을 모두 지원하는 최종 evaluator로 표현해서는 안 된다. 서비스별 KMS/종속 권한은
별도의 지원·조회 범위가 있어야 하며 알려지지 않으면 미확인이다.

GCP의 `iam:troubleshoot`는 위 인벤토리 판정에서 고정된 11개 권한·프로젝트 자원에만 쓴다. 임의의
리소스·권한이나 조건 context를 받는 평가는 같은 별도 요청 계약(선택한 principal·승인된 리소스·권한 검증,
bounded 응답 정규화, 실패·부분·오래된 관측 표시)이 있어야 한다. 필요한 정책 또는 그룹 정보를 호출 신원이
볼 수 없거나 조건 context가 없으면 unknown을 보존한다. 조직/그룹 전체 탐색을 기존 프로젝트 연결 승인에서
추론하지 않는다.

## 공식 근거

다음 공개 문서를 2026-10-06에 읽어 현재 API의 지원과 한계를 대조했다. 문서 확인은 실제
AWS/GCP 계정 호출 검증이 아니다.

- [AWS IAM Policy Simulator](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)
- [SimulatePrincipalPolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html)
- [EvaluationResult](https://docs.aws.amazon.com/IAM/latest/APIReference/API_EvaluationResult.html)
  (지정 리소스의 `MissingContextValues`·`MatchedStatements`는 `ResourceSpecificResults`에도 오므로 두 곳을 함께 읽는다),
  [Statement](https://docs.aws.amazon.com/IAM/latest/APIReference/API_Statement.html)
  (2026-10-08: 유효값 목록은 `resource`, SimulatePrincipalPolicy 예시 응답은 `Resource Policy`·`ResourcePolicy`)
- [KMS 기본 키 정책](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html),
  [GetKeyPolicy](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyPolicy.html),
  [별칭으로 접근 제어](https://docs.aws.amazon.com/kms/latest/developerguide/alias-authorization.html)
  (2026-10-08: IAM 정책은 키 정책이 계정에 위임해야 효력이 있고, 정책의 별칭 ARN은 키 사용을 허용하지 않는다)
- [GCP Policy Troubleshooter](https://cloud.google.com/policy-intelligence/docs/troubleshoot-access)
- [GCP `iam:troubleshoot` v3 REST](https://cloud.google.com/policy-intelligence/docs/reference/policytroubleshooter/rest/v3/iam/troubleshoot)
  (2026-10-07: 요청 `accessTuple.principal`은 이메일, 응답은 `overallAccessState`·`allowPolicyExplanation`·`denyPolicyExplanation`)
- [GCP Allow policy와 상속](https://cloud.google.com/iam/docs/policies)
- [Graph 서비스 주체의 appRoleAssignments](https://learn.microsoft.com/graph/api/serviceprincipal-list-approleassignments),
  [Entra 역할 할당 목록](https://learn.microsoft.com/graph/api/rbacapplication-list-roleassignments),
  [Azure 역할 할당 목록(REST, `assignedTo`)](https://learn.microsoft.com/azure/role-based-access-control/role-assignments-list-rest)
  (2026-10-07: `assignedTo`는 그룹 구성원 자격을 전이적으로 포함, RoleManagement.Read.Directory 앱 권한 ID
  `483bed4a-2ad3-4361-a73b-c83ccdbdc53c`)

## 검증 기록

합성 IAM/Google 응답과 memory/SQLite 저장, 실제 콘솔 컴포넌트의 브라우저 fixture를 사용한다.
실제 공급자 요청·발견 자격증명 사용·운영 DB 접근은 하지 않았다. 최종 실행 명령과 결과는
아래 인수 기록에 추가한다. PostgreSQL 검사는 이 작업에서 설정하지 않았고 해당 fixture는 skip이다.

2026-10-06 실행 결과 (`tmp/github-export-venv/Scripts/python.exe`,
`AWS_EC2_METADATA_DISABLED=true`, `CREMORE_TEST_POSTGRES_URL` 해제):

- `python -m pytest aws/backend/cremore_aws_provider/investigation gcp/backend/cremore_gcp_provider/metadata/tests cremore/api/credential_records_test.py cremore/api/finding_evidence_test.py -q -rs`:
  **372 passed, 17 skipped, 19 subtests passed**. Skip은 모두 미설정 PostgreSQL fixture이며
  memory/SQLite 회귀는 실행했다. FastAPI/Starlette의 기존 httpx deprecation warning 1개.
- `node --test tests/console-permissions.test.cjs tests/console-issued.test.cjs tests/console.test.cjs`:
  **48 passed**.
- `npx tsc --noEmit`: 통과.
- 변경된 Python 12개 파일의 `python -m ruff check`: 통과.
- `node tests/run-browser-proofs.cjs console-credential-permissions`: **1/1 통과**.
  KO/EN × light/dark × 375/1440에서 허용/거부/조건 누락·조직/boundary 결과,
  popover 위치·스크롤·키보드·초점·레이아웃을 검사했다. 외부 쓰기 요청 없음.
- `git diff --check`: 통과. 통합 전체 웹 build/전체 suite는 별도 통합 담당 검증이다.

2026-10-08 KMS 키 정책 판정 (합성 IAM·KMS 응답, `AWS_EC2_METADATA_DISABLED=true`):

- `python -m pytest aws/backend/cremore_aws_provider/investigation aws/backend/cremore_aws_provider/aws_readonly_test.py aws/backend/cremore_aws_provider/aws_identity_test.py -q`:
  **181 passed**.
- `node --test tests/console-permissions.test.cjs tests/console-issued.test.cjs`: **15 passed**(permissions 6). `npx tsc --noEmit`: 통과.
- `node tests/run-browser-proofs.cjs console-credential-permissions`: **1/1 통과**.
- 실제 AWS 계정의 `GetKeyPolicy`·시뮬레이터 응답은 확인하지 않았다: 키 정책을 넣은 시뮬레이션의 결정과 `SourcePolicyType`
  문자열, 리전·계정 자리에 `*`가 든 ARN을 `ResourceArns`로 받는지(받으면 그런 문장도 지정 리소스로 시뮬레이션할 수 있다).

초기 검사 중 Windows WMI 진단 `0x8007000e`가 한 번 발생했으나 pytest는 계속 실행됐다.
최종 위 실행은 정상 종료했다. `npm.CMD`는 호스트의 shim 실행 제한으로 거절되어,
브라우저 검사는 동일 npm script의 Node 진입점을 직접 실행했다.

2026-10-07 GCP 실효 판정(`effective_access`) 실행 결과 (`AWS_EC2_METADATA_DISABLED=true`, `CREMORE_TEST_POSTGRES_URL` 해제):

- `python -m pytest gcp/backend cremore/onboarding cremore/api/credential_records_test.py cremore/provider_boundaries_test.py -q`:
  **978 passed, 25 skipped, 19 subtests passed**. Skip은 미설정 PostgreSQL fixture다. 지연(429) 뒤 재개하는 회귀 테스트는
  체크포인트 복사를 되돌리면 실패하는 것을 확인했다.
- `node --test tests/*.test.cjs`(web): **298 passed**. `tsc --noEmit`, 변경 Python 파일의 ruff, `git diff --check` 통과.
- `node tests/run-browser-proofs.cjs console-credential-permissions console-metadata-popover console-setup`: **3/3 통과**.
- 합성 응답만 썼고 Policy Troubleshooter·`testIamPermissions`를 실제 Google 프로젝트에 호출하지 않았다. 특히
  `iam.denypolicies.get`·`iam.denypolicies.list`를 프로젝트 `testIamPermissions`로 확인할 수 있는지는 실제 프로젝트에서
  확인하지 않았다.

2026-10-07 Azure 앱 자격증명 권한(`app_permissions`·`app_azure_roles`) 실행 결과 (`AWS_EC2_METADATA_DISABLED=true`, PostgreSQL 미설정):

- `python -m pytest azure/backend cremore/onboarding cremore/api/credential_records_test.py cremore/provider_boundaries_test.py cremore/coverage/certificate_coverage_test.py cremore/coverage/provider_worker_integration_test.py cremore/coverage/metadata_linkage_test.py cremore/coverage/collector_runtime_test.py cremore/sources/module_contract_test.py -q`:
  **1259 passed, 25 skipped**(skip은 미설정 PostgreSQL fixture). 저장 계층(`MetadataStore.finish`)까지 거친 실행이 읽기 실패에도
  `COMPLETE`로 남는 것, 지연 뒤 같은 서비스 주체에서 이어 가는 것, 호스트별 토큰(Graph·ARM)을 확인했다.
- `node --test tests/*.test.cjs`(web): **298 passed**. `tsc --noEmit`, 변경 Python 파일의 ruff, `git diff --check` 통과.
- `node tests/run-browser-proofs.cjs console-setup console-credential-permissions console-metadata-popover`: **3/3 통과**.
- 합성 응답만 썼고 Microsoft Graph·Azure Resource Manager를 실제 테넌트에 호출하지 않았다. 루트 관리 그룹에서
  `assignedTo`가 하위 범위의 할당까지 돌려주는지, 사용자 지정 역할 명령이 실제 Cloud Shell에서 그대로 실행되는지는 확인하지 않았다.
