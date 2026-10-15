# AWS STS 사용 가능성과 권한 평가

기준: 2026-09-25 작업 트리. STS 세션의 **현재 인증 가능 여부**, **요청별 권한**, **과거 사용 사실**은
서로 다른 증거다. 현재 구현은 발급·사용 메타데이터와 정책 근거를 연결하고, 세 요소가 한 컨텍스트에
결합된(`COMPLETE`) 경우에 한해 그 삼중값으로 STS 현재 인증 여부를 확인한다. 발견한 조각들을 임의로
조합해 시험하지는 않는다. 이 문서는 구현과 AWS 공식 문서의 검토 결과이며 실제 자격증명·고객 로그·
AWS 서비스 요청으로 검증한 결과가 아니다.

아래에서 인증 확인은 코드 경로의 존재를 설명한다. 이번 후속 수정은 모듈 경계·저장된 근거의 API/UI 표현·
문서 정합성에 한정하며, 발견된 자격증명 재사용 경로의 정상 동작이나 실제 AWS 인증을 검증한 결과가 아니다.
[구현 검증 기록](AWS_INVENTORY_IMPLEMENTATION.md)은 최초 인벤토리 검사와 후속 검사를 구분한다.

| 구분 | 현재 구현과 해석 |
| --- | --- |
| 인증·유효성 확인 | 조건부 확인 코드가 있음. 저장된 결과는 확인 시점의 인증 근거이며 지속적인 활성 상태가 아님 |
| 잠재 권한 평가 | 등록된 관리용 연결로 역할 정책을 평가. `POTENTIAL`이며 실제 세션 권한의 확정이 아님 |
| 실제 서비스 사용 권한 | 세션으로 서비스별 요청을 수행하는 검증은 미구현 |

STS 세션에는 IAM 장기 키의 `Active`/`Inactive` 관리 상태를 그대로 적용하지 않는다.
화면의 지원 조건, 관측된 구성요소, 저장된 인증 결과, 만료 근거는 서로 다른 사실이다.

## 현재 구현에서 확인할 수 있는 것

| 구현 | 확인하는 사실 | 한계 |
| --- | --- | --- |
| [session_material](../aws/backend/cremore_aws_provider/detection/session_material.py) | 같은 구조의 AccessKeyId·SecretAccessKey·SessionToken 결합과 비밀 원문 없는 fingerprint | 결합된 세 요소가 존재한다는 사실만으로 발급·유효성·권한을 증명하지 않음 |
| [usage_inventory](../aws/backend/cremore_aws_provider/usage_inventory.py) | 승인한 계정·리전·기간의 발급/사용 이벤트, issuer와 recipient, 관측된 만료 시각 | CloudTrail에 관측된 세션이며 모든 활성 STS 세션의 목록이 아님; 원문 비밀을 복구하지 않음 |
| [investigation/usage](../aws/backend/cremore_aws_provider/investigation/usage.py) | 관리용 scanner로 AccessKeyId 사용 이력 조회, 리전별 성공·부분 수집, 장기 키의 IAM 소유자/최종 사용 근거 | 관측 당시의 결과; 로그 부재는 미사용·폐기·현재 무권한의 증거가 아님 |
| [identity_policies](../aws/backend/cremore_aws_provider/investigation/identity_policies.py) | 사용자의 그룹 포함 inline/managed 정책 또는 세션 발급 역할의 정책·permissions boundary | condition 값은 저장하지 않으며 resource/session 정책과 조직 전체 정책의 완전한 평가기가 아님 |
| [potential_access](../aws/backend/cremore_aws_provider/investigation/potential_access.py) | 승인된 scanner로 정해진 action 목록을 `ResourceArns=["*"]`에 대해 IAM 정책 시뮬레이션. STS 세션은 맡은 역할로 해석해 평가 | 실제 action을 실행하지 않음; 특정 ARN에만 허용된 권한·요청 context, STS 세션의 session policy·boundary를 놓칠 수 있음 |
| [role_validation](../aws/backend/cremore_aws_provider/investigation/role_validation.py) | 제품 scanner의 AssumeRole/SSO/runtime 신원이 등록 계정과 일치하는지 확인 | scanner 온보딩 검사이며 발견한 사용자 세션의 권한 검증이 아님 |

[AWSAccessKeyVerifier](../aws/backend/cremore_aws_provider/detection/verify/aws.py)는 활성 검증이 켜졌을 때
장기 `AKIA` 쌍을 GetCallerIdentity로 확인하고, 세 요소가 한 컨텍스트에 결합된(`COMPLETE`) `ASIA` 세션은
그 세션 토큰을 `x-amz-security-token` 서명 헤더로 넣어 함께 확인한다. 세션 토큰이 결합되지 않은
`ASIA` 쌍(식별자·비밀만)에는 여전히 `AWS_STS_SESSION_TOKEN_NOT_BOUND`를 반환하고 아무 요청도 보내지 않는다.
만료된 세션(`ExpiredToken`/`ExpiredTokenException`)은 "지금 인증되지 않음"으로 거절하되 사유 코드를 보존한다.
원문 세션 토큰은 AKIA 비밀 키와 같은 취급이다: 검증 요청에만 전달하고 finding·로그·checkpoint·SIEM·
fingerprint에 저장하지 않는다(엔진이 `view`에서 슬라이스해 검증기에만 넘긴다). 검증이 꺼져 있으면(기본
스위치 또는 설치 잠금) 어느 경로도 실행되지 않는다. 고정 endpoint는 상용 partition 기준이므로 다른
partition 지원을 추정하지 않는다.

## GetCallerIdentity가 증명하는 범위

일관되게 결합된 임시 자격증명의 세 요소가 있고 별도로 허용된 검증 환경이 있다면, 기술적으로
STS가 그 요청을 인증했는지와 반환 신원을 특정 시각에 확인할 수 있다. **성공은 서비스 권한의
증명이 아니다.** AWS 문서는 GetCallerIdentity에 별도 권한이 필요 없으며 이 action의 명시적
거부 정책이 있어도 같은 신원 정보를 얻을 수 있다고 설명한다. 따라서 성공 결과에서
S3 객체 읽기·Secrets Manager 조회·다른 역할 assume 가능 여부를 추론하면 안 된다.

결합된 `COMPLETE` 삼중값에 대한 현재 인증 검증은 위 verifier가 수행한다. 반면 metadata 수집기
(사용·정책·소유자)는 여전히 고객의 발견 자격증명 대신 등록·승인된 scanner session을 사용하고, 토큰
원문을 저장하지 않는다. 세션 토큰은 불투명한 값으로 취급한다. 문자열 형식만으로 만료·권한을
복원하거나, access key ID만 보고 임의의 기본 만료 시간을 부여하지 않는다.

## 요청별 유효 권한

역할의 identity policy가 허용하는 범위는 적용된 session policy와 permissions boundary로 제한될 수
있고, Organizations의 SCP/RCP, 리소스 정책, 명시적 Deny와 요청 condition도 결과에 영향을 준다.
조건에는 action/resource, 계정·리전, principal/session tag, MFA, source network, 요청 시각 등이 있다.
AssumeRole의 trust policy/ExternalId는 역할을 맡는 단계의 허용 근거이며, 이후 모든 API 호출을
허용하는 증거가 아니다.

이 전체를 단순히 모든 정책의 교집합으로 계산해서도 안 된다. 같은 계정의 resource-based grant가
IAM role ARN 또는 role-session ARN 중 어느 principal을 지목하는지에 따라 implicit deny와
boundary/session policy의 적용 방식이 달라진다. Cross-account 요청도 identity 측과 resource 측의
평가를 함께 충족해야 한다. 현재 helper는 이런 전체 평가를 재구현하지 않는다.

IAM simulator가 반환한 `ALLOWED`는 **제출한 action/resource/context에 대한 정책 평가 근거**다.
현재 helper는 curated action 집합, 전체 리소스 `*`, 관측한 IAM principal에 한정하고
실제 세션의 발급 시 session policy·모든 리소스 정책·condition 값을 완전하게 수집하지 않는다.
따라서 결과는 `POTENTIAL`로 유지한다. `COMPLETE`도 이 helper가 요청한 평가 결과를 모두 받았다는
뜻이지 계정의 모든 권한을 조사했거나 실제 서비스 요청이 성공한다는 뜻이 아니다.

STS 임시 세션(assumed-role ARN)은 `SimulatePrincipalPolicy`에 직접 넣을 수 없으므로, 맡은 역할을
`iam:GetRole`로 해석해(권한이 없거나 삭제된 역할이면 path 없는 역할 ARN으로 대체) 그 역할의 identity
policy를 평가한다. 결과에는 실제 시뮬레이션한 역할 ARN(`evaluated_role_arn`)과, 이 세션 고유의 session
policy·permissions boundary는 반영되지 않아 "세션이 아닌 역할의 잠재 권한"이라는 한계를 함께 기록한다.
이는 장기 키가 받는 것과 같은 시뮬레이션 기반 평가이며, 발견한 세션 원문으로 실제 서비스를 호출하는
것이 아니다(그 기능은 미구현).

## 시각과 불확실성 표시

- **발급 관측:** 세션 발급 이벤트에 해당 식별자와 세션 정보가 있었다. 현재 살아 있다는 의미는 아니다.
- **과거 사용 성공/거절:** 그 시각의 해당 action/resource/context 결과다. 다른 요청이나 현재 시각에 일반화하지 않는다.
- **만료 시각:** 신뢰할 수 있는 관측에 만료 시각이 있고 그 시각이 지났다면 만료 근거로 표시한다.
  아직 지나지 않았다는 사실만으로 현재 유효성을 확정하지 않는다. 만료 정보가 없으면 미상이다.
- **현재 검증:** 검증이 켜졌고 세 요소가 `COMPLETE`로 결합된 STS 세션은 GetCallerIdentity로 현재 인증 가능
  여부를 관측 시각 기준으로 기록한다. 검증이 꺼졌거나, 토큰이 결합되지 않았거나, 정책 분석만 있는 세션은
  현재 인증 가능 여부를 미검증으로 둔다. 성공은 서비스 권한의 증명이 아니다.
- **수집 실패/미관측:** 접근 거절, 요청·페이지·로그 크기 한도, 취소, 잘못된 응답은 부분/실패 근거다.
  Event History는 리전별 최근 90일의 관리 이벤트이며 데이터 이벤트까지 포괄하지 않는다.
  S3 trail도 선택한 로그·리전·기간과 trail 설정의 범위만 증명한다.

[risk/verification](../cremore/risk/verification.py)은 검증 시각·이전 확인·만료 근거를 별도로 다루며,
예전 ASIA 두 요소 검사에서 나온 인증 거절을 세션 폐기 증거로 승격하지 않는다. 구현된 STS 검증도
이 구분과 기존 승인·scope·원문 비저장 계약을 유지한다.

## 확인한 AWS 공식 문서

2026-09-25 공개 문서를 조회해 위 의미를 대조했다. AWS API를 호출한 것은 아니다.

- [STS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
- [STS AssumeRole와 session policy](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [IAM 정책 평가](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [IAM policy simulator와 한계](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)
- [CloudTrail Event history 범위](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
