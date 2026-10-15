# AWS 인벤토리 구현 검증 기록

기준: 2026-09-25, `refactoring` 작업 트리. [요구사항·운영 계약](AWS_CREDENTIAL_INVENTORY_PLAN.md)에
따른 최초 인벤토리 구현 기록과 후속 수정 기록이다. **최초 검사 수치는 후속 STS 코드 변경 이전 결과**이며,
현재 작업 트리 전체의 검증 완료를 의미하지 않는다. 실제 AWS 환경 검증과 로컬 결과를 구분한다.

## 구현과 인수 조건

| ID | 반영 내용 | 구현·검증 근거 |
| --- | --- | --- |
| A1 | IAM 키·서비스 자격증명 전체 페이지, 사용자/루트 Credential Report, 마지막 사용과 실패 상태 | [IAM collector](../aws/backend/cremore_aws_provider/iam_inventory.py), 인접 `iam_inventory_test.py` |
| A2 | 단일 계정·독립 다계정·Organizations 계정별 동일 승인 경로 | [스케줄](../cremore/coverage/aws_scheduling.py), `aws_scheduling_test.py`, `worker/aws_inventory_test.py` |
| A3 | 자동 연결·최초/정기 수집, 제외/탈퇴 중단, 중복 작업 방지, 시작/저장 시 승인 재검사 | [job](../cremore/coverage/job.py), memory/SQLite/PostgreSQL의 설정 변경·동시 enqueue·row-lock 검사 |
| A4 | OU 경로, 선택 Control Tower baseline·계정 context, 수명주기 이벤트와 정기 조회 복구 | [조직 context](../aws/backend/cremore_aws_provider/aws_org_context.py), [Control Tower](../aws/backend/cremore_aws_provider/aws_controltower.py), 인접 검사·설정 API·worker 검사 |
| A5 | STS 발급과 호출자 사용 구분, 계정·역할·만료·출처, Event History와 명시적 S3 로그 범위 | [CloudTrail collector](../aws/backend/cremore_aws_provider/usage_inventory.py), `usage_inventory_test.py`, [관측 모델](../cremore/coverage/models.py) |
| A6 | 같은 객체/설정 블록의 STS 세 구성요소 결합, 순서·모호성·원문 보호, 기존 키 쌍 지문 유지 | [AWS 결합 함수](../aws/backend/cremore_aws_provider/detection/session_material.py), [탐지 검사](../cremore/detection/aws_session_test.py) |
| A7 | 발견 키 ID에 인벤토리 연결, 식별자·키 쌍·세션 값 일치 구분, 접근 철회 시 과거 근거 보존 | [상관분석](../cremore/coverage/correlation.py), `aws_evidence_correlation_test.py`, 기존 governance·coverage API 검사 |
| A8 | 계정별 IAM/STS/보고서/수집 상태의 저장 근거 API projection, 안정된 페이지 이어 읽기, 탐지 상세 메타데이터 | [AWS presenter](../aws/backend/cremore_aws_provider/inventory_view.py), 인접 `inventory_view_test.py`. 이전 `aws/web/inventory.tsx`는 삭제되었으며 현재 콘솔은 `iam_users`·`root_status`·`iam_report`를 렌더하지 않는다. 아래 최초 웹 검증은 당시 구현의 기록이다. |
| A9 | 팀 지침·권한·설치·운영 한계 최신화, 단일 wheel·기존 API 호환 | [AGENTS](../AGENTS.md), [팀 지침](AI_TEAM_CODING_GUIDE.md), [STS 평가](AWS_STS_VERIFICATION.md), [배포 안내](../deploy/cloudformation/control-tower-events.md) |

공급자 API·정규화는 `aws/`, 현재 공통 콘솔은 `web/`, 공통 권한·작업·저장·상관분석은 기존 `cremore/` 소유자를
사용한다. 새 서버·DB·수집 플러그인 체계는 만들지 않았다. 기존 JSON 관측 저장을 확장했으며
전체 metadata 정규화/DB 전환과 Atlassian 스캔 통합은 이전 보류 결정을 유지한다.

Credential Report의 `USER_STATUS`·`ROOT_STATUS` 행은 자격증명 자체가 아니다. `state=UNKNOWN`과 빈
`last_used_at`은 의도된 기본값이며, 비밀번호·MFA·키/인증서 활성 플래그와 `iam_report`의
`password_last_used_at`·`user_created_at`·키 슬롯별 마지막 사용 및 `field_status`를 읽어야 한다.
계정별 인벤토리 presenter의 `created_at`은 `iam_report.user_created_at`이다. 반면 현재
`/api/v1/coverage`의 `root_status.created_at`은 원본 관측의 보고서 생성 시각이며 계정 생성 시각이 아니다.

후속 감사 수정(2026-10-13):
- 수동 Organizations/SSO 발견과 발견 가능 계정 조회도 설치의 discovery hard lock을 먼저 확인하여
  `AWS_DISCOVERY_DISABLED`로 거절한다. 자동 발견 switch와 수동 요청은 별개다.
- 계정 요약의 `schedule_minutes`는 worker와 같은 연결별 주기 판정을 사용한다. 연결 소유의 0은
  수동이고 설치 switch가 꺼져도 허용된 연결 소유 주기는 표시한다.
- `KEY_CREATED` 호출자 ARN 검증은 수집기와 같은 `aws-eusc` partition을 허용한다.
- STS JSON 결합은 escaped 문자열을 decode하고 비문자열 중복 필드도 모호성으로 센다.
  지문과 인증 입력에는 decode한 값을 사용하고 마스킹 위치는 원문 span을 유지한다.

## 최초 인벤토리 검증 기록 — 후속 STS 변경 이전

이 절의 3,539개 Python 검사와 웹·빌드 결과는 최초 인벤토리 구현 당시의 기록이다.
그 이후 변경된 STS 관련 코드의 검증 증거로 재사용하지 않는다.

모든 공급자 자료와 자격증명은 fake client·합성 데이터다. Python 실행은
`AWS_EC2_METADATA_DISABLED=true`와 외부 socket 연결 차단을 사용했다. PostgreSQL은 이번 검증만을
위해 만든 PostgreSQL 17 컨테이너의 localhost `cremore_test` 및 테스트별 임의 schema를 사용했다.
운영 DB·기존 서비스/volume을 재사용하지 않았다.

- 전체 Python 1차: **5,394 passed, 7 failed, 59 skipped, 278 subtests passed**.
  새 테스트의 OPERATION 필수 필드 누락 3건, 합성 ID의 소스 내 단일 문자열 1건,
  Control Tower 전용 SQS 생성 위치 guard 1건, 작성 중이던 요약 fixture 2건을 확인했다.
  수정 후 해당 대상 선택 검사 **8 passed**, 저장소 비밀 패턴 검사 **1 passed**.
  이 결과를 전체 suite가 처음부터 전부 통과한 것으로 합산하지 않는다.
- 영향 범위 1차: **3,533 passed, 2 failed**. 위 SDK 생성 guard의 이전 버전과,
  Windows에서 두 테스트 수집 시각이 같은 clock tick이 되는 기존 metadata fixture를 확인했다.
  시간 순서를 명시한 fixture로 고쳤고 비활성 Vault API 오류 호환 회귀와 함께 **5 passed**.
- 최종 영향 범위: **3,539 passed, 실패·skip 0** (366.15초). AWS provider 전체, coverage 전체,
  detection 전체, AWS worker·settings API, governance·라이브러리 경계·저장소 비밀 패턴 검사를 포함한다.
  PostgreSQL 옵션을 켠 동일 검증이다. 위 1차 결과와 중복되므로 통과 개수를 합산하지 않는다.
- PostgreSQL: 동시 계정 연결/작업 생성이 하나로 수렴하고, 관리자 설정 변경이 인벤토리 저장
  트랜잭션과 직렬화되는 검사를 통과했다. 같은 목표 DB에서 coverage 저장·재실행·scope 검사를 수행했다.
- 웹: **492 unit passed**, TypeScript 및 프로덕션 빌드 통과. AWS 인벤토리·credential coverage·
  dashboard density 브라우저 proof **3/3 통과**; 마지막 접근 상태 표시 변경 후 coverage proof도 통과.
  합성 요청만 사용했고 외부 provider 요청은 없었다. KO/EN, light/dark, 1440/390px,
  계정 전환의 늦은 응답·권한별 버튼·상세 토글·페이지 revision 변경을 검사했다.
- 실제 FastAPI TestClient 응답 2페이지를 `createAWSInventoryLoader`와
  `AWSInventorySnapshotView`에 전달해 KO/EN 렌더 통과. IAM 키·서비스 자격증명·STS,
  사용자/루트 보고서가 표시되고 원문 토큰·비공개 지문이 응답/화면에 없음을 확인했다.
- Python wheel 빌드와 신규 모듈 포함 검사, 저장소 밖 wheel import 통과.
  기존 boto3 의존성 하한은 현재 IAM 페이지네이션·Control Tower API를 제공하는 검증 버전으로 갱신했다.
- 변경 Python Ruff, 문서 링크·참조, CloudFormation YAML 4개 파싱, `git diff --check` 확인.
  최종 파일에서도 Ruff·diff 검사를 통과했고 문서의 로컬 링크 76개를 확인했다.
- Windows의 POSIX skip 59개: GitLab flock 2개·Atlassian O_NOFOLLOW/uid 57개.
  지정 테스트 이미지 `cremore-verify-tests:296cf33`의 새 Linux 컨테이너에 현재 공급자 소스
  122개 파일을 복사하고 해시·import 출처를 확인했다. 네트워크와 volume 없이 Linux 파일시스템에서
  **59 passed, 76 subtests passed, 실패·skip 0** (19.04초). 검증용 컨테이너를 정리했다.

영향 범위의 기본 재실행 명령(저장소 루트):

```powershell
$env:AWS_EC2_METADATA_DISABLED='true'
# CREMORE_TEST_POSTGRES_URL에는 별도로 만든 localhost/cremore_test만 지정한다.
python -m pytest aws/backend cremore/coverage cremore/detection cremore/worker/aws_inventory_test.py cremore/api/aws_inventory_settings_test.py cremore/api/credential_governance_test.py cremore/api/library_boundaries_test.py cremore/repository_secrets_test.py -q -ra
```

## 보장하는 의미와 운영 환경 검증 범위

- STS는 **관측된 세션**이다. 전체 활성 세션 열거 API는 없으며, 미관측을 미발급·미사용으로 판단하지 않는다.
- ID 일치는 메타데이터 연결이다. 키 쌍 일치와 세 요소의 세션 지문 일치를 따로 표시한다.
  만료 전·과거 성공·정책상 가능성도 현재 인증 성공이나 특정 서비스의 실효 권한을 확정하지 않는다.
- 최초 인벤토리 검증 당시에는 STS 활성 verifier가 없었다. 현재 코드에는 후속 조건부 인증 확인 경로가
  추가되어 있지만, 이 보고서의 최초 검사 결과가 그 경로를 검증한 것은 아니다. 저장된 인증 결과와
  역할 정책의 잠재 권한·실제 서비스 권한은 구분한다. 세부 의미는 [STS 평가](AWS_STS_VERIFICATION.md)를 따른다.
- 계정별 조회는 최근 2개 run, 최근 관측 run, 마지막 COMPLETE baseline의 제한된 projection이다.
  실패가 반복돼도 마지막 완전 수집 근거를 보존한다. 저장된 전체 과거 run의 합집합을 모두 표시하는
  이력 아카이브 화면은 아니다. 조회 한도·부분 수집·scope 변경·접근 철회를 표시한다.
- 실제 고객 AWS API·CloudTrail 전달 지연/설정·STS 원문 인증·CloudFormation 배포·운영 부하는
  검증하지 않았다. 고객 계정의 trust/IAM/KMS/S3/SQS 권한과 trail 설정은 실제 도입 환경에서 확인해야 한다.
- 로컬 코드·문서 반영과 테스트 결과이며 원격 CI 통과·커밋·push를 의미하지 않는다.

## 후속 모듈 경계·저장 근거 표현 수정 — 2026-09-25

후속 STS 코드가 추가된 작업 트리를 검토한 뒤 아래 문제를 수정했다. 발견된 자격증명을 재사용하는
인증 구현·서명·토큰 전달 경로는 이번 수정 대상이 아니며 해당 경로의 정상 동작을 검증하지 않았다.

- [탐지 패키지](../cremore/detection/__init__.py)는 기존 API 패키지의 지연 import 패턴을 사용한다.
  순수 모델·지문·공급자 보조 모듈을 먼저 import할 때의 순환 참조를 제거하고,
  기존 `Engine`·`EngineConfig` 클래스 identity와 공개 exports를 유지했다.
- [공통 설정 저장 경계](../cremore/db/settings_store.py)의 `locked_settings`가 기존 트랜잭션과
  부모 행 잠금을 소유한다. AWS 조직 context·Control Tower 모듈은 공개 repository 메서드만 호출한다.
  잠금 대상·순서, 메모리 잠금, SQLite 트랜잭션, PostgreSQL 동시 갱신 의미를 유지했다.
- [저장 근거 API](../cremore/api/credential_governance.py)는 STS 지원 조건을 `CONDITIONAL`로 표시한다.
  저장된 인증 성공 결과와 `NOT_SUPPORTED`가 동시에 나오던 모순을 수정했으며 `execution_authorized=False`는 유지했다.
  KO/EN 화면에서 구성요소 관측, 확인 시점의 인증 결과, 현재 유효성, 서비스 권한을 구별한다.
- AGENTS·팀 지침·인벤토리 계약·STS 설명을 일치시켰다. 조건부 인증 확인 코드의 존재와
  실제 서비스 권한 검증 미구현을 구별하고, 위 최초 검사 수치를 후속 코드의 검증으로 재사용하지 않는다.

이번에 실제 실행한 검사:

- 통합 Python **101 passed, 실패·skip 0** (25.12초): `detection/imports_test.py`,
  `api/library_boundaries_test.py`, `api/credential_governance_test.py`, `api/verification_continuity_test.py`,
  `sources/module_contract_test.py`, `coverage/aws_session_models_test.py`, `db/settings_test.py`,
  AWS 공급자의 `aws_controltower_test.py`·`aws_org_discovery_test.py`.
  새 import 검사는 수정 전 실패를 재현했고, 수정 후 새 프로세스에서 순수 모듈과 기존 공개 import를 확인했다.
- PostgreSQL 17은 이번 작업 전용 `--rm`·tmpfs 컨테이너와 localhost의 `cremore_test` DB를 사용했다.
  계정 context의 경쟁 갱신, lifecycle 이벤트 중복 처리·ACK, 저장 실패 처리를 검사했다.
  SQLite의 내부 저장 호출이 바깥 트랜잭션보다 먼저 commit하지 않는 회귀도 포함한다.
- 웹 **181 passed, 실패·skip 0**: `node --test tests/dashboard.test.cjs tests/aws-inventory.test.cjs`.
  저장된 합성 STS 결과의 KO/EN 렌더와 기존 화면 회귀이며, 실제 인증 요청은 없다.
- TypeScript `--noEmit --incremental false`, 이번 수정 Python Ruff, `git diff --check` 통과.
  팀 문서 5개의 로컬 링크를 확인했다.

최초 검사·담당별 중간 검사와 겹치는 수치를 합산하지 않는다. 이번에는 전체 저장소 검사,
프로덕션 빌드·브라우저 검사, 실제 AWS 인증·서비스 권한 호출·운영 부하를 실행하지 않았다.
실제 인증 재사용 경로의 작동성 검증은 제외했으며, 모듈·저장·표시 검사 통과가 이를 대신하지 않는다.

## S3 trail 로그 읽기 범위 — 2026-09-27

S3 모드 수집은 설정한 prefix 아래 객체를 모두 나열·다운로드한 뒤 계정·리전·기간으로 이벤트를 걸렀다
(`usage_inventory.py`). 조직 전체 prefix를 쓰면 계정마다 조직 전체 로그를, 단일 계정 trail이어도 보관된 전체
이력을 매번 읽어 객체 한도(`max_records`, 기본 5만 = `LOG_OBJECT_LIMIT`)에 먼저 걸렸다.

이제 [CloudTrail 문서](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html)의
경로 형식(`<prefix>/AWSLogs/[<조직 ID>/]<계정 ID>/CloudTrail/<리전>/<YYYY>/<MM>/<DD>/`, 날짜는 파일 게시일)을 따라
연결 계정·설정 리전의 디렉터리만 나열하고, 기간 시작 하루 전 날짜부터 `StartAfter`로 읽는다. 걸러 내던 레코드와
같은 범위만 읽으므로 수집 결과의 의미는 같다. `CloudTrail-Digest`·`CloudTrail-Insight`·`CloudTrail-Aggregated`는
호출 단위 신원이 없어 읽지 않고, 네트워크 활동 이벤트(`CloudTrail-NetworkActivity`)는 계속 읽는다. `AWSLogs` 아래가
CloudTrail 형식이 아니면 예전처럼 prefix 전체를 읽는다.

합성 버킷 측정(한 계정 수집, 3개 리전, 1년 보관, 기간 7일):

| 조직 규모 | 수정 전 | 수정 후 |
|---|---|---|
| 계정 20개(객체 21,900) | 요청 21,922(목록 22·다운로드 21,900), COMPLETE | 요청 33(목록 6·다운로드 27), COMPLETE |
| 계정 100개(객체 109,500), 기본 한도 | 요청 50,051·다운로드 50,000 뒤 `LOG_OBJECT_LIMIT`로 FAILED | 요청 33, COMPLETE |

수정 후 요청 수는 조직 크기·보관 기간과 무관하고 (리전 수 × 기간 일수)에 비례한다. 새 테스트 6개와 변이 7건으로
경로 따르기·기간·리전·이벤트 종류·다른 계정 prefix·형식 밖 디렉터리 처리를 확인했다. 실제 S3 버킷·조직 trail에서는
검증하지 않았다.

## 콘솔의 IAM Identity Center 로그인 — 소유자 검토·승인 2026-10-02

`aws_sso_login`(커밋 52eaadc, 콘솔의 "AWS에서 로그인")은 공동 검토 대상 모듈이라, 검토 요약(하는 일, 신뢰 경계, 남는 위험,
검증 범위)을 소유자에게 제출했다. 소유자는 2026-10-02 "1인 설치에서만"으로 승인했다.

- 코드를 승인한 사람의 권한 세트가 CreMore의 AWS 신원이 되고 같은 `~/.aws`를 쓰는 서버 CLI의 신원도 바뀐다. 그래서
  사람이 회사 IdP로 로그인하는 팀 설치(`AUTH_MODE=oidc`)에서는 `POST /api/v1/aws/sso-login/start`·`/poll`이
  `409 AWS_SSO_LOGIN_SOLO_ONLY`로 거절하고, 신원 화면(`GET /api/v1/aws/scanner-identity`의 `sign_in_here: false`)에 따라
  콘솔은 버튼 대신 서버 역할·기계 신원으로 연결하라고 안내한다. 1인 설치(`AUTH_MODE=local`)는 그대로다.
- 남는 위험은 1인 설치에만 있다: 로그인이 끊긴 사이 관리자 세션을 가진 사람이 다른 Identity Center 계정으로 승인하는 경우.
  승인된 스캔 신원과 권한 세트가 다르면 스캔이 멈추고(`AWS_SCANNER_IDENTITY_CHANGED`), 감사 기록에 승인자 세션 ARN이 남는다.
- 팀 설치가 다른 경로로(마운트한 `~/.aws`의 SSO 프로필) 사람의 세션에 기대면 운영 화면이 맨 위에 그 사실을 알린다
  (`operations/status`의 `HUMAN_SESSION_IN_SERVER_DEPLOYMENT`). 설치 단위 경보는 연결·작업별 경보 100개 상한에 잘리지 않는다.

검증: 합성 OIDC·합성 신원 조회·임시 홈 폴더(`cremore/api/aws_sso_login_routes_test.py` 6개, 경보 순서는
`cremore/operations/health_test.py`의 `test_the_installations_own_alerts_lead_and_outlast_the_cap_on_per_job_alerts`, 콘솔 단위
검사). 실제 IAM Identity Center로는 확인하지 않았다.


## 2026-10-02: 메타데이터 누락 사유와 IAM 정책 요약

- 발급 목록 응답은 마지막 사용의 정보 없음/권한 거절/실패를 보존한다. 콘솔은 실제 날짜가 없는
  사유를 값 수집률에 포함하지 않고, 만료일 없음과 발급처가 보고한 활성 상태를 구분한다.
- 발급 목록의 `iam_policy_metadata`를 켜면 IAM 사용자·그룹 정책을 기존 정책 reader로 조회한다.
  옵션이 없는 기존 연결만 종전의 `iam_potential_access` 스위치를 따른다. 명시적으로 선택한 연결은
  시뮬레이션 스위치와 분리되며 설치의 `IAM_POTENTIAL_ACCESS_MODE=disabled` 차단은 유지한다.
  기존 계획의 부재 값은 새 기본값과 구별해 같은 수집 레코드에 명시적 선택을 반영한다.
  2026-10-04 후속 검증: 온보딩·AWS 역할 회귀 125개 통과, PostgreSQL 전용 3개 skip(격리 DB 미설정).
  기존 계획 전환 회귀 2개는 수정 전 실패·수정 후 통과했고 수집 ID·중지 상태·주기 보존을 확인했다.
  설정 중단·승인 변경·취소·리스 실패·요청 한도를 유지하고 같은 사용자의 두 키는 조회를 공유한다.
- 저장은 선택적 JSON 필드 `iam_policies`의 제한된 요약뿐이다. 원문 정책·조건값은 저장하지 않는다.
  `scopes`는 그대로 두며 정책 Allow 작업을 현재 유효한 접근 권한으로 해석하지 않는다.
- scanner 역할에 `iam:GetUser`, `iam:ListUserPolicies`, `iam:GetUserPolicy`,
  `iam:ListAttachedUserPolicies`, `iam:ListGroupsForUser`, `iam:ListGroupPolicies`,
  `iam:GetGroupPolicy`, `iam:ListAttachedGroupPolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`이 필요하다.
  권한 거절은 키 삭제나 빈 정책 목록으로 바꾸지 않는다. 기존 행은 재수집 전까지 정책 미수집이다.
- AWS 발급 계획에서 CloudTrail Event History의 리전·조회 기간(1–90일)을 선택할 수 있다.
  성공한 `CreateAccessKey` 응답의 키 ID·수신 계정과 IAM 키를 연결하고 호출자 ARN·이벤트 ID·시각만 남긴다.
  생성 키를 호출자 키와 혼동하지 않고 사용 기록·현재 활성 상태로 승격하지 않는다.
  연결 없음·미수집·조회 미완료·조회 범위에서 이벤트 없음·상충 근거를 구분한다.
  IAM 전역 이벤트 조회에는 `us-east-1`을 포함한다. 오래된 이벤트는 Event History에서 조회할 수 없으며,
  별도 승인된 기존 S3 trail 수집도 같은 이벤트 정규화를 쓴다. 이 변경은 trail/S3 버킷을 생성하지 않는다.
- DB 테이블/설정 이관은 없다. 검증 결과는 아래 후속 실행 기록을 따른다.

- 온보딩의 `cloudtrail_creation_only`는 기본 켜짐이다. 생성자 확인에 필요한
  `CreateAccessKey`만 Event History에서 서버 필터로 조회하며 반환 이벤트도 다시 검사한다.
  끄면 기존 전체 이벤트 수집을 사용한다. 기존 설정은 빈 `cloudtrail_event_name`으로 호환한다.
  수집 중은 실패/권한 거절과 분리해 표시한다.

### 후속 실행 검증 (2026-10-02)

- IAM 정책 작업명 검증에 하이픈이 있는 서비스 접두사(`aws-portal`, `purchase-orders`)를 허용했다.
  정상 정책을 `IAM_POLICY_RESPONSE_INVALID`로 거절하던 회귀를 검사한다.
- 합성 검사: 정책 수정 관련 Python 232개 통과·PostgreSQL 9개 건너뜀,
  생성 이벤트 필터·모델·온보딩 101개 통과. 마지막 콘솔/AWS 단위 검사 35개와 TypeScript 검사 통과.
  격리 PostgreSQL 검사는 실행하지 않았다. 앞선 전체 웹 226개·프로덕션 빌드와 브라우저 목록 검사 1개도 통과했다.
- 승인된 로컬 AWS 연결에서 API·worker를 갱신하고 수동 재수집했다.
  IAM은 15:44:15 KST에 COMPLETE(관측 22개), CloudTrail은 15:44:24 KST에 COMPLETE(관측 18개)였다.
  액세스 키 6개 모두 정책 요약 COMPLETE 및 생성자 OBSERVED를 확인했다.
  기존 전체 이벤트 실행은 worker 교체로 중단된 이력을 유지하며, 새 실행은 생성 이벤트만 조회한다.
  자동 수집은 켜지 않았다. 정책 요약은 실제 서비스 접근 권한 검증을 뜻하지 않는다.
- 수집된 AWS 액세스 키 상세에서는 불필요한 이름 행을 생략한다.

## 2026-10-02: 노출 상세 CloudTrail 사용 기록 한도

- `investigation/usage.py`의 수동 조회는 기존 페이지 순회를 재사용해 리전당 기본 100건에서
  1,000건으로 늘렸다. 100페이지 제한을 유지하고 정규화 JSON 1 MiB 제한을 추가했다.
  다음 페이지까지 0.55초를 두며, 동시 조회에 따른 throttling은 SDK 재시도 후 실패 근거로 남는다.
- 콘솔은 저장된 `events_per_region`을 표시하고 없는 과거 기록은 100건으로 해석한다.
  페이지·크기 한도와 오류 코드도 표시하며, 잘린 결과를 완료나 미사용으로 해석하지 않는다.
- 새 조회는 새 90일 구간의 snapshot을 저장한다. 페이지 토큰·원문 응답은 저장하지 않고
  요청 사이 이어받기나 무제한 누적 기능은 추가하지 않았다.
- 검증: 사용 기록·계정 격리·세션 만료 관련 Python 29개, 웹 단위 검사 6개, TypeScript,
  변경 Python Ruff, diff 공백 검사 통과. Chrome 브라우저 proof 1개는 KO/EN·light/dark·320/1440의
  8가지 조합에서 부분 수집 사유·키보드 펼침·넘침을 확인했다. 별도 PostgreSQL 검사는 실행하지 않았다.
- 로컬 API·worker 이미지를 빌드·교체하고 승인된 연결에서 17:46 KST에 재조회를 시작했다.
  활성 리전 발견 COMPLETE, 17곳 중 16곳 COMPLETE, 조회 실패 0, 관측 1,751건이었다.
  서울 리전은 1,000건 한도로 CAPPED이며 전체는 PARTIAL이다. IAM 시뮬레이션은 COMPLETE였다.
  이 결과를 최근 90일 전체 수집 완료로 해석하지 않는다. 새로 활성화한 리전이 있으면 로컬 역할의
  `cloudtrail:LookupEvents` 리전 조건도 함께 갱신해야 한다.

## 2026-10-02: 대량 사용 기록의 백그라운드 수집

- 노출 상세의 조회는 202 응답으로 작업을 접수하고 기존 worker 큐에서 이어 읽는다.
  이전 동기 API는 유지한다. 새 작업은 콘텐츠 스캔이 아니며 DB 테이블·index 이관은 없다.
- 리전별 1,000건 제한 대신 실행당 CloudTrail 10,000페이지·6시간·활성 리전 최대 100곳을
  적용한다. 페이지당 50건이므로 최대 50만 건의 이론적 상한이며, 빈 페이지·재시도·시간에
  따라 실제 가능한 건수는 줄어든다. 조회 기간은 실행 시작 시 최근 90일로 고정한다.
- 계정별 작업은 직렬화하고 20페이지마다 큐에 돌려준다. 페이지 사이 0.55초를 두며
  요청 예산은 호출 전에 차감한다. 집계와 다음 cursor는 같은 lease-fenced transaction에
  저장하므로 worker 재시작·로그인 만료 뒤 이어 읽는다. 취소·승인 변경·수집 설정 중단과
  오래된 동기 요청의 덮어쓰기를 검사한다.
- 호출·서비스·거부·분류별 전체 합계와 최근 성공 시각을 유지하고 상세 기록은 최근 100건만
  저장한다(화면에는 최근 20건). 원문 응답은 저장하지 않으며 cursor는 비공개 checkpoint에만
  남긴다. 부분 수집과 한도·조회 오류를 완료로 승격하지 않는다.
- 합성 10,051건을 202페이지로 읽고 worker를 교체해도 중복 집계하지 않으며,
  페이지 저장 도중의 장애에서는 집계·cursor가 함께 rollback되는 것을 확인했다.
  메모리·SQLite·격리 PostgreSQL의 작업 검사 34개와 추가 로그인 만료·순환/비정상 cursor 검사
  9개가 통과했다. 별도 사용 기록·상세 근거 묶음은 59개 통과·PostgreSQL opt-in 1개 skip이었다
  (같은 PostgreSQL 검사는 앞의 격리 실행에서 통과). API·worker·task 회귀 209개,
  공급자/API 경계 76개, 웹 사용 기록·로그·수집 단위 14개, TypeScript·프로덕션 빌드·Ruff·diff 검사도 통과했다.
  Chrome proof 1개는 KO/EN·light/dark·320/1440 표시와 비동기 접수·중지 동작을 확인했다.
- 최근 상세 기록의 기존 `technique_id` 표시도 유지하며 해당 집계·계정 불일치·분류 회귀
  5개를 다시 통과했다. 수집 로그에는 `AWS 사용 기록 수집`으로 분류하고 실행 중 중지도 제공한다.
- 로컬 API·worker를 새 이미지로 교체한 후 18:19 KST에 승인된 계정의 `su_jss` 사용 기록을
  화면에서 재조회했다. 64페이지·2,453건(거부 응답 109건)을 읽고 리전 17/17 COMPLETE,
  조회 실패 0·한도 초과 0·작업 SUCCEEDED였다. 서울은 기존 한도를 넘은 1,654건으로 COMPLETE,
  IAM 시뮬레이션도 COMPLETE다. 저장된 상세는 100건이고 화면에는 최근 20건을 표시한다.
  거부 응답 109건은 해당 키의 과거 호출 결과이며 수집기의 조회 실패가 아니다.
- 키별 Event History 조사의 확장이다. 조직 전체의 지속 수집·장기 보관·데이터 이벤트는
  별도 승인된 기존 S3 trail 경로와 실제 조직 규모의 운영 검증이 필요하다.
  50만 건 부하나 다중 계정 기업 환경 전체를 검증한 결과로 해석하지 않는다.

### 브랜치 반영 전 검증 (2026-10-02)

온보딩·AWS·Notion·발급/사용 근거 묶음은 Python 1,047개 통과·격리 PostgreSQL opt-in 18개
skip이었다. 앞 절의 별도 PostgreSQL 실행 결과와 구분한다. 전체 웹 단위 228개,
TypeScript를 포함한 프로덕션 빌드, 변경 Python Ruff와 staged diff 공백 검사도 통과했다.
브라우저는 목록·연동 수정·메타데이터 팝오버·사용 기록 4종을 통과했다. 팝오버 검사의
스크롤 완료 전 열기 순서가 간헐 실패를 만들어 기존 `frames`·`openMenu` helper를 재사용했다.
목록·필터·CSV와 상세 탭의 담당자 표시는 `대응 담당자` / `Response owner`로 맞췄다.

### 상세 화면 권한 근거 동기화 (2026-10-04)

- `credential-records.aws_permissions`는 저장된 IAM 조회에서 소유 계정과 정확한 주체 ARN이
  일치하는 정책·시뮬레이션만 전달한다. 권한 카드·관계도·위험 규칙은 같은 행을 읽는다.
  별도 조회가 아직 없어도 식별자로 연결된 발급 인벤토리의 IAM 정책을 표시하고,
  조회와 인벤토리가 함께 있으면 정책 수집 시각으로 선택한다. 부분·과거 관측은 유지한다.
- 목록/상세 위험 점수와 저장 근거 재평가는 최신 검증보다 늦게 수집한 완전한 시뮬레이션을
  기존 권한 점수 해석기로 읽는다. 다른 계정·주체, 부분/실패, 누락된 작업은 점수를
  올리는 완전한 평가로 쓰지 않는다. 키 ID만으로 인증 성공을 주장하지 않는다.
  정책 목록만 있을 때는 이를 표시하되 실제 접근이나 전체 잠재 권한 평가로 대체하지 않는다.
- 다른 공급자의 기존 `scope`·`role`·`permission` 연결 경로는 유지하고 명시적 ALLOW만
  허용 권한으로 옮긴다. 거부/불명확한 항목과 과거 위치의 오래된 scope를 허용 권한으로
  합산하지 않는다. 공급자가 공개하지 않은 권한이나 실환경 지원 범위를 새로 추정하지 않는다.
- 사용 조회의 정책/시뮬레이션/작업 상태 변경 시 관련 읽기를 갱신한다. 정책 시뮬레이션은
  기존 `DetailPopover`로 열며 레이아웃을 밀지 않는다. 노출 위치 제목의 단어 줄바꿈을
  개선하고 대응 진행 카드는 대응 담당자 탭에 둔다.
- 검증: 위험 모델·재평가·API·공급자 경계 묶음 197개 통과, 후속 API 변경 54개 통과,
  후속 재평가 38개 통과. PostgreSQL opt-in 14개는 미설정으로 skip(메모리/SQLite 실행).
  웹 전체 274개, tsc, 프로덕션 빌드, 변경 Python Ruff, 공백 검사 통과.
  브라우저 4종(권한 상세·메타데이터 팝오버·대응 진행·담당자 선택) 통과.
  권한 상세는 KO/EN·light/dark·375/1440px에서 제목·팝업 경계·레이아웃 유지·
  Escape/초점 복귀·인벤토리 표시·후속 조회 자동 갱신을 확인했다. 실제 공급자 재수집은
  이 회귀 검사에 포함하지 않았다.
