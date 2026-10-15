# gcp 공급자 소유 영역

### 인벤토리 감사·금고 선택 옵션 (2026-10-05)

온보딩에서 `audit_logs`(키 생성자·키 ID가 명시된 사용), `api_metrics`(API 키 사용량 구간),
`audit_days`(1–30일)를 선택한다. 발급 목록만 연결해도 사용할 수 있으며 금고를 필수로 요구하지 않는다.
금고에는 `locations`(regional Secret Manager)와 `secret_iam`(수집한 시크릿 정책의 접근 후보)을 제공한다.
생성자 연결은 서비스 계정 키와 API key의 정확한 생성 리소스·프로젝트·actor가 있을 때만 기록한다.
regional 시크릿의 로그·정책 관계는 리전을 식별자에 유지해 같은 이름의 글로벌 시크릿과 합치지 않는다.
`service_account_iam`은 프로젝트의 직접 allow-role 바인딩만 후보 근거로 수집한다. 조건 존재를 표시하며
조직 상속·deny·경계 등을 평가한 유효 권한이나 토큰 scopes를 뜻하지 않는다(실효 판정은 아래 `effective_access`).
새 로그/정책 조회는 기본 해제이고 권한 재점검 후 적용한다. 기존 sources 없는 relations 계약은 유지한다.
지표 구간은 정확한 호출 시각이 아니며 정책 후보는 유효 권한이 아니다. 생성 로그의 privateKeyData·원문
응답은 저장하지 않는다. 상세 근거·제약은 [재검토 기록](../docs/INVENTORY_METADATA_REVIEW_2026-10-05.md)을 따른다.
키 리소스·감사 로그의 숫자 서비스 계정 ID는 같은 실행의 계정 목록이 제공한 `uniqueId`와 이메일로만
연결한다. 프로젝트 번호도 기존 Resource Manager 검증을 거친다. 단순 키 ID 일치로 다른 계정을 합치지 않는다.

### 서비스 계정 키의 실효 판정 (2026-10-07)

`effective_access`를 켜면 사용자 관리 키가 있는 서비스 계정마다 Policy Troubleshooter v3
`iam:troubleshoot`에 고위험 권한 11개를 프로젝트 기준으로 묻는다(`metadata/effective_access.py`, 한 수집에
계정 최대 20개). Google이 프로젝트·상위 폴더·조직의 allow·deny 정책, 그룹 구성원, 조건을 함께 평가한 답이며,
`CAN_ACCESS`만 키의 허용 권한(`ALLOW`)이 되어 콘솔의 권한 표에 나온다. `CANNOT_ACCESS`는 `DENY`, 그 밖의 답과
호출 실패는 `UNKNOWN`이다. 연결 신원에 조직의 `roles/iam.securityReviewer`·`roles/iam.denyReviewer`를 주고,
그룹으로 받은 권한까지 보려면 Workspace 관리자 역할의 그룹 읽기 권한도 준다. API는 연결 신원의 프로젝트
(Google 로그인은 OAuth 앱 프로젝트)에서 켠다. 꺼져 있으면 한 번 묻고 멈추며, 한 계정의 호출이 모두 실패해도
이후 계정은 묻지 않는다. 개별 버킷·시크릿 정책,
Cloud Storage ACL, VPC Service Controls는 이 판정에 들어가지 않는다. 상세는
[권한 평가의 근거와 한계](../docs/PERMISSION_ASSESSMENT.md)를 따른다.

Cloud Storage 콘텐츠, GCP metadata·ADC·값 수집 구현을 소유한다. 제품 adapter와 전용 테스트는 `backend/cremore_gcp_provider/`에 있다.
공통 플랫폼이 해당 라이브러리 함수를 직접 호출하며 제품의 Python wheel 하나에 함께 설치된다.

Cloud Storage 콘텐츠 목록은 다음 페이지 토큰 하나를 UTF-8 8 KiB로 제한하고, 같은 수집기의 목록들에서
토큰을 총 10,000개까지만 받는다. 중복 이력은 고정 길이 지문만 메모리에 남기며 순환·한도 초과는 수집 실패다.
객체 목록은 한 쪽에 1,000개씩 읽고, 스캔이 쓰는 필드(`name`·`bucket`·`generation`·`size`)만 받는다(`fields`).
버킷 목록은 100개씩이다. ADC와 Google 로그인 토큰은 동시에 읽는 스레드들이 함께 쓰며 갱신은 한 번에 하나만 한다.

이 폴더에는 UI가 없다. 연결 화면은 `backend/`의 onboarding descriptor로 콘솔(`../web/console/`)이 그린다.

`standalone/cremore_gcp/`는 플랫폼에 의존하지 않는 재사용 라이브러리다.
제품이 이 패키지의 공통 함수를 직접 사용하며, 같은 Python wheel에 함께 설치한다.
독립 CLI(인벤토리·관계·API 키 매칭·Secret 평문 내보내기·watcher)와 그것들만 쓰던 모듈은 2026-09-27 삭제했다.

| 모듈 | 책임 |
| --- | --- |
| `resources.py` | 리소스 식별자, 상태·오류 정규화, 지역별 Secret endpoint |
| `transport.py` | 공통 `ApiError`·`JsonTransport` |
| `values.py` | 크기 제한·base64·CRC32C 검증, API 키·공개 인증서·불변 Secret 버전 읽기 |
| `linkage.py` | 식별자 매칭과 `scan_text`; 명시적 호출에서만 API 키 lookup 수행 |

`backend/cremore_gcp_provider/metadata/`는 제품의 요청 예산·재시도·페이지 재개·DB 저장 연결을
소유한다. 공통 검증·값 reader·매칭은 `cremore_gcp`에서 수정하고 backend에 복제하지 않는다.
호출자가 transport를 주입해 함수를 호출하며 import만으로 인증·수집하지 않는다.

루트에서 `python -m pip install -e ".[dev,gcp]"`로 개발 설치 후
`python -m pytest gcp/backend -q`로 전용 합성 회귀를 실행한다.
실제 호출은 별도로 지정한 환경·범위에서만 수행한다.

[공통 AGENTS](../AGENTS.md), [팀 지침](../docs/AI_TEAM_CODING_GUIDE.md),
[실제 디렉터리·등록·빌드 경계](../docs/PROVIDER_DIRECTORY_REVIEW.md)를 먼저 읽는다.
UI 작업에는 [web 지침](../web/AGENTS.md)과 설치된 Next 문서도 적용한다.
공통 API·DB·권한·scope·작업 수명·SIEM 계약과 registry는 플랫폼 담당자와 나누어 작업한다.

## 조직·폴더 발견과 프로젝트 인벤토리 승인

기존 `mode=inventory`는 명시한 **단일 project**의 서비스 계정·키, API 키, Secret Manager
메타데이터를 기존 capability에 따라 수집한다. `include_values`와 `issuer_value`·`vault_value`는
승인된 값을 메모리에서 읽고 HMAC 지문으로 대조하는 계약이다. 조직 발견으로 이를 활성화하지 않는다.
수집 원문은 가역 암호화 형태도 보관하지 않는다. `store_values`·`keep_values`와 원문 조회 API는 폐기했다.
과거 설치의 값은 [이관 절차](../docs/integration/GCP_TOTAL_GUIDE_KO.md#과거-원문-저장-설치의-이관)로 별도 정리한다.

Google 응답이 프로젝트 ID 대신 번호를 사용하면 승인한 ID의 Resource Manager `projects.get`
응답에서 `projectId`와 `name`을 함께 확인해 번호를 연결한다. 이 선택적 확인에는
`resourcemanager.projects.get` 권한이 필요하다. 권한이 없거나 번호의 소속을 확인하지 못하면
그 리소스를 후속 조회·값 읽기에 사용하지 않고 부분 수집으로 표시한다. 승인한 ID가 그대로
반환되는 리소스는 추가 권한 없이 읽는다. 이 매핑은 실행 시도마다 다시 확인하며 목록 응답이나
저장된 관측만으로 다른 프로젝트를 승인하지 않는다.

Cloud Logging의 사용 관계는 승인한 프로젝트 ID·검증한 프로젝트 번호의 정확한
`cloudaudit.googleapis.com/{activity,data_access,system_event,policy}` 스트림만 요청과 응답에서
허용한다. URL 인코딩된 log ID는 한 번만 정규화한다. 다른 프로젝트·사용자 정의·중첩
스트림은 사용 근거에서 제외하고 `invalid_log_evidence`와 부분 수집으로 남긴다.

`mode=discovery`는 **단일 organization 또는 folder** 숫자 ID를 승인 root로 사용하며
`capabilities=["inventory"]`만 허용한다. `include_values=false`,
`locations=[]`로 설정한다. 인증은 ADC·workload identity 또는 대시보드 Google OAuth(`google_oauth`)를 쓴다.
OAuth 연결은 인가한 사용자의 토큰으로 조회하며 Worker의 ADC로 대체하지 않는다.
Google 로그인 앱(웹 OAuth 클라이언트)은 API의 `GCP_OAUTH_*` 설정이나 연결 마법사에서 저장한다(시크릿 봉인,
[대시보드 OAuth](../docs/integration/GCP_DASHBOARD_OAUTH_KO.md) 3.2절).

```json
{
  "provider": "gcp",
  "origin": "https://googleapis.com",
  "edition": "cloud",
  "auth_type": "adc",
  "scopes": [{"kind": "organization", "id": "123456"}],
  "capabilities": ["inventory"],
  "options": {"mode": "discovery", "include_values": false, "max_targets": 50}
}
```

이 예시는 이름·예산 등 나머지 연결 필드와 합쳐 사용하는 설정 발췌다. 폴더 root는
`{"kind":"folder","id":"234567"}`로 지정한다. `max_targets`는 root를 포함해 하위 목록을
조회할 부모 수의 상한이다. 전체 페이지·요청·레코드 예산도 모든 하위 조회에 걸쳐 적용한다.

Resource Manager v3 `GET /v3/projects?parent=...`와 `GET /v3/folders?parent=...`는 **직계 자식**만
반환하므로 ACTIVE 폴더를 재귀 조회한다. 응답의 `parent`가 요청 부모와 정확히 같아야 하며,
각 재개 작업은 저장된 부모·자식 관측으로 탐색 대상을 복원한다. 체크포인트에 임의 폴더를 넣어
승인 root를 확장할 수 없다. 외부 machine submission으로 발견 계층을 제출하는 경로도 허용하지 않는다.

필요 권한은 각 부모의 `resourcemanager.projects.list`, `resourcemanager.folders.list`다.
하위 폴더에서의 거절·잘못된 응답·중복/순환·페이지/요청/대상 한도는 `PARTIAL`로 남긴다.
429/5xx는 마지막 commit 위치에서 대기·재개하며, 저장하지 못한 페이지의 cursor는 진전하지 않는다.
삭제 요청 상태의 폴더는 선택적으로 표시하지만 그 아래를 자동 탐색하지 않는다.

발견 항목은 `resource`와 `selection=context_only`로 저장한다. 승인 root scope를 유지하고
`gcp.resource_manager.projects`·`gcp.resource_manager.folders` operation으로 발급 키 수집과 구분한다.
`proves_completeness=false`이며 **프로젝트 내부 자격증명의 완전한 목록을 증명하지 않는다**.
발견한 프로젝트의 실제 키·금고 수집은 별도의 명시된 project 연결과 권한이 필요하다.

Native export는 기존 `inventory`·`relations` 형식을 유지하고 `discovery`를 추가한다.
발견 resource를 credential이나 vault item으로 변환하지 않는다. `discovery.project_inventory_authorized`
값은 `false`이며, 기존 credential 비교·소실 판정은 hierarchy resource를 제외한다.

## 평문 서비스 계정 JSON과 발급 키의 수동적 연결

제품 내부 호출자는 `cremore_gcp_provider.metadata.linkage`에서 다음 순수 함수를 import한다.
실제 구현은 `cremore_gcp.linkage` 하나다.

- `service_account_key_identifier(candidate: Mapping) -> str | None`: `type=service_account`,
  `client_email`, `private_key_id`만 검증해 `serviceAccountKey:<email>:<key_id>`를 반환한다.
  `private_key`·`project_id`를 읽지 않는다.
- `service_account_key_identifiers(data: bytes, private_key: bytes) -> tuple[str, ...]`: 전체 UTF-8 JSON의
  같은 객체에 들어 있는 PEM과 식별자만 연결한다. JSON은 최대 1 MiB·1024 노드·깊이 32이며,
  중복 필드·비정상 JSON·초과 입력은 빈 결과다. JSON으로 이스케이프한 개행과 실제 개행을
  정규화해 탐지된 PEM과 비교하고, 같은 PEM에 연결된 서로 다른 식별자는 모두 반환한다.
  JSON 외 텍스트에서 가까이 있는 이메일·ID를 임의로 조합하지 않는다.
- 기존 `adapter.link_service_account_key(records, candidate)`의 결과 형식은 유지한다.
  `identifier_match`는 발급 목록의 식별자 연결이며 `validity=unverified`다.
- 금고 대조에서 발급 키는 금고 값에 같은 키 ID가 있으면 `IDENTIFIER_ONLY`다. 선언한 금고 범위가
  완전·최신이고 키 ID가 없거나 모호한 서비스 계정 키 값이 없을 때만 `IDENTIFIER_NOT_OBSERVED`다.
  키 ID 비교는 개인키 값 일치나 현재 인증 가능 여부를 뜻하지 않는다.

플랫폼은 공급자·origin·승인 project·connection 범위를 별도로 묶어 비교한다. 여러 식별자가
반환되면 모호한 근거이며 자동으로 하나를 선택하지 않는다. 이 연결은 개인키와 공개키의
암호학적 일치, 현재 인증 성공, 실효 권한을 증명하지 않는다. 발견된 키를 외부로 보내지 않는다.

## Secret Manager 값 대조의 두 경로

GCP Secret Manager 값은 두 계약 중 하나로 금고 대조 범위에 들어간다. 둘 다 원문을 메모리에서 지문화하지만
**현재 값으로 인정되는 근거가 다르다**.

| | schema 1 `gcp_secret_manager` | schema 2 `gcp` (`vault_metadata`·`vault_value`, `include_values=true`) |
| --- | --- | --- |
| 실행 위치 | 고객 환경의 `cremore-coverage` CLI(Google ADC). 새 연결 마법사에서는 고를 수 없고 기존 연결만 유지된다 | CreMore worker(worker의 ADC·workload identity, 또는 대시보드 Google OAuth의 봉인 참조) |
| 수집 | 지정 project의 secret 또는 명시 reference의 선택 버전(기본 `latest`) | secret·버전 메타데이터와 ENABLED 버전 값, 페이지 재개·예산 |
| 값의 버전 근거 | `latest` 조회는 `CURRENT`. 일치하면 `MATCHED` | 모든 값이 `version_state=UNKNOWN`. ENABLED 버전 목록만으로 최신 버전을 단정하지 않는다 |
| 대조 결과 | 현재 보관(`MATCHED`)과, 범위가 완전·최신일 때 부재(`NO_VAULT_MATCH`)를 판정할 수 있다 | 일치는 과거 이력(`history`)으로만 남는다. 값을 하나라도 읽었으면 `CURRENT_VERSION_NOT_CONFIRMED`가 금고 범위의 부재 판정을 막는다 |
| 원문 저장 | 없음 | 없음. 메모리에서 HMAC 지문과 필요한 메타데이터로 바꾸며 가역 암호화·Base64 보관도 금지 |

schema 2 값 읽기만으로는 비밀이 현재 금고에 있다는 판정(`MATCHED`)을 얻지 못하고, 읽은 값이 있으면 금고에
없다는 판정도 막힌다. 그 판정이 필요하면 기존 schema 1 `latest` 연결을 유지한다. 두 경로를 함께 등록하면
schema 1의 현재 값 일치와 schema 2의 이력이 따로 표시되며, schema 2가 읽은 값이 남아 있는 동안 부재 판정은
열리지 않는다.

schema 1은 Google이 리소스 이름을 프로젝트 번호로 반환하면(`projects/<번호>/secrets/...`) 같은 실행의
Resource Manager `projects.get` 응답에서 `projectId`와 번호를 확인한 뒤에만 승인한 ID 이름으로 바꿔 대조한다.
이 확인에는 `resourcemanager.projects.get` 권한이 필요하다. 확인하지 못한 번호 이름은 범위 밖
(`PROVIDER_SCOPE_MISMATCH`)으로 남는다.

두 경로 모두 연결을 켜 둔 동안 금고 대조 범위에 포함되고, 범위가 바뀌면 관리자가 대조 범위를 다시 확인해야
부재 판정이 열린다. 경로를 옮길 때는 새 경로의 수집이 완료된 뒤 이전 연결을 중지한다.

schema 2의 값 변경 관측은 성공적으로 읽은 각 payload의 비공개 HMAC을 사용한다. 바이너리·빈 값도 포함하며,
같은 scheme·key ID의 관측끼리만 변경을 판단한다. 이 지문은 기존 `value_match` 대조와 별개이며 공개 응답·export에 싣지 않는다.

## 서비스 계정 키의 승인형 조치 (`remediation.py`)

발급 목록에 있는 **사용자 관리 키**를 승인된 조치 계획으로 비활성화(`keys:disable`)하고, 비활성화된 키만 영구
삭제(`keys.delete`)한다([공급자 자격증명 조치](../docs/PROVIDER_ACTIONS.md)). Google 관리 키는 대상이 아니다. 조치는
프로젝트 하나를 가리키는 전용 연결(`remediation` 용도, ADC 또는 Google 로그인)로만 하며, 그 신원에
`iam.serviceAccounts.get`, `iam.serviceAccountKeys.get`·`.disable`·`.delete`만 담은 사용자 지정 역할을 준다. 미리 정의된
`roles/iam.serviceAccountKeyAdmin`은 키 생성(`iam.serviceAccountKeys.create`)까지 허용해 그 프로젝트의 어느 서비스 계정으로든
인증할 수 있게 하므로 쓰지 않는다.
권한 점검은 `projects.testIamPermissions`로 묻고 아무것도 바꾸지 않는다. 실행은 worker가 서비스 계정이 그 프로젝트 소속인지
확인한 뒤 상태를 읽고(`keys.get`의 `disabled`, 계획이 가리킨 정확한 이름만), 쓰고, 다시 읽는다. 키를 비활성화·삭제해도 그
키로 이미 받은 단기 토큰은 만료까지 남는다.

## Google Workspace 디렉터리 (`workspace/`)

퇴사자 점검의 사람 목록이다([퇴사자 점검](../docs/LEAVER_CHECK.md)). Google Cloud 서비스 계정 키를 봉인해 두고, 최고 관리자가
Workspace 관리 콘솔의 보안 > 액세스 및 데이터 관리 > API 제어 > 도메인 전체 위임 관리에서 그 서비스 계정의 클라이언트 ID에
`https://www.googleapis.com/auth/admin.directory.user.readonly` 하나만 허용한다(적용까지 최대 24시간).
서비스 계정의 Cloud 프로젝트에서는 Admin SDK API를 사용 설정한다. CreMore는 연결에 적은 최고 관리자로 위임받아, 먼저
그 계정이 최고 관리자(`isAdmin`)인지 확인한 뒤 `showDeleted=true`(20일 안에 삭제된 사용자)와 `users.list`(고객의 모든
도메인)를 차례로 읽는다. 일부 조직 단위만 보는 관리자는 거절한다(`GOOGLE_WORKSPACE_ADMIN_NOT_SUPER_ADMIN`). 그런 목록이
완료되면 보이지 않는 나머지 사람이 모두 떠난 것으로 판정되기 때문이다. 정지·보관·삭제가 퇴사 신호이고, 이메일과 별칭은
keyed digest로만 남는다. 토큰은 항상 `https://oauth2.googleapis.com/token`에서 받으며 키 파일의 `token_uri`는 쓰지 않는다.
한 수집은 25만 명까지 완료할 수 있다. 더 큰 디렉터리는 `PARTIAL`로 끝나며, 이때는 목록에 없다는 이유로 퇴사를 판정하지
않는다. 권한 확인은 두 목록을 모두 읽고, 위임이 없으면 허용할 클라이언트 ID를 함께 보여 준다.

사람이 Google 계정으로 콘솔에 로그인하는 팀 설치(`OIDC_ISSUER_URL=https://accounts.google.com`)에서는 이 연결이 콘솔 역할도
정한다. Google 토큰에는 그룹이 없어, 워커가 5분마다 역할 그룹(`OIDC_ADMIN_GROUP` 등에 적은 그룹 주소)의 구성원을 하위 그룹까지
`members.list`(`includeDerivedMembership=true`)로 읽고 주소는 keyed digest로만 남긴다(`role_group_members`,
[`cremore/identity/sign_in_groups.py`](../cremore/identity/sign_in_groups.py)). 이 읽기는 `https://www.googleapis.com/auth/admin.directory.group.member.readonly`
하나만 담은 별도 토큰을 쓰므로 도메인 전체 위임에 그 범위도 더한다. API는 토큰의 확인된 주소(`email_verified`)가 이 연결의
도메인(`hd`, 조직의 기본 도메인이므로 연결도 기본 도메인으로 만든다)일 때만, ASCII 주소로 비교해 역할을 준다. 그룹은 하나씩 읽어
읽지 못한 그룹만 역할을 주지 않는다. 모든 그룹을 읽지 못하면 마지막 구성원을 한 시간 동안 쓰고, 연결이 없거나 자격증명을 열지
못하거나 Workspace가 위임·관리자·키를 더는 받지 않는 등 이쪽 원인이면 바로 끊는다. 역할 그룹과 그 안의 하위 그룹은 관리자가 구성원을 정하는 그룹(초대 전용)으로 두고, 외부
구성원과 "조직의 모든 사용자" 구성원은 역할을 받지 않는다. 처음 설치는 단독 운영(`AUTH_MODE=local`)으로 이 연결을 만든 뒤 팀
설치로 바꾸며, 역할을 읽지 못해 아무도 들어오지 못하면 단독 운영으로 되돌려 고친다.

운영 조건:

- 위임받을 계정은 이 수집 전용 최고 관리자로 둔다. 그 계정이 정지·삭제되거나 최고 관리자에서 내려오면 수집은 실패로
  끝나고(목록을 추정하지 않는다), 고칠 때까지 퇴사 판정이 멈춘다. 연동 현황의 실패를 확인한다. 위임은 그 계정의
  비밀번호를 쓰지 않으므로 사람이 로그인하지 않게 두고, 2단계 인증(보안 키)을 강제하며 로그인 기록을 감시한다.
- 서비스 계정도 이 수집 전용으로 만들고, 그 클라이언트 ID에는 위의 범위(Google 로그인이면 그룹 구성원 범위까지) 말고 다른
  도메인 전체 위임을 주지 않는다. 봉인한 키는 관리 콘솔이
  그 클라이언트 ID에 허용한 모든 범위로 도메인의 어느 사용자로든 위임받을 수 있으며, CreMore는 그 목록을 보거나 줄일 수 없다.
- 조직 정책 `constraints/iam.serviceAccountKeyExpiryHours`로 새 키의 유효 기간을 정한다(최대 `2160h`). 만료 전에 새 키를 만들어
  연결의 자격증명을 바꾸고 이전 키를 삭제한다. 마법사에 키 만료일을 넣으면 14일·3일 전에 알린다.
- 연결을 끊을 때는 서비스 계정 키와 관리 콘솔의 도메인 전체 위임 항목을 함께 삭제한다.

## 공식 API의 범위와 한계

2026-09-25 공식 REST 문서 및 discovery schema를 확인했다.

| 대상 | 가능한 수집 | 명확한 한계 |
| --- | --- | --- |
| 서비스 계정 키 | 계정별 key ID·종류·유효기간·상태 | 개인키 원문은 발급 시 반환되며 목록/GET으로 복원하지 못한다 |
| API 키 | 프로젝트별 key metadata, 별도 권한으로 `getKeyString` | 목록에는 key string이 없고 location은 `global`이다. 삭제된 키(30일 안 복원 가능)의 string을 줄지는 문서에 없어, 읽히면 대조하고 Google이 그 키를 400·404로 거절하면 그 키의 사유로만 남긴다(살아 있는 키의 값 대조를 부분으로 만들지 않는다). 권한 거절·잘못된 응답·프로젝트 범위 미확인은 그대로 부분 수집이다 |
| Secret Manager | secret·버전 metadata, 별도 권한으로 버전 access | 버전 목록에는 secret data가 없다. 값 접근 승인은 별도다 |
| 조직·폴더 | 승인 root 아래 Resource Manager 프로젝트·폴더 | 전체 트리를 한 번에 반환하지 않으며 각 부모의 조회 권한이 필요하다 |
| OAuth·단기 access token | 별도 API의 발급·감사 근거가 있는 범위 | 이 GCP 인벤토리 API들은 모든 OAuth access/refresh token·활성 세션 목록을 제공하지 않는다 |

Google Workspace의 사용자별 OAuth authorization 관리와 GCP 프로젝트 키 인벤토리는 별도
제품·권한 계약이다. 짧은 수명의 token, impersonation, federation을 목록에 없다는 이유만으로
미발급·미사용·금고 미보관으로 단정하지 않는다.

공식 근거:

- [Resource Manager projects.list](https://cloud.google.com/resource-manager/reference/rest/v3/projects/list)
  · [folders.list](https://cloud.google.com/resource-manager/reference/rest/v3/folders/list)
  · [v3 discovery schema](https://cloudresourcemanager.googleapis.com/$discovery/rest?version=v3)
- [IAM service account keys.list](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/list)
  · [ServiceAccountKey의 privateKeyData 계약](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys)
- [API Keys list](https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/list)
  · [getKeyString](https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/getKeyString)
- [Secret Manager versions.list](https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions/list)
  · [versions.access](https://cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions/access)
- [Google Cloud token types](https://cloud.google.com/docs/authentication/token-types)
  · [Workspace Directory tokens.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens/list)

기본 회귀는 fake transport와 합성 JSON으로 수행한다. 실제 조직의 IAM 상속·권한, 조직 이동 중
일관성, quota, 실환경 ADC·API 호출 및 Secret 접근은 별도 환경에서 검증해야 한다.
