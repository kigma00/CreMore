# 공급자 연결 (통합 온보딩)

신규 콘솔 연결은 **제품·요금제 → 인증 → 기능 → 권한 확인 → 수집 범위 → 최종 확인** 순서다.
한 제품뿐이면 제품 단계는 생략한다. API·기존 연결 호환과 실제 검증 범위는 [제품 선택·목적 분리](EDITION_AND_COLLECTION_ONBOARDING.md)를 따른다.

### 연동 서비스 화면 (2026-10-12)

- **카드 두 묶음**: `계정·발급 목록 연결`(발급 목록·금고 대조·사람 목록·조치)과 `콘텐츠 검사 위치 연결`(평문 노출 검사)로 나눈다.
  - 계정 카드: 새 연결에 쓰는 제품 중 계정 기능이 있는 곳에만 보인다. Confluence는 계정 카드가 없다. 칩은 그 기능만, 설명은 기능을 지원하는 제품을 적는다(Notion: `Enterprise 전용: 발급 목록·조치`). `연동됨`은 계정 기능이 실제로 돌고 있을 때만 붙는다. 콘텐츠 검사만 연결했거나 인증만 저장한 계정은 계정 카드를 `연동됨`으로 만들지 않는다.
  - 콘텐츠 카드(AWS는 `Amazon S3`, S3 로고): 노출 검사가 돌고 있으면 `연동됨`이다. AWS 말고는 계정 연결 없이 콘텐츠 카드에서 바로 시작할 수 있다. AWS는 S3를 계정의 역할로 읽으므로 계정을 먼저 연결한다. 다시 쓸 계정이 하나면 바로 열고, 여럿이면 고른다.
  - 계정 카드의 제품 선택은 계정 기능이 있는 제품만 보여 주고, 하나뿐이면 건너뛴다.
- **콘텐츠 검사 흐름에는 기능 선택이 없다.** 인증 뒤 검사 대상을 바로 불러오며 단계는 `인증 → 권한 확인 → 검사 범위 → 최종 확인`이다(Google 로그인은 클라우드 동의를 위해 한 번 누른다). 이미 연결한 계정에 더할 때는 그 계정이 돌리던 기능을 `유지`로 보여 주고 바꾸지 않는다. 그 기능이 쓰는 기존 대상(기능별 구분이 없는 GitHub 조직 같은 대상 포함)은 `검사 대상`에 `유지`로 고정돼 여기서 뺄 수 없고, 빼려면 계정 연결 설정에서 뺀다. 여기서 새로 고른 대상은 노출 검사에만 쓰인다: 콘솔이 `inspect`의 `target_purposes`로 그 대상을 노출 검사로 한정해, 계정의 다른 기능이 새 대상으로 넓어지지 않는다(서버가 같은 규칙을 검사한다). 연결을 다시 편집해도 그 대상은 돌던 기능 중 노출 검사에만 쓰인다(새로 켜는 기능은 다른 대상처럼 닿는다). 연결을 편집할 때(계정·콘텐츠 카드 모두) 지금 수집 중인 대상이 이번 목록에 없으면(다음 페이지, 중지된 설치) 목록에 없다고 지운 것으로 보지 않고 계속하지 않는다(`ONBOARDING_EXISTING_TARGET_NOT_LISTED`, 초안의 `previous_unlisted`). 더 불러오거나, 그 대상을 그만 수집하려면 `수집 범위·인증 설정`의 `유지할 기존 대상`에서 직접 뺀다. 유지 기능의 권한 확인이 실패하면 검사 범위로 넘어가지 않고 그 기능에 없는 권한을 보여 준다(서버는 보낸 모든 기능을 검사한다). 기존 화면(설정 마법사)도 같은 카드에서 열면 기능 카드 없이 `검사 범위`부터 시작하고, 이미 도는 검사는 `노출을 검사할 위치` 머리글의 스위치로 끄고 켠다. 이미 연결한 계정을 카드에서 열면 그 카드의 기능만 보이고, 보이지 않는 기능은 저장할 때 그대로 둔다. 연결 대상 추가·제외(모든 기능에 걸림)는 계정 카드와 전체 설정에서만 한다. 연동 현황 행 메뉴의 `수집 범위·인증 설정`은 그 행의 묶음으로 연다. Google 로그인·GitHub App처럼 공급자로 나갔다 돌아와도 시작한 카드(콘텐츠/계정)로 돌아온다.
- **기능별 필요한 권한**을 인증 전(기능마다 접어서), 기능 카드 아래, 권한 확인 뒤(권한별 결과)에 같은 목록으로 보여 준다. `선택`은 고른 계획(없으면 제품의 기본 선택)에서 필요하지 않은 권한이다. 옵션을 켜지 않는 한 필요한 권한(예: AWS `secrets_list`)과 기본으로 켜진 옵션의 권한(예: Notion `workspace_tokens`)은 필수로 보인다. `대상에 따라`는 대상에 따라 달라지는 권한, `위와 같음`은 앞 기능과 같은 권한이며 같은 권한은 한 번만 센다. catalog의 권한 선언만으로 만든다.
- **부분 활성화**: 권한 확인 뒤 기능(과 대상)마다 `준비됨` 또는 `보류 · 권한 부족`(없는 권한·대상·주체·사유)으로 나눈다.
  - 인증 후 흐름: `준비된 기능만 계속`은 준비된 기능만으로 다시 확인하고, 세션은 보류한 기능을 목적과 대상에서 빼 `held_purposes`로 남긴다(감사 `ONBOARDING_PURPOSES_NARROWED`, 메모 `held:<기능>`). `통과한 대상만 계속`은 통과한 대상만 다시 확인하며, 실패한 대상이 이미 돌고 있는 기능의 대상이면 나오지 않는다. 모든 기능이 보류면 다시 확인만 할 수 있다. 수정 중인 연결은 이미 돌리는 기능을 보류할 수 없다.
  - 기존 설정 마법사: 기능마다 자기 권한 확인으로 판단해 하나라도 통과하면 다음으로 갈 수 있고, 마치면 통과한 기능만 켜고 그 기능의 계획 변경만 저장한다. 다시 연 연결에서 모든 기능이 거절이면 마칠 수 없다.
  - 보류한 기능은 검토·완료 화면에 남고 `권한 부여 후 다시 확인`(기존 마법사) 또는 `보류된 기능 추가`(인증 후 흐름; AWS는 연결 설정에서 추가)로 다시 켠다. 거절이 이미 수집 중인 기능을 끄지는 않는다.
  - 서버 검사는 그대로다: 선택·완료·활성화는 남은 기능×대상 모두에 30분 안의 GRANTED 근거를 요구한다. 보류한 기능은 새 대상 조회나 기능 추가 흐름으로만 돌아온다.
- **연동 현황**도 같은 두 묶음으로 나눈다. 연결은 기능이 있는 묶음마다 한 행으로 나오며(AWS 발급 목록 + S3 검사는 두 묶음에 모두), 기능이 없는 연결(인증만 저장한 계정 포함)은 제품에 계정 기능이 있으면 계정 묶음, 없으면 콘텐츠 묶음에 `계정 인증만 완료`·`검사 위치 고르기`로 나온다.
  - 행마다 그 묶음의 기능 배지를 `켜짐`·`꺼짐`·`권한 부족`(없는 권한을 툴팁과 화면 읽기 텍스트로)·`설정 중`으로 보여 주고, 노출 검사 배지는 승인 범위의 위치 수를 센다. 돌아가는 기능과 보류 기능이 섞이면 상태는 `일부 기능 권한 부족`이다.
  - `지금 수집`은 그 묶음의 수집만 실행하고(S3는 승인된 검사 범위), `검사 대상 설정`은 콘텐츠 행에만 있다. 두 묶음에 모두 있는 연결을 해제하면 두 곳이 모두 멈춘다고 알린다. `연동된 서비스` 타일은 기능이 하나라도 돌고 있는 서비스를 센다.
- **GitHub App**: `연결 방식`은 `새 App 자동 설정`/`이미 만든 App 정보 입력` 중 고르는 선택이고, 실제 시작 버튼 `GitHub에서 App 만들기·설치`는 `조직` 칸 바로 아래에서 비활성 이유(예: 조직을 먼저 입력)를 함께 보여 준다. 콘텐츠 카드에서 만드는 App은 설치 권한 선택 없이 노출 검사의 읽기 권한(`installation_purposes: ["exposure"]`)을 요청한다. 떠나기 전에 탭 저장소(sessionStorage)에 흐름을 쓰고 다시 읽으며, 저장소가 막히면(`GITHUB_APP_STORAGE_UNAVAILABLE`) 또는 응답이 GitHub 조직의 새 App 주소가 아니면(`GITHUB_APP_RESPONSE_INVALID`) 떠나지 않고 서버 흐름을 기다리지 않고 취소한 뒤 오류를 보여 준다. 시작 요청이나 돌아온 `/github/app`의 401·HTML 응답은 `GITHUB_APP_SIGN_IN_EXPIRED`(다시 로그인 안내)로 보여 준다. 흐름은 한 탭에 묶이며 API 계약은 그대로다.

감사 로그·사용 지표와 추가 금고 메타데이터는 기능 선택에서 명시적으로 켜고 필요한 권한을 다시 확인한다.
GCP `audit_logs`/`api_metrics`/`service_account_iam`/`secret_iam`/`locations`, Microsoft `credential_sign_ins`(Graph beta)·`directory_audits` 및
키·인증서·버전 옵션, GitHub `audit_events`, Atlassian `oauth_clients`의 범위·제한·기존 연결 적용은
[인벤토리 재검토](INVENTORY_METADATA_REVIEW_2026-10-05.md)를 따른다. 기존 연결에 자동 활성화하지 않는다.
GCP `effective_access`(키가 있는 서비스 계정의 실효 판정)와 Microsoft `app_permissions`·`app_azure_roles`(앱 자격증명의
애플리케이션 권한·Entra 역할·Azure 역할)의 범위·권한·한계는 [권한 평가의 근거와 한계](PERMISSION_ASSESSMENT.md)를 따른다.

모든 공급자는 **공급자 연결**을 통해 연결한다([설계 4.4·4.5](CONTINUOUS_OPERATIONS_DESIGN.md)).
지원 인증 방식은 **인증 → 기능 → 권한 확인 → 수집 범위 → 최종 확인** 순서로 연결하며, 나머지는 아래 기존 4단계 설정을 유지한다.
권한 단계의 하단 `권한 확인·다음`이 선택한 대상·옵션의 필수 권한과 리소스 목록을 함께 확인한다.
성공하면 범위 선택으로 이동하고 거절·미확인·조회 실패 시 해당 단계에 머문다. 대상·옵션 변경은 다시 점검한다.
Notion 하위 페이지 안내는 Notion에만 표시한다. 설정 필드의 설명은 마우스·키보드로 여는 툴팁에서도 제공한다.
AWS 최종 확인에는 **발견한 자격증명 조사**와 기능별 **수집 주기**가 나온다. 사용 기록·잠재 권한은
노출 검사 또는 발급 목록을 선택했을 때, Secrets Manager 메타데이터는 금고 대조를 선택했을 때만
표시한다. 조사 스위치는 설치의 모든 AWS 연결에 적용되지만 비밀값 읽기를 켜거나 계정별 AWS
권한 확인을 대신하지 않는다. 하단 연동 저장과 함께 원자적으로 적용하며 취소하거나 저장이 실패하면
적용하지 않는다. 다른 관리자가 수정한 스위치는 덮어쓰지 않고 다시 불러오도록 안내한다.
수집 주기는 이 연결의 선택된 계정에만 적용한다. 수동 수집은 자동 실행을 끄며, 새 계정은 대상에
추가하고 권한을 확인해야 한다. 옛 설치 전체 인벤토리 주기와 중복해서 설정하지 않는다.
CloudTrail 리전·기간·생성 이벤트 제한은 CloudTrail을 켰을 때만 표시한다. 키 생성 기록만 필요하면
제한을 켜고, 관측된 세션 등 다른 관리 이벤트도 필요하면 제한을 끈다. 세션 관측은 전체 세션 목록을 뜻하지 않는다.
정확한 지원 범위는 [인증 후 범위 선택](AUTH_FIRST_ONBOARDING_DESIGN.md#현재-구현-범위)을 따른다.
신규 연결은 서버의 상시 수집용 인증을 선택한다. descriptor의 `new_setup: false`는 UI와 생성 API가
함께 적용하며(`AUTH_METHOD_RETIRED_FOR_NEW_CONNECTIONS`), 기존 연결의 같은 인증정보 유지보수는 허용한다.
회사 인프라에서도 AWS OIDC→STS 자동 갱신과 다른 SaaS 연결을 운영할 수 있다.
[기계 신원](MACHINE_IDENTITY.md)과 [공급자별 인증 정책](AUTH_FIRST_ONBOARDING_DESIGN.md#설치-장소와-무인-인증)을 따른다.
공급자 연결은 공급자 신원 하나와 자격증명 하나다. 그 자격증명을 노출 스캔·발급 목록·금고·IdP 용도가 함께 쓴다.
승인된 조치 계획이 쓰는 쓰기 자격증명(`remediation` 용도)은 다른 용도와 섞지 않는 전용 연결이며 소유 레코드를 만들지 않는다
([공급자 자격증명 조치](PROVIDER_ACTIONS.md)).
기존 네 등록 창구(콘텐츠 소스, AWS 계정, schema 1·schema 2 수집 연결)는 없어졌고 호환 계층도 없다(결정 6).

## 모델

AWS 발급 목록의 **IAM 정책 메타데이터 수집**은 사용자·그룹 정책 요약을 읽는 연결별 옵션이다.
신규 연결에서 기본 선택으로 제안하며 잠재 접근 권한 시뮬레이션을 켜지는 않는다. 권한 점검은
첫 IAM 사용자의 실제 정책을 최대 100회 호출로 읽는다. 사용자가 없거나 점검이 불완전하면
확인됨으로 처리하지 않는다. 다른 사용자·그룹·정책에만 적용되는 권한 거절은 수집 결과에 남는다.
옵션이 없는 기존 연결은 이전 설치 스위치를 유지하며, 옵션을 저장하면 연결별 선택으로 전환한다.
기존 설치의 `IAM_POTENTIAL_ACCESS_MODE=disabled`는 정책 읽기도 계속 차단한다.

인증 후 연결의 마지막 검토에서 각 기능의 수집 주기(수동 또는 5분 이상)를 선택한다. 기존 연결 편집은
기존 주기를 기본으로 유지한다. 노출 검사는 설치의 **예약 검사 켜기**도 필요하며, 이 스위치는
주기가 저장된 다른 검사 범위에도 적용된다. 설치 정책으로 자동 수집을 잠갔으면 켤 수 없다.
AWS의 새 명시적 주기는 연결이 소유하고 옛 설치 전체 AWS 인벤토리 스위치는 기존 연결에 유지된다.
**최초 수집 실행**을 선택하면 저장 후 기존 수집 API로 요청한다. 접수까지 창을 열어 두어야 하며
실패한 요청만 재시도할 수 있다. 예약 주기를 설정한 경우에는 이 선택과 별개로 서버의 다음 확인부터
수집할 수 있다. 완료 화면은 실행 상태·부분 수집·다음 예약 가능 시각을 조회한다. 예약 시각은
성공 보장이 아니며, 진행 중 작업·권한·서버 가동 상태에 따라 늦어질 수 있다.

| 대상 | 저장 위치 | 내용 |
| --- | --- | --- |
| 공급자 연결 | `provider_connections` | 공급자, 에디션, 이름, 대상(비밀 아님), 인증 방식, 봉인 참조(역할별), 용도, 점검 결과, 4단계 계획, 상태, revision |
| 인증 초안 | `provider_onboarding_sessions` | 30분, 관리자·브라우저 바인딩·revision, 봉인된 인증 참조와 조회한 대상·검사 근거. 확정 전 실제 수집 레코드는 없음 |
| 소유 레코드 | 기존 저장소 | 콘텐츠 소스(`connections`), AWS 계정(`aws_accounts`), 수집 연결(`coverage_connections`, schema 1·2) |
| 소유 관계 | `provider_connection_children` | (종류, 레코드 ID) → 공급자 연결, 용도, 자격증명 슬롯 → 역할 |

자격증명 필드는 도착 즉시 하나의 봉인 봉투(`seal_fields`)로 저장하거나 `vault://` 참조 하나로 받는다. 소유 레코드는 같은
참조를 가리킨다(콘텐츠 `secret_ref`, schema 2 `secret_refs`의 각 슬롯, schema 1 `vault_token`). 자격증명을 바꾸면 슬롯만
다시 가리키고 비밀값을 복사하지 않는다. API는 참조를 돌려주지 않고 어떤 역할에 자격증명이 있는지만 보여 준다.

상태는 `DRAFT`(1·2단계) → `CHECKING`(점검 대기) → `CHECKED` → `ACTIVE`(4단계 이후)이고, 중지하면 `DISABLED`다.
점검 작업이 결과를 저장하지 못하고 끝나면(실패·철회·worker 유실) API 보기는 `CHECKED`와 `checks.error`(작업의 고정 코드,
없으면 `PROVIDER_CHECK_ENDED_WITHOUT_RESULT`), 각 권한의 `ERROR`로 보여 주며 다시 점검을 요청할 수 있다.

## 기존 설정의 4단계

| 단계 | API | 하는 일 |
| --- | --- | --- |
| 1. 무엇을 | `GET /api/v1/provider-connections/catalog` | 공급자·에디션·용도·용도별 권한 목록·인증 방식(권장 순서)·계획 항목 |
| 2. 어떻게 | `POST /api/v1/provider-connections` | 에디션, 용도, 인증 방식, 대상, 자격증명. 비밀은 봉인하고 공개 필드(계정 이메일, AWS 권한 세트 등)만 `target.auth`에 둔다 |
| 3. 권한 점검 | `POST /api/v1/provider-connections/{id}/check` | worker 작업 `provider-check`가 용도마다 필요한 권한을 실제 읽기로 확인한다 |
| 4. 범위와 첫 실행 | `POST /api/v1/provider-connections/{id}/activate` | 용도별 계획(`purposes: {용도: 계획}`)으로 소유 레코드를 만들고 링크한다. 첫 실행은 각 레코드의 일정이 맡는다 |

- **점검 결과**: 권한마다 `GRANTED`·`MISSING`·`NOT_REPORTED`·`ERROR`와 이유 코드만 저장한다. 응답 본문·토큰은 저장하지 않는다.
  결과는 설정 digest(인증 방식, 참조, 용도, 대상)와 요청 계획에 묶인다. 신규 활성화·기능 추가·범위 확대는
  30분 이내의 일치하는 근거가 필요하며, 필수 `MISSING`·`NOT_REPORTED`·`ERROR`는 서버가 거절한다.
  선택하지 않은 옵션과 명시적으로 `required: false`인 항목은 차단하지 않는다. 제거만 하는 변경은 재인증 없이 가능하다.
  수집 실행에서도 실제 거절을 따로 기록하며 기존 활성 연결을 일괄 중지하지 않는다.
- **토큰 만료일**: 갱신 종류가 `EXPIRES`이고 비밀 필드가 있는 방식(토큰·API 키)은 2단계에 "토큰 만료일 (선택)"을 받는다
  (사람 로그인인 AWS Identity Center는 받지 않는다). 공급자가 만료일을 알려 주면 그것을 쓰고 입력을 받지 않는다. 날짜는 운영
  화면과 같이 입력한 사람의 시간대로 그날의 끝이며, 연결이 소유한 레코드 중 스스로 갱신하지 않고 공급자 날짜가 없는 것마다
  운영자 만료일로 저장된다(`PUT /api/v1/operations/connections/{key}/expiry`). 새 연결은 수집을 시작한 뒤, 토큰을 바꾼
  연결은 새 토큰을 저장할 때 저장하며, 날짜 없이 바꾼 토큰은 이전 날짜를 지운다. 저장하지 못한 레코드는 완료 화면에 경고로
  남고 시작한 수집은 그대로다. 만료 14일·3일 전에 연동 행과 알림 벨(연결마다 한 번)이 알리며, 아직 한 번도 읽지 않은
  연결(`UNKNOWN`)도 같다.
- **회사 IdP에 이미 있는 서비스**: 회사 IdP가 가진 앱의 이름에 CreMore가 연결하는 서비스 이름이 있고 그 서비스의 연결이 아직
  없으면(어떤 상태든), 연동 화면의 "연동 가능 서비스" 위에 제안하고 누르면 그 서비스의 연결 마법사가 열린다
  (`GET /api/v1/provider-connections/suggestions`, 관리자 화면). 읽는 앱 목록은 셋이다(사용 중지된 앱 제외).
  Microsoft 연결의 Entra 발급 목록이 수집한 앱 등록·서비스 주체(갤러리 SSO 앱 포함), 앱 목록 옵션을 켠 Okta 사람 목록 연결의
  조직 앱(레이블과 카탈로그 이름, `okta.apps.read`), 같은 옵션을 켠 Keycloak 연결의 렐름 클라이언트(이름과 클라이언트 ID,
  `view-clients`, 렐름 기본 클라이언트 제외)다. 두 옵션은 기본 꺼짐이다(사람 목록에 없는 권한이 든다). 앱 목록은 사람 목록과
  같은 자격증명으로 많아야 하루 한 번 도는 별도 수집이라, 읽지 못해도 퇴사자 점검의 사람 목록은 완전한 수집으로 남는다.
  꺼 둔 수집의 목록은 제안하지 않는다. 저장된 목록만 읽는 안내이며 권한·범위 판단에 쓰지 않는다.
- **팀 설치의 사람 목록은 로그인 IdP**(소유자 결정 2026-10-02): 사람이 회사 IdP로 로그인하는 설치(`AUTH_MODE=oidc`)에서는
  사람 목록(`identity` 용도) 연결이 그 IdP 자신이어야 한다. 같은 Okta 조직, Entra 테넌트, Keycloak 렐름, Google Workspace다.
  각 IdP 모듈의 `sign_in_target(provider, issuer)`가 `OIDC_ISSUER_URL`이 가리키는 대상을 알려 주고, 2단계(만들기)와
  4단계(활성화)와 중지한 연결을 다시 켤 때 다른 대상을 `409 PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP`로, 어느 IdP인지 알 수 없는
  issuer면 `409 PEOPLE_DIRECTORY_SIGN_IN_IDP_UNKNOWN`으로 거절한다(`cremore/onboarding/sign_in.py`). 연결이 만든 사람 목록
  수집의 디렉터리(공급자·origin·tenant·범위·경로 접두어)도 커버리지 API로 바꾸지 못하고, 연결이 중지됐거나 로그인 IdP가 아니면 그 수집만 다시 켜지도 못한다(`409 PEOPLE_DIRECTORY_BELONGS_TO_PROVIDER_CONNECTION`).
  팀 설치로 바꾸기 전에 만든 다른 디렉터리는 계속 돌되 연결 목록·조회 응답에 `sign_in_problem`이 붙고 콘솔이 "확인 필요"로
  보여 준다(멈출지는 관리자가 정한다). GitHub 신원 연결은 GitHub 로그인을 IdP의 사람과 잇는 것이라 예외다. 카탈로그 응답의
  `sign_in_idp`(`{issuer, provider, target, exempt}`, 1인 설치는 `null`)로 콘솔은 "디렉터리 연동"에서 로그인 IdP를 대상을 채운
  채 열고, 다른 IdP는 사유와 함께 비활성화한다. 알아보는 issuer는 Okta 도메인의 조직 인증 서버(`https://acme.okta.com`)와
  사용자 지정 인증 서버(`…/oauth2/default`, `…/oauth2/aus…`, 사용자 지정 도메인 포함), Entra
  v2.0(`https://login.microsoftonline.com/<테넌트>/v2.0`)·v1(`https://sts.windows.net/<테넌트>/`), Keycloak
  (`…[/auth]/realms/<렐름>`), Google(`https://accounts.google.com`)이다. 연결 대상은 issuer의 호스트로 맞춘다. Okta가 사용자
  지정 도메인으로 로그인하면 그 도메인을, Keycloak은 issuer의 호스트를 주소로 쓴다. 관리 API(`/admin/`)를 공개 호스트에 열지
  않는 Keycloak이면 worker가 그 호스트 이름을 내부 주소로 찾게(사내 DNS·hosts) 둔다. 사용자 지정 도메인의 Okta 조직 인증 서버는
  다른 IdP와 구별되지 않아 알아보지 못하므로 로그인 issuer를 Okta 도메인이나 사용자 지정 인증 서버로 둔다. Google issuer에는
  도메인이 없어, 이미 사람을 읽고 있는(활성화했고 중지하지 않은) Google Workspace 사람 목록의 도메인이 기준이 된다. 1인 설치는 어떤 IdP든 연결한다.
- **같은 회사의 다른 서비스**: Atlassian의 Confluence·Bitbucket·조직은 따로 연결하지만, 새로 하나를 시작하면 완료 화면에서
  아직 연결하지 않은 나머지를 바로 이어서 연동할 수 있다(노출 검사 범위를 저장하는 동안에는 기다린다).
- **옵션에 묶인 권한**: 권한의 `option`은 같은 용도의 bool 계획 항목 이름이다(카탈로그가 검증한다). 점검은 그 권한도 항상
  사실대로 답하고, 콘솔은 옵션이 꺼져 있는 동안(연결 전에는 1단계의 선택, 뒤에는 저장된 계획이나 기본값) 그 권한을
  "필요한 권한"과 누락 개수에서 뺀다. 예: Slack의 `auditlogs_read`는 감사 로그 옵션(`audit_events`)을 켰을 때만 필요하다.
  반대로 `unless`는 그 옵션이 꺼져 있거나 그 제품·대상에 없는 동안만 필요한 권한이다. 예: GitHub 사람 목록의 `admin_org`는
  "조직 대신 엔터프라이즈의 SSO 신원 읽기"(`enterprise_identities`)를 켜면 빠지고 `read_enterprise`가 대신 들어간다.
- **제품별 기본값**: 계획 항목의 `edition_defaults`(`{제품: 값}`)가 그 제품에서 `default`를 대신한다(서버의 `_fields`와 콘솔의
  `planFields`가 같은 값을 쓴다). 예: GHE.com(`dedicated`)은 관리 사용자만 있어 `enterprise_identities`가 기본으로 켜진다.
  이미 활성화된 계획에 이 항목이 없으면 콘솔은 항목의 기본 `default`로 기존 동작을 표시한다. 과거 GHE.com 조직 수집은
  꺼진 선택으로 표시하고, 관리자가 켜서 저장하면 다른 옵션을 바꾸지 않아도 엔터프라이즈 수집으로 전환한다.
- **원자성**: 2단계(AWS 계정 등록 포함)와 4단계는 전부 되거나 전부 되지 않는다. PostgreSQL·SQLite는 한 트랜잭션,
  메모리 저장소는 실패 시 상태를 되돌린다. 실패한 시도의 일부가 남아 재시도와 부딪히지 않는다.
- **선택 목록**: `choices`와 `options`가 있는 `list` 항목은 검색 가능한 다중 선택·모두 선택·모두 해제로 표시한다.
  AWS 리전 목록은 공급자 descriptor 한 곳에서 제공하며 연결 계획·수집 설정·홈 리전 선택에서 재사용한다.
  `list.options`는 추천 목록이므로 기존·신규 리전의 서버 검증을 제한하지 않는다. 저장된 목록 밖 값은 명시적으로
  해제하기 전까지 유지한다. 계정·파티션에 맞는 활성 리전을 선택해야 하며, 모두 선택이 리전 활성화나 권한 승인은 아니다.
- **같은 용도 재활성화**는 `PURPOSE_ALREADY_ACTIVE:<용도>`로 거절한다. 수집 중인 용도의 계획은 아래
  [계획 변경](#계획-변경)으로 바꾼다.
- **수집기 토큰**: 고객 환경 CLI로 실행하는 수집 레코드는 활성화 응답에서 한 번만 `collector_token`을 돌려준다.

## 자격증명

- 인증 방식은 descriptor의 권장 순서로 제시한다. 클라우드는 워크로드 신원, SaaS는 앱·서비스 계정이 먼저이고 수동 토큰은 `advanced`다.
- `vault://` 참조는 비밀 필드 전체를 대신한다. 공개 필드(예: Bitbucket API 토큰의 이메일)는 함께 보낼 수 있다.
  카탈로그의 `reference_keys`가 그 KV 항목에 있어야 할 키를 알려 준다(기본 `token`; GitHub App은 `GITHUB_APP_*` 세 키).
- `reference: false`인 방식(Vault 토큰 로그인)은 참조를 받지 않는다. 그 값은 연결이 가리키는 서버로 보내지므로,
  참조를 허용하면 설치가 보관한 임의의 비밀을 그 서버로 보내게 할 수 있다(`CREDENTIAL_REFERENCE_NOT_ALLOWED`).
- `PUT /api/v1/provider-connections/{id}/credential`은 같은 인증 방식의 새 값을 받아 모든 소유 레코드를 다시 가리키고,
  실행 중인 콘텐츠 소스를 `PENDING`으로 돌려 자격증명 점검을 대기열에 넣은 뒤 권한 점검을 다시 요청한다.
  중지·제외한 소스는 `DISABLED`를 유지한다. 늦은 인증 검사 결과도 중지 상태나 교체된 인증정보를 덮어쓰지 못한다.
- 소유 레코드가 생긴 뒤에는 인증 방식과 공개 필드를 바꾸지 않는다(`AUTH_SETTINGS_FIXED_WHILE_IN_USE`). 레코드가 그 방식에
  맞춰 만들어졌기 때문이다(AWS 접근 방식, Vault 로그인 역할, 수집 인증 종류). 바꾸려면 연결을 중지하고 새로 연결한다.
- 수집 연결의 PATCH(`/api/v1/coverage/connections/{id}`, `/api/v2/coverage/connections/{id}`)는 범위·옵션은 고치지만
  참조·인증 종류·Vault 로그인은 바꾸지 않는다(`CREDENTIAL_BELONGS_TO_PROVIDER_CONNECTION`). 콘텐츠 연결 PATCH의
  `secret_ref`·`token`도 같은 코드로 거절한다. 팀 설치에서 공급자 연결이 만든 사람 목록 수집은 디렉터리(공급자·origin·
  tenant·범위)도 바꾸지 않는다(`PEOPLE_DIRECTORY_BELONGS_TO_PROVIDER_CONNECTION`).
- GCP의 Google 로그인은 `POST /api/v2/gcp/oauth/start`에 `connection_kind: "provider"`와 공급자 연결 ID를
  보내 시작하고, `POST /api/v2/gcp/oauth/complete`가 그 연결의 참조를 바꾼 뒤 권한 점검을 요청한다.
  Google 로그인 앱이 없으면 마법사가 그 단계에서 받아 저장한다(`PUT /api/v2/gcp/oauth/client`, 시크릿 봉인).
  API의 `GCP_OAUTH_*` 설정이 있으면 그 앱을 쓰고 대시보드에서 바꾸지 않는다.
- GitHub App은 마법사에서 GitHub가 만들게 한다(`cremore/onboarding/github_app.py`, [github/README](../github/README.md)의
  "App 만들기"). `POST /api/v1/github/app-manifest/start`가 매니페스트와 GitHub 페이지 주소를, `…/convert`가 GitHub의 코드를
  App ID·키로 바꾸고(서버에서만), `…/complete`가 조직 설치를 App JWT로 찾아 공급자 연결을 만들거나 새 자격증명으로 바꾼다.
  입력한 값과 같은 봉인 자격증명이 되며 권한 점검을 요청한다.
- 인증 우선 GitHub App 연결은 `onboarding: true`와 명시적 `installation_purposes`로 설치를 시작한다.
  완료 응답의 `onboarding_session_id`를 같은 브라우저 키로 읽고, 인증 확인 뒤 기능·대상·권한을 선택한다.
  읽기 App의 설치 권한과 수집 승인은 별개다. 조치용은 `remediation`만 고른 별도 App으로 만들며
  조직 PAT 접근 철회 쓰기 권한을 표시한다. 읽기 기능과 조치 권한을 한 App preset에 섞지 않는다.
- 엔터프라이즈를 적은 GitHub App 연결은 같은 App을 엔터프라이즈의 다른 조직에 설치하고 조직마다 연결을 만든다
  (`cremore/onboarding/github_enterprise.py`, [github/README](../github/README.md)의 "엔터프라이즈의 다른 조직에 설치").
  worker가 설치·연결·권한 점검 요청을 하고, 점검이 선택한 계획의 필수 권한을 허용하면 원래 연결의 계획으로 활성화한다.

### CreMore가 만드는 자격증명 (Microsoft 앱 인증서, Okta 서비스 앱 키)

Okta의 `made_key` 방식도 같은 계약이다: 클라이언트 ID만 받아 RSA 키를 만들고 개인 JWK는 봉인하며, `target.generated`에는
공개 JWK(`kid` = RFC 7638 지문)와 만든 시각만 둔다. 마법사는 서비스 앱에 붙여 넣을 공개 키와 권한 단계를 보여 준다
([okta/README](../okta/README.md)). 키는 만료가 없어 교체 스윕 대상이 아니다.

관리자가 같은 방식으로 다시 만들면(`PUT …/credential`) 공급자에 등록된 이전 키·인증서는 그곳에서 지울 때까지 유효하다. 그래서
새 공개 부분은 이전 것의 이름(`previous`: 키의 `kid`, 인증서의 지문)을 함께 가지고, 마법사가 지울 것을 알려 주며, 감사 이벤트
`PROVIDER_CONNECTION_CREDENTIAL_CHANGED`의 메모에 두 이름(`made_key <이전>-><새>`)이 남는다. 소유 레코드 중 새 자격증명으로
옮기지 못한 것(`not_updated`)은 마법사가 오류로 보인다.

인증 방식에 `generated: true`가 있으면 사람이 비밀을 넣지 않고 CreMore가 자격증명을 만든다(`generate`). Microsoft
연결의 `certificate` 방식은 애플리케이션(클라이언트) ID만 받아 RSA 키와 자체 서명 인증서(180일)를 만들고, 봉투(클라이언트
ID·테넌트·키와 인증서 PEM)를 도착 즉시 봉인한다. 평문으로 남는 것은 공개 부분(인증서 PEM, SHA-1 지문, SHA-256, 유효 기간)뿐이며
`target.generated`에 두어 마법사가 인증서 받기와 `az` 명령을 채운다. 개인 키는 API 응답·로그·이벤트에 나가지 않고 `vault://`
참조도 받지 않는다. 같은 앱의 새 인증서는 자격증명 변경이라 소유 레코드가 있어도 되지만, 다른 앱 ID(공개 필드)는 인증 설정
변경이다(`AUTH_SETTINGS_FIXED_WHILE_IN_USE`).

- **로그인**: 모든 Microsoft 호출은 client credentials 흐름의 토큰을 쓴다. assertion은 PS256·`x5t#S256`(과 `x5t`), 5분 유효다.
- **자동 교체**(`cremore/onboarding/renewal.py`): worker 정비가 한 시간에 한 번(복제본 하나) 활성 연결을 본다. 만료 60일 전부터
  현재 키로 서명한 소유 증명과 함께 Microsoft Graph `addKey`로 새 인증서를 앱 등록에 더하고, 새 봉투를 봉인해 한 트랜잭션에서
  연결을 바꾸고 모든 소유 레코드를 다시 가리키며, 소유 콘텐츠 소스의 승인된 검사 범위를 새 자격증명으로 이어 준다(같은 앱·같은
  권한이라 사람의 재승인을 기다리지 않는다). 그다음 권한 점검을 요청한다(`PROVIDER_CONNECTION_CREDENTIAL_RENEWED`). 24시간 뒤,
  모든 소유 레코드가 새 자격증명을 가리키는 것을 확인한 다음에만 이전 인증서를 `removeKey`로 지운다
  (`PROVIDER_CONNECTION_CREDENTIAL_RETIRED`, 남은 레코드가 있으면 먼저 다시 가리키고 다음 시각에 지운다). 실패는
  `PROVIDER_CONNECTION_CREDENTIAL_RENEWAL_FAILED`로 감사된다. 앱은 자기 키를 바꾸는 데 권한이 필요 없지만 자기 애플리케이션 객체를
  찾는 데 Application.Read.All이 필요하므로 인증서 방식의 모든 용도 권한 목록에 있다. `addKey` 뒤 저장 전에 실패하면 그 인증서는
  키 없이 앱 등록에 남았다가 만료된다.
- **결과**는 `checks.renewal`(`state`·`action`·`code`·`at`·`renewed_at`)에 남는다. 관리자가 새 인증서를 만들면 비워진다. 교체가
  실패하거나 인증서가 만료되면 연동 행이 "확인 필요"가 된다. 앱의 Entra 토큰은 Azure DevOps Services(`dev.azure.com`)에만
  보내며, 서버 주소가 설정된 소스에는 보내지 않는다(`AZURE_DEVOPS_ENTRA_TOKEN_CLOUD_ONLY`). `addKey`는 유효한 인증서의 증명이 필요해서 만료된 인증서는 스스로 바꾸지 못한다. 그때는 새
  인증서를 만들어 올린다. 그사이 관리자가 자격증명을 바꿨으면 교체 결과를 버린다(compare-and-set). 이미 더한 인증서는 키 없이
  남았다가 만료된다.
- **대체된 공급자**: `replaced_by`가 있는 descriptor(`entra_id` → `azure`)는 새 연결로 제시하지 않고, 기존 연결은 그대로 수집한다.

### 스스로 교체하는 토큰 (GitLab)

갱신 종류 `ROTATES`는 만료가 있는 토큰을 CreMore가 만료 전에 바꾼다는 뜻이다. GitLab 토큰 방식이 그렇다
([gitlab/README](../gitlab/README.md)의 "토큰 자동 교체"): 같은 스윕이 하루에 한 번 토큰의 만료일을 읽고(`inspect`) 수명의
마지막 3분의 1에서 self-rotate로 후속 토큰을 받는다. 공급자가 이전 자격증명을 즉시 폐기하는 모듈(`RENEWAL_REVOKES_OLD`)은
교체 전에 시도가 표시되고, 중간에 끊겼거나(`RENEWAL_INTERRUPTED`) 결과가 불확실한(`…_UNCERTAIN`) 교체는 다시 시도하지 않는다.
관리자가 새 자격증명을 넣으면(`PUT …/credential`) 교체 기록이 비워지고 다시 시작한다.

## 4단계 계획

계획 항목은 descriptor의 `purposes.<용도>.plan`이다. `when: {대상 필드: [값]}`이 있는 항목과 권한은 해당 대상에만 적용된다.
값 `"*"`는 그 필드가 입력돼 있기만 하면 된다는 뜻이다(Microsoft 연결의 Azure DevOps 조직·프로젝트).

| 공급자 | 용도 | 계획 항목 |
| --- | --- | --- |
| 공통 | 발급 목록·금고·IdP | `schedule_minutes`(0이면 요청할 때만) |
| GitHub | 발급 목록 | `token_digests`(엔터프라이즈 감사 로그 토큰이 있을 때 토큰 digest) |
| GitLab | 발급 목록 | `audit_events`, `deploy_keys`(프로젝트), `enterprise_ssh_keys`(GitLab.com 그룹), `instance_sources`(인스턴스 범위) |
| GitLab | 금고 | `read_values`(CI 변수 값을 읽어 노출값과 대조) |
| Slack | 발급 목록 | `audit_events`(최근 90일 감사 로그로 설치 상태·설치일·설치자, `auditlogs:read` 필요) |
| Okta·Keycloak·Entra ID·GitHub | 사람 목록 | `people_details`(기본 켜짐: 이름·이메일·부서·직함 보관 → `options.keep_profiles`) |
| Okta·Keycloak | 사람 목록 | `apps`(기본 꺼짐: 앱 목록을 따로 수집해 연동 제안, `okta.apps.read`·`view-clients` 필요) |
| GitHub | 사람 목록 | `enterprise_identities`(Enterprise Cloud·GHE.com·Enterprise Server에서 대상에 엔터프라이즈를 넣으면 나온다. 끄면 조직의 SAML SSO 신원(App의 Members 읽기 또는 소유자 classic PAT의 `read:org`, App은 GitHub.com·Enterprise Cloud에서만), 켜면 엔터프라이즈의 SSO 신원(EMU 또는 엔터프라이즈 SAML, Server는 인스턴스 SAML, 소유자 classic PAT의 `read:enterprise`, 새 마법사의 조직 목록에는 `read:org`도)만 읽는다. Enterprise Cloud·Server는 기본 꺼짐, GHE.com은 기본 켜짐이고 끄면 `GITHUB_IDENTITY_GHE_COM_READS_THE_ENTERPRISE`. GHE.com 사람 목록은 연결을 만들 때부터 대상에 엔터프라이즈가 있어야 한다(같은 코드로 거절). GHE.com에서 이 선택 전에 저장된 계획은 조직 수집으로 남고, 계획을 바꾸면 그 자리에서 엔터프라이즈 수집으로 바뀐다) |
| GCP | 발급 목록·금고 | `read_values`(메모리에서 HMAC 지문화), `include_deleted`. 수집 원문 보관 옵션 없음 |
| Azure | 발급 목록 | `find_subscriptions`(보이는 구독 목록), `storage_key_accounts`(키 지문을 읽을 Storage 계정 리소스 ID) |
| Azure | 금고 | `read_values`(Key Vault 값 대조) |
| Azure | 사람 목록 | `people_details`(이름·이메일·부서 보관) |
| AWS | 금고 | `regions`, `ssm_prefixes`, `previous_versions`, `max_versions`, `value_reader`(별도 값 읽기 역할로 값 읽기, 계정별 수집 역할만: [AWS](../aws/README.md#값-읽기-역할))와 함께 쓰는 `value_reader_role`·`secret_arns`(연결 계정·고른 리전의 시크릿 ARN, 계정마다 하나 이상)·`kms_key_arns`(같은 계정의 고객 관리형 키). 계획 정규화 때 모든 대상 계정을 함께 검사한다(`plan_problem`) |
| Vault·OpenBao | 금고 | `previous_versions`·`max_versions`(KV v2), `token_accessors`, `lease_prefixes` |

값 읽기는 기본 꺼짐이고 계획에서 고를 때만 켠다([값 읽기 정책](SECRET_VALUE_READING_POLICY.md)). GCP는 한 프로젝트를
한 수집 레코드가 발급 목록·금고 두 용도로 읽으므로, 두 용도를 같은 4단계에서 고르면 선택을 합치고 나중에 고르는 용도는
먼저 만든 레코드의 값 선택과 달라서는 안 된다(`GCP_VALUE_CHOICES_SET_BY_THE_PROJECT_COLLECTION`). 이 밖의 수집 옵션은
만들어진 수집 레코드의 편집(수집 연결 PATCH)에서 바꾼다.

### 기존 연결에 기능 추가·중지·재개

연동 설정에서 같은 인증 방식으로 지원하는 기능을 나중에 추가할 수 있다.
`PUT /api/v1/provider-connections/{id}/purposes`(admin, `{"purposes": ["inventory", "exposure"], "expected_revision": n}`)로
전체 선택을 저장한 뒤 권한 점검을 다시 하고, `/activate`로 새 기능만 켠다. 기존 활성 계획·자격증명·소유 레코드는 유지한다.
활성 기능은 이 요청으로 제거할 수 없고, 조치용 인증의 분리·공급자 대상 제약·로그인 IdP 규칙도 생성 때와 동일하다.
선택이 바뀌면 이전 점검은 오래된 결과가 되며, 변경 전에 시작한 점검도 새 선택을 승인하지 못한다.
GCP 프로젝트처럼 기능들이 수집 레코드 하나를 공유하면 활성화 시 같은 레코드의 capability를 갱신한다.
다른 인증이 필요한 조합(예: Notion 내부 연결 토큰의 노출 검사와 Enterprise 조직 봇의 발급 목록)은
같은 설정 화면에서 추가 인증을 이어가고 내부적으로 별도 연결을 쓴다. 한 인증 방식에 없는 기능을
회색으로 잠그는 대신 추가 인증·제품 조건을 표시한다. [공급자별 조합](AUTH_FIRST_ONBOARDING_DESIGN.md#여러-인증이-필요한-기능을-한-번에-설정하기)을 따른다.

기존 노출 검사 범위는 기본으로 유지한다. 노출 검사를 처음 추가할 때만 범위를 새로 선택한다.
반복적인 대상 추가·제외는 연동 메뉴의 **검사 대상 설정**에서 저장된 선택을 불러와 수정하고, 추가·제외·변경 수를 확인한 뒤
저장한다. 기능 추가나 발급 목록 옵션 변경만으로 승인된 범위·제외 목록을 덮어쓰지 않는다.

기능별 중지·재개는 `PUT /api/v1/provider-connections/{id}/features/{purpose}`의
`{"enabled": false, "expected_revision": n}`으로 요청한다. 중지는 외부 API 권한 없이 가능하며
계획·대상·승인 범위·수집 이력을 보존한다. `enabled: true`로 재개할 때는 저장된 정확한 계획에 대한
최신 필수 권한 점검을 요구한다. 콘솔은 재개가 `409 PERMISSION_CHECK_REQUIRED`로 거절되면 그 연결의 권한 점검을 요청해 끝나기를
기다린 뒤 한 번 다시 켠다(점검에서 권한이 부족하면 `REQUIRED_PERMISSIONS_NOT_GRANTED`를 보여 준다).
같은 자격증명으로 기능을 추가하는 `/purposes`·`/activate`와 구별한다.
공유 수집 레코드는 남아 있는 기능만 수행하고, 기능의 중지 상태는 인증정보 교체·대상 편집·전체 연동 재개로 풀리지 않는다.
연결 조회의 `feature_enabled`가 개별 기능의 상태를 제공한다. 전체 연결의 `status`가 `DISABLED`이면
개별 기능이 켜져 있어도 실행하지 않는다. `disabled_purposes`는 내부 저장 형식이다.

DB는 `provider_connections.disabled_purposes` nullable JSON을 추가하고 과거 NULL은 빈 목록으로 읽는다.
기존 행을 삭제하거나 계획에 임의 필드를 섞지 않는다. 배포는 API·worker를 함께 교체한 다음 새 웹을 연다.
이 필드를 모르는 이전 런타임으로 되돌릴 때는 중지 기능이 있는 소유 연결을 먼저 전체 중지해야 한다.
이전 코드의 전체 재개가 기능별 중지를 이해한다고 가정하지 않는다.
AWS는 모든 기능을 개별 중지해도 재인증·권한 확인에 쓸 계정 신원을 유지한다.
이 계정이 존재한다는 사실은 S3 검사나 IAM·금고 자동 수집이 켜져 있다는 뜻이 아니다.

### 계획 변경

`PUT /api/v1/provider-connections/{id}/plans/{용도}`(admin, `{"plan": {...}, "expected_revision": n}`)는 `ACTIVE` 연결에서
수집 중인 용도의 계획(종류, 옵션, 주기)을 바꾸고, 소유 수집 레코드는 다음 실행부터 바뀐 계획을 따른다.

- 이전·새 계획을 모든 활성 용도를 한 번에 고른 것처럼 공급자의 `children()`으로 각각 설명하고, 두 설명을
  수집 레코드의 종류·공급자·이름(대상에서 나온다)으로 짝짓는다. 두 계획이 다른 항목만 저장된 spec에 적용하므로 자격증명
  참조, 만든 뒤 레코드에서 직접 고친 값, 켜짐·꺼짐은 그대로다. 두 용도가 함께 쓰는 레코드(GCP 프로젝트 수집)는 어느
  용도의 계획이 바뀌어도 반영된다.
- 새 계획에만 있는 레코드는 만들고(수집기 토큰은 응답 `changed`에서 한 번만), 이전에 꺼진 같은 레코드는 새 설명으로
  다시 켠다. 이전 계획에만 있는 레코드는 지우지 않고 끈다(`COLLECTION_TURNED_OFF_BY_PLAN`). 계획이 설명하지 않는 레코드
  (AWS 계정의 발급 목록 수집, 콘텐츠 소스, AWS 계정)는 건드리지 않는다.
- 계획 저장과 레코드 변경은 한 트랜잭션이다. 정규화한 계획이 저장된 것과 같으면 아무것도 바꾸지 않는다.
- 거절: `PROVIDER_CONNECTION_NOT_ACTIVE`, `PURPOSE_NOT_ACTIVE:<용도>`, `PLAN_FIELD_*`, 공급자 계획 코드,
  `PROVIDER_CONNECTION_CHANGED`(revision), 레코드 변경 충돌은 `CONNECTION_REVISION_CONFLICT`.
- 감사 이벤트: 연결의 `PROVIDER_CONNECTION_PLAN_CHANGED`, 레코드의 `COLLECTION_PLAN_CHANGED`·`COLLECTION_TURNED_OFF_BY_PLAN`.

## 발급 목록 토큰 종류

descriptor의 `purposes.inventory.types`는 발급 목록이 가져오는 자격증명 종류와 종류별 대표 메타데이터 9개
(`INVENTORY_FIELDS`: ID·이름·생성일·만료일·권한·생성자·소유자·마지막 사용·상태)의 지원 여부를 선언한다.

- `support`는 9자리 문자열이다. `Y`는 API가 주는 값을 수집기가 보관, `P`는 조건이 맞을 때만(권한·요금제·감사 로그 등),
  `N`은 API가 주지 않음. `P`·`N`마다 `reasons`에 `[한국어, 영어]` 이유가 있어야 한다.
- `match`는 대안 목록이고 각 대안의 조건(`provider`·`prefix`·`contains`·`kind`·`fact`+`in`·`credential_type`)이 모두 맞으면
  그 종류다. `catalog.inventory_type(provider, item)`이 수집된 항목의 종류를 찾는다.
- 자격증명 목록 행은 `issued.type`을 가진다. 공개 키·앱 설치처럼 비밀이 아닌 항목은 종류가 선언된 경우에만 행이 된다.
- 선언은 공급자가 공개하는 API 필드의 설명이다. 실제 수집 여부는 연결·권한·요금제에 따라 달라지며 화면의
  채움 정도는 수집된 토큰에서 계산한다.

카탈로그 검증은 이유 없는 `P`·`N`, 모르는 조건 키, 용도의 권한·에디션 밖의 값, 발급 목록 밖의 선언을 거절한다.

종류는 `when`(대상 조건)과 `plan`(수집 방식)을 가질 수 있다. `plan`은 앞에서부터 처음 적용되는 하나가 정한다.
`{always: true, when?, editions?}`는 그 조건에서 항상 목록에 있고, `{field}`는 bool 계획 항목이 켜거나 list 계획 항목이
읽을 곳을 정하며, `{field, option}`은 choices 계획 항목의 한 선택지다. `plan`이 있는데 적용되는 것이 없으면 그 대상에서는
목록에 없다(예: GitLab SSH 키는 GitLab.com 그룹의 `enterprise_ssh_keys`나 인스턴스의 `instance_ssh_keys`로만 읽는다).
마법사의 "가져올 Credential 유형"은 이 선언에서 나오며, 켜고 끄면 연결된 계획 항목이 바뀌어 `children()`이 그대로 따른다.

## 노출 검사 위치와 검사 범위

`purposes.exposure.scans`는 노출 검사가 읽는 것(저장소 파일, 페이지 본문·첨부, 버킷 객체 등)을 선언한다. 노출 검사를
시작하는 모든 공급자가 선언하며 카탈로그 검증과 `providers_test`가 확인한다.

마법사 1단계의 "검사 범위"는 연동 계정이 볼 수 있는 전체, 또는 이름·경로 패턴(`platform/*`)이다. 활성화한 뒤
콘솔이 노출 소스(AWS는 계정)마다 목록을 새로 가져오고(`resources/refresh`, 내용은 읽지 않는 메타데이터 작업),
`selection-drafts`의 `patterns`로 맞는 곳을 정확한 리소스 ID로 고정해 승인된 검사 범위로 저장한 다음(관리자 작업),
미리보기 계획으로 첫 기본 검사를 시작한다. 설치에서 한 번에 하나만 도는 내용 검사 자리가 차 있으면 범위만 저장하고
"지금 수집"으로 나중에 시작한다. 목록은 저장할 때의 것이며 나중에 생긴 곳은 범위를 다시 정할 때 들어간다.

### 인증 후 범위 선택

[인증 후 수집 범위를 선택하는 온보딩 설계·구현 범위](AUTH_FIRST_ONBOARDING_DESIGN.md)에 현재 지원 경로와 제한을 기록한다.
목표 흐름은 서비스 선택 → 인증 → 사용할 기능 선택과 목록 권한 확인 → 수집 범위 선택과 권한 확인 → 검토·시작이다.
발급 목록·노출 검사·금고 대조·사람 목록·승인된 조치 실행 카드도 인증 뒤에 설정한다.
인증 전에는 서비스·판·인증 방식과 필요한 접속 정보만 정하고, 인증 후 지원 기능·부족한 권한을 확인하며 고른다.
지원 가능한 인증 경로에서는 계정·조직·프로젝트·페이지 ID를 직접 입력하지 않고 조회한 목록에서 선택한다.

인증 성공과 권한 충족은 별도로 검사한다. 인증 단계에서는 최소 인증 권한을, 기능 선택 후에는 필요한 목록 권한을 확인한다.
기능 선택으로 추가 동의가 필요하면 선택을 유지하고 안내하며 처음부터 모든 기능의 권한을 요구하지 않는다.
목록 필수 권한이 부족하면 범위 선택 전, 선택한 대상·옵션의
수집 권한이 부족하면 검토·시작 전에 거절된 작업·대상·해결 방법을 보여 주고 서버가 단계 이동을 막는다.
필수 권한 미확인도 통과로 처리하지 않는다. 선택하지 않은 기능의 권한은 요구하지 않는다.
서비스 계층의 `permissions.require`와 초안의 단계별 검사가 적용되며, 기존 활성화·범위 API로 우회할 수 없다.

설계안에는 등록된 공급자 전체의 판·인증 방식별 가능성, 공식 API 근거, 인증정보 소유와 갱신,
다중 대상·부분 목록·반복 범위 수정, 호환·배포·인수 조건을 정리했다. Notion Enterprise 상위 목록 등
근거가 부족한 경로와 고객 CLI처럼 서버 인증이 없는 경로는 자동 지원으로 표시하지 않는다.
기존 활성 연결은 재생성하지 않는다. 기존 연결의 대상 편집은 `/targets/draft`에서 같은 인증을 재사용하고
동일 소유자에 확정한다. 기존 세부 범위·제외·주기·예산·일시 중지는 유지한다. 여러 scope profile이 있거나 기존 대상 일부를
조회하지 못하면 기존 검사 대상 편집기로 안내한다. root 제거는 별도 `/targets` PUT으로 공급자 접근 없이 가능하다.
실계정 호출·배포 검증은 별도이며 이번 구현 검사는 fake 공급자만 사용했다.

### 검사 대상 창 (콘솔)

연동 서비스의 행("검사 대상 정하기", 메뉴의 "검사 대상 설정")과 수집·탐지 현황의 "검사 대상 설정"이 같은 창을 연다(관리자).
모든 공급자가 같은 두 단계다.

1. **대상 고르기**: 노출 검사가 읽는 곳마다(AWS는 계정, 그 밖에는 연결된 소스) 탭 하나에 목록(`resources`, 50개씩)을 보여 준다.
   처음 여는 곳은 목록을 가져오고(`resources/refresh`), "목록 새로 고침"으로 다시 가져온다. 이름 찾기, 종류, "고른 것"
   (`resources/search`의 `selected_ids`)으로 좁혀 보고, 목록에 있고 읽을 수 있는 것만 고른다(목록 권한이 없으면 행이 남되
   고를 수 없다). 고른 것은 범위를 좁힐 수 있다: 버킷·Blob 컨테이너는 모든 객체 또는 읽을·제외할 접두어, 저장소는 브랜치와
   읽을·제외할 경로, TFVC는 경로, Notion 페이지는 이 페이지만·하위 페이지 포함, Notion 데이터베이스는 고른 행
   (공급자 페이지 ID, `parent_id`·`known_root_id`로 목록을 읽는다). 서버가 거절할 선택(객체를 정하지 않은 버킷, 행이 없는
   데이터베이스)은 다음 단계로 가기 전에 막는다.
2. **확인**: 곳마다 고른 것과 저장한 것 대비 추가·빠짐·범위 바뀜, 검사 주기(직접 실행·6시간·매일·매주), 선택 입력인 변경
   이유를 보고 "저장" 또는 "저장하고 지금 검사"를 누른다. 저장은 본 목록의 스냅샷(`catalog_snapshot_id`)과 정확한 리소스 ID로
   승인된 범위(`scan-scope-profiles`)를 만들거나 바꾸고(`expected_version`), 검사는 미리보기 계획으로 기본 검사를 시작한다.
   내용 검사 자리가 차 있으면 저장만 되고 결과에 그렇게 보인다. 그사이 목록이 바뀌었으면(`SCOPE_CATALOG_CHANGED`) 다시
   확인하게 한다.

### 인증 단계는 모든 공급자가 같다

마법사 2단계는 공급자와 무관하게 인증 방식 탭, 입력 칸, 안내, 설정 도우미, "연결 확인"과 결과, 필요한 권한 순서다.
설정 도우미는 공급자 쪽에서 할 일(정책 복사, 템플릿 받기 등)을 같은 목록으로 보여 준다. AWS는 CreMore가 실행되는 AWS
신원을 안내 한 줄로 보여 주고, 승인한 신원이 없거나 바뀌었으면 "연결 확인"이 그 신원을 먼저 승인한 뒤(`PUT
/api/v1/aws/scanner-identity`, `confirm: true`) 권한을 확인한다. 로그인이 없거나 API·워커의 신원이 다르면 다른 공급자의
확인 실패와 같은 결과 줄과 해결 방법으로 보인다. 멤버 역할 방식의 계정별 역할(ExternalId, CloudFormation)은 설정 도우미의
한 단계다.

AWS 인증 후 범위 선택에서 `ASSUME_ROLE_DENIED`가 나오면 수집 역할의 신뢰 대상·ExternalId와
서버 신원의 `sts:AssumeRole` 권한을 비교한다. 삭제 후 다시 만든 서버 역할은 ARN이 같아도
기존 신뢰 정책에 이전 principal ID가 남을 수 있다. 계정 접근 실패는 계정별로 표시하고,
아직 호출하지 않은 서비스 권한은 `SCANNER_ACCESS_REQUIRED`로 구분한다. 동일한 권한 결과를
화면에서 합쳐도 기능별 필수 권한 검사는 유지한다.
서버 권한 직접 사용에서 `AWS_REGIONS_ACCESS_DENIED`가 나오면 현재 서버 역할의
`ec2:DescribeRegions` 권한을 확인한다. 실패한 기능 단계에도 기존 읽기 정책 설정 도우미를
표시하며, 권한을 수정한 뒤 같은 단계에서 대상 목록을 다시 조회할 수 있다.

## 범위

| 공급자 | 대상 | 비고 |
| --- | --- | --- |
| GitHub | 조직, 선택적 엔터프라이즈, 서버 주소(GHE.com·Server) | App은 노출·발급 목록·금고, PAT는 노출·IdP |
| GitLab | 그룹 또는 프로젝트 ID, 또는 인스턴스 전체(Self-Managed·Dedicated, 관리자) | 인스턴스 범위는 발급 목록만 |
| Atlassian | Confluence 스페이스, Bitbucket 워크스페이스·프로젝트, Atlassian 조직 | Confluence Cloud는 서비스 계정 OAuth 2.0(권장, API 게이트웨이 자동) 또는 토큰 |
| Notion | 워크스페이스 | 통합 토큰은 노출, Enterprise 조직 봇은 PAT·MCP 연결 목록을 각각 선택(기본 PAT만); 선택한 목록의 읽기 권한 필요 |
| AWS | 계정 ID 목록, 환경, `adopt_discovered` | 계정은 2단계에서 등록(ExternalId가 스택보다 먼저 있어야 한다) |
| GCP | 프로젝트, 또는 조직·폴더 번호 | 조직·폴더는 하위 프로젝트 찾기(발급 목록)만 |
| Microsoft(`azure`) | 테넌트, 구독, Storage 계정, Key Vault 이름, Azure DevOps 조직·프로젝트 | Entra ID 사람 목록은 이 연결의 기능. 개인 액세스 토큰의 Azure DevOps(Server, 테넌트에 연결되지 않은 조직)는 별도 공급자 |
| Vault·OpenBao | 주소, 네임스페이스, KV 마운트·버전·접두어, 선택적 CA 인증서 | |
| 범용 금고 | 제품 이름, 선언 경로 | 고객 환경 CLI 또는 설치된 읽기 플러그인 |
| Okta·Keycloak·Entra ID | 조직·realm·테넌트 | 퇴사자 점검용 IdP. Entra ID(사람)는 새로 만들지 않고 Microsoft 연결로 대체 |

## 고객 환경 CLI

Vault·OpenBao, 범용 금고, AWS(발급 목록·금고), GCP(Secret Manager)는 `customer_cli` 방식으로 고객 환경의
`cremore-coverage`가 읽게 할 수 있다. CreMore는 계정·프로젝트에 접근하지 않고, 값은 고객 환경에서 지문으로 바뀌어
수집기 토큰과 함께 도착한다. 이 방식의 권한 점검은 `NOT_REPORTED`(`CUSTOMER_CLI_REPORTS_ON_UPLOAD`)이며 업로드된 실행이
실제 결과를 보고한다.

## 인계와 다시 연결하기

소유 레코드는 한 번에 한 공급자 연결만 가진다. 새 연결이 설명한 레코드가 이미 있고 그 주인이 **중지된** 연결이거나 주인이
없으면 새 연결이 인계받는다(`PROVIDER_CONNECTION_RECORD_TAKEN_OVER`).

- 콘텐츠 소스는 이름으로 찾는다. 발견·스캔 이력이 그대로 이어지고 새 자격증명으로 다시 점검한다. 활성 연결이 같은 이름의
  소스를 쓰고 있으면 새 소스를 번호를 붙여 만든다(`GitHub · acme (2)`).
- AWS 계정은 같은 접근 방식(역할·권한 세트)일 때만 인계한다. 레코드와 ExternalId가 그대로라 배포한 스택을 다시 만들 필요가
  없다. 다른 접근 방식이면 `ACCOUNT_REGISTERED_WITH_ANOTHER_ACCESS`, 활성 연결이 가진 계정이면 `ACCOUNT_ALREADY_REGISTERED`다.
- 중지된 연결은 소유 레코드가 없어야 삭제된다(`PROVIDER_CONNECTION_HAS_CHILDREN`). 레코드는 이력 때문에 지우지 않는다.

## AWS 자동 발견 계정

대상의 `adopt_discovered`를 켠 활성 AWS 연결은 Identity Center·Organizations 스윕이 등록한 계정 가운데 자기 접근 방식의
계정을 받아들인다. 권한 세트 연결은 Identity Center 스윕(같은 권한 세트), 멤버 역할 연결은 Organizations 스윕(StackSet의
공유 ExternalId)이다. 받아들인 계정에는 그 연결이 저장한 4단계 계획대로 발급 목록 수집과 금고 읽기가 붙는다
(`PROVIDER_CONNECTION_RECORD_ADOPTED`). worker는 폴링마다, `POST /api/v1/aws/accounts/discover`는 스윕 직후에 실행한다.
관리자가 중지한 계정과 다른 연결이 가진 계정은 받아들이지 않는다. 계정 발견·편입은 scanner 접근 승인을 대신하지 않는다.

## API

인증 초안은 `POST /api/v1/onboarding-sessions`로 시작하고 같은 경로의 `/{id}/{action}`에서
`read`·`authenticate`·`discover`·`inspect`·`select`·`complete`·`cancel`을 사용한다. 모두 admin·`no-store`이며
사용자·브라우저 바인딩을 검사하고 변경에는 `expected_revision`이 필요하다.
기존 연결의 `POST /provider-connections/{id}/targets/draft`, 제거 전용 `PUT /provider-connections/{id}/targets`도 admin이다.
요청 필드와 권한 오류는 [API 계약](API.md)을 따른다. scope 확대 API도 최신 권한·catalog를 요구하며
충돌하는 `expected_version`은 `SCOPE_VERSION_CONFLICT`로 거절한다.

| Method | Path | Role | 설명 |
| --- | --- | --- | --- |
| GET | `/api/v1/provider-connections/catalog` | viewer | 마법사가 보여 주는 공급자·에디션·용도·권한·인증 방식 |
| GET | `/api/v1/provider-connections` | viewer | 공급자 연결 목록(참조 없음) |
| POST | `/api/v1/provider-connections` | admin | 1·2단계. 201, `Cache-Control: no-store` |
| GET | `/api/v1/provider-connections/{id}` | viewer | 연결과 소유 레코드의 현재 상태 |
| PATCH | `/api/v1/provider-connections/{id}` | admin | 이름 변경(`expected_revision` 선택) |
| POST | `/api/v1/provider-connections/{id}/check` | admin | 3단계. 202 |
| PUT | `/api/v1/provider-connections/{id}/purposes` | admin | 기존 인증으로 지원하는 기능 선택 변경. 활성 기능 유지·추가 기능은 재점검 후 활성화 |
| PUT | `/api/v1/provider-connections/{id}/features/{purpose}` | admin | `{enabled, expected_revision}`로 기능별 중지·재개. 계획·범위·이력 보존, 재개는 최신 권한 점검 필요 |
| POST | `/api/v1/provider-connections/{id}/activate` | admin | 4단계. 수집기 토큰은 이 응답에서 한 번만 |
| PUT | `/api/v1/provider-connections/{id}/plans/{용도}` | admin | 수집 중인 용도의 계획 변경. 새 레코드의 수집기 토큰은 이 응답에서 한 번만 |
| PUT | `/api/v1/provider-connections/{id}/credential` | admin | 같은 방식의 새 자격증명 |
| POST | `/api/v1/provider-connections/{id}/disable`·`enable` | admin | 모든 소유 레코드를 함께 중지·재개 |
| DELETE | `/api/v1/provider-connections/{id}` | admin | 소유 레코드가 없는 연결만. 204 |

모든 단계는 감사 이벤트(`PROVIDER_CONNECTION_*`)를 남기고 자격증명은 이벤트에 들어가지 않는다.

## 공급자 모듈 계약

공급자 담당자는 `<vendor>/backend/cremore_<vendor>_provider/onboarding.py`를 소유하고, 플랫폼은
`cremore/onboarding/catalog.py`의 `MODULES`에 명시적으로 등록한다(자동 탐색 없음). 계약은 `catalog.py` 머리말이 기준이다.

| 이름 | 필수 | 내용 |
| --- | --- | --- |
| `DESCRIPTORS` | 예 | 공급자·에디션·대상 필드·용도(권한 목록, 계획 항목, 발급 목록 토큰 종류)·인증 방식(권장 순서, 갱신 종류, 필드, `reference`, `reference_keys`, `generated`), 선택 `replaced_by` |
| `credential(provider, method, fields)` | 예 | 필드를 역할별 봉투로 정규화(`credential`이 모든 용도가 공유하는 역할) |
| `check(connection, purpose, secrets, context)` | 예 | worker에서 실행. 권한별 상태와 코드만 반환. 순수 탐색은 `cremore.onboarding.probe` |
| `authenticate(connection, secrets, context)`·`discover(connection, secrets, context)` | `auth_first` 선언 시 | worker에서 최소 인증 후 선택 기능의 정규화 대상·부분 상태·안전한 cursor를 반환. 인증 전 수집 기능을 요구하거나 목록을 최종 승인으로 취급하지 않음 |
| `credential_identity(connection, secrets, context)` | 아니요 | worker의 점검에서 실행. 저장한 토큰이 아니라 다른 것이 실행 신원일 때 그 이름(GitHub App, Google 계정, worker ADC). 점검은 이 이름이나 역할별 토큰의 키 기반 지문(`checks.credential_marks`, 화면·API에 나오지 않음)을 남기고, 같은 자격증명을 쓰는 조치 연동과 수집 연동을 양쪽에 경고한다([공급자 자격증명 조치](PROVIDER_ACTIONS.md) 3절). `None`이면 토큰 |
| `children(connection, purpose, plan)` | 예 | 용도가 필요로 하는 레코드 설명(`cremore/onboarding/children.py`). `connection["activating"]`에 같은 호출의 모든 계획. 수집 레코드 이름은 대상에서만 만든다(계획 변경이 종류·공급자·이름으로 레코드를 찾는다) |
| `target(provider, edition, values)` | 아니요 | 대상 의미 검증·정규화 |
| `ready(repo, settings, connection)` | 아니요 | 저장 전에 설치가 아직 받을 수 없는 연결 거절(예: 승인된 AWS 신원 없음) |
| `sign_in_target(provider, issuer)` | 사람을 읽는 IdP면 | 콘솔 로그인 issuer가 가리키는 대상 필드(`target`과 같은 정규화), 이 IdP의 issuer가 아니면 `None`. 팀 설치의 사람 목록은 그 대상이어야 한다 |
| `prepare(connection)` | 아니요 | 점검 전에 있어야 하는 레코드(AWS 계정) |
| `plan_problem(roots, purpose, plan)` | 아니요 | 정규화한 계획을 모든 대상을 한꺼번에 보고 거절할 코드(`cremore.onboarding.targets.normalize_plan`). `children`은 대상을 하나씩 본다(예: AWS 값 읽기 역할의 시크릿 ARN이 연결 계정 밖) |
| `adoptable(repo, connection)` | 아니요 | 발견이 등록한, 이 연결이 받아들일 레코드 |
| `generate(provider, method, fields, target)` | `generated` 방식이 있으면 | CreMore가 만드는 자격증명: `({역할: 봉투}, 공개 부분)`. 공개 부분은 `target.generated` |
| `renew_due(record, kept, now)`, `renew(record, envelope, action, kept, context)` | 아니요 | worker가 스스로 교체하는 자격증명: 할 일(`renew`, 모듈 고유의 `retire`·`inspect`)과 그 실행(`cremore/onboarding/renewal.py`). 이전 자격증명을 공급자가 즉시 폐기하면 `RENEWAL_REVOKES_OLD = True` |

카탈로그 검증(`catalog.validate`), 공급자별 레코드 행렬(`cremore/onboarding/providers_test.py`: 모든 공급자·에디션·방식·용도와
계획 항목을 켠 경우의 레코드가 실행할 저장소의 검증을 통과), 권한 점검 모의 서버(`checks_test.py`), 마법사 전 과정
(`onboarding_test.py`, 메모리·SQLite·PostgreSQL)이 계약을 검사한다. 공급자 모듈은 `cremore.onboarding.probe`와 공통 모델만
import하며 경계 테스트([provider_boundaries_test](../cremore/provider_boundaries_test.py))가 이를 확인한다.

## 없어진 경로

`POST /api/v1/source-connections`, `POST /api/v1/connections`, `POST /api/v1/aws/accounts`·`/onboarding`·`/bulk`,
`POST /api/v1/coverage/connections`, `PUT`·`DELETE /api/v1/coverage/connections/{id}/vault-token`,
`POST /api/v2/coverage/connections`, `POST /api/v2/coverage/github/enterprise-connections`,
`PUT`·`DELETE /api/v2/coverage/connections/{id}/github-enterprise-audit-token`,
`POST /api/v2/coverage/gcp/from-source/{id}`. 조회·수집·범위 선택·스캔 경로는 그대로다. 개발 중 만든 DB는 새로 시작한다.

## 검증 범위

합성 공급자(모의 HTTP·가짜 AWS 세션)와 메모리·SQLite·격리 PostgreSQL로 검증했다. 실제 공급자 계정의 권한 점검과 수집,
고객 환경 CLI 실행은 실환경 검증 항목이다. Microsoft 앱 인증서의 로그인·`addKey`·`removeKey`는 공식 문서의 형식대로 합성
Microsoft로 검증했고(`cremore/onboarding/microsoft_test.py`, `azure/backend/cremore_azure_provider/app_certificate_test.py`),
실제 테넌트에서의 동작은 실환경 검증 항목이다.
