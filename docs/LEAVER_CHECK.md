# 퇴사자 자격증명 점검

IdP에서 비활성화·삭제된 사람이 공급자에 남긴 자격증명을 찾아 판정한다. 설계 근거는
[통합 운영 설계 4.2절](CONTINUOUS_OPERATIONS_DESIGN.md#42-idp-연동)과 결정 4·12·13이다.
구현은 `cremore/identity/`(엔진), 공급자 폴더의 IdP 수집기와 소유자 함수다.

## 1. 흐름

1. **IdP 사용자 수집**: IdP 연결(schema 2 관리정보 연결)이 사용자 ID·상태·상태 변경 시각을 읽는다. 매칭에 쓰는
   이메일·로그인은 설치 키(`FINGERPRINT_KEY`에서 유도한 별도 키)로 만든 **keyed digest로만** 저장한다. 사람 정보 보관
   (`options.keep_profiles`)을 켠 연결은 담당자·연락 대상 표시용으로 표시 이름·이메일·부서·직함을 사실로 함께 남긴다
   (아래 6절). 연결 판정은 이 값을 쓰지 않는다.
2. **공급자 계정과 자격증명**: 발급 목록(GitHub·GitLab·Azure DevOps·Atlassian·Notion의 schema 2 수집, AWS IAM 인벤토리)에서
   공급자별 `credential_owner` 함수가 자격증명의 소유 계정과 연결 근거 값을 꺼낸다. GitHub 로그인이 누구인지는
   조직이나 엔터프라이즈(EMU·엔터프라이즈 SAML)의 외부 신원(SAML·SCIM, OIDC를 쓰는 EMU는 SCIM만) 연결(`github_identity`)이 알려 준다.
3. **연결**: 계정과 사람은 같은 값을 **정확한 근거**로 가리킬 때만 연결한다. 그보다 약한 근거는 관리자가 확정하는 후보다.
4. **판정·산출**: 퇴사한 사람과 연결된 계정의 자격증명마다 판정을 내리고, 판정이 새로 생기거나 바뀌면
   `identity.credential_orphaned` 이벤트와 거버넌스 티켓을 만든다. worker 하나가 5분마다 평가하며
   관리자는 `POST /api/v1/leavers/evaluate`로 바로 평가할 수 있다.

## 2. IdP 연결 (최소 권한 전용 앱)

개인 관리자 토큰은 받지 않는다(결정 12). 연결은 관리정보 연결 API(`POST /api/v1/metadata/connections`)로 만들고
비밀은 봉인 또는 금고 참조(`secret_refs`)로 넣는다. `schedule_minutes`로 주기 수집한다. IdP 수집은 CreMore worker만
실행한다. 수집기 토큰으로는 실행을 시작하거나 닫지 못한다(`IDENTITY_COLLECTION_IS_WORKER_ONLY`). 그 토큰은 IdP 기록을 보낼 수
없는데, 빈 실행이 최신 수집이 되면 worker가 본 정지·삭제의 반영이 늦어지고, worker의 실행을 중간에 닫으면 아직 읽지 않은
사람이 모두 목록에서 빠진 것으로 보이기 때문이다. 목록에서 빠진 사람을 퇴사로 보는 것은 그 수집이 지금 읽는 디렉터리(origin·tenant)의
사람뿐이다. 수집을 다른 디렉터리로 바꾸면 이전 디렉터리 사람의 상태는 마지막으로 본 그대로 남는다.
사람이 회사 IdP로 로그인하는 팀 설치(`AUTH_MODE=oidc`)에서는 공급자 연결 마법사가 로그인 IdP 자신(같은 조직·테넌트·렐름)만
사람 목록으로 받는다(2026-10-02 결정, [공급자 연결](ONBOARDING.md)). GitHub 신원 연결은 예외다. 팀 설치에서는 공급자 연결이
만든 사람 목록 수집을 다른 디렉터리로 바꾸지 못한다(`409 PEOPLE_DIRECTORY_BELONGS_TO_PROVIDER_CONNECTION`). 다른 디렉터리는 새
연결로 만든다.

| IdP | provider | 인증 | 필요한 권한 | 범위 |
| --- | --- | --- | --- | --- |
| Okta | `okta` | `private_key_jwt`: 서비스 앱의 `client_id`, 개인키(PEM 또는 `kid`가 든 JWK) | `okta.users.read` | `organization` = 조직 호스트(예: `acme.okta.com`), `tenant`도 같은 값 |
| Microsoft Entra ID | `entra_id` | `workload_identity`(`DefaultAzureCredential`: 워크로드 신원 연동·관리 ID·앱 비밀) | 애플리케이션 권한 `User.Read.All` | `organization` = 확인된 테넌트 ID |
| Keycloak | `keycloak` | `oauth_client`: 서비스 계정을 켠 confidential client의 `client_id`·`client_secret` | realm-management `view-users`(관리 이벤트를 읽을 때 `view-events`) | `realm` 하나, `tenant` = realm 이름, `options.api_path`에 예전 `/auth` 접두어 |
| Google Workspace | `google_workspace` | `private_key_jwt`: 서비스 계정 키(JSON, `private_key`)와 위임받을 최고 관리자 이메일(`username`), 도메인 전체 위임 | 최고 관리자가 관리 콘솔의 도메인 전체 위임 관리에서 서비스 계정 클라이언트 ID에 `https://www.googleapis.com/auth/admin.directory.user.readonly` 허용, 서비스 계정 프로젝트에서 Admin SDK API 사용 설정 | `organization` = 기본 도메인(예: `acme.com`), `tenant`도 같은 값 |

- **Okta**: 상태 필터 하나로 모든 상태(ACTIVE·SUSPENDED·DEPROVISIONED 등)를 읽는다. 필터 없는 목록은 DEPROVISIONED를
  빼기 때문이다. `statusChanged`가 퇴사 시각이 된다. 서비스 앱이 DPoP를 요구하면 첫 응답(`invalid_dpop_proof`·`use_dpop_nonce`)을
  보고 이번 실행용 키로 증명(`htm`·`htu`·`iat`·`jti`, API 호출은 `ath`까지)을 붙인다.
  [Users API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/),
  [OAuth for Okta](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/),
  [DPoP](https://developer.okta.com/docs/guides/dpop/oktaresourceserver/main/)
- **Entra ID**: `GET /v1.0/users`(`accountEnabled`)와 삭제된 사용자 `GET /v1.0/directory/deletedItems/microsoft.graph.user`
  (`deletedDateTime`, 30일 보관)를 읽는다. 비활성화 시각은 Graph에 없어 처음 비활성으로 본 수집 시각을 쓴다.
  [List users](https://learn.microsoft.com/en-us/graph/api/user-list),
  [List deletedItems](https://learn.microsoft.com/en-us/graph/api/directory-deleteditems-list)
- **Keycloak**: `GET /admin/realms/{realm}/users?briefRepresentation=true`를 `first`·`max`로 넘긴다. 서비스 계정 사용자는 뺀다.
  서버가 쪽을 나눈 뒤 일부 행을 빼기도 해서(LDAP에서 사라진 사용자, 볼 수 없는 사용자) 다음 쪽은 한 쪽 크기만큼 넘기고, 짧은
  쪽이 아니라 빈 쪽에서 끝난다. `GET /admin/realms/{realm}/users/count`로 시작·끝의 사용자 수를 읽어 읽은 행 수와 모두 같고
  같은 사용자를 두 번 읽지 않았을 때만 완전한 목록이다(아니면 `KEYCLOAK_USER_COUNT_MISMATCH`·`KEYCLOAK_LISTING_SHIFTED`로 부분
  수집이라 누구의 부재도 퇴사로 보지 않는다).
  `emailVerified`가 참인 이메일만 쓴다. 관리 이벤트(`include_audit_events`, Realm settings → Events → Admin events settings의
  "Save events", 변경 내용을 보려면 "Include representation")가 있으면 사용자 비활성화·삭제 시각을 쓴다. 관리 이벤트 필터는
  Keycloak 26.2 이상이 필요하다.
  [Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html)
- **Google Workspace**: 서비스 계정 키로 서명한 JWT(`sub` = 위임받을 최고 관리자, 5분 유효)로 `https://oauth2.googleapis.com/token`에서
  토큰을 받는다(키 파일의 `token_uri`는 쓰지 않는다). 먼저 `GET /admin/directory/v1/users/{sub}?fields=isAdmin`으로 최고 관리자인지
  확인한다. 아니면 `GOOGLE_WORKSPACE_ADMIN_NOT_SUPER_ADMIN`으로 실패한다. 일부 조직 단위만 보는 완료 목록은 나머지를 모두
  퇴사로 만들기 때문이다. 이어서 `showDeleted=true`로 20일 안에 삭제된 사용자(`deletionTime`)를, `GET /admin/directory/v1/users?customer=my_customer`로
  고객의 모든 도메인 사용자를 읽는다. 삭제 목록을 먼저 읽으므로 수집 한도가 전체 목록 중간에 걸려도 삭제는 반영된다.
  정지(`suspended`)·보관(`archived`)·삭제가 퇴사 신호이며, 정지 시각은 디렉터리에 없어 처음 정지로 본 수집 시각을 쓴다.
  기본 이메일과 별칭(`aliases`)을 digest로만 남긴다. 위임받는 계정이 정지·삭제되거나 권한을 잃으면 수집이 실패로 끝나
  퇴사 판정이 멈추므로 수집 전용 최고 관리자를 쓴다. 403의 `userRateLimitExceeded`·`quotaExceeded`와 429는 요청 한도로 보고
  다시 시도하며, `accessNotConfigured`는 Admin SDK API를 켜지 않은 것(`GOOGLE_WORKSPACE_API_NOT_ENABLED`)이다. 키 만료·교체와
  연결 해제 절차는 [GCP 공급자](../gcp/README.md#google-workspace-디렉터리-workspace)를 따른다.
  [users.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/list),
  [users.get](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/get),
  [한도](https://developers.google.com/workspace/admin/directory/v1/limits),
  [도메인 전체 위임](https://support.google.com/a/answer/162106)

### GitHub SAML·SCIM 신원 (`github_identity`)

GitHub 로그인만으로는 누구인지 알 수 없어, SAML SSO를 쓰는 조직의 외부 신원(`externalIdentities`: SAML NameID·
SCIM 사용자 이름·이메일과 그 신원을 쓰는 로그인)을 따로 읽는다. GitHub.com·Enterprise Cloud에서는 조직에 설치한 GitHub App의
조직 권한 Members(읽기)로 읽는다(`auth_type=github_app`). 설치 토큰을 받을 때마다 그 조직의 설치를 다시 확인하고 토큰은
`members: read` 하나만 받으며, 발급 목록·금고·노출 검사에 쓰는 App과 같은 App이어도 된다. 조직 소유자의 classic PAT(`read:org`
또는 `admin:org`, SAML SSO 승인, `bearer`·`secret_refs.token`)로도 읽는다. GHE.com과 Enterprise Server에서는 마법사가 사람
목록에 App을 내놓지 않고 API는 `AUTH_METHOD_NOT_FOR_PURPOSES`로 거절한다. Server는 SAML이 인스턴스 단위라 조직 SAML 공급자가
없어, 토큰으로도 조직 SAML 신원을 읽지 못하는 것으로 본다. Server의 인스턴스 SAML은 GitHub이 엔터프라이즈의 SAML로 답하므로
아래 엔터프라이즈 범위로 읽는다(Server 스키마에는 OIDC 공급자가 없어 SAML만 묻는다).
엔터프라이즈 관리 사용자(EMU)이거나 엔터프라이즈에 SAML을 설정해 조직의 SAML을 대신하는 회사와 Enterprise Server는 마법사의 "조직 대신
엔터프라이즈의 SSO 신원 읽기"로 엔터프라이즈 범위(`scopes.kind=enterprise`)만 읽는다(한 수집에 조직과 함께 두지 않는다,
`GITHUB_IDENTITY_ENTERPRISE_SCOPE_ALONE`). 엔터프라이즈의 SAML 또는 OIDC 공급자(`enterprise.ownerInfo`)가 로그인(관리 사용자는
`핸들_단축코드`)마다 IdP가 프로비저닝한 SCIM 사용자 이름·이메일을 알려 주며, 엔터프라이즈 소유자의 classic PAT(`read:enterprise`
또는 `admin:enterprise`, 새 마법사의 조직 목록에는 `read:org`도)가 필요하다(GitHub App으로는 읽을 수 없다). 관리 로그인을 IdP 사용자 이름에서 계산하지 않는다(GitHub의 정규화가 문자를 버려, 계산한
로그인이 다른 사람의 계정일 수 있다).
[GraphQL ExternalIdentity](https://docs.github.com/en/enterprise-cloud@latest/graphql/reference/objects#externalidentity),
[App 설치 토큰](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app),
[EMU 사용자 이름](https://docs.github.com/en/enterprise-cloud@latest/admin/managing-iam/iam-configuration-reference/username-considerations-for-external-authentication)

## 3. 연결 규칙

| 근거 | 출처 | 연결 |
| --- | --- | --- |
| `SAML_NAME_ID`, `SCIM_EXTERNAL_ID` | GitHub SAML·SCIM 신원 | 정확(한 사람에게만 닿을 때, 아래) |
| `EXTERNAL_UID` | GitLab 사용자 `identities[].extern_uid`(관리자 조회, GitHub·Bitbucket 같은 다른 서비스 계정 로그인 제외) | 정확(한 사람에게만 닿을 때, 아래) |
| `IDP_OBJECT_ID` | Azure DevOps Entra 사용자의 `originId`(= Entra ID 객체 ID) | 정확 |
| `VERIFIED_EMAIL` | Atlassian 관리 계정, Notion PAT 생성자, GitLab 기본 이메일, Azure DevOps 메일, SAML·SCIM 이메일(GitHub 신원 규칙을 따른다) | 정확 |
| `PROVIDER_LOGIN` | GitHub 로그인, GitLab 사용자 이름, AWS IAM 사용자 이름 | 후보 |
| 관리자 확정(`OPERATOR_CONFIRMED`) | `POST /api/v1/leavers/links` | 정확 |

- 값은 IdP 쪽의 사용자 ID·로그인·이메일 digest 중 하나와 같으면 맞는다. 이름 유사성은 쓰지 않는다.
- GitHub SAML·SCIM 신원(`github_identity`)은 그 조직·엔터프라이즈를 프로비저닝한 IdP의 사람이다. 어느 IdP인지 알려 줄
  사실(조직 SAML 공급자의 `issuer`·`ssoUrl`, 엔터프라이즈 SAML의 `issuer`, OIDC 공급자의 `tenantId`)은 수집하지 않으므로,
  신원의 값은 다음 두 조건을 모두 채울 때만 자동으로 잇는다.
  - **같은 종류의 값과 맞는다**: SAML NameID는 IdP가 보내도록 설정한 값이라 사용자 ID·로그인·이메일 모두, SCIM 사용자 이름은
    로그인·이메일, SAML·SCIM 이메일은 이메일과만 맞는다. 다른 종류(예: 확인되지 않은 이메일 모양의 Keycloak 사용자 이름)와
    맞으면 후보다.
  - **한 사람에게만 닿는다**: 신원의 값이 둘 이상의 IdP(provider·origin·tenant가 다른 곳) 사람에게 닿고 그 사람들의 이메일이
    서로 다르면(예: Okta가 프로비저닝한 SCIM 사용자 이름 `dana`가 이메일이 다른 Keycloak의 `dana`에도 맞음) 모두 후보로 두고
    관리자가 정한다. 두 IdP에 같은 이메일로 있는 사람은 한 사람이므로(예: SSO 디렉터리와 다른 디렉터리에 같은 업무 이메일)
    둘 다와 잇고, 두 IdP의 상태가 다르면 판정에 `IDP_STATES_DISAGREE`를 붙인다. 관리자가 그 계정에 대해 거절한 사람은 세지
    않으므로, 다른 IdP의 사람을 거절하면 남은 IdP의 사람과 다시 이어진다.
  - 연결한 IdP가 하나뿐이면 그 IdP의 사람과 잇는다. 연결하지 않은 다른 IdP가 GitHub을 프로비저닝하고 짧은 사용자 이름이
    우연히 같으면 잘못 이어질 수 있다. 이를 막으려면 GitHub 신원 수집이 조직·엔터프라이즈의 IdP 발급자를 함께 읽어 IdP 연결과
    비교해야 한다(미구현).
- GitLab의 `extern_uid`도 GitLab에 연결한 외부 로그인(SAML·LDAP·OIDC 등)이 준 값이고 어느 IdP인지 수집하지 않으므로, 위의
  "한 사람에게만 닿는다" 조건을 똑같이 적용한다(NameID처럼 사용자 ID·로그인·이메일 모두와 맞는다). 이때 GitLab이 확인한 기본
  이메일이 따로 정확히 가리키는 사람은 그 이메일로 이어지고, `extern_uid`로만 닿은 사람은 후보로 남는다. 다른 서비스의 계정으로
  로그인한 신원(`identities[].provider`가 `alicloud`·`atlassian_oauth2`·`bitbucket`·`github`·`gitlab`·`salesforce`, 그리고 GitLab이
  없앤 `dingtalk`·`facebook`·`twitter`·`ultraauth`)의 uid는 그 서비스의 계정 ID·사용자 이름이라 쓰지 않는다(Bitbucket 사용자
  이름이 IdP 로그인과 우연히 같아도 잇지 않는다). Google 로그인(`google_oauth2`)의 uid는 계정마다 고유한 Google 계정 ID라
  다른 사람과 우연히 같아지지 않으므로 그대로 쓴다. 대응 담당자 추천
  (`cremore/governance/response_routing.py`)도 GitHub 신원 값을 같은 종류 규칙으로만 맞춘다.
- 한 IdP 안의 두 사람이 같은 값에 맞으면 어느 쪽도 자동으로 잇지 않고 후보로 둔다(GitHub 신원은 종류가 맞는 값만 센다).
  IdP가 보낸 값이 아닌 계정 값(예: Notion PAT 생성자 이메일)에서는 서로 다른 IdP(예: Okta와 Entra ID)가 같은 사람을 가리키는
  것이 정상이며, 한 곳이라도 퇴사로 보면 판정하고 `IDP_STATES_DISAGREE`를 붙인다.
- 한 번 정확히 이어진 연결은 유지한다(`MATCHED`). 퇴사와 함께 SAML 신원이 지워져도 판정이 이어진다.
  잘못된 연결은 관리자가 거절(`REJECTED`)하며, 거절은 다시 후보로 올라오지 않는다. IdP가 하나일 때 이어진 GitHub 신원·GitLab
  `extern_uid` 연결(이 규칙 전에 이어진 것 포함)은 다른 IdP를 연결한 뒤에도 남는다. 그 신원이 이메일이 다른 다른 IdP의
  사람에게도 닿고 그 사람이 활성이면 판정에 `IDP_STATES_DISAGREE`를 붙여 관리자가 확인해 거절할 수 있게 한다. 관리자가 확정한
  연결도 같으며, 닿은 다른 사람을 그 계정에 대해 거절하면 표시가 사라진다.

## 4. 판정

| 판정 | 조건 |
| --- | --- |
| `USED_AFTER_DEPARTURE` | 공급자가 알려 준 마지막 사용 시각이 퇴사 시각 이후 |
| `REVOKED_OR_EXPIRED` | 공급자가 폐기·만료·비활성으로 보고했거나 만료 시각이 지남 |
| `ACTIVE` | 현재 수집에서 공급자가 활성으로 보고 |
| `UNKNOWN` | 상태를 알 수 없음(`PROVIDER_STATE_UNKNOWN`), 관측이 현재가 아님(`ISSUER_OBSERVATION_NOT_CURRENT`), 공급자가 사용자의 모든 자격증명을 나열하지 않음(`PROVIDER_DOES_NOT_LIST_EVERY_CREDENTIAL`, 계정당 한 행) |

**퇴사 시각**은 IdP가 알려 주면 그 값(`PROVIDER_REPORTED`: Okta `statusChanged`, Entra·Google Workspace 삭제 시각), Keycloak 관리 이벤트가
있으면 그 시각(`ADMIN_EVENT`), 없으면 처음 비활성으로 본 수집이 그 사람을 읽은 시각(`FIRST_OBSERVED_DISABLED`) 또는 완전한
목록에서 처음 빠진 수집이 끝난 시각(`FIRST_OBSERVED_MISSING`)이다. 뒤의 두 값은 실제 퇴사보다 이르지 않으므로(실행 도중
지워진 사람도 그 실행이 끝나기 전에 지워졌다) "퇴사 후 사용"을 추정으로 만들지 않는다. 저장된 퇴사 뒤에 다시 활성화한
관리 이벤트가 있으면 그 퇴사는 끝난 것으로 보고 새 퇴사 시각을 쓴다. 상태 이벤트가 없는 IdP(Okta 등)에서 두 수집 사이에
다시 활성화했다가 또 비활성화하면 이를 알 수 없어 앞의 퇴사 시각이 남는다. 이벤트를 쓰지 못한 Keycloak 연결(관리 이벤트를
수집하지 않거나, 아래처럼 최근 실행이 부분 수집이거나 이벤트가 잘린 경우)도 같다.
부분 수집(`PARTIAL`)에서 빠진 사람은 퇴사로 보지 않는다. 완전한 목록은 사용자 목록 보고가 완전함을 증명한
(`proves_completeness`) `COMPLETE` 실행이다. 같은 IdP의 앱 목록 수집(`options.sources=["apps"]`)은 사람을 나열하지 않으므로
그 실행으로는 아무도 퇴사로 보지 않는다. Okta의 SUSPENDED와 DEPROVISIONED, Entra의 비활성과 삭제,
Keycloak의 비활성, Google Workspace의 정지·보관·삭제는 모두 퇴사 신호다.

**목록 읽기**: 평가는 IdP 사람, 발급 자격증명, GitHub SAML·SCIM 신원, IdP 상태 이벤트 목록을 저장소에서 한 번에 1만 행씩
최대 10번(목록당 10만 행) 넘겨 읽는다. 첫 번째 읽기의 전체 건수가 한도를 넘으면 더 읽지 않는다. AWS IAM 인벤토리(schema 1)는
금고 대조 보고의 발급 행으로 들어온다. 보고는 금고 스냅샷과 같은 행 한도(10만)를 나눠 쓰므로, 그 한도가 AWS IAM 수집의
스냅샷을 잘랐거나 발급 행이 한 번에 읽는 양을 넘으면(`COVERAGE_REPORT_LIMIT_REACHED`) 잘린 목록으로 본다. 보고의 다른 곳
(발견 목록, 금고 스냅샷)이 잘린 것은 발급 행과 상관없다.
자격증명·신원 목록이나 그 보고가 한도를 넘거나(`ISSUED_CREDENTIALS_LIMIT_REACHED`, `DIRECTORY_ACCOUNTS_…`, 위 보고) 넘겨 읽는
사이에 바뀌면(`…_CHANGED_WHILE_READ`, 수집이 실행을 저장하는 중), 또는 한 IdP의 사람 목록이 그렇게 잘리면(`IDP_PEOPLE_…`)
그 평가는 `PARTIAL`로 끝나고 연결·판정·티켓을 바꾸지 않는다. 그것들과 마지막 결과(후보, 마지막 점검 시각)는 마지막 완전한
평가 그대로 남고 다음 평가가 다시 읽는다. 잘린 목록에서 사라진 자격증명을 끌어내지 않기 위해서다. 그래도 끝까지 읽은 IdP의
사람 상태는 저장한다(잘린 상태가 30일을 넘기면 수집 이력 정리가 퇴사를 본 실행까지 지워 그 퇴사를 잃기 때문이다). 사람 목록이
잘린 IdP의 사람은 저장된 상태 그대로다. 수집 이력 정리는 그대로 하고, 퇴사자 보존 정리(6절)는 다음 완전한 평가까지 미룬다.
퇴사자가 아직 켜진 자격증명을 남겼는지는 완전한 평가만 알기 때문이다. 넘겨 읽는 사이의 변화는 전체 건수와 중복으로 알아보므로,
이미 읽은 구간에서 한 행이 빠지고 같은 수만큼 뒤에 더해지면 알아보지 못한다(수집은 최근 행을, 정리는 오래된 행을 바꾼다).
IdP 상태 이벤트는 관리 이벤트를 수집하는 연결(`include_audit_events`)마다 가장 최근에 끝난 실행이 완료(`COMPLETE`)일 때
그 실행의 것만 읽는다(Keycloak 수집은 실행마다 조회 기간의 이벤트 전체를 다시 저장한다). 그 실행이 부분 수집이면
(`IDP_EVENTS_NOT_CURRENT`) 또는 이벤트를 다 읽지 못하면(`IDP_EVENTS_…`) 그 IdP의 퇴사 시각을 이벤트 없이 정하고 평가는
계속한다. 잘린 이벤트 기록이나 더 오래된 완료 실행의 기록은 그 뒤의 재활성화를 놓쳐 퇴사 시각을 실제보다 이르게 만들 수
있기 때문이다.
평가 결과(`POST /api/v1/leavers/evaluate`의 응답)와 요약(`GET /api/v1/leavers/summary`)은 `status`(`COMPLETE`·`PARTIAL`)와
`reasons`(`PARTIAL`은 잘린 목록, `COMPLETE`는 퇴사 시각에 쓰지 못한 이벤트)를 담고, worker는 `PARTIAL`을 경고 로그로 남긴다.

각 행에 노출 여부와 금고 대조 판정([범용 금고](EXTERNAL_VAULT.md))을 함께 붙인다. 공급자별 나열 범위는 다음과 같다.

| 공급자 | 사람의 자격증명 | 모든 자격증명을 나열 |
| --- | --- | --- |
| GitHub | 조직이 승인한 세분화 PAT, SSO 승인 자격증명, Enterprise 자격증명 인벤토리 | 아니요(계정 행 `UNKNOWN`) |
| GitLab | 개인 PAT(서비스 계정·봇 제외) | 아니요 |
| Azure DevOps | PAT(PAT Lifecycle 관리 API) | 예 |
| Atlassian | 관리 계정 API 토큰, 관리자 API 키(생성자) | 예 |
| Notion | PAT(생성자), MCP 연결(사용자, 관리자 확정으로만 연결) | 예 |
| AWS | IAM 사용자 액세스 키(IAM 사용자는 IdP와 이어지지 않아 관리자 확정) | 예 |

GCP 서비스 계정 키, Entra 앱 비밀처럼 사람이 아닌 주체의 자격증명은 대상이 아니다.

## 5. 산출

- **이벤트** `identity.credential_orphaned`: 판정이 새로 생기거나 바뀔 때 한 번(이미 꺼진 채 처음 본 것은 보내지 않음),
  한 번에 최대 500건. 사람·계정·자격증명은 내부 참조로만 가리키며 이메일·로그인·IdP 사용자 ID·키 ID를 넣지 않는다.
  형식은 [SIEM 연동](SIEM_INTEGRATION.md)과 [필드 매핑](SIEM_FIELD_MAPPING.md)을 따른다.
- **티켓**: `USED_AFTER_DEPARTURE`(우선순위 CRITICAL, 검토 1일)와 `ACTIVE`(HIGH, 7일) 행마다 `DEPARTED_OWNER` 템플릿
  거버넌스 티켓을 하나 연다(확인 → 공급자 조치 검토 → 서비스 인증 전환 → 사용처 확인 → 후속 일정).
- **AWS 액세스 키 비활성화**: 기존 조치 계획으로만 한다(결정 4). Remediator가
  `POST /api/v1/leavers/orphans/{ref}/action-plans`로 `DISABLE_ACCESS_KEY` 계획(사유 `OWNER_DEPARTED`, 운영 검토 포함)을 만들고,
  다른 Admin이 `/api/v1/action-plans/{id}/approve`로 승인하며, `ACTION_EXECUTION_ENABLED`가 켜진 설치에서만 실행된다(기본 꺼짐).
  다른 공급자는 보고와 티켓까지다.

## 6. 개인정보와 보존

- 저장하는 것: IdP 사용자 ID, 상태, 상태 변경 시각, 이메일·로그인의 keyed digest, 연결된 공급자 계정 ID.
  목록 API는 Analyst 이상, 연결 확정·거절과 즉시 평가는 Admin만 쓴다.
- **사람 정보(2026-09-28 사용자 결정)**: 연결 마법사의 "사람 이름·이메일·부서 보관"(`people_details`, 새 연결 기본 켜짐)이
  수집 레코드의 `options.keep_profiles`가 된다. 켠 연결만 표시 이름·이메일·부서·직함(Okta `displayName` 또는 이름·성,
  `email`·`department`·`title`, Entra `displayName`·`mail`·`department`·`jobTitle`, Keycloak 이름·성과 **검증된** 이메일,
  Google Workspace `name.fullName`·기본 이메일·주 조직의 부서·직함, GitHub SCIM(없으면 SAML)의 이름·첫 이메일)을 256자 안에서
  사실로 남긴다. 자격증명 모양의 값은 버린다. 이 기능 이전에 만든
  연결은 관리자가 연동 설정에서 켜기 전까지 digest만 남긴다. `GET /api/v1/people`(Analyst 이상)은 이 값을 IdP 계정마다 한 행으로
  보여 준다(이메일로 합치지 않는다. 같은 이메일을 가진 다른 계정은 `AMBIGUOUS_EMAIL`로 고를 수 없다). 팀 설치(`AUTH_MODE=oidc`)에서는
  로그인 IdP의 사람만 돌려준다. 상태는 IdP가 마지막으로 알린 것이고, 완전한 목록에서 빠져 퇴사자 점검이 퇴사로 본 사람은
  `DEPARTED`다. 콘솔은 담당자·연락
  대상을 이름·부서로 보여 주고, 담당자 지정 목록에서 퇴사자를 빼며, 메일 연락의 주소를 채운다.
  같은 이유로 schema 2 조회도 사람 목록 수집(용도 `identity_status`)을 Analyst 이상에게만 보여 준다. Analyst 미만에게는
  `GET /api/v2/coverage/inventory`·`/api/v1/search`가 그 사람들을 목록·건수·필터에서 빼고, `GET /api/v2/coverage/events`가 그
  변경(퇴사 등)을 빼며, 항목(`/inventory/{id}`)과 그 수집의 실행·내보내기·비교(`/runs/{id}`·`/export`·`/compare`)는 `403`이다.
  저장된 레코드는 그대로이며 보기만 다르다.
- **보존(결정 13)**: 퇴사 후 `LEAVER_RETENTION_DAYS`(기본 365, 30–3650. Helm `config.operations.leaverRetentionDays`)가
  지나면 사람의 판정·연결·digest를 지우고 참조와 삭제 시각만 남긴다. 그 사람은 IdP가 계속 나열해도 다시 판정하지 않는다.
  다만 조치가 필요한 자격증명(`USED_AFTER_DEPARTURE`·`ACTIVE`)이 남아 있는 동안에는 지우지 않는다. 지우면 열린 문제가
  보이지 않게 되기 때문이며, 그 자격증명이 꺼지면 다음 평가에서 지운다.
- IdP·SAML 신원 수집 이력은 30일(`IDENTITY_RUN_HISTORY_DAYS`)이 지나면 실행·기록째 지운다. 가장 최근 완료 실행은 남긴다.

## 7. API

| Method | Path | Role | 내용 |
| --- | --- | --- | --- |
| GET | `/api/v1/leavers/summary` | analyst | 사람·퇴사자·판정별 수, 후보 수, IdP·SAML 연결 상태, 마지막 평가 시각과 그 `status`·`reasons`, 보존 설정 |
| GET | `/api/v1/leavers/orphans` | analyst | 판정 행. `verdict`·`provider`·`person_ref` 필터, 판정 순 정렬 |
| GET | `/api/v1/leavers/people` | analyst | 상태별 사람(기본 퇴사자)과 연결된 계정, 판정별 수 |
| GET | `/api/v1/people` | analyst | 사람 정보를 보관하는 로그인 IdP 연결의 사람(IdP 계정마다 한 행: 이름·이메일·부서·직함·상태·출처, `person_ref`, 그 계정 하나의 `refs`, `selectable`·`reason`). `q`·`cursor`·`limit`(1–500), 응답 `next_cursor` |
| GET | `/api/v1/leavers/candidates` | analyst | 관리자 확정을 기다리는 후보(퇴사자만). 관리자가 확정·거절한 후보는 다음 평가 전이라도 바로 빠진다(요약의 후보 수도 같다) |
| POST | `/api/v1/leavers/links` | admin | `{account_ref, person_ref, decision: CONFIRMED\|REJECTED}` 감사 기록 |
| DELETE | `/api/v1/leavers/links` | admin | `?account_ref&person_ref` 관리자 결정을 지움 |
| POST | `/api/v1/leavers/evaluate` | admin | 지금 평가 |
| GET | `/api/v1/leavers/orphans/{ref}/action-plans` | analyst | AWS 키의 조치 계획과 정책 |
| POST | `/api/v1/leavers/orphans/{ref}/action-plans` | remediator | AWS 키 비활성화 계획 |

콘솔의 "퇴사자 Credential" 화면(Analyst 이상)은 이 API로 판정별 남은 자격증명, 퇴사자, 연결 후보, IdP 연결 상태를
보여 준다. 사람 이름·부서는 사람 정보를 보관하는 연결의 사람 목록 전체(모든 페이지)에서 `refs`로 찾고, 없으면 IdP 사용자 ID로 보인다. 관리자는
후보를 같은 사람·다른 사람으로 결정하고 "지금 점검"으로 바로 평가한다. 마지막 점검이 `PARTIAL`이면 어느 목록을 끝까지
읽지 못했는지와 함께, 보이는 판정이 마지막으로 끝까지 마친 점검의 결과라고 알린다. 퇴사자의 AWS 액세스 키는 같은 조치 계획
창에서 비활성화만(사유 `OWNER_DEPARTED`) 요청하며, 승인·실행은 "조치 승인" 화면의 일반 절차를 따른다.

## 8. 확인한 범위

합성 검증: IdP 수집기(`okta`·`keycloak`·`entra_id`·`google_workspace`·`github_identity` 테스트: 상태 대응, digest만 저장,
DPoP, 위임 토큰(키 파일의 토큰 주소 무시), 재시도·재개, 커서 검증, GitHub 엔터프라이즈 SAML·OIDC 신원과 관리 로그인, Enterprise Server의
인스턴스 SAML 신원(엔터프라이즈 범위, OIDC를 묻지 않는 쿼리), GitHub App
설치 재확인과 `members: read` 토큰의 조직 SAML 신원·GHE.com·Server에서 App 제외), 공급자 소유자 함수(각 공급자 `owners` 테스트), 엔진(`cremore/identity/leavers_test.py`: 판정 표, 이벤트 edge,
티켓 1회, 완전한 목록에서 빠짐과 그 실행의 끝난 시각, 부분 수집, 같은 IdP 안의 모호함, GitHub SAML 연결과 계정 행, 두 IdP에
닿는 GitHub 신원·GitLab `extern_uid`와 GitLab이 확인한 이메일의 연결 유지·같은 이메일의 한 사람·다른 IdP 사람 거절 뒤 재연결·남은 연결의 IdP 불일치 표시와 종류가 다른 값, 목록 넘겨
읽기·첫 읽기에서 한도 판정·읽는 중 바뀜, 한 IdP의 사람 목록·발급 목록·금고 대조 보고(AWS IAM 행만)가 잘린 `PARTIAL`과 그때의
다른 IdP 사람 저장·보존 보류·이력 정리, 이벤트는 최근 실행이 완료일 때만·이벤트 한도·재활성화 뒤 새 퇴사 시각, IAM 후보 확정·거절, 보존, 이력 정리, IAM 인벤토리→금고
대조→점검 경로), API(`cremore/api/leavers_routes_test.py`: 역할, 감사, 두 사람 승인과 실행 차단).
실서버 확인(2026-09-28): 로컬 Docker의 Keycloak 26.3(HTTPS)에 realm·서비스 계정 client(`view-users`·`view-events`)·사용자를 만들고, 한 명을 비활성화·한 명을 삭제한 뒤 수집기를 실행해 서비스 계정 제외, 페이지 넘김, 관리 이벤트의 `user.disabled`·`user.deleted`, 저장 기록에 이메일·비밀 없음, 엔진의 `ADMIN_EVENT` 퇴사 시각과 `USED_AFTER_DEPARTURE` 판정을 확인했다(확인 뒤 컨테이너·이미지 삭제). 실제 Okta·Entra ID·Google Workspace·GitHub 조직·엔터프라이즈 연동은 실환경 검증 항목이다.
