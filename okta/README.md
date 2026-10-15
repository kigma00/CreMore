# okta 공급자 소유 영역

퇴사자 점검([docs/LEAVER_CHECK.md](../docs/LEAVER_CHECK.md))에 쓰는 Okta 사용자 상태 수집과, 연동할 서비스를 제안하는
조직 앱 목록 수집([연결 안내](../docs/ONBOARDING.md))을 소유한다.
구현은 `backend/cremore_okta_provider/`이고, 공통 수집 엔진(`cremore/identity/idp.py`)이 예산·재개·검증을 맡는다.
이 폴더는 인증과 한 페이지 조회, 사용자·앱 한 행의 변환만 가진다.

| 설정 | 계약 |
| --- | --- |
| provider / edition | `okta` / `cloud` |
| origin, tenant, 범위 | 조직 URL(`https://acme.okta.com`), `tenant`와 `organization` 범위는 그 호스트 |
| 인증 | `private_key_jwt`: 서비스 앱의 `client_id`와 개인키. 연결 마법사의 권장 방식(`made_key`)은 CreMore가 키를 만든다(아래). 관리자가 Okta에서 만든 키(PEM, 또는 `kid`가 있는 JWK)를 넣을 수도 있다. scope `okta.users.read`만 요청 |
| 조회 | `GET /api/v1/users`에 모든 상태를 포함하는 `filter`, `limit`(최대 200), `Link` rel="next"의 `after`(같은 호스트·경로만) |
| DPoP | 서비스 앱이 요구하면 첫 거절(`invalid_dpop_proof`·`use_dpop_nonce`)을 보고 실행마다 만든 키로 증명을 붙인다 |

### CreMore가 만드는 키(`made_key`)

관리자는 [API 서비스 앱](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/)의 클라이언트 ID만
넣고 "키 만들기"를 누른다. `onboarding.generate`가 2048비트 RSA 키를 만들어 개인 JWK(`kid` 포함)는 즉시 봉인하고, 화면에는
공개 JWK(`kty`·`e`·`n`·`kid`·`alg`·`use`)만 남긴다(`target.generated`). `kid`는 공개 키의 RFC 7638 지문이다. 관리자는 앱의
General → Client Credentials → Public key / Private key → Add key에 이 공개 키를 붙여 넣고(Okta는 붙여 넣는 키에 고유 `kid`를
요구한다), Okta API Scopes에서 `okta.users.read`를 승인하고, Admin roles에서 사용자 보기만 있는 역할(사용자 정의 역할:
View users and their details, 모든 사용자)을 준다. 사용자 정의 역할을 쓸 수 없으면 Read-only Administrator를 준다. 개인 키는
관리자 화면·클립보드를 거치지 않는다. 키에는 만료가 없고 액세스 토큰은 읽을 때마다 받는다. 키를 다시 만들면 새 공개 키를
붙여 넣을 때까지 로그인이 거절된다(`OKTA_TOKEN_REFUSED`). Okta는 이전 키를 비활성화·삭제할 때까지 유효하게 두므로, 다시 만든
연결은 이전 키의 `kid`를 `target.generated.previous`에 남겨 마법사가 지울 키를 알려 주고, 감사 기록에 두 `kid`가 남는다.

매칭에 쓰려고 남기는 것은 사용자 ID, 상태, `statusChanged`, 로그인·이메일의 keyed digest다. 마법사의 "사람 이름·이메일·부서
보관"(`people_details`, 기본 켜짐 → `options.keep_profiles`)을 켜면 표시·연락용으로 이름(`displayName` 또는 이름·성), 이메일, 부서,
직함도 원문으로 남아 `GET /api/v1/people`에 쓰인다(매칭에는 쓰지 않는다). 끄면 원문 이메일·이름은 저장하지 않는다. 자격증명 정보는
저장하지 않으며 `okta-response=omitCredentials`로 응답에서도 뺀다. 머신 제출 경로로는 기록을 받지 않는다.

### 앱 목록(연동 제안)

마법사의 "조직의 앱 목록을 읽어 연동할 서비스 제안"(기본 꺼짐: 사람 목록에 없는 권한이 든다)은 같은 서비스 앱으로 도는 별도 수집
(`options.sources=["apps"]`, 사람 목록보다 잦지 않게 하루 한 번)을 만든다. 이미 있는 연결은 저장한 계획에서 이 옵션을 켜면 그때
수집이 생긴다. 그 수집의 토큰은 `okta.apps.read`만 요청하고, `GET /api/v1/apps`를 상태마다(`status eq "ACTIVE"`,
`status eq "INACTIVE"`) 한 번씩 읽어 앱마다 ID, 레이블, 카탈로그 이름(`name`: `slack`, `amazon_aws`), 상태만 남긴다
(`installation` 기록, 사람이 아니다). 행의 `credentials`·`settings`는 읽지 않고, 같은 범위로 열리는
`/api/v1/apps/{id}/credentials/secrets`는 부르지 않는다. 권한은 Okta API Scopes의 `okta.apps.read`와, 관리자 역할에 앱 보기
("View applications and their details", 모든 앱) 권한을 더한 사용자 정의 역할이 가장 좁다. "View client credentials"는 주지 않는다.
앱 목록을 읽지 못해도 사람 목록 수집은 완전한 수집으로 남는다(퇴사 판정이 그것에 기댄다). 퇴사 판정은 사용자 목록이 완전했음을
증명한 실행에서만 빠진 사람을 떠났다고 보므로, 사람 목록 수집을 앱 목록으로 바꿔도 아무도 떠난 것으로 바뀌지 않는다. 근거:
[Apps API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Application/),
[관리자 권한](https://developer.okta.com/docs/api/openapi/okta-management/guides/permissions/).

루트에서 `python -m pytest okta/backend -q`로 합성 검증(`httpx.MockTransport`)을 실행한다. 실제 Okta 조직 연동은
실환경 검증 항목이다. 공식 근거: [Users API](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/),
[서비스 앱 OAuth](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/),
[DPoP](https://developer.okta.com/docs/guides/dpop/oktaresourceserver/main/).
