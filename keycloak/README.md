# keycloak 공급자 소유 영역

퇴사자 점검([docs/LEAVER_CHECK.md](../docs/LEAVER_CHECK.md))에 쓰는 Keycloak 사용자 상태 수집과, 연동할 서비스를 제안하는
렐름 클라이언트 목록 수집([연결 안내](../docs/ONBOARDING.md))을 소유한다.
구현은 `backend/cremore_keycloak_provider/`이고, 공통 수집 엔진(`cremore/identity/idp.py`)이 예산·재개·검증을 맡는다.

| 설정 | 계약 |
| --- | --- |
| provider / edition | `keycloak` / `self_managed` 또는 `cloud` |
| origin, 범위 | 서버 origin, `realm` 범위 하나, `tenant`는 realm 이름. 예전 배포의 `/auth` 접두어는 `options.api_path` |
| 인증 | `oauth_client`: 서비스 계정을 켠 confidential client의 `client_id`·`client_secret`(client credentials, HTTP Basic) |
| 권한 | realm-management `view-users`, 관리 이벤트를 읽으면 `view-events` |
| 조회 | `GET /admin/realms/{realm}/users/count`, `GET /admin/realms/{realm}/users?briefRepresentation=true`(`first`·`max`), 선택 `GET .../admin-events`(`resourceTypes=USER`, `operationTypes=UPDATE,DELETE`, `dateFrom`=`audit_lookback_days` 전, `direction=asc`) |

사용자 목록은 사용자 이름 순 offset 페이지라, 읽는 동안 앞쪽 사용자가 지워지거나 생기거나 이름이 바뀌면 뒤 사용자가 밀리고, 서버는
페이지를 자른 뒤 행을 뺀다(LDAP 연동 렐름에서 LDAP에 없어진 사용자 등). 그래서 짧은 페이지를 끝으로 보지 않고 다음 offset은 한
페이지씩 나아가며 빈 페이지에서 끝낸다. 읽은 행 수가 시작과 끝의 `users/count`(둘 다 서비스 계정 제외)와 모두 같고 같은 사용자를
두 번 읽지 않았을 때만 완전한 목록이다. 아니면 `KEYCLOAK_USER_COUNT_MISMATCH` 또는 `KEYCLOAK_LISTING_SHIFTED`(재개 뒤에 다시 읽은
경우 포함)로 부분 수집이 되어 이번 목록에 없는 사람을 퇴사로 보지 않는다. LDAP에서 지워졌지만 렐름에 남은 사용자가 있으면 목록이
계속 부분 수집으로 끝난다. 같은 실행 중 읽은 위치 앞에서 한 명이 지워지고 뒤에 한 명이 생겨 수가 그대로면 이 검사로도 알 수 없다.

서비스 계정 사용자는 사람이 아니라 뺀다. 이메일은 `emailVerified`가 참일 때만 digest로 남긴다. 마법사의 "사람 이름·이메일·부서
보관"(`people_details`, 기본 켜짐 → `options.keep_profiles`)을 켜면 이름(`firstName`·`lastName`)과 확인된 이메일도 원문으로 남아
담당자·연락 대상 표시와 `GET /api/v1/people`에 쓰인다. 사용자 표현에는 `enabled`가
바뀐 시각이 없어, realm의 관리 이벤트 저장(Realm settings → Events → Admin events settings의 "Save events", 바뀐 내용을 보려면
"Include representation")이 켜져 있으면 비활성화·삭제 이벤트 시각을 퇴사 시각으로 쓴다. 관리 이벤트 조회가 보내는 `dateFrom`(epoch)·
`direction` 필터는 Keycloak 26.2부터 지원하므로 그 이전 서버(예전 `/auth` 경로 포함)에서는 이 옵션을 켜지 않는다
([RealmResource](https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/admin/client/resource/RealmResource.html)).
액세스 토큰(기본 5분)은 만료 전에 다시 받는다.

마법사의 "렐름의 클라이언트 목록을 읽어 연동할 서비스 제안"(기본 꺼짐)은 같은 서비스 계정으로 도는 별도 수집
(`options.sources=["apps"]`, 사람 목록보다 잦지 않게 하루 한 번, 한 번에 50개씩)을 만들고 realm-management `view-clients`가
필요하다(`query-clients`만으로는 빈 목록). Keycloak 26.8.0 이전에는 이 역할에도 클라이언트 시크릿이 응답에 실려 온다(26.8.0부터
`view-clients`만 가진 호출자에게는 가린다. `manage-clients`는 계속 본다. 다른 속성의 마스킹은 공식 안내에 없다,
[업그레이드 안내](https://www.keycloak.org/docs/latest/upgrading/index.html)). 그래서 기본은 꺼짐이고,
`GET /admin/realms/{realm}/clients` 응답의 각 행에서 ID, 클라이언트 ID(SAML은 엔터티 ID), 이름, 사용 여부만 읽어 `installation`
기록으로 남기며 나머지는 저장·기록하지 않는다. 렐름 기본 클라이언트(`account`, `admin-cli`, `realm-management` 등)와, master
렐름이 다른 렐름마다 가진 `<렐름>-realm` 클라이언트는 뺀다. 비밀처럼 보이는 이름은 클라이언트 ID로 대신한다.
권한 점검은 비밀이 없는 공개 클라이언트 `account-console`·`admin-cli`를 클라이언트 ID로 조회해 `view-clients`를 확인한다.
클라이언트 목록을 읽지 못해도 사람 목록 수집은 완전한 수집으로 남는다.

루트에서 `python -m pytest keycloak/backend -q`로 합성 검증을 실행한다. 2026-09-28 로컬 Docker의 Keycloak 26.3(HTTPS)에서
사용자 목록·관리 이벤트 수집과 퇴사 판정까지 실제로 확인했다([퇴사자 점검 8절](../docs/LEAVER_CHECK.md#8-확인한-범위)). 공식 근거: [Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html)
(OpenAPI `openapi.json`, 2026-09-28 확인).
