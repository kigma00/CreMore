# atlassian 공급자 소유 영역

Atlassian Cloud 발급 목록의 `oauth_clients` 선택(기본 해제)은 기존 조직/서비스 계정 OAuth client
수집기를 연결한다. 조직 조회 성공만으로 목록 권한을 추정하지 않고 선택한 각 inventory endpoint를
실제로 점검한다. API/entitlement가 제공되지 않는 조직에서는 실패·미지원 근거를 보존한다.
정규화된 이름·날짜·권한·명시적 생성자는 공통 인벤토리 projection에 전달한다.
세부 지원·검증은 [2026-10-05 재검토](../docs/INVENTORY_METADATA_REVIEW_2026-10-05.md)를 따른다.

Confluence·Bitbucket 콘텐츠 및 Jira/Confluence/Bitbucket 공유 metadata 구현을 소유한다. Python 구현과 전용 테스트는 `backend/cremore_atlassian_provider/`에 있다.
공통 플랫폼이 해당 라이브러리 함수를 직접 호출하며 제품의 Python wheel 하나에 함께 설치된다.

이 폴더에는 UI가 없다. 연결 화면은 `backend/`의 onboarding descriptor로 콘솔(`../web/console/`)이 그린다.

루트에서 `python -m pip install -e ".[dev,gcp]"`로 개발 설치 후
`python -m pytest atlassian/backend -q`로 전용 합성 회귀를 실행한다.
실제 호출은 별도로 지정한 환경·범위에서만 수행한다.

[공통 AGENTS](../AGENTS.md), [팀 지침](../docs/AI_TEAM_CODING_GUIDE.md),
[실제 디렉터리·등록·빌드 경계](../docs/PROVIDER_DIRECTORY_REVIEW.md)를 먼저 읽는다.
UI 작업에는 [web 지침](../web/AGENTS.md)과 설치된 Next 문서도 적용한다.
공통 API·DB·권한·scope·작업 수명·SIEM 계약과 registry는 플랫폼 담당자와 나누어 작업한다.

## 발급 자격증명 metadata 지원과 공식 근거

2026-09-25 공개 공식 문서를 직접 확인했다. 실제 고객 tenant·Data Center 서버 호출은
수행하지 않았으며, 아래 지원은 권한이 있는 관리 수집 연결의 metadata 조회 계약이다.
노출 자격증명을 외부 서비스에 재사용하는 동작은 포함하지 않는다.

| 구분 | 구현 및 근거 | 확인할 수 없는 범위 |
| --- | --- | --- |
| Atlassian Cloud 조직 | [API Access REST](https://developer.atlassian.com/cloud/admin/api-access/rest/api-group-api-token/)의 조직 API 키, 사용자 API 토큰, 서비스 계정 API 토큰·OAuth client, 관련 count·detail을 지원한다. `read:keys:admin`, `read:tokens:admin`, `read:service-accounts-tokens:admin` 등 operation별 권한이 필요하다 | 조직 밖/관리 범위 밖 자격증명, 비밀 원문, 모든 OAuth access-token 인스턴스의 목록이나 현재 인증 가능 여부를 보장하지 않는다 |
| Bitbucket Cloud | [공식 OpenAPI](https://dac-static.atlassian.com/cloud/bitbucket/swagger.v3.json)에 근거한 workspace·repository·키·runner·branch restriction metadata를 유지한다 | 조회 당시 공개 OpenAPI paths에 access-token/credential/password 목록 route가 없다. resource access-token 전체 목록 계약은 미확인이며 내부 API를 추가하지 않는다. branch restriction의 token 참조도 token inventory 전체 목록이 아니다 |
| Bitbucket Data Center 10.4 | [공식 Authentication REST](https://developer.atlassian.com/server/bitbucket/rest/v1004/api-group-authentication/)의 `GET /rest/access-tokens/latest/users/{userSlug}`, `/projects/{projectKey}`, `/projects/{projectKey}/repos/{repositorySlug}` | 승인한 scope 밖 자동 탐색은 하지 않는다. 공식 `RestAccessToken`의 `id`, `name`, `createdDate`만 정규화한다. 만료·마지막 사용·권한·원문 값·현재 활성 상태를 추정하지 않는다 |
| Confluence Data Center | [공식 PAT 문서](https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html)는 7.9+ PAT 및 Data Center 관리자 PAT 화면, 생성 POST를 설명한다 | 관리자 전체 PAT 목록의 공개 REST 계약은 이번 조사에서 확인하지 못했다. UI가 있다는 이유로 비공개 GET을 추측하여 구현하지 않는다 |

Cloud 서비스 계정 목록은 현행 OpenAPI에 `x-preview: true`이며 조직별 Preview 활성화가 필요하다.
조직 OAuth 목록은 `data` + `links` 및 `pageSize`·`cursor`로 문서화되어 있으며 기존 구현이 지원한다.
지원팀이 확인한 최상위 배열 응답도 읽지만 페이지 계약이 미확인이라 `unverified`
(`pagination_contract_unverified`)로 보존한다. OAuth count(`POST oauth-clients/count`)는 발견한
서비스 계정 ID 배열(요청당 최대 100개)로만 요청하고, 요청한 계정의 목록 항목과만 비교한다
(`comparison_scope=requested_service_accounts`). 근거·검증 범위는
[Preview API 계약 반영 기록](../docs/integration/atlassian-preview-contract.md)을 따른다. Native inventory 기본 source는
`admin-api-keys`, `org-api-tokens`, `service-account-api-tokens`다. OAuth까지 수집하려면
`options.sources`에 `service-account-oauth-clients`, `org-oauth-clients`를 포함하거나
관련 discovery mode를 선택한다. 수집 가능한 source와 실제 요청 source를 혼동하지 않는다.

## 연결 흐름과 만료 알림

Confluence·Bitbucket·Atlassian 조직은 인증이 서로 달라(서비스 계정 OAuth, 워크스페이스·HTTP 액세스 토큰, 조직 API 키) 연결은
따로 만들지만, 콘솔은 하나를 마치면 완료 화면에서 나머지를 바로 이어서 연동하게 한다. 만료가 있는 토큰·API 키(최대 1년)는
2단계에서 만든 때 정한 만료일을 받아 모든 소유 레코드에 저장하고, 만료 14일·3일 전에 연동 행과 알림 벨이 알린다
([ONBOARDING](../docs/ONBOARDING.md)의 "토큰 만료일"). 서비스 계정 OAuth는 시크릿에 만료가 없어 날짜를 받지 않는다.

## Confluence Cloud 서비스 계정(OAuth 2.0)

Confluence Cloud 연결의 권장 인증은 조직 [서비스 계정의 OAuth 2.0 자격증명](https://support.atlassian.com/user-management/docs/create-oauth-2-0-credential-for-service-accounts/)이다
(`cloud_api.py`, 인증 방식 `service_account`). 사람 계정에 묶이지 않고, 관리자는 클라이언트 ID·시크릿만 입력한다.

- 시크릿은 봉인되어 저장된다(`auth_kind: atlassian_oauth`, Vault 참조는 받지 않음). worker가 client credentials로
  `https://auth.atlassian.com/oauth/token`에서 60분짜리 액세스 토큰을 받고(`cremore.oauth_client`), 프로세스 안의 모든 검사
  작업(페이지마다 하나)과 권한 점검이 만료 5분 전까지 같은 토큰을 쓴다. 거절(`ATLASSIAN_OAUTH_TOKEN_REFUSED`)과 무응답·429·5xx
  (`ATLASSIAN_OAUTH_UNAVAILABLE`)를 구분하고, 실패한 뒤 1분 동안은 Atlassian에 다시 묻지 않는다. Cloud ID 조회와 토큰 발급도
  검사의 요청 예산에 들어간다. 이 봉투는 Confluence 소스에서만 토큰이 된다(`ATLASSIAN_OAUTH_NOT_FOR_THIS_SOURCE`).
  Atlassian은 서비스 계정 OAuth 시크릿에 만료일을 두지 않으므로([AX-1712](https://jira.atlassian.com/browse/AX-1712))
  갱신 종류는 `AUTOMATIC`이다. 필요 없어지면 Atlassian 관리에서 자격증명을 폐기한다.
- 이 토큰은 사이트 주소가 아니라 API 게이트웨이에서만 받아들여진다
  ([OAuth 2.0 호출 형식](https://developer.atlassian.com/cloud/confluence/oauth-2-3lo-apps/)). 그래서 연결은 사이트 주소
  (`https://acme.atlassian.net/wiki`)를 그대로 두고, 요청할 때 사이트의 Cloud ID(인증 없는
  [`/_edge/tenant_info`](https://support.atlassian.com/jira/kb/retrieve-my-atlassian-sites-cloud-id/), worker 프로세스마다 사이트당 한 번)로
  `https://api.atlassian.com/ex/confluence/{cloudId}/wiki/...`에 보낸다(Cloud ID는 하루 동안 기억). 토큰은 게이트웨이에만 가고,
  사이트에는 Cloud ID 질의만 간다. 주소가 이미 게이트웨이라면 Confluence의 것(`/ex/confluence/{cloudId}/wiki`)만 받는다.
  노출 위치의 식별(`source_instance`)과 링크는 사이트 주소다.
- 권한 점검은 서비스 계정이 가져야 할 범위를 하나씩 읽어 본다: `read:space:confluence`(공간), `read:page:confluence`(페이지
  목록·본문), `read:attachment:confluence`(첫 페이지의 첨부 목록), `read:content-details:confluence`(변경 감지의 CQL 검색과
  작성자 조회). 공간을 볼 수 없으면 404가 오므로 `CONFLUENCE_SPACE_NOT_VISIBLE`로 표시한다. 서비스 계정에 Confluence 앱 접근과
  검사할 공간의 보기 권한이 있어야 한다.
- 기존 `token` 방식은 그대로다: Data Center는 공간 보기 권한만 가진 전용 사용자의 개인 액세스 토큰을 쓴다. Cloud는 토큰을 Bearer로
  보내므로 **서비스 계정**의 범위 지정 API 토큰만 된다(개인 API 토큰은 Basic `이메일:토큰`이라 받지 않는다). 범위는 위의 네 가지이고
  (`read:content-details:confluence`는 로그인 확인의 `/rest/api/user/current`에도 필요), 주소에 게이트웨이 주소
  (`https://api.atlassian.com/ex/confluence/{cloudId}/wiki`)를 넣는다. 실제 Atlassian 조직에서는 검증하지 않았다(합성 서버만).
  근거: [서비스 계정 API 토큰](https://support.atlassian.com/user-management/docs/manage-api-tokens-for-service-accounts/),
  [개인 API 토큰](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/).

## 콘텐츠 스캔과 다시 읽기

- Confluence 페이지 본문의 리비전은 `<페이지 ID>:<버전 번호>`, 첨부는 `<첨부 ID>:<버전 번호>`다. 버전이 같으면 탐지 캐시가
  답하므로 다시 검사하지 않는다(첨부는 내려받지도 않는다). 버전 번호가 정수가 아니거나, 버전을 올리지 않고 본문을 바꾸는
  Cloud 라이브 문서(`subtype: live`)면 본문을 매번 검사한다. Data Center 첨부 목록은 기본으로 버전을 주지 않아
  `expand=version`으로 첨부 자신의 버전을 받는다. 첨부 버전이 없는 행은 캐시하지 않고 매번 검사한다.
- Confluence 변경 감지는 CQL `space = "<공간 키>"`로 찾는다(CQL `space` 필드는 공간 키만 받는다). Cloud 연결은 공간 ID를
  저장하므로 조회마다 `GET /wiki/api/v2/spaces/{id}`(`read:space:confluence`)로 키를 먼저 읽고, 키가 없으면
  `CONFLUENCE_SPACE_MALFORMED`로 그 조회를 실패시킨다. Data Center는 저장한 공간 키를 그대로 쓴다.
- 첨부는 8개까지 동시에 내려받는다. 요청마다 연결의 사이트 주소(서비스 계정은 게이트웨이)와 context path로 주소를 만들고,
  응답의 `_links.base`는 따르지 않는다. 서비스 계정 토큰이 만료되면 동시에 읽는 중에도 한 번만 발급받는다.
- Cloud 첨부는 v2 `downloadLink`(`/download/attachments/...`, 토큰 요청은 [CHANGE-2735](https://developer.atlassian.com/cloud/confluence/changelog/#CHANGE-2735)로
  제거됨)가 아니라 문서화된 REST 다운로드
  [`GET /wiki/rest/api/content/{pageId}/child/attachment/{attachmentId}/download?version=`](https://developer.atlassian.com/cloud/confluence/rest/v1/api-group-content---attachments/)로
  읽는다(`read:attachment:confluence`). 이 요청은 302로 바이트가 있는 주소를 알려 준다. redirect는 최대 2번, https만 따르고
  사용자 정보가 든 주소나 호스트 없는 주소는 `CONFLUENCE_DOWNLOAD_REDIRECT_INVALID`, 2번을 넘으면
  `CONFLUENCE_DOWNLOAD_REDIRECT_LIMIT`로 그 첨부만 읽지 못한 객체가 된다. 토큰은 사이트(서비스 계정은 게이트웨이)와 같은
  origin에만 보내고, 한 번 다른 origin으로 나가면 이후 요청에는 다시 붙이지 않는다. 사이트 밖으로 가는 redirect는 443 포트이고
  이름이 푼 모든 주소가 공인 주소(`cremore.network_addresses`: loopback·link-local·메타데이터·사설·CGNAT 거절)일 때만 따르며,
  확인한 주소로 고정해 연결한다(URL은 주소, Host 헤더와 TLS 서버 이름은 이름). 아니면 `CONFLUENCE_DOWNLOAD_ADDRESS_REFUSED`로
  아무것도 보내지 않는다. 고정 연결은 프록시를 우회하지 않으므로 프록시가 있으면 프록시가 그 주소로 연결한다.
  실제 Atlassian 사이트의 redirect 대상은 검증하지 않았다(합성 서버만). Data Center는 기존대로 같은 사이트의
  `_links.download`를 읽는다.
- Bitbucket 파일 목록에는 blob id가 없어 리비전은 커밋이다. 완전히 끝난 실행은 `provider_state`에 읽은 head(`commit`),
  마지막 전체 읽기의 커밋(`base`), `base`와 다른 리비전을 가진 파일(`revisions`)을 남긴다. 다음 DELTA 실행은
  그 commit과 지금 head의 diff(Cloud `diffstat`·`merge-base`, Data Center `changes`, 최대 20쪽)에 없는 파일의 리비전을
  그대로 두어 내려받지 않고, diff에 나온 파일만 읽는다. BASELINE·RECONCILE(전체 스캔)은 diff를 믿지 않고 모든 파일을 head로
  읽어 새 `base`를 시작하므로, Data Center가 `page.max.changes`에서 알리지 않고 자른 변경 목록도 다음 전체 스캔에서 바로잡힌다.
  목록은 항상 전체를 읽으므로 사라진 파일의 노출 정리는 그대로다. 상태가 없거나 손상됨, 저장된 커밋이 없음, 히스토리
  재작성(force push), diff 실패·잘림·쪽 한도 초과, 경로 없는 diff 항목, 상태가 48 KiB를 넘음 중 하나라도 있으면 DELTA도
  모든 파일을 head로 읽고 새 `base`를 시작한다. 변경 감지도 같은 diff와 쪽 한도를 쓴다.
- git은 허용하지만 검사 경로 규칙이 받지 않는 파일 이름(백슬래시·제어 문자·1,024자 초과)은 읽지 않은 객체로 세고
  저장소의 나머지 파일은 검사한다. diff에 그런 이름이 있으면 변경 감지는 `BITBUCKET_PATH_UNSUPPORTED`로 저장소 전체를
  다시 읽게 한다(피드 전체를 실패시키지 않는다).

## 노출 위치의 마지막 작성자

플랫폼의 `finding-context` 작업(`cremore/governance/ownership.py`)이 콘텐츠 연결의 자격증명으로 호출한다(GET만).

- Confluence(`confluence_context.py`): 연결한 space 안의 페이지만. Cloud는 페이지(`GET /wiki/api/v2/pages/{id}`)나
  첨부(`GET /wiki/api/v2/attachments/{id}`, 그 페이지의 첨부여야 함)의 현재 버전 `authorId`·`createdAt`과 그 계정의
  표시 이름·(공개된 경우) 이메일(`GET /wiki/rest/api/user?accountId=`), Data Center는 `?expand=version`의 작성자.
- Bitbucket(`bitbucket_context.py`): 연결한 workspace(Cloud)·project(Data Center) 안에서 스캔한 커밋 기준으로 그 경로를
  마지막으로 바꾼 커밋 하나. Cloud `GET /2.0/repositories/{workspace}/{repo}/commits/{commit}?path=&pagelen=1`,
  Data Center `GET /rest/api/1.0/projects/{project}/repos/{repo}/commits?path=&until=&limit=1`.
- 두 제품 모두 CODEOWNERS를 읽지 않는다. Bitbucket 저장소 권한 목록은 저장소 관리자 권한이 필요하고 직접 부여된
  사용자만 담아 접근 가능 인원으로 쓰지 않는다.

## Bitbucket Data Center 수집 계약

공통 schema 2에서 `provider=bitbucket`, `edition=data_center`, `options.mode=inventory`,
`capabilities=[inventory]`, bearer 수집 연결을 사용한다. `origin`은 HTTPS origin만 저장하고,
설치 context path는 별도 `options.api_path`(기본 빈 문자열, 예: `/bitbucket`)로 설정한다.
path는 `/[A-Za-z0-9_-]+`의 반복만 허용하며 percent escape·query·traversal은 거절한다.
`scopes`는 `user`의 userSlug, `project`의 projectKey, `repository`의 `projectKey/repositorySlug`다.
scope의 경로 구성요소도 제한된 단일 segment로 검증하며 Cloud 연결은 `api_path`를 거절한다.

[HTTP token 관리 문서](https://confluence.atlassian.com/bitbucketserver/http-access-tokens-939515499.html)에
따르면 프로젝트·저장소 토큰은 Data Center 라이선스와 해당 관리 권한이 필요하다.
목록 REST도 조회 대상에 대한 권한 부족/인증 실패 시 401, 대상 부재 시 404를 문서화한다.
수집 주체의 권한과 scope를 실제 설치 환경에서 검증해야 하며, 관리자 토큰 하나로 모든 사용자·프로젝트가
항상 열람된다고 가정하지 않는다. DC 10.4 외 버전의 호환성은 실환경에서 미검증이다.

`metadata/bitbucket_dc.py`가 HTTP 조립·정규화·cursor·레코드 검증을 소유하고 기존
`metadata/adapter.py`는 edition을 판별해 import한 함수를 호출한다. 공통 runtime·DB·worker를
재사용한다. 외부 redirect를 따르지 않으며, `nextPageStart` 정수만 다음 요청에 사용한다.
페이지·요청(재시도 포함)·레코드·응답 byte·시간 예산과 취소 검사를 적용한다. transport의
기존 최대 1 MiB 응답/120초 attempt/1,000요청/1,000페이지/100,000 entity 제한을 넘기지 않는다.
더 작은 설정값도 적용한다. 저장할 entity와 진행 cursor를 같은 page로 반환한 뒤 다음 요청을 수행한다.
재시작은 공통 저장소에서 확정한 cursor·레코드로 이어가며, 설정/context path가 바뀐 checkpoint는 거절한다.

`createdDate`(ISO 문자열 또는 REST 참조 예시의 epoch 밀리초 정수)는 `created_at` UTC로 정규화하고 누락/null/잘못된 값은 구분한다.
비밀 필드·미문서 필드는 저장하지 않으며 token metadata ID만으로 평문 토큰과의 정확한 값 일치를
선언하지 않는다. 오류·권한 부족·중복 ID·잘못된 pagination·예산 초과는 partial/failed 근거로 보존한다.
성공해도 선택 scope의 조회 완료만 뜻하며 `proves_completeness=false`, 상태 `UNKNOWN`을 유지한다.

DC typed record 저장·공통 typed export·일반 전체 재수집을 지원한다. `format=native`는 저장된
canonical records를 포함한 `bitbucket_dc_http_token_snapshot`을 scope별로 반환한다.
이는 원본 HTTP 응답 복원이나 Cloud snapshot이 아니며 비밀값·추정 상태를 추가하지 않는다.

실행 비교는 같은 설치·context path·tenant 경계의 관측을 시간순으로 비교한다. 기존 공급자
비교 함수를 재사용해 `first_observed`, `metadata_changed`, `not_observed`,
`observation_unknown`, `metadata_unknown`을 반환한다. `not_observed`는 선택 scope의
정상 수집에서 이번에 보이지 않았다는 뜻이며 삭제·폐기 증거가 아니다. 실패·부분 수집,
중복 ID·불완전 레코드·미선택 scope는 부재를 확정하지 않는다. 값 대신 변경된 필드 경로를 반환한다.

공통 collect API의 `retry_from_run`, 선택 `scope_id`·`operations`로 실패/부분 operation만
재수집할 수 있다. `include_unverified`는 명시적으로 불확실한 관측도 대상으로 허용한다.
계획은 승인 scope·고정 endpoint에 다시 바인딩하며 선택 범위를 첫 페이지부터 읽는다.
재시작 checkpoint는 계획 지문도 검증한다. 비선택 scope에는 `NOT_REQUESTED` 보고서를 남기고
기존 인벤토리 관측을 유지하며, 연결 전체를 다시 읽지 않은 실행은 `PARTIAL`로 완료한다.
재수집 대상이 없으면 요청을 거절하고 외부 호출을 하지 않는다. `scope_id`가 user/project 등에서
중복되면 모호한 선택을 거절한다. descriptor의 DC native export·compare·recollect는 지원 상태다.

`metadata/bitbucket_dc_replay.py`가 canonical replay·DC 비교/재수집 계획을 소유한다.
기존 Cloud의 입력·출력 형식과 공통 runtime·API·DB 계약은 유지한다.

2026-09-25 DC 목록 최초 구현의 isolated worktree/Windows 합성 검사:
`python -m pytest atlassian/backend cremore/coverage/collector_runtime_test.py -q`에서
281 passed, 57 skipped, 240 subtests passed였다(DC 검사 33개 및 공통 runtime 포함).
57 skip은 기존 native CLI private-file의 POSIX `O_NOFOLLOW`·uid 검사로 Windows에서 수행할 수 없는 항목이다.
변경 Python Ruff 통과. 실제 SaaS 인증·실서버 권한·실제 token 값 매핑은 이 결과로 검증되지 않는다.

같은 날 DC replay·선택 재수집 후 main/Windows에서
`python -m pytest atlassian/backend cremore/coverage/collector_runtime_test.py cremore/api/metadata_comparison_test.py -q`
결과는 **310 passed, 57 skipped, 240 subtests passed**였다. 위 POSIX 전용 skip 사유는 동일하다.
DC 새 회귀는 canonical native export, 시간·설치·tenant·scope 경계, 불완전/중복 관측 비교,
선택 재수집의 예산·취소·동일 계획 재시작, 비선택 인벤토리 유지와 실제 공통 API 경로를 검증한다.
변경 Python Ruff와 `git diff --check -- atlassian`도 통과했다. 실제 계정 호출은 하지 않았다.
