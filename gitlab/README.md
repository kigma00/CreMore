# gitlab 공급자 소유 영역

신규 온보딩은 배포 형태와 요금제를 인증 전에 선택한다. GitLab.com Free에서는 그룹·프로젝트
액세스 토큰 목록을 제외하지만 Self-Managed Free에서는 제공한다. Free의 유료 감사 옵션·Enterprise
PAT 옵션은 서버에서도 거절한다. 요금제가 기록되지 않은 기존 연결의 의미를 자동 변경하지 않는다.
계정 연결은 저장소 검사를 자동으로 시작하지 않으며 콘텐츠 카드에서 기존 인증과 승인 범위를 재사용한다.
[제품 선택·수집 목적 분리](../docs/EDITION_AND_COLLECTION_ONBOARDING.md)를 따른다.

GitLab 콘텐츠·metadata 및 native 모델 구현을 소유한다. Python 구현과 전용 테스트는 `backend/cremore_gitlab_provider/`에 있다.
공통 플랫폼이 해당 라이브러리 함수를 직접 호출하며 제품의 Python wheel 하나에 함께 설치된다.

콘텐츠 스캔은 고정한 커밋의 트리에서 blob을 id로 읽는다. 탐지 캐시에 있는 blob id는 받지 않고 나머지는 8개까지 동시에
읽는다. GET은 429와 502·503·504를 공통 `bounded_request`의 10초 안에서 다시 시도하며, 쓰기 요청은 다시 보내지 않는다.

이 폴더에는 UI가 없다. 연결 화면은 `backend/`의 onboarding descriptor로 콘솔(`../web/console/`)이 그린다.

독립 CLI(`standalone/gitlab_inventory`)와 그 출력 계약은 2026-09-27 삭제했다. GitLab 수집은 제품 adapter와 공통 worker가 맡는다.

루트에서 `python -m pip install -e ".[dev,gcp]"`로 개발 설치 후
`python -m pytest gitlab/backend -q`로 전용 합성 회귀를 실행한다.
실제 호출은 별도로 지정한 환경·범위에서만 수행한다.

[공통 AGENTS](../AGENTS.md), [팀 지침](../docs/AI_TEAM_CODING_GUIDE.md),
[실제 디렉터리·등록·빌드 경계](../docs/PROVIDER_DIRECTORY_REVIEW.md)를 먼저 읽는다.
UI 작업에는 [web 지침](../web/AGENTS.md)과 설치된 Next 문서도 적용한다.
공통 API·DB·권한·scope·작업 수명·SIEM 계약과 registry는 플랫폼 담당자와 나누어 작업한다.

## 연결 토큰과 역할

연결 토큰은 그룹·프로젝트 액세스 토큰이다(GitLab.com은 Premium·Ultimate에서만 만들 수 있다). GitLab.com Free는 그룹 서비스
계정의 개인 액세스 토큰을, 인스턴스 범위는 관리자의 개인 액세스 토큰을 쓴다. Admin Mode가 켜진 Self-Managed에서는 관리자 API에
`admin_mode` 범위도 필요하다([토큰 범위](https://docs.gitlab.com/security/tokens/access_token_scopes/)). 권한 점검은 범위와 함께
역할을 구성원 정보(`GET /{groups|projects}/:id/members/all/:user_id`)로 확인한다: 그룹은 Owner(그룹 액세스 토큰 목록, 모든
사용자의 감사 이벤트, 자격증명 인벤토리, 그룹 CI 변수 — [그룹 변수 API](https://docs.gitlab.com/api/group_level_variables/)),
프로젝트는 Maintainer(프로젝트 토큰·감사 이벤트·배포 토큰·CI 변수). 대상 조회의 프로젝트 목록은 `membership=true`로 토큰
사용자가 속한 프로젝트만 읽는다(GitLab.com에서 공개 프로젝트 전체를 훑지 않는다).

## 토큰 자동 교체

연결 토큰(그룹·프로젝트 액세스 토큰, 인스턴스 범위는 관리자 PAT)에 `self_rotate`(또는 `api`) 범위가 있으면 CreMore가 만료 전에
스스로 바꾼다(`token_rotation.py`, 플랫폼 `cremore/onboarding/renewal.py`). worker가 하루에 한 번 토큰에 자신을 묻고
(`GET /personal_access_tokens/self`: 만료일·생성일·범위, 아무것도 바꾸지 않음) 수명의 마지막 3분의 1(최대 30일)에 들어서면
[self-rotate](https://docs.gitlab.com/api/group_access_tokens/)(`POST /groups/:id/access_tokens/self/rotate`, 프로젝트는
`/projects/:id/…`, 그 밖은 [`/personal_access_tokens/self/rotate`](https://docs.gitlab.com/api/personal_access_tokens/))로
90일(인스턴스가 거절하면 30일) 토큰을 받는다. 새 토큰은 즉시 봉인되어 모든 소유 레코드가 가리키고, 승인된 검사 범위도 이어지며,
권한 점검을 다시 한다.

GitLab은 교체한 토큰을 즉시 폐기하고, 폐기된 토큰으로 다시 교체하면 같은 계열의 토큰을 모두 폐기한다. 그래서 교체는 시작 전에
표시(`checks.renewal.state = RUNNING`)되고, 교체 직전 토큰이 살아 있는지 먼저 확인하며, 분명한 거절(403·404·405, 허용되지 않는
만료일의 400)만 다른 경로나 짧은 수명으로 넘어간다. 시간 초과·5xx·해석할 수 없는 응답은 이미 교체됐을 수 있으므로
`GITLAB_ROTATION_UNCERTAIN`으로 멈추고, 한 시간 넘게 표시만 남은 시도는 `RENEWAL_INTERRUPTED`가 된다. 둘 다 이전 토큰으로
다시 시도하지 않고 관리자가 새 토큰을 넣을 때까지 기다린다(연동 행이 "확인 필요"가 된다). `self_rotate` 범위가 없으면 권한
점검이 그 항목을 없음으로 보이고, 만료가 다가오면 `GITLAB_SELF_ROTATE_SCOPE_REQUIRED`로 알린다. 토큰 조회 실패와 이 범위 부족
실패는 기록된 실패 시각(`checks.renewal.at`)부터 하루 동안 다시 시도하지 않는다(매시간 같은 실패와 감사 기록을 반복하지 않는다).

## 토큰의 승인형 폐기 (`remediation.py`)

발급 목록에 있는 그룹·프로젝트 액세스 토큰과 배포 토큰은 승인된 조치 계획으로 폐기한다
(`DELETE /{groups|projects}/:id/access_tokens/:token_id`·`/deploy_tokens/:token_id`,
[공급자 자격증명 조치](../docs/PROVIDER_ACTIONS.md)). 개인·서비스 계정 PAT는 Self-Managed·Dedicated의 인스턴스 관리자
연결로만 폐기한다(`DELETE /personal_access_tokens/:id`). GitLab에는 비활성화가 없고 폐기는 되돌릴 수 없다. 조치는 전용
연결(`remediation` 용도: `api` 범위와 그룹 Owner·프로젝트 Maintainer·인스턴스 관리자 역할)로만 하며, 권한 점검은 토큰 자신과
멤버 역할만 읽는다. 실행 전후로 토큰을 읽어(`revoked`·`active`, 폐기된 그룹·프로젝트 토큰은 30일 뒤 404) 확인한다.
GitLab.com 기업 사용자 PAT(그룹 자격증명 관리 API)와 원문 값이 필요한 `/admin/token`은 자동 폐기하지 않는다.

## 발급 인벤토리와 CI 변수 저장소

공식 문서 확인일: **2026-09-25**. 아래 표는 문서상 지원 범위와 제품의 구현 범위를 구분한다.
실제 GitLab 테넌트·버전·라이선스에서 실행한 결과는 아니며 합성 client로 검증한다.
GitLab의 웹 UI `Credentials inventory`가 Ultimate인 것과 개별 REST API의 요금제는 다르다.

| 대상 | 제품 수집 범위 | 공식 API·권한·제약 |
| --- | --- | --- |
| 기존 PAT·그룹·프로젝트·서비스 계정 | 기존 native collector와 명시한 그룹의 하위 그룹/직접 소유 프로젝트 탐색을 유지 | PAT 기본 조회는 수집자 자신의 `user_id`로 제한. 그룹/프로젝트 access·deploy token, 서비스 계정 PAT, trigger, agent 등의 기존 목록 계약 유지 |
| 인스턴스 전체 PAT | 선택한 `instance_pat` | Self-Managed/Dedicated 관리자, `GET /personal_access_tokens`. 별도 `user_id`/active 필터 없이 현재 API 목록을 페이지 수집. 값 재조회 API가 아님 |
| 인스턴스 전체 deploy token | `instance_deploy_tokens` | Self-Managed/Dedicated 관리자, `GET /deploy_tokens`. GitLab.com에서는 지원하지 않음 |
| 인스턴스 사용자 SSH 키 | `instance_ssh_keys` | 관리자에게 승인한 인스턴스의 `GET /users` keyset 발견 후 `/users/:id/keys`. 다음 쪽은 GitLab이 준 `cursor` 링크를 따르며 그 링크가 되풀이하는 false 기본 필터 외의 조건 변경은 거절한다. `/keys?fingerprint=`를 전수 목록 API로 오인하지 않음 |
| 인스턴스 deploy key | `instance_deploy_keys` | Self-Managed/Dedicated 관리자, `GET /deploy_keys`. ID·사용 프로젝트 참조(`projects_with_readonly_access`·`projects_with_write_access`)·공개키 지문 등 메타데이터 |
| GitLab.com 기업 사용자 SSH | `enterprise_ssh_keys` | Premium/Ultimate 그룹 Owner, 확인된 최상위 그룹 `/groups/:id/manage/ssh_keys`. 일반 외부 구성원의 개인 키까지 전수 수집한다고 주장하지 않음 |
| 프로젝트 deploy key | `project_deploy_keys` | 명시적으로 지정한 프로젝트 `/projects/:id/deploy_keys`. key ID·공개키 SHA256·`can_push`는 관측 메타데이터이며 실제 사용 권한 검사 아님 |
| 그룹/프로젝트 CI 변수 | `ci_variables` | 명시한 그룹 `/groups/:id/variables`, 프로젝트 `/projects/:id/variables`. 그룹 Owner, 프로젝트 Maintainer 이상 또는 해당 관리 권한 필요 |

GitLab.com 기업 사용자 PAT와 그룹/프로젝트 통합 토큰 목록은 기존
`include_enterprise_pat`·`include_resource_access_tokens` 설정으로 수집한다.
해당 관리 API는 GitLab.com Premium/Ultimate의 최상위 그룹 Owner용이며 18.7에서 GA가 되었다(Groups API의
Credentials inventory management 절, 2026-10-08 다시 확인). 같은 목록의 웹 화면은 Ultimate 전용이다.
대상 발견은 프로젝트를 `membership=true`로, 그룹을 기본값(관리자가 아니면 `all_available=false`)으로 읽어 토큰 사용자가
속한 것만 받으므로, `/projects` 전체 목록의 offset 한도(50,000)에 닿지 않는다.
키·PAT ID, 토큰 소유자·상태·scope·생성/사용/만료 시각은 해당 API가 실제로 반환한 필드만 저장한다.
추가 source 기록도 native와 같은 `family`·`identity` 사실을 남겨 유형 분류·소유자(관리자 PAT의 `user_id`)·폐기 참조에 쓰인다.
인스턴스 deploy token 목록에는 그룹/프로젝트가 없으므로 폐기 범위를 만들어 붙이지 않는다. `active` 필드가 없는 deploy token은
`revoked=false`·`expired=false`를 모두 보고할 때만 ACTIVE(`PROVIDER_REPORTED`)로 정규화한다. 날짜형 `expires_at`은 그 날짜의
UTC 00:00 만료로 본다([토큰 만료](https://docs.gitlab.com/user/profile/personal_access_tokens/#access-token-expiration)).
만료 전 상태·API에 나열되었다는 사실을 현재 인증 성공이나 서비스 사용 권한으로 바꾸지 않는다.
관리자 PAT 목록에 등장한 bot 토큰을 근거 없이 그룹/프로젝트 토큰으로 재분류하지 않는다.

### 명시적 선택과 승인 범위

`options.sources=[]`이면 기존 native 수집만 실행한다. 새 source 선택은 기존 수집에 추가된다.
관리자 source에는 `edition=self_managed` 또는 `dedicated`와
`scopes=[{"kind":"organization","id":"https://gitlab.example.com"}]`가 필요하다.
scope ID는 설정한 HTTPS origin과 정확히 같아야 한다. `/user`가 매 시도 관리자임을 보고해야
추가 인스턴스 요청을 보낸다. 이 인증은 **설정된 수집자 인증**이며 발견된 토큰을 재사용하지 않는다.
Admin Mode·API scope·서버 정책으로 목록 접근이 거절되면 부분/실패로 남긴다.

새 SSH/deploy-key source는 `public_keys` capability가 필요하다. CI 변수 목록은
`vault_metadata`, 값 지문화는 추가로 `vault_value`와 `options.include_values=true`가 모두 필요하다.
모든 GitLab 연결은 기존 `inventory` capability와 수집자 token 참조를 유지한다.
공급자 연결이 만드는 spec은 GitLab.com 전용 관리 API를 배포 형태·요금제로 고른다. Free가 아닌 GitLab.com 발급 목록은
`include_enterprise_pat=true`(확인된 최상위 그룹에서만 조회), Self-Managed·Dedicated와 GitLab.com Free는
`include_resource_access_tokens=false`다. 그룹·프로젝트의 개별 액세스 토큰 목록은 그대로 읽는다. 직접 만든 spec이
Self-Managed에서 이 옵션을 켜면 `GITLAB_CLOUD_MANAGED_API_ONLY`로 부분 완료가 된다. 이미 저장된 spec의 옵션은 자동으로 바꾸지 않는다.
관리자 전용 연결에서 자신의 PAT를 별도로 수집하지 않으려면 `include_self_pat=false`를 사용한다.

CI 변수와 프로젝트 deploy key는 **직접 명시한 scope만** 읽는다. 기존 native 탐색으로 발견한
하위 그룹/프로젝트의 변수 값은 자동으로 승인되지 않는다. 필요한 하위 범위는 별도로 등록한다.
그룹 변수 목록은 그 그룹에 저장된 변수 정의이며 프로젝트의 최종 상속·override 결과를 재구성하지 않는다.

### CI 변수 값 처리

GitLab의 변수 목록 응답에는 `value`가 포함된다. 따라서 metadata 모드도 공급자에서 값을
수신할 수 있다. 제품은 원문을 일반 기록·checkpoint·로그·native export에 넣지 않고 즉시
분리한다. 기본값은 값 지문화 비활성이다. `masked`는 로그 마스킹, `hidden`은 설정 UI에서의
재표시 제한이므로 API 응답의 값 가용성을 이 플래그만 보고 추론하지 않는다.

명시적으로 값 대조를 선택하면 같은 탐지 엔진/HMAC 키로 메모리 안에서 지문화한다.
값을 외부 GitLab 인증 요청으로 보내거나 token-info·권한 probing을 하지 않는다.
`env_var`와 `file` 모두 저장된 값 내용을 다루며 실행 중 변수 확장 결과는 수집하지 않는다.
공통 탐지기가 식별하지 못하는 불투명 문자열, 값 누락, 빈 값, 인코딩/크기 제한은
`UNRESOLVED`와 이유로 남겨 완전한 값 대조로 오판하지 않는다. 원문 저장 callback은 호출하지 않는다.

변수 식별자는 다음과 같으며 같은 변수명도 환경 범위가 다르면 별개다.

```text
groups/<group-id>/variables/<sha256>
projects/<project-id>/variables/<sha256>
sha256 = stable_id({"key": variable.key, "environment_scope": variable.environment_scope})
```

`stable_id`는 기존 GitLab native의 정렬·compact JSON SHA256이다. 이름·환경은 승인된
metadata 필드로, 비교 지문은 전용 `value_match`로 분리한다. 현재 CI 변수 API는 과거 값 버전
목록을 제공하는 계약이 아니므로 `version=""`, `version_state=CURRENT`로 해당 수집 시점만 표현한다.
API `raw` boolean은 공통 원문 차단 규칙을 유지하기 위해 `variable_raw`로 정규화한다.

### 저장·재개·완전성·출력

`metadata/extensions.py`와 `metadata/variables.py`는 기존 collector에 함수를 연결한다.
별도 서버/DB/스케줄러를 만들지 않으며 동일한 GET transport, origin 검사, 속도/재시도/응답 예산,
페이지 transaction, worker의 원자적 record+cursor commit을 사용한다. SSH 사용자 발견은
각 사용자의 키 조회와 교대로 실행해 모든 사용자를 먼저 checkpoint에 쌓지 않는다.
공통 `max_requests`, `max_pages`, `max_records`, checkpoint 한도를 넘으면 완료로 표시하지 않는다.
기존 `max_targets`는 그룹/프로젝트 탐색 제한이며 인스턴스 사용자 수를 50명으로 자르지 않는다. 발견 페이지가 한도를 넘으면
한도 안의 대상만 저장·예약하고 그 발견 목록을 `GITLAB_TARGET_LIMIT`로 실패 처리한다. 승인한 범위 자신의 토큰 목록·최종
인벤토리·관계·보고는 계속하지만 실행은 `PARTIAL`이며, 재개해도 잘린 발견 페이지를 되풀이하지 않는다. 생략된 대상의 부재는 추론하지 않는다.

CI 변수 지문 계약이 달라지면 기존 실행의 재개를 거절한다. 같은 origin이더라도 수집자 ID가
달라진 재개는 거절한다. 권한 거절·지원되지 않는 최상위 범위·불완전 페이지·값 대조 실패는
빈 성공 목록/삭제 증거가 아니다. 목록에서 더 이상 보이지 않는 자격증명을 폐기되었다고 추론하지 않는다.

기존 native export의 `inventory`와 `compare_records(..., previous_native_inventory)` 계약은 유지한다.
새 source 기록은 native export의 선택적 `supplemental_metadata` 배열에 추가한다.
여기에는 `value_match`·`value_contract`와 원문을 내보내지 않는다. 제품의 run 간 비교는
새 source metadata도 비교하되 지문/값을 diff에 넣지 않고 불완전한 목록의 부재는
`observation_unknown`으로 반환한다.

### 공식 근거

- [PAT REST API](https://docs.gitlab.com/api/personal_access_tokens/): 관리자/일반 사용자의 목록 범위, optional `user_id`.
- [Deploy tokens API](https://docs.gitlab.com/api/deploy_tokens/): 인스턴스 관리자 및 그룹/프로젝트 권한.
- [Groups credentials inventory API](https://docs.gitlab.com/api/groups/#credentials-inventory-management): GitLab.com 요금제·Owner·최상위 그룹·GA 버전·PAT/resource/SSH 목록.
- [Users API](https://docs.gitlab.com/api/users/): `/users`와 keyset pagination, `/user`의 관리 계정 정보.
- [User SSH/GPG keys API](https://docs.gitlab.com/api/user_keys/): `/users/:id/keys` 공개키 목록.
- [Deploy keys API](https://docs.gitlab.com/api/deploy_keys/): 관리자 인스턴스/프로젝트 목록·공개키 지문.
- [Group variables API](https://docs.gitlab.com/api/group_level_variables/), [Project variables API](https://docs.gitlab.com/api/project_level_variables/): 값 포함 응답, 환경별 식별, 변수 종류.
- [CI variable security](https://docs.gitlab.com/ci/variables/#hide-a-cicd-variable): hidden은 설정 페이지 재표시 제한, 17.6 GA.
- [Credentials inventory UI](https://docs.gitlab.com/administration/credentials_inventory/): Ultimate UI와 GitLab.com/인스턴스의 서로 다른 관리 범위.

## 노출 파일의 담당·접근 정보

`context.py`의 `exposure_context`는 노출이 확인된 파일마다 콘텐츠 소스 연결의 token으로 다음을 읽는다(GET만,
요청 20회 예산). 플랫폼의 `finding-context` 작업(`cremore/governance/ownership.py`)이 호출하고 저장은 플랫폼이 맡는다.

- CODEOWNERS: 탐지한 커밋 기준으로 루트 `CODEOWNERS`, `docs/CODEOWNERS`, `.gitlab/CODEOWNERS` 중 처음 있는 파일
  (`GET /projects/:id/repository/files/:path/raw`). 섹션·섹션 기본 담당자를 해석해 파일에 일치한 담당자만 남기며 원문은 저장하지 않는다.
- 마지막 작성자: `GET /projects/:id/repository/commits?path=…&ref_name=…&per_page=1`의 작성자 이름·이메일·시각.
- 접근 가능 인원: `GET /projects/:id/members/all`(상속·초대 구성원 포함, 100명씩 최대 3쪽). 활성 구성원 중
  Guest(10) 이상만 역할과 함께 남긴다. Minimal access(5)는 프로젝트를 열 수 없어 제외한다.

공식 근거(2026-09-28 확인): [Group and project members API](https://docs.gitlab.com/api/members/).

검증 대상에는 관리자/비관리자·페이지와 scope 이탈·예산·원자적 rollback·재개·지문 계약 변경,
hidden/미반환/미식별 값·환경별 식별·legacy snapshot/export/diff 호환을 포함한다.
실제 API 권한·버전·라이선스 조합은 별도 지정된 비운영 테넌트에서 후속 확인해야 한다.
