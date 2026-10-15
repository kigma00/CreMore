# 동일 로그인 IdP 기반 대응 담당자 지정

2026-10-03. 검색·추천·명시적 책임 규칙과 발송 신원 재확인의 구현 계약이다.
발견 위치의 접근 대상은 별도 [위치 접근 근거](EXPOSURE_ACCESS.md)이며 자격증명 소유자나 대응 담당자와 같다고 추정하지 않는다.

## 동작

발견 자격증명 상세에서 **근거가 있는 추천 → 같은 로그인 IdP 검색 → 담당자 선택**으로 대응자를 지정한다.
OIDC 로그인 토큰만으로 직원 전체를 얻지는 못한다. 같은 IdP의 사람 목록 연결과 읽기 권한,
`people_details`/`keep_profiles`를 통한 표시 프로필 보관 선택이 필요하다.

`identity/people.py`는 공급자·origin·tenant·IdP 사용자 ID에 고정된 `person_ref`를 사용한다.
이름이나 이메일로 다른 계정을 합치지 않는다. 검색은 `db/people_directory_store.py`의 projection에서 수행한다.
metadata 완료와 projection을 같은 트랜잭션으로 저장하며 이름·이메일·부서 검색과 snapshot에 묶인 keyset cursor를 제공한다.
화면은 25명씩 읽고 250ms 검색 지연·요청 취소·늦은 응답 무시·키보드/초점·overlay를 지원한다.
처음 500명 밖의 사람도 검색할 수 있으며 디렉터리 revision 변경 시 오래된 cursor는 거절한다.

팀 설치는 현재 로그인 IdP와 일치하는 활성 공급자 연결의 허용 대상만 조회·발송한다.
GitHub SAML/SCIM 연결은 발급 소유자 매칭 근거로 사용할 수 있지만 로그인 IdP 사람 목록을 대신하지 않는다.
담당자 선택·발송에는 24시간 이내의 최신 완전 수집, 활성 상태, 유일한 연락 이메일이 필요하다.
중지·기능 일시중지·대상 변경·미수집·부분/실패 수집·오래된 프로필·중복 이메일은 이유와 함께 차단한다.
발송 주소는 서버가 `person_ref`에서 해석하고 예약 트랜잭션에서도 재확인한다(티켓 플러그인 경로는 티켓 시스템 조회 뒤에도).
브라우저가 보낸 다른 이메일은 거절한다. 이미 발송한 요청 UUID의 재시도는 재발송하지 않는다.

## 추천과 명시적 책임

`governance/response_routing.py`는 외부 호출 없이 기존 발급 상관분석과 소유자 함수를 재사용한다.

1. 명시적으로 배정한 담당자는 재수집이 덮어쓰지 않는다.
2. 최신·완전한 정확한 발급 관측의 소유 계정과 IdP의 확정 근거가 일치하면 추천한다.
3. GitHub 사용자명은 같은 origin의 최신 조직 SAML/SCIM·EMU 근거로 연결한 뒤 대조한다.
4. 서비스계정·앱 또는 확정 소유자가 없는 경우, 관리자가 현재 발견 위치/발급 계정에 책임 담당자·팀 규칙을 저장할 수 있다.
5. 여러 신원에 겹치는 확정 키, 사용자명 후보, 생성자·이름 유사성은 단일 자동 추천으로 승격하지 않는다.
   활성 사용자와 비활성 사용자 사이의 충돌도 모호성이다. 대조 키 부재·후보 한도는 수동 선택을 막지 않는다.

확정 근거는 기존 `SCIM_EXTERNAL_ID`, `SAML_NAME_ID`, `EXTERNAL_UID`, `IDP_OBJECT_ID`, `VERIFIED_EMAIL`과
관리자가 확인한 매핑을 재사용한다. 과거 자동 `MATCHED` 기록은 현재 근거를 대신하지 않는다.
`REJECTED`는 추천에서 제외한다. 책임 팀은 명시적 표시 값이며 IdP 그룹이나 그룹 수신자로 변환하지 않는다.
위치 규칙은 source 연결과 resource에 고정되어 같은 이름의 다른 연결에 적용되지 않는다.

배정·책임 규칙은 기존 settings 잠금·버전 검사와 같은 트랜잭션의 감사 기록을 쓴다.
추천 자체는 발송이나 폐기 승인이 아니다. 대응 요청 회차는 당시 사람 참조·프로필·팀·매핑 근거/시각과
보내는 방법·응답자 참조를 보존한다. `Okay`는 완료 진술이며 이후 비교 가능한 완전 스캔만 제거를 확정한다.
기존 키 조치의 독립 승인·발송 불명확 상태·멱등성·감사 계약은 유지한다.

## 공급자별 소유자 근거

등록은 `coverage/providers/__init__.py`의 `owners`, schema 1은 `coverage/models.py::V1_OWNERS`를 따른다.
아래 확정 조건을 충족하지 못하는 공급자도 동일 IdP 검색과 명시적 책임 규칙은 사용할 수 있다.

| 공급자·종류 | 현재 근거 | 확정 가능한 조건·제약 |
| --- | --- | --- |
| AWS IAM access key | IAM user ARN, account ID, 사용자 이름 | `PROVIDER_LOGIN` 후보다. 명시적 관리자 매핑이 필요하며 CloudTrail 생성자를 소유자/대응 담당자로 대체하지 않음 |
| GitHub 개인 토큰 | owner login | login은 후보. 별도 GitHub identity의 조직 SAML/SCIM 또는 EMU 외부 ID로 회사 IdP와 확정 대조 가능(SAML NameID는 IdP 사용자 ID·로그인·이메일, SCIM 사용자 이름은 로그인·이메일, 이메일은 이메일과만 맞춘다). App·봇 제외 |
| GitLab 개인 PAT | user ID, profile external UID·확인된 이메일 | `EXTERNAL_UID`/`VERIFIED_EMAIL` 근거를 수집한 경우 확정 대조. username은 후보. 봇·서비스계정·project/group token 제외 |
| Notion Enterprise PAT | creator ID·제공된 이메일 | 이메일 capability와 확정 이메일 근거 필요. ID만 있으면 명시적 매핑. 개인 플랜의 integration token과 별도 기능 |
| Notion MCP 연결 | user ID | 현재 매칭 키 없음. 운영자 명시 매핑 필요 |
| Atlassian 관리 계정 API token | user ID·email | 검증된 조직 도메인 계정의 이메일로 확정 대조. admin API key 생성자와 개인 소유를 구별하고 서비스계정 제외 |
| Azure DevOps PAT | AAD origin ID·Graph email | `IDP_OBJECT_ID`(Entra) 또는 확인 이메일 근거. Server/기타 origin 이메일은 후보 |
| GCP 서비스계정키·Azure Entra 앱/서비스주체·ARM·Key Vault | 현재 owners 미등록 | 기계 계정/프로젝트/앱→담당자·팀 명시 규칙 필요. 생성자·앱 소유자가 현재 대응 담당자임을 추정하지 않음 |
| Slack·Bitbucket 전용 발급 목록·Vault/OpenBao | 현재 owners 미등록 | 현재 사람 자동 대조 미지원. 발급 대상·서비스·업무 팀의 관리자 확인 매핑부터 필요 |
| Okta·Entra·Keycloak·Google Workspace 사람 목록 | IdP 고유 사용자 ID·HMAC 매칭 키·선택 프로필 | 티켓 후보의 기준 디렉터리다. 디렉터리 수집과 앱 목록 수집·로그인 자체는 별개 |
| 웹사이트 등 발견 위치 | 콘텐츠 위치·작성자·접근 근거 | 다른 공급자 자격증명의 발급자/소유자를 위치만으로 결정하지 않음 |

현재 구현 근거 파일은 `aws/backend/cremore_aws_provider/leavers.py`, GitHub·GitLab·Notion·Atlassian의
`metadata/owners.py`, Azure의 `devops_tokens/owners.py`와 `identity/keys.py`, `identity/leavers.py`다.
팀 후보는 소유자 개인 계정과 별개 계약이며, IdP 부서 이름이나 CODEOWNERS 문자열만으로 그룹 수신자를 만들어내지 않는다.

## 기존 설치의 업그레이드

새 additive projection은 원본 metadata record/entity에 연결한다. 원본 record 보관 기간 정리 시 같이 제거되며,
프로필 보관을 끄거나 연결 대상이 바뀌면 과거 프로필을 검색/발송에 사용하지 않는다. 매칭 digest는 공개 응답에 포함하지 않는다.
기존에 보관한 프로필을 검색 projection에 반영하려면 새 버전/스키마에서 다음을 실행한다.

```sh
python -m cremore.identity.people --rebuild
```

이 명령은 이미 보관한 opt-in 프로필만 재구성하며 외부 공급자를 호출하지 않는다.
원본 사람 수집이 없으면 새로 디렉터리를 연결·수집해야 한다. 기존 임의 이메일 배정은 자동으로 신원에 변환하지 않는다.
로컬 1인 설치는 기존 이메일 발송 호환 경로를 유지한다.

## 검증과 한계

사람 목록은 서버 worker가 연결의 `schedule_minutes`에 따라 갱신한다. 신규 Okta 연결의 기본은
5분이며 기존에 지정한 주기는 유지한다. 담당자 배정·퇴사자 화면과 담당자 선택 메뉴에 마지막 수집,
자동 주기, 대기/수집 상태와 **지금 갱신**을 표시한다. analyst 이상은 기존 metadata 수집 API로
갱신을 요청하고, 관리자는 **자동 갱신 설정**에서 기존 연결 계획의 주기를 변경한다(0은 수동).
자동/수동 수집은 같은 연결 잠금과 활성 작업 확인으로 중복을 막으며 주기 변경은 revision을 검사한다.
화면 자동 갱신은 저장된 결과만 읽는다. 5분은 작업 예약 간격이며 API 제한·대기 작업·실패에 따라
완료가 늦어질 수 있다. 선택적 Okta 앱 목록 수집의 최소 하루 간격은 별도로 유지한다.

`identity/people_directory_test.py`, `governance/response_routing_test.py`와
`response_routing_integration_test.py`는 tenant/issuer·중지/재개·부분/오래된 수집·500명 이후 검색·cursor·동명이인·
중복 이메일/신원·보관 기간·동시 변경·발송 직전 재확인을 검사한다.
통합 검사는 실제 수집 저장 계약을 통해 GitHub 지문→SAML/SCIM→IdP 추천을 확인한다(외부 호출 없는 합성 입력).
`web/tests/console-responder.browser.cjs`는 1,201명 디렉터리의 검색/페이지, 늦은 응답,
단일/일괄 배정·규칙 버전·티켓 요청과 두 언어·좁은 화면·키보드 동작을 검증한다.
`console-directory-refresh.browser.cjs`는 수동 갱신·자동 대기/완료·권한 거절·주기 저장과
갱신 중 기존 선택 보존을 검사한다. 프로필 보관을 꺼도 재직 상태 수집은 요청할 수 있다.

2026-10-03 주기·상태 후속 변경은 Python 관련 고유 검사 727개, 웹 단위 20개,
TypeScript와 디렉터리 갱신·담당자·기존 연동 수정 브라우저 검사 3종을 통과했다.
실제 테스트 설치에서는 로그인과 동일한 Okta 조직의 읽기 전용 서비스 앱을 연결했고,
사람 목록 5분·프로필 보관 켜짐·앱 목록 꺼짐으로 첫 완전 수집과 사용자 6명을 확인했다.
연속 자동 작업의 접수 간격은 약 304초였고 두 실행 모두 완전 수집으로 끝났다.
이 검증은 실제 24시간 연속 실행이나 모든 IdP의 실환경 검증을 대신하지 않는다.

IdP 그룹 전체 동기화·팀 전체 티켓 발송·이름 유사도 매칭은 제공하지 않는다.
모든 공급자가 인간 소유자를 공개하지 않으며 불명확한 경우 명시적 지정이 필요하다.
실제 Slack·메일 발송 준비와 외부 응답 검증은 [소유자 승인과 대응 요청](TICKET_SYSTEMS.md)의 기록을 따르고,
합성 테스트 통과를 실제 직원 응답이나 모든 공급자 실환경 검증으로 보고하지 않는다.
