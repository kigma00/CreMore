# CreMore 팀 AI 코딩 지침

# 현재 지원 범위 (2026-10-16)

현재 공급자 구현과 온보딩 대상은 GitHub, AWS, Notion, Slack이다. 아래에 남아 있는 다른 공급자 설명은 당시 설계와 구현 기록이며 현재 등록·실행 계약으로 사용하지 않는다. 공급자 등록은 `cremore/onboarding/catalog.py`, 콘텐츠 소스는 `cremore/sources/registry.py`, 메타데이터 어댑터는 `cremore/coverage/providers/__init__.py`를 기준으로 확인한다.

코드 대조 기준: 2026-09-25, `refactoring`의 `2243dfb`. 이 문서는 신규 세션에서도 사용할 수 있는 개발 지침이다.
팀 공통 진입 지침은 루트 [AGENTS.md](../AGENTS.md)다. 새 AI 세션에는 두 문서를 같은 저장소
버전으로 제공하고 담당 공급자·목표·수정 범위를 함께 지정한다. 하위 `AGENTS.md`도 해당 영역에 적용한다.
설치·사용은 [README](../README.md), 기존 구조 변경과 실행 증거는 [REFACTOR_REPORT](REFACTOR_REPORT.md),
보안 제보·검토 범위는 [SECURITY](../SECURITY.md)를 함께 따른다. 변경 전에 실제 코드를 확인한다.
원래 작업 지침인 [AI_ALWAYS_ON_PROJECT_CODING_GUIDE](AI_ALWAYS_ON_PROJECT_CODING_GUIDE.md)와
[POST_REFACTOR_AI_TEAM_GUIDE_REQUIREMENT](POST_REFACTOR_AI_TEAM_GUIDE_REQUIREMENT.md)도 보존되어 있다.
두 원문의 절별 적용과 제약은 [요구사항 대응표](REFACTOR_REQUIREMENTS_MATRIX.md)에서 확인한다.
AWS 인벤토리 후속 변경은 [구현 범위·운영 계약](AWS_CREDENTIAL_INVENTORY_PLAN.md)과
[실행 검증 기록](AWS_INVENTORY_IMPLEMENTATION.md)을 함께 확인한다.
현재 공급자 확장·저장 이력·공개 인증서의 구현과 마지막 검증은
[공급자 인벤토리 구현 기록](PROVIDER_INVENTORY_IMPLEMENTATION.md)의 인수 목록·후속 검증 절이 기준이다.

2026-10-05의 [인벤토리·감사 메타데이터 재검토](INVENTORY_METADATA_REVIEW_2026-10-05.md)는
GCP Audit Logs/Monitoring, 선택적 Graph beta 키별 로그인, GitHub 조직 감사, Atlassian OAuth 및
GCP/Azure 금고 옵션의 온보딩 연결을 다룬다. 새 조회는 명시적으로 선택하고 권한을 재점검한다.
공통 인벤토리의 생성자는 명시적 생성 근거만 쓰며 소유자로 채우지 않는다. 마지막 사용은 완료/부분 완료
실행의 정확한 사용 근거만 합치고, 지표 구간·감사 관측·발급자 보고를 구분한다. 원문 로그는 보관하지 않는다.

신규 콘솔은 제품·요금제를 인증 전에 고르고 `계정·발급 목록 연결`과 `콘텐츠 검사 위치 연결` 카드·연동 현황을 분리한다
(묶음·배지 규칙은 `integrations/sections.ts`). 계정 카드는 계정 기능이 있는 edition만 고르게 한다.
`catalog.methods_for`와 서버 계획 정규화도 edition 조건을 검사한다. 인증 전용 owner는
`sessions.complete(authentication_only=true)`에서만 저장하고 source·scope·수집 주기를 만들지 않는다.
후속 콘텐츠 활성화는 같은 봉인 참조·owner를 `/targets/draft`로 재인증하고 기존 권한·scope 검증을 거친다.
콘텐츠 카드는 AWS(S3를 계정 역할로 읽음)를 빼면 계정 없이 노출 검사만으로 인증 후 흐름을 시작한다. Notion 일반 요금제는
계정 기능이 없어 콘텐츠 카드로만 들어오고, 계정 카드는 Enterprise 전용이다. 조직 봇의 별도 콘텐츠 인증은
같은 신원이라고 합치지 않는다. 기존 혼합 연결·인증만 저장한 연결은 자동 분리·삭제하지 않는다.
신규 흐름·제품별 조건·검증은 [제품 선택과 수집 목적 분리](EDITION_AND_COLLECTION_ONBOARDING.md)를 따른다.

GitHub Enterprise 전체 인벤토리는 비동기 Export API로 수집한다. 새 연결의 조직 목록·Enterprise 목록·
감사 로그는 독립 주기이고, `onboarding` descriptor의 `schedule=true`인 숫자 필드만 마지막 검토에서
추가 주기로 변경할 수 있다. 주기 변경은 권한 범위를 바꾸지 않는다. API의 `enterprise_export`는
단계·기준 시각·다음 생성 가능 시각만 공개하고 export ID·서명 URL을 공개하지 않는다.
수동 요청과 scheduler는 플랫폼의 동일 Enterprise 예약을 사용한다. `github-audit-links`는
동일 owner·origin·tenant·명시적 scope의 현재 형제 연결만 대조하며 양쪽 실행 ID로 캐시를 묶는다.
구형 목록 체크포인트는 근거를 보존해 부분 종료하고 새 수집을 안내한다.
세부 계약과 제한은 [GitHub Export](../github/README.md#enterprise-export-수집과-상태-2026-10-05)를 따른다.

GitHub·GitLab 접근자 목록은 `finding-context` 작업이 3페이지 단위로 결과·다음 페이지를 리스와 함께 저장하고 재개한다.
출처 신원/승인 변경·취소·예산을 검사하며 마지막 실패 전에 읽은 사람도 부분 근거로 보존한다.
공급자가 보고한 사용자와 bot/service 신원을 구분한다. 관측 시각·부분 목록은 실제 열람자나
과거 접근 가능자 전체를 증명하지 않는다. [위치 접근 근거](EXPOSURE_ACCESS.md)를 따른다.
권한 평가는 [평가 근거 계약](PERMISSION_ASSESSMENT.md)에 따라 누락 조건·권한 경계·조직 판단과
미평가 계층을 보존한다. wildcard 시뮬레이션을 종합 실효 권한으로 표시하지 않는다.
서버 신원은 [무인 운영 지침](UNATTENDED_DEPLOYMENT.md)에 따라 검증된 갱신 경로를 쓴다.
Roles Anywhere는 운영자 고정 helper만 허용하며 대시보드에서 임의 명령을 등록하지 않는다.
IdP 초기 실패·설정 변경·토큰 쓰기 실패에서 호스트의 다른 신원으로 대체하지 않는다.
노출에 대한 정확한 지문 연결에는 `MetadataStore.snapshot_matches`를 사용한다. 스냅샷 관측으로
독립된 고유 자격증명 행을 만들지 않으며 기존 비교 계약·키 ID 검증을 유지한다.
금고 대조의 양성 관측에도 같은 조회를 재사용하고 `issued.snapshot_observation`으로 표시한다.
이 관측 행은 고유 발급 수와 보관율에서 제외하며 금고 부재 판정에는 쓰지 않는다.

고정 ID 없는 Export 행은 공급자 descriptor의 `snapshot_identity_prefixes`로 선언한다.
`MetadataStore.inventory`는 memory/SQL 양쪽의 항목·전체 수·유형 집계에서 이를 제외하지만
원본 관측은 보존한다. `record_page(object_prefix=...)`와 실행 ID에 고정된 전용 API로
스냅샷 관측을 페이지 조회한다. App 발급 주체를 개별 설치 토큰으로 표시하거나 관측 행 수를
고유 자격증명 수에 더하지 않는다. signed URL은 표준 라이브러리의 IP 고정 HTTPS 경로만
사용하며 HTTPX/httpcore 디버그 로깅을 켠 검사에서도 로그·stdout에 남지 않아야 한다.

## AWS 인벤토리 정책 메타데이터 (2026-10-02)

AWS 발급 목록의 `iam_policy_metadata` 옵션은 기존 `identity_policies.collect_identity_policies`로
사용자·그룹 정책 요약을 읽는다. 신규 온보딩은 이를 기본 선택으로 제안하고 실제 정책 읽기를 점검한다.
`iam_potential_access`는 별도 잠재 권한 시뮬레이션이며, 옵션을 아직 저장하지 않은 기존 IAM 연결만
이전처럼 그 스위치를 따른다(`ConnectionSpec.iam_policy_metadata=None`). 기존 설치의
`IAM_POTENTIAL_ACCESS_MODE=disabled` 차단은 정책 읽기에도 유지한다. 명시적 옵션 변경은 기존 연결의
권한 재점검·revision·감사 경로를 거치고 같은 수집 이력과 주기를 유지한다.
정책 이름·Allow 작업·거부/조건부 문장 수·권한 경계 여부만 선택적 `iam_policies`에 남긴다.
정책 문서·조건값은 저장하지 않으며 실제 접근 권한이나 토큰 scopes로 승격하지 않는다.
요청마다 설정·승인·리스·취소·공통 예산을 확인하며 사용자의 두 키는 같은 조회를 공유한다.
조회 권한은 scanner IAM 역할에 별도로 필요하다. 기존 JSON 관측에는 필드가 없어도 되며
테이블 이관 없이 다음 수집부터 채운다. AWS 발급 계획에서 `cloudtrail`·`cloudtrail_regions`·
`cloudtrail_days`를 선택하면 소유 연결의 CloudTrail Event History를 수집한다. 성공한
`CreateAccessKey`의 응답 키 ID와 계정이 일치할 때만 호출자 ARN을 생성자로 연결한다.
생성 이벤트는 사용·현재 활성·완전한 발급 목록 근거가 아니다. 원문 응답은 보관하지 않는다.

노출 상세의 수동 사용 기록 조회는 별도 경로다. 콘솔은
`POST /api/v1/credentials/{id}/usage/refresh?background=true`로 접수(202)하고 기존 worker의
`credential-usage` 작업이 승인된 소유 계정 scanner로 최근 90일 관리 이벤트를 읽는다.
`ec2:DescribeRegions`와 활성 리전들의 `cloudtrail:LookupEvents`가 필요하다.
`coverage/credential_usage.py`는 계정별 작업 직렬화·승인·리스·취소를 맡고, 공급자의
`investigation/usage_pages.py`는 페이지 정규화·집계를 맡는다. 기존 작업 테이블을 쓰며
콘텐츠 scan kind나 active-scan index에는 추가하지 않는다.

한 실행의 기간은 고정하고 최대 100개 리전·CloudTrail 요청 10,000회·경과 시간 6시간으로
제한한다. 페이지당 최대 50건이므로 이론상 50만 건까지 읽을 수 있지만 빈 페이지·재시도·시간
제한에 따라 줄어든다. worker는 20페이지마다 큐에 돌려주고 요청 사이 0.55초를 둔다.
전체 호출·서비스·거부·분류를 집계하고 상세 기록은 최근 100건만 남긴다. 페이지 집계와 다음
cursor를 같은 fenced transaction으로 저장해 재시작·로그인 만료 뒤 이어 읽는다.
cursor는 비공개 작업 checkpoint에만 두며 원문 응답은 저장하지 않는다. 한도·오류·중지는
불완전 근거로 보존한다. 재조회는 새 실행이며 이전 실행에 호출 수를 더하지 않는다.

`background`를 생략한 동기 API는 호환용으로 기존 리전 25곳·리전당 1,000건·100페이지·
정규화 JSON 1 MiB 제한을 유지한다. 백그라운드 실행과의 덮어쓰기는 거절한다.
이 기능은 키별 Event History 조사이며 전체 조직의 장기 로그 보관·데이터 이벤트 수집을
대신하지 않는다. 대규모 지속 수집에는 별도 승인된 기존 S3 trail 경로와 운영 검증이 필요하다.

## 1. 제품과 기술 스택

콘텐츠 자동 검사는 `ScopeProfile`의 변경분 `schedule_minutes`와 전체 `full_scan_minutes`를 독립적으로 사용한다.
전체 주기의 null은 설치 기본값(`scan_triggers.full_scan_default_minutes`, 기본 1440분)을 따르고, 0은 비활성, 60~1440은
그 범위 자신의 주기다. 전체 검사 슬롯은 `full_scan_start_minute`(UTC 분, 기본 1020 = 02:00 KST)부터 세고 변경분 슬롯은
항상 DELTA다. 기존 연결 편집에서 빠진 필드는 유지한다. 주기를 바꿔도 scope 승인은 확장되지 않는다.
문서는 공급자 본문을 공통 `scanning/extraction`으로 전달하고 불완전 추출을 cache/제거 완료 근거로 쓰지 않는다.
외부 parser는 제한된 별도 프로세스로 실행하며 비밀 환경변수를 넘기지 않는다. OS sandbox라는 보장은 아니다.
Notion 호출은 검사 안팎(수집·카탈로그·자격증명/연결 점검·탐지 맥락·변경 피드)에서 `ScanStore.request_delay`로
같은 DB·token·origin의 요청 간격/429 cooldown을 공유한다(조치 실행 역할은 자기 프로세스 안의 간격만 쓴다). GitHub REST
요청도 `cremore.collectors.base.request_pacer`로 origin·token별 초당 10회와 보조 제한 cooldown을 공유한다.
DB 세션·권한 확인은 소유 스레드에서만 실행한다. token 원문은 pacing 키나 저장소에 넣지 않는다.
Notion 변경 webhook은 별도 관리자 확인과 공식 서명 검증을 거쳐 기존 `enqueue_event`로 접수하며
공개 Next 경로는 원문 바이트만 전달한다. 새 페이지 이벤트는 승인 범위를 넓히지 않는다.
새 노출 위치·재출현의 `finding_exposure` SIEM 이벤트는 관측 저장 트랜잭션에서 발신 대기열에 넣는다.
Slack 탐지 알림은 내장 채널(`cremore/alerts`)이 그 대기열을 목적지 `cremore.slack-alerts`로 읽어 worker 관리 프로세스
(역할을 나눈 배포는 control 프로세스)의 자기 스레드에서 약 1초마다 보내며([Slack 탐지 알림](SLACK_ALERTS.md)), 설치형 SIEM
출력 패키지 경로도 그대로 쓸 수 있다.
수신 응답 유실에 따른 중복 가능성을 숨기지 않는다.
설정·실제 검증·공급자별 한계는 [통합 구현 보고서](SCAN_AUTOMATION_IMPLEMENTATION_2026-10-06.md)를 따른다.

콘텐츠 스캔 접수는 실행 중에도 영속 대기열에 저장한다. 실행 점유는 연결별로 직렬화하고
독립 연결은 병렬로 처리한다. 연결 ID가 없는 기존 작업은 설치 전체 콘텐츠와 직렬화하며
오래된 무범위 대기 작업을 새 콘텐츠 작업이 계속 추월하지 못하게 한다. 이관 버전 11의
`scan_jobs_one_running_connection` 인덱스·부모 점유 트랜잭션과 기존 root 리스·중지 fencing을
함께 유지한다. 이벤트 ACK는 모든 작업의 영속 저장 이후다. 배포·롤백 제약은
[스캔 실행 계약](SCANNING_IMPLEMENTATION.md#연결별-동시-실행과-중지)을 따른다.

격리 배포(`ISOLATED_DEPLOYMENT`)는 [침해 이후 피해 제한 계약](POST_COMPROMISE_CONTAINMENT.md)을 따른다.
API의 연결 비밀 등록은 공개키 봉인만 하고 실제 해석은 현재 provider owner/child에서 도출한
binding으로 worker가 한다. 인증 대상·실행 목적을 envelope header에서 신뢰하지 않는다.
API의 AWS 읽기는 `coverage/aws_requests.py`의 collector 작업이며 기존 조회 응답은 완료 후 유지한다.
조치는 별도 remediator와 외부 Ed25519 승인, 일회용 nonce를 요구한다. 새 job은 역할 라우팅의
SQL/memory 양쪽에 배정하고 새 DB 테이블은 `db/privileges.py` 권한 계약에도 등록한다.
런타임은 schema를 읽어 검증하고 DDL은 독립 migration 계정만 수행한다. 강화 모드 기본값은
false이며 기존 설치를 자동 이관하지 않는다. 운영자 키 생성은 `secretstore/provision.py`,
봉인 참조 이관은 `secretstore/migrate.py`를 재사용한다. 원문 탐지값 비보관과 지문 키는 유지한다.

노출 대응 완료 확인은 `governance/response.py`가 소유하며 키 조치 실행 승인(`remediation/owner_approval.py`)과 분리한다.
담당자 응답(링크 화면의 보고 또는 티켓 플러그인 회신)은 완료 진술이고, 이후 시작한 비교 가능한 스캔만 제거 확인 또는 재조치 근거로 쓴다.
회차별 요청·응답·스캔 참조와 감사는 같은 트랜잭션에 남긴다. 재요청 UUID 멱등·버전 검사·불명확 발송 재시도 금지를 유지한다.
콘솔의 현재 노출/제거 이력과 자동 상태는 `credential_records`의 공통 projection을 쓴다.
조회 화면의 자동 갱신은 직접 공급자를 호출하는 수동 조사 API를 반복 호출하지 않아야 한다.
기존 편집기의 입력·최초 revision은 갱신 중 보존하고 저장 충돌을 알려 준다([대응 요청](TICKET_SYSTEMS.md#노출-대응-요청과-재스캔-확인)).

발견 위치의 접근 근거는 기존 `governance/ownership.py`의 finding-context 작업이 소유한다.
동일 repository/path여도 source 연결이 다르면 접근자·작성자를 합치지 않는다. 공급자가 보고한 구성원,
현재 읽기권한 근거, 실제 열람 이력은 구분하고 공개 접근·부분 목록·미지원·권한 거절을 보존한다.
현재 승인 범위를 다시 확인하며 상세 계약은 [위치 접근 근거](EXPOSURE_ACCESS.md)를 따른다.
동일 로그인 IdP 담당자 검색·추천·명시적 책임 규칙은 `identity/people.py`와 `governance/response_routing.py`가 소유한다.
검색은 보관을 선택한 프로필의 DB projection과 snapshot cursor를 쓰며 이메일로 계정을 합치지 않는다.
팀 설치에서는 최신·완전한 로그인 IdP의 `person_ref`를 발송 직전에 다시 확인한다. 이름·생성자·후보 login을 확정 소유자로 승격하지 않는다.
기존 설치의 프로필 projection은 `python -m cremore.identity.people --rebuild`로 재구성한다(외부 호출 없음).
사람 목록의 수동 갱신은 기존 metadata collect(analyst), 주기 변경은 기존 identity 계획(admin·revision 검사)을 사용한다.
신규 Okta 기본 주기는 5분이며 화면의 상태 갱신은 저장된 projection만 읽고 공급자 API를 반복 호출하지 않는다.
배정/책임 규칙과 감사는 기존 잠금 트랜잭션에 저장하며 계약과 한계는 [담당자 매핑](IDP_RESPONSE_ROUTING_REVIEW.md)에 있다.

기존 공급자 연결의 기능 추가는 `service.update_purposes`와 `/provider-connections/{id}/purposes`가 소유한다.
같은 인증 방식·대상을 유지하고 활성 계획을 제거하지 않으며, 선택 변경 후 새 권한 점검을 거쳐 `/activate`로 추가한다.
기능별 중지·재개는 `/provider-connections/{id}/features/{purpose}`와 저장소의 `disabled_purposes`가 소유한다.
인증 교체·전체 재개·대상 변경에서도 중지 상태를 유지하며, worker와 조치 실행은 유효한 기능 목록만 쓴다.
같은 UI 흐름의 추가 인증은 기존 연결 소유자를 별도로 생성하며 수집·조치 신원을 합치지 않는다.
공유 수집 레코드는 기존 `children.update`로 갱신한다. 연동 옵션 변경은 기존 검사 범위를 유지하고, 반복적인 대상 추가·제외는
콘솔 `integrations/targets.tsx`의 선택·검토·버전 검사 흐름을 재사용한다([공급자 연결](ONBOARDING.md#기존-연결에-기능-추가)).

인증 후 기능·대상을 선택하는 경로는 `onboarding/sessions.py`와 공급자 `authenticate`·`discover`가 소유한다.
Google OAuth 앱 설정은 `integrations/google-client.tsx`를 신규 인증 단계와 기존 연결 편집에서 공유한다.
앱이 없으면 같은 인증 단계에서 봉인 등록하고, 서버에 고정된 설정은 대시보드로 덮어쓰지 않는다.
GitHub App의 `연결 방식`은 새 자동 설정/이미 만든 App 입력 중 고르는 선택이며, 실제 manifest 이동은 `조직` 칸 바로 아래의
`GitHub에서 App 만들기·설치` 버튼(비활성 이유 표시)이 수행한다. 콘텐츠 카드에서 만드는 App은 `installation_purposes: ["exposure"]`를
요청한다. 앱 권한 선택은 수집 범위 승인을 대신하지 않는다.
노출 대응 v2는 `governance/response_reports.py`의 수신자 보고와 담당자의 응답을 함께 요구한다. 기본 경로는 연락 발송의
Slack·메일 링크이며, 링크 화면의 보고 하나가 응답(완료는 승인, 미완료·예외는 거절)을 같은 잠금 트랜잭션에 함께 기록한다.
링크 토큰은 digest만 저장하고 화면 API는 회사 로그인의 확인된 이메일과 현재 사람 목록으로 수신자를 다시 확인한다.
티켓 시스템 플러그인의 `Answer.report`는 비신뢰 입력이다. worker는 현재 티켓 계정 매핑을, 대응 서비스는 현재 IdP 수신자·보고 형식·
비밀값을 재검사한다. 보고/감사를 같은 잠금 트랜잭션에 추가하며 일반 댓글·HTML을 저장하지 않는다.
키 조치 실행 승인 계약은 유지한다. 보고 보완 대기 회차는 조회를 계속한다. 내장 티켓 시스템은 없다(GLPI 2026-10-12 제거).
`coverage/response_evidence.py`가 저장된 제거·발급자 종료·교체/금고 근거를 평가하고 worker가 재평가한다.
보고는 실행 승인이 아니며 `REMOVED`는 여전히 제거 이력이다. `COMPLETED`의 조건과 공급자별 근거 제한은
[대응 완료 기준](RESPONSE_COMPLETION_DESIGN.md)을 따른다. 목록·상세·대시보드·SIEM이 같은 상태를 소비한다.
콘솔의 계정 카드는 인증→기능→권한 확인→수집 범위→최종 확인, 콘텐츠 카드는 기능 단계 없이 인증→권한 확인→검사 범위→최종 확인이며,
권한 단계의 하단 버튼이 점검·목록 조회를 실행한다. 기능별 필요한 권한은 `integrations/permissions-preview.tsx`가 catalog 선언으로,
기능·대상별 준비/보류 판단은 `integrations/outcomes.ts`가 보여 준다. 일부 기능이 거절되면 `inspect`에 목적의 부분집합을 보내
통과한 기능만 계속한다(세션의 `held_purposes`, 감사 `ONBOARDING_PURPOSES_NARROWED`, 이미 도는 기능은 뺄 수 없음). 남은 기능의
필수 권한 거절·미확인·목록 실패 시에는 범위로 넘어가지 않고, `select`·`complete`·활성화는 남은 기능×대상 모두의 최신 GRANTED
근거를 계속 요구한다. 기존 계정에 콘텐츠 카드로 더한 새 대상은 `inspect`의 `target_purposes`로 노출 검사에만 묶어 계정의 다른
기능을 넓히지 않는다(서버 `sessions._scoped`: 기존 대상은 돌던 기능을 유지, 기능마다 대상 하나 이상; 다시 편집할 때는 `previous_scopes`·`_rescoped`가
그 한정을 유지). 설명 툴팁은 기존 `InfoTip`·`TooltipLayer`와 descriptor의
`description`·`description_ko`를 재사용하며 값의 종류·서버 점검·승인 계약을 바꾸지 않는다.
마지막 검토에서 기능별 수집 주기, 변경 감지 스캔(`complete.change_scans`, 기본 켜짐)과 즉시 실행 요청을
선택한다. `complete.schedules`는 선택된 기능의 주기만 변경하며 인증·권한 범위를 바꾸지 않는다. 노출 검사는
설치의 예약 검사 스위치도 필요하다(저장한 적이 없으면 켜짐, 화면에서 명시적으로 켜고 끔). API는 꺼진 상태의
새 노출 주기를 거절한다. 새 AWS 계획의 명시적 주기는 `ConnectionSpec.schedule_source=connection`으로 설치의
옛 AWS 인벤토리 스위치와 분리하며 설치 hard lock·계정 승인·기능 중지는 계속 적용한다.
기존 레코드는 그대로 유지하고 주기를 변경할 때 전환한다. 즉시 실행은 기존 collect·preview·scan-runs
API로 요청하며 접수까지 브라우저를 열어 두어야 한다. 자동 주기의 최초 실행은 다음 worker poll부터
가능하다. 실행별 조회는 `GET /api/v1/scan-runs/{id}`를 쓰고 예약 가능 시각은 worker와 같은 시계·receipt로
계산한다. 시각은 성공 보장이 아니며 대기 작업·권한·서버 상태에 따라 늦어질 수 있다.
AWS 최종 검토의 조사 스위치는 설치 전체 설정이며, 발급 목록/노출 기능에서는
사용 기록·잠재 권한, 금고 대조에서는 Secrets Manager 메타데이터만 표시한다. 숨긴 선택은 전송하지
않는다. `complete.aws_investigations`의 `changes`·`expected`는 bool 맵이며 기능에 없는 항목은 서버도
거절한다. 연동과 같은 트랜잭션에서 공통 설정 잠금·감사로 저장하고, 취소·저장 실패·설정 충돌 시
부분 적용하지 않는다. 조사 허용 스위치는 계정별 실제 AWS 권한 확인을 대신하지 않는다.
`auth_first`를 선언한 인증 방식에서만 제공한다. `new_setup: false`인 방법은 신규 생성·다른 방법에서의 전환을
API도 거절하고 기존 소유자의 같은 인증정보 유지보수만 허용한다. 설치 장소와 수집 대상은 별개이며
AWS의 새 인증 화면도 기존 scanner-identity API로 서버 신원을 표시·승인한 뒤 초안을 인증한다. 승인 실패는 다음 단계를 막고, 재승인하면 이전 승인 revision의 초안을 새로 만든다.
서버 신원이 없으면 실행 위치별 설정을 안내하고 회사 IdP 설정을 같은 연동 과정에서 연다. 역할 ARN은 IAM으로 조회하며 경로를 추측하지 않는다. 자기 역할 조회 권한이 없는 설치만 고급 수동 입력을 사용한다.
사내 서버 AWS 수집은 기존 OIDC/JWT→STS 자동 갱신을 사용한다. [인증 후 범위 선택 설계·구현 범위](AUTH_FIRST_ONBOARDING_DESIGN.md)의
지원표를 따르며 나머지는 기존 설정을 유지한다. 30분 초안은 사용자·브라우저에 묶이고 기존 `provider-check` worker만 외부 조회한다.
`permissions.py`는 선택한 대상·계획에 대한 최신 필수 권한을 신규 활성화·확대 API에서도 검사한다.
인증정보 소유자는 하나이며 target v2의 명시적 roots를 `targets.records_of`로 기능별 확장한다. 첫 root만 읽는 분기를 추가하지 않는다.
확정 시 owner·children·catalog·승인 scope·감사·초안 참조 이전을 같은 트랜잭션에 저장한다. scope 수정은 `expected_version` CAS를 쓴다.
대상 제거는 이력을 보존하며, 인증정보 갱신·늦은 인증 검사·전체 재개로 제거한 대상을 다시 켜지 않는다.
API·worker는 v1/v2를 모두 읽는 같은 버전으로 배포한다. 기존 target·인증정보 소유·승인 계약은 유지한다.

CreMore는 자체 호스팅 자격증명 노출 탐지·메타데이터 수집·거버넌스 제품이다. 일반 콘텐츠
탐지와 공급자 메타데이터 수집은 서로 다른 계약이다. 수집한 비밀 원문은 메모리에서만 처리하고,
HMAC 지문과 필요한 메타데이터만 저장한다. 가역 암호화·Base64 형태의 보관도 금지한다.
GCP의 과거 `store_values`·`keep_values` 저장 예외와 관리자 원문 조회 API는 폐기했으며,
독립 GCP export/watch CLI는 2026-09-27 삭제했다. 기존 값·백업·WAL·복제본 정리는
[GCP 이관 절차](integration/GCP_TOTAL_GUIDE_KO.md#과거-원문-저장-설치의-이관)를 따른다.
이 금지는 수집한 값의 보관에 적용한다. 공급자 연결을 인증하기 위한 자격증명은 기존 봉인 저장 계약을 유지한다.

| 대상 | 실제 구성·명령 |
| --- | --- |
| Python 제품 | Python 3.12+, `pyproject.toml`, pip, Hatchling wheel, `cremore` 0.1.0 |
| 서버 | FastAPI/Pydantic, Uvicorn, SQLAlchemy, psycopg/PostgreSQL |
| 탐지·외부 접근 | RE2, httpx, boto3, PyJWT/cryptography, dnspython·idna(도메인 검증); GCP 인증 `.[gcp]`, Azure 인증 `.[azure]` 선택 extra |
| Console | Next.js 16.3.8 App Router, React 19, TypeScript 5.8, npm lockfile |
| 스타일 | 콘솔 전용 CSS 하나(`web/app/(console)/console.css`)의 토큰, light/dark, Pretendard, 한국어/영어 |
| 테스트 | pytest, Node 내장 test, Playwright/Chrome, 독립 패키지는 unittest |
| 정적 검사 | Ruff; `web/tsconfig.json`의 strict TypeScript. Python type checker와 ESLint script는 미설정 |
| 포맷 | 별도 formatter 정책·CI gate는 없다. Ruff format 전면 적용으로 관련 없는 코드를 바꾸지 않는다 |
| 배포 | 루트 Compose, 팀 OIDC overlay, Helm, 읽기 전용/선택적 조치 CloudFormation |

Next.js는 실제 실행 프레임워크다. 페이지 렌더링·서버 프록시·인증 전달을 맡는다.
OIDC 로그인과 세션 cookie는 배포의 oauth2-proxy가 소유하고, API가 사용자 권한을 검증한다.
세션의 표시 이름은 검증된 토큰의 `name`(최대 200자)→신뢰된 이메일→subject 순이다.
계정 메뉴는 세션의 신뢰된 `email`도 함께 표시하며 없거나 미검증이면 `null`이다.
표시 이름은 권한 판정에 쓰지 않으며 감사·승인 주체의 `id`·`ref`는 기존 subject를 유지한다.
팀 설치의 `api/activity_audit.py`는 검증된 로그인 세션의 첫 API 접근과 API 요청 시작·HTTP 결과를
기존 `FindingEvent`에 추가한다. 당시 이름·신뢰된 이메일·역할은 표시 근거로 함께 보관하며
권한 판정·이메일 digest 비교에는 쓰지 않는다. 요청 본문·query·header·비밀값은 남기지 않고,
경로는 등록된 template과 UUID 대상만 남긴다. 자세한 범위·로그인 관측의 한계는 [API](API.md#team-activity-audit)를 따른다.
기존 도메인 감사 행은 동일 subject의 최근 검증된 표시 프로필을 조회 시 연결한다. 원본 행·MAC은 변경하지 않으며,
요청 기록의 당시 프로필과 구분해 표시한다. 선택 가능한 list 항목의 `options`는 공급자 descriptor에서 제공하며,
콘솔의 검색형 다중 선택이 소비한다. 값의 서버 검증·기존 list payload는 유지한다.
Vite 앱도 공개 npm UI 패키지도 아니다. 프론트엔드 수정 전 `web/AGENTS.md`와
설치된 `web/node_modules/next/dist/docs/`의 해당 버전 문서를 읽는다.

## 2. 최종 구조와 책임

| 경로 | 책임·주요 소유자 |
| --- | --- |
| `cremore/cli/` | `api.py`, `worker.py`, `coverage.py`, `siem.py`, `token_refresher.py`: 설치된 프로세스 진입점 |
| `cremore/api/app.py` | `create_app`: 서비스·인증·저장소·라우트 조립, 호환 export |
| `cremore/api/dashboard.py`, `route_context.py` | dashboard 서비스 조립과 `DashboardContext` 주입 |
| `cremore/api/routes/` | 도메인별 HTTP 등록·권한 검사. 서비스 규칙을 복제하지 않는다 |
| `cremore/api/http_support.py` | 본문 한도·안전한 validation 오류·UUID·HTTP 오류·로그 표시 |
| `cremore/api/connection_credentials.py` | 연결 비밀 입력 검증·봉인·참조 처리 |
| `cremore/api/finding_routes.py` | 기본 finding 조회·triage 등록. 대시보드 확장은 `routes/findings.py` |
| `cremore/api/*_presenters.py` | 공개 응답 변환. 원문/secret_ref 노출 금지 |
| `cremore/domain/` | 저장 모델·연결 의미·상태·조치 대상 예약 규칙 |
| `cremore/db/` | memory/SQL 저장소, schema·migration·scan/task/catalog/rescore stores |
| `cremore/scanning/` | 승인 scope, 실행 계획, 탐지→위험→저장, 재점수화, 오탐 학습·트리거 |
| `cremore/worker/` | 리스·heartbeat·취소·fenced commit, `factory.py`의 비밀 해석·공통 예산·등록 모듈 dispatch, `runtime.py` 실행 |
| `cremore/sources/` | 명시적 정적 registry·공통 설정 검증·기존 import 호환 경로. 구현은 최상위 공급자 라이브러리 |
| `cremore/siem/` | 비밀 원문 없는 최초 발견 이벤트·영속 발신 대기열·출력 계약·목적지별 재시도 |
| `cremore/collectors/` | 공통 bounded HTTP·scope·예산·수집 수명, `CollectedObject`/`Collector` 계약 및 호환 경로 |
| `cremore/detection/` | engine/catalog/decoder/validator/redaction/fingerprint, 선택적 verification |
| `cremore/risk/` | 증거 기반 위험 평가. 모르는 것을 실패·안전·미사용으로 바꾸지 않는다 |
| `cremore/coverage/` | schema 1 coverage와 schema 2 metadata 모델·런타임·저장소·스케줄 |
| `cremore/coverage/providers/` | 명시적 metadata registry·catalog·공통 계약 검사와 기존 import 호환 경로 |
| `cremore/investigation/` | 기존 AWS 조사 import 호환 경로. 실제 구현은 `aws/backend/cremore_aws_provider/investigation/` |
| `cremore/governance/` | 티켓·플레이북·담당자 검토. 버전과 승인 규칙 |
| `cremore/remediation/` | 승인·조치 상태·불확실 결과 조정. AWS API 실행·회전 구현은 AWS 라이브러리 |
| `cremore/secretstore/` | Vault/KMS/passphrase/sealed root, 참조 해석, 구성 보유 현황 |
| `cremore/aws_*.py`, `github_auth.py`, `github_hosts.py`, `gcp_auth.py` | 기존 import 호환 경로. 실제 인증·신원·host 구현은 해당 공급자 backend; I/O는 호출 시만 |
| `cremore/http_client.py`, `config.py`, `source_config.py` | bounded HTTP, 배포 설정, 공급자 설정 검증의 호환 facade |
| `web/app/` | `(console)` route group의 콘솔 page(`/`)·layout·stylesheet·글꼴, GitHub App·Google 로그인 콜백·소유자 승인 page, healthz, `api/backend/[...path]` 서버 프록시 |
| `web/console/` | 콘솔: `app.tsx` 화면 표, `shell.tsx` rail·topbar·route, `nav.ts` 화면·역할, `data.ts` 읽기·쓰기·거절 문구, `layer.tsx` tooltip·toast·menu·modal·drawer, `ui.tsx` 공통 UI, `views/<화면>/` |
| `web/components/` | 콘솔이 쓰는 locale·theme·표시 시간대·API 코드 문구(`labels.tsx`) |
| `web/lib/` | `dashboard-api.ts`, `dashboard-session.ts`, `dashboard-types.ts`, `scan-scope.ts`, `source-types.ts`, theme script 등 순수 데이터·타입 |
| `web/tests/` | `*.test.cjs` 단위 검사, `console-*.browser.cjs` 실제 스타일·상호작용 증명(`console-proof.cjs` harness) |
| `gcp/standalone/` | 제품이 재사용하는 `cremore_gcp` 라이브러리(식별자·값 reader·매칭)와 그 테스트 |
| `deploy/`, `docker-compose.yml`, `.env.example` | 배포 입력·구성 예제·차트·컨테이너·권한 템플릿 |
| `scripts/`, `.github/` | 합성 benchmark·운영 보조·CI/보안/release workflow |

새 파일은 이 중 책임을 가진 모듈에 둔다. 모든 모듈을 새 layer/package로 감싸지 않는다.
공급자 구현은 최상위 `aws/`, `gcp/`, `github/`, `gitlab/`, `notion/`, `atlassian/`, `azure/`, `vault/`에 있다.
각 `backend/cremore_<vendor>_provider/`는 Python 라이브러리와 전용 테스트를 소유한다. 공급자 폴더에는 UI가 없다.
Confluence·Bitbucket은 Atlassian, OpenBao는 Vault 소유 경계를 공유한다. 필요한 하위 폴더만 만든다.
제품 하나의 Python wheel·Next 앱에 포함하며 함수 호출로 연결한다. 공급자별 서버·Docker는 없다.
[디렉터리 보고서](PROVIDER_DIRECTORY_REVIEW.md)에 실제 이동·호환·빌드 경계를 기록했다.
연결 화면은 공급자 onboarding descriptor로 콘솔이 그린다. 공급자 고유 화면(AWS 설정·연동 대상, GitHub App,
설정 안내)은 `web/console/views/integrations/`, 발급 목록·노출·조치는 `web/console/views/credentials/`에 있으며
공급자 전용 화면을 따로 두지 않는다(AWS도 다른 공급자와 같은 연동 화면을 쓴다).

핵심 경계에서 직접 사용할 이름과 변경 주의점은 다음과 같다. 내부 재사용 API와 외부 배포
패키지 API는 같지 않으며, 아래 이름을 모두 독립 패키지로 배포하지 않는다.

| 소유 경계 | 실제 진입점·소비자 | 변경 시 함께 확인 |
| --- | --- | --- |
| API 조립 | `api/app.py::create_app`, `DashboardContext`, `routes/*::register` | route path/method/등록 순서, RBAC, context 소비 필드; [API_LIBRARIES](API_LIBRARIES.md) |
| 저장소 | `Repository`, `InMemoryRepository`, `SqlRepository`; 서비스와 API가 사용 | memory/SQL parity, transaction/CAS, 기존 NULL/JSON |
| 작업·체크포인트 | `TaskStore`, `ScanStore`, `task_state.py`의 순수 checkpoint 검증 | lease fencing·취소·재시도·원문 배제; metadata 모델에서 DB 역참조 금지 |
| 콘텐츠 공급자 | `<vendor>/backend/cremore_<vendor>_provider/source.py`, `sources/registry.py`; connections·factory·catalog·scope가 소비 | 모듈 계약·순서·scope·예산·실패/완전성·수명; `Collector`/`CollectedObject`는 기존 collectors 소유 |
| 탐지 | `Engine`, `EngineConfig`, `SanitizedDetection`, `detection/custom.py::rule_detection_policy` | 탐지 ID/순서·fingerprint·digest, `ENGINE_EPOCH`, synthetic fixture |
| Metadata | `collector_for`, `CollectionContext`, `CollectorRuntime.collect/compare_records`, `MetadataStore` | 등록·spec·record 검증·cursor commit·비교 순서·부분 결과; [METADATA_COLLECTOR_LIBRARIES](METADATA_COLLECTOR_LIBRARIES.md) |
| AWS 승인·세션 | `aws_access.save_approval`, `aws_sessions.AccountSessions` | 목적별 atomic revision, 신원 일치, cache key·만료, remediation 비캐시 |
| 비밀 참조 | `SecretResolver`, `parse_ref`, `inject_secret`, `Settings.sealing_keys` | reference 범위·이전 opener·원문 반환 경계; [CREDENTIAL_ROOTS](CREDENTIAL_ROOTS.md) |
| Web 상태·HTTP | `api`, `DashboardAPIError`, 콘솔의 `useApi`·`send`(`web/console/data.ts`) | BFF 경로·401/403·요청 세대로 오래된 응답 거절·저장 후 다시 읽기 |
| 공급자 연결 화면 | `provider-connections/catalog`의 descriptor와 `web/console/views/integrations/model.ts`의 catalog 규칙(`methodsFor`·`permissionsFor`·`targetFields`) | 서버가 가용성·권한을 결정; 마법사는 서버가 거절할 조합을 내지 않는다 |
| 공통 UI | `Modal`·`Drawer`·`Menu`(`web/console/layer.tsx`), `web/console/ui.tsx`, locale/timezone hooks | focus/Escape/복귀·닫지 못하는 동안·KO/EN·두 테마; [web README](../web/README.md) |

### 공급자 단위 함수 호출·설치·병렬 개발

콘텐츠는 `sources.registry.PROVIDERS[provider].build_collector(...)`, metadata는
`coverage.providers.collector_for(spec.provider)`가 명시적으로 등록된 공급자 함수를 호출한다.
자격증명 연결 상태 검사도 공통 비밀 해석 후 `source.check_credential(...)`로 보낸다.
공급자 생성자·HTTP transport·pagination·정규화는 해당 backend에 있고 공통 예산/실패·승인·DB 계약을 재사용한다.

새 위치를 받은 개발 환경에서는 루트에서 `python -m pip install -e ".[dev,gcp,azure]"`를 다시 실행한다.
Hatch가 단일 wheel에 `cremore`, 8개 공급자 패키지와 GCP 공통 `cremore_gcp`를 포함한다. `pip install` 후 저장소 밖에서도
import할 수 있어야 하며 runtime의 임의 `sys.path` 추가나 vendor SDK와 같은 package 이름을 쓰지 않는다.
`scripts/installed_check.py`가 설치본을 저장소 밖에서 `python -I`로 검사한다. 포장 파일=소스, registry·호환 경로의
wheel 내부 해석, 어댑터 registry의 DB 계층 미로드, 진입점, 오프라인 수집을 본다. `scripts/installed_tests.py`는
설치본의 공급자·계약 테스트를 돌린다. 전체 CI(수동 실행)는 운영 이미지처럼 해시 lock으로 설치한 뒤 둘을 실행한다.
PR마다 `boundaries` job이 경계·source 계약·콘텐츠 계약 테스트를 돌린다.
기존 leaf module은 canonical 모듈에 연결한 호환 import다. 새 구현·새 공급자 분기를 호환 파일에 넣지 않는다.
`import *` 복사로 module alias를 대신하면 monkeypatch/private 객체 identity가 깨질 수 있다.

신규 공급자는 담당 branch/worktree에서 `<vendor>/backend/`를 소유한다.
전용 Python 테스트는 backend 패키지 곁에 두고 전체 pytest가 수집한다. 공통 교차 공급자 계약 테스트와
웹 테스트 runner는 플랫폼에 남긴다. metadata 전용 Azure와 Vault에 빈 UI를 만들지 않는다.
GCP의 `standalone/cremore_gcp`는 제품이 재사용하는 플랫폼 독립 라이브러리다.
`resources`·`transport.ApiError`·`values`·`linkage`는 단일 구현을 쓴다. GCP·GitLab의 독립 CLI와
그것들만 쓰던 모듈(독립 수집·watch·평문 export·파일 저장)은 2026-09-27 삭제했다.
Python Docker는 이 GCP 패키지 소스만 추가한다.
함수별 소유 경계는 [GCP README](../gcp/README.md)를 따른다.

통합 담당자는 실제 추가되는 공급자에 한해 registry, `pyproject.toml` wheel/pytest 경로,
`deploy/docker/python.Dockerfile`을 연결한다. 연결 화면은 descriptor로 그려지므로 웹 빌드 설정은 바꾸지 않는다.
로고는 `web/public/logos/`와 `web/console/logo-set.ts`, 설정 안내·문구는 `web/console/views/integrations/guide.tsx`·`copy.ts`에 더한다.
Next와 React는 `web/node_modules` 설치 하나를 사용한다. web build context는 저장소 루트이고
standalone 실행 파일은 출력 루트 기준 `web/server.js`이며 실제 빌드 경로는 `web/.next/standalone/web/server.js`다. provider 폴더 전체를 별도 npm/Python 배포 패키지로 만들지 않는다.

새 인증·범위·DB·공개 응답 계약이 없는 공급자 내부 수정은 담당 폴더에서 진행한다.
공통 계약 확장은 필요한 파일·소비자·호환 영향·검증을 작업 카드에 배정해 플랫폼 담당자가 통합한다.
이는 모든 수정에 승인을 다시 요청한다는 뜻이 아니다. 이미 배정된 범위는 바로 진행한다.

## 3. 의존 방향과 공개 경계

Python 조립은 API/worker에서 서비스·repository·provider로 향한다. 도메인은 FastAPI,
React, vendor SDK를 import하지 않는다. HTTP 라이브러리는 app/dashboard/routes로 역참조하지 않는다.
탐지 모델·지문 같은 순수 모듈 import는 Engine을 로드하지 않는다. `cremore.detection`의 공개
`Engine`·`EngineConfig`는 기존 클래스 identity를 유지한 지연 import이며 공급자 모듈을 먼저 import해도 동작해야 한다.
`scanning/scope.py`가 승인 규칙과 순수 root identity를 소유한다. `EXACT_FIELDS`는
`sources/registry.py`가 공급자 `RESOURCE_TYPES`/`SCOPE_KIND`에서 도출하고 기존 scope import는 유지한다.
registry와 공급자 정의를 import할 때 domain·collector·API·DB를 로드하지 않는다.
수집기·catalog 구현은 호출 시 import하며 트리거가 worker를 가져오지 않는다.

콘솔은 `web/console/data.ts`(`useApi`·`send`)와 `web/lib/dashboard-api.ts`로 Next 서버 프록시를 호출한다.
순수 타입·모델(`web/lib/`, 화면의 `model.ts`)이 React 화면 구현을 import하면 안 된다. React 상태가 없는 계산은
해당 화면의 `model.ts` 등 기존 모델 소유자에 둔다. 콘텐츠 source 목록은 순수 데이터 `web/lib/source-types.ts`의
`CONTENT_SOURCE_TYPES` 한 곳에 두고 콘솔의 로그·규칙 화면이 여기서 읽는다.
`cremore/sources/module_contract_test.py`가 backend `SOURCE_TYPES`와 같은지(값·순서) 검사한다.

| 배포/라이브러리 | 공개 계약·소비자 | 검증·호환성 |
| --- | --- | --- |
| `cremore` wheel | 다섯 CLI와 `cremore.api.create_app`; 탐지·secretstore·SIEM public exports | `pip wheel --no-deps .`, public import/API 테스트. 버전은 `pyproject.toml` |
| `cremore.siem` | `Sink`, `SinkProvider`, `DeliveryError`; 설치형 SIEM 출력 패키지 | 계약 API 1, 이벤트 schema 1, 명시적 활성화·중복 거부. [SIEM guide](SIEM_INTEGRATION.md) |
| `cremore.detection` | `Engine`, `EngineConfig`, `DetectorInput`, `ResourceRef`, `SanitizedDetection`, `CatalogEntry` | 탐지기 ID·순서·fingerprint 의미 유지. 의미 변경 시 epoch 검토 |
| `cremore.secretstore` | `VaultKV`, `VaultKubernetesTokenSource`, `SecretResolver`, `SecretRefError`, `SecretStoreError`, `parse_ref`, `inject_secret` | v1/v2 읽기·이전 키 호환; 새 쓰기는 v2 |
| API 소유 모듈 | 앱 내부 재사용, [API_LIBRARIES](API_LIBRARIES.md) | 기존 app alias는 호환용. 신규 코드는 실제 소유자를 import |
| 콘텐츠 source 모듈 | `cremore.sources.registry`와 해당 공급자 모듈; 제품 내부 조립 계약 | 정적 소스 등록이며 외부 package discovery 아님. `source_config`/`api.source_contract`는 기존 import 호환 |
| Metadata runtime | `CollectorRuntime`, `CollectionContext`, `collector_for` | [METADATA_COLLECTOR_LIBRARIES](METADATA_COLLECTOR_LIBRARIES.md), provider 계약 테스트 |
| `cremore-web` | private npm 앱, 외부 npm exports 없음 | lockfile·build·타입·브라우저 검사; API 응답 형식과 같이 검토 |
| `cremore_gcp` | 제품이 재사용하는 GCP 함수(식별자·값 reader·매칭) | 같은 제품 wheel에 포함. 해당 루트 unittest. 플랫폼 내부를 import하지 않는다 |

내부 Python 모듈은 `from cremore.scanning.scope import root_identity`처럼 실제 소유자의
절대 import를 쓴다. vendor 패키지 내부의 상대 import는 기존 패턴을 따른다.
프론트엔드는 `@/` alias를 사용한다. 공개 패키지를 쓰는 외부 코드는 private deep import에
의존하지 않는다. 테스트의 의도된 private 함수 검증은 외부 지원 API를 만드는 것이 아니다.
새 package는 독립 소비자·배포·버전 관리가 실제로 필요한 경우에만 제안한다.

## 4. 변경할 때 유지할 불변 조건

1. 서버가 역할과 소유 범위를 검사한다. UI 숨김은 권한 검사가 아니다.
2. 일반 콘텐츠·탐지 raw 값은 메모리 경계 안에 머문다. 오류, 로그, job, checkpoint, finding에 넣지 않는다.
3. 요청 수·바이트·시간·페이지·레코드 한도와 취소 검사를 유지한다. 실패한 요청도 소모한 예산이다.
4. cursor는 실제 저장된 페이지와 함께 전진한다. 저장 거절·취소·리스 분실이면 이전 커서를 보존한다.
5. 모든 active exposure가 동일한 유효 FP profile에 맞아야 자동 오탐 처리한다. 수동 결정은 보존한다.
6. settings batch·AWS 승인 revision, ticket revision, finding 자동 결정, action target reservation은 repository의 원자적 작업이다.
7. timestamp만으로 경쟁 갱신을 감지하지 않는다. 동일 시각이 가능하므로 상태·resolution/version CAS를 사용한다.
8. 회전의 쓰기 시작 후 불명확한 실패는 `OUTCOME_UNKNOWN`이다. 자동 쓰기 재시도로 중복 키를 만들지 않는다.
9. 미수집·부분·권한 거절·잘못된 응답은 빈 목록 또는 부재 증거가 아니다.
10. native QA 참조 `_qa_storage.py`, `_qa_cli.py`를 제품 코드와 합쳐 독립 비교를 무력화하지 않는다.

## 5. Python·DB 규칙

타입은 실제 입출력·기존 Pydantic/dataclass 모델에 붙인다. 외부 JSON은 신뢰 경계에서
구조·길이·enum·bool/정수 구분·resource identity를 검증한다. 기능에 필요한 수준을 넘어
단일 구현 Protocol이나 새 service 계층을 만들지 않는다. 기존 주입 지점의 Protocol은 재사용한다.

Repository 변경은 `db/repository.py`와 `db/sql.py` 또는 이미 분리된 store에서 함께 검토한다.
SQLAlchemy bound parameter를 사용하고 사용자 값으로 SQL 문자열·컬럼·정렬 식을 합성하지 않는다.
필요한 정렬·필드 선택은 고정 allowlist다. 감사 기록과 상태 변경은 기존 transaction 경계를 유지한다.
긴 공급자 I/O 동안 DB write transaction을 잡지 않는다. Worker의 lease fencing을 우회하지 않는다.
AWS 신원 승인은 `aws_access.save_approval`→`put_revisioned_setting`으로 번호와 값·수행자를
함께 저장한다. `next_revision`의 조회 결과를 나중에 `put_setting`으로 저장하면 동시 승인이
같은 번호를 공유하므로 금지한다. `next_revision`은 호환용 예상값 조회일 뿐이다.

스키마는 `cremore/db/schema.py`, migration은 `cremore/db/migrations.py` 소유다. 필드 추가 시
Pydantic→SQL→memory→presenter→frontend→export 경로와 기존 NULL/legacy 데이터를 검토한다.
startup은 populated legacy 데이터를 임의 backfill하지 않는다. 오프라인 migration에는
API/worker 정지·검증된 backup·rollback 절차가 필요하다. `d96bb8d`까지의 리팩터링은 테이블
변경 없이 기존 JSON 기록에 추가 증거를 담고, 그 필드가 없는 기록을 미확인으로 취급한다.
후속 SIEM 연동은 `siem_events`·`siem_deliveries`를 추가한다. API/worker의 스키마 확장을
먼저 완료하고 exporter를 시작한다. 구체적인 순서와 롤백은 [SIEM guide](SIEM_INTEGRATION.md)를 따른다.

예외는 각 계층의 기존 타입을 쓴다: `CoverageError`, `TicketError`, `SecretRefError`,
`SecretStoreError`, `GitHubAuthError`, `AwsLoginRequired`. 원시 provider 메시지를 `str(exc)`로
사용자에게 돌려주지 않는다. AWS/수집기는 `aws_identity.error_code`의 bounded code를 재사용한다.
HTTP는 `api/http_support.py`의 오류 envelope를, 브라우저는 `DashboardAPIError` 상태를 사용한다.
401/403·409·일시적 실패·빈 결과를 각기 다르게 표시한다.

로그는 Python logging의 기존 모듈 logger를 쓴다(`cremore.api.http_support.logger`,
`cremore.worker` 등). job/run/connection ID, 단계와 고정 코드만 남긴다. 요청 body,
응답 body, authorization header, 원문 reference, 전체 SDK 예외·고객 자료는 로그에 넣지 않는다.
새로운 logging 서비스나 전역 logger singleton을 추가하지 않는다.

## 6. React·TypeScript·스타일·접근성

화면은 `web/console/views/<화면>/`에서 구성하고, 공유 타입은
`web/lib/dashboard-types.ts`와 화면의 `model.ts`를 우선 찾는다. 일반 객체 계산에 hook을 만들지 않는다.
서버/클라이언트 경계를 지키고 브라우저에 `API_TOKEN`, OIDC secret, provider credential을 전달하지 않는다.
기존 컴포넌트 상태와 명시적 props/callback을 사용한다. 전역 상태 라이브러리는 추가하지 않는다.

자격증명 권한 표·관계도·위험 규칙은 같은 `CredentialRecord`의 `scopes`·`issued.iam_policies`·
`aws_permissions`를 사용한다. IAM 정책을 token scope나 실제 접근 권한으로 바꾸지 않는다.
`aws_permissions`는 소유 계정·주체가 일치하는 저장된 조회 근거이며 인증 성공을 뜻하지 않는다.
시뮬레이션 변경은 관련 목록·상세 읽기를 갱신하고, 수집 시각·부분 수집·과거 관측을 유지한다.
정책 이름·Allow 작업·정책 시뮬레이션은 공통 `DetailPopover`로 버튼의 왼쪽 시작점 바로 아래에 겹쳐 연다.
상세 패널/대화상자 경계와 남은 높이에 맞춰 내부 스크롤하며, 맨 아래 버튼은 열기 전에 필요한 만큼만 스크롤해 보이게 한다.
스크롤·창 크기 변경으로 닫지 않고 팝업 바깥 클릭·토글 재클릭 또는 Escape로 닫는다. 스크롤할 때 버튼을 따라
배치하며 버튼이 화면 밖에 있는 동안에도 열린 상태를 보존한다. 일반 선택 메뉴의 닫기 동작은 유지한다.
목록을 펼쳐 기존 카드의 크기를 바꾸거나 내용을 아래로 밀지 않는다.
노출 위치는 위치별 목록에서 제목·검증된 원본 링크, 전체 경로, 공개 범위·발견 시각·작성자를
나누어 표시한다. 긴 경로를 좁은 표 열에 몰아넣거나 생략하지 않고, 가린 내용은 별도로 구분한다.

비동기 UI는 loading/error/empty/success를 구별한다. 선택·연결·열림 상태가 바뀌면
AbortController와 요청 세대 검사를 사용해 이전 결과를 버린다. 여러 요청 중 일부가 접수되면
성공한 job ID를 보존하고 실패 대상만 재선택한다. 진행 화면은 실제 접수한 run ID를 따른다.
취소된 클라이언트 요청이 서버 작업도 취소했다는 의미로 표시하지 않는다.

공유 대화상자는 `web/console/layer.tsx`의 `Modal`을 사용한다. `labelledBy`는 제목 id, `size`는 `wide`/`narrow`이고,
닫으면 안 되는 동안(한 번만 보이는 값을 보여 줄 때 등)은 `dismissable={false}`로 Escape·바깥 클릭을 막는다.
focus는 첫 입력(또는 `data-autofocus`)으로 들어가 Tab이 대화상자 안을 돌고, 닫히면 연 컨트롤로 돌아간다.
상세 패널은 `Drawer`, 메뉴는 `useMenu`와 `Menu`를 쓴다. Escape는 맨 위의 대화상자·메뉴가 먼저 받고, 패널 옆
입력란의 Escape와 한국어 입력 조합을 끝내는 Escape는 패널을 닫지 않는다.

```tsx
import { Modal } from "@/console/layer";
import { useL } from "@/console/text";

export function ReadOnlyNotice({ onClose }: { onClose: () => void }) {
  const L = useL();
  return <Modal onClose={onClose} labelledBy="notice-title" size="narrow">
    <h2 id="notice-title">{L("수집 상태", "Collection status")}</h2>
    <p>{L("마지막으로 저장된 수집 결과입니다.", "The last saved collection result.")}</p>
  </Modal>;
}
```

이는 component 사용 예시이며 실제 화면의 문구도 `L(한국어, English)`(`web/console/text.ts`) 관례를 따른다.
Form label, button type, 접근 가능한 이름, 키보드 동작, focus 표시, 좁은 화면, 충분한 대비를 검사한다.
색상만으로 실패·위험을 전달하지 않는다. JSX 기본 escaping을 유지한다. provider HTML을 렌더링하거나
외부 문자열을 `dangerouslySetInnerHTML`로 넣지 않는다. layout의 고정 theme script는 사용자 HTML 경로가 아니다.
외부 링크는 기존 URL 안전성 소유자를 거치며 임의 scheme·host를 허용하지 않는다.

콘솔의 스타일은 `web/app/(console)/console.css` 하나다. 색·간격·그림자는 `:root`의 토큰이고, dark는 같은 토큰을
`:root[data-theme="dark"]`와 `prefers-color-scheme: dark`(저장된 선택이 light가 아닐 때)에서 다시 정의한다.
새 색을 하드코딩하지 말고 토큰을 쓰거나 두 테마 모두에 정의한다. 기능 class는 화면 컨테이너로 범위를 좁히고,
정적 inline style 확산·범용 `section` 선택자·같은 패널의 반복 override를 금지한다. 글꼴은 layout이
`next/font/local`로 싣는 `app/(console)/fonts`의 Pretendard(KS X 1001 subset)다. Tailwind·CSS Module·
`clsx`/`tailwind-merge`/CVA는 쓰지 않는다. 단순 class 조합은 `web/console/ui.tsx`의 `cls()`와 조건부 className을 쓰고
실제 variant 복잡도가 필요하기 전에는 새 helper 의존성을 만들지 않는다.

## 7. Provider 계약과 추가 절차

콘텐츠 수집, 메타데이터 adapter, SIEM 출력은 서로 다른 소유권·등록 계약이다.
전체 수집 메타데이터의 목표 공통 계약은 [정규화 설계](UNIFIED_METADATA_CONTRACT.md)를 따른다.
자격정보와 콘텐츠 리소스 목록을 포함하되, 이 설계의 DB·API 전환은 아직 구현되지 않았다.
아래 현재 계약과 실제 코드를 기준으로 작업하고 설계 목표를 구현 완료로 가정하지 않는다.
목표 설계에서 공급자별 지원 선언·실행 결과·필드 관측은 별도로 다룬다. 향후 필드 지원이
추가되어도 과거 미수집 값을 추정하거나 승인 범위를 자동 확대하지 않는다. 세부 절차와
공통 UI 확장 경계는 정규화 설계의 '공급자별 지원 차이와 지원 범위 변경'을 따른다.

* 공급자 연결: 각 `<vendor>/backend/cremore_<vendor>_provider/onboarding.py`가 마법사의 descriptor(에디션·대상·
  용도별 권한과 계획 항목·인증 방식 권장 순서), `credential`(필드 → 봉인할 봉투), worker에서 도는 `check`, 용도별 레코드를
  설명하는 `children`과 선택 함수 `target`·`ready`·`prepare`·`adoptable`을 소유한다. CreMore가 자격증명을 만드는 방식
  (`generated`, 예: Microsoft 앱 인증서, Okta 서비스 앱 키)은 `generate`를, worker가 스스로 교체하는 자격증명(앱 인증서, GitLab 토큰)은
  `renew_due`·`renew`를 더한다. 공급자가 이전 자격증명을 즉시 폐기하면 `RENEWAL_REVOKES_OLD = True`를 둔다.
  플랫폼은 `cremore/onboarding/`에서 모델·API·원자적 생성·인계·자격증명 공유·교체(`renewal.py`)를 한 번 구현하고
  `catalog.py`의 `MODULES`에 명시적으로 등록한다.
  레코드를 직접 만드는 등록 경로를 공급자별로 다시 만들지 않는다. 계약은 [공급자 연결](ONBOARDING.md)이다.
  계획의 bool 선택에 묶인 권한은 `option`(켜졌을 때 필요)·`unless`(꺼졌거나 선택이 없을 때 필요)를 사용한다.
  계획 항목의 `edition_defaults`는 알려진 제품 ID를 키로 쓰고 `default`와 같은 타입의 값만 허용한다.
  서버와 콘솔은 현재 제품·대상에 제공되는 계획 항목과 기본값으로 권한 표시와 활성화 입력을 계산한다.
  콘솔은 기존 저장 계획에 없는 후속 옵션을 제품별 기본값으로 켜지 않는다. 저장 계획은 항목의 기본 `default`로 표시한다.
* 콘텐츠: 각 `<vendor>/backend/cremore_<vendor>_provider/source.py`가 공급자 정의를 소유한다.
  Atlassian은 같은 패키지의 `confluence_source.py`·`bitbucket_source.py`로 나눈다.
  실행은 기존 `Collector.collect() -> Iterator[CollectedObject]`다. `worker/factory.py`는 비밀 해석과
  공유 예산 뒤 모듈에 이미 제공된 client를 전달한다. `failed_objects`와 목록 완전성을 유지한다.
  자격증명 없이 확인된 회사 도메인이 읽을 범위를 정하는 웹사이트 검사는 worker가 payload 복사본에 넣는
  `domain_cover(host)`(`cremore.domains.covering`)를 요청마다 묻는다([website](../website/README.md)).
  위치를 전체 URL로 남기는 경로 범위 모듈은 선택 함수 `scope_allows(location, paths, excluded_paths)`로 정확 재검사와
  이벤트 경로의 범위 판정을 실행과 같게 한다. 어느 모듈이든 선택 함수 `scope_problem(root)`로 계획을 만들 때 막을
  범위 항목을 알려 줄 수 있다(`cremore/scanning/scope.py`).
* schema 2 메타데이터: `coverage/metadata_models.py`의 `MetadataConnectionSpec`, typed record, `MetadataPage`.
  `coverage/collector_runtime.py`의 `CollectionContext`/`CollectorRuntime`가 공통 호출 경계다.
  `coverage/providers/__init__.py`에 명시적으로 등록하며 알 수 없는 provider는 실패한다.
* AWS schema 1 인벤토리: `coverage/models.py`의 `ConnectionSpec`·`Observation`과 기존 coverage 저장·작업 계약.
  공급자 `iam_inventory.py`·`usage_inventory.py`를 `coverage/job.py`에서 호출하며 schema 2 registry 등록으로 대신하지 않는다.
* schema 1 금고 수집: 같은 `ConnectionSpec`·`Observation`으로 Vault/OpenBao KV, AWS Secrets Manager·SSM, GCP Secret Manager를 수집한다.
  Vault accessor·lease 관리 메타데이터와 실제 금고 값 관측은 다른 evidence다. `secretstore`의 제품 내부 인증 참조 해석과도 구별한다.
* SIEM: `cremore.siem`의 `SinkProvider`/`Sink`/`DeliveryError`, 설치형 `cremore.siem_sinks` entry point와
  운영자 목적지 설정을 사용한다. 수집과 별도 프로세스이며 [SIEM guide](SIEM_INTEGRATION.md)의 계약을 따른다.

콘텐츠 모듈은 `validate_config`, `job_payload`, `job_kind`, `config_from_scope`, `scope_ref`,
`build_collector`, `build_root`, `list_resources`, `check_credential`을 제공한다. capability·job/resource ID·scope 종류·
공급자별 필터·인증 표시도 이 모듈 소유다. `list_resources`는 해당 공급자의 catalog/content 함수를 호출한다. 공통 `scanning/catalog.py`는
등록 모듈로 dispatch하고 `catalog_projection.py`는 bounded resource 투영만 소유한다. `sources/registry.py`는 정적 import에서 dispatch·목록·상수를 도출하며,
`source_config.py`와 `api/source_contract.py`에는 새 공급자별 분기를 다시 만들지 않는다.
변경 감지는 선택 함수 `changes_since`·`changes_since_batch`(변경 조회기)와 `queue_changes`(큐 알림), 리비전 재사용은
`REVISION_CACHE`·`CONTENT_ADDRESSED`로 공급자 모듈이 선언한다. 계약은 [변경 감지 스캔](CHANGE_FEEDS.md) 5절이다.
노출 파일의 담당·접근 정보는 선택 함수 `exposure_context(payload, location, *, http_client, members)`로 공급자 모듈이
제공한다. GitHub·GitLab은 CODEOWNERS·작성자·구성원, Confluence·Bitbucket·Azure Repos Git은 공급자가 공개하는 제한/권한 근거를 읽는다.
S3·GCS·Blob은 정책/ACL·공개 접근의 지원 근거만 읽는다. Notion의 페이지 ACL과 Azure TFVC ACL은 미지원으로 표시한다.
소스 연결의 자격증명과 승인된 범위 안에서만 읽고, S3는 기존 scanner 세션·계정 pin·승인 revision을 재사용한다.
플랫폼의 `cremore/governance/ownership.py`가 `finding-context` 작업에서 호출해 정규화된 주체·허용/거부·제약만 저장한다.
CODEOWNERS·정책·외부 응답 원문은 저장하지 않는다. 그룹을 사람으로 펼치거나 실제 열람자·최종 실효 권한으로 단정하지 않는다.
권한 거절·미지원은 이유 코드이며 빈 목록이 아니다. 공급자별 읽기 범위와 한도는 [위치 접근 근거](EXPOSURE_ACCESS.md)를 따른다.

기존 metadata 공급자의 표시·설정 설명은 각 공급자 폴더의 `descriptor.py`가 소유한다.
공통 `catalog.py`는 기존 등록 순서로 이를 조립하며 공급자 코드를 실행해 설명을 얻지 않는다.
계약 검사 `coverage/providers/catalog_test.py`가 순서·출력·가용성·지연 import를 고정한다.
신규 수집 공급자의 실행 kind·scope·인증·저장 계약 변경은 여전히 플랫폼 담당자와 조정한다.
SIEM 출력 패키지를 설치했다고 수집 공급자가 등록되지는 않는다.

| 계약 종류 | capability·등록 | 설정·인증 | 기본 검증 위치 |
| --- | --- | --- | --- |
| 공급자 연결 | `<vendor>/.../onboarding.py`, `cremore/onboarding/catalog.py`의 `MODULES` | descriptor 인증 방식·필드(`secret`·`public`·`reference`·`reference_keys`), 공급자 연결이 봉인한 참조 하나 | `onboarding/providers_test.py`(레코드 행렬), `checks_test.py`, `onboarding_test.py`, `provider_boundaries_test.py` |
| 콘텐츠 source/reader | `<vendor>/backend/cremore_<vendor>_provider/source.py`, `sources/registry.py`, 기존 `Collector` | provider `validate_config`, 공통 connection 비밀 검사·resolver·AWS 세션 | `sources/module_contract_test.py`, `domain/connections_test.py`, collector·worker·scope tests |
| Metadata adapter | `providers/__init__.py`, `metadata_models.py` spec·typed record | connection spec origin/scope/auth_type/options, `CollectionContext` | `collector_runtime_test.py`, `metadata_job_test.py`, provider 계약·재개 tests |
| AWS schema 1 인벤토리 | `aws_iam`·`aws_cloudtrail`, AWS `iam_inventory.py`·`usage_inventory.py` | `ConnectionSpec`, scanner 승인·계정 pin, `coverage/aws_scheduling.py` | AWS 수집기 tests, `aws_scheduling_test.py`, `aws_session_models_test.py`, worker/API 회귀 |
| schema 1 금고 수집 | `vault`·`openbao`·`aws_secrets_manager`·`aws_ssm`·`gcp_secret_manager`, 공급자 `coverage.py`와 전용 helper | `ConnectionSpec`, namespace/mount/prefix·계정/region 또는 GCP project/reference, 공급자별 버전·관리 목록 옵션 | `coverage_test.py`, `vault_management_models_test.py`, 공급자 inventory tests |
| SIEM sink | 공개 `cremore.siem`, `cremore.siem_sinks` entry point | `ExportConfig`, 명시적 plugin 활성화, 출력용 token 참조 | `siem/sinks_test.py`, `siem/integration_test.py`, 팀 패키지 자체 tests |
| 사용자 인증 | `api/auth.py` local/OIDC, Next 인증 전달·proxy | `Settings` issuer/audience/groups; 서버에만 secret | `api/auth_test.py`, `api/dashboard_test.py`, `web/tests/proxy.test.cjs` |
| 비밀 저장/해석 | `SecretResolver`/Vault KV/sealed roots, 동적 plugin registry 없음 | `Settings` root 우선순위·Vault/KMS/passphrase·이전 opener | `secretstore/`의 tests, `domain/domain_test.py`, `api/request_boundary_test.py` |

AWS schema 1 인벤토리의 소유권·운영 경계:

- 공급자 수집·설정·조직/Control Tower 정보는 `aws/backend/cremore_aws_provider/`, 콘솔의 AWS 설정·연동 대상 화면은
  `web/console/views/integrations/`(`aws-settings.tsx`·`aws-identity.tsx`·`reach.tsx`)에 있다.
  순수 STS 구성요소 결합은 같은 공급자의 `detection/session_material.py`에 둔다. 공통 탐지·저장·API·상관분석 연결은 플랫폼이 통합한다.
  조직 context와 lifecycle 상태의 원자적 갱신은 `cremore.db.settings_store.locked_settings`를 사용한다.
  공급자는 공개 repository 메서드를 호출하고, DB 테이블·행 잠금·트랜잭션 조립은 플랫폼에 둔다.
- 단일 계정, 여러 독립 등록 계정, Organizations 전체·선택 OU 계정은 같은 scanner 승인·역할·ExternalId·실제 계정 검사를 사용한다.
  제외·탈퇴·비활성·범위 밖 계정의 과거 관측은 보존하며 후속 수집을 차단한다. Control Tower 이벤트는 재발견을 요청할 뿐 승인을 만들지 않는다.
- 자동 수집 설정은 admin의 `PUT /api/v1/settings/aws-credential-inventory`다. 기본 `enabled=false`, 주기 1440분이며
  `account_ids=[]`는 승인된 등록 계정 전체를 뜻한다. `SCAN_SCHEDULES_MODE=disabled`는 자동 수집을 잠근다.
  CloudTrail은 별도 `cloudtrail_enabled`·`regions`·`window_days` 설정을 사용하며 S3 모드는 버킷·prefix도 명시한다.
- 계정별 `GET /api/v1/aws/accounts/{account_id}/credential-inventory`와 analyst/admin의 같은 경로 `/refresh` POST를 사용한다.
  경로의 `account_id`는 내부 UUID이고 설정의 `account_ids`는 12자리 AWS 계정 ID다. 수동 갱신도 승인·작업 중복·리스 검사를 유지한다.
- IAM은 키·서비스 자격증명 페이지 목록, 사용자/루트 Credential Report, 선택적 마지막 사용 정보를 수집한다.
  보고서 키 슬롯을 실제 AccessKeyId에 임의 연결하지 않는다. Event History는 최근 90일 내 관리 이벤트,
  S3는 명시한 로그와 실제 trail 설정에 포함된 이벤트만 다룬다. 거절·잘못된 페이지·한도 초과는 빈 COMPLETE가 아니다.
- `IDENTIFIER`는 메타데이터 연결, `KEY_PAIR_FINGERPRINT`는 키 쌍 값 일치, `SESSION_FINGERPRINT`는 결합된 세 값 일치다.
  기존 키 쌍 fingerprint를 바꾸지 않고 별도 keyed session fingerprint를 사용한다. 원문·내부 지문을 공개 응답에 넣지 않는다.
  미관측·Vault 미매칭·만료 전 상태로 현재 사용 가능성이나 위험을 확정하지 않는다.
  현재 코드에는 완전한 STS 세션의 조건부 인증 확인 경로가 있으며 API는 지원 조건과 저장된 관측 결과를 구분한다.
  인증 결과는 확인 시점의 근거다. 역할 정책의 `POTENTIAL` 평가는 별도이며 실제 세션의 서비스 사용 권한 검증은 미구현이다.
  코드 경로의 존재와 실제 AWS 환경에서 검증한 결과를 구별해 보고한다.

전체 설정 필드와 권한은 [AWS 인벤토리 계약](AWS_CREDENTIAL_INVENTORY_PLAN.md), 중앙 S3·Control Tower·전용 SQS의
배포 조건은 [운영 지침](../deploy/cloudformation/control-tower-events.md), 현재 인증·정책 평가의 한계는
[STS 기술 평가](AWS_STS_VERIFICATION.md)를 따른다. 아래 등록 표와 adapter 추가 절차는 schema 2 경로다.

| 등록 키 | 실제 구현 | 지켜야 할 공급자 차이 |
| --- | --- | --- |
| `gcp` | `gcp/backend/cremore_gcp_provider/metadata/` | 단일 프로젝트 inventory와 별도 조직/폴더 discovery, 프로젝트 ID/숫자 alias, 고정 audit/metric window, 명시적 값 접근·저장 |
| `github` | `github/backend/cremore_github_provider/metadata/` | host·설치·조직/기업 scope, 선택적 Actions secrets 메타데이터·기업 token digest, 원문 token 값 미제공 |
| `gitlab` | `gitlab/backend/cremore_gitlab_provider/metadata/` | native 수집 queue·field 정책·audit 증거, 실패 페이지 rollback |
| `atlassian` | `atlassian/backend/cremore_atlassian_provider/metadata/` | Atlassian Cloud 조직 범위 API 키·사용자/서비스계정 토큰·OAuth client 메타데이터, response field allowlist, 재수집 planner |
| `bitbucket` | 같은 Atlassian adapter의 Bitbucket 경로 | Cloud repository/workspace와 실제 토큰 타입별 capability; Data Center는 별도 user/project/repository scope·HTTP token metadata, native export·실행 비교·실패 scope 재수집 |
| `notion` | `notion/backend/cremore_notion_provider/metadata/` | Enterprise 조직 bot·명시적 workspace, PAT·선택적 MCP 연결 메타데이터, token 값/공통 hash 없음 |
| `slack` | `slack/backend/cremore_slack_provider/metadata/` | Enterprise Grid 조직 관리자 user token·조직 또는 워크스페이스 하나, 승인 앱별 bot/user token·수신 웹훅 행, 선택적 감사 로그 설치 기록(기간 창), token 값·웹훅 URL·사용 기록 없음 |
| `azure_key_vault` | `azure/backend/cremore_azure_provider/metadata/` | 단일 pinned vault·cloud authority, secrets/keys/certificates 메타데이터, 별도 opt-in secret 값 HMAC, update≠rotation |
| `azure_entra` | `azure/backend/cremore_azure_provider/entra/` | Graph 조직 tenant 확인, application/servicePrincipal 자격정보·선택적 federation 정책, secret 값 없음 |
| `azure_resource_manager` | `azure/backend/cremore_azure_provider/arm/` | tenant/subscription discovery와 승인된 subscription inventory 분리, 명시한 storage account의 별도 opt-in key 값 HMAC |

공급자별 API·권한·edition 제약의 근거는 [기술 가능성 보고서](PROVIDER_CREDENTIAL_FEASIBILITY.md)를 따른다.
현재 구현과 인수 항목·실행 증거는 [공급자 인벤토리 구현 기록](PROVIDER_INVENTORY_IMPLEMENTATION.md)에서 확인한다.
등록 표는 전체 자격증명·임시 세션 수집이나 실환경 검증 완료를 의미하지 않는다. 최신 공식 문서를 다시 확인할 때도
API 문서의 존재, 실제 권한·라이선스 가용성, 로컬 fake 검증, 실환경 호출 결과를 구별한다.

발급·노출·금고 상관분석의 공통 규칙:

- 콘텐츠 발견 위치와 발급 공급자·조직은 별개다. 예를 들어 GitLab 문서에서 발견한 GCP 키는 GCP 발급 목록과
  대조한다. 콘텐츠 origin/tenant만으로 발급 조직을 추정하거나 다른 조직의 후보를 확정 일치로 표시하지 않는다.
- `coverage/metadata_correlation.py`는 노출→발급 목록, `coverage/issuer_coverage.py`는 발급 목록→금고의
  근거를 연결한다. 후자는 평문 노출이 없는 발급 항목도 표현하며 가짜 exposure/finding을 만들지 않는다.
  schema 1과 schema 2의 연결 결과를 제공하는 작업은 모든 저장 스키마를 통합했다는 뜻이 아니다.
- 명시적 `IDENTIFIER`, 호환되는 값 지문, GitHub의 공급자 digest, 근거 없는 `CANDIDATE`를 구별한다.
  기존 검증이 받은 소유자와 같은 소유자의 발급 항목은 `OWNER`로 앞에 두지만, 같은 소유자일 뿐 그 토큰이라는
  증거가 아니므로 `match_count`에 넣지 않는다. Azure SAS는 계정 이름으로만 `IDENTIFIER` 연결하며 서명 키는 확정하지 않는다.
  값 비교에는 fingerprint key·scheme·engine/policy digest·material kind의 호환성과 관측 시점을 확인한다.
  provider 상태·last_used·TTL·미만료·관리자 확인은 값 일치나 현재 인증/서비스 권한 검증을 대신하지 않는다.
- GitHub 기업 API의 선택적 `hashed_token`은 공급자 모듈의 `credential_digest.py`로 domain-separated HMAC 처리한다.
  원문 공급자 hash를 저장하거나 일반 응답·native export에 비공개 비교 지문을 싣지 않는다. null hash는 미제공이며 빈 token이 아니다.
  GCP 서비스 계정 key ID 연결은 동일 JSON 객체의 private key와 식별자 결합을 확인하는 순수 함수를 재사용한다.
  식별자 연결은 개인키의 암호학적 일치나 유효성 검증으로 승격하지 않는다.
- `NO_VAULT_MATCH`는 승인 범위·신선도·완전성·비교 계약이 허용하는 범위의 미매칭이다. 기업 전체 금고에 없다는
  보장이 아니다. 과거 버전만 일치·권한 거절·부분 수집·값 읽기 미승인·미지원 목록은 현재 보관이나 부재로 단정하지 않는다.
  평문 미관측 역시 비노출을 보장하지 않는다. 불확실성·실패·버전의 근거를 API/UI에서 보존한다.
- 발급자 목록·금고 값 읽기·발견 자격증명의 실제 인증은 각각 다른 동작이다. 이 상관분석 경로는 외부 인증을 하지 않는다.
  값 접근 옵션을 실제 발견 자격증명 사용 승인으로 해석하지 않는다.
- 관리자 제출 발급·저장 이력은 `coverage/storage_receipts.py`가 소유하며 기존 coverage transaction을 재사용한다.
  발급/금고 관측의 불변 run·batch·item 위치를 검증한 뒤 `coverage_storage_receipts`에 저장한다.
  UUID 동일 재시도는 멱등, 다른 내용은 충돌이며 철회된 이력을 재제출로 복원하지 않는다.
  schema 1/2를 연결할 수 있지만 기존 metadata relation의 provider/tenant 범위를 완화하지 않는다.
  collector token은 이력을 제출하지 못한다. 관리자 API·UI가 등록/철회하며 기존 로그인 역할은 조회 가능하다.
  이력은 관리자 주장으로 표시하고 비밀값 일치/현재 보관/활성 판정이나 노출 집계를 바꾸지 않는다.
  상세 API와 additive table의 호환·복구 경계는 [구현 기록](PROVIDER_INVENTORY_IMPLEMENTATION.md#발급저장-이력-api)에 있다.
- 공개 인증서 대조는 Azure 공급자 `public_certificates.certificate_evidence`를 import한다.
  Entra와 Key Vault 양쪽에 `public_keys` capability와 `public_certificates` source를 선택해야 한다.
  실제 X.509 DER를 읽고 SHA-256으로 대조하며 `customKeyIdentifier`와 `x5t`를 동등하다고 가정하지 않는다.
  `PUBLIC_CERTIFICATE_MATCH`/`PUBLIC_CERTIFICATE_SHA256`는 공개 인증서의 일치만 표시한다.
  개인키 보관·인증 권한·금고 부재를 확정하지 않고 과거/부분/중지된 관측과 현재 버전을 구분한다.
  `PUBLIC_CERTIFICATE_NOT_OBSERVED`는 확인된 범위의 선택 Key Vault 인증서 조회가 모두 최신·완료일 때의
  공개 인증서 미관측이며 개인키 부재가 아니다.
  `issuance_only`에 행을 포함하지만 노출 수·비밀값 일치율의 분모/분자는 유지한다.
  후속 공개 인증서 조회가 실패하여 최신 일반 메타데이터에 지문이 없으면 기존 공개 근거를
  `MetadataStore.latest_finished_observation`으로 제한 조회하고 `current_evidence=false`로 유지한다.
  DB 조회는 공통 store, DER 해석은 Azure 공급자, 근거 연결은 `coverage/certificate_coverage.py`가 소유한다.

새 공급자 작업에서 유지할 구체적 경계:

- Atlassian 묶음(`confluence`·`bitbucket`·`atlassian`)은 콘솔 `web/console/views/integrations/model.ts`의 `FAMILIES`가
  연결 화면에서 함께 보여 주는 표시 그룹이다.
  콘텐츠 `confluence`·`bitbucket`의 source_type·job·scope·API 식별자는 유지한다. schema 2의
  `atlassian` 조직 인벤토리 등록을 콘텐츠 수집기의 단일 공급자 등록으로 오해하지 않는다.
- [GCP](../gcp/README.md) discovery는 단일 organization/folder에서 ACTIVE 자식 리소스를 제한된 예산으로 찾는다.
  발견한 project는 context이며 인벤토리 연결·값 읽기 승인을 자동 생성하지 않는다. 프로젝트 inventory의 기존 범위는 유지한다.
- [Notion](../notion/README.md)의 PAT 목록과 MCP 연결은 Enterprise 조직 봇으로 읽는 선택한 workspace/source만의 메타데이터다.
  MCP 연결 하나를 access/refresh token 개별 인스턴스로 세거나 모든 integration/조직 bot token 목록으로 확장하지 않는다.
  일반 요금제는 공유 페이지 콘텐츠 검사를 지원하며 조직 인벤토리를 제공하지 않는다.
- 2026-10-05 사용자 범위 결정에 따라 Notion 별도 감사 webhook, Okta API-token/System Log,
  Keycloak 추가 자격증명/범용 감사 로그, Workspace OAuth grant/범용 감사 로그 수집은 구현 대상에서 제외한다.
  IdP의 로그인·역할 판정·담당자 디렉터리·퇴사자 점검은 유지한다. Keycloak의 기존 사용자 비활성화·삭제
  관리 이벤트는 퇴사자 근거이며 제외 대상이 아니다. 기존 선택적 IdP 앱 이름·상태 조회는 연동 제안용으로,
  자격증명 인벤토리로 해석하지 않는다. [현재 범위 결정](EDITION_AND_COLLECTION_ONBOARDING.md)을 따른다.
- [Slack](../slack/README.md)의 승인 앱 목록은 설치 여부를 주지 않는다. 감사 로그가 없으면 상태를 `UNKNOWN`으로 두고,
  사용자 토큰은 앱 단위 행으로만 센다. 행을 개별 사용자 토큰이나 설치된 전체 앱 목록으로 확장하지 않는다.
- [Azure](../azure/README.md)는 Key Vault data plane, Entra Graph, ARM을 각각의 등록·origin·승인 계약으로 유지한다.
  metadata 읽기만으로 secret 값 또는 storage `listKeys` 권한을 얻지 않는다. Key Vault 값은 `vault_value`와 `include_values`,
  ARM storage key는 `storage_keys` source·`issuer_value`·`include_values`·승인 subscription 안의 명시적 account ID를 모두 검사한다.
  원문 값을 저장하지 않으며 Entra secretText·힌트도 저장하지 않는다. federation/managed identity는 장기 secret 미보관 위험과 구별한다.
- [GitHub](../github/README.md)의 Actions secrets는 이름·시각·공개 범위 메타데이터이며 값은 얻을 수 없다.
  기업 token digest는 별도의 `issuer_digest` capability·`include_provider_hashes` 옵션이다. update 시각을 rotation으로 바꾸지 않는다.

schema 1 금고 수집의 경계:

- [Vault/OpenBao](../vault/README.md)는 namespace·mount·prefix 안의 KV1 현재 값, KV2 명시적 버전 또는
  `include_previous_versions=true` 이력을 수집한다. `max_versions_per_secret` 기본은 20이며 부분 실패·삭제/파기 버전은
  해결되지 않은 근거로 남긴다. KV1에 KV2 이력 의미를 적용하지 않는다. 고정 버전 선택과 이력 옵션은 동시에 사용하지 않는다.
- `include_token_accessors`·`lease_prefixes`는 관리자가 명시한 관리 메타데이터 수집이다. `MANAGED`는 `VALUE`나
  외부 issuer 발급 근거와 다르다. TTL로 활성 상태를 만들지 않고 lookup 실패·batch token 목록 미지원도 보존한다.
  token ID·password·응답 raw/meta는 버리며 accessor/lease ID도 민감한 관리 참조로 취급한다. 발급·갱신·폐기하지 않는다.
- [AWS Secrets Manager](../aws/README.md)는 기본 AWSCURRENT, 명시적 stage 또는 제한된 버전 이력이다.
  `include_previous_versions=true`는 현재 값을 먼저 보존하고 VersionId로 이력을 읽는다. 버전 역할은 반환된 stage로만 판단한다.
  이력과 비기본 stage 선택은 함께 사용하지 않는다. 계정·region·ARN·요청 버전 바인딩과 부분 실패를 유지한다. SSM의 기존 계약은 별개다.
- AWS 서버 수집의 `value_reader_role`은 같은 계정의 값 읽기 역할을 스캐너 세션에서 역할 연쇄로 맡는다.
  맡는 경로는 `aws_sessions.chain_value_reader` 하나(등록 계정은 `AccountSessions.value_reader`, 초안 점검은
  `onboarding_roles.open_reader`)이고 그 세션은 `VAULT_OPERATIONS` 클라이언트만 만든다. 주기 실행은 설치의 AWS 자동 수집 설정도 본다.
  Secrets Manager는 `references`(정확한 ARN)만 읽는다. 스캐너 세션 자체에 값 권한을 주지 않는다([AWS](../aws/README.md#값-읽기-역할)).
- 모든 금고의 값은 공통 `hash_value`를 사용해 실제 검출 타입과 호환되는 비교 근거를 만든다.
  Vault에 AWS·GitHub·GCP 등 다른 발급자의 값이 들어갈 수 있으므로 금고 제품 이름을 credential issuer로 쓰지 않는다.

Metadata adapter 추가 절차:

1. `CollectorRuntime`, `MetadataConnectionSpec`, 가까운 adapter와 계약 테스트를 읽는다.
2. 현 계약이 표현할 capability·edition·scope·auth·omission·quality를 적는다. vendor 이름만 추가하지 않는다.
3. `<vendor>/backend/cremore_<vendor>_provider/metadata/`에 정규화·transport·adapter를 둔다.
   Azure Entra·ARM처럼 별도 API·권한 계약을 가진 기존 하위 모듈은 `entra/`·`arm/` 경계를 유지한다.
4. SDK와 vendor JSON은 그 안에 유지한다. `collect_pages`, `validate_spec`, `validate_record`를 구현한다.
5. 외부 제출 scope를 따로 검증해야 하면 `validate_machine_record`를 구현한다. trusted discovery와 혼동하지 않는다.
   객체 문법만으로 정확한 scope를 증명할 수 없으면(GitLab root 탐색 등) 등록에 `machine_guard=True`를 선언한다.
   선언했는데 `validate_machine_record`가 없으면 어댑터 로드(`collector_for`)가 `METADATA_ADAPTER_UNAVAILABLE`로
   실패해 그 공급자의 metadata 수집·검증·제출이 모두 멈춘다. 조용히 기계 제출만 거부하지 않는다.
6. 공급자 `descriptor.py`, `providers/__init__.py` 등록, `metadata_models.py`의 실제 허용 값·API 설정 검증을 함께 갱신한다.
7. endpoint/origin allowlist·timeout·redirect 거절·크기/예산·페이지 cycle·재개를 검사한다.
8. `MetadataPage`에 고정 코드·부분 결과·실제 cursor를 반환한다. raw token/response는 넣지 않는다.
9. 해당 vendor 테스트와 `cremore/coverage/metadata_job_test.py`, `cremore/coverage/collector_runtime_test.py` 등 공유 계약 검사를 실행한다.
10. 연결 화면은 descriptor가 지원한다고 밝힌 capability만 콘솔이 표시한다. 설정 안내·문구가 필요하면
    `web/console/views/integrations/guide.tsx`·`copy.ts`에 더한다. `.env.example`, 배포 구성, 사용자 문서를 갱신한다.

Metadata 비교 호출자는 `CollectorRuntime.compare_records(before, after, spec=..., scope_id=...)`를
사용한다. 명시적으로 등록한 `_compare_runs` bridge가 각 native 비교 함수의 인자 순서·형식으로
변환한다. Azure의 `compare_records(previous, current)` 등 기존 native signature는 유지한다.
API가 native 함수에 공통 keyword를 직접 넘기거나 before/after를 뒤집지 않는다.
`collector_runtime_test.py`와 `api/metadata_comparison_test.py`가 이 경계를 검증한다.

Metadata inventory/events의 필터 선택지는 실제 저장자료에서 계산한 `facets`를 사용한다.
`counts`는 필터 결과의 객체 종류 집계이며 provider·purpose 목록이 아니다. 페이지 이동은
`offset`·`limit`·`total`을 기준으로 하고, 선택한 필터는 빈 결과에도 해제할 수 있어야 한다.
세부 응답 계약은 [metadata 지침](METADATA_COLLECTOR_LIBRARIES.md)을 따른다.
GitHub native source 요약은 여러 저장소의 실패를 보존하며, 작업별 상세와 집계 필드의 의미는
[GitHub 지침](../github/README.md)을 따른다.

콘텐츠 source 추가·변경 절차:

1. 기존 `<vendor>/backend/cremore_<vendor>_provider/source.py`와 collector·catalog·scope 소비자를 읽고 현재 계약으로 표현 가능한지 확인한다.
2. 공급자 모듈에 설정/오류·payload·scope 변환·일반/승인 root 생성·listing과 해당 검사를 둔다.
   런타임 import는 함수 안에 두며 공통 `sources/validation.py`의 기존 검증 규칙을 재사용한다.
3. backend `sources/registry.py`에 모듈을 명시적으로 등록한다. source/job/resource ID·capability 표시 순서와
   `RESOURCE_SOURCE`의 기존 primary resource mapping을 보존한다. consumer별 이름 목록을 복제하지 않는다.
   모듈은 `INSTANCE_SCOPED`도 선언한다(자체 호스팅 인스턴스마다 같은 리소스 이름이 반복되면 `True`).
   노출 위치의 `INSTANCE_SOURCES`, coverage API의 `source_type` 필터, 사용자 규칙의 `scope_sources` 검증은
   registry에서 파생되므로 따로 고치지 않는다. 같은 변경에서 `web/lib/source-types.ts`의 `CONTENT_SOURCE_TYPES`에
   source type을 추가한다(콘솔의 규칙 범위와 수집 로그가 읽는 목록, backend와 값·순서 동일). 기존 순서를 고정하는
   호환 테스트(`module_contract_test.py`, `custom_test.py`의 오류 메시지)의 기대값도 함께 고친다. 새 `<vendor>/backend`는 `cremore/provider_boundaries_test.py`의 `PLATFORM_IMPORTS`와
   `PROVIDER_MODULES`에도 추가한다(누락 시 테스트가 실패한다).
4. 연결 화면은 onboarding descriptor(`<vendor>/backend/cremore_<vendor>_provider/onboarding.py`)의 field·permission·purpose로
   콘솔이 그린다. 검사 대상 고르기는 공통 catalog·scope 화면(`web/console/views/integrations/targets.tsx`)이 맡는다.
   로고(`web/public/logos/`, `web/console/logo-set.ts`)와 설정 안내·문구(`guide.tsx`·`copy.ts`)만 더한다.
   화면은 backend source보다 늦게 추가해도 된다.
5. 새 인증 방식·공개 응답/schema·scope family·실행 kind는 플랫폼 담당자와 별도로 검토한다.
   connection 비밀 해석 계약, 승인·권한, 누락 리소스의 삭제 추론은
   모듈 등록만으로 확장되지 않는다. 새 kind는 `CONTENT_SCAN_KINDS`뿐 아니라 DB의 기존 active-scan
   partial index와 migration을 검토해야 한다. Python 상수 변경이 설치된 index를 갱신하지는 않는다.
6. fake client로 등록→비밀 해석→승인 scope→수집/저장→API/UI 흐름을 검사한다. 모듈 계약과 기존
   worker/scope/catalog 검사, 콘솔 연동 화면의 단위 검사(`web/tests/console-*.test.cjs`)와 browser 검사를 함께 고른다.

콘텐츠 source는 metadata 등록만으로 실행되지 않으며 metadata 전용 Azure는 콘텐츠 registry에 넣지 않는다.
기존 범위의 공급자 로직은 팀별 모듈에서 수정할 수 있지만 폴더 하나 추가로 임의 공급자 전체 기능이
완성되는 구조는 아니다. 콘텐츠/metadata는 명시적 backend 등록이고 외부 설치형 수집 플러그인은 없다.

새 cloud provider는 위 절차에 실행 신원·계정/프로젝트/vault pin·서비스 지역·권한을 더 검토한다.
AWS 예제의 scanner와 executor 분리를 다른 cloud에도 그대로 지킨다. GCP의 숫자 alias를 임의
다른 프로젝트로 바꾸거나 Azure의 응답 ID를 요청한 vault로 재라벨링하지 않는다.
외부 API를 호출하는 테스트는 승인된 별도 환경에서 명시적으로 opt-in하고 기본 unit suite는 fake transport만 쓴다.

공통 계약에 없는 vendor 기능은 바로 모든 adapter에 메서드로 추가하지 않는다. GCP·GitHub·Azure의
`value_context`, Atlassian의 recollection planner처럼 실제 공통 호출자가 필요한 optional capability인지,
해당 vendor 안에 머물러야 하는 기능인지 판단한다. 과도한 범용 registry는 필요 없다.
`value_context`는 선택한 값/digest 수집을 위한 공통 주입이며 원문 저장 허용이 아니다.
GCP의 원문 저장용 `capture_value` 경로는 제거했다. 성공적으로 읽은 값의 변경은 비공개 HMAC으로 관측하며,
scheme·key ID가 같은 관측만 비교한다. 기존 `value_match` 대조와 구분하고 이 지문을 공개 응답·export에 싣지 않는다.

네트워크 없는 실제 계약 사용 예시:

```python
from cremore.coverage.metadata_models import MetadataConnectionSpec
from cremore.coverage.providers import collector_for

spec = MetadataConnectionSpec.model_validate({
    "schema_version": 2, "name": "검증 예제", "provider": "azure_key_vault",
    "origin": "https://example-vault.vault.azure.net", "edition": "cloud",
    "scopes": [{"kind": "vault", "id": "example-vault"}],
    "capabilities": ["vault_metadata"], "auth_type": "workload_identity",
    "options": {"mode": "inventory"},
})
collector_for("azure_key_vault").validate_spec(spec)
```

이는 spec 검증만 한다. `collect()`는 외부 I/O이므로 예시를 실행한다고 호출하지 않는다.
계약 test 위치는 `cremore/coverage/providers/metadata_resume_test.py`, 각 provider의 tests 또는
`azure_key_vault_test.py`, Atlassian은 `atlassian/backend/cremore_atlassian_provider/tests/`이다.
기존 fixture에 synthetic provider 응답을 등록해 pages/replay/errors/cancel/budget/identity를 검사한다.
새 provider가 아무것도 수집하지 않아도 통과하는 조건부 assertion을 쓰지 않는다.

## 8. AI·Auth·Payment·Storage 확장

현재 LLM 모델 호출·streaming·tool calling·결제·메일 provider는 없다. 탐지 catalog의
OpenAI/Stripe credential 형식은 그 vendor의 제품 SDK 통합을 뜻하지 않는다. 이를 위한
추상 factory나 placeholder API를 만들지 않는다. 실제 AI 기능을 제안할 때는 먼저 소비자,
입출력·민감정보·비용·timeout·streaming 필요·fake 검증을 정하고 기존 조립 지점에서 좁게 주입한다.

Auth는 `cremore/api/auth.py`의 local/OIDC, oauth2-proxy의 로그인·cookie, Next의 인증 전달이 실제 계약이다. 새로운 IdP는
가능하면 기존 issuer/JWKS/audience/groups 매핑 설정을 사용한다. API가 signature·expiry·subject·role을
검사하며 provider user 객체를 domain 모델로 전달하지 않는다. provider 교체가 OIDC 밖의 새 방식이면
API와 web 양쪽의 인증 경계·cookie/CSRF·role 테스트를 먼저 합의한다.

저장은 세 가지를 구별한다: SQLAlchemy repository, 콘텐츠 reader, `secretstore`의 비밀 참조.
S3 수집기에 upload/delete/signed URL을 추가해 범용 StorageProvider로 바꾸지 않는다.
외부 비밀 저장소를 추가할 때는 `SecretResolver`의 값 정규화·허용 reference·credential injection,
`config.py` 선택 및 이전 sealed opener 호환을 검토한다. 현재 Vault KV v2와 KMS sealing root를 재사용한다.

## 9. 설정과 보안 경계

API/worker 환경변수는 `cremore/config.py::Settings`가 alias·default·validator를 소유한다. `.env.example`,
Compose API/worker 전달, 필요한 Helm 값·secret template, frontend server 경로를 함께 확인한다.
브라우저 설정으로 비밀을 옮기지 않는다. `API_ADMIN_TOKEN`은 Compose에서 `API_TOKEN` 등으로
전달되는 설치 입력이므로 이름을 임의 변경하지 않는다. `RETIRED_ENV`는 기존 이름의 거절·이행 안내다.
별도 SIEM exporter는 `siem/config.py::ExportConfig`의 목적지 JSON과 `SIEM_DATABASE_URL`을 사용한다.
API token·fingerprint/sealing key·수집 자격증명을 exporter에 전달하지 않는다. SIEM token은
각 출력 어댑터의 `token_env`로 환경변수를 참조한다. 설정 파일에 비밀 값을 적지 않는다.

| 설정 | 의미 |
| --- | --- |
| `AUTH_MODE`, `API_TOKEN`, `OIDC_ISSUER_URL`, `OIDC_AUDIENCE` | 서버 인증 경계. 팀 설치는 OIDC |
| `DATABASE_URL` | 운영 PostgreSQL 연결. 테스트 URL은 운영 DB와 분리 |
| `FINGERPRINT_KEY` | 설치별 fingerprint identity. 임의 회전하면 비교 계약이 깨진다 |
| `SEALING_KEY*`, `SEALING_KMS_KEY_ID`, `SEALING_KEY_CIPHERTEXT*`, `SEALING_KEY_VAULT_PATH*`, `SEALING_PASSPHRASE*` | 새 봉인 선택과 이전 복호화 키. [CREDENTIAL_ROOTS](CREDENTIAL_ROOTS.md) |
| `SECRET_STORE_URL`, `SECRET_STORE_TOKEN`, Vault workload 설정 | worker 참조 해석; API sealing root에는 별도 최소 권한 |
| `CREDENTIAL_VERIFICATION_MODE` | 제품의 검증 허용/강제 잠금. Engine의 기본 `VerifierConfig.enabled=False`와 구별 |

| 설치 입력 | 필수 조건·기본값 | 비밀 여부·보관 |
| --- | --- | --- |
| `FINGERPRINT_KEY` | API/worker 필수; 기본 빈 값, 최소 32 bytes의 hex | 비밀. 기존 DB identity이므로 backup과 함께 보존 |
| `API_TOKEN` (`API_ADMIN_TOKEN` Compose 입력) | local API 필수; 기본 빈 값, 최소 32문자 | 비밀. OIDC 사용자 토큰을 대체하지 않음 |
| `OIDC_ISSUER_URL`, `OIDC_AUDIENCE` | OIDC API 필수; 기본 빈 값 | 공개 식별 설정. OIDC client secret은 별도 server/proxy 비밀 |
| `DATABASE_URL` | 항상 연결 필요; 개발 기본은 로컬 PostgreSQL DSN | 비밀번호 포함 가능. 전체 값을 로그/브라우저에 노출하지 않음 |
| `SEALING_*`, `SECRET_STORE_*` | 선택한 방식에 따라 조건부 필수; root 미지정 시 fingerprint에서 파생 | key/token/passphrase는 비밀, ciphertext·Vault 경로도 운영 설정으로 보호 |
| `AWS_SSO_DISCOVERY_MODE` | 앱 기본 enabled(허용), Helm 기본 disabled; 관리자 switch와 별개 | 비밀 아님. opt-in에는 writable 로그인 cache와 사람의 재로그인 필요 |

전체 alias·default·validator는 `config.py::Settings`, 배포 예시는 `.env.example`과
`deploy/helm/values.yaml`, 기동 요구는 `Settings.validate_safety`가 기준이다. 예제에 실제 비밀을
쓰지 않는다. Helm SSO opt-in 값만 바꿔서는 cache mount가 만들어지지 않는다. 새 env는
alias/default/secret/필수 조건과 API·worker 전달 여부를 이 기준에 함께 반영한다.

설치별 역할과 provider tenant metadata는 SaaS 고객 격리가 아니다. 현재 principal·repository는
설치 단위이며 일부 v1 목록·통계·correlation은 전체 자료를 읽는다. 고객별 격리·공정한 작업 큐·
DB pagination·retention이 필요한 서비스에는 별도 설계/검증이 필요하다. 파일 분리를
그 기능이 구현됐다는 증거로 쓰지 않는다.

현재 제품의 관리자 verification switch 기본은 켜짐이며 배포에서 잠글 수 있다. 라이브러리
Engine 기본은 꺼짐이다. 테스트는 fake client를 주입하거나 검증을 끄며, 로컬 검증 작업이
실제 발견 credential을 provider로 전송하도록 두지 않는다. capability·cross-host 검사는 별도 옵션이다.

SQLi 방지는 bound values와 고정 식 선택, XSS 방지는 JSX escaping·안전한 URL, SSRF 방지는
provider별 origin/path/redirect 경계가 담당한다. 한 계층의 검사로 다른 계층의 검증을 없애지 않는다.
Vault reference, base64/봉인 envelope, JSON, provider resource ID 모두 크기와 형식을 검증한다.
숫자·문자열·boolean coercion으로 권한이나 승인 결정을 바꾸지 않는다.

## 10. 테스트·빌드 명령

저장소 루트 기준 Bash:

```bash
python -m pip install -e '.[dev,gcp,azure]'
AWS_EC2_METADATA_DISABLED=true python -m pytest -q -ra
python -m ruff check cremore aws/backend gcp/backend github/backend gitlab/backend notion/backend atlassian/backend azure/backend vault/backend okta/backend keycloak/backend slack/backend website/backend
(cd web && npm ci --ignore-scripts)
(cd web && npm test)
(cd web && npx tsc --noEmit)
(cd web && npm run build)
(cd web && npm run test:browser)
(cd gcp/standalone && python -B -m unittest discover -s tests -v)
out=$(mktemp -d)   # a fresh build and venv like CI and the production image (hash-pinned locks)
python -m venv --clear "$out/build" && "$out/build/bin/pip" install --require-hashes -r requirements-build.txt
"$out/build/bin/pip" wheel --no-deps --no-build-isolation -w "$out/dist" .
python -m venv --clear "$out/venv" && "$out/venv/bin/pip" install --require-hashes --only-binary :all: -r requirements.txt
"$out/venv/bin/pip" install --no-deps "$out"/dist/cremore-*.whl && "$out/venv/bin/pip" check
(cd "$out" && "$out/venv/bin/python" -I "$OLDPWD/scripts/installed_check.py" --source "$OLDPWD")
"$out/venv/bin/pip" install "pytest>=8.3" "jsonschema>=4.23" "rfc3339-validator>=0.1.4"
(cd "$out" && "$out/venv/bin/python" -I -X utf8 "$OLDPWD/scripts/installed_tests.py")
git diff --check
```

pytest 경로를 생략하면 `pyproject.toml`의 `testpaths`에 등록된 플랫폼·공급자 테스트를 함께 수집한다.
PowerShell에서는 첫 pytest 명령 전에 `$env:AWS_EC2_METADATA_DISABLED='true'`를 설정한다.
`cd` 대신 `Push-Location web`/`Pop-Location`을 사용할 수 있다. 독립 GitLab은 POSIX 파일 mode와
`fcntl` 검사가 있으므로 Windows에서는 WSL 또는 Linux Docker로 실행한다. Atlassian의 POSIX
검사도 같은 환경이 필요하다. 소스와 임시 파일은 Linux 파일시스템에 두고 Windows bind mount의
파일 권한·잠금 동작을 POSIX 검증으로 대신하지 않는다.
GCP·Azure 라이브러리 인증 unit 검사는 `python -m pip install -e '.[dev,gcp,azure]'` 환경에서 가능하다.
기본 Python Docker 이미지는 `requirements.txt`의 GCP·Azure extra 잠금 파일을 사용한다.
새 vendor SDK를 선택 extra에만 추가하고 기본 배포의 잠금 파일에서 빼면 실제 수집 시 import가 실패한다.
`.[dev]`에는 Atlassian 출력/작업 JSON Schema와 date-time 검사용 jsonschema·rfc3339-validator가 포함된다.

PostgreSQL 동시성 검사는 격리한 일회용 DB의 `CREMORE_TEST_POSTGRES_URL`로 opt-in한다.
공통 fixture는 host `localhost`/`127.0.0.1`, DB 이름 `cremore_test`, PostgreSQL 16 이상만 허용한다.
Docker에서는 별도 PostgreSQL 컨테이너와 tmpfs를 쓰고, 검사 컨테이너가 그 network namespace를
공유하면 `127.0.0.1:5432`로 접속할 수 있다. 이 제한을 완화하거나 기존 제품 DB를 연결하지 않는다.
DB·POSIX·GCP/Azure 인증 의존성 미설치로 생긴 skip을 passed라고 쓰지 않는다.
계정 미연결 오픈소스 개발에서는 합성 client·격리 DB·브라우저·설치 검사를 기본으로 완료하고,
실제 공급자 권한/응답·OIDC 로그인·SIEM 수신은 이후 연결 환경에서 검증할 항목으로 구분한다.
Ruff의 기존 위반과 이번 변경의 새 위반은 baseline 비교로 구분한다. 현재 저장소에는
별도 Python typecheck·ESLint·format gate 명령이 없으므로 실행했다고 보고하지 않는다.

배포 검사:

```bash
node --test deploy/helm/tests/chart.test.cjs
# Docker engine 없이, 검증된 Helm 3.17.2 binary와 Compose CLI로 동일 assertion 실행:
CREMORE_HELM_BINARY="$(command -v helm)" node --test deploy/helm/tests/chart.test.cjs
```

기본 경로는 테스트 파일에 digest로 고정된 Helm image를 사용한다. Native 대안도 버전 3.17.2를
검사한다. 이 테스트는 synthetic 변수와 빈 env 파일로 render만 하며 deploy하지 않는다.
컨테이너 build·기동 검사는 실제 OIDC 로그인·워크로드 인증·공급자 호출·SIEM 전송과 구분한다.
합성 기동 검사는 별도 이름의 컨테이너, 합성 설정, 임시 저장소, 외부 네트워크 차단을 사용한다.
기존 서비스·볼륨을 재사용하지 않고 검사가 만든 컨테이너만 정리한다. 이미 실행한 검사와
남은 범위는 해당 변경의 검증 기록에서 확인한다. 구조 리팩터링은 [검증 보고서](REFACTOR_REPORT.md),
현재 공급자 확장·저장 이력·인증서는 [공급자 인벤토리 구현 기록](PROVIDER_INVENTORY_IMPLEMENTATION.md)의
대상 코드·후속 검증 절을 따른다. 이전 Docker 산출물의 검증을 새 소스 이미지의 검증으로 쓰지 않는다.

회귀 검사 선택 예:

```bash
python -m pytest cremore/api/library_boundaries_test.py cremore/api/request_boundary_test.py -q
python -m pytest cremore/scanning/scope_test.py cremore/worker/runtime_test.py -q
python -m pytest cremore/sources/module_contract_test.py cremore/domain/connections_test.py -q
python -m pytest cremore/coverage/collector_runtime_test.py cremore/api/metadata_comparison_test.py -q
python -m pytest cremore/coverage/providers/metadata_resume_test.py cremore/coverage/gcp_integration_test.py -q
python -m pytest cremore/coverage/provider_worker_integration_test.py cremore/coverage/metadata_linkage_test.py -q
python -m pytest cremore/coverage/coverage_test.py cremore/coverage/vault_management_models_test.py -q
python -m pytest cremore/coverage/storage_receipts_test.py cremore/api/storage_receipts_test.py cremore/coverage/certificate_coverage_test.py -q
python -m pytest cremore/governance/tickets_test.py cremore/remediation/action_plans_test.py -q
(cd web && npm run test:browser -- console-notion-rows console-receipts console-rescan)
(cd web && node --test tests/console-targets.test.cjs tests/scan-scope.test.cjs)
```

브라우저 proof는 합성 fixture지만 실제 React·컴파일된 CSS를 사용한다. 문자열 검사만으로
opacity/focus/overflow/contrast가 맞다고 결론 내리지 않는다. Chrome 설치가 필요하다.
`.github/workflows/ci.yml`의 PR quick checks와 수동 full workflow를 구분한다.
PR에는 컨테이너 취약점 검사도 포함한다. release는 각 컴포넌트의 실제 빌드 digest를
검사·서명한 뒤 그 digest로 Helm/Compose 배포 묶음을 만든다. 로컬 원본 템플릿의 태그는
개발 호환용이며 서명된 release 배포 증거를 대신하지 않는다. Caddy를 바꾼 release 묶음은
운영자가 승인한 `CREMORE_CADDY_SHA256`도 명시해야 한다.
push trigger는 없으므로 `refactoring`에 코드를 게시했다고 전체 CI가 실행되지는 않는다.
머지할 대상 ref를 선택해 수동 workflow를 실행하고 해당 커밋의 결과를 확인한다.
수동 Python job은 격리된 PostgreSQL 17 service와 GCP·Azure 선택 의존성을 준비하고,
플랫폼 검사 뒤 독립 GitLab/GCP suite를 각각의 패키지 디렉터리에서 실행한다.
이 CI 설정을 추가한 것과 해당 commit의 원격 실행이 통과한 것은 별도로 보고한다.
기존 benchmark 파일은 당시의 고정 corpus 증거다. 새 실행 없이 성능 개선 수치로 재사용하지 않는다.

보안 경계 후속 계약(2026-10-03): OIDC의 외부 JWKS는 정확한 `OIDC_JWKS_URL`로 승인하며,
기본은 issuer origin과 Google의 정식 키 주소만 허용한다. redirect는 따르지 않는다.
API 목록의 cursor·개수·종속 행 제한은 [API 문서](API.md#bounded-compatibility-lists-and-private-evidence)를 따른다.
내부 전체 조회를 쓰는 승인/과거 작업 예약 검사를 API 페이지 크기로 잘라서는 안 된다.
구형 rotation 쓰기 API는 읽기 전용 이력으로 남기고 승인된 ActionPlan 경로만 실행한다.
GitHub 외부 수집기 제출은 각 identity/subject/target의 native key 자체가 승인 범위에
묶여 있어야 한다. 전역 ID에 제출자가 붙인 scope·조회 경로는 근거가 아니며,
이 ID를 포함한 전체 수집은 서버 worker를 사용한다([GitHub 제출 제한](../github/README.md)).
GitHub 알림 전용 작업도 조회 전과 저장 트랜잭션 안에서 현재 연결의 중지·철회·인증 참조를 검사한다.

탐지는 후보 10,000개·누적 후보 1 MiB·개별 매치 64 KiB·문맥 1 KiB 한도를 적용한다.
원문이 포함될 수 있는 공급자 사실도 공통 secret-aware 정규화를 통과해야 한다.
기존 evidence를 수정하지 않고 구형 문맥은 공개 projection에서 숨기며 엔진 epoch 변경으로
새 스캔에서 passive 탐지 캐시를 다시 평가한다. 캐시 결과는 현재 코드의 계약을 우회하지 않는다.
호환 연결 전체 스캔도 공급자 요청마다 취소·현재 승인·1시간 실행 한도를 확인한다.
수집 cursor는 최대 8 KiB이고 중첩/연속 목록을 합쳐 10,000개까지 받으며 이력에는 digest만 남긴다.
미지원 파일·부분 수집은 깨끗한 완료나 watermark 진전의 근거가 아니다.
자동 RESUME는 승인·인증이 현재이고 fenced checkpoint가 실제 진전한 S3의
BASELINE/DELTA/RECONCILE만 지원한다. 이벤트·non-S3·진전 없는 작업은 부분 결과를 유지하며
범위/예산을 확인한 새 수동 스캔이 필요하다. S3 LIST에서 변경되지 않은 파일로 보고되어도
저장된 노출 revision과 정확히 일치해야 관측 시각을 갱신한다.

## 11. Common Recipes

### Backend feature

먼저 `rg`로 같은 규칙·presenter·repository 메서드를 찾는다. 도메인 규칙은 해당 서비스,
HTTP 등록은 기존 `api/routes/` 기능 파일, 응답은 기존 presenter에 둔다. `DashboardContext`의
실제 의존성만 추가한다. 역할·잘못된 입력·성공·legacy 응답·경쟁 요청을 검사하고 API 문서를 갱신한다.
단순 HTTP feature에 새 microservice나 repository interface를 만들지 않는다.

### React component

연결 흐름은 `web/console/views/integrations/`, Credential 목록·패널은 `web/console/views/credentials/`에서 기존 컴포넌트를 찾는다.
순수 타입을 재사용하고 props로 데이터·callback을 전달한다. Loading/실패/빈 상태와 KO/EN,
light/dark·360px·키보드를 검증한다. 두 화면 이상이 쓰는 domain-neutral UI만
`web/console/ui.tsx`·`layer.tsx`로 승격한다.

### Provider

7절에서 콘텐츠·schema 2 metadata·schema 1 인벤토리/금고·SIEM 중 실제 계약을 선택한다. 콘텐츠 변경은 공급자 모듈과 backend/UI
등록을 소유하고 공통 승인·인증·DB 계약을 추적한다. metadata는 validate→page→저장→native
export→resume과 공통 비교 호출을 fake 응답으로 검증한다. SIEM은 독립 출력 패키지의
send/close·중복 전달·고정 오류 계약을 검증한다. 호환 facade에 공급자 분기를 다시 넣지 않는다.

### 환경변수

`config.py`의 기존 Field alias/validator 패턴을 재사용한다. default와 hard-lock 의미를 정하고
`.env.example`, `docker-compose.yml`, 필요한 Helm values/templates, `domain/domain_test.py`, 배포 render
테스트를 갱신한다. 비밀은 public Next 환경변수에 넣지 않는다. 기존 이름은 몰래 바꾸지 않는다.

### DB field·migration

`domain/models.py`→`db/schema.py`→SQL 변환/memory parity→presenter→frontend 계약을 추적한다.
기존 행의 기본값·NULL·JSON legacy 상태를 명시한다. 데이터 변환이 필요하면 `db/migrations.py`의
번호/backup/오프라인 절차를 따른다. startup에서 파괴적 변환을 자동 실행하지 않는다.

기존 identity migration이 필요한 운영 변경에서만 다음 명령을 사용한다. 먼저 모든 API/worker를
중지하고 복구 가능한 backup을 확인하며, 대상 `DATABASE_URL`은 보호된 환경변수로 전달한다.
기존 identity의 파괴적 migration은 이번 작업에 없다. 발급·저장 이력은 기존 `create_all`의
additive 확장으로 빈 `coverage_storage_receipts` 테이블을 추가하며 기존 테이블/행을 변환하지 않는다.
이전 버전으로 되돌리면 새 테이블을 사용하지 않을 뿐이며 자동 삭제하지 않는다. 위 identity
migration 명령은 이 테이블을 만들기 위한 명령이 아니며 검증용으로 실행하지 않는다.

```bash
python -m cremore.db.migrations --offline --backup-confirmed
```

두 flag는 실행자가 중지·backup을 확인했다는 선언이며 자동 backup 기능이 아니다.
rollback은 이전 소스/image와 검증된 DB backup 복구 절차를 함께 따른다.

### Shared utility·library/package

동일 불변 조건을 가진 실제 호출자 둘 이상을 확인한다. scope identity는 `scanning/scope.py`,
페이지 loop는 해당 provider/독립 package의 기존 collector, byte 표시·번역은 locale 소유자를 사용한다.
`shared/common/helpers`로 도메인 의미를 숨기지 않는다. 새 배포 package 제안에는 소비자·공개
exports·dependency 방향·build/test·버전/호환 정책을 적는다. 독립 배포 요구가 없으면 내부 모듈로 둔다.

### 새 public API

기존 route/method/순서·RBAC·safe error envelope·pagination·export schema를 먼저 기록한다.
추가 항목은 backend/frontend 계약과 문서를 함께 갱신한다. 기존 app alias는 제거하지 않는다.
Python 공개 이름은 실제 `__all__`/문서에 선언하고 import만으로 I/O가 발생하지 않게 검사한다.
현재 npm 앱은 private이며 UI component를 공개 패키지로 publish하는 설정은 없다.
Python release는 `.github/workflows/release.yml`과 `pyproject.toml`을 검토하고 별도 승인된 release 작업으로 수행한다.

## 12. 오픈소스 customization

| 변경 | 실제 위치·방법 | 한계 |
| --- | --- | --- |
| 색상·간격·반경 | `web/app/(console)/console.css`의 `:root` 토큰과 dark 재정의 | 두 테마·실제 computed style 검사 |
| 앱 이름·metadata | `web/app/(console)/layout.tsx`, rail의 brand(`web/console/shell.tsx`) | 로고 파일은 `web/public/`; provider name과 제품명을 혼동하지 않는다 |
| 언어·시각 표시 | `web/console/text.ts`, `web/components/locale.tsx`, `web/components/display-timezone.tsx` | 모든 화면의 표시 계약 유지 |
| 대화상자·공통 UI | `web/console/layer.tsx`(`Modal`·`Drawer`·`Menu`), `web/console/ui.tsx` | props와 focus/close 계약 유지 |
| 스캔·조사 허용 범위 | `config.py` hard-lock 및 관리자 settings | 환경 허용과 관리자 승인 모두 검사 |
| 콘텐츠 공급자·연결 화면 | `<vendor>/backend/`의 공급자 모듈·onboarding descriptor와 공통 registry, 콘솔의 로고·안내 문구 | 신규 인증/scope/schema/kind와 source 인식은 플랫폼 계약 검토 필요 |
| Metadata·인증 | 명시적 metadata adapter/descriptor 등록, OIDC 설정, secretstore root | 콘텐츠와 별도 등록; SIEM 출력 패키지 설치로 수집기를 활성화하지 않음 |
| SIEM 출력 | `cremore.siem` 공개 계약, `cremore.siem_sinks` entry point | 설치·버전 확인·명시적 활성화한 출력 패키지만 로드; 비신뢰 코드 sandbox는 아님 |

Theme 토큰·관리자 설정·provider 주입은 지원하지만, header/sidebar를 외부 component로 바꾸는
공개 override API는 없다. 필요한 경우 해당 source component를 수정하고 browser proof를 실행한다.
SIEM 출력의 실제 생성·send·close 수명과 버전 계약은 [SIEM guide](SIEM_INTEGRATION.md)에 있다.
결제·AI model router나 수집용 외부 플러그인처럼 존재하지 않는 extension point는 만들었다고 기록하지 않는다.

## 13. Naming·협업·금지 패턴·완료 조건

Python은 `snake_case.py`, `PascalCase`, `snake_case()`, 상수 `UPPER_SNAKE`, private `_name`을 쓴다.
플랫폼 테스트는 `*_test.py`와 `test_*.py` 모두 pytest 설정에 포함된다. TypeScript 파일은
`gcp-callback.tsx`/`scan-scope.ts`, component/type는 PascalCase, hook은 `use...`, 함수는 camelCase다.
Node 테스트는 `*.test.cjs`, 브라우저 증명은 `*.browser.cjs`다. 소스에 실제 토큰 모양을 통째로 쓰지 않는다.

여러 agent를 쓸 때에는 사전에 사용자/작업 지침의 허용을 확인한다. 각 작업에 owned boundary,
allowed/forbidden files, public contract, 검증 명령을 지정한다. 같은 shared 파일을 동시에 수정하지 않는다.
예: GCP adapter 작업은 `gcp/backend/cremore_gcp_provider/metadata/`와 해당 테스트를 소유하고, DB schema·다른 provider·
독립 GCP export 형식은 변경하지 않는다. 공통 계약 변경은 coordinator가 통합 전에 검토한다.

콘텐츠 담당자는 해당 `<vendor>/backend/cremore_<vendor>_provider/source.py`·collector와 UI provider 모듈·등록/수집 검사를 소유한다.
metadata 담당자는 해당 adapter·normalization·descriptor·native 계약과 runtime bridge 검사를 소유한다.
SIEM 담당자는 별도 출력 패키지와 전송 테스트를 소유하고 공개 `cremore.siem`만 import한다.
backend/UI registry 통합, 공개 응답/source 인식, DB/schema·active-scan index, 공통 승인·인증·
authoritative 누락 추론, 발견 이벤트의 필드/버전·발신 대기열은 플랫폼 담당자의 책임이다.
기존 출력 계약 안의 새 SIEM은 core 수정 없이 패키지 설치와 목적지 설정으로 추가한다.
새 수집 능력·인증 방식·공개 데이터 계약은 공통 경계 변경이므로 협의 없이 provider에서 우회하지 않는다.
공급자별 branch/worktree를 쓰고 공통 계약 변경을 먼저 통합한 뒤 각 어댑터의 회귀를 합친다.

실제 작업 카드 예시(새 기능 구현 지시가 아닌, 범위·인수 조건 작성 형식):

```text
Title: GitHub metadata adapter의 다음 페이지 오류 회귀 수정
Goal: 페이지 저장 실패 시 마지막으로 commit된 cursor와 PARTIAL 근거를 보존한다.
Owned boundary: schema 2 GitHub metadata 수집기
Allowed files: github/backend/cremore_github_provider/metadata/* 및 해당 provider 회귀 테스트
Forbidden files: db/schema.py, 다른 provider, 독립 CLI, web/, 배포 설정
Contract: collect_pages/MetadataPage, host와 설치별 token 범위, 예산·cursor commit 순서 유지
Approach: 모든 collect_pages 호출자와 replay 검증을 읽고 기존 transport/error helper 재사용
Validation: 실패하는 synthetic regression → 수정 → 동일 검사와 metadata_resume_test.py
DoD: 수정 전 실패/후 통과, 기존 API/export 형식 유지, 원문 로그 없음, 파일·검증 결과 보고
Handoff: 공통 MetadataPage 변경이 필요하면 해당 수정 전에 coordinator에게 영향과 대안을 보고
```

금지: vendor SDK의 domain 침투, React feature를 pure lib에서 import, app/dashboard로 역참조,
몰래 바꾸는 API/DB schema/env 이름, blanket exception 성공 처리, 불완전 수집을 삭제로 판정,
raw error/body 로그, static inline style 확산, CSS 전역 dump, 검증을 피하려는 테스트 삭제,
의미 없는 package/framework 교체, 파일 이동이나 공백 삭제를 중복 제거로 보고하는 행위.

Done은 실제 소유자에 구현됨, 기존 패턴 재사용, 모든 호출자/저장/public 계약 검토, 필요한
회귀·정적·build·UI 검사, 문서/예제/설정 일치, 실행하지 못한 검사의 공개, secret/diff 확인이다.
새 dependency는 기존 기능 중복·유지보수·보안·라이선스·bundle/runtime/설치 부담을 설명한다.
Python은 `pyproject.toml`, frontend는 `web/package.json`과 `package-lock.json`을 함께 갱신한다.

## AI Agent Quick Start

1. 이 문서와 해당 `AGENTS.md`를 읽고 작업 전 `git status --short --branch`를 확인한다.
2. 관련 service·모든 호출자·모델·presenter·테스트를 `rg`로 찾아 동작과 불변 조건을 먼저 추적한다.
3. 신규 Python은 기존 도메인/API/provider 소유자에, 화면은 `web/console/views/`의 해당 화면에 둔다(공급자 폴더에는 UI를 두지 않는다).
4. public package entry와 실제 책임 모듈을 import한다. 화면→순수 lib 방향을 유지한다.
5. provider는 공통 runtime 계약과 명시적 등록을, shared 코드는 실제 중복 호출자와 기존 소유자를 사용한다.
6. 10절에서 영향에 맞는 작은 회귀 검사를 먼저 실행하고 필요한 전체 검증으로 마무리한다.
7. 결과에는 변경·이유·실행 증거·호환 영향·미검증 환경만 명확히 적는다. 완료를 추정하지 않는다.
