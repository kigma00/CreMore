# notion 공급자 소유 영역

신규 온보딩은 Free/Plus/Business와 Enterprise를 인증 전에 구분한다. 일반 요금제는 내부 연결 토큰(이전 이름: 내부 통합)의
계정 인증을 저장한 뒤 별도 콘텐츠 카드에서 같은 토큰으로 공유된 페이지를 선택한다. 계정 저장 시
검사 작업은 생기지 않는다. Enterprise도 이 페이지 읽기 경로를 사용하며, PAT·MCP 인벤토리는 별도의
조직 봇 토큰과 scope가 필요하다. 기존 요금제 미기록 `cloud` 연결은 유지보수하되 신규 선택에서는 제외한다.
조직 봇 인증은 PAT 또는 MCP 읽기 중 허용된 endpoint로 확인하며 불필요한 사용자 목록 권한은 요구하지 않는다.
PAT 목록이 workspace에 404를 주면 MCP의 빈 성공 응답(모르는·조직 밖 ID도 빈 결과)으로 대신하지 않고 `NOTION_WORKSPACE_NOT_VISIBLE`로
인증과 두 목록 권한을 모두 거절한다.
상세 계약은 [제품 선택·수집 목적 분리](../docs/EDITION_AND_COLLECTION_ONBOARDING.md)를 따른다.

Notion 콘텐츠·리소스 목록·연결 상태 검사와 Enterprise 발급 메타데이터를 소유한다. Python 구현과 전용 테스트는 `backend/cremore_notion_provider/`에 있다.
공통 플랫폼이 해당 라이브러리 함수를 직접 호출하며 제품의 Python wheel 하나에 함께 설치된다.

콘텐츠 검색·중첩 블록 조회의 cursor는 하나당 UTF-8 8 KiB, 수집기 전체에서 총 10,000개로 제한한다.
중복 이력은 메모리의 고정 길이 지문만 남긴다. 순환·한도 초과는 검색 실패 또는 페이지 부분 수집으로 남긴다.

## Markdown 우선 콘텐츠 검사 (2026-10-06, 2026-10-09 갱신)

승인된 각 페이지는 `GET /v1/pages/{id}/markdown`으로 읽는다. 기본 `Notion-Version`은
`2026-03-11`이며 `page_markdown` 응답의 페이지 ID·`markdown`·`truncated`·`unknown_block_ids`를
검사한다. 세 개의 fetch worker가 본문을 병렬로 읽고, 결과는 원래 페이지 순서대로 탐지·저장한다.
승인·취소·리스 확인과 요청 예산 차감은 소유 스레드에서 실행한다. DB 세션을 fetch worker에 공유하지 않는다.
런타임은 Notion root를 페이지 하나씩 나누어 실행하므로 페이지 하나의 비용이 곧 검사 시간을 정한다.

| 페이지 하나의 요청 | 경우 |
| --- | --- |
| 1회 (Markdown) | 실행 계획의 검색 메타데이터(`page_meta`)에 그 페이지가 있을 때 |
| 2회 (헤더 + Markdown) | 메타데이터가 없을 때(EVENT 실행, 검색에서 찾지 못한 페이지, 계획 검색 실패) |
| 0회 | delta 실행에서 5분 이내에 관측한 메타데이터가 변경 없음을 보일 때 |
| 위 + 블록 조회 + 헤더 1회 | 실제 탐지가 있어 블록 위치를 보강할 때 |

- 완전한 Markdown에는 Block API를 호출하지 않는다. 실제 탐지가 있는 페이지에만 기존 최대 깊이 2의
  블록 조회를 추가하고, 동일 리비전에서 원문 탐지 줄 전체가 유일한 블록에 정확히 포함될 때만
  `notion_block_id`를 보강한다. 가린 힌트·이름 유사성·디코딩된 줄 번호로 연결하지 않는다.
  모호하거나 조회가 실패해도 기존 탐지를 유지한다. 페이지의 location·page ID·scope epoch는 유지한다.
- Markdown 실패·잘림·알 수 없는 블록에는 승인된 페이지의 블록 조회로 대체한다. `truncated=false`·`unknown_block_ids=[]`여도
  본문에 `<unknown …/>`(북마크·임베드·템플릿 등 Markdown이 표현하지 못한 블록)가 있으면 같은 대체 경로를 쓴다. 부분 Markdown도
  메모리에서 함께 검사하고, `unknown_block_ids`가 있으면 권한 누락일 수 있으므로 부분 수집으로 남긴다.
  바이트·깊이·페이지·요청·cursor 한도에 닿거나 블록/리비전 조회가 실패해도 완료로 올리지 않는다.
  Markdown의 임의 URL이나 알 수 없는 block ID를 따라가지 않으며 child page/database 본문은 별도 승인 대상이다.
- 본문을 읽은 뒤 페이지 헤더를 다시 읽지 않는다(2026-10-09). 실행의 watermark는 페이지 작업의 시작 시각이고
  다음 delta 실행은 그 watermark에서 overlap을 뺀 시각 이후 수정된 페이지를 다시 읽으므로, 본문을 읽는 동안 생긴
  편집은 다음 실행이 읽는다. Notion 수정 시각은 분 단위라 같은 분 안의 편집은 재확인으로도 잡지 못했고 요청만
  하나 더 들었다. 탐지 후 블록 보강은 블록을 읽은 뒤 헤더를 다시 확인하고, 리비전이 바뀌었으면 블록 위치를 붙이지
  않고 재시도 대상으로 남긴다. 404·검색 누락·부분 수집은 삭제나 깨끗한 페이지의 근거가 아니다.
- 실행 계획의 검색 메타데이터가 있으면 페이지 헤더를 읽지 않고 그 제목·URL·수정 시각(리비전)을 쓴다.
  `search.plan_metadata`가 계획 단계에서 검색을 한 번 순회해 승인 페이지의 헤더를 모으고, worker 런타임
  (`cremore/worker/runtime.py`)이 실행을 계획할 때 분할된 페이지 root에 `page_meta`로 붙인다. 형식이 맞지 않는
  항목은 무시하고 그 페이지는 자기 헤더를 읽는다. 탐지가 있어 블록을 보강할 때 읽는 새 헤더의 URL·제목으로
  위치를 고쳐, 검색 뒤 이름이 바뀐 페이지도 현재 위치로 기록한다.
- delta 실행은 수정 시각이 `watermark_since`(이전 실행 시작 − 5분)보다 12분(`LOOKBACK`) 더 이전인 성공
  페이지만 생략한다. 12분은 검색 색인 지연 10분(`SEARCH_LAG`), Notion이 수정 시각을 분 단위로 내림하는 60초
  (`EDIT_ROUNDING`), worker와 Notion의 시계 차이 60초(`CLOCK_SKEW`)를 더한 값이다. 메타데이터로 생략을 정하려면
  그 메타데이터가 5분(`META_FRESH`) 이내에 관측된 것(`observed_at`)이어야 하고, 더 오래되었거나 관측 시각이
  없거나 30초보다 더 미래이면 페이지 헤더로 판단한다. 메타데이터로 생략한 실행의 watermark(작업 시작)가 놓칠 수
  있는 편집은 그 watermark − (5분 + 10분 + 60초 + 60초) 이후로 보고되고, 다음 delta 실행은 watermark − (5분 + 12분)
  이전 페이지만 생략하므로 그 편집을 읽는다. 이 관계(`META_FRESH` ≤ 런타임 overlap)는
  `cremore/scanning/changes_test.py`가 검사한다. 헤더로 판단할 때도 같은 여유를 둔다. 이전 실패 페이지는 수정
  시각과 관계없이 다시 읽고 실패 ID를 유지한다. 검색 범위(기존 `notion` 작업)는 수정 시각 내림차순 검색 결과를
  헤더로 쓴다.
- 같은 token과 API origin의 모든 Notion 호출이 연결 제한기(`collectors/requests.py`의 `connection_limiter`)를 거친다:
  수집기의 검색·헤더·Markdown·블록·재확인, 계획 검색과 change feed 검색, 리소스 목록(`catalog.py`), 연결 상태
  검사(`credential_check.py`), 노출 페이지 편집자 조회(`context.py`), 연결 마법사의 인증·권한 점검(`onboarding.py`).
  worker 스캔 안에서는 같은 DB를 쓰는 worker 사이에서 2.5 requests/sec 간격을 공유하고, 그 밖에서는 프로세스 내
  제한기를 쓴다. 429/529는 `Retry-After`만큼 연결 전체에 cooldown을 걸고(`paced`) 최대 세 번 시도하며, cooldown
  합계가 10초를 넘는 지시는 기다리지 않고 그 응답을 실패로 남긴다. 일반 요청 간격을 기다린 시간은 이 10초에
  넣지 않는다. 대기 중에도 취소를 확인한다.
  `ScanStore.request_delay`는 원문 token 대신 origin+token의 SHA-256 키와 DB 시각으로 요청 간격과 cooldown을 예약한다.
  다른 DB의 설치와 같은 workspace의 다른 token까지 합산하는 제한은 아니며 공급자의 429를 최종 제한 신호로 따른다.
  Enterprise Admin API(발급 목록 수집·PAT 폐기)는 schema 2 수집기와 조치 계약의 자체 간격·대기 처리를 따른다.
- 리소스 목록은 `Notion-Version: 2022-06-28`을 유지한다. 2025-09-03부터 검색이 데이터베이스 대신 데이터 소스를
  돌려주고 데이터베이스 행의 parent가 데이터 소스가 되어, 기존 승인 범위의 `NOTION_DATA_SOURCE` ID와 행의
  `parent_id`가 바뀌기 때문이다. 계획 검색과 change feed는 페이지의 ID·URL·제목·수정 시각만 읽으며 이 필드는
  2026-03-11에서도 같은 형태다([업그레이드 안내](https://developers.notion.com/docs/upgrade-guide-2025-09-03)).
- 승인된 참조 확인(resolve-reference)은 페이지·데이터베이스 조회가 모두 403/404일 때만 접근 거절 항목을 만든다. 인증 오류·
  429·5xx·통신 실패·해석할 수 없는 응답은 `NOTION_REFERENCE_FAILED`로 작업을 실패시키고 기존 리소스 행을 덮어쓰지 않는다.
- 연결 점검의 공유 페이지(`pages_shared`)는 검색이 성공했을 때만 판단한다. 검색이 실패하면 `NOT_REPORTED`와 실패 사유로 남기고
  "공유된 페이지 없음"으로 보고하지 않는다.

### 계획 검색 메타데이터 (`search.plan_metadata`)

`POST /v1/search`(page 필터, 수정 시각 내림차순, 100개씩, `Notion-Version: 2026-03-11`)를 한 번 순회한다.
승인 ID는 root마다 페이지 ID(PAGE_ONLY가 아니면 승인된 하위 페이지 포함), 데이터 소스의 승인된 행,
`exact_page_ids`가 있으면 그 ID다. 모든 승인 페이지를 찾으면 멈추고, 요청은 승인 페이지 수 A에 대해 최대
min(ceil(A/100)×3+10, A)회다(아낄 수 있는 헤더 읽기보다 많이 쓰지 않는다). 승인된 페이지만
`{대시 없는 소문자 페이지 ID: {url, title, last_edited_time, observed_at}}`로 돌려준다. Notion 검색이 실패하거나
모르는 형태로 답하면 `{}`를 돌려 페이지별 헤더 읽기로 돌아가고, 실행 자체의 중지(취소·예산·리스 상실)는
그대로 전달한다. 토큰·본문은 담지 않는다.

콘솔의 페이지 선택은 하위 페이지를 고르는 화면이 없어 `PAGE_ONLY`로만 저장한다(‘하위 페이지 포함’ 전환 없음). 기존
`PAGE_WITH_DESCENDANTS` root의 명시적 `descendant_ids`는 그대로 쓰고, 비어 있으면 그 페이지만 읽으므로 ‘이 페이지만’으로 표시한다.
변경 웹훅도 같은 규칙으로 `PAGE_ONLY` root에 남은 `descendant_ids`를 무시한다.

### 변경 감지 (`search.changes_since_batch`)

플랫폼 change feed 폴링(`cremore/scanning/changes.py`)이 source 모듈의 이 함수를 자동으로 찾는다. cursor는 이전
폴링의 시작 시각이다. 폴링마다 검색을 수정 시각 내림차순으로 한 번 순회하고, 가장 오래된 cursor에서 15분을 뺀
시각보다 오래된 결과가 나오면 멈춘다(색인 지연 10분 + 분 단위 내림 60초 + 시계 차이 60초 = 12분에 여유를 둔 값).
각 root는 자기 cursor − 15분 이후 수정된 승인 페이지만 받으며, 이 ID는 `page_ids` 이벤트가 되어
`exact_page_ids` EVENT 실행으로 그 페이지만 읽는다(페이지당 헤더+Markdown 2회). 처음 보는 root는 이번 폴링 시각만
기록한다. 순회가 중간에 멈춰도 읽은 결과 중 가장 오래된 수정 시각보다 구간이 늦게 시작하는 root는 그대로 답한다.
나머지 root는 요청 예산이 떨어졌거나 Notion이 구간에 닿기 전에 목록을 끊었으면(`request_status: incomplete`)
root 전체를 delta로 읽고 cursor를 앞으로 옮기며(`NOTION_FEED_BUDGET`·`NOTION_SEARCH_INCOMPLETE`), 검색이
실패했으면 cursor를 그대로 두고 다음 폴링이 같은 구간을 다시 읽는다. cursor가 이틀(설정 가능한 가장 긴 폴링
간격인 하루보다 긴 값)보다 오래되었거나 읽을 수 없어도 root 전체를 delta로 읽는다. 아무 일도 생기지 않은 폴링은
cursor만 옮기고 마지막 변경 기록(`changed_at`·`last_mode`)은 남긴다. 승인되지 않은 페이지는 범위를 넓히지 않으며,
검색에 없다는 사실로 삭제를 추정하지 않는다. 15분 겹침 안에서 이미 읽은 편집은 다음 폴링에서 다시 읽힐 수 있다.

공식 근거: [Retrieve page as Markdown](https://developers.notion.com/reference/retrieve-page-markdown),
[Request limits](https://developers.notion.com/reference/request-limits),
[Block children](https://developers.notion.com/reference/get-block-children).
현재 문서는 일반 연결 180 requests/minute, Business/Enterprise 600 requests/minute와 workspace 공유 한도를
설명한다. 제품은 이보다 보수적인 2.5 requests/sec를 사용하고 서버의 429를 최종 제한 신호로 처리한다.

오프라인 성능 비교는 `python -m scripts.benchmark_notion_markdown --pages 500 --latency-ms 5`로 실행한다.
가짜 HTTP와 실제 탐지 엔진을 사용하며, 페이지당 중첩 그룹 4개와 탐지 페이지 비율 10%의 고정 합성 데이터다.
기본 wall time에는 API pacing을 적용하지 않는다. `--pages 5 --paced`는 같은 제한기를 실제 시간으로 실행한다.
원문 본문·실제 token·고객 자료를 파일이나 로그에 남기지 않는다.

요청 수는 `python scripts/benchmark_notion_markdown.py --pages 500 --changed 5 --assert`로 센다. 런타임처럼
페이지마다 수집기를 따로 만들고 가짜 HTTP의 요청을 센다. 2026-10-09 결과는 계획 메타데이터가 있는 전체 검사
505회(공유된 500페이지가 모두 승인 페이지라 검색 5회가 승인 페이지를 모두 찾는 경우, 페이지당 1.01회,
2.5 requests/sec 기준 202.0초), 메타데이터가 없는 전체 검사 1,000회(400초), 5페이지 변경 검사 11회(change feed
검색 1회 + EVENT 읽기 페이지당 2회, 4.4초)다. 승인된 500페이지가 공유된 5,000페이지에 고르게 흩어진 경우는
검색 상한 25회가 최근 수정된 절반만 찾아 775회(페이지당 1.55회, 310.0초)다. 이 값은 요청 간격만으로 계산한
최소 시간이며 실제 Notion 응답 시간·429·색인 지연·블록 보강은 포함하지 않는다.

아래는 이전 측정(2026-10-06 Windows 합성 실행)의 wall time이다. OS scheduling과 다른 작업 부하에 따라 바뀌며,
첫 행의 초 단위 결과를 실제 API 검사 시간으로 사용하지 않는다.

| 합성 조건 | 순차 블록 | Markdown / 3 worker | 동일 탐지 수 |
| --- | ---: | ---: | ---: |
| 500페이지, 요청당 5 ms 지연, API pacing 제외 (통합 후 재실행) | 17.4200초 | 3.8621초 | 50 |
| 5페이지, 요청당 5 ms 지연, 실제 2.5 requests/sec pacing | 12.2976초 | 6.6164초 | 1 |

당시 실측한 요청 수는 500페이지에서 기존 순차 블록 전략 3,005회, Markdown/3 worker 전략 1,305회이며
두 전략 모두 50개 탐지를 찾았다. 당시에는 본문 뒤 리비전 재확인이 있어 탐지가 전혀 없어도 검색 범위 500페이지는
1,005회(401.6초), 명시적 ID 범위는 1,500회(599.6초)가 필요했다. 재확인을 없애고 계획 메타데이터를 쓰는 지금은
검색이 승인 페이지를 모두 찾을 때 명시적 ID 범위 500페이지가 505회(202.0초)다. 이는 요청 간격만으로 계산한
최소 시간이며 실제 Notion 완료 시간 측정이 아니다. 실제 API 권한·지연·429·문서 크기는 합성 검증 범위 밖이며
별도로 승인된 환경에서 확인한다.

이 폴더에는 UI가 없다. 연결 화면은 `backend/`의 onboarding descriptor로 콘솔(`../web/console/`)이 그린다.

루트에서 `python -m pip install -e ".[dev,gcp]"`로 개발 설치 후
`python -m pytest notion/backend -q`로 전용 합성 회귀를 실행한다.
실제 호출은 별도로 지정한 환경·범위에서만 수행한다.

[공통 AGENTS](../AGENTS.md), [팀 지침](../docs/AI_TEAM_CODING_GUIDE.md),
[실제 디렉터리·등록·빌드 경계](../docs/PROVIDER_DIRECTORY_REVIEW.md)를 먼저 읽는다.
UI 작업에는 [web 지침](../web/AGENTS.md)과 설치된 Next 문서도 적용한다.
공통 API·DB·권한·scope·작업 수명·SIEM 계약과 registry는 플랫폼 담당자와 나누어 작업한다.

## 노출 페이지의 마지막 편집자

`context.py`의 `exposure_context`는 노출이 확인된 페이지(수집 때 남긴 `page_id`)를 콘텐츠 연결의 통합 token으로 읽는다
(GET만, 요청 4회 예산). 플랫폼의 `finding-context` 작업(`cremore/governance/ownership.py`)이 호출하고 저장은 플랫폼이 맡는다.

- 페이지(`GET /v1/pages/{id}`)의 `last_edited_by`·`last_edited_time`, 그 사용자(`GET /v1/users/{id}`)의 이름과 사람의 이메일.
  사용자 조회에는 통합의 사용자 정보 읽기 권한이 필요하며, 없으면 `FORBIDDEN`으로 남기고 사용자 id만 저장하지 않는다.
- Notion에는 CODEOWNERS가 없고 API가 페이지를 열 수 있는 사람을 알려 주지 않아 둘 다 읽지 않는다.

공식 근거(2026-09-28 확인): [Page object](https://developers.notion.com/reference/page),
[Retrieve a user](https://developers.notion.com/reference/get-user).

## Enterprise 자격증명 메타데이터

`metadata/adapter.py`의 `collect_pages`, `validate_spec`, `validate_record`가 기존 schema 2
`CollectorRuntime`·worker·저장 계약을 사용한다. 콘텐츠 페이지 스캔의 인증과는 별도 연결이다.
설치형 공급자 서버나 별도 DB는 필요하지 않다.

| 설정 | 계약 |
| --- | --- |
| provider / edition / origin | `notion` / `cloud` / `https://api.notion.com` 고정 |
| 인증 | Enterprise 조직 owner가 발급한 organization bot의 bearer token. `secret_refs.token`에 봉인/금고 참조를 저장 |
| 범위 | 하나 이상의 명시적 `workspace` UUID. 조직에서 발견한 모든 workspace를 자동 승인하지 않음 |
| capability / mode | `inventory` / `inventory` |
| 기본 source | `personal_access_tokens` |
| 선택 source | `mcp_client_connections`; 별도 읽기 scope 필요 |
| API 버전 / 페이지 | `Notion-Version: 2026-06-01`, `page_size` 1–100 |

위 schema 2 수집 계약의 `edition=cloud`는 기존 API 식별자이며 일반 요금제 지원을 뜻하지 않는다.
신규 온보딩에서는 `enterprise`에서만 이 인벤토리를 선택할 수 있고, `standard`의 요청은 서버에서도 거절한다.
별도 Enterprise 감사 webhook 수신은 2026-10-05 사용자 결정으로 구현 범위에서 제외했다.

연결 마법사의 **발급 목록 수집**에서 개인 액세스 토큰과 MCP 연결을 각각 선택한다.
기존 연결과 새 연결의 기본값은 PAT만 수집하며, MCP는 명시적으로 선택해야 한다.
MCP만 선택할 수도 있다. 확인 단계는 두 읽기 권한을 독립적으로 점검하며 선택한 목록의 권한만 필수로 표시한다.
단 PAT 목록이 workspace에 404를 주면 두 권한 모두 `MISSING`(`NOTION_WORKSPACE_NOT_VISIBLE`)이어서 MCP만 선택해도 연결되지 않는다.
연결 뒤 **수집 범위·인증 설정**에서 선택을 바꾸면 같은 소유 수집 연결의 `options.sources`가 갱신된다.
MCP 연결 목록은 Enterprise 조직 봇으로 읽는 관리 메타데이터이며, 문서 노출 검사·PAT 폐기 연결에는 추가되지 않는다.

- PAT: `GET /admin/v1/spaces/{space_id}/personal_access_tokens`, `personal-access-token:read`.
  active/expired/revoked를 필터 없이 수집한다. ID·생성자·상태·이름·생성/만료/사용/폐기 시각·폐기 주체를 정규화한다.
  공식 epoch **milliseconds**를 UTC ISO 시각으로 바꾸며 잘못된 값은 원문 없이 누락/부분 수집 근거로 남긴다.
- MCP: `GET /admin/v1/mcp_client_connections`, `mcp-client-connection:read`.
  각 요청에 승인된 `workspace_ids` 필터를 넣고 응답의 workspace도 대조한다. 사용자·client key·기업 관리 여부·
  IdP issuer·workspace를 결합한 안정된 식별자를 사용한다. client 이름만으로 같은 연결로 합치지 않는다.
- 두 endpoint의 현재 OpenAPI에 따라 다음 페이지에는 `cursor`를 사용한다. 일반 소개 페이지의 `start_cursor`
  문구와 차이가 있으므로 endpoint 계약을 따른다. cursor는 URL로 해석하지 않고 고정 GET의 query 값으로만 사용한다.
- 요청/페이지/레코드/응답 바이트 예산과 취소를 검사한다. 429·일시 오류는 `WAITING`으로 반환하고 worker가 재시도한다.
  재시도에도 누적 요청 수를 보존한다. 실패·순환·중복·잘못된 항목을 빈 인벤토리의 증거로 처리하지 않는다.
- 체크포인트는 설정 해시와 실제 저장 레코드/작업 report를 대조한다. 페이지 레코드와 다음 cursor를 함께 반환하며
  플랫폼이 현재 리스 아래에서 원자적으로 저장한다. 레코드 예산 초과 시 미저장 페이지의 cursor를 전진시키지 않는다.
- 원문 PAT·관리 토큰·OAuth access/refresh token은 수집/저장하지 않는다. 원시 응답과 알 수 없는 필드는 보관하지 않는다.
  프로필 이미지 URL은 목적상 제외하고 누락 사유만 기록한다. 이 의도된 제외는 PAT 목록의 완전성을 훼손하지 않는다.
- `native_snapshots`는 저장된 안전한 필드에서 export를 재구성한다. `_compare_runs`는 시점 간 필드 변화와 목록 누락을
  구분한다. 같은 source/workspace의 완료 증거가 없거나 상충하는 report가 있으면 부재를 확정하지 않는다.

PAT 목록 API는 **토큰값이나 발견값과 공유하는 해시를 반환하지 않는다**. creator ID만으로 한 사용자의 여러 PAT 중
하나를 확정하지 않는다. `last_used_at`은 인증 기록이며 최대 시간당 한 번 갱신된다. 상태는 공급자 관측값으로서
현재 실제 인증·실효 권한 검증을 대신하지 않는다. MCP 결과는 연결 목록이며 발급된 모든 개별 access/refresh token이 아니다.
internal connection(이전 internal integration), organization bot token 등은 이 두 API의 전체 수집 범위에 포함되지 않는다.

`proves_completeness`는 정상적으로 종료된 **해당 workspace의 해당 source 목록**만 뜻한다.
모든 Notion 자격증명, 모든 workspace, 금고 미저장 여부를 증명하지 않는다. MCP 목록은 모르는·조직 밖 workspace ID에도 빈
결과를 주므로, 같은 실행의 PAT 목록이 그 workspace에서 한 쪽 이상 응답했거나 MCP 행이 하나 이상 있을 때만 MCP 목록이
완전성을 증명한다. 둘 다 없으면 MCP 보고는 `PARTIAL`(`NOTION_WORKSPACE_UNVERIFIED`)이고 실행도 부분 완료다. 그래서 PAT 읽기
범위 없이 MCP만 수집하는 연결에서 MCP 연결이 하나도 없는 workspace는 계속 부분 완료로 보인다.

공식 근거(2026-09-25 확인): [Admin 소개](https://developers.notion.com/reference/admin/intro),
[PAT 목록/OpenAPI](https://developers.notion.com/reference/admin/list-personal-access-tokens),
[MCP 연결 목록/OpenAPI](https://developers.notion.com/reference/admin/list-mcp-client-connections),
[버전](https://developers.notion.com/reference/admin/versioning).

합성 검증은 `python -m pytest notion/backend/cremore_notion_provider/metadata/tests -q`로 실행한다.
모든 HTTP는 `httpx.MockTransport`를 쓰며 실계정 token을 사용하지 않는다. live Enterprise 인증·라이선스·실제 API 응답은
이 unit suite가 증명하지 않으므로 승인된 고객 환경에서 별도로 확인한다.

## 페이지 변경 알림

일반 연결의 서명된 페이지 변경 알림은 승인된 페이지의 후속 검사를 접수한다.
등록·검증·활성화, 공개 HTTPS 경로와 재전달 계약은 [Notion 변경 알림](../docs/NOTION_CHANGE_WEBHOOKS.md)을 따른다.
위에서 제외한 Enterprise 감사 로그 수집과는 별도 기능이다. 위의 검색 기반 change feed(`search.changes_since_batch`)는
공개 HTTPS 경로 없이도 바뀐 승인 페이지만 읽는다.

## PAT의 승인형 폐기 (`remediation.py`)

발급 목록에 있는 PAT(`pat:{workspace}:{id}`)는 승인된 조치 계획으로 폐기한다
(`DELETE /admin/v1/spaces/{space_id}/personal_access_tokens/{id}`, [공급자 자격증명 조치](../docs/PROVIDER_ACTIONS.md)).
Notion에는 비활성화가 없고 폐기는 되돌릴 수 없다(다시 요청해도 폐기 상태로 남는다). 조치는 워크스페이스 하나를 가리키는 전용
연결(`remediation` 용도, 조직 봇 토큰)로만 한다. 범위는 `personal-access-token:read`와 `personal-access-token:write-high-impact`가
모두 필요하며, 점검은 목록만 읽고 폐기 범위는 첫 실행에서 드러난다. 실행 전후로 토큰을 만든 사람의 목록(`creator_ids`)을
끝까지 읽어 `status`(active·expired·revoked)를 확인하고, 목록 끝까지 없을 때만 없음으로 본다. MCP 연결은 사용자가 다시
연결할 수 있어 자동 조치하지 않는다. 공식 근거(2026-09-30 확인):
[Revoke a personal access token](https://developers.notion.com/reference/admin/revoke-personal-access-token),
[Scopes](https://developers.notion.com/reference/admin/scopes).
