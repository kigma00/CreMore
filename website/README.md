# website 공급자 소유 영역

회사가 DNS로 소유를 확인한 도메인([도메인 검증](../docs/DOMAIN_VERIFICATION.md))의 웹사이트에서 비밀값을 찾는
외부 노출 검사를 소유한다. 시작 페이지의 HTML, 페이지가 불러오는 JavaScript, 스크립트의 소스맵에 담긴 원본 소스를
검사한다. Python 구현과 전용 테스트는 `backend/cremore_website_provider/`에 있고 제품의 Python wheel 하나에 함께
설치된다. 전용 UI는 없다. 콘솔이 연결 카탈로그(`cremore/onboarding/catalog.py`)의 descriptor로 마법사를 그린다.

루트에서 `python -m pip install -e ".[dev,gcp,azure]"`로 개발 설치 후
`python -m pytest website/backend -q`로 전용 합성 회귀를 실행한다. 테스트는 합성 DNS와 `httpx.MockTransport`
사이트만 쓰며 실제 사이트·DNS에 요청하지 않는다.

[공통 AGENTS](../AGENTS.md), [팀 지침](../docs/AI_TEAM_CODING_GUIDE.md),
[실제 디렉터리·등록·빌드 경계](../docs/PROVIDER_DIRECTORY_REVIEW.md)를 먼저 읽는다.
확인된 도메인 목록과 재확인은 플랫폼의 `cremore/domains.py`가 소유한다.

## 연결 마법사

| 항목 | 계약 |
| --- | --- |
| 시작 | 연동 서비스 > 기타 설정 > 도메인 검증의 **검사 연동하기**. 서비스 목록에는 없고(descriptor `entry: "domains"`), 확인된 도메인을 채운 마법사가 열린다 |
| 대상 | 확인된 도메인(20개까지)과 시작 페이지(한 줄에 하나, 도메인마다 20개까지, 비우면 `https://<도메인>/`). 시작 페이지는 그 도메인이나 하위 도메인의 http(s) URL이며 사용자 정보는 받지 않고 fragment는 지운다. 각 페이지는 가장 가까운 도메인에 속한다 |
| 인증 | 없음(`none`). 로그인해야 보이는 페이지는 읽지 않는다 |
| 권한 점검 | `domains_verified`: 모든 도메인이 지금 확인된 상태인가. `site_reachable`: 첫 확인된 도메인의 첫 시작 페이지가 검사와 같은 요청 경계·객체 크기 제한(5MiB 또는 설치 제한 중 작은 값)으로 200을 주는가(아니면 `HTTP_<상태>` 또는 아래 거절 코드) |
| 레코드 | 도메인마다 콘텐츠 소스 하나(`Website · <도메인>`, source_type·job kind `website`) |

## 검사

- 도메인 하나가 리소스 하나(`WEBSITE`)다. 시작 페이지를 읽고, HTML이면 페이지가 불러오는 스크립트
  (`<script src>`, `<link rel="modulepreload">`, `<link rel="preload" as="script">`, `<base href>` 반영, 페이지당 200개까지)를
  읽는다. 스크립트의 소스맵(`SourceMap`·`X-SourceMap` 헤더, 없으면 마지막 줄의 `sourceMappingURL`, inline `data:` 맵 포함)에
  `sourcesContent`가 있으면 원본 소스(맵당 2,000개까지)를 하나씩 검사한다. 시작 페이지는 스크립트나 소스맵이어도 된다.
- 위치: 페이지·스크립트는 URL, 소스맵의 원본은 `<맵 URL>!/<소스 이름>`, inline 맵은 `<스크립트 URL>#map!/<소스 이름>`.
- 노출 수준: 요청한 이름의 주소가 모두 공인이면 `public`, 사내 주소면 `internal`이며 finding의 위험도에 쓰인다.
- 링크를 따라 다른 페이지로 가지 않는다. 시작 페이지와 그 스크립트·소스맵만 읽는다.
- 예산: 실행당 스크립트 `max_assets`(1–1000, 기본 200), 객체 하나 5MiB(설치의 객체 크기 제한이 더 작으면 그 값),
  실행 전체 50MiB와 30분, 스코프 실행의 공유 요청 예산. 예산 때문에 읽지 않은 것은 실패로 세어 부분 실행이 된다.
- 확인된 도메인이 덮지 않는 호스트(공개 CDN 등)나 아무도 적지 않은 포트의 스크립트는 회사의 것이 아니므로 읽지 않고
  실패로 세지 않는다. 회사 호스트에서 읽지 못한 스크립트·소스맵, 예산을 넘은 스크립트는 `objects_failed`로 세어 부분
  실행이 된다. 시작 페이지는 관리자가 적은 회사의 것이므로 어떤 거절이든(도메인 확인이 끊긴 경우 포함) 실패로 세고,
  하나도 읽지 못하면 실행이 실패한다(`WEBSITE_UNREACHABLE`).
- 페이지에서 따라가 읽으므로 파일이 사라졌다는 증거가 되지 않는다(`authoritative_listing = False`). 이전 위치를
  없어진 것으로 정리하지 않는다.
- 승인된 스코프의 `paths`·`excluded_paths`는 `/`로 시작하는 URL 경로이며, 슬래시 단위 접두사로 모든 요청
  (시작 페이지·스크립트·소스맵, 리다이렉트의 각 단계)을 제한한다. 비교하는 경로는 서버가 해석하는 경로다: percent 인코딩을
  풀고, `\`와 연속 슬래시를 슬래시 하나로, `.`·`..`을 정리한다(`/x/../admin`, `//admin`, `/%61dmin`은 모두 `/admin`).
  범위 항목도 같은 방식으로 읽는다(`/%EA%B4%80%EB%A6%AC%EC%9E%90/`와 `/관리자/`는 같은 항목). 가장 너그러운 서버의 읽기
  (대소문자, `;` 매개변수, 구간 끝의 점·공백, 이중 인코딩 `%2561`, 전각 문자를 가리지 않음)도 함께 쓴다: 제외 경로는 이 읽기로
  제외하고, 포함 경로는 두 읽기가 모두 포함할 때만 읽는다. `/`로 시작하지 않거나 `?`·`#`가 든 항목은 검사 계획을 만들 때
  막는다(`scope_problem`, `WEBSITE_SCOPE_PATH_INVALID`: 계획이 실행되지 않음). 실행도 같은 항목을 거절한다. 범위 밖 요청은
  읽지 않고 건너뛴다.
- 정확 재검사(`exact_paths`)는 finding 위치의 URL(소스맵 원본이면 맵 URL)을 다시 읽고, 빈 목록이면 아무것도 읽지 않는다.
  플랫폼의 재검사·이벤트 경로 범위 확인은 모듈의 `scope_allows(location, paths, excluded_paths)`로 실행과 같은 판정을
  쓴다. 범위 항목이 잘못됐으면 재검사도 `WEBSITE_SCOPE_PATH_INVALID`로 거절한다.
- 위치는 URL의 query·fragment를 뺀 값으로 남긴다. 링크의 query에 토큰이 있을 수 있고 위치는 finding·API·SIEM에 실린다.
  그래서 재검사는 query 없이 다시 읽는다.

## 요청 경계

`fetch.py`와 `addresses.py`가 요청마다, 리다이렉트의 각 단계에도 다시 검사한다.

- http·https URL만, 사용자 정보 없이. 호스트는 지금 확인된 도메인이 덮어야 한다. worker가 payload 복사본에
  `domain_cover(host)`(`cremore.domains.covering`)를 넣고 수집기는 요청마다 묻는다. 확인된 지 7일이 지났거나 끊긴 도메인은 덮지 않는다.
- 포트는 스킴의 기본 포트, 또는 그 호스트의 시작 페이지에 적힌 포트만 쓴다.
- 이름은 절대 이름(`acme.com.`)으로 풀어 resolver의 검색 목록이 다른 이름을 답하지 못하게 한다. 풀린 **모든** 주소가
  도메인의 주소 규칙을 통과해야 한다. 공인 주소는 항상, 사설 주소(RFC 1918, `fc00::/7`, `100.64.0.0/10` 등)는 도메인의
  **사내 주소 허용**이 켜졌을 때만 허용한다. 아래는 항상 막는다.
  - 루프백, 링크 로컬(클라우드 메타데이터 `169.254.169.254` 포함), 멀티캐스트, 미지정, 예약, `0.0.0.0/8`, site-local(`fec0::/10`)
  - 플랫폼 주소: Azure `168.63.129.16`, Alibaba `100.100.100.200`, AWS의 IPv6 서비스(`fd00:ec2::/64`: 메타데이터·DNS·
    EKS Pod Identity), Google Cloud의 IPv6 메타데이터 `fd20:ce::254`
  - IPv4를 담은 IPv6는 그 IPv4로 판단한다(mapped, 6to4, NAT64 표준 접두사 `64:ff9b::/96`). IPv4 위치가 망마다 다른
    local-use NAT64(`64:ff9b:1::/48`)와 Teredo는 막는다.
- 프록시가 없으면 연결을 확인한 주소에 고정한다(IPv4 주소를 먼저 고른다). URL에는 주소를, Host 헤더와 TLS 서버 이름·
  인증서 검증에는 호스트 이름을 쓰므로 두 번째 DNS 응답이 연결을 옮기지 못한다. 요청마다 새 연결을 열고
  (`Connection: close`) 다른 이름에 재사용하지 않는다.
- 프록시 사용 여부는 이 모듈만 정한다. worker 환경의 `HTTPS_PROXY`·`HTTP_PROXY`가 가리키고 `NO_PROXY`가 빼지 않은
  호스트만 그 프록시로 이름을 넘기고, HTTP 클라이언트는 환경 변수를 읽지 않는다. 스킴 없이 적은 프록시(`proxy.corp:3128`)는
  http 프록시로 읽고, 쓸 수 없는 프록시 값은 `PROXY_INVALID`다. 프록시가 이름을 다시 풀므로 연결을 고정하지 못한다.
  이때 도달 범위는 프록시의 규칙이 정한다.
- 인증서는 설치의 신뢰 저장소(certifi)로 검증한다. `SSL_CERT_FILE`·`SSL_CERT_DIR`을 주면 그 파일이 저장소를 **대신**하므로,
  사내 CA를 쓰려면 공개 CA와 사내 CA를 함께 담은 번들을 지정한다. 관리자가 적은 http 시작 페이지도 읽지만, https에서
  http로 가는 리다이렉트는 따르지 않는다(`REDIRECT_DOWNGRADE`).
- GET만, 로그인·자격증명 없이 보낸다. 사이트가 준 쿠키는 보관하지 않는다. 리다이렉트는 5번까지 따른다.
- 응답은 받은 그대로 읽는다. `identity` 또는 온전한 gzip 멤버 하나만 받고(gzip은 크기 제한 안에서만 풀고, 멤버가
  끝나면 그 뒤는 읽지 않으며, 중간에 끊긴 멤버는 페이지로 보지 않는다) 그 밖의 인코딩(br, zstd, 여러 겹)은 거절한다
  (`ENCODING_NOT_ALLOWED`). 서버가 정한 문자 집합은 적용하지 않는다.
- 응답 하나는 요청부터 마지막 바이트까지 60초 안에 끝나야 하며, 넘으면 연결을 끊고 그 응답은 쓰지 않는다(`SITE_TOO_SLOW`).
  읽기마다 20초 제한도 따로 있고, Windows에서는 이미 기다리던 읽기가 이 20초만큼 늦게 끝날 수 있다. 모든 요청은 실행의
  요청 예산을 먼저 쓰므로, 범위 실행에서는 취소·승인 철회·리스 상실도 다음 요청 전에 알아챈다.
- 거절은 고정 코드다: `URL_NOT_ALLOWED`, `HOST_NOT_VERIFIED`, `PORT_NOT_ALLOWED`, `PATH_NOT_ALLOWED`, `HOST_NOT_RESOLVED`,
  `ADDRESS_NOT_ALLOWED`, `PROXY_INVALID`, `REDIRECT_DOWNGRADE`, `TOO_MANY_REDIRECTS`, `ENCODING_NOT_ALLOWED`, `TOO_LARGE`,
  `SITE_TOO_SLOW`, `SITE_UNAVAILABLE`. 사이트의 응답 본문은 코드·로그에 남기지 않는다. worker는 요청 URL을 남기는 httpx 로그를 끈다.
- 페이지 해석은 입력 길이에 비례한다. URL로 읽을 수 없는 링크는 건너뛰며 페이지 전체를 실패시키지 않는다. 소스맵 주석은
  길이와 관계없이 스크립트의 마지막 줄에서 찾으므로 inline 맵도 읽는다.

## 한계

- 로그인 뒤 페이지, 실행 중에 불러오는 스크립트(동적 import·웹 워커), 다른 페이지로 가는 링크, sitemap은 읽지 않는다.
- 실제 사이트·DNS·프록시로는 검증하지 않았다. 실환경에서 확인할 것: 주소로 고정한 연결의 TLS 서버 이름과 인증서
  검증(공개 CDN·사내 CA), 프록시 환경, IPv6만 있는 사이트, 큰 소스맵, 60초 제한으로 연결을 끊는 동작.
