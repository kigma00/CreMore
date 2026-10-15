# 크리덴셜 커버리지: 기존 금고와 노출 결과의 대조

2026-09-19~20 설계를 바탕으로 **2026-09-20 구현 작업까지 반영**했다.
기준은 `develop`의 `6cabc6b`와 현재 작업 트리이며 아직 커밋하지 않았다.
목적은 조직이 이미 사용하는 여러 금고를 연결해 **노출된 자격증명의 보관 근거와
판단할 수 없는 범위를 대시보드에서 구분**하는 것이다. 고객 금고 수집기, 해시 제출 API,
스냅샷 저장, 대조 화면, AWS IAM/CloudTrail 메타데이터 수집을 구현했다.
GitLab·GCP Cloud Storage·Confluence·Bitbucket 콘텐츠 연결도 기존 승인 범위/worker 경로에 추가했다.

최초 요청은 설계 개정이었고, 이후 사용자가 전체 구현과 검증을 요청했다. 아래는
**구현된 코드**, **관측 의미와 제한**, **실제 설치 환경에서 확인할 사항**을 구분한다.
합성 공급자 응답과 로컬 DB/브라우저/배포 구성 검증을 실제 고객 계정·제품 버전의
운영 인증으로 표현하지 않는다. AWS가 반환하지 않는 비밀 원문이나 모든 STS 세션의
전수 목록을 구현 완료 조건으로 삼지 않는다(10장).

실행 안내는 [고객 수집기 운영 문서](../deploy/coverage/README.md), 구현·검증 현황은
8~9장에 있다. 별도의 발급·회전 대장을 만드는 기능은 포함하지 않는다.

---

## 1. 목표와 경계

CreMore는 조직의 콘텐츠에 노출된 자격증명을 찾아 원문 없이 증거·조사·대응을
제공한다. 이 설계는 기존 노출 결과에 **고객 금고의 보관 근거와 관측 한계**를 더한다.
[현재 제품 정의](../README.md), [현재 아키텍처](ARCHITECTURE.md).

답하려는 질문은 다음과 같다.

> Secrets Manager·HashiCorp Vault·OpenBao 등 기존 금고에서 관리하는 값이
> 코드·문서·객체 저장소에도 노출되어 있는가?
> 발견한 노출 중 연결한 금고 어디에서도 보관 근거를 찾지 못한 것은 무엇인가?
> 금고와 노출 양쪽에서 아직 발견하지 못했지만 AWS에 발급되어 있는 자격증명은 무엇인가?
> 무엇은 권한·수집·형식 문제 때문에 아직 판단할 수 없는가?

| 대시보드에서 보고 싶은 상태 | 정확한 의미 |
|---|---|
| 노출됨 · 금고 보관 확인 | 동일한 자격증명 재료를 노출 위치와 현재 금고 버전에서 모두 관측 |
| 노출됨 · 연결 금고에서 미발견 | 선언한 금고 범위의 대조를 완료했지만 일치 근거가 없음 |
| 노출됨 · 보관 판단 불가 | 미연결·권한 부족·부분 수집·해석 불가·오래된 자료 등으로 대조 불가 |
| 금고 보관 확인 · 노출 미관측 | 선택한 스캔 범위에서 일치하는 노출을 관측하지 않음. 조직 전체의 미노출 보장이 아님 |
| AWS 발급 확인 · 금고 보관 근거 미확인 | AWS 목록에서 존재를 확인했지만 금고 보관 근거를 확보하지 못함. 노출 증거가 없어도 조사 대상으로 표시 |

**금고에 보관됨은 안전하게 관리됨 전체를 증명하지 않는다.** 소유자, 최소 권한,
유효성, 회전, 실제 소비자의 금고 사용은 각각 별도 근거다. 기능의 중심은
**Vault coverage / 금고 보관 대조**이며, 퍼센트는 보조 정보다.
“금고에 있으니 노출을 해결했다”, “연결 금고에 없으니 조직 어디에도 관리되지 않는다”고 하지 않는다.
**금고 미발견만으로 관리 누락을 확정하지 않는다.** 역할 기반 임시 자격증명처럼 금고에
저장하지 않는 것이 정상인 유형도 있다. 장기 키의 보관 정책 위반 후보와 구분한다(10장).

경계:

- 탐지·금고 대조 대상의 원문 비밀은 DB·제출 파일·로그에 남기지 않는다. 읽기와 해시는
  메모리에서 수행한다. 이는 Python 메모리의 물리적 zeroization 보장을 뜻하지 않는다.
- 고객 측 해셔가 금고 값을 읽고, **CreMore API/worker에는 안전한 대조 자료만 제출**하는
  B안을 기본으로 한다. 해셔 자체도 CreMore 코드이므로 “어떤 CreMore 프로세스도 값을
  보지 않는다”는 표현은 쓰지 않는다.
- 금고 내용이나 고객 인프라를 변경하지 않는다. 이 기능의 발급·회전·자동 편입은 제외한다.
  기존 승인 기반 remediation 기능까지 없애겠다는 뜻은 아니다.
- 관측 실패는 `UNKNOWN`이다. 판단 불가인 노출을 분모에서 지워 수치를 높이지 않는다.
- 같은 설치의 여러 금고·여러 노출 위치를 대조한다. 서로 다른 고객/설치의 자료는 섞지 않는다.
- 발급자·금고 제품·노출 제공자가 다른 것은 정상이다. 측정 범위가 다른 퍼센트를 합산하지 않는다.
- 기존의 **스캔 범위 커버리지**와 이 문서의 **자격증명 보관 관측률**은 다른 지표다.

---

## 2. 연결의 역할과 측정 단위

| 역할 | 질문 | 데이터 | 이번 설계에서의 위치 |
|---|---|---|---|
| **노출 수집** | 어디에 자격증명이 노출됐는가 | 기존 `credentials` / `exposures` / `findings` | 핵심 입력. 수집 대상 제공자를 확장 |
| **금고 수집** | 기존 금고의 어떤 위치·버전에 같은 재료가 있는가 | 고객 측 어댑터의 보관 관측 | 핵심 신규 입력. 여러 제품·여러 인스턴스 연결 |
| 발급자 조회 | 무엇이 발급되어 있고 현재 어떤 상태인가 | 발급 API·조사 메타데이터 | AWS 미관측 자격증명 발견의 신규 입력. 값 대조의 선행 조건은 아님. 다른 발급자는 별도 선택 |

**발급자·금고·노출 제공자는 별도 차원이다.** GitLab 토큰을 AWS Secrets Manager에
보관하고 Confluence에서 노출할 수 있다. AWS 키가 GitHub에 노출되고 Vault Enterprise와
OpenBao 양쪽에서 관측될 수도 있다. 브랜드가 같아야 대조할 수 있는 구조로 만들지 않는다.
금고와 노출의 credential type·fingerprint 재료가 호환되면 발급 목록 없이 대조한다.

### 2.1 첫 구현의 완료 조건

기존에 발견한 노출을 대상으로, **Secrets Manager와 Vault/OpenBao KV v2의 승인된
범위에서 수집한 보관 근거를 같은 대시보드에 연결**하는 것을 첫 완료 범위로 삼았다.
한 어댑터부터 순서대로 구현할 수 있지만 여러 금고를 함께 대조하는 요구를 후속 옵션으로
밀어내지 않는다. HashiCorp 상용 제품의 namespace도 해당 어댑터의 범위에 포함한다.

- 같은 자격증명이 여러 금고에 있으면 자격증명은 한 번 세고 모든 보관 위치를 보여준다.
- 노출 상세에서 금고 위치·버전·관측 시각과 판단 불가 사유를 확인할 수 있다.
- 금고에 새 값이 생겨도 그 읽기만으로 노출 finding을 생성하지 않는다.
- 금고 수집이 실패하거나 오래되면 미보관으로 단정하지 않는다.
- IAM/PAT/봇 발급 대장이 없어도 위 흐름이 완성되어야 한다.

GitLab·GCP·Confluence·Bitbucket 콘텐츠 수집은 같은 노출 입력을 늘리는 별도 경로로
구현했다. 콘텐츠 연결과 금고 연결은 서로 독립적으로 운영한다.
다만 이 첫 금고 대조만으로 AWS 미관측 자격증명 발견까지 완료했다고 하지 않는다.
그 추가 목표의 최소 범위는 10.4의 IAM 사용자 접근키 메타데이터 수집이다.

### 2.2 보조 지표 — 관측된 노출 중 금고 보관 일치율

- `E`: 선택한 스캔 범위·시점에서 노출이 관측되고 제거가 확인되지 않은 **고유 자격증명** 집합.
- `M`: `E` 중 현재 금고 버전과 정확한 일치 근거가 있는 집합.
- `N`: `E` 중 선언한 금고 범위를 완전히·호환 가능하게 대조했으나 일치하지 않은 집합.
- `U`: `E` 중 현재 보관 여부를 판단할 수 없는 집합.

```text
E = M ∪ N ∪ U  (서로 겹치지 않음)
노출 자격증명의 금고 보관 일치율 = |M| / |E|
```

이는 **전체 발급 자격증명의 관리율이 아니다.** 금고에서만 발견한 자격증명이나
금고 항목 수를 `E`에 더하지 않는다. 동일한 쌍/토큰의 복제본·노출 위치 수로 분모를
늘리지 않으며, 서로 다른 타입/material의 후보를 임의로 합치지 않는다.
10장의 AWS 발급 목록이나 사용 이력에서만 확인한 식별자도 `E`에 넣지 않는다.

기본 조회에서 오탐은 제외하고 적용한 조건을 표시한다. 과거 노출 이력은 별도로 조회한다.
기존 [도메인 모델](../cremore/domain/models.py)의 업무 처리 상태(`workflow_status`)와
위치 제거 관측(`REMOVED`, `all_locations_removed`)은 다르므로 업무를 닫았다는 이유만으로
실제 노출 위치가 없어졌다고 계산하지 않는다. 오래된 노출은 마지막 관측 시각을 표시한다.

퍼센트는 선택한 노출·금고 범위의 수집이 완전하고 최신·호환 가능하며 `U=0`, `E>0`일
때만 표시한다. 그 밖에는 확인·미일치·판단 불가 건수와 수집 범위를 보여준다.
**`|E|-|U|`로 분모를 줄이지 않는다.** 긍정 일치 근거는 다른 금고 수집이 실패해도
해당 위치·시점의 사실로 표시할 수 있다. 현재성과 부재 판정은 5장의 규칙을 따른다.

금고에서만 관측한 재료는 별도 보관 목록으로 보여줄 수 있다. 이때도 “노출 미관측”은
선택한 스캔 범위에 한정되며, 부분 스캔이면 그 한계를 함께 표시한다.

이 저장소의 `reconcile`은 이미 스캔 대상의 현재 상태를 재확인하는 실행 유형이다
([기존 테스트](../cremore/scanning/reconcile_test.py)). 금고 대조를 같은 작업으로 취급하지 않는다.

---

## 3. 노출 수집 제공자와 Enterprise 범위

아래는 **현재 구현한 콘텐츠 제공자와 배포 유형**이다. 코드의 지원 범위와 실제 설치
환경에서 검증할 조건을 구분한다. “Enterprise”를 공통 불리언으로 처리하지 않고 제품·배포 형태·호스트·
버전·권한을 확인한다. 요금제 이름만으로 API 접근이나 조직 전체 가시성을 보장하지 않는다.

| 제공자 / 제품 | 콘텐츠 수집 범위 | 현재 코드와 추가 고려사항 |
|---|---|---|
| AWS | 승인된 S3 bucket/prefix | 기존 수집기 있음. 다중 계정/리전과 실행 신원 경계를 재사용 |
| GitHub.com / Enterprise Cloud | 승인된 저장소·ref·경로 | 기존 수집기 있음. 조직 SSO·App 설치/승인·토큰 정책에 따른 실제 접근 범위 확인 |
| GitHub Enterprise Server | 설치별 저장소·ref·경로 | 기존 `github_host` 경로 있음. REST는 `https://HOST/api/v3`; 지원 GHES 버전별 검증 필요 |
| Enterprise Cloud 데이터 레지던시 (`SUBDOMAIN.ghe.com`) | 해당 enterprise의 저장소 | REST는 `https://api.SUBDOMAIN.ghe.com`. `ghe.com` 전용 호스트 변환과 합성 검증 추가. 실제 enterprise 접근 정책은 별도 확인 |
| Notion / Enterprise | 연결에 허용된 페이지·데이터 소스 | 기존 수집기 있음. Enterprise의 연결 승인·페이지 접근 정책을 반영하고 API 버전별 자료형을 확인 |
| GitLab.com / Self-Managed / Dedicated | 승인된 project의 ref·경로 | 수집기·온보딩·승인 범위 실행 구현. `/api/v4` 기반이며 설치 호스트·버전·티어·토큰 범위가 다름 |
| GCP | Cloud Storage의 승인된 bucket/prefix | 수집기·ADC·generation 고정 읽기 구현. 조직/프로젝트·IAM·네트워크 정책은 배포 환경에서 확인. Secret Manager는 4장의 금고 역할 |
| Azure | Blob Storage의 승인된 account/container·prefix | 수집기·worker Azure 신원·ETag 고정 읽기 구현([azure/README](../azure/README.md)). 실제 tenant의 RBAC·네트워크 규칙은 배포 환경에서 확인 |
| Azure DevOps Services / Server | 승인된 organization(컬렉션)/project의 Git 저장소·경로 | 수집기·암호화 PAT·브랜치 커밋 고정(기본 또는 지정 브랜치)·blob objectId 읽기, TFVC 최신 변경집합 고정 읽기 구현. Server는 `base_url`·API 5.0 |
| Confluence Cloud / Enterprise | 승인된 space/page의 본문 | Cloud REST v2 space/page·본문·읽을 수 있는 첨부 수집 구현. 서비스 계정 OAuth는 API 게이트웨이(`api.atlassian.com/ex/confluence/{cloudId}`)로 자동 전환, 앱 접근 정책은 조직 설정 |
| Confluence Data Center | 설치별 space/page의 본문 | REST `/rest/api`·PAT·페이지네이션·context path 처리 구현. 실제 지원 제품 버전은 운영 검증 필요 |
| Bitbucket Cloud | workspace별 승인된 저장소·ref·경로 | REST `/2.0`, OAuth/access token Bearer 또는 API token + Atlassian 이메일 Basic. commit SHA 고정·트리/목록 페이지네이션 구현 |
| Bitbucket Data Center | project별 승인된 저장소·ref·경로 | REST `/rest/api/1.0`, PAT Bearer, context path·HTTPS 포트·개인 project(`~user`)·페이지네이션 구현. 실제 제품 버전별 검증 필요 |

근거: [GitHub Cloud API][GH-CLOUD-REST], [GHES API][GH-SERVER-REST],
[데이터 레지던시][GH-RESIDENCY], [Notion Enterprise 연결 정책][NOTION-CONNECTIONS],
[GitLab 저장소][GL-REPOS], [Cloud Storage 목록][GCS-LIST],
[Confluence Cloud API][CONF-V2], [Data Center 페이지네이션][CONF-DC-PAGING],
[Bitbucket Cloud source API][BB-SOURCE], [Bitbucket Data Center API][BB-DC],
[Bitbucket API token 인증][BB-TOKEN].

### 3.1 제공자별 구현 경계

- **AWS**: 상용 `aws`와 중국 `aws-cn`, GovCloud `aws-us-gov`, 유럽 주권 클라우드 `aws-eusc`(리전 `eusc-de-east-1`,
  2026-01 정식 출시)는 IAM 경계가 다른 파티션이다.[AWS-PARTITIONS] 계정/리전뿐 아니라 ARN·서비스 엔드포인트·배포 정책의
  파티션을 검증해야 한다. 배포 정책의 S3/IAM 리소스 ARN은 `AWS::Partition`을 사용한다.
  이 변경만으로 GovCloud/중국의 배포·인증까지 검증했다고 하지 않는다. AWS의 별도 “Enterprise API”를 가정하지 않는다.
- **GitHub**: [호스트 해석](../cremore/github_hosts.py)을 재사용하되 Cloud 레지던시와
  GHES를 구분하는 호스트 매핑을 추가했다. App 인증·수집·원본 링크도 같은 호스트 계약을 따라야
  한다. 기존 GHES 지원을 새 기능으로 재구현하지 않는다. 선택 ref의 코드 수집과 전체 Git
  이력·이슈·Actions 산출물 수집은 별도 범위다.
- **Notion**: Enterprise에서도 연결이 볼 수 있는 페이지를 조직 전체 문서로 간주하지
  않는다. 연결 설치 제한·페이지 접근 제어를 존중한다. 감사 로그·SCIM·봇 목록은 콘텐츠
  전수 수집이나 토큰 발급 대장의 대체재가 아니다. 현재 수집기의 API 버전은
  `2022-06-28`이므로 새 데이터 소스 API를 자동 지원한다고 하지 않는다.
- **GitLab**: project 식별자와 ref를 고정하고 tree 페이지를 끝까지 처리한 뒤 blob을 읽는다.
  `.com`·Self-Managed·Dedicated를 제품 식별로 보존한다. 파일 API의 `read_repository`
  지원만 보고 project/tree 탐색까지 허용된다고 추정하지 말고 사용하는 API별 읽기 권한을
  확인한다.[GL-FILES][GL-AUTH] LFS·submodule·과거 커밋은 포함 여부를 명시한다.
- **GCP**: Cloud Storage는 `storage.objects.list`와 `storage.objects.get` 권한이 다르다.
  `nextPageToken`을 끝까지 처리하고 읽을 객체의 `generation`을 보존한다.[GCS-LIST][GCS-GET]
  live object와 이전/soft-deleted 버전을 섞지 않는다. 조직용 도입에서도 동일 Cloud API의
  IAM·프로젝트·리전·정책 차이를 확인하며 다른 제품인 Google Distributed Cloud까지
  자동 지원한다고 확대하지 않는다. 연결 인증은 ADC 기반 실행 신원/Workload Identity
  Federation을 우선 검토하고 장기 서비스 계정 JSON 키를 필수로 요구하지 않는다.[GCP-ADC]
- **Confluence**: Cloud v2는 cursor/`Link` 페이지네이션과 `body-format`을 사용하고,
  페이지/space를 볼 권한이 있어야 한다.[CONF-PAGES] Data Center는 배포 버전의 REST와
  `start`/`limit`, `body.storage`·`version` 확장을 검증한다.[CONF-DC-PAGING][CONF-DC-EXPAND]
  Cloud OAuth 2.0(3LO)의 `cloudid`/게이트웨이와 Data Center PAT Bearer 인증을
  같은 토큰 필드의 동일 동작으로 취급하지 않는다.[CONF-OAUTH][CONF-DC-PAT]
  현재 본문·코드 블록·읽을 수 있는 첨부를 수집한다. 댓글·전체 이력·외부 매크로 내용은 제외한다.
  첨부의 외부/CDN 리다이렉트는 부분 수집으로 남긴다. Jira 수집은 포함하지 않는다.
- **Bitbucket**: Cloud와 Data Center를 별도 배포 유형으로 등록한다. Cloud는 workspace,
  Data Center는 project key(개인 project 포함)가 목록 경계다. 기본 branch 또는 선택 ref를
  SHA로 해석한 후 해당 트리/파일만 읽는다. Cloud 페이지의 `next` URL 자체를 따라가지 않고
  page cursor만 원래 API 경로에 적용한다. Data Center의 `isLastPage`/`nextPageStart`,
  `/files`, `/raw`와 원본 링크의 `at` revision을 보존한다. 앱 비밀번호에 의존하지 않는다.
  Enterprise 계약/요금제가 독립적인 전사 콘텐츠 API를 뜻하지 않는다. 전체 Git 이력, LFS
  본문, submodule, pull request·issue·pipeline 산출물은 수집 범위에 포함하지 않는다.

Confluence Cloud의 배포용 인증 방식은 공식 앱 등록·scope·갱신 흐름에 맞춰 확정한다.
공식 문서는 고객 API 토큰 수집/고객별 3LO 앱 생성 방식의 앱 정책 제약도 명시하므로,
이 설계에서 단순 email+token 입력을 제품의 기본 온보딩으로 확정하지 않는다.[CONF-AUTH]
Confluence Server의 구형 API와 Data Center의 지원 버전도 동일한 지원 약속으로 묶지 않는다.

### 3.2 공통 연결 계약

관리자가 승인한 제품/배포 형태·호스트·허용 리소스·인증 참조를 연결에 귀속한다.
자체 호스팅의 사내 DNS·인증서 체인·프록시·context path를 검증하며 TLS 검증을 끄는
방식으로 맞추지 않는다. 다음 페이지/리다이렉트가 인증정보를 다른 호스트로 넘기지 않도록 한다.

**노출 원본 호스트·금고 호스트·자격증명 발급 호스트는 서로 다를 수 있다.** 콘텐츠나
금고에서 읽은 URL만으로 새로운 외부 인증 요청을 승인하지 않는다
([검증 정의](../cremore/detection/verify/http.py)). GitLab PAT는 다음과 같이 보낸다.

- GitLab.com 소스에서 발견: GitLab.com의 `/api/v4/personal_access_tokens/self`에 보낸다.
- 자체 호스팅 GitLab 소스에서 발견: **그 소스의 등록된 인스턴스에만** 같은 경로로 보낸다.
  - 주소는 관리자가 등록한 연결의 `base_url`이다. 등록 규칙(HTTPS 등)을 다시 검사하고, 호스트가 등록된 GitLab 연결의 호스트여야 한다.
  - 조건을 벗어나면 보내지 않고 `GITLAB_ISSUER_HOST_UNCONFIRMED`로 둔다. GitLab.com으로는 보내지 않는다.
  - 검증되면 토큰 ID와 함께 `verification_host`를 기록한다.
  - 거절은 다른 호스트의 토큰일 수 있어 무효 근거가 아니므로 `INDETERMINATE`
    (`REJECTED_ON_SELF_MANAGED_GITLAB_OTHER_HOSTS_UNCHECKED`)로 둔다.
- 자체 호스팅 GitLab이 등록된 설치에서 GitLab 밖에서 발견: `GITLAB_ISSUER_HOST_UNCONFIRMED`로 생략한다.
  - 관리자가 교차 호스트 검증을 켠 경우에만 GitLab.com에 보내고, 그 거절은 `INDETERMINATE`로 둔다.
  - 자체 호스팅 인스턴스에는 보내지 않는다.

발급 목록과의 정확한 연결(`PROVIDER_VERIFIED_TOKEN_ID`)은 토큰 ID가 인스턴스별이므로 검증한 인스턴스와 발급 항목의
`instance`가 같을 때만 만든다.
공급자가 다른 콘텐츠 위치만으로 토큰의 발급 호스트를 확정할 수는 없다. 금고 해셔는 항상 `verify=False`다.

제공자 추가는 UI 이름만 추가하는 작업이 아니다. 기존 연결 검증 → 메타데이터 카탈로그 →
승인 범위/실행 계획 → 인증정보 해석 → worker 수집 → 원문 없는 증거/원본 링크의 경로를
끝까지 확장한다. 403/404·미지원 기능·필터·한도 때문에 보이지 않는 범위를 빈 성공이나
노출 제거로 처리하지 않는다. 구체적인 책임 위치는 8장에 정리했다.

---

## 4. 금고 어댑터와 대조 아키텍처

### 4.1 기존 엔진을 재사용하는 경계

금고 어댑터는 고객 환경에서 허용된 값을 읽고, 기존 탐지 엔진과 같은 규칙으로
fingerprint를 만든다. AWS Secrets Manager·SSM과 설치 자신의 비밀 저장소인 Vault/OpenBao는
관리자가 연결별로 서버 수집을 켜면 같은 어댑터를 CreMore worker에서 실행한다(8.2). 서버는 원문 없이 **금고 보관 관측 ↔ 기존 노출 fingerprint**를
대조한다. 발급 API를 먼저 호출하거나 금고 값을 CreMore의 자체 금고에 복제할 필요가 없다.

재사용할 것은 [탐지 엔진](../cremore/detection/engine.py)과
[fingerprint 함수](../cremore/detection/fingerprint.py)다.
**`Orchestrator.scan_resource()` 전체를 금고 수집에 호출하지 않는다.** 이 경로는
credential뿐 아니라 exposure와 finding을 생성하므로 금고의 정상 보관을 노출로 기록한다
([현재 오케스트레이터](../cremore/scanning/orchestrator.py)).

현재 엔진은 디코딩·패턴/윈도 매칭·검증·마스킹을 수행한다. 임의 JSON의 필드 의미를
이해하거나 모든 금고 문자열을 자격증명으로 인식하는 범용 파서는 아니다.
어댑터는 객체 경계를 보존하고, 해석하지 못한 항목·필터/한도 때문에 제외된 내용을
기록해야 한다. **탐지 0건은 금고에 자격증명이 없다는 증거가 아니다.**

금고 입력은 `DetectorInput(..., verify=False)`로 처리한다. 금고 보관 관측을 위해 새
인증 시도를 자동 수행하지 않는다. 기존 노출 탐지의 공급자 검증 정책과 분리한다.

### 4.2 어댑터와 완전성

[기존 수집기](../cremore/collectors/base.py)의 요청 예산·부분 수집 원칙과 공통 HTTP/Engine을 재사용한다.
금고·발급 관측은 노출을 생성하는 Collector 경로와 분리된 `coverage.collect`에서 처리한다.

콘텐츠 수집은 기존 `CollectedObject`/`CollectorError` 계약을 사용한다. 금고 수집은
`Collection.items`에 원문 없는 `Observation`을 담고 `status`/`reasons`로 완료 상태를
반환한다. 두 경로 모두 요청 예산과 탐지 한도를 반영하지만 정상 금고 보관을 노출 수집에
넘기지는 않는다. `DetectionResults.complete=false`, 읽기/목록 실패, 해석 불가는 부분
수집 또는 실패다. 항목이 0개인 성공·실패도 실행 기록으로 구분한다(4.4).

JSON/KV 항목은 관련 필드가 같은 객체 안에 남도록 전달한다. 필드를 무조건 낱개로
쪼개거나 서로 다른 항목을 임의로 합치지 않는다. 큰 항목·바이너리·미지원 형식·페이지 제한은
그 사유를 기록한다. “원본 JSON이면 모든 형식이 자동으로 해결된다”거나 “브랜드당
30~50줄이면 된다”는 구현 비용 보장은 하지 않는다.

| 금고 제품/배포 | 구현 범위 | 구분과 제한 |
|---|---|---|
| AWS Secrets Manager | 계정·리전·명시 ARN 또는 경로 목록, `SecretString`/`SecretBinary`, 버전/단계 | 고객 측 값 읽기와 해시 구현. 기본 `AWSCURRENT`; 다른 stage는 과거 근거. 미지원 바이너리는 미해결 |
| HashiCorp Vault Community | 선언 KV v1/v2 mount·경로 LIST/READ | 기존 토큰 공급용 `VaultKV`와 별개인 coverage 수집. KV v1은 `unversioned`; KV v2는 실제 버전 보존 |
| HashiCorp Vault Enterprise | 선언 namespace·mount·경로 | 요청별 `X-Vault-Namespace` 전달. 전체 namespace 자동 발견이나 관리자 권한 요구 없음 |
| HCP Vault Dedicated | 위 Vault API의 허용 namespace·클러스터 | 고객 Agent/token sink와 사설 endpoint/CA 적용. 실제 배포·토큰 갱신 확인 필요 |
| OpenBao | 선언 namespace·KV v1/v2·mount·경로 | Vault와 공통인 KV 읽기 구현을 공유. 삭제/파기/읽기 실패는 미해결. 실제 지원 제품 버전 검증 필요 |
| GCP Secret Manager | global project·명시 secret 또는 목록, version/alias 읽기 | 실제 버전 번호 보존. `latest` 외 숫자/alias는 현재성 미확인. regional secrets 제외 |
| AWS SSM Parameter Store | 계정·리전·계층 경로, 복호화된 값, 버전 | `GetParametersByPath` 페이지네이션·겹친 경로 중복 제거. 명시 경로 밖 응답/리전 실패는 부분 수집 |
| 외부 도구의 해시 제출 | 이번 범위에 없음 | 같은 패키지·지문·엔진/정책 계약의 고객 CLI만 지원. HMSL 호환을 가정하지 않음 |

근거: [Secrets Manager 값 읽기][AWS-SM-GET], [Vault KV v1][VAULT-KV1],
[Vault KV v2][VAULT-KV], [Vault namespace][VAULT-NS], [HCP Vault Dedicated][HCP-VAULT],
[OpenBao KV v2][BAO-KV], [OpenBao namespace][BAO-NS-DOC],
[GCP 버전 읽기][GCP-SM-ACCESS], [alias][GCP-SM-ALIAS],
[버전 상태][GCP-SM-VERSION], [regional secrets][GCP-SM-REGIONAL].

**어댑터가 통일하는 것은 관측 결과이지 원본 금고 구조가 아니다.** 각 제품의 목록·값
읽기·경로·버전·실패를 공통 관측 계약으로 옮기고 원본 위치는 보존한다. 같은 제품의
여러 계정/클러스터도 연결별로 구분한다. 동일 경로라도 인스턴스·namespace·mount가
다르면 다른 위치다. AWS 계정 ID나 Vault 경로 하나로 전역 고유성을 가정하지 않는다.

KV v2는 `/metadata/` 목록과 `/data/` 값 읽기의 경로·권한이 다르고 버전의 삭제/파기
상태가 있다. KV v1에는 같은 버전 메타데이터가 없으므로 허구의 버전/생성 시각을 채우지
않는다.[VAULT-KV][VAULT-KV1] GCP는 선언한 버전 또는 운영 alias를 실제 버전 번호로
해석해 기록한다. alias 미지정 시 `latest`를 선택했다는 사실을 표시하고, 비활성/파기된
버전에서 임의로 이전 값을 골라 현재 보관 근거로 바꾸지 않는다.[GCP-SM-ACCESS][GCP-SM-VERSION]

**Vault/OpenBao 범위**: Vault namespace는 Enterprise 기능이고 OpenBao도 지원 버전에서
namespace를 제공한다.[VAULT-NS][BAO-NS-DOC] 선언한 namespace/mount/경로를 수집하며, 전수 자동 발견을
제공한다면 그 범위의 namespace 목록과 하위 범위를 빠짐없이 추적해야 한다.

- 루트만 읽었다면 루트 범위의 결과다. 전체 설치를 읽었다고 표시하지 않는다.
- namespace 미지원 제품과 권한 부족·잠김·연결 실패를 구분한다. 403/404를 통째로 정상
  “namespace 없음”으로 취급하지 않는다. 확인 불가능하면 범위를 `UNKNOWN`으로 둔다.
- 제한된 namespace/mount 목록을 운영자가 지정하는 방식도 유효하다. 전역 관리자 권한이나
  전체 설치 자동 탐색을 필수로 요구하지 않는다. 지정한 범위의 수집 완료와 설치 전체 수집을 구분한다.
- Vault KV v2와 동적 secrets engine은 다른 대상이다. 동적 크리덴셜을 발급하는 읽기
  엔드포인트를 이 어댑터의 “읽기 전용 인벤토리”에 포함하지 않는다.

Vault Secrets Sync로 AWS Secrets Manager에 복제된 값은 여러 위치에서 관측될 수 있다.
동일 자격증명은 중복 계산하지 않되 모든 보관 위치/버전은 유지한다. 동기화된 경로만
보인다는 사실을 Vault 전체 수집으로 확대하지 않는다.[VAULT-SYNC]

HashiCorp 상용 솔루션도 실제 제품을 구분한다. 위 금고 대상은 Vault Enterprise와
HCP Vault Dedicated다. Vault Radar는 노출 탐지 제품이며 이들 금고와 같은 어댑터로
취급하지 않는다. 새 금고 제품은 지원 API·인증·범위·값 형식·버전을 확인한 후 추가한다.

### 4.3 값 접근 — B를 기본으로 한다

| 방식 | 금고 값을 읽는 주체 | CreMore API/worker의 금고 값 읽기 권한 | 원문 저장 |
|---|---|---|---|
| A: 서버 직접 수집 | 별도 서버 수집 역할 | 필요 | 하지 않음 |
| **B: 고객 측 해시 제출** | **고객 환경의 해셔** | **불필요** | **하지 않음** |
| C: 값 접근 없음 | 없음 | 불필요 | 하지 않음 |

B에서도 고객 측에는 해당 금고의 값 읽기 권한이 필요하다. Secrets Manager는
`GetSecretValue`, 고객 관리 KMS 키인 경우 해당 키의 `kms:Decrypt` 등이 필요하다.[AWS-SM-GET]
“서버 권한을 추가하지 않는다”와 “누구에게도 추가 권한이 필요 없다”는 다른 말이다.

현재 코드에서 확인된 경계:

- [AWS scanner allowlist](../cremore/aws_readonly.py)는 Secrets Manager 값 읽기를 허용하지 않는다.
  SSM도 등록되어 있지 않다.
- [멤버 계정](../deploy/cloudformation/member-account-role.yaml),
  [단일 계정](../deploy/cloudformation/single-account.yaml),
  [보안 계정](../deploy/cloudformation/security-account.yaml) CFN의 scanner 정책은
  `GetSecretValue`/`BatchGetSecretValue`를 명시적으로 Deny한다.
- 저장소의 CFN 템플릿에는 회전용 Secrets Manager 값 접근 grant도 없다.
  [회전 구현](../cremore/remediation/rotation.py)이 값을 읽을 수 있는지는 별도 배포 권한과
  [실행 게이트](../cremore/cli/api.py)에 달려 있다. 코드 존재는 권한 부여의 증거가 아니다.

A를 나중에 지원하더라도 scanner의 Deny를 푸는 것을 기본 경로로 삼지 않는다.
**별도 역할·용도·허용 범위로 분리하는 설계가 필요**하며 이번 범위에서 구현하지 않는다.
C에서는 노출 결과와 금고 메타데이터가 남지만 값 일치를 통한 보관 여부는 확인할 수 없다.

### 4.3.1 B의 제출 계약

해셔는 같은 Python 패키지와 엔진을 사용하는 `cremore-coverage`로 구현했다.
[패키지 진입점](../pyproject.toml)에 `cremore-api`, `cremore-worker`와 함께 등록되어 있다.
[CLI](../cremore/cli/coverage.py)는 연결 전용 토큰으로 계약/범위를 읽고, 고객 환경에서
수집·해시한 뒤 start → 번호별 batch → finish 요청을 보낸다. 같은 실행/배치의 최대 3회
재전송은 멱등 처리한다. 원문 재시도 파일은 만들지 않는다.

[제출 모델](../cremore/coverage/models.py)의 스키마 버전은 `1`, 방식은
`cremore-credential-fingerprint-v1/hmac-sha256`이다. 자유 형식 JSON을 받지 않고,
아래 의미를 제한된 필드와 크기로 검증한다.

| 단위 | 필수 정보 | 이유 |
|---|---|---|
| 실행 | 스키마 버전, 실행 ID, 생산 도구/버전, 설치·연결 식별 | 형식 검증, 재전송 중복 처리, 제출 권한과 귀속 |
| 실행 | 시작/종료/수신 시각, 범위와 범위 개정, 완전성·실패·제외 사유 | 빈 성공/실패 구분, 시점 차이·stale 판정 |
| 실행 | fingerprint 방식, 탐지 정책 호환 정보, 키 일치 확인 | 비교 불가능한 자료를 0%로 해석하지 않기 |
| 항목 | 탐지 타입/발급자 분류, fingerprint·근거 수준, 식별자(존재할 때) | 발급 ID가 없는 토큰도 대조. ID-only와 비밀 재료 구분 |
| 항목 | 금고 제품/배포·연결·계정/리전 또는 namespace/mount, 경로, 버전/상태 | 다른 인스턴스의 같은 경로 구분, 현재 보관 근거 판단 |
| 항목 | 허용된 메타데이터, 해석 불가 사유 | 근거 보존과 정보 최소화 |

`fingerprint`는 ID-only/해석 불가 행에서는 없을 수 있다. 그 행에 임의의 해시를 채워
정상 보관 증거처럼 만들지 않는다. 제출 JSON에 원문·전체 `SanitizedDetection`·
`redacted_line`·제공자 응답 전체를 그대로 담지 않고 필드 허용 목록을 적용한다.

**같은 저장소의 코드라는 사실만으로 호환성이 보장되지 않는다.** 배포 버전·탐지 규칙·
오탐 정책·material 규칙·키가 달라질 수 있다. 현재 `Engine.detection_digest`는
`ENGINE_EPOCH`, 탐지 정의, 정책, 한도와 `fingerprint_key_epoch` 등을 이미 포함한다.
제출 계약은 이 digest와 사용자 규칙의 `policy_digest`를 사용하고, 실제 제출 경로에서
키·방식·정책 불일치를 거부한다. 기존 규칙을 무시한 별도 정규화·중복 해시 체계를 먼저 만들지 않는다.
계약의 `policy_digest`는 `Orchestrator.coverage_policy_digest`(탐지 digest와 사용자 규칙)다. 스캔 범위의 재검사를
정하는 `detection_policy_digest`는 문서 추출 정책(추출기 epoch·한도·파서 버전)까지 담지만, 추출은 무엇을 찾을지만
바꾸고 찾은 값의 지문은 바꾸지 않으므로 계약에 넣지 않는다. 그래야 파서 버전이 다른 고객 환경의 해셔도 같은 계약을 낸다.

**현재 API/worker의 정상 기동에는 무키 모드가 없다.**
[설정 검증](../cremore/config.py)의 `validate_safety()`가 최소 32바이트의 hex 키를
강제하고, API 생성과 `get_settings()`가 이를 호출한다. 저수준 `fingerprint()`가 무키
SHA-256도 지원하는 것과 제품의 정상 기동 경로를 혼동하지 않는다.
고객 해셔도 같은 키 길이와 호환성 검사를 강제한다. 외부 도구 해시 임포트는 지원하지 않는다.

**키 전달은 단순 편의 문제가 아니다.** 현재 `FINGERPRINT_KEY`는
[연결 토큰 봉인](../cremore/secretstore/sealed.py)의 암호화 키를 HKDF로 파생하는
마스터이기도 하다. 해셔에 전달하면 신뢰 경계가 넓어진다. 전달 대상·권한·폐기와
키 교체 시 양쪽 재수집을 정의해야 한다. 별도 대조 키를 택한다면 기존 fingerprint와의
마이그레이션까지 검토해야 하므로 이 문서에서 자동 해결됐다고 하지 않는다.

또한 digest/키 일치 확인은 제출자의 권한이나 내용의 진실성을 증명하지 않는다.
제출 API는 기존 인증·역할/범위 검증을 적용하고, 서버가 연결/범위를 귀속시켜야 한다.
연결 전용 제출 토큰의 해시만 저장하며, 회전/비활성/범위 개정을 쓰기 트랜잭션 안에서 다시 확인한다.
업로드 크기·개수·필드 길이 제한과 원문 없는 실행/변경 이력도 계약에 포함한다.

### 4.4 저장 위치와 수집 실행

| 데이터 | 저장 경계 |
|---|---|
| 금고 보관 관측 | 별도 관측 영역의 보관 위치·버전·fingerprint·근거 |
| 수집 실행/스냅샷 | **항목이 0개여도** 범위·시각·상태·실패를 기록 |
| 노출 | 기존 `credentials` / `exposures` / `findings` |
| 대조 결과 | 보관 관측과 노출 자격증명의 관계, 사용한 양쪽 스냅샷/판정 사유 |
| AWS 발급 메타데이터 | 계정·주체·키 ID·상태·수집 실행을 별도 관측으로 보존. 원문이나 가짜 fingerprint를 만들지 않음(10장) |
| 탐지·금고 대상 원문 | 저장하지 않음 |

[기존 `credentials` 스키마](../cremore/db/schema.py)는 fingerprint가 필수이고
`(fingerprint, credential_type)`가 고유 키다. 메타데이터/해석 불가 항목에 가짜 fingerprint를
넣거나 정상 금고 보관을 exposure/finding으로 흘리지 않는다. ID가 실제로 저장되는 경로는
[도메인 매핑](../cremore/domain/mapping.py)의 `credential_from_detection()`이다.

발급/보관/노출을 한 테이블의 `axis`로 합치는 모델을 선행 설계로 고정하지 않는다.
하나의 자격증명이 여러 보관 위치·버전과 여러 노출 위치에 대응한다. 기존 노출 모델은
재사용하고 보관 관측/실행 근거와 10장의 발급 메타데이터 관측을 추가했다. 스냅샷·귀속·
고유성을 기준으로 세 테이블에 저장한다. 현재 테이블명과 복구 경계는 8장에 있다.

비교 중인 스냅샷에 새 실행의 일부 행을 섞지 않는다. 검증·수집 완료 상태를 기준으로
게시하며 재전송은 중복 생성하지 않고, 늦게 도착한 과거 자료가 최신 자료를 덮지 않게 한다.
부분 실패 시 이전 성공 근거는 보존하되 최신 자료인 것처럼 표시하지 않는다.

페이지네이션 완료가 공급자 전체의 원자적 스냅샷을 뜻하지는 않는다. 예를 들어
Secrets Manager 목록은 최근 약 5분의 변경이 반영되지 않을 수 있다.[AWS-SM-LIST]
시작/종료 시각과 실제 버전을 남기고, 변경 중인 항목·시점 차이는 현재성 정책에 반영한다.
“지금 어느 금고에도 없다”는 실시간 보장으로 확대하지 않는다.

고객 해셔의 금고 권한은 허용 범위의 **목록/메타데이터/값 읽기**다. 이전 문구의
Vault `create`/`update`만 주는 “쓰기 전용 수집기”는 이 흐름과 맞지 않는다.
CreMore 제출 권한과 원본 금고 읽기 권한을 별도로 정의한다.

### 4.5 조인 키와 증거 수준

| 대조 근거 | 증명하는 것 / 한계 |
|---|---|
| 동일 scheme·키·material·credential type의 fingerprint | 같은 자격증명 재료가 양쪽에 있었음. 현재 유효성/안전성 전체는 아님 |
| 금고에 ID만 있거나 이름이 비슷함 | 후보 관계. 비밀 보관이나 값 일치를 증명하지 못함 |
| 이전/대기 버전에서만 값 일치 | 과거/대기 보관 근거. 현재 보관 일치로 승격하지 않음 |
| 관리자가 금고 경로를 연결함 | 확인 후보. 값 대조 없이 정확한 일치로 승격하지 않음 |

금고가 위치한 계정/호스트와 자격증명을 발급한 계정/호스트는 다를 수 있다.
보관 위치의 계정·제품을 발급자로 대입하지 않는다. 발급 ID나 발급 API 응답은
값 fingerprint 대조에 필수인 조인 키가 아니다.

**현재 material 규칙을 양쪽에서 동일하게 적용해야 한다.**

- [AWS 탐지 정의](../cremore/detection/catalog.py)는 ID와 40자 secret 형태가 같은
  입력에서 앞뒤 순서 중 하나로 발견되고 중간 구간이 `[\s\S]{0,512}`에 맞는 경우를
  대상으로 한다. secret의 엔트로피·오탐 정책도 적용된다. material은
  [엔진](../cremore/detection/engine.py)의 `id + b"\x00" + secret`이며 ID 단독이 아니다.
- JSON/KV 객체 전체를 유지해도 다중 키·중첩·배열에서 올바른 pairing이 자동 보장되지는
  않는다. 지원 형식과 모호한 입력의 판정 규칙을 검증한다. 서로 다른 secret 항목의 ID와
  비밀을 임의로 결합하거나 탐지기의 근접 매칭만으로 모든 구조를 지원한다고 하지 않는다.
- AWS secret만 generic 타입으로 탐지한 fingerprint를 `AWS_ACCESS_KEY`의 쌍 fingerprint와
  비교해 “금고에 없음”이라고 하지 않는다. 단독 ID·분리 저장·대응 불가 재료는 별도
  관측으로 남기며 관련 노출의 부재 판단을 막는다.
- GCP 서비스 계정 탐지 정의는 PEM private key를 추출한다. 같은 JSON 객체의 `client_email`·
  `private_key_id`가 하나로 정해질 때만 발급 키 ID(`serviceAccountKey:<email>:<key_id>`)와 연결한다.
  발급 키는 금고에 같은 키 ID가 있으면 `IDENTIFIER_ONLY`, 선언한 금고 범위가 완전·최신이고
  키 ID가 없거나 모호한 서비스 계정 키 값이 없을 때만 AWS 키 ID처럼 `IDENTIFIER_NOT_OBSERVED`다.
  JSON escape·PEM 표현·탐지 타입이 다른 입력의 호환성을 별도 확인하고 금고 해셔만 다른 정규화를 하지 않는다.
- GitHub·Notion·GitLab 등 토큰도 지원되는 탐지 타입/material이면 같은 방법으로 대조한다.
  특정 서비스의 탐지 정의가 있다는 사실은 그 서비스의 콘텐츠 수집기 지원과 다르다.

| 금고 관측 | 대조 처리 |
|---|---|
| 명확한 재료가 현재 버전에서 발견되고 노출 fingerprint와 일치 | `MATCHED`. 모든 보관 위치·버전·시각을 연결 |
| 식별자만 있음 | `IDENTIFIER_ONLY` 근거. 정확한 일치 `M`에 넣지 않음 |
| 분리된 필드/여러 후보/미지원 형식 | 미해결 근거로 보존. 해당 범위와 관련된 미일치 노출을 `UNKNOWN`으로 처리 |
| 이전/대기 버전에서만 일치 | 이력 근거로 표시. 현재 버전은 별도 판정 |
| 지원 형식을 완전히 대조했으나 일치 없음 | 다른 관련 금고의 완전성까지 확인한 뒤 `NO_VAULT_MATCH` 가능 |

탐지 0건은 인식 가능한 자료가 없다는 뜻일 수 있다. **목록 수집 성공·값 읽기 성공·
형식 해석 성공·대조 가능성은 별개**다. `MANAGED_UNPAIRED`라는 이전 명칭으로
특정 자격증명이 관리된 것처럼 표시하지 않는다. 미해결 항목이 어느 타입/범위에 영향을
주는지 모르면 해당 비교 범위를 보수적으로 `UNKNOWN`으로 둔다.

### 4.6 메타데이터 가용성과 의미

| 필드 | Secrets Manager | SSM Parameter Store | Vault / OpenBao KV v2 |
|---|---|---|---|
| 이름/경로 | 제공 | 제공 | 제공 |
| 저장 항목 생성 시각 | `CreatedDate` | 표준 메타데이터에 동일 필드 없음. 남아 있는 version 1 이력은 조건부 근거 | key metadata의 `created_time` |
| 수정 시각/버전 | 제공 | `LastModifiedDate`, `Version` | `updated_time`, 버전 메타데이터 |
| 저장소 읽기 시각 | `LastAccessedDate`는 리전별 저장소 접근 | 표준 메타데이터에 없음 | KV 메타데이터에 없음 |
| 회전 | `RotationEnabled`와 `LastRotatedDate` 등은 서로 다른 사실 | 파라미터 변경/정책을 자격증명 회전으로 추정하지 않음 | KV 버전을 자격증명 회전으로 추정하지 않음 |
| 수정자/소유자 | 태그 등이 있을 수 있으나 관리 책임자와 동일하지 않음 | `LastModifiedUser`는 수정자 | `custom_metadata`는 사용자 입력 |

근거: [SecretListEntry][AWS-SM-ENTRY], [ParameterMetadata][AWS-SSM-META],
[ParameterHistory][AWS-SSM-HISTORY], [KV v2 API][VAULT-KV]. 저장 시각은 자격증명 발급
시각이 아니며, 금고 읽기는 그 자격증명으로 외부 서비스를 사용했다는 뜻이 아니다.

공통 스키마를 얇게 유지하되 **제공자 응답을 원형 그대로 저장하지 않는다.** 현재
[금고 메타데이터 서비스](../cremore/investigation/secret_metadata.py)는 tags/description을
`OMITTED_BY_SECURITY_POLICY`로 제외하고 [인벤토리](../cremore/investigation/secrets_manager.py)는
태그 값 없이 키만 남긴다. 그 경계를 새 수집기에서도 유지한다. 경로/이름 역시 무조건
무해하다고 가정하지 않고 필요한 표시 필드만 제한해서 보관한다.

필드 상태는 최소한 **제공됨 / 제공자가 미지원 / 요청 결과 없음 / 권한·수집 실패 /
보안 정책상 제외**를 구분한다. 모두 빈 문자열이나 `false`로 합치지 않는다.

---

## 5. 대시보드 분류와 관측 규칙

아래 세 상태는 **현재 노출의 금고 보관 판정**이다. API는 별도로 식별자 후보와
금고에서만 관측한 재료도 반환한다.
발급 목록의 판정은 노출 요약과 따로 센다. `summary.issued`는 발급 자격증명 수이며
`issued_in_vault`(값·식별자·공개 인증서 일치), `issued_not_in_vault`(`NO_VAULT_MATCH`·
`IDENTIFIER_NOT_OBSERVED`), `issued_unknown`으로 나눈다. 관측된 STS 세션은 금고 보관 대상이
아니므로 세지 않는다. `origin` 필터(`EXPOSURE`·`ISSUANCE`·`USAGE`·`VAULT`·`MANAGEMENT`)는
목록만 좁히며 요약과 대조 범위는 바꾸지 않는다.
보관 판정·노출 판정·제공자 유효성은 서로 독립이다. 노출된 값이 금고에 있어도
finding을 닫거나 노출을 제거 처리하지 않는다.

| 보관 판정 | 조건 | 노출이 있을 때 표시 |
|---|---|---|
| `MATCHED` | 허용한 현재 금고 버전에서 호환되는 값 fingerprint 일치 | 노출됨 · 금고 보관 확인 |
| `NO_VAULT_MATCH` | 관련된 선언 금고 범위의 목록·읽기·해석·대조가 모두 완료되었으나 일치 없음 | 노출됨 · 연결 금고에서 미발견 |
| `UNKNOWN` | 연결·권한·범위·시각·형식·호환성 때문에 현재 보관 여부 판단 불가 | 노출됨 · 보관 판단 불가, 사유 표시 |

`NO_VAULT_MATCH`는 “조직 어느 금고에도 없음”이나 “발급된 미관리 키”가 아니다.
운영자가 이 대조에 포함하기로 한 금고가 아직 미연결이면 `UNKNOWN`이다. 대조 범위에
선언하지 않은 금고의 존재/내용은 확인하지 못했다고 범위에 명시한다.

현재 버전에 일치가 있고 다른 금고가 실패한 경우에도 **그 위치의 보관 확인은 유효**하다.
이 경우 전체 금고 목록은 부분 수집으로 표시한다. 이전 버전의 일치만 있으면 이력 근거를
보여주고 현재는 별도 판정한다. 최신 실행 실패로 이전 관측을 영구 현재 상태로 유지하지 않는다.

금고에서만 확인한 재료에는 “선택한 스캔에서 노출 미관측”을 표시할 수 있다. 미수집
리포·페이지·버전까지 안전하다고 말하지 않는다. 미해결 금고 항목 수와 고유 자격증명 수는
별도이며, 파싱하지 못한 항목을 자격증명 한 개로 세지 않는다.

### 5.1 화면 흐름

1. **금고 연결/범위**: 기존 인증·관리 권한 아래 제품/배포·인스턴스와 허용 계정/리전 또는
   namespace/mount/경로를 등록한다. 노출 스캔 연결과 금고 대조 연결의 용도를 구분한다.
   고객 측 해셔가 받은 범위·마지막 수집·실패 사유를 대시보드에서 확인한다.
2. **대조 목록**: 금고 대조 화면에서 보관 확인 / 연결 금고 미발견 / 판단 불가,
   발급·사용 식별자와 금고 전용 관측을 페이지로 조회한다. 기존 노출 목록의 위험도·대응
   상태는 탐지 상세 링크로 연결한다. 보관 판정·노출 제공자·보관 근거의 금고 제품으로
   목록을 필터링하며 서버에서 필터 후 페이지를 나눈다. 필터가 대조 범위나 요약 집계의
   분모를 바꾸지는 않는다. 금고 제품 필터는 현재/과거 보관 근거가 있는 행을 선택한다.
3. **노출 상세**: 모든 일치 금고의 위치·현재/과거 버전·관측 시각·정확한 일치/후보 구분을
   보여준다. 노출 원본 링크는 탐지 상세의 기존 기능을 사용한다. 금고는 참조/버전만
   표시하며 임의 URL이나 비밀 원문을 대시보드에 추가하지 않는다.
4. **보관 목록**: 연결 금고에서 확인한 자격증명과 노출 관계를 보여준다. 여러 금고 복제본을
   하나로 묶되 위치는 보존한다. 노출 미관측·대조 불가·과거 일치도 범위와 함께 표시한다.
5. **AWS 미관측 자격증명 조사**: 발급 목록에서 존재가 확인된 키를 노출 유무와 독립적으로
   보여준다. 계정·주체·상태·보관 근거와 관측 한계를 표시한다(10장). CloudTrail 사용
   관측은 별도 행이며 IAM 전용 행의 담당자 자동 추정·최근 사용 일괄 조회는 하지 않는다.

대시보드의 표현은 “보관 확인”이며 “안전” 배지가 아니다. 실제 소비자의 참조 전환,
최소 권한, 유효성, 회전 완료는 별도의 증거가 있어야 한다.

### 5.2 수치의 예

| 관측 사례 | 올바른 표시 |
|---|---|
| `E=100`, `M=40`, `N=60`, `U=0`, 모든 비교 조건 충족 | 관측된 노출 중 보관 일치율 40%, 연결 금고 미발견 60개 |
| `E=100`, `M=40`, `U=60`, 금고 수집이 부분 실패 | 보관 확인 40 / 판단 불가 60, 퍼센트 미표시. 40/40=100%로 바꾸지 않음 |
| 금고 A와 B에 같은 값, 노출 위치 5곳 | 고유 자격증명 1개, 보관 위치 2곳, 노출 위치 5곳 |
| `E=0` | “선택한 스캔에서 관측된 노출 없음”. 0%나 100%가 아님. 스캔 실패와 구분 |
| 승인한 금고 범위가 완전한 빈 목록이고 `E>0` | 그 범위의 일치율 0% 가능. 조직 전체 금고가 비었다는 의미는 아님 |
| 이전 금고 버전에서만 일치 | 과거 보관 일치 표시. 현재 보관 확인 건수에 포함하지 않음 |
| 금고에 미해결 항목 10개 | 항목 건수/사유 별도 표시. 노출 10개를 임의로 분모에서 제거하지 않음 |

### 5.3 완전성과 `UNKNOWN`

- 미연결·권한 거부·부분 페이지·요청/바이트/항목 한도·읽지 못한 리전/namespace/mount는
  해당 범위의 부재 판정을 막는다. 목록 성공과 모든 값의 읽기 성공은 다르다.
- 값이 반환되어도 미지원 바이너리·애매한 pairing·엔진 한도·정책 필터로 비교할 수 없으면
  해석 불가 사유를 남긴다. 관련성을 좁힐 수 없으면 전체 해당 비교 범위에 영향을 준다.
- 여러 금고 중 하나에서 정확히 일치하면 그 위치의 긍정 근거를 유지한다. 어디에도
  일치하지 않는다는 판정에는 관련된 모든 선언 금고 범위의 대조 완료가 필요하다.
- 키/방식/필수 호환성 정보가 다른 제출은 거부한다. 비교 실패를 0%로 표시하지 않는다.
- 양쪽 수집 시점·범위 변경·실패한 최신 실행·유효기간 초과를 판정에 반영한다.
  과거 성공 근거는 이력으로 남기고 현재 근거처럼 표시하지 않는다.
- 노출의 제거 판정은 기존 스캐너의 재확인 규칙을 따른다. 금고 연결·보관 성공·금고에서
  값이 사라졌다는 사실만으로 노출이 해결되었다고 처리하지 않는다.

### 5.4 메타데이터는 참고 근거

GitHub Actions secrets는 이름·범위 등의 메타데이터를 읽을 수 있지만 값을 반환하는
조회 API가 아니다.[GH-SECRETS] 같은 이름이나 관리자가 지정한 금고 경로는
확인 후보를 만드는 데 쓸 수 있으나 `MATCHED`나 보관율의 분자에 넣지 않는다.

금고 버전 수로 자격증명 회전을, 저장소 읽기 날짜로 키 사용을, 사용 로그가 없다는
사실로 소비자 전환 완료를 추정하지 않는다. KV v2 이외의 동적 secrets engine이나
외부 회전 제품에 대한 기능 부재를 일반화하지도 않는다.

---

## 6. 채택하지 않는 구현 방식

- **자체 Vault/OpenBao를 번들해 고객 금고를 대신한다**: 목적은 고객의 기존 금고와
  대조하는 것이다. 복사본을 만들면 추가 비밀 보관·운영 책임이 생기고 실제 소비와도 다르다.
- **대조 과정에서 발급·회전·자동 편입한다**: 읽기/관측과 쓰기/소비자 전환/복구는 다른
  책임이다. 기존 승인 기반 [회전 기능](../cremore/remediation/rotation.py)은 유지하되
  이 기능에 묶지 않는다. 고객이 가진 원본을 금고로 옮기는 데 항상 재발급이 필요한 것은
  아니다. AWS에서 생성 후 secret을 다시 조회할 수 없다는 사실과 원본을 보유하지
  못한다는 것은 다르다.[AWS-KEYS]
- **모든 제공자의 발급 대장부터 완성한다**: 발급 목록 없이도 같은 재료의 금고·노출 대조가 가능하다.
  AWS 미관측 키의 발견에는 IAM 메타데이터 수집을 추가하되 다른 제공자의 전수 발급 목록을
  그 선행 조건으로 두지 않는다.
- **Vault를 값 없는 인벤토리 DB로 사용한다**: 대조 자료·관측 실행은 기존 PostgreSQL의
  책임이다. 별도 금고를 메타데이터 DB로 운영하지 않는다.
- **금고를 기존 노출 수집기에 연결하기만 한다**: Engine은 재사용하지만 노출을 생성하는
  오케스트레이터 경로는 재사용하지 않는다. 정상 보관을 새 노출 finding으로 만들면 안 된다.
- **떨어져 관측된 ID와 SAK를 조합해 공급자에 인증을 시도한다**: 서로 다른 소스에서 나온
  식별자와 비밀을 짝지어 `sts:GetCallerIdentity`로 시험하지 않는다. 세 가지 이유다.
  (1) 조합하려면 두 평문을 탐지 경계 밖에서 동시에 보유해야 하는데, 이는
  [키드 지문](../cremore/detection/fingerprint.py)으로 평문을 남기지 않는다는 전제를 깬다.
  (2) ID N개 × SAK M개는 N×M번의 실패하는 인증 요청이고, 고객 자신의 CloudTrail에서
  자격증명 스프레이와 구분되지 않는다. (3) 그럴 필요가 없다 — 아래 대체 경로를 쓴다.
  대신 두 반쪽을 비대칭으로 다룬다.
  - **ID 반쪽**: 액세스 키 ID는 비밀이 아니므로, 연결된 계정의 IAM에
    [`iam:GetAccessKeyLastUsed`](../cremore/investigation/usage.py)로 직접 물어
    소유 계정·IAM 사용자·활성 상태·최근 사용을 확정한다. CreMore 자신의 스캐너 역할로
    인증하며, 발견한 키로 인증하지 않는다. 어느 연결 계정도 그 키를 보고하지 않으면
    `ACCOUNT_OWNER_UNKNOWN`이며, 열 수 없었던 계정은 "미조회"로 남고 "없음"으로 세지 않는다.
  - **SAK 반쪽**: 40자 base64는 자기 자신을 식별하지 못하고, 어떤 공급자 API도 비밀만으로
    소유자를 답하지 않는다. **단독 검증은 원리적으로 불가능하다.** 연결 수단은 키드 HMAC
    구성요소 동등성뿐이며(§4.5), 이는 완전한 쌍이 어딘가에서 한 번은 함께 관측되었을 때만
    성립한다. 같은 바이트가 AWS로 분류되지 않는 이름 아래 있어도 동등성으로 연결되지만,
    그 연결이 값의 분류나 신뢰도를 올리지는 않는다.

---

## 7. 시장 비교와 호환성 — 확인한 범위만

### 7.1 공식 문서로 확인된 유사 기능

| 제품/기능 | 확인된 내용 | 이 문서에서 단정하지 않는 것 |
|---|---|---|
| GitGuardian ggscout | 고객 환경에서 금고 값을 분류·해시하고 탐지 결과와 대조. Vault, AWS Secrets Manager 등 지원 | CreMore와 해시/JSON이 바로 호환된다는 주장 |
| GitGuardian 배포 | SaaS 외에 공식 self-hosted 설치 문서가 있음 | 모든 제품 모듈/요금제에서 동일 기능을 제공한다는 주장 |
| HCP Vault Radar / IDE 확장 | 노출 탐지와 IDE 확장의 Vault KV v2 인덱싱·로컬 대조가 문서화됨 | 다른 저장소를 절대 지원하지 않는다거나 미연결 저장소를 무조건 미관리로 판정한다는 주장 |

근거: [ggscout 개요][GG-SCOUT], [ggscout 동작][GG-SCOUT-DETAIL],
[GitGuardian 자체 호스팅][GG-SELFHOST], [Vault Radar][RADAR], [Radar 보안 모델][RADAR-SECURITY].

GitGuardian이 설명하는 vault coverage는 **연결된 시스템에서 탐지한 고유 자격증명**을
분모로 설명한다.[GG-COVERAGE] 이 문서도 발급 대장보다 노출·금고의 대조를 중심에 둔다.
다만 제품 간 탐지 모집단·정규화·부분 수집 처리까지 같다는 뜻은 아니다. CreMore의
정확한 분모와 표시 조건은 2.2와 5.2에 따른다.

### 7.2 HMSL은 범용 금고 교환 표준이 아니다

HMSL의 명칭은 **Has My Secret Leaked**다. 기존 문서의 “Hashed Message Secret Lookup”은
오류다. GitGuardian 서비스의 프로토콜이며, ggscout도 HMSL 해시 알고리즘을 사용한다고
명시한다.[GG-HMSL][GG-SCOUT-DETAIL]

공식 프로토콜 설명은 scrypt를 사용하며, ggshield는 fingerprint 생성·해시 prefix/full hash
질의·반환 payload 복호화를 구분한다.[GG-PROTOCOL][GG-HMSL-FP]
CreMore의 설치별 domain-separated HMAC-SHA256과 같지 않다.
**이미 계산된 HMSL 해시만 가져와 CreMore HMAC으로 변환할 수는 없다.**

따라서 “HMSL 임포트로 나머지 브랜드 전부 지원”은 계획에서 제거한다. 외부 도구를 연동하려면
라이선스/지원 범위, credential material/타입, 키·해시 방식, 실행 범위/완전성을 검증하고
같은 대조 자료를 생성할 수 있어야 한다. 원문 제출을 요구하는 방식으로 우회하지 않는다.

### 7.3 제품 포지션과 검증하지 않은 주장

CreMore가 지향할 수 있는 것은 **원문을 보관하지 않는 자체 호스팅 노출 대응에,
범위·근거·미확인을 드러내는 금고 대조를 추가하는 것**이다.
그러나 로컬 해싱·금고 대조·자체 호스팅 각각이 시장 최초라는 주장은 하지 않는다.

이전 논의의 벤더 인수 관계, “독립 업체는 하나뿐”, “상용은 전부 단일 숫자”,
“오픈소스는 시크릿 매니저 연동 없음”, `$300,000`을 전체 시장 가격처럼 사용하는 비교는
검증된 설계 근거에서 제외한다. 현행 공식 기능·계약/가격 자료 없이 경쟁사의 미지원이나
고객층 공백을 사실로 적지 않는다.

### 7.4 IAM Access Analyzer와의 관계

IAM Access Analyzer의 unused access 분석은 미사용 역할·키·비밀번호 등 접근을
찾는 기능이다.[AWS-ANALYZER] 이 설계의 금고 보관 대조와 질문이 다르다.
중복되는 조사 정보는 있을 수 있으며 대체 여부는 구체적인 고객 요구로 평가한다.

---

## 8. 현재 구현과 운영 경계

| 영역 | 구현된 경로 | 운영/지원 한계 |
|---|---|---|
| 고객 금고 수집 | [CLI](../cremore/cli/coverage.py), [어댑터](../cremore/coverage/collect.py), [값 해셔](../cremore/coverage/hasher.py) | Secrets Manager, SSM, Vault/OpenBao KV v1/v2, global GCP Secret Manager. 선언한 범위만 수집 |
| 제출·저장 | [모델](../cremore/coverage/models.py), [store](../cremore/coverage/store.py), [API](../cremore/api/coverage.py) | 연결 전용 토큰, HMAC/엔진/정책 계약, 번호 있는 불변 배치, 멱등 재전송, 범위 개정, 실행 만료 |
| 대조 | [correlation](../cremore/coverage/correlation.py) | 값 일치/선언 금고 미발견/판단 불가와 ID 관계를 구분. 금고 읽기로 exposure/finding 생성·종료하지 않음 |
| 화면 | 콘솔의 [Secret 저장소](../web/console/views/vaults/page.tsx)와 Credential 상세 패널(2026-10-01 이전 대시보드 화면 삭제) | 연결 등록·수정·중지·토큰 교체·대조 범위 확인·실행/과거 근거·페이지 조회. 탐지 상세에서도 해당 자격증명의 보관 근거 조회 |
| AWS 발견 | [metadata worker 작업](../cremore/coverage/job.py) | 승인 계정 IAM 사용자 키, 선택 service-specific ID/root report, 선택 리전 CloudTrail 관리 이벤트. 전수 STS/비밀 원문 목록 아님 |
| AWS 인벤토리 API | `/api/v1/aws/accounts/{id}/credential-inventory`, `/refresh` | 기존 인벤토리 화면과 worker queue 연결. 계정 승인 필요. 응답 5,000건 초과는 명시적 부분 결과 |
| 콘텐츠 | 기존 S3·GitHub·Notion + [GitLab/GCS/Confluence/Bitbucket](../cremore/collectors/enterprise.py) | 연결→metadata catalog→승인 profile/plan→worker→결과/원본 링크. GitLab/Bitbucket commit·GCS generation 고정. Confluence는 현재 페이지/읽을 수 있는 첨부 |
| Enterprise | [호스트 해석](../cremore/github_hosts.py), [source 설정](../cremore/source_config.py) | github.com/GHES/ghe.com 구분, GitLab 설치 URL, Confluence·Bitbucket Cloud/Data Center 구분. 요금제 선언은 접근 성공의 증거가 아님 |
| 기존 Secrets Manager 조사 | [메타데이터 조사](../cremore/investigation/secrets_manager.py) | 값 읽기 없음. 5,000건 한도 도달 시 `PARTIAL`. 관리자 ARN 선언의 `POSSIBLE_MATCH`는 값 일치로 승격하지 않음 |

관측은 세 개의 추가 테이블 `coverage_connections`, `coverage_runs`, `coverage_batches`에
저장한다. 기존 credential 필수 fingerprint를 임의로 채워 발급 메타데이터를 넣지 않는다.
기존 데이터 마이그레이션 경로의 additive schema 생성으로 추가하며 기존 노출 데이터는 유지한다.
이전 바이너리로 되돌리면 새 기능을 사용하지 않을 뿐이며 신규 테이블을 삭제할 필요는 없다.

**현재성/완전성 계약**

- 서버가 실행 순서를 부여한다. 늦은 제출 시각으로 최신 실행을 뒤집지 않는다.
- 실행의 시작 시각을 기준으로 금고 유효 시간은 기본 24시간(설정 1–168시간)이다.
  노출 부재 판정에는 **같은 노출 관측**이 엔진/정책 호환과 24시간 이내 최신성을
  동시에 만족해야 한다. 서로 다른 관측의 조건을 조합하지 않는다. S3·Notion 증분 스캔이
  목록에서 변경 없음을 확인한 객체의 기존 노출은 같은 관측의 시각을 갱신한다.
  과거/키 교체 전 노출에 stamp가 없으면 재스캔 전까지 `UNKNOWN`이다.
- 현재 성공/부분 성공의 실제 HMAC 일치는 표시할 수 있다. 이전·삭제·파기·현재성 미확인
  버전은 과거 근거이며 현재 저장 일치를 만들지 않는다. 다른 stage/GCP alias만 읽은
  연결로 현재 금고에서의 부재를 확정하지 않는다.
- 최신 실패/진행 중 실행은 이전 결과를 현재로 재사용하지 않는다. 최근 실행들과 마지막
  비어 있지 않은 관측을 과거 근거로 함께 보여준다. 실행 기록은 DB에 남는다.
- 미연결·미확인 금고 범위, 범위/계약 변경, 부분/실패/오래된 수집은 부재 판정을
  막는다. 다른 금고의 일치 근거 자체를 지우지는 않는다.
- 중지한 금고 연결은 대조 범위에서 빠진다. 범위 revision이 바뀌므로 관리자가 새 범위를
  다시 확인하기 전까지 부재 판정을 막는다. 중지한 금고의 일치는 과거 근거로만 남는다.
- 오탐으로 판정한 finding/노출과 제거 위치는 현재 노출 분모에서 제외한다. 업무의
  `RESOLVED`만으로 위치를 제거하지 않는다. `E=0`, `U>0`, 범위 미확인/불완전이면 비율은 숨긴다.
- 한 실행의 최대 관측 250,000건, 배치 250건, 요청/값 크기 한도와 6시간 실행 만료가 있다.
  조회는 관측/탐지 각 100,000건을 상한으로 두며 초과 시 `REPORT_LIMIT_REACHED`,
  `summary.complete=false`와 부분 건수를 반환하고 부재·퍼센트를 확정하지 않는다.
  대규모 설치는 리전/namespace/경로를 분할해 수집하고 조회 상한을 운영 용량에 포함한다.

### 8.1 로컬·EC2·EKS

| 배포 | 준비된 구성 | 운영자가 제공할 것 |
|---|---|---|
| 로컬 | [Compose](../docker-compose.yml), loopback·로컬 인증 | 승인된 로컬 AWS 프로필, 영속 DB/키 |
| EC2/공유 서버 | [TLS/OIDC overlay](../deploy/compose/reverse-proxy/README.md), [instance profile overlay](../deploy/compose/ec2-instance-profile.yml), 핵심 서비스 재시작 정책 | DNS·TLS·IdP·백업, instance role/IMDSv2의 실제 접근과 신원 승인 |
| EKS | [Helm](../deploy/helm/README.md), API/worker/web 분리·OIDC·TLS·probe·NetworkPolicy | 외부 DB/Secrets/인증서, IRSA 또는 Pod Identity association, ingress와 신원 승인 |

API/worker 연결 실패 안내는 로컬 프로필, EC2 instance role, IRSA, container role,
서버 workload를 구분한다. Pod Identity를 쓸 때 `networkPolicy.eksPodIdentity=true`로
agent의 IPv4/IPv6 TCP 80을 허용한다. 기본값은 false이며 다른 인터넷 HTTP를 열지 않는다.
EC2 overlay는 CLI 파일 대신 instance profile을 사용하며 SSO 계정 발견을 비활성화한다.
일반 SSO/Organizations/승인 scanner·remediation 신원 분리는 유지한다.

### 8.2 온보딩

콘텐츠는 **배포→관리자 로그인→연결/실행 신원 승인→접근 검증→metadata catalog→
선택 범위 승인→스캔** 순서다. 새 제공자는 기존 scope profile·task lease·예산·재스캔·
이벤트 경로에 연결한다. 선택하지 않은 root나 다른 호스트로 토큰을 보내지 않는다.
대시보드가 고객의 EC2/EKS/IAM 역할을 직접 배포하거나 권한을 부여하지는 않는다.

현재 서버 응답에는 legacy UI의 영속 `onboarding`/`inspection` 단계 엔진이 없다.
새 연결 등록은 실제 구현한 등록 → 선언 저장 → `credential/check` queue로 연결했다.
설정 화면은 저장 연결 상태, 인증 점검, `resources/refresh`, 기존 범위 편집기를 사용한다.
없는 `/probe`·inspection 시작·checkpoint 저장 API를 호출하거나 영구 로딩을 표시하지 않는다.
AWS는 역할 배포 안내 후 `onboarding/validate`로 검증하고, 기존 연결 재점검은 `/validate`를
사용한다. queue 접수와 worker 완료는 구분하며 새로고침으로 결과를 확인한다.

금고는 **coverage 연결 등록→제출 토큰과 HMAC 키를 고객 해셔에 주입→수집→등록 금고를
대조 범위로 명시 확인→결과 조회** 순서다. IAM/CloudTrail 연결은 승인 AWS 계정의
worker에서 metadata 수집을 예약할 수 있다. 금고 값 수집은 기본적으로 고객 환경에서 실행한다.

AWS Secrets Manager·SSM 연결만 관리자가 `server_collection=true`를 명시하면 worker가 수집한다.
IAM/CloudTrail과 같은 `aws-credential-inventory` 작업·계정 스캐너 승인 pin·리스·범위 revision 재확인을
쓰며, 수집 API(`POST /api/v1/coverage/connections/{id}/collect`)와 선택적 `schedule_minutes`(5분 이상,
AWS 인벤토리 자동 수집이 계정을 허용할 때만)로 실행한다. 값은 CLI와 같은 `collect_aws_vault`로 메모리에서
지문화하고 원문·job·checkpoint에 남기지 않는다. 스캐너 세션의 기본 읽기 전용 목록은 바뀌지 않는다.
이 작업만 `secretsmanager:GetSecretValue`·`ssm:GetParametersByPath`를 추가한 별도 목록을 쓰므로,
콘텐츠 스캔·조사 경로는 여전히 값을 읽을 수 없다. 실제 읽기는 고객이 스캐너 역할에 부여한 IAM 권한(대상
비밀·경로의 값 읽기와 KMS 복호화)으로 제한된다. 옵션이 꺼진 금고 연결의 수집 요청은 기존처럼
`409 VAULT_COLLECTION_RUNS_IN_CUSTOMER_ENVIRONMENT`다.

목록에 없는 금고는 `external_vault` 연결로 JSON Lines 내보내기나 읽기 플러그인을 대조하고, 다른 Vault 클러스터는
연결 자신의 로그인으로 서버에서 읽을 수 있다. 근거 수준과 절차는 [범용 금고 문서](EXTERNAL_VAULT.md)를 따른다.

Vault/OpenBao 연결의 서버 수집은 연결 자신의 로그인(`server_auth`)이 없으면 그 `endpoint`가 설치의 `SECRET_STORE_URL`과 같을 때만 실행한다.
worker는 이미 가진 비밀 저장소 신원(`SECRET_STORE_TOKEN` 또는 Kubernetes 인증)을 그 주소에만 보내며,
토큰을 연결·DB·job에 저장하지 않는다. 주소가 다르면 작업은 `VAULT_SERVER_IDENTITY_NOT_CONFIGURED`로
실패하고 요청을 보내지 않는다. 같은 `aws-credential-inventory` 작업 종류·리스·범위 revision 재확인을 쓰지만
AWS 승인은 관여하지 않는다. 주기 수집은 연결의 `schedule_minutes`(5분 이상)로만 켜지며 설치의 스케줄 허용
설정이 켜져 있어야 한다. 그 신원의 ACL은 승인한
마운트·접두사의 읽기로 제한해야 한다. GCP Secret Manager는 고객 측 CLI의 schema 1 연결 또는 worker의
schema 2 `gcp` 연결(`vault_value`) 중 하나를 쓴다. 선택 기준과 중복 등록 주의는 [GCP 문서](../gcp/README.md)에 있다.
[운영 안내](../deploy/coverage/README.md)와 [CronJob 예제](../deploy/coverage/cronjob.yaml)에
CLI, TLS, 인증 참조, 주기·실패 감시, 권한 경계를 정리했다.

### 8.3 실제 환경에서 확인해야 할 것

실제 EC2/EKS·IdP·AWS/GitLab/Bitbucket/Confluence/Vault 계정으로 배포하거나 수집하지 않았다.
따라서 다음은 설치별 인수 조건이다: OAuth/ADC/Vault Agent/STS 토큰 갱신, 실제 제품
버전/API 권한, 사내 CA·proxy·private endpoint, Pod Identity agent/IMDS 경로,
노드/VM 재시작과 영속 DB 복구. 합성 응답의 성공은 이 조건을 대신하지 않는다.

Confluence OAuth 발급·갱신과 Vault cloud/Kubernetes/AppRole 인증은 기존 고객 인증
시스템·Vault Agent를 사용한다. CreMore는 별도의 고객 OAuth 앱 등록·토큰 발급 서비스를
구현하지 않는다. Cloud API base와 원본 사이트 URL은 따로 입력할 수 있다.
Confluence의 외부/CDN 첨부 리다이렉트는 자동 인증 전달하지 않고 부분 수집으로 표시한다.
GCP regional Secret Manager, 동적 Vault secrets engine, 임의 호스트/Pod 파일 수집,
Lambda/CloudWatch Logs/CloudFormation 콘텐츠, Git 전체 이력·LFS는 이번 범위에 없다.

### 8.4 검증

Python 전체 회귀와 새 관측/권한/실패/재전송/어댑터 테스트, PostgreSQL 격리 스키마의
동시 제출·task/plan 테스트, Node 단위 테스트, TypeScript, 합성 브라우저,
Helm/Compose 렌더링을 사용한다. 명령·최종 결과는 9.3에 기록한다.
실제 공급자 호출·실제 클라우드 배포·자격증명 재발급은 수행하지 않았다.

---

## 9. 구현과 검증 현황

핵심 흐름은 **기존 노출 + 여러 고객 금고의 보관 관측 → 대조 → 대시보드**다.
**AWS 발급 메타데이터 → 아직 노출되지 않은 키도 조사 목록에 표시**하는 발견 경로를 추가했다.
기존 값 대조는 독립적으로 구현하며 GitHub/Notion 발급 목록의 완성을 기다리지 않는다.
표는 현재 구현 범위다. 실제 기업 계정/제품 버전 인증은 8.3의 별도 인수 조건이다.

| 단계 | 구현 결과 | 인수 기준 |
|---|---|---|
| 1 | 관측/제출 계약과 실행 스냅샷 | 범위·시점·현재 버전·미해결·빈 성공·키 호환·제출 귀속 의미 확정 |
| 2 | 고객 측 Secrets Manager 어댑터 → 기존 노출 대조 → 상세 화면 | 값 일치·미일치·판단 불가를 한 연결에서 끝까지 확인 |
| 3 | Vault Enterprise/HCP Dedicated·OpenBao KV v2 추가 | namespace/mount/경로와 버전 보존, 여러 금고의 중복·부분 실패를 같은 화면에서 확인 |
| AWS 발견 확장 | 승인 계정의 IAM 사용자 키 메타데이터 → 금고·노출 관측 연결 | 노출 없이도 키 존재를 표시. ID 관계와 값 일치 구분, 미연결/부분 수집 표시. 10.4의 범위로 검증 |
| 4 | 확장 제공자의 콘텐츠 수집 | GitLab 제품군·GCP Cloud Storage·Confluence/Bitbucket Cloud/Data Center를 각각 승인 범위부터 결과까지 구현 |
| 함께 검증 | 기존 AWS·GitHub·Notion의 기업 환경 | 파티션/Cloud 레지던시/제품 버전/Enterprise 접근 정책을 실제 지원 범위로 명시 |
| 함께 검증 | 로컬·EC2·EKS 배포와 온보딩 | 배포 구성·신원 안내·승인/범위 UI는 합성 검증. 실제 인증 갱신·노드 재시작·DB 복구는 8.3의 운영 인수 조건. 금고 해셔 권한 경계 유지 |
| 추가 금고 범위 | KV v1·global GCP Secret Manager·SSM | 버전/alias/권한/형식의 차이를 어댑터에서 처리. 메타데이터만으로 값 일치를 주장하지 않음 |
| 별도 선택 | 다른 발급자 조사·외부 도구 해시 임포트 | 기능의 실제 필요와 호환 계약이 확인된 경우. 핵심 대조를 막지 않음 |

첫 다중 금고 흐름에는 Secrets Manager뿐 아니라 사용자가 요청한 Vault/OpenBao를
포함한다. 구현 중 서로 다른 제품 API를 억지로 한 수집기로 합치지 않고, 기존 Engine·
fingerprint·수집 예산·실행/인증 패턴처럼 의미가 같은 부분만 공유한다.
새 provider framework나 별도 서비스부터 만들 필요는 없다.

### 9.1 재사용 조건

아래 체크는 구현과 로컬/합성 검증의 결과다. 고객 제품/배포의 운영 인수는 8.3에 남겨 둔다.

- [x] 고객 금고의 값 읽기는 scanner 역할과 분리하고 기존 scanner Deny를 유지한다.
- [x] 고객 측 해셔는 Engine/material을 공유하고 `verify=False`를 명시한다.
- [x] 수집/탐지 한도와 형식 해석 실패를 실행/범위의 완전성에 반영한다.
- [x] 금고 관측으로 exposure/finding을 새로 만들거나 기존 노출을 닫지 않는다.
- [x] fingerprint·키·정책 호환성을 대조 전에 확인한다.
- [x] 제출 인증·설치/연결/범위 귀속·입력 제한·원문 없는 감사를 기존 API 경계에 맞춘다.
- [x] 새 노출 제공자는 연결·카탈로그·승인 범위·worker·결과/링크까지 같은 계약을 지킨다.

### 9.2 회귀 검증 사례

- [x] 기존 노출과 같은 값이 서로 다른 두 금고에 있으면 정확히 연결되고 자격증명은 한 번 계산됨.
- [x] AWS 키뿐 아니라 지원되는 GitHub/Notion/GitLab 토큰이 다른 제품의 금고에서도 대조됨.
- [x] ID-only·이름-only·다중 쌍·분리 저장·generic material 불일치는 `MATCHED`가 되지 않음.
- [x] namespace·mount·계정이 다른 같은 경로를 다른 위치로 보존함.
- [x] KV v1/v2·현재/이전/삭제/파기 버전·GCP alias 차이를 지원 범위에 맞게 처리함.
- [x] 한 금고의 실패가 다른 금고의 정확한 일치 근거를 지우지 않으며, 미일치의 부재 판정은 막음.
- [x] 페이지/리전/namespace 실패·항목 한도·미지원 형식에서 미보관이나 퍼센트를 단정하지 않음.
- [x] 빈 성공·실패·부분 성공·stale·범위 변경과 `E=0`, `U>0`을 구분함.
- [x] 다른 키/방식 제출은 거부하고 재전송·동시 수집·늦은 자료가 최신 스냅샷을 역행시키지 않음.
- [x] GHES/Cloud 레지던시·GitLab 설치·Confluence/Bitbucket 배포별 인증/링크와 호스트 경계를 지킴.
- [x] 제출물/DB/오류 로그에 비교 대상 원문이나 불필요한 공급자 메타데이터를 남기지 않음.
- [x] IAM에만 존재하는 키도 조사 목록에 나오며, 가짜 fingerprint·노출 finding을 만들지 않음.
- [x] IAM/금고의 부분 수집·시점 차이와 ID-only 근거를 값 일치·전사 미보관으로 승격하지 않음.
- [x] 정상 역할 기반 임시 자격증명을 금고 미보관만으로 관리 누락에 포함하지 않음.

### 9.3 최종 실행한 검증 — 2026-09-20

현재 작업 트리에서 다음을 실행했다. Python의 PostgreSQL 검증은 별도 로컬
`postgres:17-alpine` 컨테이너와 매 테스트의 격리 스키마를 사용했다. 테스트 연결은
`CREMORE_TEST_POSTGRES_URL`로 전달했고 운영 DB나 고객 계정은 사용하지 않았다.

| 검증 | 명령/작업 디렉터리 | 결과 |
|---|---|---|
| Python 전체 회귀 | 저장소 루트에서 `python -m pytest -q` | **3,744 passed**, 실패·skip 없음. 287.98초. memory/SQLite/PostgreSQL 포함 |
| 웹 단위 테스트 | `web`에서 `node --test tests/*.test.cjs` | **410 passed** |
| 합성 브라우저 | `web`에서 `node tests/run-browser-proofs.cjs` | **17/17 passed**. 마지막 필터 변경 후 coverage/density **2/2 추가 통과** |
| TypeScript / 프로덕션 웹 | `web`에서 `npx tsc --noEmit`, `node node_modules/next/dist/bin/next build` | 타입 검사·Turbopack 빌드·정적 페이지 생성 통과. 최종 빌드에도 타입 검사 포함 |
| Helm / Compose | 루트에서 `node --test deploy/helm/tests/chart.test.cjs` | **44 passed**. Pod Identity 정책·EC2 overlay·재시작 정책·TLS/OIDC 렌더링 포함 |
| 고객 수집기 CronJob | `deploy/coverage/cronjob.yaml`의 YAML 파싱·실행 명령·동시 실행 금지 확인 | 통과. 실제 EKS 배포는 하지 않음 |
| Python 배포 이미지 | `docker build -f deploy/docker/python.Dockerfile -t cremore-coverage-proof:20260920 .` | hash 고정 의존성 설치·wheel 생성·`pip check` 통과 |
| 수집기 컨테이너 | 위 이미지에서 `--network none --read-only --cap-drop ALL`로 `cremore-coverage --help`와 GCP 인증 모듈 import | 비특권 런타임에서 통과. 실제 인증/수집 호출 없음 |
| 변경/문서 | `git diff --check`, 문서 참조·로컬 링크, 기존 index blob 비교 | 통과. 기존 스테이징 상태 보존, 커밋하지 않음 |

핵심 증거는 [coverage 회귀](../cremore/coverage/coverage_test.py),
[콘텐츠 수집/범위 회귀](../cremore/collectors/enterprise_test.py),
[원본 링크 회귀](../cremore/api/finding_evidence_test.py),
[저장 이력 화면 검증](../web/tests/console-receipts.browser.cjs),
[Secret 저장소 단위 검사](../web/tests/console-vaults.test.cjs)에 있다(이전 대시보드의 화면 검증은 2026-10-01 삭제).
보관 필터가 분모를 바꾸지 않는지, 늦은 조회가 다른 finding의 근거로 표시되지 않는지,
등록/권한 실패가 성공으로 보이지 않는지, Bitbucket 양 배포의 입력·인증·페이지네이션·
SHA 고정·범위 제한도 확인했다. 자체 호스팅 GitLab PAT는 public GitLab에 전송하지 않는다.

이 결과는 **합성 공급자 응답·로컬 DB/브라우저·로컬 이미지**에 대한 검증이다.
실제 AWS/GitHub/GitLab/Bitbucket/Confluence/GCP/Vault 인스턴스와 EC2/EKS·IdP를
대상으로 한 버전·권한·토큰 갱신·재시작 복구 검증은 8.3에 명시한 운영 인수로 남는다.

---

## 10. AWS에서 놓친 자격증명을 발견할 수 있는 범위

추가 목표는 **금고에도 노출 결과에도 아직 없는 자격증명의 존재까지 파악**하는 것이다.
이를 위해 AWS가 가진 발급 메타데이터를 읽어 발견 입력으로 사용한다. 발급·회전을 관리하는
별도 대장을 만들거나 원문 비밀을 중앙에 복제하는 작업은 아니다.

**승인된 계정의 현재 IAM 사용자 접근키 목록은 수집할 수 있다. AWS의 모든 자격증명
원문이나 과거·임시 자격증명 전체를 한 API로 회수할 수는 없다.** 존재를 목록화하는 것,
금고의 보관 근거를 확인하는 것, 콘텐츠에서 실제 노출을 찾는 것은 각각 별도 관측이다.

### 10.1 AWS 종류별 가능 범위

| 대상 | 공식적으로 확인할 수 있는 것 | 전수 관측의 한계 |
|---|---|---|
| IAM 사용자 장기 접근키 | 승인 계정의 `ListUsers`·`ListAccessKeys`로 키 ID·주체·상태·생성 시각. 노출/금고에 없어도 존재 확인 가능 [AWS-USERS][AWS-LIST-KEYS] | secret access key는 생성 후 재조회 불가. 현재 목록은 이미 삭제된 키의 전체 이력이 아님 [AWS-KEYS] |
| root 자격증명 | credential report의 root 행에서 키 활성·암호·MFA 등 상태 확인 [AWS-CREDENTIAL-REPORT] | 보고서는 키 ID 목록이나 비밀 원문이 아님. Organizations 중앙 root 관리의 별도 감사 경로도 있으나 현재 scanner 지원에 포함되지 않음 [AWS-ROOT-AUDIT] |
| 역할·Identity Center·EC2/EKS의 임시 자격증명 | 승인된 감사 로그에서 사용된 식별자·주체·세션 흔적 관측 | 공개 STS API에 전체 발급 세션/비밀을 나열하는 기능은 없음. 동적으로 발급·만료되며 금고에 저장하지 않는 것이 정상일 수 있음 [AWS-STS-ACTIONS][AWS-TEMP-CREDS] |
| 서비스별 장기 자격증명 | `ListServiceSpecificCredentials`의 서비스별 ID·주체·상태 등. CodeCommit/Keyspaces 자격증명과 Bedrock·CloudWatch 계열 장기 API key도 별도 고려 [AWS-SERVICE-CREDS][AWS-SERVICE-API-KEYS] | 일반 `ListAccessKeys`나 credential report만으로 다 포함되지 않음. 해당 ID 수집은 구현. ID-only 관계이며 서비스 비밀 원문 대조/복원은 아님 |
| IAM 암호·서명 인증서 등 | credential report에 포함되는 설정/활성 상태 [AWS-CREDENTIAL-REPORT] | 암호·private key 복원 기능이 아님. 모든 종류를 장기 접근키와 같은 금고 보관 기준으로 분류하지 않음 |
| AWS 안의 파일·설정·로그에 남은 비밀 | 승인된 콘텐츠 수집 범위에서 실제 값이 관측되면 기존 탐지 엔진으로 분류 가능. AWS 키뿐 아니라 외부 서비스 토큰·애플리케이션 비밀번호도 대상 | IAM 발급 목록은 이 전체를 나열하지 않음. S3 외 Lambda 설정·로그·컨테이너/호스트 내부 등은 별도 접근·수집 범위이며 현재 수집기 지원을 뜻하지 않음 |

credential report는 최대 4시간 전 생성본이 반환될 수 있으며 서비스별 자격증명을 포함하지
않는다.[AWS-CREDENTIAL-REPORT] CloudTrail Event history는 계정·리전별 최근 90일의
관리 이벤트이며 데이터 이벤트와 조직 전체 집계를 제공하지 않는다.[AWS-TRAIL-HISTORY]
로그가 없다는 사실만으로 미사용·미발급을 확정하지 않는다. 과거 기록이나 미접근 파일을
포함해 모든 자격증명을 발견했다는 보장은 하지 않는다.

AWS에 저장된 비밀의 예로 Lambda는 환경변수에 DB 자격증명·API key 등을 넣는 대신
Secrets Manager 사용을 권장한다.[AWS-LAMBDA-ENV] 이런 원본의 내용 수집은 별도 승인한
범위에서만 설계하며, 플랫폼을 EC2/EKS에 설치한 것만으로 호스트·Pod 내부 접근이 생기지 않는다.
이 절의 수집은 존재·안전한 대조 자료·발견 근거의 수집이며 원문 비밀의 중앙 수집이 아니다.

### 10.2 금고 미발견과 관리 누락의 구분

**금고에서 찾지 못함은 관리 누락의 후보 근거다.** 조직이 금고 보관을 요구하는 장기 키인지,
허용한 다른 저장 방식이 있는지, 해당 금고들을 실제로 읽고 해석할 수 있었는지를 함께 본다.
역할 기반 임시 자격증명은 장기 키 보관 정책의 위반 건수에 자동으로 포함하지 않는다.

| 확보한 근거 | 대시보드 의미 |
|---|---|
| IAM 목록에 키가 있고 노출은 아직 없음 | 발급 확인 · 선택한 스캔에서 노출 미관측. 비밀 원문을 몰라도 조사 목록에 표시 |
| IAM 키 ID가 금고에서 관측한 ID와 같음 | 보관 식별자 관계. ID만 같다는 이유로 비밀 값 일치 `MATCHED`를 만들지 않음 |
| IAM 키는 있지만 금고에서 연결할 근거가 없음 | 금고 보관 근거 미확인. 완료된 식별자 검색과 수집/형식 문제의 `UNKNOWN`을 구분하며 전사 미보관을 단정하지 않음 |
| 노출의 완전한 키 재료와 금고의 값 fingerprint가 같음 | 기존 5장의 노출됨 · 금고 보관 확인. 발급 목록이 없어도 성립 |
| 사용 이력만 있고 현재 IAM 목록에 없음 | 사용이 관측된 식별자. 임시 키·삭제·시점 차이·계정 범위를 확인하며 현재 발급 키로 단정하지 않음 |

IAM은 secret을 반환하지 않으므로 **IAM 발급 목록 자체와 값 HMAC을 직접 대조할 수 없다.**
발급 ID와 금고/노출에서 추출한 식별자의 관계는 별도 근거다. 금고에 secret만 있거나
ID/secret이 분리되어 있으면 그 대응이 불명확하며, 보관 누락으로 자동 확정하지 않는다.
정확한 노출·금고 값 대조에는 계속 4.5의 동일 material/fingerprint 계약을 적용한다.

### 10.3 현재 수집 경로

- [조직 계정 발견](../cremore/aws_org_discovery.py)과 [계정 세션](../cremore/aws_sessions.py)은
  재사용할 수 있다. Organizations의 계정 목록 열람 권한이 각 멤버 계정의 수집 권한을
  부여하는 것은 아니다.[AWS-ORG-ACCOUNTS] 미연결·거부된 계정도 범위의 공백으로 표시한다.
- [현재 IAM 조사](../cremore/api/dashboard.py)의 `_access_key_metadata()`는 **이미 발견한
  키 하나**를 조회하는 기존 경로다. 새 [coverage 수집](../cremore/coverage/collect.py)은
  `ListUsers`/`ListAccessKeys` 페이지를 순회하고 선택한 service-specific ID와 root report를
  수집한다. [scanner allowlist](../cremore/aws_readonly.py)와 배포 정책에 필요한 metadata
  작업을 반영했으며 Secrets Manager 값 읽기 Deny는 유지한다.
- [사용 이력 수집기](../cremore/investigation/usage.py)는 알려진 키 ID로 조회한다.
  신규 CloudTrail 어댑터는 승인 계정/리전의 지정 기간 관리 이벤트에서 이전에 몰랐던
  사용 키 ID를 발견한다. 발급 목록과 별도 `USAGE` 근거이며 조직 전체 로그/STS 목록이 아니다.
- 현재 AWS 콘텐츠 수집은 [S3 경로](../cremore/worker/factory.py)다. Lambda 설정,
  CloudWatch Logs, EC2 파일, ECS/EKS 내부 콘텐츠를 자동으로 수집하는 기능은 없다.
- 발급 메타데이터는 [현재 credential 스키마](../cremore/db/schema.py)의 필수 fingerprint를
  임의로 채워 저장하지 않는다. 기존 실행/스냅샷 패턴으로 별도 관측을 보존하고 노출이 없는
  키에도 조사 화면을 제공한다. `credentials`·노출 finding을 만드는 경로는 그대로 분리한다.

### 10.4 AWS 발견 확장의 최소 완료 범위

1. **승인 계정의 IAM 사용자 접근키 목록**: 활성/비활성을 함께 수집하고 계정·사용자·키 ID·
   상태·생성 시각·관측 시각을 보존한다. IAM 목록을 리전마다 중복 계산하지 않는다.
   `ListUsers`와 `ListAccessKeys`의 페이지 완료 여부를 확인하고, 실패/한도/수집 중 삭제를
   완전한 빈 결과로 처리하지 않는다. 조회 구간의 결과이지 원자적 전사 스냅샷은 아니다.
2. **발견 근거 연결**: IAM에만 있는 키도 표시하고 금고/노출의 ID 관계와 값 일치를 구분한다.
   IAM에서 찾지 못한 기존 노출·금고 관측도 지우지 않는다. 발급 메타데이터를 2.2의 노출
   분모에 섞지 않으며, secret 재발급·사용 시험으로 목록의 빈 정보를 채우지 않는다.
3. **조사 우선순위와 미확인 범위**: 활성 상태·보관 근거·CloudTrail 관측을 조사 입력으로
   제공한다. 정책 위반 확정·담당자 추정·발급 전용 키의 최근 사용 일괄 조회는 하지 않는다.
   `GetAccessKeyLastUsed`는 최근 시각/서비스/리전의 근거이며
   전체 사용 이력이나 소비자가 금고를 사용한다는 증명은 아니다.[AWS-LAST-USED]
4. **추가 범위 구분**: root 감사, 서비스별 장기 자격증명, 감사 로그 기반 신규 식별자 발견,
   S3 외 콘텐츠 수집은 각각 별도 완료 조건을 둔다. IAM 사용자 키 수집만으로 “AWS의 모든
   자격증명 지원 완료”라고 하지 않는다. 현재 root report·service-specific ID·CloudTrail
   사용 관측까지 합성 검증했고, S3 외 콘텐츠는 별도 확장 범위다. 실제 계정 수집은 하지 않았다.

### 10.5 다른 발급자의 조회

이번 가능성 검토는 AWS 대상이다. GitHub의 fine-grained PAT 목록·SSO 승인 목록은
권한/제품 조건이 있으며, Notion의 사용자/봇 목록이나 콘텐츠 웹훅은 토큰 발급 목록이 아니다.
[GH-PATS][GH-SAML][NOTION-USERS][NOTION-WEBHOOKS][NOTION-EVENTS]
다른 발급자는 별도 선택 범위로 두며 AWS 발견이나 기존 금고·노출 대조를 막지 않는다.
classic PAT 전체가 관측 불가라고 단정하거나 Notion에 웹훅이 없다고 하지 않는다.
`ORPHANED` 같은 발급 목록 부재 판정에는 별도의 완전한 모집단이 필요하다.

---

## 11. 확정한 구현 선택과 운영 인수

- 제출: 같은 설치의 engine/policy digest와 HMAC key, 연결 전용 토큰, 서버 실행 순서,
  불변 배치·수량 검증을 사용한다. 제출 토큰은 일반 대시보드 권한을 주지 않는다.
- 범위: 활성 금고들의 revision을 명시 확인한다. 금고 추가·범위 변경·중지는 범위를 바꾸므로
  다시 확인해야 한다. 전체 조직 미보관이나 모든 서비스의 발급 목록을 주장하지 않는다.
- 값: 같은 Engine material을 사용한다. 단일 토큰/명확한 AWS 단일 쌍은 비교하고,
  다중/분리 AWS 재료·바이너리·미인식 형식은 미해결로 처리한다. 각 금고 항목을 임의 결합하지 않는다.
- 인증: AWS SDK 체인, GCP ADC, 기존 secret_ref, Vault Agent를 재사용한다.
  비밀 원문이나 지문 키를 브라우저 제출 계약에 추가하지 않는다.
- 데이터: 기존 findings와 분리된 관측 테이블, 기존 worker lease와 계정 승인, 명시적
  완전성/유효 시간으로 처리한다. 발급 원문을 얻기 위한 신규 키 발급·인증 시도는 하지 않는다.
- 남은 운영 인수: 8.3의 실제 제품 버전·배포·권한·인증 갱신/복구 확인이다. 배포 예제가 있다는
  사실과 해당 기업 환경에서 운영 검증을 마쳤다는 사실을 구분한다.

---

## 출처와 확인 범위

공식 문서는 **2026-09-20 열람 기준**이다. API의 제품/버전/권한 조건이 바뀔 수 있으므로
커넥터 구현 시 다시 확인한다. 실제 고객 계정의 권한·완전성을 이 문서 검토로 검증한 것은 아니다.
시장 비교는 아래 공식 자료에서 확인한 기능만 사용하며 검색 요약·비교 블로그를 기능 부재의
근거로 삼지 않는다.

[AWS-KEYS]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
[AWS-USERS]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html
[AWS-LIST-KEYS]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html
[AWS-CREDENTIAL-REPORT]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html
[AWS-ROOT-AUDIT]: https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html#security-iam-awsmanpol-IAMAuditRootUserCredentials
[AWS-STS-ACTIONS]: https://docs.aws.amazon.com/STS/latest/APIReference/API_Operations.html
[AWS-TEMP-CREDS]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html
[AWS-SERVICE-CREDS]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListServiceSpecificCredentials.html
[AWS-SERVICE-API-KEYS]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_api_keys_for_aws_services.html
[AWS-TRAIL-HISTORY]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html
[AWS-LAMBDA-ENV]: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
[AWS-ORG-ACCOUNTS]: https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListAccounts.html
[AWS-LAST-USED]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccessKeyLastUsed.html
[AWS-SM-LIST]: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_ListSecrets.html
[AWS-SM-GET]: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
[AWS-SM-ENTRY]: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_SecretListEntry.html
[AWS-SSM-META]: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_ParameterMetadata.html
[AWS-SSM-HISTORY]: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_ParameterHistory.html
[AWS-ANALYZER]: https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-manage-unused.html
[AWS-IMDS]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
[EKS-POD-IDENTITY]: https://docs.aws.amazon.com/eks/latest/userguide/pod-id-how-it-works.html
[GH-PATS]: https://docs.github.com/en/rest/orgs/personal-access-tokens#list-fine-grained-personal-access-tokens-with-access-to-organization-resources
[GH-SAML]: https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#list-saml-sso-authorizations-for-an-organization
[GH-SECRETS]: https://docs.github.com/en/rest/actions/secrets#list-repository-secrets
[NOTION-USERS]: https://developers.notion.com/reference/get-users
[NOTION-WEBHOOKS]: https://developers.notion.com/reference/webhooks
[NOTION-EVENTS]: https://developers.notion.com/reference/webhooks-events-delivery
[VAULT-NS]: https://developer.hashicorp.com/vault/api-docs/system/namespaces
[VAULT-KV]: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2
[VAULT-SYNC]: https://developer.hashicorp.com/vault/docs/sync/awssm
[GG-SCOUT]: https://docs.gitguardian.com/ggscout-docs/home
[GG-SCOUT-DETAIL]: https://docs.gitguardian.com/ggscout-docs/what-is-ggscout
[GG-SELFHOST]: https://docs.gitguardian.com/self-hosting/home
[GG-COVERAGE]: https://blog.gitguardian.com/vault-coverage/
[GG-HMSL]: https://docs.gitguardian.com/ggshield-docs/reference/hmsl/overview
[GG-HMSL-FP]: https://docs.gitguardian.com/ggshield-docs/reference/hmsl/fingerprint
[GG-PROTOCOL]: https://blog.gitguardian.com/hasmysecretleaked-building-a-trustless-and-secure-protocol/
[RADAR]: https://developer.hashicorp.com/hcp/docs/vault-radar
[RADAR-SECURITY]: https://developer.hashicorp.com/hcp/docs/vault-radar/security-model
[AWS-PARTITIONS]: https://docs.aws.amazon.com/whitepapers/latest/aws-fault-isolation-boundaries/partitions.html
[GH-CLOUD-REST]: https://docs.github.com/en/enterprise-cloud@latest/rest/using-the-rest-api/getting-started-with-the-rest-api
[GH-SERVER-REST]: https://docs.github.com/en/enterprise-server@3.22/rest/using-the-rest-api/getting-started-with-the-rest-api
[GH-RESIDENCY]: https://docs.github.com/en/enterprise-cloud@latest/admin/data-residency/about-github-enterprise-cloud-with-data-residency
[NOTION-CONNECTIONS]: https://www.notion.com/help/add-and-manage-connections-with-the-api
[GL-REPOS]: https://docs.gitlab.com/api/repositories/
[GL-FILES]: https://docs.gitlab.com/api/repository_files/
[GL-AUTH]: https://docs.gitlab.com/api/rest/authentication/
[GCS-LIST]: https://docs.cloud.google.com/storage/docs/json_api/v1/objects/list
[GCS-GET]: https://docs.cloud.google.com/storage/docs/json_api/v1/objects/get
[GCP-ADC]: https://docs.cloud.google.com/docs/authentication/application-default-credentials
[CONF-V2]: https://developer.atlassian.com/cloud/confluence/rest/v2/intro/
[CONF-PAGES]: https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-page/
[CONF-DC-PAGING]: https://developer.atlassian.com/server/confluence/pagination-in-the-rest-api/
[CONF-DC-EXPAND]: https://developer.atlassian.com/server/confluence/expansions-in-the-rest-api/
[CONF-DC-PAT]: https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html
[CONF-OAUTH]: https://developer.atlassian.com/cloud/confluence/oauth-2-3lo-apps/
[CONF-AUTH]: https://developer.atlassian.com/cloud/confluence/basic-auth-for-rest-apis/
[VAULT-KV1]: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1
[HCP-VAULT]: https://developer.hashicorp.com/hcp/docs/vault/what-is-hcp-vault
[BAO-KV]: https://openbao.org/docs/secrets/kv/kv-v2/
[BAO-NS-DOC]: https://openbao.org/docs/concepts/namespaces/
[GCP-SM-ACCESS]: https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions/access
[GCP-SM-ALIAS]: https://docs.cloud.google.com/secret-manager/docs/assign-alias-to-secret-version
[GCP-SM-VERSION]: https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions
[GCP-SM-REGIONAL]: https://docs.cloud.google.com/secret-manager/regional-secrets/overview-rs
[BB-SOURCE]: https://developer.atlassian.com/cloud/bitbucket/rest/api-group-source/
[BB-DC]: https://developer.atlassian.com/server/bitbucket/rest/v1000/api-group-repository/
[BB-TOKEN]: https://support.atlassian.com/bitbucket-cloud/docs/using-api-tokens/
