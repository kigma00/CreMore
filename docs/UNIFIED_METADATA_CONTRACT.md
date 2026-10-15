# 전체 수집 메타데이터의 공통 정규화 계약

상태: **설계 결정 — 코드·DB 전환은 아직 적용하지 않았다.**
기준 소스: `1551f19`. 범위는 사용자가 선택한 전체 수집 메타데이터이며,
자격증명·권한·감사 정보뿐 아니라 페이지·저장소·버킷 등 콘텐츠 리소스 목록을 포함한다.
이 문서의 목표 계약을 현재 구현 완료 또는 실제 공급자 수집 지원의 증거로 사용하지 않는다.

## 결정

공급자별 입력을 플랫폼의 **하나의 버전 있는 정규화 레코드 계약**으로 변환한다.
신규 SaaS·클라우드·서드파티는 공급자 소유의 매핑과 명시적 등록으로 연결한다.
같은 의미의 데이터를 공급자마다 다른 테이블·상태·시각 형식으로 다시 정의하지 않는다.

현재 `metadata_models.py`의 네 레코드를 기준으로 공통 계약을 확장한다.
공통 계약은 저장·조회·내보내기의 의미를 정하며, 공급자 원본 API의 이름이나 버전에 종속되지 않는다.
모든 공급자가 네 종류를 반드시 생성할 필요는 없다. 수집하지 않은 관계·이벤트를 만들지 않는다.

| 레코드 | 의미 | 예 |
| --- | --- | --- |
| `EntityObservation` | 특정 시점에 관측한 객체 | 발급 자격증명, 사용자, 저장소, 페이지, 버킷, 비밀 버전 |
| `MetadataRelation` | 근거가 있는 객체 사이의 관계 | 소유, 소속, 접근 권한, 설치, 보관 위치 |
| `ProviderEvent` | 공급자가 보고한 사건 | 감사 이벤트, 특정 자격증명 사용 관측 |
| `OperationReport` | 수집 범위·완전성·실패·누락 | 페이지 일부 실패, 권한 부족, 지원되지 않는 기능 |

콘텐츠 원문, 실제 비밀 값, CreMore 자체 작업 이력은 수집 메타데이터와 별도 계약이다.
수집한 비밀 원문은 메모리에서만 처리하고 가역 암호화 형태도 저장하지 않는다. GCP 원문 저장 예외와
관리자 조회 API는 2026-10-02 폐기했다. HMAC 지문과 필요한 메타데이터만 보존한다.
SIEM은 이 모델이나 finding에서 필요한 정보를 출력 계약으로 변환하며 별도의 공급자 원본을 요구하지 않는다.
이는 현재 SIEM이 모든 메타데이터를 전송한다는 뜻이 아니다.

## 공통 필드와 의미

| 영역 | 기준 필드·규칙 |
| --- | --- |
| 버전 | 입력 프로토콜 버전, 공통 레코드 버전, 공급자 매핑 버전을 구분한다. 기존 `schema_version=1/2`를 조용히 재해석하지 않는다 |
| 공급자 | 등록된 안정적인 공급자 ID. 제품 표시 이름이나 SDK 이름과 분리한다 |
| 원본 연결 | 입력 종류, 기존 connection ID, run 또는 실제 catalog snapshot ID, 설정 revision을 보존한다 |
| 설치·조직 경계 | 실제 instance·tenant·account·project·namespace를 구분하고 확인 여부를 기록한다. URL이 아닌 설치 ID를 HTTPS 주소로 꾸미지 않는다 |
| 객체 | 객체 종류와 공급자 native ID. 이름·이메일만으로 객체를 합치지 않는다 |
| 목적 | 기존 `issuer_inventory`, `vault_metadata`, `usage`와 콘텐츠용 `resource_inventory`를 구분한다 |
| 상태 | `provider_state`, `normalized_state`, `state_basis`. 근거 없는 상태는 `UNKNOWN` |
| 권한 | 종류·이름·대상·`ALLOW/DENY/UNKNOWN`·조건. 서로 다른 공급자의 권한 이름을 동등한 권한으로 추정하지 않는다 |
| 시각 | 관측 시각과 공급자 사건·효력 시각을 분리하고 UTC로 정규화한다. 수집 종료 시각을 실제 발생 시각으로 대신하지 않는다 |
| 출처 | API 작업, 원본 리소스 식별자, 수집 실행, 원본 계약·매핑 버전 |
| 상세 속성 | 타입이 있는 `facts`, 필드의 `PRESENT/NULL/MISSING/INVALID`, 제외된 필드의 `omissions` |
| 관계·사건 | subject·target·관계/사건 종류·매칭 근거·확신 수준. 후보를 확정 일치로 승격하지 않는다 |
| 품질 | 완료·부분·실패·미지원, 요청 범위·관측 건수·누락 사유·완전성 근거 |

`normalized_state`의 ACTIVE는 근거에 따라 정규화한 상태이며 실제 자격증명 검증 성공을 뜻하지 않는다.
판단 근거는 `state_basis`에 보존한다. 설치·조직 경계를 구조화해도 기존 `EntityIdentity.key` 입력과
entity ID를 변경하지 않는다. 식별자 변경이 필요한 경우 별도 버전 전환으로 다룬다.
runner OFFLINE, secret version CURRENT, credential ACTIVE는 별개 속성이다.
빈 결과·미수집·실패는 삭제 또는 미사용의 근거가 아니다.

공급자 고유 속성은 승인된 경로·타입·길이·깊이를 가진 fact로 보존한다.
공급자가 소유한 매핑 계약을 등록하고 플랫폼 입력 검증에서도 같은 계약을 사용한다.
임의 raw JSON이나 제한 없는 `extensions`로 비밀·크기·필드 검사를 우회하지 않는다.
공통 의미가 없는 공급자 필드는 같은 이름이라는 이유만으로 공통 필드에 끼워 맞추지 않는다.

## 현재 입력과 목표 연결

| 현재 입력 | 현재 저장·소비자 | 공통 계약으로 연결할 때 유지할 의미 |
| --- | --- | --- |
| GitHub·GitLab·GCP·Atlassian·Bitbucket·Azure Key Vault schema 2 | `coverage_entities`, `coverage_records`, 원본 `coverage_batches` | 기존 식별자·native export·상태·관계·부분 수집 근거 |
| AWS·Vault/OpenBao·GCP Secret Manager schema 1 | `coverage_connections/runs/batches`, 기존 coverage API·상관분석 | `Observation`의 증거 종류와 원본 fingerprint 계약. issuer·usage·vault 목적을 유지 |
| S3·GCS·GitHub·GitLab·Notion·Confluence·Bitbucket 콘텐츠 목록 | `ScopeCatalog`, `catalog_resources`, scope·승인·선택 API | `resource_inventory`의 resource observation. 기존 catalog ID·snapshot·readiness·권한·승인 계약 유지 |

이 통합은 현재 수집하는 자료의 의미를 통일하는 작업이다. 새 공급자 API나 기존 공급자의
미지원 서비스까지 자동으로 수집하는 기능은 아니다. 실제 수집 범위·edition·권한 제약은
공급자 descriptor와 매핑 계약에 계속 명시한다.

## 공급자별 지원 차이와 지원 범위 변경

공통 스키마는 모든 공급자가 같은 값을 반드시 반환한다는 뜻이 아니다. 같은 의미는 같은
필드로 표현하고, 값이 없는 이유와 지원 여부를 별도로 보존한다. 다음은 목표 설계이며
현재 descriptor·DB·UI에 구현된 계약으로 간주하지 않는다.

현재 기반과 부족한 부분:

- 공급자 `descriptor.py`에는 capability·edition·option·제약이 있다. 설치된 수집기의 기능
  설명이며 특정 연결의 실제 권한이나 필드별 지원 현황을 증명하지 않는다.
- `MetadataFact`에는 `PRESENT/NULL/MISSING/INVALID`, `OperationReport`에는 작업별
  `COMPLETE/PARTIAL/FAILED/UNSUPPORTED/NOT_REQUESTED/UNKNOWN`과 사유가 있다.
  필드가 통째로 생략되는 매핑도 있으므로 이 모델의 존재가 모든 공급자의 누락 구분을 보장하지 않는다.
- `FieldCatalogEntry`는 관측한 경로와 타입 목록이다. 공통 필드 정의나 지원 시작 버전 목록이 아니다.
- 공통 상세 UI는 저장된 facts를 표시하지만 목록 열은 고정이며, 필드별 지원 조건으로 화면을
  구성하지 않는다. 기존 자격증명 UI의 `MetadataFieldStatus`·한국어/영어 설명은 재사용할 기반이다.
- 현재 이름 검사는 전역 `FACT_NAMES`에 의존한다. 공급자 추가 시 공통 허용 목록도 손봐야 하므로
  공급자 소유의 제한된 필드 선언을 명시적 등록에서 조립하고 동일 선언으로 저장 입력을 검증하도록 전환한다.
  이 전환 전까지 기존 검사와 공급자별 allowlist를 유지한다.

지원·수집·값은 독립적인 질문이다. 한 개의 nullable 값이나 거대한 상태 enum으로 합치지 않는다.

| 구분 | 판단할 내용 | 보존할 근거 |
| --- | --- | --- |
| 지원 계약 | CreMore가 구현했는지, 해당 API·edition·버전·요금제·객체 종류에서 제공하는지 | 공급자 소유 선언 버전·지원 조건·확인 근거. 확인하지 못한 조건은 미확인 |
| 실행 결과 | 요청했는지, 권한이 있었는지, 성공/부분/실패인지 | connection·scope·run·operation·reason·관측 시각·수집 범위 |
| 필드 관측 | 값/명시적 null/응답 누락/형식 오류인지 | 기존 fact 상태·타입 검사를 통과한 값·출처. 잘못된 원문은 저장하지 않음 |

예를 들어 B의 수집기가 미구현인 것과 B의 API가 필드를 제공하지 않는 것은 다르다.
403은 기능 미지원의 증거가 아니다. 권한 부족과 API 비활성을 구분할 근거가 없으면 그 불확실성도
유지한다. 응답에 필드가 없다는 이유만으로 미지원·미사용을
확정하지 않는다. `false`, `0`, 빈 목록도 실제 값이며 null과 합치지 않는다. 지원 조건은 공급자
adapter에서 판단하고 범용 조건 실행 언어나 자동 권한 탐색 시스템을 만들지 않는다.

필드 정의는 두 범위로 나눈다.

1. **공통 의미:** 플랫폼이 안정적인 필드 ID·의미·타입·단위/시각 정밀도·적용 객체 종류를 정의한다.
   예를 들어 특정 자격증명의 마지막 사용과 소유자 계정의 마지막 로그인은 별개다.
   공급자별 API 이름이 달라도 의미와 근거가 일치할 때만 같은 공통 필드로 매핑한다.
2. **공급자 고유 의미:** 공급자가 소유한 이름 공간에 필드·타입·길이·중첩 한도·민감정보 정책을
   선언한다. 실제 연결의 공급자에 등록된 필드만 허용하며 다른 공급자 선언이나 임의 raw JSON으로
   검증을 우회할 수 없다. 새 공통 의미가 발견되면 플랫폼 계약 검토를 거쳐 공통 필드로 승격한다.

필드 정의와 표시 설정은 선언된 데이터다. 표시 이름/번역 키·날짜/숫자/문자열 등 기존 renderer·
표시 그룹을 사용하며 외부 HTML·JavaScript나 실행 가능한 UI 정의를 받지 않는다. 모든 필드를
기본 표에 넣지 않고 공통 핵심 열과 상세 속성 영역을 유지한다. 기존 상태 설명을 재사용하되,
자격증명 전용 설명을 페이지·버킷에 그대로 붙이지 않도록 적용 객체를 구분한다.
`MetadataFieldStatus`는 UI 호환 표시용으로 재사용한다. 지원·실행·값 문제가 섞여 있는 기존 enum을
세 축을 대체하는 단일 저장 상태로 쓰지 않는다.

### B가 나중에 같은 필드를 지원하는 경우

예: A만 제공하던 특정 자격증명의 `last_used_at`을 B도 제공하기 시작한다.

1. B 담당자가 API 조건·매핑·합성 회귀를 갱신하고 공급자 매핑/지원 선언 버전을 올린다.
2. 기존 공통 의미·타입과 맞으면 같은 필드로 저장한다. 추가된 typed fact 때문에 공급자별
   테이블이나 새 DB 컬럼을 만들 필요는 없다. 선언 변경만으로 실제 수집 구현이 생기지는 않는다.
3. 기존 승인 범위·설정·예산 안에서 수집한다. 새 권한·API·추가 비용·별도 수집 목적이 필요하면
   기존 연결의 승인을 자동 확대하지 않고 해당 설정·승인 계약을 따른다.
4. 성공적으로 관측한 이후 기록부터 값과 출처를 표시한다. 이전의 미지원/미수집 기록을
   현재 지원 선언으로 다시 해석하거나 과거 값을 추정하지 않는다.
5. 공통 상세에는 기존 renderer로 표시한다. 해당 값을 목록 열·필터·정렬·집계에 쓰는 기능은
   명시적으로 추가하며, 허용된 조회 필드와 필요한 인덱스를 검토한다. 임의 JSON 경로 검색을 공개하지 않는다.

현재 값이 수집 실패 때문에 빠지면 과거 성공 값과 관측 시각을 별도로 남기고 오래된 값임을
표시한다. 새 매핑으로 결과가 달라진 경우 공급자의 실제 상태 변경과 매핑 변경을 구분한다.
비교 가능한 근거가 부족하면 변경/삭제를 확정하지 않는다.

공통 레코드·공급자 매핑·지원 선언의 버전은 구분하고 실행 당시 계약을 재현할 수 있게 보존한다.
새 선택 필드는 additive하게 추가하며 같은 필드 ID의 의미나 타입을 바꾸지 않는다. 구버전
기록에 필드별 지원 근거가 없으면 미확인으로 남긴다. 이미 보존한 안전한 원본으로 재매핑할 수 있는
항목만 명시적 backfill 대상이며, 당시 수집하지 않은 값은 재매핑으로 복원할 수 없다.
새 제출 검증과 저장된 구버전 이력의 조회·재구축 호환성은 별도로 검증한다. 현재 adapter 중에는
contract/source commit의 정확한 일치를 요구하는 경로가 있으므로 상수 변경만으로 전환을 끝내지 않는다.

## DB와 조회 경계

공통 저장 모델은 객체, 관측 기록, 출처·실행 식별자를 기준으로 한다.
공급자 ID·객체 종류·식별자·관측 시각 등 조회용 값은 인덱스 가능한 컬럼으로,
검증된 공통 레코드와 공급자 상세 속성은 JSON으로 저장하는 기존 방식을 재사용한다.
신규 공급자라는 이유만으로 공급자 전용 메타데이터 테이블을 만들지 않는다.

기존 `coverage_records`의 연결·실행 FK는 coverage 전용이므로 콘텐츠 catalog 행을 바로 넣을 수 없다.
실제 구현에서는 원본 종류와 실제 실행/snapshot의 참조를 표현하도록 저장 경계를 먼저 확장해야 한다.
콘텐츠 목록을 저장하기 위해 실행하지 않은 수집 run·인증·scope를 만들어서는 안 된다.
공통 계약 확정과 물리 테이블 migration 완료를 구분한다. 구체적인 DDL은 이 호환 확장 구현에서 검증한다.

조회 응답도 공통 모델을 사용하되 다음 권한을 유지한다.

- 콘텐츠 리소스는 기존 Analyst 이상 접근을 유지한다.
- 관리 메타데이터는 기존 Viewer 접근 범위를 유지한다.
- 목록뿐 아니라 count·facet·검색·상세·export에 같은 권한을 적용한다.
- catalog용 스캔 승인 ID와 metadata entity ID는 서로 대체하지 않는다.
- 페이지 이동은 권한 필터를 적용한 전체 결과를 기준으로 한다. 각 저장소의 첫 페이지만 합치지 않는다.

## 호환 전환

1. 공통 모델·공급자 매핑·계약 검사를 먼저 구현하고 기존 ID·native export를 검증한다.
2. 출처와 매핑 버전을 저장할 additive 구조를 마련한다. 기존 API·원본 batch·checksum은 유지한다.
3. 신규 수집은 원본 저장과 공통 정규화 저장을 같은 commit 경계에 연결한다.
   저장이 실패하면 cursor를 전진시키지 않는다. 완료 요약은 finish 시점의 원자적 갱신을 따른다.
4. 기존 이력은 명시적이고 재개 가능한 backfill로 변환한다. startup 자동 변환은 하지 않는다.
5. 공통 조회·상세·export와 기존 API 호환을 검증한 뒤 소비자를 옮긴다.
6. 롤백 시 해당 매핑 버전의 파생 조회를 비활성화하거나 재구축한다. 원본 데이터는 보존한다.
   기존 API·테이블 제거는 별도의 범위와 전환 검증이 있을 때만 한다.

현재 schema 1 계약에는 spec snapshot·fingerprint key ID·정확한 read 시각이 없다.
contract 전체 비교에 의존하는 기존 상관분석이 있으므로 contract에 새 필드를 임의로 넣지 않는다.
현재 설정 revision과 다른 과거 run을 현재 endpoint·scope로 다시 해석하지 않는다.
복원할 근거가 없는 항목은 변환 제외/부분 변환 사유와 원본을 남긴다.
불충분한 VALUE 기록을 schema 2의 완전한 `value_match` 증거로 승격하지 않는다.
실시간 GCP `value_match()`가 넣는 현재 context의 키·digest·`now()`를 과거 schema 1 변환에
재사용하지 않는다. 실행 종료 시각을 표시할 경우에도 실제 API read 시각과 구분한다.

## 현재 코드와의 호환성 검토

검토 기준: `1551f19`, 2026-09-24. **기존 테이블 확장과 출처 테이블 추가만으로는 호환되지 않는다.**
아래는 현재 제품의 새 결함 목록이 아니라, 통합 구현 전에 해결해야 하는 설계 적용 조건이다.
제품 코드·DB·운영 데이터는 이 검토에서 변경하지 않았다.

| 경계 | 현재 구현에서 확인한 제약 | 통합 시 필요한 조건 |
| --- | --- | --- |
| 저장·조회 | [records](../cremore/coverage/metadata_store.py#L53)의 run/connection은 coverage FK와 NOT NULL이다. 완료 처리와 collections 조회도 coverage spec·sequence·connection을 직접 사용한다 | FK를 nullable로 바꾸는 것만으로 끝내지 않는다. 실제 출처를 해석하는 저장·조회 경로와 기존 coverage 전용 경로를 구분한다 |
| 객체·최신값 | [identity key](../cremore/coverage/metadata_models.py#L385)에 purpose/입력 종류가 없고, entity당 summary·current/last_success가 하나다 | 기존 ID를 유지한다. 같은 객체의 관측이라도 출처·목적·권한에 맞는 최신값을 선택하며, 콘텐츠 관측으로 기존 관리용 summary를 덮어쓰지 않는다 |
| 권한 | [v2 조회](../cremore/api/metadata_coverage.py#L336)는 Viewer, 콘텐츠 목록은 Analyst다. [검색](../cremore/api/search_service.py#L8)도 두 종류를 구별한다 | 새 공통 조회는 허용된 관측을 먼저 제한한 뒤 최신값·관계·연결·count/facet/검색/상세/export를 계산한다. entity의 현재 purpose만으로 필터링하지 않는다 |
| 모델·UI | Python과 [웹 계약](../web/lib/provider-metadata.ts#L1)에 AWS·Notion·resource_inventory 등이 없으며 v2 응답을 요구한다 | 저장 가능한 공급자와 실행 가능한 collector를 구분한다. 공통 응답은 명시적으로 버전을 정하고 기존 v1/v2 응답·입력 범위를 유지한다 |
| native 출력·비교 | [export/compare](../cremore/api/metadata_coverage.py#L371)는 실제 run·당시 spec·adapter와 contract 동등성을 요구한다. native decoder는 기존 fact 이름·경로를 읽는다 | 기존 fact 경로·출력 형식을 보존한다. 공통 의미는 additive하게 투영하고, 새 공통 export와 기존 native export를 구별한다. 다른 매핑 버전은 동등성 근거 없이 비교하지 않는다 |
| 재전송·버전 | record ID와 unique index는 run/batch/item 기준이며, 동일 원본 재전송은 새 투영 전에 반환한다 | 새 파생 기록은 실제 snapshot·원본 항목·매핑 버전으로 안정적인 키를 갖는다. 같은 버전·키의 내용 충돌을 거부하고 별도 재개 가능한 투영 복구를 제공한다 |
| DB 업그레이드 | [create_all](../cremore/db/sql.py#L133)은 기존 nullable/FK/unique 제약을 선언과 자동 동기화하지 않는다 | 새 설치와 기존 설치를 각각 검사하는 명시적 migration이 필요하다. PostgreSQL 제약 변경과 SQLite 재구축을 구분하고 memory에도 같은 중복·원자성 규칙을 적용한다 |
| 원자적 저장 | [worker](../cremore/coverage/metadata_job.py#L113)는 원본·투영·checkpoint를 fence 안에서 저장하고, [catalog](../cremore/db/catalog_store.py#L119)는 header·행·index를 같은 commit에 공개한다 | 공통 저장도 같은 bound transaction에 포함한다. memory에서도 coverage뿐 아니라 catalog와 새 상태가 함께 rollback되어야 한다 |
| 과거 자료 | [catalog refresh](../cremore/db/catalog_store.py#L128)는 현재 행을 갱신·제거한다. [재구축](../cremore/coverage/metadata_store.py#L473)은 schema 2만 지원한다 | 과거 전체 catalog snapshot이 있다고 가정하지 않는다. 실제 남아 있는 자료만 backfill하고, partial refresh에서 유지된 이전 행을 이번에 새로 관측한 것으로 표시하지 않는다 |
| GCP·SIEM | 기준 소스 당시 GCP objects/events/values와 전용 API는 별도 소비자였다. 원문 values 저장·조회는 2026-10-02 폐기했다 | GCP 객체·이벤트 projection/API와 비공개 HMAC 변경 근거를 유지한다. 과거 원문은 별도 이관으로 정리하며 통합 과정에서 복사하지 않는다. metadata 통합만으로 SIEM 이벤트를 확장하지 않는다 |

물리 테이블 재사용은 위 조건을 충족할 때의 방향이다. 기존 reader·최신값 선택 규칙을 그대로 둔
채 catalog 행을 같은 테이블에 넣는 구현은 채택하지 않는다. 기존 schema 2 identity는 원래
origin/tenant/connection 입력으로 계산하고, catalog 승인 ID도 그대로 보존한다. Vault/OpenBao의
HTTP·endpoint base path·namespace·mount·version, AWS의 partition·account·region도 버리지 않는다.

배포·롤백 순서는 다음 조건으로 보강한다.

1. 기존 reader에 입력 종류·버전 경계를 먼저 적용하고, 기존 응답과 native 출력의 동등성을 확인한다.
2. 새 출처·투영 스키마와 명시적 migration을 검증한다. 기존 contract/batch/checksum/ID는 바꾸지 않는다.
3. 모든 API·worker가 새 구조를 이해하는 버전으로 전환되기 전에는 새 종류의 투영 쓰기를 활성화하지 않는다.
4. 새 공통 조회는 출처별 권한과 버전별 해석을 적용한다. 저장된 구버전 읽기와 새로운 외부 제출 검증은 구분한다.
5. 롤백 시 새 쓰기를 중지하고, 구버전 reader가 새 투영을 읽지 않도록 검증된 격리·복원 절차를 수행한다.
   원본을 보존했다는 이유만으로 구버전 binary를 바로 실행해도 안전하다고 판단하지 않는다.

### 이번 검토의 실행 증거와 한계

- `AWS_EC2_METADATA_DISABLED=true`로 기존 Python 회귀 **49 passed, 0 skipped**.
  `python -m pytest ... -q`를 두 번 실행했다. 첫 39개는 metadata store·catalog store 전체와
  coverage의 atomic submission/revision/correlation/Vault 경계, API의 schema 격리·완료 조회·native export·비교 검사다.
  다음 10개는 metadata worker의 대기/재개·연결 비활성화·lease 재시도 소진 후 복구와 역할별 검색 검사다.
- `web/`에서 `node --test tests/provider-inventory.test.cjs tests/global-search.test.cjs tests/scan-scope.test.cjs`:
  **61 passed, 0 skipped**. 기존 payload guard·권한 표시·상세 facts·scope/cursor/승인 ID 계약을 확인했다.
- 모델 입력과 테이블 선언에 대한 읽기 전용 assertion 6개로 AWS/Notion/Vault 입력, resource_inventory 목적이
  현재 모델에서 거절됨과 records의 두 coverage 참조가 필수임을 확인했다.
- 이 결과는 **현재 구현의 회귀 기준**이다. 미구현 통합의 성공 증거가 아니다. 신규 migration,
  PostgreSQL 전환, 구·신 버전 혼재, 통합 backfill/rollback, 새 권한 투영은 아직 실행 검증하지 않았다.
  외부 공급자·운영 DB·실제 SIEM에는 접근하지 않았다.

## 공급자별 병렬 개발과 완료 조건

공급자 담당자는 입력 해석·native ID·상태·권한·fact 매핑과 테스트를 소유한다.
플랫폼 담당자는 공통 모델·등록·저장·조회·권한·버전·migration을 소유한다.
기존 공통 의미로 표현 가능한 신규 공급자는 매핑과 등록으로 연결한다.
새로운 공통 의미가 필요한 경우에는 필드·타입·호환 영향을 명시해 공통 계약을 확장한다.
콘텐츠 수집·실행 인증 등록과 정규화 매핑 등록은 같은 기능으로 취급하지 않는다.

완료 검증은 공급자별 합성 입력을 공통 모델로 변환한 뒤 DB 저장·조회까지 수행한다.
메모리·SQLite·격리 PostgreSQL에서 원본 불변, ID 안정성, NULL/UNKNOWN, 중복 재전송,
부분 실패·재개·revision 변경, 권한별 count/facet/detail, backfill 재시도·롤백을 확인한다.
기존 API·scope 승인·native export·SIEM 계약 검사도 유지한다.
지원 확장 검증에는 A만 지원→B 수집기 미구현→B 지원하나 권한 거부→B 성공,
명시적 null/미반환/형식 오류, 구버전 이력 보존, 공통 상세 표시와 허용된 필드 조회를 포함한다.

현재 구현 근거:
[공통 모델](../cremore/coverage/metadata_models.py),
[coverage 저장](../cremore/coverage/store.py),
[메타데이터 투영](../cremore/coverage/metadata_store.py),
[콘텐츠 목록 저장](../cremore/db/catalog_store.py),
[권한별 검색](../cremore/api/search_service.py).
