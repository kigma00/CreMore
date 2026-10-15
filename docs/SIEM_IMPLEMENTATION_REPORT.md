# SIEM 출력 연동과 공급자 소유권 보완

변경 기준: `d96bb8d`, 구현 커밋: `9f79b206c41da4f0b269019e125086a56747249b`,
작업일: 2026-09-24. 이 보고서의 범위는 문서 마감 `7df7d45`까지다.
이후 콘텐츠 공급자 모듈화는 [후속 보고서](PROVIDER_MODULE_REPORT.md)를 참고한다.

## 구현 범위

* `cremore.siem`은 수집기와 분리된 공개 출력 계약(`Sink`, `SinkProvider`, `DeliveryError`)이다.
  설치한 출력 패키지를 `cremore.siem_sinks` entry point와 목적지 설정으로 추가한다.
  선택하지 않은 플러그인은 import하지 않으며 중복 ID·계약 버전 불일치를 거절한다.
* JSONL, HTTPS JSON, Splunk HEC, Falcon LogScale 어댑터를 제공한다. LogScale과
  Falcon NG-SIEM 전용 커넥터를 동일하게 취급하지 않는다. 다른 SIEM은 JSON 수집 파이프라인이나
  해당 제품의 별도 출력 패키지를 사용한다.
* 최초 finding 저장과 같은 트랜잭션으로 불변 `finding.created` 이벤트를 기록한다.
  `siem_events`와 목적지별 `siem_deliveries`는 additive 테이블이다. API 직접 저장·worker 저장·
  rollup 복구 생성 경로를 포함하며 롤백된 결과는 전송되지 않는다.
* 별도 `cremore-siem` 프로세스가 임대·재시도·완료 상태를 관리한다. 네트워크 요청은
  탐지 저장 트랜잭션 밖에서 실행한다. 수신 확인 전에 중단되면 같은 `event_id`로 재시도한다.
* 기존 metadata 공급자의 설명을 각 공급자 `descriptor.py`로 옮겼다. 기존 명시적 등록으로
  catalog를 조립하며 ID·순서·가용성·표시 결과·수집 계약은 유지했다.

사용·배포·버전·팀원별 출력 패키지 작성은 [SIEM integration](SIEM_INTEGRATION.md),
수집/플랫폼/출력 담당자의 소유권은 [팀 가이드](AI_TEAM_CODING_GUIDE.md)에 있다.

## 검증

* 전후 metadata catalog는 **10,265 bytes**, SHA-256
  `115810c476ca8ed986de1ad9078a029f0bb6195692710b81e0d7219a55bdc0b0`로 동일하다.
* 관련 Atlassian/API/runtime/catalog 검사: **289 passed, 57 skipped, 240 subtests passed**.
  skip은 로컬 Windows의 기존 POSIX 조건이며 원격 Linux 결과와 구분한다.
* DB·스캔 저장·worker 및 신규 outbox 검사: **265 passed, 11 skipped**.
  skip은 PostgreSQL URL 미설정이며 신규 동시성 검사 2개와 기존 검사 9개다.
* SIEM 전체·catalog·library 경계·CLI 통합 검사: **188 passed, 2 skipped**.
  이 결과는 위 범위와 겹치므로 합산하지 않는다. PostgreSQL 전용 2개는 아래 원격 CI에서 통과했다.
* 추가 API·dashboard·request 경계·orchestrator 회귀 검사: **188 passed**.
* 첫 원격 CI의 Python 3.12에서 동시 claim 4회가 즉시 8건을 모두 확보한다는 테스트 기대가
  실패했다(6건, 중복 없음). PostgreSQL statement snapshot과 조건부 upsert 경합에서는
  claim 수가 한도보다 적을 수 있다. `08b50fe`에서 첫 claim들의 유일성과 다음 poll을 포함한
  8건 전체 확보를 함께 검사하도록 수정했다. 제품 전달 로직은 변경하지 않았다.
* 잘못된 출력 객체의 자원 누수와 httpx INFO의 SIEM URL 노출을 독립 검토에서 발견했다.
  객체 정리·로그 수준을 수정하고 두 실패 조건을 모의 환경에서 회귀 검사했다.
* 변경 Python 범위 Ruff와 `git diff --check` 통과. Compose SIEM override를 실제 렌더링해
  별도 환경·읽기 전용 설정 mount·opt-in profile을 확인했다. 서비스를 시작하지 않았다.
* 설정 예제 6개를 실제 config parser로 검증하고 가이드의 JSON·TOML·Python 예제를 파싱했다.
  외부 패키지 예제의 테스트 2개를 임시 디렉터리에서 실행했으며 외부 전송은 없다.
* wheel의 **437개 패키지 파일**이 현재 소스와 바이트 단위로 일치하며 Python 파일 407개와
  CLI 4개를 포함한다. README metadata·선택 의존성·공개 SIEM 계약·공급자 descriptor도 확인했다.
  SHA-256: `6b0410a1d3503b6c46a4b45374067a302bd96639ddbd0e8807707e447e39a839`.
* 별도 프로세스에서 wheel과 임시 외부 패키지 metadata로 entry point 발견을 확인했다.
  발견 시 import 없음, 허용 전 활성화 거절, 명시적 허용 후 합성 이벤트 1개 수신을 검증했다.
  네트워크 전송은 없다. 로컬 증거는 `.git/compliance-audit/siem-wheel-final/verification.json`과
  `external-plugin-proof.json`에 남겼다.

최종 검사 커밋 `08b50fe032ea27778974b0eab955d58c67493df0`의
[원격 CI 35897387915](https://github.com/y4rvin/CreMore/actions/runs/35897387915)는
**7개 job 모두 통과**했다. 이 커밋 뒤 변경은 README·가이드·보고서·설정 예제이며
제품 코드·테스트·실행용 Compose는 동일하다.

| 원격 검사 | 결과 |
| --- | --- |
| Python 3.12 / 3.14 전체 | 각각 **5,158 passed, 342 subtests passed**, skip 없음 |
| 격리 PostgreSQL 17 | 신규 SIEM 동시 생성·claim·rollback 검사와 기존 DB 검사 실행 |
| 독립 GitLab / GCP 패키지 | 두 Python 버전에서 각각 **162 / 46 tests**, 성공 |
| 웹 / Helm | **474 / 70 tests** 성공, production build 성공 |
| 브라우저 | **21/21** 합성 proof 성공 |
| 컨테이너 3종 | API·web·oauth2-proxy 빌드와 설정된 검사 성공 |

Python의 경고 1개는 기존 Starlette TestClient의 httpx deprecation이다. 운영 SIEM 전송이나
배포 검증을 뜻하지 않는다. 원격 결과와 전체 로그는 로컬
`.git/compliance-audit/siem-ci-recheck-result.json`, `siem-ci-recheck-final.log`에도 보존했다.

## 정확한 보장 범위와 남은 제약

이벤트는 업그레이드 후 최초 생성된 finding의 **초기 관측**이다. 최종 유효성/오탐 판정,
상태 변경 전체 이력, 재발견된 모든 위치, 기존 finding의 자동 backfill을 뜻하지 않는다.
비밀 원문·식별자·문맥·경로·임의 metadata는 외부로 보내지 않는다. 내부 finding/exposure UUID로
권한이 있는 대시보드/API에서 상세를 조회한다.

수신 측은 `event_id`로 중복을 제거해야 한다. JSONL flush는 로컬 수집기 전달 경계이고,
HEC 성공은 endpoint 수락이며 indexer ACK를 확인하지 않는다. 실제 기업 SIEM·운영 DB·
인증 토큰·배포 환경을 대상으로 전송하거나 검증하지 않았다.

출력 플러그인은 운영자가 검토·설치한 신뢰 코드이며 같은 프로세스의 sandbox가 아니다.
호환 패키지 빌드·배포 고정이 필요하다. 발신 이력의 자동 삭제 정책은 없으며 운영자는
보존 기간·DB 용량·전송 backlog를 관리해야 한다. 큰 이력에서 claim 조회 성능은 부하 검증 대상이다.

이번 수집 공급자 변경은 **기존 설명의 소유권 분리**다. 새 수집 kind·인증·승인 scope·API/UI
계약을 자동으로 연결하는 외부 수집 플러그인은 구현하지 않았다. 이 공통 경계 변경은 플랫폼
담당자의 검토와 계약 테스트가 필요하다. 외부 SIEM 추가와 신규 수집 능력 추가를 혼동하지 않는다.

업그레이드와 롤백은 [SIEM guide](SIEM_INTEGRATION.md)를 따른다. exporter 중지는 수집을
중지하지 않으며, 구버전 writer는 새 SIEM 이벤트를 생성하지 않는다. 롤백을 위해 보존된
finding이나 새 이벤트 테이블을 삭제하지 않는다.
