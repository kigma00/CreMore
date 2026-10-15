# 공급자 모듈화 후속 보고서

기준: `7df7d45`, 구현: `a23ff08c77e8e2b7be052a31a79fc890c226ba9b`, 2026-09-24.
팀별 콘텐츠 수집 공급자와 SIEM 연동의 개발 범위를 분리하는 후속 변경이다.
공급자 기능·실제 접근 범위·인증 방식·DB 스키마는 추가하지 않았다.
아래 경로와 검사 수는 해당 커밋 당시의 기록이다. 이후 공급자별 디렉터리 이동은
[디렉터리 보고서](PROVIDER_DIRECTORY_REVIEW.md), 현재 개발 지침과 최신 실행 결과는
[팀 지침](AI_TEAM_CODING_GUIDE.md)과 [검증 보고서](REFACTOR_REPORT.md)를 따른다.

## 구현과 소유권

| 담당 | 실제 소유 경로와 계약 |
| --- | --- |
| 콘텐츠 공급자 | `cremore/sources/<provider>.py`: 설명·설정 검증·작업 payload/kind·범위 변환·수집기 조립·목록 조회 진입점 |
| 콘텐츠 공통 등록 | `cremore/sources/registry.py`: 명시적으로 등록한 모듈에서 API 설명, 작업/리소스 routing, token 대상, 범위 종류를 조립 |
| 공급자 등록 UI | `web/features/connections/providers/`: 설명·범위 입력·기존 인증 지원 표시·비밀 없는 폼 상태·요청 payload·초기화 규칙 |
| UI 공통 등록 | `providers/registry.ts`: 표시 순서와 공급자 모듈 연결; 실행 가능 여부는 서버 계약으로 판단 |
| 메타데이터 공급자 | 기존 `coverage/providers/<provider>/`: adapter·descriptor·normalization; 비교는 `CollectorRuntime.compare_records(before, after, ...)`로 호출 |
| SIEM 출력 담당 | 기존 `cremore.siem` 공개 계약과 별도 설치 패키지; 콘텐츠 수집 모듈과 별개 |
| 플랫폼 담당 | 승인·인증·영속 저장·리스·공통 scope 규칙·공개 응답 호환성·지원하는 데이터 계약 |

`source_config.py`, `api/source_contract.py`, `domain/models.py::CONTENT_SCAN_KINDS`와
`web/lib/provider-registry.ts`의 기존 소비자 경로는 유지한다. Worker는 공통 비밀 해석과
요청/크기/시간 예산을 적용하고 등록된 모듈로 조립을 위임한다. 범위 검사는 기존 object/path/page
규칙을 유지하며 승인 로직을 임의 callback으로 옮기지 않는다.

기존 실제 수집 구현은 `collectors/`에 남아 있고, 현재 목록 조회는 `scanning/catalog.py`의
검증된 helper를 재사용한다. 공급자별 진입점 분리와 기존 구현 전체의 파일 이동은 구분한다.
동적 외부 수집 플러그인이나 런타임 패키지 설치 기능은 추가하지 않았다.

메타데이터 비교의 provider별 인자 순서는 adapter의 작은 bridge가 담당한다.
기존 native `compare_records` 함수는 유지한다. 이 정리 중 발견한 Azure의 정상 run 비교
`TypeError`와 before/after 인자 불일치도 합성 API 회귀 검사로 수정했다.

## 팀별 병렬 개발과 통합 기준

팀원은 공급자별 backend 모듈·수집 구현·UI 모듈·테스트를 별도 branch/worktree에서 개발한다.
공통 registry 등록은 통합 담당자가 확인한다. 기존 계약 안의 설정·폼·조립 변경 때문에
API/worker의 공급자별 조건문을 함께 수정할 필요를 줄였다.

새 공급자 전체가 폴더 추가만으로 동작한다고 보장하지는 않는다. 다음은 공통 검토 대상이다.

* 새 인증·자격증명 점검·승인 방식, 기존 세 범주와 다른 scope 의미.
* 새 job kind의 DB partial unique index 반영과 migration. Python 목록을 늘리는 것만으로
  이미 설치된 index가 재생성되지는 않는다. 이번 변경의 job kind 목록은 기존과 동일하다.
* `web/lib/dashboard-model.ts::currentSource`와 공개 응답 인식. 모델을 React/feature 모듈에
  의존시키지 않기 위해 이 호환성 목록은 유지한다.
* 메타데이터 Provider/Options/허용 필드와 신규 correlation 계약.
* 목록에서 사라진 리소스를 제거된 것으로 판정하는 기능. 새 수집기의 완전한 목록 보장이 먼저 필요하다.

구체적인 개발 절차와 검증 명령은 [팀 가이드](AI_TEAM_CODING_GUIDE.md)를 따른다.
SIEM의 별도 설치형 출력 계약은 [SIEM guide](SIEM_INTEGRATION.md)를 따른다.

## 검증

* 변경 전후 같은 backend 회귀 검사: 각각 **124 passed**.
* 추가 catalog·scope 실행·worker·API·라이브러리·SIEM 통합 검사: **218 passed**.
* 메타데이터 비교와 모듈 계약 최종 검사: **22 passed**. 관련 확장 검사는 **289 passed,
  POSIX 조건 3 skipped, 46 subtests passed**였다. 서로 겹치는 검사 수는 합산하지 않는다.
* 공급자 목록·capability 전체·표시 순서·resource/job/token 매핑·revocation 설명은 변경 전과 같다.
  cold import 검사는 registry가 domain·collector·API·worker·SQLAlchemy를 불러오지 않음을 확인한다.
* 웹 단위 검사 **481 passed**, TypeScript 검사·production build 성공.
  onboarding과 확장한 investigation 브라우저 검사는 실제 폼의 요청 body, 처리 순서,
  공급자 전환 시 상태 유지 및 자격증명 초기화를 합성 환경에서 확인했다.
* 18개 영어/한국어 폼과 설명·scope 규칙의 전후 snapshot은 **316,491 UTF-8 bytes**로 동일하다.
  SHA-256: `05b33251b8fde18d41d4b0ca11312d0ddd3ce9451e8b8c97f3743222b25e67d1`.
* 변경 Python 경로 Ruff와 `git diff --check` 통과. 실제 공급자 호출·SIEM 전송·운영 배포는 없다.

최종 [원격 CI #35902022079](https://github.com/y4rvin/CreMore/actions/runs/35902022079)는
구현 커밋 `a23ff08c77e8e2b7be052a31a79fc890c226ba9b`에서 **7/7 작업 성공**이다.
이후 변경은 문서뿐이다.

* Python 3.12·3.14: 각 **5,168 passed, 342 subtests passed**, 임시 PostgreSQL 검사 포함.
* 독립 GitLab 수집기 **162개**, GCP connector **46개** 검사가 두 Python 버전에서 각각 통과했다.
* 웹 **481개**, Helm **70개**, 브라우저 proof **21/21** 통과. production build와
  API·web·oauth2-proxy 컨테이너 빌드 및 지정된 이미지 보안 검사도 성공했다.
* 로컬 CI 증거: `.git/compliance-audit/source-modules-ci-result.json`,
  `.git/compliance-audit/source-modules-ci-final.log`.

갱신한 문서 5개의 로컬 링크·이미지·앵커 **82개**를 확인했다. 아키텍처 문서의 기존
자기승인 예외와 공급자 접근 설명도 현재 코드에 맞게 바로잡았다.

최종 wheel은 Python **420개**를 모두 포함하며, 패키지 파일 **450개**가 현재 소스와
바이트 단위로 일치한다. README와 package metadata도 일치한다. wheel에서 CLI **4개**,
메타데이터 descriptor **5개**, 콘텐츠 공급자 모듈 **7개**의 계약과 공개 순서를 확인했다.
registry 단독 import는 domain·collector·API·worker·DB·vendor SDK를 로드하지 않는다.
설치형 SIEM 플러그인의 명시적 활성화 계약도 합성 이벤트 1개로 검증했으며 네트워크 전송은 없다.

* 산출물: `cremore-0.1.0-py3-none-any.whl`, **1,429,346 bytes**.
* SHA-256: `743c5b453aa5296f2175f6e617c6c9950098b18a23d5cdcc29cab400e7e5c635`.
* 로컬 증거: `.git/compliance-audit/source-modules-wheel/`의 `verification.json`,
  `source-module-proof.json`, `external-plugin-proof.json`, `build.log`, `verification.log`.
