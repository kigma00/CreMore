# 공급자별 디렉터리 리팩터링 결과

2026-09-24 · `refactoring`. 이 문서는 실제 적용된 구조를 설명한다. 2026-10-01: 이전 대시보드와 공급자별 `web/` 폴더를
삭제했다. 화면은 콘솔(`web/console/`) 하나이고 연결 화면은 공급자 onboarding descriptor로 그린다.

## 구조와 호출

```text
aws/         backend/cremore_aws_provider/
gcp/         backend/cremore_gcp_provider/         standalone/
github/      backend/cremore_github_provider/
gitlab/      backend/cremore_gitlab_provider/
notion/      backend/cremore_notion_provider/
atlassian/   backend/cremore_atlassian_provider/
azure/       backend/cremore_azure_provider/
vault/       backend/cremore_vault_provider/

cremore/     공통 API·권한·DB·worker·scope·탐지·승인·SIEM 계약
web/         Next 콘솔(`/`)·공통 UI·타입·API client·웹 테스트
deploy/      제품 전체 배포
```

이후 추가: `okta/`·`keycloak/`(퇴사자 점검 IdP 사용자 수집, 2026-10-02부터 연동 제안에 쓰는 IdP 앱 목록 수집도), 2026-09-28 `slack/`(Enterprise Grid 앱 발급 목록,
backend만 있고 콘솔은 연결 카탈로그로 그린다), 2026-09-30 `website/`(확인된 회사 도메인의 외부 노출 검사, backend만 있고
도메인 검증 화면에서 시작한다).

각 공급자 backend가 구현과 전용 Python 테스트를 소유한다. Confluence·Bitbucket은
Atlassian 공유 구현을 사용하고 OpenBao는 Vault KV 계약을 쓴다. Azure는 metadata 전용이며
빈 콘텐츠/UI 모듈을 추가하지 않았다. 공급자별 README에서 소유 범위와 검사 명령을 안내한다.

공통 플랫폼이 라이브러리 함수를 같은 프로세스에서 직접 호출한다. 한 Python wheel과 기존
Next 앱에 함께 포함하며, 공급자별 서버·Docker·별도 의존성 설치를 추가하지 않았다.

| 기능 | 공급자 구현 | 공통 호출·계약 |
| --- | --- | --- |
| 콘텐츠 설정·수집·목록 | `source.py`, `content.py`/`collectors/`, `catalog.py` | `cremore/sources/registry.py`가 source를 등록; factory/catalog가 함수를 호출 |
| 연결 상태 검사 | source의 `check_credential`, 공급자 credential check | 공통 비밀 해석 후 등록 source로 전달; 결과는 `CredentialCheck` |
| Metadata | `metadata/adapter.py`, descriptor·transport·normalization·native 코드 | `cremore/coverage/providers/__init__.py`와 `CollectorRuntime` |
| AWS 조사·조치 | AWS `investigation/`, `remediation/`, 세션·KMS 모듈 | 공통 API·승인 상태·job/DB/lease 계약 |
| 값 기반 coverage | AWS/GCP/Vault `coverage.py` | 공통 `Collection`의 예산·관측·해시 및 저장 계약 |
| 연결 화면 | onboarding descriptor(`onboarding.py`); 2026-10-01부터 공급자 폴더에 UI 없음 | 콘솔(`web/console/views/integrations/`)이 catalog로 마법사를 그리고, 공급자 고유 안내·문구·로고만 더한다 |
| SIEM | 기존 출력 패키지·sink | 공개 `cremore.siem`과 설치형 `cremore.siem_sinks`; 수집과 별도 계약 |

`enterprise.py`에 함께 있던 GitLab·GCP·Confluence·Bitbucket의 API 경로·pagination·콘텐츠
읽기를 공급자별로 분리했다. 공통 `collectors/content.py`는 HTTP 예산·크기 제한·실패 처리·
수집 수명을 재사용한다. GitLab commit pin, GCS generation match, Confluence scope와
attachment origin, Bitbucket owner/repo/ref 검증을 그대로 유지했다. 이후 추가한 Azure Blob 콘텐츠
소스(`azure/backend/cremore_azure_provider/blob_*.py`)도 같은 공통 수명과 ETag 고정 읽기를 쓴다.
Azure DevOps Repos(`devops_*.py`)는 기본 브랜치 커밋 고정과 blob objectId 읽기를 쓴다.

AWS·GitHub·Notion 목록 조회도 공급자 catalog로 옮겼다. 공통 catalog는 등록 모듈을 호출하고
부분 수집을 PARTIAL로 처리한다. connection scope는 승인 root가 넓힐 수 없다.
공통 업무 화면을 AWS 폴더에 넣지 않도록 Accounts와 ProviderCredentialInventory를 추출했다(이후 콘솔로 대체되어
2026-10-01 이전 대시보드와 함께 삭제).

## GCP 독립 실행기와 Docker

기존 `gcp-connector/`의 추적 파일은 `gcp/standalone/`으로 옮겼다. `cremore_gcp`는 기존
inventory·relation·값 export/watch 함수와 CLI를 가진 플랫폼 독립 라이브러리다. 제품 adapter는
`gcp/backend/cremore_gcp_provider/`에서 공통 worker·DB를 연결하고, 공통 식별자·값 검증·reader·
매칭은 `cremore_gcp` 함수를 직접 호출한다. 두 패키지는 제품 wheel 하나에 포함한다.
독립 CLI의 JSON 파일·명시적 원문 export와 제품의 승인·저장 계약은 각각 유지한다.
2026-09-27: GCP 독립 CLI와 그것들만 쓰던 모듈(독립 수집·관계·watch·평문 export·파일 저장), 그리고
`gitlab/standalone/` 전체를 삭제했다. `cremore_gcp`에는 제품이 쓰는 식별자·값 reader·매칭만 남는다.

제거한 `Dockerfile.watch`와 `compose.watch.yml`은 독립 watcher 배포 레시피였다.
프로젝트 하나를 기본 300초마다 조회하고 ADC 파일을 읽기 전용 마운트하며 `.local/`에
JSON 상태·조회 값을 기록했다. Dockerfile 기본 명령은 `--help`이고 실제 polling 인자는
Compose가 전달했다. 제품 worker·이미지·CI는 이 전용 Docker를 사용하지 않았다.
따라서 두 파일과 실행 안내를 제거하고 독립 CLI는 유지했다.

추적된 소스만 이동했다. 기존 ignored `.local/`·ADC·자격증명·실제 출력 파일과 실행 중인
컨테이너는 건드리지 않았다. 새 독립 실행의 상대 `.local/`은 새 실행 위치 기준이므로
기존 상태를 자동으로 합치거나 복사한다고 가정하지 않는다.

## 설치·빌드·호환

- 기존 개발 환경은 루트에서 `python -m pip install -e ".[dev,gcp]"`를 다시 실행한다.
- `pyproject.toml`은 공통 패키지와 8개 공급자 backend를 wheel·pytest 대상으로 등록한다.
  제품에서 재사용하는 기존 `cremore_gcp` 패키지도 같은 wheel에 포함한다.
  공급자 SDK 이름과 충돌하지 않는 `cremore_<vendor>_provider` namespace를 사용한다.
- Python Docker는 공급자 backend와 `gcp/standalone/cremore_gcp`를 함께 빌드한다.
  그 외 standalone 파일·UI·상태·cache는 context에서 제외한다.
- Next는 저장소 root를 tracing 경계로 사용한다(standalone의 `web/server.js` 배치를 유지). 2026-10-01 이전 대시보드와
  `<vendor>/web/`, `@providers/<vendor>` alias, Tailwind를 삭제해 웹 소스는 `web/` 안에만 있다. React 설치는 `web/node_modules` 하나다.
- web Docker context는 저장소 루트이며 허용한 web 소스만 포함한다. standalone 실행 파일은
  `web/server.js`, 정적 파일과 public은 `web/` 하위에 배치한다. Compose·CI·release 경로를 맞췄다.
- 기존 Python production leaf import는 canonical 모듈 객체에 연결된다. private 객체와
  monkeypatch identity를 유지한다. package export·기존 Atlassian `python -m` 진입점도 보존한다.
  옛 파일에 새 구현을 넣지 않는다. 테스트는 새 위치만 수집하며 옛 테스트 alias는 만들지 않는다.
- registry·descriptor import는 실행 collector·DB·API를 미리 로드하지 않는다.

## 팀원별 병렬 개발

공급자 담당자는 자기 backend·descriptor·전용 테스트·문서를 맡는다. 콘솔·공통 타입·UI·승인·
DB·worker 수명·SIEM 발신 대기열은 플랫폼 담당자가 맡는다. 팀원별 branch/worktree에서
작업하고 registry·배포·빌드 파일은 통합 담당자를 정해 동시 수정을 피한다.

새 공급자는 기존 source/metadata 계약을 구현한 뒤 명시적으로 등록한다. 물리적 새 패키지의
wheel/pytest/Docker 경로를 함께 연결한다. 연결 화면은 descriptor로 그려지므로 웹 빌드 설정은 바꾸지 않는다.
모든 공급자가 폴더 추가만으로 완성되는 구조는 아니다. 새 인증 방식·scope 의미·job kind·
공개 응답·DB 계약은 소비자와 migration 검토가 필요하다. 담당이 배정된 변경을 다시 허락받으라는 뜻은 아니다.

팀에 배포할 지침은 [AGENTS](../AGENTS.md)와 [AI_TEAM_CODING_GUIDE](AI_TEAM_CODING_GUIDE.md)다.
파일 이동을 행 수 감소나 성능 개선으로 보고하지 않는다. 이번 변경의 목적은 실제 구현 소유권과
공통 계약을 나누고, 공급자 내부 변경에 필요한 파일을 한 영역에서 찾을 수 있게 하는 것이다.

## 검증

다음 수치는 공급자 디렉터리 이동 당시의 검사다. 후속 GCP 함수 통합 검사는 아래 절에서 구분한다.
최신 제품 회귀와 Docker·PostgreSQL·POSIX 추가 검증은 [검증 보고서](REFACTOR_REPORT.md) 15–16절을 따른다.

아래 수치는 서로 겹치는 검사이며 합산하지 않는다.

- 전체 Python 회귀: 5105 passed, 71 skipped, 266 subtests. 파일 경계 검사 1개가 옛 KMS/worker 경로를 기대해 실패했다.
  실제 이동 경로로 기대값만 갱신하고 관련 AWS session 검사 18개 및 실패 항목 재실행 1개가 통과했다.
  미해결 실패는 없다. 71개 skip은 격리 PostgreSQL 미설정 12개와 Windows의 POSIX 전용 검사 59개다.
- 이동 전 콘텐츠·metadata 기준: 866 passed, 59 skipped, 266 subtests.
- 분리 후 콘텐츠·인증·catalog·coverage·KMS·수집기: 284 passed, 1 skipped.
- Metadata 이동: 630 passed, 59 skipped, 266 subtests; 마지막 호환 facade 변경 후 catalog 21 passed.
- AWS 전용 구현과 공통 승인·verification: 296 passed.
- Web: Node 484 passed, TypeScript·Next production build 통과, browser proof 4종 통과.
  이동 전후 CSS selector/context 349개의 선언 순서·값도 같음을 확인했다.
- 독립 CLI: GCP 제거 전후 및 새 위치에서 46 tests 통과; GitLab은 WSL Ubuntu/Python 3.10의 격리된 임시 사본에서 162 tests 통과.
- 단일 wheel에 공통+8개 공급자 패키지, JSON/YAML 리소스 30개, CLI 4개가 포함된다.
  격리 wheel/editable 설치를 저장소 밖에서 네트워크 차단 상태로 검사해 import alias 107개와
  제품 모듈 293개의 경로·identity를 확인했다. coverage/siem `--help`도 통과했다.
- Compose 합성 설정과 Docker COPY 원본 23개 경로를 검사했다. 실제 이미지 build는 실행하지 않았다.

실제 공급자 인증·수집·SIEM 전송·운영 DB는 검증 환경으로 사용하지 않았다.
초기 GCP 테스트의 옛 monkeypatch 경로는 새 canonical 모듈로 갱신해 ADC 자동 탐색 대신 fake transport로 검증했다.
Ruff의 새 위반은 없으며 이동 전부터 있던 GitLab/Atlassian 10개 경고는 남아 있다.

## 후속 GCP 함수·모듈 통합

공통 구현은 `gcp/standalone/cremore_gcp`에 둔다. 기존 Python 3.11+ 소스 실행과
파일 기준 기본 출력 경로를 유지하면서 제품 wheel에도 같은 패키지를 포함했다.
새 배포 패키지·서버·Docker 서비스는 추가하지 않았다. 세부 소유자는 [GCP README](../gcp/README.md)에 있다.

- 리소스 정규식·상태/오류 정규화·지역 endpoint를 `resources`로 통합했다.
- `transport.ApiError`를 단일 예외 타입으로 사용해 제품의 `retry_after`와 양쪽 catch를 유지한다.
  ADC transport를 collector에서 분리했으며 import만으로 인증하지 않는다.
- `values`에서 base64 크기 제한·CRC32C와 세 값 reader를 공유한다. 제품의 체크섬 형식 검사를
  강화하고 watch에도 공개 인증서 PEM 표식 검사를 적용했다. 기존 저장값을 자동 삭제하거나 재조회하지 않는다.
- `linkage`의 매칭 함수를 제품에서 재사용한다. CLI에 있던 `scan_text`도 이 모듈이 소유한다.
  `storage.write_snapshot`이 원자적 JSON 저장을 소유하며 watch가 CLI를 import하지 않는다.
- 기존 CLI 명령·기본 경로·JSON schema·private import 호환을 유지한다. 독립 누적 수집과
  제품의 bounded transport·페이지 cursor·DB commit, latest export와 불변 version 선택은 각각 유지한다.
  이 실행 계약과 출력 투영의 차이까지 하나의 수집기로 합쳤다는 의미는 아니다.

이번 변경의 검증:

- 변경 전 기준: 제품 GCP 136 tests, 독립 CLI 46 tests 통과.
- 변경 후 제품 GCP·통합 API·metadata 재개/조회: 186 passed, 12 subtests passed.
- 독립 CLI: 48 tests 통과. 새 검사는 공개 인증서 형식과 atomic replace 실패 시 기존 파일 보존·임시파일 정리다.
- 잘못된 체크섬·공개키 합성 입력 12개 subcase는 수정 전 실패, 수정 후 통과했다.
- 최종 import 경계 검사까지 포함한 값 모듈 재검사: 17 passed, 12 subtests passed.
- 변경 Python 파일의 Ruff와 `git diff --check` 통과. 변경 문서의 상대 링크도 확인했다.
- 플랫폼·Google auth·HTTP client·CLI를 로드하지 않는 공통 라이브러리 import와 Python 3.11 문법을 확인했다.
  실제 실행 환경은 Python 3.12이며, Python 3.11 실행 검사는 수행하지 않았다.
- 단일 wheel을 별도 venv에 설치한 뒤 저장소 밖 `-I` 실행으로 GCP 모듈 21개의 설치 경로,
  함수·예외 identity 16개와 기존 모듈 alias 9개를 확인했다. CLI 5개의 `--help`가 모두 통과했으며
  ADC·네트워크 호출은 없었다. 새로 포함된 `cremore_gcp`에는 Python 파일 15개만 있고
  tests·docs·원문 출력·cache가 없다. 기존 다른 패키지의 테스트 파일은 wheel에 그대로 포함된다.
  Docker COPY·ignore는 소스 포함과 standalone 형제 출력 제외를 정적으로 확인했다.

실제 GCP 인증·API·운영 DB는 호출하지 않았다. 당시에는 Docker engine 조회가 실패해 실제 이미지 build를 수행하지 못했다.
이후 Docker 복구와 이미지 build·기동 검증은 위 최신 보고서에 기록했다.
이동 직후 최상위 `gcp-connector`에 남았던 캐시 14개의 자동 삭제는 승인 검토가 차단했으나,
2026-09-24 후속 문서 점검 시 해당 디렉터리가 없음을 확인했다. 제품은 이 옛 경로를 사용하지 않는다.
