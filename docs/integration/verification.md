# 분석, 오프라인 검증, 병합 충돌 기록

기준일 2026-09-21. 고정 SHA는 [구현 계약 §1](implementation-contract.md)의 표를 따른다. 아래 결과는 팀원 원본 프로그램에 대한 검증이며, 아직 만들지 않은 통합 제품의 테스트 결과가 아니다.

## 1. 판독 증거

| 자료 | 의미 |
|---|---|
| [source-inventory.csv](source-inventory.csv) | 다섯 branch의 독립 트리/추가 모듈 297파일, Git commit/blob, 크기, 줄 수, 읽기 상태 |
| [baseline-read-scope.csv](baseline-read-scope.csv) | 주 조사에서 읽은 develop 접점. FULL/PARTIAL과 실제 행 범위. 각 branch 보고서의 추가 비교도 별도 참조 |
| [passive-detection-comparison.csv](passive-detection-comparison.csv) | Slack/develop 원본 탐지 엔진의 합성50개 비교. 실제 값 없이 분류, 전체 material 동등성만 기록 |

`FULL`은 전체 내용 확인, `SAME`은 전체 읽은 다른 파일과 같은 Git blob, `STRUCTURE`는 전체 JSON을 파싱해 구조, 건수, 출처를 확인했지만 샘플 leaf 값을 전부 읽지 않은 경우다. Atlassian 증거 JSON 25개가 STRUCTURE다. source code를 STRUCTURE로 처리하지 않았다. 공개 테스트 fixture의 값은 출력하지 않았다.

GCP는 전체390파일 중 조상 대비 **추가24개만 팀원 변경**이다. `git diff --name-status 6cabc6b351274a4da5340bb18c8d081caa9f899b 3d79ccbef4ad51a7e7b9e0f73eabb1ac478c5ade`의 전 항목이 `A gcp-connector/...`임을 확인했다. 나머지366파일은 새 팀원 구현으로 세지 않는다. GitHub의 고유63개 중20개가 추가 경로에 byte-identical하게 반복되어 총83파일이다.

원문 `.env`, 고객 인증정보, 실제 Vault 값, 기존 서비스 DB/volume/log를 열람하지 않았다. Atlassian의 과거 증거 JSON은 구조 검토이며, 팀원이 남긴 실환경 진단을 이번 검증 성공으로 계산하지 않았다.

## 2. 직접 실행한 테스트

| 경로 | 실제 환경/방식 | 결과 | 해석 |
|---|---|---|---|
| GitLab 원본 | Windows Python3.12, unittest | 23중21 pass, failure1/error1 | 둘 다 CLI `fcntl` 의존 |
| GitLab 원본 | 기존 Linux image, network-none, read-only mount | **23/23 pass** | 해당 Linux CLI 계약 |
| GCP 원본 | Windows Python, fake transport unittest | **39/39 pass** | GCP 인증, 실제 API 호출 없음 |
| GitHub 루트 | host Python, FakeOpener/FakeGateway, 일부 loopback 서비스 계약 | **49/49 pass** | Org/서비스/조정, 예산 계약 |
| GitHub JSON package | host Python, fake gateway unittest | **45/45 pass** | Enterprise/supplemental/checkpoint/export 계약 |
| Atlassian 원본 | 기존 Linux image, network-none, read-only mount | **148/148 pass** | 현재 Runner next 차단을 기대하는 테스트 포함 |
| Slack 원본 | Windows Python3.12.9, 외부 DNS/connect 차단 | **196/196 pass, skip0** | 최종 develop Linux/잠금 환경의 결과는 아님 |

대표 환경에서 합계 **500 test executions**가 통과했다. GitHub 양쪽에 동일 테스트9개가 있어 **고유491개**다. GitLab Windows의 진단23개는 이 통과 합계에 추가하지 않았다. original test suite의 pass는 구현의 알려진 한계까지 없다는 뜻이 아니다.

Slack 첫 실행의 error6개는 분석용 네트워크 가드가 Windows asyncio 내부 socketpair loopback까지 차단한 결과였다. 제품 코드 변경 없이 외부 DNS/connect 차단은 유지하고 내부 loopback만 허용한 뒤196개가 통과했다. 실제 `.env` 로딩과 공급자 환경변수는 비활성화하고 합성 signing/HMAC만 사용했다.

Slack 검증 의존성: fastapi0.128.2, uvicorn0.52.0, SQLAlchemy2.0.52, httpx0.28.1, pydantic2.13.4, python-dotenv1.2.2, psycopg3.3.5, 격리 설치 slack-sdk3.44.1. 이 결과를 최종 잠금/Python3.14 Linux 검증으로 대체하지 않는다. 테스트 후 Slack source95개의 blob이 원본과 같은지도 확인했다.

대표 실행 명령은 다음과 같다. 경로는 이번 조사용 사본이며 운영 데이터가 아니다. 각 CLI는 해당 snapshot을 working directory로 사용했다.

```text
# GitLab, host 진단 / GCP
python -B -m unittest discover -s tests -q

# GitLab, Linux
docker run --rm --network none --read-only --tmpfs /tmp:rw,nosuid,noexec,size=64m --mount type=bind,source=C:\Users\admin\Desktop\cremore\work\integration-review\gitlab-snapshot,target=/review,readonly --workdir /review --entrypoint python cremore-python:latest -B -m unittest discover -s tests -q

# Atlassian, Linux: 이미 로컬에 있던 image, pull 없음
docker run --rm --pull never --network none --read-only --tmpfs /tmp -e PYTHONDONTWRITEBYTECODE=1 --mount type=bind,source=C:\Users\admin\Desktop\cremore\work\integration-review\atlassian-snapshot,target=/review,readonly --workdir /review --entrypoint python 2540e311713b -B -m unittest discover -s tests -q

# GitHub: root 및 github-api-collector 각각
python -B -m unittest discover -s tests -v

# Slack: 외부 접속/.env를 차단한 조사용 wrapper에서 원본 suite 실행
python -m unittest discover -s tests -v
```

Slack 재현 wrapper, 가드, 상세 로그, branch snapshot, 원 판독 대장은 git 제외 `work/integration-review/`에 보관했다. 최종 로그 SHA256은 `c3dc7d97cf6ec82483ee07ac0834616805ee2825cd9e5f6cd91648cbf3060b0c`다. 공유 산출물에는 민감 값 없이 결과, 환경, 소스 식별을 남긴다.

## 3. 추가 합성 확인

| 대상 | 관찰한 결과 | 설계에 반영한 조건 |
|---|---|---|
| GitHub valid generated-at | 검증/파싱 뒤 반환 page에는 유실 | provider snapshot 시각 보존 |
| GitHub pending PAT context | page contexts1, 최종 index에 contexts 속성 없음 | context DB/API/export round-trip |
| GitHub repositories total_count20/빈 rows | terminal로 수용, records_seen1 | count/row/page 구분, 완주 모순 검사 |
| GitHub JSON workflow runs route | `unlisted_read_endpoint` | root에만 있는 run/job 기능도 인수 |
| GitHub 공식 감사 cursor 후속 비교 | after 단독은 성공, 빈 before가 추가되면 `invalid_pagination_link` | 공식 페이지 형식 수용, 동일 host/기업/경로 검사 유지 |
| Slack/develop50개 | xoxc/xoxd/xwfp/xoxe 일부, 라벨, Bearer의 누락, rotating capture 차이, 반대 방향 webhook 차이 | detector 수가 아닌 capture/type/material parity 검증 |

이 입력들은 합성이며 유효한 자격증명 여부를 검사하지 않았다. Slack 비교는 RE2=True, verify=False, 외부 접속 차단이다. CSV의 material=false는 다른 부분/형식을 캡처했다는 뜻이며 곧바로 미탐이라는 뜻은 아니다. DB URI는 Slack password-only와 develop 전체 URI의 의도된 material 차이가 있다. 공식 감사 cursor 비교는 네트워크 없는 순수 함수 입력2개이며 앞선 원본 테스트500회에 포함하지 않았다.

## 4. develop 대비 실제 Git 충돌

실행 방식은 `git merge-tree --write-tree --name-only develop publish/<branch>`다. Git object 계산만 했으며 checkout/index/branch refs를 변경하거나 merge commit을 생성하지 않았다. exit0=clean, exit1=conflict이고 오류 종료와 구분했다.

- **GCP:** exit0, 충돌 없음.
- **GitLab:** `.gitignore` add/add, `README.md` modify/delete.
- **Atlassian:** `.gitignore` add/add, `README.md` content.
- **Slack:** `.env.example`, `.gitignore`, `LICENSE`, `README.md`, `requirements.txt`.
- **GitHub:** 아래14경로. add/add, content 외에 초기 `CreMore_github/`에서 추론된 rename/delete 및 modify/delete가 있다.

```text
.dockerignore
.gitignore
README.md
cremore_collectors/auth.py
cremore_collectors/runner.py
github-api-collector/cremore_collectors/collectors/classic_pat.py
github-api-collector/cremore_collectors/collectors/deploy_key.py
github-api-collector/cremore_collectors/collectors/fine_grained_pat.py
github-api-collector/cremore_collectors/collectors/github_app_installation_token.py
github-api-collector/cremore_collectors/collectors/github_app_user_token.py
github-api-collector/cremore_collectors/collectors/github_token.py
github-api-collector/cremore_collectors/collectors/oauth_app_token.py
github-api-collector/cremore_collectors/collectors/user_ssh_key.py
github-api-collector/requirements.txt
```

실제 source 경로가 겹치지 않는 branch도 runtime, schema, 인증, package/UI에는 충돌이 있다. 반대로 rename 충돌은 새 기능을 버릴 이유가 아니다.

## 5. 팀원끼리 10쌍

모두 exit1이었다. 이름은 `develop_` 접두를 생략했다. 아래 묶음도 전체 경로를 정의한다.

- **GH-common:** `README.md`, `credential_dashboard/queries.py`, `cremore_collectors/collectors/github_app_user_token.py`, `cremore_collectors/collectors/oauth_app_token.py`, `cremore_collectors/collectors/user_ssh_key.py`.
- **GH-vs-GCP:** 위 §4의 GitHub14경로와 동일.
- **Slack-vs-GCP:** 위 §4의 Slack5경로와 동일.

| 조합 | 모든 충돌 경로 |
|---|---|
| gcp–gitLab | `.gitignore`, `README.md` |
| gcp–atlassian | `.gitignore`, `README.md` |
| gcp–github | GH-vs-GCP |
| gcp–slack | Slack-vs-GCP |
| gitLab–atlassian | `.gitignore` |
| gitLab–github | GH-common |
| gitLab–slack | `.gitignore` |
| atlassian–github | GH-common |
| atlassian–slack | `.gitignore`, `README.md` |
| github–slack | GH-common |

이는 고정 두 head의 현재 결과다. 실제 순차 병합, 파일 이동 후에는 그 시점의 conflict를 다시 검토한다. `-X theirs`를 자동 해결 정책으로 삼지 않는다.

## 6. 완료 주장 범위

수행: 팀원 소스 판독, baseline 접점 비교, 원본 오프라인 테스트, 합성 비교, merge-tree, 공개 공식 문서 대조, 설계/근거 문서 작성.

가독성 재작성과 대시보드 설계 보완 후 문서 검증에서는 Markdown 10개의 내부 파일/제목 링크, 표의 열 수, 명시적 source reference 308개의 고정 Git 파일 존재, 행 범위를 확인했다. 297개 판독 대장의 경로, blob을 다섯 고정 Git tree와 대조했고 누락이 없었다. 코드212개는 FULL192개와 동일 blob의 SAME20개다. `git diff --check` 및 새 파일을 포함한 산출물13개의 공백 검사도 통과했다. 현재 브랜치는 `develop_total`, `develop`은 고정 기준 `71ea52ad933708b7fb851f590ab7162d7f7ed35f` 그대로이고 제품 코드 차이는 없다.

미수행: 제품 코드 병합, baseline 전체 테스트 재실행, 최종 package/의존성 조합 검증, 실제 provider 권한 검증, 운영 DB 이행, 대시보드 구현/재배포, 외부 알림, 교체/폐기. 이 항목은 [통합 설계](../INTEGRATION_DESIGN_REVISED.md)의 구현 gate다.

## 7. 가독성 및 공식 계약의 후속 보완

본문을 공급자별 **공통점 → 추가 기능 → 충돌과 추천 → 구현 작업 → 완료 조건**으로 다시 작성했다. 세부 저장/실행/API/이행 조건은 [구현 계약](implementation-contract.md), 공식 URL, 확인 사실, 코드 차이, 미확정 사항은 [공식 문서 대조](official-docs.md)에 분리했다. 기존 소스별 기능 인수표와 판독 대장은 유지했다.

공개 문서와 관련 OpenAPI를 익명으로 읽었다. 주요 결정 경로를 고정 소스에서 다시 확인했고, GitHub, Atlassian, Slack은 각 조사 결과와 최종 본문을 별도로 교차 검토했다. 기존 제품 테스트를 문서 편집 때문에 반복 실행하지 않았다.

- GitLab: PAT의 실제 사용자 필터, GitLab.com manage 범위, active-only agent, 실험 GraphQL을 확인했다.
- GCP: 지원 지역 자동 순회와 Secret 버전 불변성에 맞춰 기존 설명을 정정했다. 감사/metric 미관측의 한계도 반영했다.
- GitHub: Enterprise total_count 부재, 공식 감사 cursor 형태, host, App 권한을 확인했다. 총수 검사는 해당 필드를 제공하는 저장소 Actions 응답에도 적용한다.
- Atlassian: Cloud17/Bitbucket26의 route/method 전부를 공식 명세와 대조했다. DC10.0 GET6개는 후속 후보이며 구현 완료가 아니다. Basic 인증을 추가하면서 OIDC 두 연산의 무인증은 보존한다.
- Slack: 앱 배포별 rate, team_id, 승인 앱/감사의 설치 주체 차이, 회전 토큰의12시간 만료, Azure의 수정 시각과 회전 시각 구분을 확인했다.

공식 문서 상충, 고객별 권한, 실제 배포는 별도 확인 항목으로 남겼다. 설계와 근거 문서만 변경했으며 이번 작업의 커밋, 푸시, 제품 병합은 수행하지 않았다.

사용자 요청에 따라 관련 Markdown 10개의 가운데점 1,297곳을 쉼표, 접속어 또는 슬래시로 바꿨다. 변경된 제목의 내부 링크도 함께 수정했다.

## 8. 대시보드 통합 설계 보완

기존 develop의 탐색, 데이터 조회, API 프록시, 공통 UI, Vault, 검색, 역할 판정과 관련 테스트를 대조했다. [통합 설계 §8](../INTEGRATION_DESIGN_REVISED.md#8-대시보드와-운영의-최종-모습)에는 유지할 디자인과 화면별 변경을, [구현 계약 §6](implementation-contract.md#6-api-대시보드-온보딩)에는 담당 파일과 인수 조건을 반영했다.

- 기존 테마, 표, 상세 패널을 재사용하면서 AWS 목록을 공급자 관리 목록으로 확장한다. 기존 AWS URL과 정보는 보존하고 새 목록은 서버 페이지 조회를 사용한다.
- AWS 전용 응답 검사, non-AWS의 Vault 오분류, Slack이 빠진 화면 필터, v1로 고정된 프록시를 실제 연결 작업으로 명시했다.
- 연결 인증, 수집 결과, 공급자가 보고한 상태, 저장된 검증, 금고 대조를 구분한다. 수집 인증 만료와 대시보드 로그인 만료도 다른 동작으로 정의했다.
- AWS 재수집 UI의 Remediator 제외와 서버의 Analyst 이상 허용이 다름을 확인했다. 서버 역할 계약과 화면을 맞추는 변경, 정확한 검색 상세 이동, 공급자별 오류 분리도 포함했다.

이번 보완은 소스 확인과 문서 변경이다. UI 코드, API, 배포는 변경하지 않았고 제품/UI 테스트도 새로 실행하지 않았다. 기존 테스트를 확장하여 구현 후 확인할 항목만 명시했다.
