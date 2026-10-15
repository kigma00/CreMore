# develop_total 구현 설계안

기준일: **2026-09-21** / 상태: **설계 완료, 제품 통합 전**

**추천은 팀원의 수집 기능을 기존 CreMore 제품 안으로 옮기는 것입니다.** 팀원이 만든 수집 범위, 상세 정보, 오류 처리와 이력을 우선 보존합니다. 실행은 기존 worker, 저장은 기존 PostgreSQL, 화면은 기존 대시보드를 사용합니다.

`develop`은 그대로 두고 `develop_total`에서 통합합니다. 이 문서의 구현 순서는 제안이며, 코드가 이미 통합됐다는 뜻은 아닙니다.

읽는 순서:

- 담당 공급자가 정해졌다면 [GitLab](#2-gitlab), [GCP](#3-gcp), [GitHub](#4-github), [Atlassian과 Bitbucket](#5-atlassian과-bitbucket), [Slack](#6-slack)으로 이동합니다.
- 공통 백엔드 담당자는 [공통 구현 순서](#7-공통-구현-순서)를 먼저 봅니다.
- 필드, DB, API의 세부 조건은 [구현 계약](integration/implementation-contract.md), 실제 API의 범위, 권한은 [공식 문서 대조](integration/official-docs.md)를 봅니다.

## 1. 무엇을 합치는 작업인가

현재 `develop`은 **콘텐츠에서 비밀의 노출을 찾고, Vault의 관리 정보와 대조하는 제품**입니다. 팀원 브랜치 대부분은 **공급자의 관리 API에서 자격증명 목록과 관련 정보를 읽는 수집기**입니다. Slack은 메시지 수집과 별도 관리 앱까지 포함합니다.

예를 들어 GitHub 파일에서 토큰을 발견하는 것과, GitHub 관리자 API에서 토큰의 소유자, 권한, 만료 정보를 읽는 것은 서로 다른 기능입니다. 두 결과를 연결해야 보안담당자가 더 정확하게 판단할 수 있습니다.

| 브랜치 | develop에도 있는 공급자, 기능 | 팀원에게서 추가되는 내용 |
|---|---|---|
| GitLab | 저장소 파일 수집, 노출 탐지 | 토큰 10종류의 관리 목록, 소유자, 권한, 상태, 관찰 이력 |
| GCP | GCS 콘텐츠, Secret Manager의 global 값 대조 | 서비스 계정/키, API key 목록, 지역별 Secret/모든 버전, 사용 관계 |
| GitHub | 저장소, 조직 콘텐츠, App 인증, 기업용 host 처리 | 조직/Enterprise 관리 목록, 앱, 정책, 권한, 감사 연결 |
| Atlassian | Confluence, Bitbucket Cloud/Data Center 콘텐츠 | Atlassian 조직 관리정보, Bitbucket Cloud 공개키, Runner 정보 |
| Slack | Slack 토큰 탐지 규칙, AWS/GCP/Vault 대조 | **Slack 콘텐츠 공급자**, 앱, 감사, 소유 토큰 관리, **Azure Key Vault metadata** |

따라서 공급자 자체가 새로 들어오는 핵심 항목은 Slack 콘텐츠 연결과 Azure Key Vault 관리정보입니다. GitHub, GitLab, GCP, Bitbucket은 기존 콘텐츠 기능에 관리정보 수집을 더합니다. AWS, Notion 등 기존 기능도 유지합니다.

여기서 **관리정보(metadata)**는 ID, 소유자, 권한, 만료, 상태 등을 뜻합니다. 비밀값 자체, 실제 노출, 인증 성공과는 구분합니다.

### 비교 근거

**Git 파일 충돌**은 두 브랜치를 합칠 때 Git이 보고한 경로입니다. **기능과 구조의 충돌**은 결과의 의미나 실행 방식이 맞지 않는 지점입니다. 팀원 코드 자체의 미완성 부분은 공식 문서 대조와 완료 조건에서 따로 설명합니다.

README뿐 아니라 팀원 소스, 진입점, 호출 경로, 저장 코드, 테스트를 읽은 [파일별 판독 대장](integration/source-inventory.csv)을 기준으로 했습니다. 297개 파일 중 코드 파일은 212개입니다. 고유 코드 192개는 전체를 읽었고 나머지 20개는 동일 Git blob인 중복 코드입니다. 원본 증거 JSON 25개는 구조를 검사했으며 고객 샘플 값까지 전부 정독했다고 주장하지 않습니다.

GCP 브랜치의 팀원 변경은 신규 24개 파일입니다. 공통 조상에서 그대로 내려온 나머지 366개는 새 기능으로 세지 않았습니다. `develop`은 관련 수집, 인증, DB, worker, API, 화면 접점을 대조했습니다. 모든 397개 파일을 새로 정독한 것은 아닙니다.

고정 commit은 `develop=71ea52ad…`, GitLab=`972eac27…`, GCP=`3d79ccbe…`, GitHub=`bfb97fb1…`, Atlassian=`11c44f2a…`, Slack=`48ea1643…`입니다. 전체 SHA와 판독 범위는 [구현 계약 §1](integration/implementation-contract.md)에 있습니다. 이번 보완에서는 결정적인 호출 경로를 재확인하고 **공식 문서의 API, 권한, 응답, 페이지 처리 계약을 실제로 읽어** 대조했습니다. 고객 계정에서의 실환경 검증은 별도입니다.

## 2. GitLab

**추천: 기존 저장소 스캔 옆에 ‘GitLab 관리 목록 수집’을 추가합니다. 팀원의 수집, 정규화 로직을 사용하고, SQLite 대신 제품 DB에 저장합니다.**

### 공통점

두 브랜치 모두 인증된 GitLab을 정해진 범위에서 읽고, 페이지, 요청 한도와 부분 실패를 처리합니다. 기존 연결, 비밀 참조, 작업이력을 재사용할 수 있습니다.

### 차이점과 추가 기능

`develop`은 저장소 파일을 읽습니다. 팀원은 다음 **10종류**의 관리정보를 읽습니다.

1. 개인 PAT, 그룹 서비스 계정 PAT, 프로젝트 서비스 계정 PAT
2. 그룹, 프로젝트 access token, 그룹, 프로젝트 deploy token
3. pipeline trigger, error-tracking client key, Kubernetes agent token

팀원은 그룹의 하위 그룹, 프로젝트와 관찰된 서비스 계정, agent, 사용자도 찾습니다. 같은 토큰이 여러 API에 나타나면 연결하되, 소유자와 발급자를 구분합니다. 재시작할 때에는 이전과 같은 인증 주체, 설정인지 확인합니다.

**공식 문서로 확인한 제한:** 현재 코드의 일반 PAT 조회는 관리자여도 자기 사용자 ID로 제한합니다. 그룹 `/manage/...`는 GitLab.com의 Premium/Ultimate, 최상위 그룹 Owner용 계약입니다. 자체 설치 GitLab에 같은 API가 된다고 표시하면 안 됩니다. Kubernetes agent 목록은 active token만 반환하며, GraphQL trigger 보완은 실험 기능입니다. [공식 근거 GL1–GL5](integration/official-docs.md#gitlab)

### 충돌과 해결

| 충돌 | 그대로 합치면 생기는 문제 | 추천 해결 |
|---|---|---|
| 콘텐츠 수집과 관리 목록의 결과 형식 | 기존 `gitlab` 작업을 교체하면 파일 노출 탐지가 사라짐 | 콘텐츠 작업 유지, 관리 목록 작업 추가 |
| 기존 AWS 중심 저장 형식 | 토큰 종류, 소유자, 출처, 누락 이유가 잘리거나 GitLab을 Vault로 오분류 | 팀원 필드를 보존하는 관리정보 모델 추가 |
| 토큰 ID와 탐지값의 지문 | ID만으로 노출, Vault 값 일치를 만들 수 없음 | 공급자 객체 ID와 비밀값 지문을 별도 저장 |
| SQLite, 파일 잠금과 제품 작업 큐 | 여러 worker 또는 EKS에서 중복 실행, 덮어쓰기 가능 | 기존 DB 작업 잠금, 중단, 재개를 사용 |

Git 파일 충돌은 **2개**입니다: `.gitignore`, `README.md`. 기능 충돌과 구분해 두 파일의 보호 규칙, 설명을 합칩니다.

### 구현 담당자가 할 일

1. 팀원의 `Collector`, `identity`, `metadata_view`를 관리정보 수집 모듈로 옮깁니다. `group_tasks`, `project_tasks`의 대상 확장과 10종류를 그대로 보존합니다.
2. 기존 `secretstore/resolver.py`에서 인증값을 받고, 기존 `TaskStore.fenced` 안에서 페이지 결과, 후속 작업, 재개 위치를 함께 저장합니다. 주체가 바뀌면 기존 실행 재개를 거절합니다.
3. 연결 화면에 instance, 그룹/프로젝트, 수집 항목을 추가합니다. 관리 목록 상세에는 소유자, 출처, 마지막 성공, 읽지 못한 이유를 보여줍니다.

**완료 조건:** 원본 Linux 23개 테스트 의미 보존, 중복 PAT, 부분 GraphQL, 인증 주체 변경, 중단 후 재개 검증, 기존 GitLab 파일 스캔 정상. native Windows CLI의 `fcntl` 제한도 해소하거나 명시해야 합니다.

코드 근거: [GitLab 전체 분석](integration/gitlab.md), `GL:gitlab_inventory/collector.py:45`, `GL:gitlab_inventory/model.py:74`, `DEV:cremore/db/task_store.py:660`.

## 3. GCP

**추천: 기존 GCP Secret Manager 수집을 팀원 기능으로 확장하고, 서비스 계정, API key 목록과 사용 관계를 같은 관리 화면에 추가합니다.**

### 공통점

양쪽에 Secret Manager 수집이 있습니다. `develop`은 이미 global Secret의 선택 버전/latest 값을 읽어 지문을 만들며, GCS 파일도 스캔합니다. 팀원 기능을 별도 watcher 서비스로 붙이면 같은 금고를 중복 수집하게 됩니다.

### 차이점과 추가 기능

- 서비스 계정과 사용자/시스템 관리 키, API key의 ID, 제약, 상태를 수집합니다.
- 지원 위치 목록을 조회해 지역별 Secret을 찾고, 모든 버전과 상태를 읽습니다. 현재 팀원 CLI는 지역을 직접 선택하는 방식이 아닙니다.
- Secret 접근 감사, 정확한 서비스 계정 키 사용 근거, API key 사용량, IAM 정책상 가능한 접근 관계를 수집합니다.
- 목록 변화와 상태 변화를 기록하고, 노출 자료의 `client_email`, `private_key_id`를 관리 목록과 연결합니다.

**공식 문서로 확인한 제한:** 서비스 계정 private key는 생성 응답에서만 받을 수 있습니다. 기존 키 목록에서 private key를 복원하는 기능은 아닙니다. API-key 목록도 key string을 주지 않으며 `showDeleted`는 최근30일 삭제분입니다. Secret 버전 목록과 값 읽기에는 서로 다른 권한이 필요합니다. [공식 근거 GC1–GC3](integration/official-docs.md#gcp)

### 충돌과 해결

| 충돌 | 그대로 합치면 생기는 문제 | 추천 해결 |
|---|---|---|
| 팀원 watcher의 평문 JSON | 비밀값이 제품 DB, export로 흘러갈 수 있음 | 값은 메모리에서 공통 지문 처리 후 버림 |
| 모든 enabled 버전과 현재값 | 과거 버전 일치를 현재 사용 중인 값으로 오해 | 버전, 상태, 선택 기준, 마지막 값 확인 시각을 저장 |
| 공개키/원문 파일 digest와 credential 지문 | 서로 다른 대상을 같은 비밀로 연결 | 공개키 지문, 값 지문, 일반 변경 digest 구분 |
| 사용 기록과 IAM 허용 정책 | 접근할 수 있다는 정책을 실제 사용으로 표시 | ‘관측한 사용’과 ‘가능한 접근’을 별도 관계로 저장 |
| 단일 JSON watcher와 공통 worker | 중복 스케줄, 여러 프로세스의 상태 덮어쓰기 | 기존 worker, DB 이력으로 수용 |

Git 파일 충돌은 **0개**입니다. 그래도 위 저장, 의미 충돌은 구현해야 합니다.

### 구현 담당자가 할 일

1. 기존 `coverage.collect_gcp`에 팀원의 지역/버전 목록과 CRC32C 검사를 합칩니다. 서비스 계정/API key는 금고 항목과 구분하여 저장합니다.
2. 팀원의 `RelationshipCollector`와 로컬 키 연결 함수를 이식합니다. 원격 `lookupKey`는 별도 선택 기능이며, 결과를 인증 성공으로 표시하지 않습니다.
3. watcher의 변화 이력을 DB에 저장합니다. **Secret 값은 버전별로 불변**이므로 새 버전, latest/별칭 이동, enable/disable/destroy를 확인합니다. 기존 cached 값은 과거 읽기 증거이며 현재 접근 성공으로 갱신하지 않습니다.
4. 대시보드에 계정/키/금고/사용 관계를 나누어 보여줍니다. 지역 선택은 새 연결 설정으로 추가하고, 현재 relations가 global Secret만 처리한다는 제한을 표시합니다.

**완료 조건:** 원본 39개 테스트 의미 보존, 지역/버전, 권한 부족, CRC, 평문 비저장, 이력 재시작 검증. 감사 로그 비활성, metric 지연/미제공은 ‘미사용’으로 판단하지 않아야 합니다.

이전 문서의 ‘같은 Secret 버전 값 변경을 놓친다’는 표현은 공식 불변성 계약에 맞춰 정정했습니다. 새로운 버전/선택 대상 변화와 마지막 확인 시각이 실제 구현 기준입니다. [공식 근거 GC4–GC6](integration/official-docs.md#gcp)

코드 근거: [GCP 전체 분석](integration/gcp.md), `DEV:cremore/coverage/collect.py:313`, `GCP:cremore_gcp/collector.py:349`, `GCP:cremore_gcp/watch.py:258`, `GCP:cremore_gcp/relations.py:587`.

## 4. GitHub

**추천: 팀원의 조직 기능과 Enterprise 기능을 모두 보존한 관리 수집기를 만듭니다. 기존 GitHub 콘텐츠 스캔, App 인증, 기업 host 처리를 공통으로 사용합니다.**

### 공통점

양쪽 모두 GitHub App 인증, 요청 한도, 일부 실패 후 결과 보존을 갖고 있습니다. `develop`에는 이미 저장소/조직 콘텐츠 스캔과 GitHub.com, GHES, ghe.com을 고려한 인증 경로가 있습니다.

### 차이점과 추가 기능

팀원 브랜치에는 두 프로그램이 있습니다.

- **루트 조직 수집기:** SSO 승인, fine-grained PAT, 저장소 권한, OAuth/App user token, SSH/deploy key, App 설치, Actions 정책을 읽습니다. 승인 대기 요청과 Actions 실행/작업 정보도 선택 수집합니다.
- **하위 Enterprise 수집기:** Enterprise 자격증명 목록, 조직/설치 정보, 감사 기록과 토큰의 관계, 페이지 저장, 재개, export를 제공합니다.

따라서 Enterprise 프로그램만 선택하면 루트에만 있는 Actions run/job 등이 빠집니다. 반대로 루트만 선택하면 Enterprise/audit, 재개가 빠집니다. `credential_dashboard`는 SQLite 저장, 조회 모듈이며 웹 대시보드가 아닙니다.

**공식 문서로 확인한 제한:** 조직 SSO 승인은 직원의 모든 토큰 목록이 아닙니다. Enterprise 목록에는 `total_count`가 없으며, Enterprise 설치 토큰에는 저장소 접근 권한이 없습니다. `ghe.com`은 공식 Cloud 문서가 지원 주소를 안내하지만 팀원 코드는 public host로 고정돼 있습니다. [공식 근거 GH1–GH4](integration/official-docs.md#github)

### 충돌과 해결

| 충돌 | 그대로 합치면 생기는 문제 | 추천 해결 |
|---|---|---|
| 기존 `github-org` 작업 이름 | 이미 조직 파일 스캔인데 metadata로 바꾸면 기존 연결 재실행이 다른 일을 함 | 이름의 기존 의미 유지, 관리 수집 작업 추가 |
| 동일 package 이름 두 개 | 실행 위치에 따라 다른 코드가 import됨 | 동일 blob20개는 통합하고 양쪽 전용 기능은 함께 보존 |
| public host 고정 | 기존 기업용 host 지원이 관리 수집에서 끊김 | 기존 host/auth를 요청, 페이지 이동, 객체 ID 전체에 적용 |
| 공급자 ID/hash와 기존 값 지문 | suffix, 감사 hash를 유출 비밀의 동일값으로 오인 | 공급자 관계와 값 일치를 구분, actor가 쓴 토큰과 사건 대상 토큰도 구분 |
| JSON/SQLite와 기존 DB | context, 권한, 감사가 사라지거나 동명 테이블 의미가 충돌 | 기존 DB에 관리 객체, 관찰, 관계를 별도 저장 |

Git 파일 충돌은 **14개**입니다. 정확한 경로는 [충돌 기록 §4](integration/verification.md)에 있습니다.

### 구현 담당자가 할 일

1. 조직 단독/Enterprise 모드를 모두 제공합니다. 인증은 기존 `GitHubAppTokenSource`를 사용하고 팀원의 installation 발견, 범위 검사를 합칩니다.
2. Enterprise 페이지 처리, 감사 연결을 중심으로 정리하되 루트의 항목 선택, 승인 요청, Actions run/job, 요청 예산을 이식합니다. 별도 서비스5개를 기본 운영 구성에 추가하지 않습니다.
3. context export, 관측된 generated-at 전달, 일부 key 오류 유실을 고칩니다. 총수 검사는 **total_count를 제공하는 installations, repositories, Actions runs/jobs 응답에만** 적용합니다.
4. 공식 감사 페이지의 빈 반대 방향 cursor(`before=` 등)를 처리하면서 host/경로/범위 검사는 유지합니다. 대시보드에는 credential, 공개키, 설치, 정책, 요청을 구분해 보여줍니다.

**완료 조건:** 원본49+45 실행의 고유 85개 테스트 의미 보존, 두 모드와 Actions 선택 기능, context 왕복, 공식 페이지 형식, host별 범위, 기존 콘텐츠 작업 재실행 검증.

Enterprise 감사 인증은 공식 페이지 안에서도 안내가 상충하므로 실제 시험이 필요합니다. GHES 관리 목록은 버전별 공식 계약 확인이 남았으며, 문서404만으로 API 미존재를 단정하지 않습니다.

코드 근거: [GitHub 전체 분석](integration/github.md), `DEV:cremore/worker/factory.py:88`, `GH:cremore_collectors/collectors/github_token.py:409`, `GH:github-api-collector/cremore_collectors/json_pipeline.py:142`, `GH:github-api-collector/cremore_collectors/validation.py:74`.

## 5. Atlassian과 Bitbucket

**추천: Confluence, Bitbucket 콘텐츠는 유지하고, 팀원의 Cloud 관리정보 수집을 별도 목적으로 연결합니다. Bitbucket 인증 방식은 기존 develop의 분기를 재사용합니다.**

### 공통점

양쪽 모두 요청 한도와 페이지 검사를 두고 허용한 원격 자원을 읽습니다. `develop`은 Confluence 페이지/첨부와 Bitbucket 파일을 Cloud, Data Center에서 수집합니다. 팀원은 그 내용을 수집하지 않습니다.

### 차이점과 추가 기능

- **Atlassian Cloud 17개 읽기 연산:** 관리자 key, 조직/서비스 계정 token, OAuth client, 관리 계정, 사용자 정보, count/detail 조회입니다. 정규화 source5개는 이17개에 포함됩니다.
- **Bitbucket Cloud core22 + Runner4:** 사용자, workspace, 프로젝트, 저장소의 공개키, pipeline SSH/known-host, OIDC, Runner 상태, 인증 관계입니다.
- 필드의 없음/null/정상/타입 오류, 소유자/생성자, API 간 상충 관찰, 페이지별 필드 목록을 보존합니다. ID 없는 count/detail 결과도 남깁니다.

공식 OpenAPI와 대조하여 **43개 연산의 경로, method 대응**을 확인했습니다. 이것이 고객 권한으로 43개가 모두 성공했다는 뜻은 아닙니다. [공식 근거 AT1–AT3](integration/official-docs.md#atlassian과-bitbucket)

### 충돌과 해결

| 충돌 | 그대로 합치면 생기는 문제 | 추천 해결 |
|---|---|---|
| 콘텐츠와 조직 관리의 인증, 대상 | 같은 브랜드라는 이유로 다른 용도의 token, 범위를 공유 | 조직 관리/관리 계정/Bitbucket core/Runner를 역할별 연결 |
| 팀원의 Bearer 전용 인증 분기 | 개인 Bitbucket API token의 공식 email+Basic 계약과 맞지 않음 | 기존 `auth_type` 분기 적용, OIDC 설정, JWKS 두 연산의 무인증 처리 유지 |
| 기존 평면 필드, ID 검사 | 공급자 ID가 거절되거나 소유자, 상충 관찰이 유실 | 공급자별 ID와 팀원의 필드 상태를 보존 |
| 공개키/Runner 정보와 노출 수 | 공개 정보나 Runner OFFLINE을 유출, 폐기로 오인 | 공개키, 신뢰 설정, Runner를 별도 종류로 표시 |
| 자유로운 snapshot, POSIX 파일 저장 | 일반 API에 과도한 정보 노출, 서버 작업, Windows 실행과 불일치 | 허용 필드만 제품 DB에 저장하고 원본의 생략 이유, 필드 목록 보존 |

Git 파일 충돌은 **2개**입니다: `.gitignore`, `README.md`.

### 구현 담당자가 할 일

1. 팀원의 `collect`, `collect_discovery`, `collect_accounts`, `collect_bitbucket`을 기존 worker에서 호출하도록 옮깁니다. 각 모드의 대상 발견, 권한을 유지합니다.
2. 값이 없는 count/detail은 작업 보고서로 저장합니다. 객체 수0을 데이터 없음으로 바꾸지 않고, 선택 API 완료를 전사 전체 수집 완료로 표시하지 않습니다.
3. 기존 `SourceHTTP`의 Basic/Bearer 선택 의미를 재사용하고, OIDC 설정, JWKS 두 연산의 무인증 처리를 유지합니다. Runner의 다음 페이지는 동일 workspace/repository임을 확인한 경우에만 처리하도록 보완합니다.
4. 기존 화면에 관리 목록, 공개키, Runner 상세와 API별 실패 이유를 추가합니다. owner와 creator, 공급자 상태와 실제 검증을 구분합니다.

**완료 조건:** 원본 148개 테스트 의미 보존,43개 연산 등록, 인증 종류별 요청, count/detail 보존, Runner 여러 페이지, 기존 Cloud/DC 콘텐츠 회귀 검증.

**기업판 추천:** Cloud Enterprise 요금제와 자체 설치 Data Center를 분리합니다. Bitbucket DC 10.0 공식 명세에는 개인/프로젝트/저장소 HTTP token의 목록, 상세 GET 6개가 있습니다. 현재 양쪽 코드에 없는 후속 구현 후보입니다. Cloud resource-token 전체 목록과 Confluence DC 관리자 목록은 별도 계약 확인이 남습니다. [공식 근거 AT4](integration/official-docs.md#atlassian과-bitbucket)

기존 Cloud 일부400/404, OAuth 배열의 완전성은 여전히 미확정입니다. 공식 경로 존재만으로 해결 완료로 바꾸지 않습니다.

코드 근거: [Atlassian 전체 분석](integration/atlassian.md)의 A03/A05/A07/A09 및 `DEV:cremore/collectors/enterprise.py:40`, `DEV:cremore/source_config.py:75`.

## 6. Slack

**추천: 먼저 Slack 메시지 수집을 기존 탐지 제품에 연결하고, 그다음 실시간, 알림, 관리정보, 소유 토큰 기능을 차례로 붙입니다. 팀원 화면을 별도 서비스로 병치하지 않습니다.**

### 공통점

양쪽에 탐지 규칙, 발견 결과, 상태 이력이 있습니다. `develop`에는 공통 스케줄/이벤트 작업과 AWS/GCP/Vault 연동도 있습니다. 다만 Slack 연결, 메시지 수집기는 없습니다.

### 차이점과 추가 기능

- 메시지 history/replies, 실시간 Socket/Events, 편집, 선택 DM/MPIM, archived 범위, 권한 부족 진단
- 발견 댓글 알림, 조치 추천, 명시 채널 참여, 수동 실행/주기 실행/모니터 제어
- 승인 앱, 공급자 감사, 설치 사건, 수동 portal 정보
- 연결/관측한 소유 토큰의 유형별 검사, 수명주기, OAuth/import, 명시 교체/폐기
- AWS/GCP/Vault 추가 metadata와 **Azure Key Vault metadata**, snapshot/export, 로컬 QA 도구

탐지 규칙도 완전히 같지 않습니다. 팀원에는 develop이 놓치거나 일부만 잡는 Slack 형식, label/Bearer 후보가 있고, develop에는 팀원에 없는 webhook 탐지가 있습니다. 상세 보고서의 **26개 기능군, 16개 규칙 전체**를 인수 기준으로 사용합니다.

### 충돌과 해결

| 충돌 | 그대로 합치면 생기는 문제 | 추천 해결 |
|---|---|---|
| 서로 다른 지문 계산 | 같은 값도 다른 credential로 보이거나 잘못 연결 | 기존 scheme을 기록하고 원문 없는 과거 hash는 강제 변환하지 않음 |
| 메시지 ID, 편집 처리 | 다른 workspace 충돌, history/실시간 중복, 편집 노출 누락 | 연결+workspace+채널+메시지+버전을 공통 ID로 사용 |
| 프로세스 내부 실행, ACK | 재시작 또는 ACK 직후 종료 시 사건/알림 유실 | DB에 수신 기록 후 ACK, 기존 worker와 새 알림 발송 큐 연결 |
| DPAPI, 여러 token 역할 | Linux에서 기존 암호 파일을 읽지 못하고 단일 token 슬롯으로 역할을 표현 못함 | 역할별 비밀 참조와 원 Windows 환경에서의 명시 이행 |
| 별도 UI, 평문 capture, clear | 권한 우회, 원문 보관, 과거 증거 삭제 위험 | 기존 인증, 화면, 감사에 통합하고 개발 도구는 분리 |
| own-token 목록과 외부 Vault | CreMore의 연결용 보관을 기업 Vault 관리로 오인 | 소유 토큰, 외부 금고, 노출, 검증을 각각 표시 |

Git 파일 충돌은 **5개**입니다: `.env.example`, `.gitignore`, `LICENSE`, `README.md`, `requirements.txt`. 특히 **develop Apache-2.0 / Slack GPLv3**의 배포 권한, 고지는 팀의 라이선스 결정이 필요합니다.

### 공식 문서를 반영한 보완점

- 조직 전체 token으로 `conversations.list`를 호출할 때 필요한 `team_id`가 현재 호출에 없습니다. Enterprise 연결과 수집 workspace를 구분해야 합니다.
- history/replies 제한은 앱 배포 유형에 따라 다릅니다. 모든 연결에 같은 속도, 페이지 수를 가정하지 않습니다.
- 승인 앱 조회의 `certified` 기본 필터 때문에 기본 응답을 전체 승인 앱으로 단정하지 않습니다. 감사 수집은 별도 Enterprise Owner User token, 권한, 조직 설치 조건을 확인합니다.
- Azure의 `updated_on`은 수정 시각입니다. 기존 `updated_at`을 유지하고, 근거 없는 `last_rotated_at` 매핑은 제거해 미확인으로 둡니다. 태그에서 받은 회전 설정은 사용자 선언으로 표시합니다.

[공식 근거 SL1–SL6](integration/official-docs.md#slack과-외부-vault)

### 구현 담당자가 할 일

1. ~~`socket_mode.py`의 이력/스레드 순회와 `detector.py`의 규칙 차이를 기존 Collector/Engine에 연결합니다.~~ **철회(2026-09-22 결정)**. 한 번 구현해 commit했다가 전부 되돌렸습니다. 아래 'Slack 제외' 참조.
2. ~~실시간 수신, 편집, 재시도, 알림~~ **제외(2026-09-22 결정)**.
3. ~~앱, 감사, 소유 토큰의 관측 사실을 관리정보 모델에 넣습니다.~~ **제외(2026-09-22 결정)**.
4. ~~AWS/GCP/Vault는 기존 어댑터에 합치고 Azure metadata를 추가합니다.~~ **Azure 완료(2026-09-21)**. `cremore/coverage/providers/azure_key_vault/`. AWS/GCP/Vault는 기존 어댑터가 이미 담당합니다.

### Slack 제외 (2026-09-22 결정)

**Slack은 이 통합에서 전부 빠집니다.** 7b·7c는 착수하지 않았고, 한 번 구현했던 7a는 되돌렸습니다.

- 7b는 기존 develop에 없는 저장소를 새로 만들어야 합니다: 암호화 수신 inbox, dedupe·claim/lease·재시도를 갖춘 영속 outbox. 기존 어느 공급자와도 형태가 다릅니다.
- 배포 권한·라이선스 결정(GPLv3 ↔ Apache-2.0)이 아직 팀 결정으로 남아 있습니다. 지금 배포물에는 Slack 브랜치에서 온 코드가 없으므로 그 결정이 배포를 막지는 않습니다.

되돌린 것과 남긴 것, 그리고 다시 구현할 때 필요한 판단은 [통합 현황](integration/INTEGRATION_STATUS.md) §5.1에 있습니다. 세 commit(`38faa31`, `e80750d`, `1d9ba76`)을 revert하면 되살아납니다.

Slack과 무관한 탐지 두 가지는 남겼습니다. `refresh_token`·`app/bot/user_token` 이름의 일반 대입 탐지와 RFC 6750 bearer 자격증명 탐지이며, 특정 공급자의 형식이 아니므로 함께 지우면 Slack과 상관없는 탐지 범위가 줄어듭니다. 통합 이전부터 제품에 있던 `slack-token-v1`·`slack-webhook-v1` 탐지기도 그대로입니다 — 통합 작업을 되돌리는 것과 제품 기능을 지우는 것은 다릅니다.

코드 근거: [Slack 전체 분석](integration/slack.md), `S:app/socket_mode.py:118`, `S:app/repository.py:17`, `S:app/token_lifecycle.py:267`, `S:app/cloud_secrets_inventory.py:167`.

## 7. 공통 구현 순서

### 먼저 데이터의 의미를 맞춥니다

| 저장할 자료 | 예시 | 화면에서 답하는 질문 |
|---|---|---|
| 콘텐츠 노출 | S3 파일, GitHub 코드, Slack 메시지 | 어디에 노출됐는가? |
| 공급자 관리 목록 | PAT ID, 서비스 계정 키 ID | 공급자가 어떤 자격증명을 알고 있는가? |
| Vault 관찰 | 특정 금고, 버전의 값 지문 | 선언한 금고에 같은 값이 있는가? |
| 사용, 상태 근거 | 감사 사건, 공급자 상태, 실제 검증 기록 | 언제 무엇을 확인했는가? |

기존 `Credential–Exposure–Finding`은 콘텐츠 노출에 계속 사용합니다. 새 관리 목록을 가짜 노출로 만들지 않습니다. 기존 coverage 저장/작업 체계를 확장하되, 공급자 객체와 상세 관찰, 관계를 담을 테이블2개를 **새로 제안**합니다. 상세 필드, 호환 API는 [구현 계약 §4–6](integration/implementation-contract.md)에 있습니다.

특히 현재 backend와 UI의 **‘AWS IAM/CloudTrail이 아니면 Vault’** 분류를 먼저 고칩니다. 그렇지 않으면 새 GitHub, GitLab 관리 목록이 금고로 집계됩니다.

### 담당별 작업 묶음

| 순서 | 구현할 것, 주요 위치 | 다음 단계로 넘어갈 조건 |
|---|---|---|
| 0 | 고정 SHA, 기능 인수표, Slack 권리/라이선스 정리 | 출처와 보존할 기능 확인, develop 변경 없음 |
| 1 | `coverage/models.py`, `correlation.py`, store/DB: 공급자 목적, 관리 객체, 관찰, 관계, 작업 보고서 | 기존 v1 입력 재생 성공, 새 정보 DB/API 왕복, 오분류 없음 |
| 2 | `domain/connections.py`, `secretstore/resolver.py`, worker: 목적별 범위, 인증, 실행 연결 | 허용 범위 밖 요청 차단, 중단, 재개, 동시 worker 검증 |
| 3 | GitLab 수집을 첫 관리정보 경로로 연결 | 10종류, 출처, 부분 실패, 화면 상세 확인 |
| 4 | GCP 기존 Vault 확장과 관리 목록, 관계 연결 | global/regional/version, 현재성, 평문 비저장 확인 |
| 5 | Atlassian/Bitbucket 연결 | 인증 종류,43개 연산, Runner, count/detail 확인 |
| 6 | GitHub 조직+Enterprise 연결 | 양쪽 전용 기능, 감사 페이지, host, context 보존 |
| 7 | Slack 콘텐츠(철회) → 실시간/알림(제외) → 관리정보/소유 토큰(제외) → Azure(완료) | 각 단계의 수집, 재시작, 권한, 이력 연속성 확인 |
| 8 | 대시보드, 설치 산출물, DB 이행, 로컬/EC2/EKS 검증 | 아래 완료 조건 통과 |

공급자 모듈은 기존 `cremore/coverage/` 아래에 둡니다. 공급자별 cursor, 필드, 권한이 다르므로 하나의 공통 HTTP 알고리즘에 억지로 맞추지 않습니다. 공통으로 사용하는 것은 작업 실행, 인증 참조, 저장, 권한, 대시보드입니다.

**팀원 우선 원칙의 적용:** 기능이나 상세 정보가 겹치면 팀원 범위를 인수합니다. 기존 제품의 데이터 의미가 달라 바로 넣을 수 없으면 저장 모델을 확장합니다. 원문 파일 보관, 독립 프로세스, 잘못된 상태 해석까지 그대로 가져오는 대신 같은 기능을 제품 구조에서 보존합니다. 어떤 기능을 유보하면 이유와 완료 조건을 인수표에 남깁니다.

## 8. 대시보드와 운영의 최종 모습

**UI 변경도 통합의 필수 작업입니다. 기존 develop의 화면 구성과 디자인을 유지하면서, 팀원이 추가한 정보를 볼 수 있도록 목록, 상세, 연결 설정을 확장합니다.** 아래 내용은 구현할 설계이며 현재 화면이 이미 바뀌었다는 뜻은 아닙니다.

### 유지할 화면과 표현

기존 사이드바, 상단 검색, 밝은/어두운 테마, 한국어/영어, 시간 표시, 버튼, 표, 배지, 접기와 상세 패널을 재사용합니다. 기존 AWS, GitHub, Notion 등의 연결과 탐지 화면도 유지합니다. 공급자마다 별도 웹 앱이나 서로 다른 디자인의 대시보드를 추가하지 않습니다.

현재 코드를 그대로 두고 공급자 이름만 추가하는 것으로는 충분하지 않습니다. `secret-inventory.tsx`는 AWS 계정, 리전, ARN을 검사하고 AWS 경로를 호출합니다. `credential-coverage.tsx`의 금고 필터도 AWS IAM/CloudTrail 외 항목을 금고로 분류합니다. 새 공급자는 정확한 응답 모델과 수집 목적에 맞춰 연결해야 합니다.

화면의 소스 허용 목록에는 Slack이 없어서 연결, 작업, 카탈로그가 걸러집니다. 기존 프록시도 API v1로 고정돼 있으므로 새 v2 관리 목록까지 연결하는 변경이 필요합니다. 메뉴와 로고만 추가해서 완료로 처리하지 않습니다.

### 화면별 변경안

| 기존 화면 | 유지할 부분 | 통합하면서 바꿀 부분 |
|---|---|---|
| 개요 | 노출 위험과 우선 대응 중심의 요약 | 관리 목록 수와 노출 수를 분리. 수집 실패와 오래된 근거를 별도 표시하며 공개키, 정책, 계정을 노출 건수에 더하지 않음 |
| 계정/공급자, 연결된 소스 | 현재 연결 등록, 점검, 범위 설정, 사용 중단 흐름 | 행에 공급자, 설치 형태, 수집 목적, 최근 상태 표시. 콘텐츠/관리 목록/Vault/감사를 구분하고 목적별 인증과 권한을 상세에서 확인 |
| AWS 자격증명 인벤토리 | AWS의 계정별 목록과 상세 근거 | 하나의 ‘공급자 관리 목록’으로 확장하고 공급자 및 객체 종류 필터 추가. 기존 AWS 진입 링크는 AWS가 선택된 상태로 호환 유지 |
| Vault / Secret Manager | 금고 보관 대조, 메타데이터, 교체 관리 | 금고 제품별 어댑터 결과 표시. 일반 PAT 관리 목록을 금고로 분류하지 않으며 Azure metadata와 실제 값 일치 지원도 구분 |
| 탐지 결과와 상세 | 위험, 노출 위치, 저장된 검증 이력을 먼저 보여주는 흐름 | 상세에 관리 목록, 금고, 사용 기록의 연결 근거 추가. 목록 행에는 요약만 표시하고 긴 권한 목록과 이력은 상세에서 조회 |
| 스캔과 작업이력 | 기존 실행, 중지, 진행 상태 | 콘텐츠 스캔과 관리정보 수집을 구분. 작업을 열면 요청 범위, 성공/실패 항목, 읽지 못한 이유, 마지막 성공, 재개 상태를 표시 |
| 감사 로그 | 기존 작업명, 수행자, 대상, 상세 보기 | CreMore 사용자의 행동과 공급자에서 읽은 사건을 구분. 숨긴 연결의 과거 이력을 유지하고 관련 작업/관리 객체로 이동 가능하게 함 |

공급자 로고는 기존 `CloudServiceIcon`과 공식 이미지 매핑을 재사용합니다. Slack과 Azure 등 새 항목에 필요한 로고만 추가합니다. 콘텐츠 공급자 목록에 Azure를 넣었다는 이유로 Azure 콘텐츠 수집이 지원되는 것으로 표시해서는 안 됩니다.

### 항목이 많아져도 읽을 수 있는 구조

기본 목록은 **이름/식별자, 공급자와 범위, 핵심 상태, 마지막 성공 시각**을 가진 짧은 행으로 구성합니다. 설명문, 전체 권한, 원본 필드, 긴 경로와 이력은 기본적으로 접고 선택한 항목의 상세에서 보여줍니다. 기존 보관 대조의 페이지당 50개 방식처럼 새 관리 목록도 서버에서 필요한 페이지를 조회합니다. 브라우저에서 첫 수백 개만 잘라 전체 결과처럼 표시하지 않습니다.

검색, 공급자/종류/상태 필터, 선택한 항목, 페이지 위치는 상세를 닫거나 갱신해도 유지합니다. 전체 건수와 현재 필터 결과 건수는 구분합니다. 연결 사용 중단 항목은 기존 정책대로 일반 목록에서 숨기고 감사 이력에 남깁니다. 긴 이름, 여러 배지, 좁은 화면에서도 버튼과 상태가 겹치지 않게 합니다.

### 서로 다른 상태를 하나의 배지로 합치지 않기

| 표시할 상태 | 예시 | 의미 |
|---|---|---|
| 연결 인증 | 수집 인증 만료 | CreMore가 현재 공급자를 읽을 수 있는지 |
| 수집 결과 | 일부 범위 수집 실패 | 요청한 항목을 어디까지 읽었는지 |
| 공급자 기록 | 공급자가 active로 보고 | 관리 API가 기록한 상태이며 실제 인증 검증과 다름 |
| 유효성 검증 | 마지막 검증 시점에 활성 | 저장된 검증 결과와 확인 시각. 위험 점수도 같은 근거 사용 |
| 금고 보관 | 값 일치 / 선언 범위에서 미일치 / 판단 불가 | 명시한 금고와 대조한 결과이며 발급 목록의 존재와 다름 |

예를 들어 GitLab이 토큰을 active로 보고했지만 검증하지 않았다면 **‘공급자 상태: active’, ‘유효성: 미검증’**으로 표시합니다. Vault 조회가 실패했다면 **‘보관 여부: 판단 불가’**이며 미관리로 확정하지 않습니다.

수집 연결이 만료돼도 이전 검증과 마지막 성공 근거를 초기화하지 않습니다. 대시보드 로그인 만료나 권한 철회 때에는 보호된 화면 데이터를 비우고 재인증하도록 하되, 서버의 이력을 삭제하지 않습니다. 재로그인 후 현재 권한으로 같은 저장 이력을 다시 조회합니다.

### 구현 순서와 화면 완료 조건

1. 기존 화면 구성과 URL을 기준으로 공급자 목적, 목록 종류, 상태의 응답 타입을 연결합니다. API 계약과 보호 프록시의 v2 coverage 경로를 함께 구현하고 공급자별 정상/부분 실패 자료로 화면을 확인합니다.
2. ~~기존 연결 설정에 **설치 형태 → 수집 목적 → 대상 범위 → 인증 역할 → 기능별 권한 확인 → 첫 수집**을 반영합니다.~~ **완료(2026-09-21)**. 7단계 요약과 근거 체크포인트는 화면에만 있고 서버가 없었으므로, `onboarding` 근거·체크포인트 저장·읽기 전용 신원 점검을 구현했습니다. 근거는 이미 저장된 것(선언·자격증명 점검·카탈로그·승인 범위·체크포인트)에서만 읽으며 화면을 여는 것으로는 아무것도 기록되지 않습니다. 관리정보 전용 연결은 자기 경로(`/api/v2/coverage/connections/{id}/setup`)로 같은 요약을 받고, 콘텐츠 세 단계가 **해당 없음**으로 나가므로 콘텐츠 스캔이 강제되지 않습니다. 서버에서 계속 진행하는 4단계 조사는 만들지 않았고, 화면이 그 조작을 제공하지 않습니다.
3. 기존 AWS 목록을 확장한 관리 목록과 상세를 연결하고, 탐지 상세 및 금고 대조에서 같은 객체로 이동할 수 있게 합니다. `github-org`의 기존 콘텐츠 작업 의미와 맞지 않는 설명도 수정합니다.
4. 작업 상세, 공급자 감사, 전역 검색을 연결합니다. 검색의 객체 종류와 권한 판정도 API와 함께 확장합니다. 화면을 열었다는 이유로 수집, 교체, 폐기 요청이 실행되지 않게 합니다.
5. 기존 UI 테스트에 새 공급자, 많은 항목, 긴 이름, 빈 결과/조회 실패/권한 부족, 좁은 화면, 키보드, 테마와 언어 전환을 추가합니다. 배지와 위험 점수의 일치, 로그인 전후 이력 연속성, 기존 AWS 연결과 URL 호환이 통과해야 화면 통합 완료입니다.

현재 Vault 설정 화면의 Admin 제한을 전체 해제하지 않습니다. 목록 조회, 재수집, 연결 설정, 외부 조치를 각각 기존 서버 역할 계약에 맞게 제공하고 UI의 불일치도 맞춥니다. 모든 공급자의 목록을 전역 갱신 때 한꺼번에 가져오지 않으며, AWS 조회 실패가 다른 공급자 목록까지 막지 않게 합니다. 구현 파일과 상세 인수 조건은 [구현 계약 §6](integration/implementation-contract.md#6-api-대시보드-온보딩)에 있습니다.

코드 근거: `DEV:web/app/page.tsx:4980`, `DEV:web/features/secrets/secret-inventory.tsx:30`, `DEV:web/features/secrets/secret-manager-workspace.tsx:21`, `DEV:web/features/credentials/credential-coverage.tsx:147`, `DEV:web/app/ui-primitives.tsx:172`, `DEV:web/app/connection-ui.tsx:60`.

### 운영 환경

로컬 Docker, EC2, EKS의 기존 배포 구성을 재사용합니다. 파일 잠금/SQLite/DPAPI만으로 여러 서버 운영을 지원한다고 판단하지 않습니다. 실제 worker 경쟁, 재시작, 비밀 참조, OIDC, DB 복구를 확인해야 합니다.

## 9. 완료 판정과 아직 남은 결정

**이미 확인한 것:** 팀원 원본 오프라인 테스트 500회 통과(중복 제외 491개), 전체 팀원 코드 판독, 합성 탐지 비교, Git 충돌, 공식 문서 대조입니다. 통합 제품 전체 테스트가 통과했다는 뜻은 아닙니다. [검증 기록](integration/verification.md)

통합 완료는 다음 조건을 모두 만족한 뒤 선언합니다.

1. 브랜치별 기능 인수표에 누락이 없고, 기존 콘텐츠, Vault, 검증 이력이 유지됩니다.
2. 부분 실패, 권한 만료, 오래된 자료를 ‘없음’, ‘폐기’, ‘미관리’로 확정하지 않습니다.
3. 비밀 원문이 작업 설정, 일반 DB, 로그, API, export에 섞이지 않고, 객체별 권한과 수집 범위를 검사합니다.
4. DB 변경은 추가 방식으로 시작하며 원본 자료를 보존합니다. 중간 실패, 재실행, 구버전 복귀를 시험합니다.
5. 최종 wheel/이미지, 의존성 lock, Python3.12/3.14, PostgreSQL, 화면, 로컬/EC2/EKS를 실제 검사합니다.
6. 공식 문서가 상충하거나 버전별 계약이 남은 항목은 승인된 시험 계정으로 확인한 뒤 지원으로 표시합니다.

남은 팀 결정은 Slack 배포 권한, 라이선스, 실제 옛 SQLite/JSON 자료의 이행 여부, 기업별 설치 버전, 허용 범위, 보존기간과 외부 조치 정책입니다. 문서로 확인되지 않은 기능을 구현 완료로 약속하지 않습니다.

### 2026-09-21 기준 진행

1~6단계와 8단계, 7단계의 d(Azure Key Vault)는 구현했고 `develop_total`에 commit·push했습니다. 7a는 구현했다가 되돌렸고 7b·7c는 착수하지 않았습니다 — 위 'Slack 제외' 참조. 무엇을 구현했고 무엇이 남았는지는 [통합 현황](integration/INTEGRATION_STATUS.md)에 단계별로 있습니다.

위 완료 조건 1~4는 구현 범위 안에서 만족합니다. 5·6은 **아직 아닙니다**: 모든 검사는 합성 transport이고, 실제 공급자 계정·PostgreSQL·배포 검증은 수행하지 않았습니다.

`develop`에는 변경하지 않았습니다.
