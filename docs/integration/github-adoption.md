# GitHub 수용 기록

기준일: 2026-09-21. 대상은 `publish/develop_github`의 `bfb97fb1f6147439904045824fa1a756c2768655`다. [기존 설계안 §4](../INTEGRATION_DESIGN_REVISED.md#4-github), [기존 GitHub 분석](github.md), [공통 구현 계약](implementation-contract.md)은 설계 시점의 기록으로 유지한다.

## 두 프로그램을 모두 수용했다

원본에는 루트 조직 수집기(`cremore_collectors/`)와 하위 Enterprise 수집기(`github-api-collector/`)가 있고, `collectors/` 8개 모듈과 `registry.py`는 **두 프로그램에서 동일 blob**이었다. 통합 패키지는 [cremore/coverage/providers/github](../../cremore/coverage/providers/github/) 하나이며, 조직 전용 기능과 Enterprise 전용 기능을 모두 갖는다.

| 원본 | 수용 위치와 처리 |
|---|---|
| `collectors/classic_pat.py`, `oauth_app_token.py`, `github_app_user_token.py`, `user_ssh_key.py`, `fine_grained_pat.py`, `deploy_key.py`, `github_app_installation_token.py`, `github_token.py` (동일 blob 8쌍) | `projection.py`: 각 수집기의 필드 목록, 소유자/저장소 scope 검사, 공개키 지문 계산, 정책 schema, run/job 대조를 그대로 유지했다. `fetch_*`의 urllib 전송과 CLI는 제거했다. 전송은 공통 worker의 책임이다. |
| `collectors/_http.py`, `validation.py`의 `next_path`/`first_path` | `endpoints.py`: 읽기 endpoint 허용 목록과 “cursor만 바뀔 수 있다”는 페이지 이동 규칙을 유지하고, **연결의 API base를 인자로 받아** GHES와 ghe.com 링크도 각자의 host에서만 허용한다. |
| `gateway.py`의 `validate_operation`, `GitHubGateway` | `endpoints.validate_operation`과 `http.Transport`: 고정 enterprise 대신 연결의 enterprise를 받는다. 전송은 `requests` 세션 대신 제품의 `bounded_request`와 `github_hosts.api_base`를 쓴다. 쓰기는 installation token 발급 POST 하나뿐이다. |
| `gateway.app_jwt`, `json_pipeline.token_for` | `http.TokenBroker`: 기존 `GitHubAppTokenSource`가 token 발급·검증·캐시를 맡고, broker는 `/enterprises/:slug/installation`과 `/orgs/:org/installation` 발견과 app_id/대상/정지 검사만 한다. JWT는 `github_auth.app_assertion`으로 같은 키 처리와 같은 claim 창을 쓴다. |
| `supplemental.py` | `pages.py`: 조직별 8개 source seeding, 후속 task 생성, 각 kind의 응답 투영을 그대로 유지했다. 여기에 루트 프로그램의 Actions run/job을 `repo_actions_runs`·`run_jobs` task로 추가했다. |
| `validation.py`의 inventory/audit 검사, `_inventory_headers` | `endpoints.py`: Enterprise credentials 레코드의 필수 상태 값, 감사 레코드의 business/org 일치, `x-github-enterprise-credentials-*` 완전성 헤더 해석을 유지했다. |
| `json_evidence.py`의 필드 허용 목록 | `projection.INVENTORY_FIELDS`, `AUDIT_FIELDS`, `SECRET_KEYS`, `CREDENTIAL_ACTION`: 저장 대상 필드와 자격증명 관련 감사 action 판정을 유지했다. |
| `json_pipeline.collect_enterprise` | `adapter.py`: task graph, 우선순위, 페이지 단위 진행, 재개를 공통 lease/checkpoint 위에서 수행한다. 파일 checkpoint, `state_lock`, page 파일은 만들지 않는다. |
| `json_store.py`, `json_export.py`, `credential_dashboard/` (SQLite) | `snapshot.py`: 두 프로그램의 JSON 관점을 commit된 record에서 재구성한다. 별도 SQLite와 별도 대시보드는 만들지 않는다. |
| `service.py`, `coordinator.py`, `runner.py`, `transport.py`, `cli.py`, `create_service_key.py`, `compose.collectors.yaml` | 별도 서비스 5개를 기본 운영 구성에 추가하지 않는다는 설계 결정에 따라 제품 진입점으로 대체했다. `contracts.validate_job`의 옵션 경계는 `MetadataOptions`와 `validate_spec`에 대응시켰다. |

## 연결 계약

| 항목 | 값 |
|---|---|
| provider / 인증 | `github` / `github_app`. secret role은 `app_id`, `private_key`, 선택 `installation_id` |
| origin과 edition | `https://github.com`+`cloud`/`enterprise_cloud`, `https://<host>`+`enterprise_server`, `https://<name>.ghe.com`+`dedicated`. edition과 host가 어긋나면 거절한다 |
| mode | `organization`(scope는 organization 1개 이상) 또는 `enterprise`(scope는 enterprise 정확히 1개) |
| capability | `inventory`(필수), `audit`, `relations`, `policy`, `public_keys` |
| source 선택 | `options.sources`로 조직 source를 좁힐 수 있다. 빈 값은 전체다 |
| 감사 | `options.include_audit_events`와 `audit` capability가 함께 필요하다. 창은 `audit_lookback_days`(기본 180)와 `audit_created_after`로 정한다 |
| Actions | `options.include_actions`가 켜진 경우에만 run/job을 읽는다 |

`principal_pin`은 거절한다. App 설치 주체를 실행 중 다시 검증하지 않으므로 검증하지 않은 고정을 검증으로 표시하지 않는다.

## 공식 문서에 따라 유지한 제한

- [SAML SSO credential authorizations](https://docs.github.com/rest/orgs/orgs#list-saml-sso-authorizations-for-an-organization): 조직 SSO 승인 목록은 **직원이 가진 모든 토큰의 목록이 아니다.** SSO를 쓰지 않는 조직에는 이 source가 없다.
- [Fine-grained PAT](https://docs.github.com/rest/orgs/personal-access-tokens): 조직 승인 목록과 요청 목록은 다르다. 요청은 `request` 종류로 두고 발급된 자격증명으로 집계하지 않는다.
- [App installations](https://docs.github.com/rest/apps/apps): 설치는 자격증명이 아니라 `installation` 종류다. 응답의 `token`, `temp_clone_token`은 저장하지 않으며 저장소 permission flag를 토큰 scope로 승격하지 않는다.
- [Deploy keys](https://docs.github.com/rest/deploy-keys/deploy-keys), [SSH 인증 키](https://docs.github.com/rest/users/keys): 둘 다 공개키다. `public_key` 종류로 두고 노출 건수에 더하지 않는다. 지문은 디코딩한 wire format에서 계산하며 값 지문과 구분한다.
- [Enterprise credentials](https://docs.github.com/rest/enterprise-admin): 응답에 `total_count`가 없다. 따라서 총수 검사는 `installations`, `repositories`, Actions `runs`/`jobs`처럼 `total_count`를 주는 응답에만 적용하며 모든 operation report의 `proves_completeness`는 false다. 완전성 헤더는 경고로 남는다.
- [Enterprise 설치 토큰](https://docs.github.com/rest/apps/apps#create-an-installation-access-token-for-an-app): Enterprise 설치 토큰에는 저장소 접근 권한이 없다. 따라서 조직·저장소 endpoint는 조직 설치 토큰으로 따로 인증하며, 설치가 없는 조직은 `organization_installation_github_http_404`로 한 번만 기록하고 재시도하지 않는다.
- [Audit log](https://docs.github.com/rest/orgs/orgs#get-the-audit-log-for-an-organization): Enterprise 감사가 완주하면 조직 감사는 `covered_by_enterprise`로 두고 **각 조직마다 그 이유를 담은 report를 남긴다.** 자격증명과 무관한 action은 이벤트로 저장하지 않는다.
- [GitHub Enterprise Cloud with data residency](https://docs.github.com/enterprise-cloud@latest/admin/data-residency): `ghe.com`은 `https://api.<subdomain>.ghe.com`을 쓴다. 원본은 `api.github.com` 고정이었고, 여기서는 기존 `github_hosts`가 판정한다.

GHES 버전별 관리 endpoint 지원 여부는 승인된 시험 서버에서 확인해야 한다. 404 하나로 API 부재를 단정하지 않으며, 실패한 source는 그 이유가 붙은 FAILED report로 남는다.

## 실행과 재개

Enterprise mode의 seed는 `inventory → organizations → (audit)`이고, 조직이 발견되면 조직별 source와 조직 감사가 우선순위대로 추가된다. Organization mode는 연결이 지정한 조직들의 source를 직접 seed한다. 모든 후속 task는 그 페이지 하나에서만 만들어진다.

한 페이지는 트랜잭션 밖에서 읽고, 그 페이지의 record와 task 상태를 worker가 함께 commit한다. 완료한 task는 재개할 때 다시 읽지 않으며, 중단한 목록은 저장된 cursor에서 이어진다. 429와 공급자 장애는 부분 결과가 아니라 `WAITING` 페이지와 재시도 시각으로 남기고, 401·응답 한도는 실행을 멈춘 뒤 PARTIAL로 마무리한다. 403/404는 해당 source만 FAILED가 된다. 요청 예산은 재시작을 가로질러 합산하며 task 수에도 상한이 있다.

## 검증

```text
python -m pytest cremore/coverage/providers/github -q
python -m ruff check cremore/coverage/providers/github
```

2026-09-21 Windows Python 3.12 기준 **61개 통과, skip 0**. 합성 transport와 합성 broker만 사용했고 실제 GitHub App, 조직, Enterprise는 사용하지 않았다.

회귀 범위: 문서화된 읽기 경로 전체와 목록 밖 경로·쓰기·traversal 거절, enterprise 경로의 연결 enterprise 대조, cursor만 바뀌는 페이지 이동과 host·scope 변경 거절, GHES 링크 허용, 모호한 next 링크, Enterprise inventory 레코드 상태 값과 감사 scope 검사, 완전성 헤더, 필드의 없음/null 구분, 저장소·설치 scope 불일치, permission level·events 형식, 공개키 지문과 실패 이유, 정책 schema, run/job scope 대조, source별 task 위조 거절, 공개 저장소의 fork 정책 제외, 조직/Enterprise 두 mode, 여러 조직의 scope 분리, Actions run/job 선택 수집, 감사 이벤트의 자격증명 action 선별과 조직 감사 대체 보고, 설치 없는 조직의 1회 기록, 중단 후 재개의 레코드 동일성과 요청 합계, 완료 run의 재요청 없음, 변경된 연결의 checkpoint 거절, 취소, 429 대기, 401 중단, 레코드 예산, native JSON 관점 재구성이다.

실제 기업 GitHub 조직·Enterprise 권한, GHES 버전, ghe.com tenant, 대시보드 연결은 이 패키지 검증과 구분해서 확인해야 한다.
