# 두 보안 CSV의 현재 코드 대조 — 2026-10-06

기준: `integration/saas-structure`, HEAD `1fbe966108470d7188a54246cb25649e3cb7043a`. 이 문서는 공급받은 CSV의 86개 행만 대조한 결과이며, 저장소 전체의 새로운 취약점 탐색 또는 취약점 부재 보증이 아니다.

정적 검토에서 현재 지원 경로에 남은 수정 대상은 확인되지 않았다. 86개 원본 행의 Finding ID는 모두 다르지만 같은 보안 통제 실패를 60개 원인 그룹으로 묶었다. 원본 행을 삭제하지 않고 아래 원인 그룹에 연결했다. 일반화된 위험 이름만 같고 source/control이 다르면 별도 그룹으로 남겼다. D02처럼 복합 주장은 주된 원인 하나에 집계하고 관련 통제를 본문에서 교차 참조했다.

| 집계 기준 | fixed | not applicable | still present | unverified | 합계 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 원본 행 | 82 | 4 | 0 | 0 | 86 |
| 중복 제거한 원인 그룹 | 57 | 3 | 0 | 0 | 60 |

`fixed`는 현재 코드가 신고된 실패 경로를 차단한다는 뜻이다. 기존 설치의 과거 원문·WAL·백업이 정리됐거나 실계정에서 검증됐다는 뜻이 아니다. `not applicable`은 삭제된 실행 경로나 명시적으로 지원하지 않는 이전 계약으로 한정된다. `unverified=0`은 코드 대조의 미분류 행이 없다는 뜻이며 실제 배포·공급자 권한·PostgreSQL·외부 CI까지 검증했다는 뜻이 아니다.

## 입력과 범위

| 접두어 | 원본 파일 | 데이터 행 | SHA-256 |
| --- | --- | ---: | --- |
| D | `C:/Users/admin/Downloads/security-findings.csv` | 36 | `10f6ab8aef013122af2f36b0ab0a20288468b3aee2d23118858f07b6814d0e3b` |
| K | `C:/Users/admin/Documents/카카오톡 받은 파일/security-findings.csv` | 50 | `65672e66ad8e88878dc7b4e617dd18ec48097473f1f9c9c9211624d0c6411a18` |

D/K 번호는 CSV header를 제외한 1-based 데이터 행 번호다. 원본 severity와 Finding ID를 그대로 보존했다. CSV의 `new` 상태는 당시 export 상태이며 현재 코드 판정과 구별한다.

정책 근거는 루트 [SECURITY.md](../SECURITY.md), [AGENTS.md](../AGENTS.md), [팀 코딩 지침](AI_TEAM_CODING_GUIDE.md)이다. `rg --files -g SECURITY.md`에서 루트 정책만 확인했고 보안 지침 resolver도 이 정책을 반환했다. 따라서 아래 모든 현재 경로에 같은 정책이 적용된다. 원문·외부 응답·metadata·source 선택·OIDC 미검증 입력을 비신뢰 입력으로 취급하며, 서버 역할/승인 경계·값 원문 비보관·bounded 처리·근거의 신선도/완전성을 검토했다.

예전 `cep/`는 현재 `cremore/` 및 공급자 소유 모듈로, `cremore/coverage/providers/<vendor>/`는 `<vendor>/backend/`로 추적했다. 삭제된 `web/app` 화면은 현재 `web/console`의 동등 소비자를 대조했다. CSV의 `github/workflows/*`는 실제 `.github/workflows/*`를 확인했다. `gcp-connector`의 독립 CLI 삭제와 제품 라이브러리의 이동을 혼동하지 않았다.

입력에는 이미 수행한 재현 설명이 있으나 이 검토에서 공격 payload·실계정 자격증명·운영 DB·외부 공급자 호출은 사용하지 않았다. 기존 합성 fake-client 회귀만 다시 실행했다. 코드 수정은 이 보고서의 담당 범위에 없었고 검토 중 새 패치 필요성은 확인되지 않았다.

## 먼저 구별할 운영 제한

- **K45 / G56:** 환경으로 넣은 passphrase는 Docker metadata에 남을 수 있다. 현재 문서와 API의 `held_here`가 이를 설명하는 상태다. ephemeral unlock이나 off-disk 보장은 구현되지 않았다. 이 항목의 `not applicable`은 옛 diskless 보장을 현재 보장으로 보지 않는다는 의미이며 환경 보관이 없어졌다는 뜻이 아니다.
- **K48 / G59:** CEP 사전 배포 DB의 연속 업그레이드는 지원하지 않는다. 그 DB를 현재 코드로 바로 재스캔하면 지문/노출 이력이 분리될 수 있다. 그런 설치가 실제 있다면 writer를 멈추고 원본 DB/감사 이력을 보존한 별도 이관 검토가 남는다.
- **과거 민감자료:** sanitizer 수정과 public projection 제한은 과거 DB·백업에서 이미 남은 원문을 소급 삭제하지 않는다. 실제 설치의 이력 점검/보존/정리 절차는 별도 운영 작업이다.
- **release:** release workflow와 생성기 통과 조건을 검토했지만 이번 검토는 원격 release, registry digest 서명 검증, live deployment를 실행하지 않았다.

## 원인 그룹별 근거

모든 `fixed` 그룹의 정적 confidence는 높음이다. 아래 source→control 설명과 실제 현재 symbol/회귀를 근거로 삼았다. `not applicable`의 잔여 제한은 각 항목에 명시했다. 인용한 커밋 26개는 모두 기준 HEAD의 ancestor임을 검사했다. 테스트 실행 묶음 A–G는 뒤의 명령/결과와 연결되며 S는 정적 증거다.

### G01 — 인접 토큰 경계 재사용

- 원본: D01 D10 D14 K07 K11; 판정: **fixed**.
- 근거: 스캔 원문의 공유 구분자를 첫 매치가 소비해도 secret group 끝에서 검색을 재개한다. 같은 후보 집합을 탐지·redaction에 사용하여 다음 토큰이 공개 evidence로 빠져나가지 않는다.
- 현재 코드: [cremore/detection/regex.py::Pattern.finditer](../cremore/detection/regex.py); [cremore/detection/engine.py::Engine._candidate_matches](../cremore/detection/engine.py).
- 수정/경계 커밋: `129d7224`.
- 회귀: [cremore/detection/sanitization_test.py::test_adjacent_synthetic_values_are_both_detected_and_masked](../cremore/detection/sanitization_test.py). 실행 묶음: A.

### G02 — 후보·매치 할당 상한

- 원본: D02; 판정: **fixed**.
- 근거: 후보 생성 중 count=10,000, 누적 material=1 MiB, 개별 match=64 KiB를 먼저 차감한다. 한도에 도달하면 incomplete이고 검사가 끝나지 않은 원문 문맥을 반환하지 않는다. 같은 행의 중복 문맥은 G04의 별도 상한도 적용한다.
- 현재 코드: [cremore/detection/engine.py::_CandidateBudget.consume](../cremore/detection/engine.py); [cremore/detection/engine.py::Engine.scan](../cremore/detection/engine.py).
- 수정/경계 커밋: `129d7224`.
- 회귀: [cremore/detection/sanitization_test.py::test_candidate_budgets_leave_an_incomplete_result_without_unchecked_context](../cremore/detection/sanitization_test.py). 실행 묶음: A.

### G03 — 여러 줄 redaction 계산량

- 원본: D03; 판정: **fixed**.
- 근거: 매치가 지나는 모든 물리적 줄을 생성하지 않고 후보 시작 위치만 정렬한다. 줄 번호를 previous→start 구간에서 증가시키므로 같은 입력 prefix를 후보마다 다시 세지 않는다.
- 현재 코드: [cremore/detection/engine.py::Engine._redacted_lines](../cremore/detection/engine.py).
- 수정/경계 커밋: `129d7224`.
- 회귀: [cremore/detection/sanitization_test.py::test_multiline_masking_counts_each_prefix_byte_at_most_once](../cremore/detection/sanitization_test.py). 실행 묶음: A.

### G04 — 문맥 길이·저장 증폭

- 원본: D34 K01; 판정: **fixed**.
- 근거: 노출당 문맥 window를 기본 1 KiB로 제한한다. 매치 수와 material 상한도 적용되어 물리적 긴 줄을 노출마다 통째로 저장하지 않는다. 구형 저장 원문 삭제는 이 코드 수정의 범위가 아니다.
- 현재 코드: [cremore/detection/engine.py::EngineConfig](../cremore/detection/engine.py); [cremore/detection/engine.py::Engine._redacted_lines](../cremore/detection/engine.py).
- 수정/경계 커밋: `129d7224`.
- 회귀: [cremore/detection/sanitization_test.py::test_context_is_bounded_without_changing_detection_coordinates](../cremore/detection/sanitization_test.py). 실행 묶음: A.

### G05 — AWS 현재 승인·계정 세션

- 원본: D04 D22 K02; 판정: **fixed**.
- 근거: S3/catalog/credential-check의 production factory가 ContentSessions→AccountSessions를 사용한다. 신원·account·목적별 승인 revision·조직 상태를 요청 및 fenced commit에서 다시 검사하고, 신원이 없다고 runtime 자격증명으로 fallback하지 않는다.
- 현재 코드: [aws/backend/cremore_aws_provider/worker_session.py::ContentSessions](../aws/backend/cremore_aws_provider/worker_session.py); [cremore/cli/worker.py::main](../cremore/cli/worker.py); [cremore/worker/runtime.py::ScanRuntime.validate](../cremore/worker/runtime.py).
- 수정/경계 커밋: `1d1eb938`, `20eb2f6f`.
- 회귀: [aws/backend/cremore_aws_provider/worker_session_test.py](../aws/backend/cremore_aws_provider/worker_session_test.py); [cremore/cli/aws_content_test.py](../cremore/cli/aws_content_test.py); [cremore/worker/worker_test.py::test_content_access_is_rechecked_at_commit_and_released_on_failure](../cremore/worker/worker_test.py). 실행 묶음: C.

### G06 — GitHub audit-link 응답 증폭

- 원본: D05; 판정: **fixed**.
- 근거: 외부 collector 기록→audit join→flatten 경로에 입력 record/byte 및 flatten 결과 byte 예산을 적용한다. 단순 페이지 slice 이전에 초과를 거절하므로 같은 entities 배열을 많은 이벤트에 반복 직렬화하는 무제한 경로가 차단된다.
- 현재 코드: [github/backend/cremore_github_provider/metadata/audit_links.py::link_inputs](../github/backend/cremore_github_provider/metadata/audit_links.py); [github/backend/cremore_github_provider/metadata/audit_links.py::audit_link_rows](../github/backend/cremore_github_provider/metadata/audit_links.py); [cremore/api/metadata_coverage.py::github_audit_links](../cremore/api/metadata_coverage.py).
- 수정/경계 커밋: `640a0f9e`.
- 회귀: [github/backend/cremore_github_provider/metadata/tests/test_audit_links.py::test_flattened_audit_rows_have_a_total_byte_budget_without_partial_results](../github/backend/cremore_github_provider/metadata/tests/test_audit_links.py); [cremore/api/github_metadata_test.py::test_audit_link_view_is_bounded_by_its_event_limit](../cremore/api/github_metadata_test.py). 실행 묶음: B,C.

### G07 — Azure Repos 재귀 목록 메모리

- 원본: D06 K35; 판정: **fixed**.
- 근거: Full→OneLevel fallback은 pending stack으로 순회한다. 자식 요청 전에 parent body/rows를 해제하고 폴더를 포함한 모든 항목을 max_objects에 차감하며 경로 크기도 검사한다.
- 현재 코드: [azure/backend/cremore_azure_provider/devops_content.py::Collector.items](../azure/backend/cremore_azure_provider/devops_content.py).
- 수정/경계 커밋: `d7eafda1`.
- 회귀: [azure/backend/cremore_azure_provider/devops_content_test.py::test_split_listing_releases_the_parent_rows_before_reading_a_child](../azure/backend/cremore_azure_provider/devops_content_test.py); [azure/backend/cremore_azure_provider/devops_content_test.py::test_directory_entries_consume_the_shared_listing_budget](../azure/backend/cremore_azure_provider/devops_content_test.py). 실행 묶음: B.

### G08 — SAS 노출 DB 물질화 상한

- 원본: D07; 판정: **fixed**.
- 근거: SAS 후보 1,000개와 노출 1,000개의 독립 예산을 둔다. repository의 exposure_limit을 SQL LIMIT 전에 전달하고 sentinel 초과는 비교 completeness=false로 남긴다.
- 현재 코드: [cremore/coverage/metadata_correlation.py::sas_candidates](../cremore/coverage/metadata_correlation.py); [cremore/db/sql.py::SqlRepository.findings_with_exposures](../cremore/db/sql.py); [cremore/coverage/metadata_job.py](../cremore/coverage/metadata_job.py).
- 수정/경계 커밋: `d7eafda1`.
- 회귀: [cremore/coverage/metadata_linkage_test.py::test_sas_exposure_budget_is_applied_before_materialization_and_reports_incomplete](../cremore/coverage/metadata_linkage_test.py). 실행 묶음: B.

### G09 — Azure DevOps PAT 잘못된 이름 격리

- 원본: D08; 판정: **fixed**.
- 근거: 정규화 뒤 typed record validation까지 토큰별 오류 경계 안에서 실행한다. 잘못된 이름은 해당 record의 오류/부분 수집으로 기록되며 전체 다음 사용자 수집을 예외로 중단하지 않는다.
- 현재 코드: [azure/backend/cremore_azure_provider/devops_tokens/adapter.py::collect_pages](../azure/backend/cremore_azure_provider/devops_tokens/adapter.py).
- 수정/경계 커밋: `d7eafda1`.
- 회귀: [azure/backend/cremore_azure_provider/devops_tokens/devops_tokens_test.py::test_rejected_optional_metadata_is_isolated_to_its_token](../azure/backend/cremore_azure_provider/devops_tokens/devops_tokens_test.py). 실행 묶음: B.

### G10 — SAS 사실·경로의 비밀 반사

- 원본: D09 D11 K06 K08 K09; 판정: **fixed**.
- 근거: SAS query의 table/range/header 및 URL path는 safe_fact_text를 통과해야 한다. sig 값과 알려진 credential 형태를 반사하는 사실은 전체를 버리고 redacted=true로 표시하며, 누락 사실로 서명 일치를 주장하지 않는다.
- 현재 코드: [azure/backend/cremore_azure_provider/sas.py::sas_facts](../azure/backend/cremore_azure_provider/sas.py); [azure/backend/cremore_azure_provider/sas.py::string_to_sign](../azure/backend/cremore_azure_provider/sas.py); [cremore/detection/safe_text.py::safe_fact_text](../cremore/detection/safe_text.py).
- 수정/경계 커밋: `129d7224`, `c508eb62`.
- 회귀: [azure/backend/cremore_azure_provider/sas_test.py](../azure/backend/cremore_azure_provider/sas_test.py); [cremore/detection/safe_text_test.py](../cremore/detection/safe_text_test.py). 실행 묶음: A.

### G11 — GitLab verifier 이름 반사

- 원본: D12 K40; 판정: **fixed**.
- 근거: PAT self 응답에서 온 name/scopes 등의 자유 텍스트는 검증한 secret 및 catalog 형태와 대조한다. HTTP verifier뿐 아니라 Engine의 durable 경계에서도 다시 검사한다.
- 현재 코드: [cremore/detection/verify/http.py::_body_facts](../cremore/detection/verify/http.py); [cremore/detection/engine.py::Engine._scan_spec](../cremore/detection/engine.py); [cremore/detection/safe_text.py::safe_fact_text](../cremore/detection/safe_text.py).
- 수정/경계 커밋: `129d7224`, `c508eb62`.
- 회귀: [cremore/detection/verify/verify_test.py::test_gitlab_facts_keep_normal_names_but_omit_reflected_credentials](../cremore/detection/verify/verify_test.py); [cremore/detection/sanitization_test.py::test_verifier_facts_cannot_reflect_raw_or_other_catalog_credentials](../cremore/detection/sanitization_test.py). 실행 묶음: A.

### G12 — greedy SAS 매치의 다른 signature 누출

- 원본: D13; 판정: **fixed**.
- 근거: SAS가 교차하는 증거 줄은 signature group 일부 가림에 의존하지 않고 고정 문구로 대체한다. SAS query/path 별도 사실도 G10의 secret-aware 검사를 거친다.
- 현재 코드: [cremore/detection/engine.py::Engine._redacted_lines](../cremore/detection/engine.py); [azure/backend/cremore_azure_provider/sas.py::sas_facts](../azure/backend/cremore_azure_provider/sas.py).
- 수정/경계 커밋: `828e55fd`, `129d7224`.
- 회귀: [cremore/detection/sanitization_test.py::test_sas_evidence_withholds_the_entire_query_line](../cremore/detection/sanitization_test.py). 실행 묶음: A.

### G13 — GCP key identifier에 비밀값 혼입

- 원본: D15 K10; 판정: **fixed**.
- 근거: 서비스 계정 key ID는 전용 hex grammar를 요구한다. linkage의 식별자 생성과 schema 1/2 issuer_identifier admission은 동일 검증을 쓰며 Engine에서도 안전한 fact만 남긴다.
- 현재 코드: [gcp/standalone/cremore_gcp/linkage.py::service_account_key_identifier](../gcp/standalone/cremore_gcp/linkage.py); [gcp/standalone/cremore_gcp/resources.py](../gcp/standalone/cremore_gcp/resources.py); [cremore/coverage/models.py](../cremore/coverage/models.py); [cremore/coverage/metadata_models.py](../cremore/coverage/metadata_models.py); [cremore/detection/engine.py::Engine._scan_spec](../cremore/detection/engine.py).
- 수정/경계 커밋: `129d7224`, `745e4e49`.
- 회귀: [gcp/standalone/tests/test_linkage.py](../gcp/standalone/tests/test_linkage.py); [cremore/detection/sanitization_test.py](../cremore/detection/sanitization_test.py). 실행 묶음: A.

### G14 — 필터 밖 Azure Blob 이름 누적

- 원본: D16 D28 K38; 판정: **fixed**.
- 근거: 중복 제거 seen에 이름을 넣기 전에 max_objects를 검사한다. include/exclude/exact-key 필터로 버리는 이름도 같은 listing 한도를 소비한다.
- 현재 코드: [azure/backend/cremore_azure_provider/blob_content.py::Collector.objects](../azure/backend/cremore_azure_provider/blob_content.py).
- 수정/경계 커밋: `d7eafda1`.
- 회귀: [azure/backend/cremore_azure_provider/blob_content_test.py::test_filtered_names_still_consume_the_scan_listing_limit](../azure/backend/cremore_azure_provider/blob_content_test.py). 실행 묶음: B.

### G15 — 철회 후 늦은 작업의 상태·저장

- 원본: D17; 판정: **fixed**.
- 근거: credential-check 완료는 같은 secret_ref·현재 상태·철회 근거를 원자적으로 확인한다. 콘텐츠 쓰기는 fenced transaction 안에서 현재 연결 승인과 credential 참조를 다시 검사한다.
- 현재 코드: [cremore/db/sql.py::SqlRepository.finish_credential_check](../cremore/db/sql.py); [cremore/db/repository.py::InMemoryRepository.finish_credential_check](../cremore/db/repository.py); [cremore/worker/runtime.py::ScanRuntime.validate](../cremore/worker/runtime.py); [cremore/worker/worker.py::_run_legacy_scan](../cremore/worker/worker.py).
- 수정/경계 커밋: `20eb2f6f`, `745e4e49`.
- 회귀: [cremore/db/scan_state_test.py::test_late_check_cannot_revive_removed_source_or_certify_new_credential](../cremore/db/scan_state_test.py); [cremore/db/scan_state_test.py::test_late_check_preserves_revocation_even_if_status_was_manually_resumed](../cremore/db/scan_state_test.py); [cremore/worker/worker_test.py::test_content_access_is_rechecked_at_commit_and_released_on_failure](../cremore/worker/worker_test.py). 실행 묶음: C,D.

### G16 — 구형 회전 승인·대상 allowlist 우회

- 원본: D18 K19; 판정: **fixed**.
- 근거: 구형 rotation POST 쓰기는 LEGACY_ROTATION_REQUIRES_ACTION_PLAN으로 거절하고 이력만 제공한다. ActionPlan은 현재 Secrets Manager allowlist, plan hash, Admin 승인 및 단계별 승인 경계를 다시 검사한다.
- 현재 코드: [cremore/api/routes/governance.py](../cremore/api/routes/governance.py); [cremore/remediation/action_plans.py](../cremore/remediation/action_plans.py).
- 수정/경계 커밋: `1c653af0`.
- 회귀: [cremore/api/dashboard_test.py::test_legacy_rotation_apply_requires_the_explicit_action_plan_workflow](../cremore/api/dashboard_test.py); [cremore/api/dashboard_test.py::test_rotation_action_plans_require_allowlist_admin_hash_and_separate_phase_approval](../cremore/api/dashboard_test.py); [cremore/remediation/action_plans_test.py::test_rotation_execution_rechecks_the_current_secret_allowlist](../cremore/remediation/action_plans_test.py). 실행 묶음: C,D.

### G17 — 구형 회전의 모호한 쓰기 결과 재시도

- 원본: D33 K17; 판정: **fixed**.
- 근거: 구형 단계는 더 이상 실행할 수 없다. 과거 PREPARED/FAILED 등 불확실한 회전 기록은 key reservation에 포함하여 새 계획이 우회하지 못하며 이력을 덮어쓰지 않는다. 승인 계획의 모호한 결과는 OUTCOME_UNKNOWN으로 보존한다.
- 현재 코드: [cremore/api/routes/governance.py](../cremore/api/routes/governance.py); [cremore/remediation/action_plans.py](../cremore/remediation/action_plans.py).
- 수정/경계 커밋: `1c653af0`.
- 회귀: [cremore/remediation/action_plans_test.py::test_legacy_rotation_uncertainty_reserves_the_key_without_changing_history](../cremore/remediation/action_plans_test.py); [cremore/remediation/action_plans_test.py::test_execution_gates_and_unknown_outcomes](../cremore/remediation/action_plans_test.py); [cremore/api/dashboard_test.py::test_legacy_rotation_history_is_read_only_and_never_resumes_writes](../cremore/api/dashboard_test.py). 실행 묶음: C,D.

### G18 — Viewer 목록·종속 행·프록시 버퍼

- 원본: D19 K16; 판정: **fixed**.
- 근거: findings는 cursor와 500개 상한, 종속 노출 10,000개·응답 8 MiB 상한을 적용한다. 형제 API 목록도 페이지를 읽고 stats는 집계한다. Next proxy는 upstream stream을 전달하고 pagination header를 보존한다.
- 현재 코드: [cremore/api/finding_routes.py::register_reads](../cremore/api/finding_routes.py); [cremore/api/routes/findings.py](../cremore/api/routes/findings.py); [cremore/api/routes/governance.py](../cremore/api/routes/governance.py); [cremore/db/sql.py](../cremore/db/sql.py); [web/app/api/backend/[...path]/route.ts](../web/app/api/backend/[...path]/route.ts).
- 수정/경계 커밋: `20eb2f6f`, `3883ce3f`.
- 회귀: [cremore/api/list_limits_test.py::test_public_sibling_lists_page_and_stats_aggregate](../cremore/api/list_limits_test.py); [web/tests/proxy.test.cjs](../web/tests/proxy.test.cjs). 실행 묶음: A,F.

### G19 — host 불명 GitHub token 외부 전송

- 원본: D20; 판정: **fixed**.
- 근거: 등록된 Enterprise host가 있는 상태에서 source host가 불명확한 GitHub 토큰은 명시적 cross-host consent 없이는 public GitHub로 보내지 않는다.
- 현재 코드: [cremore/detection/verify/http.py](../cremore/detection/verify/http.py); [cremore/detection/verify/__init__.py](../cremore/detection/verify/__init__.py).
- 수정/경계 커밋: `129d7224`.
- 회귀: [cremore/detection/verify/verify_test.py::test_host_ambiguous_github_verification_requires_explicit_cross_host_consent](../cremore/detection/verify/verify_test.py). 실행 묶음: A.

### G20 — 미지원 형식의 거짓 완전성

- 원본: D21; 판정: **fixed**.
- 근거: archive/media skip은 coverage completeness와 root watermark 진전에서 실패 근거로 남는다. legacy/scoped 종료에서도 skip을 별도 계수하고 부분 결과를 유지한다.
- 현재 코드: [cremore/scanning/service.py](../cremore/scanning/service.py); [cremore/worker/runtime.py](../cremore/worker/runtime.py); [cremore/worker/worker.py](../cremore/worker/worker.py).
- 수정/경계 커밋: `20eb2f6f`, `828e55fd`.
- 회귀: [cremore/worker/runtime_test.py::test_format_skips_leave_partial_coverage_without_retry_failures](../cremore/worker/runtime_test.py); [cremore/worker/runtime_test.py::test_two_format_skips_and_one_failure_stay_partial_and_are_counted_apart](../cremore/worker/runtime_test.py); [cremore/worker/worker_test.py::test_a_connection_scan_with_only_format_skips_retires_deleted_files_and_keeps_skipped_ones](../cremore/worker/worker_test.py). 실행 묶음: C.

### G21 — Key Vault 부모 목록 부분 수집

- 원본: D23; 판정: **fixed**.
- 근거: version 목록의 COMPLETE 판단은 secrets 부모 목록의 COMPLETE에 종속된다. 잘못된/누락 parent가 있으면 PARENT_LISTING_INCOMPLETE를 남기고 비교도 legacy 보고서를 완전한 삭제 증거로 쓰지 않는다.
- 현재 코드: [azure/backend/cremore_azure_provider/metadata/adapter.py](../azure/backend/cremore_azure_provider/metadata/adapter.py).
- 수정/경계 커밋: `d7eafda1`.
- 회귀: [azure/backend/cremore_azure_provider/metadata/azure_key_vault_test.py::test_partial_parent_listing_cannot_prove_version_removal_even_for_legacy_reports](../azure/backend/cremore_azure_provider/metadata/azure_key_vault_test.py); [azure/backend/cremore_azure_provider/metadata/azure_key_vault_test.py::test_no_accepted_parent_names_is_partial_when_parent_list_was_invalid](../azure/backend/cremore_azure_provider/metadata/azure_key_vault_test.py). 실행 묶음: B.

### G22 — GCP 감사 로그 provenance

- 원본: D24 K31; 판정: **fixed**.
- 근거: 현재 제품 metadata collector는 승인 project ID/검증한 숫자 alias의 정확한 cloudaudit stream을 query와 반환 row에서 모두 확인한다. 이름 일부가 비슷한 custom stream은 observed access 근거가 아니다. 원래 standalone CLI는 삭제됐지만 제품의 동등 경로까지 확인했다.
- 현재 코드: [gcp/backend/cremore_gcp_provider/metadata/relations.py::RelationshipCollector.base_filter](../gcp/backend/cremore_gcp_provider/metadata/relations.py); [gcp/backend/cremore_gcp_provider/metadata/relations.py::RelationshipCollector.audit_log_name](../gcp/backend/cremore_gcp_provider/metadata/relations.py).
- 수정/경계 커밋: `640a0f9e`, `25c9f98a`.
- 회귀: [gcp/backend/cremore_gcp_provider/metadata/tests/test_relations.py](../gcp/backend/cremore_gcp_provider/metadata/tests/test_relations.py). 실행 묶음: B.

### G23 — CloudTrail S3 layout 추론 누락

- 원본: D25 K32; 판정: **fixed**.
- 근거: 혼합/비정형 layout 또는 상위 loose log가 있으면 최적화된 경로로 좁히지 않고 승인 prefix를 읽는다. 타 계정 모양 디렉터리 하나만으로 원래 로그를 생략하지 않는다.
- 현재 코드: [aws/backend/cremore_aws_provider/usage_inventory.py::_directories](../aws/backend/cremore_aws_provider/usage_inventory.py); [aws/backend/cremore_aws_provider/usage_inventory.py::_log_listings](../aws/backend/cremore_aws_provider/usage_inventory.py); [aws/backend/cremore_aws_provider/usage_inventory.py::_s3_events](../aws/backend/cremore_aws_provider/usage_inventory.py).
- 수정/경계 커밋: `640a0f9e`.
- 회귀: [aws/backend/cremore_aws_provider/usage_inventory_test.py](../aws/backend/cremore_aws_provider/usage_inventory_test.py). 실행 묶음: B.

### G24 — GitHub installation 이력 replay

- 원본: D26 K33; 판정: **fixed**.
- 근거: 최근 run/report를 하나의 bounded window에서 조회한다. roster overlay에 run·record·byte 예산을 공유하고 incomplete history를 조용히 완전한 roster로 제공하지 않는다.
- 현재 코드: [cremore/api/metadata_coverage.py::github_collection_and_checks](../cremore/api/metadata_coverage.py); [cremore/coverage/metadata_store.py::MetadataStore.recent_run_reports](../cremore/coverage/metadata_store.py).
- 수정/경계 커밋: `640a0f9e`.
- 회귀: [cremore/coverage/metadata_store_test.py::test_recent_run_reports_uses_one_bounded_window_and_preserves_report_order](../cremore/coverage/metadata_store_test.py); [cremore/api/github_metadata_test.py::test_installation_history_budget_refuses_an_incomplete_roster_and_keeps_run_pages](../cremore/api/github_metadata_test.py); [cremore/api/github_metadata_test.py::test_installation_overlay_has_shared_record_and_byte_budgets](../cremore/api/github_metadata_test.py). 실행 묶음: B,C.

### G25 — TFVC 경로 대소문자 승인

- 원본: D27 K36; 판정: **fixed**.
- 근거: TFVC의 path_comparison이 server와 같은 소문자 비교를 적용한다. include/exclude/exact paths와 parent 경계에 모두 적용하며 Git/Blob의 case-sensitive 의미는 유지한다.
- 현재 코드: [azure/backend/cremore_azure_provider/devops_content.py::Collector.path_comparison](../azure/backend/cremore_azure_provider/devops_content.py); [cremore/collectors/content.py::ContentCollector.selected](../cremore/collectors/content.py).
- 수정/경계 커밋: `d7eafda1`.
- 회귀: [azure/backend/cremore_azure_provider/devops_content_test.py::test_tfvc_scope_comparisons_follow_the_server_case_semantics](../azure/backend/cremore_azure_provider/devops_content_test.py); [azure/backend/cremore_azure_provider/devops_content_test.py::test_git_path_selection_remains_case_sensitive](../azure/backend/cremore_azure_provider/devops_content_test.py). 실행 묶음: B.

### G26 — 호환 connection secret_ref 원문 쓰기

- 원본: D29 K12; 판정: **fixed**.
- 근거: 직접 connection 등록 endpoint는 제거됐고, source PATCH로 token/secret_ref를 바꾸면 CREDENTIAL_BELONGS_TO_PROVIDER_CONNECTION을 거절한다. 공급자 연결이 credential을 봉인하며 구형 잘못된 참조도 public_ref가 원문 대신 configured로 투영한다.
- 현재 코드: [cremore/api/routes/sources.py](../cremore/api/routes/sources.py); [cremore/secretstore/sealed.py::public_ref](../cremore/secretstore/sealed.py); [cremore/onboarding](../cremore/onboarding).
- 수정/경계 커밋: `20eb2f6f`, `7f8a38fe`.
- 회귀: [cremore/api/app_test.py::test_connection_crud_and_scan](../cremore/api/app_test.py); [cremore/api/app_test.py::test_connection_token_is_sealed_at_rest_never_served_and_reaches_the_worker](../cremore/api/app_test.py); [cremore/secretstore/sealed_test.py](../cremore/secretstore/sealed_test.py). 실행 묶음: A,D.

### G27 — GCP 값 읽기 project 바인딩

- 원본: D30; 판정: **fixed**.
- 근거: 응답 resource parent를 승인 project에 대조한다. 숫자 project alias는 승인 project의 Resource Manager 응답이 projectId와 name을 함께 증명할 때만 허용하고, 값 읽기 전 다시 원래 이름을 검사한다.
- 현재 코드: [gcp/backend/cremore_gcp_provider/metadata/collector.py::Collector.project_resource](../gcp/backend/cremore_gcp_provider/metadata/collector.py); [gcp/backend/cremore_gcp_provider/metadata/adapter.py](../gcp/backend/cremore_gcp_provider/metadata/adapter.py).
- 수정/경계 커밋: `d7eafda1`.
- 회귀: [gcp/backend/cremore_gcp_provider/metadata/tests/test_collector.py::test_numeric_aliases_need_the_approved_project_canonical_metadata](../gcp/backend/cremore_gcp_provider/metadata/tests/test_collector.py); [gcp/backend/cremore_gcp_provider/metadata/tests/test_collector.py::test_unavailable_or_mismatched_alias_metadata_never_authorizes_a_numeric_parent](../gcp/backend/cremore_gcp_provider/metadata/tests/test_collector.py); [gcp/backend/cremore_gcp_provider/metadata/tests/test_adapter.py](../gcp/backend/cremore_gcp_provider/metadata/tests/test_adapter.py). 실행 묶음: B.

### G28 — 알 수 없는 OIDC kid의 JWKS refresh

- 원본: D31; 판정: **fixed**.
- 근거: verifier별 lock 및 30초 refresh_not_before로 성공·실패·unknown kid 모두 coalesce한다. 공격자가 고른 kid를 무제한 보관하지 않고, 만료된 키는 refresh 실패 시 인증에 쓰지 않는다.
- 현재 코드: [cremore/api/auth.py::OIDCVerifier._key_for](../cremore/api/auth.py).
- 수정/경계 커밋: `20eb2f6f`, `3883ce3f`.
- 회귀: [cremore/api/auth_test.py::test_unknown_kid_is_rejected_without_repeated_refresh](../cremore/api/auth_test.py); [cremore/api/auth_test.py::test_key_refresh_window_coalesces_callers_and_allows_rotation](../cremore/api/auth_test.py); [cremore/api/auth_test.py::test_failed_key_refresh_is_throttled_and_stale_keys_are_not_accepted](../cremore/api/auth_test.py). 실행 묶음: A.

### G29 — 공급자 응답 사실의 자격증명 반사

- 원본: D32; 판정: **fixed**.
- 근거: verifier→Engine, GitHub credential-check, secret-scanning alert의 각 durable 경계가 safe_fact_text로 제출/응답 secret과 credential 형태를 검사한다. 허용 field name이나 문자열 길이만으로 안전함을 판단하지 않는다.
- 현재 코드: [cremore/detection/safe_text.py](../cremore/detection/safe_text.py); [cremore/detection/engine.py::Engine._scan_spec](../cremore/detection/engine.py); [github/backend/cremore_github_provider/credential_check.py](../github/backend/cremore_github_provider/credential_check.py); [github/backend/cremore_github_provider/collectors/github_secret_scanning.py](../github/backend/cremore_github_provider/collectors/github_secret_scanning.py).
- 수정/경계 커밋: `c508eb62`, `129d7224`, `640a0f9e`.
- 회귀: [cremore/detection/sanitization_test.py::test_verifier_facts_cannot_reflect_raw_or_other_catalog_credentials](../cremore/detection/sanitization_test.py); [github/backend/cremore_github_provider/credential_check_test.py::test_response_identity_and_scopes_are_screened_before_connection_evidence](../github/backend/cremore_github_provider/credential_check_test.py); [github/backend/cremore_github_provider/collectors/github_secret_scanning_test.py::test_alert_metadata_is_screened_against_value_and_connection_credential](../github/backend/cremore_github_provider/collectors/github_secret_scanning_test.py). 실행 묶음: A,C.

### G30 — release 배포 이미지 digest

- 원본: D35 K22; 판정: **fixed**.
- 근거: release가 같은 run·repository·commit에서 만든 모든 component digest를 검사/서명 후 기록한다. release.cjs가 그 기록만으로 digest pinned Helm/Compose 묶음을 생성하고 누락·다른 revision·mutable tag·template drift를 거절한다. 소스 템플릿의 개발용 tag는 서명된 release artifact와 구별한다.
- 현재 코드: [.github/workflows/release.yml](../.github/workflows/release.yml); [deploy/helm/release.cjs](../deploy/helm/release.cjs); [deploy/helm/templates/validate.yaml](../deploy/helm/templates/validate.yaml).
- 수정/경계 커밋: `b7a40be5`.
- 회귀: [deploy/helm/tests/chart.test.cjs::release packaging refuses](../deploy/helm/tests/chart.test.cjs). 실행 묶음: E.

### G31 — 삭제된 GCP API key CLI의 줄 세기

- 원본: D36 K49; 판정: **not applicable**.
- 근거: 신고 대상 standalone api_key_cli와 CLI 진입점은 25c9f98a에서 삭제됐다. 현재 wheel/명령에서 source-file 경로가 도달하지 않는다. 제품 detection의 줄 세기 문제는 G03으로 따로 검토했다.
- 현재 코드: `pyproject.toml`; [gcp/standalone](../gcp/standalone).
- 수정/경계 커밋: `25c9f98a`.
- 회귀: `git ls-files 및 pyproject.toml entrypoint 정적 검토`. 실행 묶음: S.

### G32 — 제거한 Slack 형식이 문맥에 남음

- 원본: K03; 판정: **fixed**.
- 근거: 탐지 catalog에서 제외된 Slack 계열도 safe_evidence_text의 폐기 패턴으로 보존하지 않는다. Engine epoch를 올려 구형 passive cache 결과를 새 검사를 대신해 재사용하지 않는다.
- 현재 코드: [cremore/detection/safe_text.py::safe_evidence_text](../cremore/detection/safe_text.py); [cremore/detection/engine.py::Engine._redacted_lines](../cremore/detection/engine.py).
- 수정/경계 커밋: `828e55fd`, `129d7224`.
- 회귀: [cremore/detection/sanitization_test.py::test_retired_slack_families_are_not_retained_as_nearby_context](../cremore/detection/sanitization_test.py). 실행 묶음: A.

### G33 — GCP IAM 관계 Cartesian 확장

- 원본: K04; 판정: **fixed**.
- 근거: 남은 record 예산에서 max_edges를 계산하여 policy 확장에 전달한다. edge를 append하기 전에 한도를 검사하고 부분 수집으로 남긴다.
- 현재 코드: [gcp/backend/cremore_gcp_provider/metadata/relations.py::RelationshipCollector.apply_policy](../gcp/backend/cremore_gcp_provider/metadata/relations.py); [gcp/backend/cremore_gcp_provider/metadata/adapter.py](../gcp/backend/cremore_gcp_provider/metadata/adapter.py).
- 수정/경계 커밋: `40b2db59`.
- 회귀: [gcp/backend/cremore_gcp_provider/metadata/tests/test_relations.py::test_policy_expansion_checks_the_remaining_budget_before_allocating_edges](../gcp/backend/cremore_gcp_provider/metadata/tests/test_relations.py). 실행 묶음: B.

### G34 — 교체한 enterprise request budget 미적용

- 원본: K05; 판정: **fixed**.
- 근거: ContentCollector.request_budget getter/setter가 실제 HTTP 객체의 budget을 읽고 교체한다. DurableBudget가 모든 listing request에 적용되어 결과 객체가 나오지 않는 페이지도 취소·시간·현재 승인을 검사한다.
- 현재 코드: [cremore/collectors/content.py::ContentCollector.request_budget](../cremore/collectors/content.py); [cremore/collectors/content.py::ContentHTTP.get](../cremore/collectors/content.py).
- 수정/경계 커밋: `d7eafda1`, `828e55fd`.
- 회귀: [cremore/collectors/enterprise_test.py::test_replaced_request_budget_guards_http_before_any_listing_request](../cremore/collectors/enterprise_test.py). 실행 묶음: C.

### G35 — S3 reference의 실제 bucket owner

- 원본: K13; 판정: **fixed**.
- 근거: reference HeadBucket뿐 아니라 List/Get와 paginator도 ContentSessions의 guarded client를 거친다. Bucket 인자가 있는 S3 요청은 ExpectedBucketOwner를 고정하고 상충하는 owner를 거절한다.
- 현재 코드: [aws/backend/cremore_aws_provider/worker_session.py::_Client.__getattr__](../aws/backend/cremore_aws_provider/worker_session.py); [aws/backend/cremore_aws_provider/catalog.py::_head](../aws/backend/cremore_aws_provider/catalog.py); [cremore/cli/worker.py](../cremore/cli/worker.py).
- 수정/경계 커밋: `1d1eb938`.
- 회귀: [cremore/cli/aws_content_test.py](../cremore/cli/aws_content_test.py); [aws/backend/cremore_aws_provider/worker_session_test.py](../aws/backend/cremore_aws_provider/worker_session_test.py). 실행 묶음: C.

### G36 — legacy scan 목록 중 취소·시간 검사

- 원본: K14; 판정: **fixed**.
- 근거: factory discovery부터 guard_requests context 안에서 실행한다. RequestBudget.consume은 provider 요청 전에 lease·취소·현재 credential·1시간 한도를 검사하므로 yield 없는 listing에도 적용된다.
- 현재 코드: [cremore/collectors/base.py::guard_requests](../cremore/collectors/base.py); [cremore/collectors/base.py::RequestBudget.consume](../cremore/collectors/base.py); [cremore/worker/worker.py](../cremore/worker/worker.py).
- 수정/경계 커밋: `828e55fd`.
- 회귀: [cremore/worker/worker_test.py::test_legacy_request_guard_covers_factory_discovery_and_empty_listing](../cremore/worker/worker_test.py). 실행 묶음: C.

### G37 — 미확인 AWS key ID의 전 계정 fanout

- 원본: K15; 판정: **fixed**.
- 근거: usage refresh는 verified owner 또는 현재 정확한 IAM inventory owner만 사용한다. owner가 불명확하면 409이고 모든 연결 계정에 IAM probe를 수행하지 않는다. inventory 검색도 aggregate 한도를 적용한다.
- 현재 코드: [cremore/api/routes/findings.py](../cremore/api/routes/findings.py); [aws/backend/cremore_aws_provider/inventory_view.py::key_owner](../aws/backend/cremore_aws_provider/inventory_view.py).
- 수정/경계 커밋: `469a893a`.
- 회귀: [aws/backend/cremore_aws_provider/inventory_view_test.py::test_usage_owner_limit_is_aggregate_and_cannot_hide_a_conflict](../aws/backend/cremore_aws_provider/inventory_view_test.py); [cremore/api/dashboard_test.py::test_an_identifier_without_its_secret_is_resolved_through_the_owner_account](../cremore/api/dashboard_test.py); [cremore/api/dashboard_test.py::test_usage_is_never_collected_outside_the_verified_owner_account](../cremore/api/dashboard_test.py). 실행 묶음: D.

### G38 — OIDC discovery의 임의 JWKS 목적지

- 원본: K18; 판정: **fixed**.
- 근거: issuer origin, Google의 정확한 공식 key URL, 또는 운영자가 명시한 OIDC_JWKS_URL만 허용한다. URL userinfo/fragment/잘못된 scheme을 거절하며 redirect를 따르지 않는다. 승인 issuer 자체의 trust는 배포 계약이다.
- 현재 코드: [cremore/api/auth.py::OIDCVerifier._discover](../cremore/api/auth.py); [cremore/api/auth.py::OIDCVerifier._origin](../cremore/api/auth.py); [cremore/api/auth.py::OIDCVerifier._get_json](../cremore/api/auth.py).
- 수정/경계 커밋: `3883ce3f`.
- 회귀: [cremore/api/auth_test.py::test_discovered_key_destination_is_approved_before_fetch](../cremore/api/auth_test.py); [cremore/api/auth_test.py::test_oidc_fetch_never_follows_redirects](../cremore/api/auth_test.py). 실행 묶음: A.

### G39 — content cursor·dedup 누적 상태

- 원본: K20; 판정: **fixed**.
- 근거: CursorHistory는 cursor 8 KiB·aggregate 10,000개를 제한하고 원문 대신 digest만 이력에 보관한다. fork도 count를 공유한다. Azure Blob 이름은 G14의 목록 상한을 적용한다.
- 현재 코드: [cremore/collectors/base.py::CursorHistory](../cremore/collectors/base.py); [gcp/backend/cremore_gcp_provider/content.py](../gcp/backend/cremore_gcp_provider/content.py); [notion/backend/cremore_notion_provider/collectors/notion.py](../notion/backend/cremore_notion_provider/collectors/notion.py); [azure/backend/cremore_azure_provider/blob_content.py](../azure/backend/cremore_azure_provider/blob_content.py).
- 수정/경계 커밋: `ae2689c5`, `7009e640`, `d7eafda1`.
- 회귀: [cremore/collectors/cursor_history_test.py](../cremore/collectors/cursor_history_test.py). 실행 묶음: C.

### G40 — CloudFormation account-root trust

- 원본: K21; 판정: **fixed**.
- 근거: single/security account 템플릿은 exact IAM role/user ARN 문법만 허용한다. root·STS session·wildcard는 parameter validation으로 거절하고 선택 remediation principal만 빈 값을 허용한다.
- 현재 코드: [deploy/cloudformation/single-account.yaml](../deploy/cloudformation/single-account.yaml); [deploy/cloudformation/security-account.yaml](../deploy/cloudformation/security-account.yaml).
- 수정/경계 커밋: `ddb95c98`.
- 회귀: [aws/backend/cremore_aws_provider/aws_readonly_test.py::test_direct_role_trust_accepts_only_an_exact_iam_principal](../aws/backend/cremore_aws_provider/aws_readonly_test.py). 실행 묶음: D.

### G41 — ownership 관계를 실제 사용으로 집계

- 원본: K23; 판정: **fixed**.
- 근거: usage_counts는 단순 purpose=usage만 보지 않고 exact observed_access와 명시 token activity만 센다. 소유·IAM 정책·lifecycle event는 사용 횟수에서 제외한다.
- 현재 코드: [cremore/coverage/metadata_store.py::_is_usage](../cremore/coverage/metadata_store.py); [cremore/coverage/metadata_store.py::MetadataStore.usage_counts](../cremore/coverage/metadata_store.py).
- 수정/경계 커밋: `40b2db59`.
- 회귀: [cremore/coverage/metadata_store_test.py::test_usage_counts_require_observed_use_not_ownership_policy_or_lifecycle_events](../cremore/coverage/metadata_store_test.py). 실행 묶음: B.

### G42 — event type facet의 목록 한도 우회

- 원본: K24; 판정: **fixed**.
- 근거: facet은 event pagination과 별개 개수·문자열 예산을 적용한다. SQL DISTINCT에도 sentinel LIMIT가 있고 truncated 여부를 반환한다.
- 현재 코드: [cremore/coverage/metadata_store.py::_bounded_facets](../cremore/coverage/metadata_store.py); [cremore/coverage/metadata_store.py::MetadataStore.provider_events](../cremore/coverage/metadata_store.py).
- 수정/경계 커밋: `40b2db59`.
- 회귀: [cremore/coverage/metadata_store_test.py::test_event_facets_are_bounded_independently_of_event_pagination](../cremore/coverage/metadata_store_test.py). 실행 묶음: B.

### G43 — GitHub machine inventory native scope

- 원본: K25; 판정: **fixed**.
- 근거: machine record의 identity/subject/target 각각의 native key가 승인된 organization/enterprise scope를 직접 증명해야 한다. caller가 붙인 endpoint·outer scope로 전역 ID를 재분류하지 못한다.
- 현재 코드: [github/backend/cremore_github_provider/metadata/adapter.py::validate_machine_record](../github/backend/cremore_github_provider/metadata/adapter.py); [github/backend/cremore_github_provider/metadata/adapter.py::_identity_scopes](../github/backend/cremore_github_provider/metadata/adapter.py).
- 수정/경계 커밋: `27d9d332`, `1b969552`.
- 회귀: [github/backend/cremore_github_provider/metadata/tests/test_adapter.py::test_machine_record_binds_native_identity_and_endpoint_to_its_scope](../github/backend/cremore_github_provider/metadata/tests/test_adapter.py); [github/backend/cremore_github_provider/metadata/tests/test_adapter.py::test_machine_global_ids_need_native_scope_evidence](../github/backend/cremore_github_provider/metadata/tests/test_adapter.py); [github/backend/cremore_github_provider/metadata/tests/test_adapter.py::test_machine_relation_requires_both_endpoint_keys_to_bind_scope](../github/backend/cremore_github_provider/metadata/tests/test_adapter.py). 실행 묶음: C.

### G44 — Atlassian 외부 relation scope

- 원본: K26; 판정: **fixed**.
- 근거: Cloud adapter가 실제 생성하는 entity_observation/operation_report만 받는다. 지원하지 않는 arbitrary relation/event는 외부 endpoint identity를 투영하기 전에 거절한다. Data Center는 전용 validator를 사용한다.
- 현재 코드: [atlassian/backend/cremore_atlassian_provider/metadata/adapter.py::validate_record](../atlassian/backend/cremore_atlassian_provider/metadata/adapter.py).
- 수정/경계 커밋: `61eee031`.
- 회귀: [atlassian/backend/cremore_atlassian_provider/tests/test_common_adapter.py](../atlassian/backend/cremore_atlassian_provider/tests/test_common_adapter.py). 실행 묶음: C.

### G45 — GitLab relation의 native credential scope

- 원본: K27; 판정: **fixed**.
- 근거: relation의 observed_scopes 주장 외에 payload.identity의 native scope를 검사한다. 승인 밖 credential을 승인 scope로 다시 붙일 수 없다.
- 현재 코드: [gitlab/backend/cremore_gitlab_provider/metadata/adapter.py::validate_machine_record](../gitlab/backend/cremore_gitlab_provider/metadata/adapter.py).
- 수정/경계 커밋: `61eee031`.
- 회귀: [gitlab/backend/cremore_gitlab_provider/metadata/tests/test_adapter.py](../gitlab/backend/cremore_gitlab_provider/metadata/tests/test_adapter.py). 실행 묶음: C.

### G46 — GitHub secret alert 배열 확대

- 원본: K28; 판정: **fixed**.
- 근거: 응답 배열은 PER_PAGE=100 초과를 projection 전에 거절하고 MAX_ALERTS=1,000·결과 8 MiB를 함께 검사한다. malformed 항목도 부분 근거로 남겨 빈 COMPLETE로 처리하지 않는다.
- 현재 코드: [github/backend/cremore_github_provider/collectors/github_secret_scanning.py::collect](../github/backend/cremore_github_provider/collectors/github_secret_scanning.py).
- 수정/경계 커밋: `640a0f9e`, `40b2db59`.
- 회귀: [github/backend/cremore_github_provider/collectors/github_secret_scanning_test.py::test_alert_pages_are_bounded_before_projection_and_results_share_a_budget](../github/backend/cremore_github_provider/collectors/github_secret_scanning_test.py); [github/backend/cremore_github_provider/collectors/github_secret_scanning_test.py::test_skipped_malformed_alerts_are_partial_evidence](../github/backend/cremore_github_provider/collectors/github_secret_scanning_test.py). 실행 묶음: C.

### G47 — EVENT continuation의 exact target 소실

- 원본: K29; 판정: **fixed**.
- 근거: EVENT/non-S3는 자동 RESUME 대상에서 제외하고 원래 부분 결과를 유지한다. exact target 없는 legacy EVENT task는 EVENT_EXACT_TARGET_REQUIRED로 거절한다.
- 현재 코드: [cremore/scanning/triggers.py::_has_resumable_progress](../cremore/scanning/triggers.py); [cremore/worker/runtime.py::ScanRuntime.plan](../cremore/worker/runtime.py).
- 수정/경계 커밋: `5125cac7`.
- 회귀: [cremore/scanning/triggers_test.py::test_budget_stopped_event_preserves_exact_scope_without_a_fake_continuation](../cremore/scanning/triggers_test.py); [cremore/worker/runtime_test.py::test_legacy_resume_event_without_exact_targets_cannot_complete_empty](../cremore/worker/runtime_test.py). 실행 묶음: C.

### G48 — 진전 없는 자동 재개 반복

- 원본: K30; 판정: **fixed**.
- 근거: S3 BASELINE/DELTA/RECONCILE에서 fenced checkpoint·root state·detection digest가 일치하고 last_key가 resume_start보다 진전한 경우에만 다음 작업을 만든다. non-S3/정지 cursor는 재개하지 않는다.
- 현재 코드: [cremore/scanning/triggers.py::_has_resumable_progress](../cremore/scanning/triggers.py); [cremore/scanning/triggers.py::poll_resumable](../cremore/scanning/triggers.py).
- 수정/경계 커밋: `5125cac7`.
- 회귀: [cremore/scanning/triggers_test.py::test_budget_stop_without_durable_provider_traversal_does_not_loop](../cremore/scanning/triggers_test.py); [cremore/scanning/triggers_test.py::test_s3_continuation_requires_current_approval_and_durable_advancing_progress](../cremore/scanning/triggers_test.py). 실행 묶음: C.

### G49 — GitHub installation-check 조직 범위

- 원본: K34; 판정: **fixed**.
- 근거: machine record가 worker discovery를 사칭할 수 없게 native scope를 검사한다. enterprise installation-check는 현재 enterprise 조직 목록을 worker가 다시 읽고 그 membership으로 task를 허용한다. 실패 시 absence를 단정하지 않는다.
- 현재 코드: [github/backend/cremore_github_provider/metadata/adapter.py::validate_machine_record](../github/backend/cremore_github_provider/metadata/adapter.py); [github/backend/cremore_github_provider/metadata/adapter.py::_validate_pending_task](../github/backend/cremore_github_provider/metadata/adapter.py).
- 수정/경계 커밋: `27d9d332`, `1b969552`.
- 회귀: [github/backend/cremore_github_provider/metadata/tests/test_adapter.py::test_machine_enterprise_records_cannot_claim_discovered_organization_membership](../github/backend/cremore_github_provider/metadata/tests/test_adapter.py); [github/backend/cremore_github_provider/metadata/tests/test_installation_check.py::test_stored_organization_cannot_authorize_check_without_current_membership](../github/backend/cremore_github_provider/metadata/tests/test_installation_check.py); [github/backend/cremore_github_provider/metadata/tests/test_installation_check.py::test_failed_membership_read_never_turns_installation_absence_into_fact](../github/backend/cremore_github_provider/metadata/tests/test_installation_check.py). 실행 묶음: C,D.

### G50 — Azure DevOps branch/ref 혼동

- 원본: K37; 판정: **fixed**.
- 근거: branch_ref는 HEAD/default/full refs/heads 값을 정확한 ref 하나로 해석한다. prefix-filter 응답에서도 정확히 그 이름인 row의 commit만 선택한다.
- 현재 코드: [azure/backend/cremore_azure_provider/devops_content.py::branch_ref](../azure/backend/cremore_azure_provider/devops_content.py); [azure/backend/cremore_azure_provider/devops_content.py::Collector.objects](../azure/backend/cremore_azure_provider/devops_content.py).
- 수정/경계 커밋: `d7eafda1`.
- 회귀: [azure/backend/cremore_azure_provider/devops_content_test.py::test_scope_branch_selection_cannot_be_rebound_to_a_prefixed_or_head_named_branch](../azure/backend/cremore_azure_provider/devops_content_test.py); [azure/backend/cremore_azure_provider/devops_content_test.py::test_an_explicit_full_ref_does_not_accept_a_different_branch_when_the_selected_one_is_absent](../azure/backend/cremore_azure_provider/devops_content_test.py). 실행 묶음: B.

### G51 — GitHub activity scalar fact 예외

- 원본: K39; 판정: **fixed**.
- 근거: _document_id/action/repo/actor는 list[str]인지 읽기 경계에서 검사한다. malformed retained fact는 INVALID_ACTIVITY_EVIDENCE 이유와 함께 건너뛰므로 list update의 TypeError를 만들지 않는다.
- 현재 코드: [cremore/coverage/metadata_correlation.py::_token_activity](../cremore/coverage/metadata_correlation.py).
- 수정/경계 커밋: `40b2db59`.
- 회귀: [cremore/coverage/metadata_linkage_test.py::test_token_activity_scalar_facts_are_ignored_as_invalid_evidence](../cremore/coverage/metadata_linkage_test.py). 실행 묶음: B.

### G52 — S3 delta가 다른 revision의 노출 갱신

- 원본: K41; 판정: **fixed**.
- 근거: unchanged_locations만으로 시각을 갱신하지 않는다. listed revision과 기존 exposure revision이 정확히 같아야 refresh하며 unknown/different revision은 역사적 관측으로 남는다.
- 현재 코드: [aws/backend/cremore_aws_provider/collectors/s3.py](../aws/backend/cremore_aws_provider/collectors/s3.py); [cremore/worker/runtime.py](../cremore/worker/runtime.py).
- 수정/경계 커밋: `5125cac7`.
- 회귀: [cremore/worker/runtime_test.py::test_delta_listing_does_not_refresh_a_different_or_unknown_revision](../cremore/worker/runtime_test.py). 실행 묶음: C.

### G53 — triage 문자열의 원문 저장

- 원본: K42; 판정: **fixed**.
- 근거: resolution/reason/assignee 등은 크기와 safe_fact_text 및 passive detector 검사를 상태·감사·learning 쓰기 전에 통과해야 한다. 발견 credential을 외부 인증하지 않는다.
- 현재 코드: [cremore/api/finding_routes.py::register_triage](../cremore/api/finding_routes.py); [cremore/api/finding_routes.py::_validate_note](../cremore/api/finding_routes.py).
- 수정/경계 커밋: `3883ce3f`.
- 회귀: [cremore/api/app_test.py::test_triage_rejects_credentials_before_state_audit_or_learning](../cremore/api/app_test.py). 실행 묶음: D.

### G54 — Viewer의 Vault reference path 노출

- 원본: K43; 판정: **fixed**.
- 근거: public_ref 기본은 vault 경로를 configured marker로 대체한다. 일반 source/governance presenter는 reference opt-in 없이 호출하여 상세/목록에서 내부 경로를 내보내지 않는다.
- 현재 코드: [cremore/secretstore/sealed.py::public_ref](../cremore/secretstore/sealed.py); [cremore/api/source_presenters.py](../cremore/api/source_presenters.py); [cremore/api/governance_presenters.py](../cremore/api/governance_presenters.py).
- 수정/경계 커밋: `3883ce3f`.
- 회귀: [cremore/secretstore/sealed_test.py](../cremore/secretstore/sealed_test.py); [cremore/api/app_test.py::test_connection_crud_and_scan](../cremore/api/app_test.py). 실행 묶음: A,D.

### G55 — 공개 credential/component fingerprint

- 원본: K44; 판정: **fixed**.
- 근거: detail_credential은 identifier와 fingerprint를 제외한다. exposure metadata는 issuer_comparison과 *fingerprint 필드를 제외하고 내부 matching 근거를 public projection으로 옮기지 않는다.
- 현재 코드: [cremore/api/finding_presenters.py::detail_credential](../cremore/api/finding_presenters.py); [cremore/api/finding_routes.py::register_reads](../cremore/api/finding_routes.py); [cremore/api/finding_evidence.py](../cremore/api/finding_evidence.py).
- 수정/경계 커밋: `3883ce3f`.
- 회귀: [cremore/api/credential_components_test.py](../cremore/api/credential_components_test.py). 실행 묶음: D.

### G56 — passphrase의 diskless 보장

- 원본: K45; 판정: **not applicable**.
- 근거: 현재 제품은 환경 주입을 diskless라고 보장하지 않는다. passphrase.py·CREDENTIAL_ROOTS는 Docker의 환경 보관/재시작 재사용을 명시하고 stored_locally는 held_here=true로 표시한다. 환경에 넣은 passphrase가 Docker metadata에 남는 동작 자체는 유지되며 ephemeral unlock은 구현됐다고 주장하지 않는다.
- 현재 코드: `docker-compose.yml`; [cremore/secretstore/passphrase.py](../cremore/secretstore/passphrase.py); [cremore/secretstore/stored_locally.py::local_credentials](../cremore/secretstore/stored_locally.py); [docs/CREDENTIAL_ROOTS.md](../docs/CREDENTIAL_ROOTS.md).
- 수정/경계 커밋: `daab6b61`.
- 회귀: [cremore/secretstore/stored_locally_test.py](../cremore/secretstore/stored_locally_test.py). 실행 묶음: A.

### G57 — quarantine policy를 AWS 유출 확정으로 표시

- 원본: K46; 판정: **fixed**.
- 근거: AWS 관리형 policy 부착과 실제 AWS 발급 exposure 사건을 구분한다. attachment 관측만으로 누가/왜/어느 key 때문에 붙였는지 확정하지 않으며 risk에서도 그 확정 의미를 제거한다.
- 현재 코드: [aws/backend/cremore_aws_provider/investigation/identity_policies.py](../aws/backend/cremore_aws_provider/investigation/identity_policies.py); [cremore/risk/model.py](../cremore/risk/model.py); [web/console/views/credentials/permissions.tsx](../web/console/views/credentials/permissions.tsx).
- 수정/경계 커밋: `0a6abfb8`.
- 회귀: [aws/backend/cremore_aws_provider/investigation/identity_policies_test.py::test_aws_quarantine_policy_is_named_and_cannot_be_forged_by_name](../aws/backend/cremore_aws_provider/investigation/identity_policies_test.py); [web/tests/console-issued.test.cjs](../web/tests/console-issued.test.cjs). 실행 묶음: F,G.

### G58 — literal S3 prefix의 공백 손실

- 원본: K47; 판정: **fixed**.
- 근거: 현재 targets 모델은 줄바꿈만 분리하고 진짜 빈 줄만 제거한다. 공백·쉼표는 리소스명으로 보존하며 비어 있는 restricted bucket 선택은 별도 오류로 거절한다. 옛 quick-scan 화면은 제거됐다.
- 현재 코드: [web/console/views/integrations/targets-model.ts::lines](../web/console/views/integrations/targets-model.ts); [web/console/views/integrations/targets.tsx](../web/console/views/integrations/targets.tsx).
- 수정/경계 커밋: `0a6abfb8`.
- 회귀: [web/tests/console-targets.test.cjs::typed prefixes and paths preserve literal spaces and commas](../web/tests/console-targets.test.cjs). 실행 묶음: F.

### G59 — 사전 CEP DB fingerprint 이름 변경

- 원본: K48; 판정: **not applicable**.
- 근거: e1ac9ba4는 배포 전 CEP DB와의 연속 업그레이드를 명시적으로 지원하지 않는다. 현재 CreMore 지문 도메인을 되돌리지 않았고 자동 변환도 없다. 기존 CEP DB를 가진 설치는 writer 중지·원본 DB/감사 보존·별도 이관 검토가 필요하다. 지원되지 않는 DB를 바로 재스캔해도 안전하다는 판정이 아니다.
- 현재 코드: [cremore/detection/fingerprint.py](../cremore/detection/fingerprint.py); [docs/SCANNING_IMPLEMENTATION.md](../docs/SCANNING_IMPLEMENTATION.md).
- 수정/경계 커밋: `e1ac9ba4`, `c836925c`.
- 회귀: `원래 rename commit 본문·현재 지문 상수·업그레이드 문서 정적 대조`. 실행 묶음: S.

### G60 — PR/release container 취약점 gate

- 원본: K50; 판정: **fixed**.
- 근거: PR의 containers job에서 workflow_dispatch-only 조건이 제거됐다. release는 실제 build digest를 HIGH/CRITICAL gate로 통과해야 서명과 배포 artifact 생성으로 진행한다. YAML 설정 검증과 실제 원격 CI/registry 실행은 구분한다.
- 현재 코드: [.github/workflows/ci.yml](../.github/workflows/ci.yml); [.github/workflows/release.yml](../.github/workflows/release.yml).
- 수정/경계 커밋: `b7a40be5`.
- 회귀: [deploy/helm/tests/chart.test.cjs::PR container scans and the exact release digest gate cannot be skipped before signing](../deploy/helm/tests/chart.test.cjs). 실행 묶음: E.

## 원본 행 전체 대조

각 행은 위 그룹의 코드·수정 커밋·회귀 근거를 공유한다. 같은 그룹에 여러 원본이 있어도 86개 행을 전부 아래에 남겼다.

### D 원본

| 행 | 원본 Finding ID | 원본 제목 | 원본 severity | 현재 판정 | 근거 |
| --- | --- | --- | --- | --- | --- |
| D01 | `commit:f792bb6f23688191aad0f3f4d497e644` | Adjacent tokens bypass redaction and leak into finding evidence | high | fixed | G01 |
| D02 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_3cf82d679fc136205e61379d` | Detection caps are applied after unbounded match materialization and duplicated evidence construction | high | fixed | G02 |
| D03 | `commit:3a743acdf7508191a0f989eea7285c16` | Multiline redaction introduces quadratic worker exhaustion | high | fixed | G03 |
| D04 | `commit:7510530ab96481919e3b7aaf9cafb73a` | SSO account scans fall back to the worker's runtime identity | medium | fixed | G05 |
| D05 | `commit:95fe48accb208191b039e37dfadd09ed` | Audit-link pagination permits massive response amplification | medium | fixed | G06 |
| D06 | `commit:a7269cd8065c8191b60cdebb7511072e` | Recursive split listings can exhaust worker memory | medium | fixed | G07 |
| D07 | `commit:f49d6f515e94819184a8d4c02afa7916` | Batched SAS lookup introduces unbounded exposure memory growth | medium | fixed | G08 |
| D08 | `commit:a7b09685fff48191a8778ed059962fd9` | Crafted PAT names abort Azure DevOps inventory collection | medium | fixed | G09 |
| D09 | `commit:e8383d305e808191a0c6e59e21816aa3` | New SAS table fields bypass credential redaction | medium | fixed | G10 |
| D10 | `commit:d9b188b1ac38819186e947cd7778e49e` | New Azure DevOps detector leaks adjacent PATs in finding evidence | medium | fixed | G01 |
| D11 | `commit:1bb01e05b9a881919a0b1ddba2799c43` | Azure SAS metadata bypasses redaction and exposes raw secrets | medium | fixed | G10 |
| D12 | `commit:a89cf4707db881919d3be184858534b5` | GitLab token names bypass secret sanitization | medium | fixed | G11 |
| D13 | `commit:6741570f69ec8191a6c04836e759fda6` | Greedy SAS matching leaks complete tokens in finding evidence | medium | fixed | G12 |
| D14 | `commit:c92df001c37481918c8fee7a26b3cc31` | New Entra detector leaks adjacent secrets into finding evidence | medium | fixed | G01 |
| D15 | `commit:759e67b442d081918d6cb3f5f24cef39` | GCP issuer linkage retains and exposes unredacted credentials | medium | fixed | G13 |
| D16 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_2e19667fe8dfd704c4182802` | Azure Blob enumeration accumulates an unbounded set of unselected names | medium | fixed | G14 |
| D17 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_3f3890f925847a69ed9cceb5` | Stale provider jobs can restore or persist data after credential revocation | medium | fixed | G15 |
| D18 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_62f14e13538559200aaaec1f` | Legacy rotation endpoints bypass target allowlisting and hash-bound Admin approval | medium | fixed | G16 |
| D19 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_94573bf884c6877880855c74` | Viewer finding listing materializes an unbounded table with per-row queries and proxy buffering | medium | fixed | G18 |
| D20 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_aa785b560e1fe51d1b8b392c` | Ambiguous GitHub Enterprise tokens are sent to public GitHub without cross-host consent | medium | fixed | G19 |
| D21 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_ad20cc4fee5ed20b6e11aa30` | Unsupported and media objects can advance coverage and report a clean scan | medium | fixed | G20 |
| D22 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_dadeb3ba8d9b641a125136fe` | AWS S3 catalog and content jobs bypass account-bound session and current account authorization | medium | fixed | G05 |
| D23 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_eead32174341e690070f9548` | Partial Key Vault discovery can produce authoritative version removals | medium | fixed | G21 |
| D24 | `commit:67f1ba09c854819191eb1e4be784d088` | Custom Cloud Logging entries can forge observed secret access | low | fixed | G22 |
| D25 | `commit:7d59e50521488191a8018ca76aed10ea` | One S3 object can silently suppress CloudTrail usage collection | low | fixed | G23 |
| D26 | `commit:6a4514d84f988191be9452c2468a160f` | Unbounded GitHub check replay enables authenticated API DoS | low | fixed | G24 |
| D27 | `commit:a356df31aab88191b3ac3f541178d79a` | TFVC casing changes bypass configured scan path boundaries | low | fixed | G25 |
| D28 | `commit:f7c42f775ecc81918b079e4e38b51c41` | Azure Blob listing bypasses object limits for excluded names | low | fixed | G14 |
| D29 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_0473a8b524a4ac2637ed3fdb` | Compatibility connection API can persist a raw credential and disclose it to Viewers | low | fixed | G26 |
| D30 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_7e628c149195b0f0ca79bda8` | GCP value reads are not bound to the approved project | low | fixed | G27 |
| D31 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_a7152b79fb7fae97068cc051` | Unknown OIDC key IDs trigger an outbound JWKS refresh for every authentication attempt | low | fixed | G28 |
| D32 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_cde3dd362cf51d622144eb99` | Provider-controlled evidence fields can reflect credentials into durable Viewer-visible records | low | fixed | G29 |
| D33 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_d3d87807e95acf21928be1c3` | Legacy rotation records ambiguous post-write failures as definitive failures | low | fixed | G17 |
| D34 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_ebf071961bc30c9bb2bd3d0b` | Redacted evidence retains the entire attacker-controlled physical line | low | fixed | G04 |
| D35 | `rf_wfr_2923bef27176a11301e01d939c91b5a9258101da242904c57a9c04877c085834:wfo_3b78351b299e8e05346d08ab2768d30a33aa1d40e9e4558ee18e2ddcdb3589de:occ_f900a2e96901c880cb8c0a1d` | Released deployment manifests use static mutable image tags disconnected from signed release digests | low | fixed | G30 |
| D36 | `commit:c465be11285081919fca9bb1bb309197` | Quadratic line counting can stall API-key matching | informational | not applicable | G31 |

### K 원본

| 행 | 원본 Finding ID | 원본 제목 | 원본 severity | 현재 판정 | 근거 |
| --- | --- | --- | --- | --- | --- |
| K01 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_986d5724bbcf5b54484cae08` | Whole-line redaction is duplicated per detection and can amplify a small scan into gigabytes of stored data | high | fixed | G04 |
| K02 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_cbe78d42613997f4ed6040c0` | AWS content and catalog jobs can continue after organization membership or scanner approval becomes invalid | high | fixed | G05 |
| K03 | `commit:75bd875b286c8191a021679a669eed2e` | Slack detector removal leaks tokens through finding evidence | medium | fixed | G32 |
| K04 | `commit:eef33b1c5e388191bb73c7ab5e19d8b6` | GCP IAM relationship expansion can exhaust worker memory | medium | fixed | G33 |
| K05 | `commit:ca199d3df9d48191b35cc97f8fb4fe8c` | Enterprise collectors bypass cancellation and deadline checks | medium | fixed | G34 |
| K06 | `commit:e8b30d19b79081918886a65d9fd5b63f` | New SAS range fields bypass secret redaction | medium | fixed | G10 |
| K07 | `commit:c3056cebbb648191be07a4561e78d7ef` | Azure DevOps PAT detection leaks adjacent tokens in finding evidence | medium | fixed | G01 |
| K08 | `commit:df077a3f49048191bd990e569ceefcf1` | Azure SAS path metadata bypasses secret redaction | medium | fixed | G10 |
| K09 | `commit:e3cb86c91ebc8191b35646ae7345c190` | Azure SAS metadata persists secrets that line redaction removes | medium | fixed | G10 |
| K10 | `commit:4e24422acf2481918e3cc0478c72a196` | GCP linkage reintroduces secrets into sanitized records | medium | fixed | G13 |
| K11 | `commit:16384d865d788191973c790953638a7c` | Entra detector leaks adjacent client secrets in finding evidence | medium | fixed | G01 |
| K12 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_24a313836d6692ea0ce0ca69` | Legacy connection APIs can persist plaintext credentials supplied as secret_ref | medium | fixed | G26 |
| K13 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_2ab65abb71cb641782617948` | AWS reference resolution can catalog and later scan a cross-account S3 bucket | medium | fixed | G35 |
| K14 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_366b037903cdd397397061a5` | Compatibility scans ignore cancellation and wall-clock budgets during provider listing | medium | fixed | G36 |
| K15 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_6807f78c44bbb34648bf9d50` | An Analyst can fan one fabricated AWS key identifier across every connected account | medium | fixed | G37 |
| K16 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_727f3bc2c5e5a25d9f56a353` | Viewer list routes perform unbounded database work and full-response buffering | medium | fixed | G18 |
| K17 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_7346de8e50f147b9657e0e4a` | Legacy AWS rotation performs writes before a durable claim and can retry ambiguous outcomes | medium | fixed | G17 |
| K18 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_80a2af2a72859ee14a058854` | OIDC discovery can direct the JWKS fetch to an arbitrary network destination | medium | fixed | G38 |
| K19 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_b520fdded299a1e30c4475cb` | Legacy rotation jobs bypass the configured Secrets Manager target allowlist | medium | fixed | G16 |
| K20 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_d84191ca9783db861012f9cf` | Provider pagination and deduplication state can grow beyond all aggregate budgets | medium | fixed | G39 |
| K21 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_e9718c47d03d18f251796b5b` | Single-account CloudFormation accepts account-root principals for scanner and remediation trust | medium | fixed | G40 |
| K22 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_f783ef92b3a369ab989fb9fb` | Helm deploys mutable image tags without enforcing the signed release digest | medium | fixed | G30 |
| K23 | `commit:2e38d28ee5748191bed5edc42de35f76` | Ownership records are misreported as observed credential use | low | fixed | G41 |
| K24 | `commit:a2ad352d2ed88191b68bc448b5b020a7` | Unbounded event-type facets bypass event pagination | low | fixed | G42 |
| K25 | `commit:52b6f07ece848191a10dfad2aa870b7d` | GitHub collector tokens can forge out-of-scope inventory | low | fixed | G43 |
| K26 | `commit:4392409a02948191bf6f5ed1d0f4d089` | Collector relations bypass Atlassian approved-scope checks | low | fixed | G44 |
| K27 | `commit:4179d7cb8b748191847beab41c1e628b` | GitLab relation submissions bypass approved credential scope | low | fixed | G45 |
| K28 | `commit:e99c74e316c081919deda213bd70640a` | Uncapped GitHub alert arrays can exhaust worker memory | low | fixed | G46 |
| K29 | `commit:f103aede70d08191b8b3ad1919b2f0c7` | Event continuations silently drop GitHub and Notion targets | low | fixed | G47 |
| K30 | `commit:c8ccda351c20819190495856799f9a3f` | Automatic resume loops indefinitely without scan progress | low | fixed | G48 |
| K31 | `commit:6389c14ccd6c819195cca9b0ef43c964` | Custom log entries are trusted as GCP audit evidence | low | fixed | G22 |
| K32 | `commit:dca8f50103648191b15141f39a23adbc` | S3 layout inference lets one object suppress usage collection | low | fixed | G23 |
| K33 | `commit:fea85f13e1d4819183accca1b80f1241` | Unbounded GitHub check-history replay enables API resource exhaustion | low | fixed | G24 |
| K34 | `commit:d065ab0ff8e88191ad21b36ac21267ce` | Collector records expand GitHub installation-check scope | low | fixed | G49 |
| K35 | `commit:dafe2246844c81919398c92c7b445f10` | Recursive listing fallback defeats aggregate memory limits | low | fixed | G07 |
| K36 | `commit:c975f737fb148191a7247059c7636ace` | TFVC path casing bypasses configured scan boundaries | low | fixed | G25 |
| K37 | `commit:9bb9e50b1dfc8191a3790f9b5729451e` | Azure DevOps ref confusion permits decoy-branch scans | low | fixed | G50 |
| K38 | `commit:0d15bd23f5488191a4e05f2609587cce` | Excluded Azure Blob names bypass the listing memory limit | low | fixed | G14 |
| K39 | `commit:68ef1d28e52c8191a78054384677bd57` | Collector facts can persistently break GitHub finding lookups | low | fixed | G51 |
| K40 | `commit:23d26e5990408191942b746908775d65` | GitLab token names bypass secret redaction in findings | low | fixed | G11 |
| K41 | `commit:104b930a9b1c8191951244de5b667b18` | S3 delta scans refresh evidence for unscanned replacements | low | fixed | G52 |
| K42 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_78ee865b3a7d598915e2bda1` | Analyst-controlled triage strings can store raw credentials in findings and audit events | low | fixed | G53 |
| K43 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_9d33c285cb10cdb03d95e6e9` | Viewer-readable connection projections expose internal Vault reference paths | low | fixed | G54 |
| K44 | `rf_wfr_37b425ac299414f0583b3b2e03ffa6a817778690adf60cc4ef1dd8a351a866cf:wfo_dcffe7a34dd55c4ec286c0c5cc04cb238e2cbd07217dcd6f12f325c8761dc3f2:occ_bdb68aa0c4bd8f88bd6011cd` | Finding detail exposes installation-keyed credential and AWS component fingerprints | low | fixed | G55 |
| K45 | `commit:0a4b9e7ccff081918f9af56635af0e81` | Diskless sealing passphrases persist in Docker metadata | informational | not applicable | G56 |
| K46 | `commit:11ab8a01f3348191813c7bd16a5e5eea` | Policy attachment misreported as AWS-confirmed key exposure | informational | fixed | G57 |
| K47 | `commit:1f6dbc6eac308191895b42bb13830949` | Quick scan silently changes literal S3 scope prefixes | informational | fixed | G58 |
| K48 | `commit:c81b43106f68819188ab0520545e65f4` | Fingerprint rename falsely retires existing credential exposures | informational | not applicable | G59 |
| K49 | `commit:a8c4200596288191812afeb9df2f75a1` | Quadratic line counting stalls the API-key file scanner | informational | not applicable | G31 |
| K50 | `commit:b4512288e8508191bdf04b112af98a7c` | Pull requests now skip every container vulnerability gate | informational | fixed | G60 |

## 실제 실행한 검사

아래 검사는 2026-10-06 Windows의 `tmp/github-export-venv/Scripts/python.exe` 및 Node에서 실행했다. **Python 1,049 passed + 52 subtests, Node 47 passed**. 선택 실행의 deselected는 통과 개수에 포함하지 않았다. 실행 중 다른 담당자가 같은 checkout의 작업 파일을 갱신하고 있으므로 최종 통합본/commit의 acceptance 재실행은 상위 담당자가 수행해야 한다. 이 보고서가 그 후의 변경을 자동 검증하지 않는다.

공통 PowerShell 준비:

```powershell
$env:AWS_EC2_METADATA_DISABLED='true'
Remove-Item Env:CREMORE_TEST_POSTGRES_URL -ErrorAction SilentlyContinue
```

### A — 탐지·private projection·OIDC

```powershell
& tmp/github-export-venv/Scripts/python.exe -m pytest cremore/detection/sanitization_test.py cremore/detection/safe_text_test.py cremore/detection/verify/verify_test.py azure/backend/cremore_azure_provider/sas_test.py gcp/standalone/tests/test_linkage.py cremore/api/auth_test.py cremore/api/list_limits_test.py cremore/secretstore/sealed_test.py cremore/secretstore/stored_locally_test.py -q
```

결과: 197 passed, 4 subtests passed (16.20초). Starlette TestClient의 httpx deprecation warning 1개.

### B — 공급자 목록·메타데이터 근거

```powershell
& tmp/github-export-venv/Scripts/python.exe -m pytest azure/backend/cremore_azure_provider/blob_content_test.py azure/backend/cremore_azure_provider/devops_content_test.py azure/backend/cremore_azure_provider/devops_tokens/devops_tokens_test.py azure/backend/cremore_azure_provider/metadata/azure_key_vault_test.py gcp/backend/cremore_gcp_provider/metadata/tests/test_collector.py gcp/backend/cremore_gcp_provider/metadata/tests/test_adapter.py gcp/backend/cremore_gcp_provider/metadata/tests/test_relations.py cremore/coverage/metadata_linkage_test.py cremore/coverage/metadata_store_test.py github/backend/cremore_github_provider/metadata/tests/test_audit_links.py aws/backend/cremore_aws_provider/usage_inventory_test.py -q
```

결과: 358 passed, 7 subtests passed (48.05초).

### C — 현재 승인·쓰기·collector 제출·재개

```powershell
& tmp/github-export-venv/Scripts/python.exe -m pytest aws/backend/cremore_aws_provider/worker_session_test.py cremore/cli/aws_content_test.py cremore/worker/worker_test.py cremore/worker/runtime_test.py cremore/scanning/triggers_test.py cremore/collectors/enterprise_test.py cremore/collectors/cursor_history_test.py cremore/remediation/action_plans_test.py cremore/api/github_metadata_test.py github/backend/cremore_github_provider/collectors/github_secret_scanning_test.py github/backend/cremore_github_provider/credential_check_test.py github/backend/cremore_github_provider/metadata/tests/test_adapter.py gitlab/backend/cremore_gitlab_provider/metadata/tests/test_adapter.py atlassian/backend/cremore_atlassian_provider/tests/test_common_adapter.py -q
```

결과: 405 passed, 41 subtests passed (209.93초), deprecation warning 1개. 최초 명령은 잘못된 cremore/collectors/pagination_test.py 경로 때문에 0개 실행 후 종료했으며 실제 cursor_history_test.py로 바로잡아 위 명령을 실행했다. 이 경로 오류는 통과 검사로 세지 않았다.

### D — API 거절·늦은 check·현재 owner·CF trust

```powershell
& tmp/github-export-venv/Scripts/python.exe -m pytest cremore/api/app_test.py cremore/api/credential_components_test.py cremore/api/dashboard_test.py cremore/db/scan_state_test.py aws/backend/cremore_aws_provider/inventory_view_test.py aws/backend/cremore_aws_provider/aws_readonly_test.py github/backend/cremore_github_provider/metadata/tests/test_installation_check.py -k "triage_rejects or connection_token or connection_crud or keyed or component or legacy_rotation or rotation_action_plans or usage_is_never or identifier_without or usage_owner or late_check or direct_role_trust or membership or installation_check" -q
```

결과: 88 passed, 290 deselected (110.39초), deprecation warning 1개.

### E — release 패키징·CI gate

```powershell
node --test --test-name-pattern='release packaging refuses|PR container scans' deploy/helm/tests/chart.test.cjs
```

결과: 7 passed. 생성기를 synthetic digest로 검사했고 원격 build/publish 또는 Helm 실제 배포는 수행하지 않았다. 전체 chart render suite를 실행한 결과가 아니다.

### F — 콘솔 scope·회전·권한 문구·프록시

```powershell
node --test tests/console-targets.test.cjs tests/console-issued.test.cjs tests/proxy.test.cjs tests/console-legacy-rotation.test.cjs
```

결과: 40 passed. 실행 위치는 web/. DOM/browser layout proof, TypeScript 전체 검사, production build 결과와 구분한다.

### G — policy attachment 의미

```powershell
& tmp/github-export-venv/Scripts/python.exe -m pytest aws/backend/cremore_aws_provider/investigation/identity_policies_test.py -k quarantine -q
```

결과: 1 passed, 8 deselected (0.27초).

### 후속 무결성 검사와 좁은 재실행

상위 검증을 위한 [CSV 무결성 검사기](../.unlazy/always-on-20261006/csv-integrity.py)는 표준 라이브러리만 사용한다. 원본 SHA-256 두 개를 고정하고 86개 원본 ID·제목·severity, 표/그룹의 일대일 연결, 82/4 및 57/3 판정 집계, 로컬 링크 존재, K45/K48의 주요 제한 문구를 확인한다. 코드 판정의 의미나 실제 보안 통제를 자동으로 검증하는 검사는 아니다.

```powershell
& tmp/github-export-venv/Scripts/python.exe .unlazy/always-on-20261006/csv-integrity.py
$env:AWS_EC2_METADATA_DISABLED='true'
Remove-Item Env:CREMORE_TEST_POSTGRES_URL -ErrorAction SilentlyContinue
& tmp/github-export-venv/Scripts/python.exe -m pytest cremore/detection/sanitization_test.py cremore/api/auth_test.py -k 'adjacent_synthetic or candidate_budgets or unknown_kid or discovered_key_destination' -q
```

후속 합성 회귀 결과: **20 passed, 38 deselected**, 8.87초. A 묶음의 일부를 재실행했으므로 앞선 1,049 passed 집계에 추가하지 않는다. 초기 무결성 실행에서 디렉터리를 가리키는 유효한 문서 링크를 파일로만 검사해 실패했고 존재 검사로 수정했다. 초기 Ruff의 import 공백 경고도 수정했다. 최종 실행 결과와 상위 재검증용 cmd.exe 명령은 [leaf gate](../.unlazy/always-on-20261006/gates/leaf-1.3.md)에 남긴다.

### 정적·문서 확인과 미검증

- 두 CSV의 hash/row count와 unique Finding ID를 Python csv reader로 계산했다. 원본 86행이 원인 그룹에 정확히 한 번 연결되며 원인 그룹은 60개다.
- 현재 source/test 경로 존재, 참조한 Python/TypeScript symbol 존재, 수정 commit의 HEAD ancestor 관계를 검사했다.
- `git diff --check` 통과. 공유 checkout의 다른 담당 파일은 수정하거나 되돌리지 않았다. 보고서 링크는 실제 현재 경로를 사용한다.
- PostgreSQL 실행 환경은 지정하지 않았다. SQL 관련 통과는 해당 suite의 in-memory/SQLite fixture 범위이며 실제 PostgreSQL 동시성·운영 DB 증거가 아니다.
- 실계정 provider 호출, 발견 credential 인증, 운영 DB 접근, OOM/DoS 재현, 실제 token 반사 시험, 원격 CI/release/registry, Docker 환경 영속성 실험, 전체 build/browser/장기 soak는 미실행이다.
- 이번 leaf는 이 보고서와 후속 무결성 검사기·leaf gate만 수정했다. 제품 코드는 수정하지 않았다. 공유 실행 중 변경된 최종 runtime/permission/access 구현의 통합 검증은 상위 작업의 gate에 속한다.

## 상위 검증 인계

G1: 두 입력 파일 fingerprint, 86행 provenance, 60개 그룹, 판정과 source/control/counterevidence/commit/test를 이 문서로 재검토한다. 무결성 검사기를 직접 실행하고 K45/K48의 제한을 완료 보고에서 생략하지 않는다.

G2: 최종 작업 트리가 고정된 뒤 leaf gate의 좁은 회귀 명령을 독립적으로 실행하고 실제 출력으로 gate를 갱신한다. 이번 leaf의 실행 결과는 상위 담당자의 독립 검토·재실행을 대신하지 않는다. 미확인 실환경을 코드 수정 완료와 합치지 않는다.
