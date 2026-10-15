# Gates: GitHub Enterprise inventory API transition

OWNS: github/**, cremore/coverage/**, cremore/onboarding/**, cremore/api/**, cremore/governance/ownership.py, cremore/governance/ownership_test.py, cremore/worker/worker.py, cremore/operations/collection_schedule.py, cremore/network_addresses.py, cremore/provider_boundaries_test.py, website/backend/cremore_website_provider/addresses.py, web/console/**, web/lib/**, web/components/**, web/tests/**, docs/**, GATES.md

Scope: Complete the reviewed GitHub inventory design: asynchronous Enterprise export, bounded memory-only CSV normalization, identity and authorization deduplication, safe download and restart, Enterprise permission checks, independent schedules and shared export limits, accurate access evidence and compatibility, and visible collection state. Preserve existing organization collection and private evidence contracts. Live provider execution is separate from synthetic implementation verification.

## Resumed implementation (2026-10-06)

The user resumed implementation and authorized the subsequent actual-motion PoC edit. Preserve the existing branch and all earlier changes. No deployment, push, live-provider call or operational DB change is part of these synthetic checks.

The 23 paused regression failures were reproduced and fixed. Typed snapshot IDs and Export fixtures now follow the actual API. Private compatible snapshot evidence links existing exposures and matching vault values without creating unique credential rows or inflating counts. The API exposes snapshot rows with run-pinned pagination. Unknown, partial and historical evidence stays explicit.

GitHub access collection now resumes every three pages (100 people per page), with 100-page/10,000-person, 700-request and one-hour bounds. Body/cursor commits share the task lease. Every request and final write checks source authorization; cancellation cannot commit another chunk. Credential/page failures retain earlier positive membership as partial. UI search and pagination use the observed list. The isolated `tmp/github-export-venv` contains the editable project dependencies; global Python packages were not changed.

Validation evidence below refers to this working tree, not a deployed revision. Runs overlap; do not sum their pass counts as unique tests.

| Evidence | Result |
| --- | --- |
| `output/github-resume-gates.log` | 722 passed, 17 PostgreSQL skipped, 13 subtests passed |
| `output/github-resume-postgres.log` | 195 passed, including the skipped PostgreSQL paths |
| `output/github-resume-integration.log` | 646 passed, 8 PostgreSQL skipped; one old synchronous offline fixture failed and was corrected to resume Export waiting |
| `output/github-resume-evidence-postgres-final.log` | 266 passed: ownership resume/cancel/auth failures, snapshot/vault linkage, credential records and coverage, including PostgreSQL |
| `output/github-resume-snapshot-freshness.log` | 32 passed: stable/snapshot observations under partial, failed, disabled, changed and stale collections |
| `output/github-resume-coverage-compatibility.log` | 80 passed: vault scope and public-certificate comparison compatibility |
| `output/github-resume-web-unit.log` | 275 passed |
| `output/github-resume-build.log` | TypeScript and Next production build passed |
| `output/github-resume-browser-final.log` | 4/4: access pagination/search, auth-first, edition entry, GitHub Export |
| `output/github-resume-boundaries-final.log` | 73 passed; corrected offline Export continuation and provider boundary checks |
| Changed Python Ruff / `git diff --check` | Passed |

PostgreSQL used an isolated PostgreSQL 17 tmpfs container (`cremore_test`, localhost only).
The existing product containers and DB were not changed. FastAPI emits a non-failing httpx deprecation warning.
Provider permission/licence behavior, real Enterprise exports, long-running customer installations and production deployment remain live validation, not claimed by these tests.

- [x] G1: Export CSV normalization preserves unknowns, stable identities and organization grants without retaining raw hashes or rows.
  CHECK: python -m pytest github/backend/cremore_github_provider/metadata/tests/test_exports.py -q
  EXPECT: passed
  EVIDENCE: See the resumed validation table above; synthetic/provider-fake checks only.

- [x] G2: Export creation, polling and download are bounded and authenticated safely; retries preserve the export and never duplicate an ambiguous submission.
  CHECK: python -m pytest github/backend/cremore_github_provider/metadata/tests/test_export_runtime.py -q
  EXPECT: passed
  EVIDENCE: See the resumed validation table above; synthetic/provider-fake checks only.

- [x] G3: Existing organization inventory, audit matching, digest privacy and checkpoint contracts continue to pass.
  CHECK: python -m pytest github/backend/cremore_github_provider/metadata/tests cremore/coverage/collector_runtime_test.py cremore/api/github_metadata_test.py -q
  EXPECT: passed
  EVIDENCE: See the resumed validation table above; synthetic/provider-fake checks only.

- [x] G4: Enterprise permissions and edition support are checked before collection and each collection purpose has its intended schedule.
  CHECK: python -m pytest cremore/onboarding/github_enterprise_test.py github/backend/cremore_github_provider/onboarding_export_test.py -q
  EXPECT: passed
  EVIDENCE: See the resumed validation table above; synthetic/provider-fake checks only.

- [x] G5: Manual and scheduled requests share Enterprise export limits and creation state across connections and restarts.
  CHECK: python -m pytest cremore/coverage/github_exports_test.py -q
  EXPECT: passed
  EVIDENCE: See the resumed validation table above; synthetic/provider-fake checks only.

- [x] G6: Access evidence scales through bounded continuation without presenting partial, public or historical evidence as a complete current reader list.
  CHECK: python -m pytest github/backend/cremore_github_provider/context_test.py cremore/governance/ownership_test.py -q
  EXPECT: passed
  EVIDENCE: See the resumed validation table above; synthetic/provider-fake checks only.

- [x] G7: The console exposes export progress, data age, quota waiting and independent schedules without introducing a manual CSV workflow.
  CHECK: node tests/run-browser-proofs.cjs console-github-export
  CWD: web
  EXPECT: 1/1 browser proofs passed
  EVIDENCE: See the resumed validation table above; synthetic/provider-fake checks only.

- [x] G8: Final integration, changed-file lint, typecheck/build and relevant browser checks prove the implemented requirements, with provider and operational limits documented honestly.
  EVIDENCE: See the resumed validation table above; synthetic/provider-fake checks only.

- [x] G9: Unidentified Export rows and issuing principals are visible as snapshot observations, never accumulated or advertised as unique credential counts across exports.
  CHECK: python -m pytest cremore/api/github_metadata_test.py -k snapshot_rows -q
  EXPECT: passed
  EVIDENCE: See the resumed validation table above; synthetic/provider-fake checks only.

- [x] G10: Old organization checkpoints resume with only the new default normalized; retired list checkpoints close with preserved evidence and an actionable fresh-collection reason before any I/O.
  CHECK: python -m pytest github/backend/cremore_github_provider/metadata/tests/test_checkpoint_migration.py -q
  EXPECT: passed
  EVIDENCE: See the resumed validation table above; synthetic/provider-fake checks only.

- [x] G11: Signed downloads and response headers remain absent from logs with debug logging enabled, while pinned TLS, bounded redirects and credential isolation remain enforced.
  CHECK: python -m pytest github/backend/cremore_github_provider/metadata/tests/test_export_runtime.py -q
  EXPECT: passed
  EVIDENCE: See the resumed validation table above; synthetic/provider-fake checks only.
