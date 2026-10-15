# Repository refactor plan

Baseline: `9d5dc8415544b265f6bacba23d950fc74009d549`, branch `refactoring`.
This is the pre-implementation map and plan. Completion and measured results
belong in `REFACTOR_REPORT.md`; intended changes below are not claims of completion.
The two project coding guides govern the work.

## Current Structure

The complete source inventory was read before implementation: 603 files,
138,165 physical lines. A second inventory covers 43 executable configuration,
schema and fixture files. The 4,214-pointer Atlassian response contract was read
through a lossless, reconstruction-checked rendering. Generated dependency locks,
historical benchmark output and documentation are separate from source counts.

| Boundary | Current owners and entry points | Consumers and contract |
| --- | --- | --- |
| Process composition | `cremore/cli/{api,worker,coverage}.py`, `api/app.py`, `worker/worker.py` | Installed `cremore-api`, `cremore-worker`, `cremore-coverage`; injected `create_app` factories and `app.state` |
| HTTP | `api/auth.py`, `api/http_support.py`, `api/dashboard.py`, `api/routes/`, presenters | `/api/v1` and coverage `/api/v2`; role gates, safe errors, route order, compatibility aliases |
| Domain/persistence | `domain/`, `db/repository.py`, `db/sql.py`, `db/schema.py`, stores | SQLAlchemy bound values; credential/exposure identity; memory/SQL parity; additive/offline migration rules |
| Content collection | `collectors/`, `worker/factory.py`, `source_config.py` | Bounded source readers; exact selected roots; immutable Git revisions; provider-specific absence evidence |
| Execution | `scanning/{scope,service,orchestrator,triggers}.py`, `worker/runtime.py`, `db/task_store.py` | Frozen plans, exclusive content slot, lease fencing, checkpoints, budgets, cancellation and safe retries |
| Detection/risk | `detection/`, `risk/`, `scanning/learned_fp.py` | Public engine models, stable catalog order/IDs, fingerprint/digest contracts; stored evidence and analyst decisions |
| Provider metadata | `coverage/collector_runtime.py`, models/stores, `coverage/providers/` | Explicit adapters for GCP, GitHub, GitLab, Atlassian/Bitbucket and Azure Key Vault; schema 1 passive hashes versus schema 2 metadata |
| AWS/provider access | `aws_access.py`, `aws_sessions.py`, `aws_readonly.py`, identity/discovery modules, `github_auth.py`, `gcp_auth.py` | Scanner and executor identity separated; existing endpoint/operation allowlists and independent capability gates |
| Investigation/actions | `investigation/`, `governance/`, `remediation/` | Observed/potential/declarative evidence separated; two-party/exact-hash approvals; uncertain writes reconciled, never retried |
| Secret storage | `secretstore/`, settings roots | AES-GCM v1/v2 read compatibility, old opener keys, Vault/KMS/environment roots; explicit GCP stored-value exception |
| Dashboard | `web/app/`, `web/features/`, `web/lib/`, `web/components/` | Existing Next.js server proxy and React client; TypeScript contracts, role/session invalidation, accessible dialogs, locale/theme |
| Independent collectors | `collectors/gitlab/collector_v1/`, `gcp-connector/` | Standalone CLIs/imports, native export schemas, filesystem/locking requirements; no dependency on platform internals |
| Packaging/operations | `pyproject.toml`, `web/package.json`, Compose, `deploy/helm/`, `scripts/` | One Python image; loopback local versus OIDC public setup; workload identity/secrets distribution; synthetic benchmarks |

Preliminary source totals: platform 54,017 lines, dashboard 25,688,
standalone GitLab 3,491, standalone GCP 1,923, deployment/tooling 3,863,
tests 49,183. Test totals include independent native GitLab QA storage/CLI
references (`coverage/providers/gitlab/tests/_qa_*.py`); the final report must
separate these references. Standalone packages remain separately usable products.

### Actual dependency directions

* Browser features use `lib/dashboard-api.ts` and the server proxy; Python owns
  authorization and domain decisions. Pure dashboard models currently import
  feature components, reversing this direction.
* API/worker composition supplies repositories, provider clients and settings.
  Route registrars use `DashboardContext`; `routes/sources.py` reaches back into
  `app.py` for credential sealing, creating an avoidable reverse dependency.
* Content execution uses scope/domain models, collectors and the repository.
  `scanning/triggers.py` reaches into `worker/runtime.py` for pure root identity;
  that identity belongs beside scope splitting.
* Metadata adapters emit typed pages. The worker performs network I/O before
  fenced persistence of records, counters and checkpoints. Provider resume
  semantics differ and cannot be flattened into one generic adapter.
* Static import cycles also include detection package exports, lazy verifier
  registration, native GitLab export/view type references, schema/store table
  registration, and provider provenance exports. These are not evidence of
  runtime failure. Preserve lazy public imports and registration ordering; remove
  a cycle only where its real dependency violates ownership.

## Problems

1. Composition roots and React views own reusable contracts/helpers, pulling
   lower layers and sibling features through unrelated entry points. AWS views
   also own GitHub/Notion inventory interfaces.
2. Repeated pagination, resource mappings, timestamp/error normalization and
   display helpers increase the number of places enforcing the same invariant.
   Independent reference implementations and deployable policy artifacts are
   deliberately excluded from automatic deduplication.
3. Confirmed correctness gaps include connection history sorting, request-value
   echoes on validation errors, settings writes before full validation, metadata
   checkpoint/accounting inconsistencies, and missing evidence reported as a
   changed value. Other review candidates require caller trace and a focused
   regression before changing behavior.
4. Concurrency-sensitive revision checks in governance/settings need review of
   the owning transaction/CAS, not another preflight check in an HTTP handler.
5. Dashboard defects include missing opaque dialog panels, stale asynchronous
   results, lost partial multi-start success, and failed history shown as empty.
   Some source-inspection tests are vacuous or cover an obsolete owner.
6. Documentation makes unsupported current-state/storage claims and contains
   stale provider, risk and workflow descriptions. Environment-injected secrets
   may remain in container configuration; saved observations are not fresh proof.

## Proposed Structure

Keep the modular monolith, installed dependencies, framework and existing
directory vocabulary. Work in independently verified boundaries:

1. **API ownership and validation.** Put connection credential ingestion in
   `api/connection_credentials.py`; put body/error HTTP concerns in
   `api/http_support.py`; separate finding route/presentation ownership from
   `api/app.py` using the existing route/presenter pattern. Validate complete
   settings updates before writes. Fix safe projections and history reads.
2. **Persistence and governance.** Use existing repository transactions/locks
   and compare-and-set patterns for revision-bound changes. Retain SQL/memory
   parity, audit atomicity, unique constraints and migration compatibility.
3. **Scanning, detection and risk.** Move pure root identity to `scanning/scope.py`
   and consolidate repeated resource selectors there. Bind resumable evidence to
   its policy. Reuse finding-level FP eligibility for immediate and rescore paths;
   retain analyst decisions. Verify bounded detection/redaction and conservative
   verification evidence with synthetic inputs.
4. **Provider collection.** Repair committed-cursor and spent-budget invariants
   in GCP/Azure/GitHub adapters. Preserve GitLab and Atlassian distinct replay
   contracts. Reuse existing fact/error/transport owners where semantics match;
   keep missing/invalid/partial distinct from absence. Consolidate standalone
   GCP pagination and bounded value decoding within `cremore_gcp` itself.
5. **Access, investigation and actions.** Reuse bounded safe provider errors;
   require complete readback for absence. Verify rotation drift and uncertain
   outcomes with fake clients; preserve all approval and execution gates.
   Validate Vault responses/references and accurately describe storage roots.
6. **Dashboard.** Move pure contracts/projections from views to existing `lib/`
   or feature model owners, keeping compatibility exports where consumed. Give
   GitHub/Notion inventories their provider ownership. Reuse the existing modal
   primitive for opaque, scrollable content surfaces with focus/Escape/dirty-close
   preservation. Repair loading/error/partial-success state and evidence wording.
   Scope CSS by responsibility; preserve theme variables and compiled Tailwind.
7. **Completion.** Remove proven dead imports/branches and duplicate enforcement;
   repair inaccurate verification subjects. Update README, architecture/operator
   claims, `AI_TEAM_CODING_GUIDE.md`, and the required 14-section report. Measure
   real duplication/dependency changes separately from file moves and test growth.

## Import Changes

| Existing consumer | Intended owner | Compatibility |
| --- | --- | --- |
| `api.routes.sources -> api.app.connection_secret` | `api.connection_credentials.connection_secret` | Re-export old app name |
| App-local body middleware/exception formatting | `api.http_support` | Same middleware behavior and public error envelope |
| `scanning.triggers -> worker.runtime.root_identity/split_roots` | `scanning.scope` | Re-export worker names; stable root IDs |
| `web/lib/dashboard-{types,loader} -> feature React modules` | Pure model/projection owners | Retain consumed exports and fixtures |
| Overview/findings -> rules UI workflow helpers | Finding model/view owners | Retain imports used by existing consumers/tests |
| Standalone GCP repeated page/decoding loops | Existing transport/value boundary in `cremore_gcp` | Native CLI/export behavior preserved |

New helpers must have actual callers and own an invariant. No public package,
plugin framework, generic registry or new dependency is planned merely to reduce
line count. Moving code alone is not recorded as a size optimization.

## Public API

Preserve CLI names/options, Python factory signatures, route order and paths,
response identities, schema versions, environment names, catalog IDs/order,
fingerprint/crypto formats, provider origins/permissions, native export formats,
exact approval hashes, and persisted job/task/scope identities. Safe failures,
truthful partial/unknown states and rejection of malformed inputs are intentional
corrections; document them beside their regression evidence.

No live provider scans, discovered-credential checks, deployments or cloud
mutations are part of validation. Rotation/action proofs use synthetic clients.

## Validation

Established baselines: main Python 4,669 passed / 70 skipped / 266 subtests;
dashboard 469 unit tests, build and TypeScript passed; 20 synthetic browser
proofs passed; standalone GCP 39 passed. Standalone GitLab on supported POSIX
Python 3.10: 161 passed, one SQLite authorizer test-cleanup error. Preserve its
read-only assertions and correct only the cleanup compatibility issue.

Run focused regressions before/after each ownership change, then:

* `python -m pytest cremore/ -q -ra` with `AWS_EC2_METADATA_DISABLED=true`.
* Configured Ruff checks; report baseline violations separately. No configured
  Python type checker exists; do not claim one ran.
* In `web`: `npm test`, `npx tsc --noEmit`, `npm run build`,
  `npm run test:browser`. There is no configured ESLint script.
* Standalone packages: `python -B -m unittest discover -s tests -v` in each
  package root, using POSIX for native GitLab private-file/locking proofs.
* Actual Helm/Compose rendering with the repository's pinned tooling where
  available; report Docker availability and platform skips explicitly.
* Synthetic browser checks with the full compiled stylesheet stack: light/dark,
  narrow/wide viewport, modal opacity/scroll/focus, stale reads, denied/unavailable
  evidence, partial accepted runs, safe rendered external data.
* Public imports, package build, example/contract consistency, source metrics,
  `git diff --check`, safe error/output and secret-boundary review.

Final results distinguish passed, failed, unavailable and not applicable. Update
the final documents from executed evidence, commit and push `origin/refactoring`,
then verify its remote commit. Until those steps finish, the refactor is active.
