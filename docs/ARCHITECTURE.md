# Architecture

The platform finds leaked credentials in the places an organisation keeps its
work (S3, Google Cloud Storage, Azure Blob Storage, GitHub, GitLab, Bitbucket, Azure DevOps Repos,
Notion and Confluence), explains each finding from evidence, checks exposed and issued credentials against
the organisation's vaults, and supports approval-gated remediation. Shared Python code lives under
[`cremore/`](../cremore/), with provider libraries in top-level vendor directories.
The Next.js host lives under [`web/`](../web/) and imports provider UI libraries. The product is
distributed under Apache-2.0 (see [`LICENSING.md`](../LICENSING.md)).

## Components

```
                ┌──────────────┐   /api/backend/* → /api/v1/*   ┌──────────────┐
   browser ───▶ │  web (Next)  │ ─────────────────────────────▶ │  api (Py)    │──┐
                └──────────────┘                                └──────────────┘  │
                                                                   ▲               │ Postgres
                        connections / scan jobs / findings         │               │
                                                                ┌──────────────┐  │
                          S3 · GitHub · Notion  ◀── collectors ─│ worker (Py)  │──┘
                                                                └──────────────┘
```

| Module | Responsibility |
| --- | --- |
| `cremore/detection/` | Detection engine: bounded decoders → keyword routing → matching/context checks → validators → redaction/fingerprint → false-positive policy → dedupe. Definitions live in `catalog.py` with their source documents; `ENGINE_EPOCH` binds passive cache semantics. Optional verification is separate in `verify/`. |
| `cremore/risk/` | Evidence-based risk model v6: exploitability 35 / credential impact 30 / privilege scope 20 / exposure 15. Unknown evidence gets a small floor, never a midpoint. Every score carries its evidence and overrides. |
| `cremore/collectors/` | Shared bounded HTTP, request budgets, collection lifecycle and scoped composition, plus compatibility imports. Provider content operations live in the vendor backend libraries. |
| `<vendor>/backend/cremore_<vendor>_provider/` | Provider configuration, authentication, content collection and catalogs where supported. AWS owns S3 list/delta/Inventory, GitHub owns pinned tree/blob/archive collection, and Notion owns approved page traversal. Metadata adapters live in the provider's `metadata/` directory. |
| `cremore/scanning/` | Orchestration: detect → score → persist, deduplicated by fingerprint; a finding is the credential-level rollup at its highest-severity exposure. |
| `cremore/domain/`, `cremore/db/` | Domain models, atomic upserts and deterministic finding rollups; normalized root catalogs, leased tasks, root checkpoints and disposable masked caches. PostgreSQL is the operational database; SQLite/in-memory paths are test adapters. Startup adds schema under an advisory lock; populated legacy installations require the explicit offline version-2 migration. |
| `cremore/api/` | FastAPI: findings, connections, scan jobs, governance (reviews, assignment, audit trail), management actions, rotation, AWS inventory, and the dashboard read contract. Auth in `auth.py` (local token or OIDC + role gating). |
| `cremore/worker/` | Existing DB queue: parent runs and root tasks, SKIP LOCKED claims, priority, lease/heartbeat/retry/fenced commits, optional schedules/events, bounded rescoring/cache maintenance, refreshable AWS role credentials. |
| `aws/backend/cremore_aws_provider/investigation/` | Read-only AWS investigation: IAM `SimulatePrincipalPolicy` over a curated high-impact action set (feeds the privilege axis) and a Secrets Manager inventory that never reads secret values. `cremore/investigation/` remains a compatibility import path. |
| `cremore/remediation/`, `aws/backend/cremore_aws_provider/remediation/` | The platform owns action plans and approval state; the AWS library owns provider execution and two-phase key rotation (PREPARE: create + stage + validate successor; PUBLISH: promote). Two-party control is enforced by the API and again inside the service; a single shared-token operator may self-approve an action plan after explicit re-confirmation, recorded as `self_approved`. |
| `cremore/secretstore/` | AES-256-GCM v2 seals and legacy v1 reads, opening-key rotation and reference resolution. Sealing roots are selected by configuration: Vault, KMS, passphrase, explicit key, then fingerprint-key fallback. Vault/OpenBao KV operations live in `vault/backend/cremore_vault_provider/secretstore.py`; KMS operations live in `aws/backend/cremore_aws_provider/kms.py`. The API receives its own narrowly scoped store authentication only when it must obtain a Vault sealing root. |
| `cremore/coverage/` | Separate schema 1 passive coverage and schema 2 metadata contracts, registry, runtime and persistence. GCP, GitHub, GitLab, Atlassian/Bitbucket and Azure Key Vault adapters in vendor libraries retain provider-specific evidence and replay semantics. Collected values remain in memory; only keyed fingerprints and necessary metadata persist. |
| `github/backend/cremore_github_provider/github_auth.py` | GitHub App JWT and short-lived installation-token issuance. Tokens are cached in memory and refreshed before expiry; `cremore/github_auth.py` remains a compatibility import path. |
| `cremore/sources/` | Explicit content-source registry, shared validation and compatibility imports. Provider-owned `source.py` modules supply configuration, job conversion, collector construction and resource discovery. The registry feeds API catalog and worker routing without importing runtime clients. Approval, credential protection and persistence policy stay in their existing owners. |
| `cremore/siem/` | Immutable first-finding events saved atomically with findings; per-destination delivery leases; versioned output adapters. Separate `cremore-siem` process reads only event/delivery tables and does not receive scanner credentials. |

API assembly injects the dependencies actually consumed by each route through
`DashboardContext`. The schema owns catalog table objects; catalog stores do not
register themselves by a reverse schema import. Pure task checkpoint validation
lives in `cremore/task_state.py`, so metadata contracts do not import SQLAlchemy.
Provider-independent path containment belongs to `collectors/base.py`; custom
detection-policy projection belongs to `detection/custom.py`.

Content-source configuration and construction live in each vendor backend's
`source.py` (Atlassian has `bitbucket_source.py` and `confluence_source.py`).
Vendor folders hold no UI: the console (`web/console/`) draws each connection
wizard from the provider's onboarding descriptor (`GET provider-connections/catalog`),
and keeps what a provider needs beyond that (its setup guide, words, logo) in
`web/console/views/integrations/`. The explicit registry remains
`cremore/sources/registry.py`. Existing source and collector
import paths remain compatibility facades; new provider behavior belongs in the
owning library. New authentication,
resource semantics, public response recognition and persistent job kinds still require
platform integration; adding a folder alone does not grant execution support.

The vendor owners are `aws/`, `gcp/`, `github/`, `gitlab/`, `notion/`, `atlassian/`,
`azure/` and `vault/`. Only supported capabilities have implementations: Azure
uses the console's shared metadata screens, and Vault/OpenBao owns credential-store operations.
The libraries ship in one Python wheel and one Next.js app, without per-provider
services or dependency installations. `gcp/standalone/cremore_gcp` is the GCP
library the product reuses; the independent GCP and GitLab CLIs were removed.

Metadata presentation descriptors live beside each provider; the existing explicit
adapter registrations compose their ordered catalog. `CollectorRuntime.compare_records`
uses before/after order, with provider-owned bridges preserving native comparison APIs.
Collection contracts and
approval checks remain separate from outbound SIEM plugins. The SIEM registry
loads only installed, explicitly enabled output packages using
`cremore.siem_sinks` entry points. See [SIEM integration](SIEM_INTEGRATION.md)
for delivery guarantees, plugin contracts and upgrade/rollback steps.

The console has one stylesheet, `web/app/(console)/console.css`: its tokens on `:root`, redefined for dark mode,
loaded by the console's root layout and by the synthetic browser proofs. See the [team guide](AI_TEAM_CODING_GUIDE.md)
for public entry points, extension recipes and verification commands.

## Data flow and the secret boundary

Verification is durable evidence, separate from dashboard login and collector
sessions. Passive scans preserve the last check, its provider facts and its
original check time. A failed attempt retains the previous conclusive result;
an inconclusive retry alone cannot lower a previously confirmed active key's
exploitability score. The UI shows the failed attempt and historical basis
separately. A recorded rejection or elapsed provider expiration changes the
assessment. List, detail and background rescoring share the same saved-evidence
interpretation. Legacy records without an actual check timestamp say so; content
`last_seen_at` is never displayed as a verification time. Display and rescoring
make no provider calls. Fresh authentication still needs the original material,
which is not stored: the existing exact-location rescan can re-read one approved
location without sweeping the whole source.

1. A **connection** describes *where* to scan (bucket, owner/repo, org). Its
   credential lives in `secret_ref`: a `vault://<path>` pointer, or a token the
   API sealed (`sealed:v2:<key_id>:`, AES-256-GCM under an HKDF key from
   `SEALING_KEY`, which defaults to `FINGERPRINT_KEY`) and never returns. The
   `key_id` names the master that sealed it, so an installation can hold more
   than one and rotate between them; `sealed:v1:` is still read. That master can
   instead live in AWS KMS (`SEALING_KMS_KEY_ID` + `SEALING_KEY_CIPHERTEXT`),
   leaving only a ciphertext here. The worker
   resolves it at scan time and keeps the plaintext in memory only. The API
   rejects a connection `config` that carries secret-looking keys.
2. A **scan job** is queued (API) and claimed atomically (worker). The
   collector yields objects; the engine scans each. A job ends `SUCCEEDED`
   (everything listed was read), `SUCCEEDED` with `objects_failed > 0` (shown as
   **PARTIAL**: listed but unreadable objects), or `FAILED` with a stable code
   when the scope itself could not be listed (`S3_LIST_FAILED`,
   `GITHUB_TREE_UNAVAILABLE`, `GITHUB_ORG_LIST_FAILED`, `NOTION_SEARCH_FAILED`).
   A run that never saw its scope is never reported as a clean, empty result.
   Only safe error codes and exception class names are reported; raw provider
   error bodies are not a supported logging or persistence surface. Two further job kinds share the queue:
   `catalog-refresh` (a metadata-only listing into the connection's scan-scope
   catalog) and `scope` (one collector per approved root — bucket prefixes or
   exact keys, a repository at a pinned ref with path roots or exact paths,
   exact Notion page ids — under the profile's byte / request / time budgets,
   with observed coverage counters). Approved roots become durable tasks with
   fixed shares of the run budget. Different roots can run on separate workers;
   same-target execution is serialized. Results, audit, reconciliation and
   checkpoints commit under the current task lease. `count_basis` is
   `COMMITTED_OBJECT_ATTEMPTS`: retries can process an object again, so this is
   not a count of globally unique assets.
3. Inside the engine the raw match exists only long enough to be fingerprinted
   (HMAC with the installation's `FINGERPRINT_KEY`), masked into an
   `identifier_hint` (prefix/suffix only), and — when verification is enabled
   — sent once to the issuing provider. The `SanitizedDetection` that leaves the
   engine contains no secret material. GCP management-API value reads likewise
   persist no raw or reversibly encrypted values. Their private HMAC change
   evidence covers binary and empty payloads; only matching scheme and key
   identities permit comparison. The former raw-value store and read API are
   retired; existing installations require [explicit cleanup](integration/GCP_TOTAL_GUIDE_KO.md#과거-원문-저장-설치의-이관).
   Provider authentication credentials follow the separate sealing contract in step 1.
4. The risk model scores each exposure from evidence (verification status,
   provider scopes / IAM simulation, exposure level, occurrences) and records
   the reasoning; findings roll up to the highest severity.
5. Exposure presence and credential remediation are separate. A fully read
   current object can retire missing detections in any scan mode; an
   authoritative complete listing can additionally establish missing paths.
   Notion search omissions/404 and legacy collector epochs cannot establish
   absence. Removed locations set `all_locations_removed`; they do not
   automatically resolve a finding or prove credential revocation. Stored
   evidence can be rescored in bounded batches; missing historical facts keep
   the old score and require a rescan. Analyst decisions remain intact.

## Trust boundaries

AWS identity approval writes the identity, actor and increasing revision in one
repository operation (`aws_access.save_approval` / `put_revisioned_setting`).
Memory uses its existing lock; SQL creates or locks the setting row inside one
transaction. Scanner and remediation revisions remain independent. Reading a
revision and later overwriting a setting is not a valid approval path.

| Boundary | Control |
| --- | --- |
| Browser ↔ web | Helm: Ingress TLS and OIDC via the oauth2-proxy sidecar. Compose: loopback-only ports and a shared token the server-side proxy attaches only for loopback Host headers or `CREMORE_ALLOWED_HOSTS` (DNS-rebinding defense). |
| web ↔ api | Same `/api/v1` contract over in-cluster TLS; the API validates the bearer token itself (JWKS, issuer, audience, expiry, subject) and maps groups → roles. Mutations require `analyst`, connection/account administration `admin`, executing actions `remediator`. |
| api/worker ↔ providers | Provider verification is **on by default** and an Admin switches it in the dashboard (`CREDENTIAL_VERIFICATION_MODE=disabled` locks it off). Every mutating action is **off by default** and a separate environment opt-in (`ACTION_ROTATION_ENABLED`, `ACTION_EXECUTION_ENABLED`). The three read-only AWS investigations are also off by default, but an Admin switches them in the dashboard (`*_MODE=disabled` locks one off). NetworkPolicy limits egress to DNS, PostgreSQL and the configured HTTPS ranges. |
| Persistence | Discovered secrets: only fingerprints, masked hints, locations and redacted lines. Connection tokens: a `vault://` pointer or an AES-256-GCM sealed value that the API never returns. Rotation jobs persist key *identifiers* only. |
| Two-party control | Management-action confirmation and rotation approval/publish require an independent identity. The action-plan flow permits a local shared-token operator to self-approve only after explicit re-confirmation, recorded as `self_approved`; its other execution gates still apply. |

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | local Postgres | `postgresql+psycopg://…` (plain `postgresql://` is normalised) |
| `AUTH_MODE` / `API_TOKEN` | `local` | `local`: one shared token of at least 32 characters (no per-user roles). `oidc`: needs `OIDC_ISSUER_URL` and `OIDC_AUDIENCE`; `OIDC_GROUPS_CLAIM` (any claim, e.g. `groups`, `roles`, `email`) is matched against `OIDC_{VIEWER,ANALYST,REMEDIATOR,ADMIN}_GROUP`; empty roles grant nothing. Transport (API TLS, DB `sslmode`, issuer scheme) is the installer's choice. The Helm chart renders `oidc` |
| `API_BIND`, `TLS_CERT_FILE`, `TLS_KEY_FILE` | `127.0.0.1:8080`, unset | Bind address and optional in-process TLS |
| `FINGERPRINT_KEY` | unset (required) | Hex HMAC key, at least 32 random bytes, for installation-scoped fingerprints; API and worker refuse to start without it |
| `AWS_REMEDIATION_PROFILE` | unset | AWS CLI profile the API uses for approved key actions (the separately approved remediation identity); unset = the default sign-in |
| `AWS_SCANNER_PRINCIPAL_ARN`, `AWS_ONBOARDING_TEMPLATE_URL` | unset | Both optional and independent. Onboarding trusts the runtime AWS identity an Admin approves in the dashboard; `AWS_SCANNER_PRINCIPAL_ARN` instead pins an exact role ARN for server installs, and a template S3 URL adds a CloudFormation quick-create link beside the CLI command |
| `CREDENTIAL_VERIFICATION_MODE` | `enabled` | Provider verification of discovered credentials (active/rejected/restricted plus non-secret facts). `enabled` lets an Admin switch it on/off in the dashboard (stored in `installation_settings`, read when each scan starts; on by default); `disabled` locks it off |
| `IAM_POTENTIAL_ACCESS_MODE`, `AWS_SECRETS_INVENTORY_MODE`, `AWS_USAGE_LOOKUP_MODE` | `enabled` | Allows each read-only AWS investigation (IAM simulation, Secrets Manager inventory and metadata, CloudTrail/IAM observed use), or `disabled` to hard-lock one off. All three are off until an Admin switches them on in the dashboard (`/settings/aws-investigations`), which is where an analyst needs them mid-investigation |
| `ACTION_EXECUTION_ENABLED`, `ACTION_DELETION_ENABLED`, `ACTION_ROTATION_ENABLED` | `false` | Execute approved, hash-bound IAM key action plans (disable / delete inactive key / rotation phases). Deletion needs both of the first two |
| `ROTATION_SECRET_ARNS`, `ACTION_PLAN_TTL_HOURS` | unset / `24` | Secrets Manager ARNs a rotation plan may bind to; how long an unapproved or unexecuted plan stays actionable |
| `SECRET_MANAGER_ALLOWED_REFERENCES` | unset | Secrets Manager ARNs an Admin may declare as a credential's storage location (a "possibly stored here" mapping; metadata reads only, never the value) |
| `LEARNED_FP_MODE` | `enabled` | Allows auto-triage of learned false positives, or `disabled` to hard-lock it off. The switch and its policy (threshold, sample floor, confidence ceiling) are set in the dashboard (`/settings/learned-false-positives`), where they are visible and each change records its author; `LEARNED_FP_THRESHOLD`, `LEARNED_FP_MIN_SAMPLES` and `LEARNED_FP_MAX_CONFIDENCE` remain optional pins. Verified, public and above-ceiling-confidence detections are never auto-triaged |
| `SECRET_STORE_URL` / `SECRET_STORE_MOUNT` | unset / `secret` | OpenBao/Vault KV v2 for `vault://` connection references |
| `SECRET_STORE_AUTH_MODE` / `SECRET_STORE_TOKEN` | `token` / unset | Backward-compatible static Vault token mode (worker only) |
| `SECRET_STORE_KUBERNETES_ROLE` / `SECRET_STORE_KUBERNETES_AUTH_MOUNT` / `SECRET_STORE_KUBERNETES_TOKEN_FILE` | unset / `kubernetes` / `/run/cremore-vault/token` | Renewable Vault/OpenBao login with a projected, audience-bound Kubernetes service-account token |
| `WORKER_HEARTBEAT_FILE` | `/tmp/cremore-worker.heartbeat` | Touched every poll; Kubernetes exec probe checks its age |
| `SIEM_EVENT_RETENTION_DAYS` | `0` | Days a SIEM event every active destination received is kept (0 keeps finding and connection events). Heartbeats and test events always go after 7 days |
| `OPERATIONS_HEARTBEAT_MINUTES` | `5` | How often one worker queues `platform.heartbeat` for the SIEM (1–60). Every worker also records a database beat each minute, shown by `/operations/status` |
| `MAX_OBJECT_SIZE_MB` / `MAX_INPUT_BYTES` | `50` / `8388608` | Per-object content and inline API input bounds; approved scope budgets can be smaller |
| `SCAN_SCHEDULES_MODE` | `enabled` | Allows the worker to run approved scopes on their schedules (incremental `schedule_minutes`, and full scans at `full_scan_minutes` or the installation default, daily at 02:00 KST unless an Admin changes it), or `disabled` to hard-lock it off. The switch is an Admin's, in the dashboard (`/settings/scan-triggers`), and is on unless switched off |
| `SCAN_INVENTORY_MANIFESTS` | `{}` | Optional: fixes every S3 Inventory report binding (`connectionUUID/bucket` to an exact `manifest_bucket`/`manifest_key`) for the installation. Otherwise an Admin sets them in the dashboard (`/settings/inventory-manifests`), which is where the person who knows which report belongs to which bucket is working |
| `SCAN_SQS_MODE`, `SCAN_SQS_QUEUE_URL`, `SCAN_SQS_PROFILE_ID`, `SCAN_SQS_DEDICATED_ACKNOWLEDGED` | `enabled`, unset, unset, `false` | One operator-confirmed dedicated AWS SQS queue; normalize mutation signals and ACK only after durable enqueue. The mode allows consumption or hard-locks it off; the switch, queue URL, bound profile and the acknowledgement that the queue is CreMore's own are set in the dashboard, and each value here pins its own field. A binding that is incomplete reads as off rather than failing on delivery |
| `SCAN_INVENTORY_MANIFESTS` | `{}` | Exact `connection_uuid/bucket` to existing `manifest_bucket`/`manifest_key` JSON binding; CSV Inventory report-only acceleration, never automatic bucket configuration |
| `SCAN_PUBSUB_MODE`, `SCAN_SERVICEBUS_MODE` | `enabled` | Allow reading the customer's own Pub/Sub subscription or Service Bus queue/topic subscription like the SQS queue, or hard-lock it off. The address, bound profile and dedicated acknowledgement are set in the dashboard ([change feeds](CHANGE_FEEDS.md)) |
| `SCAN_CHANGE_FEEDS_MODE` | `enabled` | Allows change feeds on approved repositories and spaces (GitHub, GitLab, Azure DevOps, Bitbucket, Confluence), or hard-locks them off. The switch and per-provider minutes are an Admin's |

The new `SCAN_*` settings are application environment variables, not automatically
forwarded by every Compose/Helm template. Inject them explicitly into the relevant
API/worker processes through an operator-reviewed deployment configuration.
See [the operator runbook](SCANNING_IMPLEMENTATION.md) for executable examples,
limits and the offline upgrade/rollback procedure. Kubernetes is optional; it is
the supplied production deployment template, not a scheduler dependency.

## Incremental execution and evidence

Public `/scan-runs` modes are `BASELINE`, `DELTA`, `RECONCILE`, and S3-only
`INVENTORY`. `EVENT` and `POLICY_SWEEP` are internal triggered modes. Each public
run consumes a fixed preview, bound to the profile version and authorization
revision; changing the run mode requires a new preview. Selection filters freeze
current catalog root IDs, not an expanding expression granting future access.

- S3 delta lists the approved prefix and filters by `LastModified` against a
  scan-start watermark with a five-minute overlap. Failed/skipped keys are
  retried even with older timestamps. Retry metadata is bounded by key count
  and serialized bytes; overflow remains sticky until a complete recovery
  sweep. A changed detection policy restarts checkpoint traversal without
  resetting consumed budgets. This saves downloads, not LIST calls.
  Ordinary list revisions use ETag/size/LastModified; a supplied VersionId can
  supplement the observation without issuing a HEAD per listed object.
- Existing Inventory manifests reduce repeated source listing for that report.
  They are delayed, may be prefix-filtered, and do not advance normal root
  watermarks. `INVENTORY_REPORT_ONLY` is never whole-bucket coverage. Missing
  known finding paths need a current-state check, and ordinary reconciliation
  remains necessary.
- GitHub fixes the run to a commit, compares blob SHA through a bounded tree,
  and caches passive engine output **before** path policy. A renamed file can
  reuse even an empty result and reapply current path/risk/FP rules. Approved
  whole-repository baselines may use a streaming tarball; each file must match
  its Git blob SHA, otherwise the blob API supplies it. No extracted files,
  cross-origin credentials, submodule traversal or historical-commit scan.
- Notion child pages/databases are boundaries, not parent-body text. Approved
  child page IDs are independent tasks. Modified-time overlap reduces stale
  reads but cannot make the Notion search index a complete inventory.
- Cache keys are scoped by connection/source root, revision and engine digest;
  source/path rule changes affect the root policy digest and schedule a
  low-priority resweep of already scanned approved roots. Severity/risk/learned
  FP changes rescore stored evidence rather than invalidate all source data.
  Explicit live verification bypasses passive cache reuse.
- Events mean “inspect current state”, not “trust this event revision”. Only
  queued tasks coalesce; a running task receives a bounded queued successor.
  At most 256 exact hints are kept, then the task becomes approved-root DELTA.
  Receipt dedupe and a finite debounce prevent indefinite postponement, but do
  not promise real-time processing under a saturated worker queue.

AWS investigation snapshots are saved observations, independent of the dashboard
login and the scanner's current AWS session. A sign-in failure before or during
usage refresh returns `409 AWS_LOGIN_REQUIRED` and leaves the existing usage,
IAM policies, key metadata and collection timestamps unchanged. This applies to
region discovery, CloudTrail reads, IAM simulation, policy reads and last-used
metadata; an error inside an observed CloudTrail event is not a scanner error.
The IAM panel identifies stored errors as belonging to the displayed collection
time. `AccessDenied` means the scanner's read was denied, not that the discovered
key is invalid or that a session expired. The Identity Center permission-set
policy includes the same policy-document read actions as the scanner-role
templates. Existing AWS permission sets need an operator-applied policy update;
upgrading CreMore does not alter IAM permissions or erase historical denials.

## Dashboard support matrix

The Next.js dashboard was designed against a wider contract than this API
implements. Every `/api/v1` path the API does not serve answers **501** with an
`error` explaining so (never a bare 404), and the affected panel shows that
reason. What works today:

| Dashboard area | Status | Backed by |
| --- | --- | --- |
| Session, roles (Viewer/Analyst/Remediator/Admin) | works | `GET /session` (local token = Admin; OIDC groups → role) |
| Overview, findings list/detail, acknowledge/resolve/reopen/assign, false-positive, ignore | works | findings, events |
| Ownership review (responsible team, due date, status; bulk update with revision guard) | works | `GET /findings/{id}/ownership-review`, `POST /ownership-reviews/bulk` (CODEOWNERS candidates from the finding's context) |
| Exposure context: each exposed file's CODEOWNERS owners and last commit author, and the repository's collaborators or project members (GitHub, GitLab); the last editor or commit author of an exposed Notion or Confluence page and of a Bitbucket or Azure DevOps file | works | `finding-context` job (the worker queues open findings with none, or one older than 7 days, every 10 minutes), `GET/POST /findings/{id}/context` (Analyst); credential rows carry names and counts only |
| Detection policy: engine identity, 867-detector catalog, **custom regex rules** (create/edit/delete, sample and synthetic-fixture tests, scope by source/globs/exclusion words, operator severity) | works | `/rules`, `/rules/{id}/test`; rules compile into the engine per job and are reported under the `custom` provider |
| Connected sources: register (S3 bucket[/prefix], GitHub owner/repo, organization or personal account, Notion) with an optional `vault://` reference, queue scan, job list, cancel queued job, **credential check** (GitHub PAT `/user` or App `/installation/repositories`, Notion `/users/me`, STS + `HeadBucket`) | works | `POST /source-connections`, `POST /source-connections/{id}/scans`, `POST /source-connections/{id}/credential/check`, `GET /source-scan-jobs` |
| Operational status: authentication, worker queue/activity and failed/partial jobs, with safe alert codes only | works (Admin) | `GET /operations/status`; Pod availability remains a Kubernetes readiness/liveness and Deployment metric |
| Connection health: one vocabulary for content, vault/metadata and AWS account connections (authentication, renewal, provider or operator expiry with 14/3-day stages, last success/failure, freshness) | works | `GET /operations/connections`, `PUT /operations/connections/{key}/expiry` (Admin, audited); console `?view=operations` |
| SIEM delivery operations: destination status, backlog, held events, test event; worker liveness | works (Admin) | `/siem/status`, `/siem/test-event`, `/siem/events/{id}/deliveries`, `/siem/destinations/{id}/release-held`; console `?view=operations` |
| Rescan outcome: proven missing locations retire exposures; finding presence is shown separately and never implies key revocation. Historical `REMOVED_BY_RESCAN` resolutions can reopen on reappearance; manual decisions remain intact | works | object/list evidence reconciliation and deterministic rollup, `all_locations_removed` |
| Connecting a provider | API (dashboard with the redesign) | `/api/v1/provider-connections`: one credential per provider shared by every purpose, four steps, owned records re-pointed on a credential change ([ONBOARDING.md](ONBOARDING.md)) |
| Accounts: approve the runtime AWS identity (API and worker must match; Identity Center permission set, IAM role or IAM user), register one or many accounts through one AWS provider connection, per-account CloudFormation CLI command (optional quick-create link), worker-run role validation (STS assume + account check), `AWS_LOGIN_REQUIRED` / `AWS_SCANNER_IDENTITY_CHANGED` holds that defer AWS tasks without spending retries; account discovery from AWS Organizations (`aws/backend/cremore_aws_provider/aws_org_discovery.py`, Control Tower included -- registered OUs scope it) or from the operator's IAM Identity Center assignments (`aws/backend/cremore_aws_provider/aws_sso_discovery.py`) | works | `/aws/scanner-identity`, `/aws/accounts/onboarding`, `/aws/accounts/discoverable`, `/aws/accounts/bulk`, `/aws/accounts/{id}/validate` |
| Account routing: investigations (observed use, potential access, Secrets metadata/inventory) and key actions open a session in the account they concern (`aws/backend/cremore_aws_provider/aws_sessions.py`); purpose-scoped validation revisions with compare-and-set results (`aws/backend/cremore_aws_provider/aws_access.py`); three access modes -- `ROLE` (member role + ExternalId), `RUNTIME_IDENTITY` (the identity's own account) and `SSO_PERMISSION_SET` (IAM Identity Center vends the account's credentials, nothing deployed, scanner only, requiring a writable interactive-login cache, pinned to the approved directory); separate remediation identity; unverified legacy evidence | works | `/aws/remediation-identity`, `/aws/accounts/{id}/validate?purpose=`, `/aws/accounts/{id}/promote`, `/credentials/{id}/usage/refresh` |
| Connection governance: administrator declaration, capability projection | works (declared only; nothing is probed, `supported` is always false) | `GET /connections`, `/connections/{kind}/{id}/{capabilities,profile}` |
| Audit log | works | finding events (`GET /audit`) |
| Governance reviews, management actions (two-party), rotation (two-phase, two-party) | works | own models |
| Observed use (CloudTrail event history per region, IAM last-used, curated IAM potential access) | works when an Admin switches observed use on (+ potential access) | `GET/POST /credentials/{id}/usage[/refresh]`; coverage is reported per region and never claimed complete on failure or cap |
| Approved action plans: disable key, delete inactive key, prepare/publish rotation — hash-bound, independent Admin approval, operational-readiness gate, write-then-read-back, `OUTCOME_UNKNOWN` is rechecked never retried | plans + approval always; execution when `ACTION_EXECUTION_ENABLED` (+ `ACTION_DELETION_ENABLED` / `ACTION_ROTATION_ENABLED`) | `/credentials/{id}/action-plans`, `/action-plans/{id}/{approve,execute,recheck,cancel}` |
| Secrets Manager inventory | works when an Admin switches the secrets inventory on | read-only `ListSecrets` |
| Learned false-positive profiles | works when an Admin switches it on | per-scope profiles learned from analyst false-positive decisions (redacted path / line-shape features only); an active profile auto-triages repeats with an audit event, reopening contradicts it — see [LEARNED_FALSE_POSITIVES.md](LEARNED_FALSE_POSITIVES.md) |
| Connection: stop using (disable + withdraw queued work, provider revocation guidance), verification-history ledger (requested / claimed / ended), blast radius (resources and findings reached through the connection) | works | `/source-connections/{id}/credential/revoke`, `/verification-history`, `/blast-radius` |
| Optional secret-manager mapping: allowlisted Secrets Manager ARN declared per credential (a "possibly stored here", never a value match) with metadata-only reads (`DescribeSecret`; tags/description omitted by policy) | works when `SECRET_MANAGER_ALLOWED_REFERENCES` is set (+ the secrets inventory switched on, for reads) | `GET /secret-managers`, `/credentials/{id}/management[/metadata]` |
| Scan-scope selection: metadata-only root catalog, frozen selection drafts, Admin-approved versioned profiles, includes/excludes/priority/budgets, fixed previews, observed coverage, exact-location rescan | works | `/connections/{kind}/{id}/resources[...]`, `/scan-scope-profiles`, `/selection-drafts`, `/scan-runs`, `/findings/{id}/rescan[-profiles\|-preview]`. Worker schedules/events execute only when separately configured; preview otherwise warns `SCHEDULE_NOT_CONFIGURED` / `EVENTS_NOT_CONFIGURED` |
| Persistent connection "investigation" | 501 | not implemented (content is scanned directly by the queued job) |
| Internal tickets / playbooks | works | `/tickets`, `/governance/playbooks` — operator declarations; CUSTOM playbooks freeze conditions and an independent-Admin approval rule at creation |

## Known limitations

- **Verification coverage**: 867 detectors but 64 verification rules — most
  label-gated detectors have no stateless "who am I" endpoint. Unverified
  findings are floored at MEDIUM by the risk model rather than guessed.
- **Rotation scope**: only AWS IAM access keys stored in Secrets Manager. Old
  keys are never disabled by rotation; that is a separate approved step. The
  secret's AWSCURRENT value must be a JSON object whose `AWS_ACCESS_KEY_ID` is
  the old key; the successor version replaces `AWS_ACCESS_KEY_ID` and
  `AWS_SECRET_ACCESS_KEY` and keeps the object's other fields.
- **Dashboard depth**: see the support matrix above. Connection capability
  projections are declarations and do not call providers. Scanning, resource
  discovery, verification, investigations and approved actions have their own
  provider-access paths and gates.
- **Collectors** are read-only and bounded. Arbitrary ZIP/gzip/encrypted object
  contents are not unpacked; they are unsupported coverage, distinct from the
  verified GitHub transport tarball. Glacier `InvalidObjectState` is
  `SKIPPED_ARCHIVED`; `GLACIER_IR` remains readable. Submodules, Git history and
  old S3 object versions are not comprehensively scanned.
- **Customer isolation**: OIDC roles and repositories are installation-scoped.
  A provider tenant identifier describes observed provider data; it is not a
  customer isolation boundary. Shared SaaS hosting needs a separate tenancy,
  authorization, key separation and queue-fairness design.
- **Query scale**: metadata inventory batches observation/connection state for
  a page. Some v1 finding/statistics/ticket endpoints still materialize full
  collections; correlation also has a bounded full finding read. These paths
  need database filtering/pagination and workload measurements before making
  large-installation throughput claims.
- **Scale** is bounded, not unlimited: profiles select at most 10,000 roots,
  catalog pages contain at most 200, and discovery has request/response/item
  caps. Storage-row/TTL cache maintenance is not a hard database byte quota.
  Queue/run/catalog/evidence retention and capacity remain operator duties.
  Only one content scan per installation may be active; multiple root workers
  within that run do not remove this admission limit.
- **Approval scope**: the compatibility connection-wide scan route still uses
  the connection's configured scope, not a profile's path exclusions/budgets.
  Use approved `/scan-runs` for fine-grained selection. Scan approval does not
  authorize creating cloud infrastructure or changing source permissions.
- **Integration**: the normalized signed endpoint is not a native provider
  webhook receiver. Only a dedicated SQS queue may be consumed. Existing S3
  notifications, CloudTrail selectors, Inventory and EventBridge rules are
  never provisioned or overwritten automatically. S3 Batch Operations is
  deferred; Redis, Kafka, Lambda and Alembic are not needed for this path.
- **OIDC** relies on the issuer's groups claim; there is no built-in user
  directory or per-user policy.
- **Provider leak evidence** is read, never matched. A GitHub secret-scanning
  alert is a provider-reported finding. AWS quarantine policy attachment is
  instead a fact about the principal's policies: a customer can attach the
  genuine AWS-managed policy, and the attachment identifies neither the actor
  nor the specific key that may have been exposed. Alerts are not joined to this platform's
  findings, because the join would need the secret value, which is not stored;
  a shared `secret_type` is not identity. Secret scanning needs GitHub Advanced
  Security on private and internal repositories and can be switched off, so a
  refusal is recorded as `UNSUPPORTED` with its reason and never as "no alerts".
- **Observed-call techniques** name the ATT&CK technique an AWS API call belongs
  to. They do not establish that an attack happened: an operator creates access
  keys and reads secrets too, and a call outside the table stays unclassified
  rather than being assumed benign.
- **The exposure path** reports six observations per finding and no
  probabilities. A stage nobody collected reads as uncollected, which is not the
  same as looked-and-found-nothing, and neither means the credential is safe.
- **Quarantine policy attachment does not raise risk.** Model v9 scores the
  observed exposure, verification and privilege evidence without treating the
  attachment as public exposure. Policy names remain visible with their limits.
  The legacy `provider_quarantine` argument is accepted but ignored; saved facts
  keep their schema. The changed policy version schedules reevaluation from
  stored evidence through the existing bounded rescore path. Rows lacking enough
  evidence still require a rescan, and historical audit records are retained.

## Least privilege per capability

Grant each workload identity only what the enabled capability needs; nothing
below is required unless its opt-in is set.

| Capability | Provider permission | Never grant to the scanner |
| --- | --- | --- |
| S3 content | `s3:ListBucket` + `s3:GetObject` on the approved bucket/prefix; `s3:GetBucketPolicyStatus` / `s3:GetBucketAcl` for reachability | `s3:GetObject*` on every bucket, any write |
| Existing S3 Inventory (optional) | `s3:GetObject` on the explicit manifest and report objects; approved source reads (and narrowly scoped KMS permission only if encryption requires it) | Inventory/bucket-policy/notification configuration writes; restore operations |
| Dedicated event queue (optional, separate from source read client) | `sqs:ReceiveMessage`, `sqs:DeleteMessage` on the exact CreMore-owned queue | Consuming an existing business queue, creating queues/rules or editing CloudTrail selectors |
| Scan-scope catalog (`catalog-refresh` job) | `s3:ListAllMyBuckets` (connected account) / `s3:ListBucket` (HeadBucket on a source bucket); GitHub repository metadata; Notion search — metadata only | any object, blob or block read |
| GitHub content | Installation token or fine-grained PAT: *Contents: read*, *Metadata: read* on the selected repositories | Organisation administration, PAT management |
| Notion content | Internal connection (formerly internal integration) with *read content* on the pages explicitly shared with it | Workspace admin, comment/insert |
| IAM potential access (dashboard switch) | `iam:SimulatePrincipalPolicy`, `iam:GetUser`, `iam:ListAccessKeys` on the investigated principals; the named resources' own policies: `s3:GetBucketPolicy`, `secretsmanager:GetResourcePolicy`, `kms:GetKeyPolicy` on this account's keys | `iam:*AccessKey`, policy writes |
| IAM identity policies (usage refresh) | `iam:List/GetUserPolicy`, `iam:ListAttachedUserPolicies`, `iam:ListGroupsForUser`, `iam:List/GetGroupPolicy`, `iam:ListAttachedGroupPolicies`, `iam:GetRole`, `iam:List/GetRolePolicy`, `iam:ListAttachedRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion` | policy writes; reading with the discovered key |
| Secrets inventory (dashboard switch) | `secretsmanager:ListSecrets`, `secretsmanager:DescribeSecret` | `secretsmanager:GetSecretValue`, `kms:Decrypt` |
| Observed use (dashboard switch) | `cloudtrail:LookupEvents`, `ec2:DescribeRegions`, `iam:GetAccessKeyLastUsed` | CloudTrail data-event or Lake access; any write |
| Rotation (`ACTION_ROTATION_ENABLED`, separate executor identity) | Exact secret ARN: `secretsmanager:GetSecretValue`, `PutSecretValue`, `UpdateSecretVersionStage`, `DescribeSecret`; exact user: `iam:CreateAccessKey`, `iam:ListAccessKeys`; `sts:GetCallerIdentity` | `iam:DeleteAccessKey` / `UpdateAccessKey` (old-key disable is a separate approved plan) |
| Key actions (`ACTION_EXECUTION_ENABLED`, separate executor identity) | Exact user: `iam:ListAccessKeys`, `iam:UpdateAccessKey`; plus `iam:DeleteAccessKey` only with `ACTION_DELETION_ENABLED` | Anything on `*` users; the scanner identity itself |
