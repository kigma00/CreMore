# Enterprise Helm deployment

This chart is the production deployment path for the Python platform (`cremore/`)
and the Next.js dashboard (`web/`). Docker Compose remains an isolated local
demo and must not be internet-facing.

The chart is not tied to one company. Hostnames, OIDC issuer/client/claims/groups,
ingress class and selectors, cluster-DNS selectors, PostgreSQL port, image
references, workload identity annotations, AWS region/principal, CIDRs, secret
names, and certificate names are deployment values. One release is one
administrative organisation and one data boundary; deploy separate releases
(separate PostgreSQL databases, fingerprint keys, OIDC clients/groups and
workload identities) for organisations that require isolation.

## Components

For GCP, the optional `gcp.adcSecretName` / `gcp.adcSecretKey` values mount an existing ADC configuration only into the worker. `gcp.quotaProject` sets its quota project. Leave the file mount unset for an attached GKE workload identity. See the [GCP deployment and collection guide](../../docs/integration/GCP_TOTAL_GUIDE_KO.md).

| Component | Image | Entrypoint | Port |
| --- | --- | --- | --- |
| `api` | `image.api` (Python image) | `cremore-api` | 8080 in-pod, HTTPS; Service `:8443` |
| `worker` | `image.worker` (same Python image) | `cremore-worker` | none — liveness is a heartbeat file |
| `web` | `image.web` | Next.js | 3000; behind the oauth2-proxy sidecar on 4443 in OIDC mode |
| `siem` (optional) | `siem.image` or `image.worker` | `cremore-siem` | none — liveness is a heartbeat file; see below |

`api` and `worker` are built from `deploy/docker/python.Dockerfile`; the
Deployment selects the entrypoint with `command`.

With `networkPolicy.enabled`, the API reaches the company's SMTP relay for owner
contact only when it is listed in `contactDelivery.smtpEgress` (`[{cidr, port}]`,
e.g. `10.30.0.25/32` and `587`); Slack goes over the HTTPS egress.

## Isolated execution roles

`isolation.enabled=true` adds separate `remediator` and `control` workers and
turns the existing `worker` into the collector. It requires a CNI that enforces
NetworkPolicy, explicit database networking, separately provisioned PostgreSQL
roles, and migrated credential envelopes. Existing values without this opt-in
keep the shared runtime deployment.

| Workload | Credential keys and database |
| --- | --- |
| `api`, `control` | Public recipient/verifier files, control sealing key, each role's database URL |
| `worker` (collector) | Public files, collector private keys, collector database URL |
| `remediator` | Public files, remediator private keys, remediator database URL |
| `siem` | Its existing destination credentials and restricted database URL; no connector or control keys |
| `migrator` | Migration database URL and optional database CA; no application keys |

Provision `isolation.publicKeysConfigMap` with `recipients.json` and
`isolation.approvalPublicKeyConfigMap` with `public.pem`. The role key Secrets
each contain `private-keys.json`; `isolation.controlKeySecret` contains `key`.
Only the independent approver holds the approval signing private key; the
chart never mounts it. Each collector replica holds all current collector
recipient keys, and each remediator replica holds all current remediator keys.
The queue routes by role, so a partial role key set is rejected at startup.
These are two credential authority domains, not independently routed provider
shards. Private key files are read-only `0440` mounts for the pod group; public
policy files are read-only and must also be protected from unauthorized edits.

Each `isolation.databaseSecrets` entry contains `url`; the SIEM URL remains
under `siem.databaseUrlSecret`. Different Secret names are required but do not
prove different database users or correct grants. Provision and verify the
restricted database roles before the runtime starts. To run the schema migration
deliberately, enable `isolation.migrationJob.enabled` and choose a new
`isolation.migrationJob.revision`. This bounded Job invokes
`python -m cremore.db.startup` with only the migration role and database CA.
It is not a Helm hook or API init container. Finish the migration before rolling
out the application. Credential-envelope migration is a separate offline,
backup-confirmed operation; this Job does not receive the keys it would need.

Use distinct service accounts for every role. In isolation, the existing
`aws`, `gcp`, and `azure` workload identity values apply only to the collector;
`isolation.remediatorIdentity` supplies separate action identities. API,
control, web, SIEM and migration accounts must have no cloud identity bindings,
including externally managed bindings. The chart rejects shared configured
identity names and IDs; operators must also check that distinct Secrets or
federation bindings do not resolve to the same principal. Normal OIDC login
and API-only Google OAuth app configuration remain separate control functions.
All three isolated workers receive `AUTH_MODE=oidc` and the same public issuer,
audience, JWKS and role-group settings as the API, so worker-side sign-in checks
use the team's login provider. Login client and cookie secrets remain with the
login proxy; they are not sent to the workers.

Every isolated workload gets only DNS, its database path when needed, and its
`isolation.egress.<role>` entries (`[{cidr, port}]`). Web also reaches the API.
Empty role lists grant no provider/destination egress. Legacy `httpsCIDR`,
`httpsEgressCIDRs`, `contactDelivery.smtpEgress`, `vaultConnections.egress` and
`siem.egressPorts` do not add isolated egress: explicitly list IdP, SMTP, Vault,
provider, SIEM and required workload-agent destinations under the consuming
role. Kubernetes NetworkPolicy matches IP ranges, not hostnames; enforce
provider hostname restrictions through the deployment's egress proxy or CNI.
Use `isolation.nodeSelectors` and separate pools/hosts when host compromise is
in scope; pod separation alone does not isolate a compromised node.

Offline rendering checks run with
`node --test deploy/helm/tests/chart.test.cjs deploy/helm/tests/isolation.test.cjs`.
They use the cached pinned Helm image with networking disabled, or a supplied
`CREMORE_HELM_BINARY` at version 3.17.2. They verify manifests and rejected
configurations, not live CNI enforcement, cloud identities or database grants.

## SIEM exporter

`siem.enabled=true` adds the `cremore-siem` Deployment
([SIEM guide](../../docs/SIEM_INTEGRATION.md)). It reads only the SIEM outbox:

| Value | Meaning |
| --- | --- |
| `siem.config` | The destination JSON (`destinations`, optional `max_attempts`, `batch_size`, `poll_seconds`); no tokens |
| `siem.databaseUrlSecret` | Existing Secret with the restricted role's `SIEM_DATABASE_URL` (grants in the SIEM guide) |
| `siem.tokenSecretName` | Optional existing Secret; each key becomes an environment variable a `token_env` names |
| `siem.egressPorts` | Legacy destination TCP ports (default `[443]`; syslog over TLS usually `6514`); isolation uses `isolation.egress.siem` instead |
| `siem.tlsSecretName` | Optional existing Secret mounted at `/etc/cremore-siem` for a `syslog_tls` destination's `ca_file`, `cert_file` and `key_file` |

The pod mounts no service-account token and receives no scanner secret or
fingerprint key. A changed destination list restarts it; a heartbeat file older
than fifteen minutes fails the liveness probe.

## External services

Network, TLS and identity design are your organization's choice; the chart's
defaults are a recommended starting point, not requirements.

- A PostgreSQL service. The secret URL uses the `postgresql+psycopg://` form (or
  plain `postgresql://`, which the API normalises). Choose `sslmode` for your
  network; `verify-full` is recommended when the database is off-cluster.
- An OIDC provider whose signed token contains the configured audience,
  subject and expiry. The API validates issuer, JWKS signature, audience, expiry
  and subject itself and maps the configured claim (`auth.oidc.groupsClaim`, which
  may be `groups`, `roles` or `email`) to roles; it never trusts a proxy header.
  Roles left empty grant nothing.
- Optionally an ingress controller and browser TLS certificate
  (`ingress.enabled`), plus the internal certificates the chart mounts.
- Separate Kubernetes service accounts for API, worker and web. Cloud workload
  identity (IRSA / Pod Identity) is needed only when AWS is actually connected.
- Existing Kubernetes Secrets. The chart deliberately generates no credentials.

## Secrets and certificates

| Secret | Required keys | Purpose |
| --- | --- | --- |
| `databaseUrlSecret.name` | `databaseUrlSecret.key` | PostgreSQL URL |
| `applicationSecret.name` | `fingerprint-key` | Hex-encoded HMAC key; fingerprints are keyed with it (API and worker) |
| `secretStore.secretName` | `url`; also `token` only in static-token mode | Optional OpenBao/Vault KV v2 store. Secret-store values reach the worker, and the API only when `config.sealing.vaultPath` is set |
| `auth.oidc.secret.name` | `client-secret`, `cookie-secret` | OIDC client and 32-byte base64url oauth2-proxy cookie key |
| `internalTLS.apiSecretName` | `tls.crt`, `tls.key` | API in-process TLS; certificate covers `<release>-cremore-api` |
| `internalTLS.webSecretName` | `tls.crt`, `tls.key` | oauth2-proxy TLS; covers `<release>-cremore-web` |
| `internalTLS.caSecretName` | `ca.crt` | CA trusted by the Next.js proxy for API TLS |
| `ingress.tlsSecretName` | `tls.crt`, `tls.key` | Browser-facing TLS |

When PostgreSQL uses a private CA, set `databaseTLS.caSecretName`; it is mounted
read-only and exposed through `PGSSLROOTCERT`.

## Install

Use the `cremore-<version>.tgz` asset from the matching GitHub release for a
released installation. The release workflow packages the API, worker, web and
oauth2-proxy digests that it built, signed and attested in that run. It also
publishes `release-images.json` with those references and the source commit.
Each exact release digest must pass the pinned Trivy HIGH/CRITICAL vulnerability
gate before signing; scan errors and findings stop the release. PRs also build
and scan the application images. These configured CI gates are not evidence
that a particular release passed until that workflow run succeeds.
The optional SIEM exporter inherits the worker digest.

1. Export the packaged defaults with `helm show values cremore-<version>.tgz`
   to an environment-owned values file, or write only your changed settings.
   Do not copy image tags from the source chart over a release's defaults.
2. Replace the example host, issuer, audience/client ID, role group names (or emails),
   certificate/Secret names and network CIDRs. Configure the AWS
   region/principal only when connecting AWS.
3. Create the required Secrets with your external secret controller.
4. Confirm the internal certificate SANs match the rendered Service DNS names.
5. Render and review before installation:

```sh
helm lint cremore-<version>.tgz -f values.production.yaml
helm template cremore cremore-<version>.tgz --namespace security-platform -f values.production.yaml > rendered.yaml
helm upgrade --install cremore cremore-<version>.tgz --namespace security-platform --create-namespace -f values.production.yaml
```

Replace `<version>` with the downloaded version. Release defaults set
`image.requireDigest: true`: mutable application, oauth2-proxy and enabled SIEM
image overrides fail rendering. If you mirror or customize images, choose and
verify their digests explicitly. This shape check does not verify a signature;
verify the published image signatures/provenance under your deployment policy.
The source chart remains usable as `deploy/helm` for development with its existing
tag defaults and `image.requireDigest: false`; it is not the release artifact.

There is no separate development mode. The chart renders OIDC through the
oauth2-proxy sidecar; use `docker-compose.yml` or your own manifests for
shared-token authentication. Rendering fails only on malformed values and on
CreMore-owned guarantees (deletion requiring
execution, event signing key references). Ingress, NetworkPolicy, issuer scheme,
scopes and group layout are yours to choose.

At process startup the API and worker also validate the Secret-backed
fingerprint key: at least 32 random bytes encoded as hex.

## Opt-in behaviour (all default off)

| Value | Effect |
| --- | --- |
| `config.verificationMode` (default `enabled`) | On by default and switched by an Admin in the dashboard; `disabled` locks it off. Sends each discovered credential to its issuing provider (AWS STS `GetCallerIdentity`, provider whoami endpoints) to record whether it is active and the non-secret facts returned (account, scopes). Needs HTTPS egress to each provider; with CIDR-restricted `networkPolicy.httpsEgressCIDRs`, unreachable providers are recorded as `indeterminate` (`PROVIDER_UNREACHABLE`) |
| `config.iamPotentialAccessMode` | `enabled` (default) allows scoring a discovered AWS principal's privilege with `iam:SimulatePrincipalPolicy` and the bucket, secret and KMS key policies of the resources its policies name (read-only); `disabled` hard-locks it off |
| `config.awsSecretsInventoryMode` | `enabled` (default) allows the read-only Secrets Manager inventory and metadata reads (`ListSecrets`, `DescribeSecret`; never `GetSecretValue`); `disabled` hard-locks it off |
| `config.awsUsageLookupMode` | `enabled` (default) allows observed use of a discovered AWS key: `cloudtrail:LookupEvents` across enabled regions (90-day event history) and `iam:GetAccessKeyLastUsed`, read-only; `disabled` hard-locks it off |
| | These three are **off until an Admin switches them on** in the dashboard (`GET`/`PUT /api/v1/settings/aws-investigations`), so an analyst can turn one on during an investigation without a redeploy. The chart values only decide whether that switch is available |
| `config.learnedFalsePositivesMode` | `enabled` (default) allows auto-triage of learned false positives; `disabled` hard-locks it off. The switch itself, and the threshold and sample floor it applies, are an Admin's and live in the dashboard, where the policy is visible and each change records who made it. Profiles learn from analyst decisions using redacted path and line-shape features only; reopening contradicts and deactivates a profile. Both containers |
| `config.rotationExecutionEnabled` | Execute approved two-party AWS key rotation (PREPARE stages and validates a successor; PUBLISH promotes it). Requests and review work while this is off; nothing touches AWS until it is true |
| `config.actionExecutionEnabled` | Execute approved, hash-bound action plans: IAM keys in the API (`iam:UpdateAccessKey` to disable, with `ListAccessKeys` read-back), other providers' credentials in the worker through their remediation connection ([provider actions](../../docs/PROVIDER_ACTIONS.md)). Both containers, since the worker checks it again |
| `config.actionDeletionEnabled` | Additionally allow irreversible plans: `DELETE_ACCESS_KEY` (already-inactive keys only, `iam:DeleteAccessKey`) and revoking another provider's credential. Requires `actionExecutionEnabled`. Both containers |
| `config.rotationSecretArns` | Secrets Manager ARNs a rotation plan may bind to; an allowlist, not a grant |
| `config.secretManagerAllowedReferences` | Secrets Manager ARNs an Admin may declare as a discovered credential's storage location; metadata reads only (`DescribeSecret`, `ListSecretVersionIds`), never the value |
| `config.onboardingTemplateURL` | Optional S3 URL of the member-account CloudFormation template; adds a quick-create link beside the CLI deploy command |
| `config.scannerPrincipalArn` | Optional exact role ARN of the workload's AWS identity (IRSA/Pod Identity); without it an Admin approves the identity the API and worker report in the dashboard |
| `config.ticketSystemPlugins` (default empty) | `TICKET_SYSTEM_PLUGINS` of the API and worker containers: installed ticket-system plugins an Admin may choose for owner approvals and exposure responses, comma-separated ids such as `jira` (the image includes the Jira plugin). Empty offers none ([ticket systems](../../docs/TICKET_SYSTEMS.md)) |
| `config.workerConcurrency` (default `2`) | `WORKER_CONCURRENCY` of the worker (collector) pods: task-runner processes per pod, each scanning one task at a time beside a control loop that keeps polling schedules, change feeds and queues. Scans running at once are `replicas.worker` times this. `0` picks min(4, the CPUs the pod may use: its CPU limit and affinity). Each runner holds its own database connections and memory: about 120 MiB at rest, plus up to 256 MiB of read-ahead and a document parser child of up to 512 MiB while it scans. Size `resources.worker.limits.memory` as about 0.9 GiB per runner plus the control loop (the default 3 GiB covers 2 with headroom). Size the database's `max_connections` with it: about 10 per runner (8 read-ahead threads, the runner and its lease heartbeat), up to 15 per API pod and a few per control loop, for the pods of a rolling update too. The default layout needs about 80 at rest and up to about 120 while a rollout runs, above PostgreSQL's default 100, so set 200 (the Compose database does). Remediator and control pods share `resources.worker` and keep one loop. A stop ends the runners within about 11 s, inside the pods' 30 s termination grace period. When all runners keep crashing, the worker stops touching its heartbeat file (the liveness probe then fails) and exits after 8 crashes in a row |
| `workerPod.shareProcessNamespace` (default `false`) | The image has no init process; `true` makes the pod's pause process PID 1, which reaps a document-parser child orphaned when its parser server is killed (otherwise it stays a zombie until the pod restarts). Leave it `false` where a sidecar may be injected into the worker pod: a container sharing the namespace can read the worker's `/proc`, its environment included |
| `secretStore.enabled` | Resolve connection `vault://` references through KV v2. `authMode=token` preserves static-token installs; `authMode=kubernetes` renews workload login automatically |
| `config.sealing.vaultPath` | KV v2 path holding the master that seals stored credentials, so it is not on a node. Requires `secretStore.enabled` and wires the API in as well |
| `config.sealing.kmsKeyId` / `keyCiphertext` | The same master held by AWS KMS instead: only the ciphertext is in the release, and `kms:Decrypt` belongs to the workload's IRSA/Pod Identity role |

Rotation requires two distinct OIDC identities: the requester (Analyst or above)
and the approver (Remediator or above). The API enforces this and so does the
rotation service itself. Old keys are never disabled by rotation; that remains
a separate, later approved step.

## Optional scan schedules, events and Inventory

Every trigger mode defaults to `enabled` (allowed) and Inventory bindings to `{}`.
The switches themselves are an Admin's, in the dashboard: scheduled scans (a daily
full scan of every approved scope, each starting at its own fixed time between
02:00 and 06:00 KST by default) and change feeds are on unless switched off, also
right after an upgrade, while queues consume nothing until an Admin binds and
acknowledges one. An upgrade does not read everything at once: schema migration 14
records the upgrade's moment with the database clock, the full-scan slot already
due then is skipped once for scopes approved before it (their first scheduled full
scan is the next one due: usually the next night's, the same night's if the upgrade
falls inside the 02:00-06:00 window before that scope's time), and the policy re-scan
the new extractor version calls for waits until that full scan has ended; meanwhile
incremental and change runs read only what changed
(or wait, for cache-based sources) instead of turning into whole re-reads. Run the
migration before the runtimes: an isolated runtime refuses a database without
migration 14. To keep change feeds from starting, set `scanning.changeFeedsMode:
disabled` before it rolls out; `scanning.schedulesMode: disabled` keeps schedules off.
First register the connection,
discover its catalog and save an Admin-approved scan-scope profile in CreMore.
Use the profile UUID returned by that API/UI, not an AWS account number.
Settings never grant scope: a profile's incremental schedule needs its
`schedule_minutes >= 5`, its full scans follow its `full_scan_minutes` or the
installation default, and events need its `event_mode: ENABLED`.

| Helm value | Environment variable in API and worker |
| --- | --- |
| `scanning.schedulesMode` | `SCAN_SCHEDULES_MODE`: `enabled` (default) allows the worker to honour a profile's `schedule_minutes`; `disabled` hard-locks schedules off |
| `scanning.sqs.mode` | `SCAN_SQS_MODE`: allows queue consumption (default), or `disabled` to hard-lock it off |
| `scanning.pubsub.mode` | `SCAN_PUBSUB_MODE`: allows reading the customer's own Pub/Sub subscription (default), or `disabled` |
| `scanning.serviceBus.mode` | `SCAN_SERVICEBUS_MODE`: allows reading the customer's own Service Bus queue or topic subscription (default), or `disabled` |
| `scanning.changeFeedsMode` | `SCAN_CHANGE_FEEDS_MODE`: allows change feeds on approved repositories and spaces (default), or `disabled` |
| `scanning.sqs.queueURL` | `SCAN_SQS_QUEUE_URL` -- optional pin |
| `scanning.sqs.profileId` | `SCAN_SQS_PROFILE_ID` -- optional pin |
| `scanning.sqs.dedicatedAcknowledged` | `SCAN_SQS_DEDICATED_ACKNOWLEDGED` -- optional pin; otherwise an Admin acknowledges the queue in the dashboard |
| | Scheduled scans (a daily full scan of every approved scope at 02:00 KST by default) and change feeds are **on unless an Admin switches them off**, also after an upgrade; queues are off until an Admin binds and acknowledges one (`GET`/`PUT /api/v1/settings/scan-triggers`). These values only decide whether a switch is available (`disabled` keeps it off), and pin the fields you want fixed |
| `scanning.inventoryManifests` | `SCAN_INVENTORY_MANIFESTS`, serialized as a JSON object |

Example values for an installation that wants its triggers fixed in
configuration, after the referenced profile and dedicated queue have been
provisioned by your organisation. Everything below is an optional pin -- an Admin
can set the same fields in the dashboard -- and a queue still needs its dashboard
switch (schedules and change feeds are on unless switched off):

```yaml
scanning:
  schedulesMode: enabled
  sqs:
    mode: enabled
    queueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/cremore-dedicated"
    profileId: "11111111-1111-4111-8111-111111111111" # replace with approved S3 profile UUID
    dedicatedAcknowledged: true
  inventoryManifests:
    # Use the CreMore connection UUID, not the profile UUID, in this map key.
    "22222222-2222-4222-8222-222222222222/approved-bucket":
      manifest_bucket: existing-inventory-reports
      manifest_key: reports/2026-09-15/manifest.json
```

Enable only the integrations you use. The web pod receives none of the scanning
settings. The API exposes no unauthenticated route: the signed event receiver
that once did was removed, because it could not accept a provider's own webhook
and required each organisation to build a translating adapter for it.

Only consume a CreMore-dedicated SQS queue: receiving/deleting messages from an
existing enterprise queue can deprive its existing consumers of events. The
chart rejects SQS enablement without `dedicatedAcknowledged: true`, a profile
UUID and an explicit HTTPS AWS queue URL. Grant the worker `sqs:ReceiveMessage`
and `sqs:DeleteMessage` on that exact queue through its existing workload
identity; source scanning permissions remain read-only. The chart creates no
queue, bucket, CloudTrail trail or EventBridge rule and changes no source
notification settings. An administrator may provision an isolated queue and
new delivery rule without replacing existing consumers or rules.

Inventory bindings point only to already produced reports. They do not enable
Inventory on a source bucket or automatically start an Inventory scan. Start a
profile run explicitly with `mode: INVENTORY`; only approved S3 roots are legal.
Report-only coverage remains `PARTIAL` / `INVENTORY_REPORT_ONLY`, does not advance
the root watermark and does not prove whole-bucket deletion. Keep ordinary
DELTA/reconciliation scans, and update the manifest pointer when a new report
is available. Exact pointer shape and supported report format are validated by
the application; access to both the source objects and existing report objects
must be granted separately.

The local Compose stack forwards the same uppercase `SCAN_*` variables from
your process environment (or a private, untracked environment file) to API and
worker only. `SCAN_INVENTORY_MANIFESTS` must be a JSON object string; when unset
or empty it resolves to `{}`. Compose is still loopback-only development: unlike
Helm Secret references, its rendered configuration contains injected environment
values, so do not publish `docker compose config` output or commit credentials.

## Renewable authentication

For unattended operation, prefer Vault/OpenBao Kubernetes auth and GitHub Apps
over long-lived Vault tokens and GitHub PATs. Configure the Vault Kubernetes
role out of band so it is bound to this release's worker ServiceAccount,
namespace and audience, with read access only to the KV prefixes referenced by
connections. Then set:

```yaml
secretStore:
  enabled: true
  secretName: cremore-vault-address
  authMode: kubernetes
  mount: secret
  kubernetes:
    role: cremore-worker
    authMount: kubernetes
    audience: vault
    tokenExpirationSeconds: 3600
```

The chart keeps `automountServiceAccountToken: false` and projects an
audience-bound token into the worker. The worker exchanges it for a Vault lease,
refreshes before expiry, and retries one KV request after a `403` with a fresh
login. The web pod receives neither the Vault token nor the projected token, and
neither does the API unless `config.sealing.vaultPath` is set (below).
`secretStore.authMode=token` remains compatible with existing installs and reads
`secretStore.tokenKey` from the same Secret.

### Azure workload identity and other Vault clusters

```yaml
azure:
  workloadIdentity:
    enabled: true
    clientId: 00000000-0000-0000-0000-000000000000   # the Entra application
    tenantId: ""                                      # empty: the webhook's tenant
    tokenExpirationSeconds: 3600
vaultConnections:
  tokens:
    - name: vault-pay        # a connection's server_auth.token_file
      audience: vault-pay    # the audience that cluster's Kubernetes or JWT role expects
  expirationSeconds: 600
  egress:
    - cidr: 10.20.0.0/16
      port: 8200
```

Azure labels the API and worker pods `azure.workload.identity/use: "true"` (the
selector is unchanged) and annotates their ServiceAccounts with the client and
tenant IDs, so the AKS webhook injects `AZURE_FEDERATED_TOKEN_FILE` for
`DefaultAzureCredential`. Each `vaultConnections.tokens` entry projects one
audience-bound token into the worker under `VAULT_CONNECTION_TOKEN_DIR`; it is
never the installation's own secret-store token. See
[machine identity](../../docs/MACHINE_IDENTITY.md).

### The sealing master in Vault

`config.sealing.vaultPath` keeps the master that seals stored connection
credentials in the same Vault, at a KV v2 path under `secretStore.mount` whose
`vaultField` (default `key`) holds 32 or more random bytes as hex. Nothing
long-lived is then written into the chart or onto a node, which is what a
multi-replica installation needs -- every replica resolves the same master.

```yaml
config:
  sealing:
    vaultPath: cremore/sealing-key
    # vaultPathPrevious: cremore/sealing-key-2024   # opens, never seals
secretStore:
  enabled: true
  kubernetes:
    role: cremore-worker
    # Optional: the API only reads the sealing path, so give it a role whose
    # policy grants exactly that. Empty reuses role above.
    sealingRole: cremore-sealing
```

This is the one case where the API is wired into the store: it is what seals a
credential an operator types into the dashboard, so it has to resolve the same
master the worker later opens it with. `secretStore.kubernetes.sealingRole` (or
`secretStore.sealingTokenKey` in static-token mode) keeps that access to the one
path. Rotate by writing a new master and moving the old path into
`vaultPathPrevious`, which opens stored credentials but seals no new one.

An installation with no Vault can instead keep the master in AWS KMS with
`config.sealing.kmsKeyId` and `keyCiphertext`; see
[docs/CREDENTIAL_ROOTS.md](../../docs/CREDENTIAL_ROOTS.md).

For GitHub, create and install an App with only `Contents: Read-only` and
`Metadata: Read-only`, then store this KV v2 data at the connection's
`vault://` path:

```json
{
  "GITHUB_APP_ID": "123456",
  "GITHUB_APP_INSTALLATION_ID": "789012",
  "GITHUB_APP_PRIVATE_KEY_BASE64": "<base64-encoded PEM>"
}
```

The worker issues installation tokens in memory and refreshes them two minutes
before expiry. Existing `{ "token": "..." }` and
`{ "access_token": "..." }` secrets remain supported.

OIDC scopes include `offline_access`; oauth2-proxy refreshes its cookie every
`auth.oidc.oauth2Proxy.cookieRefresh` (default `1h`) and expires it after
`cookieExpire` (default `8h`). The IdP client must allow the refresh-token grant
and issue refresh tokens for `offline_access`. IdP absolute session limits still
apply and intentionally require reauthentication when reached.

Owner approval links (`/owner-approval`) and exposure-response links (`/response`)
are opened through the same login: the person needs no CreMore group, but the IdP
client must let them sign in and put their `email` in the token. A token with
`email_verified: false` is refused; one without the claim (Entra ID sends none) is
trusted as the IdP's own address. Only the person whose email is the address the
link went to can read and answer it.

Use `GET /api/v1/operations/status` with an Admin bearer token for safe counts
and alert codes covering connection authentication and queued/running/failed/
partial jobs. Monitor worker availability through Deployment available replicas
and the chart's heartbeat readiness/liveness probes; the API does not infer Pod
health from database activity.

## Validation without a cluster

```sh
node --test deploy/helm/tests/chart.test.cjs
```

The tests use Node and the locally available, digest-pinned Helm 3.17.2 Docker
image with networking disabled. `helm template` must reject invalid
configurations; `helm lint` alone is insufficient because this Helm version logs
template `fail` calls as informational messages.

## Traffic and identity boundaries

The only Ingress backend is the oauth2-proxy TLS port. It authenticates the
browser and passes the signed OIDC token to Next.js; Next.js forwards it to the
API over HTTPS, and the API validates the token independently. The API is
ClusterIP-only, the worker has no Service, default-deny NetworkPolicies isolate
each component, and every network hop uses TLS. Plain HTTP exists only over
loopback between oauth2-proxy and Next.js in the same pod.

The default `0.0.0.0/0` egress CIDRs are functional baselines, not least
privilege. Restrict them to the selected database, approved provider endpoints
and OIDC endpoints in each environment.

| Value | Default | Scope |
| --- | --- | --- |
| `networkPolicy.dnsNamespaceSelector` | `kubernetes.io/metadata.name: kube-system` | Exact namespace labels of the cluster DNS pods |
| `networkPolicy.dnsPodSelector` | `k8s-app: kube-dns` | Exact DNS pod labels, ANDed with the namespace selector |
| `networkPolicy.databasePort` | `5432` | PostgreSQL destination port for API/worker only |
| `networkPolicy.httpsEgressCIDRs` | `[]` | When non-empty, replaces `httpsCIDR` for web, API and worker TCP443 egress |

Both DNS selector maps must remain non-empty with string label values; the
chart rejects empty/non-map selectors and database ports outside `1..65535`.
