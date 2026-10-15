# Enterprise hardening

Turning a single-operator install into a team deployment. Most of this is
**enabling features that already ship** — the platform provides the hooks and
samples and leaves infrastructure choices (TLS, IdP, network) to you, rather
than forcing a "secure mode". Each section says what to set and links the
detailed docs instead of repeating them.

## Recommended order

1. **Access control (OIDC + RBAC)** — put real identities in front first.
2. **Network exposure (TLS + auth front-end)** — publish only behind that.
3. **Credential storage (external secret manager)** — move tokens out of the DB.
4. **Providers** — GitHub App / GHES, then AWS multi-account.
5. **Verify** — collection works, unauthenticated access is blocked, a Viewer
   cannot mutate.

---

## 1. Access control — OIDC + RBAC

The API validates every bearer itself (issuer, JWKS signature, audience, expiry)
and maps a groups claim to one of four roles (`viewer`, `analyst`,
`remediator`, `admin`).

- **API**: `AUTH_MODE=oidc`, `OIDC_ISSUER_URL`, `OIDC_AUDIENCE`,
  `OIDC_GROUPS_CLAIM`, and `OIDC_{VIEWER,ANALYST,REMEDIATOR,ADMIN}_GROUP`. A user
  with no mapped group gets no access. Missing issuer/audience is a startup error.
- **Compose**: use the overlay in §2, which sets this up end to end.
- **Signing-key destinations**: discovery and JWKS requests never follow redirects.
  Keys must be on the configured issuer's origin (scheme, host and port), or at
  the exact operator-configured `OIDC_JWKS_URL` (`auth.oidc.jwksURL` in Helm).
  Google sign-in also permits its canonical `https://www.googleapis.com/oauth2/v3/certs`.
  Private on-premises IdP origins remain supported; DNS and network policy for
  that configured origin belong to the installation. Key refreshes share a
  30-second cooldown including failures and unknown key IDs, preventing one
  fetch per rejected token. A newly rotated key may wait until that window ends.
- **Kubernetes**: the Helm chart's `auth.oidc` block — see
  [`deploy/helm/README.md`](../deploy/helm/README.md).
- **People directory**: once people sign in through the IdP, the connection that
  reads people (departed owners, owner contacts) must be that IdP itself — the
  same Okta organization, Entra tenant, Keycloak realm or Google Workspace. The
  wizard opens it filled in from `OIDC_ISSUER_URL` and the API refuses any other
  (`409 PEOPLE_DIRECTORY_NOT_SIGN_IN_IDP`), also when re-enabling one made
  earlier or re-pointing its collection; GitHub's identity link is exempt
  ([onboarding](ONBOARDING.md)). The directory is connected by the issuer's
  host: an Okta org signing in on a custom URL domain is connected by that
  domain, and a Keycloak that keeps `/admin/` off its public host needs the
  worker to resolve that host name to the internal endpoint (internal DNS or a
  hosts entry). Keep an Okta issuer on the Okta domain or a custom authorization
  server (`/oauth2/default`): an org authorization server on a custom domain is
  not recognized.
- **Google sign-in**: Google ID tokens carry no groups claim. Set
  `OIDC_ISSUER_URL=https://accounts.google.com` and each `OIDC_*_GROUP` to a
  Workspace group address (`cremore-admins@acme.com`); the worker reads those
  groups' members every five minutes through the Google Workspace people
  connection, so its service account's domain-wide delegation also needs
  `admin.directory.group.member.readonly`. Only a verified address of that
  Workspace (`hd`, the organization's primary domain: connect the primary
  domain) gets a role. Keep the role groups and every group nested in them
  admin-managed or invitation-only: anyone a nested group lets in gets the role;
  external and "all users in the organization" members get none. A group that
  cannot be read grants nothing; when none can be read, the last membership
  serves for an hour, and a cause on CreMore's or the company's side (no people
  connection, a credential it cannot open, a delegation, admin or key Workspace
  no longer accepts) ends it at once. Bootstrap: connect Google
  Workspace as the people directory while still `AUTH_MODE=local`, then switch
  to `oidc`; if nobody can sign in, switch back to `local` to fix it. Settings →
  Sign-in shows when the groups were last read and why a read failed.

## 2. Network exposure — TLS + auth front-end

`CREMORE_ALLOWED_HOSTS` is a DNS-rebinding guard for **local** mode, **not**
per-user authentication. Never publish local mode with TLS alone — it would
expose an admin-authenticated dashboard.

- **Compose**: [`deploy/compose/reverse-proxy/`](../deploy/compose/reverse-proxy/README.md)
  — Caddy (TLS) → oauth2-proxy (OIDC) → web/api in `oidc` mode. The proxy never
  falls back to the admin token for external callers.
- **Kubernetes**: the chart already ships oauth2-proxy + Ingress TLS.

## 3. Credential storage — external secret manager

Discovered-connection tokens are AES-GCM sealed in the DB by default. To keep
them in Vault/OpenBao instead, store a `vault://` reference:

- Set `SECRET_STORE_URL` and `SECRET_STORE_AUTH_MODE` (`token` or `kubernetes`),
  then attach `credential_ref: vault://<path>` when registering a connection
  (API), rather than a raw token.
- The KV entry holds either a `token`/`access_token`, or GitHub App fields (§4).
- **Note**: the dashboard's `secret_reference_enabled` flag is the *AWS Secrets
  Manager ARN picker* (off by design) — it is **not** the Vault switch. Vault is
  enabled by `SECRET_STORE_URL` + a `vault://` `credential_ref`.

## 4. Providers

### GitHub App / fine-grained PAT (incl. GHES)

- **fine-grained PAT**: store as the secret's `token`. Scope it to
  `Contents: read` + `Metadata: read` **for the repositories whose content is
  collected** — that is the content-scan grant, not org-wide management access.
- **GitHub App**: store `GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID`,
  `GITHUB_APP_PRIVATE_KEY_BASE64` in the secret; installation tokens are minted
  and refreshed automatically.
- **GHES**: register each connection's host (`enterprise_host`) and list every
  host in `GITHUB_ENTERPRISE_HOSTS`. Token issuance, the identity check,
  collection and catalog all use the connection's host. Cross-host verification
  is a separate, off-by-default dashboard switch.

### AWS multi-account (StackSet + org discovery)

- **Hub**: deploy [`security-account.yaml`](../deploy/cloudformation/security-account.yaml)
  in the security account; set `EnableOrgDiscovery=true` to grant read-only
  Organizations account discovery (register that account as an Organizations
  delegated administrator from the management account).
- **Spokes**: deploy [`member-account-role.yaml`](../deploy/cloudformation/member-account-role.yaml)
  as a service-managed StackSet with `DeploymentMode=Organization` (skips the
  single-account match, requires `OrganizationId`). SingleAccount stays the
  default for hand-created stacks.
- **Auto-register**: set in the dashboard, not the deployment (AWS account roles
  -> Connect AWS account -> AWS Organizations): the StackSet's shared ExternalId,
  an optional OU scope (nested OUs included), accounts to exclude, and the sweep
  switch. "Import accounts now" runs one sweep immediately instead of waiting for
  the worker's poll. Discovery registers accounts; S3 content scans still need an
  explicit bucket scope.
- Configuration keeps the last word: `AWS_ORG_DISCOVERY_MODE=disabled` hard-locks
  the sweep off, and `AWS_ORG_DISCOVERY_EXTERNAL_ID`, `AWS_ORG_DISCOVERY_OU_IDS`
  or `AWS_ORG_DISCOVERY_EXCLUDE_ACCOUNTS` each pin their own field.
  `AWS_ORG_DISCOVERY_INTERVAL_MINUTES` paces the sweep.
- **New accounts**: create the StackSet with `--auto-deployment
  Enabled=true,RetainStacksOnAccountRemoval=false` and target the OUs rather than
  an account list. The scanner role then lands in every account added to those
  OUs afterwards, so nothing has to be repeated per account.

### AWS Control Tower

Control Tower sits **on top of** Organizations and needs no CreMore-specific
setting. Use the section above as written, with two notes:

- **Scope by registered OU.** Put the OU ids Control Tower registered into
  `AWS_ORG_DISCOVERY_OU_IDS`. Accounts that are in the organization but not
  enrolled (or that drifted out of a registered OU) are still listed by
  Organizations; they are registered and then blocked as
  `OUT_OF_DEPLOYMENT_SCOPE` rather than scanned with a role that may not be there.
- **Account Factory.** With `AutoDeployment` on (above), an account Control Tower
  provisions into a registered OU gets the scanner role as part of being
  enrolled.

**`AWSControlTowerExecution` is deliberately never used.** Control Tower creates
it in every enrolled account and the management account can assume it, which
makes it a tempting shortcut. It is administrator-equivalent, so using it would
discard the whole read-only guarantee (`cremore/aws_readonly.py` plus the
`ScannerMutationDeny` in every role template). CreMore deploys its own read-only
role instead.

### AWS accounts without organization access (IAM Identity Center)

When the operator holds an Identity Center assignment but no Organizations
permission -- common in Control Tower estates, where delegated administration is
held elsewhere -- CreMore can reach accounts through **that assignment** instead:

- **No configuration change is needed.** The permission set and the background
  sweep are both chosen in the dashboard (AWS account roles -> Connect AWS
  account -> IAM Identity Center), because the operator running an installation
  is frequently not the person who can edit its environment. The dialog offers
  the permission sets Identity Center actually reports; nothing is defaulted,
  since an operator usually also holds `AdministratorAccess`.
- Configuration still has the last word where an organization wants it:
  `AWS_SSO_DISCOVERY_MODE=disabled` hard-locks the route off, and
  `AWS_SSO_DISCOVERY_PERMISSION_SET` pins the permission set so the dashboard
  cannot change it.
- Nothing is deployed in any account: `sso:GetRoleCredentials` vends the
  credentials, and `cremore/aws_readonly.py` remains the only boundary, so the
  permission set should itself be read-only. CreMore reports what it observes
  about that permission set; it does not police its contents.
- **The permission set carries the read-only work.** No role is assumed here, so
  the `sts:AssumeRole` policy shown for member-role access is not what this mode
  needs -- a permission set holding only that fails on the first object read. The
  identity panel prints the correct policy beside it (`permission_set_policy` on
  `/aws/scanner-identity`); it is the member role template's grants minus
  `iam:UpdateAccessKey`, which only the remediation path may ever hold.
- **The single-operator default; off in the chart.** It needs the interactive
  `aws sso login` token cached in `~/.aws`. `config.ssoDiscoveryMode` ships as
  `disabled` in `deploy/helm` and member-role access is the server path, but the
  value is a choice rather than a lock: it does work on a cluster if you accept
  the two constraints below.
- **The cache must be writable.** The hourly access token is renewed with nobody
  present, but botocore rewrites the cache file to store it -- and the rotated
  refresh token with it. A read-only mount (a Kubernetes Secret) fails with
  `EROFS`, reported as `SSO_CACHE_NOT_WRITABLE`. Use a writable volume.
- **Someone signs in about every 90 days.** Renewal stops when the client
  registration expires (`registrationExpiresAt`); botocore then makes no AWS call
  and the state is `AWS_LOGIN_REQUIRED` until a person runs `aws sso login` on the
  host and re-seeds the cache. (Signing in from the connection wizard, which does the
  same device authorization from the API, exists only on a single operator's install,
  `AUTH_MODE=local`: a team install refuses it with `AWS_SSO_LOGIN_SOLO_ONLY`.) A copy of a cache cannot be kept in two places, because
  whichever one renews gets the new refresh token and invalidates the other.
- An expired sign-in reports `AWS_LOGIN_REQUIRED` and AWS work waits, exactly as
  it does for a role.
- The Identity Center instance is pinned at approval: pointing the same profile
  at another directory blocks every such account with
  `AWS_SSO_SESSION_CHANGED` rather than silently scanning a different estate.
- Promote an account to a member role later from its card (`POST
  /aws/accounts/{id}/promote`). The record, its findings and its history stay;
  the stored result stops counting until the deployed role is proved.

## 5. Least privilege (keep the defaults)

Scanner identities are read-only: an SDK allowlist (`cremore/aws_readonly.py`) and an
explicit `ScannerMutationDeny` in every role template. Capability probing,
cross-host verification, and all key actions are off by default — turn them on
only where a policy allows. Nothing here needs changing; do not widen it.

## 6. Audit trail integrity

Every audit row is sealed into a keyed hash chain by one worker each minute
(`cremore/db/audit_chain.py`, `cremore/operations/audit_integrity.py`). A row's
chain MAC covers its position, its content and the previous row's MAC. The key
comes from `AUDIT_CHAIN_KEY`, or is derived from `FINGERPRINT_KEY` when that is
not set, and is never stored in the database. The API and worker also MAC each
row as they write it. The first seal takes in every older row and then starts
the chain with `AUDIT_CHAIN_STARTED`. A chain is never started again once one
existed: not while an authentic start, anchor or rewind row remains, and not
while the worker remembers the head it sealed (it writes a removed rewind row
again for as long as it runs). On PostgreSQL, sealing and the hourly check run in
the worker's own thread, so a long first seal does not stop its liveness beat.

What `GET /api/v1/audit/integrity` (Analyst) finds on its own, from the
database and the key:

- changed rows (`MAC_MISMATCH`) and deleted rows (`SEQUENCE_GAP`) anywhere in
  the chain, not only the first, and rows put at a position no chain has
  (`SEQUENCE_INVALID`; the table also refuses such positions);
- rows after the chain's start that no CreMore process wrote (`UNAUTHENTICATED`),
  sealed or waiting. The check begins at the first start row the sealer wrote; a
  start row it did not write is `GENESIS_INVALID` and moves nothing, and a
  changed start row is a changed row. The start names how many rows came before
  it, so rows sealed again in front of it show as `GENESIS_MOVED`;
- rows un-sealed and sealed again: each hourly `AUDIT_CHAIN_ANCHORED` row claims
  the head's position and MAC, and a claim that no longer holds is
  `ANCHOR_CLAIM_MISMATCH`. While the worker runs, a moved head is recorded as
  `AUDIT_CHAIN_REWOUND`, sealed at once in the same transaction;
- a chain whose positions are gone (`CHAIN_RESET`), a removed start
  (`GENESIS_MISSING`) and a key under which nothing in the chain verifies
  (`KEY_MISMATCH`).

One check runs at a time (`429 AUDIT_CHECK_RUNNING` meanwhile) and the same
answer serves a minute; an anchor to compare is one lookup on top of it. An
admin accepts a problem they have examined with
`POST /api/v1/audit/integrity/acknowledge`, naming the `ack` value the check gave
it. It binds the problem's kind, place and content, so a later change to that
row is open again. A gap is bound to its extent and both sides of it (the MAC
before it and the row after it, whose link can no longer be checked): a wider
gap, or that row changed or swapped, is open again. A row no CreMore process
wrote is bound to its ID and content, sealed or waiting. Only problems open at
that moment can be accepted, and the acknowledgement is itself a chained row.
A rewind (`CHAIN_REWOUND`), a moved start (`GENESIS_MOVED`) or an anchor claim
that no longer holds cannot be examined from the report alone: accept one only
after comparing the trail with a backup or the SIEM, typically right after a
restore.

What needs the SIEM: the database alone cannot show a rewrite of the rows after
the latest anchor that survives, done together with deleting the later anchors
and restarting the worker, nor a rewrite of the whole chain that also deletes its
start and every anchor. Each hourly `audit.chain_anchor` event carries the
result, the chain's start (`genesis_seq`, `genesis_mac`), the anchor number, the
head and the count of open problems. The worker's log holds the same line; the
outbox copy is only as safe as the database, so evaluate these rules on the log
copy where you can:

- alert when `chain_state` is not `INTACT`, and when `open_problems` grows;
- alert when `genesis_mac` changes, when `anchor_no` is not one more than the
  last one received, and when `chain_seq` goes down;
- alert when anchors stop arriving;
- check a kept head with `?anchor_seq=&anchor_mac=`.

Limits, stated plainly:

- A row deleted before its first seal (up to a minute, or while the worker is
  down) leaves no trace; its `audit.action` event may already be in the SIEM.
- Whoever holds the audit key can rewrite the whole chain. `FINGERPRINT_KEY`
  also goes to an external vault's hasher (deploy/coverage); set
  `AUDIT_CHAIN_KEY` before the first start where that host is not trusted. There
  is no re-keying: under another key the chain reads as `KEY_MISMATCH`, and as
  changed rows once anything is sealed with the new key, so keep the key for the
  life of the trail.
- A worker remembers the head it sealed only while it runs. A worker that was
  restarted or added has no such memory: once the waiting rewind row is removed,
  it starts a new chain, which the SIEM sees as a new `genesis_mac` and
  `anchor_no` counting from one.
- Stop the workers before restoring the database. A worker that sees its chain
  vanish records `AUDIT_CHAIN_REWOUND` and never starts a chain again
  (`CHAIN_RESET`, which cannot be accepted). After a restore to a backup from
  before the chain, with the workers stopped, delete the waiting
  `AUDIT_CHAIN_REWOUND` rows (`chain_seq IS NULL`); the next start takes in the
  restored rows and starts a new chain, which the SIEM sees as a new
  `genesis_mac`.
- The first seal after the upgrade takes in the whole existing trail in one
  transaction; on PostgreSQL it holds back vacuum while it runs.
- Upgrade the API and worker together: a row an older API writes after the
  chain has started carries no entry MAC and shows as `UNAUTHENTICATED` until an
  admin accepts it.
- Findings and credentials are never deleted by CreMore; their audit rows would
  go with them (`ON DELETE CASCADE`), which the chain reports as gaps.

---

## Hardening checklist

- [ ] `AUTH_MODE=oidc`; every operator reaches the dashboard through the IdP.
- [ ] Group→role mapping set; a no-group user is denied.
- [ ] Published only behind the reverse-proxy overlay (or the chart's Ingress).
- [ ] `API_ADMIN_TOKEN` treated as a break-glass server credential, not the
      day-to-day path; rotated.
- [ ] Connection tokens in Vault (`vault://`) or, at least, never in plaintext.
- [ ] GitHub via App / fine-grained PAT with least scope; GHES hosts listed.
- [ ] AWS spokes via StackSet (`DeploymentMode=Organization`, `OrganizationId`
      set, `AutoDeployment` on for new accounts); discovery excludes the
      management account. Control Tower: the registered OUs are the scan scope,
      and `AWSControlTowerExecution` is not used.
- [ ] Identity Center access: the chart's `config.ssoDiscoveryMode` left at
      `disabled` unless a writable token cache and a ~90-day re-login are
      accepted; on an operator PC, the chosen permission set is read-only (pin it
      with `AWS_SSO_DISCOVERY_PERMISSION_SET` where that must not change).
- [ ] Read-only defaults unchanged; key actions off unless a policy allows.
- [ ] The SIEM alerts on `audit.chain_anchor` (preferably the worker log copy)
      whose `chain_state` is not `INTACT`, whose `open_problems` grows, whose
      `genesis_mac` changes, whose `anchor_no` is not the last one plus one, whose
      `chain_seq` goes down, or that stops arriving.

## Verification

- **Collection**: run a scan of a known-exposed source and confirm findings and
  their metadata (score, exposure locations, verification/identity where enabled).
- **Unauthenticated access is blocked**: a request with no bearer returns `401`
  (`web/tests/proxy.test.cjs` covers the proxy; the API rejects independently).
- **Viewer cannot mutate**: a `viewer`-group session gets `403` on any mutation
  (`require_role` enforces it server-side).
