# External-exposure overlay (Caddy + oauth2-proxy + OIDC)

The base `docker-compose.yml` runs in **local** mode: the web proxy attaches the
shared admin token for loopback callers, and `CREMORE_ALLOWED_HOSTS` is only a
DNS-rebinding guard — **not** per-user authentication. Adding TLS alone in front
of that would publish an admin-authenticated dashboard to everyone.

This overlay is the supported way to expose the dashboard to more than one
operator. It puts an OIDC login in front and switches the platform off the
admin-token path entirely — the same **oauth2-proxy → web → API OIDC** shape the
Helm chart uses, with Caddy handling TLS for Compose.

```
Internet ──TLS──▶ Caddy ──▶ oauth2-proxy ──▶ web (CREMORE_AUTH_MODE=oidc) ──▶ api (AUTH_MODE=oidc)
                            │ OIDC login       │ forwards the user's         │ validates JWT,
                            │ (per user)        │ bearer, never the           │ maps groups → role
                            ▼                   ▼ admin token                  ▼
                       your IdP                                          RBAC enforced
```

## Why this is safe

- **web** runs with `CREMORE_AUTH_MODE=oidc`, so the proxy forwards the caller's
  OIDC bearer and **never** attaches the local admin token — regardless of the
  `Host` header. (Covered by `web/tests/proxy.test.cjs`: *"OIDC mode never falls
  back to the local admin token…"*.)
- **api** runs with `AUTH_MODE=oidc`, so it independently validates every bearer
  (issuer, JWKS signature, audience, expiry) and maps the groups claim to a
  role. A user with no mapped group gets no access.
- The API and web host ports stay bound to `127.0.0.1` from the base file; the
  only public entry point is Caddy on 443.
- The shared admin token is **cleared**, not just unused: `API_TOKEN` and
  `CREMORE_API_TOKEN` are empty, so no container holds a credential it cannot
  use, and flipping `AUTH_MODE` back to `local` fails at startup rather than
  quietly restoring one shared identity for everyone.

## What changes about AWS access

IAM Identity Center access reads the interactive `aws sso login` token cached on
this machine. On a shared server that token is **one person's session**, so
every user of the dashboard would reach AWS as them and the account sweep would
run under their assignment. This overlay therefore hard-locks it off
(`AWS_SSO_DISCOVERY_MODE=disabled` on both `api` and `worker`), exactly as
`deploy/helm` does.

A shared install reaches member accounts the other way: deploy the read-only
scanner role with CloudFormation and register the account. That path has no
cached session, no 90-day re-login and no single person's identity in it.

## Owner approval and response links

A key's owner approves an action plan at `/owner-approval`, and the person asked
to deal with an exposed credential reports what they did at `/response`, after
signing in through this same login: neither needs a CreMore group, but the IdP
client must let them sign in (assign it to the people who own keys or fix
exposures) and put their `email` in the token. A token with `email_verified:
false` is refused; one without the claim (Entra ID sends none) is trusted as the
IdP's own address. Only the person whose email is the address the link went to
can read and answer it. In local mode no links are sent; the operator records
the owner's approval or the person's reply instead.

## Setup

1. **DNS**: point `PUBLIC_HOST` at this machine; open ports 80 and 443.
2. **IdP**: register a confidential client, redirect URI
   `https://PUBLIC_HOST/oauth2/callback`, and emit the four groups
   (`cremore-viewers`/`cremore-analysts`/`cremore-remediators`/`cremore-admins`, or your names)
   in the `groups` claim.
3. **Config**:
   ```bash
   cp deploy/compose/reverse-proxy/.env.public.example .env.public
   # fill in PUBLIC_HOST and every OIDC_* value
   ```
4. **Run** (both env files, both compose files):
   ```bash
   docker compose --env-file .env --env-file .env.public \
     -f docker-compose.yml -f deploy/compose/reverse-proxy/compose.public.yml up -d
   ```
5. Browse to `https://PUBLIC_HOST`. Caddy obtains the certificate on first
   request; without public DNS use `tls internal` (see the `Caddyfile`).
6. **SIEM** (recommended for a shared server): create the exporter's restricted
   database role ([grants](../../../docs/SIEM_INTEGRATION.md)), fill in the
   `SIEM_*` values in `.env.public`, and run with the exporter file included so
   connection health, heartbeats and findings reach the SOC unattended:
   ```bash
   docker compose --env-file .env --env-file .env.public \
     -f docker-compose.yml -f deploy/compose/reverse-proxy/compose.public.yml \
     -f deploy/compose/siem/compose.yml up -d
   ```
   A SIEM rule that alerts when `platform.heartbeat` stops for two intervals
   catches this whole stack, its database or the exporter going down.

## Released images

For a released installation, check out the corresponding source tag and download
`compose.release.yml` and `release-images.json` from that same GitHub release.
The override pins API, worker, web and oauth2-proxy to the exact digests built,
signed and attested by the release workflow. Apply it **after** every configuration
overlay and use Docker Compose 2.24.4 or newer (`build: !reset` is required):

```bash
docker compose --env-file .env --env-file .env.public \
  -f docker-compose.yml -f deploy/compose/reverse-proxy/compose.public.yml \
  -f compose.release.yml up -d --no-build
```

The release override removes local build settings and always pulls the pinned
images. Review `docker compose ... config --images` before starting and verify
image signatures/provenance under your deployment policy. Do not combine assets
from different releases or put an image-changing overlay after the release file.
Source-only commands above retain their development build/tag behavior.

If SIEM is enabled, download `compose.release.siem.yml` and add it last after
the normal SIEM overlay and `compose.release.yml`. The optional identity refresher
similarly uses `compose.release.identity.yml` after its normal overlays. These
files use the signed worker image. Include them only when the corresponding
service is configured; they are not standalone service definitions.

The release digest manifest covers CreMore's four published images. PostgreSQL
uses the base Compose file's pinned upstream digest. Caddy is an upstream image
outside this build/sign workflow: choose and verify its digest and put the bare
64-character SHA-256 value in `CREMORE_CADDY_SHA256` in `.env.public`. The release
override requires it and uses `caddy@sha256:<value>`; it cannot fall back to the
source overlay's `caddy:2` tag. CreMore's signatures do not cover that upstream
image, and the workflow does not claim to have audited the operator's choice.

## Operational notes

- The web container still receives `CREMORE_API_TOKEN` from the base file; in oidc
  mode the proxy never reads it. Rotate it as usual — it is not the auth path.
- Role changes are made in your IdP by moving users between groups; the platform
  reads the mapping on every request.
- Secret storage, GitHub App/GHES, and AWS org onboarding are configured
  separately — see [`docs/ENTERPRISE_HARDENING.md`](../../../docs/ENTERPRISE_HARDENING.md).
