# Contributing

Thank you for improving CreMore.

## One name

The product is **CreMore**; `cremore` is its identifier form -- the Python
package, the Compose project, the Helm chart, the container images, the
PostgreSQL database, the CloudFormation stack onboarding suggests. There is no
second name to learn.

## Before opening a change

- Read [AI_TEAM_CODING_GUIDE.md](docs/AI_TEAM_CODING_GUIDE.md) for module owners, provider contracts and extension recipes.
- Use a public issue for feature proposals and ordinary defects. Use the repository's private GitHub Security Advisory flow for suspected vulnerabilities.
- Never attach live credentials, raw customer objects, unredacted detector output, AWS session data, database dumps, or production logs.
- Keep changes within the self-hosted product boundary and preserve the security invariants documented in the README and security policy.
- Never commit a credential-shaped value, even a fake one. Detector fixtures
  split each value into adjacent string pieces (`"AKIAZ5X9K2" "MBV7QP3LN6"`) that
  join only at run time; `cremore/repository_secrets_test.py` scans every tracked file
  with the platform's engine and fails otherwise.
- Add or update tests for behavior changes. Real AWS tests must use an explicitly authorized disposable account and must not run by default.

## Local checks

```sh
pip install -e ".[dev]"
python -m pytest cremore/ -q                    # Python API, worker, engine, catalog audit
ruff check cremore
(cd web && npm ci --ignore-scripts && npm test && npx tsc --noEmit && npm run build)
(cd web && npm run test:browser)              # synthetic proofs; needs Google Chrome installed
node --test deploy/helm/tests/chart.test.cjs  # pinned Helm image; Compose CLI is also required
docker compose build
```

Without a Docker engine, the rendering suite can use the verified Helm **3.17.2**
binary through `CREMORE_HELM_BINARY`; Compose configuration rendering still uses
`docker compose config` and needs its CLI. Rendering does not deploy workloads.
Baseline lint findings and environment skips are recorded in
[REFACTOR_REPORT.md](docs/REFACTOR_REPORT.md), not silently treated as passing.

Pull requests should explain the user-visible behavior, security/trust-boundary impact, verification performed, migration or rollback needs, and any new dependency or license. Keep generated data, `.env`, local AWS profiles, temporary scan files, build output, and credentials out of commits.

## Reusing API code

Import shared validation, response projections and service helpers from their
owning modules, rather than from `cremore.api.dashboard`. The dashboard module
composes application dependencies; `routes/` handles HTTP registration.
See [API library boundaries and examples](docs/API_LIBRARIES.md) for the module
map, dependency context, compatibility imports and verification commands.
Changes to this boundary must keep `cremore/api/library_boundaries_test.py`
and the existing API behavior tests passing.

## Reusing metadata collectors

Use `CollectorRuntime` and `CollectionContext` for shared metadata execution.
Declare supported services in the provider registration; do not infer them
from function signatures. Keep authentication resolution, bounded batches and
provider I/O separate from task/transaction ownership. See
[Metadata collector libraries](docs/METADATA_COLLECTOR_LIBRARIES.md) for the
contract, registration steps, compatibility entry points and regression tests.

## Dependencies and licensing

**This project is Apache-2.0.** See `LICENSE` and `LICENSING.md`.

The detection engine lives under `cremore/detection/`. Every detector, decoder,
verification rule and false-positive heuristic is written from **public
encoding specifications and provider API documentation**, and records its
source in `source_url`.

Practical consequences for a change to the detection engine:

- Add or edit detectors only from provider/spec documentation and set an
  accurate `source_url`. **Do not copy code, patterns or wordlists from other
  projects** into `cremore/`; contributions must be your own work.
- Patterns must be RE2-safe (no lookaround/backreferences). The catalog audit
  (`cremore/detection/catalog_audit_test.py`) enforces this and rejects over-broad
  or unroutable detectors — keep it green.
- Keep `THIRD_PARTY_NOTICES.md` accurate when dependencies change.

## Console styles and dark mode

The console supports light and dark themes (the system's, or a per-device
choice in the top bar). Its one stylesheet, `web/app/(console)/console.css`,
defines colours as tokens on `:root` and defines them again for dark mode under
`:root[data-theme="dark"]` and `prefers-color-scheme: dark`. A new colour is a
token defined in both places, or one of the existing tokens (`--surface`,
`--ink`, `--line`, `--primary` and the rest); check both themes in the browser
proofs (`npm run test:browser` in `web/`).

By contributing, you agree that your contribution is provided under the
repository's Apache-2.0 license unless a file clearly states otherwise.
