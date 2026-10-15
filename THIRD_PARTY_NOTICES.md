# Third-party notices

This repository is licensed under Apache-2.0 (see [`LICENSE`](LICENSE)). It does
not bundle any third-party source. This file records the runtime dependencies the
Python platform requires and their licences.

## Detection engine

The detection engine is the project's own code, written from public encoding
specifications and provider API documentation (each detector records its source
in `source_url`). It bundles no third-party detector catalog, wordlist or
scanner.

## Python runtime dependencies

These are required at install/run time (declared in [`pyproject.toml`](pyproject.toml))
and are not redistributed as source in this repository. Each is used under its own
licence:

| Dependency | Licence |
| --- | --- |
| FastAPI | MIT |
| Starlette | BSD-3-Clause |
| Uvicorn | BSD-3-Clause |
| Pydantic / pydantic-settings | MIT |
| SQLAlchemy | MIT |
| psycopg | LGPL-3.0 (used as an unmodified library) |
| httpx | BSD-3-Clause |
| idna | BSD-3-Clause |
| dnspython | ISC |
| boto3 / botocore | Apache-2.0 |
| google-re2 | BSD-3-Clause (optional; falls back to the Python standard `re`) |
| PyJWT | MIT |
| cryptography (via `PyJWT[crypto]`) | Apache-2.0 OR BSD-3-Clause |
| pytest (dev only) | MIT |
| ruff (dev only) | MIT |

The Helm chart's OIDC sidecar image is built from oauth2-proxy (MIT) source
verified by hash in `deploy/docker/oauth2-proxy.Dockerfile`; its licence file is
copied into that image.

Consult each project for the authoritative licence text. The web frontend
(`web/`) declares its own dependencies in its `package.json`. Next.js installs
`sharp` (libvips, LGPL-3.0) as an optional image-optimization dependency; the
dashboard does not use `next/image`, so `web/next.config.ts` disables image
optimization and excludes `sharp`/`@img` from the standalone output, and CI
fails if they reappear in the web image.
