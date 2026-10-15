# Console layout

The web application is the CreMore console, a Next.js app served at `/`. Paths
below are relative to this `web/` directory.

```
app/(console)/  the console's route group: page (/), root layout, console.css, Pretendard fonts,
                and the pages Google, GitHub and an owner's approval link return to
app/api/        the server-side proxy to the API (backend/[...path]) and the owner approval relay
console/        the console itself: shell, routes, data, layers, shared UI and views/<screen>/
components/     locale, theme, display timezone and the words for the API's codes (labels.tsx)
lib/            no JSX: the API client, the session, shared types, the scan scope model, source types
tests/          node tests (*.test.cjs) and browser proofs (console-*.browser.cjs)
scripts/        alias resolution for the tests
```

There are no provider directories with UI of their own. An integration's
connection wizard is drawn from the provider's onboarding descriptor (served by
`GET provider-connections/catalog`), so adding a provider changes no web build
setting. What a provider needs beyond that -- its setup guide, its words, a
screen such as AWS's settings or GitHub App installation -- lives in
`console/views/integrations/`, and its logo in `public/logos/` with
`console/logo-set.ts`.

**Dependencies flow from views to the console's shared modules and pure lib.**
`lib/` imports nothing from the console. `components/` may use `lib/`. A view
may use both, and the console's `data.ts`, `layer.tsx`, `ui.tsx`, `text.ts`.
Pure models (`model.ts` beside a view) do not import React views.

## Imports

Cross-file imports use `@/`:

```ts
import { api } from "@/lib/dashboard-api";
import { useLocale } from "@/components/locale";
import { useApi, send } from "@/console/data";
import { Modal } from "@/console/layer";
```

A relative import spells a file differently depending on where the importer
sits, so moving either one silently rewrites the other's address. The alias
does not, which is what makes a file movable at all. `tsconfig.json` owns it.

## Styling

The console has one stylesheet, `app/(console)/console.css`, loaded by its root
layout. Colours, surfaces, lines and shadows are tokens on `:root`; dark mode
redefines the same tokens under `:root[data-theme="dark"]` and, when no light
choice is saved, under `prefers-color-scheme: dark`. A saved choice is set on
`<html>` before paint by the layout's inline script (`lib/theme-script.ts`), so
the page never flashes the other theme. New rules use the tokens, scope their
classes to the screen's container, and avoid inline styles and broad selectors.

Text is set in Pretendard (`app/(console)/fonts`, SIL Open Font License, a
KS X 1001 subset), loaded with `next/font/local`. There is no Tailwind, CSS
Module or class-name helper library; `cls()` in `console/ui.tsx` joins
conditional class names.

## Tests

`tests/load-module.cjs` resolves a specifier the way the bundler does, for the
node tests; `tests/bundle-module.cjs` does the same for the browser proofs,
which render the real console in headless Chrome. Both use
`scripts/source-paths.cjs` to read `@/...` from `tsconfig.json`, so a test names
a module the same way the application does and a moved file is one edit.
Neither stubs anything: a test that wants a scripted `react` or an extra export
passes it explicitly.

Run these commands from `web/` after `npm ci --ignore-scripts`:

```sh
npm test              # node tests, no browser
npm run test:browser  # browser proofs (needs Chrome)
npm run build         # production build
npx tsc --noEmit      # types
```

The console's proofs (`tests/console-*.browser.cjs`) share `tests/console-proof.cjs`.
It bundles the real console (`console/app.tsx`) with `app/(console)/console.css`
and its Pretendard fonts, serves it from a synthetic origin and answers every API
request from the proof. The shared harness builds empty API responses and the
minimum credential rows used by the panel and list checks; each proof adds the
inputs its assertions need at run time. These inputs are never captured from a
running installation or saved as a data file. The browser's clock starts at a
fixed time so date assertions do not depend on the test date. Each proof records
writes, reads with no synthetic answer, requests off the page and page errors,
and fails on any it does not expect;
where a proof checks layout, a page, details panel or dialog that scrolls
sideways or leaves the viewport fails it. `console-shell` walks every screen on
the rail and a credential panel in Korean and English, light and dark, at 360,
768 and 1440 pixels, and keeps a screenshot of a failing layout with the run's
artifacts (the system temporary directory when a proof runs alone); the others
cover search, storage records, rescans, key deletion plans, the audit log, Notion
database rows, the credential list, the display timezone, late answers and the
page Google returns a GCP sign-in to.

A proof that names a path with no synthetic answer means a screen reads something
new: add the smallest response needed to that proof, or to
`tests/console-proof.cjs` when the response is shared. Run the affected proof with
`npm run test:browser -- <proof-name>`, then the relevant broader checks. No
development API or seeded database is needed.

Console changes include the surfaces reached from each screen: detail panels,
dialogs, menus, filters, selection, paging and focus return. Use synthetic
records for these checks; a screen that renders does not verify live provider
permissions, credential validity, collection completeness or SIEM delivery.

## Build

`next.config.ts` sets the repository root for Turbopack and output tracing, so
the standalone build keeps the layout the image runs. It also redirects
`/console`, where the console lived while it replaced the old dashboard, to `/`
with its query, and the old dashboard's `/demo` page to `/`.

The Docker build context is the repository root; only `web/` enters it
(`Dockerfile.dockerignore`):

```sh
docker build -f web/Dockerfile .
```

The standalone build entry is `web/.next/standalone/web/server.js` relative to
the repository root. The Dockerfile copies public assets and `.next/static`
alongside that nested application and starts `web/server.js`. Follow the
[team guide](../docs/AI_TEAM_CODING_GUIDE.md) and the
[Next.js workspace instructions](AGENTS.md) for shared contracts and checks.
