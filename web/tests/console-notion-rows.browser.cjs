// Synthetic proof of choosing a Notion database's rows as scan targets: the database's rows are listed for it alone,
// none is chosen until someone chooses it, and saving keeps exactly the chosen rows (by their Notion page ids) with
// the rows-only page mode. The integrations screen is an Admin's: a Viewer is told so, and nothing of the integration
// is read or sent. Phone and desktop.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { respond, openConsole, preview, settled, inBounds, assertClean, openMenu } = require("./console-proof.cjs");

const NOTION = "5f74386e-28a0-4700-90b1-5140c5451819", SOURCE = "91c75b21-cd1e-4b32-8a59-338a9426af51";
const BASE = `connections/source/${SOURCE}`;
const DATABASE = { id: "res-db", provider_resource_id: "db-11111111111111111111111111111111", resource_type: "NOTION_DATA_SOURCE", display_name: "Customer list",
  canonical_reference: "Customer list", provider_instance_id: "notion", visibility: "WORKSPACE", list_visibility: "VISIBLE", content_readiness: "NEEDS_RUNTIME_CHECK" };
const PAGE = { ...DATABASE, id: "res-page", provider_resource_id: "pg-22222222222222222222222222222222", resource_type: "NOTION_PAGE", display_name: "Runbook", canonical_reference: "Runbook" };
const row = n => ({ ...PAGE, id: `res-row-${n}`, provider_resource_id: `row-${n}${"0".repeat(31)}`, display_name: `Customer ${n}`, canonical_reference: `Customer ${n}`,
  parent_id: DATABASE.provider_resource_id });
const catalog = items => ({ kind: "source", connection_id: SOURCE, catalog_snapshot_id: "snap-1", auth_revision: "auth-1", items, catalog_completeness: "COMPLETE",
  last_refreshed_at: "2026-10-01T06:00:00Z", known_count: items.length, count_accuracy: "EXACT", has_more: false, available_filters: ["resource_type"] });

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  const answers = preview();
  const notion = { id: NOTION, provider: "notion", edition: "cloud", name: "Notion · Test", status: "ACTIVE", revision: 1,
    purposes: ["exposure"], target: {}, plans: { exposure: {} }, auth_method: "integration", renewal: "NONE",
    credential: { roles: ["credential"], reference: false }, checks: { results: {}, stale: false },
    children: [{ kind: "content", id: SOURCE, purpose: "exposure" }] };
  answers["provider-connections"] = [notion];
  answers["provider-connections/catalog"] = { purposes: ["exposure"], providers: [{ provider: "notion", label: "Notion", label_ko: "Notion",
    category: "saas", editions: [{ id: "cloud", label: "Cloud", label_ko: "클라우드" }], purposes: { exposure: {} }, auth_methods: [] }] };
  answers[`${BASE}/scan-scope-profiles`] = { kind: "source", connection_id: SOURCE, profiles: [], runs: [], state: "UNCONFIGURED" };
  try {
    for (const role of ["Admin", "Viewer"]) for (const width of [390, 1280]) {
      const label = `${role}-${width}`;
      const { context, page, record } = await openConsole(browser, { width, theme: "light", view: "sources", answer: ({ method, endpoint, body }) => {
        if (endpoint === "session") return { ...answers.session, role };
        if (endpoint === `provider-connections/${NOTION}`) return notion;
        if (method === "POST" && endpoint === `provider-connections/${NOTION}/check`) return { ...notion,
          checks: { stale: false, requested_at: "2026-10-01T12:00:00Z", checked_at: "2026-10-01T12:00:00Z", blockers: [],
            requested_plans: body.plans, results: { exposure: { status: "PASSED", items: [{ permission: "contents", status: "GRANTED" }] } } } };
        if (method === "GET" && endpoint.startsWith(`${BASE}/resources?`)) {
          const query = new URLSearchParams(endpoint.split("?")[1]);
          // A database's rows, asked for by the database's own id; otherwise the places the account sees.
          return query.get("parent_id") === DATABASE.provider_resource_id && query.get("resource_type") === "NOTION_PAGE" ? catalog([row(1), row(2), row(3)]) : catalog([DATABASE, PAGE]);
        }
        // As the server gives a saved profile (cremore/scanning/scope.py profile_public).
        if (method === "POST" && endpoint === `${BASE}/scan-scope-profiles`) return respond(201, { kind: "source", connection_id: SOURCE,
          id: "00000000-0000-4000-8000-000000000051", name: body.name, version: 1, state: "READY", selected_roots: body.selected_roots, excluded_ids: body.excluded_ids ?? [],
          budgets: body.budgets, schedule_minutes: body.schedule_minutes, event_mode: body.event_mode, change_reason: body.change_reason, catalog_snapshot_id: "snap-1",
          auth_revision: "auth-1", approved_by: "local operator", approved_at: "2026-10-01T06:30:00+00:00" });
        return method === "GET" ? answers[endpoint] : undefined;
      } });
      try {
        await settled(page, record);
        const menu = page.locator(`button[aria-label^="Notion · "][aria-label$="연동 메뉴"]`);
        if (role === "Viewer") {
          // The integrations screen is an Admin's: a Viewer is told so, and nothing of the integration is read or sent.
          await page.locator(".placeholder").getByText("이 화면을 볼 권한이 없습니다").waitFor();
          assert.equal(await menu.count(), 0, `${label}: no integration menu`);
          assert.deepEqual(record.calls.filter(call => call.endpoint.startsWith(BASE)), [], `${label}: nothing of the integration read`);
          assert.deepEqual(record.writes, [], `${label}: a write`);
        } else {
          await openMenu(page, menu);
          await page.locator(".menu .menu-item", { hasText: "검사 대상 설정" }).click();
          const dialog = page.locator("[role=dialog]");
          await dialog.getByText("Customer list", { exact: true }).waitFor();
          await settled(page, record);
          const pageChoice = dialog.getByRole("checkbox", { name: "Runbook 고르기" });
          await pageChoice.focus();
          await page.keyboard.press("Space");
          // A `has` locator is queried inside the row, so it must not start from the dialog.
          const pageRow = dialog.locator("tr", { has: page.getByRole("checkbox", { name: "Runbook 빼기" }) });
          assert.equal(await pageRow.getByText("이 페이지만", { exact: true }).count(), 1, `${label}: page-only scope`);
          assert.equal(await pageRow.getByRole("button", { name: "범위 좁히기", exact: true }).count(), 0, `${label}: no unsupported subpage toggle`);
          await dialog.getByRole("checkbox", { name: "Customer list 고르기" }).click();
          await dialog.getByRole("button", { name: "행 고르기" }).click();
          await dialog.getByText("Customer 3", { exact: true }).waitFor();
          // The rows were asked for under the database itself.
          const asked = record.calls.find(call => call.endpoint.includes("parent_id="));
          assert.equal(new URLSearchParams(asked.endpoint.split("?")[1]).get("known_root_id"), DATABASE.provider_resource_id, `${label}: rows of this database`);
          // None is chosen until someone chooses it.
          const rows = dialog.locator(".tg-rows [role=checkbox]");
          assert.deepEqual(await rows.evaluateAll(items => items.map(item => item.getAttribute("aria-checked"))), ["false", "false", "false"], `${label}: no row chosen by default`);
          await rows.nth(0).click();
          await rows.nth(2).click();
          assert.deepEqual(await rows.evaluateAll(items => items.map(item => item.getAttribute("aria-checked"))), ["true", "false", "true"], `${label}: the chosen rows`);
          await inBounds(page, `${label} rows`);
          await dialog.getByRole("button", { name: "다음", exact: true }).click();
          await dialog.getByRole("button", { name: "저장", exact: true }).click();
          await dialog.getByText("검사 대상을 저장했습니다").waitFor();
          const saved = record.writes;
          assert.deepEqual(saved.map(write => `${write.method} ${write.endpoint}`),
            [`POST provider-connections/${NOTION}/check`, `POST ${BASE}/scan-scope-profiles`], `${label}: permission check before one save`);
          assert.deepEqual(saved[0].body, { plans: notion.plans }, `${label}: check the connection's current plans`);
          const roots = saved[1].body.selected_roots;
          assert.equal(roots.length, 2, `${label}: one database and one page`);
          const databaseRoot = roots.find(root => root.resource_id === DATABASE.id);
          assert.equal(databaseRoot.page_mode, "DATA_SOURCE_SELECTED_PAGES", `${label}: rows only`);
          assert.deepEqual([...databaseRoot.descendant_ids].sort(), [row(1).provider_resource_id, row(3).provider_resource_id].sort(), `${label}: exactly the chosen rows`);
          assert.equal(databaseRoot.include_future_descendants, false, `${label}: no row added later`);
          const pageRoot = roots.find(root => root.resource_id === PAGE.id);
          assert.equal(pageRoot.page_mode, "PAGE_ONLY", `${label}: page-only approval`);
          assert.deepEqual(pageRoot.descendant_ids, [], `${label}: no implicit subpage approval`);
        }
        assertClean(record, label);
      } finally { await context.close(); }
    }
    console.log("PASS console Notion rows: a database's rows listed under it, none chosen by default, saved exactly as chosen with the rows-only mode and no later rows; a Viewer cannot open the screen and nothing is read or sent; 390 and 1280.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
