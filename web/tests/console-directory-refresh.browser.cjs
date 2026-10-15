// Stored directory status and explicit metadata refresh; every provider response is synthetic.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { openConsole, preview, settled, inBounds, assertClean, withScreenshot, refusal } = require("./console-proof.cjs");
const person = n => ({ id: `p${n}`, person_ref: `p${n}`, name: `Person ${n}`, email: `person${n}@example.test`, state: "ACTIVE", selectable: true, sources: [] });
const source = (provider, extra = {}) => ({ connection_id: `${provider}-child`, provider, name: `${provider} directory`,
  provider_connection_id: `${provider}-owner`, status: "READY", usable: true, observed_at: "2026-10-01T12:00:00Z",
  schedule_minutes: 5, collection_status: null, ...extra });
const listing = (sources, items = [], extra = {}) => ({ items, total: items.length, next_cursor: null,
  directory: { status: sources[0]?.status ?? "NOT_CONFIGURED", usable: sources[0]?.usable ?? false, sources }, ...extra });

async function overview(browser, role, locale, width) {
  const answers = preview(); answers.session.role = role; answers.session.auth_mode = "oidc";
  let queued = false, deny = false;
  const sources = () => [source("okta", { collection_status: queued ? "QUEUED" : null }), source("entra_id", { schedule_minutes: 17 }),
    source("keycloak", { status: "PROFILES_DISABLED", usable: false, schedule_minutes: 0 }), source("google_workspace", { provider_connection_id: null })];
  const { page, context, record } = await openConsole(browser, { view: "assign", width, locale, theme: width === 360 ? "dark" : "light",
    answer: ({ method, endpoint }) => {
      if (method === "GET") return endpoint === "people?q=&limit=1" ? listing(sources()) : answers[endpoint];
      if (endpoint === "v2/coverage/connections/okta-child/collect") { if (deny) return refusal(403, "FORBIDDEN"); queued = true; return { job_id: "job-one", status: "QUEUED" }; }
      if (endpoint === "v2/coverage/connections/keycloak-child/collect") return { job_id: "employment-state-only", status: "QUEUED" };
    } });
  const L = (ko, en) => locale === "ko" ? ko : en;
  try {
    await withScreenshot(page, `directory-${role}-${width}`, async () => {
      await settled(page, record);
      if (role === "Viewer") {
        assert.equal(await page.locator(".people-directory").count(), 0);
        assert.equal(record.calls.some(call => call.endpoint.startsWith("people?")), false);
        assertClean(record, "viewer cannot request analyst directory"); return;
      }
      const directory = page.locator(".people-directory");
      assert.ok((await directory.textContent()).includes(L("5분마다", "Every 5 minutes")));
      assert.ok((await directory.textContent()).includes(L("17분마다", "Every 17 minutes")));
      assert.ok((await directory.textContent()).includes(L("직접 실행할 때만", "Only when run manually")));
      assert.ok((await directory.textContent()).includes(L("마지막 수집", "Last collected")));
      assert.equal(await directory.getByRole("link").count(), role === "Admin" ? 3 : 0);
      if (role === "Admin") assert.equal(await directory.getByRole("link").first().getAttribute("href"), "/?view=sources&edit=okta-owner&step=3");
      const employmentRefresh = page.getByRole("button", { name: `${L("지금 갱신", "Refresh now")} · keycloak directory`, exact: true });
      assert.equal(await employmentRefresh.isDisabled(), false, "profile retention is not required to refresh employment state");
      await page.clock.fastForward(30_000); await settled(page, record);
      assert.equal(record.writes.length, 0, "display polling must never collect from a provider");
      const refresh = page.getByRole("button", { name: `${L("지금 갱신", "Refresh now")} · okta directory`, exact: true });
      deny = true; await refresh.click(); await settled(page, record);
      assert.equal(await directory.getByRole("alert").count(), 1, "API denial is visible without hiding last good status");
      assert.ok((await directory.textContent()).includes(L("5분마다", "Every 5 minutes")));
      deny = false; await refresh.click(); await settled(page, record);
      assert.equal(await refresh.isDisabled(), true);
      assert.ok((await directory.textContent()).includes(L("갱신 대기 중", "Refresh queued")));
      assert.deepEqual(record.writes.map(write => write.endpoint), ["v2/coverage/connections/okta-child/collect", "v2/coverage/connections/okta-child/collect"]);
      await page.clock.fastForward(30_000); await settled(page, record);
      assert.equal(record.writes.length, 2, "polling a queued collection must not resubmit it");
      await employmentRefresh.click(); await settled(page, record);
      assert.equal(record.writes.at(-1).endpoint, "v2/coverage/connections/keycloak-child/collect");
      assert.ok((await directory.textContent()).includes(L("이름·이메일 보관", "Enable name and email profiles")), "refreshing employment state does not imply retained profiles");
      await inBounds(page, `directory-${role}-${width}`); assertClean(record, "directory overview");
    });
  } finally { await context.close(); }
}

async function picker(browser) {
  const answers = preview(), row = answers["credential-records"].items[0], finding = row.finding_id;
  answers.session.role = "Analyst"; answers.session.auth_mode = "oidc";
  let phase = "ready";
  const { context, page, record } = await openConsole(browser, { view: "exposed", locale: "en", width: 360, theme: "dark", query: `&id=${encodeURIComponent(row.id)}`,
    answer: ({ method, endpoint }) => {
      if (method === "GET") {
        if (endpoint === `findings/${finding}/response/routing`) return { version: 1, status: "UNASSIGNED", manual_email_allowed: false, assignment: null, recommendations: [], targets: [] };
        if (endpoint.startsWith("people?q=")) {
          const cursor = new URL(endpoint, "https://example.test").searchParams.get("cursor");
          if (phase === "ready" || phase === "autoqueued") return listing([source("okta", { collection_status: phase === "autoqueued" ? "QUEUED" : null })],
            [person(cursor ? 2 : 1)], { total: 2, next_cursor: cursor ? null : "old-snapshot" });
          assert.equal(cursor, null, "refresh drops the old snapshot cursor");
          if (phase === "done") return listing([source("okta", { observed_at: "2026-10-01T12:05:00Z" })], [person(3)]);
          return listing([source("okta", { status: "SYNCING", usable: false, collection_status: phase === "queued" ? "QUEUED" : "RUNNING" })], []);
        }
        return answers[endpoint];
      }
      if (endpoint === "v2/coverage/connections/okta-child/collect") { phase = "queued"; return { job_id: "only-directory", status: "QUEUED" }; }
    } });
  try {
    await withScreenshot(page, "directory-picker-refresh", async () => {
      await settled(page, record);
      await page.getByRole("button", { name: "Actions", exact: true }).click();
      await page.getByRole("menuitem", { name: "Assign owner", exact: true }).click(); await settled(page, record);
      const modal = page.getByRole("dialog"), combo = modal.getByRole("combobox", { name: "Responder", exact: true });
      await combo.click(); await settled(page, record);
      await page.getByRole("listbox").getByRole("option", { name: /Person 1/ }).click();
      assert.equal(await modal.getByRole("button", { name: "Assign", exact: true }).isDisabled(), false);
      phase = "autoqueued";
      await combo.click(); await settled(page, record); await page.clock.fastForward(10_000); await settled(page, record);
      assert.match(await combo.textContent(), /person1@example.test/, "an automatically queued job does not clear a valid selected person");
      assert.equal(await modal.getByRole("button", { name: "Assign", exact: true }).isDisabled(), false);
      assert.equal(record.writes.length, 0);
      await page.keyboard.press("Escape"); phase = "ready";
      await combo.click(); await settled(page, record);
      await page.getByRole("button", { name: "Load more results" }).click(); await settled(page, record);
      assert.equal(await page.getByRole("listbox").getByRole("option").count(), 2);
      const before = await modal.boundingBox();
      await page.getByRole("button", { name: "Refresh now · okta directory", exact: true }).click(); await settled(page, record);
      assert.equal(await modal.getByRole("button", { name: "Assign", exact: true }).isDisabled(), true, "the selected snapshot is invalidated before using a refreshed directory");
      assert.equal(await page.getByRole("button", { name: "Refresh now · okta directory", exact: true }).isDisabled(), true);
      assert.equal(await page.locator(".menu").getByRole("link").count(), 0, "analysts do not get the admin settings link");
      phase = "running"; await page.clock.fastForward(10_000); await settled(page, record);
      assert.match(await page.locator(".menu").textContent(), /Refreshing/);
      phase = "done"; await page.clock.fastForward(10_000); await settled(page, record);
      await page.getByRole("listbox").getByRole("option", { name: /Person 3/ }).waitFor();
      const after = await modal.boundingBox(); assert.equal(after.x, before.x); assert.equal(after.width, before.width);
      await inBounds(page, "directory-picker-overlay");
      await page.getByLabel("Search IdP people").press("ArrowDown"); await page.keyboard.press("Enter");
      assert.match(await combo.textContent(), /person3@example.test/);
      assert.equal(record.writes.length, 1); assertClean(record, "directory picker refresh");
    });
  } finally { await context.close(); }
}

async function schedule(browser) {
  const answers = preview(), named = label => ({ label, label_ko: label });
  const descriptor = { provider: "okta", ...named("Okta"), editions: [{ id: "cloud", ...named("Cloud") }], target: [],
    purposes: { identity: { permissions: [], plan: [
      { name: "people_details", kind: "bool", default: false, ...named("Profiles") },
      { name: "schedule_minutes", kind: "number", default: 5, ...named("Schedule") },
    ] } }, auth_methods: [{ id: "private_key_jwt", ...named("OAuth app"), purposes: ["identity"], fields: [], renewal: "NONE" }] };
  let connection = { id: "okta-owner", provider: "okta", edition: "cloud", name: "Okta directory", status: "ACTIVE", revision: 4,
    purposes: ["identity"], plans: { identity: { people_details: true, schedule_minutes: 17 } }, target: { domain: "https://example.okta.com" },
    auth_method: "private_key_jwt", credential: { roles: ["credential"], reference: false }, children: [],
    checks: { checked_at: "2026-10-02T02:00:00Z", requested_at: "2026-10-02T01:00:00Z", stale: false, results: {} } };
  answers["provider-connections/catalog"] = { purposes: [], providers: [descriptor] };
  answers["provider-connections"] = [connection];
  const { context, page, record } = await openConsole(browser, { view: "sources", locale: "en", query: "&edit=okta-owner&step=3",
    answer: ({ method, endpoint, body }) => {
      if (method === "GET") return endpoint === "provider-connections/okta-owner" ? connection : answers[endpoint];
      if (endpoint === "provider-connections/okta-owner/plans/identity") {
        assert.deepEqual(body, { expected_revision: 4, plan: { people_details: true, schedule_minutes: 5 } });
        connection = { ...connection, revision: 5, plans: { identity: body.plan } }; return connection;
      }
    } });
  try {
    await withScreenshot(page, "directory-schedule", async () => {
      await settled(page, record);
      const select = page.getByLabel("Schedule", { exact: true }); await select.waitFor();
      assert.equal(await select.inputValue(), "17", "an arbitrary saved cadence is retained");
      const choices = await select.locator("option").evaluateAll(items => items.map(item => item.value));
      for (const value of ["0", "5", "15", "30", "17"]) assert.ok(choices.includes(value), `schedule choice ${value}`);
      await select.selectOption("5");
      await page.getByRole("button", { name: "Save changes", exact: true }).click(); await settled(page, record);
      await page.getByRole("heading", { name: "Changes saved", exact: true }).waitFor();
      assert.deepEqual(record.writes.map(write => write.endpoint), ["provider-connections/okta-owner/plans/identity"]);
      assertClean(record, "directory existing plan editor");
    });
  } finally { await context.close(); }
}

(async () => {
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  try {
    await overview(browser, "Admin", "ko", 1440);
    await overview(browser, "Analyst", "en", 360);
    await overview(browser, "Viewer", "en", 1440);
    await picker(browser);
    await schedule(browser);
    console.log("PASS directory refresh: exact source, analyst/admin/viewer rights, queued/running/completed, no automatic writes, server denial, stale cursor/selection reset, arbitrary schedule/manual display, overlay/keyboard/KO/EN/light/dark/360px.");
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
