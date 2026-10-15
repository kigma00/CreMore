// Synthetic proof of the Audit Log: a record opens by click and by Enter and shows its full ids and code; an action
// with no description keeps its raw code; a saved connection record says so; search finds records by their
// translated action words and their target; a filter chip narrows and clears from the keyboard; provider events are
// kept apart from CreMore's own records. Korean and English at 320 and 1440, light and dark.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { load } = require("./load-module.cjs");
const { openConsole, preview, settled, inBounds, assertClean, openMenu } = require("./console-proof.cjs");

const labels = load("@/components/labels.tsx");
const LONG = "7f3e2c1a-9b8d-4e6f-a5c4-3b2a1f0e9d8c";
const UNKNOWN = "SOMETHING_NOT_DESCRIBED_YET";

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  const answers = preview();
  const known = { actor_id: "test-operator", action: "CONNECTION_STOPPED", target_type: "connection", from_status: "ACTIVE", to_status: "DISABLED" };
  const rows = [
    { ...known, id: "11111111-1111-4111-8111-111111111111", target_id: LONG, target_name: "deploy-bot connection", note: "first line\nsecond line", created_at: "2026-10-01T06:20:00Z" },
    { ...known, id: "22222222-2222-4222-8222-222222222222", action: UNKNOWN, actor_id: "svc-worker", target_name: null, note: null, created_at: "2026-10-01T06:10:00Z" },
    // Revocation an older installation saved without an audit event, as the server shows it (cremore/api/routes/misc.py).
    { id: "connection-stop-record:44444444-4444-4444-8444-444444444444", actor_id: "UNKNOWN", action: "CONNECTION_STOPPED", target_type: "connection",
      target_id: "44444444-4444-4444-8444-444444444444", target_name: "old github", from_status: null, to_status: "DISABLED", note: null,
      created_at: "2026-10-01T06:00:00+00:00", recovered_from_connection: true },
    { ...known, id: "33333333-3333-4333-8333-333333333333", action: "API_REQUEST_ACCEPTED", target_type: "api_request",
      actor_name: "Alice", actor_email: "alice@example.test", target_id: LONG, target_name: null, note: null,
      created_at: "2026-10-01T05:50:00Z", activity: { method: "POST", route: "/api/v1/provider-connections/{connection_id}/check",
        targets: { connection_id: LONG }, status: 202, role: "admin" } },
  ];
  const event = (id, provider, type, object) => ({ id, provider, connection_id: "c-1", run_id: "r-1", event_type: type, event_id: `log-${id}`,
    occurred_at: "2026-09-29T11:40:00+00:00", observed_at: "2026-09-30T00:00:00+00:00", match_basis: "AUDIT_REFERENCE", confidence: "IDENTIFIER",
    subject: { entity_id: `e-${id}`, object_id: object, object_kind: "credential" }, target: null, facts: [] });
  const UNLISTED_EVENT = "outside.facets.user.revoke";
  const events = (filter, eventType) => {
    const all = [event("1", "gcp", "google.iam.admin.v1.DeleteServiceAccountKey", "apiKey:legacy-reporting"),
      event("2", "github", "personal_access_token.revoke", "pat:deploy-bot")];
    const candidates = eventType === UNLISTED_EVENT ? [event("3", "github", UNLISTED_EVENT, "pat:unlisted")] : all;
    const items = candidates.filter(item => (!filter || item.provider === filter) && (!eventType || item.event_type === eventType));
    // As the server counts them (cremore/coverage/metadata_store.py): the facets before a filter narrows the items, the
    // event types after.
    return { schema_version: 2, boundary: "PROVIDER_REPORTED_NOT_CREMORE_ACTIONS", event_types: [...new Set(items.map(item => item.event_type))],
      facets_truncated: true, event_types_truncated: true,
      facets: { provider: ["gcp", "github"], event_type: all.map(item => item.event_type) }, items, total: items.length, offset: 0, limit: 50 };
  };
  try {
    for (const locale of ["ko", "en"]) for (const [theme, width] of [["light", 320], ["dark", 1440]]) {
      const label = `${locale}-${theme}-${width}`;
      const { context, page, record } = await openConsole(browser, { width, locale, theme, view: "audit", answer: ({ method, endpoint }) => {
        if (method !== "GET") return undefined;
        if (endpoint === "audit?limit=1000") return rows;
        if (endpoint.startsWith("v2/coverage/events?")) {
          const params = new URLSearchParams(endpoint.split("?")[1]);
          return events(params.get("provider"), params.get("event_type"));
        }
        return answers[endpoint];
      } });
      try {
        await settled(page, record);
        const body = page.locator(".list-card tbody");
        assert.equal(await body.locator("tr").count(), 4, `${label}: the records`);
        await inBounds(page, `${label} records`);
        const pageBounds = await page.locator(".main").boundingBox();
        const tableBounds = await page.locator(".list-card table").boundingBox();
        // By click: the full record and target ids, the note as written.
        await body.locator("tr").nth(0).click();
        const drawer = page.locator(".drawer");
        await drawer.waitFor();
        assert.deepEqual(await page.locator(".main").boundingBox(), pageBounds, `${label}: drawer does not resize the page`);
        assert.deepEqual(await page.locator(".list-card table").boundingBox(), tableBounds, `${label}: drawer does not squeeze the table`);
        assert.equal(await drawer.evaluate(el => el.parentElement === document.body), true, `${label}: drawer above the main container`);
        await drawer.getByText("11111111-1111-4111-8111-111111111111", { exact: true }).waitFor();
        await drawer.getByText(LONG, { exact: true }).waitFor();
        assert.equal(await drawer.getByText(/first line\s+second line/).count(), 1, `${label}: the note`);
        await inBounds(page, `${label} record`);
        const close = drawer.getByRole("button", { name: locale === "ko" ? "상세 닫기" : "Close details", exact: true });
        await close.click();
        await drawer.waitFor({ state: "detached" });
        // By Enter: an action with no description keeps its code.
        await body.locator("tr").nth(1).focus();
        await page.keyboard.press("Enter");
        await drawer.getByText(UNKNOWN, { exact: true }).waitFor();
        await close.click();
        await drawer.waitFor({ state: "detached" });
        // A saved connection record reads as one.
        assert.equal(await body.locator("tr").nth(2).getByText(locale === "ko" ? "저장된 연결 기록" : "Saved connection record").count(), 1, `${label}: recovered row`);
        // Verified identity, request target and HTTP result; searchable by email.
        await page.locator("#audit-search").fill("alice@example.test");
        await page.waitForFunction(() => new URLSearchParams(location.search).get("q") === "alice@example.test");
        await settled(page, record);
        assert.equal(await body.locator("tr").count(), 1, `${label}: email search`);
        await body.getByText("Alice", { exact: true }).click();
        await drawer.getByText("alice@example.test", { exact: true }).waitFor();
        await drawer.getByText("202", { exact: true }).waitFor();
        await drawer.getByText("POST /api/v1/provider-connections/{connection_id}/check", { exact: true }).waitFor();
        await inBounds(page, `${label} activity`);
        await close.click();
        await drawer.waitFor({ state: "detached" });
        // Search by the translated action words, then by the target.
        const words = labels.auditActionText("CONNECTION_STOPPED", locale).label;
        await page.locator("#audit-search").fill(words);
        await page.waitForFunction(() => new URLSearchParams(location.search).has("q"));
        await settled(page, record, label);
        assert.equal(await body.locator("tr").count(), 2, `${label}: '${words}' finds the two stopped connections`);
        await page.locator("#audit-search").fill("deploy-bot");
        await page.waitForFunction(() => new URLSearchParams(location.search).get("q") === "deploy-bot");
        await settled(page, record, label);
        assert.equal(await body.locator("tr").count(), 1, `${label}: target search`);
        await page.locator("#audit-search").fill("");
        await page.waitForFunction(() => !new URLSearchParams(location.search).has("q"));
        await settled(page, record, label);
        // A filter chip: pick one actor, then clear it from the keyboard.
        const actor = page.locator(".chips-row .fchip", { hasText: locale === "ko" ? "수행자" : "Actor" });
        await openMenu(page, actor.locator(".fchip-open"));
        await page.locator(".menu .menu-item").filter({ hasText: "svc-worker" }).click();
        await page.keyboard.press("Escape");
        await settled(page, record);
        assert.equal(await body.locator("tr").count(), 1, `${label}: actor filter`);
        await actor.locator(".x").focus();
        await page.keyboard.press("Enter");
        await settled(page, record, label);
        assert.equal(await body.locator("tr").count(), 4, `${label}: filter cleared`);
        assert.equal(await actor.locator(".fchip-open").evaluate(el => el === document.activeElement), true, `${label}: focus back on the chip`);
        // Provider events sit apart, under their own banner, with their own filter.
        await page.getByRole("tab", { name: locale === "ko" ? "공급자 이벤트" : "Provider events" }).click();
        await settled(page, record);
        await page.getByText(locale === "ko" ? "공급자가 자기 자격증명에 대해 보고한 기록입니다." : "What providers reported about their own credentials.", { exact: false }).waitFor();
        assert.equal(await page.locator(".list-card tbody tr").count(), 2, `${label}: provider events`);
        await openMenu(page, page.locator(".chips-row button.fchip", { hasText: locale === "ko" ? "공급자" : "Provider" }));
        await page.locator(".menu .menu-item").filter({ hasText: "GitHub" }).click();
        await settled(page, record);
        assert.equal(await page.locator(".list-card tbody tr").count(), 1, `${label}: provider filter`);
        await page.getByText(locale === "ko" ? "조회 한도로 필터 선택지가 일부만 표시됩니다." : "Filter choices are partial because of the lookup limit.", { exact: false }).waitFor();
        await page.getByLabel(locale === "ko" ? "이벤트 이름 직접 조회" : "Look up an event by name", { exact: true }).fill(UNLISTED_EVENT);
        await page.getByRole("button", { name: locale === "ko" ? "조회" : "Look up", exact: true }).click();
        await page.waitForFunction(value => new URLSearchParams(location.search).get("pe.event") === value, UNLISTED_EVENT);
        await settled(page, record);
        assert.equal(await page.locator(".list-card tbody").getByText(UNLISTED_EVENT, { exact: true }).count(), 1, `${label}: unlisted event queried directly`);
        await page.getByRole("button", { name: locale === "ko" ? "이벤트 필터 해제" : "Clear event filter", exact: true }).click();
        await settled(page, record);
        assert.equal(await page.locator(".list-card tbody").getByText("personal_access_token.revoke", { exact: true }).count(), 1, `${label}: direct event filter cleared`);
        await inBounds(page, `${label} provider events`);
        assertClean(record, label);
        assert.deepEqual(record.writes, [], `${label}: a write`);
      } finally { await context.close(); }
    }
    console.log("PASS console audit log: records open by click and Enter with full ids and code, recovered rows marked, search by translated words and target, actor filter cleared from the keyboard, provider events apart with their own filter; ko/en at 320 and 1440.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
