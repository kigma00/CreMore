// Synthetic proof of the display timezone: chosen on the settings screen, it changes the times another open tab shows
// at once (no reload), survives a reload, and changes no stored time (the raw timestamp beside it stays).
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { load } = require("./load-module.cjs");
const { ORIGIN, openConsole, preview, capturedAt, settled, assertClean } = require("./console-proof.cjs");

const AT = "2026-10-01T06:20:00Z";

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  const answers = preview();
  const text = load("@/console/text.ts");
  // Expected times use the same fixed clock as the browser.
  const now = Date.parse(capturedAt());
  const shownIn = (locale, zone) => text.fmtDT(AT, locale, zone, now);
  const row = { id: "11111111-1111-4111-8111-111111111111", created_at: AT, actor_id: "test-operator", action: "CONNECTION_STOPPED",
    target_type: "connection", target_id: "test-connection", from_status: "ACTIVE", to_status: "DISABLED" };
  // The scan-trigger section also loads the bindable profiles and the detection alerts card: none set up.
  const extra = { "settings/scan-triggers/bindable-profiles": [], "settings/detection-alerts": { enabled: false, transport: "webhook",
    webhook_saved: false, channel: null, channels: [], bot_ready: false, min_severity: "HIGH", detail: "standard", language: "ko", events: [],
    console_url: null, enabled_at: null, updated_by: null, updated_at: null, status: { pending: 0, oldest_pending_at: null,
      last_seen_at: null, last_success_at: null, last_failure_at: null, last_error_code: null, consecutive_failures: 0 } } };
  const answer = ({ method, endpoint }) => method !== "GET" ? undefined : endpoint === "audit?limit=1000" ? [row]
    : extra[endpoint] ?? answers[endpoint];
  try {
    for (const locale of ["ko", "en"]) {
      const { context, page: settings, record } = await openConsole(browser, { width: 1280, locale, view: "settings", answer });
      try {
        await settled(settings, record);
        // A second tab shows the record's time.
        const audit = await context.newPage();
        await audit.goto(`${ORIGIN}/?view=audit&id=${row.id}`);
        const time = audit.locator(".drawer .fact", { hasText: AT }).locator("dd");
        await time.waitFor();
        const shown = async () => (await time.innerText()).replace(AT, "").trim();
        assert.equal(await shown(), shownIn(locale, "Asia/Seoul"), `${locale}: KST by default`);
        const zones = settings.getByRole("group", { name: locale === "ko" ? "표시 시간대" : "Display timezone" });
        await zones.getByRole("button", { name: "UTC" }).click();
        // The other tab follows at once.
        await audit.waitForFunction(([selector, expected]) => document.querySelector(selector)?.textContent.includes(expected),
          [".drawer", shownIn(locale, "UTC")]);
        assert.equal(await shown(), shownIn(locale, "UTC"), `${locale}: UTC in the other tab`);
        // A reload keeps it; the stored time beside it never changes.
        await audit.reload();
        await time.waitFor();
        assert.equal(await shown(), shownIn(locale, "UTC"), `${locale}: UTC after a reload`);
        assert.equal(await audit.locator(".drawer").getByText(AT, { exact: true }).count(), 1, `${locale}: the stored time`);
        await zones.getByRole("button", { name: "KST" }).click();
        await audit.waitForFunction(([selector, expected]) => document.querySelector(selector)?.textContent.includes(expected),
          [".drawer", shownIn(locale, "Asia/Seoul")]);
        // The schedules card says a scope's full scan starts at its own fixed time within 4 hours of the start time.
        await settings.getByRole("tab", { name: locale === "ko" ? "스캔 시작 조건" : "What starts a scan" }).click();
        await settings.getByText(locale === "ko" ? "시작 시각부터 최대 4시간 뒤" : "between the start time and up to 4 hours later",
          { exact: false }).waitFor();
        await settled(settings, record);
        assert.deepEqual(record.writes, [], `${locale}: a device preference writes nothing to the server`);
        assertClean(record, locale);
      } finally { await context.close(); }
    }
    console.log("PASS console display timezone: KST by default, a choice on the settings screen changes another tab at once, survives a reload, and leaves the stored time as it was; the scan-trigger section says full scans start within 4 hours of the start time; ko/en.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
