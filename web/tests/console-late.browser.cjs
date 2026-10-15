// Synthetic proof that a late answer never lands in the wrong panel: credential A's details are slow, the reader opens
// credential B meanwhile, and when A's answer finally arrives B's panel still shows B's exposure. Phone and desktop.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { openConsole, preview, settled, assertClean } = require("./console-proof.cjs");

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  const answers = preview();
  const records = answers["credential-records"].items.filter(item => item.exposed && item.finding_id);
  const a = records.find(item => item.credential_id === "5db0c402-9087-42c0-9039-69bf34e32663");
  const b = records.find(item => item !== a);
  // B's answers are A's with B's ids and its own location, so whose they are shows on the page.
  const ofB = text => JSON.parse(JSON.stringify(text).replaceAll(a.finding_id, b.finding_id).replaceAll(a.credential_id, b.credential_id)
    .replaceAll("exports/2026-09/app.env.bak", "only-in-b/settings.env"));
  try {
    for (const width of [390, 1280]) {
      const label = `w${width}`;
      let late = 0;
      const { context, page, record } = await openConsole(browser, { width, view: "exposed", answer: async ({ method, endpoint }) => {
        if (method !== "GET") return undefined;
        if (endpoint.includes(b.finding_id) || endpoint.includes(b.credential_id)) {
          const original = endpoint.replaceAll(b.finding_id, a.finding_id).replaceAll(b.credential_id, a.credential_id);
          return answers[original] === undefined ? undefined : ofB(answers[original]);
        }
        // A's details take their time.
        if (endpoint.includes(a.finding_id)) { await sleep(1500); late = Date.now(); }
        return answers[endpoint];
      } });
      try {
        await settled(page, record);
        const row = item => page.locator("tbody tr").filter({ hasText: item.hint }).first();
        await row(a).focus();
        await page.keyboard.press("Enter");
        await page.locator(".drawer").waitFor();
        // B, before A's details have come.
        await row(b).focus();
        await page.keyboard.press("Enter");
        await page.waitForFunction(id => decodeURIComponent(location.search).includes(id), b.id);
        const opened = Date.now();
        // Settled: nothing in flight, so A's slow answers have come too, after B was opened.
        await settled(page, record, label);
        assert.ok(late > opened, `${label}: A's answer came after B was opened`);
        const drawer = page.locator(".drawer");
        assert.equal(await drawer.getByText("only-in-b/settings.env", { exact: false }).count() > 0, true, `${label}: B's exposure`);
        assert.equal(await drawer.getByText("exports/2026-09/app.env.bak", { exact: false }).count(), 0, `${label}: nothing of A's in B's panel`);
        assertClean(record, label);
        assert.deepEqual(record.writes, [], `${label}: a write`);
      } finally { await context.close(); }
    }
    console.log("PASS console late answers: a slow answer for one credential never replaces the panel of the credential opened after it; 390 and 1280.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
