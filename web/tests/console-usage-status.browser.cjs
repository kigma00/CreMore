"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { openConsole, preview, settled, assertClean, withScreenshot, respond } = require("./console-proof.cjs");

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  const answers = preview();
  const key = answers["credential-records"].items[0];
  key.hint = "AKIA••••TEST";
  answers[`credentials/${key.credential_id}/usage`] = {
    collection_status: "PARTIAL", region_discovery_status: "FALLBACK", region_discovery_error: "UnauthorizedOperation",
    regions_discovered: 10, regions_complete: 0, regions_failed: 8, regions_capped: 2,
    window_start: "2026-07-02T00:00:00Z", window_end: "2026-09-30T00:00:00Z",
    collected_at: "2026-09-30T00:00:00Z", events: [], coverage: [], scenarios: [],
  };
  try {
    for (const locale of ["ko", "en"]) for (const theme of ["light", "dark"]) for (const width of [320, 1440]) {
      const label = `${locale}-${theme}-${width}`;
      const { context, page, record } = await openConsole(browser, { locale, theme, width, height: 800,
        view: "exposed", query: `&id=${encodeURIComponent(key.id)}`,
        answer: ({ method, endpoint }) => method === "GET" ? answers[endpoint] : undefined });
      try {
        await withScreenshot(page, `usage-status-${label}`, async () => {
          await settled(page, record, label);
          const notice = page.locator(".usage-status"), summary = notice.locator("summary");
          await summary.scrollIntoViewIfNeeded();
          assert.equal(await notice.getAttribute("open"), null, `${label}: starts compact`);
          const text = await summary.innerText();
          for (const expected of locale === "ko" ? ["부분 수집", "리전 완료 0/10", "조회 실패 8", "한도 도달 2"]
            : ["Partial collection", "Regions complete 0/10", "8 failed", "2 capped"]) assert.ok(text.includes(expected), `${label}: ${expected}`);
          assert.ok((await notice.boundingBox()).height < (width === 320 ? 140 : 90), `${label}: compact summary`);
          await summary.focus();
          await summary.press("Enter");
          assert.notEqual(await notice.getAttribute("open"), null, `${label}: keyboard opens reasons`);
          assert.equal(await notice.locator("p").isVisible(), true);
          const reason = await notice.locator("p").innerText();
          for (const expected of locale === "ko" ? ["기본 리전", "8곳은 읽지 못", "호출 100건"]
            : ["default ones", "8 could not be read", "first 100 calls"]) assert.ok(reason.includes(expected), `${label}: retained ${expected}`);
          assert.ok(await notice.evaluate(el => {
            const r = el.getBoundingClientRect();
            return r.left >= 0 && r.right <= document.documentElement.clientWidth && el.scrollWidth <= el.clientWidth;
          }), `${label}: no horizontal overflow`);
          await summary.press("Space");
          assert.equal(await notice.getAttribute("open"), null, `${label}: keyboard closes reasons`);
          assert.ok(await summary.evaluate(el => el === document.activeElement), `${label}: focus stays on summary`);
          assertClean(record, label);
          assert.deepEqual(record.writes, [], `${label}: no lookup or write`);
        });
      } finally { await context.close(); }
    }
    for (const locale of ["ko", "en"]) {
      const endpoint = `credentials/${key.credential_id}/usage`, job = "11111111-1111-4111-8111-111111111111";
      let state = { ...answers[endpoint], collection_status: "COMPLETE", region_discovery_status: "COMPLETE",
        regions_complete: 17, regions_discovered: 17, regions_failed: 0, regions_capped: 0,
        summary: { events: 10051, denied: 0, techniques: {}, services: {
          s3: { service: "s3", calls: 10051, writes: 0, denied: 0, last: null } } } };
      const { context, page, record } = await openConsole(browser, { locale, width: 390, height: 800,
        view: "exposed", query: `&id=${encodeURIComponent(key.id)}`,
        answer: ({ method, endpoint: path }) => {
          if (method === "GET" && path === endpoint) return state;
          if (method === "POST" && path === `${endpoint}/refresh?background=true`) {
            state = { ...state, collection_status: "PARTIAL", regions_complete: 1,
              refresh_job: { id: job, status: "RUNNING" } };
            return respond(202, { job_id: job, status: "QUEUED" });
          }
          if (method === "POST" && path === `source-scan-jobs/${job}/cancel`) {
            state = { ...state, refresh_job: { id: job, status: "CANCELLED" } };
            return { id: job, status: "CANCELLED" };
          }
          return method === "GET" ? answers[path] : undefined;
        } });
      try {
        await settled(page, record, locale);
        await page.getByRole("button", { name: locale === "ko" ? "지금 조회" : "Look up now", exact: true }).click();
        const stop = page.getByRole("button", { name: locale === "ko" ? "수집 중지" : "Stop collection", exact: true });
        await stop.waitFor();
        assert.ok((await page.locator(".drawer").innerText()).includes("10051"), "counts exceed the retained sample");
        await page.getByText(locale === "ko" ? "백그라운드에서 페이지를 이어서 수집하고 있습니다. 이 화면을 닫아도 계속됩니다."
          : "Collecting pages in the background. Collection continues after this panel closes.", { exact: true }).waitFor();
        await stop.click();
        await page.getByRole("button", { name: locale === "ko" ? "지금 조회" : "Look up now", exact: true }).waitFor();
        assert.deepEqual(record.writes.map(write => write.endpoint), [`${endpoint}/refresh?background=true`, `source-scan-jobs/${job}/cancel`]);
        assertClean(record, locale);
      } finally { await context.close(); }
    }
    console.log("PASS usage status: compact partial counts, complete reasons, native keyboard disclosure, no overflow or writes; KO/EN, light/dark, 320/1440.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
