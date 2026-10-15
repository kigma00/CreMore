// Synthetic proof of the whole console: every screen on the rail and a credential's panel in both languages, both
// themes and three widths, with minimal runtime inputs. Nothing is written and nothing leaves the page.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { openConsole, preview, settled, inBounds, assertClean, withScreenshot, show } = require("./console-proof.cjs");

const TABS = 5;

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  const answers = preview();
  // A connection whose change feed has failed for hours (cremore/operations/health.feed_alerts) and the response threads'
  // job that cannot post (cremore/governance/response_threads.alerts): the operations screen says so at the top, in each
  // language, theme and width.
  answers["operations/status"] = { ...answers["operations/status"], alerts: [{ code: "CHANGE_FEED_RATE_LIMITED", resource_type: "connection",
    resource_id: "00000000-0000-4000-8000-000000000001", provider: "github", failing_roots: 2, failing_since: "2026-10-01T03:00:00+00:00",
    error_codes: ["SOURCE_RATE_LIMITED"] }, { code: "RESPONSE_THREADS_FAILING", resource_type: "response_threads", resource_id: "progress",
    last_run_at: "2026-10-01T05:00:00+00:00", owed_replies: 3, failing_since: "2026-10-01T03:30:00+00:00", error_codes: ["SLACK_RATE_LIMITED"] }] };
  // Two change runs after an upgrade (cremore/api/source_presenters.py present_scan_run): one partial only for the hold,
  // which the scans screen explains and leaves out of its failed count, and one with a gap of its own, which it counts.
  const scanRun = (id, extra) => ({ id, status: "PARTIAL", kind: "scope", mode: "DELTA", trigger_type: "SCHEDULE", connection_id: null,
    resources_succeeded: 3, resources_failed: 0, findings_total: 0, duration_seconds: 2, error: null, policy_held_roots: 1,
    created_at: "2026-10-01T09:00:00Z", started_at: "2026-10-01T09:00:01Z", completed_at: "2026-10-01T09:00:03Z", ...extra });
  answers["scan-runs"] = [scanRun("held-only", { policy_held_only: true }), scanRun("held-and-gap", { created_at: "2026-10-01T08:00:00Z" }),
    scanRun("running", { status: "RUNNING", policy_held_roots: undefined, resources_succeeded: 1, duration_seconds: null,
      created_at: "2026-10-01T10:00:00Z", completed_at: null })];
  const heldNote = { ko: "업그레이드 후 첫 전체 검사 전이라 전체를 다시 읽지 않았습니다", en: "Not re-read whole until the post-upgrade full scan" };
  // The exposed AWS key used by the panel proof.
  const key = answers["credential-records"].items.find(item => answers[`credentials/${item.credential_id}/usage`]);
  const visited = [];
  try {
    for (const locale of ["ko", "en"]) for (const theme of ["light", "dark"]) for (const width of [360, 768, 1440]) {
      const label = `${locale}-${theme}-${width}`;
      const { context, page, record } = await openConsole(browser, { width, locale, theme,
        answer: ({ method, endpoint }) => method === "GET" ? answers[endpoint] : undefined });
      try {
        await withScreenshot(page, `shell-${label}`, async () => {
          await settled(page, record, label);
          // The saved theme wins over the opposite operating-system theme, reaches the page's background, and is the
          // one the theme switch shows as chosen.
          const painted = await page.evaluate(() => {
            const paint = document.createElement("canvas").getContext("2d", { willReadFrequently: true });
            paint.fillStyle = getComputedStyle(document.body).backgroundColor;
            paint.fillRect(0, 0, 1, 1);
            return { attribute: document.documentElement.dataset.theme, background: [...paint.getImageData(0, 0, 1, 1).data].slice(0, 3) };
          });
          assert.equal(painted.attribute, theme, `${label}: saved theme`);
          assert.ok(painted.background.every(value => theme === "dark" ? value < 64 : value > 220), `${label}: background ${painted.background}`);
          const chosen = page.locator(`.topbar-right [role=group][aria-label="${locale === "ko" ? "화면 테마" : "Theme"}"] button[aria-pressed="true"]`);
          assert.equal(await chosen.getAttribute("aria-label"), { ko: { light: "라이트", dark: "다크" }, en: { light: "Light", dark: "Dark" } }[locale][theme], `${label}: the theme switch`);
          assert.equal(await page.locator("html").getAttribute("lang"), locale, `${label}: language`);
          // Every screen the rail offers.
          const views = await page.locator(".rail a.rail-item").evaluateAll(links => links.map(link => new URL(link.href).searchParams.get("view")));
          assert.ok(views.length >= 14 && views.includes("metadata"), `${label}: the rail ${views}`);
          for (const view of views) {
            await show(page, record, view);
            assertClean(record, `${label} ${view}`);
            assert.equal(await page.locator(`.rail a[href="?view=${view}"]`).getAttribute("aria-current"), "page", `${label} ${view}: rail`);
            assert.ok((await page.locator(".topbar h1").first().innerText()).trim(), `${label} ${view}: a title`);
            assert.equal(await page.locator(".placeholder").count(), 0, `${label} ${view}: a placeholder instead of the screen`);
            assert.deepEqual(await page.locator("[role=alert]:visible").allTextContents(), [], `${label} ${view}: an error line`);
            await inBounds(page, `${label} ${view}`);
            // The proof's health list is empty: the banner names the service and promises no scan.
            if (view === "operations") assert.match(await page.locator(".banner").filter({ hasText: locale === "ko" ? "변경 감지" : "change feed" }).innerText(),
              locale === "ko" ? /^GitHub 연결의 변경 감지가 .+부터 실패하고 있습니다\(요청 제한\)\. 실패하는 대상 2곳의 변경 검사는 조회가 성공할 때까지 멈춰 있습니다\.$/
                : /^The change feed of a GitHub connection has failed since .+ \(rate limited\)\. Change scans of the 2 failing targets wait until a look succeeds\.$/,
              `${label}: the failing change feed`);
            if (view === "operations") assert.match(await page.locator(".banner").filter({ hasText: locale === "ko" ? "팀 채널 스레드" : "team channel threads" }).innerText(),
              locale === "ko" ? /^대응 요청의 팀 채널 스레드에 올릴 진행 기록 3건이 .+부터 올라가지 않고 있습니다\. 마지막 오류: Slack 요청 한도에 걸렸습니다\./
                : /^3 progress replies have waited since .+ to go to response requests' team channel threads\. Last error: Slack's rate limit was reached\./,
              `${label}: the stuck response threads`);
            // The held run explains itself on its row and in its panel, opened from the keyboard; only the other run is failed.
            if (view === "scans") {
              assert.equal(await page.locator("tbody tr .ig-note").filter({ hasText: heldNote[locale] }).count(), 1, `${label}: the held note`);
              const failed = page.locator(".tile").filter({ hasText: locale === "ko" ? "최근 7일 실패" : "Failed in 7 days" });
              assert.equal((await failed.locator(".tile-value").innerText()).trim(), "1", `${label}: failed in 7 days`);
              await page.locator("tbody tr").filter({ hasText: heldNote[locale] }).focus();
              await page.keyboard.press("Enter");
              await page.locator(".drawer").filter({ hasText: heldNote[locale] }).waitFor();
              await inBounds(page, `${label} held run panel`);
              await page.keyboard.press("Escape");
              await page.locator(".drawer").waitFor({ state: "detached" });
              // The tile's list is just what it counts: the run with a gap, not the held one. It starts from filters that
              // hide both runs (the checks tab, a search that matches nothing) and clears them. From the keyboard, then cleared.
              const runRows = page.locator("tbody tr[tabindex]");
              await page.getByRole("tab", { name: new RegExp(`^${locale === "ko" ? "권한·인증 확인" : "Checks"}`) }).click();
              await page.locator("#log-search").fill("matches-no-run");
              await settled(page, record, `${label} filtered`);
              assert.equal(await runRows.count(), 0, `${label}: the filters hide every run`);
              await failed.focus();
              await page.keyboard.press("Enter");
              const chip = page.locator(".applied-chip").filter({ hasText: locale === "ko" ? "최근 7일 실패" : "Failed in 7 days" });
              await chip.waitFor();
              await settled(page, record, `${label} failed drilldown`);
              assert.equal(await runRows.count(), 1, `${label}: the failed drilldown`);
              assert.equal(await page.locator("tbody tr .ig-note").filter({ hasText: heldNote[locale] }).count(), 0, `${label}: a held run in the failed drilldown`);
              await inBounds(page, `${label} failed drilldown`);
              await chip.getByRole("button").focus();
              await page.keyboard.press("Enter");
              await chip.waitFor({ state: "detached" });
              await settled(page, record, `${label} every run`);
              assert.equal(await runRows.count(), 3, `${label}: every run again`);
              // The in-progress tile's list is just what it counts too, from the same hiding filters.
              await page.getByRole("tab", { name: new RegExp(`^${locale === "ko" ? "권한·인증 확인" : "Checks"}`) }).click();
              await page.locator("#log-search").fill("matches-no-run");
              await settled(page, record, `${label} filtered again`);
              assert.equal(await runRows.count(), 0, `${label}: the filters hide every run again`);
              const active = page.locator(".tile").filter({ hasText: locale === "ko" ? "진행 중" : "In progress" });
              assert.equal((await active.locator(".tile-value").innerText()).trim(), "1", `${label}: in progress`);
              await active.focus();
              await page.keyboard.press("Enter");
              await settled(page, record, `${label} in-progress drilldown`);
              assert.equal(await runRows.count(), 1, `${label}: the in-progress drilldown`);
              await inBounds(page, `${label} in-progress drilldown`);
            }
            assertClean(record, `${label} ${view}`);
            visited.push(`${label} ${view}`);
          }
          // A credential's panel, opened from the keyboard: every tab, then closed with Escape.
          await show(page, record, "exposed");
          await page.locator("tbody tr").filter({ hasText: key.hint }).first().focus();
          await page.keyboard.press("Enter");
          await page.locator(".drawer").waitFor();
          const tabs = page.locator(".drawer [role=tab]");
          assert.equal(await tabs.count(), TABS, `${label}: the panel's tabs`);
          for (let index = 0; index < TABS; index++) {
            await tabs.nth(index).click();
            await settled(page, record, `${label} panel tab ${index + 1}`);
            assertClean(record, `${label} panel tab ${index + 1}`);
            assert.equal(await tabs.nth(index).getAttribute("aria-selected"), "true", `${label} panel tab ${index + 1}: chosen`);
            assert.deepEqual(await page.locator(".drawer [role=alert]:visible").allTextContents(), [], `${label} panel tab ${index + 1}: an error line`);
            await inBounds(page, `${label} panel tab ${index + 1}`);
          }
          await page.keyboard.press("Escape");
          await page.locator(".drawer").waitFor({ state: "detached" });
          visited.push(`${label} panel`);
          assertClean(record, label);
          assert.deepEqual(record.writes, [], `${label}: a write`);
        });
      } finally { await context.close(); }
    }
    console.log(`PASS console shell: ${visited.length} screens and panels in ko/en, light/dark, 360/768/1440; saved theme wins; no sideways scroll, placeholder, error line, write or outside request.`);
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
