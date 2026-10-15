// Signed-in profile display uses the session response; no provider calls or persisted fixture data.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { openConsole, preview, settled, openMenu, inBounds, assertClean, withScreenshot } = require("./console-proof.cjs");

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  try {
    for (const locale of ["ko", "en"]) for (const theme of ["light", "dark"]) for (const width of [360, 1440]) {
      const answers = preview();
      const email = "a".repeat(60) + "@example.test";
      answers.session = { id: "oidc-user-1", name: "홍길동", email, role: "Analyst", auth_mode: "oidc" };
      const label = `${locale}-${theme}-${width}`;
      const { context, page, record } = await openConsole(browser, { locale, theme, width,
        answer: ({ method, endpoint }) => method === "GET" ? answers[endpoint] : undefined });
      try {
        await withScreenshot(page, `account-${label}`, async () => {
          await settled(page, record);
          const avatar = page.getByRole("button", { name: `홍길동 (${email}) · ${locale === "ko" ? "분석가" : "Analyst"}`, exact: true });
          await openMenu(page, avatar, { keyboard: true });
          const menu = page.getByRole("menu", { name: locale === "ko" ? "내 정보" : "Account" });
          assert.equal(await menu.getByText("홍길동", { exact: true }).count(), 1);
          assert.equal(await menu.getByText(email, { exact: true }).count(), 1);
          assert.equal(await menu.getByText("oidc-user-1", { exact: true }).count(), 0);
          const size = await menu.evaluate(el => ({ scroll: el.scrollWidth, client: el.clientWidth }));
          assert.ok(size.scroll <= size.client + 1, `${label}: long email overflows`);
          await inBounds(page, label);
          await page.keyboard.press("Escape");
          await menu.waitFor({ state: "detached" });
          assert.equal(await avatar.evaluate(el => el === document.activeElement), true);
          assertClean(record, label);
          assert.deepEqual(record.writes, []);
        });
      } finally { await context.close(); }
    }
    console.log("PASS account profile: name/email, ko/en, light/dark, 360/1440, long-email wrapping and keyboard focus.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
