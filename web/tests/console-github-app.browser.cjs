// The GitHub App return page (/github/app) when the CreMore sign-in ran out on the detour to GitHub: the proxy answers
// with its sign-in page instead of the API's JSON. The page says so and offers "sign in again", in both languages and
// themes, reachable from the keyboard. Synthetic answers only.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");
const { bundle } = require("./bundle-module.cjs");
const { ORIGIN, capturedAt, withScreenshot } = require("./console-proof.cjs");
const app = bundle({ React: "react", client: "react-dom/client", github: "@/console/views/integrations/github-app.tsx", locale: "@/components/locale.tsx" });
const css = fs.readFileSync(path.join(__dirname, "../app/(console)/console.css"), "utf8");
const SIGN_IN_PAGE = "<!doctype html><html><body><form action=/oauth2/start>Sign in with your company account</form></body></html>";

// `answer` is how the proxy stands in for the API: a followed redirect (200 HTML) or a refusal (401 HTML); an object is
// the API's own JSON answer.
async function visit(browser, { locale, theme, query, pending, answer }) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  await context.addInitScript(data => { window.__fixture = data; }, app.data);
  await context.addInitScript(([key, value]) => { if (location.pathname === "/github/app") sessionStorage.setItem(key, value); },
    ["cremore.github.app.pending", JSON.stringify(pending)]);
  const calls = [], errors = [];
  const html = `<html data-theme="${theme}" lang="${locale}"><head><meta charset="utf-8"><style>${css}</style></head><body><div id="root"></div><script>${app.preamble}
    client.createRoot(document.getElementById('root')).render(React.createElement(locale.LocaleContext.Provider,{value:${JSON.stringify(locale)}},
      location.pathname==='/github/app'?React.createElement(github.GitHubAppReturn):React.createElement('p',{id:'console'},'console')));</script></body></html>`;
  await context.route("**/*", async route => {
    const req = route.request(), url = new URL(req.url());
    if (url.origin !== ORIGIN) { errors.push(`unexpected origin ${url.origin}`); return route.abort(); }
    if (req.isNavigationRequest()) return route.fulfill({ contentType: "text/html", body: html });
    calls.push(url.pathname);
    return typeof answer === "number" ? route.fulfill({ status: answer, contentType: "text/html", body: SIGN_IN_PAGE })
      : route.fulfill({ contentType: "application/json", body: JSON.stringify(answer) });
  });
  const page = await context.newPage(); page.setDefaultTimeout(12000); page.on("pageerror", e => errors.push(e.stack));
  await page.clock.setFixedTime(capturedAt());  // pendingApp() compares expires_at with the page's clock
  await page.goto(`${ORIGIN}/github/app${query}`);
  return { context, page, calls, errors };
}

async function main() {
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  const expires = "2026-10-01T12:10:00Z";  // ten minutes after the pinned clock (capturedAt)
  const flow = { session_id: "00000000-0000-4000-8000-000000000001", state: "synthetic-state", browser_key: "synthetic-key", expires_at: expires };
  const cases = [
    { name: "convert, followed redirect", locale: "en", theme: "light", query: "?code=synthetic&state=synthetic-state", pending: flow, answer: 200,
      endpoint: "/api/backend/github/app-manifest/convert", text: /Your CreMore sign-in expired/, link: "Sign in again" },
    { name: "complete, refused", locale: "ko", theme: "dark", query: "", pending: { ...flow, install_url: "https://github.com/apps/synthetic/installations/new" }, answer: 401,
      endpoint: "/api/backend/github/app-manifest/complete", text: /CreMore 로그인이 만료됐습니다/, link: "다시 로그인" },
  ];
  try {
    for (const c of cases) {
      const run = await visit(browser, c);
      try {
        await withScreenshot(run.page, `github-app ${c.name}`, async () => {
          const page = run.page, link = page.getByRole("link", { name: c.link, exact: true });
          await link.waitFor();
          assert.match(await page.locator(".gh-return-bad").innerText(), c.text);
          assert.deepEqual(run.calls, [c.endpoint]);
          assert.equal(await link.getAttribute("href"), "/?view=sources");
          // Retrying with the sign-in gone cannot succeed, so the page does not offer it.
          assert.equal(await page.getByRole("button").count(), 0);
          for (let i = 0; i < 3 && await page.evaluate(() => document.activeElement?.textContent) !== c.link; i++) await page.keyboard.press("Tab");
          assert.equal(await page.evaluate(() => document.activeElement?.textContent), c.link, "the sign-in link is reached from the keyboard");
          await page.keyboard.press("Enter");
          await page.locator("#console").waitFor();
          assert.equal(new URL(page.url()).search, "?view=sources");
          assert.deepEqual(run.errors, []);
        });
      } finally { await run.context.close(); }
    }
    // A finished flow goes back to the card it began from: the content card's entry rides in the address.
    const draft = "00000000-0000-4000-8000-000000000002", connection = "00000000-0000-4000-8000-000000000003";
    for (const [pending, answer, search] of [
      [{ ...flow, onboarding: true, entry: "exposure" }, { onboarding_session_id: draft }, "?view=sources&connect=github&entry=exposure"],
      [{ ...flow, onboarding: true, entry: "account" }, { onboarding_session_id: draft }, "?view=sources&connect=github"],
      [{ ...flow, onboarding: true }, { onboarding_session_id: draft }, "?view=sources&connect=github"],
      [{ ...flow, entry: "exposure" }, { provider_connection_id: connection }, `?view=sources&edit=${connection}&step=2&entry=exposure`],
      [{ ...flow, entry: "account" }, { provider_connection_id: connection }, `?view=sources&edit=${connection}&step=2&entry=account`],
      [flow, { provider_connection_id: connection }, `?view=sources&edit=${connection}&step=2`],
      // A store holding something other than the two cards comes back with no entry at all.
      [{ ...flow, entry: "admin" }, { provider_connection_id: connection }, `?view=sources&edit=${connection}&step=2`],
      [{ ...flow, onboarding: true, entry: "admin" }, { onboarding_session_id: draft }, "?view=sources&connect=github"],
    ]) {
      const run = await visit(browser, { locale: "en", theme: "light", query: "", pending, answer });
      try {
        await withScreenshot(run.page, `github-app return ${search}`, async () => {
          await run.page.locator("#console").waitFor();
          assert.equal(new URL(run.page.url()).search, search);
          assert.deepEqual(run.calls, ["/api/backend/github/app-manifest/complete"]);
          assert.deepEqual(run.errors, []);
        });
      } finally { await run.context.close(); }
    }
    console.log("PASS github-app return: a sign-in page instead of the API on convert (200) and complete (401) reads as an expired sign-in with a keyboard-reachable sign-in link, ko/en, light/dark; a finished flow returns with its card's entry");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
