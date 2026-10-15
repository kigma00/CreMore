// Real component and CSS; no Notion requests, real tokens or system clipboard writes.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");
const { bundle } = require("./bundle-module.cjs");
const { ORIGIN, frames, withScreenshot } = require("./console-proof.cjs");
const app = bundle({ React: "react", client: "react-dom/client", hooks: "@/console/views/notion-webhooks.tsx", locale: "@/components/locale.tsx" });
const css = fs.readFileSync(path.join(__dirname, "../app/(console)/console.css"), "utf8");
const id = "00000000-0000-4000-8000-000000000001";

async function visit(browser, width, language, theme) {
  const context = await browser.newContext({ viewport: { width, height: 900 } });
  const page = await context.newPage(), errors = [], calls = [];
  let binding = null, fail = false;
  const L = (ko, en) => language === "ko" ? ko : en;
  await context.addInitScript(data => {
    window.__fixture = data;
    window.__frame = requestAnimationFrame.bind(window);
    Object.defineProperty(navigator, "clipboard", { value: { writeText: async value => { window.__copied = value; } } });
  }, app.data);
  const html = `<html data-theme="${theme}" lang="${language}"><head><meta charset="utf-8"><style>${css}</style></head><body><main class="page"><div id="root"></div></main><script>${app.preamble}
    client.createRoot(document.getElementById('root')).render(React.createElement(locale.LocaleContext.Provider,{value:'${language}'},React.createElement(hooks.NotionWebhooks)));</script></body></html>`;
  page.on("pageerror", error => errors.push(String(error)));
  await context.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== ORIGIN) { errors.push("external request"); return route.abort(); }
    if (request.isNavigationRequest()) return route.fulfill({ contentType: "text/html", body: html });
    const endpoint = url.pathname.replace(/^\/api\/backend\//, ""), method = request.method();
    calls.push({ endpoint, method, body: request.postDataJSON() });
    let body = {};
    if (endpoint === "settings/notion-webhooks" && method === "GET") body = { profiles: [{ id: "scope", name: "Approved pages", connection: "Notion" }], bindings: binding ? [binding] : [] };
    else if (endpoint === "settings/notion-webhooks" && method === "POST") {
      assert.deepEqual(request.postDataJSON(), { profile_id: "scope" });
      binding = { id, profile_id: "scope", state: "WAITING" };
    } else if (endpoint.endsWith("/verification") && method === "GET") body = { verification_token: "synthetic-verification-value" };
    else if (endpoint.endsWith("/confirm") && method === "POST") {
      assert.deepEqual(request.postDataJSON(), { verified_in_notion: true, probe_digest: "signed-probe" });
      if (fail) return route.fulfill({ status: 409, contentType: "application/json", body: JSON.stringify({ error: "NOTION_WEBHOOK_PROBE_CHANGED" }) });
      binding.state = "ACTIVE";
    } else if (endpoint === `settings/notion-webhooks/${id}` && method === "DELETE") binding = null;
    else errors.push(`unknown request ${method} ${endpoint}`);
    return route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
  });
  const button = (ko, en) => page.getByRole("button", { name: L(ko, en), exact: true });
  const poll = async () => { await page.clock.fastForward(5100); await frames(page); };
  // A copy finishes after its click: the verification token is read from the API first, then written.
  const copied = async expected => {
    for (let tries = 0; tries < 50 && await page.evaluate(() => window.__copied) !== expected; tries++) await frames(page);
    assert.equal(await page.evaluate(() => window.__copied), expected);
  };
  try {
    await page.goto(ORIGIN);
    await page.clock.install();
    await withScreenshot(page, `notion-webhooks-${language}-${width}`, async () => {
      const create = button("수신 주소 만들기", "Create receiving URL");
      await create.waitFor();
      assert.equal(await create.isDisabled(), true);
      await page.getByLabel(L("Notion 검사 범위", "Notion scan scope")).selectOption("scope");
      await create.focus(); await page.keyboard.press("Enter");
      await button("수신 주소 복사", "Copy receiving URL").click();
      await copied(`${ORIGIN}/api/v1/hooks/notion/${id}`);
      binding.state = "PENDING"; await poll();
      const confirm = button("확인하고 활성화", "Confirm and enable");
      await confirm.waitFor();
      assert.equal(await confirm.isDisabled(), true);
      await button("검증 토큰 복사", "Copy verification token").click();
      await copied("synthetic-verification-value");
      assert.equal((await page.locator("body").textContent()).includes("synthetic-verification-value"), false);
      await page.getByRole("checkbox").check();
      assert.equal(await confirm.isDisabled(), true, "operator checkbox alone cannot activate");
      binding.probe = { digest: "signed-probe" }; await poll();
      await confirm.waitFor({ state: "visible" });
      fail = true; await confirm.click();
      await page.getByRole("alert").waitFor();
      assert.equal(binding.state, "PENDING");
      fail = false; await confirm.click();
      await page.getByText(L("활성 · 서명된 변경 알림을 수신합니다", "Active · receiving signed changes"), { exact: true }).waitFor();
      assert.equal(await confirm.count(), 0);
      const writes = calls.filter(call => call.method !== "GET").length;
      await poll();
      assert.equal(calls.filter(call => call.method !== "GET").length, writes, "display polling never writes");
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), "no horizontal overflow");
      await button("연결 해제", "Disconnect").click();
      await button("연결 해제", "Disconnect").waitFor({ state: "detached" });
      assert.equal(binding, null);
      assert.deepEqual(errors, []);
    });
  } finally { await context.close(); }
}
(async () => {
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  try {
    for (const args of [[1440, "ko", "light"], [360, "en", "dark"]]) await visit(browser, ...args);
    console.log("PASS Notion webhook setup: approval scope, verification, signed probe gate, refusal/retry, clipboard secrecy, passive polling, keyboard, KO/EN/light/dark/360px.");
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
