// Synthetic proof of the Google sign-in callback (/gcp/oauth/callback): with this browser's pending sign-in and its
// state, the code goes to the API once -- from an address that no longer holds it -- and the browser returns to the
// integrations screen to finish; a callback with another state sends nothing and leaves the real sign-in pending; a
// refused approval cancels the sign-in. The page speaks the sign-in's language, or else the console's saved one. No
// Google request.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { bundle } = require("./bundle-module.cjs");
const { ORIGIN } = require("./console-proof.cjs");
const fs = require("node:fs");
const path = require("node:path");

const app = bundle({ React: "react", client: "react-dom/client", callback: "@/console/gcp-callback.tsx" });
const css = fs.readFileSync(path.join(__dirname, "../app/(console)/console.css"), "utf8");
const SESSION = { session_id: "11111111-2222-4333-8444-555555555555", state: ["st", "ate", "-", "synthetic"].join(""), browser_key: "synthetic-browser-key",
  expires_at: new Date(Date.now() + 600_000).toISOString(), locale: "ko" };
const html = `<!doctype html><html lang="ko"><head><meta charset="utf-8"><style>${css}</style></head><body><div id="root"></div>`
  + `<script>${app.preamble}client.createRoot(document.getElementById("root")).render(React.createElement(callback.GcpOAuthCallback));</script></body></html>`;

async function visit(browser, query, { session = SESSION, saved = null } = {}) {
  const context = await browser.newContext({ viewport: { width: 390, height: 800 } });
  const calls = [], navigations = [], errors = [];
  await context.addInitScript(({ data, value, locale }) => {
    window.__fixture = data;
    if (value) sessionStorage.setItem("cremore.gcp.oauth.pending", JSON.stringify(value));
    if (locale) localStorage.setItem("cremore.locale", locale);
    // Each request says where the page was at the moment it was sent.
    const send = window.fetch;
    window.fetch = (input, init = {}) => send(input, { ...init, headers: { ...(init.headers || {}), "x-proof-from": location.search } });
  }, { data: app.data, value: session, locale: saved });
  await context.route("**/*", route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== ORIGIN) { calls.push({ external: url.href }); return route.abort(); }
    if (url.pathname === "/gcp/oauth/callback") return route.fulfill({ contentType: "text/html; charset=utf-8", body: html });
    if (url.pathname === "/") { navigations.push(url.pathname + url.search); return route.fulfill({ contentType: "text/html", body: "<p>console</p>" }); }
    if (url.pathname.startsWith("/api/backend/")) {
      // Where the page was when it sent this: the code must have left the address first.
      calls.push({ endpoint: url.pathname.slice("/api/backend/".length), body: JSON.parse(request.postData() || "null"), from: request.headers()["x-proof-from"] });
      return route.fulfill({ contentType: "application/json", body: "{}" });
    }
    calls.push({ external: url.href }); return route.abort();
  });
  const page = await context.newPage();
  page.on("pageerror", error => errors.push(error.message));
  await page.goto(`${ORIGIN}/gcp/oauth/callback?${query}`);
  return { context, page, calls, navigations, errors };
}

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  try {
    // This browser's sign-in: the code goes once, leaves the address, and the integrations screen finishes it.
    const done = await visit(browser, `state=${SESSION.state}&code=synthetic-code`);
    try {
      await done.page.waitForURL(url => url.pathname === "/");
      assert.deepEqual(done.calls, [{ endpoint: "v2/gcp/oauth/finish", body: { session_id: SESSION.session_id, browser_key: SESSION.browser_key, state: SESSION.state, code: "synthetic-code" }, from: "" }]);
      assert.deepEqual(done.navigations, [`/?view=sources&gcp_oauth=${SESSION.session_id}`]);
      assert.deepEqual(done.errors, []);
    } finally { await done.context.close(); }
    // Another browser's (or a forged) state: nothing is sent, and the address keeps no code.
    const forged = await visit(browser, "state=other&code=synthetic-code");
    try {
      await forged.page.getByRole("alert").waitFor();
      assert.match(await forged.page.getByRole("alert").innerText(), /GCP_OAUTH_STATE_INVALID/);
      assert.equal(new URL(forged.page.url()).search, "", "the code left the address");
      assert.deepEqual(forged.calls, []);
      assert.equal(await forged.page.locator("a.primary-btn").getAttribute("href"), "/?view=sources");
      assert.notEqual(await forged.page.evaluate(() => sessionStorage.getItem("cremore.gcp.oauth.pending")), null, "a forged answer leaves the real sign-in pending");
    } finally { await forged.context.close(); }
    // No pending sign-in at all (another tab, or expired): nothing is sent, in the console's saved language.
    const none = await visit(browser, `state=${SESSION.state}&code=synthetic-code`, { session: null, saved: "en" });
    try {
      await none.page.getByRole("alert").waitFor();
      assert.match(await none.page.getByRole("alert").innerText(), /not for a Google connection started in this browser, or it has expired/);
      assert.equal(await none.page.locator("h1").innerText(), "Google connection");
      assert.deepEqual(none.calls, []);
    } finally { await none.context.close(); }
    // Refused at Google: the sign-in is cancelled, once, in the language it started in.
    const refused = await visit(browser, `state=${SESSION.state}&error=access_denied`, { session: { ...SESSION, locale: "en" } });
    try {
      await refused.page.getByRole("alert").waitFor();
      assert.match(await refused.page.getByRole("alert").innerText(), /Google approval was not given\. GCP_OAUTH_CONSENT_CANCELLED/);
      for (let tries = 0; !refused.calls.length && tries < 50; tries++) await refused.page.waitForTimeout(40);
      assert.deepEqual(refused.calls, [{ endpoint: "v2/gcp/oauth/cancel", body: { session_id: SESSION.session_id, browser_key: SESSION.browser_key }, from: "" }]);
      assert.equal(await refused.page.evaluate(() => sessionStorage.getItem("cremore.gcp.oauth.pending")), null);
    } finally { await refused.context.close(); }
    console.log("PASS console Google callback: this browser's code goes once from an address that no longer holds it, then back to Integrations; another state or none sends nothing and a forged one leaves the sign-in pending; a refusal cancels once; the page speaks the sign-in's or the saved language.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
