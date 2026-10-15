// A failed list poll cannot unmount the live authentication editor. Synthetic API only.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { ORIGIN, preview, openConsole, settled, refusal, LOST, assertClean, withScreenshot } = require("./console-proof.cjs");
const label = text => ({ label: text, label_ko: text });
const descriptor = { provider: "okta", ...label("Okta"), category: "identity", editions: [{ id: "cloud", ...label("Okta") }],
  target: [{ name: "organization", kind: "text", required: true, ...label("Organization") }],
  purposes: { identity: { plan: [], permissions: [{ id: "users_read", ...label("okta.users.read") }] } },
  auth_methods: [{ id: "made_key", ...label("Service app"), generated: true, renewal: "AUTOMATIC", purposes: ["identity"],
    auth_first: { context: ["organization"] }, fields: [{ name: "client_id", kind: "text", public: true, ...label("Client ID") },
      { name: "private_key", kind: "text", secret: true, optional: true, ...label("Private key") }] }] };

async function initialFailure(browser, endpoint) {
  const answers = preview();
  let failed = true;
  const run = await openConsole(browser, { view: "sources", locale: "en", answer: ({ method, endpoint: path }) =>
    method === "GET" && path === endpoint && failed ? refusal(503, "TEMPORARY_FAILURE") : answers[path] });
  try {
    await settled(run.page, run.record);
    assert.match(await run.page.locator("main").textContent(), /server could not complete/);
    assert.equal(await run.page.getByRole("dialog").count(), 0);
    failed = false;
    await run.page.getByRole("button", { name: "Retry", exact: true }).click();
    await settled(run.page, run.record);
    assert.equal(await run.page.locator(".err-line").count(), 0);
    assert.deepEqual(run.record.writes, []);
    assertClean(run.record, `first load ${endpoint}`);
  } finally { await run.context.close(); }
}

async function preserveEditor(browser) {
  const answers = preview();
  answers["provider-connections/catalog"] = { providers: [descriptor], purposes: ["identity"] };
  let failing = null, mode = "http", draft, after;
  const run = await openConsole(browser, { view: "sources", query: "&connect=okta", locale: "en", answer: ({ method, endpoint, body }) => {
    if (method === "GET") return endpoint === failing ? mode === "http" ? refusal(503, "TEMPORARY_FAILURE") : LOST : answers[endpoint];
    if (endpoint === "onboarding-sessions") {
      assert.equal(body.auth_method, "made_key");
      draft = { id: "synthetic-draft", revision: 1, provider: "okta", auth_method: "made_key", edition: "cloud", state: "SETUP_REQUIRED",
        context: body.context, expires_at: "2026-10-01T13:00:00Z", public_auth: { client_id: body.credential.client_id, private_key: "synthetic-must-not-restore" },
        generated: { kid: "synthetic-public-key", public_jwk: { kty: "RSA", e: "AQAB", n: "synthetic-public-only", kid: "synthetic-public-key", alg: "RS256", use: "sig" } } };
      return draft;
    }
    // A remounted wizard may try to restore a draft. The proof detects that extra read.
    if (endpoint === "onboarding-sessions/synthetic-draft/read") {
      if (after) { draft = { ...draft, ...after, revision: draft.revision + 1 }; after = null; }
      return draft;
    }
    if (endpoint === "onboarding-sessions/synthetic-draft/authenticate") {
      assert.equal(body.credential, undefined, "restored public fields must reuse the stored credential");
      draft = { ...draft, revision: 2, state: "WORKING", checks: {} };
      after = { state: "AUTHENTICATED", authentication: { status: "GRANTED" } };
      return draft;
    }
    if (endpoint === "onboarding-sessions/synthetic-draft/discover") {
      assert.deepEqual(body.purposes, ["identity"]);
      draft = { ...draft, purposes: body.purposes, state: "WORKING", checks: {}, revision: draft.revision + 1 };
      after = { state: "LISTED", completeness: "COMPLETE", roots: [{ id: "org", label: "Synthetic Okta org", target: { organization: "synthetic.okta.com" } }] };
      return draft;
    }
  } });
  const { page, record } = run;
  try {
    await withScreenshot(page, "integration-refresh", async () => {
      await settled(page, record);
      const organization = page.getByLabel("Organization", { exact: true });
      const client = page.getByLabel("Client ID", { exact: true });
      await organization.fill("synthetic.okta.com"); await client.fill("synthetic-client");
      await page.getByRole("button", { name: "Create sign-in key", exact: true }).click();
      await settled(page, record);
      await page.getByRole("button", { name: "Copy the public key", exact: true }).waitFor();
      await client.evaluate(el => { el.dataset.proofOriginal = "yes"; });
      for (const endpoint of ["provider-connections", "provider-connections/catalog"]) {
        failing = endpoint;
        await page.clock.fastForward(10_001); await settled(page, record);
        assert.equal(await page.getByRole("dialog").count(), 1, `${endpoint}: polling must keep the editor mounted`);
        assert.equal(await client.getAttribute("data-proof-original"), "yes", "the original input DOM survives");
        assert.equal(await client.inputValue(), "synthetic-client");
        assert.equal(await organization.inputValue(), "synthetic.okta.com");
        assert.equal(await page.getByRole("button", { name: "Copy the public key", exact: true }).count(), 1);
        assert.match(await page.locator("main").textContent(), /last loaded list and your input are kept/i);
        failing = null;
        await page.clock.fastForward(10_001); await settled(page, record);
        assert.equal(await client.getAttribute("data-proof-original"), "yes");
        assert.doesNotMatch(await page.locator("main").textContent(), /last loaded list and your input are kept/i);
        mode = "network";
      }
      // An unsaved public form edit is not replaced by the saved draft during a later failure.
      await client.fill("unsaved-client-edit");
      failing = "provider-connections";
      await page.clock.fastForward(10_001); await settled(page, record);
      assert.equal(await client.inputValue(), "unsaved-client-edit");
      assert.equal(await client.getAttribute("data-proof-original"), "yes");
      assert.deepEqual(record.writes.map(item => item.endpoint), ["onboarding-sessions"], "poll failures cannot create, restore, retry auth or cancel a draft");
      // Explicit reopening restores declared public fields from the server, never a private field.
      failing = null;
      await page.goto(`${ORIGIN}/?view=sources&connect=okta`); await settled(page, record);
      assert.equal(await client.inputValue(), "synthetic-client", "the remembered draft restores its saved public Client ID");
      assert.equal(await page.getByLabel(/^Private key/).inputValue(), "");
      assert.equal(await page.getByRole("button", { name: "Copy the public key", exact: true }).count(), 1);
      await page.getByRole("button", { name: "Key registered · authenticate", exact: true }).click(); await settled(page, record);
      await page.clock.fastForward(1501); await settled(page, record);
      await page.locator(".ig-feat-card").click();
      await page.getByRole("button", { name: "List targets", exact: true }).click(); await settled(page, record);
      assert.equal(await page.getByRole("dialog").count(), 1, "WORKING checks:{} must not crash required-permission calculation");
      await page.clock.fastForward(1501); await settled(page, record);
      // The access check is its own step (2e80582b): selection is offered only after required access is verified.
      assert.equal(await page.getByRole("button", { name: "Check access and continue", exact: true }).count(), 1);
      assert.equal(await page.getByRole("button", { name: "Review selection", exact: true }).count(), 0, "missing results never grant permission");
      assert.deepEqual(record.writes.map(item => item.endpoint), ["onboarding-sessions", "onboarding-sessions/synthetic-draft/read", "onboarding-sessions/synthetic-draft/authenticate",
        "onboarding-sessions/synthetic-draft/read", "onboarding-sessions/synthetic-draft/discover", "onboarding-sessions/synthetic-draft/read"]);
      assertClean(record, "preserve integration editor during refresh failure");
    });
  } finally { await run.context.close(); }
}

(async () => {
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  try {
    await preserveEditor(browser);
    for (const endpoint of ["provider-connections", "provider-connections/catalog"]) await initialFailure(browser, endpoint);
    console.log("PASS integration refresh: generated public-key draft and unsaved input survive 503/network polls, recovery preserves DOM, initial failures retry GET only, no authentication replay.");
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
