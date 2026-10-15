// Existing integrations gain features through the real wizard. Every request is synthetic.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { bundle } = require("./bundle-module.cjs");
const { ORIGIN, withScreenshot, openMenu, frames } = require("./console-proof.cjs");
const fs = require("node:fs");
const path = require("node:path");
const app = bundle({ React: "react", client: "react-dom/client", wizard: "@/console/views/integrations/wizard.tsx",
  locale: "@/components/locale.tsx" });
const css = fs.readFileSync(path.join(__dirname, "../app/(console)/console.css"), "utf8");
const label = name => ({ label: name, label_ko: name });
const descriptor = { provider: "github", ...label("GitHub"), editions: [{ id: "cloud", ...label("Cloud") }],
  target: [{ name: "organization", kind: "name", ...label("Organization") }],
  purposes: { inventory: { plan: [{ name: "audit_events", kind: "bool", default: false, ...label("Audit") }], permissions: [] },
    exposure: { plan: [], permissions: [{ id: "contents", ...label("contents:read") }], scans: [{ id: "repositories", ...label("Repositories") }] },
    remediation: { plan: [], permissions: [] } },
  auth_methods: [{ id: "token", ...label("PAT"), renewal: "NONE", purposes: ["inventory", "exposure", "remediation"],
    fields: [{ name: "token", secret: true, ...label("Token") }] }] };
const connection = () => ({ id: "g1", provider: "github", edition: "cloud", name: "GitHub · acme", status: "ACTIVE", revision: 4,
  purposes: ["inventory"], plans: { inventory: { audit_events: false } }, target: { organization: "acme" }, auth_method: "token",
  credential: { roles: ["credential"], reference: false }, children: [],
  checks: { checked_at: "2026-10-02T02:00:00Z", requested_at: "2026-10-02T01:00:00Z", stale: false, results: {} } });

const passed = () => ({ exposure: { status: "PASSED", items: [{ permission: "contents", status: "GRANTED" }] } });

// `fixture.results` is what the next check answers; a test may change it between checks. `fixture.storage` is the tab's
// sessionStorage before the page loads (what a flow saved before leaving for a provider).
async function visit(browser, initial, d = descriptor, width = 1280, language = "ko", theme = "light", open = { id: "g1", step: 1 }, fixture = { results: passed() }) {
  const context = await browser.newContext({ viewport: { width, height: 900 } });
  await context.addInitScript(() => { window.__frame = requestAnimationFrame.bind(window); });
  const calls = [], errors = [];
  let current = initial;
  await context.addInitScript(data => { window.__fixture = data; }, app.data);
  await context.addInitScript(saved => { for (const [key, value] of Object.entries(saved)) sessionStorage.setItem(key, JSON.stringify(value)); }, fixture.storage ?? {});
  const html = `<html data-theme="${theme}" lang="${language}"><head><style>${css}</style></head><body><div id="root"></div><script>${app.preamble}
    client.createRoot(document.getElementById('root')).render(React.createElement(locale.LocaleContext.Provider,{value:'${language}'},
      React.createElement(wizard.ConnectWizard,{catalog:${JSON.stringify({ providers: [d] })},open:${JSON.stringify(open)},
      admin:true,onClose(){},go(){},can(){return true}})));</script></body></html>`;
  await context.route("**/*", async route => {
    const req = route.request(), url = new URL(req.url());
    if (url.origin !== ORIGIN) { errors.push(`external ${url.href}`); return route.abort(); }
    if (req.isNavigationRequest()) return route.fulfill({ contentType: "text/html", body: html });
    if (req.resourceType() === "image") return route.fulfill({ contentType: "image/svg+xml", body: '<svg xmlns="http://www.w3.org/2000/svg"/>' });
    const endpoint = url.pathname.replace(/^\/api\/backend\//, ""), method = req.method(), body = req.postDataJSON();
    calls.push({ endpoint, method, body });
    let result;
    if (endpoint === "provider-connections/g1" && method === "GET") result = current;
    else if (endpoint === "v2/gcp/oauth/complete" && method === "POST") result = { provider_connection_id: "g1" };
    else if (endpoint === "v2/gcp/oauth/status" && method === "GET") result = { configured: true, locked: true };
    else if (endpoint.endsWith("/purposes") && method === "PUT") {
      assert.equal(body.expected_revision, current.revision);
      current = { ...current, purposes: body.purposes, revision: current.revision + 1, checks: { ...current.checks, stale: true } };
      result = current;
    } else if (endpoint.endsWith("/check") && method === "POST") {
      // Without plans (a feature switched back on) the check covers the saved plans, as the API does.
      current = { ...current, revision: current.revision + 1, checks: { ...current.checks, stale: false,
        checked_at: new Date().toISOString(), requested_plans: body?.plans ?? current.plans, results: fixture.results } };
      result = current;
    } else if (/\/features\/\w+$/.test(endpoint) && method === "PUT") {
      const purpose = endpoint.split("/").pop();
      // Switching back on needs fresh permission evidence (cremore/onboarding/service.set_feature).
      if (current.checks.stale) return route.fulfill({ status: 409, contentType: "application/json", body: JSON.stringify({ error: "PERMISSION_CHECK_REQUIRED" }) });
      assert.equal(body.expected_revision, current.revision, "the retry carries the checked revision");
      current = { ...current, revision: current.revision + 1, feature_enabled: { ...current.feature_enabled, [purpose]: body.enabled } };
      result = current;
    } else if (endpoint.endsWith("/activate") && method === "POST") {
      assert.equal(current.checks.stale, false);
      current = { ...current, plans: { ...current.plans, ...body.purposes }, children: [{ kind: "content", purpose: "exposure", id: "s1" }] };
      result = { ...current, created: [] };
    } else if (/\/plans\/\w+$/.test(endpoint) && method === "PUT") {
      current = { ...current, plans: { ...current.plans, [endpoint.split("/").pop()]: body.plan } }; result = current;
    } else if (endpoint.endsWith("/scan-scope-profiles") && method === "GET") result = { profiles: [] };
    else if (endpoint.endsWith("/resources/refresh")) result = { catalog_snapshot_id: "snapshot" };
    else if (endpoint.endsWith("/selection-drafts")) result = { resource_ids: ["repo1"], catalog_snapshot_id: "snapshot" };
    else if (endpoint.endsWith("/scan-scope-profiles") && method === "POST") result = { id: "profile1", version: 1 };
    else if (endpoint.endsWith("/preview")) result = { executable: false }; // Scope saved; no scan needed in this proof.
    else { errors.push(`${method} ${endpoint}`); return route.abort(); }
    return route.fulfill({ contentType: "application/json", body: JSON.stringify(result) });
  });
  const page = await context.newPage();
  page.on("pageerror", error => errors.push(error.message));
  await page.goto(ORIGIN);
  await page.locator(".ig-steps, #product-title").first().waitFor();
  return { page, context, calls, errors, fixture };
}

async function main() {
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  try {
    const added = await visit(browser, connection());
    try {
      await withScreenshot(added.page, "integration-add", async () => {
        const page = added.page;
        assert.equal(await page.locator('.ig-feat-card').nth(0).getAttribute("aria-checked"), "true", "the active feature stays selected");
        assert.match(await page.locator('.ig-feat-card').nth(2).textContent(), /추가 인증/, "remediation uses a separate credential");
        await page.locator('.ig-feat-card').nth(1).click();
        assert.equal(await page.locator("#ig-scope").inputValue(), "all", "a new scope never inherits keep");
        await page.locator("#ig-scope").selectOption("named");
        assert.ok(await page.locator("#ig-next").isDisabled());
        await page.locator("#ig-scope-text").fill("platform/*");
        await page.locator("#ig-next").click();
        assert.ok(await page.locator("#ig-next").isDisabled(), "an old check cannot approve another feature");
        await page.getByRole("button", { name: "권한 다시 확인", exact: true }).click();
        await page.waitForFunction(() => !document.querySelector("#ig-next").disabled);
        await page.locator("#ig-next").click();
        await page.getByRole("button", { name: "연동하고 수집 시작", exact: true }).click();
        await page.getByText(/검사 범위로 저장했습니다/).waitFor();
        const writes = added.calls.filter(c => c.method !== "GET");
        assert.deepEqual(writes.slice(0, 3).map(c => c.endpoint), ["provider-connections/g1/purposes", "provider-connections/g1/check", "provider-connections/g1/activate"]);
        assert.deepEqual(writes[2].body, { purposes: { exposure: {} } });
        assert.deepEqual(writes.find(c => c.endpoint.endsWith("/selection-drafts")).body, { patterns: ["platform/*"] });
        assert.deepEqual(added.errors, []);
      });
    } finally { await added.context.close(); }
    const initial = connection(); initial.purposes.push("exposure"); initial.plans.exposure = {};
    const kept = await visit(browser, initial);
    try {
      const page = kept.page;
      assert.equal(await page.locator("#ig-scope").inputValue(), "keep");
      await page.getByText("Audit", { exact: true }).click();
      await page.locator("#ig-next").click();
      await page.getByRole("button", { name: "권한 다시 확인", exact: true }).click();
      await page.waitForFunction(() => !document.querySelector("#ig-next").disabled);
      await page.locator("#ig-next").click();
      await page.getByRole("button", { name: "변경 저장", exact: true }).click();
      await page.getByRole("heading", { name: "변경을 저장했습니다" }).waitFor();
      assert.deepEqual(kept.calls.filter(c => c.method !== "GET").map(c => c.endpoint), ["provider-connections/g1/check", "provider-connections/g1/plans/inventory"]);
      assert.deepEqual(kept.errors, []);
    } finally { await kept.context.close(); }
    // A feature switched off a while ago comes back on: the refused switch asks for the check, then switches on once.
    // set_feature leaves no check requested and marks the evidence stale when it pauses a feature.
    const paused = connection(); paused.feature_enabled = { inventory: false }; Object.assign(paused.checks, { stale: true, requested_at: null });
    const resumed = await visit(browser, paused);
    try {
      const page = resumed.page, card = page.locator(".ig-feat-card").nth(0);
      assert.equal(await card.getAttribute("aria-checked"), "false");
      await card.click();
      await page.waitForFunction(() => document.querySelector(".ig-feat-card")?.getAttribute("aria-checked") === "true");
      assert.match(await card.textContent(), /켜짐/);
      assert.deepEqual(resumed.calls.filter(c => c.method !== "GET").map(c => c.endpoint),
        ["provider-connections/g1/features/inventory", "provider-connections/g1/check", "provider-connections/g1/features/inventory"]);
      assert.equal(await page.locator(".banner").count(), 0, "no refusal is left on screen");
      assert.deepEqual(resumed.errors, []);
    } finally { await resumed.context.close(); }
    // Opened from the content-scan card on an account without a scan: no feature choice, only the scan's scope; saving
    // keeps the account's other features and starts the scan alone.
    const scan = await visit(browser, connection(), descriptor, 1280, "ko", "light", { id: "g1", step: 1, entry: "exposure", addPurpose: "exposure" });
    try {
      const page = scan.page;
      assert.match(await page.locator("#ig-title").textContent(), /GitHub · 콘텐츠 검사/);
      assert.equal(await page.locator(".ig-feat-card").count(), 0, "the content card asks for no feature choice");
      assert.match(await page.locator('.ig-steps [aria-current="step"]').innerText(), /검사 범위/);
      await page.getByRole("heading", { name: "노출을 검사할 위치" }).waitFor();
      assert.equal(await page.getByRole("switch").count(), 0, "a scan not started yet has nothing to switch");
      assert.equal(await page.getByText("Audit", { exact: true }).count(), 0, "the inventory's options stay on the account card");
      await page.locator("#ig-scope").selectOption("named");
      await page.locator("#ig-scope-text").fill("platform/*");
      await page.locator("#ig-next").click();
      await page.getByRole("button", { name: "권한 다시 확인", exact: true }).click();
      await page.waitForFunction(() => !document.querySelector("#ig-next").disabled);
      await page.locator("#ig-next").click();
      await page.getByRole("button", { name: "연동하고 수집 시작", exact: true }).click();
      await page.getByText(/검사 범위로 저장했습니다/).waitFor();
      assert.deepEqual(scan.calls.find(c => c.endpoint.endsWith("/purposes")).body.purposes, ["inventory", "exposure"], "the hidden inventory is kept");
      assert.deepEqual(scan.calls.find(c => c.endpoint.endsWith("/activate")).body, { purposes: { exposure: {} } });
      assert.deepEqual(scan.errors, []);
    } finally { await scan.context.close(); }
    // A scan already running keeps its on/off switch, in its own section's header, and works from the keyboard.
    for (const [width, language, theme] of [[1440, "ko", "light"], [768, "en", "dark"]]) {
      const T = (ko, en) => language === "ko" ? ko : en;
      const live = connection(); live.purposes.push("exposure"); live.plans.exposure = {};
      const run = await visit(browser, live, descriptor, width, language, theme, { id: "g1", step: 1, entry: "exposure" });
      try {
        await withScreenshot(run.page, `scan-switch-${width}`, async () => {
          const page = run.page;
          assert.equal(await page.locator(".ig-feat-card").count(), 0);
          const head = page.locator(".ig-section-head").filter({ has: page.getByRole("heading", { name: T("노출을 검사할 위치", "Where to scan for exposures") }) });
          const toggle = head.getByRole("switch");
          assert.equal(await toggle.getAttribute("aria-checked"), "true");
          assert.match(await toggle.innerText(), T(/이 계정의 평문 노출 검사 켜짐/, /Plaintext exposure scan on this account: On/));
          await toggle.click();
          await page.waitForFunction(() => document.querySelector('[role="switch"]')?.getAttribute("aria-checked") === "false");
          assert.match(await toggle.innerText(), T(/꺼짐/, /Off/));
          await toggle.focus(); await page.keyboard.press("Enter");
          await page.waitForFunction(() => document.querySelector('[role="switch"]')?.getAttribute("aria-checked") === "true");
          assert.deepEqual(run.calls.filter(c => c.method === "PUT").map(c => [c.endpoint, c.body.enabled]),
            [["provider-connections/g1/features/exposure", false], ["provider-connections/g1/features/exposure", true]]);
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "no horizontal escape");
          assert.deepEqual(run.errors, []);
        });
      } finally { await run.context.close(); }
    }
    // The account card's product choice offers only the editions with an account feature, and none when one remains.
    const editions = ids => ({ ...descriptor, editions: ids.map(id => ({ id, ...label(id) })),
      purposes: { ...descriptor.purposes, inventory: { ...descriptor.purposes.inventory, editions: ids.filter(id => id !== "Free") },
        remediation: { ...descriptor.purposes.remediation, editions: ids.filter(id => id !== "Free") } } });
    const chooser = await visit(browser, connection(), editions(["Free", "Team", "Enterprise"]), 1280, "ko", "light", { provider: "github", entry: "account" });
    try {
      const page = chooser.page;
      assert.deepEqual(await page.getByLabel("제품·요금제").locator("option").allTextContents(), ["Team", "Enterprise"], "the scan-only edition is not offered");
      assert.deepEqual(chooser.errors, []);
    } finally { await chooser.context.close(); }
    const single = await visit(browser, connection(), editions(["Free", "Enterprise"]), 1280, "ko", "light", { provider: "github", entry: "account" });
    try {
      const page = single.page;
      assert.equal(await page.locator("#product-title").count(), 0, "one edition left: no product choice");
      assert.deepEqual(await page.locator(".ig-feat-card .t").allTextContents(), ["발급 목록 수집", "승인된 조치 실행"]);
      assert.equal(await page.getByLabel("제품", { exact: true }).count(), 0, "the scan-only edition is not offered later either");
      assert.deepEqual(single.errors, []);
    } finally { await single.context.close(); }
    // One feature refused, another granted: the granted one starts, the refused one is held with what it misses and is
    // turned on alone after a fresh check; with every feature refused nothing can go on.
    const members = { ...descriptor, purposes: { ...descriptor.purposes, inventory: { ...descriptor.purposes.inventory, permissions: [{ id: "members", ...label("members:read") }] } } };
    const unstarted = () => ({ ...connection(), status: "CHECKED", purposes: ["inventory", "exposure"], plans: {} });
    const refused = id => ({ status: "MISSING", items: [{ permission: id, status: "MISSING" }] });
    for (const [width, language, theme] of [[1440, "ko", "light"], [360, "en", "dark"]]) {
      const T = (ko, en) => language === "ko" ? ko : en;
      const run = await visit(browser, unstarted(), members, width, language, theme, { id: "g1", step: 1 },
        { results: { ...passed(), inventory: refused("members") } });
      try {
        await withScreenshot(run.page, `partial-${width}`, async () => {
          const page = run.page;
          await page.locator("#ig-next").click();
          await page.getByRole("button", { name: T("권한 다시 확인", "Check again"), exact: true }).click();
          await page.waitForFunction(() => !document.querySelector("#ig-next").disabled);
          await page.getByText(T("권한이 확인된 기능만 켭니다. 보류: 발급 목록 수집", "Only the features whose permissions were confirmed are turned on. Held: Issuance inventory"), { exact: true }).waitFor();
          await page.locator("#ig-next").click();
          const heldList = page.locator(".ig-section").filter({ has: page.getByRole("heading", { name: T("보류된 기능", "Held features") }) });
          assert.match(await heldList.innerText(), T(/발급 목록 수집[\s\S]*members:read/, /Issuance inventory[\s\S]*members:read/));
          await page.getByRole("button", { name: T("연동하고 수집 시작", "Connect and start"), exact: true }).click();
          await page.locator(".ig-done").waitFor();
          assert.deepEqual(run.calls.filter(c => c.endpoint.endsWith("/activate")).map(c => c.body), [{ purposes: { exposure: {} } }], "only the granted feature starts");
          assert.match(await heldList.innerText(), /members:read/, "the done step still lists what the held feature misses");
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "no horizontal escape");
          // Granted now: checking again turns on the held feature alone.
          run.fixture.results = { ...passed(), inventory: { status: "PASSED", items: [{ permission: "members", status: "GRANTED" }] } };
          const retry = heldList.getByRole("button", { name: T("권한 부여 후 다시 확인", "Check again after granting"), exact: true });
          await retry.focus(); await page.keyboard.press("Enter");
          await heldList.waitFor({ state: "detached" });
          const activations = run.calls.filter(c => c.endpoint.endsWith("/activate")).map(c => Object.keys(c.body.purposes));
          assert.deepEqual(activations, [["exposure"], ["inventory"]]);
          assert.deepEqual(run.errors, []);
        });
      } finally { await run.context.close(); }
    }
    // A connection checked a moment ago opens at review (CHECKED): the refused feature is held there too.
    const partialResults = () => ({ ...passed(), inventory: refused("members") });
    const reviewed = { ...unstarted(), checks: { ...unstarted().checks, checked_at: new Date().toISOString(),
      requested_plans: { inventory: { audit_events: false }, exposure: {} }, results: partialResults() } };
    const reopened = await visit(browser, reviewed, members, 1280, "ko", "light", { id: "g1" }, { results: partialResults() });
    try {
      const page = reopened.page;
      assert.match(await page.locator('.ig-steps [aria-current="step"]').innerText(), /확인/);
      const heldList = page.locator(".ig-section").filter({ has: page.getByRole("heading", { name: "보류된 기능" }) });
      assert.match(await heldList.innerText(), /발급 목록 수집[\s\S]*members:read/);
      await page.getByRole("button", { name: "연동하고 수집 시작", exact: true }).click();
      await page.locator(".ig-done").waitFor();
      assert.deepEqual(reopened.calls.filter(c => c.endpoint.endsWith("/activate")).map(c => c.body), [{ purposes: { exposure: {} } }],
        "reopened at review, only the granted feature starts");
      assert.match(await heldList.innerText(), /members:read/);
      assert.deepEqual(reopened.errors, []);
    } finally { await reopened.context.close(); }
    // Reopened at review with every feature refused: Finish stays off (no empty success); the held list and its recheck stay.
    const allRefused = () => ({ exposure: refused("contents"), inventory: refused("members") });
    const deniedRecord = { ...reviewed, checks: { ...reviewed.checks, results: allRefused() } };
    const denied = await visit(browser, deniedRecord, members, 1280, "ko", "light", { id: "g1" }, { results: allRefused() });
    try {
      const page = denied.page;
      assert.match(await page.locator('.ig-steps [aria-current="step"]').innerText(), /확인/);
      const heldList = page.locator(".ig-section").filter({ has: page.getByRole("heading", { name: "보류된 기능" }) });
      assert.match(await heldList.innerText(), /발급 목록 수집[\s\S]*members:read[\s\S]*평문 노출 검사[\s\S]*contents:read/);
      assert.equal(await heldList.getByRole("button", { name: "권한 부여 후 다시 확인", exact: true }).count(), 2);
      const finishButton = page.locator(".modal-foot .primary-btn");
      assert.ok(await finishButton.isDisabled(), "nothing would start: Finish waits for a passing check");
      assert.equal(await finishButton.getAttribute("data-tip"), "필요한 권한이 확인된 기능이 없습니다. 권한을 준 뒤 다시 확인하세요.");
      assert.equal(await page.locator(".ig-done").count(), 0);
      assert.equal(denied.calls.some(c => c.method !== "GET"), false, "no activation and no other write");
      assert.deepEqual(denied.errors, []);
    } finally { await denied.context.close(); }
    // Back from Google (the {oauth} open): the content card's entry saved before leaving is the one the flow continues
    // with, so the content view comes back without any feature selection.
    const gcp = { provider: "gcp", ...label("GCP"), editions: [{ id: "cloud", ...label("Cloud") }], target: [{ name: "project", kind: "name", ...label("Project") }],
      purposes: { inventory: { plan: [], permissions: [] },
        exposure: { plan: [], permissions: [{ id: "contents", ...label("storage.objects.list") }], scans: [{ id: "buckets", ...label("Buckets") }] } },
      auth_methods: [{ id: "google_oauth", ...label("Google sign-in"), renewal: "AUTOMATIC", flow: "gcp_oauth", purposes: ["inventory", "exposure"], fields: [] }] };
    const signedIn = { ...connection(), provider: "gcp", status: "CHECKED", purposes: ["exposure"], plans: {}, target: { project: "acme" },
      auth_method: "google_oauth", checks: { ...connection().checks, checked_at: new Date().toISOString(), requested_plans: { exposure: {} }, results: passed() } };
    const returned = await visit(browser, signedIn, gcp, 1280, "ko", "light", { oauth: "oauth-session" }, { results: passed(), storage: {
      "cremore.gcp.oauth.pending": { session_id: "oauth-session", state: "state", browser_key: "key", expires_at: "2099-01-01T00:00:00Z", locale: "ko" },
      "cremore:onboarding-entry:gcp": { edition: "cloud", entry: "exposure" } } });
    try {
      const page = returned.page;
      assert.match(await page.locator("#ig-title").textContent(), /GCP · 콘텐츠 검사/, "the content card's view comes back");
      assert.match(await page.locator(".ig-steps li").first().innerText(), /검사 범위/);
      assert.ok(returned.calls.some(c => c.endpoint === "v2/gcp/oauth/complete"));
      await page.getByRole("button", { name: "이전", exact: true }).click();
      await page.getByRole("heading", { name: "노출을 검사할 위치" }).waitFor();
      assert.equal(await page.locator(".ig-feat-card").count(), 0, "no feature selection after the provider return");
      assert.deepEqual(returned.errors, []);
    } finally { await returned.context.close(); }
    // A content flow's return as {provider} (no entry named): its saved card and its content journey are resumed together;
    // the journey is checked against the content card's features, not the account card's.
    const resumedRun = await visit(browser, signedIn, gcp, 1280, "ko", "light", { provider: "gcp" }, { results: passed(), storage: {
      "cremore:setup:gcp": { provider: "gcp", edition: "cloud", expires: Date.now() + 10 * 60 * 1000, requested: ["exposure"], pending: [], completed: [] },
      "cremore:onboarding-entry:gcp": { edition: "cloud", entry: "exposure" } } });
    try {
      const page = resumedRun.page;
      assert.match(await page.locator("#ig-title").textContent(), /GCP · 콘텐츠 검사/, "the saved content card is resumed");
      assert.equal(await page.locator(".ig-feat-card").count(), 0, "no feature selection");
      await page.getByRole("heading", { name: "노출을 검사할 위치" }).waitFor();
      assert.deepEqual(resumedRun.errors, []);
    } finally { await resumedRun.context.close(); }
    // A card naming its entry wins over a saved choice for the other card.
    const named = await visit(browser, signedIn, gcp, 1280, "ko", "light", { provider: "gcp", entry: "account" }, { results: passed(), storage: {
      "cremore:onboarding-entry:gcp": { edition: "cloud", entry: "exposure" } } });
    try {
      const page = named.page;
      assert.doesNotMatch(await page.locator("#ig-title").textContent(), /콘텐츠 검사/);
      assert.deepEqual(await page.locator(".ig-feat-card .t").allTextContents(), ["발급 목록 수집"]);
      assert.deepEqual(named.errors, []);
    } finally { await named.context.close(); }
    const blocked = await visit(browser, unstarted(), members, 1280, "ko", "light", { id: "g1", step: 1 },
      { results: { exposure: refused("contents"), inventory: refused("members") } });
    try {
      const page = blocked.page;
      await page.locator("#ig-next").click();
      await page.getByRole("button", { name: "권한 다시 확인", exact: true }).click();
      await page.getByText(/권한 2개가 없습니다/).waitFor();
      assert.ok(await page.locator("#ig-next").isDisabled(), "every feature refused: nothing goes on");
      assert.equal(await page.locator("#ig-next").getAttribute("data-tip"), "필요한 권한이 확인된 기능이 없습니다. 권한을 준 뒤 다시 확인하세요.");
      assert.equal(blocked.calls.some(c => c.endpoint.endsWith("/activate")), false);
      assert.deepEqual(blocked.errors, []);
    } finally { await blocked.context.close(); }
    // Opened from the account card: the content scan and its scope are not part of it.
    const both = connection(); both.purposes.push("exposure"); both.plans.exposure = {};
    const account = await visit(browser, both, descriptor, 1280, "ko", "light", { id: "g1", step: 1, entry: "account" });
    try {
      const page = account.page;
      assert.equal(await page.locator(".ig-feat-card").filter({ hasText: "평문 노출 검사" }).count(), 0);
      assert.equal(await page.locator("#ig-scope").count(), 0);
      assert.equal(await page.getByText("Audit", { exact: true }).count(), 1);
      assert.deepEqual(account.errors, []);
    } finally { await account.context.close(); }
    // A scan set up and abandoned before activation (in purposes, no plan yet): saving from the account card neither checks
    // nor starts it, and no scope is saved.
    const pending = connection(); pending.purposes.push("exposure");
    const leftover = await visit(browser, pending, descriptor, 1280, "ko", "light", { id: "g1", step: 1, entry: "account" });
    try {
      const page = leftover.page;
      await page.getByText("Audit", { exact: true }).click();
      await page.locator("#ig-next").click();
      await page.getByRole("button", { name: "권한 다시 확인", exact: true }).click();
      await page.waitForFunction(() => !document.querySelector("#ig-next").disabled);
      await page.locator("#ig-next").click();
      await page.getByRole("button", { name: "변경 저장", exact: true }).click();
      await page.getByRole("heading", { name: "변경을 저장했습니다" }).waitFor();
      const writes = leftover.calls.filter(c => c.method !== "GET");
      assert.deepEqual(writes.map(c => c.endpoint), ["provider-connections/g1/check", "provider-connections/g1/plans/inventory"]);
      assert.deepEqual(Object.keys(writes[0].body.plans), ["inventory"], "the unfinished scan is not checked here");
      assert.deepEqual(leftover.errors, []);
    } finally { await leftover.context.close(); }
    // Removing a target stops it for every feature, so the content card never offers it; the full settings still do.
    const rooted = () => { const c = connection(); c.purposes.push("exposure"); c.plans.exposure = {};
      c.target = { version: 2, roots: [{ id: "r1", target: { organization: "acme" } }, { id: "r2", target: { organization: "labs" } }] }; return c; };
    for (const [open, offered] of [[{ id: "g1", step: 1, entry: "exposure" }, 0], [{ id: "g1", step: 1 }, 1]]) {
      const run = await visit(browser, rooted(), descriptor, 1280, "ko", "light", open);
      try {
        const stop = run.page.getByRole("button", { name: "선택에서 빠진 대상의 수집 중지", exact: true });
        assert.equal(await stop.count(), offered, `${JSON.stringify(open)}: target removal`);
        assert.deepEqual(run.errors, []);
      } finally { await run.context.close(); }
    }
    // A schedule picked on the content card never reaches the account's features it hides.
    const scheduled = { ...descriptor, purposes: { ...descriptor.purposes, inventory: { ...descriptor.purposes.inventory,
      plan: [...descriptor.purposes.inventory.plan, { name: "schedule_minutes", kind: "number", default: 1440, min: 0, max: 10080, ...label("Every") }] } } };
    const mixed = connection(); mixed.purposes.push("exposure"); mixed.plans = { inventory: { audit_events: false, schedule_minutes: 1440 }, exposure: {} };
    const s3 = await visit(browser, mixed, scheduled, 1280, "ko", "light", { id: "g1", step: 1, entry: "exposure" });
    try {
      const page = s3.page;
      await page.locator("#ig-next").click();
      await page.getByRole("button", { name: "권한 다시 확인", exact: true }).click();
      await page.waitForFunction(() => !document.querySelector("#ig-next").disabled);
      await page.locator("#ig-next").click();
      await page.locator("#ig-sched").selectOption("60");
      await page.getByRole("button", { name: "변경 저장", exact: true }).click();
      await page.getByRole("heading", { name: "변경을 저장했습니다" }).waitFor();
      assert.equal(s3.calls.some(c => c.endpoint.endsWith("/plans/inventory")), false, "the hidden inventory keeps its schedule");
      assert.equal(s3.calls.find(c => c.endpoint.endsWith("/check")).body.plans.inventory.schedule_minutes, 1440);
      assert.deepEqual(s3.errors, []);
    } finally { await s3.context.close(); }
    // The catalog's list options use the same dropdown as closed choices without changing list payloads.
    for (const [width, language, theme] of [[1440, "ko", "light"], [360, "en", "dark"]]) {
      const fields = [
        { name: "regions", kind: "list", ...label("Regions"), description: "Choose enabled regions", description_ko: "활성 리전 선택",
          options: ["ap-northeast-2", "us-east-1"].map(id => ({ id, ...label(id) })) },
        { name: "days", kind: "number", default: 90, ...label("Days") },
        { name: "sources", kind: "choices", default: [], ...label("Sources"), options: ["one", "two"].map(id => ({ id, ...label(id) })) },
      ];
      const d = { ...descriptor, purposes: { ...descriptor.purposes, inventory: { plan: fields, permissions: [] } } };
      const initial = connection(); initial.plans.inventory = { regions: ["future-region-1"], days: 90, sources: [] };
      const chosen = await visit(browser, initial, d, width, language, theme);
      try {
        await withScreenshot(chosen.page, `region-options-${width}`, async () => {
          const page = chosen.page, regions = page.getByRole("button", { name: "Regions (" + (language === "ko" ? "선택" : "optional") + ")", exact: true });
          const number = page.getByLabel("Days (" + (language === "ko" ? "선택" : "optional") + ")", { exact: true });
          await regions.scrollIntoViewIfNeeded(); await frames(page);
          const a = await regions.boundingBox(), b = await number.boundingBox();
          assert.equal(a.height, b.height, "single-line controls have the same height despite a hint");
          if (width > 600) assert.equal(a.y, b.y, "adjacent controls align");
          await regions.click();
          const menu = page.getByRole("menu", { name: "Regions", exact: false });
          await menu.waitFor();
          assert.deepEqual(await regions.boundingBox(), a, "opening dropdown keeps the field in place");
          assert.deepEqual(await number.boundingBox(), b, "opening dropdown never pushes adjacent controls");
          assert.equal(await menu.evaluate(el => { const r = el.getBoundingClientRect(); return r.left >= 0 && r.top >= 0 && r.right <= innerWidth && r.bottom <= innerHeight; }), true, "dropdown stays inside viewport");
          assert.equal(await menu.getByRole("menuitemcheckbox", { name: /future-region-1/ }).getAttribute("aria-checked"), "true", "unknown saved region preserved");
          await menu.getByRole("textbox").fill("ap-");
          await menu.getByRole("menuitem", { name: language === "ko" ? "모두 선택" : "Select all", exact: true }).click();
          await menu.getByRole("textbox").fill("");
          assert.equal(await menu.locator('[role="menuitemcheckbox"][aria-checked="true"]').count(), 3, "all includes hidden search results and saved regions");
          await menu.getByRole("menuitem", { name: language === "ko" ? "모두 해제" : "Clear all", exact: true }).click();
          assert.equal(await menu.locator('[role="menuitemcheckbox"][aria-checked="true"]').count(), 0);
          await menu.getByRole("menuitemcheckbox", { name: "ap-northeast-2", exact: true }).click();
          await menu.getByRole("menuitemcheckbox", { name: "us-east-1", exact: true }).click();
          await page.keyboard.press("Escape");
          assert.equal(await menu.count(), 0, "Escape closes only dropdown");
          assert.equal(await page.locator(".modal").count(), 1);
          assert.equal(await regions.evaluate(el => document.activeElement === el), true, "focus returns to trigger");
          await openMenu(page, page.getByRole("button", { name: "Sources", exact: true }), { keyboard: true });
          await page.keyboard.press("ArrowDown");
          await page.keyboard.press("Enter"); // Select all from search, using only the keyboard.
          assert.equal(await page.locator('.menu [role="menuitemcheckbox"][aria-checked="true"]').count(), 2);
          await page.keyboard.press("Escape");
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, "no horizontal escape");
          await page.locator("#ig-next").click();
          await page.getByRole("button", { name: language === "ko" ? "권한 다시 확인" : "Check again", exact: true }).click();
          await page.waitForFunction(() => !document.querySelector("#ig-next").disabled);
          await page.locator("#ig-next").click();
          await page.getByRole("button", { name: language === "ko" ? "변경 저장" : "Save changes", exact: true }).click();
          await page.getByRole("heading", { name: language === "ko" ? "변경을 저장했습니다" : "Changes saved" }).waitFor();
          assert.deepEqual(chosen.calls.find(call => call.endpoint.endsWith("/plans/inventory")).body.plan,
            { regions: ["ap-northeast-2", "us-east-1"], days: 90, sources: ["one", "two"] });
          assert.deepEqual(chosen.errors, []);
        });
      } finally { await chosen.context.close(); }
    }
    console.log("PASS integration edit: same connection, fresh check, named new scope, existing scope preserved, remediation isolated.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
