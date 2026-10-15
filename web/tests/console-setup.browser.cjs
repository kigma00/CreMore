// Real React/modal/dropdown behavior, exclusively synthetic API and GitHub redirects.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");
const { bundle } = require("./bundle-module.cjs");
const { ORIGIN, frames, withScreenshot } = require("./console-proof.cjs");
const app = bundle({ React: "react", client: "react-dom/client", wizard: "@/console/views/integrations/wizard.tsx",
  github: "@/console/views/integrations/github-app.tsx", locale: "@/components/locale.tsx" });
const css = fs.readFileSync(path.join(__dirname, "../app/(console)/console.css"), "utf8");
const label = value => ({ label: value, label_ko: value });
const feature = purpose => ({ permissions: [{ id: purpose, ...label(`Read ${purpose}`) }], plan: [] });
const token = { name: "token", ...label("Token"), secret: true, kind: "secret" };
// As the catalog has it: the product comes first, an account connection never selects content to scan (that is the
// content connection's), and the Enterprise organization bot also lists its targets.
const notion = { provider: "notion", ...label("Notion"), category: "saas", editions: [{ id: "cloud", ...label("Personal") }, { id: "enterprise", ...label("Enterprise") }],
  target: [{ name: "workspace", ...label("Workspace ID"), kind: "id" }],
  purposes: { exposure: feature("exposure"), inventory: feature("inventory"), remediation: feature("remediation") },
  auth_methods: [{ id: "integration", ...label("Internal integration"), renewal: "NONE", auth_first: { context: [] }, purposes: ["exposure"], fields: [token] },
    { id: "organization_bot", ...label("Organization bot (Enterprise)"), editions: ["enterprise"], renewal: "NONE", auth_first: { context: [] }, purposes: ["inventory", "remediation"], fields: [token] }] };
const github = { provider: "github", ...label("GitHub"), category: "code", editions: [{ id: "cloud", ...label("GitHub.com") }],
  target: [{ name: "organization", ...label("Organization"), required: true, kind: "name" }],
  purposes: { exposure: feature("exposure"), inventory: feature("inventory"), identity: feature("identity"), remediation: feature("remediation") },
  auth_methods: [{ id: "github_app", ...label("GitHub App"), renewal: "AUTOMATIC", auth_first: { context: [] }, purposes: ["exposure", "inventory", "remediation"],
    fields: [{ name: "app_id", ...label("App ID") }, { name: "installation_id", ...label("Installation ID") }, { name: "private_key", ...label("Private key"), secret: true }] },
  { id: "token", ...label("Personal access token"), renewal: "EXPIRES", auth_first: { context: [] }, purposes: ["exposure", "identity"], fields: [token] }] };
const id = value => `00000000-0000-4000-8000-${String(value).padStart(12, "0")}`;

async function visit(browser, descriptor, width = 1280, theme = "light", entry = null) {
  const context = await browser.newContext({ viewport: { width, height: 900 } });
  await context.addInitScript(() => { window.__frame = requestAnimationFrame.bind(window); });
  await context.addInitScript(data => { window.__fixture = data; }, app.data);
  const calls = [], errors = [], drafts = new Map(), records = new Map();
  let serial = 1, manifestKey, retryComplete = true, failToggle = true, denySecondOrg = Boolean(descriptor.proofMulti);
  const html = `<html data-theme="${theme}" lang="en"><head><meta charset="utf-8"><style>${css}</style></head><body><div id="root"></div><script>${app.preamble}
    const root=client.createRoot(document.getElementById('root')); const query=new URLSearchParams(location.search);
    // As the integrations page does: a GitHub App return names its card in the URL (?connect=…&entry=…), else the card opened.
    const entry=query.has('connect')?query.get('entry'):${JSON.stringify(entry)};
    let opened={provider:${JSON.stringify(descriptor.provider)},...(entry==='exposure'?{entry:'exposure',purpose:'exposure'}:{})};
    window.__edit=id=>{opened={id};window.__render()}; window.__render=()=>root.render(React.createElement(locale.LocaleContext.Provider,{value:'en'},
      location.pathname==='/github/app'?React.createElement(github.GitHubAppReturn):React.createElement(wizard.ConnectWizard,{key:JSON.stringify(opened),catalog:{providers:[${JSON.stringify(descriptor)}],purposes:${JSON.stringify(Object.keys(descriptor.purposes))}},
      open:opened,admin:true,can:()=>true,go(){},onClose(){window.__closed=true}}))); window.__render();</script></body></html>`;
  function record(body) {
    const c = { id: id(serial++), provider: descriptor.provider, edition: body.edition, name: body.name || "Synthetic connection", status: "CHECKED", revision: 1,
      purposes: body.purposes || [], plans: {}, target: body.target || {}, auth_method: body.auth_method, renewal: "NONE", credential: { roles: ["credential"], reference: false }, children: [],
      checks: { checked_at: new Date().toISOString(), requested_at: "2020-01-01T00:00:00Z", job_id: null, stale: false, error: null, results: {} } };
    records.set(c.id, c); return c;
  }
  function newDraft(body) {
    const sid = id(serial++), value = { id: sid, revision: 1, state: "WORKING", edition: body.edition, auth_method: body.auth_method, context: body.context || {},
      expires_at: new Date(Date.now() + 600000).toISOString(), blockers: [], purposes: [], plans: {} };
    drafts.set(sid, { value, next: { state: "AUTHENTICATED", authentication: { status: "GRANTED" } }, key: body.browser_key }); return sid;
  }
  await context.route("**/*", async route => {
    try {
      const req = route.request(), url = new URL(req.url());
      if (url.origin === "https://github.com" && req.isNavigationRequest()) {
        assert.ok(url.pathname === "/organizations/synthetic/settings/apps/new" || url.pathname === "/apps/synthetic/installations/new");
        const back = url.pathname.includes("organizations") ? `${ORIGIN}/github/app?code=synthetic&state=synthetic-state` : `${ORIGIN}/github/app`;
        return route.fulfill({ contentType: "text/html", body: `<script>location.replace(${JSON.stringify(back)})</script>` });
      }
      if (url.origin !== ORIGIN) { errors.push(`unexpected origin ${url.origin}`); return route.abort(); }
      if (req.isNavigationRequest()) return route.fulfill({ contentType: "text/html", body: html });
      if (req.resourceType() === "image") return route.fulfill({ contentType: "image/svg+xml", body: '<svg xmlns="http://www.w3.org/2000/svg"/>' });
      const endpoint = url.pathname.replace(/^\/api\/backend\//, ""), body = req.postData() ? req.postDataJSON() : null;
      calls.push({ endpoint, body, method: req.method() });
      const respond = (value, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(value) });
      if (endpoint === "github/app-manifest/start") {
        assert.equal(body.onboarding, true); assert.equal(body.purposes, undefined); assert.equal(body.target.organization, "synthetic");
        assert.equal(body.target.host, undefined); manifestKey = body.browser_key;
        return respond({ session_id: id(800), state: "synthetic-state", expires_at: new Date(Date.now() + 600000).toISOString(),
          form_url: "https://github.com/organizations/synthetic/settings/apps/new?state=synthetic-state", manifest: { name: "Synthetic", default_permissions: {} } });
      }
      if (endpoint === "github/app-manifest/convert") { assert.equal(body.browser_key, manifestKey); return respond({ install_url: "https://github.com/apps/synthetic/installations/new" }); }
      if (endpoint === "github/app-manifest/complete") {
        assert.equal(body.browser_key, manifestKey);
        if (retryComplete) { retryComplete = false; return respond({ error: "GITHUB_APP_UNAVAILABLE" }, 503); }
        const sid = newDraft({ edition: descriptor.editions[0].id, auth_method: "github_app", browser_key: manifestKey });
        return respond({ onboarding_session_id: sid });
      }
      if (endpoint === "onboarding-sessions") {
        assert.ok(body.credential.token.startsWith("synthetic-"));
        const sid = newDraft(body); return respond(drafts.get(sid).value);
      }
      const draftMatch = /^onboarding-sessions\/([^/]+)\/(.+)$/.exec(endpoint);
      if (draftMatch) {
        const item = drafts.get(draftMatch[1]); assert.ok(item, endpoint); assert.equal(body.browser_key, item.key);
        const action = draftMatch[2], d = item.value;
        if (action === "read") { if (d.state === "WORKING") Object.assign(d, item.next, { revision: d.revision + 1 }); }
        else if (action === "discover") {
          assert.ok(body.purposes.every(p => descriptor.auth_methods.find(m => m.id === d.auth_method).purposes.includes(p)));
          assert.ok(!body.purposes.includes("remediation") || body.purposes.length === 1);
          Object.assign(d, { state: "WORKING", purposes: body.purposes, revision: d.revision + 1 });
          item.next = { state: "LISTED", completeness: "COMPLETE", roots: [{ id: "target", label: "Synthetic target", target: { organization: "synthetic" } },
            ...(descriptor.proofMulti ? [{ id: "other", label: "Second organization", target: { organization: "synthetic-labs" } }] : [])] };
        } else if (action === "inspect") {
          Object.assign(d, { state: "WORKING", plans: body.plans, selected_targets: body.target_ids, revision: d.revision + 1 });
          item.next = { state: "CHECKED", snapshot_id: "snapshot", checks: { results: Object.fromEntries(d.purposes.map(p => [p, { items: [{ permission: p, status: "GRANTED" }] }])) },
            resources: d.purposes.includes("exposure") ? [{ id: "page", source_key: "source", resource_type: "NOTION_PAGE", provider_resource_id: "page", display_name: "Synthetic page", list_visibility: "VISIBLE", content_readiness: "NOT_PROBED" }] : [] };
          if (descriptor.proofMulti) {
            assert.deepEqual(body.target_ids, ["target", "other"]);
            item.next.checks.results.inventory.items.push({ permission: "inventory", status: denySecondOrg ? "MISSING" : "GRANTED", subject: "synthetic-labs" });
            item.next.blockers = denySecondOrg ? [{ permission: "inventory", status: "MISSING" }] : [];
            denySecondOrg = false;
          }
        } else if (action === "select") Object.assign(d, { state: "SELECTED", selected_resources: body.resource_ids, selected_roots: body.selected_roots, revision: d.revision + 1 });
        else if (action === "complete") {
          assert.equal(d.state, "SELECTED");
          const c = record({ edition: d.edition, auth_method: d.auth_method, purposes: d.purposes, name: body.name,
            target: { version: 2, roots: d.roots.filter(r => d.selected_targets.includes(r.id)),
              ...(descriptor.proofMulti ? { auth: { github_enterprise: "synthetic-corp" } } : {}) } });
          Object.assign(c, { status: "ACTIVE", plans: d.plans, feature_enabled: Object.fromEntries(d.purposes.map(p => [p, true])) });
          d.state = "COMPLETED"; return respond(c);
        } else if (action === "cancel") d.state = "CANCELLED";
        else throw Error(endpoint);
        return respond(d);
      }
      if (endpoint === "provider-connections" && req.method() === "POST") { assert.ok(body.credential.token.startsWith("synthetic-")); return respond(record(body)); }
      const cMatch = /^provider-connections\/([^/]+)(?:\/(.*))?$/.exec(endpoint);
      if (cMatch) {
        const c = records.get(cMatch[1]); assert.ok(c, endpoint);
        if (cMatch[2] === "github-enterprise") return respond({ enterprise: "synthetic-corp", host: null, organization: "synthetic", source_status: "ACTIVE", auto: false,
          state: "READY", app: { slug: "synthetic", owner: "synthetic-corp", owner_type: "Enterprise" }, made: [],
          organizations: [{ organization: "synthetic", installed: true, connection: c }, { organization: "synthetic-labs", installed: true, connection: c },
            { organization: "synthetic-new", installed: false, connection: null, requested: false, result: null }] });
        if (cMatch[2] === "github-enterprise/install") { assert.deepEqual(body.organizations, ["synthetic-new"]); return respond({ requested: body.organizations }); }
        if (cMatch[2] === "check") {
          c.checks.requested_plans = body?.plans ?? c.plans;  // without plans the API checks the saved ones
          c.checks.results = Object.fromEntries(c.purposes.map(p => [p, { status: "PASSED", items: [{ permission: p, status: "GRANTED" }] }]));
        } else if (cMatch[2] === "activate") { c.plans = body.purposes; c.status = "ACTIVE"; c.feature_enabled = Object.fromEntries(Object.keys(c.plans).map(p => [p, true])); }
        else if (cMatch[2]?.startsWith("features/")) {
          assert.equal(body.expected_revision, c.revision);
          if (failToggle && body.enabled) { failToggle = false; return respond({ error: "PERMISSION_CHECK_REQUIRED" }, 409); }
          c.feature_enabled[cMatch[2].split("/")[1]] = body.enabled; c.revision++;
        } else if (req.method() === "PATCH") { c.name = body.name; c.revision++; }
        else assert.equal(req.method(), "GET", endpoint);
        return respond(c);
      }
      if (endpoint === "operations/connections") return respond({ items: [] });
      if (endpoint === "settings/scan-triggers") return respond({ schedules: { enabled: true } });
      throw Error(endpoint);
    } catch (error) { errors.push(error.stack); await route.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({ error: "SYNTHETIC_FIXTURE_ERROR" }) }); }
  });
  const page = await context.newPage(); page.setDefaultTimeout(12000); page.on("pageerror", e => errors.push(e.stack));
  await page.goto(ORIGIN);
  return { context, page, calls, errors, records };
}

// Targets, the access check and the selection are steps of their own (2e80582b); a saved account setup goes on to the
// next sign-in it needs, if any. Content selection (resources, reload, its menu) is console-auth-first's proof.
async function scope(page) {
  await page.getByRole("button", { name: "List targets", exact: true }).click();
  await page.getByRole("button", { name: "Check access and continue", exact: true }).click();
  await page.getByRole("button", { name: "Review selection", exact: true }).click();
  await page.getByRole("button", { name: "Save integration", exact: true }).click();
  await page.getByRole("button", { name: "Done · continue", exact: true }).click();
}
/** Turn a feature card on or off, whatever the edition offered first. */
async function choose(page, name, on = true) {
  const card = page.getByRole("checkbox", { name });
  if (await card.getAttribute("aria-checked") !== String(on)) await card.click();
}
/** Notion's account card offers only Enterprise (the edition with account features): the product modal opens only
 * while the wizard still lists the Personal edition, and is skipped once it is scoped (spec §4.2). */
async function enterprise(page) {
  await page.locator("#product-title, #auth-first-title, #ig-title").first().waitFor();
  if (!await page.locator("#product-title").count()) return;
  await page.getByRole("combobox").selectOption("enterprise");
  await page.getByRole("button", { name: "Continue to sign-in", exact: true }).click();
}
async function legacy(page, secret) {
  await page.getByLabel("Workspace ID (optional)", { exact: true }).fill(id(900));
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByLabel("Token", { exact: true }).fill(secret);
  await page.getByRole("button", { name: "Test connection", exact: true }).click();
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByRole("button", { name: /^(Connect and start|Connect and turn on)$/ }).click();
  await page.getByRole("button", { name: "Continue setup", exact: true }).click();
}

async function main() {
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  try {
    for (const width of [1280, 360]) {
      const run = await visit(browser, notion, width, width === 360 ? "dark" : "light"), { page } = run;
      try {
        await withScreenshot(page, `setup-notion-${width}`, async () => {
          await enterprise(page);
          await page.getByLabel("Token", { exact: true }).fill("synthetic-inventory");
          await page.getByRole("button", { name: "Authenticate", exact: true }).click();
          await choose(page, /Issuance inventory/); await choose(page, /Approved actions/);
          await scope(page);
          // Approved actions act with a credential of their own (service.create): their own sign-in comes next.
          assert.equal(await page.locator("#setup-done").count(), 0, "no full success while an acting credential remains");
          await page.getByLabel("Token", { exact: true }).fill("synthetic-acting");
          await page.getByRole("button", { name: "Authenticate", exact: true }).click();
          await scope(page);
          await page.locator("#setup-done").waitFor();
          const typed = run.calls.filter(c => c.endpoint === "onboarding-sessions").map(c => c.body.credential.token);
          assert.deepEqual(typed, ["synthetic-inventory", "synthetic-acting"], "each credential is typed and submitted once");
          assert.deepEqual([...run.records.values()].map(c => [c.edition, c.purposes]), [["enterprise", ["inventory"]], ["enterprise", ["remediation"]]]);
          const inventory = [...run.records.values()].find(c => c.plans.inventory);
          await page.evaluate(id => window.__edit(id), inventory.id);
          const toggle = page.getByRole("checkbox", { name: /Issuance inventory/ }); await toggle.click();
          await page.locator('.ig-feat-card[aria-checked="false"]').filter({ hasText: "Issuance inventory" }).waitFor();
          assert.equal(await toggle.getAttribute("aria-checked"), "false");
          // The refused enable asks for the check and switches on once it answers: no second click, no refusal left.
          await toggle.click(); await page.locator('.ig-feat-card[aria-checked="true"]').filter({ hasText: "Issuance inventory" }).waitFor().catch(async error => {
            throw Error(`${error.message}\n${await page.locator("body").innerText()}\n${JSON.stringify(run.calls.slice(-5))}\n${run.errors.join("\n")}`);
          });
          assert.deepEqual(run.calls.filter(c => c.endpoint.startsWith(`provider-connections/${inventory.id}/`) && c.method !== "GET").slice(-3)
            .map(c => c.endpoint.slice(`provider-connections/${inventory.id}/`.length)), ["features/inventory", "check", "features/inventory"]);
          assert.equal(await page.locator(".banner").filter({ hasText: /check|권한/i }).count(), 0);
          assert.deepEqual(run.errors, []);
        });
      } finally { await run.context.close(); }
    }
    // Cancelling the sign-in still to come keeps the saved connection and forgets the draft.
    const cancelled = await visit(browser, notion, 360, "dark");
    try {
      const page = cancelled.page;
      await withScreenshot(page, "setup-notion-cancel", async () => {
        await enterprise(page);
        await page.getByLabel("Token", { exact: true }).fill("synthetic-inventory");
        await page.getByRole("button", { name: "Authenticate", exact: true }).click();
        await choose(page, /Issuance inventory/); await choose(page, /Approved actions/);
        await scope(page);
        await page.getByLabel("Token", { exact: true }).waitFor();
        await page.getByRole("button", { name: "Cancel", exact: true }).click();
        await page.waitForFunction(() => window.__closed);
        assert.deepEqual([...cancelled.records.values()].map(c => [c.status, Object.keys(c.plans)]), [["ACTIVE", ["inventory"]]]);
        assert.equal(await page.evaluate(() => sessionStorage.getItem("cremore:setup:notion")), null);
        assert.deepEqual(cancelled.errors, []);
      });
    } finally { await cancelled.context.close(); }
    // A sign-in method that cannot list targets walks the existing setup, one connection after another.
    const legacyOnly = await visit(browser, { ...notion, auth_methods: notion.auth_methods.map(({ auth_first, ...method }) => method) });
    try {
      const page = legacyOnly.page;
      await withScreenshot(page, "setup-notion-legacy", async () => {
        await enterprise(page);
        await choose(page, /Issuance inventory/); await choose(page, /Approved actions/);
        await legacy(page, "synthetic-legacy-inventory");
        await legacy(page, "synthetic-legacy-acting");
        await page.locator("#setup-done").waitFor();
        assert.deepEqual([...legacyOnly.records.values()].map(c => Object.keys(c.plans)), [["inventory"], ["remediation"]]);
        assert.deepEqual(legacyOnly.errors, []);
      });
    } finally { await legacyOnly.context.close(); }
    const run = await visit(browser, github, 360, "dark"), { page } = run;
    try {
      assert.equal(await page.getByLabel("Private key", { exact: true }).count(), 0);
      await page.getByLabel("Organization", { exact: true }).fill("synthetic");
      // The start right under the organization field; the footer offers the same action.
      assert.equal(await page.getByRole("button", { name: "Create and install App on GitHub", exact: true }).count(), 2);
      await page.locator("#ig-app-start").click();
      await page.getByRole("button", { name: "Check installation again", exact: true }).click();
      await page.getByRole("checkbox", { name: /Issuance inventory/ }).click();
      await page.getByRole("checkbox", { name: /People directory/ }).click();
      await scope(page);
      await page.getByLabel("Token", { exact: true }).fill("synthetic-identity");
      await page.getByRole("button", { name: "Authenticate", exact: true }).click();
      await scope(page);
      await page.locator("#setup-done").waitFor();
      assert.equal(run.calls.filter(c => c.endpoint === "github/app-manifest/start").length, 1);
      assert.equal(run.calls.filter(c => c.endpoint === "github/app-manifest/complete").length, 2, "retry resumes completion after a transient failure");
      assert.deepEqual([...run.records.values()].map(c => [c.auth_method, Object.keys(c.plans)]), [["github_app", ["inventory"]], ["token", ["identity"]]]);
      const storage = await page.evaluate(() => JSON.stringify(sessionStorage));
      assert.ok(!storage.includes("synthetic-identity") && !storage.includes("private_key"));
      assert.deepEqual(run.errors, []);
    } finally { await run.context.close(); }
    // A content card's GitHub App: the draft that comes back from GitHub is still the content card's, with no feature step.
    const scan = await visit(browser, github, 1280, "light", "exposure");
    try {
      const page = scan.page;
      await page.getByLabel("Organization", { exact: true }).fill("synthetic");
      assert.equal(await page.locator(".ig-feat-card, .ig-feats, [role=checkbox]").count(), 0, "no feature choice before the App is made either");
      assert.equal(await page.getByText("Choose App installation permissions", { exact: true }).count(), 0);
      await page.locator("#ig-app-start").click();
      await page.getByRole("button", { name: "Check installation again", exact: true }).click();
      const check = page.getByRole("button", { name: "Check access and continue", exact: true });
      await check.waitFor();
      assert.equal(await page.locator(".ig-feat-card").count(), 0, "no feature step after the GitHub return");
      assert.match(await page.locator('.ig-steps [aria-current="step"]').innerText(), /2.*Access check/s);
      assert.deepEqual(scan.calls.filter(c => c.endpoint.endsWith("/discover")).map(c => c.body.purposes), [["exposure"]]);
      assert.deepEqual(scan.calls.find(c => c.endpoint === "github/app-manifest/start").body.installation_purposes, ["exposure"],
        "the App asks GitHub for the scan's read access only");
      await check.click();
      const select = page.getByRole("button", { name: "1 loaded resources", exact: true });
      await select.click(); await page.getByRole("menuitemcheckbox", { name: "Synthetic page", exact: true }).click(); await page.keyboard.press("Escape");
      await page.getByRole("button", { name: "Review selection", exact: true }).click();
      await page.getByRole("button", { name: /^Save integration/ }).click();
      await page.getByRole("button", { name: "Done · continue", exact: true }).click();
      await page.locator("#setup-done").waitFor();
      assert.deepEqual([...scan.records.values()].map(c => [c.auth_method, Object.keys(c.plans)]), [["github_app", ["exposure"]]]);
      assert.equal(scan.calls.filter(c => c.endpoint === "github/app-manifest/start").length, 1);
      assert.deepEqual(scan.errors, []);
    } finally { await scan.context.close(); }
    const multi = await visit(browser, { ...github, proofMulti: true, editions: [{ id: "enterprise_cloud", ...label("Enterprise Cloud") }] }, 360, "dark");
    try {
      const page = multi.page;
      await page.getByLabel("Organization", { exact: true }).fill("synthetic");
      await page.locator("#ig-app-start").click();
      await page.getByRole("button", { name: "Check installation again", exact: true }).click();
      await page.getByRole("checkbox", { name: /Issuance inventory/ }).click();
      await page.getByRole("button", { name: "List targets", exact: true }).click();
      const target = page.getByRole("button", { name: "Targets", exact: true }); await target.click();
      await page.getByRole("menuitemcheckbox", { name: "Synthetic target", exact: true }).click();
      await page.getByRole("menuitemcheckbox", { name: "Second organization", exact: true }).click();
      await page.keyboard.press("Escape");
      const check = page.getByRole("button", { name: "Check access and continue", exact: true });
      await check.click();
      await page.getByText(/Required access for the selected features is not verified/).waitFor();
      assert.equal(await page.getByRole("button", { name: "Continue with ready features", exact: true }).count(), 0, "one feature refused on one organization: nothing else is ready");
      assert.equal(await page.getByRole("button", { name: "Review selection", exact: true }).count(), 0, "a denied organization keeps the access check open");
      await check.click();
      await page.getByRole("button", { name: "Review selection", exact: true }).click();
      await page.getByRole("button", { name: "Save integration", exact: true }).click();
      await page.getByRole("button", { name: "Done · continue", exact: true }).click();
      await page.getByRole("button", { name: "Install on enterprise organizations", exact: true }).click();
      await page.locator("#ge-title").waitFor();
      assert.equal(await page.getByRole("dialog").count(), 1, "enterprise installer replaces the setup modal");
      assert.equal(await page.locator("#setup-done").count(), 0);
      await page.getByRole("checkbox", { name: "Select synthetic-new", exact: true }).click();
      assert.match(await page.locator(".ge").innerText(), /all its repositories/);
      await page.getByRole("button", { name: "Install and connect 1 selected", exact: true }).click();
      await page.getByRole("button", { name: "Install and connect 0 selected", exact: true }).waitFor();
      assert.equal(multi.calls.filter(c => c.endpoint.endsWith("/github-enterprise/install")).length, 1);
      assert.deepEqual(multi.errors, []);
    } finally { await multi.context.close(); }
    console.log("PASS setup: product first, Enterprise acting credential signed in on its own, cancel keeps what was saved, existing setup, GitHub manifest retry/return, toggles, enterprise installer, 360px overlays");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
