// Real React/CSS, fake API only: auth precedes features and exact access precedes scope approval.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { bundle } = require("./bundle-module.cjs");
const { ORIGIN, frames } = require("./console-proof.cjs");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const app = bundle({ React: "react", client: "react-dom/client", wizard: "@/console/views/integrations/auth-first.tsx", locale: "@/components/locale.tsx",
  fields: "@/console/views/integrations/fields.tsx", layer: "@/console/layer.tsx" });
const css = fs.readFileSync(path.join(__dirname, "../app/(console)/console.css"), "utf8");
const labelled = (label, label_ko = label) => ({ label, label_ko });
const descriptor = { provider: "notion", ...labelled("Notion"), editions: [{ id: "cloud", ...labelled("Cloud") }],
  target: [], purposes: { exposure: { plan: [], permissions: [{ id: "pages", ...labelled("Read shared pages", "공유 페이지 읽기") }] } },
  auth_methods: [{ id: "integration", ...labelled("Integration"), auth_first: { context: [] }, renewal: "NONE", purposes: ["exposure"],
    fields: [{ name: "token", ...labelled("Token", "토큰"), secret: true }] }] };

async function visit(browser, width, language, theme, mode = "new", aws = null) {
  const context = await browser.newContext({ viewport: { width, height: 900 } });
  await context.addInitScript(() => { window.__frame = requestAnimationFrame.bind(window); });
  await context.addInitScript(data => { window.__fixture = data; }, app.data);
  const calls = [], errors = [];
  let state, after, inspected = 0, schedulesEnabled = false, googleConfigured = false, listingFailed = false;
  // content: a new content-scan card; content-edit: the same card on an account that already collects its inventory
  // (content-edit-refused: whose inventory check now fails; content-plain: whose targets are shared, GitHub-like, roots);
  // mixed: a new account whose inventory access is refused while its scan passes; github-content: a content card's App.
  const keeping = mode.startsWith("content-");
  const editing = mode === "edit" || keeping;
  const editDescriptor = { ...descriptor,
    purposes: { exposure: { ...descriptor.purposes.exposure,
      plan: [{ name: "schedule_minutes", kind: "number", default: 1440, ...labelled("Schedule") }] },
      inventory: { ...(keeping ? { permissions: [{ id: "iam_read", ...labelled("Read members", "구성원 읽기") }] } : {}),
        plan: [{ name: "audit", kind: "bool", default: false, when: { inventory_scope: ["enabled"] }, ...labelled("Audit records") },
        { name: "previous_versions", kind: "bool", default: false, when: { kv_version: ["2"] }, ...labelled("Previous versions") },
        { name: "storage_key_accounts", kind: "list", ...labelled("Storage accounts") }] } },
    auth_methods: descriptor.auth_methods.map(m => ({ ...m, purposes: ["exposure", "inventory"] })) };
  const usedDescriptor = aws ? { ...descriptor, provider: "aws", ...labelled("Amazon Web Services"),
    ...(aws.checkDenied ? { purposes: Object.fromEntries(["exposure", "inventory"].map(p => [p, { plan: p === "inventory" ? aws.inventoryPlan ?? [] : [], permissions: [
      { id: "scanner_access", ...labelled("Scanner access") }, { id: p === "exposure" ? "list_buckets" : "iam_read", ...labelled(p + " read") },
    ] }])) } : {}),
    auth_methods: [{ id: aws.method ?? "role", ...labelled("Server role"), auth_first: { context: [] }, purposes: aws.checkDenied ? ["exposure", "inventory"] : ["exposure"], fields: [] }] }
    : mode === "remediator" ? { ...descriptor, purposes: { remediation: descriptor.purposes.exposure },
      auth_methods: descriptor.auth_methods.map(m => ({ ...m, purposes: ["remediation"] })) }
    : editing ? editDescriptor
    : mode === "mixed" ? { ...descriptor, purposes: { exposure: descriptor.purposes.exposure,
      inventory: { plan: [], permissions: [{ id: "members", ...labelled("Read members", "구성원 읽기") }] } },
      auth_methods: descriptor.auth_methods.map(m => ({ ...m, purposes: ["exposure", "inventory"] })) }
    : mode.startsWith("github") ? { ...descriptor, provider: "github", ...labelled("GitHub"),
      target: [{ name: "organization", kind: "text", required: true, ...labelled("Organization", "조직") }],
      auth_methods: [{ id: "github_app", ...labelled("GitHub App"), auth_first: { context: [] }, purposes: ["exposure"],
        fields: [{ name: "app_id", ...labelled("App ID") }, { name: "private_key", ...labelled("Private key"), secret: true }] }] }
    : mode === "generated" || mode.startsWith("oauth") ? { ...descriptor,
      auth_methods: descriptor.auth_methods.map(m => ({ ...m, ...(mode === "generated" ? { generated: true } : { flow: "gcp_oauth" }) })) } : descriptor;
  const previousPlans = { exposure: { schedule_minutes: 60 }, inventory: { audit: true, previous_versions: true, storage_key_accounts: ["storage-a", "storage-b"] } };
  const existing = mode === "edit" ? { id: "existing", revision: 3, name: "Original", edition: "cloud",
    auth_method: "integration", plans: previousPlans }
    : keeping ? { id: "existing", revision: 3, name: "Original", edition: "cloud", auth_method: "integration",
      purposes: ["inventory"], plans: { inventory: previousPlans.inventory }, feature_enabled: { inventory: true } } : undefined;
  const html = `<html data-theme="${theme}" lang="${language}"><head><meta charset="utf-8"><style>${css}</style></head><body><div id="root"></div><script>${app.preamble}
    const root=client.createRoot(document.getElementById('root')); window.__redraw=()=>root.render(React.createElement(locale.LocaleContext.Provider,{value:'${language}'},
      React.createElement(wizard.AuthFirstWizard,{admin:${aws?.admin !== false},descriptor:${JSON.stringify(usedDescriptor)},existing:${JSON.stringify(existing)},
      ${mode === "remediator" ? 'supplemental:true,initialPurposes:["remediation"],' : ''}${mode.startsWith("content") || mode === "github-content" ? 'entry:"exposure",' : ''}onClose(){window.__closed=true},onAdvanced(){}}))); window.__redraw();</script></body></html>`;
  await context.route("**/*", async route => {
    const req = route.request(), url = new URL(req.url());
    if (url.origin !== ORIGIN) { errors.push("external request"); return route.abort(); }
    if (req.isNavigationRequest()) return route.fulfill({ contentType: "text/html", body: html });
    if (req.resourceType() === "image") return route.fulfill({ contentType: "image/svg+xml", body: '<svg xmlns="http://www.w3.org/2000/svg"/>' });
    const endpoint = url.pathname.replace(/^\/api\/backend\//, ""), body = req.postDataJSON();
    calls.push({ endpoint, body, method: req.method() });
    if (endpoint === "settings/aws-investigations") {
      assert.ok(aws, "other providers never load AWS investigations");
      assert.equal(req.method(), "GET", "draft edits do not autosave global settings");
      return route.fulfill({ contentType: "application/json", body: JSON.stringify(Object.fromEntries(
        ["usage_lookup", "potential_access", "secrets_inventory"].map(key => [key, {
          switch: false, enabled: false, installation_allows: key !== "potential_access", updated_at: null, updated_by: null,
        }]))) });
    }
    if (endpoint === "settings/scan-triggers") {
      if (req.method() === "PUT") { assert.equal(body.schedules_enabled, true); schedulesEnabled = true; }
      return route.fulfill({ contentType: "application/json", body: JSON.stringify({ schedules: { enabled: schedulesEnabled } }) });
    }
    if (endpoint === "connections/source/saved-source/scan-scope-profiles") return route.fulfill({ contentType: "application/json",
      body: JSON.stringify({ profiles: [{ id: "profile", version: 1, name: "Shared page", selected_roots: [{ resource_id: "page1" }] }] }) });
    if (endpoint === "scan-scope-profiles/profile/preview") return route.fulfill({ contentType: "application/json", body: JSON.stringify({ plan_id: "plan", executable: true }) });
    if (endpoint === "scan-runs") {
      assert.equal(body.plan_id, "plan");
      return route.fulfill({ contentType: "application/json", body: JSON.stringify({ id: "job" }) });
    }
    if (endpoint === "scan-runs/job") return route.fulfill({ contentType: "application/json", body: JSON.stringify({ status: "PARTIAL",
      schedule: { enabled: true, minutes: 15, next_due_at: new Date(Date.now() + 900000).toISOString() } }) });
    if (endpoint === "settings/machine-identity") return route.fulfill({ contentType: "application/json", body: JSON.stringify({
      configured: false, revision: 0, secret_saved: false, idp: {}, aws: {}, gcp: {}, azure: {}, vault: [], processes: [], test: null,
    }) });
    if (endpoint === "aws/scanner-identity") {
      assert.ok(aws, "other providers never request AWS identity");
      if (req.method() === "PUT") {
        assert.equal(body.confirm, true);
        if (aws.denied) return route.fulfill({ status: 409, contentType: "application/json", body: JSON.stringify({ error: "WORKER_IDENTITY_MISMATCH" }) });
        if (aws.view.api.requires === "ROLE_ARN") assert.equal(body.role_arn, "arn:aws:iam::123456789012:role/path/Scanner");
        aws.view = { ...aws.view, api: { ...aws.view.api, requires: null }, approvable: null, hold: null,
          approved: { ...aws.view.api, principal_arn: body.role_arn ?? aws.view.api.principal_arn } };
      } else if (aws.readFails) return route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: "IDENTITY_UNAVAILABLE" }) });
      return route.fulfill({ contentType: "application/json", body: JSON.stringify(aws.view) });
    }
    if (endpoint === "v2/gcp/oauth/status") {
      assert.ok(mode.startsWith("oauth"), "other methods never load Google OAuth settings");
      return route.fulfill({ contentType: "application/json", body: JSON.stringify({ configured: googleConfigured,
        locked: mode === "oauth-locked", source: mode === "oauth-locked" ? "SETTING" : "DASHBOARD" }) });
    }
    if (endpoint === "v2/gcp/oauth/client") {
      assert.equal(mode, "oauth");
      assert.equal(req.method(), "PUT");
      assert.deepEqual(body, { client_id: "synthetic.apps.googleusercontent.com", client_secret: "synthetic-client-secret",
        redirect_uri: ORIGIN + "/gcp/oauth/callback" });
      googleConfigured = true;
      return route.fulfill({ contentType: "application/json", body: "{}" });
    }
    if (endpoint === "github/app-manifest/start") {
      assert.ok(mode.startsWith("github"));
      assert.equal(body.onboarding, true);
      assert.deepEqual(body.target, { organization: "acme" });
      // A content card's App asks GitHub for the scan's read access; an account card's starts with none chosen.
      assert.deepEqual(body.installation_purposes, mode === "github-content" ? ["exposure"] : []);
      return route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: "GITHUB_APP_UNAVAILABLE" }) });
    }
    if (endpoint === "v2/gcp/oauth/start") {
      assert.equal(mode, "oauth");
      assert.equal(body.connection_id, "draft");
      return route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: "GCP_OAUTH_SETUP_REQUIRED" }) });
    }
    if (endpoint === "onboarding-sessions" || endpoint === "provider-connections/existing/targets/draft") {
      if (editing) assert.equal(body.expected_revision, 3);
      else if (aws) assert.ok(aws.view.approved, "AWS approval must succeed before the authentication draft is created");
      else assert.equal(body.credential.token, "synthetic-notion-token");
      if (!editing) assert.equal(body.credential_purpose, mode === "remediator" ? "remediator" : "collector");
      assert.equal(body.purposes, undefined, "no feature or content access requested before authentication");
      state = { id: "draft", revision: 1, state: "WORKING", edition: "cloud", auth_method: usedDescriptor.auth_methods[0].id, context: {}, plans: {},
        expires_at: new Date(Date.now() + 600000).toISOString(), blockers: [] };
      // The content run's sign-in works with a warning (as GitHub's classic PAT without read:org answers).
      after = { state: "AUTHENTICATED", authentication: { status: "GRANTED", ...(mode === "content" ? { detail: "GITHUB_TOKEN_READ_ORG_REQUIRED" } : {}) } };
      if (mode === "edit") state = { ...state, editing: "existing", previous_target_ids: ["workspace", "account", "account-b"], previous_plans: previousPlans };
      if (keeping) state = { ...state, editing: "existing", purposes: ["inventory"], previous_target_ids: [mode.startsWith("content-plain") ? "org-a" : "account"],
        previous_plans: { inventory: previousPlans.inventory }, feature_enabled: { inventory: true } };
      if (mode === "generated") state = { ...state, state: "SETUP_REQUIRED", generated: { kid: "synthetic-public-key" } };
      if (mode === "oauth") state = { ...state, state: "AWAITING_OAUTH" };
    } else if (endpoint.endsWith("/cancel")) {
      state = { ...state, state: "CANCELLED", revision: state.revision + 1 };
    } else if (endpoint.endsWith("/authenticate")) {
      assert.equal(state.state, "SETUP_REQUIRED");
      assert.equal(body.credential, undefined, "retry the existing generated key without creating another credential");
      state = { ...state, state: "WORKING", revision: state.revision + 1 };
    } else if (endpoint.endsWith("/read")) { if (state.state === "WORKING") state = { ...state, ...after, revision: state.revision + 1 }; }
    else if (endpoint.endsWith("/discover")) {
      // The content card's automatic listing is refused once: it must wait for the retry, never call again by itself.
      if (mode === "content" && !listingFailed) { listingFailed = true; return route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: "UNAVAILABLE" }) }); }
      assert.deepEqual(body.purposes, mode === "edit" ? ["exposure", "inventory"] : keeping || aws?.checkDenied ? ["inventory", "exposure"]
        : mode === "mixed" ? ["inventory", "exposure"] : ["exposure"]);
      state = { ...state, purposes: body.purposes, state: "WORKING", revision: state.revision + 1 };
      after = { state: "LISTED", completeness: "COMPLETE", roots: [{ id: "workspace", label: "Workspace", target: {} }] };
      if (editing) after.roots = [{ ...after.roots[0], purposes: ["exposure"] },
        { id: "account", label: "Inventory account", target: { inventory_scope: "enabled", kv_version: "1" }, purposes: ["inventory"], plan_options: { storage_key_accounts: ["storage-a"] } },
        ...(mode === "edit" ? [{ id: "account-b", label: "Second inventory account", target: { inventory_scope: "enabled", kv_version: "2" }, purposes: ["inventory"], plan_options: { storage_key_accounts: ["storage-b"] } }] : [])];
      // GitHub-like: organizations without per-root features serve every feature of the account.
      if (mode === "content-plain") after.roots = [{ id: "org-a", label: "Org A", target: { org: "a" } }, { id: "org-b", label: "Org B", target: { org: "b" } }];
      if (mode === "content-plain-missing") after = { ...after, roots: [{ id: "org-b", label: "Org B", target: { org: "b" } }], previous_unlisted: 1 };
      if (aws?.discoveryDenied) after = { state: "FAILED", error: "AWS_REGIONS_ACCESS_DENIED" };
    } else if (endpoint.endsWith("/inspect")) {
      assert.deepEqual(body.target_ids, mode === "edit" ? ["workspace", "account", "account-b"] : mode === "content-plain" ? ["org-a", "org-b"]
        : keeping ? ["account", "workspace"] : ["workspace"]);
      if (mode === "edit") assert.deepEqual(body.plans, previousPlans, "preserve plans on a LISTED refresh and normalize each feature against its own root");
      if (keeping) assert.deepEqual(Object.keys(body.plans).sort(), ["exposure", "inventory"], "the kept inventory rides along unchanged");
      // A scan location added on a content card serves the scan only: the kept inventory stays on Org A.
      assert.deepEqual(body.target_purposes, mode === "content-plain" ? { "org-b": ["exposure"] } : undefined);
      if (mode === "content-plain") state = { ...state, roots: state.roots.map(r => r.id === "org-b" ? { ...r, purposes: ["exposure"] } : r) };
      const status = ++inspected === 1 && ["new", "mixed"].includes(mode) ? "MISSING" : "GRANTED";
      state = { ...state, plans: body.plans, selected_targets: body.target_ids, state: "WORKING", revision: state.revision + 1 };
      after = { state: "CHECKED", blockers: status === "MISSING" ? [{ permission: "pages", status, detail: "HTTP_403" }] : [],
        snapshot_id: "snapshot", checks: { results: { exposure: { items: [{ permission: "pages", status, detail: status === "MISSING" ? "HTTP_403" : undefined }] } } },
        resources: status === "MISSING" ? [] : [{ id: "page1", source_key: "source", resource_type: "NOTION_PAGE", provider_resource_id: "page-id",
          display_name: "Shared page", list_visibility: "VISIBLE", content_readiness: "NOT_PROBED" }] };
      if (mode === "edit") after = { ...after, selected_resources: ["page1"],
        selected_roots: [{ resource_id: "page1", page_mode: "PAGE_ONLY", priority: 7, descendant_ids: [] }] };
      if (mode === "mixed" && inspected === 1) {
        // The scan passed and the inventory was refused: the server lists no resources while any feature is blocked.
        assert.deepEqual(Object.keys(body.plans).sort(), ["exposure", "inventory"]);
        after = { ...after, blockers: [{ purpose: "inventory", permission: "members", status: "MISSING", detail: "HTTP_403" }],
          checks: { results: { exposure: { items: [{ permission: "pages", status: "GRANTED" }] },
            inventory: { items: [{ permission: "members", status: "MISSING", detail: "HTTP_403" }] } } } };
      } else if (mode === "mixed") {
        assert.deepEqual(body.plans, { exposure: {} }, "continuing with the ready feature checks only that feature again");
        state = { ...state, purposes: ["exposure"], held_purposes: ["inventory"] };
      }
      if (keeping) {
        // Answers per target, as a multi-target draft has them; the kept inventory is checked too.
        const [scan, kept] = mode === "content-plain" ? [["org-a", "org-b"], ["org-a"]] : [["workspace"], ["account"]];
        const refused = { "content-edit-refused": ["inventory", "account"], "content-plain": ["exposure", "org-a"] }[mode];
        const answer = (purpose, permission, target_id) => refused?.[0] === purpose && refused[1] === target_id
          ? { permission, status: "MISSING", detail: "HTTP_403", target_id } : { permission, status: "GRANTED", target_id };
        const results = { exposure: { items: scan.map(t => answer("exposure", "pages", t)) }, inventory: { items: kept.map(t => answer("inventory", "iam_read", t)) } };
        const blockers = Object.entries(results).flatMap(([purpose, r]) => r.items.filter(i => i.status !== "GRANTED").map(i => ({ purpose, ...i })));
        // The worker lists no resources while any feature is blocked.
        after = { ...after, checks: { results }, blockers, resources: blockers.length ? [] : after.resources };
      }
      if (aws?.method === "role" && "checkDenied" in aws) {
        const results = Object.fromEntries(["exposure", "inventory"].map(p => [p, { items: [
          { permission: "scanner_access", subject: "123456789012", status: aws.checkDenied ? "MISSING" : "GRANTED", detail: aws.checkDenied ? "ASSUME_ROLE_DENIED" : undefined },
          { permission: p === "exposure" ? "list_buckets" : "iam_read", subject: "123456789012", status: aws.checkDenied ? "NOT_REPORTED" : "GRANTED", detail: aws.checkDenied ? "SCANNER_ACCESS_REQUIRED" : undefined },
        ] }]));
        // As permissions.blockers gives them: every answer that is not GRANTED, with its feature.
        after = { ...after, resources: aws.checkDenied ? [] : after.resources, checks: { results },
          blockers: Object.entries(results).flatMap(([purpose, r]) => r.items.filter(i => i.status !== "GRANTED").map(i => ({ purpose, ...i }))) };
      }
    } else if (endpoint.endsWith("/select")) {
      assert.equal(inspected, ["edit", "content"].includes(mode) || keeping ? 1 : 2); assert.deepEqual(body.resource_ids, ["page1"]);
      assert.equal(body.selected_roots[0].page_mode, "PAGE_ONLY");
      if (mode === "edit") assert.equal(body.selected_roots[0].priority, 7, "preserve existing root settings");
      state = { ...state, state: "SELECTED", revision: state.revision + 1 };
    } else if (endpoint.endsWith("/complete")) {
      if (aws?.saveFails) {
        aws.saveFails = false;
        return route.fulfill({ status: 409, contentType: "application/json", body: JSON.stringify({ error: "PROVIDER_CONNECTION_CHANGED" }) });
      }
      assert.equal(state.state, "SELECTED"); state = { ...state, state: "COMPLETED" };
      // A new scope follows the installation's full-scan default (null) unless a cadence is chosen, and scans what changed.
      assert.deepEqual(body.schedules, editing ? {} : { exposure: { schedule_minutes: aws ? 0 : 15, full_scan_minutes: aws ? 0 : null } });
      // Scopes saved now (a new integration's, targets added while editing) scan what changed; saved ones keep theirs.
      assert.equal(body.change_scans, true);
      assert.deepEqual(body.aws_investigations, aws ? { changes: { usage_lookup: true }, expected: { usage_lookup: false } } : undefined);
      return route.fulfill({ contentType: "application/json", body: JSON.stringify({ id: "saved", provider: "notion",
        checks: { authentication_only: false }, plans: { exposure: {} }, children: [{ kind: "content", id: "saved-source", purpose: "exposure", name: "Source" }] }) });
    } else { errors.push(endpoint); return route.abort(); }
    return route.fulfill({ contentType: "application/json", body: JSON.stringify(state) });
  });
  const page = await context.newPage();
  page.on("pageerror", error => errors.push(error.message));
  await page.goto(ORIGIN);
  await page.locator("#auth-first-title").waitFor().catch(error => { throw new Error(`${error.message}\n${errors.join("\n")}`); });
  return { context, page, calls, errors };
}

async function main() {
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  try {
    const awsFields = JSON.parse(execFileSync("python", ["-c", "import json; from cremore_aws_provider.onboarding import DESCRIPTORS; print(json.dumps(DESCRIPTORS[0]['purposes']['inventory']['plan']))"],
      { cwd: path.join(__dirname, "../.."), encoding: "utf8", env: { ...process.env, AWS_EC2_METADATA_DISABLED: "true" } }));
    for (const [lang, theme] of [["ko", "light"], ["en", "dark"]]) for (const width of [360, 1280]) {
      const context = await browser.newContext({ viewport: { width, height: 900 } });
      try {
        await context.addInitScript(data => { window.__fixture = data; }, app.data);
        await context.route("**/*", route => route.request().isNavigationRequest() && new URL(route.request().url()).origin === ORIGIN
          ? route.fulfill({ contentType: "text/html", body: `<html lang="${lang}" data-theme="${theme}"><meta charset="utf-8"><style>${css}</style><body><div id="root"></div><script>${app.preamble}
            function Fields(){const [v,set]=React.useState({iam_policy_metadata:true,cloudtrail:false,cloudtrail_creation_only:true});return React.createElement(React.Fragment,null,
              React.createElement(layer.Modal,{className:'integ',labelledBy:'title',onClose:()=>window.__closed=true},React.createElement('h2',{id:'title'},'AWS'),
                React.createElement(fields.FieldGrid,{fields:${JSON.stringify(awsFields)},values:v,onChange:(k,n)=>{window.__values={...v,[k]:n};set(window.__values)}})),React.createElement(layer.TooltipLayer));}
            client.createRoot(document.getElementById('root')).render(React.createElement(locale.LocaleContext.Provider,{value:'${lang}'},React.createElement(Fields)));
          </script></body></html>` }) : route.abort());
        const page = await context.newPage(), errors = [];
        page.on("pageerror", error => errors.push(error.message));
        await page.goto(ORIGIN);
        await page.getByRole("checkbox").first().waitFor({ timeout: 3000 }).catch(async error => {
          throw new Error(`${error.message}\n${errors.join("\n")}\n${await page.locator("body").innerText()}`);
        });
        const textOf = f => lang === "ko" ? f.description_ko : f.description;
        const fitsModal = async () => assert.equal(await page.getByRole("tooltip").evaluate(el => {
          const r=el.getBoundingClientRect(), m=document.querySelector('.modal').getBoundingClientRect();
          return r.left>=m.left+7 && r.right<=m.right-7 && r.top>=m.top+7 && r.bottom<=m.bottom-7 && el.scrollWidth<=el.clientWidth;
        }), true, "help stays inset from every modal edge");
        for (const name of ["iam_policy_metadata", "cloudtrail", "cloudtrail_creation_only"]) {
          const f = awsFields.find(f => f.name === name), button = page.getByRole("checkbox", { name: lang === "ko" ? f.label_ko : f.label, exact: true });
          const before = await button.boundingBox(); await button.focus();
          const tip = page.getByRole("tooltip"); await tip.waitFor();
          assert.equal(await tip.innerText(), textOf(f));
          assert.deepEqual(await button.boundingBox(), before, "help overlays the form");
          assert.equal(await tip.evaluate(el => {const r=el.getBoundingClientRect();return r.left>=0 && r.right<=innerWidth && r.top>=0 && r.bottom<=innerHeight;}), true);
          await fitsModal();
          assert.equal(await button.evaluate(el => {
            const r=el.getBoundingClientRect(), c=el.querySelector('.check').getBoundingClientRect(), n=el.querySelector('.nm').getBoundingClientRect();
            return Math.abs((c.left+n.right)/2-(r.left+r.right)/2)<2;
          }), true, "checkbox and label form a centered group");
        }
        const cloudtrail = awsFields.find(f => f.name === "cloudtrail");
        await page.getByRole("checkbox", { name: lang === "ko" ? cloudtrail.label_ko : cloudtrail.label, exact: true }).click();
        assert.deepEqual(await page.evaluate(() => window.__values), { iam_policy_metadata: true, cloudtrail: true, cloudtrail_creation_only: true }, "policy metadata is a separate bool and help does not change the payload contract");
        const days = awsFields.find(f => f.name === "cloudtrail_days");
        await page.getByRole("img", { name: textOf(days), exact: true }).focus();
        assert.equal(await page.getByRole("tooltip").innerText(), textOf(days), "number field help is keyboard reachable");
        await fitsModal();
        await page.keyboard.press("Escape");
        await page.getByRole("tooltip").waitFor({ state: "hidden" });
        assert.notEqual(await page.evaluate(() => window.__closed), true, "Escape dismisses help before its dialog");
        const toggle = page.getByRole("checkbox", { name: lang === "ko" ? cloudtrail.label_ko : cloudtrail.label, exact: true });
        await page.mouse.move(0, 0);
        await toggle.hover(); await page.getByRole("tooltip").waitFor();
        await page.getByRole("tooltip").hover();
        assert.equal(await page.getByRole("tooltip").count(), 1, "one hoverable tooltip replaces prior help");
        await page.mouse.move(0, 0);
        await page.getByRole("tooltip").waitFor({ state: "hidden" });
        await toggle.hover(); await page.getByRole("tooltip").waitFor();
        await page.setViewportSize({ width, height: 700 });
        await page.getByRole("tooltip").waitFor({ state: "hidden" });
        assert.deepEqual(errors, []);
      } finally { await context.close(); }
    }
    const awsView = changes => ({ api: { state: "READY", kind: "IAM_ROLE", account_id: "123456789012",
      principal_arn: "arn:aws:iam::123456789012:role/path/Scanner", requires: null },
      worker: { state: "READY" }, worker_stale: false, same_identity: true, sign_in: null, sign_in_here: false,
      approvable: null, approved: null, hold: null, policy: {}, permission_set_policy: {}, ...changes });
    const approvals = run => run.calls.filter(c => c.endpoint === "aws/scanner-identity" && c.method === "PUT");
    const drafts = run => run.calls.filter(c => c.endpoint === "onboarding-sessions");
    for (const method of ["runtime", "role"]) {
      const config = { view: awsView(), method, discoveryDenied: method === "runtime", checkDenied: method === "role", inventoryPlan: awsFields.filter(f => f.name !== "schedule_minutes") };
      const run = await visit(browser, 360, "en", "dark", "new", config);
      try {
        const page = run.page;
        await page.getByRole("button", { name: "Approve identity and authenticate", exact: true }).click();
        await page.locator(".ig-feat-card").first().waitFor();
        for (const card of await page.locator(".ig-feat-card").all()) await card.click();
        await page.getByRole("button", { name: "List targets", exact: true }).click();
        if (method === "runtime") {
          await page.getByText("Give CreMore's identity the read policy", { exact: true }).waitFor();
          assert.equal(await page.getByRole("button", { name: "Copy policy", exact: true }).count(), 1);
          assert.equal(await page.getByRole("button", { name: "List targets", exact: true }).isEnabled(), true);
          config.discoveryDenied = false;
          await page.getByRole("button", { name: "List targets", exact: true }).click();
          await page.getByRole("button", { name: "Check access and continue", exact: true }).waitFor();
        } else {
          const cloudtrail = page.getByRole("checkbox", { name: "Enable CloudTrail collection", exact: true });
          await cloudtrail.waitFor();
          assert.equal(await page.getByLabel("CloudTrail history days (optional)", { exact: true }).count(), 0, "dependent fields stay hidden while CloudTrail is off");
          await cloudtrail.click();
          assert.equal(await page.getByLabel("CloudTrail history days (optional)", { exact: true }).count(), 1);
          await cloudtrail.click();
          await page.getByRole("button", { name: "Check access and continue", exact: true }).click();
          await page.getByText(/The server could not assume the collection role/).first().waitFor();
          // Each held feature lists what it lacks, with the account it was checked for.
          assert.equal(await page.locator("li").filter({ hasText: "Scanner access · 123456789012 · The server could not assume the collection role" }).count(), 2);
          assert.equal(await page.locator("li").filter({ hasText: "Account access failed, so this permission has not been checked yet." }).count(), 2);
          assert.equal(await page.getByRole("button", { name: "Continue with ready features", exact: true }).count(), 0, "with every feature held there is nothing to continue with");
          assert.equal(await page.getByRole("button", { name: "Review selection", exact: true }).count(), 0);
          assert.equal(await page.getByText("ASSUME_ROLE_DENIED", { exact: true }).count(), 0);
          config.checkDenied = false;
          await page.locator(".modal-foot .primary-btn").click();
          await page.getByRole("button", { name: "1 loaded resources", exact: true }).waitFor();
          assert.match(await page.locator('.ig-steps [aria-current="step"]').innerText(), /4.*Collection scope/s);
          assert.equal(await page.getByText(/Notion|child pages/).count(), 0, "AWS never shows Notion scope instructions");
          assert.equal(await page.getByText("Only selected items are saved as scan targets.", { exact: true }).count(), 1);
          await page.getByRole("button", { name: "1 loaded resources", exact: true }).click();
          await page.getByRole("menuitemcheckbox", { name: "Shared page", exact: true }).click();
          await page.keyboard.press("Escape");
          await page.getByRole("button", { name: "Review selection", exact: true }).click();
          const usage = page.getByRole("switch", { name: "Observed use of a discovered key", exact: true });
          await usage.waitFor();
          assert.equal(await page.getByRole("switch", { name: "Secrets Manager inventory and metadata", exact: true }).count(), 0, "no vault selection means no Secrets Manager investigation");
          assert.equal(await page.getByRole("switch", { name: "Potential access simulation", exact: true }).isDisabled(), true, "installation locks remain enforced");
          await usage.focus(); await page.keyboard.press("Space");
          assert.equal(await usage.getAttribute("aria-checked"), "true");
          await page.getByLabel("Start initial collection for selected features after saving", { exact: true }).uncheck();
          await page.locator(".ig-section select").last().selectOption("0");
          await page.getByRole("combobox", { name: "Full scope scan schedule", exact: true }).selectOption("0");
          await page.reload(); await usage.waitFor();
          assert.equal(await usage.getAttribute("aria-checked"), "true", "unsaved investigation selection survives draft reload");
          assert.equal(await page.locator(".modal").evaluate(el => el.scrollWidth <= el.clientWidth), true, "review investigation rows fit 360px");
          assert.equal(run.calls.filter(c => c.endpoint === "settings/aws-investigations" && c.method !== "GET").length, 0);
          config.saveFails = true;
          const save = page.getByRole("button", { name: "Save integration", exact: true });
          await save.click();
          await page.getByText("Someone changed it first. Reload and apply again.", { exact: true }).waitFor();
          assert.equal(await usage.getAttribute("aria-checked"), "true", "save failure keeps review selections");
          await save.click();
          await page.getByRole("button", { name: "Done · continue", exact: true }).waitFor();
        }
        assert.equal(await page.locator(".modal").evaluate(el => el.scrollWidth <= el.clientWidth), true);
        assert.deepEqual(run.errors, []);
      } finally { await run.context.close(); }
    }
    for (const method of ["role", "runtime"]) {
      const view = awsView();
      if (method === "role") {
        view.api = { ...view.api, principal_arn: null, caller_arn: "arn:aws:sts::123456789012:assumed-role/Scanner/server",
          requires: "ROLE_ARN" };
        view.approvable = "ROLE_ARN_REQUIRED";
      }
      const config = { view, method };
      const run = await visit(browser, 360, "en", "dark", "new", config);
      try {
        const approve = run.page.getByRole("button", { name: "Approve identity and authenticate", exact: true });
        await approve.waitFor({ timeout: 3000 });
        assert.equal(drafts(run).length, 0, "mounting does not approve or authenticate");
        assert.equal(approvals(run).length, 0);
        if (method === "role") {
          assert.equal(await approve.isDisabled(), true);
          assert.equal(await run.page.getByLabel("IAM role ARN this identity uses (with its path)", { exact: true }).isVisible(), false);
          await run.page.getByText("Enter the role ARN manually (advanced)", { exact: true }).click();
          await run.page.getByLabel("IAM role ARN this identity uses (with its path)", { exact: true }).fill("arn:aws:iam::123456789012:role/path/Scanner");
        }
        assert.equal(await run.page.locator(".modal").evaluate(el => el.scrollWidth <= el.clientWidth), true, "long ARNs fit the mobile dialog");
        await approve.click();
        await run.page.locator(".ig-feats").waitFor();
        assert.equal(approvals(run).length, 1);
        assert.ok(run.calls.indexOf(approvals(run)[0]) < run.calls.indexOf(drafts(run)[0]));
        await run.page.getByRole("button", { name: "Back", exact: true }).click();
        await run.page.getByRole("button", { name: "Authenticate", exact: true }).click();
        assert.equal(approvals(run).length, 1, "an approved identity is not approved again");
        assert.equal(drafts(run).length, 1);
        if (method === "runtime") {
          await run.page.getByRole("button", { name: "Back", exact: true }).click();
          config.view = { ...config.view, hold: "AWS_SCANNER_IDENTITY_CHANGED" };
          await run.page.getByRole("button", { name: "Refresh AWS identity", exact: true }).click();
          await approve.click();
          await run.page.locator(".ig-feats").waitFor();
          assert.equal(approvals(run).length, 2);
          assert.equal(drafts(run).length, 2, "a new approval recreates the draft bound to the old revision");
          const cancelled = run.calls.find(c => c.endpoint.endsWith("/cancel"));
          assert.ok(cancelled && run.calls.indexOf(cancelled) < run.calls.indexOf(drafts(run)[1]));
        }
        assert.deepEqual(run.errors, []);
      } finally { await run.context.close(); }
    }
    const bootstrapConfig = { view: awsView({ api: { state: "NO_CREDENTIALS" }, worker: null, same_identity: false,
      sign_in: { reason: "AWS_CONFIG_NOT_MOUNTED" } }) };
    const bootstrap = await visit(browser, 360, "en", "dark", "new", bootstrapConfig);
    try {
      const page = bootstrap.page;
      await page.getByText("Set up the server's AWS identity first", { exact: true }).waitFor();
      assert.equal(await page.locator(".modal-foot .primary-btn").isDisabled(), true);
      assert.equal(await page.getByText(/AWS_CONFIG_DIR/).count(), 0, "team setup never asks for an operator's AWS CLI directory");
      const host = page.getByLabel("Where the CreMore server runs", { exact: true });
      await host.selectOption("ec2");
      await page.getByRole("link", { name: "Open the EC2 console", exact: true }).waitFor();
      await host.selectOption("kubernetes");
      await page.getByText(/On EKS, bind the API and worker/).waitFor();
      await host.selectOption("external");
      await page.getByRole("button", { name: "Set up the server identity with the company IdP", exact: true }).click();
      await page.locator("#mi-title").waitFor();
      assert.equal(await page.getByRole("dialog").count(), 1, "setup replaces the dialog without competing focus traps");
      bootstrapConfig.view = awsView(); // The configured role is returned by IAM, including its path.
      await page.getByRole("button", { name: "Close", exact: true }).click();
      await page.getByText("arn:aws:iam::123456789012:role/path/Scanner", { exact: true }).waitFor();
      assert.equal(await page.getByLabel("IAM role ARN this identity uses (with its path)").count(), 0);
      assert.equal(drafts(bootstrap).length, 0, "setting up the server never approves a collection implicitly");
      await page.getByRole("button", { name: "Approve identity and authenticate", exact: true }).click();
      await page.locator(".ig-feats").waitFor();
      assert.deepEqual(approvals(bootstrap)[0].body, { confirm: true }, "no operator-entered ARN is needed");
      assert.deepEqual(bootstrap.errors, []);
    } finally { await bootstrap.context.close(); }
    for (const config of [
      { view: awsView({ worker_stale: true }) }, { view: awsView({ same_identity: false }) },
      { view: awsView({ approvable: "ROOT_CREDENTIALS_REFUSED" }) }, { view: awsView(), admin: false },
      { view: awsView(), readFails: true }, { view: awsView(), denied: true },
      { view: awsView({ approved: { principal_arn: "arn:aws:iam::123456789012:role/Previous" }, hold: "AWS_SCANNER_IDENTITY_CHANGED" }), denied: true },
    ]) {
      const run = await visit(browser, 900, "ko", "light", "new", config);
      try {
        await run.page.getByRole("button", { name: "AWS 신원 다시 확인", exact: true }).waitFor({ timeout: 3000 });
        const authenticate = run.page.locator(".modal-foot .primary-btn");
        if (config.denied) {
          await authenticate.click();
          await run.page.getByText(/API와 워커가 서로 다른 AWS 신원/).waitFor({ timeout: 3000 });
          assert.equal(approvals(run).length, 1);
        } else {
          assert.equal(await authenticate.isDisabled(), true);
          assert.equal(approvals(run).length, 0);
          if (config.readFails) {
            config.readFails = false;
            await run.page.getByRole("button", { name: "AWS 신원 다시 확인", exact: true }).click();
            await run.page.getByRole("button", { name: "신원 승인·인증 확인", exact: true }).waitFor();
            await authenticate.click();
            await run.page.locator(".ig-feats").waitFor();
          }
        }
        assert.equal(drafts(run).length, config.readFails === false ? 1 : 0, "blocked or rejected approval never creates a draft");
        assert.deepEqual(run.errors, []);
      } finally { await run.context.close(); }
    }
    for (const [width, lang, theme] of [[1280, "ko", "light"], [360, "en", "dark"]]) {
      const run = await visit(browser, width, lang, theme), page = run.page;
      const L = (ko, en) => lang === "ko" ? ko : en;
      try {
        assert.equal(await page.locator(".ig-feats").count(), 0);
        // What the feature needs is shown before signing in, folded per feature, and opens from the keyboard.
        await page.getByRole("heading", { name: L("기능별 필요한 권한", "Permissions each feature needs"), exact: true }).waitFor();
        const needs = page.locator("summary").filter({ hasText: L("필요한 권한 (1)", "Permissions needed (1)") });
        assert.equal(await page.getByText(L("공유 페이지 읽기", "Read shared pages"), { exact: true }).isVisible(), false);
        await needs.focus(); await page.keyboard.press("Enter");
        await page.getByText(L("공유 페이지 읽기", "Read shared pages"), { exact: true }).waitFor();
        await page.getByLabel(L("토큰", "Token"), { exact: true }).fill("synthetic-notion-token", { timeout: 3000 }).catch(async error => {
          throw new Error(`${error.message}\n${await page.locator("body").innerText()}\n${run.errors.join("\n")}`);
        });
        await page.getByRole("button", { name: L("인증 확인", "Authenticate"), exact: true }).click();
        await page.locator(".ig-feat-card").waitFor();
        await page.locator(".ig-feat-card").click();
        await page.getByRole("button", { name: L("대상 불러오기", "List targets"), exact: true }).click();
        const check = page.getByRole("button", { name: L("권한 확인·다음", "Check access and continue"), exact: true });
        await check.waitFor();
        assert.equal(await check.evaluate(el => el.matches('.modal-foot .primary-btn')), true, "the footer owns progression");
        assert.equal(await page.getByRole("button", { name: "Check access and list resources", exact: true }).count(), 0);
        await check.click();
        await page.getByText(L("선택한 기능의 필수 권한이 확인되지 않았습니다.", "Required access for the selected features is not verified."), { exact: false }).waitFor();
        assert.equal(await page.getByRole("button", { name: L("준비된 기능만 계속", "Continue with ready features"), exact: true }).count(), 0, "a single held feature has nothing ready to continue with");
        assert.equal(await page.locator("li").filter({ hasText: L("공유 페이지 읽기 · 이 조회가 거절되었습니다.", "Read shared pages · This read was denied.") }).count(), 1);
        const review = page.getByRole("button", { name: L("선택 검토", "Review selection"), exact: true });
        assert.equal(await review.count(), 0, "access refusal stays before the scope step");
        assert.match(await page.locator('.ig-steps [aria-current="step"]').innerText(), new RegExp(L("3.*권한 확인", "3.*Access check"), "s"));
        await check.click();
        const select = page.getByRole("button", { name: L("조회된 검사 대상 1개", "1 loaded resources"), exact: true });
        await select.waitFor(); await page.reload(); await select.waitFor();
        assert.match(await page.locator('.ig-steps [aria-current="step"]').innerText(), new RegExp(L("4.*수집 범위", "4.*Collection scope"), "s"));
        assert.equal(await page.getByText(L("선택한 페이지만 검사하며 하위 페이지는 별도로 선택합니다.", "Only selected pages are scanned. Select child pages separately."), { exact: true }).count(), 1);
        assert.equal(run.calls.filter(c => c.endpoint === "onboarding-sessions").length, 1, "reload resumes one draft without replaying the token");
        await select.scrollIntoViewIfNeeded(); await frames(page);
        const before = await select.boundingBox();
        await select.click();
        const menu = page.getByRole("menu").last(); await menu.waitFor();
        assert.deepEqual(await select.boundingBox(), before, "opening a list does not shift the form");
        assert.equal(await menu.evaluate(el => { const r = el.getBoundingClientRect(); return r.left >= 0 && r.right <= innerWidth && r.top >= 0 && r.bottom <= innerHeight; }), true);
        await menu.getByRole("menuitemcheckbox", { name: "Shared page", exact: true }).click();
        await page.keyboard.press("Escape");
        assert.equal(await select.evaluate(el => document.activeElement === el), true);
        await review.click();
        const save = page.getByRole("button", { name: L("연동 저장·수집 시작", "Save integration and collect"), exact: true });
        assert.equal(await save.isDisabled(), true, "a saved interval never conceals a disabled installation trigger");
        assert.equal(await page.getByRole("checkbox", { name: L(/^변경되면 검사/, /^Scan when it changes/) }).isChecked(), true,
          "a new integration scans what changed unless switched off");
        assert.equal(await page.getByRole("combobox", { name: L("전체 범위 검사 주기", "Full scope scan schedule"), exact: true }).inputValue(), "-2",
          "a new scope follows the installation's full-scan default");
        await page.getByRole("button", { name: L("예약 검사 켜기", "Enable scheduled scans"), exact: true }).click();
        await page.locator(".ig-section select").last().selectOption("15");
        await page.reload();
        await save.waitFor();
        assert.equal(await page.locator(".ig-section select").last().inputValue(), "15", "review schedule survives a reload");
        await save.click();
        await page.getByText(L("부분 수집", "Partial"), { exact: true }).waitFor();
        await page.getByText(L("다음 예약 실행 가능 시각", "Next scheduled eligibility"), { exact: false }).waitFor();
        await page.getByRole("button", { name: L("확인·계속", "Done · continue"), exact: true }).click();
        await page.waitForFunction(() => window.__closed);
        assert.deepEqual(run.errors, []);
        assert.equal(run.calls.filter(c => c.endpoint.endsWith("/complete")).length, 1);
      } finally { await run.context.close(); }
    }
    const generated = await visit(browser, 900, "en", "light", "generated");
    try {
      await generated.page.getByLabel("Token", { exact: true }).fill("synthetic-notion-token");
      await generated.page.getByRole("button", { name: "Create sign-in key", exact: true }).click();
      assert.equal(await generated.page.locator(".ig-feats").count(), 0);
      await generated.page.getByRole("button", { name: "Key registered · authenticate", exact: true }).click();
      await generated.page.locator(".ig-feats").waitFor();
      assert.equal(generated.calls.filter(c => c.endpoint === "onboarding-sessions").length, 1);
      assert.deepEqual(generated.errors, []);
    } finally { await generated.context.close(); }
    const editing = await visit(browser, 900, "en", "light", "edit");
    try {
      await editing.page.locator(".ig-feat-card").first().waitFor();
      assert.equal(await editing.page.locator(".ig-feat-card").first().getAttribute("aria-checked"), "true");
      assert.equal(await editing.page.getByRole("button", { name: "Back", exact: true }).count(), 0, "saved authentication has no editable previous step");
      await editing.page.getByRole("button", { name: "List targets", exact: true }).click();
      await editing.page.getByRole("button", { name: "Check access and continue", exact: true }).waitFor();
      assert.equal(await editing.page.getByLabel("Schedule (optional)", { exact: true }).count(), 0, "execution settings belong to review");
      assert.deepEqual(await editing.page.locator("h3").allTextContents(), ["Collection options"], "only actual options get a heading; no empty or repeated feature titles");
      assert.equal(await editing.page.getByRole("checkbox", { name: "Audit records", exact: true }).getAttribute("aria-checked"), "true");
      assert.equal(await editing.page.getByRole("checkbox", { name: "Previous versions", exact: true }).getAttribute("aria-checked"), "true", "a field offered by the second selected root remains available");
      await editing.page.getByRole("button", { name: "Storage accounts (optional)", exact: true }).click();
      const accounts = editing.page.getByRole("menu").last();
      assert.equal(await accounts.getByRole("menuitemcheckbox", { name: "storage-a", exact: true }).count(), 1);
      assert.equal(await accounts.getByRole("menuitemcheckbox", { name: "storage-b", exact: true }).count(), 1, "list options are the union of both subscriptions, without saved-only fallbacks");
      await editing.page.keyboard.press("Escape");
      await editing.page.reload();
      await editing.page.getByRole("button", { name: "Check access and continue", exact: true }).waitFor();
      assert.equal(await editing.page.getByLabel("Schedule (optional)", { exact: true }).count(), 0);
      assert.equal(await editing.page.getByRole("checkbox", { name: "Audit records", exact: true }).getAttribute("aria-checked"), "true");
      assert.equal(await editing.page.getByRole("checkbox", { name: "Previous versions", exact: true }).getAttribute("aria-checked"), "true");
      await editing.page.getByRole("button", { name: "Check access and continue", exact: true }).click();
      const review = editing.page.getByRole("button", { name: "Review selection", exact: true });
      await editing.page.getByRole("button", { name: "1 loaded resources", exact: true }).waitFor();
      await editing.page.reload();
      await review.click();
      assert.equal(await editing.page.locator(".ig-section select").last().inputValue(), "-1", "existing schedules stay unchanged by default");
      await editing.page.getByRole("button", { name: "Save integration", exact: true }).click();
      await editing.page.getByRole("button", { name: "Done · continue", exact: true }).click();
      await editing.page.waitForFunction(() => window.__closed);
      assert.equal(editing.calls.filter(c => c.endpoint === "onboarding-sessions").length, 0, "reuse the credential owner");
      assert.deepEqual(editing.errors, []);
    } finally { await editing.context.close(); }
    const refreshing = await visit(browser, 900, "en", "light", "edit");
    try {
      await refreshing.page.getByRole("button", { name: "List targets", exact: true }).click();
      await refreshing.page.getByRole("button", { name: "Check access and continue", exact: true }).click();
      await refreshing.page.getByRole("button", { name: "1 loaded resources", exact: true }).waitFor();
      await refreshing.page.getByRole("button", { name: "Review selection", exact: true }).click();
      await refreshing.page.getByLabel("Integration name", { exact: true }).fill("Unsaved integration name");
      await refreshing.page.evaluate(() => window.__redraw());
      await frames(refreshing.page);
      assert.equal(await refreshing.page.getByLabel("Integration name", { exact: true }).inputValue(), "Unsaved integration name", "background catalog/connection refresh preserves unsaved input");
      assert.deepEqual(refreshing.errors, []);
    } finally { await refreshing.context.close(); }
    const oauth = await visit(browser, 900, "en", "light", "oauth");
    try {
      await oauth.page.getByLabel("Token", { exact: true }).fill("synthetic-notion-token");
      const authenticate = oauth.page.getByRole("button", { name: "Authenticate", exact: true });
      await oauth.page.getByText("Set up the Google sign-in app", { exact: true }).waitFor();
      assert.equal(await authenticate.isDisabled(), true, "no draft or OAuth redirect before the app is configured");
      assert.equal(oauth.calls.some(c => c.endpoint === "onboarding-sessions"), false);
      await oauth.page.getByLabel("Client ID", { exact: true }).fill("synthetic.apps.googleusercontent.com");
      await oauth.page.getByLabel("Client secret", { exact: true }).fill("synthetic-client-secret");
      await oauth.page.getByRole("button", { name: "Save", exact: true }).click();
      await oauth.page.getByText("The Google sign-in app is ready.", { exact: false }).waitFor();
      assert.equal(await oauth.page.getByLabel("Client secret", { exact: true }).count(), 0, "the client secret form is unmounted after saving");
      const start = () => oauth.page.waitForResponse(response => response.url().endsWith("/v2/gcp/oauth/start"));
      await Promise.all([start(), authenticate.click()]);
      await Promise.all([start(), authenticate.click()]);
      await oauth.page.reload();
      await oauth.page.getByText("Other sign-in and existing setup", { exact: true }).waitFor();
      await Promise.all([start(), authenticate.click()]);
      assert.equal(oauth.calls.filter(c => c.endpoint === "onboarding-sessions").length, 1);
      assert.equal(oauth.calls.filter(c => c.endpoint.endsWith("/authenticate")).length, 0);
      assert.equal(oauth.calls.filter(c => c.endpoint === "v2/gcp/oauth/start").length, 3);
      assert.deepEqual(oauth.errors, []);
    } finally { await oauth.context.close(); }
    const locked = await visit(browser, 390, "ko", "dark", "oauth-locked");
    try {
      await locked.page.getByText("서버에 고정된 Google 로그인 앱 설정이 올바르지 않습니다.", { exact: false }).waitFor();
      assert.equal(await locked.page.getByRole("button", { name: "인증 확인", exact: true }).isDisabled(), true);
      assert.equal(await locked.page.getByLabel("클라이언트 시크릿", { exact: true }).count(), 0, "pinned configuration cannot be overwritten");
      assert.deepEqual(locked.errors, []);
    } finally { await locked.context.close(); }
    const remediate = await visit(browser, 900, "en", "light", "remediator");
    try {
      await remediate.page.getByLabel("Token", { exact: true }).fill("synthetic-notion-token");
      await Promise.all([remediate.page.waitForResponse(r => r.url().endsWith("onboarding-sessions")),
        remediate.page.getByRole("button", { name: "Authenticate", exact: true }).click()]);
      assert.equal(remediate.calls.find(c => c.endpoint === "onboarding-sessions").body.credential_purpose, "remediator");
      assert.deepEqual(remediate.errors, []);
    } finally { await remediate.context.close(); }
    const github = await visit(browser, 900, "ko", "light", "github");
    try {
      const page = github.page;
      const mode = page.getByRole("radio", { name: "새 App 자동 설정", exact: true });
      const manual = page.getByRole("radio", { name: "이미 만든 App 정보 입력", exact: true });
      const start = page.locator("#ig-app-start");
      await mode.waitFor();
      assert.equal(await page.getByRole("radiogroup", { name: "연결 방식", exact: true }).count(), 1);
      assert.deepEqual([await mode.getAttribute("aria-checked"), await manual.getAttribute("aria-checked")], ["true", "false"]);
      assert.equal(await start.isDisabled(), true);
      assert.equal(await start.getAttribute("aria-describedby"), "ig-app-start-reason");
      assert.equal(await page.locator("#ig-app-start-reason").innerText(), "조직을 먼저 입력하세요.", "the disabled start says why, next to it");
      // The start sits right under the organization field.
      const [field, button] = [await page.getByLabel("조직", { exact: true }).boundingBox(), await start.boundingBox()];
      assert.ok(button.y > field.y && button.y - (field.y + field.height) < 60, "the start button follows the organization field");
      await mode.click();
      assert.equal(github.calls.some(c => c.endpoint === "github/app-manifest/start"), false, "mode selector never navigates");
      // Arrow keys move the choice and focus as a radio group does; the existing-App fields replace the start.
      await mode.focus(); await page.keyboard.press("ArrowRight");
      assert.deepEqual([await mode.getAttribute("aria-checked"), await manual.getAttribute("aria-checked")], ["false", "true"]);
      assert.equal(await manual.evaluate(el => document.activeElement === el), true);
      assert.equal(await start.count(), 0);
      await page.keyboard.press("ArrowLeft");
      assert.equal(await mode.getAttribute("aria-checked"), "true");
      await page.getByLabel("조직", { exact: true }).fill("acme");
      assert.equal(await start.isEnabled(), true);
      assert.equal(await page.locator("#ig-app-start-reason").count(), 0);
      assert.equal(await page.locator(".modal-foot .primary-btn").innerText(), "GitHub에서 App 만들기·설치", "the footer keeps the same action");
      await page.locator(".modal").evaluate(el => { el.scrollTop = el.scrollHeight; });
      await Promise.all([page.waitForResponse(r => r.url().endsWith("github/app-manifest/start")), start.click()]);
      const banner = page.getByRole("alert").filter({ hasText: "GitHub에 연결하지 못했습니다. 잠시 뒤 다시 시도하세요." });
      await banner.waitFor();
      assert.equal(await banner.evaluate(el => { const r = el.getBoundingClientRect(), m = el.closest(".modal").getBoundingClientRect();
        return r.top >= m.top && r.bottom <= m.bottom; }), true, "the start's failure is scrolled into view");
      assert.equal(github.calls.filter(c => c.endpoint === "github/app-manifest/start").length, 1, "the inline start calls start exactly once");
      assert.deepEqual(github.errors, []);
    } finally { await github.context.close(); }
    // A content-scan card on a new account: sign in, then access check, scope and review; no feature step at all.
    const content = await visit(browser, 768, "ko", "dark", "content");
    try {
      const page = content.page;
      const current = () => page.locator('.ig-steps [aria-current="step"]').innerText();
      assert.deepEqual(await page.locator(".ig-steps li").allInnerTexts(), ["1\n인증", "2\n권한 확인", "3\n검사 범위", "4\n최종 확인"]);
      await page.getByRole("heading", { name: "기능별 필요한 권한", exact: true }).waitFor();
      await page.getByLabel("토큰", { exact: true }).fill("synthetic-notion-token");
      await page.getByRole("button", { name: "인증 확인", exact: true }).click();
      const check = page.getByRole("button", { name: "권한 확인·다음", exact: true });
      const retry = page.getByRole("button", { name: "대상 다시 불러오기", exact: true });
      await retry.waitFor();
      await page.getByRole("alert").filter({ hasText: "서버가 요청을 처리하지 못했습니다." }).waitFor();
      // The sign-in's warning is where the wizard landed (the listing step), not only behind Back.
      assert.match(await current(), /2.*권한 확인/s);
      await page.getByText("이 classic PAT로는 조직 목록(GET /user/orgs)을 읽을 수 없습니다.", { exact: false }).waitFor();
      await frames(page); await page.waitForTimeout(500);
      assert.equal(content.calls.filter(c => c.endpoint.endsWith("/discover")).length, 1, "a failed automatic listing is not repeated by itself");
      await retry.click();
      await check.waitFor();
      assert.match(await current(), /2.*권한 확인/s);
      assert.equal(await page.locator(".ig-feat-card, .ig-feats").count(), 0, "a content card never asks which feature to use");
      assert.deepEqual(content.calls.filter(c => c.endpoint.endsWith("/discover")).map(c => c.body.purposes), [["exposure"], ["exposure"]]);
      // Back from the access check returns to sign-in; the confirmed sign-in goes straight back without listing again.
      await page.getByRole("button", { name: "이전", exact: true }).click();
      await page.getByRole("button", { name: "인증 확인", exact: true }).click();
      await check.waitFor();
      assert.equal(content.calls.filter(c => c.endpoint.endsWith("/discover")).length, 2);
      await check.click();
      const select = page.getByRole("button", { name: "조회된 검사 대상 1개", exact: true });
      await select.waitFor();
      assert.match(await current(), /3.*검사 범위/s);
      await select.click(); await page.getByRole("menuitemcheckbox", { name: "Shared page", exact: true }).click(); await page.keyboard.press("Escape");
      await page.getByRole("button", { name: "선택 검토", exact: true }).click();
      const schedulesOn = page.getByRole("button", { name: "예약 검사 켜기", exact: true });
      await schedulesOn.waitFor();
      assert.match(await current(), /4.*최종 확인/s);
      await schedulesOn.click();
      await page.locator(".ig-section select").last().selectOption("15");
      await page.getByRole("button", { name: "연동 저장·수집 시작", exact: true }).click();
      await page.getByRole("button", { name: "확인·계속", exact: true }).waitFor();
      assert.equal(content.calls.filter(c => c.endpoint.endsWith("/complete")).length, 1);
      assert.equal(await page.locator(".modal").evaluate(el => el.scrollWidth <= el.clientWidth), true);
      assert.deepEqual(content.errors, []);
    } finally { await content.context.close(); }
    // The same card on an account that already collects its inventory: the inventory is kept, only the scan is gated.
    const kept = await visit(browser, 1440, "en", "light", "content-edit");
    try {
      const page = kept.page;
      const check = page.getByRole("button", { name: "Check access and continue", exact: true });
      await check.waitFor();
      assert.deepEqual(kept.calls.filter(c => c.endpoint.endsWith("/discover")).map(c => c.body.purposes), [["inventory", "exposure"]]);
      assert.equal(await page.locator(".ig-feat-card").count(), 0);
      assert.equal(await page.getByText("Issuance inventory · Kept", { exact: true }).count(), 1);
      assert.equal(await page.getByRole("button", { name: "Back", exact: true }).count(), 0, "the saved sign-in has no step to go back to");
      assert.equal(await page.getByText("Audit records", { exact: true }).count(), 0, "a kept feature's options stay on the account card");
      await page.getByRole("button", { name: "Scan targets", exact: true }).click();
      const menu = page.getByRole("menu").last();
      assert.deepEqual(await menu.getByRole("menuitemcheckbox").allInnerTexts(), ["Workspace"], "only places the scan reads are offered");
      await menu.getByRole("menuitemcheckbox", { name: "Workspace", exact: true }).click(); await page.keyboard.press("Escape");
      await check.click();
      // The kept inventory is checked too and passes; the scan's own access is what this card chose.
      const select = page.getByRole("button", { name: "1 loaded resources", exact: true });
      await select.waitFor();
      await select.click(); await page.getByRole("menuitemcheckbox", { name: "Shared page", exact: true }).click(); await page.keyboard.press("Escape");
      await page.getByRole("button", { name: "Review selection", exact: true }).click();
      const save = page.getByRole("button", { name: "Save integration", exact: true });
      await save.waitFor();
      assert.equal(await page.getByText("Issuance inventory · Kept", { exact: true }).count(), 1);
      await save.click();
      await page.getByRole("button", { name: "Done · continue", exact: true }).waitFor();
      assert.deepEqual(kept.errors, []);
    } finally { await kept.context.close(); }
    // GitHub-like shared targets: one the kept inventory collects from cannot be dropped, here or by "passing targets only".
    const plain = await visit(browser, 768, "en", "light", "content-plain");
    try {
      const page = plain.page;
      const check = page.getByRole("button", { name: "Check access and continue", exact: true });
      await check.waitFor();
      await page.getByRole("button", { name: "Scan targets", exact: true }).click();
      const menu = page.getByRole("menu").last();
      const orgA = menu.getByRole("menuitemcheckbox", { name: "Org A · Kept", exact: true });
      assert.equal(await orgA.getAttribute("aria-checked"), "true");
      await orgA.click();
      assert.equal(await orgA.getAttribute("aria-checked"), "true", "a target the kept inventory collects from stays");
      await menu.getByRole("menuitem", { name: "Clear all", exact: true }).click();
      assert.equal(await orgA.getAttribute("aria-checked"), "true", "clearing all keeps it too");
      await menu.getByRole("menuitemcheckbox", { name: "Org B", exact: true }).click(); await page.keyboard.press("Escape");
      await page.getByText("Targets marked ‘Kept’ stay: this account's other features collect from them.", { exact: false }).waitFor();
      await check.click();
      await page.getByRole("button", { name: "Check again after granting", exact: true }).waitFor();
      assert.equal(await page.locator("li").filter({ hasText: "Read shared pages · Org A · This read was denied." }).count(), 1);
      assert.equal(await page.getByRole("button", { name: "Continue with passing targets", exact: true }).count(), 0,
        "dropping Org A would stop the inventory that runs there");
      assert.deepEqual(plain.calls.filter(c => c.endpoint.endsWith("/inspect")).map(c => [c.body.target_ids, c.body.target_purposes]),
        [[["org-a", "org-b"], { "org-b": ["exposure"] }]], "Org B, added here, is scanned without widening the kept inventory to it");
      assert.deepEqual(plain.errors, []);
    } finally { await plain.context.close(); }
    // Org A, the inventory's only target, is not listed (a suspended installation): nothing to check until it is.
    const missing = await visit(browser, 768, "en", "light", "content-plain-missing");
    try {
      const page = missing.page;
      const check = page.getByRole("button", { name: "Check access and continue", exact: true });
      await check.waitFor();
      await page.getByRole("button", { name: "Scan targets", exact: true }).click();
      await page.getByRole("menu").last().getByRole("menuitemcheckbox", { name: "Org B", exact: true }).click(); await page.keyboard.press("Escape");
      await page.getByText("1 target this integration collects from is not in this listing, so this cannot continue", { exact: false }).waitFor();
      assert.equal(await check.isDisabled(), true, "completing would take the inventory's targets away");
      assert.deepEqual(missing.calls.filter(c => c.endpoint.endsWith("/inspect")), []);
      assert.deepEqual(missing.errors, []);
    } finally { await missing.context.close(); }
    // The kept inventory is refused on its account: no scope step, and what it lacks is named.
    const refusedKept = await visit(browser, 1440, "ko", "dark", "content-edit-refused");
    try {
      const page = refusedKept.page;
      const check = page.getByRole("button", { name: "권한 확인·다음", exact: true });
      await check.waitFor();
      await page.getByRole("button", { name: "검사 대상", exact: true }).click();
      await page.getByRole("menu").last().getByRole("menuitemcheckbox", { name: "Workspace", exact: true }).click(); await page.keyboard.press("Escape");
      await check.click();
      await page.getByText("발급 목록 수집 · 유지 · 권한 부족", { exact: true }).waitFor();
      assert.equal(await page.locator("li").filter({ hasText: "구성원 읽기 · Inventory account · 이 조회가 거절되었습니다." }).count(), 1);
      await page.getByText("이 계정에서 계속 수집하는 기능의 권한이 확인되지 않아 저장할 수 없습니다.", { exact: false }).waitFor();
      assert.equal(await page.getByText("평문 노출 검사 · 준비됨", { exact: true }).count(), 1);
      await frames(page);
      assert.match(await page.locator('.ig-steps [aria-current="step"]').innerText(), /2.*권한 확인/s, "no advance to an empty scope step");
      assert.equal(await page.getByRole("button", { name: /조회된 검사 대상/ }).count(), 0);
      assert.equal(await page.getByRole("button", { name: "권한 부여 후 다시 확인", exact: true }).count(), 1);
      assert.deepEqual(refusedKept.errors, []);
    } finally { await refusedKept.context.close(); }
    // A content card's GitHub App: no feature choice before the App is made, and the App asks for the scan's read access.
    const appContent = await visit(browser, 900, "en", "dark", "github-content");
    try {
      const page = appContent.page;
      await page.locator("#ig-app-start").waitFor();
      assert.equal(await page.locator(".ig-feats, .ig-feat-card, [role=checkbox]").count(), 0);
      assert.equal(await page.getByText("Choose App installation permissions", { exact: true }).count(), 0);
      await page.getByLabel("Organization", { exact: true }).fill("acme");
      await Promise.all([page.waitForResponse(r => r.url().endsWith("github/app-manifest/start")), page.locator("#ig-app-start").click()]);
      assert.deepEqual(appContent.calls.filter(c => c.endpoint === "github/app-manifest/start").map(c => c.body.installation_purposes), [["exposure"]]);
      assert.deepEqual(appContent.errors, []);
    } finally { await appContent.context.close(); }
    // The scan passes and the inventory is refused: continue with the scan only, and keep the inventory listed as held.
    const mixed = await visit(browser, 360, "en", "dark", "mixed");
    try {
      const page = mixed.page;
      await page.getByLabel("Token", { exact: true }).fill("synthetic-notion-token");
      await page.getByRole("button", { name: "Authenticate", exact: true }).click();
      await page.locator(".ig-feat-card").first().waitFor();
      // Each feature card says what it needs before targets are chosen.
      assert.equal(await page.locator(".ig-feats summary").count(), 2);
      for (const card of await page.locator(".ig-feat-card").all()) await card.click();
      await page.getByRole("button", { name: "List targets", exact: true }).click();
      await page.getByRole("button", { name: "Check access and continue", exact: true }).click();
      const ready = page.getByRole("button", { name: "Continue with ready features", exact: true });
      await ready.waitFor();
      assert.equal(await page.getByText("Plaintext exposure scan · Ready", { exact: true }).count(), 1);
      assert.equal(await page.getByText("Issuance inventory · Held · access missing", { exact: true }).count(), 1);
      assert.equal(await page.locator("li").filter({ hasText: "Read members · This read was denied." }).count(), 1);
      assert.equal(await page.getByRole("button", { name: "Check again after granting", exact: true }).count(), 1);
      assert.equal(await page.getByRole("button", { name: "Review selection", exact: true }).count(), 0);
      await ready.click();
      const select = page.getByRole("button", { name: "1 loaded resources", exact: true });
      await select.waitFor();
      const inspects = mixed.calls.filter(c => c.endpoint.endsWith("/inspect"));
      assert.deepEqual(inspects.map(c => Object.keys(c.body.plans).sort()), [["exposure", "inventory"], ["exposure"]]);
      await select.click(); await page.getByRole("menuitemcheckbox", { name: "Shared page", exact: true }).click(); await page.keyboard.press("Escape");
      await page.getByRole("button", { name: "Review selection", exact: true }).click();
      await page.getByRole("heading", { name: "Held features", exact: true }).waitFor();
      assert.equal(await page.locator("li").filter({ hasText: "Read members · This read was denied." }).count(), 1, "the review says what the held feature lacks");
      assert.match(await page.locator("dl.kv dd").first().innerText(), /^Plaintext exposure scan$/);
      await page.getByRole("button", { name: "Enable scheduled scans", exact: true }).click();
      await page.locator(".ig-section select").last().selectOption("15");
      await page.getByRole("button", { name: "Save integration and collect", exact: true }).click();
      await page.getByRole("button", { name: "Done · continue", exact: true }).waitFor();
      assert.equal(await page.getByRole("button", { name: "Add the held feature", exact: true }).count(), 1);
      assert.equal(await page.locator("li").filter({ hasText: "Read members · This read was denied." }).count(), 1);
      assert.equal(await page.locator(".modal").evaluate(el => el.scrollWidth <= el.clientWidth), true, "the held list fits 360px");
      assert.deepEqual(mixed.errors, []);
    } finally { await mixed.context.close(); }
  } finally { await browser.close(); }
  console.log("PASS auth-first: AWS role/runtime approval, rejection and refresh; auth, denied/retry, exact scope, refresh, generated key retry, existing edit/plan preservation, mixed-root fields/options, OAuth retry, overlay, keyboard, KO/EN, light/dark, 360px; content-only new and kept-account flows, permission preview, partial activation, GitHub start radio/inline start");
}
main().catch(error => { console.error(error); process.exitCode = 1; });
