/* What the console's browser proofs share: the real console (web/console/app.tsx), its own stylesheet and fonts in
 * headless Chrome, served from a synthetic origin. Every API request is answered by the proof and recorded; a request to
 * any other origin is refused and listed. Empty screen responses and the two credential rows needed by the shared
 * panel/list proofs are constructed below. Each proof supplies its own additional inputs. Nothing is captured from a
 * running installation or saved as a data file. The fixed clock makes date assertions independent of the run date.
 */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { bundle } = require("./bundle-module.cjs");
const { themeInitScript, themeStorageKey } = require("./load-theme.cjs");

const ORIGIN = "http://console.synthetic.test";
// An answer that never arrives: the request is cut, as a response lost on the way back.
const LOST = Symbol("lost");
const WEB = path.join(__dirname, "..");
let bundled = null;
const consoleApp = () => bundled ||= bundle({ React: "react", client: "react-dom/client", app: "@/console/app.tsx" });
// The console's stylesheet with Pretendard as its layout loads it (app/(console)/layout.tsx), so text is measured in
// the face it is read in.
const consoleStyles = () => [["Regular", 400], ["Medium", 500], ["SemiBold", 600]]
  .map(([name, weight]) => `@font-face{font-family:"Pretendard";src:url(/fonts/Pretendard-${name}.subset.woff2) format("woff2");font-weight:${weight};font-style:normal;font-display:block}`)
  .join("") + ':root{--font-pretendard:"Pretendard"}' + fs.readFileSync(path.join(WEB, "app/(console)/console.css"), "utf8");

const capturedAt = () => "2026-10-01T12:00:00Z";
/** Explicit empty API responses. Unknown paths still fail the proof instead of silently receiving an empty object. */
function preview() {
  const at = capturedAt(), page = () => ({ items: [], total: 0, offset: 0, limit: 200 });
  const credential = "5db0c402-9087-42c0-9039-69bf34e32663", finding = "ee434166-6c89-4a00-84ea-516ad89b77df";
  const exposure = { source_type: "s3", resource_name: "test-bucket", location: "exports/2026-09/app.env.bak", line: 1,
    snippet: "[redacted]", visibility: "private", current: true, first_seen_at: at, last_seen_at: at };
  // Two different types are required by the list filter and two exposed credentials by the late-answer proof.
  const first = { id: `credential:${credential}`, credential_id: credential, finding_id: finding, provider: "aws",
    credential_type: "AWS_ACCESS_KEY", category: "apikey", kind: "cloud", name: "test AWS key", hint: "AWS masked A",
    exposed: true, status: "pending", workflow_status: "OPEN", risk: "low", verification: { state: "active", basis: "ISSUER_REPORTED", at },
    exposures: [exposure], exposure_count: 1, location_count: 1, first_seen_at: at, last_seen_at: at, expiry: "unknown",
    vault: { state: "unknown", where: [], basis: "UNKNOWN", reasons: [] }, tags: [], steps: {}, annotations_revision: 0 };
  const second = { ...first, id: "credential:test-b", credential_id: "test-b", finding_id: "test-finding-b", provider: "github",
    credential_type: "GITHUB_TOKEN", category: "token", kind: "token", name: "test token", hint: "GitHub masked B" };
  const summary = { exposed: 2, matched: 0, no_vault_match: 0, unknown: 2, issuance_only: 0, vault_only: 0, managed: 0,
    issued: 0, issued_in_vault: 0, issued_not_in_vault: 0, issued_unknown: 0, matched_percent: null, complete: true };
  const tickets = { mode: "REAL", data: { items: [], next_offset: null } };
  return {
    session: { id: "00000000-0000-0000-0000-000000000001", name: "test operator", role: "Admin", auth_mode: "local" },
    "credential-records": { items: [first, second], total: 2, complete: true, coverage: summary, scope_confirmed: false, scope_reasons: [], generated_at: at },
    "provider-connections": [], "provider-connections/catalog": { purposes: [], providers: [] }, "provider-connections/suggestions": { items: [] },
    "operations/connections": { items: [], generated_at: at, summary: { total: 0 } },
    "operations/status": { worker: { alive: 0, observed: 0, last_beat_at: null, queue_delay_seconds: null, queued_jobs: 0,
      running_jobs: 0, heartbeat_interval_minutes: 5, instances: [] }, alerts: [] },
    "siem/status": { destinations: [], exporter_active: false },
    "detection-engine": { name: "test", detectors: [], collection_sources: [], network_verification: false, scan_policy: {} },
    rules: [], "scan-runs": [], "people?limit=500": page(),
    "people?q=&limit=1": { ...page(), next_cursor: null, directory: { status: "NOT_CONFIGURED", usable: false, sources: [] } },
    "coverage?limit=1": { ...page(), summary, scope_confirmed: false, scope_reasons: [], connections: [], root_status: [] },
    "coverage/storage-receipts?offset=0&limit=20": page(),
    "audit?limit=1000": [], "audit/integrity": { state: "NOT_STARTED", legacy_rows: 0, pending: 0, problem_count: 0, open_problems: 0,
      problems: [], anchors: { count: 0, last: null }, unauthenticated: { sealed_count: 0, pending_count: 0 } },
    "leavers/summary": { people: 0, departed: 0, departed_with_credentials: 0, orphans: 0, by_verdict: {}, candidates: 0, sources: [] },
    "leavers/orphans?limit=200": { ...page(), facets: { verdict: [], provider: [] } }, "leavers/people?limit=200": page(), "leavers/candidates": page(),
    "action-plans": { items: [], policy: {} }, "management-actions?limit=100": [], "rotation-automation/jobs?limit=100": [], "rotation-automation/profiles": [],
    tickets, "tickets?offset=0": tickets, "ticket-system": { system: null, label: null }, "secret-managers": { mode: "REAL", items: [] },
    "contact-delivery": { mail: false, slack: false, allowed_domains: [], allowed_channels: [] }, domains: { domains: [], limit: 10 },
    "response-channels": { channels: [] },
    "settings/sign-in": { mode: "local", issuer: "", audience: "", groups_claim: "groups", groups: {} },
    "settings/machine-identity": { configured: false, revision: 0, idp: null, aws: null, gcp: null, azure: null, vault: null, processes: [] },
    "settings/notion-webhooks": { profiles: [], bindings: [] },
    // An installation that never saved its scan triggers, as the API answers (trigger_settings.config): daily full
    // scans at 02:00 KST and change feeds on, customer queues off.
    "settings/scan-triggers": { schedules: { enabled: true, switch: true, installation_allows: true, full_scan_default_minutes: 1440,
      full_scan_start_minute: 1020 }, change_feeds: { enabled: true, switch: true, installation_allows: true,
      minutes: { github: 5, gitlab: 5, azure_devops: 5, bitbucket: 15, confluence: 5, notion: 5 } },
      ...Object.fromEntries([["sqs", "queue_url"], ["pubsub", "subscription"], ["servicebus", "queue"]].map(([kind, address]) => [kind, {
        enabled: false, switch: false, installation_allows: true, profile_id: "", profile_id_locked: false, [address]: "",
        [`${address}_locked`]: false, dedicated_acknowledged: false, dedicated_acknowledged_locked: false, blocked_by: null }])),
      updated_by: null, updated_at: null },
    [`findings/${finding}`]: { id: finding, workflow_status: "OPEN", primary_exposure_id: "6dd89d2b-1169-4f97-b424-54230da1d306",
      credential: {}, exposures: [{ ...exposure, id: "6dd89d2b-1169-4f97-b424-54230da1d306", status: "OPEN", line_number: 1 }], events: [] },
    [`findings/${finding}/context`]: { status: "NOT_COLLECTED", locations: [], repositories: [], reasons: [] },
    [`findings/${finding}/ownership-review`]: { finding_id: finding, review: { status: "OPEN", revision: 0 },
      context: { status: "NOT_COLLECTED", candidates: [], basis: "CODEOWNERS_DECLARATION", file_match: false } },
    [`findings/${finding}/response`]: { state: "NEW", version: 0, current: null, history: [] },
    [`findings/${finding}/response/routing`]: { version: 0, status: "UNASSIGNED", manual_email_allowed: true, assignment: null, recommendations: [], targets: [] },
    [`v2/coverage/findings/${finding}`]: { ...page(), evidence: "NONE", provider: "aws", object_kind: "access_key" },
    [`credentials/${credential}/usage`]: { collection_status: "NOT_COLLECTED", events: [], coverage: [], scenarios: [] },
    [`credentials/${credential}/management`]: { credential_id: credential, status: "UNKNOWN", match_status: "UNKNOWN", revision: 0, can_read_metadata: false },
    [`credentials/${credential}/action-plans`]: { plans: [], policy: {} },
    [`tickets?credential_id=${credential}&offset=0`]: tickets,
  };
}

const RESPONSE = Symbol("response");
/** An answer with its own status (a plain body is answered 200). */
const respond = (status, body, headers = {}) => ({ [RESPONSE]: true, status, body, headers });
/** A refusal as the API words one: the reason both as `detail` and as `error`, "CODE: sentence". */
const refusal = (status, reason) => respond(status, { detail: reason, error: reason });

/**
 * Open the console in a new browser context.
 *
 * `answer({ method, endpoint, body })` returns a body (answered 200), `respond(status, body)`, LOST for a response
 * lost on the way back, or undefined: an unknown GET is answered 404 and listed in `record.unknown`, any other unknown
 * request 409 and listed in `record.refused`. A saved theme is set against the opposite operating-system theme, so it
 * is the saved one that has to win. `now` is where the browser's clock starts; it runs on from there.
 */
async function openConsole(browser, { width = 1440, height = 900, locale = "ko", theme = "light", view = "dashboard", query = "", now = capturedAt(), answer }) {
  const context = await browser.newContext({ viewport: { width, height }, colorScheme: theme === "dark" ? "light" : "dark" });
  const record = { calls: [], writes: [], unknown: [], refused: [], external: [], errors: [], pending: 0 };
  const app = consoleApp();
  // The browser's own frame callback, kept before the clock replaces it with a timer: waiting for a painted frame
  // waits for the browser to render, not for 16 ms to pass.
  await context.addInitScript(() => { window.__frame = window.requestAnimationFrame.bind(window); });
  await context.clock.install({ time: now });
  await context.addInitScript(({ locale, theme, key, data }) => {
    try { localStorage.setItem("cremore.locale", locale); localStorage.setItem(key, theme); } catch { /* the page still renders */ }
    window.__fixture = data;
  }, { locale, theme, key: themeStorageKey, data: app.data });
  // In flight from the moment the page sends a request until its answer has arrived or failed.
  const ours = request => new URL(request.url()).origin === ORIGIN;
  context.on("request", request => { if (ours(request)) record.pending++; });
  for (const event of ["requestfinished", "requestfailed"]) context.on(event, request => { if (ours(request)) record.pending--; });
  const html = `<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">`
    + `<script>${themeInitScript}</script><style>${consoleStyles()}</style></head><body><div id="root"></div>`
    + `<script>${app.preamble}client.createRoot(document.getElementById("root")).render(React.createElement(app.ConsoleApp));</script></body></html>`;
  await context.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== ORIGIN) { record.external.push(url.href); return await route.abort(); }
    if (url.pathname === "/") return await route.fulfill({ contentType: "text/html; charset=utf-8", body: html });
    const asset = url.pathname.startsWith("/logos/") ? path.join(WEB, "public", url.pathname)
      : url.pathname.startsWith("/fonts/") ? path.join(WEB, "app/(console)", url.pathname) : null;
    if (asset) {
      if (fs.existsSync(asset)) return await route.fulfill({ path: asset });
      record.unknown.push(url.pathname);
      return await route.fulfill({ status: 404, body: "" });
    }
    if (!url.pathname.startsWith("/api/backend/")) { record.external.push(url.href); return await route.abort(); }
    const endpoint = url.pathname.slice("/api/backend/".length) + url.search, method = request.method();
    let body = request.postData() ?? undefined;
    try { body = body === undefined ? undefined : JSON.parse(body); } catch { /* kept as sent */ }
    record.calls.push({ method, endpoint, body });
    if (method !== "GET") record.writes.push({ method, endpoint, body });
    let reply;
    try { reply = await answer({ method, endpoint, body }); } catch (error) {
      record.errors.push(`the proof's answer to ${method} ${endpoint}: ${error.message}`);
      return await route.fulfill({ status: 500, contentType: "application/json", body: "{}" });
    }
    if (reply === LOST) return await route.abort("connectionreset");
    if (reply === undefined) {
      (method === "GET" ? record.unknown : record.refused).push(method === "GET" ? endpoint : `${method} ${endpoint}`);
      return await route.fulfill({ status: method === "GET" ? 404 : 409, contentType: "application/json",
        body: JSON.stringify({ error: method === "GET" ? "SYNTHETIC_FIXTURE_MISSING" : "SYNTHETIC_MUTATION_DISABLED" }) });
    }
    const framed = reply?.[RESPONSE] === true;
    return await route.fulfill({ status: framed ? reply.status : 200, contentType: "application/json", headers: framed ? reply.headers : {}, body: JSON.stringify(framed ? reply.body : reply) });
  });
  // A script error on any page of the context (a second tab too).
  context.on("weberror", error => record.errors.push(error.error().message));
  const page = await context.newPage();
  page.setDefaultTimeout(12_000);
  await page.goto(`${ORIGIN}/?view=${view}${query}`);
  return { context, page, record };
}

/** Wait until no request has been in flight and nothing has been loading for a while (a screen reads some things
 * after its first answers come), then for the fonts and two painted frames. Fails after 15 s, saying what is busy. */
async function settled(page, record, label = "") {
  const deadline = Date.now() + 15_000;
  for (let quiet = 0; quiet < 5;) {
    await page.waitForTimeout(80);
    const loading = await page.locator(".loading-line").count();
    quiet = record.pending > 0 || loading > 0 ? 0 : quiet + 1;
    if (!quiet && Date.now() > deadline) {
      const last = record.calls.slice(-4).map(call => `${call.method} ${call.endpoint}`);
      throw new Error(`${label || page.url()}: still busy after 15 s (${record.pending} requests in flight, ${loading} loading lines; last requests ${JSON.stringify(last)})`);
    }
  }
  const painted = page.evaluate(() => Promise.all([document.fonts.ready, new Promise(resolve => window.__frame(() => window.__frame(resolve)))]));
  let timer;
  const late = new Promise(resolve => { timer = setTimeout(resolve, 5_000, "late"); });
  try {
    if (await Promise.race([painted.then(() => "painted"), late]) === "late") throw new Error(`${label || page.url()}: no frame painted in 5 s`);
  } finally { clearTimeout(timer); painted.catch(() => {}); }
}

/** Nothing reaches past the viewport sideways, and every open panel or dialog sits inside it without scrolling sideways. */
async function inBounds(page, label) {
  const measured = await page.evaluate(() => {
    // The layout viewport, not innerWidth: a page that overflows widens innerWidth with it on a phone.
    const width = document.documentElement.clientWidth;
    const name = el => `${el.tagName.toLowerCase()}.${el.getAttribute("class") ?? ""}`;
    // What sticks out past `right` inside `root`, outside any region that scrolls or clips it.
    const sticking = (root, right) => [...root.querySelectorAll("*")].filter(el => {
      const r = el.getBoundingClientRect();
      if (!r.width || r.right <= right + 1) return false;
      for (let parent = el.parentElement; parent && parent !== root; parent = parent.parentElement) {
        if (/auto|scroll|hidden|clip/.test(getComputedStyle(parent).overflowX) || getComputedStyle(parent).position === "fixed") return false;
      }
      return true;
    }).slice(0, 6).map(name);
    return {
      width, height: innerHeight, document: document.documentElement.scrollWidth, wide: sticking(document.body, width),
      // The details panel is fixed beside the page, so the page's width never shows it overflowing: it is measured itself.
      layers: [...document.querySelectorAll(".drawer, [role=dialog]")].map(el => {
        const r = el.getBoundingClientRect();
        return { name: name(el), dialog: el.getAttribute("role") === "dialog", left: r.left, right: r.right, top: r.top, bottom: r.bottom,
          scroll: el.scrollWidth, client: el.clientWidth, wide: sticking(el, r.right) };
      }),
    };
  });
  assert.ok(measured.document <= measured.width + 1, `${label}: the page scrolls sideways ${JSON.stringify(measured)}`);
  for (const layer of measured.layers) {
    const inside = layer.left >= -1 && layer.right <= measured.width + 1 && layer.top >= -1 && (!layer.dialog || layer.bottom <= measured.height + 1);
    assert.ok(inside, `${label}: ${layer.name} leaves the viewport ${JSON.stringify(layer)}`);
    assert.ok(layer.scroll <= layer.client + 1, `${label}: ${layer.name} scrolls sideways ${JSON.stringify(layer)}`);
  }
}

/** Nothing went wrong behind the page: every request had an answer, every write was one the proof answers, nothing left
 * the page and no script failed. */
function assertClean(record, label) {
  assert.deepEqual(record.unknown, [], `${label}: a request with no synthetic answer`);
  assert.deepEqual(record.refused, [], `${label}: a write the proof does not answer`);
  assert.deepEqual(record.external, [], `${label}: a request off the page`);
  assert.deepEqual(record.errors, [], `${label}: a page error`);
}

/** Run a step; when it fails, keep a screenshot of the page (in the run's artifacts, or the temporary directory when a
 * proof runs alone) and name it in the error. */
async function withScreenshot(page, label, step) {
  try { return await step(); } catch (error) {
    const file = path.join(process.env.CREMORE_PROOF_ARTIFACTS || os.tmpdir(), `cremore-console-${label.replace(/[^\w.-]+/g, "_")}.png`);
    await page.screenshot({ path: file, fullPage: true }).then(() => { error.message += `\nscreenshot: ${file}`; }, () => {});
    throw error;
  }
}

/** Go to a screen the way the rail does (its link, or the route where the rail item is not on screen). */
async function show(page, record, view) {
  const link = page.locator(`.rail a[href="?view=${view}"]`);
  if (await link.isVisible()) {
    await link.click();
    // The rail opens under the pointer: move it off, as a reader's hand does, before anything near the left is used.
    const size = page.viewportSize();
    await page.mouse.move(size.width - 4, size.height - 4);
  } else await page.evaluate(next => { history.pushState(null, "", `?view=${next}`); dispatchEvent(new PopStateEvent("popstate")); }, view);
  await settled(page, record, view);
}

/** Two frames the browser painted: what a key, click or scroll changed is on screen and its events have fired. */
const frames = page => page.evaluate(() => new Promise(resolve => window.__frame(() => window.__frame(resolve))));

/** Open a menu from its control, with a click or from the keyboard. The control is scrolled into view first and the
 * page left to paint: a menu closes on a scroll around it, and the browser reports the scroll that brought the control
 * into view a frame later, after a click that came at once would have opened the menu. */
async function openMenu(page, control, { keyboard = false } = {}) {
  await control.scrollIntoViewIfNeeded();
  await frames(page);
  if (keyboard) {
    await control.focus();
    await frames(page);
    await page.keyboard.press("Enter");
  } else await control.click();
  await page.locator(".menu").waitFor();
}

module.exports = { ORIGIN, LOST, respond, refusal, openConsole, preview, capturedAt, settled, inBounds, assertClean, withScreenshot, show, frames, openMenu };
