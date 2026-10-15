// Synthetic proof of the console's search: "/" opens it on its text box, results come from the loaded credentials and
// the server search (asked once, for the text typing stopped at), arrows move through them, Escape closes it and hands
// focus back, a credential opens its panel, and below Admin an integration result is shown but not followed. Escape
// closes a panel opened from search (nothing has focus) or from a click on its row; in a text field beside the panel,
// or ending what an input method was composing, it is not the panel's. Light/dark, phone and desktop widths.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { openConsole, preview, settled, inBounds, assertClean, frames, openMenu } = require("./console-proof.cjs");

// As the server answers (cremore/api/search_service.py): every group, each saying whether this role may search it.
const NEEDS = { connection: "viewer", aws_account: "viewer", finding: "viewer", asset: "analyst", managed_object: "viewer" };
const RANK = ["viewer", "analyst", "remediator", "admin"];
const HITS = {
  connection: [{ kind: "connection", id: "p-aws", label: "AWS · production", provider: "aws", context: "Amazon Web Services" }],
  managed_object: [{ kind: "managed_object", id: "e-1", label: "deploy-bot key", provider: "aws", context: "IAM", detail: "credential" }],
};
const search = (role, query) => ({ query, limit: 8, role, groups: Object.entries(NEEDS).map(([kind, needs]) => RANK.indexOf(role) < RANK.indexOf(needs)
  ? { kind, requires_role: needs, permitted: false, searched: false, reason: "ROLE_REQUIRED", total: 0, items: [] }
  : { kind, requires_role: needs, permitted: true, searched: true, reason: "", total: (HITS[kind] ?? []).length, items: HITS[kind] ?? [] }) });

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  const answers = preview();
  // The exposed AWS key whose panel the fixture holds.
  const key = answers["credential-records"].items.find(item => answers[`credentials/${item.credential_id}/usage`]);
  try {
    for (const role of ["Admin", "Viewer"]) for (const theme of ["light", "dark"]) for (const width of [390, 1280]) {
      const label = `${role}-${theme}-${width}`;
      const session = { ...answers.session, role };
      const searches = [];
      const { context, page, record } = await openConsole(browser, { width, theme, view: "dashboard", answer: ({ method, endpoint }) => {
        if (method !== "GET") return undefined;
        if (endpoint === "session") return session;
        if (endpoint.startsWith("search?")) {
          searches.push(endpoint);
          return search(role.toLowerCase(), new URLSearchParams(endpoint.split("?")[1]).get("q"));
        }
        return answers[endpoint];
      } });
      try {
        await settled(page, record, label);
        // "/" anywhere outside a text box opens the search on its text box.
        await page.locator("main").focus();
        await page.keyboard.press("/");
        const box = page.locator(".menu .menu-search input");
        await box.waitFor();
        assert.equal(await box.evaluate(el => el === document.activeElement), true, `${label}: the text box takes focus`);
        // Typed with the page's clock held and moved on by hand, so a slow machine cannot stretch the gap between keys:
        // keys 100 ms apart send nothing, and the text typing stopped at is searched once the wait after it has passed.
        await page.clock.pauseAt(await page.evaluate(() => Date.now()) + 1_000);
        for (const letter of "aws") {
          await box.press(letter);
          await frames(page);
          await page.clock.runFor(100);
        }
        await page.clock.runFor(300);
        await page.clock.resume();
        await page.locator(".menu .menu-item", { hasText: "AWS · production" }).waitFor();
        await settled(page, record, label);
        assert.deepEqual(searches, ["search?q=aws&limit=8"], `${label}: one server search`);
        const items = page.locator(".menu .menu-item");
        assert.ok(await items.count() >= 3, `${label}: credential and server results`);
        await inBounds(page, `${label} results`);
        const menu = await page.locator(".menu").boundingBox();
        assert.ok(menu.x >= 0 && menu.x + menu.width <= width + 1, `${label}: the results stay on screen ${JSON.stringify(menu)}`);
        // Arrows move through the results that can be followed, wrapping at the ends.
        await page.keyboard.press("ArrowDown");
        const first = await page.evaluate(() => document.activeElement.textContent);
        await page.keyboard.press("ArrowUp");
        const last = await page.evaluate(() => document.activeElement.textContent);
        assert.notEqual(first, last, `${label}: arrows move`);
        const integration = page.locator(".menu .menu-item", { hasText: "AWS · production" });
        assert.equal(await integration.getAttribute("aria-disabled"), role === "Admin" ? null : "true", `${label}: integration result for ${role}`);
        // Escape closes it and hands focus back to the search button.
        await page.keyboard.press("Escape");
        await page.locator(".menu").waitFor({ state: "detached" });
        assert.equal(await page.evaluate(() => document.activeElement.id), "global-search-button", `${label}: focus back`);
        // A credential result opens that credential's panel; nothing has focus then, and Escape closes the panel.
        await openMenu(page, page.locator("#global-search-button"));
        await page.locator(".menu .menu-search input").fill(key.hint);
        const credential = page.locator(".menu .menu-item").filter({ hasText: key.hint }).first();
        await credential.waitFor();
        await credential.click();
        const drawer = page.locator(".drawer");
        await drawer.waitFor();
        await settled(page, record, label);
        assert.match(await page.evaluate(() => location.search), /[?&]view=exposed&id=credential%3A/, `${label}: the panel's route`);
        assert.equal(await drawer.evaluate(el => el === document.activeElement), true, `${label}: the panel takes focus, so Tab starts in it`);
        // An Escape that ends what an input method was composing (Korean being typed) is the input method's.
        await page.evaluate(() => document.activeElement.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", isComposing: true, bubbles: true, cancelable: true })));
        await frames(page);
        assert.equal(await drawer.count(), 1, `${label}: an Escape ending a composition leaves the panel`);
        await page.keyboard.press("Escape");
        await drawer.waitFor({ state: "detached" });
        assert.doesNotMatch(await page.evaluate(() => location.search), /[?&]id=/, `${label}: the panel's route is left`);
        // Opened by a click on its row, focus stays on the row: Escape closes the panel as well.
        const row = page.locator("tbody tr").filter({ hasText: key.hint }).first();
        await row.click();
        await drawer.waitFor();
        await settled(page, record, label);
        assert.equal(await row.evaluate(el => el === document.activeElement), true, `${label}: focus on the row`);
        await page.keyboard.press("Escape");
        await drawer.waitFor({ state: "detached" });
        // Escape in the list's search box beside the panel is the box's: the panel stays.
        await row.click();
        await drawer.waitFor();
        await settled(page, record, label);
        await page.locator("#cred-search").focus();
        await page.keyboard.press("Escape");
        await frames(page);
        assert.equal(await drawer.count(), 1, `${label}: Escape in a text field leaves the panel`);
        await drawer.getByRole("button", { name: "상세 닫기", exact: true }).click();
        await drawer.waitFor({ state: "detached" });
        // Below Admin an integration result is not followed.
        if (role !== "Admin") {
          await openMenu(page, page.locator("#global-search-button"));
          await page.locator(".menu .menu-search input").fill("aws");
          // Pressed anyway (it is marked unavailable): nothing follows.
          await page.locator(".menu .menu-item", { hasText: "AWS · production" }).click({ force: true });
          assert.equal(await page.locator(".menu").count(), 1, `${label}: an integration result stays put for ${role}`);
        }
        assertClean(record, label);
        assert.deepEqual(record.writes, [], `${label}: a write`);
      } finally { await context.close(); }
    }
    console.log("PASS console search: '/' opens on the text box, one server search for the text typing stopped at, arrows, Escape hands focus back, a credential opens its panel; Escape closes a panel opened from search or its row and leaves it for a text field; integrations not followed below Admin; light/dark at 390 and 1280; no write or outside request.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
