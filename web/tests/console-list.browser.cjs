// Synthetic proof of the credential list's working tools: it pages by the reader's page size, a filter chip narrows it
// and its clear button hands focus back to the chip (from the keyboard), "Filters" clears every filter at once, and
// nothing sends a write. Light and dark at 360 and 1440.
"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { openConsole, preview, settled, inBounds, assertClean, openMenu } = require("./console-proof.cjs");

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  const answers = preview();
  const records = answers["credential-records"];
  // Sixty records from the two test types, under distinct ids/names, to exercise pagination and filtering.
  const items = Array.from({ length: 60 }, (_, index) => {
    const item = records.items[index % records.items.length];
    return { ...item, id: `${item.id.split(":")[0]}:synthetic-${String(index).padStart(3, "0")}`, name: `${item.name || "credential"} #${String(index + 1).padStart(2, "0")}` };
  });
  try {
    for (const theme of ["light", "dark"]) for (const width of [360, 1440]) {
      const label = `${theme}-${width}`;
      const { context, page, record } = await openConsole(browser, { width, theme, view: "inventory", answer: ({ method, endpoint }) => {
        if (method !== "GET") return undefined;
        if (endpoint === "credential-records") return { ...records, items };
        return answers[endpoint];
      } });
      try {
        await settled(page, record, label);
        const card = page.locator(".list-card");
        const range = () => card.locator(".pager .num").innerText();
        assert.match(await range(), /^1–50 \/ 60/, `${label}: the first page`);
        await card.getByRole("button", { name: "다음 페이지" }).click();
        await settled(page, record, label);
        assert.match(await range(), /^51–60 \/ 60/, `${label}: the next page`);
        assert.equal(await page.evaluate(() => new URLSearchParams(location.search).get("page")), "1", `${label}: the page in the address`);
        // A smaller page size starts from the first page again.
        await card.locator(".pager-size select").selectOption("25");
        await settled(page, record, label);
        assert.match(await range(), /^1–25 \/ 60/, `${label}: 25 a page`);
        await inBounds(page, `${label} list`);
        // A chip narrows the list (opened from the keyboard); its clear button, from the keyboard, hands focus back to it.
        const chip = name => card.locator(".chips-row .fchip").filter({ has: page.locator(".clip", { hasText: name }) });
        const narrow = async name => {
          await openMenu(page, chip(name).locator(".fchip-open"), { keyboard: true });
          await page.locator(".menu .menu-item").first().click();
          await page.keyboard.press("Escape");
          await settled(page, record, `${label} ${name}`);
        };
        await narrow("유형");
        const narrowed = await range();
        assert.doesNotMatch(narrowed, /\/ 60/, `${label}: narrowed (${narrowed})`);
        await chip("유형").locator(".x").focus();
        await page.keyboard.press("Enter");
        await settled(page, record, label);
        assert.match(await range(), /\/ 60/, `${label}: cleared`);
        assert.equal(await page.evaluate(() => document.activeElement?.closest(".fchip")?.textContent.includes("유형") && document.activeElement.classList.contains("fchip-open")),
          true, `${label}: focus back on the chip`);
        // Two filters, then "Filters" clears both.
        await narrow("유형");
        await narrow("활성 여부");
        assert.equal(await card.locator(".chips-row .fchip.on").count(), 2, `${label}: two filters`);
        await card.locator(".tool-btns .ghost-btn").filter({ has: page.locator(".filter-count") }).click();
        await settled(page, record, label);
        assert.equal(await card.locator(".chips-row .fchip.on").count(), 0, `${label}: every filter cleared`);
        assert.match(await range(), /\/ 60/, `${label}: the whole list again`);
        assertClean(record, label);
        assert.deepEqual(record.writes, [], `${label}: a write`);
      } finally { await context.close(); }
    }
    console.log("PASS console credential list: pages by the chosen size, a chip narrows and its clear button keeps focus on the chip, Filters clears all; light/dark at 360 and 1440; no write.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
