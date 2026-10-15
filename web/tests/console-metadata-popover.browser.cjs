"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { openConsole, preview, settled, assertClean, withScreenshot, frames, openMenu } = require("./console-proof.cjs");

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  const answers = preview();
  const names = ["AdministratorAccess", "Billing", "AWSBillingConductorFullAccess", "AWSBillingConductorReadOnlyAccess", "AWSBillingReadOnlyAccess"];
  const arn = "arn:aws:iam::123456789012:user/team/test-creator";
  const records = answers["credential-records"];
  records.items = [{ ...records.items[0], issued: { provider: "aws_iam", type: "access_key", current: true,
    creator: { arn, region: "us-east-1", current: true },
    iam_policies: { status: "COMPLETE", policy_names: names, allow_actions: [], truncated: false } } }];
  records.total = 1;
  answers["provider-connections/catalog"].providers = [{ provider: "aws", label: "AWS", label_ko: "AWS", editions: [], auth_methods: [],
    purposes: { inventory: { types: [{ id: "access_key", label: "Access key", label_ko: "액세스 키", support: "YNYNPPYYY", reasons: {} }] } } }];
  try {
    for (const locale of ["ko", "en"]) for (const theme of ["light", "dark"]) for (const width of [320, 1440]) {
      const label = `${locale}-${theme}-${width}`;
      const { context, page, record } = await openConsole(browser, { locale, theme, width, height: 700,
        view: "metadata", query: "&id=aws%3Aaccess_key&dtab=tokens",
        answer: ({ method, endpoint }) => method === "GET" ? answers[endpoint] : undefined });
      try {
        await withScreenshot(page, `metadata-popover-${label}`, async () => {
          await settled(page, record, label);
          // Reserve a real scrollbar gutter: innerWidth includes space the panel cannot occupy.
          await page.addStyleTag({ content: "html{overflow-y:scroll;scrollbar-gutter:stable}" });
          const card = page.locator(".md-tok");
          for (const [name, content] of [[locale === "ko" ? "IAM 정책 5개" : "5 IAM policies", names], ["test-creator", [arn, "CloudTrail"]]]) {
            const trigger = card.getByRole("button", { name, exact: true });
            await trigger.scrollIntoViewIfNeeded();
            await trigger.focus();
            await frames(page);
            const before = await card.boundingBox();
            await trigger.press("Enter");
            const popup = page.getByRole("dialog", { name, exact: true });
            await popup.waitFor({ state: "visible" });
            const anchor = await trigger.boundingBox(), panel = await popup.boundingBox();
            const drawerBox = await page.locator(".drawer").boundingBox();
            assert.ok(panel.x >= drawerBox.x + 8 && panel.x + panel.width <= drawerBox.x + drawerBox.width - 7, `${label}: popup leaves the detail panel`);
            assert.ok(Math.abs(panel.x - anchor.x) < 2, `${label}: popup must start at the trigger's left edge`);
            assert.ok(Math.abs(panel.y - (anchor.y + anchor.height + 6)) < 2, `${label}: popup must open directly below its trigger`);
            const after = await card.boundingBox();
            assert.equal(after.width, before.width, `${label}: opening resizes the card`);
            assert.equal(after.height, before.height, `${label}: opening expands the card`);
            for (const text of content) assert.ok((await popup.innerText()).includes(text), `${label}: missing ${text}`);
            const fits = await popup.evaluate(el => {
              const r = el.getBoundingClientRect(), d = document.documentElement;
              return r.left >= 8 && r.right <= d.clientWidth - 7 && r.top >= 8 && r.bottom <= d.clientHeight - 7 && el.scrollWidth <= el.clientWidth;
            });
            assert.ok(fits, `${label}: popup escapes the visible viewport`);
            await page.keyboard.press("Escape");
            await popup.waitFor({ state: "hidden" });
            assert.equal(await page.locator(".drawer").count(), 1, `${label}: Escape closed the drawer`);
            assert.ok(await trigger.evaluate(el => el === document.activeElement), `${label}: focus not restored`);
            await openMenu(page, trigger);
            await popup.waitFor({ state: "visible" });
            await page.locator(".drawer h2").click();
            await popup.waitFor({ state: "hidden" });
            await openMenu(page, trigger);
            await popup.waitFor({ state: "visible" });
            await popup.click();
            await popup.waitFor({ state: "visible" });
            await page.locator(".drawer").evaluate(el => { el.scrollTop += 12; });
            await frames(page);
            assert.equal(await trigger.getAttribute("aria-expanded"), "true", `${label}: scrolling closes the toggle`);
            const scrolledAnchor = await trigger.boundingBox(), scrolledPanel = await popup.boundingBox();
            assert.ok(Math.abs(scrolledPanel.y - (scrolledAnchor.y + scrolledAnchor.height + 6)) < 2, `${label}: popup does not follow its trigger`);
            await page.setViewportSize({ width: width - 10, height: 700 });
            await frames(page);
            await popup.waitFor({ state: "visible" });
            assert.equal(await trigger.getAttribute("aria-expanded"), "true");
            await trigger.click();
            await popup.waitFor({ state: "hidden" });
            await page.setViewportSize({ width, height: 700 });
          }
          assertClean(record, label);
          assert.deepEqual(record.writes, [], `${label}: a write`);
        });
      } finally { await context.close(); }
    }
    console.log("PASS metadata popovers: below/left anchored within drawer, no reflow, stay open on scroll/resize, outside click/toggle/Escape close; KO/EN, light/dark, 320/1440.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
