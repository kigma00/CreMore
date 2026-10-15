"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { openConsole, preview, settled, assertClean, inBounds, frames, withScreenshot } = require("./console-proof.cjs");

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  try {
    for (const locale of ["ko", "en"]) for (const theme of ["light", "dark"]) for (const width of [375, 1440]) {
      const label = `${locale}-${theme}-${width}`, L = (ko, en) => locale === "ko" ? ko : en;
      const answers = preview(), row = answers["credential-records"].items[0], fid = row.finding_id;
      row.hint = "AKIA••••TEST";
      row.recent_sources = [{ address: "203.0.113.5", kind: "IPV4", last_seen_at: "2026-10-04T05:03:00+00:00", count: 3 },
        { address: "cloudtrail.amazonaws.com", kind: "AWS_INTERNAL", last_seen_at: "2026-10-03T05:03:00+00:00", count: 1 }];
      // Light: every distinct address the lookup read, past what it could count (a lower bound past those listed).
      // Dark: a lower bound with none known past those listed (a lookup saved before every address was counted).
      Object.assign(row, { recent_sources_total: theme === "light" ? 1258 : 2, recent_sources_more: true });
      const at = "2026-10-02T00:00:00Z", later = "2026-10-02T00:01:00Z";
      const summary = { status: "COMPLETE", checked_at: at, policy_names: ["AdministratorAccess"], allow_actions: Array.from({ length: 80 }, (_, i) => `service:Action${i}`),
        deny_statements: 0, conditional_statements: 0, permissions_boundary: false };
      row.issued = { provider: "aws_iam", type: "access_key", current: true, iam_policies: summary };
      const location = { resource_name: "CreMore PoC", source_type: "notion", location: "https://app.notion.com/p/CreMore-PoC-" + "a".repeat(32) };
      Object.assign(row.exposures[0], location);
      row.exposures[0].author = "담당자 · Owner";
      Object.assign(answers[`findings/${fid}`].exposures[0], location, { redacted_line: "[Credential material redacted]", line_number: 4,
        source_location: { source_provider: "notion", original_link: { status: "CURRENT_ONLY", url: "https://www.notion.so/" + "a".repeat(32),
          requires_source_auth: true, historical_content: false } } });
      answers[`findings/${fid}`].exposure_path = { stages: [{ stage: "PRIVILEGED", state: "NOT_COLLECTED" }] };
      let collected = false;
      const potential = { collection_status: "COMPLETE", assessment_version: 2, evaluated_at: later, actions: Array.from({ length: 20 }, (_, index) => ({
        action: index === 0 ? "iam:CreateAccessKey" : `service:Action${index}`, service: "iam",
        decision: index === 1 ? "EXPLICIT_DENY" : index === 2 ? "IMPLICIT_DENY" : "ALLOWED", risk: "PRIVILEGE_ESCALATION",
        missing_context_values: index === 2 ? ["aws:SourceIp"] : [],
        ...(index === 1 ? { organizations_allowed: false, permissions_boundary_allowed: true } : {}) })) };
      const { context, page, record } = await openConsole(browser, { locale, theme, width, height: 800, view: "exposed",
        query: `&id=${encodeURIComponent(row.id)}`, answer: ({ method, endpoint }) => {
          if (method !== "GET") return undefined;
          if (endpoint === "credential-records") return { ...answers[endpoint], items: [{ ...row,
            aws_permissions: collected ? { potential_access: potential } : {} }], total: 1 };
          if (endpoint === `credentials/${row.credential_id}/usage`) return { ...answers[endpoint],
            ...(collected ? { potential_access: potential } : {}) };
          return answers[endpoint];
        } });
      try {
        await withScreenshot(page, `credential-permissions-${label}`, async () => {
          await settled(page, record, label);
          const drawer = page.locator(".drawer");
          assert.equal(await drawer.getByText(L("대응 진행", "Response progress"), { exact: true }).count(), 0);
          const title = drawer.locator(".exposure-locations .loc-cell .cell-wrap");
          assert.equal(await title.innerText(), "CreMore PoC");
          assert.ok(await title.evaluate(el => {
            const text = el.firstChild, tops = [];
            for (let i = 0; i < 7; i++) { const r = document.createRange(); r.setStart(text, i); r.setEnd(text, i + 1); tops.push(r.getBoundingClientRect().top); }
            return new Set(tops).size === 1 && el.scrollWidth <= el.clientWidth;
          }), `${label}: CreMore splits in the middle`);
          const exposure = drawer.locator(".exposure-location");
          assert.equal(await exposure.locator(".exposure-location-path").innerText(), location.location);
          assert.ok((await exposure.locator(".exposure-location-path").boundingBox()).width > (await exposure.boundingBox()).width * 0.95, "long paths use the full entry width");
          assert.equal(await exposure.locator("dt").count(), 3);
          assert.ok((await exposure.innerText()).includes("담당자 · Owner"));
          const sources = await drawer.locator(".fact").filter({ hasText: L("최근 사용 출처", "Recently used from") }).innerText();
          assert.ok(sources.includes("203.0.113.5") && sources.includes(L("AWS 서비스 cloudtrail.amazonaws.com", "AWS service cloudtrail.amazonaws.com")), label);
          assert.ok(sources.includes(theme === "light" ? L("+1,256곳 이상", "+1,256 or more") : L("더 있을 수 있음", "possibly more")), `${label}: ${sources}`);
          assert.ok(!sources.includes("+0"), `${label}: ${sources}`);
          assert.ok((await exposure.innerText()).includes(L("자격증명은 숨김 처리되었습니다.", "Credential material is hidden.")));
          const source = exposure.getByRole("link", { name: L("원본 열기", "Open source") });
          assert.equal(await source.getAttribute("href"), "https://www.notion.so/" + "a".repeat(32));
          assert.equal(await source.getAttribute("referrerpolicy"), "no-referrer");
          await exposure.evaluate(el => {
            const panel = el.closest(".drawer");
            panel.scrollTop += el.getBoundingClientRect().top - panel.querySelector(".drawer-head").getBoundingClientRect().bottom - 8;
          });
          await frames(page);
          await inBounds(page, label);
          if (process.env.CREMORE_PROOF_ARTIFACTS && locale === "ko" && theme === "light") {
            await page.screenshot({ path: require("node:path").join(process.env.CREMORE_PROOF_ARTIFACTS, `location-spacing-${width}.png`) });
          }
          await drawer.getByRole("button", { name: L("권한 범위", "Access scope"), exact: true }).click();
          assert.equal(await drawer.locator("svg text").filter({ hasText: L("권한 미확인", "Permissions unknown") }).count(), 0);
          assert.ok((await drawer.locator(".g-node").allTextContents()).join(" ").includes("Administrator"));
          await drawer.getByRole("tab", { name: new RegExp(L("위험 분석", "Risk analysis")) }).click();
          assert.equal(await drawer.getByRole("button", { name: L("권한 범위 미확인", "Permissions unknown"), exact: true }).count(), 0);
          await drawer.getByRole("tab", { name: new RegExp(L("개요", "Overview")) }).click();
          await settled(page, record, label);
          const allowName = L("Allow 문장에 적힌 작업 · 80개", "Actions named in Allow statements · 80");
          const allowTrigger = drawer.getByRole("button", { name: allowName, exact: true });
          await allowTrigger.scrollIntoViewIfNeeded();
          const allowBefore = await allowTrigger.boundingBox();
          await allowTrigger.click();
          const allowPopup = page.getByRole("dialog", { name: allowName, exact: true });
          await allowPopup.waitFor({ state: "visible" });
          const allowAfter = await allowTrigger.boundingBox();
          assert.equal(allowAfter.width, allowBefore.width);
          assert.equal(allowAfter.height, allowBefore.height);
          assert.ok(Math.abs((await allowPopup.boundingBox()).y - (allowAfter.y + allowAfter.height + 6)) < 2);
          assert.equal(await allowPopup.locator("li").count(), 80);
          assert.ok(await allowPopup.evaluate(el => el.scrollHeight > el.clientHeight), "long Allow list must scroll internally");
          const allowPanel = await allowPopup.boundingBox(), drawerBox = await drawer.boundingBox();
          assert.ok(Math.abs(allowPanel.x - allowAfter.x) < 2, `${label}: Allow list must start below its label`);
          assert.ok(allowPanel.x >= drawerBox.x && allowPanel.x + allowPanel.width <= drawerBox.x + drawerBox.width);
          await allowPopup.evaluate(el => { el.scrollTop = 100; });
          await drawer.evaluate(el => { el.scrollTop += 16; });
          await frames(page);
          assert.equal(await allowTrigger.getAttribute("aria-expanded"), "true");
          assert.ok(await allowPopup.evaluate(el => el.scrollTop > 0), "page scrolling must preserve list position");
          await inBounds(page, label);
          await allowTrigger.click();
          await allowPopup.waitFor({ state: "hidden" });
          collected = true;
          await page.clock.fastForward(5001);
          await settled(page, record, label);
          const name = L("정책 시뮬레이션 · 평가 20개", "Policy simulation · 20 evaluated");
          const trigger = drawer.getByRole("button", { name, exact: true });
          await trigger.waitFor();
          await trigger.scrollIntoViewIfNeeded(); await trigger.focus(); await frames(page);
          const card = trigger.locator("xpath=ancestor::*[contains(concat(' ',normalize-space(@class),' '),' card ')][1]");
          const before = await card.boundingBox();
          await trigger.press("Enter");
          const popup = page.getByRole("dialog", { name, exact: true });
          await popup.waitFor({ state: "visible" });
          const anchor = await trigger.boundingBox(), panel = await popup.boundingBox();
          assert.ok(Math.abs(panel.y - (anchor.y + anchor.height + 6)) < 2, `${label}: simulation must open below its trigger`);
          assert.ok(Math.abs(panel.x - anchor.x) < 2, `${label}: simulation must align to the label`);
          const after = await card.boundingBox();
          assert.equal(after.width, before.width, `${label}: simulation resizes the card`);
          assert.equal(after.height, before.height, `${label}: simulation expands the card`);
          assert.equal(await popup.locator(".simulation-actions li").count(), 20);
          assert.ok((await popup.innerText()).includes("iam:CreateAccessKey"));
          const simulationText = await popup.innerText();
          assert.ok(simulationText.includes(L("명시적 거부 (시뮬레이션)", "Explicit deny (simulation)")));
          assert.ok(simulationText.includes(L("조건 입력 부족", "Missing context")) && simulationText.includes("aws:SourceIp"));
          assert.ok(simulationText.includes(L("조직: 허용 안 됨", "Organizations: does not allow")));
          assert.ok(simulationText.includes(L("권한 경계: 허용", "Boundary: allows")));
          assert.ok(simulationText.includes(L("실제 접근 권한은 평가하지 않았습니다", "Effective access was not evaluated")));
          await drawer.evaluate(el => { el.scrollTop += 16; });
          await frames(page);
          assert.equal(await trigger.getAttribute("aria-expanded"), "true");
          const movedAnchor = await trigger.boundingBox(), movedPopup = await popup.boundingBox();
          assert.ok(Math.abs(movedPopup.y - (movedAnchor.y + movedAnchor.height + 6)) < 2);
          await inBounds(page, label);
          if (process.env.CREMORE_PROOF_ARTIFACTS && locale === "ko" && theme === "light") {
            await page.screenshot({ path: require("node:path").join(process.env.CREMORE_PROOF_ARTIFACTS, `anchored-simulation-${width}.png`) });
          }
          await page.keyboard.press("Escape");
          await popup.waitFor({ state: "hidden" });
          assert.ok(await trigger.evaluate(el => el === document.activeElement));
          assert.equal(await drawer.count(), 1);
          assertClean(record, label);
          assert.deepEqual(record.writes, []);
        });
      } finally { await context.close(); }
    }
    console.log("PASS credential permissions: inventory and refresh synchronization, natural title wrap, overlay/focus/no shift; KO/EN, light/dark, 375/1440.");
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
