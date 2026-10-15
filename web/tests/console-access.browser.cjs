"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { openConsole, preview, settled, inBounds, assertClean, withScreenshot } = require("./console-proof.cjs");

async function proof(browser, width, locale, theme) {
  const answers = preview(), row = answers["credential-records"].items[0], finding = row.finding_id;
  const at = "2026-10-01T12:00:00Z";
  const locations = ["a", "b", "unsupported", "limited", "partial", "legacy"].map((key, i) => ({ exposure_id: `exposure-${key}`, source_type: i === 2 ? "notion" : "github",
    repository: "same/repository", path: `file-${key}.env`, source_connection_id: `connection-${key}`, source_label: `Host ${key}`, access_key: key,
    context_status: i === 2 ? "UNSUPPORTED" : i === 3 ? "LIMIT_REACHED" : "OBSERVED", codeowners: {}, author: {} }));
  const repositories = locations.map(location => ({ ...location, status: location.context_status, basis: "GITHUB_REPOSITORY_COLLABORATORS",
    evidence_kind: "PROVIDER_COLLABORATORS", completeness: "COMPLETE", visibility: "PUBLIC", observed_at: at,
    limitations: ["NOT_ACCESS_HISTORY", "PUBLIC_ACCESS_NOT_ENUMERATED", "TOKENS_AND_APPS_NOT_ENUMERATED"],
    people: [{ login: "same-login", name: `Person from ${location.source_label}`, role: "read", read_access: "REPORTED" }] }));
  repositories[0].people.push(...Array.from({ length: 234 }, (_, n) => ({ login: `member-${n}`, name: `Member ${n}`, role: "read", read_access: "REPORTED" })));
  for (const n of [2, 3]) Object.assign(repositories[n], { people: [], completeness: n === 2 ? "UNSUPPORTED" : "UNKNOWN", observed_at: null });
  Object.assign(repositories[4], { status: "FORBIDDEN", completeness: "PARTIAL", truncated: true, basis: "GITLAB_PROJECT_MEMBERS", evidence_kind: "PROVIDER_MEMBERSHIP",
    limitations: ["MEMBER_PAGE_UNAVAILABLE", "MEMBERSHIP_NOT_EFFECTIVE_READ_ACCESS"], people: [{ login: "guest-one", name: "Observed guest", role: "guest", principal_kind: "USER", read_access: "UNKNOWN" }] });
  delete locations[5].access_key; delete locations[5].source_connection_id;
  const observed = { status: "PARTIAL", locations, repositories, collected_at: at, location_count: 8, unqueried_locations: 4, omitted_locations: 2, reasons: ["CONTEXT_LOCATION_LIMIT"], job_status: "RUNNING" };
  const { context, page, record } = await openConsole(browser, { width, locale, theme, view: "exposed", query: `&id=${encodeURIComponent(row.id)}&dtab=owner`,
    answer: ({ method, endpoint }) => method === "GET" ? endpoint === `findings/${finding}/context` ? observed : answers[endpoint] : undefined });
  const L = (ko, en) => locale === "ko" ? ko : en;
  try {
    await withScreenshot(page, `access-${width}-${locale}-${theme}`, async () => {
      await settled(page, record);
      const open = page.getByRole("button", { name: L("목록 보기", "View list"), exact: true });
      await open.scrollIntoViewIfNeeded();
      const before = await page.locator(".drawer").boundingBox();
      await open.click();
      const modal = page.getByRole("dialog", { name: L("발견 위치별 접근 목록", "Access by discovered location") });
      await modal.waitFor();
      assert.equal(await page.locator(".access-list tbody tr").count(), 100, "large lists render a bounded page");
      await modal.getByRole("button", { name: L("다음 페이지", "Next page"), exact: true }).click();
      await modal.getByRole("button", { name: L("다음 페이지", "Next page"), exact: true }).click();
      assert.equal(await page.locator(".access-list tbody tr").count(), 35);
      assert.match(await page.locator(".access-list tbody").textContent(), /member-233/);
      const after = await page.locator(".drawer").boundingBox();
      assert.equal(after.x, before.x); assert.equal(after.width, before.width, "overlay never shrinks the underlying drawer");
      await modal.getByLabel(L("계정·그룹 검색", "Search accounts and groups")).fill("member-24");
      assert.equal(await page.locator(".access-list tbody tr").count(), 1);
      assert.match(await page.locator(".access-list tbody").textContent(), /member-24/);
      await modal.getByLabel(L("발견 위치 선택", "Choose discovered location")).selectOption("1");
      assert.equal(await page.locator(".access-list tbody tr").count(), 1);
      assert.match(await page.locator(".access-list").textContent(), /Person from Host b/);
      assert.doesNotMatch(await page.locator(".access-list").textContent(), /Person from Host a/);
      await modal.locator("summary").click();
      assert.ok((await modal.textContent()).includes(L("공개 위치입니다", "This location is public")));
      await modal.getByLabel(L("발견 위치 선택", "Choose discovered location")).selectOption("2");
      assert.ok((await modal.textContent()).includes(L("지원하지 않습니다", "not currently supported")));
      assert.equal(await page.locator(".access-list tbody tr").count(), 0);
      await modal.getByLabel(L("발견 위치 선택", "Choose discovered location")).selectOption("3");
      assert.ok((await modal.textContent()).includes(L("위치 한도", "location limit")));
      await modal.getByLabel(L("발견 위치 선택", "Choose discovered location")).selectOption("4");
      assert.match(await page.locator(".access-list tbody").textContent(), /Observed guest/);
      assert.ok((await page.locator(".access-list tbody").textContent()).includes(L("미확인", "Unknown")));
      assert.ok((await modal.textContent()).includes(L("부분 목록", "partial list")));
      assert.ok((await modal.textContent()).includes(L("현재 접근 가능 여부를 보장하지 않습니다", "does not guarantee access now")));
      assert.ok((await modal.textContent()).includes(L("저장된 근거 1건", "1 evidence rows have been saved")));
      assert.ok((await page.locator(".access-list tbody").textContent()).includes(L("사용자", "User")));
      await inBounds(page, `access-${width}-${locale}-${theme}`);
      if (process.env.CREMORE_PROOF_ARTIFACTS) await page.screenshot({ path: require("node:path").join(process.env.CREMORE_PROOF_ARTIFACTS, `access-${width}-${locale}-${theme}.png`) });
      await modal.getByLabel(L("발견 위치 선택", "Choose discovered location")).selectOption("5");
      assert.ok((await modal.textContent()).includes(L("이전 관측", "older observation")));
      assert.equal(await page.locator(".access-list tbody tr").count(), 0);
      const downloaded = page.waitForEvent("download");
      await modal.getByRole("button", { name: L("CSV 내보내기", "Export CSV") }).click();
      assert.match((await downloaded).suggestedFilename(), /^cremore-access-.*\.csv$/);
      await page.keyboard.press("Escape");
      assert.equal(await page.getByRole("dialog").count(), 0);
      assert.equal(await open.evaluate(el => document.activeElement === el), true, "keyboard focus returns to the opener");
      assertClean(record, "location access");
      assert.equal(record.writes.length, 0, "reading lists and exporting never triggers a provider collection");
    });
  } finally { await context.close(); }
}

(async () => {
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  try {
    await proof(browser, 1440, "ko", "light");
    await proof(browser, 360, "en", "dark");
    console.log("PASS location access: 235 rows searchable in bounded pages; connection-isolated same repository/logins; unknown/partial/unsupported/capped/legacy evidence; saved observation freshness and progress; CSV; overlay/no layout shift; focus restore; KO/EN/light/dark/360px; no provider writes.");
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
