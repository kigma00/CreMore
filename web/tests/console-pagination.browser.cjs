"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { openConsole, preview, respond, settled, inBounds, assertClean } = require("./console-proof.cjs");

async function main() {
  const browser = await chromium.launch({ headless: true, channel: "chrome" });
  const cursor = "11111111-1111-4111-8111-111111111111";
  try {
    for (const locale of ["ko", "en"]) for (const [theme, width] of [["light", 320], ["dark", 1440]]) {
      const answers = preview(), label = `${locale}-${theme}-${width}`;
      const word = (ko, en) => locale === "ko" ? ko : en;
      const { context, page, record } = await openConsole(browser, { locale, theme, width, view: "approvals", answer: ({ endpoint }) => {
        if (/^(rotation-automation\/jobs|management-actions)\?/.test(endpoint)) {
          const query = new URLSearchParams(endpoint.split("?")[1]);
          assert.ok(!query.has("after"), "list APIs accept cursor, not the repository's internal after argument");
          const next = query.get("cursor");
          // An empty filtered page must retain its server cursor.
          return respond(200, [], { "X-Page-Limit": "100", ...(next ? {} : { "X-Next-Cursor": cursor }) });
        }
        if (endpoint.startsWith("tickets?offset=")) return { data: { items: [], next_offset: endpoint.endsWith("=0") ? 50 : null } };
        return answers[endpoint];
      } });
      try {
        await settled(page, record);
        assert.ok((await page.locator(".main").textContent()).includes(word("건수는 현재 불러온 페이지 기준", "Counts cover the loaded pages")));
        assert.ok(record.calls.every(call => !call.endpoint.includes("cursor=") && !call.endpoint.endsWith("offset=50")), "no automatic next-page request");
        for (const [name, endpoint] of [[word("키 교체 기록", "Key rotation history"), "rotation-automation/jobs"],
          [word("관리 조치", "Management actions"), "management-actions"], [word("티켓 승인", "Ticket approvals"), "tickets"]]) {
          const nav = page.getByRole("navigation", { name, exact: true });
          const next = nav.getByRole("button", { name: word("다음", "Next"), exact: true });
          assert.equal(await next.isEnabled(), true, `${label}: empty ${name} page retains next`);
          await next.click(); await settled(page, record);
          assert.ok(record.calls.some(call => call.endpoint.startsWith(endpoint) && (endpoint === "tickets" ? call.endpoint.endsWith("offset=50") : call.endpoint.includes(`cursor=${cursor}`))));
          assert.equal(await next.isEnabled(), false, `${label}: last page`);
          await nav.getByRole("button", { name: word("이전", "Previous"), exact: true }).click();
          await settled(page, record);
          assert.equal(await next.isEnabled(), true, `${label}: previous page restores next`);
        }
        await inBounds(page, label);
        assertClean(record, label);
      } finally { await context.close(); }
    }
  } finally { await browser.close(); }
  console.log("approval pagination: Korean/English, 320/1440, first/next/previous and empty pages passed");
}

main().catch(error => { console.error(error); process.exitCode = 1; });
