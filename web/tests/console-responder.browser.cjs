"use strict";
const assert = require("node:assert/strict");
const { chromium } = require("playwright");
const { openConsole, preview, settled, inBounds, assertClean, withScreenshot, refusal } = require("./console-proof.cjs");
const ref = n => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const person = n => ({ id: ref(n), person_ref: ref(n), name: n < 3 ? "Same name" : `Person ${n}`, email: `person${n}@example.test`,
  department: n === 1 ? "Sales" : "Operations", title: null, state: "ACTIVE", sources: [], selectable: true, reason: null });
const directory = (items, extra = {}) => ({ items, total: 1201, next_cursor: null,
  directory: { status: "READY", usable: true, observed_at: "2026-10-01T12:00:00Z", sources: [] }, ...extra });
const routing = () => ({ version: 7, status: "AMBIGUOUS", manual_email_allowed: false, assignment: null,
  recommendations: [1, 2].map(n => ({ person: person(n), basis: "VERIFIED_EMAIL" })),
  targets: [{ kind: "location", key: "server-bound-location", label: "Exact source / project", rule: { version: 3, person_ref: ref(1), team: "Previous team" } }] });

async function responseProof(browser, width, locale, theme) {
  const answers = preview(), row = answers["credential-records"].items[0], finding = row.finding_id;
  answers.session.auth_mode = "oidc";
  let state = { state: "NEW", version: 0, current: null, history: [], can_request: true }, releaseSlow;
  const { context, page, record } = await openConsole(browser, { width, locale, theme, view: "exposed", query: `&id=${encodeURIComponent(row.id)}`,
    answer: async ({ method, endpoint, body }) => {
      if (method === "GET") {
        if (endpoint === `findings/${finding}/response`) return state;
        if (endpoint === `findings/${finding}/response/routing`) return routing();
        if (endpoint === "contact-delivery") return { mail: true, slack: true, allowed_domains: ["example.test"], allowed_channels: [], console_url: "https://cremore.example.test" };
        if (endpoint.startsWith("people?q=")) {
          const p = new URL(endpoint, "https://example.test/").searchParams;
          assert.equal(p.get("limit"), "25");
          const q = p.get("q"), cursor = p.get("cursor");
          if (q === "slow") return await new Promise(resolve => { releaseSlow = () => resolve(directory([person(777)])); });
          if (q === "expired" && cursor) return refusal(409, "DIRECTORY_CURSOR_EXPIRED");
          if (q === "expired") return directory([person(2)], { next_cursor: "expired-snapshot" });
          if (q === "stale") return directory([person(888)], { directory: { status: "STALE", usable: false, observed_at: "2026-01-01T00:00:00Z" } });
          if (q) return directory([person(1200)]);
          return cursor ? directory([person(501), person(502)]) : directory(Array.from({ length: 25 }, (_, n) => person(n + 1)), { next_cursor: "opaque/page+2=" });
        }
        return answers[endpoint];
      }
      if (endpoint === `findings/${finding}/response/routing-rule`) {
        assert.deepEqual(body, { kind: "location", key: "server-bound-location", person_ref: ref(1200), team: "Explicit response team", expected_version: 3 });
        return { version: 4 };
      }
      if (endpoint === `findings/${finding}/response/ticket`) {
        assert.equal(body.channel, "slack", "a team installation asks by a Slack link first");
        assert.equal(body.person_ref, ref(1200)); assert.equal(body.team, "Explicit response team"); assert.equal(body.expected_version, 0);
        assert.equal(Object.hasOwn(body, "to"), false, "the server resolves the selected identity's current email");
        assert.equal(body.dm, true); assert.equal(Object.hasOwn(body, "slack_channel"), false, "no team channel approved: the DM only");
        state = { state: "WAITING_OWNER", version: 1, can_request: false, current: { request_id: body.request_id, cycle: 1, state: "WAITING_OWNER", channel: "slack", ticket: null, assigned_to: person(1200).email,
          recipient: person(1200), team: body.team, requested_by: "operator", requested_at: "2026-10-01T12:00:00Z", link_expires_at: "2026-10-08T12:00:00Z", link_expired: false }, history: [] };
        return state;
      }
    } });
  const L = (ko, en) => locale === "ko" ? ko : en;
  try {
    await withScreenshot(page, `responder-${width}-${locale}-${theme}`, async () => {
      await settled(page, record);
      await page.locator(".drawer").getByRole("tab", { name: L("대응 담당자", "Response owner"), exact: true }).click();
      await page.getByRole("button", { name: L("대응 요청", "Request response"), exact: true }).click();
      const how = page.getByLabel(L("요청 방법", "Send by"));
      assert.deepEqual(await how.locator("option").allTextContents(), ["Slack", L("메일", "Mail")], "no record on a team installation, no ticket system set up");
      assert.equal(await how.inputValue(), "slack");
      assert.ok((await page.locator(".drawer-body").textContent()).includes(L("7일 동안", "7 days")));
      const submit = page.getByRole("button", { name: L("대응 요청 보내기", "Send response request"), exact: true });
      assert.equal(await submit.isDisabled(), true, "a recommendation is not an automatic selection");
      const combo = page.getByRole("combobox", { name: L("대응 담당자", "Responder"), exact: true });
      await combo.scrollIntoViewIfNeeded();
      const before = await page.locator(".drawer").boundingBox();
      await combo.click(); await settled(page, record);
      assert.equal(await page.getByRole("listbox").getByRole("option").count(), 25);
      await page.getByRole("button", { name: L("다음 결과 더 보기", "Load more results") }).click(); await settled(page, record);
      assert.equal(await page.getByRole("listbox").getByRole("option").count(), 27);
      assert.match(await page.getByRole("listbox").textContent(), /person501@example.test/);
      const search = page.getByLabel(L("IdP 사람 검색", "Search IdP people"));
      await search.fill("person1200"); await page.clock.fastForward(300); await settled(page, record);
      assert.equal(await page.getByRole("listbox").getByRole("option").count(), 1);
      const after = await page.locator(".drawer").boundingBox();
      assert.equal(after.width, before.width); assert.equal(after.x, before.x);
      await inBounds(page, `responder-search-${width}`);
      await search.press("ArrowDown"); await page.keyboard.press("Enter");
      assert.match(await combo.textContent(), /person1200@example.test/);
      assert.equal(await submit.isDisabled(), false);
      await combo.click(); await settled(page, record);
      await search.fill("slow"); await page.clock.fastForward(300);
      for (let i = 0; !releaseSlow && i < 100; i++) await page.waitForTimeout(20);
      assert.equal(typeof releaseSlow, "function");
      assert.equal(await submit.isDisabled(), true, "editing the query clears the previous person reference immediately");
      await search.fill("quick"); await page.clock.fastForward(300);
      await page.getByRole("listbox").getByRole("option", { name: /Person 1200/ }).waitFor();
      releaseSlow(); await settled(page, record);
      assert.doesNotMatch(await page.getByRole("listbox").textContent(), /Person 777/);
      await search.fill("stale"); await page.clock.fastForward(300); await settled(page, record);
      assert.equal(await page.getByRole("listbox").getByRole("option").getAttribute("aria-disabled"), "true");
      await page.getByRole("listbox").getByRole("option").click({ force: true });
      assert.equal(await submit.isDisabled(), true);
      assert.ok((await page.locator(".menu").textContent()).includes(L("오래됐습니다", "stale")));
      await search.fill("expired"); await page.clock.fastForward(300); await settled(page, record);
      await page.getByRole("button", { name: L("다음 결과 더 보기", "Load more results") }).click(); await settled(page, record);
      assert.ok((await page.locator(".menu").textContent()).includes(L("디렉터리가 갱신됐습니다", "directory changed")));
      await page.getByRole("button", { name: L("다시 검색", "Search again"), exact: true }).click(); await page.clock.fastForward(300); await settled(page, record);
      assert.equal(await page.getByRole("listbox").getByRole("option").count(), 1);
      await page.keyboard.press("Escape");
      assert.equal(await combo.evaluate(el => document.activeElement === el), true);
      await combo.click(); await settled(page, record);
      await search.fill("person1200"); await page.clock.fastForward(300); await settled(page, record);
      await page.getByRole("listbox").getByRole("option").click();
      await page.getByLabel(L("명시적 책임 팀 (선택)", "Explicit responsible team (optional)")).fill("Explicit response team");
      await page.getByLabel(L("같은 위치·발급 계정의 다음 발견에도 적용", "Reuse for future findings at this location or issuing account")).selectOption("location:server-bound-location");
      await submit.click(); await settled(page, record);
      assert.ok((await page.locator(".drawer-body").textContent()).includes("person1200@example.test"));
      assert.ok((await page.locator(".drawer-body").textContent()).includes("Explicit response team"));
      const body = async () => await page.locator(".drawer-body").textContent();
      assert.ok((await body()).includes(L("링크 보냄", "Link sent")));
      assert.ok((await body()).includes(L("링크 만료", "Link expires")));
      assert.ok(!(await body()).includes(L("외부 티켓", "External ticket")));
      const again = page.getByRole("button", { name: L("대응 다시 요청", "Request response again"), exact: true });
      assert.equal(await again.count(), 0, "a waiting link: the server allows no new request");
      // The link expired while the cycle waits: the server says a new request may start.
      state = { ...state, version: 2, can_request: true, current: { ...state.current, link_expired: true } };
      await page.clock.fastForward(10001); await settled(page, record);
      assert.ok((await body()).includes(L("만료됨 · 다시 요청할 수 있음", "Expired · can be requested again")));
      assert.equal(await again.count(), 1);
      // The send failed: the link is void and the reason is said once.
      state = { ...state, state: "NOT_SENT", version: 3, can_request: true, current: { ...state.current, state: "NOT_SENT", link_expired: false, error_code: "SLACK_USER_NOT_FOUND" } };
      await page.clock.fastForward(10001); await settled(page, record);
      assert.ok((await page.locator(".drawer-head").textContent()).includes(L("대응 요청 발송 안 됨", "Request not sent")));
      assert.ok((await body()).includes(L("Slack에서 이 주소의 사용자를 찾지 못했습니다.", "No Slack user has this address.")));
      assert.ok((await body()).includes(L("보내지 못함", "Not sent")));
      assert.equal(await again.count(), 1);
      await inBounds(page, `responder-sent-${width}`);
      assertClean(record, "remote IdP responder");
      assert.equal(record.writes.length, 2);
    });
  } finally { if (releaseSlow) releaseSlow(); await context.close(); }
}

async function assignProof(browser, bulk) {
  const answers = preview(), row = answers["credential-records"].items[0], finding = row.finding_id;
  answers["credential-records"].items = [row]; answers["credential-records"].total = 1;
  const { context, page, record } = await openConsole(browser, { view: bulk ? "assign" : "exposed", locale: "en", query: bulk ? "" : `&id=${encodeURIComponent(row.id)}`,
    answer: ({ method, endpoint, body }) => {
      if (method === "GET") {
        if (endpoint === `findings/${finding}/response/routing`) return routing();
        if (endpoint.startsWith("people?q=")) return directory([person(1200)]);
        return answers[endpoint];
      }
      if (endpoint === `findings/${finding}/assign`) { assert.deepEqual(body, { person_ref: ref(1200), team: "Team", expected_version: 7 }); return {}; }
      if (endpoint === "text-check") return { contains_credential: false };
      if (endpoint === `findings/${finding}/comments`) return {};
    } });
  try {
    await settled(page, record);
    if (bulk) {
      await page.getByRole("checkbox", { name: "Select every row shown" }).click();
      await page.getByRole("button", { name: "Assign owner", exact: true }).click();
    } else {
      await page.getByRole("button", { name: "Actions", exact: true }).click();
      await page.getByRole("menuitem", { name: "Assign owner", exact: true }).click();
    }
    const modal = page.getByRole("dialog"); await settled(page, record);
    await modal.getByRole("combobox", { name: "Responder", exact: true }).click(); await settled(page, record);
    await page.getByRole("listbox").getByRole("option", { name: /Person 1200/ }).click();
    await modal.getByLabel("Explicit responsible team (optional)").fill("Team");
    await modal.getByRole("button", { name: "Assign", exact: true }).click(); await settled(page, record);
    assert.equal(await page.getByRole("dialog").count(), 0);
    assert.equal(record.writes.filter(write => write.endpoint.endsWith("/assign")).length, 1);
    assertClean(record, bulk ? "bulk stable assignment" : "single stable assignment");
  } finally { await context.close(); }
}

(async () => {
  const browser = await chromium.launch({ channel: "chrome", headless: true });
  try {
    await responseProof(browser, 1440, "ko", "light");
    await responseProof(browser, 360, "en", "dark");
    await assignProof(browser, false); await assignProof(browser, true);
    console.log("PASS IdP responder: server search beyond 500, opaque pagination, debounce/cancel/late reply, stale and cursor expiry, keyboard/overlay/focus, same-name identity, rule + person_ref Slack link request, server can_request, link expiry and NOT_SENT, individual/bulk CAS assignment, KO/EN/light/dark/360px.");
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
